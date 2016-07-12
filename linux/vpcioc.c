/*
 * Copyright 2012, Marvell
 * All rights reserved
 *
 */
/*
 * VSA Peer Cache IOCTL handlers
 */
#include <linux/moduleparam.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/netdevice.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include "vpc.h"


#define	MAX_OUTSTANDING		64
#define	MIN(x, y)	((x) < (y) ? (x) : (y))

typedef struct _qe {
	u32_t conn_hdl;
	u32_t type;
	vpc_req_t *req;
	struct _qe * next;
} vpc_qent_t;

typedef struct _kbuf {
	struct _kbuf *next;
} vpc_kbuf_t;

typedef struct _rqlist {
	vpc_req_ext_t *head;
} vpc_req_list_t;

typedef struct _cv {
	struct task_struct *thr;
} cond_t;

static int listen_on;
static struct task_struct *svr_thr;
static vpc_qent_t *await_q_hd;
static vpc_qent_t *await_q_tl;
static vpc_kbuf_t *kbuf_hd;
static vpc_kbuf_t *kbuf_tl;
static vpc_qent_t *qent_hd;
static vpc_qent_t *qent_tl;
static spinlock_t await_qlock;
static spinlock_t qentlock;
static spinlock_t kbuflock;
static vpc_req_list_t clnt_reqlist;

/* for perf test */
static int perf_svr;
static int perf_test;
static int cmpltd;
static spinlock_t plock;
static cond_t pcond;
static spinlock_t pendq_lock;
static vpc_req_ext_t *pending_q_hd;
static vpc_req_ext_t *pending_q_tl;

static int copy_to_uiov(void *ubuf, struct kvec *iov, int iovlen);

static void
deq(vpc_req_ext_t *rqx)
{
	vpc_req_ext_t *p, *q;

	spin_lock(&pendq_lock);
	q = rqx->next;
	p = rqx->prev;

	if (p == NULL) {
		pending_q_hd = q;
		if (q == NULL)
			pending_q_tl = NULL;
		else
			q->prev = NULL;
	} else {
		p->next = q;
		if (q == NULL)
			pending_q_tl = p;
		else
			q->prev = p;
	}
	spin_unlock(&pendq_lock);
}

static vpc_req_ext_t *
deq_hd(void)
{
	vpc_req_ext_t *p;

	spin_lock(&pendq_lock);
	p = pending_q_hd;
	if (p != NULL) {
		pending_q_hd = p->next;
		if (pending_q_hd == NULL)
			pending_q_tl = NULL;
		else
			pending_q_hd->prev = NULL;
	} else {
		pending_q_tl = NULL;
	}
	spin_unlock(&pendq_lock);
	return p;
}

static void
enq_tail(vpc_req_ext_t *rqx)
{
	spin_lock(&pendq_lock);
	if (pending_q_hd == NULL) {
		pending_q_hd = rqx;
		pending_q_tl = rqx;
		rqx->next = NULL;
		rqx->prev = NULL;
	} else {
		pending_q_tl->next = rqx;
		rqx->prev = pending_q_tl;
		pending_q_tl = rqx;
		rqx->next = NULL;
	}
	spin_unlock(&pendq_lock);
}

static void *
alloc_kbuf(int len)
{
	vpc_kbuf_t *kbuf;

	spin_lock(&kbuflock);
	kbuf = kbuf_hd;
	if (kbuf == NULL) {
		spin_unlock(&kbuflock);
		return NULL;
	}
	kbuf_hd = kbuf->next;
	if (kbuf_hd == NULL)
		kbuf_tl = NULL;
	spin_unlock(&kbuflock);
	return kbuf;	
}

static void
free_kbuf(void *buf)
{
	vpc_kbuf_t *kbuf = (vpc_kbuf_t *)buf;

	kbuf->next = NULL;
	spin_lock(&kbuflock);
	if (kbuf_tl != NULL) {
		kbuf_tl->next = kbuf;
		kbuf_tl = kbuf;
	} else
		kbuf_hd = kbuf_tl = kbuf;
	spin_unlock(&kbuflock);
}

static vpc_qent_t *
alloc_qent(void)
{
	vpc_qent_t *qent;

	spin_lock(&qentlock);
	qent = qent_hd;
	if (qent == NULL) {
		spin_unlock(&qentlock);
		return NULL;
	}
	qent_hd = qent->next;
	if (qent_hd == NULL)
		qent_tl = NULL;
	spin_unlock(&qentlock);
	return qent;	
}
static void
free_qent(vpc_qent_t *qent)
{
	qent->next = NULL;
	spin_lock(&qentlock);
	if (qent_tl != NULL) {
		qent_tl->next = qent;
		qent_tl = qent;
	} else
		qent_hd = qent_tl = qent;
	spin_unlock(&qentlock);
}

static int
vpc_request_poll(vpcioc_await_req_t *iocreq)
{
	vpc_qent_t *qe;
	int ret = 0;

	/* Check if Server listening */
	if (!listen_on)
		return -1;

	/* Wait on request wait queue */
wait_again:
	set_current_state(TASK_INTERRUPTIBLE);
	spin_lock(&await_qlock);
	if (await_q_hd == NULL) {
		svr_thr = current;
		spin_unlock(&await_qlock);
		schedule();
		if (signal_pending(current))
			return (-ERESTARTSYS);
		spin_lock(&await_qlock);
	}
	set_current_state(TASK_RUNNING);

	qe = await_q_hd;
	if (qe == NULL) {
		spin_unlock(&await_qlock);
		goto wait_again;
	}

	await_q_hd = qe->next;
	if (await_q_hd == NULL) {
		await_q_tl = NULL;
		svr_thr = NULL;
	}
	spin_unlock(&await_qlock);

	iocreq->conn_hdl = qe->conn_hdl;
	iocreq->type = qe->type;
	if (qe->type == VPC_REQ_ASSOC) {
		vpc_assoc_req_t *assocrq = (vpc_assoc_req_t *)
							qe->req->rqst;
		vpcioc_assoc_req_t *associoc;

		associoc = (vpcioc_assoc_req_t *)iocreq->reqmsg;
		memcpy(associoc->msgcookie,
				qe->req->msgcookie, sizeof(u64_t));
		associoc->flags = assocrq->flags;
		if (assocrq->flags & VPC_ASSOC_FLAG_PERF)
			perf_svr = 1;
		else
			perf_svr = 0;
		associoc->batchid = assocrq->batchid;
		memcpy(associoc->obj_id, assocrq->clnt_obj_id, MAX_OBJ_ID_LEN);
		memcpy(associoc->ct_id, assocrq->srvr_ct_id, MAX_OBJ_ID_LEN);
	} else if (qe->type == VPC_REQ_REASSOC) {
		vpc_reassoc_req_t *assocrq = (vpc_reassoc_req_t *)
							qe->req->rqst;
		vpcioc_reassoc_req_t *associoc;

		associoc = (vpcioc_reassoc_req_t *)iocreq->reqmsg;
		memcpy(associoc->msgcookie,
				qe->req->msgcookie, sizeof(u64_t));
		associoc->batchid = assocrq->batchid;
		memcpy(associoc->clnt_obj_id, assocrq->clnt_obj_id, MAX_OBJ_ID_LEN);
		memcpy(associoc->srvr_obj_id, assocrq->srvr_obj_id, MAX_OBJ_ID_LEN);
	} else if (qe->type == VPC_REQ_WRITE) {
		vpc_wr_req_t *wrrq = (vpc_wr_req_t *)qe->req->rqst;
		vpcioc_wr_req_t *wrioc;

		wrioc = (vpcioc_wr_req_t *)iocreq->reqmsg;
		if (iocreq->buflen < wrrq->dlen) {
			printk("Too large write req recd\n");
			ret = -EINVAL;
			goto out;
		}

		if (perf_svr)
			goto skip_dcopy;

		if (wrrq->dtype == DATA_SNGLBUF) {
			if (copy_to_user((void __user *)iocreq->dbuf,
					wrrq->data, wrrq->dlen)) {
				ret = (-EACCES);
				goto out;
			}
		} else {
			ret = copy_to_uiov(iocreq->dbuf, wrrq->data,
						wrrq->iovlen);
			if (ret < 0)
				goto out;
		}
skip_dcopy:
		memcpy(wrioc->msgcookie, qe->req->msgcookie, sizeof(u64_t));
		iocreq->buflen = wrrq->dlen;
		wrioc->obj_hdl = wrrq->obj_hdl;
		wrioc->offset_l = wrrq->offset_l;
		wrioc->batchid = wrrq->batchid;
	} else if (qe->type == VPC_REQ_SETATTR) {
		vpc_setattr_req_t *sarq = (vpc_setattr_req_t *)qe->req->rqst;
		vpcioc_setattr_req_t *saioc;

		saioc = (vpcioc_setattr_req_t *)iocreq->reqmsg;
		if (iocreq->buflen < sarq->dlen) {
			printk("Too large setattr req recd\n");
			ret = -EINVAL;
			goto out;
		}

		if (sarq->dtype == DATA_SNGLBUF) {
			if (copy_to_user((void __user *)iocreq->dbuf,
					sarq->data, sarq->dlen)) {
				ret = (-EACCES);
				goto out;
			}
		} else {
			ret = copy_to_uiov(iocreq->dbuf, sarq->data,
						sarq->iovlen);
			if (ret < 0)
				goto out;
		}

		memcpy(saioc->msgcookie, qe->req->msgcookie, sizeof(u64_t));
		iocreq->buflen = sarq->dlen;
		saioc->obj_hdl = sarq->obj_hdl;
	} else if (qe->type == VPC_REQ_DISASSOC) {
		vpcioc_disassoc_req_t *disassocrq;

		disassocrq = (vpcioc_disassoc_req_t *)iocreq->reqmsg;
		disassocrq->obj_hdl = (u32_t)(unsigned long)qe->req;
		free_qent(qe);
		return 0;
	} else if (qe->type == VPC_REQ_INVAL_BATCH) {
		vpc_invb_req_t *invbrq = (vpc_invb_req_t *)qe->req->rqst;
		vpcioc_invb_req_t *invbioc;

		invbioc = (vpcioc_invb_req_t *)iocreq->reqmsg;
		memcpy(invbioc->msgcookie, qe->req->msgcookie, sizeof(u64_t));
		invbioc->obj_hdl = invbrq->obj_hdl;
		invbioc->batchid = invbrq->batchid;
	}
out:
	vpc_req_free(qe->type, qe->req);
	free_qent(qe);
	return ret;
}

static int
cond_wait(cond_t *cv, spinlock_t *lock)
{
	set_current_state(TASK_INTERRUPTIBLE);
	cv->thr = current;

	spin_unlock(lock);

	schedule();

	if (signal_pending(current)) {
		cv->thr = NULL;
		return (-ERESTARTSYS);
	}
	cv->thr = NULL;
	spin_lock(lock);
	set_current_state(TASK_RUNNING);
	return 0;
}

void
cond_signal(cond_t *cv)
{
	if (cv->thr != NULL)
		wake_up_process(cv->thr);
}

static int
vpc_wait(vpc_req_ext_t *rq, int timo)
{
	/* Sleep on arg for timo seconds */
	set_current_state(TASK_INTERRUPTIBLE);
	rq->thr = current;

	schedule();

	if (signal_pending(current)) {
		siginfo_t info;
		printk(KERN_WARNING "vpc pid %d: %s got signal %d\n",
			task_pid_nr(current), current->comm,
			dequeue_signal_lock(current, &current->blocked,
			&info));
		/* WARNING */
		/* resp_upcall will not find this req */
		rq->thr = NULL;
		return (-ERESTARTSYS);
	}

	rq->thr = NULL;
	set_current_state(TASK_RUNNING);
	return 0;
}

static int
vpc_resp_upcall(int type, void *arg)
{
	vpc_req_ext_t *rq = (vpc_req_ext_t *)arg;
	struct task_struct *thr;

	/* Wakeup sleeper on arg */
	/* if waiter has exited, arg may be invalid */
	/* Real ASN must not use req ptr directly as arg */

	thr = rq->thr;
	if (thr != NULL) {
		wake_up_process(thr);
	} else
		printk("vpc_resp_upcall: thr NULL, type:%d, req:%p\n",
				type, arg);	
	rq->thr = NULL;
	return 0;
}

static void
vpc_conn_err_upcall(u32_t conn_hdl, u32_t obj_hdl)
{
	vpc_qent_t *qe;
	struct task_struct *thr;

	qe = alloc_qent();
	qe->conn_hdl = conn_hdl;
	qe->type = VPC_REQ_DISASSOC;
	qe->req = (void *)(unsigned long)obj_hdl;
	qe->next = NULL;
	spin_lock(&await_qlock);
	if (await_q_tl == NULL) {
		await_q_hd = await_q_tl = qe;
	} else {
		await_q_tl->next = qe;
		await_q_tl = qe;
	}
	thr = svr_thr;
	spin_unlock(&await_qlock);
	/* wakeup server thr in await ioctl */
	perf_svr = 0;
	if (thr != NULL) {
		wake_up_process(thr);
	}
}

static void
vpc_clnt_err_upcall(void *arg)
{
	vpc_req_list_t *cl_list = (vpc_req_list_t *)arg;
	vpc_req_ext_t *req;

	/* err out any waiting reqs */
	req = cl_list->head;
	if (req != NULL) {
		vpc_resp_upcall(0, req);
	}
	cl_list->head = NULL;

	/* err out perf_test */
	if (perf_test) {
		vpc_req_ext_t *p;

		while ((p = deq_hd()) != NULL) {
			kfree(p);
		}
		perf_test = 0;
		cond_signal(&pcond);
	}
}

static int
vpc_srv_req_upcall(u32_t conn_hdl, int type, void *arg)
{
	vpc_req_t *req = (vpc_req_t *)arg;
	vpc_qent_t *qe;
	struct task_struct *thr;

	qe = alloc_qent();
	qe->conn_hdl = conn_hdl;
	qe->type = type;
	qe->req = req;
	qe->next = NULL;
	spin_lock(&await_qlock);
	if (await_q_tl == NULL) {
		await_q_hd = await_q_tl = qe;
	} else {
		await_q_tl->next = qe;
		await_q_tl = qe;
	}
	thr = svr_thr;
	spin_unlock(&await_qlock);
	/* wakeup server thr in await ioctl */
	if (thr != NULL) {
		wake_up_process(thr);
	}
	return 0;
}

static int
copy_to_uiov(void *ubuf, struct kvec *iov, int iovlen)
{
	int i, off = 0;

	for (i = 0; i < iovlen; i++) {
		if (copy_to_user((void __user *)ubuf + off,
				iov[i].iov_base, iov[i].iov_len))
			return (-EACCES);
		off += iov[i].iov_len;
	}
	return 0;
}

static void
free_iov(struct kvec *iov, int iovlen)
{
	int i;
	for (i = 0; i < iovlen; i++)
		free_kbuf(iov[i].iov_base);
	kfree(iov);
}

static int
alloc_iov(int len, struct kvec **iovp, int *iovlen)
{
	struct kvec *iov;
	int n, i;
	void *kbuf;

	n = len/PAGE_SIZE;
	if ((len % PAGE_SIZE) > 0)
		n += 1;
	iov = kzalloc(n * sizeof(struct kvec), GFP_KERNEL);
	if (iov == NULL)
		return (-ENOMEM);
	for (i = 0; i < n; i++) {
		kbuf = alloc_kbuf(0);
		if (kbuf == NULL)
			break;
		iov[i].iov_base = kbuf;
		iov[i].iov_len = MIN(PAGE_SIZE, len);
		len -= MIN(PAGE_SIZE, len);
	}
	/* if something failed to alloc free everything */
	if (i < n) {
		free_iov(iov, i);
		return (-ENOMEM);
	}
	*iovp = iov;
	*iovlen = n;
	return 0;
}

static int
vpc_perfclnt_upcall(int type, void *arg)
{
	vpc_req_ext_t *rqx = (vpc_req_ext_t *)arg;

	deq(rqx);
	spin_lock(&plock);
	cmpltd++;
	spin_unlock(&plock);
	cond_signal(&pcond);
	kfree(arg);
	return 0;
}

static int
do_perf_test(u32_t conn_hdl, u32_t tot_bytes, u32_t iolen, u32_t qdepth)
{
	int i, n, ret;
	int submitted;
	vpc_req_ext_t *rqx;
	vpc_req_t *req;
	vpc_wr_req_t *wrreq;
	vpc_wr_rsp_t *wrrsp;
	struct kvec *iov;
	int iovlen;

	iov = NULL;
	iovlen = 0;
	ret = alloc_iov(iolen, &iov, &iovlen);
	if (ret < 0)
		return (ret);

	n = tot_bytes/iolen;
	submitted = 0;
	cmpltd = 0;
	spin_lock_init(&pendq_lock);
	perf_test = 1;

	for (i = 0; i < n; i++) {
		spin_lock(&plock);
		while ((submitted - cmpltd) > (qdepth - 1)) {
			cond_wait(&pcond, &plock);
			if (!perf_test) {
				spin_unlock(&plock);
				printk("Test erred out\n");
				goto out;
			}
		}
		spin_unlock(&plock);

		rqx = kmalloc(sizeof(vpc_req_ext_t), GFP_KERNEL);
		req = &rqx->req;
		wrreq = (vpc_wr_req_t *)req->rqst;
		wrreq->data = iov;
		wrreq->dtype = DATA_IOVEC;
		wrreq->iovlen = iovlen;
		wrreq->conn_hdl = conn_hdl;
		wrreq->obj_hdl = 0;
		wrreq->offset_l = 0;
		wrreq->offset_h = 0;
		wrreq->dlen = iolen;
		req->rsp_upcall = vpc_perfclnt_upcall;

		wrrsp = (vpc_wr_rsp_t *)req->resp;
		wrrsp->rsp_code = (-VPC_ERR_INVALID);

		ret = vpc_submit_req(VPC_REQ_WRITE, req);
		if (ret < 0) {
			kfree(rqx);
			goto out;
		}
		enq_tail(rqx);
		submitted++;
	}
	spin_lock(&plock);
	while (cmpltd < submitted) {
		cond_wait(&pcond, &plock);
		if (!perf_test) {
			printk("Test erred out\n");
			break;
		}
	}
	spin_unlock(&plock);
out:
	free_iov(iov, iovlen);
	return 0;
}

static vpc_ret_t
do_srv_init(vpcioc_srv_info_t *iocsrvinfo)
{
	vpc_srvinfo_t srvinfo;
	vpc_ret_t ret;

	srvinfo.ip = iocsrvinfo->ip;
	srvinfo.port = iocsrvinfo->port;
	srvinfo.req_upcall = vpc_srv_req_upcall;
	srvinfo.conn_err_upcall = vpc_conn_err_upcall;
	srvinfo.vsa_id = iocsrvinfo->vsa_id;

	ret = vpc_init_srvr(&srvinfo);

	if (ret == VPC_RSP_OK)
		listen_on = 1;
	if (ret == VPC_ERR_LISTEN_FAIL)
		printk("VPC Server init failed listen\n");
	return ret;
}

static vpc_ret_t
do_assoc(vpc_req_ext_t *rq, vpcioc_assoc_req_t *assoc_req)
{
	vpc_req_t *req;
	vpc_assoc_req_t *vpc_assoc_rq;
	vpc_assoc_rsp_t *vpc_assoc_rsp;
	vpc_ret_t ret = VPC_RSP_OK;

	req = &rq->req;

	vpc_assoc_rq = (vpc_assoc_req_t *)req->rqst;
	vpc_assoc_rq->ip = assoc_req->server_ip;
	vpc_assoc_rq->port = assoc_req->port;
	vpc_assoc_rq->flags = assoc_req->flags;
	vpc_assoc_rq->batchid = assoc_req->batchid;
	strcpy(vpc_assoc_rq->clnt_obj_id, assoc_req->obj_id);
	strcpy(vpc_assoc_rq->srvr_ct_id, assoc_req->ct_id);
	req->rsp_upcall = vpc_resp_upcall;
	vpc_assoc_rq->err_upcall = vpc_clnt_err_upcall;
	vpc_assoc_rq->clnt_cookie = &clnt_reqlist;

	vpc_assoc_rsp = (vpc_assoc_rsp_t *)req->resp;
	vpc_assoc_rsp->rsp_code = VPC_ERR_INVALID;
	vpc_assoc_rsp->conn_hdl = VPC_INVALID_CONHDL;
	vpc_assoc_rsp->obj_hdl = VPC_INVALID_OBJHDL;

	rq->thr = NULL;

	ret = vpc_submit_req(VPC_REQ_ASSOC, req);
	if (ret == VPC_RSP_OK) {
		/* 10 second timeout */
		ret = vpc_wait(rq, 10);
		if (ret == 0) {
			assoc_req->rsp_code = vpc_assoc_rsp->rsp_code;
			assoc_req->conn_hdl = vpc_assoc_rsp->conn_hdl;
			assoc_req->obj_hdl = vpc_assoc_rsp->obj_hdl;
			strcpy(assoc_req->rmt_obj_id, vpc_assoc_rsp->obj_id);
		} else {
			assoc_req->rsp_code = VPC_ERR_MSG_TIMEOUT;
		}
	}
	return ret;
}

static vpc_ret_t
do_reassoc(vpc_req_ext_t *rq, vpcioc_reassoc_req_t *assoc_req)
{
	vpc_req_t *req;
	vpc_reassoc_req_t *vpc_assoc_rq;
	vpc_assoc_rsp_t *vpc_assoc_rsp;
	vpc_ret_t ret = VPC_RSP_OK;

	req = &rq->req;

	vpc_assoc_rq = (vpc_reassoc_req_t *)req->rqst;
	vpc_assoc_rq->ip = assoc_req->server_ip;
	vpc_assoc_rq->port = assoc_req->port;
	vpc_assoc_rq->batchid = assoc_req->batchid;
	strcpy(vpc_assoc_rq->clnt_obj_id, assoc_req->clnt_obj_id);
	strcpy(vpc_assoc_rq->srvr_obj_id, assoc_req->srvr_obj_id);
	req->rsp_upcall = vpc_resp_upcall;
	vpc_assoc_rq->err_upcall = vpc_clnt_err_upcall;
	vpc_assoc_rq->clnt_cookie = &clnt_reqlist;

	vpc_assoc_rsp = (vpc_assoc_rsp_t *)req->resp;
	vpc_assoc_rsp->rsp_code = VPC_ERR_INVALID;
	vpc_assoc_rsp->conn_hdl = VPC_INVALID_CONHDL;
	vpc_assoc_rsp->obj_hdl = VPC_INVALID_OBJHDL;

	rq->thr = NULL;

	ret = vpc_submit_req(VPC_REQ_REASSOC, req);
	if (ret == VPC_RSP_OK) {
		/* 10 second timeout */
		ret = vpc_wait(rq, 10);
		if (ret == 0) {
			assoc_req->rsp_code = vpc_assoc_rsp->rsp_code;
			assoc_req->conn_hdl = vpc_assoc_rsp->conn_hdl;
			assoc_req->obj_hdl = vpc_assoc_rsp->obj_hdl;
		} else {
			assoc_req->rsp_code = VPC_ERR_MSG_TIMEOUT;
		}
	}
	return ret;
}

static vpc_ret_t
do_inval_batch(vpc_req_ext_t *rq, vpcioc_invb_req_t *invb_req)
{
	vpc_req_t *req;
	vpc_invb_req_t *vpc_invb_rq;
	vpc_invb_rsp_t *vpc_invb_rsp;
	vpc_ret_t ret = VPC_RSP_OK;

	req = &rq->req;

	vpc_invb_rq = (vpc_invb_req_t *)req->rqst;
	vpc_invb_rq->conn_hdl = invb_req->conn_hdl;
	vpc_invb_rq->obj_hdl = invb_req->obj_hdl;
	vpc_invb_rq->batchid = invb_req->batchid;
	req->rsp_upcall = vpc_resp_upcall;

	vpc_invb_rsp = (vpc_invb_rsp_t *)req->resp;
	vpc_invb_rsp->rsp_code = VPC_ERR_INVALID;
	rq->thr = NULL;

	ret = vpc_submit_req(VPC_REQ_INVAL_BATCH, req);
	if (ret == VPC_RSP_OK) {
		ret = vpc_wait(rq, 10);
		if (ret == 0) {
			invb_req->rsp_code = VPC_RSP_OK;
		} else {
			invb_req->rsp_code = VPC_ERR_MSG_TIMEOUT;
		}
	}
	return ret;
}

static vpc_ret_t
do_setattr(vpc_req_ext_t *rq, vpcioc_setattr_req_t *sa_req)
{
	vpc_setattr_req_t *vpc_setattr_rq;
	vpc_setattr_rsp_t *vpc_setattr_rsp;
	vpc_req_t *req;
	vpc_ret_t ret = VPC_RSP_OK;
	void *kbuf;

	if (sa_req->data != NULL) {
		req = &rq->req;
		vpc_setattr_rq = (vpc_setattr_req_t *)req->rqst;

		if (sa_req->dlen <= PAGE_SIZE) {
			kbuf = alloc_kbuf(sa_req->dlen);
			if (kbuf == NULL) {
				printk("vpc kbuf null\n");
				return (-ENOMEM);
			}

			if (copy_from_user(kbuf, (void __user *)sa_req->data,
					sa_req->dlen)) {
				free_kbuf((void *)kbuf);
				return (-EACCES);
			}
			vpc_setattr_rq->data = kbuf;
			vpc_setattr_rq->dtype = DATA_SNGLBUF;
			vpc_setattr_rq->iovlen = 0;
		} else {
			struct kvec *iov;
			int iovlen, i, off, len;

			iov = NULL;
			iovlen = 0;
			ret = alloc_iov(sa_req->dlen, &iov, &iovlen);
			if (ret < 0)
				return (ret);
			len = sa_req->dlen;
			off = 0;
			for (i = 0; i < iovlen; i++) {
				if (copy_from_user( iov[i].iov_base,
					(void __user *) sa_req->data + off,
					MIN(PAGE_SIZE, len))) {
					free_iov(iov, iovlen);
					return (-EACCES);
				}
				off += MIN(PAGE_SIZE, len);
				len -= MIN(PAGE_SIZE, len);
			}
			vpc_setattr_rq->data = iov;
			vpc_setattr_rq->dtype = DATA_IOVEC;
			vpc_setattr_rq->iovlen = iovlen;
		}

		vpc_setattr_rq->conn_hdl = sa_req->conn_hdl;
		vpc_setattr_rq->obj_hdl = sa_req->obj_hdl;
		vpc_setattr_rq->dlen = sa_req->dlen;
		req->rsp_upcall = vpc_resp_upcall;

		vpc_setattr_rsp = (vpc_setattr_rsp_t *)req->resp;
		vpc_setattr_rsp->rsp_code = (-VPC_ERR_INVALID);

		rq->thr = NULL;
		clnt_reqlist.head = rq;

		ret = vpc_submit_req(VPC_REQ_SETATTR, req);

		if (ret == 0) {
			/* 10 seconds timeout */
			ret = vpc_wait(rq, 10);
			if (ret == 0) {
				sa_req->rsp_code = vpc_setattr_rsp->rsp_code;
			} else
				sa_req->rsp_code = VPC_ERR_MSG_TIMEOUT;
		} else
			printk("submit req err:%d\n", ret);

		clnt_reqlist.head = NULL;

		if (vpc_setattr_rq->dtype == DATA_SNGLBUF)
			free_kbuf(vpc_setattr_rq->data);
		else
			free_iov(vpc_setattr_rq->data, vpc_setattr_rq->iovlen);
	}
	return ret;
}


static vpc_ret_t
do_write(vpc_req_ext_t *rq, vpcioc_wr_req_t *wr_req)
{
	vpc_wr_req_t *vpc_wr_rq;
	vpc_wr_rsp_t *vpc_wr_rsp;
	vpc_req_t *req;
	vpc_ret_t ret = VPC_RSP_OK;
	void *kbuf;

	if (wr_req->data != NULL) {
		req = &rq->req;
		vpc_wr_rq = (vpc_wr_req_t *)req->rqst;

		if (wr_req->dlen <= PAGE_SIZE) {
			kbuf = alloc_kbuf(wr_req->dlen);
			if (kbuf == NULL) {
				printk("vpc kbuf null\n");
				return (-ENOMEM);
			}

			if (copy_from_user(kbuf, (void __user *)wr_req->data,
					wr_req->dlen)) {
				free_kbuf((void *)kbuf);
				return (-EACCES);
			}
			vpc_wr_rq->data = kbuf;
			vpc_wr_rq->dtype = DATA_SNGLBUF;
			vpc_wr_rq->iovlen = 0;
		} else {
			struct kvec *iov;
			int iovlen, i, off, len;

			iov = NULL;
			iovlen = 0;
			ret = alloc_iov(wr_req->dlen, &iov, &iovlen);
			if (ret < 0)
				return (ret);
			len = wr_req->dlen;
			off = 0;
			for (i = 0; i < iovlen; i++) {
				if (copy_from_user( iov[i].iov_base,
					(void __user *) wr_req->data + off,
					MIN(PAGE_SIZE, len))) {
					free_iov(iov, iovlen);
					return (-EACCES);
				}
				off += MIN(PAGE_SIZE, len);
				len -= MIN(PAGE_SIZE, len);
			}
			vpc_wr_rq->data = iov;
			vpc_wr_rq->dtype = DATA_IOVEC;
			vpc_wr_rq->iovlen = iovlen;
		}

		vpc_wr_rq->conn_hdl = wr_req->conn_hdl;
		vpc_wr_rq->obj_hdl = wr_req->obj_hdl;
		vpc_wr_rq->offset_l = wr_req->offset_l;
		vpc_wr_rq->offset_h = 0;
		vpc_wr_rq->dlen = wr_req->dlen;
		vpc_wr_rq->batchid = wr_req->batchid;
		req->rsp_upcall = vpc_resp_upcall;

		vpc_wr_rsp = (vpc_wr_rsp_t *)req->resp;
		vpc_wr_rsp->rsp_code = (-VPC_ERR_INVALID);

		rq->thr = NULL;
		clnt_reqlist.head = rq;

		ret = vpc_submit_req(VPC_REQ_WRITE, req);

		if (ret == 0) {
			/* 10 seconds timeout */
			ret = vpc_wait(rq, 10);
			if (ret == 0) {
				wr_req->rsp_code = vpc_wr_rsp->rsp_code;
			} else
				wr_req->rsp_code = VPC_ERR_MSG_TIMEOUT;
		} else
			printk("submit req err:%d\n", ret);

		clnt_reqlist.head = NULL;

		if (vpc_wr_rq->dtype == DATA_SNGLBUF)
			free_kbuf(vpc_wr_rq->data);
		else
			free_iov(vpc_wr_rq->data, vpc_wr_rq->iovlen);
	}
	return ret;
}

static vpc_ret_t
do_send_setattr_resp(vpcioc_resp_t *iocrsp)
{
	vpc_resp_t resp;
	vpc_setattr_rsp_t *sarsp;
	vpc_ret_t ret;

	sarsp = (vpc_setattr_rsp_t *)&resp.resp;
	sarsp->rsp_code = iocrsp->rsp_code;
	memcpy(resp.msgcookie, iocrsp->msgcookie, sizeof(u64_t));
	resp.send_done = NULL;

	ret = vpc_send_resp(iocrsp->conn_hdl, VPC_REQ_SETATTR, &resp);

	return ret;
}

static vpc_ret_t
do_send_invb_resp(vpcioc_resp_t *iocrsp)
{
	vpc_resp_t resp;
	vpc_invb_rsp_t *invbrsp;
	vpc_ret_t ret;

	invbrsp = (vpc_invb_rsp_t *)&resp.resp;
	invbrsp->rsp_code = iocrsp->rsp_code;
	memcpy(resp.msgcookie, iocrsp->msgcookie, sizeof(u64_t));
	resp.send_done = NULL;

	ret = vpc_send_resp(iocrsp->conn_hdl, VPC_REQ_INVAL_BATCH, &resp);

	return ret;
}

static vpc_ret_t
do_send_wr_resp(vpcioc_resp_t *iocrsp)
{
	vpc_resp_t resp;
	vpc_wr_rsp_t *wrrsp;
	vpc_ret_t ret;

	wrrsp = (vpc_wr_rsp_t *)&resp.resp;
	wrrsp->rsp_code = iocrsp->rsp_code;
	memcpy(resp.msgcookie, iocrsp->msgcookie, sizeof(u64_t));
	resp.send_done = NULL;

	ret = vpc_send_resp(iocrsp->conn_hdl, VPC_REQ_WRITE, &resp);

	return ret;
}

static vpc_ret_t
do_send_assoc_resp(vpcioc_resp_t *iocrsp)
{
	vpc_resp_t resp;
	vpc_assoc_rsp_t *rsp = (vpc_assoc_rsp_t *)&resp.resp;
	vpc_ret_t ret;

	rsp->obj_hdl = iocrsp->obj_hdl;
	rsp->rsp_code = iocrsp->rsp_code;
	strcpy(rsp->obj_id, iocrsp->obj_id);
	resp.send_done = NULL;
	memcpy(resp.msgcookie, iocrsp->msgcookie, sizeof(u64_t));

	ret = vpc_send_resp(iocrsp->conn_hdl, VPC_REQ_ASSOC, &resp);

	return ret;
}

int
vpcioc_ioctl(struct inode *inode, struct file *file,
		unsigned int cmd, unsigned long param)
{
	vpc_ret_t ret = VPC_RSP_OK;

	switch (cmd) {
		case VPCIOC_SRV_INIT:
		{
			vpcioc_srv_info_t iocsrvinfo;

			if (copy_from_user(&iocsrvinfo, (void __user *)param,
						sizeof(vpcioc_srv_info_t))) {
				return (-EACCES);
			}
			ret = do_srv_init(&iocsrvinfo);
		}
		break;
		case VPCIOC_SRV_STOP:
		{
			vpc_stop_srvr();
		}
		break;
		case VPCIOC_ASSOC:
		{
			vpc_req_ext_t rq;
			vpcioc_assoc_req_t assoc_req;

			if (copy_from_user(&assoc_req, (void __user *)param,
						sizeof(vpcioc_assoc_req_t)))
				return (-EACCES);

			ret = do_assoc(&rq, &assoc_req);

			if (copy_to_user((void __user *)param, &assoc_req,
					sizeof(vpcioc_assoc_req_t)))
				return (-EACCES);
		}
		break;
		case VPCIOC_REASSOC:
		{
			vpc_req_ext_t rq;
			vpcioc_reassoc_req_t assoc_req;

			if (copy_from_user(&assoc_req, (void __user *)param,
						sizeof(vpcioc_reassoc_req_t)))
				return (-EACCES);

			ret = do_reassoc(&rq, &assoc_req);

			if (copy_to_user((void __user *)param, &assoc_req,
					sizeof(vpcioc_reassoc_req_t)))
				return (-EACCES);
		}
		break;
		case VPCIOC_WRREQ:
		{
			vpcioc_wr_req_t wr_req;
			vpc_req_ext_t rq;

			if (copy_from_user(&wr_req, (void __user *)param,
						sizeof(vpcioc_wr_req_t)))
				return (-EACCES);

			ret = do_write(&rq, &wr_req);

			if (copy_to_user((void __user *)param, &wr_req,
						sizeof(vpcioc_wr_req_t)))
				return (-EACCES);
		}
		break;
		case VPCIOC_SETATTR_REQ:
		{
			vpcioc_setattr_req_t sa_req;
			vpc_req_ext_t rq;

			if (copy_from_user(&sa_req, (void __user *)param,
						sizeof(vpcioc_setattr_req_t)))
				return (-EACCES);

			ret = do_setattr(&rq, &sa_req);

			if (copy_to_user((void __user *)param, &sa_req,
						sizeof(vpcioc_setattr_req_t)))
				return (-EACCES);
		}
		break;
		case VPCIOC_RESP_WR:
		{
			vpcioc_resp_t iocrsp;

			if (copy_from_user(&iocrsp, (void __user *)param,
						sizeof(vpcioc_resp_t)))
				return (-EACCES);

			ret = do_send_wr_resp(&iocrsp);
		}
		break;
		case VPCIOC_RESP_SETATTR:
		{
			vpcioc_resp_t iocrsp;

			if (copy_from_user(&iocrsp, (void __user *)param,
						sizeof(vpcioc_resp_t)))
				return (-EACCES);

			ret = do_send_setattr_resp(&iocrsp);
		}
		break;
		case VPCIOC_RESP_INVB:
		{
			vpcioc_resp_t iocrsp;

			if (copy_from_user(&iocrsp, (void __user *)param,
						sizeof(vpcioc_resp_t)))
				return (-EACCES);

			ret = do_send_invb_resp(&iocrsp);
		}
		break;
		case VPCIOC_INVAL_BATCH:
		{
			vpcioc_invb_req_t invb_req;
			vpc_req_ext_t rq;

			if (copy_from_user(&invb_req, (void __user *)param,
						sizeof(vpcioc_invb_req_t)))
				return (-EACCES);

			ret = do_inval_batch(&rq, &invb_req);

			if (copy_to_user((void __user *)param, &invb_req,
						sizeof(vpcioc_invb_req_t)))
				return (-EACCES);
		}
		break;
		case VPCIOC_RESP_ASSOC:
		{
			vpcioc_resp_t iocrsp;

			if (copy_from_user(&iocrsp, (void __user *)param,
						sizeof(vpcioc_resp_t)))
				return (-EACCES);

			ret = do_send_assoc_resp(&iocrsp);
		}
		break;
		case VPCIOC_WAIT:
		{
			vpcioc_await_req_t iocreq;

			if (copy_from_user(&iocreq, (void __user *)param,
						sizeof(vpcioc_await_req_t)))
				return (-EACCES);

			ret = vpc_request_poll(&iocreq);
			if (ret != 0)
				return (ret);


			if (copy_to_user((void __user *)param, &iocreq,
						sizeof(vpcioc_await_req_t)))
				return (-EACCES);
		}
		break;
		case VPCIOC_CLOSE:
		{
			vpcioc_close_t clsreq;

			if (copy_from_user(&clsreq, (void __user *)param,
					sizeof(vpcioc_close_t)))
				return (-EACCES);

			ret = vpc_close_conn(clsreq.conn_hdl);
			if (ret != 0)
				return (-EINVAL);
		}
		break;
		case VPCIOC_PERF_CLNT:
		{
			vpcioc_perf_t prq;

			if (copy_from_user(&prq, (void __user *)param,
						sizeof(vpcioc_perf_t)))
					return (-EACCES);
			do_perf_test(prq.conn_hdl, prq.mbytes, prq.iolen,
					prq.qdepth);
		}
		break;
		default:
			return (-EINVAL);
	}
	return ret;
}

void
vpcioc_init(void)
{
	vpc_qent_t *qe;
	vpc_kbuf_t *kbuf;
	int i;

	/* initialize vpc kmem cache */
	for (i = 0; i < MAX_OUTSTANDING; i++) {
		qe = kmalloc(sizeof(vpc_qent_t), GFP_KERNEL);
		qe->next = NULL;
		if (qent_tl == NULL)
			qent_hd = qent_tl = qe;
		else {
			qent_tl->next = qe;
			qent_tl = qe;
		}
		kbuf = (vpc_kbuf_t *)kmalloc(PAGE_SIZE, GFP_KERNEL);
		kbuf->next = NULL;
		if (kbuf_tl == NULL)
			kbuf_hd = kbuf_tl = kbuf;
		else {
			kbuf_tl->next = kbuf;
			kbuf_tl = kbuf;
		}
	}

	spin_lock_init(&await_qlock);
	spin_lock_init(&qentlock);
	spin_lock_init(&kbuflock);
}

void 
vpcioc_exit(void)
{
	vpc_qent_t *qe, *pe;
	vpc_kbuf_t *kbuf, *pbuf;

	spin_lock(&await_qlock);
	qe = await_q_hd;
	while (qe != NULL) {
		if (qe->req != NULL)
			vpc_req_free(qe->type, qe->req);
		pe = qe;
		qe = qe->next;
		kfree(pe);
	}
	spin_unlock(&await_qlock);

	spin_lock(&qentlock);
	qe = qent_hd;
	while (qe != NULL) {
		pe = qe;
		qe = qe->next;
		kfree(pe);
	}
	spin_unlock(&qentlock);

	spin_lock(&kbuflock);
	kbuf = kbuf_hd;
	while (kbuf != NULL) {
		pbuf = kbuf;
		kbuf = kbuf->next;
		kfree(kbuf);
	}
	spin_unlock(&kbuflock);
}
