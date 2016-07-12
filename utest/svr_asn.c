#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <aio.h>
#include <pthread.h>
#include <string.h>
#ifdef	__KSOCK
#include "vpc.h"
#include <signal.h>
#else
#include "vpc_api.h"
#endif

#define	MAX_Q		4
#define	MAX_FILES	8
#define	SERVER_VSA_ID	0xabcd
#define	BUFSIZE		(64 * 1024)
#define MAX_DIR		32

typedef struct {
	void *next;
} free_list_t;

typedef struct {
	struct aiocb *aio;
	char id[sizeof(u64_t)];
	u32_t conn_hdl;
	u32_t obj_hdl;
} req_info_t;

struct obj_file {
	int fd;
	int batchid;
	char coname[MAX_OBJ_ID_LEN];
};

const char *const vpc_err_str[] = { VPC_ERR_CODES };
static free_list_t *free_bufs;
static struct aiocb *m_aiocb[MAX_Q];
static int aio_freehd;
static int aio_freetl;
static struct obj_file files[MAX_FILES];
static char svr_dirpath[MAX_DIR];
static int free_filehd;
static int free_filetl;
static int vpc_devfd;
static pthread_cond_t srv_cond;
static pthread_mutex_t srv_lock;

static pthread_cond_t aio_cond;
static pthread_mutex_t aio_lock;
static int n_aio[MAX_FILES];
static int perftest;

static void aio_cmpl_hdlr(sigval_t sigval);

static struct aiocb *
get_aiocb(void)
{
	struct aiocb *aio;

	if (aio_freehd == aio_freetl)
		return NULL;

	aio = m_aiocb[aio_freehd];
	m_aiocb[aio_freehd] = NULL;

	aio_freehd = ((aio_freehd + 1) % MAX_Q);

	return aio;
}

static void
rlse_aiocb(struct aiocb *aio)
{
	aio_freetl = ((aio_freetl + 1) % MAX_Q);
	m_aiocb[aio_freetl] = aio;
}

static int
get_file_slot(void)
{
	int slot;

	slot = free_filehd;
	free_filehd = ((free_filehd + 1) % MAX_FILES);
}

static void
add_free_buf(void *buf)
{
	if (free_bufs == NULL) {
		free_bufs = (free_list_t *)buf;
		free_bufs->next = NULL;
	} else {
		((free_list_t *)buf)->next = free_bufs;
		free_bufs = buf;
	}
}

static void *
get_free_buf(void)
{
	free_list_t *buf;

	if (free_bufs == NULL)
		return NULL;
	buf = free_bufs;
	free_bufs = buf->next;

	return (void *)buf;
}

static int
init_marlin(int devfd)
{
	int i;
	void *buf;

	for (i = 0; i < MAX_Q; i++) {
		buf = malloc(BUFSIZE);
		if (buf == NULL) {
			printf("Memory alloc fail\n");
			return -1;
		}
		add_free_buf(buf);
	}

	for (i = 0; i < MAX_Q; i++) {
		m_aiocb[i] = (struct aiocb *)malloc(sizeof(struct aiocb));
	}
	aio_freehd = 0;
	aio_freetl = (MAX_Q - 1);

	free_filehd = 0;
	free_filetl = (MAX_FILES - 1);

	pthread_mutex_init(&aio_lock, NULL);
	pthread_cond_init(&aio_cond, NULL);

	return 0;
}


static int
send_write_resp(u32_t conn_hdl, int rsp_code, char *cookie, int cookie_len)
{
	int ret;
#ifdef	__KSOCK
	vpcioc_resp_t resp;
#else
	vpc_resp_t resp;
	vpc_wr_rsp_t *rsp = (vpc_wr_rsp_t *)&resp.resp;
#endif

#ifdef	__KSOCK
	resp.rsp_code = rsp_code;
	resp.conn_hdl = conn_hdl;
	memcpy(resp.msgcookie, cookie, cookie_len);
	ret = ioctl(vpc_devfd, VPCIOC_RESP_WR, &resp);
#else
	rsp->rsp_code = rsp_code;
	resp.send_done = NULL;
	memcpy(resp.msgcookie, cookie, cookie_len);
	ret = vpc_send_resp(conn_hdl, VPC_REQ_WRITE, &resp);
#endif
	return ret;
}

static int
send_setattr_resp(u32_t conn_hdl, int rsp_code, char *cookie, int cookie_len)
{
	int ret;
#ifdef __KSOCK
	vpcioc_resp_t resp;
#else
	vpc_resp_t resp;
	vpc_setattr_rsp_t *rsp = (vpc_setattr_rsp_t *)&resp.resp;
#endif

#ifdef	__KSOCK
	resp.rsp_code = rsp_code;
	resp.conn_hdl = conn_hdl;
	memcpy(resp.msgcookie, cookie, cookie_len);
	ret = ioctl(vpc_devfd, VPCIOC_RESP_SETATTR, &resp);
#else
	rsp->rsp_code = rsp_code;
	resp.send_done = NULL;
	memcpy(resp.msgcookie, cookie, cookie_len);
	ret = vpc_send_resp(conn_hdl, VPC_REQ_SETATTR, &resp);
#endif
	return ret;
}

static int
send_invb_resp(u32_t conn_hdl, int rsp_code, char *cookie, int cookie_len)
{
	int ret;
#ifdef __KSOCK
	vpcioc_resp_t resp;
#else
	vpc_resp_t resp;
	vpc_invb_rsp_t *rsp = (vpc_invb_rsp_t *)&resp.resp;
#endif

#ifdef	__KSOCK
	resp.rsp_code = rsp_code;
	resp.conn_hdl = conn_hdl;
	memcpy(resp.msgcookie, cookie, cookie_len);
	ret = ioctl(vpc_devfd, VPCIOC_RESP_INVB, &resp);
#else
	rsp->rsp_code = rsp_code;
	resp.send_done = NULL;
	memcpy(resp.msgcookie, cookie, cookie_len);
	ret = vpc_send_resp(conn_hdl, VPC_REQ_INVAL_BATCH, &resp);
#endif
	return ret;
}

static int
send_assoc_resp(u32_t conn_hdl, int rsp_code, u32_t obj_hdl, char *obj_id,
		char *cookie, int cookie_len)
{
	int ret;
#ifdef	__KSOCK
	vpcioc_resp_t resp;
#else
	vpc_resp_t resp;
	vpc_assoc_rsp_t *rsp = (vpc_assoc_rsp_t *)&resp.resp;
#endif

#ifdef	__KSOCK
	resp.obj_hdl = obj_hdl;
	resp.conn_hdl = conn_hdl;
	resp.rsp_code = rsp_code;
	if (obj_id != NULL)
		strcpy(resp.obj_id, obj_id);
	else
		strcpy(resp.obj_id, "NULL_OBJ");
	memcpy(resp.msgcookie, cookie, cookie_len);
	ret = ioctl(vpc_devfd, VPCIOC_RESP_ASSOC, &resp);
#else
	rsp->obj_hdl = obj_hdl;
	rsp->rsp_code = rsp_code;
	if (obj_id != NULL)
		strcpy(rsp->obj_id, obj_id);
	else
		strcpy(rsp->obj_id, "NULL_OBJ");
	resp.send_done = NULL;
	memcpy(resp.msgcookie, cookie, cookie_len);
	ret = vpc_send_resp(conn_hdl, VPC_REQ_ASSOC, &resp);
#endif
	return ret;
}

int srv_reqs;

static void
handle_setattr_req(u32_t conn_hdl, void *arg)
{
	FILE *fp;
#ifdef	__USOCK
	vpc_setattr_req_t *sareq;
	vpc_req_t *req = (vpc_req_t *)arg;
#else
	vpcioc_setattr_req_t *sareq;
	vpcioc_await_req_t *req = (vpcioc_await_req_t*)arg;
#endif
	char msgcookie[sizeof(u64_t)];
	char *data_buf;
	char fname[4*MAX_DIR];

#ifdef	__USOCK
	sareq = (vpc_setattr_req_t *)req->rqst;
	memcpy(msgcookie, req->msgcookie, sizeof(u64_t));
	data_buf = get_free_buf();
	if (sareq->dtype == DATA_IOVEC) {
		int i;
		void *ptr;
		struct iovec *iov;

		i = 0;
		ptr = data_buf;
		iov = (struct iovec*)sareq->data;
		while (i < sareq->iovlen) {
			memcpy(ptr, iov[i].iov_base, iov[i].iov_len);
			ptr += iov[i].iov_len;
			i++;
		}
	} else
		memcpy(data_buf, sareq->data, sareq->dlen);
#else
	sareq = (vpcioc_setattr_req_t *)req->reqmsg;
	data_buf = req->dbuf;
	sareq->dlen = req->buflen;
	memcpy(msgcookie, sareq->msgcookie, sizeof(u64_t));
#endif
	/*
	 * Open ATTR file
	 */
	sprintf(fname, "%s/ATTR", files[sareq->obj_hdl].coname);
	fp = fopen(fname, "a");
	if (fp == NULL) {
		send_setattr_resp(conn_hdl, VPC_ERR_SETATTR_FAIL,
					msgcookie, sizeof(u64_t));
#ifdef	__USOCK
		vpc_req_free(VPC_REQ_SETATTR, req);
#endif
		return;
	}
	fprintf(fp, "%s\n", data_buf);
	printf("Set ATTR %s on OBJ: %s\n", data_buf, files[sareq->obj_hdl].coname);
	fclose(fp);
#ifdef	__USOCK
	vpc_req_free(VPC_REQ_SETATTR, req);
#endif
	send_setattr_resp(conn_hdl, VPC_RSP_OK,
				msgcookie, sizeof(u64_t));
}

static void
handle_write_req(u32_t conn_hdl, void *arg)
{
#ifdef	__USOCK
	vpc_wr_req_t *wrreq;
	vpc_req_t *req = (vpc_req_t *)arg;
#else
	vpcioc_wr_req_t *wrreq;
	vpcioc_await_req_t *req = (vpcioc_await_req_t*)arg;
#endif
	char msgcookie[sizeof(u64_t)];
	struct aiocb *aio;
	req_info_t *reqinfo;
	char *data_buf;

#ifdef	__USOCK
	wrreq = (vpc_wr_req_t *)req->rqst;
	memcpy(msgcookie, req->msgcookie, sizeof(u64_t));
	data_buf = get_free_buf();
	if (wrreq->dtype == DATA_IOVEC) {
		int i;
		void *ptr;
		struct iovec *iov;

		i = 0;
		ptr = data_buf;
		iov = (struct iovec*)wrreq->data;
		while (i < wrreq->iovlen) {
			memcpy(ptr, iov[i].iov_base, iov[i].iov_len);
			ptr += iov[i].iov_len;
			i++;
		}
	} else
		memcpy(data_buf, wrreq->data, wrreq->dlen);
#else
	wrreq = (vpcioc_wr_req_t *)req->reqmsg;
	data_buf = req->dbuf;
	wrreq->dlen = req->buflen;
	memcpy(msgcookie, wrreq->msgcookie, sizeof(u64_t));
#endif
	if (perftest) {
#ifdef	__KSOCK
		add_free_buf(wrreq->data);
#else
		vpc_req_free(VPC_REQ_WRITE, req);
#endif
		send_write_resp(conn_hdl, VPC_RSP_OK, msgcookie,
				sizeof(u64_t));
		srv_reqs++;
		return;
	}

	aio = get_aiocb();
	if (aio == NULL) {
#ifdef	__KSOCK
		add_free_buf(wrreq->data);
#else
		vpc_req_free(VPC_REQ_WRITE, req);
#endif
		send_write_resp(conn_hdl, VPC_ERR_QFULL,
				msgcookie,
				sizeof(u64_t));
		return;
	}
	reqinfo = (req_info_t *)malloc(sizeof(req_info_t));
	if (reqinfo == NULL) {
		perror("reqinfo");
#ifdef	__USOCK
		vpc_req_free(VPC_REQ_WRITE, req);
#endif
		return;
	}
	/*
	 * switch files on batchid change
	 */
	if (files[wrreq->obj_hdl].batchid != wrreq->batchid) {
		char fname[4*MAX_DIR];
		int fd;

		printf("new batchid\n");
		/* create new data file */
		sprintf(fname, "%s/%d", files[wrreq->obj_hdl].coname,
				wrreq->batchid);
		fd = open(fname, O_CREAT | O_RDWR | O_TRUNC,
				S_IRUSR | S_IWUSR |
				S_IRGRP | S_IWGRP);
		if (fd < 0) {
			send_write_resp(conn_hdl, VPC_ERR_BATCH_CREAT,
					msgcookie, sizeof(u64_t));
#ifdef	__USOCK
			vpc_req_free(VPC_REQ_WRITE, req);
#endif
			return;
		}
		close(files[wrreq->obj_hdl].fd);
		files[wrreq->obj_hdl].fd = fd;
		files[wrreq->obj_hdl].batchid = wrreq->batchid;
		/* update persistent last batch record */
		sprintf(fname, "%s/lastbatch", files[wrreq->obj_hdl].coname);
		fd = open(fname, O_CREAT | O_RDWR | O_TRUNC,
				S_IRUSR | S_IWUSR |
				S_IRGRP | S_IWGRP);
		if (fd < 0) {
			send_write_resp(conn_hdl, VPC_ERR_BATCH_CREAT,
					msgcookie, sizeof(u64_t));
#ifdef	__USOCK
			vpc_req_free(VPC_REQ_WRITE, req);
#endif
			return;
		}
		sprintf(fname, "%d\n", wrreq->batchid);
		write(fd, fname, strlen(fname));
		close(fd);
	}
	aio->aio_fildes = files[wrreq->obj_hdl].fd;
	aio->aio_buf = data_buf;
	aio->aio_nbytes = wrreq->dlen;
	aio->aio_offset = wrreq->offset_l;

	reqinfo->aio = (void *)aio;
	memcpy(reqinfo->id, msgcookie, sizeof(u64_t));
	reqinfo->conn_hdl = conn_hdl;
	reqinfo->obj_hdl = wrreq->obj_hdl;

	aio->aio_sigevent.sigev_notify = SIGEV_THREAD;
	aio->aio_sigevent.sigev_notify_function = aio_cmpl_hdlr;
	aio->aio_sigevent.sigev_notify_attributes = NULL;
	aio->aio_sigevent.sigev_value.sival_ptr = reqinfo;
	aio_write(aio);

	pthread_mutex_lock(&aio_lock);
	n_aio[wrreq->obj_hdl]++;
	pthread_mutex_unlock(&aio_lock);
#ifdef	__USOCK
	vpc_req_free(VPC_REQ_WRITE, req);
#endif
}

static void
handle_invb_req(u32_t conn_hdl, void *arg)
{
#ifdef	__USOCK
	vpc_invb_req_t *invbreq;
	vpc_req_t *req = (vpc_req_t *)arg;
#else
	vpcioc_invb_req_t *invbreq;
	vpcioc_await_req_t *req = (vpcioc_await_req_t*)arg;
#endif
	char msgcookie[sizeof(u64_t)];
	req_info_t *reqinfo;

#ifdef	__USOCK
	invbreq = (vpc_invb_req_t *)req->rqst;
	memcpy(msgcookie, req->msgcookie, sizeof(u64_t));
#else
	invbreq = (vpcioc_invb_req_t *)req->reqmsg;
	memcpy(msgcookie, invbreq->msgcookie, sizeof(u64_t));
#endif
	if (files[invbreq->obj_hdl].batchid == invbreq->batchid) {
		/* Cannot invalidate active batchid */
		send_invb_resp(conn_hdl, VPC_ERR_ACTV_BATCH, msgcookie,
				sizeof(u64_t));
#ifdef	__USOCK
		vpc_req_free(VPC_REQ_WRITE, req);
#endif
		return;
	} else {
		char fname[4*MAX_DIR];
		int ret;

		/* delete file fname */
		sprintf(fname, "%s/%d", files[invbreq->obj_hdl].coname,
				invbreq->batchid);
		ret = unlink(fname);
		if (ret < 0) {
			/* No such file? */
			send_invb_resp(conn_hdl, VPC_ERR_BATCH_INVAL, msgcookie,
				sizeof(u64_t));
#ifdef	__USOCK
			vpc_req_free(VPC_REQ_WRITE, req);
#endif
			return;
		}
		send_invb_resp(conn_hdl, VPC_RSP_OK, msgcookie,
				sizeof(u64_t));
	}
#ifdef	__USOCK
	vpc_req_free(VPC_REQ_INVAL_BATCH, req);
#endif
	return;
}

#ifdef __KSOCK
static void
handle_disassoc_req(u32_t conn_hdl, void *arg)
{
	vpcioc_disassoc_req_t *disassocrq;
	vpcioc_await_req_t *req = (vpcioc_await_req_t *)arg;
	int fd;

	disassocrq = (vpcioc_disassoc_req_t *)req->reqmsg;

	fd = files[disassocrq->obj_hdl].fd;
	close(fd);
	/* wait for all aio to finish */
	pthread_mutex_lock(&aio_lock);
	while (n_aio[disassocrq->obj_hdl] > 0)
		pthread_cond_wait(&aio_cond, &aio_lock);
	pthread_mutex_unlock(&aio_lock);
	/* release obj_hdl */
	files[disassocrq->obj_hdl].fd = 0;
	printf("Disassociated obj hdl:%d\n", disassocrq->obj_hdl);
}
#endif

static void
handle_assoc_req(u32_t conn_hdl, void *arg)
{
	char ctname[2*MAX_DIR], fname[4*MAX_DIR], coname[3*MAX_DIR];
	int fd, slot, ret;
	struct stat stbuf;
	char msgcookie[sizeof(u64_t)];
#ifdef	__USOCK
	vpc_assoc_req_t *assocreq;
	vpc_req_t *req = (vpc_req_t *)arg;

	assocreq = (vpc_assoc_req_t *)req->rqst;
	memcpy(msgcookie, req->msgcookie, sizeof(u64_t));
	printf("flags: %d\n", assocreq->flags);
	sprintf(ctname, "%s/%s", svr_dirpath, assocreq->srvr_ct_id);
	sprintf(coname, "%s/%s/%s", svr_dirpath, assocreq->srvr_ct_id,
			assocreq->clnt_obj_id);
#else
	vpcioc_assoc_req_t *assocreq;
	vpcioc_await_req_t *req = (vpcioc_await_req_t*)arg;

	assocreq = (vpcioc_assoc_req_t *)req->reqmsg;
	memcpy(msgcookie, assocreq->msgcookie, sizeof(u64_t));
	sprintf(ctname, "%s/%s", svr_dirpath, assocreq->ct_id);
	sprintf(coname, "%s/%s/%s", svr_dirpath, assocreq->ct_id,
			assocreq->obj_id);
#endif

	if (assocreq->flags & VPC_ASSOC_FLAG_PERF) {
		send_assoc_resp(conn_hdl, VPC_RSP_OK, 0, "fake-obj",
				msgcookie, sizeof(u64_t));
		perftest = 1;
		return;
	}

	ret = stat(ctname, &stbuf);
	if (ret < 0) {
		send_assoc_resp(conn_hdl, VPC_ERR_INVAL_CTID,
				VPC_INVALID_OBJHDL, NULL,
				msgcookie, sizeof(u64_t));
		return;
	}

	if (assocreq->flags & VPC_ASSOC_FLAG_CREAT) {
		int fd1;

		fd = mkdir(coname, S_IRUSR | S_IWUSR | S_IXUSR |
				S_IRGRP | S_IWGRP | S_IXGRP);
		if (fd < 0) {
			send_assoc_resp(conn_hdl, VPC_ERR_CREAT_FAIL,
					VPC_INVALID_OBJHDL, NULL,
					msgcookie,
					sizeof(u64_t));
			return ;
		}
		sprintf(fname, "%s/%d", coname, assocreq->batchid);
		fd = open(fname, O_CREAT | O_RDWR | O_TRUNC,
				S_IRUSR | S_IWUSR |
				S_IRGRP | S_IWGRP);
		if (fd < 0) {
			send_assoc_resp(conn_hdl, VPC_ERR_CREAT_FAIL,
					VPC_INVALID_OBJHDL, NULL,
					msgcookie,
					sizeof(u64_t));
			return ;
		}
		/* update persistent last batch record */
		sprintf(fname, "%s/lastbatch", coname);
		fd1 = open(fname, O_CREAT | O_RDWR | O_TRUNC,
				S_IRUSR | S_IWUSR |
				S_IRGRP | S_IWGRP);
		if (fd1 < 0) {
			close(fd);
			send_assoc_resp(conn_hdl, VPC_ERR_CREAT_FAIL,
					VPC_INVALID_OBJHDL, NULL,
					msgcookie,
					sizeof(u64_t));
			return ;
		}
		sprintf(fname, "%d\n", assocreq->batchid);
		write(fd1, fname, strlen(fname));
		close(fd1);
	} else {
		sprintf(fname, "%s/%d", coname, assocreq->batchid);
		fd = open(fname, O_CREAT | O_RDWR | O_TRUNC,
				S_IRUSR | S_IWUSR |
				S_IRGRP | S_IWGRP);
		if (fd < 0) {
			send_assoc_resp(conn_hdl, VPC_ERR_NOT_FOUND,
					VPC_INVALID_OBJHDL, NULL,
					msgcookie,
					sizeof(u64_t));
			return ;
		}
	}
	slot = get_file_slot();
	if (slot < 0) {
		close(fd);
		send_assoc_resp(conn_hdl, VPC_ERR_OBJ_EXCEEDED,
				VPC_INVALID_OBJHDL, NULL,
				msgcookie,
				sizeof(u64_t));
		return ;
	}

	files[slot].fd = fd;
	files[slot].batchid = assocreq->batchid;
	strcpy(files[slot].coname, coname);
#ifdef __USOCK
	sprintf(fname, "%s.%s", assocreq->srvr_ct_id, assocreq->clnt_obj_id);
#else
	sprintf(fname, "%s.%s", assocreq->ct_id, assocreq->obj_id);
#endif
	send_assoc_resp(conn_hdl, VPC_RSP_OK, slot, fname,
			msgcookie, sizeof(u64_t));
}

static void
handle_reassoc_req(u32_t conn_hdl, void *arg)
{
	char ctpath[2*MAX_DIR], fname[4*MAX_DIR], copath[3*MAX_DIR];
	char ctname[MAX_DIR], *p, *objname;
	int fd, slot, ret, found, fd1;
	struct stat stbuf;
	char msgcookie[sizeof(u64_t)];
#ifdef	__USOCK
	vpc_reassoc_req_t *assocreq;
	vpc_req_t *req = (vpc_req_t *)arg;

	assocreq = (vpc_reassoc_req_t *)req->rqst;
	memcpy(msgcookie, req->msgcookie, sizeof(u64_t));
#else
	vpcioc_reassoc_req_t *assocreq;
	vpcioc_await_req_t *req = (vpcioc_await_req_t*)arg;

	assocreq = (vpcioc_reassoc_req_t *)req->reqmsg;
	memcpy(msgcookie, assocreq->msgcookie, sizeof(u64_t));
#endif

	strcpy(ctname, assocreq->srvr_obj_id);
	p = ctname;
	found = 0;
	while (*p != '\0') {
		if (*p == '.') {
			*p = '\0';
			objname = p + 1;
			found = 1;
			break;
		}
		p++;
	}
	if (!found)
		goto err_objid;

	sprintf(ctpath, "%s/%s", svr_dirpath, ctname);
	// printf("Re-assoc with CT: %s\n", ctpath);
	ret = stat(ctpath, &stbuf);
	if (ret < 0)
		goto err_objid;

	sprintf(copath, "%s/%s/%s", svr_dirpath, ctname, objname);
	printf("Re-assoc with Obj: %s\n", copath);
	ret = stat(copath, &stbuf);
	if (ret < 0)
		goto err_objid;

	sprintf(fname, "%s/%d", copath, assocreq->batchid);
	fd = open(fname, O_CREAT | O_RDWR | O_TRUNC,
				S_IRUSR | S_IWUSR |
				S_IRGRP | S_IWGRP);
	if (fd < 0) {
		send_assoc_resp(conn_hdl, VPC_ERR_CREAT_FAIL,
				VPC_INVALID_OBJHDL, NULL,
				msgcookie, sizeof(u64_t));
		return ;
	}
	/* update persistent last batch record */
	sprintf(fname, "%s/lastbatch", copath);
	fd1 = open(fname, O_CREAT | O_RDWR | O_TRUNC,
				S_IRUSR | S_IWUSR |
				S_IRGRP | S_IWGRP);
	if (fd1 < 0) {
		close(fd);
		send_assoc_resp(conn_hdl, VPC_ERR_CREAT_FAIL,
				VPC_INVALID_OBJHDL, NULL,
				msgcookie,
				sizeof(u64_t));
		return ;
	}
	sprintf(fname, "%d", assocreq->batchid);
	write(fd1, fname, strlen(fname));
	close(fd1);

	/* get obj handle */
	slot = get_file_slot();
	if (slot < 0) {
		close(fd);
		send_assoc_resp(conn_hdl, VPC_ERR_OBJ_EXCEEDED,
				VPC_INVALID_OBJHDL, NULL,
				msgcookie,
				sizeof(u64_t));
		return ;
	}

	files[slot].fd = fd;
	files[slot].batchid = assocreq->batchid;
	strcpy(files[slot].coname, copath);
	send_assoc_resp(conn_hdl, VPC_RSP_OK, slot, NULL,
			msgcookie, sizeof(u64_t));
	return;

err_objid:
	send_assoc_resp(conn_hdl, VPC_ERR_INVAL_OBJID,
			VPC_INVALID_OBJHDL, NULL,
			msgcookie, sizeof(u64_t));
	return;
}

static int
server_req_upcall(u32_t conn_hdl, int type, void *arg)
{
	if (type == VPC_REQ_WRITE) {
		handle_write_req(conn_hdl, arg);
	} else if (type == VPC_REQ_INVAL_BATCH) {
		handle_invb_req(conn_hdl, arg);
	} else if (type == VPC_REQ_ASSOC) {
		handle_assoc_req(conn_hdl, arg);
	} else if (type == VPC_REQ_REASSOC) {
		handle_reassoc_req(conn_hdl, arg);
	} else if (type == VPC_REQ_SETATTR) {
		handle_setattr_req(conn_hdl, arg);
	}
#ifdef	__KSOCK
	else if (type == VPC_REQ_DISASSOC) {
		handle_disassoc_req(conn_hdl, arg);
	}
#endif
	return 0;
}

static int
server_init(int devfd, in_addr_t ip, int port)
{
	int ret;
#ifdef	__KSOCK
	vpcioc_srv_info_t srv_info;
#else
	vpc_srvinfo_t srv_info;
#endif

	srv_info.ip = ip;
	srv_info.port = port;
	srv_info.vsa_id = SERVER_VSA_ID;

#ifdef __KSOCK
	ret = ioctl(devfd, VPCIOC_SRV_INIT, &srv_info);
#else
	vpc_protocol_init();
	srv_info.req_upcall = server_req_upcall;
	ret = vpc_init_srvr(&srv_info);
#endif
	return ret;
}

static void
aio_cmpl_hdlr(sigval_t sigval)
{
	req_info_t *req;
	int ret;

	req = (req_info_t *)sigval.sival_ptr;

	pthread_mutex_lock(&aio_lock);
	n_aio[req->obj_hdl]--;
	if (n_aio[req->obj_hdl] == 0)
		pthread_cond_signal(&aio_cond);
	pthread_mutex_unlock(&aio_lock);

	if (aio_error((struct aiocb *)req->aio) == 0) {
		ret = aio_return(req->aio);
		if (ret < 0)
			send_write_resp(req->conn_hdl, VPC_ERR_WRFAIL,
					req->id,
					sizeof(u64_t));
		else
			send_write_resp(req->conn_hdl, VPC_RSP_OK,
					req->id,
					sizeof(u64_t));
	}
	/* Free stuff */
	add_free_buf((void *)req->aio->aio_buf);
	rlse_aiocb(req->aio);
	free(req);
}

#ifdef __KSOCK
void
ctrl_c(int sig)
{
	int ret;

	printf("Got ctrl-C\n");
	if (vpc_devfd > 0)
		ioctl(vpc_devfd, VPCIOC_SRV_STOP, NULL);
	exit(0);
}
#endif

static void
marlin_loop(int devfd)
{
#ifdef	__KSOCK
	int ret, slot;
	int fd;
	vpcioc_await_req_t *req;
	struct sigaction new;

	vpc_devfd = devfd;
	req = malloc(sizeof(vpcioc_await_req_t));
	req->dbuf = get_free_buf();
	if (req->dbuf == NULL)
		return;

	new.sa_handler = ctrl_c;
	sigemptyset(&new.sa_mask);
	new.sa_flags = 0;
	sigaction(SIGINT, &new, NULL);

	for (;;) {
		/* wait for a request */
		req->buflen = BUFSIZE;
		ret = ioctl(devfd, VPCIOC_WAIT, req);
		if (ret < 0) {
			printf("IOC_WAIT returned: %d\n", ret);
			add_free_buf(req->dbuf);
			free(req);
			return;
		}
		/* call req handler */
		server_req_upcall(req->conn_hdl, req->type, req->reqmsg);

	}
#else
	pthread_cond_init(&srv_cond, NULL);
	pthread_mutex_init(&srv_lock, NULL);
	pthread_cond_wait(&srv_cond, &srv_lock);
#endif
}

int
main(int argc, char**argv)
{
	in_addr_t srv_ip;
	int port, fd, devfd;
	struct stat stbuf;
	int ret;

	if (argc < 6) {
		printf("Usage:\n");
		printf("srvr -s <ip> -p <port> -d <dir>\n");
		exit(1);
	}
	if (strcmp(argv[1], "-s") || strcmp(argv[3], "-p")) {
		printf("Usage:\n");
		printf("clnt -s <ip> -p <port> -d <dir>\n");
		exit(1);
	}

	srv_ip = inet_addr(argv[2]);
	if (srv_ip == (in_addr_t)(-1)) {
		printf("Invalid ip addr.\n");
		exit(1);
	}

	port = strtol(argv[4], NULL, 10);

	if (!strcmp(argv[5], "-d")) {

		/*
		 * Test Svr Dir exists
		 */
		ret = stat(argv[6], &stbuf);
		if (ret < 0 ||
			!S_ISDIR(stbuf.st_mode)) {
			printf("Failed to directory check on %s\n", argv[6]);
			exit(1);
		}
		strcpy(svr_dirpath, argv[6]);
		perftest = 0;
	}


#ifdef	__KSOCK
	devfd = open("/dev/vpc", O_RDWR);
	if (devfd < 0) {
		printf("Failed to open VPC device\n");
		exit(1);
	}
#endif


	ret = server_init(devfd, srv_ip, port);
	if (ret != 0) {
		printf("Error code %s\n", vpc_err_str[ret]);
		exit(1);
	}

	ret = init_marlin(devfd);
	if (ret < 0) {
		printf("Error code %d\n", ret);
		exit(1);
	}
	marlin_loop(devfd);

	exit(0);
}
