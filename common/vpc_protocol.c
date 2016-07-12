#include <vpc_api.h>
#include <osl.h>
#include "vpc_transp.h"
#include "vpc_protocol.h"

#ifdef	VPC_LOCK_DEBUG
#undef	SPIN_LOCK
#undef SPIN_UNLOCK

#define	SPIN_LOCK(lk)	do { \
				sprintf(lock_logp, "%s lock %p\n", \
						__FUNCTION__, lk); \
				lock_logp += strlen(lock_logp); \
			} while (0);
#define	SPIN_UNLOCK(lk)	do { \
				sprintf(lock_logp, "%s unlock %p\n", \
						__FUNCTION__, lk); \
				lock_logp += strlen(lock_logp); \
			} while (0);
#endif

#define	MIN(x, y)		((x) < (y) ? (x) : (y))
#define	INVALID_IDX		(0)
#define	MAX_CONN		16
#define	CACHE_ENT_N		4096	// 16384 for WAM2 driver to work with mkfs
#define	MAX_RQRSP_SZ		512
#define	VPC_BUF_LEN		4096
#define	SMALL_IOV		16
#define	M_WAIT			1
#define	M_NOWAIT		0

typedef struct _msgb {
	struct _msgb *next;
	char data[MAX_RQRSP_SZ - sizeof(void *)];
} msgbuf_t;

typedef struct _dbuf {
	struct _dbuf *next;
} dbuf_t;

SPIN_LOCK_T	conn_arr_lock;
SPIN_LOCK_T	msgbuf_lock;
THR_WAITQ_T	mb_wait;
SPIN_LOCK_T	md_lock;
THR_WAITQ_T	md_wait;
SPIN_LOCK_T	dbuf_lock;
SPIN_LOCK_T	iov_lock;
static vpc_conn_t *conn_arr[MAX_CONN];
static int (*asn_req_upcall)(u32_t conn_hdl, int type, void *arg);
static void (*asn_err_upcall)(u32_t conn_hdl, u32_t obj_hdl);
static u32_t my_vsaid;
static msgbuf_t *msgbuf_hd;
static dbuf_t *dbuf_hd;
static struct msg_desc *msgd_hd;
static dbuf_t *smiov_hd;
static char lock_log[8192];
static char *lock_logp;

static void vpc_conn_err_hdlr(void *arg);
static vpc_ret_t vpc_send_hb(vpc_conn_t *conn);
static vpc_ret_t vpc_send_hb_rsp(vpc_conn_t *conn);
static vpc_ret_t try_send_mdesc(vpc_conn_t *conn, struct msg_desc *mdesc);

static int
conn_add(vpc_conn_t *conn)
{
	int i;

	SPIN_LOCK(&conn_arr_lock);
	for (i = 1; i < MAX_CONN; i++) {
		if (conn_arr[i] == NULL) {
			conn_arr[i] = conn;
			conn->conn_idx = i;
			SPIN_UNLOCK(&conn_arr_lock);
			return i;
		}
	}
	SPIN_UNLOCK(&conn_arr_lock);
	return INVALID_IDX;
}

static void
conn_del(u32_t conn_idx)
{
	SPIN_LOCK(&conn_arr_lock);
	conn_arr[conn_idx] = NULL;
	SPIN_UNLOCK(&conn_arr_lock);
}

static vpc_conn_t *
conn_get(u32_t conn_idx)
{
	vpc_conn_t *conn;

	SPIN_LOCK(&conn_arr_lock);
	conn = conn_arr[conn_idx];
	SPIN_UNLOCK(&conn_arr_lock);
	return conn;
}

static void *
alloc_msgbuf(int flag)
{
	msgbuf_t *msgbuf;

	SPIN_LOCK(&msgbuf_lock);
retry:
	if (msgbuf_hd == NULL) {
		if (flag != M_WAIT) {
			SPIN_UNLOCK(&msgbuf_lock);
			return NULL;
		} else {
			OS_THR_WAIT(&mb_wait, &msgbuf_lock);
			goto retry;
		}
	}
	msgbuf = msgbuf_hd;
	msgbuf_hd = msgbuf->next;
	SPIN_UNLOCK(&msgbuf_lock);
	return (void *)msgbuf;
}

static void
free_msgbuf(msgbuf_t *msgbuf)
{
	SPIN_LOCK(&msgbuf_lock);
	msgbuf->next = msgbuf_hd;
	msgbuf_hd = msgbuf;
	SPIN_UNLOCK(&msgbuf_lock);
	OS_THR_SIGNAL(&mb_wait);
}

static void *
alloc_msgdesc(int flag)
{
	struct msg_desc *msgd;

	SPIN_LOCK(&md_lock);
retry:
	if (msgd_hd == NULL) {
		if (flag != M_WAIT) {
			SPIN_UNLOCK(&md_lock);
			return NULL;
		} else {
			OS_THR_WAIT(&md_wait, &md_lock);
			goto retry;
		}
	}

	msgd = msgd_hd;
	msgd_hd = msgd_hd->next;
	SPIN_UNLOCK(&md_lock);
	return (void *)msgd;
}

static void
free_msgdesc(struct msg_desc *md)
{
	SPIN_LOCK(&md_lock);
	md->next = msgd_hd;
	msgd_hd = md;
	SPIN_UNLOCK(&md_lock);
	OS_THR_SIGNAL(&md_wait);
}

/*
 * Allocate data buffers for received data
 */
static void *
vpc_buffer_alloc(int size)
{
	dbuf_t *dbuf;

	SPIN_LOCK(&dbuf_lock);
	if (dbuf_hd == NULL) {
		SPIN_UNLOCK(&dbuf_lock);
		return NULL;
	}

	dbuf = dbuf_hd;
	dbuf_hd = dbuf->next;
	SPIN_UNLOCK(&dbuf_lock);
	return (void *)dbuf;
}

/*
 * Free data buffers
 */
void
vpc_buffer_free(void *buf)
{
	dbuf_t *dbuf = (dbuf_t *)buf;

	SPIN_LOCK(&dbuf_lock);
	dbuf->next = dbuf_hd;
	dbuf_hd = dbuf;
	SPIN_UNLOCK(&dbuf_lock);
}

static void *
alloc_iov(int iovlen )
{
	dbuf_t *dbuf;

	/* if iovlen > SMALL_IOV then use vpc_buffer */
	/* TBD: ASSERT iovlen < (VPC_BUF_LEN/sizeof(OS_IOV)) */
	if (iovlen > SMALL_IOV)
		return vpc_buffer_alloc(0);

	SPIN_LOCK(&iov_lock);
	if (smiov_hd == NULL) {
		SPIN_UNLOCK(&iov_lock);
		return NULL;
	}

	dbuf = smiov_hd;
	smiov_hd = dbuf->next;
	SPIN_UNLOCK(&iov_lock);
	return (void *)dbuf;
}

static void
alloc_iov_data(OS_IOV *iov, int iovlen)
{
	int i;

	for (i = 0; i < iovlen; i++) {
		iov[i].iov_base = vpc_buffer_alloc(0);
		iov[i].iov_len = VPC_BUF_LEN;
	}
}

static void
free_iov(void *iov, int iovlen)
{
	dbuf_t *dbuf = (dbuf_t *)iov;

	SPIN_LOCK(&iov_lock);
	dbuf->next = smiov_hd;
	smiov_hd = dbuf;
	SPIN_UNLOCK(&iov_lock);
}

static void
free_iov_data(OS_IOV *iov, int iovlen)
{
	int i;

	for (i = 0; i < iovlen; i++)
		vpc_buffer_free(iov[i].iov_base);
}

/*
 * Try to read iovec from transport
 */
static int
try_read_datav(vpc_conn_t *conn)
{
	OS_IOV *iov;
	struct msg_desc *mdesc;
	int len, ret, last, off, left;
	void *thdl = conn->transp_hdl;

	mdesc = &conn->cur_rx_msg;
	iov = mdesc->data;

	while (1) {
		left = mdesc->dlen - mdesc->done;
		len = MIN(left, iov[mdesc->last].iov_len - mdesc->off);

		last = mdesc->last;
		off = mdesc->off;

		SPIN_UNLOCK(&conn->lock);
		ret = vpc_transp_read_data(thdl, iov[last].iov_base + off, len);
		SPIN_LOCK(&conn->lock);

		if (conn->state != VPC_STATE_CONNECTED)
			return 0;
		if (ret == -1 || ret == 0)
			return ret;

		mdesc->off += ret;
		mdesc->done += ret;
		if (mdesc->off == iov[mdesc->last].iov_len) {
			mdesc->last++;
			mdesc->off = 0;
		}
		/* handle iov_len unaligned length */
		if (mdesc->done == mdesc->dlen) {
			if (mdesc->off != 0)
				iov[mdesc->last].iov_len = mdesc->off;
			break;
		}
	}

	return mdesc->done;
}

/*
 * Handle WR_RESP
 */
static void
handle_gen_resp(u32_t conn_idx, vpc_msg_gen_rsp_t *rspmsg)
{
	vpc_req_t *req;
	u64_t tmp;
	u32_t rsp_code;


	rsp_code = NTOHL(rspmsg->rsp_code);
	/* Get req from msgcookie */
	memcpy(&tmp, rspmsg->msgcookie, sizeof(tmp));

	switch (NTOHL(rspmsg->req_mtype)) {
	case VPC_MSG_WR_REQ:
		{
			vpc_wr_rsp_t *wr_rsp;
			vpc_wr_req_t *wr_req;

			wr_req = (vpc_wr_req_t *)(long)tmp;

			req = (vpc_req_t *)wr_req;
			wr_rsp = (vpc_wr_rsp_t *)&req->resp;
			wr_rsp->rsp_code = rsp_code;

			(req->rsp_upcall)(VPC_REQ_WRITE, req);
		}
		break;
	case VPC_MSG_SETATTR_REQ:
		{
			vpc_setattr_rsp_t *sa_rsp;
			vpc_setattr_req_t *sa_req;

			sa_req = (vpc_setattr_req_t *)(long)tmp;

			req = (vpc_req_t *)sa_req;
			sa_rsp = (vpc_setattr_rsp_t *)&req->resp;
			sa_rsp->rsp_code = rsp_code;

			(req->rsp_upcall)(VPC_REQ_SETATTR, req);
		}
		break;
	case VPC_MSG_INVAL_BATCH:
		{
			vpc_invb_rsp_t *invb_rsp;
			vpc_invb_req_t *invb_req;

			invb_req = (vpc_invb_req_t *)(long)tmp;

			req = (vpc_req_t *)invb_req;
			invb_rsp = (vpc_invb_rsp_t *)&req->resp;
			invb_rsp->rsp_code = rsp_code;

			(req->rsp_upcall)(VPC_REQ_INVAL_BATCH, req);
		}
		break;
	}
}

/*
 * Handle ASSOC_RESP
 */
static void
handle_assoc_resp(u32_t conn_idx, vpc_msg_assoc_rsp_t *rspmsg)
{
	vpc_req_t *req;
	vpc_assoc_rsp_t *assoc_rsp;
	vpc_assoc_req_t *assoc_req;
	u64_t tmp;

	/* get req from msgcookie */
	memcpy(&tmp, rspmsg->msgcookie, sizeof(tmp));
	assoc_req = (vpc_assoc_req_t *)(long)tmp;

	req = (vpc_req_t*)assoc_req;
	assoc_rsp = (vpc_assoc_rsp_t *)&req->resp;

	/* put resp status in response buffer */
	assoc_rsp->rsp_code = HTONL(rspmsg->rsp_code);
	assoc_rsp->obj_hdl = HTONL(rspmsg->obj_hdl);
	memcpy(assoc_rsp->obj_id, rspmsg->obj_id, MAX_OBJ_ID);
	assoc_rsp->conn_hdl = conn_idx;

	/* asn upcall */
	(req->rsp_upcall)(VPC_REQ_ASSOC, req);
}

/*
 * Handle INVAL_BATCH
 */
static void
handle_inval_batch(u32_t conn_idx, vpc_msg_invb_t *invbmsg)
{
	vpc_req_t *req;
	vpc_invb_req_t *invb_req;

	req = (vpc_req_t *)alloc_msgbuf(M_NOWAIT);
	if (req == NULL)
		return;
	/*
	 * Fill in invb req from network msg
	 */
	invb_req = (vpc_invb_req_t *)req->rqst;

	memcpy(req->msgcookie, invbmsg->msgcookie, sizeof(u64_t));
	invb_req->batchid = NTOHL(invbmsg->batchid);
	invb_req->obj_hdl = NTOHL(invbmsg->obj_hdl);

	asn_req_upcall(conn_idx, VPC_REQ_INVAL_BATCH, (void *)req);
}

/*
 * Handle ReAssoc Request
 */
static void
handle_reassoc_req(u32_t conn_idx, vpc_msg_reassoc_t *assoc_msg)
{
	vpc_req_t *req;
	vpc_reassoc_req_t *assoc_req;

	req = (vpc_req_t *)alloc_msgbuf(M_NOWAIT);
	if (req == NULL)
		return;
	/*
	 * Fill in reassoc req from network msg
	 */
	assoc_req = (vpc_reassoc_req_t *)req->rqst;

	memcpy(req->msgcookie, assoc_msg->msgcookie, sizeof(u64_t));
	assoc_req->batchid = NTOHL(assoc_msg->batchid);
	memcpy(assoc_req->clnt_obj_id, assoc_msg->clnt_obj_id, MAX_OBJ_ID);
	memcpy(assoc_req->srvr_obj_id, assoc_msg->srvr_obj_id, MAX_OBJ_ID);

	asn_req_upcall(conn_idx, VPC_REQ_REASSOC, (void *)req);
}

/*
 * Handle Assoc Request
 */
static void
handle_assoc_req(u32_t conn_idx, vpc_msg_assoc_t *assoc_msg)
{
	vpc_req_t *req;
	vpc_assoc_req_t *assoc_req;

	req = (vpc_req_t *)alloc_msgbuf(M_NOWAIT);
	if (req == NULL)
		return;
	/*
	 * Fill in assoc req from network msg
	 */
	assoc_req = (vpc_assoc_req_t *)req->rqst;

	memcpy(req->msgcookie, assoc_msg->msgcookie, sizeof(u64_t));
	assoc_req->obj_access_type = NTOHL(assoc_msg->obj_access_type);
	assoc_req->flags = NTOHL(assoc_msg->flags);
	assoc_req->batchid = NTOHL(assoc_msg->batchid);
	memcpy(assoc_req->clnt_obj_id, assoc_msg->clnt_obj_id, MAX_OBJ_ID);
	memcpy(assoc_req->srvr_ct_id, assoc_msg->srvr_ct_id, MAX_OBJ_ID);

	asn_req_upcall(conn_idx, VPC_REQ_ASSOC, (void *)req);
}

/*
 * Received Msg handler for Protocol msgs without Data vec
 */
static void
vpc_msg_hdlr(u32_t conn_idx, void *msg, int type)
{
	switch (type) {
	case VPC_MSG_ASSOC_REQ:
		handle_assoc_req(conn_idx, msg);
		break;
	case VPC_MSG_REASSOC_REQ:
		handle_reassoc_req(conn_idx, msg);
		break;
	case VPC_MSG_ASSOC_RESP:
		handle_assoc_resp(conn_idx, msg);
		break;
	case VPC_MSG_GEN_RESP:
		handle_gen_resp(conn_idx, msg);
		break;
	case VPC_MSG_INVAL_BATCH:
		handle_inval_batch(conn_idx, msg);
		break;
	}
	return ;
}

/*
 * Received Msg handler for Protocol msgs with Data vec
 */
static void
vpc_msgv_hdlr(u32_t conn_idx, void *msg, OS_IOV *iov, int iovlen,
	int dlen, int type)
{
	switch (type) {
	case VPC_MSG_WR_REQ:
	{
		vpc_req_t *req;
		vpc_msg_write_t *wr_msg;
		vpc_wr_req_t *wr_req;

		req = (vpc_req_t *)alloc_msgbuf(M_NOWAIT);
		if (req == NULL)
			return;

		wr_req = (vpc_wr_req_t *)req->rqst;
		wr_msg = (vpc_msg_write_t *)msg;
		wr_req->obj_hdl = NTOHL(wr_msg->obj_hdl);
		wr_req->offset_l = NTOHL(wr_msg->offset_l);
		wr_req->offset_h = NTOHL(wr_msg->offset_h);
		wr_req->batchid = NTOHL(wr_msg->batchid);
		memcpy(req->msgcookie, wr_msg->msgcookie, sizeof(u64_t));
		wr_req->dlen = dlen;
		wr_req->iovlen = iovlen;
		wr_req->dtype = DATA_IOVEC;
		wr_req->data = iov;
		asn_req_upcall(conn_idx, VPC_REQ_WRITE, (void *)req);
	}
		break;
	case VPC_MSG_SETATTR_REQ:
	{
		vpc_req_t *req;
		vpc_msg_setattr_t *sa_msg;
		vpc_setattr_req_t *sa_req;

		req = (vpc_req_t *)alloc_msgbuf(M_NOWAIT);
		if (req == NULL)
			return;

		sa_req = (vpc_setattr_req_t *)req->rqst;
		sa_msg = (vpc_msg_setattr_t *)msg;
		sa_req->obj_hdl = NTOHL(sa_msg->obj_hdl);
		memcpy(req->msgcookie, sa_msg->msgcookie, sizeof(u64_t));
		sa_req->dlen = dlen;
		sa_req->iovlen = iovlen;
		sa_req->dtype = DATA_IOVEC;
		sa_req->data = iov;

		asn_req_upcall(conn_idx, VPC_REQ_SETATTR, (void *)req);
	}
		break;
	//case VPC_MSG_RD_RESP:
	//	break;
	default:
		// ASSERT(0);
		break;
	}
}


/*
 * Server side handler for transport connect
 */
static void *
vpc_connect_hdlr(void *transp_hdl, u32_t clnt_ip)
{
	vpc_conn_t *conn;

	conn = OS_ZALLOC_WAIT(sizeof(vpc_conn_t));

	OS_SPIN_LOCK_INIT(&conn->lock);
	conn->state = VPC_STATE_CONNECTED;
	conn->rmt_ip = clnt_ip;
	conn->transp_hdl = transp_hdl;
	conn->rx_state = EXPECT_MSG_HDR;
	conn->err_upcall = NULL;
	conn->clnt_cookie = NULL;
	conn->flags = 0;
	conn->obj_hdl = VPC_INVALID_OBJHDL;

	conn_add(conn);
	return conn;
}

static void
close_conn(vpc_conn_t *conn)
{
	struct msg_desc *m, *mdesc;

	conn->state = VPC_STATE_CLOSED;

	vpc_transp_conn_shutdown(conn->transp_hdl);
	conn->transp_hdl = NULL;

	/* Release all Msgs on Send queue */
	m = conn->tx_q_hd;
	while (m != NULL) {
		OS_PRINT("tx_q m=%p\n", m);
		mdesc = m;
		m = mdesc->next;
		free_msgbuf((msgbuf_t *)mdesc->msgbuf);
		if (mdesc->asn_send_done != NULL)
			mdesc->asn_send_done(mdesc->sd_arg);
		free_msgdesc(mdesc);
	}
	/* Throw away all incomplete Msgs on Receive queue */
	if (conn->cur_rx_msg.msgbuf != NULL)
		free_msgbuf((msgbuf_t *) conn->cur_rx_msg.msgbuf);
	if (conn->cur_rx_msg.data != NULL) {
		if (conn->cur_rx_msg.iovlen == 0)
			vpc_buffer_free(conn->cur_rx_msg.data);
		else {
			free_iov_data(conn->cur_rx_msg.data,
					conn->cur_rx_msg.iovlen);
			free_iov(conn->cur_rx_msg.data,
					conn->cur_rx_msg.iovlen);
		}
	}

	conn_del(conn->conn_idx);
}

/*
 * Handler for transport heart-beat timer
 * Server side of connection.
 */
static void
vpc_svr_hb_hdlr(void *arg)
{
	vpc_conn_t *conn = (vpc_conn_t *)arg;
	static unsigned int rx_msgs_last = 0;

	SPIN_LOCK(&conn->lock);
	if (conn->state == VPC_STATE_CLOSED) {
		SPIN_UNLOCK(&conn->lock);
		return;
	}
	if (conn->rx_msgs != rx_msgs_last)
		rx_msgs_last = conn->rx_msgs;
	else {
		SPIN_UNLOCK(&conn->lock);

		OS_PRINT("vpc server no activity\n");
		vpc_conn_err_hdlr(conn);
		return;
	}
	SPIN_UNLOCK(&conn->lock);
	OS_PRINT("SVR HB\n");
}

/*
 * Handler for transport heart-beat timer
 * Client side of connection.
 */
static void
vpc_clnt_hb_hdlr(void *arg)
{
	vpc_conn_t *conn = (vpc_conn_t *)arg;
	int shutdown = 0;
	static unsigned int rx_msgs_last = 0;

	SPIN_LOCK(&conn->lock);
	if (conn->state == VPC_STATE_CLOSED) {
		SPIN_UNLOCK(&conn->lock);
		return;
	}
	// OS_PRINT("CLNT HB\n");
	if (conn->rx_msgs == rx_msgs_last) {
		conn->n_hb++;
		if (conn->n_hb > HB_RETRY_LIMIT)
			shutdown = 1;
		SPIN_UNLOCK(&conn->lock);
		if (shutdown) {
			OS_PRINT("vpc clnt no response\n");
			vpc_conn_err_hdlr(conn);
		} else
			vpc_send_hb(conn);
		return;
	} else {
		rx_msgs_last = conn->rx_msgs;
	}
	SPIN_UNLOCK(&conn->lock);
}

/*
 * Handler for transport connection shutdown
 */
static void
vpc_conn_err_hdlr(void *arg)
{
	vpc_conn_t *conn = (vpc_conn_t *)arg;
	void (*err_upcall)(void *); 
	void *cookie;
	u32_t conn_hdl;
	u32_t obj_hdl;

	SPIN_LOCK(&conn->lock);
	if (conn->state == VPC_STATE_CLOSED) {
		SPIN_UNLOCK(&conn->lock);
		return;
	}

	OS_PRINT("Conn Error: %p\n", conn);
	OS_PRINT("Conn rx state: %d\n", conn->rx_state);
	OS_PRINT("Conn rx msgs: %d\n", conn->rx_msgs);
	OS_PRINT("Conn tx msgs: %d\n", conn->tx_msgs);
	OS_PRINT("Conn cur rx hdone: %d\n", conn->cur_rx_msg.hdone);
	OS_PRINT("Conn cur rx done: %d\n", conn->cur_rx_msg.done);
	OS_PRINT("Conn cur rx dlen: %d\n", conn->cur_rx_msg.dlen);


	err_upcall = conn->err_upcall;
	cookie = conn->clnt_cookie;
	conn_hdl = conn->conn_idx;
	obj_hdl = conn->obj_hdl;

	close_conn(conn);

	SPIN_UNLOCK(&conn->lock);

	OS_FREE(conn);

	/* check for client upcall */
	if (err_upcall != NULL)
		err_upcall(cookie);

	/* check for server upcall */
	if (asn_err_upcall != NULL &&
			obj_hdl != VPC_INVALID_OBJHDL)
		asn_err_upcall(conn_hdl, obj_hdl);
}

/*
 * Upcall from transport when data has arrived
 */
static void
vpc_rx_hdlr(void *arg)
{
	int ret, dlen, mtype, len, off;
	u32_t ver, conn_idx;
	vpc_conn_t *conn = (vpc_conn_t*)arg;
	void *msgbuf = NULL, *msgp, *thdl;

	SPIN_LOCK(&conn->lock);
	if (conn->state != VPC_STATE_CONNECTED) {
		SPIN_UNLOCK(&conn->lock);
		return;
	}
	for (;;) {
		if (conn->state != VPC_STATE_CONNECTED) {
			SPIN_UNLOCK(&conn->lock);
			return;
		}
		if (conn->rx_state == EXPECT_MSG_HDR) {
			vpc_msg_hdr_t *msg_hdr;

			if (conn->cur_rx_msg.msgbuf == NULL) {
				msgbuf = alloc_msgbuf(M_NOWAIT);
				if (msgbuf == NULL) {
					SPIN_UNLOCK(&conn->lock);
					return;
				}
				conn->cur_rx_msg.msgbuf = msgbuf;
			} else
				msgbuf = conn->cur_rx_msg.msgbuf;

			thdl = conn->transp_hdl;
			len = sizeof(*msg_hdr) - conn->cur_rx_msg.done;
			off = conn->cur_rx_msg.done;
			SPIN_UNLOCK(&conn->lock);
			/* Read first the msg header */
			msg_hdr = (vpc_msg_hdr_t *)msgbuf;
			if (len != 0) {
				ret = vpc_transp_read_data(thdl,
						(void *)msg_hdr + off,
							len);
				if (ret == 0)
					return;
			} else
				ret = sizeof(vpc_msg_hdr_t);
			SPIN_LOCK(&conn->lock);
			if (ret == -1) {
				if (conn->cur_rx_msg.done == 0) {
					conn->cur_rx_msg.msgbuf = NULL;
					free_msgbuf(msgbuf);
				}
				SPIN_UNLOCK(&conn->lock);
				return;
			}
			if (ret < len) {
			//	OS_PRINT("VPC Transport returned less than ");
			//	OS_PRINT("LOW_WAT\n");
				conn->cur_rx_msg.done += ret;
				SPIN_UNLOCK(&conn->lock);
				return;
			}
			if (conn->state != VPC_STATE_CONNECTED) {
				SPIN_UNLOCK(&conn->lock);
				return;
			}
			ver = NTOHL(msg_hdr->proto_ver);
			if (ver != VPC_PROTO_VER) {
				OS_PRINT("VPC Bug: invalid hdr\n");
				SPIN_UNLOCK(&conn->lock);
				return;
			}
			conn->cur_rx_msg.mtype = NTOHL(msg_hdr->msg_type);
			conn->cur_rx_msg.hlen = NTOHL(msg_hdr->msg_hlen);
			conn->cur_rx_msg.dlen = NTOHL(msg_hdr->msg_dlen);

			/* Ready to read rest of the MSG */
			if (conn->cur_rx_msg.hlen > sizeof(vpc_msg_hdr_t)) {
				conn->rx_state = EXPECT_MSGBUF;
				conn->cur_rx_msg.done = sizeof(vpc_msg_hdr_t);
				conn->cur_rx_msg.msgbuf = msgbuf;
			} else if (conn->cur_rx_msg.mtype == VPC_MSG_HB) {
				conn->rx_state = EXPECT_MSG_HDR;
				conn->rx_msgs++;
				SPIN_UNLOCK(&conn->lock);
				/* Send HB rsp */
				vpc_send_hb_rsp(conn);
				SPIN_LOCK(&conn->lock);
				free_msgbuf((msgbuf_t *)
						conn->cur_rx_msg.msgbuf);
				memset(&conn->cur_rx_msg, 0,
						sizeof(conn->cur_rx_msg));
				continue;
			} else if (conn->cur_rx_msg.mtype == VPC_MSG_HB_RSP) {
				conn->rx_state = EXPECT_MSG_HDR;
				conn->rx_msgs++;
				conn->n_hb--;
				free_msgbuf((msgbuf_t *)
						conn->cur_rx_msg.msgbuf);
				memset(&conn->cur_rx_msg, 0,
						sizeof(conn->cur_rx_msg));
				continue;
			}
		}

		if (conn->rx_state == EXPECT_MSGBUF) {
			thdl = conn->transp_hdl;
			msgp = conn->cur_rx_msg.msgbuf + conn->cur_rx_msg.done;
			len = conn->cur_rx_msg.hlen - conn->cur_rx_msg.done;
			SPIN_UNLOCK(&conn->lock);
			ret = vpc_transp_read_data(thdl, msgp, len);
			if (ret == 0) {
				return;
			}
			SPIN_LOCK(&conn->lock);
			if (conn->state != VPC_STATE_CONNECTED) {
				SPIN_UNLOCK(&conn->lock);
				return;
			}
			if (ret == -1) {
				if (msgbuf != NULL)
					conn->cur_rx_msg.msgbuf = msgbuf;
				SPIN_UNLOCK(&conn->lock);
				return;
			}

			conn->cur_rx_msg.done += ret;

			if (conn->cur_rx_msg.done < conn->cur_rx_msg.hlen) {
				if (msgbuf != NULL)
					conn->cur_rx_msg.msgbuf = msgbuf;
				SPIN_UNLOCK(&conn->lock);
				return;
			}

			/* Ready to read MSG DATA */
			if (conn->cur_rx_msg.dlen > 0) {
				conn->rx_state = EXPECT_MSG_DATA;
			} else {
				conn->rx_msgs++;
				conn_idx = conn->conn_idx;
				msgbuf = conn->cur_rx_msg.msgbuf;
				mtype = conn->cur_rx_msg.mtype;
				/* Drop lock */
				SPIN_UNLOCK(&conn->lock);

				vpc_msg_hdlr(conn_idx, msgbuf, mtype);

				SPIN_LOCK(&conn->lock);
				/* free rx allocated buffer */
				if (conn->cur_rx_msg.msgbuf != NULL)
					free_msgbuf((msgbuf_t *)
						conn->cur_rx_msg.msgbuf);
				/* Done with this msg */
				/* Expect another one */
				conn->rx_state = EXPECT_MSG_HDR;
				memset(&conn->cur_rx_msg, 0,
						sizeof(conn->cur_rx_msg));
			}
		}

		if (conn->rx_state == EXPECT_MSG_DATA) {
			void *data;
			int iovlen;

			/* Alloc buffers */
			if (conn->cur_rx_msg.data == NULL) {
				iovlen = conn->cur_rx_msg.dlen / VPC_BUF_LEN;
				if ((conn->cur_rx_msg.dlen % VPC_BUF_LEN) != 0)
						iovlen++;
				// ASSERT iovlen < MAX_IOV_LEN
				data = alloc_iov(iovlen);
				alloc_iov_data(data, iovlen);
				conn->cur_rx_msg.iovlen = iovlen;
				conn->cur_rx_msg.done = 0;
				conn->cur_rx_msg.data = data;
			} else
				data = conn->cur_rx_msg.data;

			/* try to read data into buffers */
			ret = try_read_datav(conn);

			if (ret == 0) {
				SPIN_UNLOCK(&conn->lock);
				return;
			}
			if (ret == -1) {
				SPIN_UNLOCK(&conn->lock);
				return;
			}
			if (conn->cur_rx_msg.done < conn->cur_rx_msg.dlen) {
				SPIN_UNLOCK(&conn->lock);
				// OS_PRINT("Transp read %d bytes\n", ret);
				return;
			}
			conn->rx_msgs++;
			iovlen = conn->cur_rx_msg.iovlen;
			conn_idx = conn->conn_idx;
			msgbuf = conn->cur_rx_msg.msgbuf;
			data = conn->cur_rx_msg.data;
			dlen = conn->cur_rx_msg.dlen;
			mtype = conn->cur_rx_msg.mtype;
			/* Drop lock */
			SPIN_UNLOCK(&conn->lock);

			vpc_msgv_hdlr(conn_idx, msgbuf, data,
						iovlen, dlen, mtype);

			SPIN_LOCK(&conn->lock);
			if (conn->cur_rx_msg.msgbuf != NULL)
			/* free rx allocated buffers */
				free_msgbuf((msgbuf_t *)
						conn->cur_rx_msg.msgbuf);

			conn->rx_state = EXPECT_MSG_HDR;
			memset(&conn->cur_rx_msg, 0, sizeof(conn->cur_rx_msg));
		}
	}
}

/*
 * Handle sending REASSOC_REQ
 */
static vpc_ret_t
vpc_send_reassoc_req(vpc_reassoc_req_t *assoc_req)
{
	vpc_conn_t *conn;
	u32_t conn_idx;
	vpc_msg_reassoc_t *msg;
	u64_t tmp;
	int ret;

	/* If no connection exists do transport connect */
	conn = OS_ZALLOC_WAIT(sizeof(vpc_conn_t));
	ret = vpc_transp_connect(assoc_req->ip, assoc_req->port,
				conn, &conn->transp_hdl);
	if (ret < 0) {
		OS_FREE(conn);
		return VPC_ERR_CONN_FAIL;
	}
	OS_SPIN_LOCK_INIT(&conn->lock);
	conn->state = VPC_STATE_CONNECTED;
	conn->flags = 0;
	conn->rmt_ip = assoc_req->ip;
	conn->rx_state = EXPECT_MSG_HDR;

	/* Add connection to conn list */
	conn_idx = conn_add(conn);

	/* alloc a msgbuf to form request pkt */
	msg = (vpc_msg_reassoc_t *)alloc_msgbuf(M_NOWAIT);
	if (msg == NULL) {
		conn_del(conn_idx);
		OS_FREE(conn);
		return VPC_ERR_NOMEM;
	}
	/* Format protocol assoc request */
	strcpy(msg->clnt_obj_id, assoc_req->clnt_obj_id);
	strcpy(msg->srvr_obj_id, assoc_req->srvr_obj_id);
	tmp = (u64_t)(long)assoc_req;
	memcpy(msg->msgcookie, &tmp, sizeof(u64_t));
	msg->batchid = HTONL(assoc_req->batchid);

	/* Format msg header */
	msg->m_hdr.proto_ver = HTONL(VPC_PROTO_VER);
	msg->m_hdr.msg_type = HTONL(VPC_MSG_REASSOC_REQ);
	msg->m_hdr.msg_hlen = HTONL(sizeof(vpc_msg_reassoc_t));
	msg->m_hdr.msg_dlen = 0;

	/* Send assoc request on transport */
	ret = vpc_transp_send_msg(conn->transp_hdl, msg,
			sizeof(vpc_msg_reassoc_t), NULL, 0);
	if (ret < 0) {
		OS_PRINT("assoc send failed: %d\n", ret);
		conn_del(conn_idx);
		OS_FREE(conn);
		free_msgbuf((msgbuf_t *)msg);
		return VPC_ERR_SEND_FAIL;
	}
	free_msgbuf((msgbuf_t*)msg);
	/* set err upcall for client conn */
	conn->err_upcall = assoc_req->err_upcall;
	conn->clnt_cookie = assoc_req->clnt_cookie;
	conn->obj_hdl = VPC_INVALID_OBJHDL;

	return VPC_RSP_OK;
}

/*
 * Handle sending INVBATCH_REQ
 */
static vpc_ret_t
vpc_send_invb_req(vpc_invb_req_t *invb_req)
{
	vpc_conn_t *conn;
	vpc_msg_invb_t *msg;
	struct msg_desc *mdesc;
	u64_t tmp;
	int ret;

	/* Check for valid conn hdl */
	conn = conn_get(invb_req->conn_hdl);
	if (conn == NULL)
		return VPC_INVALID_CONHDL;

	/* Format protocol write req */
	msg = alloc_msgbuf(M_WAIT);
	if (msg == NULL)
		return VPC_ERR_NOMEM;

	/* fill in msg hdr */
	tmp = (u64_t)(long)invb_req;
	memcpy(msg->msgcookie, &tmp, sizeof(u64_t));
	msg->obj_hdl = HTONL(invb_req->obj_hdl);
	msg->batchid = HTONL(invb_req->batchid);

	/* Format msg header */
	msg->m_hdr.proto_ver = HTONL(VPC_PROTO_VER);
	msg->m_hdr.msg_type = HTONL(VPC_MSG_INVAL_BATCH);
	msg->m_hdr.msg_hlen = HTONL(sizeof(vpc_msg_invb_t));
	msg->m_hdr.msg_dlen = 0;

	mdesc = (struct msg_desc *)alloc_msgdesc(M_NOWAIT);
	if (mdesc == NULL) {
		free_msgbuf((msgbuf_t*)msg);
		return VPC_ERR_NOMEM;
	}
	mdesc->hlen = sizeof(vpc_msg_invb_t);
	mdesc->dlen = 0;
	mdesc->done = 0;
	mdesc->hdone = 0;
	mdesc->next = NULL;
	mdesc->msgbuf = msg;
	mdesc->data = NULL;
	mdesc->iovlen = 0;
	mdesc->asn_send_done = NULL;

	ret = try_send_mdesc(conn, mdesc);
	if (ret != VPC_RSP_OK) {
		free_msgbuf((msgbuf_t*)msg);
		free_msgdesc(mdesc);
		return VPC_ERR_SEND_FAIL;
	}

	return VPC_RSP_OK;
}

/*
 * Handle sending ASSOC_REQ
 */
static vpc_ret_t
vpc_send_assoc_req(vpc_assoc_req_t *assoc_req)
{
	vpc_conn_t *conn;
	u32_t conn_idx;
	vpc_msg_assoc_t *msg;
	u64_t tmp;
	int ret;

	/* If no connection exists do transport connect */
	conn = OS_ZALLOC_WAIT(sizeof(vpc_conn_t));
	ret = vpc_transp_connect(assoc_req->ip, assoc_req->port,
				conn, &conn->transp_hdl);
	if (ret < 0) {
		OS_FREE(conn);
		return VPC_ERR_CONN_FAIL;
	}
	OS_SPIN_LOCK_INIT(&conn->lock);
	conn->state = VPC_STATE_CONNECTED;
	conn->flags = 0;
	conn->rmt_ip = assoc_req->ip;
	conn->rx_state = EXPECT_MSG_HDR;

	/* Add connection to conn list */
	conn_idx = conn_add(conn);

	/* alloc a msgbuf to form request pkt */
	msg = (vpc_msg_assoc_t *)alloc_msgbuf(M_NOWAIT);
	if (msg == NULL) {
		conn_del(conn_idx);
		OS_FREE(conn);
		return VPC_ERR_NOMEM;
	}
	/* Format protocol assoc request */
	strcpy(msg->clnt_obj_id, assoc_req->clnt_obj_id);
	strcpy(msg->srvr_ct_id, assoc_req->srvr_ct_id);
	tmp = (u64_t)(long)assoc_req;
	memcpy(msg->msgcookie, &tmp, sizeof(u64_t));
	msg->flags = HTONL(assoc_req->flags);
	msg->batchid = HTONL(assoc_req->batchid);

	/* Format msg header */
	msg->m_hdr.proto_ver = HTONL(VPC_PROTO_VER);
	msg->m_hdr.msg_type = HTONL(VPC_MSG_ASSOC_REQ);
	msg->m_hdr.msg_hlen = HTONL(sizeof(vpc_msg_assoc_t));
	msg->m_hdr.msg_dlen = 0;

	/* Send assoc request on transport */
	ret = vpc_transp_send_msg(conn->transp_hdl, msg,
			sizeof(vpc_msg_assoc_t), NULL, 0);
	if (ret < 0) {
		OS_PRINT("assoc send failed: %d\n", ret);
		conn_del(conn_idx);
		OS_FREE(conn);
		free_msgbuf((msgbuf_t *)msg);
		return VPC_ERR_SEND_FAIL;
	}
	free_msgbuf((msgbuf_t*)msg);
	/* set err upcall for client conn */
	conn->err_upcall = assoc_req->err_upcall;
	conn->clnt_cookie = assoc_req->clnt_cookie;
	conn->obj_hdl = VPC_INVALID_OBJHDL;

	return VPC_RSP_OK;
}

/*
 * Returns -1 when send is incomplete. vpc_send_retry will try again
 */
static int
try_send_msg(void *transp_hdl, struct msg_desc *mdesc)
{
	int ret;

	if (mdesc->hdone < mdesc->hlen) {
		ret = vpc_transp_send_msg(transp_hdl,
						mdesc->msgbuf + mdesc->hdone,
						mdesc->hlen - mdesc->hdone,
						mdesc->data, mdesc->dlen);
		if (ret <= 0)
			return -1;

		if (ret > (mdesc->hlen - mdesc->hdone)) {
			mdesc->done += (ret - mdesc->hlen);
			mdesc->hdone = mdesc->hlen;
		} else if (ret <= (mdesc->hlen - mdesc->hdone))
			mdesc->hdone += ret;
	} else {
		ret = vpc_transp_send_msg(transp_hdl, NULL, 0,
						mdesc->data + mdesc->done,
						mdesc->dlen - mdesc->done);

		if (ret < 0)
			return -1;
		mdesc->done += ret;
	}

	if ((mdesc->hdone + mdesc->done) < (mdesc->hlen +  mdesc->dlen))
		return -1;

	return 0;
}

/*
 * Returns -1 when send is incomplete. vpc_send_retry will try again
 */
static int
try_send_msgv(void *transp_hdl, struct msg_desc *mdesc)
{
	int ret, len;
	OS_IOV *iov;

	while (mdesc->hdone < mdesc->hlen) {
		ret = vpc_transp_send_msg(transp_hdl,
				mdesc->msgbuf + mdesc->hdone,
				mdesc->hlen - mdesc->hdone, NULL, 0);
		if (ret > 0)
			mdesc->hdone += ret;
		else
			return -1;
		mdesc->last = 0;
		mdesc->off = 0;
	}

	if (mdesc->dlen == 0)
		return 0;

	iov = mdesc->data;
	while (mdesc->done < mdesc->dlen) {
		len = iov[mdesc->last].iov_len - mdesc->off;
		ret = vpc_transp_send_msg(transp_hdl, NULL, 0,
				iov[mdesc->last].iov_base + mdesc->off, len);
		if (ret == -1)
			return ret;

		mdesc->done += ret;
		if (ret < len) {
			mdesc->off += ret;
			return -1;
		}
		mdesc->last++;
		mdesc->off = 0;
	}
	return 0;
}

/*
 * Upcall to retry Send after when transport flow control is lifted.
 */
static void
vpc_send_retry(void *arg)
{
	struct msg_desc *mdesc;
	vpc_conn_t *conn = (vpc_conn_t *)arg;
	void *thdl;
	int ret;

	SPIN_LOCK(&conn->lock);
	if (conn->state != VPC_STATE_CONNECTED ||
			conn->flags & TX_IN_PROGRESS) {
		SPIN_UNLOCK(&conn->lock);
		return ;
	}

	conn->flags |= TX_IN_PROGRESS;

	while ((mdesc = conn->tx_q_hd)) {
		/* Try send drop lock */
		thdl = conn->transp_hdl;	
		if (mdesc->iovlen == 0) {
			SPIN_UNLOCK(&conn->lock);
			ret = try_send_msg(thdl, mdesc);
		} else {
			SPIN_UNLOCK(&conn->lock);
			ret = try_send_msgv(thdl, mdesc);
		}
		SPIN_LOCK(&conn->lock);
		if (ret == 0) {
			conn->tx_msgs++;
			mdesc = conn->tx_q_hd;
			/* Done with this one, dequeue and pick next */
			if (mdesc->asn_send_done != NULL)
				mdesc->asn_send_done(mdesc->sd_arg);
			free_msgbuf((msgbuf_t *)mdesc->msgbuf);
			conn->tx_q_hd = mdesc->next;
			free_msgdesc(mdesc);
		} else
			break;
	}
	if (conn->tx_q_hd == NULL)
		conn->tx_q_tl = NULL;

	conn->flags &= ~TX_IN_PROGRESS;

	SPIN_UNLOCK(&conn->lock);
}

/*
 * Try to send on transport. If flow controlled, then queue for retry later
 */
static vpc_ret_t
try_send_mdesc(vpc_conn_t *conn, struct msg_desc *mdesc)
{
	SPIN_LOCK(&conn->lock);
	if (conn->state != VPC_STATE_CONNECTED) {
		SPIN_UNLOCK(&conn->lock);
		return VPC_ERR_CONN_FAIL;
	}
	/* If send queue not empty just queue to tail */
	if (conn->tx_q_tl != NULL) {
		conn->tx_q_tl->next = mdesc;
		conn->tx_q_tl = mdesc;
	} else {
		/* queue to head */
		conn->tx_q_hd = conn->tx_q_tl = mdesc;
	}

	if (conn->flags & TX_IN_PROGRESS) {
		SPIN_UNLOCK(&conn->lock);
		return VPC_RSP_OK;
	}

	SPIN_UNLOCK(&conn->lock);

	vpc_send_retry(conn);

	return VPC_RSP_OK;
}

/*
 * Send HeartBeat msg
 */
static vpc_ret_t
vpc_send_hb(vpc_conn_t *conn)
{
	struct msg_desc *mdesc;
	vpc_msg_hdr_t *msg;
	int ret;

	msg = alloc_msgbuf(M_NOWAIT);
	if (msg == NULL)
		return VPC_ERR_NOMEM;
	/* fill in msg req */
	msg->proto_ver = HTONL(VPC_PROTO_VER);
	msg->msg_type = HTONL(VPC_MSG_HB);
	msg->msg_hlen = HTONL(sizeof(vpc_msg_hdr_t));
	msg->msg_dlen = 0;

	mdesc = (struct msg_desc *)alloc_msgdesc(M_NOWAIT);
	if (mdesc == NULL) {
		free_msgbuf((msgbuf_t*)msg);
		return VPC_ERR_NOMEM;
	}
	mdesc->hlen = NTOHL(msg->msg_hlen);
	mdesc->dlen = 0;
	mdesc->done = 0;
	mdesc->hdone = 0;
	mdesc->next = NULL;
	mdesc->msgbuf = msg;
	mdesc->data = NULL;
	mdesc->iovlen = 0;
	mdesc->asn_send_done = NULL;

	ret = try_send_mdesc(conn, mdesc);
	if (ret != VPC_RSP_OK) {
		free_msgbuf((msgbuf_t*)msg);
		free_msgdesc(mdesc);
		return VPC_ERR_SEND_FAIL;
	}

	return VPC_RSP_OK;
}

/*
 * Send HeartBeat rsp
 */
static vpc_ret_t
vpc_send_hb_rsp(vpc_conn_t *conn)
{
	struct msg_desc *mdesc;
	vpc_msg_hdr_t *msg;
	int ret;

	msg = alloc_msgbuf(M_NOWAIT);
	if (msg == NULL)
		return VPC_ERR_NOMEM;
	/* fill in msg req */
	msg->proto_ver = HTONL(VPC_PROTO_VER);
	msg->msg_type = HTONL(VPC_MSG_HB_RSP);
	msg->msg_hlen = HTONL(sizeof(vpc_msg_hdr_t));
	msg->msg_dlen = 0;

	mdesc = (struct msg_desc *)alloc_msgdesc(M_NOWAIT);
	if (mdesc == NULL) {
		free_msgbuf((msgbuf_t*)msg);
		return VPC_ERR_NOMEM;
	}
	mdesc->hlen = NTOHL(msg->msg_hlen);
	mdesc->dlen = 0;
	mdesc->done = 0;
	mdesc->hdone = 0;
	mdesc->next = NULL;
	mdesc->msgbuf = msg;
	mdesc->data = NULL;
	mdesc->iovlen = 0;
	mdesc->asn_send_done = NULL;

	ret = try_send_mdesc(conn, mdesc);
	if (ret != VPC_RSP_OK) {
		free_msgbuf((msgbuf_t*)msg);
		free_msgdesc(mdesc);
		return VPC_ERR_SEND_FAIL;
	}

	return VPC_RSP_OK;
}

/*
 * Handle sending SETATTR_REQ
 */
static vpc_ret_t
vpc_send_setattr_req(vpc_setattr_req_t * sa_req)
{
	int ret = 0;
	vpc_msg_setattr_t *msg;
	u64_t tmp;
	vpc_conn_t *conn;
	struct msg_desc *mdesc;

	/* Check for valid conn hdl */
	conn = conn_get(sa_req->conn_hdl);
	if (conn == NULL)
		return VPC_INVALID_CONHDL;

	/* Format protocol write req */
	msg = alloc_msgbuf(M_WAIT);
	if (msg == NULL)
		return VPC_ERR_NOMEM;

	/* fill in msg hdr */
	tmp = (u64_t)(long)sa_req;
	memcpy(msg->msgcookie, &tmp, sizeof(u64_t));
	msg->obj_hdl = HTONL(sa_req->obj_hdl);

	/* fill in msg req */
	msg->m_hdr.proto_ver = HTONL(VPC_PROTO_VER);
	msg->m_hdr.msg_type = HTONL(VPC_MSG_SETATTR_REQ);
	msg->m_hdr.msg_hlen = HTONL(sizeof(vpc_msg_setattr_t));
	msg->m_hdr.msg_dlen = HTONL(sa_req->dlen);

	mdesc = (struct msg_desc *)alloc_msgdesc(M_WAIT);
	if (mdesc == NULL) {
		free_msgbuf((msgbuf_t*)msg);
		return VPC_ERR_NOMEM;
	}
	mdesc->hlen = sizeof(vpc_msg_setattr_t);
	mdesc->dlen = sa_req->dlen;
	mdesc->done = 0;
	mdesc->hdone = 0;
	mdesc->next = NULL;
	mdesc->msgbuf = msg;

	/* If single data buffer, try to send in one shot if possible */
	/* Useful if hdr+data < MTU */
	if (sa_req->iovlen == 1) {
		mdesc->data = ((OS_IOV *)sa_req->data)->iov_base;
		mdesc->iovlen = 0;
	} else {
		mdesc->data = sa_req->data;
		mdesc->iovlen = sa_req->iovlen;
	}
	mdesc->asn_send_done = NULL;

	ret = try_send_mdesc(conn, mdesc);
	if (ret != VPC_RSP_OK) {
		free_msgbuf((msgbuf_t*)msg);
		free_msgdesc(mdesc);
		return VPC_ERR_SEND_FAIL;
	}

	return VPC_RSP_OK;
}

/*
 * Handle sending WR_REQ
 */
static vpc_ret_t
vpc_send_write_req(vpc_wr_req_t *wr_req)
{
	int ret = 0;
	vpc_msg_write_t *msg;
	u64_t tmp;
	vpc_conn_t *conn;
	struct msg_desc *mdesc;

	/* Check for valid conn hdl */
	conn = conn_get(wr_req->conn_hdl);
	if (conn == NULL)
		return VPC_INVALID_CONHDL;

	/* Format protocol write req */
	msg = alloc_msgbuf(M_WAIT);
	if (msg == NULL)
		return VPC_ERR_NOMEM;

	/* fill in msg hdr */
	tmp = (u64_t)(long)wr_req;
	memcpy(msg->msgcookie, &tmp, sizeof(u64_t));
	msg->obj_hdl = HTONL(wr_req->obj_hdl);
	msg->offset_l = HTONL(wr_req->offset_l);
	msg->offset_h = HTONL(wr_req->offset_h);
	msg->batchid = HTONL(wr_req->batchid);

	/* fill in msg req */
	msg->m_hdr.proto_ver = HTONL(VPC_PROTO_VER);
	msg->m_hdr.msg_type = HTONL(VPC_MSG_WR_REQ);
	msg->m_hdr.msg_hlen = HTONL(sizeof(vpc_msg_write_t));
	msg->m_hdr.msg_dlen = HTONL(wr_req->dlen);

	mdesc = (struct msg_desc *)alloc_msgdesc(M_WAIT);
	if (mdesc == NULL) {
		free_msgbuf((msgbuf_t*)msg);
		return VPC_ERR_NOMEM;
	}
	mdesc->hlen = NTOHL(msg->m_hdr.msg_hlen);
	mdesc->dlen = NTOHL(msg->m_hdr.msg_dlen);
	mdesc->done = 0;
	mdesc->hdone = 0;
	mdesc->next = NULL;
	mdesc->msgbuf = msg;

	/* If single data buffer, try to send in one shot if possible */
	/* Useful if hdr+data < MTU */
	if (wr_req->iovlen == 1) {
		mdesc->data = ((OS_IOV *)wr_req->data)->iov_base;
		mdesc->iovlen = 0;
	} else {
		mdesc->data = wr_req->data;
		mdesc->iovlen = wr_req->iovlen;
	}
	mdesc->asn_send_done = NULL;

	ret = try_send_mdesc(conn, mdesc);
	if (ret != VPC_RSP_OK) {
		free_msgbuf((msgbuf_t*)msg);
		free_msgdesc(mdesc);
		return VPC_ERR_SEND_FAIL;
	}

	return VPC_RSP_OK;
}

/*
 * VPC PROTOCOL API
 */

/*
 * Protocol API to server start transport listener
 */
vpc_ret_t
vpc_init_srvr(vpc_srvinfo_t *srvinfo)
{
	int ret;

	/* Check for valid ip */

	/* Check if vsa_id already listening */

	/* Transport listen */

	asn_req_upcall = srvinfo->req_upcall;
	asn_err_upcall = srvinfo->conn_err_upcall;
	my_vsaid = srvinfo->vsa_id;

	ret = vpc_transp_listen(srvinfo->ip, srvinfo->port);
	if (ret < 0)
		return (VPC_ERR_LISTEN_FAIL);

	return VPC_RSP_OK;
}
EXPORT_SYMBOL(vpc_init_srvr);

/*
 * Protocol API to stop listener
 */
void
vpc_stop_srvr(void)
{
	vpc_transp_stop_listen();
}
EXPORT_SYMBOL(vpc_stop_srvr);

/*
 * Protocol API for sending RESP
 */
vpc_ret_t
vpc_send_resp(u32_t conn_hdl, int req_type, vpc_resp_t *resp)
{
	vpc_conn_t *conn;
	void *msg = NULL;
	struct msg_desc *mdesc;
	int ret, rsp_type, hlen = 0, dlen = 0;

	/* Check for valid conn handle */
	conn = conn_get(conn_hdl);
	if (conn == NULL)
		return VPC_ERR_INVALID;

	if (req_type == VPC_REQ_WRITE || req_type == VPC_REQ_INVAL_BATCH ||
			req_type == VPC_REQ_SETATTR) {
		vpc_msg_gen_rsp_t *rspm;
		vpc_wr_rsp_t *rsp;

		rspm = (vpc_msg_gen_rsp_t *)alloc_msgbuf(M_WAIT);
		if (rspm == NULL)
			return VPC_ERR_INVALID;

		rsp = (vpc_wr_rsp_t *)resp->resp;
		rsp_type = VPC_MSG_GEN_RESP;
		hlen = sizeof(vpc_msg_gen_rsp_t);
		rspm->m_hdr.msg_hlen = HTONL(hlen);
		dlen = 0;
		rspm->m_hdr.msg_dlen = dlen;
		/* Format protocol resp message */
		rspm->m_hdr.proto_ver = HTONL(VPC_PROTO_VER);
		rspm->m_hdr.msg_type = HTONL(rsp_type);
		rspm->rsp_code = HTONL(rsp->rsp_code);
		if (req_type == VPC_REQ_WRITE)
			rspm->req_mtype = HTONL(VPC_MSG_WR_REQ);
		if (req_type == VPC_REQ_INVAL_BATCH)
			rspm->req_mtype = HTONL(VPC_MSG_INVAL_BATCH);
		if (req_type == VPC_REQ_SETATTR)
			rspm->req_mtype = HTONL(VPC_MSG_SETATTR_REQ);
		memcpy(rspm->msgcookie, resp->msgcookie, sizeof(u64_t));
		msg = (void *)rspm;
	} else if (req_type == VPC_REQ_ASSOC || req_type == VPC_REQ_REASSOC) {
		vpc_msg_assoc_rsp_t *rspm;
		vpc_assoc_rsp_t *rsp;

		rspm = (vpc_msg_assoc_rsp_t *)alloc_msgbuf(M_WAIT);
		if (rspm == NULL)
			return VPC_ERR_INVALID;

		rsp = (vpc_assoc_rsp_t *)resp->resp;
		rsp_type = VPC_MSG_ASSOC_RESP;
		hlen = sizeof(vpc_msg_assoc_rsp_t);
		rspm->m_hdr.msg_hlen = HTONL(hlen);
		dlen = 0;
		rspm->m_hdr.msg_dlen = dlen;
		rspm->obj_hdl = HTONL(rsp->obj_hdl);
		memcpy(rspm->obj_id, rsp->obj_id, MAX_OBJ_ID);
		/* Format protocol resp message */
		rspm->m_hdr.proto_ver = HTONL(VPC_PROTO_VER);
		rspm->m_hdr.msg_type = HTONL(rsp_type);
		rspm->rsp_code = HTONL(rsp->rsp_code);
		memcpy(rspm->msgcookie, resp->msgcookie, sizeof(u64_t));
		msg = (void *)rspm;
		conn->obj_hdl = rsp->obj_hdl;
	}

	mdesc = (struct msg_desc *)alloc_msgdesc(M_WAIT);
	if (mdesc == NULL) {
		free_msgbuf((msgbuf_t*)msg);
		return VPC_ERR_NOMEM;
	}
	mdesc->hlen = hlen;
	mdesc->dlen = dlen;
	mdesc->done = 0;
	mdesc->hdone = 0;
	mdesc->next = NULL;
	mdesc->msgbuf = msg;
	mdesc->data = resp->data;
	mdesc->iovlen = 0;
	mdesc->asn_send_done = resp->send_done;
	mdesc->sd_arg = (void *)resp;

	/* Send Resp Msg on Transport */
	ret = try_send_mdesc(conn, mdesc);
	if (ret != VPC_RSP_OK) {
		free_msgbuf((msgbuf_t*)msg);
		free_msgdesc(mdesc);
		return VPC_ERR_SEND_FAIL;
	}

	return VPC_RSP_OK;
}
EXPORT_SYMBOL(vpc_send_resp);

/*
 * Protocol API to submit remote requests
 */
vpc_ret_t
vpc_submit_req(int type, vpc_req_t *reqst)
{
	vpc_ret_t ret;

	ret = VPC_ERR_INVALID;
	switch (type) {
		case VPC_REQ_ASSOC:
			ret = vpc_send_assoc_req((vpc_assoc_req_t *)
								reqst->rqst);
		break;
		case VPC_REQ_REASSOC:
			ret = vpc_send_reassoc_req((vpc_reassoc_req_t *)
								reqst->rqst);
		break;
		case VPC_REQ_WRITE:
			ret = vpc_send_write_req((vpc_wr_req_t *)reqst->rqst);
		break;
		case VPC_REQ_INVAL_BATCH:
			ret = vpc_send_invb_req((vpc_invb_req_t *)reqst->rqst);
		break;
		case VPC_REQ_SETATTR:
			ret = vpc_send_setattr_req((vpc_setattr_req_t *)
							reqst->rqst);
		break;
	}
	return ret;
}
EXPORT_SYMBOL(vpc_submit_req);

/*
 * Protocol API for server ASN to release request buffer
 */
void
vpc_req_free(int type, vpc_req_t *req)
{
	if (type == VPC_REQ_WRITE) {
		vpc_wr_req_t *wrq = (vpc_wr_req_t *)req->rqst;
		/* free data buffers */
		if (wrq->dtype == DATA_SNGLBUF)
			vpc_buffer_free(wrq->data);
		else {
			free_iov_data(wrq->data, wrq->iovlen);
			free_iov(wrq->data, wrq->iovlen);
		}
	}
	free_msgbuf((msgbuf_t *)req);
}
EXPORT_SYMBOL(vpc_req_free);

/*
 * Protocol API to close client ASN connection.
 */
int
vpc_close_conn(u32_t conn_hdl)
{
	vpc_conn_t *conn;

	conn = conn_get(conn_hdl);
	if (conn == NULL)
		return VPC_INVALID_CONHDL;

	SPIN_LOCK(&conn->lock);
	OS_PRINT("close conn\n");

	close_conn(conn);

	SPIN_UNLOCK(&conn->lock);

	OS_FREE(conn);

	OS_PRINT("%s\n", lock_log);

	return 0;
}
EXPORT_SYMBOL(vpc_close_conn);

/*
 * API to initialize protocol module
 */
void
vpc_protocol_init(void)
{
	int i;
	msgbuf_t *msgbuf;
	dbuf_t *dbuf;
	struct msg_desc *msgd;
	OS_IOV *iov;
	vpc_handlers_t hdlrs = {
		.rx_data_hdlr = vpc_rx_hdlr,
		.xmit_retry = vpc_send_retry,
		.connect_hdlr = vpc_connect_hdlr,
		.conn_error = vpc_conn_err_hdlr,
		.svr_hb = vpc_svr_hb_hdlr,
		.clnt_hb = vpc_clnt_hb_hdlr,
	};

	/* register VSA protocol handlers */
	vpc_transp_init(&hdlrs);

	/* create a cache of msgbuf structs */
	for (i = 0; i < CACHE_ENT_N; i++) {
		msgbuf = (msgbuf_t *)OS_MALLOC(sizeof(msgbuf_t));
		msgbuf->next = msgbuf_hd;
		msgbuf_hd = msgbuf;
	}
	/* create a cache of msg_desc structs */
	for (i = 0; i < CACHE_ENT_N; i++) {
		msgd = (struct msg_desc*)
			OS_ZALLOC_WAIT(sizeof(struct msg_desc));
		msgd->next = msgd_hd;
		msgd_hd = msgd;
	}
	/* create a cache of IOVEC structs */
	for (i = 0; i < CACHE_ENT_N; i++) {
		iov = (OS_IOV *)OS_ZALLOC_WAIT(sizeof(OS_IOV) * SMALL_IOV);
		dbuf = (dbuf_t *)iov;
		dbuf->next = smiov_hd;
		smiov_hd = dbuf;
	}

	/* create a cache of data buffers */
	for (i = 0; i < CACHE_ENT_N; i++) {
		dbuf = (dbuf_t *)OS_MALLOC(VPC_BUF_LEN);
		dbuf->next = dbuf_hd;
		dbuf_hd = dbuf;
	}
	OS_SPIN_LOCK_INIT(&conn_arr_lock);
	OS_SPIN_LOCK_INIT(&msgbuf_lock);
	OS_THR_WAIT_INIT(&mb_wait);
	OS_SPIN_LOCK_INIT(&md_lock);
	OS_THR_WAIT_INIT(&md_wait);
	OS_SPIN_LOCK_INIT(&dbuf_lock);
	OS_SPIN_LOCK_INIT(&iov_lock);
	lock_logp = lock_log;
}
EXPORT_SYMBOL(vpc_protocol_init);

/*
 * prepare for module exit
 */
void
vpc_protocol_exit(void)
{
	int i;
	dbuf_t *buf;
	struct msg_desc *msgd;
	msgbuf_t *msgbuf;
	void *p;

	OS_PRINT("Closing listen sock\n");
	vpc_transp_stop_listen();

	/* cleanup transp */
	vpc_transp_exit();

	/* shutdown connections */
	for (i = 1; i < MAX_CONN; i++) {
		if (conn_arr[i] != NULL) {
			vpc_conn_err_hdlr(conn_arr[i]);
			conn_arr[i] = NULL;
		}
	}

	OS_PRINT("Freeing caches\n");

	/* free caches */
	msgbuf = msgbuf_hd;
	while (msgbuf != NULL) {
		p = (void *)msgbuf;
		msgbuf = msgbuf->next;
		OS_FREE(p);
	}

	msgd = msgd_hd;
	while (msgd != NULL) {
		p = (void *)msgd;
		msgd = msgd->next;
		OS_FREE(p);
	}

	buf = dbuf_hd;
	while (buf != NULL) {
		p = (void *)buf;
		buf = buf->next;
		OS_FREE(p);
	}

	buf = smiov_hd;
	while (buf != NULL) {
		p = (void *)buf;
		buf = buf->next;
		OS_FREE(p);
	}

}
EXPORT_SYMBOL(vpc_protocol_exit);

