#ifndef _VPC_H_
#define	_VPC_H_

#include <linux/ioctl.h>
#include "vpc_api.h"

#define	VPCIOC_MAGIC		'V'
#define	VPCIOC_ASSOC		_IOWR(VPCIOC_MAGIC, 1, vpcioc_assoc_req_t)
#define	VPCIOC_WRREQ		_IOWR(VPCIOC_MAGIC, 2, vpcioc_wr_req_t)
#define	VPCIOC_SRV_INIT		_IOWR(VPCIOC_MAGIC, 3, vpcioc_srv_info_t)
#define	VPCIOC_RESP_WR		_IOWR(VPCIOC_MAGIC, 4, vpcioc_resp_t)
#define	VPCIOC_RESP_ASSOC	_IOWR(VPCIOC_MAGIC, 5, vpcioc_resp_t)
#define	VPCIOC_WAIT		_IOWR(VPCIOC_MAGIC, 6, vpcioc_await_req_t)
#define	VPCIOC_CLOSE		_IOWR(VPCIOC_MAGIC, 7, vpcioc_await_req_t)
#define	VPCIOC_PERF_WAIT	_IOWR(VPCIOC_MAGIC, 8, vpcioc_await_req_t)
#define	VPCIOC_PERF_CLNT	_IOWR(VPCIOC_MAGIC, 9, vpcioc_perf_t)
#define	VPCIOC_SRV_STOP		_IO(VPCIOC_MAGIC, 10)
#define	VPCIOC_REASSOC		_IOWR(VPCIOC_MAGIC, 11, vpcioc_reassoc_req_t)
#define	VPCIOC_INVAL_BATCH	_IOWR(VPCIOC_MAGIC, 12, vpcioc_invb_req_t)
#define	VPCIOC_RESP_INVB	_IOWR(VPCIOC_MAGIC, 13, vpcioc_resp_t)
#define	VPCIOC_RESP_SETATTR	_IOWR(VPCIOC_MAGIC, 14, vpcioc_resp_t)
#define	VPCIOC_SETATTR_REQ	_IOWR(VPCIOC_MAGIC, 15, vpcioc_setattr_req_t)


#ifdef	__KERNEL__
#define	MAX_IOC_RQST_SZ		512
typedef struct _ext_rq {
	vpc_req_t req;
	struct task_struct *thr;
	struct _ext_rq *next;
	struct _ext_rq *prev;
} vpc_req_ext_t;
#endif


/*
 * REQ_WRITE ioctl struct
 */
typedef struct _write_req {
	u32_t conn_hdl;
	u32_t obj_hdl;
	void *data;
	int dlen;
	u32_t offset_l;
	int rsp_code;
	u32_t batchid;
	char msgcookie[sizeof(u64_t)];
} vpcioc_wr_req_t;

/*
 * REQ_SETATTR ioctl struct
 */
typedef struct _sa_req {
	u32_t conn_hdl;
	u32_t obj_hdl;
	void *data;
	int dlen;
	int rsp_code;
	char msgcookie[sizeof(u64_t)];
} vpcioc_setattr_req_t;

/*
 * REQ_INVAL_BATCH ioctl struct
 */
typedef struct _inval_batch {
	u32_t conn_hdl;
	u32_t obj_hdl;
	u32_t batchid;
	int rsp_code;
	char msgcookie[sizeof(u64_t)];
} vpcioc_invb_req_t;

/*
 * REQ_CLOSE ioctl struct
 */
typedef struct _cls_rq {
	u32_t conn_hdl;
} vpcioc_close_t;

/*
 * REQ_ASSOC ioctl struct
 */
typedef struct _assoc_req {
	u32_t server_ip;
	u32_t port;
	u32_t obj_access_type;
	char obj_id[MAX_OBJ_ID_LEN];
	char ct_id[MAX_OBJ_ID_LEN];
	u32_t flags;
	u32_t batchid;
	int rsp_code;
	u32_t conn_hdl;
	u32_t obj_hdl;
	char rmt_obj_id[MAX_OBJ_ID_LEN];
	char msgcookie[sizeof(u64_t)];
} vpcioc_assoc_req_t;

/*
 * REQ_REASSOC ioctl
 */
typedef struct _reassoc_req {
	u32_t server_ip;
	u32_t port;
	char clnt_obj_id[MAX_OBJ_ID_LEN];
	char srvr_obj_id[MAX_OBJ_ID_LEN];
	u32_t batchid;
	int rsp_code;
	u32_t conn_hdl;
	u32_t obj_hdl;
	char msgcookie[sizeof(u64_t)];
} vpcioc_reassoc_req_t;

/*
 * REQ_DISASSOC ioctl struct
 */
typedef struct _disassoc_req {
	u32_t obj_hdl;
} vpcioc_disassoc_req_t;

/*
 * SRV_INIT ioctl struct
 */
typedef struct _srv_info {
	u32_t ip;
	u32_t port;
	u32_t vsa_id;
} vpcioc_srv_info_t;

#define	MAX_RESP_SZ	256
/*
 * ioctl response
 */
typedef struct _vpcioc_resp {
	u32_t conn_hdl;
	u32_t obj_hdl;
	int rsp_code;
	char obj_id[MAX_OBJ_ID_LEN];
	char msgcookie[sizeof(u64_t)];
} vpcioc_resp_t;

#define	MAX_REQ_SZ	256
typedef struct _wait_req {
	char reqmsg[MAX_REQ_SZ];
	u32_t conn_hdl;
	u32_t type;
	void *dbuf;
	u32_t buflen;
} vpcioc_await_req_t;

typedef struct _pclnt_req {
	u32_t conn_hdl;
	u32_t mbytes;
	u32_t iolen;
	u32_t qdepth;
} vpcioc_perf_t;


#endif /* _VPC_H_ */
