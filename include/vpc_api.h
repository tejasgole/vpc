#ifndef _VPC_API_H_
#define	_VPC_API_H_

#include "vpc_types.h"

#define	MAX_OBJ_ID_LEN	16
#define	MAX_RQST_BYTES	128
#define	MAX_RESP_BYTES	128


/*
 * Error codes
 */
#define	C(x)	x,
#define	VPC_ERR_CODES	\
	C(VPC_RSP_OK) \
	C(VPC_ERR_CREAT_FAIL) \
	C(VPC_ERR_NOT_FOUND) \
	C(VPC_ERR_QFULL) \
	C(VPC_ERR_WRFAIL) \
	C(VPC_ERR_OBJ_EXCEEDED) \
	C(VPC_ERR_LISTEN_FAIL) \
	C(VPC_ERR_CONN_FAIL) \
	C(VPC_ERR_SEND_FAIL) \
	C(VPC_ERR_NOMEM) \
	C(VPC_ERR_BATCH_CREAT) \
	C(VPC_ERR_INVAL_CTID) \
	C(VPC_ERR_INVAL_OBJID) \
	C(VPC_ERR_ACTV_BATCH) \
	C(VPC_ERR_BATCH_INVAL) \
	C(VPC_ERR_SETATTR_FAIL) \
	C(VPC_ERR_MSG_TIMEOUT) 


/*
 * Return codes
 *
 * define string array to print error codes in calling program:
 * const char *const vpc_err_str[] = { VPC_ERR_CODES };
 * This way doing the following will print error string:
 *
 * ret = vpc_submit_req(...);
 * if (ret != VPC_RSP_OK)
 * 	printf("error: %s\n", vpc_err_str[ret]);
 *
 */
typedef enum {
	VPC_ERR_CODES
	VPC_ERR_INVALID = 255
} vpc_ret_t;

#undef C
#define	C(x)	#x,

/*
 * Invalid handle values
 */
#define	VPC_INVALID_CONHDL	(0)
#define	VPC_INVALID_OBJHDL	 (0xFFFF)

/*
 * Request Type values
 * 	for vpc_submit_req
 */
enum {
	VPC_REQ_ASSOC = 0x100,
	VPC_REQ_WRITE,
	VPC_REQ_REASSOC,
	VPC_REQ_SETATTR,
	VPC_REQ_INVAL_BATCH,
	VPC_REQ_DISASSOC
};

/*
 * Request structure
 */
typedef struct _reqst {
	char rqst[MAX_RQST_BYTES];	/* cast to req type specific struct */
	char resp[MAX_RESP_BYTES];	/* response received in this area */
	char msgcookie[sizeof(u64_t)];	/* internal use */
	int (*rsp_upcall)(int type, void *); /* clnt req completion callback */
} vpc_req_t;

/*
 * Resp structure for send by server.
 */
typedef struct _vpc_resp {
	char resp[MAX_RESP_BYTES];	/* cast to resp type specific struct */
	u32_t dlen;
	u16_t dtype;	/* Is data an IOVEC */
	u16_t iovlen;
	void *data;
	char msgcookie[sizeof(u64_t)];
	void (*send_done)(void *resp); /* optional completion upcall */
} vpc_resp_t;

/*
 * ===================== REQ/RSP structures ====================
 */

/*
 * Resp for VPC_REQ_WRITE
 */
typedef struct _wrrsp {
	u32_t rsp_code;
} vpc_wr_rsp_t;

/*
 * Client Req for VPC_REQ_WRITE
 */
#define	DATA_SNGLBUF	1
#define	DATA_IOVEC	2
typedef struct _wrrq {
	u32_t conn_hdl;
	u32_t obj_hdl;
	u32_t offset_l;
	u32_t offset_h;
	u32_t batchid;
	u32_t dlen;
	u16_t dtype;	/* Is data an IOVEC */
	u16_t iovlen;
	void *data;
} vpc_wr_req_t;

/*
 * Client Req for Setattr
 */
typedef struct _setattr {
	u32_t conn_hdl;
	u32_t obj_hdl;

	u32_t dlen;
	u16_t dtype;	/* Is data an IOVEC */
	u16_t iovlen;
	void *data;
} vpc_setattr_req_t;

/*
 * Setattr Resp
 */
typedef struct _setatr_rsp {
	u32_t rsp_code;
} vpc_setattr_rsp_t;

/*
 * Client Req for VPC_REQ_INVAL_BATCH
 */
typedef struct _invbrq {
	u32_t conn_hdl;
	u32_t obj_hdl;
	u32_t batchid;
} vpc_invb_req_t;

/*
 * Resp for VPC_REQ_INVAL_BATCH
 */
typedef struct _invbrsp {
	u32_t rsp_code;
} vpc_invb_rsp_t;

/*
 * Resp for VPC_REQ_ASSOC
 */
typedef struct _assocrsp {
	u32_t rsp_code;
	u32_t conn_hdl;
	u32_t obj_hdl;
	char  obj_id[MAX_OBJ_ID_LEN];
} vpc_assoc_rsp_t;

/*
 * Client Req for VPC_REQ_ASSOC
 */
#define	VPC_OBJ_RDWR		1
#define	VPC_OBJ_RDONLY		2
#define	VPC_ASSOC_FLAG_CREAT	1
#define	VPC_ASSOC_FLAG_PERF	2
typedef struct _assocrq {
	u32_t ip;
	u32_t port;
	char clnt_obj_id[MAX_OBJ_ID_LEN];
	char srvr_ct_id[MAX_OBJ_ID_LEN];
	u32_t flags;
	u32_t batchid;
	u32_t obj_access_type;
	void (*err_upcall)(void *);
	void *clnt_cookie;
} vpc_assoc_req_t;

typedef struct _reassocrq {
	u32_t ip;
	u32_t port;
	char clnt_obj_id[MAX_OBJ_ID_LEN];
	char srvr_obj_id[MAX_OBJ_ID_LEN];
	u32_t batchid;
	void (*err_upcall)(void *);
	void *clnt_cookie;
} vpc_reassoc_req_t;

/*
 * ================ End REQ/RSP structs ======================
 */

/*
 * Server register info
 */
typedef struct _srvinfo {
	u32_t ip;
	u32_t port;
	u32_t vsa_id;
	int (*req_upcall)(u32_t conn_hdl, int type, void *);
	void (*conn_err_upcall)(u32_t conn_hdl, u32_t obj_hdl);
} vpc_srvinfo_t;

/*
 * Protocol API
 */
extern void vpc_protocol_init(void);
extern void vpc_protocol_exit(void);
extern vpc_ret_t vpc_init_srvr(vpc_srvinfo_t *srvinfo);
extern void vpc_stop_srvr(void);
extern vpc_ret_t vpc_submit_req(int type, vpc_req_t *reqbuf);
extern void vpc_req_free(int type, vpc_req_t *reqbuf);
extern vpc_ret_t vpc_send_resp(u32_t conn_hdl, int rsp_type, vpc_resp_t *rsp);
extern int vpc_close_conn(u32_t);

#endif
