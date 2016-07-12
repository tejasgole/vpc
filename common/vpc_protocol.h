#ifndef _VPC_PROTOCOL_H_
#define	_VPC_PROTOCOL_H_

#define	VPC_PROTO_VER	1

#define	OFFSET_OF(f, t)		(int)(&((t *)(0))->f)
#define	CONTAINER(field, type, ptr)	\
		(((void *)ptr) - OFFSET_OF(field, type))
/*
 * VPC Message types
 */
enum {
	VPC_MSG_ASSOC_REQ = 0x100,
	VPC_MSG_ASSOC_RESP,
	VPC_MSG_WR_REQ,
	VPC_MSG_GEN_RESP,
	VPC_MSG_HB,
	VPC_MSG_HB_RSP,
	VPC_MSG_REASSOC_REQ,
	VPC_MSG_INVAL_BATCH,
	VPC_MSG_SETATTR_REQ
};

/*
 * VPC conn states
 */
enum {
	VPC_STATE_CONNECTED = 1,
	VPC_STATE_CLOSED,
};

/*
 * VPC rx states
 */
enum {
	EXPECT_MSG_HDR = 1,
	EXPECT_MSGBUF,
	EXPECT_MSG_DATA
};

/*
 * msg descriptor
 */
struct msg_desc {
	u32_t mtype;
	u16_t hlen;
	u16_t hdone;
	u32_t dlen;
	u32_t done;
	void *msgbuf;
	void *data;
	struct msg_desc *next;
	void (*asn_send_done)(void *sd_arg);
	void *sd_arg;
	int iovlen;
	int last;
	int off;
};

/*
 * Connection struct
 */
typedef struct _conn {
	SPIN_LOCK_T	lock;
	int state;
	int rx_state;
	int rx_msgs;
	int tx_msgs;
	int n_hb;
#define	TX_IN_PROGRESS	1
	unsigned int flags;
	struct msg_desc *tx_q_hd;
	struct msg_desc *tx_q_tl;
	u32_t rmt_ip;
	u32_t conn_idx;
	void *transp_hdl;
	void (*err_upcall)(void *cookie);
	void *clnt_cookie;
	u32_t obj_hdl;
	struct msg_desc cur_rx_msg;
} vpc_conn_t;


#define	MAX_OBJ_ID	16
#define	MAX_MSG_BUF	256
#define	HB_RETRY_LIMIT	9

/*
 * On the WIRE message format:
 * +----------------+
 * |    msg_hdr     | common header: 16bytes
 * +----------------+
 * |    msgcookie   | 8bytes
 * +----------------+
 * | type spcfc hdr | variable bytes MAX 1000bytes
 * +----------------+
 * |  optional data | variable MAX 512KB
 * +----------------+
 */

/*
 * Common Msg Header
 * NBO (Network Byte Order)
 */
typedef struct _m_hdr {
	u32_t proto_ver;
	u32_t msg_type;
	u32_t msg_hlen;
	u32_t msg_dlen;
} vpc_msg_hdr_t;

/*
 * ASSOC MSG on the wire
 * NBO (Network Byte Order)
 */
typedef struct _assoc_msg {
	vpc_msg_hdr_t m_hdr;
	char	msgcookie[sizeof(u64_t)];
	u32_t	obj_access_type;
	u32_t	flags;
	u32_t batchid;
	char	clnt_obj_id[MAX_OBJ_ID];
	char	srvr_ct_id[MAX_OBJ_ID];
} vpc_msg_assoc_t;

/*
 * RE-ASSOC MSG on the wire
 * NBO (Network Byte Order)
 */
typedef struct _reassoc_msg {
	vpc_msg_hdr_t m_hdr;
	char	msgcookie[sizeof(u64_t)];
	char	clnt_obj_id[MAX_OBJ_ID];
	char	srvr_obj_id[MAX_OBJ_ID];
	u32_t batchid;
} vpc_msg_reassoc_t;

/*
 * ASSOC RSP on the wire
 * NBO (Network Byte Order)
 */
typedef struct _assoc_rsp {
	vpc_msg_hdr_t m_hdr;
	char	msgcookie[sizeof(u64_t)];
	u32_t	rsp_code;
	u32_t	obj_hdl;
	char	obj_id[MAX_OBJ_ID];
} vpc_msg_assoc_rsp_t;


/*
 * WRITE MSG on the wire
 * NBO
 */
typedef struct _wr_msg {
	vpc_msg_hdr_t m_hdr;
	char	msgcookie[sizeof(u64_t)];
	u32_t obj_hdl;
	u32_t batchid;
	u32_t offset_l;
	u32_t offset_h;
} vpc_msg_write_t;

/*
 * BATCH INVAL MSG on the wire
 * NBO
 */
typedef struct _invb_msg {
	vpc_msg_hdr_t m_hdr;
	char msgcookie[sizeof(u64_t)];
	u32_t obj_hdl;
	u32_t batchid;
} vpc_msg_invb_t;

/*
 * SETATTR MSG on the wire
 * NBO
 */
typedef struct _setattr_msg {
	vpc_msg_hdr_t m_hdr;
	char	msgcookie[sizeof(u64_t)];
	u32_t	obj_hdl;
	u32_t	attr_len;
	/* attrib data follows */
} vpc_msg_setattr_t;

/*
 * GENERIC RSP on the wire
 * NBO
 */
typedef struct _gen_rsp {
	vpc_msg_hdr_t m_hdr;
	char msgcookie[sizeof(u64_t)];
	u32_t rsp_code;
	u32_t req_mtype;
} vpc_msg_gen_rsp_t;

#endif
