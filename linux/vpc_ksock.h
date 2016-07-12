#ifndef _VPC_SOCK_PRIV_H_
#define _VPC_SOCK_PRIV_H_

#define	VPC_MIN_HDR		16
#define	VPC_MAX_MSG		4096
#define	HS_MSG_SZ		32

#define	OFFSET_OF(f, t)		(long)(&((t *)(0))->f)
#define	CONTAINER_OF(f, t, p)	\
				(((void *)p) - OFFSET_OF(f, t))

#define	SERVER_HB_INTVL		(45*1000)
#define	CLIENT_HB_INTVL		(5*1000)
#define	SK_CONNECTED		1
#define	SK_CLOSED		2
typedef struct sk_conn {
	spinlock_t lock;
	void *opaque;
	struct socket *sock;
	void *data_ready;
	void *write_space;
	void *state_change;
	struct timer_list hb_timer;
	struct work_struct rx_work;
	struct work_struct tx_work;
	struct work_struct shdn_work;
	struct work_struct hb_work;
	int	state;
	int	hb_time;
	int	svr_flag;
} sk_conn_info_t;

typedef struct _tuneable {
	u32_t snd_buf_size;
	u32_t rcv_buf_size;
	u32_t srvr_hb_intv;
	u32_t clnt_hb_intv;
} vpc_tunables_t;

#endif
