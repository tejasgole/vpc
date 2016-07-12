#ifndef _VPC_USOCK_H_
#define _VPC_USOCK_H_

#define	VPC_MIN_HDR	16
#define	VPC_MAX_MSG	4096

typedef struct sk_conn {
	void *opaque;
	int sock;
	int	state;
	int wr_blocked;
} sk_conn_info_t;

typedef struct _tuneable {
	unsigned snd_buf_size;
	unsigned rcv_buf_size;
	unsigned tcp_idle_time;
	unsigned tcp_keep_intvl;
} vpc_tunables_t;

#endif
