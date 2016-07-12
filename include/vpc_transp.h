#ifndef _VPC_TRANSP_H_
#define	_VPC_TRANSP_H_

#include "vpc_types.h"

typedef struct _hdlrs {
	void (*rx_data_hdlr)(void *);
	void (*xmit_retry)(void *);
	void *(*connect_hdlr)(void *, u32_t);
	void (*conn_error)(void *);
	void (*svr_hb)(void *);
	void (*clnt_hb)(void *);
} vpc_handlers_t;

#define	TRANSP_WAIT	1
#define	TRANSP_NOWAIT	0

struct iovec;

void vpc_transp_init(vpc_handlers_t *);
void vpc_transp_exit(void);
int vpc_transp_listen(u32_t, int);
void vpc_transp_stop_listen(void);
int vpc_transp_connect(u32_t, int, void *, void **);
int vpc_transp_send_msgv(void *thdl, OS_IOV *, int, int);
int vpc_transp_send_msg(void *thdl, void *hdr, int hlen, void *, int);
int vpc_transp_read_datav(void *, OS_IOV *, int, int);
int vpc_transp_read_data(void *, void *, int);
void vpc_transp_conn_shutdown(void *);
#endif
