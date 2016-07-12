#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <time.h>
#include "osl.h"
#include "vpc_transp.h"
#include "vpc_usock.h"

static int vpc_listen_sock = -1;
static sk_conn_info_t *vpc_clnt_skconn;
static sk_conn_info_t *vpc_srv_skconn;

static vpc_handlers_t proto_hdlrs;
static vpc_tunables_t vpc_tunable = {
	.snd_buf_size = 60000,
	.rcv_buf_size = 60000,
	.tcp_idle_time = 5,
	.tcp_keep_intvl = 5
};
static int vpc_srv_inited;
static pthread_t vpc_transp_thr;
static pthread_cond_t vpc_sock_cond;
static pthread_mutex_t vpc_sock_lock;

/*
 * Upcall when socket has data
 */
static void
vpc_sock_data_ready(sk_conn_info_t *sk_connp)
{
	if (sk_connp == NULL)
		return;
	if (sk_connp->opaque == NULL)
		return;

	proto_hdlrs.rx_data_hdlr(sk_connp->opaque);
}

/*
 * Upcall when socket has space to write
 */
static void
vpc_sock_write_space(sk_conn_info_t *sk_connp)
{
	if (sk_connp == NULL)
		return;

	proto_hdlrs.xmit_retry(sk_connp->opaque);
}

/*
 * Upcall when socket changes state
 */
static void
vpc_sock_state_change(sk_conn_info_t *sk_connp)
{

	if (sk_connp == NULL) {
		return;
	}

	proto_hdlrs.conn_error(sk_connp->opaque);
}

/*
 * Set socket options according to tunables.
 */
static int
set_sockopts(int sock)
{
	int ret, siz, opts;

	opts = fcntl(sock, F_GETFL);
	if (opts < 0)
		goto errout;
	opts = (opts | O_NONBLOCK);
	if (fcntl(sock, F_SETFL, opts) < 0)
		goto errout;
		
	/*
	 * Set socket options for data socket
	 */
	siz = vpc_tunable.snd_buf_size;
	ret = setsockopt(sock, SOL_SOCKET, SO_SNDBUF,
			(char *)&siz, sizeof(siz));
	if (ret < 0)
		goto errout;
	siz = vpc_tunable.rcv_buf_size;
	ret = setsockopt(sock, SOL_SOCKET, SO_RCVBUF,
			(char *)&siz, sizeof(siz));
	if (ret < 0)
		goto errout;

	siz = VPC_MIN_HDR;
	ret = setsockopt(sock, SOL_SOCKET, SO_RCVLOWAT,
			(char *)&siz, sizeof(siz));
	if (ret < 0)
		goto errout;

	/*
	 * Set TCP options
	 */
	siz = 1;
	ret = setsockopt(sock, IPPROTO_TCP, TCP_NODELAY,
			(char *)&siz, sizeof(siz));
	if (ret < 0)
		goto errout;

	return 0;
errout:
	return -1;
}

/*
 * Function to accept one connect request
 */
static int
vpc_sock_handle_connreq(int sock)
{
	sk_conn_info_t *sk_connp;
	int new_sock;
	struct sockaddr_in peer;
	int ret, addrlen;

	/*
	 * Accept connection on new socket
	 */
	addrlen = sizeof(peer);
	new_sock = accept(sock, (struct sockaddr *)&peer, &addrlen);
	if (new_sock < 0) {
		close(sock);
		return (ret);
	}

	/*
	 * Setup socket options
	 */
	ret = set_sockopts(new_sock);

	sk_connp = calloc(sizeof(sk_conn_info_t), 1);
	if (sk_connp == NULL) {
		close(new_sock);
		return (-ENOMEM);
	}
	sk_connp->sock = new_sock;

	/*
	 * Tell upper layer that connection is ready
	 */
	sk_connp->opaque = proto_hdlrs.connect_hdlr(sk_connp,
			peer.sin_addr.s_addr);

	vpc_srv_skconn = sk_connp;

	return 0;
}

static	fd_set rd_fdset;
static	fd_set wr_fdset;
static	fd_set err_fdset;

/*
 * Socket worker thread
 */
static void *
vpc_sock_worker(void *arg)
{
	struct timespec ts;
	struct timeval tv;

	while (vpc_listen_sock == -1 &&
			vpc_clnt_skconn == NULL) {
		/* Wait until listen or connect */
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += 1;
		pthread_cond_timedwait(&vpc_sock_cond, &vpc_sock_lock, &ts);
	}

	for (;;) {
		FD_ZERO(&rd_fdset);
		FD_ZERO(&wr_fdset);
		FD_ZERO(&err_fdset);

		if (vpc_listen_sock != -1)
			FD_SET(vpc_listen_sock, &rd_fdset);
		if (vpc_srv_skconn != NULL)
			if (vpc_srv_skconn->sock > -1) {
				FD_SET(vpc_srv_skconn->sock, &rd_fdset);
				if (vpc_srv_skconn->wr_blocked)
					FD_SET(vpc_srv_skconn->sock, &wr_fdset);
				FD_SET(vpc_srv_skconn->sock, &err_fdset);
			}
		if (vpc_clnt_skconn != NULL)
			if (vpc_clnt_skconn->sock > -1) {
				FD_SET(vpc_clnt_skconn->sock, &rd_fdset);
				if (vpc_clnt_skconn->wr_blocked)
					FD_SET(vpc_clnt_skconn->sock, &wr_fdset);
				FD_SET(vpc_clnt_skconn->sock, &err_fdset);
			}

		pthread_mutex_unlock(&vpc_sock_lock);
		tv.tv_sec = 0;
		tv.tv_usec = 10000;
		if (select(FD_SETSIZE, &rd_fdset, &wr_fdset,
					&err_fdset, &tv) < 0) {
			perror("select");
			continue;
		}
		pthread_mutex_lock(&vpc_sock_lock);
		if (vpc_listen_sock > -1 &&
				FD_ISSET(vpc_listen_sock, &rd_fdset)) {
			pthread_mutex_unlock(&vpc_sock_lock);
			vpc_sock_handle_connreq(vpc_listen_sock);
			pthread_mutex_lock(&vpc_sock_lock);
			continue;
		}

		if (vpc_srv_skconn != NULL &&
				FD_ISSET(vpc_srv_skconn->sock, &rd_fdset)) {
			pthread_mutex_unlock(&vpc_sock_lock);
			vpc_sock_data_ready(vpc_srv_skconn);
			pthread_mutex_lock(&vpc_sock_lock);
		}

		if (vpc_clnt_skconn != NULL &&
				FD_ISSET(vpc_clnt_skconn->sock, &rd_fdset)) {
			pthread_mutex_unlock(&vpc_sock_lock);
			vpc_sock_data_ready(vpc_clnt_skconn);
			pthread_mutex_lock(&vpc_sock_lock);
		}

		if (vpc_srv_skconn != NULL &&
				FD_ISSET(vpc_srv_skconn->sock, &wr_fdset)) {
			vpc_srv_skconn->wr_blocked = 0;
			pthread_mutex_unlock(&vpc_sock_lock);
			vpc_sock_write_space(vpc_srv_skconn);
			pthread_mutex_lock(&vpc_sock_lock);
		}

		if (vpc_clnt_skconn != NULL &&
				FD_ISSET(vpc_clnt_skconn->sock, &wr_fdset)) {
			vpc_clnt_skconn->wr_blocked = 0;
			pthread_mutex_unlock(&vpc_sock_lock);
			vpc_sock_write_space(vpc_clnt_skconn);
			pthread_mutex_lock(&vpc_sock_lock);
		}
	}
}

/*
 * VPC TRANSP API
 */

/*
 * API to start server listening on specified addr/port
 */
int
vpc_transp_listen(unsigned ip, int port)
{
	struct sockaddr_in listen_addr;
	int ret = 0, one;
	int sock;

	if (vpc_srv_inited)
		printf("Reinitializing VPC Server\n");
	else {
		vpc_srv_inited = 1;
		printf("Initializing VPC Server\n");
	}

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock < 0)
		goto err_out1;

	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
				(char *)&one, sizeof(one));

	listen_addr.sin_family = PF_INET;
	/* Assumes already in NBO from inet_addr */
	listen_addr.sin_addr.s_addr = ip;
	listen_addr.sin_port = htons(port);
	ret = bind(sock, (struct sockaddr *)&listen_addr,
				sizeof (struct sockaddr_in));
	if (ret < 0)
		goto err_out2;

	ret = listen(sock, 5);
	if (ret < 0)
		goto err_out2;

	vpc_listen_sock = sock;

	/* wake up service thread */
	pthread_cond_signal(&vpc_sock_cond);

	return 0;

err_out2:
	close(sock);
err_out1:
	return -1;
}

/*
 * API to connect to specified server
 */
int
vpc_transp_connect(unsigned ip, int port, void *opaque, void **skconnpp)
{
	int sock = -1;
	sk_conn_info_t *sk_connp;
	struct sockaddr_in remote = { 0 };
	int ret;

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;

	sk_connp = calloc(sizeof(sk_conn_info_t), 1);
	if (sk_connp == NULL) {
		close(sock);
		return (-ENOMEM);
	}

	remote.sin_family = PF_INET;
	/* Assumes already in NBO from inet_addr */
	remote.sin_addr.s_addr = ip;
	remote.sin_port = htons(port);
	ret = connect(sock, (struct sockaddr *)&remote, sizeof(remote));
	if (ret < 0) {
		free(sk_connp);
		return -1;
	}

	*skconnpp = sk_connp;
	sk_connp->sock = sock;
	sk_connp->opaque = opaque;

	vpc_clnt_skconn = sk_connp;

	set_sockopts(sock);


	/* wakeup worker on client side */
	pthread_cond_signal(&vpc_sock_cond);

	return 0;
}

/*
 * API to shutdown connection
 */
void
vpc_transp_conn_shutdown(void *thdl)
{
	sk_conn_info_t *sk_connp = (sk_conn_info_t*)thdl;
	if (sk_connp->sock) {
		if (sk_connp == vpc_clnt_skconn)
			vpc_clnt_skconn = NULL;
		if (sk_connp == vpc_srv_skconn)
			vpc_srv_skconn = NULL;
		shutdown(sk_connp->sock, SHUT_RDWR);
		close(sk_connp->sock);
	}
}

/*
 * API to send Message Vector. Non-blocking.
 */
int
vpc_transp_send_msgv(void *thdl, struct iovec *datav,
		int vlen, int total)
{
	sk_conn_info_t *sk_connp = (sk_conn_info_t*)thdl;
	struct msghdr msg = { 0 };
	int ret;

	msg.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL,
	msg.msg_iov = datav;
	msg.msg_iovlen = vlen;

	ret =  sendmsg(sk_connp->sock, &msg, O_NONBLOCK);
	if (ret == -EAGAIN) {
		pthread_mutex_lock(&vpc_sock_lock);
		sk_connp->wr_blocked = 1;
		FD_SET(sk_connp->sock, &wr_fdset);
		pthread_mutex_unlock(&vpc_sock_lock);
	}

	return ret; 
}

/*
 * API to send single data buffer message. Non-blocking.
 */
int
vpc_transp_send_msg(void *thdl, void *hdr, int hlen,
		void *data, int len)
{
	sk_conn_info_t *sk_connp = (sk_conn_info_t*)thdl;
	struct msghdr msg = { 0 };
	struct iovec vec[2];
	int ret, vlen;

	if (hdr != NULL) {
		vec[0].iov_base = hdr;
		vec[0].iov_len = hlen;
		vec[1].iov_base = data;
		vec[1].iov_len = len;
		if (len == 0)
			vlen = 1;
		else
			vlen = 2;
	} else {
		vec[0].iov_base = data;
		vec[0].iov_len = len;
		vlen = 1;
	}

	msg.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL,
	msg.msg_iov = vec;
	msg.msg_iovlen = vlen;

	ret =  sendmsg(sk_connp->sock, &msg, O_NONBLOCK);
	if (ret < 0) {
		perror("sendmsg");
		pthread_mutex_lock(&vpc_sock_lock);
		sk_connp->wr_blocked = 1;
		FD_SET(sk_connp->sock, &wr_fdset);
		pthread_mutex_unlock(&vpc_sock_lock);
	}
	return ret; 
}

/*
 * API to read from socket into given Data Vector. Non-blocking.
 */
int
vpc_transp_read_datav(void *thdl, struct iovec *datav,
		int vlen, int total)
{
	sk_conn_info_t *sk_connp = (sk_conn_info_t*)thdl;
	struct msghdr msg = { 0 };
	int ret;

	msg.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL;
	msg.msg_iov = datav;
	msg.msg_iovlen = vlen;

	ret = recvmsg(sk_connp->sock, &msg, O_NONBLOCK);
	return ret;
}

/*
 * API to read from socket into given data buffer. Non-blocking.
 */
int
vpc_transp_read_data(void *thdl, void *dbuf, int len)
{
	sk_conn_info_t *sk_connp = (sk_conn_info_t*)thdl;
	struct msghdr msg = { 0 };
	struct iovec vec = {
		.iov_base = dbuf,
		.iov_len = len,
	};
	int ret;

	msg.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;

	ret = recvmsg(sk_connp->sock, &msg, O_NONBLOCK);
	return ret;
}

/*
 * API to initialize socket transport.
 */
void
vpc_transp_init(vpc_handlers_t *phdlrs)
{
	/* start worker thread */
	pthread_mutex_init(&vpc_sock_lock, NULL);
	pthread_cond_init(&vpc_sock_cond, NULL);
	pthread_create(&vpc_transp_thr, NULL, vpc_sock_worker, NULL);

	/* Initialize protocol handler upcalls */
	proto_hdlrs = *phdlrs;
}

void
vpc_transp_exit(void)
{
}

void
vpc_transp_stop_listen(void)
{
}

