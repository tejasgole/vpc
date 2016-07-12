#include <linux/kernel.h>
#include <net/sock.h>
#include <linux/fcntl.h>
#include <linux/tcp.h>
#include <linux/workqueue.h>
#include <linux/timer.h>
#include "osl.h"
#include "vpc_transp.h"
#include "vpc_ksock.h"

static struct work_struct listen_work;
static struct workqueue_struct *accept_wq;
static struct workqueue_struct *rx_wq;
static struct workqueue_struct *tx_wq;
static struct workqueue_struct *shdn_wq;
static struct workqueue_struct *hb_wq;

static struct socket *vpc_listen_sock;

static vpc_handlers_t proto_hdlrs;
static vpc_tunables_t vpc_tunable = {
	.snd_buf_size = 70000,
	.rcv_buf_size = 700000,
	.srvr_hb_intv = SERVER_HB_INTVL,
	.clnt_hb_intv = CLIENT_HB_INTVL,
};
static int vpc_srv_inited;

/*
 * Timer callback for Heart beat
 */
static void
vpc_sock_hbtimer_cb(unsigned long data)
{
	sk_conn_info_t *sk_connp = (sk_conn_info_t *)data;
	void	*opaque;

	spin_lock_bh(&sk_connp->lock);
	if (sk_connp->state != SK_CONNECTED) {
		spin_unlock_bh(&sk_connp->lock);
		return;
	}

	/* restart timer */
	mod_timer(&sk_connp->hb_timer, jiffies + sk_connp->hb_time);

	opaque = sk_connp->opaque;
	spin_unlock_bh(&sk_connp->lock);

	/* XXXXX: queue_work */
	queue_work(hb_wq, &sk_connp->hb_work);
}

static void
vpc_sock_hb_worker(struct work_struct *work)
{
	sk_conn_info_t *sk_connp;
	void *opaque;
	int svr = 0;

	sk_connp = (sk_conn_info_t *)CONTAINER_OF(hb_work,
						sk_conn_info_t, work);
	spin_lock_bh(&sk_connp->lock);
	if (sk_connp->state != SK_CONNECTED) {
		spin_unlock_bh(&sk_connp->lock);
		return;
	}
	opaque = sk_connp->opaque;
	svr = sk_connp->svr_flag;
	spin_unlock_bh(&sk_connp->lock);

	if (opaque != NULL) {
		if (svr)
			proto_hdlrs.svr_hb(opaque);
		else
			proto_hdlrs.clnt_hb(opaque);
	} else
		printk("sk_connp opaque is NULL\n");
}

/*
 * Upcall when socket has data
 */
static void
vpc_sock_data_ready(struct sock *sk, int bytes)
{
	sk_conn_info_t *sk_connp;

	read_lock(&sk->sk_callback_lock);
	sk_connp = sk->sk_user_data;
	if (sk_connp == NULL)
		return;

	spin_lock_bh(&sk_connp->lock);
	if (sk_connp->state != SK_CONNECTED) {
		spin_unlock_bh(&sk_connp->lock);
		return;
	}
	queue_work(rx_wq, &sk_connp->rx_work);
	spin_unlock_bh(&sk_connp->lock);

	read_unlock(&sk->sk_callback_lock);
}

static void
vpc_sock_datardy_worker(struct work_struct *work)
{
	sk_conn_info_t *sk_connp;
	void *opaque;

	sk_connp = (sk_conn_info_t *)CONTAINER_OF(rx_work,
						sk_conn_info_t, work);
	spin_lock_bh(&sk_connp->lock);
	if (sk_connp->state != SK_CONNECTED) {
		spin_unlock_bh(&sk_connp->lock);
		return;
	}
	opaque = sk_connp->opaque;
	spin_unlock_bh(&sk_connp->lock);

	if (opaque != NULL)
		proto_hdlrs.rx_data_hdlr(opaque);
	else
		printk("sk_connp opaque is NULL\n");
}

/*
 * Upcall when socket has space to write
 */
static void
vpc_sock_write_space(struct sock *sk)
{
	sk_conn_info_t *sk_connp;
	void (*old_write_space)(struct sock *);

	read_lock(&sk->sk_callback_lock);
	sk_connp = sk->sk_user_data;
	if (sk_connp == NULL)
		return;

	spin_lock_bh(&sk_connp->lock);

	old_write_space = sk_connp->write_space;
	read_unlock(&sk->sk_callback_lock);

	if (old_write_space != NULL)
		old_write_space(sk);

	if (sk_connp->state != SK_CONNECTED) {
		spin_unlock_bh(&sk_connp->lock);
		return;
	}

	queue_work(tx_wq, &sk_connp->tx_work);
	spin_unlock_bh(&sk_connp->lock);

	if (sk->sk_socket)
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);

	return ;
}

static void
vpc_sock_wrrdy_worker(struct work_struct *work)
{
	sk_conn_info_t *sk_connp;
	void *opaque;

	sk_connp = (sk_conn_info_t *)CONTAINER_OF(tx_work,
					sk_conn_info_t, work);
	spin_lock_bh(&sk_connp->lock);
	if (sk_connp->state != SK_CONNECTED) {
		spin_unlock_bh(&sk_connp->lock);
		return;
	}
	opaque = sk_connp->opaque;
	spin_unlock_bh(&sk_connp->lock);

	if (opaque != NULL)
		proto_hdlrs.xmit_retry(opaque);
}

static void
vpc_sock_shutdown_worker(struct work_struct *work)
{
	sk_conn_info_t *sk_connp;

	sk_connp = (sk_conn_info_t *)CONTAINER_OF(shdn_work,
					sk_conn_info_t, work);
	proto_hdlrs.conn_error(sk_connp->opaque);
}

static void
sock_restore_callbacks(sk_conn_info_t *sk_connp, struct sock *sk)
{
	write_lock_bh(&sk->sk_callback_lock);
	sk->sk_user_data = NULL;
	sk->sk_data_ready = sk_connp->data_ready;
	sk->sk_write_space = sk_connp->write_space;
	sk->sk_state_change = sk_connp->state_change;
	sk->sk_no_check = 0;
	write_unlock_bh(&sk->sk_callback_lock);
}

/*
 * Upcall when socket changes state
 */
static void
vpc_sock_state_change(struct sock *sk)
{
	sk_conn_info_t *sk_connp;
	void (*old_state_change)(struct sock *);

	read_lock(&sk->sk_callback_lock);
	sk_connp = sk->sk_user_data;
	if (sk_connp == NULL) {
		read_unlock(&sk->sk_callback_lock);
		return;
	}

	printk("sock state change: %d\n", sk->sk_state);
	old_state_change = sk_connp->state_change;

	switch (sk->sk_state) {
		case TCP_SYN_SENT:
		case TCP_SYN_RECV:
		case TCP_ESTABLISHED:
			break;
		case TCP_CLOSE:
			// closed_wq sock_release
			break;
		case TCP_CLOSE_WAIT:
			// peer closed
			// shutdown sock in wq
			spin_lock_bh(&sk_connp->lock);
			sk_connp->state = SK_CLOSED;

			read_unlock(&sk->sk_callback_lock);
			/* restore callbacks */
			sock_restore_callbacks(sk_connp, sk_connp->sock->sk);
			read_lock(&sk->sk_callback_lock);
			queue_work(shdn_wq, &sk_connp->shdn_work);
			spin_unlock_bh(&sk_connp->lock);
		default:
			break;
	}
	read_unlock(&sk->sk_callback_lock);

	if (old_state_change != NULL)
		old_state_change(sk);
	return;
}

/*
 * Set socket options according to tunables.
 */
static int
set_sockopts(struct socket *sock)
{
	int ret, siz;

	/*
	 * Set socket options for data socket
	 */
	siz = vpc_tunable.snd_buf_size;
	ret = kernel_setsockopt(sock, SOL_SOCKET, SO_SNDBUF,
			(char *)&siz, sizeof(siz));
	if (ret < 0)
		goto errout;
	siz = vpc_tunable.rcv_buf_size;
	ret = kernel_setsockopt(sock, SOL_SOCKET, SO_RCVBUF,
			(char *)&siz, sizeof(siz));
	if (ret < 0)
		goto errout;

	siz = VPC_MIN_HDR;
	ret = kernel_setsockopt(sock, SOL_SOCKET, SO_RCVLOWAT,
			(char *)&siz, sizeof(siz));
	if (ret < 0)
		goto errout;

	/*
	 * Set TCP options
	 */
	siz = 1;
	ret = kernel_setsockopt(sock, SOL_TCP, TCP_NODELAY,
			(char *)&siz, sizeof(siz));
	if (ret < 0)
		goto errout;

	return 0;
errout:
	return -1;
}

static int
sock_send_handshake(struct socket *sock)
{
	int ret;
	struct msghdr msg = { 0 };
	mm_segment_t oldfs;
	struct kvec iov;
	char hs_data[HS_MSG_SZ];

	strcpy(hs_data, "VPC HANDSHAKE");
	iov.iov_base = hs_data;
	iov.iov_len = HS_MSG_SZ;

	msg.msg_iov = (struct iovec *)&iov;
	msg.msg_iovlen = 1;

	oldfs = get_fs();
	set_fs(get_ds());
	ret = sock_sendmsg(sock, &msg, HS_MSG_SZ);
	set_fs(oldfs);

	return ret;
}

/*
 * Function to accept one connect request
 */
static int
vpc_sock_handle_connreq(struct socket *sock)
{
	sk_conn_info_t *sk_connp;
	struct socket *new_sock;
	struct sockaddr_in peer;
	int ret, len;

	/*
	 * Accept connection on new socket
	 */
	ret = kernel_accept(sock, &new_sock, O_NONBLOCK);
	if (ret < 0) {
		printk("ksock accept failed: %d\n", ret);
		return (ret);
		sock_release(new_sock);
		return (ret);
	}

	/*
	 * Setup socket options
	 */
	ret = set_sockopts(new_sock);

	sk_connp = kzalloc(sizeof(sk_conn_info_t), GFP_KERNEL);
	if (sk_connp == NULL) {
		sock_release(new_sock);
		return (-ENOMEM);
	}

	sk_connp->sock = new_sock;
	new_sock->sk->sk_user_data = sk_connp;
	/*
	 * setup socket upcalls
	 */
	/* save callbacks */
	sk_connp->data_ready = sock->sk->sk_data_ready;
	sk_connp->write_space = sock->sk->sk_write_space;
	sk_connp->state_change = sock->sk->sk_state_change;
	/* set callbacks */
	new_sock->sk->sk_data_ready = vpc_sock_data_ready;
	new_sock->sk->sk_write_space = vpc_sock_write_space;
	new_sock->sk->sk_state_change = vpc_sock_state_change;

	INIT_WORK(&sk_connp->rx_work, vpc_sock_datardy_worker);
	INIT_WORK(&sk_connp->tx_work, vpc_sock_wrrdy_worker);
	INIT_WORK(&sk_connp->shdn_work, vpc_sock_shutdown_worker);
	INIT_WORK(&sk_connp->hb_work, vpc_sock_hb_worker);
	spin_lock_init(&sk_connp->lock);

	/* Send handshake msg */
	ret = sock_send_handshake(new_sock);
	if (ret < 0) {
		sock_release(new_sock);
		kfree(sk_connp);
	}
	
	/* setup HeartBeat timer */
	sk_connp->svr_flag = 1;
	setup_timer(&sk_connp->hb_timer, vpc_sock_hbtimer_cb,
						(unsigned long)sk_connp);
	sk_connp->hb_time = msecs_to_jiffies(vpc_tunable.srvr_hb_intv);
	ret = mod_timer(&sk_connp->hb_timer, jiffies + sk_connp->hb_time);
	if (ret != 0) {
		printk("vpc_transp: failed HB timer init\n");
	}

	/*
	 * Tell upper layer that connection is ready
	 */
	len = sizeof(peer);
	kernel_getpeername(new_sock, (struct sockaddr *)&peer, &len);
	sk_connp->opaque = proto_hdlrs.connect_hdlr(sk_connp,
			peer.sin_addr.s_addr);

	sk_connp->state = SK_CONNECTED;

	return 0;
}

/*
 * Connection accept worker
 */
static void
vpc_sock_connect_worker(struct work_struct *work)
{
	//while (vpc_sock_handle_connreq(vpc_listen_sock) == 0)
	//	cond_resched();
	vpc_sock_handle_connreq(vpc_listen_sock);
}

/*
 * upcall in tasklet to handle connection request
 */
static void
vpc_sock_listen_data_ready(struct sock *sk, int bytes)
{
	if (sk->sk_state != TCP_LISTEN)
		return;

	/* start connection accept worker */
	queue_work(accept_wq, &listen_work);
}

/*
 * VPC TRANSP API
 */

/*
 * API to start server listening on specified addr/port
 */
int
vpc_transp_listen(u32_t ip, int port)
{
	struct sockaddr_in listen_addr;
	int ret = 0, one;
	struct socket *sock;
	mm_segment_t old_fs = get_fs();

	if (vpc_srv_inited)
		printk("Reinitializing VPC Server\n");
	else {
		vpc_srv_inited = 1;
		printk("Initializing VPC Server\n");
	}

	ret = sock_create_kern(PF_INET, SOCK_STREAM,
				IPPROTO_TCP, &sock);
	if (ret < 0)
		goto err_out1;

	sock->sk->sk_reuse = 1;

	set_fs(KERNEL_DS);
	kernel_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
				(char *)&one, sizeof(one));
	set_fs(old_fs);

	write_lock_bh(&sock->sk->sk_callback_lock);
	sock->sk->sk_user_data = sock->sk->sk_data_ready;
	sock->sk->sk_data_ready = vpc_sock_listen_data_ready;
	write_unlock_bh(&sock->sk->sk_callback_lock);

	listen_addr.sin_family = PF_INET;
	listen_addr.sin_addr.s_addr = ip;
	listen_addr.sin_port = htons(port);
	ret = kernel_bind(sock, (struct sockaddr *)&listen_addr,
				sizeof (struct sockaddr_in));
	if (ret < 0) {
		printk("VPC: Bind failed on listen socket:%d\n", ret);
		goto err_out2;
	}

	ret = kernel_listen(sock, 64);
	if (ret < 0) {
		printk("VPC: Listen failed on listen socket:%d\n", ret);
		goto err_out2;
	}

	INIT_WORK(&listen_work, vpc_sock_connect_worker);
	vpc_listen_sock = sock;

	printk("VPC Server Listening\n");
	return 0;

err_out2:
	sock_release(sock);
err_out1:
	return -1;
}

/*
 * API to connect to specified server
 */
int
vpc_transp_connect(u32_t ip, int port, void *opaque, void **skconnpp)
{
	struct socket *sock = NULL;
	sk_conn_info_t *sk_connp;
	struct sockaddr_in remote = { 0 };
	mm_segment_t oldfs = get_fs();
	struct msghdr msg = { 0 };
	struct kvec iov;
	char hs_data[HS_MSG_SZ];
	int ret;

	ret = sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP,
			&sock);
	if (ret < 0)
		return -1;

	sk_connp = kzalloc(sizeof(sk_conn_info_t), GFP_KERNEL);
	if (sk_connp == NULL) {
		sock_release(sock);
		return (-ENOMEM);
	}

	remote.sin_family = PF_INET;
	remote.sin_addr.s_addr = ip;
	remote.sin_port = htons(port);
	ret = sock->ops->connect(sock, (struct sockaddr *)&remote,
			sizeof(remote), 0);
	if (ret < 0) {
		printk("kernel connect failed: %d\n", ret);
		kfree(sk_connp);
		return -1;
	}

	/* Wait for handshake msg */
	iov.iov_base = hs_data;
	iov.iov_len = HS_MSG_SZ;
	msg.msg_flags = MSG_NOSIGNAL;
	set_fs(get_ds());
	ret = kernel_recvmsg(sock, &msg, &iov, 1, HS_MSG_SZ, MSG_NOSIGNAL);
	set_fs(oldfs);
	if (ret < 0) {
		printk("kernel recvmsg failed: %d\n", ret);
		kfree(sk_connp);
		return -1;
	}

	sk_connp->sock = sock;
	sk_connp->opaque = opaque;

	sock->sk->sk_user_data = (void *)sk_connp;
	/* save callbacks */
	sk_connp->data_ready = sock->sk->sk_data_ready;
	sk_connp->write_space = sock->sk->sk_write_space;
	sk_connp->state_change = sock->sk->sk_state_change;
	/* set callbacks */
	sock->sk->sk_data_ready = vpc_sock_data_ready;
	sock->sk->sk_write_space = vpc_sock_write_space;
	sock->sk->sk_state_change = vpc_sock_state_change;

	INIT_WORK(&sk_connp->rx_work, vpc_sock_datardy_worker);
	INIT_WORK(&sk_connp->tx_work, vpc_sock_wrrdy_worker);
	INIT_WORK(&sk_connp->shdn_work, vpc_sock_shutdown_worker);
	INIT_WORK(&sk_connp->hb_work, vpc_sock_hb_worker);
	spin_lock_init(&sk_connp->lock);

	set_fs(KERNEL_DS);
	ret = set_sockopts(sock);
	set_fs(oldfs);

	/* setup HeartBeat timer */
	sk_connp->svr_flag = 0;
	setup_timer(&sk_connp->hb_timer, vpc_sock_hbtimer_cb,
						(unsigned long)sk_connp);
	sk_connp->hb_time = msecs_to_jiffies(vpc_tunable.clnt_hb_intv);
	ret = mod_timer(&sk_connp->hb_timer, jiffies + sk_connp->hb_time);
	if (ret != 0) {
		printk("vpc_transp: failed HB timer init\n");
	}


	sk_connp->state = SK_CONNECTED;

	*skconnpp = sk_connp;

	return 0;
}

/*
 * API to shutdown connection
 */
void
vpc_transp_conn_shutdown(void *thdl)
{
	sk_conn_info_t *sk_connp = (sk_conn_info_t*)thdl;

	spin_lock_bh(&sk_connp->lock);

	sk_connp->state = SK_CLOSED;
	printk("transp conn shutdown\n");

	sk_connp->opaque = NULL;

	spin_unlock_bh(&sk_connp->lock);

	del_timer(&sk_connp->hb_timer);

	if (sk_connp->sock) {
		kernel_sock_shutdown(sk_connp->sock, RCV_SHUTDOWN |
		 		SEND_SHUTDOWN);
		sock_release(sk_connp->sock);
		sk_connp->sock = NULL;
		kfree(sk_connp);
	}
}

/*
 * API to send Message Vector. Non-blocking.
 */
int
vpc_transp_send_msgv(void *thdl, struct kvec *datav,
		int vlen, int total)
{
	sk_conn_info_t *sk_connp = (sk_conn_info_t*)thdl;
	struct msghdr msg = { 0 };
	struct socket *sock;
	int ret;

	spin_lock_bh(&sk_connp->lock);

	if (sk_connp->state != SK_CONNECTED) {
		spin_unlock_bh(&sk_connp->lock);
		return -1;
	}
	sock = sk_connp->sock;
	spin_unlock_bh(&sk_connp->lock);

	msg.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL,

	set_bit(SOCK_NOSPACE, &sock->flags);
	ret =  kernel_sendmsg(sock, &msg, datav, vlen, total);

	if (ret == (-EAGAIN))
		ret = -1;

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
	struct kvec vec[2];
	struct socket *sock;
	int ret, vlen;

	spin_lock_bh(&sk_connp->lock);

	if (sk_connp->state != SK_CONNECTED) {
		spin_unlock_bh(&sk_connp->lock);
		return -1;
	}
	sock = sk_connp->sock;
	spin_unlock_bh(&sk_connp->lock);

	if (hdr != NULL) {
		vec[0].iov_base = hdr;
		vec[0].iov_len = hlen;
		vec[1].iov_base = data;
		vec[1].iov_len = len;
		if (len == 0) {
			vlen = 1;
			len = hlen;
		} else {
			vlen = 2;
			len = hlen + len;
		}
	} else {
		vec[0].iov_base = data;
		vec[0].iov_len = len;
		vlen = 1;
	}

	msg.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL,

	set_bit(SOCK_NOSPACE, &sock->flags);
	ret =  kernel_sendmsg(sock, &msg, vec, vlen, len);

	if (ret == (-EAGAIN))
		ret = -1;

	return ret; 
}

/*
 * API to read from socket into given Data Vector. Non-blocking.
 */
int
vpc_transp_read_datav(void *thdl, struct kvec *datav,
		int vlen, int total)
{
	sk_conn_info_t *sk_connp = (sk_conn_info_t*)thdl;
	struct msghdr msg = { 0 };
	struct socket *sock;
	int ret;

	spin_lock_bh(&sk_connp->lock);

	if (sk_connp->state != SK_CONNECTED) {
		spin_unlock_bh(&sk_connp->lock);
		return -1;
	}
	sock = sk_connp->sock;
	/* Need to mark read pending in conn ?? */
	spin_unlock_bh(&sk_connp->lock);

	msg.msg_flags = MSG_WAITALL | MSG_DONTWAIT | MSG_NOSIGNAL;
	ret = kernel_recvmsg(sk_connp->sock, &msg, datav, vlen,
			total, MSG_DONTWAIT | MSG_NOSIGNAL);

	if (ret == (-EAGAIN))
		ret = -1;

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
	struct kvec vec = {
		.iov_base = dbuf,
		.iov_len = len,
	};
	struct socket *sock;
	int ret;

	spin_lock_bh(&sk_connp->lock);

	if (sk_connp->state != SK_CONNECTED) {
		spin_unlock_bh(&sk_connp->lock);
		return -1;
	}
	sock = sk_connp->sock;
	/* Need to mark read pending in conn ?? */
	spin_unlock_bh(&sk_connp->lock);

	msg.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL;
	ret = kernel_recvmsg(sk_connp->sock, &msg, &vec, 1,
			len, MSG_DONTWAIT | MSG_NOSIGNAL);

	if (ret == (-EAGAIN))
		ret = -1;

	return ret;
}

/*
 * API to initialize socket transport.
 */
void
vpc_transp_init(vpc_handlers_t *phdlrs)
{
	accept_wq = create_singlethread_workqueue("vpc accept wq");
	rx_wq = create_singlethread_workqueue("vpc rx wq");
	tx_wq = create_singlethread_workqueue("vpc tx wq");
	shdn_wq = create_singlethread_workqueue("vpc shutdown wq");
	hb_wq = create_singlethread_workqueue("vpc hb wq");
	/* Initialize protocol handler upcalls */
	proto_hdlrs = *phdlrs;
}

void
vpc_transp_exit(void)
{

	destroy_workqueue(accept_wq);
	destroy_workqueue(tx_wq);
	destroy_workqueue(rx_wq);
	destroy_workqueue(shdn_wq);
	destroy_workqueue(hb_wq);
}

void
vpc_transp_stop_listen(void)
{
	if (vpc_listen_sock != NULL) {
		kernel_sock_shutdown(vpc_listen_sock, RCV_SHUTDOWN |
		 		SEND_SHUTDOWN);
		sock_release(vpc_listen_sock);
		vpc_listen_sock = NULL;
	}
}
