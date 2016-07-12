#ifndef _OSL_H_
#define	_OSL_H_

#ifdef	__KERNEL__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/in.h>
#include <linux/spinlock.h>
#include <linux/kthread.h>
#include <linux/string.h>

struct task_struct;
typedef struct _cond {
	wait_queue_head_t wait_q;
	spinlock_t cond_spin;
	unsigned long cond;
} condvar_t;
	
#define	OS_PRINT		printk
#define	OS_ZALLOC_WAIT(x)	kzalloc(x, GFP_KERNEL)
#define	OS_MALLOC(x)		kmalloc(x, GFP_KERNEL)
#define	OS_FREE(x)		kfree(x)
#define	HTONL(x)		htonl(x)
#define	NTOHL(x)		ntohl(x)
#define	HTONS(x)		htons(x)
#define	NTOHS(x)		ntohs(x)
#define	SPIN_LOCK_T		spinlock_t
#define	SPIN_LOCK(lk)		spin_lock_bh(lk)
#define	SPIN_UNLOCK(lk)		spin_unlock_bh(lk)
#define	THREAD_T		struct task_struct *
#define	THR_WAITQ_T		condvar_t
#define	OS_THR_CREATE(thr, fn, data, str)	 do { \
					thr = kthread_create(fn, data, str); \
				} while(0);
#define	OS_THR_WAIT_INIT(w)  	do { \
					init_waitqueue_head(&(w)->wait_q); \
					(w)->cond = 0; \
					spin_lock_init(&(w)->cond_spin); \
				} while (0);
#define	OS_THR_WAIT(w, l)	do { \
				   DEFINE_WAIT(wait); \
					spin_lock_bh(&(w)->cond_spin); \
					clear_bit(1, &(w)->cond); \
					while (!test_bit(1, &(w)->cond) && \
							!test_and_clear_bit(0, \
							       	&(w)->cond)) { \
						prepare_to_wait(&(w)->wait_q, \
							&wait,	\
							TASK_INTERRUPTIBLE); \
						spin_unlock_bh(&(w)->cond_spin); \
						spin_unlock_bh(l); \
						schedule(); \
						spin_lock_bh(l); \
						spin_lock_bh(&(w)->cond_spin); \
					} \
					spin_lock_bh(l); \
				} while (0);
#define	OS_THR_SIGNAL(w)	wake_up_interruptible(&(w)->wait_q)
#define	OS_SPIN_LOCK_INIT(l)	spin_lock_init(l)
#define	OS_IOV		struct kvec

#else	// USER
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/socket.h>

#define	OS_PRINT		printf
#define	OS_ZALLOC_WAIT(x)	calloc(x, 1)
#define	OS_MALLOC(x)		malloc(x)
#define	OS_FREE(x)		free(x)
#define	HTONL(x)	htonl(x)
#define	NTOHL(x)	ntohl(x)
#define	HTONS(x)	htons(x)
#define	NTOHS(x)	ntohs(x)
#define	THREAD_T	pthread_t
#define	THR_WAITQ_T	pthread_cond_t
#define	SPIN_LOCK_T	pthread_mutex_t
#define	SPIN_LOCK(lk)		pthread_mutex_lock(lk)
#define	SPIN_UNLOCK(lk)		pthread_mutex_unlock(lk)
#define	OS_THR_CREATE(thr, fn, data, str)	pthread_create(thr, NULL, \
								fn, data)
#define	OS_THR_WAIT(w, l)	pthread_cond_wait(w, l)
#define	OS_THR_SIGNAL(w)	pthread_cond_signal(w)
#define	OS_THR_WAIT_INIT(w)	pthread_cond_init(w, NULL)
#define	OS_SPIN_LOCK_INIT(l)	pthread_mutex_init(l, NULL)
#define	OS_IOV		struct iovec

#define	EXPORT_SYMBOL(x)
#endif

#endif
