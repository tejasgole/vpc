/*
 * Copyright 2012, Marvell
 * All rights reserved
 *
 */
/*
 * VSA Peer Cache Module
 */
#include <linux/moduleparam.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/netdevice.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include "vpc.h"

MODULE_LICENSE("GPL");

#define	MAX_OUTSTANDING		64
#define	MIN(x, y)	((x) < (y) ? (x) : (y))

static int vpc_ioctl(struct inode *, struct file *, unsigned int,
		unsigned long);
static int vpc_major;
static struct file_operations vpc_fops =
{
	.ioctl = vpc_ioctl,
};

extern int vpcioc_ioctl(struct inode *, struct file *, unsigned int, unsigned long);
extern void vpcioc_init(void);
extern void vpcioc_exit(void);

/*
 * IOCTL handler
 */
static int
vpc_ioctl(struct inode *inode, struct file *file,
		unsigned int cmd, unsigned long param)
{
	return vpcioc_ioctl(inode, file, cmd, param);
}

/*
 * Module init
 */
int __init
vpc_init(void)
{

	/* register char dev */
	vpc_major = register_chrdev(0, "vpc", &vpc_fops);

	/* initialize vpc protocol */
	vpc_protocol_init();

	/* initialize vpc kmem cache */
	vpcioc_init();

	printk("VPC module loaded\n");
	return (0);
}

/*
 * Module exit
 */
void __exit
vpc_exit(void)
{
	vpc_protocol_exit();

	vpcioc_exit();

	unregister_chrdev(vpc_major, "vpc");
	printk("VPC module unloaded\n");
}

module_init(vpc_init);
module_exit(vpc_exit);
