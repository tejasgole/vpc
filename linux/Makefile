
VPC_ROOT=$(PWD)
obj-m += vpcd.o
vpcd-objs := ../common/vpc_protocol.o vpc.o vpcioc.o vpc_ksock.o
EXTRA_CFLAGS = -O2 -I$(VPC_ROOT)/ -I$(VPC_ROOT)/../include -I$(VPC_ROOT)/../common -D__LINUX_KRN__
REL=$(shell uname -r)
KDIR = 	/lib/modules/$(REL)/build/

default:
	make -C $(KDIR) SUBDIRS=$(PWD) modules
clean:
	rm -f *.o
	rm -f ../common/*.o
	rm -f *.ko
	rm -f *~
	rm -f *~ ../common/*~ ../include/*~
	make -C $(KDIR) SUBDIRS=$(PWD) clean

