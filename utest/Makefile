
UMODE_FLAG = __USOCK -g
KMODE_FLAG = __KSOCK -g

all: uclnt_asn usvr_asn kclnt_asn ksvr_asn

uclnt_asn: clnt_asn.c vpc_usock.c ../common/vpc_protocol.c
	gcc -o uclnt_asn -lrt -lpthread -D$(UMODE_FLAG) -I./ -I../include -I../common -I../linux \
		clnt_asn.c vpc_usock.c ../common/vpc_protocol.c

kclnt_asn: clnt_asn.c
	gcc -o kclnt_asn -lrt -lpthread -D$(KMODE_FLAG) -I./ -I../include -I../common -I../linux \
		clnt_asn.c

usvr_asn: svr_asn.c vpc_usock.c ../common/vpc_protocol.c
	gcc -o usvr_asn -lrt -lpthread -D$(UMODE_FLAG) -I../include -I./ -I../linux svr_asn.c \
		vpc_usock.c ../common/vpc_protocol.c

ksvr_asn: svr_asn.c
	gcc -o ksvr_asn -lrt -lpthread -D$(KMODE_FLAG) -I../include -I./ -I../linux svr_asn.c

clean:
	rm -f uclnt_asn usvr_asn kclnt_asn ksvr_asn *.o
	rm -f ../common/*.o
	rm -f *~ ../common/*~ ../include/*~
