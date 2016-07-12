#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <string.h>
#ifdef	__KSOCK
#include "vpc.h"
#else
#include "vpc_api.h"
#endif

#define	CLIENT_VSA_ID	0x1234
#define	SERVER_VSA_ID	0xabcd
#define MAX_ASN		16

const char *const vpc_err_str[] = { VPC_ERR_CODES };
static pthread_cond_t clnt_cond;
static pthread_mutex_t	clnt_lock;
static pthread_t clnt_thr;
static	in_addr_t srv_ip;
static int srv_port, devfd;

typedef enum {
	CREAT_OBJ = 1,
	WRITE_DATA,
	CHANGE_BATCH,
	INVAL_BATCH,
	CLOSE_ASN,
	RECREAT_ASN,
	SET_ATTR,
	EXIT
} choice_t;

struct asn_s {
	char objname[MAX_OBJ_ID_LEN];
	char rmtobjname[MAX_OBJ_ID_LEN];
	u32_t conn_hdl;
	u32_t obj_hdl;
	u32_t batchid;
	int	fd;
};

static struct asn_s *asns[MAX_ASN];

#ifdef	__USOCK
int
clnt_rsp_upcall(int type, void *arg)
{
	pthread_cond_signal(&clnt_cond);
}
#endif

int
rmt_write(u32_t conn_h, u32_t obj_hdl, char *buf, int off,
		int len, int batchid)
{
	int ret, rsp_code;
#ifdef	__KSOCK
	vpcioc_wr_req_t wrt_reqbuf;
#else // __USOCK
	vpc_req_t wrt_reqbuf;
	vpc_wr_req_t *wrt_req = (vpc_wr_req_t *)&wrt_reqbuf.rqst;
	vpc_wr_rsp_t *wrt_rsp = (vpc_wr_rsp_t *)&wrt_reqbuf.resp;
#endif

	// printf("Wait for rmt write\n");
#ifdef	__USOCK
	wrt_req->conn_hdl = conn_h;
	wrt_req->obj_hdl = obj_hdl;
	wrt_req->offset_l = off;
	wrt_req->offset_h = 0;
	wrt_req->batchid = batchid;
	wrt_req->dlen = len;
	wrt_req->dtype = DATA_SNGLBUF;
	wrt_req->iovlen = 0;
	wrt_req->data = buf;

	wrt_rsp->rsp_code = VPC_ERR_INVALID;
	wrt_reqbuf.rsp_upcall = clnt_rsp_upcall;
	ret = vpc_submit_req(VPC_REQ_WRITE, &wrt_reqbuf);
	if (ret < 0) {
		return ret;
	}
	pthread_cond_wait(&clnt_cond, &clnt_lock);
	rsp_code = wrt_rsp->rsp_code;
#else
	wrt_reqbuf.conn_hdl = conn_h;
	wrt_reqbuf.obj_hdl = obj_hdl;
	wrt_reqbuf.offset_l = off;
	wrt_reqbuf.dlen = len;
	wrt_reqbuf.data = buf;
	wrt_reqbuf.rsp_code = -1;
	wrt_reqbuf.batchid = batchid;
	ret = ioctl(devfd, VPCIOC_WRREQ, &wrt_reqbuf);
	if (ret < 0) {
		printf("IOCTL error:%d\n", ret);
		return ret;
	}
	rsp_code = wrt_reqbuf.rsp_code;
#endif
	// printf("rmt write done\n");

	if (rsp_code == VPC_RSP_OK)
		return 0;

	printf("Remote write resp: %d\n", vpc_err_str[rsp_code]);
	return -1;
}

int
do_reassoc(in_addr_t sip, int port, char *lcl_objid, char *rmt_objid,
		int *obj_hdl, int batchid)
{
	u32_t conn_hdl, rsp_code;
	int ret;
#ifdef __USOCK
	vpc_req_t assoc_reqbuf;
	vpc_reassoc_req_t *assoc_req = (vpc_reassoc_req_t *)&assoc_reqbuf.rqst;
	vpc_assoc_rsp_t *assoc_rsp = (vpc_assoc_rsp_t *)&assoc_reqbuf.resp;

	assoc_req->ip = sip;
	assoc_req->port = port;
	strcpy(assoc_req->clnt_obj_id, lcl_objid);
	strcpy(assoc_req->srvr_obj_id, rmt_objid);
	assoc_req->batchid = batchid;
	assoc_rsp->rsp_code = VPC_ERR_INVALID;
	assoc_reqbuf.rsp_upcall = clnt_rsp_upcall;
	assoc_req->err_upcall = NULL;

	ret = vpc_submit_req(VPC_REQ_REASSOC, &assoc_reqbuf);
	if (ret != VPC_RSP_OK)
		return VPC_INVALID_CONHDL;
	pthread_cond_wait(&clnt_cond, &clnt_lock);
	rsp_code = assoc_rsp->rsp_code;
	if (rsp_code == VPC_RSP_OK) {
		conn_hdl = assoc_rsp->conn_hdl;
		*obj_hdl = assoc_rsp->obj_hdl;
	} else {
		printf("Response error: %s\n", vpc_err_str[rsp_code]);
		return VPC_INVALID_CONHDL;
	}
#else
	vpcioc_reassoc_req_t assoc_reqbuf;

	assoc_reqbuf.server_ip = sip;
	assoc_reqbuf.port = port;
	strcpy(assoc_reqbuf.clnt_obj_id, lcl_objid);
	strcpy(assoc_reqbuf.srvr_obj_id, rmt_objid);
	assoc_reqbuf.batchid = batchid;
	assoc_reqbuf.rsp_code = VPC_ERR_INVALID;

	ret = ioctl(devfd, VPCIOC_REASSOC, &assoc_reqbuf);
	if (ret < 0)
		return VPC_INVALID_CONHDL;
	rsp_code = assoc_reqbuf.rsp_code;
	if (rsp_code == VPC_RSP_OK) {
		conn_hdl = assoc_reqbuf.conn_hdl;
		*obj_hdl = assoc_reqbuf.obj_hdl;
	} else {
		if (rsp_code != VPC_ERR_INVALID)
			printf("Response error: %s\n", vpc_err_str[rsp_code]);
		else
			printf("No response\n");
		return VPC_INVALID_CONHDL;
	}
#endif

	return conn_hdl;
}

static void
do_set_attr(struct asn_s *asn, char *attr_str)
{
	u32_t conn_hdl, rsp_code;
	int ret;
#ifdef __USOCK
	vpc_req_t sa_reqbuf;
	vpc_setattr_req_t *sa_req = (vpc_setattr_req_t *)&sa_reqbuf.rqst;
	vpc_setattr_rsp_t *sa_rsp = (vpc_setattr_rsp_t *)&sa_reqbuf.resp;

	sa_req->conn_hdl= asn->conn_hdl;
	sa_req->obj_hdl = asn->obj_hdl;
	sa_req->dlen = strlen(attr_str) + 1;
	sa_rsp->rsp_code = VPC_ERR_INVALID;
	sa_reqbuf.rsp_upcall = clnt_rsp_upcall;
	sa_req->dtype = DATA_SNGLBUF;
	sa_req->iovlen = 0;
	sa_req->data = attr_str;

	ret = vpc_submit_req(VPC_REQ_SETATTR, &sa_reqbuf);
	if (ret != VPC_RSP_OK) {
		printf("submit req failed: %d\n", ret);
		return ;
	}
	pthread_cond_wait(&clnt_cond, &clnt_lock);
	rsp_code = sa_rsp->rsp_code;
	if (rsp_code == VPC_RSP_OK) {
		printf("Set Rmt Attr: %s\n", attr_str);
	} else {
		printf("Response error: %s\n", vpc_err_str[rsp_code]);
	}
#else
	vpcioc_setattr_req_t sa_reqbuf;

	sa_reqbuf.conn_hdl = asn->conn_hdl;
	sa_reqbuf.obj_hdl = asn->obj_hdl;
	sa_reqbuf.dlen = strlen(attr_str) + 1;
	sa_reqbuf.rsp_code = VPC_ERR_INVALID;
	sa_reqbuf.data = attr_str;

	ret = ioctl(devfd, VPCIOC_SETATTR_REQ, &sa_reqbuf);
	if (ret < 0) {
		printf("submit req failed: %d\n", ret);
		return ;
	}
	rsp_code = sa_reqbuf.rsp_code;
	if (rsp_code == VPC_RSP_OK) {
		printf("Set Rmt Attr: %s\n", attr_str);
	} else {
		if (rsp_code != VPC_ERR_INVALID)
			printf("Response error: %s\n", vpc_err_str[rsp_code]);
		else
			printf("No response\n");
	}
#endif
	return;
}

static void
do_batch_inval(struct asn_s *asn, u32_t batchid)
{
	u32_t conn_hdl, rsp_code;
	int ret;
#ifdef __USOCK
	vpc_req_t invb_reqbuf;
	vpc_invb_req_t *invb_req = (vpc_invb_req_t *)&invb_reqbuf.rqst;
	vpc_invb_rsp_t *invb_rsp = (vpc_invb_rsp_t *)&invb_reqbuf.resp;

	invb_req->conn_hdl= asn->conn_hdl;
	invb_req->obj_hdl = asn->obj_hdl;
	invb_req->batchid = batchid;
	invb_rsp->rsp_code = VPC_ERR_INVALID;
	invb_reqbuf.rsp_upcall = clnt_rsp_upcall;

	ret = vpc_submit_req(VPC_REQ_INVAL_BATCH, &invb_reqbuf);
	if (ret != VPC_RSP_OK) {
		printf("submit req failed: %d\n", ret);
		return ;
	}
	pthread_cond_wait(&clnt_cond, &clnt_lock);
	rsp_code = invb_rsp->rsp_code;
	if (rsp_code == VPC_RSP_OK) {
		printf("Invalidated Batch: %d\n", batchid);
	} else {
		printf("Response error: %s\n", vpc_err_str[rsp_code]);
	}
#else
	vpcioc_invb_req_t invb_reqbuf;

	invb_reqbuf.conn_hdl = asn->conn_hdl;
	invb_reqbuf.obj_hdl = asn->obj_hdl;
	invb_reqbuf.batchid = batchid;
	invb_reqbuf.rsp_code = VPC_ERR_INVALID;

	ret = ioctl(devfd, VPCIOC_INVAL_BATCH, &invb_reqbuf);
	if (ret < 0) {
		printf("submit req failed: %d\n", ret);
		return ;
	}
	rsp_code = invb_reqbuf.rsp_code;
	if (rsp_code == VPC_RSP_OK) {
		printf("Invalidated Batch.\n");
	} else {
		if (rsp_code != VPC_ERR_INVALID)
			printf("Response error: %s\n", vpc_err_str[rsp_code]);
		else
			printf("No response\n");
	}
#endif
	return;
}

int
do_assoc(in_addr_t sip, int port, char *ctname, char *objname,
		u32_t flags, int *obj_hdl, char *obj_id,
		int batchid)
{
	u32_t conn_hdl, rsp_code;
	int ret;
#ifdef __USOCK
	vpc_req_t assoc_reqbuf;
	vpc_assoc_req_t *assoc_req = (vpc_assoc_req_t *)&assoc_reqbuf.rqst;
	vpc_assoc_rsp_t *assoc_rsp = (vpc_assoc_rsp_t *)&assoc_reqbuf.resp;

	assoc_req->ip = sip;
	assoc_req->port = port;
	if (strlen(objname) > MAX_OBJ_ID_LEN) {
			printf("objname too long\n");
			return -1;
	}
	assoc_req->obj_access_type = VPC_OBJ_RDWR;
	assoc_req->flags = flags;
	assoc_req->batchid = batchid;
	memcpy(assoc_req->clnt_obj_id, objname, strlen(objname)+1);
	memcpy(assoc_req->srvr_ct_id, ctname, strlen(ctname)+1);
	assoc_rsp->rsp_code = VPC_ERR_INVALID;
	assoc_reqbuf.rsp_upcall = clnt_rsp_upcall;
	assoc_req->err_upcall = NULL;

	ret = vpc_submit_req(VPC_REQ_ASSOC, &assoc_reqbuf);
	if (ret != VPC_RSP_OK)
		return VPC_INVALID_CONHDL;
	pthread_cond_wait(&clnt_cond, &clnt_lock);
	rsp_code = assoc_rsp->rsp_code;
	if (rsp_code == VPC_RSP_OK) {
		conn_hdl = assoc_rsp->conn_hdl;
		*obj_hdl = assoc_rsp->obj_hdl;
		memcpy(obj_id, assoc_rsp->obj_id, MAX_OBJ_ID_LEN);
	} else {
		printf("Response error: %s\n", vpc_err_str[rsp_code]);
		return VPC_INVALID_CONHDL;
	}
#else
	vpcioc_assoc_req_t assoc_reqbuf;

	assoc_reqbuf.server_ip = sip;
	assoc_reqbuf.port = port;
	if (strlen(objname) > MAX_OBJ_ID_LEN) {
			printf("Filename too long\n");
			return -1;
	}
	strcpy(assoc_reqbuf.obj_id, objname);
	strcpy(assoc_reqbuf.ct_id, ctname);
	assoc_reqbuf.obj_access_type = VPC_OBJ_RDWR;
	assoc_reqbuf.flags = flags;
	assoc_reqbuf.batchid = batchid;
	assoc_reqbuf.rsp_code = VPC_ERR_INVALID;

	ret = ioctl(devfd, VPCIOC_ASSOC, &assoc_reqbuf);
	if (ret < 0)
		return VPC_INVALID_CONHDL;
	rsp_code = assoc_reqbuf.rsp_code;
	if (rsp_code == VPC_RSP_OK) {
		conn_hdl = assoc_reqbuf.conn_hdl;
		*obj_hdl = assoc_reqbuf.obj_hdl;
		memcpy(obj_id, assoc_reqbuf.rmt_obj_id, MAX_OBJ_ID_LEN);
	} else {
		if (rsp_code != VPC_ERR_INVALID)
			printf("Response error: %s\n", vpc_err_str[rsp_code]);
		else
			printf("No response\n");
		return VPC_INVALID_CONHDL;
	}
#endif

	return conn_hdl;
}


int
test_basic_writes(u32_t conn_hdl, int fd, u32_t obj_hdl, int batchid)
{
	char *buf512, *buf4K, *buf64K;
	int i, off = 0, ret;
	buf512 = malloc(512);
	buf4K = malloc(4096);
	buf64K = malloc(65536);

	memset(buf512, 'c', 512);
	memset(buf4K, 'b', 4096);
	memset(buf64K, 'd', 65536);

	for (i = 0; i < 1; i++) {
		write(fd, buf512, 512);
		ret = rmt_write(conn_hdl, obj_hdl, buf512, off, 512, batchid);
		if (ret < 0) {
			printf("rmt_write failed: %d\n", ret);
			return ret;
		}
		off += 512;
		write(fd, buf4K, 4096);
		ret = rmt_write(conn_hdl, obj_hdl, buf4K, off, 4096, batchid);
		if (ret < 0) {
			printf("rmt_write failed: %d\n", ret);
			return ret;
		}
		off += 4096;
		write(fd, buf64K, 65536);
		ret = rmt_write(conn_hdl, obj_hdl, buf64K, off, 65536, batchid);
		if (ret < 0)
			return ret;
		off += 65536;
	}
	return 0;
}

#ifdef	__KSOCK
int
do_perf_test(u32_t conn_hdl, u32_t sz_mb, u32_t io_size, u32_t qd)
{
	int ret = 0;
	vpcioc_close_t clsreq;
	vpcioc_perf_t perfreq;

	perfreq.conn_hdl = conn_hdl;
	perfreq.mbytes = sz_mb;
	perfreq.iolen = io_size;
	perfreq.qdepth = qd;
	ret = ioctl(devfd, VPCIOC_PERF_CLNT, &perfreq);
	if (ret < 0)
		return ret;

	clsreq.conn_hdl = conn_hdl;
	ret = ioctl(devfd, VPCIOC_CLOSE, &clsreq);
	return ret;
}
#else
static int cmpltd;
static pthread_mutex_t perf_lock;
static pthread_cond_t perf_cond;
int
perf_rsp_upcall(int type, void *arg)
{
	free(arg);
	pthread_mutex_lock(&perf_lock);
	cmpltd++;
	pthread_mutex_unlock(&perf_lock);
	pthread_cond_signal(&perf_cond);
}

int
do_perf_test(u32_t conn_hdl, u32_t total_sz, u32_t io_size, u32_t qd)
{
	int i, qdepth, n, ret;
	int submitted;
	char *buf;
	vpc_req_t *wrt_reqbuf;
	vpc_wr_req_t *wrt_req;
	vpc_wr_rsp_t *wrt_rsp;

	buf = malloc(io_size);
	n = total_sz/io_size;
	qdepth = qd;
	cmpltd = 0;
	submitted = 0;
	pthread_cond_init(&perf_cond, NULL);
	pthread_mutex_init(&perf_lock, NULL);

	for (i = 0; i < n; i++) {
		pthread_mutex_lock(&perf_lock);
		while ((submitted - cmpltd) > (qdepth - 1)) {
			pthread_cond_wait(&perf_cond, &perf_lock);
		}
		pthread_mutex_unlock(&perf_lock);

		wrt_reqbuf = malloc(sizeof(vpc_req_t));
		wrt_req = (vpc_wr_req_t *)&wrt_reqbuf->rqst;
		wrt_rsp = (vpc_wr_rsp_t *)&wrt_reqbuf->resp;

		wrt_req->conn_hdl = conn_hdl;
		wrt_req->obj_hdl = 0;
		wrt_req->offset_l = 0;
		wrt_req->offset_h = 0;
		wrt_req->dlen = io_size;
		wrt_req->dtype = DATA_SNGLBUF;
		wrt_req->iovlen = 0;
		wrt_req->data = buf;
		wrt_req->batchid = 1;

		wrt_rsp->rsp_code = VPC_ERR_INVALID;
		wrt_reqbuf->rsp_upcall = perf_rsp_upcall;

		ret = vpc_submit_req(VPC_REQ_WRITE, wrt_reqbuf);
		if (ret < 0)
			goto out;
		submitted++;
	}
	pthread_mutex_lock(&perf_lock);
	while (cmpltd < submitted)
		pthread_cond_wait(&perf_cond, &perf_lock);
	pthread_mutex_unlock(&perf_lock);
out:
	free(buf);
	printf("Submitted:%d, Cmpltd:%d\n", submitted, cmpltd);
	return 0;
}
#endif

static void
asn_close(u32_t conn_hdl)
{
	int ret;
#ifdef	__KSOCK
	vpcioc_close_t clsreq;
#endif

#ifdef	__USOCK
	ret = vpc_close_conn(conn_hdl);
#else
	clsreq.conn_hdl = conn_hdl;
	ret = ioctl(devfd, VPCIOC_CLOSE, &clsreq);
#endif
	if (ret != 0) {
		printf("Close conn Error code %d\n", ret);
	}
}

static void
asn_recreat(char *local_objid)
{
	u32_t conn_hdl, obj_hdl;
	int i, ret, fd, lastbatchid;
	FILE *fp;
	struct asn_s *asn;
	char rmt_objid[MAX_OBJ_ID_LEN];
	char str[64];

	/* Check local objid is valid */
	/* Get rmt objname */
	sprintf(str, "clnt/ct-1/%s/ASN", local_objid);
	fp = fopen(str, "r");
	if (fp == NULL) {
		printf("Failed to open %s file\n", str);
		return;
	}
	fgets(rmt_objid, MAX_OBJ_ID_LEN, fp);
	fclose(fp);

	/* Get last batch id */
	sprintf(str, "clnt/ct-1/%s/lastbatch", local_objid);
	fp = fopen(str, "r");
	if (fp == NULL) {
		printf("Failed to open %s file\n", str);
		return;
	}
	fscanf(fp, "%d", &lastbatchid);
	fclose(fp);
	fp = fopen(str, "w+");
	if (fp == NULL) {
		printf("Failed to open %s file\n", str);
		return;
	}

	/* Reassoc to remote */
	printf("Re-assoc with %s, batchid:%d\n", rmt_objid, lastbatchid + 1);
	conn_hdl = do_reassoc(srv_ip, srv_port, local_objid, rmt_objid,
			&obj_hdl, lastbatchid + 1);
	if (conn_hdl == VPC_INVALID_CONHDL) {
		printf("ReAssoc failed\n");
		return;
	}
	printf("\tGot rmt obj hdl = %d\n", obj_hdl);

	asn = malloc(sizeof(struct asn_s));
	strcpy(asn->objname, local_objid);
	strcpy(asn->rmtobjname, rmt_objid);
	asn->conn_hdl = conn_hdl;
	asn->obj_hdl = obj_hdl;
	asn->batchid = lastbatchid + 1;

	for (i = 0; i < MAX_ASN; i++)
		if (asns[i] == NULL)
			break;
	if (i >= MAX_ASN) {
		printf("Too many ASN\n");
		goto err;
	}
	asns[i] = asn;
	/* Create data file at batchid */
	sprintf(str, "clnt/ct-1/%s/%d", local_objid, asn->batchid);
	fd = open(str, O_RDWR | O_CREAT | O_TRUNC,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (fd < 0) {
		printf("Failed to create %s file\n", str);
		goto err;
	}
	asn->fd = fd;

	/* update batch id record */
	fprintf(fp, "%d\n", asn->batchid);
	fclose(fp);
	return;
err:
	fclose(fp);
	asn_close(asn->conn_hdl);
	free(asn);
	asns[i] = NULL;
}

static void 
clnt_asn(char *ctname, char *objname)
{
	u32_t conn_hdl, obj_hdl;
	int ret, i, flags, fd;
	char obj_id[MAX_OBJ_ID_LEN];
	char str[64];
	struct asn_s *asn;

	flags = VPC_ASSOC_FLAG_CREAT;

	conn_hdl = do_assoc(srv_ip, srv_port, ctname, objname, flags,
			&obj_hdl, obj_id, 1);
	if (conn_hdl == VPC_INVALID_CONHDL) {
		printf("Assoc failed\n");
		return;
	}

	printf("\tGot rmt obj hdl = %d\n", obj_hdl);
	printf("\tRmt obj_id = %s\n", obj_id);

	asn = malloc(sizeof(struct asn_s));
	strcpy(asn->objname, objname);
	strcpy(asn->rmtobjname, obj_id);
	asn->conn_hdl = conn_hdl;
	asn->obj_hdl = obj_hdl;
	asn->batchid = 1;

	for (i = 0; i < MAX_ASN; i++)
		if (asns[i] == NULL)
			break;
	if (i >= MAX_ASN) {
		printf("Too many ASN\n");
		goto err;
	}
	asns[i] = asn;
	sprintf(str, "clnt/ct-1/%s", objname);
	mkdir(str, S_IRUSR | S_IWUSR | S_IXUSR |
			S_IRGRP | S_IWGRP | S_IXGRP);
	sprintf(str, "clnt/ct-1/%s/1", objname);
	fd = open(str, O_RDWR | O_CREAT | O_TRUNC,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (fd < 0) {
		printf("Failed to create %s file\n", str);
		goto err;
	}
	asn->fd = fd;
	sprintf(str, "clnt/ct-1/%s/lastbatch", objname);
	fd = open(str, O_RDWR | O_CREAT | O_TRUNC,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (fd < 0) {
		printf("Failed to create %s file\n", str);
		close(asn->fd);
		goto err;
	}
	/* save batchid */
	sprintf(str, "%d\n", 1);
	write(fd, str, strlen(str));
	close(fd);
	/* save rmt objid */
	sprintf(str, "clnt/ct-1/%s/ASN", objname);
	fd = open(str, O_RDWR | O_CREAT | O_TRUNC,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (fd < 0) {
		printf("Failed to create %s file\n", str);
		close(asn->fd);
		goto err;
	}
	write(fd, asn->rmtobjname, strlen(asn->rmtobjname));
	close(fd);
	return;
err:
	asn_close(asn->conn_hdl);
	free(asn);
	asns[i] = NULL;
}

static int
find_asn(char *objid)
{
	int i;

	for (i = 0; i < MAX_ASN; i++) {
		if (asns[i] != NULL) {
			if (!strcmp(asns[i]->objname, objid))
				return i;
		}
	}
	if (i >= MAX_ASN)
		return -1;
}

static void
show_choices(void)
{
	printf("\t\t1) Create OBJ ASN\n");
	printf("\t\t2) WRITE ASN\n");
	printf("\t\t3) Change ASN BATCHID\n");
	printf("\t\t4) INVALIDATE ASN BATCHID\n");
	printf("\t\t5) Close ASN\n");
	printf("\t\t6) Recreate OBJ ASN\n");
	printf("\t\t7) Set OBJ ATTR:\n");
	printf("\t\t8) Exit\n");
}


static choice_t
get_choice(void)
{
	int i;

	(void) scanf("%d", &i);
	return (choice_t)i;
}

static void
do_main_loop(void)
{
	char rmt_ctid[64];
	char local_objid[64];
	char attrib_str[128];
	char fname[64];
	struct asn_s *asn;
	int fd, asnid, ret, batchid;
	choice_t choice;
	FILE *fp;
#ifdef	__KSOCK
	vpcioc_close_t clsreq;
#endif

	do {
		show_choices();
		choice = get_choice();
		switch (choice) {
		case CREAT_OBJ:
			printf("Remote CT ID: ");
			fscanf(stdin, "%s", rmt_ctid);
			printf("Local OBJ ID: ");
			fscanf(stdin, "%s", local_objid);
			clnt_asn(rmt_ctid, local_objid);
			break;
		case RECREAT_ASN:
			printf("Local OBJ ID: ");
			fscanf(stdin, "%s", local_objid);
			asn_recreat(local_objid);
			break;
		case WRITE_DATA:
			printf("Local OBJ ID: ");
			fscanf(stdin, "%s", local_objid);
			asnid = find_asn(local_objid);
			if (asnid < 0) {
				printf("No such ASN\n");
				continue;
			}
			asn = asns[asnid];
			ret = test_basic_writes(asn->conn_hdl, asn->fd,
					asn->obj_hdl, asn->batchid);	
			if (ret != 0) {
				printf("rmt_write Error code %d\n", ret);
			}
			printf("\tWrote Data\n");
			break;
		case CHANGE_BATCH:
			printf("Local OBJ ID: ");
			fscanf(stdin, "%s", local_objid);
			asnid = find_asn(local_objid);
			if (asnid < 0) {
				printf("No such ASN\n");
				continue;
			}
			printf("New batch id: ");
			fscanf(stdin, "%d", &batchid);
			sprintf(fname, "clnt/ct-1/%s/%d", local_objid,
							batchid);
			fd = open(fname, O_RDWR | O_CREAT | O_TRUNC,
					S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
			if (fd < 0) {
				printf("Failed to create %s\n", fname);
				continue;
			}
			/* change fd */
			close(asns[asnid]->fd);
			asns[asnid]->fd = fd;
			/* change batchid */
			sprintf(fname, "clnt/ct-1/%s/lastbatch", local_objid);
			fd = open(fname, O_RDWR | O_CREAT | O_TRUNC,
					S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
			if (fd < 0) {
				printf("Failed to open %s\n", fname);
				continue;
			}
			sprintf(fname, "%d\n", batchid);
			write(fd, fname, strlen(fname));
			close(fd);
			asns[asnid]->batchid = batchid;
			printf("\tBatchid updated to %d\n", batchid);
			break;
		case INVAL_BATCH:
			printf("Local OBJ ID: ");
			fscanf(stdin, "%s", local_objid);
			asnid = find_asn(local_objid);
			if (asnid < 0) {
				printf("No such ASN\n");
				continue;
			}
			printf("Inval batch id: ");
			fscanf(stdin, "%d", &batchid);
			sprintf(fname, "clnt/ct-1/%s/%d", local_objid,
							batchid);
			/* Test Batch id is valid & not current */
			if (asns[asnid]->batchid == batchid) {
				printf("Cannot Invalidate Active batchid\n");
				continue;
			}
			ret = unlink(fname);
			if (ret < 0) {
				printf("Cannot Invalidate batchid: %d\n", batchid);
				continue;
			}
			do_batch_inval(asns[asnid], batchid);
			break;
		case SET_ATTR:
			printf("Local OBJ ID: ");
			fscanf(stdin, "%s", local_objid);
			asnid = find_asn(local_objid);
			if (asnid < 0) {
				printf("No such ASN\n");
				continue;
			}
			printf("Attrib Data String (key=val): ");
			fscanf(stdin, "%s", attrib_str);
			sprintf(fname, "clnt/ct-1/%s/ATTR", local_objid);
			fp = fopen(fname, "a+");
			if (fp == NULL) {
				printf("Failed to open %s file\n", fname);
				return;
			}
			fprintf(fp, "%s\n", attrib_str);
			fclose(fp);
			printf("Set Local Attrib: %s\n", attrib_str);
			do_set_attr(asns[asnid], attrib_str);
			break;
		case CLOSE_ASN:
			printf("Local OBJ ID: ");
			fscanf(stdin, "%s", local_objid);
			asnid = find_asn(local_objid);
			if (asnid < 0) {
				printf("Invalid ASN\n");
				continue;
			}
			asn = asns[asnid];
			asn_close(asn->conn_hdl);
			free(asn);
			asns[asnid] = NULL;
			printf("\tClosed ASN %s\n", local_objid);
			break;
		case EXIT:
			for (asnid = 0; asnid < MAX_ASN; asnid++) {
				if (asns[asnid] != NULL) {
					asn_close(asns[asnid]->conn_hdl);
					free(asns[asnid]);
				}
			}
			return;
		default:
			break;
		}
	} while (1);
}


int
main(int argc, char**argv)
{
	int ret;

	if (argc < 6) {
		printf("Usage:\n");
		printf("clnt -s <ip> -p <port> -i\n");
		printf("clnt -s <ip> -p <port> -m <MB> -l <IO len>\n");
		exit(1);
	}
	if (strcmp(argv[1], "-s") || strcmp(argv[3], "-p")) {
		printf("Usage:\n");
		printf("clnt -s <ip> -p <port> -i\n");
		printf("clnt -s <ip> -p <port> -m <MB> -l <IO len>\n");
		exit(1);
	}

	srv_ip = inet_addr(argv[2]);
	if (srv_ip == (in_addr_t)(-1)) {
		printf("Invalid ip addr.\n");
		exit(1);
	}

	srv_port = strtol(argv[4], NULL, 10);

#ifdef	__KSOCK
	devfd = open("/dev/vpc", O_RDWR);
	if (devfd < 0) {
		printf("Failed to open VPC device\n");
		exit(1);
	}
#else
	vpc_protocol_init();
#endif
	if (!strcmp(argv[5], "-m")) {
		int mb, iolen, qd;
		u32_t conn_hdl, obj_hdl;
		char obj_id[MAX_OBJ_ID_LEN];

		if (strcmp(argv[7], "-l")) {
			printf("clnt -s <ip> -p <port> -m <MB> -l <IO len>\n");
			exit(1);
		}
		mb = strtol(argv[6], NULL, 10);
		iolen = strtol(argv[8], NULL, 10);

		if (argv[9] != NULL) {
			if (!strcmp(argv[9], "-q"))
				qd = strtol(argv[10], NULL, 10);
			else
				qd = 1;
		} else
			qd = 1;
		conn_hdl = do_assoc(srv_ip, srv_port, "perf-ct", "fake-file",
				VPC_ASSOC_FLAG_PERF, &obj_hdl, obj_id, 1);
		if (conn_hdl == VPC_INVALID_CONHDL) {
			exit(1);
		}

		do_perf_test(conn_hdl, mb, iolen, qd);

	} else if (!strcmp(argv[5], "-i")) {
		do_main_loop();
	}

	exit(0);
}

