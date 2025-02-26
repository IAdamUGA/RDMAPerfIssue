#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>

#include "common.h"

#define USAGE_STR "usage: %s <server_address> <port> [mem_size]\n"

#ifndef WRITE_SIZE
	#define WRITE_SIZE 125000000 //125MB
#endif
#define SEND_SIZE sizeof(uint64_t)
#define MSG_SIZE (SEND_SIZE)
#define I_M_DONE (uint64_t)UINT64_MAX

int
main(int argc, char *argv[])
{
	int ret = 0;
	/* validate parameters */
	if (argc < 3) {
		fprintf(stderr, USAGE_STR, argv[0]);
		exit(-1);
	}

	/* read common parameters */
	char *addr = argv[1];
	char *port = argv[2];
	uint64_t write_size;
	if(argv >= 4)
		write_size = argv[3];
	else
		write_size = WRITE_SIZE;

	//Memory region ressources
	struct common_mem mem;
	memset(&mem, 0, sizeof(struct common_mem));
	struct l_rdma_mr_remote *dst_mr = NULL;
	size_t dst_size = 0;
	size_t dst_offset = 0;
	struct l_rdma_mr_local src_mr = NULL;
	struct ibv_wc;

	mem.mr_ptr = malloc(write_size);
	if(mrm.mr_ptr == NULL){
		fprintf(stderr, "memory allocation failed\n");
		exit(-1);
	}

	struct l_rdma_peer *peer = NULL;
	struct l_rdma_conn *conn = NULL;

	ret = common_peer_via_address(addr, L_RDMA_UTIL_IBV_CONTEXT_REMOTE, &peer);
	if(ret){
		fprintf(stderr, "Peer_via_address failed: %d\n", ret);
		exit(-1);
	}

	ret = client_connect(peer, addr, port, NULL, NULL, &conn);
	if(ret){
		fprintf(stderr, "Connection to server failed: %d\n", ret);
		exit(-1);
	}

	ret = l_rdma_mr_reg(peer, mem.mr_ptr, mem.mr_size, L_RDMA_MR_USAGE_WRITE_SRC, &src_mr);
	if(ret){
		fprintf(stderr, "Memory registration failed: %d\n");
		exit(-2);
	}

	//Remote memory region description
	struct l_rdma_conn_private_data pdata;
	ret = l_rdma_conn_get_private_data(conn, &pdata);
	if(ret || pdata.len < sizeof(struct common_data)){
		fprintf(stderr, "Failed to get private data\n");
		exit(-3);
	}

	struct common_data *dst_data = pdata.ptr;
	ret = l_rdma_mr_remote_from_descriptor(&dst_data->descriptors[0], dst_data->mr_desc_size, &dst_mr);

	//get remote size
	ret = l_rdma_mr_remote_get_size(dst_mr, &dst_size);
	if(ret){
		fprintf(sterr, "Failet to get remote Size: %d\n", ret);
		exit(-4);
	} else if (dst_size < write_size){
		fprintf(stderr, "Remote size too small (%zu < %d)\n",	dst_size - dst_offset, write_size);
		exit(-5);
	}

	struct l_rdma_cq *cq = NULL;
	ret = l_rdma_conn_get_cq(conn, &cq);
	if(ret){
		fprintf(stderr, "Failed to get CompletionQueue: %d\n", ret);
		exit(-6);
	}

	double timeWrite = 0;
	struct timespec tick, tock;

	uint64_t writing = 1;

	while(1){
		clock_gettime(CLOCK_REALTIME, &tick);
		ret = l_rdma_write(conn, dst_mr, dst_offset, src_mr, 0, writing, L_RDMA_F_COMPLETION_ALWAYS);
		if(ret){
			fprintf(sterr, "Failed to Write data: %d\n", ret);
			exit(-7);
		}

		ret = l_rdma_cq_wait(cq);
		if(ret){
			fprintf(sterr, "Failed to wait a completion: %d\n", ret);
			exit(-8);
		}

		clock_gettime(CLOCK_REALTIME, &tock);

		ret = l_rdma_cq_get_wc(cq, 1, &wc, NULL);
		if(ret){
			fprintf(sterr, "Failed to get a Work Completion: %d\n", ret);
			exit(-9);
		}
		if (wc.status != IBV_WC_SUCCESS) {
			ret = -1;
			(void) fprintf(stderr, "rpma_read() failed: %s\n",
					ibv_wc_status_str(wc.status));
			exit(-10);
		}
		if (wc.opcode != IBV_WC_RDMA_READ) {
			ret = -1;
			(void) fprintf(stderr,
					"unexpected wc.opcode value (%d != %d)\n",
					wc.opcode, IBV_WC_RDMA_READ);
			exit(-11);
		}

		printf("Write %d Bytes in %d ns\n", writing, timeWrite);
		writing = writing*2;
		if(writing > write_size)
			writing = write_size;

	}

}
