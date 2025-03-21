/*Code inspired from the ping/pong from the libRPMA*/

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#define USAGE_STR "usage: %s <server_address>\n"

#include "common.h"

#include "common.h"
#ifdef NVMM
#include "memkind.h"
#endif

#ifndef WRITE_SIZE
	#define WRITE_SIZE 250000000 //250MB
#endif
#define SEND_SIZE sizeof(uint64_t)
#define MSG_SIZE (SEND_SIZE + WRITE_SIZE)
#define I_M_DONE (uint64_t)UINT64_MAX

typedef struct thread_param_t {
	int id;
	char* addr;
	char* port;
} thread_param;

void* thread_run(void *args){
	thread_param* param = (thread_param*) args;
	int id = param->id;
	char* addr = param->addr;
	char* port = param->port;

	int ret;

	/* prepare memory */
	common_mem mem;
	memset(&mem, 0, sizeof(common_mem));
	struct l_rdma_mr_local *mr = NULL;

#ifdef NVMM
	mem.mr_ptr = memkind_malloc(MEMKIND_DAX_KMEM_ALL, write_size);
#else
	mem.mr_ptr = malloc(WRITE_SIZE);
#endif
	if(mem.mr_ptr == NULL){
		fprintf(stderr, "failed to allocate memory\n");
		exit(-1);
	}

	//connection ressources
	struct l_rdma_peer *peer;
	struct l_rdma_ep *ep;
	struct l_rdma_conn *conn;

	ret = common_peer_via_address(addr, L_RDMA_UTIL_IBV_CONTEXT_LOCAL, &peer);
	if(ret){
		fprintf(stderr, "Failed to peer with addr\n", ret);
		exit(-2);
	}

	ret = l_rdma_ep_listen(peer, addr, port, &ep);
	if(ret){
		fprintf(stderr, "Failed to Listen\n", ret);
		exit(-3);
	}

	ret = l_rdma_mr_reg(peer, mem.mr_ptr, WRITE_SIZE, L_RDMA_MR_USAGE_WRITE_DST, &mr);
	if(ret){
		fprintf(stderr, "Failed to register memory\n", ret);
		exit(-4);
	}


	size_t mr_desc_size;
	ret = l_rdma_mr_get_descriptor_size(mr, &mr_desc_size);
	if(ret){
		fprintf(stderr, "Failed to get descirptor size\n", ret);
		exit(-5);
	}


	struct common_data data = {0};
	data.data_offset = 0;
	data.mr_desc_size = mr_desc_size;

	ret= l_rdma_mr_get_descriptor(mr, &data.descriptors[0]);
	if(ret){
		fprintf(stderr, "Failed to get descriptor\n", ret);
		exit(-6);
	}

	struct l_rdma_conn_private_data pdata;
	pdata.ptr = &data;
	pdata.len = sizeof(struct common_data);

	ret = server_accept_connection(NULL, &conn, ep, &pdata);
	if(ret){
		fprintf(stderr, "Failed to accept connection\n", ret);
		exit(-7);
	}


	ret = common_disconnect_and_wait_for_conn_close(&conn);
	if(ret){
		fprintf(stderr, "Failed to wait or disconnect\n", ret);
		exit(-8);
	}
}

int
main(int argc, char *argv[])
{
	int ret = 0;
	/* validate parameters */
	if (argc < 2) {
		fprintf(stderr, USAGE_STR, argv[0]);
		exit(-1);
	}

	/* read common parameters */
	char *addr = argv[1];
	char *port[4] = {"1234", "1235", "1236", "1237"};

	thread_param params[4];
	pthread_t id[4];

	for (size_t i = 0; i < 4; i++) {
		params[i].id = i;
		params[i].addr = addr;
		params[i].port = port[i];
		pthread_create(&id[i], NULL, thread_run, (void*)&params[i]);
	}

	for (size_t i = 0; i < 4; i++) {
		ret = pthread_join(id[i], NULL);
		if(ret){
			fprintf(stderr, "Error on join function: %d\n", ret);
			exit(-1);
		}
	}

}
