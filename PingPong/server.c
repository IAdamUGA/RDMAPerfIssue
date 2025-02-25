/*Code inspired from the ping/pong from the libRPMA*/

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#define USAGE_STR "usage: %s <server_address> <port>\n"

#include "common.h"

#ifndef WRITE_SIZE
	#define WRITE_SIZE 125000000 //125MB
#endif
#define SEND_SIZE sizeof(uint64_t)
#define MSG_SIZE (SEND_SIZE + WRITE_SIZE)
#define I_M_DONE (uint64_t)UINT64_MAX

int
main(int argc, char *argv[])
{
	/* validate parameters */
	if (argc < 3) {
		fprintf(stderr, USAGE_STR, argv[0]);
		exit(-1);
	}

	/* read common parameters */
	char *addr = argv[1];
	char *port = argv[2];
	int ret;

	/* prepare memory */
	struct l_rdma_mr_local *recv_mr, *send_mr;
	uint64_t *recv = malloc_aligned(MSG_SIZE);
	if (recv == NULL)
		return -1;
	uint64_t *send = malloc_aligned(MSG_SIZE);
	if (send == NULL) {
		free(recv);
		return -1;
	}

	/* l_rdma resources */
	struct l_rdma_peer *peer = NULL;
	struct l_rdma_ep *ep = NULL;
	struct l_rdma_conn_req *req = NULL;
	enum l_rdma_conn_event conn_event = L_RDMA_CONN_UNDEFINED;
	struct l_rdma_conn *conn = NULL;

	/*
	 * lookup an ibv_context via the address and create a new peer using it
	 */
	ret = common_peer_via_address(addr, L_RDMA_UTIL_IBV_CONTEXT_LOCAL, &peer);
	if (ret)
		goto err_free;

	/* start a listening endpoint at addr:port */
	ret = l_rdma_ep_listen(peer, addr, port, &ep);
	if (ret)
		goto err_peer_delete;

	/* register the memory */
	ret = l_rdma_mr_reg(peer, recv, MSG_SIZE, L_RDMA_MR_USAGE_RECV, &recv_mr);
	if (ret)
		goto err_ep_shutdown;
	ret = l_rdma_mr_reg(peer, send, MSG_SIZE, L_RDMA_MR_USAGE_SEND, &send_mr);
	if (ret) {
		(void) l_rdma_mr_dereg(&recv_mr);
		goto err_ep_shutdown;
	}

	size_t mr_desc_size;
	ret = l_rdma_mr_get_descriptor_size(recv_mr, &mr_desc_size);
	if(ret){
		fprintf(stderr, "error get descriptor size\n");
		exit(-2);
	}

	struct common_data data = {0};
	data.data_offset=0;
	data.mr_desc_size = mr_desc_size;

	ret = l_rdma_mr_get_descriptor(recv_mr, &data.descriptors[0]);

	/*
 * Wait for an incoming connection request, accept it and wait for its
 * establishment.
 */
	struct l_rdma_conn_private_data pdata;
	pdata.ptr = &data;
	pdata.len = sizeof(struct common_data);
	/* receive an incoming connection request */
	ret = l_rdma_ep_next_conn_req(ep, NULL, &req);
	if (ret)
		goto err_mr_dereg;

	if (ret) {
		(void) l_rdma_conn_req_delete(&req);
		goto err_mr_dereg;
	}

	/* accept the connection request and obtain the connection object */
	ret = l_rdma_conn_req_connect(&req, &pdata, &conn);
	if (ret)
		goto err_mr_dereg;

	/* wait for the connection to be established */
	ret = l_rdma_conn_next_event(conn, &conn_event);
	if (ret)
		goto err_conn_disconnect;
	if (conn_event != L_RDMA_CONN_ESTABLISHED) {
		fprintf(stderr, "error conn_event not right event\n");
		goto err_conn_disconnect;
	}

	/* get the connection's main CQ */
	struct l_rdma_cq *cq = NULL;
	ret = l_rdma_conn_get_cq(conn, &cq);
	if (ret)
		goto err_conn_disconnect;

	/* IBV_WC_SEND completion in the first round is not present */
	int send_cmpl = 1;
	int recv_cmpl = 0;
	l_rdma_recv(conn, recv_mr, 0, MSG_SIZE, recv);
	wait_one_completion(cq, recv);
	if (ret)
		exit(1);

	while (1) {

		if (*recv == I_M_DONE)
			break;

		/* print the received old value of the client's counter */
		(void) printf("Value received: %" PRIu64 "\n", *recv);

		/* calculate a new counter's value */
		*send = *recv + 1;
		/*
		 * XXX when using l_rdma_F_COMPLETION_ON_ERROR
		 * after few rounds l_rdma_send() returns ENOMEM.
		 */
		ret = l_rdma_send(conn, send_mr, 0, MSG_SIZE, L_RDMA_F_COMPLETION_ALWAYS, NULL);
		if (ret)
			break;


		/* send the new value to the client */
		(void) printf("Value sent: %" PRIu64 "\n", *send);

		/* prepare a receive for the client's response */
		ret = l_rdma_recv(conn, recv_mr, 0, MSG_SIZE, recv);
		if (ret)
			break;
		/* reset */
		send_cmpl = 0;
		recv_cmpl = 0;
		/* get completions and process them */
		ret = wait_and_process_completions(cq, recv, &send_cmpl, &recv_cmpl);
	}

err_conn_disconnect:
	ret |= common_disconnect_and_wait_for_conn_close(&conn);

err_mr_dereg:
	/* deregister the memory regions */
	ret |= l_rdma_mr_dereg(&send_mr);
	ret |= l_rdma_mr_dereg(&recv_mr);

err_ep_shutdown:
	//ret |= l_rdma_ep_shutdown(&ep);

err_peer_delete:
	/* delete the peer object */
	ret |= l_rdma_peer_delete(&peer);

err_free:
	free(send);
	free(recv);

	return ret ? -1 : 0;
}
