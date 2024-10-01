/*Code inspired from the ping/pong from the libRPMA*/

#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>

#include "common.h"

#define USAGE_STR "usage: %s <server_address> <port> <seed> <rounds> [<sleep>]\n"

#define MSG_SIZE sizeof(uint64_t)
#define I_M_DONE (uint64_t)UINT64_MAX

int
main(int argc, char *argv[])
{
	/* validate parameters */
	if (argc < 5) {
		fprintf(stderr, USAGE_STR, argv[0]);
		exit(-1);
	}

	/* read common parameters */
	char *addr = argv[1];
	char *port = argv[2];
	uint64_t cntr = strtoul_noerror(argv[3]);
	uint64_t rounds = strtoul_noerror(argv[4]);
	uint64_t sleep_usec = 0;

	if (argc >= 6)
		sleep_usec = strtoul_noerror(argv[5]);

	int ret;

	/* l_rdma resources - general */
	struct l_rdma_peer *peer = NULL;
	struct l_rdma_conn *conn = NULL;

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

	/*
	 * lookup an ibv_context via the address and create a new peer using it
	 */
	//ret = client_peer_via_address(addr, &peer);
	ret = common_peer_via_address(addr, L_RDMA_UTIL_IBV_CONTEXT_REMOTE, &peer);
	if (ret)
		goto err_mr_free;

	/* register the memory */
	ret = l_rdma_mr_reg(peer, recv, MSG_SIZE, L_RDMA_MR_USAGE_RECV, &recv_mr);
	if (ret)
		goto err_peer_delete;
	ret = l_rdma_mr_reg(peer, send, MSG_SIZE, L_RDMA_MR_USAGE_SEND, &send_mr);
	if (ret) {
		(void) l_rdma_mr_dereg(&recv_mr);
		goto err_peer_delete;
	}

	/* establish a new connection to a server listening at addr:port */
	ret = client_connect(peer, addr, port, NULL, NULL, &conn);
	if (ret)
		goto err_mr_dereg;

	/* get the connection's main CQ */
	struct l_rdma_cq *cq = NULL;
	ret = l_rdma_conn_get_cq(conn, &cq);
	if (ret)
		goto err_conn_disconnect;

	while (--rounds) {
		/* prepare a receive for the server's response */
		ret = l_rdma_recv(conn, recv_mr, 0, MSG_SIZE, recv);
		if (ret)
			break;

		/* send a message to the server */
		(void) printf("Value sent: %" PRIu64 "\n", cntr);
		*send = cntr;
		/*
		 * XXX when using l_rdma_F_COMPLETION_ON_ERROR
		 * after few rounds l_rdma_send() returns ENOMEM.
		 */
		ret = l_rdma_send(conn, send_mr, 0, MSG_SIZE, L_RDMA_F_COMPLETION_ALWAYS, NULL);
		if (ret)
			break;

		int send_cmpl = 0;
		int recv_cmpl = 0;

		/* get completions and process them */
			ret = wait_and_process_completions(cq, recv, &send_cmpl, &recv_cmpl);
		if (ret)
			break;

		/* copy the new value of the counter and print it out */
		cntr = *recv;
		printf("Value received: %" PRIu64 "\n", cntr);

		/* sleep if required */
		if (sleep_usec > 0)
			(void) usleep(sleep_usec);
	}

	/* send the I_M_DONE message */
	*send = I_M_DONE;
	ret |= l_rdma_send(conn, send_mr, 0, MSG_SIZE, L_RDMA_F_COMPLETION_ON_ERROR, NULL);

err_conn_disconnect:
	ret |= common_disconnect_and_wait_for_conn_close(&conn);

err_mr_dereg:
	/* deregister the memory regions */
	ret |= l_rdma_mr_dereg(&send_mr);
	ret |= l_rdma_mr_dereg(&recv_mr);

err_peer_delete:
	/* delete the peer object */
	ret |= l_rdma_peer_delete(&peer);

err_mr_free:
	/* free the memory */
	free(send);
	free(recv);

	return ret ? -1 : 0;
}
