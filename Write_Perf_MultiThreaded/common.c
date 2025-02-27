#include "common.h"
#include <inttypes.h> //Only for the {Ox%" PRIXPTR "} macro

int common_peer_via_address(const char *addr, enum l_rdma_util_ibv_context_type type,
		struct l_rdma_peer **peer_ptr){

  struct ibv_context *ibv_ctx = NULL;

	int ret = l_rdma_utils_get_ibv_context(addr, type, &ibv_ctx);
	if(ret){
		fprintf(stderr, "Error common peer addres => get ibv context\n");
		return ret;
	}

	ret = l_rdma_peer_new(ibv_ctx, peer_ptr);
	if(ret){
		fprintf(stderr, "Error common peer address => l_rdma_peer_new\n");
	}

	return ret;
}

int common_disconnect_and_wait_for_conn_close(struct l_rdma_conn **conn_ptr){
	int ret = 0;
	enum l_rdma_conn_event conn_event = L_RDMA_CONN_UNDEFINED;
	ret = l_rdma_conn_next_event(*conn_ptr, &conn_event);
	if (!ret && conn_event != L_RDMA_CONN_CLOSED) {
		fprintf(stderr,
			"rdma_conn_next_event returned an unexpected event\n");
	}
  ret |= l_rdma_conn_disconnect(*conn_ptr);
  ret |= l_rdma_conn_delete(conn_ptr);
  return ret;
}

int
client_connect(struct l_rdma_peer *peer, const char *addr, const char *port,
		struct l_rdma_conn_cfg *cfg, struct l_rdma_conn_private_data *pdata,
		struct l_rdma_conn **conn_ptr)
{
  struct l_rdma_conn_req *req = NULL;
	enum l_rdma_conn_event conn_event = L_RDMA_CONN_UNDEFINED;

	int ret = l_rdma_conn_req_new(peer, addr, port, cfg, &req);
	if(ret)
		return ret;

	ret = l_rdma_conn_req_connect(&req, pdata, conn_ptr);
	if(ret)
		return ret;

	ret = l_rdma_conn_next_event(*conn_ptr, &conn_event);
	if(ret){
		goto err_conn_delete;
	} else if (conn_event != L_RDMA_CONN_ESTABLISHED){
		fprintf(stderr, "l_rdma_conn_next_event returned an unexpected event\n");
		ret = -1;
		goto err_conn_delete;
	}

	return 0;

err_conn_delete:
	l_rdma_conn_delete(conn_ptr);

	return ret;

}

int server_accept_connection(struct l_rdma_conn_cfg *cfg, struct l_rdma_conn **conn, struct l_rdma_ep *ep, struct l_rdma_conn_private_data *pdata)
{
	struct l_rdma_conn_req *req = NULL;
	enum l_rdma_conn_event conn_event = L_RDMA_CONN_UNDEFINED;

	int ret = l_rdma_ep_next_conn_req(ep, cfg, &req);
	if(ret){
		fprintf(stderr, "Error gettint connection request\n");
		return ret;
	}

	ret = l_rdma_conn_req_connect(&req, pdata, conn);
	if(ret){
		fprintf(stderr,"Error l_rdma_conn_req_connect\n");
		return ret;
	}

	ret = l_rdma_conn_next_event(*conn, &conn_event);
	printf("Got connection event : %d\n", conn_event);
	if(!ret && conn_event != L_RDMA_CONN_ESTABLISHED){
		fprintf(stderr, "l_rdma_conn_next_event returne an unexpected event\n");
		ret = -1;
	}

	if(ret){
		l_rdma_conn_delete(conn);
	}

	return ret;
}

void *
malloc_aligned(size_t size)
{
	long pagesize = sysconf(_SC_PAGESIZE);
	if (pagesize < 0) {
		perror("sysconf");
		return NULL;
	}

	/* allocate a page size aligned local memory pool */
	void *mem;
	int ret = posix_memalign(&mem, (size_t)pagesize, size);
	if (ret) {
		(void) fprintf(stderr, "posix_memalign: %s\n", strerror(ret));
		return NULL;
	}

	/* zero the allocated memory */
	memset(mem, 0, size);

	return mem;
}

uint64_t
strtoul_noerror(const char *in)
{
	uint64_t out = strtoul(in, NULL, 10);
	if (out == ULONG_MAX && errno == ERANGE) {
		(void) fprintf(stderr, "strtoul(%s) overflowed\n", in);
		exit(-1);
	}
	return out;
}

int
wait_and_process_completions(struct l_rdma_cq *cq, uint64_t *recv, int *send_cmpl, int *recv_cmpl)
{
	struct ibv_wc wc[2];
	int num_got;
	int ret;

	do {
		/* wait for the completion to be ready */
		ret = l_rdma_cq_wait(cq);
		if (ret)
			return ret;

		/* reset num_got to 0  */
		num_got = 0;

		/* get two next completions at most (1 of send + 1 of recv) */
		ret = l_rdma_cq_get_wc(cq, 2, wc, &num_got);
		if (ret)
			/* lack of completion is not an error */
			if (ret != L_RDMA_E_NO_COMPLETION)
				return ret;

		/* validate received completions */
		for (int i = 0; i < num_got; i++) {
			ret = validate_wc(&wc[i], recv, send_cmpl, recv_cmpl);
			if (ret)
				return ret;
		}
	} while (*send_cmpl == 0 || *recv_cmpl == 0);

	return 0;
}

int
validate_wc(struct ibv_wc *wc, uint64_t *recv, int *send_cmpl, int *recv_cmpl)
{
	if (wc->status != IBV_WC_SUCCESS) {
		char *func = (wc->opcode == IBV_WC_SEND)? "send" : "recv";
		(void) fprintf(stderr, "rpma_%s() failed: %s\n",
			func, ibv_wc_status_str(wc->status));
		return -1;
	}

	if (wc->opcode == IBV_WC_SEND) {
		*send_cmpl = 1;
	} else if (wc->opcode == IBV_WC_RECV) {
		if (wc->wr_id != (uintptr_t)recv || wc->byte_len != sizeof(uint64_t)) {
			(void) fprintf(stderr,
				"received completion is not as expected (0x%"
				PRIXPTR " != 0x%" PRIXPTR " [wc.wr_id] || %"
				PRIu32 " != %ld [wc.byte_len])\n", wc->wr_id,
				(uintptr_t)recv, wc->byte_len, sizeof(uint64_t));
			return -1;
		}
		*recv_cmpl = 1;
	}

	return 0;
}

int wait_one_completion(struct l_rdma_cq *cq, uint64_t *recv){
	struct ibv_wc wc[2];
	int num_got;
	int ret;

	ret = l_rdma_cq_wait(cq);
	if (ret)
		return ret;

	num_got = 0;

	ret = l_rdma_cq_get_wc(cq, 1, wc, &num_got);
	if(ret){
		if (ret == L_RDMA_E_NO_COMPLETION)
			printf("No completion received\n");
		return ret;
	}

/*Validate completion*/

	if (wc->status != IBV_WC_SUCCESS) {
		char *func = (wc->opcode == IBV_WC_SEND)? "send" : "recv";
		(void) fprintf(stderr, "rpma_%s() failed: %s\n",
			func, ibv_wc_status_str(wc->status));
		return -1;
	}

	if (wc->opcode == IBV_WC_SEND) {
	} else if (wc->opcode == IBV_WC_RECV) {
		if (wc->wr_id != (uintptr_t)recv || wc->byte_len != sizeof(uint64_t)) {
			(void) fprintf(stderr,
				"received completion is not as expected (0x%"
				PRIXPTR " != 0x%" PRIXPTR " [wc.wr_id] || %"
				PRIu32 " != %ld [wc.byte_len])\n", wc->wr_id,
				(uintptr_t)recv, wc->byte_len, sizeof(uint64_t));
			return -1;
		}
	}
	return 0;
}
