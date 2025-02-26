#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "lib_rdma.h"

#define DESCRIPTORS_MAX_SIZE 24
#define ERROR_CLIENT_PEER_ADDR -101
#define ERROR_CLIENT_CONNECT -102
#define ERROR_REGISTER_MEM_REGION -103
#define ERROR_GET_PRIVATE_DATA -104
#define ERROR_DISTANT_SIZE_TOO_SMALL -105
#define ERROR_CLIENT_WRITE -106
#define ERROR_PEER_CFG_FROM_DESC -107
#define ERROR_CONN_APPLY_PEER_CFG -108
#define ERROR_MR_REMOTE_FROM_DESC -109
#define ERROR_MR_GET_SIZE -110
#define ERROR_GET_COMPLETION_QUEUE -111
#define ERROR_CLIENT_REG_MEM_REGION -112
#define ERROR_CLIENT_FLUSH -113
#define ERROR_GETTING_WORK_COMPLETION_QUUEU_EVENT -114
#define ERROR_FLUSH_ID -115
#define ERROR_FLUSH_FAIL -116
#define ERROR_CLIENT_WAIT_CQ -117
#define ERROR_INVAL_PARAMETERS -118
#define ERROR_CLIENT_READ -119
#define ERROR_CLIENT_RECV -120
#define ERROR_CLIENT_SEND -121

#define ERROR_PEER_CFG_NEW -1
#define ERROR_SET_DIRECT_WRITE_PMEM -2
#define ERROR_PEER_VIA_ADDR -3
#define ERROR_LISTEN -4
#define ERROR_PMAM_MAP_FILE -5
#define ERROR_MEM_REGISTER -6
#define ERROR_GET_MR_DESCRIPTOR_SIZE -7
#define ERROR_GET_PEER_DESCRIPTOR_SIZE -8
#define ERROR_GET_MR_DESCRIPTOR -9
#define ERROR_GET_PEER_DESCRIPTOR -10
#define ERROR_SERVER_ACCEPT_CONNECTION -11
#define ERROR_SERVER_DISCONNECT -12
#define ERROR_SERVER_RECV -13
#define ERROR_SERVER_SEND -14
#define ERROR_SERVER_WAIT_CQ -117
#define ERROR_SERVER_GET_CQ -118

#define ERROR_INIT -1000

typedef struct common_mem_t{
  char* mr_ptr;

	size_t mr_size;

	// size_t offset;

	size_t data_offset;
	int is_pmem;
	// persist_fn persist;

	struct l_rdma_mr_local *src_mr;
} common_mem;

struct common_data {
	uint16_t data_offset;	/* user data offset */
	uint8_t mr_desc_size;	/* size of mr_desc in descriptors[] */
	uint8_t pcfg_desc_size;	/* size of pcfg_desc in descriptors[] */
	/* buffer containing mr_desc and pcfg_desc */
	char descriptors[DESCRIPTORS_MAX_SIZE];
};

int common_peer_via_address(const char *addr, enum l_rdma_util_ibv_context_type type, struct l_rdma_peer **peer_ptr);

int common_disconnect_and_wait_for_conn_close(struct l_rdma_conn **conn_ptr);

int client_connect(struct l_rdma_peer *peer, const char *addr, const char *port,
		struct l_rdma_conn_cfg *cfg, struct l_rdma_conn_private_data *pdata,
		struct l_rdma_conn **conn_ptr);
uint64_t strtoul_noerror(const char *in);

void* malloc_aligned(size_t size);

int server_accept_connection(struct l_rdma_conn_cfg *cfg, struct l_rdma_conn *conn, struct l_rdma_ep *ep, struct l_rdma_conn_private_data *pdata);
