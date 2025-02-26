/*************INCLUDES*************/
#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>
#include <stdbool.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
/*************DEFINES*************/

#if defined(ibv_reg_mr)
#define L_RDMA_IBV_ACCESS(access) (unsigned)access
#else
#define L_RDMA_IBV_ACCESS(access) access
#endif
#define CLIP_TO_INT(size)	((size) > INT_MAX ? INT_MAX : (int)(size))

#define RAW_SIZE 8 //Read After Write mem region size

#define L_RDMA_E_UNKNOW (-100000)
#define L_RDMA_E_NOSUPP (-100001)
#define L_RDMA_E_PROVIDER (-100002)
#define L_RDMA_E_NOMEM (-100003)
#define L_RDMA_E_INVAL (-100004)
#define L_RDMA_E_NO_COMPLETION (-100005)
#define L_RDMA_E_NO_EVENT (-100006)
#define L_RDMA_E_SHARED_CHANNEL (-100008)

#define L_RDMA_MAX_SGE 1
#define L_RDMA_MAX_INLINE_DATA 8
#define L_RDMA_DEFAULT_TIMEOUT_MS 1000
#define L_RDMA_DEFAULT_Q_SIZE 10
#define L_RDMA_DEFAULT_RCQ_SIZE 0 //Set to 0 so we put the receive queue with the send queue, therefore we do not make a difference for the receive and send queue, guaranteing the operation order.
#define L_RDMA_DEFAULT_SHARED_COMPL_CHANNEL false

#define L_RDMA_F_COMPLETION_ON_ERROR (1 << 0)
#define L_RDMA_F_COMPLETION_ALWAYS (1 << 1 | L_RDMA_F_COMPLETION_ON_ERROR)
#define L_RDMA_F_COMPLETION_ON_SUCCES (L_RDMA_F_COMPLETION_ALWAYS & ~L_RDMA_F_COMPLETION_ON_ERROR)

#define L_RDMA_MR_USAGE_READ_SRC (1 << 0)
#define L_RDMA_MR_USAGE_READ_DST (1 << 1)
#define L_RDMA_MR_USAGE_WRITE_SRC (1 << 2)
#define L_RDMA_MR_USAGE_WRITE_DST (1 << 3)
#define L_RDMA_MR_USAGE_FLUSH_TYPE_VISIBILITY (1 << 4)
#define L_RDMA_MR_USAGE_FLUSH_TYPE_PERSISTENT (1 << 5)
#define L_RDMA_MR_USAGE_SEND (1 << 6)
#define L_RDMA_MR_USAGE_RECV (1 << 7)
#define L_RDMA_MR_DESC_SIZE (2 * sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint8_t))

#define L_RDMA_DEFAULT_DIRECT_WRITE_TO_PMEM false

#define USAGE_ALL_ALLOWED (L_RDMA_MR_USAGE_READ_SRC | L_RDMA_MR_USAGE_READ_DST |\
		L_RDMA_MR_USAGE_WRITE_SRC | L_RDMA_MR_USAGE_WRITE_DST |\
		L_RDMA_MR_USAGE_SEND | L_RDMA_MR_USAGE_RECV |\
		L_RDMA_MR_USAGE_FLUSH_TYPE_VISIBILITY |\
		L_RDMA_MR_USAGE_FLUSH_TYPE_PERSISTENT)

/*************ENUMS*************/
enum l_rdma_util_ibv_context_type {
  L_RDMA_UTIL_IBV_CONTEXT_LOCAL,
  L_RDMA_UTIL_IBV_CONTEXT_REMOTE
};

enum l_rdma_conn_event {
  L_RDMA_CONN_UNDEFINED = -1,
  L_RDMA_CONN_ESTABLISHED,
  L_RDMA_CONN_CLOSED,
  L_RDMA_CONN_LOST,
  L_RDMA_CONN_REJECTED,
  L_RDMA_CONN_UNREACHABLE
};

enum l_rdma_info_side {
  L_RDMA_INFO_PASSIVE,
  L_RDMA_INFO_ACTIVE
};

enum l_rdma_flush_type {
  L_RDMA_FLUSH_TYPE_PERSISTENT,
  L_RDMA_FLUSH_TYPE_VISIBILITY,
};

typedef int (*l_rdma_flush_func)(struct ibv_qp *qp, struct l_rdma_flush *flush,
	struct l_rdma_mr_remote *dst, size_t dst_offset, size_t len,
	enum l_rdma_flush_type type, int flags, const void *op_context);

typedef int (*l_rdma_flush_delete_func)(struct l_rdma_flush *flush);


/*************STRUCT*************/
struct flush_apm{
	void *raw;
	size_t mmap_size;
	struct l_rdma_mr_local *raw_mr;
};

struct l_rdma_conn_private_data {
  void *ptr;
  uint8_t len;
};

struct l_rdma_info{
  enum l_rdma_info_side side;
  struct rdma_addrinfo *rai;
  struct sockaddr_in *s_addr;
};

struct l_rdma_peer{
  struct ibv_pd *pd;
  int is_odp_supported;
  int is_native_atomic_write_supported;
  int is_native_flush_supported;
};

struct l_rdma_peer_cfg{
  bool direct_write_to_pmem;
};

struct l_rdma_ep{
  struct l_rdma_peer *peer;
  struct rdma_cm_id *id;
  struct rdma_event_channel *evch;
};

struct l_rdma_conn{
  struct rdma_cm_id *id;
  struct rdma_event_channel *evch;
  struct l_rdma_cq *cq;
  struct l_rdma_cq *rcq;
  struct ibv_comp_channel *channel;
  struct l_rdma_conn_private_data data;
  struct l_rdma_flush *flush;

  bool direct_write_to_pmem;
};

struct l_rdma_conn_cfg{
  int timeout_ms;		/* connection establishment timeout */
	uint32_t cq_size;	/* main CQ size */
	uint32_t rcq_size;	/* receive CQ size */
	uint32_t sq_size;	/* SQ size */
	uint32_t rq_size;	/* RQ size */
	bool shared_comp_channel; /* completion channel shared by CQ and RCQ */
	uintptr_t srq;
};

struct l_rdma_conn_req{
  int is_passive;
  struct rdma_cm_id *id;
  struct l_rdma_cq *cq;
  struct l_rdma_cq *rcq;
  struct ibv_comp_channel *channel;
  struct l_rdma_conn_private_data data;
  struct l_rdma_peer *peer;
};

struct l_rdma_flush{
  l_rdma_flush_func func;
};

struct l_rdma_flush_internal{
  l_rdma_flush_func flush_func;
  l_rdma_flush_delete_func delete_func;
  void *context;
};

struct l_rdma_srq{
  struct ibv_srq *ibv_srq;
	struct l_rdma_cq *rcq;
};

struct l_rdma_cq{
  struct ibv_comp_channel *channel;
	bool shared_comp_channel;
	struct ibv_cq *cq;
};

struct l_rdma_mr_remote{
  uint64_t raddr;
  uint64_t size;
  uint32_t rkey;
  int usage;
};

struct l_rdma_mr_local{
  struct ibv_mr *ibv_mr;
  int usage;
};

/*************FUNCTIONS*************/
// int get_addr(char *dst, struct sockaddr *addr);
int l_rdma_conn_get_cq(const struct l_rdma_conn *conn, struct l_rdma_cq **cq_ptr);
// int l_rdma_conn_cfg_get_timeout(const struct l_rdma_conn_cfg *cfg, int *timeout_ms);
int l_rdma_conn_disconnect(struct l_rdma_conn *conn);
int l_rdma_conn_delete(struct l_rdma_conn **conn_ptr);
// struct l_rdma_conn_cfg* l_rdma_conn_cfg_default();
// int l_rdma_conn_cfg_get_srq(const struct l_rdma_conn_cfg *cfg, struct l_rdma_srq **srq_ptr);
// int l_rdma_conn_cfg_get_compl_channel(const struct l_rdma_conn_cfg *cfg, bool *shared);
// void l_rdma_conn_cgf_get_rcqe(const struct l_rdma_conn_cfg *cfg, int *rcqe);
// int l_rdma_conn_cfg_get_rcq_size(const struct l_rdma_conn_cfg *cfg, uint32_t *rcq_size);
// void l_rdma_conn_cfg_get_cqe(const struct l_rdma_conn_cfg *cfg, int *cqe);
// int l_rdma_conn_cfg_get_cq_size(const struct l_rdma_conn_cfg *cfg, uint32_t *cq_size);
// int l_rdma_conn_req_new(struct l_rdma_peer *peer, const char *addr, const char *port, const struct l_rdma_conn_cfg *cfg, struct l_rdma_conn_req **req_ptr);
// static int l_rdma_conn_req_new_from_id(struct l_rdma_peer *peer, struct rdma_cm_id *id, const struct l_rdma_conn_cfg *cfg, struct l_rdma_conn_req **req_ptr);
int l_rdma_conn_req_connect(struct l_rdma_conn_req **req_ptr, const struct l_rdma_conn_private_data *pdata, struct l_rdma_conn **conn_ptr);
int l_rdma_conn_next_event(struct l_rdma_conn *conn, enum l_rdma_conn_event *event);
static int l_rdma_conn_new_accept(struct l_rdma_conn_req *req, struct rdma_conn_param *conn_param, struct l_rdma_conn **conn_ptr);
static int l_rdma_conn_new_connect(struct l_rdma_conn_req *req, struct rdma_conn_param *conn_param, struct l_rdma_conn **conn_ptr);
int l_rdma_conn_req_delete(struct l_rdma_conn_req **req_ptr);
// int l_rdma_conn_req_reject(struct l_rdma_conn_req *req);
// static int l_rdma_conn_req_destroy(struct l_rdma_conn_req *req);
// int l_rdma_conn_cfg_get_sq_size(const struct l_rdma_conn_cfg *cfg, uint32_t *sq_size);
// int l_rdma_conn_cfg_get_rq_size(const struct l_rdma_conn_cfg *cfg, uint32_t *rq_size);
// int l_rdma_cq_new(struct ibv_context *ibv_ctx, int cqe, struct ibv_comp_channel *shared_channel, struct l_rdma_cq **cq_ptr);
int l_rdma_cq_wait(struct l_rdma_cq *cq);
// struct ibv_cq * l_rdma_cq_get_ibv_cq(const struct l_rdma_cq *cq);
int l_rdma_cq_get_wc(struct l_rdma_cq *cq, int num_entries, struct ibv_wc *wc, int *num_entries_got);
int l_rdma_cq_delete(struct l_rdma_cq **cq_ptr);
// int l_rdma_srq_get_rcq(const struct l_rdma_srq *srq, struct l_rdma_cq ** rcq_ptr);
// int l_rdma_info_new(const char *addr, const char *port, enum l_rdma_info_side side, struct l_rdma_info **info_ptr);
// int l_rdma_info_resolve_addr(const struct l_rdma_info *info, struct rdma_cm_id *id, int timeout_ms);
// int l_rdma_info_bind_addr(const struct l_rdma_info *info, struct rdma_cm_id *id);
// int l_rdma_info_delete(struct l_rdma_info **info_ptr);
int l_rdma_mr_reg(struct l_rdma_peer *peer, void *ptr, size_t size, int usage, struct l_rdma_mr_local **mr_ptr);
// int l_rdma_mr_dereg(struct l_rdma_mr_local **mr_ptr);
// static int l_rdma_peer_usage2access(struct l_rdma_peer *peer, int usage);
// int l_rdma_peer_setup_qp(struct l_rdma_peer *peer, struct rdma_cm_id *id, struct l_rdma_cq *cq, struct l_rdma_cq *rcq, const struct l_rdma_conn_cfg *cfg);
// int l_rdma_peer_setup_mr_reg(struct l_rdma_peer *peer, struct ibv_mr **ibv_mr_ptr, void *addr, size_t length, int usage);
// int l_rdma_peer_delete(struct l_rdma_peer **peer_ptr);
// int l_rdma_peer_new(struct ibv_context *ibv_ctx, struct l_rdma_peer **peer_ptr);
// int l_rdma_flush_new(struct l_rdma_peer *peer, struct ibv_qp *qp, struct l_rdma_flush **flush_ptr);
int l_rdma_flush_delete(struct l_rdma_flush **flush_ptr);
// static int l_rdma_flush_apm_new(struct l_rdma_peer *peer, struct l_rdma_flush *flush);
int l_rdma_private_data_store(struct rdma_cm_event *edata, struct l_rdma_conn_private_data *pdata);
void l_rdma_private_data_delete(struct l_rdma_conn_private_data *pdata);
int l_rdma_ep_listen(struct l_rdma_peer *peer, const char *addr, const char *port, struct l_rdma_ep **ep_ptr);
int l_rdma_ep_next_conn_req(struct l_rdma_ep *ep, const struct l_rdma_conn_cfg *cfg, struct l_rdma_conn_req **req_ptr);
// int l_rdma_utils_get_ibv_context(const char *addr, enum l_rdma_util_ibv_context_type type, struct ibv_context ** ibv_ctx_ptr);
// int l_rdma_utils_ibv_context_is_atomic_write_capable(struct ibv_context *ibv_ctx, int *is_atomic_write_capable);
// int l_rdma_utils_ibv_context_is_odp_capable(struct ibv_context *ibv_ctx, int *is_odp_capable);
// struct ibv_srq * l_rdma_srq_get_ibv_srq(const struct l_rdma_srq *srq);
// int l_rdma_mr_recv(struct ibv_qp* qp, struct l_rdma_mr_local *dst, size_t offset, size_t len, const void* op_context);
// int l_rdma_recv(struct l_rdma_conn *conn, struct l_rdma_mr_local *dst, size_t offset, size_t len, const void *op_context);
// int l_rdma_mr_send(struct ibv_qp* qp, const struct l_rdma_mr_local *src, size_t offset, size_t len, int flags, enum ibv_wr_opcode operation, uint32_t imm, const void *op_context);
// int l_rdma_send(struct l_rdma_conn *conn, const struct l_rdma_mr_local *src, size_t offset, size_t len, int flags, const void *op_context);
int l_rdma_mr_remote_from_descriptor(const void *desc, size_t desc_size, struct l_rdma_mr_remote **mr_ptr);
int l_rdma_conn_get_private_data(const struct l_rdma_conn *conn, struct l_rdma_conn_private_data *pdara);
int l_rdma_mr_remote_get_size(const struct l_rdma_mr_remote *mr, size_t *size);
int l_rdma_mr_write(struct ibv_qp *qp, struct l_rdma_mr_remote *dst, size_t dst_offset, const struct l_rdma_mr_local *src, size_t src_offset, size_t len, int flags, enum ibv_wr_opcode operation, uint32_t imm, const void *op_context);
int l_rdma_write(struct l_rdma_conn *conn, struct l_rdma_mr_remote *dst, size_t dst_offset, const struct l_rdma_mr_local *src, size_t src_offset, size_t len, int flags, const void *op_context);
int l_rdma_mr_get_descriptor(const struct l_rdma_mr_local *mr, void *desc);
int l_rdma_mr_get_descriptor_size(const struct l_rdma_mr_local *mr, size_t *desc_size);
