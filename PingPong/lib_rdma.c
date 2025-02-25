#include <stdio.h>
#include <fcntl.h>
#include "lib_rdma.h"
#include <sys/mman.h>

int get_addr(char *dst, struct sockaddr *addr){
	struct addrinfo *res;
	int ret = -1;
	ret = getaddrinfo(dst, NULL, NULL, &res);
	if(ret){
		fprintf(stderr, "getaddrinfo failed - invalid hostname or IP adress\n");
		return ret;
	}
	memcpy(addr, res->ai_addr, sizeof(struct sockaddr_in));
	freeaddrinfo(res);
	return ret;
}

int l_rdma_mr_remote_from_descriptor(const void *desc, size_t desc_size, struct l_rdma_mr_remote **mr_ptr){
	if(desc == NULL || mr_ptr == NULL)
		return L_RDMA_E_INVAL;

	char *buff = (char *)desc;

	uint64_t raddr;
	uint64_t size;
	uint32_t rkey;

	if (desc_size < L_RDMA_MR_DESC_SIZE)
		return L_RDMA_E_INVAL;

	memcpy(&raddr, buff, sizeof(uint64_t));
	buff += sizeof(uint64_t);

	memcpy(&size, buff, sizeof(uint64_t));
	buff += sizeof(uint64_t);

	memcpy(&rkey, buff, sizeof(uint32_t));
	buff += sizeof(uint32_t);

	uint8_t usage = *(uint8_t *)buff;

	if(usage == 0)
		L_RDMA_E_INVAL;

	struct l_rdma_mr_remote *mr = malloc(sizeof(struct l_rdma_mr_remote));
	if(mr == NULL)
		return L_RDMA_E_NOMEM;

	mr->raddr = le64toh(raddr);
	mr->size = le64toh(size);
	mr->rkey = le32toh(rkey);
	mr->usage = usage;
	*mr_ptr = mr;

	return 0;
}

int l_rdma_conn_get_private_data(const struct l_rdma_conn *conn, struct l_rdma_conn_private_data *pdata){
	if(conn == NULL || pdata == NULL)
		return L_RDMA_E_INVAL;

	pdata->ptr = conn->data.ptr;
	pdata->len = conn->data.len;

	return 0;
}

int l_rdma_mr_remote_get_size(const struct l_rdma_mr_remote *mr, size_t *size){
	if(mr==NULL || size == NULL)
		return L_RDMA_E_INVAL;

	*size = mr->size;

	return 0;
}

int l_rdma_conn_get_cq(const struct l_rdma_conn *conn, struct l_rdma_cq **cq_ptr){
	if(conn == NULL || cq_ptr == NULL)
		return L_RDMA_E_INVAL;

	*cq_ptr = conn->cq;

	return 0;
}

int l_rdma_conn_cfg_get_timeout(const struct l_rdma_conn_cfg *cfg, int *timeout_ms){
	if(cfg == NULL || timeout_ms == NULL)
		return L_RDMA_E_INVAL;

	*timeout_ms = cfg->timeout_ms;

	return 0;
}

int l_rdma_conn_disconnect(struct l_rdma_conn *conn){

	if(conn == NULL)
		return L_RDMA_E_INVAL;

	if (rdma_disconnect(conn->id))
		return L_RDMA_E_PROVIDER;

	return 0;
}

int l_rdma_conn_delete(struct l_rdma_conn **conn_ptr){

	if(conn_ptr == NULL)
		return L_RDMA_E_INVAL;

	struct l_rdma_conn *conn = *conn_ptr;
	if(conn == NULL)
		return 0;

	int ret = 0;
	ret = l_rdma_flush_delete(&conn->flush);
	if(ret)
		goto err_destroy_qp;

	rdma_destroy_qp(conn->id);

	ret = l_rdma_cq_delete(&conn->rcq);
	if(ret)
		goto err_l_rdma_cq_delete;

	ret = l_rdma_cq_delete(&conn->cq);
	if(ret)
		goto err_destroy_id;

	if(rdma_destroy_id(conn->id)){
		ret = L_RDMA_E_PROVIDER;
		goto err_destroy_comp_channel;
	}

	if(conn->channel){
		errno = ibv_destroy_comp_channel(conn->channel);
		if(errno){
			ret = L_RDMA_E_PROVIDER;
			goto err_destroy_event_channel;
		}
	}

	rdma_destroy_event_channel(conn->evch);
	l_rdma_private_data_delete(&conn->data);

	free(conn);
	*conn_ptr = NULL;

	return 0;

err_destroy_qp:
	rdma_destroy_qp(conn->id);
	l_rdma_cq_delete(&conn->rcq);
err_l_rdma_cq_delete:
	l_rdma_cq_delete(&conn->cq);
err_destroy_id:
	rdma_destroy_id(conn->id);
err_destroy_comp_channel:
	if(conn->channel)
		ibv_destroy_comp_channel(conn->channel);
err_destroy_event_channel:
	rdma_destroy_event_channel(conn->evch);
	l_rdma_private_data_delete(&conn->data);

	free(conn);
	*conn_ptr = NULL;

	return ret;

}

static struct l_rdma_conn_cfg Conn_cfg_default  = {
	.timeout_ms = L_RDMA_DEFAULT_TIMEOUT_MS,
	.cq_size = L_RDMA_DEFAULT_Q_SIZE,
	.rcq_size = L_RDMA_DEFAULT_RCQ_SIZE,
	.sq_size = L_RDMA_DEFAULT_Q_SIZE,
	.rq_size = L_RDMA_DEFAULT_Q_SIZE,
	.shared_comp_channel = L_RDMA_DEFAULT_SHARED_COMPL_CHANNEL,
	.srq = 0
};

struct l_rdma_conn_cfg* l_rdma_conn_cfg_default(){
	return &Conn_cfg_default;
}

int l_rdma_conn_cfg_get_srq(const struct l_rdma_conn_cfg *cfg, struct l_rdma_srq **srq_ptr){

	if(cfg == NULL || srq_ptr == NULL)
		return L_RDMA_E_INVAL;

	*srq_ptr = (struct l_rdma_srq *) cfg->srq;
	return 0;
}

int l_rdma_conn_cfg_get_compl_channel(const struct l_rdma_conn_cfg *cfg, bool *shared){
	if(cfg == NULL || shared == NULL)
		return L_RDMA_E_INVAL;

	*shared = cfg->shared_comp_channel;
	return 0;
}

void l_rdma_conn_cgf_get_rcqe(const struct l_rdma_conn_cfg *cfg, int *rcqe){

	uint32_t rcq_size = 0;
	l_rdma_conn_cfg_get_rcq_size(cfg, &rcq_size);
	*rcqe = CLIP_TO_INT(rcq_size);
}

int l_rdma_conn_cfg_get_rcq_size(const struct l_rdma_conn_cfg *cfg, uint32_t *rcq_size){
	if(cfg == NULL || rcq_size == NULL)
		return L_RDMA_E_INVAL;
	*rcq_size = cfg->rcq_size;
	return 0;
}

void l_rdma_conn_cfg_get_cqe(const struct l_rdma_conn_cfg *cfg, int *cqe){
	uint32_t cq_size = 0;
	l_rdma_conn_cfg_get_cq_size(cfg, &cq_size);
	*cqe = CLIP_TO_INT(cq_size);
}

int l_rdma_conn_cfg_get_cq_size(const struct l_rdma_conn_cfg *cfg, uint32_t *cq_size){
	if(cfg == NULL || cq_size == NULL)
		return L_RDMA_E_INVAL;

	*cq_size = cfg->cq_size;
	return 0;
}

int l_rdma_conn_req_new(struct l_rdma_peer *peer, const char *addr, const char *port, const struct l_rdma_conn_cfg *cfg, struct l_rdma_conn_req **req_ptr){

	if (peer == NULL || addr == NULL || port == NULL || req_ptr == NULL)
		return L_RDMA_E_INVAL;

	if(cfg == NULL)
		cfg = l_rdma_conn_cfg_default();

	int timeout_ms = 0;
	l_rdma_conn_cfg_get_timeout(cfg, &timeout_ms);

	struct l_rdma_info *info;
	int ret = l_rdma_info_new(addr, port, L_RDMA_INFO_ACTIVE, &info);
	if(ret)
		return ret;

	struct rdma_cm_id *id;
	if(rdma_create_id(NULL, &id, NULL, RDMA_PS_TCP)){
		ret = L_RDMA_E_PROVIDER;
		goto err_info_delete;
	}

	ret = l_rdma_info_resolve_addr(info, id, timeout_ms);
	if(ret)
		goto err_destroy_id;

	if(rdma_resolve_route(id, timeout_ms)){
		ret = L_RDMA_E_PROVIDER;
		goto err_destroy_id;
	}

	struct l_rdma_conn_req *req;
	ret = l_rdma_conn_req_new_from_id(peer, id, cfg, &req);
	if(ret)
		goto err_destroy_id;

	*req_ptr = req;

	l_rdma_info_delete(&info);

	return 0;

err_destroy_id:
	rdma_destroy_id(id);

err_info_delete:
	l_rdma_info_delete(&info);
	return ret;
}

static int l_rdma_conn_req_new_from_id(struct l_rdma_peer *peer, struct rdma_cm_id *id, const struct l_rdma_conn_cfg *cfg, struct l_rdma_conn_req **req_ptr){
	int ret = 0;

	int cqe, rcqe;
	bool shared = false;
	struct l_rdma_srq *srq = NULL;
	struct l_rdma_cq *cq = NULL;
	struct l_rdma_cq *rcq = NULL;
	struct l_rdma_cq *srq_rcq = NULL;

	l_rdma_conn_cfg_get_cqe(cfg, &cqe);
	l_rdma_conn_cgf_get_rcqe(cfg, &rcqe);
	l_rdma_conn_cfg_get_compl_channel(cfg, &shared);
	l_rdma_conn_cfg_get_srq(cfg, &srq);

	if(srq)
		l_rdma_srq_get_rcq(srq, &srq_rcq);

	if(shared && srq_rcq){
		fprintf(stderr, "connection shared completion channel cannot be used when the shared RQ has its own RCQ");
		return L_RDMA_E_INVAL;
	}

	struct ibv_comp_channel *channel = NULL;
	if(shared){
		channel = ibv_create_comp_channel(id->verbs);
		if(channel == NULL)
			return L_RDMA_E_PROVIDER;
	}

	ret = l_rdma_cq_new(id->verbs, cqe, channel, &cq);
	if(ret)
		goto err_comp_channel_destroy;

	if(!srq_rcq && rcqe){
		ret = l_rdma_cq_new(id->verbs, rcqe, channel, &rcq);
		if(ret)
			goto err_l_rdma_cq_delete;
	}

	ret = l_rdma_peer_setup_qp(peer, id, cq, srq_rcq ? srq_rcq : rcq, cfg);
	if(ret)
		goto err_l_rdma_rcq_delete;

	*req_ptr = (struct l_rdma_conn_req *) malloc(sizeof(struct l_rdma_conn_req));
	if(*req_ptr == NULL){
		ret = L_RDMA_E_NOMEM;
		goto err_destroy_qp;
	}

	(*req_ptr)->is_passive = 0;
	(*req_ptr)->id = id;
	(*req_ptr)->cq = cq;
	(*req_ptr)->rcq = rcq;
	(*req_ptr)->channel = channel;
	(*req_ptr)->data.ptr = NULL;
	(*req_ptr)->data.len = 0;
	(*req_ptr)->peer = peer;

	return 0;

err_destroy_qp:
	rdma_destroy_qp(id);
err_l_rdma_rcq_delete:
	l_rdma_cq_delete(&rcq);
err_l_rdma_cq_delete:
	l_rdma_cq_delete(&cq);
err_comp_channel_destroy:
	if(channel)
		ibv_destroy_comp_channel(channel);

	return ret;
}

int l_rdma_conn_req_new_from_cm_event(struct l_rdma_peer *peer, struct rdma_cm_event *event, const struct l_rdma_conn_cfg *cfg, struct l_rdma_conn_req **req_ptr){

	if (peer == NULL || event == NULL || event->event != RDMA_CM_EVENT_CONNECT_REQUEST ||
		req_ptr == NULL)
		return L_RDMA_E_INVAL;

	struct l_rdma_conn_req *req = NULL;
	int ret = l_rdma_conn_req_new_from_id(peer, event->id, cfg, &req);
	if(ret)
		return ret;

	ret = l_rdma_private_data_store(event, &req->data);
	if(ret)
		goto err_conn_req_delete;

	req->is_passive = 1;
	*req_ptr = req;

	return 0;

err_conn_req_delete:
	l_rdma_conn_req_delete(&req);

	return ret;
}

int l_rdma_conn_req_connect(struct l_rdma_conn_req **req_ptr, const struct l_rdma_conn_private_data *pdata, struct l_rdma_conn **conn_ptr){
	if(req_ptr == NULL || *req_ptr == NULL)
		return L_RDMA_E_INVAL;

	if(conn_ptr == NULL || (pdata != NULL && (pdata->ptr == NULL || pdata->len == 0))) {
		l_rdma_conn_req_delete(req_ptr);
		return L_RDMA_E_INVAL;
	}

	struct rdma_conn_param conn_param = {0};

	conn_param.private_data = pdata ? pdata->ptr : NULL;
	conn_param.private_data_len = pdata ? pdata->len : 0;
	conn_param.responder_resources = RDMA_MAX_RESP_RES;
	conn_param.initiator_depth = RDMA_MAX_INIT_DEPTH;
	conn_param.flow_control = 1;
	conn_param.retry_count = 7; /* max 3-bit value */
	conn_param.rnr_retry_count = 7; /* max 3-bit value */

	int ret = 0;
	if((*req_ptr)->is_passive)
		ret = l_rdma_conn_new_accept(*req_ptr, &conn_param, conn_ptr);
	else
		ret = l_rdma_conn_new_connect(*req_ptr, &conn_param, conn_ptr);

	free(*req_ptr);
	*req_ptr = NULL;

	return ret;
}

int l_rdma_conn_next_event(struct l_rdma_conn *conn, enum l_rdma_conn_event *event){
	int ret = 0;
	if(conn == NULL || event == NULL)
		return L_RDMA_E_INVAL;

	struct rdma_cm_event *edata = NULL;
	if (rdma_get_cm_event(conn->evch, &edata)) {
		if (errno == ENODATA)
			return L_RDMA_E_NO_EVENT;
		return L_RDMA_E_PROVIDER;
	}
	if(edata->event == RDMA_CM_EVENT_ESTABLISHED && conn->data.ptr == NULL){
		ret = l_rdma_private_data_store(edata, &conn->data);
		if(ret){
			rdma_ack_cm_event(edata);
			return ret;
		}
	}
	enum rdma_cm_event_type cm_event = edata->event;
	if(rdma_ack_cm_event(edata)){
		ret = L_RDMA_E_PROVIDER;
		goto err_private_data_discard;
	}
	switch (cm_event) {
		case RDMA_CM_EVENT_ESTABLISHED:
			*event = L_RDMA_CONN_ESTABLISHED;
			break;
		case RDMA_CM_EVENT_CONNECT_ERROR:
		case RDMA_CM_EVENT_DEVICE_REMOVAL:
			*event = L_RDMA_CONN_LOST;
			break;
		case RDMA_CM_EVENT_DISCONNECTED:
		case RDMA_CM_EVENT_TIMEWAIT_EXIT:
			*event = L_RDMA_CONN_CLOSED;
			break;
		case RDMA_CM_EVENT_REJECTED:
			*event = L_RDMA_CONN_REJECTED;
			break;
		case RDMA_CM_EVENT_UNREACHABLE:
			*event = L_RDMA_CONN_UNREACHABLE;
			break;
		default:
			return L_RDMA_E_UNKNOW;
	}
	return 0;

err_private_data_discard:
	l_rdma_private_data_delete(&conn->data);

}

int l_rdma_conn_new(struct l_rdma_peer *peer, struct rdma_cm_id *id, struct l_rdma_cq * cq, struct l_rdma_cq *rcq, struct ibv_comp_channel *channel, struct l_rdma_conn **conn_ptr){
	if(peer == NULL || id == NULL || cq == NULL || conn_ptr == NULL)
		return L_RDMA_E_INVAL;

	int ret = 0;

	struct rdma_event_channel *evch = rdma_create_event_channel();
	if(!evch)
		return L_RDMA_E_PROVIDER;

	if(rdma_migrate_id(id, evch)){
		ret = L_RDMA_E_PROVIDER;
		goto err_destroy_evch;
	}

	struct l_rdma_flush *flush;
	ret = l_rdma_flush_new(peer, id->qp, &flush);
	if(ret)
		goto err_migrate_id_NULL;

	struct l_rdma_conn *conn = malloc(sizeof(*conn));
	if(!conn){
		ret = L_RDMA_E_NOMEM;
		goto err_flush_delete;
	}

	conn->id = id;
	conn->evch = evch;
	conn->cq = cq;
	conn->rcq = rcq;
	conn->channel = channel;
	conn->data.ptr = NULL;
	conn->data.len = 0;
	conn->flush = flush;
	conn->direct_write_to_pmem = false;

	*conn_ptr = conn;

	return 0;

err_flush_delete:
	l_rdma_flush_delete(&flush);
err_migrate_id_NULL:
	rdma_migrate_id(id, NULL);
err_destroy_evch:
	rdma_destroy_event_channel(evch);

	return ret;
}

static int l_rdma_conn_new_accept(struct l_rdma_conn_req *req, struct rdma_conn_param *conn_param, struct l_rdma_conn **conn_ptr){
	int ret = 0;

	if (rdma_accept(req->id, conn_param)){
		ret = L_RDMA_E_PROVIDER;
		goto err_conn_req_delete;
	}

	struct l_rdma_conn *conn = NULL;
	ret = l_rdma_conn_new(req->peer, req->id, req->cq, req->rcq, req->channel, &conn);
	if(ret)
		goto err_conn_disconnect;

	l_rdma_conn_transfer_private_data(conn, &req->data);

	*conn_ptr = conn;
	return 0;

err_conn_disconnect:
	rdma_disconnect(req->id);

err_conn_req_delete:
	rdma_destroy_qp(req->id);
	l_rdma_cq_delete(&req->rcq);
	l_rdma_cq_delete(&req->cq);
	l_rdma_private_data_delete(&req->data);
	if (req->channel)
		ibv_destroy_comp_channel(req->channel);

	return ret;
}

static int l_rdma_conn_new_connect(struct l_rdma_conn_req *req, struct rdma_conn_param *conn_param, struct l_rdma_conn **conn_ptr){
	int ret = 0;

	struct l_rdma_conn *conn = NULL;

	ret = l_rdma_conn_new(req->peer, req->id, req->cq, req->rcq, req->channel, &conn);
	if(ret)
		goto err_conn_new;

	if(rdma_connect(req->id, conn_param))
		return L_RDMA_E_PROVIDER;

	*conn_ptr = conn;
	return 0;

err_conn_new:
	rdma_destroy_qp(req->id);
	l_rdma_cq_delete(&req->rcq);
	l_rdma_cq_delete(&req->cq);
	rdma_destroy_id(req->id);
	if(req->channel)
		ibv_destroy_comp_channel(req->channel);

	return ret;
}

int l_rdma_conn_req_delete(struct l_rdma_conn_req **req_ptr){
	if (req_ptr == NULL)
		return L_RDMA_E_INVAL;

	struct l_rdma_conn_req *req = *req_ptr;
	if(req == NULL)
		return 0;

	rdma_destroy_qp(req->id);

	int ret = l_rdma_cq_delete(&req->rcq);
	int ret2 = l_rdma_cq_delete(&req->cq);

	if(!ret)
		ret = ret2;

	if(req->is_passive)
		ret2 = l_rdma_conn_req_reject(req);
	else
		ret2 = l_rdma_conn_req_destroy(req);

	if(!ret)
		ret = ret2;

	if (req->channel){
		errno = ibv_destroy_comp_channel(req->channel);
		if(errno)
			ret = L_RDMA_E_PROVIDER;
	}

	l_rdma_private_data_delete(&req->data);

	free(req);
	*req_ptr = NULL;

	return ret;
}

void l_rdma_conn_transfer_private_data(struct l_rdma_conn *conn, struct l_rdma_conn_private_data *pdata){

	conn->data.ptr = pdata->ptr;
	conn->data.len = pdata->len;

	pdata->ptr = NULL,
	pdata->len = 0;
}

int l_rdma_conn_req_reject(struct l_rdma_conn_req *req){
	if(rdma_reject(req->id, NULL, 0))
		return L_RDMA_E_PROVIDER;
	return 0;
}

static int l_rdma_conn_req_destroy(struct l_rdma_conn_req *req){
	if(rdma_destroy_id(req->id)){
		return L_RDMA_E_PROVIDER;
	}
	return 0;
}

int l_rdma_conn_cfg_get_sq_size(const struct l_rdma_conn_cfg *cfg, uint32_t *sq_size){
	if(cfg == NULL || sq_size == NULL)
		return L_RDMA_E_INVAL;
	*sq_size = cfg->sq_size;
	return 0;
}

int l_rdma_conn_cfg_get_rq_size(const struct l_rdma_conn_cfg *cfg, uint32_t *rq_size){
	if(cfg == NULL || rq_size == NULL)
		return L_RDMA_E_INVAL;
	*rq_size = cfg->rq_size;
	return 0;
}

int l_rdma_cq_new(struct ibv_context *ibv_ctx, int cqe, struct ibv_comp_channel *shared_channel, struct l_rdma_cq **cq_ptr){

	struct ibv_comp_channel *channel;
	int ret = 0;

	if (shared_channel){
		channel = shared_channel;
	}else{
		channel = ibv_create_comp_channel(ibv_ctx);
		if(channel == NULL)
			return L_RDMA_E_PROVIDER;
	}

	errno = 0;
	struct ibv_cq *cq = ibv_create_cq(ibv_ctx, cqe, NULL, channel, 0);
	if(cq == NULL){
		if(errno == EINVAL)
			printf("ERROR DU TO PARAMETERS\n");
		if(errno == ENOMEM)
			printf("ERROR DU TO MEMORY\n");
		ret = L_RDMA_E_PROVIDER;
		goto err_destroy_comp_channel;
	}

	errno = ibv_req_notify_cq(cq, 0);
	if(errno) {
		ret = L_RDMA_E_PROVIDER;
		goto err_destroy_cq;
	}

	*cq_ptr = (struct l_rdma_cq *) malloc(sizeof(struct l_rdma_cq));
	if(*cq_ptr == NULL){
		ret = L_RDMA_E_NOMEM;
		goto err_destroy_cq;
	}

	(*cq_ptr)->channel = channel;
	(*cq_ptr)->shared_comp_channel = (shared_channel != NULL);
	(*cq_ptr)->cq = cq;

	return 0;

err_destroy_cq:
	(void) ibv_destroy_cq(cq);

err_destroy_comp_channel:
	if (!shared_channel)
		(void) ibv_destroy_comp_channel(channel);

	return ret;
}

int l_rdma_cq_wait(struct l_rdma_cq *cq){
	if(cq == NULL)
		return L_RDMA_E_INVAL;

	if(cq->shared_comp_channel)
		return L_RDMA_E_SHARED_CHANNEL;

	struct ibv_cq *ev_cq;
	void *ev_ctx;
	if(ibv_get_cq_event(cq->channel, &ev_cq, &ev_ctx))
		return L_RDMA_E_NO_COMPLETION;

	ibv_ack_cq_events(cq->cq, 1);
	errno = ibv_req_notify_cq(cq->cq, 0);
	if(errno)
		return L_RDMA_E_PROVIDER;

	return 0;
}

struct ibv_cq * l_rdma_cq_get_ibv_cq(const struct l_rdma_cq *cq){
	return cq->cq;
}

int l_rdma_cq_get_wc(struct l_rdma_cq *cq, int num_entries, struct ibv_wc *wc, int *num_entries_got){
	if(cq == NULL || num_entries < 1 || wc == NULL)
		return L_RDMA_E_INVAL;

	if(num_entries > 1 && num_entries_got == NULL)
		return L_RDMA_E_INVAL;

	int result = ibv_poll_cq(cq->cq, num_entries, wc);
	if(result == 0){
		return L_RDMA_E_NO_COMPLETION;
	}else if(result < 0){
		return L_RDMA_E_PROVIDER;
	}else if(result > num_entries){
		return L_RDMA_E_UNKNOW;
	}

	if(num_entries_got)
		*num_entries_got = result;

	return 0;
}

int l_rdma_cq_delete(struct l_rdma_cq **cq_ptr){

	struct l_rdma_cq *cq = *cq_ptr;
	int ret = 0;

	if(cq == NULL)
		return ret;

	errno = ibv_destroy_cq(cq->cq);
	if(errno)
		ret = L_RDMA_E_PROVIDER;

	if(!cq->shared_comp_channel){
		if(!ret && errno){
			ret = L_RDMA_E_PROVIDER;
		}
	}

	free(cq);
	*cq_ptr = NULL;

	return ret;
}

int l_rdma_srq_get_rcq(const struct l_rdma_srq *srq, struct l_rdma_cq ** rcq_ptr){
	if(srq == NULL || rcq_ptr == NULL)
		return L_RDMA_E_INVAL;

	*rcq_ptr = srq->rcq;

	return 0;
}

int l_rdma_info_new(const char *addr, const char *port, enum l_rdma_info_side side, struct l_rdma_info **info_ptr){

	struct sockaddr_in *server_sockaddr = malloc(sizeof(struct sockaddr_in));
	int ret;

	if(addr == NULL || info_ptr == NULL)
		return L_RDMA_E_INVAL;

	bzero(server_sockaddr, sizeof server_sockaddr);
	server_sockaddr->sin_family = AF_INET;
	ret=get_addr(addr, (struct sockaddr*) server_sockaddr);
	if(ret)
		return ret;

	if(port!=NULL){
		server_sockaddr->sin_port = htons(strtol(port, NULL, 0));
	}

	struct rdma_addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	if(side == L_RDMA_INFO_PASSIVE)
		hints.ai_flags |= RAI_PASSIVE;
	hints.ai_qp_type = IBV_QPT_RC;
	hints.ai_port_space = RDMA_PS_TCP;

	struct rdma_addrinfo *rai = NULL;
	ret = rdma_getaddrinfo(addr, port, &hints, &rai);
	if(ret){
		return L_RDMA_E_PROVIDER;
	}

	struct l_rdma_info *info = malloc(sizeof(*info));
	if (info == NULL){
		ret = L_RDMA_E_NOMEM;
		goto err_freeaddrinfo;
	}

	info->side = side;
	info->rai = rai;
	info->s_addr = server_sockaddr;
	*info_ptr = info;

	return 0;

err_freeaddrinfo:
	rdma_freeaddrinfo(rai);
	return ret;
}

int l_rdma_info_resolve_addr(const struct l_rdma_info *info, struct rdma_cm_id *id, int timeout_ms){
	int ret=0;
	if(info->s_addr->sin_port != 0){
		rdma_resolve_addr(id, NULL, (struct sockaddr*) info->s_addr, 2000);//TEST: changer valeur voir si ca change le résultat du send/recv ?
	}else{
		rdma_resolve_addr(id, info->rai->ai_src_addr, info->rai->ai_dst_addr, timeout_ms);
	}

	if(ret)
		return L_RDMA_E_PROVIDER;
	return 0;
}

int l_rdma_info_bind_addr(const struct l_rdma_info *info, struct rdma_cm_id *id){
	if(id == NULL || info == NULL)
		return L_RDMA_E_INVAL;

	int ret = rdma_bind_addr(id, info->rai->ai_src_addr);
	if(ret)
		return L_RDMA_E_PROVIDER;

	return 0;
}

int l_rdma_info_delete(struct l_rdma_info **info_ptr) {
	if(info_ptr == NULL)
		return L_RDMA_E_INVAL;

	struct l_rdma_info *info = *info_ptr;
	if(info == NULL)
		return 0;

	rdma_freeaddrinfo(info->rai);
	free(info);
	*info_ptr = NULL;

	return 0;
}

int l_rdma_mr_reg(struct l_rdma_peer *peer, void *ptr, size_t size, int usage, struct l_rdma_mr_local **mr_ptr){

	int ret;

	if(peer == NULL || ptr == NULL || size == 0 || mr_ptr == NULL)
		return L_RDMA_E_INVAL;

	if(usage == 0 || (usage & ~USAGE_ALL_ALLOWED))
		return L_RDMA_E_INVAL;

	struct l_rdma_mr_local *mr;
	mr = malloc(sizeof(struct l_rdma_mr_local));
	if(mr == NULL)
		return L_RDMA_E_NOMEM;

	struct ibv_mr *ibv_mr;
	ret = l_rdma_peer_setup_mr_reg(peer, &ibv_mr, ptr, size, usage);
	if(ret){
		free(mr);
		return ret;
	}

	mr->ibv_mr = ibv_mr;
	mr->usage = usage;
	*mr_ptr = mr;

	return 0;
}

int l_rdma_mr_dereg(struct l_rdma_mr_local **mr_ptr){
	if(mr_ptr == NULL)
		return L_RDMA_E_INVAL;

	if(*mr_ptr == NULL)
		return 0;

	int ret = 0;
	struct l_rdma_mr_local *mr = *mr_ptr;
	errno = ibv_dereg_mr(mr->ibv_mr);
	if(errno)
		ret = L_RDMA_E_PROVIDER;

	free(mr);
	*mr_ptr = NULL;

	return ret;
}

static int l_rdma_peer_usage2access(struct l_rdma_peer *peer, int usage){

	enum ibv_transport_type type = peer->pd->context->device->transport_type;
	int access = 0;

	if (usage & L_RDMA_MR_USAGE_READ_SRC)
		access |= IBV_ACCESS_REMOTE_READ;

	if(usage &(L_RDMA_MR_USAGE_FLUSH_TYPE_VISIBILITY | L_RDMA_MR_USAGE_FLUSH_TYPE_PERSISTENT))
		access|=IBV_ACCESS_REMOTE_READ;

	if(usage & L_RDMA_MR_USAGE_READ_DST){
		access |= IBV_ACCESS_LOCAL_WRITE;

	if(type == IBV_TRANSPORT_IWARP)
		access|=IBV_ACCESS_REMOTE_WRITE;
	}

	if (usage & L_RDMA_MR_USAGE_WRITE_SRC)
		access |= IBV_ACCESS_LOCAL_WRITE;

	if(usage & L_RDMA_MR_USAGE_WRITE_DST)
		access|= IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_LOCAL_WRITE;

	if(usage & L_RDMA_MR_USAGE_RECV)
		access|= IBV_ACCESS_LOCAL_WRITE;

	return access;
}

int l_rdma_peer_setup_qp(struct l_rdma_peer *peer, struct rdma_cm_id *id, struct l_rdma_cq *cq, struct l_rdma_cq *rcq, const struct l_rdma_conn_cfg *cfg){

	if (peer == NULL || id == NULL || cq == NULL)
		return L_RDMA_E_INVAL;

	uint32_t sq_size = 0;
	uint32_t rq_size = 0;
	struct l_rdma_srq *srq = NULL;
	l_rdma_conn_cfg_get_sq_size(cfg, &sq_size);
	l_rdma_conn_cfg_get_rq_size(cfg, &rq_size);//DEBUG : CHANGE HERE
	l_rdma_conn_cfg_get_srq(cfg, &srq);

	struct ibv_srq *ibv_srq = srq  ? l_rdma_srq_get_ibv_srq(srq) : NULL;
	struct ibv_cq *ibv_cq = l_rdma_cq_get_ibv_cq(cq);
	struct ibv_qp_init_attr_ex qp_init_attr;
	qp_init_attr.qp_context = NULL;
	qp_init_attr.send_cq = ibv_cq;
	qp_init_attr.recv_cq = rcq ? l_rdma_cq_get_ibv_cq(rcq) : ibv_cq;
	qp_init_attr.srq = ibv_srq;
	qp_init_attr.cap.max_send_wr = sq_size;
	qp_init_attr.cap.max_recv_wr = rq_size;
	qp_init_attr.cap.max_send_sge = L_RDMA_MAX_SGE;
	qp_init_attr.cap.max_recv_sge = L_RDMA_MAX_SGE;
	qp_init_attr.cap.max_inline_data = L_RDMA_MAX_INLINE_DATA;
	qp_init_attr.qp_type = IBV_QPT_RC;
	qp_init_attr.sq_sig_all = 0;
	qp_init_attr.comp_mask = IBV_QP_INIT_ATTR_PD;
	qp_init_attr.pd = peer->pd;

	if(rdma_create_qp_ex(id, &qp_init_attr)){
		return L_RDMA_E_PROVIDER;
	}

	return 0;
}

int l_rdma_peer_setup_mr_reg(struct l_rdma_peer *peer, struct ibv_mr **ibv_mr_ptr, void *addr, size_t length, int usage){
	int access = l_rdma_peer_usage2access(peer, usage);

	*ibv_mr_ptr = ibv_reg_mr(peer->pd, addr, length, L_RDMA_IBV_ACCESS(access));
	if(*ibv_mr_ptr != NULL)
		return 0;

	return L_RDMA_E_PROVIDER;
}

int l_rdma_peer_delete(struct l_rdma_peer **peer_ptr){

	if(peer_ptr == NULL)
		return L_RDMA_E_INVAL;

	struct l_rdma_peer *peer = *peer_ptr;
	if(peer == NULL)
		return 0;

	int ret = ibv_dealloc_pd(peer->pd);
	if(ret)
		ret = L_RDMA_E_PROVIDER;

	free(peer);
	*peer_ptr = NULL;

	return ret;
}

int l_rdma_peer_new(struct ibv_context *ibv_ctx, struct l_rdma_peer **peer_ptr){
	int is_odp_supported = 0;
	int is_native_atomic_write_supported = 0;
	int is_native_flush_supported = 0;
	int ret;

	if (ibv_ctx == NULL || peer_ptr == NULL)
		return L_RDMA_E_INVAL;

	ret = l_rdma_utils_ibv_context_is_atomic_write_capable(ibv_ctx, &is_native_atomic_write_supported);
	if (ret)
		return ret;

	ret = l_rdma_utils_ibv_context_is_odp_capable(ibv_ctx, &is_odp_supported);
	if (ret)
		return ret;
	errno=0;
	struct ibv_pd *pd = ibv_alloc_pd(ibv_ctx);
	if (pd == NULL){
		if (errno == ENOMEM) {
			return L_RDMA_E_NOMEM;
		} else if (errno != 0){
			return L_RDMA_E_PROVIDER;
		} else{
			return L_RDMA_E_UNKNOW;
		}
	}

	struct l_rdma_peer *peer = malloc(sizeof(*peer));
	if(peer == NULL){
		ret = L_RDMA_E_NOMEM;
		goto err_dealloc_pd;
	}

	peer->pd = pd;
	peer->is_odp_supported = is_odp_supported;
	peer->is_native_atomic_write_supported = is_native_atomic_write_supported;
	peer->is_native_flush_supported = is_native_flush_supported;
	*peer_ptr = peer;

	return 0;

err_dealloc_pd:
	ibv_dealloc_pd(pd);
	return ret;
}

// int l_rdma_peer_cfg_get_direct_write_to_pmem(const struct l_rdma_peer_cfg *pcfg, bool *supported){
// 	if(pcfg == NULL || supported == NULL)
// 		return L_RDMA_E_INVAL;
//
// 	*supported = pcfg->direct_write_to_pmem;
// 	return 0;
// }

int l_rdma_flush_new(struct l_rdma_peer *peer, struct ibv_qp *qp, struct l_rdma_flush **flush_ptr){
	int ret;

	struct l_rdma_flush *flush = malloc(sizeof(struct l_rdma_flush_internal));
	if(!flush)
		return L_RDMA_E_NOMEM;

	ret = l_rdma_flush_apm_new(peer, flush);

	if(ret){
		free(flush);
		return ret;
	}

	*flush_ptr = flush;

	return 0;
}

int l_rdma_flush_delete(struct l_rdma_flush **flush_ptr){

	struct l_rdma_flush_internal *flush_internal = *(struct l_rdma_flush_internal **)flush_ptr;
	int ret = 0;

	if(flush_internal->delete_func)
		ret = flush_internal->delete_func(*flush_ptr);

	free(*flush_ptr);
	*flush_ptr = NULL;

	return ret;
}

static int l_rdma_flush_apm_new(struct l_rdma_peer *peer, struct l_rdma_flush *flush){
	int ret;

	long pagesize = sysconf(_SC_PAGESIZE);
	if(pagesize<0)
		return L_RDMA_E_PROVIDER;

	size_t mmap_size = (size_t) pagesize;

	void *raw = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if(raw == MAP_FAILED)
		return L_RDMA_E_NOMEM;

	struct l_rdma_mr_local *raw_mr = NULL;
	ret = l_rdma_mr_reg(peer, raw, RAW_SIZE, L_RDMA_MR_USAGE_READ_DST, &raw_mr);
	if(ret){
		munmap(raw, mmap_size);
		return ret;
	}

	struct flush_apm *flush_apm = malloc(sizeof(struct flush_apm));
	if(flush_apm == NULL){
		l_rdma_mr_dereg(&raw_mr);
		munmap(raw, mmap_size);
		return L_RDMA_E_NOMEM;
	}

	flush_apm->raw = raw;
	flush_apm->raw_mr = raw_mr;
	flush_apm->mmap_size = mmap_size;

	struct l_rdma_flush_internal *flush_internal = (struct l_rdma_flush_internal *)flush;
	//flush_internal->flush_func = l_rdma_flush_apm_execute;
	//flush_internal->delete_func = l_rdma_flush_apm_delete;
	flush_internal->context = flush_apm;

	return 0;
}

int l_rdma_private_data_store(struct rdma_cm_event *edata, struct l_rdma_conn_private_data *pdata){

	const void *ptr = edata->param.conn.private_data;
	uint8_t len = edata->param.conn.private_data_len;

	if(ptr == NULL || len == 0)
		return 0;

	void *ptr_copy = malloc(len);
	if(ptr_copy == NULL)
		return L_RDMA_E_NOMEM;

	memcpy(ptr_copy, ptr, len);

	pdata->ptr = ptr_copy;
	pdata->len = len;

	return 0;
}

void l_rdma_private_data_delete(struct l_rdma_conn_private_data *pdata){

	free(pdata->ptr);

	pdata->ptr = NULL;
	pdata->len = 0;
}

int l_rdma_ep_listen(struct l_rdma_peer *peer, const char *addr, const char *port, struct l_rdma_ep **ep_ptr){
	if(peer == NULL || addr == NULL || port == NULL || ep_ptr == NULL)
		return L_RDMA_E_INVAL;

	struct rdma_event_channel *evch = NULL;
	struct rdma_cm_id *id = NULL;
	struct l_rdma_info *info = NULL;
	struct l_rdma_ep *ep = NULL;
	int ret = 0;

	if((evch = rdma_create_event_channel()) == NULL)
		return L_RDMA_E_PROVIDER;

	if(rdma_create_id(evch, &id, NULL, RDMA_PS_TCP)){
		ret = L_RDMA_E_PROVIDER;
		goto err_destroy_event_channel;
	}

	ret = l_rdma_info_new(addr, port, L_RDMA_INFO_PASSIVE, &info);
	if(ret)
		goto err_destroy_id;

	ret = l_rdma_info_bind_addr(info, id);
	if(ret)
		goto err_info_delete;

	if(rdma_listen(id, 0)){
		ret = L_RDMA_E_PROVIDER;
		goto err_info_delete;
	}

	ep = malloc(sizeof(*ep));
	if(ep == NULL){
		ret = L_RDMA_E_NOMEM;
		goto err_info_delete;
	}

	ep->peer = peer;
	ep->evch = evch;
	ep->id = id;
	*ep_ptr = ep;

	l_rdma_info_delete(&info);

	return ret;

err_info_delete:
	l_rdma_info_delete(&info);
err_destroy_id:
	rdma_destroy_id(id);
err_destroy_event_channel:
	rdma_destroy_event_channel(evch);
	return ret;

}

int l_rdma_ep_next_conn_req(struct l_rdma_ep *ep, const struct l_rdma_conn_cfg *cfg, struct l_rdma_conn_req **req_ptr){

	if(ep == NULL || req_ptr == NULL)
		return L_RDMA_E_INVAL;

	if(cfg == NULL)
		cfg = l_rdma_conn_cfg_default();

	int ret = 0;
	struct rdma_cm_event *event = NULL;

	if (rdma_get_cm_event(ep->evch, &event)){
		if(errno == ENODATA)
			return L_RDMA_E_NO_EVENT;
		return L_RDMA_E_PROVIDER;
	}

	if(event->event != RDMA_CM_EVENT_CONNECT_REQUEST){
		ret = L_RDMA_E_INVAL;
		goto err_ack;
	}

	ret = l_rdma_conn_req_new_from_cm_event(ep->peer, event, cfg, req_ptr);
	if(ret)
		goto err_ack;

	if (rdma_ack_cm_event(event)) {
		l_rdma_conn_req_delete(req_ptr);
		return L_RDMA_E_PROVIDER;
	}
	return 0;

err_ack:
	(void) rdma_ack_cm_event(event);
	return ret;
}

int l_rdma_utils_get_ibv_context(const char *addr, enum l_rdma_util_ibv_context_type type, struct ibv_context ** ibv_ctx_ptr){
	if(addr == NULL || ibv_ctx_ptr == NULL)
		return L_RDMA_E_INVAL;

	enum l_rdma_info_side side;
	switch (type) {
		case L_RDMA_UTIL_IBV_CONTEXT_LOCAL:
			side = L_RDMA_INFO_PASSIVE;
			break;
		case L_RDMA_UTIL_IBV_CONTEXT_REMOTE:
			side = L_RDMA_INFO_ACTIVE;
			break;
		default:
			return L_RDMA_E_INVAL;
	}

	struct l_rdma_info *info;
	int ret = l_rdma_info_new(addr, NULL, side, &info);
	if(ret)
		return ret;

	struct rdma_cm_id *temp_id;
	ret = rdma_create_id(NULL, &temp_id, NULL, RDMA_PS_TCP);
	if (ret){
		ret = L_RDMA_E_PROVIDER;
		goto err_info_delete;
	}

	if(side == L_RDMA_INFO_PASSIVE){
		ret = l_rdma_info_bind_addr(info, temp_id);
		if(ret)
			goto err_destroy_id;
	}else{
		ret = l_rdma_info_resolve_addr(info, temp_id, L_RDMA_DEFAULT_TIMEOUT_MS);
		if(ret)
			goto err_destroy_id;
	}

	*ibv_ctx_ptr = temp_id->verbs;

err_destroy_id:
	(void) rdma_destroy_id(temp_id);

err_info_delete:
	(void) l_rdma_info_delete(&info);
	return ret;
}

int l_rdma_utils_ibv_context_is_atomic_write_capable(struct ibv_context *ibv_ctx, int *is_atomic_write_capable){
	*is_atomic_write_capable=0;
	return 0;
}

int l_rdma_utils_ibv_context_is_odp_capable(struct ibv_context *ibv_ctx, int *is_odp_capable){
	if(ibv_ctx == NULL || is_odp_capable == NULL)
		return L_RDMA_E_INVAL;

	*is_odp_capable = 0;

	// struct ibv_device_attr_ex attr = {{{0}}};
	// errno = ibv_query_device_ex(ibv_ctx, NULL, &attr);
	// if(errno){
	// 	return L_RDMA_E_PROVIDER;
	// }
	//
	// struct ibv_odp_caps *odp_caps = &attr.odp_caps;
	// if(odp_caps->general_caps & IBV_ODP_SUPPORT){
	// 	uint32_t rc_odp_caps = odp_caps->per_transport_caps.rc_odp_caps;
	// 	if((rc_odp_caps & IBV_ODP_SUPPORT_WRITE) && (rc_odp_caps & IBV_ODP_SUPPORT_READ)){
	// 		*is_odp_capable = 1;
	// 	}
	// }
	return 0;
}

struct ibv_srq * l_rdma_srq_get_ibv_srq(const struct l_rdma_srq *srq){
	return srq-> ibv_srq;
}

int l_rdma_mr_recv(struct ibv_qp* qp, struct l_rdma_mr_local *dst, size_t offset, size_t len, const void* op_context){
	struct ibv_recv_wr wr = {0};
	struct ibv_sge sge;

	if(dst == NULL){
		wr.sg_list = NULL;
		wr.num_sge = 0;
	} else {
		sge.addr = (uint64_t)((uintptr_t)dst->ibv_mr->addr + offset);
		sge.length = (uint32_t)len;
		sge.lkey = dst->ibv_mr->lkey;

		wr.sg_list = &sge;
		wr.num_sge = 1;
	}

	wr.next = NULL;
	wr.wr_id = (uint64_t)op_context;

	struct ibv_recv_wr *bad_wr;
	int ret = ibv_post_recv(qp, &wr, &bad_wr);
	if(ret) {
		fprintf("Error on the ibv_post_recv function: %d\n", ret);
		return L_RDMA_E_PROVIDER;
	}
	return 0;
}

int l_rdma_recv(struct l_rdma_conn *conn, struct l_rdma_mr_local *dst, size_t offset, size_t len, const void *op_context){
	if(conn == NULL || (dst == NULL && (offset != 0 || len != 0)))
		return L_RDMA_E_INVAL;

	return l_rdma_mr_recv(conn->id->qp, dst, offset, len, op_context);
}

int l_rdma_mr_send(struct ibv_qp* qp, const struct l_rdma_mr_local *src, size_t offset, size_t len, int flags, enum ibv_wr_opcode operation, uint32_t imm, const void *op_context){
	struct ibv_send_wr wr = {0};
	struct ibv_sge sge;

	if(src == NULL){
		wr.sg_list = NULL;
		wr.num_sge = 0;
	} else {
		sge.addr = (uint64_t)((uintptr_t)src->ibv_mr->addr + offset);
		sge.length = (uint32_t)len;
		sge.lkey = src->ibv_mr->lkey;

		wr.sg_list = &sge;
		wr.num_sge = 1;
	}

	wr.next = NULL;
	wr.opcode = operation;
	switch(wr.opcode){
		case IBV_WR_SEND:
			break;
		case IBV_WR_SEND_WITH_IMM:
			wr.imm_data = htonl(imm);
			break;
		default:
			fprintf(stderr, "unsupported wr.opcode == %d\n", wr.opcode);
			return L_RDMA_E_NOSUPP;
	}

	wr.wr_id = (uint64_t)op_context;
	wr.send_flags = (flags & L_RDMA_F_COMPLETION_ON_SUCCES) ? IBV_SEND_SIGNALED : 0;

	struct ibv_sebd_wr *bad_wr;
	int ret = ibv_post_send(qp, &wr, &bad_wr);
	if(ret){
		fprintf("Error on the ibv_post_send function: %d\n", ret);
		return L_RDMA_E_PROVIDER;
	}

	return 0;
}

int l_rdma_send(struct l_rdma_conn *conn, const struct l_rdma_mr_local *src, size_t offset, size_t len, int flags, const void *op_context){
	if(conn == NULL || flags == 0 ||
			(src == NULL && (offset != 0 || len != 0)))
		return L_RDMA_E_INVAL;

	return l_rdma_mr_send(conn->id->qp, src, offset, len, flags, IBV_WR_SEND, 0, op_context);
}

int l_rdma_conn_req_recv(struct l_rdma_conn_req *req, struct l_rdma_mr_local *dst, size_t offset, size_t len, const void *op_context){
	if(req == NULL || dst == NULL)
		return L_RDMA_E_INVAL;
	return l_rdma_mr_recv(req->id->qp, dst, offset, len, op_context);
}

int l_rdma_mr_write(struct ibv_qp *qp, struct l_rdma_mr_remote *dst, size_t dst_offset, const struct l_rdma_mr_local *src, size_t src_offset, size_t len, int flags, enum ibv_wr_opcode operation, uint32_t imm, const void *op_context){
	struct ibv_send_wr wr = {0};
	struct ibv_sge sge = {0};

	if (src == NULL){
		wr.sg_list = NULL;
		wr.num_sge = 0;

		wr.wr.rdma.remote_addr = 0;
		wr.wr.rdma.rkey = 0;
	} else {
		/* source */
		sge.addr = (uint64_t)((uintptr_t)src->ibv_mr->addr + src_offset);
		sge.length = (uint32_t)len;
		sge.lkey = src->ibv_mr->lkey;

		wr.sg_list = &sge;
		wr.num_sge = 1;

		/* destination */
		wr.wr.rdma.remote_addr = dst->raddr + dst_offset;
		wr.wr.rdma.rkey = dst->rkey;
	}


	wr.wr_id = (uint64_t)op_context;
	wr.next = NULL;

	wr.opcode = operation;
	switch (wr.opcode) {
	case IBV_WR_RDMA_WRITE:
		break;
	case IBV_WR_RDMA_WRITE_WITH_IMM:
		wr.imm_data = htonl(imm);
		break;
	default:
		return L_RDMA_E_NOSUPP;
	}

	wr.send_flags = (flags & L_RDMA_F_COMPLETION_ON_SUCCES) ? IBV_SEND_SIGNALED : 0;

	struct ibv_send_wr * bad_wr;
	int ret = ibv_post_send(qp, &wr, &bad_wr);
	if(ret)
		return L_RDMA_E_PROVIDER;

	return 0;
}

int l_rdma_write(struct l_rdma_conn *conn, struct l_rdma_mr_remote *dst, size_t dst_offset, const struct l_rdma_mr_local *src, size_t src_offset, size_t len, int flags, const void *op_context){

	if(conn == NULL || flags == 0 || ((src == NULL || dst == NULL) && (src != NULL || dst == NULL || dst_offset != 0 || src_offset != 0 || len != 0)))
		return L_RDMA_E_INVAL;

	return l_rdma_mr_write(conn->id->qp, dst, dst_offset, src, src_offset, len, flags, IBV_WR_RDMA_WRITE, 0, op_context);
}
