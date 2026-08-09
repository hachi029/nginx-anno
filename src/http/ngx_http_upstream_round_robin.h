
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#if (NGX_HTTP_UPSTREAM_SID)
#define NGX_HTTP_UPSTREAM_SID_LEN    32  /* md5 in hex */
#endif

#define NGX_HTTP_UPSTREAM_FAILED     1

#if (NGX_HTTP_UPSTREAM_STICKY)
#define NGX_HTTP_UPSTREAM_DRAINING   8
#endif


//管理多个上游服务器地址
typedef struct ngx_http_upstream_rr_peers_s  ngx_http_upstream_rr_peers_t;
//代表单个上游服务器地址
typedef struct ngx_http_upstream_rr_peer_s   ngx_http_upstream_rr_peer_t;


#if (NGX_HTTP_UPSTREAM_ZONE)

typedef struct {
    ngx_event_t                     event;         /* must be first */
    ngx_uint_t                      worker;
    ngx_str_t                       name;
    ngx_str_t                       service;
    time_t                          valid;
    ngx_http_upstream_rr_peers_t   *peers;
    ngx_http_upstream_rr_peer_t    *peer;
} ngx_http_upstream_host_t;

#endif


/**
 * 标识upstream{}里配置的每个server，保存了每个peer的信息，和相关描述信息，如总的权重、总的地址数、域名
 */
struct ngx_http_upstream_rr_peer_s {
    /* 后端服务器 IP 地址 */
    struct sockaddr                *sockaddr;
     /* 后端服务器 IP 地址的长度 */
    socklen_t                       socklen;
    /* 地址的名字 */
    ngx_str_t                       name;
    /* 后端服务器的名称 */
    ngx_str_t                       server;

     /* 后端服务器当前的权重,初始化为0,之后会动态调整 */
    ngx_int_t                       current_weight;
    /* 后端服务器有效权重,动态权重,被初始化为server指令后的weight权重, 会因失败而降低 */
    /**
     * 在释放后端时，如果发现和后端的通信过程中发生了错误，就减小effective_weight。
     * 此后有新的请求过来时，在选取后端的过程中，再逐步增加effective_weight，最终又恢复到weight。
     * 之所以增加这个字段，是为了当后端发生错误时，降低其权重。
     */
    ngx_int_t                       effective_weight;//动态权重，它被初始化为server指令后的weight权重
     /* 配置文件中指定的该后端的权重，这个值是固定不变的 */
    ngx_int_t                       weight;

    /* 当前连接数 */
    ngx_uint_t                      conns;
    ngx_uint_t                      max_conns;

     /* "一段时间内"，已经失败的次数 */
    ngx_uint_t                      fails;
    /* 最近一次失败的时间点 */
    time_t                          accessed;
    //配合fail_timeout使用，记录上次检查时间。用于检查是否超过了"一段时间"
    //if (now - peer->checked <= peer->fail_timeout)
    /**
     *     if (now - best->checked > best->fail_timeout) {
     *          best->checked = now;
     *      }
     */
    time_t                          checked;

     /* "一段时间内"，最大的失败次数，固定值 */
    ngx_uint_t                      max_fails;
    /* "一段时间"的值，固定值, 默认为10s */
    time_t                          fail_timeout;
    ngx_msec_t                      slow_start;
    ngx_msec_t                      start_time;

    /* 后端服务器是否参与策略，若为1，表示不参与， 永久不可用的标志 */
    ngx_uint_t                      down;

#if (NGX_HTTP_SSL || NGX_COMPAT)
    void                           *ssl_session;
    int                             ssl_session_len;
#endif

#if (NGX_HTTP_UPSTREAM_SID || NGX_COMPAT)
    unsigned                        route:1;
#endif

#if (NGX_HTTP_UPSTREAM_ZONE)
    unsigned                        zombie:1;

    ngx_atomic_t                    lock;
    ngx_uint_t                      refs;
    ngx_http_upstream_host_t       *host;
#endif

#if (NGX_HTTP_UPSTREAM_SID || NGX_COMPAT)
    ngx_str_t                       sid;
#endif

     /* 指向下一个后端peer，用于构成链表 */
    ngx_http_upstream_rr_peer_t    *next;

#if (NGX_HTTP_UPSTREAM_LEAST_TIME || NGX_COMPAT)
    ngx_msec_t                      header_time;
    ngx_msec_t                      response_time;
    ngx_msec_t                      inflight_time;
    ngx_msec_t                      inflight_last;
    ngx_msec_t                      inflight_reqs_changed;
    ngx_uint_t                      inflight_reqs;
#endif

    NGX_COMPAT_BEGIN(7)
    NGX_COMPAT_END
};


/**
 * 管理IP地址列表, 表示一组后端服务器，比如一个后端集群。
 */
struct ngx_http_upstream_rr_peers_s {
    /* 非backup后端服务器的数量 */
    ngx_uint_t                      number;

#if (NGX_HTTP_UPSTREAM_ZONE)
    ngx_slab_pool_t                *shpool;
    ngx_atomic_t                    rwlock;
    ngx_uint_t                     *config;
    ngx_http_upstream_rr_peer_t    *resolve;
    ngx_http_upstream_rr_peers_t   *zone_next;
#endif

    /* 所有后端服务器总的权重 */
    ngx_uint_t                      total_weight;
    //初始为 非backup后端服务器的数量
    ngx_uint_t                      tries;

    /* 标志位，若为 1，表示后端服务器仅有一台，此时不需要选择策略, 特殊场景优化 */
    unsigned                        single:1;
    /* 标志位，若为 1，表示所有后端服务器总的权重等于服务器的数量, 即是否使用权重  */
    unsigned                        weighted:1;

    //upstream块的名字
    ngx_str_t                      *name;

    /* backup服务器集群  */
    ngx_http_upstream_rr_peers_t   *next;

    /* 主(primary)后端服务器IP单向链表 */
    ngx_http_upstream_rr_peer_t    *peer;
};


#if (NGX_HTTP_UPSTREAM_ZONE)

#define ngx_http_upstream_rr_peers_rlock(peers)                               \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_rlock(&peers->rwlock);                                     \
    }

#define ngx_http_upstream_rr_peers_wlock(peers)                               \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_wlock(&peers->rwlock);                                     \
    }

#define ngx_http_upstream_rr_peers_unlock(peers)                              \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_unlock(&peers->rwlock);                                    \
    }


#define ngx_http_upstream_rr_peer_lock(peers, peer)                           \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_wlock(&peer->lock);                                        \
    }

#define ngx_http_upstream_rr_peer_unlock(peers, peer)                         \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_unlock(&peer->lock);                                       \
    }


#define ngx_http_upstream_rr_peer_ref(peers, peer)                            \
    (peer)->refs++;


static ngx_inline void
ngx_http_upstream_rr_peer_free_locked(ngx_http_upstream_rr_peers_t *peers,
    ngx_http_upstream_rr_peer_t *peer)
{
    if (peer->refs) {
        peer->zombie = 1;
        return;
    }

    ngx_slab_free_locked(peers->shpool, peer->sockaddr);
    ngx_slab_free_locked(peers->shpool, peer->name.data);

    if (peer->server.data) {
        ngx_slab_free_locked(peers->shpool, peer->server.data);
    }

#if (NGX_HTTP_SSL)
    if (peer->ssl_session) {
        ngx_slab_free_locked(peers->shpool, peer->ssl_session);
    }
#endif

    ngx_slab_free_locked(peers->shpool, peer);
}


static ngx_inline void
ngx_http_upstream_rr_peer_free(ngx_http_upstream_rr_peers_t *peers,
    ngx_http_upstream_rr_peer_t *peer)
{
    ngx_shmtx_lock(&peers->shpool->mutex);
    ngx_http_upstream_rr_peer_free_locked(peers, peer);
    ngx_shmtx_unlock(&peers->shpool->mutex);
}


static ngx_inline ngx_int_t
ngx_http_upstream_rr_peer_unref(ngx_http_upstream_rr_peers_t *peers,
    ngx_http_upstream_rr_peer_t *peer)
{
    peer->refs--;

    if (peers->shpool == NULL) {
        return NGX_OK;
    }

    if (peer->refs == 0 && peer->zombie) {
        ngx_http_upstream_rr_peer_free(peers, peer);
        return NGX_DONE;
    }

    return NGX_OK;
}

#else

#define ngx_http_upstream_rr_peers_rlock(peers)
#define ngx_http_upstream_rr_peers_wlock(peers)
#define ngx_http_upstream_rr_peers_unlock(peers)
#define ngx_http_upstream_rr_peer_lock(peers, peer)
#define ngx_http_upstream_rr_peer_unlock(peers, peer)
#define ngx_http_upstream_rr_peer_ref(peers, peer)
#define ngx_http_upstream_rr_peer_unref(peers, peer)  NGX_OK

#endif


/**
 * 负载均衡算法使用的数据结构， 保存每个请求的负载均衡数据。
 * 
 * 在请求的负载均衡数据初始化函数peer.init中，会给该请求创建一个ngx_http_upstream__peer_data_t实例，pc->data就是该实例的地址。
 */
typedef struct {
    ngx_uint_t                      config;
    ngx_http_upstream_rr_peers_t   *peers;      /* 后端集群 */
    ngx_http_upstream_rr_peer_t    *current;    /* 当前使用的后端服务器 */
    uintptr_t                      *tried;      /* 指向后端服务器的位图 */
    uintptr_t                       data;       /* 当后端服务器的数量较少时，用于存放其位图 */
} ngx_http_upstream_rr_peer_data_t;


/* exponential moving average + rounding */
#define ngx_http_upstream_response_time_avg(avg, v)                            \
    *(avg) = (*(avg) ? (0.5 + ((double) (v) * 0.05 + (double) (*(avg)) * 0.95))\
                     : (v))


ngx_int_t ngx_http_upstream_init_round_robin(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
ngx_int_t ngx_http_upstream_init_round_robin_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
ngx_int_t ngx_http_upstream_create_round_robin_peer(ngx_http_request_t *r,
    ngx_http_upstream_resolved_t *ur);
ngx_int_t ngx_http_upstream_get_round_robin_peer(ngx_peer_connection_t *pc,
    void *data);
void ngx_http_upstream_free_round_robin_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);
void ngx_http_upstream_free_round_robin_peer_locked(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);

#if (NGX_HTTP_SSL)
ngx_int_t
    ngx_http_upstream_set_round_robin_peer_session(ngx_peer_connection_t *pc,
    void *data);
void ngx_http_upstream_save_round_robin_peer_session(ngx_peer_connection_t *pc,
    void *data);
#endif

#if (NGX_HTTP_UPSTREAM_SID)

#define ngx_http_upstream_copy_round_robin_sid(dst, src)                      \
    ngx_http_upstream_init_round_robin_sid(dst,                               \
                                           (src)->route ? &(src)->sid : NULL)

void ngx_http_upstream_init_round_robin_sid(ngx_http_upstream_rr_peer_t *peer,
    ngx_str_t *route);
ngx_http_upstream_rr_peer_t *ngx_http_upstream_get_rr_peer_by_sid(
    ngx_http_upstream_rr_peer_data_t *rrp, ngx_str_t *hint, ngx_uint_t *p,
    ngx_uint_t lock);

#endif


#endif /* _NGX_HTTP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_ */
