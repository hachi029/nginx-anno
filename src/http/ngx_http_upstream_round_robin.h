
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct ngx_http_upstream_rr_peers_s  ngx_http_upstream_rr_peers_t;
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
 * 与服务器的具体ip地址一一对应
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

     /* 后端服务器当前的权重 */
    ngx_int_t                       current_weight;
    /* 后端服务器有效权重 */
    ngx_int_t                       effective_weight;
     /* 配置项所指定的权重 */
    ngx_int_t                       weight;

    /* 活跃连接数 */
    ngx_uint_t                      conns;
    ngx_uint_t                      max_conns;

     /* 已经失败的次数 */
    ngx_uint_t                      fails;
    /* 访问时间 */
    time_t                          accessed;
    time_t                          checked;

     /* 最大失败次数 */
    ngx_uint_t                      max_fails;
    /* 失败时间阈值 */
    time_t                          fail_timeout;
    ngx_msec_t                      slow_start;
    ngx_msec_t                      start_time;

    /* 后端服务器是否参与策略，若为1，表示不参与 */
    ngx_uint_t                      down;

#if (NGX_HTTP_SSL || NGX_COMPAT)
    void                           *ssl_session;
    int                             ssl_session_len;
#endif

#if (NGX_HTTP_UPSTREAM_ZONE)
    unsigned                        zombie:1;

    ngx_atomic_t                    lock;
    ngx_uint_t                      refs;
    ngx_http_upstream_host_t       *host;
#endif

    /* 下一个peer的位置 */
    ngx_http_upstream_rr_peer_t    *next;

    NGX_COMPAT_BEGIN(15)
    NGX_COMPAT_END
};


/**
 * 管理IP地址列表
 */
struct ngx_http_upstream_rr_peers_s {
    /* 待选后端服务器的数量 */
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
    ngx_uint_t                      tries;

    /* 标志位，若为 1，表示后端服务器仅有一台，此时不需要选择策略, 特殊场景优化 */
    unsigned                        single:1;
    /* 标志位，若为 1，表示所有后端服务器总的权重等于服务器的数量 */
    unsigned                        weighted:1;

    //upstream块的名字
    ngx_str_t                      *name;

    /* 备(backup)后端服务器IP列表 */
    ngx_http_upstream_rr_peers_t   *next;

    /* 主(primary)后端服务器IP列表 */
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
 * 负载均衡算法使用的数据结构
 */
typedef struct {
    ngx_uint_t                      config;
    ngx_http_upstream_rr_peers_t   *peers;      //ip地址列表
    ngx_http_upstream_rr_peer_t    *current;    //当前使用的peer
    uintptr_t                      *tried;      //重试bit数组
    uintptr_t                       data;
} ngx_http_upstream_rr_peer_data_t;


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

#if (NGX_HTTP_SSL)
ngx_int_t
    ngx_http_upstream_set_round_robin_peer_session(ngx_peer_connection_t *pc,
    void *data);
void ngx_http_upstream_save_round_robin_peer_session(ngx_peer_connection_t *pc,
    void *data);
#endif


#endif /* _NGX_HTTP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_ */
