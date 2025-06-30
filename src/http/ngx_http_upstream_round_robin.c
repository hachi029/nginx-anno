
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define ngx_http_upstream_tries(p) ((p)->tries                                \
                                    + ((p)->next ? (p)->next->tries : 0))


static ngx_http_upstream_rr_peer_t *ngx_http_upstream_get_peer(
    ngx_http_upstream_rr_peer_data_t *rrp);

#if (NGX_HTTP_SSL)

static ngx_int_t ngx_http_upstream_empty_set_session(ngx_peer_connection_t *pc,
    void *data);
static void ngx_http_upstream_empty_save_session(ngx_peer_connection_t *pc,
    void *data);

#endif


/**
 * round robin算法时Nginx负载均衡算法的基础，banlancer模块必须使用此函数初始化服务器IP地址列表，
 * 然后再基于这个列表实现特定的算法
 * 
 * 加权轮询策略的基本工作过程是：
 * 初始化负载均衡服务器列表，初始化后端服务器，选择合适后端服务器处理请求，释放后端服务器。
 * 
 * 此函数初始化服务器列表
 * 
 */
ngx_int_t
ngx_http_upstream_init_round_robin(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_url_t                      u;
    ngx_uint_t                     i, j, n, r, w, t;
    ngx_http_upstream_server_t    *server;
    ngx_http_upstream_rr_peer_t   *peer, **peerp;
    ngx_http_upstream_rr_peers_t  *peers, *backup;
#if (NGX_HTTP_UPSTREAM_ZONE)
    ngx_uint_t                     resolve;
    ngx_http_core_loc_conf_t      *clcf;
    ngx_http_upstream_rr_peer_t  **rpeerp;
#endif

    /* 设置 ngx_http_upstream_peer_t 结构体中 init 的回调方法 */
    us->peer.init = ngx_http_upstream_init_round_robin_peer;

    /* 第一种情况：若 upstream 机制中有配置后端服务器 */
    if (us->servers) {
         /* ngx_http_upstream_srv_conf_t us 结构体成员 servers 是一个指向服务器数组 ngx_array_t 的指针，*/
        server = us->servers->elts;

        n = 0;      //计算地址的总数
        r = 0;
        w = 0;      //计算总权重
        t = 0;

#if (NGX_HTTP_UPSTREAM_ZONE)
        resolve = 0;
#endif

        /* 在这里说明下：一个域名可能会对应多个 IP 地址，upstream 机制中把一个 IP 地址看作一个后端服务器 */
        /* 遍历服务器数组中所有后端服务器，统计非备用后端服务器的 IP 地址总个数(即非备用后端服务器总的个数) 和 总权重 */
        for (i = 0; i < us->servers->nelts; i++) {

#if (NGX_HTTP_UPSTREAM_ZONE)
            if (server[i].host.len) {
                resolve = 1;
            }
#endif

            /* 若当前服务器是备用服务器，则 continue 跳过以下检查，继续检查下一个服务器 */
            if (server[i].backup) {
                continue;
            }

#if (NGX_HTTP_UPSTREAM_ZONE)
            if (server[i].host.len) {
                r++;
                continue;
            }
#endif

            /* 统计所有非备用后端服务器 IP 地址总的个数(即非备用后端服务器总的个数) */
            n += server[i].naddrs;
            /* 统计所有非备用后端服务器总的权重 */
            w += server[i].naddrs * server[i].weight;

            if (!server[i].down) {
                t += server[i].naddrs;
            }
        }

#if (NGX_HTTP_UPSTREAM_ZONE)
        if (us->shm_zone) {

            if (resolve && !(us->flags & NGX_HTTP_UPSTREAM_MODIFY)) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "load balancing method does not support"
                              " resolving names at run time in"
                              " upstream \"%V\" in %s:%ui",
                              &us->host, us->file_name, us->line);
                return NGX_ERROR;
            }

            clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

            if (us->resolver == NULL) {
                us->resolver = clcf->resolver;
            }

            /*
             * Without "resolver_timeout" in http{} the merged value is unset.
             */
            ngx_conf_merge_msec_value(us->resolver_timeout,
                                      clcf->resolver_timeout, 30000);

            if (resolve
                && (us->resolver == NULL
                    || us->resolver->connections.nelts == 0))
            {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "no resolver defined to resolve names"
                              " at run time in upstream \"%V\" in %s:%ui",
                              &us->host, us->file_name, us->line);
                return NGX_ERROR;
            }

        } else if (resolve) {

            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "resolving names at run time requires"
                          " upstream \"%V\" in %s:%ui"
                          " to be in shared memory",
                          &us->host, us->file_name, us->line);
            return NGX_ERROR;
        }
#endif

        if (n + r == 0) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "no servers in upstream \"%V\" in %s:%ui",
                          &us->host, us->file_name, us->line);
            return NGX_ERROR;
        }

         /* 值得注意的是：备用后端服务器列表 和 非备用后端服务器列表 是分开挂载的，因此需要分开设置 */
        /* 为非备用后端服务器分配内存空间 */
        peers = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_rr_peers_t));
        if (peers == NULL) {
            return NGX_ERROR;
        }

        peer = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_rr_peer_t)
                                     * (n + r));
        if (peer == NULL) {
            return NGX_ERROR;
        }

         /* 初始化非备用后端服务器列表 ngx_http_upstream_rr_peers_t 结构体 */
        peers->single = (n == 1);       /* 表示只有一个非备用后端服务器 */
        peers->number = n;              /* 非备用后端服务器总的个数 */
        peers->weighted = (w != n);     /* 设置默认权重为 1 或 0 */
        peers->total_weight = w;        /* 设置非备用后端服务器总的权重 */
        peers->tries = t;               
        peers->name = &us->host;        /* 非备用后端服务器名称 */

        n = 0;
        peerp = &peers->peer;

#if (NGX_HTTP_UPSTREAM_ZONE)
        rpeerp = &peers->resolve;
#endif

        /* 遍历服务器数组中所有后端服务器，初始化主后端服务器 */
        for (i = 0; i < us->servers->nelts; i++) {
            if (server[i].backup) {     //只处理主服务器
                continue;
            }

#if (NGX_HTTP_UPSTREAM_ZONE)
            if (server[i].host.len) {

                peer[n].host = ngx_pcalloc(cf->pool,
                                           sizeof(ngx_http_upstream_host_t));
                if (peer[n].host == NULL) {
                    return NGX_ERROR;
                }

                peer[n].host->name = server[i].host;
                peer[n].host->service = server[i].service;

                peer[n].sockaddr = server[i].addrs[0].sockaddr;
                peer[n].socklen = server[i].addrs[0].socklen;
                peer[n].name = server[i].addrs[0].name;
                peer[n].weight = server[i].weight;
                peer[n].effective_weight = server[i].weight;
                peer[n].current_weight = 0;
                peer[n].max_conns = server[i].max_conns;
                peer[n].max_fails = server[i].max_fails;
                peer[n].fail_timeout = server[i].fail_timeout;
                peer[n].down = server[i].down;
                peer[n].server = server[i].name;

                *rpeerp = &peer[n];
                rpeerp = &peer[n].next;
                n++;

                continue;
            }
#endif

            /* 以下关于 ngx_http_upstream_rr_peer_t 结构体中三个权重值的说明 */
            /*
             * effective_weight 相当于质量(来源于配置文件配置项的 weight)，current_weight 相当于重量。
             * 前者反应本质，一般是不变的。current_weight 是运行时的动态权值，它的变化基于 effective_weight。
             * 但是 effective_weight 在其对应的 peer 服务异常时，会被调低，
             * 当服务恢复正常时，effective_weight 会逐渐恢复到实际值（配置项的weight）;
             */
            /* 遍历非备用后端服务器所对应 IP 地址数组中的所有 IP 地址(即一个后端服务器域名可能会对应多个 IP 地址) */
            for (j = 0; j < server[i].naddrs; j++) {
                 /* 为每个非备用后端服务器初始化 */
                peer[n].sockaddr = server[i].addrs[j].sockaddr;         /* 设置非备用后端服务器 IP 地址 */
                peer[n].socklen = server[i].addrs[j].socklen;           /* 设置非备用后端服务器 IP 地址长度 */
                peer[n].name = server[i].addrs[j].name;                 /* 设置非备用后端服务器域名 */
                peer[n].weight = server[i].weight;                      /* 设置非备用后端服务器配置项权重 */
                peer[n].effective_weight = server[i].weight;            /* 设置非备用后端服务器有效权重 */
                peer[n].current_weight = 0;                             /* 设置非备用后端服务器当前权重 */
                peer[n].max_conns = server[i].max_conns;                /* 设置非备用后端服务器最大失败次数 */
                peer[n].max_fails = server[i].max_fails;                /* 设置非备用后端服务器失败时间阈值 */
                peer[n].fail_timeout = server[i].fail_timeout;          /* 设置非备用后端服务器 down 标志位，若该标志位为 1，则不参与策略 */
                peer[n].down = server[i].down;
                peer[n].server = server[i].name;

                *peerp = &peer[n];
                peerp = &peer[n].next;
                n++;
            }
        }

         /*
         * 将非备用服务器列表挂载到 ngx_http_upstream_srv_conf_t 结构体成员结构体
         * ngx_http_upstream_peer_t peer 的成员 data 中；
         */
        us->peer.data = peers;

        /* backup servers */

        n = 0;
        r = 0;
        w = 0;
        t = 0;

        /* 遍历服务器数组中所有后端服务器，统计备用后端服务器的 IP 地址总个数(即备用后端服务器总的个数) 和 总权重 */
        for (i = 0; i < us->servers->nelts; i++) {
            if (!server[i].backup) {
                continue;
            }

#if (NGX_HTTP_UPSTREAM_ZONE)
            if (server[i].host.len) {
                r++;
                continue;
            }
#endif

            n += server[i].naddrs;      /* 统计所有备用后端服务器的 IP 地址总的个数 */
            w += server[i].naddrs * server[i].weight;    /* 统计所有备用后端服务器总的权重 */

            if (!server[i].down) {
                t += server[i].naddrs;
            }
        }

        if (n == 0                  /* 若没有备用后端服务器，则直接返回 */
#if (NGX_HTTP_UPSTREAM_ZONE)
            && !resolve
#endif
        ) {
            return NGX_OK;
        }

        if (n + r == 0 && !(us->flags & NGX_HTTP_UPSTREAM_BACKUP)) {
            return NGX_OK;
        }

         /* 分配备用服务器列表的内存空间 */
        backup = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_rr_peers_t));
        if (backup == NULL) {
            return NGX_ERROR;
        }

        peer = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_rr_peer_t)
                                     * (n + r));
        if (peer == NULL) {
            return NGX_ERROR;
        }

        if (n > 0) {
            peers->single = 0;
        }

        /* 初始化备用后端服务器列表 ngx_http_upstream_rr_peers_t 结构体 */
        backup->single = 0;
        backup->number = n;
        backup->weighted = (w != n);
        backup->total_weight = w;
        backup->tries = t;
        backup->name = &us->host;

        n = 0;
        peerp = &backup->peer;

#if (NGX_HTTP_UPSTREAM_ZONE)
        rpeerp = &backup->resolve;
#endif

        /* 遍历服务器数组中所有后端服务器，初始化备用后端服务器 */
        for (i = 0; i < us->servers->nelts; i++) {      /* 若是非备用后端服务器，则 continue 跳过当前后端服务器，检查下一个后端服务器 */
            if (!server[i].backup) {
                continue;
            }

#if (NGX_HTTP_UPSTREAM_ZONE)
            if (server[i].host.len) {

                peer[n].host = ngx_pcalloc(cf->pool,
                                           sizeof(ngx_http_upstream_host_t));
                if (peer[n].host == NULL) {
                    return NGX_ERROR;
                }

                peer[n].host->name = server[i].host;
                peer[n].host->service = server[i].service;

                peer[n].sockaddr = server[i].addrs[0].sockaddr;
                peer[n].socklen = server[i].addrs[0].socklen;
                peer[n].name = server[i].addrs[0].name;
                peer[n].weight = server[i].weight;
                peer[n].effective_weight = server[i].weight;
                peer[n].current_weight = 0;
                peer[n].max_conns = server[i].max_conns;
                peer[n].max_fails = server[i].max_fails;
                peer[n].fail_timeout = server[i].fail_timeout;
                peer[n].down = server[i].down;
                peer[n].server = server[i].name;

                *rpeerp = &peer[n];
                rpeerp = &peer[n].next;
                n++;

                continue;
            }
#endif

            /* 遍历备用后端服务器所对应 IP 地址数组中的所有 IP 地址(即一个后端服务器域名可能会对应多个 IP 地址) */
            for (j = 0; j < server[i].naddrs; j++) {
                peer[n].sockaddr = server[i].addrs[j].sockaddr;     /* 设置备用后端服务器 IP 地址 */
                peer[n].socklen = server[i].addrs[j].socklen;       /* 设置备用后端服务器 IP 地址长度 */
                peer[n].name = server[i].addrs[j].name;             /* 设置备用后端服务器域名 */
                peer[n].weight = server[i].weight;                  /* 设置备用后端服务器配置项权重 */
                peer[n].effective_weight = server[i].weight;        /* 设置备用后端服务器有效权重 */
                peer[n].current_weight = 0;                         /* 设置备用后端服务器当前权重 */
                peer[n].max_conns = server[i].max_conns;            /* 设置备用后端服务器最大失败次数 */
                peer[n].max_fails = server[i].max_fails;
                peer[n].fail_timeout = server[i].fail_timeout;      /* 设置备用后端服务器失败时间阈值 */
                peer[n].down = server[i].down;                      /* 设置备用后端服务器 down 标志位，若该标志位为 1，则不参与策略 */
                peer[n].server = server[i].name;

                *peerp = &peer[n];
                peerp = &peer[n].next;
                n++;
            }
        }

        /*
         * 将备用服务器列表挂载到 ngx_http_upstream_rr_peers_t 结构体中
         * 的成员 next 中；
         */
        peers->next = backup;

        /* 第一种情况到此返回 */
        return NGX_OK;
    }


    /* 第二种情况：若 upstream 机制中没有直接配置后端服务器，则采用默认的方式 proxy_pass 配置后端服务器地址 */
    /* an upstream implicitly defined by proxy_pass, etc. */

    /* 若端口号为 0，则出错返回 */
    if (us->port == 0) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "no port in upstream \"%V\" in %s:%ui",
                      &us->host, us->file_name, us->line);
        return NGX_ERROR;
    }

    /* 初始化 ngx_url_t 结构体所有成员为 0 */
    ngx_memzero(&u, sizeof(ngx_url_t));

    u.host = us->host;
    u.port = us->port;

    /* 解析 IP 地址 */
    if (ngx_inet_resolve_host(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "%s in upstream \"%V\" in %s:%ui",
                          u.err, &us->host, us->file_name, us->line);
        }

        return NGX_ERROR;
    }

    n = u.naddrs;

     /* 分配非备用后端服务器列表的内存空间 */
    peers = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_rr_peers_t));
    if (peers == NULL) {
        return NGX_ERROR;
    }

    peer = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_rr_peer_t) * n);
    if (peer == NULL) {
        return NGX_ERROR;
    }

    /* 初始化非备用后端服务器列表 */
    peers->single = (n == 1);
    peers->number = n;
    peers->weighted = 0;
    peers->total_weight = n;
    peers->tries = n;
    peers->name = &us->host;

    peerp = &peers->peer;

    for (i = 0; i < u.naddrs; i++) {
        peer[i].sockaddr = u.addrs[i].sockaddr;
        peer[i].socklen = u.addrs[i].socklen;
        peer[i].name = u.addrs[i].name;
        peer[i].weight = 1;
        peer[i].effective_weight = 1;
        peer[i].current_weight = 0;
        peer[i].max_conns = 0;
        peer[i].max_fails = 1;
        peer[i].fail_timeout = 10;
        *peerp = &peer[i];
        peerp = &peer[i].next;
    }

    /* 挂载非备用后端服务器列表 */
    us->peer.data = peers;

    /* implicitly defined upstream has no backup servers */

    return NGX_OK;
}


/**
 * 在选择合适的后端服务器处理客户请求时，首先需要初始化后端服务器，然后根据后端服务器的权重，
 * 选择权重最高的后端服务器来处理请求。初始化后端服务器
 * 
 * 上面的初始化负载服务器列表的全局初始化工作完成之后，当客户端发起请求时，Nginx 会选择一个合适的后端服务器来处理该请求。
 * 在本轮选择后端服务器之前，Nginx 会对后端服务器进行初始化工作，该工作由函数 ngx_http_upstream_init_round_robin_peer 实现。
 */
/* 当客户端发起请求时，upstream 机制为本轮选择一个后端服务器做初始化工作 */
ngx_int_t
ngx_http_upstream_init_round_robin_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_uint_t                         n;
    ngx_http_upstream_rr_peer_data_t  *rrp;

     /* 注意：r->upstream->peer 是 ngx_peer_connection_t 结构体类型 */
     /* 获取当前客户端请求中的 ngx_http_upstream_rr_peer_data_t 结构体 */
    rrp = r->upstream->peer.data;

    if (rrp == NULL) {
        rrp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_rr_peer_data_t));
        if (rrp == NULL) {
            return NGX_ERROR;
        }

        r->upstream->peer.data = rrp;
    }

    /* 获取非备用后端服务器列表 */
    rrp->peers = us->peer.data;
    /* 若采用遍历方式选择后端服务器时，作为起始节点编号 */
    rrp->current = NULL;

    ngx_http_upstream_rr_peers_rlock(rrp->peers);

#if (NGX_HTTP_UPSTREAM_ZONE)
    rrp->config = rrp->peers->config ? *rrp->peers->config : 0;
#endif

    /* 下面是取值 n，若存在备用后端服务器列表，则 n 的值为非备用后端服务器个数 与 备用后端服务器个数 之间的较大者 */
    n = rrp->peers->number;

    if (rrp->peers->next && rrp->peers->next->number > n) {
        n = rrp->peers->next->number;
    }

    r->upstream->peer.tries = ngx_http_upstream_tries(rrp->peers);

    ngx_http_upstream_rr_peers_unlock(rrp->peers);

    /* rrp->tried 是一个位图，在本轮选择中，该位图记录各个后端服务器是否被选择过 */
    /*
     * 如果后端服务器数量 n 不大于 32，则只需在一个 int 中即可记录下所有后端服务器状态；
     * 如果后端服务器数量 n 大于 32，则需在内存池中申请内存来存储所有后端服务器的状态；
     */
    if (n <= 8 * sizeof(uintptr_t)) {
        rrp->tried = &rrp->data;
        rrp->data = 0;

    } else {
        n = (n + (8 * sizeof(uintptr_t) - 1)) / (8 * sizeof(uintptr_t));

        rrp->tried = ngx_pcalloc(r->pool, n * sizeof(uintptr_t));
        if (rrp->tried == NULL) {
            return NGX_ERROR;
        }
    }

    /*
     * 设置 ngx_peer_connection_t 结构体中 get 、free 的回调方法；
     * 设置 ngx_peer_connection_t 结构体中 tries 重试连接的次数为非备用后端服务器的个数；
     */
    r->upstream->peer.get = ngx_http_upstream_get_round_robin_peer;
    r->upstream->peer.free = ngx_http_upstream_free_round_robin_peer;
#if (NGX_HTTP_SSL)
    r->upstream->peer.set_session =
                               ngx_http_upstream_set_round_robin_peer_session;
    r->upstream->peer.save_session =
                               ngx_http_upstream_save_round_robin_peer_session;
#endif

    return NGX_OK;
}


ngx_int_t
ngx_http_upstream_create_round_robin_peer(ngx_http_request_t *r,
    ngx_http_upstream_resolved_t *ur)
{
    u_char                            *p;
    size_t                             len;
    socklen_t                          socklen;
    ngx_uint_t                         i, n;
    struct sockaddr                   *sockaddr;
    ngx_http_upstream_rr_peer_t       *peer, **peerp;
    ngx_http_upstream_rr_peers_t      *peers;
    ngx_http_upstream_rr_peer_data_t  *rrp;

    rrp = r->upstream->peer.data;

    if (rrp == NULL) {
        rrp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_rr_peer_data_t));
        if (rrp == NULL) {
            return NGX_ERROR;
        }

        r->upstream->peer.data = rrp;
    }

    peers = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_rr_peers_t));
    if (peers == NULL) {
        return NGX_ERROR;
    }

    peer = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_rr_peer_t)
                                * ur->naddrs);
    if (peer == NULL) {
        return NGX_ERROR;
    }

    peers->single = (ur->naddrs == 1);
    peers->number = ur->naddrs;
    peers->tries = ur->naddrs;
    peers->name = &ur->host;

    if (ur->sockaddr) {
        peer[0].sockaddr = ur->sockaddr;
        peer[0].socklen = ur->socklen;
        peer[0].name = ur->name.data ? ur->name : ur->host;
        peer[0].weight = 1;
        peer[0].effective_weight = 1;
        peer[0].current_weight = 0;
        peer[0].max_conns = 0;
        peer[0].max_fails = 1;
        peer[0].fail_timeout = 10;
        peers->peer = peer;

    } else {
        peerp = &peers->peer;

        for (i = 0; i < ur->naddrs; i++) {

            socklen = ur->addrs[i].socklen;

            sockaddr = ngx_palloc(r->pool, socklen);
            if (sockaddr == NULL) {
                return NGX_ERROR;
            }

            ngx_memcpy(sockaddr, ur->addrs[i].sockaddr, socklen);
            ngx_inet_set_port(sockaddr, ur->port);

            p = ngx_pnalloc(r->pool, NGX_SOCKADDR_STRLEN);
            if (p == NULL) {
                return NGX_ERROR;
            }

            len = ngx_sock_ntop(sockaddr, socklen, p, NGX_SOCKADDR_STRLEN, 1);

            peer[i].sockaddr = sockaddr;
            peer[i].socklen = socklen;
            peer[i].name.len = len;
            peer[i].name.data = p;
            peer[i].weight = 1;
            peer[i].effective_weight = 1;
            peer[i].current_weight = 0;
            peer[i].max_conns = 0;
            peer[i].max_fails = 1;
            peer[i].fail_timeout = 10;
            *peerp = &peer[i];
            peerp = &peer[i].next;
        }
    }

    rrp->peers = peers;
    rrp->current = NULL;
    rrp->config = 0;

    if (rrp->peers->number <= 8 * sizeof(uintptr_t)) {
        rrp->tried = &rrp->data;
        rrp->data = 0;

    } else {
        n = (rrp->peers->number + (8 * sizeof(uintptr_t) - 1))
                / (8 * sizeof(uintptr_t));

        rrp->tried = ngx_pcalloc(r->pool, n * sizeof(uintptr_t));
        if (rrp->tried == NULL) {
            return NGX_ERROR;
        }
    }

    r->upstream->peer.get = ngx_http_upstream_get_round_robin_peer;
    r->upstream->peer.free = ngx_http_upstream_free_round_robin_peer;
    r->upstream->peer.tries = ngx_http_upstream_tries(rrp->peers);
#if (NGX_HTTP_SSL)
    r->upstream->peer.set_session = ngx_http_upstream_empty_set_session;
    r->upstream->peer.save_session = ngx_http_upstream_empty_save_session;
#endif

    return NGX_OK;
}


/**
 * 完成客户端请求的初始化工作之后，会选择一个后端服务器来处理该请求，选择后端服务器由函数实现
 */
ngx_int_t
ngx_http_upstream_get_round_robin_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_rr_peer_data_t  *rrp = data;

    ngx_int_t                      rc;
    ngx_uint_t                     i, n;
    ngx_http_upstream_rr_peer_t   *peer;
    ngx_http_upstream_rr_peers_t  *peers;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get rr peer, try: %ui", pc->tries);

    pc->cached = 0;
    pc->connection = NULL;

    peers = rrp->peers;
    ngx_http_upstream_rr_peers_wlock(peers);

#if (NGX_HTTP_UPSTREAM_ZONE)
    if (peers->config && rrp->config != *peers->config) {
        goto busy;
    }
#endif

    /*
     * 检查 ngx_http_upstream_rr_peers_t 结构体中的 single 标志位;
     * 若 single 标志位为 1，表示只有一台非备用后端服务器，
     * 接着检查该非备用后端服务器的 down 标志位，若 down 标志位为 0，则选择该非备用后端服务器来处理请求；
     * 若 down 标志位为 1, 该非备用后端服务器表示不参与策略选择，
     * 则跳至 goto failed 步骤从备用后端服务器列表中选择后端服务器来处理请求；
     */
    if (peers->single) {
        peer = peers->peer;

        if (peer->down) {
            goto failed;
        }

        if (peer->max_conns && peer->conns >= peer->max_conns) {
            goto failed;
        }

        rrp->current = peer;
        ngx_http_upstream_rr_peer_ref(peers, peer);

    } else {

        /* 若 single 标志位为 0，表示不止一台非备用后端服务器 */
        /* there are several peers */

         /* 根据非备用后端服务器的权重来选择一台后端服务器处理请求 */
        peer = ngx_http_upstream_get_peer(rrp);

        if (peer == NULL) {
             /*
             * 若从非备用后端服务器列表中没有选择一台合适的后端服务器处理请求，
             * 则 goto failed 从备用后端服务器列表中选择一台后端服务器来处理请求；
             */
            goto failed;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "get rr peer, current: %p %i",
                       peer, peer->current_weight);
    }

    /*
     * 若从非备用后端服务器列表中已经选到了一台合适的后端服务器处理请求;
     * 则获取该后端服务器的地址信息；
     */
    pc->sockaddr = peer->sockaddr;      /* 获取被选中的非备用后端服务器的地址 */
    pc->socklen = peer->socklen;        /* 获取被选中的非备用后端服务器的地址长度 */
    pc->name = &peer->name;             /* 获取被选中的非备用后端服务器的域名 */

    peer->conns++;

    ngx_http_upstream_rr_peers_unlock(peers);

    return NGX_OK;

failed:

/* 若存在备用后端服务器，则从备用后端服务器列表中选择一台后端服务器来处理请求；*/
    if (peers->next) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "backup servers");

        /* 获取备用后端服务器列表 */
        rrp->peers = peers->next;

         /* 把后端服务器重试连接的次数 tries 设置为备用后端服务器个数 number */
        n = (rrp->peers->number + (8 * sizeof(uintptr_t) - 1))
                / (8 * sizeof(uintptr_t));

       /* 初始化备用后端服务器在位图 rrp->tried[i] 中的值为 0 */       
        for (i = 0; i < n; i++) {
            rrp->tried[i] = 0;
        }

        ngx_http_upstream_rr_peers_unlock(peers);

        /* 把备用后端服务器列表当前非备用后端服务器列表递归调用 ngx_http_upstream_get_round_robin_peer 选择一台后端服务器 */
        rc = ngx_http_upstream_get_round_robin_peer(pc, rrp);

        if (rc != NGX_BUSY) {
            return rc;
        }

        ngx_http_upstream_rr_peers_wlock(peers);
    }

#if (NGX_HTTP_UPSTREAM_ZONE)
busy:
#endif

    ngx_http_upstream_rr_peers_unlock(peers);

    pc->name = peers->name;

    return NGX_BUSY;
}


/**
 * 计算每一个后端服务器的权重值，并选择一个权重最高的后端服务器
 */
static ngx_http_upstream_rr_peer_t *
ngx_http_upstream_get_peer(ngx_http_upstream_rr_peer_data_t *rrp)
{
    time_t                        now;
    uintptr_t                     m;
    ngx_int_t                     total;
    ngx_uint_t                    i, n, p;
    ngx_http_upstream_rr_peer_t  *peer, *best;

    now = ngx_time();

    best = NULL;
    total = 0;

#if (NGX_SUPPRESS_WARN)
    p = 0;
#endif

    /* 遍历后端服务器列表 */
    for (peer = rrp->peers->peer, i = 0;
         peer;
         peer = peer->next, i++)
    {
        /* 计算当前后端服务器在位图中的位置 n */
        n = i / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

        /* 当前后端服务器在位图中已经有记录，则不再次被选择，即 continue 检查下一个后端服务器 */
        if (rrp->tried[n] & m) {
            continue;
        }

         /* 检查当前后端服务器的 down 标志位，若为 1 表示不参与策略选择，则 continue 检查下一个后端服务器 */
        if (peer->down) {
            continue;
        }

        /*
         * 当前后端服务器的 down 标志位为 0,接着检查当前后端服务器连接失败的次数是否已经达到 max_fails；
         * 且睡眠的时间还没到 fail_timeout，则当前后端服务器不被选择，continue 检查下一个后端服务器；
         */
        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            continue;
        }

        if (peer->max_conns && peer->conns >= peer->max_conns) {
            continue;
        }

        /* 若当前后端服务器可能被选中，则计算其权重 */

        /*
         * 在上面初始化过程中 current_weight = 0，effective_weight = weight；
         * 此时，设置当前后端服务器的权重 current_weight 的值为原始值加上 effective_weight；
         * 设置总的权重为原始值加上 effective_weight；
         */
        peer->current_weight += peer->effective_weight;
        total += peer->effective_weight;

        /* 服务器正常，调整 effective_weight 的值 */
        if (peer->effective_weight < peer->weight) {
            peer->effective_weight++;
        }

         /* 若当前后端服务器的权重 current_weight 大于目前 best 服务器的权重，则当前后端服务器被选中 */
        if (best == NULL || peer->current_weight > best->current_weight) {
            best = peer;
            p = i;
        }
    }

    if (best == NULL) {
        return NULL;
    }

     /* 记录被选中后端服务器在 ngx_http_upstream_rr_peer_data_t 结构体 current 成员的值，在释放后端服务器时会用到该值 */
    rrp->current = best;
    ngx_http_upstream_rr_peer_ref(rrp->peers, best);

    /* 计算被选中后端服务器在位图中的位置 */
    n = p / (8 * sizeof(uintptr_t));
    m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

    /* 在位图相应的位置记录被选中后端服务器 */
    rrp->tried[n] |= m;

    /* 更新被选中后端服务器的权重 */
    best->current_weight -= total;

    if (now - best->checked > best->fail_timeout) {
        best->checked = now;
    }

    /* 返回被选中的后端服务器 */
    return best;
}


/**
 * 成功连接后端服务器并且正常处理完成客户端请求后需释放后端服务器
 */
void
ngx_http_upstream_free_round_robin_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_http_upstream_rr_peer_data_t  *rrp = data;

    time_t                       now;
    ngx_http_upstream_rr_peer_t  *peer;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "free rr peer %ui %ui", pc->tries, state);

    /* TODO: NGX_PEER_KEEPALIVE */

    peer = rrp->current;

    ngx_http_upstream_rr_peers_rlock(rrp->peers);
    ngx_http_upstream_rr_peer_lock(rrp->peers, peer);

    /* 若只有一个后端服务器，则设置 ngx_peer_connection_t 结构体成员 tries 为 0，并 return 返回 */
    if (rrp->peers->single) {

        if (peer->fails) {
            peer->fails = 0;
        }

        peer->conns--;

        if (ngx_http_upstream_rr_peer_unref(rrp->peers, peer) == NGX_OK) {
            ngx_http_upstream_rr_peer_unlock(rrp->peers, peer);
        }

        ngx_http_upstream_rr_peers_unlock(rrp->peers);

        pc->tries = 0;
        return;
    }
    /* 若不止一个后端服务器，则执行以下程序 */

    /*
     * 若在本轮被选中的后端服务器在进行连接测试时失败，或者在处理请求过程中失败，
     * 则需要进行重新选择后端服务器；
     */
    if (state & NGX_PEER_FAILED) {
        now = ngx_time();

        peer->fails++;              /* 增加当前后端服务器失败的次数 */
         /* 设置当前后端服务器访问的时间 */
        peer->accessed = now;
        peer->checked = now;

        if (peer->max_fails) {
            /* 由于当前后端服务器失败，表示发生异常，此时降低 effective_weight 的值 */
            peer->effective_weight -= peer->weight / peer->max_fails;

            if (peer->fails >= peer->max_fails) {
                ngx_log_error(NGX_LOG_WARN, pc->log, 0,
                              "upstream server temporarily disabled");
            }
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "free rr peer failed: %p %i",
                       peer, peer->effective_weight);

         /* 保证 effective_weight 的值不能小于 0 */
        if (peer->effective_weight < 0) {
            peer->effective_weight = 0;
        }

    } else {

        /* 若被选中的后端服务器成功处理请求，并返回，则将其 fails 设置为 0 */
        /* mark peer live if check passed */

        /* 若 fail_timeout 时间已过，则将其 fails 设置为 0 */
        if (peer->accessed < peer->checked) {
            peer->fails = 0;
        }
    }

     /* 减少 tries 的值 */
    peer->conns--;

    if (ngx_http_upstream_rr_peer_unref(rrp->peers, peer) == NGX_OK) {
        ngx_http_upstream_rr_peer_unlock(rrp->peers, peer);
    }

    ngx_http_upstream_rr_peers_unlock(rrp->peers);

    if (pc->tries) {
        pc->tries--;
    }
}


#if (NGX_HTTP_SSL)

ngx_int_t
ngx_http_upstream_set_round_robin_peer_session(ngx_peer_connection_t *pc,
    void *data)
{
    ngx_http_upstream_rr_peer_data_t  *rrp = data;

    ngx_int_t                      rc;
    ngx_ssl_session_t             *ssl_session;
    ngx_http_upstream_rr_peer_t   *peer;
#if (NGX_HTTP_UPSTREAM_ZONE)
    int                            len;
    const u_char                  *p;
    ngx_http_upstream_rr_peers_t  *peers;
#endif

    peer = rrp->current;

#if (NGX_HTTP_UPSTREAM_ZONE)
    peers = rrp->peers;

    if (peers->shpool) {
        ngx_http_upstream_rr_peers_rlock(peers);
        ngx_http_upstream_rr_peer_lock(peers, peer);

        if (peer->ssl_session == NULL) {
            ngx_http_upstream_rr_peer_unlock(peers, peer);
            ngx_http_upstream_rr_peers_unlock(peers);
            return NGX_OK;
        }

        len = peer->ssl_session_len;

        ngx_memcpy(ngx_ssl_session_buffer, peer->ssl_session, len);

        ngx_http_upstream_rr_peer_unlock(peers, peer);
        ngx_http_upstream_rr_peers_unlock(peers);

        p = ngx_ssl_session_buffer;
        ssl_session = d2i_SSL_SESSION(NULL, &p, len);

        rc = ngx_ssl_set_session(pc->connection, ssl_session);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "set session: %p", ssl_session);

        ngx_ssl_free_session(ssl_session);

        return rc;
    }
#endif

    ssl_session = peer->ssl_session;

    rc = ngx_ssl_set_session(pc->connection, ssl_session);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "set session: %p", ssl_session);

    return rc;
}


void
ngx_http_upstream_save_round_robin_peer_session(ngx_peer_connection_t *pc,
    void *data)
{
    ngx_http_upstream_rr_peer_data_t  *rrp = data;

    ngx_ssl_session_t             *old_ssl_session, *ssl_session;
    ngx_http_upstream_rr_peer_t   *peer;
#if (NGX_HTTP_UPSTREAM_ZONE)
    int                            len;
    u_char                        *p;
    ngx_http_upstream_rr_peers_t  *peers;
#endif

#if (NGX_HTTP_UPSTREAM_ZONE)
    peers = rrp->peers;

    if (peers->shpool) {

        ssl_session = ngx_ssl_get0_session(pc->connection);

        if (ssl_session == NULL) {
            return;
        }

        len = i2d_SSL_SESSION(ssl_session, NULL);

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "save session: %p:%d", ssl_session, len);

        /* do not cache too big session */

        if (len > NGX_SSL_MAX_SESSION_SIZE) {
            return;
        }

        p = ngx_ssl_session_buffer;
        (void) i2d_SSL_SESSION(ssl_session, &p);

        peer = rrp->current;

        ngx_http_upstream_rr_peers_rlock(peers);
        ngx_http_upstream_rr_peer_lock(peers, peer);

        if (len > peer->ssl_session_len) {
            ngx_shmtx_lock(&peers->shpool->mutex);

            if (peer->ssl_session) {
                ngx_slab_free_locked(peers->shpool, peer->ssl_session);
            }

            peer->ssl_session = ngx_slab_alloc_locked(peers->shpool, len);

            ngx_shmtx_unlock(&peers->shpool->mutex);

            if (peer->ssl_session == NULL) {
                peer->ssl_session_len = 0;

                ngx_http_upstream_rr_peer_unlock(peers, peer);
                ngx_http_upstream_rr_peers_unlock(peers);
                return;
            }

            peer->ssl_session_len = len;
        }

        ngx_memcpy(peer->ssl_session, ngx_ssl_session_buffer, len);

        ngx_http_upstream_rr_peer_unlock(peers, peer);
        ngx_http_upstream_rr_peers_unlock(peers);

        return;
    }
#endif

    ssl_session = ngx_ssl_get_session(pc->connection);

    if (ssl_session == NULL) {
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "save session: %p", ssl_session);

    peer = rrp->current;

    old_ssl_session = peer->ssl_session;
    peer->ssl_session = ssl_session;

    if (old_ssl_session) {

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "old session: %p", old_ssl_session);

        ngx_ssl_free_session(old_ssl_session);
    }
}


static ngx_int_t
ngx_http_upstream_empty_set_session(ngx_peer_connection_t *pc, void *data)
{
    return NGX_OK;
}


static void
ngx_http_upstream_empty_save_session(ngx_peer_connection_t *pc, void *data)
{
    return;
}

#endif
