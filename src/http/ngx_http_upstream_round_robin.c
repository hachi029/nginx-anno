
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>


#define ngx_http_upstream_tries(p) ((p)->tries                                \
                                    + ((p)->next ? (p)->next->tries : 0))


#if (NGX_HTTP_UPSTREAM_SID)
static ngx_int_t ngx_http_upstream_create_sid(ngx_conf_t *cf,
    ngx_http_upstream_rr_peer_t *peer, ngx_str_t *route);
#endif

static ngx_http_upstream_rr_peer_t *ngx_http_upstream_get_peer(
    ngx_http_upstream_rr_peer_data_t *rrp, ngx_peer_connection_t *pc);

#if (NGX_HTTP_SSL)

static ngx_int_t ngx_http_upstream_empty_set_session(ngx_peer_connection_t *pc,
    void *data);
static void ngx_http_upstream_empty_save_session(ngx_peer_connection_t *pc,
    void *data);

#endif


/**
 * 加权轮询是upstream默认的负载均衡算法，当upstream配置块中没有指定使用的负载均衡算法时，默认使用的是加权轮询
 * 
 * round robin算法是Nginx负载均衡算法的基础，banlancer模块必须使用此函数初始化服务器IP地址列表，
 * 然后再基于这个列表实现特定的算法
 * 
 * 加权轮询策略的基本工作过程是：
 * 初始化负载均衡服务器列表，初始化后端服务器，选择合适后端服务器处理请求，释放后端服务器。
 * 
 * 此函数作为upstream模块的初始化函数，指定请求的负载均衡初始化函数init，
 * 
 * us标识一个upstream配置结构体
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

    /* 设置 ngx_http_upstream_peer_t 结构体中 init 的回调方法, 此方法用于接收到用户请求后，进行负载均衡前，初始化算法的上下文环境 */
    us->peer.init = ngx_http_upstream_init_round_robin_peer;

    /* 第一种情况：若 upstream 机制中有配置后端服务器（upstream块） */    
    if (us->servers) {
         /* ngx_http_upstream_srv_conf_t us 结构体成员 servers 是一个指向服务器数组 ngx_array_t 的指针，每个元素对于一个server指令*/
        server = us->servers->elts;

        n = 0;      //所有后端服务器的数量 
        r = 0;      //r为host的个数。一个host可能对应多个地址
        w = 0;      //所有后端服务器的权重之和（如果一个域名解析出多个地址，则该域名权重为weight*地址个数）
        t = 0;      //为非down状态的地址总数

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

            /* 忽略备用服务器 */
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

            //统计所有非down状态的地址总数
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
        /* 为非备用后端服务器分配内存空间，代表一个后端集群的实例 */
        peers = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_rr_peers_t));
        if (peers == NULL) {
            return NGX_ERROR;
        }

        /* 创建后端服务器的实例，总共有n台 */
        peer = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_rr_peer_t)
                                     * (n + r));
        if (peer == NULL) {
            return NGX_ERROR;
        }

         /* 初始化后端服务器集群 ngx_http_upstream_rr_peers_t 结构体 */
        peers->single = (n == 1);       /* 表示只有一个非备用后端服务器 */
        peers->number = n;              /* 非备用后端服务器总的个数 */
        peers->weighted = (w != n);     /* 是否使用权重， 权重默认为1*/
        peers->total_weight = w;        /* 设置非备用后端服务器总的权重 */
        peers->tries = t;               /* 非down状态地址数量 */
        peers->name = &us->host;        /* upstream配置块的名称*/

        n = 0;
        //单向链表首个元素
        peerp = &peers->peer;

#if (NGX_HTTP_UPSTREAM_ZONE)
        rpeerp = &peers->resolve;
#endif

        /* 初始化代表后端的结构体ngx_http_upstream_peer_t.
         * server指令后跟的是域名的话，可能对应多台后端.
         */
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

#if (NGX_HTTP_UPSTREAM_SID)
                if (ngx_http_upstream_create_sid(cf, &peer[n], &server[i].sid)
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }
#endif

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
                peer[n].sockaddr = server[i].addrs[j].sockaddr;         /* 后端服务器的地址 */
                peer[n].socklen = server[i].addrs[j].socklen;           /* 地址的长度*/
                peer[n].name = server[i].addrs[j].name;                 /* 后端服务器地址的字符串 */
                peer[n].weight = server[i].weight;                      /* 配置项指定的权重，固定值 */
                peer[n].effective_weight = server[i].weight;            /* 有效的权重，会因为失败而降低 */
                peer[n].current_weight = 0;                             /* 当前的权重，动态调整，初始值为0 */
                peer[n].max_conns = server[i].max_conns;                /* 设置非备用后端服务器最大失败次数 */
                peer[n].max_fails = server[i].max_fails;                /* "一段时间内"，最大的失败次数，固定值 */
                peer[n].fail_timeout = server[i].fail_timeout;          /* "一段时间"的值，固定值 */
                peer[n].down = server[i].down;                          /* 服务器永久不可用的标志 */
                peer[n].server = server[i].name;                        /* server的名称 */

#if (NGX_HTTP_UPSTREAM_SID)
                if (ngx_http_upstream_create_sid(cf, &peer[n], &server[i].sid)
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }
#endif





                /* 把后端服务器组成一个链表，第一个后端的地址保存在peers->peer */
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

        /* 开始创建和初始化备份集群，peers->next指向备份集群，和上述流程类似，不再赘述 */
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

#if (NGX_HTTP_UPSTREAM_SID)
                if (ngx_http_upstream_create_sid(cf, &peer[n], &server[i].sid)
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }
#endif

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

#if (NGX_HTTP_UPSTREAM_SID)
                if (ngx_http_upstream_create_sid(cf, &peer[n], &server[i].sid)
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }
#endif

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


    /* 第二种情况：若 upstream 机制中没有直接配置后端服务器，则采用默认的方式 proxy_pass 配置后端服务器地址， 如proxy_pass http://a.com */
    //由proxy_pass隐含式定义的upstream场景
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

    /* 根据URL解析域名 */
    if (ngx_inet_resolve_host(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "%s in upstream \"%V\" in %s:%ui",
                          u.err, &us->host, us->file_name, us->line);
        }

        return NGX_ERROR;
    }

    //解析出的ip地址个数
    n = u.naddrs;

     /* 分配非备用后端服务器集群的内存空间 */
    peers = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_rr_peers_t));
    if (peers == NULL) {
        return NGX_ERROR;
    }

    peer = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_rr_peer_t) * n);
    if (peer == NULL) {
        return NGX_ERROR;
    }

    /* 初始化非备用后端服务器集群 */
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


#if (NGX_HTTP_UPSTREAM_SID)

static ngx_int_t
ngx_http_upstream_create_sid(ngx_conf_t *cf, ngx_http_upstream_rr_peer_t *peer,
    ngx_str_t *route)
{
    if (route->len) {
        peer->route = 1;
        peer->sid = *route;
        return NGX_OK;
    }

    peer->sid.data = ngx_pnalloc(cf->pool, NGX_HTTP_UPSTREAM_SID_LEN);
    if (peer->sid.data == NULL) {
        return NGX_ERROR;
    }

    ngx_http_upstream_init_round_robin_sid(peer, NULL);

    return NGX_OK;
}


void
ngx_http_upstream_init_round_robin_sid(ngx_http_upstream_rr_peer_t *peer,
    ngx_str_t *route)
{
    u_char     hash[16];
    ngx_md5_t  md5;

    if (route && route->len) {
        peer->route = 1;
        peer->sid.len = route->len;
        ngx_memcpy(peer->sid.data, route->data, route->len);
        return;
    }

    peer->route = 0;

    /* SID is the MD5 hash of a printable socket address */

    if (peer->name.len == 0) {
        peer->sid.len = 0;
        return;
    }

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, peer->name.data, peer->name.len);
    ngx_md5_final(hash, &md5);

    ngx_hex_dump(peer->sid.data, hash, 16);
    peer->sid.len = NGX_HTTP_UPSTREAM_SID_LEN;
}

#endif



/**
 * 
 * 主要用于创建和初始化ngx_http_upstream_rr_peer_data_t结构体，是对本次请求执行负载均衡算法的上下文结构体
 * 
 * 当客户端发起请求时，upstream 机制为本轮选择一个后端服务器做初始化工作, 此方法用于初始化per request的负载均衡数据  
 * 
 * 创建和初始化该请求的负载均衡数据块
 * 初始化负载均衡算法： 
 *     指定r->upstream->peer.get，用于从集群中选取一台后端服务器;
 *     指定r->upstream->peer.free，当不用该后端时，进行数据的更新（不管成功或失败都调用）
 *     指定r->upstream->peer.tries，请求最多允许尝试这么多个后端
 * 
 */
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
        /* 创建per request 的 请求的负载均衡数据块 */
        rrp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_rr_peer_data_t));
        if (rrp == NULL) {
            return NGX_ERROR;
        }

        r->upstream->peer.data = rrp;   /* 保存请求负载均衡数据的地址 */
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

    /* rrp->tried 是一个位图，每一位代表一台后端的状态，0表示可用，1表示不可用 */
    /*
     * 如果后端服务器数量 n 不大于 32，则只需在一个 int 中即可记录下所有后端服务器状态（使用rrp->data作为位图）；
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
    r->upstream->peer.get = ngx_http_upstream_get_round_robin_peer;     /* 指定peer.get，用于从集群中选取一台后端服务器 */
    r->upstream->peer.free = ngx_http_upstream_free_round_robin_peer;    /* 指定peer.free，当不用该后端时，进行数据的更新 */
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

    //数组，大小为待选服务器个数
    peer = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_rr_peer_t)
                                * ur->naddrs);
    if (peer == NULL) {
        return NGX_ERROR;
    }

    //只有一个地址
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

        //初始化peer数组
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

    //设置tired bit数组
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
 * 采用加权轮询算法，从集群中选出一台后端来处理本次请求。 选定后端的地址保存在pc->sockaddr，pc为主动连接
 * 返回值：
 * NGX_DONE：选定一个后端，和该后端的连接已经建立。之后会直接发送请求。(已经建立起连接了)
 * NGX_OK：选定一个后端，和该后端的连接尚未建立。之后会和后端建立连接。
*  NGX_BUSY：所有的后端（包括备份集群）都不可用。之后会给客户端发送502（Bad Gateway）。
 */
ngx_int_t
ngx_http_upstream_get_round_robin_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_rr_peer_data_t  *rrp = data;  /* 请求的负载均衡数据 */

    ngx_int_t                      rc;
    ngx_uint_t                     i, n;
    ngx_http_upstream_rr_peer_t   *peer;
    ngx_http_upstream_rr_peers_t  *peers;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get rr peer, try: %ui", pc->tries);

    pc->cached = 0;
    pc->connection = NULL;

    peers = rrp->peers;      /* 后端集群 */
    ngx_http_upstream_rr_peers_wlock(peers);

#if (NGX_HTTP_UPSTREAM_ZONE)
    if (peers->config && rrp->config != *peers->config) {
        goto busy;
    }
#endif

    /*
     * 检查 ngx_http_upstream_rr_peers_t 结构体中的 single 标志位;
     * 若 single 标志位为 1，表示只有一台非备用后端服务器，不用选
     */
    if (peers->single) {
#if (NGX_HTTP_UPSTREAM_SID)
        peer = ngx_http_upstream_get_rr_peer_by_sid(rrp, pc->hint, &i, 0);

        if (peer == NULL) {
#endif
            peer = peers->peer;

            //若 down 标志位为 1, 该非备用后端服务器表示不参与策略选择，
            if (peer->down) {
                goto failed;
            }

            if (peer->max_conns && peer->conns >= peer->max_conns) {
                goto failed;
            }
#if (NGX_HTTP_UPSTREAM_SID)
        }
#endif

        rrp->current = peer;
        //(peer)->refs++
        ngx_http_upstream_rr_peer_ref(peers, peer);

    } else {

        /* 若 single 标志位为 0，表示不止一台非备用后端服务器 */
        /* there are several peers */

         /* 调用ngx_http_upstream_get_peer来从后端集群中选定一台后端服务器 */
        peer = ngx_http_upstream_get_peer(rrp, pc);

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
#if (NGX_HTTP_UPSTREAM_SID)
    pc->sid = &peer->sid;
#endif

    peer->conns++;

    ngx_http_upstream_rr_peers_unlock(peers);

    return NGX_OK;

failed:

    /* 如果不能从集群中选取一台后端，那么尝试备用集群 */

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
 * 
 * 用于从集群中选取一台后端服务器
 * 
 * 选定后端的地址保存在pc->sockaddr，pc为主动连接。
 * 
*/
static ngx_http_upstream_rr_peer_t *
ngx_http_upstream_get_peer(ngx_http_upstream_rr_peer_data_t *rrp,
    ngx_peer_connection_t *pc)
{
    time_t                        now;
    uintptr_t                     m;
    ngx_int_t                     total;
    ngx_uint_t                    i, n, p;
    ngx_http_upstream_rr_peer_t  *peer, *best;

#if (NGX_HTTP_UPSTREAM_SID)
    ngx_int_t                     low_limit;
    ngx_uint_t                    st_p;
    ngx_http_upstream_rr_peer_t  *st_peer;
#endif

    now = ngx_time();

    best = NULL;
    total = 0;

#if (NGX_SUPPRESS_WARN)
    p = 0;
#endif

#if (NGX_HTTP_UPSTREAM_SID)
    st_peer = ngx_http_upstream_get_rr_peer_by_sid(rrp, pc->hint, &p, 0);

    if (st_peer) {

        low_limit = -((ngx_int_t)(rrp->peers->total_weight - st_peer->weight));

        /*
         * note: current code accounts only one sticky request in a row, if it
         *       is required to account more, multiply low_limit by N below
         */
        if (st_peer->current_weight <= low_limit) {

            /* do not update weights if the limit exceeded */
            best = st_peer;
            goto best_chosen;
        }
        /* else: proceed to reweight with existing st_peer */
    }

    st_p = p;
#endif

    for (peer = rrp->peers->peer, i = 0;
         peer;
         peer = peer->next, i++)
    {
        /* 计算当前后端服务器在位图中的位置 n */
        n = i / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

       /* 检查该后端服务器在位图中对应的位，为1时表示不可用 */
        if (rrp->tried[n] & m) {
            continue;
        }

         /* 检查当前后端服务器的 down 标志位，若为 1 表示不参与策略选择，则 continue 检查下一个后端服务器 */
        if (peer->down) {
            continue;
        }

        /**
         * 相关变量的更新
         *  accessed：释放peer时，如果发现后端出错了，则更新为now。
         *  checked：释放peer时，如果发现后端出错了，则更新为now。选定该peer时，如果now - checked > fail_timeout，则更新为now。
         *  fails：释放peer时，如果本次成功了且accessed < checked，说明距离最后一次失败的时间点，已超过fail_timeout了，清零fails。
         */
        /* 在一段时间内，如果此后端服务器的失败次数，超过了允许的最大值，那么此后一段时间内不再使用此后端了 */
        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            continue;
        }

        if (peer->max_conns && peer->conns >= peer->max_conns) {
            continue;
        }

        //https://www.kancloud.cn/digest/sknginx/130030
        //https://www.taohui.pub/2021/02/08/nginx/深入剖析Nginx负载均衡算法/
        
        /**
         * weight: 配置文件中指定的该后端的权重，这个值是固定不变的。
         * current_weight: 后端目前的权重，一开始为0，之后会动态调整
         * effective_weight: 后端的有效权重，初始值为weight。
         * 
         * 
         * 加权轮询算法可描述为：
         * 1.对于每个请求，遍历集群中的所有可用后端，对于每个后端peer执行：
         *    peer->current_weight += peer->effecitve_weight。
         *    同时累加所有peer的effective_weight，保存为total。
         * 2.从集群中选出current_weight最大的peer，作为本次选定的后端。
         * 3.对于本次选定的后端，执行：peer->current_weight -= total。
         */
        peer->current_weight += peer->effective_weight;     /* 对每个后端，增加其当前权重 */
        total += peer->effective_weight;                    /* 累加所有后端的有效权重 */

       /* 如果之前此后端发生了失败，会减小其effective_weight来降低它的权重。          
         * 此后在选取后端的过程中，又通过增加其effective_weight来恢复它的权重。          
         */  
        if (peer->effective_weight < peer->weight) {
            peer->effective_weight++;
        }

        /* 选取当前权重最大者，作为本次选定的后端 */
        if (best == NULL || peer->current_weight > best->current_weight) {
            //从集群中选出current_weight最大的peer，作为本次选定的后端。
            best = peer;
            p = i;
        }
    }

#if (NGX_HTTP_UPSTREAM_SID)
    /* prefer peer chosen by sticky to best from RR */

    if (st_peer) {
        best = st_peer;
        p = st_p;
    }
#endif

    if (best == NULL) {
        return NULL;
    }

    best->current_weight -= total;

#if (NGX_HTTP_UPSTREAM_SID)
best_chosen:
#endif

    rrp->current = best;
    ngx_http_upstream_rr_peer_ref(rrp->peers, best);

    /* 计算被选中后端服务器在位图中的位置 */
    n = p / (8 * sizeof(uintptr_t));
    m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

    /* 对于本次请求，如果之后需要再次选取后端，不能再选取这个后端了 */   
    rrp->tried[n] |= m;

    /* 选定后端后，需要降低其当前权重 */
    best->current_weight -= total;

    if (now - best->checked > best->fail_timeout) {
        best->checked = now;
    }

    /* 返回被选中的后端服务器 */
    return best;
}


#if (NGX_HTTP_UPSTREAM_SID)

ngx_http_upstream_rr_peer_t *
ngx_http_upstream_get_rr_peer_by_sid(ngx_http_upstream_rr_peer_data_t *rrp,
    ngx_str_t *hint, ngx_uint_t *p, ngx_uint_t lock)
{
    uintptr_t                     m;
    ngx_uint_t                    i, n;
    ngx_http_upstream_rr_peer_t  *peer;

    if (hint == NULL) {
        return NULL;
    }

    for (peer = rrp->peers->peer, i = 0;
         peer;
         peer = peer->next, i++)
    {

        if (peer->sid.len == hint->len
            && ngx_memcmp(peer->sid.data, hint->data, hint->len) == 0)
        {
            goto found;
        }
    }

    return NULL;

found:

    n = i / (8 * sizeof(uintptr_t));
    m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

    if (rrp->tried[n] & m) {
        return NULL;
    }

    if (lock) {
        ngx_http_upstream_rr_peer_lock(rrp->peers, peer);
    }

    if (peer->down
#if (NGX_HTTP_UPSTREAM_STICKY)
        & ~NGX_HTTP_UPSTREAM_DRAINING
#endif
    ) {
        goto failed;
    }

    if (peer->max_fails
        && peer->fails >= peer->max_fails
        && ngx_time() - peer->checked <= peer->fail_timeout)
    {
        goto failed;
    }

    if (peer->max_conns && peer->conns >= peer->max_conns) {
        goto failed;
    }

    *p = i;
    return peer;

failed:

    if (lock) {
        ngx_http_upstream_rr_peer_unlock(rrp->peers, peer);
    }

    return NULL;
}

#endif


/**
 * 当不再使用一台后端时，需要进行收尾处理，比如统计失败的次数。
 *
 * 函数参数state的取值：
 *      0，请求被成功处理;
 *      NGX_PEER_FAILED，连接失败;
 *      NGX_PEER_NEXT，连接失败，或者连接成功但后端未能成功处理请求
 * 当state为后两个值时：
 *      如果pc->tries不为0，需要重新选取一个后端，继续尝试，此后会重复调用r->upstream->peer.get。
 *      如果pc->tries为0，便不再尝试，给客户端返回502错误码（Bad Gateway）。
 * 成功连接后端服务器并且正常处理完成客户端请求后需释放后端服务器
 *
 *
 * 相关变量的更新
 *  accessed：释放peer时，如果发现后端出错了，则更新为now。
 *  checked：释放peer时，如果发现后端出错了，则更新为now。选定该peer时，如果now - checked > fail_timeout，则更新为now。
 *  fails：释放peer时，如果本次成功了且accessed < checked，说明距离最后一次失败的时间点，已超过fail_timeout了，清零fails。
 */
void
ngx_http_upstream_free_round_robin_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
#if (NGX_HTTP_UPSTREAM_ZONE)
    ngx_http_upstream_rr_peer_data_t  *rrp = data;

    ngx_http_upstream_rr_peers_rlock(rrp->peers);
    ngx_http_upstream_rr_peer_lock(rrp->peers, rrp->current);
#endif

    ngx_http_upstream_free_round_robin_peer_locked(pc, data, state);
}


void
ngx_http_upstream_free_round_robin_peer_locked(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state)
{
    ngx_http_upstream_rr_peer_data_t  *rrp = data;

    time_t                       now;
    ngx_http_upstream_rr_peer_t  *peer;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "free rr peer %ui %ui", pc->tries, state);

    /* TODO: NGX_PEER_KEEPALIVE */

    peer = rrp->current;         /* 当前使用的后端服务器 */

    ngx_http_upstream_rr_peers_rlock(rrp->peers);
    ngx_http_upstream_rr_peer_lock(rrp->peers, peer);

    /* 若只有一个后端服务器，则设置 ngx_peer_connection_t 结构体成员 tries 为 0，并 return 返回 */
    if (rrp->peers->single) {

        if (peer->fails) {
            peer->fails = 0; /* 不能再继续尝试了 */
        }

        peer->conns--;      /* 减少后端的当前连接数 */

        if (ngx_http_upstream_rr_peer_unref(rrp->peers, peer) == NGX_OK) {
            ngx_http_upstream_rr_peer_unlock(rrp->peers, peer);
        }

        ngx_http_upstream_rr_peers_unlock(rrp->peers);

        pc->tries = 0;
        return;
    }
    /* 若不止一个后端服务器，则执行以下程序 */

    /*
     * 如果连接后端失败了
     */
    if (state & NGX_PEER_FAILED) {
        now = ngx_time();

        peer->fails++;             /* 一段时间内，已经失败的次数 */
        peer->accessed = now;     /* 最近一次失败的时间点 */
        peer->checked = now;     /* 用于检查是否超过了“一段时间” */

        /* 当后端出错时，降低其有效权重 */
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

        /* 有效权重的最小值为0 */
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

    /* 更新后端的当前连接数 */
    peer->conns--;

    if (ngx_http_upstream_rr_peer_unref(rrp->peers, peer) == NGX_OK) {
        ngx_http_upstream_rr_peer_unlock(rrp->peers, peer);
    }

    ngx_http_upstream_rr_peers_unlock(rrp->peers);

    if (pc->tries) {
        pc->tries--;        /* 对于一个请求，允许尝试的后端个数 */
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
