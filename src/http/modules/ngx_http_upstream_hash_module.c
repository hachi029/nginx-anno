
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/**
 * 表示一个虚拟节点， 一个真实节点，一般会对应weight * 160个虚拟节点。
 * 
 */
typedef struct {
    uint32_t                            hash;       /* 虚拟节点的哈希值 */
    ngx_str_t                          *server;     /* 虚拟节点归属的真实节点，对应真实节点的server成员 */
} ngx_http_upstream_chash_point_t;


/**
 * 表示整个虚拟环
 */
typedef struct {
    ngx_uint_t                          number;         /* 虚拟节点的个数 */
    ngx_http_upstream_chash_point_t     point[1];       /* 虚拟节点的数组首地址 */
} ngx_http_upstream_chash_points_t;


/**
 * 本模块的配置结构体
 */
typedef struct {
    ngx_http_complex_value_t            key;        /* 关联hash指令的第一个参数，用于计算请求的hash值 */
#if (NGX_HTTP_UPSTREAM_ZONE)
    ngx_uint_t                          config;
#endif
    ngx_http_upstream_chash_points_t   *points;     /* 虚拟节点的数组 */
} ngx_http_upstream_hash_srv_conf_t;


typedef struct {
    /* the round robin data must be first */
    ngx_http_upstream_rr_peer_data_t    rrp;        /* round robin的per request负载均衡数据 */
    ngx_http_upstream_hash_srv_conf_t  *conf;       /* server配置块 */
    ngx_str_t                           key;        /* 对于本次请求，hash指令的第一个参数的具体值，用于计算本次请求的哈希值 */
    ngx_uint_t                          tries;      /* 已经尝试的虚拟节点数 */
    ngx_uint_t                          rehash;     /* 本算法不使用此成员 */
    uint32_t                            hash;       /* 根据请求的哈希值，找到顺时方向最近的一个虚拟节点，hash为该虚拟节点在数组中的索引 */
    ngx_event_get_peer_pt               get_rr_peer;/* round robin算法的peer.get函数 */
} ngx_http_upstream_hash_peer_data_t;


static ngx_int_t ngx_http_upstream_init_hash(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_init_hash_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_hash_peer(ngx_peer_connection_t *pc,
    void *data);

static ngx_int_t ngx_http_upstream_init_chash(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_update_chash(ngx_pool_t *pool,
    ngx_http_upstream_srv_conf_t *us);
static int ngx_libc_cdecl
    ngx_http_upstream_chash_cmp_points(const void *one, const void *two);
static ngx_uint_t ngx_http_upstream_find_chash_point(
    ngx_http_upstream_chash_points_t *points, uint32_t hash);
static ngx_int_t ngx_http_upstream_init_chash_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_chash_peer(ngx_peer_connection_t *pc,
    void *data);

static void *ngx_http_upstream_hash_create_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_hash(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_upstream_hash_commands[] = {

    //在一个upstream配置块中，如果有hash指令，则使用的负载均衡算法为哈希算法，
    { ngx_string("hash"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE12,
      ngx_http_upstream_hash,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


/**
 * https://www.kancloud.cn/digest/sknginx/130034
 * 
 * 当后端是缓存服务器时，经常使用一致性哈希算法来进行负载均衡。
 * 
 * 使用一致性哈希的好处在于，增减集群的缓存服务器时，只有少量的缓存会失效，回源量较小。
 * 
 */
static ngx_http_module_t  ngx_http_upstream_hash_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_upstream_hash_create_conf,    /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_hash_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_hash_module_ctx,    /* module context */
    ngx_http_upstream_hash_commands,       /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


/**
 * 
 */
static ngx_int_t
ngx_http_upstream_init_hash(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
{
    if (ngx_http_upstream_init_round_robin(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    us->peer.init = ngx_http_upstream_init_hash_peer;

    return NGX_OK;
}


/**
 * hash算法的per request负载均衡初始化函数。
 * 
 */
static ngx_int_t
ngx_http_upstream_init_hash_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_upstream_hash_srv_conf_t   *hcf;
    ngx_http_upstream_hash_peer_data_t  *hp;

    hp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_hash_peer_data_t));
    if (hp == NULL) {
        return NGX_ERROR;
    }

    r->upstream->peer.data = &hp->rrp;

    /* 调用round robin的per request负载均衡初始化函数 */
    if (ngx_http_upstream_init_round_robin_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    r->upstream->peer.get = ngx_http_upstream_get_hash_peer;

    hcf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_hash_module);

    /* 获取本请求对应的hash指令的第一个参数值，用于计算请求的hash值 */
    if (ngx_http_complex_value(r, &hcf->key, &hp->key) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "upstream hash key:\"%V\"", &hp->key);

    hp->conf = hcf;
    hp->tries = 0;
    hp->rehash = 0;
    hp->hash = 0;
    hp->get_rr_peer = ngx_http_upstream_get_round_robin_peer;       /* round robin的peer.get函数 */

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_get_hash_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_hash_peer_data_t  *hp = data;

    time_t                        now;
    u_char                        buf[NGX_INT_T_LEN];
    size_t                        size;
    uint32_t                      hash;
    ngx_int_t                     w;
    uintptr_t                     m;
    ngx_uint_t                    n, p;
    ngx_http_upstream_rr_peer_t  *peer;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get hash peer, try: %ui", pc->tries);

    ngx_http_upstream_rr_peers_rlock(hp->rrp.peers);

    if (hp->tries > 20 || hp->rrp.peers->number < 2 || hp->key.len == 0) {
        ngx_http_upstream_rr_peers_unlock(hp->rrp.peers);
        return hp->get_rr_peer(pc, &hp->rrp);
    }

#if (NGX_HTTP_UPSTREAM_ZONE)
    if (hp->rrp.peers->config && hp->rrp.config != *hp->rrp.peers->config) {
        ngx_http_upstream_rr_peers_unlock(hp->rrp.peers);
        return hp->get_rr_peer(pc, &hp->rrp);
    }
#endif

    now = ngx_time();

    pc->cached = 0;
    pc->connection = NULL;

#if (NGX_HTTP_UPSTREAM_SID)
    peer = ngx_http_upstream_get_rr_peer_by_sid(&hp->rrp, pc->hint, &p, 1);

    if (peer) {
        n = p / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

        goto found;
    }
#endif

    for ( ;; ) {

        /*
         * Hash expression is compatible with Cache::Memcached:
         * ((crc32([REHASH] KEY) >> 16) & 0x7fff) + PREV_HASH
         * with REHASH omitted at the first iteration.
         */

        ngx_crc32_init(hash);

        if (hp->rehash > 0) {
            size = ngx_sprintf(buf, "%ui", hp->rehash) - buf;
            ngx_crc32_update(&hash, buf, size);
        }

        ngx_crc32_update(&hash, hp->key.data, hp->key.len);
        ngx_crc32_final(hash);

        hash = (hash >> 16) & 0x7fff;

        hp->hash += hash;
        hp->rehash++;

        w = hp->hash % hp->rrp.peers->total_weight;
        peer = hp->rrp.peers->peer;
        p = 0;

        while (w >= peer->weight) {
            w -= peer->weight;
            peer = peer->next;
            p++;
        }

        n = p / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

        if (hp->rrp.tried[n] & m) {
            goto next;
        }

        ngx_http_upstream_rr_peer_lock(hp->rrp.peers, peer);

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "get hash peer, value:%uD, peer:%ui", hp->hash, p);

        if (peer->down) {
            ngx_http_upstream_rr_peer_unlock(hp->rrp.peers, peer);
            goto next;
        }

        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            ngx_http_upstream_rr_peer_unlock(hp->rrp.peers, peer);
            goto next;
        }

        if (peer->max_conns && peer->conns >= peer->max_conns) {
            ngx_http_upstream_rr_peer_unlock(hp->rrp.peers, peer);
            goto next;
        }

        break;

    next:

        if (++hp->tries > 20) {
            ngx_http_upstream_rr_peers_unlock(hp->rrp.peers);
            return hp->get_rr_peer(pc, &hp->rrp);
        }
    }

#if (NGX_HTTP_UPSTREAM_SID)
found:
#endif

    hp->rrp.current = peer;
    ngx_http_upstream_rr_peer_ref(hp->rrp.peers, peer);

    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;

#if (NGX_HTTP_UPSTREAM_SID)
    pc->sid = &peer->sid;
#endif

    peer->conns++;

    if (now - peer->checked > peer->fail_timeout) {
        peer->checked = now;
    }

    ngx_http_upstream_rr_peer_unlock(hp->rrp.peers, peer);
    ngx_http_upstream_rr_peers_unlock(hp->rrp.peers);

    hp->rrp.tried[n] |= m;

    return NGX_OK;
}


/**
 * 在执行ngx_http_upstream_module的init main conf函数时，会调用所有upstream块的初始化函数。
 * 对于使用一致性哈希的upstream块，其初始化函数（peer.init_upstream）就是此函数
 * 
 * 主要工作：
 *  调用round robin的upstream块初始化函数来创建和初始化真实节点
 *  指定per request的负载均衡初始化函数peer.init
 *  创建和初始化虚拟节点数组，使该数组中的虚拟节点有序而不重复
 */
static ngx_int_t
ngx_http_upstream_init_chash(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
{
    /* 使用round robin的upstream块初始化函数，创建和初始化真实节点 */
    if (ngx_http_upstream_init_round_robin(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    /* 重新设置per request的负载均衡初始化函数 */
    us->peer.init = ngx_http_upstream_init_chash_peer;

#if (NGX_HTTP_UPSTREAM_ZONE)
    if (us->shm_zone) {
        return NGX_OK;
    }
#endif

    return ngx_http_upstream_update_chash(cf->pool, us);
}


/**
 * 构建虚拟环
 */
static ngx_int_t
ngx_http_upstream_update_chash(ngx_pool_t *pool,
    ngx_http_upstream_srv_conf_t *us)
{
    u_char                             *host, *port, c;
    size_t                              host_len, port_len, size;
    uint32_t                            hash, base_hash;
    ngx_str_t                          *server;
    ngx_uint_t                          npoints, i, j;
    ngx_http_upstream_rr_peer_t        *peer;
    ngx_http_upstream_rr_peers_t       *peers;
    ngx_http_upstream_chash_points_t   *points;
    ngx_http_upstream_hash_srv_conf_t  *hcf;
    union {
        uint32_t                        value;
        u_char                          byte[4];
    } prev_hash;

    hcf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_hash_module);

    if (hcf->points) {
        ngx_free(hcf->points);
        hcf->points = NULL;
    }

    peers = us->peer.data;
    npoints = peers->total_weight * 160;

    /* 一共创建npoints个虚拟节点 */
    size = sizeof(ngx_http_upstream_chash_points_t)
           - sizeof(ngx_http_upstream_chash_point_t)
           + sizeof(ngx_http_upstream_chash_point_t) * npoints;

    points = pool ? ngx_palloc(pool, size) : ngx_alloc(size, ngx_cycle->log);
    if (points == NULL) {
        return NGX_ERROR;
    }

    points->number = 0;

    if (npoints == 0) {
        hcf->points = points;
        return NGX_OK;
    }

    /* 初始化所有的虚拟节点 */
    for (peer = peers->peer; peer; peer = peer->next) {
        server = &peer->server;

        /*
         * Hash expression is compatible with Cache::Memcached::Fast:
         * crc32(HOST \0 PORT PREV_HASH).
         */

        if (server->len >= 5
            && ngx_strncasecmp(server->data, (u_char *) "unix:", 5) == 0)
        {
            host = server->data + 5;
            host_len = server->len - 5;
            port = NULL;
            port_len = 0;
            goto done;
        }

        /* 把每个peer的server成员，解析为HOST和PORT */
        for (j = 0; j < server->len; j++) {
            c = server->data[server->len - j - 1];

            if (c == ':') {
                host = server->data;
                host_len = server->len - j - 1;
                port = server->data + server->len - j;
                port_len = j;
                goto done;
            }

            if (c < '0' || c > '9') {       /* 表示没有指定端口 */
                break;
            }
        }

        host = server->data;
        host_len = server->len;
        port = NULL;
        port_len = 0;

    done:

        /* 根据解析peer的server成员所得的HOST和PORT，计算虚拟节点的base_hash值 */
        ngx_crc32_init(base_hash);
        ngx_crc32_update(&base_hash, host, host_len);
        ngx_crc32_update(&base_hash, (u_char *) "", 1);     /* 空字符串包含字符\0 */
        ngx_crc32_update(&base_hash, port, port_len);

        /* 对于归属同一个真实节点的虚拟节点，它们的base_hash值相同，而prev_hash不同 */
        prev_hash.value = 0;
        npoints = peer->weight * 160;

        for (j = 0; j < npoints; j++) {
            hash = base_hash;

            ngx_crc32_update(&hash, prev_hash.byte, 4);
            ngx_crc32_final(hash);

            points->point[points->number].hash = hash;      /* 虚拟节点的哈希值 */
            points->point[points->number].server = server;  /* 虚拟节点所归属的真实节点，对应真实节点的server成员 */
            points->number++;

#if (NGX_HAVE_LITTLE_ENDIAN)
            prev_hash.value = hash;
#else
            prev_hash.byte[0] = (u_char) (hash & 0xff);
            prev_hash.byte[1] = (u_char) ((hash >> 8) & 0xff);
            prev_hash.byte[2] = (u_char) ((hash >> 16) & 0xff);
            prev_hash.byte[3] = (u_char) ((hash >> 24) & 0xff);
#endif
        }
    }

    /* 使用快速排序，使虚拟节点数组的元素，按照其hash值从小到大有序 */
    ngx_qsort(points->point,
              points->number,
              sizeof(ngx_http_upstream_chash_point_t),
              ngx_http_upstream_chash_cmp_points);

    /* 如果虚拟节点数组中，有多个元素的hash值相同，只保留第一个 */
    for (i = 0, j = 1; j < points->number; j++) {
        if (points->point[i].hash != points->point[j].hash) {
            points->point[++i] = points->point[j];
        }
    }

    /* 经过上述步骤后，虚拟节点数组中的元素，有序而不重复 */
    points->number = i + 1;

    hcf->points = points;       /* 保存虚拟节点数组 */

    return NGX_OK;
}


static int ngx_libc_cdecl
ngx_http_upstream_chash_cmp_points(const void *one, const void *two)
{
    ngx_http_upstream_chash_point_t *first =
                                       (ngx_http_upstream_chash_point_t *) one;
    ngx_http_upstream_chash_point_t *second =
                                       (ngx_http_upstream_chash_point_t *) two;

    if (first->hash < second->hash) {
        return -1;

    } else if (first->hash > second->hash) {
        return 1;

    } else {
        return 0;
    }
}


/**
 * 
 * 虚拟节点数组是有序的，事先已按照虚拟节点的hash值从小到大排序好了。
 * 
 * 现在使用二分查找，寻找第一个hash值大于等于请求的哈希值的虚拟节点，即“顺时针方向最近”的一个虚拟节点。
 * 
 */
static ngx_uint_t
ngx_http_upstream_find_chash_point(ngx_http_upstream_chash_points_t *points,
    uint32_t hash)
{
    ngx_uint_t                        i, j, k;
    ngx_http_upstream_chash_point_t  *point;

    /* find first point >= hash */

    point = &points->point[0];  //环上第1个虚拟节点

    i = 0;
    j = points->number;

    while (i < j) {         //以二分法检索虚拟节点
        k = (i + j) / 2;

        if (hash > point[k].hash) {
            i = k + 1;

        } else if (hash < point[k].hash) {
            j = k;

        } else {
            return k;       //以二分法检索虚拟节点
        }
    }

    return i;
}


/**
 * ngx_http_proxy_module模块的CONTENT_PHASE阶段的处理函数ngx_http_proxy_handler，
 * 在初始化upstream机制的ngx_http_upstream_init_request函数中，调用在第二步中指定的peer.init，主要用于初始化请求的负载均衡数据。
 * 对于一致性哈希，peer.init为ngx_http_upstream_init_chash_peer
 * 
 * 主要工作：
 *  首先调用hash算法的per request负载均衡初始化函数，创建和初始化请求的负载均衡数据。
 *  重新指定peer.get，用于选取一个真实节点来处理本次请求。
 *  获取的本请求对应的hash指令的第一个参数值，计算请求的hash值。
 *  寻找第一个hash值大于等于请求的哈希值的虚拟节点，即寻找“顺时针方向最近”的一个虚拟节点。
 * 
 */ 
static ngx_int_t
ngx_http_upstream_init_chash_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    uint32_t                             hash;
    ngx_http_upstream_hash_srv_conf_t   *hcf;
    ngx_http_upstream_hash_peer_data_t  *hp;

    /* 调用hash算法的per request负载均衡初始化函数，创建和初始化请求的负载均衡数据 */
    if (ngx_http_upstream_init_hash_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

     /* 重新指定peer.get，用于选取一个真实节点 */
    r->upstream->peer.get = ngx_http_upstream_get_chash_peer;

    hp = r->upstream->peer.data;
    hcf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_hash_module);

     /* 根据获取的本请求对应的hash指令的第一个参数值，计算请求的hash值 */
    hash = ngx_crc32_long(hp->key.data, hp->key.len);

    ngx_http_upstream_rr_peers_rlock(hp->rrp.peers);

#if (NGX_HTTP_UPSTREAM_ZONE)
    if (hp->rrp.peers->config
        && (hcf->points == NULL || hcf->config != *hp->rrp.peers->config))
    {
        if (ngx_http_upstream_update_chash(NULL, us) != NGX_OK) {
            ngx_http_upstream_rr_peers_unlock(hp->rrp.peers);
            return NGX_ERROR;
        }

        hcf->config = *hp->rrp.peers->config;
    }
#endif

    if (hcf->points->number) {
        /* 根据请求的hash值，找到顺时针方向最近的一个虚拟节点，hp->hash记录此虚拟节点
        * 在数组中的索引。
        */
        hp->hash = ngx_http_upstream_find_chash_point(hcf->points, hash);
    }

    ngx_http_upstream_rr_peers_unlock(hp->rrp.peers);

    return NGX_OK;
}


/**
 * 对于一致性哈希算法的peer.get函数
 * 
 * 其实在peer.init中，已经找到了该请求对应的虚拟节点了：根据请求对应的hash指令的第一个参数值，计算请求的hash值。
 * 寻找第一个哈希值大于等于请求的hash值的虚拟节点，即“顺时针方向最近”的一个虚拟节点。
 * 
 * 
 * 在peer.get中，需查找此虚拟节点对应的真实节点。根据虚拟节点的server成员，在真实节点数组中查找server成员一样的且可用的真实节点。
 * 
 * 如果找不到，那么沿着顺时针方向，继续查找下一个虚拟节点对应的真实节点。如果找到一个真实节点，那么就是它了。
 * 
 * 如果找到多个真实节点，使用轮询的方法从中选取一个。
 * 
 */
static ngx_int_t
ngx_http_upstream_get_chash_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_hash_peer_data_t  *hp = data;

    time_t                              now;
    intptr_t                            m;
    ngx_str_t                          *server;
    ngx_int_t                           total;
    ngx_uint_t                          i, n, best_i;
    ngx_http_upstream_rr_peer_t        *peer, *best;
    ngx_http_upstream_chash_point_t    *point;
    ngx_http_upstream_chash_points_t   *points;
    ngx_http_upstream_hash_srv_conf_t  *hcf;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get consistent hash peer, try: %ui", pc->tries);

    ngx_http_upstream_rr_peers_wlock(hp->rrp.peers);

    if (hp->tries > 20 || hp->rrp.peers->single || hp->key.len == 0) {
        ngx_http_upstream_rr_peers_unlock(hp->rrp.peers);
        return hp->get_rr_peer(pc, &hp->rrp);
    }

    pc->cached = 0;
    pc->connection = NULL;

    if (hp->rrp.peers->number == 0) {
        pc->name = hp->rrp.peers->name;
        ngx_http_upstream_rr_peers_unlock(hp->rrp.peers);
        return NGX_BUSY;
    }

#if (NGX_HTTP_UPSTREAM_ZONE)
    if (hp->rrp.peers->config && hp->rrp.config != *hp->rrp.peers->config) {
        pc->name = hp->rrp.peers->name;
        ngx_http_upstream_rr_peers_unlock(hp->rrp.peers);
        return NGX_BUSY;
    }
#endif

    now = ngx_time();
    hcf = hp->conf;

    points = hcf->points;           /* 虚拟节点数组 */
    point = &points->point[0];      /* 指向第一个虚拟节点 */

#if (NGX_HTTP_UPSTREAM_SID)
    best = ngx_http_upstream_get_rr_peer_by_sid(&hp->rrp, pc->hint, &best_i, 0);

    if (best) {
        goto found;
    }
#endif

    for ( ;; ) {

         /* 在peer.init中，已根据请求的哈希值，找到顺时针方向最近的一个虚拟节点，
         * hash为该虚拟节点在数组中的索引。
         * 一开始hash值肯定小于number，之后每尝试一个虚拟节点后，hash++。取模是为了防止越界访问。
         */
        server = point[hp->hash % points->number].server;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "consistent hash peer:%uD, server:\"%V\"",
                       hp->hash, server);

        best = NULL;
        best_i = 0;
        total = 0;

        /* 遍历真实节点数组，寻找可用的、该虚拟节点归属的真实节点(server成员相同)，
          * 如果有多个真实节点同时符合条件，那么使用轮询来从中选取一个真实节点。
          */
        for (peer = hp->rrp.peers->peer, i = 0;
             peer;
             peer = peer->next, i++)
        {
            /* 检查此真实节点在状态位图中对应的位，为1时表示不可用 */
            n = i / (8 * sizeof(uintptr_t));
            m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

            if (hp->rrp.tried[n] & m) {
                continue;
            }

            /* server指令中携带了down属性，表示后端永久不可用 */
            if (peer->down) {
                continue;
            }

            /* 在一段时间内，如果此真实节点的失败次数，超过了允许的最大值，那么不允许使用了 */
            if (peer->max_fails
                && peer->fails >= peer->max_fails
                && now - peer->checked <= peer->fail_timeout)
            {
                continue;
            }

            if (peer->max_conns && peer->conns >= peer->max_conns) {
                continue;
            }

            /* 如果真实节点的server成员和虚拟节点的不同，表示虚拟节点不属于此真实节点 */
            if (peer->server.len != server->len
                || ngx_strncmp(peer->server.data, server->data, server->len)
                   != 0)
            {
                continue;
            }

            peer->current_weight += peer->effective_weight;     /* 对每个真实节点，增加其当前权重 */
            total += peer->effective_weight;                    /* 累加所有真实节点的有效权重 */

            /* 如果之前此真实节点发生了失败，会减小其effective_weight来降低它的权重。          
             * 此后又通过增加其effective_weight来恢复它的权重。          
             */ 
            if (peer->effective_weight < peer->weight) {
                peer->effective_weight++;
            }

            /* 选取当前权重最大者，作为本次选定的真实节点 */
            if (best == NULL || peer->current_weight > best->current_weight) {
                best = peer;
                best_i = i;
            }
        }

        /* 如果选定了一个真实节点 */
        if (best) {
            /* 如果使用了轮询，需要降低选定节点的当前权重 */
            best->current_weight -= total;
            goto found;
        }

        /* 增加虚拟节点的索引，即“沿着顺时针方向” */
        hp->hash++;
        /* 已经尝试的虚拟节点数 */
        hp->tries++;

        /* 如果把所有的虚拟节点都尝试了一遍，还找不到可用的真实节点 */
        if (hp->tries > 20) {
            ngx_http_upstream_rr_peers_unlock(hp->rrp.peers);
            return hp->get_rr_peer(pc, &hp->rrp);
        }
    }

found:

    /* 找到了和虚拟节点相对应的、可用的真实节点了 */
    hp->rrp.current = best;     /* 选定的真实节点 */
    ngx_http_upstream_rr_peer_ref(hp->rrp.peers, best);

    /* 保存选定的后端服务器的地址，之后会向这个地址发起连接 */
    pc->sockaddr = best->sockaddr;
    pc->socklen = best->socklen;
    pc->name = &best->name;

#if (NGX_HTTP_UPSTREAM_SID)
    pc->sid = &best->sid;
#endif

    best->conns++;

    /* 更新checked时间 */
    if (now - best->checked > best->fail_timeout) {
        best->checked = now;
    }

    ngx_http_upstream_rr_peers_unlock(hp->rrp.peers);

    n = best_i / (8 * sizeof(uintptr_t));
    m = (uintptr_t) 1 << best_i % (8 * sizeof(uintptr_t));

    /* 对于本次请求，如果之后需要再次选取真实节点，不能再选取同一个了 */
    hp->rrp.tried[n] |= m;

    return NGX_OK;
}


/**
 * 创建srv级别配置结构体
 */
static void *
ngx_http_upstream_hash_create_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_hash_srv_conf_t  *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_http_upstream_hash_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->points = NULL;

    return conf;
}


/**
 * hash指令解析函数
 * 
 * 如果hash指令，只带一个参数，则使用的负载均衡算法为哈希算法，比如：hash $host$uri;
 * 如果有hash指令，带了两个参数，且第二个参数为consistent，则使用的负载均衡算法为一致性哈希算法，比如： hash $host$uri consistent;
 */
static char *
ngx_http_upstream_hash(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_hash_srv_conf_t  *hcf = conf;

    ngx_str_t                         *value;
    ngx_http_upstream_srv_conf_t      *uscf;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &hcf->key;

    /* 把hash指令的第一个参数，关联到一个ngx_http_complex_value_t变量，
     * 之后可以通过该变量获取参数的实时值。
     */
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    /* 获取所在的upstream{}块 */
    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    if (uscf->peer.init_upstream) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "load balancing method redefined");
    }

    /* 指定此upstream块中server指令支持的属性 */
    uscf->flags = NGX_HTTP_UPSTREAM_CREATE
                  |NGX_HTTP_UPSTREAM_MODIFY
                  |NGX_HTTP_UPSTREAM_WEIGHT
                  |NGX_HTTP_UPSTREAM_MAX_CONNS
                  |NGX_HTTP_UPSTREAM_MAX_FAILS
                  |NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
                  |NGX_HTTP_UPSTREAM_DOWN;

     /* 根据hash指令携带的参数来判断是使用哈希算法，还是一致性哈希算法。
     * 每种算法都有自己的upstream块初始化函数。
      */
    if (cf->args->nelts == 2) {
        uscf->peer.init_upstream = ngx_http_upstream_init_hash;

    } else if (ngx_strcmp(value[2].data, "consistent") == 0) {
        uscf->peer.init_upstream = ngx_http_upstream_init_chash;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
