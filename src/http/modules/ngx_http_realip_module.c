
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_REALIP_XREALIP  0      //X-Real-IP
#define NGX_HTTP_REALIP_XFWD     1      //X-Forwarded-For
#define NGX_HTTP_REALIP_HEADER   2      // 用户自定义头
#define NGX_HTTP_REALIP_PROXY    3      //proxy_protocol


/**
 * https://nginx.org/en/docs/http/ngx_http_realip_module.html
 * 不是默认开启的模块
 */

/**
 * 模块的配置结构体 
 */ 
typedef struct {
    //set_real_ip_from 配置，每个元素为 ngx_cidr_t*
    ngx_array_t       *from;        /* array of ngx_cidr_t */
    ngx_uint_t         type;        //从哪个请求头解析客户端真实ip
    ngx_uint_t         hash;        //header的hash
    ngx_str_t          header;      //其他请求头 当不是三个之一时：X-Real-IP X-Forwarded-For proxy_protocol 
    ngx_flag_t         recursive;   //real_ip_recursive on | off
} ngx_http_realip_loc_conf_t;


/**
 * 模块自定义上下文，解析出真实客户端ip后，会用真实客户端ip设置到连接c上
 * 
 * 而本结构体保留了原始连接的 sockaddr 、socklen、addr_text 信息
 * 
 */
typedef struct {
    ngx_connection_t  *connection;      //与客户端的连接
    struct sockaddr   *sockaddr;        //原始连接的sockaddr
    socklen_t          socklen;         //原始连接的socklen
    ngx_str_t          addr_text;       //原始连接的addr_text
} ngx_http_realip_ctx_t;


static ngx_int_t ngx_http_realip_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_realip_set_addr(ngx_http_request_t *r,
    ngx_addr_t *addr);
static void ngx_http_realip_cleanup(void *data);
static char *ngx_http_realip_from(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_realip(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_realip_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_realip_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_realip_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_realip_init(ngx_conf_t *cf);
static ngx_http_realip_ctx_t *ngx_http_realip_get_module_ctx(
    ngx_http_request_t *r);


static ngx_int_t ngx_http_realip_remote_addr_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_realip_remote_port_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);


static ngx_command_t  ngx_http_realip_commands[] = {

    { ngx_string("set_real_ip_from"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_realip_from,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("real_ip_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_realip,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("real_ip_recursive"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_realip_loc_conf_t, recursive),
      NULL },

      ngx_null_command
};



static ngx_http_module_t  ngx_http_realip_module_ctx = {
    ngx_http_realip_add_variables,         /* preconfiguration */
    ngx_http_realip_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_realip_create_loc_conf,       /* create location configuration */
    ngx_http_realip_merge_loc_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_realip_module = {
    NGX_MODULE_V1,
    &ngx_http_realip_module_ctx,           /* module context */
    ngx_http_realip_commands,              /* module directives */
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
 * 本模块提供的变量
 * 
 * keeps the original client address
 * 
 */
static ngx_http_variable_t  ngx_http_realip_vars[] = {

    //keeps the original client address
    { ngx_string("realip_remote_addr"), NULL,
      ngx_http_realip_remote_addr_variable, 0, 0, 0 },

    //keeps the original client port
    { ngx_string("realip_remote_port"), NULL,
      ngx_http_realip_remote_port_variable, 0, 0, 0 },

      ngx_http_null_variable
};


/**
 * POST_READ_PHASE 和PREACCESS handler
 * 
 * 在这两个阶段都会回调此handler
 */
static ngx_int_t
ngx_http_realip_handler(ngx_http_request_t *r)
{
    u_char                      *p;
    size_t                       len;
    ngx_str_t                   *value;
    ngx_uint_t                   i, hash;
    ngx_addr_t                   addr;
    ngx_list_part_t             *part;
    ngx_table_elt_t             *header, *xfwd;
    ngx_connection_t            *c;
    ngx_http_realip_ctx_t       *ctx;
    ngx_http_realip_loc_conf_t  *rlcf;

    //获取loc配置
    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_realip_module);

    //如果没配置 set_real_ip_from 指令
    if (rlcf->from == NULL) {
        return NGX_DECLINED;
    }

    //获取模块上下文
    ctx = ngx_http_realip_get_module_ctx(r);

    if (ctx) {      //解析到真实ip后，会设置进ctx中。ctx不为NULL，说明已经获取到真实ip了
        return NGX_DECLINED;
    }

    //根据 real_ip_header 指令配置值
    switch (rlcf->type) {

    //x_real_ip
    case NGX_HTTP_REALIP_XREALIP:

        if (r->headers_in.x_real_ip == NULL) {
            return NGX_DECLINED;
        }

        //value只能是一个值
        value = &r->headers_in.x_real_ip->value;
        xfwd = NULL;

        break;

    //x_forwarded_for
    case NGX_HTTP_REALIP_XFWD:

        //xfwd支持多个请求头
        xfwd = r->headers_in.x_forwarded_for;

        if (xfwd == NULL) {
            return NGX_DECLINED;
        }

        value = NULL;

        break;

    //proxy_protocol
    case NGX_HTTP_REALIP_PROXY:

        if (r->connection->proxy_protocol == NULL) {
            return NGX_DECLINED;
        }

        value = &r->connection->proxy_protocol->src_addr;
        xfwd = NULL;

        break;

    //用户自定义头    
    default: /* NGX_HTTP_REALIP_HEADER */

        part = &r->headers_in.headers.part;
        header = part->elts;

        hash = rlcf->hash;
        len = rlcf->header.len;
        p = rlcf->header.data;

        //遍历所有请求头进行查找
        for (i = 0; /* void */ ; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            //比较时，先比较hash, 再比较长度，最后进行字符串比较
            if (hash == header[i].hash
                && len == header[i].key.len
                && ngx_strncmp(p, header[i].lowcase_key, len) == 0)
            {
                value = &header[i].value;
                xfwd = NULL;

                goto found;
            }
        }

        return NGX_DECLINED;
    }

found:

    c = r->connection;

    //优先匹配对端ip
    addr.sockaddr = c->sockaddr;
    addr.socklen = c->socklen;
    /* addr.name = c->addr_text; */

    //依次匹配对端ip, xfwd, value查找真实ip
    if (ngx_http_get_forwarded_addr(r, &addr, xfwd, value, rlcf->from,
                                    rlcf->recursive)
        != NGX_DECLINED)
    {
        //如果是 proxy_protocol， 设置addr.sockaddr的端口号
        if (rlcf->type == NGX_HTTP_REALIP_PROXY) {
            ngx_inet_set_port(addr.sockaddr, c->proxy_protocol->src_port);
        }

        return ngx_http_realip_set_addr(r, &addr);
    }

    return NGX_DECLINED;
}


/**
 * 查找到真实ip后， 设置真实ip到模块自定义上下文ctx中
 */
static ngx_int_t
ngx_http_realip_set_addr(ngx_http_request_t *r, ngx_addr_t *addr)
{
    size_t                  len;
    u_char                 *p;
    u_char                  text[NGX_SOCKADDR_STRLEN];
    ngx_connection_t       *c;
    ngx_pool_cleanup_t     *cln;
    ngx_http_realip_ctx_t  *ctx;

    //增加一个清理函数，清理函数的data为模块上下文
    cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_http_realip_ctx_t));
    if (cln == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = cln->data;

    c = r->connection;

    len = ngx_sock_ntop(addr->sockaddr, addr->socklen, text,
                        NGX_SOCKADDR_STRLEN, 0);
    if (len == 0) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = ngx_pnalloc(c->pool, len);
    if (p == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memcpy(p, text, len);

    //这个cleanup, 在请求结束时恢复连接上设置的sockaddr
    cln->handler = ngx_http_realip_cleanup;
    //设置模块上下文
    ngx_http_set_ctx(r, ctx, ngx_http_realip_module);

    //ctx临时记录连接上原始的sockaddr
    ctx->connection = c;
    ctx->sockaddr = c->sockaddr;
    ctx->socklen = c->socklen;
    ctx->addr_text = c->addr_text;

    //将原始的sockaddr设置为解析出来的真实ip
    c->sockaddr = addr->sockaddr;
    c->socklen = addr->socklen;
    c->addr_text.len = len;
    c->addr_text.data = p;

    return NGX_DECLINED;
}


/**
 * 本模块r-pool上的cleanup回调。
 * 
 * 解析出真实ip后，会设置这个方法作为cleanup
 * 
 * data为模块的上下文 ngx_http_realip_ctx_t
 * 
 * 恢复原始连接上的sockaddr
 * 
 */
static void
ngx_http_realip_cleanup(void *data)
{
    ngx_http_realip_ctx_t *ctx = data;

    ngx_connection_t  *c;

    c = ctx->connection;

    c->sockaddr = ctx->sockaddr;
    c->socklen = ctx->socklen;
    c->addr_text = ctx->addr_text;
}


/**
 * 解析配置指令 set_real_ip_from 
 * 
 * set_real_ip_from address | CIDR | unix:;
 * 
 */
static char *
ngx_http_realip_from(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_realip_loc_conf_t *rlcf = conf;

    ngx_int_t             rc;
    ngx_str_t            *value;
    ngx_url_t             u;
    ngx_cidr_t            c, *cidr;
    ngx_uint_t            i;
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    value = cf->args->elts;

    //如果为NULL， 初始化rlcf->from动态数组
    if (rlcf->from == NULL) {
        rlcf->from = ngx_array_create(cf->pool, 2,
                                      sizeof(ngx_cidr_t));
        if (rlcf->from == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    //unix:
#if (NGX_HAVE_UNIX_DOMAIN)

    if (ngx_strcmp(value[1].data, "unix:") == 0) {
        cidr = ngx_array_push(rlcf->from);
        if (cidr == NULL) {
            return NGX_CONF_ERROR;
        }

        cidr->family = AF_UNIX;
        return NGX_CONF_OK;
    }

#endif

    //解析cidr str为 ngx_cidr_t
    rc = ngx_ptocidr(&value[1], &c);

    if (rc != NGX_ERROR) {
        if (rc == NGX_DONE) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "low address bits of %V are meaningless",
                               &value[1]);
        }

        //加入到 rlcf->from
        cidr = ngx_array_push(rlcf->from);
        if (cidr == NULL) {
            return NGX_CONF_ERROR;
        }

        *cidr = c;

        return NGX_CONF_OK;
    }

    //这里说明将&value[1]解析为一个cidr失败了，配置的可能不是cidr而是一个域名

    
    //也支持配置一个域名
    ngx_memzero(&u, sizeof(ngx_url_t));
    u.host = value[1];

    //解析域名
    if (ngx_inet_resolve_host(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in set_real_ip_from \"%V\"",
                               u.err, &u.host);
        }

        return NGX_CONF_ERROR;
    }

    //加入到rlcf->from动态数组, naddrs为解析出的地址个数
    cidr = ngx_array_push_n(rlcf->from, u.naddrs);
    if (cidr == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(cidr, u.naddrs * sizeof(ngx_cidr_t));

    //遍历解析出来的每个地址
    for (i = 0; i < u.naddrs; i++) {
        cidr[i].family = u.addrs[i].sockaddr->sa_family;

        switch (cidr[i].family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) u.addrs[i].sockaddr;
            cidr[i].u.in6.addr = sin6->sin6_addr;
            ngx_memset(cidr[i].u.in6.mask.s6_addr, 0xff, 16);
            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) u.addrs[i].sockaddr;
            cidr[i].u.in.addr = sin->sin_addr.s_addr;
            cidr[i].u.in.mask = 0xffffffff;
            break;
        }
    }

    return NGX_CONF_OK;
}


/**
 * 配置指令real_ip_header 解析
 * 
 * real_ip_header field | X-Real-IP | X-Forwarded-For | proxy_protocol;
 * 
 * 定义从哪个请求头中提取客户端真实ip
 * 
 */
static char *
ngx_http_realip(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_realip_loc_conf_t *rlcf = conf;

    ngx_str_t  *value;

    //已经配置过了
    if (rlcf->type != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;

    //X-Real-IP
    if (ngx_strcmp(value[1].data, "X-Real-IP") == 0) {
        rlcf->type = NGX_HTTP_REALIP_XREALIP;
        return NGX_CONF_OK;
    }

    //X-Forwarded-For
    if (ngx_strcmp(value[1].data, "X-Forwarded-For") == 0) {
        rlcf->type = NGX_HTTP_REALIP_XFWD;
        return NGX_CONF_OK;
    }

    //proxy_protocol
    if (ngx_strcmp(value[1].data, "proxy_protocol") == 0) {
        rlcf->type = NGX_HTTP_REALIP_PROXY;
        return NGX_CONF_OK;
    }

    //其他值
    rlcf->type = NGX_HTTP_REALIP_HEADER;
    rlcf->hash = ngx_hash_strlow(value[1].data, value[1].data, value[1].len);
    rlcf->header = value[1];

    return NGX_CONF_OK;
}


/**
 * 创建loc配置结构体
 */
static void *
ngx_http_realip_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_realip_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_realip_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->from = NULL;
     *     conf->hash = 0;
     *     conf->header = { 0, NULL };
     */

    conf->type = NGX_CONF_UNSET_UINT;
    conf->recursive = NGX_CONF_UNSET;

    return conf;
}


/**
 * 合并loc配置结构体
 */
static char *
ngx_http_realip_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_realip_loc_conf_t  *prev = parent;
    ngx_http_realip_loc_conf_t  *conf = child;

    if (conf->from == NULL) {
        conf->from = prev->from;
    }

    ngx_conf_merge_uint_value(conf->type, prev->type, NGX_HTTP_REALIP_XREALIP);
    ngx_conf_merge_value(conf->recursive, prev->recursive, 0);

    if (conf->header.len == 0) {
        conf->hash = prev->hash;
        conf->header = prev->header;
    }

    return NGX_CONF_OK;
}


/**
 * 注册变量
 */
static ngx_int_t
ngx_http_realip_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_realip_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


/**
 * postconfiguration
 * 
 * 注册一个POST_READ_PHASE和PREACCESS_PHASE的handler
 * 
 * handler都是 ngx_http_realip_handler
 *  
 */
static ngx_int_t
ngx_http_realip_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_realip_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_realip_handler;

    return NGX_OK;
}


/**
 * 获取模块自定义ctx
 * 
 * 增加从r->pool->cleanup中获取的逻辑
 */
static ngx_http_realip_ctx_t *
ngx_http_realip_get_module_ctx(ngx_http_request_t *r)
{
    ngx_pool_cleanup_t     *cln;
    ngx_http_realip_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_realip_module);

    if (ctx == NULL && (r->internal || r->filter_finalize)) {

        /*
         * if module context was reset, the original address
         * can still be found in the cleanup handler
         */

        for (cln = r->pool->cleanup; cln; cln = cln->next) {
            if (cln->handler == ngx_http_realip_cleanup) {
                ctx = cln->data;
                break;
            }
        }
    }

    return ctx;
}


/**
 * $realip_remote_addr 的get_handler
 * 
 * 获取的是 ctx->addr_text (ctx保留了原始的c上的addr_text)
 */
static ngx_int_t
ngx_http_realip_remote_addr_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t              *addr_text;
    ngx_http_realip_ctx_t  *ctx;

    ctx = ngx_http_realip_get_module_ctx(r);

    addr_text = ctx ? &ctx->addr_text : &r->connection->addr_text;

    v->len = addr_text->len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = addr_text->data;

    return NGX_OK;
}


/**
 * $realip_remote_port 的get_handler
 * 
 * 获取的是 ctx->sockaddr 中的port (ctx保留了原始的c上的sockaddr)
 */
static ngx_int_t
ngx_http_realip_remote_port_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_uint_t              port;
    struct sockaddr        *sa;
    ngx_http_realip_ctx_t  *ctx;

    ctx = ngx_http_realip_get_module_ctx(r);

    sa = ctx ? ctx->sockaddr : r->connection->sockaddr;

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = ngx_pnalloc(r->pool, sizeof("65535") - 1);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    port = ngx_inet_get_port(sa);

    if (port > 0 && port < 65536) {
        v->len = ngx_sprintf(v->data, "%ui", port) - v->data;
    }

    return NGX_OK;
}
