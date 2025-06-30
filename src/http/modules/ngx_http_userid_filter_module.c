
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_USERID_OFF   0
#define NGX_HTTP_USERID_LOG   1
#define NGX_HTTP_USERID_V1    2
#define NGX_HTTP_USERID_ON    3

#define NGX_HTTP_USERID_COOKIE_OFF              0x0002
#define NGX_HTTP_USERID_COOKIE_SECURE           0x0004
#define NGX_HTTP_USERID_COOKIE_HTTPONLY         0x0008
#define NGX_HTTP_USERID_COOKIE_SAMESITE         0x0010
#define NGX_HTTP_USERID_COOKIE_SAMESITE_STRICT  0x0020
#define NGX_HTTP_USERID_COOKIE_SAMESITE_LAX     0x0040
#define NGX_HTTP_USERID_COOKIE_SAMESITE_NONE    0x0080

/* 31 Dec 2037 23:55:55 GMT */
#define NGX_HTTP_USERID_MAX_EXPIRES  2145916555


/**
 * https://nginx.org/en/docs/http/ngx_http_userid_module.html
 * 
 * 浏览器第一次请求nginx的时候，nginx在响应时在http的响应头中插入一段唯一性的用来标识用户的user id的cookie代码，
 * 等到下一次浏览器继续请求nginx的时候，nginx将获得之前植入在cookie中的user id，从而可以在后续根据这个标识的user id，
 * 通过日志分析来分析用户的行为等等
 */
typedef struct {
    ngx_uint_t  enable;
    ngx_uint_t  flags;

    ngx_int_t   service;

    ngx_str_t   name;
    ngx_str_t   domain;
    ngx_str_t   path;
    ngx_str_t   p3p;

    time_t      expires;

    u_char      mark;
} ngx_http_userid_conf_t;


typedef struct {
    uint32_t    uid_got[4];
    uint32_t    uid_set[4];
    ngx_str_t   cookie;
    ngx_uint_t  reset;
} ngx_http_userid_ctx_t;


static ngx_http_userid_ctx_t *ngx_http_userid_get_uid(ngx_http_request_t *r,
    ngx_http_userid_conf_t *conf);
static ngx_int_t ngx_http_userid_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_str_t *name, uint32_t *uid);
static ngx_int_t ngx_http_userid_set_uid(ngx_http_request_t *r,
    ngx_http_userid_ctx_t *ctx, ngx_http_userid_conf_t *conf);
static ngx_int_t ngx_http_userid_create_uid(ngx_http_request_t *r,
    ngx_http_userid_ctx_t *ctx, ngx_http_userid_conf_t *conf);

static ngx_int_t ngx_http_userid_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_userid_init(ngx_conf_t *cf);
static void *ngx_http_userid_create_conf(ngx_conf_t *cf);
static char *ngx_http_userid_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_userid_domain(ngx_conf_t *cf, void *post, void *data);
static char *ngx_http_userid_path(ngx_conf_t *cf, void *post, void *data);
static char *ngx_http_userid_expires(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_userid_p3p(ngx_conf_t *cf, void *post, void *data);
static char *ngx_http_userid_mark(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_userid_init_worker(ngx_cycle_t *cycle);



static uint32_t  start_value;
static uint32_t  sequencer_v1 = 1;
static uint32_t  sequencer_v2 = 0x03030302;


static u_char expires[] = "; expires=Thu, 31-Dec-37 23:55:55 GMT";


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;


static ngx_conf_enum_t  ngx_http_userid_state[] = {
    { ngx_string("off"), NGX_HTTP_USERID_OFF },
    { ngx_string("log"), NGX_HTTP_USERID_LOG },
    { ngx_string("v1"), NGX_HTTP_USERID_V1 },
    { ngx_string("on"), NGX_HTTP_USERID_ON },
    { ngx_null_string, 0 }
};


static ngx_conf_bitmask_t  ngx_http_userid_flags[] = {
    { ngx_string("off"), NGX_HTTP_USERID_COOKIE_OFF },
    { ngx_string("secure"), NGX_HTTP_USERID_COOKIE_SECURE },
    { ngx_string("httponly"), NGX_HTTP_USERID_COOKIE_HTTPONLY },
    { ngx_string("samesite=strict"),
      NGX_HTTP_USERID_COOKIE_SAMESITE|NGX_HTTP_USERID_COOKIE_SAMESITE_STRICT },
    { ngx_string("samesite=lax"),
      NGX_HTTP_USERID_COOKIE_SAMESITE|NGX_HTTP_USERID_COOKIE_SAMESITE_LAX },
    { ngx_string("samesite=none"),
      NGX_HTTP_USERID_COOKIE_SAMESITE|NGX_HTTP_USERID_COOKIE_SAMESITE_NONE },
    { ngx_null_string, 0 }
};


static ngx_conf_post_handler_pt  ngx_http_userid_domain_p =
    ngx_http_userid_domain;
static ngx_conf_post_handler_pt  ngx_http_userid_path_p = ngx_http_userid_path;
static ngx_conf_post_handler_pt  ngx_http_userid_p3p_p = ngx_http_userid_p3p;


static ngx_command_t  ngx_http_userid_commands[] = {

    /**
     * on: 开启设置v2版本的cookie， 对于接收到的对应cookie会进行日志记录。
     * v1: 开启设置v1版本的cookie，对于接收到的对应cookie会进行日志记录。
     * log: 关闭设置cookie功能，但是对于接收到的对应cookie会进行日志记录。
     * off: 关闭userid模块功能。
     */
    { ngx_string("userid"),     //开启userid 模块
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_userid_conf_t, enable),
      ngx_http_userid_state },

    /**
     * 	userid_service number;
     * 定义每台nginx server自己的标识来确保在多台nginx的集群环境中生成的客户端userid的唯一性
     * 如果user id是由多台nginx服务器生成的，那么每台nginx server最好都设置自己的标识来确保生成的客户端user id是唯一的。
      对于v1版本的cookie，默认值是0；而对于v2版本的cookie，默认值是服务器IP地址的最后四个8位字节的数字
     */ 
    { ngx_string("userid_service"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_userid_conf_t, service),
      NULL },

    /**
     * 设置nginx响应的时候cookie的名字，或者nginx接收到用户请求的时候通过这个设置的cookie的名字来获取用户的ID
     */
    { ngx_string("userid_name"),    //  设置将在用户浏览器中植入的cookie的字段名
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_userid_conf_t, name),
      NULL },

    { ngx_string("userid_domain"),  // 设置在哪个域名下进行设置cookie
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_userid_conf_t, domain),
      &ngx_http_userid_domain_p },

    { ngx_string("userid_path"),    //设置在哪个路径下设置cookie。
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_userid_conf_t, path),
      &ngx_http_userid_path_p },

    /**
     * time: 超时的时长，单位可以是s,m,d,w,M,y
     *  max: 设置超时时间为“31 Dec 2037 23:55:55 GMT”.
     *  off: 设置cookie在浏览器关闭之后立即实效。
     */
    { ngx_string("userid_expires"), //cookie的生效时间。
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_userid_expires,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /**
     * 为cookie设置附加的标记。
     * 
     * off: 不添加附加标记。
     * secure: 设置本属性可以加强cookie的安全性，浏览器只有在https请求中才会发送该cookie。
     * httponly: 设置本属性避免浏览器的javascript访问这个cookie值。
     * samesite=strict: 浏览器只有在对cookie的源站点进行请求的时候才会发送该cookie。
     * samesite=lax: “Lax"和"strict” 是类似的，但是浏览器在用户访问 cookie 的源站点时（即使用户从不同的站点进入），
     *               也会发送该 cookie。例如，通过从外部站点跟随链接。
     * samesite=none: “none” 指定了在源站点和跨站请求中都发送 cookie，但仅在安全上下文中（即，如果 samesite=none，
     *                则还必须设置 secure 属性）。
     * 
     * 如果没有设置 SameSite 属性，则 cookie 被视为 Lax。
     */
    { ngx_string("userid_flags"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_userid_conf_t, flags),
      &ngx_http_userid_flags },

    /**
     * p3p: Platform for Privacy Preferences
     * 通过设置正确的 userid_p3p 参数， 可以提供网站的隐私政策通知，增加用户对于隐私保护的信任，并确保网站在不同环境中的兼容性
     * 
     * userid_p3p 参数允许您指定一个 P3P 策略标记，该标记将与生成的 Cookie 一起发送给客户端。这样，客户端在接收 Cookie 时可以查看该策略标记，并了解有关网站的隐私偏好和数据处理的信息。
     * P3P 是一种隐私策略框架，旨在帮助网站向用户传达其隐私政策和数据收集行为。它使用特定的标记语言，允许网站提供有关其隐私偏好的信息，并让用户能够了解和控制其个人数据的使用方式。
     * P3P 策略标记使用特定的语法和字段，描述网站的隐私偏好和数据收集实践。例如，它可以包含有关数据收集目的、数据使用方式、数据披露和共享等方面的信息。
     * 
     * */  
    { ngx_string("userid_p3p"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_userid_conf_t, p3p),
      &ngx_http_userid_p3p_p },

    /**
     * 如果参数不是off，则启用cookie标记机制并设置用作标记的字符。
     * 此机制用于在保留客户端标识符的同时添加或更改userid_p3p和/或cookie过期时间。
     * 标记可以是英文字母（区分大小写），数字或“ =”字符的任何字母。
     * 
     * 如果标记已设置，则将其与在cookie中传递的客户机标识的base64表示形式中的第一个填充符号进行比较。
     * 如果它们不匹配，则Cookie会重新发送指定的标记，到期时间和“P3P”标题。
     */
    { ngx_string("userid_mark"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_userid_mark,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_userid_filter_module_ctx = {
    ngx_http_userid_add_variables,         /* preconfiguration */
    ngx_http_userid_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_userid_create_conf,           /* create location configuration */
    ngx_http_userid_merge_conf             /* merge location configuration */
};


ngx_module_t  ngx_http_userid_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_userid_filter_module_ctx,    /* module context */
    ngx_http_userid_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_userid_init_worker,           /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t   ngx_http_userid_got = ngx_string("uid_got");
static ngx_str_t   ngx_http_userid_set = ngx_string("uid_set");
static ngx_str_t   ngx_http_userid_reset = ngx_string("uid_reset");
static ngx_uint_t  ngx_http_userid_reset_index;


static ngx_int_t
ngx_http_userid_filter(ngx_http_request_t *r)
{
    ngx_http_userid_ctx_t   *ctx;
    ngx_http_userid_conf_t  *conf;

    if (r != r->main) {
        return ngx_http_next_header_filter(r);
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_userid_filter_module);

    if (conf->enable < NGX_HTTP_USERID_V1) {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_http_userid_get_uid(r, conf);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ngx_http_userid_set_uid(r, ctx, conf) == NGX_OK) {
        return ngx_http_next_header_filter(r);
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_userid_got_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_userid_ctx_t   *ctx;
    ngx_http_userid_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r->main, ngx_http_userid_filter_module);

    if (conf->enable == NGX_HTTP_USERID_OFF) {
        v->not_found = 1;
        return NGX_OK;
    }

    ctx = ngx_http_userid_get_uid(r->main, conf);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ctx->uid_got[3] != 0) {
        return ngx_http_userid_variable(r->main, v, &conf->name, ctx->uid_got);
    }

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_userid_set_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_userid_ctx_t   *ctx;
    ngx_http_userid_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r->main, ngx_http_userid_filter_module);

    if (conf->enable < NGX_HTTP_USERID_V1) {
        v->not_found = 1;
        return NGX_OK;
    }

    ctx = ngx_http_userid_get_uid(r->main, conf);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ngx_http_userid_create_uid(r->main, ctx, conf) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ctx->uid_set[3] == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    return ngx_http_userid_variable(r->main, v, &conf->name, ctx->uid_set);
}


static ngx_http_userid_ctx_t *
ngx_http_userid_get_uid(ngx_http_request_t *r, ngx_http_userid_conf_t *conf)
{
    ngx_str_t               src, dst;
    ngx_table_elt_t        *cookie;
    ngx_http_userid_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_userid_filter_module);

    if (ctx) {
        return ctx;
    }

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_userid_ctx_t));
        if (ctx == NULL) {
            return NULL;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_userid_filter_module);
    }

    cookie = ngx_http_parse_multi_header_lines(r, r->headers_in.cookie,
                                               &conf->name, &ctx->cookie);
    if (cookie == NULL) {
        return ctx;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "uid cookie: \"%V\"", &ctx->cookie);

    if (ctx->cookie.len < 22) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "client sent too short userid cookie \"%V\"",
                      &cookie->value);
        return ctx;
    }

    src = ctx->cookie;

    /*
     * we have to limit the encoded string to 22 characters because
     *  1) cookie may be marked by "userid_mark",
     *  2) and there are already the millions cookies with a garbage
     *     instead of the correct base64 trail "=="
     */

    src.len = 22;

    dst.data = (u_char *) ctx->uid_got;

    if (ngx_decode_base64(&dst, &src) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "client sent invalid userid cookie \"%V\"",
                      &cookie->value);
        return ctx;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "uid: %08XD%08XD%08XD%08XD",
                   ctx->uid_got[0], ctx->uid_got[1],
                   ctx->uid_got[2], ctx->uid_got[3]);

    return ctx;
}


static ngx_int_t
ngx_http_userid_set_uid(ngx_http_request_t *r, ngx_http_userid_ctx_t *ctx,
    ngx_http_userid_conf_t *conf)
{
    u_char           *cookie, *p;
    size_t            len;
    ngx_str_t         src, dst;
    ngx_table_elt_t  *set_cookie, *p3p;

    if (ngx_http_userid_create_uid(r, ctx, conf) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ctx->uid_set[3] == 0) {
        return NGX_OK;
    }

    len = conf->name.len + 1 + ngx_base64_encoded_length(16) + conf->path.len;

    if (conf->expires) {
        len += sizeof(expires) - 1 + 2;
    }

    if (conf->domain.len) {
        len += conf->domain.len;
    }

    if (conf->flags & NGX_HTTP_USERID_COOKIE_SECURE) {
        len += sizeof("; secure") - 1;
    }

    if (conf->flags & NGX_HTTP_USERID_COOKIE_HTTPONLY) {
        len += sizeof("; httponly") - 1;
    }

    if (conf->flags & NGX_HTTP_USERID_COOKIE_SAMESITE_STRICT) {
        len += sizeof("; samesite=strict") - 1;
    }

    if (conf->flags & NGX_HTTP_USERID_COOKIE_SAMESITE_LAX) {
        len += sizeof("; samesite=lax") - 1;
    }

    if (conf->flags & NGX_HTTP_USERID_COOKIE_SAMESITE_NONE) {
        len += sizeof("; samesite=none") - 1;
    }

    cookie = ngx_pnalloc(r->pool, len);
    if (cookie == NULL) {
        return NGX_ERROR;
    }

    p = ngx_copy(cookie, conf->name.data, conf->name.len);
    *p++ = '=';

    if (ctx->uid_got[3] == 0 || ctx->reset) {
        src.len = 16;
        src.data = (u_char *) ctx->uid_set;
        dst.data = p;

        ngx_encode_base64(&dst, &src);

        p += dst.len;

        if (conf->mark) {
            *(p - 2) = conf->mark;
        }

    } else {
        p = ngx_cpymem(p, ctx->cookie.data, 22);
        *p++ = conf->mark;
        *p++ = '=';
    }

    if (conf->expires == NGX_HTTP_USERID_MAX_EXPIRES) {
        p = ngx_cpymem(p, expires, sizeof(expires) - 1);

    } else if (conf->expires) {
        p = ngx_cpymem(p, expires, sizeof("; expires=") - 1);
        p = ngx_http_cookie_time(p, ngx_time() + conf->expires);
    }

    p = ngx_copy(p, conf->domain.data, conf->domain.len);

    p = ngx_copy(p, conf->path.data, conf->path.len);

    if (conf->flags & NGX_HTTP_USERID_COOKIE_SECURE) {
        p = ngx_cpymem(p, "; secure", sizeof("; secure") - 1);
    }

    if (conf->flags & NGX_HTTP_USERID_COOKIE_HTTPONLY) {
        p = ngx_cpymem(p, "; httponly", sizeof("; httponly") - 1);
    }

    if (conf->flags & NGX_HTTP_USERID_COOKIE_SAMESITE_STRICT) {
        p = ngx_cpymem(p, "; samesite=strict", sizeof("; samesite=strict") - 1);
    }

    if (conf->flags & NGX_HTTP_USERID_COOKIE_SAMESITE_LAX) {
        p = ngx_cpymem(p, "; samesite=lax", sizeof("; samesite=lax") - 1);
    }

    if (conf->flags & NGX_HTTP_USERID_COOKIE_SAMESITE_NONE) {
        p = ngx_cpymem(p, "; samesite=none", sizeof("; samesite=none") - 1);
    }

    set_cookie = ngx_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        return NGX_ERROR;
    }

    set_cookie->hash = 1;
    ngx_str_set(&set_cookie->key, "Set-Cookie");
    set_cookie->value.len = p - cookie;
    set_cookie->value.data = cookie;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "uid cookie: \"%V\"", &set_cookie->value);

    if (conf->p3p.len == 0) {
        return NGX_OK;
    }

    p3p = ngx_list_push(&r->headers_out.headers);
    if (p3p == NULL) {
        return NGX_ERROR;
    }

    p3p->hash = 1;
    ngx_str_set(&p3p->key, "P3P");
    p3p->value = conf->p3p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_userid_create_uid(ngx_http_request_t *r, ngx_http_userid_ctx_t *ctx,
    ngx_http_userid_conf_t *conf)
{
    ngx_connection_t           *c;
    struct sockaddr_in         *sin;
    ngx_http_variable_value_t  *vv;
#if (NGX_HAVE_INET6)
    u_char                     *p;
    struct sockaddr_in6        *sin6;
#endif

    if (ctx->uid_set[3] != 0) {
        return NGX_OK;
    }

    if (ctx->uid_got[3] != 0) {

        vv = ngx_http_get_indexed_variable(r, ngx_http_userid_reset_index);

        if (vv == NULL || vv->not_found) {
            return NGX_ERROR;
        }

        if (vv->len == 0 || (vv->len == 1 && vv->data[0] == '0')) {

            if (conf->mark == '\0'
                || (ctx->cookie.len > 23
                    && ctx->cookie.data[22] == conf->mark
                    && ctx->cookie.data[23] == '='))
            {
                return NGX_OK;
            }

            ctx->uid_set[0] = ctx->uid_got[0];
            ctx->uid_set[1] = ctx->uid_got[1];
            ctx->uid_set[2] = ctx->uid_got[2];
            ctx->uid_set[3] = ctx->uid_got[3];

            return NGX_OK;

        } else {
            ctx->reset = 1;

            if (vv->len == 3 && ngx_strncmp(vv->data, "log", 3) == 0) {
                ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                        "userid cookie \"%V=%08XD%08XD%08XD%08XD\" was reset",
                        &conf->name, ctx->uid_got[0], ctx->uid_got[1],
                        ctx->uid_got[2], ctx->uid_got[3]);
            }
        }
    }

    /*
     * TODO: in the threaded mode the sequencers should be in TLS and their
     * ranges should be divided between threads
     */

    if (conf->enable == NGX_HTTP_USERID_V1) {
        if (conf->service == NGX_CONF_UNSET) {
            ctx->uid_set[0] = 0;
        } else {
            ctx->uid_set[0] = conf->service;
        }
        ctx->uid_set[1] = (uint32_t) ngx_time();
        ctx->uid_set[2] = start_value;
        ctx->uid_set[3] = sequencer_v1;
        sequencer_v1 += 0x100;

    } else {
        if (conf->service == NGX_CONF_UNSET) {

            c = r->connection;

            if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
                return NGX_ERROR;
            }

            switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
            case AF_INET6:
                sin6 = (struct sockaddr_in6 *) c->local_sockaddr;

                p = (u_char *) &ctx->uid_set[0];

                *p++ = sin6->sin6_addr.s6_addr[12];
                *p++ = sin6->sin6_addr.s6_addr[13];
                *p++ = sin6->sin6_addr.s6_addr[14];
                *p = sin6->sin6_addr.s6_addr[15];

                break;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
            case AF_UNIX:
                ctx->uid_set[0] = 0;
                break;
#endif

            default: /* AF_INET */
                sin = (struct sockaddr_in *) c->local_sockaddr;
                ctx->uid_set[0] = sin->sin_addr.s_addr;
                break;
            }

        } else {
            ctx->uid_set[0] = htonl(conf->service);
        }

        ctx->uid_set[1] = htonl((uint32_t) ngx_time());
        ctx->uid_set[2] = htonl(start_value);
        ctx->uid_set[3] = htonl(sequencer_v2);
        sequencer_v2 += 0x100;
        if (sequencer_v2 < 0x03030302) {
            sequencer_v2 = 0x03030302;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_userid_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    ngx_str_t *name, uint32_t *uid)
{
    v->len = name->len + sizeof("=00001111222233334444555566667777") - 1;
    v->data = ngx_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    ngx_sprintf(v->data, "%V=%08XD%08XD%08XD%08XD",
                name, uid[0], uid[1], uid[2], uid[3]);

    return NGX_OK;
}


static ngx_int_t
ngx_http_userid_reset_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    *v = ngx_http_variable_null_value;

    return NGX_OK;
}


/**
 * 注册变量
 */
static ngx_int_t
ngx_http_userid_add_variables(ngx_conf_t *cf)
{
    ngx_int_t             n;
    ngx_http_variable_t  *var;

    var = ngx_http_add_variable(cf, &ngx_http_userid_got, 0);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_userid_got_variable;

    var = ngx_http_add_variable(cf, &ngx_http_userid_set, 0);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_userid_set_variable;

    var = ngx_http_add_variable(cf, &ngx_http_userid_reset,
                                NGX_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_userid_reset_variable;

    n = ngx_http_get_variable_index(cf, &ngx_http_userid_reset);
    if (n == NGX_ERROR) {
        return NGX_ERROR;
    }

    ngx_http_userid_reset_index = n;

    return NGX_OK;
}


static void *
ngx_http_userid_create_conf(ngx_conf_t *cf)
{
    ngx_http_userid_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_userid_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->flags = 0;
     *     conf->name = { 0, NULL };
     *     conf->domain = { 0, NULL };
     *     conf->path = { 0, NULL };
     *     conf->p3p = { 0, NULL };
     */

    conf->enable = NGX_CONF_UNSET_UINT;
    conf->service = NGX_CONF_UNSET;
    conf->expires = NGX_CONF_UNSET;
    conf->mark = (u_char) '\xFF';

    return conf;
}


static char *
ngx_http_userid_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_userid_conf_t *prev = parent;
    ngx_http_userid_conf_t *conf = child;

    ngx_conf_merge_uint_value(conf->enable, prev->enable,
                              NGX_HTTP_USERID_OFF);

    ngx_conf_merge_bitmask_value(conf->flags, prev->flags,
                            (NGX_CONF_BITMASK_SET|NGX_HTTP_USERID_COOKIE_OFF));

    ngx_conf_merge_str_value(conf->name, prev->name, "uid");
    ngx_conf_merge_str_value(conf->domain, prev->domain, "");
    ngx_conf_merge_str_value(conf->path, prev->path, "; path=/");
    ngx_conf_merge_str_value(conf->p3p, prev->p3p, "");

    ngx_conf_merge_value(conf->service, prev->service, NGX_CONF_UNSET);
    ngx_conf_merge_sec_value(conf->expires, prev->expires, 0);

    if (conf->mark == (u_char) '\xFF') {
        if (prev->mark == (u_char) '\xFF') {
            conf->mark = '\0';
        } else {
            conf->mark = prev->mark;
        }
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_userid_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_userid_filter;

    return NGX_OK;
}


static char *
ngx_http_userid_domain(ngx_conf_t *cf, void *post, void *data)
{
    ngx_str_t  *domain = data;

    u_char  *p, *new;

    if (ngx_strcmp(domain->data, "none") == 0) {
        ngx_str_set(domain, "");
        return NGX_CONF_OK;
    }

    new = ngx_pnalloc(cf->pool, sizeof("; domain=") - 1 + domain->len);
    if (new == NULL) {
        return NGX_CONF_ERROR;
    }

    p = ngx_cpymem(new, "; domain=", sizeof("; domain=") - 1);
    ngx_memcpy(p, domain->data, domain->len);

    domain->len += sizeof("; domain=") - 1;
    domain->data = new;

    return NGX_CONF_OK;
}


static char *
ngx_http_userid_path(ngx_conf_t *cf, void *post, void *data)
{
    ngx_str_t  *path = data;

    u_char  *p, *new;

    new = ngx_pnalloc(cf->pool, sizeof("; path=") - 1 + path->len);
    if (new == NULL) {
        return NGX_CONF_ERROR;
    }

    p = ngx_cpymem(new, "; path=", sizeof("; path=") - 1);
    ngx_memcpy(p, path->data, path->len);

    path->len += sizeof("; path=") - 1;
    path->data = new;

    return NGX_CONF_OK;
}


static char *
ngx_http_userid_expires(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_userid_conf_t *ucf = conf;

    ngx_str_t  *value;

    if (ucf->expires != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "max") == 0) {
        ucf->expires = NGX_HTTP_USERID_MAX_EXPIRES;
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[1].data, "off") == 0) {
        ucf->expires = 0;
        return NGX_CONF_OK;
    }

    ucf->expires = ngx_parse_time(&value[1], 1);
    if (ucf->expires == (time_t) NGX_ERROR) {
        return "invalid value";
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_userid_p3p(ngx_conf_t *cf, void *post, void *data)
{
    ngx_str_t  *p3p = data;

    if (ngx_strcmp(p3p->data, "none") == 0) {
        ngx_str_set(p3p, "");
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_userid_mark(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_userid_conf_t *ucf = conf;

    ngx_str_t  *value;

    if (ucf->mark != (u_char) '\xFF') {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        ucf->mark = '\0';
        return NGX_CONF_OK;
    }

    if (value[1].len != 1
        || !((value[1].data[0] >= '0' && value[1].data[0] <= '9')
              || (value[1].data[0] >= 'A' && value[1].data[0] <= 'Z')
              || (value[1].data[0] >= 'a' && value[1].data[0] <= 'z')
              || value[1].data[0] == '='))
    {
        return "value must be \"off\" or a single letter, digit or \"=\"";
    }

    ucf->mark = value[1].data[0];

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_userid_init_worker(ngx_cycle_t *cycle)
{
    struct timeval  tp;

    ngx_gettimeofday(&tp);

    /* use the most significant usec part that fits to 16 bits */
    start_value = (((uint32_t) tp.tv_usec / 20) << 16) | ngx_pid;

    return NGX_OK;
}
