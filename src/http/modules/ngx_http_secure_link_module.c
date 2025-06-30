
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>


/**
 * https://nginx.org/en/docs/http/ngx_http_secure_link_module.html
 * 
 * 用于对url进行验签并限制url的有效期。
 * 
 * url有效期由url生成时指定，参与签名的计算
 * 
 * 模块提供两个变量：
 *  $secure_link: "" 表示验签失败，"0" 表示url已经过期
 *  $secure_link_expires 链接过期时间，从args参数中获取
 * 
 *  secure_link $arg_md5,$arg_expires;
    secure_link_md5 "$secure_link_expires$uri$remote_addr secret";
 * 
 */


 /**
  * 本模块loc级别配置
  */
typedef struct {
    ngx_http_complex_value_t  *variable;        //secure_link $arg_md5,$arg_expires; 第一个参数编译出来的复杂变量
    //第一个参数编译出来的负载变量
    ngx_http_complex_value_t  *md5;             //secure_link_md5 "$secure_link_expires$uri$remote_addr secret";
    ngx_str_t                  secret;          //secure_link_secret word; 配置的word
} ngx_http_secure_link_conf_t;


/**
 * 模块的上下文结构体
 */
typedef struct {
    ngx_str_t                  expires;     //链接过期时间
} ngx_http_secure_link_ctx_t;


static ngx_int_t ngx_http_secure_link_old_variable(ngx_http_request_t *r,
    ngx_http_secure_link_conf_t *conf, ngx_http_variable_value_t *v,
    uintptr_t data);
static ngx_int_t ngx_http_secure_link_expires_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void *ngx_http_secure_link_create_conf(ngx_conf_t *cf);
static char *ngx_http_secure_link_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_secure_link_add_variables(ngx_conf_t *cf);


static ngx_command_t  ngx_http_secure_link_commands[] = {

    { ngx_string("secure_link"),      //配置格式 secure_link $arg_md5,$arg_expires;  
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,      //是一个复杂变量
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_secure_link_conf_t, variable),
      NULL },

    { ngx_string("secure_link_md5"),       //配置格式 secure_link_md5 "$secure_link_expires$uri$remote_addr secret"; 
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,    //是一个复杂变量
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_secure_link_conf_t, md5),   
      NULL },

    { ngx_string("secure_link_secret"),     //秘钥模式
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,                //ngx_str_t
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_secure_link_conf_t, secret),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_secure_link_module_ctx = {
    ngx_http_secure_link_add_variables,    /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_secure_link_create_conf,      /* create location configuration */
    ngx_http_secure_link_merge_conf        /* merge location configuration */
};


ngx_module_t  ngx_http_secure_link_module = {
    NGX_MODULE_V1,
    &ngx_http_secure_link_module_ctx,      /* module context */
    ngx_http_secure_link_commands,         /* module directives */
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
 * 本模块提供的连个变量
 */
//$secure_link: "" 表示验签失败，"0" 表示url已经过期
static ngx_str_t  ngx_http_secure_link_name = ngx_string("secure_link");
//$secure_link_expires 链接过期时间，从args参数中获取
static ngx_str_t  ngx_http_secure_link_expires_name =
    ngx_string("secure_link_expires");


/**
 * 变量$secure_link的get_handler
 */
static ngx_int_t
ngx_http_secure_link_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                       *p, *last;
    ngx_str_t                     val, hash;
    time_t                        expires;
    ngx_md5_t                     md5;
    ngx_http_secure_link_ctx_t   *ctx;
    ngx_http_secure_link_conf_t  *conf;
    u_char                        hash_buf[18], md5_buf[16];

    //获取loc配置
    conf = ngx_http_get_module_loc_conf(r, ngx_http_secure_link_module);

    //如果配置是的有secret的模式
    if (conf->secret.data) {
        return ngx_http_secure_link_old_variable(r, conf, v, data);
    }

    // secure_link_md5 模式
    /**
     * secure_link $arg_md5,$arg_expires;
        secure_link_md5 "$secure_link_expires$uri$remote_addr secret";
     */

    if (conf->variable == NULL || conf->md5 == NULL) {
        goto not_found;
    }

    //计算secure_link 配置的值
    if (ngx_http_complex_value(r, conf->variable, &val) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "secure link: \"%V\"", &val);

    last = val.data + val.len;

    //, 分割
    p = ngx_strlchr(val.data, last, ',');
    expires = 0;

    //解析过期时间 expires
    if (p) {
        //更新val长度
        val.len = p++ - val.data;

        //url过期时间
        expires = ngx_atotm(p, last - p);
        if (expires <= 0) {
            goto not_found;
        }

        //分配上下文结构体，里边只有一个expires字段
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_secure_link_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        //设置上下文结构体
        ngx_http_set_ctx(r, ctx, ngx_http_secure_link_module);

        ctx->expires.len = last - p;
        ctx->expires.data = p;
    }

    //val为 md5。16个字符baseEncode为24
    if (val.len > 24) {
        goto not_found;
    }

    //hash为解码出来的md5
    hash.data = hash_buf;

    //base64Decode
    if (ngx_decode_base64url(&hash, &val) != NGX_OK) {
        goto not_found;
    }

    //长度不合法
    if (hash.len != 16) {
        goto not_found;
    }

    //计算复杂变量值。 secure_link_md5 "$secure_link_expires$uri$remote_addr secret"
    if (ngx_http_complex_value(r, conf->md5, &val) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "secure link md5: \"%V\"", &val);

    //计算md5值
    ngx_md5_init(&md5);
    ngx_md5_update(&md5, val.data, val.len);
    ngx_md5_final(md5_buf, &md5);

    //比较md5值是否一致
    if (ngx_memcmp(hash_buf, md5_buf, 16) != 0) {
        goto not_found;
    }

    //将expire与当前时间进行比较，url是否过期
    v->data = (u_char *) ((expires && expires < ngx_time()) ? "0" : "1");
    v->len = 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;

not_found:

    v->not_found = 1;

    return NGX_OK;
}


/**
 * secure_link_secret 模式
 * 
 * url格式 /prefix/hash/link
 * 其中hash是由 link+secret的hash值
 */
static ngx_int_t
ngx_http_secure_link_old_variable(ngx_http_request_t *r,
    ngx_http_secure_link_conf_t *conf, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    u_char      *p, *start, *end, *last;
    size_t       len;
    ngx_int_t    n;
    ngx_uint_t   i;
    ngx_md5_t    md5;
    u_char       hash[16];

    //从第二个字符开始
    p = &r->unparsed_uri.data[1];
    last = r->unparsed_uri.data + r->unparsed_uri.len;

    //寻找第一个/
    //start记录md5开始位置
    while (p < last) {
        if (*p++ == '/') {
            start = p;
            goto md5_start;
        }
    }

    goto not_found;

    //找到了md5开始的位置
md5_start:

    //end记录md5结束位置
    while (p < last) {
        if (*p++ == '/') {
            end = p - 1;
            goto url_start;
        }
    }

    goto not_found;

    //找到url的位置
url_start:

    //start记录md5开始位置
    //end记录md5结束位置
    //last-p 为link的长度
    //p 为link开始的位置
    len = last - p;

    if (end - start != 32 || len == 0) {
        goto not_found;
    }

    ngx_md5_init(&md5);     //初始化md5
    ngx_md5_update(&md5, p, len);  //md5(link)
    ngx_md5_update(&md5, conf->secret.data, conf->secret.len);  //md5(secret)
    ngx_md5_final(hash, &md5);  //计算最终的md5值

    //16进制
    //计算出来的hash和url里的start开始的hash进行比较
    for (i = 0; i < 16; i++) {
        n = ngx_hextoi(&start[2 * i], 2);
        if (n == NGX_ERROR || n != hash[i]) {
            goto not_found;
        }
    }

    //验证通过
    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;        //p为link的起始位置 char *p

    return NGX_OK;

not_found:

    v->not_found = 1;

    return NGX_OK;
}


/**
 * $secure_link_expires的get_handler
 */
static ngx_int_t
ngx_http_secure_link_expires_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_secure_link_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_secure_link_module);

    if (ctx) {
        v->len = ctx->expires.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = ctx->expires.data;

    } else {
        v->not_found = 1;
    }

    return NGX_OK;
}


/**
 * 创建loc级别配置结构体
 */
static void *
ngx_http_secure_link_create_conf(ngx_conf_t *cf)
{
    ngx_http_secure_link_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_secure_link_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->secret = { 0, NULL };
     */

    conf->variable = NGX_CONF_UNSET_PTR;
    conf->md5 = NGX_CONF_UNSET_PTR;

    return conf;
}


/**
 * 合并loc级别配置结构体
 */
static char *
ngx_http_secure_link_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_secure_link_conf_t *prev = parent;
    ngx_http_secure_link_conf_t *conf = child;

    if (conf->secret.data) {
        ngx_conf_init_ptr_value(conf->variable, NULL);
        ngx_conf_init_ptr_value(conf->md5, NULL);

        //不能两种模式混用
        if (conf->variable || conf->md5) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"secure_link_secret\" cannot be mixed with "
                               "\"secure_link\" and \"secure_link_md5\"");
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
    }

    ngx_conf_merge_ptr_value(conf->variable, prev->variable, NULL);
    ngx_conf_merge_ptr_value(conf->md5, prev->md5, NULL);

    if (conf->variable == NULL && conf->md5 == NULL) {
        conf->secret = prev->secret;
    }

    return NGX_CONF_OK;
}


/**
 * 注册变量
 */
static ngx_int_t
ngx_http_secure_link_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var;

    //$secure_link
    var = ngx_http_add_variable(cf, &ngx_http_secure_link_name, 0);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_secure_link_variable;

    //$secure_link_expires
    var = ngx_http_add_variable(cf, &ngx_http_secure_link_expires_name, 0);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_secure_link_expires_variable;

    return NGX_OK;
}
