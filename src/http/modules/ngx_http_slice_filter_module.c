
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/**
 * https://nginx.org/en/docs/http/ngx_http_slice_module.html
 * 
 * 将一个请求分解成多个子请求，每个子请求返回响应内容的一个片段，让大文件的缓存更有效率
 * 
 * 
 * HTTP 客户端下载文件时，如果发生了网络中断，必须重新向服务器发起 HTTP 请求，这时客户端已经有了文件的一部分，
 * 只需要请求剩余的内容，而不需要传输整个文件，Range 请求就可以用来处理这种问题。如果 HTTP 请求的头部有 Range 字段，
 * 如下：Range: bytes=1024-2047 表示客户端请求文件的第 1025 到第 2048 个字节，
 * 这时服务器只会响应文件的这部分内容，响应的状态码为206，表示返回的是响应的一部分。
 * 如果服务器不支持 Range 请求，仍然会返回整个文件，这时状态码仍是 200。
 * 
 * 
 * 默认不启用
 * 
 * 
 * location / {
    slice             1m;
    proxy_cache       cache;
    proxy_cache_key   $uri$is_args$args$slice_range;
    proxy_set_header  Range $slice_range;
    proxy_cache_valid 200 206 1h;
    proxy_pass        http://localhost:8000;
  }


    客户端请求100个字节，起始于150，请求内容的范围是150-249。发到 nginx 之后根据 slice 配置，比如配置为 100，
    那么就是 0-100，100-200，200-300，这样就分为了3块，但是最终这个文件有多大就切分为多少块。之后nginx就会构造两个请求，
    第一个请求时 100-199，然后第二个请求时 200-300 的。这两个请求返回之后会生成两个文件，第一个100-199，200-299。
    然后将其组合起来生成客户端要的 150-249 这样一个响应。

 * 
 */

 /**
  * 本模块配置结构体
  */
typedef struct {
    size_t               size;  //slice size; 切片大小
} ngx_http_slice_loc_conf_t;


/**
 * 模块自定义上下文
 */
typedef struct {
    off_t                start;     //rang请求头 start根据slice取整
    off_t                end;
    ngx_str_t            range;     //根据slice配置调整过的请求头
    ngx_str_t            etag;
    unsigned             last:1;    //标识当前是最后一个buf
    unsigned             active:1;
    ngx_http_request_t  *sr;        //子请求
} ngx_http_slice_ctx_t;


/**
 * 表示content_range响应头。 表示部分消息在完整消息中的位置。
 * content_range格式： Content-Range: <unit> <range-start>-<range-end>/<size>
 * 
 * 如：Content-Range: bytes 200-1000/67589
 */
typedef struct {
    off_t                start;                 //range start
    off_t                end;                   //range end
    off_t                complete_length;       //文件总长度
} ngx_http_slice_content_range_t;


static ngx_int_t ngx_http_slice_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_slice_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_slice_parse_content_range(ngx_http_request_t *r,
    ngx_http_slice_content_range_t *cr);
static ngx_int_t ngx_http_slice_range_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static off_t ngx_http_slice_get_start(ngx_http_request_t *r);
static void *ngx_http_slice_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_slice_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_slice_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_slice_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_slice_filter_commands[] = {

    { ngx_string("slice"),      //slice size; 配置切片大小
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_slice_loc_conf_t, size),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_slice_filter_module_ctx = {
    ngx_http_slice_add_variables,          /* preconfiguration */
    //注册header_filter和body_filter
    ngx_http_slice_init,                   /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_slice_create_loc_conf,        /* create location configuration */
    ngx_http_slice_merge_loc_conf          /* merge location configuration */
};


ngx_module_t  ngx_http_slice_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_slice_filter_module_ctx,     /* module context */
    ngx_http_slice_filter_commands,        /* module directives */
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
 * 提供的变量 $slice_range, get_handler为 ngx_http_slice_range_variable
 */
static ngx_str_t  ngx_http_slice_range_name = ngx_string("slice_range");

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


/**
 * header_filter 
 */
static ngx_int_t
ngx_http_slice_header_filter(ngx_http_request_t *r)
{
    off_t                            end;
    ngx_int_t                        rc;
    ngx_table_elt_t                 *h;
    ngx_http_slice_ctx_t            *ctx;
    ngx_http_slice_loc_conf_t       *slcf;
    ngx_http_slice_content_range_t   cr;

    //获取模块上下文结构体
    ctx = ngx_http_get_module_ctx(r, ngx_http_slice_filter_module);
    if (ctx == NULL) {
        return ngx_http_next_header_filter(r);
    }

    //如果响应码不是 206 PARTIAL_CONTENT
    if (r->headers_out.status != NGX_HTTP_PARTIAL_CONTENT) {
        if (r == r->main) {     //主请求
            //清空ctx
            ngx_http_set_ctx(r, NULL, ngx_http_slice_filter_module);
            return ngx_http_next_header_filter(r);
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "unexpected status code %ui in slice response",
                      r->headers_out.status);
        return NGX_ERROR;
    }

    h = r->headers_out.etag;

    if (ctx->etag.len) {
        if (h == NULL
            || h->value.len != ctx->etag.len
            || ngx_strncmp(h->value.data, ctx->etag.data, ctx->etag.len)
               != 0)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "etag mismatch in slice response");
            return NGX_ERROR;
        }
    }

    if (h) {
        ctx->etag = h->value;
    }

    //解析content_range响应头
    if (ngx_http_slice_parse_content_range(r, &cr) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "invalid range in slice response");
        return NGX_ERROR;
    }

    //表示文件总大小未知
    if (cr.complete_length == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "no complete length in slice response");
        return NGX_ERROR;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http slice response range: %O-%O/%O",
                   cr.start, cr.end, cr.complete_length);

    //获取模块配置               
    slcf = ngx_http_get_module_loc_conf(r, ngx_http_slice_filter_module);

    //计算range结束位置
    end = ngx_min(cr.start + (off_t) slcf->size, cr.complete_length);

    if (cr.start != ctx->start || cr.end != end) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "unexpected range in slice response: %O-%O, "
                      "expected: %O-%O", cr.start, cr.end, ctx->start, end);
        return NGX_ERROR;
    }

    ctx->start = end;
    ctx->active = 1;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.status_line.len = 0;
    r->headers_out.content_length_n = cr.complete_length;
    r->headers_out.content_offset = cr.start;
    r->headers_out.content_range->hash = 0;
    r->headers_out.content_range = NULL;

    if (r->headers_out.accept_ranges) {
        r->headers_out.accept_ranges->hash = 0;
        r->headers_out.accept_ranges = NULL;
    }

    r->allow_ranges = 1;
    r->subrequest_ranges = 1;
    r->single_range = 1;

    rc = ngx_http_next_header_filter(r);

    if (r != r->main) {
        return rc;
    }

    r->preserve_body = 1;

    if (r->headers_out.status == NGX_HTTP_PARTIAL_CONTENT) {
        if (ctx->start + (off_t) slcf->size <= r->headers_out.content_offset) {
            ctx->start = slcf->size
                         * (r->headers_out.content_offset / slcf->size);
        }

        ctx->end = r->headers_out.content_offset
                   + r->headers_out.content_length_n;

    } else {
        ctx->end = cr.complete_length;
    }

    return rc;
}


/**
 * 
 * body_filter
 * 
 * 客户端向 nginx 请求一个10M文件，nginx 进行 4m 的切片，整个过程如下：

    1.客户端向 nginx 请求 10M
    2.nginx 发起第一个切片（主请求）请求 range：0-4194303
    3.第一个切片（主请求）请求的内容全部发给客户端后，在 slice 模块的 body_filter 发起第二个切片（子请求），
      请求range: 4194304-8388607
    4.第二个切片（子请求）请求的内容完全发完給客户端后，切回主请求
    5.主请求在 slice 模块的 body_filter 发起第三个切片（子请求），请求 range: 8388608-12582911
    6.第三个切片（子请求）请求的内容（8388608-10485759）完全发完給客户端后，切回主请求
    7.主请求在 slice 模块的 body_filter 判断已经将 10M 的文件发給客户端，不再进行 slice 的模块处理
 */

static ngx_int_t
ngx_http_slice_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                   rc;
    ngx_chain_t                *cl;
    ngx_http_slice_ctx_t       *ctx;
    ngx_http_slice_loc_conf_t  *slcf;

    //获取模块上下文
    ctx = ngx_http_get_module_ctx(r, ngx_http_slice_filter_module);

    if (ctx == NULL || r != r->main) {              //非主请求
        return ngx_http_next_body_filter(r, in);
    }

    //找到最后一个buf
    for (cl = in; cl; cl = cl->next) {
        if (cl->buf->last_buf) {
            cl->buf->last_buf = 0;      //重置last_buf
            cl->buf->last_in_chain = 1;
            cl->buf->sync = 1;
            ctx->last = 1;
        }
    }

    rc = ngx_http_next_body_filter(r, in);

    if (rc == NGX_ERROR || !ctx->last) {
        return rc;
    }

    //是最后一个buf
    if (ctx->sr && !ctx->sr->done) {
        return rc;
    }

    if (!ctx->active) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "missing slice response");
        return NGX_ERROR;
    }

    if (ctx->start >= ctx->end) {
        ngx_http_set_ctx(r, NULL, ngx_http_slice_filter_module);
        ngx_http_send_special(r, NGX_HTTP_LAST);
        return rc;
    }

    if (r->buffered) {
        return rc;
    }

    //创建子请求
    if (ngx_http_subrequest(r, &r->uri, &r->args, &ctx->sr, NULL,
                            NGX_HTTP_SUBREQUEST_CLONE)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    //保存模块上下文
    ngx_http_set_ctx(ctx->sr, ctx, ngx_http_slice_filter_module);

    //获取模块配置
    slcf = ngx_http_get_module_loc_conf(r, ngx_http_slice_filter_module);

    //重新设置ctx->range
    ctx->range.len = ngx_sprintf(ctx->range.data, "bytes=%O-%O", ctx->start,
                                 ctx->start + (off_t) slcf->size - 1)
                     - ctx->range.data;

    ctx->active = 0;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http slice subrequest: \"%V\"", &ctx->range);

    return rc;
}


/**
 * 解析响应头 Content-Range, Content-Range表示部分消息在完整消息中的位置。
 * 格式为 bytes start-end/file_length
 * 67589为文件总长度.  file_length为*表示文件大小未知
 * Content-Range: bytes 200-1000/67589
 */
static ngx_int_t
ngx_http_slice_parse_content_range(ngx_http_request_t *r,
    ngx_http_slice_content_range_t *cr)
{
    off_t             start, end, complete_length, cutoff, cutlim;
    u_char           *p;
    ngx_table_elt_t  *h;

    //获取content_range响应头
    h = r->headers_out.content_range;

    //content_range以 'bytes '开头
    if (h == NULL
        || h->value.len < 7
        || ngx_strncmp(h->value.data, "bytes ", 6) != 0)
    {
        return NGX_ERROR;
    }

    p = h->value.data + 6;

    cutoff = NGX_MAX_OFF_T_VALUE / 10;
    cutlim = NGX_MAX_OFF_T_VALUE % 10;

    start = 0;
    end = 0;
    complete_length = 0;

    //去掉前置空格
    while (*p == ' ') { p++; }

    //解析start
    if (*p < '0' || *p > '9') {
        return NGX_ERROR;
    }

    while (*p >= '0' && *p <= '9') {
        if (start >= cutoff && (start > cutoff || *p - '0' > cutlim)) {
            return NGX_ERROR;
        }

        start = start * 10 + (*p++ - '0');
    }

    while (*p == ' ') { p++; }

    //-
    if (*p++ != '-') {
        return NGX_ERROR;
    }

    while (*p == ' ') { p++; }

    //解析end
    if (*p < '0' || *p > '9') {
        return NGX_ERROR;
    }

    while (*p >= '0' && *p <= '9') {
        if (end >= cutoff && (end > cutoff || *p - '0' > cutlim)) {
            return NGX_ERROR;
        }

        end = end * 10 + (*p++ - '0');
    }

    end++;

    while (*p == ' ') { p++; }

    //解析complete_length
    if (*p++ != '/') {
        return NGX_ERROR;
    }

    while (*p == ' ') { p++; }

    if (*p != '*') {
        if (*p < '0' || *p > '9') {
            return NGX_ERROR;
        }

        while (*p >= '0' && *p <= '9') {
            if (complete_length >= cutoff
                && (complete_length > cutoff || *p - '0' > cutlim))
            {
                return NGX_ERROR;
            }

            complete_length = complete_length * 10 + (*p++ - '0');
        }

    } else {
        //  complete_length为*
        complete_length = -1;       //表示文件大小未知
        p++;
    }

    while (*p == ' ') { p++; }

    if (*p != '\0') {
        return NGX_ERROR;
    }

    cr->start = start;
    cr->end = end;
    cr->complete_length = complete_length;

    return NGX_OK;
}


/**
 * $slice_range 变量的get_handler
 * 
 * slice_range是根据slice对请求头里的range进行向下取整后的结果
 * 如 slice=100, 请求头Range: 150-250
 * 调整后的range变为 Range: 100-199
 * 
 */
static ngx_int_t
ngx_http_slice_range_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    ngx_http_slice_ctx_t       *ctx;
    ngx_http_slice_loc_conf_t  *slcf;

    //获取模块的上下文
    ctx = ngx_http_get_module_ctx(r, ngx_http_slice_filter_module);

    if (ctx == NULL) {  //如果没有获取到正下文
        if (r != r->main || r->headers_out.status) {        //如果是子请求或已经确定了响应状态码
            v->not_found = 1;
            return NGX_OK;
        }

        //获取配置结构体
        slcf = ngx_http_get_module_loc_conf(r, ngx_http_slice_filter_module);

        //如果未开启
        if (slcf->size == 0) {
            v->not_found = 1;
            return NGX_OK;
        }

        //创建上下文结构体
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_slice_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        p = ngx_pnalloc(r->pool, sizeof("bytes=-") - 1 + 2 * NGX_OFF_T_LEN);
        if (p == NULL) {
            return NGX_ERROR;
        }

        //设置模块上下文结构体
        ngx_http_set_ctx(r, ctx, ngx_http_slice_filter_module);


        //向下取整， slice=100， range=250, ctx.start=200
        ctx->start = slcf->size * (ngx_http_slice_get_start(r) / slcf->size);

        //ctx->range变为 200-299
        ctx->range.data = p;
        ctx->range.len = ngx_sprintf(p, "bytes=%O-%O", ctx->start,
                                     ctx->start + (off_t) slcf->size - 1)
                         - p;
    }

    v->data = ctx->range.data;
    v->valid = 1;
    v->not_found = 0;
    v->no_cacheable = 1;
    v->len = ctx->range.len;

    return NGX_OK;
}


/**
 * Range: bytes=200-1000， 返回200
 * 获取Range请求头start值
 */
static off_t
ngx_http_slice_get_start(ngx_http_request_t *r)
{
    off_t             start, cutoff, cutlim;
    u_char           *p;
    ngx_table_elt_t  *h;

    //如果有if_range请求头
    if (r->headers_in.if_range) {
        return 0;
    }

    //取出range请求头
    h = r->headers_in.range;

    //必须是bytes=开头
    if (h == NULL
        || h->value.len < 7
        || ngx_strncasecmp(h->value.data, (u_char *) "bytes=", 6) != 0)
    {
        return 0;
    }

    //Range: bytes=200-1000, 2000-6576, 19000-
    p = h->value.data + 6;

    //如果包含, 返回 0
    if (ngx_strchr(p, ',')) {
        return 0;
    }

    while (*p == ' ') { p++; }

    if (*p == '-') {
        return 0;
    }

    cutoff = NGX_MAX_OFF_T_VALUE / 10;
    cutlim = NGX_MAX_OFF_T_VALUE % 10;

    start = 0;

    while (*p >= '0' && *p <= '9') {
        if (start >= cutoff && (start > cutoff || *p - '0' > cutlim)) {
            return 0;
        }

        start = start * 10 + (*p++ - '0');
    }

    return start;
}


static void *
ngx_http_slice_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_slice_loc_conf_t  *slcf;

    slcf = ngx_palloc(cf->pool, sizeof(ngx_http_slice_loc_conf_t));
    if (slcf == NULL) {
        return NULL;
    }

    slcf->size = NGX_CONF_UNSET_SIZE;

    return slcf;
}


static char *
ngx_http_slice_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_slice_loc_conf_t *prev = parent;
    ngx_http_slice_loc_conf_t *conf = child;

    ngx_conf_merge_size_value(conf->size, prev->size, 0);

    return NGX_CONF_OK;
}


/**
 * 注册变量 $slice_range
 */
static ngx_int_t
ngx_http_slice_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var;

    var = ngx_http_add_variable(cf, &ngx_http_slice_range_name, 0);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_slice_range_variable;

    return NGX_OK;
}


/**
 * postconfiguration
 * 
 * 注册header_filter和body_filter
 */
static ngx_int_t
ngx_http_slice_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_slice_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_slice_body_filter;

    return NGX_OK;
}
