
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/**
 * 本模块注册了两个filter: ngx_http_chunked_header_filter 和 ngx_http_chunked_body_filter
 * 
 * 主要作用是，处理响应数据，如果响应头没content-length，且支持cunked编码，则在原来的输出buf前增加chunked编码标识
 * 
 * chunked编码格式：
 * [chunk size][\r\n][chunk data][\r\n][chunk size][\r\n][chunk data][\r\n][chunk size = 0][\r\n][\r\n]
 * 
 * 同时负责triler_header的发送
 * Trailer 头部是 HTTP 协议中针对动态头部需求的重要扩展，通过与分块传输编码配合，解决了 “先有数据后有元信息” 的场景痛点，
 * 提升了大文件传输、流式数据处理和安全校验等场景的灵活性。在实际应用中，它常与现代 Web 技术（如 API 接口、实时数据推送）结合，
 * 成为优化 HTTP 通信的重要工具
 * 
 */

/**
 * 模块自定义上下文结构体
 */
typedef struct {
    ngx_chain_t         *free;
    ngx_chain_t         *busy;
} ngx_http_chunked_filter_ctx_t;


static ngx_int_t ngx_http_chunked_filter_init(ngx_conf_t *cf);
static ngx_chain_t *ngx_http_chunked_create_trailers(ngx_http_request_t *r,
    ngx_http_chunked_filter_ctx_t *ctx);


static ngx_http_module_t  ngx_http_chunked_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    //安装了header和body的filter
    ngx_http_chunked_filter_init,          /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_chunked_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_chunked_filter_module_ctx,   /* module context */
    NULL,                                  /* module directives */
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


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


/**
 *  header_filter
 * 
 *  初始化自定义上下文结构体。如果响应头里没设置content-length, 设置r->chunked 标识分块响应
 * 
 */
static ngx_int_t
ngx_http_chunked_header_filter(ngx_http_request_t *r)
{
    ngx_http_core_loc_conf_t       *clcf;
    ngx_http_chunked_filter_ctx_t  *ctx;

    //没有响应体，不需要处理
    if (r->headers_out.status == NGX_HTTP_NOT_MODIFIED      //304
        || r->headers_out.status == NGX_HTTP_NO_CONTENT     //204
        || r->headers_out.status < NGX_HTTP_OK              //<200
        || r != r->main                                     //子请求
        || r->method == NGX_HTTP_HEAD)                      //HEAD请求
    {
        return ngx_http_next_header_filter(r);
    }

    //没有设置content_length
    if (r->headers_out.content_length_n == -1
        || r->expect_trailers)
    {
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        if (r->http_version >= NGX_HTTP_VERSION_11      //http版本大于1.1,且enable分块传输
            && clcf->chunked_transfer_encoding)     //配置项 https://nginx.org/en/docs/http/ngx_http_core_module.html#chunked_transfer_encoding
        {
            if (r->expect_trailers) {
                ngx_http_clear_content_length(r);
            }

            r->chunked = 1;     //标识需要分块传输

            //分配自定义上下文结构体
            ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_chunked_filter_ctx_t));
            if (ctx == NULL) {
                return NGX_ERROR;
            }

            //设置自定义上下文结构体
            ngx_http_set_ctx(r, ctx, ngx_http_chunked_filter_module);

        } else if (r->headers_out.content_length_n == -1) {
            //如果没有设置content_length，且(http版本不支持分块传输或关闭了分块传输), 关闭keepalive
            r->keepalive = 0;
        }
    }

    return ngx_http_next_header_filter(r);
}


/**
 * body_filter
 */
static ngx_int_t
ngx_http_chunked_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    u_char                         *chunk;
    off_t                           size;
    ngx_int_t                       rc;
    ngx_buf_t                      *b;
    ngx_chain_t                    *out, *cl, *tl, **ll;
    ngx_http_chunked_filter_ctx_t  *ctx;

    //in == NULL, 本次没有发送有效数据
    //!r->chunked, 响应头设置了content-length或客户端不支持chunked响应
    //r->header_only, 没有响应体 
    if (in == NULL || !r->chunked || r->header_only) {  //不需要处理
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_chunked_filter_module);

    out = NULL;
    ll = &out;

    size = 0;
    cl = in;

    //复制in链表到out链表。 out链表最终会传给下一个body_filter
    for ( ;; ) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http chunk: %O", ngx_buf_size(cl->buf));

        size += ngx_buf_size(cl->buf);

        if (cl->buf->flush
            || cl->buf->sync
            || ngx_buf_in_memory(cl->buf)
            || cl->buf->in_file)
        {
            tl = ngx_alloc_chain_link(r->pool);
            if (tl == NULL) {
                return NGX_ERROR;
            }

            tl->buf = cl->buf;
            *ll = tl;
            ll = &tl->next;
        }

        if (cl->next == NULL) {
            break;
        }

        cl = cl->next;
    }

    //chunked格式编码 [chunk size][\r\n][chunk data][\r\n]
    //如果有数据要发送, 创建一个[chunk size][\r\n]的 buf， 插入到原始的数据之前 
    if (size) {
        tl = ngx_chain_get_free_buf(r->pool, &ctx->free);
        if (tl == NULL) {
            return NGX_ERROR;
        }

        b = tl->buf;
        chunk = b->start;

        if (chunk == NULL) {        //最后一个chunk
            /* the "0000000000000000" is 64-bit hexadecimal string */

            chunk = ngx_palloc(r->pool, sizeof("0000000000000000" CRLF) - 1);
            if (chunk == NULL) {
                return NGX_ERROR;
            }

            b->start = chunk;
            b->end = chunk + sizeof("0000000000000000" CRLF) - 1;
        }

        b->tag = (ngx_buf_tag_t) &ngx_http_chunked_filter_module;
        b->memory = 0;
        b->temporary = 1;
        b->pos = chunk;
        b->last = ngx_sprintf(chunk, "%xO" CRLF, size);     //复制buf

        //将tl插入到out链表头部
        tl->next = out;
        out = tl;
    }

    if (cl->buf->last_buf) {        //如果是最后一个buf， 添加chunked传输结束标识
        tl = ngx_http_chunked_create_trailers(r, ctx);
        if (tl == NULL) {
            return NGX_ERROR;
        }

        cl->buf->last_buf = 0;

        *ll = tl;

        if (size == 0) {
            tl->buf->pos += 2;
        }

    } else if (size > 0) {
        //在原始数据之后，添加一个\n\r的buf
        tl = ngx_chain_get_free_buf(r->pool, &ctx->free);
        if (tl == NULL) {
            return NGX_ERROR;
        }

        b = tl->buf;

        b->tag = (ngx_buf_tag_t) &ngx_http_chunked_filter_module;
        b->temporary = 0;
        b->memory = 1;
        b->pos = (u_char *) CRLF;
        b->last = b->pos + 2;

        *ll = tl;

    } else {
        *ll = NULL;
    }

    rc = ngx_http_next_body_filter(r, out);

    ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
                            (ngx_buf_tag_t) &ngx_http_chunked_filter_module);

    return rc;
}


/**
 * 基于chunked编码规则，在最后一个chunked后添加 [chunk size = 0][\r\n][\r\n] 作为传输结束标识
 */
static ngx_chain_t *
ngx_http_chunked_create_trailers(ngx_http_request_t *r,
    ngx_http_chunked_filter_ctx_t *ctx)
{
    size_t            len;
    ngx_buf_t        *b;
    ngx_uint_t        i;
    ngx_chain_t      *cl;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *header;

    len = 0;

    //是否有trailer头部需要发送
    part = &r->headers_out.trailers.part;
    header = part->elts;

    //遍历trailers header, 计算所需存储空间
    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        //计算所有trailers header 所需的存储空间
        len += header[i].key.len + sizeof(": ") - 1
               + header[i].value.len + sizeof(CRLF) - 1;
    }

    //申请空间
    cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
    if (cl == NULL) {
        return NULL;
    }

    b = cl->buf;

    b->tag = (ngx_buf_tag_t) &ngx_http_chunked_filter_module;
    b->temporary = 0;
    b->memory = 1;
    b->last_buf = 1;

    if (len == 0) {     //表示没有需要发送的trailers header
        b->pos = (u_char *) CRLF "0" CRLF CRLF;
        b->last = b->pos + sizeof(CRLF "0" CRLF CRLF) - 1;
        return cl;
    }

    len += sizeof(CRLF "0" CRLF CRLF) - 1;

    b->pos = ngx_palloc(r->pool, len);
    if (b->pos == NULL) {
        return NULL;
    }

    b->last = b->pos;

    *b->last++ = CR; *b->last++ = LF;
    *b->last++ = '0';
    *b->last++ = CR; *b->last++ = LF;

    part = &r->headers_out.trailers.part;
    header = part->elts;

    //构建发送的trailers header buf
    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http trailer: \"%V: %V\"",
                       &header[i].key, &header[i].value);

        b->last = ngx_copy(b->last, header[i].key.data, header[i].key.len);
        *b->last++ = ':'; *b->last++ = ' ';

        b->last = ngx_copy(b->last, header[i].value.data, header[i].value.len);
        *b->last++ = CR; *b->last++ = LF;
    }

    *b->last++ = CR; *b->last++ = LF;

    //返回最终的buf
    return cl;
}


/**
 * postconfiguration 阶段直接，安装header_filter和body_filter
 */
static ngx_int_t
ngx_http_chunked_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_chunked_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_chunked_body_filter;

    return NGX_OK;
}
