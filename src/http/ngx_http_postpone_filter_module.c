
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/**
 * 是一个必选filter, 不能通过编译选项移除。实现子请求必不可少
 * 
 * 将子请求产生的数据按序放回父请求
 * 
 * 为了subrequest功能而建立的
 * 如果原始请求派生出许多子请求，并且希望将所有子请求的响应依次转发给客户端，
 * 当然，这里的“依次”就是按照创建子请求的顺序来发送响应，这时，postpone模块就有了“用武之地”
 * 
 * 
 * 此模块会强制地把待转发的响应包体放在一个链表中发送，只有优先转发的子请求结束后才会开始转发下一个子请求中的响应
 * 
 * 此模块注册一个body_filter
 */
static ngx_int_t ngx_http_postpone_filter_add(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_postpone_filter_in_memory(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_postpone_filter_init(ngx_conf_t *cf);


static ngx_http_module_t  ngx_http_postpone_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_postpone_filter_init,         /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_postpone_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_postpone_filter_module_ctx,  /* module context */
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


static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


/**
 * body_filter, 是保证子请求顺序正确的关键，通过c->data控制 子请求数据发送的顺序
 * 
 * 每当使用ngx_http_output_filter方法（反向代理模块也使用该方法转发响应）向下游的客户端发送响应包体时，
 * 都会调用到ngx_http_postpone_filter_module过滤模块处理这段要发送的包体
 * 
 * in就是将要发送给客户端的一段包体
 */
static ngx_int_t
ngx_http_postpone_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_connection_t              *c;
    ngx_http_postponed_request_t  *pr;

    c = r->connection;  // c是 Nginx与下游客户端间的连接， c->data保存的是原始请求

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http postpone filter \"%V?%V\" %p", &r->uri, &r->args, in);

    if (r->subrequest_in_memory) {
        return ngx_http_postpone_filter_in_memory(r, in);
    }

    // 如果当前请求r是一个子请求（因为 c->data指向原始请求）
    if (r != c->data) {

        //如果待发送的in包体不为空，则把in加到postponed链表中属于当前请求的ngx_http_postponed_request_t结构体的out链表中，
        //同时返回NGX_OK，这意味着本次不会把in包体发给客户端
        if (in) {
            if (ngx_http_postpone_filter_add(r, in) != NGX_OK) {
                return NGX_ERROR;
            }
            //不再继续让后续body_filter处理。实际上后续的body_filter都是官方提供的filter模块
            return NGX_OK;
        }
    // 如果当前请求是子请求，而 in包体又为空，那么直接返回即可
#if 0
        /* TODO: SSI may pass NULL */
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "http postpone filter NULL inactive request");
#endif

        return NGX_OK;
    }

    // 如果postponed为空，表示请求r没有子请求产生的响应需要转发
    if (r->postponed == NULL) {

        if (in || c->buffered) {
            //直接调用下一个HTTP过滤模块继续处理in包体即可。如果没有错误的话，就会开始向下游客户端发送响应
            return ngx_http_next_body_filter(r->main, in);
        }

        return NGX_OK;
    }
    //至此，说明postponed链表中是有子请求产生的响应需要转发的，可以先把in包体加到待转发响应的末尾
    if (in) {
        //先把in包体加到待转发响应的末尾
        if (ngx_http_postpone_filter_add(r, in) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    // 循环处理 postponed链表中所有子请求待转发的包体
    do {
        pr = r->postponed;

        //如果 pr->request是子请求，则加入到原始请求的posted_requests队列中，等待HTTP框架下次调用这个请求时再来处理
        if (pr->request) {

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http postpone filter wake \"%V?%V\"",
                           &pr->request->uri, &pr->request->args);

            r->postponed = pr->next;

            c->data = pr->request;

            return ngx_http_post_request(pr->request, NULL);
        }

        // 调用下一个 HTTP过滤模块转发 out链表中保存的待转发的包体
        if (pr->out == NULL) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "http postpone filter NULL output");

        } else {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http postpone filter output \"%V?%V\"",
                           &r->uri, &r->args);

            if (ngx_http_next_body_filter(r->main, pr->out) == NGX_ERROR) {
                return NGX_ERROR;
            }
        }
        //遍历完 postponed链表
        r->postponed = pr->next;

    } while (r->postponed);

    return NGX_OK;
}


/**
 * 将in封装成一个ngx_http_postponed_request_t结构体，然后加入到r->postponed链表尾部
 */
static ngx_int_t
ngx_http_postpone_filter_add(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_postponed_request_t  *pr, **ppr;

    //ppr指向r->postponed最后一个节点
    if (r->postponed) {
        for (pr = r->postponed; pr->next; pr = pr->next) { /* void */ }

        if (pr->request == NULL) {
            goto found;
        }

        ppr = &pr->next;

    } else {
        ppr = &r->postponed;
    }

    pr = ngx_palloc(r->pool, sizeof(ngx_http_postponed_request_t));
    if (pr == NULL) {
        return NGX_ERROR;
    }

    //如果ppr指向的指针为null, 则申请新的ngx_http_postponed_request_t结构体
    *ppr = pr;

    pr->request = NULL;
    pr->out = NULL;
    pr->next = NULL;

found:

    //将in复制到pr->out尾部
    if (ngx_chain_add_copy(r->pool, &pr->out, in) == NGX_OK) {
        return NGX_OK;
    }

    return NGX_ERROR;
}


/**
 * 当子请求数据在内存中的处理，确保子请求响应数据的有序性
 * 
 * 当子请求运行结束后，响应头数据就在r->headers_out里
 */
static ngx_int_t
ngx_http_postpone_filter_in_memory(ngx_http_request_t *r, ngx_chain_t *in)
{
    size_t                     len;
    ngx_buf_t                 *b;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http postpone filter in memory");

    if (r->out == NULL) {
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        if (r->headers_out.content_length_n != -1) {
            len = r->headers_out.content_length_n;

            if (len > clcf->subrequest_output_buffer_size) {
                ngx_log_error(NGX_LOG_ERR, c->log, 0,
                              "too big subrequest response: %uz", len);
                return NGX_ERROR;
            }

        } else {
            len = clcf->subrequest_output_buffer_size;
        }

        b = ngx_create_temp_buf(r->pool, len);      //创建缓冲区
        if (b == NULL) {
            return NGX_ERROR;
        }

        b->last_buf = 1;                        //只用一块内存保存数据

        r->out = ngx_alloc_chain_link(r->pool); //分配链表节点
        if (r->out == NULL) {
            return NGX_ERROR;
        }

        r->out->buf = b;                    //连接到缓冲区
        r->out->next = NULL;                //链表结束，即只有一个节点
    }

    b = r->out->buf;

    for ( /* void */ ; in; in = in->next) {     //遍历数据链表拷贝

        if (ngx_buf_special(in->buf)) {         //跳过特殊的控制用的缓冲区
            continue;
        }

        len = in->buf->last - in->buf->pos;     //检测缓冲区数据长度

        if (len > (size_t) (b->end - b->last)) {    //超过了限定大小
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "too big subrequest response");
            return NGX_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http postpone filter in memory %uz bytes", len);

        b->last = ngx_cpymem(b->last, in->buf->pos, len);   //拷贝到缓冲区
        in->buf->pos = in->buf->last;
    }

    return NGX_OK;
}


/**
 * postconfiguration
 * 安装一个body_filter
 */
static ngx_int_t
ngx_http_postpone_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_postpone_filter;

    return NGX_OK;
}
