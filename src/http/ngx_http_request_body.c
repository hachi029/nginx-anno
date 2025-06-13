
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static void ngx_http_read_client_request_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_do_read_client_request_body(ngx_http_request_t *r);
static ngx_int_t ngx_http_copy_pipelined_header(ngx_http_request_t *r,
    ngx_buf_t *buf);
static ngx_int_t ngx_http_write_request_body(ngx_http_request_t *r);
static ngx_int_t ngx_http_read_discarded_request_body(ngx_http_request_t *r);
static ngx_int_t ngx_http_discard_request_body_filter(ngx_http_request_t *r,
    ngx_buf_t *b);
static ngx_int_t ngx_http_test_expect(ngx_http_request_t *r);

static ngx_int_t ngx_http_request_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_request_body_length_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_request_body_chunked_filter(ngx_http_request_t *r,
    ngx_chain_t *in);


/**
 * 调用此方法开始读取请求体, 读取完成后回调post_handler
 * 
 * 调用此方法一般不能一次读完请求体，后续触发的可读事件，将由ngx_http_read_client_request_body_handler处理
 * 
 */
ngx_int_t
ngx_http_read_client_request_body(ngx_http_request_t *r,
    ngx_http_client_body_handler_pt post_handler)
{
    size_t                     preread;
    ssize_t                    size;
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_chain_t                out;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    r->main->count++;       //请求对应的原始请求的引用计数加1

    //如果是子请求、已经读取过请求体了、或者丢弃请求体
    //如果request_body已经被分配过了，证明已经读取过HTTP包体了
    //如果discard_body为1，则证明曾经执行过 丢弃包体的方法，现在包体正在被丢弃中
    if (r != r->main || r->request_body || r->discard_body) {
        r->request_body_no_buffering = 0;
        post_handler(r);        // 直接回调post_handler
        return NGX_OK;
    }

    if (ngx_http_test_expect(r) != NGX_OK) {        //处理 Expect请求头
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    //分配r->request_body请求体结构体
    rb = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (rb == NULL) {
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     rb->temp_file = NULL;
     *     rb->bufs = NULL;
     *     rb->buf = NULL;
     *     rb->free = NULL;
     *     rb->busy = NULL;
     *     rb->chunked = NULL;
     *     rb->received = 0;
     *     rb->filter_need_buffering = 0;
     *     rb->last_sent = 0;
     *     rb->last_saved = 0;
     */

    rb->rest = -1;      //请求体的剩余长度
    rb->post_handler = post_handler;        //读取完请求体后的回调

    r->request_body = rb;       // 设置请求体结构体， 读取之前为NULL

    //如果请求头里没有content_length（如get请求），且没有chunked请求头
    if (r->headers_in.content_length_n < 0 && !r->headers_in.chunked) {
        r->request_body_no_buffering = 0;
        post_handler(r);        //直接执行回调post_handler
        return NGX_OK;
    }

#if (NGX_HTTP_V2)
    if (r->stream) {
        rc = ngx_http_v2_read_request_body(r);
        goto done;
    }
#endif

#if (NGX_HTTP_V3)
    if (r->http_version == NGX_HTTP_VERSION_30) {
        rc = ngx_http_v3_read_request_body(r);
        goto done;
    }
#endif

    //preread是读取请求头时读取到的请求头的长度
    preread = r->header_in->last - r->header_in->pos;

    //处理preread部分数据
    if (preread) {      //如果r->header_in中存在请求体数据

        /* there is the pre-read part of the request body */

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http client request body preread %uz", preread);

        out.buf = r->header_in; //将请求头的buf加到out链表, 当前为链表头
        out.next = NULL;

        rc = ngx_http_request_body_filter(r, &out);     //调用ngx_http_request_body_filter处理请求体

        if (rc != NGX_OK) {
            goto done;
        }

        //更新已经读取到的数据（r->header_in->last - r->header_in->pos 通常为0， 因为在ngx_http_request_body_filter中已经消费过out了）
        r->request_length += preread - (r->header_in->last - r->header_in->pos);

        if (!r->headers_in.chunked  //如果请求头没有chunked
            && rb->rest > 0 //请求体的剩余长度大于0
            && rb->rest <= (off_t) (r->header_in->end - r->header_in->last)) //如果请求体的剩余长度小于等于请求头buf的剩余长度
        {

            /* the whole request body may be placed in r->header_in */

            //整个请求体可以放到header_in中
            b = ngx_calloc_buf(r->pool);    //分配一个buf
            if (b == NULL) {
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
                goto done;
            }

            //buf指向header_in
            b->temporary = 1;
            b->start = r->header_in->pos;
            b->pos = r->header_in->pos;
            b->last = r->header_in->last;
            b->end = r->header_in->end;

            //请求体rb的buf指向新分配的buf
            rb->buf = b;

            //设置读事件处理器， 后续的可读事件由此handler处理
            r->read_event_handler = ngx_http_read_client_request_body_handler;
            //设置写事件处理器设置为empty
            r->write_event_handler = ngx_http_request_empty_handler;
            //读取请求体， 数据被读到r->request_body中
            rc = ngx_http_do_read_client_request_body(r);
            goto done;
        }

    } else {
        //至此说明 没有预读的请求体数据
        /* set rb->rest */

        rc = ngx_http_request_body_filter(r, NULL);

        if (rc != NGX_OK) {
            goto done;
        }
    }

    if (rb->rest == 0 && rb->last_saved) {      //已经读取完了
        /* the whole request body was pre-read */
        r->request_body_no_buffering = 0;
        post_handler(r);
        return NGX_OK;
    }

    if (rb->rest < 0) {     //非正常状态
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "negative request body rest");
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    size = clcf->client_body_buffer_size;
    size += size >> 2;

    /* TODO: honor r->request_body_in_single_buf */

    if (!r->headers_in.chunked && rb->rest < size) {    //如果是非chunked请求且剩余待接收数据<size
        size = (ssize_t) rb->rest;  //size置为剩余需要接收的数据大小

        if (r->request_body_in_single_buf) {    //如果要求请求体存在一个buf里
            size += preread;    //size需要加上预读的大小
        }

        if (size == 0) {
            size++;
        }

    } else {
        size = clcf->client_body_buffer_size;
    }

    //分配一个buf用于存放剩余的请求体
    rb->buf = ngx_create_temp_buf(r->pool, size);
    if (rb->buf == NULL) {
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    //当再有可读事件时，调用此方法读取请求体
    r->read_event_handler = ngx_http_read_client_request_body_handler;
    r->write_event_handler = ngx_http_request_empty_handler;

    rc = ngx_http_do_read_client_request_body(r);

done:
    //到这里说明已经读取到了一部分数据
    //request_body_no_buffering， 说明不要缓存请求数据
    if (r->request_body_no_buffering
        && (rc == NGX_OK || rc == NGX_AGAIN))
    {
        if (rc == NGX_OK) { //读取完了
            r->request_body_no_buffering = 0;

        } else {        //读取到了部分数据
            /* rc == NGX_AGAIN */
            r->reading_body = 1;
        }

        //已经读取完了请求体或读取到了部分请求体
        r->read_event_handler = ngx_http_block_reading;
        post_handler(r);
    }

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        r->main->count--;
    }

    return rc;
}


ngx_int_t
ngx_http_read_unbuffered_request_body(ngx_http_request_t *r)
{
    ngx_int_t  rc;

#if (NGX_HTTP_V2)
    if (r->stream) {
        rc = ngx_http_v2_read_unbuffered_request_body(r);

        if (rc == NGX_OK) {
            r->reading_body = 0;
        }

        return rc;
    }
#endif

#if (NGX_HTTP_V3)
    if (r->http_version == NGX_HTTP_VERSION_30) {
        rc = ngx_http_v3_read_unbuffered_request_body(r);

        if (rc == NGX_OK) {
            r->reading_body = 0;
        }

        return rc;
    }
#endif

    if (r->connection->read->timedout) {
        r->connection->timedout = 1;
        return NGX_HTTP_REQUEST_TIME_OUT;
    }

    rc = ngx_http_do_read_client_request_body(r);

    if (rc == NGX_OK) {
        r->reading_body = 0;
    }

    return rc;
}

/**
 * 当调用ngx_http_read_client_request_body开启读取客户端请求体，如果第一次没读取完，
 * 下次读事件再次触发时，调用此函数继续进行读取。
 * 
 * r->read_event_handler = this handler
 */
static void
ngx_http_read_client_request_body_handler(ngx_http_request_t *r)
{
    ngx_int_t  rc;

    if (r->connection->read->timedout) {    //如果连接读取超时
        r->connection->timedout = 1;
        ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);    //408状态码
        return;
    }

    rc = ngx_http_do_read_client_request_body(r);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {     //>=300 表示希望返回错误码
        ngx_http_finalize_request(r, rc);
    }
}

/**
 * 开启读取客户端请求体后，ngx_http_read_client_request_body_handler
 * 和ngx_http_read_client_request_body都会调用本方法
 * 
 * 该方法把客户端与Nginx之间TCP连接上套接字缓冲区中的当前字符流全部读出来，
 * 并判断是否需要写入文 件，以及是否接收到全部的包体，同时在接收到完整的包体后激活post_handler回调方法
 */
static ngx_int_t
ngx_http_do_read_client_request_body(ngx_http_request_t *r)
{
    off_t                      rest;
    size_t                     size;
    ssize_t                    n;
    ngx_int_t                  rc;
    ngx_uint_t                 flush;
    ngx_chain_t                out;
    ngx_connection_t          *c;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;
    rb = r->request_body;
    flush = 1;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http read client request body");

    for ( ;; ) {
        for ( ;; ) {
            if (rb->rest == 0) {     //已经读完了请求体，跳出循环
                break;
            }

            if (rb->buf->last == rb->buf->end) {    //缓冲区已满

                /* update chains */

                //调用body_filter处理读到的请求数据, 会将缓存保存到本地文件
                rc = ngx_http_request_body_filter(r, NULL); 

                if (rc != NGX_OK) {
                    return rc;
                }

                if (rb->busy != NULL) {
                    if (r->request_body_no_buffering) {
                        //添加读超时事件
                        if (c->read->timer_set) {
                            ngx_del_timer(c->read);
                        }

                        //监听读事件
                        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                            return NGX_HTTP_INTERNAL_SERVER_ERROR;
                        }

                        return NGX_AGAIN;
                    }

                    if (rb->filter_need_buffering) {
                        clcf = ngx_http_get_module_loc_conf(r,
                                                         ngx_http_core_module);
                        ngx_add_timer(c->read, clcf->client_body_timeout);

                        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                            return NGX_HTTP_INTERNAL_SERVER_ERROR;
                        }

                        return NGX_AGAIN;
                    }

                    ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                                  "busy buffers after request body flush");

                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                flush = 0;
                //重置缓冲区
                rb->buf->pos = rb->buf->start;
                rb->buf->last = rb->buf->start;
            }

            //缓冲区未满
            size = rb->buf->end - rb->buf->last;  //size为rb的剩余可用空间
            rest = rb->rest - (rb->buf->last - rb->buf->pos);   //rest为剩余待读取数据

            if ((off_t) size > rest) {
                size = (size_t) rest;
            }

            if (size == 0) {
                break;
            }
            //读取数据
            n = c->recv(c, rb->buf->last, size);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http client request body recv %z", n);

            if (n == NGX_AGAIN) {   //当前无数据可读
                break;
            }

            if (n == 0) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client prematurely closed connection");
            }

            if (n == 0 || n == NGX_ERROR) {
                c->error = 1;
                return NGX_HTTP_BAD_REQUEST;
            }

            //正确读取到了数据
            rb->buf->last += n;
            r->request_length += n;

            /* pass buffer to request body filter chain */

            flush = 0;
            out.buf = rb->buf;
            out.next = NULL;

            //处理请求
            rc = ngx_http_request_body_filter(r, &out);     //会将请求体保存到文件

            if (rc != NGX_OK) {
                return rc;
            }

            if (rb->rest == 0) {
                break;
            }

            if (rb->buf->last < rb->buf->end) {
                break;
            }
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http client request body rest %O", rb->rest);

        if (flush) {
            rc = ngx_http_request_body_filter(r, NULL);

            if (rc != NGX_OK) {
                return rc;
            }
        }

        //已经读完了请求体且也已经保存到了本地磁盘
        if (rb->rest == 0 && rb->last_saved) {
            break;
        }

        //不可读或已读完
        if (!c->read->ready || rb->rest == 0) {

            clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            ngx_add_timer(c->read, clcf->client_body_timeout);      //默认60s

            //添加事件监听
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            return NGX_AGAIN;
        }
    }

    if (ngx_http_copy_pipelined_header(r, rb->buf) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    //已经接收到了完整包体
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (!r->request_body_no_buffering) {
        //表示要缓存
        r->read_event_handler = ngx_http_block_reading;
        rb->post_handler(r);    //执行回调
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_copy_pipelined_header(ngx_http_request_t *r, ngx_buf_t *buf)
{
    size_t                     n;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl;
    ngx_http_connection_t     *hc;
    ngx_http_core_srv_conf_t  *cscf;

    b = r->header_in;
    n = buf->last - buf->pos;

    if (buf == b || n == 0) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http body pipelined header: %uz", n);

    /*
     * if there is a pipelined request in the client body buffer,
     * copy it to the r->header_in buffer if there is enough room,
     * or allocate a large client header buffer
     */

    if (n > (size_t) (b->end - b->last)) {

        hc = r->http_connection;

        if (hc->free) {
            cl = hc->free;
            hc->free = cl->next;

            b = cl->buf;

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http large header free: %p %uz",
                           b->pos, b->end - b->last);

        } else {
            cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

            b = ngx_create_temp_buf(r->connection->pool,
                                    cscf->large_client_header_buffers.size);
            if (b == NULL) {
                return NGX_ERROR;
            }

            cl = ngx_alloc_chain_link(r->connection->pool);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            cl->buf = b;

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http large header alloc: %p %uz",
                           b->pos, b->end - b->last);
        }

        cl->next = hc->busy;
        hc->busy = cl;
        hc->nbusy++;

        r->header_in = b;

        if (n > (size_t) (b->end - b->last)) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "too large pipelined header after reading body");
            return NGX_ERROR;
        }
    }

    ngx_memcpy(b->last, buf->pos, n);

    b->last += n;
    r->request_length -= n;

    return NGX_OK;
}


/**
 * 读取请求时，如果配置了proxy_request_buffering on, 且读取缓冲区满了，
 *  会将读取到的缓冲区写入临时文件
 * 将请求体写入临时文件
 * 1.如果请求体已经写入临时文件，则直接返回
 * 2.如果请求体没有写入临时文件，则创建临时文件，并将请求体写入临时文件
 */
static ngx_int_t
ngx_http_write_request_body(ngx_http_request_t *r)
{
    ssize_t                    n;
    ngx_chain_t               *cl, *ln;
    ngx_temp_file_t           *tf;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    rb = r->request_body;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http write client request body, bufs %p", rb->bufs);

    if (rb->temp_file == NULL) {        //如果请求体没有写入临时文件
        tf = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));
        if (tf == NULL) {
            return NGX_ERROR;
        }

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        tf->file.fd = NGX_INVALID_FILE;
        tf->file.log = r->connection->log;
        tf->path = clcf->client_body_temp_path;
        tf->pool = r->pool;
        tf->warn = "a client request body is buffered to a temporary file";
        tf->log_level = r->request_body_file_log_level;
        tf->persistent = r->request_body_in_persistent_file;
        tf->clean = r->request_body_in_clean_file;

        if (r->request_body_file_group_access) {
            tf->access = 0660;
        }

        rb->temp_file = tf;     //将临时文件结构体赋值给请求体结构体request_body

        if (rb->bufs == NULL) {     //如果请求体为空
            /* empty body with r->request_body_in_file_only */

            //只是创建临时文件，不写入数据
            if (ngx_create_temp_file(&tf->file, tf->path, tf->pool,
                                     tf->persistent, tf->clean, tf->access)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            return NGX_OK;
        }
    }

    if (rb->bufs == NULL) {     //已经写入临时文件了
        return NGX_OK;
    }

    //将请求体写入临时文件， n是写入的字节数
    n = ngx_write_chain_to_temp_file(rb->temp_file, rb->bufs);

    /* TODO: n == 0 or not complete and level event */

    if (n == NGX_ERROR) {
        return NGX_ERROR;
    }

    rb->temp_file->offset += n;

    /* mark all buffers as written */

    for (cl = rb->bufs; cl; /* void */) {

        cl->buf->pos = cl->buf->last;       //将buf标记为已消费

        ln = cl;
        cl = cl->next;
        ngx_free_chain(r->pool, ln);        //释放链表节点
    }

    rb->bufs = NULL;        //将bufs置为空

    return NGX_OK;
}

/**
 * 放弃接收包体
 * 
 * 它也使用了3个方法实现，HTTP模 块调用的ngx_http_discard_request_body方法用于第一次启动丢弃包体动作，
 * 而 ngx_http_discarded_request_body_handler是作为请求的read_event_handler方法的，
 * 在有新的可读事件时会调用它处理包体。ngx_http_read_discarded_request_body方法则是根据上述两个方法通用部分提取出的公共方法，
 * 用来读取包体且不做任何处理
 */
ngx_int_t
ngx_http_discard_request_body(ngx_http_request_t *r)
{
    ssize_t       size;
    ngx_int_t     rc;
    ngx_event_t  *rev;

    //r->discard_body 标识是否已经执行过本方法
    //r->request_body 表示已经读取过请求体了。读取请求体过程中会给r->request_body赋值
    if (r != r->main || r->discard_body || r->request_body) {
        return NGX_OK;
    }

#if (NGX_HTTP_V2)
    if (r->stream) {
        r->stream->skip_data = 1;
        return NGX_OK;
    }
#endif

#if (NGX_HTTP_V3)
    if (r->http_version == NGX_HTTP_VERSION_30) {
        return NGX_OK;
    }
#endif

    //Expect: 100-continue 机制
    if (ngx_http_test_expect(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rev = r->connection->read;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0, "http set discard body");

    //不再需要超时定时器
    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    //如果没有content_length请求头，且不是分块传输
    if (r->headers_in.content_length_n <= 0 && !r->headers_in.chunked) {
        return NGX_OK;
    }

    //header的长度， header_in是一个ngx_buf_t
    size = r->header_in->last - r->header_in->pos;

    //如果请求体的长度大于0，或者是分块传输
    if (size || r->headers_in.chunked) {
        rc = ngx_http_discard_request_body_filter(r, r->header_in);

        if (rc != NGX_OK) {
            return rc;
        }

        if (r->headers_in.content_length_n == 0) {
            return NGX_OK;
        }
    }

    rc = ngx_http_read_discarded_request_body(r);

    if (rc == NGX_OK) {
        r->lingering_close = 0;
        return NGX_OK;
    }

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    /* rc == NGX_AGAIN */

    r->read_event_handler = ngx_http_discarded_request_body_handler;

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->count++;
    r->discard_body = 1;

    return NGX_OK;
}


void
ngx_http_discarded_request_body_handler(ngx_http_request_t *r)
{
    ngx_int_t                  rc;
    ngx_msec_t                 timer;
    ngx_event_t               *rev;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;
    rev = c->read;

    if (rev->timedout) {
        c->timedout = 1;
        c->error = 1;
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }

    if (r->lingering_time) {
        timer = (ngx_msec_t) r->lingering_time - (ngx_msec_t) ngx_time();

        if ((ngx_msec_int_t) timer <= 0) {
            r->discard_body = 0;
            r->lingering_close = 0;
            ngx_http_finalize_request(r, NGX_ERROR);
            return;
        }

    } else {
        timer = 0;
    }

    rc = ngx_http_read_discarded_request_body(r);

    if (rc == NGX_OK) {
        r->discard_body = 0;
        r->lingering_close = 0;
        r->lingering_time = 0;
        ngx_http_finalize_request(r, NGX_DONE);
        return;
    }

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        c->error = 1;
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }

    /* rc == NGX_AGAIN */

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        c->error = 1;
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }

    if (timer) {

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        timer *= 1000;

        if (timer > clcf->lingering_timeout) {
            timer = clcf->lingering_timeout;
        }

        ngx_add_timer(rev, timer);
    }
}

/**
 * 使用4k的缓冲区，尝试读取数据
 */
static ngx_int_t
ngx_http_read_discarded_request_body(ngx_http_request_t *r)
{
    size_t     size;
    ssize_t    n;
    ngx_int_t  rc;
    ngx_buf_t  b;
    u_char     buffer[NGX_HTTP_DISCARD_BUFFER_SIZE];    //4k的buf

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http read discarded body");

    ngx_memzero(&b, sizeof(ngx_buf_t));

    b.temporary = 1;

    for ( ;; ) {
        if (r->headers_in.content_length_n == 0) {  //已经读完所有的body
            break;
        }

        if (!r->connection->read->ready) {      //不可读
            return NGX_AGAIN;
        }

        //本次最多读取的字节数量
        size = (size_t) ngx_min(r->headers_in.content_length_n,
                                NGX_HTTP_DISCARD_BUFFER_SIZE);

        //读取数据
        n = r->connection->recv(r->connection, buffer, size);

        if (n == NGX_ERROR) {       //读取错误
            r->connection->error = 1;
            return NGX_OK;
        }

        if (n == NGX_AGAIN) {       //需下次调度
            return NGX_AGAIN;
        }

        if (n == 0) {               //
            return NGX_OK;
        }

        b.pos = buffer;
        b.last = buffer + n;

        rc = ngx_http_discard_request_body_filter(r, &b);

        if (rc != NGX_OK) {
            return rc;
        }
    }

    if (ngx_http_copy_pipelined_header(r, &b) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->read_event_handler = ngx_http_block_reading; //不再读取数据

    return NGX_OK;
}

/**
 * 读取到的数据，调用此方法进行处理。
 * 如果是chunked请求，需要解析读取到的数据，计算需要读取的数据
 * 如果是正常请求，仅更新content_length_n，使用content_length_n记录仍然需要读取的数据
 */
static ngx_int_t
ngx_http_discard_request_body_filter(ngx_http_request_t *r, ngx_buf_t *b)
{
    size_t                     size;
    ngx_int_t                  rc;
    ngx_http_request_body_t   *rb;
    ngx_http_core_srv_conf_t  *cscf;

    if (r->headers_in.chunked) {        //如果是chunked请求

        rb = r->request_body;

        //初始化request_body，读取到的请求体会保存到r->request_body中
        if (rb == NULL) {

            //分配request_body结构体
            rb = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
            if (rb == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            //分配ngx_http_chunked_t结构体
            rb->chunked = ngx_pcalloc(r->pool, sizeof(ngx_http_chunked_t));
            if (rb->chunked == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            r->request_body = rb;
        }

        for ( ;; ) {

            //解析chunked包体
            rc = ngx_http_parse_chunked(r, b, rb->chunked, 0);

            if (rc == NGX_OK) {

                /* a chunk has been parsed successfully */

                size = b->last - b->pos;

                if ((off_t) size > rb->chunked->size) {
                    b->pos += (size_t) rb->chunked->size;
                    rb->chunked->size = 0;

                } else {
                    rb->chunked->size -= size;
                    b->pos = b->last;
                }

                continue;
            }

            if (rc == NGX_DONE) {

                /* a whole response has been parsed successfully */

                r->headers_in.content_length_n = 0;
                break;
            }

            if (rc == NGX_AGAIN) {

                /* set amount of data we want to see next time */

                cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

                r->headers_in.content_length_n = ngx_max(rb->chunked->length,
                               (off_t) cscf->large_client_header_buffers.size);
                break;
            }

            /* invalid */

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "client sent invalid chunked body");

            return NGX_HTTP_BAD_REQUEST;
        }

    } else {
        size = b->last - b->pos;

        //如果buf的长度大于content_length_n， 说明读取到了下个请求的内容
        if ((off_t) size > r->headers_in.content_length_n) {
            //只将post往后移动content_length_n，表示这部分数据已经消费过了
            b->pos += (size_t) r->headers_in.content_length_n;
            r->headers_in.content_length_n = 0;

        } else {    //说明请求体还没有读取完
            b->pos = b->last;
            //更新还需要读取的数据长度
            r->headers_in.content_length_n -= size;
        }
    }

    return NGX_OK;
}


/**
 * 在read_client_request_body()和discard_request_body()中会调用此方法
 * 
 * 只是无条件地发送 HTTP/1.1 100 Continue
 * 
 * Expect: 100-continue 机制
客户端在发送较大请求体前，可通过 Expect: 100-continue 头询问服务器是否愿意接收请求体。
服务器若接受，返回 100 Continue 状态码；否则返回错误（如 417 Expectation Failed）。
 */
static ngx_int_t
ngx_http_test_expect(ngx_http_request_t *r)
{
    ngx_int_t   n;
    ngx_str_t  *expect;

    if (r->expect_tested    //如果已经测试过了
        || r->headers_in.expect == NULL     //如果没有expect请求头
        || r->http_version < NGX_HTTP_VERSION_11        //如果http版本小于1.1
#if (NGX_HTTP_V2)
        || r->stream != NULL
#endif
#if (NGX_HTTP_V3)
        || r->connection->quic != NULL
#endif
       )
    {
        return NGX_OK;
    }

    r->expect_tested = 1;                   //标记已经测试过了

    expect = &r->headers_in.expect->value;  //获取expect请求头

    if (expect->len != sizeof("100-continue") - 1
        || ngx_strncasecmp(expect->data, (u_char *) "100-continue",
                           sizeof("100-continue") - 1)
           != 0)        //如果expect请求头的值不是'100-continue'
    {
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "send 100 Continue");

    //发送100 Continue响应
    n = r->connection->send(r->connection,
                            (u_char *) "HTTP/1.1 100 Continue" CRLF CRLF,
                            sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1);
    //如果已经发送完了100 Continue响应
    if (n == sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1) {
        return NGX_OK;
    }

    /* we assume that such small packet should be send successfully */

    r->connection->error = 1;       //发送失败会导致内部错误，向客户端发送500错误

    return NGX_ERROR;       
}

/**
 * 根据是否是chunked请求，执行不同逻辑 , in是读取到的HTTP包体
 * 返回值不为NGX_OK表示有错误
 */
static ngx_int_t
ngx_http_request_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    if (r->headers_in.chunked) {
        return ngx_http_request_body_chunked_filter(r, in);

    } else {
        return ngx_http_request_body_length_filter(r, in);
    }
}


/**
 * 处理非chunked请求体
 * 
 * 将in链表中的buf复制到out链表中，然后调用ngx_http_top_request_body_filter，启动body_filter
 * 
 */
static ngx_int_t
ngx_http_request_body_length_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    size_t                     size;
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl, *tl, *out, **ll;
    ngx_http_request_body_t   *rb;

    rb = r->request_body;

    out = NULL;
    ll = &out;

    if (rb->rest == -1) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http request body content length filter");

        rb->rest = r->headers_in.content_length_n;      //设置剩余的待读取的请求体长度

        if (rb->rest == 0) {      //如果没有请求体  

            tl = ngx_chain_get_free_buf(r->pool, &rb->free);
            if (tl == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            b = tl->buf;

            ngx_memzero(b, sizeof(ngx_buf_t));

            b->last_buf = 1;        //标记为最后一个buf

            *ll = tl;
            ll = &tl->next;
        }
    }

    //复制in链表中的buf到out链表中
    for (cl = in; cl; cl = cl->next) {

        if (rb->rest == 0) {        //读取完了
            break;
        }

        tl = ngx_chain_get_free_buf(r->pool, &rb->free);
        if (tl == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b = tl->buf;

        ngx_memzero(b, sizeof(ngx_buf_t));

        b->temporary = 1;
        b->tag = (ngx_buf_tag_t) &ngx_http_read_client_request_body;
        b->start = cl->buf->pos;
        b->pos = cl->buf->pos;
        b->last = cl->buf->last;
        b->end = cl->buf->end;
        b->flush = r->request_body_no_buffering;

        size = cl->buf->last - cl->buf->pos;        //size为当前buf的长度

        if ((off_t) size < rb->rest) {    //如果当前buf的长度小于剩余的请求体长度
            cl->buf->pos = cl->buf->last;
            rb->rest -= size;       //更新剩余的请求体长度

        } else {                    //如果当前buf的长度大于剩余的请求体长度
            cl->buf->pos += (size_t) rb->rest;
            rb->rest = 0;           //标记已经读取完成
            b->last = cl->buf->pos;
            b->last_buf = 1;        //标记为最后一个buf
        }

        *ll = tl;
        ll = &tl->next;
    }

    // 这里调用请求体过滤链表，对数据进行过滤处理
    // 实际上是ngx_http_request_body_save_filter
    rc = ngx_http_top_request_body_filter(r, out);

    ngx_chain_update_chains(r->pool, &rb->free, &rb->busy, &out,
                            (ngx_buf_tag_t) &ngx_http_read_client_request_body);

    return rc;
}


static ngx_int_t
ngx_http_request_body_chunked_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    size_t                     size;
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl, *out, *tl, **ll;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_core_srv_conf_t  *cscf;

    rb = r->request_body;

    out = NULL;
    ll = &out;

    if (rb->rest == -1) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http request body chunked filter");

        rb->chunked = ngx_pcalloc(r->pool, sizeof(ngx_http_chunked_t));
        if (rb->chunked == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

        r->headers_in.content_length_n = 0;
        rb->rest = cscf->large_client_header_buffers.size;
    }

    for (cl = in; cl; cl = cl->next) {

        b = NULL;

        for ( ;; ) {

            ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                           "http body chunked buf "
                           "t:%d f:%d %p, pos %p, size: %z file: %O, size: %O",
                           cl->buf->temporary, cl->buf->in_file,
                           cl->buf->start, cl->buf->pos,
                           cl->buf->last - cl->buf->pos,
                           cl->buf->file_pos,
                           cl->buf->file_last - cl->buf->file_pos);

            rc = ngx_http_parse_chunked(r, cl->buf, rb->chunked, 0);

            if (rc == NGX_OK) {

                /* a chunk has been parsed successfully */

                clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

                if (clcf->client_max_body_size
                    && clcf->client_max_body_size
                       - r->headers_in.content_length_n < rb->chunked->size)
                {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "client intended to send too large chunked "
                                  "body: %O+%O bytes",
                                  r->headers_in.content_length_n,
                                  rb->chunked->size);

                    r->lingering_close = 1;

                    return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
                }

                if (b
                    && rb->chunked->size <= 128
                    && cl->buf->last - cl->buf->pos >= rb->chunked->size)
                {
                    r->headers_in.content_length_n += rb->chunked->size;

                    if (rb->chunked->size < 8) {

                        while (rb->chunked->size) {
                            *b->last++ = *cl->buf->pos++;
                            rb->chunked->size--;
                        }

                    } else {
                        ngx_memmove(b->last, cl->buf->pos, rb->chunked->size);
                        b->last += rb->chunked->size;
                        cl->buf->pos += rb->chunked->size;
                        rb->chunked->size = 0;
                    }

                    continue;
                }

                tl = ngx_chain_get_free_buf(r->pool, &rb->free);
                if (tl == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                b = tl->buf;

                ngx_memzero(b, sizeof(ngx_buf_t));

                b->temporary = 1;
                b->tag = (ngx_buf_tag_t) &ngx_http_read_client_request_body;
                b->start = cl->buf->pos;
                b->pos = cl->buf->pos;
                b->last = cl->buf->last;
                b->end = cl->buf->end;
                b->flush = r->request_body_no_buffering;

                *ll = tl;
                ll = &tl->next;

                size = cl->buf->last - cl->buf->pos;

                if ((off_t) size > rb->chunked->size) {
                    cl->buf->pos += (size_t) rb->chunked->size;
                    r->headers_in.content_length_n += rb->chunked->size;
                    rb->chunked->size = 0;

                } else {
                    rb->chunked->size -= size;
                    r->headers_in.content_length_n += size;
                    cl->buf->pos = cl->buf->last;
                }

                b->last = cl->buf->pos;

                continue;
            }

            if (rc == NGX_DONE) {

                /* a whole response has been parsed successfully */

                rb->rest = 0;

                tl = ngx_chain_get_free_buf(r->pool, &rb->free);
                if (tl == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                b = tl->buf;

                ngx_memzero(b, sizeof(ngx_buf_t));

                b->last_buf = 1;

                *ll = tl;
                ll = &tl->next;

                break;
            }

            if (rc == NGX_AGAIN) {

                /* set rb->rest, amount of data we want to see next time */

                cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

                rb->rest = ngx_max(rb->chunked->length,
                               (off_t) cscf->large_client_header_buffers.size);

                break;
            }

            /* invalid */

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "client sent invalid chunked body");

            return NGX_HTTP_BAD_REQUEST;
        }
    }

    rc = ngx_http_top_request_body_filter(r, out);

    ngx_chain_update_chains(r->pool, &rb->free, &rb->busy, &out,
                            (ngx_buf_tag_t) &ngx_http_read_client_request_body);

    return rc;
}


/**
 * 将in链表中的buf复制到r->request_body->bufs中
 * 
 * 如果允许将请求体缓存到本地文件，则尝试将请求缓存到本地磁盘
 * 
 */
ngx_int_t
ngx_http_request_body_save_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_buf_t                 *b;
    ngx_chain_t               *cl, *tl, **ll;
    ngx_http_request_body_t   *rb;

    rb = r->request_body;

    ll = &rb->bufs;

    //ll指向rb->bufs的最后一个元素
    for (cl = rb->bufs; cl; cl = cl->next) {

#if 0
        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "http body old buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
#endif

        ll = &cl->next; 
    }

    //将in链表中的buf复制到ll
    for (cl = in; cl; cl = cl->next) {

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "http body new buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

        if (cl->buf->last_buf) {

            if (rb->last_saved) {
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                              "duplicate last buf in save filter");
                *ll = NULL;
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            rb->last_saved = 1;
        }

        tl = ngx_alloc_chain_link(r->pool);
        if (tl == NULL) {
            *ll = NULL;
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        tl->buf = cl->buf;
        *ll = tl;
        ll = &tl->next;
    }

    //ll 仍指向最后一个元素
    *ll = NULL;

    //表示不要将请求体缓冲到文件
    if (r->request_body_no_buffering) {
        return NGX_OK;
    }

    ////////此时可以将请求体缓冲到文件中
    if (rb->rest > 0) {     //如果请求体还没有读取完,

        //缓存已经满了
        if (rb->bufs && rb->buf && rb->buf->last == rb->buf->end
            && ngx_http_write_request_body(r) != NGX_OK)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        return NGX_OK;
    }

    if (!rb->last_saved) {
        return NGX_OK;
    }

    //需要将请求体写入临时文件
    if (rb->temp_file || r->request_body_in_file_only) {  

        if (rb->bufs && rb->bufs->buf->in_file) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "body already in file");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        //将请求体写入临时文件
        if (ngx_http_write_request_body(r) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (rb->temp_file->file.offset != 0) {

            cl = ngx_chain_get_free_buf(r->pool, &rb->free);
            if (cl == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            b = cl->buf;

            ngx_memzero(b, sizeof(ngx_buf_t));

            b->in_file = 1;
            b->file_last = rb->temp_file->file.offset;
            b->file = &rb->temp_file->file;

            rb->bufs = cl;
        }
    }

    return NGX_OK;
}
