
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
 * 是一个异步方法
 * 
 * 调用此方法一般不能一次读完请求体，后续触发的可读事件，将由ngx_http_read_client_request_body_handler处理
 * 
 * 
 *  执行流程：
 * 1.原始请求引用计算 r->main->count 增加 1；引用计数 count 的管理是：当逻辑开启流程时，引用计数就增加1，结束此流程时，引用计数就减1。在ngx_http_read_client_request_body 函数中，首先将原始请求的引用计数增加1，当遇到异常终止时，引用计数会在该函数返回之前减1；若正常结束时，引用计数由post_handler回调方法继续维护；
 * 
 * 2.判断当前请求包体是否已被完整接收（r->request_body 为1）或被丢弃（r->discard_body为1），若满足其中一个则不需要再次接收请求包体，直接执行post_handler 回调方法，并NGX_OK 从当前函数返回；
 * 
 * 3.若需要接收 HTTP 请求包体，则首先调用 ngx_http_test_expect 方法，检查客户端是否发送 Expect:100-continue 头部期望发送请求包体，服务器会回复 HTTP/1.1 100 Continue 表示允许客户端发送请求包体；
 * 
 * 4.分配当前请求 ngx_http_request_t 结构体request_body 成员，准备接收请求包体；
 * 
 * 5.检查请求的 content-length 头部，若请求头部的 content-length 字段小于0，则表示不需要继续接收请求包体（即已经接收到完整的请求包体），直接执行post_handler 回调方法，并 NGX_OK 从当前函数返回；
 * 
 * 6.若请求头部的 content-length 字段大于 0，则表示需要继续接收请求包体。首先判断当前请求 ngx_http_request_t 的header_in 成员是否存在未处理数据，若存在未被处理的数据，表示该缓冲区header_in 在接收请求头部期间已经预接收了请求包体，因为在接收HTTP 请求头部期间有可能预接收请求包体，由于在接收请求包体之前，请求头部已经被接收完毕，所以若该缓冲区存在未被处理的数据，那就是请求包体。
 * 
 * 7.若 header_in 缓冲区存在未被处理的数据，即是预接收的请求包体，首先检查缓冲区请求包体长度preread 是否大于请求包体长度的content-length 字段，若大于则表示已经接收到完整的HTTP 请求包体，不需要继续接收，则执行post_handler 回调方法；
 * 
 * 8.若 header_in 缓冲区存在未被处理的数据，即是预接收的请求包体，但是缓冲区请求包体长度preread 小于请求包体长度的content-length 字段，表示已接收的请求包体不完整，则需要继续接收请求包体。调用函数ngx_http_request_body_filte 解析并把已接收的请求包体挂载到请求ngx_http_request_t r 的 request_body->bufs，header_in 缓冲区剩余的空间足够接收剩余的请求包体大小rest，则不需要分配新的缓冲区，进而设置当前请求ngx_http_request_t  的 read_event_handler 读事件回调方法为ngx_http_read_client_request_body_handler，写事件write_event_handler 回调方法为ngx_http_request_empty_handler (即不执行任何操作)，然后调用方法ngx_http_do_read_client_request_body 真正接收HTTP 请求包体，该方法将TCP 连接上的套接字缓冲区中的字符流全部读取出来，并判断是否需要写入到临时文件，以及是否接收全部的请求包体，同时在接收到完整包体后执行回调方法post_handler；
 * 
 * 9.若 header_in 缓冲区存在未被处理的数据，即是预接收的请求包体，但是缓冲区请求包体长度preread 小于请求包体长度的content-length 字段，或者header_in 缓冲区不存在未被处理的数据，且header_in 剩余的空间不足够接收HTTP 请求包体，则会重新分配接收请求包体的缓冲区，再进而设置当前请求ngx_http_request_t 的read_event_handler 读事件回调方法为ngx_http_read_client_request_body_handler，写事件write_event_handler 回调方法为ngx_http_request_empty_handler (即不执行任何操作)，然后调用方法ngx_http_do_read_client_request_body 真正接收HTTP 请求包体；
 * 
 * https://www.kancloud.cn/digest/understandingnginx/202605
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

    /*
     * 当有逻辑开启流程时，引用计数会增加1，此流程结束时，引用计数将减1；
     * 在ngx_http_read_client_request_body方法中，首先将原始请求引用计数增加1，
     * 当遇到异常终止时，则在该函数返回前会将引用计数减1,；
     * 若正常结束时，引用计数由post_handler方法继续维护；
     */
    r->main->count++;       //请求对应的原始请求的引用计数加1

    //如果是子请求、已经读取过请求体了、或者丢弃请求体
    //如果request_body已经被分配过了，证明已经读取过HTTP包体了
    //如果discard_body为1，则证明曾经执行过 丢弃包体的方法，现在包体正在被丢弃中
    if (r != r->main || r->request_body || r->discard_body) {
        r->request_body_no_buffering = 0;
        post_handler(r);        // 直接回调post_handler
        return NGX_OK;
    }

    /*
     * ngx_http_test_expect 用于检查客户端是否发送Expect:100-continue头部，
     * 若客户端已发送该头部表示期望发送请求包体数据，则服务器回复HTTP/1.1 100 Continue；
     * 具体意义是：客户端期望发送请求包体，服务器允许客户端发送，
     * 该函数返回NGX_OK；
     */
    if (ngx_http_test_expect(r) != NGX_OK) {        //处理 Expect请求头
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    //只有在确定要接收请求包体时才分配存储HTTP请求包体的结构体 ngx_http_request_body_t 空间
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

    /* 令当前请求的post_body成员指向存储请求包体结构 */
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

     /* 若指定HTTP请求包体的content_length字段大于0，则表示需要接收包体；*/

    /*
     * 在请求结构ngx_http_request_t 成员中header_in缓冲区保存的是HTTP请求头部，
     * 由于在处理HTTP请求之前，HTTP头部已被完整接收，所以若header_in缓冲区里面
     * 还存在未处理的数据，则证明在接收HTTP请求头部期间，已经预接收了HTTP请求包体；
     */
    //preread是读取请求头时读取到的请求头的长度
    preread = r->header_in->last - r->header_in->pos;

    /*
     * 若header_in缓冲区存在预接收的HTTP请求包体，
     * 则计算还需接收HTTP请求包体的大小rest；
     */
    //处理preread部分数据
    if (preread) {      //如果r->header_in中存在请求体数据

        /* there is the pre-read part of the request body */

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http client request body preread %uz", preread);

        /* 将out的缓冲区指向header_in缓冲区中的请求包体数据 */
        out.buf = r->header_in; //将请求头的buf加到out链表, 当前为链表头
        out.next = NULL;

        /*
         * 将预接收的HTTP请求包体数据添加到r->request_body->bufs中，
         * 即将请求包体存储在新分配的ngx_http_request_body_t rb 结构体的bufs中；
         */
        rc = ngx_http_request_body_filter(r, &out);     //调用ngx_http_request_body_filter处理请求体

        if (rc != NGX_OK) {
            goto done;
        }
        /* 若ngx_http_request_body_filter返回NGX_OK，则继续执行以下程序 */

        //更新已经读取到的数据（r->header_in->last - r->header_in->pos 通常为0， 因为在ngx_http_request_body_filter中已经消费过out了）
        r->request_length += preread - (r->header_in->last - r->header_in->pos);

        /*
         * 若已接收的请求包体不完整，即rest大于0，表示需要继续接收请求包体；
         * 若此时header_in缓冲区仍然有足够的剩余空间接收剩余的请求包体长度，
         * 则不再分配缓冲区内存；
         */
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
            /*
             * 真正开始接收请求包体数据；
             * 将TCP套接字连接缓冲区中当前的字符流全部读取出来，
             * 并判断是否需要写入临时文件，以及是否接收全部的请求包体，
             * 同时在接收到完整包体后执行回调方法post_handler；
             */
            //读取请求体， 数据被读到r->request_body中
            rc = ngx_http_do_read_client_request_body(r);
            goto done;
        }

    } else {
        /*
         * 若在接收HTTP请求头部过程没有预接收HTTP请求包体数据，
         * 或者预接收了不完整的HTTP请求包体，但是header_in缓冲区不够继续存储剩余的包体；
         * 进一步计算待需接收HTTP请求的大小rest；
         */
        //至此说明 没有预读的请求体数据
        /* set rb->rest */

        rc = ngx_http_request_body_filter(r, NULL);

        if (rc != NGX_OK) {
            goto done;
        }
    }

    /* 若rest为0，表示无需继续接收HTTP请求包体，即已接收到完整的HTTP请求包体 */
    if (rb->rest == 0 && rb->last_saved) {      //若已接收完整的HTTP请求包体
        /* the whole request body was pre-read */
        r->request_body_no_buffering = 0;
        post_handler(r);         /* 执行回调方法 */
        return NGX_OK;
    }

    /* rest小于0表示出错 */
    if (rb->rest < 0) {     //非正常状态
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "negative request body rest");
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    /* 若rest大于0，则表示需要继续接收HTTP请求包体数据，执行以下程序 */

    /* 获取ngx_http_core_module模块的loc级别配置项结构 */
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    /* 获取缓存请求包体的buffer缓冲区大小 */
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

    /* 接收请求包体 */
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
 * 
 * 1.检查连接上读事件 timeout 标志位是否超时，若超时则调用函数ngx_http_finalize_request 终止当前请求；
 * 2.若不超时，调用函数 ngx_http_do_read_client_request_body 开始读取HTTP 请求包体数据；
 * 
 */
static void
ngx_http_read_client_request_body_handler(ngx_http_request_t *r)
{
    ngx_int_t  rc;

    /* 检查连接上读事件timeout标志位是否超时，若超时则终止该请求 */
    if (r->connection->read->timedout) {
        r->connection->timedout = 1;
        ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);    //408状态码
        return;
    }

     /* 开始接收HTTP请求包体数据 */
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
 * 
 * 函数执行流程：
 * 1.若 request_body->buf 缓冲区没有剩余的空间，则先调用函数ngx_http_write_request_body 将该缓冲区的数据写入到文件中；此时，该缓冲区就有空间；或者 request_body->buf 缓冲区有剩余的空间；接着分别计算request_body->buf 缓冲区所剩余的可用空间大小 size、待接收 HTTP 请求包体的长度 rest；若当前缓冲区剩余大小足够接收HTTP 请求包体，即size > rest，则调用recv 方法从 TCP 连接套接字缓冲区中读取请求包体数据到当前缓冲区request_body->buf 中，下面根据recv 方法的返回值n 做不同的判断：
 * 2.返回值 n 为 NGX_AGAIN，表示 TCP 连接套接字缓冲区上的字符流未读取完毕，则需继续读取；
 * 3.返回值 n 为 0 或 NGX_ERROR，表示读取失败，设置当前请求的errno 标志位错误编码，并退出；
 * 4.返回值 n 不是以上的值，则表示读取成功，此时，更新当缓冲区request_body->buf的使用情况，更新当前请求的长度。判断已成功读取的长度n 是否等于待接收HTTP 请求包体的长度rest，若n = rest，则将已读取的请求包体挂载到当前请求的request body->buf链表中；并重新更新待接收的剩余请求包体长度rest 值；
 * 5.根据 rest 值判断是否已经接收到完整的 HTTP 请求包体：
 * 6.rest 值大于 0，表示未接收到完整的 HTTP 请求包体，且当前套接字缓冲区已经没有可读数据，则需要调用函数ngx_add_timer 将当前连接的读事件添加到定时器机制，调用函数ngx_handler_read_event 将当前连接读事件注册到epoll 事件机制中，等待可读事件的发生；此时，ngx_http_do_read_client_reuqest_body 返回NGX_AGAIN；
 * 7.rest 等于 0，表示已经接收到完整的 HTTP 请求包体，则把读事件从定时器机制移除，把缓冲区数据写入到文件中，设置读事件的回调方法为ngx_http_block_reading（不进行任何操作），最后执行post_handler 回调方法；
 * 
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

    /* 获取当前请求所对应的连接 */
    c = r->connection;
    /* 获取当前请求的请求包体结构体 */
    rb = r->request_body;
    flush = 1;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http read client request body");

    for ( ;; ) {
        for ( ;; ) {
            if (rb->rest == 0) {     //已经读完了请求体，跳出循环
                break;
            }

            /* 若当前缓冲区buf已满 */
            if (rb->buf->last == rb->buf->end) {

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
                /* 由于已经将当前缓冲区的字符流写入到文件，则该缓冲区有空间继续使用 */
                rb->buf->pos = rb->buf->start;
                rb->buf->last = rb->buf->start;
            }

            //缓冲区未满
            size = rb->buf->end - rb->buf->last;  //size为rb的剩余可用空间
            rest = rb->rest - (rb->buf->last - rb->buf->pos);   //rest为剩余待读取数据

            /* 若当前缓冲区有足够的空间接收剩余的请求包体，则不需要再分配缓冲区 */
            if ((off_t) size > rest) {
                size = (size_t) rest;
            }

            if (size == 0) {
                break;
            }

            /* 从TCP连接套接字读取请求包体，并保存到当前缓冲区 */
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

            /* 读取错误，设置错误编码 */
            if (n == 0 || n == NGX_ERROR) {
                c->error = 1;
                return NGX_HTTP_BAD_REQUEST;
            }

            //正确读取到了数据, 调整当前缓冲区的使用情况
            rb->buf->last += n;
            /* 设置已接收HTTP请求长度 */
            r->request_length += n;

            /* pass buffer to request body filter chain */

            flush = 0;
            out.buf = rb->buf;
            out.next = NULL;

            //将已读取的请求包体数据挂载到r->request_body->bufs中，并重新计算rest值
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
        /*
         * 若未接接收到完整的HTTP请求包体，且当前连接读事件未准备就绪，
         * 则需将读事件添加到定时器机制，注册到epoll事件机制中，等待可读事件发生；
         */
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
        //需要将读事件从定时器机制中移除
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
 * 
 * 执行流程：
 * 1.若当前是子请求，或请求包体已经被完整接收，或请求包体已被丢弃，则不需要继续，直接返回 NGX_OK 结束该函数；
 * 2.调用函数 ngx_http_test_expect 检查客户端是否要发送请求包体，若服务器允许发送，则继续执行；
 * 3.若当前请求连接上的读事件在定时器机制中（即 timer_set 标志位为1），则将该读事件从定时器机制中移除（丢弃请求包体不需要考虑超时问题，除非设置linger_timer）；
 * 4.由于此时，待丢弃包体长度 content_length_n 为请求content-length 头部字段大小，所有判断content-length头部字段是否小于0，若小于0，表示已经成功丢弃完整的请求包体，直接返回NGX_OK；若大于0，表示需要继续丢弃请求包体，则继续执行；
 * 5.检查当前请求的 header_in 缓冲区是否预接收了 HTTP 请求，设此时 header_in 缓冲区里面未处理的数据大小为size，若size 不为0，表示已经预接收了HTTP 请求包体数据，则调用函数ngx_http_discard_request_body_filter 将该请求包体丢弃，并根据已经预接收请求包体长度和请求content-length 头部字段长度，重新计算需要待丢弃请求包体的长度content_length_n 的值；根据ngx_http_discard_request_body_filter 函数的返回值rc 进行不同的判断：
 * 6.若 rc = NGX_OK，且 content_length_n 的值为 0，则表示已经接收到完整请求包体，并将其丢弃；
 * 7.若 rc ！= NGX_OK，则表示需要继续接收请求包体，根据content_length_n 的值来表示待丢弃请求包体的长度；
 * 8.若还需继续丢弃请求包体，则调用函数 ngx_http_read_discard_request_body 读取剩余的请求包体数据，并将其丢弃；并根据该函数返回值rc 不同进行判断：
 * 9.若 rc = NGX_OK，表示已成功丢弃完整的请求包体；
 * 10.若 rc ！= NGX_OK，则表示接收到请求包体依然不完整，且此时连接套接字上已经没有剩余数据可读，则设置当前请求读事件的回调方法read_event_handler 为ngx_http_discarded_request_body_handler，并调用函数ngx_handle_read_event 将该请求连接上的读事件注册到epoll 事件机制中，等待可读事件发生以便继续读取请求包体；同时将引用计数增加1（防止继续丢弃包体），当前请求的discard_body 标志位设置为1，表示正在丢弃，并返回NGX_OK（这里并不表示已经成功丢弃完整的请求包体，只是表示ngx_http_discard_request_body 执行完毕，接下来的是等待读事件发生并继续丢弃包体）；
 * 
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
        /*
         * 丢弃预接收请求包体数据，并根据预接收请求包体大小与请求content-length头部大小，
         * 重新计算content_length_n的值；
         */
        rc = ngx_http_discard_request_body_filter(r, r->header_in);

        /* 若rc不为NGX_OK表示预接收的请求包体数据不完整，需继续接收 */
        if (rc != NGX_OK) {
            return rc;
        }

        /* 若返回rc=NGX_OK，且待丢弃请求包体大小content-length_n为0，表示已丢弃完整的请求包体 */
        if (r->headers_in.content_length_n == 0) {
            return NGX_OK;
        }
    }

    /* 读取剩余的HTTP请求包体数据，并将其丢弃 */
    rc = ngx_http_read_discarded_request_body(r);

    /* 若已经读取到完整请求包体，则返回NGX_OK */
    if (rc == NGX_OK) {
        r->lingering_close = 0;
        return NGX_OK;
    }

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    /* rc == NGX_AGAIN */

     /*
     * 若读取到的请求包体依然不完整，但此时已经没有剩余数据可读，
     * 则将当前请求读事件回调方法设置为ngx_http_discard_request_body_handler，
     * 并将读事件注册到epoll事件机制中，等待可读事件发生以便继续读取请求包体；
     */
    r->read_event_handler = ngx_http_discarded_request_body_handler;

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* 由于已将读事件注册到epoll事件机制中，则引用计数增加1，discard_body标志为1 */
    r->count++;
    r->discard_body = 1;

    return NGX_OK;
}


/**
 * 丢弃请求体时，当前请求读事件回调方法
 * 
 * 1.判断当前请求连接上的读事件是否超时，若超时（即标志位 timeout 为1），则调用函数ngx_http_finalize_request 将引用计数减1，若此时引用计数为0，则终止当前请求；
 * 2.调用函数 ngx_http_read_discarded_request_body 开始读取请求包体，并将所读取的请求包体丢弃；同时根据该函数的返回值rc 不同进行判断：
 * 3.若返回值 rc = NGX_OK，表示已经接收到完整请求包体，并成功将其丢弃，则此时设置discard_body 标志位为0，设置lingering_close 标志位为0，并调用函数ngx_http_finalize_request 结束当前请求；
 * 4.若返回值 rc ！= NGX_OK，则表示读取的请求包体依旧不完整，调用函数ngx_handle_read_event 将读事件注册到epoll 事件机制中，等待可读事件发生；
 * 
 */
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

    /*
     * 判断读事件是否超时，若超时则调用ngx_http_finalize_request方法将引用计数减1，
     * 若此时引用计数是0，则直接终止该请求；
     */
    if (rev->timedout) {
        c->timedout = 1;
        c->error = 1;
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }

     /* 若需要延迟关闭，则设置延迟关闭连接的时间 */
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

     /* 读取剩余请求包体，并将其丢弃 */
    rc = ngx_http_read_discarded_request_body(r);

    /* 若返回rc=NGX_OK，则表示已接收到完整请求包体，并成功将其丢弃 */
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

    /* 若读取的请求包体依旧不完整，则再次将读事件注册到epoll事件机制中 */
    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        c->error = 1;
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }

    /* 若设置了延迟，则将读事件添加到定时器事件机制中 */
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
 * 
 * 执行流程：
 * 1.若待丢弃请求包体长度 content_length_n 为0，表示已经接收到完整请求包体，并成功将其丢弃，则此时，设置读事件的回调方法为ngx_http_block_reading（不进行任何操作），同时返回NGX_OK，表示已成功丢弃完整请求包体；
 * 2.若需要继续丢弃请求包体数据，且此时，连接上套接字缓冲区没有可读数据，即读事件未准备就绪，则返回 NGX_AGAIN，表示需要等待读事件再次被触发时继续读取请求包体并丢弃；
 * 3.调用函数 recv 读取请求包体数据，根据不同返回值 n，进行不同的判断：
 * 4.若返回值 n = NGX_AGAIN，表示读取的请求包体依旧不完整，需要等待下次读事件被触发，继续读取请求包体数据；
 * 5.若 n = NGX_ERROR 或 n = 0，表示客户端主动关闭当前连接，则不需要读取请求包体，即直接返回 NGX_OK，表示结束丢弃包体动作；
 * 6.若返回值 n = NGX_OK，则表示读取请求包体成功，此时调用函数ngx_http_discard_request_body_filter 将已经读取的请求包体丢弃，并更新content_length_n 的值；根据content_length_n 的值进行判断是否继续读取请求包体数据（此时又回到步骤1，因此是一个for 循环），直到读取到完整的请求包体，并将其丢弃，才结束for 循环，并从该函数返回；
 * 
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

         /* 若当前连接的读事件未准备就绪，则不能读取数据，即返回NGX_AGAIN */
        if (!r->connection->read->ready) {      //不可读
            return NGX_AGAIN;
        }

        //本次最多读取的字节数量
        size = (size_t) ngx_min(r->headers_in.content_length_n,
                                NGX_HTTP_DISCARD_BUFFER_SIZE);

        /* 从连接套接字缓冲区读取请求包体数据 */
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

        /* 将读取的完整请求包体丢弃 */
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
