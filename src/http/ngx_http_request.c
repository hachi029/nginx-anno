
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static void ngx_http_wait_request_handler(ngx_event_t *ev);
static ngx_http_request_t *ngx_http_alloc_request(ngx_connection_t *c);
static void ngx_http_process_request_line(ngx_event_t *rev);
static void ngx_http_process_request_headers(ngx_event_t *rev);
static ssize_t ngx_http_read_request_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_alloc_large_header_buffer(ngx_http_request_t *r,
    ngx_uint_t request_line);

static ngx_int_t ngx_http_process_header_line(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_process_unique_header_line(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_process_host(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_process_connection(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_process_user_agent(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);

static ngx_int_t ngx_http_find_virtual_server(ngx_connection_t *c,
    ngx_http_virtual_names_t *virtual_names, ngx_str_t *host,
    ngx_http_request_t *r, ngx_http_core_srv_conf_t **cscfp);

static void ngx_http_request_handler(ngx_event_t *ev);
static void ngx_http_terminate_request(ngx_http_request_t *r, ngx_int_t rc);
static void ngx_http_terminate_handler(ngx_http_request_t *r);
static void ngx_http_finalize_connection(ngx_http_request_t *r);
static ngx_int_t ngx_http_set_write_handler(ngx_http_request_t *r);
static void ngx_http_writer(ngx_http_request_t *r);
static void ngx_http_request_finalizer(ngx_http_request_t *r);

static void ngx_http_set_keepalive(ngx_http_request_t *r);
static void ngx_http_keepalive_handler(ngx_event_t *ev);
static void ngx_http_set_lingering_close(ngx_connection_t *c);
static void ngx_http_lingering_close_handler(ngx_event_t *ev);
static ngx_int_t ngx_http_post_action(ngx_http_request_t *r);
static void ngx_http_log_request(ngx_http_request_t *r);

static u_char *ngx_http_log_error(ngx_log_t *log, u_char *buf, size_t len);
static u_char *ngx_http_log_error_handler(ngx_http_request_t *r,
    ngx_http_request_t *sr, u_char *buf, size_t len);

#if (NGX_HTTP_SSL)
static void ngx_http_ssl_handshake(ngx_event_t *rev);
static void ngx_http_ssl_handshake_handler(ngx_connection_t *c);
#endif


static char *ngx_http_client_errors[] = {

    /* NGX_HTTP_PARSE_INVALID_METHOD */
    "client sent invalid method",

    /* NGX_HTTP_PARSE_INVALID_REQUEST */
    "client sent invalid request",

    /* NGX_HTTP_PARSE_INVALID_VERSION */
    "client sent invalid version",

    /* NGX_HTTP_PARSE_INVALID_09_METHOD */
    "client sent invalid method in HTTP/0.9 request"
};


/**
 * 定义了一些核心的请求头及其处理函数
 */
ngx_http_header_t  ngx_http_headers_in[] = {
    { ngx_string("Host"), offsetof(ngx_http_headers_in_t, host),
                 ngx_http_process_host },

    { ngx_string("Connection"), offsetof(ngx_http_headers_in_t, connection),
                 ngx_http_process_connection },

    { ngx_string("If-Modified-Since"),
                 offsetof(ngx_http_headers_in_t, if_modified_since),
                 ngx_http_process_unique_header_line },

    { ngx_string("If-Unmodified-Since"),
                 offsetof(ngx_http_headers_in_t, if_unmodified_since),
                 ngx_http_process_unique_header_line },

    { ngx_string("If-Match"),
                 offsetof(ngx_http_headers_in_t, if_match),
                 ngx_http_process_unique_header_line },

    { ngx_string("If-None-Match"),
                 offsetof(ngx_http_headers_in_t, if_none_match),
                 ngx_http_process_unique_header_line },

    { ngx_string("User-Agent"), offsetof(ngx_http_headers_in_t, user_agent),
                 ngx_http_process_user_agent },

    { ngx_string("Referer"), offsetof(ngx_http_headers_in_t, referer),
                 ngx_http_process_header_line },

    { ngx_string("Content-Length"),
                 offsetof(ngx_http_headers_in_t, content_length),
                 ngx_http_process_unique_header_line },

    { ngx_string("Content-Range"),
                 offsetof(ngx_http_headers_in_t, content_range),
                 ngx_http_process_unique_header_line },

    { ngx_string("Content-Type"),
                 offsetof(ngx_http_headers_in_t, content_type),
                 ngx_http_process_header_line },

    { ngx_string("Range"), offsetof(ngx_http_headers_in_t, range),
                 ngx_http_process_header_line },

    { ngx_string("If-Range"),
                 offsetof(ngx_http_headers_in_t, if_range),
                 ngx_http_process_unique_header_line },

    { ngx_string("Transfer-Encoding"),
                 offsetof(ngx_http_headers_in_t, transfer_encoding),
                 ngx_http_process_unique_header_line },

    { ngx_string("TE"),
                 offsetof(ngx_http_headers_in_t, te),
                 ngx_http_process_header_line },

    { ngx_string("Expect"),
                 offsetof(ngx_http_headers_in_t, expect),
                 ngx_http_process_unique_header_line },

    { ngx_string("Upgrade"),
                 offsetof(ngx_http_headers_in_t, upgrade),
                 ngx_http_process_header_line },

#if (NGX_HTTP_GZIP || NGX_HTTP_HEADERS)
    { ngx_string("Accept-Encoding"),
                 offsetof(ngx_http_headers_in_t, accept_encoding),
                 ngx_http_process_header_line },

    { ngx_string("Via"), offsetof(ngx_http_headers_in_t, via),
                 ngx_http_process_header_line },
#endif

    { ngx_string("Authorization"),
                 offsetof(ngx_http_headers_in_t, authorization),
                 ngx_http_process_unique_header_line },

    { ngx_string("Keep-Alive"), offsetof(ngx_http_headers_in_t, keep_alive),
                 ngx_http_process_header_line },

#if (NGX_HTTP_X_FORWARDED_FOR)
    { ngx_string("X-Forwarded-For"),
                 offsetof(ngx_http_headers_in_t, x_forwarded_for),
                 ngx_http_process_header_line },
#endif

#if (NGX_HTTP_REALIP)
    { ngx_string("X-Real-IP"),
                 offsetof(ngx_http_headers_in_t, x_real_ip),
                 ngx_http_process_header_line },
#endif

#if (NGX_HTTP_HEADERS)
    { ngx_string("Accept"), offsetof(ngx_http_headers_in_t, accept),
                 ngx_http_process_header_line },

    { ngx_string("Accept-Language"),
                 offsetof(ngx_http_headers_in_t, accept_language),
                 ngx_http_process_header_line },
#endif

#if (NGX_HTTP_DAV)
    { ngx_string("Depth"), offsetof(ngx_http_headers_in_t, depth),
                 ngx_http_process_header_line },

    { ngx_string("Destination"), offsetof(ngx_http_headers_in_t, destination),
                 ngx_http_process_header_line },

    { ngx_string("Overwrite"), offsetof(ngx_http_headers_in_t, overwrite),
                 ngx_http_process_header_line },

    { ngx_string("Date"), offsetof(ngx_http_headers_in_t, date),
                 ngx_http_process_header_line },
#endif

    { ngx_string("Cookie"), offsetof(ngx_http_headers_in_t, cookie),
                 ngx_http_process_header_line },

    { ngx_null_string, 0, NULL }
};


/**
 * 初始化连接结构体。
 * 当一个客户端连接刚建立成功时的逻辑
 * 
 * 执行流程:
 * 1.设置当前连接上写事件的回调方法 handler 为 ngx_http_empty_handler（实际上该方法不进行任何操作）；
 * 2.设置当前连接上读事件的回调方法 handler 为 ngx_http_wait_request_handler；
 * 3.检查当前连接上读事件是否准备就绪（即 ready 标志位为1）：
 * 4.若读事件 ready 标志位为1，表示当前连接上有可读的TCP 流，则执行读事件的回调方法ngx_http_wait_request_handler；
 * 5.若读事件 ready 标志位为0，表示当前连接上没有可读的TCP 流，则将读事件添加到定时器事件机制中（监控可读事件是否超时），同时将读事件注册到epoll 事件机制中，等待可读事件的发生；
 */
void
ngx_http_init_connection(ngx_connection_t *c)
{
    ngx_uint_t                 i;
    ngx_event_t               *rev;
    struct sockaddr_in        *sin;
    ngx_http_port_t           *port;
    ngx_http_in_addr_t        *addr;
    ngx_http_log_ctx_t        *ctx;
    ngx_http_connection_t     *hc;
    ngx_http_core_srv_conf_t  *cscf;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6       *sin6;
    ngx_http_in6_addr_t       *addr6;
#endif

    /* 分配http连接ngx_http_connection_t结构体空间 */
    hc = ngx_pcalloc(c->pool, sizeof(ngx_http_connection_t));
    if (hc == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    c->data = hc;       //hc挂到c->data

    /* find the server configuration for the address:port */

    port = c->listening->servers;

    if (port->naddrs > 1) {

        /*
         * there are several addresses on this port and one of them
         * is an "*:port" wildcard so getsockname() in ngx_http_server_addr()
         * is required to determine a server address
         */

        if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
            ngx_http_close_connection(c);
            return;
        }

        switch (c->local_sockaddr->sa_family) {     //AF_INET6、AF_INET、

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) c->local_sockaddr;

            addr6 = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (ngx_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
                    break;
                }
            }

            hc->addr_conf = &addr6[i].conf;

            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) c->local_sockaddr;

            addr = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (addr[i].addr == sin->sin_addr.s_addr) {
                    break;
                }
            }

            hc->addr_conf = &addr[i].conf;      //设置hc的addr_conf

            break;
        }

    } else {

        switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            addr6 = port->addrs;
            hc->addr_conf = &addr6[0].conf;
            break;
#endif

        default: /* AF_INET */
            addr = port->addrs;
            hc->addr_conf = &addr[0].conf;
            break;
        }
    }

    /* the default server configuration for the address:port */
    //初始使用default_server->ctx
    hc->conf_ctx = hc->addr_conf->default_server->ctx;

    ctx = ngx_palloc(c->pool, sizeof(ngx_http_log_ctx_t));
    if (ctx == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    /* 设置当前连接的日志属性 */
    ctx->connection = c;
    ctx->request = NULL;
    ctx->current_request = NULL;

    c->log->connection = c->number;
    c->log->handler = ngx_http_log_error;
    c->log->data = ctx;
    c->log->action = "waiting for request";

    c->log_error = NGX_ERROR_INFO;

    /* 设置当前连接读、写事件的handler处理方法 */
    rev = c->read;
    rev->handler = ngx_http_wait_request_handler;   //设置连接上的读事件回调

    /* 该方法不执行任何实际操作，只记录日志；
     * 因为处理请求的过程不需要write方法；
     */
    c->write->handler = ngx_http_empty_handler;     //设置连接上的写事件回调,什么也不做

#if (NGX_HTTP_V3)
    if (hc->addr_conf->quic) {
        ngx_http_v3_init_stream(c);
        return;
    }
#endif

#if (NGX_HTTP_SSL)
    if (hc->addr_conf->ssl) {
        hc->ssl = 1;
        c->log->action = "SSL handshaking";
        rev->handler = ngx_http_ssl_handshake;
    }
#endif

    if (hc->addr_conf->proxy_protocol) {
        hc->proxy_protocol = 1;
        c->log->action = "reading PROXY protocol";
    }

    //如果新连接的读事件ngx_event_t结构体中的标志位ready为1，实际上表示这个连接对 应的套接字缓存上已经有用户发来的数据
    //如打开了deferred选项， 内核仅在套接字上确实收到请求时才会通知epoll 调度事件的回调方法
    if (rev->ready) {
        /* the deferred accept(), iocp */

        /*
         * 若使用了负载均衡锁ngx_use_accept_mutex，
         * 则将该读事件添加到待处理事件队列ngx_post_event中，
         * 直到退出锁时，才处理该读事件；
         */
        if (ngx_use_accept_mutex) {
            ngx_post_event(rev, &ngx_posted_events);        //延后处理
            return;
        }

        /* 若没有使用负载均衡锁，则直接处理该读事件；
         * 读事件的处理函数handler为ngx_http_wait_request_handler；
         */
        rev->handler(rev);      //调用事件处理器
        return;
    }

    cscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_core_module);

    /*
     * 若当前连接的读事件未准备就绪，
     * 则将其添加到定时器事件机制，并注册到epoll事件机制中；
     */
    //添加读取header超时定时器
    ngx_add_timer(rev, cscf->client_header_timeout);
    ngx_reusable_connection(c, 1);

    // 将当前连接的读事件注册到epoll事件机制中
    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_http_close_connection(c);
        return;
    }
}


/**
 * 当与客户端间的连接刚建立成功后，将连接上的可读事件回调设置为此方法
 * 当TCP连接上第一次出现可读事件时，将会调用此方法初始化这个HTTP请求
 * 
 * 该函数的功能是初始化HTTP请求，但是它并不会在成功建立连接之后就立刻初始化请求，而是在当前连接所对应的套接字缓冲区上确定接收到来自客户端的实际请求数据时才真正进行初始化工作，这样做可以减少不必要的内存消耗（若当成功建立连接之后，客户端并不进行实际数据通信，而此时Nginx 却因为初始化工作分配内存）
 * 执行流程：
 * 1.首先判断当前读事件是否超时（即读事件的 timedout 标志位是否为1）：
 * 2.若 timedout 标志位为1，表示当前读事件已经超时，则调用ngx_http_close_connection 方法关闭当前连接，return 从当前函数返回；
 * 3.若 timedout 标志位为0，表示当前读事件还未超时，则继续检查当前连接的close标志位；
 * 4.若当前连接的 close 标志位为1，表示当前连接要关闭，则调用ngx_http_close_connection 方法关闭当前连接，return 从当前函数返回；
 * 5.若当前连接的 close 标志位为0，表示不需要关闭当前连接，进而调用recv() 函数尝试从当前连接所对应的套接字缓冲区中接收数据，这个步骤是为了确定客户端是否真正的发送请求数据，以免因为客户端不发送实际请求数据，出现初始化请求而导致内存被消耗。根据所读取的数据情况n 来判断是否要真正进行初始化请求工作：
 * 6.若 n = NGX_AGAIN，表示客户端发起连接请求，但是暂时还没发送实际的数据，则将当前连接上的读事件添加到定时器机制中，同时将读事件注册到epoll 事件机制中，return 从当前函数返回；
 * 7.若 n = NGX_ERROR，表示当前连接出错，则直接调用ngx_http_close_connection 关闭当前连接，return 从当前函数返回；
 * 8.若 n = 0，表示客户端已经主动关闭当前连接，所有服务器端调用ngx_http_close_connection 关闭当前连接，return 从当前函数返回；
 * 9.若 n 大于 0，表示读取到实际的请求数据，因此决定开始初始化当前请求，继续往下执行；
 * 10.调用 ngx_http_create_request 方法构造ngx_http_request_t 请求结构体，并设置到当前连接的data 成员；
 * 11.设置当前读事件的回调方法为 ngx_http_process_request_line，并执行该回调方法开始接收并解析请求行；
 * 
 * 
 */
static void
ngx_http_wait_request_handler(ngx_event_t *rev)
{
    u_char                    *p;
    size_t                     size;
    ssize_t                    n;
    ngx_buf_t                 *b;
    ngx_connection_t          *c;
    ngx_http_connection_t     *hc;
#if (NGX_HTTP_V2)
    ngx_http_v2_srv_conf_t    *h2scf;
#endif
    ngx_http_core_srv_conf_t  *cscf;

     /* 获取读事件所对应的连接ngx_connection_t 对象 */
    c = rev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http wait request handler");

    if (rev->timedout) {        //如果是超时时间，关闭连接诶
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        ngx_http_close_connection(c);
        return;
    }

    /* 若当前读事件所对应的连接设置关闭连接标志位，则关闭该链接 */
    if (c->close) {     //如果已经关闭了
        ngx_http_close_connection(c);
        return;
    }

    /* 若当前读事件不超时，且其所对应的连接不设置close标志位，则继续指向以下语句 */
    hc = c->data;       //ngx_connection_t->data是ngx_http_connection_t
    /* 获取当前读事件请求的相关配置项结构 */
    cscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_core_module);

    //https://nginx.org/en/docs/http/ngx_http_core_module.html#client_header_buffer_size
    //Sets buffer size for reading client request header
    size = cscf->client_header_buffer_size;

    b = c->buffer;

    //初始化连接上的buffer
    if (b == NULL) {        //若当前连接的接收缓冲区不存在，则创建该接收缓冲区
        b = ngx_create_temp_buf(c->pool, size);
        if (b == NULL) {
            ngx_http_close_connection(c);
            return;
        }

        c->buffer = b;

    } else if (b->start == NULL) {

        /* 若当前接收缓冲区存在，但是为空，则为其分配内存 */
        b->start = ngx_palloc(c->pool, size);
        if (b->start == NULL) {
            ngx_http_close_connection(c);
            return;
        }

         /* 初始化接收缓冲区各成员指针 */
        b->pos = b->start;
        b->last = b->start;
        b->end = b->last + size;
    }

    size = b->end - b->last;

     /* 在当前连接上开始接收HTTP请求数据 */
    //接收数据,最多接收buffer的剩余空间大小的字节
    n = c->recv(c, b->last, size);

    if (n == NGX_AGAIN) {       //当前暂时没有数据可读

        if (!rev->timer_set) {  //如果没有设置定时器，添加读超时定时器
            //ngx_event_add_timer 会将rev->timer_set设置为1
            ngx_add_timer(rev, cscf->client_header_timeout);
            ngx_reusable_connection(c, 1);
        }

        //将读事件添加到epoll中
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_http_close_connection(c);
            return;
        }

        //b中没数据，暂时将其占用的buffer内存释放掉，避免大量无数据的连接占用过多内存
        if (b->pos == b->last) {

            /*
             * We are trying to not hold c->buffer's memory for an
             * idle connection.
             */

            if (ngx_pfree(c->pool, b->start) == NGX_OK) {
                b->start = NULL;
            }
        }

        return;
    }

    if (n == NGX_ERROR) {   //接收数据出错
        ngx_http_close_connection(c);
        return;
    }

    if (n == 0) {   //未读取到数据
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "client closed connection");
        ngx_http_close_connection(c);
        return;
    }

    //正常读取到了数据
    b->last += n;

    /* 若接收HTTP请求数据成功，则调整接收缓冲区成员指针 */
    if (hc->proxy_protocol) {       //正常为0, 可通过nginx.conf 配置启用
        hc->proxy_protocol = 0;

        //尝试读取proxy协议头
        p = ngx_proxy_protocol_read(c, b->pos, b->last);

        if (p == NULL) {    //读取失败
            ngx_http_close_connection(c);
            return;
        }

        b->pos = p;

        if (b->pos == b->last) {
            c->log->action = "waiting for request";
            b->pos = b->start;
            b->last = b->start;
            ngx_post_event(rev, &ngx_posted_events);
            return;
        }
    }

#if (NGX_HTTP_V2)

    h2scf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_v2_module);

    if (!hc->ssl && (h2scf->enable || hc->addr_conf->http2)) {

        size = ngx_min(sizeof(NGX_HTTP_V2_PREFACE) - 1,
                       (size_t) (b->last - b->pos));

        if (ngx_memcmp(b->pos, NGX_HTTP_V2_PREFACE, size) == 0) {

            if (size == sizeof(NGX_HTTP_V2_PREFACE) - 1) {
                ngx_http_v2_init(rev);
                return;
            }

            ngx_post_event(rev, &ngx_posted_events);
            return;
        }
    }

#endif

    c->log->action = "reading client request line";

    ngx_reusable_connection(c, 0);

     /* 为当前连接创建一个请求结构体ngx_http_request_t */
    //此时将c->data设置为ngx_http_request_t结构体
    c->data = ngx_http_create_request(c);       //创建ngx_http_request_t结构体
    if (c->data == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    //将读事件的回调设置为ngx_http_process_request_line
    rev->handler = ngx_http_process_request_line;
    /* 执行该读事件的处理方法ngx_http_process_request_line，接收HTTP请求行 */
    ngx_http_process_request_line(rev);
}


/**
 * 当第一次从TCP连接上读取到数据时，调用此方法创建ngx_http_request_t结构体
 * 
 * 主要还是调用ngx_http_alloc_request开创建一个ngx_http_request_t实例
 */
ngx_http_request_t *
ngx_http_create_request(ngx_connection_t *c)
{
    ngx_http_request_t        *r;
    ngx_http_log_ctx_t        *ctx;
    ngx_http_core_loc_conf_t  *clcf;

    //创建并初始化ngx_http_request_t结构体
    r = ngx_http_alloc_request(c);
    if (r == NULL) {
        return NULL;
    }

    c->requests++;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_set_connection_log(c, clcf->error_log);

    ctx = c->log->data;
    ctx->request = r;
    ctx->current_request = r;

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_reading, 1);
    r->stat_reading = 1;
    (void) ngx_atomic_fetch_add(ngx_stat_requests, 1);
#endif

    return r;
}


/**
 * 创建并初始化ngx_http_request_t结构体
 */
static ngx_http_request_t *
ngx_http_alloc_request(ngx_connection_t *c)
{
    ngx_pool_t                 *pool;
    ngx_time_t                 *tp;
    ngx_http_request_t         *r;
    ngx_http_connection_t      *hc;
    ngx_http_core_srv_conf_t   *cscf;
    ngx_http_core_main_conf_t  *cmcf;

    hc = c->data;

    cscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_core_module);

    //初始pool大小 https://nginx.org/en/docs/http/ngx_http_core_module.html#request_pool_size
    //请求结束时（连接可能会被复用）该内存池中分配的内存都会及时回收
    pool = ngx_create_pool(cscf->request_pool_size, c->log);
    if (pool == NULL) {
        return NULL;
    }

    //创建ngx_http_request_t结构体
    r = ngx_pcalloc(pool, sizeof(ngx_http_request_t));
    if (r == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    r->pool = pool;

    r->http_connection = hc;
    r->signature = NGX_HTTP_MODULE;
    r->connection = c;

    //表示这个请求对应的main、srv、loc级别的配置项，实际上只是默认配置
    r->main_conf = hc->conf_ctx->main_conf;
    r->srv_conf = hc->conf_ctx->srv_conf;
    r->loc_conf = hc->conf_ctx->loc_conf;

    r->read_event_handler = ngx_http_block_reading;

    r->header_in = hc->busy ? hc->busy->buf : c->buffer;

    //初始化请求结构体的部分容器  headers_out
    if (ngx_list_init(&r->headers_out.headers, r->pool, 20,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        ngx_destroy_pool(r->pool);
        return NULL;
    }

    //
    if (ngx_list_init(&r->headers_out.trailers, r->pool, 4,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        ngx_destroy_pool(r->pool);
        return NULL;
    }

    //每个HTTP模块都可以针对一个请求设置上下文结构体, 并通过 ngx_http_set_ctx和ngx_http_get_module_ctx宏来设置和获取上下文
    //此处分配保存每个模块的上下文结构体的数组
    r->ctx = ngx_pcalloc(r->pool, sizeof(void *) * ngx_http_max_module);
    if (r->ctx == NULL) {
        ngx_destroy_pool(r->pool);
        return NULL;
    }

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    //分配保存变量值variables的数组
    // 缓存变量值的 variables数组下标，与全局唯一的、索引化的、表示变量名的数组 cmcf->variables下标，它们是一一对应的
    r->variables = ngx_pcalloc(r->pool, cmcf->variables.nelts
                                        * sizeof(ngx_http_variable_value_t));
    if (r->variables == NULL) {
        ngx_destroy_pool(r->pool);
        return NULL;
    }

#if (NGX_HTTP_SSL)
    if (c->ssl && !c->ssl->sendfile) {
        r->main_filter_need_in_memory = 1;
    }
#endif

    r->main = r;    //表示当前请求是主请求
    r->count = 1;

    tp = ngx_timeofday();
    r->start_sec = tp->sec;     //请求开始时间sec
    r->start_msec = tp->msec;   //请求开始时间msec

    //初始化r重要字段
    r->method = NGX_HTTP_UNKNOWN;
    r->http_version = NGX_HTTP_VERSION_10;

    r->headers_in.content_length_n = -1;
    r->headers_in.keep_alive_n = -1;
    r->headers_out.content_length_n = -1;
    r->headers_out.last_modified_time = -1;

    r->uri_changes = NGX_HTTP_MAX_URI_CHANGES + 1; //11
    r->subrequests = NGX_HTTP_MAX_SUBREQUESTS + 1;  //50

    r->http_state = NGX_HTTP_READING_REQUEST_STATE;

    r->log_handler = ngx_http_log_error_handler;

    return r;
}


#if (NGX_HTTP_SSL)

static void
ngx_http_ssl_handshake(ngx_event_t *rev)
{
    u_char                    *p, buf[NGX_PROXY_PROTOCOL_MAX_HEADER + 1];
    size_t                     size;
    ssize_t                    n;
    ngx_err_t                  err;
    ngx_int_t                  rc;
    ngx_connection_t          *c;
    ngx_http_connection_t     *hc;
    ngx_http_ssl_srv_conf_t   *sscf;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_core_srv_conf_t  *cscf;

    c = rev->data;
    hc = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                   "http check ssl handshake");

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        ngx_http_close_connection(c);
        return;
    }

    if (c->close) {
        ngx_http_close_connection(c);
        return;
    }

    size = hc->proxy_protocol ? sizeof(buf) : 1;

    n = recv(c->fd, (char *) buf, size, MSG_PEEK);

    err = ngx_socket_errno;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, rev->log, 0, "http recv(): %z", n);

    if (n == -1) {
        if (err == NGX_EAGAIN) {
            rev->ready = 0;

            if (!rev->timer_set) {
                cscf = ngx_http_get_module_srv_conf(hc->conf_ctx,
                                                    ngx_http_core_module);
                ngx_add_timer(rev, cscf->client_header_timeout);
                ngx_reusable_connection(c, 1);
            }

            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                ngx_http_close_connection(c);
            }

            return;
        }

        ngx_connection_error(c, err, "recv() failed");
        ngx_http_close_connection(c);

        return;
    }

    if (hc->proxy_protocol) {
        hc->proxy_protocol = 0;

        p = ngx_proxy_protocol_read(c, buf, buf + n);

        if (p == NULL) {
            ngx_http_close_connection(c);
            return;
        }

        size = p - buf;

        if (c->recv(c, buf, size) != (ssize_t) size) {
            ngx_http_close_connection(c);
            return;
        }

        c->log->action = "SSL handshaking";

        if (n == (ssize_t) size) {
            ngx_post_event(rev, &ngx_posted_events);
            return;
        }

        n = 1;
        buf[0] = *p;
    }

    if (n == 1) {
        if (buf[0] & 0x80 /* SSLv2 */ || buf[0] == 0x16 /* SSLv3/TLSv1 */) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                           "https ssl handshake: 0x%02Xd", buf[0]);

            clcf = ngx_http_get_module_loc_conf(hc->conf_ctx,
                                                ngx_http_core_module);

            if (clcf->tcp_nodelay && ngx_tcp_nodelay(c) != NGX_OK) {
                ngx_http_close_connection(c);
                return;
            }

            sscf = ngx_http_get_module_srv_conf(hc->conf_ctx,
                                                ngx_http_ssl_module);

            if (ngx_ssl_create_connection(&sscf->ssl, c, NGX_SSL_BUFFER)
                != NGX_OK)
            {
                ngx_http_close_connection(c);
                return;
            }

            ngx_reusable_connection(c, 0);

            rc = ngx_ssl_handshake(c);

            if (rc == NGX_AGAIN) {

                if (!rev->timer_set) {
                    cscf = ngx_http_get_module_srv_conf(hc->conf_ctx,
                                                        ngx_http_core_module);
                    ngx_add_timer(rev, cscf->client_header_timeout);
                }

                c->ssl->handler = ngx_http_ssl_handshake_handler;
                return;
            }

            ngx_http_ssl_handshake_handler(c);

            return;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0, "plain http");

        c->log->action = "waiting for request";

        rev->handler = ngx_http_wait_request_handler;
        ngx_http_wait_request_handler(rev);

        return;
    }

    ngx_log_error(NGX_LOG_INFO, c->log, 0, "client closed connection");
    ngx_http_close_connection(c);
}


static void
ngx_http_ssl_handshake_handler(ngx_connection_t *c)
{
    if (c->ssl->handshaked) {

        /*
         * The majority of browsers do not send the "close notify" alert.
         * Among them are MSIE, old Mozilla, Netscape 4, Konqueror,
         * and Links.  And what is more, MSIE ignores the server's alert.
         *
         * Opera and recent Mozilla send the alert.
         */

        c->ssl->no_wait_shutdown = 1;

#if (NGX_HTTP_V2                                                              \
     && defined TLSEXT_TYPE_application_layer_protocol_negotiation)
        {
        unsigned int             len;
        const unsigned char     *data;
        ngx_http_connection_t   *hc;
        ngx_http_v2_srv_conf_t  *h2scf;

        hc = c->data;

        h2scf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_v2_module);

        if (h2scf->enable || hc->addr_conf->http2) {

            SSL_get0_alpn_selected(c->ssl->connection, &data, &len);

            if (len == 2 && data[0] == 'h' && data[1] == '2') {
                ngx_http_v2_init(c->read);
                return;
            }
        }
        }
#endif

        c->log->action = "waiting for request";

        c->read->handler = ngx_http_wait_request_handler;
        /* STUB: epoll edge */ c->write->handler = ngx_http_empty_handler;

        ngx_reusable_connection(c, 1);

        ngx_http_wait_request_handler(c->read);

        return;
    }

    if (c->read->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
    }

    ngx_http_close_connection(c);
}


#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

int
ngx_http_ssl_servername(ngx_ssl_conn_t *ssl_conn, int *ad, void *arg)
{
    ngx_int_t                  rc;
    ngx_str_t                  host;
    const char                *servername;
    ngx_connection_t          *c;
    ngx_http_connection_t     *hc;
    ngx_http_ssl_srv_conf_t   *sscf;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_core_srv_conf_t  *cscf;

    c = ngx_ssl_get_connection(ssl_conn);

    if (c->ssl->handshaked) {
        *ad = SSL_AD_NO_RENEGOTIATION;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    hc = c->data;

    servername = SSL_get_servername(ssl_conn, TLSEXT_NAMETYPE_host_name);

    if (servername == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "SSL server name: null");
        goto done;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "SSL server name: \"%s\"", servername);

    host.len = ngx_strlen(servername);

    if (host.len == 0) {
        goto done;
    }

    host.data = (u_char *) servername;

    rc = ngx_http_validate_host(&host, c->pool, 1);

    if (rc == NGX_ERROR) {
        goto error;
    }

    if (rc == NGX_DECLINED) {
        goto done;
    }

    rc = ngx_http_find_virtual_server(c, hc->addr_conf->virtual_names, &host,
                                      NULL, &cscf);

    if (rc == NGX_ERROR) {
        goto error;
    }

    if (rc == NGX_DECLINED) {
        goto done;
    }

    sscf = ngx_http_get_module_srv_conf(cscf->ctx, ngx_http_ssl_module);

#if (defined TLS1_3_VERSION                                                   \
     && !defined LIBRESSL_VERSION_NUMBER && !defined OPENSSL_IS_BORINGSSL)

    /*
     * SSL_SESSION_get0_hostname() is only available in OpenSSL 1.1.1+,
     * but servername being negotiated in every TLSv1.3 handshake
     * is only returned in OpenSSL 1.1.1+ as well
     */

    if (sscf->verify) {
        const char  *hostname;

        hostname = SSL_SESSION_get0_hostname(SSL_get0_session(ssl_conn));

        if (hostname != NULL && ngx_strcmp(hostname, servername) != 0) {
            c->ssl->handshake_rejected = 1;
            *ad = SSL_AD_ACCESS_DENIED;
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        }
    }

#endif

    hc->ssl_servername = ngx_palloc(c->pool, sizeof(ngx_str_t));
    if (hc->ssl_servername == NULL) {
        goto error;
    }

    *hc->ssl_servername = host;

    hc->conf_ctx = cscf->ctx;

    clcf = ngx_http_get_module_loc_conf(hc->conf_ctx, ngx_http_core_module);

    ngx_set_connection_log(c, clcf->error_log);

    c->ssl->buffer_size = sscf->buffer_size;

    if (sscf->ssl.ctx) {
        if (SSL_set_SSL_CTX(ssl_conn, sscf->ssl.ctx) == NULL) {
            goto error;
        }

        /*
         * SSL_set_SSL_CTX() only changes certs as of 1.0.0d
         * adjust other things we care about
         */

        SSL_set_verify(ssl_conn, SSL_CTX_get_verify_mode(sscf->ssl.ctx),
                       SSL_CTX_get_verify_callback(sscf->ssl.ctx));

        SSL_set_verify_depth(ssl_conn, SSL_CTX_get_verify_depth(sscf->ssl.ctx));

#if OPENSSL_VERSION_NUMBER >= 0x009080dfL
        /* only in 0.9.8m+ */
        SSL_clear_options(ssl_conn, SSL_get_options(ssl_conn) &
                                    ~SSL_CTX_get_options(sscf->ssl.ctx));
#endif

        SSL_set_options(ssl_conn, SSL_CTX_get_options(sscf->ssl.ctx));

#ifdef SSL_OP_NO_RENEGOTIATION
        SSL_set_options(ssl_conn, SSL_OP_NO_RENEGOTIATION);
#endif

#ifdef SSL_OP_ENABLE_MIDDLEBOX_COMPAT
#if (NGX_HTTP_V3)
        if (c->listening->quic) {
            SSL_clear_options(ssl_conn, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
        }
#endif
#endif
    }

done:

    sscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_ssl_module);

    if (sscf->reject_handshake) {
        c->ssl->handshake_rejected = 1;
        *ad = SSL_AD_UNRECOGNIZED_NAME;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    return SSL_TLSEXT_ERR_OK;

error:

    *ad = SSL_AD_INTERNAL_ERROR;
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

#endif


#ifdef SSL_R_CERT_CB_ERROR

int
ngx_http_ssl_certificate(ngx_ssl_conn_t *ssl_conn, void *arg)
{
    ngx_str_t                  cert, key;
    ngx_uint_t                 i, nelts;
    ngx_connection_t          *c;
    ngx_http_request_t        *r;
    ngx_http_ssl_srv_conf_t   *sscf;
    ngx_http_complex_value_t  *certs, *keys;

    c = ngx_ssl_get_connection(ssl_conn);

    if (c->ssl->handshaked) {
        return 0;
    }

    r = ngx_http_alloc_request(c);
    if (r == NULL) {
        return 0;
    }

    r->logged = 1;

    sscf = arg;

    nelts = sscf->certificate_values->nelts;
    certs = sscf->certificate_values->elts;
    keys = sscf->certificate_key_values->elts;

    for (i = 0; i < nelts; i++) {

        if (ngx_http_complex_value(r, &certs[i], &cert) != NGX_OK) {
            goto failed;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "ssl cert: \"%s\"", cert.data);

        if (ngx_http_complex_value(r, &keys[i], &key) != NGX_OK) {
            goto failed;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "ssl key: \"%s\"", key.data);

        if (ngx_ssl_connection_certificate(c, r->pool, &cert, &key,
                                           sscf->certificate_cache,
                                           sscf->passwords)
            != NGX_OK)
        {
            goto failed;
        }
    }

    ngx_http_free_request(r, 0);
    c->log->action = "SSL handshaking";
    c->destroyed = 0;
    return 1;

failed:

    ngx_http_free_request(r, 0);
    c->log->action = "SSL handshaking";
    c->destroyed = 0;
    return 0;
}

#endif

#endif


/**
 * 当TCP连接上第一次出现可读事件时，调用此方法开始接收并解析 HTTP 请求行
 * 在 HTTP 协议中我们可以知道，请求行的长度并不是固定的，它与URI 长度相关，若当内核套接字缓冲区不能一次性完整的接收HTTP 请求行时，会多次调用ngx_http_process_request_line 方法继续接收，即ngx_http_process_request_line 方法重新作为当前连接上读事件的回调方法，必要时将读事件添加到定时器机制，注册到epoll 事件机制，直到接收并解析出完整的HTTP 请求行
 * 执行流程：
 * 1.首先，判断当前请求是否超时，若超时（即读事件的 timedout 标志位为1），则设置当前连接的超时标志位为1（c->timedout = 1），调用ngx_http_close_request 方法关闭该请求，并return 从当前函数返回；
 * 2.若当前请求未超时（读事件的 timedout 标志位为 0），调用 ngx_http_read_request_header 方法开始读取当前请求行，根据该函数的返回值n 进行以下判断：
 * 3.若返回值 n = NGX_AGAIN，表示当前连接上套接字缓冲区不存在可读TCP 流，则需将当前读事件添加到定时器机制，注册到epoll 事件机制中，等待可读事件发生。return 从当前函数返回；
 * 4.若返回值 n = NGX_ERROR，表示当前连接出错，则调用ngx_http_finalize_request 方法结束请求，return 从当前函数返回；
 * 5.若返回值 n 大于 0，表示读取请求行成功，调用函数 ngx_http_parse_request_line 开始解析由函数ngx_http_read_request_header 读取所返回的请求行，根据函数ngx_http_parse_request_line 函数返回值rc 不同进行判断；
 * 6.若返回值 rc = NGX_ERROR，表示解析请求行时出错，此时，调用ngx_http_finalize_request 方法终止该请求，并return 从当前函数返回；
 * 7.若返回值 rc = NGX_AGAIN，表示没有解析到完整的请求行，即仍需接收请求行，首先根据要求调整接收缓冲区header_in 的内存空间，则继续调用函数ngx_http_read_request_header 读取请求数据进入请求行自动处理机制，直到请求行解析完毕；
 * 8.若返回值 rc = NGX_OK，表示解析到完整的 HTTP 请求行，则设置请求行的成员信息（例如：方法名称、URI 参数、HTTP 版本等信息）；
 * 9.若 HTTP 协议版本小于 1.0 版本，表示不需要处理 HTTP 请求头部，则直接调用函数ngx_http_process_request 处理该请求，return 从当前函数返回；
 * 10.若HTTP协议版本不小于 1.0 版本，表示需要处理HTTP请求头部：
 * 11.调用函数 ngx_list_init 初始化保存 HTTP 请求头部的结构体 ngx_http_request_t 中成员headers_in 链表容器（该链表缓冲区是保存所接收到的HTTP 请求数据）；
 * 12.设置当前读事件的回调方法为 ngx_http_process_request_headers 方法，并调用该方法ngx_http_process_request_headers 开始处理HTTP 请求头部。return 从当前函数返回；
 * 
 * 此方法可能或被多次调用
 */
static void
ngx_http_process_request_line(ngx_event_t *rev)
{
    ssize_t              n;
    ngx_int_t            rc, rv;
    ngx_str_t            host;
    ngx_connection_t    *c;
    ngx_http_request_t  *r;

    /* 获取当前读事件所对应的连接 */
    c = rev->data;
    /* 获取连接中所对应的请求结构 */
    r = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                   "http process request line");

    /* 若当前读事件超时，则进行相应地处理，并关闭当前请求 */
    //读事件是否已经超时，超时事件仍然是client_header_timeout
    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_http_close_request(r, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    /* 设置NGX_AGAIN标志，表示请求行还没解析完毕 */
    rc = NGX_AGAIN;

    for ( ;; ) {

        /* 若请求行还没解析完毕，则继续解析 */
        if (rc == NGX_AGAIN) {
            //内核套接字缓冲区中的TCP流复制到header_in缓冲区
            n = ngx_http_read_request_header(r);

            /* 若没有数据，或读取失败，则直接退出 */
            if (n == NGX_AGAIN || n == NGX_ERROR) {
                break;
            }
        }

        //解析请求行
        //* 1. 返回NGX_OK表示成功地解析到完整的HTTP请求行
        //* 2. 返回NGX_AGAIN表示目前接收到的字符流不足以构成完成的请求行，还需要接收更多的字符流
        //* 3. 返回NGX_HTTP_PARSE_INVALID_REQUEST或者NGX_HTTP_PARSE_INVALID_09_METHOD等其他值时表示接收到非法的请求行
        rc = ngx_http_parse_request_line(r, r->header_in);

        if (rc == NGX_OK) {   //1.成功地接收到完整的请求行，赋值r相关字段

            /* the request line has been parsed successfully */

            /* 设置请求行的成员，请求行是ngx_str_t类型 */
            r->request_line.len = r->request_end - r->request_start;
            r->request_line.data = r->request_start;
            /* 设置请求长度，包括请求头部、请求包体 */
            r->request_length = r->header_in->pos - r->request_start;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http request line: \"%V\"", &r->request_line);

            /* 设置请求方法名称字符串 */
            r->method_name.len = r->method_end - r->request_start + 1;
            r->method_name.data = r->request_line.data;

            /* 设置HTTP请求协议 */
            if (r->http_protocol.data) {
                r->http_protocol.len = r->request_end - r->http_protocol.data;
            }

            // 解析请求url、args、exten
            if (ngx_http_process_request_uri(r) != NGX_OK) {
                break;
            }

            if (r->schema_end) {
                r->schema.len = r->schema_end - r->schema_start;
                r->schema.data = r->schema_start;
            }

            if (r->host_end) {

                host.len = r->host_end - r->host_start;
                host.data = r->host_start;

                rc = ngx_http_validate_host(&host, r->pool, 0);

                if (rc == NGX_DECLINED) {
                    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                                  "client sent invalid host in request line");
                    ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
                    break;
                }

                if (rc == NGX_ERROR) {
                    ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                    break;
                }

                if (ngx_http_set_virtual_server(r, &host) == NGX_ERROR) {
                    break;
                }

                r->headers_in.server = host;
            }

            //如果是HTTP/0.9版本, 没有解析header这一步
            if (r->http_version < NGX_HTTP_VERSION_10) { 

                if (r->headers_in.server.len == 0
                    && ngx_http_set_virtual_server(r, &r->headers_in.server)
                       == NGX_ERROR)
                {
                    break;
                }

                //由于不需要再次接收HTTP头部，调用 ngx_http_process_request方法开始处理请求（
                ngx_http_process_request(r);
                break;
            }


            /* 初始化headers_in链表容器，为接收HTTP请求头部做准备 */
            if (ngx_list_init(&r->headers_in.headers, r->pool, 20,
                              sizeof(ngx_table_elt_t))
                != NGX_OK)
            {
                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                break;
            }

            c->log->action = "reading client request headers";

            //将读事件的回调设置为ngx_http_process_request_headers, 接下来处理请求头部
            rev->handler = ngx_http_process_request_headers;
            //开始解析请求头
            ngx_http_process_request_headers(rev);

            break;
        }

        /* 解析请求行出错 */
        if (rc != NGX_AGAIN) {  //2.返回NGX_HTTP_PARSE_INVALID_REQUEST或者NGX_HTTP_PARSE_INVALID_09_METHOD等其他值时表示接收到非法的请求行

            /* there was error while a request line parsing */

            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          ngx_http_client_errors[rc - NGX_HTTP_CLIENT_ERROR]);

            if (rc == NGX_HTTP_PARSE_INVALID_VERSION) {
                ngx_http_finalize_request(r, NGX_HTTP_VERSION_NOT_SUPPORTED);

            } else {
                ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
            }

            break;
        }

        /* NGX_AGAIN: a request line parsing is still incomplete */

        //3.返回NGX_AGAIN还需要接收更多的字符流
        if (r->header_in->pos == r->header_in->end) {   //如果缓冲区满了

            //分配更大的缓冲区存放请求行
            rv = ngx_http_alloc_large_header_buffer(r, 1);

            if (rv == NGX_ERROR) {
                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                break;
            }

            if (rv == NGX_DECLINED) {
                r->request_line.len = r->header_in->end - r->request_start;
                r->request_line.data = r->request_start;

                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client sent too long URI");
                ngx_http_finalize_request(r, NGX_HTTP_REQUEST_URI_TOO_LARGE);
                break;
            }
        }
    }

    ngx_http_run_posted_requests(c);
}


/**
 * 解析请求url、args、exten
 */
ngx_int_t
ngx_http_process_request_uri(ngx_http_request_t *r)
{
    ngx_http_core_srv_conf_t  *cscf;

    if (r->args_start) {
        r->uri.len = r->args_start - 1 - r->uri_start;
    } else {
        r->uri.len = r->uri_end - r->uri_start;
    }

    if (r->complex_uri || r->quoted_uri || r->empty_path_in_uri) {

        if (r->empty_path_in_uri) {
            r->uri.len++;
        }

        r->uri.data = ngx_pnalloc(r->pool, r->uri.len);
        if (r->uri.data == NULL) {
            ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_ERROR;
        }

        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

        if (ngx_http_parse_complex_uri(r, cscf->merge_slashes) != NGX_OK) {
            r->uri.len = 0;

            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent invalid request");
            ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
            return NGX_ERROR;
        }

    } else {
        r->uri.data = r->uri_start;
    }

    r->unparsed_uri.len = r->uri_end - r->uri_start;
    r->unparsed_uri.data = r->uri_start;

    r->valid_unparsed_uri = r->empty_path_in_uri ? 0 : 1;

    if (r->uri_ext) {
        if (r->args_start) {
            r->exten.len = r->args_start - 1 - r->uri_ext;
        } else {
            r->exten.len = r->uri_end - r->uri_ext;
        }

        r->exten.data = r->uri_ext;
    }

    if (r->args_start && r->uri_end > r->args_start) {
        r->args.len = r->uri_end - r->args_start;
        r->args.data = r->args_start;
    }

#if (NGX_WIN32)
    {
    u_char  *p, *last;

    p = r->uri.data;
    last = r->uri.data + r->uri.len;

    while (p < last) {

        if (*p++ == ':') {

            /*
             * this check covers "::$data", "::$index_allocation" and
             * ":$i30:$index_allocation"
             */

            if (p < last && *p == '$') {
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                              "client sent unsafe win32 URI");
                ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
                return NGX_ERROR;
            }
        }
    }

    p = r->uri.data + r->uri.len - 1;

    while (p > r->uri.data) {

        if (*p == ' ') {
            p--;
            continue;
        }

        if (*p == '.') {
            p--;
            continue;
        }

        break;
    }

    if (p != r->uri.data + r->uri.len - 1) {
        r->uri.len = p + 1 - r->uri.data;
        ngx_http_set_exten(r);
    }

    }
#endif

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http uri: \"%V\"", &r->uri);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http args: \"%V\"", &r->args);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http exten: \"%V\"", &r->exten);

    return NGX_OK;
}


/**
 * 接收并解析请求头,也是需要使用状态机来解析的
 * 解析完请求行后，设置此方法可读事件的回调来接收并解析请求头，可能被反复调用
 * 
 * 当最初分配的大小为client_header_buffer_size的缓冲区且无法容纳下完整的HTTP请求行 或者头部时，
 * 会再次分配大小为large_client_header_buffers（这两个值皆为nginx.conf文件中指 定的配置项）的缓冲区，
 * 同时会将原先缓冲区的内容复制到新的缓冲区中。
 * 所以，这意味着 可变长度的HTTP请求行加上HTTP头部的长度总和不能超过large_client_header_buffers指定的字节数，
 * 否则Nginx将会报错
 * 执行流程：
 * 
 * 
 * 1.首先，判断当前请求读事件是否超时，若超时（即读事件的 timedout 标志位为1），则设置当前连接超时标志位为1（c->timedout = 1），并调用ngx_http_close_request 方法关闭该请求，并return 从当前函数返回；
 * 2.若当前请求读事件未超时（即读事件的 timedout 标志位为0），检查接收HTTP 请求头部的header_in 缓冲区是否有剩余内存空间，若没有剩余的内存空间，则调用ngx_http_alloc_large_header_buffer 方法分配更大的缓冲区。若有剩余的内存，则无需再分配内存空间。
 * 3.调用 ngx_http_read_request_header 方法开始读取当前请求头部保存到header_in 缓冲区中，根据该函数的返回值 n 进行以下判断：
 * 4.若返回值 n = NGX_AGAIN，表示当前连接上套接字缓冲区不存在可读TCP 流，则需将当前读事件添加到定时器机制，注册到epoll 事件机制中，等待可读事件发生。return 从当前函数返回；
 * 5.若返回值 n = NGX_ERROR，表示当前连接出错，则调用ngx_http_finalize_request 方法结束请求，return 从当前函数返回；
 * 6.若返回值 n 大于 0，表示读取请求头部成功，调用函数 ngx_http_parse_request_line 开始解析由函数ngx_http_read_request_header 读取所返回的请求头部，根据函数ngx_http_parse_request_line 函数返回值rc不同进行判断；
 * 7.若返回值 rc = NGX_ERROR，表示解析请求行时出错，此时，调用ngx_http_finalize_request 方法终止该请求，并return 从当前函数返回；
 * 8.若返回值 rc = NGX_AGAIN，表示没有解析到完整一行的请求头部，仍需继续接收TCP 字符流才能够是完整一行的请求头部，则continue 继续调用函数ngx_http_read_request_header 和ngx_http_parse_request_line 方法读取并解析下一行请求头部，直到全部请求头部解析完毕；
 * 9.若返回值 rc = NGX_OK，表示解析出一行 HTTP 请求头部（注意：一行请求头部只是整个请求头部的一部分），判断当前解析出来的一行请求头部是否合法，若非法，则忽略当前一行请求头部，继续读取并解析下一行请求头部。若合法，则调用ngx_list_push 方法将该行请求头部设置到当前请求ngx_http_request_t 结构体 header_in 缓冲区成员的headers 链表中，设置请求头部名称的hash 值，并continue 继续调用函数ngx_http_read_request_header 和ngx_http_parse_request_line 方法读取并解析下一行请求头部，直到全部请求头部解析完毕；
 * 10.若返回值 rc = NGX_HTTP_PARSE_HEADER_DONE，则表示已经读取并解析出全部请求头部，此时，调用ngx_http_process_request 方法开始处理请求，return 从当前函数返回；
 * 
 */
static void
ngx_http_process_request_headers(ngx_event_t *rev)
{
    u_char                     *p;
    size_t                      len;
    ssize_t                     n;
    ngx_int_t                   rc, rv;
    ngx_table_elt_t            *h;
    ngx_connection_t           *c;
    ngx_http_header_t          *hh;
    ngx_http_request_t         *r;
    ngx_http_core_srv_conf_t   *cscf;
    ngx_http_core_main_conf_t  *cmcf;

    /* 获取当前请求所对应的连接 */
    c = rev->data;
    /* 获取当前连接的读事件 */
    r = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                   "http process request header line");

     /* 若当前读事件超时，则关闭该请求，并退出 */
    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_http_close_request(r, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    /* 获取ngx_http_core_module模块的main级别配置项结构 */
    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    /* 表示当前请求头部未解析完毕 */
    rc = NGX_AGAIN;

    for ( ;; ) {

        if (rc == NGX_AGAIN) {

            //检查header_in缓冲区是否已满
            if (r->header_in->pos == r->header_in->end) {   //如果缓冲区满了

                //分配更大的缓冲区存放请求头，并将原先缓冲区的内容r->header_in复制到新的缓冲区中
                //会有3种返回值:
                //  1.NGX_OK表示 成功分配到更大的缓冲区，可以继续接收客户端发来的字符流；
                //  2.NGX_DECLINED表示已经达到缓冲区大小的上限，无法分配更大的缓冲区；
                //  3.NGX_ERROR表示出现错误
                rv = ngx_http_alloc_large_header_buffer(r, 0);

                if (rv == NGX_ERROR) {
                    ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                    break;
                }

                if (rv == NGX_DECLINED) {   //已经达到缓冲区大小的上限，无法分配更大的缓冲区；
                    p = r->header_name_start;

                    r->lingering_close = 1;

                    if (p == NULL) {
                        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                                      "client sent too large request");
                        ngx_http_finalize_request(r,
                                            NGX_HTTP_REQUEST_HEADER_TOO_LARGE);
                        break;
                    }

                    len = r->header_in->end - p;

                    if (len > NGX_MAX_ERROR_STR - 300) {
                        len = NGX_MAX_ERROR_STR - 300;
                    }

                    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                                "client sent too long header line: \"%*s...\"",
                                len, r->header_name_start);

                    //如果是请求头过大，返回494错误
                    ngx_http_finalize_request(r,
                                            NGX_HTTP_REQUEST_HEADER_TOO_LARGE);
                    break;
                }
            }

            //读取数据到header_in缓冲区
            n = ngx_http_read_request_header(r);

             /* 若没有可读的数据，或读取失败，则直接退出 */
            if (n == NGX_AGAIN || n == NGX_ERROR) {
                break;
            }
        }

        /* 获取ngx_http_core_module模块的srv级别配置项结构 */
        /* the host header could change the server configuration context */
        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

        //解析接收到的数据
        rc = ngx_http_parse_header_line(r, r->header_in,
                                        cscf->underscores_in_headers);

        if (rc == NGX_OK) {         //1.解析出了一个完整的请求头

            /* 设置当前请求的长度 */
            r->request_length += r->header_in->pos - r->header_name_start;

             /*
             * 若当前解析出来的一行请求头部是非法的，或Nginx当前版本不支持，
             * 则记录错误日志，并继续解析下一行请求头部；
             */
            if (r->invalid_header && cscf->ignore_invalid_headers) {

                /* there was error while a header line parsing */

                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client sent invalid header line: \"%*s\"",
                              r->header_end - r->header_name_start,
                              r->header_name_start);
                continue;
            }

            /* a header line has been parsed successfully */

            /*
             * 若当前解析出来的一行请求头部是合法的，表示成功解析出该行请求头部，
             * 将该行请求头部保存在当前请求的headers_in的headers链表中；
             * 接着继续解析下一行请求头部；
             */
            //添加到headers_in链表中
            h = ngx_list_push(&r->headers_in.headers);
            if (h == NULL) {
                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                break;
            }

            /* 设置请求头部名称的hash值 */
            h->hash = r->header_hash;

            h->key.len = r->header_name_end - r->header_name_start;
            h->key.data = r->header_name_start;
            h->key.data[h->key.len] = '\0';

            h->value.len = r->header_end - r->header_start;
            h->value.data = r->header_start;
            h->value.data[h->value.len] = '\0';

            //分配lowcase_key空间
            h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
            if (h->lowcase_key == NULL) {
                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                break;
            }

            if (h->key.len == r->lowcase_index) {
                ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);

            } else {
                ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            //查找ngx_http_upstream_headers_in组成的hash表，解析相关特殊头
            hh = ngx_hash_find(&cmcf->headers_in_hash, h->hash,
                               h->lowcase_key, h->key.len);

            //解析一些特殊的头部
            if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
                break;
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http header: \"%V: %V\"",
                           &h->key, &h->value);

            continue;
        }

        /* 若成功解析所有请求头部，则接下来就开始处理该请求 */
        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {     //2.解析完完整的请求头了

            /* a whole header has been parsed successfully */

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http header done");

            r->request_length += r->header_in->pos - r->header_name_start;

            /* 设置当前请求的解析状态 */
            r->http_state = NGX_HTTP_PROCESS_REQUEST_STATE;

            /*
             * 调用该函数主要目的有两个：
             * 1、根据HTTP头部的host字段，调用ngx_http_find_virtual_server查找虚拟主机的配置块；
             * 2、对HTTP请求头部协议版本进行检查，例如http1.1版本，host头部不能为空，否则会返回400 Bad Request错误；
             */
            //主要逻辑是进行请求头格式校验、是否符合http协议规范
            rc = ngx_http_process_request_header(r);

            if (rc != NGX_OK) {
                break;
            }

            //接收完请求头，开始处理请求
            ngx_http_process_request(r);    //里边会执行 ngx_http_core_run_phases

            break;
        }

         /* 表示当前行的请求头部未解析完毕，则继续读取请求数据进行解析 */
        if (rc == NGX_AGAIN) {      //3.仍需接收更多数据

            /* a header line parsing is still not complete */

            continue;
        }

        /* rc == NGX_HTTP_PARSE_INVALID_HEADER */

        /* 解析请求头部出错，则关闭该请求，并退出 */
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "client sent invalid header line: \"%*s\\x%02xd...\"",
                      r->header_end - r->header_name_start,
                      r->header_name_start, *r->header_end);

        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        break;
    }

    ngx_http_run_posted_requests(c);
}


/**
 * 将内核套接字缓冲区中的TCP流复制到header_in缓冲区
 * 
 * 执行流程：
 * 1.检测当前请求的接收缓冲区 header_in 是否有数据，若有直接返回该数据n；
 * 2.若接收缓冲区 header_in 没有数据，检查当前读事件是否准备就绪（即判断ready 标志位是否为0 ）：
 * 3.若当前读事件未准备就绪（即当前读事件 ready 标志位为0），则设置返回值n= NGX_AGAIN；
 * 4.若当前读事件已经准备就绪（即 ready 标志位为 1），则调用 recv() 方法从当前连接套接字中读取数据并保存到接收缓冲区header_in 中，并设置n 为recv()方法所读取的数据的返回值；
 * 5.下面根据 n 的取值执行不同的操作：
 * 6.若 n = NGX_AGAIN（此时，n 的值可能当前事件未准备就绪而设置的NGX_AGAIN，也可能是recv()方法返回的NGX_AGAIN 值，但是只能是其中一种情况），将当前读事件添加到定时器事件机制中， 将当前读事件注册到epoll 事件机制中，等待事件可读，n 从当前函数返回；
 * 7.若 n = 0 或 n = ERROR，则调用 ngx_http_finalize_request 结束请求，并返回NGX_ERROR 退出当前函数；
 * 
 * 
 */
static ssize_t
ngx_http_read_request_header(ngx_http_request_t *r)
{
    ssize_t                    n;
    ngx_event_t               *rev;
    ngx_connection_t          *c;
    ngx_http_core_srv_conf_t  *cscf;

     /* 获取当前请求所对应的连接 */
    c = r->connection;
    /* 获取当前连接的读事件 */
    rev = c->read;

    /* 获取当前请求接收缓冲区的数据，header_in 是ngx_buf_t类型 */
    n = r->header_in->last - r->header_in->pos;

    //如果header_in缓冲区还有未消费数据，直接返回
    if (n > 0) {
        return n;
    }

     /* 若当前接收缓冲区没有数据，首先判断当前读事件是否准备就绪 */
    if (rev->ready) {
        /* 若当前读事件已准备就绪，则从其所对应的连接套接字读取数据，并保存到接收缓冲区中 */
        n = c->recv(c, r->header_in->last,
                    r->header_in->end - r->header_in->last);
    } else {
        /* 若接收缓冲区没有数据，且读事件未准备就绪，则设置为NGX_AGAIN */
        n = NGX_AGAIN;
    }

     /* 若接收缓冲区没有数据，且读事件未准备就绪，则设置为NGX_AGAIN */
    /* 将当前读事件添加到定时器机制；
     * 将当前读事件注册到epoll事件机制；
     */
    if (n == NGX_AGAIN) {       //暂时无数据可读
        if (!rev->timer_set) {  //如果rev没有添加到定时器中，则将其添加到定时器中
            cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
            /* 将当前读事件添加到定时器机制中 */
            ngx_add_timer(rev, cscf->client_header_timeout);
        }

        //将可读事件添加到epoll中
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    if (n == 0) {       //读取数据失败
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "client prematurely closed connection");
    }

    if (n == 0 || n == NGX_ERROR) {
        c->error = 1;
        c->log->action = "reading client request headers";

        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return NGX_ERROR;
    }

    r->header_in->last += n;    //更新header_in缓冲区的last指针

    return n;
}

/**
 * r->header_in负责存放请求行和请求头部
 * 当r->header_in 缓冲区满了时还没有解析到完整的请求行，则分配更大的缓冲
 * https://nginx.org/en/docs/http/ngx_http_core_module.html#large_client_header_buffers
* 会有3种返回值:
  1.NGX_OK表示 成功分配到更大的缓冲区，可以继续接收客户端发来的字符流；
  2.NGX_DECLINED表示已经 达到缓冲区大小的上限，无法分配更大的缓冲区；
  3.NGX_ERROR表示出现错误
 *
    request_line表示是解析请求行还是解析请求头时缓存不足

    最后将header_in指向新分配的buf
 */
static ngx_int_t
ngx_http_alloc_large_header_buffer(ngx_http_request_t *r,
    ngx_uint_t request_line)
{
    u_char                    *old, *new;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl;
    ngx_http_connection_t     *hc;
    ngx_http_core_srv_conf_t  *cscf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http alloc large header buffer");

    if (request_line && r->state == 0) {        //接收请求行时缓存不足

        /* the client fills up the buffer with "\r\n" */

        r->header_in->pos = r->header_in->start;
        r->header_in->last = r->header_in->start;

        return NGX_OK;
    }

    old = request_line ? r->request_start : r->header_name_start;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    if (r->state != 0
        && (size_t) (r->header_in->pos - old)
                                     >= cscf->large_client_header_buffers.size)
    {
        return NGX_DECLINED;
    }

    hc = r->http_connection;

    if (hc->free) {
        cl = hc->free;
        hc->free = cl->next;

        b = cl->buf;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http large header free: %p %uz",
                       b->pos, b->end - b->last);

    } else if (hc->nbusy < cscf->large_client_header_buffers.num) {

        //分配一个buf
        b = ngx_create_temp_buf(r->connection->pool,
                                cscf->large_client_header_buffers.size);
        if (b == NULL) {
            return NGX_ERROR;
        }

        //分配一个cl
        cl = ngx_alloc_chain_link(r->connection->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        //buf挂上cl
        cl->buf = b;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http large header alloc: %p %uz",
                       b->pos, b->end - b->last);

    } else {
        return NGX_DECLINED;
    }

    cl->next = hc->busy;
    hc->busy = cl;
    hc->nbusy++;    //更新已经分配的buffer个数

    if (r->state == 0) {
        /*
         * r->state == 0 means that a header line was parsed successfully
         * and we do not need to copy incomplete header line and
         * to relocate the parser header pointers
         */

        r->header_in = b;

        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http large header copy: %uz", r->header_in->pos - old);

    if (r->header_in->pos - old > b->end - b->start) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "too large header to copy");
        return NGX_ERROR;
    }

    new = b->start;

    //拷贝header_in到new
    ngx_memcpy(new, old, r->header_in->pos - old);

    b->pos = new + (r->header_in->pos - old);
    b->last = new + (r->header_in->pos - old);

    if (request_line) {     //需要更新相关字段引用到新的buf
        r->request_start = new;

        if (r->request_end) {
            r->request_end = new + (r->request_end - old);
        }

        if (r->method_end) {
            r->method_end = new + (r->method_end - old);
        }

        if (r->uri_start) {
            r->uri_start = new + (r->uri_start - old);
        }

        if (r->uri_end) {
            r->uri_end = new + (r->uri_end - old);
        }

        if (r->schema_start) {
            r->schema_start = new + (r->schema_start - old);
            if (r->schema_end) {
                r->schema_end = new + (r->schema_end - old);
            }
        }

        if (r->host_start) {
            r->host_start = new + (r->host_start - old);
            if (r->host_end) {
                r->host_end = new + (r->host_end - old);
            }
        }

        if (r->uri_ext) {
            r->uri_ext = new + (r->uri_ext - old);
        }

        if (r->args_start) {
            r->args_start = new + (r->args_start - old);
        }

        if (r->http_protocol.data) {
            r->http_protocol.data = new + (r->http_protocol.data - old);
        }

    } else {
        r->header_name_start = new;

        if (r->header_name_end) {
            r->header_name_end = new + (r->header_name_end - old);
        }

        if (r->header_start) {
            r->header_start = new + (r->header_start - old);
        }

        if (r->header_end) {
            r->header_end = new + (r->header_end - old);
        }
    }

    r->header_in = b;

    return NGX_OK;
}


/**
 * 处理普通请求头，允许客户端发送重复的相同请求头 （相对于ngx_http_process_unique_header_line）
 * 
 * 找到r->headers_in 对于请求头ngx_table_elt_t链表最后一个元素，将h挂上去
 */
static ngx_int_t
ngx_http_process_header_line(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    ngx_table_elt_t  **ph;

    ph = (ngx_table_elt_t **) ((char *) &r->headers_in + offset);

    //最后一个元素
    while (*ph) { ph = &(*ph)->next; }

    *ph = h;
    h->next = NULL;

    return NGX_OK;
}


/**
 * 处理unique请求头, 不允许客户端发送重复的相同请求头 （相对于ngx_http_process_header_line）
 * 
 * 对r->headers_in->xxx进行赋值，将其指向*h
 * 
 */
static ngx_int_t
ngx_http_process_unique_header_line(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    ngx_table_elt_t  **ph;

    ph = (ngx_table_elt_t **) ((char *) &r->headers_in + offset);

    //将r->headers_in->if_modified_since 指向h 
    if (*ph == NULL) {
        *ph = h;
        h->next = NULL;
        return NGX_OK;
    }

    //发送了重复的请求头
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "client sent duplicate header line: \"%V: %V\", "
                  "previous value: \"%V: %V\"",
                  &h->key, &h->value, &(*ph)->key, &(*ph)->value);

    ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);

    return NGX_ERROR;
}


/**
 * Host请求头解析， 将代表Host请求头的h 赋值给 r->headers_in.host
 */
static ngx_int_t
ngx_http_process_host(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    ngx_int_t  rc;
    ngx_str_t  host;

    if (r->headers_in.host) {       //已经解析过了
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent duplicate host header: \"%V: %V\", "
                      "previous value: \"%V: %V\"",
                      &h->key, &h->value, &r->headers_in.host->key,
                      &r->headers_in.host->value);
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return NGX_ERROR;
    }

    r->headers_in.host = h;
    h->next = NULL;

    host = h->value;

    //校验host是否合法（如是否包含..或/等 ）
    rc = ngx_http_validate_host(&host, r->pool, 0);

    //host请求头不合法
    if (rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent invalid host header");
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return NGX_ERROR;
    }

    //NGX_ERROR 说明内部分配存储失败
    if (rc == NGX_ERROR) {
        ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    //如果已经设置了server头，则直接返回，无须重复设置
    if (r->headers_in.server.len) {
        return NGX_OK;
    }

    if (ngx_http_set_virtual_server(r, &host) == NGX_ERROR) {
        return NGX_ERROR;
    }

    r->headers_in.server = host;

    return NGX_OK;
}


/**
 * 解析 Connection 请求头
 */
static ngx_int_t
ngx_http_process_connection(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    if (ngx_http_process_header_line(r, h, offset) != NGX_OK) {
        return NGX_ERROR;
    }

    //如果Connection 为 "close"
    if (ngx_strcasestrn(h->value.data, "close", 5 - 1)) {
        r->headers_in.connection_type = NGX_HTTP_CONNECTION_CLOSE;

    //如果Connection 为 "keep-alive"
    } else if (ngx_strcasestrn(h->value.data, "keep-alive", 10 - 1)) {
        r->headers_in.connection_type = NGX_HTTP_CONNECTION_KEEP_ALIVE;
    }

    return NGX_OK;
}


/**
 * 处理请求头 User-Agent， 并标识浏览器类型 isMSIE, isOpera...
 */
static ngx_int_t
ngx_http_process_user_agent(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    u_char  *user_agent, *msie;

    if (ngx_http_process_header_line(r, h, offset) != NGX_OK) {
        return NGX_ERROR;
    }

    /* check some widespread browsers while the header is in CPU cache */

    user_agent = h->value.data;

    //设置请求头 headers_in.msie6
    //msie为"MSIE "在user_agent中出现的位置
    msie = ngx_strstrn(user_agent, "MSIE ", 5 - 1);

    if (msie && msie + 7 < user_agent + h->value.len) {

        r->headers_in.msie = 1;

        if (msie[6] == '.') {

            switch (msie[5]) {
            case '4':
            case '5':
                r->headers_in.msie6 = 1;
                break;
            case '6':
                if (ngx_strstrn(msie + 8, "SV1", 3 - 1) == NULL) {
                    r->headers_in.msie6 = 1;
                }
                break;
            }
        }

#if 0
        /* MSIE ignores the SSL "close notify" alert */
        if (c->ssl) {
            c->ssl->no_send_shutdown = 1;
        }
#endif
    }

    if (ngx_strstrn(user_agent, "Opera", 5 - 1)) {
        r->headers_in.opera = 1;
        r->headers_in.msie = 0;
        r->headers_in.msie6 = 0;
    }

    if (!r->headers_in.msie && !r->headers_in.opera) {

        if (ngx_strstrn(user_agent, "Gecko/", 6 - 1)) {
            r->headers_in.gecko = 1;

        } else if (ngx_strstrn(user_agent, "Chrome/", 7 - 1)) {
            r->headers_in.chrome = 1;

        } else if (ngx_strstrn(user_agent, "Safari/", 7 - 1)
                   && ngx_strstrn(user_agent, "Mac OS X", 8 - 1))
        {
            r->headers_in.safari = 1;

        } else if (ngx_strstrn(user_agent, "Konqueror", 9 - 1)) {
            r->headers_in.konqueror = 1;
        }
    }

    return NGX_OK;
}


/**
 * 当接收并解析完全部的请求头后被调用
 * 
 * 主要逻辑是进行请求头格式校验、是否符合http协议规范
 */
ngx_int_t
ngx_http_process_request_header(ngx_http_request_t *r)
{
    //查找虚拟主机
    if (r->headers_in.server.len == 0
        && ngx_http_set_virtual_server(r, &r->headers_in.server)
           == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    //请求头格式校验
    if (r->headers_in.host == NULL && r->http_version > NGX_HTTP_VERSION_10) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                   "client sent HTTP/1.1 request without \"Host\" header");
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return NGX_ERROR;
    }

    if (r->headers_in.content_length) {
        r->headers_in.content_length_n =
                            ngx_atoof(r->headers_in.content_length->value.data,
                                      r->headers_in.content_length->value.len);

        if (r->headers_in.content_length_n == NGX_ERROR) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent invalid \"Content-Length\" header");
            ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
            return NGX_ERROR;
        }
    }

    if (r->headers_in.transfer_encoding) {
        //transfer_encoding头是1.1规范定义的
        if (r->http_version < NGX_HTTP_VERSION_11) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent HTTP/1.0 request with "
                          "\"Transfer-Encoding\" header");
            ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
            return NGX_ERROR;
        }

        //如果transfer_encoding头是chunked
        if (r->headers_in.transfer_encoding->value.len == 7
            && ngx_strncasecmp(r->headers_in.transfer_encoding->value.data,
                               (u_char *) "chunked", 7) == 0)
        {
            //不允许同时传content_length和chunked
            if (r->headers_in.content_length) {
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                              "client sent \"Content-Length\" and "
                              "\"Transfer-Encoding\" headers "
                              "at the same time");
                ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
                return NGX_ERROR;
            }

            //标记当前为chunked请求
            r->headers_in.chunked = 1;

        } else {        //只支持chunked编码
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent unknown \"Transfer-Encoding\": \"%V\"",
                          &r->headers_in.transfer_encoding->value);
            ngx_http_finalize_request(r, NGX_HTTP_NOT_IMPLEMENTED);
            return NGX_ERROR;
        }
    }

    if (r->headers_in.connection_type == NGX_HTTP_CONNECTION_KEEP_ALIVE) {
        if (r->headers_in.keep_alive) {
            r->headers_in.keep_alive_n =
                            ngx_atotm(r->headers_in.keep_alive->value.data,
                                      r->headers_in.keep_alive->value.len);
        }
    }

    if (r->method == NGX_HTTP_CONNECT) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent CONNECT method");
        ngx_http_finalize_request(r, NGX_HTTP_NOT_ALLOWED);
        return NGX_ERROR;
    }

    if (r->method == NGX_HTTP_TRACE) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent TRACE method");
        ngx_http_finalize_request(r, NGX_HTTP_NOT_ALLOWED);
        return NGX_ERROR;
    }

    return NGX_OK;
}


/**
 * 接收完并解析完成请求行和请求头部后，已经有足够的信息开始处理HTTP请求, 调用该函数开始处理请求
 * 
 * http0.9版本没有请求头部，在解析完请求行后直接调用ngx_http_process_request方法
 * 
 * 执行流程：
 * 1.若当前读事件在定时器机制中，则调用 ngx_del_timer 函数将其从定时器机制中移除，因为在处理HTTP 请求时不存在接收HTTP 请求头部超时的问题；
 * 2.由于处理 HTTP 请求不需要再接收 HTTP 请求行或头部，则需重新设置当前连接读、写事件的回调方法，读、写事件的回调方法都设置为 ngx_http_request_handler，即后续处理 HTTP 请求的过程都是通过该方法进行；
 * 3.设置当前请求 ngx_http_request_t 结构体中的成员read_event_handler 的回调方法为ngx_http_block_reading，该回调方法实际不做任何操作，即在处理请求时不会对请求的读事件进行任何处理，除非某个HTTP模块重新设置该回调方法；
 * 4.接下来调用函数 ngx_http_handler 开始处理HTTP 请求；
 * 5.调用函数 ngx_http_run_posted_requests 处理post 子请求；
 * 
 */
void
ngx_http_process_request(ngx_http_request_t *r)
{
    ngx_connection_t  *c;

    c = r->connection;

#if (NGX_HTTP_SSL)

    if (r->http_connection->ssl) {
        long                      rc;
        X509                     *cert;
        const char               *s;
        ngx_http_ssl_srv_conf_t  *sscf;

        if (c->ssl == NULL) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "client sent plain HTTP request to HTTPS port");
            ngx_http_finalize_request(r, NGX_HTTP_TO_HTTPS);
            return;
        }

        sscf = ngx_http_get_module_srv_conf(r, ngx_http_ssl_module);

        if (sscf->verify) {
            rc = SSL_get_verify_result(c->ssl->connection);

            if (rc != X509_V_OK
                && (sscf->verify != 3 || !ngx_ssl_verify_error_optional(rc)))
            {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client SSL certificate verify error: (%l:%s)",
                              rc, X509_verify_cert_error_string(rc));

                ngx_ssl_remove_cached_session(c->ssl->session_ctx,
                                       (SSL_get0_session(c->ssl->connection)));

                ngx_http_finalize_request(r, NGX_HTTPS_CERT_ERROR);
                return;
            }

            if (sscf->verify == 1) {
                cert = SSL_get_peer_certificate(c->ssl->connection);

                if (cert == NULL) {
                    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                                  "client sent no required SSL certificate");

                    ngx_ssl_remove_cached_session(c->ssl->session_ctx,
                                       (SSL_get0_session(c->ssl->connection)));

                    ngx_http_finalize_request(r, NGX_HTTPS_NO_CERT);
                    return;
                }

                X509_free(cert);
            }

            if (ngx_ssl_ocsp_get_status(c, &s) != NGX_OK) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client SSL certificate verify error: %s", s);

                ngx_ssl_remove_cached_session(c->ssl->session_ctx,
                                       (SSL_get0_session(c->ssl->connection)));

                ngx_http_finalize_request(r, NGX_HTTPS_CERT_ERROR);
                return;
            }
        }
    }

#endif

    /*
     * 由于现在不需要再接收HTTP请求头部超时问题，
     * 则需要把当前连接的读事件从定时器机制中删除；
     * timer_set为1表示读事件已添加到定时器机制中，
     * 则将其从定时器机制中删除，0表示不在定时器机制中；
     */
     //如果readEvent仍然在定时器中，将其删除
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_reading, -1);
    r->stat_reading = 0;
    (void) ngx_atomic_fetch_add(ngx_stat_writing, 1);
    r->stat_writing = 1;
#endif

    //将连接读写事件的回调都设置成ngx_http_request_handler
    //当ngx_http_core_run_phases任一模块无法继续处理如需等待更多数据时，后续接收到数据由此方法执行
    c->read->handler = ngx_http_request_handler;
    c->write->handler = ngx_http_request_handler;
    //问题 read_event_handler 与 read->handler
    r->read_event_handler = ngx_http_block_reading;

    ngx_http_handler(r);        //启动ngx_http_core_run_phases
}


/**
 * 校验请求头Host值是否合法 (如是否包含..或/等)
 * 返回NGX_DECLINED或NGX_ERROR都代表有错误
 */
ngx_int_t
ngx_http_validate_host(ngx_str_t *host, ngx_pool_t *pool, ngx_uint_t alloc)
{
    u_char  *h, ch;
    size_t   i, dot_pos, host_len;

    enum {
        sw_usual = 0,
        sw_literal,
        sw_rest
    } state;

    dot_pos = host->len;        //最后一个.的位置
    host_len = host->len;       //到最后一个:的长度

    h = host->data;

    state = sw_usual;

    for (i = 0; i < host->len; i++) {
        ch = h[i];

        switch (ch) {

        case '.':
            if (dot_pos == i - 1) {     //出现了连续的 ..
                return NGX_DECLINED;    //返回错误 400 Bad Request
            }
            dot_pos = i;
            break;

        case ':':
            if (state == sw_usual) {
                host_len = i;
                state = sw_rest;
            }
            break;

        case '[':
            if (i == 0) {
                state = sw_literal;
            }
            break;

        case ']':
            if (state == sw_literal) {
                host_len = i + 1;
                state = sw_rest;
            }
            break;

        default:

            if (ngx_path_separator(ch)) {       //出现了字符‘/' 
                return NGX_DECLINED;            //返回错误 400 Bad Request
            }

            if (ch <= 0x20 || ch == 0x7f) {     //是否包含控制字符
                return NGX_DECLINED;
            }

            if (ch >= 'A' && ch <= 'Z') {       //是否包含大写字母
                alloc = 1;
            }

            break;
        }
    }

    if (dot_pos == host_len - 1) {  //如果为a.com.:8080, host_len为5而不是6
        host_len--;
    }

    if (host_len == 0) {        //host_len代表 host部分长度，如a.com:8080, host_len为5
        return NGX_DECLINED;
    }

    if (alloc) {    //如果包含大写字母，将其转为小写
        host->data = ngx_pnalloc(pool, host_len);
        if (host->data == NULL) {
            return NGX_ERROR;       //分配内存错误
        }

        ngx_strlow(host->data, h, host_len);
    }

    host->len = host_len;       //如果为a.com:8080， host只包含:前的部分

    return NGX_OK;
}


/**
 * 根据Host请求头查找虚拟主机配置ngx_http_core_srv_conf_t结构体
 */
ngx_int_t
ngx_http_set_virtual_server(ngx_http_request_t *r, ngx_str_t *host)
{
    ngx_int_t                  rc;
    ngx_http_connection_t     *hc;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_core_srv_conf_t  *cscf;

#if (NGX_SUPPRESS_WARN)
    cscf = NULL;
#endif

    hc = r->http_connection;

#if (NGX_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)

    if (hc->ssl_servername) {
        if (hc->ssl_servername->len == host->len
            && ngx_strncmp(hc->ssl_servername->data,
                           host->data, host->len) == 0)
        {
#if (NGX_PCRE)
            if (hc->ssl_servername_regex
                && ngx_http_regex_exec(r, hc->ssl_servername_regex,
                                          hc->ssl_servername) != NGX_OK)
            {
                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return NGX_ERROR;
            }
#endif
            return NGX_OK;
        }
    }

#endif

    rc = ngx_http_find_virtual_server(r->connection,
                                      hc->addr_conf->virtual_names,
                                      host, r, &cscf);

    if (rc == NGX_ERROR) {
        ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

#if (NGX_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)

    if (hc->ssl_servername) {
        ngx_http_ssl_srv_conf_t  *sscf;

        if (rc == NGX_DECLINED) {
            cscf = hc->addr_conf->default_server;
            rc = NGX_OK;
        }

        sscf = ngx_http_get_module_srv_conf(cscf->ctx, ngx_http_ssl_module);

        if (sscf->verify) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client attempted to request the server name "
                          "different from the one that was negotiated");
            ngx_http_finalize_request(r, NGX_HTTP_MISDIRECTED_REQUEST);
            return NGX_ERROR;
        }
    }

#endif

    if (rc == NGX_DECLINED) {
        return NGX_OK;
    }

    r->srv_conf = cscf->ctx->srv_conf;
    r->loc_conf = cscf->ctx->loc_conf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_set_connection_log(r->connection, clcf->error_log);

    return NGX_OK;
}


/**
 * 读取完请求头后，根据Host查找虚拟主机
 * host: 为请求host头
 * 
 */
static ngx_int_t
ngx_http_find_virtual_server(ngx_connection_t *c,
    ngx_http_virtual_names_t *virtual_names, ngx_str_t *host,
    ngx_http_request_t *r, ngx_http_core_srv_conf_t **cscfp)
{
    ngx_http_core_srv_conf_t  *cscf;

    if (virtual_names == NULL) {
        return NGX_DECLINED;
    }

    cscf = ngx_hash_find_combined(&virtual_names->names,
                                  ngx_hash_key(host->data, host->len),
                                  host->data, host->len);

    if (cscf) {
        *cscfp = cscf;
        return NGX_OK;
    }

#if (NGX_PCRE)

    if (host->len && virtual_names->nregex) {
        ngx_int_t                n;
        ngx_uint_t               i;
        ngx_http_server_name_t  *sn;

        sn = virtual_names->regex;

#if (NGX_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)

        if (r == NULL) {
            ngx_http_connection_t  *hc;

            for (i = 0; i < virtual_names->nregex; i++) {

                n = ngx_regex_exec(sn[i].regex->regex, host, NULL, 0);

                if (n == NGX_REGEX_NO_MATCHED) {
                    continue;
                }

                if (n >= 0) {
                    hc = c->data;
                    hc->ssl_servername_regex = sn[i].regex;

                    *cscfp = sn[i].server;
                    return NGX_OK;
                }

                ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                              ngx_regex_exec_n " failed: %i "
                              "on \"%V\" using \"%V\"",
                              n, host, &sn[i].regex->name);

                return NGX_ERROR;
            }

            return NGX_DECLINED;
        }

#endif /* NGX_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME */

        for (i = 0; i < virtual_names->nregex; i++) {

            n = ngx_http_regex_exec(r, sn[i].regex, host);

            if (n == NGX_DECLINED) {
                continue;
            }

            if (n == NGX_OK) {
                *cscfp = sn[i].server;
                return NGX_OK;
            }

            return NGX_ERROR;
        }
    }

#endif /* NGX_PCRE */

    return NGX_DECLINED;
}


/**
 * 接收完请求头后调用，立即调用ngx_http_core_run_phases。
 * 如果再有读写事件触发，此方法会被调用
 */
static void
ngx_http_request_handler(ngx_event_t *ev)
{
    ngx_connection_t    *c;
    ngx_http_request_t  *r;

    c = ev->data;
    r = c->data;

    ngx_http_set_log_request(c->log, r);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http run request: \"%V?%V\"", &r->uri, &r->args);

    if (c->close) {     //如果是clise事件，结束请求
        r->main->count++;
        ngx_http_terminate_request(r, 0);
        ngx_http_run_posted_requests(c);
        return;
    }

    //限速超时
    if (ev->delayed && ev->timedout) {
        ev->delayed = 0;
        ev->timedout = 0;
    }

    //如果一个事件的读写标志同时为1时，仅write_event_handler方法会被调用，
    //即可写事件的处 理优先于可读事件（这正是Nginx高性能设计的体现，优先处理可写事件可以尽快释放内存，
    //尽量保持各HTTP模块少使用内存以提高并发能力）

    //可写事件
    if (ev->write) {
        // 此时write_event_handler已经在ngx_http_handler中被设置为 ngx_http_core_run_phases
        r->write_event_handler(r);

    } else {    //可读事件
        //此时write_event_handler已经在ngx_http_process_request中被设置为 ngx_http_block_reading
        r->read_event_handler(r);
    }

    ngx_http_run_posted_requests(c);
}


/**
 * 驱动子请求运行的关键函数
 * post请求的设计就是用于实现subrequest子请求机制的
 * 
 * 遍历r->main->posted_requests， 执行其write_event_handler
 * 通常就是ngx_http_core_run_phases引擎数组处理请求
 * 
 * 函数执行流程： 
 *  1.判断当前连接是否已被销毁（即标志位 destroyed 是否为0），若被销毁则直接return 退出，否则继续执行；
 *  2.获取原始请求的子请求链表，若子请求链表为空（表示没有 post 请求）则直接return 退出，否则继续执行；
 *  3.遍历子请求链表，执行每个 post 请求的写事件回调方法write_event_handler；
 * 
 */
void
ngx_http_run_posted_requests(ngx_connection_t *c)
{
    ngx_http_request_t         *r;
    ngx_http_posted_request_t  *pr;

    //循环执行 r->main->posted_requests
    for ( ;; ) {

        if (c->destroyed) {     //检查连接是否已销毁
            return;
        }

        /* 获取当前连接所对应的请求 */
        r = c->data;
        pr = r->main->posted_requests;      //找到原始请求的posted_requests

        /* 若子请求单链表为空，则直接退出 */
        if (pr == NULL) {
            return;
        }

        r->main->posted_requests = pr->next;    //将原始请求的posted_requests 指向下一个子请求

        /* 获取子请求链表中的第一个post请求 */
        r = pr->request;

        ngx_http_set_log_request(c->log, r);

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http posted request: \"%V?%V\"", &r->uri, &r->args);
        //执行请求的write_event_handler方法, 这里的r是子请求
        //子请求不是被网络事件驱动的，执行post请求时就相当于有可写事件，由Nginx主动做出动作
        r->write_event_handler(r);  //实际就是ngx_http_handler， 参考ngx_http_subrequest
    }
}


/**
 * 将pr指向的子请求添加到主请求的posted_requests链表中
 * 如果pr为NULL，则分配一个ngx_http_posted_request_t结构体
 * ngx_http_run_posted_requests 方法就是通过遍历该单链表来执行子请求的 其write_event_handler方法
 */
ngx_int_t
ngx_http_post_request(ngx_http_request_t *r, ngx_http_posted_request_t *pr)
{
    ngx_http_posted_request_t  **p;

    // 分配一个链表节点
    if (pr == NULL) {
        pr = ngx_palloc(r->pool, sizeof(ngx_http_posted_request_t));
        if (pr == NULL) {
            return NGX_ERROR;
        }
    }

    pr->request = r;
    pr->next = NULL;

    //找到父请求的posted_requests链表末端
    for (p = &r->main->posted_requests; *p; p = &(*p)->next) { /* void */ }
    //将当前子请求挂上去
    *p = pr;

    return NGX_OK;
}


/**
 * 是开发HTTP模块时最常使用的结束请求方法
 * 参数r就是当前请求，它可能是派生出的子请求，也可能是客户端发来的原始请求。
 * 参数rc就非常复杂了，它既可能是NGX_OK、NGX_ERROR、NGX_AGAIN、 NGX_DONE、NGX_DECLINED这种系统定义的返回值，又可能是类似 NGX_HTTP_REQUEST_TIME_OUT这样的HTTP响应码，因此，ngx_http_finalize_request方法 的流程异常复杂
 */
// 重要函数，以“适当”的方式“结束”请求
// 并不一定会真正结束，大部分情况下只是暂时停止处理，等待epoll事件发生
// 参数rc决定了函数的逻辑，在content阶段就是handler的返回值
// 调用ngx_http_finalize_connection，检查请求相关的异步事件，尝试关闭请求
//
// done，例如调用read body,因为count已经增加，所以不会关闭请求
void
ngx_http_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_connection_t          *c;
    ngx_http_request_t        *pr;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http finalize request: %i, \"%V?%V\" a:%d, c:%d",
                   rc, &r->uri, &r->args, r == c->data, r->main->count);

    //NGX_DONE参数表示不需要做任何事
    if (rc == NGX_DONE) {
        ngx_http_finalize_connection(r);
        return;
    }

    if (rc == NGX_OK && r->filter_finalize) {
        c->error = 1;
    }

    //NGX_DECLINED表示请求还需要按照11个HTTP阶段继续处理下去，
    if (rc == NGX_DECLINED) {
        r->content_handler = NULL; 
        r->write_event_handler = ngx_http_core_run_phases;
        ngx_http_core_run_phases(r);
        return;
    }

    //将父请求加入待处理请求链表，这样子请求结束时调度函数ngx_http_run_posted_requests会继续执行父请求
    //当前请求是否为subrequest子请求, 调用post_subrequest下的handler回调方法
    /* 如果当前请求是某个原始请求的一个子请求，检查它是否有回调handler处理函数，若存在则执行 */
    if (r != r->main && r->post_subrequest) {
        //执行子请求结束的回调， rc为子请求结束的状态码
        rc = r->post_subrequest->handler(r, r->post_subrequest->data, rc);
    }

    //错误，直接调用ngx_http_terminate_request方法强制结束请求
    if (rc == NGX_ERROR
        || rc == NGX_HTTP_REQUEST_TIME_OUT
        || rc == NGX_HTTP_CLIENT_CLOSED_REQUEST
        || c->error)
    {
        if (ngx_http_post_action(r) == NGX_OK) {
            return;
        }

        ngx_http_terminate_request(r, rc);
        return;
    }

    //表示请求的动作是上传文件，或者HTTP模块需要 HTTP框架构造并发送响应码大于或等于300以上的特殊响应
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE
        || rc == NGX_HTTP_CREATED
        || rc == NGX_HTTP_NO_CONTENT)
    {
        if (rc == NGX_HTTP_CLOSE) {
            c->timedout = 1;
            ngx_http_terminate_request(r, rc);
            return;
        }

        if (r == r->main) { //如果是主请求
            if (c->read->timer_set) {
                ngx_del_timer(c->read);
            }

            if (c->write->timer_set) {
                ngx_del_timer(c->write);
            }
        }

        c->read->handler = ngx_http_request_handler;
        c->write->handler = ngx_http_request_handler;

        //根据rc参数构造完整的 HTTP响应
        ngx_http_finalize_request(r, ngx_http_special_response_handler(r, rc));
        return;
    }

     /* 若 r 是子请求 */
    if (r != r->main) {

         /* 该子请求还有未处理完的数据或者子请求 */
        //子请求，需要跳到它的父请求上，激活父请求继续向下执行
        if (r->buffered || r->postponed) {

             /* 添加一个该子请求的写事件，并设置合适的write event hander，
               以便下次写事件来的时候继续处理，这里实际上下次执行时会调用ngx_http_output_filter函数，
               最终还是会进入ngx_http_postpone_filter进行处理 */
            if (ngx_http_set_write_handler(r) != NGX_OK) {
                ngx_http_terminate_request(r, 0);
            }

            return;
        }

        pr = r->parent;

         /* 该子请求已经处理完毕，如果它拥有发送数据的权利，则将权利移交给父请求， */
        if (r == c->data || r->background) {

            if (!r->logged) {

                clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

                if (clcf->log_subrequest) {
                    ngx_http_log_request(r);
                }

                r->logged = 1;

            } else {
                ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                              "subrequest: \"%V?%V\" logged again",
                              &r->uri, &r->args);
            }

            r->done = 1;

            if (r->background) {
                ngx_http_finalize_connection(r);
                return;
            }

            r->main->count--;

            /* 如果该子请求不是提前完成，则从父请求的postponed链表中删除 */
            if (pr->postponed && pr->postponed->request == r) {
                pr->postponed = pr->postponed->next;
            }

            /* 将发送权利移交给父请求，父请求下次执行的时候会发送它的postponed链表中可以
             * 发送的数据节点，或者将发送权利移交给它的下一个子请求 */
            c->data = pr;

        } else {

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http finalize non-active request: \"%V?%V\"",
                           &r->uri, &r->args);

            /* 该子请求提前执行完成，而且它没有产生任何数据，则它下次再次获得
             * 执行机会时，将会执行ngx_http_request_finalzier函数，它实际上是执行
             * ngx_http_finalzie_request（r,0），不做具体操作，直到它发送数据时，
             * ngx_http_finalzie_request函数会将它从父请求的postponed链表中删除
             */
            r->write_event_handler = ngx_http_request_finalizer;

            if (r->waited) {
                r->done = 1;
            }
        }

        /* 将父请求加入posted_request队尾，获得一次运行机会 */
        if (ngx_http_post_request(pr, NULL) != NGX_OK) {
            r->main->count++;
            ngx_http_terminate_request(r, 0);
            return;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http wake parent request: \"%V?%V\"",
                       &pr->uri, &pr->args);

        return;
    }

     /* 这里是处理主请求结束的逻辑，如果主请求有未发送的数据或者未处理的子请求，
     * 则给主请求添加写事件，并设置合适的write event hander，
     * 以便下次写事件来的时候继续处理 */
    if (r->buffered || c->buffered || r->postponed) {

        if (ngx_http_set_write_handler(r) != NGX_OK) {
            ngx_http_terminate_request(r, 0);
        }

        return;
    }

    if (r != c->data) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "http finalize non-active request: \"%V?%V\"",
                      &r->uri, &r->args);
        return;
    }

    r->done = 1;

    r->read_event_handler = ngx_http_block_reading;
    r->write_event_handler = ngx_http_request_empty_handler;

    if (!r->post_action) {
        r->request_complete = 1;
    }

    if (ngx_http_post_action(r) == NGX_OK) {
        return;
    }

    /*
     * 将读、写事件从定时器机制中移除；
     */
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        c->write->delayed = 0;
        ngx_del_timer(c->write);
    }

    ngx_http_finalize_connection(r);
}


/**
 * 提供给HTTP模块使用的结束请求方法,属于非正常结束的场景
 * 直接找出该请求的main成员指向的原始请求，并直接将该原始请求的引用 计数置为1，
 * 同时会调用ngx_http_close_request方法去关闭请求
 */
static void
ngx_http_terminate_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_http_cleanup_t    *cln;
    ngx_http_request_t    *mr;
    ngx_http_ephemeral_t  *e;

    mr = r->main;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http terminate request count:%d", mr->count);

    mr->terminated = 1;

    if (rc > 0 && (mr->headers_out.status == 0 || mr->connection->sent == 0)) {
        mr->headers_out.status = rc;
    }

    /* 调用原始请求的cleanup的回调方法，开始清理工作 */
    cln = mr->cleanup;
    mr->cleanup = NULL;

    while (cln) {
        if (cln->handler) {
            cln->handler(cln->data);
        }

        cln = cln->next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http terminate cleanup count:%d blk:%d",
                   mr->count, mr->blocked);

    if (mr->write_event_handler) {

        if (mr->blocked) {
            r = r->connection->data;

            r->connection->error = 1;
            r->write_event_handler = ngx_http_request_finalizer;

            return;
        }

        e = ngx_http_ephemeral(mr);
        mr->posted_requests = NULL;
        mr->write_event_handler = ngx_http_terminate_handler;
        (void) ngx_http_post_request(mr, &e->terminal_posted_request);
        return;
    }

    /* 释放请求，并关闭连接 */
    ngx_http_close_request(mr, rc);
}


static void
ngx_http_terminate_handler(ngx_http_request_t *r)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http terminate handler count:%d", r->count);

    r->count = 1;

    ngx_http_close_request(r, 0);
}


/**
 * 在结束请求时处理keepalive特性、lingering_close的问题
 */
static void
ngx_http_finalize_connection(ngx_http_request_t *r)
{
    ngx_http_core_loc_conf_t  *clcf;

#if (NGX_HTTP_V2)
    if (r->stream) {
        ngx_http_close_request(r, 0);
        return;
    }
#endif

#if (NGX_HTTP_V3)
    if (r->connection->quic) {
        ngx_http_close_request(r, 0);
        return;
    }
#endif

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (r->main->count != 1) {  //表示还有多个动作在操作着请求

        /*
         * 检查当前请求的discard_body标志位，若该标志位为1，表示当前请求正在丢弃包体；
         */
        if (r->discard_body) {
            /* 设置当前请求读事件的回调方法，并将读事件添加到定时器机制中 */
            r->read_event_handler = ngx_http_discarded_request_body_handler;
            ngx_add_timer(r->connection->read, clcf->lingering_timeout);

            if (r->lingering_time == 0) {
                r->lingering_time = ngx_time()
                                      + (time_t) (clcf->lingering_time / 1000);
            }
        }

         /* 关闭当前请求 */
        ngx_http_close_request(r, 0);
        return;
    }

    //r->main->count==1, 真的准备结束请求了
    r = r->main;

    if (r->connection->read->eof) {
        ngx_http_close_request(r, 0);
        return;
    }

    if (r->reading_body) {
        r->keepalive = 0;
        r->lingering_close = 1;
    }

    //表示只需要释放请求，但是当前连接需要复用
    if (r->keepalive
        && clcf->keepalive_min_timeout > 0)
    {
        //设置当前连接为keepalive状态
        ngx_http_set_keepalive(r);
        return;
    }

    if (!ngx_terminate
         && !ngx_exiting
         && r->keepalive
         && clcf->keepalive_timeout > 0)
    {
        ngx_http_set_keepalive(r);
        return;
    }

    if (clcf->lingering_close == NGX_HTTP_LINGERING_ALWAYS
        || (clcf->lingering_close == NGX_HTTP_LINGERING_ON
            && (r->lingering_close
                || r->header_in->pos < r->header_in->last
                || r->connection->read->ready
                || r->connection->pipeline)))
    {
        ngx_http_set_lingering_close(r->connection);
        return;
    }

    /* 若keepalive标志为0，且lingering_close标志也为0，则立刻关闭请求 */
    ngx_http_close_request(r, 0);
}


/**
 * 1.设置当前请求的读事件回调方法为：ngx_httpp_discarded_request_body_handler（丢弃包体） 或ngx_http_test_reading；
 * 2.设置当前请求的写事件回调方法为 ngx_http_writer（发送out 链表缓冲区剩余的响应）；
 * 3.若当前写事件准备就绪（即 ready 和 delayed 标志位为 1）开始限速的发送 out 链表缓冲区中的剩余响应；
 * 4.若当前写事件未准备就绪，则将写事件添加到定时器机制，注册到 epoll 事件机制中；
 */
static ngx_int_t
ngx_http_set_write_handler(ngx_http_request_t *r)
{
    ngx_event_t               *wev;
    ngx_http_core_loc_conf_t  *clcf;

    r->http_state = NGX_HTTP_WRITING_REQUEST_STATE;

    /* 设置当前请求读事件的回调方法：丢弃包体或不进行任何操作 */
    r->read_event_handler = r->discard_body ?
                                ngx_http_discarded_request_body_handler:
                                ngx_http_test_reading;
    //设置写事件的回调方法为ngx_http_writer，即发送out链表缓冲区剩余的响应
    r->write_event_handler = ngx_http_writer;

    wev = r->connection->write;

    /* 若写事件的ready标志位和delayed标志为都为1，则返回NGX_OK */
    if (wev->ready && wev->delayed) {
        return NGX_OK;
    }

     /*
     * 若写事件的ready标志位为0，或delayed标志位为0，则将写事件添加到定时器机制中；
     * 同时将写事件注册到epoll事件机制中；
     * 最后返回NGX_OK；
     */
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (!wev->delayed) {
        ngx_add_timer(wev, clcf->send_timeout);
    }

    if (ngx_handle_write_event(wev, clcf->send_lowat) != NGX_OK) {
        ngx_http_close_request(r, 0);
        return NGX_ERROR;
    }

    return NGX_OK;
}


/**
 * 可写事件回调， 请求的连接上可写事件被触发，此方法被调用
 * 无论是ngx_http_send_header还是ngx_http_output_filter方法，它们在调用时一般都无 法发送全部的响应，
 * 剩下的响应内容都得靠ngx_http_writer方法来发送
 * 
 * 1.检查写事件的 timedout 标志位，若该标志位为 1（表示超时），进而判断属于哪种情况引起的超时（第一种：网络异常或客户端长时间不接收响应；第二种：由于响应发送速度超速，导致写事件被添加到定时器机制（注意一点：delayed 标志位此时是为1），有超速引起的超时，不算真正的响应发送超时）；
 * 2.检查 delayed 标志位，若 delayed 为 0，表示由第一种情况引起的超时，即是真正的响应超时，此时设置timedout 标志位为1，并调用函数ngx_http_finalize_request 结束请求；
 * 3.若 delayed 为 1，表示由第二种情况引起的超时，不算真正的响应超时，此时，把标志位 timedout、delayed 都设置为 0，继续检查写事件的 ready 标志位，若 ready 为 0，表示当前写事件未准备就绪（即不可写），因此，将写事件添加到定时器机制，注册到epoll 事件机制中，等待可写事件发送，返回return 结束该方法；
 * 4.若写事件 timedout 为 0，且 delayed 为 0，且 ready 为 1，则调用函数 ngx_http_output_filter 发送响应；该函数的第二个参数为NULL，表示需要调用各个包体过滤模块处理链表缓冲区out 中剩余的响应，最后由ngx_http_write_filter 方法把响应发送出去；
 * 
 * 真正发送响应的是 ngx_http_write_filter 函数，但是该函数不能保证一次性把响应发送完毕，若发送不完毕，把剩余的响应保存在out 链表缓冲区中，继而调用ngx_http_writer 把剩余的响应发送出去，函数ngx_http_writer 最终调用的是ngx_http_output_filter 函数发送响应，但是要知道的是ngx_http_output_filter 函数是需要调用个包体过滤模块来处理剩余响应的out 链表缓冲区，并由最后一个过滤模块 ngx_http_write_filter_module 调用ngx_http_write_filter 方法将响应发送出去；因此，我们可知道，真正发送响应的函数是ngx_http_write_filter；
 * 
 */
static void
ngx_http_writer(ngx_http_request_t *r)
{
    ngx_int_t                  rc;
    ngx_event_t               *wev;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;

    /* 获取当前请求的连接 */
    c = r->connection;
    /* 获取连接上的写事件 */
    wev = c->write;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, wev->log, 0,
                   "http writer handler: \"%V?%V\"", &r->uri, &r->args);

    /* 获取ngx_http_core_module模块的loc级别配置项结构 */
    clcf = ngx_http_get_module_loc_conf(r->main, ngx_http_core_module);

    if (wev->timedout) {        //超时
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "client timed out");
        c->timedout = 1;

        ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    /**
     * 写事件已经超时，这时有两种可能性：第 一种，由于网络异常或者客户端长时间不接收响应，导致真实的发送响应超时；
     * 第二种，由 于上一次发送响应时发送速率过快，超过了请求的limit_rate速率上限，而上节的 ngx_http_write_filter方法就会设置一个超时时间将写事件添加到定时器中，
     * 这时本次的超时 只是由限速导致，并非真正超时
     * 
     * 判断这个超时是真的超时还是出于限速？delayed标志位。
     * 如果是限速把写事件加入定时器，一定会把delayed标志位置为1
     */
    if (wev->delayed || r->aio) {   //延迟
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0,
                       "http writer delayed");

        if (!wev->delayed) {    //非限速超时
            ngx_add_timer(wev, clcf->send_timeout);
        }

        //仍然添加事件监听
        if (ngx_handle_write_event(wev, clcf->send_lowat) != NGX_OK) {
            ngx_http_close_request(r, 0);
        }

        return;
    }

    //调用ngx_http_output_filter方法发送响应，其中第2个参数（也就是表示需要发送的缓 冲区）为NULL指针。
    //这意味着，需要调用各包体过滤模块处理out缓冲区中的剩余内容，最后调用ngx_http_write_filter方法把响应发送出去
    rc = ngx_http_output_filter(r, NULL);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http writer output filter: %i, \"%V?%V\"",
                   rc, &r->uri, &r->args);

    /* 若发送响应错误，则调用ngx_http_finalize_request结束请求，并return返回 */
    if (rc == NGX_ERROR) {
        ngx_http_finalize_request(r, rc);
        return;
    }

    /*
     * 若成功发送响应，则检查当前请求的out链表缓冲区是否存在剩余待发送的响应报文，
     * 若存在剩余待发送响应，又因为此时写事件不可写，则将其添加到定时器机制，注册到epoll事件机制中，
     * 等待可写事件的发生生；*/
    if (r->buffered || r->postponed || (r == r->main && c->buffered)) {

        if (!wev->delayed) {
            ngx_add_timer(wev, clcf->send_timeout);
        }

        if (ngx_handle_write_event(wev, clcf->send_lowat) != NGX_OK) {
            ngx_http_close_request(r, 0);
        }

        return;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, wev->log, 0,
                   "http writer done: \"%V?%V\"", &r->uri, &r->args);

    /*
     * 若当前out链表缓冲区不存在未发送的响应数据，则表示已成功发送完整的响应数据，
     * 此时，重新设置写事件的回调方法为ngx_http_request_empty_handler即不进行任何操作；
     */
    r->write_event_handler = ngx_http_request_empty_handler;

    ngx_http_finalize_request(r, rc);
}


static void
ngx_http_request_finalizer(ngx_http_request_t *r)
{
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http finalizer done: \"%V?%V\"", &r->uri, &r->args);

    ngx_http_finalize_request(r, 0);
}


void
ngx_http_block_reading(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http reading blocked");

    /* aio does not call this handler */

    //水平触发，移除事件监听
    if ((ngx_event_flags & NGX_USE_LEVEL_EVENT)
        && r->connection->read->active)
    {
        if (ngx_del_event(r->connection->read, NGX_READ_EVENT, 0) != NGX_OK) {
            ngx_http_close_request(r, 0);
        }
    }
}


/**
 * read_event_handler
 */
void
ngx_http_test_reading(ngx_http_request_t *r)
{
    int                n;
    char               buf[1];
    ngx_err_t          err;
    ngx_event_t       *rev;
    ngx_connection_t  *c;

    c = r->connection;
    rev = c->read;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http test reading");

#if (NGX_HTTP_V2)

    if (r->stream) {
        if (c->error) {
            err = 0;
            goto closed;
        }

        return;
    }

#endif

#if (NGX_HTTP_V3)

    if (c->quic) {
        if (rev->error) {
            c->error = 1;
            err = 0;
            goto closed;
        }

        return;
    }

#endif

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {

        if (!rev->pending_eof) {
            return;
        }

        rev->eof = 1;
        c->error = 1;
        err = rev->kq_errno;

        goto closed;
    }

#endif

#if (NGX_HAVE_EPOLLRDHUP)

    if ((ngx_event_flags & NGX_USE_EPOLL_EVENT) && ngx_use_epoll_rdhup) {
        socklen_t  len;

        if (!rev->pending_eof) {
            return;
        }

        rev->eof = 1;
        c->error = 1;

        err = 0;
        len = sizeof(ngx_err_t);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = ngx_socket_errno;
        }

        goto closed;
    }

#endif

    n = recv(c->fd, buf, 1, MSG_PEEK);

    if (n == 0) {
        rev->eof = 1;
        c->error = 1;
        err = 0;

        goto closed;

    } else if (n == -1) {
        err = ngx_socket_errno;

        if (err != NGX_EAGAIN) {
            rev->eof = 1;
            c->error = 1;

            goto closed;
        }
    }

    /* aio does not call this handler */

    if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && rev->active) {

        if (ngx_del_event(rev, NGX_READ_EVENT, 0) != NGX_OK) {
            ngx_http_close_request(r, 0);
        }
    }

    return;

closed:

    if (err) {
        rev->error = 1;
    }

#if (NGX_HTTP_SSL)
    if (c->ssl) {
        c->ssl->no_send_shutdown = 1;
    }
#endif

    ngx_log_error(NGX_LOG_INFO, c->log, err,
                  "client prematurely closed connection");

    ngx_http_finalize_request(r, NGX_HTTP_CLIENT_CLOSED_REQUEST);
}


/**
 * 由ngx_http_finalize_connection调用
 * 将当前连接设置为keepalive状态，会将ngx_http_request_t结构体释放，但不会关闭TCP连接
 * 同时也会检测keepalive连接是否超时
 */
static void
ngx_http_set_keepalive(ngx_http_request_t *r)
{
    int                        tcp_nodelay;
    ngx_buf_t                 *b, *f;
    ngx_chain_t               *cl, *ln;
    ngx_event_t               *rev, *wev;
    ngx_connection_t          *c;
    ngx_http_connection_t     *hc;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;
    rev = c->read;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "set http keepalive handler");

    c->log->action = "closing request";

    hc = r->http_connection;
    b = r->header_in;

    if (b->pos < b->last) {

        /* the pipelined request */

        if (b != c->buffer) {

            /*
             * If the large header buffers were allocated while the previous
             * request processing then we do not use c->buffer for
             * the pipelined request (see ngx_http_create_request()).
             *
             * Now we would move the large header buffers to the free list.
             */

            for (cl = hc->busy; cl; /* void */) {
                ln = cl;
                cl = cl->next;

                if (ln->buf == b) {
                    ngx_free_chain(c->pool, ln);
                    continue;
                }

                f = ln->buf;
                f->pos = f->start;
                f->last = f->start;

                ln->next = hc->free;
                hc->free = ln;
            }

            cl = ngx_alloc_chain_link(c->pool);
            if (cl == NULL) {
                ngx_http_close_request(r, 0);
                return;
            }

            cl->buf = b;
            cl->next = NULL;

            hc->busy = cl;
            hc->nbusy = 1;
        }
    }

    /* guard against recursive call from ngx_http_finalize_connection() */
    r->keepalive = 0;

    ngx_http_free_request(r, 0);

    c->data = hc;

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_http_close_connection(c);
        return;
    }

    wev = c->write;
    wev->handler = ngx_http_empty_handler;

    if (b->pos < b->last) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "pipelined request");

        c->log->action = "reading client pipelined request line";

        r = ngx_http_create_request(c);
        if (r == NULL) {
            ngx_http_close_connection(c);
            return;
        }

        r->pipeline = 1;

        c->data = r;

        c->sent = 0;
        c->destroyed = 0;
        c->pipeline = 1;

        if (rev->timer_set) {
            ngx_del_timer(rev);
        }

        rev->handler = ngx_http_process_request_line;
        ngx_post_event(rev, &ngx_posted_events);
        return;
    }

    /*
     * To keep a memory footprint as small as possible for an idle keepalive
     * connection we try to free c->buffer's memory if it was allocated outside
     * the c->pool.  The large header buffers are always allocated outside the
     * c->pool and are freed too.
     */

    b = c->buffer;

    if (ngx_pfree(c->pool, b->start) == NGX_OK) {

        /*
         * the special note for ngx_http_keepalive_handler() that
         * c->buffer's memory was freed
         */

        b->pos = NULL;

    } else {
        b->pos = b->start;
        b->last = b->start;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "hc free: %p",
                   hc->free);

    if (hc->free) {
        for (cl = hc->free; cl; /* void */) {
            ln = cl;
            cl = cl->next;
            ngx_pfree(c->pool, ln->buf->start);
            ngx_free_chain(c->pool, ln);
        }

        hc->free = NULL;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0, "hc busy: %p %i",
                   hc->busy, hc->nbusy);

    if (hc->busy) {
        for (cl = hc->busy; cl; /* void */) {
            ln = cl;
            cl = cl->next;
            ngx_pfree(c->pool, ln->buf->start);
            ngx_free_chain(c->pool, ln);
        }

        hc->busy = NULL;
        hc->nbusy = 0;
    }

#if (NGX_HTTP_SSL)
    if (c->ssl) {
        ngx_ssl_free_buffer(c);
    }
#endif

    rev->handler = ngx_http_keepalive_handler;

    if (wev->active && (ngx_event_flags & NGX_USE_LEVEL_EVENT)) {
        if (ngx_del_event(wev, NGX_WRITE_EVENT, 0) != NGX_OK) {
            ngx_http_close_connection(c);
            return;
        }
    }

    c->log->action = "keepalive";

    if (c->tcp_nopush == NGX_TCP_NOPUSH_SET) {
        if (ngx_tcp_push(c->fd) == -1) {
            ngx_connection_error(c, ngx_socket_errno, ngx_tcp_push_n " failed");
            ngx_http_close_connection(c);
            return;
        }

        c->tcp_nopush = NGX_TCP_NOPUSH_UNSET;
        tcp_nodelay = ngx_tcp_nodelay_and_tcp_nopush ? 1 : 0;

    } else {
        tcp_nodelay = 1;
    }

    if (tcp_nodelay && clcf->tcp_nodelay && ngx_tcp_nodelay(c) != NGX_OK) {
        ngx_http_close_connection(c);
        return;
    }

#if 0
    /* if ngx_http_request_t was freed then we need some other place */
    r->http_state = NGX_HTTP_KEEPALIVE_STATE;
#endif

    if (clcf->keepalive_min_timeout == 0) {
        c->idle = 1;
        ngx_reusable_connection(c, 1);
    }

    if (clcf->keepalive_min_timeout > 0
        && clcf->keepalive_timeout > clcf->keepalive_min_timeout)
    {
        hc->keepalive_timeout = clcf->keepalive_timeout
                                - clcf->keepalive_min_timeout;

    } else {
        hc->keepalive_timeout = 0;
    }

    ngx_add_timer(rev, clcf->keepalive_timeout - hc->keepalive_timeout);

    if (rev->ready) {
        ngx_post_event(rev, &ngx_posted_events);
    }
}


static void
ngx_http_keepalive_handler(ngx_event_t *rev)
{
    size_t                  size;
    ssize_t                 n;
    ngx_buf_t              *b;
    ngx_connection_t       *c;
    ngx_http_connection_t  *hc;

    c = rev->data;
    hc = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http keepalive handler");

    if (!ngx_terminate
         && !ngx_exiting
         && rev->timedout
         && hc->keepalive_timeout > 0)
    {
        c->idle = 1;
        ngx_reusable_connection(c, 1);

        ngx_add_timer(rev, hc->keepalive_timeout);

        hc->keepalive_timeout = 0;
        rev->timedout = 0;
        return;
    }

    if (rev->timedout || c->close) {
        ngx_http_close_connection(c);
        return;
    }

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
        if (rev->pending_eof) {
            c->log->handler = NULL;
            ngx_log_error(NGX_LOG_INFO, c->log, rev->kq_errno,
                          "kevent() reported that client %V closed "
                          "keepalive connection", &c->addr_text);
#if (NGX_HTTP_SSL)
            if (c->ssl) {
                c->ssl->no_send_shutdown = 1;
            }
#endif
            ngx_http_close_connection(c);
            return;
        }
    }

#endif

    b = c->buffer;
    size = b->end - b->start;

    if (b->pos == NULL) {

        /*
         * The c->buffer's memory was freed by ngx_http_set_keepalive().
         * However, the c->buffer->start and c->buffer->end were not changed
         * to keep the buffer size.
         */

        b->pos = ngx_palloc(c->pool, size);
        if (b->pos == NULL) {
            ngx_http_close_connection(c);
            return;
        }

        b->start = b->pos;
        b->last = b->pos;
        b->end = b->pos + size;
    }

    /*
     * MSIE closes a keepalive connection with RST flag
     * so we ignore ECONNRESET here.
     */

    c->log_error = NGX_ERROR_IGNORE_ECONNRESET;
    ngx_set_socket_errno(0);

    n = c->recv(c, b->last, size);
    c->log_error = NGX_ERROR_INFO;

    if (n == NGX_AGAIN) {
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_http_close_connection(c);
            return;
        }

        /*
         * Like ngx_http_set_keepalive() we are trying to not hold
         * c->buffer's memory for a keepalive connection.
         */

        if (ngx_pfree(c->pool, b->start) == NGX_OK) {

            /*
             * the special note that c->buffer's memory was freed
             */

            b->pos = NULL;
        }

        return;
    }

    if (n == NGX_ERROR) {
        ngx_http_close_connection(c);
        return;
    }

    c->log->handler = NULL;

    if (n == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, ngx_socket_errno,
                      "client %V closed keepalive connection", &c->addr_text);
        ngx_http_close_connection(c);
        return;
    }

    b->last += n;

    c->log->handler = ngx_http_log_error;
    c->log->action = "reading client request line";

    c->idle = 0;
    ngx_reusable_connection(c, 0);

    c->data = ngx_http_create_request(c);
    if (c->data == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    c->sent = 0;
    c->destroyed = 0;

    ngx_del_timer(rev);

    rev->handler = ngx_http_process_request_line;
    ngx_http_process_request_line(rev);
}


static void
ngx_http_set_lingering_close(ngx_connection_t *c)
{
    ngx_event_t               *rev, *wev;
    ngx_http_request_t        *r;
    ngx_http_core_loc_conf_t  *clcf;

    r = c->data;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (r->lingering_time == 0) {
        r->lingering_time = ngx_time() + (time_t) (clcf->lingering_time / 1000);
    }

#if (NGX_HTTP_SSL)
    if (c->ssl) {
        ngx_int_t  rc;

        c->ssl->shutdown_without_free = 1;

        rc = ngx_ssl_shutdown(c);

        if (rc == NGX_ERROR) {
            ngx_http_close_request(r, 0);
            return;
        }

        if (rc == NGX_AGAIN) {
            c->ssl->handler = ngx_http_set_lingering_close;
            return;
        }
    }
#endif

    rev = c->read;
    rev->handler = ngx_http_lingering_close_handler;

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_http_close_request(r, 0);
        return;
    }

    wev = c->write;
    wev->handler = ngx_http_empty_handler;

    if (wev->active && (ngx_event_flags & NGX_USE_LEVEL_EVENT)) {
        if (ngx_del_event(wev, NGX_WRITE_EVENT, 0) != NGX_OK) {
            ngx_http_close_request(r, 0);
            return;
        }
    }

    if (ngx_shutdown_socket(c->fd, NGX_WRITE_SHUTDOWN) == -1) {
        ngx_connection_error(c, ngx_socket_errno,
                             ngx_shutdown_socket_n " failed");
        ngx_http_close_request(r, 0);
        return;
    }

    c->close = 0;
    ngx_reusable_connection(c, 1);

    ngx_add_timer(rev, clcf->lingering_timeout);

    if (rev->ready) {
        ngx_http_lingering_close_handler(rev);
    }
}


static void
ngx_http_lingering_close_handler(ngx_event_t *rev)
{
    ssize_t                    n;
    ngx_msec_t                 timer;
    ngx_connection_t          *c;
    ngx_http_request_t        *r;
    ngx_http_core_loc_conf_t  *clcf;
    u_char                     buffer[NGX_HTTP_LINGERING_BUFFER_SIZE];

    c = rev->data;
    r = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http lingering close handler");

    if (rev->timedout || c->close) {
        ngx_http_close_request(r, 0);
        return;
    }

    timer = (ngx_msec_t) r->lingering_time - (ngx_msec_t) ngx_time();
    if ((ngx_msec_int_t) timer <= 0) {
        ngx_http_close_request(r, 0);
        return;
    }

    do {
        n = c->recv(c, buffer, NGX_HTTP_LINGERING_BUFFER_SIZE);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "lingering read: %z", n);

        if (n == NGX_AGAIN) {
            break;
        }

        if (n == NGX_ERROR || n == 0) {
            ngx_http_close_request(r, 0);
            return;
        }

    } while (rev->ready);

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_http_close_request(r, 0);
        return;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    timer *= 1000;

    if (timer > clcf->lingering_timeout) {
        timer = clcf->lingering_timeout;
    }

    ngx_add_timer(rev, timer);
}


void
ngx_http_empty_handler(ngx_event_t *wev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0, "http empty handler");

    return;
}


void
ngx_http_request_empty_handler(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http request empty handler");

    return;
}

/**
 * 发送控制buf, flags可以是NGX_HTTP_LAST和NGX_HTTP_FLUSH
 * 创建一个新的chain, 并挂载buf, 设置控制标志，然后发送出去
 */
ngx_int_t
ngx_http_send_special(ngx_http_request_t *r, ngx_uint_t flags)
{
    ngx_buf_t    *b;
    ngx_chain_t   out;

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    if (flags & NGX_HTTP_LAST) {

        if (r == r->main && !r->post_action) {  //主请求且没有post_action
            b->last_buf = 1;

        } else {
            b->sync = 1;
            b->last_in_chain = 1;
        }
    }

    if (flags & NGX_HTTP_FLUSH) {       //flash
        b->flush = 1;
    }

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


static ngx_int_t
ngx_http_post_action(ngx_http_request_t *r)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (clcf->post_action.data == NULL) {
        return NGX_DECLINED;
    }

    if (r->post_action && r->uri_changes == 0) {
        return NGX_DECLINED;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "post action: \"%V\"", &clcf->post_action);

    r->main->count--;

    r->http_version = NGX_HTTP_VERSION_9;
    r->header_only = 1;
    r->post_action = 1;

    r->read_event_handler = ngx_http_block_reading;

    if (clcf->post_action.data[0] == '/') {
        ngx_http_internal_redirect(r, &clcf->post_action, NULL);

    } else {
        ngx_http_named_location(r, &clcf->post_action);
    }

    return NGX_OK;
}


/**
 * 是比ngx_http_free_request更高层的用于关闭请求
 * 主要负责引用计数检测
 */
void
ngx_http_close_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_connection_t  *c;

    r = r->main;        //取出原始请求
    c = r->connection;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http request count:%d blk:%d", r->count, r->blocked);

    if (r->count == 0) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "http request count is zero");
    }

    r->count--;

    //引用计数不为0。blocked标志位主要由异步I/O使用
    if (r->count || r->blocked) {
        return;
    }
    //引用计数清零
#if (NGX_HTTP_V2)
    if (r->stream) {
        ngx_http_v2_close_stream(r->stream, rc);
        return;
    }
#endif

    /*
     * 若引用计数此时为0（表示请求没有其他动作要使用），
     * 且blocked也为0（表示没有HTTP模块还需要处理请求），
     * 则调用ngx_http_free_request释放请求所对应的结构体ngx_http_request_t，
     * 调用ngx_http_close_connection关闭当前连接；
     */
    ngx_http_free_request(r, rc);
    //关闭连接
    ngx_http_close_connection(c);
}


/**
 * 会释放请求对应的ngx_http_request_t数据结构
 * 1. 执行r中的cleanup链表
 * 2. 执行log_phase
 * 3. 销毁r上的内存池
 */
void
ngx_http_free_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_t                 *log;
    ngx_pool_t                *pool;
    struct linger              linger;
    ngx_http_cleanup_t        *cln;
    ngx_http_log_ctx_t        *ctx;
    ngx_http_core_loc_conf_t  *clcf;

    log = r->connection->log;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "http close request");

    if (r->pool == NULL) {
        ngx_log_error(NGX_LOG_ALERT, log, 0, "http request already closed");
        return;
    }

    /* 获取当前请求的清理cleanup方法 */
    cln = r->cleanup;
    r->cleanup = NULL;

    //循环地遍历请求ngx_http_request_t结构体中的cleanup链表，
    //依次调用每一个 ngx_http_cleanup_pt方法释放资源
    while (cln) {
        if (cln->handler) {
            cln->handler(cln->data);
        }

        cln = cln->next;
    }

#if (NGX_STAT_STUB)

    //更新共享内存计数
    if (r->stat_reading) {
        (void) ngx_atomic_fetch_add(ngx_stat_reading, -1);
    }

    if (r->stat_writing) {
        (void) ngx_atomic_fetch_add(ngx_stat_writing, -1);
    }

#endif

    if (rc > 0 && (r->headers_out.status == 0 || r->connection->sent == 0)) {
        r->headers_out.status = rc;
    }

    //2. 执行log_phase
    if (!r->logged) {
        log->action = "logging request";

        ngx_http_log_request(r);
    }

    log->action = "closing request";

    if (r->connection->timedout
#if (NGX_HTTP_V3)
        && r->connection->quic == NULL
#endif
       )
    {
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        if (clcf->reset_timedout_connection) {
            linger.l_onoff = 1;
            linger.l_linger = 0;

            if (setsockopt(r->connection->fd, SOL_SOCKET, SO_LINGER,
                           (const void *) &linger, sizeof(struct linger)) == -1)
            {
                ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno,
                              "setsockopt(SO_LINGER) failed");
            }
        }
    }

    /* the various request strings were allocated from r->pool */
    ctx = log->data;
    ctx->request = NULL;

    r->request_line.len = 0;

    r->connection->destroyed = 1;

    /*
     * Setting r->pool to NULL will increase probability to catch double close
     * of request since the request object is allocated from its own pool.
     */

    pool = r->pool;
    r->pool = NULL;

    //3.销毁内存池
    ngx_destroy_pool(pool);
}


/**
 * 由ngx_http_free_request 调用而来
 * 执行log_phase
 */
static void
ngx_http_log_request(ngx_http_request_t *r)
{
    ngx_uint_t                  i, n;
    ngx_http_handler_pt        *log_handler;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    log_handler = cmcf->phases[NGX_HTTP_LOG_PHASE].handlers.elts;
    n = cmcf->phases[NGX_HTTP_LOG_PHASE].handlers.nelts;

    for (i = 0; i < n; i++) {
        log_handler[i](r);
    }
}


/**
 * 用于释放TCP连接
 */
void
ngx_http_close_connection(ngx_connection_t *c)
{
    ngx_pool_t  *pool;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "close http connection: %d", c->fd);

#if (NGX_HTTP_SSL)

    if (c->ssl) {
        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
            c->ssl->handler = ngx_http_close_connection;
            return;
        }
    }

#endif

#if (NGX_HTTP_V3)
    if (c->quic) {
        ngx_http_v3_reset_stream(c);
    }
#endif

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif

    /* 设置当前连接的destroyed标志位为1，表示即将销毁该连接 */
    c->destroyed = 1;

    pool = c->pool;

    /* 关闭套接字连接 */
    ngx_close_connection(c);

    /* 销毁连接所使用的内存池 */
    ngx_destroy_pool(pool);
}


static u_char *
ngx_http_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char              *p;
    ngx_http_request_t  *r;
    ngx_http_log_ctx_t  *ctx;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    ctx = log->data;

    p = ngx_snprintf(buf, len, ", client: %V", &ctx->connection->addr_text);
    len -= p - buf;

    r = ctx->request;

    if (r) {
        return r->log_handler(r, ctx->current_request, p, len);

    } else {
        p = ngx_snprintf(p, len, ", server: %V",
                         &ctx->connection->listening->addr_text);
    }

    return p;
}


static u_char *
ngx_http_log_error_handler(ngx_http_request_t *r, ngx_http_request_t *sr,
    u_char *buf, size_t len)
{
    char                      *uri_separator;
    u_char                    *p;
    ngx_http_upstream_t       *u;
    ngx_http_core_srv_conf_t  *cscf;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    p = ngx_snprintf(buf, len, ", server: %V", &cscf->server_name);
    len -= p - buf;
    buf = p;

    if (r->request_line.data == NULL && r->request_start) {
        for (p = r->request_start; p < r->header_in->last; p++) {
            if (*p == CR || *p == LF) {
                break;
            }
        }

        r->request_line.len = p - r->request_start;
        r->request_line.data = r->request_start;
    }

    if (r->request_line.len) {
        p = ngx_snprintf(buf, len, ", request: \"%V\"", &r->request_line);
        len -= p - buf;
        buf = p;
    }

    if (r != sr) {
        p = ngx_snprintf(buf, len, ", subrequest: \"%V\"", &sr->uri);
        len -= p - buf;
        buf = p;
    }

    u = sr->upstream;

    if (u && u->peer.name) {

        uri_separator = "";

#if (NGX_HAVE_UNIX_DOMAIN)
        if (u->peer.sockaddr && u->peer.sockaddr->sa_family == AF_UNIX) {
            uri_separator = ":";
        }
#endif

        p = ngx_snprintf(buf, len, ", upstream: \"%V%V%s%V\"",
                         &u->schema, u->peer.name,
                         uri_separator, &u->uri);
        len -= p - buf;
        buf = p;
    }

    if (r->headers_in.host) {
        p = ngx_snprintf(buf, len, ", host: \"%V\"",
                         &r->headers_in.host->value);
        len -= p - buf;
        buf = p;
    }

    if (r->headers_in.referer) {
        p = ngx_snprintf(buf, len, ", referrer: \"%V\"",
                         &r->headers_in.referer->value);
        buf = p;
    }

    return buf;
}
