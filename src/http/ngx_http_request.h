
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_REQUEST_H_INCLUDED_
#define _NGX_HTTP_REQUEST_H_INCLUDED_


#define NGX_HTTP_MAX_URI_CHANGES           10
#define NGX_HTTP_MAX_SUBREQUESTS           50

/* must be 2^n */
#define NGX_HTTP_LC_HEADER_LEN             32


#define NGX_HTTP_DISCARD_BUFFER_SIZE       4096
#define NGX_HTTP_LINGERING_BUFFER_SIZE     4096


#define NGX_HTTP_VERSION_9                 9
#define NGX_HTTP_VERSION_10                1000
#define NGX_HTTP_VERSION_11                1001
#define NGX_HTTP_VERSION_20                2000
#define NGX_HTTP_VERSION_30                3000

#define NGX_HTTP_UNKNOWN                   0x00000001
#define NGX_HTTP_GET                       0x00000002
#define NGX_HTTP_HEAD                      0x00000004
#define NGX_HTTP_POST                      0x00000008
#define NGX_HTTP_PUT                       0x00000010
#define NGX_HTTP_DELETE                    0x00000020
#define NGX_HTTP_MKCOL                     0x00000040
#define NGX_HTTP_COPY                      0x00000080
#define NGX_HTTP_MOVE                      0x00000100
#define NGX_HTTP_OPTIONS                   0x00000200
#define NGX_HTTP_PROPFIND                  0x00000400
#define NGX_HTTP_PROPPATCH                 0x00000800
#define NGX_HTTP_LOCK                      0x00001000
#define NGX_HTTP_UNLOCK                    0x00002000
#define NGX_HTTP_PATCH                     0x00004000
#define NGX_HTTP_TRACE                     0x00008000
#define NGX_HTTP_CONNECT                   0x00010000

#define NGX_HTTP_CONNECTION_CLOSE          1
#define NGX_HTTP_CONNECTION_KEEP_ALIVE     2


#define NGX_NONE                           1


#define NGX_HTTP_PARSE_HEADER_DONE         1

#define NGX_HTTP_CLIENT_ERROR              10
#define NGX_HTTP_PARSE_INVALID_METHOD      10
#define NGX_HTTP_PARSE_INVALID_REQUEST     11
#define NGX_HTTP_PARSE_INVALID_VERSION     12
#define NGX_HTTP_PARSE_INVALID_09_METHOD   13

#define NGX_HTTP_PARSE_INVALID_HEADER      14


/* unused                                  1 */
//输出不会发送到客户端，而是存储在内存中。该标志仅影响由代理模块之一处理的子请求。在子请求完成后，它的输出信息保存在类型为 ngx_buf_t的 r->out变量中
//Output is not sent to the client, but rather stored in memory. The flag only affects subrequests which are processed by one of the proxying modules. After a subrequest is finalized its output is available in r->out of type ngx_buf_t
#define NGX_HTTP_SUBREQUEST_IN_MEMORY      2
//The subrequest's done flag is set even if the subrequest is not active when it is finalized. This subrequest flag is used by the SSI filter
//表示如果该子请求提前完成(按后序遍历的顺序)，是否设置将它的状态设为done，当设置该参数时，提前完成就会设置done，不设时，会让该子请求等待它之前的子请求处理完毕才会将状态设置为done
#define NGX_HTTP_SUBREQUEST_WAITED         4
//The subrequest is created as a clone of its parent. It is started at the same location and proceeds from the same phase as the parent request
//子请求是作为其父的克隆而创建的。它是在同一位置开始的，并从与父级请求相同的阶段开始
#define NGX_HTTP_SUBREQUEST_CLONE          8
//创建后台子请求。此类子请求不参与主请求的响应构造，也就不会占用主请求的响应时间，但它依然会保持对主请求的引用
#define NGX_HTTP_SUBREQUEST_BACKGROUND     16

#define NGX_HTTP_LOG_UNSAFE                1


#define NGX_HTTP_CONTINUE                  100
#define NGX_HTTP_SWITCHING_PROTOCOLS       101
#define NGX_HTTP_PROCESSING                102
#define NGX_HTTP_EARLY_HINTS               103

//https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Reference/Status/412
#define NGX_HTTP_OK                        200
#define NGX_HTTP_CREATED                   201
#define NGX_HTTP_ACCEPTED                  202
#define NGX_HTTP_NO_CONTENT                204
#define NGX_HTTP_PARTIAL_CONTENT           206

#define NGX_HTTP_SPECIAL_RESPONSE          300
#define NGX_HTTP_MOVED_PERMANENTLY         301
#define NGX_HTTP_MOVED_TEMPORARILY         302
#define NGX_HTTP_SEE_OTHER                 303
#define NGX_HTTP_NOT_MODIFIED              304
#define NGX_HTTP_TEMPORARY_REDIRECT        307
#define NGX_HTTP_PERMANENT_REDIRECT        308

#define NGX_HTTP_BAD_REQUEST               400
#define NGX_HTTP_UNAUTHORIZED              401
#define NGX_HTTP_FORBIDDEN                 403
#define NGX_HTTP_NOT_FOUND                 404
#define NGX_HTTP_NOT_ALLOWED               405
#define NGX_HTTP_PROXY_AUTH_REQUIRED       407
#define NGX_HTTP_REQUEST_TIME_OUT          408
#define NGX_HTTP_CONFLICT                  409
#define NGX_HTTP_LENGTH_REQUIRED           411
#define NGX_HTTP_PRECONDITION_FAILED       412
#define NGX_HTTP_REQUEST_ENTITY_TOO_LARGE  413
#define NGX_HTTP_REQUEST_URI_TOO_LARGE     414
#define NGX_HTTP_UNSUPPORTED_MEDIA_TYPE    415
#define NGX_HTTP_RANGE_NOT_SATISFIABLE     416
#define NGX_HTTP_MISDIRECTED_REQUEST       421
#define NGX_HTTP_TOO_MANY_REQUESTS         429


/* Our own HTTP codes */

/* The special code to close connection without any response */
#define NGX_HTTP_CLOSE                     444

#define NGX_HTTP_NGINX_CODES               494

#define NGX_HTTP_REQUEST_HEADER_TOO_LARGE  494

#define NGX_HTTPS_CERT_ERROR               495
#define NGX_HTTPS_NO_CERT                  496

/*
 * We use the special code for the plain HTTP requests that are sent to
 * HTTPS port to distinguish it from 4XX in an error page redirection
 */
#define NGX_HTTP_TO_HTTPS                  497

/* 498 is the canceled code for the requests with invalid host name */

/*
 * HTTP does not define the code for the case when a client closed
 * the connection while we are processing its request so we introduce
 * own code to log such situation when a client has closed the connection
 * before we even try to send the HTTP header to it
 */
#define NGX_HTTP_CLIENT_CLOSED_REQUEST     499


#define NGX_HTTP_INTERNAL_SERVER_ERROR     500
#define NGX_HTTP_NOT_IMPLEMENTED           501
#define NGX_HTTP_BAD_GATEWAY               502
#define NGX_HTTP_SERVICE_UNAVAILABLE       503
#define NGX_HTTP_GATEWAY_TIME_OUT          504
#define NGX_HTTP_VERSION_NOT_SUPPORTED     505
#define NGX_HTTP_INSUFFICIENT_STORAGE      507


#define NGX_HTTP_LOWLEVEL_BUFFERED         0xf0
#define NGX_HTTP_WRITE_BUFFERED            0x10
#define NGX_HTTP_GZIP_BUFFERED             0x20
#define NGX_HTTP_SSI_BUFFERED              0x01
#define NGX_HTTP_SUB_BUFFERED              0x02
#define NGX_HTTP_COPY_BUFFERED             0x04


//http报文解析状态， r->http_state
typedef enum {
    NGX_HTTP_INITING_REQUEST_STATE = 0,     //初始状态，不使用
    NGX_HTTP_READING_REQUEST_STATE,         //刚创建请求对象，正在读取请求数据
    NGX_HTTP_PROCESS_REQUEST_STATE,         //请求头解析完毕，准备处理请求

    NGX_HTTP_CONNECT_UPSTREAM_STATE,        //正在连接后端upstream
    NGX_HTTP_WRITING_UPSTREAM_STATE,        //向后端upstream发送数据
    NGX_HTTP_READING_UPSTREAM_STATE,        //从后端upstream读取数据

    NGX_HTTP_WRITING_REQUEST_STATE,         //响应请求，向客户端发送数据
    NGX_HTTP_LINGERING_CLOSE_STATE,         //延迟关闭状态
    NGX_HTTP_KEEPALIVE_STATE                //长连接keepalive
} ngx_http_state_e;


//ngx_http_upstream_headers_in的元素，解析客户端请求头时使用
typedef struct {
    ngx_str_t                         name;     //头部名称
    ngx_uint_t                        offset;   //在headers_in偏移
    ngx_http_header_handler_pt        handler;  //handler解析rfc中常见请求头。请r->headers_in.headers中的解析为r->headers_in中对应字段快速引用
} ngx_http_header_t;


typedef struct {
    ngx_str_t                         name;
    ngx_uint_t                        offset;
} ngx_http_header_out_t;


/**
 *  r->headers_in
 *  表示所有请求头部
 *  
 */
typedef struct {
    //所有解析过的 HTTP头部都在 headers链表中，每一个元素都是ngx_table_elt_t成员
    ngx_list_t                        headers;
    ngx_uint_t                        count;

    /**
     * 以下每个 ngx_table_elt_t成员都是 RFC2616规范中定义的 HTTP头部， 它们实际都指向 headers链表中的相应成员
     * 
     * 当它们为NULL空指针时，表示没有解析到相应的 HTTP头部
     */
    ngx_table_elt_t                  *host;
    ngx_table_elt_t                  *connection;
    ngx_table_elt_t                  *if_modified_since;
    ngx_table_elt_t                  *if_unmodified_since;
    ngx_table_elt_t                  *if_match;
    ngx_table_elt_t                  *if_none_match;
    ngx_table_elt_t                  *user_agent;
    ngx_table_elt_t                  *referer;
    ngx_table_elt_t                  *content_length;
    ngx_table_elt_t                  *content_range;
    ngx_table_elt_t                  *content_type;

    ngx_table_elt_t                  *range;
    //常见的用例是恢复下载，以确保自最后一次片段接收以来，存储的资源没有发生更改
    ngx_table_elt_t                  *if_range;

    ngx_table_elt_t                  *transfer_encoding;
    ngx_table_elt_t                  *te;
    ngx_table_elt_t                  *expect;
    ngx_table_elt_t                  *upgrade;

#if (NGX_HTTP_GZIP || NGX_HTTP_HEADERS)
    ngx_table_elt_t                  *accept_encoding;
    ngx_table_elt_t                  *via;
#endif

    ngx_table_elt_t                  *authorization;
    ngx_table_elt_t                  *proxy_authorization;

    ngx_table_elt_t                  *keep_alive;

#if (NGX_HTTP_X_FORWARDED_FOR)
    ngx_table_elt_t                  *x_forwarded_for;
#endif

#if (NGX_HTTP_REALIP)
    ngx_table_elt_t                  *x_real_ip;
#endif

#if (NGX_HTTP_HEADERS)
    ngx_table_elt_t                  *accept;
    ngx_table_elt_t                  *accept_language;
#endif

#if (NGX_HTTP_DAV)
    ngx_table_elt_t                  *depth;
    ngx_table_elt_t                  *destination;
    ngx_table_elt_t                  *overwrite;
    ngx_table_elt_t                  *date;
#endif

    ngx_table_elt_t                  *cookie;

    ngx_str_t                         user;     //用户名
    ngx_str_t                         passwd;

    //请求Host
    ngx_str_t                         server;       //host
    // 根据 ngx_table_elt_t *content_length计算出的 HTTP包体大小
    off_t                             content_length_n; //content_length的数字格式
    time_t                            keep_alive_n;

    /**
     * 为1表示客户端请求头Connection: close; 为2 为Connection: keep-alive
     */
    unsigned                          connection_type:2;
    unsigned                          chunked:1;
    unsigned                          multi:1;
    unsigned                          multi_linked:1;
    unsigned                          msie:1;       //标识UA是否包含MSIE
    unsigned                          msie6:1;      //标识UA是否包含MSIE6
    unsigned                          opera:1;      //标识UA是否包含opera
    unsigned                          gecko:1;      //
    unsigned                          chrome:1;     //
    unsigned                          safari:1;     //
    unsigned                          konqueror:1;  //及以上几个标识都是解析浏览器类型
} ngx_http_headers_in_t;


/**
 * r->headers_out 表示所有响应头部
 * 只要指定headers_out中的成员，就可以在调用ngx_http_send_header时正确地把HTTP头部 发出
 */
typedef struct {
    // 待发送的 HTTP头部链表，与 headers_in中的 headers成员类似
    ngx_list_t                        headers;
    //在发送完响应后发送的响应头部。
    ngx_list_t                        trailers;

    ngx_uint_t                        status;   //响应中的状态值，如 200表示成功
    ngx_str_t                         status_line;  // 响应的状态行， 如 HTTP/1.1 201 CREATED

    /**
     * 以下成员（包括 ngx_table_elt_t）都是 RFC1616规范中定义的 HTTP头部，
     * 设置后， ngx_http_header_filter_module过滤模块可以把它们加到待发送的网络包中
     */
    ngx_table_elt_t                  *server;
    ngx_table_elt_t                  *date;
    ngx_table_elt_t                  *content_length;
    //响应体的内容编码,如gzip/deflate/br
    ngx_table_elt_t                  *content_encoding;
    ngx_table_elt_t                  *location;     //响应头Location
    ngx_table_elt_t                  *refresh;
    ngx_table_elt_t                  *last_modified;
    ngx_table_elt_t                  *content_range;
    ngx_table_elt_t                  *accept_ranges;
    ngx_table_elt_t                  *www_authenticate;
    ngx_table_elt_t                  *proxy_authenticate;
    ngx_table_elt_t                  *expires;
    ngx_table_elt_t                  *etag;

    ngx_table_elt_t                  *cache_control;
    ngx_table_elt_t                  *link;

    //X-Accel-Charset 响应头 参考 ngx_http_upstream_process_charset
    ngx_str_t                        *override_charset;

    //可以调用ngx_http_set_content_type(r)方法帮助我们设置Content-Type头部，
    //这个方法会根据URI中的文件扩展名并对应着mime.type来设置Content-Type值
    size_t                            content_type_len;
    ngx_str_t                         content_type;
    ngx_str_t                         charset;
    u_char                           *content_type_lowcase;
    ngx_uint_t                        content_type_hash;

    //在这里指定content_length_n后，不用再次到ngx_table_elt_t *content_ length中设置响应长度
    off_t                             content_length_n;
    off_t                             content_offset;
    time_t                            date_time;
    time_t                            last_modified_time;
} ngx_http_headers_out_t;


typedef void (*ngx_http_client_body_handler_pt)(ngx_http_request_t *r);


/**
 * Each HTTP client connection runs through the following stages:
 *  ngx_event_accept() accepts a client TCP connection. This handler is called in response to a read notification on a listen socket. 
 *           A new ngx_connection_t object is created at this stage to wrap the newly accepted client socket. 
 *           Each nginx listener provides a handler to pass the new connection object to. For HTTP connections it's ngx_http_init_connection(c).
 *  ngx_http_init_connection() performs early initialization of the HTTP connection. 
 *           At this stage an ngx_http_connection_t object is created for the connection and its reference is stored in the connection's data field.
 *           Later it will be replaced by an HTTP request object. A PROXY protocol parser and the SSL handshake are started at this stage as well.
 *  ngx_http_wait_request_handler() read event handler is called when data is available on the client socket. 
 *            At this stage an HTTP request object ngx_http_request_t is created and set to the connection's data field.
 *  ngx_http_process_request_line() read event handler reads client request line. The handler is set by ngx_http_wait_request_handler(). 
 *           The data is read into connection's buffer. The size of the buffer is initially set by the directive client_header_buffer_size. 
 *           The entire client header is supposed to fit in the buffer. If the initial size is not sufficient, a bigger buffer is allocated, with the capacity set by the large_client_header_buffers directive.
 *  ngx_http_process_request_headers() read event handler, is set after ngx_http_process_request_line() to read the client request header.
 *  ngx_http_core_run_phases() is called when the request header is completely read and parsed. 
 *          This function runs request phases from NGX_HTTP_POST_READ_PHASE to NGX_HTTP_CONTENT_PHASE. 
 *         The last phase is intended to generate a response and pass it along the filter chain. 
 *         The response is not necessarily sent to the client at this phase. It might remain buffered and be sent at the finalization stage.
 *  ngx_http_finalize_request() is usually called when the request has generated all the output or produced an error. 
 *         In the latter case an appropriate error page is looked up and used as the response. 
 *         If the response is not completely sent to the client by this point, an HTTP writer ngx_http_writer() is activated to finish sending outstanding data.
 *  ngx_http_finalize_connection() is called when the complete response has been sent to the client and the request can be destroyed. 
 *         If the client connection keepalive feature is enabled, ngx_http_set_keepalive() is called, which destroys the current request and waits for the next request on the connection. 
 *         Otherwise, ngx_http_close_request() destroys both the request and the connection.
 * 
 */

/**
 * The function ngx_http_read_client_request_body(r, post_handler) allocates the request_body request field of type ngx_http_request_body_t
 * 
 * 读取到的客户端请求体body保存到此结构体中, r->request_body成员
 * 
 * 保存请求体读取过程用到的缓存引用，临时文件引用，剩余请求体大小等信息
 * 
 */
typedef struct {
    // 指向储存请求体的临时文件的指针；
    ngx_temp_file_t                  *temp_file;    //不为NULL表示保存到了临时文件里
    //keeps the result as a buffer chain
    //指向保存请求体的链表头；
    //当包体需要全部存放在内存中时，如果一块 ngx_buf_t 缓冲区(即下边的buf字段)无法存放完，这时就需要使用 ngx_chain_t链表来存放
    //该链表最多可能有2个节点，每个节点为一个buffer，但是这个buffer的内容可能是保存在内存中，也可能是保存在磁盘文件中
    ngx_chain_t                      *bufs;
    //指向当前用于保存请求体的内存缓存；大小为client_body_buffer_size,如果超出此值，则需要通过上边的bufs来存放
    ngx_buf_t                        *buf;      //直接接收 HTTP包体的缓存
    //根据 content-length头部和已接收到的包体长度，计算出的还需要接收的包体长度
    off_t                             rest;     //剩余的待读取的请求体长度, 初始化为content-length
    off_t                             received;
    /* 接收HTTP请求包体缓冲区链表空闲缓冲区 */
    ngx_chain_t                      *free;
    /* 接收HTTP请求包体缓冲区链表已使用的缓冲区 */
    ngx_chain_t                      *busy;
    /* 保存chunked的解码状态，供ngx_http_parse_chunked方法使用 */
    ngx_http_chunked_t               *chunked;      //解析chunked请求
    //HTTP包体接收完毕后执行的回调方法，也就是 ngx_http_read_client_request_body 方法传递的第 2个参数
    ngx_http_client_body_handler_pt   post_handler;
    //If a filter is planning to delay data buffers, it should set the flag r->request_body->filter_need_buffering to 1 when called for the first time
    unsigned                          filter_need_buffering:1;
    unsigned                          last_sent:1;
    unsigned                          last_saved:1;
} ngx_http_request_body_t;      //r->request_body


typedef struct ngx_http_addr_conf_s  ngx_http_addr_conf_t;

//用来管理HTTP连接相关的配置信息和缓冲区信息
typedef struct {
    ngx_http_addr_conf_t             *addr_conf;    //保存server的基本信息
    ngx_http_conf_ctx_t              *conf_ctx;     //server{}里的配置结构体

#if (NGX_HTTP_SSL || NGX_COMPAT)
    ngx_str_t                        *ssl_servername;
#if (NGX_PCRE)
    ngx_http_regex_t                 *ssl_servername_regex;
#endif
#endif

    ngx_chain_t                      *busy;         //正在使用的数据块链
    //alloc_large_header_buffer时，已经使用的buffer的个数， 上边的busy数组长度
    ngx_int_t                         nbusy;        //数据块链长度

    ngx_chain_t                      *free;         //可复用的数据块链

    ngx_msec_t                        keepalive_timeout;

    //标明此链接上启用了ssl
    unsigned                          ssl:1;
    //此链接上是否启用proxy_protocol协议
    unsigned                          proxy_protocol:1;
} ngx_http_connection_t;


typedef void (*ngx_http_cleanup_pt)(void *data);

typedef struct ngx_http_cleanup_s  ngx_http_cleanup_t;

//任何一个请求的ngx_http_request_t结构体中都有一个ngx_http_cleanup_t类型的成 员cleanup
//ngx_pool_cleanup_t仅在所用的内存池 销毁时才会被调用来清理资源，它何时释放资源将视所使用的内存池而定，
//而 ngx_http_cleanup_pt是在ngx_http_request_t结构体释放时被调用来释放资源的
struct ngx_http_cleanup_s {
    ngx_http_cleanup_pt               handler;  //由 HTTP模块提供的清理资源的回调方法
    void                             *data;     //希望给上面的 handler方法传递的参数
    ngx_http_cleanup_t               *next;     ///一个请求可能会有多个 ngx_http_cleanup_t清理方法，这些清理方法间就是通过 next指针连接成单链表的
};


/**
 * 实现子请求处理完毕时的回调方法
 * data参数就是ngx_http_post_subrequest_t结构体中的data成员指针
 * rc参数是子请求在结束时的状态
 * 
 * 参考 ngx_http_finalize_request中 
 *  rc = r->post_subrequest->handler(r, r->post_subrequest->data, rc);
 * 
 * 
*/
typedef ngx_int_t (*ngx_http_post_subrequest_pt)(ngx_http_request_t *r,
    void *data, ngx_int_t rc);

/**
 * 为sr->post_subrequest
 * 
 * 建立此结构体把这个回调方法传递给subrequest子请求
 * 
 * handler中，必须设置父请求激活后的处理方法
 * 
 */
typedef struct {
    
    //此回调中，必须设置父请求激活后的处理方法. 即重新设置父请求的write_event_handler, 
    //因为此前父请求的write_event_handler已经被设置成了ngx_http_request_empty_handler
    ngx_http_post_subrequest_pt       handler;  //子请求结束的回调
    void                             *data;     //回调handler传参, 相当于上下文
} ngx_http_post_subrequest_t;


typedef struct ngx_http_postponed_request_s  ngx_http_postponed_request_t;

//为了能够正确组织子请求返回的数据，使用此结构组织子请求的响应
struct ngx_http_postponed_request_s {
    ngx_http_request_t               *request;  //子请求对象
    //子请求产生的响应
    ngx_chain_t                      *out;  //指向的是来自上游的、将要转发给下游的响应包体
    ngx_http_postponed_request_t     *next; //下一个链表节点, 即下一个postpone_request
};


typedef struct ngx_http_posted_request_s  ngx_http_posted_request_t;

/**
 * subrequest 子请求是基于 post 机制的
 * 
 * 子请求通过此节点组织成单向链表， r->main->posted_requests
 * 
 * 在请求结构体 ngx_http_request_t 中有一个与post 子请求相关的成员posted_requests，该成员把各个post 子请求按照子请求结构体ngx_http_posted_request_t 的结构连接成单链表的形式，请求结构体ngx_http_request_t 中main 成员是子请求的原始请求，parent 成员是子请求的父请求
 * 
 */
struct ngx_http_posted_request_s {
    ngx_http_request_t               *request;  //当前子请求
    ngx_http_posted_request_t        *next;     //下一个
};


/**
 * 由 HTTP模块实现的handler处理方法
 */
typedef ngx_int_t (*ngx_http_handler_pt)(ngx_http_request_t *r);

//父请求被激活后的回调方法由指针 ngx_http_event_handler_pt 实现。该方法负责把响应包发送给用户
typedef void (*ngx_http_event_handler_pt)(ngx_http_request_t *r);


/**
 * For each client HTTP request the ngx_http_request_t object is created
 */
struct ngx_http_request_s {
    uint32_t                          signature;         /* "HTTP" */

    /**
     * Pointer to a ngx_connection_t client connection object
     * Several requests can reference the same connection object at the same time - one main request and its subrequests
     * After a request is deleted, a new request can be created on the same connection
     */
    /**
     * Note that for HTTP connections ngx_connection_t's data field points back to the request.
     * Such requests are called active, as opposed to the other requests tied to the connection.
     * An active request is used to handle client connection events and is allowed to output its response to the client
     * Normally, each request becomes active at some point so that it can send its output
     */
    ngx_connection_t                 *connection;   // 这个请求对应的客户端连接

    /**
     * Array of HTTP module contexts
     * Each module of type NGX_HTTP_MODULE can store any value (normally, a pointer to a structure) in the request
     * The value is stored in the ctx array at the module's ctx_index position
     *   ngx_http_get_module_ctx(r, module) — Returns the module's context
     *   ngx_http_set_ctx(r, c, module) — Sets c as the module's context
     */
    //指向每个HTTP模块的自定义上下文结构体的数组. 数组的元素个数为ngx_http_max_module
    void                            **ctx;
    /**
     * main_conf, srv_conf, loc_conf 
     *  — Arrays of current request configurations. Configurations are stored at the module's ctx_index positions.
     */
    void                            **main_conf;    // 指向请求对应的存放 main级别配置结构体的指针数组
    void                            **srv_conf;     // 指向请求对应的存放 srv级别配置结构体的指针数组
    /**
     * https://nginx.org/en/docs/dev/development_guide.html#http_request_redirection
     * 
     * An HTTP request is always connected to a location via the loc_conf
     * 
     * This means that at any point the location configuration of any module can be retrieved from the request by calling ngx_http_get_module_loc_conf(r, module)
     * 
     * Request location can change several times during the request's lifetime.Initially, a default server location of the default server is assigned to a request
     *  If the request switches to a different server (chosen by the HTTP “Host” header or SSL SNI extension),  the request switches to the default location of that server as well
     * The next change of the location takes place at the NGX_HTTP_FIND_CONFIG_PHASE request phase.
     * 
     * 
     * */ 
    void                            **loc_conf;     // 指向请求对应的存放 loc级别配置结构体的指针数组

    /**
     * read_event_handler, write_event_handler - Read and write event handlers for the request. 
     * Normally, both the read and write event handlers for an HTTP connection are set to ngx_http_request_handler(). 
     * 
     * This function calls the read_event_handler and write_event_handler handlers for the currently active request.
     */
    /**
     * 通常，HTTP连接的读取和写入事件处理程序都设置为 ngx_http_request_handler()。
     * 
     * 此函数为当前活动请求调用read_event_handler and write_event_handler处理程序
     */

    /**
     * 在接收完 HTTP头部，第一次在业务上处理HTTP请求时， 
     * HTTP框架提供的处理方法是 ngx_http_process_request。
     * 但如果该方法无法一次处理完该请求的全部业务，在归还控制权到 epoll事件模块后，
     * 该请求再次被回调时，将通过 ngx_http_request_handler 方法来处理，
     * 而这个方法中对于可读事件的处理就是调用 read_event_handler处理请求。
     * 也就是说， HTTP模块希望在底层处理请求的读事件时，重新实现read_event_handler方法
     */
    ngx_http_event_handler_pt         read_event_handler;
    /**
     * 与 read_event_handler 回调方法类似，如果 ngx_http_request_handler 方法判断当前事件是可写事件，
     * 则调用 write_event_handler处理请求
     */
    ngx_http_event_handler_pt         write_event_handler;

    /**
     * Request cache object for caching the upstream response.
     */
#if (NGX_HTTP_CACHE)
    ngx_http_cache_t                 *cache;
#endif

    //Request upstream object for proxying.
    //使用upstream机制时，需要创建此结构体，并正确设置其conf配置结构体(ngx_http_upstream_conf_t类型)
    ngx_http_upstream_t              *upstream;
    //用于记录与一个上游服务器的交互状态
    //在启动upstream机制时，创建此字段。ngx_http_upstream_init_request方法, 元素类型 ngx_http_upstream_state_t
    ngx_array_t                      *upstream_states;
                                         /* of ngx_http_upstream_state_t */

    /**
     * Request pool. The request object itself is allocated in this pool, which is destroyed when the request is deleted. 
     * 
     * For allocations that need to be available throughout the client connection's lifetime, use ngx_connection_t's pool instead.
     */
    //表示这个请求的内存池，在ngx_http_free_request方法中销毁。
    //它与 ngx_connection_t中的内存池意义不同，当请求释放时， 
    //TCP连接可能并没有关闭，这时请求的内存池会销毁，但 ngx_connection_t的内存池并不会销毁
    ngx_pool_t                       *pool;
    //Buffer into which the client HTTP request header is read.
    //用于接收 HTTP请求内容的缓冲区，主要用于接收HTTP请求的请求行和请求头部。
    // 如果这个缓冲区满了,  会调用ngx_http_alloc_large_header_buffer 分配更大的缓冲区
    //  ngx_http_parse_request_line(r, r->header_in);
    ngx_buf_t                        *header_in;

    /**
     * headers_in, headers_out — Input and output HTTP headers objects. 
     * Both objects contain the headers field of type ngx_list_t for keeping the raw list of headers. 
     * In addition to that, specific headers are available for getting and setting as separate fields, for example content_length_n, status etc
     */
    //ngx_http_process_request_headers方法在接收、解析完 HTTP请求的头部后，
    //会把解析完的每一个 HTTP头部加入到 headers_in的 headers链表中，同时会构造 headers_in中的其他成员
    ngx_http_headers_in_t             headers_in;
    //HTTP模块会把想要发送的HTTP响应信息放到 headers_out中，期望HTTP框架将 headers_out中的成员序列化为HTTP响应包发送给用户
    //只要将将响应头放入此字段，调用ngx_http_send_header方法就可以将响应头发送给客户端
    ngx_http_headers_out_t            headers_out;

    //Client request body object.
    // 接收HTTP请求中包体的数据结构
    ngx_http_request_body_t          *request_body;

    //延迟关闭连接的时间
    time_t                            lingering_time;

    /**
     * start_sec, start_msec — Time point when the request was created, used for tracking request duration
     */
    //如果这个请求是子请求，则该时间是子请求的生成时间；
    //如果这个请求是用户发来的请求，则是在建立起TCP连接后，第一次接收到可读事件时的时间
    time_t                            start_sec;    //请求结构体创建时间 sec
    ngx_msec_t                        start_msec;   //请求结构体创建时间 msec

    /**
     * method, method_name — Numeric and text representation of the client HTTP request method. 
     * Numeric values for methods are defined in src/http/ngx_http_request.h with the macros NGX_HTTP_GET, NGX_HTTP_HEAD, NGX_HTTP_POST, etc
     */
    /*
     * 以下的 9 个成员是函数 ngx_http_process_request_line 在接收、解析http请求行时解析出的信息 */
    ngx_uint_t                        method;               /* 方法名称 */
    //Client HTTP protocol version in numeric form (NGX_HTTP_VERSION_10, NGX_HTTP_VERSION_11, etc.)
    ngx_uint_t                        http_version;         /* 协议版本 */

    //request_line, unparsed_uri — Request line and URI in the original client request
    ngx_str_t                         request_line;         //表示请求行
    /**
     * uri, args, exten — URI, arguments and file extension for the current request. 
     * The URI value here might differ from the original URI sent by the client due to normalization. 
     * 
     * Throughout request processing, these values can change as internal redirects are performed
     */
    ngx_str_t                         uri;                  /* 客户请求中的uri, 不带args */
    ngx_str_t                         args;                 /* uri 中的参数 */
    ngx_str_t                         exten;                /* 客户请求的文件扩展名 */
    //变量$request_uri: full original request URI (with arguments)
    ngx_str_t                         unparsed_uri;         /* 没经过URI 解码的原始请求uri字符串，带请求参数 */

    ngx_str_t                         method_name;          /* 方法名称字符串 */
    //Client HTTP protocol version in its original text form (“HTTP/1.0”, “HTTP/1.1” etc)
    ngx_str_t                         http_protocol;        /* 其data成员指向请求中http的起始地址 */
    ngx_str_t                         schema;

    /**
     * 表示需要发送给客户端的 HTTP响应。 
     * out中保存着由 headers_out中序列化后的表示 HTTP头部的 TCP流。
     * 在调用 ngx_http_output_filter方法后， out中还会保存待发送的 HTTP包体，它是实现异步发送 HTTP响应的关键
    */
    ngx_chain_t                      *out;
    /**
     * Pointer to a main request object. 
     * This object is created to process a client HTTP request, as opposed to subrequests, which are created to perform a specific subtask within the main request
     */
    //*当前请求既可能是用户发来的请求，也可能是派生出的子请求，
    //而 main则标识一系列相关的派生子请求的原始请求， contains a link to the main request in a group of requests.
    //一般可通过 main和当前请求的地址是否相等来判断当前请求是否为用户发来的原始请求
    ngx_http_request_t               *main;
    // 当前请求的父请求。注意，父请求未必是原始请求
    //Pointer to the parent request of a subrequest.
    //for a subrequest contains a link to its parent request and is NULL for the main request
    ngx_http_request_t               *parent;
    /**
     * List of output buffers and subrequests, in the order in which they are sent and created. 
     * The list is used by the postpone filter to provide consistent request output when parts of it are created by subrequests.
     */
    //是一个链表，每个节点是一个子请求产生的响应，用于保证子请求有序向客户端转发，参考ngx_http_postpone_filter_module模块
    //输出缓冲区和子请求的列表，按照它们发送和创建的顺序。当子请求创建时，该列表由postpone过滤器使用，以提供一致的请求输出
    ngx_http_postponed_request_t     *postponed;

    /**
     *  Pointer to a handler with the context to be called when a subrequest gets finalized. Unused for main requests.
     */
    //https://tengine.taobao.org/book/chapter_12.html#subrequest-99
    //每个子请求结束时的回调函数，组成一个链表
    //如果是子请求，结束时会调用此字段里的handler。 参考：ngx_http_finalize_request
    ngx_http_post_subrequest_t       *post_subrequest;
    /**
     * List of requests to be started or resumed, which is done by calling the request's write_event_handler. 
     * Normally, this handler holds the request main function, which at first runs request phases and then produces the output.
     * 
     * A request is usually posted by the ngx_http_post_request(r, NULL) call.
     * It is always posted to the main request posted_requests list.
     * 
     * The function ngx_http_run_posted_requests(c) runs all requests that are posted in the main request of the passed connection's active request
     * 
     * All event handlers call ngx_http_run_posted_requests, which can lead to new posted requests. Normally, it is called after invoking a request's read or write handler
     */
    //所有的子请求(request)都是通过 posted_requests 这个单链表来连接起来的，
    //执行 post子请求时调用的 ngx_http_run_posted_requests 方法就是通过遍历该单链表来执行子请求的
    /**
     * struct ngx_http_posted_request_s {
            ngx_http_request_t               *request;  //当前子请求
            ngx_http_posted_request_t        *next;     //下一个节点
        };
        这个链表用以保存需要延迟处理的请求（不局限于子请求）。因此子请求会在父请求本地调度完毕后得到运行的机会，这通常是子请求获得首次运行机会的手段
     */
    ngx_http_posted_request_t        *posted_requests;      //由子请求组成的单链表

    //Index of current request phase.
    //全局的 ngx_http_phase_engine_t结构体中定义了一个 ngx_http_phase_handler_t回调方法组成的数组，
    //而 phase_handler成员则与该数组配合使用，表示请求下次应当执行以 phase_handler作为序号指定的数组中的回调方法。 
    //HTTP框架正是以这种方式把各个HTTP模块集成起来处理请求的, 叫phase_handler_index更合适
    ngx_int_t                         phase_handler;
    //表示 NGX_HTTP_CONTENT_PHASE阶段提供给 HTTP模块处理请求的一种方式， 
    //content_handler指向 HTTP模块实现的请求处理方法
    ngx_http_handler_pt               content_handler;
    //在 NGX_HTTP_ACCESS_PHASE阶段需要判断请求是否具有访问权限时，
    //通过 access_code来传递 HTTP模块的 handler回调方法的返回值，
    //如果 access_code为 0，则表示请求具备访问权限，反之则说明请求不具备访问权限
    ngx_uint_t                        access_code;

    /**
     * 变量值如果可以被缓存，那么它一定只能缓存在每一个HTTP请求内, 此字段即为当前请求缓存的变量值
     * 
     * variables数组存储所有序列化了的变量值，数组下标即为config阶段获取到的变量索引号
     * 
     * 当HTTP请求刚到达Nginx时，就会创建缓存变量值的variables数组 （ngx_http_create_request）
     * 
     */
    ngx_http_variable_value_t        *variables;

#if (NGX_PCRE)
    /**
     * ncaptures, captures, captures_data — Regex captures produced by the last regex match of the request
     * 
     * A regex match can occur at a number of places during request processing: map lookup, server lookup by SNI or HTTP Host, rewrite, proxy_redirect, etc
     * Captures produced by a lookup are stored in the above mentioned fields.
     * 
     * ncaptures holds the number of captures
     * captures holds captures boundaries
     * captures_data holds the string against which the regex was matched and which is used to extract captures
     * 
     * After each new regex match, request captures are reset to hold new values
     */
    /**
     * Regex捕获了请求的最后一个正则匹配项产生的。在请求处理过程中，可以在许多地方进行正则匹配：MAP查找，SNI或HTTP主机的服务器查找，重写，Proxy_redirect等。
     * 
     * 捕获由查找产生的捕获存储在上述字段中。
     * 字段ncaptures保留捕获的数量，
     * captures保留捕获边界和captures_data保留匹配正则并用于提取捕获的字符串。
     * 
     * 每次新的正则匹配项之后，请求捕获重置以保持新值
     */
    ngx_uint_t                        ncaptures;        //记录正则捕获组的数量 
    /**
     * 如123helloxxx (\d+)hello(xxx)
     * captures为[0,3]
     * captures_data为123xxx
     */
    int                              *captures;         //记录的是每个捕获组的起始位置，如获取$1的长度: captures[2] - captures[1]
    u_char                           *captures_data;    //记录捕获到的数据。只有捕获到的数据会被保存
#endif

    /* 限制当前请求的发送的速率 */
    size_t                            limit_rate;       //限流速度， 参考 ngx_http_upstream_process_limit_rate
    size_t                            limit_rate_after;

    /* http响应的长度，不包括http响应头部 */
    /* used to learn the Apache compatible response length without a header */
    size_t                            header_size;

    //http请求的长度，包括http请求头部、http请求包体
    off_t                             request_length;

    /* 表示错误状态标志 */
    ngx_uint_t                        err_status;

    /* http 连接 */
    ngx_http_connection_t            *http_connection;
    ngx_http_v2_stream_t             *stream;
    ngx_http_v3_parse_t              *v3_parse;

    /* http记录错误日志处理函数,在ngx_http_alloc_request方法中设置为 ngx_http_log_error_handler */
    ngx_http_log_handler_pt           log_handler;

    //在这个请求中如果打开了某些资源，并需要在请求结束时释放，那么都需要在把定义的释放资源方法添加到 cleanup成员中
    //清理函数链表，包括一个handler和一个data指针. 当ngx_http_request_t 结构体被释放时调用
    ngx_http_cleanup_t               *cleanup;

    in_port_t                         port;
    /**
     * Request reference counter. The field only makes sense for the main request
     *  Increasing the counter is done by simple r->main->count++. To decrease the counter, call ngx_http_finalize_request(r, rc)
     * Creating of a subrequest and running the request body read process both increment the counter.
     */
    /**
     * 表示当前请求的引用次数。
     * 例如，在使用 subrequest功能时，依附在这个请求上的子请求数目会返回到 count上，每增加一个子请求， 
     * count数就要加 1。其中任何一个子请求派生出新的子请求时，对应的原始请求（ main指针指向的请求）
     * 的 count值都要加 1。又如，当我们接收 HTTP包体时，由于这也是一个异步调用，所以 count上也需要加 1，
     * 这样在结束请求时就不会在count引用计数未清零时销毁请求
     */
    unsigned                          count:16;
    /**
     * Current subrequest nesting level. Each subrequest inherits its parent's nesting level, decreased by one
     * An error is generated if the value reaches zero. The value for the main request is defined by the NGX_HTTP_MAX_SUBREQUESTS constant
     */
    unsigned                          subrequests:8;    //记录主请求的子请求层级，最大值为50
    // 阻塞标志位，目前仅由 aio使用
    /**
     * Counter of blocks held on the request. While this value is non-zero, the request cannot be terminated. 
     * Currently, this value is increased by pending AIO operations (POSIX AIO and thread operations) and active cache lock
     */
    unsigned                          blocked:8;

    //标志位，为 1时表示当前请求正在使用异步文件 IO
    unsigned                          aio:1;

    //记录http请求解析的阶段  NGX_HTTP_PROCESS_REQUEST_STATE
    unsigned                          http_state:4;

    /* URI with "/." and on Win32 with "//" */
    unsigned                          complex_uri:1;

    /* URI with "%" */
    unsigned                          quoted_uri:1;

    /* URI with "+" */
    unsigned                          plus_in_uri:1;

    /* URI with empty path */
    unsigned                          empty_path_in_uri:1;

    //标识请求头是否valid。如解析请求头时，遇到了请求头header name中包含下划线.参考 ngx_http_parse_header_line
    unsigned                          invalid_header:1;

    unsigned                          add_uri_to_alias:1;
    unsigned                          valid_location:1;
    unsigned                          valid_unparsed_uri:1;
    //标志位，为 1时表示 URL发生过 rewrite重写.如调用了ngx.redirect
    unsigned                          uri_changed:1;
    /**
     *  Number of URI changes remaining for the request.
     * The total number of times a request can change its URI is limited by the NGX_HTTP_MAX_URI_CHANGES constant.
     * With each change the value is decremented until it reaches zero, at which time an error is generated.
     * Rewrites and internal redirects to normal or named locations are considered URI changes.
     */
    //表示使用rewrite重写 URL的次数。因为目前最多可以更改10次，所以uri_changes初始化为11，
    //而每重写URL一次就把uri_changes减1，一旦uri_changes等于 0，则向用户返回失败
    unsigned                          uri_changes:4;    //记录uri变化的次数，最大值为11

    /**
     * The following fields of the request determine how the request body is read:
    */

    //https://nginx.org/en/docs/http/ngx_http_core_module.html#client_body_in_single_buffer
    //save the entire client request body in a single buffer. 用于访问 $request_body 场景
    // Read the body to a single memory buffer
    unsigned                          request_body_in_single_buf:1;
    //将请求体写入文件，没有相关配置项。如果此标志为1，则可以在r->request_body->temp_file->file中找到存储请求体的临时文件
    //Always read the body to a file, even if fits in the memory buffer.
    unsigned                          request_body_in_file_only:1;
    //Do not unlink the file immediately after creation. A file with this flag can be moved to another directory
    unsigned                          request_body_in_persistent_file:1;
    //Unlink the file when the request is finalized. 
    //This can be useful when a file was supposed to be moved to another directory but was not moved for some reason
    unsigned                          request_body_in_clean_file:1;
    //Enable group access to the file by replacing the default 0600 access mask with 0660
    unsigned                          request_body_file_group_access:1;
    //Severity level at which to log file errors.
    unsigned                          request_body_file_log_level:3;
    /**
     * https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_request_buffering
     * 控制是否对客户端请求体进行缓冲,不将请求体数据缓冲到内存或临时文件中，而是直接转发给后端服务器
     * proxy_request_buffering off;：禁用代理模块的请求体缓冲； 默认为on 即缓存请求体
     */

    /**
     * The request_body_no_buffering flag enables the unbuffered mode of reading a request body. 
     * In this mode, after calling ngx_http_read_client_request_body(), the bufs chain might keep only a part of the body. 
     * To read the next part, call the ngx_http_read_unbuffered_request_body(r) function. 
     * The return value NGX_AGAIN and the request flag reading_body indicate that more data is available. 
     * If bufs is NULL after calling this function, there is nothing to read at the moment. 
     * The request callback read_event_handler will be called when the next part of request body is available.
     */
    unsigned                          request_body_no_buffering:1;  //Read the request body without buffering


    /**
     * upstream机制中，subrequest_in_memory标志位为1时, 即upstream不转发响应包体到下游，由HTTP模块实现的input_filter方法处理包体
     *  
     * 当subrequest_in_memory为0时，upstream会转发响应包体。
     * 当ngx_http_upstream_conf_t配置结构体中的buffering标志位为1时，将开启更多的内存和磁盘文件用于缓存上游的响应包体，
     * 这意味上游网速更快；当buffering为0时，将使用固定大小的缓冲区（就是上面介绍的buffer缓冲区）来转发响应包体
     */
    //https://nginx.org/en/docs/http/ngx_http_core_module.html#subrequest_output_buffer_size
    //为1表示要在内存中处理子请求的响应。数据不能超过subrequest_output_buffer_size设置的大小
    unsigned                          subrequest_in_memory:1; /* 决定是否转发响应，若该标志位为1，表示不转发响应,在内存中处理，否则转发响应 */
    //如果子请求提前完成，会将子请求的done标识设置为1
    unsigned                          waited:1;

#if (NGX_HTTP_CACHE)
    unsigned                          cached:1;
#endif

#if (NGX_HTTP_GZIP)
    unsigned                          gzip_tested:1;     //标识请求上有没有执行过 ngx_http_gzip_ok
    unsigned                          gzip_ok:1;        //标识客户端是否支持gzip,是否可以对响应体进行gzip压缩。在ngx_http_gzip_ok()方法中设置
    unsigned                          gzip_vary:1;      //标识是否添加响应头 Vary: Accept-Encoding
#endif

#if (NGX_PCRE)
    unsigned                          realloc_captures:1;
#endif

    unsigned                          proxy:1;
    unsigned                          bypass_cache:1;
    unsigned                          no_cache:1;

    /*
     * instead of using the request context data in
     * ngx_http_limit_conn_module and ngx_http_limit_req_module
     * we use the bit fields in the request structure
     */
    // 给流量控制模块用的标志位
    // 不放在ctx结构体里，节约内存
    unsigned                          limit_conn_status:2;      //连接数限流
    unsigned                          limit_req_status:3;       //请求数限速状态，是个枚举值

    //标识是否设置了限流
    unsigned                          limit_rate_set:1;
    unsigned                          limit_rate_after_set:1;

#if 0
    unsigned                          cacheable:1;
#endif

    unsigned                          pipeline:1;
    // 两种含义，如果请求头有chunked那么置1，表示请求体长度不确定
    // 如果响应头无content_length_n，那么表示响应体长度不确定，是chunked
    //如果为1， 在ngx_http_header_filter_module向客户端发送响应头时，会增加响应头 "Transfer-Encoding: chunked" 
    unsigned                          chunked:1;
    /**
     * Flag indicating that the output does not require a body. For example, this flag is used by HTTP HEAD requests.
     * 
     * 若当前方法为 HEAD 则仅发送 header ，表示输出不需要http body
     * src/http/ngx_http_header_filter_module.c:187
     */
    unsigned                          header_only:1;
    //标志位，为 1时表示当前响应有tailer_header需要发送
    unsigned                          expect_trailers:1;
    /**
     * Flag indicating whether client connection keepalive is supported. 
     * The value is inferred from the HTTP version and the value of the “Connection” header.
     **/ 
    //标志位，为 1时表示当前请求是 keepalive请求。从HTTP版本和“Connection”标头的值推断的出来
    unsigned                          keepalive:1;
    //延迟关闭标志位，为 1时表示需要延迟关闭。例如，在接收完 HTTP头部时如果发现包体存在，
    //该标志位会设为1，而放弃接收包体时则会设为 0
    unsigned                          lingering_close:1;
    //标志位，为 1时表示正在丢弃 HTTP请求中的包体
    unsigned                          discard_body:1;
    unsigned                          reading_body:1;
    /**
     * Flag indicating that the current request is internal.
     * To enter the internal state, a request must pass through an internal redirect or be a subrequest. 
     * Internal requests are allowed to enter internal locations.
     *  */  
    //标志位，为 1时表示请求的当前状态是在做内部跳转。(internal request) 或者子请求
    unsigned                          internal:1;
    unsigned                          error_page:1;
    unsigned                          filter_finalize:1;
    unsigned                          post_action:1;
    unsigned                          request_complete:1;
    unsigned                          request_output:1;
    //Flag indicating that the output header has already been sent by the request.
    //标志位，为 1时表示发送给客户端的 HTTP响应头部已经发送。在调用ngx_http_send_header方法后，
    //若已经成功地启动响应头部发送流程，该标志位就会置为 1，用来防止反复地发送头部
    unsigned                          header_sent:1;
    unsigned                          response_sent:1;
    unsigned                          expect_tested:1;
    unsigned                          root_tested:1;
    unsigned                          done:1;
    //标识请求是否已经执行了log_phase了
    unsigned                          logged:1;
    unsigned                          terminated:1;

    /**
     * Bitmask showing which modules have buffered the output produced by the request
     * A number of filters can buffer output; for example, sub_filter can buffer data because of a partial string match, 
     *  copy filter can buffer data because of the lack of free output buffers etc.
     * As long as this value is non-zero, the request is not finalized pending the flush.
     */
    //表示缓冲中是否有待发送内容的标志位
    /**
     * 通过位图方式显示了哪些模块已缓冲了请求产生的输出。许多过滤器可以缓冲输出；
     * 例如，sub_filter可以由于部分字符串匹配而可以缓冲数据，因此copy filter 可以缓冲数据，因为缺乏free输出缓冲区等。
     * 
     * 只要此值不为零，请求未完成等待将缓冲区中内容发送。
     * 
     * if (r->buffered || r->postponed) {
            if (ngx_http_set_write_handler(r) != NGX_OK) {
                ngx_http_terminate_request(r, 0);
            }
            return;
        }
     */
    unsigned                          buffered:4;

    /**
     * main_filter_need_in_memory, filter_need_in_memory — Flags requesting that the output produced in memory buffers rather than files.
     * 
     * This is a signal to the copy filter to read data from file buffers even if sendfile is enabled.
     * The difference between the two flags is the location of the filter modules that set them. 
     *  Filters called before the postpone filter in the filter chain set filter_need_in_memory, requesting that only the current request output come in memory buffers
     *  Filters called later in the filter chain set main_filter_need_in_memory, requesting that both the main request and all subrequests read files in memory while sending output.
     * 
     */
    unsigned                          main_filter_need_in_memory:1;
    //如ngx_buf_t实际数据在文件中，则设置此标识会导致buf被重新复制一份到内存
    unsigned                          filter_need_in_memory:1;
    /**
     * Flag requesting that the request output be produced in temporary buffers, but not in readonly memory buffers or file buffers. 
     * This is used by filters which may change output directly in the buffers where it's sent.
     */
    //如ngx_buf_t实际数据不可写，则设置此标识会导致buf被重新复制一份并标记可写
    unsigned                          filter_need_temporary:1;
    /**
     * Upstream: keep request body file from removal if requested.
        The new request flag "preserve_body" indicates that the request body file should
        not be removed by the upstream module because it may be used later by a
        subrequest. The flag is set by the SSI (ticket #585), addition and slice
        modules. Additionally, it is also set by the upstream module when a background
        cache update subrequest is started to prevent the request body file removal
        after an internal redirect. Only the main request is now allowed to remove the
        file.

     */
    //避免请求体临时文件被upstream模块清理
    unsigned                          preserve_body:1;
    // Flag indicating that a partial response can be sent to the client, as requested by the HTTP Range header
    unsigned                          allow_ranges:1;
    // Flag indicating that a partial response can be sent while a subrequest is being processed.
    //标志表明在处理子要求时可以发送部分响应。参考ngx_http_range_header_filter()
    unsigned                          subrequest_ranges:1;
    /**
     * Flag indicating that only a single continuous range of output data can be sent to the client. 
     * This flag is usually set when sending a stream of data, for example from a proxied server, and the entire response is not available in one buffer.
     */
    // 标志表明只能将单个连续的输出数据范围发送到客户端。通常在发送数据流时设置此标志，例如从代理服务器发送，整个响应在不在一个缓冲区中.参考 range_filter模块 
    unsigned                          single_range:1;
    //by_pass ngx_http_not_modified_header_filter
    // https://github.com/hachi029/lua-resty-core/blob/master/lib/ngx/resp.md#bypass_if_checks
    unsigned                          disable_not_modified:1;
    unsigned                          stat_reading:1;
    unsigned                          stat_writing:1;
    unsigned                          stat_processing:1;

    //创建的「后台子请求」不参与响应生产过程，所以并不 需要加入「子请求关系树」。
    unsigned                          background:1;
    unsigned                          health_check:1;

    /* used to parse HTTP headers */
    // 状态机解析 HTTP时使用 state来表示当前的解析状态
    ngx_uint_t                        state;

    ngx_uint_t                        header_hash;
    ngx_uint_t                        lowcase_index;
    u_char                            lowcase_header[NGX_HTTP_LC_HEADER_LEN];

    u_char                           *header_name_start;    //header开始位置
    u_char                           *header_name_end;      //header name 结束位置
    u_char                           *header_start;         //header value 开始位置
    u_char                           *header_end;           //header结束位置

    /*
     * a memory that can be reused after parsing a request line
     * via ngx_http_ephemeral_t
     */

    u_char                           *uri_start;
    u_char                           *uri_end;
    u_char                           *uri_ext;
    u_char                           *args_start;
    u_char                           *request_start;    //请求行开始位置
    u_char                           *request_end;      //请求行结束位置
    u_char                           *method_end;
    u_char                           *schema_start;
    u_char                           *schema_end;
    u_char                           *host_start;
    u_char                           *host_end;

    //http_major, http_minor  — Client HTTP protocol version in numeric form split into major and minor parts.
    unsigned                          http_minor:16;
    unsigned                          http_major:16;
};


typedef struct {
    ngx_http_posted_request_t         terminal_posted_request;
} ngx_http_ephemeral_t;


#define ngx_http_ephemeral(r)  (void *) (&r->uri_start)

#define ngx_http_proxy_auth(r)  ((r)->method == NGX_HTTP_CONNECT)


extern ngx_http_header_t       ngx_http_headers_in[];
extern ngx_http_header_out_t   ngx_http_headers_out[];


#define ngx_http_set_log_request(log, r)                                      \
    ((ngx_http_log_ctx_t *) log->data)->current_request = r


#endif /* _NGX_HTTP_REQUEST_H_INCLUDED_ */
