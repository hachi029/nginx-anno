
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
#define NGX_HTTP_SUBREQUEST_IN_MEMORY      2
#define NGX_HTTP_SUBREQUEST_WAITED         4
#define NGX_HTTP_SUBREQUEST_CLONE          8
#define NGX_HTTP_SUBREQUEST_BACKGROUND     16

#define NGX_HTTP_LOG_UNSAFE                1


#define NGX_HTTP_CONTINUE                  100
#define NGX_HTTP_SWITCHING_PROTOCOLS       101
#define NGX_HTTP_PROCESSING                102

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


//ngx_http_upstream_headers_in的元素
typedef struct {
    ngx_str_t                         name;     //头部名称
    ngx_uint_t                        offset;   //在headers_in偏移
    ngx_http_header_handler_pt        handler;  //解析方法
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
    ngx_table_elt_t                  *content_encoding;
    ngx_table_elt_t                  *location;     //响应头Location
    ngx_table_elt_t                  *refresh;
    ngx_table_elt_t                  *last_modified;
    ngx_table_elt_t                  *content_range;
    ngx_table_elt_t                  *accept_ranges;
    ngx_table_elt_t                  *www_authenticate;
    ngx_table_elt_t                  *expires;
    ngx_table_elt_t                  *etag;

    ngx_table_elt_t                  *cache_control;
    ngx_table_elt_t                  *link;

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
 * 读取到的客户端请求体body保存到此结构体中, r->request_body成员
 */
typedef struct {
    // 存放 HTTP包体的临时文件
    ngx_temp_file_t                  *temp_file;    //不为NULL表示保存到了临时文件里
    ///接收 HTTP包体的缓冲区链表。
    //当包体需要全部存放在内存中时，如果一块 ngx_buf_t缓冲区无法存放完，这时就需要使用 ngx_chain_t链表来存放
    ngx_chain_t                      *bufs;
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
    //HTTP包体接收完毕后执行的回调方法，也就是 ngx_http_read_client_request_body方法传递的第 2个参数
    ngx_http_client_body_handler_pt   post_handler;
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
    //alloc_large_header_buffer时，已经使用的buffer的个数
    ngx_int_t                         nbusy;        //数据块链长度

    ngx_chain_t                      *free;         //可复用的数据块链

    ngx_msec_t                        keepalive_timeout;

    unsigned                          ssl:1;
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
    ngx_http_postponed_request_t     *next; //下一个链表节点
};


typedef struct ngx_http_posted_request_s  ngx_http_posted_request_t;

/**
 * subrequest 子请求是基于 post 机制的
 * 
 * 子请求单向链表， r->main->posted_requests
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


struct ngx_http_request_s {
    uint32_t                          signature;         /* "HTTP" */

    ngx_connection_t                 *connection;   // 这个请求对应的客户端连接

    //指向每个HTTP模块的自定义上下文结构体的数组. 数组的元素个数为ngx_http_max_module
    void                            **ctx;
    void                            **main_conf;    // 指向请求对应的存放 main级别配置结构体的指针数组
    void                            **srv_conf;     // 指向请求对应的存放 srv级别配置结构体的指针数组
    void                            **loc_conf;     // 指向请求对应的存放 loc级别配置结构体的指针数组

    /**
     * 在接收完 HTTP头部，第一次在业务上处理HTTP请求时， 
     * HTTP框架提供的处理方法是 ngx_http_process_request。
     * 但如果该方法无法一次处理完该请求的全部业务，在归还控制权到 epoll事件模块后，
     * 该请求再次被回调时，将通过 ngx_http_request_handler方法来处理，
     * 而这个方法中对于可读事件的处理就是调用 read_event_handler处理请求。
     * 也就是说， HTTP模块希望在底层处理请求的读事件时，重新实现read_event_handler方法
     */
    ngx_http_event_handler_pt         read_event_handler;
    /**
     * 与 read_event_handler回调方法类似，如果 ngx_http_request_handler方法判断当前事件是可写事件，
     * 则调用 write_event_handler处理请求
     */
    ngx_http_event_handler_pt         write_event_handler;

#if (NGX_HTTP_CACHE)
    ngx_http_cache_t                 *cache;
#endif

    //使用upstream机制时，需要创建此结构体，并正确设置其conf配置结构体(ngx_http_upstream_conf_t类型)
    ngx_http_upstream_t              *upstream;
    //在启动upstream机制时，创建此字段。ngx_http_upstream_init_request方法
    ngx_array_t                      *upstream_states;
                                         /* of ngx_http_upstream_state_t */

    //表示这个请求的内存池，在ngx_http_free_request方法中销毁。
    //它与 ngx_connection_t中的内存池意义不同，当请求释放时， 
    //TCP连接可能并没有关闭，这时请求的内存池会销毁，但 ngx_connection_t的内存池并不会销毁
    ngx_pool_t                       *pool;
    //用于接收 HTTP请求内容的缓冲区，主要用于接收HTTP请求的请求行和请求头部。如果这个缓冲区满了
    // 会调用ngx_http_alloc_large_header_buffer 分配更大的缓冲区
    //  ngx_http_parse_request_line(r, r->header_in);
    ngx_buf_t                        *header_in;

    //ngx_http_process_request_headers方法在接收、解析完 HTTP请求的头部后，
    //会把解析完的每一个 HTTP头部加入到 headers_in的 headers链表中，同时会构造 headers_in中的其他成员
    ngx_http_headers_in_t             headers_in;
    //HTTP模块会把想要发送的HTTP响应信息放到 headers_out中，期望HTTP框架将 headers_out中的成员序列化为HTTP响应包发送给用户
    //只要将将响应头放入此字段，调用ngx_http_send_header方法就可以将响应头发送给客户端
    ngx_http_headers_out_t            headers_out;

    // 接收HTTP请求中包体的数据结构
    ngx_http_request_body_t          *request_body;

    //延迟关闭连接的时间
    time_t                            lingering_time;

    //如果这个请求是子请求，则该时间是子请求的生成时间；
    //如果这个请求是用户发来的请求，则是在建立起TCP连接后，第一次接收到可读事件时的时间
    time_t                            start_sec;    //请求结构体创建时间 sec
    ngx_msec_t                        start_msec;   //请求结构体创建时间 msec

    /*
     * 以下的 9 个成员是函数ngx_http_process_request_line在接收、解析http请求行时解析出的信息 */
    ngx_uint_t                        method;               /* 方法名称 */
    ngx_uint_t                        http_version;         /* 协议版本 */

    ngx_str_t                         request_line;         //表示请求行
    ngx_str_t                         uri;                  /* 客户请求中的uri, 不带args */
    ngx_str_t                         args;                 /* uri 中的参数 */
    ngx_str_t                         exten;                /* 客户请求的文件扩展名 */
    //相当于$request_uri
    ngx_str_t                         unparsed_uri;         /* 没经过URI 解码的原始请求uri字符串，带请求参数 */

    ngx_str_t                         method_name;          /* 方法名称字符串 */
    ngx_str_t                         http_protocol;        /* 其data成员指向请求中http的起始地址 */
    ngx_str_t                         schema;

    /**
     * 表示需要发送给客户端的 HTTP响应。 
     * out中保存着由 headers_out中序列化后的表示 HTTP头部的 TCP流。
     * 在调用 ngx_http_output_filter方法后， out中还会保存待发送的 HTTP包体，它是实现异步发送 HTTP响应的关键
    */
    ngx_chain_t                      *out;
    //*当前请求既可能是用户发来的请求，也可能是派生出的子请求，
    //而 main则标识一系列相关的派生子请求的原始请求，
    //一般可通过 main和当前请求的地址是否相等来判断当前请求是否为用户发来的原始请求
    ngx_http_request_t               *main;
    // 当前请求的父请求。注意，父请求未必是原始请求
    ngx_http_request_t               *parent;
    //子请求产生的响应，需要保证有序,是一个链表，参考ngx_http_postpone_filter_module模块
    //与 subrequest子请求相关的功能, 下级子请求产生的数据
    ngx_http_postponed_request_t     *postponed;

    //每个子请求结束时的回调函数，组成一个链表
    //如果是子请求，结束时会调用此字段里的handler。 参考：ngx_http_finalize_request
    ngx_http_post_subrequest_t       *post_subrequest;
    //所有的子请求(request)都是通过 posted_requests这个单链表来连接起来的，
    //执行 post子请求时调用的 ngx_http_run_posted_requests方法就是通过遍历该单链表来执行子请求的
    /**
     * struct ngx_http_posted_request_s {
            ngx_http_request_t               *request;  //当前子请求
            ngx_http_posted_request_t        *next;     //下一个
        };
     */
    ngx_http_posted_request_t        *posted_requests;      //单链表

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
    size_t                            limit_rate;
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

    /* http日志处理函数 */
    ngx_http_log_handler_pt           log_handler;

    //在这个请求中如果打开了某些资源，并需要在请求结束时释放，那么都需要在把定义的释放资源方法添加到 cleanup成员中
    //清理函数链表，包括一个handler和一个data指针, 
    ngx_http_cleanup_t               *cleanup;

    /**
     * 表示当前请求的引用次数。
     * 例如，在使用 subrequest功能时，依附在这个请求上的子请求数目会返回到 count上，每增加一个子请求， 
     * count数就要加 1。其中任何一个子请求派生出新的子请求时，对应的原始请求（ main指针指向的请求）
     * 的 count值都要加 1。又如，当我们接收 HTTP包体时，由于这也是一个异步调用，所以 count上也需要加 1，
     * 这样在结束请求时就不会在count引用计数未清零时销毁请求
     */
    unsigned                          count:16;
    unsigned                          subrequests:8;    //记录主请求的子请求层级，最大值为50
    // 阻塞标志位，目前仅由 aio使用
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

    unsigned                          invalid_header:1;

    unsigned                          add_uri_to_alias:1;
    unsigned                          valid_location:1;
    unsigned                          valid_unparsed_uri:1;
    //标志位，为 1时表示 URL发生过 rewrite重写
    unsigned                          uri_changed:1;
    //表示使用rewrite重写 URL的次数。因为目前最多可以更改10次，所以uri_changes初始化为11，
    //而每重写URL一次就把uri_changes减1，一旦uri_changes等于 0，则向用户返回失败
    unsigned                          uri_changes:4;    //记录uri变化的次数，最大值为11

    //https://nginx.org/en/docs/http/ngx_http_core_module.html#client_body_in_single_buffer
    //save the entire client request body in a single buffer. 用于访问 $request_body 场景
    unsigned                          request_body_in_single_buf:1;
    //将请求体写入文件，没有相关配置项。如果此标志为1，则可以在r->request_body->temp_file->file中找到存储请求体的临时文件
    unsigned                          request_body_in_file_only:1;
    unsigned                          request_body_in_persistent_file:1;
    unsigned                          request_body_in_clean_file:1;
    unsigned                          request_body_file_group_access:1;
    unsigned                          request_body_file_log_level:3;
    /**
     * https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_request_buffering
     * 控制是否对客户端请求体进行缓冲,不将请求体数据缓冲到内存或临时文件中，而是直接转发给后端服务器
     * proxy_request_buffering off;：禁用代理模块的请求体缓冲
     */
    unsigned                          request_body_no_buffering:1;


    /**
     * upstream机制中，subrequest_in_memory标志位为1时, 即upstream不转发响应包体到下游，由HTTP模块实现的input_filter方法处理包体
     *  
     * 当subrequest_in_memory为0时，upstream会转发响应包体。
     * 当ngx_http_upstream_conf_t配置结构体中的buffering标志位为1时，将开启更多的内存和磁盘文件用于缓存上游的响应包体，
     * 这意味上游网速更快；当buffering为0时，将使用固定大小的缓冲区（就是上面介绍的buffer缓冲区）来转发响应包体
     */
    //https://nginx.org/en/docs/http/ngx_http_core_module.html#subrequest_output_buffer_size
    //为1表示要在内存中处理子请求的响应。数据不能超过subrequest_output_buffer_size设置的大小
    unsigned                          subrequest_in_memory:1; /* 决定是否转发响应，若该标志位为1，表示不转发响应，否则转发响应 */
    unsigned                          waited:1;

#if (NGX_HTTP_CACHE)
    unsigned                          cached:1;
#endif

#if (NGX_HTTP_GZIP)
    unsigned                          gzip_tested:1;        //标识请求上有没有执行过 ngx_http_gzip_ok
    unsigned                          gzip_ok:1;        //标识客户端是否支持gzip
    unsigned                          gzip_vary:1;
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
     * 若当前方法为 HEAD 则仅发送 header 
     * src/http/ngx_http_header_filter_module.c:187
     */
    unsigned                          header_only:1;
    //标志位，为 1时表示当前响应有tailer_header需要发送
    unsigned                          expect_trailers:1;
    //标志位，为 1时表示当前请求是 keepalive请求
    unsigned                          keepalive:1;
    //延迟关闭标志位，为 1时表示需要延迟关闭。例如，在接收完 HTTP头部时如果发现包体存在，
    //该标志位会设为1，而放弃接收包体时则会设为 0
    unsigned                          lingering_close:1;
    //标志位，为 1时表示正在丢弃 HTTP请求中的包体
    unsigned                          discard_body:1;
    unsigned                          reading_body:1;
    //标志位，为 1时表示请求的当前状态是在做内部跳转。(internal request)
    unsigned                          internal:1;
    unsigned                          error_page:1;
    unsigned                          filter_finalize:1;
    unsigned                          post_action:1;
    unsigned                          request_complete:1;
    unsigned                          request_output:1;
    //标志位，为 1时表示发送给客户端的 HTTP响应头部已经发送。在调用ngx_http_send_header方法后，
    //若已经成功地启动响应头部发送流程，该标志位就会置为 1，用来防止反复地发送头部
    unsigned                          header_sent:1;
    unsigned                          response_sent:1;
    unsigned                          expect_tested:1;
    unsigned                          root_tested:1;
    unsigned                          done:1;
    unsigned                          logged:1;
    unsigned                          terminated:1;

    //表示缓冲中是否有待发送内容的标志位
    unsigned                          buffered:4;

    unsigned                          main_filter_need_in_memory:1;
    unsigned                          filter_need_in_memory:1;
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
    unsigned                          allow_ranges:1;
    unsigned                          subrequest_ranges:1;
    unsigned                          single_range:1;
    unsigned                          disable_not_modified:1;
    unsigned                          stat_reading:1;
    unsigned                          stat_writing:1;
    unsigned                          stat_processing:1;

    unsigned                          background:1;
    unsigned                          health_check:1;

    /* used to parse HTTP headers */
    // 状态机解析 HTTP时使用 state来表示当前的解析状态
    ngx_uint_t                        state;

    ngx_uint_t                        header_hash;
    ngx_uint_t                        lowcase_index;
    u_char                            lowcase_header[NGX_HTTP_LC_HEADER_LEN];

    u_char                           *header_name_start;    //header开始位置
    u_char                           *header_name_end;     
    u_char                           *header_start;
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

    unsigned                          http_minor:16;
    unsigned                          http_major:16;
};


typedef struct {
    ngx_http_posted_request_t         terminal_posted_request;
} ngx_http_ephemeral_t;


#define ngx_http_ephemeral(r)  (void *) (&r->uri_start)


extern ngx_http_header_t       ngx_http_headers_in[];
extern ngx_http_header_out_t   ngx_http_headers_out[];


#define ngx_http_set_log_request(log, r)                                      \
    ((ngx_http_log_ctx_t *) log->data)->current_request = r


#endif /* _NGX_HTTP_REQUEST_H_INCLUDED_ */
