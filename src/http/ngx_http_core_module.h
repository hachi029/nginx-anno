
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_CORE_H_INCLUDED_
#define _NGX_HTTP_CORE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_THREADS)
#include <ngx_thread_pool.h>
#elif (NGX_COMPAT)
typedef struct ngx_thread_pool_s  ngx_thread_pool_t;
#endif


#define NGX_HTTP_GZIP_PROXIED_OFF       0x0002
#define NGX_HTTP_GZIP_PROXIED_EXPIRED   0x0004
#define NGX_HTTP_GZIP_PROXIED_NO_CACHE  0x0008
#define NGX_HTTP_GZIP_PROXIED_NO_STORE  0x0010
#define NGX_HTTP_GZIP_PROXIED_PRIVATE   0x0020
#define NGX_HTTP_GZIP_PROXIED_NO_LM     0x0040
#define NGX_HTTP_GZIP_PROXIED_NO_ETAG   0x0080
#define NGX_HTTP_GZIP_PROXIED_AUTH      0x0100
#define NGX_HTTP_GZIP_PROXIED_ANY       0x0200


#define NGX_HTTP_AIO_OFF                0
#define NGX_HTTP_AIO_ON                 1
#define NGX_HTTP_AIO_THREADS            2


#define NGX_HTTP_SATISFY_ALL            0
#define NGX_HTTP_SATISFY_ANY            1


#define NGX_HTTP_LINGERING_OFF          0
#define NGX_HTTP_LINGERING_ON           1
#define NGX_HTTP_LINGERING_ALWAYS       2


#define NGX_HTTP_IMS_OFF                0
#define NGX_HTTP_IMS_EXACT              1
#define NGX_HTTP_IMS_BEFORE             2


#define NGX_HTTP_KEEPALIVE_DISABLE_NONE    0x0002
#define NGX_HTTP_KEEPALIVE_DISABLE_MSIE6   0x0004
#define NGX_HTTP_KEEPALIVE_DISABLE_SAFARI  0x0008


#define NGX_HTTP_SERVER_TOKENS_OFF      0
#define NGX_HTTP_SERVER_TOKENS_ON       1
#define NGX_HTTP_SERVER_TOKENS_BUILD    2


typedef struct ngx_http_location_tree_node_s  ngx_http_location_tree_node_t;
typedef struct ngx_http_core_loc_conf_s  ngx_http_core_loc_conf_t;


typedef struct {
    struct sockaddr           *sockaddr;
    socklen_t                  socklen;
    ngx_str_t                  addr_text;

    unsigned                   set:1;
    unsigned                   default_server:1;
    unsigned                   bind:1;
    unsigned                   wildcard:1;
    unsigned                   ssl:1;
    unsigned                   http2:1;
    unsigned                   quic:1;
#if (NGX_HAVE_INET6)
    unsigned                   ipv6only:1;
#endif
    unsigned                   deferred_accept:1;
    unsigned                   reuseport:1;
    unsigned                   so_keepalive:2;
    unsigned                   proxy_protocol:1;

    int                        backlog;
    int                        rcvbuf;
    int                        sndbuf;
    int                        type;
#if (NGX_HAVE_SETFIB)
    int                        setfib;
#endif
#if (NGX_HAVE_TCP_FASTOPEN)
    int                        fastopen;
#endif
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                        tcp_keepidle;
    int                        tcp_keepintvl;
    int                        tcp_keepcnt;
#endif

#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    char                      *accept_filter;
#endif
} ngx_http_listen_opt_t;

/**
 * NGX请求处理的11个阶段
 */
typedef enum {
    // 在接收到完整的 HTTP头部后处理的 HTTP阶段
    NGX_HTTP_POST_READ_PHASE = 0,

    //在将请求的URI与 location表达式匹配前，修改请求的 URI（所谓的重定向）是一个独立的 HTTP阶段
    NGX_HTTP_SERVER_REWRITE_PHASE,

    //根据请求的 URI寻找匹配的 location表达式
    NGX_HTTP_FIND_CONFIG_PHASE,     //只能由ngx_http_core_module模块实现
    //在 NGX_HTTP_FIND_CONFIG_PHASE阶段寻找到匹配的 location之后再修改请求的 URI
    NGX_HTTP_REWRITE_PHASE,
    //这一阶段是用于在 rewrite重写 URL后，防止错误的 nginx.conf配置导致死循环（递归地修改 URI）
    //这一阶段仅由 ngx_http_core_module模块处理。目前，控制死循环的方式很简单，首先检查 rewrite的次数，
    //如果一个请求超过10次重定向 ,就认为进入了rewrite死循环，这时在 NGX_HTTP_POST_REWRITE_PHASE阶段就会向用户返回 500，表示服务器内部错误
    NGX_HTTP_POST_REWRITE_PHASE,  //仅由 ngx_http_core_module模块处理

    //处理 NGX_HTTP_ACCESS_PHASE阶段决定请求的访问权限前， HTTP模块可以介入的处理阶段
    NGX_HTTP_PREACCESS_PHASE,

    //用于让HTTP模块判断是否允许这个请求访问 Nginx服务器
    NGX_HTTP_ACCESS_PHASE,
    //在 NGX_HTTP_ACCESS_PHASE阶段中，当 HTTP模块的 handler处理函数返回不允许访问的错误码时
    //（实际就是 NGX_HTTP_FORBIDDEN或者 NGX_HTTP_UNAUTHORIZED），这里将负责向用户发送拒绝服务的错误响应。
    //因此，这个阶段实际上用于给NGX_HTTP_ACCESS_PHASE阶段收尾
    NGX_HTTP_POST_ACCESS_PHASE,

    //这个阶段完全是为 try_files配置项而设立的，当 HTTP请求访问静态文件资源时， 
    //try_files配置项可以使这个请求顺序地访问多个静态文件资源，如果某一次访问失败，
    //则继续访问 try_files中指定的下一个静态资源。这个功能完全是在 NGX_HTTP_TRY_FILES_PHASE阶段中实现的
    NGX_HTTP_PRECONTENT_PHASE,

    // 用于处理 HTTP请求内容的阶段，这是大部分 HTTP模块介入的阶段
    NGX_HTTP_CONTENT_PHASE,

    //处理完请求后记录日志的阶段。例如，ngx_http_log_module模块就在这个阶段中加入了一个 handler处理方法，
    //使得每个 HTTP请求处理完毕后会记录 access_log访问日志
    NGX_HTTP_LOG_PHASE
} ngx_http_phases;

typedef struct ngx_http_phase_handler_s  ngx_http_phase_handler_t;

//一个 HTTP处理阶段中的 checker检查方法，仅可以由 HTTP框架实现，以此控制 HTTP请求的处理流程
typedef ngx_int_t (*ngx_http_phase_handler_pt)(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);

//ngx_http_phase_handler_t结构体仅表示处理阶段中的一个处理方法

//这4个checker方法的主要任务在于，根据phase_handler执行某个HTTP模块实现的回调方法，
//并根据方法的返回值决定：当前阶段已经完全结束了吗？下次要执行的回调方法是哪一个？
//究竟是立刻执行下一个回调方法还是先把控制权交还给epoll

/**
 * 在处理到某一个 HTTP阶段时， HTTP框架将会在 checker方法已实现的前提下首先调用 checker方法来处理请求，
 * 而不会直接调用任何阶段中的handler方法，只有在 checker方法中才会去调用 handler方法。
 * 因此，事实上所有的 checker方法都是由框架中的 ngx_http_core_module模块实现的，且普通的 HTTP模块无法重定义checker方法
 */
struct ngx_http_phase_handler_s {
    //在各个HTTP模块能 够介入的7个阶段中，实际上共享了4个checker方法：
    //ngx_http_core_generic_phase、 ngx_http_core_rewrite_phase、
    //ngx_http_core_access_phase、ngx_http_core_content_phase
    ngx_http_phase_handler_pt  checker;     //checker
    ngx_http_handler_pt        handler;     //HTTP模块实现的handler方法

    //将要执行的下一个 HTTP处理阶段的序号
    ngx_uint_t                 next;   //指向下一个阶段的phase_handler  r->phase_handler = ph->next;
};

//是所有ngx_http_phase_handler_t组成的数组
typedef struct {
    //handlers是由 ngx_http_phase_handler_t构成的数组首地址，它表示一个请求可能经历的所有 ngx_http_handler_pt处理方法
    ngx_http_phase_handler_t  *handlers;        //数组，索引为r->phase_handler
    //表示 NGX_HTTP_SERVER_REWRITE_PHASE阶段第 1个ngx_http_phase_handler_t处理方法在handlers数组中的序号，
    //用于在执行HTTP请求的任何阶段中快速跳转到 NGX_HTTP_SERVER_REWRITE_PHASE阶段处理请求
    ngx_uint_t                 server_rewrite_index;
    //表示 NGX_HTTP_REWRITE_PHASE阶段第 1个ngx_http_phase_handler_t处理方法在handlers数组中的序号，
    //用于在执行 HTTP请求的任何阶段中快速跳转到NGX_HTTP_REWRITE_PHASE阶段处理请求
    ngx_uint_t                 location_rewrite_index;
} ngx_http_phase_engine_t;


// handlers动态数组保存着每一个 HTTP模块初始化时添加到当前阶段的处理方法
typedef struct {
    ngx_array_t                handlers;
} ngx_http_phase_t;

/**
 * 表示http{}块配置，只有一个全局唯一的实例
 */
typedef struct {
    /**
     * 动态数组，每一个代表一个server{}块的配置
     * 存储指针的动态数组，每个指针指向ngx_http_core_srv_conf_t结构体的地址，其成员类型为ngx_http_core_srv_conf_t**
     */
    ngx_array_t                servers;         /* ngx_http_core_srv_conf_t */

    //phase_handler数组
    //由下面各阶段处理方法构成的 phases数组构建的阶段引擎才是流水式处理 HTTP请求的实际数据结构
    ngx_http_phase_engine_t    phase_engine;

    //ngx_http_upstream_headers_in 构成的hash表
    //其初始化流程参考  ngx_http_init_headers_in_hash 
    ngx_hash_t                 headers_in_hash;

    /**
     * 存储变量名的散列表，调用 ngx_http_get_variable 方法获取未索引的变量值时就靠这个
     * 散列表找到变量的解析方法
     */
    ngx_hash_t                 variables_hash;      //!!!!!存放hash变量， 参考ngx_http_get_variable方法

    /**
     *  存储索引过的变量的数组，通常各模块使用变量时都会在 Nginx启动阶段从该数组中获得索引号， 
     *  这样，在Nginx运行期内，如果变量值没有被缓存，就会通过索引号在variables数组中找到变量的定义，再解析出变量值
     * 
     * variables/prefix_variables: 在配置解析阶段，会调用ngx_http_variables_init_vars()
     * 将所有模块定义的变量放入这两个动态数组里
     * 
     * 每个请求结构体r也有个和variables相同大小的表示变量值的variables字段
     */
    ngx_array_t                variables;         /* ngx_http_variable_t */     //!!!!!!!存放索引变量
    //存放带有前缀的变量，如(http_、arg_)
    ngx_array_t                prefix_variables;  /* ngx_http_variable_t */
    ngx_uint_t                 ncaptures;

    ngx_uint_t                 server_names_hash_max_size;
    ngx_uint_t                 server_names_hash_bucket_size;

    ngx_uint_t                 variables_hash_max_size;
    ngx_uint_t                 variables_hash_bucket_size;

    // 用于构造 variables_hash散列表的初始结构体, 只是临时使用， 参考函数 ngx_http_variables_init_vars. 使用结束后置为NULL
    ngx_hash_keys_arrays_t    *variables_keys;

    //存放着该 http{}配置块下监听的所有 ngx_http_conf_port_t端口
    ngx_array_t               *ports; 

    //用于在 HTTP框架初始化时帮助各个 HTTP模块在任意阶段中添加HTTP处理方法，
    //它是一个有 11个成员的 ngx_http_phase_t数组，其中每一个ngx_http_phase_t结构体对应一个 HTTP阶段。
    //在 HTTP框架初始化完毕后，运行过程中的 phases数组是无用的
    ngx_http_phase_t           phases[NGX_HTTP_LOG_PHASE + 1];
} ngx_http_core_main_conf_t;

/**
 * 代表server{}配置
 */
typedef struct {
    /* array of the ngx_http_server_name_t, "server_name" directive */
    ngx_array_t                 server_names;

    /* server ctx */
    // 指向当前 server块所属的 ngx_http_conf_ctx_t结构体
    ngx_http_conf_ctx_t        *ctx;

    u_char                     *file_name;
    ngx_uint_t                  line;

    //当前 server块的虚拟主机名，如果存在的话，则会与HTTP请求中的Host头部做匹配，
    //匹配上后再由当前 ngx_http_core_srv_conf_t处理请求
    ngx_str_t                   server_name;

    size_t                      connection_pool_size;
    //https://nginx.org/en/docs/http/ngx_http_core_module.html#request_pool_size
    //创建ngx_http_request_t时，为r分配的pool初始大小
    size_t                      request_pool_size;
    size_t                      client_header_buffer_size;

    ngx_bufs_t                  large_client_header_buffers;

    ngx_msec_t                  client_header_timeout;

    ngx_flag_t                  ignore_invalid_headers;
    ngx_flag_t                  merge_slashes;
    ngx_flag_t                  underscores_in_headers;

    unsigned                    listen:1;
#if (NGX_PCRE)
    unsigned                    captures:1;
#endif

    ngx_http_core_loc_conf_t  **named_locations;
} ngx_http_core_srv_conf_t;


/* list of structures to find core_srv_conf quickly at run time */


typedef struct {
#if (NGX_PCRE)
    ngx_http_regex_t          *regex;
#endif
    ngx_http_core_srv_conf_t  *server;   /* virtual name server conf */
    ngx_str_t                  name;
} ngx_http_server_name_t;


typedef struct {
    ngx_hash_combined_t        names;

    ngx_uint_t                 nregex;
    ngx_http_server_name_t    *regex;
} ngx_http_virtual_names_t;


struct ngx_http_addr_conf_s {
    /* the default server configuration for this address:port */
    ngx_http_core_srv_conf_t  *default_server;

    ngx_http_virtual_names_t  *virtual_names;

    unsigned                   ssl:1;
    unsigned                   http2:1;
    unsigned                   quic:1;
    unsigned                   proxy_protocol:1;
};


typedef struct {
    in_addr_t                  addr;
    ngx_http_addr_conf_t       conf;
} ngx_http_in_addr_t;


#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr            addr6;
    ngx_http_addr_conf_t       conf;
} ngx_http_in6_addr_t;

#endif


typedef struct {
    /* ngx_http_in_addr_t or ngx_http_in6_addr_t */
    void                      *addrs;
    ngx_uint_t                 naddrs;
} ngx_http_port_t;

/**
 * 每监听一个TCP端口，都将使用一个独立的ngx_http_conf_port_t结构体来表示
 */
typedef struct {
    ngx_int_t                  family;     // socket地址家族
    ngx_int_t                  type;    //
    in_port_t                  port;    // 监听端
    //监听的端口下对应着的所有 ngx_http_conf_addr_t地址. 
    //同一个端口，可以监听不同地址，如127.0.0.1:8000、173.39.160.51:8000
    ngx_array_t                addrs;     /* array of ngx_http_conf_addr_t */
} ngx_http_conf_port_t;

/**
 * 代表一个监听地址 127.0.0.1:8000
 */
typedef struct {
    ngx_http_listen_opt_t      opt; // 监听套接字的各种属性

    unsigned                   protocols:3;
    unsigned                   protocols_set:1;
    unsigned                   protocols_changed:1;

    //*以下 3个散列表用于加速寻找到对应监听端口上的新连接，确定到底使用哪个 server{}虚拟主机下的配置来处理它。
    //所以，散列表的值就是 ngx_http_core_srv_conf_t 结构体的地址
    ngx_hash_t                 hash;    //完全匹配 server name的散列表
    ngx_hash_wildcard_t       *wc_head; // 通配符前置的散列表
    ngx_hash_wildcard_t       *wc_tail; // 通配符后置的散列表

#if (NGX_PCRE)
    // 下面的 regex数组中元素的个数
    ngx_uint_t                 nregex;
    //指向静态数组，其数组成员就是 ngx_http_server_name_t结构体，表示正则表达式及其匹配的 server{}虚拟主机
    ngx_http_server_name_t    *regex;
#endif

    /* the default server configuration for this address:port */
    // 该监听端口下对应的默认 server{}虚拟主机
    ngx_http_core_srv_conf_t  *default_server;
    // servers动态数组中的成员将指向 ngx_http_core_srv_conf_t结构体
    ngx_array_t                servers;  /* array of ngx_http_core_srv_conf_t */
} ngx_http_conf_addr_t;


typedef struct {
    ngx_int_t                  status;
    ngx_int_t                  overwrite;
    ngx_http_complex_value_t   value;
    ngx_str_t                  args;
} ngx_http_err_page_t;

/**
 * 代表一个location{}的配置
 * ngx_http_core_loc_conf_t拥有足够的信息来表达1个location块，
 * 它的loc_conf成员也可以引用到各HTTP模块在当前location块中的配置项
 */
struct ngx_http_core_loc_conf_s {
    // location的名字 如 "/"、"/index.html"、"/images/"等
    // location的名称，即 nginx.conf中 location后的表达式
    ngx_str_t     name;          /* location name */
    ngx_str_t     escaped_name;

#if (NGX_PCRE)
    ngx_http_regex_t  *regex;
#endif

    unsigned      noname:1;   /* "if () {}" block or limit_except */
    unsigned      lmt_excpt:1;
    unsigned      named:1;

    unsigned      exact_match:1;
    unsigned      noregex:1;

    // name以 / 结尾
    unsigned      auto_redirect:1;
#if (NGX_HTTP_GZIP)
    unsigned      gzip_disable_msie6:2;
    unsigned      gzip_disable_degradation:2;
#endif

    ngx_http_location_tree_node_t   *static_locations;
#if (NGX_PCRE)
    ngx_http_core_loc_conf_t       **regex_locations;
#endif

    //指向所属 location块内 ngx_http_conf_ctx_t结构体中的 loc_conf指针数组，
    //它保存着当前location块内所有HTTP模块create_loc_conf方法产生的结构体指针
    /* pointer to the modules' loc_conf */
    void        **loc_conf;

    uint32_t      limit_except;
    void        **limit_except_loc_conf;

    //content_handler
    ngx_http_handler_pt  handler;

    /* location name length for inclusive location with inherited alias */
    size_t        alias;        // name.length
    ngx_str_t     root;                    /* root, alias */
    ngx_str_t     post_action;

    ngx_array_t  *root_lengths;
    ngx_array_t  *root_values;

    ngx_array_t  *types;
    ngx_hash_t    types_hash;
    ngx_str_t     default_type;

    off_t         client_max_body_size;    /* client_max_body_size */
    off_t         directio;                /* directio */
    off_t         directio_alignment;      /* directio_alignment */

    //
    size_t        client_body_buffer_size; /* client_body_buffer_size */
    size_t        send_lowat;              /* send_lowat */
    //https://nginx.org/en/docs/http/ngx_http_core_module.html#postpone_output
    //直到有postpone_output大小的数据，才将数据输出
    size_t        postpone_output;         /* postpone_output */
    size_t        sendfile_max_chunk;      /* sendfile_max_chunk */
    size_t        read_ahead;              /* read_ahead */
    size_t        subrequest_output_buffer_size;
                                           /* subrequest_output_buffer_size */

    ngx_http_complex_value_t  *limit_rate; /* limit_rate */
    ngx_http_complex_value_t  *limit_rate_after; /* limit_rate_after */

    ngx_msec_t    client_body_timeout;     /* client_body_timeout */
    ngx_msec_t    send_timeout;            /* send_timeout */
    ngx_msec_t    keepalive_time;          /* keepalive_time */
    ngx_msec_t    keepalive_timeout;       /* keepalive_timeout */
    ngx_msec_t    keepalive_min_timeout;   /* keepalive_min_timeout */
    ngx_msec_t    lingering_time;          /* lingering_time */
    ngx_msec_t    lingering_timeout;       /* lingering_timeout */
    ngx_msec_t    resolver_timeout;        /* resolver_timeout */
    ngx_msec_t    auth_delay;              /* auth_delay */

    ngx_resolver_t  *resolver;             /* resolver */

    time_t        keepalive_header;        /* keepalive_timeout */

    ngx_uint_t    keepalive_requests;      /* keepalive_requests */
    ngx_uint_t    keepalive_disable;       /* keepalive_disable */
    ngx_uint_t    satisfy;                 /* satisfy */
    ngx_uint_t    lingering_close;         /* lingering_close */
    //https://nginx.org/en/docs/http/ngx_http_core_module.html#if_modified_since
    ngx_uint_t    if_modified_since;       /* if_modified_since */
    ngx_uint_t    max_ranges;              /* max_ranges */
    ngx_uint_t    client_body_in_file_only; /* client_body_in_file_only */

    ngx_flag_t    client_body_in_single_buffer;
                                           /* client_body_in_singe_buffer */
    ngx_flag_t    internal;                /* internal */
    ngx_flag_t    sendfile;                /* sendfile */
    ngx_flag_t    aio;                     /* aio */
    ngx_flag_t    aio_write;               /* aio_write */
    ngx_flag_t    tcp_nopush;              /* tcp_nopush */
    ngx_flag_t    tcp_nodelay;             /* tcp_nodelay */
    ngx_flag_t    reset_timedout_connection; /* reset_timedout_connection */
    ngx_flag_t    absolute_redirect;       /* absolute_redirect */
    ngx_flag_t    server_name_in_redirect; /* server_name_in_redirect */
    ngx_flag_t    port_in_redirect;        /* port_in_redirect */
    ngx_flag_t    msie_padding;            /* msie_padding */
    ngx_flag_t    msie_refresh;            /* msie_refresh */
    ngx_flag_t    log_not_found;           /* log_not_found */
    ngx_flag_t    log_subrequest;          /* log_subrequest */
    ngx_flag_t    recursive_error_pages;   /* recursive_error_pages */
    ngx_uint_t    server_tokens;           /* server_tokens */
    ngx_flag_t    chunked_transfer_encoding; /* chunked_transfer_encoding */
    ngx_flag_t    etag;                    /* etag */

#if (NGX_HTTP_GZIP)
    ngx_flag_t    gzip_vary;               /* gzip_vary */

    ngx_uint_t    gzip_http_version;       /* gzip_http_version */
    ngx_uint_t    gzip_proxied;            /* gzip_proxied */

#if (NGX_PCRE)
    ngx_array_t  *gzip_disable;            /* gzip_disable */
#endif
#endif

#if (NGX_THREADS || NGX_COMPAT)
    ngx_thread_pool_t         *thread_pool;
    ngx_http_complex_value_t  *thread_pool_value;
#endif

#if (NGX_HAVE_OPENAT)
    ngx_uint_t    disable_symlinks;        /* disable_symlinks */
    ngx_http_complex_value_t  *disable_symlinks_from;
#endif

    ngx_array_t  *error_pages;             /* error_page */

    ngx_path_t   *client_body_temp_path;   /* client_body_temp_path */

    ngx_open_file_cache_t  *open_file_cache;
    time_t        open_file_cache_valid;
    ngx_uint_t    open_file_cache_min_uses;
    ngx_flag_t    open_file_cache_errors;
    ngx_flag_t    open_file_cache_events;

    ngx_log_t    *error_log;

    ngx_uint_t    types_hash_max_size;
    ngx_uint_t    types_hash_bucket_size;

    //将同一个server块内多个表达location块的 ngx_http_core_loc_conf_t结构体以双向链表方式组织起来，
    //该 locations指针将指向 ngx_http_location_queue_t结构体
    //属于当前块的所有ocation块通过ngx_http_location_queue_t结构体构成的双向链表
    ngx_queue_t  *locations;

#if 0
    ngx_http_core_loc_conf_t  *prev_location;
#endif
};

/**
 * 每一个ngx_http_core_loc_conf_t结构体(代表一个location{}块)都对应着 1个ngx_http_location_queue_t，
 * 因此，此处将把ngx_http_location_queue_t串联成双向链表
 */
typedef struct {
    //queue将作为 ngx_queue_t双向链表容器，从而将 ngx_http_location_queue_t结构体连接起来
    ngx_queue_t                      queue;
    //如果 location中的字符串可以精确匹配（包括正则表达式），exact将指向对应的 ngx_http_core_loc_conf_t结构体，否则值为 NULL
    ngx_http_core_loc_conf_t        *exact;
    //如果 location中的字符串无法精确匹配（包括了自定义的通配符）， inclusive将指向对应的 ngx_http_core_loc_conf_t结构体，否则值为 NULL
    ngx_http_core_loc_conf_t        *inclusive;
    //指向 location的名称
    ngx_str_t                       *name;
    u_char                          *file_name;
    ngx_uint_t                       line;
    ngx_queue_t                      list;
} ngx_http_location_queue_t;

/**
 * location查找的静态二叉树节点
 */
struct ngx_http_location_tree_node_s {
    ngx_http_location_tree_node_t   *left;  // 左子树
    ngx_http_location_tree_node_t   *right;  // 右子树
    ngx_http_location_tree_node_t   *tree;  // 无法完全匹配的 location组成的树

    //如果 location对应的 URI匹配字符串属于能够完全匹配的类型，则 exact指向其对应的 ngx_http_core_loc_conf_t结构体，否则为 NULL空指针
    ngx_http_core_loc_conf_t        *exact;
    //如果 location对应的 URI匹配字符串属于无法完全匹配的类型，则 inclusive指向其对应的 ngx_http_core_loc_conf_t结构体，否则为 NULL空指针
    ngx_http_core_loc_conf_t        *inclusive;

    // name字符串的实际长度
    u_short                          len;
    // 自动重定向标志
    u_char                           auto_redirect;
    // name指向 location对应的 URI匹配表达式
    u_char                           name[1];
};


void ngx_http_core_run_phases(ngx_http_request_t *r);
ngx_int_t ngx_http_core_generic_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_rewrite_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_find_config_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_post_rewrite_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_access_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_post_access_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_content_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);


void *ngx_http_test_content_type(ngx_http_request_t *r, ngx_hash_t *types_hash);
ngx_int_t ngx_http_set_content_type(ngx_http_request_t *r);
void ngx_http_set_exten(ngx_http_request_t *r);
ngx_int_t ngx_http_set_etag(ngx_http_request_t *r);
void ngx_http_weak_etag(ngx_http_request_t *r);
ngx_int_t ngx_http_send_response(ngx_http_request_t *r, ngx_uint_t status,
    ngx_str_t *ct, ngx_http_complex_value_t *cv);
u_char *ngx_http_map_uri_to_path(ngx_http_request_t *r, ngx_str_t *name,
    size_t *root_length, size_t reserved);
ngx_int_t ngx_http_auth_basic_user(ngx_http_request_t *r);
#if (NGX_HTTP_GZIP)
ngx_int_t ngx_http_gzip_ok(ngx_http_request_t *r);
#endif

// 创建子请求对象，复制父请求的大部分字段
ngx_int_t ngx_http_subrequest(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args, ngx_http_request_t **psr,
    ngx_http_post_subrequest_t *ps, ngx_uint_t flags);
ngx_int_t ngx_http_internal_redirect(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args);
ngx_int_t ngx_http_named_location(ngx_http_request_t *r, ngx_str_t *name);

// 当http请求结束时的清理动作
ngx_http_cleanup_t *ngx_http_cleanup_add(ngx_http_request_t *r, size_t size);

// 响应头过滤函数原型
typedef ngx_int_t (*ngx_http_output_header_filter_pt)(ngx_http_request_t *r);

// 响应体过滤函数原型，chain 是本次要发送的数据
typedef ngx_int_t (*ngx_http_output_body_filter_pt)
    (ngx_http_request_t *r, ngx_chain_t *chain);

// 请求体过滤函数原型, chain 是接收到的数据
typedef ngx_int_t (*ngx_http_request_body_filter_pt)
    (ngx_http_request_t *r, ngx_chain_t *chain);


ngx_int_t ngx_http_output_filter(ngx_http_request_t *r, ngx_chain_t *chain);
ngx_int_t ngx_http_write_filter(ngx_http_request_t *r, ngx_chain_t *chain);
ngx_int_t ngx_http_request_body_save_filter(ngx_http_request_t *r,
    ngx_chain_t *chain);


ngx_int_t ngx_http_set_disable_symlinks(ngx_http_request_t *r,
    ngx_http_core_loc_conf_t *clcf, ngx_str_t *path, ngx_open_file_info_t *of);

ngx_int_t ngx_http_get_forwarded_addr(ngx_http_request_t *r, ngx_addr_t *addr,
    ngx_table_elt_t *headers, ngx_str_t *value, ngx_array_t *proxies,
    int recursive);

ngx_int_t ngx_http_link_multi_headers(ngx_http_request_t *r);


extern ngx_module_t  ngx_http_core_module;

extern ngx_uint_t ngx_http_max_module;

extern ngx_str_t  ngx_http_core_get_method;

/**
 * 移除content_length响应头
 * 1.content_length_n 设置为-1
 * 2.content_length响应头置空
 */
#define ngx_http_clear_content_length(r)                                      \
                                                                              \
    r->headers_out.content_length_n = -1;                                     \
    if (r->headers_out.content_length) {                                      \
        r->headers_out.content_length->hash = 0;                              \
        r->headers_out.content_length = NULL;                                 \
    }

/**
 * 移除accept_ranges响应头
 * 1. allow_ranges设置为0
 * 2. accept_ranges响应头置空
 */
#define ngx_http_clear_accept_ranges(r)                                       \
                                                                              \
    r->allow_ranges = 0;                                                      \
    if (r->headers_out.accept_ranges) {                                       \
        r->headers_out.accept_ranges->hash = 0;                               \
        r->headers_out.accept_ranges = NULL;                                  \
    }

/**
 * 移除last_modified响应头
 * 1. last_modified_time设置为-1
 * 2. last_modified响应头置空
 */
#define ngx_http_clear_last_modified(r)                                       \
                                                                              \
    r->headers_out.last_modified_time = -1;                                   \
    if (r->headers_out.last_modified) {                                       \
        r->headers_out.last_modified->hash = 0;                               \
        r->headers_out.last_modified = NULL;                                  \
    }

/**
 * 移除location响应头
 */
#define ngx_http_clear_location(r)                                            \
                                                                              \
    if (r->headers_out.location) {                                            \
        r->headers_out.location->hash = 0;                                    \
        r->headers_out.location = NULL;                                       \
    }

/**
 * 移除etag响应头
 */
#define ngx_http_clear_etag(r)                                                \
                                                                              \
    if (r->headers_out.etag) {                                                \
        r->headers_out.etag->hash = 0;                                        \
        r->headers_out.etag = NULL;                                           \
    }


#endif /* _NGX_HTTP_CORE_H_INCLUDED_ */
