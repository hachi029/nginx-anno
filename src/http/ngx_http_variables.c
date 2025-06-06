
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>


static ngx_http_variable_t *ngx_http_add_prefix_variable(ngx_conf_t *cf,
    ngx_str_t *name, ngx_uint_t flags);

static ngx_int_t ngx_http_variable_request(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
#if 0
static void ngx_http_variable_request_set(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
#endif
static ngx_int_t ngx_http_variable_request_get_size(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_header(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_variable_cookies(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_headers_internal(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data, u_char sep);

static ngx_int_t ngx_http_variable_unknown_header_in(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_unknown_header_out(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_unknown_trailer_out(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_request_line(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_cookie(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_argument(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
#if (NGX_HAVE_TCP_INFO)
static ngx_int_t ngx_http_variable_tcpinfo(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
#endif

static ngx_int_t ngx_http_variable_content_length(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_host(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_binary_remote_addr(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_remote_addr(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_remote_port(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_proxy_protocol_addr(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_proxy_protocol_port(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_proxy_protocol_tlv(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_server_addr(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_server_port(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_scheme(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_https(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void ngx_http_variable_set_args(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_is_args(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_document_root(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_realpath_root(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_request_filename(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_server_name(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_request_method(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_remote_user(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_bytes_sent(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_body_bytes_sent(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_pipe(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_request_completion(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_request_body(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_request_body_file(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_request_length(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_request_time(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_request_id(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_status(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_variable_sent_content_type(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_sent_content_length(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_sent_location(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_sent_last_modified(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_sent_connection(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_sent_keep_alive(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_sent_transfer_encoding(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void ngx_http_variable_set_limit_rate(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_variable_connection(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_connection_requests(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_connection_time(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_variable_nginx_version(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_hostname(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_pid(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_msec(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_time_iso8601(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_time_local(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

/*
 * TODO:
 *     Apache CGI: AUTH_TYPE, PATH_INFO (null), PATH_TRANSLATED
 *                 REMOTE_HOST (null), REMOTE_IDENT (null),
 *                 SERVER_SOFTWARE
 *
 *     Apache SSI: DOCUMENT_NAME, LAST_MODIFIED, USER_NAME (file owner)
 */

/*
 * the $http_host, $http_user_agent, $http_referer, and $http_via
 * variables may be handled by generic
 * ngx_http_variable_unknown_header_in(), but for performance reasons
 * they are handled using dedicated entries
 */

static ngx_http_variable_t  ngx_http_core_variables[] = {

    { ngx_string("http_host"), NULL, ngx_http_variable_header,
      offsetof(ngx_http_request_t, headers_in.host), 0, 0 },

    { ngx_string("http_user_agent"), NULL, ngx_http_variable_header,
      offsetof(ngx_http_request_t, headers_in.user_agent), 0, 0 },

    { ngx_string("http_referer"), NULL, ngx_http_variable_header,
      offsetof(ngx_http_request_t, headers_in.referer), 0, 0 },

#if (NGX_HTTP_GZIP)
    { ngx_string("http_via"), NULL, ngx_http_variable_header,
      offsetof(ngx_http_request_t, headers_in.via), 0, 0 },
#endif

#if (NGX_HTTP_X_FORWARDED_FOR)
    { ngx_string("http_x_forwarded_for"), NULL, ngx_http_variable_header,
      offsetof(ngx_http_request_t, headers_in.x_forwarded_for), 0, 0 },
#endif

    { ngx_string("http_cookie"), NULL, ngx_http_variable_cookies,
      offsetof(ngx_http_request_t, headers_in.cookie), 0, 0 },

    { ngx_string("content_length"), NULL, ngx_http_variable_content_length,
      0, 0, 0 },

    { ngx_string("content_type"), NULL, ngx_http_variable_header,
      offsetof(ngx_http_request_t, headers_in.content_type), 0, 0 },

    { ngx_string("host"), NULL, ngx_http_variable_host, 0, 0, 0 },

    { ngx_string("binary_remote_addr"), NULL,
      ngx_http_variable_binary_remote_addr, 0, 0, 0 },

    { ngx_string("remote_addr"), NULL, ngx_http_variable_remote_addr, 0, 0, 0 },

    { ngx_string("remote_port"), NULL, ngx_http_variable_remote_port, 0, 0, 0 },

    { ngx_string("proxy_protocol_addr"), NULL,
      ngx_http_variable_proxy_protocol_addr,
      offsetof(ngx_proxy_protocol_t, src_addr), 0, 0 },

    { ngx_string("proxy_protocol_port"), NULL,
      ngx_http_variable_proxy_protocol_port,
      offsetof(ngx_proxy_protocol_t, src_port), 0, 0 },

    { ngx_string("proxy_protocol_server_addr"), NULL,
      ngx_http_variable_proxy_protocol_addr,
      offsetof(ngx_proxy_protocol_t, dst_addr), 0, 0 },

    { ngx_string("proxy_protocol_server_port"), NULL,
      ngx_http_variable_proxy_protocol_port,
      offsetof(ngx_proxy_protocol_t, dst_port), 0, 0 },

    { ngx_string("proxy_protocol_tlv_"), NULL,
      ngx_http_variable_proxy_protocol_tlv,
      0, NGX_HTTP_VAR_PREFIX, 0 },

    { ngx_string("server_addr"), NULL, ngx_http_variable_server_addr, 0, 0, 0 },

    { ngx_string("server_port"), NULL, ngx_http_variable_server_port, 0, 0, 0 },

    { ngx_string("server_protocol"), NULL, ngx_http_variable_request,
      offsetof(ngx_http_request_t, http_protocol), 0, 0 },

    { ngx_string("scheme"), NULL, ngx_http_variable_scheme, 0, 0, 0 },

    { ngx_string("https"), NULL, ngx_http_variable_https, 0, 0, 0 },

    { ngx_string("request_uri"), NULL, ngx_http_variable_request,
      offsetof(ngx_http_request_t, unparsed_uri), 0, 0 },

    { ngx_string("uri"), NULL, ngx_http_variable_request,
      offsetof(ngx_http_request_t, uri),
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("document_uri"), NULL, ngx_http_variable_request,
      offsetof(ngx_http_request_t, uri),
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("request"), NULL, ngx_http_variable_request_line, 0, 0, 0 },

    { ngx_string("document_root"), NULL,
      ngx_http_variable_document_root, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("realpath_root"), NULL,
      ngx_http_variable_realpath_root, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("query_string"), NULL, ngx_http_variable_request,
      offsetof(ngx_http_request_t, args),
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("args"),
      ngx_http_variable_set_args,
      ngx_http_variable_request,
      offsetof(ngx_http_request_t, args),
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("is_args"), NULL, ngx_http_variable_is_args,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("request_filename"), NULL,
      ngx_http_variable_request_filename, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("server_name"), NULL, ngx_http_variable_server_name, 0, 0, 0 },

    { ngx_string("request_method"), NULL,
      ngx_http_variable_request_method, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("remote_user"), NULL, ngx_http_variable_remote_user, 0, 0, 0 },

    { ngx_string("bytes_sent"), NULL, ngx_http_variable_bytes_sent,
      0, 0, 0 },

    { ngx_string("body_bytes_sent"), NULL, ngx_http_variable_body_bytes_sent,
      0, 0, 0 },

    { ngx_string("pipe"), NULL, ngx_http_variable_pipe,
      0, 0, 0 },

    { ngx_string("request_completion"), NULL,
      ngx_http_variable_request_completion,
      0, 0, 0 },

    { ngx_string("request_body"), NULL,
      ngx_http_variable_request_body,
      0, 0, 0 },

    { ngx_string("request_body_file"), NULL,
      ngx_http_variable_request_body_file,
      0, 0, 0 },

    { ngx_string("request_length"), NULL, ngx_http_variable_request_length,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("request_time"), NULL, ngx_http_variable_request_time,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("request_id"), NULL,
      ngx_http_variable_request_id,
      0, 0, 0 },

    { ngx_string("status"), NULL,
      ngx_http_variable_status, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("sent_http_content_type"), NULL,
      ngx_http_variable_sent_content_type, 0, 0, 0 },

    { ngx_string("sent_http_content_length"), NULL,
      ngx_http_variable_sent_content_length, 0, 0, 0 },

    { ngx_string("sent_http_location"), NULL,
      ngx_http_variable_sent_location, 0, 0, 0 },

    { ngx_string("sent_http_last_modified"), NULL,
      ngx_http_variable_sent_last_modified, 0, 0, 0 },

    { ngx_string("sent_http_connection"), NULL,
      ngx_http_variable_sent_connection, 0, 0, 0 },

    { ngx_string("sent_http_keep_alive"), NULL,
      ngx_http_variable_sent_keep_alive, 0, 0, 0 },

    { ngx_string("sent_http_transfer_encoding"), NULL,
      ngx_http_variable_sent_transfer_encoding, 0, 0, 0 },

    { ngx_string("sent_http_cache_control"), NULL, ngx_http_variable_header,
      offsetof(ngx_http_request_t, headers_out.cache_control), 0, 0 },

    { ngx_string("sent_http_link"), NULL, ngx_http_variable_header,
      offsetof(ngx_http_request_t, headers_out.link), 0, 0 },

    { ngx_string("limit_rate"), ngx_http_variable_set_limit_rate,
      ngx_http_variable_request_get_size,
      offsetof(ngx_http_request_t, limit_rate),
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("connection"), NULL,
      ngx_http_variable_connection, 0, 0, 0 },

    { ngx_string("connection_requests"), NULL,
      ngx_http_variable_connection_requests, 0, 0, 0 },

    { ngx_string("connection_time"), NULL, ngx_http_variable_connection_time,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("nginx_version"), NULL, ngx_http_variable_nginx_version,
      0, 0, 0 },

    { ngx_string("hostname"), NULL, ngx_http_variable_hostname,
      0, 0, 0 },

    { ngx_string("pid"), NULL, ngx_http_variable_pid,
      0, 0, 0 },

    { ngx_string("msec"), NULL, ngx_http_variable_msec,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("time_iso8601"), NULL, ngx_http_variable_time_iso8601,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("time_local"), NULL, ngx_http_variable_time_local,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

#if (NGX_HAVE_TCP_INFO)
    { ngx_string("tcpinfo_rtt"), NULL, ngx_http_variable_tcpinfo,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("tcpinfo_rttvar"), NULL, ngx_http_variable_tcpinfo,
      1, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("tcpinfo_snd_cwnd"), NULL, ngx_http_variable_tcpinfo,
      2, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("tcpinfo_rcv_space"), NULL, ngx_http_variable_tcpinfo,
      3, NGX_HTTP_VAR_NOCACHEABLE, 0 },
#endif

    { ngx_string("http_"), NULL, ngx_http_variable_unknown_header_in,
      0, NGX_HTTP_VAR_PREFIX, 0 },

    { ngx_string("sent_http_"), NULL, ngx_http_variable_unknown_header_out,
      0, NGX_HTTP_VAR_PREFIX, 0 },

    { ngx_string("sent_trailer_"), NULL, ngx_http_variable_unknown_trailer_out,
      0, NGX_HTTP_VAR_PREFIX, 0 },

    { ngx_string("cookie_"), NULL, ngx_http_variable_cookie,
      0, NGX_HTTP_VAR_PREFIX, 0 },

    { ngx_string("arg_"), NULL, ngx_http_variable_argument,
      0, NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_PREFIX, 0 },

      ngx_http_null_variable
};


ngx_http_variable_value_t  ngx_http_variable_null_value =
    ngx_http_variable("");
ngx_http_variable_value_t  ngx_http_variable_true_value =
    ngx_http_variable("1");


static ngx_uint_t  ngx_http_variable_depth = 100;

/**
 * 变量的索引由两部分组成，一是定义变量的ngx_http_variable_t结构体构成的索引数组； 
 * 二是描述变量值的ngx_http_variable_value_t结构体构成的数组
 * 前者在Nginx只有全局的唯一 一份，存储在ngx_http_core_main_conf_t结构体的variables中
 * 后者对每一个HTTP请求都会有 一份，存储在ngx_http_request_t结构体的variables中
 * 
 * 这两者间同属于一个变量的名字、值在 各自数组中的索引号都是一一对应的
 * 
 * 
 * 想以索引方式使用变量的模块，都会在模块初始化阶段获得索引号，在Nginx运行中、 HTTP请求到达时，则会根据这个索引号，
 * 要么从ngx_http_variable_t构成的数组中找到变量 定义并使用get_handler方法解析出变量值
 * （如果flags参数指明可以缓存，那么还会缓存到请 求中），要么从ngx_http_variable_value_t构成的数组中直接获得缓存的变量值
 * 
 * 
 * 
 * 每一个HTTP请求都必须为所有缓存的变量建立ngx_http_variable_value_t数组，这似乎有 些内存浪费，
 * 因此，不使用索引而是散列表来使用变量也是可以的
 * 
 * 此时，使用变量的模块不用在Nginx初始化阶段做些什么，只要这个变量已经有模块定义过，那么在处理请求时，
 * 仅需要把变量名字符串按照hash方法求出散列值，就可以在 ngx_http_core_main_conf_t结构体的variables_hash
 * 散列表中找到定义变量的ngx_http_variable_t 结构体，
 * 如果其flags成员指明变量是被索引的，那么会根据index成员直接向请求的variables 数组里获得预分配的ngx_http_variable_value_t结构体，
 * 这个变量值若没有解析过，就会用该结构体传给get_handler方法解析、缓存（如果可以的话）。
 * 
 * 如果flags成员没有说明变量被索 引过，那么就会在请求的内存池里新分配1个ngx_http_variable_value_t结构体，
 * 用于传递给get_handler方法解析、承载变量值
 * 
 * 
 * 如果这个变量被索引过，那么ngx_http_get_variable方法会优先在 ngx_http_request_t中缓存变量值的variables数组中的获取值。
 * 是否被索引过的依据就是检查 flags参数是否含有NGX_HTTP_VAR_INDEXED标志位
 * 
 */


/**
 * 
 * 注册一个变量，在ngx_http_module_t的preconfiguration方法中调用
 * 
 * cf的用途有两个：
 *    定义新变量一定会放到 全局唯一的ngx_http_core_main_conf_t结构体，参数cf可以找到这个全局配置结构体；
 *    分配变量相关结构体的内存时，可以用cf的内存池
 * name: 变量的名称
 * flags: 等价于ngx_http_variable_t中的flags成员
 * 
 * 返回值就是已经准备好的、用于定义变量的ngx_http_variable_t结构体, 这个结构 体的name和flags成员已经设置好了
 * 需要指定解析方法，包 括指定get_handler、set_handler（很少设置）、data（如果有必要的话）
 * 
 * 如果这个变量曾经被其他模块添加过，那么此时的返回值ngx_http_variable_t 就是其他模块已经设置过的对象，
 * 它的get_handler等成员可能已经设置过了。开发模块新变量时应当妥善处理这种变量名冲突问题
 * 
 * 
 */
ngx_http_variable_t *
ngx_http_add_variable(ngx_conf_t *cf, ngx_str_t *name, ngx_uint_t flags)
{
    ngx_int_t                   rc;
    ngx_uint_t                  i;
    ngx_hash_key_t             *key;
    ngx_http_variable_t        *v;
    ngx_http_core_main_conf_t  *cmcf;

    //变量名不能为空
    if (name->len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"$\"");
        return NULL;
    }

    //如果是带前缀的变量
    if (flags & NGX_HTTP_VAR_PREFIX) {
        //处理带前缀变量的专用函数
        //前缀变量名会加入到动态数组 cmcf->prefix_variables中
        return ngx_http_add_prefix_variable(cf, name, flags);
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    //遍历 cmcf->variables_keys->keys
    key = cmcf->variables_keys->keys.elts;
    for (i = 0; i < cmcf->variables_keys->keys.nelts; i++) {
        if (name->len != key[i].key.len
            || ngx_strncasecmp(name->data, key[i].key.data, name->len) != 0)
        {
            continue;
        }

        //此处说明在cmcf->variables_keys->keys动态数组中找到了相同名称的变量
        v = key[i].value;

        //如果flags中没有NGX_HTTP_VAR_CHANGEABLE标识，则返回事变
        if (!(v->flags & NGX_HTTP_VAR_CHANGEABLE)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "the duplicate \"%V\" variable", name);
            return NULL;
        }

        //如果新定义变量没有VAR_WEAK标识，则同步更新已注册的变量flags
        if (!(flags & NGX_HTTP_VAR_WEAK)) {
            v->flags &= ~NGX_HTTP_VAR_WEAK;
        }

        return v;
    }

    //分配一个保存变量名称的结构体 ngx_http_variable_t
    v = ngx_palloc(cf->pool, sizeof(ngx_http_variable_t));
    if (v == NULL) {
        return NULL;
    }

    v->name.len = name->len;
    v->name.data = ngx_pnalloc(cf->pool, name->len);
    if (v->name.data == NULL) {
        return NULL;
    }

    //将name转小写后赋值给v
    ngx_strlow(v->name.data, name->data, name->len);

    v->set_handler = NULL;
    v->get_handler = NULL;
    v->data = 0;
    v->flags = flags;
    v->index = 0;

    //添加到临时动态数组里
    rc = ngx_hash_add_key(cmcf->variables_keys, &v->name, v, 0);

    if (rc == NGX_ERROR) {
        return NULL;
    }

    if (rc == NGX_BUSY) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "conflicting variable name \"%V\"", name);
        return NULL;
    }

    //返回新创建的代表变量名的结构体v
    return v;
}


/**
 * 添加带前缀的变量， ngx_http_add_variable中，如果flags中有NGX_HTTP_VAR_PREFIX标识，会调用此方法
 * 
 * 前缀变量名会加入到动态数组 cmcf->prefix_variables中
 */
static ngx_http_variable_t *
ngx_http_add_prefix_variable(ngx_conf_t *cf, ngx_str_t *name, ngx_uint_t flags)
{
    ngx_uint_t                  i;
    ngx_http_variable_t        *v;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    //遍历所有前缀变量名
    v = cmcf->prefix_variables.elts;
    for (i = 0; i < cmcf->prefix_variables.nelts; i++) {
        if (name->len != v[i].name.len
            || ngx_strncasecmp(name->data, v[i].name.data, name->len) != 0)
        {
            continue;
        }

        //找到了相同前缀的变量名
        v = &v[i];

        if (!(v->flags & NGX_HTTP_VAR_CHANGEABLE)) {    //如果不是 VAR_CHANGEABLE，即不允许重新定义， 则报错
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "the duplicate \"%V\" variable", name);
            return NULL;
        }

        if (!(flags & NGX_HTTP_VAR_WEAK)) {     //重新定义VAR_WEAK标识
            v->flags &= ~NGX_HTTP_VAR_WEAK;
        }

        return v;
    }

    //到此处说明是新的前缀变量，将其加入到cmcf->prefix_variables动态数组中
    v = ngx_array_push(&cmcf->prefix_variables);
    if (v == NULL) {
        return NULL;
    }

    v->name.len = name->len;
    v->name.data = ngx_pnalloc(cf->pool, name->len);
    if (v->name.data == NULL) {
        return NULL;
    }

    //转为小写
    ngx_strlow(v->name.data, name->data, name->len);

    v->set_handler = NULL;
    v->get_handler = NULL;
    v->data = 0;
    v->flags = flags;
    v->index = 0;

    return v;
}


/**
 * 
 * Nginx提供了两种方式来找出要使用的内部变量:
 *  一种是索引过的变量，可直接由数组下标找到元素；
 *   另一种是添加到散列表的变量，需要将字符串变量名由散列方法算出散列值，再从散列表中找出元素，遇到元素冲突时需要遍历开散列表的槽位链表
 * 
 * 
 * 获取变量的索引值
 * 使用索引值 而不是变量字符串来获取变量值会加快Nginx的执行速度
 * 
 * name为变量名
 * 返回值就是这个变量的索引值
 * 
 * !!!!如果对应名称的变量未找到，则将其加入到&cmcf->variables变量
 */
ngx_int_t
ngx_http_get_variable_index(ngx_conf_t *cf, ngx_str_t *name)
{
    ngx_uint_t                  i;
    ngx_http_variable_t        *v;
    ngx_http_core_main_conf_t  *cmcf;

    //如果name为空字符串
    if (name->len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"$\"");
        return NGX_ERROR;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    v = cmcf->variables.elts;

    if (v == NULL) {    //如果为NULL，则初始化cmcf->variables
        if (ngx_array_init(&cmcf->variables, cf->pool, 4,
                           sizeof(ngx_http_variable_t))
            != NGX_OK)
        {
            return NGX_ERROR;
        }

    } else {
        //遍历cmcf->variables数组，找到对应元素的索引
        for (i = 0; i < cmcf->variables.nelts; i++) {
            if (name->len != v[i].name.len
                || ngx_strncasecmp(name->data, v[i].name.data, name->len) != 0)
            {
                continue;
            }

            return i;
        }
    }

    //没找到，则将其加入到动态数组中
    v = ngx_array_push(&cmcf->variables);
    if (v == NULL) {
        return NGX_ERROR;
    }

    v->name.len = name->len;
    v->name.data = ngx_pnalloc(cf->pool, name->len);
    if (v->name.data == NULL) {
        return NGX_ERROR;
    }

    //转为小写
    ngx_strlow(v->name.data, name->data, name->len);

    v->set_handler = NULL;
    v->get_handler = NULL;
    v->data = 0;
    v->flags = 0;
    v->index = cmcf->variables.nelts - 1;

    //返回新添加元素的索引
    return v->index;
}


/**
 * 基于变量索引值，获取变量值
 * 返回值就是变量值, 返回NULL 即没有解析出变量
 * 
 * 
 * 需要使用变量的模块，通常会在解析配置的这一步中将待使用的变量索引化，变量索引化是有代价的，
 * 所有索引化的变量都会导致存储请求的结构体 ngx_http_request_t增加内存占用
 * 
 */
ngx_http_variable_value_t *
ngx_http_get_indexed_variable(ngx_http_request_t *r, ngx_uint_t index)
{
    ngx_http_variable_t        *v;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    //如果index大于cmcf->variables元素个数
    if (cmcf->variables.nelts <= index) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "unknown variable index: %ui", index);
        return NULL;
    }

    //已经解析过
    if (r->variables[index].not_found || r->variables[index].valid) {
        return &r->variables[index];
    }

    //索引数组的起始地址
    v = cmcf->variables.elts;

    if (ngx_http_variable_depth == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "cycle while evaluating variable \"%V\"",
                      &v[index].name);
        return NULL;
    }

    ngx_http_variable_depth--;

    //获取变量值
    if (v[index].get_handler(r, &r->variables[index], v[index].data)
        == NGX_OK)
    {
        ngx_http_variable_depth++;

        if (v[index].flags & NGX_HTTP_VAR_NOCACHEABLE) {
            r->variables[index].no_cacheable = 1;       //设置NGX_HTTP_VAR_NOCACHEABLE标识
        }

        return &r->variables[index];
    }

    ngx_http_variable_depth++;

    //not found
    r->variables[index].valid = 0;
    r->variables[index].not_found = 1;

    return NULL;
}


/**
 * 作用等同于ngx_http_get_indexed_variable， 区别是如果flags里设置了 NGX_HTTP_VAR_NOCACHEABLE，本方法重新解析
 * 
 */
ngx_http_variable_value_t *
ngx_http_get_flushed_variable(ngx_http_request_t *r, ngx_uint_t index)
{
    ngx_http_variable_value_t  *v;

    v = &r->variables[index];

    if (v->valid || v->not_found) {     //都说明已经解析过了
        if (!v->no_cacheable) {     //如果没有NGX_HTTP_VAR_NOCACHEABLE flag
            return v;
        }

        v->valid = 0;           //重置标识，触发重新解析
        v->not_found = 0;
    }

    return ngx_http_get_indexed_variable(r, index);
}


/**
 * 根据变量名获取变量值
 * 
 * 变量并非要么在散列表中，要么在索引数组中。对于特殊变量，是可以绕开二者用ngx_http_get_variable方法获取其值的
 * 
 * 从被hash过的散列表中找到对应的变量并调用其解析方法获取值，这里不存在缓存变量值的可能
 * 
 * 若是5中特殊变量，可以从此方法中获取解析出的值
 * 
 * 
 * 依次尝试从cmcf->variables_hash、cmcf->prefix_variables 中获取变量值
 * 
 */
ngx_http_variable_value_t *
ngx_http_get_variable(ngx_http_request_t *r, ngx_str_t *name, ngx_uint_t key)
{
    size_t                      len;
    ngx_uint_t                  i, n;
    ngx_http_variable_t        *v;
    ngx_http_variable_value_t  *vv;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    //1.先从&cmcf->variables_has中找到代表变量名的ngx_http_variable_t
    v = ngx_hash_find(&cmcf->variables_hash, key, name->data, name->len);

    if (v) {
        if (v->flags & NGX_HTTP_VAR_INDEXED) {  //如果是索引变量，通过索引获取变量值
            return ngx_http_get_flushed_variable(r, v->index);
        }

        if (ngx_http_variable_depth == 0) {     //避免变量解析死循环
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "cycle while evaluating variable \"%V\"", name);
            return NULL;
        }

        ngx_http_variable_depth--;

        //分配一个代表hash值的ngx_http_variable_value_t结构体
        vv = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));

        //调用变量获取值的方法
        if (vv && v->get_handler(r, vv, v->data) == NGX_OK) {
            ngx_http_variable_depth++;
            return vv;
        }

        //v->get_handler 失败
        ngx_http_variable_depth++;
        return NULL;
    }

    //2. 从cmcf->variables_hash 中未找到，尝试从cmcf->prefix_variables查找
    vv = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));
    if (vv == NULL) {
        return NULL;
    }

    len = 0;

    //前缀变量
    v = cmcf->prefix_variables.elts;
    n = cmcf->prefix_variables.nelts;

    for (i = 0; i < cmcf->prefix_variables.nelts; i++) {
        if (name->len >= v[i].name.len && name->len > len
            && ngx_strncmp(name->data, v[i].name.data, v[i].name.len) == 0)
        {
            //前缀匹配
            len = v[i].name.len;
            n = i;
        }
    }

    if (n != cmcf->prefix_variables.nelts) {        //判断前一步根据前缀是否匹配到
        if (v[n].get_handler(r, vv, (uintptr_t) name) == NGX_OK) {
            return vv;
        }

        return NULL;
    }

    //未找到
    vv->not_found = 1;

    return vv;
}


/**
 * 解析变量值的handler, 变量值存放到r中， data为对应字段在r中的偏移。 且变量值为ngx_str
 */
static ngx_int_t
ngx_http_variable_request(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_str_t  *s;

    s = (ngx_str_t *) ((char *) r + data);

    if (s->data) {
        v->len = s->len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = s->data;

    } else {
        v->not_found = 1;
    }

    return NGX_OK;
}


#if 0

static void
ngx_http_variable_request_set(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t  *s;

    s = (ngx_str_t *) ((char *) r + data);

    s->len = v->len;
    s->data = v->data;
}

#endif


/**
 * 解析变量值的handler, 变量值存放到r中， data为对应字段在r中的偏移。 且变量值为ngx_size_t
 */
static ngx_int_t
ngx_http_variable_request_get_size(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    size_t  *sp;

    sp = (size_t *) ((char *) r + data);

    v->data = ngx_pnalloc(r->pool, NGX_SIZE_T_LEN);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(v->data, "%uz", *sp) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


/**
 * 解析请求头， UA、Host、Referer等
 */
static ngx_int_t
ngx_http_variable_header(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    return ngx_http_variable_headers_internal(r, v, data, ',');
}


/**
 * 解析Cookie 
 */
static ngx_int_t
ngx_http_variable_cookies(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    return ngx_http_variable_headers_internal(r, v, data, ';');
}


/**
 * 解析变量， data作为请求r的offset, 变量值是ngx_table_elt_t 指针
 * 
 * 值可能有多个，多个按照'sep'+' ' 分割
 */
static ngx_int_t
ngx_http_variable_headers_internal(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data, u_char sep)
{
    size_t            len;
    u_char           *p, *end;
    ngx_table_elt_t  *h, *th;

    // data偏移量就是解析过的 ngx_table_elt_t类型的成员，在 ngx_http_request_t结构体中的偏移量
    h = *(ngx_table_elt_t **) ((char *) r + data);

    len = 0;    //记录后续需要申请的缓冲区长度

    for (th = h; th; th = th->next) {

        //跳过hash为0的元素
        if (th->hash == 0) {
            continue;
        }

        len += th->value.len + 2;       //+2, 一个是参数sep, 另一个是空格' ', 参考下边逻辑
    }

    if (len == 0) {
        //h为null, 未找到
        v->not_found = 1;
        return NGX_OK;
    }

    len -= 2;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (h->next == NULL) {      //h->next==NULL说明是单个值 (单个header)
        // 将 len和 data指向字符串值
        v->len = h->value.len;
        v->data = h->value.data;

        return NGX_OK;
    }

    //申请内存
    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = len;
    v->data = p;

    end = p + len;

    for (th = h; th; th = th->next) {

        //跳过hash为0的元素
        if (th->hash == 0) {
            continue;
        }

        //拷贝值
        p = ngx_copy(p, th->value.data, th->value.len);

        if (p == end) {
            break;
        }

        //分割符为 'sep '
        *p++ = sep; *p++ = ' ';
    }

    return NGX_OK;
}


/**
 * 解析5类特殊变量中的http_开头的变量。即请求头参数
 */
static ngx_int_t
ngx_http_variable_unknown_header_in(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    return ngx_http_variable_unknown_header(r, v, (ngx_str_t *) data,
                                            &r->headers_in.headers.part,
                                            sizeof("http_") - 1);
}


/**
 * 解析5类特殊变量中的sent_http_开头的变量。即相应头参数
 */
static ngx_int_t
ngx_http_variable_unknown_header_out(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    return ngx_http_variable_unknown_header(r, v, (ngx_str_t *) data,
                                            &r->headers_out.headers.part,
                                            sizeof("sent_http_") - 1);
}


static ngx_int_t
ngx_http_variable_unknown_trailer_out(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    return ngx_http_variable_unknown_header(r, v, (ngx_str_t *) data,
                                            &r->headers_out.trailers.part,
                                            sizeof("sent_trailer_") - 1);
}


/**
 * 解析header变量值，包括(sent_http_、http_、sent_trailer_)
 */
ngx_int_t
ngx_http_variable_unknown_header(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_str_t *var,
    ngx_list_part_t *part, size_t prefix)
{
    u_char           *p, ch;
    size_t            len;
    ngx_uint_t        i, n;
    ngx_table_elt_t  *header, *h, **ph;

    ph = &h;
#if (NGX_SUPPRESS_WARN)
    len = 0;
#endif

    header = part->elts;

    for (i = 0; /* void */ ; i++) {

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

        if (header[i].key.len != var->len - prefix) {
            continue;
        }

        for (n = 0; n < var->len - prefix; n++) {
            ch = header[i].key.data[n];

            if (ch >= 'A' && ch <= 'Z') {
                ch |= 0x20;

            } else if (ch == '-') {
                ch = '_';
            }

            if (var->data[n + prefix] != ch) {
                break;
            }
        }

        if (n != var->len - prefix) {
            continue;
        }

        len += header[i].value.len + 2;

        *ph = &header[i];
        ph = &header[i].next;
    }

    *ph = NULL;

    if (h == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    len -= 2;

    if (h->next == NULL) {

        v->len = h->value.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = h->value.data;

        return NGX_OK;
    }

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    for ( ;; ) {

        p = ngx_copy(p, h->value.data, h->value.len);

        if (h->next == NULL) {
            break;
        }

        *p++ = ','; *p++ = ' ';

        h = h->next;
    }

    return NGX_OK;
}


/**
 * 变量 $request, 即请求行
 */
static ngx_int_t
ngx_http_variable_request_line(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p, *s;

    s = r->request_line.data;

    if (s == NULL) {        //为NULL表示还没有解析请求行
        s = r->request_start;   //s 为请求数据开始的位置

        if (s == NULL) {
            v->not_found = 1;
            return NGX_OK;
        }

        for (p = s; p < r->header_in->last; p++) {
            //直到找到请求行尾部
            if (*p == CR || *p == LF) {
                break;
            }
        }

        //设置请求行
        r->request_line.len = p - s;
        r->request_line.data = s;
    }

    //将v指向请求行
    v->len = r->request_line.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = s;

    return NGX_OK;
}


/**
 * 解析5类特殊变量中的cookie_开头的变量。即请求cookie参数
 */
static ngx_int_t
ngx_http_variable_cookie(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_str_t *name = (ngx_str_t *) data;

    ngx_str_t  cookie, s;

    s.len = name->len - (sizeof("cookie_") - 1);
    s.data = name->data + sizeof("cookie_") - 1;

    if (ngx_http_parse_multi_header_lines(r, r->headers_in.cookie, &s, &cookie)
        == NULL)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = cookie.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = cookie.data;

    return NGX_OK;
}


/**
 * 解析5类特殊变量中的arg_开头的变量。即请求URL参数
 */
static ngx_int_t
ngx_http_variable_argument(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_str_t *name = (ngx_str_t *) data;

    u_char     *arg;
    size_t      len;
    ngx_str_t   value;

    len = name->len - (sizeof("arg_") - 1);
    arg = name->data + sizeof("arg_") - 1;

    if (len == 0 || ngx_http_arg(r, arg, len, &value) != NGX_OK) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = value.data;
    v->len = value.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


#if (NGX_HAVE_TCP_INFO)

static ngx_int_t
ngx_http_variable_tcpinfo(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    struct tcp_info  ti;
    socklen_t        len;
    uint32_t         value;

    len = sizeof(struct tcp_info);
    if (getsockopt(r->connection->fd, IPPROTO_TCP, TCP_INFO, &ti, &len) == -1) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ngx_pnalloc(r->pool, NGX_INT32_LEN);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    switch (data) {
    case 0:
        value = ti.tcpi_rtt;
        break;

    case 1:
        value = ti.tcpi_rttvar;
        break;

    case 2:
        value = ti.tcpi_snd_cwnd;
        break;

    case 3:
        value = ti.tcpi_rcv_space;
        break;

    /* suppress warning */
    default:
        value = 0;
        break;
    }

    v->len = ngx_sprintf(v->data, "%uD", value) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

#endif


static ngx_int_t
ngx_http_variable_content_length(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    if (r->headers_in.content_length) {
        v->len = r->headers_in.content_length->value.len;
        v->data = r->headers_in.content_length->value.data;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;

    } else if (r->reading_body) {
        v->not_found = 1;
        v->no_cacheable = 1;

    } else if (r->headers_in.content_length_n >= 0) {
        p = ngx_pnalloc(r->pool, NGX_OFF_T_LEN);
        if (p == NULL) {
            return NGX_ERROR;
        }

        v->len = ngx_sprintf(p, "%O", r->headers_in.content_length_n) - p;
        v->data = p;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;

    } else if (r->headers_in.chunked) {
        v->not_found = 1;
        v->no_cacheable = 1;

    } else {
        v->not_found = 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_host(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_core_srv_conf_t  *cscf;

    if (r->headers_in.server.len) {
        v->len = r->headers_in.server.len;
        v->data = r->headers_in.server.data;

    } else {
        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

        v->len = cscf->server_name.len;
        v->data = cscf->server_name.data;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_binary_remote_addr(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    switch (r->connection->sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;

        v->len = sizeof(struct in6_addr);
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = sin6->sin6_addr.s6_addr;

        break;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
    case AF_UNIX:

        v->len = r->connection->addr_text.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = r->connection->addr_text.data;

        break;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) r->connection->sockaddr;

        v->len = sizeof(in_addr_t);
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = (u_char *) &sin->sin_addr;

        break;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_remote_addr(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    v->len = r->connection->addr_text.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = r->connection->addr_text.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_remote_port(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_uint_t  port;

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = ngx_pnalloc(r->pool, sizeof("65535") - 1);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    port = ngx_inet_get_port(r->connection->sockaddr);

    if (port > 0 && port < 65536) {
        v->len = ngx_sprintf(v->data, "%ui", port) - v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_proxy_protocol_addr(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t             *addr;
    ngx_proxy_protocol_t  *pp;

    pp = r->connection->proxy_protocol;
    if (pp == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    addr = (ngx_str_t *) ((char *) pp + data);

    v->len = addr->len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = addr->data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_proxy_protocol_port(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_uint_t             port;
    ngx_proxy_protocol_t  *pp;

    pp = r->connection->proxy_protocol;
    if (pp == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = ngx_pnalloc(r->pool, sizeof("65535") - 1);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    port = *(in_port_t *) ((char *) pp + data);

    if (port > 0 && port < 65536) {
        v->len = ngx_sprintf(v->data, "%ui", port) - v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_proxy_protocol_tlv(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t *name = (ngx_str_t *) data;

    ngx_int_t  rc;
    ngx_str_t  tlv, value;

    tlv.len = name->len - (sizeof("proxy_protocol_tlv_") - 1);
    tlv.data = name->data + sizeof("proxy_protocol_tlv_") - 1;

    rc = ngx_proxy_protocol_get_tlv(r->connection, &tlv, &value);

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (rc == NGX_DECLINED) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = value.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = value.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_server_addr(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t  s;
    u_char     addr[NGX_SOCKADDR_STRLEN];

    s.len = NGX_SOCKADDR_STRLEN;
    s.data = addr;

    if (ngx_connection_local_sockaddr(r->connection, &s, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    s.data = ngx_pnalloc(r->pool, s.len);
    if (s.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(s.data, addr, s.len);

    v->len = s.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = s.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_server_port(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_uint_t  port;

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (ngx_connection_local_sockaddr(r->connection, NULL, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    v->data = ngx_pnalloc(r->pool, sizeof("65535") - 1);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    port = ngx_inet_get_port(r->connection->local_sockaddr);

    if (port > 0 && port < 65536) {
        v->len = ngx_sprintf(v->data, "%ui", port) - v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_scheme(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
#if (NGX_HTTP_SSL)

    if (r->connection->ssl) {
        v->len = sizeof("https") - 1;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = (u_char *) "https";

        return NGX_OK;
    }

#endif

    v->len = sizeof("http") - 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) "http";

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_https(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
#if (NGX_HTTP_SSL)

    if (r->connection->ssl) {
        v->len = sizeof("on") - 1;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = (u_char *) "on";

        return NGX_OK;
    }

#endif

    *v = ngx_http_variable_null_value;

    return NGX_OK;
}


static void
ngx_http_variable_set_args(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    r->args.len = v->len;
    r->args.data = v->data;
    r->valid_unparsed_uri = 0;
}


static ngx_int_t
ngx_http_variable_is_args(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    if (r->args.len == 0) {
        *v = ngx_http_variable_null_value;
        return NGX_OK;
    }

    v->len = 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) "?";

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_document_root(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t                  path;
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (clcf->root_lengths == NULL) {
        v->len = clcf->root.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = clcf->root.data;

    } else {
        if (ngx_http_script_run(r, &path, clcf->root_lengths->elts, 0,
                                clcf->root_values->elts)
            == NULL)
        {
            return NGX_ERROR;
        }

        if (ngx_get_full_name(r->pool, (ngx_str_t *) &ngx_cycle->prefix, &path)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        v->len = path.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = path.data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_realpath_root(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                    *real;
    size_t                     len;
    ngx_str_t                  path;
    ngx_http_core_loc_conf_t  *clcf;
#if (NGX_HAVE_MAX_PATH)
    u_char                     buffer[NGX_MAX_PATH];
#endif

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (clcf->root_lengths == NULL) {
        path = clcf->root;

    } else {
        if (ngx_http_script_run(r, &path, clcf->root_lengths->elts, 1,
                                clcf->root_values->elts)
            == NULL)
        {
            return NGX_ERROR;
        }

        path.data[path.len - 1] = '\0';

        if (ngx_get_full_name(r->pool, (ngx_str_t *) &ngx_cycle->prefix, &path)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

#if (NGX_HAVE_MAX_PATH)
    real = buffer;
#else
    real = NULL;
#endif

    real = ngx_realpath(path.data, real);

    if (real == NULL) {
        ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                      ngx_realpath_n " \"%s\" failed", path.data);
        return NGX_ERROR;
    }

    len = ngx_strlen(real);

    v->data = ngx_pnalloc(r->pool, len);
    if (v->data == NULL) {
#if !(NGX_HAVE_MAX_PATH)
        ngx_free(real);
#endif
        return NGX_ERROR;
    }

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    ngx_memcpy(v->data, real, len);

#if !(NGX_HAVE_MAX_PATH)
    ngx_free(real);
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_request_filename(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    size_t     root;
    ngx_str_t  path;

    if (ngx_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
        return NGX_ERROR;
    }

    /* ngx_http_map_uri_to_path() allocates memory for terminating '\0' */

    v->len = path.len - 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = path.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_server_name(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_core_srv_conf_t  *cscf;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    v->len = cscf->server_name.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = cscf->server_name.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_request_method(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    if (r->main->method_name.data) {
        v->len = r->main->method_name.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = r->main->method_name.data;

    } else {
        v->not_found = 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_remote_user(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_int_t  rc;

    rc = ngx_http_auth_basic_user(r);

    if (rc == NGX_DECLINED) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    v->len = r->headers_in.user.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = r->headers_in.user.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_bytes_sent(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = ngx_pnalloc(r->pool, NGX_OFF_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%O", r->connection->sent) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_body_bytes_sent(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    off_t    sent;
    u_char  *p;

    sent = r->connection->sent - r->header_size;

    if (sent < 0) {
        sent = 0;
    }

    p = ngx_pnalloc(r->pool, NGX_OFF_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%O", sent) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_pipe(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    v->data = (u_char *) (r->pipeline ? "p" : ".");
    v->len = 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_status(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_uint_t  status;

    v->data = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    if (r->err_status) {
        status = r->err_status;

    } else if (r->headers_out.status) {
        status = r->headers_out.status;

    } else if (r->http_version == NGX_HTTP_VERSION_9) {
        status = 9;

    } else {
        status = 0;
    }

    v->len = ngx_sprintf(v->data, "%03ui", status) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_sent_content_type(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    if (r->headers_out.content_type.len) {
        v->len = r->headers_out.content_type.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = r->headers_out.content_type.data;

    } else {
        v->not_found = 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_sent_content_length(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    if (r->headers_out.content_length) {
        v->len = r->headers_out.content_length->value.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = r->headers_out.content_length->value.data;

        return NGX_OK;
    }

    if (r->headers_out.content_length_n >= 0) {
        p = ngx_pnalloc(r->pool, NGX_OFF_T_LEN);
        if (p == NULL) {
            return NGX_ERROR;
        }

        v->len = ngx_sprintf(p, "%O", r->headers_out.content_length_n) - p;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = p;

        return NGX_OK;
    }

    v->not_found = 1;

    return NGX_OK;
}


/**
 * 解析变量 $sent_http_location
 */
static ngx_int_t
ngx_http_variable_sent_location(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t  name;

    if (r->headers_out.location) {      //如果headers_out中已经有值了
        v->len = r->headers_out.location->value.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = r->headers_out.location->value.data;

        return NGX_OK;
    }

    ngx_str_set(&name, "sent_http_location");

    return ngx_http_variable_unknown_header(r, v, &name,
                                            &r->headers_out.headers.part,
                                            sizeof("sent_http_") - 1);
}


/**
 * 解析变量 $sent_http_last_modified
 */
static ngx_int_t
ngx_http_variable_sent_last_modified(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    //1. 如果headers_out.last_modified中有值
    if (r->headers_out.last_modified) {
        v->len = r->headers_out.last_modified->value.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = r->headers_out.last_modified->value.data;

        return NGX_OK;
    }

    //2. 如果headers_out.last_modified_time中有值
    if (r->headers_out.last_modified_time >= 0) {
        p = ngx_pnalloc(r->pool, sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1);
        if (p == NULL) {
            return NGX_ERROR;
        }

        v->len = ngx_http_time(p, r->headers_out.last_modified_time) - p;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = p;

        return NGX_OK;
    }

    //3. 未找到
    v->not_found = 1;

    return NGX_OK;
}


/**
 * 解析变量 $sent_http_connection
 */
static ngx_int_t
ngx_http_variable_sent_connection(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    size_t   len;
    char    *p;

    if (r->headers_out.status == NGX_HTTP_SWITCHING_PROTOCOLS) {    //101状态码
        len = sizeof("upgrade") - 1;
        p = "upgrade";

    } else if (r->keepalive) {      //如果需要保持连接
        len = sizeof("keep-alive") - 1;
        p = "keep-alive";

    } else {                        //否则为close
        len = sizeof("close") - 1;
        p = "close";
    }

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) p;

    return NGX_OK;
}


/**
 * 解析变量 $sent_http_keep_alive
 */
static ngx_int_t
ngx_http_variable_sent_keep_alive(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                    *p;
    ngx_http_core_loc_conf_t  *clcf;

    if (r->keepalive) {     //如果需要保持连接
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        //使用配置值： https://nginx.org/en/docs/http/ngx_http_core_module.html#keepalive_timeout 
        if (clcf->keepalive_header) {

            p = ngx_pnalloc(r->pool, sizeof("timeout=") - 1 + NGX_TIME_T_LEN);
            if (p == NULL) {
                return NGX_ERROR;
            }

            v->len = ngx_sprintf(p, "timeout=%T", clcf->keepalive_header) - p;
            v->valid = 1;
            v->no_cacheable = 0;
            v->not_found = 0;
            v->data = p;

            return NGX_OK;
        }
    }

    v->not_found = 1;

    return NGX_OK;
}


/**
 * 解析变量 $sent_http_transfer_encoding
 */
static ngx_int_t
ngx_http_variable_sent_transfer_encoding(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    if (r->chunked) {       //如果请求为chunked
        v->len = sizeof("chunked") - 1;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = (u_char *) "chunked";

    } else {
        v->not_found = 1;
    }

    return NGX_OK;
}


/**
 * 变量$limit_rate 的set_handler
 */
static void
ngx_http_variable_set_limit_rate(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ssize_t    s;
    ngx_str_t  val;

    val.len = v->len;
    val.data = v->data;

    s = ngx_parse_size(&val);

    if (s == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "invalid $limit_rate \"%V\"", &val);
        return;
    }

    r->limit_rate = s;
    r->limit_rate_set = 1;
}


/**
 * 解析变量 $request_completion
 */
static ngx_int_t
ngx_http_variable_request_completion(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    if (r->request_complete) {
        v->len = 2;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = (u_char *) "OK";

        return NGX_OK;
    }

    *v = ngx_http_variable_null_value;

    return NGX_OK;
}


/**
 * 解析变量$request_body
 * 将r->request_body->bufs数据返回
 */
static ngx_int_t
ngx_http_variable_request_body(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char       *p;
    size_t        len;
    ngx_buf_t    *buf;
    ngx_chain_t  *cl;

    if (r->request_body == NULL
        || r->request_body->bufs == NULL
        || r->request_body->temp_file)      //如果请求被缓存到文件里了，直接返回NULL
    {
        v->not_found = 1;

        return NGX_OK;
    }

    cl = r->request_body->bufs;
    buf = cl->buf;

    if (cl->next == NULL) {     //只有一个buf
        v->len = buf->last - buf->pos;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = buf->pos;

        return NGX_OK;
    }

    //计算请求体长度
    len = buf->last - buf->pos;
    cl = cl->next;

    for ( /* void */ ; cl; cl = cl->next) {
        buf = cl->buf;
        len += buf->last - buf->pos;
    }

    //分配内存
    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->data = p;
    cl = r->request_body->bufs;

    //复制r->request_body->bufs链表
    for ( /* void */ ; cl; cl = cl->next) {
        buf = cl->buf;
        p = ngx_cpymem(p, buf->pos, buf->last - buf->pos);
    }

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


/**
 * 解析变量 $request_body_file
 */
static ngx_int_t
ngx_http_variable_request_body_file(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    //如果请求体不在本地文件中，直接返回NULL
    if (r->request_body == NULL || r->request_body->temp_file == NULL) {
        v->not_found = 1;

        return NGX_OK;
    }

    //返回文件名
    v->len = r->request_body->temp_file->file.name.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = r->request_body->temp_file->file.name.data;

    return NGX_OK;
}


/**
 * 解析变量 $request_length
 */
static ngx_int_t
ngx_http_variable_request_length(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = ngx_pnalloc(r->pool, NGX_OFF_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    //直接返回 r->request_length
    v->len = ngx_sprintf(p, "%O", r->request_length) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


/**
 * 解析变量 $request_time
 * 是请求已经处理了多长时间 （当前时间-请求开始处理时间）
 */
static ngx_int_t
ngx_http_variable_request_time(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char          *p;
    ngx_time_t      *tp;
    ngx_msec_int_t   ms;

    p = ngx_pnalloc(r->pool, NGX_TIME_T_LEN + 4);
    if (p == NULL) {
        return NGX_ERROR;
    }

    tp = ngx_timeofday();

    //当前时间-请求开始处理时间
    ms = (ngx_msec_int_t)
             ((tp->sec - r->start_sec) * 1000 + (tp->msec - r->start_msec));
    ms = ngx_max(ms, 0);

    v->len = ngx_sprintf(p, "%T.%03M", (time_t) ms / 1000, ms % 1000) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


/**
 * 解析变量 $request_id
 * 
 * 是nginx随机生成的一个32位字符串
 */
static ngx_int_t
ngx_http_variable_request_id(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char  *id;

#if (NGX_OPENSSL)
    u_char   random_bytes[16];
#endif

    id = ngx_pnalloc(r->pool, 32);      //32字节长度
    if (id == NULL) {
        return NGX_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->len = 32;
    v->data = id;

#if (NGX_OPENSSL)

    if (RAND_bytes(random_bytes, 16) == 1) {
        ngx_hex_dump(id, random_bytes, 16);
        return NGX_OK;
    }

    ngx_ssl_error(NGX_LOG_ERR, r->connection->log, 0, "RAND_bytes() failed");

#endif

    ngx_sprintf(id, "%08xD%08xD%08xD%08xD",
                (uint32_t) ngx_random(), (uint32_t) ngx_random(),
                (uint32_t) ngx_random(), (uint32_t) ngx_random());

    return NGX_OK;
}


/**
 * 解析变量 $connection
 * 为 r->connection->number
 */
static ngx_int_t
ngx_http_variable_connection(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = ngx_pnalloc(r->pool, NGX_ATOMIC_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%uA", r->connection->number) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


/**
 * 解析变量 $connection_requests
 * 为 r->connection->requests
 */
static ngx_int_t
ngx_http_variable_connection_requests(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%ui", r->connection->requests) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_connection_time(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char          *p;
    ngx_msec_int_t   ms;

    p = ngx_pnalloc(r->pool, NGX_TIME_T_LEN + 4);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ms = ngx_current_msec - r->connection->start_time;
    ms = ngx_max(ms, 0);

    v->len = ngx_sprintf(p, "%T.%03M", (time_t) ms / 1000, ms % 1000) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_nginx_version(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    v->len = sizeof(NGINX_VERSION) - 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) NGINX_VERSION;

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_hostname(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    v->len = ngx_cycle->hostname.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ngx_cycle->hostname.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_pid(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = ngx_pnalloc(r->pool, NGX_INT64_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%P", ngx_pid) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_msec(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char      *p;
    ngx_time_t  *tp;

    p = ngx_pnalloc(r->pool, NGX_TIME_T_LEN + 4);
    if (p == NULL) {
        return NGX_ERROR;
    }

    tp = ngx_timeofday();

    v->len = ngx_sprintf(p, "%T.%03M", tp->sec, tp->msec) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_time_iso8601(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = ngx_pnalloc(r->pool, ngx_cached_http_log_iso8601.len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(p, ngx_cached_http_log_iso8601.data,
               ngx_cached_http_log_iso8601.len);

    v->len = ngx_cached_http_log_iso8601.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_time_local(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = ngx_pnalloc(r->pool, ngx_cached_http_log_time.len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(p, ngx_cached_http_log_time.data, ngx_cached_http_log_time.len);

    v->len = ngx_cached_http_log_time.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


void *
ngx_http_map_find(ngx_http_request_t *r, ngx_http_map_t *map, ngx_str_t *match)
{
    void        *value;
    u_char      *low;
    size_t       len;
    ngx_uint_t   key;

    len = match->len;

    if (len) {
        low = ngx_pnalloc(r->pool, len);
        if (low == NULL) {
            return NULL;
        }

    } else {
        low = NULL;
    }

    key = ngx_hash_strlow(low, match->data, len);

    value = ngx_hash_find_combined(&map->hash, key, low, len);
    if (value) {
        return value;
    }

#if (NGX_PCRE)

    if (len && map->nregex) {
        ngx_int_t              n;
        ngx_uint_t             i;
        ngx_http_map_regex_t  *reg;

        reg = map->regex;

        for (i = 0; i < map->nregex; i++) {

            n = ngx_http_regex_exec(r, reg[i].regex, match);

            if (n == NGX_OK) {
                return reg[i].value;
            }

            if (n == NGX_DECLINED) {
                continue;
            }

            /* NGX_ERROR */

            return NULL;
        }
    }

#endif

    return NULL;
}


#if (NGX_PCRE)

static ngx_int_t
ngx_http_variable_not_found(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    v->not_found = 1;
    return NGX_OK;
}


ngx_http_regex_t *
ngx_http_regex_compile(ngx_conf_t *cf, ngx_regex_compile_t *rc)
{
    u_char                     *p;
    size_t                      size;
    ngx_str_t                   name;
    ngx_uint_t                  i, n;
    ngx_http_variable_t        *v;
    ngx_http_regex_t           *re;
    ngx_http_regex_variable_t  *rv;
    ngx_http_core_main_conf_t  *cmcf;

    rc->pool = cf->pool;

    if (ngx_regex_compile(rc) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc->err);
        return NULL;
    }

    re = ngx_pcalloc(cf->pool, sizeof(ngx_http_regex_t));
    if (re == NULL) {
        return NULL;
    }

    re->regex = rc->regex;
    re->ncaptures = rc->captures;
    re->name = rc->pattern;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    cmcf->ncaptures = ngx_max(cmcf->ncaptures, re->ncaptures);

    n = (ngx_uint_t) rc->named_captures;

    if (n == 0) {
        return re;
    }

    rv = ngx_palloc(rc->pool, n * sizeof(ngx_http_regex_variable_t));
    if (rv == NULL) {
        return NULL;
    }

    re->variables = rv;
    re->nvariables = n;

    size = rc->name_size;
    p = rc->names;

    for (i = 0; i < n; i++) {
        rv[i].capture = 2 * ((p[0] << 8) + p[1]);

        name.data = &p[2];
        name.len = ngx_strlen(name.data);

        v = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_CHANGEABLE);
        if (v == NULL) {
            return NULL;
        }

        rv[i].index = ngx_http_get_variable_index(cf, &name);
        if (rv[i].index == NGX_ERROR) {
            return NULL;
        }

        v->get_handler = ngx_http_variable_not_found;

        p += size;
    }

    return re;
}


ngx_int_t
ngx_http_regex_exec(ngx_http_request_t *r, ngx_http_regex_t *re, ngx_str_t *s)
{
    ngx_int_t                   rc, index;
    ngx_uint_t                  i, n, len;
    ngx_http_variable_value_t  *vv;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    if (re->ncaptures) {
        len = cmcf->ncaptures;

        if (r->captures == NULL || r->realloc_captures) {
            r->realloc_captures = 0;

            r->captures = ngx_palloc(r->pool, len * sizeof(int));
            if (r->captures == NULL) {
                return NGX_ERROR;
            }
        }

    } else {
        len = 0;
    }

    rc = ngx_regex_exec(re->regex, s, r->captures, len);

    if (rc == NGX_REGEX_NO_MATCHED) {
        return NGX_DECLINED;
    }

    if (rc < 0) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      ngx_regex_exec_n " failed: %i on \"%V\" using \"%V\"",
                      rc, s, &re->name);
        return NGX_ERROR;
    }

    for (i = 0; i < re->nvariables; i++) {

        n = re->variables[i].capture;
        index = re->variables[i].index;
        vv = &r->variables[index];

        vv->len = r->captures[n + 1] - r->captures[n];
        vv->valid = 1;
        vv->no_cacheable = 0;
        vv->not_found = 0;
        vv->data = &s->data[r->captures[n]];

#if (NGX_DEBUG)
        {
        ngx_http_variable_t  *v;

        v = cmcf->variables.elts;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http regex set $%V to \"%v\"", &v[index].name, vv);
        }
#endif
    }

    r->ncaptures = rc * 2;
    r->captures_data = s->data;

    return NGX_OK;
}

#endif


/**
 * 把用于存放变量的结构体初始化，再将Nginx核心变量加入准备hash的数组variables_keys中
 * 
 * 调用ngx_http_add_variable方法将ngx_http_core_variables数组里的所有核心变量 注册至Nginx框架
 * 
 * http://nginx.org/cn/docs/http/ngx_http_core_module.html#variables
 */
ngx_int_t
ngx_http_variables_add_core_vars(ngx_conf_t *cf)
{
    ngx_http_variable_t        *cv, *v;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    //创建ngx_hash_keys_arrays_t
    cmcf->variables_keys = ngx_pcalloc(cf->temp_pool,
                                       sizeof(ngx_hash_keys_arrays_t));
    if (cmcf->variables_keys == NULL) {
        return NGX_ERROR;
    }

    cmcf->variables_keys->pool = cf->pool;
    cmcf->variables_keys->temp_pool = cf->pool;

    //初始化 ngx_hash_keys_arrays_t cmcf->variables_keys
    if (ngx_hash_keys_array_init(cmcf->variables_keys, NGX_HASH_SMALL)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    //初始化动态数组 &cmcf->prefix_variables,
    if (ngx_array_init(&cmcf->prefix_variables, cf->pool, 8,
                       sizeof(ngx_http_variable_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    //遍历ngx_http_core_variables， 将其注册到nginx框架中
    for (cv = ngx_http_core_variables; cv->name.len; cv++) {
        v = ngx_http_add_variable(cf, &cv->name, cv->flags);
        if (v == NULL) {
            return NGX_ERROR;
        }

        *v = *cv;
    }

    return NGX_OK;
}


/**
 * 确认变量名是否合法（使用变量的是否存在、）
 * 初始化HTTP变量, 这一方法主要包括3个子步骤:
 * 1）一个变量是否进行索引，应该由使用它的模块决定，而不是由定义它的模块决定。
 *    这样就可能带来冲突，如果使用模块索引了一个变量，其实却没有其他模块定义它怎么办？或者说，有模块定义了它，
 *    但是这个模块没有编译进Nginx怎么办？所以，ngx_http_variables_init_vars方法首先要确保索引了的变量都是合法的：索引过的变量必须是定义过的；
 *    其次，使用索引变量的模块只知道索引某个变量名，此时需要把相应的变量值解析方法等属性也设置好
 * 2）对于部分变量名不明确的，这样的请求Nginx总结为5类，它们仅需要5个固定的解析变量方法即可，而每类中的变量名是不确定的，由使用变量的模块决定。
 *    这5类变量都由HTTP框架定义，而要求使用它们的模块必须在变量名中强制定义前缀为http_、sent_http_、upstream_http_、cookie_或者 arg_。
 * 3）定义变量的模块是希望变量可以被快速访问的，然而，它不能寄希望于变量被索引，因为是否索引是使用变量模块的权力！
 *    于是定义的变量就需要被hash为散列表来加速访问。另一个问题是5.2步的5类名字不明确的HTTP变量怎么办？
 *    只有使用变量的模块才知道明确的变量名，定义它们的ngx_http_core_module模块不知道变量名就无法按照变量名hash成散列表。
 *    所以这一步构造散列表，将除表15-1的5类变量以外的、没有显式设置不要hash的变量生成到一个静态的开散列表中
 */
ngx_int_t
ngx_http_variables_init_vars(ngx_conf_t *cf)
{
    size_t                      len;
    ngx_uint_t                  i, n;
    ngx_hash_key_t             *key;
    ngx_hash_init_t             hash;
    ngx_http_variable_t        *v, *av, *pv;
    ngx_http_core_main_conf_t  *cmcf;

    /* set the handlers for the indexed http variables */

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    v = cmcf->variables.elts;       //索引变量
    pv = cmcf->prefix_variables.elts;   //带前缀的变量
    key = cmcf->variables_keys->keys.elts;  //哈希变量

    //遍历所有索引变量，从cmcf->variables_keys->keys 中找到相同名称的，赋值其 get_handler、flags、data等字段
    for (i = 0; i < cmcf->variables.nelts; i++) {

        for (n = 0; n < cmcf->variables_keys->keys.nelts; n++) {

            av = key[n].value;

            if (v[i].name.len == key[n].key.len
                && ngx_strncmp(v[i].name.data, key[n].key.data, v[i].name.len)
                   == 0)
            {       //找到相同名称
                v[i].get_handler = av->get_handler;
                v[i].data = av->data;

                av->flags |= NGX_HTTP_VAR_INDEXED;      //添加INDEXED表示
                v[i].flags = av->flags;

                av->index = i;                      //index值

                if (av->get_handler == NULL
                    || (av->flags & NGX_HTTP_VAR_WEAK))
                {
                    break;      //
                }

                goto next;      //OK, i+1
            }
        }

        len = 0;
        av = NULL;

        //从前缀变量中查找
        for (n = 0; n < cmcf->prefix_variables.nelts; n++) {
            if (v[i].name.len >= pv[n].name.len && v[i].name.len > len
                && ngx_strncmp(v[i].name.data, pv[n].name.data, pv[n].name.len)
                   == 0)
            {
                av = &pv[n];
                len = pv[n].name.len;
            }
        }

        if (av) {
            v[i].get_handler = av->get_handler;
            v[i].data = (uintptr_t) &v[i].name;
            v[i].flags = av->flags;

            goto next;          //OK
        }

        //get_handler 不能为NULL
        if (v[i].get_handler == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "unknown \"%V\" variable", &v[i].name);

            return NGX_ERROR;
        }

    next:
        continue;
    }


    for (n = 0; n < cmcf->variables_keys->keys.nelts; n++) {
        av = key[n].value;

        if (av->flags & NGX_HTTP_VAR_NOHASH) {
            key[n].key.data = NULL;
        }
    }


    //初始化cmcf->variables_hash 哈希表
    hash.hash = &cmcf->variables_hash;
    hash.key = ngx_hash_key;
    hash.max_size = cmcf->variables_hash_max_size;
    hash.bucket_size = cmcf->variables_hash_bucket_size;
    hash.name = "variables_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (ngx_hash_init(&hash, cmcf->variables_keys->keys.elts,
                      cmcf->variables_keys->keys.nelts)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    //不再使用，置NULL
    cmcf->variables_keys = NULL;

    return NGX_OK;
}
