
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_INET_H_INCLUDED_
#define _NGX_INET_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_INET_ADDRSTRLEN   (sizeof("255.255.255.255") - 1)
#define NGX_INET6_ADDRSTRLEN                                                 \
    (sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255") - 1)
#define NGX_UNIX_ADDRSTRLEN                                                  \
    (sizeof("unix:") - 1 +                                                   \
     sizeof(struct sockaddr_un) - offsetof(struct sockaddr_un, sun_path))

#if (NGX_HAVE_UNIX_DOMAIN)
#define NGX_SOCKADDR_STRLEN   NGX_UNIX_ADDRSTRLEN
#elif (NGX_HAVE_INET6)
#define NGX_SOCKADDR_STRLEN   (NGX_INET6_ADDRSTRLEN + sizeof("[]:65535") - 1)
#else
#define NGX_SOCKADDR_STRLEN   (NGX_INET_ADDRSTRLEN + sizeof(":65535") - 1)
#endif

/* compatibility */
#define NGX_SOCKADDRLEN       sizeof(ngx_sockaddr_t)


typedef union {
    struct sockaddr           sockaddr;
    struct sockaddr_in        sockaddr_in;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6       sockaddr_in6;
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
    struct sockaddr_un        sockaddr_un;
#endif
} ngx_sockaddr_t;


/**
 * 一个ipv4的cidr
 */
typedef struct {
    in_addr_t                 addr;     //无符号32位整数, 4 Bytes
    in_addr_t                 mask;     //子网掩码
} ngx_in_cidr_t;


#if (NGX_HAVE_INET6)

/**
 * 一个ipv6的cidr
 */
typedef struct {
    struct in6_addr           addr;     //无符号128位整数,  16 Bytes
    struct in6_addr           mask;     //子网掩码
} ngx_in6_cidr_t;

#endif


/**
 * 代表一个CIDR配置
 */
typedef struct {
    ngx_uint_t                family;   //AF_INET/AF_INET6/AF_UNIX
    union {
        ngx_in_cidr_t         in;       //ipv4 cidr
#if (NGX_HAVE_INET6)
        ngx_in6_cidr_t        in6;      //ipv6 cidr
#endif
    } u;
} ngx_cidr_t;


typedef struct {
    struct sockaddr          *sockaddr;
    socklen_t                 socklen;
    ngx_str_t                 name;
} ngx_addr_t;


/**
 * 表示一个url
 * 
 * 
 */
typedef struct {
    ngx_str_t                 url;          //原始url
    ngx_str_t                 host;         //host
    ngx_str_t                 port_text;    //端口字符串
    ngx_str_t                 uri;          // /及其之后的部分，包括args

    in_port_t                 port;         //数字格式端口
    in_port_t                 default_port; //当url中没有出现端口时的默认端口
    in_port_t                 last_port;
    int                       family;

    unsigned                  listen:1;
    unsigned                  uri_part:1;
    unsigned                  no_resolve:1;

    unsigned                  no_port:1;        //标识url中没有出现过端口
    unsigned                  wildcard:1;

    socklen_t                 socklen;
    ngx_sockaddr_t            sockaddr;

    ngx_addr_t               *addrs;            //是一个数组，表示域名解析出来的多个地址
    ngx_uint_t                naddrs;           //如果是一个域名，这个字段为域名解析出来的地址的个数

    char                     *err;
} ngx_url_t;


in_addr_t ngx_inet_addr(u_char *text, size_t len);
#if (NGX_HAVE_INET6)
ngx_int_t ngx_inet6_addr(u_char *p, size_t len, u_char *addr);
size_t ngx_inet6_ntop(u_char *p, u_char *text, size_t len);
#endif
size_t ngx_sock_ntop(struct sockaddr *sa, socklen_t socklen, u_char *text,
    size_t len, ngx_uint_t port);
size_t ngx_inet_ntop(int family, void *addr, u_char *text, size_t len);
ngx_int_t ngx_ptocidr(ngx_str_t *text, ngx_cidr_t *cidr);
ngx_int_t ngx_cidr_match(struct sockaddr *sa, ngx_array_t *cidrs);
ngx_int_t ngx_parse_addr(ngx_pool_t *pool, ngx_addr_t *addr, u_char *text,
    size_t len);
ngx_int_t ngx_parse_addr_port(ngx_pool_t *pool, ngx_addr_t *addr,
    u_char *text, size_t len);
ngx_int_t ngx_parse_url(ngx_pool_t *pool, ngx_url_t *u);
ngx_int_t ngx_inet_resolve_host(ngx_pool_t *pool, ngx_url_t *u);
ngx_int_t ngx_cmp_sockaddr(struct sockaddr *sa1, socklen_t slen1,
    struct sockaddr *sa2, socklen_t slen2, ngx_uint_t cmp_port);
in_port_t ngx_inet_get_port(struct sockaddr *sa);
void ngx_inet_set_port(struct sockaddr *sa, in_port_t port);
ngx_uint_t ngx_inet_wildcard(struct sockaddr *sa);


#endif /* _NGX_INET_H_INCLUDED_ */
