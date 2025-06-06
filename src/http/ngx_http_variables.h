
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_VARIABLES_H_INCLUDED_
#define _NGX_HTTP_VARIABLES_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef ngx_variable_value_t  ngx_http_variable_value_t;

#define ngx_http_variable(v)     { sizeof(v) - 1, 1, 0, 0, 0, (u_char *) v }

typedef struct ngx_http_variable_s  ngx_http_variable_t;

/**
 * ngx_http_set_variable_pt 和ngx_http_get_variable_pt 分别是变量的set和get的handler， 都接收3个参数：
 * r: 表示请求
 * v: 表示变量值
 * data: 定义变量名的ngx_http_variable_t结构体中的data成员
 *  1）不起作用， 生成一些和用户请求无关的变量值，例如当前时间、系统负载、磁盘状况等
 *  2）为指针，指向变量名。 例如http_或者sent_http_，实际上每一个这样的变量其解析方法都大同小异，
 *     遍历解析出来的r->headers_in.headers或者r->headers_in.headers数组，找到变量名再返回其值即可
 *  3）为序列化内存的相对偏移量使用。指向已经解析出来的变量： offsetof(ngx_http_request_t, headers_in.user_agent)
 * 
 */
typedef void (*ngx_http_set_variable_pt) (ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
typedef ngx_int_t (*ngx_http_get_variable_pt) (ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);


#define NGX_HTTP_VAR_CHANGEABLE   1
#define NGX_HTTP_VAR_NOCACHEABLE  2
#define NGX_HTTP_VAR_INDEXED      4
#define NGX_HTTP_VAR_NOHASH       8
#define NGX_HTTP_VAR_WEAK         16
#define NGX_HTTP_VAR_PREFIX       32

/**
 * 保存变量名的结构体
 * 负责指定一个变量名字符串，以及如何去解析出相应的变量值
 * 
 * 所有 的变量名定义ngx_http_variable_t都会保存在全局唯一的ngx_http_core_main_conf_t对象中
 */
struct ngx_http_variable_s {
    // name就是字符串变量名，例如 nginx.conf中常见的 $remote_addr这样的字符串，不包括$符号
    ngx_str_t                     name;   /* must be first to build the hash */
    // 如果需要变量最初赋值时就进行变量值的设置，那么可以实现 set_handler方法。如果我们定义的
    // 内部变量允许在 nginx.conf中以 set方式又重新设置其值，那么可以实现该方法（参考 args参数， 
    // 它就是一个内部变量，同时也允许 set方式在 nginx.conf里重新设置其值），
    ngx_http_set_variable_pt      set_handler;

    // 每次获取一个变量的值时，会先调用 get_handler方法，所以 Nginx的官方模块变量的解析大都在此方法中完成
    ngx_http_get_variable_pt      get_handler;
    // 这个整数是作为参数传递给get_handler、 set_handler回调方法使用
    uintptr_t                     data;

    /**
     * #define NGX_HTTP_VAR_CHANGEABLE   1      表示变量可变
     * #define NGX_HTTP_VAR_NOCACHEABLE  2      不要缓存值，每次使用变量都重新解析。
     * #define NGX_HTTP_VAR_INDEXED      4      将变量索引，加速访问
     * #define NGX_HTTP_VAR_NOHASH       8      不加入hash, 如只通过索引访问的变量
     */
    ngx_uint_t                    flags;
    // 这个数字也就是变量值在请求中的缓存数组中的索引
    ngx_uint_t                    index;
};

#define ngx_http_null_variable  { ngx_null_string, NULL, NULL, 0, 0, 0 }


ngx_http_variable_t *ngx_http_add_variable(ngx_conf_t *cf, ngx_str_t *name,
    ngx_uint_t flags);
ngx_int_t ngx_http_get_variable_index(ngx_conf_t *cf, ngx_str_t *name);
ngx_http_variable_value_t *ngx_http_get_indexed_variable(ngx_http_request_t *r,
    ngx_uint_t index);
ngx_http_variable_value_t *ngx_http_get_flushed_variable(ngx_http_request_t *r,
    ngx_uint_t index);

ngx_http_variable_value_t *ngx_http_get_variable(ngx_http_request_t *r,
    ngx_str_t *name, ngx_uint_t key);

ngx_int_t ngx_http_variable_unknown_header(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_str_t *var, ngx_list_part_t *part,
    size_t prefix);


#if (NGX_PCRE)

typedef struct {
    ngx_uint_t                    capture;
    ngx_int_t                     index;
} ngx_http_regex_variable_t;


typedef struct {
    ngx_regex_t                  *regex;
    ngx_uint_t                    ncaptures;
    ngx_http_regex_variable_t    *variables;
    ngx_uint_t                    nvariables;
    ngx_str_t                     name;
} ngx_http_regex_t;


typedef struct {
    ngx_http_regex_t             *regex;
    void                         *value;
} ngx_http_map_regex_t;


ngx_http_regex_t *ngx_http_regex_compile(ngx_conf_t *cf,
    ngx_regex_compile_t *rc);
ngx_int_t ngx_http_regex_exec(ngx_http_request_t *r, ngx_http_regex_t *re,
    ngx_str_t *s);

#endif


typedef struct {
    ngx_hash_combined_t           hash;
#if (NGX_PCRE)
    ngx_http_map_regex_t         *regex;
    ngx_uint_t                    nregex;
#endif
} ngx_http_map_t;


void *ngx_http_map_find(ngx_http_request_t *r, ngx_http_map_t *map,
    ngx_str_t *match);


ngx_int_t ngx_http_variables_add_core_vars(ngx_conf_t *cf);
ngx_int_t ngx_http_variables_init_vars(ngx_conf_t *cf);


extern ngx_http_variable_value_t  ngx_http_variable_null_value;
extern ngx_http_variable_value_t  ngx_http_variable_true_value;


#endif /* _NGX_HTTP_VARIABLES_H_INCLUDED_ */
