
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HASH_H_INCLUDED_
#define _NGX_HASH_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

//散列表中的元素
typedef struct {
    //指向用户自定义元素数据的指针，如果当前 ngx_hash_elt_t槽为空，则 value的值为 0
    void             *value;
    //元素关键字的长度
    u_short           len;
    //元素关键字的首地址
    u_char            name[1];
} ngx_hash_elt_t;

/**
 * buckets数组
 *        __________________________________
 *        |ngx_hash_elt_t|ngx_hash_elt_t|...|
 *        |value|len|name|value|len|name|...|
 * 
 * 共有size个buckets
 */
typedef struct {
    // 指向散列表的首地址，也是第 1个槽的地址
    ngx_hash_elt_t  **buckets;
    // 散列表中槽的总数， 数组的长度
    ngx_uint_t        size;
} ngx_hash_t;


typedef struct {
    ngx_hash_t        hash;  // 基本散列表        
    void             *value; //当使用这个 ngx_hash_wildcard_t通配符散列表作为某容器的元素时，可以使用这个value指针指向用户数据
} ngx_hash_wildcard_t;


// 初始化散列表的数组元素
// 存放的是key、对应的hash和值
typedef struct {
    ngx_str_t         key;      // 元素关键字
    ngx_uint_t        key_hash; // 由散列方法算出来的关键码
    void             *value;    // 指向实际的用户数据
} ngx_hash_key_t;

/**
 * 自定义key的散列方法，
 * data是元素关键字的首地址，
 * len是元素关键字的长度
 * 
 * 可以把任意的数 据结构强制转换为u_char*并传给ngx_hash_key_pt散列方法，从而决定返回什么样的散列整型关键码来使碰撞率降低
 * nginx提供两个内置：
        ngx_uint_t ngx_hash_key(u_char *data, size_t len);
        ngx_uint_t ngx_hash_key_lc(u_char *data, size_t len);
 * 
 */
typedef ngx_uint_t (*ngx_hash_key_pt) (u_char *data, size_t len);

/**
 * 支持简单通配符的散列表
 * 
 * 专门针对URI、域名支持前置或者后置的通 配符
 * 
 */
typedef struct {
    ngx_hash_t            hash;          // 精确匹配的散列表    
    ngx_hash_wildcard_t  *wc_head;      // 通配符在前面的散列表
    ngx_hash_wildcard_t  *wc_tail;      // 通配符在后面的散列表
} ngx_hash_combined_t;


// 初始化散列表的结构体
typedef struct {
     // 待初始化的散列表结构体 
    ngx_hash_t       *hash;
    // 散列函数
    // 通常是ngx_hash_key_lc
    ngx_hash_key_pt   key;

    // 散列表里的最大桶数量
    ngx_uint_t        max_size;

    // 桶的大小，即ngx_hash_elt_t加自定义数据,  它限制了每个散列表元素关键字的最大长度
    ngx_uint_t        bucket_size;

     // 待初始化的散列表结构体     // 散列表的名字，记录日志用
    char             *name;

    // 使用的内存池
    ngx_pool_t       *pool;

    // 临时用的内存池，它仅存在于初始化散列表之前。它主要用于分配一些临时的动态数组，
    //带通配符的元素在初始化时需要用到这些数组
    ngx_pool_t       *temp_pool;
} ngx_hash_init_t;


#define NGX_HASH_SMALL            1
#define NGX_HASH_LARGE            2

#define NGX_HASH_LARGE_ASIZE      16384
#define NGX_HASH_LARGE_HSIZE      10007

#define NGX_HASH_WILDCARD_KEY     1
#define NGX_HASH_READONLY_KEY     2


/**
 * 是使用ngx_hash_init或者ngx_hash_wildcard_init方法构造hash表的前提条件。
 * 
 * 先构造好了ngx_hash_keys_arrays_t 结构体，就可以非常简单地调用ngx_hash_init或者ngx_hash_wildcard_init方法来创建支持通配符的散列表
 * 
 * 3个动态数组容器keys、dns_wc_head、 dns_wc_tail会以ngx_hash_key_t结构体作为元素类型，
 * 分别保存完全匹配关键字、带前置通配 符的关键字、带后置通配符的关键字
 * 
 * 在使用ngx_hash_keys_array_init初始化ngx_hash_keys_arrays_t结构体后，就可以调用 ngx_hash_add_key方法向其加入散列表元素了。
 * 当添加元素成功后，再调用ngx_hash_init_t提供的两个初始化方法来创建散列表，这样得到的散列表就是完全可用的容器了
 * 
 * 
 */
typedef struct {
    //下面的 keys_hash、 dns_wc_head_hash、 dns_wc_tail_hash都是简易散列表，
    //而hsize指明了散列表的槽个数，其简易散列方法也需要对 hsize求余
    ngx_uint_t        hsize;

    //内存池，用于分配永久性内存,暂无意义
    ngx_pool_t       *pool;
    // 临时内存池，下面的动态数组需要的内存都由 temp_pool内存池分配
    ngx_pool_t       *temp_pool;

    // 用动态数组以 ngx_hash_key_t结构体保存着不含有通配符关键字的元素
    ngx_array_t       keys;
    //一个极其简易的散列表，它以数组的形式保存着 hsize个元素(槽位)，每个元素都是 ngx_array_t动态数组。
    //在用户添加的元素过程中，会根据用户的 ngx_str_t类型的关键字hash值添加到 ngx_array_t动态数组中。
    //这里所有的用户元素的关键字都不可以带通配符，表示精确匹配
    ngx_array_t      *keys_hash;

    //用动态数组以 ngx_hash_key_t结构体保存着含有前置通配符关键字的元素生成的中间关键字
    ngx_array_t       dns_wc_head;
    //一个极其简易的散列表，它以数组的形式保存着 hsize个元素，每个元素都是 ngx_array_t动态数组。在用户添加元素过程中，
    //会根据关键码将用户的 ngx_str_t类型的关键字添加到ngx_array_t动态数组中。这里所有的用户元素的关键字都带前置通配符
    ngx_array_t      *dns_wc_head_hash;

    //用动态数组以 ngx_hash_key_t结构体保存着含有后置通配符关键字的元素生成的中间关键字
    ngx_array_t       dns_wc_tail;
    //一个极其简易的散列表，它以数组的形式保存着 hsize个元素，每个元素都是 ngx_array_t动态数组。在用户添加元素过程中，
    //会根据关键码将用户的 ngx_str_t类型的关键字添加到 ngx_array_t动态数组中。这里所有的用户元素的关键字都带后置通配符
    ngx_array_t      *dns_wc_tail_hash;
} ngx_hash_keys_arrays_t;



typedef struct ngx_table_elt_s  ngx_table_elt_t;

/**
 * 专为存放http请求/响应头部的结构体
 * 
 * 键值对结构, 主要用来表示HTTP头部信息
 */
struct ngx_table_elt_s {
    ngx_uint_t        hash;     //hash, 0表示删除， 可以在ngx_hash_t中更快地找到相同key的 ngx_table_elt_t数据
    ngx_str_t         key;      //头部名称
    ngx_str_t         value;    //头部值
    u_char           *lowcase_key;  //小写的头部名称
    ngx_table_elt_t  *next;     //下一个元素
};


void *ngx_hash_find(ngx_hash_t *hash, ngx_uint_t key, u_char *name, size_t len);

void *ngx_hash_find_wc_head(ngx_hash_wildcard_t *hwc, u_char *name, size_t len);
void *ngx_hash_find_wc_tail(ngx_hash_wildcard_t *hwc, u_char *name, size_t len);
void *ngx_hash_find_combined(ngx_hash_combined_t *hash, ngx_uint_t key,
    u_char *name, size_t len);
// 初始化散列表hinit
// 输入一个ngx_hash_key_t数组，长度散nelts
ngx_int_t ngx_hash_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
    ngx_uint_t nelts);

// 初始化通配符散列表hinit
// 函数执行后把names数组里的元素放入散列表，可以hash查找
// Nginx散列表是只读的，初始化后不能修改，只能查找
ngx_int_t ngx_hash_wildcard_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
    ngx_uint_t nelts);

// 简单地对单个字符计算散列
#define ngx_hash(key, c)   ((ngx_uint_t) key * 31 + c)
// 计算散列值
ngx_uint_t ngx_hash_key(u_char *data, size_t len);
// 小写后再计算hash
ngx_uint_t ngx_hash_key_lc(u_char *data, size_t len);
// 小写化的同时计算出散列值
ngx_uint_t ngx_hash_strlow(u_char *dst, u_char *src, size_t n);


ngx_int_t ngx_hash_keys_array_init(ngx_hash_keys_arrays_t *ha, ngx_uint_t type);
ngx_int_t ngx_hash_add_key(ngx_hash_keys_arrays_t *ha, ngx_str_t *key,
    void *value, ngx_uint_t flags);


#endif /* _NGX_HASH_H_INCLUDED_ */
