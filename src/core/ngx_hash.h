
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HASH_H_INCLUDED_
#define _NGX_HASH_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


//同一个槽中的元素存放在连续的地址
//散列表中的元素， 多个elt元素在同一个槽中。 参考 ngx_hash_find 方法
//null表示在同一个槽中elt元素的结尾
typedef struct {
    //指向用户自定义元素数据的指针，如果当前 ngx_hash_elt_t槽为空，则 value的值为 0
    void             *value;     //指向value的指针
    //元素关键字的长度
    u_short           len;      //key的长度
    //元素关键字的首地址
    u_char            name[1]; //指向key的第一个地址，key长度为变长
} ngx_hash_elt_t;


/**
 * buckets数组
 *        ______________________________________________________________________
 *        |ngx_hash_elt_t                    |ngx_hash_elt_t                    |
 *        |value|len|name|null               |value|len|name|value|len|name|null|
 * 
 * 共有size个buckets,
 */
typedef struct {
    // 指向散列表槽数组的首地址，也是第 1个槽的地址。（是一个指针数组，每个元素指向索引对应槽的首地址，槽间以NULL指针进行分割）
    ngx_hash_elt_t  **buckets;
    // 散列表中槽的总数， 数组元素的个数
    ngx_uint_t        size;                 //elt = hash->buckets[key % hash->size];
} ngx_hash_t;


/**
 * nginx为了处理带有通配符的域名的匹配问题，实现了ngx_hash_wildcard_t这样的hash表。可以支持两种类型的带有通配符的域名。
 * 一种是通配符在前的，例如：“*.abc.com”，也可以省略掉星号，直接写成".abc.com"。
 * 这样的key，可以匹配www.abc.com，qqq.www.abc.com之类的。
 * 
 * 另一种是通配符在末尾的，例如："mail.xxx.*"，请特别注意通配符在末尾的不像位于开始的通配符可以被省略掉。
 * 这样的通配符，可以匹配mail.xxx.com、mail.xxx.com.cn、mail.xxx.net之类的域名。 
 * 
 * 注意，一个ngx_hash_wildcard_t类型的hash表只能包含通配符在前的key或者是通配符在后的key。不能同时包含两种类型的通配符的key。
 */
typedef struct {
    ngx_hash_t        hash;  // 基本散列表        
    void             *value; //当使用这个 ngx_hash_wildcard_t通配符散列表作为某容器的元素时，可以使用这个value指针指向用户数据
} ngx_hash_wildcard_t;


// 初始化散列表的数组元素
// 存放的是key、对应的hash和值
//在实际使用中，一般将多个键-值对保存在 ngx_hash_key_t 结构的数组中，作为参数传给ngx_hash_init()
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
 * 专门针对URI、域名支持前置或者后置的通配符
 * 
 * 该类型实际上包含了三个hash表，一个普通hash表，一个包含前向通配符的hash表和一个包含后向通配符的hash表
 * 
 * nginx提供该类型的作用，在于提供一个方便的容器包含三个类型的hash表，当有包含通配符的和不包含通配符的一组key构建hash表以后，
 * 以一种方便的方式来查询，你不需要再考虑一个key到底是应该到哪个类型的hash表里去查了
 * 
 * 对于该类型hash表的查询，nginx提供了一个方便的函数ngx_hash_find_combined
 * 
 */
typedef struct {
    ngx_hash_t            hash;         // 精确匹配的散列表    
    ngx_hash_wildcard_t  *wc_head;      // 通配符在前面的散列表
    ngx_hash_wildcard_t  *wc_tail;      // 通配符在后面的散列表
} ngx_hash_combined_t;


//散列表初始化方法：ngx_int_t ngx_hash_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names, ngx_uint_t nelts);
//用于 初始化散列表 的结构体， 构建散列表必须使用此结构体
typedef struct {
    // 待初始化的散列表结构体 
    /**
     * 该字段如果为NULL，那么调用完初始化韩式有，该字段指向新创建出来的hash表。
     * 如果该字段不为NULL，那么在初始的时候，所有的数据被插入了这个字段所指的hash表中。
     */
    ngx_hash_t       *hash; //出参
    ngx_hash_key_pt   key;  //计算key hash的函数，常用选项有ngx_hash_key和ngx_hash_key_lc

    /**
     * 散列表里的最大桶个数
     * 
     * 字段越大，元素存储时冲突的可能性越小，每个桶中存储的元素会更少，则查询起来的速度更快。
     * 当然，这个值越大，越造成内存的浪费，(实际上也浪费不了多少)
     */
    ngx_uint_t        max_size;

    // 桶的最大大小，即ngx_hash_elt_t加自定义数据,  它限制了每个散列表元素关键字的最大长度
    /**
     * 如果在初始化一个hash表的时候，发现某个桶里面无法存的下所有属于该桶的元素，则hash表初始化失败
     */
    ngx_uint_t        bucket_size;

    // 散列表的名字，记录日志用
    char             *name;

    // /内存池，它分配散列表（最多3个，包括1个普通散列表、1个前置通配符散列表、1个后置通配符散列表）中的所有槽
    ngx_pool_t       *pool;

    //临时用的内存池，它仅存在于初始化散列表之前。它主要用于分配一些临时的动态数组，
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
 * 与其相关的几个方法： 
 *  1.ngx_hash_keys_array_init 初始化本结构体
 *  2.ngx_hash_add_key 向本结构体加入散列元素
 *  3.ngx_hash_init 用于初始化和构建散列表 
 */
/**
 * 在构建一个ngx_hash_wildcard_t的时候，需要对通配符的哪些key进行预处理。这个处理起来比较麻烦。而当有一组key，
 * 这些里面既有无通配符的key，也有包含通配符的key的时候。我们就需要构建三个hash表，一个包含普通的key的hash表，
 * 一个包含前向通配符的hash表，一个包含后向通配符的hash表（或者也可以把这三个hash表组合成一个ngx_hash_combined_t）。
 * 在这种情况下，为了让大家方便的构造这些hash表，nginx提供给了此辅助类型。
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

    //用动态数组以 ngx_hash_key_t结构体保存着不含有通配符关键字的元素
    ngx_array_t       keys;
    //1.一个极其简易的散列表，它以数组的形式保存着 hsize个元素(槽位)，每个元素都是 ngx_array_t动态数组。
    //在用户添加的元素过程中，会根据用户的 ngx_str_t类型的关键字hash值添加到 ngx_array_t动态数组中。
    //这里所有的用户元素的关键字都不可以带通配符，表示精确匹配
    /**
     * 这是个二维数组，第一个维度代表的是bucket的编号，那么keys_hash[i]中存放的是所有的key算出来的hash值对hsize取模以后的值为i的key。
     * 假设有3个key,分别是key1,key2和key3假设hash值算出来以后对hsize取模的值都是i，那么这三个key的值就顺序存放在keys_hash[i][0],keys_hash[i][1], keys_hash[i][2]。
     * 该值在调用的过程中用来保存和检测是否有冲突的key值，也就是是否有重复
     */
    ngx_array_t      *keys_hash;

    //用动态数组以 ngx_hash_key_t结构体保存着含有前置通配符关键字的元素生成的中间关键字
    //放前向通配符key被处理完成以后的值。比如：“*.abc.com” 被处理完成以后，变成 “com.abc.” 被存放在此数组中
    ngx_array_t       dns_wc_head;
    //2.一个极其简易的散列表，它以数组的形式保存着 hsize个元素，每个元素都是 ngx_array_t动态数组。在用户添加元素过程中，
    //会根据关键码将用户的 ngx_str_t类型的关键字添加到ngx_array_t动态数组中。这里所有的用户元素的关键字都带前置通配符
    ngx_array_t      *dns_wc_head_hash; //该值在调用的过程中用来保存和检测是否有冲突的前向通配符的key值，也就是是否有重复。

    //用动态数组以 ngx_hash_key_t结构体保存着含有后置通配符关键字的元素生成的中间关键字
    //存放后向通配符key被处理完成以后的值。比如：“mail.xxx.*” 被处理完成以后，变成 “mail.xxx.” 被存放在此数组中。
    ngx_array_t       dns_wc_tail;
    //3.一个极其简易的散列表，它以数组的形式保存着 hsize个元素，每个元素都是 ngx_array_t动态数组。在用户添加元素过程中，
    //会根据关键码将用户的 ngx_str_t类型的关键字添加到 ngx_array_t动态数组中。这里所有的用户元素的关键字都带后置通配符
    ngx_array_t      *dns_wc_tail_hash; //该值在调用的过程中用来保存和检测是否有冲突的后向通配符的key值，也就是是否有重复。
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


/**
 * 用于从hash表中查询元素
 * hash是散列表结构体的指针
 * key则是根据散列方法算出来的散列关键字
 * name和len则表示实际关键字的地址与长度
 * 
 * 返回散列表中关键字与name、len指定关键字完全相同的槽中，ngx_hash_elt_t结构体中value成员所指向的用户数据
 */
void *ngx_hash_find(ngx_hash_t *hash, ngx_uint_t key, u_char *name, size_t len);


void *ngx_hash_find_wc_head(ngx_hash_wildcard_t *hwc, u_char *name, size_t len);
void *ngx_hash_find_wc_tail(ngx_hash_wildcard_t *hwc, u_char *name, size_t len);

/**
 * 带有通配符的key查询
 */
void *ngx_hash_find_combined(ngx_hash_combined_t *hash, ngx_uint_t key,
    u_char *name, size_t len);

// 初始化完全匹配散列表 hinit：为初始化结构体
// 输入一个代表KV的ngx_hash_key_t数组names，长度为nelts
ngx_int_t ngx_hash_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
    ngx_uint_t nelts);

// 初始化通配符散列表hinit
// 函数执行后把names数组里的元素放入散列表，可以hash查找
// Nginx散列表是只读的，初始化后不能修改，只能查找
/**
 * hint: 构造一个通配符hash表的一些参数的一个集合。关于该参数对应的类型的说明，请参见ngx_hash_t类型中ngx_hash_init函数的说明。
 * names: 构造此hash表的所有的通配符key的数组。特别要注意的是这里的key已经都是被预处理过的。
 *        例如：“*.abc.com”或者“.abc.com”被预处理完成以后，变成了“com.abc.”。而“mail.xxx.*”则被预处理为“mail.xxx.”。
 *        为什么会被处理这样？这里不得不简单地描述一下通配符hash表的实现原理。当构造此类型的hash表的时候，
 *        实际上是构造了一个hash表的一个“链表”，是通过hash表中的key“链接”起来的。比如：对于“*.abc.com”将会构造出2个hash表，
 *        第一个hash表中有一个key为com的表项，该表项的value包含有指向第二个hash表的指针，而第二个hash表中有一个表项abc，
 *        该表项的value包含有指向*.abc.com对应的value的指针。那么查询的时候，比如查询www.abc.com的时候，先查com，
 *        通过查com可以找到第二级的hash表，在第二级hash表中，再查找abc，依次类推，
 *        直到在某一级的hash表中查到的表项对应的value对应一个真正的值而非一个指向下一级hash表的指针的时候，查询过程结束。
 *        这里有一点需要特别注意的，就是names数组中元素的value所对应的值（也就是真正的value所在的地址）必须是能被4整除的，
 *        或者说是在4的倍数的地址上是对齐的。因为这个value的值的低两位bit是有用的，所以必须为0。如果不满足这个条件，
 *        这个hash表查询不出正确结果。
 * nelts: names数组元素的个数。
 */
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


/**
 * 初始化 ngx_hash_keys_arrays_t结构，向ha中添加元素前，必须先调用此方法
 * type取值：NGX_HASH_SMALL NGX_HASH_LARGE， 标识初始化元素的多少
 */
ngx_int_t ngx_hash_keys_array_init(ngx_hash_keys_arrays_t *ha, ngx_uint_t type);
/**
 *  向ha中添加一个元素
 *  key是要添加的关键字
 *  value是key关键字对应的用户数据的指针
 */
ngx_int_t ngx_hash_add_key(ngx_hash_keys_arrays_t *ha, ngx_str_t *key,
    void *value, ngx_uint_t flags);


#endif /* _NGX_HASH_H_INCLUDED_ */
