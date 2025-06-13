#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/**
 * 
 * struct ngx_rbtree_node_s {
    ngx_rbtree_key_t       key;     // 无符号整型的关键字
    ngx_rbtree_node_t     *left;    // 左子节点
    ngx_rbtree_node_t     *right;   // 右子节点
    ngx_rbtree_node_t     *parent;  // 父节点
    u_char                 color;   // 节点的颜色， 0表示黑色， 1表示红色
    u_char                 data;    // 仅 1个字节的节点数据。由于表示的空间太小，所以一般很少使用
    };

    可以接着ngx_rbtree_node_t的color成员之后（覆盖data成员），开始定义我们的结构体 ngx_http_testslab_node_t
 * 
 */

 //ngx_http_testslab_node_t上接ngx_rbtree_node_t、下接变长字符串. 代表红黑树的节点和value
typedef struct {
    //其实就是ngx_rbtree_node_s的data成员
    u_char rbtree_node_data;   // 对应于 ngx_rbtree_node_t最后一个 data成员
    ngx_queue_t queue;         // 按先后顺序把所有访问结点串起，方便淘汰过期结点

    ngx_msec_t last;        // 上一次成功访问该URL的时间，精确到毫秒

    u_short len;            // 客户端IP地址与URL组合而成的字符串长度

    u_char data[1];         // 以字符串保存客户端IP地址与URL

} ngx_http_testslab_node_t;

// ngx_http_testslab_shm_t保存在共享内存中
typedef struct {
    ngx_rbtree_t rbtree;    // 红黑树用于快速检索

    ngx_rbtree_node_t sentinel;     // 使用 Nginx红黑树必须定义的哨兵结点

    ngx_queue_t queue;  // 所有操作记录构成的淘汰链表
} ngx_http_testslab_shm_t;


//ngx_http_testslab_conf_t不是放在共享内存中的, 模块的配置结构
typedef struct
{
    ssize_t shmsize;        // 共享内存大小

    ngx_int_t interval;    // 两次成功访问所必须间隔的时间

    ngx_slab_pool_t *shpool;    // 操作共享内存一定需要 ngx_slab_pool_t结构体, 这个结构体也在共享内存中

    ngx_http_testslab_shm_t *sh;    // 指向共享内存中的 ngx_http_testslab_shm_t结构体
} ngx_http_testslab_conf_t;

static ngx_int_t
ngx_http_testslab_handler(ngx_http_request_t *r);

static char 
*ngx_http_testslab_createmem(ngx_conf_t *cf, ngx_conf_t *cmd, void *conf);

static ngx_int_t 
ngx_http_testslab_init(ngx_conf_t *cf);

static void 
*ngx_http_testslab_create_main_conf(ngx_conf_t *cf);

static ngx_command_t ngx_http_testslab_commands[] =
{
    {
        ngx_string("test_slab"),
        // 仅支持在 http块下配置 test_slab配置项
        // 必须携带 2个参数，前者为两次成功访问同一URL时的最小间隔秒数, 后者为共享内存的大小
        NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE2,
        ngx_http_testslab_createmem,
        0,
        0,
        NULL
    },
    ngx_null_command
};


static ngx_http_module_t ngx_http_testslab_module_ctx =
    {
        NULL,                   /* preconfiguration */
        ngx_http_testslab_init, /* postconfiguration */

        ngx_http_testslab_create_main_conf, /* create main configuration */
        NULL,                               /* init main configuration */

        NULL, /* create server configuration */
        NULL, /* merge server configuration */

        NULL, /* create location configuration */
        NULL  /* merge location configuration */
};


/**
 * 
 * 若访问来自同一个IP且URL相同，则每N秒钟最多只能成功访问一次
 * 
 * 基于红黑树实现，关键字是IP+URL的字符串，而值则记录了上次成功访问的时间。请求到来时， 以IP+URL组成的字符串为关键字查询红黑树，
 * 没有查到或查到后发现上次访问的时间距现 在大于某个阀值，则允许访问，同时将该键值对插下红黑树；
 * 反之，若查到了且上次访问的 时间距现在小于某个阀值，则拒绝访问
 * 
 * 为了避免内存耗尽，所有的结点将通过一个链表连接起来，其插入顺序按IP+URL最后一次访问的时间组织。淘汰链表末尾数据
 */

ngx_module_t ngx_http_testslab_module =
{
    NGX_MODULE_V1,
    &ngx_http_testslab_module_ctx, /* module context */
    ngx_http_testslab_commands,    /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

/**
 * 创建配置结构体， test_slab 10 10M;
 */
static void * 
ngx_http_testslab_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_testslab_conf_t *conf;

    // 在 worker内存中分配配置结构体
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_testslab_conf_t));

    if (NULL == conf) {
        return NULL;
    }

    // interval初始化为 -1，同时用于判断是否未开启模块的限速功能
    conf->interval = -1;
    conf->shmsize = -1;

    return conf;
}


/**
 * 
 * 自定义配置项解析 test_slab 10 10M;
 */
static char * 
ngx_http_testslab_createmem(ngx_conf_t *cf, ngx_conf_t *cmd, void *conf) {
    ngx_str_t *value;
    ngx_shm_zone_t *shm_zone;

    // conf参数为 ngx_http_testslab_create_main_conf 创建的结构体
    ngx_http_testslab_conf_t *mconf = (ngx_http_testslab_conf_t *)conf;

    ngx_str_t name = ngx_string("test_slab_shm");   // 这块共享内存的名字

    // 取到 test_slab配置项后的参数数组
    value = cf->args->elts;

    // 获取两次成功访问的时间间隔，注意时间单位
    mconf->interval = 1000 * ngx_atoi(value[1].data, value[1].len);

    if (mconf->interval == NGX_ERROR || mconf->interval == 0) {

        mconf->interval = -1;       // 约定设置为 -1就关闭模块的限速功能
        return "invalid value";
    }

    mconf->shmsize = ngx_parse_size(&value[2]);     // 获取共享内存大小
    if (mconf->shmsize == (ssize_t)NGX_ERROR || mconf->shmsize == 0) {

        // 关闭模块的限速功能
        mconf->interval = -1;
        return "invalid value";
    }

    // 要求 Nginx准备分配共享内存
    shm_zone = ngx_shared_memory_add(cf, &name, mconf->shmsize,
                                     &ngx_http_testslab_module);
    if (NULL == shm_zone) {
        mconf->interval = -1;       // 关闭模块的限速功能
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_http_testslab_shm_init;        // 设置共享内存分配成功后的回调方法

    // 设置 init回调时可以由 data中获取 ngx_http_testslab_conf_t配置结构体
    shm_zone->data = mconf;

    return NGX_CONF_OK;
}

/**
 * 
 * ngx_shared_memory_add执行成功后，Nginx将会在所有配置文件解析完毕后开始分配共享内存，
 * 并在名为test_slab_shm的slab共享内存初始化完毕后回调ngx_http_testslab_shm_init方法
 * 
 */
static ngx_int_t
ngx_http_testslab_shm_init(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_testslab_conf_t *conf;

    // data可能为空，也可能是上次 ngx_http_testslab_shm_init执行完成后的
    ngx_http_testslab_conf_t *oconf = data;
    size_t len;

    // shm_zone->data存放着本次初始化cycle时创建的 ngx_http_testslab_conf_t配置结构体
    conf = (ngx_http_testslab_conf_t *)shm_zone->data;

     // 判断是否为reload配置项后导致的初始化共享内存
    if (oconf) {

         // 此时， data成员里就是上次创建的
         // 将sh和shpool指针指向旧的共享内存即可
        conf->sh = oconf->sh;
        conf->shpool = oconf->shpool;

        return NGX_OK;
    }

    
    // shm.addr里放着共享内存首地址 : ngx_slab_pool_t结构体
    conf->shpool = (ngx_slab_pool_t *)shm_zone->shm.addr;

    // slab共享内存中每一次分配的内存都用于存放 ngx_http_testslab_shm_t
    conf->sh = ngx_slab_alloc(conf->shpool, sizeof(ngx_http_testslab_shm_t));
    if (conf->sh == NULL)
    {
        return NGX_ERROR;
    }

    
    conf->shpool->data = conf->sh;


    // 初始化红黑树
    ngx_rbtree_init(&conf->sh->rbtree, &conf->sh->sentinel,
                    ngx_http_testslab_rbtree_insert_value);

    ngx_queue_init(&conf->sh->queue);

    len = sizeof(" in testslab \"\"") + shm_zone->shm.name.len;

     // slab操作共享内存出现错误时，其 log输出会将 log_ctx字符串作为后缀，以方便识别
    conf->shpool->log_ctx = ngx_slab_alloc(conf->shpool, len);
    if (conf->shpool->log_ctx == NULL)
    {
        return NGX_ERROR;
    }

    ngx_sprintf(conf->shpool->log_ctx, " in testslab \"%V\"%z",
                &shm_zone->shm.name);

    return NGX_OK;
}



/**
 * 自定义的红黑树插入方法，因为本模块使用ip+url作为关键字，需要处理hash相同但是关键字不同的情况
 * 
 */
static void
ngx_http_testslab_rbtree_insert_value(ngx_rbtree_node_t *temp,
                                      ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t **p;
    ngx_http_testslab_node_t *lrn, *lrnt;

    for ( ;;) {

        // ngx_rbtree_node_t中的key仅为 hash值
        // 先比较整型的 key可以加快插入速度
        if (node->key < temp->key) {
            p = &temp->left;

        } else if (node->key > temp->key) {
            p = &temp->right;

        } else {    /* node->key == temp->key */
            
            // 从 data成员开始就是 ngx_http_testslab_node_t结构体
            lrn = (ngx_http_testslab_node_t *)&node->data;
            lrnt = (ngx_http_testslab_node_t *)&temp->data;

            //比较字符串
            p = (ngx_memn2cmp(lrn->data, lrnt->data, lrn->len, lrnt->len) < 0) ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;

    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


/**
 * 负责从双向链表的尾部开始检查访问记录
 * 
 * 如果上次访问的时间距当前已经超出了允许阀值，则可以删除访问记录从而释放共享内存
 * 
 */
static void
ngx_http_testslab_expire(ngx_http_request_t *r, ngx_http_testslab_conf_t *conf)
{
    ngx_time_t *tp;
    ngx_msec_t now;
    ngx_queue_t *q;
    ngx_msec_int_t ms;
    ngx_rbtree_node_t *node;
    ngx_http_testslab_node_t *lr;

    tp = ngx_timeofday();   // 取出缓存的当前时间

    now = (ngx_msec_t)(tp->sec * 1000 * tp->msec);

    while (1) {  // 循环的结束条件为，要么链表空了，要么遇到了一个不需要淘汰的结点

        // 要先判断链表是否为空
        if (ngx_queue_empty(&conf->sh->queue)) {
            // 链表为空则结束循环
            return;
        }

        // 从链表尾部开始淘汰
        // 因为最新访问的记录会更新到链表首部，所以尾部是最老的记录
        q = ngx_queue_last(&conf->sh->queue);

        // ngx_queue_data可以取出 ngx_queue_t成员所在结构体的首地址
        lr = ngx_queue_data(q, ngx_http_testslab_node_t, queue);

         // 可以从 lr地址向前找到ngx_rbtree_node_t
        node = (ngx_rbtree_node_t *)((u_char *)lr - offsetof(ngx_rbtree_node_t, data));

        // 取当前时间与上次成功访问的时间之差
        ms = (ngx_msec_int_t)(now - lr->last);

        // 若当前结点没有淘汰掉，则后续结点也不需要淘汰
        if (ms < conf->interval) {
            return;
        }

        // 将淘汰结点移出双向链表
        ngx_queue_remove(q);

        // 将淘汰结点移出红黑树
        ngx_rbtree_delete(&conf->sh->rbtree, node);

        // 此时再释放这块共享内存
        ngx_slab_free_locked(conf->shpool, node);
    }
}


/**
 * 查找记录
 * 
 * 负责在http请求到来时，首先利用红黑树的快速检索特性，查看共享内存中是否存在访问记录。
 * 查找记录时，首先查找hash值，若相同再比较字符串，在该过程中都按左子树小于右子树的规则进行。
 * 
 * 如果查找到访问记录，则检查上次访问的时间距当前的时间差是否超过允许阀值，超过了则更新上次访问的时间，
 * 并把这条记录重新放到双向链表的首部（因为眼下这条记录最不容易被淘汰），
 * 同时返回NGX_DECLINED表示允 许访问；
 * 若没有超过阀值，则返回NGX_HTTP_FORBIDDEN表示拒绝访问。
 * 如果红黑树中没有查找到这条记录，则向slab共享内存中分配一条记录所需大小的内存块，并设置好相应的值，
 * 同时返回NGX_DECLINED表示允许访问
 * 
 * 
 * conf是全局配置结构体
 * data和 len参数表示IP+URL字符串
 * hash则是该字符串的hash值：  hash = ngx_crc32_short(data, len);
 * 
 */
static ngx_int_t
ngx_http_testslab_lookup(ngx_http_request_t *r, ngx_http_testslab_conf_t *conf,
                         ngx_uint_t hash, u_char *data, size_t len)
{
    size_t size;
    ngx_int_t rc;
    ngx_time_t *tp;
    ngx_msec_t now;
    ngx_msec_int_t ms;
    ngx_rbtree_node_t *node, *sentinel;
    ngx_http_testslab_node_t *lr;

    tp = ngx_timeofday();       //取到当前时间

    now = (ngx_msec_t)(tp->sec * 1000 + tp->msec);

    node = conf->sh->rbtree.root;
    sentinel = conf->sh->rbtree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {     // 先由hash值快速查找请求
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        // 精确比较 IP+URL字符串
        lr = (ngx_http_testslab_node_t *)&node->data;
        rc = ngx_memn2cmp(data, lr->data, len, (size_t)lr->len);


        if (rc == 0) {

            // 找到后先取得当前时间与上次访问时间之差
            ms = (ngx_msec_int_t)(now - lr->last);

            // 判断是否超过阀值
            if (ms > conf->interval) {
                // 允许访问，则更新这个结点的上次访问时间
                lr->last = now;

                // 不需要修改该结点在红黑树中的结构
                // 但需要将这个结点移动到链表首部
                ngx_queue_remove(&lr->queue);
                ngx_queue_insert_head(&conf->sh->queue, &lr->queue);

                // 返回 NGX_DECLINED表示当前 handler允许访问，继续向下执行
                return NGX_DECLINED;
            } else {
                // 向客户端返回403拒绝访问
                return NGX_HTTP_FORBIDDEN;
            }
        }

        node = (rc < 0) ? node->left : node->right;
    }

    // 获取到连续内存块的长度
    size = offsetof(ngx_rbtree_node_t, data) + offsetof(ngx_http_testslab_node_t, data) + len;

    // 首先尝试淘汰过期 node，以释放出更多共享内存
    ngx_http_testslab_expire(r, conf);

    // 释放完过期访问记录后就有更大机会分配到共享内存
    // 由于已经加过锁，所以没有调用 ngx_slab_alloc方法
    node = ngx_slab_alloc_locked(conf->shpool, size);

    if (node == NULL) {
        // 共享内存不足时简单返回错误，这个简单的例子没有做更多的处理
        return NGX_ERROR;
    }

    // key里存放 ip+url字符串的 hash值以加快访问红黑树的速度
    node->key = hash;

    lr = (ngx_http_testslab_node_t *)&node->data;

    // 设置访问时间
    lr->last = now;

    // 将连续内存块中的字符串及其长度设置好
    lr->len = (u_char)len;
    ngx_memcpy(lr->data, data, len);

    // 插入红黑树
    ngx_rbtree_insert(&conf->sh->rbtree, node);

    // 插入红黑树
    ngx_queue_insert_head(&conf->sh->queue, &lr->queue);

    // 允许访问
    return NGX_DECLINED;
}


/**
 * 
 * access handler
 * 
 */
static ngx_int_t
ngx_http_testslab_handler(ngx_http_request_t *r)
{
    size_t len;
    uint32_t hash;
    ngx_int_t rc;
    ngx_http_testslab_conf_t *conf;

    conf = ngx_http_get_module_main_conf(r, ngx_http_testslab_module);
    rc = NGX_DECLINED;

    // 如果没有配置 test_slab，或者 test_slab参数错误，返回 NGX_DECLINED继续执行下一个http handler
    if (conf->interval == -1) {
        return rc;
    }

    // 以客户端 IP地址（ r->connection->addr_text中已经保存了解析出的IP字符串） 和 url来识别同一请求
    len = r->connection->addr_text.len + r->uri.len;
    u_char *data = ngx_palloc(r->pool, len);
    ngx_memcpy(data, r->uri.data, r->uri.len);
    ngx_memcpy(data + r->uri.len, r->connection->addr_text.data,
               r->connection->addr_text.len);

    //crc32算法将 IP+URL字符串生成 hash码
    // hash码作为红黑树的关键字来提高效率
    hash = ngx_crc32_short(data, len);
 
    // 多进程同时操作同一共享内存，需要加锁
    ngx_shmtx_lock(&conf->shpool->mutex);

    rc = ngx_http_testslab_lookup(r, conf, hash, data, len);

    ngx_shmtx_unlock(&conf->shpool->mutex);

    return rc;
}


/**
 * 
 * 安装 access handler
 * 
 */
static ngx_int_t 
ngx_http_testslab_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    // 设置模块在 NGX_HTTP_PREACCESS_PHASE阶段介入请求的处理
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (NULL == h)
    {
        return NGX_ERROR;
    }

    // 设置请求的处理方法
    *h = ngx_http_testslab_handler;

    return NGX_OK;
}

