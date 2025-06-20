
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>

// 如果编译时指定宏NGX_DEBUG_PALLOC
// 则不会启用内存池机制，都使用malloc分配内存
// 方便使用valgrind等来检测内存问题
// 此宏自1.9.x开始出现

// 在本内存池内分配小块内存
// 不超过NGX_MAX_ALLOC_FROM_POOL,即4k-1
static ngx_inline void *ngx_palloc_small(ngx_pool_t *pool, size_t size,
    ngx_uint_t align);
// 所有内存池节点都空间不足
// 创建一个新的节点，即内存块
// 跳过内存池描述信息的长度
// 后面的max,current等没有意义，所以可以被利用
static void *ngx_palloc_block(ngx_pool_t *pool, size_t size);
// 分配大块内存(>4k),直接调用malloc
// 挂到大块链表里方便后续的回收
static void *ngx_palloc_large(ngx_pool_t *pool, size_t size);


/**
 * 
 * 从进程的堆中预分配更多的内存（ngx_create_pool的size参数决 定预分配大小），
 * 而后直接使用这块内存的一部分作为小块内存返回给申请者，以此实现减少碎片和调用malloc的次数。
 * 
 * 创建一个ngx_pool_t,  size指定了预分配的内存大小
 */
// 字节对齐分配一个size - sizeof(ngx_pool_t)80字节内存
// 内存池的大小可以超过4k
// 一开始只有一个内存池节点
ngx_pool_t *
ngx_create_pool(size_t size, ngx_log_t *log)
{
    ngx_pool_t  *p;

    // 字节对齐分配内存,16字节的倍数
    // os/unix/ngx_alloc.c
    p = ngx_memalign(NGX_POOL_ALIGNMENT, size, log);
    if (p == NULL) {
        return NULL;
    }


    /**
	 * Nginx会分配一块大内存，其中内存头部存放ngx_pool_t本身内存池的数据结构
	 * ngx_pool_data_t	p->d 存放内存池的数据部分（适合小于p->max的内存块存储）
	 * p->large 存放大内存块列表
	 * p->cleanup 存放可以被回调函数清理的内存块（该内存块不一定会在内存池上面分配）
	 */

    // 设置可用的内存，减去了自身的大小80字节
    p->d.last = (u_char *) p + sizeof(ngx_pool_t);
    p->d.end = (u_char *) p + size;     //内存结束地址
    // 一开始只有一个内存池节点
    p->d.next = NULL;
    // 失败次数初始化为0
    p->d.failed = 0;

    // 池内可用的内存空间，减去了自身的大小80字节
    size = size - sizeof(ngx_pool_t);
    // #define NGX_MAX_ALLOC_FROM_POOL  (ngx_pagesize - 1)
    // 不能超过NGX_MAX_ALLOC_FROM_POOL,即4k-1
    p->max = (size < NGX_MAX_ALLOC_FROM_POOL) ? size : NGX_MAX_ALLOC_FROM_POOL;

    // 刚创建，就使用自己。只有缓存池的d的首个点，才会用到下面的这些  ，其他next节点只挂载在p->d.next,并且只负责p->d的数据内容
    p->current = p;
    p->chain = NULL;
    p->large = NULL;
    p->cleanup = NULL;
    p->log = log;

    return p;
}

/**
 * 销毁pool
 * 1. 执行pool->cleanup
 * 2. 检查大块内存链表，直接free
 * 3. 遍历内存池节点，逐个free
 */
void
ngx_destroy_pool(ngx_pool_t *pool)
{
    ngx_pool_t          *p, *n;
    ngx_pool_large_t    *l;
    ngx_pool_cleanup_t  *c;

    //1.执行pool->cleanup
    for (c = pool->cleanup; c; c = c->next) {
        if (c->handler) {
            ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, pool->log, 0,
                           "run cleanup: %p", c);
            c->handler(c->data);
        }
    }

#if (NGX_DEBUG)

    /*
     * we could allocate the pool->log from this pool
     * so we cannot use this log while free()ing the pool
     */

    for (l = pool->large; l; l = l->next) {
        ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, pool->log, 0, "free: %p", l->alloc);
    }

    for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
        ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, pool->log, 0,
                       "free: %p, unused: %uz", p, p->d.end - p->d.last);

        if (n == NULL) {
            break;
        }
    }

#endif

    //2.释放大块内存
    for (l = pool->large; l; l = l->next) {
        if (l->alloc) {
            ngx_free(l->alloc);
        }
    }

    //3. 遍历内存池节点， 释放小块内存
    for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
        ngx_free(p);

        if (n == NULL) {
            break;
        }
    }
}


// 重置内存池，释放内存，但没有free归还给系统
// 之前已经分配的内存块仍然保留
// 遍历内存池节点，逐个重置空闲指针位置
// 注意cleanup链表没有清空
// 只有destroy时才会销毁
void
ngx_reset_pool(ngx_pool_t *pool)
{
    ngx_pool_t        *p;
    ngx_pool_large_t  *l;

     // 检查大块内存链表，直接free掉
    for (l = pool->large; l; l = l->next) {
        if (l->alloc) {
            ngx_free(l->alloc);
        }
    }

    // 遍历内存池节点，逐个重置空闲指针位置
    // 相当于释放了已经分配的内存
    //
    // 这里有一个问题，其他节点的块实际上只用了ngx_pool_data_t
    // reset指针移动了ngx_pool_t大小
    // 就浪费了80-32字节的内存
    for (p = pool; p; p = p->d.next) {
        p->d.last = (u_char *) p + sizeof(ngx_pool_t);
        p->d.failed = 0;
    }

    // 当前内存池指针
    pool->current = pool;
    pool->chain = NULL;
    pool->large = NULL;
    // 注意cleanup链表没有清空
    // 只有destroy时才会销毁
}


/**
 * 分配过程一般为，首先判断待分配的内存是否大于 pool->max，如果大于则使用 ngx_palloc_large 在 large 链表里分配一段内存并返回， 
 * 如果小于测尝试从链表的 pool->current 开始遍历链表，尝试找出一个可以分配的内存，当链表里的任何一个节点都无法分配内存的时候，
 * 就调用 ngx_palloc_block 生成链表里一个新的节点， 并在新的节点里分配内存并返回， 同时， 还会将pool->current 指针指向新的位置（从链表里面pool->d.failed小于等于4的节点里找出）
 */
// 分配对齐的内存，速度快，可能有少量浪费
// 多用于创建结构体
void *
ngx_palloc(ngx_pool_t *pool, size_t size)
{
#if !(NGX_DEBUG_PALLOC)
//将申请的内存大小size与ngx_pool_t的max成员比较，以决定申请的是小块内存还是大 块内存
    if (size <= pool->max) {
        return ngx_palloc_small(pool, size, 1);
    }
#endif

    // 分配大块内存(>4k),直接调用malloc
    return ngx_palloc_large(pool, size);
}


// 分配未对齐的内存
// 多用于字符串等不规则内存需求
void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
#if !(NGX_DEBUG_PALLOC)
    // 如果要求小于4k的内存，不对齐分配
    if (size <= pool->max) {
        return ngx_palloc_small(pool, size, 0);
    }
#endif

    // 分配大块内存(>4k),直接调用malloc
    return ngx_palloc_large(pool, size);
}


/**
 * 从ngx_pool_t中分配小块内存(size < pool.max)
 */
static ngx_inline void *
ngx_palloc_small(ngx_pool_t *pool, size_t size, ngx_uint_t align)
{
    u_char      *m;
    ngx_pool_t  *p;

    //取到ngx_pool_t的current指针，它表示应当首先尝试从这个小块内存池里分配，
    //因为 current之前的pool已经屡次分配失败（大于4次），其剩余的空间多半无法满足size。
    //这当然 是一种存在浪费的预估，但性能不坏。(逻辑在ngx_palloc_block中)
    p = pool->current;

    do {
        //从当前小块内存池的ngx_pool_data_t的last指针入手
        m = p->d.last;

        //调用ngx_align_ptr找到last后 最近的对齐地址
        if (align) {
            // 取得 last的 NGX_ALIGNMENT字节对齐地址
            m = ngx_align_ptr(m, NGX_ALIGNMENT);
        }

        //比较对齐地址与ngx_pool_data_t的end指针间是否可以容纳size字节
        if ((size_t) (p->d.end - m) >= size) {
            //将新内存池的空闲地址的首地址对齐，作为返回给申请的内存，再设last到空闲内存的首地址
            p->d.last = m + size;

            return m;
        }

        //尝试从下一块小块内存储中分配内存
        p = p->d.next;

    } while (p);

    // 所有当前的内存池节点都空间不足
    // 需要创建一个新的节点
    return ngx_palloc_block(pool, size);
}


// 所有小块内存池节点都空间不足
// 创建一个新的用于分配小块内存的节点，即内存块
// 跳过内存池描述信息的长度
// 后面的max,current等没有意义，所以可以被利用
static void *
ngx_palloc_block(ngx_pool_t *pool, size_t size)
{
    u_char      *m;
    size_t       psize;
    ngx_pool_t  *p, *new;

    // 计算当前内存池的大小
    // 即当初创建时的大小
    psize = (size_t) (pool->d.end - (u_char *) pool);

    // 创建一个新节点
    // 字节对齐分配内存,16字节的倍数
    m = ngx_memalign(NGX_POOL_ALIGNMENT, psize, pool->log);
    if (m == NULL) {
        return NULL;
    }

    // 新的内存块
    new = (ngx_pool_t *) m;

    // 设置节点的空闲空间， m为新内存地址起始处，psize为内存大小
    new->d.end = m + psize;
    new->d.next = NULL;
    new->d.failed = 0;

    // 跳过内存池描述信息的长度, 64位系统是32字节
    // 后面的max,current等没有意义，所以可以被利用
    // 新的内存块比头节点多80-32=48字节可用
    m += sizeof(ngx_pool_data_t);
    m = ngx_align_ptr(m, NGX_ALIGNMENT);
    // 移动空闲内存的位置，size为本次需要申请的内存
    new->d.last = m + size;

    //从current指向的小块内存池开始遍历到当前的新内存池，依次将各failed成员加1，
    //并 把current指向首个failed<=4的小块内存池，用于下一次的小块内存分配
    for (p = pool->current; p->d.next; p = p->d.next) {
        if (p->d.failed++ > 4) {
            pool->current = p->d.next;
        }
    }

    // p必定是链表的最后一个，挂到末尾
    p->d.next = new;

    // 返回分配的内存
    return m;
}


// 分配大块内存(>4k),直接调用malloc
// 挂到大块链表里方便后续的回收
// 所以可以用jemalloc来优化
static void *
ngx_palloc_large(ngx_pool_t *pool, size_t size)
{
    void              *p;
    ngx_uint_t         n;
    ngx_pool_large_t  *large;

    //分配大块内存
    p = ngx_alloc(size, pool->log);
    if (p == NULL) {
        return NULL;
    }

    n = 0;

    //遍历ngx_pool_t的large链表，看看有没有ngx_pool_large_t的alloc成员值为NULL（
    //这 个alloc指向的大块内存执行过ngx_pfree方法）
    for (large = pool->large; large; large = large->next) {
        if (large->alloc == NULL) {
            large->alloc = p;
            return p;
        }

        // 只找三次，避免低效查找
        // 3是一个“经验”数据
        if (n++ > 3) {
            break;
        }
    }

    //分配一个ngx_pool_large_t
    large = ngx_palloc_small(pool, sizeof(ngx_pool_large_t), 1);
    if (large == NULL) {
        ngx_free(p);
        return NULL;
    }

    //alloc成员置为分配的内存地址
    large->alloc = p;
    //将ngx_pool_large_t添加到ngx_pool_t的large链表首部，返回地址
    large->next = pool->large;
    pool->large = large;

    return p;
}


// 字节对齐分配大块内存
void *
ngx_pmemalign(ngx_pool_t *pool, size_t size, size_t alignment)
{
    void              *p;
    ngx_pool_large_t  *large;

    // 字节对齐分配内存,16字节的倍数
    // os/unix/ngx_alloc.c
    p = ngx_memalign(alignment, size, pool->log);
    if (p == NULL) {
        return NULL;
    }

    // 新建一个管理节点
    large = ngx_palloc_small(pool, sizeof(ngx_pool_large_t), 1);
    if (large == NULL) {
        ngx_free(p);
        return NULL;
    }

    // 加入大块内存链表
    large->alloc = p;
    large->next = pool->large;
    pool->large = large;

    return p;
}


/**
 * 提前释放大块内存
 * 实现是遍历large链表，找到alloc等于待释放地址的ngx_pool_large_t后，
 * 调用ngx_free释放大 块内存，但不释放ngx_pool_large_t结构体，而是把alloc置为NULL
 * 意义在于： 下次分配大块内存时，会期望复用这个ngx_pool_large_t结构体
 */
ngx_int_t
ngx_pfree(ngx_pool_t *pool, void *p)
{
    ngx_pool_large_t  *l;

    // 遍历大块链表，找到则释放
    // 如果多次申请大块内存需要当心效率
    for (l = pool->large; l; l = l->next) {
        if (p == l->alloc) {
            ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, pool->log, 0,
                           "free: %p", l->alloc);
            ngx_free(l->alloc);
            // 指针置为空，之后可以复用节点
            l->alloc = NULL;

            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


// 使用ngx_palloc分配内存，并将内存块清零
void *
ngx_pcalloc(ngx_pool_t *pool, size_t size)
{
    void *p;

    p = ngx_palloc(pool, size);
    if (p) {
        ngx_memzero(p, size);
    }

    return p;
}


// 创建一个清理结构体，size是ngx_pool_cleanup_t::data分配的大小
// size可以为0,用户需要自己设置ngx_pool_cleanup_t::data指针
ngx_pool_cleanup_t *
ngx_pool_cleanup_add(ngx_pool_t *p, size_t size)
{
    ngx_pool_cleanup_t  *c;

    // 内存池拿一块内存
    c = ngx_palloc(p, sizeof(ngx_pool_cleanup_t));
    if (c == NULL) {
        return NULL;
    }

    // 如果要求额外数据就再分配一块
    // 注意都是对齐的
    if (size) {
        c->data = ngx_palloc(p, size);
        if (c->data == NULL) {
            return NULL;
        }

    } else {
        c->data = NULL;
    }

    // handler清空，之后用户自己设置
    c->handler = NULL;
    // 挂到内存池的清理链表里
    c->next = p->cleanup;

    p->cleanup = c;

    ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, p->log, 0, "add cleanup: %p", c);

    return c;
}


/**
 * 会遍历pool上cleanup,调用所有handler为ngx_pool_cleanup_file且fd为指定参数的文件
 * fd: 需要清理的文件描述符
 */
void
ngx_pool_run_cleanup_file(ngx_pool_t *p, ngx_fd_t fd)
{
    ngx_pool_cleanup_t       *c;
    ngx_pool_cleanup_file_t  *cf;

    for (c = p->cleanup; c; c = c->next) {
        if (c->handler == ngx_pool_cleanup_file) {

            cf = c->data;

            if (cf->fd == fd) {
                c->handler(cf);
                c->handler = NULL;
                return;
            }
        }
    }
}


/**
 * 清理文件描述符，实际上是关闭了文件描述符。常用于ngx_pool_t上的cleanup
 */
void
ngx_pool_cleanup_file(void *data)
{
    ngx_pool_cleanup_file_t  *c = data;

    ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, c->log, 0, "file cleanup: fd:%d",
                   c->fd);

    if (ngx_close_file(c->fd) == NGX_FILE_ERROR) {      //close
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", c->name);
    }
}


/**
 * 删除文件，调用ngx_delete_file和ngx_close_file。常用于ngx_pool_t上的cleanup
 */
void
ngx_pool_delete_file(void *data)
{
    ngx_pool_cleanup_file_t  *c = data;

    ngx_err_t  err;

    ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, c->log, 0, "file cleanup: fd:%d %s",
                   c->fd, c->name);

    //删除文件
    if (ngx_delete_file(c->name) == NGX_FILE_ERROR) {
        err = ngx_errno;

        if (err != NGX_ENOENT) {
            ngx_log_error(NGX_LOG_CRIT, c->log, err,
                          ngx_delete_file_n " \"%s\" failed", c->name);
        }
    }

    //关闭文件描述符
    if (ngx_close_file(c->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", c->name);
    }
}


#if 0

static void *
ngx_get_cached_block(size_t size)
{
    void                     *p;
    ngx_cached_block_slot_t  *slot;

    if (ngx_cycle->cache == NULL) {
        return NULL;
    }

    slot = &ngx_cycle->cache[(size + ngx_pagesize - 1) / ngx_pagesize];

    slot->tries++;

    if (slot->number) {
        p = slot->block;
        slot->block = slot->block->next;
        slot->number--;
        return p;
    }

    return NULL;
}

#endif
