
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PALLOC_H_INCLUDED_
#define _NGX_PALLOC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

// 如果编译时指定宏NGX_DEBUG_PALLOC
// 则不会启用内存池机制，都使用malloc分配内存
// 方便使用valgrind等来检测内存问题
/*
 * NGX_MAX_ALLOC_FROM_POOL should be (ngx_pagesize - 1), i.e. 4095 on x86.
 * On Windows NT it decreases a number of locked pages in a kernel.
 */
//定义了ngx_pool中小块内存池大小, 通常是4k-1
#define NGX_MAX_ALLOC_FROM_POOL  (ngx_pagesize - 1)

// 默认一个内存池块ngx_pool_data_t大小是16k
// 用于cycle->pool
// 注意，默认池大小与pagesize无关
#define NGX_DEFAULT_POOL_SIZE    (16 * 1024)

// 内存池对齐数，16字节，即128位
#define NGX_POOL_ALIGNMENT       16
// 内存池块最小的大小
// 首先要能够容纳ngx_pool_t结构体
// 然后还要至少能分配两个大内存块
// 最后16字节对齐
// 用于配置内存池时的参数检查
#define NGX_MIN_POOL_SIZE                                                     \
    ngx_align((sizeof(ngx_pool_t) + 2 * sizeof(ngx_pool_large_t)),            \
              NGX_POOL_ALIGNMENT)


// 内存池销毁时调用的清理函数
// 相当于析构函数，必要的清理动作
typedef void (*ngx_pool_cleanup_pt)(void *data);

typedef struct ngx_pool_cleanup_s  ngx_pool_cleanup_t;

/**
 * 代表一个需要释放的资源， 包括函数指针和参数
 */
struct ngx_pool_cleanup_s {
    // handler初始为 NULL，需要设置为清理方法,执行实际清理资源工作
    ngx_pool_cleanup_pt   handler;
    // 用于为 handler指向的方法传递必要的参数
    // ngx_pool_cleanup_add方法的 size>0时 data不为 NULL，此时可改写data指向的内存，
    void                 *data;
    // 由 ngx_pool_cleanup_add方法设置 next成员，用于将当前 ngx_pool_cleanup_t 
    // 添加到 ngx_pool_t的 cleanup链表中
    ngx_pool_cleanup_t   *next;
};

// 大块内存节点
typedef struct ngx_pool_large_s  ngx_pool_large_t;

/**
 * 当申请的内存算是大块内存时（大于ngx_pool_t的max成员），是直接调用ngx_alloc从进程的堆中分配的，
 * 同时会再分配一个ngx_pool_large_t结构体 挂在large链表中
 * 大于4k
 */
struct ngx_pool_large_s {
    // 所有大块内存通过 next指针联在一起
    ngx_pool_large_t     *next;
    // alloc指向 ngx_alloc分配出的大块内存。调用 ngx_pfree后 alloc可能是 NULL
    void                 *alloc;
};

/**
 * 描述ngx_pool_s中的用于分配小块内存的结构体
 */
typedef struct {
    // 指向未分配的空闲内存的首地址
    u_char               *last;
    // 指向当前小块内存池的尾部
    u_char               *end;
    // 同属于一个 pool的多个小块内存池间，通过 next相连
    ngx_pool_t           *next;
    // 每当剩余空间不足以分配出小块内存时， failed成员就会加 1。failed成员大于 4后,
    //ngx_pool_t的 current将移向下一个小块内存池
    ngx_uint_t            failed;
} ngx_pool_data_t;


/**
 * 
 * ngx_pool_t,动态内存池，大小可动态增长，而ngx_slab_t是静态内存块，以页为单位管理，大小不能改变
 * 
 * 表示ngx内存池 内存池销毁时才会将内存释 放回操作系统
 * 本质上是以若干个指针连接的内存块
 */
struct ngx_pool_s {
    // 描述小块内存池。当分配小块内存时，剩余的预分配空间不足时，会再分配 1个ngx_pool_t， 
    // 它们会通过 d中的 next成员构成单链表
    //由d.end-p得到d的内存块大小(默认16k)
    ngx_pool_data_t       d;
    // 评估申请内存属于小块还是大块的标准
    size_t                max;
    // 多个ngx_pool_data_t构成链表时， current指向分配内存时遍历的第 1个小块内存池
    ngx_pool_t           *current;
    // 用于 ngx_output_chain，与内存池关系不大，略过
    ngx_chain_t          *chain;

    //大于pagesize-1的内存块组成的链表
    // 大块内存都直接从进程的堆中分配，为了能够在销毁内存池时同时释放大块内存，
    // 就把每一次分配的大块内存通过 ngx_pool_large_t组成单链表挂在large成员上
    ngx_pool_large_t     *large;
    // 所有待清理资源（例如需要关闭或者删除的文件）以 ngx_pool_cleanup_t对象构成单链表， 
    // 挂在 cleanup成员上
    ngx_pool_cleanup_t   *cleanup;
    // 内存池执行中输出日志的对象
    ngx_log_t            *log;
};

/**
 * 代表一个需要清理的文件
 */
typedef struct {
    ngx_fd_t              fd;   // 文件句柄
    u_char               *name; // 文件名称
    ngx_log_t            *log;
} ngx_pool_cleanup_file_t;

// 分配内存,不用内存池，使用malloc
// 实现在os/unix/ngx_alloc.c
// void *ngx_alloc(size_t size, ngx_log_t *log);
// void *ngx_calloc(size_t size, ngx_log_t *log);

// 创建/销毁内存池

// 字节对齐分配一个size - sizeof(ngx_pool_t)内存
// 内存池的大小可以超过4k
ngx_pool_t *ngx_create_pool(size_t size, ngx_log_t *log);

// 销毁内存池
// 调用清理函数链表
// 检查大块内存链表，直接free
// 遍历内存池节点，逐个free
void ngx_destroy_pool(ngx_pool_t *pool);

// 重置内存池，释放内存，但没有free归还给系统
// 之前已经分配的内存块仍然保留
// 遍历内存池节点，逐个重置空闲指针位置
// 注意cleanup链表没有清空
// 只有destroy时才会销毁
void ngx_reset_pool(ngx_pool_t *pool);

// 分配8字节对齐的内存，速度快，可能有少量浪费
// 分配大块内存(>4k),直接调用malloc
// 所以可以用jemalloc来优化
void *ngx_palloc(ngx_pool_t *pool, size_t size);

// 分配未对齐的内存
// 分配大块内存(>4k),直接调用malloc
// 所以可以用jemalloc来优化
void *ngx_pnalloc(ngx_pool_t *pool, size_t size);

// 使用ngx_palloc分配内存，并将内存块清零
// 分配大块内存(>4k),直接调用malloc
// 所以可以用jemalloc来优化
void *ngx_pcalloc(ngx_pool_t *pool, size_t size);

// 字节对齐分配大块内存
void *ngx_pmemalign(ngx_pool_t *pool, size_t size, size_t alignment);

// 把内存归还给内存池，通常无需调用
// 实际上只释放大块内存
ngx_int_t ngx_pfree(ngx_pool_t *pool, void *p);


// 创建一个清理结构体，size是ngx_pool_cleanup_t::data分配的大小
// size可以为0,用户需要自己设置ngx_pool_cleanup_t::data指针
ngx_pool_cleanup_t *ngx_pool_cleanup_add(ngx_pool_t *p, size_t size);

void ngx_pool_run_cleanup_file(ngx_pool_t *p, ngx_fd_t fd);

// 清理文件用
void ngx_pool_cleanup_file(void *data);
void ngx_pool_delete_file(void *data);


#endif /* _NGX_PALLOC_H_INCLUDED_ */
