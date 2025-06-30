
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_BUF_H_INCLUDED_
#define _NGX_BUF_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef void *            ngx_buf_tag_t;

typedef struct ngx_buf_s  ngx_buf_t;

/**
 * 处理大数据的关键数据结构，它既应用于内存数据也应用于磁盘数据
 * 
 */
struct ngx_buf_s {
    ///*pos通常是用来告诉使用者本次应该从 pos这个位置开始处理内存中的数据，
    //这样设置是因为同一个ngx_buf_t可能被多次反复处理。当然， pos的含义是由使用它的模块定义的
    u_char          *pos;       //未消费的数据的首个地址
    //last通常表示有效的内容到此为止，注意，pos与last之间的内存是希望nginx处理的内容
    u_char          *last;      //未消费的数据的末尾地址
    //当数据位于文件中时
    off_t            file_pos;  //处理文件时，待处理的文件开始标记
    off_t            file_last; //处理文件时，待处理的文件结尾标记

    //如果ngx_buf_t缓冲区用于内存，那么start指向这段内存的起始地址
    u_char          *start;         /* start of buffer */
    u_char          *end;           /* end of buffer */
    //表示当前缓冲区的类型，例如由哪个模块使用就指向这个模块 ngx_module_t变量的地址
    ngx_buf_tag_t    tag;
    // 引用的文件
    ngx_file_t      *file;
    /* 当前缓冲区的一个影子缓冲区，即当一个缓冲区复制另一个缓冲区的数据，
     * 就会发生相互指向对方的shadow指针
     */
    ngx_buf_t       *shadow;


    // 临时内存标志位，为 1时表示数据在内存中且这段内存可以修改
    /* the buf's content could be changed */
    unsigned         temporary:1;

    /*
     * the buf's content is in a memory cache or in a read only memory
     * and must not be changed
     */
    // 标志位，为 1时表示数据在内存中且这段内存不可以被修改
    unsigned         memory:1;

    // 标志位，为 1时表示这段内存是用mmap系统调用映射过来的，不可以被修改
    /* the buf's content is mmap()ed and must not be changed */
    unsigned         mmap:1;

    // 标志位，为 1时表示可回收
    unsigned         recycled:1;

    // 标志位，为1时表示这段缓冲区处理的是文件而不是内存
    unsigned         in_file:1;
    unsigned         flush:1;   // 标志位，为 1时表示需要执行 flush操作

    /**
     * 标志位，对于操作这块缓冲区时是否使用同步方式，需谨慎考虑，这可能会阻塞Nginx进程，
     * Nginx中所有操作几乎都是异步的，这是它支持高并发的关键。
     * 有些框架代码在 sync为 1时可能会有阻塞的方式进行 I/O操作，它的意义视使用它的 Nginx模块而定
     */
    unsigned         sync:1;

    /**
     * 标志位，表示是否是最后一块缓冲区，因为 ngx_buf_t可以由ngx_chain_t链表串联起来，
     * 因此，当 last_buf为 1时，表示当前是最后一块待处理的缓冲区
     */
    unsigned         last_buf:1;    
    //标志位，表示是否是 ngx_chain_t中的最后一块缓冲区
    unsigned         last_in_chain:1;

    unsigned         last_shadow:1;     /* 标志位，为1时，表示是否是最后一个影子缓冲区 */
    unsigned         temp_file:1;       // 标志位，表示当前缓冲区是否属于临时文件

    /* STUB */ int   num;
};


/**
 * ngx_chain_t是与ngx_buf_t配合使用的链表数据结构
 * 一个链表节点
 */
struct ngx_chain_s {
    ngx_buf_t    *buf;      //指向当前的ngx_buf_t缓冲区
    ngx_chain_t  *next;     //指向下一个ngx_chain_t, 如果这是最后一个 ngx_chain_t，则需要把next置为NULL，否则会导致未定义错误
};


/**
 * 
 * 代表一个缓冲区的大小配置，包括缓冲区的个数和每个缓冲区的大小
 * 
 * 如 gunzip_buffers number size;
 */
typedef struct {
    ngx_int_t    num;
    size_t       size;
} ngx_bufs_t;


typedef struct ngx_output_chain_ctx_s  ngx_output_chain_ctx_t;

typedef ngx_int_t (*ngx_output_chain_filter_pt)(void *ctx, ngx_chain_t *in);

typedef void (*ngx_output_chain_aio_pt)(ngx_output_chain_ctx_t *ctx,
    ngx_file_t *file);

struct ngx_output_chain_ctx_s {
    ngx_buf_t                   *buf;
    ngx_chain_t                 *in;
    ngx_chain_t                 *free;
    ngx_chain_t                 *busy;

    unsigned                     sendfile:1;
    unsigned                     directio:1;
    unsigned                     unaligned:1;
    unsigned                     need_in_memory:1;
    unsigned                     need_in_temp:1;
    unsigned                     aio:1;

#if (NGX_HAVE_FILE_AIO || NGX_COMPAT)
    ngx_output_chain_aio_pt      aio_handler;
#endif

#if (NGX_THREADS || NGX_COMPAT)
    ngx_int_t                  (*thread_handler)(ngx_thread_task_t *task,
                                                 ngx_file_t *file);
    ngx_thread_task_t           *thread_task;
#endif

    off_t                        alignment;

    ngx_pool_t                  *pool;
    ngx_int_t                    allocated;
    ngx_bufs_t                   bufs;
    ngx_buf_tag_t                tag;       //ngx_buf_tag_t 为 void*, 一般为模块的地址

    ngx_output_chain_filter_pt   output_filter;
    void                        *filter_ctx;
};


typedef struct {
    ngx_chain_t                 *out;
    ngx_chain_t                **last;
    ngx_connection_t            *connection;
    ngx_pool_t                  *pool;
    off_t                        limit;
} ngx_chain_writer_ctx_t;


#define NGX_CHAIN_ERROR     (ngx_chain_t *) NGX_ERROR


#define ngx_buf_in_memory(b)       ((b)->temporary || (b)->memory || (b)->mmap)
#define ngx_buf_in_memory_only(b)  (ngx_buf_in_memory(b) && !(b)->in_file)

#define ngx_buf_special(b)                                                   \
    (((b)->flush || (b)->last_buf || (b)->sync)                              \
     && !ngx_buf_in_memory(b) && !(b)->in_file)

#define ngx_buf_sync_only(b)                                                 \
    ((b)->sync && !ngx_buf_in_memory(b)                                      \
     && !(b)->in_file && !(b)->flush && !(b)->last_buf)

//判断b上是否还有未消费的数据     
#define ngx_buf_size(b)                                                      \
    (ngx_buf_in_memory(b) ? (off_t) ((b)->last - (b)->pos):                  \
                            ((b)->file_last - (b)->file_pos))

//创建一个缓冲区。需要传入pool和buf的大小
ngx_buf_t *ngx_create_temp_buf(ngx_pool_t *pool, size_t size);
ngx_chain_t *ngx_create_chain_of_bufs(ngx_pool_t *pool, ngx_bufs_t *bufs);


#define ngx_alloc_buf(pool)  ngx_palloc(pool, sizeof(ngx_buf_t))
//申请内存放置ngx_buf_t结构体
#define ngx_calloc_buf(pool) ngx_pcalloc(pool, sizeof(ngx_buf_t))

ngx_chain_t *ngx_alloc_chain_link(ngx_pool_t *pool);
/**
 * 回收chain, 只是将其放入pool->chain链表中
 */
#define ngx_free_chain(pool, cl)                                             \
    (cl)->next = (pool)->chain;                                              \
    (pool)->chain = (cl)



ngx_int_t ngx_output_chain(ngx_output_chain_ctx_t *ctx, ngx_chain_t *in);
ngx_int_t ngx_chain_writer(void *ctx, ngx_chain_t *in);

ngx_int_t ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain,
    ngx_chain_t *in);
ngx_chain_t *ngx_chain_get_free_buf(ngx_pool_t *p, ngx_chain_t **free);
void ngx_chain_update_chains(ngx_pool_t *p, ngx_chain_t **free,
    ngx_chain_t **busy, ngx_chain_t **out, ngx_buf_tag_t tag);

off_t ngx_chain_coalesce_file(ngx_chain_t **in, off_t limit);

ngx_chain_t *ngx_chain_update_sent(ngx_chain_t *in, off_t sent);

#endif /* _NGX_BUF_H_INCLUDED_ */
