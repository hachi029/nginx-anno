
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#if 0
#define NGX_SENDFILE_LIMIT  4096
#endif

/*
 * When DIRECTIO is enabled FreeBSD, Solaris, and MacOSX read directly
 * to an application memory from a device if parameters are aligned
 * to device sector boundary (512 bytes).  They fallback to usual read
 * operation if the parameters are not aligned.
 * Linux allows DIRECTIO only if the parameters are aligned to a filesystem
 * sector boundary, otherwise it returns EINVAL.  The sector size is
 * usually 512 bytes, however, on XFS it may be 4096 bytes.
 */

#define NGX_NONE            1


static ngx_inline ngx_int_t
    ngx_output_chain_as_is(ngx_output_chain_ctx_t *ctx, ngx_buf_t *buf);
static ngx_int_t ngx_output_chain_add_copy(ngx_pool_t *pool,
    ngx_chain_t **chain, ngx_chain_t *in);
static ngx_int_t ngx_output_chain_align_file_buf(ngx_output_chain_ctx_t *ctx,
    off_t bsize);
static ngx_int_t ngx_output_chain_get_buf(ngx_output_chain_ctx_t *ctx,
    off_t bsize);
static ngx_int_t ngx_output_chain_copy_buf(ngx_output_chain_ctx_t *ctx);


/**
 * https://www.kancloud.cn/kancloud/master-nginx-develop/51865
 * 
 * 发送 in 中的数据，ctx 用来保存发送的上下文。
 * 发送通常情况下，不能一次完成，需要使用 context 上下文对象来保存发送到什么环节了
 * 
 * 两种调用场景【向上游发送请求， body-filter，向客户端发送响应(代理或发送本地文件)】
 */
/**
 * 向上游服务器发送ngx_http_upstream_t结构体中的 request_bufs 链表，
 * 这个方法对于发送缓冲区构成的ngx_chain_t链表非常有用，它会把未发送完成的链表缓冲区保存下来，
 * 这样就不用每次调用时都携带上request_bufs链表。怎么理解 呢？当第一次调用ngx_output_chain方法时，需要传递request_bufs链表构成的请求
    如果ngx_output_chain一次无法发送完所有的request_bufs请求内容， 
    ngx_output_chain_ctx_t类型的u->output会把未发送完的请求保存在自己的成员中，
    同时返回 NGX_AGAIN。当可写事件再次触发，发送请求时就不需要再传递参数了  ngx_output_chain(&u->output, NULL);
    */
ngx_int_t
ngx_output_chain(ngx_output_chain_ctx_t *ctx, ngx_chain_t *in)
{
    off_t         bsize;
    ngx_int_t     rc, last;
    ngx_chain_t  *cl, *out, **last_out;

    //一个快捷路径（short path）, 当能直接确定所有的in chain都不需要复制的时, 可以直接调用output_filter来交给next-filter去处理：
    if (ctx->in == NULL && ctx->busy == NULL
#if (NGX_HAVE_FILE_AIO || NGX_THREADS)
        && !ctx->aio
#endif
       )
    {
        /*
         * the short path for the case when the ctx->in and ctx->busy chains
         * are empty, the incoming chain is empty too or has the single buf
         * that does not require the copy
         */

        if (in == NULL) {
            //为 ngx_http_next_body_filter 参考 ngx_http_copy_filter
            return ctx->output_filter(ctx->filter_ctx, in);
        }

        // 要发送的 buf 只有一个，不需要复制
        if (in->next == NULL
#if (NGX_SENDFILE_LIMIT)
            && !(in->buf->in_file && in->buf->file_last > NGX_SENDFILE_LIMIT)
#endif
            && ngx_output_chain_as_is(ctx, in->buf))
        {
            return ctx->output_filter(ctx->filter_ctx, in);    //调用的是 ngx_http_next_body_filter  
        }
    }

    /* add the incoming buf to the chain ctx->in */

    if (in) {
        // 把输出 in 追加到 ctx->in chain 列表后，chain 对象是新建的，buf 对象还是复用 in 中的
        if (ngx_output_chain_add_copy(ctx->pool, &ctx->in, in) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }
    /**
     * 然后就是主要的逻辑处理阶段。这里nginx做的非常巧妙也非常复杂，首先是chain的重用，然后是buf的重用。

        先来看chain的重用。关键的几个结构以及域：ctx的free，busy以及ctx->pool的chain域。

        其中每次发送没有发完的chain就放到busy中，而已经发送完毕的就放到free中，而最后会调用 ngx_free_chain来将free的chain放入到pool->chain中,
        而在ngx_alloc_chain_link中，如果pool->chain中存在chain的话，就不用malloc了，而是直接返回pool->chain
     */

     /* out为最终需要传输的chain，也就是交给剩下的filter处理的chain */
    out = NULL;
    /* last_out为out的最后一个chain */
    last_out = &out;
    last = NGX_NONE;

    for ( ;; ) {

#if (NGX_HAVE_FILE_AIO || NGX_THREADS)
        if (ctx->aio) {
            return NGX_AGAIN;
        }
#endif

        /* 开始循环处理ctx-in chain. */
        while (ctx->in) {

            /*
             * cycle while there are the ctx->in bufs
             * and there are the free output bufs to copy in
             */

            /* 取得当前chain的buf大小 */
            bsize = ngx_buf_size(ctx->in->buf);

            /* 跳过bsize为0的buf */
            //如果buf的大小为0，并且不是特殊buf, 则跳过
            if (bsize == 0 && !ngx_buf_special(ctx->in->buf)) {

                ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, 0,
                              "zero size buf in output "
                              "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                              ctx->in->buf->temporary,
                              ctx->in->buf->recycled,
                              ctx->in->buf->in_file,
                              ctx->in->buf->start,
                              ctx->in->buf->pos,
                              ctx->in->buf->last,
                              ctx->in->buf->file,
                              ctx->in->buf->file_pos,
                              ctx->in->buf->file_last);

                ngx_debug_point();

                cl = ctx->in;
                ctx->in = cl->next;

                ngx_free_chain(ctx->pool, cl);

                continue;
            }

            //如果buf的大小小于0，表示无效buf
            if (bsize < 0) {

                ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, 0,
                              "negative size buf in output "
                              "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                              ctx->in->buf->temporary,
                              ctx->in->buf->recycled,
                              ctx->in->buf->in_file,
                              ctx->in->buf->start,
                              ctx->in->buf->pos,
                              ctx->in->buf->last,
                              ctx->in->buf->file,
                              ctx->in->buf->file_pos,
                              ctx->in->buf->file_last);

                ngx_debug_point();

                return NGX_ERROR;
            }

            //判断是否需要复制buf */
            if (ngx_output_chain_as_is(ctx, ctx->in->buf)) {

                /* move the chain link to the output chain */

                /* 如果不需要复制，则直接链接chain到out，然后继续循环 */
                cl = ctx->in;
                ctx->in = cl->next;

                *last_out = cl;
                last_out = &cl->next;
                cl->next = NULL;

                continue;
            }

            /* 到达这里，说明需要拷贝buf，这里buf最终都会被拷贝进ctx->buf中，因此这里先判断ctx->buf是否为空 */
            if (ctx->buf == NULL) {

                /* 如果为空，则取得buf，这里要注意，一般来说如果没有开启directio的话，这个函数都会返回NGX_DECLINED */
                rc = ngx_output_chain_align_file_buf(ctx, bsize);

                if (rc == NGX_ERROR) {
                    return NGX_ERROR;
                }

                /* 大部分情况下(如果是memory buf)，都会落入这个分支 */
                if (rc != NGX_OK) {

                    /* 准备分配buf，首先在free中寻找可以重用的buf */
                    if (ctx->free) {

                        /* get the free buf */

                        /* 得到free buf */
                        cl = ctx->free;
                        ctx->buf = cl->buf;
                        ctx->free = cl->next;

                        /* 将要重用的chain链接到ctx->poll中，以便于chain的重用 */
                        ngx_free_chain(ctx->pool, cl);

                    } else if (out || ctx->allocated == ctx->bufs.num) {

                        /* 如果已经等于buf的个数限制，则跳出循环，发送已经存在的buf。
                       这里可以看到如果out存在的话，nginx会跳出循环，然后发送out，
                       等发送完会再次处理，这里很好的体现了nginx的流式处理 */
                        break;

                    //否则要重新create一个buf，然后链接到ctx，这里主要buf的大小和in chain的没有处理的数据一样大
                    } else if (ngx_output_chain_get_buf(ctx, bsize) != NGX_OK) {
                         /* 上面这个函数也比较关键，它用来取得buf。 */
                        return NGX_ERROR;
                    }
                }
            }

            /* 从原来的buf中拷贝内容（src在内存中）或者从文件中读取内容(src在文件中), 拷贝ctx->in->buf 到  ctx->buf;*/
            rc = ngx_output_chain_copy_buf(ctx);

            if (rc == NGX_ERROR) {
                return rc;
            }

            if (rc == NGX_AGAIN) {
                if (out) {
                    break;
                }

                return rc;
            }

            /* delete the completed buf from the ctx->in chain */

            //如果size为0,说明in chain中的第一个chain的数据已经被拷贝完了，此时删除这个chain
            if (ngx_buf_size(ctx->in->buf) == 0) {
                cl = ctx->in;
                //将ctx->in指向下一个ctx->in.next
                ctx->in = cl->next;

                ngx_free_chain(ctx->pool, cl);
            }

            /* 分配新的chain节点 */
            cl = ngx_alloc_chain_link(ctx->pool);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            //链接buf到cl
            //out为最终需要传输的chain，也就是交给剩下的filter处理的chain, last_out为out的最后一个chain */
            cl->buf = ctx->buf;
            cl->next = NULL;
            *last_out = cl;
            last_out = &cl->next;
            ctx->buf = NULL;
        }

        if (out == NULL && last != NGX_NONE) {

            if (ctx->in) {
                return NGX_AGAIN;
            }

            return last;
        }

        //分配新的buf和chain，并调用ngx_output_chain_copy_buf拷贝完数据之后，Nginx就将新的chain链表交给下一个body filter继续处理
        //调用回调函数,ngx_http_next_body_filter
        last = ctx->output_filter(ctx->filter_ctx, out);

        if (last == NGX_ERROR || last == NGX_DONE) {
            return last;
        }

        //在其他body filter处理完之后，ngx_output_chain 函数还需要更新chain链表，以便回收利用，
        //ngx_chain_update_chains函数主要是将处理完毕的chain节点放入到free链表，没有处理完毕的放到busy链表中，另外这个函数用到了tag，
        //它只回收copy filter产生的chain节点。
        ngx_chain_update_chains(ctx->pool, &ctx->free, &ctx->busy, &out,
                                ctx->tag);
        last_out = &out;
    }
}


/**
 * 判断是否需要复制buf到内存中(如有的buf在文件里，需要修改，则复制一份到内存，以供之后的filter进行处理)
 * 
 * 返回1,表示不需要拷贝，否则为需要拷贝
 * 
 * 有两个标记要注意:
 * 1.need_in_memory ，这个主要是用于当使用sendfile的时候，Nginx并不会将请求文件拷贝到内存中，而有时需要操作文件的内容，
 *      此时就需要设置这个标记。然后后面的body filter就能操作内容了。
 * 2.need_in_temp，这个主要是用于把本来就存在于内存中的buf复制一份可修改的拷贝出来，这里有用到的模块有charset，也就是编解码 filter。
 * 
 * 
 */
static ngx_inline ngx_int_t
ngx_output_chain_as_is(ngx_output_chain_ctx_t *ctx, ngx_buf_t *buf)
{
    ngx_uint_t  sendfile;

    //是否为特殊buf（special buf），是的话返回1，也就是不用拷贝
    if (ngx_buf_special(buf)) {
        return 1;
    }

#if (NGX_THREADS)
    if (buf->in_file) {
        buf->file->thread_handler = ctx->thread_handler;
        buf->file->thread_ctx = ctx->filter_ctx;
    }
#endif

    sendfile = ctx->sendfile;

#if (NGX_SENDFILE_LIMIT)
    /* 如果pos大于sendfile的限制，设置标记为0 */
    if (buf->in_file && buf->file_pos >= NGX_SENDFILE_LIMIT) {
        sendfile = 0;
    }

#endif

#if !(NGX_HAVE_SENDFILE_NODISKIO)

    /*
     * With DIRECTIO, disable sendfile() unless sendfile(SF_NOCACHE)
     * is available.
     */

    //如果buf在文件中，并且使用了directio的话，需要拷贝buf
    if (buf->in_file && buf->file->directio) {
        sendfile = 0;
    }

#endif

    if (!sendfile) {

        //如果不走sendfile，而且buf不在内存中，则需要复制到内存一份
        if (!ngx_buf_in_memory(buf)) {
            return 0;
        }

        buf->in_file = 0;
    }

    //如果需要内存中有一份拷贝，而并不在内存中，此时返回0，表示需要拷贝
    if (ctx->need_in_memory && !ngx_buf_in_memory(buf)) {
        return 0;
    }

    //如果需要内存中有可修改的拷贝，并且buf存在于只读的内存中或者mmap中，则返回0
    if (ctx->need_in_temp && (buf->memory || buf->mmap)) {
        return 0;
    }

    //不需要拷贝
    return 1;
}


/**
 * 将in链表中的buf拷贝到chain链表中
 * 1. 如果buf在文件中，并且文件的pos大于sendfile的限制，设置标记为0
 * 2. 如果buf在内存中，并且使用了directio的话，需要拷贝buf
 * 3. 如果buf在内存中，并且需要内存中有一份拷贝，而并不在内存中，此时返回0，表示需要拷贝
 * 4. 如果buf在内存中，并且需要内存中有可修改的拷贝，并且buf存在于只读的内存中或者mmap中，则返回0
 */
static ngx_int_t
ngx_output_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain,
    ngx_chain_t *in)    
{
    ngx_chain_t  *cl, **ll;
#if (NGX_SENDFILE_LIMIT)
    ngx_buf_t    *b, *buf;
#endif

    ll = chain;

    // ll 指向最后一个节点的地址
    for (cl = *chain; cl; cl = cl->next) {
        ll = &cl->next;
    }

    while (in) {

        cl = ngx_alloc_chain_link(pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

#if (NGX_SENDFILE_LIMIT)

        buf = in->buf;

        //如果buf是存在于文件中，并且file_pos超过了sendfile limit，此时就会切割buf为两个buf，然后保存在两个chain中，最终连接起来
        if (buf->in_file
            && buf->file_pos < NGX_SENDFILE_LIMIT
            && buf->file_last > NGX_SENDFILE_LIMIT)
        {
            /* split a file buf on two bufs by the sendfile limit */

            b = ngx_calloc_buf(pool);
            if (b == NULL) {
                return NGX_ERROR;
            }

            ngx_memcpy(b, buf, sizeof(ngx_buf_t));

            if (ngx_buf_in_memory(buf)) {
                buf->pos += (ssize_t) (NGX_SENDFILE_LIMIT - buf->file_pos);
                b->last = buf->pos;
            }

            buf->file_pos = NGX_SENDFILE_LIMIT;
            b->file_last = NGX_SENDFILE_LIMIT;

            cl->buf = b;

        } else {
            cl->buf = buf;
            in = in->next;
        }

#else
        cl->buf = in->buf;
        in = in->next;

#endif

        cl->next = NULL;
        *ll = cl;
        ll = &cl->next;
    }

    return NGX_OK;
}


/**
 * 主要是处理file buf，如果是file buf则会create一个buf链接到ctx
 */
static ngx_int_t
ngx_output_chain_align_file_buf(ngx_output_chain_ctx_t *ctx, off_t bsize)
{
    size_t      size;
    ngx_buf_t  *in;

    in = ctx->in->buf;

    //buf不在文件或不是directio，则返回
    if (in->file == NULL || !in->file->directio) {
        return NGX_DECLINED;
    }

    ctx->directio = 1;

    size = (size_t) (in->file_pos - (in->file_pos & ~(ctx->alignment - 1)));

    if (size == 0) {

        if (bsize >= (off_t) ctx->bufs.size) {
            return NGX_DECLINED;
        }

        size = (size_t) bsize;

    } else {
        size = (size_t) ctx->alignment - size;

        if ((off_t) size > bsize) {
            size = (size_t) bsize;
        }
    }

    ctx->buf = ngx_create_temp_buf(ctx->pool, size);
    if (ctx->buf == NULL) {
        return NGX_ERROR;
    }

    /*
     * we do not set ctx->buf->tag, because we do not want
     * to reuse the buf via ctx->free list
     */

#if (NGX_HAVE_ALIGNED_DIRECTIO)
    ctx->unaligned = 1;
#endif

    return NGX_OK;
}


/**
 * ngx_output_chain->.
 * 
 * 这个函数当没有可重用的buf时用来分配buf
 * 
 * 如果当前的buf位于最后一个chain，则需要特殊处理，一是buf的recycled域，另外是将要分配的buf的大小。

    1.先来说recycled域，这个域表示当前的buf需要被回收。而一般情况下Nginx(比如在非last buf)会缓存一部分buf(默认是1460字节)，然后再发送，
        而设置了recycled的话，就不会让它缓存buf，也就是尽量发送出去，然后以供回收使用。 因此如果是最后一个buf，则不需要设置recycled域的，否则的话，需要设置recycled域。

    2.然后就是buf的大小。这里会有两个大小，一个是需要复制的buf的大小，一个是配置文件中设置的大小。如果不是最后一个buf，则只需要分配配置中设置的buf的大小就行了。如果是最后一个buf，则就处理不太一样，
 */
static ngx_int_t
ngx_output_chain_get_buf(ngx_output_chain_ctx_t *ctx, off_t bsize)
{
    size_t       size;
    ngx_buf_t   *b, *in;
    ngx_uint_t   recycled;

    in = ctx->in->buf;
    /* 可以看到这里分配的buf，每个buf的大小是配置文件中设置的size */
    size = ctx->bufs.size;
    /* 默认有设置recycled域 */
    recycled = 1;

    /* 如果当前的buf是属于最后一个chain的时候，需要特殊处理 */
    if (in->last_in_chain) {

        /* 如果buf大小小于配置指定的大小，则直接按实际大小分配，不设置回收标记 */
        if (bsize < (off_t) size) {

            /*
             * allocate a small temp buf for a small last buf
             * or its small last part
             */

            size = (size_t) bsize;
            recycled = 0;

        } else if (!ctx->directio
                   && ctx->bufs.num == 1
                   && (bsize < (off_t) (size + size / 4)))
        {
            /*
             * allocate a temp buf that equals to a last buf,
             * if there is no directio, the last buf size is lesser
             * than 1.25 of bufs.size and the temp buf is single
             */

            size = (size_t) bsize;
            recycled = 0;
        }
    }

    /* 开始分配buf内存 */
    b = ngx_calloc_buf(ctx->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    if (ctx->directio) {
        /* directio需要对齐 */

        /*
         * allocate block aligned to a disk sector size to enable
         * userland buffer direct usage conjunctly with directio
         */

        b->start = ngx_pmemalign(ctx->pool, size, (size_t) ctx->alignment);
        if (b->start == NULL) {
            return NGX_ERROR;
        }

    } else {
         /* 大部分情况会走到这里 */
        b->start = ngx_palloc(ctx->pool, size);
        if (b->start == NULL) {
            return NGX_ERROR;
        }
    }

    b->pos = b->start;
    b->last = b->start;
    b->end = b->last + size;
    /* 设置temporary, 标识允许修改 */
    b->temporary = 1;
    b->tag = ctx->tag;
    b->recycled = recycled;

    ctx->buf = b;
    /* 更新allocated,可以看到每分配一个就加1 */
    ctx->allocated++;

    return NGX_OK;
}


/**
 * 原来的buf中拷贝内容或者从文件中读取内容
 * 
 *  src = ctx->in->buf;
 *  dst = ctx->buf;
 * 
 */
static ngx_int_t
ngx_output_chain_copy_buf(ngx_output_chain_ctx_t *ctx)
{
    off_t        size;
    ssize_t      n;
    ngx_buf_t   *src, *dst;
    ngx_uint_t   sendfile;

    //src
    src = ctx->in->buf;
    //dst
    dst = ctx->buf;

    size = ngx_buf_size(src);
    size = ngx_min(size, dst->end - dst->pos);

    sendfile = ctx->sendfile && !ctx->directio;

#if (NGX_SENDFILE_LIMIT)

    if (src->in_file && src->file_pos >= NGX_SENDFILE_LIMIT) {
        sendfile = 0;
    }

#endif

    //如果src 在内存中
    if (ngx_buf_in_memory(src)) {
        //执行内存拷贝
        ngx_memcpy(dst->pos, src->pos, (size_t) size);
        //标记src已经消费的位置
        src->pos += (size_t) size;
        dst->last += (size_t) size;

        if (src->in_file) {

            //处理sendfile
            if (sendfile) {
                dst->in_file = 1;
                dst->file = src->file;
                dst->file_pos = src->file_pos;
                dst->file_last = src->file_pos + size;

            } else {
                dst->in_file = 0;
            }

            src->file_pos += size;

        } else {
            dst->in_file = 0;
        }

        //dst为拷贝src的最后一个buf, 拷贝其控制标识
        if (src->pos == src->last) {
            dst->flush = src->flush;
            dst->last_buf = src->last_buf;
            dst->last_in_chain = src->last_in_chain;

        } else {
            dst->flush = 0;
            dst->last_buf = 0;
            dst->last_in_chain = 0;
        }

    } else {
        /** 在文件中 */

#if (NGX_HAVE_ALIGNED_DIRECTIO)

        if (ctx->unaligned) {
            if (ngx_directio_off(src->file->fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, ngx_errno,
                              ngx_directio_off_n " \"%s\" failed",
                              src->file->name.data);
            }
        }

#endif

#if (NGX_HAVE_FILE_AIO)
        if (ctx->aio_handler) {
            n = ngx_file_aio_read(src->file, dst->pos, (size_t) size,
                                  src->file_pos, ctx->pool);
            if (n == NGX_AGAIN) {
                ctx->aio_handler(ctx, src->file);
                return NGX_AGAIN;
            }

        } else
#endif
#if (NGX_THREADS)
        if (ctx->thread_handler) {
            src->file->thread_task = ctx->thread_task;
            src->file->thread_handler = ctx->thread_handler;
            src->file->thread_ctx = ctx->filter_ctx;

            n = ngx_thread_read(src->file, dst->pos, (size_t) size,
                                src->file_pos, ctx->pool);
            if (n == NGX_AGAIN) {
                ctx->thread_task = src->file->thread_task;
                return NGX_AGAIN;
            }

        } else
#endif
        {
            //读取文件到dst
            n = ngx_read_file(src->file, dst->pos, (size_t) size,
                              src->file_pos);
        }

#if (NGX_HAVE_ALIGNED_DIRECTIO)

        if (ctx->unaligned) {
            ngx_err_t  err;

            err = ngx_errno;

            if (ngx_directio_on(src->file->fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, ngx_errno,
                              ngx_directio_on_n " \"%s\" failed",
                              src->file->name.data);
            }

            ngx_set_errno(err);

            ctx->unaligned = 0;
        }

#endif

        if (n == NGX_ERROR) {
            return (ngx_int_t) n;
        }

        //读取不完全，返回错误
        if (n != size) {
            ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, 0,
                          ngx_read_file_n " read only %z of %O from \"%s\"",
                          n, size, src->file->name.data);
            return NGX_ERROR;
        }

        dst->last += n;

        if (sendfile) {
            dst->in_file = 1;
            dst->file = src->file;
            dst->file_pos = src->file_pos;
            dst->file_last = src->file_pos + n;

        } else {
            dst->in_file = 0;
        }

        src->file_pos += n;

        if (src->file_pos == src->file_last) {
            dst->flush = src->flush;
            dst->last_buf = src->last_buf;
            dst->last_in_chain = src->last_in_chain;

        } else {
            dst->flush = 0;
            dst->last_buf = 0;
            dst->last_in_chain = 0;
        }
    }

    return NGX_OK;
}


/**
 * ngx_http_proxy_body_output_filter->.
 * 
 * 输出数据
 */
ngx_int_t
ngx_chain_writer(void *data, ngx_chain_t *in)
{
    ngx_chain_writer_ctx_t *ctx = data;

    off_t              size;
    ngx_chain_t       *cl, *ln, *chain;
    ngx_connection_t  *c;

    c = ctx->connection;

    //这里将in中的也就是新加入的chain ，全部复制到last中。也就是它保存了最后的数据
    for (size = 0; in; in = in->next) {

        if (ngx_buf_size(in->buf) == 0 && !ngx_buf_special(in->buf)) {

            ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, 0,
                          "zero size buf in chain writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          in->buf->temporary,
                          in->buf->recycled,
                          in->buf->in_file,
                          in->buf->start,
                          in->buf->pos,
                          in->buf->last,
                          in->buf->file,
                          in->buf->file_pos,
                          in->buf->file_last);

            ngx_debug_point();

            continue;
        }

        if (ngx_buf_size(in->buf) < 0) {

            ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, 0,
                          "negative size buf in chain writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          in->buf->temporary,
                          in->buf->recycled,
                          in->buf->in_file,
                          in->buf->start,
                          in->buf->pos,
                          in->buf->last,
                          in->buf->file,
                          in->buf->file_pos,
                          in->buf->file_last);

            ngx_debug_point();

            return NGX_ERROR;
        }

        //计算大小
        size += ngx_buf_size(in->buf);

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, c->log, 0,
                       "chain writer buf fl:%d s:%uO",
                       in->buf->flush, ngx_buf_size(in->buf));

        cl = ngx_alloc_chain_link(ctx->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        //加入last
        cl->buf = in->buf;
        cl->next = NULL;
        *ctx->last = cl;
        ctx->last = &cl->next;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
                   "chain writer in: %p", ctx->out);

    //遍历out chain
    for (cl = ctx->out; cl; cl = cl->next) {

        if (ngx_buf_size(cl->buf) == 0 && !ngx_buf_special(cl->buf)) {

            ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, 0,
                          "zero size buf in chain writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            ngx_debug_point();

            continue;
        }

        if (ngx_buf_size(cl->buf) < 0) {

            ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, 0,
                          "negative size buf in chain writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            ngx_debug_point();

            return NGX_ERROR;
        }

        ///计算所需要输出的大小
        size += ngx_buf_size(cl->buf);
    }

    if (size == 0 && !c->buffered) {
        return NGX_OK;
    }

    //调用send_chain(一般是writev)来输出out中的数据
    //对于https为 ngx_ssl_send_chain; 对于http为 
    chain = c->send_chain(c, ctx->out, ctx->limit);

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
                   "chain writer out: %p", chain);

    if (chain == NGX_CHAIN_ERROR) {
        return NGX_ERROR;
    }

    if (chain && c->write->ready) {
        ngx_post_event(c->write, &ngx_posted_next_events);
    }

    for (cl = ctx->out; cl && cl != chain; /* void */) {
        ln = cl;
        cl = cl->next;
        ngx_free_chain(ctx->pool, ln);
    }

    ctx->out = chain;

    if (ctx->out == NULL) {
        ctx->last = &ctx->out;

        if (!c->buffered) {
            return NGX_OK;
        }
    }

    return NGX_AGAIN;
}
