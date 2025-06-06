
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


/**
 * 将in链表数据构造成iovec结构发送出去
 * 返回值为尚未发送取出的第一个chain
 */
ngx_chain_t *
ngx_writev_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    ssize_t        n, sent;
    off_t          send, prev_send;
    ngx_chain_t   *cl;
    ngx_event_t   *wev;
    ngx_iovec_t    vec;
    struct iovec   iovs[NGX_IOVS_PREALLOCATE];

    wev = c->write;

    if (!wev->ready) {
        return in;
    }

#if (NGX_HAVE_KQUEUE)

    if ((ngx_event_flags & NGX_USE_KQUEUE_EVENT) && wev->pending_eof) {
        (void) ngx_connection_error(c, wev->kq_errno,
                               "kevent() reported about an closed connection");
        wev->error = 1;
        return NGX_CHAIN_ERROR;
    }

#endif

    /* the maximum limit size is the maximum size_t value - the page size */

    if (limit == 0 || limit > (off_t) (NGX_MAX_SIZE_T_VALUE - ngx_pagesize)) {
        limit = NGX_MAX_SIZE_T_VALUE - ngx_pagesize;
    }

    send = 0;

    vec.iovs = iovs;
    vec.nalloc = NGX_IOVS_PREALLOCATE;

    for ( ;; ) {
        prev_send = send;

        /* create the iovec and coalesce the neighbouring bufs */

        //创建vec结构，将in中的buf复制到vec的数组中
        cl = ngx_output_chain_to_iovec(&vec, in, limit - send, c->log);

        if (cl == NGX_CHAIN_ERROR) {
            return NGX_CHAIN_ERROR;
        }

        //ngx_output_chain_to_iovec 可能是遇到了in_file的buf返回的
        if (cl && cl->buf->in_file) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "file buf in writev "
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

            return NGX_CHAIN_ERROR;
        }

        send += vec.size;

        //发送出去
        n = ngx_writev(c, &vec);

        if (n == NGX_ERROR) {
            return NGX_CHAIN_ERROR;
        }

        sent = (n == NGX_AGAIN) ? 0 : n;

        c->sent += sent;    //更新已经发送出去的字节数量

        //更新in链表，标记已经消费过的数据
        in = ngx_chain_update_sent(in, sent);

        //prev_send不为0
        if (send - prev_send != sent) {
            wev->ready = 0;
            return in;
        }

        if (send >= limit || in == NULL) {
            return in;
        }
    }
}

/**
 * 将in转成ngx_iovec_t结构体
 * limit为输出最大字节数
 * 在遇到buf在文件里时也会返回。
 */
ngx_chain_t *
ngx_output_chain_to_iovec(ngx_iovec_t *vec, ngx_chain_t *in, size_t limit,
    ngx_log_t *log)
{
    size_t         total, size;
    u_char        *prev;
    ngx_uint_t     n;
    struct iovec  *iov;

    iov = NULL;
    prev = NULL;
    total = 0;
    n = 0;

    //循环遍历in链表
    for ( /* void */ ; in && total < limit; in = in->next) {

        if (ngx_buf_special(in->buf)) {     //忽略控制buf
            continue;
        }

        if (in->buf->in_file) {     //如果是文件
            break;
        }

        if (!ngx_buf_in_memory(in->buf)) {      //不在内存里
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                          "bad buf in output chain "
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

            return NGX_CHAIN_ERROR;
        }

        //本buf有效数据
        size = in->buf->last - in->buf->pos;

        //只能读取limit字节
        if (size > limit - total) {
            size = limit - total;
        }

        if (prev == in->buf->pos) {
            iov->iov_len += size;

        } else {
            //如果达到了vec数组个数
            if (n == vec->nalloc) {
                break;
            }

            iov = &vec->iovs[n++];

            iov->iov_base = (void *) in->buf->pos;
            iov->iov_len = size;
        }

        prev = in->buf->pos + size;
        total += size;
    }

    vec->count = n;
    vec->size = total;

    return in;
}

/**
 * 将vec里存放的数据发送出去
 * 返回的n是实际发送出去的字节数
 */
ssize_t
ngx_writev(ngx_connection_t *c, ngx_iovec_t *vec)
{
    ssize_t    n;
    ngx_err_t  err;

eintr:

    n = writev(c->fd, vec->iovs, vec->count);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "writev: %z of %uz", n, vec->size);

    if (n == -1) {
        err = ngx_errno;

        switch (err) {
        case NGX_EAGAIN:
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
                           "writev() not ready");
            return NGX_AGAIN;

        case NGX_EINTR:
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
                           "writev() was interrupted");
            goto eintr;

        default:
            c->write->error = 1;
            ngx_connection_error(c, err, "writev() failed");
            return NGX_ERROR;
        }
    }

    return n;
}
