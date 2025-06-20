
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


/**
 * 创建一个ngx_buf_t结构体，同时分配size大小空间，并进行初始化
 */
ngx_buf_t *
ngx_create_temp_buf(ngx_pool_t *pool, size_t size)
{
    ngx_buf_t *b;

    //ngx_pcalloc(pool, sizeof(ngx_buf_t)
    b = ngx_calloc_buf(pool);
    if (b == NULL) {
        return NULL;
    }

    //分配缓冲区内存
    b->start = ngx_palloc(pool, size);
    if (b->start == NULL) {
        return NULL;
    }

    /*
     * set by ngx_calloc_buf():
     *
     *     b->file_pos = 0;
     *     b->file_last = 0;
     *     b->file = NULL;
     *     b->shadow = NULL;
     *     b->tag = 0;
     *     and flags
     */

    b->pos = b->start;
    b->last = b->start;
    b->end = b->last + size;
    b->temporary = 1;           //内存可修改

    return b;
}


/**
 * 从poll中取出一个ngx_chain_t结构体, 不分配buf结构体
 * 1.如果poll->chain不为空，则从链表中取出一个节点
 * 2.如果poll->chain为空，则分配一个新的节点
 */
ngx_chain_t *
ngx_alloc_chain_link(ngx_pool_t *pool)
{
    ngx_chain_t  *cl;

    cl = pool->chain;

    // 如果pool->chain不为空，从链表中取出一个节点
    if (cl) {
        pool->chain = cl->next;
        return cl;
    }

    // 如果pool->chain为空，分配一个新的节点
    cl = ngx_palloc(pool, sizeof(ngx_chain_t));
    if (cl == NULL) {
        return NULL;
    }

    return cl;
}


/**
 * 批量创建多个buf，并且用链表串起来
 * 用于配置文件中缓冲区配置的创建，如 proxy_buffers number size;
 * buf参数 包含缓存的大小和数量
 */
ngx_chain_t *
ngx_create_chain_of_bufs(ngx_pool_t *pool, ngx_bufs_t *bufs)
{
    u_char       *p;
    ngx_int_t     i;
    ngx_buf_t    *b;
    ngx_chain_t  *chain, *cl, **ll;

    //在内存池pool上分配bufs->num个buf缓冲区 ，每个大小为bufs->size
    p = ngx_palloc(pool, bufs->num * bufs->size);
    if (p == NULL) {
        return NULL;
    }

    ll = &chain;

    for (i = 0; i < bufs->num; i++) {

        //创建ngx_buf_t
        b = ngx_calloc_buf(pool);
        if (b == NULL) {
            return NULL;
        }

        /*
         * set by ngx_calloc_buf():
         *
         *     b->file_pos = 0;
         *     b->file_last = 0;
         *     b->file = NULL;
         *     b->shadow = NULL;
         *     b->tag = 0;
         *     and flags
         *
         */

        b->pos = p;
        b->last = p;
        b->temporary = 1;

        b->start = p;
        //p 指向下一段buf的起始位置
        p += bufs->size;
        b->end = p;

        //创建一个ngx_chain_t
        cl = ngx_alloc_chain_link(pool);
        if (cl == NULL) {
            return NULL;
        }

        //将buf挂到ngx_chain_t上
        cl->buf = b;
        *ll = cl;
        //ll 指向cl->next
        ll = &cl->next;
    }

    *ll = NULL;

    return chain;
}


/**
 * 将in链表中的buf复制到chain链表中  (会分配新的ngx_chain_t结构体)
 * 
 * 1.遍历chain链表，找到最后一个节点
 * 2.将in链表中的buf复制到chain链表中
 */
ngx_int_t
ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain, ngx_chain_t *in)
{
    ngx_chain_t  *cl, **ll;

    ll = chain;

    // 遍历chain链表，找到最后一个节点
    for (cl = *chain; cl; cl = cl->next) {
        ll = &cl->next;
    }

    while (in) {
        //分配一个新的ngx_chain_t结构体
        cl = ngx_alloc_chain_link(pool);
        if (cl == NULL) {
            *ll = NULL;
            return NGX_ERROR;
        }

        //将in链表中的buf挂到chain链表中
        cl->buf = in->buf;
        *ll = cl;
        ll = &cl->next;
        in = in->next;
    }

    *ll = NULL;

    return NGX_OK;
}


/**
 * 获取一个ngx_chain_t结构体，包含ngx_buf_t结构体
 * 
 * 优先从free指向的chain_t链表中取出一个ngx_chain_t结构体
 * 如果free链表为空，则分配一个新的ngx_chain_t结构体
 */
ngx_chain_t *
ngx_chain_get_free_buf(ngx_pool_t *p, ngx_chain_t **free)
{
    ngx_chain_t  *cl;

    if (*free) {
        cl = *free;
        *free = cl->next;
        cl->next = NULL;
        return cl;
    }

    cl = ngx_alloc_chain_link(p);
    if (cl == NULL) {
        return NULL;
    }

    //创建ngx_chain_t结构体
    cl->buf = ngx_calloc_buf(p);
    if (cl->buf == NULL) {
        return NULL;
    }

    cl->next = NULL;

    return cl;
}


/**
 * 更新free_bufs、busy_bufs、out_bufs这3个 缓冲区链表
 * 1.清空out_bufs链表/ out指向的是本次发送还没发送完的buf
 * 2.把out_bufs中已经发送完的ngx_buf_t结构体清空重置（即把pos和last成员指向start）， 同时把它们追加到free_bufs链表中
 * 3.如果out_bufs中还有未发送完的ngx_buf_t结构体，那么添加到busy_bufs链表中。
 *  这一 步与ngx_http_upstream_non_buffered_filter方法的执行是对应的。
 */
/**
 * 1.如果out链表不为NULL，将其挂载到busy链表后
 * 2.从头遍历busy链表，如果buf已经被消费完了(pos=last), 将其插入到free链表头部。直到遇到首个还有数据待消费的buf, 将busy指向这个buf
 * 
 * 在遍历busy链表时，如果发现某个节点的buf的tag和参数中的tag不一样，会将其free掉(ngx_chain_t插入pool->chain链表头部)
 */
void
ngx_chain_update_chains(ngx_pool_t *p, ngx_chain_t **free, ngx_chain_t **busy,
    ngx_chain_t **out, ngx_buf_tag_t tag)
{
    ngx_chain_t  *cl;

    if (*out) {     //将out挂到busy链表上，然后out置为NULL
        if (*busy == NULL) {
            *busy = *out;

        } else {    //busy不为null, 找到busy的末尾，将out挂上去
            for (cl = *busy; cl->next; cl = cl->next) { /* void */ }

            cl->next = *out;
        }
        //将out置为null
        *out = NULL;
    }

    //遍历busy链， 1:清理tag不为参数tag的buf；2:清理已经被消费过的buf
    while (*busy) {
        cl = *busy;

        if (cl->buf->tag != tag) {
            *busy = cl->next;       //将cl节点从链表中摘除
            ngx_free_chain(p, cl);
            continue;
        }

        //判断cl->buf上是否还有未消费的数据，如果有，则跳出
        if (ngx_buf_size(cl->buf) != 0) {
            break;
        }

        //没有数据了， 重置cl->buf
        cl->buf->pos = cl->buf->start;
        cl->buf->last = cl->buf->start;

        //busy指向下一个chain
        *busy = cl->next;

        //将没有数据的buf放到free链表头
        cl->next = *free;
        *free = cl;     //加入free链
    }
}


/**
 * 更新in链表，根据已经消费的字节数，移动in链表中所有buf的pos
 * limit为已经消费掉的字节数
 * 返回未实际消费的字节数 total
 */
off_t
ngx_chain_coalesce_file(ngx_chain_t **in, off_t limit)
{
    off_t         total, size, aligned, fprev;
    ngx_fd_t      fd;
    ngx_chain_t  *cl;

    total = 0;

    cl = *in;
    fd = cl->buf->file->fd;

    do {
        //计算当前buf未消费的字节数
        size = cl->buf->file_last - cl->buf->file_pos;

        //如果size > 剩余的limit
        if (size > limit - total) {
            size = limit - total;

            aligned = (cl->buf->file_pos + size + ngx_pagesize - 1)
                       & ~((off_t) ngx_pagesize - 1);

            if (aligned <= cl->buf->file_last) {
                size = aligned - cl->buf->file_pos;
            }

            total += size;
            break;
        }

        //否则，更新total， 移动到下个cl
        total += size;
        fprev = cl->buf->file_pos + size;       //将当前cl标记为已消费
        cl = cl->next;

    } while (cl
             && cl->buf->in_file
             && total < limit
             && fd == cl->buf->file->fd
             && fprev == cl->buf->file_pos);

    *in = cl;

    return total;
}


/**
 * 更新in链表，根据已经消费的字节数，移动in链表中所有buf的pos
 * sent为已经消费掉的字节数
 * 返回链表为尚未消费或未消费完的第一个chain
 */
ngx_chain_t *
ngx_chain_update_sent(ngx_chain_t *in, off_t sent)
{
    off_t  size;

    //遍历链表
    for ( /* void */ ; in; in = in->next) {

        //不在内存也不在文件。同时flush、sync、last_buf 其中一个置位
        if (ngx_buf_special(in->buf)) {
            continue;
        }

        if (sent == 0) {        //之前的buf字节数刚好为sent
            break;
        }

        //当前buf上还没有消费完的数据
        size = ngx_buf_size(in->buf);

        if (sent >= size) {
            sent -= size;

            if (ngx_buf_in_memory(in->buf)) {
                in->buf->pos = in->buf->last;   //该buf已经被全部消费了
            }

            if (in->buf->in_file) {
                in->buf->file_pos = in->buf->file_last; //该buf已经被全部消费了
            }

            continue;
        }

        // sent < size 
        if (ngx_buf_in_memory(in->buf)) {
            in->buf->pos += (size_t) sent;  //移动pos指针
        }

        if (in->buf->in_file) {
            in->buf->file_pos += sent;      //移动pos指针
        }

        break;
    }

    return in;
}
