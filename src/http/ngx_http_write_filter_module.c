
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static ngx_int_t ngx_http_write_filter_init(ngx_conf_t *cf);


/**
 * 该模块负责向客户端发送HTTP响应
 * 作为body_filter的最后一个filter节点
 */
static ngx_http_module_t  ngx_http_write_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    //安装响应体的最后一个filter。处理响应头最后一个filter最后也调用这里的handler
    ngx_http_write_filter_init,            /* postconfiguration */  

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL,                                  /* merge location configuration */
};


ngx_module_t  ngx_http_write_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_write_filter_module_ctx,     /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


/**
 * 将in链表赋值到r->out末尾。
 * 发送r->out上的buf, 然后更新r->out为第一个待发送的chain
 * in为本次要发送的数据，将会被加入到out链表末尾
 * 
 * 1.检查当前连接的错误标志位 error，若该标志位为 1，表示当前请求出粗，则返回 NGX_ERROR 结束该函数，否则继续；
 * 2.遍历当前请求 ngx_http_request_t 结构体中的链表缓冲区成员out，计算剩余响应报文的长度size。因为当响应报文一次性不能发送完毕时，会把剩余的响应报文保存在out 中，相对于本次待发送的响应报文 in (即是该函数所传入的参数in )来说，out 链表缓冲区保存的是前一次剩余的响应报文；
 * 3.将本次待发送的响应报文的缓冲区 in 添加到 out 链表缓冲区的尾部，并计算待发送响应报文的总长度 size；
 * 4.若缓冲区 ngx_buf_t 块的 last_buf (即 last)、flush 标志位为0，则表示待发送的out 链表缓冲区没有一个是需要立刻发送响应报文，并且本次待发送的in 不为空，且待发送的响应报文数据总长度 size 小于postpone_output 参数（该参数由nginx.conf配置文件中设置），则不需要发送响应报文，即返回NGX_OK 结束该函数；
 * 5.若需要发送响应报文，则检查当前连接上写事件的 delayed 标志位，若为1，表示发送响应超速，则需要在epoll 事件机制中减速，所有相当于延迟发送响应报文，则返回NGX_AGIAN；
 * 6.若不需要延迟发送响应报文，检查当前请求的限速标志位 limit_rate，若该标志位设置为大于0，表示当前发送响应报文的速度不能超过limit_rate 值；
 * 7.根据限速值 r->limit_rate、当前客户开始接收响应的时间r->start_sec、在当前连接上已发送响应的长度c->sent、和limit_after 值计算本次可以发送的字节数limit，若limit 值不大于0，表示当前连接上发送响应的速度超过limit_rate 限速值，即本次不可以发送响应，因此将写事件的delayed 标志位设置为1，把写事件添加到定时器机制，并设置当前连接ngx_connection_t 结构体中的成员buffered 为NGX_HTTP_WRITE_BUFFERED（即可写状态），同时返回NGX_AGAIN，表示链表缓冲区out 还保存着剩余待发送的响应报文；
 * 8.若 limit 值大于 0，则根据 limit 值、配置项参数 sendfile_max_chunk 和待发送字节数 size 来计算本次发送响应的长度(即三者中的最小值)；
 * 9.根据前一步骤计算的可发送响应的长度，再次检查 limit_rate 标志位，若limit_rate 还是为1，表示继续需要限速检查。再按照前面的计算方法判断是否超过限速值limit_rate，若超过该限速值，则需再次把写事件添加到定时器机制中，标志位delayed 设置为1；
 * 10.若不会超过限速值，则发送响应，并重新调整链表缓冲区 out 的情况，把已发送响应数据的缓冲区进行回收内存；
 * 11.继续检查链表缓冲区 out 是否还存在数据，若存在数据，则表示未发送完毕，返回NGX_AGAIN，表示等待下次HTTP 框架被调用发送out 缓冲区剩余的响应数据；若不存在数据，则表示成功发送完整的响应数据，并返回NGX_OK；
 * 
 */
ngx_int_t
ngx_http_write_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    off_t                      size, sent, nsent, limit;
    ngx_uint_t                 last, flush, sync;
    ngx_msec_t                 delay;
    ngx_chain_t               *cl, *ln, **ll, *chain;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;

     /* 获取当前请求所对应的连接 */
    c = r->connection;

    /*
     * 检查当前连接的错误标志位error，若该标志位为1，
     * 表示当前请求出错，返回NGX_ERROR；
     */
    if (c->error) {         // 请求出错
        return NGX_ERROR;
    }

    size = 0;
    flush = 0;
    sync = 0;
    last = 0;
    ll = &r->out;

    /* find the size, the flush point and the last link of the saved chain */

    //遍历r->out, 直到最后一个节点。计算out缓冲区数据大小
    /*
     * 遍历当前请求out链表缓冲区，计算剩余响应报文的长度；
     * 因为当响应报文一次性不能发送完成时，会把剩余的响应报文保存在out中，
     * 相对于本次发送的响应报文数据in来说（即该方法所传入的参数in），
     * out链表缓冲区保存的是前一次剩余的响应报文；
     */
    for (cl = r->out; cl; cl = cl->next) {
        ll = &cl->next;

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "write old buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

        //buf为空，却不是控制buf    
        if (ngx_buf_size(cl->buf) == 0 && !ngx_buf_special(cl->buf)) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "zero size buf in writer "
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

        if (ngx_buf_size(cl->buf) < 0) {        //size<0, 非法的size
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "negative size buf in writer "
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

        size += ngx_buf_size(cl->buf);  //size记录了所有buf有效数据长度

        if (cl->buf->flush || cl->buf->recycled) {  //有flush节点
            flush = 1;
        }

        if (cl->buf->sync) {    //有sync节点
            sync = 1;
        }

        if (cl->buf->last_buf) {    //响应中的最后一个buf
            last = 1;
        }
    }

    /*
     * 将本次待发送的响应报文的缓冲区in添加到out链表缓冲区的尾部，
     * 并计算待发送响应报文总的长度size；
     */
    /* add the new chain to the existent one */
    //遍历in链表，将其buf复制in到out链表
    for (ln = in; ln; ln = ln->next) {
        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = ln->buf;
        *ll = cl;       /* 由上面可知 ll=&r->out */
        ll = &cl->next;

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "write new buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

        if (ngx_buf_size(cl->buf) == 0 && !ngx_buf_special(cl->buf)) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "zero size buf in writer "
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

        if (ngx_buf_size(cl->buf) < 0) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "negative size buf in writer "
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

        size += ngx_buf_size(cl->buf);  //更新size

        if (cl->buf->flush || cl->buf->recycled) {
            flush = 1;
        }

        if (cl->buf->sync) {
            sync = 1;
        }

        if (cl->buf->last_buf) {
            last = 1;
        }
    }

    *ll = NULL;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter: l:%ui f:%ui s:%O", last, flush, size);

     /* 获取ngx_http_core_module模块的loc级别配置项结构体 */               
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    /*
     * avoid the output if there are no last buf, no flush point,
     * there are the incoming bufs and the size of all bufs
     * is smaller than "postpone_output" directive
     */

     /*
     * 若out链表最后一块缓冲区last为空，且没有强制性刷新flush链表缓冲区out，
     * 且当前有待发响应报文in，但是待发送响应报文总的长度size小于预设可发送条件值postpone_output,
     * 则本次不能发送响应报文，继续保存在out链表缓冲区中，以待下次才发送；
     * 其中postpone_output预设值我们可以在配置文件nginx.conf中设置；
     */
     //如果len小于postpone_output,并且没有flush和last, 直接返回
     //https://nginx.org/en/docs/http/ngx_http_core_module.html#postpone_output 默认1460
     //the size of all bufs is smaller than "postpone_output" directive
    if (!last && !flush && in && size < (off_t) clcf->postpone_output) {
        return NGX_OK;
    }

     /*
     * 检查当前连接上写事件的delayed标志位，
     * 若该标志位为1，表示需要延迟发送响应报文，
     * 因此，返回NGX_AGAIN，表示延迟发送；
     */
    if (c->write->delayed) {    //delay表示响应需要延长发送
        c->buffered |= NGX_HTTP_WRITE_BUFFERED;
        return NGX_AGAIN;
    }

    if (size == 0
        && !(c->buffered & NGX_LOWLEVEL_BUFFERED)
        && !(last && c->need_last_buf)
        && !(flush && c->need_flush_buf))
    {
        if (last || flush || sync) {
            for (cl = r->out; cl; /* void */) {
                ln = cl;
                cl = cl->next;
                ngx_free_chain(r->pool, ln);    //size==0说明r->out 都没数据了,可以回收掉了
            }

            r->out = NULL;
            c->buffered &= ~NGX_HTTP_WRITE_BUFFERED;

            if (last) {
                r->response_sent = 1;
            }

            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "the http output chain is empty");

        ngx_debug_point();

        return NGX_ERROR;
    }

    if (!r->limit_rate_set) {       //计算限速
        r->limit_rate = ngx_http_complex_value_size(r, clcf->limit_rate, 0);
        r->limit_rate_set = 1;
    }

    /*
     * 检查当前请求的限速标志位limit_rate，
     * 若该标志位为大于0，表示发送响应报文的速度不能超过limit_rate指定的速度；
     */
    if (r->limit_rate) {

        if (!r->limit_rate_after_set) {
            r->limit_rate_after = ngx_http_complex_value_size(r,
                                                    clcf->limit_rate_after, 0);
            r->limit_rate_after_set = 1;
        }

        /* 计算发送速度是否超过限速值 */
        limit = (off_t) r->limit_rate * (ngx_time() - r->start_sec + 1)
                - (c->sent - r->limit_rate_after);

         /*
         * 若当前发送响应报文的速度超过限速值，则写事件标志位delayed设为1，
         * 并把该写事件添加到定时器机制中，并且将buffered设置为可写状态，
         * 返回NGX_AGAIN，表示链表缓冲区out还保存剩余待发送的响应报文；
         */        
        if (limit <= 0) {
            c->write->delayed = 1;
            delay = (ngx_msec_t) (- limit * 1000 / r->limit_rate + 1);
            ngx_add_timer(c->write, delay);

            c->buffered |= NGX_HTTP_WRITE_BUFFERED;

            return NGX_AGAIN;
        }

        if (clcf->sendfile_max_chunk
            && (off_t) clcf->sendfile_max_chunk < limit)
        {
            limit = clcf->sendfile_max_chunk;
        }

    } else {
        limit = clcf->sendfile_max_chunk;
    }

    /* 若不需要减速，或没有设置速度限制，则向客户端发送响应字符流 */
    sent = c->sent;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter limit %O", limit);

    chain = c->send_chain(c, r->out, limit);        //将r->out中的数据输出， ngx_writev_chain

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter %p", chain);

    if (chain == NGX_CHAIN_ERROR) {
        c->error = 1;
        return NGX_ERROR;
    }

    /* 再次检查limit_rate标志位 */
    if (r->limit_rate) {

        nsent = c->sent;

        if (r->limit_rate_after) {

            sent -= r->limit_rate_after;
            if (sent < 0) {
                sent = 0;
            }

            nsent -= r->limit_rate_after;
            if (nsent < 0) {
                nsent = 0;
            }
        }

        /* 再次计算当前发送响应报文速度是否超过限制值 */
        delay = (ngx_msec_t) ((nsent - sent) * 1000 / r->limit_rate);

        /* 再次计算当前发送响应报文速度是否超过限制值 */
        if (delay > 0) {
            c->write->delayed = 1;
            ngx_add_timer(c->write, delay);
        }
    }

    if (chain && c->write->ready && !c->write->delayed) {
        ngx_post_event(c->write, &ngx_posted_next_events);
    }

    /* 重新调整链表缓冲区out的情况，把已发送数据的缓冲区内存回收 */
    //chain之前的buf已经消费掉了，可以清理了
    for (cl = r->out; cl && cl != chain; /* void */) {
        ln = cl;
        cl = cl->next;
        ngx_free_chain(r->pool, ln);
    }

    /* 检查out链表缓冲区是否还有数据 */
    r->out = chain;     //r->out指向待发送的chain

    /* 若还有数据，返回NGX_AGAIN，表示还存在待发送的响应报文数据 */
    if (chain) {
        c->buffered |= NGX_HTTP_WRITE_BUFFERED;
        return NGX_AGAIN;
    }

    c->buffered &= ~NGX_HTTP_WRITE_BUFFERED;

    if (last) {
        r->response_sent = 1;
    }

    if ((c->buffered & NGX_LOWLEVEL_BUFFERED) && r->postponed == NULL) {
        return NGX_AGAIN;
    }

    /* 若已发送全部数据则返回NGX_OK */
    return NGX_OK;
}


static ngx_int_t
ngx_http_write_filter_init(ngx_conf_t *cf)
{
    /* 调用模块的回调方法 */
    ngx_http_top_body_filter = ngx_http_write_filter;

    return NGX_OK;
}
