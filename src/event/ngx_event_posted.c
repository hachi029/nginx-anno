
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


/**
 * 将epoll_wait产生的一批事件，分到这两个队列中，让存放着新连接事件的 ngx_posted_accept_events队列优先执行，存放普通事件的ngx_posted_events队列最后执行，这
    是解决“惊群”和负载均衡两个问题的关键

    如果在处理一个事件的过程中产生了另一个事件，而我们希望这个事件随后执行（不是立刻执行），就可以把它放到post队列中
 */

/**
 * 
 * ngx_posted_accept_events队列和 ngx_posted_events队列把这批事件归类了，
 * 即新连接事件全部放到ngx_posted_accept_events队 列中，普通事件则放到ngx_posted_events队列中。
 * 这样，接下来会先处理 ngx_posted_accept_events队列中的事件，处理完后就要立刻释放ngx_accept_mutex锁，
 * 接着再处理ngx_posted_events队列中的事件，这样就大大减少了ngx_accept_mutex锁占 用的时间
 */
//由被触发的监听连接的读 事件构成的ngx_posted_accept_events队列
ngx_queue_t  ngx_posted_accept_events;  //都指向事件队列中的首个事件
ngx_queue_t  ngx_posted_next_events;
//由普通读/写事件构成的 ngx_posted_events队列.存放暂时不需要处理的事件
ngx_queue_t  ngx_posted_events;


/**
 * 执行posted队列中的事件
 */
void
ngx_event_process_posted(ngx_cycle_t *cycle, ngx_queue_t *posted)
{
    ngx_queue_t  *q;
    ngx_event_t  *ev;

    while (!ngx_queue_empty(posted)) {

        q = ngx_queue_head(posted);
        ev = ngx_queue_data(q, ngx_event_t, queue);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                      "posted event %p", ev);

        ngx_delete_posted_event(ev);

        ev->handler(ev);
    }
}


void
ngx_event_move_posted_next(ngx_cycle_t *cycle)
{
    ngx_queue_t  *q;
    ngx_event_t  *ev;

    for (q = ngx_queue_head(&ngx_posted_next_events);
         q != ngx_queue_sentinel(&ngx_posted_next_events);
         q = ngx_queue_next(q))
    {
        ev = ngx_queue_data(q, ngx_event_t, queue);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                      "posted next event %p", ev);

        ev->ready = 1;
        ev->available = -1;
    }

    ngx_queue_add(&ngx_posted_events, &ngx_posted_next_events);
    ngx_queue_init(&ngx_posted_next_events);
}
