
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


/**
 * 所有定时器事件组成的红黑树,红黑树中的每个节点都是ngx_event_t事件中的timer成员
 * 而ngx_rbtree_node_t节点的 关键字就是事件的超时时间，以这个超时时间的大小组成了二叉排序树
 * 该红黑树中最左边的节点代表最可能超时的事件
 * 
 */
ngx_rbtree_t              ngx_event_timer_rbtree;
/**
 * 这棵红黑树的哨兵节点
 */
static ngx_rbtree_node_t  ngx_event_timer_sentinel;

/*
 * the event timer rbtree may contain the duplicate keys, however,
 * it should not be a problem, because we use the rbtree to find
 * a minimum timer value only
 */

 /* 定时器事件初始化， 实际上就是调用红黑树的初始化 */
ngx_int_t
ngx_event_timer_init(ngx_log_t *log)
{
    /* 初始化红黑树 */
    ngx_rbtree_init(&ngx_event_timer_rbtree, &ngx_event_timer_sentinel,
                    ngx_rbtree_insert_timer_value);

    return NGX_OK;
}


/**
 *  调用一次 ngx_event_expire_timers方法的频率
 *  返回下一个最近的超时事件多久后会发生， 即找出定时器红黑树最左边的节点
 * 
 */
ngx_msec_t
ngx_event_find_timer(void)
{
    ngx_msec_int_t      timer;
    ngx_rbtree_node_t  *node, *root, *sentinel;

    //定时器为空
    if (ngx_event_timer_rbtree.root == &ngx_event_timer_sentinel) {
        return NGX_TIMER_INFINITE;
    }

    root = ngx_event_timer_rbtree.root;
    sentinel = ngx_event_timer_rbtree.sentinel;

    /* 找出红黑树最小的节点，即最左边的节点 */
    node = ngx_rbtree_min(root, sentinel);

    //是否超时： 过期时间-当前时间
    timer = (ngx_msec_int_t) (node->key - ngx_current_msec);

     /*
     * 若timer大于0，则事件不超时，返回该值；
     * 若timer不大于0，则事件超时，返回0，标志触发超时事件；
     */
    return (ngx_msec_t) (timer > 0 ? timer : 0);
}


/**
 * 触发所有超时的事件,在这个方法中，循环调用所有满足超时条件的事件的handler回调方法
 */
void
ngx_event_expire_timers(void)
{
    ngx_event_t        *ev;
    ngx_rbtree_node_t  *node, *root, *sentinel;

    sentinel = ngx_event_timer_rbtree.sentinel;

    /* 循环检查 */
    for ( ;; ) {
        root = ngx_event_timer_rbtree.root;

        /* 若定时器红黑树为空，则直接返回，不做任何处理 */
        if (root == sentinel) {
            return;
        }

        /* 找出定时器红黑树最左边的节点，即最小的节点，同时也是最有可能超时的事件对象 */
        node = ngx_rbtree_min(root, sentinel);

        /* node->key > ngx_current_msec */

        if ((ngx_msec_int_t) (node->key - ngx_current_msec) > 0) {
            return;
        }

        /* 若检查到的当前事件已超时 */
         /* 获取超时的具体事件 */
        ev = ngx_rbtree_data(node, ngx_event_t, timer);

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "event timer del: %d: %M",
                       ngx_event_ident(ev->data), ev->timer.key);

        /* 将已超时事件对象从现有定时器红黑树中移除 */
        ngx_rbtree_delete(&ngx_event_timer_rbtree, &ev->timer);

#if (NGX_DEBUG)
        ev->timer.left = NULL;
        ev->timer.right = NULL;
        ev->timer.parent = NULL;
#endif

        /* 设置事件的在定时器红黑树中的监控标志位 */
        ev->timer_set = 0;

        /* 设置事件的超时标志位 */
        ev->timedout = 1;       /* 1表示已经超时 */

        /* 调用已超时事件的处理函数对该事件进行处理 */
        ev->handler(ev);
    }
}


ngx_int_t
ngx_event_no_timers_left(void)
{
    ngx_event_t        *ev;
    ngx_rbtree_node_t  *node, *root, *sentinel;

    sentinel = ngx_event_timer_rbtree.sentinel;
    root = ngx_event_timer_rbtree.root;

    if (root == sentinel) {
        return NGX_OK;
    }

    for (node = ngx_rbtree_min(root, sentinel);
         node;
         node = ngx_rbtree_next(&ngx_event_timer_rbtree, node))
    {
        ev = ngx_rbtree_data(node, ngx_event_t, timer);

        if (!ev->cancelable) {
            return NGX_AGAIN;
        }
    }

    /* only cancelable timers left */

    return NGX_OK;
}
