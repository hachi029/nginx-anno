
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


static void ngx_queue_merge(ngx_queue_t *queue, ngx_queue_t *tail,
    ngx_int_t (*cmp)(const ngx_queue_t *, const ngx_queue_t *));


/*
 * find the middle queue element if the queue has odd number of elements
 * or the first element of the queue's second part otherwise
 */

 /* 返回队列链表中心元素 第n/2+1个*/
ngx_queue_t *
ngx_queue_middle(ngx_queue_t *queue)
{
    ngx_queue_t  *middle, *next;

    /* 获取队列链表头节点 */
    middle = ngx_queue_head(queue);

     /* 若队列链表的头节点就是尾节点，表示该队列链表只有一个元素 */
    if (middle == ngx_queue_last(queue)) {
        return middle;
    }

    /* next作为临时指针，首先指向队列链表的头节点 */
    next = ngx_queue_head(queue);

    //快慢指针法
    for ( ;; ) {
         /* 若队列链表不止一个元素，则等价于middle = middle->next */
        middle = ngx_queue_next(middle);

        next = ngx_queue_next(next);

          /* 队列链表有偶数个元素 */
        if (next == ngx_queue_last(queue)) {
            return middle;
        }

        next = ngx_queue_next(next);

        /* 队列链表有奇数个元素 */
        if (next == ngx_queue_last(queue)) {
            return middle;
        }
    }
}


/* the stable merge sort */

/**
 * 链表排序
 * 
 * 使用插入排序法
 */
void
ngx_queue_sort(ngx_queue_t *queue,
    ngx_int_t (*cmp)(const ngx_queue_t *, const ngx_queue_t *))
{
    ngx_queue_t  *q, tail;

    //头结点
    q = ngx_queue_head(queue);

    /* 若队列链表只有一个元素，则直接返回 */
    if (q == ngx_queue_last(queue)) {
        return;
    }

    //找到中间节点
    q = ngx_queue_middle(queue);

    ngx_queue_split(queue, q, &tail);

    ngx_queue_sort(queue, cmp);
    ngx_queue_sort(&tail, cmp);

    ngx_queue_merge(queue, &tail, cmp);
}


static void
ngx_queue_merge(ngx_queue_t *queue, ngx_queue_t *tail,
    ngx_int_t (*cmp)(const ngx_queue_t *, const ngx_queue_t *))
{
    ngx_queue_t  *q1, *q2;

    q1 = ngx_queue_head(queue);
    q2 = ngx_queue_head(tail);

    for ( ;; ) {
        if (q1 == ngx_queue_sentinel(queue)) {
            ngx_queue_add(queue, tail);
            break;
        }

        if (q2 == ngx_queue_sentinel(tail)) {
            break;
        }

        if (cmp(q1, q2) <= 0) {
            q1 = ngx_queue_next(q1);
            continue;
        }

        ngx_queue_remove(q2);
        ngx_queue_insert_before(q1, q2);

        q2 = ngx_queue_head(tail);
    }
}
