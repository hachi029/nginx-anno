
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef _NGX_QUEUE_H_INCLUDED_
#define _NGX_QUEUE_H_INCLUDED_


typedef struct ngx_queue_s  ngx_queue_t;

/**
 * 
 * 双向链表
 * 不负责分配内存来存放链表元素, 实现了排序功能
 * 
 * 非常轻量级，对每个用户数据而言，只需要增加两个指针的空间即可
 * 
 * 
 * 对于链表中的每一个元素，其类型可以是任意的struct结构体，但这个结构体中必须要有一个ngx_queue_t类型的成员
 */
struct ngx_queue_s {
    ngx_queue_t  *prev;
    ngx_queue_t  *next;
};


/* h 为链表结构体 ngx_queue_t 的指针；初始化双链表 */
#define ngx_queue_init(q)                                                     \
    (q)->prev = q;                                                            \
    (q)->next = q


/* h 为链表容器结构体 ngx_queue_t 的指针； 判断链表是否为空 */
#define ngx_queue_empty(h)                                                    \
    (h == (h)->prev)


/* h 为链表容器结构体 ngx_queue_t 的指针，x 为插入元素结构体中 ngx_queue_t 成员的指针；将 x 插入到链表头部 */
#define ngx_queue_insert_head(h, x)                                           \
    (x)->next = (h)->next;                                                    \
    (x)->next->prev = x;                                                      \
    (x)->prev = h;                                                            \
    (h)->next = x


#define ngx_queue_insert_after   ngx_queue_insert_head


/*将 x 插入到链表尾部 */
#define ngx_queue_insert_tail(h, x)                                           \
    (x)->prev = (h)->prev;                                                    \
    (x)->prev->next = x;                                                      \
    (x)->next = h;                                                            \
    (h)->prev = x


#define ngx_queue_insert_before   ngx_queue_insert_tail


/* 获取队列尾头节点 */
#define ngx_queue_head(h)                                                     \
    (h)->next


/* 获取队列尾节点 */
#define ngx_queue_last(h)                                                     \
    (h)->prev


#define ngx_queue_sentinel(h)                                                 \
    (h)


/*返回 q 元素的下一个元素。*/
#define ngx_queue_next(q)                                                     \
    (q)->next


/*返回 q 元素的上一个元素。*/
#define ngx_queue_prev(q)                                                     \
    (q)->prev


#if (NGX_DEBUG)

/*从queue中移除x元素*/
#define ngx_queue_remove(x)                                                   \
    (x)->next->prev = (x)->prev;                                              \
    (x)->prev->next = (x)->next;                                              \
    (x)->prev = NULL;                                                         \
    (x)->next = NULL

#else

/*从容器中移除 x 元素*/
#define ngx_queue_remove(x)                                                   \
    (x)->next->prev = (x)->prev;                                              \
    (x)->prev->next = (x)->next

#endif


/* h 为链表容器结构体 ngx_queue_t 的指针。该函数用于拆分链表，
 * h 是链表容器，而 q 是链表 h 中的一个元素。
 * 将链表 h 以元素 q 为界拆分成两个链表 h 和 n
 * 
 * 拆分后，原始队列以q为分界，头节点h到q之前的节点作为一个队列（不包括q节点），
 * 另一个队列是以n为头节点，以节点q及其之后的节点作为新的队列链表；
 * 
 */
#define ngx_queue_split(h, q, n)                                              \
    (n)->prev = (h)->prev;                                                    \
    (n)->prev->next = n;                                                      \
    (n)->next = q;                                                            \
    (h)->prev = (q)->prev;                                                    \
    (h)->prev->next = h;                                                      \
    (q)->prev = n;


/* 
 * 合并链表，将 n 链表添加到 h 链表的末尾
 * h 为链表容器结构体 ngx_queue_t 的指针， n为另一个链表容器结构体 ngx_queue_t 的指针
 */
#define ngx_queue_add(h, n)                                                   \
    (h)->prev->next = (n)->next;                                              \
    (n)->next->prev = (h)->prev;                                              \
    (h)->prev = (n)->prev;                                                    \
    (h)->prev->next = h;


/**
 * 返回q元素所属结构体的地址
 * q: 当前节点
 * type: 包含ngx_queue_t的数据节点类型定义
 * link: ngx_queue_t类型的成员
 */
#define ngx_queue_data(q, type, link)                                         \
    (type *) ((u_char *) q - offsetof(type, link))


/*返回链表中心元素，即第 N/2 + 1 个 */
ngx_queue_t *ngx_queue_middle(ngx_queue_t *queue);
/* h 为链表容器结构体 ngx_queue_t cmp 是比较回调函数。使用插入排序对链表进行排序 */
void ngx_queue_sort(ngx_queue_t *queue,
    ngx_int_t (*cmp)(const ngx_queue_t *, const ngx_queue_t *));


#endif /* _NGX_QUEUE_H_INCLUDED_ */
