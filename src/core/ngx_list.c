
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


/**
 * 创建单向链表，返回ngx_list_t指针
 * n为每个ngx_list_part_t中元素个数，size为单个元素占用的空间
 */
ngx_list_t *
ngx_list_create(ngx_pool_t *pool, ngx_uint_t n, size_t size)
{
    ngx_list_t  *list;

    //创建一个ngx_list_t结构体
    list = ngx_palloc(pool, sizeof(ngx_list_t));
    if (list == NULL) {
        return NULL;
    }

    //初始化ngx_list_t结构体，分配第一个ngx_list_part_t的数组空间
    if (ngx_list_init(list, pool, n, size) != NGX_OK) {
        return NULL;
    }

    return list;
}


/**
 * 向单项链表尾部插入一个元素
 * 
 * 返回下一个未使用的数组元素位置
 */
void *
ngx_list_push(ngx_list_t *l)
{
    void             *elt;
    ngx_list_part_t  *last;

    last = l->last;     //最后一个part

    if (last->nelts == l->nalloc) { //如果最后一个part已经满了

        /* the last part is full, allocate a new list part */

        //申请一个新的part
        last = ngx_palloc(l->pool, sizeof(ngx_list_part_t));
        if (last == NULL) {
            return NULL;
        }

        //申请新part的数组空间
        last->elts = ngx_palloc(l->pool, l->nalloc * l->size);
        if (last->elts == NULL) {
            return NULL;
        }

        //新part的已使用元素个数
        last->nelts = 0;
        last->next = NULL;  //新part的next为NULL

        //将新part挂到单向链表末尾
        l->last->next = last;
        //更新l->last
        l->last = last;
    }

    //新加入元素的地址
    elt = (char *) last->elts + l->size * last->nelts;
    last->nelts++;  //已使用元素个数+1

    return elt;
}
