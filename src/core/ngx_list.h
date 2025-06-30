
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_LIST_H_INCLUDED_
#define _NGX_LIST_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_list_part_s  ngx_list_part_t;

//描述单项链表的一个元素
struct ngx_list_part_s {
    void             *elts;     //指向数组的起始地址
    ngx_uint_t        nelts;    //表示数组中已经使用了多少个元素
    ngx_list_part_t  *next;     //下一个链表元素ngx_list_part_t的地址
};


/**
 * 描述整个链表
 * 
 * 是一个单向链表，称为存储数组的链表， 每个链表元素ngx_list_part_t又是一个数组
 * 用单链表将多段连续内存块连接起来，每段连续内存块存储了多个元素. 多个相同大小数组组成的链表
 */
typedef struct {
    ngx_list_part_t  *last; //指向链表的最后一个数组part
    ngx_list_part_t   part; //链表的首个数组元素
    size_t            size; //每一个数组元素的占用的空间大小
    ngx_uint_t        nalloc; //表示每个ngx_list_part_t数组的容量，即最多可存储多少个数据
    ngx_pool_t       *pool; //链表中管理内存分配的内存池对象
} ngx_list_t;


/**
 * 创建新的链表
 * 返回新创建的链表地址
 */
ngx_list_t *ngx_list_create(ngx_pool_t *pool, ngx_uint_t n, size_t size);

/**
 * 用于初始化一个已有的链表.主要是分配第一个part中的数组
 */
static ngx_inline ngx_int_t
ngx_list_init(ngx_list_t *list, ngx_pool_t *pool, ngx_uint_t n, size_t size)
{
    list->part.elts = ngx_palloc(pool, n * size);
    if (list->part.elts == NULL) {
        return NGX_ERROR;
    }

    list->part.nelts = 0;       //数组中已经使用了多少个元素
    list->part.next = NULL;     //下一个part
    list->last = &list->part;   //最后一个part
    list->size = size;          //每个数组元素的长度
    list->nalloc = n;           //每个part的元素个数
    list->pool = pool;

    return NGX_OK;
}


/*
 *
 *  the iteration through the list:
 *
 *  part = &list.part;
 *  data = part->elts;
 *
 *  for (i = 0 ;; i++) {
 *
 *      if (i >= part->nelts) {
 *          if (part->next == NULL) {
 *              break;
 *          }
 *
 *          part = part->next;
 *          data = part->elts;
 *          i = 0;
 *      }
 *
 *      ...  data[i] ...
 *
 *  }
 */


/**
 * 向list中添加新的元素。
 * 返回的是新分配的元素首地址
 */
void *ngx_list_push(ngx_list_t *list);


#endif /* _NGX_LIST_H_INCLUDED_ */
