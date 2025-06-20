
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


/**
 * 创建动态数组
 * n: 为初始化数组大小
 * size: 为单个数组元素大小
 */
ngx_array_t *
ngx_array_create(ngx_pool_t *p, ngx_uint_t n, size_t size)
{
    ngx_array_t *a;

    //只是创建了ngx_array_t结构体本身
    a = ngx_palloc(p, sizeof(ngx_array_t));
    if (a == NULL) {
        return NULL;
    }

    //分配元素占用的内存，初始化相关字段
    if (ngx_array_init(a, p, n, size) != NGX_OK) {
        return NULL;
    }

    return a;
}


/**
 * 销毁动态内存
 * 
 * 会去检查数组是否在内存池内存块上的结尾部分，如果在结尾部分，则将内存回收给内存池。
 * 
 */
void
ngx_array_destroy(ngx_array_t *a)
{
    ngx_pool_t  *p;

    p = a->pool;

    //这里只检查pool的小块内存池，通常认为ngx_array_t分配的是小块内存

    //如果当前数组结尾地址就是pool可用内存的起始地址，那么只需要移动p的last指针即可
    if ((u_char *) a->elts + a->size * a->nalloc == p->d.last) {
        p->d.last -= a->size * a->nalloc;
    }

    //如果当前数组的位置+sizeof(ngx_array_t) 就是pool可用内存的起始地址
    // 将pool可用内存的起始地址左移sizeof(ngx_array_t)
    if ((u_char *) a + sizeof(ngx_array_t) == p->d.last) {
        p->d.last = (u_char *) a;
    }
}


/**
 * 向a指向的数组中添加一个元素
 */
void *
ngx_array_push(ngx_array_t *a)
{
    void        *elt, *new;
    size_t       size;
    ngx_pool_t  *p;

    //数组已经满了，需要扩容。
    /**
     * 扩容有两种方式
     * 1.如果数组元素的末尾和内存池pool的可用开始的地址相同，并且内存池剩余的空间支持数组扩容，则在当前内存池上扩容
     * 2. 如果扩容的大小超出了当前内存池剩余的容量或者数组元素的末尾和内存池pool的可用开始的地址不相同，
     * 则需要重新分配一个新的内存块存储数组，并且将原数组拷贝到新的地址上
     */
    if (a->nelts == a->nalloc) {

        /* the array is full */

        //size是当前数组占用的空间（每个元素的大小*数组中元素个数）
        size = a->size * a->nalloc;

        p = a->pool;

        //1.如果当前数组结尾地址就是pool可用内存的起始地址，那么只需要移动p的last指针即可
        if ((u_char *) a->elts + size == p->d.last
            && p->d.last + a->size <= p->d.end)
        {
            /*
             * the array allocation is the last in the pool
             * and there is space for new allocation
             */

            p->d.last += a->size;   //移动d.last位置
            a->nalloc++;            //可存储元素数量+1

        } else {
            /* allocate a new array */
            //2.否则扩容2倍
            new = ngx_palloc(p, 2 * size);
            if (new == NULL) {
                return NULL;
            }

            //将之前的元素拷贝到新数组中
            ngx_memcpy(new, a->elts, size);
            a->elts = new;      
            a->nalloc *= 2;     //可存储元素数量*2
        }
    }

    //elt为新分配元素的地址
    elt = (u_char *) a->elts + a->size * a->nelts;
    a->nelts++;

    return elt;
}


/**
 * 向当前a动态数组中添加n个元素，返回的是新添加这批元素中第一个元素的地址
 */
void *
ngx_array_push_n(ngx_array_t *a, ngx_uint_t n)
{
    void        *elt, *new;
    size_t       size;
    ngx_uint_t   nalloc;
    ngx_pool_t  *p;

    //size是存储n个元素所需的空间
    size = n * a->size;

    //如果数组剩余空间不够存储n个元素
    if (a->nelts + n > a->nalloc) {

        /* the array is full */

        p = a->pool;

        //1.如果当前数组结尾地址就是pool可用内存的起始地址，那么只需要移动p的last指针即可
        if ((u_char *) a->elts + a->size * a->nalloc == p->d.last
            && p->d.last + size <= p->d.end)
        {
            /*
             * the array allocation is the last in the pool
             * and there is space for new allocation
             */

            p->d.last += size;    //移动d.last位置
            a->nalloc += n;       //可存储元素数量+n

        } else {
            /* allocate a new array */
            //否则， 如果n > 数组可容纳元素的个数，则扩容为2n;
            //      否则扩容为2*a->nalloc
            nalloc = 2 * ((n >= a->nalloc) ? n : a->nalloc);

            new = ngx_palloc(p, nalloc * a->size);  //申请空间
            if (new == NULL) {
                return NULL;
            }

            ngx_memcpy(new, a->elts, a->nelts * a->size);   //复制内存
            a->elts = new;  //数组起始位置指向新申请的内存
            a->nalloc = nalloc; //更新可容纳元素个数
        }
    }

    elt = (u_char *) a->elts + a->size * a->nelts;
    a->nelts += n;

    return elt;
}
