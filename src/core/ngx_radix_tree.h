
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_RADIX_TREE_H_INCLUDED_
#define _NGX_RADIX_TREE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_RADIX_NO_VALUE   (uintptr_t) -1

typedef struct ngx_radix_node_s  ngx_radix_node_t;

/**
 * 基数树的节点
 * 
 */
struct ngx_radix_node_s {
    ngx_radix_node_t  *right;   //指向右子树，如果没有右子树，则值为null
    ngx_radix_node_t  *left;    // 指向左子树，如果没有左子树，则值为null空指针
    ngx_radix_node_t  *parent;  // 指向父节点，如果没有父节点，则（如根节点）值为 null空指针
    //value存储的是指针的值，它指向用户定义的数据结构。如果这个节点还未使用，value的值将是 NGX_RADIX_NO_VALUE
    uintptr_t          value;   //可以存储的值只是1个指针，它指向实际的数据
};

/**
 * 基数树
 * 
 * 必须以32位整型数据作为关键字,是按二进制位来建立树
 * 
 * 插入、删除元素时不需要做旋转 操作，因此它的插入、删除效率一般要比ngx_rbtree_t红黑树高
 * 
 * 每一个节点的key关键字已经决定了这个节点处于树中的位置,
 * 决定节点位置的方法为：先将这个节点的整型关键字转化为二进制，从左向右数这32个位，遇到0时进入左子树，
 * 遇到1时进入右子树。因此，ngx_radix_tree_t树的最大深度是32
 * 
 * 为了减少树的高度，ngx_radix_tree_t又加入了掩码的概念，掩码中为1的位节点关键字中有效的位数同时也决定了树的有效高度
 * 
 */
typedef struct {
    ngx_radix_node_t  *root;    // 指向根节点
    ngx_pool_t        *pool;    //内存池，它负责给基数树的节点分配内存
    //每次删除1个节点时，ngx_radix_tree_t基数树并不会释放 这个节点占用的内存，而是把它添加到free单链表中
    //在添加新的节点时，会首先查 看free中是否还有节点，如果free中有未使用的节点，
    //则会优先使用，如果没有，就会再从 pool内存池中分配新内存存储节点
    ngx_radix_node_t  *free;    //管理已经分配但暂时未使用（不在树中）的节点，free实际上是所有不在树中节点的单链表
    char              *start;   //已分配内存中还未使用内存的首地址
    size_t             size;    //已分配内存中还未使用的内存大小
} ngx_radix_tree_t;

/**
 * 创建基数树
 */
ngx_radix_tree_t *ngx_radix_tree_create(ngx_pool_t *pool,
    ngx_int_t preallocate);

ngx_int_t ngx_radix32tree_insert(ngx_radix_tree_t *tree,
    uint32_t key, uint32_t mask, uintptr_t value);
ngx_int_t ngx_radix32tree_delete(ngx_radix_tree_t *tree,
    uint32_t key, uint32_t mask);
uintptr_t ngx_radix32tree_find(ngx_radix_tree_t *tree, uint32_t key);

#if (NGX_HAVE_INET6)
ngx_int_t ngx_radix128tree_insert(ngx_radix_tree_t *tree,
    u_char *key, u_char *mask, uintptr_t value);
ngx_int_t ngx_radix128tree_delete(ngx_radix_tree_t *tree,
    u_char *key, u_char *mask);
uintptr_t ngx_radix128tree_find(ngx_radix_tree_t *tree, u_char *key);
#endif


#endif /* _NGX_RADIX_TREE_H_INCLUDED_ */
