
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_RBTREE_H_INCLUDED_
#define _NGX_RBTREE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


// 红黑树的key类型，无符号整数
// 通常我们使用这个key类型
typedef ngx_uint_t  ngx_rbtree_key_t;
// 红黑树的key类型，有符号整数
typedef ngx_int_t   ngx_rbtree_key_int_t;


// 红黑树节点
typedef struct ngx_rbtree_node_s  ngx_rbtree_node_t;

/**
 * 代表红黑树节点，节点可以是任意包含ngx_rbtree_node_t成员的结构体
 * 一般它放到结构体中的第1个成员中，这样方便把自定义的结构体强制转换成ngx_rbtree_node_t类型
 */
struct ngx_rbtree_node_s {
    ngx_rbtree_key_t       key;     // 无符号整型的关键字
    ngx_rbtree_node_t     *left;    // 左子节点
    ngx_rbtree_node_t     *right;   // 右子节点
    ngx_rbtree_node_t     *parent;  // 父节点
    u_char                 color;   // 节点的颜色， 0表示黑色， 1表示红色
    u_char                 data;    // 仅 1个字节的节点数据。由于表示的空间太小，所以一般很少使用
};


// 定义红黑树结构
typedef struct ngx_rbtree_s  ngx_rbtree_t;

// 插入红黑树的函数指针
typedef void (*ngx_rbtree_insert_pt) (ngx_rbtree_node_t *root,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);

/**
 * 红黑树, 当需要容器的检索速度很快，或者需要支持范围查询时
 * 1：节点是红色或黑色;
 * 2：根节点是黑色;
 * 3：所有叶子节点都是黑色（叶子是NIL节点，也叫“哨兵”）。
 * 4: 每个红色节点的两个子节点都是黑色（每个叶子节点到根节点的所有路径上不能有两个连续的红色节点）
 * 5: 从任一节点到其每个叶子节点的所有简单路径都包含相同数目的黑色节点
 * 
 * 红黑树的关键性质：从根节点到叶子节点的最长可能路径长度不大于最短可能路径的两倍
 * 
 * 特性4实际上决定了1个路径不能有两个毗连的红色节点，这一点就足够了。
 * 最短的可能路径都是黑色节点，最长的可能路径有交替的红色节点和黑色节点。
 * 根据特性5可知，所有最长的路径都有相同数目的黑色节点，这就表明了没有路径能大于其他路径长度的两倍。
 * 
 * 
 */
struct ngx_rbtree_s {
    // 指向树的根节点。注意，根节点也是数据元素
    ngx_rbtree_node_t     *root;
    //作用等同于NULL, 所有子节点为null的节点的子节点指针指向sentinel
    ngx_rbtree_node_t     *sentinel;    // 指向 NIL哨兵节点

    // 表示红黑树添加元素的函数指针，它决定在添加新节点时的行为究竟是替换还是新增
    /**
     * 很多场合下是允许不同的节点拥有相同的关键字的.例如，不同的字符串可能会散列出相同的关键字，
     * 这时它们在红黑树中的关键字是相同的，然而它们又是不同的节点，这样在添加时就不可以覆盖原有同名关键字节点，
     * 而是作为新插入的节点存 在。因此，在添加元素时，需要考虑到这种情况。将添加元素的方法抽象出
     * 
     * 参考 ngx_rbtree_insert_pt
     * 
     * 处理的主要问题就是当key关键字相同时，继续以何种数据结构作为标准来确定红黑树节点的唯一性
     */
    ngx_rbtree_insert_pt   insert;
};


/* 初始化红黑树，即为空的红黑树
 * tree 是指向红黑树的指针，
 * s 是红黑树的一个NIL节点，
 * i 表示函数指针，决定节点是新增还是替换
 */
#define ngx_rbtree_init(tree, s, i)                                           \
    ngx_rbtree_sentinel_init(s);                                              \
    (tree)->root = s;                                                         \
    (tree)->sentinel = s;                                                     \
    (tree)->insert = i

#define ngx_rbtree_data(node, type, link)                                     \
    (type *) ((u_char *) (node) - offsetof(type, link))


// 向红黑树插入一个节点
// 插入后旋转红黑树，保持平衡
void ngx_rbtree_insert(ngx_rbtree_t *tree, ngx_rbtree_node_t *node);
// 在红黑树里删除一个节点
void ngx_rbtree_delete(ngx_rbtree_t *tree, ngx_rbtree_node_t *node);
// 普通红黑树插入函数
void ngx_rbtree_insert_value(ngx_rbtree_node_t *root, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel);
// 定时器红黑树专用插入函数
void ngx_rbtree_insert_timer_value(ngx_rbtree_node_t *root,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
// 1.11.11新增，可以用来遍历红黑树
ngx_rbtree_node_t *ngx_rbtree_next(ngx_rbtree_t *tree,
    ngx_rbtree_node_t *node);


/* 给节点着色，1表示红色，0表示黑色  */
#define ngx_rbt_red(node)               ((node)->color = 1)
#define ngx_rbt_black(node)             ((node)->color = 0)
/* 判断节点的颜色 */
#define ngx_rbt_is_red(node)            ((node)->color)
#define ngx_rbt_is_black(node)          (!ngx_rbt_is_red(node))
/* 复制某个节点的颜色 */
#define ngx_rbt_copy_color(n1, n2)      (n1->color = n2->color)


/* a sentinel must be black */

// 哨兵节点颜色是黑的
#define ngx_rbtree_sentinel_init(node)  ngx_rbt_black(node)


/**
 * 使用红黑树，一般只使用此方法
 * 
 * 找出当前节点及其子节点的最小节点
 */
static ngx_inline ngx_rbtree_node_t *
ngx_rbtree_min(ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    while (node->left != sentinel) {
        node = node->left;
    }

    return node;
}


#endif /* _NGX_RBTREE_H_INCLUDED_ */
