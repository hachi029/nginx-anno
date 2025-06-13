
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SHMTX_H_INCLUDED_
#define _NGX_SHMTX_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    ngx_atomic_t   lock;
#if (NGX_HAVE_POSIX_SEM)
    ngx_atomic_t   wait;
#endif
} ngx_shmtx_sh_t;

/**
 * 信号量与信号不同，它不像信号那样用来传递消息，而是用来保证两个或多个代码段不被并发访问，
 * 是一种保证共享资源有序访问的工具
 * 使用信号量作为互斥锁有可能导致进程睡眠
 * 
 */

 /**
  * 互斥锁，作为进程间同步
  * 
  * 基于原子操作、信号量以及文件锁，Nginx在更高层次封装了一个互斥锁
  * 
  * ngx_shmtx_t结构体涉及两个宏：NGX_HAVE_ATOMIC_OPS、 NGX_HAVE_POSIX_SEM，
  * 这两个宏对应着互斥锁的3种不同实现
  * 
  */
typedef struct {
#if (NGX_HAVE_ATOMIC_OPS)
    ngx_atomic_t  *lock;    // 原子变量锁
#if (NGX_HAVE_POSIX_SEM)
    ngx_atomic_t  *wait;
    ngx_uint_t     semaphore;   // semaphore为 1时表示获取锁将可能使用到的信号量
    sem_t          sem;         // sem就是信号量锁
#endif
#else
    ngx_fd_t       fd;          // 使用文件锁时 fd表示使用的文件句柄
    u_char        *name;        // name表示文件名
#endif
    //自旋次数，表示在自旋状态下等待其他处理器执行结果中释放锁的时间。由文件锁实现时， spin没有任何意义
    ngx_uint_t     spin;
} ngx_shmtx_t;


ngx_int_t ngx_shmtx_create(ngx_shmtx_t *mtx, ngx_shmtx_sh_t *addr,
    u_char *name);
void ngx_shmtx_destroy(ngx_shmtx_t *mtx);
ngx_uint_t ngx_shmtx_trylock(ngx_shmtx_t *mtx);
void ngx_shmtx_lock(ngx_shmtx_t *mtx);
void ngx_shmtx_unlock(ngx_shmtx_t *mtx);
ngx_uint_t ngx_shmtx_force_unlock(ngx_shmtx_t *mtx, ngx_pid_t pid);


#endif /* _NGX_SHMTX_H_INCLUDED_ */
