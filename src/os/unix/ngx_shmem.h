
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SHMEM_H_INCLUDED_
#define _NGX_SHMEM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/**
 * 共享内存是Linux下提供的最基本的进程间通信方法，它通过mmap或者shmget系统调用在内存中创建了一块连续的线性地址空间，
 * 而通过munmap或者shmdt系统调用可以释放这块内存。使用共享内存的好处是当多个进程使用同一块共享内存时，
 * 在任何一个进程修改了共享内存中的内容后，其他进程通过访问这段共享内存都能够得到修改后的内容.
 * 
 * 在使用共享内存时，Nginx一般是由master进程创建，在master进程fork出worker子进程后，所有的进程开始使用这块内存中的数据
 * 
 * 
 * 
 */
//此结构体 描述共享内存的结构体
typedef struct {
    u_char      *addr;  // 指向共享内存的起始地址
    size_t       size;  // 共享内存的长度
    ngx_str_t    name;  // 这块共享内存的名称
    ngx_log_t   *log;
    // 表示共享内存是否已经分配过的标志位，为 1时表示已经存在
    ngx_uint_t   exists;   /* unsigned  exists:1;  */
} ngx_shm_t;


//用于分配新的共享内存
/**
 * 有3种实现（不映射文件使用mmap分配共享内存、以/dev/zero文 件使用mmap映射共享内存、用shmget调用来分配共享内存）
 */
ngx_int_t ngx_shm_alloc(ngx_shm_t *shm);
//用于释放已经存在的共享内存
void ngx_shm_free(ngx_shm_t *shm);


#endif /* _NGX_SHMEM_H_INCLUDED_ */
