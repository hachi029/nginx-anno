
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CHANNEL_H_INCLUDED_
#define _NGX_CHANNEL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

/**
 * ngx_channel_t频道是Nginx master进程与worker进程之间通信的常用工具，它是使用本机套接字实现的。
 * 
 * 基于socketpair实现
 * 
 * Nginx仅用这个频道同步master进程与worker进程间的状态
 * 
 */
typedef struct {
    ngx_uint_t  command;  // 传递的TCP消息中的命令
    ngx_pid_t   pid;     // 进程 ID，一般是发送命令方的进程 ID
    ngx_int_t   slot;   // 表示发送命令方在 ngx_processes进程数组间的序号
    ngx_fd_t    fd;     // 通信的套接字句柄
} ngx_channel_t;


ngx_int_t ngx_write_channel(ngx_socket_t s, ngx_channel_t *ch, size_t size,
    ngx_log_t *log);
ngx_int_t ngx_read_channel(ngx_socket_t s, ngx_channel_t *ch, size_t size,
    ngx_log_t *log);
ngx_int_t ngx_add_channel_event(ngx_cycle_t *cycle, ngx_fd_t fd,
    ngx_int_t event, ngx_event_handler_pt handler);
void ngx_close_channel(ngx_fd_t *fd, ngx_log_t *log);


#endif /* _NGX_CHANNEL_H_INCLUDED_ */
