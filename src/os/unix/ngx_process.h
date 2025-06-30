
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PROCESS_H_INCLUDED_
#define _NGX_PROCESS_H_INCLUDED_


#include <ngx_setaffinity.h>
#include <ngx_setproctitle.h>


typedef pid_t       ngx_pid_t;

#define NGX_INVALID_PID  -1

typedef void (*ngx_spawn_proc_pt) (ngx_cycle_t *cycle, void *data);

/**
 * 所有子进程相关的状态信息
 */
typedef struct {
    // 进程 ID
    ngx_pid_t           pid;
    // 由 waitpid系统调用获取到的进程状态
    int                 status;
    //这是由socketpair系统调用产生出的用于进程间通信的 socket句柄，
    //这一对 socket句柄可以互相通信，目前用于 master父进程与 worker子进程间的通信
    ngx_socket_t        channel[2];

    // 子进程的循环执行方法，当父进程调用 ngx_spawn_process生成子进程时使用
    ngx_spawn_proc_pt   proc;
    //上面的 ngx_spawn_proc_pt方法中第 2个参数需要传递 1个指针，它是可选的。
    //例如， worker子进程就不需要，而 cache manage进程就需要 ngx_cache_manager_ctx上下文成员。
    //这时， data一般与 ngx_spawn_proc_pt方法中第 2个参数是等价的
    void               *data;           //proc和data参数是worker挂掉之后，能重新原样启动的关键
    // 进程名称。操作系统中显示的进程名称与 name相同
    char               *name;
    // 标志位，为 1时表示在重新生成子进程
    unsigned            respawn:1;
    //标志位，为 1时表示正在生成子进程
    unsigned            just_spawn:1;
    //标志位，为 1时表示在进行父、子进程分离
    unsigned            detached:1;
    //标志位，为 1时表示进程正在退出
    unsigned            exiting:1;
    //标志位，为 1时表示进程已经退出
    unsigned            exited:1;
} ngx_process_t;


typedef struct {
    char         *path;
    char         *name;
    char *const  *argv;
    char *const  *envp;
} ngx_exec_ctx_t;

//1024个元素的 ngx_processes数组，也就是最多只能有 1024个子进程
#define NGX_MAX_PROCESSES         1024

#define NGX_PROCESS_NORESPAWN     -1
#define NGX_PROCESS_JUST_SPAWN    -2
#define NGX_PROCESS_RESPAWN       -3
#define NGX_PROCESS_JUST_RESPAWN  -4
#define NGX_PROCESS_DETACHED      -5


#define ngx_getpid   getpid
#define ngx_getppid  getppid

#ifndef ngx_log_pid
#define ngx_log_pid  ngx_pid
#endif


ngx_pid_t ngx_spawn_process(ngx_cycle_t *cycle,
    ngx_spawn_proc_pt proc, void *data, char *name, ngx_int_t respawn);
ngx_pid_t ngx_execute(ngx_cycle_t *cycle, ngx_exec_ctx_t *ctx);
ngx_int_t ngx_init_signals(ngx_log_t *log);
void ngx_debug_point(void);


#if (NGX_HAVE_SCHED_YIELD)
#define ngx_sched_yield()  sched_yield()
#else
#define ngx_sched_yield()  usleep(1)
#endif


extern int            ngx_argc;
extern char         **ngx_argv;
extern char         **ngx_os_argv;

extern ngx_pid_t      ngx_pid;
extern ngx_pid_t      ngx_parent;
extern ngx_socket_t   ngx_channel;
extern ngx_int_t      ngx_process_slot;
extern ngx_int_t      ngx_last_process;
extern ngx_process_t  ngx_processes[NGX_MAX_PROCESSES];


#endif /* _NGX_PROCESS_H_INCLUDED_ */
