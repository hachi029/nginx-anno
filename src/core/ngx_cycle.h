
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CYCLE_H_INCLUDED_
#define _NGX_CYCLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef NGX_CYCLE_POOL_SIZE
#define NGX_CYCLE_POOL_SIZE     NGX_DEFAULT_POOL_SIZE
#endif


#define NGX_DEBUG_POINTS_STOP   1
#define NGX_DEBUG_POINTS_ABORT  2


typedef struct ngx_shm_zone_s  ngx_shm_zone_t;

/**
 * 第1个参数就是ngx_shared_memory_add返回的
 * 第二个参数：如果Nginx是首次启动，data则为 空指针NULL；
 *           若是重读配置文件，由于配置项、http模块的初始化导致共享内存再次创建， 那么data就会指向第一次创建共享内存时，
 *           ngx_shared_memory_add返回的ngx_shm_zone_t中的 data成员
 */
typedef ngx_int_t (*ngx_shm_zone_init_pt) (ngx_shm_zone_t *zone, void *data);

/**
 * 代表一个共享内存区域
 */
struct ngx_shm_zone_s {
    // 当ngx_shm_zone_init_pt方法回调时，通常在使用 slab内存池的代码前需要做一些初始化工作，
    // 这一工作可能需要用到在解析配置文件时就获取到的一些参数，而 data主要担当传递参数的职责
    void                     *data;
    // 描述共享内存的结构体
    ngx_shm_t                 shm;
    ngx_shm_zone_init_pt      init;     // 在真正创建好 slab共享内存池后，就会回调 init指向的方法
    // 对应于 ngx_shared_memory_add的 tag参数
    void                     *tag;
    void                     *sync;
    ngx_uint_t                noreuse;  /* unsigned  noreuse:1; */
};


/**
 * 无论是master、worker工、cache manager（loader）进程，都有唯一一个ngx_cycle_t结构体
 * 
 */
// nginx核心数据结构，表示nginx的生命周期，含有许多重要参数
//
// conf_ctx, 存储所有模块的配置结构体，是个二维数组
// free_connections,空闲连接，使用指针串成单向链表
// listening,监听的端口数组
// connections/read_events/write_events,连接池,大小是connection_n
struct ngx_cycle_s {
    //保存着所有模块存储配置项的结构体的指针，它首先是一个数组，每个数组成员又是一个指针，
    //这个指针指向另一个存储着指针的数组
    // 存储所有模块的配置结构体，是个二维数组
    // 0 = ngx_core_module
    // 1 = ngx_errlog_module
    // 3 = ngx_event_module
    // 4 = ngx_event_core_module
    // 5 = ngx_epoll_module
    // 7 = ngx_http_module
    // 8 = ngx_http_core_module
    void                  ****conf_ctx;
    // 内存池
    ngx_pool_t               *pool;

    /**
     * 日志模块中提供了生成基本ngx_log_t日志对象的功能，这里的log实际上是在还没有执行 ngx_init_cycle方法前，
     * 也就是还没有解析配置前，如果有信息需要输出到日志，就会暂时使用log对象，它会输出到屏幕。
     * 在 ngx_init_cycle方法执行后，将会根据 nginx.conf配置文件中的配置项，构造出正确的日志文件，
     * 此时会对log重新赋值
     */
    ngx_log_t                *log;
    //由 nginx.conf配置文件读取到日志文件路径后，将开始初始化 error_log日志文件，
    //由于 log对象还在用于输出日志到屏幕，这时会用 new_log对象暂时性地替代 log日志，
    //待初始化成功后，会用new_log的地址覆盖上面的log指针
    ngx_log_t                 new_log;

    ngx_uint_t                log_use_stderr;  /* unsigned  log_use_stderr:1; */

    //只在poll和devpoll事件模型中有用
    //对于 poll、 rtsig这样的事件模块，会以有效文件句柄数来预先建立这些 ngx_connection_t结构体，
    //以加速事件的收集、分发。这时 files就会保存所有 ngx_connection_t的指针组成的数组， 
    //files_n就是指针的总数，而文件句柄的值用来访问 files数组成员
    ngx_connection_t        **files;
    /**
     * free_connections指向第一个ngx_connection_t空闲连接,所有的空闲连接ngx_connection_t都以 data 成员作为 next 指针
     * 串联成一个单链表。一旦有用户发起连接时就从free_connections指向的链表头获取一个空闲的连接，
     * 同时free_connections再指向下一个空闲连接。而归还连接时只需把该连接插入到free_connections链表表头即可
     */
    ngx_connection_t         *free_connections;
    ngx_uint_t                free_connection_n;    //初始为connection_n, 可用连接池中连接的总数

    // 1.10，保存模块数组，可以加载动态模块
    // 可以容纳所有的模块，大小是ngx_max_module + 1
    // ngx_cycle_modules()初始化
    ngx_module_t            **modules;
    // 拷贝模块序号计数器到本cycle
    // ngx_cycle_modules()初始化
    ngx_uint_t                modules_n;
    // 标志位，cycle已经完成模块的初始化，不能再添加模块
    // 在ngx_load_module里检查，不允许加载动态模块
    ngx_uint_t                modules_used;    /* unsigned  modules_used:1; */

    ///双向链表容器，元素类型是ngx_connection_t结构体，表示可重复使用连接队列
    ngx_queue_t               reusable_connections_queue;
    ngx_uint_t                reusable_connections_n;
    time_t                    connections_reuse_time;

    //动态数组,每个数组元素都是ngx_listening_t结构体,代表nginx监听的多个端口, 表示监听端口及相关的参数
    ngx_array_t               listening;
    /**
     * 动态数组容器，它保存着 Nginx所有要操作的目录。如果有目录不存在，则会试图创建，
     * 而创建目录失败将会导致 Nginx启动失败。例如，上传文件的临时目录也在 pathes中，
     * 如果没有权限创建，则会导致Nginx无法启动
     */
    ngx_array_t               paths;

    ngx_array_t               config_dump;
    ngx_rbtree_t              config_dump_rbtree;
    ngx_rbtree_node_t         config_dump_sentinel;

    /**
     * 单链表容器，元素类型是 ngx_open_file_t结构体，它表示 Nginx已经打开的所有文件。
     * 事实上， Nginx框架不会向 open_files链表中添加文件，而是由对此感兴趣的模块向其中添加文件路径名，
     *  Nginx框架会在 ngx_init_cycle方法中打开这些文件
     */
    ngx_list_t                open_files;
    //单链表容器，元素的类型是 ngx_shm_zone_t结构体，每个元素表示一块共享内存，
    ngx_list_t                shared_memory;

    //worker_connection 配置值,连接池中连接数数量. 当前进程中所有连接对象的总数
    ngx_uint_t                connection_n;
    //只在poll和devpoll事件模型中有用
    // 与下面的files成员配合使用，指出 files数组里元素的总数
    ngx_uint_t                files_n;

    /**
     * connections和free_connections这两个成员构成了一个连接池
     * connections指向整个连接池数组的首部
     */
    ngx_connection_t         *connections;
    // 指向当前进程中的所有读事件对象， connection_n同时表示所有读事件的总数
    ngx_event_t              *read_events;
    // 指向当前进程中的所有写事件对象，connection_n同时表示所有写事件的总数
    ngx_event_t              *write_events;

    /**
     * 旧的 ngx_cycle_t对象用于引用上一个 ngx_cycle_t对象中的成员。
     * 例如 ngx_init_cycle方法，在启动初期，需要建立一个临时的 ngx_cycle_t对象保存一些变量，
     * 再调用 ngx_init_cycle方法时就可以把旧的 ngx_cycle_t对象传进去，
     * 而这时 old_cycle对象就会保存这个前期的 ngx_cycle_t对象
     */
    ngx_cycle_t              *old_cycle;

    // 配置文件相对于安装目录的路径名称
    ngx_str_t                 conf_file;
    //Nginx处理配置文件时需要特殊处理的在命令行携带的参数，一般是 -g选项携带的参数
    ngx_str_t                 conf_param;
    // Nginx配置文件所在目录的路径
    ngx_str_t                 conf_prefix;
    // Nginx安装目录的路径
    ngx_str_t                 prefix;
    //
    ngx_str_t                 error_log;
    // 用于进程间同步的文件锁名称
    ngx_str_t                 lock_file;
    // 使用 gethostname系统调用得到的主机名
    ngx_str_t                 hostname;
};


typedef struct {
    ngx_flag_t                daemon;
    ngx_flag_t                master;

    ngx_msec_t                timer_resolution;
    ngx_msec_t                shutdown_timeout;

    ngx_int_t                 worker_processes;
    ngx_int_t                 debug_points;

    ngx_int_t                 rlimit_nofile;
    off_t                     rlimit_core;

    int                       priority;

    ngx_uint_t                cpu_affinity_auto;
    ngx_uint_t                cpu_affinity_n;
    ngx_cpuset_t             *cpu_affinity;

    char                     *username;
    ngx_uid_t                 user;
    ngx_gid_t                 group;

    ngx_str_t                 working_directory;
    ngx_str_t                 lock_file;

    ngx_str_t                 pid;
    ngx_str_t                 oldpid;

    ngx_array_t               env;
    char                    **environment;

    ngx_uint_t                transparent;  /* unsigned  transparent:1; */
} ngx_core_conf_t;


#define ngx_is_init_cycle(cycle)  (cycle->conf_ctx == NULL)


ngx_cycle_t *ngx_init_cycle(ngx_cycle_t *old_cycle);
ngx_int_t ngx_create_pidfile(ngx_str_t *name, ngx_log_t *log);
void ngx_delete_pidfile(ngx_cycle_t *cycle);
ngx_int_t ngx_signal_process(ngx_cycle_t *cycle, char *sig);
void ngx_reopen_files(ngx_cycle_t *cycle, ngx_uid_t user);
char **ngx_set_environment(ngx_cycle_t *cycle, ngx_uint_t *last);
ngx_pid_t ngx_exec_new_binary(ngx_cycle_t *cycle, char *const *argv);
ngx_cpuset_t *ngx_get_cpu_affinity(ngx_uint_t n);
ngx_shm_zone_t *ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name,
    size_t size, void *tag);
void ngx_set_shutdown_timer(ngx_cycle_t *cycle);


extern volatile ngx_cycle_t  *ngx_cycle;
extern ngx_array_t            ngx_old_cycles;
extern ngx_module_t           ngx_core_module;
extern ngx_uint_t             ngx_test_config;
extern ngx_uint_t             ngx_dump_config;
extern ngx_uint_t             ngx_quiet_mode;


#endif /* _NGX_CYCLE_H_INCLUDED_ */
