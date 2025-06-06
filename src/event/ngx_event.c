
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define DEFAULT_CONNECTIONS  512


extern ngx_module_t ngx_kqueue_module;
extern ngx_module_t ngx_eventport_module;
extern ngx_module_t ngx_devpoll_module;
extern ngx_module_t ngx_epoll_module;
extern ngx_module_t ngx_select_module;


static char *ngx_event_init_conf(ngx_cycle_t *cycle, void *conf);
static ngx_int_t ngx_event_module_init(ngx_cycle_t *cycle);
static ngx_int_t ngx_event_process_init(ngx_cycle_t *cycle);
static char *ngx_events_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *ngx_event_connections(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_event_use(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_event_debug_connection(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static void *ngx_event_core_create_conf(ngx_cycle_t *cycle);
static char *ngx_event_core_init_conf(ngx_cycle_t *cycle, void *conf);


static ngx_uint_t     ngx_timer_resolution;
//ngx_event_timer_alarm是个全局变量，当它设为1时，表示需要更新时间。
//在ngx_event_actions_t的process_events方法中，每一个事件驱动模块都需要在 ngx_event_timer_alarm为1时调用ngx_time_update方法
//更新系统时间，在更新 系统结束后需要将ngx_event_timer_alarm设为0
sig_atomic_t          ngx_event_timer_alarm;

static ngx_uint_t     ngx_event_max_module;

ngx_uint_t            ngx_event_flags;
ngx_event_actions_t   ngx_event_actions;


static ngx_atomic_t   connection_counter = 1;
ngx_atomic_t         *ngx_connection_counter = &connection_counter;


ngx_atomic_t         *ngx_accept_mutex_ptr;
//是Nginx进 程间的同步锁, 用于进程间负载均衡
ngx_shmtx_t           ngx_accept_mutex;
//标明是否开启进程间的负载均衡
ngx_uint_t            ngx_use_accept_mutex;
ngx_uint_t            ngx_accept_events;
//标识是否持有锁, 当前进程的一个全局变量，如果为1，则表示这个进程已经获取到了ngx_accept_mutex锁；
//如果为0，则表示没有获 取到锁，这个标志位主要用于进程内各模块了解是否获取到了ngx_accept_mutex锁
ngx_uint_t            ngx_accept_mutex_held;
//https://nginx.org/en/docs/ngx_core_module.html#accept_mutex_delay
ngx_msec_t            ngx_accept_mutex_delay;

/**
 * 在Nginx启动时，ngx_accept_disabled的值就是一个负数，其值为连接总数的7/8。 
 * 其实，ngx_accept_disabled的用法很简单，当它为负数时，不会进行触发负载均衡操作；
 * 而 当ngx_accept_disabled是正数时，就会触发Nginx进行负载均衡操作了。
 * Nginx的做法也很简 单，就是当ngx_accept_disabled是正数时当前进程将不再处理新连接事件，
 * 取而代之的仅仅 是ngx_accept_disabled值减1
 * 
 * 在当前使用的连接到达总连接数的7/8时，就不会再处理新连接了，
 * 同时，在每次调用process_events时都会将ngx_accept_disabled减1，
 * 直到 ngx_accept_disabled降到总连接数的7/8以下时，才会调用ngx_trylock_accept_mutex试图去处理新连接事件
 * 
 * Nginx各worker子进程间的负载均衡仅在某个worker进程处理的连接数达到它最大 处理总数的7/8时才会触发，
 * 这时该worker进程就会减少处理新连接的机会，这样其他较空闲 的worker进程就有机会去处理更多的新连接
 * 
 * 
 */
ngx_int_t             ngx_accept_disabled;
ngx_uint_t            ngx_use_exclusive_accept;


#if (NGX_STAT_STUB)

static ngx_atomic_t   ngx_stat_accepted0;       // 已经建立成功过的 TCP连接数
ngx_atomic_t         *ngx_stat_accepted = &ngx_stat_accepted0;
//连接建立成功且获取到 ngx_connection_t结构体后，已经分配过内存池，并且在表示初始化了读 /写事件后的连接数
static ngx_atomic_t   ngx_stat_handled0;
ngx_atomic_t         *ngx_stat_handled = &ngx_stat_handled0;
// 已经由 HTTP模块处理过的连接数
static ngx_atomic_t   ngx_stat_requests0;
ngx_atomic_t         *ngx_stat_requests = &ngx_stat_requests0;
//已经从 ngx_cycle_t核心结构体的 free_connections连接池中获取到 ngx_connection_t对象的活跃连接数
static ngx_atomic_t   ngx_stat_active0;
ngx_atomic_t         *ngx_stat_active = &ngx_stat_active0;
// 正在接收 TCP流的连接数
static ngx_atomic_t   ngx_stat_reading0;
ngx_atomic_t         *ngx_stat_reading = &ngx_stat_reading0;
// 正在发送TCP流的连接数
static ngx_atomic_t   ngx_stat_writing0;
ngx_atomic_t         *ngx_stat_writing = &ngx_stat_writing0;
static ngx_atomic_t   ngx_stat_waiting0;
ngx_atomic_t         *ngx_stat_waiting = &ngx_stat_waiting0;

#endif


/**
 * ngx_events_module模块是一个核心模块，它定义了一类新模块：事件模块。
 * 它的功能如下：定义新的事件类型，并定义每个事件模块都需要实现的ngx_event_module_t接口
 * 
 * 需要管理这些事件模块生成的配置项结构体，并解析事件类配置项，在解析配置项时会调用其在ngx_command_t数组中定义的回调方法
 */

static ngx_command_t  ngx_events_commands[] = {

    { ngx_string("events"),
      NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_events_block,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_events_module_ctx = {
    ngx_string("events"),
    NULL,
    ngx_event_init_conf
};


ngx_module_t  ngx_events_module = {
    NGX_MODULE_V1,
    &ngx_events_module_ctx,                /* module context */
    ngx_events_commands,                   /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t  event_core_name = ngx_string("event_core");


static ngx_command_t  ngx_event_core_commands[] = {

    //连接池的大小，也就是每个worker进程中支持的TCP最大连接数
    { ngx_string("worker_connections"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_event_connections,
      0,
      0,
      NULL },

    // 确定选择哪一个事件模块作为事件驱动机制
    { ngx_string("use"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_event_use,
      0,
      0,
      NULL },

    /**
     * 对应于事件定义的 available字段。
     * 对于 epoll事件驱动模式来说，意味着在接收到一个新连接事件时，调用 accept以尽可能多地接收连接
     */
    { ngx_string("multi_accept"),
      NGX_EVENT_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      0,
      offsetof(ngx_event_conf_t, multi_accept),
      NULL },

    // 确定是否使用 accept_mutex负载均衡锁  
    { ngx_string("accept_mutex"),
      NGX_EVENT_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      0,
      offsetof(ngx_event_conf_t, accept_mutex),
      NULL },

      /*启用 accept_mutex负载均衡锁后，延迟 accept_mutex_delay毫秒后再试图处理新连接事件 */
    { ngx_string("accept_mutex_delay"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      0,
      offsetof(ngx_event_conf_t, accept_mutex_delay),
      NULL },

    // 需要对来自指定 IP的 TCP连接打印 debug级别的调试日志  
    { ngx_string("debug_connection"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_event_debug_connection,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_event_module_t  ngx_event_core_module_ctx = {
    &event_core_name,
    ngx_event_core_create_conf,            /* create configuration */
    ngx_event_core_init_conf,              /* init configuration */

    { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }
};

/**
 * ngx_event_core_module模块是一个事件类型的模块，它在所有事件模块中的顺序是第一位
 * （configure执行时必须把它放在其他事件模块之前）。这就保证了它会先于其他事件模块执行，
 * 由此它选择事件驱动机制的任务才可以完成
 * 
 * ngx_event_core_module模块负责创建连接池（包括读/ 写事件），
 * 同时会决定究竟使用哪些事件驱动机制，以及初始化将要使用的事件模块
 * 
 */

ngx_module_t  ngx_event_core_module = {
    NGX_MODULE_V1,
    &ngx_event_core_module_ctx,            /* module context */
    ngx_event_core_commands,               /* module directives */
    NGX_EVENT_MODULE,                      /* module type */
    NULL,                                  /* init master */
    //在Nginx启动过程中还没有fork出worker子进程时，会首先调用ngx_event_module_init
    ngx_event_module_init,                 /* init module */
    //而在fork出worker子进程后，每一个worker进程会在调用 ngx_event_process_init方法后才会进入正式的工作循环
    ngx_event_process_init,                /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

/**
 * 每个worker进程都在ngx_worker_process_cycle方法中循环处理事件
 * 
 * 此方法就是Nginx实际上处理Web服务的方法，所有业务的执行都 是由它开始的
 * 
 * 既会处理普通的网络事件，也会处 理定时器事件
 * 
 * 1. 调用所使用的事件驱动模块实现的process_events方法，处理网络事件
 * 2. 处理两个post事件队列中的事件，实际上就是分别调用 
 * ngx_event_process_posted(cycle,&ngx_posted_accept_events)和
    ngx_event_process_posted(cycle,&ngx_posted_events)方法
   3. 处理定时器事件，实际上就是调用ngx_event_expire_timers()方法 
 * 
 */
void
ngx_process_events_and_timers(ngx_cycle_t *cycle)
{
    ngx_uint_t  flags;
    ngx_msec_t  timer, delta;

    //如果配置文件中使用了timer_resolution配置项, 也就是ngx_timer_resolution值大于0， 
    //则说明用户希望服务器时间精确度为ngx_timer_resolution毫秒
    if (ngx_timer_resolution) {
        //将ngx_process_events 的timer参数设为–1，告诉ngx_process_events方法在检测事件时不要等待，
        //直接搜集所有已经 就绪的事件然后返回
        timer = NGX_TIMER_INFINITE;
        //将flags参数初始化为0，它是在告诉ngx_process_events没有任何 附加动作
        flags = 0;

    } else {
        //如果没有使用timer_resolution，那么将调用ngx_event_find_timer()方法
        //获取最近一个将要触发的事件距离现在有多少毫秒，然后把这个值赋予timer参数
        timer = ngx_event_find_timer();
        //将flags 参数设置为NGX_UPDATE_TIME，告诉ngx_process_events方法更新缓存的时间
        flags = NGX_UPDATE_TIME;

#if (NGX_WIN32)

        /* handle signals from master in case of network inactivity */

        if (timer == NGX_TIMER_INFINITE || timer > 500) {
            timer = 500;
        }

#endif
    }

    //开启了负载均衡锁
    if (ngx_use_accept_mutex) {
        //检测负载均衡阈值变量ngx_accept_disabled。
        //如果ngx_accept_disabled是正数，则将其值减去 1
        if (ngx_accept_disabled > 0) {
            ngx_accept_disabled--;

        } else {    //是负数，表明还没有触发到负载均衡机制,
            //此时要调用ngx_trylock_accept_mutex方法试图去获取accept_mutex锁
            //试图处理监听端口的新连接事件, 如果为1，就表示开始处理新连接事件了
            if (ngx_trylock_accept_mutex(cycle) == NGX_ERROR) {
                return;
            }

            //如果 ngx_accept_mutex_held为1，就表示开始处理新连接事件了
            if (ngx_accept_mutex_held) { 
                //参考 ngx_epoll_process_events 的逻辑
                //告诉ngx_process_events方法搜集到的事件没有直接执行它的handler方法，
                //而是分门别类地放到ngx_posted_accept_events队列和ngx_posted_events 队列中
                flags |= NGX_POST_EVENTS;   //这时将flags标志位加上 NGX_POST_EVENTS

            } else {
                //如果没有获取到accept_mutex锁，则意味着既不能让当前worker进程频繁地试图抢锁，
                //也不能让它经过太长时间再去抢锁

                //即使开启了timer_resolution时间精度，也需要让ngx_process_events方法在没有新事件的时候至少等待ngx_accept_mutex_delay毫秒再去试图抢锁
                if (timer == NGX_TIMER_INFINITE
                    || timer > ngx_accept_mutex_delay)
                {
                    //如果最近一个定时器事件的超时时间距离现在超过了ngx_accept_mutex_delay毫秒的话， 
                    //也要把timer设置为ngx_accept_mutex_delay毫秒，这是因为当前进程虽然没有抢到 accept_mutex锁，
                    //但也不能让ngx_process_events方法在没有新事件的时候等待的时间超过 ngx_accept_mutex_delay毫秒，
                    //这会影响整个负载均衡机制
                    timer = ngx_accept_mutex_delay;
                }
            }
        }
    }

    if (!ngx_queue_empty(&ngx_posted_next_events)) {
        ngx_event_move_posted_next(cycle);
        timer = 0;
    }

    //delta是ngx_process_events执行时消耗的毫秒数
    delta = ngx_current_msec;

    //调用ngx_process_events方法，并计算ngx_process_events执行时消耗的时间
    (void) ngx_process_events(cycle, timer, flags);

    delta = ngx_current_msec - delta;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "timer delta: %M", delta);

    //执行ngx_posted_accept_events队列中需要建立新连接的事件
    ngx_event_process_posted(cycle, &ngx_posted_accept_events);

    //如果ngx_accept_mutex_held标志位为1，则表示当前进程获得了accept_mutex锁，
    //而且 在第8步中也已经处理完了新连接事件，这时需要调用ngx_shmtx_unlock释放accept_mutex锁
    if (ngx_accept_mutex_held) {
        ngx_shmtx_unlock(&ngx_accept_mutex);
    }

    //处理所有可能过期的定时器事件
    ngx_event_expire_timers();

    //执行 ngx_posted_events队列中的普通读/写事件
    ngx_event_process_posted(cycle, &ngx_posted_events);
}

/**
 * 将读事件加入epool
 * 将读事件添加到事件驱动模块中，这样该事件对应的TCP连接上一旦出现可读事件，就会调用该事件上的handler方法
 * rev是要操作的事件
 * flags将会指定事件的驱动方式 一般可以忽略这个参数
 */
ngx_int_t
ngx_handle_read_event(ngx_event_t *rev, ngx_uint_t flags)
{
#if (NGX_QUIC)

    ngx_connection_t  *c;

    c = rev->data;

    if (c->quic) {
        return NGX_OK;
    }

#endif

    if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {

        /* kqueue, epoll */

        if (!rev->active && !rev->ready) {
            if (ngx_add_event(rev, NGX_READ_EVENT, NGX_CLEAR_EVENT)
                == NGX_ERROR)
            {
                return NGX_ERROR;
            }
        }

        return NGX_OK;

    } else if (ngx_event_flags & NGX_USE_LEVEL_EVENT) {

        /* select, poll, /dev/poll */

        if (!rev->active && !rev->ready) {
            if (ngx_add_event(rev, NGX_READ_EVENT, NGX_LEVEL_EVENT)
                == NGX_ERROR)
            {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

        if (rev->active && (rev->ready || (flags & NGX_CLOSE_EVENT))) {
            if (ngx_del_event(rev, NGX_READ_EVENT, NGX_LEVEL_EVENT | flags)
                == NGX_ERROR)
            {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

    } else if (ngx_event_flags & NGX_USE_EVENTPORT_EVENT) {

        /* event ports */

        if (!rev->active && !rev->ready) {
            if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

        if (rev->oneshot && rev->ready) {
            if (ngx_del_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }

            return NGX_OK;
        }
    }

    /* iocp */

    return NGX_OK;
}

/**
 * 将写事件加入epool
 * 将写事件添加到事件驱动模块中
 * wev是要操作的事件
 * lowat则表示只有当连接对应套接字的发送缓冲区中必须有lowat大小的可用空间时，才会触发事件
 * 返回值为NGX_OK表示成功，NGX_ERROR表示失败
 */
ngx_int_t
ngx_handle_write_event(ngx_event_t *wev, size_t lowat)
{
    ngx_connection_t  *c;

    c = wev->data;

#if (NGX_QUIC)
    if (c->quic) {
        return NGX_OK;
    }
#endif

    if (lowat) {
        if (ngx_send_lowat(c, lowat) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {

        /* kqueue, epoll */

        if (!wev->active && !wev->ready) {
            if (ngx_add_event(wev, NGX_WRITE_EVENT,
                              NGX_CLEAR_EVENT | (lowat ? NGX_LOWAT_EVENT : 0))
                == NGX_ERROR)
            {
                return NGX_ERROR;
            }
        }

        return NGX_OK;

    } else if (ngx_event_flags & NGX_USE_LEVEL_EVENT) {

        /* select, poll, /dev/poll */

        if (!wev->active && !wev->ready) {
            if (ngx_add_event(wev, NGX_WRITE_EVENT, NGX_LEVEL_EVENT)
                == NGX_ERROR)
            {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

        if (wev->active && wev->ready) {
            if (ngx_del_event(wev, NGX_WRITE_EVENT, NGX_LEVEL_EVENT)
                == NGX_ERROR)
            {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

    } else if (ngx_event_flags & NGX_USE_EVENTPORT_EVENT) {

        /* event ports */

        if (!wev->active && !wev->ready) {
            if (ngx_add_event(wev, NGX_WRITE_EVENT, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

        if (wev->oneshot && wev->ready) {
            if (ngx_del_event(wev, NGX_WRITE_EVENT, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }

            return NGX_OK;
        }
    }

    /* iocp */

    return NGX_OK;
}


static char *
ngx_event_init_conf(ngx_cycle_t *cycle, void *conf)
{
#if (NGX_HAVE_REUSEPORT)
    ngx_uint_t        i;
    ngx_core_conf_t  *ccf;
    ngx_listening_t  *ls;
#endif

    if (ngx_get_conf(cycle->conf_ctx, ngx_events_module) == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "no \"events\" section in configuration");
        return NGX_CONF_ERROR;
    }

    if (cycle->connection_n < cycle->listening.nelts + 1) {

        /*
         * there should be at least one connection for each listening
         * socket, plus an additional connection for channel
         */

        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "%ui worker_connections are not enough "
                      "for %ui listening sockets",
                      cycle->connection_n, cycle->listening.nelts);

        return NGX_CONF_ERROR;
    }

#if (NGX_HAVE_REUSEPORT)

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    if (!ngx_test_config && ccf->master) {

        ls = cycle->listening.elts;
        for (i = 0; i < cycle->listening.nelts; i++) {

            if (!ls[i].reuseport || ls[i].worker != 0) {
                continue;
            }

            if (ngx_clone_listening(cycle, &ls[i]) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            /* cloning may change cycle->listening.elts */

            ls = cycle->listening.elts;
        }
    }

#endif

    return NGX_CONF_OK;
}

/**
 * master 进程fork出子进程前调用
 * 
 * 主要初始化了一些变量，尤其是 ngx_http_stub_status_module统计模块使用的一些原子性的统计变量
 * 
 */
static ngx_int_t
ngx_event_module_init(ngx_cycle_t *cycle)
{
    void              ***cf;
    u_char              *shared;
    size_t               size, cl;
    ngx_shm_t            shm;
    ngx_time_t          *tp;
    ngx_core_conf_t     *ccf;
    ngx_event_conf_t    *ecf;

    cf = ngx_get_conf(cycle->conf_ctx, ngx_events_module);
    ecf = (*cf)[ngx_event_core_module.ctx_index];

    if (!ngx_test_config && ngx_process <= NGX_PROCESS_MASTER) {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "using the \"%s\" event method", ecf->name);
    }

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    ngx_timer_resolution = ccf->timer_resolution;

#if !(NGX_WIN32)
    {
    ngx_int_t      limit;
    struct rlimit  rlmt;

    if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "getrlimit(RLIMIT_NOFILE) failed, ignored");

    } else {
        if (ecf->connections > (ngx_uint_t) rlmt.rlim_cur
            && (ccf->rlimit_nofile == NGX_CONF_UNSET
                || ecf->connections > (ngx_uint_t) ccf->rlimit_nofile))
        {
            limit = (ccf->rlimit_nofile == NGX_CONF_UNSET) ?
                         (ngx_int_t) rlmt.rlim_cur : ccf->rlimit_nofile;

            ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                          "%ui worker_connections exceed "
                          "open file resource limit: %i",
                          ecf->connections, limit);
        }
    }
    }
#endif /* !(NGX_WIN32) */


    if (ccf->master == 0) {
        return NGX_OK;
    }

    if (ngx_accept_mutex_ptr) {
        return NGX_OK;
    }


    /* cl should be equal to or greater than cache line size */

    cl = 128;

    size = cl            /* ngx_accept_mutex */
           + cl          /* ngx_connection_counter */
           + cl;         /* ngx_temp_number */

#if (NGX_STAT_STUB)

    size += cl           /* ngx_stat_accepted */
           + cl          /* ngx_stat_handled */
           + cl          /* ngx_stat_requests */
           + cl          /* ngx_stat_active */
           + cl          /* ngx_stat_reading */
           + cl          /* ngx_stat_writing */
           + cl;         /* ngx_stat_waiting */

#endif

    shm.size = size;
    ngx_str_set(&shm.name, "nginx_shared_zone");
    shm.log = cycle->log;

    if (ngx_shm_alloc(&shm) != NGX_OK) {
        return NGX_ERROR;
    }

    shared = shm.addr;

    ngx_accept_mutex_ptr = (ngx_atomic_t *) shared;
    ngx_accept_mutex.spin = (ngx_uint_t) -1;

    if (ngx_shmtx_create(&ngx_accept_mutex, (ngx_shmtx_sh_t *) shared,
                         cycle->lock_file.data)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_connection_counter = (ngx_atomic_t *) (shared + 1 * cl);

    (void) ngx_atomic_cmp_set(ngx_connection_counter, 0, 1);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "counter: %p, %uA",
                   ngx_connection_counter, *ngx_connection_counter);

    ngx_temp_number = (ngx_atomic_t *) (shared + 2 * cl);

    tp = ngx_timeofday();

    ngx_random_number = (tp->msec << 16) + ngx_pid;

#if (NGX_STAT_STUB)

    ngx_stat_accepted = (ngx_atomic_t *) (shared + 3 * cl);
    ngx_stat_handled = (ngx_atomic_t *) (shared + 4 * cl);
    ngx_stat_requests = (ngx_atomic_t *) (shared + 5 * cl);
    ngx_stat_active = (ngx_atomic_t *) (shared + 6 * cl);
    ngx_stat_reading = (ngx_atomic_t *) (shared + 7 * cl);
    ngx_stat_writing = (ngx_atomic_t *) (shared + 8 * cl);
    ngx_stat_waiting = (ngx_atomic_t *) (shared + 9 * cl);

#endif

    return NGX_OK;
}


#if !(NGX_WIN32)

/**
 * 如果nginx.conf配置文件中设置了timer_resolution配置项，即表明需要控制时间精度， 
 * 这时会调用setitimer方法，设置时间间隔为timer_resolution毫秒来回调ngx_timer_signal_handler 方法
 */
static void
ngx_timer_signal_handler(int signo)
{
    ngx_event_timer_alarm = 1;

#if 1
    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0, "timer signal");
#endif
}

#endif

/**
 * 在fork出worker子进程后，每一个worker进程都会调用
 * 子进程调用完此方法后才会进入正式的工作循环
 */
static ngx_int_t
ngx_event_process_init(ngx_cycle_t *cycle)
{
    ngx_uint_t           m, i;
    ngx_event_t         *rev, *wev;
    ngx_listening_t     *ls;
    ngx_connection_t    *c, *next, *old;
    ngx_core_conf_t     *ccf;
    ngx_event_conf_t    *ecf;
    ngx_event_module_t  *module;

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
    ecf = ngx_event_get_conf(cycle->conf_ctx, ngx_event_core_module);

    //当打开accept_mutex负载均衡锁，同时使用了master模式并且worker进程数量大于1 时
    if (ccf->master && ccf->worker_processes > 1 && ecf->accept_mutex) {
        ngx_use_accept_mutex = 1;       //将使用accept_mutex负载均衡锁
        ngx_accept_mutex_held = 0;
        ngx_accept_mutex_delay = ecf->accept_mutex_delay;

    } else {
        ngx_use_accept_mutex = 0;   //关闭负载均衡锁
    }

#if (NGX_WIN32)

    /*
     * disable accept mutex on win32 as it may cause deadlock if
     * grabbed by a process which can't accept connections
     */

    ngx_use_accept_mutex = 0;

#endif

    ngx_use_exclusive_accept = 0;

    ngx_queue_init(&ngx_posted_accept_events);
    ngx_queue_init(&ngx_posted_next_events);
    ngx_queue_init(&ngx_posted_events);

    //初始化红黑树实现的定时器
    if (ngx_event_timer_init(cycle->log) == NGX_ERROR) {
        return NGX_ERROR;
    }

    //调用use配置项指定的事件模块中,ngx_event_actions_t中的init方法进行这个事件模块的初始化工作
    for (m = 0; cycle->modules[m]; m++) {
        if (cycle->modules[m]->type != NGX_EVENT_MODULE) {
            continue;
        }

        if (cycle->modules[m]->ctx_index != ecf->use) {
            continue;
        }

        module = cycle->modules[m]->ctx;
        //ngx_event_actions_t中的init方法
        if (module->actions.init(cycle, ngx_timer_resolution) != NGX_OK) {
            /* fatal */
            exit(2);
        }

        break;
    }

#if !(NGX_WIN32)

    //了timer_resolution配置项，即表明需要控制时间精度， 这时会调用setitimer方法，
    //设置时间间隔为timer_resolution毫秒来回调ngx_timer_signal_handler 方法
    if (ngx_timer_resolution && !(ngx_event_flags & NGX_USE_TIMER_EVENT)) {
        struct sigaction  sa;
        struct itimerval  itv;

        ngx_memzero(&sa, sizeof(struct sigaction));
        sa.sa_handler = ngx_timer_signal_handler;
        sigemptyset(&sa.sa_mask);

        if (sigaction(SIGALRM, &sa, NULL) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "sigaction(SIGALRM) failed");
            return NGX_ERROR;
        }

        itv.it_interval.tv_sec = ngx_timer_resolution / 1000;
        itv.it_interval.tv_usec = (ngx_timer_resolution % 1000) * 1000;
        itv.it_value.tv_sec = ngx_timer_resolution / 1000;
        itv.it_value.tv_usec = (ngx_timer_resolution % 1000 ) * 1000;

        if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "setitimer() failed");
        }
    }

    if (ngx_event_flags & NGX_USE_FD_EVENT) {       //poll和devpoll事件中会开启这个宏
        struct rlimit  rlmt;

        //获取当前进程可以打开的最大文件描述符数量
        if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "getrlimit(RLIMIT_NOFILE) failed");
            return NGX_ERROR;
        }

        cycle->files_n = (ngx_uint_t) rlmt.rlim_cur;

        cycle->files = ngx_calloc(sizeof(ngx_connection_t *) * cycle->files_n,
                                  cycle->log);
        if (cycle->files == NULL) {
            return NGX_ERROR;
        }
    }

#else

    if (ngx_timer_resolution && !(ngx_event_flags & NGX_USE_TIMER_EVENT)) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                      "the \"timer_resolution\" directive is not supported "
                      "with the configured event method, ignored");
        ngx_timer_resolution = 0;
    }

#endif

    //预分配ngx_connection_t数组作为连接池,同时将ngx_cycle_t结构体中的connections成 员指向该数组
    cycle->connections =
        ngx_alloc(sizeof(ngx_connection_t) * cycle->connection_n, cycle->log);
    if (cycle->connections == NULL) {
        return NGX_ERROR;
    }

    c = cycle->connections;

    //预分配ngx_event_t事件数组作为读事件池，同时将ngx_cycle_t结构体中的read_events 成员指向该数组
    cycle->read_events = ngx_alloc(sizeof(ngx_event_t) * cycle->connection_n,
                                   cycle->log);
    if (cycle->read_events == NULL) {
        return NGX_ERROR;
    }

    rev = cycle->read_events;
    for (i = 0; i < cycle->connection_n; i++) {
        rev[i].closed = 1;
        rev[i].instance = 1;
    }
    //预分配ngx_event_t事件数组作为写事件池，同时将ngx_cycle_t结构体中的write_events 成员指向该数组
    cycle->write_events = ngx_alloc(sizeof(ngx_event_t) * cycle->connection_n,
                                    cycle->log);
    if (cycle->write_events == NULL) {
        return NGX_ERROR;
    }

    wev = cycle->write_events;
    for (i = 0; i < cycle->connection_n; i++) {
        wev[i].closed = 1;
    }

    i = cycle->connection_n;
    next = NULL;

    do {
        i--;

        /**
         * 按照数组索引idx将相应的读/写事件设置到对应ngx_connection_t连接对象中
         * 以data成员作为next指针串联成链表
         */
        c[i].data = next;
        c[i].read = &cycle->read_events[i];
        c[i].write = &cycle->write_events[i];
        c[i].fd = (ngx_socket_t) -1;

        next = &c[i];
    } while (i);
    
    //将free_connections指向单链表首部
    cycle->free_connections = next;
    cycle->free_connection_n = cycle->connection_n;

    /* for each listening socket */

    //在刚刚建立好的连接池中，为所有ngx_listening_t监听对象中的connection成员分配连接，
    //同时对监听端口的读事件设置处理方法为ngx_event_accept，也就是说，有新连接事件时将调用ngx_event_accept方法建立新连接
    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

#if (NGX_HAVE_REUSEPORT)
        if (ls[i].reuseport && ls[i].worker != ngx_worker) {
            continue;
        }
#endif

        c = ngx_get_connection(ls[i].fd, cycle->log);

        if (c == NULL) {
            return NGX_ERROR;
        }

        c->type = ls[i].type;
        c->log = &ls[i].log;

        c->listening = &ls[i];
        ls[i].connection = c;

        rev = c->read;

        rev->log = c->log;
        rev->accept = 1;

#if (NGX_HAVE_DEFERRED_ACCEPT)
        rev->deferred_accept = ls[i].deferred_accept;
#endif

        if (!(ngx_event_flags & NGX_USE_IOCP_EVENT)
            && cycle->old_cycle)
        {
            if (ls[i].previous) {

                /*
                 * delete the old accept events that were bound to
                 * the old cycle read events array
                 */

                old = ls[i].previous->connection;

                if (ngx_del_event(old->read, NGX_READ_EVENT, NGX_CLOSE_EVENT)
                    == NGX_ERROR)
                {
                    return NGX_ERROR;
                }

                old->fd = (ngx_socket_t) -1;
            }
        }

#if (NGX_WIN32)

        if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
            ngx_iocp_conf_t  *iocpcf;

            rev->handler = ngx_event_acceptex;

            if (ngx_use_accept_mutex) {
                continue;
            }

            if (ngx_add_event(rev, 0, NGX_IOCP_ACCEPT) == NGX_ERROR) {
                return NGX_ERROR;
            }

            ls[i].log.handler = ngx_acceptex_log_error;

            iocpcf = ngx_event_get_conf(cycle->conf_ctx, ngx_iocp_module);
            if (ngx_event_post_acceptex(&ls[i], iocpcf->post_acceptex)
                == NGX_ERROR)
            {
                return NGX_ERROR;
            }

        } else {
            rev->handler = ngx_event_accept;

            if (ngx_use_accept_mutex) {
                continue;
            }

            if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }
        }

#else

        //对监听端口的读事件设置处理方法为ngx_event_accept
        if (c->type == SOCK_STREAM) {
            rev->handler = ngx_event_accept;

#if (NGX_QUIC)
        } else if (ls[i].quic) {
            rev->handler = ngx_quic_recvmsg;
#endif
        } else {
            rev->handler = ngx_event_recvmsg;
        }

#if (NGX_HAVE_REUSEPORT)

        if (ls[i].reuseport) {
            if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }

            continue;
        }

#endif

        if (ngx_use_accept_mutex) {
            continue;
        }

#if (NGX_HAVE_EPOLLEXCLUSIVE)

        if ((ngx_event_flags & NGX_USE_EPOLL_EVENT)
            && ccf->worker_processes > 1)
        {
            ngx_use_exclusive_accept = 1;

            if (ngx_add_event(rev, NGX_READ_EVENT, NGX_EXCLUSIVE_EVENT)
                == NGX_ERROR)
            {
                return NGX_ERROR;
            }

            continue;
        }

#endif

        //将监听对象连接的读事件添加到事件驱动模块中，这样，epoll等事件模块就开始检 测监听服务，并开始向用户提供服务了
        if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
            return NGX_ERROR;
        }

#endif

    }

    return NGX_OK;
}


ngx_int_t
ngx_send_lowat(ngx_connection_t *c, size_t lowat)
{
    int  sndlowat;

#if (NGX_HAVE_LOWAT_EVENT)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
        c->write->available = lowat;
        return NGX_OK;
    }

#endif

    if (lowat == 0 || c->sndlowat) {
        return NGX_OK;
    }

    sndlowat = (int) lowat;

    if (setsockopt(c->fd, SOL_SOCKET, SO_SNDLOWAT,
                   (const void *) &sndlowat, sizeof(int))
        == -1)
    {
        ngx_connection_error(c, ngx_socket_errno,
                             "setsockopt(SO_SNDLOWAT) failed");
        return NGX_ERROR;
    }

    c->sndlowat = 1;

    return NGX_OK;
}

/**
 * 解析events{}配置块
 */
static char *
ngx_events_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                 *rv;
    void               ***ctx;
    ngx_uint_t            i;
    ngx_conf_t            pcf;
    ngx_event_module_t   *m;

    if (*(void **) conf) {
        return "is duplicate";
    }

    /* count the number of the event modules and set up their indices */

    //初始化事件模块的ctx_index, ngx_event_max_module为编译进Nginx的所有事件模块的总个数
    ngx_event_max_module = ngx_count_modules(cf->cycle, NGX_EVENT_MODULE);

    //ctx是一个指针
    ctx = ngx_pcalloc(cf->pool, sizeof(void *));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    //ctx指向一个void指针数组，数组的大小为ngx_event_max_module
    *ctx = ngx_pcalloc(cf->pool, ngx_event_max_module * sizeof(void *));
    if (*ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    *(void **) conf = ctx;

    //遍历所有的事件模块
    for (i = 0; cf->cycle->modules[i]; i++) {
        if (cf->cycle->modules[i]->type != NGX_EVENT_MODULE) {
            continue;
        }

        m = cf->cycle->modules[i]->ctx;

        //调用事件模块实现的create_conf方法
        if (m->create_conf) {
            //create_conf生成的配置项结构体指针会被存储在ctx指向的数组中。索引为ctx_index
            (*ctx)[cf->cycle->modules[i]->ctx_index] =
                                                     m->create_conf(cf->cycle);
            if ((*ctx)[cf->cycle->modules[i]->ctx_index] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }

    pcf = *cf;
    cf->ctx = ctx;
    cf->module_type = NGX_EVENT_MODULE;
    cf->cmd_type = NGX_EVENT_CONF;

    //解析配置
    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    //遍历所有的事件模块，调用它们的init_conf方法
    for (i = 0; cf->cycle->modules[i]; i++) {
        if (cf->cycle->modules[i]->type != NGX_EVENT_MODULE) {
            continue;
        }

        m = cf->cycle->modules[i]->ctx;

        if (m->init_conf) {
            rv = m->init_conf(cf->cycle,
                              (*ctx)[cf->cycle->modules[i]->ctx_index]);
            if (rv != NGX_CONF_OK) {
                return rv;
            }
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_event_connections(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_event_conf_t  *ecf = conf;

    ngx_str_t  *value;

    if (ecf->connections != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;
    ecf->connections = ngx_atoi(value[1].data, value[1].len);
    if (ecf->connections == (ngx_uint_t) NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid number \"%V\"", &value[1]);

        return NGX_CONF_ERROR;
    }

    cf->cycle->connection_n = ecf->connections;

    return NGX_CONF_OK;
}


static char *
ngx_event_use(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_event_conf_t  *ecf = conf;

    ngx_int_t             m;
    ngx_str_t            *value;
    ngx_event_conf_t     *old_ecf;
    ngx_event_module_t   *module;

    if (ecf->use != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->cycle->old_cycle->conf_ctx) {
        old_ecf = ngx_event_get_conf(cf->cycle->old_cycle->conf_ctx,
                                     ngx_event_core_module);
    } else {
        old_ecf = NULL;
    }


    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_EVENT_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        if (module->name->len == value[1].len) {
            if (ngx_strcmp(module->name->data, value[1].data) == 0) {
                ecf->use = cf->cycle->modules[m]->ctx_index;
                ecf->name = module->name->data;

                if (ngx_process == NGX_PROCESS_SINGLE
                    && old_ecf
                    && old_ecf->use != ecf->use)
                {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "when the server runs without a master process "
                               "the \"%V\" event type must be the same as "
                               "in previous configuration - \"%s\" "
                               "and it cannot be changed on the fly, "
                               "to change it you need to stop server "
                               "and start it again",
                               &value[1], old_ecf->name);

                    return NGX_CONF_ERROR;
                }

                return NGX_CONF_OK;
            }
        }
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid event type \"%V\"", &value[1]);

    return NGX_CONF_ERROR;
}


static char *
ngx_event_debug_connection(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
#if (NGX_DEBUG)
    ngx_event_conf_t  *ecf = conf;

    ngx_int_t             rc;
    ngx_str_t            *value;
    ngx_url_t             u;
    ngx_cidr_t            c, *cidr;
    ngx_uint_t            i;
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    value = cf->args->elts;

#if (NGX_HAVE_UNIX_DOMAIN)

    if (ngx_strcmp(value[1].data, "unix:") == 0) {
        cidr = ngx_array_push(&ecf->debug_connection);
        if (cidr == NULL) {
            return NGX_CONF_ERROR;
        }

        cidr->family = AF_UNIX;
        return NGX_CONF_OK;
    }

#endif

    rc = ngx_ptocidr(&value[1], &c);

    if (rc != NGX_ERROR) {
        if (rc == NGX_DONE) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "low address bits of %V are meaningless",
                               &value[1]);
        }

        cidr = ngx_array_push(&ecf->debug_connection);
        if (cidr == NULL) {
            return NGX_CONF_ERROR;
        }

        *cidr = c;

        return NGX_CONF_OK;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));
    u.host = value[1];

    if (ngx_inet_resolve_host(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in debug_connection \"%V\"",
                               u.err, &u.host);
        }

        return NGX_CONF_ERROR;
    }

    cidr = ngx_array_push_n(&ecf->debug_connection, u.naddrs);
    if (cidr == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(cidr, u.naddrs * sizeof(ngx_cidr_t));

    for (i = 0; i < u.naddrs; i++) {
        cidr[i].family = u.addrs[i].sockaddr->sa_family;

        switch (cidr[i].family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) u.addrs[i].sockaddr;
            cidr[i].u.in6.addr = sin6->sin6_addr;
            ngx_memset(cidr[i].u.in6.mask.s6_addr, 0xff, 16);
            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) u.addrs[i].sockaddr;
            cidr[i].u.in.addr = sin->sin_addr.s_addr;
            cidr[i].u.in.mask = 0xffffffff;
            break;
        }
    }

#else

    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "\"debug_connection\" is ignored, you need to rebuild "
                       "nginx using --with-debug option to enable it");

#endif

    return NGX_CONF_OK;
}


static void *
ngx_event_core_create_conf(ngx_cycle_t *cycle)
{
    ngx_event_conf_t  *ecf;

    ecf = ngx_palloc(cycle->pool, sizeof(ngx_event_conf_t));
    if (ecf == NULL) {
        return NULL;
    }

    ecf->connections = NGX_CONF_UNSET_UINT;
    ecf->use = NGX_CONF_UNSET_UINT;
    ecf->multi_accept = NGX_CONF_UNSET;
    ecf->accept_mutex = NGX_CONF_UNSET;
    ecf->accept_mutex_delay = NGX_CONF_UNSET_MSEC;
    ecf->name = (void *) NGX_CONF_UNSET;

#if (NGX_DEBUG)

    if (ngx_array_init(&ecf->debug_connection, cycle->pool, 4,
                       sizeof(ngx_cidr_t)) == NGX_ERROR)
    {
        return NULL;
    }

#endif

    return ecf;
}


static char *
ngx_event_core_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_event_conf_t  *ecf = conf;

#if (NGX_HAVE_EPOLL) && !(NGX_TEST_BUILD_EPOLL)
    int                  fd;
#endif
    ngx_int_t            i;
    ngx_module_t        *module;
    ngx_event_module_t  *event_module;

    module = NULL;

#if (NGX_HAVE_EPOLL) && !(NGX_TEST_BUILD_EPOLL)

    fd = epoll_create(100);

    if (fd != -1) {
        (void) close(fd);
        module = &ngx_epoll_module;

    } else if (ngx_errno != NGX_ENOSYS) {
        module = &ngx_epoll_module;
    }

#endif

#if (NGX_HAVE_DEVPOLL) && !(NGX_TEST_BUILD_DEVPOLL)

    module = &ngx_devpoll_module;

#endif

#if (NGX_HAVE_KQUEUE)

    module = &ngx_kqueue_module;

#endif

#if (NGX_HAVE_SELECT)

    if (module == NULL) {
        module = &ngx_select_module;
    }

#endif

    if (module == NULL) {
        for (i = 0; cycle->modules[i]; i++) {

            if (cycle->modules[i]->type != NGX_EVENT_MODULE) {
                continue;
            }

            event_module = cycle->modules[i]->ctx;

            if (ngx_strcmp(event_module->name->data, event_core_name.data) == 0)
            {
                continue;
            }

            module = cycle->modules[i];
            break;
        }
    }

    if (module == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "no events module found");
        return NGX_CONF_ERROR;
    }

    ngx_conf_init_uint_value(ecf->connections, DEFAULT_CONNECTIONS);
    cycle->connection_n = ecf->connections;

    ngx_conf_init_uint_value(ecf->use, module->ctx_index);

    event_module = module->ctx;
    ngx_conf_init_ptr_value(ecf->name, event_module->name->data);

    ngx_conf_init_value(ecf->multi_accept, 0);
    ngx_conf_init_value(ecf->accept_mutex, 0);
    ngx_conf_init_msec_value(ecf->accept_mutex_delay, 500);

    return NGX_CONF_OK;
}
