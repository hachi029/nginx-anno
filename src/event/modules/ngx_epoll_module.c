
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#if (NGX_TEST_BUILD_EPOLL)

/* epoll declarations */

#define EPOLLIN        0x001
#define EPOLLPRI       0x002
#define EPOLLOUT       0x004
#define EPOLLERR       0x008
#define EPOLLHUP       0x010
#define EPOLLRDNORM    0x040
#define EPOLLRDBAND    0x080
#define EPOLLWRNORM    0x100
#define EPOLLWRBAND    0x200
#define EPOLLMSG       0x400

#define EPOLLRDHUP     0x2000

#define EPOLLEXCLUSIVE 0x10000000
#define EPOLLONESHOT   0x40000000
#define EPOLLET        0x80000000

#define EPOLL_CTL_ADD  1
#define EPOLL_CTL_DEL  2
#define EPOLL_CTL_MOD  3

typedef union epoll_data {
    void         *ptr;
    int           fd;
    uint32_t      u32;
    uint64_t      u64;
} epoll_data_t;

struct epoll_event {
    uint32_t      events;
    epoll_data_t  data;
};


/**
 * 参数size时告诉epoll所要处理的大致事件数目，在新版本的内核实现中，此参数无意义
 */
int epoll_create(int size);

int epoll_create(int size)
{
    return -1;
}


/**
 *  op: EPOLL_CTL_ADD/EPOLL_CTL_MOD/EPOLL_CTL_DEL
 *  fd: 要检测的连接套接字
 *  event: 告诉epoll对什么样的事件感兴趣,
 */
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    return -1;
}


/**
 * 
 * 
 * events: 分配好的epoll_event结构体数组，epoll将会把发生的事件复制到events数组中，
 *         （events不可以是空指针，内核只负责把数据复制到这个events数组中，不会去帮助我们在用户态中分配内存。内核这种做法效率很高）
 * maxevents: 本次可以返回的最大事件数目,通常maxevents参数与预分配的events数组的大小是相等的
 * timeout: 示在没有检测到事件发生时最多等待的时间（单位为毫秒），如果timeout为0，则表示epoll_wait在rdllist链表中为空，立刻返回，不会等待
 * 
 * 返回值表示当前发生的事件个数，如果返回0，则表示本次调用中没有事件发生，如果返回–1，则表示出现错误，需要检查errno错误码判断错误类型。
 */
int epoll_wait(int epfd, struct epoll_event *events, int nevents, int timeout);

int epoll_wait(int epfd, struct epoll_event *events, int nevents, int timeout)
{
    return -1;
}

#if (NGX_HAVE_EVENTFD)
#define SYS_eventfd       323
#endif

#if (NGX_HAVE_FILE_AIO)

#define SYS_io_setup      245
#define SYS_io_destroy    246
#define SYS_io_getevents  247

typedef u_int  aio_context_t;

struct io_event {
    // 与提交事件时对应的iocb结构体中的 aio_data是一致的
    uint64_t  data;  /* the data field from the iocb */
    // 指向提交事件时对应的 iocb结构体
    uint64_t  obj;   /* what iocb this event came from */
    // 异步 I/O请求的结构。 res大于或等于 0时表示成功，小于0时表示失败
    int64_t   res;   /* result code for this event */
    // 保留字段
    int64_t   res2;  /* secondary result */
};


#endif
#endif /* NGX_TEST_BUILD_EPOLL */


//保存ngx_epoll_module 事件驱动模块的配置
typedef struct {
    //events是调用epoll_wait方法时传入的第3个参数maxevents
    //而第2个参数events数 组的大小也是由它决定的
    ngx_uint_t  events;             //表示epoll_wait函数返回的最大事件数
    ngx_uint_t  aio_requests;       //并发处理异步IO事件个数
} ngx_epoll_conf_t;


static ngx_int_t ngx_epoll_init(ngx_cycle_t *cycle, ngx_msec_t timer);
#if (NGX_HAVE_EVENTFD)
static ngx_int_t ngx_epoll_notify_init(ngx_log_t *log);
static void ngx_epoll_notify_handler(ngx_event_t *ev);
#endif
#if (NGX_HAVE_EPOLLRDHUP)
static void ngx_epoll_test_rdhup(ngx_cycle_t *cycle);
#endif
static void ngx_epoll_done(ngx_cycle_t *cycle);
static ngx_int_t ngx_epoll_add_event(ngx_event_t *ev, ngx_int_t event,
    ngx_uint_t flags);
static ngx_int_t ngx_epoll_del_event(ngx_event_t *ev, ngx_int_t event,
    ngx_uint_t flags);
static ngx_int_t ngx_epoll_add_connection(ngx_connection_t *c);
static ngx_int_t ngx_epoll_del_connection(ngx_connection_t *c,
    ngx_uint_t flags);
#if (NGX_HAVE_EVENTFD)
static ngx_int_t ngx_epoll_notify(ngx_event_handler_pt handler);
#endif
static ngx_int_t ngx_epoll_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,
    ngx_uint_t flags);

#if (NGX_HAVE_FILE_AIO)
static void ngx_epoll_eventfd_handler(ngx_event_t *ev);
#endif

static void *ngx_epoll_create_conf(ngx_cycle_t *cycle);
static char *ngx_epoll_init_conf(ngx_cycle_t *cycle, void *conf);

/* epoll对象描述符 */
static int                  ep = -1;
/* 作为epoll_wait函数的第二个参数，保存从内存复制的事件 */
static struct epoll_event  *event_list;
/* epoll_wait函数返回的最多事件数 */
static ngx_uint_t           nevents;

#if (NGX_HAVE_EVENTFD)
static int                  notify_fd = -1;
static ngx_event_t          notify_event;
static ngx_connection_t     notify_conn;
#endif

#if (NGX_HAVE_FILE_AIO)

// 用于通知异步I/O事件的描述符，它与 iocb结构体中的 aio_resfd成员是一致的
int                         ngx_eventfd = -1;
// 异步 I/O的上下文，全局唯一，必须由 io_setup初始化才能使用
aio_context_t               ngx_aio_ctx = 0;

//异步 I/O事件完成后进行通知的描述符，也就是 ngx_eventfd所对应的ngx_event_t事件
static ngx_event_t          ngx_eventfd_event;
//异步 I/O事件完成后进行通知的描述符 ngx_eventfd所对应的 ngx_connection_t连接
static ngx_connection_t     ngx_eventfd_conn;

#endif

#if (NGX_HAVE_EPOLLRDHUP)
ngx_uint_t                  ngx_use_epoll_rdhup;
#endif

static ngx_str_t      epoll_name = ngx_string("epoll");

/* 定义epoll模块感兴趣的配置项结构数组 */
static ngx_command_t  ngx_epoll_commands[] = {

    //在调用 epoll_wait时，将由第 2和第3个参数告诉Linux内核一次最多可返回多少个事件。
    //这个配置项表示调用一次 epoll_wait时最多可以返回的事件数，当然，它也会预分配那么多 epoll_event结构体用于存储事件
    { ngx_string("epoll_events"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_epoll_conf_t, events),
      NULL },

    //https://nginx.org/en/docs/ngx_core_module.html#worker_aio_requests
    //指明在开启异步 I/O且使用 io_setup系统调用初始化异步I/O上下文环境时 ,初始分配的异步I/O事件个数
    //即io_setup函数的第一个参数；
    { ngx_string("worker_aio_requests"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_epoll_conf_t, aio_requests),
      NULL },

      ngx_null_command
};


/**
 * 该上下文结构是基于事件模块的通用接口ngx_event_module_t 结构来定义的, 每个事件模块都要实现
 */
static ngx_event_module_t  ngx_epoll_module_ctx = {
    &epoll_name,
    ngx_epoll_create_conf,               /* create configuration */     //解析配置项
    ngx_epoll_init_conf,                 /* init configuration */       //解析配置项

    //actions成员定义的10个回调
    {
        ngx_epoll_add_event,             /* add an event */
        ngx_epoll_del_event,             /* delete an event */
        ngx_epoll_add_event,             /* enable an event */
        ngx_epoll_del_event,             /* disable an event */
        ngx_epoll_add_connection,        /* add an connection */
        ngx_epoll_del_connection,        /* delete an connection */
#if (NGX_HAVE_EVENTFD)
        ngx_epoll_notify,                /* trigger a notify */
#else
        NULL,                            /* trigger a notify */
#endif
        ngx_epoll_process_events,        /* process the events */
        /**
         * 创建epoll对象和创建 event_list 数组（调用epoll_wait 函数时用于存储从内核复制的已就绪的事件）
         */
        ngx_epoll_init,                  /* init the events */
        //在Nginx退出服务时它会得到调用, 主要是关闭epoll描述符ep，同时释放event_list数组
        ngx_epoll_done,                  /* done the events */
    }
};

/* epoll模块定义 */
ngx_module_t  ngx_epoll_module = {
    NGX_MODULE_V1,
    &ngx_epoll_module_ctx,               /* module context */
    ngx_epoll_commands,                  /* module directives */
    NGX_EVENT_MODULE,                    /* module type */
    NULL,                                /* init master */
    NULL,                                /* init module */
    NULL,                                /* init process */
    NULL,                                /* init thread */
    NULL,                                /* exit thread */
    NULL,                                /* exit process */
    NULL,                                /* exit master */
    NGX_MODULE_V1_PADDING
};


#if (NGX_HAVE_FILE_AIO)

/*
 * We call io_setup(), io_destroy() io_submit(), and io_getevents() directly
 * as syscalls instead of libaio usage, because the library header file
 * supports eventfd() since 0.3.107 version only.
 */

/**
 * 初始化文件异步IO的上下文结构
 * 
 * Linux内核提供的文件异步I/O机制充分利用了在内核中CPU与I/O设备是各自独立工作的这一特性，
 * 在提交了异步I/O操作后，进程完全可以做其他工作，直到空 闲再来查看异步I/O操作是否完成。
 * 
 * 调用io_setup方法后会获得这个异步I/O上下文的描述符（aio_context_t类型）， 
 * 这个描述符和epoll_create返回的描述符一样
 */
static int
io_setup(u_int nr_reqs, aio_context_t *ctx)
{
    return syscall(SYS_io_setup, nr_reqs, ctx);
}


/**
 * 销毁文件异步IO的上下文结构
 * 
 * 进程退出时需要调用io_destroy方法销毁异步I/O上下文，这相当于调用close关闭epoll的 描述符
 */
static int
io_destroy(aio_context_t ctx)
{
    return syscall(SYS_io_destroy, ctx);
}


/**
 * 
 * 从文件异步IO操作队列中读取操作
 * 
 * 获取已经完成的异步I/O事件, 相当于epoll中的 epoll_wait方法
 * 根据获取的io_event结构体数组，就可以获得已经完成的异步I/O操作了，特别是iocb结构体中的aio_data成员和io_event中的data，
 * 可用于传递指针，也就是说，业务中的数 据结构、事件完成后的回调方法都在这里
 */
static int
io_getevents(aio_context_t ctx, long min_nr, long nr, struct io_event *events,
    struct timespec *tmo)
{
    return syscall(SYS_io_getevents, ctx, min_nr, nr, events, tmo);
}


/**
 * 异步IO的初始化
 * 
 * ngx_epoll_init代码中，在epoll_create执行完成后如果开启了文件异步I/O功 能，则会调用此方法
 * 
 * 此方法会把异步I/O与epoll结合起来，当某一个异步I/O事件完成 后，ngx_eventfd句柄就处于可用状态，
 * 这样epoll_wait在返回ngx_eventfd_event事件后就会调 用它的回调方法ngx_epoll_eventfd_handler处理已经完成的异步I/O事件
 */
static void
ngx_epoll_aio_init(ngx_cycle_t *cycle, ngx_epoll_conf_t *epcf)
{
    int                 n;
    struct epoll_event  ee;

#if (NGX_HAVE_SYS_EVENTFD_H)
    ngx_eventfd = eventfd(0, 0);
#else
    //使用 Linux中第323个系统调用获取一个描述符句柄
    //创建一个虚拟的fd, 当异步IO完成后，这个fd上会有IO就绪事件
    ngx_eventfd = syscall(SYS_eventfd, 0);
#endif

    if (ngx_eventfd == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "eventfd() failed");
        ngx_file_aio = 0;
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "eventfd: %d", ngx_eventfd);

    n = 1;

    //设置ngx_eventfd描述符句柄为非阻塞IO模式
    if (ioctl(ngx_eventfd, FIONBIO, &n) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "ioctl(eventfd, FIONBIO) failed");
        goto failed;
    }

    // 初始化文件异步IO的上下文结构
    if (io_setup(epcf->aio_requests, &ngx_aio_ctx) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "io_setup() failed");
        goto failed;
    }

    /* 设置异步IO事件ngx_eventfd_event，该事件是ngx_eventfd对应的ngx_event事件 */
    //设置用于异步 I/O完成通知的 ngx_eventfd_event事件，它与 ngx_eventfd_conn连接是对应的
    ngx_eventfd_event.data = &ngx_eventfd_conn;
    // 在异步 I/O事件完成后，使用 ngx_epoll_eventfd_handler方法处理
    ngx_eventfd_event.handler = ngx_epoll_eventfd_handler;
     /* 设置事件相应的日志 */
    ngx_eventfd_event.log = cycle->log;
    /* 设置active标志位 */
    ngx_eventfd_event.active = 1;
    /* 初始化ngx_eventfd_conn 连接 */
    ngx_eventfd_conn.fd = ngx_eventfd;
    /* ngx_eventfd_conn连接的读事件就是ngx_eventfd_event事件 */
    ngx_eventfd_conn.read = &ngx_eventfd_event;
    /* 设置连接的相应日志 */
    ngx_eventfd_conn.log = cycle->log;

    ee.events = EPOLLIN|EPOLLET;
    ee.data.ptr = &ngx_eventfd_conn;

    /* 向epoll对象添加异步IO通知描述符ngx_eventfd */
    if (epoll_ctl(ep, EPOLL_CTL_ADD, ngx_eventfd, &ee) != -1) {
        return;
    }

    /* 若添加出错，则销毁文件异步IO上下文结构，并返回 */
    ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                  "epoll_ctl(EPOLL_CTL_ADD, eventfd) failed");

    if (io_destroy(ngx_aio_ctx) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "io_destroy() failed");
    }

failed:

    if (close(ngx_eventfd) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "eventfd close() failed");
    }

    ngx_eventfd = -1;
    ngx_aio_ctx = 0;
    ngx_file_aio = 0;
}

#endif


/**
 * epoll模块初始化函数
 * 1）调用epoll_create方法创建epoll对象。
 * 2）创建event_list数组，用于进行epoll_wait调用时传递内核态的事件。
 */
static ngx_int_t
ngx_epoll_init(ngx_cycle_t *cycle, ngx_msec_t timer)
{
    ngx_epoll_conf_t  *epcf;

    /* 获取ngx_epoll_module模块的配置项结构 */
    epcf = ngx_event_get_conf(cycle->conf_ctx, ngx_epoll_module);

    if (ep == -1) {
        //创建epoll对象描述符, 大部分版本不处理参数
        ep = epoll_create(cycle->connection_n / 2);

        /* 若创建失败，则出错返回 */
        if (ep == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "epoll_create() failed");
            return NGX_ERROR;
        }

#if (NGX_HAVE_EVENTFD)
        if (ngx_epoll_notify_init(cycle->log) != NGX_OK) {
            ngx_epoll_module_ctx.actions.notify = NULL;
        }
#endif

#if (NGX_HAVE_FILE_AIO)
        /* 若系统支持异步IO，则初始化异步IO */
        ngx_epoll_aio_init(cycle, epcf);
#endif

#if (NGX_HAVE_EPOLLRDHUP)
        ngx_epoll_test_rdhup(cycle);
#endif
    }

    /*
     * 预分配events个epoll_event结构event_list，event_list是存储产生事件的数组；
     * events由epoll_events配置项指定；
     */
    if (nevents < epcf->events) {
        /*
         * 若现有event_list个数小于配置项所指定的值epcf->events，
         * 则先释放，再从新分配；
         */
        if (event_list) {
            ngx_free(event_list);
        }

        //创建event_list数组，用于进行epoll_wait调用时传递内核态的事件
        //nevents是epoll_events配置项参数,既指明了epoll_wait一次返回的最大事件数，也告诉了event_list应该分配的数组大小
        event_list = ngx_alloc(sizeof(struct epoll_event) * epcf->events,
                               cycle->log);
        if (event_list == NULL) {
            return NGX_ERROR;
        }
    }

    /* 设置正确的epoll_event结构个数 */
    nevents = epcf->events;

    /* 指定IO的读写方法 */
    /*
     * 初始化全局变量ngx_io, ngx_os_io定义为:
        ngx_os_io_t ngx_os_io = {
            ngx_unix_recv,
            ngx_readv_chain,
            ngx_udp_unix_recv,
            ngx_unix_send,
            ngx_writev_chain,
            0
        };（位于src/os/unix/ngx_posix_init.c）
    */
    ngx_io = ngx_os_io;

    //设置 ngx_event_actions接口
    ngx_event_actions = ngx_epoll_module_ctx.actions;

#if (NGX_HAVE_CLEAR_EVENT)
    //默认是采用 ET模式来使用 epoll的，NGX_USE_CLEAR_EVENT宏实际上就是在告诉 Nginx使用 LT模式
    ngx_event_flags = NGX_USE_CLEAR_EVENT
#else
    /* LT模式 */
    ngx_event_flags = NGX_USE_LEVEL_EVENT
#endif
                      |NGX_USE_GREEDY_EVENT
                      |NGX_USE_EPOLL_EVENT;

    return NGX_OK;
}


#if (NGX_HAVE_EVENTFD)

static ngx_int_t
ngx_epoll_notify_init(ngx_log_t *log)
{
    struct epoll_event  ee;

#if (NGX_HAVE_SYS_EVENTFD_H)
    notify_fd = eventfd(0, 0);
#else
    notify_fd = syscall(SYS_eventfd, 0);
#endif

    if (notify_fd == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "eventfd() failed");
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0,
                   "notify eventfd: %d", notify_fd);

    notify_event.handler = ngx_epoll_notify_handler;
    notify_event.log = log;
    notify_event.active = 1;

    notify_conn.fd = notify_fd;
    notify_conn.read = &notify_event;
    notify_conn.log = log;

    ee.events = EPOLLIN|EPOLLET;
    ee.data.ptr = &notify_conn;

    if (epoll_ctl(ep, EPOLL_CTL_ADD, notify_fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "epoll_ctl(EPOLL_CTL_ADD, eventfd) failed");

        if (close(notify_fd) == -1) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                            "eventfd close() failed");
        }

        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_epoll_notify_handler(ngx_event_t *ev)
{
    ssize_t               n;
    uint64_t              count;
    ngx_err_t             err;
    ngx_event_handler_pt  handler;

    if (++ev->index == NGX_MAX_UINT32_VALUE) {
        ev->index = 0;

        n = read(notify_fd, &count, sizeof(uint64_t));

        err = ngx_errno;

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "read() eventfd %d: %z count:%uL", notify_fd, n, count);

        if ((size_t) n != sizeof(uint64_t)) {
            ngx_log_error(NGX_LOG_ALERT, ev->log, err,
                          "read() eventfd %d failed", notify_fd);
        }
    }

    handler = ev->data;
    handler(ev);
}

#endif


#if (NGX_HAVE_EPOLLRDHUP)

static void
ngx_epoll_test_rdhup(ngx_cycle_t *cycle)
{
    int                 s[2], events;
    struct epoll_event  ee;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, s) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "socketpair() failed");
        return;
    }

    ee.events = EPOLLET|EPOLLIN|EPOLLRDHUP;

    if (epoll_ctl(ep, EPOLL_CTL_ADD, s[0], &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "epoll_ctl() failed");
        goto failed;
    }

    if (close(s[1]) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "close() failed");
        s[1] = -1;
        goto failed;
    }

    s[1] = -1;

    events = epoll_wait(ep, &ee, 1, 5000);

    if (events == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "epoll_wait() failed");
        goto failed;
    }

    if (events) {
        ngx_use_epoll_rdhup = ee.events & EPOLLRDHUP;

    } else {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, NGX_ETIMEDOUT,
                      "epoll_wait() timed out");
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "testing the EPOLLRDHUP flag: %s",
                   ngx_use_epoll_rdhup ? "success" : "fail");

failed:

    if (s[1] != -1 && close(s[1]) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "close() failed");
    }

    if (close(s[0]) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "close() failed");
    }
}

#endif

/**
 * 在Nginx退出服务时它会得到调用, 主要是关闭epoll描述符ep，同时释放event_list数组
 */
static void
ngx_epoll_done(ngx_cycle_t *cycle)
{
    if (close(ep) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "epoll close() failed");
    }

    ep = -1;

#if (NGX_HAVE_EVENTFD)

    if (close(notify_fd) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "eventfd close() failed");
    }

    notify_fd = -1;

#endif

#if (NGX_HAVE_FILE_AIO)

    if (ngx_eventfd != -1) {

        if (io_destroy(ngx_aio_ctx) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "io_destroy() failed");
        }

        if (close(ngx_eventfd) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "eventfd close() failed");
        }

        ngx_eventfd = -1;
    }

    ngx_aio_ctx = 0;

#endif

    ngx_free(event_list);

    event_list = NULL;
    nevents = 0;
}


/**
 * 向epoll中添加事件, 通过调用epoll_ctl函数实现
 * 
 * 将某个描述符的某个事件添加到epoll对象的监控机制中
 */
static ngx_int_t
ngx_epoll_add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    int                  op;
    uint32_t             events, prev;
    ngx_event_t         *e;
    ngx_connection_t    *c;
    struct epoll_event   ee;

    //每个事件的 data成员都存放着其对应的 ngx_connection_t连接
    /* 获取事件关联的连接 */
    c = ev->data;

    /* events参数是方便下面确定当前事件是可读还是可写 */
    events = (uint32_t) event;

    /*
     * 这里在判断事件类型是可读还是可写，必须根据事件的active标志位来判断事件是否活跃；
     * 因为epoll_ctl函数有添加add和修改mod模式，
     * 若一个事件所关联的连接已经在epoll对象的监控中，则只需修改事件的类型即可；
     * 若一个事件所关联的连接没有在epoll对象的监控中，则需要将其相应的事件类型注册到epoll对象中；
     * 这样做的情况是避免与事件相关联的连接两次注册到epoll对象中；
     */
    //下面会根据 event参数确定当前事件是读事件还是写事件，这会决定 events是加上 EPOLLIN标志位还是EPOLLOUT标志位
    if (event == NGX_READ_EVENT) {
        /*
         * 若待添加的事件类型event是可读；
         * 则首先判断该事件所关联的连接是否将写事件添加到epoll对象中，
         * 即先判断关联的连接的写事件是否为活跃事件；
         */
        e = c->write;
        prev = EPOLLOUT;
#if (NGX_READ_EVENT != EPOLLIN|EPOLLRDHUP)
        events = EPOLLIN|EPOLLRDHUP;
#endif

    } else {
        e = c->read;
        prev = EPOLLIN|EPOLLRDHUP;
#if (NGX_WRITE_EVENT != EPOLLOUT)
        events = EPOLLOUT;
#endif
    }

    //根据 active标志位确定是否为活跃事件，以决定到底是修改还是添加事件
    if (e->active) {
        /* 若当前事件是活跃事件，则只需修改其事件类型即可 */
        op = EPOLL_CTL_MOD;
        events |= prev;

    } else {
        /* 若当前事件不是活跃事件，则将该事件添加到epoll对象中 */
        op = EPOLL_CTL_ADD;
    }

#if (NGX_HAVE_EPOLLEXCLUSIVE && NGX_HAVE_EPOLLRDHUP)
    if (flags & NGX_EXCLUSIVE_EVENT) {
        events &= ~EPOLLRDHUP;
    }
#endif

    //加入 flags参数到events标志位中
    ee.events = events | (uint32_t) flags;
    //ptr成员存储的是 ngx_connection_t连接
    ee.data.ptr = (void *) ((uintptr_t) c | ev->instance);

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "epoll add event: fd:%d op:%d ev:%08XD",
                   c->fd, op, ee.events);

    //调用 epoll_ctl方法向epoll中添加事件或者在 epoll中修改事件
    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                      "epoll_ctl(%d, %d) failed", op, c->fd);
        return NGX_ERROR;
    }

    // 将事件的 active标志位置为 1，表示当前事件是活跃的
    ev->active = 1;
#if 0
    ev->oneshot = (flags & NGX_ONESHOT_EVENT) ? 1 : 0;
#endif

    return NGX_OK;
}


/**
 * 将某个连接的某个事件从epoll对象监控中删除。 删除epoll中的事件，通过调用epoll_ctl函数实现
 * 一个ev上可能添加了多个事件（读、写）到epoll上，此方法可能只是删除读或删除写
 * 
 */
static ngx_int_t
ngx_epoll_del_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    int                  op;
    uint32_t             prev;
    ngx_event_t         *e;
    ngx_connection_t    *c;
    struct epoll_event   ee;

    /*
     * when the file descriptor is closed, the epoll automatically deletes
     * it from its queue, so we do not need to delete explicitly the event
     * before the closing the file descriptor
     */

     /* 当事件关联的文件描述符关闭后，epoll对象自动将其事件删除 */
    if (flags & NGX_CLOSE_EVENT) {
        ev->active = 0;
        return NGX_OK;
    }

    /* 获取事件关联的连接对象 */
    c = ev->data;

    /* 根据event参数判断当前删除的是读事件还是写事件 */
    if (event == NGX_READ_EVENT) {
        /* 若要删除读事件，则首先判断写事件的active标志位 */
        e = c->write;
        prev = EPOLLOUT;

    } else {
         /* 若要删除写事件，则判断读事件的active标志位 */
        e = c->read;
        prev = EPOLLIN|EPOLLRDHUP;
    }

    /*
     * 若要删除读事件，且写事件是活跃事件，则修改事件类型即可；
     * 若要删除写事件，且读事件是活跃事件，则修改事件类型即可；
     */
    if (e->active) {
        op = EPOLL_CTL_MOD;
        ee.events = prev | (uint32_t) flags;
        ee.data.ptr = (void *) ((uintptr_t) c | ev->instance);

    } else {
        /* 若读写事件都不是活跃事件，此时表示事件未准备就绪，则将其删除 */
        op = EPOLL_CTL_DEL;
        ee.events = 0;
        ee.data.ptr = NULL;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "epoll del event: fd:%d op:%d ev:%08XD",
                   c->fd, op, ee.events);

    /* 删除或修改事件 */
    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                      "epoll_ctl(%d, %d) failed", op, c->fd);
        return NGX_ERROR;
    }

    /* 设置当前事件的active标志位 */
    ev->active = 0;

    return NGX_OK;
}


/**
 * 连接添加， 通过调用epoll_ctl 函数， 将指定连接所关联的描述符添加到epoll对象中
 * 添加EPOLLIN|EPOLLOUT|EPOLLET|EPOLLRDHUP事件
 */
static ngx_int_t
ngx_epoll_add_connection(ngx_connection_t *c)
{
    struct epoll_event  ee;

    /* 设置事件的类型：可读、可写、ET模式 */
    ee.events = EPOLLIN|EPOLLOUT|EPOLLET|EPOLLRDHUP;
    ee.data.ptr = (void *) ((uintptr_t) c | c->read->instance);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "epoll add connection: fd:%d ev:%08XD", c->fd, ee.events);

    /* 调用epoll_ctl方法将连接所关联的描述符添加到epoll对象中 */
    if (epoll_ctl(ep, EPOLL_CTL_ADD, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "epoll_ctl(EPOLL_CTL_ADD, %d) failed", c->fd);
        return NGX_ERROR;
    }

    /* 设置读写事件的active标志位 */
    c->read->active = 1;
    c->write->active = 1;

    return NGX_OK;
}


/**
 * 将连接所关联的描述符从epoll对象中删除
 * 
 * 设置 ee.events = 0;  连接删除， 通过调用epoll_ctl 函数
 * 
 */
static ngx_int_t
ngx_epoll_del_connection(ngx_connection_t *c, ngx_uint_t flags)
{
    int                 op;
    struct epoll_event  ee;

    /*
     * when the file descriptor is closed the epoll automatically deletes
     * it from its queue so we do not need to delete explicitly the event
     * before the closing the file descriptor
     */

    if (flags & NGX_CLOSE_EVENT) {
        c->read->active = 0;
        c->write->active = 0;
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "epoll del connection: fd:%d", c->fd);

    op = EPOLL_CTL_DEL;
    ee.events = 0;
    ee.data.ptr = NULL;

    /* 调用epoll_ctl方法将描述符从epoll对象中删除 */
    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "epoll_ctl(%d, %d) failed", op, c->fd);
        return NGX_ERROR;
    }

    /* 设置描述符读写事件的active标志位 */
    c->read->active = 0;
    c->write->active = 0;

    return NGX_OK;
}


#if (NGX_HAVE_EVENTFD)

static ngx_int_t
ngx_epoll_notify(ngx_event_handler_pt handler)
{
    static uint64_t inc = 1;

    notify_event.data = handler;

    if ((size_t) write(notify_fd, &inc, sizeof(uint64_t)) != sizeof(uint64_t)) {
        ngx_log_error(NGX_LOG_ALERT, notify_event.log, ngx_errno,
                      "write() to eventfd %d failed", notify_fd);
        return NGX_ERROR;
    }

    return NGX_OK;
}

#endif


/**
 * ngx_epoll_module 模块的事件处理由函数, 处理已准备就绪的事件
 * 
 * 实现了收集、分发 事件的process_events接口的方法
 * 
 * 方法会收集当前触发的所有事件，对于不需要加入到post队列延 后处理的事件，该方法会立刻执行它们的回调方法，
 * 这其实是在做分发事件的工作，只是它 会在自己的进程中调用这些回调方法而已，
 * 因此，每一个回调方法都不能导致进程休眠或者 消耗太多的时间，以免epoll不能即时地处理其他事件
 * 
 */
static ngx_int_t
ngx_epoll_process_events(ngx_cycle_t *cycle, ngx_msec_t timer, ngx_uint_t flags)
{
    int                events;
    uint32_t           revents;
    ngx_int_t          instance, i;
    ngx_uint_t         level;
    ngx_err_t          err;
    ngx_event_t       *rev, *wev;
    ngx_queue_t       *queue;
    ngx_connection_t  *c;

    /* NGX_TIMER_INFINITE == INFTIM */

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "epoll timer: %M", timer);

    // nevents 最多取出的事件个数
    //timer最多等待的时间, 等待监控的事件准备就绪 
    events = epoll_wait(ep, event_list, (int) nevents, timer);

    /* 若出错，设置错误编码 */
    err = (events == -1) ? ngx_errno : 0;

    /*
     * 若没有设置timer_resolution配置项时，
     * NGX_UPDATE_TIME 标志表示每次调用epoll_wait函数返回后需要更新时间；
     * 若设置timer_resolution配置项，
     * 则每隔timer_resolution配置项参数会设置ngx_event_timer_alarm为1，表示需要更新时间；
     */
    //Nginx对时间的缓存和管理。当 flags标志位指示要更新时间时，就是在这里更新的
    if (flags & NGX_UPDATE_TIME || ngx_event_timer_alarm) {
        /* 更新时间，将时间缓存到一组全局变量中，方便程序高效获取事件 */
        ngx_time_update();
    }

    /* 处理epoll_wait的错误 */
    if (err) {
        if (err == NGX_EINTR) {

            if (ngx_event_timer_alarm) {
                ngx_event_timer_alarm = 0;
                return NGX_OK;
            }

            level = NGX_LOG_INFO;

        } else {
            level = NGX_LOG_ALERT;
        }

        ngx_log_error(level, cycle->log, err, "epoll_wait() failed");
        return NGX_ERROR;
    }

    /*
     * 若epoll_wait返回的事件数events为0，则有两种可能：
     * 1、超时返回，即时间超过timer；
     * 2、在限定的timer时间内返回，此时表示出错error返回；
     */
    if (events == 0) {
        if (timer != NGX_TIMER_INFINITE) {
            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                      "epoll_wait() returned no events without timeout");
        return NGX_ERROR;
    }

    /* 遍历由epoll_wait返回的所有已准备就绪的事件，并处理这些事件 */
    for (i = 0; i < events; i++) {
         //对照ngx_epoll_add_event方法，可以看到ptr成员就是 ngx_connection_t连接的地址，
        //但最后 1位有特殊含义，是添加事件时设置的事件过期标志位, 需要把它屏蔽掉
        c = event_list[i].data.ptr;

        //将地址的最后一位取出来，用 instance变量标识, 作为事件过期标志位
        instance = (uintptr_t) c & 1;
        //无论是 32位还是 64位机器，其地址的最后 1位肯定是 0，可以用下面这行语句把ngx_connection_t的地址还原到真正的地址值
        /* 屏蔽连接对象的最低位，即获取连接对象的真正地址 */
        c = (ngx_connection_t *) ((uintptr_t) c & (uintptr_t) ~1);

        /* 获取读事件 */
        rev = c->read;

        /*
         * 同一连接的读写事件的instance标志位是相同的；
         * 若fd描述符为-1，或连接对象读事件的instance标志位不相同，则判为过期事件；
         */
        // 判断这个读事件是否为过期事件
        //当fd套接字描述符为 -1或者 instance标志位不相等时，表示这个事件已经过期了，不用处理
        if (c->fd == -1 || rev->instance != instance) {

            /*
             * the stale event from a file descriptor
             * that was just closed in this iteration
             */

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "epoll: stale event %p", c);
            continue;
        }

        /* 获取连接对象中已准备就绪的事件类型 */
        revents = event_list[i].events;

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "epoll: fd:%d ev:%04XD d:%p",
                       c->fd, revents, event_list[i].data.ptr);

        /* 记录epoll_wait的错误返回状态 */
        /*
         * EPOLLERR表示连接出错；EPOLLHUP表示收到RST报文；
         * 检测到上面这两种错误时，TCP连接中可能存在未读取的数据；
         */
        if (revents & (EPOLLERR|EPOLLHUP)) {
            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "epoll_wait() error on fd:%d ev:%04XD",
                           c->fd, revents);

            /*
             * if the error events were returned, add EPOLLIN and EPOLLOUT
             * to handle the events at least in one active handler
             */

            revents |= EPOLLIN|EPOLLOUT;
        }

#if 0
        if (revents & ~(EPOLLIN|EPOLLOUT|EPOLLERR|EPOLLHUP)) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          "strange epoll_wait() events fd:%d ev:%04XD",
                          c->fd, revents);
        }
#endif

         /* 连接有可读事件，且该读事件是active活跃的 */
        if ((revents & EPOLLIN) && rev->active) {

#if (NGX_HAVE_EPOLLRDHUP)
            /* EPOLLRDHUP表示连接对端关闭了读取端 */
            if (revents & EPOLLRDHUP) {
                rev->pending_eof = 1;
            }
#endif

            /* 读事件已准备就绪 */
            /*
            * 这里要区分active与ready：
            * active是指事件被添加到epoll对象的监控中，
            * 而ready表示被监控的事件已经准备就绪，即可以对其进程IO处理；
            */
            rev->ready = 1;
            rev->available = -1;

            /*
             * NGX_POST_EVENTS表示已准备就绪的事件需要延迟处理，
             * 根据accept标志位将事件加入到相应的队列中；
             */
            // 在开启了负载均衡锁且获取到了锁后，flags参数中会含有 NGX_POST_EVENTS，表示这批事件要延后处理
            if (flags & NGX_POST_EVENTS) {
                //如果要在 post队列中延后处理该事件，首先要判断它是新连接事件还是普通事件，
                //以决定把它加入到 ngx_posted_accept_events队列或者 ngx_posted_events队列中。
                queue = rev->accept ? &ngx_posted_accept_events
                                    : &ngx_posted_events;

                //将事件加入queue中
                ngx_post_event(rev, queue);

            } else {
                // 若不延迟处理，立即调用读事件的回调方法来处理这个事件
                rev->handler(rev);
            }
        }

        /* 获取连接的写事件，写事件的处理逻辑过程与读事件类似 */
        wev = c->write;

        /* 连接有可写事件，且该写事件是active活跃的 */
        if ((revents & EPOLLOUT) && wev->active) {

            // 判断这个读事件是否为过期事件
            //当 fd套接字描述符为 -1或者 instance标志位不相等时，表示这个事件已经过期了，不用处理
            if (c->fd == -1 || wev->instance != instance) {

                /*
                 * the stale event from a file descriptor
                 * that was just closed in this iteration
                 */

                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                               "epoll: stale event %p", c);
                continue;
            }

            /* 写事件已准备就绪 */
            wev->ready = 1;
#if (NGX_THREADS)
            wev->complete = 1;
#endif

            /*
             * NGX_POST_EVENTS表示已准备就绪的事件需要延迟处理，
             * 根据accept标志位将事件加入到相应的队列中；
             */
            if (flags & NGX_POST_EVENTS) {
                // 将这个事件添加到 post队列中延后处理
                ngx_post_event(wev, &ngx_posted_events);

            } else {
                // 若不延迟处理，立即调用这个写事件的回调方法来处理这个事件
                wev->handler(wev);
            }
        }
    }

    return NGX_OK;
}


#if (NGX_HAVE_FILE_AIO)

/**
 * 异步io事件触发后的handler
 * epoll_wait在返回ngx_eventfd_event事件后就会调用它的回调方法ngx_epoll_eventfd_handler处理已经完成的异步I/O事件
 * 
 * 通过ngx_eventfd通知描述符和 ngx_epoll_eventfd_handler回调方法，将文件异步I/O事件结合起来的
 */
static void
ngx_epoll_eventfd_handler(ngx_event_t *ev)
{
    int               n, events;
    long              i;
    uint64_t          ready;
    ngx_err_t         err;
    ngx_event_t      *e;
    ngx_event_aio_t  *aio;
    // 一次性最多处理 64个事件
    struct io_event   event[64];
    struct timespec   ts;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0, "eventfd handler");

    //获取已经完成的事件数目，并设置到 ready中，注意，这个 ready是可以大于 64的
    n = read(ngx_eventfd, &ready, 8);

    err = ngx_errno;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0, "eventfd: %d", n);

    if (n != 8) {
        if (n == -1) {
            if (err == NGX_EAGAIN) {
                return;
            }

            ngx_log_error(NGX_LOG_ALERT, ev->log, err, "read(eventfd) failed");
            return;
        }

        ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                      "read(eventfd) returned only %d bytes", n);
        return;
    }

    ts.tv_sec = 0;
    ts.tv_nsec = 0;

     /* 遍历ready，处理异步IO事件 */
    // ready表示还未处理的事件。当 ready大于0时继续处理
    while (ready) {

        // 调用io_getevents获取已经完成的异步I/O事件
        events = io_getevents(ngx_aio_ctx, 1, 64, event, &ts);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "io_getevents: %d", events);

        if (events > 0) {
            // 将 ready减去已经取出的事件
            ready -= events;

            // 处理 event数组里的事件
            for (i = 0; i < events; i++) {

                ngx_log_debug4(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                               "io_event: %XL %XL %L %L",
                                event[i].data, event[i].obj,
                                event[i].res, event[i].res2);

                /* 获取异步IO事件对应的实际事件 */
                e = (ngx_event_t *) (uintptr_t) event[i].data;

                e->complete = 1;
                e->active = 0;
                e->ready = 1;

                // data成员指向这个异步 I/O事件对应着的实际事件
                aio = e->data;
                aio->res = event[i].res;

                // 将该事件放到 ngx_posted_events队列中延后执行
                ngx_post_event(e, &ngx_posted_events);
            }

            continue;
        }

        if (events == 0) {
            return;
        }

        /* events == -1 */
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                      "io_getevents() failed");
        return;
    }
}

#endif


/**
 * 创建模块配置结构体
 */
static void *
ngx_epoll_create_conf(ngx_cycle_t *cycle)
{
    ngx_epoll_conf_t  *epcf;

    epcf = ngx_palloc(cycle->pool, sizeof(ngx_epoll_conf_t));
    if (epcf == NULL) {
        return NULL;
    }

    epcf->events = NGX_CONF_UNSET;
    epcf->aio_requests = NGX_CONF_UNSET;

    return epcf;
}


/**
 * 初始化模块配置结构体
 */
static char *
ngx_epoll_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_epoll_conf_t *epcf = conf;

    ngx_conf_init_uint_value(epcf->events, 512);
    ngx_conf_init_uint_value(epcf->aio_requests, 32);

    return NGX_CONF_OK;
}
