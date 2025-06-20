
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_ZLIB)
#include <zlib.h>
#endif


/**
 * https://nginx.org/en/docs/http/ngx_http_log_module.html
 * 记录访问日志模块
 */
typedef struct ngx_http_log_op_s  ngx_http_log_op_t;

typedef u_char *(*ngx_http_log_op_run_pt) (ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);

typedef size_t (*ngx_http_log_op_getlen_pt) (ngx_http_request_t *r,
    uintptr_t data);


/**
 * 表示log_format配置指令中的一个变量 $xxx
 */
struct ngx_http_log_op_s {
    size_t                      len;        //变量名称长度
    ngx_http_log_op_getlen_pt   getlen;     //获取变量值的长度
    ngx_http_log_op_run_pt      run;        //获取变量值的handler
    uintptr_t                   data;      //如果为预置变量， data为0，否则为 变量索引index ;还可能是预分配的存放变量值的内存空间
};


//表示一种日志格式
typedef struct {
    ngx_str_t                   name;   //日志格式名称
    //日志格式中使用的变量的索引
    ngx_array_t                *flushes; //元素类型为ngx_int_t, 指向ngx_http_log_op_t 的data
    //每个元素代表一个日志格式中的变量
    ngx_array_t                *ops;        /* array of ngx_http_log_op_t */
} ngx_http_log_fmt_t;


/**
 * 本模块main级别的配置结构体
 */
typedef struct { 
    //通过log_format指令配置的多种日志格式, 元素类型为ngx_http_log_fmt_t
    ngx_array_t                 formats;    /* array of ngx_http_log_fmt_t */
    //标识使用的是默认预置的combined格式
    ngx_uint_t                  combined_used; /* unsigned  combined_used:1 */
} ngx_http_log_main_conf_t;


/**
 * 表示日志输出的buf缓冲区
 */
typedef struct {
    u_char                     *start;
    u_char                     *pos;
    u_char                     *last;

    ngx_event_t                *event;      //定时flush事件
    ngx_msec_t                  flush;      //定时时间interval
    ngx_int_t                   gzip;       //gzip level
} ngx_http_log_buf_t;


typedef struct {
    ngx_array_t                *lengths;
    ngx_array_t                *values;
} ngx_http_log_script_t;


/**
 * 表示一个日志输出配置 access_log
 */
typedef struct {
    ngx_open_file_t            *file;               //输出的文件
    ngx_http_log_script_t      *script;             //包含变量的文件名，需要在运行时才能获取真实的文件名
    time_t                      disk_full_time;     //日志磁盘满时间
    time_t                      error_log_time;     //上次记录写入日志错误的事件，用于避免频繁向错误日志输出错误信息。（每隔60秒记录一次）
    ngx_syslog_peer_t          *syslog_peer;        //用于向syslog输出日志
    ngx_http_log_fmt_t         *format;
    ngx_http_complex_value_t   *filter;             //[if=condition]], 日志过滤条件
} ngx_http_log_t;


/**
 * 本模块loc级别配置
 * 
 * https://nginx.org/en/docs/http/ngx_http_log_module.html#open_log_file_cache
 */
typedef struct {
    //当前级别(main|srv|loc)配置的多个access_log.  元素类型 ngx_http_log_t
    ngx_array_t                *logs;       /* array of ngx_http_log_t */

    ngx_open_file_cache_t      *open_file_cache;        //本模块定义的打开文件缓存区。为null表示关闭缓冲区
    time_t                      open_file_cache_valid;  // 设置要检查文件是否存在的事件间隔，默认60秒
    ngx_uint_t                  open_file_cache_min_uses; //在inactive时间内，文件至少被使用多少次才被认为活跃而不从缓存区中移除

    //关闭日志输出
    ngx_uint_t                  off;        /* unsigned  off:1 */
} ngx_http_log_loc_conf_t;


typedef struct {
    ngx_str_t                   name;
    size_t                      len;
    ngx_http_log_op_run_pt      run;
} ngx_http_log_var_t;


#define NGX_HTTP_LOG_ESCAPE_DEFAULT  0
#define NGX_HTTP_LOG_ESCAPE_JSON     1
#define NGX_HTTP_LOG_ESCAPE_NONE     2


static void ngx_http_log_write(ngx_http_request_t *r, ngx_http_log_t *log,
    u_char *buf, size_t len);
static ssize_t ngx_http_log_script_write(ngx_http_request_t *r,
    ngx_http_log_script_t *script, u_char **name, u_char *buf, size_t len);

#if (NGX_ZLIB)
static ssize_t ngx_http_log_gzip(ngx_fd_t fd, u_char *buf, size_t len,
    ngx_int_t level, ngx_log_t *log);

static void *ngx_http_log_gzip_alloc(void *opaque, u_int items, u_int size);
static void ngx_http_log_gzip_free(void *opaque, void *address);
#endif

static void ngx_http_log_flush(ngx_open_file_t *file, ngx_log_t *log);
static void ngx_http_log_flush_handler(ngx_event_t *ev);

static u_char *ngx_http_log_pipe(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);
static u_char *ngx_http_log_time(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);
static u_char *ngx_http_log_iso8601(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);
static u_char *ngx_http_log_msec(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);
static u_char *ngx_http_log_request_time(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);
static u_char *ngx_http_log_status(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);
static u_char *ngx_http_log_bytes_sent(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);
static u_char *ngx_http_log_body_bytes_sent(ngx_http_request_t *r,
    u_char *buf, ngx_http_log_op_t *op);
static u_char *ngx_http_log_request_length(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);

static ngx_int_t ngx_http_log_variable_compile(ngx_conf_t *cf,
    ngx_http_log_op_t *op, ngx_str_t *value, ngx_uint_t escape);
static size_t ngx_http_log_variable_getlen(ngx_http_request_t *r,
    uintptr_t data);
static u_char *ngx_http_log_variable(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);
static uintptr_t ngx_http_log_escape(u_char *dst, u_char *src, size_t size);
static size_t ngx_http_log_json_variable_getlen(ngx_http_request_t *r,
    uintptr_t data);
static u_char *ngx_http_log_json_variable(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);
static size_t ngx_http_log_unescaped_variable_getlen(ngx_http_request_t *r,
    uintptr_t data);
static u_char *ngx_http_log_unescaped_variable(ngx_http_request_t *r,
    u_char *buf, ngx_http_log_op_t *op);


static void *ngx_http_log_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_log_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_log_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_log_set_log(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_log_set_format(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_log_compile_format(ngx_conf_t *cf,
    ngx_array_t *flushes, ngx_array_t *ops, ngx_array_t *args, ngx_uint_t s);
static char *ngx_http_log_open_file_cache(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_log_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_log_commands[] = {

    { ngx_string("log_format"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_2MORE,
      ngx_http_log_set_format,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("access_log"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_HTTP_LMT_CONF|NGX_CONF_1MORE,
      ngx_http_log_set_log,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("open_log_file_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_http_log_open_file_cache,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_log_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_log_init,                     /* postconfiguration */

    ngx_http_log_create_main_conf,         /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_log_create_loc_conf,          /* create location configuration */
    ngx_http_log_merge_loc_conf            /* merge location configuration */
};


ngx_module_t  ngx_http_log_module = {
    NGX_MODULE_V1,
    &ngx_http_log_module_ctx,              /* module context */
    ngx_http_log_commands,                 /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t  ngx_http_access_log = ngx_string(NGX_HTTP_LOG_PATH);


static ngx_str_t  ngx_http_combined_fmt =
    ngx_string("$remote_addr - $remote_user [$time_local] "
               "\"$request\" $status $body_bytes_sent "
               "\"$http_referer\" \"$http_user_agent\"");


/**
 * 本模块提供的变量,（并没有注册到全局变量，只是在打印日志时，可以快速获取值） 
 */
static ngx_http_log_var_t  ngx_http_log_vars[] = {
    { ngx_string("pipe"), 1, ngx_http_log_pipe },
    { ngx_string("time_local"), sizeof("28/Sep/1970:12:00:00 +0600") - 1,
                          ngx_http_log_time },
    { ngx_string("time_iso8601"), sizeof("1970-09-28T12:00:00+06:00") - 1,
                          ngx_http_log_iso8601 },
    { ngx_string("msec"), NGX_TIME_T_LEN + 4, ngx_http_log_msec },
    { ngx_string("request_time"), NGX_TIME_T_LEN + 4,
                          ngx_http_log_request_time },
    { ngx_string("status"), NGX_INT_T_LEN, ngx_http_log_status },
    { ngx_string("bytes_sent"), NGX_OFF_T_LEN, ngx_http_log_bytes_sent },
    { ngx_string("body_bytes_sent"), NGX_OFF_T_LEN,
                          ngx_http_log_body_bytes_sent },
    { ngx_string("request_length"), NGX_SIZE_T_LEN,
                          ngx_http_log_request_length },

    { ngx_null_string, 0, NULL }
};


/**
 * LOG_PHASE handler
 */
static ngx_int_t
ngx_http_log_handler(ngx_http_request_t *r)
{
    u_char                   *line, *p;
    size_t                    len, size;
    ssize_t                   n;
    ngx_str_t                 val;
    ngx_uint_t                i, l;
    ngx_http_log_t           *log;
    ngx_http_log_op_t        *op;
    ngx_http_log_buf_t       *buffer;
    ngx_http_log_loc_conf_t  *lcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http log handler");

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_log_module);

    //关闭日志输出
    if (lcf->off) {
        return NGX_OK;
    }

    log = lcf->logs->elts;
    //遍历每个日志输出配置
    for (l = 0; l < lcf->logs->nelts; l++) {

        if (log[l].filter) {        //执行if condition
            if (ngx_http_complex_value(r, log[l].filter, &val) != NGX_OK) {
                return NGX_ERROR;
            }

            //如果值为0，则不输出
            if (val.len == 0 || (val.len == 1 && val.data[0] == '0')) {
                continue;
            }
        }

        //如果日志所在磁盘已满
        if (ngx_time() == log[l].disk_full_time) {

            /*
             * on FreeBSD writing to a full filesystem with enabled softupdates
             * may block process for much longer time than writing to non-full
             * filesystem, so we skip writing to a log for one second
             */

            continue;
        }

        //强制重新解析no_cacheable的变量
        ngx_http_script_flush_no_cacheable_variables(r, log[l].format->flushes);

        len = 0;    //计算日志中每个变量值长度
        op = log[l].format->ops->elts;
        for (i = 0; i < log[l].format->ops->nelts; i++) {
            if (op[i].len == 0) {
                len += op[i].getlen(r, op[i].data);

            } else {
                len += op[i].len;
            }
        }

        //如果是输出到syslog
        if (log[l].syslog_peer) {

            /* length of syslog's PRI and HEADER message parts */
            len += sizeof("<255>Jan 01 00:00:00 ") - 1
                   + ngx_cycle->hostname.len + 1
                   + log[l].syslog_peer->tag.len + 2;

            goto alloc_line;
        }

        len += NGX_LINEFEED_SIZE;

        buffer = log[l].file ? log[l].file->data : NULL;

        //日志输出缓冲区
        if (buffer) {

            //如果缓冲区中剩余空间不足，则将缓冲区中数据flush到文件
            if (len > (size_t) (buffer->last - buffer->pos)) {

                ngx_http_log_write(r, &log[l], buffer->start,
                                   buffer->pos - buffer->start);

                //清空缓冲区
                buffer->pos = buffer->start;
            }

            //日志能存入buffer
            if (len <= (size_t) (buffer->last - buffer->pos)) {

                p = buffer->pos;

                //如果当前缓冲区是空的 且配置了 定时flush
                if (buffer->event && p == buffer->start) {
                    ngx_add_timer(buffer->event, buffer->flush);    //添加一个定时器
                }

                //将日志内存赋值到缓冲区
                for (i = 0; i < log[l].format->ops->nelts; i++) {
                    p = op[i].run(r, p, &op[i]);
                }

                //增加换行符
                ngx_linefeed(p);

                //更新缓冲区位置指针
                buffer->pos = p;

                continue;
            }

            //移除定时器
            if (buffer->event && buffer->event->timer_set) {
                ngx_del_timer(buffer->event);
            }
        }

        //不经buffer,将日志直接写入文件
    alloc_line:

        //申请内存
        line = ngx_pnalloc(r->pool, len);
        if (line == NULL) {
            return NGX_ERROR;
        }

        p = line;

        //添加syslog日志头
        if (log[l].syslog_peer) {
            p = ngx_syslog_add_header(log[l].syslog_peer, line);
        }

        //构建日志
        for (i = 0; i < log[l].format->ops->nelts; i++) {
            p = op[i].run(r, p, &op[i]);
        }

        //发送至syslog
        if (log[l].syslog_peer) {

            size = p - line;

            n = ngx_syslog_send(log[l].syslog_peer, line, size);

            if (n < 0) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "send() to syslog failed");

            } else if ((size_t) n != size) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "send() to syslog has written only %z of %uz",
                              n, size);
            }

            continue;
        }

        ngx_linefeed(p);

        //发送至文件
        ngx_http_log_write(r, &log[l], line, p - line);
    }

    return NGX_OK;
}


/**
 * 
 * 将buf指向的长度为len的数据输出到文件
 * 
 */
static void
ngx_http_log_write(ngx_http_request_t *r, ngx_http_log_t *log, u_char *buf,
    size_t len)
{
    u_char              *name;
    time_t               now;
    ssize_t              n;
    ngx_err_t            err;
#if (NGX_ZLIB)
    ngx_http_log_buf_t  *buffer;
#endif

    if (log->script == NULL) {  //日志路径中不包含参数的场景
        name = log->file->name.data;

#if (NGX_ZLIB)
        buffer = log->file->data;

        if (buffer && buffer->gzip) {
            n = ngx_http_log_gzip(log->file->fd, buf, len, buffer->gzip,
                                  r->connection->log);
        } else {
            n = ngx_write_fd(log->file->fd, buf, len);
        }
#else
        n = ngx_write_fd(log->file->fd, buf, len);
#endif

    } else {        //日志路径中包含参数的场景
        name = NULL;
        n = ngx_http_log_script_write(r, log->script, &name, buf, len);
    }

    //完全写入
    if (n == (ssize_t) len) {
        return;
    }

    now = ngx_time();

    if (n == -1) {
        //写入失败
        err = ngx_errno;

        if (err == NGX_ENOSPC) {
            log->disk_full_time = now;
        }

        if (now - log->error_log_time > 59) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, err,
                          ngx_write_fd_n " to \"%s\" failed", name);

            log->error_log_time = now;
        }

        return;
    }

    //未完全写入，记录错误日志
    if (now - log->error_log_time > 59) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      ngx_write_fd_n " to \"%s\" was incomplete: %z of %uz",
                      name, n, len);

        log->error_log_time = now;  //更新打错误日志的时间，避免频繁记录错误日志
    }
}


/**
 * 将buf指向的长度为len的数据输出到文件, 专用于日志路径中包含参数的场景
 */
static ssize_t
ngx_http_log_script_write(ngx_http_request_t *r, ngx_http_log_script_t *script,
    u_char **name, u_char *buf, size_t len)
{
    size_t                     root;
    ssize_t                    n;
    ngx_str_t                  log, path;
    ngx_open_file_info_t       of;
    ngx_http_log_loc_conf_t   *llcf;
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (!r->root_tested) {

        /* test root directory existence */

        if (ngx_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
            /* simulate successful logging */
            return len;
        }

        path.data[root] = '\0';

        ngx_memzero(&of, sizeof(ngx_open_file_info_t));

        of.valid = clcf->open_file_cache_valid;
        of.min_uses = clcf->open_file_cache_min_uses;
        of.test_dir = 1;
        of.test_only = 1;
        of.errors = clcf->open_file_cache_errors;
        of.events = clcf->open_file_cache_events;

        if (ngx_http_set_disable_symlinks(r, clcf, &path, &of) != NGX_OK) {
            /* simulate successful logging */
            return len;
        }

        if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
            != NGX_OK)
        {
            if (of.err == 0) {
                /* simulate successful logging */
                return len;
            }

            ngx_log_error(NGX_LOG_ERR, r->connection->log, of.err,
                          "testing \"%s\" existence failed", path.data);

            /* simulate successful logging */
            return len;
        }

        if (!of.is_dir) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, NGX_ENOTDIR,
                          "testing \"%s\" existence failed", path.data);

            /* simulate successful logging */
            return len;
        }
    }

    if (ngx_http_script_run(r, &log, script->lengths->elts, 1,
                            script->values->elts)
        == NULL)
    {
        /* simulate successful logging */
        return len;
    }

    log.data[log.len - 1] = '\0';
    *name = log.data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http log \"%s\"", log.data);

    llcf = ngx_http_get_module_loc_conf(r, ngx_http_log_module);

    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

    of.log = 1;
    of.valid = llcf->open_file_cache_valid;
    of.min_uses = llcf->open_file_cache_min_uses;
    of.directio = NGX_OPEN_FILE_DIRECTIO_OFF;

    if (ngx_http_set_disable_symlinks(r, clcf, &log, &of) != NGX_OK) {
        /* simulate successful logging */
        return len;
    }

    if (ngx_open_cached_file(llcf->open_file_cache, &log, &of, r->pool)
        != NGX_OK)
    {
        if (of.err == 0) {
            /* simulate successful logging */
            return len;
        }

        ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                      "%s \"%s\" failed", of.failed, log.data);
        /* simulate successful logging */
        return len;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http log #%d", of.fd);

    n = ngx_write_fd(of.fd, buf, len);

    return n;
}


#if (NGX_ZLIB)

/**
 * 缓存中数据压缩后写入文件
 */
static ssize_t
ngx_http_log_gzip(ngx_fd_t fd, u_char *buf, size_t len, ngx_int_t level,
    ngx_log_t *log)
{
    int          rc, wbits, memlevel;
    u_char      *out;
    size_t       size;
    ssize_t      n;
    z_stream     zstream;
    ngx_err_t    err;
    ngx_pool_t  *pool;

    wbits = MAX_WBITS;
    memlevel = MAX_MEM_LEVEL - 1;

    while ((ssize_t) len < ((1 << (wbits - 1)) - 262)) {
        wbits--;
        memlevel--;
    }

    /*
     * This is a formula from deflateBound() for conservative upper bound of
     * compressed data plus 18 bytes of gzip wrapper.
     */

    size = len + ((len + 7) >> 3) + ((len + 63) >> 6) + 5 + 18;

    ngx_memzero(&zstream, sizeof(z_stream));

    pool = ngx_create_pool(256, log);
    if (pool == NULL) {
        /* simulate successful logging */
        return len;
    }

    pool->log = log;

    zstream.zalloc = ngx_http_log_gzip_alloc;
    zstream.zfree = ngx_http_log_gzip_free;
    zstream.opaque = pool;

    out = ngx_pnalloc(pool, size);
    if (out == NULL) {
        goto done;
    }

    zstream.next_in = buf;
    zstream.avail_in = len;
    zstream.next_out = out;
    zstream.avail_out = size;

    rc = deflateInit2(&zstream, (int) level, Z_DEFLATED, wbits + 16, memlevel,
                      Z_DEFAULT_STRATEGY);

    if (rc != Z_OK) {
        ngx_log_error(NGX_LOG_ALERT, log, 0, "deflateInit2() failed: %d", rc);
        goto done;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, log, 0,
                   "deflate in: ni:%p no:%p ai:%ud ao:%ud",
                   zstream.next_in, zstream.next_out,
                   zstream.avail_in, zstream.avail_out);

    rc = deflate(&zstream, Z_FINISH);

    if (rc != Z_STREAM_END) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                      "deflate(Z_FINISH) failed: %d", rc);
        goto done;
    }

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, log, 0,
                   "deflate out: ni:%p no:%p ai:%ud ao:%ud rc:%d",
                   zstream.next_in, zstream.next_out,
                   zstream.avail_in, zstream.avail_out,
                   rc);

    size -= zstream.avail_out;

    rc = deflateEnd(&zstream);

    if (rc != Z_OK) {
        ngx_log_error(NGX_LOG_ALERT, log, 0, "deflateEnd() failed: %d", rc);
        goto done;
    }

    n = ngx_write_fd(fd, out, size);

    if (n != (ssize_t) size) {
        err = (n == -1) ? ngx_errno : 0;

        ngx_destroy_pool(pool);

        ngx_set_errno(err);
        return -1;
    }

done:

    ngx_destroy_pool(pool);

    /* simulate successful logging */
    return len;
}


static void *
ngx_http_log_gzip_alloc(void *opaque, u_int items, u_int size)
{
    ngx_pool_t *pool = opaque;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pool->log, 0,
                   "gzip alloc: n:%ud s:%ud", items, size);

    return ngx_palloc(pool, items * size);
}


static void
ngx_http_log_gzip_free(void *opaque, void *address)
{
#if 0
    ngx_pool_t *pool = opaque;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pool->log, 0, "gzip free: %p", address);
#endif
}

#endif


/**
 * 将file->data代表的日志输出缓冲区中的日志flush输出
 * 
 */
static void
ngx_http_log_flush(ngx_open_file_t *file, ngx_log_t *log)
{
    size_t               len;
    ssize_t              n;
    ngx_http_log_buf_t  *buffer;

    buffer = file->data;

    //有效数据长度
    len = buffer->pos - buffer->start;

    if (len == 0) {
        return;
    }

#if (NGX_ZLIB)
    if (buffer->gzip) {
        //压缩输出
        n = ngx_http_log_gzip(file->fd, buffer->start, len, buffer->gzip, log);
    } else {
        //直接输出
        n = ngx_write_fd(file->fd, buffer->start, len);
    }
#else
    n = ngx_write_fd(file->fd, buffer->start, len);
#endif

    if (n == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      ngx_write_fd_n " to \"%s\" failed",
                      file->name.data);

    } else if ((size_t) n != len) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                      ngx_write_fd_n " to \"%s\" was incomplete: %z of %uz",
                      file->name.data, n, len);
    }

    //重置buffer
    buffer->pos = buffer->start;

    //如果有定时器事件，将定时器事件移除
    if (buffer->event && buffer->event->timer_set) {
        ngx_del_timer(buffer->event);
    }
}


/**
 * 定时flush事件触发handler 
 * buffer->event->handler = ngx_http_log_flush_handler;
 */
static void
ngx_http_log_flush_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "http log buffer flush handler");

    ngx_http_log_flush(ev->data, ev->log);
}


/**
 * 拷贝小于一个指针长度的数据
 * op->data作为数据
 * 将op->data指针本身作为数据输出
 */
static u_char *
ngx_http_log_copy_short(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    size_t     len;
    uintptr_t  data;

    len = op->len;
    data = op->data;

    while (len--) {
        *buf++ = (u_char) (data & 0xff);
        data >>= 8;
    }

    return buf;
}


/**
 * op->data作为指针
 * 拷贝op->data指向的内存空间
 */
static u_char *
ngx_http_log_copy_long(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    return ngx_cpymem(buf, (u_char *) op->data, op->len);
}


/**
 * $pipe get_handler
 */
static u_char *
ngx_http_log_pipe(ngx_http_request_t *r, u_char *buf, ngx_http_log_op_t *op)
{
    if (r->pipeline) {
        *buf = 'p';
    } else {
        *buf = '.';
    }

    return buf + 1;
}


/**
 * $time_local get_handler
 */
static u_char *
ngx_http_log_time(ngx_http_request_t *r, u_char *buf, ngx_http_log_op_t *op)
{
    return ngx_cpymem(buf, ngx_cached_http_log_time.data,
                      ngx_cached_http_log_time.len);
}

/**
 * $time_iso8601 get_handler
 */
static u_char *
ngx_http_log_iso8601(ngx_http_request_t *r, u_char *buf, ngx_http_log_op_t *op)
{
    return ngx_cpymem(buf, ngx_cached_http_log_iso8601.data,
                      ngx_cached_http_log_iso8601.len);
}

/**
 * $msec get_handler
 */
static u_char *
ngx_http_log_msec(ngx_http_request_t *r, u_char *buf, ngx_http_log_op_t *op)
{
    ngx_time_t  *tp;

    tp = ngx_timeofday();

    return ngx_sprintf(buf, "%T.%03M", tp->sec, tp->msec);
}


/**
 * $request_time get_handler
 */
static u_char *
ngx_http_log_request_time(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    ngx_time_t      *tp;
    ngx_msec_int_t   ms;

    tp = ngx_timeofday();

    ms = (ngx_msec_int_t)
             ((tp->sec - r->start_sec) * 1000 + (tp->msec - r->start_msec));
    ms = ngx_max(ms, 0);

    return ngx_sprintf(buf, "%T.%03M", (time_t) ms / 1000, ms % 1000);
}


/**
 * $status get_handler
 */
static u_char *
ngx_http_log_status(ngx_http_request_t *r, u_char *buf, ngx_http_log_op_t *op)
{
    ngx_uint_t  status;

    if (r->err_status) {
        status = r->err_status;

    } else if (r->headers_out.status) {
        status = r->headers_out.status;

    } else if (r->http_version == NGX_HTTP_VERSION_9) {
        status = 9;

    } else {
        status = 0;
    }

    return ngx_sprintf(buf, "%03ui", status);
}


/**
 * $bytes_sent get_handler
 */
static u_char *
ngx_http_log_bytes_sent(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    return ngx_sprintf(buf, "%O", r->connection->sent);
}


/*
 * although there is a real $body_bytes_sent variable,
 * this log operation code function is more optimized for logging
 */

 /**
  * $body_bytes_sent get_handler
  */
static u_char *
ngx_http_log_body_bytes_sent(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    off_t  length;

    length = r->connection->sent - r->header_size;

    if (length > 0) {
        return ngx_sprintf(buf, "%O", length);
    }

    *buf = '0';

    return buf + 1;
}


/**
 * $request_length get_handler
 */
static u_char *
ngx_http_log_request_length(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    return ngx_sprintf(buf, "%O", r->request_length);
}


/**
 * 编译log_format配置指令中的变量
 */
static ngx_int_t
ngx_http_log_variable_compile(ngx_conf_t *cf, ngx_http_log_op_t *op,
    ngx_str_t *value, ngx_uint_t escape)
{
    ngx_int_t  index;

    //获取变量的index。如果变量没被索引，会创建新的加入到索引变量动态数组中。
    index = ngx_http_get_variable_index(cf, value);
    if (index == NGX_ERROR) {
        return NGX_ERROR;
    }

    op->len = 0;

    /**
     * 不同的escape, 有不同的获取变量值长度和变量值的方法
     */
    switch (escape) {
    case NGX_HTTP_LOG_ESCAPE_JSON:
        op->getlen = ngx_http_log_json_variable_getlen;
        op->run = ngx_http_log_json_variable;
        break;

    case NGX_HTTP_LOG_ESCAPE_NONE:
        op->getlen = ngx_http_log_unescaped_variable_getlen;
        op->run = ngx_http_log_unescaped_variable;
        break;

    default: /* NGX_HTTP_LOG_ESCAPE_DEFAULT */
        op->getlen = ngx_http_log_variable_getlen;
        op->run = ngx_http_log_variable;
    }

    op->data = index;

    return NGX_OK;
}


/**
 * 获取索引变量值的长度
 */
static size_t
ngx_http_log_variable_getlen(ngx_http_request_t *r, uintptr_t data)
{
    uintptr_t                   len;
    ngx_http_variable_value_t  *value;

    value = ngx_http_get_indexed_variable(r, data);

    if (value == NULL || value->not_found) {
        return 1;
    }

    len = ngx_http_log_escape(NULL, value->data, value->len);

    value->escape = len ? 1 : 0;

    return value->len + len * 3;
}


/**
 * 获取索引变量值
 */
static u_char *
ngx_http_log_variable(ngx_http_request_t *r, u_char *buf, ngx_http_log_op_t *op)
{
    ngx_http_variable_value_t  *value;

    value = ngx_http_get_indexed_variable(r, op->data);

    if (value == NULL || value->not_found) {
        *buf = '-';
        return buf + 1;
    }

    if (value->escape == 0) {
        return ngx_cpymem(buf, value->data, value->len);

    } else {
        return (u_char *) ngx_http_log_escape(buf, value->data, value->len);
    }
}


static uintptr_t
ngx_http_log_escape(u_char *dst, u_char *src, size_t size)
{
    ngx_uint_t      n;
    static u_char   hex[] = "0123456789ABCDEF";

    static uint32_t   escape[] = {
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                    /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
        0x00000004, /* 0000 0000 0000 0000  0000 0000 0000 0100 */

                    /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
        0x10000000, /* 0001 0000 0000 0000  0000 0000 0000 0000 */

                    /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
        0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    };


    if (dst == NULL) {

        /* find the number of the characters to be escaped */

        n = 0;

        while (size) {
            if (escape[*src >> 5] & (1U << (*src & 0x1f))) {
                n++;
            }
            src++;
            size--;
        }

        return (uintptr_t) n;
    }

    while (size) {
        if (escape[*src >> 5] & (1U << (*src & 0x1f))) {
            *dst++ = '\\';
            *dst++ = 'x';
            *dst++ = hex[*src >> 4];
            *dst++ = hex[*src & 0xf];
            src++;

        } else {
            *dst++ = *src++;
        }
        size--;
    }

    return (uintptr_t) dst;
}


/**
 * json格式的日志获取变量值长度函数
 */
static size_t
ngx_http_log_json_variable_getlen(ngx_http_request_t *r, uintptr_t data)
{
    uintptr_t                   len;
    ngx_http_variable_value_t  *value;

    value = ngx_http_get_indexed_variable(r, data);

    if (value == NULL || value->not_found) {
        return 0;
    }

    len = ngx_escape_json(NULL, value->data, value->len);

    value->escape = len ? 1 : 0;

    return value->len + len;
}


/**
 * json格式的日志获取变量值
 */
static u_char *
ngx_http_log_json_variable(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    ngx_http_variable_value_t  *value;

    value = ngx_http_get_indexed_variable(r, op->data);

    if (value == NULL || value->not_found) {
        return buf;
    }

    if (value->escape == 0) {
        return ngx_cpymem(buf, value->data, value->len);

    } else {
        return (u_char *) ngx_escape_json(buf, value->data, value->len);
    }
}


/**
 * 原始格式的日志获取变量值长度
 */
static size_t
ngx_http_log_unescaped_variable_getlen(ngx_http_request_t *r, uintptr_t data)
{
    ngx_http_variable_value_t  *value;

    value = ngx_http_get_indexed_variable(r, data);

    if (value == NULL || value->not_found) {
        return 0;
    }

    value->escape = 0;

    return value->len;
}


/**
 * 原始格式的日志获取变量值
 */
static u_char *
ngx_http_log_unescaped_variable(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    ngx_http_variable_value_t  *value;

    value = ngx_http_get_indexed_variable(r, op->data);

    if (value == NULL || value->not_found) {
        return buf;
    }

    return ngx_cpymem(buf, value->data, value->len);
}


/**
 * 创建main级别配置结构体
 */
static void *
ngx_http_log_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_log_main_conf_t  *conf;

    ngx_http_log_fmt_t  *fmt;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_log_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&conf->formats, cf->pool, 4, sizeof(ngx_http_log_fmt_t))
        != NGX_OK)
    {
        return NULL;
    }

    fmt = ngx_array_push(&conf->formats);
    if (fmt == NULL) {
        return NULL;
    }

    ngx_str_set(&fmt->name, "combined");

    fmt->flushes = NULL;

    fmt->ops = ngx_array_create(cf->pool, 16, sizeof(ngx_http_log_op_t));
    if (fmt->ops == NULL) {
        return NULL;
    }

    return conf;
}


/**
 * 创建loc级别配置结构体
 */
static void *
ngx_http_log_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_log_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_log_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->open_file_cache = NGX_CONF_UNSET_PTR;

    return conf;
}


/**
 * 合并loc级别配置结构体
 */
static char *
ngx_http_log_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_log_loc_conf_t *prev = parent;
    ngx_http_log_loc_conf_t *conf = child;

    ngx_http_log_t            *log;
    ngx_http_log_fmt_t        *fmt;
    ngx_http_log_main_conf_t  *lmcf;

    if (conf->open_file_cache == NGX_CONF_UNSET_PTR) {

        conf->open_file_cache = prev->open_file_cache;
        conf->open_file_cache_valid = prev->open_file_cache_valid;
        conf->open_file_cache_min_uses = prev->open_file_cache_min_uses;

        if (conf->open_file_cache == NGX_CONF_UNSET_PTR) {
            conf->open_file_cache = NULL;
        }
    }

    if (conf->logs || conf->off) {
        return NGX_CONF_OK;
    }

    conf->logs = prev->logs;
    conf->off = prev->off;

    if (conf->logs || conf->off) {
        return NGX_CONF_OK;
    }

    conf->logs = ngx_array_create(cf->pool, 2, sizeof(ngx_http_log_t));
    if (conf->logs == NULL) {
        return NGX_CONF_ERROR;
    }

    log = ngx_array_push(conf->logs);
    if (log == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(log, sizeof(ngx_http_log_t));

    log->file = ngx_conf_open_file(cf->cycle, &ngx_http_access_log);
    if (log->file == NULL) {
        return NGX_CONF_ERROR;
    }

    lmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_log_module);
    fmt = lmcf->formats.elts;

    /* the default "combined" format */
    log->format = &fmt[0];
    lmcf->combined_used = 1;

    return NGX_CONF_OK;
}


/**
 * 解析配置指令access_log
 * 
 * 	access_log path [format [buffer=size] [gzip[=level]] [flush=time] [if=condition]];
    access_log off;
 * Default:	access_log logs/access.log combined;
 */
static char *
ngx_http_log_set_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_log_loc_conf_t *llcf = conf;

    ssize_t                            size;
    ngx_int_t                          gzip;
    ngx_uint_t                         i, n;
    ngx_msec_t                         flush;
    ngx_str_t                         *value, name, s;
    ngx_http_log_t                    *log;
    ngx_syslog_peer_t                 *peer;
    ngx_http_log_buf_t                *buffer;
    ngx_http_log_fmt_t                *fmt;
    ngx_http_log_main_conf_t          *lmcf;
    ngx_http_script_compile_t          sc;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    //access_log off; 关闭当前级别日志打印
    if (ngx_strcmp(value[1].data, "off") == 0) {
        llcf->off = 1;
        if (cf->args->nelts == 2) {
            return NGX_CONF_OK;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    //一个loc下可以有多个 access_log 配置
    if (llcf->logs == NULL) {
        llcf->logs = ngx_array_create(cf->pool, 2, sizeof(ngx_http_log_t));
        if (llcf->logs == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    //本模块main级别配置
    lmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_log_module);

    //ngx_http_log_t
    log = ngx_array_push(llcf->logs);
    if (log == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(log, sizeof(ngx_http_log_t));


    //syslog:前缀， Logging to syslog
    if (ngx_strncmp(value[1].data, "syslog:", 7) == 0) {

        peer = ngx_pcalloc(cf->pool, sizeof(ngx_syslog_peer_t));
        if (peer == NULL) {
            return NGX_CONF_ERROR;
        }

        if (ngx_syslog_process_conf(cf, peer) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }

        log->syslog_peer = peer;

        goto process_formats;
    }

    //value[1] 为日志文件path
    n = ngx_http_script_variables_count(&value[1]);

    if (n == 0) {   //不包含变量
        log->file = ngx_conf_open_file(cf->cycle, &value[1]);
        if (log->file == NULL) {
            return NGX_CONF_ERROR;
        }

    } else {
        //获取全路径(如相对路径改为绝对路径，不包含变量解析)
        if (ngx_conf_full_name(cf->cycle, &value[1], 0) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        log->script = ngx_pcalloc(cf->pool, sizeof(ngx_http_log_script_t));
        if (log->script == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = &value[1];
        sc.lengths = &log->script->lengths;
        sc.values = &log->script->values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        //编译变量
        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

process_formats:

    //name为日志格式名称
    if (cf->args->nelts >= 3) {
        name = value[2];

        if (ngx_strcmp(name.data, "combined") == 0) {
            lmcf->combined_used = 1;
        }

    //只配置了日志路径，格式使用默认的combined
    } else {
        ngx_str_set(&name, "combined");
        lmcf->combined_used = 1;
    }

    //从formats中找到相同名称的log_format
    fmt = lmcf->formats.elts;
    for (i = 0; i < lmcf->formats.nelts; i++) {
        if (fmt[i].name.len == name.len
            && ngx_strcasecmp(fmt[i].name.data, name.data) == 0)
        {
            log->format = &fmt[i];
            break;
        }
    }

    //log_format未定义:未找到指定名称的log->format
    if (log->format == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "unknown log format \"%V\"", &name);
        return NGX_CONF_ERROR;
    }

    size = 0;       //buffer=size
    flush = 0;      //flush=time
    gzip = 0;       //gzip[=level]

    for (i = 3; i < cf->args->nelts; i++) {

        //[buffer=size]
        if (ngx_strncmp(value[i].data, "buffer=", 7) == 0) {
            s.len = value[i].len - 7;
            s.data = value[i].data + 7;

            size = ngx_parse_size(&s);

            if (size == NGX_ERROR || size == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid buffer size \"%V\"", &s);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        //[flush=time]
        if (ngx_strncmp(value[i].data, "flush=", 6) == 0) {
            s.len = value[i].len - 6;
            s.data = value[i].data + 6;

            flush = ngx_parse_time(&s, 0);

            if (flush == (ngx_msec_t) NGX_ERROR || flush == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid flush time \"%V\"", &s);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        //[gzip[=level]]
        if (ngx_strncmp(value[i].data, "gzip", 4) == 0
            && (value[i].len == 4 || value[i].data[4] == '='))
        {
#if (NGX_ZLIB)
            if (size == 0) {
                size = 64 * 1024;
            }

            if (value[i].len == 4) {
                gzip = Z_BEST_SPEED;
                continue;
            }

            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            gzip = ngx_atoi(s.data, s.len);

            if (gzip < 1 || gzip > 9) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid compression level \"%V\"", &s);
                return NGX_CONF_ERROR;
            }

            continue;

#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "nginx was built without zlib support");
            return NGX_CONF_ERROR;
#endif
        }

        //[if=condition]]
        if (ngx_strncmp(value[i].data, "if=", 3) == 0) {
            s.len = value[i].len - 3;
            s.data = value[i].data + 3;

            ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &s;
            ccv.complex_value = ngx_palloc(cf->pool,
                                           sizeof(ngx_http_complex_value_t));
            if (ccv.complex_value == NULL) {
                return NGX_CONF_ERROR;
            }

            //编译condition
            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            log->filter = ccv.complex_value;

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (flush && size == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "no buffer is defined for access_log \"%V\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    if (size) {     //buffer_size

        if (log->script) {      //包含变量的文件名
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "buffered logs cannot have variables in name");
            return NGX_CONF_ERROR;
        }

        if (log->syslog_peer) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "logs to syslog cannot be buffered");
            return NGX_CONF_ERROR;
        }

        //在log_format配置指令中已经配置过buf了
        if (log->file->data) {
            buffer = log->file->data;

            if (buffer->last - buffer->start != size
                || buffer->flush != flush
                || buffer->gzip != gzip)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "access_log \"%V\" already defined "
                                   "with conflicting parameters",
                                   &value[1]);
                return NGX_CONF_ERROR;
            }

            return NGX_CONF_OK;
        }

        //创建代表buffer的结构体ngx_http_log_buf_t
        buffer = ngx_pcalloc(cf->pool, sizeof(ngx_http_log_buf_t));
        if (buffer == NULL) {
            return NGX_CONF_ERROR;
        }

        //申请缓冲区空间
        buffer->start = ngx_pnalloc(cf->pool, size);
        if (buffer->start == NULL) {
            return NGX_CONF_ERROR;
        }

        buffer->pos = buffer->start;
        buffer->last = buffer->start + size;

        if (flush) {        //定时flush
            buffer->event = ngx_pcalloc(cf->pool, sizeof(ngx_event_t));
            if (buffer->event == NULL) {
                return NGX_CONF_ERROR;
            }

            buffer->event->data = log->file;
            buffer->event->handler = ngx_http_log_flush_handler;    //event_handler
            buffer->event->log = &cf->cycle->new_log;
            buffer->event->cancelable = 1;

            buffer->flush = flush;
        }

        buffer->gzip = gzip;

        log->file->flush = ngx_http_log_flush;
        log->file->data = buffer;       //file->data指向日志输出buffer
    }

    return NGX_CONF_OK;
}


/**
 * log_format 配置指令解析函数
 * 
 * 例如:
 * log_format compression '$remote_addr - $remote_user [$time_local] '
                       '"$request" $status $bytes_sent '
                       '"$http_referer" "$http_user_agent" "$gzip_ratio"'
 * 
 */
static char *
ngx_http_log_set_format(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_log_main_conf_t *lmcf = conf;

    ngx_str_t           *value;
    ngx_uint_t           i;
    ngx_http_log_fmt_t  *fmt;

    //配置的多种日志格式
    value = cf->args->elts;

    //检查是否已经有相同名称的日志格式了
    fmt = lmcf->formats.elts;
    for (i = 0; i < lmcf->formats.nelts; i++) {
        if (fmt[i].name.len == value[1].len
            && ngx_strcmp(fmt[i].name.data, value[1].data) == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate \"log_format\" name \"%V\"",
                               &value[1]);
            return NGX_CONF_ERROR;
        }
    }

    //新增一个元素
    fmt = ngx_array_push(&lmcf->formats);
    if (fmt == NULL) {
        return NGX_CONF_ERROR;
    }

    //格式名称为value[1]
    fmt->name = value[1];

    fmt->flushes = ngx_array_create(cf->pool, 4, sizeof(ngx_int_t));
    if (fmt->flushes == NULL) {
        return NGX_CONF_ERROR;
    }

    fmt->ops = ngx_array_create(cf->pool, 16, sizeof(ngx_http_log_op_t));
    if (fmt->ops == NULL) {
        return NGX_CONF_ERROR;
    }

    return ngx_http_log_compile_format(cf, fmt->flushes, fmt->ops, cf->args, 2);
}


/**
 * 解析配置指令 log_format name [escape=default|json|none] string ...;
 */
static char *
ngx_http_log_compile_format(ngx_conf_t *cf, ngx_array_t *flushes,
    ngx_array_t *ops, ngx_array_t *args, ngx_uint_t s)
{
    u_char              *data, *p, ch;
    size_t               i, len;
    ngx_str_t           *value, var;
    ngx_int_t           *flush;
    ngx_uint_t           bracket, escape;
    ngx_http_log_op_t   *op;
    ngx_http_log_var_t  *v;

    escape = NGX_HTTP_LOG_ESCAPE_DEFAULT;
    value = args->elts;

    //解析 [escape=default|json|none] 
    if (s < args->nelts && ngx_strncmp(value[s].data, "escape=", 7) == 0) {
        data = value[s].data + 7;

        if (ngx_strcmp(data, "json") == 0) {
            escape = NGX_HTTP_LOG_ESCAPE_JSON;

        } else if (ngx_strcmp(data, "none") == 0) {
            escape = NGX_HTTP_LOG_ESCAPE_NONE;

        } else if (ngx_strcmp(data, "default") != 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "unknown log format escaping \"%s\"", data);
            return NGX_CONF_ERROR;
        }

        s++;
    }

    //日志格式解析 ${xxx} 和$xxx等同
    for ( /* void */ ; s < args->nelts; s++) {

        i = 0;

        //遍历每个字符。 value[s] 为多个变量的混合  '$remote_addr - $remote_user [$time_local] "$request" '
        while (i < value[s].len) {

            op = ngx_array_push(ops);
            if (op == NULL) {
                return NGX_CONF_ERROR;
            }

            data = &value[s].data[i];

            //如果是变量
            if (value[s].data[i] == '$') {

                if (++i == value[s].len) {
                    goto invalid;
                }

                if (value[s].data[i] == '{') {
                    bracket = 1;

                    if (++i == value[s].len) {
                        goto invalid;
                    }

                    var.data = &value[s].data[i];

                } else {
                    bracket = 0;
                    var.data = &value[s].data[i];
                }

                for (var.len = 0; i < value[s].len; i++, var.len++) {
                    ch = value[s].data[i];

                    if (ch == '}' && bracket) {
                        i++;
                        bracket = 0;
                        break;
                    }

                    if ((ch >= 'A' && ch <= 'Z')
                        || (ch >= 'a' && ch <= 'z')
                        || (ch >= '0' && ch <= '9')
                        || ch == '_')
                    {
                        continue;
                    }

                    //找到了一个变量的结束位置
                    break;
                }

                if (bracket) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "the closing bracket in \"%V\" "
                                       "variable is missing", &var);
                    return NGX_CONF_ERROR;
                }

                if (var.len == 0) {
                    goto invalid;
                }

                //与预置的几个变量比较
                for (v = ngx_http_log_vars; v->name.len; v++) {

                    if (v->name.len == var.len
                        && ngx_strncmp(v->name.data, var.data, var.len) == 0)
                    {
                        op->len = v->len;
                        op->getlen = NULL;
                        op->run = v->run;
                        op->data = 0;

                        goto found;
                    }
                }

                //非预置变量
                if (ngx_http_log_variable_compile(cf, op, &var, escape)
                    != NGX_OK)
                {
                    return NGX_CONF_ERROR;
                }

                if (flushes) {

                    flush = ngx_array_push(flushes);
                    if (flush == NULL) {
                        return NGX_CONF_ERROR;
                    }

                    *flush = op->data; /* variable index */
                }

            found:

                continue;
            }

            i++;

            //非变量(如变量之间的分隔符)
            while (i < value[s].len && value[s].data[i] != '$') {
                i++;
            }

            len = &value[s].data[i] - data;

            if (len) {

                op->len = len;
                op->getlen = NULL;

                if (len <= sizeof(uintptr_t)) {     //如果值的长度小于一个指针（8个字节）
                    op->run = ngx_http_log_copy_short;
                    op->data = 0;

                    while (len--) {     //op->data指针本身作为数据存储位置
                        op->data <<= 8;
                        op->data |= data[len];
                    }

                } else {    //如果值的长度大于一个指针（8个字节），申请内存空间，将当前固定字符串写入进去
                    op->run = ngx_http_log_copy_long;

                    p = ngx_pnalloc(cf->pool, len);
                    if (p == NULL) {
                        return NGX_CONF_ERROR;
                    }

                    ngx_memcpy(p, data, len);
                    op->data = (uintptr_t) p;   //p->data指向新申请的内存
                }
            }
        }
    }

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%s\"", data);

    return NGX_CONF_ERROR;
}


/**
 * 配置指令 open_log_file_cache
 * 
 * Defines a cache that stores the file descriptors of frequently used logs whose names contain variables
 * 
 * open_log_file_cache max=N [inactive=time] [min_uses=N] [valid=time];
    open_log_file_cache off;
 */
static char *
ngx_http_log_open_file_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_log_loc_conf_t *llcf = conf;

    time_t       inactive, valid;
    ngx_str_t   *value, s;
    ngx_int_t    max, min_uses;
    ngx_uint_t   i;

    if (llcf->open_file_cache != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    max = 0;
    inactive = 10;
    valid = 60;
    min_uses = 1;

    for (i = 1; i < cf->args->nelts; i++) {

        //max=N sets the maximum number of descriptors in a cache
        if (ngx_strncmp(value[i].data, "max=", 4) == 0) {

            max = ngx_atoi(value[i].data + 4, value[i].len - 4);
            if (max == NGX_ERROR) {
                goto failed;
            }

            continue;
        }

        //[inactive=time]
        if (ngx_strncmp(value[i].data, "inactive=", 9) == 0) {

            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            inactive = ngx_parse_time(&s, 1);
            if (inactive == (time_t) NGX_ERROR) {
                goto failed;
            }

            continue;
        }

        //[min_uses=N] 在inactive时间内，文件至少被使用多少次才被认为活跃而不从缓存区中移除
        if (ngx_strncmp(value[i].data, "min_uses=", 9) == 0) {

            min_uses = ngx_atoi(value[i].data + 9, value[i].len - 9);
            if (min_uses == NGX_ERROR) {
                goto failed;
            }

            continue;
        }

        //[valid=time] 设置要检查文件是否存在的事件间隔，默认60秒
        if (ngx_strncmp(value[i].data, "valid=", 6) == 0) {

            s.len = value[i].len - 6;
            s.data = value[i].data + 6;

            valid = ngx_parse_time(&s, 1);
            if (valid == (time_t) NGX_ERROR) {
                goto failed;
            }

            continue;
        }

        //off 关闭缓冲
        if (ngx_strcmp(value[i].data, "off") == 0) {

            llcf->open_file_cache = NULL;

            continue;
        }

    failed:

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid \"open_log_file_cache\" parameter \"%V\"",
                           &value[i]);
        return NGX_CONF_ERROR;
    }

    //关闭缓冲
    if (llcf->open_file_cache == NULL) {
        return NGX_CONF_OK;
    }

    if (max == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "\"open_log_file_cache\" must have \"max\" parameter");
        return NGX_CONF_ERROR;
    }

    //初始化open_file_cache
    llcf->open_file_cache = ngx_open_file_cache_init(cf->pool, max, inactive);

    if (llcf->open_file_cache) {

        llcf->open_file_cache_valid = valid;
        llcf->open_file_cache_min_uses = min_uses;

        return NGX_CONF_OK;
    }

    return NGX_CONF_ERROR;
}


/**
 * postconfiguration
 * 安装一个LOG_PHASE 的handler
 */
static ngx_int_t
ngx_http_log_init(ngx_conf_t *cf)
{
    ngx_str_t                  *value;
    ngx_array_t                 a;
    ngx_http_handler_pt        *h;
    ngx_http_log_fmt_t         *fmt;
    ngx_http_log_main_conf_t   *lmcf;
    ngx_http_core_main_conf_t  *cmcf;

    lmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_log_module);

    if (lmcf->combined_used) {
        if (ngx_array_init(&a, cf->pool, 1, sizeof(ngx_str_t)) != NGX_OK) {
            return NGX_ERROR;
        }

        value = ngx_array_push(&a);
        if (value == NULL) {
            return NGX_ERROR;
        }

        *value = ngx_http_combined_fmt;
        fmt = lmcf->formats.elts;

        if (ngx_http_log_compile_format(cf, NULL, fmt->ops, &a, 0)
            != NGX_CONF_OK)
        {
            return NGX_ERROR;
        }
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_log_handler;

    return NGX_OK;
}
