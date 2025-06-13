
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#if 0

typedef struct {
    ngx_buf_t     *buf;
    size_t         size;
    ngx_pool_t    *pool;
    size_t         alloc_size;
    ngx_chain_t  **last_out;
} ngx_http_autoindex_ctx_t;

#endif


/**
 * 仅处理请求url以/结尾的请求， 列出对应目录里的文件
 * 
 * 当ngx_http_index_module找不到一个index文件后，由该文件处理请求
 * 
 */

 /**
  * 代表目录里的一项(一个文件)
  */
typedef struct {
    ngx_str_t      name;
    size_t         utf_len;
    size_t         escape;
    size_t         escape_html;

    unsigned       dir:1;
    unsigned       file:1;

    time_t         mtime;
    off_t          size;
} ngx_http_autoindex_entry_t;


/**
 * 配置结构体
 */
typedef struct {
    ngx_flag_t     enable;      //是否开启本模块
    ngx_uint_t     format;      //输出格式 html、xml、json、jsonp
    ngx_flag_t     localtime;   //时间格式
    ngx_flag_t     exact_size;  //是否输出精确文件大小，否则转为k/m/g格式展示
} ngx_http_autoindex_loc_conf_t;


#define NGX_HTTP_AUTOINDEX_HTML         0
#define NGX_HTTP_AUTOINDEX_JSON         1
#define NGX_HTTP_AUTOINDEX_JSONP        2
#define NGX_HTTP_AUTOINDEX_XML          3

#define NGX_HTTP_AUTOINDEX_PREALLOCATE  50

#define NGX_HTTP_AUTOINDEX_NAME_LEN     50


static ngx_buf_t *ngx_http_autoindex_html(ngx_http_request_t *r,
    ngx_array_t *entries);
static ngx_buf_t *ngx_http_autoindex_json(ngx_http_request_t *r,
    ngx_array_t *entries, ngx_str_t *callback);
static ngx_int_t ngx_http_autoindex_jsonp_callback(ngx_http_request_t *r,
    ngx_str_t *callback);
static ngx_buf_t *ngx_http_autoindex_xml(ngx_http_request_t *r,
    ngx_array_t *entries);

static int ngx_libc_cdecl ngx_http_autoindex_cmp_entries(const void *one,
    const void *two);
static ngx_int_t ngx_http_autoindex_error(ngx_http_request_t *r,
    ngx_dir_t *dir, ngx_str_t *name);

static ngx_int_t ngx_http_autoindex_init(ngx_conf_t *cf);
static void *ngx_http_autoindex_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_autoindex_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);


static ngx_conf_enum_t  ngx_http_autoindex_format[] = {
    { ngx_string("html"), NGX_HTTP_AUTOINDEX_HTML },
    { ngx_string("json"), NGX_HTTP_AUTOINDEX_JSON },
    { ngx_string("jsonp"), NGX_HTTP_AUTOINDEX_JSONP },
    { ngx_string("xml"), NGX_HTTP_AUTOINDEX_XML },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_autoindex_commands[] = {

    // on | off, 是否启用这个模块
    { ngx_string("autoindex"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_autoindex_loc_conf_t, enable),
      NULL },

    //autoindex_format html | xml | json | jsonp;
    //设置输出格式
    { ngx_string("autoindex_format"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_autoindex_loc_conf_t, format),
      &ngx_http_autoindex_format },

    //输出文件格式  local time zone or UTC
    { ngx_string("autoindex_localtime"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_autoindex_loc_conf_t, localtime),
      NULL },

    { ngx_string("autoindex_exact_size"),       //是否展示精确的文件大小, 否则转为k/m/g格式展示
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_autoindex_loc_conf_t, exact_size),
      NULL },

      ngx_null_command
};


/**
 * https://nginx.org/en/docs/http/ngx_http_autoindex_module.html
 * 
 * processes requests ending with the slash character (‘/’) and produces a directory listing
 * 
 * Usually a request is passed to the ngx_http_autoindex_module module when the ngx_http_index_module module cannot find an index file
 * 
 */
static ngx_http_module_t  ngx_http_autoindex_module_ctx = {
    NULL,                                  /* preconfiguration */
    // 安装content_handler
    ngx_http_autoindex_init,               /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    //创建配置结构体
    ngx_http_autoindex_create_loc_conf,    /* create location configuration */
    //只是简单的合并配置
    ngx_http_autoindex_merge_loc_conf      /* merge location configuration */
};


ngx_module_t  ngx_http_autoindex_module = {
    NGX_MODULE_V1,
    &ngx_http_autoindex_module_ctx,        /* module context */
    ngx_http_autoindex_commands,           /* module directives */
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


/**
 * content_handler
 */
static ngx_int_t
ngx_http_autoindex_handler(ngx_http_request_t *r)
{
    u_char                         *last, *filename;
    size_t                          len, allocated, root;
    ngx_err_t                       err;
    ngx_buf_t                      *b;
    ngx_int_t                       rc;
    ngx_str_t                       path, callback;
    ngx_dir_t                       dir;
    ngx_uint_t                      level, format;
    ngx_pool_t                     *pool;
    ngx_chain_t                     out;
    ngx_array_t                     entries;
    ngx_http_autoindex_entry_t     *entry;
    ngx_http_autoindex_loc_conf_t  *alcf;

    //如果uri不以/结尾，不处理
    if (r->uri.data[r->uri.len - 1] != '/') {
        return NGX_DECLINED;
    }

    //请求方法必须是GET或HEAD
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_DECLINED;
    }

    //获取模块配置
    alcf = ngx_http_get_module_loc_conf(r, ngx_http_autoindex_module);

    //如果未启用，直接返回
    if (!alcf->enable) {
        return NGX_DECLINED;
    }

    //丢弃请求体
    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    //将uri映射为文件路径(包含了root和alias的处理)
    //last为path最后一个字符的下个位置
    last = ngx_http_map_uri_to_path(r, &path, &root,
                                    NGX_HTTP_AUTOINDEX_PREALLOCATE);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    allocated = path.len;
    path.len = last - path.data;
    if (path.len > 1) {
        path.len--;
    }
    path.data[path.len] = '\0';     //常规字符串

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http autoindex: \"%s\"", path.data);

    //输出格式
    format = alcf->format;

    if (format == NGX_HTTP_AUTOINDEX_JSONP) {
        //只是校验callback参数
        if (ngx_http_autoindex_jsonp_callback(r, &callback) != NGX_OK) {
            return NGX_HTTP_BAD_REQUEST;
        }

        if (callback.len == 0) {
            format = NGX_HTTP_AUTOINDEX_JSON;
        }
    }

    //打开文件目录
    if (ngx_open_dir(&path, &dir) == NGX_ERROR) {
        //打开失败
        err = ngx_errno;

        if (err == NGX_ENOENT
            || err == NGX_ENOTDIR
            || err == NGX_ENAMETOOLONG)
        {
            //目录未找到，返回404
            level = NGX_LOG_ERR;
            rc = NGX_HTTP_NOT_FOUND;

        } else if (err == NGX_EACCES) {
            //访问权限问题，返回403
            level = NGX_LOG_ERR;
            rc = NGX_HTTP_FORBIDDEN;

        } else {
            //内部错误，返回500
            level = NGX_LOG_CRIT;
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_log_error(level, r->connection->log, err,
                      ngx_open_dir_n " \"%s\" failed", path.data);

        //返回给客户端错误
        return rc;
    }

#if (NGX_SUPPRESS_WARN)

    /* MSVC thinks 'entries' may be used without having been initialized */
    ngx_memzero(&entries, sizeof(ngx_array_t));

#endif

    /* TODO: pool should be temporary pool */
    pool = r->pool;

    //初始化entries动态数组
    if (ngx_array_init(&entries, pool, 40, sizeof(ngx_http_autoindex_entry_t))
        != NGX_OK)
    {
        //关闭文件夹，返回500错误
        return ngx_http_autoindex_error(r, &dir, &path);
    }

    //响应200 OK
    r->headers_out.status = NGX_HTTP_OK;

    //根据不同的format， 设置响应的content_type
    switch (format) {

    case NGX_HTTP_AUTOINDEX_JSON:
        ngx_str_set(&r->headers_out.content_type, "application/json");
        break;

    case NGX_HTTP_AUTOINDEX_JSONP:
        ngx_str_set(&r->headers_out.content_type, "application/javascript");
        break;

    case NGX_HTTP_AUTOINDEX_XML:
        ngx_str_set(&r->headers_out.content_type, "text/xml");
        ngx_str_set(&r->headers_out.charset, "utf-8");
        break;

    default: /* NGX_HTTP_AUTOINDEX_HTML */
        ngx_str_set(&r->headers_out.content_type, "text/html");
        break;
    }

    r->headers_out.content_type_len = r->headers_out.content_type.len;
    r->headers_out.content_type_lowcase = NULL;

    //发送响应头
    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        if (ngx_close_dir(&dir) == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                          ngx_close_dir_n " \"%V\" failed", &path);
        }

        return rc;
    }

    filename = path.data;
    filename[path.len] = '/';

    for ( ;; ) {
        ngx_set_errno(0);

        if (ngx_read_dir(&dir) == NGX_ERROR) {
            //读取目录失败
            err = ngx_errno;

            if (err != NGX_ENOMOREFILES) {
                ngx_log_error(NGX_LOG_CRIT, r->connection->log, err,
                              ngx_read_dir_n " \"%V\" failed", &path);
                return ngx_http_autoindex_error(r, &dir, &path);
            }

            break;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http autoindex file: \"%s\"", ngx_de_name(&dir));

        //目录项文件名长度
        len = ngx_de_namelen(&dir);

        //隐藏文件
        if (ngx_de_name(&dir)[0] == '.') {
            continue;
        }

        if (!dir.valid_info) {      //opendir步骤中，将dir.valid_info置为0

            /* 1 byte for '/' and 1 byte for terminating '\0' */

            if (path.len + 1 + len + 1 > allocated) {
                allocated = path.len + 1 + len + 1
                                     + NGX_HTTP_AUTOINDEX_PREALLOCATE;

                filename = ngx_pnalloc(pool, allocated);
                if (filename == NULL) {
                    return ngx_http_autoindex_error(r, &dir, &path);
                }

                last = ngx_cpystrn(filename, path.data, path.len + 1);
                *last++ = '/';
            }

            ngx_cpystrn(last, ngx_de_name(&dir), len + 1);

            //读取文件目录项详细信息
            if (ngx_de_info(filename, &dir) == NGX_FILE_ERROR) {
                err = ngx_errno;

                if (err != NGX_ENOENT && err != NGX_ELOOP) {
                    ngx_log_error(NGX_LOG_CRIT, r->connection->log, err,
                                  ngx_de_info_n " \"%s\" failed", filename);

                    if (err == NGX_EACCES) {
                        continue;
                    }

                    return ngx_http_autoindex_error(r, &dir, &path);
                }

                if (ngx_de_link_info(filename, &dir) == NGX_FILE_ERROR) {
                    ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                                  ngx_de_link_info_n " \"%s\" failed",
                                  filename);
                    return ngx_http_autoindex_error(r, &dir, &path);
                }
            }
        }

        //entries动态数组中加入一项
        entry = ngx_array_push(&entries);
        if (entry == NULL) {
            return ngx_http_autoindex_error(r, &dir, &path);
        }

        //文件名
        entry->name.len = len;

        entry->name.data = ngx_pnalloc(pool, len + 1);
        if (entry->name.data == NULL) {
            return ngx_http_autoindex_error(r, &dir, &path);
        }

        ngx_cpystrn(entry->name.data, ngx_de_name(&dir), len + 1);

        //是否是目录
        entry->dir = ngx_de_is_dir(&dir);
        //是否是目录
        entry->file = ngx_de_is_file(&dir);
        //修改时间
        entry->mtime = ngx_de_mtime(&dir);
        //文件大小
        entry->size = ngx_de_size(&dir);
    }

    //遍历结束，关闭文件目录
    if (ngx_close_dir(&dir) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                      ngx_close_dir_n " \"%V\" failed", &path);
    }

    if (entries.nelts > 1) {
        //排序
        ngx_qsort(entries.elts, (size_t) entries.nelts,
                  sizeof(ngx_http_autoindex_entry_t),
                  ngx_http_autoindex_cmp_entries);
    }

    //根据不同格式，构建响应体b
    switch (format) {

    case NGX_HTTP_AUTOINDEX_JSON:
        b = ngx_http_autoindex_json(r, &entries, NULL);
        break;

    case NGX_HTTP_AUTOINDEX_JSONP:
        b = ngx_http_autoindex_json(r, &entries, &callback);
        break;

    case NGX_HTTP_AUTOINDEX_XML:
        b = ngx_http_autoindex_xml(r, &entries);
        break;

    default: /* NGX_HTTP_AUTOINDEX_HTML */
        b = ngx_http_autoindex_html(r, &entries);
        break;
    }

    if (b == NULL) {
        return NGX_ERROR;
    }

    /* TODO: free temporary pool */

    if (r == r->main) {
        b->last_buf = 1;
    }

    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


/**
 * 构建html响应体
 */
static ngx_buf_t *
ngx_http_autoindex_html(ngx_http_request_t *r, ngx_array_t *entries)
{
    u_char                         *last, scale;
    off_t                           length;
    size_t                          len, entry_len, char_len, escape_html;
    ngx_tm_t                        tm;
    ngx_buf_t                      *b;
    ngx_int_t                       size;
    ngx_uint_t                      i, utf8;
    ngx_time_t                     *tp;
    ngx_http_autoindex_entry_t     *entry;
    ngx_http_autoindex_loc_conf_t  *alcf;

    static u_char  title[] =
        "<html>" CRLF
        "<head><title>Index of "
    ;

    static u_char  header[] =
        "</title></head>" CRLF
        "<body>" CRLF
        "<h1>Index of "
    ;

    static u_char  tail[] =
        "</body>" CRLF
        "</html>" CRLF
    ;

    static char  *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                               "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    if (r->headers_out.charset.len == 5
        && ngx_strncasecmp(r->headers_out.charset.data, (u_char *) "utf-8", 5)
           == 0)
    {
        utf8 = 1;

    } else {
        utf8 = 0;
    }

    escape_html = ngx_escape_html(NULL, r->uri.data, r->uri.len);

    len = sizeof(title) - 1
          + r->uri.len + escape_html
          + sizeof(header) - 1
          + r->uri.len + escape_html
          + sizeof("</h1>") - 1
          + sizeof("<hr><pre><a href=\"../\">../</a>" CRLF) - 1
          + sizeof("</pre><hr>") - 1
          + sizeof(tail) - 1;

    //1. 计算响应体长度
    entry = entries->elts;
    for (i = 0; i < entries->nelts; i++) {
        entry[i].escape = 2 * ngx_escape_uri(NULL, entry[i].name.data,
                                             entry[i].name.len,
                                             NGX_ESCAPE_URI_COMPONENT);

        entry[i].escape_html = ngx_escape_html(NULL, entry[i].name.data,
                                               entry[i].name.len);

        if (utf8) {
            entry[i].utf_len = ngx_utf8_length(entry[i].name.data,
                                               entry[i].name.len);
        } else {
            entry[i].utf_len = entry[i].name.len;
        }

        entry_len = sizeof("<a href=\"") - 1
                  + entry[i].name.len + entry[i].escape
                  + 1                                    /* 1 is for "/" */
                  + sizeof("\">") - 1
                  + entry[i].name.len - entry[i].utf_len
                  + entry[i].escape_html
                  + NGX_HTTP_AUTOINDEX_NAME_LEN + sizeof("&gt;") - 2
                  + sizeof("</a>") - 1
                  + sizeof(" 28-Sep-1970 12:00 ") - 1
                  + 20                                   /* the file size */
                  + 2;

        if (len > NGX_MAX_SIZE_T_VALUE - entry_len) {
            return NULL;
        }

        len += entry_len;
    }

    //2. 申请内存
    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NULL;
    }

    //3. 构建响应体
    b->last = ngx_cpymem(b->last, title, sizeof(title) - 1);

    if (escape_html) {
        b->last = (u_char *) ngx_escape_html(b->last, r->uri.data, r->uri.len);
        b->last = ngx_cpymem(b->last, header, sizeof(header) - 1);
        b->last = (u_char *) ngx_escape_html(b->last, r->uri.data, r->uri.len);

    } else {
        b->last = ngx_cpymem(b->last, r->uri.data, r->uri.len);
        b->last = ngx_cpymem(b->last, header, sizeof(header) - 1);
        b->last = ngx_cpymem(b->last, r->uri.data, r->uri.len);
    }

    b->last = ngx_cpymem(b->last, "</h1>", sizeof("</h1>") - 1);

    b->last = ngx_cpymem(b->last, "<hr><pre><a href=\"../\">../</a>" CRLF,
                         sizeof("<hr><pre><a href=\"../\">../</a>" CRLF) - 1);

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_autoindex_module);
    tp = ngx_timeofday();

    for (i = 0; i < entries->nelts; i++) {
        b->last = ngx_cpymem(b->last, "<a href=\"", sizeof("<a href=\"") - 1);

        if (entry[i].escape) {
            ngx_escape_uri(b->last, entry[i].name.data, entry[i].name.len,
                           NGX_ESCAPE_URI_COMPONENT);

            b->last += entry[i].name.len + entry[i].escape;

        } else {
            b->last = ngx_cpymem(b->last, entry[i].name.data,
                                 entry[i].name.len);
        }

        if (entry[i].dir) {
            *b->last++ = '/';
        }

        *b->last++ = '"';
        *b->last++ = '>';

        len = entry[i].utf_len;

        if (entry[i].name.len != len) {
            if (len > NGX_HTTP_AUTOINDEX_NAME_LEN) {
                char_len = NGX_HTTP_AUTOINDEX_NAME_LEN - 3 + 1;

            } else {
                char_len = NGX_HTTP_AUTOINDEX_NAME_LEN + 1;
            }

            last = b->last;
            b->last = ngx_utf8_cpystrn(b->last, entry[i].name.data,
                                       char_len, entry[i].name.len + 1);

            if (entry[i].escape_html) {
                b->last = (u_char *) ngx_escape_html(last, entry[i].name.data,
                                                     b->last - last);
            }

            last = b->last;

        } else {
            if (entry[i].escape_html) {
                if (len > NGX_HTTP_AUTOINDEX_NAME_LEN) {
                    char_len = NGX_HTTP_AUTOINDEX_NAME_LEN - 3;

                } else {
                    char_len = len;
                }

                b->last = (u_char *) ngx_escape_html(b->last,
                                                  entry[i].name.data, char_len);
                last = b->last;

            } else {
                b->last = ngx_cpystrn(b->last, entry[i].name.data,
                                      NGX_HTTP_AUTOINDEX_NAME_LEN + 1);
                last = b->last - 3;
            }
        }

        if (len > NGX_HTTP_AUTOINDEX_NAME_LEN) {
            b->last = ngx_cpymem(last, "..&gt;</a>", sizeof("..&gt;</a>") - 1);

        } else {
            if (entry[i].dir && NGX_HTTP_AUTOINDEX_NAME_LEN - len > 0) {
                *b->last++ = '/';
                len++;
            }

            b->last = ngx_cpymem(b->last, "</a>", sizeof("</a>") - 1);

            if (NGX_HTTP_AUTOINDEX_NAME_LEN - len > 0) {
                ngx_memset(b->last, ' ', NGX_HTTP_AUTOINDEX_NAME_LEN - len);
                b->last += NGX_HTTP_AUTOINDEX_NAME_LEN - len;
            }
        }

        *b->last++ = ' ';

        ngx_gmtime(entry[i].mtime + tp->gmtoff * 60 * alcf->localtime, &tm);

        b->last = ngx_sprintf(b->last, "%02d-%s-%d %02d:%02d ",
                              tm.ngx_tm_mday,
                              months[tm.ngx_tm_mon - 1],
                              tm.ngx_tm_year,
                              tm.ngx_tm_hour,
                              tm.ngx_tm_min);

        if (alcf->exact_size) {
            if (entry[i].dir) {
                b->last = ngx_cpymem(b->last,  "                  -",
                                     sizeof("                  -") - 1);
            } else {
                b->last = ngx_sprintf(b->last, "%19O", entry[i].size);
            }

        } else {
            if (entry[i].dir) {
                b->last = ngx_cpymem(b->last,  "      -",
                                     sizeof("      -") - 1);

            } else {
                length = entry[i].size;

                if (length > 1024 * 1024 * 1024 - 1) {
                    size = (ngx_int_t) (length / (1024 * 1024 * 1024));
                    if ((length % (1024 * 1024 * 1024))
                                                > (1024 * 1024 * 1024 / 2 - 1))
                    {
                        size++;
                    }
                    scale = 'G';

                } else if (length > 1024 * 1024 - 1) {
                    size = (ngx_int_t) (length / (1024 * 1024));
                    if ((length % (1024 * 1024)) > (1024 * 1024 / 2 - 1)) {
                        size++;
                    }
                    scale = 'M';

                } else if (length > 9999) {
                    size = (ngx_int_t) (length / 1024);
                    if (length % 1024 > 511) {
                        size++;
                    }
                    scale = 'K';

                } else {
                    size = (ngx_int_t) length;
                    scale = '\0';
                }

                if (scale) {
                    b->last = ngx_sprintf(b->last, "%6i%c", size, scale);

                } else {
                    b->last = ngx_sprintf(b->last, " %6i", size);
                }
            }
        }

        *b->last++ = CR;
        *b->last++ = LF;
    }

    b->last = ngx_cpymem(b->last, "</pre><hr>", sizeof("</pre><hr>") - 1);

    b->last = ngx_cpymem(b->last, tail, sizeof(tail) - 1);

    return b;
}


/**
 * 构建json响应体
 * 输出json格式。entries里存放的是请求目录下的所以文件项
 * 
 * 如果callback不为null, 则输出jsonp格式。
 * 
 * json格式：
 *  [{"name":"a","type":"directory", "mtime":"xxxx"},{}]
 * 
 * jsonp格式：
 *  1.响应头content_type是 "application/javascript"
 *  2.响应体将会是js代码函数调用, 如：callback=abc, 则响应内容为 abc($json)
 * 
 */
static ngx_buf_t *
ngx_http_autoindex_json(ngx_http_request_t *r, ngx_array_t *entries,
    ngx_str_t *callback)
{
    size_t                       len, entry_len;
    ngx_buf_t                   *b;
    ngx_uint_t                   i;
    ngx_http_autoindex_entry_t  *entry;

    len = sizeof("[" CRLF CRLF "]") - 1;

    if (callback) {
        len += sizeof("/* callback */" CRLF "();") - 1 + callback->len;
    }

    entry = entries->elts;

    //1.计算json的长度
    for (i = 0; i < entries->nelts; i++) {
        entry[i].escape = ngx_escape_json(NULL, entry[i].name.data,
                                          entry[i].name.len);

        entry_len = sizeof("{  }," CRLF) - 1
                  + sizeof("\"name\":\"\"") - 1
                  + entry[i].name.len + entry[i].escape
                  + sizeof(", \"type\":\"directory\"") - 1
                  + sizeof(", \"mtime\":\"Wed, 31 Dec 1986 10:00:00 GMT\"") - 1;

        if (entry[i].file) {
            entry_len += sizeof(", \"size\":") - 1 + NGX_OFF_T_LEN;
        }

        if (len > NGX_MAX_SIZE_T_VALUE - entry_len) {
            return NULL;
        }

        len += entry_len;
    }

    //2.申请空间
    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NULL;
    }

    if (callback) {
        b->last = ngx_cpymem(b->last, "/* callback */" CRLF,
                             sizeof("/* callback */" CRLF) - 1);

        b->last = ngx_cpymem(b->last, callback->data, callback->len);

        *b->last++ = '(';
    }

    *b->last++ = '[';

    //3.构建json
    for (i = 0; i < entries->nelts; i++) {
        b->last = ngx_cpymem(b->last, CRLF "{ \"name\":\"",
                             sizeof(CRLF "{ \"name\":\"") - 1);

        if (entry[i].escape) {
            b->last = (u_char *) ngx_escape_json(b->last, entry[i].name.data,
                                                 entry[i].name.len);
        } else {
            b->last = ngx_cpymem(b->last, entry[i].name.data,
                                 entry[i].name.len);
        }

        b->last = ngx_cpymem(b->last, "\", \"type\":\"",
                             sizeof("\", \"type\":\"") - 1);

        if (entry[i].dir) {
            b->last = ngx_cpymem(b->last, "directory", sizeof("directory") - 1);

        } else if (entry[i].file) {
            b->last = ngx_cpymem(b->last, "file", sizeof("file") - 1);

        } else {
            b->last = ngx_cpymem(b->last, "other", sizeof("other") - 1);
        }

        b->last = ngx_cpymem(b->last, "\", \"mtime\":\"",
                             sizeof("\", \"mtime\":\"") - 1);

        b->last = ngx_http_time(b->last, entry[i].mtime);

        if (entry[i].file) {
            b->last = ngx_cpymem(b->last, "\", \"size\":",
                                 sizeof("\", \"size\":") - 1);
            b->last = ngx_sprintf(b->last, "%O", entry[i].size);

        } else {
            *b->last++ = '"';
        }

        b->last = ngx_cpymem(b->last, " },", sizeof(" },") - 1);
    }

    if (i > 0) {
        b->last--;  /* strip last comma */
    }

    b->last = ngx_cpymem(b->last, CRLF "]", sizeof(CRLF "]") - 1);

    if (callback) {
        *b->last++ = ')'; *b->last++ = ';';
    }

    return b;
}


/**
 * 响应格式为jsonp
 * 
 * 本方法只是对请求url参数callback做了简单校验
 * 
 * 如果不含callback参数或callback参数校验通过，返回NGX_OK
 */
static ngx_int_t
ngx_http_autoindex_jsonp_callback(ngx_http_request_t *r, ngx_str_t *callback)
{
    u_char      *p, c, ch;
    ngx_uint_t   i;

    //获取请求url参数：callback
    if (ngx_http_arg(r, (u_char *) "callback", 8, callback) != NGX_OK) {
        callback->len = 0;
        return NGX_OK;  //如果没有callback参数，直接返回。将降级为使用json
    }

    if (callback->len > 128) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent too long callback name: \"%V\"", callback);
        return NGX_DECLINED;
    }

    p = callback->data;

    //对callback参数进行校验:只能包含大小写、数字、_、.。如果有其他字符，报错
    for (i = 0; i < callback->len; i++) {
        ch = p[i];

        c = (u_char) (ch | 0x20);
        if (c >= 'a' && c <= 'z') {
            continue;
        }

        if ((ch >= '0' && ch <= '9') || ch == '_' || ch == '.') {
            continue;
        }

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent invalid callback name: \"%V\"", callback);

        return NGX_DECLINED;
    }

    return NGX_OK;
}


/**
 * 构建xml响应体
 */
static ngx_buf_t *
ngx_http_autoindex_xml(ngx_http_request_t *r, ngx_array_t *entries)
{
    size_t                          len, entry_len;
    ngx_tm_t                        tm;
    ngx_buf_t                      *b;
    ngx_str_t                       type;
    ngx_uint_t                      i;
    ngx_http_autoindex_entry_t     *entry;

    static u_char  head[] = "<?xml version=\"1.0\"?>" CRLF "<list>" CRLF;
    static u_char  tail[] = "</list>" CRLF;

    len = sizeof(head) - 1 + sizeof(tail) - 1;

    entry = entries->elts;

    //1.先计算响应体长度
    for (i = 0; i < entries->nelts; i++) {
        entry[i].escape = ngx_escape_html(NULL, entry[i].name.data,
                                          entry[i].name.len);

        entry_len = sizeof("<directory></directory>" CRLF) - 1
                  + entry[i].name.len + entry[i].escape
                  + sizeof(" mtime=\"1986-12-31T10:00:00Z\"") - 1;

        if (entry[i].file) {
            entry_len += sizeof(" size=\"\"") - 1 + NGX_OFF_T_LEN;
        }

        if (len > NGX_MAX_SIZE_T_VALUE - entry_len) {
            return NULL;
        }

        len += entry_len;
    }

    //2. 申请内存
    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NULL;
    }

    //3. 构建响应体
    b->last = ngx_cpymem(b->last, head, sizeof(head) - 1);

    for (i = 0; i < entries->nelts; i++) {
        *b->last++ = '<';

        if (entry[i].dir) {
            ngx_str_set(&type, "directory");

        } else if (entry[i].file) {
            ngx_str_set(&type, "file");

        } else {
            ngx_str_set(&type, "other");
        }

        b->last = ngx_cpymem(b->last, type.data, type.len);

        b->last = ngx_cpymem(b->last, " mtime=\"", sizeof(" mtime=\"") - 1);

        ngx_gmtime(entry[i].mtime, &tm);

        b->last = ngx_sprintf(b->last, "%4d-%02d-%02dT%02d:%02d:%02dZ",
                              tm.ngx_tm_year, tm.ngx_tm_mon,
                              tm.ngx_tm_mday, tm.ngx_tm_hour,
                              tm.ngx_tm_min, tm.ngx_tm_sec);

        if (entry[i].file) {
            b->last = ngx_cpymem(b->last, "\" size=\"",
                                 sizeof("\" size=\"") - 1);
            b->last = ngx_sprintf(b->last, "%O", entry[i].size);
        }

        *b->last++ = '"'; *b->last++ = '>';

        if (entry[i].escape) {
            b->last = (u_char *) ngx_escape_html(b->last, entry[i].name.data,
                                                 entry[i].name.len);
        } else {
            b->last = ngx_cpymem(b->last, entry[i].name.data,
                                 entry[i].name.len);
        }

        *b->last++ = '<'; *b->last++ = '/';

        b->last = ngx_cpymem(b->last, type.data, type.len);

        *b->last++ = '>';

        *b->last++ = CR; *b->last++ = LF;
    }

    b->last = ngx_cpymem(b->last, tail, sizeof(tail) - 1);

    return b;
}


/**
 * 目录项名称比较函数，用户输出结果排序
 */
static int ngx_libc_cdecl
ngx_http_autoindex_cmp_entries(const void *one, const void *two)
{
    ngx_http_autoindex_entry_t *first = (ngx_http_autoindex_entry_t *) one;
    ngx_http_autoindex_entry_t *second = (ngx_http_autoindex_entry_t *) two;

    if (first->dir && !second->dir) {
        /* move the directories to the start */
        return -1;
    }

    if (!first->dir && second->dir) {
        /* move the directories to the start */
        return 1;
    }

    return (int) ngx_strcmp(first->name.data, second->name.data);
}


#if 0

static ngx_buf_t *
ngx_http_autoindex_alloc(ngx_http_autoindex_ctx_t *ctx, size_t size)
{
    ngx_chain_t  *cl;

    if (ctx->buf) {

        if ((size_t) (ctx->buf->end - ctx->buf->last) >= size) {
            return ctx->buf;
        }

        ctx->size += ctx->buf->last - ctx->buf->pos;
    }

    ctx->buf = ngx_create_temp_buf(ctx->pool, ctx->alloc_size);
    if (ctx->buf == NULL) {
        return NULL;
    }

    cl = ngx_alloc_chain_link(ctx->pool);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = ctx->buf;
    cl->next = NULL;

    *ctx->last_out = cl;
    ctx->last_out = &cl->next;

    return ctx->buf;
}

#endif


/**
 * 错误，关闭打开的文件目录。返回500
 */
static ngx_int_t
ngx_http_autoindex_error(ngx_http_request_t *r, ngx_dir_t *dir, ngx_str_t *name)
{
    if (ngx_close_dir(dir) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                      ngx_close_dir_n " \"%V\" failed", name);
    }

    return r->header_sent ? NGX_ERROR : NGX_HTTP_INTERNAL_SERVER_ERROR;
}


/**
 * 创建配置结构体
 */
static void *
ngx_http_autoindex_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_autoindex_loc_conf_t  *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_http_autoindex_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->format = NGX_CONF_UNSET_UINT;
    conf->localtime = NGX_CONF_UNSET;
    conf->exact_size = NGX_CONF_UNSET;

    return conf;
}


/**
 * 合并配置
 */
static char *
ngx_http_autoindex_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_autoindex_loc_conf_t *prev = parent;
    ngx_http_autoindex_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_uint_value(conf->format, prev->format,
                              NGX_HTTP_AUTOINDEX_HTML);
    ngx_conf_merge_value(conf->localtime, prev->localtime, 0);
    ngx_conf_merge_value(conf->exact_size, prev->exact_size, 1);

    return NGX_CONF_OK;
}


/**
 *  postconfiguration , 安装content_handler
 */
static ngx_int_t
ngx_http_autoindex_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_autoindex_handler;

    return NGX_OK;
}
