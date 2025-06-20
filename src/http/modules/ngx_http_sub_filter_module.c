
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/**
 * https://nginx.org/en/docs/http/ngx_http_sub_module.html
 * 
 * 实现文本替换，非默认启用
 * 
 * 如： sub_filter '<a href="http://127.0.0.1:8080/'  '<a href="https://$host/';
 */

/**
 * 表示一条替换指令
 */
typedef struct {
    ngx_http_complex_value_t   match;       //原始值
    ngx_http_complex_value_t   value;       //替换值
} ngx_http_sub_pair_t;


typedef struct {
    ngx_str_t                  match;
    ngx_http_complex_value_t  *value;
} ngx_http_sub_match_t;


typedef struct {
    ngx_uint_t                 min_match_len;       //最短替换源字符串的长度
    ngx_uint_t                 max_match_len;       //最长替换源字符串的长度

    u_char                     index[257];
    u_char                     shift[256];
} ngx_http_sub_tables_t;


/**
 * 模块loc级别配置结构体
 */
typedef struct {
    //标识要替换的string是否包含变量
    ngx_uint_t                 dynamic; /* unsigned dynamic:1; */

    ngx_array_t               *pairs;       //表示当前loc上配置的所有替换规则，元素类型为ngx_http_sub_pair_t

    ngx_http_sub_tables_t     *tables;

    ngx_hash_t                 types;           //types_keys 组成的hash表
    ngx_flag_t                 once;            //标识只进行一次替换
    ngx_flag_t                 last_modified;   //标识是否保留last_modified响应头

    ngx_array_t               *types_keys;      //sub_filter_types mime-type ...; 配置进行替换的 MIME types. 元素类型为 ngx_hash_key_t
    ngx_array_t               *matches;         //如果dynamic=0， matches为pairs复制，元素类型为 ngx_http_sub_match_t
} ngx_http_sub_loc_conf_t;


/**
 * 模块的自定义上下文
 */
typedef struct {
    ngx_str_t                  saved;
    ngx_str_t                  looked;

    ngx_uint_t                 once;   /* unsigned  once:1 */

    ngx_buf_t                 *buf;

    u_char                    *pos;
    u_char                    *copy_start;
    u_char                    *copy_end;

    ngx_chain_t               *in;
    ngx_chain_t               *out;
    ngx_chain_t              **last_out;
    ngx_chain_t               *busy;
    ngx_chain_t               *free;

    ngx_str_t                 *sub;
    ngx_uint_t                 applied;

    ngx_int_t                  offset;
    ngx_uint_t                 index;

    ngx_http_sub_tables_t     *tables;
    ngx_array_t               *matches;
} ngx_http_sub_ctx_t;


static ngx_uint_t ngx_http_sub_cmp_index;


static ngx_int_t ngx_http_sub_output(ngx_http_request_t *r,
    ngx_http_sub_ctx_t *ctx);
static ngx_int_t ngx_http_sub_parse(ngx_http_request_t *r,
    ngx_http_sub_ctx_t *ctx, ngx_uint_t flush);
static ngx_int_t ngx_http_sub_match(ngx_http_sub_ctx_t *ctx, ngx_int_t start,
    ngx_str_t *m);

static char * ngx_http_sub_filter(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void *ngx_http_sub_create_conf(ngx_conf_t *cf);
static char *ngx_http_sub_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);
static void ngx_http_sub_init_tables(ngx_http_sub_tables_t *tables,
    ngx_http_sub_match_t *match, ngx_uint_t n);
static ngx_int_t ngx_http_sub_cmp_matches(const void *one, const void *two);
static ngx_int_t ngx_http_sub_filter_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_sub_filter_commands[] = {

    { ngx_string("sub_filter"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_sub_filter,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("sub_filter_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_types_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_sub_loc_conf_t, types_keys),
      &ngx_http_html_default_types[0] },

    { ngx_string("sub_filter_once"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_sub_loc_conf_t, once),
      NULL },

    { ngx_string("sub_filter_last_modified"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_sub_loc_conf_t, last_modified),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_sub_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    //注册header_filter/body_filter
    ngx_http_sub_filter_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_sub_create_conf,              /* create location configuration */
    ngx_http_sub_merge_conf                /* merge location configuration */
};


ngx_module_t  ngx_http_sub_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_sub_filter_module_ctx,       /* module context */
    ngx_http_sub_filter_commands,          /* module directives */
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


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


/**
 * header filter
 */
static ngx_int_t
ngx_http_sub_header_filter(ngx_http_request_t *r)
{
    ngx_str_t                *m;
    ngx_uint_t                i, j, n;
    ngx_http_sub_ctx_t       *ctx;
    ngx_http_sub_pair_t      *pairs;
    ngx_http_sub_match_t     *matches;
    ngx_http_sub_loc_conf_t  *slcf;

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_sub_filter_module);

    if (slcf->pairs == NULL
        || r->headers_out.content_length_n == 0
        || ngx_http_test_content_type(r, &slcf->types) == NULL)     //响应头是否命中配置的content_type
    {
        return ngx_http_next_header_filter(r);
    }

    //创建模块自定义上下文结构体
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_sub_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (slcf->dynamic == 0) {       //如果key不包含变量，直接复制配置文件中的
        ctx->tables = slcf->tables;
        ctx->matches = slcf->matches;

    } else {
        //否则获取key表示的复杂变量值，然后构建ctx->matches数组
        pairs = slcf->pairs->elts;
        n = slcf->pairs->nelts;

        matches = ngx_pcalloc(r->pool, sizeof(ngx_http_sub_match_t) * n);
        if (matches == NULL) {
            return NGX_ERROR;
        }

        //遍历所有的匹配规则，获取key的真实值
        j = 0;
        for (i = 0; i < n; i++) {
            matches[j].value = &pairs[i].value;

            if (pairs[i].match.lengths == NULL) {
                matches[j].match = pairs[i].match.value;
                j++;
                continue;
            }

            m = &matches[j].match;
            //获取每个替换规则中key的真实值
            if (ngx_http_complex_value(r, &pairs[i].match, m) != NGX_OK) {
                return NGX_ERROR;
            }

            if (m->len == 0) {
                continue;
            }

            ngx_strlow(m->data, m->data, m->len);
            j++;
        }

        if (j == 0) {
            return ngx_http_next_header_filter(r);
        }

        //创建matches数组
        ctx->matches = ngx_palloc(r->pool, sizeof(ngx_array_t));
        if (ctx->matches == NULL) {
            return NGX_ERROR;
        }

        //赋值数据
        ctx->matches->elts = matches;
        ctx->matches->nelts = j;

        ctx->tables = ngx_palloc(r->pool, sizeof(ngx_http_sub_tables_t));
        if (ctx->tables == NULL) {
            return NGX_ERROR;
        }

        //初始化ctx->tables
        ngx_http_sub_init_tables(ctx->tables, ctx->matches->elts,
                                 ctx->matches->nelts);
    }

    ctx->saved.data = ngx_pnalloc(r->pool, ctx->tables->max_match_len - 1);
    if (ctx->saved.data == NULL) {
        return NGX_ERROR;
    }

    ctx->looked.data = ngx_pnalloc(r->pool, ctx->tables->max_match_len - 1);
    if (ctx->looked.data == NULL) {
        return NGX_ERROR;
    }

    //保存模块上下文结构体
    ngx_http_set_ctx(r, ctx, ngx_http_sub_filter_module);

    ctx->offset = ctx->tables->min_match_len - 1;
    ctx->last_out = &ctx->out;

    r->filter_need_in_memory = 1;

    if (r == r->main) {         //如果是主请求
        ngx_http_clear_content_length(r);       //清理content_length响应头

        if (!slcf->last_modified) {             //根据配置是否清理响应头last_modified / etag
            ngx_http_clear_last_modified(r);
            ngx_http_clear_etag(r);

        } else {
            ngx_http_weak_etag(r);      //如果配置保存last_modified, etag标识为weak
        }
    }

    return ngx_http_next_header_filter(r);
}


/**
 * body filter
 */
static ngx_int_t
ngx_http_sub_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_str_t                 *sub;
    ngx_uint_t                 flush, last;
    ngx_chain_t               *cl;
    ngx_http_sub_ctx_t        *ctx;
    ngx_http_sub_match_t      *match;
    ngx_http_sub_loc_conf_t   *slcf;

    //获取模块上下文结构体
    ctx = ngx_http_get_module_ctx(r, ngx_http_sub_filter_module);

    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    //空响应体
    if ((in == NULL
         && ctx->buf == NULL
         && ctx->in == NULL
         && ctx->busy == NULL))
    {
        return ngx_http_next_body_filter(r, in);
    }

    if (ctx->once && (ctx->buf == NULL || ctx->in == NULL)) {

        if (ctx->busy) {
            if (ngx_http_sub_output(r, ctx) == NGX_ERROR) {
                return NGX_ERROR;
            }
        }

        return ngx_http_next_body_filter(r, in);
    }

    /* add the incoming chain to the chain ctx->in */

    if (in) {
        //将in拷贝到  &ctx->in
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http sub filter \"%V\"", &r->uri);

    flush = 0;
    last = 0;

    while (ctx->in || ctx->buf) {

        //ctx->buf 指向ctx->in->buf. ctx->in指向下一个buf
        if (ctx->buf == NULL) {

            cl = ctx->in;
            ctx->buf = cl->buf;
            ctx->in = cl->next;
            ctx->pos = ctx->buf->pos;

            ngx_free_chain(r->pool, cl);
        }

        if (ctx->buf->flush || ctx->buf->recycled) {
            flush = 1;
        }

        if (ctx->in == NULL) {
            last = flush;
        }

        b = NULL;

        while (ctx->pos < ctx->buf->last) {

            rc = ngx_http_sub_parse(r, ctx, last);

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "parse: %i, looked: \"%V\" %p-%p",
                           rc, &ctx->looked, ctx->copy_start, ctx->copy_end);

            if (rc == NGX_ERROR) {
                return rc;
            }

            if (ctx->saved.len) {

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "saved: \"%V\"", &ctx->saved);

                cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
                if (cl == NULL) {
                    return NGX_ERROR;
                }

                b = cl->buf;

                ngx_memzero(b, sizeof(ngx_buf_t));

                b->pos = ngx_pnalloc(r->pool, ctx->saved.len);
                if (b->pos == NULL) {
                    return NGX_ERROR;
                }

                ngx_memcpy(b->pos, ctx->saved.data, ctx->saved.len);
                b->last = b->pos + ctx->saved.len;
                b->memory = 1;

                *ctx->last_out = cl;
                ctx->last_out = &cl->next;

                ctx->saved.len = 0;
            }

            if (ctx->copy_start != ctx->copy_end) {

                cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
                if (cl == NULL) {
                    return NGX_ERROR;
                }

                b = cl->buf;

                ngx_memcpy(b, ctx->buf, sizeof(ngx_buf_t));

                b->pos = ctx->copy_start;
                b->last = ctx->copy_end;
                b->shadow = NULL;
                b->last_buf = 0;
                b->last_in_chain = 0;
                b->recycled = 0;

                if (b->in_file) {
                    b->file_last = b->file_pos + (b->last - ctx->buf->pos);
                    b->file_pos += b->pos - ctx->buf->pos;
                }

                *ctx->last_out = cl;
                ctx->last_out = &cl->next;
            }

            if (rc == NGX_AGAIN) {
                continue;
            }


            /* rc == NGX_OK */

            cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            b = cl->buf;

            ngx_memzero(b, sizeof(ngx_buf_t));

            slcf = ngx_http_get_module_loc_conf(r, ngx_http_sub_filter_module);

            if (ctx->sub == NULL) {
                ctx->sub = ngx_pcalloc(r->pool, sizeof(ngx_str_t)
                                                * ctx->matches->nelts);
                if (ctx->sub == NULL) {
                    return NGX_ERROR;
                }
            }

            sub = &ctx->sub[ctx->index];

            if (sub->data == NULL) {
                match = ctx->matches->elts;

                if (ngx_http_complex_value(r, match[ctx->index].value, sub)
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }
            }

            if (sub->len) {
                b->memory = 1;
                b->pos = sub->data;
                b->last = sub->data + sub->len;

            } else {
                b->sync = 1;
            }

            *ctx->last_out = cl;
            ctx->last_out = &cl->next;

            ctx->index = 0;
            ctx->once = slcf->once && (++ctx->applied == ctx->matches->nelts);

            continue;
        }

        if (ctx->looked.len
            && (ctx->buf->last_buf || ctx->buf->last_in_chain))
        {
            cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            b = cl->buf;

            ngx_memzero(b, sizeof(ngx_buf_t));

            b->pos = ctx->looked.data;
            b->last = b->pos + ctx->looked.len;
            b->memory = 1;

            *ctx->last_out = cl;
            ctx->last_out = &cl->next;

            ctx->looked.len = 0;
        }

        if (ctx->buf->last_buf || ctx->buf->flush || ctx->buf->sync
            || ngx_buf_in_memory(ctx->buf))
        {
            if (b == NULL) {
                cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
                if (cl == NULL) {
                    return NGX_ERROR;
                }

                b = cl->buf;

                ngx_memzero(b, sizeof(ngx_buf_t));

                b->sync = 1;

                *ctx->last_out = cl;
                ctx->last_out = &cl->next;
            }

            b->last_buf = ctx->buf->last_buf;
            b->last_in_chain = ctx->buf->last_in_chain;
            b->flush = ctx->buf->flush;
            b->shadow = ctx->buf;

            b->recycled = ctx->buf->recycled;
        }

        ctx->buf = NULL;
    }

    if (ctx->out == NULL && ctx->busy == NULL) {
        return NGX_OK;
    }

    return ngx_http_sub_output(r, ctx);
}


static ngx_int_t
ngx_http_sub_output(ngx_http_request_t *r, ngx_http_sub_ctx_t *ctx)
{
    ngx_int_t     rc;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

#if 1
    b = NULL;
    for (cl = ctx->out; cl; cl = cl->next) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "sub out: %p %p", cl->buf, cl->buf->pos);
        if (cl->buf == b) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "the same buf was used in sub");
            ngx_debug_point();
            return NGX_ERROR;
        }
        b = cl->buf;
    }
#endif

    rc = ngx_http_next_body_filter(r, ctx->out);

    if (ctx->busy == NULL) {
        ctx->busy = ctx->out;

    } else {
        for (cl = ctx->busy; cl->next; cl = cl->next) { /* void */ }
        cl->next = ctx->out;
    }

    ctx->out = NULL;
    ctx->last_out = &ctx->out;

    while (ctx->busy) {

        cl = ctx->busy;
        b = cl->buf;

        if (ngx_buf_size(b) != 0) {
            break;
        }

        if (b->shadow) {
            b->shadow->pos = b->shadow->last;
        }

        ctx->busy = cl->next;

        if (ngx_buf_in_memory(b) || b->in_file) {
            /* add data bufs only to the free buf chain */

            cl->next = ctx->free;
            ctx->free = cl;
        }
    }

    if (ctx->in || ctx->buf) {
        r->buffered |= NGX_HTTP_SUB_BUFFERED;

    } else {
        r->buffered &= ~NGX_HTTP_SUB_BUFFERED;
    }

    return rc;
}


static ngx_int_t
ngx_http_sub_parse(ngx_http_request_t *r, ngx_http_sub_ctx_t *ctx,
    ngx_uint_t flush)
{
    u_char                   *p, c;
    ngx_str_t                *m;
    ngx_int_t                 offset, start, next, end, len, rc;
    ngx_uint_t                shift, i, j;
    ngx_http_sub_match_t     *match;
    ngx_http_sub_tables_t    *tables;
    ngx_http_sub_loc_conf_t  *slcf;

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_sub_filter_module);
    tables = ctx->tables;
    match = ctx->matches->elts;

    offset = ctx->offset;
    end = ctx->buf->last - ctx->pos;

    if (ctx->once) {
        /* sets start and next to end */
        offset = end + (ngx_int_t) tables->min_match_len - 1;
        goto again;
    }

    while (offset < end) {

        c = offset < 0 ? ctx->looked.data[ctx->looked.len + offset]
                       : ctx->pos[offset];

        c = ngx_tolower(c);

        shift = tables->shift[c];
        if (shift > 0) {
            offset += shift;
            continue;
        }

        /* a potential match */

        start = offset - (ngx_int_t) tables->min_match_len + 1;

        i = ngx_max((ngx_uint_t) tables->index[c], ctx->index);
        j = tables->index[c + 1];

        while (i != j) {

            if (slcf->once && ctx->sub && ctx->sub[i].data) {
                goto next;
            }

            m = &match[i].match;

            rc = ngx_http_sub_match(ctx, start, m);

            if (rc == NGX_DECLINED) {
                goto next;
            }

            ctx->index = i;

            if (rc == NGX_AGAIN) {
                goto again;
            }

            ctx->offset = offset + (ngx_int_t) m->len;
            next = start + (ngx_int_t) m->len;
            end = ngx_max(next, 0);
            rc = NGX_OK;

            goto done;

        next:

            i++;
        }

        offset++;
        ctx->index = 0;
    }

    if (flush) {
        for ( ;; ) {
            start = offset - (ngx_int_t) tables->min_match_len + 1;

            if (start >= end) {
                break;
            }

            for (i = 0; i < ctx->matches->nelts; i++) {
                m = &match[i].match;

                if (ngx_http_sub_match(ctx, start, m) == NGX_AGAIN) {
                    goto again;
                }
            }

            offset++;
        }
    }

again:

    ctx->offset = offset;
    start = offset - (ngx_int_t) tables->min_match_len + 1;
    next = start;
    rc = NGX_AGAIN;

done:

    /* send [ - looked.len, start ] to client */

    ctx->saved.len = ctx->looked.len + ngx_min(start, 0);
    ngx_memcpy(ctx->saved.data, ctx->looked.data, ctx->saved.len);

    ctx->copy_start = ctx->pos;
    ctx->copy_end = ctx->pos + ngx_max(start, 0);

    /* save [ next, end ] in looked */

    len = ngx_min(next, 0);
    p = ctx->looked.data;
    p = ngx_movemem(p, p + ctx->looked.len + len, - len);

    len = ngx_max(next, 0);
    p = ngx_cpymem(p, ctx->pos + len, end - len);
    ctx->looked.len = p - ctx->looked.data;

    /* update position */

    ctx->pos += end;
    ctx->offset -= end;

    return rc;
}


static ngx_int_t
ngx_http_sub_match(ngx_http_sub_ctx_t *ctx, ngx_int_t start, ngx_str_t *m)
{
    u_char  *p, *last, *pat, *pat_end;

    pat = m->data;
    pat_end = m->data + m->len;

    if (start >= 0) {
        p = ctx->pos + start;

    } else {
        last = ctx->looked.data + ctx->looked.len;
        p = last + start;

        while (p < last && pat < pat_end) {
            if (ngx_tolower(*p) != *pat) {
                return NGX_DECLINED;
            }

            p++;
            pat++;
        }

        p = ctx->pos;
    }

    while (p < ctx->buf->last && pat < pat_end) {
        if (ngx_tolower(*p) != *pat) {
            return NGX_DECLINED;
        }

        p++;
        pat++;
    }

    if (pat != pat_end) {
        /* partial match */
        return NGX_AGAIN;
    }

    return NGX_OK;
}


/**
 * sub_filter 指令配置解析
 * 
 * 	sub_filter string replacement;
 *  
 *  可以配置多个
 * 
 */
static char *
ngx_http_sub_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_sub_loc_conf_t *slcf = conf;

    ngx_str_t                         *value;
    ngx_http_sub_pair_t               *pair;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (value[1].len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "empty search pattern");
        return NGX_CONF_ERROR;
    }

    //初始化slcf->pairs动态数组
    if (slcf->pairs == NULL) {
        slcf->pairs = ngx_array_create(cf->pool, 1,
                                       sizeof(ngx_http_sub_pair_t));
        if (slcf->pairs == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    //最多255条
    if (slcf->pairs->nelts == 255) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "number of search patterns exceeds 255");
        return NGX_CONF_ERROR;
    }

    ngx_strlow(value[1].data, value[1].data, value[1].len);

    //创建一个代表一条替换规则的 ngx_http_sub_pair_t
    pair = ngx_array_push(slcf->pairs);
    if (pair == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &pair->match;

    //编译复杂变量 value[1] string
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (ccv.complex_value->lengths != NULL) {
        //包含变量
        slcf->dynamic = 1;

    } else {
        //不包含变量，转小写
        ngx_strlow(pair->match.value.data, pair->match.value.data,
                   pair->match.value.len);
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &pair->value;

    //编译replacement value[2]
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/**
 * 创建loc配置结构体
 */
static void *
ngx_http_sub_create_conf(ngx_conf_t *cf)
{
    ngx_http_sub_loc_conf_t  *slcf;

    slcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sub_loc_conf_t));
    if (slcf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->dynamic = 0;
     *     conf->pairs = NULL;
     *     conf->tables = NULL;
     *     conf->types = { NULL };
     *     conf->types_keys = NULL;
     *     conf->matches = NULL;
     */

    slcf->once = NGX_CONF_UNSET;
    slcf->last_modified = NGX_CONF_UNSET;

    return slcf;
}


/**
 * 合并loc配置结构体
 */
static char *
ngx_http_sub_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_uint_t                i, n;
    ngx_http_sub_pair_t      *pairs;
    ngx_http_sub_match_t     *matches;
    ngx_http_sub_loc_conf_t  *prev = parent;
    ngx_http_sub_loc_conf_t  *conf = child;

    ngx_conf_merge_value(conf->once, prev->once, 1);
    ngx_conf_merge_value(conf->last_modified, prev->last_modified, 0);

    if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             ngx_http_html_default_types)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (conf->pairs == NULL) {
        conf->dynamic = prev->dynamic;
        conf->pairs = prev->pairs;
        conf->matches = prev->matches;
        conf->tables = prev->tables;
    }

    //conf->dynamic == 0 表示所有sub_filter 配置指令中配置的key都是静态不包含变量的
    //如果conf->dynamic == 0， 将 conf->pairs 复制到 conf->matches
    if (conf->pairs && conf->dynamic == 0 && conf->tables == NULL) {
        pairs = conf->pairs->elts;
        n = conf->pairs->nelts;

        //申请一个长度为n的ngx_http_sub_match_t数组
        matches = ngx_palloc(cf->pool, sizeof(ngx_http_sub_match_t) * n);
        if (matches == NULL) {
            return NGX_CONF_ERROR;
        }

        //为每个ngx_http_sub_match_t赋值
        for (i = 0; i < n; i++) {
            matches[i].match = pairs[i].match.value;
            matches[i].value = &pairs[i].value;
        }

        //创建  conf->matches 动态数组
        conf->matches = ngx_palloc(cf->pool, sizeof(ngx_array_t));
        if (conf->matches == NULL) {
            return NGX_CONF_ERROR;
        }

        conf->matches->elts = matches;
        conf->matches->nelts = n;

        conf->tables = ngx_palloc(cf->pool, sizeof(ngx_http_sub_tables_t));
        if (conf->tables == NULL) {
            return NGX_CONF_ERROR;
        }

        //初始化conf->tables
        ngx_http_sub_init_tables(conf->tables, conf->matches->elts,
                                 conf->matches->nelts);
    }

    return NGX_CONF_OK;
}


static void
ngx_http_sub_init_tables(ngx_http_sub_tables_t *tables,
    ngx_http_sub_match_t *match, ngx_uint_t n)
{
    u_char      c;
    ngx_uint_t  i, j, min, max, ch;

    min = match[0].match.len;       //最短替换源字符串的长度
    max = match[0].match.len;       //最长替换源字符串的长度

    for (i = 1; i < n; i++) {
        min = ngx_min(min, match[i].match.len);
        max = ngx_max(max, match[i].match.len);
    }

    tables->min_match_len = min;
    tables->max_match_len = max;

    ngx_http_sub_cmp_index = tables->min_match_len - 1;
    //根据第ngx_http_sub_cmp_index个字符进行排序
    ngx_sort(match, n, sizeof(ngx_http_sub_match_t), ngx_http_sub_cmp_matches);

    min = ngx_min(min, 255);
    ngx_memset(tables->shift, min, 256);

    ch = 0;

    //n为match数组个数
    for (i = 0; i < n; i++) {

        for (j = 0; j < min; j++) {
            c = match[i].match.data[tables->min_match_len - 1 - j];
            tables->shift[c] = ngx_min(tables->shift[c], (u_char) j);
        }

        c = match[i].match.data[tables->min_match_len - 1];
        while (ch <= (ngx_uint_t) c) {
            tables->index[ch++] = (u_char) i;
        }
    }

    while (ch < 257) {
        tables->index[ch++] = (u_char) n;
    }
}


/**
 * ngx_http_sub_match_t 类型的比较函数
 * 
 * 根据ngx_http_sub_match_t中ngx_str_t成员match的第ngx_http_sub_cmp_index个字符进行排序
 */
static ngx_int_t
ngx_http_sub_cmp_matches(const void *one, const void *two)
{
    ngx_int_t              c1, c2;
    ngx_http_sub_match_t  *first, *second;

    first = (ngx_http_sub_match_t *) one;
    second = (ngx_http_sub_match_t *) two;

    //第ngx_http_sub_cmp_index个字符
    c1 = first->match.data[ngx_http_sub_cmp_index];
    c2 = second->match.data[ngx_http_sub_cmp_index];

    return c1 - c2;
}


/**
 * postconfiguration
 * 注册header_filter/body_filter
 */
static ngx_int_t
ngx_http_sub_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_sub_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_sub_body_filter;

    return NGX_OK;
}
