#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static u_int hit = 100;
static ngx_str_t res_null = ngx_string("null");
static ngx_str_t res_no_arg = ngx_string("no_arg");
static ngx_str_t res_not_hit = ngx_string("not_hit");
static ngx_str_t res_hit = ngx_string("hit");

static ngx_int_t ngx_http_myhash_handler(ngx_http_request_t *r);

static void* ngx_http_myhash_create_loc_conf(ngx_conf_t *cf);

static char *ngx_http_myhash_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static char *ngx_http_conf_myhash(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static int ngx_libc_cdecl ngx_http_cmp_myhash_wildcards(const void *one, const void *two);

/**
 * 演示hash_combined的用法
 */
typedef struct
{
    ngx_hash_combined_t      hash;
    ngx_uint_t               my_hash_max_size;     //hash 槽数量
    ngx_uint_t               my_hash_bucket_size;  //hash槽大小
    ngx_array_t*  	         my_keys;
    ngx_hash_keys_arrays_t  *keys;      //临时的用于初始化hash结构体
} ngx_http_myhash_conf_t;


static ngx_command_t  ngx_http_myhash_commands[] = {
    {
        ngx_string("myhash"),
        NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
        ngx_http_conf_myhash,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },

    { ngx_string("my_hash_max_size"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_myhash_conf_t, my_hash_max_size),
      NULL 
    },

    { ngx_string("my_hash_max_size"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_myhash_conf_t, my_hash_max_size),
      NULL 
    },
    ngx_null_command
};

static ngx_http_module_t  ngx_http_myhash_module_ctx = {
    NULL,                              /* preconfiguration */
    NULL,                  		/* postconfiguration */

    NULL,                              /* create main configuration */
    NULL,                              /* init main configuration */

    NULL,                              /* create server configuration */
    NULL,                              /* merge server configuration */

    ngx_http_myhash_create_loc_conf, /* create location configuration */
    ngx_http_myhash_merge_loc_conf   /* merge location configuration */
};

ngx_module_t  ngx_http_myhash_module = {
    NGX_MODULE_V1,
    &ngx_http_myhash_module_ctx,           /* module context */
    ngx_http_myhash_commands,              /* module directives */
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
 * 解析配置 myhash 
 */
static char *
ngx_http_conf_myhash(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t    *clcf;
    ngx_http_myhash_conf_t      *rlcf = conf;

    ngx_str_t   *value;
    ngx_uint_t   i;

    //初始化 ngx_hash_keys_arrays_t
    if (rlcf->keys == NULL) {

        rlcf->keys = ngx_pcalloc(cf->temp_pool, sizeof(ngx_hash_keys_arrays_t));

        if (rlcf->keys == NULL) {
            return NGX_CONF_ERROR;
        }

        rlcf->keys->pool = cf->pool;
        rlcf->keys->temp_pool = cf->pool;

        if (ngx_hash_keys_array_init(rlcf->keys, NGX_HASH_SMALL) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }


    //添加key
    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        if (value[i].len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid key \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }

        if(ngx_hash_add_key(rlcf->keys, &value[i], &hit, NGX_HASH_WILDCARD_KEY) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    //安装content_handler
    clcf->handler = ngx_http_myhash_handler;

    return NGX_CONF_OK;
}

/**
 * 创建配置结构体
 */
static void* 
ngx_http_myhash_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_myhash_conf_t  *mycf;

    mycf = (ngx_http_myhash_conf_t  *)ngx_pcalloc(cf->pool, sizeof(ngx_http_myhash_conf_t));
    if (mycf == NULL)
    {
        return NULL;
    }

    mycf->my_keys = NGX_CONF_UNSET_PTR;
    mycf->my_hash_max_size = NGX_CONF_UNSET_UINT;
    mycf->my_hash_bucket_size = NGX_CONF_UNSET_UINT;
    return mycf;
}

/**
 * 合并配置
 */
static char *
ngx_http_myhash_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_myhash_conf_t *prev = (ngx_http_myhash_conf_t *)parent;
    ngx_http_myhash_conf_t *conf = (ngx_http_myhash_conf_t *)child;
    
    ngx_hash_init_t         hash;


    if (conf->keys == NULL) {
        conf->hash = prev->hash;
        ngx_conf_merge_uint_value(conf->my_hash_max_size,
                                    prev->my_hash_max_size, 2048);
        ngx_conf_merge_uint_value(conf->my_hash_bucket_size,
                                    prev->my_hash_bucket_size, 64);
        return NGX_CONF_OK;
    }
    ngx_conf_merge_uint_value(conf->my_hash_max_size,
                                prev->my_hash_max_size, 2048);
    ngx_conf_merge_uint_value(conf->my_hash_bucket_size,
                                prev->my_hash_bucket_size, 64);
    conf->my_hash_bucket_size = ngx_align(conf->my_hash_bucket_size,
                                               ngx_cacheline_size);

    //准备 ngx_hash_init_t 结构体
    hash.key = ngx_hash_key_lc;
    hash.max_size = conf->my_hash_max_size;
    hash.bucket_size = conf->my_hash_bucket_size;
    hash.name = "my_hash";
    hash.pool = cf->pool;

    //初始化普通hash
    if (conf->keys->keys.nelts) {

        hash.hash = &conf->hash.hash;
        hash.temp_pool = NULL;
        
        if (ngx_hash_init(&hash, conf->keys->keys.elts, conf->keys->keys.nelts)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    //初始化前置通配符hash
    if (conf->keys->dns_wc_head.nelts) {

        ngx_qsort(conf->keys->dns_wc_head.elts,
                  (size_t) conf->keys->dns_wc_head.nelts,
                  sizeof(ngx_hash_key_t),
                  ngx_http_cmp_myhash_wildcards);

        hash.hash = NULL;
        hash.temp_pool = cf->temp_pool;

        if (ngx_hash_wildcard_init(&hash, conf->keys->dns_wc_head.elts,
                                   conf->keys->dns_wc_head.nelts)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

        conf->hash.wc_head = (ngx_hash_wildcard_t *) hash.hash;
    }

    //初始化后置通配符hash
    if (conf->keys->dns_wc_tail.nelts) {

        ngx_qsort(conf->keys->dns_wc_tail.elts,
                  (size_t) conf->keys->dns_wc_tail.nelts,
                  sizeof(ngx_hash_key_t),
                  ngx_http_cmp_myhash_wildcards);

        hash.hash = NULL;
        hash.temp_pool = cf->temp_pool;

        if (ngx_hash_wildcard_init(&hash, conf->keys->dns_wc_tail.elts,
                                   conf->keys->dns_wc_tail.nelts)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

        conf->hash.wc_tail = (ngx_hash_wildcard_t *) hash.hash;
    }
    conf->keys = NULL;
    return NGX_CONF_OK;
}

/**
 * content_handler
 */
static ngx_int_t ngx_http_myhash_handler(ngx_http_request_t *r)
{

    ngx_uint_t                 hash;
    ngx_str_t *res;

    ngx_str_t arg_string;
    ngx_http_myhash_conf_t   *rlcf;



    //丢弃请求中的包体
    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK)
    {
        return rc;
    }

    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_myhash_module);


    if (rlcf->hash.hash.buckets == NULL
            && rlcf->hash.wc_head == NULL
            && rlcf->hash.wc_tail == NULL) {

        res = &res_null;

    } else {
        //获取string uri请求参数
        if (ngx_http_arg(r, (u_char *) "string", 6, &arg_string) != NGX_OK) {
            res = &res_no_arg;
        } else {
            //获取到了
            hash = ngx_hash_key_lc(arg_string.data, arg_string.len);

            if (ngx_hash_find_combined(&rlcf->hash, hash, arg_string.data, arg_string.len)) {
                res = &res_hit;
            } else {
                res = &res_not_hit;
            }
        }
    }

    ngx_str_t type = ngx_string("text/plain");
    //设置返回状态码
    r->headers_out.status = NGX_HTTP_OK;
    //响应包是有包体内容的，所以需要设置Content-Length长度
    r->headers_out.content_length_n = res->len;
    //设置Content-Type
    r->headers_out.content_type = type;
    //发送http头部
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)
    {
        return rc;
    }

    //构造ngx_buf_t结构准备发送包体
    ngx_buf_t                 *b;
    b = ngx_create_temp_buf(r->pool, res->len);
    if (b == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    //将Hello World拷贝到ngx_buf_t指向的内存中
    ngx_memcpy(b->pos, res->data, res->len);
    //注意，一定要设置好last指针
    b->last = b->pos + res->len;
    //声明这是最后一块缓冲区
    b->last_buf = 1;

    //构造发送时的ngx_chain_t结构体
    ngx_chain_t		out;
    //赋值ngx_buf_t
    out.buf = b;
    //设置next为NULL
    out.next = NULL;
    //最后一步发送包体，http框架会调用ngx_http_finalize_request方法
    return ngx_http_output_filter(r, &out);
}


static int ngx_libc_cdecl
ngx_http_cmp_myhash_wildcards(const void *one, const void *two)
{
    ngx_hash_key_t  *first, *second;

    first = (ngx_hash_key_t *) one;
    second = (ngx_hash_key_t *) two;

    return ngx_dns_strcmp(first->key.data, second->key.data);
}