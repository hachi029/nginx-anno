#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/**
 * 演示complex_value用法
 */
static ngx_int_t ngx_http_my_script_handler(ngx_http_request_t *r);

static void* ngx_http_my_script_create_loc_conf(ngx_conf_t *cf);

static char *ngx_http_conf_my_script(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

typedef struct {
    ngx_str_t                name;
    ngx_array_t             *lengths;   //复杂变量
    ngx_array_t             *values;    //复杂变量
} ngx_http_my_script_conf_t;


static ngx_command_t  ngx_http_my_script_commands[] = {
    {
        ngx_string("my_script"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_conf_my_script,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    ngx_null_command
};

static ngx_http_module_t  ngx_http_my_script_module_ctx = {
    NULL,                              /* preconfiguration */
    NULL,                              /* postconfiguration */

    NULL,                              /* create main configuration */
    NULL,                              /* init main configuration */

    NULL,                              /* create server configuration */
    NULL,                              /* merge server configuration */

    ngx_http_my_script_create_loc_conf, /* create location configuration */
    NULL   /* merge location configuration */
};

ngx_module_t  ngx_http_my_script_module = {
    NGX_MODULE_V1,
    &ngx_http_my_script_module_ctx,           /* module context */
    ngx_http_my_script_commands,              /* module directives */
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
 * 解析配置 my_script 
 */
static char *
ngx_http_conf_my_script(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    
    ngx_uint_t                               n;
    ngx_str_t                               *value;
    ngx_http_core_loc_conf_t                *clcf;
    ngx_http_my_script_conf_t               *lcf = conf;
    ngx_http_script_compile_t                sc;

    value = cf->args->elts;

    n = ngx_http_script_variables_count(&value[1]);

    if (n == 0) {   //不包含变量
        lcf->name.len = value[1].len;
        lcf->name.data = value[1].data;
    } else {
        sc.cf = cf;
        sc.source = &value[1];
        sc.lengths = &lcf->lengths;
        sc.values =  &lcf->values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        //编译脚本
        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    //注册content_handler
    clcf->handler = ngx_http_my_script_handler;
    return NGX_OK;
}


/**
 * 创建配置结构体
 */
static void* 
ngx_http_my_script_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_my_script_conf_t  *mycf;

    mycf = (ngx_http_my_script_conf_t  *)ngx_pcalloc(cf->pool, sizeof(ngx_http_my_script_conf_t));
    if (mycf == NULL)
    {
        return NULL;
    }

    mycf->lengths = NULL;
    mycf->values = NULL;
    return mycf;
}



/**
 * content_handler
 */
static ngx_int_t ngx_http_my_script_handler(ngx_http_request_t *r)
{

    size_t                        len;
    ngx_str_t                     *res;
    ngx_http_my_script_conf_t    *rlcf;
    ngx_http_script_code_pt       code;
    ngx_http_script_engine_t      e;
    ngx_http_script_len_code_pt   lcode;


    //丢弃请求中的包体
    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK)
    {
        return rc;
    }

    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_my_script_module);


    if (rlcf->lengths == NULL) {
        len = rlcf->name.len;
    } else {
        //也可以使用 ngx_http_script_run方法
        ngx_memzero(&e, sizeof(ngx_http_script_engine_t));
        e.ip = rlcf->lengths->elts;
        e.request = r;
        e.flushed = 1;
            /* 1 is for terminating '\0' as in static names */
        len = 1;

        while (*(uintptr_t *) e.ip) {
            lcode = *(ngx_http_script_len_code_pt *) e.ip;
            len += lcode(&e);
        }
    }

    if (rlcf->values == NULL) {
        res = &rlcf->name;
    } else {
        res = ngx_pnalloc(r->pool, sizeof(ngx_str_t));
        res->data = ngx_pnalloc(r->pool, len);
        res->len = len;
        e.ip = rlcf->values->elts;
        e.pos = res->data;

        while (*(uintptr_t *) e.ip) {
            code = *(ngx_http_script_code_pt *) e.ip;
            code((ngx_http_script_engine_t *) &e);
        }

    }

    //也可以使用下边代码获取值
    // res = ngx_pnalloc(r->pool, sizeof(ngx_str_t));
    // ngx_http_script_run(r, res, rlcf->lengths->elts, 0, rlcf->values->elts);

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
