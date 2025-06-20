
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/**
 * https://nginx.org/en/docs/http/ngx_http_auth_request_module.html
 * 
 * implements client authorization based on the result of a subrequest
 * 
 * If the subrequest returns a 2xx response code, the access is allowed. 
 * If it returns 401 or 403, the access is denied with the corresponding error code
 * 
 * 非默认开启模块
 */

 //本模块的配置结构体
typedef struct {
    ngx_str_t                 uri;      //subrequest 的url
    ngx_array_t              *vars;     //本模块定义的多个变量， 元素类型为ngx_http_auth_request_ctx_t
} ngx_http_auth_request_conf_t;


/**
 * 模块自定义上下文
 */
typedef struct {
    ngx_uint_t                done;         //表示子请求是否结束（在子请求结束回调函数里把这个字段设为1）
    ngx_uint_t                status;       //代表子请求结束的响应状态码（在子请求结束回调函数里设置）
    ngx_http_request_t       *subrequest;   //代表子请求
} ngx_http_auth_request_ctx_t;


/**
 * 代表本模块通过auth_request_set  设置的多个变量
 */
typedef struct {
    ngx_int_t                 index;        //变量index
    ngx_http_complex_value_t  value;        //变量值
    ngx_http_set_variable_pt  set_handler;  //set_handler
} ngx_http_auth_request_variable_t;


static ngx_int_t ngx_http_auth_request_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_request_done(ngx_http_request_t *r,
    void *data, ngx_int_t rc);
static ngx_int_t ngx_http_auth_request_set_variables(ngx_http_request_t *r,
    ngx_http_auth_request_conf_t *arcf, ngx_http_auth_request_ctx_t *ctx);
static ngx_int_t ngx_http_auth_request_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void *ngx_http_auth_request_create_conf(ngx_conf_t *cf);
static char *ngx_http_auth_request_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_auth_request_init(ngx_conf_t *cf);
static char *ngx_http_auth_request(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_auth_request_set(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_auth_request_commands[] = {

    { ngx_string("auth_request"),   //是否开启，以及subrequest的url
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_auth_request,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_request_set"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_auth_request_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_auth_request_module_ctx = {
    NULL,                                  /* preconfiguration */
    //  注册 ACCESS_PHASE阶段的handler
    ngx_http_auth_request_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_auth_request_create_conf,     /* create location configuration */
    ngx_http_auth_request_merge_conf       /* merge location configuration */
};


ngx_module_t  ngx_http_auth_request_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_request_module_ctx,     /* module context */
    ngx_http_auth_request_commands,        /* module directives */
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
 * Access 阶段的 handler
 */
static ngx_int_t
ngx_http_auth_request_handler(ngx_http_request_t *r)
{
    ngx_table_elt_t               *h, *ho, **ph;
    ngx_http_request_t            *sr;
    ngx_http_post_subrequest_t    *ps;
    ngx_http_auth_request_ctx_t   *ctx;
    ngx_http_auth_request_conf_t  *arcf;

    arcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_request_module);

    if (arcf->uri.len == 0) {       //未启用， auth_request off；
        return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth request handler");

    //获取模块上下文
    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_request_module);

    if (ctx != NULL) {
        if (!ctx->done) {       //子请求未结束
            return NGX_AGAIN;
        }

        /*
         * as soon as we are done - explicitly set variables to make
         * sure they will be available after internal redirects
         */

        if (ngx_http_auth_request_set_variables(r, arcf, ctx) != NGX_OK) {
            return NGX_ERROR;
        }

        /* return appropriate status */

        if (ctx->status == NGX_HTTP_FORBIDDEN) {
            return ctx->status;
        }

        if (ctx->status == NGX_HTTP_UNAUTHORIZED) {     //未认证
            sr = ctx->subrequest;

            h = sr->headers_out.www_authenticate;       //先尝试获取子请求的响应头 www_authenticate

            if (!h && sr->upstream) {       //在尝试获取子请求upstream的headers_in.www_authenticate
                h = sr->upstream->headers_in.www_authenticate;
            }

            ph = &r->headers_out.www_authenticate;

            //将子请求的响应头 www_authenticate赋值到主请求的响应头
            while (h) {
                ho = ngx_list_push(&r->headers_out.headers);
                if (ho == NULL) {
                    return NGX_ERROR;
                }

                *ho = *h;
                ho->next = NULL;

                *ph = ho;
                ph = &ho->next;

                h = h->next;
            }

            //返回
            return ctx->status;
        }

        if (ctx->status >= NGX_HTTP_OK      //200~300间的状态码
            && ctx->status < NGX_HTTP_SPECIAL_RESPONSE)
        {
            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth request unexpected status: %ui", ctx->status);

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    //创建自定义模块上下文
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_auth_request_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    //创建子请求结构体
    ps = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (ps == NULL) {
        return NGX_ERROR;
    }

    //子请求结束的回调
    ps->handler = ngx_http_auth_request_done;
    ps->data = ctx;

    //创建子请求
    if (ngx_http_subrequest(r, &arcf->uri, NULL, &sr, ps,
                            NGX_HTTP_SUBREQUEST_WAITED)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /*
     * allocate fake request body to avoid attempts to read it and to make
     * sure real body file (if already read) won't be closed by upstream
     */

    //子请求请求体
    sr->request_body = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (sr->request_body == NULL) {
        return NGX_ERROR;
    }

    sr->header_only = 1;    //只读取响应体

    ctx->subrequest = sr;

    ngx_http_set_ctx(r, ctx, ngx_http_auth_request_module);

    return NGX_AGAIN;
}


/**
 * 子请求结束的回调
 */
static ngx_int_t
ngx_http_auth_request_done(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_auth_request_ctx_t   *ctx = data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth request done s:%ui", r->headers_out.status);

    ctx->done = 1;      //标识子请求已经结束
    ctx->status = r->headers_out.status;    //传递子请求的响应码

    return rc;
}


/**
 * 解析本模块定义的所有变量
 */
static ngx_int_t
ngx_http_auth_request_set_variables(ngx_http_request_t *r,
    ngx_http_auth_request_conf_t *arcf, ngx_http_auth_request_ctx_t *ctx)
{
    ngx_str_t                          val;
    ngx_http_variable_t               *v;
    ngx_http_variable_value_t         *vv;
    ngx_http_auth_request_variable_t  *av, *last;
    ngx_http_core_main_conf_t         *cmcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth request set variables");

    if (arcf->vars == NULL) {
        return NGX_OK;
    }

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
    v = cmcf->variables.elts;

    av = arcf->vars->elts;
    last = av + arcf->vars->nelts;

    //遍历本模块定义的所有变量
    while (av < last) {
        /*
         * explicitly set new value to make sure it will be available after
         * internal redirects
         */

        vv = &r->variables[av->index];

        //获取变量值
        if (ngx_http_complex_value(ctx->subrequest, &av->value, &val)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        //vv为解析出来的变量值
        vv->valid = 1;
        vv->not_found = 0;
        vv->data = val.data;
        vv->len = val.len;

        if (av->set_handler) {
            /*
             * set_handler only available in cmcf->variables_keys, so we store
             * it explicitly
             */

            av->set_handler(r, vv, v[av->index].data);
        }

        av++;
    }

    return NGX_OK;
}


/**
 * 本模块定义的变量的get_handler
 */
static ngx_int_t
ngx_http_auth_request_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth request variable");

    v->not_found = 1;

    return NGX_OK;
}


/**
 * 创建模块配置结构体
 */
static void *
ngx_http_auth_request_create_conf(ngx_conf_t *cf)
{
    ngx_http_auth_request_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_request_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->uri = { 0, NULL };
     */

    conf->vars = NGX_CONF_UNSET_PTR;

    return conf;
}


/**
 * 模块配置合并方法
 */
static char *
ngx_http_auth_request_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_auth_request_conf_t *prev = parent;
    ngx_http_auth_request_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->uri, prev->uri, "");
    ngx_conf_merge_ptr_value(conf->vars, prev->vars, NULL);

    return NGX_CONF_OK;
}


/**
 * 注册 ACCESS_PHASE阶段的handler
 */
static ngx_int_t
ngx_http_auth_request_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_request_handler;

    return NGX_OK;
}


/**
 * 配置指令 auth_request 的解析函数
 * 
 * auth_request uri | off;
 */
static char *
ngx_http_auth_request(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_request_conf_t *arcf = conf;

    ngx_str_t        *value;

    if (arcf->uri.data != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {    //未开启
        arcf->uri.len = 0;
        arcf->uri.data = (u_char *) "";

        return NGX_CONF_OK;
    }

    arcf->uri = value[1];

    return NGX_CONF_OK;
}


/**
 * 解析配置指令 auth_request_set $variable value;
 * 
 * Sets the request variable to the given value after the authorization request completes
 */
static char *
ngx_http_auth_request_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_request_conf_t *arcf = conf;

    ngx_str_t                         *value;
    ngx_http_variable_t               *v;
    ngx_http_auth_request_variable_t  *av;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (value[1].data[0] != '$') {      //错误的格式
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    //去除$符号
    value[1].len--;
    value[1].data++;

    if (arcf->vars == NGX_CONF_UNSET_PTR) {     //是一个数组，可以配置多条这个指令，即定义多个变量
        arcf->vars = ngx_array_create(cf->pool, 1,
                                      sizeof(ngx_http_auth_request_variable_t));
        if (arcf->vars == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    av = ngx_array_push(arcf->vars);
    if (av == NULL) {
        return NGX_CONF_ERROR;
    }

    //注册变量 &value[1]为变量名， flag: changeable, 相同变量可以重复定义
    v = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_CHANGEABLE);
    if (v == NULL) {
        return NGX_CONF_ERROR;
    }

    //获取变量索引
    av->index = ngx_http_get_variable_index(cf, &value[1]);
    if (av->index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    if (v->get_handler == NULL) {
        //这个get_handler直接返回not_found
        v->get_handler = ngx_http_auth_request_variable;
        v->data = (uintptr_t) av;
    }

    av->set_handler = v->set_handler;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &av->value;

    //编译复杂变量
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
