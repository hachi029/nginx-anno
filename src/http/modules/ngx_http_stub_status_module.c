
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/**
 * https://nginx.org/en/docs/http/ngx_http_stub_status_module.html
 * 定义了4个变量，注册了一个content_handler
 */

static ngx_int_t ngx_http_stub_status_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_stub_status_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_stub_status_add_variables(ngx_conf_t *cf);
static char *ngx_http_set_stub_status(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_status_commands[] = {

    { ngx_string("stub_status"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS|NGX_CONF_TAKE1,
      ngx_http_set_stub_status, //注册content_handler
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_stub_status_module_ctx = {
    ngx_http_stub_status_add_variables,    /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_stub_status_module = {
    NGX_MODULE_V1,
    &ngx_http_stub_status_module_ctx,      /* module context */
    ngx_http_status_commands,              /* module directives */
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


static ngx_http_variable_t  ngx_http_stub_status_vars[] = {

    { ngx_string("connections_active"), NULL, ngx_http_stub_status_variable,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("connections_reading"), NULL, ngx_http_stub_status_variable,
      1, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("connections_writing"), NULL, ngx_http_stub_status_variable,
      2, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("connections_waiting"), NULL, ngx_http_stub_status_variable,
      3, NGX_HTTP_VAR_NOCACHEABLE, 0 },

      ngx_http_null_variable
};


//content_handler
static ngx_int_t
ngx_http_stub_status_handler(ngx_http_request_t *r)
{
    size_t             size;
    ngx_int_t          rc;
    ngx_buf_t         *b;
    ngx_chain_t        out;
    ngx_atomic_int_t   ap, hn, ac, rq, rd, wr, wa;

    //只允许GET/HEAD
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    // 不需要请求体
    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    //设置content_type
    r->headers_out.content_type_len = sizeof("text/plain") - 1;
    ngx_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.content_type_lowcase = NULL;

    //计算响应体size
    size = sizeof("Active connections:  \n") + NGX_ATOMIC_T_LEN
           + sizeof("server accepts handled requests\n") - 1
           + 6 + 3 * NGX_ATOMIC_T_LEN
           + sizeof("Reading:  Writing:  Waiting:  \n") + 3 * NGX_ATOMIC_T_LEN;

    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    //几个变量是ngx_event.c定义的全局外部变量
    ap = *ngx_stat_accepted;
    hn = *ngx_stat_handled;
    ac = *ngx_stat_active;
    rq = *ngx_stat_requests;
    rd = *ngx_stat_reading;
    wr = *ngx_stat_writing;
    wa = *ngx_stat_waiting;

    b->last = ngx_sprintf(b->last, "Active connections: %uA \n", ac);

    b->last = ngx_cpymem(b->last, "server accepts handled requests\n",
                         sizeof("server accepts handled requests\n") - 1);

    b->last = ngx_sprintf(b->last, " %uA %uA %uA \n", ap, hn, rq);

    b->last = ngx_sprintf(b->last, "Reading: %uA Writing: %uA Waiting: %uA \n",
                          rd, wr, wa);

    r->headers_out.status = NGX_HTTP_OK;                    //status=200
    r->headers_out.content_length_n = b->last - b->pos;     //content_length_n

    b->last_buf = (r == r->main) ? 1 : 0;               //主请求，last_buf设为1
    b->last_in_chain = 1;                               

    rc = ngx_http_send_header(r);   //发送响应头

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) { //出错或heade请求
        return rc;
    }

    return ngx_http_output_filter(r, &out); //发送响应体
}

//定义的4个变量的get_handler, 直接读取全局原子变量
static ngx_int_t
ngx_http_stub_status_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char            *p;
    ngx_atomic_int_t   value;

    p = ngx_pnalloc(r->pool, NGX_ATOMIC_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    switch (data) {
    case 0:
        value = *ngx_stat_active;
        break;

    case 1:
        value = *ngx_stat_reading;
        break;

    case 2:
        value = *ngx_stat_writing;
        break;

    case 3:
        value = *ngx_stat_waiting;
        break;

    /* suppress warning */
    default:
        value = 0;
        break;
    }

    v->len = ngx_sprintf(p, "%uA", value) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


/**
 * //定义了4个变量
 * connections_active/connections_reading/connections_writing/connections_waiting
 */
static ngx_int_t
ngx_http_stub_status_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_stub_status_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;  //都是ngx_http_stub_status_variable
        var->data = v->data;    //data为在ngx_http_stub_status_vars数组中的索引
    }

    return NGX_OK;
}


static char *
ngx_http_set_stub_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_stub_status_handler;       //挂载content_handler

    return NGX_CONF_OK;
}
