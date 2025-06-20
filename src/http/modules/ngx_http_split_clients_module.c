
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */



/**
 * 创建用于AB测试的变量
 * 
 * split_clients "${remote_addr}AAA" $variant {
               0.5%               .one;
               2.0%               .two;
               *                  "";
    }

    对${remote_addr}AAA 值进行MurmurHash2， hash结果0.5% ， $variant=.one
    2.0% .two
 * 
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    uint32_t                    percent;        //比率，如果是*， 比例为0
    ngx_http_variable_value_t   value;          //比率值
} ngx_http_split_clients_part_t;


typedef struct {
    //split_clients 配置指令中配置的复杂变量，运行时获取值，对其进行hash,hash结果按比例设置变量的不值
    ngx_http_complex_value_t    value;
    ngx_array_t                 parts;      //split_clients配置指令配置的多个变量值，元素类型为ngx_http_split_clients_part_t
} ngx_http_split_clients_ctx_t;


static char *ngx_conf_split_clients_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_split_clients(ngx_conf_t *cf, ngx_command_t *dummy,
    void *conf);

static ngx_command_t  ngx_http_split_clients_commands[] = {

    { ngx_string("split_clients"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE2,
      ngx_conf_split_clients_block,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_split_clients_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_split_clients_module = {
    NGX_MODULE_V1,
    &ngx_http_split_clients_module_ctx,    /* module context */
    ngx_http_split_clients_commands,       /* module directives */
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
 * A/B test变量值的get_handler
 */
static ngx_int_t
ngx_http_split_clients_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_split_clients_ctx_t *ctx = (ngx_http_split_clients_ctx_t *) data;

    uint32_t                        hash;
    ngx_str_t                       val;
    ngx_uint_t                      i;
    ngx_http_split_clients_part_t  *part;

    *v = ngx_http_variable_null_value;

    //计算复杂变量值
    if (ngx_http_complex_value(r, &ctx->value, &val) != NGX_OK) {
        return NGX_OK;
    }

    //hash
    hash = ngx_murmur_hash2(val.data, val.len);

    part = ctx->parts.elts;

    for (i = 0; i < ctx->parts.nelts; i++) {

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http split: %uD %uD", hash, part[i].percent);

        if (hash < part[i].percent || part[i].percent == 0) {
            *v = part[i].value;
            return NGX_OK;
        }
    }

    return NGX_OK;
}


/**
 * split_clients 配置指令解析
 * 
 * split_clients "${remote_addr}AAA" $variant {
               0.5%               .one;
               2.0%               .two;
               *                  "";
  }
 */
static char *
ngx_conf_split_clients_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                                *rv;
    uint32_t                             sum, last;
    ngx_str_t                           *value, name;
    ngx_uint_t                           i;
    ngx_conf_t                           save;
    ngx_http_variable_t                 *var;
    ngx_http_split_clients_ctx_t        *ctx;
    ngx_http_split_clients_part_t       *part;
    ngx_http_compile_complex_value_t     ccv;

    //创建一个ngx_http_split_clients_ctx_t结构体
    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_split_clients_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &ctx->value;

    //编译复杂变量
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    //要创建的变量名称
    name = value[2];

    if (name.data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &name);
        return NGX_CONF_ERROR;
    }

    name.len--;
    name.data++;

    //注册变量
    var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    //设置get_handler
    var->get_handler = ngx_http_split_clients_variable;
    var->data = (uintptr_t) ctx;

    //存放{}里的配置的每一行
    if (ngx_array_init(&ctx->parts, cf->pool, 2,
                       sizeof(ngx_http_split_clients_part_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    save = *cf;
    cf->ctx = ctx;
    cf->handler = ngx_http_split_clients;
    cf->handler_conf = conf;

    //解析{}里的配置,每一行解析为ctx->parts中的一个元素
    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    sum = 0;
    last = 0;
    part = ctx->parts.elts;

    for (i = 0; i < ctx->parts.nelts; i++) {
        //这里可以约束*必定位于{}中的最后一行
        sum = part[i].percent ? sum + part[i].percent : 10000;
        //总和不能超过10000
        if (sum > 10000) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "percent total is greater than 100%%");
            return NGX_CONF_ERROR;
        }

        //计算每一行的之前的累加percent
        if (part[i].percent) {
            last += part[i].percent * (uint64_t) 0xffffffff / 10000;
            part[i].percent = last;
        }
    }

    return rv;
}


/**
 * 解析split_clients配置指令 中的{}部分中的一行
 * 
 * split_clients "${remote_addr}AAA" $variant {
               0.5%               .one;
               2.0%               .two;
               *                  "";
    }
 */
static char *
ngx_http_split_clients(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    ngx_int_t                       n;
    ngx_str_t                      *value;
    ngx_http_split_clients_ctx_t   *ctx;
    ngx_http_split_clients_part_t  *part;

    ctx = cf->ctx;
    value = cf->args->elts;

    //创建一个ngx_http_split_clients_part_t元素
    part = ngx_array_push(&ctx->parts);
    if (part == NULL) {
        return NGX_CONF_ERROR;
    }

    //如果是*
    if (value[0].len == 1 && value[0].data[0] == '*') {
        part->percent = 0;

    } else {
        //如果为空或不是一个%数值，则为无效
        if (value[0].len == 0 || value[0].data[value[0].len - 1] != '%') {
            goto invalid;
        }

        //转为整数 10.5% --> 1050
        n = ngx_atofp(value[0].data, value[0].len - 1, 2);
        if (n == NGX_ERROR || n == 0) {
            goto invalid;
        }

        //记录比值
        part->percent = (uint32_t) n;
    }

    part->value.len = value[1].len;
    part->value.valid = 1;
    part->value.no_cacheable = 0;
    part->value.not_found = 0;
    part->value.data = value[1].data;

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid percent value \"%V\"", &value[0]);
    return NGX_CONF_ERROR;
}
