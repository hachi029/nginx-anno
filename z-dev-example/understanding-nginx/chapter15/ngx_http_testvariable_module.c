#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    // 变量 variable的索引值
    int variable_index;
    // myallow配置后第 1个参数，表示待处理变量名
    ngx_str_t variable;
    // myallow配置后第 2个参数，表示变量值必须为equalvalue才能放行请求
    ngx_str_t equalvalue;
} ngx_myallow_loc_conf_t;

static void *ngx_http_mytest_create_loc_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_mytest_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_mytest_init(ngx_conf_t *cf);
static char * ngx_http_myallow(ngx_conf_t *cf, ngx_command_t * cmd, void * conf);

static ngx_str_t new_varaible_is_chome = ngx_string("is_chrome");

//preconfiguration阶段定义变量
static ngx_int_t ngx_http_mytest_add_variable(ngx_conf_t *cf);


/**
 * 示例内部变量的使用
 * 当请求命中location，必须根据配置项myallow指定的变量及其判定值来决定请求是否被允许。
 * 比如，myallow $http_testHeader xxx; 请求必须具备testHeader:xxx这样的http头部才能放行;
 *      myallow $remote_addr 10.69.50.199 则必须来自于IP 10.69.50.199才能放行，
 * 只要是Nginx定义的内部变量都可以放在myallow中.
 */

static ngx_command_t ngx_http_testvariable_commands[] =
{
    {
        ngx_string("myallow"), // 配置项只能存在于 location内，且只能有 2个参数
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
        ngx_http_myallow,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_testvariable_module_ctx = {
    ngx_http_mytest_add_variable, /* preconfiguration */
    // 解析配置完毕后会回调  ngx_http_mytest_init   NGX_HTTP_ACCESS_PHASE 阶段安装handler
    ngx_http_mytest_init, /* postconfiguration */
    // myallow配置不能存在于 http{}和server{}配置下，所以通常下面这 4个回调方法不用实现
    NULL, /* create main configuration */
    NULL, /* init main configuration */
    NULL, /* create server configuration */
    NULL, /* merge server configuration */
    ngx_http_mytest_create_loc_conf,    // 生成存放 location下 myallow配置的结构体
    /* create location configuration */
    // 因为不存在合并不同级别下冲突的配置项的需求，所以不需要 merge方法
    NULL /* merge location configuration */
};

/**
 * 模块定义
 */
ngx_module_t  ngx_http_testvariable_module =
{
    NGX_MODULE_V1,
    &ngx_http_testvariable_module_ctx,     /* module context */
    ngx_http_testvariable_commands,        /* module directives */
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
 * 解析变量
 */
static ngx_int_t ngx_http_ischrome_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) 
{ 
    // 实际上 r->headers_in.chrome已经根据 user_agent头部解析过请求是否来自于 chrome浏览器 
    if (r->headers_in.chrome) { 
        *v = ngx_http_variable_true_value; 
        return NGX_OK;
    } 
    *v = ngx_http_variable_null_value; 
    return NGX_OK; 
}


static ngx_int_t ngx_http_mytest_add_variable(ngx_conf_t *cf) 
{ 
    ngx_http_variable_t *v; 
    // 添加变量 
    v = ngx_http_add_variable(cf, &new_varaible_is_chome, NGX_HTTP_VAR_CHANGEABLE); 
    if (v == NULL) { 
        return NGX_ERROR; 
    } 
    // 如果 is_chrome这个变量没有被添加过，那么 get_handler就是 NULL空指针 
    v->get_handler = ngx_http_ischrome_variable; 
    // 这里的data成员没有使用价值，故设为 0 
    v->data = 0; 
    return NGX_OK; 
}



/**
 * 生成存放 location下 myallow配置的结构体
 */
static void *
ngx_http_mytest_create_loc_conf(ngx_conf_t *cf)
{
    ngx_myallow_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_myallow_loc_conf_t));
    if (conf == NULL){
        return NULL;
    }

    // 没有出现 myallow配置时 variable_index成员为 -1 conf->variable_index = -1;
    return conf;
}

/**
 * 处理请求， access阶段
 */
static ngx_int_t
ngx_http_mytest_handler(ngx_http_request_t *r)
{
    ngx_myallow_loc_conf_t *conf;
    ngx_http_variable_value_t *vv; 
    
    // 先取到当前location下本模块的配置项存储结构体
    conf = ngx_http_get_module_loc_conf(r, ngx_http_testvariable_module);
    if (conf == NULL){
        return NGX_ERROR;
    } 
    
    // 如果 location下没有 myallow配置项，放行请求
    if (conf->variable_index == -1) {
        return NGX_DECLINED;
    } 
    
    // 根据索引过的 variable_index下标，快速取得变量值 vv
    vv = ngx_http_get_indexed_variable(r, conf->variable_index);
    if (vv == NULL || vv->not_found) {
        return NGX_HTTP_FORBIDDEN;
    } 
    
    // 比较变量值是否与 conf->equalvalue相同，完全相同才会放行请求
    if (vv->len == conf->equalvalue.len && 0 == ngx_strncmp(conf->equalvalue.data, vv->data, vv->len)) {
        return NGX_DECLINED;
    } 
    
    // 否则，返回 403拒绝请求继续向下执行
    return NGX_HTTP_FORBIDDEN;
}

/**
 * NGX_HTTP_ACCESS_PHASE 阶段安装handler
 * 
 * 因为需要控制请求的访问权限，加入到 NGX_HTTP_ACCESS_PHASE阶段中
 */
static ngx_int_t
ngx_http_mytest_init(ngx_conf_t *cf){

    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;
    
    // 取出全局唯一的核心结构体 ngx_http_core_main_conf_t
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    
    // 在 cmcf->phases[NGX_HTTP_ACCESS_PHASE]阶段添加处理方法
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    // 处理请求的方法是本模块的 ngx_http_mytest_handler方法
    *h = ngx_http_mytest_handler;
    
    return NGX_OK;
}

/**
 * 没有使用标准的解析方法，而是自定义的方法解析配置指令
 *  指令格式：myallow $http_testHeader xxx;
 */
static char * 
ngx_http_myallow(ngx_conf_t *cf, ngx_command_t * cmd, void * conf){
    ngx_str_t *value;
    ngx_myallow_loc_conf_t *macf = conf;        //conf为自定义配置结构
    
    value = cf->args->elts; 
    
    // myallow只会有2个参数，加上其自身， cf->args应有3个成员
    if (cf->args->nelts != 3) {
        return NGX_CONF_ERROR;
    }
    
    // 第 1个参数必须是$打头的字符串
    if (value[1].data[0] == '$') { 
        // 去除第 1个$字符后， value[1]就是变量名
        value[1].len--;
        value[1].data++; 
        
        // 获取变量名在 Nginx中的索引值，加速访问
        macf->variable_index = ngx_http_get_variable_index(cf, &value[1]);
        
        if (macf->variable_index == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }
        
        macf->variable = value[1];
    } else {
        return NGX_CONF_ERROR;
    } 
    
    // 保存 myallow的第2个参数
    macf->equalvalue = value[2];
    
    return NGX_CONF_OK;
};