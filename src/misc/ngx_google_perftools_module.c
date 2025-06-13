
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>

/*
 * declare Profiler interface here because
 * <google/profiler.h> is C++ header file
 */

int ProfilerStart(u_char* fname);
void ProfilerStop(void);
void ProfilerRegisterThread(void);


/**
 * https://nginx.org/en/docs/ngx_google_perftools_module.html#google_perftools_profiles
 * 
 * This module requires the gperftools library.
 * 
 * 这个模块只是在init-worker时，根据配置调用ProfilerStart
 * 
 * 只有一个配置项， profile文件输出位置
 */
static void *ngx_google_perftools_create_conf(ngx_cycle_t *cycle);
static ngx_int_t ngx_google_perftools_worker(ngx_cycle_t *cycle);


typedef struct {
    ngx_str_t  profiles;        // profile文件输出位置 /path/to/profile
} ngx_google_perftools_conf_t;


static ngx_command_t  ngx_google_perftools_commands[] = {

    //Profiles will be stored as /path/to/profile.<worker_pid>.
    //google_perftools_profiles /path/to/profile;
    { ngx_string("google_perftools_profiles"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_google_perftools_conf_t, profiles),
      NULL },

      ngx_null_command
};


/**
 * 核心模块
 */
static ngx_core_module_t  ngx_google_perftools_module_ctx = {
    ngx_string("google_perftools"),
    ngx_google_perftools_create_conf,       //创建配置结构体
    NULL
};


ngx_module_t  ngx_google_perftools_module = {
    NGX_MODULE_V1,
    &ngx_google_perftools_module_ctx,      /* module context */
    ngx_google_perftools_commands,         /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_google_perftools_worker,           /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

/**
 * 创建配置结构体
 */
static void *
ngx_google_perftools_create_conf(ngx_cycle_t *cycle)
{
    ngx_google_perftools_conf_t  *gptcf;

    gptcf = ngx_pcalloc(cycle->pool, sizeof(ngx_google_perftools_conf_t));
    if (gptcf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc()
     *
     *     gptcf->profiles = { 0, NULL };
     */

    return gptcf;
}


/**
 * init_worker阶段
 */
static ngx_int_t
ngx_google_perftools_worker(ngx_cycle_t *cycle)
{
    u_char                       *profile;
    ngx_google_perftools_conf_t  *gptcf;

    gptcf = (ngx_google_perftools_conf_t *)
                ngx_get_conf(cycle->conf_ctx, ngx_google_perftools_module);

    //没开启
    if (gptcf->profiles.len == 0) {
        return NGX_OK;
    }

    profile = ngx_alloc(gptcf->profiles.len + NGX_INT_T_LEN + 2, cycle->log);
    if (profile == NULL) {
        return NGX_OK;
    }

    if (getenv("CPUPROFILE")) {
        /* disable inherited Profiler enabled in master process */
        ProfilerStop();
    }

    // /path/to/profile.<worker_pid>.
    ngx_sprintf(profile, "%V.%d%Z", &gptcf->profiles, ngx_pid);

    if (ProfilerStart(profile)) {
        /* start ITIMER_PROF timer */
        ProfilerRegisterThread();

    } else {
        ngx_log_error(NGX_LOG_CRIT, cycle->log, ngx_errno,
                      "ProfilerStart(%s) failed", profile);
    }

    ngx_free(profile);

    return NGX_OK;
}


/* ProfilerStop() is called on Profiler destruction */
