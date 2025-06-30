
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_STRING_H_INCLUDED_
#define _NGX_STRING_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    size_t      len;    //len表示字符串的有效长 度
    u_char     *data;   //data指针指向字符串起始地址
} ngx_str_t;


// key-value结构体，用于解析配置文件里的数据
typedef struct {
    ngx_str_t   key;
    ngx_str_t   value;
} ngx_keyval_t;


/**
 * 描述变量值的结构 ngx_http_variable_value_t 等同于此. 类似ngx_str_t, 只是多了一些标识
 */
typedef struct {
    unsigned    len:28;     // 变量值必须是在一段连续内存中的字符串，值的长度就是 len成员

    unsigned    valid:1;    // valid为 1时表示当前这个变量值已经解析过，且数据是可用的
    // no_cacheable为 1时表示变量值不可以被缓存，它与ngx_http_variable_t结构体 flags成员
    // 里的 NGX_HTTP_VAR_NOCACHEABLE标志位是相关的，即设置这个标志位后 no_cacheable就会为 1
    unsigned    no_cacheable:1; 
    unsigned    not_found:1;    // not_found为 1表示当前这个变量值已经解析过，但没有解析到相应的值
    unsigned    escape:1;       // 仅由 ngx_http_log_module模块使用，用于日志格式的字符转义，其他模块通常忽略这个字段

    u_char     *data;           // data就指向变量值所在内存的起始地址，与len成员配合使用
} ngx_variable_value_t;


// 初始化字符串，只能用于初始化，str必须是个字面值
#define ngx_string(str)     { sizeof(str) - 1, (u_char *) str }
// 空字符串
#define ngx_null_string     { 0, NULL }
// 运行时设置字符串，str是指针（地址）
#define ngx_str_set(str, text)                                               \
    (str)->len = sizeof(text) - 1; (str)->data = (u_char *) text
// 把字符串置为空字符串，运行时设置，str是指针
#define ngx_str_null(str)   (str)->len = 0; (str)->data = NULL


// 字符大小写转换
#define ngx_tolower(c)      (u_char) ((c >= 'A' && c <= 'Z') ? (c | 0x20) : c)
#define ngx_toupper(c)      (u_char) ((c >= 'a' && c <= 'z') ? (c & ~0x20) : c)

// 小写化字符串到dst
void ngx_strlow(u_char *dst, u_char *src, size_t n);

/**
 * 用于比较两个字符串的前 n 个字符
 * 返回值:
 * <0：如果 s1 的前 n 个字符按字典序小于 s2。
   0：如果 s1 和 s2 的前 n 个字符完全相同，或者 n 为 0。
   >0：如果 s1 的前 n 个字符按字典序大于 s2。
 */
#define ngx_strncmp(s1, s2, n)  strncmp((const char *) s1, (const char *) s2, n)

/**
 * 按字典序（ASCII 值）比较两个字符串是否相同, 逐字符比较，直到发现不同字符或遇到字符串结束符 '\0'。
 * 调用前需要保证s1与s2长度一致
 */
/* msvc and icc7 compile strcmp() to inline loop */
#define ngx_strcmp(s1, s2)  strcmp((const char *) s1, (const char *) s2)

// 查找子串
#define ngx_strstr(s1, s2)  strstr((const char *) s1, (const char *) s2)

// 字符串长度
#define ngx_strlen(s)       strlen((const char *) s)

// 字符串长度，最多n个字符查找，返回第一个'\0'或者n
size_t ngx_strnlen(u_char *p, size_t n);

//从字符串中查找字符首次出现的位置。成功返回指向字符首次出现的位置char*, 未找到返回NULL
#define ngx_strchr(s1, c)   strchr((const char *) s1, (int) c)

/**
 * 查找字符c出现的位置
 */
static ngx_inline u_char *
ngx_strlchr(u_char *p, u_char *last, u_char c)
{
    while (p < last) {

        if (*p == c) {
            return p;
        }

        p++;
    }

    return NULL;
}


/*
 * msvc and icc7 compile memset() to the inline "rep stos"
 * while ZeroMemory() and bzero() are the calls.
 * icc7 may also inline several mov's of a zeroed register for small blocks.
 */
// 内存清零和设置内存，简单的宏替换
#define ngx_memzero(buf, n)       (void) memset(buf, 0, n)
#define ngx_memset(buf, c, n)     (void) memset(buf, c, n)

// 1.15.7新增，多了memory barrier
void ngx_explicit_memzero(void *buf, size_t n);


// 内存拷贝，应该使用ngx_copy或者ngx_cpymem
// 与c函数memcpy不一样，它返回拷贝后的地址，可以简化连续拷贝内存
#if (NGX_MEMCPY_LIMIT)

void *ngx_memcpy(void *dst, const void *src, size_t n);
#define ngx_cpymem(dst, src, n)   (((u_char *) ngx_memcpy(dst, src, n)) + (n))

#else

/*
 * gcc3, msvc, and icc7 compile memcpy() to the inline "rep movs".
 * gcc3 compiles memcpy(d, s, 4) to the inline "mov"es.
 * icc8 compile memcpy(d, s, 4) to the inline "mov"es or XMM moves.
 */
#define ngx_memcpy(dst, src, n)   (void) memcpy(dst, src, n)
//返回dst的结尾位置
#define ngx_cpymem(dst, src, n)   (((u_char *) memcpy(dst, src, n)) + (n))

#endif


#if ( __INTEL_COMPILER >= 800 )

/*
 * the simple inline cycle copies the variable length strings up to 16
 * bytes faster than icc8 autodetecting _intel_fast_memcpy()
 */

static ngx_inline u_char *
ngx_copy(u_char *dst, u_char *src, size_t len)
{
    if (len < 17) {

        while (len) {
            *dst++ = *src++;
            len--;
        }

        return dst;

    } else {
        return ngx_cpymem(dst, src, len);
    }
}

#else

#define ngx_copy                  ngx_cpymem

#endif


// 内存移动，应该使用ngx_movemem
// 与c函数不一样，它返回移动后的地址，可以简化连续移动内存
#define ngx_memmove(dst, src, n)  (void) memmove(dst, src, n)
//ngx_movemem返回dst的结尾位置
#define ngx_movemem(dst, src, n)  (((u_char *) memmove(dst, src, n)) + (n))


/* msvc and icc7 compile memcmp() to the inline loop */
#define ngx_memcmp(s1, s2, n)     memcmp(s1, s2, n)


// 拷贝字符串
// 保证在末尾添加'\0'
// 与ngx_cpymem一样，返回拷贝后的末尾位置
u_char *ngx_cpystrn(u_char *dst, u_char *src, size_t n);
//在内存池里复制一个新的字符串
u_char *ngx_pstrdup(ngx_pool_t *pool, ngx_str_t *src);
// 字符串格式化,ngx_snprintf/ngx_slprintf较安全，不会缓冲区溢出
// 参数max和last指明了缓冲区的的结束位置，所以格式化的结果只会填满缓冲区为止。
// 函数执行后会返回u_char*指针，指示格式化输出后在buf里的结束位置，可以用这个返回值来判断结果的长度。
u_char * ngx_cdecl ngx_sprintf(u_char *buf, const char *fmt, ...);
u_char * ngx_cdecl ngx_snprintf(u_char *buf, size_t max, const char *fmt, ...);
u_char * ngx_cdecl ngx_slprintf(u_char *buf, u_char *last, const char *fmt,
    ...);
//ngx_sprintf、ngx_snprintf、ngx_slprintf的内部函数，用于不定长参数的函数使用
u_char *ngx_vslprintf(u_char *buf, u_char *last, const char *fmt, va_list args);
#define ngx_vsnprintf(buf, max, fmt, args)                                   \
    ngx_vslprintf(buf, buf + (max), fmt, args)

// 大小写无关比较，s1需要NULL结尾，调用前需要保证s1与s2长度一致
ngx_int_t ngx_strcasecmp(u_char *s1, u_char *s2);
ngx_int_t ngx_strncasecmp(u_char *s1, u_char *s2, size_t n);

// 在len长度里查找子串，类似strstr
u_char *ngx_strnstr(u_char *s1, char *s2, size_t n);

// 已知s2的长度查找子串，n必须是strlen(s2)-1
u_char *ngx_strstrn(u_char *s1, char *s2, size_t n);
//忽略大小写，在s1中搜索子串s2，s1需要NULL结尾，n为s2长度-1
u_char *ngx_strcasestrn(u_char *s1, char *s2, size_t n);
//忽略大小写，在[s1,last]中搜索子串s2，n为s2长度-1
u_char *ngx_strlcasestrn(u_char *s1, u_char *last, u_char *s2, size_t n);

// 反向比较字符串
ngx_int_t ngx_rstrncmp(u_char *s1, u_char *s2, size_t n);
//忽略大小写比对，调用前需要保证s1与s2长度一致
ngx_int_t ngx_rstrncasecmp(u_char *s1, u_char *s2, size_t n);
// 已知长度内存比较
ngx_int_t ngx_memn2cmp(u_char *s1, u_char *s2, size_t n1, size_t n2);
// 比较dns字符串，对-.做特殊处理
ngx_int_t ngx_dns_strcmp(u_char *s1, u_char *s2);
// 比较文件名字符串，且忽略最后的'/'字符， 根据操作系统，选择是否忽略大小写
ngx_int_t ngx_filename_cmp(u_char *s1, u_char *s2, size_t n);

// 字符串转换为数字
// 也可以使用C++11的stoi()或者boost::lexical_cast
ngx_int_t ngx_atoi(u_char *line, size_t n);
ngx_int_t ngx_atofp(u_char *line, size_t n, size_t point);
ssize_t ngx_atosz(u_char *line, size_t n);
off_t ngx_atoof(u_char *line, size_t n);
time_t ngx_atotm(u_char *line, size_t n);
ngx_int_t ngx_hextoi(u_char *line, size_t n);

// 把内存数据dump为16进制字符串
u_char *ngx_hex_dump(u_char *dst, u_char *src, size_t len);

// base64编码解码
#define ngx_base64_encoded_length(len)  (((len + 2) / 3) * 4)
#define ngx_base64_decoded_length(len)  (((len + 3) / 4) * 3)

void ngx_encode_base64(ngx_str_t *dst, ngx_str_t *src);
void ngx_encode_base64url(ngx_str_t *dst, ngx_str_t *src);
ngx_int_t ngx_decode_base64(ngx_str_t *dst, ngx_str_t *src);
ngx_int_t ngx_decode_base64url(ngx_str_t *dst, ngx_str_t *src);

// utf8编码解码
uint32_t ngx_utf8_decode(u_char **p, size_t n);
size_t ngx_utf8_length(u_char *p, size_t n);
u_char *ngx_utf8_cpystrn(u_char *dst, u_char *src, size_t n, size_t len);


// uri编码解码
#define NGX_ESCAPE_URI            0
#define NGX_ESCAPE_ARGS           1
#define NGX_ESCAPE_URI_COMPONENT  2
#define NGX_ESCAPE_HTML           3
#define NGX_ESCAPE_REFRESH        4
#define NGX_ESCAPE_MEMCACHED      5
#define NGX_ESCAPE_MAIL_AUTH      6

#define NGX_UNESCAPE_URI       1
#define NGX_UNESCAPE_REDIRECT  2

uintptr_t ngx_escape_uri(u_char *dst, u_char *src, size_t size,
    ngx_uint_t type);
void ngx_unescape_uri(u_char **dst, u_char **src, size_t size, ngx_uint_t type);
uintptr_t ngx_escape_html(u_char *dst, u_char *src, size_t size);
uintptr_t ngx_escape_json(u_char *dst, u_char *src, size_t size);


// 用于字符串红黑树的节点定义
typedef struct {
    ngx_rbtree_node_t         node;
    ngx_str_t                 str;
} ngx_str_node_t;


// 字符串红黑树专用插入函数
void ngx_str_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);

// 字符串红黑树专门的查找函数
// 注意hash值的类型是uint32_t，所以必须用murmurhash计算，不能用ngx_hash_key
ngx_str_node_t *ngx_str_rbtree_lookup(ngx_rbtree_t *rbtree, ngx_str_t *name,
    uint32_t hash);


void ngx_sort(void *base, size_t n, size_t size,
    ngx_int_t (*cmp)(const void *, const void *));
#define ngx_qsort             qsort


// 预处理字符串化，相当于BOOST_STRINGIZE()
#define ngx_value_helper(n)   #n
#define ngx_value(n)          ngx_value_helper(n)


#endif /* _NGX_STRING_H_INCLUDED_ */
