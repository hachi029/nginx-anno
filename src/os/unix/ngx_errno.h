
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_ERRNO_H_INCLUDED_
#define _NGX_ERRNO_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


// 重定义unix的错误码类型
typedef int               ngx_err_t;

// 重定义unix错误码
// 较重要的有：
// NGX_EINTR，发生系统中断
// NGX_ENFILE/NGX_EMFILE，系统文件描述符不足
// NGX_EINPROGRESS，发起上游连接，但还没有连接成功，之后调用get option来检测是否成功
// NGX_ETIMEDOUT，超时错误
// NGX_EAGAIN，非阻塞调用专用错误码，未准备好，需重试
#define NGX_EPERM         EPERM     //无权限
#define NGX_ENOENT        ENOENT
#define NGX_ENOPATH       ENOENT
#define NGX_ESRCH         ESRCH     //进程不存在
#define NGX_EINTR         EINTR     //发生了系统中断
#define NGX_ECHILD        ECHILD    //无子进程
#define NGX_ENOMEM        ENOMEM
#define NGX_EACCES        EACCES
#define NGX_EBUSY         EBUSY
#define NGX_EEXIST        EEXIST
#define NGX_EEXIST_FILE   EEXIST
#define NGX_EXDEV         EXDEV
#define NGX_ENOTDIR       ENOTDIR
#define NGX_EISDIR        EISDIR
#define NGX_EINVAL        EINVAL
#define NGX_ENFILE        ENFILE    //系统文件描述符不足
#define NGX_EMFILE        EMFILE    //系统文件描述符不足
#define NGX_ENOSPC        ENOSPC
#define NGX_EPIPE         EPIPE
#define NGX_EINPROGRESS   EINPROGRESS   //已发起连接，但是连接还没建立成功
#define NGX_ENOPROTOOPT   ENOPROTOOPT
#define NGX_EOPNOTSUPP    EOPNOTSUPP
#define NGX_EADDRINUSE    EADDRINUSE    //地址已被占用
#define NGX_ECONNABORTED  ECONNABORTED
#define NGX_ECONNRESET    ECONNRESET    //连接被重置(RST)
#define NGX_ENOTCONN      ENOTCONN
#define NGX_ETIMEDOUT     ETIMEDOUT     //超时
#define NGX_ECONNREFUSED  ECONNREFUSED  //连接被拒绝
#define NGX_ENAMETOOLONG  ENAMETOOLONG
#define NGX_ENETDOWN      ENETDOWN
#define NGX_ENETUNREACH   ENETUNREACH
#define NGX_EHOSTDOWN     EHOSTDOWN
#define NGX_EHOSTUNREACH  EHOSTUNREACH
#define NGX_ENOSYS        ENOSYS
#define NGX_ECANCELED     ECANCELED
#define NGX_EILSEQ        EILSEQ
#define NGX_ENOMOREFILES  0
#define NGX_ELOOP         ELOOP
#define NGX_EBADF         EBADF
#define NGX_EMSGSIZE      EMSGSIZE

#if (NGX_HAVE_OPENAT)
#define NGX_EMLINK        EMLINK
#endif

#if (__hpux__)
#define NGX_EAGAIN        EWOULDBLOCK
#else
//非阻塞调用专用错误码，未准备好，需要重试
#define NGX_EAGAIN        EAGAIN
#endif


// 重命名错误码errno，更清楚
#define ngx_errno                  errno
#define ngx_socket_errno           errno
// 设置错误码的操作
#define ngx_set_errno(err)         errno = err
#define ngx_set_socket_errno(err)  errno = err


u_char *ngx_strerror(ngx_err_t err, u_char *errstr, size_t size);
ngx_int_t ngx_strerror_init(void);


#endif /* _NGX_ERRNO_H_INCLUDED_ */
