
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


#if (NGX_HAVE_ATOMIC_OPS)


static void ngx_shmtx_wakeup(ngx_shmtx_t *mtx);


/**
 * 初始化信号量
 * 
 */
ngx_int_t
ngx_shmtx_create(ngx_shmtx_t *mtx, ngx_shmtx_sh_t *addr, u_char *name)
{
    mtx->lock = &addr->lock;

    if (mtx->spin == (ngx_uint_t) -1) {
        return NGX_OK;
    }

    mtx->spin = 2048;

#if (NGX_HAVE_POSIX_SEM)

    mtx->wait = &addr->wait;

   /**
    * 定义一个sem_t类型的变量后，即可围绕着它使用信号量。使用前，先要调用 sem_init方法初始化信号量
    * int sem_init(sem_t *sem, int pshared, unsigned int value);
    * sem即为定义的信号量
    * pshared将指明sem信号量是用于进程间 同步还是用于线程间同步, 当pshared为0时表示线程间同步，而pshared为1时表示进程间同 步
    * 数value表示信号 量sem的初始值
    * 
    * 最初的信号量sem值为0，调用sem_post方法 将会把sem值加1，这个操作不会有任何阻塞；
    * 调用sem_wait方法将会把信号量sem的值减1， 如果sem值已经小于或等于0了，则阻塞住当前进程（进程会进入睡眠状态），
    * 直到其他进程 将信号量sem的值改变为正数后，这时才能继续通过将sem减1而使得当前进程继续向下执行。
    * 因此，sem_post方法可以实现解锁的功能，而sem_wait方法可以实现加锁的功能
    * 
    * 
    * */ 

    // 信号量 mtx->sem初始化为0，用于进程间通信
    if (sem_init(&mtx->sem, 1, 0) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                      "sem_init() failed");
    } else {
        mtx->semaphore = 1;
    }

#endif

    return NGX_OK;
}


void
ngx_shmtx_destroy(ngx_shmtx_t *mtx)
{
#if (NGX_HAVE_POSIX_SEM)

    if (mtx->semaphore) {
        //销毁信号量
        if (sem_destroy(&mtx->sem) == -1) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                          "sem_destroy() failed");
        }
    }

#endif
}


/**
 * 是一个非阻塞的获取锁的方法。如果成功获取到锁，则返回1，否 则返回0
 */
ngx_uint_t
ngx_shmtx_trylock(ngx_shmtx_t *mtx)
{
    return (*mtx->lock == 0 && ngx_atomic_cmp_set(mtx->lock, 0, ngx_pid));
}


/**
 * 
 * 使用原子变量和信号量来实现ngx_shmtx_t互斥锁, 当Nginx判断当前操作系统支持原子变量时，将会优先使用原子变量
 * 
 */
void
ngx_shmtx_lock(ngx_shmtx_t *mtx)
{
    ngx_uint_t         i, n;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "shmtx lock");

    for ( ;; ) {

        //当lock值为0或者正数时表示没有进程持有锁；当lock值为负 数时表示有进程正持有锁
        if (*mtx->lock == 0 && ngx_atomic_cmp_set(mtx->lock, 0, ngx_pid)) {
            return;
        }

        if (ngx_ncpu > 1) {

            for (n = 1; n < mtx->spin; n <<= 1) {

                for (i = 0; i < n; i++) {
                    ngx_cpu_pause();
                }

                if (*mtx->lock == 0
                    && ngx_atomic_cmp_set(mtx->lock, 0, ngx_pid))
                {
                    return;
                }
            }
        }

#if (NGX_HAVE_POSIX_SEM)

        if (mtx->semaphore) {
            (void) ngx_atomic_fetch_add(mtx->wait, 1);

            if (*mtx->lock == 0 && ngx_atomic_cmp_set(mtx->lock, 0, ngx_pid)) {
                (void) ngx_atomic_fetch_add(mtx->wait, -1);
                return;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                           "shmtx wait %uA", *mtx->wait);

            // 如果没有拿到锁，这时Nginx进程将会睡眠，直到其他进程释放了锁
            while (sem_wait(&mtx->sem) == -1) {
                ngx_err_t  err;

                err = ngx_errno;

                if (err != NGX_EINTR) {
                    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, err,
                                  "sem_wait() failed while waiting on shmtx");
                    break;
                }
            }

            ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                           "shmtx awoke");

            continue;
        }

#endif

        ngx_sched_yield();
    }
}


/**
 * 负责释放锁
 */
void
ngx_shmtx_unlock(ngx_shmtx_t *mtx)
{
    if (mtx->spin != (ngx_uint_t) -1) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "shmtx unlock");
    }

    if (ngx_atomic_cmp_set(mtx->lock, ngx_pid, 0)) {
        ngx_shmtx_wakeup(mtx);
    }
}


ngx_uint_t
ngx_shmtx_force_unlock(ngx_shmtx_t *mtx, ngx_pid_t pid)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "shmtx forced unlock");

    if (ngx_atomic_cmp_set(mtx->lock, pid, 0)) {
        ngx_shmtx_wakeup(mtx);
        return 1;
    }

    return 0;
}


static void
ngx_shmtx_wakeup(ngx_shmtx_t *mtx)
{
#if (NGX_HAVE_POSIX_SEM)
    ngx_atomic_uint_t  wait;

    if (!mtx->semaphore) {
        return;
    }

    for ( ;; ) {

        wait = *mtx->wait;

        if ((ngx_atomic_int_t) wait <= 0) {
            return;
        }

        if (ngx_atomic_cmp_set(mtx->wait, wait, wait - 1)) {
            break;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "shmtx wake %uA", wait);

    // 释放信号量锁时是不会使进程睡眠的
    if (sem_post(&mtx->sem) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                      "sem_post() failed while wake shmtx");
    }

#endif
}


#else

/**
 * 通过文件锁实现, 即通过对fcntl系统调用封装过的ngx_trylock_fd、ngx_lock_fd和ngx_unlock_fd方法实现的锁
 */

//初始化ngx_shmtx_t互斥锁
ngx_int_t
ngx_shmtx_create(ngx_shmtx_t *mtx, ngx_shmtx_sh_t *addr, u_char *name)
{
    // 不用在调用 ngx_shmtx_create方法前先行赋值给 ngx_shmtx_t结构体中的成员
    if (mtx->name) {
        //如果ngx_shmtx_t中的 name成员有值，那么如果与name参数相同，意味着mtx互斥锁已经初始化过了；
        //否则，需要先销毁mtx中的互斥锁再重新分配 mtx
        if (ngx_strcmp(name, mtx->name) == 0) {
            //// 如果 name参数与ngx_shmtx_t中的 name成员相同，则表示已经初始化了
            mtx->name = name;
            return NGX_OK;      //直接返回成功即可
        }

        //如果 ngx_shmtx_t中的 name与参数 name不一致，说明这一次使用了一个新的文件作为文件锁，
        //那么先调用 ngx_shmtx_destory方法销毁原文件锁
        ngx_shmtx_destroy(mtx);
    }

    // 按照 name指定的路径创建并打开这个文件
    mtx->fd = ngx_open_file(name, NGX_FILE_RDWR, NGX_FILE_CREATE_OR_OPEN,
                            NGX_FILE_DEFAULT_ACCESS);

    if (mtx->fd == NGX_INVALID_FILE) {
        // 一旦文件因为各种原因（如权限不够）无法打开，通常会出现无法运行错误
        ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", name);
        return NGX_ERROR;
    }

    //由于只需要这个文件在内核中的 INODE信息，所以可以把文件删除，只要 fd可用就行
    if (ngx_delete_file(name) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                      ngx_delete_file_n " \"%s\" failed", name);
    }

    mtx->name = name;

    return NGX_OK;
}


/**
 * 于关闭在ngx_shmtx_create方法中已经打开的fd句柄
 */
void
ngx_shmtx_destroy(ngx_shmtx_t *mtx)
{
    // 关闭 ngx_shmtx_t结构体中的 fd句柄
    if (ngx_close_file(mtx->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", mtx->name);
    }
}


/**
 * 试图使用非阻塞的方式获得锁，返回1时表示获取锁成功，返回0 表示获取锁失败
 */
ngx_uint_t
ngx_shmtx_trylock(ngx_shmtx_t *mtx)
{
    ngx_err_t  err;

    //ngx_trylock_fd方法实现非阻塞互斥锁的获取
    err = ngx_trylock_fd(mtx->fd);

    if (err == 0) {
        return 1;
    }

    // 如果 err错误码是 NGX_EAGAIN，则表示现在锁已经被其他进程持有了
    if (err == NGX_EAGAIN) {
        return 0;
    }

#if __osf__ /* Tru64 UNIX */

    if (err == NGX_EACCES) {
        return 0;
    }

#endif

    ngx_log_abort(err, ngx_trylock_fd_n " %s failed", mtx->name);

    return 0;
}


/**
 * 会在获取锁失败时阻塞代码的继续执行,它会使当前进程处于睡 眠状态，等待其他进程释放锁后内核唤醒它。
 * 没有返回值，因为它一旦返回就相当于获取到互斥锁了，这会使得代码继续向下执行
 */
void
ngx_shmtx_lock(ngx_shmtx_t *mtx)
{
    ngx_err_t  err;

    // ngx_lock_fd方法返回 0时表示成功地持有锁，返回 -1时表示出现错误
    err = ngx_lock_fd(mtx->fd);

    if (err == 0) {
        return;
    }

    ngx_log_abort(err, ngx_lock_fd_n " %s failed", mtx->name);
}


/**
 * 释放文件锁
 */
void
ngx_shmtx_unlock(ngx_shmtx_t *mtx)
{
    ngx_err_t  err;

    err = ngx_unlock_fd(mtx->fd);

    if (err == 0) {
        return;
    }

    ngx_log_abort(err, ngx_unlock_fd_n " %s failed", mtx->name);
}


ngx_uint_t
ngx_shmtx_force_unlock(ngx_shmtx_t *mtx, ngx_pid_t pid)
{
    return 0;
}

#endif
