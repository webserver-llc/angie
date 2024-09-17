
/*
 * Copyright (C) 2024 Web Server LLC
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


static ngx_fd_t  ngx_daemon_fd = NGX_INVALID_FILE;


ngx_int_t
ngx_daemon(ngx_log_t *log)
{
    u_char    buf[1];
    ssize_t   n;
    ngx_fd_t  fd, pp[2];

    if (pipe(pp) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "pipe() failed");
        return NGX_ERROR;
    }

    switch (fork()) {
    case -1:
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "fork() failed");
        return NGX_ERROR;

    case 0:
        if (close(pp[0]) == -1) {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "close() pipe failed");
            return NGX_ERROR;
        }

        ngx_daemon_fd = pp[1];
        break;

    default:
        if (close(pp[1]) == -1) {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "close() pipe failed");
            return NGX_ERROR;
        }

        n = read(pp[0], buf, 1);

        if (n == 0) {
            /* child exited */
            return NGX_ERROR;
        }

        if (n != 1) {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                          "read() pipe failed");
            return NGX_ERROR;
        }

        if (close(pp[0]) == -1) {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "close() pipe failed");
            return NGX_ERROR;
        }

        exit(0);
    }

    ngx_pid = ngx_getpid();
    ngx_parent = -1;

    if (setsid() == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "setsid() failed");
        return NGX_ERROR;
    }

    umask(0);

    fd = open("/dev/null", O_RDWR);
    if (fd == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "open(\"/dev/null\") failed");
        return NGX_ERROR;
    }

    if (dup2(fd, STDIN_FILENO) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "dup2(STDIN) failed");
        return NGX_ERROR;
    }

    if (dup2(fd, STDOUT_FILENO) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "dup2(STDOUT) failed");
        return NGX_ERROR;
    }

#if 0
    if (dup2(fd, STDERR_FILENO) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "dup2(STDERR) failed");
        return NGX_ERROR;
    }
#endif

    if (fd > STDERR_FILENO) {
        if (close(fd) == -1) {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "close() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_daemon_sync(ngx_log_t *log)
{
    if (ngx_daemon_fd == NGX_INVALID_FILE) {
        return NGX_OK;
    }

    if (write(ngx_daemon_fd, "", 1) != 1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "write() pipe failed");
        return NGX_ERROR;
    }

    if (close(ngx_daemon_fd) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "close() pipe failed");
        return NGX_ERROR;
    }

    ngx_daemon_fd = NGX_INVALID_FILE;

    return NGX_OK;
}
