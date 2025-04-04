
/*
 * Copyright (C) 2025 Web Server LLC
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


#if (NGX_HAVE_MAP_ANON)

ngx_int_t
ngx_shm_alloc(ngx_shm_t *shm)
{
    int    flags;
    void  *addr;

    addr = shm->addr;
    flags = MAP_ANON|MAP_SHARED;

    if (addr) {
#if (NGX_HAVE_MAP_FIXED_NOREPLACE)
        flags |= MAP_FIXED_NOREPLACE;
#elif (NGX_HAVE_MAP_FIXED_EXCL)
        flags |= MAP_FIXED|MAP_EXCL;
#else
        ngx_log_error(NGX_LOG_ALERT, shm->log, 0,
                      "Angie was built without support for  "
                      "allocations at fixed address");
        return NGX_ERROR;
#endif
    }

    shm->addr = (u_char *) mmap(addr, shm->size,
                                PROT_READ|PROT_WRITE, flags, -1, 0);

    if (shm->addr == MAP_FAILED) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                      "mmap(MAP_ANON|MAP_SHARED, %uz) failed", shm->size);
        return NGX_ERROR;
    }

    if (addr && shm->addr != addr) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, 0,
                      "failed to restore zone at address %p, size %uz",
                      addr, shm->size);
        return NGX_ERROR;
    }

    return NGX_OK;
}


void
ngx_shm_free(ngx_shm_t *shm)
{
    if (munmap((void *) shm->addr, shm->size) == -1) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                      "munmap(%p, %uz) failed", shm->addr, shm->size);
    }
}

#elif (NGX_HAVE_MAP_DEVZERO)

ngx_int_t
ngx_shm_alloc(ngx_shm_t *shm)
{
    int        flags;
    void      *addr;
    ngx_fd_t   fd;

    fd = open("/dev/zero", O_RDWR);

    if (fd == -1) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                      "open(\"/dev/zero\") failed");
        return NGX_ERROR;
    }

    addr = shm->addr;
    flags = MAP_ANON|MAP_SHARED;

    if (addr) {
#if (NGX_HAVE_MAP_FIXED_NOREPLACE)
        flags |= MAP_FIXED_NOREPLACE;
#elif (NGX_HAVE_MAP_FIXED_EXCL)
        flags |= MAP_FIXED|MAP_EXCL;
#else
        ngx_log_error(NGX_LOG_ALERT, shm->log, 0,
                      "Angie was built without support for  "
                      "allocations at fixed address");
        return NGX_ERROR;
#endif
    }

    shm->addr = (u_char *) mmap(addr, shm->size, PROT_READ|PROT_WRITE,
                                flags, fd, 0);

    if (shm->addr == MAP_FAILED) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                      "mmap(/dev/zero, MAP_SHARED, %uz) failed", shm->size);
    }

    if (close(fd) == -1) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                      "close(\"/dev/zero\") failed");
    }

    if (addr && shm->addr != addr) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, 0,
                      "failed to restore zone at address %p, size %uz",
                      addr, shm->size);
        return NGX_ERROR;
    }

    return (shm->addr == MAP_FAILED) ? NGX_ERROR : NGX_OK;
}


void
ngx_shm_free(ngx_shm_t *shm)
{
    if (munmap((void *) shm->addr, shm->size) == -1) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                      "munmap(%p, %uz) failed", shm->addr, shm->size);
    }
}

#elif (NGX_HAVE_SYSVSHM)

#include <sys/ipc.h>
#include <sys/shm.h>


ngx_int_t
ngx_shm_alloc(ngx_shm_t *shm)
{
    int    id;
    void  *addr;

    addr = shm->addr;

    id = shmget(IPC_PRIVATE, shm->size, (SHM_R|SHM_W|IPC_CREAT));

    if (id == -1) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                      "shmget(%uz) failed", shm->size);
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, shm->log, 0, "shmget id: %d", id);

    shm->addr = shmat(id, addr, 0);

    if (shm->addr == (void *) -1) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno, "shmat() failed");
    }

    if (addr && shm->addr != addr) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, 0,
                      "failed to restore zone at address %p, size %uz",
                      addr, shm->size);
        return NGX_ERROR;
    }

    if (shmctl(id, IPC_RMID, NULL) == -1) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                      "shmctl(IPC_RMID) failed");
    }

    return (shm->addr == (void *) -1) ? NGX_ERROR : NGX_OK;
}


void
ngx_shm_free(ngx_shm_t *shm)
{
    if (shmdt(shm->addr) == -1) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                      "shmdt(%p) failed", shm->addr);
    }
}

#endif
