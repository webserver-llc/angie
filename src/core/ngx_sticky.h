
/*
 * Copyright (C) 2025 Web Server LLC
 */


#ifndef _NGX_STICKY_H_INCLUDED_
#define _NGX_STICKY_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_md5.h>


#define NGX_STICKY_SID_LEN  32


typedef union {
    u_char                md5[16];
    ngx_uint_t            hash;
} ngx_md5_key_t;


typedef struct {
    ngx_msec_t            last;                    /* last use time, msec */
    ngx_md5_key_t         key;                     /* hashed session id */
    u_char                sid[NGX_STICKY_SID_LEN]; /* keeps result from shm */
#if (NGX_DEBUG)
    ngx_str_t             id;                      /* session id as text */
#endif
} ngx_sticky_sess_t;


/*
 * creates new shared memory zone for sticky sessions named 'name' with
 * size 'size' in the context of module 'mod' tied with upstream 'host'.
 * sessions have 'timeout' ttl and 'refresh' controls last use update
 */
ngx_shm_zone_t *ngx_sticky_learn_create_zone(ngx_conf_t *cf, ngx_str_t *name,
    size_t size, ngx_str_t *host, ngx_msec_t timeout, ngx_uint_t refresh,
    ngx_module_t *mod);

/* start managing the zone */
void ngx_sticky_start(ngx_shm_zone_t *lz);

/*
 * performs lookup in the shared memory zone 'lz' using the key 'sk'
 * and saves result into 'res' if found.
 * returns NGX_OK if found and NGX_DECLINED otherwise
 */
ngx_int_t ngx_sticky_learn_lookup(ngx_shm_zone_t *lz, ngx_sticky_sess_t *sk,
    ngx_str_t *res);

/*
 * creates or updates session with key 'sk' in the shared memory zone 'lz'
 * with the value 'sid'. If 'create' is 0, updates last use if found.
 */
void ngx_sticky_learn_set_session(ngx_shm_zone_t *lz,
    ngx_sticky_sess_t *learn_sess, ngx_str_t *sid, ngx_uint_t create);

#define ngx_sticky_learn_session(lz, ls, sid) \
    ngx_sticky_learn_set_session(lz, ls, sid, 1)

#define ngx_sticky_learn_update_session(lz, ls, sid) \
    ngx_sticky_learn_set_session(lz, ls, sid, 0)


static ngx_inline void
ngx_sticky_learn_init_sess(ngx_sticky_sess_t *sk, ngx_str_t *hint,
    ngx_uint_t set_last)
{
    ngx_md5_t    md5;
    ngx_msec_t   now;
    ngx_time_t  *tp;

    if (set_last) {
        tp = ngx_timeofday();
        now = tp->sec * 1000 + tp->msec;
        sk->last = now;
    }

#if (NGX_DEBUG)
    sk->id = *hint;
#endif

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, hint->data, hint->len);
    ngx_md5_final(sk->key.md5, &md5);
}


static ngx_inline size_t
ngx_sticky_hash(ngx_str_t *in, ngx_str_t *salt, u_char *out)
{
    ngx_md5_t  md5;
    u_char     hash[16];

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, in->data, in->len);
    ngx_md5_update(&md5, salt->data, salt->len);
    ngx_md5_final(hash, &md5);

    ngx_hex_dump(out, hash, 16);

    return 32;
}

#endif /* _NGX_STICKY_H_INCLUDED_ */
