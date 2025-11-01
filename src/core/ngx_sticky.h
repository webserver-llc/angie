
/*
 * Copyright (C) 2025 Web Server LLC
 */


#ifndef _NGX_STICKY_H_INCLUDED_
#define _NGX_STICKY_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_md5.h>

/*
 * must be the same as NGX_HTTP_UPSTREAM_SID_LEN
 * or NGX_STREAM_UPSTREAM_SID_LEN
 */
#define NGX_STICKY_SID_LEN  32


typedef union {
    u_char                md5[16];
    ngx_uint_t            hash;
} ngx_md5_key_t;


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
