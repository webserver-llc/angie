
/*
 * Copyright (C) 2022 Web Server LLC
 */


#ifndef _NGX_JSON_H_INCLUDED_
#define _NGX_JSON_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef enum {
    NGX_JSON_OBJ,
    NGX_JSON_ARR
} ngx_json_type_t;


typedef struct {
    u_char           *pos;
    ngx_str_t         desc;
} ngx_json_parse_error_t;


/* JSON string generator state */
typedef struct {
    u_char           *curr;
    u_char           *last;
    ngx_json_type_t   type;
    unsigned          comma:1;
    unsigned          truncated:1;
} ngx_json_escape_t;


ngx_buf_t *ngx_json_render(ngx_pool_t *pool, ngx_data_item_t *item,
    ngx_uint_t is_pretty);

ngx_data_item_t *ngx_json_parse(u_char *start, u_char *end, ngx_pool_t *pool,
    ngx_json_parse_error_t *error);

ngx_data_item_t *ngx_json_parse_first_object(u_char *start, u_char *end,
    u_char **last, ngx_pool_t *pool, ngx_json_parse_error_t *error);


/* JSON strings generation */

ngx_int_t ngx_json_push_key(ngx_json_escape_t *je, const char *key);

ngx_int_t ngx_cdecl ngx_json_push_string(ngx_json_escape_t *je, ngx_str_t *str);
ngx_int_t ngx_cdecl ngx_json_push_string_item(ngx_json_escape_t *je,
    ngx_str_t *str);

ngx_int_t ngx_cdecl ngx_json_push_kv(ngx_json_escape_t *je, ngx_uint_t quote,
    const char *key, const char *fmt, ...);

ngx_int_t ngx_json_vpush_kv(ngx_json_escape_t *je, ngx_uint_t escape_fmt,
    ngx_uint_t quote, const char *key, const char *fmt, va_list args);


static ngx_inline ngx_int_t
ngx_json_start(ngx_json_escape_t *ctx, ngx_json_type_t type, u_char *p,
    u_char *last)
{
    ngx_memzero(ctx, sizeof(ngx_json_escape_t));

    if (last - p < 2) {
        /* impossible to produce even empty object */
        return NGX_ERROR;
    }

    ctx->last = last - 1; /* reserve for terminating symbol */

    ctx->type = type;
    ctx->curr = p;

    switch (type) {

    case NGX_JSON_OBJ:
        *p++ = '{';
        break;

    case NGX_JSON_ARR:
        *p++ = '[';
        break;
    }

    ctx->curr = p;

    return NGX_OK;
}


static ngx_inline u_char*
ngx_json_end(ngx_json_escape_t *ctx)
{
    u_char *p = ctx->curr;

    switch (ctx->type) {
    case NGX_JSON_OBJ:
        *p++ = '}';
        break;

    case NGX_JSON_ARR:
        *p++ = ']';
        break;
    }

    ctx->curr = p;

    return p;
}


#endif /* _NGX_JSON_H_INCLUDED_ */
