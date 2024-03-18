
/*
 * Copyright (C) 2022-2024 Web Server LLC
 */


#ifndef _NGX_JSON_H_INCLUDED_
#define _NGX_JSON_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    u_char     *pos;
    ngx_str_t   desc;
} ngx_json_parse_error_t;


ngx_buf_t *ngx_json_render(ngx_pool_t *pool, ngx_data_item_t *item,
    ngx_uint_t is_pretty);

ngx_data_item_t *ngx_json_parse(u_char *start, u_char *end, ngx_pool_t *pool,
    ngx_json_parse_error_t *error);


#endif /* _NGX_JSON_H_INCLUDED_ */
