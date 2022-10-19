
/*
 * Copyright (C) 2022 Web Server LLC
 */


#ifndef _NGX_JSON_H_INCLUDED_
#define _NGX_JSON_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


ngx_buf_t *ngx_json_render(ngx_pool_t *pool, ngx_data_item_t *item,
    ngx_uint_t is_pretty);


#endif /* _NGX_JSON_H_INCLUDED_ */
