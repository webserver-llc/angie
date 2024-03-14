
/*
 * Copyright (C) 2022-2024 Web Server LLC
 */


#ifndef _NGX_API_H_INCLUDED_
#define _NGX_API_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_API_NOT_FOUND       1


typedef struct ngx_api_ctx_s    ngx_api_ctx_t;
typedef struct ngx_api_entry_s  ngx_api_entry_t;


struct ngx_api_ctx_s {
    ngx_str_t                   path;
    ngx_connection_t           *connection;
    ngx_pool_t                 *pool;
    ngx_data_item_t            *out;

    unsigned                    pretty:1;
    unsigned                    config_files:1;
    unsigned                    epoch:1;

    ngx_str_t                   orig_path;
    ngx_str_t                   err;
    ngx_str_t                   err_desc;
};


typedef union {
    ngx_api_entry_t            *ents;
    ngx_str_t                  *str;
    ngx_uint_t                  flag;
    int64_t                     num;
    ngx_atomic_t              **atpp;
    ngx_time_t                 *tp;
    size_t                      off;
} ngx_api_entry_data_t;


struct ngx_api_entry_s {
    ngx_str_t                   name;
    ngx_int_t                 (*handler)(ngx_api_entry_data_t data,
                                         ngx_api_ctx_t *actx, void *ctx);
    ngx_api_entry_data_t        data;
};

#define ngx_api_null_entry    { .name = ngx_null_string }

#define ngx_api_is_null(e)    ((e)->name.len == 0)


typedef struct {
    ngx_api_entry_t             entry;
    void                       *ctx;
    void                       *elts;
} ngx_api_iter_ctx_t;

typedef ngx_int_t (*ngx_api_iter_pt)(ngx_api_iter_ctx_t *ictx,
                                     ngx_api_ctx_t *actx);

ngx_int_t ngx_api_object_iterate(ngx_api_iter_pt iter, ngx_api_iter_ctx_t *ictx,
                                 ngx_api_ctx_t *actx);


ngx_int_t ngx_api_object_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
ngx_int_t ngx_api_string_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
ngx_int_t ngx_api_flag_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
ngx_int_t ngx_api_number_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
ngx_int_t ngx_api_time_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
ngx_int_t ngx_api_atomic_pp_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
ngx_int_t ngx_api_struct_str_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
ngx_int_t ngx_api_struct_int_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
ngx_int_t ngx_api_struct_int64_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
ngx_int_t ngx_api_struct_atomic_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);

ngx_api_entry_t *ngx_api_root(ngx_cycle_t *cycle);

ngx_int_t ngx_api_add(ngx_cycle_t *cycle, const char *data,
    ngx_api_entry_t *child);


#endif /* _NGX_API_H_INCLUDED_ */
