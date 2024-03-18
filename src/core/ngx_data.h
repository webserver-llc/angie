
/*
 * Copyright (C) 2022-2024 Web Server LLC
 */


#ifndef _NGX_DATA_H_INCLUDED_
#define _NGX_DATA_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_data_item_s  ngx_data_item_t;


#define NGX_DATA_MAX_STR        (8 + NGX_PTR_SIZE - 2)
#define NGX_DATA_MAX_STRING     NGX_MAX_UINT32_VALUE


struct ngx_data_item_s {
    ngx_data_item_t            *next;

    union {
        ngx_uint_t              boolean;  /* unsigned  boolean:1 */
        int64_t                 integer;

        struct {
            u_char              start[NGX_DATA_MAX_STR];
            uint8_t             length;
        } str;

        struct {
            u_char             *start;
            uint32_t            length;
        } ngx_packed string;

        ngx_data_item_t        *child;
    } ngx_packed data;

    uint8_t                     type;     /* unsigned  type:3 */
};


ngx_data_item_t *ngx_data_new_item(ngx_pool_t *pool, ngx_uint_t type);
ngx_data_item_t *ngx_data_new_container(ngx_pool_t *pool, ngx_uint_t type);

ngx_int_t ngx_data_object_add(ngx_data_item_t *obj, ngx_data_item_t *name,
    ngx_data_item_t *item);
ngx_int_t ngx_data_object_add_str(ngx_data_item_t *obj, ngx_str_t *name,
    ngx_data_item_t *item, ngx_pool_t *pool);
ngx_int_t ngx_data_list_add(ngx_data_item_t *list, ngx_data_item_t *item);


#define NGX_DATA_UNDEF_TYPE    0
#define NGX_DATA_OBJECT_TYPE   1
#define NGX_DATA_LIST_TYPE     2
#define NGX_DATA_STR_TYPE      3
#define NGX_DATA_STRING_TYPE   4
#define NGX_DATA_INTEGER_TYPE  5
#define NGX_DATA_BOOLEAN_TYPE  6
#define NGX_DATA_NULL_TYPE     7


#define ngx_data_new_object(pool)                                             \
    ngx_data_new_container(pool, NGX_DATA_OBJECT_TYPE)
#define ngx_data_new_list(pool)                                               \
    ngx_data_new_container(pool, NGX_DATA_LIST_TYPE)

ngx_data_item_t *ngx_data_new_integer(int64_t value, ngx_pool_t *pool);
ngx_data_item_t *ngx_data_new_string(ngx_str_t *value, ngx_pool_t *pool);
ngx_data_item_t *ngx_data_new_boolean(ngx_uint_t value, ngx_pool_t *pool);

#define ngx_data_new_null(pool)                                               \
    ngx_data_new_item(pool, NGX_DATA_NULL_TYPE)


ngx_int_t ngx_data_get_string(ngx_str_t *value, ngx_data_item_t *item);


#endif /* _NGX_DATA_H_INCLUDED_ */
