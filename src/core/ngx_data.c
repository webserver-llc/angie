
/*
 * Copyright (C) 2022-2024 Web Server LLC
 */


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    ngx_data_item_t    item;
    ngx_data_item_t  **next_p;
} ngx_data_container_t;

#define ngx_data_container(i)                                                 \
    (ngx_data_container_t *) ((u_char *) (i)                                  \
                              - offsetof(ngx_data_container_t, item))


ngx_data_item_t *
ngx_data_new_container(ngx_pool_t *pool, ngx_uint_t type)
{
    ngx_data_container_t  *cont;

    cont = ngx_palloc(pool, sizeof(ngx_data_container_t));
    if (cont == NULL) {
        return NULL;
    }

    cont->item.next = NULL;
    cont->item.data.child = NULL;
    cont->item.type = type;
    /*
     * A pointer to the union field rather than its data.child member
     * workarounds a false warning -Waddress-of-packed-member on GCC 9.
     */
    cont->next_p = (ngx_data_item_t **) &cont->item.data;

    return &cont->item;
}


ngx_data_item_t *
ngx_data_new_item(ngx_pool_t *pool, ngx_uint_t type)
{
    ngx_data_item_t  *item;

    item = ngx_palloc(pool, sizeof(ngx_data_item_t));
    if (item == NULL) {
        return NULL;
    }

    item->next = NULL;
    item->type = type;

    return item;
}


ngx_int_t
ngx_data_object_add(ngx_data_item_t *obj, ngx_data_item_t *name,
    ngx_data_item_t *item)
{
    ngx_data_container_t  *cont;

    if (obj->type != NGX_DATA_OBJECT_TYPE
        || (name->type != NGX_DATA_STR_TYPE
            && name->type != NGX_DATA_STRING_TYPE))
    {
        return NGX_ERROR;
    }

    name->next = item;

    cont = ngx_data_container(obj);

    *cont->next_p = name;
    cont->next_p = &item->next;

    return NGX_OK;
}


ngx_int_t
ngx_data_object_add_str(ngx_data_item_t *obj, ngx_str_t *name,
    ngx_data_item_t *item, ngx_pool_t *pool)
{
    ngx_data_item_t  *str;

    str = ngx_data_new_string(name, pool);
    if (str == NULL) {
        return NGX_ERROR;
    }

    return ngx_data_object_add(obj, str, item);
}


ngx_int_t
ngx_data_list_add(ngx_data_item_t *list, ngx_data_item_t *item)
{
    ngx_data_container_t  *cont;

    if (list->type != NGX_DATA_LIST_TYPE) {
        return NGX_ERROR;
    }

    cont = ngx_data_container(list);

    *cont->next_p = item;
    cont->next_p = &item->next;

    return NGX_OK;
}


ngx_data_item_t *
ngx_data_new_integer(int64_t value, ngx_pool_t *pool)
{
    ngx_data_item_t  *item;

    item = ngx_data_new_item(pool, NGX_DATA_INTEGER_TYPE);
    if (item == NULL) {
        return NULL;
    }

    item->data.integer = value;

    return item;
}


ngx_data_item_t *
ngx_data_new_string(ngx_str_t *value, ngx_pool_t *pool)
{
    ngx_uint_t        is_long;
    ngx_data_item_t  *item;

#if (NGX_PTR_SIZE == 8)
    if (value->len > NGX_DATA_MAX_STRING) {
        ngx_log_error(NGX_LOG_ALERT, pool->log, 0,
                      "data string length is out of bound: %uz", value->len);
        return NULL;
    }
#endif

    is_long = (value->len > NGX_DATA_MAX_STR);

    item = ngx_data_new_item(pool, is_long ? NGX_DATA_STRING_TYPE
                                           : NGX_DATA_STR_TYPE);
    if (item == NULL) {
        return NULL;
    }

    if (is_long) {
        item->data.string.start = ngx_pstrdup(pool, value);
        if (item->data.string.start == NULL) {
            return NULL;
        }

        item->data.string.length = value->len;

    } else {
        ngx_memcpy(item->data.str.start, value->data, value->len);
        item->data.str.length = value->len;
    }

    return item;
}


ngx_data_item_t *
ngx_data_new_boolean(ngx_uint_t value, ngx_pool_t *pool)
{
    ngx_data_item_t  *item;

    item = ngx_data_new_item(pool, NGX_DATA_BOOLEAN_TYPE);
    if (item == NULL) {
        return NULL;
    }

    item->data.boolean = value;

    return item;
}


ngx_int_t
ngx_data_get_string(ngx_str_t *value, ngx_data_item_t *item)
{
    switch (item->type) {
    case NGX_DATA_STR_TYPE:
        value->len = item->data.str.length;
        value->data = item->data.str.start;
        return NGX_OK;

    case NGX_DATA_STRING_TYPE:
        value->len = item->data.string.length;
        value->data = item->data.string.start;
        return NGX_OK;
    }

    return NGX_ERROR;
}
