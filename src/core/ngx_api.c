
/*
 * Copyright (C) Web Server LLC
 */


#include <ngx_config.h>
#include <ngx_core.h>


static ngx_int_t ngx_api_next_segment(ngx_str_t *path, ngx_str_t *name);

static ngx_int_t ngx_api_generic_iter(ngx_api_iter_ctx_t *ictx,
    ngx_api_ctx_t *actx);


static ngx_core_module_t  ngx_api_module_ctx = {
    ngx_string("api"),
    NULL,
    NULL
};


ngx_module_t  ngx_api_module = {
    NGX_MODULE_V1,
    &ngx_api_module_ctx,                   /* module context */
    NULL,                                  /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_api_entry_t  ngx_api_status_entries[] = {
    ngx_api_null_entry
};


static ngx_api_entry_t  ngx_api_root_entries[] = {

    {
        .name      = ngx_string("status"),
        .handler   = ngx_api_object_handler,
        .data.ents = ngx_api_status_entries
    },

    ngx_api_null_entry
};


ngx_api_entry_t  ngx_api_root_entry = {
    .name      = ngx_string("/"),
    .handler   = ngx_api_object_handler,
    .data.ents = ngx_api_root_entries
};


ngx_int_t
ngx_api_object_iterate(ngx_api_iter_pt iter, ngx_api_iter_ctx_t *ictx,
    ngx_api_ctx_t *actx)
{
    ngx_int_t         rc;
    ngx_str_t         name;
    ngx_data_item_t  *obj;

    if (ngx_api_next_segment(&actx->path, &name) == NGX_OK) {
        obj = NULL;

    } else {
        obj = ngx_data_new_object(actx->pool);
        if (obj == NULL) {
            return NGX_ERROR;
        }
    }

    for ( ;; ) {
        rc = iter(ictx, actx);

        if (rc != NGX_OK) {
            if (rc == NGX_DECLINED) {
                break;
            }

            return NGX_ERROR;
        }

        if (obj == NULL
            && (ictx->entry.name.len != name.len
                || ngx_strncmp(ictx->entry.name.data,
                               name.data, name.len) != 0))
        {
            continue;
        }

        actx->out = NULL;

        rc = ictx->entry.handler(ictx->entry.data, actx, ictx->ctx);

        if (obj == NULL) {
            return rc;
        }

        if (rc == NGX_DECLINED) {
            continue;
        }

        if (rc != NGX_OK) {
            return rc;
        }

        rc = ngx_data_object_add(obj, &ictx->entry.name, actx->out, actx->pool);
        if (rc != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (obj == NULL) {
        return NGX_API_NOT_FOUND;
    }

    actx->out = obj;

    return NGX_OK;
}


static ngx_int_t
ngx_api_next_segment(ngx_str_t *path, ngx_str_t *name)
{
    u_char  *p, *end;

    p = path->data;
    end = p + path->len;

    if (end - p <= 1) {
        return NGX_DECLINED;
    }

    p++; /* skip '/' */

    name->data = p;
    while (p < end && *p != '/') { p++; }
    name->len = p - name->data;

    path->len = end - p;
    path->data = p;

    return NGX_OK;
}


ngx_int_t
ngx_api_object_handler(ngx_api_entry_data_t data, ngx_api_ctx_t *actx,
    void *ctx)
{
    ngx_api_iter_ctx_t  ictx;

    ictx.ctx = ctx;
    ictx.elts = data.ents;

    return ngx_api_object_iterate(ngx_api_generic_iter, &ictx, actx);
}


static ngx_int_t
ngx_api_generic_iter(ngx_api_iter_ctx_t *ictx, ngx_api_ctx_t *actx)
{
    ngx_api_entry_t  *entry;

    entry = ictx->elts;

    if (ngx_api_is_null(entry)) {
        return NGX_DECLINED;
    }

    ictx->entry = *entry;
    ictx->elts = ++entry;

    return NGX_OK;
}


ngx_int_t
ngx_api_string_handler(ngx_api_entry_data_t data, ngx_api_ctx_t *actx,
    void *ctx)
{
    actx->out = ngx_data_new_string(data.str, actx->pool);

    return actx->out ? NGX_OK : NGX_ERROR;
}


ngx_int_t
ngx_api_struct_str_handler(ngx_api_entry_data_t data, ngx_api_ctx_t *actx,
    void *ctx)
{
    data.str = (ngx_str_t *) ((u_char *) ctx + data.off);

    return ngx_api_string_handler(data, actx, ctx);
}
