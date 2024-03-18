
/*
 * Copyright (C) 2022-2024 Web Server LLC
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


static ngx_int_t ngx_api_next_segment(ngx_str_t *path, ngx_str_t *name);

static ngx_int_t ngx_api_generic_iter(ngx_api_iter_ctx_t *ictx,
    ngx_api_ctx_t *actx);

static void *ngx_api_create_conf(ngx_cycle_t *cycle);
static void ngx_api_cleanup(void *data);
static void ngx_api_entries_free(ngx_api_entry_t *entry);
static ngx_api_entry_t *ngx_api_entries_dup(ngx_api_entry_t *entry,
    ngx_log_t *log);


static ngx_core_module_t  ngx_api_module_ctx = {
    ngx_string("api"),
    ngx_api_create_conf,
    NULL
};

static ngx_int_t ngx_api_angie_address_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_angie_generation_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_angie_load_time_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_angie_config_files_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_angie_config_files_iter(ngx_api_iter_ctx_t *ictx,
    ngx_api_ctx_t *actx);

static ngx_int_t ngx_api_connections_dropped_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_connections_active_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);

ngx_int_t ngx_api_slabs_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);


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


static ngx_str_t  ngx_api_angie_version = ngx_string(ANGIE_VERSION);
#ifdef NGX_BUILD
static ngx_str_t  ngx_api_angie_build = ngx_string(NGX_BUILD);
#endif


static ngx_api_entry_t  ngx_api_angie_entries[] = {

    {
        .name      = ngx_string("version"),
        .handler   = ngx_api_string_handler,
        .data.str  = &ngx_api_angie_version
    },

#ifdef NGX_BUILD
    {
        .name      = ngx_string("build"),
        .handler   = ngx_api_string_handler,
        .data.str  = &ngx_api_angie_build
    },
#endif

    {
        .name      = ngx_string("address"),
        .handler   = ngx_api_angie_address_handler,
    },

    {
        .name      = ngx_string("generation"),
        .handler   = ngx_api_angie_generation_handler,
    },

    {
        .name      = ngx_string("load_time"),
        .handler   = ngx_api_angie_load_time_handler,
    },

    {
        .name      = ngx_string("config_files"),
        .handler   = ngx_api_angie_config_files_handler,
    },

    ngx_api_null_entry
};


static ngx_api_entry_t  ngx_api_connections_entries[] = {

    {
        .name      = ngx_string("accepted"),
        .handler   = ngx_api_atomic_pp_handler,
        .data.atpp = &ngx_stat_accepted
    },

    {
        .name      = ngx_string("dropped"),
        .handler   = ngx_api_connections_dropped_handler,
    },

    {
        .name      = ngx_string("active"),
        .handler   = ngx_api_connections_active_handler,
    },

    {
        .name      = ngx_string("idle"),
        .handler   = ngx_api_atomic_pp_handler,
        .data.atpp = &ngx_stat_waiting
    },

    ngx_api_null_entry
};


static ngx_api_entry_t  ngx_api_status_entries[] = {

    {
        .name      = ngx_string("angie"),
        .handler   = ngx_api_object_handler,
        .data.ents = ngx_api_angie_entries
    },

    {
        .name      = ngx_string("connections"),
        .handler   = ngx_api_object_handler,
        .data.ents = ngx_api_connections_entries
    },

    {
        .name      = ngx_string("slabs"),
        .handler   = ngx_api_slabs_handler,
    },

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


static ngx_api_entry_t  ngx_api_root_entry = {
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

        rc = ngx_data_object_add_str(obj, &ictx->entry.name, actx->out,
                                     actx->pool);
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

    for ( ;; ) {
        if (p == end) {
            ngx_str_null(name);
            path->len = 0;
            return NGX_DECLINED;
        }

        if (*p != '/') {
            break;
        }

        p++;
    }

    name->data = p;
    do { p++; } while (p < end && *p != '/');
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
ngx_api_flag_handler(ngx_api_entry_data_t data, ngx_api_ctx_t *actx, void *ctx)
{
    actx->out = ngx_data_new_boolean(data.flag, actx->pool);

    return actx->out ? NGX_OK : NGX_ERROR;
}


ngx_int_t
ngx_api_number_handler(ngx_api_entry_data_t data, ngx_api_ctx_t *actx,
    void *ctx)
{
    actx->out = ngx_data_new_integer(data.num, actx->pool);

    return actx->out ? NGX_OK : NGX_ERROR;
}


ngx_int_t
ngx_api_atomic_pp_handler(ngx_api_entry_data_t data, ngx_api_ctx_t *actx,
    void *ctx)
{
    data.num = **data.atpp;

    return ngx_api_number_handler(data, actx, ctx);
}


ngx_int_t
ngx_api_time_handler(ngx_api_entry_data_t data, ngx_api_ctx_t *actx, void *ctx)
{
    u_char     *p;
    ngx_tm_t    tm;
    ngx_str_t   src;
    u_char      iso8601[sizeof("1970-01-01T00:00:00.000Z") - 1];

    if (actx->epoch) {
        data.num = data.tp->sec;
        return ngx_api_number_handler(data, actx, ctx);
    }

    ngx_gmtime(data.tp->sec, &tm);

    p = ngx_sprintf(iso8601, "%4d-%02d-%02dT%02d:%02d:%02d",
                    tm.ngx_tm_year, tm.ngx_tm_mon, tm.ngx_tm_mday,
                    tm.ngx_tm_hour, tm.ngx_tm_min, tm.ngx_tm_sec);

    if (data.tp->msec) {
        p = ngx_sprintf(p, ".%03ui", data.tp->msec);
    }

    *p++ = 'Z';

    src.data = iso8601;
    src.len = p - iso8601;

    data.str = &src;

    return ngx_api_string_handler(data, actx, ctx);
}


ngx_int_t
ngx_api_struct_str_handler(ngx_api_entry_data_t data, ngx_api_ctx_t *actx,
    void *ctx)
{
    data.str = (ngx_str_t *) ((u_char *) ctx + data.off);

    return ngx_api_string_handler(data, actx, ctx);
}


ngx_int_t
ngx_api_struct_int_handler(ngx_api_entry_data_t data, ngx_api_ctx_t *actx,
    void *ctx)
{
    data.num = *(ngx_int_t *) ((u_char *) ctx + data.off);

    return ngx_api_number_handler(data, actx, ctx);
}


ngx_int_t
ngx_api_struct_int64_handler(ngx_api_entry_data_t data, ngx_api_ctx_t *actx,
    void *ctx)
{
    data.num = *(int64_t *) ((u_char *) ctx + data.off);

    return ngx_api_number_handler(data, actx, ctx);
}


ngx_int_t
ngx_api_struct_atomic_handler(ngx_api_entry_data_t data, ngx_api_ctx_t *actx,
    void *ctx)
{
    data.num = *(ngx_atomic_uint_t *) ((u_char *) ctx + data.off);

    return ngx_api_number_handler(data, actx, ctx);
}


static ngx_int_t
ngx_api_angie_address_handler(ngx_api_entry_data_t data, ngx_api_ctx_t *actx,
    void *ctx)
{
    u_char     addr[NGX_SOCKADDR_STRLEN];
    ngx_str_t  address;

    address.len = NGX_SOCKADDR_STRLEN;
    address.data = addr;

    if (ngx_connection_local_sockaddr(actx->connection, &address, 0)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    data.str = &address;

    return ngx_api_string_handler(data, actx, ctx);
}


static ngx_int_t
ngx_api_angie_generation_handler(ngx_api_entry_data_t data, ngx_api_ctx_t *actx,
    void *ctx)
{
    data.num = ngx_cycle->generation;

    return ngx_api_number_handler(data, actx, ctx);
}


static ngx_int_t
ngx_api_angie_load_time_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    data.tp = &((ngx_cycle_t *) ngx_cycle)->time;

    return ngx_api_time_handler(data, actx, ctx);
}


static ngx_int_t
ngx_api_angie_config_files_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    ngx_str_t           str;
    ngx_api_iter_ctx_t  ictx;

    if (!actx->config_files) {
        return NGX_DECLINED;
    }

    ictx.entry.handler = ngx_api_string_handler;
    ictx.entry.data.str = &str;
    ictx.elts = ngx_cycle->config_dump.elts;

    return ngx_api_object_iterate(ngx_api_angie_config_files_iter, &ictx, actx);
}


static ngx_int_t
ngx_api_angie_config_files_iter(ngx_api_iter_ctx_t *ictx, ngx_api_ctx_t *actx)
{
    ngx_buf_t        *b;
    ngx_conf_dump_t  *first, *current;

    first = ngx_cycle->config_dump.elts;
    current = ictx->elts;

    if ((ngx_uint_t) (current - first) == ngx_cycle->config_dump.nelts) {
        return NGX_DECLINED;
    }

    ictx->elts = current + 1;

    ictx->entry.name = current->name;

    b = current->buffer;
    ictx->entry.data.str->len = b->last - b->pos;
    ictx->entry.data.str->data = b->pos;

    return NGX_OK;
}


static ngx_int_t
ngx_api_connections_dropped_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    data.num = *ngx_stat_accepted - *ngx_stat_handled;

    return ngx_api_number_handler(data, actx, ctx);
}


static ngx_int_t
ngx_api_connections_active_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    data.num = *ngx_stat_active - *ngx_stat_waiting;

    return ngx_api_number_handler(data, actx, ctx);
}


static void *
ngx_api_create_conf(ngx_cycle_t *cycle)
{
    ngx_api_entry_t     *root;
    ngx_pool_cleanup_t  *cln;

    cln = ngx_pool_cleanup_add(cycle->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    root = ngx_alloc(sizeof(ngx_api_entry_t), cycle->log);
    if (root == NULL) {
        return NULL;
    }

    cln->data = root;
    cln->handler = ngx_api_cleanup;

    *root = ngx_api_root_entry;

    root->data.ents = ngx_api_entries_dup(root->data.ents, cycle->log);
    if (root->data.ents == NULL) {
        return NULL;
    }

    return root;
}


ngx_api_entry_t *
ngx_api_root(ngx_cycle_t *cycle)
{
    return (ngx_api_entry_t *) ngx_get_conf(cycle->conf_ctx, ngx_api_module);
}


static void
ngx_api_cleanup(void *data)
{
    ngx_api_entry_t *root = data;

    ngx_api_entries_free(root->data.ents);

    ngx_free(root);
}


static void
ngx_api_entries_free(ngx_api_entry_t *entry)
{
    void  *p;

    if (entry != NULL) {
        p = entry;

        while (!ngx_api_is_null(entry)) {
            if (entry->handler == &ngx_api_object_handler) {
                ngx_api_entries_free(entry->data.ents);
            }

            entry++;
        }

        ngx_free(p);
    }
}


static ngx_api_entry_t *
ngx_api_entries_dup(ngx_api_entry_t *entry, ngx_log_t *log)
{
    size_t            copy;
    ngx_uint_t        i;
    ngx_api_entry_t  *dup;

    for (i = 0; !ngx_api_is_null(&entry[i]); i++) { /* void */ }

    copy = sizeof(ngx_api_entry_t) * (i + 1);

    dup = ngx_alloc(copy, log);
    if (dup == NULL) {
        return NULL;
    }

    ngx_memcpy(dup, entry, copy);

    entry = dup;

    while (!ngx_api_is_null(entry)) {
        if (entry->handler == &ngx_api_object_handler) {
            entry->data.ents = ngx_api_entries_dup(entry->data.ents, log);
            if (entry->data.ents == NULL) {
                ngx_memzero(entry, sizeof(ngx_api_entry_t));
                ngx_api_entries_free(dup);
                return NULL;
            }
        }

        entry++;
    }

    return dup;
}


ngx_int_t
ngx_api_add(ngx_cycle_t *cycle, const char *data, ngx_api_entry_t *child)
{
    ngx_str_t         path, name;
    ngx_uint_t        n;
    ngx_api_entry_t  *entry, *parent;

    entry = ngx_api_root(cycle);

    path.data = (u_char *) data;
    path.len = ngx_strlen(data);

    for ( ;; ) {
        if (entry->handler != &ngx_api_object_handler) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "cannot add at api path %s", data);
            return NGX_ERROR;
        }

        if (ngx_api_next_segment(&path, &name) != NGX_OK) {
            break;
        }

        entry = entry->data.ents;

        while (!ngx_api_is_null(entry)) {
            if (entry->name.len == name.len
                && ngx_strncmp(entry->name.data, name.data, name.len) == 0)
            {
                goto next;
            }

            entry++;
        }

        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "api path %s not found", data);
        return NGX_ERROR;

    next:

        continue;
    }

    parent = entry;
    entry = entry->data.ents;

    name = child->name;

    while (!ngx_api_is_null(entry)) {
        if (entry->name.len == name.len
            && ngx_strncmp(entry->name.data, name.data, name.len) == 0)
        {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "api path %s/%V already exists", data, &name);
            return NGX_ERROR;
        }

        entry++;
    }

    n = entry - parent->data.ents;

    entry = ngx_realloc(parent->data.ents, sizeof(ngx_api_entry_t) * (n + 2),
                        cycle->log);
    if (entry == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(entry + n, child, sizeof(ngx_api_entry_t));
    ngx_memzero(&entry[n + 1], sizeof(ngx_api_entry_t));

    parent->data.ents = entry;

    if (entry[n].handler == &ngx_api_object_handler) {
        entry[n].data.ents = ngx_api_entries_dup(entry[n].data.ents,
                                                 cycle->log);
        if (entry[n].data.ents == NULL) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}
