
/*
 * Copyright (C) 2023 Web Server LLC
 * Copyright (C) Ruslan Ermilov
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static char *ngx_http_upstream_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_upstream_init_zone(ngx_shm_zone_t *shm_zone,
    void *data);
static ngx_http_upstream_rr_peers_t *ngx_http_upstream_zone_copy_peers(
    ngx_slab_pool_t *shpool, ngx_http_upstream_srv_conf_t *uscf);
static ngx_http_upstream_rr_peer_t *ngx_http_upstream_zone_copy_peer(
    ngx_http_upstream_rr_peers_t *peers, ngx_http_upstream_rr_peer_t *src);

#if (NGX_API)

static ngx_int_t ngx_api_http_upstreams_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_http_upstreams_iter(ngx_api_iter_ctx_t *ictx,
    ngx_api_ctx_t *actx);
static ngx_int_t ngx_api_http_upstream_peers_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_http_upstream_peers_iter(ngx_api_iter_ctx_t *ictx,
    ngx_api_ctx_t *actx);
static ngx_int_t ngx_api_http_upstream_keepalive_handler(
    ngx_api_entry_data_t data, ngx_api_ctx_t *actx, void *ctx);
#if (NGX_DEBUG)
static ngx_int_t ngx_api_http_upstream_zone_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
#endif

static ngx_int_t ngx_api_http_upstream_peer_server_handler(
    ngx_api_entry_data_t data, ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_http_upstream_peer_backup_handler(
    ngx_api_entry_data_t data, ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_http_upstream_peer_state_handler(
    ngx_api_entry_data_t data, ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_http_upstream_peer_max_conns_handler(
    ngx_api_entry_data_t data, ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_http_upstream_peer_response_codes_handler(
    ngx_api_entry_data_t data, ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_http_upstream_peer_response_codes_iter(
    ngx_api_iter_ctx_t *ictx, ngx_api_ctx_t *actx);
static ngx_int_t ngx_api_http_upstream_peer_downtime_handler(
    ngx_api_entry_data_t data, ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_http_upstream_peer_downstart_handler(
    ngx_api_entry_data_t data, ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_http_upstream_peer_selected_last_handler(
    ngx_api_entry_data_t data, ngx_api_ctx_t *actx, void *ctx);

#endif


#if (NGX_API)

static ngx_api_entry_t  ngx_api_http_upstream_entries[] = {

    {
        .name      = ngx_string("peers"),
        .handler   = ngx_api_http_upstream_peers_handler,
    },

    {
        .name      = ngx_string("keepalive"),
        .handler   = ngx_api_http_upstream_keepalive_handler,
    },

#if (NGX_DEBUG)
    {
        .name      = ngx_string("zone"),
        .handler   = ngx_api_http_upstream_zone_handler,
    },
#endif

    ngx_api_null_entry
};


static ngx_uint_t  ngx_api_http_upstream_peer_backup;


static ngx_api_entry_t  ngx_api_http_upstream_peer_selected_entries[] = {

    {
        .name      = ngx_string("current"),
        .handler   = ngx_api_struct_int_handler,
        .data.off  = offsetof(ngx_http_upstream_rr_peer_t, conns)
    },

    {
        .name      = ngx_string("total"),
        .handler   = ngx_api_struct_int64_handler,
        .data.off  = offsetof(ngx_http_upstream_rr_peer_t, stats.requests)
    },

    {
        .name      = ngx_string("last"),
        .handler   = ngx_api_http_upstream_peer_selected_last_handler,
    },

    ngx_api_null_entry
};


static ngx_api_entry_t  ngx_api_http_upstream_peer_health_entries[] = {

    {
        .name      = ngx_string("fails"),
        .handler   = ngx_api_struct_int64_handler,
        .data.off  = offsetof(ngx_http_upstream_rr_peer_t, stats.fails)
    },

    {
        .name      = ngx_string("unavailable"),
        .handler   = ngx_api_struct_int64_handler,
        .data.off  = offsetof(ngx_http_upstream_rr_peer_t, stats.unavailable)
    },

    {
        .name      = ngx_string("downtime"),
        .handler   = ngx_api_http_upstream_peer_downtime_handler,
    },

    {
        .name      = ngx_string("downstart"),
        .handler   = ngx_api_http_upstream_peer_downstart_handler,
    },

    ngx_api_null_entry
};


static ngx_api_entry_t  ngx_api_http_upstream_peer_data_entries[] = {

    {
        .name      = ngx_string("sent"),
        .handler   = ngx_api_struct_int64_handler,
        .data.off  = offsetof(ngx_http_upstream_rr_peer_t, stats.sent)
    },

    {
        .name      = ngx_string("received"),
        .handler   = ngx_api_struct_int64_handler,
        .data.off  = offsetof(ngx_http_upstream_rr_peer_t, stats.received)
    },

    ngx_api_null_entry
};


static ngx_api_entry_t  ngx_api_http_upstream_peer_entries[] = {

    {
        .name      = ngx_string("server"),
        .handler   = ngx_api_http_upstream_peer_server_handler,
    },

    {
        .name      = ngx_string("backup"),
        .handler   = ngx_api_http_upstream_peer_backup_handler,
    },

    {
        .name      = ngx_string("weight"),
        .handler   = ngx_api_struct_int_handler,
        .data.off  = offsetof(ngx_http_upstream_rr_peer_t, weight)
    },

    {
        .name      = ngx_string("state"),
        .handler   = ngx_api_http_upstream_peer_state_handler,
    },

    {
        .name      = ngx_string("selected"),
        .handler   = ngx_api_object_handler,
        .data.ents = ngx_api_http_upstream_peer_selected_entries
    },

    {
        .name      = ngx_string("max_conns"),
        .handler   = ngx_api_http_upstream_peer_max_conns_handler,
    },

    {
        .name      = ngx_string("responses"),
        .handler   = ngx_api_http_upstream_peer_response_codes_handler,
        .data.off  = offsetof(ngx_http_upstream_rr_peer_t, stats.responses)
    },

    {
        .name      = ngx_string("data"),
        .handler   = ngx_api_object_handler,
        .data.ents = ngx_api_http_upstream_peer_data_entries
    },

    {
        .name      = ngx_string("health"),
        .handler   = ngx_api_object_handler,
        .data.ents = ngx_api_http_upstream_peer_health_entries
    },

    ngx_api_null_entry
};


static ngx_api_entry_t  ngx_api_http_upstreams_entry = {
    .name      = ngx_string("upstreams"),
    .handler   = ngx_api_http_upstreams_handler,
};

#endif


static ngx_command_t  ngx_http_upstream_zone_commands[] = {

    { ngx_string("zone"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE12,
      ngx_http_upstream_zone,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_int_t ngx_http_upstream_zone_init(ngx_conf_t *cf);


static ngx_http_module_t  ngx_http_upstream_zone_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_upstream_zone_init,           /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_zone_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_zone_module_ctx,    /* module context */
    ngx_http_upstream_zone_commands,       /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static char *
ngx_http_upstream_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ssize_t                         size;
    ngx_str_t                      *value;
    ngx_http_upstream_srv_conf_t   *uscf;
    ngx_http_upstream_main_conf_t  *umcf;

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);

    value = cf->args->elts;

    if (!value[1].len) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid zone name \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts == 3) {
        size = ngx_parse_size(&value[2]);

        if (size == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid zone size \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }

        if (size < (ssize_t) (8 * ngx_pagesize)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "zone \"%V\" is too small", &value[1]);
            return NGX_CONF_ERROR;
        }

    } else {
        size = 0;
    }

    uscf->shm_zone = ngx_shared_memory_add(cf, &value[1], size,
                                           &ngx_http_upstream_module);
    if (uscf->shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    uscf->shm_zone->init = ngx_http_upstream_init_zone;
    uscf->shm_zone->data = umcf;

    uscf->shm_zone->noreuse = 1;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_upstream_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    size_t                          len;
    ngx_uint_t                      i;
    ngx_slab_pool_t                *shpool;
    ngx_http_upstream_rr_peers_t   *peers, **peersp;
    ngx_http_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_http_upstream_main_conf_t  *umcf;

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    umcf = shm_zone->data;
    uscfp = umcf->upstreams.elts;

    if (shm_zone->shm.exists) {
        peers = shpool->data;

        for (i = 0; i < umcf->upstreams.nelts; i++) {
            uscf = uscfp[i];

            if (uscf->shm_zone != shm_zone) {
                continue;
            }

            uscf->peer.data = peers;
            peers = peers->zone_next;
        }

        return NGX_OK;
    }

    len = sizeof(" in upstream zone \"\"") + shm_zone->shm.name.len;

    shpool->log_ctx = ngx_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(shpool->log_ctx, " in upstream zone \"%V\"%Z",
                &shm_zone->shm.name);


    /* copy peers to shared memory */

    peersp = (ngx_http_upstream_rr_peers_t **) (void *) &shpool->data;

    for (i = 0; i < umcf->upstreams.nelts; i++) {
        uscf = uscfp[i];

        if (uscf->shm_zone != shm_zone) {
            continue;
        }

        peers = ngx_http_upstream_zone_copy_peers(shpool, uscf);
        if (peers == NULL) {
            return NGX_ERROR;
        }

        *peersp = peers;
        peersp = &peers->zone_next;
    }

    return NGX_OK;
}


static ngx_http_upstream_rr_peers_t *
ngx_http_upstream_zone_copy_peers(ngx_slab_pool_t *shpool,
    ngx_http_upstream_srv_conf_t *uscf)
{
    ngx_str_t                     *name;
    ngx_http_upstream_rr_peer_t   *peer, **peerp;
    ngx_http_upstream_rr_peers_t  *peers, *backup;

    peers = ngx_slab_alloc(shpool, sizeof(ngx_http_upstream_rr_peers_t));
    if (peers == NULL) {
        return NULL;
    }

    ngx_memcpy(peers, uscf->peer.data, sizeof(ngx_http_upstream_rr_peers_t));

    name = ngx_slab_alloc(shpool, sizeof(ngx_str_t));
    if (name == NULL) {
        return NULL;
    }

    name->data = ngx_slab_alloc(shpool, peers->name->len);
    if (name->data == NULL) {
        return NULL;
    }

    ngx_memcpy(name->data, peers->name->data, peers->name->len);
    name->len = peers->name->len;

    peers->name = name;

    peers->shpool = shpool;

    for (peerp = &peers->peer; *peerp; peerp = &peer->next) {
        /* pool is unlocked */
        peer = ngx_http_upstream_zone_copy_peer(peers, *peerp);
        if (peer == NULL) {
            return NULL;
        }

        *peerp = peer;
    }

    if (peers->next == NULL) {
        goto done;
    }

    backup = ngx_slab_alloc(shpool, sizeof(ngx_http_upstream_rr_peers_t));
    if (backup == NULL) {
        return NULL;
    }

    ngx_memcpy(backup, peers->next, sizeof(ngx_http_upstream_rr_peers_t));

    backup->name = name;

    backup->shpool = shpool;

    for (peerp = &backup->peer; *peerp; peerp = &peer->next) {
        /* pool is unlocked */
        peer = ngx_http_upstream_zone_copy_peer(backup, *peerp);
        if (peer == NULL) {
            return NULL;
        }

        *peerp = peer;
    }

    peers->next = backup;

done:

    uscf->peer.data = peers;

    return peers;
}


static ngx_http_upstream_rr_peer_t *
ngx_http_upstream_zone_copy_peer(ngx_http_upstream_rr_peers_t *peers,
    ngx_http_upstream_rr_peer_t *src)
{
    ngx_slab_pool_t              *pool;
    ngx_http_upstream_rr_peer_t  *dst;

    pool = peers->shpool;

    dst = ngx_slab_calloc_locked(pool, sizeof(ngx_http_upstream_rr_peer_t));
    if (dst == NULL) {
        return NULL;
    }

    if (src) {
        ngx_memcpy(dst, src, sizeof(ngx_http_upstream_rr_peer_t));
        dst->sockaddr = NULL;
        dst->name.data = NULL;
        dst->server.data = NULL;
    }

    dst->sockaddr = ngx_slab_calloc_locked(pool, sizeof(ngx_sockaddr_t));
    if (dst->sockaddr == NULL) {
        goto failed;
    }

    dst->name.data = ngx_slab_calloc_locked(pool, NGX_SOCKADDR_STRLEN);
    if (dst->name.data == NULL) {
        goto failed;
    }

    if (src) {
        ngx_memcpy(dst->sockaddr, src->sockaddr, src->socklen);
        ngx_memcpy(dst->name.data, src->name.data, src->name.len);

        dst->server.data = ngx_slab_alloc_locked(pool, src->server.len);
        if (dst->server.data == NULL) {
            goto failed;
        }

        ngx_memcpy(dst->server.data, src->server.data, src->server.len);
    }

    return dst;

failed:

    if (dst->server.data) {
        ngx_slab_free_locked(pool, dst->server.data);
    }

    if (dst->name.data) {
        ngx_slab_free_locked(pool, dst->name.data);
    }

    if (dst->sockaddr) {
        ngx_slab_free_locked(pool, dst->sockaddr);
    }

    ngx_slab_free_locked(pool, dst);

    return NULL;
}


#if (NGX_API)

static ngx_int_t
ngx_api_http_upstreams_handler(ngx_api_entry_data_t data, ngx_api_ctx_t *actx,
    void *ctx)
{
    ngx_array_t                      upstreams;
    ngx_api_iter_ctx_t               ictx;
    ngx_http_upstream_main_conf_t   *umcf;

    umcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_http_upstream_module);
    upstreams = umcf->upstreams;

    ictx.entry.handler = ngx_api_object_handler;
    ictx.entry.data.ents = ngx_api_http_upstream_entries;
    ictx.elts = &upstreams;

    return ngx_api_object_iterate(ngx_api_http_upstreams_iter, &ictx, actx);
}


static ngx_int_t
ngx_api_http_upstreams_iter(ngx_api_iter_ctx_t *ictx, ngx_api_ctx_t *actx)
{
    ngx_array_t                    *upstreams;
    ngx_http_upstream_srv_conf_t  **uscfp, *uscf;

    upstreams = ictx->elts;

    for ( ;; ) {
        if (upstreams->nelts == 0) {
            return NGX_DECLINED;
        }

        uscfp = upstreams->elts;

        upstreams->elts = uscfp + 1;
        upstreams->nelts--;

        uscf = *uscfp;

        if (uscf->shm_zone && (uscf->flags & NGX_HTTP_UPSTREAM_CONF)) {
            ictx->entry.name = uscf->host;
            ictx->ctx = uscf;

            return NGX_OK;
        }
    }
}


static ngx_int_t
ngx_api_http_upstream_peers_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    ngx_http_upstream_srv_conf_t *uscf = ctx;

    ngx_int_t                      rc;
    ngx_api_iter_ctx_t             ictx;
    ngx_http_upstream_rr_peers_t  *peers;

    peers = uscf->peer.data;

    ngx_api_http_upstream_peer_backup = 0;

    ngx_http_upstream_rr_peers_rlock(peers);

    if (peers->next) {
        ngx_http_upstream_rr_peers_rlock(peers->next);
    }

    ictx.entry.handler = ngx_api_object_handler;
    ictx.entry.data.ents = ngx_api_http_upstream_peer_entries;
    ictx.ctx = NULL;
    ictx.elts = peers;

    rc = ngx_api_object_iterate(ngx_api_http_upstream_peers_iter, &ictx, actx);

    ngx_http_upstream_rr_peers_unlock(peers);

    if (peers->next) {
        ngx_http_upstream_rr_peers_unlock(peers->next);
    }

    return rc;
}


static ngx_int_t
ngx_api_http_upstream_peers_iter(ngx_api_iter_ctx_t *ictx, ngx_api_ctx_t *actx)
{
    ngx_http_upstream_rr_peer_t   *peer;
    ngx_http_upstream_rr_peers_t  *peers;

    peers = ictx->elts;
    peer = ictx->ctx;

    peer = (peer == NULL) ? peers->peer : peer->next;

    for ( ;; ) {

        if (peer == NULL) {

            peers = peers->next;

            if (peers == NULL) {
                return NGX_DECLINED;
            }

            ngx_api_http_upstream_peer_backup = 1;

            ictx->elts = peers;
            peer = peers->peer;

            continue;
        }

        ictx->entry.name = peer->name;
        ictx->ctx = peer;

        return NGX_OK;
    }
}


static ngx_int_t
ngx_api_http_upstream_keepalive_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    ngx_http_upstream_srv_conf_t *uscf = ctx;

    ngx_http_upstream_rr_peers_t  *peers;

    peers = uscf->peer.data;

    data.num = peers->stats.keepalive;

    return ngx_api_number_handler(data, actx, ctx);
}


#if (NGX_DEBUG)

static ngx_int_t
ngx_api_http_upstream_zone_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    ngx_http_upstream_srv_conf_t *uscf = ctx;

    data.str = &uscf->shm_zone->shm.name;

    return ngx_api_string_handler(data, actx, ctx);
}

#endif


static ngx_int_t
ngx_api_http_upstream_peer_server_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    ngx_http_upstream_rr_peer_t *peer = ctx;

    data.str = &peer->server;

    return ngx_api_string_handler(data, actx, ctx);
}


static ngx_int_t
ngx_api_http_upstream_peer_backup_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    data.flag = ngx_api_http_upstream_peer_backup;

    return ngx_api_flag_handler(data, actx, ctx);
}


static ngx_int_t
ngx_api_http_upstream_peer_state_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    ngx_http_upstream_rr_peer_t *peer = ctx;

    ngx_str_t  state;

    if (peer->down) {
        ngx_str_set(&state, "down");

    } else if (peer->stats.downstart != 0) {
        ngx_str_set(&state, "unavailable");

    } else {
        ngx_str_set(&state, "up");
    }

    data.str = &state;

    return ngx_api_string_handler(data, actx, ctx);
}


static ngx_int_t
ngx_api_http_upstream_peer_max_conns_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    ngx_http_upstream_rr_peer_t *peer = ctx;

    if (peer->max_conns == 0) {
        return NGX_DECLINED;
    }

    data.num = peer->max_conns;

    return ngx_api_number_handler(data, actx, ctx);
}


static ngx_int_t
ngx_api_http_upstream_peer_response_codes_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    ngx_http_upstream_rr_peer_t *peer = ctx;

    void                *codes;
    ngx_api_iter_ctx_t   ictx;

    codes = (u_char *) peer + data.off;

    ictx.entry.handler = ngx_api_number_handler;
    ictx.ctx = (void *) 0;
    ictx.elts = codes;

    return ngx_api_object_iterate(
                                ngx_api_http_upstream_peer_response_codes_iter,
                                &ictx, actx);
}


static ngx_int_t
ngx_api_http_upstream_peer_response_codes_iter(ngx_api_iter_ctx_t *ictx,
    ngx_api_ctx_t *actx)
{
    int64_t      num;
    ngx_str_t   *name;
    ngx_uint_t   i;
    uint64_t    *codes;

    codes = ictx->elts;
    i = (ngx_uint_t) ictx->ctx;

    do {
        if (i >= 500) {
            goto end;
        }

        num = codes[i++];
    } while (num == 0);

    name = &ictx->entry.name;

    name->len = 3;
    name->data = ngx_pnalloc(actx->pool, 3);
    if (name->data == NULL) {
        return NGX_ERROR;
    }

    (void) ngx_sprintf(name->data, "%ui", i - 1 + 100);

    ictx->entry.data.num = num;
    ictx->ctx = (void *) i;

    return NGX_OK;

end:

    if (i == 501 || codes[500] == 0) {
        return NGX_DECLINED;
    }

    /* 500th element counts status codes out of 100-599 range */

    ngx_str_set(&ictx->entry.name, "xxx");

    ictx->entry.data.num = codes[500];
    ictx->ctx = (void *) 501;

    return NGX_OK;
}


static ngx_int_t
ngx_api_http_upstream_peer_downtime_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    ngx_http_upstream_rr_peer_t *peer = ctx;

    ngx_time_t  *tp;

    data.num = peer->stats.downtime;

    if (peer->stats.downstart) {
        tp = ngx_timeofday();
        data.num += (uint64_t) tp->sec * 1000 + tp->msec
                    - peer->stats.downstart;
    }

    return ngx_api_number_handler(data, actx, ctx);
}


static ngx_int_t
ngx_api_http_upstream_peer_downstart_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    ngx_http_upstream_rr_peer_t *peer = ctx;

    uint64_t    downstart;
    ngx_time_t  time;

    downstart = peer->stats.downstart;

    if (downstart == 0) {
        return NGX_DECLINED;
    }

    time.sec = downstart / 1000;
    time.msec = downstart % 1000;

    data.tp = &time;

    return ngx_api_time_handler(data, actx, ctx);
}


static ngx_int_t
ngx_api_http_upstream_peer_selected_last_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    ngx_http_upstream_rr_peer_t *peer = ctx;

    ngx_time_t  time;

    if (peer->stats.selected == 0) {
        return NGX_DECLINED;
    }

    time.sec = peer->stats.selected;
    time.msec = 0;

    data.tp = &time;

    return ngx_api_time_handler(data, actx, ctx);
}

#endif


static ngx_int_t
ngx_http_upstream_zone_init(ngx_conf_t *cf)
{
#if (NGX_API)
    if (ngx_api_add(cf->cycle, "/status/http", &ngx_api_http_upstreams_entry)
        != NGX_OK)
    {
        return NGX_ERROR;
    }
#endif

    return NGX_OK;
}
