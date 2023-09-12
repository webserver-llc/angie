
/*
 * Copyright (C) 2023 Web Server LLC
 * Copyright (C) Ruslan Ermilov
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


static char *ngx_stream_upstream_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_stream_upstream_init_zone(ngx_shm_zone_t *zone,
    void *data);
static ngx_stream_upstream_rr_peers_t *ngx_stream_upstream_zone_copy_peers(
    ngx_slab_pool_t *shpool, ngx_stream_upstream_srv_conf_t *uscf,
    ngx_stream_upstream_srv_conf_t *ouscf);
static ngx_stream_upstream_rr_peer_t *ngx_stream_upstream_zone_copy_peer(
    ngx_stream_upstream_rr_peers_t *peers, ngx_stream_upstream_rr_peer_t *src);
static ngx_int_t ngx_stream_upstream_zone_preresolve(
    ngx_stream_upstream_rr_peer_t *resolve,
    ngx_stream_upstream_rr_peers_t *peers,
    ngx_stream_upstream_rr_peer_t *oresolve,
    ngx_stream_upstream_rr_peers_t *opeers);
static ngx_stream_upstream_rr_peer_t *ngx_stream_upstream_zone_new_peer(
    ngx_stream_upstream_rr_peers_t *peers, ngx_resolver_addr_t *addr,
    ngx_stream_upstream_rr_peer_t *template);

#if (NGX_API)

static ngx_int_t ngx_api_stream_upstreams_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_stream_upstreams_iter(ngx_api_iter_ctx_t *ictx,
    ngx_api_ctx_t *actx);
static ngx_int_t ngx_api_stream_upstream_peers_handler(
    ngx_api_entry_data_t data, ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_stream_upstream_peers_iter(ngx_api_iter_ctx_t *ictx,
    ngx_api_ctx_t *actx);
#if (NGX_DEBUG)
static ngx_int_t ngx_api_stream_upstream_zombies_handler(
    ngx_api_entry_data_t data, ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_stream_upstream_zone_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
#endif

static ngx_int_t ngx_api_stream_upstream_peer_server_handler(
    ngx_api_entry_data_t data, ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_stream_upstream_peer_backup_handler(
    ngx_api_entry_data_t data, ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_stream_upstream_peer_state_handler(
    ngx_api_entry_data_t data, ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_stream_upstream_peer_max_conns_handler(
    ngx_api_entry_data_t data, ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_stream_upstream_peer_downtime_handler(
    ngx_api_entry_data_t data, ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_stream_upstream_peer_downstart_handler(
    ngx_api_entry_data_t data, ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_stream_upstream_peer_selected_last_handler(
    ngx_api_entry_data_t data, ngx_api_ctx_t *actx, void *ctx);

#endif


#if (NGX_API)

static ngx_api_entry_t  ngx_api_stream_upstream_entries[] = {

    {
        .name      = ngx_string("peers"),
        .handler   = ngx_api_stream_upstream_peers_handler,
    },

#if (NGX_DEBUG)
    {
        .name      = ngx_string("zombies"),
        .handler   = ngx_api_stream_upstream_zombies_handler,
    },

    {
        .name      = ngx_string("zone"),
        .handler   = ngx_api_stream_upstream_zone_handler,
    },
#endif

    ngx_api_null_entry
};


static ngx_uint_t  ngx_api_stream_upstream_peer_backup;


static ngx_api_entry_t  ngx_api_stream_upstream_peer_selected_entries[] = {

    {
        .name      = ngx_string("current"),
        .handler   = ngx_api_struct_int_handler,
        .data.off  = offsetof(ngx_stream_upstream_rr_peer_t, conns)
    },

    {
        .name      = ngx_string("total"),
        .handler   = ngx_api_struct_int64_handler,
        .data.off  = offsetof(ngx_stream_upstream_rr_peer_t, stats.conns)
    },

    {
        .name      = ngx_string("last"),
        .handler   = ngx_api_stream_upstream_peer_selected_last_handler,
    },

    ngx_api_null_entry
};


static ngx_api_entry_t  ngx_api_stream_upstream_peer_health_entries[] = {

    {
        .name      = ngx_string("fails"),
        .handler   = ngx_api_struct_int64_handler,
        .data.off  = offsetof(ngx_stream_upstream_rr_peer_t, stats.fails)
    },

    {
        .name      = ngx_string("unavailable"),
        .handler   = ngx_api_struct_int64_handler,
        .data.off  = offsetof(ngx_stream_upstream_rr_peer_t, stats.unavailable)
    },

    {
        .name      = ngx_string("downtime"),
        .handler   = ngx_api_stream_upstream_peer_downtime_handler,
    },

    {
        .name      = ngx_string("downstart"),
        .handler   = ngx_api_stream_upstream_peer_downstart_handler,
    },

    ngx_api_null_entry
};


static ngx_api_entry_t  ngx_api_stream_upstream_peer_data_entries[] = {

    {
        .name      = ngx_string("sent"),
        .handler   = ngx_api_struct_int64_handler,
        .data.off  = offsetof(ngx_stream_upstream_rr_peer_t, stats.sent)
    },

    {
        .name      = ngx_string("received"),
        .handler   = ngx_api_struct_int64_handler,
        .data.off  = offsetof(ngx_stream_upstream_rr_peer_t, stats.received)
    },

    ngx_api_null_entry
};


static ngx_api_entry_t  ngx_api_stream_upstream_peer_entries[] = {

    {
        .name      = ngx_string("server"),
        .handler   = ngx_api_stream_upstream_peer_server_handler,
    },

    {
        .name      = ngx_string("backup"),
        .handler   = ngx_api_stream_upstream_peer_backup_handler,
    },

    {
        .name      = ngx_string("weight"),
        .handler   = ngx_api_struct_int_handler,
        .data.off  = offsetof(ngx_stream_upstream_rr_peer_t, weight)
    },

    {
        .name      = ngx_string("state"),
        .handler   = ngx_api_stream_upstream_peer_state_handler,
    },

    {
        .name      = ngx_string("selected"),
        .handler   = ngx_api_object_handler,
        .data.ents = ngx_api_stream_upstream_peer_selected_entries
    },

    {
        .name      = ngx_string("max_conns"),
        .handler   = ngx_api_stream_upstream_peer_max_conns_handler,
    },

    {
        .name      = ngx_string("data"),
        .handler   = ngx_api_object_handler,
        .data.ents = ngx_api_stream_upstream_peer_data_entries
    },

    {
        .name      = ngx_string("health"),
        .handler   = ngx_api_object_handler,
        .data.ents = ngx_api_stream_upstream_peer_health_entries
    },

#if (NGX_DEBUG)
    {
        .name      = ngx_string("refs"),
        .handler   = ngx_api_struct_int_handler,
        .data.off  = offsetof(ngx_stream_upstream_rr_peer_t, refs)
    },
#endif

    ngx_api_null_entry
};


static ngx_api_entry_t  ngx_api_stream_upstreams_entry = {
    .name      = ngx_string("upstreams"),
    .handler   = ngx_api_stream_upstreams_handler,
};

#endif


static ngx_command_t  ngx_stream_upstream_zone_commands[] = {

    { ngx_string("zone"),
      NGX_STREAM_UPS_CONF|NGX_CONF_TAKE12,
      ngx_stream_upstream_zone,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_int_t ngx_stream_upstream_zone_init_worker(ngx_cycle_t *cycle);
static ngx_int_t ngx_stream_upstream_zone_init(ngx_conf_t *cf);
static void ngx_stream_upstream_zone_resolve_timer(ngx_event_t *event);
static void ngx_stream_upstream_zone_resolve_handler(ngx_resolver_ctx_t *ctx);


static ngx_stream_module_t  ngx_stream_upstream_zone_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_stream_upstream_zone_init,         /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL                                   /* merge server configuration */
};


ngx_module_t  ngx_stream_upstream_zone_module = {
    NGX_MODULE_V1,
    &ngx_stream_upstream_zone_module_ctx,  /* module context */
    ngx_stream_upstream_zone_commands,     /* module directives */
    NGX_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_stream_upstream_zone_init_worker,  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static char *
ngx_stream_upstream_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ssize_t                           size;
    ngx_str_t                        *value;
    ngx_stream_upstream_srv_conf_t   *uscf;
    ngx_stream_upstream_main_conf_t  *umcf;

    uscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_upstream_module);
    umcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_upstream_module);

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
                                           &ngx_stream_upstream_module);
    if (uscf->shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    uscf->shm_zone->init = ngx_stream_upstream_init_zone;
    uscf->shm_zone->data = umcf;

    uscf->shm_zone->noreuse = 1;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_stream_upstream_init_zone(ngx_shm_zone_t *zone, void *data)
{
    size_t                            len;
    ngx_uint_t                        i, j;
    ngx_slab_pool_t                  *shpool;
    ngx_stream_upstream_rr_peers_t   *peers, **peersp;
    ngx_stream_upstream_srv_conf_t   *uscf, *ouscf, **uscfp, **ouscfp;
    ngx_stream_upstream_main_conf_t  *umcf, *oumcf;

    umcf = zone->data;
    uscfp = umcf->upstreams.elts;
    shpool = (ngx_slab_pool_t *) zone->shm.addr;

    if (zone->shm.exists) {
        peers = shpool->data;

        for (i = 0; i < umcf->upstreams.nelts; i++) {
            uscf = uscfp[i];

            if (uscf->shm_zone != zone) {
                continue;
            }

            uscf->peer.data = peers;
            peers = peers->zone_next;
        }

        return NGX_OK;
    }

    len = sizeof(" in upstream zone \"\"") + zone->shm.name.len;

    shpool->log_ctx = ngx_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(shpool->log_ctx, " in upstream zone \"%V\"%Z",
                &zone->shm.name);

    /* copy peers to shared memory */

    peersp = (ngx_stream_upstream_rr_peers_t **) (void *) &shpool->data;
    oumcf = data;

    for (i = 0; i < umcf->upstreams.nelts; i++) {
        uscf = uscfp[i];

        if (uscf->shm_zone != zone) {
            continue;
        }

        ouscf = NULL;

        if (oumcf) {
            ouscfp = oumcf->upstreams.elts;

            for (j = 0; j < oumcf->upstreams.nelts; j++) {

                if (ouscfp[j]->shm_zone == NULL
                    || ouscfp[j]->shm_zone->shm.name.len != zone->shm.name.len
                    || ngx_memcmp(ouscfp[j]->shm_zone->shm.name.data,
                                  zone->shm.name.data, zone->shm.name.len)
                       != 0)
                {
                    continue;
                }

                if (ouscfp[j]->host.len == uscf->host.len
                    && ngx_memcmp(ouscfp[j]->host.data, uscf->host.data,
                                  uscf->host.len)
                       == 0)
                {
                    ouscf = ouscfp[j];
                    break;
                }
            }
        }

        peers = ngx_stream_upstream_zone_copy_peers(shpool, uscf, ouscf);
        if (peers == NULL) {
            return NGX_ERROR;
        }

        *peersp = peers;
        peersp = &peers->zone_next;
    }

    return NGX_OK;
}


static ngx_stream_upstream_rr_peers_t *
ngx_stream_upstream_zone_copy_peers(ngx_slab_pool_t *shpool,
    ngx_stream_upstream_srv_conf_t *uscf, ngx_stream_upstream_srv_conf_t *ouscf)
{
    ngx_str_t                       *name;
    ngx_uint_t                      *generation;
    ngx_stream_upstream_rr_peer_t   *peer, **peerp;
    ngx_stream_upstream_rr_peers_t  *peers, *opeers, *backup;

    opeers = (ouscf ? ouscf->peer.data : NULL);

    generation = ngx_slab_calloc(shpool, sizeof(ngx_uint_t));
    if (generation == NULL) {
        return NULL;
    }

    peers = ngx_slab_alloc(shpool, sizeof(ngx_stream_upstream_rr_peers_t));
    if (peers == NULL) {
        return NULL;
    }

    ngx_memcpy(peers, uscf->peer.data, sizeof(ngx_stream_upstream_rr_peers_t));

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
    peers->generation = generation;

    for (peerp = &peers->peer; *peerp; peerp = &peer->next) {
        /* pool is unlocked */
        peer = ngx_stream_upstream_zone_copy_peer(peers, *peerp);
        if (peer == NULL) {
            return NULL;
        }

        *peerp = peer;
    }

    for (peerp = &peers->resolve; *peerp; peerp = &peer->next) {
        peer = ngx_stream_upstream_zone_copy_peer(peers, *peerp);
        if (peer == NULL) {
            return NULL;
        }

        *peerp = peer;
    }

    if (opeers) {
        if (ngx_stream_upstream_zone_preresolve(peers->resolve, peers,
                                                opeers->resolve, opeers)
            != NGX_OK)
        {
            return NULL;
        }
    }

    if (peers->next == NULL) {
        goto done;
    }

    backup = ngx_slab_alloc(shpool, sizeof(ngx_stream_upstream_rr_peers_t));
    if (backup == NULL) {
        return NULL;
    }

    ngx_memcpy(backup, peers->next, sizeof(ngx_stream_upstream_rr_peers_t));

    backup->name = name;

    backup->shpool = shpool;
    backup->generation = generation;

    for (peerp = &backup->peer; *peerp; peerp = &peer->next) {
        /* pool is unlocked */
        peer = ngx_stream_upstream_zone_copy_peer(backup, *peerp);
        if (peer == NULL) {
            return NULL;
        }

        *peerp = peer;
    }

    for (peerp = &backup->resolve; *peerp; peerp = &peer->next) {
        peer = ngx_stream_upstream_zone_copy_peer(backup, *peerp);
        if (peer == NULL) {
            return NULL;
        }

        *peerp = peer;
    }

    peers->next = backup;

    if (opeers && opeers->next) {

        if (ngx_stream_upstream_zone_preresolve(backup->resolve, backup,
                                                opeers->next->resolve,
                                                opeers->next)
            != NGX_OK)
        {
            return NULL;
        }
    }

done:

    uscf->peer.data = peers;

    ngx_stream_upstream_set_round_robin_single(uscf);

    return peers;
}


static ngx_stream_upstream_rr_peer_t *
ngx_stream_upstream_zone_copy_peer(ngx_stream_upstream_rr_peers_t *peers,
    ngx_stream_upstream_rr_peer_t *src)
{
    ngx_slab_pool_t                *pool;
    ngx_stream_upstream_rr_peer_t  *dst;

    pool = peers->shpool;

    dst = ngx_slab_calloc_locked(pool, sizeof(ngx_stream_upstream_rr_peer_t));
    if (dst == NULL) {
        return NULL;
    }

    if (src) {
        ngx_memcpy(dst, src, sizeof(ngx_stream_upstream_rr_peer_t));
        dst->sockaddr = NULL;
        dst->name.data = NULL;
        dst->server.data = NULL;
        dst->host = NULL;
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

        if (src->host) {
            dst->host = ngx_slab_calloc_locked(pool,
                                           sizeof(ngx_stream_upstream_host_t));
            if (dst->host == NULL) {
                goto failed;
            }

            dst->host->name.data = ngx_slab_alloc_locked(pool,
                                                         src->host->name.len);
            if (dst->host->name.data == NULL) {
                goto failed;
            }

            dst->host->peers = peers;
            dst->host->peer = dst;

            dst->host->name.len = src->host->name.len;
            ngx_memcpy(dst->host->name.data, src->host->name.data,
                       src->host->name.len);
        }
    }

    return dst;

failed:

    if (dst->host) {
        if (dst->host->name.data) {
            ngx_slab_free_locked(pool, dst->host->name.data);
        }

        ngx_slab_free_locked(pool, dst->host);
    }

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


static ngx_int_t
ngx_stream_upstream_zone_preresolve(ngx_stream_upstream_rr_peer_t *resolve,
    ngx_stream_upstream_rr_peers_t *peers,
    ngx_stream_upstream_rr_peer_t *oresolve,
    ngx_stream_upstream_rr_peers_t *opeers)
{
    ngx_resolver_addr_t              addr;
    ngx_stream_upstream_host_t      *host;
    ngx_stream_upstream_rr_peer_t  **peerp, *template, *opeer, *peer;

    if (resolve == NULL || oresolve == NULL) {
        return NGX_OK;
    }

    for (peerp = &peers->peer; *peerp; peerp = &(*peerp)->next) {
        /* void */
    }

    ngx_stream_upstream_rr_peers_rlock(opeers);

    for (template = resolve; template; template = template->next) {
        for (opeer = oresolve; opeer; opeer = opeer->next) {

            if (opeer->host->name.len != template->host->name.len
                || ngx_memcmp(opeer->host->name.data,
                              template->host->name.data,
                              template->host->name.len)
                   != 0)
            {
                continue;
            }

            host = opeer->host;

            for (opeer = opeers->peer; opeer; opeer = opeer->next) {

                if (opeer->host != host) {
                    continue;
                }

                addr.sockaddr = opeer->sockaddr;
                addr.socklen = opeer->socklen;

                peer = ngx_stream_upstream_zone_new_peer(peers, &addr,
                                                         template);
                if (peer == NULL) {
                    ngx_stream_upstream_rr_peers_unlock(opeers);
                    return NGX_ERROR;
                }

                *peerp = peer;
                peerp = &peer->next;

                peers->number++;
                peers->total_weight += peer->weight;
            }

            peers->weighted = (peers->total_weight != peers->number);

            break;
        }
    }

    ngx_stream_upstream_rr_peers_unlock(opeers);
    return NGX_OK;
}


static ngx_stream_upstream_rr_peer_t *
ngx_stream_upstream_zone_new_peer(ngx_stream_upstream_rr_peers_t *peers,
    ngx_resolver_addr_t *addr, ngx_stream_upstream_rr_peer_t *template)
{
    ngx_str_t                      *server;
    ngx_stream_upstream_rr_peer_t  *peer;

    ngx_shmtx_lock(&peers->shpool->mutex);
    peer = ngx_stream_upstream_zone_copy_peer(peers, NULL);
    ngx_shmtx_unlock(&peers->shpool->mutex);

    if (peer == NULL) {
        return NULL;
    }

    ngx_memcpy(peer->sockaddr, addr->sockaddr, addr->socklen);

    ngx_inet_set_port(peer->sockaddr, ngx_inet_get_port(template->sockaddr));

    peer->socklen = addr->socklen;

    peer->name.len = ngx_sock_ntop(peer->sockaddr, peer->socklen,
                                   peer->name.data, NGX_SOCKADDR_STRLEN, 1);

    peer->host = template->host;

    server = &template->server;

    peer->server.data = ngx_slab_alloc(peers->shpool, server->len);
    if (peer->server.data == NULL) {
        ngx_stream_upstream_rr_peer_free(peers, peer);
        return NULL;
    }

    peer->server.len = server->len;
    ngx_memcpy(peer->server.data, server->data, server->len);

    peer->weight = template->weight;
    peer->effective_weight = peer->weight;
    peer->max_conns = template->max_conns;
    peer->max_fails = template->max_fails;
    peer->fail_timeout = template->fail_timeout;
    peer->down = template->down;

    return peer;
}


#if (NGX_API)

static ngx_int_t
ngx_api_stream_upstreams_handler(ngx_api_entry_data_t data, ngx_api_ctx_t *actx,
    void *ctx)
{
    ngx_array_t                        upstreams;
    ngx_api_iter_ctx_t                 ictx;
    ngx_stream_upstream_main_conf_t   *umcf;

    umcf = ngx_stream_cycle_get_module_main_conf(ngx_cycle,
                                                 ngx_stream_upstream_module);
    upstreams = umcf->upstreams;

    ictx.entry.handler = ngx_api_object_handler;
    ictx.entry.data.ents = ngx_api_stream_upstream_entries;
    ictx.elts = &upstreams;

    return ngx_api_object_iterate(ngx_api_stream_upstreams_iter, &ictx, actx);
}


static ngx_int_t
ngx_api_stream_upstreams_iter(ngx_api_iter_ctx_t *ictx, ngx_api_ctx_t *actx)
{
    ngx_array_t                      *upstreams;
    ngx_stream_upstream_srv_conf_t  **uscfp, *uscf;

    upstreams = ictx->elts;

    for ( ;; ) {
        if (upstreams->nelts == 0) {
            return NGX_DECLINED;
        }

        uscfp = upstreams->elts;

        upstreams->elts = uscfp + 1;
        upstreams->nelts--;

        uscf = *uscfp;

        if (uscf->shm_zone && (uscf->flags & NGX_STREAM_UPSTREAM_CONF)) {
            ictx->entry.name = uscf->host;
            ictx->ctx = uscf;

            return NGX_OK;
        }
    }
}


static ngx_int_t
ngx_api_stream_upstream_peers_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    ngx_stream_upstream_srv_conf_t *uscf = ctx;

    ngx_int_t                        rc;
    ngx_api_iter_ctx_t               ictx;
    ngx_stream_upstream_rr_peers_t  *peers;

    peers = uscf->peer.data;

    ngx_api_stream_upstream_peer_backup = 0;

    ngx_stream_upstream_rr_peers_rlock(peers);

    if (peers->next) {
        ngx_stream_upstream_rr_peers_rlock(peers->next);
    }

    ictx.entry.handler = ngx_api_object_handler;
    ictx.entry.data.ents = ngx_api_stream_upstream_peer_entries;
    ictx.ctx = NULL;
    ictx.elts = peers;

    rc = ngx_api_object_iterate(ngx_api_stream_upstream_peers_iter,
                                &ictx, actx);

    ngx_stream_upstream_rr_peers_unlock(peers);

    if (peers->next) {
        ngx_stream_upstream_rr_peers_unlock(peers->next);
    }

    return rc;
}


static ngx_int_t
ngx_api_stream_upstream_peers_iter(ngx_api_iter_ctx_t *ictx,
    ngx_api_ctx_t *actx)
{
    ngx_stream_upstream_rr_peer_t   *peer;
    ngx_stream_upstream_rr_peers_t  *peers;

    peers = ictx->elts;
    peer = ictx->ctx;

    peer = (peer == NULL) ? peers->peer : peer->next;

    for ( ;; ) {

        if (peer == NULL) {

            peers = peers->next;

            if (peers == NULL) {
                return NGX_DECLINED;
            }

            ngx_api_stream_upstream_peer_backup = 1;

            ictx->elts = peers;
            peer = peers->peer;

            continue;
        }

        ictx->entry.name = peer->name;
        ictx->ctx = peer;

        return NGX_OK;
    }
}


#if (NGX_DEBUG)

static ngx_int_t
ngx_api_stream_upstream_zombies_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    ngx_stream_upstream_srv_conf_t *uscf = ctx;

    ngx_stream_upstream_rr_peers_t  *peers;

    peers = uscf->peer.data;

    data.num = peers->zombies;

    return ngx_api_number_handler(data, actx, ctx);
}


static ngx_int_t
ngx_api_stream_upstream_zone_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    ngx_stream_upstream_srv_conf_t *uscf = ctx;

    data.str = &uscf->shm_zone->shm.name;

    return ngx_api_string_handler(data, actx, ctx);
}

#endif


static ngx_int_t
ngx_api_stream_upstream_peer_server_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    ngx_stream_upstream_rr_peer_t *peer = ctx;

    data.str = &peer->server;

    return ngx_api_string_handler(data, actx, ctx);
}


static ngx_int_t
ngx_api_stream_upstream_peer_backup_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    data.flag = ngx_api_stream_upstream_peer_backup;

    return ngx_api_flag_handler(data, actx, ctx);
}


static ngx_int_t
ngx_api_stream_upstream_peer_state_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    ngx_stream_upstream_rr_peer_t *peer = ctx;

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
ngx_api_stream_upstream_peer_max_conns_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    ngx_stream_upstream_rr_peer_t *peer = ctx;

    if (peer->max_conns == 0) {
        return NGX_DECLINED;
    }

    data.num = peer->max_conns;

    return ngx_api_number_handler(data, actx, ctx);
}


static ngx_int_t
ngx_api_stream_upstream_peer_downtime_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    ngx_stream_upstream_rr_peer_t *peer = ctx;

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
ngx_api_stream_upstream_peer_downstart_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    ngx_stream_upstream_rr_peer_t *peer = ctx;

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
ngx_api_stream_upstream_peer_selected_last_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    ngx_stream_upstream_rr_peer_t *peer = ctx;

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
ngx_stream_upstream_zone_init_worker(ngx_cycle_t *cycle)
{
    ngx_uint_t                        i;
    ngx_event_t                      *event;
    ngx_stream_upstream_rr_peer_t    *peer;
    ngx_stream_upstream_rr_peers_t   *peers;
    ngx_stream_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_stream_upstream_main_conf_t  *umcf;

    if (ngx_process != NGX_PROCESS_WORKER
        && ngx_process != NGX_PROCESS_SINGLE)
    {
        return NGX_OK;
    }

    umcf = ngx_stream_cycle_get_module_main_conf(cycle,
                                                 ngx_stream_upstream_module);
    if (umcf == NULL) {
        return NGX_OK;
    }

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        uscf = uscfp[i];

        if (uscf->shm_zone == NULL) {
            continue;
        }

        peers = uscf->peer.data;

        do {
            ngx_stream_upstream_rr_peers_wlock(peers);

            for (peer = peers->resolve; peer; peer = peer->next) {

                if (peer->host->worker != ngx_worker) {
                    continue;
                }

                event = &peer->host->event;
                ngx_memzero(event, sizeof(ngx_event_t));

                event->data = uscf;
                event->handler = ngx_stream_upstream_zone_resolve_timer;
                event->log = cycle->log;
                event->cancelable = 1;

                ngx_stream_upstream_rr_peer_ref(peers, peer);
                ngx_add_timer(event, 1);
            }

            ngx_stream_upstream_rr_peers_unlock(peers);

            peers = peers->next;

        } while (peers);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_upstream_zone_init(ngx_conf_t *cf)
{
#if (NGX_API)
    if (ngx_api_add(cf->cycle, "/status/stream",
                    &ngx_api_stream_upstreams_entry)
        != NGX_OK)
    {
        return NGX_ERROR;
    }
#endif

    return NGX_OK;
}


static void
ngx_stream_upstream_zone_resolve_timer(ngx_event_t *event)
{
    ngx_resolver_ctx_t              *ctx;
    ngx_stream_upstream_host_t      *host;
    ngx_stream_upstream_rr_peer_t   *template;
    ngx_stream_upstream_rr_peers_t  *peers;
    ngx_stream_upstream_srv_conf_t  *uscf;

    host = (ngx_stream_upstream_host_t *) event;
    uscf = event->data;
    peers = host->peers;
    template = host->peer;

    if (template->zombie) {
        (void) ngx_stream_upstream_rr_peer_unref(peers, template);

        ngx_shmtx_lock(&peers->shpool->mutex);
        ngx_slab_free_locked(peers->shpool, host->name.data);
        ngx_slab_free_locked(peers->shpool, host);
        ngx_shmtx_unlock(&peers->shpool->mutex);

        return;
    }

    ctx = ngx_resolve_start(uscf->resolver, NULL);
    if (ctx == NULL) {
        goto retry;
    }

    if (ctx == NGX_NO_RESOLVER) {
        ngx_log_error(NGX_LOG_ERR, event->log, 0,
                      "no resolver defined to resolve %V", &host->name);
        return;
    }

    ctx->name = host->name;
    ctx->handler = ngx_stream_upstream_zone_resolve_handler;
    ctx->data = host;
    ctx->timeout = uscf->resolver_timeout;
    ctx->cancelable = 1;

    if (ngx_resolve_name(ctx) == NGX_OK) {
        return;
    }

retry:

    ngx_add_timer(event, ngx_max(uscf->resolver_timeout, 1000));
}


#define ngx_stream_upstream_zone_addr_marked(addr)                            \
    ((uintptr_t) (addr)->sockaddr & 1)

#define ngx_stream_upstream_zone_mark_addr(addr)                              \
    (addr)->sockaddr = (struct sockaddr *) ((uintptr_t) (addr)->sockaddr | 1)

#define ngx_stream_upstream_zone_unmark_addr(addr)                            \
    (addr)->sockaddr =                                                        \
        (struct sockaddr *) ((uintptr_t) (addr)->sockaddr & ~((uintptr_t) 1))

static void
ngx_stream_upstream_zone_resolve_handler(ngx_resolver_ctx_t *ctx)
{
    time_t                           now;
    ngx_msec_t                       timer;
    ngx_uint_t                       i, j;
    ngx_event_t                     *event;
    ngx_resolver_addr_t             *addr;
    ngx_stream_upstream_host_t      *host;
    ngx_stream_upstream_rr_peer_t   *template, **peerp, *peer;
    ngx_stream_upstream_rr_peers_t  *peers;
    ngx_stream_upstream_srv_conf_t  *uscf;

    host = ctx->data;
    peers = host->peers;
    template = host->peer;

    ngx_stream_upstream_rr_peers_wlock(peers);

    if (template->zombie) {
        (void) ngx_stream_upstream_rr_peer_unref(peers, template);

        ngx_stream_upstream_rr_peers_unlock(peers);

        ngx_shmtx_lock(&peers->shpool->mutex);
        ngx_slab_free_locked(peers->shpool, host->name.data);
        ngx_slab_free_locked(peers->shpool, host);
        ngx_shmtx_unlock(&peers->shpool->mutex);

        ngx_resolve_name_done(ctx);

        return;
    }

    event = &host->event;
    uscf = event->data;

    if (ctx->state) {
        ngx_log_error(NGX_LOG_ERR, event->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &ctx->name, ctx->state,
                      ngx_resolver_strerror(ctx->state));

        if (ctx->state != NGX_RESOLVE_NXDOMAIN) {
            ngx_stream_upstream_rr_peers_unlock(peers);

            ngx_resolve_name_done(ctx);

            ngx_add_timer(event, ngx_max(uscf->resolver_timeout, 1000));
            return;
        }

        /* NGX_RESOLVE_NXDOMAIN */

        ctx->naddrs = 0;
    }

#if (NGX_DEBUG)
    {
    u_char  text[NGX_SOCKADDR_STRLEN];
    size_t  len;

    for (i = 0; i < ctx->naddrs; i++) {
        len = ngx_sock_ntop(ctx->addrs[i].sockaddr, ctx->addrs[i].socklen,
                            text, NGX_SOCKADDR_STRLEN, 1);

        ngx_log_debug5(NGX_LOG_DEBUG_STREAM, event->log, 0,
                       "name %V was resolved to %*s "
                       "n:\"%V\" w:%d",
                       &host->name, len, text,
                       &ctx->addrs[i].name, ctx->addrs[i].weight);
    }
    }
#endif

    for (peerp = &peers->peer; *peerp; /* void */ ) {
        peer = *peerp;

        if (peer->host != host) {
            goto next;
        }

        for (j = 0; j < ctx->naddrs; j++) {

            addr = &ctx->addrs[j];

            if (ngx_stream_upstream_zone_addr_marked(addr)) {
                continue;
            }

            if (ngx_cmp_sockaddr(peer->sockaddr, peer->socklen,
                                 addr->sockaddr, addr->socklen, 0)
                != NGX_OK)
            {
                continue;
            }

            ngx_stream_upstream_zone_mark_addr(addr);

            goto next;
        }

        *peerp = peer->next;

        peers->number--;
        peers->total_weight -= peer->weight;

        peers->weighted = (peers->total_weight != peers->number);
        (*peers->generation)++;

        ngx_stream_upstream_rr_peer_free(peers, peer);

        continue;

    next:

        peerp = &peer->next;
    }

    for (i = 0; i < ctx->naddrs; i++) {

        addr = &ctx->addrs[i];

        if (ngx_stream_upstream_zone_addr_marked(addr)) {
            ngx_stream_upstream_zone_unmark_addr(addr);
            continue;
        }

        peer = ngx_stream_upstream_zone_new_peer(peers, addr, template);
        if (peer == NULL) {
            ngx_log_error(NGX_LOG_ERR, event->log, 0,
                          "cannot add new server to upstream \"%V\", "
                          "memory exhausted", peers->name);
            goto done;
        }

        *peerp = peer;
        peerp = &peer->next;

        peers->number++;
        peers->total_weight += peer->weight;

        peers->weighted = (peers->total_weight != peers->number);
        (*peers->generation)++;
    }

done:

    ngx_stream_upstream_set_round_robin_single(uscf);

    ngx_stream_upstream_rr_peers_unlock(peers);

    while (++i < ctx->naddrs) {
        ngx_stream_upstream_zone_unmark_addr(&ctx->addrs[i]);
    }

    now = ngx_time();

    timer = (ngx_msec_t) 1000 * (ctx->valid > now ? ctx->valid - now + 1 : 1);
    timer = ngx_min(timer, uscf->resolver_timeout);

    ngx_resolve_name_done(ctx);

    ngx_add_timer(event, timer);
}
