
/*
 * Copyright (C) 2023 Web Server LLC
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_sticky.h>


typedef struct {
    ngx_array_t                              lookup_vars;
    ngx_stream_complex_value_t              *secret;
    ngx_flag_t                               strict;

    ngx_stream_upstream_init_pt              original_init_upstream;
    ngx_stream_upstream_init_peer_pt         original_init_peer;

} ngx_stream_upstream_sticky_srv_conf_t;


typedef struct {
    ngx_stream_upstream_sticky_srv_conf_t   *conf;

    ngx_str_t                                hint;
    ngx_str_t                                salt;

    ngx_event_get_peer_pt                    original_get_peer;
} ngx_stream_upstream_sticky_peer_data_t;


static ngx_int_t ngx_stream_upstream_sticky_select_peer(
    ngx_stream_upstream_rr_peer_data_t *rrp,
    ngx_stream_upstream_sticky_peer_data_t *sp, ngx_peer_connection_t *pc,
    ngx_str_t *hint);
static ngx_int_t ngx_stream_upstream_init_sticky(ngx_conf_t *cf,
    ngx_stream_upstream_srv_conf_t *us);
static ngx_int_t ngx_stream_upstream_init_sticky_peer(ngx_stream_session_t *s,
    ngx_stream_upstream_srv_conf_t *us);
static ngx_int_t ngx_stream_upstream_get_sticky_peer(ngx_peer_connection_t *pc,
    void *data);

static void *ngx_stream_upstream_sticky_create_conf(ngx_conf_t *cf);
static char *ngx_stream_upstream_sticky(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_upstream_sticky_route(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

static ngx_command_t  ngx_stream_upstream_sticky_commands[] = {

    { ngx_string("sticky"),
      NGX_STREAM_UPS_CONF|NGX_CONF_2MORE,
      ngx_stream_upstream_sticky,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("sticky_secret"),
      NGX_STREAM_UPS_CONF|NGX_CONF_TAKE1,
      ngx_stream_set_complex_value_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_upstream_sticky_srv_conf_t, secret),
      NULL },

    { ngx_string("sticky_strict"),
      NGX_STREAM_UPS_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_upstream_sticky_srv_conf_t, strict),
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_upstream_sticky_module_ctx = {
    NULL,                                    /* preconfiguration */
    NULL,                                    /* postconfiguration */

    NULL,                                    /* create main configuration */
    NULL,                                    /* init main configuration */

    ngx_stream_upstream_sticky_create_conf,  /* create server configuration */
    NULL,                                    /* merge server configuration */
};


ngx_module_t  ngx_stream_upstream_sticky_module = {
    NGX_MODULE_V1,
    &ngx_stream_upstream_sticky_module_ctx,  /* module context */
    ngx_stream_upstream_sticky_commands,     /* module directives */
    NGX_STREAM_MODULE,                       /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    NULL,                                    /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_stream_upstream_sticky_select_peer(ngx_stream_upstream_rr_peer_data_t *rrp,
    ngx_stream_upstream_sticky_peer_data_t *sp, ngx_peer_connection_t *pc,
    ngx_str_t *hint)
{
    size_t                           len;
    u_char                          *sid;
    ngx_uint_t                       i;
    ngx_stream_session_t            *s;
    ngx_stream_upstream_state_t     *us;
    ngx_stream_upstream_rr_peer_t   *peer;
    ngx_stream_upstream_rr_peers_t  *peers;

    u_char                           buf[NGX_STICKY_SID_LEN];

    s = pc->ctx;

    us = s->upstream->state;

    peers = rrp->peers;

again:

    ngx_stream_upstream_rr_peers_rlock(peers);

    if (ngx_stream_upstream_conf_changed(peers, rrp)) {
        ngx_stream_upstream_rr_peers_unlock(peers);
        return NGX_BUSY;
    }

    for (peer = peers->peer, i = 0;
         peer;
         peer = peer->next, i++)
    {
        ngx_stream_upstream_rr_peer_lock(peers, peer);

        if (!ngx_stream_upstream_rr_peer_ready(rrp, peer, i)) {
            ngx_stream_upstream_rr_peer_unlock(peers, peer);
            continue;
        }

        if (sp->salt.len) {
            len = ngx_sticky_hash(&peer->sid, &sp->salt, buf);
            sid = buf;

        } else {
            len = peer->sid.len;
            sid = peer->sid.data;
        }

        if (len != hint->len || ngx_strncmp(sid, hint->data, len) != 0) {
            ngx_stream_upstream_rr_peer_unlock(rrp->peers, peer);
            continue;
        }

        us->sticky_status = NGX_STREAM_UPSTREAM_STICKY_STATUS_HIT;

        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "sticky: found matching peer %ui", i);

        ngx_stream_upstream_use_rr_peer(pc, rrp, peer, i);

        ngx_stream_upstream_rr_peer_unlock(peers, peer);
        ngx_stream_upstream_rr_peers_unlock(peers);

        return NGX_OK;
    }

    if (peers->next) {
        ngx_stream_upstream_rr_peers_unlock(peers);
        peers = peers->next;
        goto again;
    }

    ngx_stream_upstream_rr_peers_unlock(peers);

    us->sticky_status = NGX_STREAM_UPSTREAM_STICKY_STATUS_MISS;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                   "sticky: no match strict:%i", sp->conf->strict);

    if (sp->conf->strict) {
        pc->name = peers->name;
        return NGX_BUSY;
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_stream_upstream_init_sticky(ngx_conf_t *cf,
    ngx_stream_upstream_srv_conf_t *us)
{
    ngx_stream_upstream_sticky_srv_conf_t   *scf;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, cf->log, 0, "sticky: init");

    scf = ngx_stream_conf_upstream_srv_conf(us,
                                            ngx_stream_upstream_sticky_module);

    ngx_conf_init_value(scf->strict, 0);
    ngx_conf_init_ptr_value(scf->secret, NULL);

    if (scf->original_init_upstream(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    scf->original_init_peer = us->peer.init;

    us->peer.init = ngx_stream_upstream_init_sticky_peer;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_upstream_init_sticky_peer(ngx_stream_session_t *s,
    ngx_stream_upstream_srv_conf_t *us)
{
    ngx_uint_t                               i;
    ngx_stream_complex_value_t              *vars;
    ngx_stream_upstream_sticky_srv_conf_t   *scf;
    ngx_stream_upstream_sticky_peer_data_t  *sp;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "sticky: init peer");

    scf = ngx_stream_conf_upstream_srv_conf(us,
                                            ngx_stream_upstream_sticky_module);

    if (scf->original_init_peer(s, us) != NGX_OK) {
        return NGX_ERROR;
    }

    sp = ngx_pcalloc(s->connection->pool,
                     sizeof(ngx_stream_upstream_sticky_peer_data_t));
    if (sp == NULL) {
        return NGX_ERROR;
    }

    sp->conf = scf;

    ngx_stream_set_ctx(s, sp, ngx_stream_upstream_sticky_module);

    sp->original_get_peer = s->upstream->peer.get;
    s->upstream->peer.get = ngx_stream_upstream_get_sticky_peer;

    sp->hint.len = 0;

    vars = scf->lookup_vars.elts;

    for (i = 0; i < scf->lookup_vars.nelts; i++) {

        if (ngx_stream_complex_value(s, &vars[i], &sp->hint) != NGX_OK) {
            return NGX_ERROR;
        }

        if (sp->hint.len == 0) {
            continue;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "sticky: extracted hint \"%V\" from variable %ui",
                       &sp->hint, i);
        break;
    }

    if (scf->secret) {
        if (ngx_stream_complex_value(s, scf->secret, &sp->salt) != NGX_OK) {
            return NGX_ERROR;
        }

    } else {
        sp->salt.len = 0;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_upstream_get_sticky_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_stream_upstream_rr_peer_data_t  *rrp = data;

    ngx_int_t                                rc;
    ngx_stream_session_t                    *s;
    ngx_stream_upstream_state_t             *us;
    ngx_stream_upstream_sticky_peer_data_t  *sp;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0, "sticky: get peer");

    s = pc->ctx;

    pc->cached = 0;
    pc->connection = NULL;

    sp = ngx_stream_get_module_ctx(s, ngx_stream_upstream_sticky_module);

    if (sp->hint.len == 0) {
        us = s->upstream->state;
        us->sticky_status = NGX_STREAM_UPSTREAM_STICKY_STATUS_NEW;

        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "sticky: no hint provided");

    } else {

        rc = ngx_stream_upstream_sticky_select_peer(rrp, sp, pc, &sp->hint);

        switch (rc) {
        case NGX_OK:
            return NGX_OK;

        case NGX_DECLINED:
            /* use original balancer */
            break;

        case NGX_BUSY:
            pc->name = rrp->peers->name;
            return NGX_BUSY;
        }
    }

    rc = sp->original_get_peer(pc, data);
    if (rc != NGX_OK) {
        return rc;
    }

    return NGX_OK;
}


static void *
ngx_stream_upstream_sticky_create_conf(ngx_conf_t *cf)
{
    ngx_stream_upstream_sticky_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool,
                       sizeof(ngx_stream_upstream_sticky_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&conf->lookup_vars, cf->pool, 4,
                       sizeof(ngx_stream_complex_value_t))
        != NGX_OK)
    {
        return NULL;
    }

    conf->strict = NGX_CONF_UNSET;
    conf->secret = NGX_CONF_UNSET_PTR;

    /*
     * set by ngx_pcalloc():
     *
     *     conf->original_init_upstream = NULL;
     *     conf->original_init_peer = NULL;
     */

    return conf;
}


static char *
ngx_stream_upstream_sticky(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_upstream_sticky_srv_conf_t  *scf = conf;

    char                            *rv;
    ngx_str_t                       *value;
    ngx_stream_upstream_srv_conf_t  *uscf;

    value = cf->args->elts;

    if (scf->lookup_vars.nelts) {
        return "is duplicate";
    }

    if (value[1].len == 5
               && ngx_strncmp(value[1].data, "route", 5) == 0)
    {
        rv = ngx_stream_upstream_sticky_route(cf, cmd, conf);

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "unknown sticky mode \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    uscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_upstream_module);

    scf->original_init_upstream = uscf->peer.init_upstream
                                  ? uscf->peer.init_upstream
                                  : ngx_stream_upstream_init_round_robin;

    uscf->peer.init_upstream = ngx_stream_upstream_init_sticky;

    return NGX_CONF_OK;
}


static char *
ngx_stream_upstream_sticky_route(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_upstream_sticky_srv_conf_t  *scf = conf;

    ngx_str_t                           *value;
    ngx_uint_t                           i;
    ngx_stream_complex_value_t          *cv;
    ngx_stream_compile_complex_value_t   ccv;

    value = cf->args->elts;

    for (i = 2; i < cf->args->nelts; i++) {

        cv = ngx_array_push(&scf->lookup_vars);
        if (cv == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[i];
        ccv.complex_value = cv;

        if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}
