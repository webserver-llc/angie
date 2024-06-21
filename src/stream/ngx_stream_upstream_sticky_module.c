
/*
 * Copyright (C) 2023-2024 Web Server LLC
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_md5.h>


typedef struct {
    ngx_array_t                        lookup_vars;
    ngx_stream_complex_value_t        *secret;
    ngx_flag_t                         strict;

    ngx_stream_upstream_init_pt        original_init_upstream;
    ngx_stream_upstream_init_peer_pt   original_init_peer;

} ngx_stream_upstream_sticky_srv_conf_t;


typedef struct {
    ngx_str_t                          hint;
    ngx_str_t                          salt;

    ngx_event_get_peer_pt              original_get_peer;
} ngx_stream_upstream_sticky_peer_data_t;


static ngx_int_t ngx_stream_upstream_sticky_select_peer(
    ngx_stream_upstream_rr_peer_data_t *rrp,
    ngx_stream_upstream_sticky_peer_data_t *sp, ngx_peer_connection_t *pc);
static size_t ngx_stream_upstream_sticky_hash(ngx_str_t *in, ngx_str_t *salt,
    u_char *out);
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
    ngx_stream_upstream_sticky_peer_data_t *sp, ngx_peer_connection_t *pc)
{
    size_t       len;
    time_t       now;
    u_char      *sid, hashed[NGX_STREAM_UPSTREAM_SID_LEN];
    ngx_str_t   *hint;
    uintptr_t    m;
    ngx_uint_t   i, n;

    ngx_stream_session_t                   *s;
    ngx_stream_upstream_state_t            *us;
    ngx_stream_upstream_rr_peer_t          *peer;
    ngx_stream_upstream_rr_peers_t         *peers;
    ngx_stream_upstream_sticky_srv_conf_t  *scf;

    s = pc->ctx;

    hint = &sp->hint;
    us = s->upstream->state;

    if (hint->len == 0) {
        us->sticky_status = NGX_STREAM_UPSTREAM_STICKY_STATUS_NEW;

        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "sticky: no hint provided");
        return NGX_OK;
    }

    now = ngx_time();

    peers = rrp->peers;

again:

    ngx_stream_upstream_rr_peers_rlock(peers);

#if (NGX_STREAM_UPSTREAM_ZONE)
    if (peers->generation && rrp->generation != *peers->generation) {
        ngx_stream_upstream_rr_peers_unlock(peers);
        return NGX_BUSY;
    }
#endif

    for (peer = peers->peer, i = 0;
         peer;
         peer = peer->next, i++)
    {
        n = i / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

        if (rrp->tried[n] & m) {
            continue;
        }

        ngx_stream_upstream_rr_peer_lock(peers, peer);

        if (peer->down) {
            ngx_stream_upstream_rr_peer_unlock(peers, peer);
            continue;
        }

        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            ngx_stream_upstream_rr_peer_unlock(peers, peer);
            continue;
        }

        if (peer->max_conns && peer->conns >= peer->max_conns) {
            ngx_stream_upstream_rr_peer_unlock(peers, peer);
            continue;
        }

        if (sp->salt.len) {
            len = ngx_stream_upstream_sticky_hash(&peer->sid, &sp->salt,
                                                  hashed);
            sid = hashed;

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

        rrp->current = peer;
        ngx_stream_upstream_rr_peer_ref(peers, peer);

        pc->sockaddr = peer->sockaddr;
        pc->socklen = peer->socklen;
        pc->name = &peer->name;
        pc->sid = peer->sid;

        peer->conns++;

        if (now - peer->checked > peer->fail_timeout) {
            peer->checked = now;
        }

#if (NGX_API && NGX_STREAM_UPSTREAM_ZONE)
        peer->stats.conns++;
        peer->stats.selected = now;
#endif

        ngx_stream_upstream_rr_peer_unlock(peers, peer);
        ngx_stream_upstream_rr_peers_unlock(peers);

        rrp->tried[n] |= m;

        return NGX_OK;
    }

    if (peers->next) {
        ngx_stream_upstream_rr_peers_unlock(peers);
        peers = peers->next;
        goto again;
    }

    us->sticky_status = NGX_STREAM_UPSTREAM_STICKY_STATUS_MISS;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0, "sticky: no match");

    ngx_stream_upstream_rr_peers_unlock(peers);

    scf = ngx_stream_conf_upstream_srv_conf(s->upstream->upstream,
                                            ngx_stream_upstream_sticky_module);

    return scf->strict ? NGX_BUSY : NGX_OK;
}


static size_t
ngx_stream_upstream_sticky_hash(ngx_str_t *in, ngx_str_t *salt, u_char *out)
{
    ngx_md5_t  md5;
    u_char     hash[16];

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, in->data, in->len);
    ngx_md5_update(&md5, salt->data, salt->len);
    ngx_md5_final(hash, &md5);

    ngx_hex_dump(out, hash, 16);

    return 32;
}


static ngx_int_t
ngx_stream_upstream_init_sticky(ngx_conf_t *cf,
    ngx_stream_upstream_srv_conf_t *us)
{
    ngx_stream_upstream_sticky_srv_conf_t  *scf;

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
    ngx_stream_upstream_sticky_srv_conf_t   *scf;
    ngx_stream_upstream_sticky_peer_data_t  *sp;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "sticky: init peer");

    scf = ngx_stream_conf_upstream_srv_conf(us,
                                            ngx_stream_upstream_sticky_module);

    sp = ngx_pcalloc(s->connection->pool,
                     sizeof(ngx_stream_upstream_sticky_peer_data_t));
    if (sp == NULL) {
        return NGX_ERROR;
    }

    ngx_stream_set_ctx(s, sp, ngx_stream_upstream_sticky_module);

    if (scf->original_init_peer(s, us) != NGX_OK) {
        return NGX_ERROR;
    }

    sp->original_get_peer = s->upstream->peer.get;
    s->upstream->peer.get = ngx_stream_upstream_get_sticky_peer;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_upstream_get_sticky_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_stream_upstream_rr_peer_data_t  *rrp = data;

    ngx_int_t                                rc, *vars;
    ngx_uint_t                               i;
    ngx_stream_session_t                    *s;
    ngx_stream_variable_value_t             *vv;
    ngx_stream_upstream_sticky_srv_conf_t   *scf;
    ngx_stream_upstream_sticky_peer_data_t  *sp;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0, "sticky: get peer");

    s = pc->ctx;

    sp = ngx_stream_get_module_ctx(s, ngx_stream_upstream_sticky_module);

    scf = ngx_stream_conf_upstream_srv_conf(s->upstream->upstream,
                                            ngx_stream_upstream_sticky_module);
    sp->hint.len = 0;

    vars = scf->lookup_vars.elts;

    for (i = 0; i < scf->lookup_vars.nelts; i++) {

        vv = ngx_stream_get_indexed_variable(s, vars[i]);

        if (vv == NULL || vv->not_found || vv->len == 0) {
            continue;
        }

        sp->hint.data = vv->data;
        sp->hint.len = vv->len;

        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "sticky: extracted hint %V from variable %ui",
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

    rc = ngx_stream_upstream_sticky_select_peer(rrp, sp, pc);

    if (rc == NGX_BUSY) {
        pc->name = rrp->peers->name;
        return NGX_BUSY;
    }

    if (pc->sockaddr) {
        /* peer selected by sticky, we are done */
        return NGX_OK;
    }

    /* sticky peer not found, fallback allowed to original balancer */
    return sp->original_get_peer(pc, data);
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

    if (ngx_array_init(&conf->lookup_vars, cf->pool, 4, sizeof(ngx_uint_t))
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

    ngx_str_t   *value;
    ngx_int_t   *v;
    ngx_uint_t   i;

    value = cf->args->elts;

    for (i = 2; i < cf->args->nelts; i++) {

        if (value[i].len < 2 || value[i].data[0] != '$') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "variables expected as \"route\" arguments");
            return NGX_CONF_ERROR;
        }

        value[i].len--;
        value[i].data++;

        v = ngx_array_push(&scf->lookup_vars);
        if (v == NULL) {
            return NGX_CONF_ERROR;
        }

        *v = ngx_stream_get_variable_index(cf, &value[i]);
        if (*v == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}
