
/*
 * Copyright (C) 2023 Web Server LLC
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_sticky.h>


typedef struct {
    ngx_array_t                              stickies; /* of shm_zone_t* */
} ngx_stream_upstream_sticky_main_conf_t;


typedef struct {
    ngx_array_t                              lookup_vars;
    ngx_array_t                              create_vars;
    ngx_stream_complex_value_t              *secret;
    ngx_flag_t                               strict;
    ngx_flag_t                               connect;
    ngx_flag_t                               refresh;

    ngx_stream_upstream_init_pt              original_init_upstream;
    ngx_stream_upstream_init_peer_pt         original_init_peer;

    ngx_shm_zone_t                          *learn_zone;

} ngx_stream_upstream_sticky_srv_conf_t;


typedef struct {
    ngx_stream_upstream_sticky_srv_conf_t   *conf;

    ngx_str_t                                hint;
    ngx_str_t                                salt;

    ngx_event_get_peer_pt                    original_get_peer;
    ngx_event_free_peer_pt                   original_free_peer;
    ngx_event_notify_peer_pt                 original_notify_peer;

    ngx_sticky_sess_t                       *learn_sess;
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

static void *ngx_stream_upstream_sticky_create_main_conf(ngx_conf_t *cf);
static void *ngx_stream_upstream_sticky_create_conf(ngx_conf_t *cf);
static char *ngx_stream_upstream_sticky(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_upstream_sticky_route(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

static void ngx_stream_upstream_free_sticky_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);
static void ngx_stream_upstream_notify_sticky_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t type);
static char *ngx_stream_upstream_sticky_learn(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_stream_upstream_sticky_init_worker(ngx_cycle_t *cycle);
static void ngx_stream_upstream_sticky_process_session(
    ngx_stream_upstream_sticky_peer_data_t *sp, ngx_peer_connection_t *pc);


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

    ngx_stream_upstream_sticky_create_main_conf,/* create main configuration */
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
    ngx_stream_upstream_sticky_init_worker,  /* init process */
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

        /* note the peer_usable() function is used but not peer_ready() */
        if (!ngx_stream_upstream_rr_peer_usable(rrp, peer, i)) {
            ngx_stream_upstream_rr_peer_unlock(peers, peer);
            continue;
        }

        if (ngx_stream_upstream_rr_is_adm_down(peer)) {
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

    /* don't set handlers for probe */
    if (s->health_check) {
        return NGX_OK;
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

    if (scf->learn_zone) {
        if (scf->connect) {
            if (s->upstream->peer.type == SOCK_DGRAM) {
                /* sessions will be handled directly by peer.get() */
                return NGX_OK;
            }

            sp->original_notify_peer = s->upstream->peer.notify;
            s->upstream->peer.notify =
                                    ngx_stream_upstream_notify_sticky_peer;

        } else {
            sp->original_free_peer = s->upstream->peer.free;
            s->upstream->peer.free = ngx_stream_upstream_free_sticky_peer;
        }
    }

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

    if (scf->secret && !sp->conf->learn_zone) {
        if (ngx_stream_complex_value(s, scf->secret, &sp->salt) != NGX_OK) {
            return NGX_ERROR;
        }

    } else {
        sp->salt.len = 0;
    }

    if (scf->learn_zone && sp->hint.len) {
        sp->learn_sess = ngx_pcalloc(s->connection->pool,
                                     sizeof(ngx_sticky_sess_t));
        if (sp->learn_sess == NULL) {
            return NGX_ERROR;
        }

        ngx_sticky_learn_init_sess(sp->learn_sess, &sp->hint, 0);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_upstream_get_sticky_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_stream_upstream_rr_peer_data_t  *rrp = data;

    ngx_int_t                                rc;
    ngx_str_t                                hint;
    ngx_stream_session_t                    *s;
    ngx_stream_upstream_state_t             *us;
    ngx_stream_upstream_sticky_peer_data_t  *sp;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0, "sticky: get peer");

    s = pc->ctx;

    pc->cached = 0;
    pc->connection = NULL;

    sp = ngx_stream_get_module_ctx(s, ngx_stream_upstream_sticky_module);

    if (sp->conf->learn_zone) {

        hint.len = 0;

        if (sp->hint.len) {
            (void) ngx_sticky_learn_lookup(sp->conf->learn_zone,
                                           sp->learn_sess, &hint);
        }

    } else {
        hint = sp->hint;
    }

    if (hint.len == 0) {
        us = s->upstream->state;
        us->sticky_status = NGX_STREAM_UPSTREAM_STICKY_STATUS_NEW;

        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                           "sticky: no hint provided");

    } else {

        rc = ngx_stream_upstream_sticky_select_peer(rrp, sp, pc, &hint);

        switch (rc) {
        case NGX_OK:
            goto peer_selected;

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

peer_selected:

    if (sp->conf->learn_zone && sp->conf->connect && pc->type == SOCK_DGRAM) {
        ngx_stream_upstream_sticky_process_session(sp, pc);
    }

    return NGX_OK;
}


static void *
ngx_stream_upstream_sticky_create_main_conf(ngx_conf_t *cf)
{
    ngx_stream_upstream_sticky_main_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool,
                       sizeof(ngx_stream_upstream_sticky_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
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

    if (ngx_array_init(&conf->create_vars, cf->pool, 4,
                       sizeof(ngx_stream_complex_value_t))
        != NGX_OK)
    {
        return NULL;
    }

    conf->strict = NGX_CONF_UNSET;
    conf->secret = NGX_CONF_UNSET_PTR;
    conf->refresh = NGX_CONF_UNSET;
    conf->connect = NGX_CONF_UNSET;

    /*
     * set by ngx_pcalloc():
     *
     *     conf->original_init_upstream = NULL;
     *     conf->original_init_peer = NULL;
     *     conf->learn_zone = NULL;
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

    } else if (value[1].len == 5
               && ngx_strncmp(value[1].data, "learn", 5) == 0)
    {
        rv = ngx_stream_upstream_sticky_learn(cf, cmd, conf);

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


static void
ngx_stream_upstream_free_sticky_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_stream_session_t                    *s;
    ngx_stream_upstream_sticky_peer_data_t  *sp;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0, "sticky: free peer");

    s = pc->ctx;

    sp = ngx_stream_get_module_ctx(s, ngx_stream_upstream_sticky_module);

    if (!(state & NGX_PEER_FAILED)) {
        ngx_stream_upstream_sticky_process_session(sp, pc);
    }

    sp->original_free_peer(pc, data, state);
}


static void
ngx_stream_upstream_notify_sticky_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t type)
{
    ngx_stream_session_t                    *s;
    ngx_stream_upstream_sticky_peer_data_t  *sp;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0, "sticky: notify peer");

    s = pc->ctx;

    sp = ngx_stream_get_module_ctx(s, ngx_stream_upstream_sticky_module);

    if (type & NGX_STREAM_UPSTREAM_NOTIFY_CONNECT) {
        ngx_stream_upstream_sticky_process_session(sp, pc);
    }

    if (sp->original_notify_peer) {
        sp->original_notify_peer(pc, data, type);
    }
}


static char *
ngx_stream_upstream_sticky_learn(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_upstream_sticky_srv_conf_t  *scf = conf;

    u_char                                   *p;
    ssize_t                                   zsize;
    ngx_str_t                                 str, *value;
    ngx_msec_t                                timeout;
    ngx_uint_t                                i;
    ngx_shm_zone_t                          **zonep;
    ngx_stream_complex_value_t               *cv;
    ngx_stream_upstream_srv_conf_t           *us;
    ngx_stream_compile_complex_value_t        ccv;
    ngx_stream_upstream_sticky_main_conf_t   *smcf;

    value = cf->args->elts;
    zsize = 0;
    timeout = NGX_CONF_UNSET_MSEC;

#if (NGX_SUPPRESS_WARN)
    ngx_str_null(&str);
#endif

    for (i = 2; i < cf->args->nelts; i++) {

        if (value[i].len >= 7
            && ngx_strncmp(value[i].data, "create=", 7) == 0)
        {
            value[i].len -= 7;
            value[i].data += 7;

            cv = ngx_array_push(&scf->create_vars);
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

            continue;
        }

        if (value[i].len >= 7
            && ngx_strncmp(value[i].data, "lookup=", 7) == 0)
        {
            value[i].len -= 7;
            value[i].data += 7;

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

            continue;
        }

        if (ngx_strncmp(value[i].data, "timeout=", 8) == 0) {

            if (timeout != NGX_CONF_UNSET_MSEC) {
                return "duplicate timeout";
            }

            value[i].data += 8;
            value[i].len -= 8;

            timeout = ngx_parse_time(&value[i], 0);
            if (timeout == (ngx_msec_t) NGX_ERROR || timeout == 0) {
                return "invalid timeout";
            }

            continue;
        }

        if (ngx_strcmp(value[i].data, "norefresh") == 0) {

            if (scf->refresh != NGX_CONF_UNSET) {
                return "duplicate norefresh";
            }

            scf->refresh = 0;
            continue;
        }

        if (ngx_strcmp(value[i].data, "connect") == 0) {

            if (scf->connect != NGX_CONF_UNSET) {
                return "duplicate connect";
            }

            scf->connect = 1;
            continue;
        }

        if (value[i].len >= 5 && ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            if (zsize != 0) {
                return "duplicate zone";
            }

            value[i].len -= 5;
            value[i].data += 5;

            if (value[i].len == 0) {
                return "zone parameters not specified";
            }

            p = (u_char *) ngx_strchr(value[i].data, ':');

            if (p == value[i].data) {
                return "empty zone name";
            }

            if (p == NULL) {
                return "zone size is not specified";
            }

            str.len = value[i].data + value[i].len - (p + 1);

            if (str.len == 0) {
                return "zone size is not specified";
            }

            str.data = p + 1;

            zsize = ngx_parse_size(&str);
            if (zsize == NGX_ERROR) {
                return "invalid zone size";
            }

            if (zsize < (ssize_t) (8 * ngx_pagesize)) {
                return "zone is too small";
            }

            str.data = value[i].data;
            str.len = p - value[i].data;

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "unknown sticky learn parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (zsize == 0) {
        return "zone not specified";
    }

    if (scf->create_vars.nelts == 0) {
        return "no create vars";
    }

    if (scf->lookup_vars.nelts == 0) {
        return "no lookup vars";
    }

    us = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_upstream_module);

    if (timeout == NGX_CONF_UNSET_MSEC) {
        timeout = 3600 * 1000;
    }

    if (scf->refresh == NGX_CONF_UNSET) {
        scf->refresh = 1;
    }

    if (scf->connect == NGX_CONF_UNSET) {
        scf->connect = 0;
    }

    scf->learn_zone = ngx_sticky_learn_create_zone(cf, &str, zsize, &us->host,
                                                   timeout, scf->refresh,
                                           &ngx_stream_upstream_sticky_module);
    if (scf->learn_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    smcf = ngx_stream_conf_get_module_main_conf(cf,
                                            ngx_stream_upstream_sticky_module);

    if (smcf->stickies.elts == NULL
        && ngx_array_init(&smcf->stickies, cf->pool, 4,
                          sizeof(ngx_shm_zone_t *))
           != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    zonep = ngx_array_push(&smcf->stickies);
    if (zonep == NULL) {
        return NGX_CONF_ERROR;
    }

    *zonep = scf->learn_zone;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_stream_upstream_sticky_init_worker(ngx_cycle_t *cycle)
{
    ngx_uint_t                               i;
    ngx_shm_zone_t                          *zone, **zonep;
    ngx_stream_upstream_sticky_main_conf_t  *smcf;

    smcf = ngx_stream_cycle_get_module_main_conf(cycle,
                                            ngx_stream_upstream_sticky_module);
    if (smcf == NULL) {
        return NGX_OK;
    }

    if (ngx_process != NGX_PROCESS_WORKER
        && ngx_process != NGX_PROCESS_SINGLE)
    {
        return NGX_OK;
    }

    zonep = smcf->stickies.elts;

    for (i = 0; i < smcf->stickies.nelts; i++) {
        zone = zonep[i];
        ngx_sticky_start(zone);
    }

    return NGX_OK;
}

static void
ngx_stream_upstream_sticky_process_session(
    ngx_stream_upstream_sticky_peer_data_t *sp, ngx_peer_connection_t *pc)
{
    ngx_str_t                                sess_id;
    ngx_uint_t                               i;
    ngx_sticky_sess_t                        sess;
    ngx_stream_session_t                    *s;
    ngx_stream_complex_value_t              *vars;
    ngx_stream_upstream_sticky_srv_conf_t   *scf;

#if (NGX_SUPPRESS_WARN)
    ngx_str_null(&sess_id);
#endif

    s = pc->ctx;

    scf = sp->conf;

    vars = scf->create_vars.elts;

    for (i = 0; i < scf->create_vars.nelts; i++) {

        if (ngx_stream_complex_value(s, &vars[i], &sess_id) != NGX_OK) {
            return;
        }

        if (sess_id.len == 0) {
            continue;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "sticky: extracted sess_id %V from variable %ui",
                       &sess_id, i);

        ngx_sticky_learn_init_sess(&sess, &sess_id, 1);
        ngx_sticky_learn_session(scf->learn_zone, &sess, &pc->sid);

        return;
    }

    if (sp->hint.len == 0) {
        return;
    }

    ngx_sticky_learn_init_sess(&sess, &sp->hint, 1);
    ngx_sticky_learn_update_session(scf->learn_zone, &sess, &pc->sid);
}
