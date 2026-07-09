
/*
 * Copyright (C) 2023 Web Server LLC
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <float.h>
#include <math.h>


#define NGX_STREAM_UPSTREAM_LEAST_TIME_CONNECT                                \
    offsetof(ngx_stream_upstream_rr_peer_t, connect_time)
#define NGX_STREAM_UPSTREAM_LEAST_TIME_FIRST_BYTE                             \
    offsetof(ngx_stream_upstream_rr_peer_t, first_byte_time)
#define NGX_STREAM_UPSTREAM_LEAST_TIME_LAST_BYTE                              \
    offsetof(ngx_stream_upstream_rr_peer_t, response_time)


typedef struct {
    ngx_int_t                       account_var;
    size_t                          mode;
    ngx_uint_t                      factor;
    ngx_uint_t                      use_stat; /* unsigned  use_stat:1; */
} ngx_stream_upstream_least_time_srv_conf_t;


typedef struct {
    ngx_event_notify_peer_pt        original_notify_peer;
    ngx_event_free_peer_pt          original_free_peer;
} ngx_stream_upstream_least_time_peer_data_t;


static ngx_int_t ngx_stream_upstream_init_least_time_peer(
    ngx_stream_session_t *s, ngx_stream_upstream_srv_conf_t *us);
static ngx_int_t ngx_stream_upstream_get_least_time_peer(
    ngx_peer_connection_t *pc, void *data);
static ngx_int_t ngx_stream_upstream_check_account(ngx_stream_session_t *s);
static void ngx_stream_upstream_notify_least_time_peer(
    ngx_peer_connection_t *pc, void *data, ngx_uint_t type);
static void ngx_stream_upstream_free_least_time_peer(
    ngx_peer_connection_t *pc, void *data, ngx_uint_t state);

static void *ngx_stream_upstream_least_time_create_conf(ngx_conf_t *cf);
static char *ngx_stream_upstream_least_time(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_stream_upstream_least_time_commands[] = {

    { ngx_string("least_time"),
      NGX_STREAM_UPS_CONF|NGX_CONF_1MORE,
      ngx_stream_upstream_least_time,
      NGX_STREAM_SRV_CONF_OFFSET,
      0, NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_upstream_least_time_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_stream_upstream_least_time_create_conf,
                                           /* create server configuration */
    NULL                                   /* merge server configuration */
};


ngx_module_t  ngx_stream_upstream_least_time_module = {
    NGX_MODULE_V1,
    &ngx_stream_upstream_least_time_module_ctx, /* module context */
    ngx_stream_upstream_least_time_commands,    /* module directives */
    NGX_STREAM_MODULE,                          /* module type */
    NULL,                                       /* init master */
    NULL,                                       /* init module */
    NULL,                                       /* init process */
    NULL,                                       /* init thread */
    NULL,                                       /* exit thread */
    NULL,                                       /* exit process */
    NULL,                                       /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_stream_upstream_init_least_time(ngx_conf_t *cf,
    ngx_stream_upstream_srv_conf_t *us)
{
    ngx_stream_upstream_least_time_srv_conf_t  *ltcf;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, cf->log, 0,
                   "init least time");

    if (ngx_stream_upstream_init_round_robin(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    ltcf = ngx_stream_conf_upstream_srv_conf(us,
                                         ngx_stream_upstream_least_time_module);

    /*
     * Earlier least_time module used "response_time_factor" directive to get
     * factor (it's part of average calculation formula).  Now least_time module
     * has its own factor value.  So module will roll back to the value of
     * "response_time_factor" if local "factor=<num>" is not defined.
     */
    ngx_conf_init_uint_value(ltcf->factor, us->rt_factor);

    /*
     * The rr balancer collects statistics using us->rt_factor.  If we
     * consider client requests only but not probes and balancing factor is
     * equal to the statistics factor then it's not necessary to calculate our
     * own average value.  The statistics can be used instead.
     */
    if (ltcf->account_var == NGX_CONF_UNSET && ltcf->factor == us->rt_factor) {
        ltcf->use_stat = 1;
    }

    us->peer.init = ngx_stream_upstream_init_least_time_peer;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_upstream_init_least_time_peer(ngx_stream_session_t *s,
    ngx_stream_upstream_srv_conf_t *us)
{
    ngx_stream_upstream_least_time_srv_conf_t   *ltcf;
    ngx_stream_upstream_least_time_peer_data_t  *ltp;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "init least time peer");

    ltcf = ngx_stream_conf_upstream_srv_conf(us,
                                        ngx_stream_upstream_least_time_module);

    if (ngx_stream_upstream_init_round_robin_peer(s, us) != NGX_OK) {
        return NGX_ERROR;
    }

    s->upstream->peer.get = ngx_stream_upstream_get_least_time_peer;

    if (ltcf->mode == NGX_STREAM_UPSTREAM_LEAST_TIME_FIRST_BYTE) {
        s->upstream->peer.notify_mask |=
                                      NGX_STREAM_UPSTREAM_NOTIFY_RESPONSE_BEGIN;

    } else if (ltcf->mode == NGX_STREAM_UPSTREAM_LEAST_TIME_CONNECT) {
        s->upstream->peer.notify_mask |= NGX_STREAM_UPSTREAM_NOTIFY_CONNECT;
    }

    if (ltcf->use_stat) {
        return NGX_OK;
    }

    ltp = ngx_palloc(s->connection->pool,
                     sizeof(ngx_stream_upstream_least_time_peer_data_t));
    if (ltp == NULL) {
        return NGX_ERROR;
    }

    ngx_stream_set_ctx(s, ltp, ngx_stream_upstream_least_time_module);

    ltp->original_notify_peer = s->upstream->peer.notify;
    ltp->original_free_peer = s->upstream->peer.free;

    if (ltcf->mode == NGX_STREAM_UPSTREAM_LEAST_TIME_LAST_BYTE) {
        s->upstream->peer.free = ngx_stream_upstream_free_least_time_peer;

    } else {
        s->upstream->peer.notify = ngx_stream_upstream_notify_least_time_peer;
    }

    return NGX_OK;
}


static ngx_inline double
ngx_stream_upstream_get_least_time(
    ngx_stream_upstream_least_time_srv_conf_t *ltcf,
    ngx_stream_upstream_rr_peer_t *peer)
{
    if (!ltcf->use_stat) {
        return peer->average;
    }

    /*
     * The macros NGX_STREAM_UPSTREAM_LEAST_TIME_CONNECT, etc. are not just an
     * arbitrary numbers but contain offset of correspondent structure's field
     * so "mode" actually is an appropriate offset.
     */
    return (double) *((ngx_msec_t *) ((uintptr_t) peer + ltcf->mode));
}


static ngx_int_t
ngx_stream_upstream_get_least_time_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_stream_upstream_rr_peer_data_t  *rrp = data;

    ngx_stream_upstream_least_time_srv_conf_t  *ltcf;

    double                           rt, range, rnd, min_portion;
    double                           active_sum, val, last_average;
    ngx_int_t                        rc;
    ngx_uint_t                       i, active_num;
    ngx_stream_session_t            *s;
    ngx_stream_upstream_rr_peer_t   *peer, *best;
    ngx_stream_upstream_rr_peers_t  *peers;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                   "get least time peer, try: %ui", pc->tries);

    if (rrp->peers->single) {
        return ngx_stream_upstream_get_round_robin_peer(pc, rrp);
    }

    s = pc->ctx;

    ltcf = ngx_stream_conf_upstream_srv_conf(s->upstream->upstream,
                                        ngx_stream_upstream_least_time_module);

    pc->cached = 0;
    pc->connection = NULL;

    best = NULL;

    peers = rrp->peers;

    ngx_stream_upstream_rr_peers_wlock(peers);

    if (ngx_stream_upstream_conf_changed(peers, rrp)) {
        ngx_stream_upstream_rr_peers_unlock(peers);
        goto busy;
    }

again:

    active_num = 0;
    active_sum = 0;
    range = 0;
    last_average = peers->last_average;
    min_portion = (last_average <= 0 ? 1 : 1.0 / last_average)
                  / 100 / peers->number;

    for (peer = peers->peer, i = 0;
         peer;
         peer = peer->next, i++)
    {
        if (!ngx_stream_upstream_rr_peer_ready(rrp, peer, i)) {
            continue;
        }

        rt = ngx_stream_upstream_get_least_time(ltcf, peer);

        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, pc->log, 0, "least time (get): "
                       "peer: %V, rt: %.6f", &peer->server, rt);

        if (rt <= 0) {
            val = (last_average == 0) ? (DBL_MAX / 2) : (1.0 / last_average);

        } else {
            val = 1.0 / rt;

            /* calculate last average for the active values only */
            active_sum += rt / peers->number;
            active_num++;
        }

        /* divide by peers->number to prevent overflow */
        val = val / peers->number;
        val = ngx_max(val, min_portion);

        range += val;
    }

    if (active_num > 0) {
        /* correct sum of averages due to number of active (not total) peers */
        peers->last_average = active_sum / active_num * peers->number;

        /* last_average value is critically out of date so recalculate */
        if (last_average == 0 && peers->last_average > 0) {
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                           "get least time peer, recalculate");
            goto again;
        }
    }

    if (range == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "get least time peer, no peer found");

        goto failed;
    }

    rnd = (double) ngx_random() / (1U << 31) * range;

    for (peer = peers->peer, i = 0;
         peer;
         peer = peer->next, i++)
    {
        if (!ngx_stream_upstream_rr_peer_ready(rrp, peer, i)) {
            continue;
        }

        rt = ngx_stream_upstream_get_least_time(ltcf, peer);

        if (rt <= 0) {
            val = (last_average == 0) ? (DBL_MAX / 2) : (1.0 / last_average);

        } else {
            val = 1.0 / rt;
        }

        val = val / peers->number;
        val = ngx_max(val, min_portion);

        if (rnd < val) {
            best = peer;
            goto found;
        }

        rnd -= val;
    }

    goto failed;

found:

    ngx_stream_upstream_use_rr_peer(pc, rrp, best, i);

    ngx_stream_upstream_rr_peers_unlock(peers);

    return NGX_OK;

failed:

    if (peers->next) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "get least time peer, backup servers");

        rrp->peers = peers->next;

        ngx_stream_upstream_rr_reset_tried(rrp, rrp->peers->number);

        ngx_stream_upstream_rr_peers_unlock(peers);

        rc = ngx_stream_upstream_get_least_time_peer(pc, rrp);

        if (rc != NGX_BUSY) {
            return rc;
        }
    }

busy:

    pc->name = peers->name;

    return NGX_BUSY;
}


static ngx_int_t
ngx_stream_upstream_check_account(ngx_stream_session_t *s)
{
    ngx_stream_variable_value_t                *a;
    ngx_stream_upstream_least_time_srv_conf_t  *ltcf;

    ltcf = ngx_stream_conf_upstream_srv_conf(s->upstream->upstream,
                                         ngx_stream_upstream_least_time_module);

    if (ltcf->account_var == NGX_CONF_UNSET) {
        return NGX_OK;
    }

    a = ngx_stream_get_indexed_variable(s, ltcf->account_var);

    if (a == NULL || a->not_found || a->len == 0
        || (a->len == 1 && a->data[0] == '0'))
    {
        return NGX_DECLINED;
    }

    return NGX_OK;
}


static ngx_inline void
ngx_stream_upstream_least_time_avg(double *avg, ngx_msec_t v, ngx_uint_t factor)
{
    *avg = (*avg > 0) ? (*avg * factor + v * (100 - factor)) / 100 : v;

    if (*avg == 0) {
        *avg = 1;
    }
}


static void
ngx_stream_upstream_free_least_time_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state)
{
    ngx_stream_upstream_rr_peer_data_t  *rrp = data;

    ngx_stream_session_t                        *s;
    ngx_stream_upstream_t                       *u;
    ngx_stream_upstream_rr_peer_t               *peer;
    ngx_stream_upstream_least_time_srv_conf_t   *ltcf;
    ngx_stream_upstream_least_time_peer_data_t  *ltp;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                   "least time: free peer");

    s = pc->ctx;

    if (state & NGX_PEER_FAILED) {
        goto done;
    }

    u = s->upstream;

    if (u->state->connect_time == (ngx_msec_t) -1) {
        goto done;
    }

    if (ngx_stream_upstream_check_account(s) != NGX_OK) {
        goto done;
    }

    peer = rrp->current;

    ltcf = ngx_stream_conf_upstream_srv_conf(u->upstream,
                                         ngx_stream_upstream_least_time_module);

    ngx_stream_upstream_rr_peers_rlock(rrp->peers);
    ngx_stream_upstream_rr_peer_lock(rrp->peers, peer);

    ngx_stream_upstream_least_time_avg(&peer->average,
                                       u->state->response_time, ltcf->factor);

    ngx_log_debug4(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                   "least time (response): "
                   "peer: %V, value: %M, avg: %.6f, probe: %s",
                   &peer->server, u->state->response_time, peer->average,
                   s->health_check ? "y" : "n");

    ngx_stream_upstream_rr_peer_unlock(rrp->peers, peer);
    ngx_stream_upstream_rr_peers_unlock(rrp->peers);

done:

    ltp = ngx_stream_get_module_ctx(s, ngx_stream_upstream_least_time_module);

    if (ltp && ltp->original_free_peer) {
        ltp->original_free_peer(pc, rrp, state);
    }
}


static void
ngx_stream_upstream_notify_least_time_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t type)
{
    ngx_stream_upstream_rr_peer_data_t  *rrp = data;

    ngx_stream_session_t                        *s;
    ngx_stream_upstream_t                       *u;
    ngx_stream_upstream_rr_peer_t               *peer;
    ngx_stream_upstream_least_time_srv_conf_t   *ltcf;
    ngx_stream_upstream_least_time_peer_data_t  *ltp;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                   "least time: notify peer");

    s = pc->ctx;

    if (!(type & (NGX_STREAM_UPSTREAM_NOTIFY_CONNECT
                 | NGX_STREAM_UPSTREAM_NOTIFY_RESPONSE_BEGIN)))
    {
        goto done;
    }

    if (ngx_stream_upstream_check_account(s) != NGX_OK) {
        goto done;
    }

    u = s->upstream;
    peer = rrp->current;

    ltcf = ngx_stream_conf_upstream_srv_conf(u->upstream,
                                         ngx_stream_upstream_least_time_module);

    ngx_stream_upstream_rr_peers_rlock(rrp->peers);
    ngx_stream_upstream_rr_peer_lock(rrp->peers, peer);

    if (type & NGX_STREAM_UPSTREAM_NOTIFY_CONNECT) {
        ngx_stream_upstream_least_time_avg(&peer->average,
                                          u->state->connect_time, ltcf->factor);

        ngx_log_debug4(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "least time (connect): "
                       "peer: %V, value: %M, avg: %.6f, probe: %s",
                       &peer->server, u->state->connect_time, peer->average,
                       s->health_check ? "y" : "n");

    /* NGX_STREAM_UPSTREAM_NOTIFY_RESPONSE_BEGIN */
    } else {
        ngx_stream_upstream_least_time_avg(&peer->average,
                                       u->state->first_byte_time, ltcf->factor);

        ngx_log_debug4(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "least time (first_byte): "
                       "peer: %V, value: %M, avg: %.6f, probe: %s",
                       &peer->server, u->state->first_byte_time, peer->average,
                       s->health_check ? "y" : "n");
    }

    ngx_stream_upstream_rr_peer_unlock(rrp->peers, peer);
    ngx_stream_upstream_rr_peers_unlock(rrp->peers);

done:

    ltp = ngx_stream_get_module_ctx(s, ngx_stream_upstream_least_time_module);

    if (ltp && ltp->original_notify_peer) {
        ltp->original_notify_peer(pc, rrp, type);
    }
}


static void *
ngx_stream_upstream_least_time_create_conf(ngx_conf_t *cf)
{
    ngx_stream_upstream_least_time_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool,
                       sizeof(ngx_stream_upstream_least_time_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->account_var = NGX_CONF_UNSET;
    conf->mode = NGX_CONF_UNSET_SIZE;
    conf->factor = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_stream_upstream_least_time(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                                  *value, name;
    ngx_int_t                                   factor;
    ngx_uint_t                                  i;
    ngx_stream_upstream_srv_conf_t             *uscf;
    ngx_stream_upstream_least_time_srv_conf_t  *ltcf;

    uscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_upstream_module);

    if (uscf->peer.init_upstream) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "load balancing method redefined");
    }

    uscf->peer.init_upstream = ngx_stream_upstream_init_least_time;

    uscf->flags = NGX_STREAM_UPSTREAM_CREATE
                  |NGX_STREAM_UPSTREAM_CONF
                  |NGX_STREAM_UPSTREAM_MAX_CONNS
                  |NGX_STREAM_UPSTREAM_MAX_FAILS
                  |NGX_STREAM_UPSTREAM_FAIL_TIMEOUT
                  |NGX_STREAM_UPSTREAM_DOWN
                  |NGX_STREAM_UPSTREAM_BACKUP;

    value = cf->args->elts;
    ltcf = conf;
    i = 1;

    /* parse balancer mode */
    if (ngx_strcmp(value[i].data, "connect") == 0) {
        ltcf->mode = NGX_STREAM_UPSTREAM_LEAST_TIME_CONNECT;

    } else if (ngx_strcmp(value[i].data, "first_byte") == 0) {
        ltcf->mode = NGX_STREAM_UPSTREAM_LEAST_TIME_FIRST_BYTE;

    } else if (ngx_strcmp(value[i].data, "last_byte") == 0) {
        ltcf->mode = NGX_STREAM_UPSTREAM_LEAST_TIME_LAST_BYTE;

    } else {
        goto invalid;
    }

    /* parse optional arguments */
    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "factor=", 7) == 0) {

            factor = ngx_atoi(&value[i].data[7], value[i].len - 7);

            if (factor == NGX_ERROR || factor >= 100) {
                goto invalid;
            }

            ltcf->factor = factor;

            continue;
        }

        if (ngx_strncmp(value[i].data, "account=", 8) == 0) {

            name = value[i];
            name.len -= 8;
            name.data += 8;

            if (name.data[0] != '$') {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                              "variable expected as the \"account\" argument");
                return NGX_CONF_ERROR;
            }

            name.len--;
            name.data++;

            ltcf->account_var = ngx_stream_get_variable_index(cf, &name);

            if (ltcf->account_var == NGX_ERROR) {
                goto invalid;
            }

            continue;
        }

        goto invalid;
    }

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[i]);

    return NGX_CONF_ERROR;
}
