
/*
 * Copyright (C) 2023 Web Server LLC
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <float.h>
#include <math.h>


#define NGX_HTTP_UPSTREAM_LEAST_TIME_HEADER     0
#define NGX_HTTP_UPSTREAM_LEAST_TIME_LAST_BYTE  1


typedef struct {
    ngx_int_t                       account_var;
    ngx_uint_t                      mode;
    ngx_uint_t                      factor;
    ngx_uint_t                      use_stat; /* unsigned  use_stat:1; */
} ngx_http_upstream_least_time_srv_conf_t;


typedef struct {
    ngx_event_notify_peer_pt        original_notify_peer;
    ngx_event_free_peer_pt          original_free_peer;
} ngx_http_upstream_least_time_peer_data_t;


static ngx_int_t ngx_http_upstream_init_least_time_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_least_time_peer(
    ngx_peer_connection_t *pc, void *data);
static ngx_int_t ngx_http_upstream_check_account(ngx_http_request_t *r);
static void ngx_http_upstream_notify_least_time_peer(
    ngx_peer_connection_t *pc, void *data, ngx_uint_t type);
static void ngx_http_upstream_free_least_time_peer(
    ngx_peer_connection_t *pc, void *data, ngx_uint_t state);

static void *ngx_http_upstream_least_time_create_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_least_time(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_upstream_least_time_commands[] = {

    { ngx_string("least_time"),
      NGX_HTTP_UPS_CONF|NGX_CONF_1MORE,
      ngx_http_upstream_least_time,
      NGX_HTTP_SRV_CONF_OFFSET,
      0, NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_least_time_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_upstream_least_time_create_conf, /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_least_time_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_least_time_module_ctx, /* module context */
    ngx_http_upstream_least_time_commands, /* module directives */
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


static ngx_int_t
ngx_http_upstream_init_least_time(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_upstream_least_time_srv_conf_t  *ltcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "init least time");

    if (ngx_http_upstream_init_round_robin(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    ltcf = ngx_http_conf_upstream_srv_conf(us,
                                           ngx_http_upstream_least_time_module);

    /*
     * Earlier least_time module used "response_time_factor" directive to get
     * factor (it's part of average calculation formula).  Now least_time module
     * has its own factor value.  So module will roll back to the value of
     * "response_time_factor" if local "factor=<num>" is not defined.
     */
    ngx_conf_init_uint_value(ltcf->factor, us->rt_factor);

    /*
     * The rr balancer collects statistics for response_time and header_time
     * using us->rt_factor.  If we consider client requests only but not probes
     * and balancing factor is equal to statistics factor then it's not
     * necessary to calculate our own average value.  The statistics can be used
     * instead.
     */
    if (ltcf->account_var == NGX_CONF_UNSET && ltcf->factor == us->rt_factor) {
        ltcf->use_stat = 1;
    }

    us->peer.init = ngx_http_upstream_init_least_time_peer;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_init_least_time_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_upstream_least_time_srv_conf_t   *ltcf;
    ngx_http_upstream_least_time_peer_data_t  *ltp;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "init least time peer");

    ltcf = ngx_http_conf_upstream_srv_conf(us,
                                           ngx_http_upstream_least_time_module);

    if (ngx_http_upstream_init_round_robin_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    r->upstream->peer.get = ngx_http_upstream_get_least_time_peer;

    if (ltcf->mode == NGX_HTTP_UPSTREAM_LEAST_TIME_HEADER) {
        r->upstream->peer.notify_mask |= NGX_HTTP_UPSTREAM_NOTIFY_HEADER;
    }

    if (ltcf->use_stat) {
        return NGX_OK;
    }

    ltp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_least_time_peer_data_t));
    if (ltp == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ltp, ngx_http_upstream_least_time_module);

    if (ltcf->mode == NGX_HTTP_UPSTREAM_LEAST_TIME_HEADER) {
        ltp->original_notify_peer = r->upstream->peer.notify;
        r->upstream->peer.notify = ngx_http_upstream_notify_least_time_peer;

    /* NGX_HTTP_UPSTREAM_LEAST_TIME_LAST_BYTE */
    } else {
        ltp->original_free_peer = r->upstream->peer.free;
        r->upstream->peer.free = ngx_http_upstream_free_least_time_peer;
    }

    return NGX_OK;
}


static ngx_inline double
ngx_http_upstream_get_least_time(ngx_http_upstream_least_time_srv_conf_t *ltcf,
    ngx_http_upstream_rr_peer_t *peer)
{
    if (!ltcf->use_stat) {
        return peer->average;
    }

    return (ltcf->mode == NGX_HTTP_UPSTREAM_LEAST_TIME_HEADER)
           ? peer->header_time : peer->response_time;
}


static ngx_int_t
ngx_http_upstream_get_least_time_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_rr_peer_data_t  *rrp = data;

    ngx_http_upstream_least_time_srv_conf_t  *ltcf;

    double                         rt, range, rnd, min_portion;
    double                         active_sum, val, last_average;
    ngx_int_t                      rc;
    ngx_uint_t                     i, active_num;
    ngx_http_request_t            *r;
    ngx_http_upstream_rr_peer_t   *peer, *best;
    ngx_http_upstream_rr_peers_t  *peers;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get least time peer, try: %ui", pc->tries);

    if (rrp->peers->single) {
        return ngx_http_upstream_get_round_robin_peer(pc, rrp);
    }

    r = pc->ctx;

    ltcf = ngx_http_conf_upstream_srv_conf(r->upstream->upstream,
                                           ngx_http_upstream_least_time_module);

    pc->cached = 0;
    pc->connection = NULL;

    best = NULL;

    peers = rrp->peers;

    ngx_http_upstream_rr_peers_wlock(peers);

    if (ngx_http_upstream_conf_changed(peers, rrp)) {
        ngx_http_upstream_rr_peers_unlock(peers);
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
        if (!ngx_http_upstream_rr_peer_ready(rrp, peer, i)) {
            continue;
        }

        rt = ngx_http_upstream_get_least_time(ltcf, peer);

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0, "least time (get): "
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
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                           "get least time peer, recalculate");
            goto again;
        }
    }

    if (range == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "get least time peer, no peer found");

        goto failed;
    }

    rnd = (double) ngx_random() / (1U << 31) * range;

    for (peer = peers->peer, i = 0;
         peer;
         peer = peer->next, i++)
    {
        if (!ngx_http_upstream_rr_peer_ready(rrp, peer, i)) {
            continue;
        }

        rt = ngx_http_upstream_get_least_time(ltcf, peer);

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

    ngx_http_upstream_use_rr_peer(pc, rrp, best, i);

    ngx_http_upstream_rr_peers_unlock(peers);

    return NGX_OK;

failed:

    ngx_http_upstream_rr_peers_unlock(peers);

    if (peers->next) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "get least time peer, backup servers");

        rrp->peers = peers->next;

        ngx_http_upstream_rr_reset_tried(rrp, rrp->peers->number);

        rc = ngx_http_upstream_get_least_time_peer(pc, rrp);

        if (rc != NGX_BUSY) {
            return rc;
        }
    }

busy:

    pc->name = peers->name;

    return NGX_BUSY;
}


static ngx_int_t
ngx_http_upstream_check_account(ngx_http_request_t *r)
{
    ngx_http_variable_value_t                *a;
    ngx_http_upstream_least_time_srv_conf_t  *ltcf;

    ltcf = ngx_http_conf_upstream_srv_conf(r->upstream->upstream,
                                           ngx_http_upstream_least_time_module);

    if (ltcf->account_var == NGX_CONF_UNSET) {
        return NGX_OK;
    }

    a = ngx_http_get_indexed_variable(r, ltcf->account_var);

    if (a == NULL || a->not_found || a->len == 0
        || (a->len == 1 && a->data[0] == '0'))
    {
        return NGX_DECLINED;
    }

    return NGX_OK;
}


static ngx_inline void
ngx_http_upstream_least_time_avg(double *avg, ngx_msec_t v, ngx_uint_t factor)
{
    *avg = (*avg > 0) ? (*avg * factor + v * (100 - factor)) / 100 : v;

    if (*avg == 0) {
        *avg = 1;
    }
}


static void
ngx_http_upstream_free_least_time_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state)
{
    ngx_http_upstream_rr_peer_data_t  *rrp = data;

    ngx_connection_t                          *c;
    ngx_event_pipe_t                          *p;
    ngx_http_request_t                        *r;
    ngx_http_upstream_t                       *u;
    ngx_http_upstream_rr_peer_t               *peer;
    ngx_http_upstream_least_time_srv_conf_t   *ltcf;
    ngx_http_upstream_least_time_peer_data_t  *ltp;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "least time: free peer");

    r = pc->ctx;

    if (state & (NGX_PEER_FAILED | NGX_PEER_NEXT)) {
        goto done;
    }

    u = r->upstream;

    if (u->state->header_time == (ngx_msec_t) -1) {
        goto done;
    }

    c = pc->connection;

    if (u->buffering) {
        p = u->pipe;

        if (!p->upstream_done && !(p->upstream_eof && p->length == -1)) {
            goto done;
        }

    } else if (u->length != 0 && !(c->read->eof && u->length == -1)) {
        goto done;
    }

    if (ngx_http_upstream_check_account(r) != NGX_OK) {
        goto done;
    }

    peer = rrp->current;

    ltcf = ngx_http_conf_upstream_srv_conf(u->upstream,
                                           ngx_http_upstream_least_time_module);

    ngx_http_upstream_rr_peers_rlock(rrp->peers);
    ngx_http_upstream_rr_peer_lock(rrp->peers, peer);

    ngx_http_upstream_least_time_avg(&peer->average, u->state->response_time,
                                     ltcf->factor);

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, pc->log, 0, "least time (response): "
                   "peer: %V, value: %M, avg: %.6f, probe: %s",
                   &peer->server, u->state->response_time, peer->average,
                   r->health_check ? "y" : "n");

    ngx_http_upstream_rr_peer_unlock(rrp->peers, peer);
    ngx_http_upstream_rr_peers_unlock(rrp->peers);

done:

    ltp = ngx_http_get_module_ctx(r, ngx_http_upstream_least_time_module);

    if (ltp && ltp->original_free_peer) {
        ltp->original_free_peer(pc, rrp, state);
    }
}


static void
ngx_http_upstream_notify_least_time_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t type)
{
    ngx_http_upstream_rr_peer_data_t  *rrp = data;

    ngx_http_request_t                        *r;
    ngx_http_upstream_t                       *u;
    ngx_http_upstream_rr_peer_t               *peer;
    ngx_http_upstream_least_time_srv_conf_t   *ltcf;
    ngx_http_upstream_least_time_peer_data_t  *ltp;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "least time: notify peer");

    r = pc->ctx;

    if (!(type & NGX_HTTP_UPSTREAM_NOTIFY_HEADER)) {
        goto done;
    }

    if (ngx_http_upstream_check_account(r) != NGX_OK) {
        goto done;
    }

    u = r->upstream;
    peer = rrp->current;

    ltcf = ngx_http_conf_upstream_srv_conf(u->upstream,
                                           ngx_http_upstream_least_time_module);

    ngx_http_upstream_rr_peers_rlock(rrp->peers);
    ngx_http_upstream_rr_peer_lock(rrp->peers, peer);

    ngx_http_upstream_least_time_avg(&peer->average, u->state->header_time,
                                     ltcf->factor);

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, pc->log, 0, "least time (header): "
                   "peer: %V, value: %M, avg: %.6f, probe: %s",
                   &peer->server, u->state->header_time, peer->average,
                   r->health_check ? "y" : "n");

    ngx_http_upstream_rr_peer_unlock(rrp->peers, peer);
    ngx_http_upstream_rr_peers_unlock(rrp->peers);

done:

    ltp = ngx_http_get_module_ctx(r, ngx_http_upstream_least_time_module);

    if (ltp && ltp->original_notify_peer) {
        ltp->original_notify_peer(pc, rrp, type);
    }
}


static void *
ngx_http_upstream_least_time_create_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_least_time_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool,
                       sizeof(ngx_http_upstream_least_time_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->mode = NGX_CONF_UNSET_UINT;
    conf->factor = NGX_CONF_UNSET_UINT;
    conf->account_var = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_upstream_least_time(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                                *value, name;
    ngx_int_t                                 factor;
    ngx_uint_t                                i;
    ngx_http_upstream_srv_conf_t             *uscf;
    ngx_http_upstream_least_time_srv_conf_t  *ltcf;

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    if (uscf->peer.init_upstream) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "load balancing method redefined");
    }

    uscf->peer.init_upstream = ngx_http_upstream_init_least_time;

    uscf->flags = NGX_HTTP_UPSTREAM_CREATE
                  |NGX_HTTP_UPSTREAM_CONF
                  |NGX_HTTP_UPSTREAM_MAX_CONNS
                  |NGX_HTTP_UPSTREAM_MAX_FAILS
                  |NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
                  |NGX_HTTP_UPSTREAM_DOWN
                  |NGX_HTTP_UPSTREAM_BACKUP;

    value = cf->args->elts;
    ltcf = conf;
    i = 1;

    /* parse balancer mode */
    if (ngx_strcmp(value[i].data, "header") == 0) {
        ltcf->mode = NGX_HTTP_UPSTREAM_LEAST_TIME_HEADER;

    } else if (ngx_strcmp(value[i].data, "last_byte") == 0) {
        ltcf->mode = NGX_HTTP_UPSTREAM_LEAST_TIME_LAST_BYTE;

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

            ltcf->account_var = ngx_http_get_variable_index(cf, &name);

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
