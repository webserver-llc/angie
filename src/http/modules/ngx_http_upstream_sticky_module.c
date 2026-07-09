
/*
 * Copyright (C) 2023 Web Server LLC
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_sticky.h>


#define NGX_HTTP_STICKY_COOKIE_MAX_EXPIRES  2145916555


typedef struct {
    ngx_array_t                                stickies; /* of shm_zone_t* */
} ngx_http_upstream_sticky_main_conf_t;


typedef struct {
    ngx_str_t                                  cookie;
    ngx_array_t                                cookie_attrs;
    time_t                                     cookie_expires;
    ngx_array_t                                lookup_vars;
    ngx_array_t                                create_vars;
    ngx_http_complex_value_t                  *secret;
    ngx_flag_t                                 strict;
    ngx_flag_t                                 header;
    ngx_flag_t                                 refresh;

    ngx_http_upstream_init_pt                  original_init_upstream;
    ngx_http_upstream_init_peer_pt             original_init_peer;

    ngx_shm_zone_t                            *learn_zone;
} ngx_http_upstream_sticky_srv_conf_t;


typedef struct {
    ngx_http_upstream_sticky_srv_conf_t       *conf;

    ngx_str_t                                  hint;
    ngx_str_t                                  salt;

    ngx_table_elt_t                           *set_cookie;

    ngx_event_get_peer_pt                      original_get_peer;
    ngx_event_free_peer_pt                     original_free_peer;
    ngx_event_notify_peer_pt                   original_notify_peer;

    ngx_sticky_sess_t                         *learn_sess;
} ngx_http_upstream_sticky_peer_data_t;


static ngx_int_t ngx_http_upstream_sticky_select_peer(
    ngx_http_upstream_rr_peer_data_t *rrp,
    ngx_http_upstream_sticky_peer_data_t *sp, ngx_peer_connection_t *pc,
    ngx_str_t *hint);
static ngx_int_t ngx_http_upstream_init_sticky(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_init_sticky_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_sticky_peer(ngx_peer_connection_t *pc,
    void *data);
static ngx_int_t ngx_http_upstream_sticky_set_cookie(ngx_http_request_t *r,
    ngx_http_upstream_sticky_srv_conf_t *scf,
    ngx_http_upstream_sticky_peer_data_t *sp, ngx_str_t *sid);

static void *ngx_http_upstream_sticky_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_upstream_sticky_create_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_sticky(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_upstream_sticky_cookie(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_upstream_sticky_add_cv(ngx_conf_t *cf,
    ngx_array_t *values, ngx_str_t *value);
static char *ngx_http_upstream_sticky_route(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static void ngx_http_upstream_free_sticky_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);
static void ngx_http_upstream_notify_sticky_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t type);
static char *ngx_http_upstream_sticky_learn(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_int_t ngx_http_upstream_sticky_init_worker(ngx_cycle_t *cycle);
static void ngx_http_upstream_sticky_process_session(
    ngx_http_upstream_sticky_peer_data_t *sp, ngx_peer_connection_t *pc);

static u_char ngx_http_upstream_sticky_cookie_expires[] =
    "; expires=Thu, 31-Dec-37 23:55:55 GMT; max-age=315360000";

static ngx_command_t  ngx_http_upstream_sticky_commands[] = {

    { ngx_string("sticky"),
      NGX_HTTP_UPS_CONF|NGX_CONF_2MORE,
      ngx_http_upstream_sticky,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("sticky_secret"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_upstream_sticky_srv_conf_t, secret),
      NULL },

    { ngx_string("sticky_strict"),
      NGX_HTTP_UPS_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_upstream_sticky_srv_conf_t, strict),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_sticky_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    ngx_http_upstream_sticky_create_main_conf, /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_upstream_sticky_create_conf,  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_sticky_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_sticky_module_ctx,  /* module context */
    ngx_http_upstream_sticky_commands,     /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_upstream_sticky_init_worker,  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_upstream_sticky_select_peer(ngx_http_upstream_rr_peer_data_t *rrp,
    ngx_http_upstream_sticky_peer_data_t *sp, ngx_peer_connection_t *pc,
    ngx_str_t *hint)
{
    size_t                         len;
    u_char                        *sid;
    ngx_uint_t                     i;
    ngx_http_request_t            *r;
    ngx_http_upstream_state_t     *us;
    ngx_http_upstream_rr_peer_t   *peer;
    ngx_http_upstream_rr_peers_t  *peers;

    u_char                         buf[NGX_STICKY_SID_LEN];

    r = pc->ctx;

    us = r->upstream->state;

    peers = rrp->peers;

again:

    ngx_http_upstream_rr_peers_rlock(peers);

    if (ngx_http_upstream_conf_changed(peers, rrp)) {
        ngx_http_upstream_rr_peers_unlock(peers);
        return NGX_BUSY;
    }

    for (peer = peers->peer, i = 0;
         peer;
         peer = peer->next, i++)
    {
        ngx_http_upstream_rr_peer_lock(peers, peer);

        /* note the peer_usable() function is used but not peer_ready() */
        if (!ngx_http_upstream_rr_peer_usable(rrp, peer, i)) {
            ngx_http_upstream_rr_peer_unlock(peers, peer);
            continue;
        }

        if (ngx_http_upstream_rr_is_adm_down(peer)) {
            ngx_http_upstream_rr_peer_unlock(peers, peer);
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
            ngx_http_upstream_rr_peer_unlock(rrp->peers, peer);
            continue;
        }

        us->sticky_status = NGX_HTTP_UPSTREAM_STICKY_STATUS_HIT;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "sticky: found matching peer %ui", i);

        ngx_http_upstream_use_rr_peer(pc, rrp, peer, i);

        ngx_http_upstream_rr_peer_unlock(peers, peer);
        ngx_http_upstream_rr_peers_unlock(peers);

        return NGX_OK;
    }

    if (peers->next) {
        ngx_http_upstream_rr_peers_unlock(peers);
        peers = peers->next;
        goto again;
    }

    ngx_http_upstream_rr_peers_unlock(peers);

    us->sticky_status = NGX_HTTP_UPSTREAM_STICKY_STATUS_MISS;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "sticky: no match strict:%i", sp->conf->strict);

    if (sp->conf->strict) {
        pc->name = peers->name;
        return NGX_BUSY;
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_upstream_init_sticky(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
{
    ngx_str_t                          vname;
    ngx_http_complex_value_t          *cv;
    ngx_http_compile_complex_value_t   ccv;

    ngx_http_upstream_sticky_srv_conf_t  *scf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0, "sticky: init");

    scf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_sticky_module);

    ngx_conf_init_value(scf->strict, 0);
    ngx_conf_init_ptr_value(scf->secret, NULL);

    if (scf->original_init_upstream(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    scf->original_init_peer = us->peer.init;

    us->peer.init = ngx_http_upstream_init_sticky_peer;

    if (scf->cookie.len) {

        vname.len = sizeof("$cookie_") - 1 + scf->cookie.len;
        vname.data = ngx_palloc(cf->pool, vname.len);
        if (vname.data == NULL) {
            return NGX_ERROR;
        }

        (void) ngx_sprintf(vname.data, "$cookie_%V", &scf->cookie);

        cv = ngx_array_push(&scf->lookup_vars);
        if (cv == NULL) {
            return NGX_ERROR;
        }

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &vname;
        ccv.complex_value = cv;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_init_sticky_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_uint_t                             i;
    ngx_http_complex_value_t              *vars;
    ngx_http_upstream_sticky_srv_conf_t   *scf;
    ngx_http_upstream_sticky_peer_data_t  *sp;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "sticky: init peer");

    scf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_sticky_module);

    if (scf->original_init_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    sp = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_sticky_peer_data_t));
    if (sp == NULL) {
        return NGX_ERROR;
    }

    sp->conf = scf;

    ngx_http_set_ctx(r, sp, ngx_http_upstream_sticky_module);

    sp->original_get_peer = r->upstream->peer.get;
    r->upstream->peer.get = ngx_http_upstream_get_sticky_peer;

    if (scf->learn_zone) {
        if (scf->header) {
            sp->original_notify_peer = r->upstream->peer.notify;
            r->upstream->peer.notify = ngx_http_upstream_notify_sticky_peer;
            r->upstream->peer.notify_mask |= NGX_HTTP_UPSTREAM_NOTIFY_HEADER;

        } else {
            sp->original_free_peer = r->upstream->peer.free;
            r->upstream->peer.free = ngx_http_upstream_free_sticky_peer;
        }
    }

    sp->hint.len = 0;

    vars = scf->lookup_vars.elts;

    for (i = 0; i < scf->lookup_vars.nelts; i++) {

        if (ngx_http_complex_value(r, &vars[i], &sp->hint) != NGX_OK) {
            return NGX_ERROR;
        }

        if (sp->hint.len == 0) {
            continue;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "sticky: extracted hint \"%V\" from variable %ui",
                       &sp->hint, i);
        break;
    }

    if (scf->secret && !sp->conf->learn_zone) {
        if (ngx_http_complex_value(r, scf->secret, &sp->salt) != NGX_OK) {
            return NGX_ERROR;
        }

    } else {
        sp->salt.len = 0;
    }


    if (scf->learn_zone && sp->hint.len) {
        sp->learn_sess = ngx_pcalloc(r->pool, sizeof(ngx_sticky_sess_t));
        if (sp->learn_sess == NULL) {
            return NGX_ERROR;
        }

        ngx_sticky_learn_init_sess(sp->learn_sess, &sp->hint, 0);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_get_sticky_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_rr_peer_data_t  *rrp = data;

    ngx_int_t                              rc;
    ngx_str_t                              hint;
    ngx_http_request_t                    *r;
    ngx_http_upstream_state_t             *us;
    ngx_http_upstream_sticky_peer_data_t  *sp;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "sticky: get peer");

    r = pc->ctx;

    pc->cached = 0;
    pc->connection = NULL;

    sp = ngx_http_get_module_ctx(r, ngx_http_upstream_sticky_module);

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
        us = r->upstream->state;
        us->sticky_status = NGX_HTTP_UPSTREAM_STICKY_STATUS_NEW;

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "sticky: no hint provided");

    } else {

        rc = ngx_http_upstream_sticky_select_peer(rrp, sp, pc, &hint);

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

    if (sp->conf->cookie.len == 0) {
        /* sticky route or sticky learn */
        return NGX_OK;
    }

    if (ngx_http_upstream_sticky_set_cookie(r, sp->conf, sp, &pc->sid)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_sticky_set_cookie(ngx_http_request_t *r,
    ngx_http_upstream_sticky_srv_conf_t *scf,
    ngx_http_upstream_sticky_peer_data_t *sp, ngx_str_t *sid)
{
    u_char      *p, *cookie, hashed[NGX_STICKY_SID_LEN];
    size_t       len;
    ngx_str_t    value, tmp;
    ngx_uint_t   i;

    ngx_table_elt_t           *set_cookie;
    ngx_http_complex_value_t  *attr;

    if (scf->secret) {
        tmp.data = hashed;
        tmp.len = ngx_sticky_hash(sid, &sp->salt, hashed);

        sid = &tmp;
    }

    len = scf->cookie.len;
    len += sizeof("=") - 1 + sid->len;

    if (scf->cookie_expires != (time_t) NGX_CONF_UNSET) {
        len += sizeof(ngx_http_upstream_sticky_cookie_expires) - 1
               + NGX_TIME_T_LEN;
    }

    attr = scf->cookie_attrs.elts;

    for (i = 0; i < scf->cookie_attrs.nelts; i++) {

        if (ngx_http_complex_value(r, &attr[i], &value) != NGX_OK) {
            return NGX_ERROR;
        }

        if (value.len == 0) {
            continue;
        }

        /* skip "foo=" */
        if (value.data[value.len - 1] == '=') {
            continue;
        }

        len += sizeof("; ") - 1 + value.len;
    }

    cookie = ngx_pnalloc(r->pool, len);
    if (cookie == NULL) {
        return NGX_ERROR;
    }

    p = cookie;

    p = ngx_cpymem(p, scf->cookie.data, scf->cookie.len);
    *p++ = '=';

    p = ngx_cpymem(p, sid->data, sid->len);

    if (scf->cookie_expires != (time_t) NGX_CONF_UNSET) {

        if (scf->cookie_expires == NGX_HTTP_STICKY_COOKIE_MAX_EXPIRES) {
            p = ngx_cpymem(p, ngx_http_upstream_sticky_cookie_expires,
                          sizeof(ngx_http_upstream_sticky_cookie_expires) - 1);

        } else {
            p = ngx_cpymem(p, "; expires=", 10);
            p = ngx_http_cookie_time(p, ngx_time() + scf->cookie_expires);
            p = ngx_sprintf(p, "; max-age=%T", scf->cookie_expires);
        }
    }

    for (i = 0; i < scf->cookie_attrs.nelts; i++) {
        if (ngx_http_complex_value(r, &attr[i], &value) != NGX_OK) {
            return NGX_ERROR;
        }

        if (value.len == 0) {
            continue;
        }

        if (value.data[value.len - 1] == '=') {
            continue;
        }

        p = ngx_cpymem(p, "; ", sizeof("; ") - 1);
        p = ngx_cpymem(p, value.data, value.len);
    }

    set_cookie = sp->set_cookie;

    /* avoid duplicates on proxy_next_upstream etc. */
    if (set_cookie == NULL) {

        set_cookie = ngx_list_push(&r->headers_out.headers);
        if (set_cookie == NULL) {
            return NGX_ERROR;
        }

        set_cookie->hash = 1;
        ngx_str_set(&set_cookie->key, "Set-Cookie");

        sp->set_cookie = set_cookie;
    }

    set_cookie->value.len = p - cookie;
    set_cookie->value.data = cookie;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "sticky: setting cookie \"%V\"", &set_cookie->value);
    return NGX_OK;
}


static void *
ngx_http_upstream_sticky_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_sticky_main_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool,
                       sizeof(ngx_http_upstream_sticky_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static void *
ngx_http_upstream_sticky_create_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_sticky_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool,
                       sizeof(ngx_http_upstream_sticky_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&conf->cookie_attrs, cf->pool, 4,
                       sizeof(ngx_http_complex_value_t))
        != NGX_OK)
    {
        return NULL;
    }

    if (ngx_array_init(&conf->lookup_vars, cf->pool, 4,
                       sizeof(ngx_http_complex_value_t))
        != NGX_OK)
    {
        return NULL;
    }

    if (ngx_array_init(&conf->create_vars, cf->pool, 4,
                       sizeof(ngx_http_complex_value_t))
        != NGX_OK)
    {
        return NULL;
    }

    conf->strict = NGX_CONF_UNSET;
    conf->secret = NGX_CONF_UNSET_PTR;
    conf->refresh = NGX_CONF_UNSET;
    conf->cookie_expires = NGX_CONF_UNSET;
    conf->header = NGX_CONF_UNSET;

    /*
     * set by ngx_pcalloc():
     *
     *     conf->cookie = { 0, NULL };
     *     conf->original_init_upstream = NULL;
     *     conf->original_init_peer = NULL;
     *     conf->learn_zone = NULL;
     */

    return conf;
}


static char *
ngx_http_upstream_sticky(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_sticky_srv_conf_t  *scf = conf;

    char                          *rv;
    ngx_str_t                     *value;
    ngx_http_upstream_srv_conf_t  *uscf;

    value = cf->args->elts;

    if (scf->cookie.len || scf->lookup_vars.nelts) {
        return "is duplicate";
    }

    if (value[1].len == 6
        && ngx_strncmp(value[1].data, "cookie", 6) == 0)
    {
        rv = ngx_http_upstream_sticky_cookie(cf, cmd, conf);

    } else if (value[1].len == 5
               && ngx_strncmp(value[1].data, "route", 5) == 0)
    {
        rv = ngx_http_upstream_sticky_route(cf, cmd, conf);

    } else if (value[1].len == 5
               && ngx_strncmp(value[1].data, "learn", 5) == 0)
    {
        rv = ngx_http_upstream_sticky_learn(cf, cmd, conf);

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "unknown sticky mode \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    scf->original_init_upstream = uscf->peer.init_upstream
                                  ? uscf->peer.init_upstream
                                  : ngx_http_upstream_init_round_robin;

    uscf->peer.init_upstream = ngx_http_upstream_init_sticky;

    return NGX_CONF_OK;
}


static char *
ngx_http_upstream_sticky_cookie(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_sticky_srv_conf_t  *scf = conf;

    ngx_str_t   *value;
    ngx_uint_t   i, has_path;

    static ngx_str_t  default_path = ngx_string("path=/");

    value = cf->args->elts;

    if (value[2].len == 0) {
        return "empty cookie name";
    }

    scf->cookie.data = ngx_pstrdup(cf->pool, &value[2]);
    if (scf->cookie.data == NULL) {
        return NGX_CONF_ERROR;
    }

    scf->cookie.len = value[2].len;

    has_path = 0;

    for (i = 3; i < cf->args->nelts; i++) {

        if (value[i].len >= 5
            && ngx_strncasecmp(value[i].data, (u_char *) "path=", 5) == 0)
        {
            has_path = 1;
        }

        /* nginx compatibility  */
        if (ngx_strncmp(value[i].data, "expires=", 8) == 0) {

            if (scf->cookie_expires != (time_t) NGX_CONF_UNSET) {
                return "parameter \"expires\" is duplicate";
            }

            value[i].data += 8;
            value[i].len -= 8;

            if (ngx_strcmp(value[i].data, "max") == 0) {
                scf->cookie_expires = NGX_HTTP_STICKY_COOKIE_MAX_EXPIRES;

            } else {
                scf->cookie_expires = ngx_parse_time(&value[i], 1);

                if (scf->cookie_expires == (time_t) NGX_ERROR) {

                    ngx_conf_log_error(NGX_LOG_INFO, cf, 0,
                                       "expires= does not look like valid "
                                       "time, falling back to verbatim value");
                    goto fallback;
                }
            }

            continue;
        }

    fallback:

        if (ngx_http_upstream_sticky_add_cv(cf, &scf->cookie_attrs, &value[i])
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    if (!has_path) {
        if (ngx_http_upstream_sticky_add_cv(cf, &scf->cookie_attrs,
                                            &default_path)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_upstream_sticky_add_cv(ngx_conf_t *cf, ngx_array_t *values,
    ngx_str_t *value)
{
    ngx_http_complex_value_t          *cv;
    ngx_http_compile_complex_value_t   ccv;

    cv = ngx_array_push(values);
    if (cv == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = value;
    ccv.complex_value = cv;

    return ngx_http_compile_complex_value(&ccv);
}


static char *
ngx_http_upstream_sticky_route(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_sticky_srv_conf_t  *scf = conf;

    ngx_str_t                         *value;
    ngx_uint_t                         i;
    ngx_http_complex_value_t          *cv;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    for (i = 2; i < cf->args->nelts; i++) {

        cv = ngx_array_push(&scf->lookup_vars);
        if (cv == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[i];
        ccv.complex_value = cv;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static void
ngx_http_upstream_free_sticky_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_http_request_t                    *r;
    ngx_http_upstream_sticky_peer_data_t  *sp;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "sticky: free peer");

    r = pc->ctx;

    sp = ngx_http_get_module_ctx(r, ngx_http_upstream_sticky_module);

    if (!(state & (NGX_PEER_FAILED|NGX_PEER_NEXT))) {
        ngx_http_upstream_sticky_process_session(sp, pc);
    }

    sp->original_free_peer(pc, data, state);
}


static void
ngx_http_upstream_notify_sticky_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t type)
{
    ngx_http_request_t                    *r;
    ngx_http_upstream_sticky_peer_data_t  *sp;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "sticky: notify peer");

    r = pc->ctx;

    sp = ngx_http_get_module_ctx(r, ngx_http_upstream_sticky_module);

    if (type & NGX_HTTP_UPSTREAM_NOTIFY_HEADER) {
        ngx_http_upstream_sticky_process_session(sp, pc);
    }

    if (sp->original_notify_peer) {
        sp->original_notify_peer(pc, data, type);
    }
}


static char *
ngx_http_upstream_sticky_learn(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_sticky_srv_conf_t  *scf = conf;

    u_char                                 *p;
    ssize_t                                 zsize;
    ngx_str_t                               str, *value;
    ngx_msec_t                              timeout;
    ngx_uint_t                              i;
    ngx_shm_zone_t                        **zonep;
    ngx_http_complex_value_t               *cv;
    ngx_http_upstream_srv_conf_t           *us;
    ngx_http_compile_complex_value_t        ccv;
    ngx_http_upstream_sticky_main_conf_t   *smcf;

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

            ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &value[i];
            ccv.complex_value = cv;

            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
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

            ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &value[i];
            ccv.complex_value = cv;

            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
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

        if (ngx_strcmp(value[i].data, "header") == 0) {

            if (scf->header != NGX_CONF_UNSET) {
                return "duplicate header";
            }

            scf->header = 1;
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

    if (timeout == NGX_CONF_UNSET_MSEC) {
        timeout = 3600 * 1000;
    }

    if (scf->refresh == NGX_CONF_UNSET) {
        scf->refresh = 1;
    }

    if (scf->header == NGX_CONF_UNSET) {
        scf->header = 0;
    }

    smcf = ngx_http_conf_get_module_main_conf(cf,
                                              ngx_http_upstream_sticky_module);

    if (smcf->stickies.elts == NULL
        && ngx_array_init(&smcf->stickies, cf->pool, 4,
                          sizeof(ngx_shm_zone_t *))
           != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    us = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    scf->learn_zone = ngx_sticky_learn_create_zone(cf, &str, zsize, &us->host,
                                                   timeout, scf->refresh,
                                             &ngx_http_upstream_sticky_module);
    if (scf->learn_zone == NULL) {
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
ngx_http_upstream_sticky_init_worker(ngx_cycle_t *cycle)
{
    ngx_uint_t                              i;
    ngx_shm_zone_t                         *zone, **zonep;
    ngx_http_upstream_sticky_main_conf_t   *smcf;

    smcf = ngx_http_cycle_get_module_main_conf(cycle,
                                               ngx_http_upstream_sticky_module);
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
ngx_http_upstream_sticky_process_session(
    ngx_http_upstream_sticky_peer_data_t *sp, ngx_peer_connection_t *pc)
{
    ngx_str_t                             sess_id;
    ngx_uint_t                            i;
    ngx_sticky_sess_t                     sess;
    ngx_http_request_t                   *r;
    ngx_http_complex_value_t             *vars;
    ngx_http_upstream_sticky_srv_conf_t  *scf;

#if (NGX_SUPPRESS_WARN)
    ngx_str_null(&sess_id);
#endif

    r = pc->ctx;

    scf = sp->conf;

    vars = scf->create_vars.elts;

    for (i = 0; i < scf->create_vars.nelts; i++) {

        if (ngx_http_complex_value(r, &vars[i], &sess_id) != NGX_OK) {
            return;
        }

        if (sess_id.len == 0) {
            continue;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
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

