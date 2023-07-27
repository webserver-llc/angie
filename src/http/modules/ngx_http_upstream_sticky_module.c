
/*
 * Copyright (C) 2023 Web Server LLC
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>


typedef struct {
    ngx_str_t                        cookie;
    ngx_array_t                      cookie_attrs;
    ngx_array_t                      lookup_vars;
    ngx_http_complex_value_t        *secret;
    ngx_flag_t                       strict;

    ngx_http_upstream_init_pt        original_init_upstream;
    ngx_http_upstream_init_peer_pt   original_init_peer;

} ngx_http_upstream_sticky_srv_conf_t;


typedef struct {
    ngx_str_t                        hint;
    ngx_str_t                        salt;
    ngx_table_elt_t                 *set_cookie;

    ngx_event_get_peer_pt            original_get_peer;
} ngx_http_upstream_sticky_peer_data_t;

static ngx_int_t ngx_http_upstream_sticky_select_peer(
    ngx_http_upstream_rr_peer_data_t *rrp,
    ngx_http_upstream_sticky_peer_data_t *sp, ngx_peer_connection_t *pc);
static size_t ngx_http_upstream_sticky_hash(ngx_str_t *in, ngx_str_t *salt,
    u_char *out);
static ngx_int_t ngx_http_upstream_init_sticky(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_init_sticky_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_sticky_peer(ngx_peer_connection_t *pc,
    void *data);
static ngx_int_t ngx_http_upstream_sticky_set_cookie(ngx_http_request_t *r,
    ngx_http_upstream_sticky_srv_conf_t *scf,
    ngx_http_upstream_sticky_peer_data_t *sp, ngx_str_t *sid);

static void *ngx_http_upstream_sticky_create_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_sticky(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_upstream_sticky_cookie(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_upstream_sticky_add_cv(ngx_conf_t *cf,
    ngx_array_t *values, ngx_str_t *value);
static char *ngx_http_upstream_sticky_route(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

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

    NULL,                                  /* create main configuration */
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
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_upstream_sticky_select_peer(ngx_http_upstream_rr_peer_data_t *rrp,
    ngx_http_upstream_sticky_peer_data_t *sp, ngx_peer_connection_t *pc)
{
    size_t       len;
    time_t       now;
    u_char      *sid, hashed[NGX_HTTP_UPSTREAM_SID_LEN];
    ngx_str_t   *hint;
    uintptr_t    m;
    ngx_uint_t   i, n;

    ngx_http_request_t                   *r;
    ngx_http_upstream_state_t            *us;
    ngx_http_upstream_rr_peer_t          *peer;
    ngx_http_upstream_rr_peers_t         *peers;
    ngx_http_upstream_sticky_srv_conf_t  *scf;

    r = pc->ctx;

    hint = &sp->hint;
    us = r->upstream->state;

    if (hint->len == 0) {
        us->sticky_status = NGX_HTTP_UPSTREAM_STICKY_STATUS_NEW;

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "sticky: no hint provided");
        return NGX_OK;
    }

    now = ngx_time();

    peers = rrp->peers;

again:

    ngx_http_upstream_rr_peers_rlock(peers);

#if (NGX_HTTP_UPSTREAM_ZONE)
    if (peers->generation && rrp->generation != *peers->generation) {
        ngx_http_upstream_rr_peers_unlock(peers);
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

        ngx_http_upstream_rr_peer_lock(peers, peer);

        if (peer->down) {
            ngx_http_upstream_rr_peer_unlock(peers, peer);
            continue;
        }

        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            ngx_http_upstream_rr_peer_unlock(peers, peer);
            continue;
        }

        if (peer->max_conns && peer->conns >= peer->max_conns) {
            ngx_http_upstream_rr_peer_unlock(peers, peer);
            continue;
        }

        if (sp->salt.len) {
            len = ngx_http_upstream_sticky_hash(&peer->sid, &sp->salt, hashed);
            sid = hashed;

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

        rrp->current = peer;
        ngx_http_upstream_rr_peer_ref(peers, peer);

        pc->sockaddr = peer->sockaddr;
        pc->socklen = peer->socklen;
        pc->name = &peer->name;
        pc->sid = peer->sid;

        peer->conns++;

        if (now - peer->checked > peer->fail_timeout) {
            peer->checked = now;
        }

#if (NGX_API && NGX_HTTP_UPSTREAM_ZONE)
        peer->stats.requests++;
        peer->stats.selected = now;
#endif

        ngx_http_upstream_rr_peer_unlock(peers, peer);
        ngx_http_upstream_rr_peers_unlock(peers);

        rrp->tried[n] |= m;

        return NGX_OK;
    }

    if (peers->next) {
        ngx_http_upstream_rr_peers_unlock(peers);
        peers = peers->next;
        goto again;
    }

    us->sticky_status = NGX_HTTP_UPSTREAM_STICKY_STATUS_MISS;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "sticky: no match");

    ngx_http_upstream_rr_peers_unlock(peers);

    scf = ngx_http_conf_upstream_srv_conf(r->upstream->upstream,
                                          ngx_http_upstream_sticky_module);

    return scf->strict ? NGX_BUSY : NGX_OK;
}


static size_t
ngx_http_upstream_sticky_hash(ngx_str_t *in, ngx_str_t *salt, u_char *out)
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
ngx_http_upstream_init_sticky(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
{
    ngx_int_t  *v;
    ngx_str_t   vname;

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

        vname.len = sizeof("cookie_") - 1 + scf->cookie.len;
        vname.data = ngx_palloc(cf->pool, vname.len);
        if (vname.data == NULL) {
            return NGX_ERROR;
        }

        (void) ngx_sprintf(vname.data, "cookie_%V", &scf->cookie);

        v = ngx_array_push(&scf->lookup_vars);
        if (v == NULL) {
            return NGX_ERROR;
        }

        *v = ngx_http_get_variable_index(cf, &vname);
        if (*v == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_init_sticky_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_upstream_sticky_srv_conf_t   *scf;
    ngx_http_upstream_sticky_peer_data_t  *sp;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "sticky: init peer");

    scf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_sticky_module);

    sp = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_sticky_peer_data_t));
    if (sp == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, sp, ngx_http_upstream_sticky_module);

    if (scf->original_init_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    sp->original_get_peer = r->upstream->peer.get;
    r->upstream->peer.get = ngx_http_upstream_get_sticky_peer;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_get_sticky_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_rr_peer_data_t  *rrp = data;

    ngx_int_t                              rc, *vars;
    ngx_uint_t                             i;
    ngx_http_request_t                    *r;
    ngx_http_variable_value_t             *vv;
    ngx_http_upstream_sticky_srv_conf_t   *scf;
    ngx_http_upstream_sticky_peer_data_t  *sp;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "sticky: get peer");

    r = pc->ctx;

    sp = ngx_http_get_module_ctx(r, ngx_http_upstream_sticky_module);

    scf = ngx_http_conf_upstream_srv_conf(r->upstream->upstream,
                                          ngx_http_upstream_sticky_module);
    sp->hint.len = 0;

    vars = scf->lookup_vars.elts;

    for (i = 0; i < scf->lookup_vars.nelts; i++) {

        vv = ngx_http_get_indexed_variable(r, vars[i]);

        if (vv == NULL || vv->not_found || vv->len == 0) {
            continue;
        }

        sp->hint.data = vv->data;
        sp->hint.len = vv->len;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "sticky: extracted hint %V from variable %ui",
                       &sp->hint, i);
        break;
    }

    if (scf->secret) {
        if (ngx_http_complex_value(r, scf->secret, &sp->salt) != NGX_OK) {
            return NGX_ERROR;
        }

    } else {
        sp->salt.len = 0;
    }

    rc = ngx_http_upstream_sticky_select_peer(rrp, sp, pc);

    if (rc == NGX_BUSY) {
        pc->name = rrp->peers->name;
        return NGX_BUSY;
    }

    /* rc == NGX_OK */

    rc = sp->original_get_peer(pc, data);
    if (rc != NGX_OK && rc != NGX_DONE) {
        return rc;
    }

    if (scf->cookie.len == 0) {
        /* sticky route */
        return rc;
    }

    if (ngx_http_upstream_sticky_set_cookie(r, scf, sp, &pc->sid) != NGX_OK) {
        return NGX_ERROR;
    }

    return rc;
}


static ngx_int_t
ngx_http_upstream_sticky_set_cookie(ngx_http_request_t *r,
    ngx_http_upstream_sticky_srv_conf_t *scf,
    ngx_http_upstream_sticky_peer_data_t *sp, ngx_str_t *sid)
{
    u_char      *p, *cookie, hashed[NGX_HTTP_UPSTREAM_SID_LEN];
    size_t       len;
    ngx_str_t    value, tmp;
    ngx_uint_t   i;

    ngx_table_elt_t           *set_cookie;
    ngx_http_complex_value_t  *attr;

    if (scf->secret) {
        if (ngx_http_complex_value(r, scf->secret, &value) != NGX_OK) {
            return NGX_ERROR;
        }

        tmp.data = hashed;
        tmp.len = ngx_http_upstream_sticky_hash(sid, &value, hashed);

        sid = &tmp;
    }

    len = scf->cookie.len;
    len += sizeof("=") - 1 + sid->len;

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
     *     conf->cookie = { 0, NULL };
     *     conf->original_init_upstream = NULL;
     *     conf->original_init_peer = NULL;
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

        *v = ngx_http_get_variable_index(cf, &value[i]);
        if (*v == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}
