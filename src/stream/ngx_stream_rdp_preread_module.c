
/*
 * Copyright (C) 2024 Web Server LLC
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


typedef struct {
    ngx_flag_t  enabled;
} ngx_stream_rdp_preread_srv_conf_t;


typedef struct {
    size_t  len;
    u_char  cookie[1];
} ngx_stream_rdp_preread_ctx_t;


static ngx_int_t ngx_stream_rdp_preread_handler(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_rdp_preread_cookie_variable(
    ngx_stream_session_t *s, ngx_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_stream_rdp_preread_cookie_name_variable(
    ngx_stream_session_t *s, ngx_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_stream_rdp_preread_add_variables(ngx_conf_t *cf);
static void *ngx_stream_rdp_preread_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_rdp_preread_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_stream_rdp_preread_init(ngx_conf_t *cf);


static ngx_command_t  ngx_stream_rdp_preread_commands[] = {

    { ngx_string("rdp_preread"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_rdp_preread_srv_conf_t, enabled),
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_rdp_preread_module_ctx = {
    ngx_stream_rdp_preread_add_variables,     /* preconfiguration */
    ngx_stream_rdp_preread_init,              /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    ngx_stream_rdp_preread_create_srv_conf,   /* create server configuration */
    ngx_stream_rdp_preread_merge_srv_conf     /* merge server configuration */
};


ngx_module_t  ngx_stream_rdp_preread_module = {
    NGX_MODULE_V1,
    &ngx_stream_rdp_preread_module_ctx,       /* module context */
    ngx_stream_rdp_preread_commands,          /* module directives */
    NGX_STREAM_MODULE,                        /* module type */
    NULL,                                     /* init master */
    NULL,                                     /* init module */
    NULL,                                     /* init process */
    NULL,                                     /* init thread */
    NULL,                                     /* exit thread */
    NULL,                                     /* exit process */
    NULL,                                     /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_stream_variable_t  ngx_stream_rdp_preread_vars[] = {

    { ngx_string("rdp_cookie"), NULL,
      ngx_stream_rdp_preread_cookie_variable, 0, 0, 0 },

    { ngx_string("rdp_cookie_"), NULL,
      ngx_stream_rdp_preread_cookie_name_variable, 0,
      NGX_STREAM_VAR_NOCACHEABLE|NGX_STREAM_VAR_PREFIX, 0 },

      ngx_stream_null_variable
};


static ngx_int_t
ngx_stream_rdp_preread_handler(ngx_stream_session_t *s)
{
    size_t                              len;
    u_char                             *end, *last, *p, *start;
    ngx_connection_t                   *c;
    ngx_stream_rdp_preread_ctx_t       *ctx;
    ngx_stream_rdp_preread_srv_conf_t  *rscf;

    c = s->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "rdp preread handler");

    rscf = ngx_stream_get_module_srv_conf(s, ngx_stream_rdp_preread_module);

    if (!rscf->enabled) {
        return NGX_DECLINED;
    }

    if (c->type != SOCK_STREAM) {
        return NGX_DECLINED;
    }

    if (c->buffer == NULL) {
        return NGX_AGAIN;
    }

    p = c->buffer->pos;
    last = c->buffer->last;

    /* waiting for last TPKT length byte */
    if ((size_t) (last - p) < 4) {
        return NGX_AGAIN;
    }

    if (*p != 3) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "rdp preread: not a TPKT packet header");
        return NGX_DECLINED;
    }

    p++;

    if (*p != 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "rdp preread: bad reserved byte");
        return NGX_DECLINED;
    }

    len = *(++p) << 8;
    len |= *(++p);

    /* 4 + 8 + 7 + 2 (CR+LF) */
    if (len < 21) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "rdp preread: empty cookie");
        return NGX_DECLINED;
    }

    len -= 4;

    if ((size_t) (last - p) < len) {
        return NGX_AGAIN;
    }

    end = p + len;
    p += 8;

    if (ngx_strncasecmp(p, (u_char *) "Cookie:", 7) != 0) {
        return NGX_DECLINED;
    }

    p += 7;

    /* only 15 bytes consumed of >17 */
    if (*p == ' ') {
        p++;
        while (*p == ' ' && ++p != end) { /* void */ };
    }

    start = p;

    while (p != end && *p != '\r') {
        p++;
    }

    if (p == end || p[1] != '\n') {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "rdp preread: bad cookie");
        return NGX_DECLINED;
    }

    len = (size_t) (p - start);

    ctx = ngx_palloc(c->pool,
                     offsetof(ngx_stream_rdp_preread_ctx_t, cookie) + len);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->len = len;
    ngx_memcpy(ctx->cookie, start, len);

    ngx_stream_set_ctx(s, ctx, ngx_stream_rdp_preread_module);

    return NGX_OK;
}


static ngx_int_t
ngx_stream_rdp_preread_cookie_variable(ngx_stream_session_t *s,
    ngx_variable_value_t *v, uintptr_t data)
{
    ngx_stream_rdp_preread_ctx_t  *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_rdp_preread_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = ctx->len;
    v->data = ctx->cookie;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_rdp_preread_cookie_name_variable(ngx_stream_session_t *s,
    ngx_variable_value_t *v, uintptr_t data)
{
    ngx_str_t *name = (ngx_str_t *) data;

    u_char                        *p;
    size_t                         len;
    ngx_stream_rdp_preread_ctx_t  *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_rdp_preread_module);

    if (ctx == NULL || ctx->len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    len = name->len - (sizeof("rdp_cookie_") - 1);
    p = name->data + sizeof("rdp_cookie_") - 1;

    if (ctx->len - 1 < len
        || ctx->cookie[len] != '='
        || ngx_strncasecmp(ctx->cookie, p, len) != 0)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = ctx->len - len - 1;
    v->data = ctx->cookie + len + 1;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_rdp_preread_add_variables(ngx_conf_t *cf)
{
    ngx_stream_variable_t  *var, *v;

    for (v = ngx_stream_rdp_preread_vars; v->name.len; v++) {
        var = ngx_stream_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static void *
ngx_stream_rdp_preread_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_rdp_preread_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_rdp_preread_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enabled = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_stream_rdp_preread_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_stream_rdp_preread_srv_conf_t *prev = parent;
    ngx_stream_rdp_preread_srv_conf_t *conf = child;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_stream_rdp_preread_init(ngx_conf_t *cf)
{
    ngx_stream_handler_pt        *h;
    ngx_stream_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_STREAM_PREREAD_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_stream_rdp_preread_handler;

    return NGX_OK;
}
