
/*
 * Copyright (C) 2023 Web Server LLC
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


#define NGX_STREAM_MQTT_PREREAD_RESERVED_FLAG  0x01
#define NGX_STREAM_MQTT_PREREAD_WILL_FLAG      0x04
#define NGX_STREAM_MQTT_PREREAD_USERNAME_FLAG  0x80


typedef struct {
    ngx_flag_t  enabled;
} ngx_stream_mqtt_preread_srv_conf_t;


typedef struct {
    ngx_str_t  clientid;
    ngx_str_t  username;
} ngx_stream_mqtt_preread_ctx_t;


static ngx_int_t ngx_stream_mqtt_preread_handler(ngx_stream_session_t *s);
static u_char *ngx_stream_mqtt_preread_next_varbyte(size_t *value,
    u_char *pos, u_char *end);
static u_char *ngx_stream_mqtt_preread_next_str(ngx_str_t *str, u_char *pos,
    u_char *end);
static ngx_int_t ngx_stream_mqtt_preread_set_variable(
    ngx_stream_session_t *s, ngx_stream_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_stream_mqtt_preread_add_variables(ngx_conf_t *cf);
static void *ngx_stream_mqtt_preread_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_mqtt_preread_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_stream_mqtt_preread_init(ngx_conf_t *cf);


static ngx_command_t  ngx_stream_mqtt_preread_commands[] = {

    { ngx_string("mqtt_preread"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_mqtt_preread_srv_conf_t, enabled),
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_mqtt_preread_module_ctx = {
    ngx_stream_mqtt_preread_add_variables,    /* preconfiguration */
    ngx_stream_mqtt_preread_init,             /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    ngx_stream_mqtt_preread_create_srv_conf,  /* create server configuration */
    ngx_stream_mqtt_preread_merge_srv_conf    /* merge server configuration */
};


ngx_module_t  ngx_stream_mqtt_preread_module = {
    NGX_MODULE_V1,
    &ngx_stream_mqtt_preread_module_ctx,      /* module context */
    ngx_stream_mqtt_preread_commands,         /* module directives */
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


static ngx_stream_variable_t  ngx_stream_mqtt_preread_vars[] = {

    { ngx_string("mqtt_preread_clientid"), NULL,
      ngx_stream_mqtt_preread_set_variable,
      offsetof(ngx_stream_mqtt_preread_ctx_t, clientid), 0, 0 },

    { ngx_string("mqtt_preread_username"), NULL,
      ngx_stream_mqtt_preread_set_variable,
      offsetof(ngx_stream_mqtt_preread_ctx_t, username), 0, 0 },

      ngx_stream_null_variable
};


static ngx_int_t
ngx_stream_mqtt_preread_handler(ngx_stream_session_t *s)
{
    size_t                               len;
    u_char                               flags, *last, *p;
    ngx_str_t                            protocol, tmp;
    ngx_uint_t                           version;
    ngx_connection_t                    *c;
    ngx_stream_mqtt_preread_ctx_t       *ctx;
    ngx_stream_mqtt_preread_srv_conf_t  *mscf;

    c = s->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "mqtt preread handler");

    mscf = ngx_stream_get_module_srv_conf(s, ngx_stream_mqtt_preread_module);

    if (!mscf->enabled) {
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

    /* minimal MQTT CONNECT packet length */
    if ((size_t) (last - p) < 14) {
        return NGX_AGAIN;
    }

    if (*p != 0x10) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "mqtt preread: not a CONNECT packet");
        return NGX_DECLINED;
    }

    p++;

    p = ngx_stream_mqtt_preread_next_varbyte(&len, p, last);
    if (p == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "mqtt preread: failed to parse remaining length");
        return NGX_DECLINED;
    }

    if ((size_t) (last - p) < len) {
        return NGX_AGAIN;
    }

    /* CONNECT variable header parsing */

    p = ngx_stream_mqtt_preread_next_str(&protocol, p, last);
    if (p == NULL
        || protocol.len != 4 || ngx_memcmp(protocol.data, "MQTT", 4) != 0)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "mqtt preread: bad protocol name");
        return NGX_DECLINED;
    }

    /*
     * here we have at least 4 bytes left, due to check for
     * "minimal MQTT CONNECT packet length" above
     */

    version = (ngx_uint_t) *p++;

    switch (version) {
    case 4:
    case 5:
        break;
    default:
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "mqtt preread: bad protocol version \"%ui\"", version);
        return NGX_DECLINED;
    }

    flags = (u_char) *p++;

    if (flags & NGX_STREAM_MQTT_PREREAD_RESERVED_FLAG) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "mqtt preread: \"reserved\" flag set to 1");
        return NGX_DECLINED;
    }

    /* skip keep alive */
    p += 2;

    /* skip properties */
    if (version == 5) {
        p = ngx_stream_mqtt_preread_next_varbyte(&len, p, last);
        if (p == NULL || (size_t) (last - p) < len) {
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                           "mqtt preread: failed to parse properties length");
            return NGX_DECLINED;
        }

        p += len;
    }

    /* CONNECT payload parsing */

    p = ngx_stream_mqtt_preread_next_str(&tmp, p, last);
    if (p == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "mqtt preread: failed to parse client id");
        return NGX_DECLINED;
    }

    ctx = ngx_pcalloc(c->pool, sizeof(ngx_stream_mqtt_preread_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->clientid.len = tmp.len;
    ctx->clientid.data = ngx_pstrdup(c->pool, &tmp);
    if (ctx->clientid.data == NULL) {
        return NGX_ERROR;
    }

    if (!(flags & NGX_STREAM_MQTT_PREREAD_USERNAME_FLAG)) {
        goto done;
    }

    /* skip will properties */
    if (flags & NGX_STREAM_MQTT_PREREAD_WILL_FLAG) {
        if (version == 5) {
            p = ngx_stream_mqtt_preread_next_varbyte(&len, p, last);
            if (p == NULL || (size_t) (last - p) < len) {
                ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                               "mqtt preread: failed to parse "
                               "\"will properties\"");
                return NGX_DECLINED;
            }

            p += len;
        }

        p = ngx_stream_mqtt_preread_next_str(&tmp, p, last);
        if (p == NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                           "mqtt preread: failed to parse \"will topic\"");
            return NGX_DECLINED;
        }

        p = ngx_stream_mqtt_preread_next_str(&tmp, p, last);
        if (p == NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                           "mqtt preread: failed to parse \"will payload\"");
            return NGX_DECLINED;
        }
    }

    p = ngx_stream_mqtt_preread_next_str(&tmp, p, last);
    if (p == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "mqtt preread: failed to parse username");
        return NGX_DECLINED;
    }

    ctx->username.len = tmp.len;
    ctx->username.data = ngx_pstrdup(c->pool, &tmp);
    if (ctx->username.data == NULL) {
        return NGX_ERROR;
    }

done:

    ngx_stream_set_ctx(s, ctx, ngx_stream_mqtt_preread_module);

    return NGX_OK;
}


static u_char *
ngx_stream_mqtt_preread_next_varbyte(size_t *value, u_char *pos,
    u_char *end)
{
    ngx_uint_t  octet, shift;

    *value = 0;

    if (end - pos > 4) {
        end = pos + 4;
    }

    for (shift = 0; pos != end; shift += 7) {
        octet = *pos++;

        *value += (octet & 0x7f) << shift;

        if (octet < 128) {
            return pos;
        }
    }

    return NULL;
}


static u_char *
ngx_stream_mqtt_preread_next_str(ngx_str_t *str, u_char *pos, u_char *end)
{
    size_t  len;

    if (end - pos < 2) {
        return NULL;
    }

    len = (pos[0] << 8) | pos[1];
    pos += 2;

    if ((size_t) (end - pos) < len) {
        return NULL;
    }

    str->len = len;
    str->data = pos;

    pos += len;

    return pos;
}


static ngx_int_t
ngx_stream_mqtt_preread_set_variable(ngx_stream_session_t *s,
    ngx_variable_value_t *v, uintptr_t data)
{
    ngx_str_t                      *variable;
    ngx_stream_mqtt_preread_ctx_t  *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_mqtt_preread_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    variable = (ngx_str_t *) ((char *) ctx + data);

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = variable->len;
    v->data = variable->data;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_mqtt_preread_add_variables(ngx_conf_t *cf)
{
    ngx_stream_variable_t  *var, *v;

    for (v = ngx_stream_mqtt_preread_vars; v->name.len; v++) {
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
ngx_stream_mqtt_preread_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_mqtt_preread_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_mqtt_preread_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enabled = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_stream_mqtt_preread_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_stream_mqtt_preread_srv_conf_t *prev = parent;
    ngx_stream_mqtt_preread_srv_conf_t *conf = child;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_stream_mqtt_preread_init(ngx_conf_t *cf)
{
    ngx_stream_handler_pt        *h;
    ngx_stream_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_STREAM_PREREAD_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_stream_mqtt_preread_handler;

    return NGX_OK;
}
