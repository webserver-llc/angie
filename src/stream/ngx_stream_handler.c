
/*
 * Copyright (C) 2022 Web Server LLC
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_stream.h>


static void ngx_stream_log_session(ngx_stream_session_t *s);
static void ngx_stream_close_connection(ngx_connection_t *c);
static u_char *ngx_stream_log_error(ngx_log_t *log, u_char *buf, size_t len);
static void ngx_stream_proxy_protocol_handler(ngx_event_t *rev);

#if (NGX_API)
static ngx_int_t ngx_api_stream_server_zones_iter(ngx_api_iter_ctx_t *ictx,
    ngx_api_ctx_t *actx);
static ngx_int_t ngx_api_stream_zone_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_stream_session_codes_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
#if (NGX_STREAM_SSL)
static ngx_int_t ngx_api_stream_ssl_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
#endif
#endif


#if (NGX_API)

#if (NGX_STREAM_SSL)

static ngx_api_entry_t  ngx_api_stream_server_zone_ssl_entries[] = {

    {
        .name      = ngx_string("handshaked"),
        .handler   = ngx_api_struct_atomic_handler,
        .data.off  = offsetof(ngx_stream_server_stats_t, ssl_handshaked)
    },

    {
        .name      = ngx_string("reuses"),
        .handler   = ngx_api_struct_atomic_handler,
        .data.off  = offsetof(ngx_stream_server_stats_t, ssl_reuses)
    },

    {
        .name      = ngx_string("timedout"),
        .handler   = ngx_api_struct_atomic_handler,
        .data.off  = offsetof(ngx_stream_server_stats_t, ssl_timedout)
    },

    {
        .name      = ngx_string("failed"),
        .handler   = ngx_api_struct_atomic_handler,
        .data.off  = offsetof(ngx_stream_server_stats_t, ssl_failed)
    },

    ngx_api_null_entry
};

#endif


static ngx_api_entry_t  ngx_api_stream_server_zone_connections_entries[] = {

    {
        .name      = ngx_string("total"),
        .handler   = ngx_api_struct_atomic_handler,
        .data.off  = offsetof(ngx_stream_server_stats_t, connections)
    },

    {
        .name      = ngx_string("processing"),
        .handler   = ngx_api_struct_atomic_handler,
        .data.off  = offsetof(ngx_stream_server_stats_t, processing)
    },

    {
        .name      = ngx_string("discarded"),
        .handler   = ngx_api_struct_atomic_handler,
        .data.off  = offsetof(ngx_stream_server_stats_t, discarded)
    },

    ngx_api_null_entry
};


static ngx_api_entry_t  ngx_api_stream_server_zone_data_entries[] = {

    {
        .name      = ngx_string("received"),
        .handler   = ngx_api_struct_atomic_handler,
        .data.off  = offsetof(ngx_stream_server_stats_t, received)
    },

    {
        .name      = ngx_string("sent"),
        .handler   = ngx_api_struct_atomic_handler,
        .data.off  = offsetof(ngx_stream_server_stats_t, sent)
    },

    ngx_api_null_entry
};


static ngx_api_entry_t  ngx_api_stream_server_zone_entries[] = {

#if (NGX_STREAM_SSL)
    {
        .name      = ngx_string("ssl"),
        .handler   = ngx_api_stream_ssl_handler,
        .data.ents = ngx_api_stream_server_zone_ssl_entries
    },
#endif

    {
        .name      = ngx_string("connections"),
        .handler   = ngx_api_stream_zone_handler,
        .data.ents = ngx_api_stream_server_zone_connections_entries
    },

    {
        .name      = ngx_string("sessions"),
        .handler   = ngx_api_stream_session_codes_handler,
        .data.off  = offsetof(ngx_stream_server_stats_t, sessions)
    },

    {
        .name      = ngx_string("data"),
        .handler   = ngx_api_stream_zone_handler,
        .data.ents = ngx_api_stream_server_zone_data_entries
    },

    ngx_api_null_entry
};


static ngx_api_entry_t  ngx_api_stream_session_codes_entries[] = {

    {
        .name      = ngx_string("success"),
        .handler   = ngx_api_struct_atomic_handler,
        .data.off  = 0 * sizeof(ngx_atomic_t)
    },

    {
        .name      = ngx_string("invalid"),
        .handler   = ngx_api_struct_atomic_handler,
        .data.off  = 1 * sizeof(ngx_atomic_t)
    },

    {
        .name      = ngx_string("forbidden"),
        .handler   = ngx_api_struct_atomic_handler,
        .data.off  = 2 * sizeof(ngx_atomic_t)
    },

    {
        .name      = ngx_string("internal_error"),
        .handler   = ngx_api_struct_atomic_handler,
        .data.off  = 3 * sizeof(ngx_atomic_t)
    },

    {
        .name      = ngx_string("bad_gateway"),
        .handler   = ngx_api_struct_atomic_handler,
        .data.off  = 4 * sizeof(ngx_atomic_t)
    },

    {
        .name      = ngx_string("service_unavailable"),
        .handler   = ngx_api_struct_atomic_handler,
        .data.off  = 5 * sizeof(ngx_atomic_t)
    },

    ngx_api_null_entry
};

#endif


void
ngx_stream_init_connection(ngx_connection_t *c)
{
    u_char                        text[NGX_SOCKADDR_STRLEN];
    size_t                        len;
    ngx_uint_t                    i;
    ngx_time_t                   *tp;
    ngx_event_t                  *rev;
    struct sockaddr              *sa;
    ngx_stream_port_t            *port;
    struct sockaddr_in           *sin;
    ngx_stream_in_addr_t         *addr;
    ngx_stream_session_t         *s;
    ngx_stream_addr_conf_t       *addr_conf;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6          *sin6;
    ngx_stream_in6_addr_t        *addr6;
#endif
    ngx_stream_core_srv_conf_t   *cscf;
    ngx_stream_core_main_conf_t  *cmcf;

    /* find the server configuration for the address:port */

    port = c->listening->servers;

    if (port->naddrs > 1) {

        /*
         * There are several addresses on this port and one of them
         * is the "*:port" wildcard so getsockname() is needed to determine
         * the server address.
         *
         * AcceptEx() and recvmsg() already gave this address.
         */

        if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
            ngx_stream_close_connection(c);
            return;
        }

        sa = c->local_sockaddr;

        switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) sa;

            addr6 = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (ngx_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
                    break;
                }
            }

            addr_conf = &addr6[i].conf;

            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) sa;

            addr = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (addr[i].addr == sin->sin_addr.s_addr) {
                    break;
                }
            }

            addr_conf = &addr[i].conf;

            break;
        }

    } else {
        switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            addr6 = port->addrs;
            addr_conf = &addr6[0].conf;
            break;
#endif

        default: /* AF_INET */
            addr = port->addrs;
            addr_conf = &addr[0].conf;
            break;
        }
    }

    s = ngx_pcalloc(c->pool, sizeof(ngx_stream_session_t));
    if (s == NULL) {
        ngx_stream_close_connection(c);
        return;
    }

    s->signature = NGX_STREAM_MODULE;
    s->main_conf = addr_conf->ctx->main_conf;
    s->srv_conf = addr_conf->ctx->srv_conf;

#if (NGX_STREAM_SSL)
    s->ssl = addr_conf->ssl;
#endif

    if (c->buffer) {
        s->received += c->buffer->last - c->buffer->pos;
    }

    s->connection = c;
    c->data = s;

    cscf = ngx_stream_get_module_srv_conf(s, ngx_stream_core_module);

    ngx_set_connection_log(c, cscf->error_log);

    len = ngx_sock_ntop(c->sockaddr, c->socklen, text, NGX_SOCKADDR_STRLEN, 1);

    ngx_log_error(NGX_LOG_INFO, c->log, 0, "*%uA %sclient %*s connected to %V",
                  c->number, c->type == SOCK_DGRAM ? "udp " : "",
                  len, text, &addr_conf->addr_text);

    c->log->connection = c->number;
    c->log->handler = ngx_stream_log_error;
    c->log->data = s;
    c->log->action = "initializing session";
    c->log_error = NGX_ERROR_INFO;

    s->ctx = ngx_pcalloc(c->pool, sizeof(void *) * ngx_stream_max_module);
    if (s->ctx == NULL) {
        ngx_stream_close_connection(c);
        return;
    }

    cmcf = ngx_stream_get_module_main_conf(s, ngx_stream_core_module);

    s->variables = ngx_pcalloc(s->connection->pool,
                               cmcf->variables.nelts
                               * sizeof(ngx_stream_variable_value_t));

    if (s->variables == NULL) {
        ngx_stream_close_connection(c);
        return;
    }

    tp = ngx_timeofday();
    s->start_sec = tp->sec;
    s->start_msec = tp->msec;

#if (NGX_API)
    {
    ngx_stream_server_stats_t  *stats;

    if (cscf->server_zone) {
        stats = cscf->server_zone->stats;

        (void) ngx_atomic_fetch_add(&stats->processing, 1);
        s->stat_processing = 1;
        (void) ngx_atomic_fetch_add(&stats->connections, 1);
    }
    }
#endif

    rev = c->read;
    rev->handler = ngx_stream_session_handler;

    if (addr_conf->proxy_protocol) {
        c->log->action = "reading PROXY protocol";

        rev->handler = ngx_stream_proxy_protocol_handler;

        if (!rev->ready) {
            ngx_add_timer(rev, cscf->proxy_protocol_timeout);

            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                ngx_stream_finalize_session(s,
                                            NGX_STREAM_INTERNAL_SERVER_ERROR);
            }

            return;
        }
    }

    if (ngx_use_accept_mutex) {
        ngx_post_event(rev, &ngx_posted_events);
        return;
    }

    rev->handler(rev);
}


static void
ngx_stream_proxy_protocol_handler(ngx_event_t *rev)
{
    u_char                      *p, buf[NGX_PROXY_PROTOCOL_MAX_HEADER];
    size_t                       size;
    ssize_t                      n;
    ngx_err_t                    err;
    ngx_connection_t            *c;
    ngx_stream_session_t        *s;
    ngx_stream_core_srv_conf_t  *cscf;

    c = rev->data;
    s = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "stream PROXY protocol handler");

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        ngx_stream_finalize_session(s, NGX_STREAM_OK);
        return;
    }

    n = recv(c->fd, (char *) buf, sizeof(buf), MSG_PEEK);

    err = ngx_socket_errno;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "recv(): %z", n);

    if (n == -1) {
        if (err == NGX_EAGAIN) {
            rev->ready = 0;

            if (!rev->timer_set) {
                cscf = ngx_stream_get_module_srv_conf(s,
                                                      ngx_stream_core_module);

                ngx_add_timer(rev, cscf->proxy_protocol_timeout);
            }

            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                ngx_stream_finalize_session(s,
                                            NGX_STREAM_INTERNAL_SERVER_ERROR);
            }

            return;
        }

        ngx_connection_error(c, err, "recv() failed");

        ngx_stream_finalize_session(s, NGX_STREAM_OK);
        return;
    }

    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    p = ngx_proxy_protocol_read(c, buf, buf + n);

    if (p == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_BAD_REQUEST);
        return;
    }

    size = p - buf;

    if (c->recv(c, buf, size) != (ssize_t) size) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    c->log->action = "initializing session";

    ngx_stream_session_handler(rev);
}


void
ngx_stream_session_handler(ngx_event_t *rev)
{
    ngx_connection_t      *c;
    ngx_stream_session_t  *s;

    c = rev->data;
    s = c->data;

    ngx_stream_core_run_phases(s);
}


void
ngx_stream_finalize_session(ngx_stream_session_t *s, ngx_uint_t rc)
{
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "finalize stream session: %i", rc);

    s->status = rc;

    ngx_stream_log_session(s);

    ngx_stream_close_connection(s->connection);
}


static void
ngx_stream_log_session(ngx_stream_session_t *s)
{
    ngx_uint_t                    i, n;
    ngx_stream_handler_pt        *log_handler;
    ngx_stream_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_get_module_main_conf(s, ngx_stream_core_module);

    log_handler = cmcf->phases[NGX_STREAM_LOG_PHASE].handlers.elts;
    n = cmcf->phases[NGX_STREAM_LOG_PHASE].handlers.nelts;

    for (i = 0; i < n; i++) {
        log_handler[i](s);
    }
}


static void
ngx_stream_close_connection(ngx_connection_t *c)
{
    ngx_pool_t  *pool;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "close stream connection: %d", c->fd);

#if (NGX_STREAM_SSL)

    if (c->ssl) {
        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
            c->ssl->handler = ngx_stream_close_connection;
            return;
        }
    }

#endif

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif

#if (NGX_API)
    if (c->data) {
        ngx_stream_session_t        *s;
        ngx_stream_server_stats_t   *stats;
        ngx_stream_core_srv_conf_t  *cscf;

        s = c->data;
        cscf = ngx_stream_get_module_srv_conf(s, ngx_stream_core_module);

        if (cscf->server_zone) {
            stats = cscf->server_zone->stats;

            if (s->stat_processing) {
                (void) ngx_atomic_fetch_add(&stats->processing, -1);
            } else {
                (void) ngx_atomic_fetch_add(&stats->connections, 1);
            }

            if (s->status > 0) {

                switch (s->status) {
                case NGX_STREAM_OK:
                    (void) ngx_atomic_fetch_add(&stats->sessions[0], 1);
                    break;

                case NGX_STREAM_BAD_REQUEST:
                    (void) ngx_atomic_fetch_add(&stats->sessions[1], 1);
                    break;

                case NGX_STREAM_FORBIDDEN:
                    (void) ngx_atomic_fetch_add(&stats->sessions[2], 1);
                    break;

                case NGX_STREAM_INTERNAL_SERVER_ERROR:
                    (void) ngx_atomic_fetch_add(&stats->sessions[3], 1);
                    break;

                case NGX_STREAM_BAD_GATEWAY:
                    (void) ngx_atomic_fetch_add(&stats->sessions[4], 1);
                    break;

                case NGX_STREAM_SERVICE_UNAVAILABLE:
                    (void) ngx_atomic_fetch_add(&stats->sessions[5], 1);
                    break;
                }

            } else {
                (void) ngx_atomic_fetch_add(&stats->discarded, 1);
            }

            if (s->received > 0) {
                (void) ngx_atomic_fetch_add(&stats->received, s->received);
            }

            if (c->sent > 0) {
                (void) ngx_atomic_fetch_add(&stats->sent, c->sent);
            }
        }
    }
#endif

    pool = c->pool;

    ngx_close_connection(c);

    ngx_destroy_pool(pool);
}


static u_char *
ngx_stream_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                *p;
    ngx_stream_session_t  *s;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    s = log->data;

    p = ngx_snprintf(buf, len, ", %sclient: %V, server: %V",
                     s->connection->type == SOCK_DGRAM ? "udp " : "",
                     &s->connection->addr_text,
                     &s->connection->listening->addr_text);
    len -= p - buf;
    buf = p;

    if (s->log_handler) {
        p = s->log_handler(log, buf, len);
    }

    return p;
}


#if (NGX_API)

ngx_int_t
ngx_api_stream_server_zones_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    ngx_api_iter_ctx_t            ictx;
    ngx_stream_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_cycle_get_module_main_conf(ngx_cycle,
                                                 ngx_stream_core_module);

    ictx.entry.handler = ngx_api_object_handler;
    ictx.entry.data.ents = ngx_api_stream_server_zone_entries;
    ictx.elts = cmcf->server_zones;

    return ngx_api_object_iterate(ngx_api_stream_server_zones_iter,
                                  &ictx, actx);
}


static ngx_int_t
ngx_api_stream_server_zones_iter(ngx_api_iter_ctx_t *ictx, ngx_api_ctx_t *actx)
{
    ngx_stream_stats_zone_t  *zone;

    zone = ictx->elts;

    if (zone == NULL) {
        return NGX_DECLINED;
    }

    ictx->entry.name = zone->name;
    ictx->ctx = zone;
    ictx->elts = zone->next;

    return NGX_OK;
}


static ngx_int_t
ngx_api_stream_zone_handler(ngx_api_entry_data_t data, ngx_api_ctx_t *actx,
    void *ctx)
{
    ngx_stream_stats_zone_t *zone = ctx;

    return ngx_api_object_handler(data, actx, zone->stats);
}


static ngx_int_t
ngx_api_stream_session_codes_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    ngx_stream_stats_zone_t *zone = ctx;

    ctx = (u_char *) zone->stats + data.off;
    data.ents = ngx_api_stream_session_codes_entries;

    return ngx_api_object_handler(data, actx, ctx);
}


#if (NGX_STREAM_SSL)

static ngx_int_t
ngx_api_stream_ssl_handler(ngx_api_entry_data_t data,ngx_api_ctx_t *actx,
    void *ctx)
{
    ngx_stream_stats_zone_t *zone = ctx;

    if (zone->ssl) {
        return ngx_api_object_handler(data, actx, zone->stats);
    }

    return NGX_DECLINED;
}

#endif

#endif /* NGX_API */
