
/*
 * Copyright (C) 2025 Web Server LLC
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_client.h>


#define ngx_http_client_from_conn(c)                                          \
    (ngx_http_client_t *)                                                     \
        ((u_char *) c - offsetof(ngx_http_client_t, connection))


#define ngx_http_client_reset_log_ctx(log)                                    \
    do {                                                                      \
        ngx_http_log_ctx_t  *ctx;                                             \
        ctx = (ngx_http_log_ctx_t *) (log)->data;                             \
        ctx->request = NULL;                                                  \
        ctx->current_request = NULL;                                          \
    } while (0)


typedef struct {
    ngx_log_t                                log;
    ngx_http_conf_ctx_t                     *ctx;

    ngx_connection_t                         connection;
    ngx_event_t                              read;
    ngx_event_t                              write;
} ngx_http_client_t;


typedef struct {
    void                                    *data;
    ngx_http_post_subrequest_pt              handler;
    ngx_http_output_header_filter_pt         response_header_filter;
    ngx_http_output_body_filter_pt           response_body_filter;

} ngx_http_client_request_ctx_t;


static void **ngx_http_client_find_loc_conf(ngx_conf_t *cf,
    ngx_http_conf_ctx_t *srv_ctx, ngx_str_t *name);
static ngx_http_conf_ctx_t *ngx_http_client_create_srv_ctx(ngx_conf_t *cf);
static ngx_http_core_main_conf_t *ngx_http_client_get_main_conf(ngx_conf_t *cf);

static ngx_int_t ngx_http_client_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_client_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_client_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static void ngx_http_client_cleanup(void *data);
static u_char *ngx_http_client_log_error(ngx_log_t *log, u_char *buf,
    size_t len);
static ngx_http_client_t *ngx_http_client_create(ngx_pool_t *pool);
static ngx_int_t ngx_http_client_init_connection(ngx_http_client_t *htc);
static void ngx_http_client_request_handler(ngx_event_t *ev);
static ngx_int_t ngx_http_client_init_request(ngx_connection_t *c,
    ngx_http_conf_ctx_t *ctx, ngx_str_t *uri,
    ngx_http_post_subrequest_pt handler, void *data);
static void ngx_http_client_request_cleanup(void *data);


static ngx_http_module_t  ngx_http_client_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_client_init,                   /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    NULL,                                   /* create location configuration */
    NULL                                    /* merge location configuration */
};


ngx_module_t  ngx_http_client_module = {
    NGX_MODULE_V1,
    &ngx_http_client_module_ctx,           /* module context */
    NULL,                                  /* module directives */
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


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt  ngx_http_next_body_filter;


ngx_http_conf_ctx_t *
ngx_http_client_create_location(ngx_conf_t *cf, ngx_str_t *name,
    ngx_str_t *commands)
{
    void                        *buf;
    ngx_int_t                    rc;
    ngx_str_t                    loc_cmd;
    ngx_http_conf_ctx_t         *ctx, *srv_ctx;
    ngx_http_core_main_conf_t   *cmcf;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "http client create location \"%V\"", name);

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    rc = ngx_http_client_find_location(cf, name, ctx);
    if (rc == NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                      "using explicit client location for \"%V\"", name);
        goto done;
    }

    /* no default commands ? location must exist then */
    if (commands == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "requested client location \"%V\" is missing", name);
        return NULL;
    }

    /* default commands are provided - proceed with creation */

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                  "creating implicit client block for \"%V\"", name);

    cmcf = ngx_http_client_get_main_conf(cf);
    if (cmcf == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                       "http{} block injection failed");
        return NULL;
    }

    srv_ctx = ngx_http_client_create_srv_ctx(cf);
    if (srv_ctx == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                       "client{} block injection failed");
        return NULL;
    }

    ctx->main_conf = srv_ctx->main_conf;
    ctx->srv_conf = srv_ctx->srv_conf;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "http client injecting location \"%V\"", name);

    loc_cmd.len = name->len + sizeof("location {}}") - 1;
    buf = ngx_pnalloc(cf->pool, loc_cmd.len);
    if (buf == NULL) {
        return NULL;
    }
    loc_cmd.data = buf;

    loc_cmd.len = ngx_sprintf(buf, "location %V{}}", name) - loc_cmd.data;

    /* this will create location in given server */
    if (ngx_conf_parse_chunk(cf, srv_ctx, &loc_cmd, NGX_HTTP_MODULE,
                             NGX_HTTP_SRV_CONF)
        != NGX_OK)
    {
        return NULL;
    }

    /* find the created location */
    ctx->loc_conf = ngx_http_client_find_loc_conf(cf, srv_ctx, name);
    if (ctx->loc_conf == NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                       "location \"%V\" injection failed", name);
        return NULL;
    }

done:

    if (commands == NULL) {
        /* no default commands, but location exists */
        return ctx;
    }

    /* now parse commands in found or created location */

    if (ngx_conf_parse_chunk(cf, ctx, commands, NGX_HTTP_MODULE,
                             NGX_HTTP_LOC_CONF)
        != NGX_OK)
    {
        return NULL;
    }

    return ctx;
}


ngx_int_t
ngx_http_client_find_location(ngx_conf_t *cf, ngx_str_t *name,
    ngx_http_conf_ctx_t *res)
{
    ngx_queue_t                 *q;
    ngx_http_conf_ctx_t         *srv_ctx;
    ngx_http_core_srv_conf_t    *cscf;
    ngx_http_core_main_conf_t   *cmcf;

    cmcf = ngx_http_cycle_get_module_main_conf(cf->cycle, ngx_http_core_module);
    if (cmcf == NULL) {
        /* no http block */
        return NGX_DECLINED;
    }

    /* scan all client blocks */
    for (q = ngx_queue_head(&cmcf->clients);
         q != ngx_queue_sentinel(&cmcf->clients);
         q = ngx_queue_next(q))
    {
        cscf = ngx_queue_data(q, ngx_http_core_srv_conf_t, client_queue);

        srv_ctx = cscf->ctx;

        /* scan all locations inside client block */
        res->loc_conf = ngx_http_client_find_loc_conf(cf, srv_ctx, name);
        if (res->loc_conf) {
            res->main_conf = srv_ctx->main_conf;
            res->srv_conf = srv_ctx->srv_conf;

            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


static void **
ngx_http_client_find_loc_conf(ngx_conf_t *cf, ngx_http_conf_ctx_t *srv_ctx,
    ngx_str_t *name)
{
    void                       *orig;
    ngx_queue_t                *q;
    ngx_http_core_loc_conf_t   *pclcf;
    ngx_http_location_queue_t  *lq;

    orig = cf->ctx;
    cf->ctx = srv_ctx;
    pclcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    cf->ctx = orig;

    if (pclcf == NULL || pclcf->locations == NULL) {
        return NULL;
    }

    for (q = ngx_queue_head(pclcf->locations);
         q != ngx_queue_sentinel(pclcf->locations);
         q = ngx_queue_next(q))
    {
        lq = (ngx_http_location_queue_t *) q;

        /* named locations are always exact */
        if (!lq->exact) {
            continue;
        }

        if (name->len != lq->name->len
            || ngx_strncmp(name->data, lq->name->data, name->len) != 0)
        {
            continue;
        }

        return lq->exact->conf->loc_conf;
    }

    return NULL;
}


static ngx_http_core_main_conf_t *
ngx_http_client_get_main_conf(ngx_conf_t *cf)
{
    ngx_http_conf_ctx_t        *hctx;
    ngx_http_core_main_conf_t  *cmcf;

    static ngx_str_t http_block = ngx_string("http{}}");

    cmcf = ngx_http_cycle_get_module_main_conf(cf->cycle, ngx_http_core_module);
    if (cmcf) {
        return cmcf;
    }

    /* need to create */

    hctx = (ngx_http_conf_ctx_t *) cf->cycle->conf_ctx;

    if (ngx_conf_parse_chunk(cf, hctx, &http_block, NGX_CORE_MODULE,
                             NGX_MAIN_CONF)
        != NGX_OK)
    {
        return NULL;
    }

    return ngx_http_cycle_get_module_main_conf(cf->cycle, ngx_http_core_module);
}


static ngx_http_conf_ctx_t *
ngx_http_client_create_srv_ctx(ngx_conf_t *cf)
{
    ngx_queue_t                *q;
    ngx_http_conf_ctx_t        *hctx;
    ngx_http_core_srv_conf_t   *cscf;
    ngx_http_core_main_conf_t  *cmcf;

    static ngx_str_t client_block = ngx_string("client{access_log off;}}");

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "http client injecting client block");

    hctx = (ngx_http_conf_ctx_t *) cf->cycle->conf_ctx[ngx_http_module.index];

    if (ngx_conf_parse_chunk(cf, hctx, &client_block, NGX_HTTP_MODULE,
                             NGX_HTTP_MAIN_CONF)
        != NGX_OK)
    {
        return NULL;
    }

    /* just added client block is the last one in queue */
    cmcf = ngx_http_cycle_get_module_main_conf(cf->cycle, ngx_http_core_module);

    q = ngx_queue_last(&cmcf->clients);

    cscf = ngx_queue_data(q, ngx_http_core_srv_conf_t, client_queue);

    cscf->is_implicit = 1;

    return cscf->ctx;
}


ngx_http_request_t *
ngx_http_client_create_request(ngx_pool_t *pool,
    ngx_http_conf_ctx_t *ctx, ngx_str_t *uri,
    ngx_http_post_subrequest_pt handler, void *data)
{
    ngx_connection_t    *c;
    ngx_http_client_t   *htc;
    ngx_http_request_t  *r;

    htc = ngx_http_client_create(pool);
    if (htc == NULL) {
        return NULL;
    }

    if (ngx_http_client_init_connection(htc) != NGX_OK) {
        return NULL;
    }

    c = &htc->connection;

    if (ngx_http_client_init_request(c, ctx, uri, handler, data)
        != NGX_OK)
    {
        c->destroyed = 1;
        pool = c->pool;
        ngx_close_connection(c);
        ngx_destroy_pool(pool);

        return NULL;
    }

    r = c->data;

    return r;
}


void
ngx_http_client_close_request(ngx_http_request_t *r)
{
    ngx_http_client_request_ctx_t  *cctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http client close request");

    cctx = ngx_http_get_module_ctx(r, ngx_http_client_module);

    /* disable user handler that is called from http cleanup */
    cctx->handler = NULL;

    ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
}


static ngx_int_t
ngx_http_client_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_client_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_client_body_filter;

    return NGX_OK;
}


static ngx_int_t
ngx_http_client_header_filter(ngx_http_request_t *r)
{
    ngx_http_client_request_ctx_t  *cctx;

    cctx = ngx_http_get_module_ctx(r, ngx_http_client_module);

    if (cctx == NULL) {
        return ngx_http_next_header_filter(r);
    }

    if (cctx->response_header_filter) {
        return cctx->response_header_filter(r);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_client_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_client_request_ctx_t  *cctx;

    cctx = ngx_http_get_module_ctx(r, ngx_http_client_module);

    if (cctx == NULL || cctx->response_body_filter == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    return cctx->response_body_filter(r, in);
}


static void
ngx_http_client_cleanup(void *data)
{
    ngx_connection_t   *c;
    ngx_http_client_t  *htc;

    htc = data;
    c = &htc->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, &htc->log, 0,
                   "http client cleanup");

    if (c->destroyed) {
        return;
    }

    c->destroyed = 1;

    ngx_close_connection(c);

    if (c->pool) {
        ngx_destroy_pool(c->pool);
    }
}


static u_char *
ngx_http_client_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char              *p;
    ngx_http_request_t  *r;
    ngx_http_log_ctx_t  *ctx;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    ctx = log->data;
    r = ctx->request;

    if (r == NULL) {
        return buf;
    }

    return r->log_handler(r, ctx->current_request, buf, len);
}


static ngx_http_client_t *
ngx_http_client_create(ngx_pool_t *pool)
{
    ngx_http_client_t   *htc;
    ngx_http_log_ctx_t  *log_ctx;
    ngx_pool_cleanup_t  *cln;

    htc = ngx_pcalloc(pool, sizeof(ngx_http_client_t));
    if (htc == NULL) {
        return NULL;
    }

    log_ctx = ngx_pcalloc(pool, sizeof(ngx_http_log_ctx_t));
    if (log_ctx == NULL) {
        return NULL;
    }

    cln = ngx_pool_cleanup_add(pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_http_client_cleanup;
    cln->data = htc;

    ngx_memcpy(&htc->log, pool->log, sizeof(ngx_log_t));

    htc->log.handler = ngx_http_client_log_error;
    htc->log.data = log_ctx;

    return htc;
}


static ngx_int_t
ngx_http_client_init_connection(ngx_http_client_t *htc)
{
    ngx_event_t         *rev, *wev;
    ngx_connection_t    *c;
    struct sockaddr_in  *sin;

    c = &htc->connection;

    c->pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, &htc->log);
    if (c->pool == NULL) {
        return NGX_ERROR;
    }

    rev = &htc->read;
    wev = &htc->write;

    wev->write = 1;

    rev->data = c;
    wev->data = c;

    rev->ready = 1;
    wev->ready = 1;

    rev->log = &htc->log;
    wev->log = &htc->log;

    rev->index = NGX_INVALID_INDEX;
    wev->index = NGX_INVALID_INDEX;

    rev->handler = ngx_http_client_request_handler;
    wev->handler = ngx_http_client_request_handler;

    c->log = &htc->log;

    c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
    c->log->connection = c->number;

    c->read = rev;
    c->write = wev;

    c->fd = -1;
    c->stub = 1;
    c->tcp_nodelay = NGX_TCP_NODELAY_DISABLED;

    sin = ngx_pcalloc(c->pool, sizeof(struct sockaddr_in));
    if (sin == NULL) {
        ngx_destroy_pool(c->pool);
        return NGX_ERROR;
    }

    /* fake client address: 127.0.0.1:0 */
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin->sin_port = htons(0);

    c->local_sockaddr = (struct sockaddr *) sin;
    c->local_socklen = sizeof(struct sockaddr_in);

    c->type = SOCK_STREAM;

    c->start_time = ngx_current_msec;

    return NGX_OK;
}


static void
ngx_http_client_request_handler(ngx_event_t *ev)
{
    ngx_connection_t    *c;
    ngx_http_request_t  *r;

    c = ev->data;
    r = c->data;

    ngx_http_set_log_request(c->log, r);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http client request handler: \"%V?%V\"", &r->uri, &r->args);

    if (ev->delayed && ev->timedout) {
        ev->delayed = 0;
        ev->timedout = 0;
    }

    if (ev->write) {
        r->write_event_handler(r);

    } else {
        r->read_event_handler(r);
    }

    ngx_http_run_posted_requests(c);
}


static ngx_int_t
ngx_http_client_init_request(ngx_connection_t *c, ngx_http_conf_ctx_t *ctx,
    ngx_str_t *uri, ngx_http_post_subrequest_pt handler, void *data)
{
    u_char                         *p;
    ngx_http_cleanup_t             *cln;
    ngx_http_request_t             *r;
    ngx_http_connection_t           hc;
    ngx_http_client_request_ctx_t  *cctx;

    ngx_memzero(&hc, sizeof(ngx_http_connection_t));

    hc.conf_ctx = ctx;

    c->data = &hc;

    r = ngx_http_create_request(c);
    if (r == NULL) {
        return NGX_ERROR;
    }

    cctx = ngx_pcalloc(r->pool, sizeof(ngx_http_client_request_ctx_t));
    if (cctx == NULL) {
       return NGX_ERROR;
    }

    cctx->handler = handler;
    cctx->data = data;

    ngx_http_set_ctx(r, cctx, ngx_http_client_module);

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_http_client_request_cleanup;
    cln->data = r;

    c->data = r;

    r->header_in = ngx_alloc_buf(r->pool);
    if (r->header_in == NULL) {
        goto failed;
    }

    if (ngx_list_init(&r->headers_in.headers, r->pool, 4,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        goto failed;
    }

    r->read_event_handler = ngx_http_request_empty_handler;
    r->write_event_handler = ngx_http_request_empty_handler;

    r->method = NGX_HTTP_GET;
    r->method_name = ngx_http_core_get_method;

    /* no real client here, prevents shutdown() */
    r->lingering_close = 0;

    /* avoid writing logs on close */
    r->logged = 1;

    p = (u_char *) ngx_strlchr(uri->data, uri->data + uri->len, '?');

    if (p) {
        r->uri.data = uri->data;
        r->uri.len = p - uri->data;

        p++;

        r->args.data = p;
        r->args.len = (uri->data + uri->len) - p;

    } else {
        r->uri = *uri;
        ngx_str_null(&r->args);
    }

    r->unparsed_uri = *uri;
    r->valid_unparsed_uri = 1;

    return NGX_OK;

failed:

    ngx_http_client_reset_log_ctx(c->log);
    ngx_destroy_pool(r->pool);

    return NGX_ERROR;
}


void
ngx_http_client_set_header_filter(ngx_http_request_t *r,
    ngx_http_output_header_filter_pt header_filter)
{
    ngx_http_client_request_ctx_t  *cctx;

    cctx = ngx_http_get_module_ctx(r, ngx_http_client_module);

    cctx->response_header_filter = header_filter;
}


void
ngx_http_client_set_body_filter(ngx_http_request_t *r,
    ngx_http_output_body_filter_pt body_filter)
{
    ngx_http_client_request_ctx_t  *cctx;

    cctx = ngx_http_get_module_ctx(r, ngx_http_client_module);

    cctx->response_body_filter = body_filter;
}


static void
ngx_http_client_request_cleanup(void *data)
{
    ngx_int_t                       rc;
    ngx_http_request_t             *r;
    ngx_http_client_request_ctx_t  *cctx;

    r = (ngx_http_request_t *) data;

    cctx = ngx_http_get_module_ctx(r, ngx_http_client_module);

    if (cctx == NULL) {
        /* should not happen normally */
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "missing client ctx in request pool on cleanup");
        return;
    }

    if (cctx->handler == NULL) {
        /* early error, client reset */
        return;
    }

    rc = r->terminated ? NGX_ERROR
                       : (r->headers_out.status == 0) ? NGX_ERROR : NGX_OK;

    (void) cctx->handler(r, cctx->data, rc);
}
