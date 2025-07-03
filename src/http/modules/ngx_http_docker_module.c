
/*
 * Copyright (C) 2025 Web Server LLC
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>
#include <ngx_docker.h>


#define ngx_http_docker_get_main_conf()                                       \
    ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_docker_module)


typedef struct ngx_http_docker_session_s  ngx_http_docker_session_t;

typedef ngx_int_t (*ngx_http_docker_body_filter_pt)(ngx_http_request_t *r,
                                                    ngx_chain_t *in);

typedef void (*ngx_http_docker_response_pt)(ngx_http_docker_session_t *ds,
                                            ngx_http_request_t *r,
                                            ngx_int_t rc);


typedef struct {
    ngx_url_t                          url;

    ngx_log_t                          log;
    ngx_http_log_ctx_t                 log_ctx;

    size_t                             max_object_size;

    ngx_http_conf_ctx_t               *events_ctx;
    ngx_http_conf_ctx_t               *containers_ctx;
} ngx_http_docker_main_conf_t;

typedef struct {
    ngx_rbtree_t                       rbtree;
    ngx_rbtree_node_t                  sentinel;

    ngx_event_t                        version_event;
    ngx_event_t                        containers_event;
    ngx_event_t                        tracking_event;

    ngx_docker_api_version_t           api_version;

    time_t                             last_update;
} ngx_http_docker_ctx_t;

struct ngx_http_docker_session_s {
    ngx_buf_t                          buf;

    ngx_pool_t                        *pool;

    ngx_http_docker_response_pt        response_handler;

    ngx_http_docker_ctx_t             *ctx;
    ngx_event_t                        ev;

    void                              *data;
};


static ngx_int_t ngx_http_docker_init_worker(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_docker_events_json_handler(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_docker_json_handler(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_docker_send_request(ngx_http_docker_session_t *ds,
    ngx_str_t *uri, ngx_http_conf_ctx_t *ctx, ngx_uint_t events);
static ngx_int_t ngx_http_docker_send_events_request(
    ngx_http_docker_session_t *ds, ngx_str_t *uri);
static ngx_int_t ngx_http_docker_send_containers_request(
    ngx_http_docker_session_t *ds, ngx_str_t *uri);

static void ngx_http_docker_container_handler(ngx_event_t *ev);
static void ngx_http_docker_destroy_session(ngx_http_docker_session_t *ds);
static void ngx_http_docker_version_handler(ngx_event_t *ev);
static void ngx_http_docker_containers_handler(ngx_event_t *ev);
static void ngx_http_docker_events_handler(ngx_event_t *ev);
static void ngx_http_docker_container_response_handler(
    ngx_http_docker_session_t *ds, ngx_http_request_t *r, ngx_int_t rc);
static void ngx_http_docker_events_response_handler(
    ngx_http_docker_session_t *ds, ngx_http_request_t *r, ngx_int_t rc);
static void ngx_http_docker_containers_response_handler(
    ngx_http_docker_session_t *ds, ngx_http_request_t *r, ngx_int_t rc);
static ngx_int_t ngx_http_docker_finalize_request(ngx_http_request_t *r,
    void *data, ngx_int_t rc);
static void ngx_http_docker_version_response_handler(
    ngx_http_docker_session_t *ds, ngx_http_request_t *r, ngx_int_t rc);
static void ngx_http_docker_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);

static void *ngx_http_docker_create_main_conf(ngx_conf_t *cf);

static char *ngx_http_docker_init_main_conf(ngx_conf_t *cf, void *conf);
static char *ngx_http_docker_endpoint(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_docker_format_endpoint(ngx_pool_t *pool,
    ngx_str_t *url, ngx_str_t *res, const char *fmt);

static ngx_http_docker_session_t *ngx_http_docker_create_session(
    ngx_http_docker_ctx_t *ctx);


static ngx_command_t  ngx_http_docker_commands[] = {

    { ngx_string("docker_endpoint"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_docker_endpoint,
      0,
      0,
      NULL },

    { ngx_string("docker_max_object_size"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_docker_main_conf_t, max_object_size),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_docker_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    ngx_http_docker_create_main_conf,      /* create main configuration */
    ngx_http_docker_init_main_conf,        /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */

};


ngx_module_t  ngx_http_docker_module = {
    NGX_MODULE_V1,
    &ngx_http_docker_module_ctx,         /* module context */
    ngx_http_docker_commands,            /* module directives */
    NGX_HTTP_MODULE,                     /* module type */
    NULL,                                /* init master */
    NULL,                                /* init module */
    ngx_http_docker_init_worker,         /* init process */
    NULL,                                /* init thread */
    NULL,                                /* exit thread */
    NULL,                                /* exit process */
    NULL,                                /* exit master */
    NGX_MODULE_V1_PADDING
};


static void
ngx_http_docker_events_response_handler(ngx_http_docker_session_t *ds,
    ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_connection_t       *c;
    ngx_http_docker_ctx_t  *ctx;

    ctx = ds->ctx;

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "response error (%i)", rc);
    }

    c = r->connection;

    if (c->error) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "connection error");
    }

    if (ngx_exiting) {
        return;
    }

    ngx_add_timer(&ctx->tracking_event, NGX_DOCKER_EVENT_RETRY_TIME);
}


static void
ngx_http_docker_container_response_handler(ngx_http_docker_session_t *ds,
    ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_str_t               *id;
    ngx_http_docker_ctx_t   *ctx;
    ngx_docker_container_t  *dc;

    id = ds->data;
    ctx = ds->ctx;

    dc = ngx_docker_lookup_container(&ctx->rbtree, id);
    if (dc == NULL || dc->ip.len != 0) {
        return;
    }

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "response error (%i)", rc);
        goto retry;
    }

    if (r->connection->error) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "connection error");
        goto retry;
    }

    ngx_docker_process_container(dc, &ds->buf, ds->pool, &ctx->rbtree,
                                 r->connection->log);

    return;

retry:

    if (dc->expired == 2) {
        return;
    }

    dc->expired++;

    ngx_add_timer(&dc->event, NGX_DOCKER_EVENT_RETRY_TIME);
}


static void
ngx_http_docker_containers_response_handler(ngx_http_docker_session_t *ds,
    ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_table_elt_t        *date;
    ngx_http_docker_ctx_t  *ctx;

    ctx = ds->ctx;

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "response error (%i)", rc);
        goto retry;
    }

    if (r->connection->error) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "connection error");
        goto retry;
    }

    if (ngx_docker_process_containers(&ds->buf, ds->pool, &ctx->rbtree,
                                      ngx_cycle->log) != NGX_OK)
    {
        goto retry;
    }

    date = r->headers_out.date;
    if (date != NULL) {
        ctx->last_update = ngx_parse_http_time(date->value.data,
                                               date->value.len);
    }

    ngx_post_event(&ctx->tracking_event, &ngx_posted_events);

    return;

retry:

    ngx_add_timer(&ctx->containers_event, NGX_DOCKER_EVENT_RETRY_TIME);
}


static void
ngx_http_docker_version_response_handler(ngx_http_docker_session_t *ds,
    ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_http_docker_ctx_t  *ctx;

    ctx = ds->ctx;

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "response error (%i)", rc);
        goto retry;
    }

    if (r->connection->error) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "connection error");
        goto retry;
    }

    if (ngx_docker_get_api_version(&ds->buf, ds->pool, &ctx->api_version,
                                   r->connection->log) != NGX_OK)
    {
        goto retry;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                   "Docker API version: \"v%ui.%ui\"",
                   ctx->api_version.major, ctx->api_version.minor);

    ngx_post_event(&ctx->containers_event, &ngx_posted_events);

    return;

retry:

    ngx_add_timer(&ctx->version_event, NGX_DOCKER_EVENT_RETRY_TIME);
}


static void
ngx_http_docker_destroy_session(ngx_http_docker_session_t *ds)
{
    ngx_free(ds->buf.start);

    ngx_destroy_pool(ds->pool);
}


static ngx_int_t
ngx_http_docker_finalize_request(ngx_http_request_t *r, void *data,
    ngx_int_t rc)
{
    ngx_http_docker_session_t *ds = (ngx_http_docker_session_t *) data;

    ds->response_handler(ds, r, rc);
    ngx_post_event(&ds->ev, &ngx_posted_events);

    return NGX_OK;
}


static void
ngx_http_docker_session_delete_handler(ngx_event_t *ev)
{
    ngx_http_docker_session_t *ds = ev->data;

    ngx_http_docker_destroy_session(ds);
}


static ngx_http_docker_session_t *
ngx_http_docker_create_session(ngx_http_docker_ctx_t *ctx)
{
    ngx_pool_t                 *pool;
    ngx_http_docker_session_t  *ds;

    pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, ngx_cycle->log);
    if (pool == NULL) {
        return NULL;
    }

    ds = ngx_pcalloc(pool, sizeof(ngx_http_docker_session_t));
    if (ds == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    ds->ctx = ctx;
    ds->pool = pool;

    ds->ev.data = ds;
    ds->ev.handler = ngx_http_docker_session_delete_handler;
    ds->ev.log = ngx_cycle->log;

    ds->buf.memory = 1;

    return ds;
}


static ngx_int_t
ngx_http_docker_send_request(ngx_http_docker_session_t *ds, ngx_str_t *uri,
    ngx_http_conf_ctx_t *ctx, ngx_uint_t events)
{
    ngx_http_request_t              *r;
    ngx_http_core_loc_conf_t        *clcf;
    ngx_http_output_body_filter_pt   filter;

    r = ngx_http_client_create_request(ds->pool, ctx, uri,
                                       ngx_http_docker_finalize_request, ds);
    if (r == NULL) {
        return NGX_ERROR;
    }

    r->connection->idle = events ? 1 : 0;

    filter = events ? ngx_http_docker_events_json_handler
                    : ngx_http_docker_json_handler;

    ngx_http_client_set_body_filter(r, filter);

    ngx_http_set_ctx(r, ds, ngx_http_docker_module);

    if (ngx_http_request_add_header_cstr(r, "User-Agent", ANGIE_VER)
        != NGX_OK)
    {
        ngx_http_client_close_request(r);
        return NGX_ERROR;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_http_finalize_request(r, clcf->handler(r));

    return NGX_OK;
}


static ngx_int_t
ngx_http_docker_send_events_request(ngx_http_docker_session_t *ds,
    ngx_str_t *uri)
{
    ngx_http_docker_main_conf_t  *dmcf;

    dmcf = ngx_http_docker_get_main_conf();

    return ngx_http_docker_send_request(ds, uri, dmcf->events_ctx, 1);
}


static ngx_int_t
ngx_http_docker_send_containers_request(ngx_http_docker_session_t *ds,
    ngx_str_t *uri)
{
    ngx_http_docker_main_conf_t  *dmcf;

    dmcf = ngx_http_docker_get_main_conf();

    return ngx_http_docker_send_request(ds, uri, dmcf->containers_ctx, 0);
}


static void
ngx_http_docker_version_handler(ngx_event_t *ev)
{
    ngx_str_t                   uri;
    ngx_http_docker_ctx_t      *ctx;
    ngx_http_docker_session_t  *ds;

    ctx = ev->data;

    ds = ngx_http_docker_create_session(ctx);
    if (ds == NULL) {
        goto retry;
    }

    ds->response_handler = ngx_http_docker_version_response_handler;

    ngx_str_set(&uri, "/version");

    if (ngx_http_docker_send_containers_request(ds, &uri) != NGX_OK) {
        ngx_http_docker_destroy_session(ds);
        goto retry;
    }

    return;

retry:

    ngx_add_timer(&ctx->version_event, NGX_DOCKER_EVENT_RETRY_TIME);
}


static void
ngx_http_docker_containers_handler(ngx_event_t *ev)
{
    u_char                     *p;
    ngx_str_t                   uri;
    ngx_http_docker_ctx_t      *ctx;
    ngx_http_docker_session_t  *ds;

    ctx = ev->data;

    ds = ngx_http_docker_create_session(ctx);
    if (ds == NULL) {
        goto retry;
    }

    ds->response_handler = ngx_http_docker_containers_response_handler;

    uri.len = sizeof("/v255.255/containers/json") - 1;

    uri.data = ngx_pnalloc(ds->pool, uri.len);
    if (uri.data == NULL) {
        ngx_http_docker_destroy_session(ds);
        goto retry;
    }

    p = ngx_snprintf(uri.data, uri.len,
                     "/v%ui.%ui/containers/json",
                      ctx->api_version.major, ctx->api_version.minor);

    uri.len = p - uri.data;

    if (ngx_http_docker_send_containers_request(ds, &uri) != NGX_OK) {
        ngx_http_docker_destroy_session(ds);
        goto retry;
    }

    return;

retry:

    ngx_add_timer(&ctx->containers_event, NGX_DOCKER_EVENT_RETRY_TIME);
}


static void
ngx_http_docker_events_handler(ngx_event_t *ev)
{
    u_char                     *p;
    ngx_str_t                   uri;
    ngx_http_docker_ctx_t      *ctx;
    ngx_http_docker_session_t  *ds;

    ctx = ev->data;

    ds = ngx_http_docker_create_session(ctx);
    if (ds == NULL) {
        goto retry;
    }

    ds->response_handler = ngx_http_docker_events_response_handler;

    uri.len = sizeof("/v255.255/events?filters="
                     "{\"type\":{\"container\":true}}&since=") - 1
              + NGX_TIME_T_LEN;

    uri.data = ngx_pnalloc(ds->pool, uri.len);
    if (uri.data == NULL) {
        ngx_http_docker_destroy_session(ds);
        goto retry;
    }

    p = ngx_snprintf(uri.data, uri.len,
                     "/v%ui.%ui/events?filters={\"type\":{\"container\":true}}",
                     ctx->api_version.major, ctx->api_version.minor);

    if (ctx->last_update != (time_t) NGX_ERROR) {
        p = ngx_snprintf(p, uri.len - (p - uri.data),
                         "&since=%T", ctx->last_update);
    }

    uri.len = p - uri.data;

    if (ngx_http_docker_send_events_request(ds, &uri) != NGX_OK) {
        ngx_http_docker_destroy_session(ds);
        goto retry;
    }

    return;

retry:

    ngx_add_timer(&ctx->tracking_event, NGX_DOCKER_EVENT_RETRY_TIME);
}


static void
ngx_http_docker_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t       **p;
    ngx_docker_container_t   *dc, *dct;

    for ( ;; ) {

        if (node->key < temp->key) {
            p = &temp->left;

        } else if (node->key > temp->key) {
            p = &temp->right;

        } else { /* node->key == temp->key */
            dc = ngx_docker_node(node);
            dct = ngx_docker_node(node);

            p = (ngx_memn2cmp(dc->id.data, dct->id.data, dc->id.len,
                              dct->id.len) < 0) ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static ngx_int_t
ngx_http_docker_init_worker(ngx_cycle_t *cycle)
{
    ngx_http_docker_ctx_t        *ctx;
    ngx_http_docker_main_conf_t  *dmcf;

    if ((ngx_process != NGX_PROCESS_WORKER
        && ngx_process != NGX_PROCESS_SINGLE) || ngx_worker > 0)
    {
        return NGX_OK;
    }

    dmcf = ngx_http_docker_get_main_conf();

    if (dmcf == NULL || dmcf->url.addrs == NULL) {
        return NGX_OK;
    }

    ctx = ngx_pcalloc(cycle->pool, sizeof(ngx_http_docker_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->last_update = (time_t) NGX_ERROR;

    ngx_rbtree_init(&ctx->rbtree, &ctx->sentinel,
                    ngx_http_docker_rbtree_insert_value);

    ctx->version_event.data = ctx;
    ctx->version_event.handler = ngx_http_docker_version_handler;
    ctx->version_event.log = cycle->log;
    ctx->version_event.cancelable = 1;

    ctx->containers_event.data = ctx;
    ctx->containers_event.handler = ngx_http_docker_containers_handler;
    ctx->containers_event.log = cycle->log;
    ctx->containers_event.cancelable = 1;

    ctx->tracking_event.data = ctx;
    ctx->tracking_event.handler = ngx_http_docker_events_handler;
    ctx->tracking_event.log = cycle->log;
    ctx->tracking_event.cancelable = 1;

    ngx_add_timer(&ctx->version_event, 1);

    return NGX_OK;
}


static ngx_int_t
ngx_http_docker_json_handler(ngx_http_request_t *r, ngx_chain_t *in)
{
    size_t                        chain_size, size;
    ngx_buf_t                    *b;
    ngx_chain_t                  *cl;
    ngx_http_docker_session_t    *ds;
    ngx_http_docker_main_conf_t  *dmcf;

    chain_size = 0;

    for (cl = in; cl; cl = cl->next) {
        size = cl->buf->last - cl->buf->pos;

        if (size == 0) {
            continue;
        }

        if (!ngx_buf_in_memory(cl->buf)) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "attempting to read from file buffer during "
                          "processing Docker JSON object");
            return NGX_ERROR;
        }

        chain_size += size;
    }

    if (chain_size == 0) {
        return NGX_OK;
    }

    dmcf = ngx_http_docker_get_main_conf();

    ds = ngx_http_get_module_ctx(r, ngx_http_docker_module);

    b = &ds->buf;

    if (b->start == NULL) {

        if (chain_size > dmcf->max_object_size) {
            goto error;
        }

        b->start = ngx_alloc(dmcf->max_object_size, r->connection->log);
        if (b->start == NULL) {
            return NGX_ERROR;
        }

        b->pos = b->start;
        b->last = b->start;
        b->end = b->start + dmcf->max_object_size;

    } else if (chain_size > (size_t) (b->end - b->last)) {
        goto error;
    }

    for ( /* void */ ; in; in = in->next) {
        size = in->buf->last - in->buf->pos;

        b->last = ngx_cpymem(b->last, in->buf->pos, size);

        in->buf->pos = in->buf->last;
    }

    return NGX_OK;

error:

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "Docker sends too large (%ui) object "
                  "for the configured buffer (%ui)",
                  dmcf->max_object_size + chain_size, dmcf->max_object_size);


    return NGX_ERROR;
}


static void
ngx_http_docker_container_handler(ngx_event_t *ev)
{
    u_char                     *p;
    ngx_str_t                  *id, uri;
    ngx_http_docker_ctx_t      *ctx;
    ngx_docker_container_t     *dc;
    ngx_http_docker_session_t  *ds;

    dc = ev->data;
    ctx = dc->data;

    ds = ngx_http_docker_create_session(ctx);
    if (ds == NULL) {
        goto error;
    }

    ds->response_handler = ngx_http_docker_container_response_handler;

    id = ngx_palloc(ds->pool, sizeof(ngx_str_t));
    if (id == NULL) {
        goto error;
    }

    id->len = dc->id.len;

    id->data = ngx_pnalloc(ds->pool, id->len);
    if (id->data == NULL) {
        goto error;
    }

    ngx_memcpy(id->data, dc->id.data, id->len);

    ds->data = id;

    uri.len = sizeof("/v255.255/containers//json") - 1 + dc->id.len;

    uri.data = ngx_pnalloc(ds->pool, uri.len);
    if (uri.data == NULL) {
        goto error;
    }

    p = ngx_snprintf(uri.data, uri.len,
                     "/v%ui.%ui/containers/%V/json",
                     ctx->api_version.major, ctx->api_version.minor, &dc->id);

    uri.len = p - uri.data;

    if (ngx_http_docker_send_containers_request(ds, &uri) != NGX_OK) {
        goto error;
    }

    return;

error:

    if (ds != NULL) {
        ngx_http_docker_destroy_session(ds);
    }

    if (dc->expired == 2) {
        return;
    }

    dc->expired++;

    ngx_add_timer(ev, NGX_DOCKER_EVENT_RETRY_TIME);
}


static time_t
ngx_get_last_event_time(ngx_data_item_t *json)
{
    ngx_str_t         time;
    ngx_data_item_t  *item;

    ngx_str_set(&time, "time");

    item = ngx_data_object_take(json, &time);
    if (item == NULL) {
        return NGX_ERROR;
    }

    return (item->type == NGX_DATA_INTEGER_TYPE) ? (item->data.integer + 1)
                                                 : NGX_ERROR;
}


static ngx_int_t
ngx_http_docker_events_json_handler(ngx_http_request_t *r, ngx_chain_t *in)
{
    u_char                       *last, *p;
    size_t                        size, new_size, last_size, rest_size;
    ngx_buf_t                    *b;
    ngx_int_t                     rc, empty_chain;
    ngx_pool_t                   *tmp_pool;
    ngx_chain_t                  *cl;
    ngx_data_item_t              *json;
    ngx_json_parse_error_t        err;
    ngx_docker_container_t       *dc;
    ngx_http_docker_session_t    *ds;
    ngx_http_docker_main_conf_t  *dmcf;

    empty_chain = 1;

    for (cl = in; cl; cl = cl->next) {

        if (cl->buf->last == cl->buf->pos) {
            continue;
        }

        if (!ngx_buf_in_memory_only(cl->buf)) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "attempting to read from a file buffer via "
                          "processing Docker event");
            return NGX_ERROR;
        }

        empty_chain = 0;
    }

    if (empty_chain) {
        return NGX_OK;
    }

    tmp_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, r->connection->log);
    if (tmp_pool == NULL) {
        return NGX_ERROR;
    }

    dmcf = ngx_http_docker_get_main_conf();

    ds = ngx_http_get_module_ctx(r, ngx_http_docker_module);

    rc = NGX_ERROR;

    for ( /* void */ ; in; in = in->next) {

        if (ds->buf.last == ds->buf.pos) {
            b = in->buf;

        } else {
            b = &ds->buf;

            new_size = in->buf->last - in->buf->pos;

            last_size = (size_t) (b->end - b->last);
            rest_size = last_size + (size_t) (b->pos - b->start);

            if (new_size > rest_size) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "Docker sends too large (%ui) event object "
                              "for the configured buffer (%ui)",
                              dmcf->max_object_size + new_size,
                              dmcf->max_object_size);
                goto exit;
            }

            if (new_size > last_size) {
                size = b->last - b->pos;

                ngx_memmove(b->start, b->pos, size);

                b->pos = b->start;
                b->last = b->start + size;
            }

            b->last = ngx_cpymem(b->last, in->buf->pos, new_size);

            in->buf->pos += new_size;
        }

        while (b->last != b->pos) {
            json = ngx_json_parse_first_object(b->pos, b->last, &last, tmp_pool,
                                               &err);
            if (json != NULL) {
                dc = ngx_docker_process_event(json, &ds->ctx->rbtree,
                                              ngx_cycle->log);
                if (dc != NULL) {
                    dc->data = ds->ctx;
                    dc->event.data = dc;
                    dc->event.log = ngx_cycle->log;
                    dc->event.cancelable = 1;
                    dc->event.handler = ngx_http_docker_container_handler;

                    ngx_post_event(&dc->event, &ngx_posted_events);
                }

                b->pos = last;

                ds->ctx->last_update = ngx_get_last_event_time(json);

                continue;
            }

            /* json == NULL */

            if (err.pos != b->last) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "processing Docker JSON event failed: \"%V\"",
                              &err.desc);
                goto exit;
            }

            if (b != &ds->buf) {
                size = b->last - b->pos;

                if (size >= dmcf->max_object_size) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "Docker sends too large (%ui) event object "
                                  "for the configured buffer (%ui)",
                                  dmcf->max_object_size + size,
                                  dmcf->max_object_size);
                    goto exit;
                }

                if (ds->buf.start == NULL) {
                    p = ngx_alloc(dmcf->max_object_size, r->connection->log);
                    if (p == NULL) {
                        goto exit;
                    }

                } else {
                    p = ds->buf.start;
                }

                ngx_memcpy(p, b->pos, size);

                b->pos += size;

                b = &ds->buf;

                b->start = p;
                b->pos = p;
                b->last = p + size;
                b->end = p + dmcf->max_object_size;
            }

            break;
        }
    }

    rc = NGX_OK;

exit:

    if (ds->buf.start != NULL && (ds->buf.last - ds->buf.pos) == 0) {
        ngx_free(ds->buf.start);

        ds->buf.start = NULL;
    }

    ngx_destroy_pool(tmp_pool);

    return rc;
}


static char *
ngx_http_docker_endpoint(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_docker_main_conf_t *dmcf = conf;

    u_char     *p;
    size_t      len;
    ngx_url_t   u;
    ngx_str_t  *value, *url, name, eproxy, cproxy;

    if (dmcf->url.addrs != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;
    url = &value[1];

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = *url;
    u.uri_part = 1;
    u.no_resolve = 1;

    if (ngx_strncasecmp(url->data, (u_char *) "unix:/", 6) == 0) {
        len = url->len + 7;

        p = ngx_pnalloc(cf->pool, len);
        if (p == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_snprintf(p, len, "http://%V", url);

        url->data = p;
        url->len = len;
    }

    u.url = *url;

    if (ngx_strncasecmp(u.url.data, (u_char *) "http://", 7) == 0) {
        u.url.data += 7;
        u.url.len -= 7;
        u.default_port = 80;

    } else if (ngx_strncasecmp(u.url.data, (u_char *) "https://", 8) == 0) {
        u.url.data += 8;
        u.url.len -= 8;
        u.default_port = 443;

    } else {
        return "invalid url prefix";
    }

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {

        if (u.err) {
            ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                               "%s in Docker endpoint \"%V\"",
                               u.err, url);
        }
        return NGX_CONF_ERROR;
    }

    dmcf->url = u;

    if (ngx_http_docker_format_endpoint(cf->pool, url, &eproxy,
                                        "proxy_pass %V;"
                                        "proxy_buffering off;"
                                        "proxy_read_timeout 365d;"
                                        "proxy_pass_header Date;}")
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }


    if (ngx_http_docker_format_endpoint(cf->pool, url, &cproxy,
                                        "proxy_pass %V;"
                                        "proxy_buffering off;}")
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }


    ngx_str_set(&name, "@docker_events");
    dmcf->events_ctx = ngx_http_client_create_location(cf, &name, &eproxy);
    if (dmcf->events_ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_str_set(&name, "@docker_containers");
    dmcf->containers_ctx = ngx_http_client_create_location(cf, &name, &cproxy);
    if (dmcf->containers_ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_docker_format_endpoint(ngx_pool_t *pool, ngx_str_t *url,
    ngx_str_t *res, const char *fmt)
{
    res->len = ngx_strlen(fmt) + url->len;

    res->data = ngx_pnalloc(pool, res->len);
    if (res->data == NULL) {
        return NGX_ERROR;
    }

    res->len = ngx_snprintf(res->data, res->len, fmt, url) - res->data;

    return NGX_OK;
}


static void *
ngx_http_docker_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_docker_main_conf_t  *dmcf;

    dmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_docker_main_conf_t));
    if (dmcf == NULL) {
        return NULL;
    }

    dmcf->max_object_size = NGX_CONF_UNSET_UINT;

    return dmcf;
}


static char *
ngx_http_docker_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_docker_main_conf_t *dmcf = conf;

    ngx_conf_init_uint_value(dmcf->max_object_size, 64 * 1024);

    return NGX_CONF_OK;
}
