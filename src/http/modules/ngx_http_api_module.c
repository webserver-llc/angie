
/*
 * Copyright (C) Web Server LLC
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static ngx_int_t ngx_http_api_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_api_args(ngx_http_request_t *r, ngx_api_ctx_t *ctx);
static ngx_int_t ngx_http_api_response(ngx_http_request_t *r,
    ngx_api_ctx_t *ctx);
static ngx_int_t ngx_http_api_error(ngx_http_request_t *r, ngx_api_ctx_t *ctx,
    ngx_uint_t status);
static char *ngx_http_set_api(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_http_api_commands[] = {

    { ngx_string("api"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_set_api,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_api_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_api_module = {
    NGX_MODULE_V1,
    &ngx_http_api_module_ctx,              /* module context */
    ngx_http_api_commands,                 /* module directives */
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


static ngx_api_entry_t  ngx_http_api_error_entries[] = {

    {
        .name      = ngx_string("error"),
        .handler   = ngx_api_struct_str_handler,
        .data.off  = offsetof(ngx_api_ctx_t, err)
    },

    {
        .name      = ngx_string("description"),
        .handler   = ngx_api_struct_str_handler,
        .data.off  = offsetof(ngx_api_ctx_t, err_desc)
    },

    ngx_api_null_entry
};


static ngx_int_t
ngx_http_api_handler(ngx_http_request_t *r)
{
    size_t                     len;
    ngx_int_t                  rc;
    ngx_api_ctx_t              ctx;
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    len = clcf->name.len;

    if (len && clcf->name.data[len - 1] == '/') {
        len--;
    }

    ngx_memzero(&ctx, sizeof(ngx_api_ctx_t));

    ctx.connection = r->connection;
    ctx.pool = r->pool;
    ctx.path.data = r->uri.data + len;
    ctx.path.len = r->uri.len - len;

    if (ctx.path.len) {
        ctx.orig_path = ctx.path;

    } else {
        ngx_str_set(&ctx.orig_path, "/");
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http api request path: \"%V\", method: %ui",
                   &ctx.path, r->method);

    if (ngx_http_api_args(r, &ctx) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ctx.path.len && ctx.path.data[0] != '/') {
        return ngx_http_api_error(r, &ctx, NGX_HTTP_NOT_FOUND);
    }

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return ngx_http_api_error(r, &ctx, NGX_HTTP_NOT_ALLOWED);
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return ngx_http_api_error(r, &ctx, rc);
    }

    return ngx_http_api_response(r, &ctx);
}


static ngx_int_t
ngx_http_api_args(ngx_http_request_t *r, ngx_api_ctx_t *ctx)
{
    ngx_str_t  value;

    if (ngx_http_arg(r, (u_char *) "pretty", 6, &value) == NGX_OK) {
        ctx->pretty = (value.len != 3 || ngx_memcmp(value.data, "off", 3) != 0);

    } else {
        ctx->pretty = 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_api_response(ngx_http_request_t *r, ngx_api_ctx_t *ctx)
{
    ngx_int_t         rc;
    ngx_chain_t       out;
    ngx_api_entry_t  *entry;
    ngx_table_elt_t  *expires, *cc;

    entry = ngx_api_root((ngx_cycle_t *) ngx_cycle);

    rc = entry->handler(entry->data, ctx, NULL);

    if (rc == NGX_OK && ctx->path.len > 1) {
        rc = NGX_API_NOT_FOUND;
    }

    if (rc == NGX_DECLINED) {
        rc = NGX_API_NOT_FOUND;
    }

    switch (rc) {

    case NGX_ERROR:
        return ngx_http_api_error(r, ctx, NGX_HTTP_INTERNAL_SERVER_ERROR);

    case NGX_API_NOT_FOUND:
        return ngx_http_api_error(r, ctx, NGX_HTTP_NOT_FOUND);
    }

    /* NGX_OK */

    ngx_str_set(&r->headers_out.content_type, "application/json");

    r->headers_out.content_type_len = r->headers_out.content_type.len;
    r->headers_out.content_type_lowcase = NULL;

    expires = ngx_list_push(&r->headers_out.headers);
    if (expires == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.expires = expires;
    expires->next = NULL;

    expires->hash = 1;
    ngx_str_set(&expires->key, "Expires");
    ngx_str_set(&expires->value, "Thu, 01 Jan 1970 00:00:01 GMT");

    cc = ngx_list_push(&r->headers_out.headers);
    if (cc == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cc->hash = 1;
    ngx_str_set(&cc->key, "Cache-Control");
    ngx_str_set(&cc->value, "no-cache");

    r->headers_out.cache_control = cc;
    cc->next = NULL;

    out.buf = ngx_json_render(r->pool, ctx->out, ctx->pretty);
    if (out.buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = out.buf->last - out.buf->pos;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    out.buf->last_buf = (r == r->main) ? 1 : 0;
    out.buf->last_in_chain = 1;

    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


static ngx_int_t
ngx_http_api_error(ngx_http_request_t *r, ngx_api_ctx_t *ctx, ngx_uint_t status)
{
    size_t                len;
    ngx_int_t             rc;
    ngx_chain_t           out;
    ngx_api_entry_data_t  data;
    u_char                errstr[NGX_MAX_ERROR_STR];

    if (ctx->err.len == 0) {
        switch (status) {

        case NGX_HTTP_NOT_FOUND:
            ngx_str_set(&ctx->err, "PathNotFound");

            len = ngx_snprintf(errstr, NGX_MAX_ERROR_STR,
                               "Requested API element \"%V\" doesn't exist.",
                               &ctx->orig_path)
                  - errstr;

            ctx->err_desc.len = len;
            ctx->err_desc.data = errstr;
            break;

        case NGX_HTTP_NOT_ALLOWED:
            ngx_str_set(&ctx->err, "MethodNotAllowed");

            len = ngx_snprintf(errstr, NGX_MAX_ERROR_STR,
                               "The %V method is not allowed for "
                               "the requested API element \"%V\".",
                               &r->method_name, &ctx->orig_path)
                  - errstr;

            ctx->err_desc.len = len;
            ctx->err_desc.data = errstr;
            break;

        case NGX_HTTP_BAD_REQUEST:
            ngx_str_set(&ctx->err, "BadRequest");
            ngx_str_set(&ctx->err_desc, "Client sent invalid request.");
            break;

        case NGX_HTTP_INTERNAL_SERVER_ERROR:
        default:
            ngx_str_set(&ctx->err, "InternalError");
            ngx_str_set(&ctx->err_desc,
                        "Something went wrong during the API request "
                        "processing.  Check error log for additional "
                        "details.");
        }
    }

    ctx->path.len = 0;

    data.ents = ngx_http_api_error_entries;

    rc = ngx_api_object_handler(data, ctx, ctx);
    if (rc != NGX_OK) {
        return status;
    }

    ngx_str_set(&r->headers_out.content_type, "application/json");

    r->headers_out.content_type_len = r->headers_out.content_type.len;
    r->headers_out.content_type_lowcase = NULL;

    out.buf = ngx_json_render(r->pool, ctx->out, ctx->pretty);
    if (out.buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->expect_tested = 1;

    if (ngx_http_discard_request_body(r) != NGX_OK) {
        r->keepalive = 0;
    }

    r->headers_out.status = status;
    r->headers_out.content_length_n = out.buf->last - out.buf->pos;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    out.buf->last_buf = (r == r->main) ? 1 : 0;
    out.buf->last_in_chain = 1;

    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


static char *
ngx_http_set_api(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    if (clcf->named) {
        return "cannot be used inside the named location";
    }

#if (NGX_PCRE)
    if (clcf->regex) {
        return "cannot be used inside location given by regular expression";
    }
#endif

    clcf->handler = ngx_http_api_handler;

    if (clcf->name.len && clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    return NGX_CONF_OK;
}
