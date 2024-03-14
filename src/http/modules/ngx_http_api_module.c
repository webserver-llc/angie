
/*
 * Copyright (C) 2022-2024 Web Server LLC
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_http_complex_value_t  *prefix;
    ngx_flag_t                 config_files;
} ngx_http_api_conf_t;


static ngx_int_t ngx_http_api_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_api_args(ngx_http_request_t *r, ngx_api_ctx_t *ctx);
static ngx_int_t ngx_http_api_response(ngx_http_request_t *r,
    ngx_api_ctx_t *ctx);
static ngx_int_t ngx_http_api_error(ngx_http_request_t *r, ngx_api_ctx_t *ctx,
    ngx_uint_t status);
static ngx_int_t ngx_http_api_output(ngx_http_request_t *r, ngx_api_ctx_t *ctx,
    ngx_uint_t status);

static void *ngx_http_api_create_conf(ngx_conf_t *cf);
static char *ngx_http_api_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_set_api(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_http_api_commands[] = {

    { ngx_string("api"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_api,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("api_config_files"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_api_conf_t, config_files),
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

    ngx_http_api_create_conf,              /* create location configuration */
    ngx_http_api_merge_conf                /* merge location configuration */
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
    u_char                    *p;
    size_t                     skip;
    ngx_str_t                  prefix;
    ngx_int_t                  rc;
    ngx_api_ctx_t              ctx;
    ngx_http_api_conf_t       *acf;
    ngx_http_core_loc_conf_t  *clcf;

    acf = ngx_http_get_module_loc_conf(r, ngx_http_api_module);

    if (ngx_http_complex_value(r, acf->prefix, &prefix) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memzero(&ctx, sizeof(ngx_api_ctx_t));

    ctx.connection = r->connection;
    ctx.pool = r->pool;
    ctx.config_files = acf->config_files;

    if (ngx_http_api_args(r, &ctx) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

#if (NGX_PCRE)
    if (clcf->regex) {
        ctx.path = prefix;
    } else
#endif
    {
        if (r->valid_location
            || (r->uri.len >= clcf->name.len
                && ngx_memcmp(r->uri.data, clcf->name.data,
                                           clcf->name.len) == 0))
        {
            skip = clcf->name.len;

        } else {
            /*
             * The request URI has been rewritten inside location to something
             * completely new, so we use the entire URI.
             */
            skip = 0;
        }

        /*
         * We need to concatenate two paths parts: prefix and a part of URI.
         * But there is no guarantee that prefix has ending slash or the
         * URI part has leading slash, because prefix is interpolated from
         * variables and URI can be rewritten to anything.  Thus we have to
         * insert a slash in between explicitly: "prefix" + '/' + "URI".
         *
         * At the same time we'd like to avoid slash duplication, so before
         * concatenation, possible additional slashes are removed from the URI
         * part and prefix.
         */

        if (r->uri.len > skip && r->uri.data[skip] == '/') {
            skip++;
        }

        if (r->uri.len == skip) {
            /* The URI part is empty; use prefix as API path. */
            ctx.path = prefix;

        } else {
            if (prefix.len && prefix.data[prefix.len - 1] == '/') {
                prefix.len--;
            }

            if (prefix.len == 0) {
                /* Prefix is empty; use the URI part as API path. */
                ctx.path.len = r->uri.len - skip;
                ctx.path.data = r->uri.data + skip;

            } else {
                ctx.path.len = prefix.len + 1 + r->uri.len - skip;

                p = ngx_pnalloc(r->pool, ctx.path.len);
                if (p == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                ctx.path.data = p;

                p = ngx_cpymem(p, prefix.data, prefix.len);
                *p++ = '/';
                ngx_memcpy(p, r->uri.data + skip, r->uri.len - skip);
            }
        }
    }

    /*
     * This is needed for consistent display of API paths in error messages.
     * Leading slash is removed if presented, but always added on rendering.
     */
    if (ctx.path.len && ctx.path.data[0] == '/') {
        ctx.path.len--;
        ctx.path.data++;
    }

    ctx.orig_path = ctx.path;

    /*
     * Remove of ending slashes allows consistent detection if more path
     * segments are left by just checking "ctx.path.len".
     */
    while (ctx.path.len && ctx.path.data[ctx.path.len - 1] == '/') {
        ctx.path.len--;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http api request path: \"%V\", method: %ui",
                   &ctx.path, r->method);

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

    if (ngx_http_arg(r, (u_char *) "date", 4, &value) == NGX_OK
        && value.len == 5 && ngx_memcmp(value.data, "epoch", 5) == 0)
    {
        ctx->epoch = 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_api_response(ngx_http_request_t *r, ngx_api_ctx_t *ctx)
{
    ngx_int_t         rc;
    ngx_api_entry_t  *entry;
    ngx_table_elt_t  *expires, *cc;

    entry = ngx_api_root((ngx_cycle_t *) ngx_cycle);

    rc = entry->handler(entry->data, ctx, NULL);

    if (rc == NGX_OK && ctx->path.len) {
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

    return ngx_http_api_output(r, ctx, NGX_HTTP_OK);
}


static ngx_int_t
ngx_http_api_error(ngx_http_request_t *r, ngx_api_ctx_t *ctx, ngx_uint_t status)
{
    size_t                len;
    ngx_int_t             rc;
    ngx_api_entry_data_t  data;
    u_char                errstr[NGX_MAX_ERROR_STR];

    if (ctx->err.len == 0) {
        switch (status) {

        case NGX_HTTP_NOT_FOUND:
            ngx_str_set(&ctx->err, "PathNotFound");

            len = ngx_snprintf(errstr, NGX_MAX_ERROR_STR,
                               "Requested API entity \"/%V\" doesn't exist.",
                               &ctx->orig_path)
                  - errstr;

            ctx->err_desc.len = len;
            ctx->err_desc.data = errstr;
            break;

        case NGX_HTTP_NOT_ALLOWED:
            ngx_str_set(&ctx->err, "MethodNotAllowed");

            len = ngx_snprintf(errstr, NGX_MAX_ERROR_STR,
                               "The %V method is not allowed for "
                               "the requested API entity \"/%V\".",
                               &r->method_name, &ctx->orig_path)
                  - errstr;

            ctx->err_desc.len = len;
            ctx->err_desc.data = errstr;
            break;

        case NGX_HTTP_BAD_REQUEST:
            ngx_str_set(&ctx->err, "BadRequest");
            ngx_str_set(&ctx->err_desc, "HTTP request is invalid.");
            break;

        case NGX_HTTP_INTERNAL_SERVER_ERROR:
        default:
            ngx_str_set(&ctx->err, "InternalError");
            ngx_str_set(&ctx->err_desc,
                        "Something went wrong during API request processing.  "
                        "Check the error log for additional details.");
        }
    }

    ctx->path.len = 0;

    data.ents = ngx_http_api_error_entries;

    rc = ngx_api_object_handler(data, ctx, ctx);
    if (rc != NGX_OK) {
        return status;
    }

    r->expect_tested = 1;

    if (ngx_http_discard_request_body(r) != NGX_OK) {
        r->keepalive = 0;
    }

    return ngx_http_api_output(r, ctx, status);
}


static ngx_int_t
ngx_http_api_output(ngx_http_request_t *r, ngx_api_ctx_t *ctx,
    ngx_uint_t status)
{
    ngx_int_t    rc;
    ngx_chain_t  out;

    ngx_str_set(&r->headers_out.content_type, "application/json");

    r->headers_out.content_type_len = r->headers_out.content_type.len;
    r->headers_out.content_type_lowcase = NULL;

    out.buf = ngx_json_render(r->pool, ctx->out, ctx->pretty);
    if (out.buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
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


static void *
ngx_http_api_create_conf(ngx_conf_t *cf)
{
    ngx_http_api_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_api_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->prefix = NULL;
     */

    conf->config_files = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_api_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_api_conf_t  *prev = parent;
    ngx_http_api_conf_t  *conf = child;

    ngx_conf_merge_value(conf->config_files, prev->config_files, 0);

    return NGX_CONF_OK;
}


static char *
ngx_http_set_api(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_api_conf_t *acf = conf;

    ngx_str_t                         *value;
    ngx_http_core_loc_conf_t          *clcf;
    ngx_http_compile_complex_value_t   ccv;

    if (acf->prefix != NULL) {
        return "is duplicate";
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    if (clcf->named || clcf->combined != NULL) {
        return "cannot be used inside named or combined locations";
    }

    if (!clcf->exact_match
#if (NGX_PCRE)
        && !clcf->regex
#endif
        && (clcf->name.len == 0 || clcf->name.data[clcf->name.len - 1] != '/'))
    {
        return "cannot be used inside prefix location without slash at the end";
    }

    clcf->handler = ngx_http_api_handler;
    clcf->auto_redirect = 1;

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (ccv.complex_value == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    acf->prefix = ccv.complex_value;

    return NGX_CONF_OK;
}
