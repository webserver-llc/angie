
/*
 * Copyright (C) 2023-2024 Web Server LLC
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct ngx_http_prometheus_render_s  ngx_http_prometheus_render_t;


struct ngx_http_prometheus_render_s {
    ngx_str_t                       name;
    ngx_str_t                       value;
    ngx_http_prometheus_render_t   *next;
};


typedef struct {
    ngx_http_request_t             *request;
    ngx_array_t                    *metrics;
    ngx_http_prometheus_render_t  **renders;
#if (NGX_API)
#define NGX_HTTP_PROMETHEUS_MAX_PATH  2048

    u_char                          path[NGX_HTTP_PROMETHEUS_MAX_PATH];
#endif
} ngx_http_prometheus_render_ctx_t;


typedef struct {
    ngx_http_complex_value_t       *name;
    size_t                          name_len;
    ngx_int_t                       value;
#if (NGX_API)
    ngx_str_t                       path;
#if (NGX_PCRE)
    ngx_http_regex_t               *path_regex;
#endif
#endif
    ngx_str_t                       type;
    ngx_str_t                       help;
} ngx_http_prometheus_metric_t;


typedef struct {
    ngx_str_t                       name;
    ngx_array_t                     metrics;

    u_char                         *file;
    ngx_uint_t                      line;
} ngx_http_prometheus_template_t;


static ngx_int_t ngx_http_prometheus_handler(ngx_http_request_t *r);
static ngx_buf_t *ngx_http_prometheus_render(ngx_http_request_t *r);
static ngx_int_t ngx_http_prometheus_render_metric(ngx_uint_t m,
    ngx_http_prometheus_render_ctx_t *ctx);
#if (NGX_API)
static ngx_int_t ngx_http_prometheus_render_item(ngx_data_item_t *item,
    u_char *p, u_char *end, ngx_http_prometheus_render_ctx_t *ctx);
static ngx_int_t ngx_http_prometheus_render_object(ngx_data_item_t *item,
    u_char *p, u_char *end, ngx_http_prometheus_render_ctx_t *ctx);
static ngx_int_t ngx_http_prometheus_render_list(ngx_data_item_t *item,
    u_char *p, u_char *end, ngx_http_prometheus_render_ctx_t *ctx);
static ngx_int_t ngx_http_prometheus_render_value(ngx_data_item_t *item,
    u_char *p, u_char *end, ngx_http_prometheus_render_ctx_t *ctx);
static ngx_int_t ngx_http_prometheus_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
#endif

static ngx_int_t ngx_http_prometheus_add_variable(ngx_conf_t *cf);

static void *ngx_http_prometheus_create_templates(ngx_conf_t *cf);
static char *ngx_http_prometheus_check_templates(ngx_conf_t *cf, void *conf);
static ngx_http_prometheus_template_t *ngx_http_prometheus_get_template(
    ngx_conf_t *cf, ngx_str_t *name);

static char *ngx_http_prometheus_template(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_prometheus_metric(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_prometheus(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_prometheus_commands[] = {

    { ngx_string("prometheus_template"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_http_prometheus_template,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("prometheus"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_prometheus,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_prometheus_module_ctx = {
    ngx_http_prometheus_add_variable,      /* preconfiguration */
    NULL,                                  /* postconfiguration */

    ngx_http_prometheus_create_templates,  /* create main configuration */
    ngx_http_prometheus_check_templates,   /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_prometheus_module = {
    NGX_MODULE_V1,
    &ngx_http_prometheus_module_ctx,       /* module context */
    ngx_http_prometheus_commands,          /* module directives */
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
ngx_http_prometheus_handler(ngx_http_request_t *r)
{
    ngx_int_t         rc;
    ngx_chain_t       out;
    ngx_table_elt_t  *expires, *cc;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

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

    ngx_str_set(&r->headers_out.content_type, "text/plain");

    r->headers_out.content_type_len = r->headers_out.content_type.len;
    r->headers_out.content_type_lowcase = NULL;

    out.buf = ngx_http_prometheus_render(r);
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


static ngx_buf_t *
ngx_http_prometheus_render(ngx_http_request_t *r)
{
    size_t                              size;
    u_char                             *p;
    ngx_buf_t                          *buf;
    ngx_uint_t                          i;
#if (NGX_API)
    ngx_api_ctx_t                       actx;
    ngx_api_entry_t                    *entry;
#endif
    ngx_http_prometheus_metric_t       *metric;
    ngx_http_prometheus_render_t      **renders, *render, *next;
    ngx_http_prometheus_template_t     *tmpl;
    ngx_http_prometheus_render_ctx_t    ctx;

    static const char  comm[] = "# Angie Prometheus template \"%V\"\n";
    static ngx_str_t   help = ngx_string("# HELP ");
    static ngx_str_t   type = ngx_string("# TYPE ");

    tmpl = ngx_http_get_module_loc_conf(r, ngx_http_prometheus_module);

    ctx.request = r;
    ctx.metrics = &tmpl->metrics;

    renders = ngx_pcalloc(r->pool, ctx.metrics->nelts
                                   * sizeof(ngx_http_prometheus_render_t *));
    if (renders == NULL) {
        return NULL;
    }

    ctx.renders = renders;

#if (NGX_API)
    ngx_memzero(&actx, sizeof(ngx_api_ctx_t));

    actx.connection = r->connection;
    actx.pool = r->pool;

    ngx_str_set(&actx.path, "/status");

    actx.epoch = 1;

    entry = ngx_api_root((ngx_cycle_t *) ngx_cycle);

    if (entry->handler(entry->data, &actx, NULL) != NGX_OK) {
        return NULL;
    }

    if (ngx_http_prometheus_render_item(actx.out, ctx.path,
                                        ctx.path + sizeof(ctx.path), &ctx)
        != NGX_OK)
    {
        return NULL;
    }
#endif

    size = sizeof(comm) - 1 + tmpl->name.len - 2;  /* %V */
    metric = ctx.metrics->elts;

    for (i = 0; i < ctx.metrics->nelts; i++) {

#if (NGX_API)
        if (metric[i].path.len == 0
#if (NGX_PCRE)
            && metric[i].path_regex == NULL
#endif
           )
#endif
        {
            if (ngx_http_prometheus_render_metric(i, &ctx) != NGX_OK) {
                return NULL;
            }
        }

        render = renders[i];

        if (render == NULL) {
            continue;
        }

        if (metric[i].help.len != 0) {
            size += help.len + metric[i].name_len + 1 + metric[i].help.len + 1;
        }

        if (metric[i].type.len != 0) {
            size += help.len + metric[i].name_len + 1 + metric[i].type.len + 1;
        }

        renders[i] = NULL;

        do {
            size += render->name.len + 1 + render->value.len + 1;

            /* reverse order back to original */
            next = render->next;
            render->next = renders[i];
            renders[i] = render;
            render = next;
        } while (render);
    }

    buf = ngx_create_temp_buf(r->pool, size);
    if (buf == NULL) {
        return NULL;
    }

    p = ngx_sprintf(buf->last, comm, &tmpl->name);

    for (i = 0; i < ctx.metrics->nelts; i++) {
        render = renders[i];

        if (render == NULL) {
            continue;
        }

        if (metric[i].help.len != 0) {
            p = ngx_cpymem(p, help.data, help.len);
            p = ngx_cpymem(p, metric[i].name->value.data, metric[i].name_len);
            *p++ = ' ';
            p = ngx_cpymem(p, metric[i].help.data, metric[i].help.len);
            *p++ = '\n';
        }

        if (metric[i].type.len != 0) {
            p = ngx_cpymem(p, type.data, type.len);
            p = ngx_cpymem(p, metric[i].name->value.data, metric[i].name_len);
            *p++ = ' ';
            p = ngx_cpymem(p, metric[i].type.data, metric[i].type.len);
            *p++ = '\n';
        }

        do {
            p = ngx_cpymem(p, render->name.data, render->name.len);
            *p++ = ' ';
            p = ngx_cpymem(p, render->value.data, render->value.len);
            *p++ = '\n';

            render = render->next;
        } while (render);
    }

    buf->last = p;

    return buf;
}


static ngx_int_t
ngx_http_prometheus_render_metric(ngx_uint_t m,
    ngx_http_prometheus_render_ctx_t *ctx)
{
    ngx_http_variable_value_t     *vv;
    ngx_http_prometheus_metric_t  *metric;
    ngx_http_prometheus_render_t  *render;

    metric = ctx->metrics->elts;

    vv = ngx_http_get_flushed_variable(ctx->request, metric[m].value);

    if (vv == NULL || vv->not_found || vv->len == 0) {
        return NGX_OK;
    }

    render = ngx_palloc(ctx->request->pool,
                        sizeof(ngx_http_prometheus_render_t));
    if (render == NULL) {
        return NGX_ERROR;
    }

    if (ngx_http_complex_value(ctx->request, metric[m].name, &render->name)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    render->value.len = vv->len;
    render->value.data = vv->data;

    render->next = ctx->renders[m];
    ctx->renders[m] = render;

    return NGX_OK;
}


#if (NGX_API)

static ngx_int_t
ngx_http_prometheus_render_item(ngx_data_item_t *item, u_char *p, u_char *end,
    ngx_http_prometheus_render_ctx_t *ctx)
{
    switch (item->type) {

    case NGX_DATA_OBJECT_TYPE:
        return ngx_http_prometheus_render_object(item->data.child, p, end, ctx);

    case NGX_DATA_LIST_TYPE:
        return ngx_http_prometheus_render_list(item->data.child, p, end, ctx);

    default:
        return ngx_http_prometheus_render_value(item, p, end, ctx);
    }
}


static ngx_int_t
ngx_http_prometheus_render_object(ngx_data_item_t *item, u_char *p, u_char *end,
    ngx_http_prometheus_render_ctx_t *ctx)
{
    ngx_str_t  str;

    if (item != NULL) {
        if (p == end) {
            return NGX_OK;
        }

        *p++ = '/';

        do {
            if (item->type == NGX_DATA_STR_TYPE) {
                str.len = item->data.str.length;
                str.data = item->data.str.start;

            } else {
                str.len = item->data.string.length;
                str.data = item->data.string.start;
            }

            if ((size_t) (end - p) < str.len) {
                continue;
            }

            ngx_memcpy(p, str.data, str.len);

            if (ngx_http_prometheus_render_item(item->next, p + str.len, end,
                                                ctx)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            item = item->next->next;
        } while (item != NULL);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_prometheus_render_list(ngx_data_item_t *item, u_char *p, u_char *end,
    ngx_http_prometheus_render_ctx_t *ctx)
{
    u_char      *pos;
    ngx_uint_t   i;

    if (item != NULL) {
        if (p == end) {
            return NGX_OK;
        }

        *p++ = '/';
        i = 0;

        do {
            pos = ngx_slprintf(p, end, "%ui", i);

            if (pos == end) {
                break;
            }

            if (ngx_http_prometheus_render_item(item->next, pos, end, ctx)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            i++;
            item = item->next;
        } while (item != NULL);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_prometheus_render_value(ngx_data_item_t *item, u_char *p, u_char *end,
    ngx_http_prometheus_render_ctx_t *ctx)
{
    ngx_str_t                      path;
    ngx_int_t                      rc;
    ngx_uint_t                     i;
    ngx_http_prometheus_metric_t  *metric;

    path.len = p - ctx->path;
    path.data = ctx->path;

    metric = ctx->metrics->elts;

    for (i = 0; i < ctx->metrics->nelts; i++) {
#if (NGX_PCRE)
        if (metric[i].path_regex != NULL) {
            rc = ngx_http_regex_exec(ctx->request, metric[i].path_regex, &path);

            if (rc == NGX_DECLINED) {
                continue;
            }

            if (rc == NGX_OK) {
                goto found;
            }

            return NGX_ERROR;
        }
#endif

        if (metric[i].path.len == path.len
            && ngx_memcmp(metric[i].path.data, path.data, path.len) == 0)
        {
            goto found;
        }
    }

    return NGX_OK;

found:

    ngx_http_set_ctx(ctx->request, item, ngx_http_prometheus_module);

    rc = ngx_http_prometheus_render_metric(i, ctx);

    ngx_http_set_ctx(ctx->request, NULL, ngx_http_prometheus_module);

    return rc;
}


static ngx_int_t
ngx_http_prometheus_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char           *p;
    ngx_data_item_t  *item;

    item = ngx_http_get_module_ctx(r, ngx_http_prometheus_module);

    if (item == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    switch (item->type) {

    case NGX_DATA_INTEGER_TYPE:
        p = ngx_pnalloc(r->pool, NGX_INT64_LEN);
        if (p == NULL) {
            return NGX_ERROR;
        }

        v->data = p;
        p = ngx_sprintf(p, "%L", item->data.integer);
        v->len = p - v->data;
        break;

    case NGX_DATA_BOOLEAN_TYPE:
        v->len = 1;
        v->data = (u_char *) (item->data.boolean ? "1" : "0");
        break;

    case NGX_DATA_STR_TYPE:
        v->len = item->data.str.length;
        v->data = item->data.str.start;
        break;

    case NGX_DATA_STRING_TYPE:
        v->len = item->data.string.length;
        v->data = item->data.string.start;
        break;

    case NGX_DATA_NULL_TYPE:
        v->len = 6;
        v->data = (u_char *) "(null)";
        break;

    default:
        return NGX_ERROR;
    }

    v->valid = 1;
    v->not_found = 0;

    return NGX_OK;
}

#endif /* NGX_API */


static ngx_int_t
ngx_http_prometheus_add_variable(ngx_conf_t *cf)
{
#if (NGX_API)
    ngx_http_variable_t  *var;

    static ngx_str_t  name = ngx_string("p8s_value");

    var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_prometheus_variable;
#endif

    return NGX_OK;
}


static void *
ngx_http_prometheus_create_templates(ngx_conf_t *cf)
{
    ngx_array_t  *tmpls;

    tmpls = ngx_array_create(cf->temp_pool, 4,
                             sizeof(ngx_http_prometheus_template_t *));
    if (tmpls == NULL) {
        return NULL;
    }

    return tmpls;
}


static char *
ngx_http_prometheus_check_templates(ngx_conf_t *cf, void *conf)
{
    ngx_uint_t                        i;
    ngx_http_prometheus_template_t  **tmpl;

    ngx_array_t  *tmpls = conf;

    tmpl = tmpls->elts;

    for (i = 0; i < tmpls->nelts; i++) {
        if (tmpl[i]->metrics.elts != NULL) {
            continue;
        }

        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "unknown Prometheus template \"%V\" in %s:%ui",
                      &tmpl[i]->name, tmpl[i]->file, tmpl[i]->line);

        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_http_prometheus_template_t *
ngx_http_prometheus_get_template(ngx_conf_t *cf, ngx_str_t *name)
{
    ngx_uint_t                        i;
    ngx_array_t                      *tmpls;
    ngx_http_prometheus_template_t  **tmpl;

    tmpls = ngx_http_conf_get_module_main_conf(cf, ngx_http_prometheus_module);

    tmpl = tmpls->elts;

    for (i = 0; i < tmpls->nelts; i++) {
        if (tmpl[i]->name.len == name->len
            && ngx_memcmp(tmpl[i]->name.data, name->data, name->len) == 0)
        {
            return tmpl[i];
        }
    }

    tmpl = ngx_array_push(tmpls);
    if (tmpl == NULL) {
        return NULL;
    }

    *tmpl = ngx_pcalloc(cf->pool, sizeof(ngx_http_prometheus_template_t));
    if (*tmpl == NULL) {
        return NULL;
    }

    (*tmpl)->name = *name;

    (*tmpl)->file = cf->conf_file->file.name.data;
    (*tmpl)->line = cf->conf_file->line;

    return *tmpl;
}


static char *
ngx_http_prometheus_template(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                            *rv;
    ngx_str_t                       *value;
    ngx_conf_t                       save;
    ngx_http_prometheus_template_t  *tmpl;

    value = cf->args->elts;

    tmpl = ngx_http_prometheus_get_template(cf, &value[1]);
    if (tmpl == NULL) {
        return NGX_CONF_ERROR;
    }

    if (tmpl->metrics.elts != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate Prometheus template \"%V\"", &tmpl->name);
        return NGX_CONF_ERROR;
    }

    if (ngx_array_init(&tmpl->metrics, cf->pool, 16,
                       sizeof(ngx_http_prometheus_metric_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    save = *cf;
    cf->handler = ngx_http_prometheus_metric;
    cf->handler_conf = &tmpl->metrics;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    return rv;
}


static char *
ngx_http_prometheus_metric(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_array_t *metrics = conf;

    u_char                            *p;
    ngx_str_t                         *value;
    ngx_uint_t                         i;
    ngx_http_prometheus_metric_t      *metric;
    ngx_http_compile_complex_value_t   ccv;

    if (cf->args->nelts < 2) {
        return "invalid number of metric parameters";
    }

    metric = ngx_array_push(metrics);
    if (metric == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(metric, sizeof(ngx_http_prometheus_metric_t));

    value = cf->args->elts;

    p = (u_char *) ngx_strchr(value[0].data, '{');

    metric->name_len = (p == NULL) ? value[0].len
                                   : (size_t) (p - value[0].data);

    for (i = 0; i < metric->name_len; i++) {
        if (value[0].data[i] == '$') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid metric name: "
                               "\"%*s\" - only labels can contain variables",
                               metric->name_len, value[0].data);
            return NGX_CONF_ERROR;
        }
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[0];
    ccv.complex_value = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (ccv.complex_value == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    metric->name = ccv.complex_value;

    if (value[1].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "metric value \"%V\" isn't a variable", &value[1]);
        return NGX_CONF_ERROR;
    }

    value[1].len--;
    value[1].data++;

    metric->value = ngx_http_get_variable_index(cf, &value[1]);

    if (metric->value == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "path=", 5) == 0) {
#if (NGX_API)
            value[i].len -= 5;
            value[i].data += 5;

            if (value[i].len == 0) {
                return "empty metric matching path";
            }

            if (value[i].data[0] != '~') {
                ngx_strlow(value[i].data, value[i].data, value[i].len);
                metric->path = value[i];

            } else {
#if (NGX_PCRE)
                u_char               *p;
                ngx_regex_compile_t   rc;
                u_char                errstr[NGX_MAX_CONF_ERRSTR];

                value[i].len--;
                value[i].data++;

                if (value[i].len == 0) {
                    return "empty regex in metric matching path";
                }

                ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

                rc.pattern = value[i];
                rc.err.len = NGX_MAX_CONF_ERRSTR;
                rc.err.data = errstr;

                for (p = value[i].data; p < value[i].data + value[i].len; p++) {
                    if (*p >= 'A' && *p <= 'Z') {
                        rc.options = NGX_REGEX_CASELESS;
                        break;
                    }
                }

                metric->path_regex = ngx_http_regex_compile(cf, &rc);
                if (metric->path_regex == NULL) {
                    return NGX_CONF_ERROR;
                }

#else  /* no NGX_PCRE */
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "using regex \"%V\" "
                                   "requires PCRE library", &value[i]);

                return NGX_CONF_ERROR;
#endif
            }

            continue;

#else /* no NGX_API */
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "using \"%V\" requires API module", &value[i]);

            return NGX_CONF_ERROR;
#endif
        }

        if (ngx_strncmp(value[i].data, "type=", 5) == 0) {
            value[i].len -= 5;
            value[i].data += 5;

            if (value[i].len == 0) {
                return "empty metric type";
            }

            metric->type = value[i];

            continue;
        }

        if (ngx_strncmp(value[i].data, "help=", 5) == 0) {
            value[i].len -= 5;
            value[i].data += 5;

            if (value[i].len == 0) {
                return "empty metric help";
            }

            metric->help = value[i];

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid metric parameter \"%V\"", &value[i]);

        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_prometheus(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                       *value;
    ngx_http_conf_ctx_t             *ctx;
    ngx_http_core_loc_conf_t        *clcf;
    ngx_http_prometheus_template_t  *tmpl;

    value = cf->args->elts;

    tmpl = ngx_http_prometheus_get_template(cf, &value[1]);
    if (tmpl == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx = cf->ctx;
    ctx->loc_conf[ngx_http_prometheus_module.ctx_index] = tmpl;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_prometheus_handler;

    return NGX_CONF_OK;
}
