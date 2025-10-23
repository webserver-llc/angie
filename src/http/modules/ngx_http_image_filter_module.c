
/*
 * Copyright (C) 2025 Web Server LLC
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <gd.h>


#define NGX_HTTP_IMAGE_OFF       0
#define NGX_HTTP_IMAGE_TEST      1
#define NGX_HTTP_IMAGE_SIZE      2
#define NGX_HTTP_IMAGE_RESIZE    3
#define NGX_HTTP_IMAGE_CROP      4
#define NGX_HTTP_IMAGE_ROTATE    5
#define NGX_HTTP_IMAGE_CONVERT   6


#define NGX_HTTP_IMAGE_START     0
#define NGX_HTTP_IMAGE_READ      1
#define NGX_HTTP_IMAGE_PROCESS   2
#define NGX_HTTP_IMAGE_PASS      3
#define NGX_HTTP_IMAGE_DONE      4


#define NGX_HTTP_IMAGE_NONE      0
#define NGX_HTTP_IMAGE_JPEG      1
#define NGX_HTTP_IMAGE_GIF       2
#define NGX_HTTP_IMAGE_PNG       3
#define NGX_HTTP_IMAGE_WEBP      4
#define NGX_HTTP_IMAGE_HEIC      5
#define NGX_HTTP_IMAGE_AVIF      6


#define NGX_HTTP_IMAGE_BUFFERED  0x08


#define ngx_image_filter_parse_uint32(p)                                      \
    ((uint32_t) (p)[0] << 24 | (p)[1] << 16 | (p)[2] << 8 | (p)[3])

#define ngx_image_filter_parse_uint64(p)                                      \
    ( (uint64_t) (p)[0] << 56 | (uint64_t) (p)[1] << 48                       \
    | (uint64_t) (p)[2] << 40 | (uint64_t) (p)[3] << 32                       \
    | (uint64_t) (p)[4] << 24 | (p)[5] << 16 | (p)[6] << 8 | (p)[7])


typedef struct {
    ngx_uint_t                      value;
    ngx_http_complex_value_t       *complex_value;
} ngx_http_image_filter_value_t;


typedef struct {
    ngx_uint_t                      filter;
    ngx_uint_t                      width;
    ngx_uint_t                      height;
    ngx_uint_t                      angle;

    ngx_flag_t                      transparency;
    ngx_flag_t                      interlace;

    ngx_http_complex_value_t       *wcv;
    ngx_http_complex_value_t       *hcv;
    ngx_http_complex_value_t       *acv;

    ngx_http_image_filter_value_t   jpeg_quality;
    ngx_http_image_filter_value_t   webp_quality;
    ngx_http_image_filter_value_t   heic_quality;
    ngx_http_image_filter_value_t   avif_quality;
    ngx_http_image_filter_value_t   avif_speed;
    ngx_http_image_filter_value_t   sharpen;
    ngx_http_image_filter_value_t   output_type;

    size_t                          buffer_size;
} ngx_http_image_filter_conf_t;


typedef struct {
    u_char                         *image;
    u_char                         *last;

    size_t                          length;

    ngx_uint_t                      width;
    ngx_uint_t                      height;
    ngx_uint_t                      max_width;
    ngx_uint_t                      max_height;
    ngx_uint_t                      angle;

    ngx_uint_t                      phase;
    ngx_uint_t                      type;
    ngx_uint_t                      force;
    ngx_uint_t                      output_type;
} ngx_http_image_filter_ctx_t;


static ngx_int_t ngx_http_image_send(ngx_http_request_t *r,
    ngx_http_image_filter_ctx_t *ctx, ngx_chain_t *in);
static ngx_uint_t ngx_http_image_test(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_image_read(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_buf_t *ngx_http_image_process(ngx_http_request_t *r);
static ngx_buf_t *ngx_http_image_json(ngx_http_request_t *r,
    ngx_http_image_filter_ctx_t *ctx);
static ngx_buf_t *ngx_http_image_asis(ngx_http_request_t *r,
    ngx_http_image_filter_ctx_t *ctx);
static void ngx_http_image_length(ngx_http_request_t *r, ngx_buf_t *b);
static ngx_int_t ngx_http_image_size(ngx_http_request_t *r,
    ngx_http_image_filter_ctx_t *ctx);

static ngx_buf_t *ngx_http_image_resize(ngx_http_request_t *r,
    ngx_http_image_filter_ctx_t *ctx);
static gdImagePtr ngx_http_image_source(ngx_http_request_t *r,
    ngx_http_image_filter_ctx_t *ctx);
static gdImagePtr ngx_http_image_new(ngx_http_request_t *r, int w, int h,
    int colors);
static u_char *ngx_http_image_out(ngx_http_request_t *r, ngx_uint_t type,
    gdImagePtr img, int *size);
static void ngx_http_image_cleanup(void *data);
static ngx_uint_t ngx_http_image_filter_get_value(ngx_http_request_t *r,
    ngx_http_complex_value_t *cv, ngx_uint_t v);
static ngx_uint_t ngx_http_image_filter_value(ngx_str_t *value);


static void *ngx_http_image_filter_create_conf(ngx_conf_t *cf);
static char *ngx_http_image_filter_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static void ngx_http_image_filter_merge_value(
    ngx_http_image_filter_value_t *conf, ngx_http_image_filter_value_t *prev,
    ngx_uint_t default_value);
static char *ngx_http_image_filter(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_uint_t ngx_http_image_filter_output_type(ngx_str_t *value);
static char* ngx_http_image_filter_conf_value(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char* ngx_http_image_filter_avif_quality(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_image_filter_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_image_filter_commands[] = {

    { ngx_string("image_filter"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
      ngx_http_image_filter,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("image_filter_jpeg_quality"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_image_filter_conf_value,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_image_filter_conf_t, jpeg_quality),
      NULL },

    { ngx_string("image_filter_webp_quality"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_image_filter_conf_value,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_image_filter_conf_t, webp_quality),
      NULL },

    { ngx_string("image_filter_heic_quality"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_image_filter_conf_value,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_image_filter_conf_t, heic_quality),
      NULL },

    { ngx_string("image_filter_avif_quality"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_image_filter_avif_quality,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("image_filter_sharpen"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_image_filter_conf_value,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_image_filter_conf_t, sharpen),
      NULL },

    { ngx_string("image_filter_transparency"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_image_filter_conf_t, transparency),
      NULL },

    { ngx_string("image_filter_interlace"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_image_filter_conf_t, interlace),
      NULL },

    { ngx_string("image_filter_buffer"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_image_filter_conf_t, buffer_size),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_image_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_image_filter_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_image_filter_create_conf,     /* create location configuration */
    ngx_http_image_filter_merge_conf       /* merge location configuration */
};


ngx_module_t  ngx_http_image_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_image_filter_module_ctx,     /* module context */
    ngx_http_image_filter_commands,        /* module directives */
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
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_str_t  ngx_http_image_types[] = {
    ngx_string("image/jpeg"),
    ngx_string("image/gif"),
    ngx_string("image/png"),
    ngx_string("image/webp"),
    ngx_string("image/heic"),
    ngx_string("image/avif")
};


static ngx_int_t
ngx_http_image_header_filter(ngx_http_request_t *r)
{
    off_t                          len;
    ngx_http_image_filter_ctx_t   *ctx;
    ngx_http_image_filter_conf_t  *conf;

    if (r->headers_out.status == NGX_HTTP_NOT_MODIFIED) {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_image_filter_module);

    if (ctx) {
        ngx_http_set_ctx(r, NULL, ngx_http_image_filter_module);
        return ngx_http_next_header_filter(r);
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_image_filter_module);

    if (conf->filter == NGX_HTTP_IMAGE_OFF) {
        return ngx_http_next_header_filter(r);
    }

    if (r->headers_out.content_type.len
            >= sizeof("multipart/x-mixed-replace") - 1
        && ngx_strncasecmp(r->headers_out.content_type.data,
                           (u_char *) "multipart/x-mixed-replace",
                           sizeof("multipart/x-mixed-replace") - 1)
           == 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "image filter: multipart/x-mixed-replace response");

        return NGX_ERROR;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_image_filter_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_image_filter_module);

    len = r->headers_out.content_length_n;

    if (len != -1 && len > (off_t) conf->buffer_size) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "image filter: too big response: %O", len);

        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    if (len == -1) {
        ctx->length = conf->buffer_size;

    } else {
        ctx->length = (size_t) len;
    }

    if (r->headers_out.refresh) {
        r->headers_out.refresh->hash = 0;
    }

    r->main_filter_need_in_memory = 1;
    r->allow_ranges = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_image_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                      rc;
    ngx_str_t                     *ct, value;
    ngx_chain_t                    out;
    ngx_http_image_filter_ctx_t   *ctx;
    ngx_http_image_filter_conf_t  *conf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "image filter");

    if (in == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_image_filter_module);

    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    switch (ctx->phase) {

    case NGX_HTTP_IMAGE_START:

        ctx->type = ngx_http_image_test(r, in);

        conf = ngx_http_get_module_loc_conf(r, ngx_http_image_filter_module);

        if (ctx->type == NGX_HTTP_IMAGE_NONE) {

            if (conf->filter == NGX_HTTP_IMAGE_SIZE) {
                out.buf = ngx_http_image_json(r, NULL);

                if (out.buf) {
                    out.next = NULL;
                    ctx->phase = NGX_HTTP_IMAGE_DONE;

                    return ngx_http_image_send(r, ctx, &out);
                }
            }

            return ngx_http_filter_finalize_request(r,
                                              &ngx_http_image_filter_module,
                                              NGX_HTTP_UNSUPPORTED_MEDIA_TYPE);
        }

        /* override content type */

        if (conf->output_type.complex_value == NULL) {
            ctx->output_type = conf->output_type.value;

        } else {

            if (ngx_http_complex_value(r, conf->output_type.complex_value,
                                       &value)
                != NGX_OK)
            {
                return ngx_http_filter_finalize_request(r,
                                               &ngx_http_image_filter_module,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            }

            ctx->output_type = ngx_http_image_filter_output_type(&value);
        }

        if (ctx->output_type == NGX_HTTP_IMAGE_NONE) {
            ctx->output_type = ctx->type;
        }

        ct = &ngx_http_image_types[ctx->output_type - 1];
        r->headers_out.content_type_len = ct->len;
        r->headers_out.content_type = *ct;
        r->headers_out.content_type_lowcase = NULL;

        if (conf->filter == NGX_HTTP_IMAGE_TEST) {
            ctx->phase = NGX_HTTP_IMAGE_PASS;

            return ngx_http_image_send(r, ctx, in);
        }

        ctx->phase = NGX_HTTP_IMAGE_READ;

        /* fall through */

    case NGX_HTTP_IMAGE_READ:

        rc = ngx_http_image_read(r, in);

        if (rc == NGX_AGAIN) {
            return NGX_OK;
        }

        if (rc == NGX_ERROR) {
            return ngx_http_filter_finalize_request(r,
                                              &ngx_http_image_filter_module,
                                              NGX_HTTP_UNSUPPORTED_MEDIA_TYPE);
        }

        /* fall through */

    case NGX_HTTP_IMAGE_PROCESS:

        out.buf = ngx_http_image_process(r);

        if (out.buf == NULL) {
            return ngx_http_filter_finalize_request(r,
                                              &ngx_http_image_filter_module,
                                              NGX_HTTP_UNSUPPORTED_MEDIA_TYPE);
        }

        out.next = NULL;
        ctx->phase = NGX_HTTP_IMAGE_PASS;

        return ngx_http_image_send(r, ctx, &out);

    case NGX_HTTP_IMAGE_PASS:

        return ngx_http_next_body_filter(r, in);

    default: /* NGX_HTTP_IMAGE_DONE */

        rc = ngx_http_next_body_filter(r, NULL);

        /* NGX_ERROR resets any pending data */
        return (rc == NGX_OK) ? NGX_ERROR : rc;
    }
}


static ngx_int_t
ngx_http_image_send(ngx_http_request_t *r, ngx_http_image_filter_ctx_t *ctx,
    ngx_chain_t *in)
{
    ngx_int_t  rc;

    rc = ngx_http_next_header_filter(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return NGX_ERROR;
    }

    rc = ngx_http_next_body_filter(r, in);

    if (ctx->phase == NGX_HTTP_IMAGE_DONE) {
        /* NGX_ERROR resets any pending data */
        return (rc == NGX_OK) ? NGX_ERROR : rc;
    }

    return rc;
}


static ngx_uint_t
ngx_http_image_test(ngx_http_request_t *r, ngx_chain_t *in)
{
    u_char  *p, *end;
    size_t   len;

    p = in->buf->pos;

    if (in->buf->last - p < 16) {
        return NGX_HTTP_IMAGE_NONE;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "image filter: \"%c%c\"", p[0], p[1]);

    if (p[0] == 0xff && p[1] == 0xd8) {

        /* JPEG */

        return NGX_HTTP_IMAGE_JPEG;

    } else if (p[0] == 'G' && p[1] == 'I' && p[2] == 'F' && p[3] == '8'
               && p[5] == 'a')
    {
        if (p[4] == '9' || p[4] == '7') {
            /* GIF */
            return NGX_HTTP_IMAGE_GIF;
        }

    } else if (p[0] == 0x89 && p[1] == 'P' && p[2] == 'N' && p[3] == 'G'
               && p[4] == 0x0d && p[5] == 0x0a && p[6] == 0x1a && p[7] == 0x0a)
    {
        /* PNG */

        return NGX_HTTP_IMAGE_PNG;

    } else if (p[0] == 'R' && p[1] == 'I' && p[2] == 'F' && p[3] == 'F'
               && p[8] == 'W' && p[9] == 'E' && p[10] == 'B' && p[11] == 'P')
    {
        /* WebP */

        return NGX_HTTP_IMAGE_WEBP;

    } else if (p[4] == 'f' && p[5] == 't' && p[6] == 'y' && p[7] == 'p') {

        /* HEIF container for HEIC and AVIF */

        if (p[8] == 'a' && p[9] == 'v' && p[10] == 'i' && p[11] == 'f') {

            /* main brand AVIF */
            return NGX_HTTP_IMAGE_AVIF;
        }

        if (p[8] == 'h' && p[9] == 'e' && p[10] == 'i'
            && (p[11] == 'c' || p[11] == 'x'))
        {
            /* main brand HEIC */
            return NGX_HTTP_IMAGE_HEIC;
        }

        len = ngx_image_filter_parse_uint32(p);

        if ((size_t) (in->buf->last - p) < len || len < 16) {
            return NGX_HTTP_IMAGE_NONE;
        }

        end = p + len;

        p += 16;

        /* iterate over compatible brands */

        while (end - p >= 4) {

            if (p[0] == 'a' && p[1] == 'v' && p[2] == 'i' && p[3] == 'f') {
                return NGX_HTTP_IMAGE_AVIF;
            }

            if (p[0] == 'h' && p[1] == 'e' && p[2] == 'i' && (p[3] == 'c'
                                                              || p[3] == 'x'))
            {
                return NGX_HTTP_IMAGE_HEIC;
            }

            p += 4;
        }
    }

    return NGX_HTTP_IMAGE_NONE;
}


static ngx_int_t
ngx_http_image_read(ngx_http_request_t *r, ngx_chain_t *in)
{
    u_char                       *p;
    size_t                        size, rest;
    ngx_buf_t                    *b;
    ngx_chain_t                  *cl;
    ngx_http_image_filter_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_image_filter_module);

    if (ctx->image == NULL) {
        ctx->image = ngx_palloc(r->pool, ctx->length);
        if (ctx->image == NULL) {
            return NGX_ERROR;
        }

        ctx->last = ctx->image;
    }

    p = ctx->last;

    for (cl = in; cl; cl = cl->next) {

        b = cl->buf;
        size = b->last - b->pos;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "image buf: %uz", size);

        rest = ctx->image + ctx->length - p;

        if (size > rest) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "image filter: too big response");
            return NGX_ERROR;
        }

        p = ngx_cpymem(p, b->pos, size);
        b->pos += size;

        if (b->last_buf) {
            ctx->last = p;
            return NGX_OK;
        }
    }

    ctx->last = p;
    r->connection->buffered |= NGX_HTTP_IMAGE_BUFFERED;

    return NGX_AGAIN;
}


static ngx_buf_t *
ngx_http_image_process(ngx_http_request_t *r)
{
    ngx_int_t                      rc;
    ngx_http_image_filter_ctx_t   *ctx;
    ngx_http_image_filter_conf_t  *conf;

    r->connection->buffered &= ~NGX_HTTP_IMAGE_BUFFERED;

    ctx = ngx_http_get_module_ctx(r, ngx_http_image_filter_module);

    rc = ngx_http_image_size(r, ctx);

    conf = ngx_http_get_module_loc_conf(r, ngx_http_image_filter_module);

    if (conf->filter == NGX_HTTP_IMAGE_SIZE) {
        return ngx_http_image_json(r, rc == NGX_OK ? ctx : NULL);
    }

    ctx->angle = ngx_http_image_filter_get_value(r, conf->acv, conf->angle);

    if (conf->filter == NGX_HTTP_IMAGE_ROTATE) {

        if (ctx->angle != 90 && ctx->angle != 180 && ctx->angle != 270) {
            return NULL;
        }

        return ngx_http_image_resize(r, ctx);
    }

    if (conf->filter == NGX_HTTP_IMAGE_CONVERT) {

        if (ctx->output_type == ctx->type) {
            return ngx_http_image_asis(r, ctx);
        }

        return ngx_http_image_resize(r, ctx);
    }

    ctx->max_width = ngx_http_image_filter_get_value(r, conf->wcv, conf->width);
    if (ctx->max_width == 0) {
        return NULL;
    }

    ctx->max_height = ngx_http_image_filter_get_value(r, conf->hcv,
                                                      conf->height);
    if (ctx->max_height == 0) {
        return NULL;
    }

    if (rc == NGX_OK
        && ctx->width <= ctx->max_width
        && ctx->height <= ctx->max_height
        && ctx->angle == 0
        && !ctx->force
        && ctx->output_type == ctx->type)
    {
        return ngx_http_image_asis(r, ctx);
    }

    return ngx_http_image_resize(r, ctx);
}


static ngx_buf_t *
ngx_http_image_json(ngx_http_request_t *r, ngx_http_image_filter_ctx_t *ctx)
{
    size_t      len;
    ngx_buf_t  *b;

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NULL;
    }

    b->memory = 1;
    b->last_buf = 1;

    ngx_http_clean_header(r);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_type_len = sizeof("application/json") - 1;
    ngx_str_set(&r->headers_out.content_type, "application/json");
    r->headers_out.content_type_lowcase = NULL;

    if (ctx == NULL) {
        b->pos = (u_char *) "{}" CRLF;
        b->last = b->pos + sizeof("{}" CRLF) - 1;

        ngx_http_image_length(r, b);

        return b;
    }

    len = sizeof("{ \"img\" : "
                 "{ \"width\": , \"height\": , \"type\": \"jpeg\" } }" CRLF) - 1
          + 2 * NGX_SIZE_T_LEN;

    b->pos = ngx_pnalloc(r->pool, len);
    if (b->pos == NULL) {
        return NULL;
    }

    b->last = ngx_sprintf(b->pos,
                          "{ \"img\" : "
                                       "{ \"width\": %uz,"
                                        " \"height\": %uz,"
                                        " \"type\": \"%s\" } }" CRLF,
                          ctx->width, ctx->height,
                          ngx_http_image_types[ctx->type - 1].data + 6);

    ngx_http_image_length(r, b);

    return b;
}


static ngx_buf_t *
ngx_http_image_asis(ngx_http_request_t *r, ngx_http_image_filter_ctx_t *ctx)
{
    ngx_buf_t  *b;

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NULL;
    }

    b->pos = ctx->image;
    b->last = ctx->last;
    b->memory = 1;
    b->last_buf = 1;

    ngx_http_image_length(r, b);

    return b;
}


static void
ngx_http_image_length(ngx_http_request_t *r, ngx_buf_t *b)
{
    r->headers_out.content_length_n = b->last - b->pos;

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
    }

    r->headers_out.content_length = NULL;
}


static ngx_int_t
ngx_http_image_size(ngx_http_request_t *r, ngx_http_image_filter_ctx_t *ctx)
{
    u_char      *p, *last;
    size_t       len, app;
    uint64_t     heif_box_len;
    ngx_uint_t   width, height;

    p = ctx->image;

    switch (ctx->type) {

    case NGX_HTTP_IMAGE_JPEG:

        p += 2;
        last = ctx->image + ctx->length - 10;
        width = 0;
        height = 0;
        app = 0;

        while (p < last) {

            if (p[0] == 0xff && p[1] != 0xff) {

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "JPEG: %02xd %02xd", p[0], p[1]);

                p++;

                if ((*p == 0xc0 || *p == 0xc1 || *p == 0xc2 || *p == 0xc3
                     || *p == 0xc9 || *p == 0xca || *p == 0xcb)
                    && (width == 0 || height == 0))
                {
                    width = p[6] * 256 + p[7];
                    height = p[4] * 256 + p[5];
                }

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "JPEG: %02xd %02xd", p[1], p[2]);

                len = p[1] * 256 + p[2];

                if (*p >= 0xe1 && *p <= 0xef) {
                    /* application data, e.g., EXIF, Adobe XMP, etc. */
                    app += len;
                }

                p += len;

                continue;
            }

            p++;
        }

        if (width == 0 || height == 0) {
            return NGX_DECLINED;
        }

        if (ctx->length / 20 < app) {
            /* force conversion if application data consume more than 5% */
            ctx->force = 1;
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "app data size: %uz", app);
        }

        break;

    case NGX_HTTP_IMAGE_GIF:

        if (ctx->length < 10) {
            return NGX_DECLINED;
        }

        width = p[7] * 256 + p[6];
        height = p[9] * 256 + p[8];

        break;

    case NGX_HTTP_IMAGE_PNG:

        if (ctx->length < 24) {
            return NGX_DECLINED;
        }

        width = p[18] * 256 + p[19];
        height = p[22] * 256 + p[23];

        break;

    case NGX_HTTP_IMAGE_WEBP:

        if (ctx->length < 30) {
            return NGX_DECLINED;
        }

        if (p[12] != 'V' || p[13] != 'P' || p[14] != '8') {
            return NGX_DECLINED;
        }

        switch (p[15]) {

        case ' ':
            if (p[20] & 1) {
                /* not a key frame */
                return NGX_DECLINED;
            }

            if (p[23] != 0x9d || p[24] != 0x01 || p[25] != 0x2a) {
                /* invalid start code */
                return NGX_DECLINED;
            }

            width = (p[26] | p[27] << 8) & 0x3fff;
            height = (p[28] | p[29] << 8) & 0x3fff;

            break;

        case 'L':
            if (p[20] != 0x2f) {
                /* invalid signature */
                return NGX_DECLINED;
            }

            width = ((p[21] | p[22] << 8) & 0x3fff) + 1;
            height = ((p[22] >> 6 | p[23] << 2 | p[24] << 10) & 0x3fff) + 1;

            break;

        case 'X':
            width = (p[24] | p[25] << 8 | p[26] << 16) + 1;
            height = (p[27] | p[28] << 8 | p[29] << 16) + 1;
            break;

        default:
            return NGX_DECLINED;
        }

        break;

    case NGX_HTTP_IMAGE_HEIC:
    case NGX_HTTP_IMAGE_AVIF:

        heif_box_len = ngx_image_filter_parse_uint32(p);

        if (heif_box_len > ctx->length) {
            return NGX_DECLINED;
        }

        last = p + ctx->length;

        p += heif_box_len;

        /* skip boxes until meta box */
        for ( ;; ) {

            if (last - p < 8) {
                return NGX_DECLINED;
            }

            heif_box_len = ngx_image_filter_parse_uint32(p);

            if (heif_box_len == 1) {

                if (last - p < 16) {
                    return NGX_DECLINED;
                }

                heif_box_len = ngx_image_filter_parse_uint64(&p[8]);
            }

            if (heif_box_len > (uint64_t) (last - p)) {
                return NGX_DECLINED;
            }

            if (p[4] == 'm' && p[5] == 'e' && p[6] == 't' && p[7] == 'a') {
                break;
            }

            p += heif_box_len;
        }

        if (heif_box_len < 12) {
            return NGX_DECLINED;
        }

        last = p + heif_box_len;

        p += 12;

        /* check if ispe subbox fits in meta box */
        for ( ;; ) {

            if (last - p < 20) {
                return NGX_DECLINED;
            }

            if (p[4] == 'i' && p[5] == 's' && p[6] == 'p' && p[7] == 'e') {

                width = ngx_image_filter_parse_uint32(&p[12]);

                height = ngx_image_filter_parse_uint32(&p[16]);

                break;
            }

            heif_box_len = ngx_image_filter_parse_uint32(p);

            /* box with zero length continues until EOF */
            if (heif_box_len == 0) {
                return NGX_DECLINED;
            }

            if (p[4] == 'i' && p[5] == 'p' && ((p[6] == 'r' && p[7] == 'p')
                || (p[6] == 'c' && p[7] == 'o')))
            {
                /* ignore container box header, continue reading box children */
                p += 8;
                continue;
            }

            if (heif_box_len == 1) {
                heif_box_len = ngx_image_filter_parse_uint64(&p[8]);
            }

            if (heif_box_len > (uint64_t) (last - p)) {
                return NGX_DECLINED;
            }

            p += heif_box_len;
        }

        break;

    default:

        return NGX_DECLINED;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "image size: %d x %d", (int) width, (int) height);

    ctx->width = width;
    ctx->height = height;

    return NGX_OK;
}


static ngx_buf_t *
ngx_http_image_resize(ngx_http_request_t *r, ngx_http_image_filter_ctx_t *ctx)
{
    int                            sx, sy, dx, dy, ox, oy, ax, ay, size,
                                   colors, palette, transparent, sharpen,
                                   red, green, blue, t;
    u_char                        *out;
    ngx_buf_t                     *b;
    ngx_uint_t                     resize;
    gdImagePtr                     src, dst;
    ngx_pool_cleanup_t            *cln;
    ngx_http_image_filter_conf_t  *conf;

    src = ngx_http_image_source(r, ctx);

    if (src == NULL) {
        return NULL;
    }

    sx = gdImageSX(src);
    sy = gdImageSY(src);

    conf = ngx_http_get_module_loc_conf(r, ngx_http_image_filter_module);

    if (!ctx->force
        && ctx->angle == 0
        && (ngx_uint_t) sx <= ctx->max_width
        && (ngx_uint_t) sy <= ctx->max_height
        && ctx->output_type == ctx->type)
    {
        gdImageDestroy(src);
        return ngx_http_image_asis(r, ctx);
    }

    colors = gdImageColorsTotal(src);

    if (colors && conf->transparency) {
        transparent = gdImageGetTransparent(src);

        if (transparent != -1) {
            palette = colors;
            red = gdImageRed(src, transparent);
            green = gdImageGreen(src, transparent);
            blue = gdImageBlue(src, transparent);

            goto transparent;
        }
    }

    palette = 0;
    transparent = -1;
    red = 0;
    green = 0;
    blue = 0;

transparent:

    gdImageColorTransparent(src, -1);

    if (conf->filter == NGX_HTTP_IMAGE_CONVERT) {
        dst = src;
        goto output;
    }

    dx = sx;
    dy = sy;

    if (conf->filter == NGX_HTTP_IMAGE_RESIZE) {

        if ((ngx_uint_t) dx > ctx->max_width) {
            dy = dy * ctx->max_width / dx;
            dy = dy ? dy : 1;
            dx = ctx->max_width;
        }

        if ((ngx_uint_t) dy > ctx->max_height) {
            dx = dx * ctx->max_height / dy;
            dx = dx ? dx : 1;
            dy = ctx->max_height;
        }

        resize = 1;

    } else if (conf->filter == NGX_HTTP_IMAGE_ROTATE) {

        resize = 0;

    } else { /* NGX_HTTP_IMAGE_CROP */

        resize = 0;

        if ((double) dx / dy < (double) ctx->max_width / ctx->max_height) {
            if ((ngx_uint_t) dx > ctx->max_width) {
                dy = dy * ctx->max_width / dx;
                dy = dy ? dy : 1;
                dx = ctx->max_width;
                resize = 1;
            }

        } else {
            if ((ngx_uint_t) dy > ctx->max_height) {
                dx = dx * ctx->max_height / dy;
                dx = dx ? dx : 1;
                dy = ctx->max_height;
                resize = 1;
            }
        }
    }

    if (resize) {
        dst = ngx_http_image_new(r, dx, dy, palette);
        if (dst == NULL) {
            gdImageDestroy(src);
            return NULL;
        }

        if (colors == 0) {
            gdImageSaveAlpha(dst, 1);
            gdImageAlphaBlending(dst, 0);
        }

        gdImageCopyResampled(dst, src, 0, 0, 0, 0, dx, dy, sx, sy);

        if (colors) {
            gdImageTrueColorToPalette(dst, 1, 256);
        }

        gdImageDestroy(src);

    } else {
        dst = src;
    }

    if (ctx->angle) {
        src = dst;

        ax = (dx % 2 == 0) ? 1 : 0;
        ay = (dy % 2 == 0) ? 1 : 0;

        switch (ctx->angle) {

        case 90:
        case 270:
            dst = ngx_http_image_new(r, dy, dx, palette);
            if (dst == NULL) {
                gdImageDestroy(src);
                return NULL;
            }
            if (ctx->angle == 90) {
                ox = dy / 2 + ay;
                oy = dx / 2 - ax;

            } else {
                ox = dy / 2 - ay;
                oy = dx / 2 + ax;
            }

            gdImageCopyRotated(dst, src, ox, oy, 0, 0,
                               dx + ax, dy + ay, ctx->angle);
            gdImageDestroy(src);

            t = dx;
            dx = dy;
            dy = t;
            break;

        case 180:
            dst = ngx_http_image_new(r, dx, dy, palette);
            if (dst == NULL) {
                gdImageDestroy(src);
                return NULL;
            }
            gdImageCopyRotated(dst, src, dx / 2 - ax, dy / 2 - ay, 0, 0,
                               dx + ax, dy + ay, ctx->angle);
            gdImageDestroy(src);
            break;
        }
    }

    if (conf->filter == NGX_HTTP_IMAGE_CROP) {

        src = dst;

        if ((ngx_uint_t) dx > ctx->max_width) {
            ox = dx - ctx->max_width;

        } else {
            ox = 0;
        }

        if ((ngx_uint_t) dy > ctx->max_height) {
            oy = dy - ctx->max_height;

        } else {
            oy = 0;
        }

        if (ox || oy) {

            dst = ngx_http_image_new(r, dx - ox, dy - oy, colors);

            if (dst == NULL) {
                gdImageDestroy(src);
                return NULL;
            }

            ox /= 2;
            oy /= 2;

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "image crop: %d x %d @ %d x %d",
                           dx, dy, ox, oy);

            if (colors == 0) {
                gdImageSaveAlpha(dst, 1);
                gdImageAlphaBlending(dst, 0);
            }

            gdImageCopy(dst, src, 0, 0, ox, oy, dx - ox, dy - oy);

            if (colors) {
                gdImageTrueColorToPalette(dst, 1, 256);
            }

            gdImageDestroy(src);
        }
    }

output:

    if (transparent != -1 && colors) {
        gdImageColorTransparent(dst, gdImageColorExact(dst, red, green, blue));
    }

    sharpen = ngx_http_image_filter_get_value(r, conf->sharpen.complex_value,
                                              conf->sharpen.value);
    if (sharpen > 0) {
        gdImageSharpen(dst, sharpen);
    }

    gdImageInterlace(dst, (int) conf->interlace);

    out = ngx_http_image_out(r, ctx->output_type, dst, &size);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "image: %d x %d %d", sx, sy, colors);

    gdImageDestroy(dst);
    ngx_pfree(r->pool, ctx->image);

    if (out == NULL) {
        return NULL;
    }

    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        gdFree(out);
        return NULL;
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        gdFree(out);
        return NULL;
    }

    cln->handler = ngx_http_image_cleanup;
    cln->data = out;

    b->pos = out;
    b->last = out + size;
    b->memory = 1;
    b->last_buf = 1;

    ngx_http_image_length(r, b);
    ngx_http_weak_etag(r);

    return b;
}


static gdImagePtr
ngx_http_image_source(ngx_http_request_t *r, ngx_http_image_filter_ctx_t *ctx)
{
    char        *failed;
    gdImagePtr   img;

    img = NULL;

    switch (ctx->type) {

    case NGX_HTTP_IMAGE_JPEG:
        img = gdImageCreateFromJpegPtr(ctx->length, ctx->image);
        failed = "gdImageCreateFromJpegPtr() failed";
        break;

    case NGX_HTTP_IMAGE_GIF:
        img = gdImageCreateFromGifPtr(ctx->length, ctx->image);
        failed = "gdImageCreateFromGifPtr() failed";
        break;

    case NGX_HTTP_IMAGE_PNG:
        img = gdImageCreateFromPngPtr(ctx->length, ctx->image);
        failed = "gdImageCreateFromPngPtr() failed";
        break;

    case NGX_HTTP_IMAGE_WEBP:
#if (NGX_HAVE_GD_WEBP)
        img = gdImageCreateFromWebpPtr(ctx->length, ctx->image);
        failed = "gdImageCreateFromWebpPtr() failed";
#else
        failed = "Angie was built without GD WebP support";
#endif
        break;

    case NGX_HTTP_IMAGE_HEIC:
#if (NGX_HAVE_GD_HEIC)
        img = gdImageCreateFromHeifPtr(ctx->length, ctx->image);
        failed = "gdImageCreateFromHeifPtr() failed";
#else
        failed = "Angie was built without GD HEIC support";
#endif
        break;

    case NGX_HTTP_IMAGE_AVIF:
#if (NGX_HAVE_GD_AVIF)
        img = gdImageCreateFromAvifPtr(ctx->length, ctx->image);
        failed = "gdImageCreateFromAvifPtr() failed";
#else
        failed = "Angie was built without GD AVIF support";
#endif
        break;

    default:
        failed = "unknown image type";
        break;
    }

    if (img == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, failed);
    }

    return img;
}


static gdImagePtr
ngx_http_image_new(ngx_http_request_t *r, int w, int h, int colors)
{
    gdImagePtr  img;

    if (colors == 0) {
        img = gdImageCreateTrueColor(w, h);

        if (img == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "gdImageCreateTrueColor() failed");
            return NULL;
        }

    } else {
        img = gdImageCreate(w, h);

        if (img == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "gdImageCreate() failed");
            return NULL;
        }
    }

    return img;
}


static u_char *
ngx_http_image_out(ngx_http_request_t *r, ngx_uint_t type, gdImagePtr img,
    int *size)
{
    char                          *failed;
    u_char                        *out;
    ngx_int_t                      q;
#if (NGX_HAVE_GD_AVIF)
    ngx_int_t                      s;
#endif
    ngx_http_image_filter_conf_t  *conf;

    out = NULL;

    switch (type) {

    case NGX_HTTP_IMAGE_JPEG:
        conf = ngx_http_get_module_loc_conf(r, ngx_http_image_filter_module);

        q = ngx_http_image_filter_get_value(r, conf->jpeg_quality.complex_value,
                                            conf->jpeg_quality.value);
        if (q <= 0) {
            return NULL;
        }

        out = gdImageJpegPtr(img, size, q);
        failed = "gdImageJpegPtr() failed";
        break;

    case NGX_HTTP_IMAGE_GIF:
        out = gdImageGifPtr(img, size);
        failed = "gdImageGifPtr() failed";
        break;

    case NGX_HTTP_IMAGE_PNG:
        out = gdImagePngPtr(img, size);
        failed = "gdImagePngPtr() failed";
        break;

    case NGX_HTTP_IMAGE_WEBP:
#if (NGX_HAVE_GD_WEBP)
        conf = ngx_http_get_module_loc_conf(r, ngx_http_image_filter_module);

        q = ngx_http_image_filter_get_value(r, conf->webp_quality.complex_value,
                                            conf->webp_quality.value);
        if (q <= 0) {
            return NULL;
        }

        out = gdImageWebpPtrEx(img, size, q);
        failed = "gdImageWebpPtrEx() failed";
#else
        failed = "Angie was built without GD WebP support";
#endif
        break;

    case NGX_HTTP_IMAGE_HEIC:
#if (NGX_HAVE_GD_HEIC)
        conf = ngx_http_get_module_loc_conf(r, ngx_http_image_filter_module);

        q = ngx_http_image_filter_get_value(r, conf->heic_quality.complex_value,
                                            conf->heic_quality.value);
        if (q <= 0) {
            return NULL;
        }

        out = gdImageHeifPtrEx(img, size, q, GD_HEIF_CODEC_HEVC,
                               GD_HEIF_CHROMA_444);

        failed = "gdImageHeifPtrEx() failed";
#else
        failed = "Angie was built without GD HEIC support";
#endif
        break;

    case NGX_HTTP_IMAGE_AVIF:
#if (NGX_HAVE_GD_AVIF)
        conf = ngx_http_get_module_loc_conf(r, ngx_http_image_filter_module);

        q = ngx_http_image_filter_get_value(r, conf->avif_quality.complex_value,
                                            conf->avif_quality.value);
        if (q <= 0) {
            return NULL;
        }

        s = ngx_http_image_filter_get_value(r, conf->avif_speed.complex_value,
                                            conf->avif_speed.value);
        if (s <= 0) {
            return NULL;
        }

        out = gdImageAvifPtrEx(img, size, q, s);
        failed = "gdImageAvifPtrEx() failed";
#else
        failed = "Angie was built without GD AVIF support";
#endif
        break;


    default:
        failed = "unknown image type";
        break;
    }

    if (out == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, failed);
    }

    return out;
}


static void
ngx_http_image_cleanup(void *data)
{
    gdFree(data);
}


static ngx_uint_t
ngx_http_image_filter_get_value(ngx_http_request_t *r,
    ngx_http_complex_value_t *cv, ngx_uint_t v)
{
    ngx_str_t  val;

    if (cv == NULL) {
        return v;
    }

    if (ngx_http_complex_value(r, cv, &val) != NGX_OK) {
        return 0;
    }

    return ngx_http_image_filter_value(&val);
}


static ngx_uint_t
ngx_http_image_filter_value(ngx_str_t *value)
{
    ngx_int_t  n;

    if (value->len == 1 && value->data[0] == '-') {
        return (ngx_uint_t) -1;
    }

    n = ngx_atoi(value->data, value->len);

    if (n > 0) {
        return (ngx_uint_t) n;
    }

    return 0;
}


static void *
ngx_http_image_filter_create_conf(ngx_conf_t *cf)
{
    ngx_http_image_filter_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_image_filter_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->width = 0;
     *     conf->height = 0;
     *     conf->angle = 0;
     *     conf->wcv = NULL;
     *     conf->hcv = NULL;
     *     conf->acv = NULL;
     *     conf->jpeg_quality.complex_value = NULL;
     *     conf->webp_quality.complex_value = NULL;
     *     conf->heic_quality.complex_value = NULL;
     *     conf->avif_quality.complex_value = NULL;
     *     conf->avif_speed.complex_value = NULL;
     *     conf->sharpen.complex_value = NULL;
     *     conf->output_type.complex_value = NULL;
     */

    conf->filter = NGX_CONF_UNSET_UINT;
    conf->jpeg_quality.value = NGX_CONF_UNSET_UINT;
    conf->webp_quality.value = NGX_CONF_UNSET_UINT;
    conf->heic_quality.value = NGX_CONF_UNSET_UINT;
    conf->avif_quality.value = NGX_CONF_UNSET_UINT;
    conf->avif_speed.value = NGX_CONF_UNSET_UINT;
    conf->sharpen.value = NGX_CONF_UNSET_UINT;
    conf->output_type.value = NGX_CONF_UNSET_UINT;
    conf->transparency = NGX_CONF_UNSET;
    conf->interlace = NGX_CONF_UNSET;
    conf->buffer_size = NGX_CONF_UNSET_SIZE;

    return conf;
}


static char *
ngx_http_image_filter_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_image_filter_conf_t *prev = parent;
    ngx_http_image_filter_conf_t *conf = child;

    if (conf->filter == NGX_CONF_UNSET_UINT) {

        if (prev->filter == NGX_CONF_UNSET_UINT) {
            conf->filter = NGX_HTTP_IMAGE_OFF;

        } else {
            conf->filter = prev->filter;
            conf->width = prev->width;
            conf->height = prev->height;
            conf->angle = prev->angle;
            conf->wcv = prev->wcv;
            conf->hcv = prev->hcv;
            conf->acv = prev->acv;
        }
    }

    /* 75 is libjpeg default quality */
    ngx_http_image_filter_merge_value(&conf->jpeg_quality, &prev->jpeg_quality,
                                      75);

    /* 80 is libwebp default quality */
    ngx_http_image_filter_merge_value(&conf->webp_quality, &prev->webp_quality,
                                      80);

    ngx_http_image_filter_merge_value(&conf->heic_quality, &prev->heic_quality,
                                      80);

    ngx_http_image_filter_merge_value(&conf->avif_quality, &prev->avif_quality,
                                      80);

    ngx_http_image_filter_merge_value(&conf->avif_speed, &prev->avif_speed, 6);

    ngx_http_image_filter_merge_value(&conf->sharpen, &prev->sharpen, 0);

    ngx_http_image_filter_merge_value(&conf->output_type, &prev->output_type,
                                      NGX_HTTP_IMAGE_NONE);

    ngx_conf_merge_value(conf->transparency, prev->transparency, 1);

    ngx_conf_merge_value(conf->interlace, prev->interlace, 0);

    ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
                              1 * 1024 * 1024);

    return NGX_CONF_OK;
}


static void
ngx_http_image_filter_merge_value(ngx_http_image_filter_value_t *conf,
    ngx_http_image_filter_value_t *prev, ngx_uint_t default_value)
{
    if (conf->value != NGX_CONF_UNSET_UINT) {
        return;
    }

    ngx_conf_merge_uint_value(conf->value, prev->value, default_value);

    if (conf->complex_value == NULL) {
        conf->complex_value = prev->complex_value;
    }
}


static char *
ngx_http_image_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_image_filter_conf_t *imcf = conf;

    ngx_str_t                         *value;
    ngx_int_t                          n;
    ngx_uint_t                         i;
    ngx_http_complex_value_t           cv;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    i = 1;

    if (cf->args->nelts == 2) {
        if (ngx_strcmp(value[i].data, "off") == 0) {
            imcf->filter = NGX_HTTP_IMAGE_OFF;

        } else if (ngx_strcmp(value[i].data, "test") == 0) {
            imcf->filter = NGX_HTTP_IMAGE_TEST;

        } else if (ngx_strcmp(value[i].data, "size") == 0) {
            imcf->filter = NGX_HTTP_IMAGE_SIZE;

        } else {
            goto failed;
        }

        return NGX_CONF_OK;

    } else if (cf->args->nelts == 3) {

        if (ngx_strcmp(value[i].data, "rotate") == 0) {
            if (imcf->filter != NGX_HTTP_IMAGE_RESIZE
                && imcf->filter != NGX_HTTP_IMAGE_CROP)
            {
                imcf->filter = NGX_HTTP_IMAGE_ROTATE;
            }

            ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &value[++i];
            ccv.complex_value = &cv;

            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            if (cv.lengths == NULL) {
                n = ngx_http_image_filter_value(&value[i]);

                if (n != 90 && n != 180 && n != 270) {
                    goto failed;
                }

                imcf->angle = (ngx_uint_t) n;

            } else {
                imcf->acv = ngx_palloc(cf->pool,
                                       sizeof(ngx_http_complex_value_t));
                if (imcf->acv == NULL) {
                    return NGX_CONF_ERROR;
                }

                *imcf->acv = cv;
            }

            return NGX_CONF_OK;

        } else if (ngx_strcmp(value[i].data, "convert") == 0) {

            if (imcf->filter == NGX_CONF_UNSET_UINT) {
                imcf->filter = NGX_HTTP_IMAGE_CONVERT;
            }

            ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &value[++i];
            ccv.complex_value = &cv;

            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            if (cv.lengths == NULL) {
                imcf->output_type.value = ngx_http_image_filter_output_type(
                                                                    &value[i]);
                if (imcf->output_type.value == NGX_HTTP_IMAGE_NONE) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "invalid parameter \"%V\"", &value[i]);
                    return NGX_CONF_ERROR;
                }

            } else {
                imcf->output_type.complex_value = ngx_palloc(cf->pool,
                                             sizeof(ngx_http_complex_value_t));
                if (imcf->output_type.complex_value == NULL) {
                    return NGX_CONF_ERROR;
                }

                *imcf->output_type.complex_value = cv;
            }

            return NGX_CONF_OK;

        } else {
            goto failed;
        }
    }

    if (ngx_strcmp(value[i].data, "resize") == 0) {
        imcf->filter = NGX_HTTP_IMAGE_RESIZE;

    } else if (ngx_strcmp(value[i].data, "crop") == 0) {
        imcf->filter = NGX_HTTP_IMAGE_CROP;

    } else {
        goto failed;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[++i];
    ccv.complex_value = &cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = ngx_http_image_filter_value(&value[i]);

        if (n == 0) {
            goto failed;
        }

        imcf->width = (ngx_uint_t) n;

    } else {
        imcf->wcv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if (imcf->wcv == NULL) {
            return NGX_CONF_ERROR;
        }

        *imcf->wcv = cv;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[++i];
    ccv.complex_value = &cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = ngx_http_image_filter_value(&value[i]);

        if (n == 0) {
            goto failed;
        }

        imcf->height = (ngx_uint_t) n;

    } else {
        imcf->hcv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if (imcf->hcv == NULL) {
            return NGX_CONF_ERROR;
        }

        *imcf->hcv = cv;
    }

    return NGX_CONF_OK;

failed:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"",
                       &value[i]);

    return NGX_CONF_ERROR;
}


static ngx_uint_t
ngx_http_image_filter_output_type(ngx_str_t *value)
{
    size_t      len;
    ngx_str_t   type;
    ngx_uint_t  i;

    len = sizeof(ngx_http_image_types) / sizeof(ngx_http_image_types[0]);

    for (i = 0; i < len; i++) {
        type.data = ngx_http_image_types[i].data + 6;
        type.len = ngx_http_image_types[i].len - 6;

        if (type.len == value->len
            && ngx_strncmp(type.data, value->data, type.len) == 0)
        {
            return i + 1;
        }
    }

    return NGX_HTTP_IMAGE_NONE;
}


static char *
ngx_http_image_filter_conf_value(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    char *p = conf;

    ngx_str_t                         *value;
    ngx_int_t                          n;
    ngx_http_complex_value_t           cv;
    ngx_http_image_filter_value_t     *vp;
    ngx_http_compile_complex_value_t   ccv;

    vp = (ngx_http_image_filter_value_t *) (p + cmd->offset);

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = ngx_http_image_filter_value(&value[1]);

        if (n <= 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid value \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

        vp->value = (ngx_uint_t) n;

    } else {
        vp->complex_value = ngx_palloc(cf->pool,
                                       sizeof(ngx_http_complex_value_t));
        if (vp->complex_value == NULL) {
            return NGX_CONF_ERROR;
        }

        *vp->complex_value = cv;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_image_filter_avif_quality(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_str_t  *value;

    cmd->offset = offsetof(ngx_http_image_filter_conf_t, avif_quality);

    if (ngx_http_image_filter_conf_value(cf, cmd, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts == 2) {
        return NGX_CONF_OK;
    }

    value = cf->args->elts;

    value[1].data = value[2].data;
    value[1].len = value[2].len;

    cmd->offset = offsetof(ngx_http_image_filter_conf_t, avif_speed);

    return ngx_http_image_filter_conf_value(cf, cmd, conf);
}


static ngx_int_t
ngx_http_image_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_image_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_image_body_filter;

    return NGX_OK;
}
