/*
 * Copyright (C) 2026 Web Server LLC
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_DOH_TRANSPORT_TCP  0
#define NGX_HTTP_DOH_TRANSPORT_UDP  1
#define NGX_HTTP_DOH_TRANSPORT_AUTO 2


typedef struct {
    ngx_http_upstream_conf_t   upstream;
    size_t                     max_size;
    ngx_uint_t                 transport;
} ngx_http_doh_loc_conf_t;


typedef struct {
    ngx_http_request_t        *request;
    ngx_chain_t               *request_cl;   /* UDP starts at ->next */
    size_t                     request_len;
    u_char                     query_id[2];  /* original client query ID */
    u_char                     random_id[2]; /* randomized ID to upstream */
    unsigned                   transport:2;
    unsigned                   tc_retry:1;
} ngx_http_doh_ctx_t;


static ngx_int_t ngx_http_doh_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_doh_check_len(off_t len, size_t max_size);
static void ngx_http_doh_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_doh_init_upstream(ngx_http_request_t *r,
    ngx_chain_t *body, size_t len);
static ngx_int_t ngx_http_doh_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_doh_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_doh_process_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_doh_filter_init(void *data);
static ngx_int_t ngx_http_doh_filter(void *data, ssize_t bytes);
static void ngx_http_doh_abort_request(ngx_http_request_t *r);
static void ngx_http_doh_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);

static void *ngx_http_doh_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_doh_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_http_doh_pass(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_uint_t ngx_http_doh_extract_min_ttl(u_char *data, size_t len);
static ngx_int_t ngx_http_doh_skip_name(u_char **p, u_char *end);
static ngx_int_t ngx_http_doh_parse_ttl(u_char *p, ngx_uint_t *min_ttl);


static ngx_conf_num_bounds_t  ngx_http_doh_buffer_size_bounds = {
    ngx_conf_check_num_bounds, 512, -1
};


static ngx_conf_bitmask_t  ngx_http_doh_next_upstream_masks[] = {
    { ngx_string("error"), NGX_HTTP_UPSTREAM_FT_ERROR },
    { ngx_string("timeout"), NGX_HTTP_UPSTREAM_FT_TIMEOUT },
    { ngx_string("invalid_response"), NGX_HTTP_UPSTREAM_FT_INVALID_HEADER },
    { ngx_string("off"), NGX_HTTP_UPSTREAM_FT_OFF },
    { ngx_null_string, 0 }
};


static ngx_conf_num_bounds_t  ngx_http_doh_max_size_bounds = {
    ngx_conf_check_num_bounds, 12, -1
};


static ngx_conf_enum_t  ngx_http_doh_transport_names[] = {
    { ngx_string("tcp"), NGX_HTTP_DOH_TRANSPORT_TCP },
    { ngx_string("udp"), NGX_HTTP_DOH_TRANSPORT_UDP },
    { ngx_string("auto"), NGX_HTTP_DOH_TRANSPORT_AUTO },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_doh_commands[] = {

    { ngx_string("doh_pass"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_doh_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("doh_bind"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_upstream_bind_set_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_doh_loc_conf_t, upstream.local),
      NULL },

    { ngx_string("doh_socket_keepalive"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_doh_loc_conf_t, upstream.socket_keepalive),
      NULL },

    { ngx_string("doh_connect_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_doh_loc_conf_t, upstream.connect_timeout),
      NULL },

    { ngx_string("doh_send_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_doh_loc_conf_t, upstream.send_timeout),
      NULL },

    { ngx_string("doh_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_doh_loc_conf_t, upstream.buffer_size),
      &ngx_http_doh_buffer_size_bounds },

    { ngx_string("doh_read_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_doh_loc_conf_t, upstream.read_timeout),
      NULL },

    { ngx_string("doh_next_upstream"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_doh_loc_conf_t, upstream.next_upstream),
      &ngx_http_doh_next_upstream_masks },

    { ngx_string("doh_next_upstream_tries"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_doh_loc_conf_t, upstream.next_upstream_tries),
      NULL },

    { ngx_string("doh_next_upstream_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_doh_loc_conf_t, upstream.next_upstream_timeout),
      NULL },

    { ngx_string("doh_max_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_doh_loc_conf_t, max_size),
      &ngx_http_doh_max_size_bounds },

    { ngx_string("doh_transport"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_doh_loc_conf_t, transport),
      &ngx_http_doh_transport_names },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_doh_module_ctx = {
    NULL,                              /* preconfiguration */
    NULL,                              /* postconfiguration */

    NULL,                              /* create main configuration */
    NULL,                              /* init main configuration */

    NULL,                              /* create server configuration */
    NULL,                              /* merge server configuration */

    ngx_http_doh_create_loc_conf,      /* create location configuration */
    ngx_http_doh_merge_loc_conf        /* merge location configuration */
};


ngx_module_t  ngx_http_doh_module = {
    NGX_MODULE_V1,
    &ngx_http_doh_module_ctx,          /* module context */
    ngx_http_doh_commands,             /* module directives */
    NGX_HTTP_MODULE,                   /* module type */
    NULL,                              /* init master */
    NULL,                              /* init module */
    NULL,                              /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    NULL,                              /* exit process */
    NULL,                              /* exit master */
    NGX_MODULE_V1_PADDING
};


static const ngx_str_t  ngx_http_doh_type
    = ngx_string("application/dns-message");


static ngx_int_t
ngx_http_doh_handler(ngx_http_request_t *r)
{
    size_t                    pad_len;
    ngx_str_t                 dns_param, decoded, padded;
    ngx_int_t                 rc;
    ngx_buf_t                *b;
    ngx_chain_t              *cl;
    ngx_http_doh_loc_conf_t  *dlcf;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_POST))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_doh_module);

    if (r->method == NGX_HTTP_GET) {

        /*
         * RFC 8484: GET method uses ?dns=<base64url> query parameter.
         * Extract and decode the base64url-encoded DNS query.
         */

        if (ngx_http_arg(r, (u_char *) "dns", 3, &dns_param) != NGX_OK) {
            return NGX_HTTP_BAD_REQUEST;
        }

        if (dns_param.len == 0) {
            return NGX_HTTP_BAD_REQUEST;
        }

        /*
         * base64url may have padding stripped; ngx_decode_base64url() expects
         * the input length to be a multiple of 4, so we may need to add
         * padding characters.
         */

        pad_len = (4 - dns_param.len % 4) % 4;

        if (pad_len != 0) {
            padded.data = ngx_pnalloc(r->pool, dns_param.len + pad_len);
            if (padded.data == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            ngx_memcpy(padded.data, dns_param.data, dns_param.len);
            ngx_memset(padded.data + dns_param.len, '=', pad_len);
            padded.len = dns_param.len + pad_len;

        } else {
            padded = dns_param;
        }

        decoded.len = ngx_base64_decoded_length(padded.len);
        decoded.data = ngx_pnalloc(r->pool, decoded.len);
        if (decoded.data == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (ngx_decode_base64url(&decoded, &padded) != NGX_OK) {
            return NGX_HTTP_BAD_REQUEST;
        }

        rc = ngx_http_doh_check_len(decoded.len, dlcf->max_size);
        if (rc != NGX_OK) {
            return rc;
        }

        rc = ngx_http_discard_request_body(r);
        if (rc != NGX_OK) {
            return rc;
        }

        /*
         * Build a persistent buf+chain for the decoded DNS data.
         * init_upstream stores the chain pointer, so it must
         * outlive the call.
         */

        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b->temporary = 1;
        b->pos = decoded.data;
        b->last = decoded.data + decoded.len;
        b->start = b->pos;
        b->end = b->last;

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        cl->buf = b;
        cl->next = NULL;

        r->main->count++;

        rc = ngx_http_doh_init_upstream(r, cl, decoded.len);

        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            r->main->count--;
        }

        return rc;
    }

    /* NGX_HTTP_POST */

    if (r->headers_in.content_type == NULL
        || r->headers_in.content_type->value.len != ngx_http_doh_type.len
        || ngx_strncasecmp(r->headers_in.content_type->value.data,
                           ngx_http_doh_type.data, ngx_http_doh_type.len)
        != 0)
    {
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    if (r->headers_in.content_length_n >= 0) {
        rc = ngx_http_doh_check_len(r->headers_in.content_length_n,
                                    dlcf->max_size);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    rc = ngx_http_read_client_request_body(r, ngx_http_doh_body_handler);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static ngx_int_t
ngx_http_doh_check_len(off_t len, size_t max_size)
{
    if (len > (off_t) max_size) {
        return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
    }

    if (len < 12) {
        return NGX_HTTP_BAD_REQUEST;
    }

    return NGX_OK;
}


static void
ngx_http_doh_body_handler(ngx_http_request_t *r)
{
    size_t                    len;
    ngx_int_t                 rc;
    ngx_chain_t              *cl;
    ngx_http_doh_loc_conf_t  *dlcf;

    /* NGX_HTTP_POST */

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_doh_module);

    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return;
    }

    if (r->headers_in.chunked) {
        rc = ngx_http_doh_check_len(r->headers_in.content_length_n,
                                    dlcf->max_size);
        if (rc != NGX_OK) {
            ngx_http_finalize_request(r, rc);
            return;
        }
    }

    len = (size_t) r->headers_in.content_length_n;
    cl = r->request_body->bufs;

    rc = ngx_http_doh_init_upstream(r, cl, len);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_http_finalize_request(r, rc);
        return;
    }

    /* rc == NGX_DONE; upstream framework will finalize the request */
}


static ngx_int_t
ngx_http_doh_init_upstream(ngx_http_request_t *r, ngx_chain_t *body, size_t len)
{
    size_t                    file_size;
    ssize_t                   n;
    uint16_t                  id;
    ngx_buf_t                *b;
    ngx_chain_t              *cl;
    ngx_http_doh_ctx_t       *ctx;
    ngx_http_upstream_t      *u;
    ngx_http_doh_loc_conf_t  *dlcf;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_doh_module);

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u = r->upstream;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_doh_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->request = r;
    ctx->request_len = len;

    ctx->transport = (dlcf->transport == NGX_HTTP_DOH_TRANSPORT_AUTO)
                      ? NGX_HTTP_DOH_TRANSPORT_UDP
                      : dlcf->transport;

    /*
     * Replace the client query ID with a random one to prevent poisoning.
     * For file-backed buffers, read the body into memory first.
     */

    if (body->buf->in_file) {
        file_size = body->buf->file_last - body->buf->file_pos;

        b = ngx_create_temp_buf(r->pool, file_size);
        if (b == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        n = ngx_read_file(body->buf->file, b->last, file_size,
                          body->buf->file_pos);

        if (n != (ssize_t) file_size) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b->last += n;

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        cl->buf = b;
        cl->next = body->next;
        body = cl;
    }

    /* body is guaranteed in memory from here */

    ngx_memcpy(ctx->query_id, body->buf->pos, 2);

    id = ngx_random();
    ngx_memcpy(ctx->random_id, (u_char *) &id, 2);
    ngx_memcpy(body->buf->pos, ctx->random_id, 2);

    /*
     * Build a single chain: [2-byte TCP length prefix] → [body].
     * For UDP, create_request skips the prefix by starting at ->next.
     */

    b = ngx_create_temp_buf(r->pool, 2);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    *b->last++ = (u_char) ((len >> 8) & 0xff);
    *b->last++ = (u_char) (len & 0xff);

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cl->buf = b;
    cl->next = body;

    ctx->request_cl = cl;

    /* Set flush/last_buf on the last buffer of the body chain. */
    for (cl = body; cl->next; cl = cl->next) { /* void */ }
    cl->buf->flush = 1;
    cl->buf->last_buf = 1;

    ngx_http_set_ctx(r, ctx, ngx_http_doh_module);

    /* upstream configuration */

    ngx_str_set(&u->schema, "dns://");
    u->output.tag = (ngx_buf_tag_t) &ngx_http_doh_module;
    u->conf = &dlcf->upstream;

    u->create_request = ngx_http_doh_create_request;
    u->reinit_request = ngx_http_doh_reinit_request;
    u->process_header = ngx_http_doh_process_header;
    u->abort_request = ngx_http_doh_abort_request;
    u->finalize_request = ngx_http_doh_finalize_request;

    if (ctx->transport == NGX_HTTP_DOH_TRANSPORT_UDP) {
        u->peer.type = SOCK_DGRAM;
    }

    u->input_filter_init = ngx_http_doh_filter_init;
    u->input_filter = ngx_http_doh_filter;
    u->input_filter_ctx = ctx;

    ngx_http_upstream_init(r);

    return NGX_DONE;
}


static ngx_int_t
ngx_http_doh_create_request(ngx_http_request_t *r)
{
    ngx_http_doh_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_doh_module);

    r->upstream->request_bufs = (ctx->transport == NGX_HTTP_DOH_TRANSPORT_TCP)
                                ? ctx->request_cl
                                : ctx->request_cl->next;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "DoH create request: %uz bytes, transport=%s",
                   ctx->request_len,
                   ctx->transport == NGX_HTTP_DOH_TRANSPORT_TCP
                       ? "tcp" : "udp");

    return NGX_OK;
}


static ngx_int_t
ngx_http_doh_reinit_request(ngx_http_request_t *r)
{
    ngx_uint_t                prev;
    ngx_http_doh_ctx_t       *ctx;
    ngx_http_upstream_t      *u;
    ngx_http_doh_loc_conf_t  *dlcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_doh_module);

    if (ctx == NULL) {
        return NGX_OK;
    }

    u = r->upstream;
    prev = ctx->transport;

    if (ctx->tc_retry) {
        /* TC=1 fallback: switch to TCP. */
        ctx->transport = NGX_HTTP_DOH_TRANSPORT_TCP;

    } else {
        if (u->peer.connection && u->peer.connection->type == SOCK_STREAM) {
            /*
             * In auto mode, the upstream keepalive cache may return a cached
             * TCP connection when u->peer.type was SOCK_DGRAM.
             */
            ctx->transport = NGX_HTTP_DOH_TRANSPORT_TCP;

        } else {
            dlcf = ngx_http_get_module_loc_conf(r, ngx_http_doh_module);

            if (dlcf->transport == NGX_HTTP_DOH_TRANSPORT_AUTO) {
                /*
                 * Normal retry: reset transport to the configured default.
                 * This ensures that a previous cached TCP connection returned
                 * for an auto-mode UDP request does not affect retries.
                 */
                ctx->transport = NGX_HTTP_DOH_TRANSPORT_UDP;
            }
        }
    }

    /*
     * Rebuild the request buffer when transport changed.  This covers:
     *  - TC retry: UDP → TCP (first retry only; subsequent TCP retries
     *    are no-change since tc_retry already set transport = TCP)
     *  - Keepalive returned cached-TCP: UDP → TCP
     *  - Transport reset after cached-TCP failure: TCP → UDP
     */
    if (ctx->transport != prev) {
        return ngx_http_doh_create_request(r);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_doh_process_header(ngx_http_request_t *r)
{
    size_t                    len, need;
    ngx_uint_t                min_ttl;
    u_char                   *dns;
    ngx_table_elt_t          *cc;
    ngx_http_doh_ctx_t       *ctx;
    ngx_http_upstream_t      *u;
    ngx_http_doh_loc_conf_t  *dlcf;

    u = r->upstream;
    ctx = ngx_http_get_module_ctx(r, ngx_http_doh_module);
    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_doh_module);

    /*
     * Parse the wire framing to locate the DNS message.
     *
     * TCP: 2-byte big-endian length prefix + DNS wire format.
     * UDP: raw DNS wire format (entire response in one datagram).
     */

    if (ctx->transport == NGX_HTTP_DOH_TRANSPORT_TCP) {

        if ((size_t) (u->buffer.last - u->buffer.pos) < 2) {
            return NGX_AGAIN;
        }

        len = ((size_t) u->buffer.pos[0] << 8) | u->buffer.pos[1];
        need = ngx_min(dlcf->upstream.buffer_size, 2 + len);

        if ((size_t) (u->buffer.last - u->buffer.pos) < need) {
            return NGX_AGAIN;
        }

        u->buffer.pos += 2;

    } else {
        len = u->buffer.last - u->buffer.pos;
    }

    dns = u->buffer.pos;

    if (len < 12) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "DoH upstream sent too short response: %uz", len);
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }

    /* validate DNS query ID matches the randomized ID we sent */
    if (ngx_memcmp(dns, ctx->random_id, 2) != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "DoH upstream sent response with mismatched query ID");
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }

    /* restore the original client query ID in the response */
    ngx_memcpy(dns, ctx->query_id, 2);

    /* validate QR bit: byte 2, bit 7 must be 1 (this is a response) */
    if (!(dns[2] & 0x80)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "DoH upstream sent DNS message with "
                      "QR=0 (not a response)");
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }

    /* extract and log DNS RCODE from flags (bottom 4 bits of byte 3) */
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "DoH upstream response: TC=%d RCODE=%d",
                   (dns[2] & 0x02) ? 1 : 0, dns[3] & 0x0f);

    if (ctx->transport == NGX_HTTP_DOH_TRANSPORT_UDP && (dns[2] & 0x02)) {
        /*
         * RFC 8484 / RFC 1035: the upstream DNS server returned a truncated
         * response (TC=1) over UDP.
         */

        u->state->header_time = ngx_current_msec - u->start_time;
        u->state->status = NGX_HTTP_UPGRADE_REQUIRED;

        if (dlcf->transport == NGX_HTTP_DOH_TRANSPORT_UDP) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "DoH upstream UDP response truncated (TC=1), "
                          "no TCP fallback available");
            /*
             * A truncated DNS response is useless to a DoH client.
             *
             * The upstream framework will finalize the request with 500
             * and stats the attempt as 426 without penalizing the server
             * (the response was valid, just too large for UDP).
             */
            return NGX_ERROR;
        }

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "DoH upstream UDP response truncated (TC=1), "
                      "retrying over TCP");

        u->peer.type = SOCK_STREAM;
        ctx->tc_retry = 1;

        return NGX_HTTP_UPSTREAM_RECONNECT;
    }

    /* set response headers */

    r->headers_out.content_type_len = ngx_http_doh_type.len;
    r->headers_out.content_type = ngx_http_doh_type;
    r->headers_out.content_type_lowcase = NULL;

    cc = ngx_list_push(&r->headers_out.headers);
    if (cc == NULL) {
        return NGX_ERROR;
    }

    cc->hash = 1;
    cc->next = NULL;
    ngx_str_set(&cc->key, "Cache-Control");

    /*
     * Extract minimum TTL from the answer section.  For TCP streaming
     * responses (larger than buffer), only the buffered portion of the
     * answer section is available; extract_min_ttl handles truncated
     * data safely and returns 0 (no cache hint) if the answer section
     * is incomplete.
     */
    min_ttl = ngx_http_doh_extract_min_ttl(dns, u->buffer.last - dns);

    if (min_ttl == 0) {
        ngx_str_set(&cc->value, "no-store");

    } else {
        cc->value.data = ngx_pnalloc(r->pool, sizeof("max-age=2147483647") - 1);
        if (cc->value.data == NULL) {
            cc->hash = 0;
            return NGX_ERROR;
        }

        cc->value.len = ngx_sprintf(cc->value.data, "max-age=%ui", min_ttl)
                        - cc->value.data;
    }

    r->headers_out.cache_control = cc;

    u->headers_in.content_length_n = (off_t) len;
    u->headers_in.status_n = 200;

    u->state->status = 200;

    /*
     * Allow the upstream keepalive module to cache this TCP connection
     * for reuse.  Only set u->keepalive for TCP: UDP connections are
     * datagram-based and must not be cached (the keepalive close handler
     * also rejects SOCK_DGRAM, but we avoid setting the flag regardless).
     */

    u->keepalive = (ctx->transport == NGX_HTTP_DOH_TRANSPORT_TCP);

    return NGX_OK;
}


static ngx_int_t
ngx_http_doh_filter_init(void *data)
{
    ngx_http_doh_ctx_t   *ctx = data;
    ngx_http_upstream_t  *u;

    u = ctx->request->upstream;
    u->length = u->headers_in.content_length_n;

    return NGX_OK;
}


static ngx_int_t
ngx_http_doh_filter(void *data, ssize_t bytes)
{
    ngx_http_doh_ctx_t  *ctx = data;

    ngx_buf_t            *b;
    ngx_chain_t          *cl, **ll;
    ngx_http_upstream_t  *u;

    u = ctx->request->upstream;

    b = &u->buffer;

    ll = &u->out_bufs;

    while (*ll) {
        ll = &(*ll)->next;
    }

    cl = ngx_chain_get_free_buf(ctx->request->pool, &u->free_bufs);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf->flush = 1;
    cl->buf->memory = 1;

    *ll = cl;

    cl->buf->pos = b->last;
    b->last += bytes;
    cl->buf->last = b->last;
    cl->buf->tag = u->output.tag;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "DoH filter bytes:%z size:%z length:%O",
                   bytes, b->last - b->pos, u->length);

    if (bytes > u->length) {

        ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                      "DoH filter: upstream sent more data than specified "
                      "in the DNS length prefix");

        cl->buf->last = cl->buf->pos + u->length;
        u->length = 0;

        return NGX_OK;
    }

    u->length -= bytes;

    return NGX_OK;
}


static void
ngx_http_doh_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http doh request");
}


static void
ngx_http_doh_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http doh request");
}


static void *
ngx_http_doh_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_doh_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_doh_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->upstream.bufs.num = 0;
     *     conf->upstream.next_upstream = 0;
     *     conf->upstream.temp_path = NULL;
     */

    conf->upstream.local = NGX_CONF_UNSET_PTR;
    conf->upstream.socket_keepalive = NGX_CONF_UNSET;
    conf->upstream.next_upstream_tries = NGX_CONF_UNSET_UINT;
    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;

    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

    /* the hardcoded values */
    conf->upstream.cyclic_temp_file = 0;
    conf->upstream.buffering = 0;
    conf->upstream.ignore_client_abort = 0;
    conf->upstream.send_lowat = 0;
    conf->upstream.bufs.num = 0;
    conf->upstream.busy_buffers_size = 0;
    conf->upstream.max_temp_file_size = 0;
    conf->upstream.temp_file_write_size = 0;
    conf->upstream.intercept_errors = 1;
    conf->upstream.intercept_404 = 1;
    conf->upstream.pass_request_headers = 0;
    conf->upstream.pass_request_body = 0;
    conf->upstream.force_ranges = 0;

    conf->max_size = NGX_CONF_UNSET_SIZE;
    conf->transport = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_doh_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_doh_loc_conf_t  *prev = parent;
    ngx_http_doh_loc_conf_t  *conf = child;

    ngx_conf_merge_ptr_value(conf->upstream.local,
                              prev->upstream.local, NULL);

    ngx_conf_merge_value(conf->upstream.socket_keepalive,
                              prev->upstream.socket_keepalive, 0);

    ngx_conf_merge_uint_value(conf->upstream.next_upstream_tries,
                              prev->upstream.next_upstream_tries, 0);

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.next_upstream_timeout,
                              prev->upstream.next_upstream_timeout, 0);

    ngx_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) 16 * 1024);

    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
                              prev->upstream.next_upstream,
                              (NGX_CONF_BITMASK_SET
                               |NGX_HTTP_UPSTREAM_FT_ERROR
                               |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    /*
     * DNS queries are inherently idempotent regardless of HTTP method.
     * Always allow retries on non-idempotent requests so that the upstream
     * framework's POST-method check does not block legitimate DNS retries.
     */
    if (!(conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF)) {
        conf->upstream.next_upstream |= NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT;
    }

    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
                                       |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->upstream.upstream == NULL) {
        conf->upstream.upstream = prev->upstream.upstream;
    }

    ngx_conf_merge_size_value(conf->max_size, prev->max_size,
                              (size_t) ngx_pagesize);

    ngx_conf_merge_uint_value(conf->transport, prev->transport,
                              NGX_HTTP_DOH_TRANSPORT_AUTO);

    return NGX_CONF_OK;
}


static char *
ngx_http_doh_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_doh_loc_conf_t  *dlcf = conf;

    ngx_str_t                 *value;
    ngx_url_t                  u;
    ngx_http_core_loc_conf_t  *clcf;

    if (dlcf->upstream.upstream) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.no_resolve = 1;

    dlcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
    if (dlcf->upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_doh_handler;

    return NGX_CONF_OK;
}


static ngx_uint_t
ngx_http_doh_extract_min_ttl(u_char *data, size_t len)
{
    u_char      *p, *end, *rp, *soa_end;
    size_t       rdlength;
    ngx_uint_t   qdcount, ancount, nscount, min_ttl, i, rtype, count, authority;

    if (len < 12) {
        /*
         * Defensive check: the caller (process_header) already validates
         * that len >= 12 before calling.  Kept as a safety guard in case
         * this function is ever called from a different context.
         */
        return 0;
    }

    p = data + 2 + 2;  /* skip ID(2) + flags(2) */

    qdcount = (p[0] << 8) | p[1];
    p += 2;

    ancount = (p[0] << 8) | p[1];
    p += 2;

    nscount = (p[0] << 8) | p[1];
    p += 2 + 2; /* skip ARCOUNT(2) */

    end = data + len;

    /* skip question section */
    for (i = 0; i < qdcount && p < end; i++) {
        if (ngx_http_doh_skip_name(&p, end) != NGX_OK) {
            return 0;
        }

        p += 2 + 2;  /* QTYPE(2) + QCLASS(2) */

        if (p > end) {
            return 0;
        }
    }

    min_ttl = NGX_MAX_UINT32_VALUE;

    /*
     * Iterate answer section, then authority section.
     * Per RFC 2308 §5, for negative responses (NXDOMAIN, NODATA) the
     * negative TTL comes from the SOA MINIMUM field in the authority
     * section, so we also scan it for SOA records.
     */

    count = ancount;
    authority = 0;

next_section:

    for (i = 0; i < count && p < end; i++) {
        if (ngx_http_doh_skip_name(&p, end) != NGX_OK) {
            return 0;
        }

        if (end - p < 10) {
            return 0;
        }

        rtype = ((ngx_uint_t) p[0] << 8) | p[1];
        p += 2 + 2;  /* skip CLASS(2) */

        if (ngx_http_doh_parse_ttl(p, &min_ttl) != NGX_OK) {
            return 0;
        }

        p += 4;  /* TTL(4) */

        rdlength = ((size_t) p[0] << 8) | p[1];
        p += 2;

        if (rdlength > (size_t) (end - p)) {
            return 0;
        }

        if (authority && rtype == 6 /* SOA */) {
            /*
             * SOA RDATA contains: MNAME, RNAME, SERIAL(4), REFRESH(4),
             * RETRY(4), EXPIRE(4), MINIMUM(4).
             * Per RFC 2308 §5, the MINIMUM field is the negative cache TTL.
             * We already recorded the SOA record's own TTL above; also
             * extract MINIMUM and use the lower of the two.
             */
            rp = p;
            soa_end = p + rdlength;

            /* skip MNAME (domain name) */
            if (ngx_http_doh_skip_name(&rp, soa_end) == NGX_OK

                /* skip RNAME (domain name) */
                && ngx_http_doh_skip_name(&rp, soa_end) == NGX_OK

                /* SERIAL+REFRESH+RETRY+EXPIRE = 16, MINIMUM = 4 */
                && rp + 20 <= soa_end)
            {
                rp += 16;

                /* MINIMUM(4) */
                if (ngx_http_doh_parse_ttl(rp, &min_ttl) != NGX_OK) {
                    return 0;
                }
            }
        }

        p += rdlength;
    }

    if (!authority) {
        if (ancount > 0 && min_ttl != NGX_MAX_UINT32_VALUE) {
            return min_ttl;
        }

        /* fall back to authority section for negative TTL (RFC 2308 §5) */
        count = nscount;
        authority = 1;
        goto next_section;
    }

    return (min_ttl == NGX_MAX_UINT32_VALUE) ? 0 : min_ttl;
}


static ngx_int_t
ngx_http_doh_skip_name(u_char **p, u_char *end)
{
    uint8_t  n;

    if (*p == end) {
        return NGX_ERROR;
    }

    for ( ;; ) {
        n = *(*p)++;

        if (n == 0) {
            break;
        }

        if (n & 0xc0) {
            if ((n & 0xc0) != 0xc0) {
                /*
                 * Extended label type (0x40-0xBF) per RFC 6891.
                 * Only 0x00-0x3F (label) and 0xC0-0xFF (compression)
                 * are valid; anything else means we cannot reliably
                 * parse the name.
                 */
                return NGX_ERROR;
            }

            /* compression pointer */

            if (*p == end) {
                return NGX_ERROR;
            }

            (*p)++;
            break;
        }

        if (n >= end - *p) {
            return NGX_ERROR;
        }

        *p += n;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_doh_parse_ttl(u_char *p, ngx_uint_t *min_ttl)
{
    ngx_uint_t  ttl;

    ttl = ((ngx_uint_t) p[0] << 24)
          | ((ngx_uint_t) p[1] << 16)
          | ((ngx_uint_t) p[2] << 8)
          | p[3];

    if (ttl > NGX_MAX_INT32_VALUE) {
        /*
         * Per RFC 2181 §8, the maximum valid TTL value is 2^31 - 1.
         * Values bigger than that must be handled like zero.
         */
        return NGX_ERROR;
    }

    if (ttl < *min_ttl) {
        *min_ttl = ttl;
    }

    return NGX_OK;
}
