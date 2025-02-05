
/*
 * Copyright (C) 2023 Web Server LLC
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_HTTP_V3 && NGX_QUIC_OPENSSL_COMPAT)
#include <ngx_event_quic_openssl_compat.h>
#endif


#define  NGX_HTTP_PROXY_COOKIE_SECURE           0x0001
#define  NGX_HTTP_PROXY_COOKIE_SECURE_ON        0x0002
#define  NGX_HTTP_PROXY_COOKIE_SECURE_OFF       0x0004
#define  NGX_HTTP_PROXY_COOKIE_HTTPONLY         0x0008
#define  NGX_HTTP_PROXY_COOKIE_HTTPONLY_ON      0x0010
#define  NGX_HTTP_PROXY_COOKIE_HTTPONLY_OFF     0x0020
#define  NGX_HTTP_PROXY_COOKIE_SAMESITE         0x0040
#define  NGX_HTTP_PROXY_COOKIE_SAMESITE_STRICT  0x0080
#define  NGX_HTTP_PROXY_COOKIE_SAMESITE_LAX     0x0100
#define  NGX_HTTP_PROXY_COOKIE_SAMESITE_NONE    0x0200
#define  NGX_HTTP_PROXY_COOKIE_SAMESITE_OFF     0x0400


typedef struct {
    ngx_array_t                    caches;  /* ngx_http_file_cache_t * */
} ngx_http_proxy_main_conf_t;


typedef struct ngx_http_proxy_rewrite_s  ngx_http_proxy_rewrite_t;

typedef ngx_int_t (*ngx_http_proxy_rewrite_pt)(ngx_http_request_t *r,
    ngx_str_t *value, size_t prefix, size_t len,
    ngx_http_proxy_rewrite_t *pr);

struct ngx_http_proxy_rewrite_s {
    ngx_http_proxy_rewrite_pt      handler;

    union {
        ngx_http_complex_value_t   complex;
#if (NGX_PCRE)
        ngx_http_regex_t          *regex;
#endif
    } pattern;

    ngx_http_complex_value_t       replacement;
};


typedef struct {
    union {
        ngx_http_complex_value_t   complex;
#if (NGX_PCRE)
        ngx_http_regex_t          *regex;
#endif
    } cookie;

    ngx_array_t                    flags_values;
    ngx_uint_t                     regex;
} ngx_http_proxy_cookie_flags_t;


typedef struct {
    ngx_str_t                      key_start;
    ngx_str_t                      schema;
    ngx_str_t                      host_header;
    ngx_str_t                      port;
    ngx_str_t                      uri;
} ngx_http_proxy_vars_t;


typedef struct {
    ngx_array_t                   *flushes;
    ngx_array_t                   *lengths;
    ngx_array_t                   *values;
    ngx_hash_t                     hash;
} ngx_http_proxy_headers_t;


typedef struct {
    ngx_http_upstream_conf_t       upstream;

    ngx_array_t                   *body_flushes;
    ngx_array_t                   *body_lengths;
    ngx_array_t                   *body_values;
    ngx_str_t                      body_source;

    ngx_http_proxy_headers_t       headers;
#if (NGX_HTTP_CACHE)
    ngx_http_proxy_headers_t       headers_cache;
#endif
    ngx_array_t                   *headers_source;

    ngx_array_t                   *proxy_lengths;
    ngx_array_t                   *proxy_values;

    ngx_array_t                   *redirects;
    ngx_array_t                   *cookie_domains;
    ngx_array_t                   *cookie_paths;
    ngx_array_t                   *cookie_flags;

    ngx_http_complex_value_t      *method;
    ngx_str_t                      location;
    ngx_str_t                      url;

#if (NGX_HTTP_CACHE)
    ngx_http_complex_value_t       cache_key;
#endif

    ngx_http_proxy_vars_t          vars;

    ngx_flag_t                     redirect;

    ngx_uint_t                     http_version;

    ngx_uint_t                     headers_hash_max_size;
    ngx_uint_t                     headers_hash_bucket_size;

#if (NGX_HTTP_SSL)
    ngx_uint_t                     ssl;
    ngx_uint_t                     ssl_protocols;
    ngx_str_t                      ssl_ciphers;
    ngx_uint_t                     ssl_verify_depth;
    ngx_str_t                      ssl_trusted_certificate;
    ngx_str_t                      ssl_crl;
    ngx_array_t                   *ssl_conf_commands;
#endif

#if (NGX_HTTP_V3)
    ngx_str_t                      host;
    ngx_uint_t                     host_set;
    ngx_flag_t                     enable_hq;
    ngx_uint_t                     max_table_capacity_set;
#endif
} ngx_http_proxy_loc_conf_t;


typedef struct {
    ngx_http_status_t              status;
    ngx_http_chunked_t             chunked;
    ngx_http_proxy_vars_t          vars;
    off_t                          internal_body_length;

    ngx_chain_t                   *free;
    ngx_chain_t                   *busy;

    ngx_buf_t                     *trailers;

#if (NGX_HTTP_V3)
    ngx_str_t                      host;
    ngx_http_v3_parse_t           *v3_parse;
    size_t                         data_recvd;
#endif

    unsigned                       head:1;
    unsigned                       internal_chunked:1;
    unsigned                       header_sent:1;
} ngx_http_proxy_ctx_t;


static ngx_int_t ngx_http_proxy_eval(ngx_http_request_t *r,
    ngx_http_proxy_ctx_t *ctx, ngx_http_proxy_loc_conf_t *plcf);
#if (NGX_HTTP_CACHE)
static ngx_int_t ngx_http_proxy_create_key(ngx_http_request_t *r);
#endif
static ngx_int_t ngx_http_proxy_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_body_output_filter(void *data, ngx_chain_t *in);
static ngx_int_t ngx_http_proxy_process_status_line(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_process_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_input_filter_init(void *data);
static ngx_int_t ngx_http_proxy_copy_filter(ngx_event_pipe_t *p,
    ngx_buf_t *buf);
static ngx_int_t ngx_http_proxy_chunked_filter(ngx_event_pipe_t *p,
    ngx_buf_t *buf);
static ngx_int_t ngx_http_proxy_non_buffered_copy_filter(void *data,
    ssize_t bytes);
static ngx_int_t ngx_http_proxy_non_buffered_chunked_filter(void *data,
    ssize_t bytes);
static ngx_int_t ngx_http_proxy_process_trailer(ngx_http_request_t *r,
    ngx_buf_t *buf);
static void ngx_http_proxy_abort_request(ngx_http_request_t *r);
static void ngx_http_proxy_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);

static ngx_int_t ngx_http_proxy_host_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_proxy_port_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t
    ngx_http_proxy_add_x_forwarded_for_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t
    ngx_http_proxy_internal_body_length_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_proxy_internal_chunked_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_proxy_rewrite_redirect(ngx_http_request_t *r,
    ngx_table_elt_t *h, size_t prefix);
static ngx_int_t ngx_http_proxy_rewrite_cookie(ngx_http_request_t *r,
    ngx_table_elt_t *h);
static ngx_int_t ngx_http_proxy_parse_cookie(ngx_str_t *value,
    ngx_array_t *attrs);
static ngx_int_t ngx_http_proxy_rewrite_cookie_value(ngx_http_request_t *r,
    ngx_str_t *value, ngx_array_t *rewrites);
static ngx_int_t ngx_http_proxy_rewrite_cookie_flags(ngx_http_request_t *r,
    ngx_array_t *attrs, ngx_array_t *flags);
static ngx_int_t ngx_http_proxy_edit_cookie_flags(ngx_http_request_t *r,
    ngx_array_t *attrs, ngx_uint_t flags);
static ngx_int_t ngx_http_proxy_rewrite(ngx_http_request_t *r,
    ngx_str_t *value, size_t prefix, size_t len, ngx_str_t *replacement);

static ngx_int_t ngx_http_proxy_add_variables(ngx_conf_t *cf);
static void *ngx_http_proxy_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_proxy_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_proxy_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_proxy_preserve_ssl_passwords(ngx_conf_t *cf,
    ngx_http_upstream_conf_t *conf, ngx_http_upstream_conf_t *prev);
#endif

static ngx_int_t ngx_http_proxy_init_headers(ngx_conf_t *cf,
    ngx_http_proxy_loc_conf_t *conf, ngx_http_proxy_headers_t *headers,
    ngx_keyval_t *default_headers);

static char *ngx_http_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_proxy_redirect(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_proxy_cookie_domain(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_proxy_cookie_path(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_proxy_cookie_flags(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_proxy_store(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
#if (NGX_HTTP_CACHE)
static char *ngx_http_proxy_cache(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_proxy_cache_key(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
#endif
#if (NGX_HTTP_SSL)
static char *ngx_http_proxy_ssl_certificate_cache(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_proxy_ssl_password_file(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
#endif

static char *ngx_http_proxy_lowat_check(ngx_conf_t *cf, void *post, void *data);
#if (NGX_HTTP_SSL)
static char *ngx_http_proxy_ssl_conf_command_check(ngx_conf_t *cf, void *post,
    void *data);
#endif

static ngx_int_t ngx_http_proxy_rewrite_regex(ngx_conf_t *cf,
    ngx_http_proxy_rewrite_t *pr, ngx_str_t *regex, ngx_uint_t caseless);

#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_proxy_merge_ssl(ngx_conf_t *cf,
    ngx_http_proxy_loc_conf_t *conf, ngx_http_proxy_loc_conf_t *prev);
static ngx_int_t ngx_http_proxy_set_ssl(ngx_conf_t *cf,
    ngx_http_proxy_loc_conf_t *plcf);
#if (NGX_HTTP_PROXY_MULTICERT)
static ngx_int_t ngx_http_proxy_compile_certificates(ngx_conf_t *cf,
    ngx_http_proxy_loc_conf_t *plcf);
#endif
#endif
static void ngx_http_proxy_set_vars(ngx_url_t *u, ngx_http_proxy_vars_t *v);

#if (NGX_HTTP_V3)

/* context for creating http/3 request */
typedef struct {
    /* calculated length of request */
    size_t                         n;

    /* encode method state */
    ngx_str_t                      method;

    /* encode path state */
    size_t                         loc_len;
    size_t                         uri_len;
    uintptr_t                      escape;
    ngx_uint_t                     unparsed_uri;

    /* encode headers state */
    size_t                         max_head;
    ngx_http_proxy_headers_t      *headers;
    ngx_http_script_engine_t       le;
    ngx_http_script_engine_t       e;

} ngx_http_v3_proxy_ctx_t;


static char *ngx_http_v3_proxy_host_key(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_v3_proxy_merge_quic(ngx_conf_t *cf,
    ngx_http_proxy_loc_conf_t *conf, ngx_http_proxy_loc_conf_t *prev);

static ngx_int_t ngx_http_v3_proxy_create_request(ngx_http_request_t *r);

static ngx_chain_t *ngx_http_v3_create_headers_frame(ngx_http_request_t *r,
    ngx_buf_t *hbuf);
static ngx_chain_t *ngx_http_v3_create_data_frame(ngx_http_request_t *r,
    ngx_chain_t *body, size_t size);
static ngx_inline ngx_uint_t ngx_http_v3_map_method(ngx_uint_t method);
static ngx_int_t ngx_http_v3_proxy_encode_method(ngx_http_request_t *r,
    ngx_http_v3_proxy_ctx_t *v3c, ngx_buf_t *b);
static ngx_int_t ngx_http_v3_proxy_encode_authority(ngx_http_request_t *r,
    ngx_http_v3_proxy_ctx_t *v3c, ngx_buf_t *b);
static ngx_int_t ngx_http_v3_proxy_encode_path(ngx_http_request_t *r,
    ngx_http_v3_proxy_ctx_t *v3c, ngx_buf_t *b);
static ngx_int_t ngx_http_v3_proxy_encode_headers(ngx_http_request_t *r,
    ngx_http_v3_proxy_ctx_t *v3c, ngx_buf_t *b);
static ngx_int_t ngx_http_v3_proxy_body_length(ngx_http_request_t *r,
    ngx_http_v3_proxy_ctx_t *v3c);
static ngx_chain_t *ngx_http_v3_proxy_encode_body(ngx_http_request_t *r,
    ngx_http_v3_proxy_ctx_t *v3c);
static ngx_int_t ngx_http_v3_proxy_body_output_filter(void *data,
    ngx_chain_t *in);

static ngx_int_t ngx_http_v3_proxy_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_v3_proxy_process_status_line(ngx_http_request_t *r);
static void ngx_http_v3_proxy_abort_request(ngx_http_request_t *r);
static void ngx_http_v3_proxy_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);
static ngx_int_t ngx_http_v3_proxy_process_header(ngx_http_request_t *r,
    ngx_str_t *name, ngx_str_t *value);

static ngx_int_t ngx_http_v3_proxy_headers_done(ngx_http_request_t *r);
static ngx_int_t ngx_http_v3_proxy_process_pseudo_header(ngx_http_request_t *r,
    ngx_str_t *name, ngx_str_t *value);
static ngx_int_t ngx_http_v3_proxy_input_filter_init(void *data);
static ngx_int_t ngx_http_v3_proxy_copy_filter(ngx_event_pipe_t *p,
    ngx_buf_t *buf);
static ngx_int_t ngx_http_v3_proxy_non_buffered_copy_filter(void *data,
    ssize_t bytes);
static ngx_int_t ngx_http_v3_proxy_construct_cookie_header(
    ngx_http_request_t *r);

static ngx_str_t  ngx_http_v3_proxy_quic_salt = ngx_string("ngx_quic");
#endif


static ngx_conf_post_t  ngx_http_proxy_lowat_post =
    { ngx_http_proxy_lowat_check };


static ngx_conf_bitmask_t  ngx_http_proxy_next_upstream_masks[] = {
    { ngx_string("error"), NGX_HTTP_UPSTREAM_FT_ERROR },
    { ngx_string("timeout"), NGX_HTTP_UPSTREAM_FT_TIMEOUT },
    { ngx_string("invalid_header"), NGX_HTTP_UPSTREAM_FT_INVALID_HEADER },
    { ngx_string("non_idempotent"), NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT },
    { ngx_string("http_500"), NGX_HTTP_UPSTREAM_FT_HTTP_500 },
    { ngx_string("http_502"), NGX_HTTP_UPSTREAM_FT_HTTP_502 },
    { ngx_string("http_503"), NGX_HTTP_UPSTREAM_FT_HTTP_503 },
    { ngx_string("http_504"), NGX_HTTP_UPSTREAM_FT_HTTP_504 },
    { ngx_string("http_403"), NGX_HTTP_UPSTREAM_FT_HTTP_403 },
    { ngx_string("http_404"), NGX_HTTP_UPSTREAM_FT_HTTP_404 },
    { ngx_string("http_429"), NGX_HTTP_UPSTREAM_FT_HTTP_429 },
    { ngx_string("updating"), NGX_HTTP_UPSTREAM_FT_UPDATING },
    { ngx_string("off"), NGX_HTTP_UPSTREAM_FT_OFF },
    { ngx_null_string, 0 }
};


#if (NGX_HTTP_SSL)

static ngx_conf_bitmask_t  ngx_http_proxy_ssl_protocols[] = {
    { ngx_string("SSLv2"), NGX_SSL_SSLv2 },
    { ngx_string("SSLv3"), NGX_SSL_SSLv3 },
    { ngx_string("TLSv1"), NGX_SSL_TLSv1 },
    { ngx_string("TLSv1.1"), NGX_SSL_TLSv1_1 },
    { ngx_string("TLSv1.2"), NGX_SSL_TLSv1_2 },
    { ngx_string("TLSv1.3"), NGX_SSL_TLSv1_3 },
    { ngx_null_string, 0 }
};

static ngx_conf_post_t  ngx_http_proxy_ssl_conf_command_post =
    { ngx_http_proxy_ssl_conf_command_check };

#endif


static ngx_conf_enum_t  ngx_http_proxy_http_version[] = {
    { ngx_string("1.0"), NGX_HTTP_VERSION_10 },
    { ngx_string("1.1"), NGX_HTTP_VERSION_11 },
    { ngx_string("3"), NGX_HTTP_VERSION_30 },
    { ngx_null_string, 0 }
};


ngx_module_t  ngx_http_proxy_module;


static ngx_command_t  ngx_http_proxy_commands[] = {

    { ngx_string("proxy_pass"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
      ngx_http_proxy_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("proxy_redirect"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_proxy_redirect,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("proxy_cookie_domain"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_proxy_cookie_domain,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("proxy_cookie_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_proxy_cookie_path,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("proxy_cookie_flags"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_http_proxy_cookie_flags,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("proxy_store"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_proxy_store,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("proxy_store_access"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
      ngx_conf_set_access_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.store_access),
      NULL },

    { ngx_string("proxy_buffering"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.buffering),
      NULL },

    { ngx_string("proxy_request_buffering"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.request_buffering),
      NULL },

    { ngx_string("proxy_ignore_client_abort"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.ignore_client_abort),
      NULL },

    { ngx_string("proxy_bind"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_upstream_bind_set_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.local),
      NULL },

    { ngx_string("proxy_socket_keepalive"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.socket_keepalive),
      NULL },

    { ngx_string("proxy_connect_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.connect_timeout),
      NULL },

    { ngx_string("proxy_send_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.send_timeout),
      NULL },

    { ngx_string("proxy_send_lowat"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.send_lowat),
      &ngx_http_proxy_lowat_post },

    { ngx_string("proxy_intercept_errors"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.intercept_errors),
      NULL },

    { ngx_string("proxy_set_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_keyval_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, headers_source),
      NULL },

    { ngx_string("proxy_headers_hash_max_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, headers_hash_max_size),
      NULL },

    { ngx_string("proxy_headers_hash_bucket_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, headers_hash_bucket_size),
      NULL },

    { ngx_string("proxy_set_body"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, body_source),
      NULL },

    { ngx_string("proxy_method"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, method),
      NULL },

    { ngx_string("proxy_pass_request_headers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.pass_request_headers),
      NULL },

    { ngx_string("proxy_pass_request_body"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.pass_request_body),
      NULL },

    { ngx_string("proxy_pass_trailers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.pass_trailers),
      NULL },

    { ngx_string("proxy_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.buffer_size),
      NULL },

    { ngx_string("proxy_read_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.read_timeout),
      NULL },

    { ngx_string("proxy_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_bufs_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.bufs),
      NULL },

    { ngx_string("proxy_busy_buffers_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.busy_buffers_size_conf),
      NULL },

    { ngx_string("proxy_force_ranges"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.force_ranges),
      NULL },

    { ngx_string("proxy_limit_rate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.limit_rate),
      NULL },

    { ngx_string("proxy_connection_drop"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_upstream_connection_drop_set_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.connection_drop),
      NULL },

#if (NGX_HTTP_CACHE)

    { ngx_string("proxy_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_proxy_cache,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("proxy_cache_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_proxy_cache_key,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("proxy_cache_path"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_2MORE,
      ngx_http_file_cache_set_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_proxy_main_conf_t, caches),
      &ngx_http_proxy_module },

    { ngx_string("proxy_cache_bypass"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_set_predicate_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.cache_bypass),
      NULL },

    { ngx_string("proxy_no_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_set_predicate_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.no_cache),
      NULL },

    { ngx_string("proxy_cache_valid"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_file_cache_valid_set_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.cache_valid),
      NULL },

    { ngx_string("proxy_cache_min_uses"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.cache_min_uses),
      NULL },

    { ngx_string("proxy_cache_max_range_offset"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_off_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.cache_max_range_offset),
      NULL },

    { ngx_string("proxy_cache_use_stale"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.cache_use_stale),
      &ngx_http_proxy_next_upstream_masks },

    { ngx_string("proxy_cache_methods"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.cache_methods),
      &ngx_http_upstream_cache_method_mask },

    { ngx_string("proxy_cache_lock"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.cache_lock),
      NULL },

    { ngx_string("proxy_cache_lock_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.cache_lock_timeout),
      NULL },

    { ngx_string("proxy_cache_lock_age"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.cache_lock_age),
      NULL },

    { ngx_string("proxy_cache_revalidate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.cache_revalidate),
      NULL },

    { ngx_string("proxy_cache_convert_head"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.cache_convert_head),
      NULL },

    { ngx_string("proxy_cache_background_update"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.cache_background_update),
      NULL },

#endif

    { ngx_string("proxy_temp_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_conf_set_path_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.temp_path),
      NULL },

    { ngx_string("proxy_max_temp_file_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.max_temp_file_size_conf),
      NULL },

    { ngx_string("proxy_temp_file_write_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.temp_file_write_size_conf),
      NULL },

    { ngx_string("proxy_next_upstream"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.next_upstream),
      &ngx_http_proxy_next_upstream_masks },

    { ngx_string("proxy_next_upstream_tries"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.next_upstream_tries),
      NULL },

    { ngx_string("proxy_next_upstream_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.next_upstream_timeout),
      NULL },

    { ngx_string("proxy_pass_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.pass_headers),
      NULL },

    { ngx_string("proxy_hide_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.hide_headers),
      NULL },

    { ngx_string("proxy_ignore_headers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.ignore_headers),
      &ngx_http_upstream_ignore_headers_masks },

    /* also allowed in all places where "proxy_pass" can happen */
    { ngx_string("proxy_http_version"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
      |NGX_HTTP_LIF_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, http_version),
      &ngx_http_proxy_http_version },

#if (NGX_HTTP_SSL)

    { ngx_string("proxy_ssl_session_reuse"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.ssl_session_reuse),
      NULL },

    { ngx_string("proxy_ssl_protocols"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, ssl_protocols),
      &ngx_http_proxy_ssl_protocols },

    { ngx_string("proxy_ssl_ciphers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, ssl_ciphers),
      NULL },

    { ngx_string("proxy_ssl_name"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.ssl_name),
      NULL },

    { ngx_string("proxy_ssl_server_name"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.ssl_server_name),
      NULL },

    { ngx_string("proxy_ssl_verify"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.ssl_verify),
      NULL },

    { ngx_string("proxy_ssl_verify_depth"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, ssl_verify_depth),
      NULL },

    { ngx_string("proxy_ssl_trusted_certificate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, ssl_trusted_certificate),
      NULL },

    { ngx_string("proxy_ssl_crl"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, ssl_crl),
      NULL },

#if (NGX_HTTP_PROXY_MULTICERT)

    { ngx_string("proxy_ssl_certificate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_ssl_certificate_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.ssl_certificates),
      NULL },

    { ngx_string("proxy_ssl_certificate_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_ssl_certificate_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.ssl_certificate_keys),
      NULL },

#else

    { ngx_string("proxy_ssl_certificate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_zero_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.ssl_certificate),
      NULL },

    { ngx_string("proxy_ssl_certificate_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_zero_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.ssl_certificate_key),
      NULL },

#endif

    { ngx_string("proxy_ssl_certificate_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
      ngx_http_proxy_ssl_certificate_cache,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("proxy_ssl_password_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_proxy_ssl_password_file,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("proxy_ssl_conf_command"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_keyval_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, ssl_conf_commands),
      &ngx_http_proxy_ssl_conf_command_post },

#if (NGX_HAVE_NTLS)
    { ngx_string("proxy_ssl_ntls"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.ssl_ntls),
      NULL },
#endif

#endif

#if (NGX_HTTP_V3)

    { ngx_string("proxy_http3_max_concurrent_streams"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t,
               upstream.h3_settings.max_concurrent_streams),
      NULL },

    { ngx_string("proxy_http3_stream_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.quic.stream_buffer_size),
      NULL },

    { ngx_string("proxy_quic_gso"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.quic.gso_enabled),
      NULL },

    { ngx_string("proxy_quic_host_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_v3_proxy_host_key,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("proxy_quic_active_connection_id_limit"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t,
               upstream.quic.active_connection_id_limit),
      NULL },

    { ngx_string("proxy_http3_hq"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, enable_hq),
      NULL },

    { ngx_string("proxy_http3_max_table_capacity"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t,
               upstream.h3_settings.max_table_capacity),
      NULL },

#endif

      ngx_null_command
};


static ngx_http_module_t  ngx_http_proxy_module_ctx = {
    ngx_http_proxy_add_variables,          /* preconfiguration */
    NULL,                                  /* postconfiguration */

    ngx_http_proxy_create_main_conf,       /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_proxy_create_loc_conf,        /* create location configuration */
    ngx_http_proxy_merge_loc_conf          /* merge location configuration */
};


ngx_module_t  ngx_http_proxy_module = {
    NGX_MODULE_V1,
    &ngx_http_proxy_module_ctx,            /* module context */
    ngx_http_proxy_commands,               /* module directives */
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


static char  ngx_http_proxy_version[] = " HTTP/1.0" CRLF;
static char  ngx_http_proxy_version_11[] = " HTTP/1.1" CRLF;


static ngx_keyval_t  ngx_http_proxy_headers[] = {
    { ngx_string("Host"), ngx_string("$proxy_host") },
    { ngx_string("Connection"), ngx_string("close") },
    { ngx_string("Content-Length"), ngx_string("$proxy_internal_body_length") },
    { ngx_string("Transfer-Encoding"), ngx_string("$proxy_internal_chunked") },
    { ngx_string("TE"), ngx_string("") },
    { ngx_string("Keep-Alive"), ngx_string("") },
    { ngx_string("Expect"), ngx_string("") },
    { ngx_string("Upgrade"), ngx_string("") },
    { ngx_null_string, ngx_null_string }
};


#if (NGX_HTTP_V3)

/*
 * RFC 9114  4.2 HTTP Fields
 *
 * An intermediary transforming an HTTP/1.x message to HTTP/3 MUST remove
 * connection-specific header fields as discussed in Section 7.6.1 of [HTTP],
 * or their messages will be treated by other HTTP/3 endpoints as malformed.
 */
static ngx_keyval_t  ngx_http_v3_proxy_headers[] = {
    { ngx_string("Content-Length"), ngx_string("$proxy_internal_body_length") },
#if 0
    /* TODO: trailers */
    { ngx_string("TE"), ngx_string("$v3_proxy_internal_trailers") },
#endif
    { ngx_string("Host"), ngx_string("") },
    { ngx_string("Connection"), ngx_string("") },
    { ngx_string("Transfer-Encoding"), ngx_string("") },
    { ngx_string("Keep-Alive"), ngx_string("") },
    { ngx_string("Expect"), ngx_string("") },
    { ngx_string("Upgrade"), ngx_string("") },
    { ngx_null_string, ngx_null_string }
};

#if (NGX_HTTP_CACHE)

static ngx_keyval_t  ngx_http_v3_proxy_cache_headers[] = {
    { ngx_string("Host"), ngx_string("") },
    { ngx_string("Connection"), ngx_string("") },
    { ngx_string("Content-Length"), ngx_string("$proxy_internal_body_length") },
    { ngx_string("Transfer-Encoding"), ngx_string("") },
    { ngx_string("TE"), ngx_string("") },
    { ngx_string("Keep-Alive"), ngx_string("") },
    { ngx_string("Expect"), ngx_string("") },
    { ngx_string("Upgrade"), ngx_string("") },
    { ngx_string("If-Modified-Since"),
      ngx_string("$upstream_cache_last_modified") },
    { ngx_string("If-Unmodified-Since"), ngx_string("") },
    { ngx_string("If-None-Match"), ngx_string("$upstream_cache_etag") },
    { ngx_string("If-Match"), ngx_string("") },
    { ngx_string("Range"), ngx_string("") },
    { ngx_string("If-Range"), ngx_string("") },
    { ngx_null_string, ngx_null_string }
};

#endif

#endif


static ngx_str_t  ngx_http_proxy_hide_headers[] = {
    ngx_string("Date"),
    ngx_string("Server"),
    ngx_string("X-Pad"),
    ngx_string("X-Accel-Expires"),
    ngx_string("X-Accel-Redirect"),
    ngx_string("X-Accel-Limit-Rate"),
    ngx_string("X-Accel-Buffering"),
    ngx_string("X-Accel-Charset"),
    ngx_null_string
};


#if (NGX_HTTP_CACHE)

static ngx_keyval_t  ngx_http_proxy_cache_headers[] = {
    { ngx_string("Host"), ngx_string("$proxy_host") },
    { ngx_string("Connection"), ngx_string("close") },
    { ngx_string("Content-Length"), ngx_string("$proxy_internal_body_length") },
    { ngx_string("Transfer-Encoding"), ngx_string("$proxy_internal_chunked") },
    { ngx_string("TE"), ngx_string("") },
    { ngx_string("Keep-Alive"), ngx_string("") },
    { ngx_string("Expect"), ngx_string("") },
    { ngx_string("Upgrade"), ngx_string("") },
    { ngx_string("If-Modified-Since"),
      ngx_string("$upstream_cache_last_modified") },
    { ngx_string("If-Unmodified-Since"), ngx_string("") },
    { ngx_string("If-None-Match"), ngx_string("$upstream_cache_etag") },
    { ngx_string("If-Match"), ngx_string("") },
    { ngx_string("Range"), ngx_string("") },
    { ngx_string("If-Range"), ngx_string("") },
    { ngx_null_string, ngx_null_string }
};

#endif


static ngx_http_variable_t  ngx_http_proxy_vars[] = {

    { ngx_string("proxy_host"), NULL, ngx_http_proxy_host_variable, 0,
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("proxy_port"), NULL, ngx_http_proxy_port_variable, 0,
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("proxy_add_x_forwarded_for"), NULL,
      ngx_http_proxy_add_x_forwarded_for_variable, 0, NGX_HTTP_VAR_NOHASH, 0 },

#if 0
    { ngx_string("proxy_add_via"), NULL, NULL, 0, NGX_HTTP_VAR_NOHASH, 0 },
#endif

    { ngx_string("proxy_internal_body_length"), NULL,
      ngx_http_proxy_internal_body_length_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("proxy_internal_chunked"), NULL,
      ngx_http_proxy_internal_chunked_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

      ngx_http_null_variable
};


static ngx_path_init_t  ngx_http_proxy_temp_path = {
    ngx_string(NGX_HTTP_PROXY_TEMP_PATH), { 1, 2, 0 }
};


static ngx_conf_bitmask_t  ngx_http_proxy_cookie_flags_masks[] = {

    { ngx_string("secure"),
      NGX_HTTP_PROXY_COOKIE_SECURE|NGX_HTTP_PROXY_COOKIE_SECURE_ON },

    { ngx_string("nosecure"),
      NGX_HTTP_PROXY_COOKIE_SECURE|NGX_HTTP_PROXY_COOKIE_SECURE_OFF },

    { ngx_string("httponly"),
      NGX_HTTP_PROXY_COOKIE_HTTPONLY|NGX_HTTP_PROXY_COOKIE_HTTPONLY_ON },

    { ngx_string("nohttponly"),
      NGX_HTTP_PROXY_COOKIE_HTTPONLY|NGX_HTTP_PROXY_COOKIE_HTTPONLY_OFF },

    { ngx_string("samesite=strict"),
      NGX_HTTP_PROXY_COOKIE_SAMESITE|NGX_HTTP_PROXY_COOKIE_SAMESITE_STRICT },

    { ngx_string("samesite=lax"),
      NGX_HTTP_PROXY_COOKIE_SAMESITE|NGX_HTTP_PROXY_COOKIE_SAMESITE_LAX },

    { ngx_string("samesite=none"),
      NGX_HTTP_PROXY_COOKIE_SAMESITE|NGX_HTTP_PROXY_COOKIE_SAMESITE_NONE },

    { ngx_string("nosamesite"),
      NGX_HTTP_PROXY_COOKIE_SAMESITE|NGX_HTTP_PROXY_COOKIE_SAMESITE_OFF },

    { ngx_null_string, 0 }
};


static ngx_int_t
ngx_http_proxy_handler(ngx_http_request_t *r)
{
    ngx_int_t                    rc;
    ngx_http_upstream_t         *u;
    ngx_http_proxy_ctx_t        *ctx;
    ngx_http_proxy_loc_conf_t   *plcf;
#if (NGX_HTTP_CACHE)
    ngx_http_proxy_main_conf_t  *pmcf;
#endif

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_proxy_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_proxy_module);

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    u = r->upstream;

    if (plcf->proxy_lengths == NULL) {
#if (NGX_HTTP_V3)
        ctx->host = plcf->host;
#endif
        ctx->vars = plcf->vars;
        u->schema = plcf->vars.schema;
#if (NGX_HTTP_SSL)
        u->ssl = plcf->ssl;
#endif

    } else {
        if (ngx_http_proxy_eval(r, ctx, plcf) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    u->output.tag = (ngx_buf_tag_t) &ngx_http_proxy_module;

    u->conf = &plcf->upstream;

#if (NGX_HTTP_CACHE)
    pmcf = ngx_http_get_module_main_conf(r, ngx_http_proxy_module);

    u->caches = &pmcf->caches;
    u->create_key = ngx_http_proxy_create_key;
#endif

    u->create_request = ngx_http_proxy_create_request;
    u->reinit_request = ngx_http_proxy_reinit_request;
    u->process_header = ngx_http_proxy_process_status_line;
    u->abort_request = ngx_http_proxy_abort_request;
    u->finalize_request = ngx_http_proxy_finalize_request;

#if (NGX_HTTP_V3)
    if (plcf->http_version == NGX_HTTP_VERSION_30) {

        u->h3 = 1;
        u->peer.type = SOCK_DGRAM;

        if (plcf->enable_hq) {
            u->hq = 1;

        } else {
            u->create_request = ngx_http_v3_proxy_create_request;
            u->reinit_request = ngx_http_v3_proxy_reinit_request;
            u->process_header = ngx_http_v3_proxy_process_status_line;
            u->abort_request = ngx_http_v3_proxy_abort_request;
            u->finalize_request = ngx_http_v3_proxy_finalize_request;
        }

        ctx->v3_parse = ngx_pcalloc(r->pool, sizeof(ngx_http_v3_parse_t));
        if (ctx->v3_parse == NULL) {
            return NGX_ERROR;
        }
    }
#endif

    r->state = 0;

    if (plcf->redirects) {
        u->rewrite_redirect = ngx_http_proxy_rewrite_redirect;
    }

    if (plcf->cookie_domains || plcf->cookie_paths || plcf->cookie_flags) {
        u->rewrite_cookie = ngx_http_proxy_rewrite_cookie;
    }

    u->buffering = plcf->upstream.buffering;

    u->pipe = ngx_pcalloc(r->pool, sizeof(ngx_event_pipe_t));
    if (u->pipe == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u->pipe->input_filter = ngx_http_proxy_copy_filter;

    u->input_filter_init = ngx_http_proxy_input_filter_init;
    u->input_filter = ngx_http_proxy_non_buffered_copy_filter;

#if (NGX_HTTP_V3)
    if (plcf->http_version == NGX_HTTP_VERSION_30 && !plcf->enable_hq) {
        u->pipe->input_filter = ngx_http_v3_proxy_copy_filter;

        u->input_filter_init = ngx_http_v3_proxy_input_filter_init;
        u->input_filter = ngx_http_v3_proxy_non_buffered_copy_filter;
    }
#endif

    u->pipe->input_ctx = r;
    u->input_filter_ctx = r;

    u->accel = 1;

    if (!plcf->upstream.request_buffering
        && plcf->body_values == NULL && plcf->upstream.pass_request_body
        && (!r->headers_in.chunked
            || (plcf->http_version == NGX_HTTP_VERSION_11
#if (NGX_HTTP_V3)
                || plcf->http_version == NGX_HTTP_VERSION_30
#endif
           )))
    {
        r->request_body_no_buffering = 1;
    }

    rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static ngx_int_t
ngx_http_proxy_eval(ngx_http_request_t *r, ngx_http_proxy_ctx_t *ctx,
    ngx_http_proxy_loc_conf_t *plcf)
{
    u_char               *p;
    size_t                add;
    u_short               port;
    ngx_str_t             proxy;
    ngx_url_t             url;
    ngx_http_upstream_t  *u;

    if (ngx_http_script_run(r, &proxy, plcf->proxy_lengths->elts, 0,
                            plcf->proxy_values->elts)
        == NULL)
    {
        return NGX_ERROR;
    }

    if (proxy.len > 7
        && ngx_strncasecmp(proxy.data, (u_char *) "http://", 7) == 0)
    {
        add = 7;
        port = 80;
#if (NGX_HTTP_V3)
        if (plcf->http_version == NGX_HTTP_VERSION_30) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "http/3 requires https prefix");
            return NGX_ERROR;
        }
#endif

#if (NGX_HTTP_SSL)

    } else if (proxy.len > 8
               && ngx_strncasecmp(proxy.data, (u_char *) "https://", 8) == 0)
    {
        add = 8;
        port = 443;
        r->upstream->ssl = 1;

#endif

    } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "invalid URL prefix in \"%V\"", &proxy);
        return NGX_ERROR;
    }

    u = r->upstream;

    u->schema.len = add;
    u->schema.data = proxy.data;

    ngx_memzero(&url, sizeof(ngx_url_t));

    url.url.len = proxy.len - add;
    url.url.data = proxy.data + add;
    url.default_port = port;
    url.uri_part = 1;
    url.no_resolve = 1;

    if (ngx_parse_url(r->pool, &url) != NGX_OK) {
        if (url.err) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "%s in upstream \"%V\"", url.err, &url.url);
        }

        return NGX_ERROR;
    }

    if (url.uri.len) {
        if (url.uri.data[0] == '?') {
            p = ngx_pnalloc(r->pool, url.uri.len + 1);
            if (p == NULL) {
                return NGX_ERROR;
            }

            *p++ = '/';
            ngx_memcpy(p, url.uri.data, url.uri.len);

            url.uri.len++;
            url.uri.data = p - 1;
        }
    }

    ctx->vars.key_start = u->schema;

    ngx_http_proxy_set_vars(&url, &ctx->vars);

    u->resolved = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
    if (u->resolved == NULL) {
        return NGX_ERROR;
    }

    if (url.addrs) {
        u->resolved->sockaddr = url.addrs[0].sockaddr;
        u->resolved->socklen = url.addrs[0].socklen;
        u->resolved->name = url.addrs[0].name;
        u->resolved->naddrs = 1;
    }

    u->resolved->host = url.host;
    u->resolved->port = (in_port_t) (url.no_port ? port : url.port);
    u->resolved->no_port = url.no_port;

#if (NGX_HTTP_V3)
    if (url.family != AF_UNIX) {

        if (url.no_port) {
            ctx->host = url.host;

        } else {
            ctx->host.len = url.host.len + 1 + url.port_text.len;
            ctx->host.data = url.host.data;
        }

    } else {
        ngx_str_set(&ctx->host, "localhost");
    }
#endif

    return NGX_OK;
}


#if (NGX_HTTP_CACHE)

static ngx_int_t
ngx_http_proxy_create_key(ngx_http_request_t *r)
{
    size_t                      len, loc_len;
    u_char                     *p;
    uintptr_t                   escape;
    ngx_str_t                  *key;
    ngx_http_upstream_t        *u;
    ngx_http_proxy_ctx_t       *ctx;
    ngx_http_proxy_loc_conf_t  *plcf;

    u = r->upstream;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    key = ngx_array_push(&r->cache->keys);
    if (key == NULL) {
        return NGX_ERROR;
    }

    if (plcf->cache_key.value.data) {

        if (ngx_http_complex_value(r, &plcf->cache_key, key) != NGX_OK) {
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    *key = ctx->vars.key_start;

    key = ngx_array_push(&r->cache->keys);
    if (key == NULL) {
        return NGX_ERROR;
    }

    if (plcf->proxy_lengths && ctx->vars.uri.len) {

        *key = ctx->vars.uri;
        u->uri = ctx->vars.uri;

        return NGX_OK;

    } else if (ctx->vars.uri.len == 0 && r->valid_unparsed_uri) {
        *key = r->unparsed_uri;
        u->uri = r->unparsed_uri;

        return NGX_OK;
    }

    loc_len = (r->valid_location && ctx->vars.uri.len) ? plcf->location.len : 0;

    if (r->quoted_uri || r->internal) {
        escape = 2 * ngx_escape_uri(NULL, r->uri.data + loc_len,
                                    r->uri.len - loc_len, NGX_ESCAPE_URI);
    } else {
        escape = 0;
    }

    len = ctx->vars.uri.len + r->uri.len - loc_len + escape
          + sizeof("?") - 1 + r->args.len;

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    key->data = p;

    if (r->valid_location) {
        p = ngx_copy(p, ctx->vars.uri.data, ctx->vars.uri.len);
    }

    if (escape) {
        ngx_escape_uri(p, r->uri.data + loc_len,
                       r->uri.len - loc_len, NGX_ESCAPE_URI);
        p += r->uri.len - loc_len + escape;

    } else {
        p = ngx_copy(p, r->uri.data + loc_len, r->uri.len - loc_len);
    }

    if (r->args.len > 0) {
        *p++ = '?';
        p = ngx_copy(p, r->args.data, r->args.len);
    }

    key->len = p - key->data;
    u->uri = *key;

    return NGX_OK;
}

#endif


static ngx_int_t
ngx_http_proxy_create_request(ngx_http_request_t *r)
{
    size_t                        len, uri_len, loc_len, body_len,
                                  key_len, val_len;
    uintptr_t                     escape;
    ngx_buf_t                    *b;
    ngx_str_t                     method;
    ngx_uint_t                    i, unparsed_uri;
    ngx_chain_t                  *cl, *body;
    ngx_list_part_t              *part;
    ngx_table_elt_t              *header;
    ngx_http_upstream_t          *u;
    ngx_http_proxy_ctx_t         *ctx;
    ngx_http_script_code_pt       code;
    ngx_http_proxy_headers_t     *headers;
    ngx_http_script_engine_t      e, le;
    ngx_http_proxy_loc_conf_t    *plcf;
    ngx_http_script_len_code_pt   lcode;

    u = r->upstream;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

#if (NGX_HTTP_CACHE)
    headers = u->cacheable ? &plcf->headers_cache : &plcf->headers;
#else
    headers = &plcf->headers;
#endif

    if (u->method.len) {
        /* HEAD was changed to GET to cache response */
        method = u->method;

    } else if (plcf->method) {
        if (ngx_http_complex_value(r, plcf->method, &method) != NGX_OK) {
            return NGX_ERROR;
        }

    } else {
        method = r->method_name;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (method.len == 4
        && ngx_strncasecmp(method.data, (u_char *) "HEAD", 4) == 0)
    {
        ctx->head = 1;
    }

    len = method.len + 1 + sizeof(ngx_http_proxy_version) - 1
          + sizeof(CRLF) - 1;

    escape = 0;
    loc_len = 0;
    unparsed_uri = 0;

    if (plcf->proxy_lengths && ctx->vars.uri.len) {
        uri_len = ctx->vars.uri.len;

    } else if (ctx->vars.uri.len == 0 && r->valid_unparsed_uri) {
        unparsed_uri = 1;
        uri_len = r->unparsed_uri.len;

    } else {
        loc_len = (r->valid_location && ctx->vars.uri.len) ?
                      plcf->location.len : 0;

        if (r->quoted_uri || r->internal) {
            escape = 2 * ngx_escape_uri(NULL, r->uri.data + loc_len,
                                        r->uri.len - loc_len, NGX_ESCAPE_URI);
        }

        uri_len = ctx->vars.uri.len + r->uri.len - loc_len + escape
                  + sizeof("?") - 1 + r->args.len;
    }

    if (uri_len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "zero length URI to proxy");
        return NGX_ERROR;
    }

    len += uri_len;

    ngx_memzero(&le, sizeof(ngx_http_script_engine_t));

    ngx_http_script_flush_no_cacheable_variables(r, plcf->body_flushes);
    ngx_http_script_flush_no_cacheable_variables(r, headers->flushes);

    if (plcf->body_lengths) {
        le.ip = plcf->body_lengths->elts;
        le.request = r;
        le.flushed = 1;
        body_len = 0;

        while (*(uintptr_t *) le.ip) {
            lcode = *(ngx_http_script_len_code_pt *) le.ip;
            body_len += lcode(&le);
        }

        ctx->internal_body_length = body_len;
        len += body_len;

    } else if (r->headers_in.chunked && r->reading_body) {
        ctx->internal_body_length = -1;
        ctx->internal_chunked = 1;

    } else {
        ctx->internal_body_length = r->headers_in.content_length_n;
    }

    le.ip = headers->lengths->elts;
    le.request = r;
    le.flushed = 1;

    while (*(uintptr_t *) le.ip) {

        lcode = *(ngx_http_script_len_code_pt *) le.ip;
        key_len = lcode(&le);

        for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
            lcode = *(ngx_http_script_len_code_pt *) le.ip;
        }
        le.ip += sizeof(uintptr_t);

        if (val_len == 0) {
            continue;
        }

        len += key_len + sizeof(": ") - 1 + val_len + sizeof(CRLF) - 1;
    }


    if (plcf->upstream.pass_request_headers) {
        part = &r->headers_in.headers.part;
        header = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if (ngx_hash_find(&headers->hash, header[i].hash,
                              header[i].lowcase_key, header[i].key.len))
            {
                continue;
            }

            len += header[i].key.len + sizeof(": ") - 1
                + header[i].value.len + sizeof(CRLF) - 1;
        }
    }


    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;


    /* the request line */

    b->last = ngx_copy(b->last, method.data, method.len);
    *b->last++ = ' ';

    u->uri.data = b->last;

    if (plcf->proxy_lengths && ctx->vars.uri.len) {
        b->last = ngx_copy(b->last, ctx->vars.uri.data, ctx->vars.uri.len);

    } else if (unparsed_uri) {
        b->last = ngx_copy(b->last, r->unparsed_uri.data, r->unparsed_uri.len);

    } else {
        if (r->valid_location) {
            b->last = ngx_copy(b->last, ctx->vars.uri.data, ctx->vars.uri.len);
        }

        if (escape) {
            ngx_escape_uri(b->last, r->uri.data + loc_len,
                           r->uri.len - loc_len, NGX_ESCAPE_URI);
            b->last += r->uri.len - loc_len + escape;

        } else {
            b->last = ngx_copy(b->last, r->uri.data + loc_len,
                               r->uri.len - loc_len);
        }

        if (r->args.len > 0) {
            *b->last++ = '?';
            b->last = ngx_copy(b->last, r->args.data, r->args.len);
        }
    }

    u->uri.len = b->last - u->uri.data;

#if (NGX_HTTP_V3)
    if (plcf->http_version == NGX_HTTP_VERSION_30 && plcf->enable_hq) {
        goto nover;
    }
#endif

    if (plcf->http_version == NGX_HTTP_VERSION_11) {
        b->last = ngx_cpymem(b->last, ngx_http_proxy_version_11,
                             sizeof(ngx_http_proxy_version_11) - 1);

    } else {
        b->last = ngx_cpymem(b->last, ngx_http_proxy_version,
                             sizeof(ngx_http_proxy_version) - 1);
    }

#if (NGX_HTTP_V3)
nover:
#endif

    ngx_memzero(&e, sizeof(ngx_http_script_engine_t));

    e.ip = headers->values->elts;
    e.pos = b->last;
    e.request = r;
    e.flushed = 1;

    le.ip = headers->lengths->elts;

    while (*(uintptr_t *) le.ip) {

        lcode = *(ngx_http_script_len_code_pt *) le.ip;
        (void) lcode(&le);

        for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
            lcode = *(ngx_http_script_len_code_pt *) le.ip;
        }
        le.ip += sizeof(uintptr_t);

        if (val_len == 0) {
            e.skip = 1;

            while (*(uintptr_t *) e.ip) {
                code = *(ngx_http_script_code_pt *) e.ip;
                code((ngx_http_script_engine_t *) &e);
            }
            e.ip += sizeof(uintptr_t);

            e.skip = 0;

            continue;
        }

        code = *(ngx_http_script_code_pt *) e.ip;
        code((ngx_http_script_engine_t *) &e);

        *e.pos++ = ':'; *e.pos++ = ' ';

        while (*(uintptr_t *) e.ip) {
            code = *(ngx_http_script_code_pt *) e.ip;
            code((ngx_http_script_engine_t *) &e);
        }
        e.ip += sizeof(uintptr_t);

        *e.pos++ = CR; *e.pos++ = LF;
    }

    b->last = e.pos;


    if (plcf->upstream.pass_request_headers) {
        part = &r->headers_in.headers.part;
        header = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if (ngx_hash_find(&headers->hash, header[i].hash,
                              header[i].lowcase_key, header[i].key.len))
            {
                continue;
            }

            b->last = ngx_copy(b->last, header[i].key.data, header[i].key.len);

            *b->last++ = ':'; *b->last++ = ' ';

            b->last = ngx_copy(b->last, header[i].value.data,
                               header[i].value.len);

            *b->last++ = CR; *b->last++ = LF;

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy header: \"%V: %V\"",
                           &header[i].key, &header[i].value);
        }
    }


    /* add "\r\n" at the header end */
    *b->last++ = CR; *b->last++ = LF;

    if (plcf->body_values) {
        e.ip = plcf->body_values->elts;
        e.pos = b->last;
        e.skip = 0;

        while (*(uintptr_t *) e.ip) {
            code = *(ngx_http_script_code_pt *) e.ip;
            code((ngx_http_script_engine_t *) &e);
        }

        b->last = e.pos;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy header:%N\"%*s\"",
                   (size_t) (b->last - b->pos), b->pos);

    if (r->request_body_no_buffering) {

        u->request_bufs = cl;

        if (ctx->internal_chunked) {
            u->output.output_filter = ngx_http_proxy_body_output_filter;
            u->output.filter_ctx = r;
        }

    } else if (plcf->body_values == NULL && plcf->upstream.pass_request_body) {

        body = u->request_bufs;
        u->request_bufs = cl;

        while (body) {
            b = ngx_alloc_buf(r->pool);
            if (b == NULL) {
                return NGX_ERROR;
            }

            ngx_memcpy(b, body->buf, sizeof(ngx_buf_t));

            cl->next = ngx_alloc_chain_link(r->pool);
            if (cl->next == NULL) {
                return NGX_ERROR;
            }

            cl = cl->next;
            cl->buf = b;

            body = body->next;
        }

    } else {
        u->request_bufs = cl;
    }

    b->flush = 1;
    cl->next = NULL;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_reinit_request(ngx_http_request_t *r)
{
    ngx_http_proxy_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (ctx == NULL) {
        return NGX_OK;
    }

    ctx->status.code = 0;
    ctx->status.count = 0;
    ctx->status.start = NULL;
    ctx->status.end = NULL;
    ctx->chunked.state = 0;

    r->upstream->process_header = ngx_http_proxy_process_status_line;
    r->upstream->pipe->input_filter = ngx_http_proxy_copy_filter;
    r->upstream->input_filter = ngx_http_proxy_non_buffered_copy_filter;
    r->state = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_body_output_filter(void *data, ngx_chain_t *in)
{
    ngx_http_request_t  *r = data;

    off_t                  size;
    u_char                *chunk;
    ngx_int_t              rc;
    ngx_buf_t             *b;
    ngx_chain_t           *out, *cl, *tl, **ll, **fl;
    ngx_http_proxy_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "proxy output filter");

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (in == NULL) {
        out = in;
        goto out;
    }

    out = NULL;
    ll = &out;

    if (!ctx->header_sent) {
        /* first buffer contains headers, pass it unmodified */

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "proxy output header");

        ctx->header_sent = 1;

        tl = ngx_alloc_chain_link(r->pool);
        if (tl == NULL) {
            return NGX_ERROR;
        }

        tl->buf = in->buf;
        *ll = tl;
        ll = &tl->next;

        in = in->next;

        if (in == NULL) {
            tl->next = NULL;
            goto out;
        }
    }

    size = 0;
    cl = in;
    fl = ll;

    for ( ;; ) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "proxy output chunk: %O", ngx_buf_size(cl->buf));

        size += ngx_buf_size(cl->buf);

        if (cl->buf->flush
            || cl->buf->sync
            || ngx_buf_in_memory(cl->buf)
            || cl->buf->in_file)
        {
            tl = ngx_alloc_chain_link(r->pool);
            if (tl == NULL) {
                return NGX_ERROR;
            }

            tl->buf = cl->buf;
            *ll = tl;
            ll = &tl->next;
        }

        if (cl->next == NULL) {
            break;
        }

        cl = cl->next;
    }

    if (size) {
        tl = ngx_chain_get_free_buf(r->pool, &ctx->free);
        if (tl == NULL) {
            return NGX_ERROR;
        }

        b = tl->buf;
        chunk = b->start;

        if (chunk == NULL) {
            /* the "0000000000000000" is 64-bit hexadecimal string */

            chunk = ngx_palloc(r->pool, sizeof("0000000000000000" CRLF) - 1);
            if (chunk == NULL) {
                return NGX_ERROR;
            }

            b->start = chunk;
            b->end = chunk + sizeof("0000000000000000" CRLF) - 1;
        }

        b->tag = (ngx_buf_tag_t) &ngx_http_proxy_body_output_filter;
        b->memory = 0;
        b->temporary = 1;
        b->pos = chunk;
        b->last = ngx_sprintf(chunk, "%xO" CRLF, size);

        tl->next = *fl;
        *fl = tl;
    }

    if (cl->buf->last_buf) {
        tl = ngx_chain_get_free_buf(r->pool, &ctx->free);
        if (tl == NULL) {
            return NGX_ERROR;
        }

        b = tl->buf;

        b->tag = (ngx_buf_tag_t) &ngx_http_proxy_body_output_filter;
        b->temporary = 0;
        b->memory = 1;
        b->last_buf = 1;
        b->pos = (u_char *) CRLF "0" CRLF CRLF;
        b->last = b->pos + 7;

        cl->buf->last_buf = 0;

        *ll = tl;

        if (size == 0) {
            b->pos += 2;
        }

    } else if (size > 0) {
        tl = ngx_chain_get_free_buf(r->pool, &ctx->free);
        if (tl == NULL) {
            return NGX_ERROR;
        }

        b = tl->buf;

        b->tag = (ngx_buf_tag_t) &ngx_http_proxy_body_output_filter;
        b->temporary = 0;
        b->memory = 1;
        b->pos = (u_char *) CRLF;
        b->last = b->pos + 2;

        *ll = tl;

    } else {
        *ll = NULL;
    }

out:

    rc = ngx_chain_writer(&r->upstream->writer, out);

    ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
                            (ngx_buf_tag_t) &ngx_http_proxy_body_output_filter);

    return rc;
}


static ngx_int_t
ngx_http_proxy_process_status_line(ngx_http_request_t *r)
{
    size_t                 len;
    ngx_int_t              rc;
    ngx_http_upstream_t   *u;
    ngx_http_proxy_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    u = r->upstream;

    rc = ngx_http_parse_status_line(r, &u->buffer, &ctx->status);

    if (rc == NGX_AGAIN) {
        return rc;
    }

    if (rc == NGX_ERROR) {

#if (NGX_HTTP_CACHE)

        if (r->cache) {
            r->http_version = NGX_HTTP_VERSION_9;
            return NGX_OK;
        }

#endif

#if (NGX_HTTP_V3)
        {

        ngx_http_proxy_loc_conf_t  *plcf;

        plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

        if (plcf->http_version == NGX_HTTP_VERSION_30 && plcf->enable_hq) {
            r->http_version = NGX_HTTP_VERSION_9;
            u->state->status = NGX_HTTP_OK;
            u->headers_in.connection_close = 1;

            return NGX_OK;
        }

        }
#endif

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent no valid HTTP/1.0 header");

#if 0
        if (u->accel) {
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }
#endif

        r->http_version = NGX_HTTP_VERSION_9;
        u->state->status = NGX_HTTP_OK;
        u->headers_in.connection_close = 1;

        return NGX_OK;
    }

    if (u->state && u->state->status == 0) {
        u->state->status = ctx->status.code;
    }

    u->headers_in.status_n = ctx->status.code;

    len = ctx->status.end - ctx->status.start;
    u->headers_in.status_line.len = len;

    u->headers_in.status_line.data = ngx_pnalloc(r->pool, len);
    if (u->headers_in.status_line.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(u->headers_in.status_line.data, ctx->status.start, len);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy status %ui \"%V\"",
                   u->headers_in.status_n, &u->headers_in.status_line);

    if (ctx->status.http_version < NGX_HTTP_VERSION_11) {
        u->headers_in.connection_close = 1;
    }

    u->process_header = ngx_http_proxy_process_header;

    return ngx_http_proxy_process_header(r);
}


static ngx_int_t
ngx_http_proxy_process_header(ngx_http_request_t *r)
{
    ngx_int_t                       rc;
    ngx_table_elt_t                *h;
    ngx_http_upstream_t            *u;
    ngx_http_proxy_ctx_t           *ctx;
    ngx_http_upstream_header_t     *hh;
    ngx_http_upstream_main_conf_t  *umcf;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    for ( ;; ) {

        rc = ngx_http_parse_header_line(r, &r->upstream->buffer, 1);

        if (rc == NGX_OK) {

            /* a header line has been parsed successfully */

            h = ngx_list_push(&r->upstream->headers_in.headers);
            if (h == NULL) {
                return NGX_ERROR;
            }

            h->hash = r->header_hash;

            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;

            h->key.data = ngx_pnalloc(r->pool,
                               h->key.len + 1 + h->value.len + 1 + h->key.len);
            if (h->key.data == NULL) {
                h->hash = 0;
                return NGX_ERROR;
            }

            h->value.data = h->key.data + h->key.len + 1;
            h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;

            ngx_memcpy(h->key.data, r->header_name_start, h->key.len);
            h->key.data[h->key.len] = '\0';
            ngx_memcpy(h->value.data, r->header_start, h->value.len);
            h->value.data[h->value.len] = '\0';

            if (h->key.len == r->lowcase_index) {
                ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);

            } else {
                ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
                               h->lowcase_key, h->key.len);

            if (hh) {
                rc = hh->handler(r, h, hh->offset);

                if (rc != NGX_OK) {
                    return rc;
                }
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy header: \"%V: %V\"",
                           &h->key, &h->value);

            continue;
        }

        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy header done");

            /*
             * if no "Server" and "Date" in header line,
             * then add the special empty headers
             */

            if (r->upstream->headers_in.server == NULL) {
                h = ngx_list_push(&r->upstream->headers_in.headers);
                if (h == NULL) {
                    return NGX_ERROR;
                }

                h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(
                                    ngx_hash('s', 'e'), 'r'), 'v'), 'e'), 'r');

                ngx_str_set(&h->key, "Server");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char *) "server";
                h->next = NULL;
            }

            if (r->upstream->headers_in.date == NULL) {
                h = ngx_list_push(&r->upstream->headers_in.headers);
                if (h == NULL) {
                    return NGX_ERROR;
                }

                h->hash = ngx_hash(ngx_hash(ngx_hash('d', 'a'), 't'), 'e');

                ngx_str_set(&h->key, "Date");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char *) "date";
                h->next = NULL;
            }

            /* clear content length if response is chunked */

            u = r->upstream;

            if (u->headers_in.chunked) {
                u->headers_in.content_length_n = -1;
            }

            /*
             * set u->keepalive if response has no body; this allows to keep
             * connections alive in case of r->header_only or X-Accel-Redirect
             */

            ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

            if (u->headers_in.status_n == NGX_HTTP_NO_CONTENT
                || u->headers_in.status_n == NGX_HTTP_NOT_MODIFIED
                || ctx->head
                || (!u->headers_in.chunked
                    && u->headers_in.content_length_n == 0))
            {
                u->keepalive = !u->headers_in.connection_close;
            }

            if (u->headers_in.status_n == NGX_HTTP_SWITCHING_PROTOCOLS) {
                u->keepalive = 0;

                if (r->headers_in.upgrade) {
                    u->upgrade = 1;
                }
            }

            return NGX_OK;
        }

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        /* rc == NGX_HTTP_PARSE_INVALID_HEADER */

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent invalid header: \"%*s\\x%02xd...\"",
                      r->header_end - r->header_name_start,
                      r->header_name_start, *r->header_end);

        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }
}


static ngx_int_t
ngx_http_proxy_input_filter_init(void *data)
{
    ngx_http_request_t    *r = data;
    ngx_http_upstream_t   *u;
    ngx_http_proxy_ctx_t  *ctx;

    u = r->upstream;
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy filter init s:%ui h:%d c:%d l:%O",
                   u->headers_in.status_n, ctx->head, u->headers_in.chunked,
                   u->headers_in.content_length_n);

    /* as per RFC2616, 4.4 Message Length */

    if (u->headers_in.status_n == NGX_HTTP_NO_CONTENT
        || u->headers_in.status_n == NGX_HTTP_NOT_MODIFIED
        || ctx->head)
    {
        /* 1xx, 204, and 304 and replies to HEAD requests */
        /* no 1xx since we don't send Expect and Upgrade */

        u->pipe->length = 0;
        u->length = 0;
        u->keepalive = !u->headers_in.connection_close;

    } else if (u->headers_in.chunked) {
        /* chunked */

        u->pipe->input_filter = ngx_http_proxy_chunked_filter;
        u->pipe->length = 3; /* "0" LF LF */

        u->input_filter = ngx_http_proxy_non_buffered_chunked_filter;
        u->length = 1;

    } else if (u->headers_in.content_length_n == 0) {
        /* empty body: special case as filter won't be called */

        u->pipe->length = 0;
        u->length = 0;
        u->keepalive = !u->headers_in.connection_close;

    } else {
        /* content length or connection close */

        u->pipe->length = u->headers_in.content_length_n;
        u->length = u->headers_in.content_length_n;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_copy_filter(ngx_event_pipe_t *p, ngx_buf_t *buf)
{
    ngx_buf_t           *b;
    ngx_chain_t         *cl;
    ngx_http_request_t  *r;

    if (buf->pos == buf->last) {
        return NGX_OK;
    }

    if (p->upstream_done) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, p->log, 0,
                       "http proxy data after close");
        return NGX_OK;
    }

    if (p->length == 0) {

        ngx_log_error(NGX_LOG_WARN, p->log, 0,
                      "upstream sent more data than specified in "
                      "\"Content-Length\" header");

        r = p->input_ctx;
        r->upstream->keepalive = 0;
        p->upstream_done = 1;

        return NGX_OK;
    }

    cl = ngx_chain_get_free_buf(p->pool, &p->free);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    b = cl->buf;

    ngx_memcpy(b, buf, sizeof(ngx_buf_t));
    b->shadow = buf;
    b->tag = p->tag;
    b->last_shadow = 1;
    b->recycled = 1;
    buf->shadow = b;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0, "input buf #%d", b->num);

    if (p->in) {
        *p->last_in = cl;
    } else {
        p->in = cl;
    }
    p->last_in = &cl->next;

    if (p->length == -1) {
        return NGX_OK;
    }

    if (b->last - b->pos > p->length) {

        ngx_log_error(NGX_LOG_WARN, p->log, 0,
                      "upstream sent more data than specified in "
                      "\"Content-Length\" header");

        b->last = b->pos + p->length;
        p->upstream_done = 1;

        return NGX_OK;
    }

    p->length -= b->last - b->pos;

    if (p->length == 0) {
        r = p->input_ctx;
        r->upstream->keepalive = !r->upstream->headers_in.connection_close;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_chunked_filter(ngx_event_pipe_t *p, ngx_buf_t *buf)
{
    ngx_int_t                   rc;
    ngx_buf_t                  *b, **prev;
    ngx_chain_t                *cl;
    ngx_http_request_t         *r;
    ngx_http_proxy_ctx_t       *ctx;
    ngx_http_proxy_loc_conf_t  *plcf;

    if (buf->pos == buf->last) {
        return NGX_OK;
    }

    r = p->input_ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (p->upstream_done) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, p->log, 0,
                       "http proxy data after close");
        return NGX_OK;
    }

    if (p->length == 0) {

        ngx_log_error(NGX_LOG_WARN, p->log, 0,
                      "upstream sent data after final chunk");

        r->upstream->keepalive = 0;
        p->upstream_done = 1;

        return NGX_OK;
    }

    b = NULL;

    if (ctx->trailers) {
        rc = ngx_http_proxy_process_trailer(r, buf);

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (rc == NGX_OK) {

            /* a whole response has been parsed successfully */

            p->length = 0;
            r->upstream->keepalive = !r->upstream->headers_in.connection_close;

            if (buf->pos != buf->last) {
                ngx_log_error(NGX_LOG_WARN, p->log, 0,
                              "upstream sent data after trailers");
                r->upstream->keepalive = 0;
            }
        }

        goto free_buf;
    }

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    prev = &buf->shadow;

    for ( ;; ) {

        rc = ngx_http_parse_chunked(r, buf, &ctx->chunked,
                                    plcf->upstream.pass_trailers);

        if (rc == NGX_OK) {

            /* a chunk has been parsed successfully */

            cl = ngx_chain_get_free_buf(p->pool, &p->free);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            b = cl->buf;

            ngx_memzero(b, sizeof(ngx_buf_t));

            b->pos = buf->pos;
            b->start = buf->start;
            b->end = buf->end;
            b->tag = p->tag;
            b->temporary = 1;
            b->recycled = 1;

            *prev = b;
            prev = &b->shadow;

            if (p->in) {
                *p->last_in = cl;
            } else {
                p->in = cl;
            }
            p->last_in = &cl->next;

            /* STUB */ b->num = buf->num;

            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, p->log, 0,
                           "input buf #%d %p", b->num, b->pos);

            if (buf->last - buf->pos >= ctx->chunked.size) {

                buf->pos += (size_t) ctx->chunked.size;
                b->last = buf->pos;
                ctx->chunked.size = 0;

                continue;
            }

            ctx->chunked.size -= buf->last - buf->pos;
            buf->pos = buf->last;
            b->last = buf->last;

            continue;
        }

        if (rc == NGX_DONE) {

            if (plcf->upstream.pass_trailers) {
                rc = ngx_http_proxy_process_trailer(r, buf);

                if (rc == NGX_ERROR) {
                    return NGX_ERROR;
                }

                if (rc == NGX_AGAIN) {
                    p->length = 1;
                    break;
                }
            }

            /* a whole response has been parsed successfully */

            p->length = 0;
            r->upstream->keepalive = !r->upstream->headers_in.connection_close;

            if (buf->pos != buf->last) {
                ngx_log_error(NGX_LOG_WARN, p->log, 0,
                              "upstream sent data after final chunk");
                r->upstream->keepalive = 0;
            }

            break;
        }

        if (rc == NGX_AGAIN) {

            /* set p->length, minimal amount of data we want to see */

            p->length = ctx->chunked.length;

            break;
        }

        /* invalid response */

        ngx_log_error(NGX_LOG_ERR, p->log, 0,
                      "upstream sent invalid chunked response");

        return NGX_ERROR;
    }

free_buf:

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, p->log, 0,
                   "http proxy chunked state %ui, length %O",
                   ctx->chunked.state, p->length);

    if (b) {
        b->shadow = buf;
        b->last_shadow = 1;

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "input buf %p %z", b->pos, b->last - b->pos);

        return NGX_OK;
    }

    /* there is no data record in the buf, add it to free chain */

    if (ngx_event_pipe_add_free_buf(p, buf) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_non_buffered_copy_filter(void *data, ssize_t bytes)
{
    ngx_http_request_t   *r = data;

    ngx_buf_t            *b;
    ngx_chain_t          *cl, **ll;
    ngx_http_upstream_t  *u;

    u = r->upstream;

    if (u->length == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "upstream sent more data than specified in "
                      "\"Content-Length\" header");
        u->keepalive = 0;
        return NGX_OK;
    }

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    *ll = cl;

    cl->buf->flush = 1;
    cl->buf->memory = 1;

    b = &u->buffer;

    cl->buf->pos = b->last;
    b->last += bytes;
    cl->buf->last = b->last;
    cl->buf->tag = u->output.tag;

    if (u->length == -1) {
        return NGX_OK;
    }

    if (bytes > u->length) {

        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "upstream sent more data than specified in "
                      "\"Content-Length\" header");

        cl->buf->last = cl->buf->pos + u->length;
        u->length = 0;

        return NGX_OK;
    }

    u->length -= bytes;

    if (u->length == 0) {
        u->keepalive = !u->headers_in.connection_close;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_non_buffered_chunked_filter(void *data, ssize_t bytes)
{
    ngx_http_request_t   *r = data;

    ngx_int_t                   rc;
    ngx_buf_t                  *b, *buf;
    ngx_chain_t                *cl, **ll;
    ngx_http_upstream_t        *u;
    ngx_http_proxy_ctx_t       *ctx;
    ngx_http_proxy_loc_conf_t  *plcf;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    u = r->upstream;
    buf = &u->buffer;

    buf->pos = buf->last;
    buf->last += bytes;

    if (ctx->trailers) {
        rc = ngx_http_proxy_process_trailer(r, buf);

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (rc == NGX_OK) {

            /* a whole response has been parsed successfully */

            r->upstream->keepalive = !u->headers_in.connection_close;
            u->length = 0;

            if (buf->pos != buf->last) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "upstream sent data after trailers");
                u->keepalive = 0;
            }
        }

        return NGX_OK;
    }

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    for ( ;; ) {

        rc = ngx_http_parse_chunked(r, buf, &ctx->chunked,
                                    plcf->upstream.pass_trailers);

        if (rc == NGX_OK) {

            /* a chunk has been parsed successfully */

            cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            *ll = cl;
            ll = &cl->next;

            b = cl->buf;

            b->flush = 1;
            b->memory = 1;

            b->pos = buf->pos;
            b->tag = u->output.tag;

            if (buf->last - buf->pos >= ctx->chunked.size) {
                buf->pos += (size_t) ctx->chunked.size;
                b->last = buf->pos;
                ctx->chunked.size = 0;

            } else {
                ctx->chunked.size -= buf->last - buf->pos;
                buf->pos = buf->last;
                b->last = buf->last;
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy out buf %p %z",
                           b->pos, b->last - b->pos);

            continue;
        }

        if (rc == NGX_DONE) {

            if (plcf->upstream.pass_trailers) {
                rc = ngx_http_proxy_process_trailer(r, buf);

                if (rc == NGX_ERROR) {
                    return NGX_ERROR;
                }

                if (rc == NGX_AGAIN) {
                    u->length = 1;
                    break;
                }
            }

            /* a whole response has been parsed successfully */

            u->keepalive = !u->headers_in.connection_close;
            u->length = 0;

            if (buf->pos != buf->last) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "upstream sent data after final chunk");
                u->keepalive = 0;
            }

            break;
        }

        if (rc == NGX_AGAIN) {
            break;
        }

        /* invalid response */

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent invalid chunked response");

        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_process_trailer(ngx_http_request_t *r, ngx_buf_t *buf)
{
    size_t                      len;
    ngx_int_t                   rc;
    ngx_buf_t                  *b;
    ngx_table_elt_t            *h;
    ngx_http_proxy_ctx_t       *ctx;
    ngx_http_proxy_loc_conf_t  *plcf;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (ctx->trailers == NULL) {
        ctx->trailers = ngx_create_temp_buf(r->pool,
                                            plcf->upstream.buffer_size);
        if (ctx->trailers == NULL) {
            return NGX_ERROR;
        }
    }

    b = ctx->trailers;
    len = ngx_min(buf->last - buf->pos, b->end - b->last);

    b->last = ngx_cpymem(b->last, buf->pos, len);

    for ( ;; ) {

        rc = ngx_http_parse_header_line(r, b, 1);

        if (rc == NGX_OK) {

            /* a header line has been parsed successfully */

            h = ngx_list_push(&r->upstream->headers_in.trailers);
            if (h == NULL) {
                return NGX_ERROR;
            }

            h->hash = r->header_hash;

            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;

            h->key.data = ngx_pnalloc(r->pool,
                               h->key.len + 1 + h->value.len + 1 + h->key.len);
            if (h->key.data == NULL) {
                h->hash = 0;
                return NGX_ERROR;
            }

            h->value.data = h->key.data + h->key.len + 1;
            h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;

            ngx_memcpy(h->key.data, r->header_name_start, h->key.len);
            h->key.data[h->key.len] = '\0';
            ngx_memcpy(h->value.data, r->header_start, h->value.len);
            h->value.data[h->value.len] = '\0';

            if (h->key.len == r->lowcase_index) {
                ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);

            } else {
                ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy trailer: \"%V: %V\"",
                           &h->key, &h->value);
            continue;
        }

        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            buf->pos += len - (b->last - b->pos);

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy trailer done");

            return NGX_OK;
        }

        if (rc == NGX_AGAIN) {
            buf->pos += len;

            if (b->last == b->end) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent too big trailers");
                return NGX_ERROR;
            }

            return NGX_AGAIN;
        }

        /* rc == NGX_HTTP_PARSE_INVALID_HEADER */

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent invalid trailer: \"%*s\\x%02xd...\"",
                      r->header_end - r->header_name_start,
                      r->header_name_start, *r->header_end);

        return NGX_ERROR;
    }
}


static void
ngx_http_proxy_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http proxy request");

    return;
}


static void
ngx_http_proxy_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http proxy request");

    return;
}


static ngx_int_t
ngx_http_proxy_host_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_proxy_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = ctx->vars.host_header.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ctx->vars.host_header.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_port_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_proxy_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = ctx->vars.port.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ctx->vars.port.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_add_x_forwarded_for_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    size_t            len;
    u_char           *p;
    ngx_table_elt_t  *h, *xfwd;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    xfwd = r->headers_in.x_forwarded_for;

    len = 0;

    for (h = xfwd; h; h = h->next) {
        len += h->value.len + sizeof(", ") - 1;
    }

    if (len == 0) {
        v->len = r->connection->addr_text.len;
        v->data = r->connection->addr_text.data;
        return NGX_OK;
    }

    len += r->connection->addr_text.len;

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = len;
    v->data = p;

    for (h = xfwd; h; h = h->next) {
        p = ngx_copy(p, h->value.data, h->value.len);
        *p++ = ','; *p++ = ' ';
    }

    ngx_memcpy(p, r->connection->addr_text.data, r->connection->addr_text.len);

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_internal_body_length_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_proxy_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (ctx == NULL || ctx->internal_body_length < 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = ngx_pnalloc(r->pool, NGX_OFF_T_LEN);

    if (v->data == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(v->data, "%O", ctx->internal_body_length) - v->data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_internal_chunked_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_proxy_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (ctx == NULL || !ctx->internal_chunked) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = (u_char *) "chunked";
    v->len = sizeof("chunked") - 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_rewrite_redirect(ngx_http_request_t *r, ngx_table_elt_t *h,
    size_t prefix)
{
    size_t                      len;
    ngx_int_t                   rc;
    ngx_uint_t                  i;
    ngx_http_proxy_rewrite_t   *pr;
    ngx_http_proxy_loc_conf_t  *plcf;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    pr = plcf->redirects->elts;

    if (pr == NULL) {
        return NGX_DECLINED;
    }

    len = h->value.len - prefix;

    for (i = 0; i < plcf->redirects->nelts; i++) {
        rc = pr[i].handler(r, &h->value, prefix, len, &pr[i]);

        if (rc != NGX_DECLINED) {
            return rc;
        }
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_proxy_rewrite_cookie(ngx_http_request_t *r, ngx_table_elt_t *h)
{
    u_char                     *p;
    size_t                      len;
    ngx_int_t                   rc, rv;
    ngx_str_t                  *key, *value;
    ngx_uint_t                  i;
    ngx_array_t                 attrs;
    ngx_keyval_t               *attr;
    ngx_http_proxy_loc_conf_t  *plcf;

    if (ngx_array_init(&attrs, r->pool, 2, sizeof(ngx_keyval_t)) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_proxy_parse_cookie(&h->value, &attrs) != NGX_OK) {
        return NGX_ERROR;
    }

    attr = attrs.elts;

    if (attr[0].value.data == NULL) {
        return NGX_DECLINED;
    }

    rv = NGX_DECLINED;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    for (i = 1; i < attrs.nelts; i++) {

        key = &attr[i].key;
        value = &attr[i].value;

        if (plcf->cookie_domains && key->len == 6
            && ngx_strncasecmp(key->data, (u_char *) "domain", 6) == 0
            && value->data)
        {
            rc = ngx_http_proxy_rewrite_cookie_value(r, value,
                                                     plcf->cookie_domains);
            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (rc != NGX_DECLINED) {
                rv = rc;
            }
        }

        if (plcf->cookie_paths && key->len == 4
            && ngx_strncasecmp(key->data, (u_char *) "path", 4) == 0
            && value->data)
        {
            rc = ngx_http_proxy_rewrite_cookie_value(r, value,
                                                     plcf->cookie_paths);
            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (rc != NGX_DECLINED) {
                rv = rc;
            }
        }
    }

    if (plcf->cookie_flags) {
        rc = ngx_http_proxy_rewrite_cookie_flags(r, &attrs,
                                                 plcf->cookie_flags);
        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (rc != NGX_DECLINED) {
            rv = rc;
        }

        attr = attrs.elts;
    }

    if (rv != NGX_OK) {
        return rv;
    }

    len = 0;

    for (i = 0; i < attrs.nelts; i++) {

        if (attr[i].key.data == NULL) {
            continue;
        }

        if (i > 0) {
            len += 2;
        }

        len += attr[i].key.len;

        if (attr[i].value.data) {
            len += 1 + attr[i].value.len;
        }
    }

    p = ngx_pnalloc(r->pool, len + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }

    h->value.data = p;
    h->value.len = len;

    for (i = 0; i < attrs.nelts; i++) {

        if (attr[i].key.data == NULL) {
            continue;
        }

        if (i > 0) {
            *p++ = ';';
            *p++ = ' ';
        }

        p = ngx_cpymem(p, attr[i].key.data, attr[i].key.len);

        if (attr[i].value.data) {
            *p++ = '=';
            p = ngx_cpymem(p, attr[i].value.data, attr[i].value.len);
        }
    }

    *p = '\0';

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_parse_cookie(ngx_str_t *value, ngx_array_t *attrs)
{
    u_char        *start, *end, *p, *last;
    ngx_str_t      name, val;
    ngx_keyval_t  *attr;

    start = value->data;
    end = value->data + value->len;

    for ( ;; ) {

        last = (u_char *) ngx_strchr(start, ';');

        if (last == NULL) {
            last = end;
        }

        while (start < last && *start == ' ') { start++; }

        for (p = start; p < last && *p != '='; p++) { /* void */ }

        name.data = start;
        name.len = p - start;

        while (name.len && name.data[name.len - 1] == ' ') {
            name.len--;
        }

        if (p < last) {

            p++;

            while (p < last && *p == ' ') { p++; }

            val.data = p;
            val.len = last - val.data;

            while (val.len && val.data[val.len - 1] == ' ') {
                val.len--;
            }

        } else {
            ngx_str_null(&val);
        }

        attr = ngx_array_push(attrs);
        if (attr == NULL) {
            return NGX_ERROR;
        }

        attr->key = name;
        attr->value = val;

        if (last == end) {
            break;
        }

        start = last + 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_rewrite_cookie_value(ngx_http_request_t *r, ngx_str_t *value,
    ngx_array_t *rewrites)
{
    ngx_int_t                  rc;
    ngx_uint_t                 i;
    ngx_http_proxy_rewrite_t  *pr;

    pr = rewrites->elts;

    for (i = 0; i < rewrites->nelts; i++) {
        rc = pr[i].handler(r, value, 0, value->len, &pr[i]);

        if (rc != NGX_DECLINED) {
            return rc;
        }
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_proxy_rewrite_cookie_flags(ngx_http_request_t *r, ngx_array_t *attrs,
    ngx_array_t *flags)
{
    ngx_str_t                       pattern, value;
#if (NGX_PCRE)
    ngx_int_t                       rc;
#endif
    ngx_uint_t                      i, m, f, nelts;
    ngx_keyval_t                   *attr;
    ngx_conf_bitmask_t             *mask;
    ngx_http_complex_value_t       *flags_values;
    ngx_http_proxy_cookie_flags_t  *pcf;

    attr = attrs->elts;
    pcf = flags->elts;

    for (i = 0; i < flags->nelts; i++) {

#if (NGX_PCRE)
        if (pcf[i].regex) {
            rc = ngx_http_regex_exec(r, pcf[i].cookie.regex, &attr[0].key);

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (rc == NGX_OK) {
                break;
            }

            /* NGX_DECLINED */

            continue;
        }
#endif

        if (ngx_http_complex_value(r, &pcf[i].cookie.complex, &pattern)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (pattern.len == attr[0].key.len
            && ngx_strncasecmp(attr[0].key.data, pattern.data, pattern.len)
               == 0)
        {
            break;
        }
    }

    if (i == flags->nelts) {
        return NGX_DECLINED;
    }

    nelts = pcf[i].flags_values.nelts;
    flags_values = pcf[i].flags_values.elts;

    mask = ngx_http_proxy_cookie_flags_masks;
    f = 0;

    for (i = 0; i < nelts; i++) {

        if (ngx_http_complex_value(r, &flags_values[i], &value) != NGX_OK) {
            return NGX_ERROR;
        }

        if (value.len == 0) {
            continue;
        }

        for (m = 0; mask[m].name.len != 0; m++) {

            if (mask[m].name.len != value.len
                || ngx_strncasecmp(mask[m].name.data, value.data, value.len)
                   != 0)
            {
                continue;
            }

            f |= mask[m].mask;

            break;
        }

        if (mask[m].name.len == 0) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "invalid proxy_cookie_flags flag \"%V\"", &value);
        }
    }

    if (f == 0) {
        return NGX_DECLINED;
    }

    return ngx_http_proxy_edit_cookie_flags(r, attrs, f);
}


static ngx_int_t
ngx_http_proxy_edit_cookie_flags(ngx_http_request_t *r, ngx_array_t *attrs,
    ngx_uint_t flags)
{
    ngx_str_t     *key, *value;
    ngx_uint_t     i;
    ngx_keyval_t  *attr;

    attr = attrs->elts;

    for (i = 1; i < attrs->nelts; i++) {
        key = &attr[i].key;

        if (key->len == 6
            && ngx_strncasecmp(key->data, (u_char *) "secure", 6) == 0)
        {
            if (flags & NGX_HTTP_PROXY_COOKIE_SECURE_ON) {
                flags &= ~NGX_HTTP_PROXY_COOKIE_SECURE_ON;

            } else if (flags & NGX_HTTP_PROXY_COOKIE_SECURE_OFF) {
                key->data = NULL;
            }

            continue;
        }

        if (key->len == 8
            && ngx_strncasecmp(key->data, (u_char *) "httponly", 8) == 0)
        {
            if (flags & NGX_HTTP_PROXY_COOKIE_HTTPONLY_ON) {
                flags &= ~NGX_HTTP_PROXY_COOKIE_HTTPONLY_ON;

            } else if (flags & NGX_HTTP_PROXY_COOKIE_HTTPONLY_OFF) {
                key->data = NULL;
            }

            continue;
        }

        if (key->len == 8
            && ngx_strncasecmp(key->data, (u_char *) "samesite", 8) == 0)
        {
            value = &attr[i].value;

            if (flags & NGX_HTTP_PROXY_COOKIE_SAMESITE_STRICT) {
                flags &= ~NGX_HTTP_PROXY_COOKIE_SAMESITE_STRICT;

                if (value->len != 6
                    || ngx_strncasecmp(value->data, (u_char *) "strict", 6)
                       != 0)
                {
                    ngx_str_set(key, "SameSite");
                    ngx_str_set(value, "Strict");
                }

            } else if (flags & NGX_HTTP_PROXY_COOKIE_SAMESITE_LAX) {
                flags &= ~NGX_HTTP_PROXY_COOKIE_SAMESITE_LAX;

                if (value->len != 3
                    || ngx_strncasecmp(value->data, (u_char *) "lax", 3) != 0)
                {
                    ngx_str_set(key, "SameSite");
                    ngx_str_set(value, "Lax");
                }

            } else if (flags & NGX_HTTP_PROXY_COOKIE_SAMESITE_NONE) {
                flags &= ~NGX_HTTP_PROXY_COOKIE_SAMESITE_NONE;

                if (value->len != 4
                    || ngx_strncasecmp(value->data, (u_char *) "none", 4) != 0)
                {
                    ngx_str_set(key, "SameSite");
                    ngx_str_set(value, "None");
                }

            } else if (flags & NGX_HTTP_PROXY_COOKIE_SAMESITE_OFF) {
                key->data = NULL;
            }

            continue;
        }
    }

    if (flags & NGX_HTTP_PROXY_COOKIE_SECURE_ON) {
        attr = ngx_array_push(attrs);
        if (attr == NULL) {
            return NGX_ERROR;
        }

        ngx_str_set(&attr->key, "Secure");
        ngx_str_null(&attr->value);
    }

    if (flags & NGX_HTTP_PROXY_COOKIE_HTTPONLY_ON) {
        attr = ngx_array_push(attrs);
        if (attr == NULL) {
            return NGX_ERROR;
        }

        ngx_str_set(&attr->key, "HttpOnly");
        ngx_str_null(&attr->value);
    }

    if (flags & (NGX_HTTP_PROXY_COOKIE_SAMESITE_STRICT
                 |NGX_HTTP_PROXY_COOKIE_SAMESITE_LAX
                 |NGX_HTTP_PROXY_COOKIE_SAMESITE_NONE))
    {
        attr = ngx_array_push(attrs);
        if (attr == NULL) {
            return NGX_ERROR;
        }

        ngx_str_set(&attr->key, "SameSite");

        if (flags & NGX_HTTP_PROXY_COOKIE_SAMESITE_STRICT) {
            ngx_str_set(&attr->value, "Strict");

        } else if (flags & NGX_HTTP_PROXY_COOKIE_SAMESITE_LAX) {
            ngx_str_set(&attr->value, "Lax");

        } else {
            ngx_str_set(&attr->value, "None");
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_rewrite_complex_handler(ngx_http_request_t *r, ngx_str_t *value,
    size_t prefix, size_t len, ngx_http_proxy_rewrite_t *pr)
{
    ngx_str_t  pattern, replacement;

    if (ngx_http_complex_value(r, &pr->pattern.complex, &pattern) != NGX_OK) {
        return NGX_ERROR;
    }

    if (pattern.len > len
        || ngx_rstrncmp(value->data + prefix, pattern.data, pattern.len) != 0)
    {
        return NGX_DECLINED;
    }

    if (ngx_http_complex_value(r, &pr->replacement, &replacement) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_http_proxy_rewrite(r, value, prefix, pattern.len, &replacement);
}


#if (NGX_PCRE)

static ngx_int_t
ngx_http_proxy_rewrite_regex_handler(ngx_http_request_t *r, ngx_str_t *value,
    size_t prefix, size_t len, ngx_http_proxy_rewrite_t *pr)
{
    ngx_str_t  pattern, replacement;

    pattern.len = len;
    pattern.data = value->data + prefix;

    if (ngx_http_regex_exec(r, pr->pattern.regex, &pattern) != NGX_OK) {
        return NGX_DECLINED;
    }

    if (ngx_http_complex_value(r, &pr->replacement, &replacement) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_http_proxy_rewrite(r, value, prefix, len, &replacement);
}

#endif


static ngx_int_t
ngx_http_proxy_rewrite_domain_handler(ngx_http_request_t *r, ngx_str_t *value,
    size_t prefix, size_t len, ngx_http_proxy_rewrite_t *pr)
{
    u_char     *p;
    ngx_str_t   pattern, replacement;

    if (ngx_http_complex_value(r, &pr->pattern.complex, &pattern) != NGX_OK) {
        return NGX_ERROR;
    }

    p = value->data + prefix;

    if (len && p[0] == '.') {
        p++;
        prefix++;
        len--;
    }

    if (pattern.len != len || ngx_rstrncasecmp(pattern.data, p, len) != 0) {
        return NGX_DECLINED;
    }

    if (ngx_http_complex_value(r, &pr->replacement, &replacement) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_http_proxy_rewrite(r, value, prefix, len, &replacement);
}


static ngx_int_t
ngx_http_proxy_rewrite(ngx_http_request_t *r, ngx_str_t *value, size_t prefix,
    size_t len, ngx_str_t *replacement)
{
    u_char  *p, *data;
    size_t   new_len;

    if (len == value->len) {
        *value = *replacement;
        return NGX_OK;
    }

    new_len = replacement->len + value->len - len;

    if (replacement->len > len) {

        data = ngx_pnalloc(r->pool, new_len + 1);
        if (data == NULL) {
            return NGX_ERROR;
        }

        p = ngx_copy(data, value->data, prefix);
        p = ngx_copy(p, replacement->data, replacement->len);

        ngx_memcpy(p, value->data + prefix + len,
                   value->len - len - prefix + 1);

        value->data = data;

    } else {
        p = ngx_copy(value->data + prefix, replacement->data, replacement->len);

        ngx_memmove(p, value->data + prefix + len,
                    value->len - len - prefix + 1);
    }

    value->len = new_len;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_proxy_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static void *
ngx_http_proxy_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_proxy_main_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_proxy_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

#if (NGX_HTTP_CACHE)
    if (ngx_array_init(&conf->caches, cf->pool, 4,
                       sizeof(ngx_http_file_cache_t *))
        != NGX_OK)
    {
        return NULL;
    }
#endif

    return conf;
}


static void *
ngx_http_proxy_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_proxy_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_proxy_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->upstream.bufs.num = 0;
     *     conf->upstream.ignore_headers = 0;
     *     conf->upstream.next_upstream = 0;
     *     conf->upstream.cache_zone = NULL;
     *     conf->upstream.cache_use_stale = 0;
     *     conf->upstream.cache_methods = 0;
     *     conf->upstream.temp_path = NULL;
     *     conf->upstream.hide_headers_hash = { NULL, 0 };
     *     conf->upstream.store_lengths = NULL;
     *     conf->upstream.store_values = NULL;
     *
     *     conf->location = NULL;
     *     conf->url = { 0, NULL };
     *     conf->headers.lengths = NULL;
     *     conf->headers.values = NULL;
     *     conf->headers.hash = { NULL, 0 };
     *     conf->headers_cache.lengths = NULL;
     *     conf->headers_cache.values = NULL;
     *     conf->headers_cache.hash = { NULL, 0 };
     *     conf->body_lengths = NULL;
     *     conf->body_values = NULL;
     *     conf->body_source = { 0, NULL };
     *     conf->redirects = NULL;
     *     conf->ssl = 0;
     *     conf->ssl_protocols = 0;
     *     conf->ssl_ciphers = { 0, NULL };
     *     conf->ssl_trusted_certificate = { 0, NULL };
     *     conf->ssl_crl = { 0, NULL };
     *
     *     conf->host = { 0, NULL };
     *     conf->host_set = 0;
     *     conf->max_table_capacity_set = 0;
     *
     *     conf->upstream.quic.host_key = { 0, NULL }
     *     conf->upstream.quic.stream_reject_code_uni = 0;
     *     conf->upstream.quic.disable_active_migration = 0;
     *     conf->upstream.quic.idle_timeout = 0;
     *     conf->upstream.quic.handshake_timeout = 0;
     *     conf->upstream.quic.retry = 0;
     *
     *     conf->upstream.h3_settings.max_blocked_streams = 0;
     */

    conf->upstream.store = NGX_CONF_UNSET;
    conf->upstream.store_access = NGX_CONF_UNSET_UINT;
    conf->upstream.next_upstream_tries = NGX_CONF_UNSET_UINT;
    conf->upstream.buffering = NGX_CONF_UNSET;
    conf->upstream.request_buffering = NGX_CONF_UNSET;
    conf->upstream.ignore_client_abort = NGX_CONF_UNSET;
    conf->upstream.force_ranges = NGX_CONF_UNSET;

    conf->upstream.local = NGX_CONF_UNSET_PTR;
    conf->upstream.socket_keepalive = NGX_CONF_UNSET;

    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.connection_drop = NGX_CONF_UNSET_MSEC;

    conf->upstream.send_lowat = NGX_CONF_UNSET_SIZE;
    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;
    conf->upstream.limit_rate = NGX_CONF_UNSET_PTR;

    conf->upstream.busy_buffers_size_conf = NGX_CONF_UNSET_SIZE;
    conf->upstream.max_temp_file_size_conf = NGX_CONF_UNSET_SIZE;
    conf->upstream.temp_file_write_size_conf = NGX_CONF_UNSET_SIZE;

    conf->upstream.pass_request_headers = NGX_CONF_UNSET;
    conf->upstream.pass_request_body = NGX_CONF_UNSET;
    conf->upstream.pass_trailers = NGX_CONF_UNSET;

#if (NGX_HTTP_CACHE)
    conf->upstream.cache = NGX_CONF_UNSET;
    conf->upstream.cache_min_uses = NGX_CONF_UNSET_UINT;
    conf->upstream.cache_max_range_offset = NGX_CONF_UNSET;
    conf->upstream.cache_bypass = NGX_CONF_UNSET_PTR;
    conf->upstream.no_cache = NGX_CONF_UNSET_PTR;
    conf->upstream.cache_valid = NGX_CONF_UNSET_PTR;
    conf->upstream.cache_lock = NGX_CONF_UNSET;
    conf->upstream.cache_lock_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.cache_lock_age = NGX_CONF_UNSET_MSEC;
    conf->upstream.cache_revalidate = NGX_CONF_UNSET;
    conf->upstream.cache_convert_head = NGX_CONF_UNSET;
    conf->upstream.cache_background_update = NGX_CONF_UNSET;
#endif

    conf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
    conf->upstream.pass_headers = NGX_CONF_UNSET_PTR;

    conf->upstream.intercept_errors = NGX_CONF_UNSET;

#if (NGX_HTTP_SSL)
    conf->upstream.ssl_session_reuse = NGX_CONF_UNSET;
    conf->upstream.ssl_name = NGX_CONF_UNSET_PTR;
    conf->upstream.ssl_server_name = NGX_CONF_UNSET;
    conf->upstream.ssl_verify = NGX_CONF_UNSET;
#if (NGX_HTTP_PROXY_MULTICERT)
    conf->upstream.ssl_certificates = NGX_CONF_UNSET_PTR;
    conf->upstream.ssl_certificate_keys = NGX_CONF_UNSET_PTR;
    conf->upstream.ssl_certificate_values = NGX_CONF_UNSET_PTR;
    conf->upstream.ssl_certificate_key_values = NGX_CONF_UNSET_PTR;
#else
    conf->upstream.ssl_certificate = NGX_CONF_UNSET_PTR;
    conf->upstream.ssl_certificate_key = NGX_CONF_UNSET_PTR;
#endif
    conf->upstream.ssl_certificate_cache = NGX_CONF_UNSET_PTR;
    conf->upstream.ssl_passwords = NGX_CONF_UNSET_PTR;
    conf->ssl_verify_depth = NGX_CONF_UNSET_UINT;
    conf->ssl_conf_commands = NGX_CONF_UNSET_PTR;
#if (NGX_HAVE_NTLS)
    conf->upstream.ssl_ntls = NGX_CONF_UNSET;
#endif
#endif

    /* "proxy_cyclic_temp_file" is disabled */
    conf->upstream.cyclic_temp_file = 0;

    conf->upstream.change_buffering = 1;

    conf->headers_source = NGX_CONF_UNSET_PTR;

    conf->method = NGX_CONF_UNSET_PTR;

    conf->redirect = NGX_CONF_UNSET;

    conf->cookie_domains = NGX_CONF_UNSET_PTR;
    conf->cookie_paths = NGX_CONF_UNSET_PTR;
    conf->cookie_flags = NGX_CONF_UNSET_PTR;

    conf->http_version = NGX_CONF_UNSET_UINT;

    conf->headers_hash_max_size = NGX_CONF_UNSET_UINT;
    conf->headers_hash_bucket_size = NGX_CONF_UNSET_UINT;

    ngx_str_set(&conf->upstream.module, "proxy");

#if (NGX_HTTP_V3)

    conf->upstream.quic.stream_buffer_size = NGX_CONF_UNSET_SIZE;
    conf->upstream.quic.max_concurrent_streams_bidi = NGX_CONF_UNSET_UINT;
    conf->upstream.quic.max_concurrent_streams_uni =
                                                   NGX_HTTP_V3_MAX_UNI_STREAMS;
    conf->upstream.quic.gso_enabled = NGX_CONF_UNSET;

    conf->upstream.quic.active_connection_id_limit = NGX_CONF_UNSET_UINT;

    conf->upstream.quic.stream_close_code = NGX_HTTP_V3_ERR_NO_ERROR;
    conf->upstream.quic.stream_reject_code_bidi =
                                              NGX_HTTP_V3_ERR_REQUEST_REJECTED;

    conf->upstream.quic.shutdown = ngx_http_v3_shutdown;

    conf->enable_hq = NGX_CONF_UNSET;

    conf->upstream.h3_settings.max_table_capacity = NGX_CONF_UNSET;
    conf->upstream.h3_settings.max_concurrent_streams = NGX_CONF_UNSET_UINT;

#endif

    return conf;
}


static char *
ngx_http_proxy_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_proxy_loc_conf_t *prev = parent;
    ngx_http_proxy_loc_conf_t *conf = child;

    u_char                     *p;
    size_t                      size;
    ngx_int_t                   rc;
    ngx_keyval_t               *proxy_headers;
    ngx_hash_init_t             hash;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_proxy_rewrite_t   *pr;
    ngx_http_script_compile_t   sc;

#if (NGX_HTTP_CACHE)

    if (conf->upstream.store > 0) {
        conf->upstream.cache = 0;
    }

    if (conf->upstream.cache > 0) {
        conf->upstream.store = 0;
    }

#endif

    if (conf->upstream.store == NGX_CONF_UNSET) {
        ngx_conf_merge_value(conf->upstream.store,
                              prev->upstream.store, 0);

        conf->upstream.store_lengths = prev->upstream.store_lengths;
        conf->upstream.store_values = prev->upstream.store_values;
    }

    ngx_conf_merge_uint_value(conf->upstream.store_access,
                              prev->upstream.store_access, 0600);

    ngx_conf_merge_uint_value(conf->upstream.next_upstream_tries,
                              prev->upstream.next_upstream_tries, 0);

    ngx_conf_merge_value(conf->upstream.buffering,
                              prev->upstream.buffering, 1);

    ngx_conf_merge_value(conf->upstream.request_buffering,
                              prev->upstream.request_buffering, 1);

    ngx_conf_merge_value(conf->upstream.ignore_client_abort,
                              prev->upstream.ignore_client_abort, 0);

    ngx_conf_merge_value(conf->upstream.force_ranges,
                              prev->upstream.force_ranges, 0);

    ngx_conf_merge_ptr_value(conf->upstream.local,
                              prev->upstream.local, NULL);

    ngx_conf_merge_value(conf->upstream.socket_keepalive,
                              prev->upstream.socket_keepalive, 0);

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.next_upstream_timeout,
                              prev->upstream.next_upstream_timeout, 0);

    ngx_conf_merge_msec_value(conf->upstream.connection_drop,
                              prev->upstream.connection_drop,
                              NGX_HTTP_UPSTREAM_CONNECTION_DROP_OFF);

    ngx_conf_merge_size_value(conf->upstream.send_lowat,
                              prev->upstream.send_lowat, 0);

    ngx_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) ngx_pagesize);

    ngx_conf_merge_ptr_value(conf->upstream.limit_rate,
                              prev->upstream.limit_rate, NULL);

    ngx_conf_merge_bufs_value(conf->upstream.bufs, prev->upstream.bufs,
                              8, ngx_pagesize);

    if (conf->upstream.bufs.num < 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "there must be at least 2 \"proxy_buffers\"");
        return NGX_CONF_ERROR;
    }


    size = conf->upstream.buffer_size;
    if (size < conf->upstream.bufs.size) {
        size = conf->upstream.bufs.size;
    }


    ngx_conf_merge_size_value(conf->upstream.busy_buffers_size_conf,
                              prev->upstream.busy_buffers_size_conf,
                              NGX_CONF_UNSET_SIZE);

    if (conf->upstream.busy_buffers_size_conf == NGX_CONF_UNSET_SIZE) {
        conf->upstream.busy_buffers_size = 2 * size;
    } else {
        conf->upstream.busy_buffers_size =
                                         conf->upstream.busy_buffers_size_conf;
    }

    if (conf->upstream.busy_buffers_size < size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"proxy_busy_buffers_size\" must be equal to or greater than "
             "the maximum of the value of \"proxy_buffer_size\" and "
             "one of the \"proxy_buffers\"");

        return NGX_CONF_ERROR;
    }

    if (conf->upstream.busy_buffers_size
        > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"proxy_busy_buffers_size\" must be less than "
             "the size of all \"proxy_buffers\" minus one buffer");

        return NGX_CONF_ERROR;
    }


    ngx_conf_merge_size_value(conf->upstream.temp_file_write_size_conf,
                              prev->upstream.temp_file_write_size_conf,
                              NGX_CONF_UNSET_SIZE);

    if (conf->upstream.temp_file_write_size_conf == NGX_CONF_UNSET_SIZE) {
        conf->upstream.temp_file_write_size = 2 * size;
    } else {
        conf->upstream.temp_file_write_size =
                                      conf->upstream.temp_file_write_size_conf;
    }

    if (conf->upstream.temp_file_write_size < size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"proxy_temp_file_write_size\" must be equal to or greater "
             "than the maximum of the value of \"proxy_buffer_size\" and "
             "one of the \"proxy_buffers\"");

        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_size_value(conf->upstream.max_temp_file_size_conf,
                              prev->upstream.max_temp_file_size_conf,
                              NGX_CONF_UNSET_SIZE);

    if (conf->upstream.max_temp_file_size_conf == NGX_CONF_UNSET_SIZE) {
        conf->upstream.max_temp_file_size = 1024 * 1024 * 1024;
    } else {
        conf->upstream.max_temp_file_size =
                                        conf->upstream.max_temp_file_size_conf;
    }

    if (conf->upstream.max_temp_file_size != 0
        && conf->upstream.max_temp_file_size < size)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"proxy_max_temp_file_size\" must be equal to zero to disable "
             "temporary files usage or must be equal to or greater than "
             "the maximum of the value of \"proxy_buffer_size\" and "
             "one of the \"proxy_buffers\"");

        return NGX_CONF_ERROR;
    }


    ngx_conf_merge_bitmask_value(conf->upstream.ignore_headers,
                              prev->upstream.ignore_headers,
                              NGX_CONF_BITMASK_SET);


    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
                              prev->upstream.next_upstream,
                              (NGX_CONF_BITMASK_SET
                               |NGX_HTTP_UPSTREAM_FT_ERROR
                               |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
                                       |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (ngx_conf_merge_path_value(cf, &conf->upstream.temp_path,
                              prev->upstream.temp_path,
                              &ngx_http_proxy_temp_path)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }


#if (NGX_HTTP_CACHE)

    if (conf->upstream.cache == NGX_CONF_UNSET) {
        ngx_conf_merge_value(conf->upstream.cache,
                              prev->upstream.cache, 0);

        conf->upstream.cache_zone = prev->upstream.cache_zone;
        conf->upstream.cache_value = prev->upstream.cache_value;
    }

    if (conf->upstream.cache_zone && conf->upstream.cache_zone->data == NULL) {
        ngx_shm_zone_t  *shm_zone;

        shm_zone = conf->upstream.cache_zone;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"proxy_cache\" zone \"%V\" is unknown",
                           &shm_zone->shm.name);

        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_uint_value(conf->upstream.cache_min_uses,
                              prev->upstream.cache_min_uses, 1);

    ngx_conf_merge_off_value(conf->upstream.cache_max_range_offset,
                              prev->upstream.cache_max_range_offset,
                              NGX_MAX_OFF_T_VALUE);

    ngx_conf_merge_bitmask_value(conf->upstream.cache_use_stale,
                              prev->upstream.cache_use_stale,
                              (NGX_CONF_BITMASK_SET
                               |NGX_HTTP_UPSTREAM_FT_OFF));

    if (conf->upstream.cache_use_stale & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.cache_use_stale = NGX_CONF_BITMASK_SET
                                         |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->upstream.cache_use_stale & NGX_HTTP_UPSTREAM_FT_ERROR) {
        conf->upstream.cache_use_stale |= NGX_HTTP_UPSTREAM_FT_NOLIVE;
    }

    if (conf->upstream.cache_methods == 0) {
        conf->upstream.cache_methods = prev->upstream.cache_methods;
    }

    conf->upstream.cache_methods |= NGX_HTTP_GET|NGX_HTTP_HEAD;

    ngx_conf_merge_ptr_value(conf->upstream.cache_bypass,
                             prev->upstream.cache_bypass, NULL);

    ngx_conf_merge_ptr_value(conf->upstream.no_cache,
                             prev->upstream.no_cache, NULL);

    ngx_conf_merge_ptr_value(conf->upstream.cache_valid,
                             prev->upstream.cache_valid, NULL);

    if (conf->cache_key.value.data == NULL) {
        conf->cache_key = prev->cache_key;
    }

    ngx_conf_merge_value(conf->upstream.cache_lock,
                              prev->upstream.cache_lock, 0);

    ngx_conf_merge_msec_value(conf->upstream.cache_lock_timeout,
                              prev->upstream.cache_lock_timeout, 5000);

    ngx_conf_merge_msec_value(conf->upstream.cache_lock_age,
                              prev->upstream.cache_lock_age, 5000);

    ngx_conf_merge_value(conf->upstream.cache_revalidate,
                              prev->upstream.cache_revalidate, 0);

    ngx_conf_merge_value(conf->upstream.cache_convert_head,
                              prev->upstream.cache_convert_head, 1);

    ngx_conf_merge_value(conf->upstream.cache_background_update,
                              prev->upstream.cache_background_update, 0);

#endif

    ngx_conf_merge_value(conf->upstream.pass_request_headers,
                              prev->upstream.pass_request_headers, 1);
    ngx_conf_merge_value(conf->upstream.pass_request_body,
                              prev->upstream.pass_request_body, 1);

    ngx_conf_merge_value(conf->upstream.pass_trailers,
                              prev->upstream.pass_trailers, 0);

    ngx_conf_merge_value(conf->upstream.intercept_errors,
                              prev->upstream.intercept_errors, 0);

#if (NGX_HTTP_SSL)

    if (ngx_http_proxy_merge_ssl(cf, conf, prev) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_value(conf->upstream.ssl_session_reuse,
                              prev->upstream.ssl_session_reuse, 1);

    ngx_conf_merge_bitmask_value(conf->ssl_protocols, prev->ssl_protocols,
                              (NGX_CONF_BITMASK_SET|NGX_SSL_DEFAULT_PROTOCOLS));

    ngx_conf_merge_str_value(conf->ssl_ciphers, prev->ssl_ciphers,
                             "DEFAULT");

    ngx_conf_merge_ptr_value(conf->upstream.ssl_name,
                              prev->upstream.ssl_name, NULL);
    ngx_conf_merge_value(conf->upstream.ssl_server_name,
                              prev->upstream.ssl_server_name, 0);
    ngx_conf_merge_value(conf->upstream.ssl_verify,
                              prev->upstream.ssl_verify, 0);
    ngx_conf_merge_uint_value(conf->ssl_verify_depth,
                              prev->ssl_verify_depth, 1);
    ngx_conf_merge_str_value(conf->ssl_trusted_certificate,
                              prev->ssl_trusted_certificate, "");
    ngx_conf_merge_str_value(conf->ssl_crl, prev->ssl_crl, "");

    ngx_conf_merge_ptr_value(conf->upstream.ssl_passwords,
                              prev->upstream.ssl_passwords, NULL);

#if (NGX_HTTP_PROXY_MULTICERT)
    ngx_conf_merge_ptr_value(conf->upstream.ssl_certificates,
                              prev->upstream.ssl_certificates, NULL);
    ngx_conf_merge_ptr_value(conf->upstream.ssl_certificate_keys,
                              prev->upstream.ssl_certificate_keys, NULL);

    if (conf->upstream.ssl_certificates) {
        if (ngx_http_proxy_compile_certificates(cf, conf) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    ngx_conf_merge_ptr_value(conf->upstream.ssl_certificate_values,
                             prev->upstream.ssl_certificate_values, NULL);

    ngx_conf_merge_ptr_value(conf->upstream.ssl_certificate_key_values,
                              prev->upstream.ssl_certificate_key_values, NULL);

#else
    ngx_conf_merge_ptr_value(conf->upstream.ssl_certificate,
                              prev->upstream.ssl_certificate, NULL);
    ngx_conf_merge_ptr_value(conf->upstream.ssl_certificate_key,
                              prev->upstream.ssl_certificate_key, NULL);
#endif

    ngx_conf_merge_ptr_value(conf->upstream.ssl_certificate_cache,
                              prev->upstream.ssl_certificate_cache, NULL);

    if (ngx_http_proxy_preserve_ssl_passwords(cf, &conf->upstream,
                                              &prev->upstream)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_ptr_value(conf->ssl_conf_commands,
                              prev->ssl_conf_commands, NULL);

#if (NGX_HAVE_NTLS)
    ngx_conf_merge_value(conf->upstream.ssl_ntls,
                              prev->upstream.ssl_ntls, 0);

    if (conf->upstream.ssl_ntls) {
        conf->upstream.ssl_ciphers = conf->ssl_ciphers;
    }
#endif

    if (conf->ssl && ngx_http_proxy_set_ssl(cf, conf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

#endif

    ngx_conf_merge_ptr_value(conf->method, prev->method, NULL);

    ngx_conf_merge_value(conf->redirect, prev->redirect, 1);

    if (conf->redirect) {

        if (conf->redirects == NULL) {
            conf->redirects = prev->redirects;
        }

        if (conf->redirects == NULL && conf->url.data) {

            conf->redirects = ngx_array_create(cf->pool, 1,
                                             sizeof(ngx_http_proxy_rewrite_t));
            if (conf->redirects == NULL) {
                return NGX_CONF_ERROR;
            }

            pr = ngx_array_push(conf->redirects);
            if (pr == NULL) {
                return NGX_CONF_ERROR;
            }

            ngx_memzero(&pr->pattern.complex,
                        sizeof(ngx_http_complex_value_t));

            ngx_memzero(&pr->replacement, sizeof(ngx_http_complex_value_t));

            pr->handler = ngx_http_proxy_rewrite_complex_handler;

            if (conf->vars.uri.len) {
                pr->pattern.complex.value = conf->url;
                pr->replacement.value = conf->location;

            } else {
                pr->pattern.complex.value.len = conf->url.len
                                                + sizeof("/") - 1;

                p = ngx_pnalloc(cf->pool, pr->pattern.complex.value.len);
                if (p == NULL) {
                    return NGX_CONF_ERROR;
                }

                pr->pattern.complex.value.data = p;

                p = ngx_cpymem(p, conf->url.data, conf->url.len);
                *p = '/';

                ngx_str_set(&pr->replacement.value, "/");
            }
        }
    }

    ngx_conf_merge_ptr_value(conf->cookie_domains, prev->cookie_domains, NULL);

    ngx_conf_merge_ptr_value(conf->cookie_paths, prev->cookie_paths, NULL);

    ngx_conf_merge_ptr_value(conf->cookie_flags, prev->cookie_flags, NULL);

    ngx_conf_merge_uint_value(conf->http_version, prev->http_version,
                              NGX_HTTP_VERSION_10);

    ngx_conf_merge_uint_value(conf->headers_hash_max_size,
                              prev->headers_hash_max_size, 512);

    ngx_conf_merge_uint_value(conf->headers_hash_bucket_size,
                              prev->headers_hash_bucket_size, 64);

    conf->headers_hash_bucket_size = ngx_align(conf->headers_hash_bucket_size,
                                               ngx_cacheline_size);

    hash.max_size = conf->headers_hash_max_size;
    hash.bucket_size = conf->headers_hash_bucket_size;
    hash.name = "proxy_headers_hash";

    if (ngx_http_upstream_hide_headers_hash(cf, &conf->upstream,
            &prev->upstream, ngx_http_proxy_hide_headers, &hash)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

#if (NGX_HTTP_V3)

    ngx_conf_merge_value(conf->enable_hq, prev->enable_hq, 0);

    if (conf->enable_hq) {
        conf->upstream.quic.alpn.data = (unsigned char *)
                                        NGX_HTTP_V3_HQ_ALPN_PROTO;

        conf->upstream.quic.alpn.len = sizeof(NGX_HTTP_V3_HQ_ALPN_PROTO) - 1;

    } else {
        conf->upstream.quic.alpn.data = (unsigned char *)
                                        NGX_HTTP_V3_ALPN_PROTO;

        conf->upstream.quic.alpn.len = sizeof(NGX_HTTP_V3_ALPN_PROTO) - 1;
    }

    if (conf->upstream.h3_settings.max_table_capacity != NGX_CONF_UNSET_UINT) {
        /* really set in user config */
        conf->max_table_capacity_set = 1;
    }

    ngx_conf_merge_uint_value(conf->upstream.h3_settings.max_table_capacity,
                              prev->upstream.h3_settings.max_table_capacity,
                              NGX_HTTP_V3_MAX_TABLE_CAPACITY);

    ngx_conf_merge_uint_value(conf->upstream.h3_settings.max_concurrent_streams,
                              prev->upstream.h3_settings.max_concurrent_streams,
                              128);

    conf->upstream.h3_settings.max_blocked_streams =
                             conf->upstream.h3_settings.max_concurrent_streams;

    ngx_conf_merge_size_value(conf->upstream.quic.stream_buffer_size,
                              prev->upstream.quic.stream_buffer_size,
                              65536);

    conf->upstream.quic.max_concurrent_streams_bidi =
                             conf->upstream.h3_settings.max_concurrent_streams;

    ngx_conf_merge_value(conf->upstream.quic.gso_enabled,
                         prev->upstream.quic.gso_enabled,
                         0);

    ngx_conf_merge_uint_value(conf->upstream.quic.active_connection_id_limit,
                              prev->upstream.quic.active_connection_id_limit,
                              2);

    conf->upstream.quic.idle_timeout = conf->upstream.read_timeout;
    conf->upstream.quic.handshake_timeout = conf->upstream.connect_timeout;

    ngx_conf_merge_str_value(conf->upstream.quic.host_key,
                             prev->upstream.quic.host_key, "");


    if (conf->http_version == NGX_HTTP_VERSION_30) {
        if (ngx_http_v3_proxy_merge_quic(cf, conf, prev) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

#endif

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    if (clcf->noname
        && conf->upstream.upstream == NULL && conf->proxy_lengths == NULL)
    {
        conf->upstream.upstream = prev->upstream.upstream;
        conf->location = prev->location;
        conf->vars = prev->vars;
#if (NGX_HTTP_V3)
        conf->host = prev->host;
#endif

        conf->proxy_lengths = prev->proxy_lengths;
        conf->proxy_values = prev->proxy_values;

#if (NGX_HTTP_SSL)
        conf->ssl = prev->ssl;
#endif
    }

    if (clcf->lmt_excpt && clcf->handler == NULL
        && (conf->upstream.upstream || conf->proxy_lengths))
    {
        clcf->handler = ngx_http_proxy_handler;
    }

    if (conf->body_source.data == NULL) {
        conf->body_flushes = prev->body_flushes;
        conf->body_source = prev->body_source;
        conf->body_lengths = prev->body_lengths;
        conf->body_values = prev->body_values;
    }

    if (conf->body_source.data && conf->body_lengths == NULL) {

        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = &conf->body_source;
        sc.flushes = &conf->body_flushes;
        sc.lengths = &conf->body_lengths;
        sc.values = &conf->body_values;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    ngx_conf_merge_ptr_value(conf->headers_source, prev->headers_source, NULL);

    if (conf->headers_source == prev->headers_source
#if (NGX_HTTP_V3)
        /* H3 uses own set of headers, so do not inherit on version change */
        && !((conf->http_version == NGX_HTTP_VERSION_30
              || prev->http_version == NGX_HTTP_VERSION_30)
             && conf->http_version != prev->http_version)
#endif
       )
    {
        conf->headers = prev->headers;
#if (NGX_HTTP_CACHE)
        conf->headers_cache = prev->headers_cache;
#endif

#if (NGX_HTTP_V3)
        conf->host_set = prev->host_set;
#endif
    }

    proxy_headers = ngx_http_proxy_headers;

#if (NGX_HTTP_V3)
    if (conf->http_version == NGX_HTTP_VERSION_30) {
        proxy_headers = ngx_http_v3_proxy_headers;
    }
#endif

    rc = ngx_http_proxy_init_headers(cf, conf, &conf->headers, proxy_headers);
    if (rc != NGX_OK) {
        return NGX_CONF_ERROR;
    }

#if (NGX_HTTP_CACHE)

    if (conf->upstream.cache) {

        proxy_headers = ngx_http_proxy_cache_headers;

#if (NGX_HTTP_V3)
        if (conf->http_version == NGX_HTTP_VERSION_30) {
            proxy_headers = ngx_http_v3_proxy_cache_headers;
        }
#endif

        rc = ngx_http_proxy_init_headers(cf, conf, &conf->headers_cache,
                                         proxy_headers);
        if (rc != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

#endif

    /*
     * special handling to preserve conf->headers in the "http" section
     * to inherit it to all servers
     */

    if (prev->headers.hash.buckets == NULL
        && conf->headers_source == prev->headers_source)
    {
        prev->headers = conf->headers;
#if (NGX_HTTP_CACHE)
        prev->headers_cache = conf->headers_cache;
#endif

#if (NGX_HTTP_V3)
        conf->host_set = prev->host_set;
#endif
    }

    return NGX_CONF_OK;
}


#if (NGX_HTTP_SSL)

static ngx_int_t
ngx_http_proxy_preserve_ssl_passwords(ngx_conf_t *cf,
    ngx_http_upstream_conf_t *conf, ngx_http_upstream_conf_t *prev)
{
#if (NGX_HTTP_PROXY_MULTICERT)
    if (conf->ssl_certificates == NULL)
#else
    if (conf->ssl_certificate == NULL
        || conf->ssl_certificate->value.len == 0
        || conf->ssl_certificate_key == NULL)
#endif
    {
        return NGX_OK;
    }

#if (NGX_HTTP_PROXY_MULTICERT)
    if (conf->ssl_certificate_values == NULL
        || conf->ssl_certificate_key_values == NULL)
#else
    if (conf->ssl_certificate->lengths == NULL
        && conf->ssl_certificate_key->lengths == NULL)
#endif
    {
        if (conf->ssl_passwords && conf->ssl_passwords->pool == NULL) {
            /* un-preserve empty password list */
            conf->ssl_passwords = NULL;
        }

        return NGX_OK;
    }

    return ngx_http_upstream_preserve_ssl_passwords(cf, conf, prev);
}

#endif


static ngx_int_t
ngx_http_proxy_init_headers(ngx_conf_t *cf, ngx_http_proxy_loc_conf_t *conf,
    ngx_http_proxy_headers_t *headers, ngx_keyval_t *default_headers)
{
    u_char                       *p;
    size_t                        size;
    uintptr_t                    *code;
    ngx_uint_t                    i;
    ngx_array_t                   headers_names, headers_merged;
    ngx_keyval_t                 *src, *s, *h;
    ngx_hash_key_t               *hk;
    ngx_hash_init_t               hash;
    ngx_http_script_compile_t     sc;
    ngx_http_script_copy_code_t  *copy;

    if (headers->hash.buckets) {
        return NGX_OK;
    }

    if (ngx_array_init(&headers_names, cf->temp_pool, 4, sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_array_init(&headers_merged, cf->temp_pool, 4, sizeof(ngx_keyval_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    headers->lengths = ngx_array_create(cf->pool, 64, 1);
    if (headers->lengths == NULL) {
        return NGX_ERROR;
    }

    headers->values = ngx_array_create(cf->pool, 512, 1);
    if (headers->values == NULL) {
        return NGX_ERROR;
    }

    if (conf->headers_source) {

        src = conf->headers_source->elts;
        for (i = 0; i < conf->headers_source->nelts; i++) {

#if (NGX_HTTP_V3)
            if (src[i].key.len == 4
                && ngx_strncasecmp(src[i].key.data, (u_char *) "Host", 4) == 0)
            {
                conf->host_set = 1;
            }
#endif

            s = ngx_array_push(&headers_merged);
            if (s == NULL) {
                return NGX_ERROR;
            }

            *s = src[i];
        }
    }

    h = default_headers;

    while (h->key.len) {

        src = headers_merged.elts;
        for (i = 0; i < headers_merged.nelts; i++) {
            if (ngx_strcasecmp(h->key.data, src[i].key.data) == 0) {
                goto next;
            }
        }

        s = ngx_array_push(&headers_merged);
        if (s == NULL) {
            return NGX_ERROR;
        }

        *s = *h;

    next:

        h++;
    }


    src = headers_merged.elts;
    for (i = 0; i < headers_merged.nelts; i++) {

        hk = ngx_array_push(&headers_names);
        if (hk == NULL) {
            return NGX_ERROR;
        }

        hk->key = src[i].key;
        hk->key_hash = ngx_hash_key_lc(src[i].key.data, src[i].key.len);
        hk->value = (void *) 1;

        if (src[i].value.len == 0) {
            continue;
        }

        copy = ngx_array_push_n(headers->lengths,
                                sizeof(ngx_http_script_copy_code_t));
        if (copy == NULL) {
            return NGX_ERROR;
        }

        copy->code = (ngx_http_script_code_pt) (void *)
                                                 ngx_http_script_copy_len_code;
        copy->len = src[i].key.len;

        size = (sizeof(ngx_http_script_copy_code_t)
                + src[i].key.len + sizeof(uintptr_t) - 1)
               & ~(sizeof(uintptr_t) - 1);

        copy = ngx_array_push_n(headers->values, size);
        if (copy == NULL) {
            return NGX_ERROR;
        }

        copy->code = ngx_http_script_copy_code;
        copy->len = src[i].key.len;

        p = (u_char *) copy + sizeof(ngx_http_script_copy_code_t);
        ngx_memcpy(p, src[i].key.data, src[i].key.len);

        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = &src[i].value;
        sc.flushes = &headers->flushes;
        sc.lengths = &headers->lengths;
        sc.values = &headers->values;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_ERROR;
        }

        code = ngx_array_push_n(headers->lengths, sizeof(uintptr_t));
        if (code == NULL) {
            return NGX_ERROR;
        }

        *code = (uintptr_t) NULL;

        code = ngx_array_push_n(headers->values, sizeof(uintptr_t));
        if (code == NULL) {
            return NGX_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    code = ngx_array_push_n(headers->lengths, sizeof(uintptr_t));
    if (code == NULL) {
        return NGX_ERROR;
    }

    *code = (uintptr_t) NULL;


    hash.hash = &headers->hash;
    hash.key = ngx_hash_key_lc;
    hash.max_size = conf->headers_hash_max_size;
    hash.bucket_size = conf->headers_hash_bucket_size;
    hash.name = "proxy_headers_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    return ngx_hash_init(&hash, headers_names.elts, headers_names.nelts);
}


static char *
ngx_http_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_proxy_loc_conf_t *plcf = conf;

    size_t                      add;
    u_short                     port;
    ngx_str_t                  *value, *url;
    ngx_url_t                   u;
    ngx_uint_t                  n;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_script_compile_t   sc;

    if (plcf->upstream.upstream || plcf->proxy_lengths) {
        return "is duplicate";
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_proxy_handler;
    clcf->auto_redirect = 1;

    value = cf->args->elts;

    url = &value[1];

    n = ngx_http_script_variables_count(url);

    if (n) {

        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = url;
        sc.lengths = &plcf->proxy_lengths;
        sc.values = &plcf->proxy_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

#if (NGX_HTTP_SSL)
        plcf->ssl = 1;
#endif

        return NGX_CONF_OK;
    }

    if (ngx_strncasecmp(url->data, (u_char *) "http://", 7) == 0) {
        add = 7;
        port = 80;

    } else if (ngx_strncasecmp(url->data, (u_char *) "https://", 8) == 0) {

#if (NGX_HTTP_SSL)
        plcf->ssl = 1;

        add = 8;
        port = 443;
#else
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "https protocol requires SSL support");
        return NGX_CONF_ERROR;
#endif

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid URL prefix");
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url.len = url->len - add;
    u.url.data = url->data + add;
    u.default_port = port;
    u.uri_part = 1;
    u.no_resolve = 1;

    plcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
    if (plcf->upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    plcf->vars.schema.len = add;
    plcf->vars.schema.data = url->data;
    plcf->vars.key_start = plcf->vars.schema;

#if (NGX_HTTP_V3)
    if (u.family != AF_UNIX) {

        if (u.no_port) {
            plcf->host = u.host;

        } else {
            plcf->host.len = u.host.len + 1 + u.port_text.len;
            plcf->host.data = u.host.data;
        }

    } else {
        ngx_str_set(&plcf->host, "localhost");
    }
#endif

    ngx_http_proxy_set_vars(&u, &plcf->vars);

    plcf->location = clcf->name;

    if (clcf->named
#if (NGX_PCRE)
        || clcf->regex
#endif
        || clcf->noname
        || clcf->combined != NULL)
    {
        if (plcf->vars.uri.len) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"proxy_pass\" cannot have URI part in "
                               "a location specified with a regex, "
                               "inside a named location, "
                               "inside a combined location, "
                               "inside an \"if\" statement, "
                               "or inside a \"limit_except\" block");
            return NGX_CONF_ERROR;
        }

        plcf->location.len = 0;
    }

    plcf->url = *url;

    return NGX_CONF_OK;
}


static char *
ngx_http_proxy_redirect(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_proxy_loc_conf_t *plcf = conf;

    u_char                            *p;
    ngx_str_t                         *value;
    ngx_http_proxy_rewrite_t          *pr;
    ngx_http_compile_complex_value_t   ccv;

    if (plcf->redirect == 0) {
        return "is duplicate";
    }

    plcf->redirect = 1;

    value = cf->args->elts;

    if (cf->args->nelts == 2) {
        if (ngx_strcmp(value[1].data, "off") == 0) {

            if (plcf->redirects) {
                return "is duplicate";
            }

            plcf->redirect = 0;
            return NGX_CONF_OK;
        }

        if (ngx_strcmp(value[1].data, "default") != 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }
    }

    if (plcf->redirects == NULL) {
        plcf->redirects = ngx_array_create(cf->pool, 1,
                                           sizeof(ngx_http_proxy_rewrite_t));
        if (plcf->redirects == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    pr = ngx_array_push(plcf->redirects);
    if (pr == NULL) {
        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts == 2
        && ngx_strcmp(value[1].data, "default") == 0)
    {
        if (plcf->proxy_lengths) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"proxy_redirect default\" cannot be used "
                               "with \"proxy_pass\" directive with variables");
            return NGX_CONF_ERROR;
        }

        if (plcf->url.data == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"proxy_redirect default\" should be placed "
                               "after the \"proxy_pass\" directive");
            return NGX_CONF_ERROR;
        }

        pr->handler = ngx_http_proxy_rewrite_complex_handler;

        ngx_memzero(&pr->pattern.complex, sizeof(ngx_http_complex_value_t));

        ngx_memzero(&pr->replacement, sizeof(ngx_http_complex_value_t));

        if (plcf->vars.uri.len) {
            pr->pattern.complex.value = plcf->url;
            pr->replacement.value = plcf->location;

        } else {
            pr->pattern.complex.value.len = plcf->url.len + sizeof("/") - 1;

            p = ngx_pnalloc(cf->pool, pr->pattern.complex.value.len);
            if (p == NULL) {
                return NGX_CONF_ERROR;
            }

            pr->pattern.complex.value.data = p;

            p = ngx_cpymem(p, plcf->url.data, plcf->url.len);
            *p = '/';

            ngx_str_set(&pr->replacement.value, "/");
        }

        return NGX_CONF_OK;
    }


    if (value[1].data[0] == '~') {
        value[1].len--;
        value[1].data++;

        if (value[1].data[0] == '*') {
            value[1].len--;
            value[1].data++;

            if (ngx_http_proxy_rewrite_regex(cf, pr, &value[1], 1) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

        } else {
            if (ngx_http_proxy_rewrite_regex(cf, pr, &value[1], 0) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }

    } else {

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[1];
        ccv.complex_value = &pr->pattern.complex;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        pr->handler = ngx_http_proxy_rewrite_complex_handler;
    }


    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &pr->replacement;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_proxy_cookie_domain(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_proxy_loc_conf_t *plcf = conf;

    ngx_str_t                         *value;
    ngx_http_proxy_rewrite_t          *pr;
    ngx_http_compile_complex_value_t   ccv;

    if (plcf->cookie_domains == NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->args->nelts == 2) {

        if (ngx_strcmp(value[1].data, "off") == 0) {

            if (plcf->cookie_domains != NGX_CONF_UNSET_PTR) {
                return "is duplicate";
            }

            plcf->cookie_domains = NULL;
            return NGX_CONF_OK;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (plcf->cookie_domains == NGX_CONF_UNSET_PTR) {
        plcf->cookie_domains = ngx_array_create(cf->pool, 1,
                                     sizeof(ngx_http_proxy_rewrite_t));
        if (plcf->cookie_domains == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    pr = ngx_array_push(plcf->cookie_domains);
    if (pr == NULL) {
        return NGX_CONF_ERROR;
    }

    if (value[1].data[0] == '~') {
        value[1].len--;
        value[1].data++;

        if (ngx_http_proxy_rewrite_regex(cf, pr, &value[1], 1) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

    } else {

        if (value[1].data[0] == '.') {
            value[1].len--;
            value[1].data++;
        }

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[1];
        ccv.complex_value = &pr->pattern.complex;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        pr->handler = ngx_http_proxy_rewrite_domain_handler;

        if (value[2].data[0] == '.') {
            value[2].len--;
            value[2].data++;
        }
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &pr->replacement;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_proxy_cookie_path(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_proxy_loc_conf_t *plcf = conf;

    ngx_str_t                         *value;
    ngx_http_proxy_rewrite_t          *pr;
    ngx_http_compile_complex_value_t   ccv;

    if (plcf->cookie_paths == NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->args->nelts == 2) {

        if (ngx_strcmp(value[1].data, "off") == 0) {

            if (plcf->cookie_paths != NGX_CONF_UNSET_PTR) {
                return "is duplicate";
            }

            plcf->cookie_paths = NULL;
            return NGX_CONF_OK;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (plcf->cookie_paths == NGX_CONF_UNSET_PTR) {
        plcf->cookie_paths = ngx_array_create(cf->pool, 1,
                                     sizeof(ngx_http_proxy_rewrite_t));
        if (plcf->cookie_paths == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    pr = ngx_array_push(plcf->cookie_paths);
    if (pr == NULL) {
        return NGX_CONF_ERROR;
    }

    if (value[1].data[0] == '~') {
        value[1].len--;
        value[1].data++;

        if (value[1].data[0] == '*') {
            value[1].len--;
            value[1].data++;

            if (ngx_http_proxy_rewrite_regex(cf, pr, &value[1], 1) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

        } else {
            if (ngx_http_proxy_rewrite_regex(cf, pr, &value[1], 0) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }

    } else {

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[1];
        ccv.complex_value = &pr->pattern.complex;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        pr->handler = ngx_http_proxy_rewrite_complex_handler;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &pr->replacement;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_proxy_cookie_flags(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_proxy_loc_conf_t *plcf = conf;

    ngx_str_t                         *value;
    ngx_uint_t                         i;
    ngx_http_complex_value_t          *cv;
    ngx_http_proxy_cookie_flags_t     *pcf;
    ngx_http_compile_complex_value_t   ccv;
#if (NGX_PCRE)
    ngx_regex_compile_t                rc;
    u_char                             errstr[NGX_MAX_CONF_ERRSTR];
#endif

    if (plcf->cookie_flags == NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->args->nelts == 2) {

        if (ngx_strcmp(value[1].data, "off") == 0) {

            if (plcf->cookie_flags != NGX_CONF_UNSET_PTR) {
                return "is duplicate";
            }

            plcf->cookie_flags = NULL;
            return NGX_CONF_OK;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (plcf->cookie_flags == NGX_CONF_UNSET_PTR) {
        plcf->cookie_flags = ngx_array_create(cf->pool, 1,
                                        sizeof(ngx_http_proxy_cookie_flags_t));
        if (plcf->cookie_flags == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    pcf = ngx_array_push(plcf->cookie_flags);
    if (pcf == NULL) {
        return NGX_CONF_ERROR;
    }

    pcf->regex = 0;

    if (value[1].data[0] == '~') {
        value[1].len--;
        value[1].data++;

#if (NGX_PCRE)
        ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

        rc.pattern = value[1];
        rc.err.len = NGX_MAX_CONF_ERRSTR;
        rc.err.data = errstr;
        rc.options = NGX_REGEX_CASELESS;

        pcf->cookie.regex = ngx_http_regex_compile(cf, &rc);
        if (pcf->cookie.regex == NULL) {
            return NGX_CONF_ERROR;
        }

        pcf->regex = 1;
#else
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "using regex \"%V\" requires PCRE library",
                           &value[1]);
        return NGX_CONF_ERROR;
#endif

    } else {

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[1];
        ccv.complex_value = &pcf->cookie.complex;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    if (ngx_array_init(&pcf->flags_values, cf->pool, cf->args->nelts - 2,
                       sizeof(ngx_http_complex_value_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    for (i = 2; i < cf->args->nelts; i++) {

        cv = ngx_array_push(&pcf->flags_values);
        if (cv == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[i];
        ccv.complex_value = cv;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_proxy_rewrite_regex(ngx_conf_t *cf, ngx_http_proxy_rewrite_t *pr,
    ngx_str_t *regex, ngx_uint_t caseless)
{
#if (NGX_PCRE)
    u_char               errstr[NGX_MAX_CONF_ERRSTR];
    ngx_regex_compile_t  rc;

    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

    rc.pattern = *regex;
    rc.err.len = NGX_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

    if (caseless) {
        rc.options = NGX_REGEX_CASELESS;
    }

    pr->pattern.regex = ngx_http_regex_compile(cf, &rc);
    if (pr->pattern.regex == NULL) {
        return NGX_ERROR;
    }

    pr->handler = ngx_http_proxy_rewrite_regex_handler;

    return NGX_OK;

#else

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "using regex \"%V\" requires PCRE library", regex);
    return NGX_ERROR;

#endif
}


static char *
ngx_http_proxy_store(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_proxy_loc_conf_t *plcf = conf;

    ngx_str_t                  *value;
    ngx_http_script_compile_t   sc;

    if (plcf->upstream.store != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        plcf->upstream.store = 0;
        return NGX_CONF_OK;
    }

    if (value[1].len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "empty path");
        return NGX_CONF_ERROR;
    }

#if (NGX_HTTP_CACHE)
    if (plcf->upstream.cache > 0) {
        return "is incompatible with \"proxy_cache\"";
    }
#endif

    plcf->upstream.store = 1;

    if (ngx_strcmp(value[1].data, "on") == 0) {
        return NGX_CONF_OK;
    }

    /* include the terminating '\0' into script */
    value[1].len++;

    ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

    sc.cf = cf;
    sc.source = &value[1];
    sc.lengths = &plcf->upstream.store_lengths;
    sc.values = &plcf->upstream.store_values;
    sc.variables = ngx_http_script_variables_count(&value[1]);
    sc.complete_lengths = 1;
    sc.complete_values = 1;

    if (ngx_http_script_compile(&sc) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


#if (NGX_HTTP_CACHE)

static char *
ngx_http_proxy_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_proxy_loc_conf_t *plcf = conf;

    ngx_str_t                         *value;
    ngx_shm_zone_params_t              zp;
    ngx_http_complex_value_t           cv;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (plcf->upstream.cache != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    if (ngx_strcmp(value[1].data, "off") == 0) {
        plcf->upstream.cache = 0;
        return NGX_CONF_OK;
    }

    if (plcf->upstream.store > 0) {
        return "is incompatible with \"proxy_store\"";
    }

    plcf->upstream.cache = 1;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cv.lengths != NULL) {

        plcf->upstream.cache_value = ngx_palloc(cf->pool,
                                             sizeof(ngx_http_complex_value_t));
        if (plcf->upstream.cache_value == NULL) {
            return NGX_CONF_ERROR;
        }

        *plcf->upstream.cache_value = cv;

        return NGX_CONF_OK;
    }

    ngx_memzero(&zp, sizeof(ngx_shm_zone_params_t));

    zp.size = NGX_CONF_UNSET;

    if (ngx_conf_parse_zone_spec(cf, &zp, &value[1]) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    plcf->upstream.cache_zone = ngx_shared_memory_add(cf, &zp.name, 0,
                                                      &ngx_http_proxy_module);
    if (plcf->upstream.cache_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_proxy_cache_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_proxy_loc_conf_t *plcf = conf;

    ngx_str_t                         *value;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (plcf->cache_key.value.data) {
        return "is duplicate";
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &plcf->cache_key;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

#endif


#if (NGX_HTTP_SSL)

static char *
ngx_http_proxy_ssl_certificate_cache(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_proxy_loc_conf_t *plcf = conf;

    time_t       inactive, valid;
    ngx_str_t   *value, s;
    ngx_int_t    max;
    ngx_uint_t   i;

    if (plcf->upstream.ssl_certificate_cache != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    max = 0;
    inactive = 10;
    valid = 60;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "max=", 4) == 0) {

            max = ngx_atoi(value[i].data + 4, value[i].len - 4);
            if (max <= 0) {
                goto failed;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "inactive=", 9) == 0) {

            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            inactive = ngx_parse_time(&s, 1);
            if (inactive == (time_t) NGX_ERROR) {
                goto failed;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "valid=", 6) == 0) {

            s.len = value[i].len - 6;
            s.data = value[i].data + 6;

            valid = ngx_parse_time(&s, 1);
            if (valid == (time_t) NGX_ERROR) {
                goto failed;
            }

            continue;
        }

        if (ngx_strcmp(value[i].data, "off") == 0) {

            plcf->upstream.ssl_certificate_cache = NULL;

            continue;
        }

    failed:

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (plcf->upstream.ssl_certificate_cache == NULL) {
        return NGX_CONF_OK;
    }

    if (max == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"proxy_ssl_certificate_cache\" must have "
                           "the \"max\" parameter");
        return NGX_CONF_ERROR;
    }

    plcf->upstream.ssl_certificate_cache = ngx_ssl_cache_init(cf->pool, max,
                                                              valid, inactive);
    if (plcf->upstream.ssl_certificate_cache == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_proxy_ssl_password_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_proxy_loc_conf_t *plcf = conf;

    ngx_str_t  *value;

    if (plcf->upstream.ssl_passwords != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    plcf->upstream.ssl_passwords = ngx_ssl_read_password_file(cf, &value[1]);

    if (plcf->upstream.ssl_passwords == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

#endif


static char *
ngx_http_proxy_lowat_check(ngx_conf_t *cf, void *post, void *data)
{
#if (NGX_FREEBSD)
    ssize_t *np = data;

    if ((u_long) *np >= ngx_freebsd_net_inet_tcp_sendspace) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"proxy_send_lowat\" must be less than %d "
                           "(sysctl net.inet.tcp.sendspace)",
                           ngx_freebsd_net_inet_tcp_sendspace);

        return NGX_CONF_ERROR;
    }

#elif !(NGX_HAVE_SO_SNDLOWAT)
    ssize_t *np = data;

    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "\"proxy_send_lowat\" is not supported, ignored");

    *np = 0;

#endif

    return NGX_CONF_OK;
}


#if (NGX_HTTP_SSL)

static char *
ngx_http_proxy_ssl_conf_command_check(ngx_conf_t *cf, void *post, void *data)
{
#ifndef SSL_CONF_FLAG_FILE
    return "is not supported on this platform";
#else
    return NGX_CONF_OK;
#endif
}


static ngx_int_t
ngx_http_proxy_merge_ssl(ngx_conf_t *cf, ngx_http_proxy_loc_conf_t *conf,
    ngx_http_proxy_loc_conf_t *prev)
{
    ngx_uint_t  preserve;

    if (conf->ssl_protocols == 0
        && conf->ssl_ciphers.data == NULL
#if (NGX_HTTP_PROXY_MULTICERT)
        && conf->upstream.ssl_certificates == NGX_CONF_UNSET_PTR
        && conf->upstream.ssl_certificate_keys == NGX_CONF_UNSET_PTR
#else
        && conf->upstream.ssl_certificate == NGX_CONF_UNSET_PTR
        && conf->upstream.ssl_certificate_key == NGX_CONF_UNSET_PTR
#endif
        && conf->upstream.ssl_passwords == NGX_CONF_UNSET_PTR
        && conf->upstream.ssl_verify == NGX_CONF_UNSET
        && conf->ssl_verify_depth == NGX_CONF_UNSET_UINT
        && conf->ssl_trusted_certificate.data == NULL
        && conf->ssl_crl.data == NULL
        && conf->upstream.ssl_session_reuse == NGX_CONF_UNSET
#if (NGX_HAVE_NTLS)
        && conf->upstream.ssl_ntls == NGX_CONF_UNSET
#endif
        && conf->ssl_conf_commands == NGX_CONF_UNSET_PTR)
    {
        if (prev->upstream.ssl) {
            conf->upstream.ssl = prev->upstream.ssl;
            return NGX_OK;
        }

        preserve = 1;

    } else {
        preserve = 0;
    }

    conf->upstream.ssl = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
    if (conf->upstream.ssl == NULL) {
        return NGX_ERROR;
    }

    conf->upstream.ssl->log = cf->log;

    /*
     * special handling to preserve conf->upstream.ssl
     * in the "http" section to inherit it to all servers
     */

    if (preserve) {
        prev->upstream.ssl = conf->upstream.ssl;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_set_ssl(ngx_conf_t *cf, ngx_http_proxy_loc_conf_t *plcf)
{
    ngx_pool_cleanup_t  *cln;

    if (plcf->upstream.ssl->ctx) {
        return NGX_OK;
    }

    if (ngx_ssl_create(plcf->upstream.ssl, plcf->ssl_protocols, NULL)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

#if (NGX_HTTP_V3 && NGX_QUIC_OPENSSL_COMPAT)
    if (ngx_quic_compat_init(cf, plcf->upstream.ssl->ctx) != NGX_OK) {
        return NGX_ERROR;
    }
#endif

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        ngx_ssl_cleanup_ctx(plcf->upstream.ssl);
        return NGX_ERROR;
    }

    cln->handler = ngx_ssl_cleanup_ctx;
    cln->data = plcf->upstream.ssl;

    if (ngx_ssl_ciphers(cf, plcf->upstream.ssl, &plcf->ssl_ciphers, 0)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

#if (NGX_HTTP_PROXY_MULTICERT)

    if (plcf->upstream.ssl_certificates
        && plcf->upstream.ssl_certificate_values == NULL)
    {
        if (ngx_ssl_certificates(cf, plcf->upstream.ssl,
                                 plcf->upstream.ssl_certificates,
                                 plcf->upstream.ssl_certificate_keys,
                                 plcf->upstream.ssl_passwords)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

#else

    if (plcf->upstream.ssl_certificate
        && plcf->upstream.ssl_certificate->value.len)
    {
        if (plcf->upstream.ssl_certificate_key == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "no \"proxy_ssl_certificate_key\" is defined "
                          "for certificate \"%V\"",
                          &plcf->upstream.ssl_certificate->value);
            return NGX_ERROR;
        }

        if (plcf->upstream.ssl_certificate->lengths == NULL
            && plcf->upstream.ssl_certificate_key->lengths == NULL)
        {
            if (ngx_ssl_certificate(cf, plcf->upstream.ssl,
                                    &plcf->upstream.ssl_certificate->value,
                                    &plcf->upstream.ssl_certificate_key->value,
                                    plcf->upstream.ssl_passwords)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
    }

#endif

    if (plcf->upstream.ssl_verify) {
        if (plcf->ssl_trusted_certificate.len == 0) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "no proxy_ssl_trusted_certificate for proxy_ssl_verify");
            return NGX_ERROR;
        }

        if (ngx_ssl_trusted_certificate(cf, plcf->upstream.ssl,
                                        &plcf->ssl_trusted_certificate,
                                        plcf->ssl_verify_depth)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (ngx_ssl_crl(cf, plcf->upstream.ssl, &plcf->ssl_crl) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (ngx_ssl_client_session_cache(cf, plcf->upstream.ssl,
                                     plcf->upstream.ssl_session_reuse)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_ssl_conf_commands(cf, plcf->upstream.ssl, plcf->ssl_conf_commands)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


#if (NGX_HTTP_PROXY_MULTICERT)

static ngx_int_t
ngx_http_proxy_compile_certificates(ngx_conf_t *cf,
    ngx_http_proxy_loc_conf_t *plcf)
{
    ngx_str_t                cert;
    ngx_http_ssl_srv_conf_t  scf;

    cert = *((ngx_str_t *) plcf->upstream.ssl_certificates->elts);
#if (NGX_HAVE_NTLS)
    ngx_ssl_ntls_prefix_strip(&cert);
#endif

    if (plcf->upstream.ssl_certificates->nelts == 1 && cert.len == 0) {
        /* single empty certificate: cancel certificate loading */

        plcf->upstream.ssl_certificates = NULL;
        plcf->upstream.ssl_certificate_values = NULL;
        plcf->upstream.ssl_certificate_key_values = NULL;

        return NGX_OK;
    }

    if (plcf->upstream.ssl_certificate_keys == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "no \"proxy_ssl_certificate_key\" is defined "
                      "for certificate \"%V\"", &cert);
        return NGX_ERROR;
    }

    if (plcf->upstream.ssl_certificate_keys->nelts
        < plcf->upstream.ssl_certificates->nelts)
    {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "number of \"proxy_ssl_certificate_key\" does not "
                      "correspond \"proxy_ssl_ssl_certificate\"");
        return NGX_ERROR;
    }

    ngx_memzero(&scf, sizeof(ngx_http_ssl_srv_conf_t));

    scf.certificates = plcf->upstream.ssl_certificates;
    scf.certificate_keys = plcf->upstream.ssl_certificate_keys;
    scf.passwords = plcf->upstream.ssl_passwords;

    if (ngx_http_ssl_compile_certificates(cf, &scf) != NGX_OK) {
        return NGX_ERROR;
    }

    plcf->upstream.ssl_passwords = scf.passwords;
    plcf->upstream.ssl_certificate_values = scf.certificate_values;
    plcf->upstream.ssl_certificate_key_values = scf.certificate_key_values;

    return NGX_OK;
}

#endif

#endif


static void
ngx_http_proxy_set_vars(ngx_url_t *u, ngx_http_proxy_vars_t *v)
{
    if (u->family != AF_UNIX) {

        if (u->no_port || u->port == u->default_port) {

            v->host_header = u->host;

            if (u->default_port == 80) {
                ngx_str_set(&v->port, "80");

            } else {
                ngx_str_set(&v->port, "443");
            }

        } else {
            v->host_header.len = u->host.len + 1 + u->port_text.len;
            v->host_header.data = u->host.data;
            v->port = u->port_text;
        }

        v->key_start.len += v->host_header.len;

    } else {
        ngx_str_set(&v->host_header, "localhost");
        ngx_str_null(&v->port);
        v->key_start.len += sizeof("unix:") - 1 + u->host.len + 1;
    }

    v->uri = u->uri;
}


#if (NGX_HTTP_V3)

static char *
ngx_http_v3_proxy_host_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_proxy_loc_conf_t *plcf = conf;

    u_char           *buf;
    size_t            size;
    ssize_t           n;
    ngx_str_t        *value;
    ngx_file_t        file;
    ngx_file_info_t   fi;
    ngx_quic_conf_t  *qcf;

    qcf = &plcf->upstream.quic;

    if (qcf->host_key.len) {
        return "is duplicate";
    }

    buf = NULL;
#if (NGX_SUPPRESS_WARN)
    size = 0;
#endif

    value = cf->args->elts;

    if (ngx_conf_full_name(cf->cycle, &value[1], 1) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.name = value[1];
    file.log = cf->log;

    file.fd = ngx_open_file(file.name.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);

    if (file.fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_open_file_n " \"%V\" failed", &file.name);
        return NGX_CONF_ERROR;
    }

    if (ngx_fd_info(file.fd, &fi) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                           ngx_fd_info_n " \"%V\" failed", &file.name);
        goto failed;
    }

    size = ngx_file_size(&fi);

    if (size == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" zero key size", &file.name);
        goto failed;
    }

    buf = ngx_pnalloc(cf->pool, size);
    if (buf == NULL) {
        goto failed;
    }

    n = ngx_read_file(&file, buf, size, 0);

    if (n == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                           ngx_read_file_n " \"%V\" failed", &file.name);
        goto failed;
    }

    if ((size_t) n != size) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, 0,
                           ngx_read_file_n " \"%V\" returned only "
                           "%z bytes instead of %uz", &file.name, n, size);
        goto failed;
    }

    qcf->host_key.data = buf;
    qcf->host_key.len = n;

    if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
                      ngx_close_file_n " \"%V\" failed", &file.name);
    }

    return NGX_CONF_OK;

failed:

    if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
                      ngx_close_file_n " \"%V\" failed", &file.name);
    }

    if (buf) {
        ngx_explicit_memzero(buf, size);
    }

    return NGX_CONF_ERROR;
}


static ngx_int_t
ngx_http_v3_proxy_merge_quic(ngx_conf_t *cf, ngx_http_proxy_loc_conf_t *conf,
    ngx_http_proxy_loc_conf_t *prev)
{
    if ((conf->upstream.upstream || conf->proxy_lengths)
        && (conf->ssl == 0 || conf->upstream.ssl == NULL))
    {
        /* we have proxy_pass, http/3 and no ssl - this isn't going to work */

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "http3 proxy requires ssl configuration "
                           "and https:// scheme");
        return NGX_ERROR;
    }


    if (conf->upstream.quic.host_key.len == 0) {

        conf->upstream.quic.host_key.len = NGX_QUIC_DEFAULT_HOST_KEY_LEN;
        conf->upstream.quic.host_key.data = ngx_palloc(cf->pool,
                                             conf->upstream.quic.host_key.len);

        if (conf->upstream.quic.host_key.data == NULL) {
            return NGX_ERROR;
        }

        if (RAND_bytes(conf->upstream.quic.host_key.data,
                       NGX_QUIC_DEFAULT_HOST_KEY_LEN)
            <= 0)
        {
            return NGX_ERROR;
        }
    }

    if (ngx_quic_derive_key(cf->log, "av_token_key",
                            &conf->upstream.quic.host_key,
                            &ngx_http_v3_proxy_quic_salt,
                            conf->upstream.quic.av_token_key,
                            NGX_QUIC_AV_KEY_LEN)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_quic_derive_key(cf->log, "sr_token_key",
                            &conf->upstream.quic.host_key,
                            &ngx_http_v3_proxy_quic_salt,
                            conf->upstream.quic.sr_token_key,
                            NGX_QUIC_SR_KEY_LEN)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    conf->upstream.quic.ssl = conf->upstream.ssl;

#if (NGX_HTTP_CACHE)

        if (conf->upstream.cache
            && conf->upstream.h3_settings.max_table_capacity)
        {
            if (conf->max_table_capacity_set) {

                /* the setting is present in config file, refuse to accept it */
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "http3 cache does not work with dynamic table");

                return NGX_ERROR;
            }

            /* the value is from defaults, disable dynamic table */
            conf->upstream.h3_settings.max_table_capacity = 0;
        }
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_proxy_create_request(ngx_http_request_t *r)
{
    ngx_buf_t                  *b;
    ngx_chain_t                *cl, *body, *out;
    ngx_http_upstream_t        *u;
    ngx_http_proxy_ctx_t       *ctx;
    ngx_http_v3_proxy_ctx_t     v3c;
    ngx_http_proxy_headers_t   *headers;
    ngx_http_proxy_loc_conf_t  *plcf;

    /*
     * HTTP/3 Request:
     *
     * HEADERS FRAME
     *    :method:
     *    :scheme:
     *    :path:
     *    :authority:
     *     proxy headers[]
     *     client headers[]
     *
     * DATA FRAME
     *    body
     *
     * HEADERS FRAME
     *    trailers[]
     */

    u = r->upstream;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

#if (NGX_HTTP_CACHE)
    headers = u->cacheable ? &plcf->headers_cache : &plcf->headers;
#else
    headers = &plcf->headers;
#endif

    ngx_memzero(&v3c, sizeof(ngx_http_v3_proxy_ctx_t));

    ngx_http_script_flush_no_cacheable_variables(r, plcf->body_flushes);
    ngx_http_script_flush_no_cacheable_variables(r, headers->flushes);

    v3c.headers = headers;

    v3c.n = ngx_http_v3_encode_field_section_prefix(NULL, 0, 0, 0);

    /* calculate lengths */

    ngx_http_v3_proxy_encode_method(r, &v3c, NULL);

    v3c.n += ngx_http_v3_encode_field_ri(NULL, 0,
                                         NGX_HTTP_V3_HEADER_SCHEME_HTTPS);

    if (ngx_http_v3_proxy_encode_path(r, &v3c, NULL) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_v3_proxy_encode_authority(r, &v3c, NULL) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_v3_proxy_body_length(r, &v3c) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_v3_proxy_encode_headers(r, &v3c, NULL) != NGX_OK) {
        return NGX_ERROR;
    }

    /* generate HTTP/3 request of known size */

    b = ngx_create_temp_buf(r->pool, v3c.n);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->last = (u_char *) ngx_http_v3_encode_field_section_prefix(b->last,
                                                                 0, 0, 0);

    if (ngx_http_v3_proxy_encode_method(r, &v3c, b) != NGX_OK) {
        return NGX_ERROR;
    }

    b->last = (u_char *) ngx_http_v3_encode_field_ri(b->last, 0,
                                              NGX_HTTP_V3_HEADER_SCHEME_HTTPS);

    if (ngx_http_v3_proxy_encode_path(r, &v3c, b) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_v3_proxy_encode_authority(r, &v3c, b) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_v3_proxy_encode_headers(r, &v3c, b) != NGX_OK) {
        return NGX_ERROR;
    }

    out = ngx_http_v3_create_headers_frame(r, b);
    if (out == NGX_CHAIN_ERROR) {
        return NGX_ERROR;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (r->request_body_no_buffering || ctx->internal_chunked) {
        u->output.output_filter = ngx_http_v3_proxy_body_output_filter;
        u->output.filter_ctx = r;

    } else if (ctx->internal_body_length != -1) {

        body = ngx_http_v3_proxy_encode_body(r, &v3c);
        if (body == NGX_CHAIN_ERROR) {
            return NGX_ERROR;
        }

        body = ngx_http_v3_create_data_frame(r, body,
                                             ctx->internal_body_length);
        if (body == NGX_CHAIN_ERROR) {
            return NGX_ERROR;
        }

        for (cl = out; cl->next; cl = cl->next) { /* void */ }
        cl->next = body;
    }

    /* TODO: trailers */

    u->request_bufs = out;

    return NGX_OK;
}


static ngx_chain_t *
ngx_http_v3_create_headers_frame(ngx_http_request_t *r, ngx_buf_t *hbuf)
{
    ngx_buf_t    *b;
    size_t        n, len;
    ngx_chain_t  *cl, *head;

    n = hbuf->last - hbuf->pos;

    len = ngx_http_v3_encode_varlen_int(NULL, NGX_HTTP_V3_FRAME_HEADERS)
          + ngx_http_v3_encode_varlen_int(NULL, n);

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_CHAIN_ERROR;
    }

    b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->last,
                                                    NGX_HTTP_V3_FRAME_HEADERS);
    b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->last, n);

    /* mark our header buffers to distinguish them in non-buffered filter */
    b->tag = (ngx_buf_tag_t) &ngx_http_v3_create_headers_frame;
    hbuf->tag = (ngx_buf_tag_t) &ngx_http_v3_create_headers_frame;

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_CHAIN_ERROR;
    }

    cl->buf = b;
    head = cl;

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_CHAIN_ERROR;
    }

    cl->buf = hbuf;
    cl->next = NULL;

    head->next = cl;

    return head;
}


static ngx_chain_t *
ngx_http_v3_create_data_frame(ngx_http_request_t *r, ngx_chain_t *body,
    size_t size)
{
    size_t        len;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    len = ngx_http_v3_encode_varlen_int(NULL, NGX_HTTP_V3_FRAME_DATA)
          + ngx_http_v3_encode_varlen_int(NULL, size);

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_CHAIN_ERROR;
    }

    b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->last,
                                                       NGX_HTTP_V3_FRAME_DATA);
    b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->last, size);

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_CHAIN_ERROR;
    }

    cl->buf = b;
    cl->next = body;

    return cl;
}


static ngx_inline ngx_uint_t
ngx_http_v3_map_method(ngx_uint_t method)
{
    switch (method) {
    case NGX_HTTP_GET:
        return NGX_HTTP_V3_HEADER_METHOD_GET;
    case NGX_HTTP_HEAD:
        return NGX_HTTP_V3_HEADER_METHOD_HEAD;
    case NGX_HTTP_POST:
        return NGX_HTTP_V3_HEADER_METHOD_POST;
    case NGX_HTTP_PUT:
        return NGX_HTTP_V3_HEADER_METHOD_PUT;
    case NGX_HTTP_DELETE:
        return NGX_HTTP_V3_HEADER_METHOD_DELETE;
    case NGX_HTTP_OPTIONS:
        return NGX_HTTP_V3_HEADER_METHOD_OPTIONS;
    default:
        return 0;
    }
}


static ngx_int_t
ngx_http_v3_proxy_encode_method(ngx_http_request_t *r,
    ngx_http_v3_proxy_ctx_t *v3c, ngx_buf_t *b)
{
    size_t                      n;
    ngx_str_t                   method;
    ngx_uint_t                  v3method;
    ngx_http_upstream_t        *u;
    ngx_http_proxy_ctx_t       *ctx;
    ngx_http_proxy_loc_conf_t  *plcf;

    static ngx_str_t ngx_http_v3_header_method = ngx_string(":method");

    if (b == NULL) {
        /* calculate length */

        plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);
        ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

        method.len = 0;
        n = 0;

        u = r->upstream;

        if (u->method.len) {
            /* HEAD was changed to GET to cache response */
            method = u->method;

        } else if (plcf->method) {
            if (ngx_http_complex_value(r, plcf->method, &method) != NGX_OK) {
                return NGX_ERROR;
            }
        } else {
            method = r->method_name;
        }

        if (method.len == 4
            && ngx_strncasecmp(method.data, (u_char *) "HEAD", 4) == 0)
        {
            ctx->head = 1;
        }

        if (method.len) {
            n = ngx_http_v3_encode_field_l(NULL, &ngx_http_v3_header_method,
                                           &method);
        } else {

            v3method = ngx_http_v3_map_method(r->method);

            if (v3method) {
                n = ngx_http_v3_encode_field_ri(NULL, 0, v3method);

            } else {
                n = ngx_http_v3_encode_field_l(NULL,
                                               &ngx_http_v3_header_method,
                                               &r->method_name);
            }
        }

        v3c->n += n;
        v3c->method = method;

        return NGX_OK;
    }

    method = v3c->method;

    if (method.len) {
        b->last = (u_char *) ngx_http_v3_encode_field_l(b->last,
                                                    &ngx_http_v3_header_method,
                                                    &method);
    } else {

        v3method = ngx_http_v3_map_method(r->method);

        if (v3method) {
            b->last = (u_char *) ngx_http_v3_encode_field_ri(b->last, 0,
                                                             v3method);
        } else {
            b->last = (u_char *) ngx_http_v3_encode_field_l(b->last,
                                                    &ngx_http_v3_header_method,
                                                    &r->method_name);
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_proxy_encode_authority(ngx_http_request_t *r,
    ngx_http_v3_proxy_ctx_t *v3c, ngx_buf_t *b)
{
    size_t                      n;
    ngx_http_proxy_ctx_t       *ctx;
    ngx_http_proxy_loc_conf_t  *plcf;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    if (plcf->host_set) {
        return NGX_OK;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (b == NULL) {

        n = ngx_http_v3_encode_field_lri(NULL, 0, NGX_HTTP_V3_HEADER_AUTHORITY,
                                         NULL, ctx->host.len);
        v3c->n += n;

        return NGX_OK;
    }

    b->last = (u_char *) ngx_http_v3_encode_field_lri(b->last, 0,
                  NGX_HTTP_V3_HEADER_AUTHORITY, ctx->host.data, ctx->host.len);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http3 header: \":authority: %V\"", &ctx->host);

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_proxy_encode_path(ngx_http_request_t *r,
    ngx_http_v3_proxy_ctx_t *v3c, ngx_buf_t *b)
{
    size_t                      n;
    u_char                     *p;
    size_t                      loc_len;
    size_t                      uri_len;
    ngx_str_t                   tmp;
    uintptr_t                   escape;
    ngx_uint_t                  unparsed_uri;
    ngx_http_upstream_t        *u;
    ngx_http_proxy_ctx_t       *ctx;
    ngx_http_proxy_loc_conf_t  *plcf;

    static ngx_str_t ngx_http_v3_path = ngx_string(":path");

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (b == NULL) {

        escape = 0;
        uri_len = 0;
        loc_len = 0;
        unparsed_uri = 0;

        if (plcf->proxy_lengths && ctx->vars.uri.len) {
            uri_len = ctx->vars.uri.len;

        } else if (ctx->vars.uri.len == 0 && r->valid_unparsed_uri) {
            unparsed_uri = 1;
            uri_len = r->unparsed_uri.len;

        } else {
            loc_len = (r->valid_location && ctx->vars.uri.len) ?
                                                        plcf->location.len : 0;

            if (r->quoted_uri || r->internal) {
               escape = 2 * ngx_escape_uri(NULL, r->uri.data + loc_len,
                                           r->uri.len - loc_len,
                                           NGX_ESCAPE_URI);
            }

            uri_len = ctx->vars.uri.len + r->uri.len - loc_len + escape
                      + sizeof("?") - 1 + r->args.len;
        }

        if (uri_len == 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "zero length URI to proxy");
            return NGX_ERROR;
        }

        tmp.data = NULL;
        tmp.len = uri_len;

        n = ngx_http_v3_encode_field_l(NULL, &ngx_http_v3_path, &tmp);

        v3c->n += n;

        v3c->escape = escape;
        v3c->uri_len = uri_len;
        v3c->loc_len = loc_len;
        v3c->unparsed_uri = unparsed_uri;

        return NGX_OK;
    }

    u = r->upstream;

    escape = v3c->escape;
    uri_len = v3c->uri_len;
    loc_len = v3c->loc_len;
    unparsed_uri = v3c->unparsed_uri;

    p = ngx_palloc(r->pool, uri_len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    u->uri.data = p;

    if (plcf->proxy_lengths && ctx->vars.uri.len) {
        p = ngx_copy(p, ctx->vars.uri.data, ctx->vars.uri.len);

    } else if (unparsed_uri) {
        p = ngx_copy(p, r->unparsed_uri.data, r->unparsed_uri.len);

    } else {
        if (r->valid_location) {
            p = ngx_copy(p, ctx->vars.uri.data, ctx->vars.uri.len);
        }

        if (escape) {
            ngx_escape_uri(p, r->uri.data + loc_len,
                           r->uri.len - loc_len, NGX_ESCAPE_URI);
            p += r->uri.len - loc_len + escape;

        } else {
            p = ngx_copy(p, r->uri.data + loc_len, r->uri.len - loc_len);
        }

        if (r->args.len > 0) {
            *p++ = '?';
            p = ngx_copy(p, r->args.data, r->args.len);
        }
    }

    u->uri.len = p - u->uri.data;

    b->last = (u_char *) ngx_http_v3_encode_field_l(b->last, &ngx_http_v3_path,
                                                    &u->uri);
    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_proxy_body_length(ngx_http_request_t *r,
    ngx_http_v3_proxy_ctx_t *v3c)
{
    size_t                        body_len, n;
    ngx_http_proxy_ctx_t         *ctx;
    ngx_http_script_engine_t     *le;
    ngx_http_proxy_loc_conf_t    *plcf;
    ngx_http_script_len_code_pt   lcode;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    le = &v3c->le;

    n = 0;

    if (plcf->body_lengths) {
        le->ip = plcf->body_lengths->elts;
        le->request = r;
        le->flushed = 1;
        body_len = 0;

        while (*(uintptr_t *) le->ip) {
            lcode = *(ngx_http_script_len_code_pt *) le->ip;
            body_len += lcode(le);
        }

        ctx->internal_body_length = body_len;
        n += body_len;

    } else if (r->headers_in.chunked && r->reading_body) {
        ctx->internal_body_length = -1;
        ctx->internal_chunked = 1;

    } else {
        ctx->internal_body_length = r->headers_in.content_length_n;
        n = r->headers_in.content_length_n;
    }

    v3c->n += n;

    return NGX_OK;
}


static ngx_chain_t *
ngx_http_v3_proxy_encode_body(ngx_http_request_t *r,
    ngx_http_v3_proxy_ctx_t *v3c)
{
    ngx_buf_t                  *b;
    ngx_chain_t                *body, *cl, *prev, *head;
    ngx_http_upstream_t        *u;
    ngx_http_proxy_ctx_t       *ctx;
    ngx_http_script_code_pt     code;
    ngx_http_script_engine_t   *e;
    ngx_http_proxy_loc_conf_t  *plcf;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    u = r->upstream;

    /* body set in configuration */

    if (plcf->body_values) {

        e = &v3c->e;

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_CHAIN_ERROR;
        }

        b = ngx_create_temp_buf(r->pool, ctx->internal_body_length);
        if (b == NULL) {
            return NGX_CHAIN_ERROR;
        }

        cl->buf = b;
        cl->next = NULL;

        e->ip = plcf->body_values->elts;
        e->pos = b->last;
        e->skip = 0;

        while (*(uintptr_t *) e->ip) {
            code = *(ngx_http_script_code_pt *) e->ip;
            code((ngx_http_script_engine_t *) e);
        }

        b->last = e->pos;

        return cl;
    }

    if (!plcf->upstream.pass_request_body) {
        return NULL;
    }

    /* body from client */

    cl = NULL;
    head = NULL;
    prev = NULL;

    body = u->request_bufs;

    while (body) {

        b = ngx_alloc_buf(r->pool);
        if (b == NULL) {
            return NGX_CHAIN_ERROR;
        }

        ngx_memcpy(b, body->buf, sizeof(ngx_buf_t));

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_CHAIN_ERROR;
        }

        cl->buf = b;

        if (prev) {
            prev->next = cl;

        } else {
            head = cl;
        }

        prev = cl;
        body = body->next;
    }

    if (cl) {
        cl->next = NULL;
    }

    return head;
}


static ngx_int_t
ngx_http_v3_proxy_body_output_filter(void *data, ngx_chain_t *in)
{
    ngx_http_request_t  *r = data;

    off_t                  size;
    u_char                *chunk;
    size_t                 len;
    ngx_buf_t             *b;
    ngx_int_t              rc;
    ngx_chain_t           *out, *cl, *tl, **ll, **fl;
    ngx_http_proxy_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "v3 proxy output filter");

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (in == NULL) {
        out = in;
        goto out;
    }

    out = NULL;
    ll = &out;

    if (!ctx->header_sent) {

        /* buffers contain v3-encoded headers frame, pass it as is */

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "v3 proxy output header");

        ctx->header_sent = 1;

        for ( ;; ) {

            if (in->buf->tag
                != (ngx_buf_tag_t) &ngx_http_v3_create_headers_frame)
            {
                break;
            }

            tl = ngx_alloc_chain_link(r->pool);
            if (tl == NULL) {
                return NGX_ERROR;
            }

            tl->buf = in->buf;
            *ll = tl;
            ll = &tl->next;

            in = in->next;

            if (in == NULL) {
                tl->next = NULL;
                goto out;
            }
        }
    }

    size = 0;
    fl = ll;

    for (cl = in; cl; cl = cl->next) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "v3 proxy output chunk: %O", ngx_buf_size(cl->buf));

        size += ngx_buf_size(cl->buf);

        if (cl->buf->flush
            || cl->buf->sync
            || ngx_buf_in_memory(cl->buf)
            || cl->buf->in_file)
        {
            tl = ngx_alloc_chain_link(r->pool);
            if (tl == NULL) {
                return NGX_ERROR;
            }

            tl->buf = cl->buf;
            *ll = tl;
            ll = &tl->next;
        }
    }

    if (size) {

        tl = ngx_chain_get_free_buf(r->pool, &ctx->free);
        if (tl == NULL) {
            return NGX_ERROR;
        }

        b = tl->buf;
        chunk = b->start;

        if (chunk == NULL) {
            len = ngx_http_v3_encode_varlen_int(NULL,
                                                 NGX_HTTP_V3_FRAME_DATA)
                   + 8 /* max varlen int length*/;

            chunk = ngx_palloc(r->pool, len);
            if (chunk == NULL) {
                return NGX_ERROR;
            }
            b->start = chunk;
            b->pos = b->start;
            b->end = chunk + len;
        }

        b->tag = (ngx_buf_tag_t) &ngx_http_v3_proxy_body_output_filter;
        b->memory = 0;
        b->temporary = 1;

        b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->start,
                                                       NGX_HTTP_V3_FRAME_DATA);
        b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->last, size);

        tl->next = *fl;
        *fl = tl;
    }

    *ll = NULL;

out:

    rc = ngx_chain_writer(&r->upstream->writer, out);

    ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
                        (ngx_buf_tag_t) &ngx_http_v3_proxy_body_output_filter);

    return rc;
}


static ngx_int_t
ngx_http_v3_proxy_encode_headers(ngx_http_request_t *r,
    ngx_http_v3_proxy_ctx_t *v3c, ngx_buf_t *b)
{
    u_char                       *p, *start;
    size_t                        key_len, val_len, hlen, max_head, n;
    ngx_str_t                     tmp, tmpv;
    ngx_uint_t                    i;
    ngx_list_part_t              *part;
    ngx_table_elt_t              *header;
    ngx_http_script_code_pt       code;
    ngx_http_proxy_headers_t     *headers;
    ngx_http_script_engine_t     *le;
    ngx_http_script_engine_t     *e;
    ngx_http_proxy_loc_conf_t    *plcf;
    ngx_http_script_len_code_pt   lcode;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    headers = v3c->headers;
    le = &v3c->le;
    e = &v3c->e;

    if (b == NULL) {

        le->ip = headers->lengths->elts;
        le->request = r;
        le->flushed = 1;

        n = 0;
        max_head = 0;

        while (*(uintptr_t *) le->ip) {

            lcode = *(ngx_http_script_len_code_pt *) le->ip;
            key_len = lcode(le);

            for (val_len = 0; *(uintptr_t *) le->ip; val_len += lcode(le)) {
                lcode = *(ngx_http_script_len_code_pt *) le->ip;
            }
            le->ip += sizeof(uintptr_t);

            if (val_len == 0) {
                continue;
            }

            tmp.data = NULL;
            tmp.len = key_len;

            tmpv.data = NULL;
            tmpv.len = val_len;

            hlen = key_len + val_len;
            if (hlen > max_head) {
                max_head = hlen;
            }

            n += ngx_http_v3_encode_field_l(NULL, &tmp, &tmpv);
        }

        if (plcf->upstream.pass_request_headers) {
            part = &r->headers_in.headers.part;
            header = part->elts;

            for (i = 0; /* void */; i++) {

                if (i >= part->nelts) {
                    if (part->next == NULL) {
                        break;
                    }

                    part = part->next;
                    header = part->elts;
                    i = 0;
                }

                if (ngx_hash_find(&headers->hash, header[i].hash,
                                  header[i].lowcase_key, header[i].key.len))
                {
                    continue;
                }

                n += ngx_http_v3_encode_field_l(NULL, &header[i].key,
                                                &header[i].value);
            }
        }

        v3c->n += n;
        v3c->max_head = max_head;

        return NGX_OK;
    }

    max_head = v3c->max_head;

    p = ngx_pnalloc(r->pool, max_head);
    if (p == NULL) {
        return NGX_ERROR;
    }

    start = p;

    ngx_memzero(e, sizeof(ngx_http_script_engine_t));

    e->ip = headers->values->elts;
    e->pos = p;
    e->request = r;
    e->flushed = 1;

    le->ip = headers->lengths->elts;

    tmp.data = p;
    tmp.len = 0;

    tmpv.data = NULL;
    tmpv.len = 0;

    while (*(uintptr_t *) le->ip) {

        lcode = *(ngx_http_script_len_code_pt *) le->ip;
        (void) lcode(le);

        for (val_len = 0; *(uintptr_t *) le->ip; val_len += lcode(le)) {
            lcode = *(ngx_http_script_len_code_pt *) le->ip;
        }
        le->ip += sizeof(uintptr_t);

        if (val_len == 0) {
            e->skip = 1;

            while (*(uintptr_t *) e->ip) {
                code = *(ngx_http_script_code_pt *) e->ip;
                code((ngx_http_script_engine_t *) e);
            }
            e->ip += sizeof(uintptr_t);

            e->skip = 0;

            continue;
        }

        code = *(ngx_http_script_code_pt *) e->ip;
        code((ngx_http_script_engine_t *) e);

        tmp.len = e->pos - tmp.data;
        tmpv.data = e->pos;

        while (*(uintptr_t *) e->ip) {
            code = *(ngx_http_script_code_pt *) e->ip;
            code((ngx_http_script_engine_t *) e);
        }
        e->ip += sizeof(uintptr_t);

        tmpv.len = e->pos - tmpv.data;

        b->last = (u_char *) ngx_http_v3_encode_field_l(b->last, &tmp, &tmpv);

        tmp.data = p;
        tmp.len = 0;

        tmpv.data = NULL;
        tmpv.len = 0;
        e->pos = start;
    }

    if (plcf->upstream.pass_request_headers) {
        part = &r->headers_in.headers.part;
        header = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if (ngx_hash_find(&headers->hash, header[i].hash,
                              header[i].lowcase_key, header[i].key.len))
            {
                continue;
            }

            b->last = (u_char *) ngx_http_v3_encode_field_l(b->last,
                                                            &header[i].key,
                                                            &header[i].value);

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy header: \"%V: %V\"",
                           &header[i].key, &header[i].value);
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_proxy_reinit_request(ngx_http_request_t *r)
{
    ngx_http_proxy_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (ctx == NULL) {
        return NGX_OK;
    }

    r->upstream->process_header = ngx_http_v3_proxy_process_status_line;
    r->upstream->pipe->input_filter = ngx_http_v3_proxy_copy_filter;
    r->upstream->input_filter = ngx_http_v3_proxy_non_buffered_copy_filter;

    r->state = 0;
    ngx_memzero(ctx->v3_parse, sizeof(ngx_http_v3_parse_t));

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_proxy_process_status_line(ngx_http_request_t *r)
{
    u_char                       *p;
    ngx_buf_t                    *b;
    ngx_int_t                     rc;
    ngx_connection_t             *c;
    ngx_http_upstream_t          *u;
    ngx_http_proxy_ctx_t         *ctx;
    ngx_http_v3_session_t        *h3c;
    ngx_http_v3_parse_headers_t  *st;
#if (NGX_HTTP_CACHE)
    ngx_connection_t              stub;
    ngx_http_conf_ctx_t           conf_ctx;
    ngx_http_connection_t         hc;
#endif

    u = r->upstream;
    c = u->peer.connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ngx_http_v3_proxy_process_status_line");

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

#if (NGX_HTTP_CACHE)
    if (r->cache && c == NULL) {
        /* QPACK table checks require session object */

        ngx_memzero(&hc, sizeof(ngx_http_connection_t));
        ngx_memzero(&stub, sizeof(ngx_connection_t));

        conf_ctx.main_conf = r->main_conf;
        conf_ctx.srv_conf = r->srv_conf;
        conf_ctx.loc_conf = r->loc_conf;

        hc.conf_ctx = &conf_ctx;

        c = &stub;

        c->data = &hc;
        c->log = r->connection->log;
        c->pool = r->connection->pool;

        if (ngx_http_v3_init_session(c) != NGX_OK) {
            return NGX_ERROR;
        }
    }
#endif

    h3c = ngx_http_v3_get_session(c);

    if (ngx_list_init(&u->headers_in.headers, r->pool, 20,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ctx->v3_parse->header_limit = u->conf->bufs.size * u->conf->bufs.num;

    st = &ctx->v3_parse->headers;
    b = &u->buffer;

    for ( ;; ) {

       p = b->pos;

       rc = ngx_http_v3_parse_headers(c, st, b);
       if (rc > 0) {

            if (h3c && c->quic) {
                ngx_quic_reset_stream(c, rc);
            }
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent invalid header rc:%i", rc);
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (h3c) {
            h3c->total_bytes += b->pos - p;
        }

        if (rc == NGX_BUSY) {
            /* HTTP/3 blocked */
            return NGX_AGAIN;
        }

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        /* rc == NGX_OK || rc == NGX_DONE */

        if (h3c) {
            h3c->payload_bytes += ngx_http_v3_encode_field_l(NULL,
                                                   &st->field_rep.field.name,
                                                   &st->field_rep.field.value);
        }

        if (ngx_http_v3_proxy_process_header(r, &st->field_rep.field.name,
                                             &st->field_rep.field.value)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (rc == NGX_DONE) {
            return ngx_http_v3_proxy_headers_done(r);
        }
    }

    return NGX_OK;
}


static void
ngx_http_v3_proxy_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http v3 proxy request");
}


static void
ngx_http_v3_proxy_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http v3 proxy request");
}


static ngx_int_t
ngx_http_v3_proxy_process_header(ngx_http_request_t *r, ngx_str_t *name,
    ngx_str_t *value)
{
    size_t                          len;
    ngx_table_elt_t                *h;
    ngx_http_upstream_t            *u;
    ngx_http_proxy_ctx_t           *ctx;
    ngx_http_upstream_header_t     *hh;
    ngx_http_upstream_main_conf_t  *umcf;

    /* based on ngx_http_v3_process_header() */

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    u = r->upstream;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    len = name->len + value->len;

    if (len > ctx->v3_parse->header_limit) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent too large header");
        return NGX_ERROR;
    }

    ctx->v3_parse->header_limit -= len;

    if (name->len && name->data[0] == ':') {
        return ngx_http_v3_proxy_process_pseudo_header(r, name, value);
    }

    h = ngx_list_push(&u->headers_in.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    /*
     * HTTP/3 parsing used peer->connection.pool, which might be destroyed,
     * at the moment when r->headers_out are used;
     * thus allocate from r->pool and copy header name/value
     */
    h->key.len = name->len;
    h->key.data = ngx_pnalloc(r->pool, name->len + 1);
    if (h->key.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(h->key.data, name->data, name->len);
    h->key.data[h->key.len] = 0;

    h->value.len = value->len;
    h->value.data = ngx_pnalloc(r->pool, value->len + 1);
    if (h->value.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(h->value.data, value->data, value->len);
    h->value.data[h->value.len] = 0;

    h->lowcase_key = h->key.data;
    h->hash = ngx_hash_key(h->key.data, h->key.len);

    hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
                       h->lowcase_key, h->key.len);

    if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http3 header: \"%V: %V\"", name, value);

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_proxy_headers_done(ngx_http_request_t *r)
{
    ngx_table_elt_t         *h;
    ngx_connection_t        *c;
    ngx_http_proxy_ctx_t    *ctx;
    ngx_http_upstream_t     *u;

    /*
     * based on NGX_HTTP_PARSE_HEADER_DONE in ngx_http_proxy_process_header()
     * and ngx_http_v3_process_request_header()
     */

    u = r->upstream;
    c = u->peer.connection;

    /*
     * if no "Server" and "Date" in header line,
     * then add the special empty headers
     */

    if (u->headers_in.server == NULL) {
        h = ngx_list_push(&u->headers_in.headers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(
                                    ngx_hash('s', 'e'), 'r'), 'v'), 'e'), 'r');

        ngx_str_set(&h->key, "Server");
        ngx_str_null(&h->value);
        h->lowcase_key = (u_char *) "server";
        h->next = NULL;
    }

    if (u->headers_in.date == NULL) {
        h = ngx_list_push(&u->headers_in.headers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        h->hash = ngx_hash(ngx_hash(ngx_hash('d', 'a'), 't'), 'e');

        ngx_str_set(&h->key, "Date");
        ngx_str_null(&h->value);
        h->lowcase_key = (u_char *) "date";
        h->next = NULL;
    }

    if (ngx_http_v3_proxy_construct_cookie_header(r) != NGX_OK) {
        return NGX_ERROR;
    }

    if (u->headers_in.content_length) {
        u->headers_in.content_length_n =
                            ngx_atoof(u->headers_in.content_length->value.data,
                                      u->headers_in.content_length->value.len);

        if (u->headers_in.content_length_n == NGX_ERROR) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "client sent invalid \"Content-Length\" header");
            return NGX_ERROR;
        }

    } else {
        u->headers_in.content_length_n = -1;
    }

    /*
     * set u->keepalive if response has no body; this allows to keep
     * connections alive in case of r->header_only or X-Accel-Redirect
     */

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (u->headers_in.status_n == NGX_HTTP_NO_CONTENT
        || u->headers_in.status_n == NGX_HTTP_NOT_MODIFIED
        || ctx->head
        || (!u->headers_in.chunked
            && u->headers_in.content_length_n == 0))
    {
        u->keepalive = !u->headers_in.connection_close;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_proxy_process_pseudo_header(ngx_http_request_t *r, ngx_str_t *name,
    ngx_str_t *value)
{
    ngx_int_t             status;
    ngx_str_t            *status_line;
    ngx_http_upstream_t  *u;

    /* based on ngx_http_v3_process_pseudo_header() */

    /*
     * RFC 9114, 4.3.2
     *
     * For responses, a single ":status" pseudo-header field
     * is defined that carries the HTTP status code;
     */

    u = r->upstream;

    if (name->len == 7 && ngx_strncmp(name->data, ":status", 7) == 0) {

        if (u->state && u->state->status
#if (NGX_HTTP_CACHE)
            && !r->cached
#endif
        ) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "upstream sent duplicate \":status\" header");
            return NGX_ERROR;
        }

        if (value->len == 0) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "upstream sent empty \":status\" header");
            return NGX_ERROR;
        }

        if (value->len < 3) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "upstream sent too short \":status\" header");
            return NGX_ERROR;
        }

        status = ngx_atoi(value->data, 3);

        if (status == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent invalid status \"%V\"", value);
            return NGX_ERROR;
        }

        if (u->state && u->state->status == 0) {
            u->state->status = status;
        }

        u->headers_in.status_n = status;

        status_line = ngx_http_status_line(status);
        if (status_line) {
            u->headers_in.status_line = *status_line;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http v3 proxy status %ui \"%V\"",
                       u->headers_in.status_n, &u->headers_in.status_line);

        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "upstream sent unexpected pseudo-header \"%V\"", name);

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_v3_proxy_input_filter_init(void *data)
{
    ngx_http_request_t  *r = data;

    ngx_http_upstream_t   *u;
    ngx_http_proxy_ctx_t  *ctx;

    u = r->upstream;
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http v3 proxy filter init s:%ui h:%d c:%d l:%O",
                   u->headers_in.status_n, ctx->head, u->headers_in.chunked,
                   u->headers_in.content_length_n);

    /* as per RFC2616, 4.4 Message Length */

    /* HTTP/3 is 'chunked-like' by default, filter is already set */

    if (u->headers_in.status_n == NGX_HTTP_NO_CONTENT
        || u->headers_in.status_n == NGX_HTTP_NOT_MODIFIED
        || ctx->head)
    {
        /* 1xx, 204, and 304 and replies to HEAD requests */
        /* no 1xx since we don't send Expect and Upgrade */

        u->pipe->length = 0;
        u->length = 0;

    } else if (u->headers_in.content_length_n == 0) {
        /* empty body: special case as filter won't be called */

        u->pipe->length = 0;
        u->length = 0;

    } else {
        /* content length or connection close */

        u->pipe->length = u->headers_in.content_length_n;
        u->length = u->headers_in.content_length_n;
    }

    /* TODO: check flag handling in HTTP/3 */
    u->keepalive = 1;

    return NGX_OK;
}


/* reading non-buffered body from V3 upstream */
static ngx_int_t
ngx_http_v3_proxy_non_buffered_copy_filter(void *data, ssize_t bytes)
{
    ngx_http_request_t  *r = data;

    size_t                     size, len;
    ngx_int_t                  rc;
    ngx_buf_t                 *b, *buf;
    ngx_chain_t               *cl, **ll;
    ngx_http_upstream_t       *u;
    ngx_http_proxy_ctx_t      *ctx;
    ngx_http_v3_parse_data_t  *st;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http v3 proxy non buffered copy filter");

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    u = r->upstream;
    buf = &u->buffer;

    buf->pos = buf->last;
    buf->last += bytes;

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    st = &ctx->v3_parse->body;

    while (buf->pos < buf->last) {

        if (st->length == 0) {

            rc = ngx_http_v3_parse_data(r->connection, st, buf);

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "ngx_http_v3_parse_data rc:%i st->length: %ui",
                           rc, st->length);

            if (rc == NGX_AGAIN) {
                break;
            }

            if (rc == NGX_ERROR || rc > 0) {
                return NGX_ERROR;
            }

            if (rc == NGX_DONE) {
                /* TODO: trailers */
                u->length = 0;
            }

            /* rc == NGX_OK */
            continue;
        }

        /* need to consume ctx->st.length bytes and then parse again */

        cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        *ll = cl;
        ll = &cl->next;

        b = cl->buf;

        b->start = buf->pos;
        b->pos = buf->pos;
        b->last = buf->last;
        b->end = buf->end;

        b->tag = u->output.tag;
        b->flush = 1;
        b->temporary = 1;

        size = buf->last - buf->pos;
        len = ngx_min(size, st->length);

        buf->pos += len;
        st->length -= len;

        if (u->length != -1) {
            u->length -= len;
        }

        b->last = buf->pos;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http v3 proxy out buf %p %z",
                       b->pos, b->last - b->pos);
    }

    if (u->length == 0) {
        u->keepalive = !u->headers_in.connection_close;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_proxy_copy_filter(ngx_event_pipe_t *p, ngx_buf_t *buf)
{
    size_t                     size, len;
    ngx_int_t                  rc;
    ngx_buf_t                 *b, **prev;
    ngx_chain_t               *cl;
    ngx_http_upstream_t       *u;
    ngx_http_request_t        *r;
    ngx_http_proxy_ctx_t      *ctx;
    ngx_http_v3_parse_data_t  *st;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, p->log, 0,
                   "http_v3_proxy_copy_filter");

    if (buf->pos == buf->last) {
        return NGX_OK;
    }

    if (p->upstream_done) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, p->log, 0,
                       "http v3 proxy data after close");
        return NGX_OK;
    }

    if (p->length == 0) {
        ngx_log_error(NGX_LOG_WARN, p->log, 0,
                      "upstream sent more data than specified in "
                      "\"Content-Length\" header");

        r = p->input_ctx;
        r->upstream->keepalive = 0;
        p->upstream_done = 1;

        return NGX_OK;
    }

    r = p->input_ctx;
    u = r->upstream;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    st = &ctx->v3_parse->body;

    b = NULL;
    prev = &buf->shadow;

    while (buf->pos < buf->last) {

        if (st->length == 0) {
            rc = ngx_http_v3_parse_data(r->connection, st, buf);

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "ngx_http_v3_parse_data rc:%i st->length: %ui",
                           rc, st->length);

            if (rc == NGX_AGAIN) {
                break;
            }

            if (rc == NGX_ERROR || rc > 0) {
                return NGX_ERROR;
            }

            if (rc == NGX_DONE) {
                /* TODO: trailers */
                p->length = 0;
            }

            /* rc == NGX_OK */
            continue;
        }

        /* need to consume ctx->st.length bytes and then parse again */

        cl = ngx_chain_get_free_buf(p->pool, &p->free);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        b = cl->buf;

        ngx_memcpy(b, buf, sizeof(ngx_buf_t));

        b->tag = p->tag;
        b->recycled = 1;
        b->temporary = 1;

        *prev = b;
        prev = &b->shadow;

        if (p->in) {
            *p->last_in = cl;

        } else {
            p->in = cl;
        }

        p->last_in = &cl->next;

        size = buf->last - buf->pos;

        len = ngx_min(size, st->length);

        buf->pos += len;
        b->last = buf->pos;

        st->length -= len;
        ctx->data_recvd += len;

        if (p->length != -1) {
            p->length -= len;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "http v3 proxy input buf #%d %p", b->num, b->pos);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, p->log, 0,
                   "http v3 proxy copy filter st length %ui pipe len:%O",
                   st->length, p->length);

    if (p->length == 0) {
        u->keepalive = !u->headers_in.connection_close;
    }

    if (b) {
        b->shadow = buf;
        b->last_shadow = 1;

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "input buf %p %z", b->pos, b->last - b->pos);
        return NGX_OK;
    }

    /* there is no data record in the buf, add it to free chain */

    if (ngx_event_pipe_add_free_buf(p, buf) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_proxy_construct_cookie_header(ngx_http_request_t *r)
{
    u_char                         *buf, *p, *end;
    size_t                          len;
    ngx_str_t                      *vals;
    ngx_uint_t                      i;
    ngx_array_t                    *cookies;
    ngx_table_elt_t                *h;
    ngx_http_header_t              *hh;
    ngx_http_upstream_t            *u;
    ngx_http_proxy_ctx_t           *ctx;
    ngx_http_upstream_main_conf_t  *umcf;

    static ngx_str_t cookie = ngx_string("cookie");

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    u = r->upstream;
    cookies = ctx->v3_parse->cookies;

    if (cookies == NULL) {
        return NGX_OK;
    }

    vals = cookies->elts;

    i = 0;
    len = 0;

    do {
        len += vals[i].len + 2;
    } while (++i != cookies->nelts);

    len -= 2;

    buf = ngx_pnalloc(r->pool, len + 1);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    p = buf;
    end = buf + len;

    for (i = 0; /* void */ ; i++) {

        p = ngx_cpymem(p, vals[i].data, vals[i].len);

        if (p == end) {
            *p = '\0';
            break;
        }

        *p++ = ';'; *p++ = ' ';
    }

    h = ngx_list_push(&u->headers_in.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(
                                    ngx_hash('c', 'o'), 'o'), 'k'), 'i'), 'e');

    h->key.len = cookie.len;
    h->key.data = cookie.data;

    h->value.len = len;
    h->value.data = buf;

    h->lowcase_key = cookie.data;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
                       h->lowcase_key, h->key.len);

    if (hh == NULL) {
        return NGX_ERROR;
    }

    if (hh->handler(r, h, hh->offset) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

#endif
