
/*
 * Copyright (C) 2023 Web Server LLC
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_QUIC_OPENSSL_COMPAT)
#include <ngx_event_quic_openssl_compat.h>
#endif

#if (NGX_HTTP_ACME)
#include <ngx_acme.h>
#endif


typedef ngx_int_t (*ngx_ssl_variable_handler_pt)(ngx_connection_t *c,
    ngx_pool_t *pool, ngx_str_t *s);


#define NGX_DEFAULT_CIPHERS     "HIGH:!aNULL:!MD5"
#define NGX_DEFAULT_ECDH_CURVE  "auto"

#define NGX_HTTP_ALPN_PROTOS    "\x08http/1.1\x08http/1.0\x08http/0.9"


#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
static int ngx_http_ssl_alpn_select(ngx_ssl_conn_t *ssl_conn,
    const unsigned char **out, unsigned char *outlen,
    const unsigned char *in, unsigned int inlen, void *arg);
#endif

static ngx_int_t ngx_http_ssl_static_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ssl_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_ssl_add_variables(ngx_conf_t *cf);
static void *ngx_http_ssl_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_ssl_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);

#if (!defined(NGX_HTTP_PROXY_MULTICERT))
static ngx_int_t ngx_http_ssl_compile_certificates(ngx_conf_t *cf,
    ngx_http_ssl_srv_conf_t *conf);
#endif

static char *ngx_http_ssl_certificate_cache(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_ssl_password_file(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_ssl_keylog_file(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_ssl_session_cache(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_ssl_ocsp_cache(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static char *ngx_http_ssl_conf_command_check(ngx_conf_t *cf, void *post,
    void *data);

static ngx_int_t ngx_http_ssl_init(ngx_conf_t *cf);
#if (NGX_QUIC_OPENSSL_COMPAT)
static ngx_int_t ngx_http_ssl_quic_compat_init(ngx_conf_t *cf,
    ngx_http_conf_addr_t *addr);
#endif


static ngx_conf_bitmask_t  ngx_http_ssl_protocols[] = {
    { ngx_string("SSLv2"), NGX_SSL_SSLv2 },
    { ngx_string("SSLv3"), NGX_SSL_SSLv3 },
    { ngx_string("TLSv1"), NGX_SSL_TLSv1 },
    { ngx_string("TLSv1.1"), NGX_SSL_TLSv1_1 },
    { ngx_string("TLSv1.2"), NGX_SSL_TLSv1_2 },
    { ngx_string("TLSv1.3"), NGX_SSL_TLSv1_3 },
    { ngx_null_string, 0 }
};


static ngx_conf_enum_t  ngx_http_ssl_verify[] = {
    { ngx_string("off"), 0 },
    { ngx_string("on"), 1 },
    { ngx_string("optional"), 2 },
    { ngx_string("optional_no_ca"), 3 },
    { ngx_null_string, 0 }
};


static ngx_conf_enum_t  ngx_http_ssl_ocsp[] = {
    { ngx_string("off"), 0 },
    { ngx_string("on"), 1 },
    { ngx_string("leaf"), 2 },
    { ngx_null_string, 0 }
};


static ngx_conf_post_t  ngx_http_ssl_conf_command_post =
    { ngx_http_ssl_conf_command_check };


static ngx_command_t  ngx_http_ssl_commands[] = {

#if (NGX_HTTP_PROXY_MULTICERT)

    { ngx_string("ssl_certificate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE12,
      ngx_ssl_certificate_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, certificates),
      NULL },

    { ngx_string("ssl_certificate_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE12,
      ngx_ssl_certificate_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, certificate_keys),
      NULL },

#else

    { ngx_string("ssl_certificate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, certificates),
      NULL },

    { ngx_string("ssl_certificate_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, certificate_keys),
      NULL },

#endif

    { ngx_string("ssl_certificate_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE123,
      ngx_http_ssl_certificate_cache,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ssl_password_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_ssl_password_file,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ssl_certificate_compression"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, certificate_compression),
      NULL },

    { ngx_string("ssl_keylog_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_ssl_keylog_file,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ssl_dhparam"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, dhparam),
      NULL },

    { ngx_string("ssl_ecdh_curve"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, ecdh_curve),
      NULL },

    { ngx_string("ssl_protocols"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, protocols),
      &ngx_http_ssl_protocols },

    { ngx_string("ssl_ciphers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, ciphers),
      NULL },

    { ngx_string("ssl_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, buffer_size),
      NULL },

    { ngx_string("ssl_verify_client"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, verify),
      &ngx_http_ssl_verify },

    { ngx_string("ssl_verify_depth"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, verify_depth),
      NULL },

    { ngx_string("ssl_client_certificate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, client_certificate),
      NULL },

    { ngx_string("ssl_trusted_certificate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, trusted_certificate),
      NULL },

    { ngx_string("ssl_prefer_server_ciphers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, prefer_server_ciphers),
      NULL },

    { ngx_string("ssl_session_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE12,
      ngx_http_ssl_session_cache,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ssl_session_tickets"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, session_tickets),
      NULL },

    { ngx_string("ssl_session_ticket_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, session_ticket_keys),
      NULL },

    { ngx_string("ssl_session_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, session_timeout),
      NULL },

    { ngx_string("ssl_crl"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, crl),
      NULL },

    { ngx_string("ssl_ocsp"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, ocsp),
      &ngx_http_ssl_ocsp },

    { ngx_string("ssl_ocsp_responder"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, ocsp_responder),
      NULL },

    { ngx_string("ssl_ocsp_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_ssl_ocsp_cache,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ssl_stapling"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, stapling),
      NULL },

    { ngx_string("ssl_stapling_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, stapling_file),
      NULL },

    { ngx_string("ssl_stapling_responder"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, stapling_responder),
      NULL },

    { ngx_string("ssl_stapling_verify"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, stapling_verify),
      NULL },

    { ngx_string("ssl_early_data"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, early_data),
      NULL },

    { ngx_string("ssl_encrypted_hello_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, encrypted_hello_keys),
      NULL },

    { ngx_string("ssl_conf_command"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_keyval_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, conf_commands),
      &ngx_http_ssl_conf_command_post },

    { ngx_string("ssl_reject_handshake"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, reject_handshake),
      NULL },

#if (NGX_HAVE_NTLS)
    { ngx_string("ssl_ntls"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, ntls),
      NULL },
#endif

      ngx_null_command
};


static ngx_http_module_t  ngx_http_ssl_module_ctx = {
    ngx_http_ssl_add_variables,            /* preconfiguration */
    ngx_http_ssl_init,                     /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_ssl_create_srv_conf,          /* create server configuration */
    ngx_http_ssl_merge_srv_conf,           /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_ssl_module = {
    NGX_MODULE_V1,
    &ngx_http_ssl_module_ctx,              /* module context */
    ngx_http_ssl_commands,                 /* module directives */
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


static ngx_http_variable_t  ngx_http_ssl_vars[] = {

    { ngx_string("ssl_protocol"), NULL, ngx_http_ssl_static_variable,
      (uintptr_t) ngx_ssl_get_protocol, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_cipher"), NULL, ngx_http_ssl_static_variable,
      (uintptr_t) ngx_ssl_get_cipher_name, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_ciphers"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_ciphers, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_curve"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_curve, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_curves"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_curves, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_sigalg"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_sigalg, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_session_id"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_session_id, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_session_reused"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_session_reused, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_early_data"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_early_data,
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("ssl_encrypted_hello"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_encrypted_hello, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_server_name"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_server_name, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_alpn_protocol"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_alpn_protocol, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_client_cert"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_certificate, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_client_raw_cert"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_raw_certificate,
      NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_client_escaped_cert"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_escaped_certificate,
      NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_client_s_dn"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_subject_dn, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_client_i_dn"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_issuer_dn, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_client_s_dn_legacy"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_subject_dn_legacy, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_client_i_dn_legacy"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_issuer_dn_legacy, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_client_serial"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_serial_number, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_client_fingerprint"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_fingerprint, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_client_verify"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_client_verify, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_client_v_start"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_client_v_start, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_client_v_end"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_client_v_end, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_client_v_remain"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_client_v_remain, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_server_cert_type"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_server_cert_type, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_client_sigalg"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_client_sigalg, NGX_HTTP_VAR_CHANGEABLE, 0 },

      ngx_http_null_variable
};


static ngx_str_t ngx_http_ssl_sess_id_ctx = ngx_string("HTTP");


#if (NGX_API)

typedef struct {
    X509_NAME               *name;
    STACK_OF(GENERAL_NAME)  *alt_names;
} ngx_api_http_ssl_dn_ctx_t;


static ngx_int_t ngx_api_http_ssl_static_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_http_ssl_cert_iter(ngx_api_iter_ctx_t *ictx,
    ngx_api_ctx_t *actx);
static ngx_int_t ngx_api_http_ssl_key_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_http_ssl_chain_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_http_ssl_subject_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_http_ssl_issuer_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_http_ssl_common_name_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_http_ssl_alt_names_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_http_ssl_country_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_http_ssl_state_or_province_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_http_ssl_organization_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_http_ssl_dn_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, X509_NAME *name, int nid);
static ngx_int_t ngx_api_http_ssl_since_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_http_ssl_until_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_http_ssl_time_info(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, ASN1_TIME  *asn1_time);
static void ngx_api_cert_key_info(EVP_PKEY *key, u_char *buf, size_t *size);

#if (NGX_HTTP_ACME)
static ngx_int_t ngx_api_http_ssl_acme_clients_handler(
    ngx_api_entry_data_t data, ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_acme_get_cert(ngx_pool_t *pool, ngx_acme_client_t * cli,
    STACK_OF(X509) **cert, EVP_PKEY **key);
static void ngx_http_acme_certs_free(void *data);
#endif


static ngx_api_entry_t  ngx_api_http_ssl_certificates_entries[] = {

    {
        .name      = ngx_string("static"),
        .handler   = ngx_api_http_ssl_static_handler,
    },

#if (NGX_HTTP_ACME)
    {
        .name      = ngx_string("acme_clients"),
        .handler   = ngx_api_http_ssl_acme_clients_handler,
    },
#endif

    ngx_api_null_entry
};


static ngx_api_entry_t  ngx_api_http_ssl_entry = {
    .name      = ngx_string("certificates"),
    .handler   = ngx_api_object_handler,
    .data.ents = ngx_api_http_ssl_certificates_entries
};


static ngx_api_entry_t  ngx_api_http_ssl_dn_entries[] = {

    {
        .name      = ngx_string("common_name"),
        .handler   = ngx_api_http_ssl_common_name_handler,
    },

    {
        .name      = ngx_string("alt_names"),
        .handler   = ngx_api_http_ssl_alt_names_handler,
    },

    {
        .name      = ngx_string("country"),
        .handler   = ngx_api_http_ssl_country_handler,
    },

    {
        .name      = ngx_string("state_or_province"),
        .handler   = ngx_api_http_ssl_state_or_province_handler,
    },

    {
        .name      = ngx_string("organization"),
        .handler   = ngx_api_http_ssl_organization_handler,
    },

    ngx_api_null_entry
};


static ngx_api_entry_t  ngx_api_http_ssl_validity_entries[] = {

    {
        .name      = ngx_string("since"),
        .handler   = ngx_api_http_ssl_since_handler,
    },

    {
        .name      = ngx_string("until"),
        .handler   = ngx_api_http_ssl_until_handler,
    },

    ngx_api_null_entry
};


static ngx_api_entry_t  ngx_api_http_ssl_chain_entries[] = {

    {
        .name      = ngx_string("subject"),
        .handler   = ngx_api_http_ssl_subject_handler,
        .data.ents = ngx_api_http_ssl_dn_entries,
    },

    {
        .name      = ngx_string("issuer"),
        .handler   = ngx_api_http_ssl_issuer_handler,
        .data.ents = ngx_api_http_ssl_dn_entries,
    },

    {
        .name      = ngx_string("validity"),
        .handler   = ngx_api_object_handler,
        .data.ents = ngx_api_http_ssl_validity_entries,
    },

    ngx_api_null_entry
};


static ngx_api_entry_t  ngx_api_http_ssl_cert_entries[] = {

    {
        .name      = ngx_string("key"),
        .handler   = ngx_api_http_ssl_key_handler,
    },

    {
        .name      = ngx_string("chain"),
        .handler   = ngx_api_http_ssl_chain_handler,
        .data.ents = ngx_api_http_ssl_chain_entries,
    },

    ngx_api_null_entry
};

#endif


#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation

static int
ngx_http_ssl_alpn_select(ngx_ssl_conn_t *ssl_conn, const unsigned char **out,
    unsigned char *outlen, const unsigned char *in, unsigned int inlen,
    void *arg)
{
    unsigned int             srvlen;
    unsigned char           *srv;
#if (NGX_DEBUG)
    unsigned int             i;
#endif
#if (NGX_HTTP_V2 || NGX_HTTP_V3)
    ngx_http_connection_t   *hc;
#endif
#if (NGX_HTTP_V2)
    ngx_http_v2_srv_conf_t  *h2scf;
#endif
#if (NGX_HTTP_V3)
    ngx_http_v3_srv_conf_t  *h3scf;
#endif
#if (NGX_HTTP_V2 || NGX_HTTP_V3 || NGX_DEBUG)
    ngx_connection_t        *c;

    c = ngx_ssl_get_connection(ssl_conn);
#endif

#if (NGX_DEBUG)
    for (i = 0; i < inlen; i += in[i] + 1) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "SSL ALPN supported by client: %*s",
                       (size_t) in[i], &in[i + 1]);
    }
#endif

#if (NGX_HTTP_V2 || NGX_HTTP_V3)
    hc = c->data;
#endif

#if (NGX_HTTP_V3)
    if (hc->addr_conf->quic) {

        h3scf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_v3_module);

        if (h3scf->enable && h3scf->enable_hq) {
            srv = (unsigned char *) NGX_HTTP_V3_ALPN_PROTO
                                    NGX_HTTP_V3_HQ_ALPN_PROTO;
            srvlen = sizeof(NGX_HTTP_V3_ALPN_PROTO NGX_HTTP_V3_HQ_ALPN_PROTO)
                     - 1;

        } else if (h3scf->enable_hq) {
            srv = (unsigned char *) NGX_HTTP_V3_HQ_ALPN_PROTO;
            srvlen = sizeof(NGX_HTTP_V3_HQ_ALPN_PROTO) - 1;

        } else if (h3scf->enable) {
            srv = (unsigned char *) NGX_HTTP_V3_ALPN_PROTO;
            srvlen = sizeof(NGX_HTTP_V3_ALPN_PROTO) - 1;

        } else {
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        }

    } else
#endif
    {
#if (NGX_HTTP_V2)
        h2scf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_v2_module);

        if (h2scf->enable || hc->addr_conf->http2) {
            srv = (unsigned char *) NGX_HTTP_V2_ALPN_PROTO NGX_HTTP_ALPN_PROTOS;
            srvlen = sizeof(NGX_HTTP_V2_ALPN_PROTO NGX_HTTP_ALPN_PROTOS) - 1;

        } else
#endif
        {
            srv = (unsigned char *) NGX_HTTP_ALPN_PROTOS;
            srvlen = sizeof(NGX_HTTP_ALPN_PROTOS) - 1;
        }
    }

    if (SSL_select_next_proto((unsigned char **) out, outlen, srv, srvlen,
                              in, inlen)
        != OPENSSL_NPN_NEGOTIATED
#if (NGX_HTTP_ACME)
        && ngx_acme_select_alpn_proto(out, outlen, in, inlen) != NGX_OK
#endif
        )
    {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "SSL ALPN selected: %*s", (size_t) *outlen, *out);

    return SSL_TLSEXT_ERR_OK;
}

#endif


static ngx_int_t
ngx_http_ssl_static_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_ssl_variable_handler_pt  handler = (ngx_ssl_variable_handler_pt) data;

    size_t     len;
    ngx_str_t  s;

    if (r->connection->ssl) {

        (void) handler(r->connection, NULL, &s);

        v->data = s.data;

        for (len = 0; v->data[len]; len++) { /* void */ }

        v->len = len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;

        return NGX_OK;
    }

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ssl_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_ssl_variable_handler_pt  handler = (ngx_ssl_variable_handler_pt) data;

    ngx_str_t  s;

    if (r->connection->ssl) {

        if (handler(r->connection, r->pool, &s) != NGX_OK) {
            return NGX_ERROR;
        }

        v->len = s.len;
        v->data = s.data;

        if (v->len) {
            v->valid = 1;
            v->no_cacheable = 0;
            v->not_found = 0;

            return NGX_OK;
        }
    }

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ssl_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_ssl_vars; v->name.len; v++) {
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
ngx_http_ssl_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_ssl_srv_conf_t  *sscf;

    sscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ssl_srv_conf_t));
    if (sscf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     sscf->protocols = 0;
     *     sscf->certificate_values = NULL;
     *     sscf->dhparam = { 0, NULL };
     *     sscf->ecdh_curve = { 0, NULL };
     *     sscf->client_certificate = { 0, NULL };
     *     sscf->trusted_certificate = { 0, NULL };
     *     sscf->crl = { 0, NULL };
     *     sscf->ciphers = { 0, NULL };
     *     sscf->shm_zone = NULL;
     *     sscf->ocsp_responder = { 0, NULL };
     *     sscf->stapling_file = { 0, NULL };
     *     sscf->stapling_responder = { 0, NULL };
     */

    sscf->prefer_server_ciphers = NGX_CONF_UNSET;
    sscf->certificate_compression = NGX_CONF_UNSET;
    sscf->early_data = NGX_CONF_UNSET;
    sscf->reject_handshake = NGX_CONF_UNSET;
    sscf->buffer_size = NGX_CONF_UNSET_SIZE;
    sscf->verify = NGX_CONF_UNSET_UINT;
    sscf->verify_depth = NGX_CONF_UNSET_UINT;
    sscf->certificates = NGX_CONF_UNSET_PTR;
    sscf->certificate_keys = NGX_CONF_UNSET_PTR;
    sscf->certificate_cache = NGX_CONF_UNSET_PTR;
    sscf->passwords = NGX_CONF_UNSET_PTR;
    sscf->keylog_file = NGX_CONF_UNSET_PTR;
    sscf->conf_commands = NGX_CONF_UNSET_PTR;
    sscf->builtin_session_cache = NGX_CONF_UNSET;
    sscf->session_timeout = NGX_CONF_UNSET;
    sscf->session_tickets = NGX_CONF_UNSET;
    sscf->session_ticket_keys = NGX_CONF_UNSET_PTR;
    sscf->ocsp = NGX_CONF_UNSET_UINT;
    sscf->ocsp_cache_zone = NGX_CONF_UNSET_PTR;
    sscf->stapling = NGX_CONF_UNSET;
    sscf->stapling_verify = NGX_CONF_UNSET;
    sscf->encrypted_hello_keys = NGX_CONF_UNSET_PTR;
#if (NGX_HAVE_NTLS)
    sscf->ntls = NGX_CONF_UNSET;
#endif

    return sscf;
}


static char *
ngx_http_ssl_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ssl_srv_conf_t *prev = parent;
    ngx_http_ssl_srv_conf_t *conf = child;

    ngx_pool_cleanup_t  *cln;

    ngx_conf_merge_value(conf->session_timeout,
                         prev->session_timeout, 300);

    ngx_conf_merge_value(conf->prefer_server_ciphers,
                         prev->prefer_server_ciphers, 0);

    ngx_conf_merge_value(conf->certificate_compression,
                         prev->certificate_compression, 0);

    ngx_conf_merge_value(conf->early_data, prev->early_data, 0);
    ngx_conf_merge_value(conf->reject_handshake, prev->reject_handshake, 0);

    ngx_conf_merge_bitmask_value(conf->protocols, prev->protocols,
                         (NGX_CONF_BITMASK_SET|NGX_SSL_DEFAULT_PROTOCOLS));

    ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
                         NGX_SSL_BUFSIZE);

    ngx_conf_merge_uint_value(conf->verify, prev->verify, 0);
    ngx_conf_merge_uint_value(conf->verify_depth, prev->verify_depth, 1);

    ngx_conf_merge_ptr_value(conf->certificates, prev->certificates, NULL);
    ngx_conf_merge_ptr_value(conf->certificate_keys, prev->certificate_keys,
                         NULL);

    ngx_conf_merge_ptr_value(conf->certificate_cache, prev->certificate_cache,
                         NULL);

    ngx_conf_merge_ptr_value(conf->passwords, prev->passwords, NULL);

    ngx_conf_merge_ptr_value(conf->keylog_file, prev->keylog_file, NULL);

    ngx_conf_merge_str_value(conf->dhparam, prev->dhparam, "");

    ngx_conf_merge_str_value(conf->client_certificate, prev->client_certificate,
                         "");
    ngx_conf_merge_str_value(conf->trusted_certificate,
                         prev->trusted_certificate, "");
    ngx_conf_merge_str_value(conf->crl, prev->crl, "");

    ngx_conf_merge_str_value(conf->ecdh_curve, prev->ecdh_curve,
                         NGX_DEFAULT_ECDH_CURVE);

    ngx_conf_merge_str_value(conf->ciphers, prev->ciphers, NGX_DEFAULT_CIPHERS);

    ngx_conf_merge_ptr_value(conf->conf_commands, prev->conf_commands, NULL);

    ngx_conf_merge_uint_value(conf->ocsp, prev->ocsp, 0);
    ngx_conf_merge_str_value(conf->ocsp_responder, prev->ocsp_responder, "");
    ngx_conf_merge_ptr_value(conf->ocsp_cache_zone,
                         prev->ocsp_cache_zone, NULL);

    ngx_conf_merge_value(conf->stapling, prev->stapling, 0);
    ngx_conf_merge_value(conf->stapling_verify, prev->stapling_verify, 0);
    ngx_conf_merge_str_value(conf->stapling_file, prev->stapling_file, "");
    ngx_conf_merge_str_value(conf->stapling_responder,
                         prev->stapling_responder, "");

#if (NGX_HAVE_NTLS)
    ngx_conf_merge_value(conf->ntls, prev->ntls, 0);
#endif

    conf->ssl.log = cf->log;

    if (conf->certificates) {

        if (conf->certificate_keys == NULL
            || conf->certificate_keys->nelts < conf->certificates->nelts)
        {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "no \"ssl_certificate_key\" is defined "
                          "for certificate \"%V\"",
                          ((ngx_str_t *) conf->certificates->elts)
                          + conf->certificates->nelts - 1);
            return NGX_CONF_ERROR;
        }

    } else if (!conf->reject_handshake) {
        return NGX_CONF_OK;
    }

    if (ngx_ssl_create(&conf->ssl, conf->protocols, conf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        ngx_ssl_cleanup_ctx(&conf->ssl);
        return NGX_CONF_ERROR;
    }

    cln->handler = ngx_ssl_cleanup_ctx;
    cln->data = &conf->ssl;

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    {
    static ngx_ssl_client_hello_arg cb = { ngx_http_ssl_servername };

    if (ngx_ssl_set_client_hello_callback(&conf->ssl, &cb) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (SSL_CTX_set_tlsext_servername_callback(conf->ssl.ctx,
                                               ngx_http_ssl_servername)
        == 0)
    {
        ngx_log_error(NGX_LOG_WARN, cf->log, 0,
            "Angie was built with SNI support, however, now it is linked "
            "dynamically to an OpenSSL library which has no tlsext support, "
            "therefore SNI is not available");
    }
    }
#endif

#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
    SSL_CTX_set_alpn_select_cb(conf->ssl.ctx, ngx_http_ssl_alpn_select, NULL);
#endif

    if (ngx_ssl_ciphers(cf, &conf->ssl, &conf->ciphers,
                        conf->prefer_server_ciphers)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_ssl_compile_certificates(cf, conf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (conf->certificate_values) {

#ifdef SSL_R_CERT_CB_ERROR

        /* install callback to lookup certificates */

        SSL_CTX_set_cert_cb(conf->ssl.ctx, ngx_http_ssl_certificate, conf);

#else
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "variables in "
                      "\"ssl_certificate\" and \"ssl_certificate_key\" "
                      "directives are not supported on this platform");
        return NGX_CONF_ERROR;
#endif

    } else if (conf->certificates) {

        /* configure certificates */

        if (ngx_ssl_certificates(cf, &conf->ssl, conf->certificates,
                                 conf->certificate_keys, conf->passwords)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

        if (ngx_ssl_certificate_compression(cf, &conf->ssl,
                                            conf->certificate_compression)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    conf->ssl.buffer_size = conf->buffer_size;

    if (conf->verify) {

        if (conf->verify != 3
            && conf->client_certificate.len == 0
            && conf->trusted_certificate.len == 0)
        {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "no ssl_client_certificate or "
                          "ssl_trusted_certificate for ssl_verify_client");
            return NGX_CONF_ERROR;
        }

        if (ngx_ssl_client_certificate(cf, &conf->ssl,
                                       &conf->client_certificate,
                                       conf->verify_depth)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    if (ngx_ssl_trusted_certificate(cf, &conf->ssl,
                                    &conf->trusted_certificate,
                                    conf->verify_depth)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_ssl_crl(cf, &conf->ssl, &conf->crl) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (conf->ocsp) {

        if (conf->verify == 3) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "\"ssl_ocsp\" is incompatible with "
                          "\"ssl_verify_client optional_no_ca\"");
            return NGX_CONF_ERROR;
        }

        if (ngx_ssl_ocsp(cf, &conf->ssl, &conf->ocsp_responder, conf->ocsp,
                         conf->ocsp_cache_zone)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    if (ngx_ssl_dhparam(cf, &conf->ssl, &conf->dhparam) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (ngx_ssl_ecdh_curve(cf, &conf->ssl, &conf->ecdh_curve) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_value(conf->builtin_session_cache,
                         prev->builtin_session_cache, NGX_SSL_NONE_SCACHE);

    if (conf->shm_zone == NULL) {
        conf->shm_zone = prev->shm_zone;
    }

    if (ngx_ssl_session_cache(&conf->ssl, &ngx_http_ssl_sess_id_ctx,
                              conf->certificates, conf->builtin_session_cache,
                              conf->shm_zone, conf->session_timeout)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_value(conf->session_tickets, prev->session_tickets, 1);

#ifdef SSL_OP_NO_TICKET
    if (!conf->session_tickets) {
        SSL_CTX_set_options(conf->ssl.ctx, SSL_OP_NO_TICKET);
    }
#endif

    ngx_conf_merge_ptr_value(conf->session_ticket_keys,
                         prev->session_ticket_keys, NULL);

    if (ngx_ssl_session_ticket_keys(cf, &conf->ssl, conf->session_ticket_keys)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (conf->stapling) {

        if (conf->certificate_compression) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "\"ssl_stapling\" is incompatible with "
                          "\"ssl_certificate_compression\"");
            return NGX_CONF_ERROR;
        }

        if (ngx_ssl_stapling(cf, &conf->ssl, &conf->stapling_file,
                             &conf->stapling_responder, conf->stapling_verify)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    if (ngx_ssl_early_data(cf, &conf->ssl, conf->early_data) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_ptr_value(conf->encrypted_hello_keys,
                         prev->encrypted_hello_keys, NULL);

    if (ngx_ssl_encrypted_hello_keys(cf, &conf->ssl,
                                     conf->encrypted_hello_keys)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_ssl_conf_commands(cf, &conf->ssl, conf->conf_commands) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (conf->keylog_file) {
        conf->ssl.keylog_file = conf->keylog_file;
        SSL_CTX_set_keylog_callback(conf->ssl.ctx, ngx_ssl_keylogger);
    }

    return NGX_CONF_OK;
}


#if (NGX_HTTP_PROXY_MULTICERT)
ngx_int_t
#else
static ngx_int_t
#endif
ngx_http_ssl_compile_certificates(ngx_conf_t *cf,
    ngx_http_ssl_srv_conf_t *conf)
{
    ngx_str_t                         *cert, *key;
    ngx_uint_t                         i, nelts;
    ngx_http_complex_value_t          *cv;
    ngx_http_compile_complex_value_t   ccv;

    if (conf->certificates == NULL) {
        return NGX_OK;
    }

    cert = conf->certificates->elts;
    key = conf->certificate_keys->elts;
    nelts = conf->certificates->nelts;

    for (i = 0; i < nelts; i++) {

        if (ngx_http_script_variables_count(&cert[i])) {
            goto found;
        }

        if (ngx_http_script_variables_count(&key[i])) {
            goto found;
        }
    }

    return NGX_OK;

found:

    conf->certificate_values = ngx_array_create(cf->pool, nelts,
                                             sizeof(ngx_http_complex_value_t));
    if (conf->certificate_values == NULL) {
        return NGX_ERROR;
    }

    conf->certificate_key_values = ngx_array_create(cf->pool, nelts,
                                             sizeof(ngx_http_complex_value_t));
    if (conf->certificate_key_values == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < nelts; i++) {

        cv = ngx_array_push(conf->certificate_values);
        if (cv == NULL) {
            return NGX_ERROR;
        }

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &cert[i];
        ccv.complex_value = cv;
        ccv.zero = 1;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_ERROR;
        }

        cv = ngx_array_push(conf->certificate_key_values);
        if (cv == NULL) {
            return NGX_ERROR;
        }

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &key[i];
        ccv.complex_value = cv;
        ccv.zero = 1;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    conf->passwords = ngx_ssl_preserve_passwords(cf, conf->passwords);
    if (conf->passwords == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static char *
ngx_http_ssl_certificate_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ssl_srv_conf_t *sscf = conf;

    time_t       inactive, valid;
    ngx_str_t   *value, s;
    ngx_int_t    max;
    ngx_uint_t   i;

    if (sscf->certificate_cache != NGX_CONF_UNSET_PTR) {
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

            sscf->certificate_cache = NULL;

            continue;
        }

    failed:

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (sscf->certificate_cache == NULL) {
        return NGX_CONF_OK;
    }

    if (max == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"ssl_certificate_cache\" must have "
                           "the \"max\" parameter");
        return NGX_CONF_ERROR;
    }

    sscf->certificate_cache = ngx_ssl_cache_init(cf->pool, max, valid,
                                                 inactive);
    if (sscf->certificate_cache == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_ssl_password_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ssl_srv_conf_t *sscf = conf;

    ngx_str_t  *value;

    if (sscf->passwords != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    sscf->passwords = ngx_ssl_read_password_file(cf, &value[1]);

    if (sscf->passwords == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_ssl_keylog_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ssl_srv_conf_t *sscf = conf;

    ngx_str_t  *value;

    if (sscf->keylog_file != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    sscf->keylog_file = ngx_conf_open_file(cf->cycle, &value[1]);

    if (sscf->keylog_file == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_ssl_session_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ssl_srv_conf_t *sscf = conf;

    size_t       len;
    ngx_str_t   *value, name, size;
    ngx_int_t    n;
    ngx_uint_t   i, j;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strcmp(value[i].data, "off") == 0) {
            sscf->builtin_session_cache = NGX_SSL_NO_SCACHE;
            continue;
        }

        if (ngx_strcmp(value[i].data, "none") == 0) {
            sscf->builtin_session_cache = NGX_SSL_NONE_SCACHE;
            continue;
        }

        if (ngx_strcmp(value[i].data, "builtin") == 0) {
            sscf->builtin_session_cache = NGX_SSL_DFLT_BUILTIN_SCACHE;
            continue;
        }

        if (value[i].len > sizeof("builtin:") - 1
            && ngx_strncmp(value[i].data, "builtin:", sizeof("builtin:") - 1)
               == 0)
        {
            n = ngx_atoi(value[i].data + sizeof("builtin:") - 1,
                         value[i].len - (sizeof("builtin:") - 1));

            if (n == NGX_ERROR) {
                goto invalid;
            }

            sscf->builtin_session_cache = n;

            continue;
        }

        if (value[i].len > sizeof("shared:") - 1
            && ngx_strncmp(value[i].data, "shared:", sizeof("shared:") - 1)
               == 0)
        {
            len = 0;

            for (j = sizeof("shared:") - 1; j < value[i].len; j++) {
                if (value[i].data[j] == ':') {
                    break;
                }

                len++;
            }

            if (len == 0 || j == value[i].len) {
                goto invalid;
            }

            name.len = len;
            name.data = value[i].data + sizeof("shared:") - 1;

            size.len = value[i].len - j - 1;
            size.data = name.data + len + 1;

            n = ngx_parse_size(&size);

            if (n == NGX_ERROR) {
                goto invalid;
            }

            if (n < (ngx_int_t) (8 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "session cache \"%V\" is too small",
                                   &value[i]);

                return NGX_CONF_ERROR;
            }

            sscf->shm_zone = ngx_shared_memory_add(cf, &name, n,
                                                   &ngx_http_ssl_module);
            if (sscf->shm_zone == NULL) {
                return NGX_CONF_ERROR;
            }

            sscf->shm_zone->init = ngx_ssl_session_cache_init;

            continue;
        }

        goto invalid;
    }

    if (sscf->shm_zone && sscf->builtin_session_cache == NGX_CONF_UNSET) {
        sscf->builtin_session_cache = NGX_SSL_NO_BUILTIN_SCACHE;
    }

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid session cache \"%V\"", &value[i]);

    return NGX_CONF_ERROR;
}


static char *
ngx_http_ssl_ocsp_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ssl_srv_conf_t *sscf = conf;

    size_t       len;
    ngx_int_t    n;
    ngx_str_t   *value, name, size;
    ngx_uint_t   j;

    if (sscf->ocsp_cache_zone != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        sscf->ocsp_cache_zone = NULL;
        return NGX_CONF_OK;
    }

    if (value[1].len <= sizeof("shared:") - 1
        || ngx_strncmp(value[1].data, "shared:", sizeof("shared:") - 1) != 0)
    {
        goto invalid;
    }

    len = 0;

    for (j = sizeof("shared:") - 1; j < value[1].len; j++) {
        if (value[1].data[j] == ':') {
            break;
        }

        len++;
    }

    if (len == 0 || j == value[1].len) {
        goto invalid;
    }

    name.len = len;
    name.data = value[1].data + sizeof("shared:") - 1;

    size.len = value[1].len - j - 1;
    size.data = name.data + len + 1;

    n = ngx_parse_size(&size);

    if (n == NGX_ERROR) {
        goto invalid;
    }

    if (n < (ngx_int_t) (8 * ngx_pagesize)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "OCSP cache \"%V\" is too small", &value[1]);

        return NGX_CONF_ERROR;
    }

    sscf->ocsp_cache_zone = ngx_shared_memory_add(cf, &name, n,
                                                  &ngx_http_ssl_module_ctx);
    if (sscf->ocsp_cache_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    sscf->ocsp_cache_zone->init = ngx_ssl_ocsp_cache_init;

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid OCSP cache \"%V\"", &value[1]);

    return NGX_CONF_ERROR;
}


static char *
ngx_http_ssl_conf_command_check(ngx_conf_t *cf, void *post, void *data)
{
#ifndef SSL_CONF_FLAG_FILE
    return "is not supported on this platform";
#else
    return NGX_CONF_OK;
#endif
}


static ngx_int_t
ngx_http_ssl_init(ngx_conf_t *cf)
{
    ngx_uint_t                   a, p, s;
    const char                  *name;
    ngx_http_conf_addr_t        *addr;
    ngx_http_conf_port_t        *port;
    ngx_http_ssl_srv_conf_t     *sscf;
    ngx_http_core_loc_conf_t    *clcf;
    ngx_http_core_srv_conf_t   **cscfp, *cscf;
    ngx_http_core_main_conf_t   *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    cscfp = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {

        sscf = cscfp[s]->ctx->srv_conf[ngx_http_ssl_module.ctx_index];

        if (sscf->ssl.ctx == NULL) {
            continue;
        }

        clcf = cscfp[s]->ctx->loc_conf[ngx_http_core_module.ctx_index];

        if (sscf->stapling) {
            if (ngx_ssl_stapling_resolver(cf, &sscf->ssl, clcf->resolver,
                                          clcf->resolver_timeout)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
        }

        if (sscf->ocsp) {
            if (ngx_ssl_ocsp_resolver(cf, &sscf->ssl, clcf->resolver,
                                      clcf->resolver_timeout)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
    }

#if (NGX_API)
    if (ngx_api_add(cf->cycle, "/", &ngx_api_http_ssl_entry)
        != NGX_OK)
    {
        return NGX_ERROR;
    }
#endif

    if (cmcf->ports == NULL) {
        return NGX_OK;
    }

    port = cmcf->ports->elts;
    for (p = 0; p < cmcf->ports->nelts; p++) {

        addr = port[p].addrs.elts;
        for (a = 0; a < port[p].addrs.nelts; a++) {

            if (!addr[a].opt.ssl && !addr[a].opt.quic) {
                continue;
            }

            if (addr[a].opt.quic) {
                name = "quic";

#if (NGX_QUIC_OPENSSL_COMPAT)
                if (ngx_http_ssl_quic_compat_init(cf, &addr[a]) != NGX_OK) {
                    return NGX_ERROR;
                }
#endif

            } else {
                name = "ssl";
            }

            cscf = addr[a].default_server;
            sscf = cscf->ctx->srv_conf[ngx_http_ssl_module.ctx_index];

            if (sscf->certificates) {

                if (addr[a].opt.quic && !(sscf->protocols & NGX_SSL_TLSv1_3)) {
                    ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                                  "\"ssl_protocols\" must enable TLSv1.3 for "
                                  "the \"listen ... %s\" directive in %s:%ui",
                                  name, cscf->file_name, cscf->line);
                    return NGX_ERROR;
                }

                continue;
            }

            if (!sscf->reject_handshake) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "no \"ssl_certificate\" is defined for "
                              "the \"listen ... %s\" directive in %s:%ui",
                              name, cscf->file_name, cscf->line);
                return NGX_ERROR;
            }

            /*
             * if no certificates are defined in the default server,
             * check all non-default server blocks
             */

            cscfp = addr[a].servers.elts;
            for (s = 0; s < addr[a].servers.nelts; s++) {

                cscf = cscfp[s];
                sscf = cscf->ctx->srv_conf[ngx_http_ssl_module.ctx_index];

                if (sscf->certificates || sscf->reject_handshake) {
                    continue;
                }

                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "no \"ssl_certificate\" is defined for "
                              "the \"listen ... %s\" directive in %s:%ui",
                              name, cscf->file_name, cscf->line);
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}


#if (NGX_QUIC_OPENSSL_COMPAT)

static ngx_int_t
ngx_http_ssl_quic_compat_init(ngx_conf_t *cf, ngx_http_conf_addr_t *addr)
{
    ngx_uint_t                  s;
    ngx_http_ssl_srv_conf_t    *sscf;
    ngx_http_core_srv_conf_t  **cscfp, *cscf;

    cscfp = addr->servers.elts;
    for (s = 0; s < addr->servers.nelts; s++) {

        cscf = cscfp[s];
        sscf = cscf->ctx->srv_conf[ngx_http_ssl_module.ctx_index];

        if (sscf->certificates || sscf->reject_handshake) {
            if (ngx_quic_compat_init(cf, sscf->ssl.ctx) != NGX_OK) {
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}

#endif


#if (NGX_API)

static ngx_int_t
ngx_api_http_ssl_static_handler(ngx_api_entry_data_t data, ngx_api_ctx_t *actx,
    void *ctx)
{
    ngx_str_t                    cert, key;
    ngx_uint_t                   i, j, s;
    ngx_array_t                  certs;
    ngx_ssl_api_cert_t           item, *pitem;
    ngx_api_iter_ctx_t           ictx;
    ngx_http_ssl_srv_conf_t     *sscf;
    ngx_http_core_srv_conf_t   **cscfp;
    ngx_http_core_main_conf_t   *cmcf;

    if (ngx_array_init(&certs, actx->pool, 8, sizeof(ngx_ssl_api_cert_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    cmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_core_module);
    cscfp = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {

        sscf = cscfp[s]->ctx->srv_conf[ngx_http_ssl_module.ctx_index];

        if (sscf->certificates == NULL) {
            continue;
        }

        for (i = 0; i < sscf->certificates->nelts; i++) {

            cert = ((ngx_str_t *) sscf->certificates->elts)[i];
            key = ((ngx_str_t *) sscf->certificate_keys->elts)[i];

            if (ngx_http_script_variables_count(&cert) > 0
                || ngx_http_script_variables_count(&key) > 0)
            {
                continue;
            }

            item.chain = ngx_ssl_cache_static_peek(actx->pool,
                                                   NGX_SSL_CACHE_CERT, &cert);

            if (item.chain == NULL) {
                continue;
            }

            for (j = 0; j < certs.nelts; j++) {
                pitem = &((ngx_ssl_api_cert_t *) certs.elts)[j];

                if (pitem->chain == item.chain) {
                    /* skip duplicate certificates */
                    goto next_cert;
                }
            }

            item.pkey = ngx_ssl_cache_static_peek(actx->pool,
                                                  NGX_SSL_CACHE_PKEY, &key);
            if (item.pkey == NULL) {
                continue;
            }

            item.filename = cert;

            pitem = ngx_array_push(&certs);
            if (pitem == NULL) {
                return NGX_ERROR;
            }

            *pitem = item;

        next_cert:

            continue;
        }
    }

#if (NGX_STREAM_SSL)
    if (ngx_api_stream_add_certs(actx, &certs) != NGX_OK) {
        return NGX_ERROR;
    }
#endif

    if (certs.nelts == 0) {
        return NGX_DECLINED;
    }

    ngx_memzero(&ictx, sizeof(ngx_api_iter_ctx_t));

    ictx.entry.handler = ngx_api_object_handler;
    ictx.entry.data.ents = ngx_api_http_ssl_cert_entries;
    ictx.ctx = NULL;
    ictx.elts = &certs;
    ictx.read_only = 1;

    return ngx_api_object_iterate(ngx_api_http_ssl_cert_iter, &ictx, actx);
}


static ngx_int_t
ngx_api_http_ssl_cert_iter(ngx_api_iter_ctx_t *ictx, ngx_api_ctx_t *actx)
{
    ngx_array_t         *certs;
    ngx_ssl_api_cert_t  *cert, *end;

    cert = ictx->ctx;
    certs = ictx->elts;

    if (cert == NULL) {
        cert = certs->elts;

    } else {
        cert++;
        end = &((ngx_ssl_api_cert_t *) certs->elts)[certs->nelts];
        if (cert == end) {
            return NGX_DECLINED;
        }
    }

    ictx->entry.name = cert->filename;
    ictx->ctx = cert;

    return NGX_OK;
}


static ngx_int_t
ngx_api_http_ssl_key_handler(ngx_api_entry_data_t data, ngx_api_ctx_t *actx,
    void *ctx)
{
    ngx_str_t            s;
    ngx_ssl_api_cert_t  *cert;
    u_char               buf[32];

    cert = ctx;
    s.data = buf;
    s.len = sizeof(buf);

    ngx_api_cert_key_info(cert->pkey, s.data, &s.len);

    data.str = &s;

    return ngx_api_string_handler(data, actx, ctx);
}


static ngx_int_t
ngx_api_http_ssl_chain_handler(ngx_api_entry_data_t data, ngx_api_ctx_t *actx,
    void *ctx)
{
    int                  i, n;
    X509                *x509;
    ngx_str_t            name;
    ngx_int_t            index, rc;
    ngx_data_item_t     *list;
    ngx_ssl_api_cert_t  *cert;

    cert = ctx;
    index = -1;

    n = sk_X509_num(cert->chain);

    if (ngx_api_next_segment(&actx->path, &name) == NGX_OK) {
        /* .../chain/N */
        index = ngx_atoi(name.data, name.len);
        if (index == NGX_ERROR || index >= n) {
            return NGX_DECLINED;
        }

        x509 = sk_X509_value(cert->chain, index);

        return ngx_api_object_handler(data, actx, x509);
    }

    /* .../chain */

    list = ngx_data_new_list(actx->pool);
    if (list == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < n; i++) {
        x509 = sk_X509_value(cert->chain, i);

        rc = ngx_api_object_handler(data, actx, x509);

        if (rc != NGX_OK) {
            return rc;
        }

        if (ngx_data_list_add(list, actx->out) != NGX_OK) {
            return NGX_ERROR;
        }

        actx->out = NULL;
    }

    actx->out = list;

    return NGX_OK;
}


static ngx_int_t
ngx_api_http_ssl_subject_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    X509                       *x509;
    ngx_int_t                   rc;
    ngx_api_http_ssl_dn_ctx_t   nctx;

    x509 = ctx;

    nctx.name = X509_get_subject_name(x509);
    nctx.alt_names = X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);

    rc = ngx_api_object_handler(data, actx, &nctx);

    if (nctx.alt_names != NULL) {
        GENERAL_NAMES_free(nctx.alt_names);
    }

    return rc;
}


static ngx_int_t
ngx_api_http_ssl_issuer_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    X509                       *x509;
    ngx_int_t                   rc;
    ngx_api_http_ssl_dn_ctx_t   nctx;

    x509 = ctx;

    nctx.name = X509_get_issuer_name(x509);
    nctx.alt_names = X509_get_ext_d2i(x509, NID_issuer_alt_name, NULL, NULL);

    rc = ngx_api_object_handler(data, actx, &nctx);

    if (nctx.alt_names != NULL) {
        GENERAL_NAMES_free(nctx.alt_names);
    }

    return rc;
}


static ngx_int_t
ngx_api_http_ssl_common_name_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    ngx_api_http_ssl_dn_ctx_t  *nctx = ctx;

    return ngx_api_http_ssl_dn_handler(data, actx, nctx->name, NID_commonName);
}


static ngx_int_t
ngx_api_http_ssl_alt_names_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    ngx_api_http_ssl_dn_ctx_t  *nctx = ctx;

    int               i, count;
    ngx_str_t         s;
    ngx_int_t         index, n;
    GENERAL_NAME     *alt_name;
    ngx_data_item_t  *list, *name;

    if (nctx->alt_names == NULL) {
        return NGX_DECLINED;
    }

    index = -1;

    if (ngx_api_next_segment(&actx->path, &s) == NGX_OK) {
        /* .../alt_names/N */
        index = ngx_atoi(s.data, s.len);
        if (index == NGX_ERROR) {
            return NGX_DECLINED;
        }

        if (ngx_api_next_segment(&actx->path, &s) == NGX_OK) {
            return NGX_DECLINED;
        }
    }

    list = NULL;
    n = 0;
    count = sk_GENERAL_NAME_num(nctx->alt_names);

    for (i = 0; i != count; i++) {
        alt_name = sk_GENERAL_NAME_value(nctx->alt_names, i);

        if (alt_name->type != GEN_DNS) {
            continue;
        }

        s.len = ASN1_STRING_length(alt_name->d.dNSName);
#if OPENSSL_VERSION_NUMBER > 0x10100000L
        s.data = (u_char *) ASN1_STRING_get0_data(alt_name->d.dNSName);
#else
        s.data = ASN1_STRING_data(alt_name->d.dNSName);
#endif

        if (index < 0) {
            /* .../alt_names */
            name = ngx_data_new_string(&s, actx->pool);
            if (name == NULL) {
                return NGX_ERROR;
            }

            if (list == NULL) {
                list = ngx_data_new_list(actx->pool);
                if (list == NULL) {
                    return NGX_ERROR;
                }
            }

            if (ngx_data_list_add(list, name) != NGX_OK) {
                return NGX_ERROR;
            }

        } else if (index == n) {
            /* .../alt_names/N */
            data.str = &s;

            return ngx_api_string_handler(data, actx, ctx);
        }

        n++;
    }

    if (list == NULL) {
        return NGX_DECLINED;
    }

    actx->out = list;
    return NGX_OK;
}


static ngx_int_t
ngx_api_http_ssl_country_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    ngx_api_http_ssl_dn_ctx_t  *nctx = ctx;

    return ngx_api_http_ssl_dn_handler(data, actx, nctx->name, NID_countryName);
}


static ngx_int_t
ngx_api_http_ssl_state_or_province_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    ngx_api_http_ssl_dn_ctx_t  *nctx = ctx;

    return ngx_api_http_ssl_dn_handler(data, actx, nctx->name,
                                       NID_stateOrProvinceName);
}


static ngx_int_t
ngx_api_http_ssl_organization_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    ngx_api_http_ssl_dn_ctx_t  *nctx = ctx;

    return ngx_api_http_ssl_dn_handler(data, actx, nctx->name,
                                       NID_organizationName);
}


static ngx_int_t
ngx_api_http_ssl_dn_handler(ngx_api_entry_data_t data, ngx_api_ctx_t *actx,
    X509_NAME *name, int nid)
{
    int        len;
    ngx_str_t  s;
    u_char     buf[256];

    if (name == NULL) {
        return NGX_DECLINED;
    }

    len = X509_NAME_get_text_by_NID(name, nid, (char *) buf, sizeof(buf));

    if (len < 0) {
        return NGX_DECLINED;
    }

    s.len = len;
    s.data = buf;

    data.str = &s;

    return ngx_api_string_handler(data, actx, NULL);
}


static ngx_int_t
ngx_api_http_ssl_since_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    return ngx_api_http_ssl_time_info(data, actx,
                                      X509_get_notBefore((X509 *) ctx));
}


static ngx_int_t
ngx_api_http_ssl_until_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    return ngx_api_http_ssl_time_info(data, actx,
                                      X509_get_notAfter((X509 *) ctx));
}


static ngx_int_t
ngx_api_http_ssl_time_info(ngx_api_entry_data_t data, ngx_api_ctx_t *actx,
    ASN1_TIME *asn1_time)
{
    BIO        *bio;
    ngx_log_t  *log;
    ngx_int_t   rc;
    ngx_str_t   s;

    log = actx->pool->log;

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, log, 0, "BIO_new() failed");
        return NGX_ERROR;
    }

    if (ASN1_TIME_print(bio, asn1_time) == 1) {
        s.len = BIO_get_mem_data(bio, &s.data);

        data.str = &s;

        rc = ngx_api_string_handler(data, actx, NULL);

    } else {
        ngx_ssl_error(NGX_LOG_ALERT, log, 0, "ASN1_TIME_print() failed");
        rc = NGX_ERROR;
    }

    BIO_free(bio);

    return rc;
}


static void
ngx_api_cert_key_info(EVP_PKEY *key, u_char *buf, size_t *size)
{
    int            nid;
    u_char        *s, *end;
    const EC_KEY  *ec;

    if (key == NULL) {
        *size = 0;
        return;
    }

    end = buf + *size;

    switch (EVP_PKEY_base_id(key)) {
    case EVP_PKEY_RSA:
        s = ngx_slprintf(buf, end, "RSA (%d bits)", EVP_PKEY_bits(key));
        break;

    case EVP_PKEY_DH:
        s = ngx_slprintf(buf, end, "DH (%d bits)", EVP_PKEY_bits(key));
        break;

    case EVP_PKEY_EC:
        ec = EVP_PKEY_get0_EC_KEY(key);
        if (ec != NULL) {
            nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec));
            s = (nid != NID_undef)
                ? ngx_slprintf(buf, end, "EC (%s)", OBJ_nid2sn(nid))
                : ngx_slprintf(buf, end, "EC");

        } else {
            s = ngx_slprintf(buf, end, "EC");
        }
        break;

    default:
        s = ngx_slprintf(buf, end, "unknown");
        break;
    }

    *size = s - buf;
}


#if (NGX_HTTP_ACME)

static ngx_int_t
ngx_api_http_ssl_acme_clients_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    EVP_PKEY            *pkey;
    ngx_uint_t           i;
    ngx_array_t         *certs;
    ngx_array_t         *clients;
    STACK_OF(X509)      *chain;
    ngx_acme_client_t   *cli;
    ngx_ssl_api_cert_t  *pitem;
    ngx_api_iter_ctx_t   ictx;
    ngx_pool_cleanup_t  *cln;

    chain = NULL;
    pkey = NULL;

    clients = ngx_acme_clients((ngx_cycle_t *) ngx_cycle);
    if (clients == NULL || clients->nelts == 0) {
        return NGX_DECLINED;
    }

    certs = ngx_array_create(actx->pool, clients->nelts,
                             sizeof(ngx_ssl_api_cert_t));
    if (certs == NULL) {
        return NGX_ERROR;
    }

    /*
     * Certificate/key pairs provided by ACME clients will be converted
     * to OpenSSL objects, which must be freed after use.
     */
    cln = ngx_pool_cleanup_add(actx->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_http_acme_certs_free;
    cln->data = certs;

    for (i = 0; i < clients->nelts; i++) {

        cli = ((ngx_acme_client_t **) clients->elts)[i];

        switch (ngx_acme_get_cert(actx->pool, cli, &chain, &pkey)) {

        case NGX_OK:
            pitem = ngx_array_push(certs);
            if (pitem == NULL) {
                sk_X509_pop_free(chain, X509_free);
                EVP_PKEY_free(pkey);
                return NGX_ERROR;
            }

            pitem->filename = *ngx_acme_client_name(cli);
            pitem->chain = chain;
            pitem->pkey = pkey;

            break;

        case NGX_ERROR:
            return NGX_ERROR;

        default: /* NGX_DECLINED */
            continue;
        }
    }

    if (certs->nelts == 0) {
        return NGX_DECLINED;
    }

    ngx_memzero(&ictx, sizeof(ngx_api_iter_ctx_t));

    ictx.entry.handler = ngx_api_object_handler;
    ictx.entry.data.ents = ngx_api_http_ssl_cert_entries;
    ictx.ctx = NULL;
    ictx.elts = certs;
    ictx.read_only = 1;

    return ngx_api_object_iterate(ngx_api_http_ssl_cert_iter, &ictx, actx);
}


static ngx_int_t
ngx_acme_get_cert(ngx_pool_t *pool, ngx_acme_client_t *cli,
    STACK_OF(X509) **chain, EVP_PKEY **pkey)
{
    BIO                   *bio;
    X509                  *x509;
    u_long                 err;
    ngx_int_t              rc, count;
    ngx_log_t             *log;
    ngx_str_t              cert, key;
    ngx_variable_value_t   v;

    log = pool->log;

    if (ngx_acme_handle_cert_variable(pool, &v, cli, NULL) != NGX_OK) {
        return NGX_ERROR;
    }

    if (v.not_found) {
        return NGX_DECLINED;
    }

    /* skip "data:" */
    cert.data = v.data + 5;
    cert.len = v.len - 5;

    if (ngx_acme_handle_cert_key_variable(pool, &v, cli, NULL) != NGX_OK) {
        return NGX_ERROR;
    }

    if (v.not_found) {
        return NGX_DECLINED;
    }

    key.data = v.data + 5;
    key.len = v.len - 5;

    *chain = sk_X509_new_null();
    if (*chain == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, log, 0, "sk_X509_new_null() failed");
        return NGX_ERROR;
    }

    rc = NGX_ERROR;
    x509 = NULL;

    bio = BIO_new_mem_buf(cert.data, (int) cert.len);

    if (bio == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, log, 0, "BIO_new_mem_buf() failed");
        goto failed;
    }

    for (count = 0; /* void */; count++) {
        x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (x509 == NULL) {
            err = ERR_peek_last_error();

            if (count > 0
                && ERR_GET_LIB(err) == ERR_LIB_PEM
                && ERR_GET_REASON(err) == PEM_R_NO_START_LINE)
            {
                ERR_clear_error();
                break;

            } else {
                ngx_ssl_error(NGX_LOG_ALERT, log, 0,
                              "PEM_read_bio_X509() failed");
            }

            goto failed;
        }

        if (sk_X509_push(*chain, x509) == 0) {
            ngx_ssl_error(NGX_LOG_ALERT, log, 0, "sk_X509_push() failed");
            goto failed;
        }
    }

    BIO_free(bio);

    bio = BIO_new_mem_buf(key.data, (int) key.len);

    if (bio == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, log, 0, "BIO_new_mem_buf() failed");
        goto failed;
    }

    *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);

    if (*pkey == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, log, 0,
                      "PEM_read_bio_PrivateKey() failed");
        goto failed;
    }

    rc = NGX_OK;

failed:

    if (rc != NGX_OK) {
        sk_X509_pop_free(*chain, X509_free);
    }

    if (x509 != NULL) {
        X509_free(x509);
    }

    if (bio != NULL) {
        BIO_free(bio);
    }

    return rc;
}


static void
ngx_http_acme_certs_free(void *data)
{
    ngx_array_t  *certs = data;

    ngx_uint_t           i;
    ngx_ssl_api_cert_t  *cert;

    for (i = 0; i < certs->nelts; i++) {
        cert = &((ngx_ssl_api_cert_t *) certs->elts)[i];

        sk_X509_pop_free(cert->chain, X509_free);
        EVP_PKEY_free(cert->pkey);
    }
}

#endif

#endif
