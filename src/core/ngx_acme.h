
/*
 * Copyright (C) 2025 Web Server LLC
 */


#ifndef _NGX_ACME_H_INCLUDED_
#define _NGX_ACME_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef enum {
    NGX_KT_UNSUPPORTED,
    NGX_KT_RSA,
    NGX_KT_EC,
} ngx_keytype_t;


typedef enum {
    NGX_AC_HTTP_01,
    NGX_AC_DNS_01,
    NGX_AC_ALPN_01
} ngx_acme_challenge_t;


typedef enum {
    NGX_AH_ADD,
    NGX_AH_REMOVE,
} ngx_acme_hook_t;


typedef enum {
    NGX_AEA_HS256,
    NGX_AEA_HS384,
    NGX_AEA_HS512,
} ngx_acme_eab_alg_t;


typedef struct {
    ngx_keytype_t                type;
    EVP_PKEY                    *key;
    int                          bits;
    ngx_file_t                   file;
    size_t                       file_size;
} ngx_acme_privkey_t;


typedef struct ngx_acme_client_s           ngx_acme_client_t;
typedef struct ngx_acme_session_s          ngx_acme_session_t;
typedef struct ngx_acme_sh_cert_s          ngx_acme_sh_cert_t;

typedef struct ngx_http_acme_client_s      ngx_http_acme_client_t;


struct ngx_acme_client_s {
    ngx_log_t                   *log;
    ngx_str_t                    name;
    ngx_str_t                    path;
    ngx_uint_t                   cf_line;
    ngx_str_t                    cf_filename;
    ngx_str_t                    server;
    ngx_url_t                    server_url;
    ngx_str_t                    email;
    ngx_array_t                 *domains;
    time_t                       renew_before_expiry;
    time_t                       retry_after_error;
    time_t                       expiry_time;
    time_t                       renew_time;
    size_t                       max_cert_size;
    ngx_uint_t                   challenge;
    ngx_acme_privkey_t           account_key;
    ngx_acme_privkey_t           private_key;
    u_char                      *private_key_data;
    ngx_file_t                   certificate_file;
    size_t                       certificate_file_size;
    ngx_acme_session_t          *session;
    ngx_acme_sh_cert_t          *sh_cert;
    ngx_http_acme_client_t      *hcli;
    ngx_str_t                    eab_id;
    ngx_str_t                    eab_key;
    ngx_acme_eab_alg_t           eab_alg;

    unsigned                     enabled:1;
    unsigned                     renew_on_load:1;
    unsigned                     referenced:1;
};


typedef struct {
    ngx_array_t                  clients;
} ngx_acme_conf_t;


ngx_int_t ngx_acme_handle_cert_variable(ngx_pool_t *pool,
    ngx_variable_value_t *v, ngx_acme_client_t *cli,
    ngx_ssl_connection_t *ssl);
ngx_int_t ngx_acme_handle_cert_key_variable(ngx_pool_t *pool,
    ngx_variable_value_t *v, ngx_acme_client_t *cli,
    ngx_ssl_connection_t *ssl);
ngx_array_t *ngx_acme_clients(ngx_cycle_t *cycle);
ngx_int_t ngx_acme_add_server_names(ngx_conf_t *cf, ngx_acme_client_t *cli,
    ngx_array_t *server_names, u_char *cf_file_name, ngx_uint_t cf_line);
ngx_int_t ngx_acme_select_alpn_proto(const unsigned char **out,
    unsigned char *outlen, const unsigned char *in, unsigned int inlen);
ngx_uint_t ngx_acme_is_alpn_needed(ngx_conf_t *cf);
ngx_acme_client_t *ngx_acme_client_add(ngx_conf_t *cf, ngx_str_t *name);


extern ngx_module_t              ngx_acme_module;


#endif /* _NGX_ACME_H_INCLUDED_ */
