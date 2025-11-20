
/*
 * Copyright (C) 2025 Web Server LLC
 */


#ifndef _NGX_ACME_H_INCLUDED_
#define _NGX_ACME_H_INCLUDED_

/*
 * Some ACME declarations that can be used by both ngx_http_acme_module and
 * ngx_stream_acme_module.
 */

#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_acme_client_s            ngx_acme_client_t;

typedef struct {
    ngx_str_t                    name;
    ngx_acme_client_t           *ref;

    u_char                      *file_name;
    ngx_uint_t                   line;
} ngx_acme_client_ref_t;


ngx_int_t ngx_acme_handle_cert_variable(ngx_pool_t *pool,
    ngx_variable_value_t *v, ngx_acme_client_t *cli,
    ngx_ssl_connection_t *ssl);
ngx_int_t ngx_acme_handle_cert_key_variable(ngx_pool_t *pool,
    ngx_variable_value_t *v, ngx_acme_client_t *cli,
    ngx_ssl_connection_t *ssl);
ngx_array_t *ngx_acme_clients(ngx_conf_t *cf);
ngx_str_t *ngx_acme_client_name(ngx_acme_client_t *cli);
ngx_int_t ngx_acme_add_server_names(ngx_conf_t *cf, ngx_acme_client_t *cli,
    ngx_array_t *server_names, u_char *cf_file_name, ngx_uint_t cf_line);
ngx_int_t ngx_acme_select_alpn_proto(const unsigned char **out,
    unsigned char *outlen, const unsigned char *in, unsigned int inlen);
ngx_uint_t ngx_acme_is_alpn_needed(ngx_conf_t *cf);

#if (NGX_STREAM_ACME)
ngx_acme_client_ref_t *ngx_stream_acme_find_client(ngx_conf_t *cf,
    ngx_str_t *name);
#endif

#endif /* _NGX_ACME_H_INCLUDED_ */
