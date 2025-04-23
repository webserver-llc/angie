
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


ngx_array_t *ngx_acme_clients(ngx_conf_t *cf);
ngx_str_t *ngx_acme_client_name(ngx_acme_client_t *cli);
ngx_int_t ngx_acme_handle_cert_variable(ngx_pool_t *pool,
    ngx_variable_value_t *v, ngx_acme_client_t *cli);
ngx_int_t ngx_acme_handle_cert_key_variable(ngx_variable_value_t *v,
    ngx_acme_client_t *cli);
ngx_int_t ngx_acme_add_server_names(ngx_conf_t *cf, ngx_acme_client_t *cli,
    ngx_array_t *server_names, u_char *cf_file_name, ngx_uint_t cf_line);


#endif /* _NGX_ACME_H_INCLUDED_ */
