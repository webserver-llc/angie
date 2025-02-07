
/*
 * Copyright (C) 2023 Web Server LLC
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_STREAM_SSL_H_INCLUDED_
#define _NGX_STREAM_SSL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


typedef struct {
    ngx_msec_t       handshake_timeout;

    ngx_flag_t       prefer_server_ciphers;
    ngx_flag_t       early_data;
    ngx_flag_t       reject_handshake;

    ngx_ssl_t        ssl;

    ngx_uint_t       protocols;

    ngx_uint_t       verify;
    ngx_uint_t       verify_depth;
    ngx_flag_t       no_check_time;

    ssize_t          builtin_session_cache;

    time_t           session_timeout;

    ngx_array_t     *certificates;
    ngx_array_t     *certificate_keys;

    ngx_array_t     *certificate_values;
    ngx_array_t     *certificate_key_values;

    ngx_str_t        dhparam;
    ngx_str_t        ecdh_curve;
    ngx_str_t        client_certificate;
    ngx_str_t        trusted_certificate;
    ngx_str_t        crl;
    ngx_str_t        alpn;

    ngx_str_t        ciphers;

    ngx_array_t     *passwords;
    ngx_array_t     *conf_commands;

    ngx_shm_zone_t  *shm_zone;

    ngx_flag_t       session_tickets;
    ngx_array_t     *session_ticket_keys;

    ngx_uint_t       ocsp;
    ngx_str_t        ocsp_responder;
    ngx_shm_zone_t  *ocsp_cache_zone;

    ngx_flag_t       stapling;
    ngx_flag_t       stapling_verify;
    ngx_str_t        stapling_file;
    ngx_str_t        stapling_responder;

#if (NGX_HAVE_NTLS)
    ngx_flag_t       ntls;
#endif

} ngx_stream_ssl_srv_conf_t;


extern ngx_module_t  ngx_stream_ssl_module;

#if (NGX_STREAM_PROXY_MULTICERT)
char *ngx_stream_ssl_certificate_slot(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
ngx_int_t ngx_stream_ssl_compile_certificates(ngx_conf_t *cf,
    ngx_stream_ssl_srv_conf_t *conf);
#endif

#endif /* _NGX_STREAM_SSL_H_INCLUDED_ */
