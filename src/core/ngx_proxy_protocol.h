
/*
 * Copyright (C) 2025 Web Server LLC
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PROXY_PROTOCOL_H_INCLUDED_
#define _NGX_PROXY_PROTOCOL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_PROXY_PROTOCOL_MAX_HEADER     4096


struct ngx_proxy_protocol_s {
    ngx_str_t           src_addr;
    ngx_str_t           dst_addr;
    in_port_t           src_port;
    in_port_t           dst_port;
    ngx_str_t           tlvs;
};


/* function prototype for complex value evaluation callback */
typedef ngx_int_t (*ngx_complex_value_pt)(void *ctx, void *cv, ngx_str_t *v);


/* proxy protocol configuration */
typedef struct {
    ngx_complex_value_pt   complex_value;
    ngx_uint_t             version;
    ngx_array_t           *tlvs;
    ngx_array_t           *tlvs_ssl;
} ngx_proxy_protocol_conf_t;


u_char *ngx_proxy_protocol_read(ngx_connection_t *c, u_char *buf,
    u_char *last);
u_char *ngx_proxy_protocol_write(ngx_connection_t *c,
    ngx_proxy_protocol_conf_t *conf, u_char **buf_last);
ngx_int_t ngx_proxy_protocol_get_tlv(ngx_connection_t *c, ngx_str_t *name,
    ngx_str_t *value);
char *ngx_proxy_protocol_conf_add_tlv(ngx_conf_t *cf,
    ngx_proxy_protocol_conf_t *conf, ngx_str_t *name, void *cv);


#endif /* _NGX_PROXY_PROTOCOL_H_INCLUDED_ */
