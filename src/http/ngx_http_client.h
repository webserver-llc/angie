
/*
 * Copyright (C) 2025 Web Server LLC
 */


#ifndef _NGX_HTTP_CLIENT_H_INCLUDED_
#define _NGX_HTTP_CLIENT_H_INCLUDED_

/*
 * injects the named location with provided commands block into the
 * configuration and returns resulting http configuration context.
 *
 * the http {} and client {} blocks are created if necessary.
 * if the named location already exists, pointer to existing configuration
 * is returned, allowing user to override default commands.
 */
ngx_http_conf_ctx_t *ngx_http_client_create_location(ngx_conf_t *cf,
    ngx_str_t *name, ngx_str_t *commands);

/* searches for existing named client location with given name */
ngx_int_t ngx_http_client_find_location(ngx_conf_t *cf, ngx_str_t *name,
    ngx_http_conf_ctx_t *res);

/*
 * creates client request using configuration specified by ctx and given URI;
 * the handler sets finalization handler, data is a user-provided pointer.
 * the request is not active and can be further initialized as required;
 * use ngx_http_finalize_request() to initiate request processing.
 */
ngx_http_request_t *ngx_http_client_create_request(ngx_pool_t *pool,
    ngx_http_conf_ctx_t *ctx, ngx_str_t *uri,
    ngx_http_post_subrequest_pt handler, void *data);

/* destroys the client request */
void ngx_http_client_close_request(ngx_http_request_t *r);

/* sets and enables the response header filter */
void ngx_http_client_set_header_filter(ngx_http_request_t *r,
    ngx_http_output_header_filter_pt header_filter);

/* sets and enables the response body filter */
void ngx_http_client_set_body_filter(ngx_http_request_t *r,
    ngx_http_output_body_filter_pt body_filter);



#endif /* _NGX_HTTP_CLIENT_H_INCLUDED_ */
