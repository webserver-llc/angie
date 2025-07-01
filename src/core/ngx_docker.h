
/*
 * Copyright (C) 2025 Web Server LLC
 */


#ifndef _NGX_DOCKER_H_INCLUDED_
#define _NGX_DOCKER_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define NGX_DOCKER_UPSTREAM_SID_LEN  32

#define NGX_DOCKER_EVENT_RETRY_TIME  (15 * 1000)

#define ngx_docker_node(n)  ngx_rbtree_data(n, ngx_docker_container_t, node)


typedef struct ngx_docker_upstream_s  ngx_docker_upstream_t;

typedef ngx_int_t (*ngx_docker_upstream_action_pt)(ngx_docker_upstream_t *u);


typedef enum {
    NGX_DOCKER_UNKNOWN_UPSTREAM,
    NGX_DOCKER_HTTP_UPSTREAM,
    NGX_DOCKER_STREAM_UPSTREAM
} ngx_docker_upstream_type_t;


typedef struct {
    uint8_t                            major;
    uint8_t                            minor;
} ngx_docker_api_version_t;

typedef struct {
    ngx_docker_upstream_action_pt      add;
    ngx_docker_upstream_action_pt      remove;
    ngx_docker_upstream_action_pt      pause;
} ngx_docker_upstream_action_t;

typedef struct {
    ngx_rbtree_node_t                  node;

    ngx_str_t                          id;
    ngx_str_t                          ip;
    ngx_str_t                          network;

    ngx_pool_t                        *pool;

    ngx_event_t                        event;

    ngx_docker_upstream_t             *upstream;

    void                              *data;

    ngx_uint_t                         expired;

    unsigned                           down:1;
} ngx_docker_container_t;

struct ngx_docker_upstream_s {
    ngx_str_t                          name;
    ngx_str_t                          sid;

    ngx_url_t                          url;

    ngx_uint_t                         port;
    ngx_uint_t                         weight;
    ngx_uint_t                         max_conns;
    ngx_uint_t                         max_fails;

    time_t                             fail_timeout;
    ngx_msec_t                         slow_start;

    ngx_docker_container_t            *container;

    ngx_docker_upstream_type_t         type;

    ngx_docker_upstream_action_t       action;

    ngx_docker_upstream_t             *next;

    void                              *uscf;

    unsigned                           backup:1;
};


void ngx_docker_containers_cleanup(ngx_rbtree_t *rbtree);
void ngx_docker_init_stream_upstream_actions(ngx_docker_upstream_action_pt add,
    ngx_docker_upstream_action_pt remove, ngx_docker_upstream_action_pt patch);
void ngx_docker_init_http_upstream_actions(ngx_docker_upstream_action_pt add,
    ngx_docker_upstream_action_pt remove, ngx_docker_upstream_action_pt patch);
void ngx_docker_process_container(ngx_docker_container_t *dc, ngx_buf_t *b,
    ngx_pool_t *pool, ngx_rbtree_t *rbtree, ngx_log_t *log);

ngx_int_t ngx_docker_process_containers(ngx_buf_t *b, ngx_pool_t *pool,
    ngx_rbtree_t *rbtree, ngx_log_t *log);
ngx_int_t ngx_docker_get_api_version(ngx_buf_t *b, ngx_pool_t *pool,
    ngx_docker_api_version_t *api_version, ngx_log_t *log);

ngx_docker_container_t *ngx_docker_lookup_container(ngx_rbtree_t *rbtree,
    ngx_str_t *key);
ngx_docker_container_t *ngx_docker_process_event(ngx_data_item_t *json,
    ngx_rbtree_t *rbtree, ngx_log_t *log);


#endif /* _NGX_DOCKER_H_INCLUDED_ */
