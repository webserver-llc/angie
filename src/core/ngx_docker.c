
/*
 * Copyright (C) 2025 Web Server LLC
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_docker.h>


#define ngx_docker_upstream_type(u)                                           \
    ((u)->type == NGX_DOCKER_HTTP_UPSTREAM ? "http" : "stream")

#define ngx_docker_get_data_child(item)                                       \
    (((item)->type != NGX_DATA_OBJECT_TYPE || (item)->data.child == NULL)     \
     ? NULL : (item)->data.child->next)


static ngx_docker_upstream_action_t  http_upstream_action;
static ngx_docker_upstream_action_t  stream_upstream_action;


static ngx_int_t ngx_docker_process_labels(ngx_docker_container_t *dc,
    ngx_str_t *attr, ngx_data_item_t *json, ngx_log_t *log);
static ngx_int_t ngx_docker_process_label(ngx_data_item_t *item,
    ngx_docker_container_t *dc, ngx_log_t *log);
static ngx_int_t ngx_docker_process_network(ngx_docker_container_t *dc,
    ngx_data_item_t *json, ngx_log_t *log);
static ngx_int_t ngx_docker_get_object_value(ngx_data_item_t *json,
    ngx_str_t *target, ngx_str_t *out);
static ngx_int_t ngx_docker_parse_api_version(ngx_str_t *vstr,
    ngx_docker_api_version_t *v);

static void ngx_docker_label_next_part(ngx_str_t *label, ngx_str_t *part);
static void ngx_docker_destroy_container(ngx_docker_container_t *dc);
static void ngx_docker_process_event_die(ngx_str_t *id, ngx_rbtree_t *tree);
static void ngx_docker_process_event_pause(ngx_str_t *id, ngx_rbtree_t *tree,
    ngx_int_t down);

static ngx_docker_container_t *ngx_docker_process_event_start(ngx_str_t *id,
    ngx_data_item_t *json, ngx_rbtree_t *tree, ngx_log_t *log);


static ngx_int_t
ngx_docker_get_object_value(ngx_data_item_t *json, ngx_str_t *target,
    ngx_str_t *out)
{
    ngx_data_item_t  *item;

    item = ngx_data_object_take(json, target);
    if (item == NULL) {
        return NGX_ERROR;
    }

    return ngx_data_get_string(out, item);
}


static void
ngx_docker_label_next_part(ngx_str_t *label, ngx_str_t *part)
{
    u_char  *p;

    p = ngx_strlchr(label->data, label->data + label->len, '.');
    if (p == NULL) {
        part->len = label->len;
        part->data = label->data;

        label->len = 0;
        label->data = NULL;

        return;
    }

    part->len = p - label->data;
    part->data = label->data;

    label->len -= (part->len + 1);
    label->data = ++p;
}


static void
ngx_docker_upstreams_action_remove(ngx_docker_container_t *dc)
{
    ngx_docker_upstream_t  *u;

    for (u = dc->upstream; u; u = u->next) {
        u->action.remove(u);
    }
}


static void
ngx_docker_upstreams_action_pause(ngx_docker_container_t *dc)
{
    ngx_docker_upstream_t  *u;

    for (u = dc->upstream; u; u = u->next) {
        u->action.pause(u);
    }
}


static ngx_int_t
ngx_docker_upstreams_action_add(ngx_docker_container_t *dc)
{
    ngx_int_t               rc;
    ngx_docker_upstream_t  *u;

    rc = NGX_ERROR;

    for (u = dc->upstream; u; u = u->next) {

        if (u->action.add(u) == NGX_OK) {
            rc = NGX_OK;
            continue;
        }
    }

    return rc;
}


static ngx_docker_upstream_t *
ngx_docker_get_upstream(ngx_docker_container_t *dc, ngx_str_t *name,
    ngx_docker_upstream_type_t type, ngx_log_t *log)
{
    ngx_docker_upstream_t  *u, **up;

    for (up = &dc->upstream; *up; up = &(*up)->next) {
        u = *up;

        if (u->type == type
            && u->name.len == name->len
            && ngx_strncmp(u->name.data, name->data, u->name.len) == 0)
        {
            return u;
        }
    }

    u = ngx_pcalloc(dc->pool, sizeof(ngx_docker_upstream_t));
    if (u == NULL) {
        return NULL;
    }

    *up = u;

    u->uscf = (void *) -1;
    u->port = (ngx_uint_t) -1;
    u->weight = (ngx_uint_t) -1;
    u->max_fails = (ngx_uint_t) -1;
    u->fail_timeout = (time_t) -1;
    u->slow_start = (ngx_msec_t) -1;
    u->type = type;
    u->container = dc;

    u->name.data = ngx_pstrdup(dc->pool, name);
    if (u->name.data == NULL) {
        return NULL;
    }

    u->name.len = name->len;

    if (type == NGX_DOCKER_HTTP_UPSTREAM) {

        if (http_upstream_action.add == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "cannot process Docker container \"%V\": "
                          "Angie was built without shared memory zone support "
                          "in http upstream module "
                          "(--without-http_upstream_zone_module)",
                          &dc->id);
            return NULL;
        }

        u->action = http_upstream_action;

    } else {

        if (stream_upstream_action.add == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "cannot process Docker container \"%V\": "
                          "Angie was built without shared memory zone support "
                          "in stream upstream module "
                          "(--without-stream_upstream_zone_module)",
                          &dc->id);
            return NULL;
        }

        u->action = stream_upstream_action;
    }

    return u;
}


static ngx_int_t
ngx_docker_process_label(ngx_data_item_t *item, ngx_docker_container_t *dc,
    ngx_log_t *log)
{
    ngx_str_t                    orig_label, part, label, value;
    ngx_docker_upstream_t       *u;
    ngx_docker_upstream_type_t   type;

    if (ngx_data_get_string(&label, item) != NGX_OK) {
        return NGX_ERROR;
    }

    if (item->next == NULL) {
        return NGX_ERROR;
    }

    if (ngx_data_get_string(&value, item->next) != NGX_OK) {
        return NGX_ERROR;
    }

    if (label.len < 6 || ngx_strncmp(label.data, "angie.", 6) != 0) {
        return NGX_OK;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, log, 0, "Angie label: \"%V=%V\"",
                   &label, &value);

    orig_label = label;

    /* skip 'angie' part */
    ngx_docker_label_next_part(&label, &part);

    ngx_docker_label_next_part(&label, &part);

    if (part.len == 7 && ngx_strncmp(part.data, "network", 7) == 0) {

        dc->network.data = ngx_pstrdup(dc->pool, &value);
        if (dc->network.data == NULL) {
            return NGX_ERROR;
        }

        dc->network.len = value.len;

        ngx_docker_label_next_part(&label, &part);

        if (part.len != 0) {
            goto part_error;
        }

        return NGX_OK;
    }

    if (part.len == 4 && ngx_strncmp(part.data, "http", 4) == 0) {
        type = NGX_DOCKER_HTTP_UPSTREAM;

    } else if (part.len == 6 && ngx_strncmp(part.data, "stream", 6) == 0) {
        type = NGX_DOCKER_STREAM_UPSTREAM;

    } else {
        goto part_error;
    }

    ngx_docker_label_next_part(&label, &part);

    if (part.len != 9 || ngx_strncmp(part.data, "upstreams", 9) != 0) {
        goto part_error;
    }

    ngx_docker_label_next_part(&label, &part);

    u = ngx_docker_get_upstream(dc, &part, type, log);
    if (u == NULL) {
        return NGX_ERROR;
    }

    ngx_docker_label_next_part(&label, &part);

    if (part.len == 4 && ngx_strncmp(part.data, "port", 4) == 0) {
        u->port = ngx_atoi(value.data, value.len);
        if (u->port < 1 || u->port > 65535) {
            goto value_error;
        }

    } else if (part.len == 6 && ngx_strncmp(part.data, "weight", 6) == 0) {
        u->weight = ngx_atoi(value.data, value.len);
        if (u->weight == (ngx_uint_t) NGX_ERROR) {
            goto value_error;
        }

    } else if (part.len == 9 && ngx_strncmp(part.data, "max_conns", 9) == 0) {
        u->max_conns = ngx_atoi(value.data, value.len);
        if (u->max_conns == (ngx_uint_t) NGX_ERROR) {
            goto value_error;
        }

    } else if (part.len == 9 && ngx_strncmp(part.data, "max_fails", 9) == 0) {
        u->max_fails = ngx_atoi(value.data, value.len);
        if (u->max_fails == (ngx_uint_t) NGX_ERROR) {
            goto value_error;
        }

    } else if (part.len == 12
               && ngx_strncmp(part.data, "fail_timeout", 12) == 0)
    {
        u->fail_timeout = ngx_parse_time(&value, 1);
        if (u->fail_timeout == (time_t) NGX_ERROR) {
            goto value_error;
        }

    } else if (part.len == 3 && ngx_strncmp(part.data, "sid", 3) == 0) {

        if (value.len > NGX_DOCKER_UPSTREAM_SID_LEN) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "cannot process label \"%V\" for Docker container "
                          "\"%V\": %s upstream server's sid "
                          "can't be longer than %d bytes",
                          &orig_label, &dc->id, ngx_docker_upstream_type(u),
                          NGX_DOCKER_UPSTREAM_SID_LEN);
            return NGX_ERROR;
        }

        u->sid.data = ngx_pstrdup(dc->pool, &value);
        if (u->sid.data == NULL) {
            return NGX_ERROR;
        }

        u->sid.len = value.len;

    } else if (part.len == 10
               && ngx_strncmp(part.data, "slow_start", 10) == 0)
    {
        u->slow_start = ngx_parse_time(&value, 0);
        if (u->slow_start == (ngx_msec_t) NGX_ERROR) {
            goto value_error;
        }

    } else if (part.len == 6 && ngx_strncmp(part.data, "backup", 6) == 0) {

        if (value.len == 4 && ngx_strncmp(value.data, "true", 4) == 0) {
            u->backup = 1;

        } else if (value.len == 5 && ngx_strncmp(value.data, "false", 5) == 0) {
            u->backup = 0;

        } else {
            goto value_error;
        }

    } else {
        goto part_error;
    }

    ngx_docker_label_next_part(&label, &part);

    if (part.len != 0) {
        goto part_error;
    }

    return NGX_OK;

value_error:

    ngx_log_error(NGX_LOG_ERR, log, 0,
                  "invalid value \"%V\" while processing Docker label \"%V\" "
                  "for container \"%V\"",
                  &value, &orig_label, &dc->id);

    return NGX_ERROR;

part_error:

    ngx_log_error(NGX_LOG_ERR, log, 0,
                  "unknown Docker label part \"%V\" while processing label "
                  "\"%V\" for container \"%V\"",
                  &part, &orig_label, &dc->id);

    return NGX_ERROR;
}


static ngx_int_t
ngx_docker_process_labels(ngx_docker_container_t *dc, ngx_str_t *attr,
    ngx_data_item_t *json, ngx_log_t *log)
{
    ngx_int_t               rc;
    ngx_data_item_t        *item;
    ngx_docker_upstream_t  *u;

    item = ngx_data_object_take(json, attr);
    if (item == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "processing Docker labels failed: "
                      "Docker API response does not contain JSON object \"%V\"",
                      attr);
        return NGX_ERROR;
    }

    for (item = item->data.child; item; item = item->next->next) {

        if (ngx_docker_process_label(item, dc, log) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    rc = NGX_ERROR;

    for (u = dc->upstream; u; u = u->next) {

        if (u->port != (ngx_uint_t) -1) {
            rc = NGX_OK;
            continue;
        }

        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "cannot manage Docker container \"%V\" in "
                      "%s upstream \"%V\" due to missing port label",
                      &dc->id, ngx_docker_upstream_type(u), &u->name);
    }

    return rc;
}


ngx_docker_container_t *
ngx_docker_lookup_container(ngx_rbtree_t *rbtree, ngx_str_t *key)
{
    uint32_t                 hash;
    ngx_int_t                rc;
    ngx_rbtree_node_t       *node, *sentinel;
    ngx_docker_container_t  *dc;

    hash = ngx_crc32_short(key->data, key->len);

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        dc = ngx_docker_node(node);

        rc = ngx_memcmp(key->data, dc->id.data, key->len);

        if (rc == 0) {
            return dc;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


static ngx_int_t
ngx_docker_process_network(ngx_docker_container_t *dc,
    ngx_data_item_t *json, ngx_log_t *log)
{
    size_t                  url_len;
    u_char                 *p, *url;
    ngx_str_t               str;
    ngx_data_item_t        *item;
    ngx_docker_upstream_t  *u;

    ngx_str_set(&str, "NetworkSettings");
    item = ngx_data_object_take(json, &str);
    if (item == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "processing Docker network failed: "
                      "Docker API response does not contain JSON object \"%V\"",
                      &str);
        return NGX_ERROR;
    }

    ngx_str_set(&str, "Networks");
    item = ngx_data_object_take(item, &str);
    if (item == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "processing Docker network failed: "
                      "Docker API response does not contain JSON object \"%V\"",
                      &str);
        return NGX_ERROR;
    }

    item = dc->network.len == 0 ? ngx_docker_get_data_child(item)
                                : ngx_data_object_take(item, &dc->network);

    if (item == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "processing Docker network failed: "
                      "cannot find container network");
        return NGX_ERROR;
    }

    ngx_str_set(&str, "IPAddress");
    if (ngx_docker_get_object_value(item, &str, &dc->ip) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "processing Docker network failed: "
                      "cannot process JSON object \"%V\" from Docker API",
                      &str);
        return NGX_ERROR;
    }

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, log, 0,
                  "Docker container IP: \"%V\"", &dc->ip);

    url_len = dc->ip.len + sizeof("65535");

    for (u = dc->upstream; u; u = u->next) {

        if (u->port == (ngx_uint_t) -1) {
            continue;
        }

        url = ngx_pnalloc(dc->pool, url_len);
        if (url == NULL) {
            return NGX_ERROR;
        }

        p = ngx_snprintf(url, url_len, "%V:%i", &dc->ip, u->port);

        u->url.url.data = url;
        u->url.url.len = p - url;

        if (ngx_parse_url(dc->pool, &u->url) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static void
ngx_docker_destroy_container(ngx_docker_container_t *dc)
{
    if (dc->event.timer_set) {
        ngx_del_timer(&dc->event);
    }

    ngx_destroy_pool(dc->pool);
}


static ngx_docker_container_t *
ngx_docker_create_container(ngx_str_t *id, ngx_log_t *log)
{
    ngx_pool_t              *pool;
    ngx_docker_container_t  *dc;

    pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, log);
    if (pool == NULL) {
        return NULL;
    }

    dc = ngx_pcalloc(pool, sizeof(ngx_docker_container_t));
    if (dc == NULL) {
        goto error;
    }

    dc->id.data = ngx_pstrdup(pool, id);
    if (dc->id.data == NULL) {
        goto error;
    }

    dc->id.len = id->len;

    dc->pool = pool;

    return dc;

error:

    ngx_destroy_pool(pool);

    return NULL;
}


static void
ngx_docker_process_event_die(ngx_str_t *id, ngx_rbtree_t *tree)
{
    ngx_docker_container_t  *dc;

    dc = ngx_docker_lookup_container(tree, id);
    if (dc == NULL) {
        return;
    }

    ngx_docker_upstreams_action_remove(dc);
    ngx_rbtree_delete(tree, &dc->node);
    ngx_docker_destroy_container(dc);
}


static void
ngx_docker_process_event_pause(ngx_str_t *id, ngx_rbtree_t *tree,
    ngx_int_t down)
{
    ngx_docker_container_t  *dc;

    dc = ngx_docker_lookup_container(tree, id);
    if (dc == NULL) {
        return;
    }

    dc->down = down;

    ngx_docker_upstreams_action_pause(dc);
}


static ngx_docker_container_t *
ngx_docker_process_event_start(ngx_str_t *id, ngx_data_item_t *json,
    ngx_rbtree_t *rbtree, ngx_log_t *log)
{
    ngx_int_t                rc;
    ngx_str_t                attr;
    ngx_docker_container_t  *dc;

    dc = ngx_docker_lookup_container(rbtree, id);
    if (dc != NULL) {
        ngx_docker_upstreams_action_remove(dc);
        ngx_rbtree_delete(rbtree, &dc->node);
        ngx_docker_destroy_container(dc);
    }

    dc = ngx_docker_create_container(id, log);
    if (dc == NULL) {
        return NULL;
    }

    ngx_str_set(&attr, "Attributes");
    rc = ngx_docker_process_labels(dc, &attr, json, log);
    if (rc != NGX_OK) {
        ngx_docker_destroy_container(dc);
        return NULL;
    }

    dc->node.key = ngx_crc32_short(id->data, id->len);

    ngx_rbtree_insert(rbtree, &dc->node);

    return dc;
}


void
ngx_docker_process_container(ngx_docker_container_t *dc, ngx_buf_t *b,
    ngx_pool_t *pool, ngx_rbtree_t *rbtree, ngx_log_t *log)
{
    ngx_str_t                target, status;
    ngx_data_item_t         *json, *item;
    ngx_json_parse_error_t   err;

    json = ngx_json_parse(b->start, b->last, pool, &err);
    if (json == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "parsing Docker container \"%V\" JSON "
                      "from Docker API response failed: \"%V\"",
                      &dc->id, &err.desc);
        goto error;
    }

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, log, 0,
                  "Docker container ID: \"%V\"", &dc->id);

    ngx_str_set(&target, "State");
    item = ngx_data_object_take(json, &target);
    if (item == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "processing Docker container \"%V\" failed: "
                      "Docker API response does not contain JSON object \"%V\"",
                      &dc->id, &target);
        goto error;
    }

    ngx_str_set(&target, "Status");
    if (ngx_docker_get_object_value(item, &target, &status) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "processing Docker container \"%V\" failed: "
                      "cannot process JSON object \"%V\" from Docker API",
                      &dc->id, &target);
        goto error;
    }

    if (status.len == 6 && ngx_strncmp(status.data, "paused", 6) == 0) {
        dc->down = 1;
    }

    if (ngx_docker_process_network(dc, json, log) != NGX_OK) {
        goto error;
    }

    if (ngx_docker_upstreams_action_add(dc) != NGX_OK) {
        goto error;
    }

    return;

error:

    ngx_rbtree_delete(rbtree, &dc->node);
    ngx_docker_destroy_container(dc);
}


ngx_int_t
ngx_docker_process_containers(ngx_buf_t *b, ngx_pool_t *pool,
    ngx_rbtree_t *rbtree, ngx_log_t *log)
{
    ngx_int_t                rc;
    ngx_str_t                id, target, state;
    ngx_data_item_t         *json, *item;
    ngx_json_parse_error_t   err;
    ngx_docker_container_t  *dc;

    json = ngx_json_parse(b->start, b->last, pool, &err);
    if (json == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "parsing Docker containers JSON "
                      "from Docker API response failed: \"%V\"",
                      &err.desc);
        return NGX_ERROR;
    }

    for (item = json->data.child; item; item = item->next) {
        ngx_str_set(&target, "Id");
        if (ngx_docker_get_object_value(item, &target, &id) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "processing Docker containers failed: "
                          "cannot process JSON object \"%V\" from Docker API",
                          &target);
            continue;
        }

        ngx_log_debug(NGX_LOG_DEBUG_EVENT, log, 0,
                      "Docker container ID: \"%V\"", &id);

        dc = ngx_docker_create_container(&id, log);
        if (dc == NULL) {
            continue;
        }

        ngx_str_set(&target, "Labels");
        rc = ngx_docker_process_labels(dc, &target, item, log);
        if (rc != NGX_OK) {
            ngx_docker_destroy_container(dc);
            continue;
        }

        ngx_str_set(&target, "State");
        if (ngx_docker_get_object_value(item, &target, &state) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "processing Docker containers failed: "
                          "cannot process JSON object \"%V\" from Docker API",
                          &target);
            continue;
        }

        if (state.len == 6 && ngx_strncmp(state.data, "paused", 6) == 0) {
            dc->down = 1;
        }

        if (ngx_docker_process_network(dc, item, log) != NGX_OK) {
            ngx_docker_destroy_container(dc);
            continue;
        }

        if (ngx_docker_upstreams_action_add(dc) != NGX_OK) {
            ngx_docker_destroy_container(dc);
            continue;
        }

        dc->node.key = ngx_crc32_short(dc->id.data, dc->id.len);

        ngx_rbtree_insert(rbtree, &dc->node);
    }

    return NGX_OK;
}


ngx_docker_container_t *
ngx_docker_process_event(ngx_data_item_t *json, ngx_rbtree_t *rbtree,
    ngx_log_t *log)
{
    ngx_str_t         target, id, str;
    ngx_data_item_t  *item;

    ngx_str_set(&target, "Actor");
    item = ngx_data_object_take(json, &target);
    if (item == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "processing Docker event failed: "
                      "Docker API response does not contain JSON object \"%V\"",
                      &target);
        return NULL;
    }

    ngx_str_set(&target, "ID");
    if (ngx_docker_get_object_value(item, &target, &id) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "processing Docker event failed: "
                      "cannot process JSON object \"%V\" from Docker API",
                      &target);
        return NULL;
    }

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, log, 0,
                  "Docker container ID: \"%V\"", &id);

    ngx_str_set(&target, "status");
    if (ngx_docker_get_object_value(json, &target, &str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "processing Docker event failed: "
                      "cannot process JSON object \"%V\" from Docker API",
                      &target);
        return NULL;
    }

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, log, 0,
                  "Docker container status: \"%V\"", &str);

    if (str.len == 5 && ngx_strncmp(str.data, "start", 5) == 0) {
        return ngx_docker_process_event_start(&id, item, rbtree, log);

    } else if (str.len == 5 && ngx_strncmp(str.data, "pause", 5) == 0) {
        ngx_docker_process_event_pause(&id, rbtree, 1);

    } else if (str.len == 3 && ngx_strncmp(str.data, "die", 3) == 0) {
        ngx_docker_process_event_die(&id, rbtree);

    } else if (str.len == 7 && ngx_strncmp(str.data, "unpause", 7) == 0) {
        ngx_docker_process_event_pause(&id, rbtree, 0);
    }

    return NULL;
}


static ngx_int_t
ngx_docker_parse_api_version(ngx_str_t *vstr, ngx_docker_api_version_t *v)
{
    u_char     *p, *last;
    ngx_int_t   n;

    if (vstr->len < 3) {
        return NGX_ERROR;
    }

    last = vstr->data + vstr->len;

    p = ngx_strlchr(vstr->data, last, '.');
    if (p == NULL) {
        return NGX_ERROR;
    }

    n = ngx_atoi(vstr->data, p - vstr->data);
    if (n == NGX_ERROR || n < 0 || n > 255) {
        return NGX_ERROR;
    }

    v->major = n;

    if (p == last) {
        return NGX_ERROR;
    }

    p++;

    n = ngx_atoi(p, last - p);
    if (n == NGX_ERROR || n < 0 || n > 255) {
        return NGX_ERROR;
    }

    v->minor = n;

    return NGX_OK;
}


ngx_int_t
ngx_docker_get_api_version(ngx_buf_t *b, ngx_pool_t *pool,
    ngx_docker_api_version_t *v, ngx_log_t *log)
{
    ngx_str_t                target, vstr;
    ngx_data_item_t         *json;
    ngx_json_parse_error_t   err;

    json = ngx_json_parse(b->start, b->last, pool, &err);
    if (json == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "parsing Docker API version JSON "
                      "from Docker API response failed: \"%V\"",
                      &err.desc);
        return NGX_ERROR;
    }

    ngx_str_set(&target, "ApiVersion");
    if (ngx_docker_get_object_value(json, &target, &vstr) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "processing Docker API version failed: "
                      "cannot process JSON object \"%V\" from Docker API",
                      &target);
        return NGX_ERROR;
    }

    if (ngx_docker_parse_api_version(&vstr, v) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "processing Docker API version failed: "
                      "unknown Docker API version format \"%V\"",
                      &vstr);
        return NGX_ERROR;
    }

    if (v->major < 1 || (v->major == 1 && v->minor < 24)) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "processing Docker API version failed: "
                      "unsupported Docker API version \"%V\"",
                      &vstr);
        return NGX_ERROR;
    }

    ngx_str_set(&target, "MinAPIVersion");
    if (ngx_docker_get_object_value(json, &target, &vstr) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "processing Docker API version failed: "
                      "cannot process JSON object \"%V\" from Docker API",
                      &target);
        return NGX_ERROR;
    }

    if (ngx_docker_parse_api_version(&vstr, v) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "processing Docker API version failed: "
                      "unknown Docker API minimal version format \"%V\"",
                      &vstr);
        return NGX_ERROR;
    }

    if (v->major < 1 || (v->major == 1 && v->minor < 24)) {
        v->major = 1;
        v->minor = 24;
    }

    return NGX_OK;
}


void
ngx_docker_containers_cleanup(ngx_rbtree_t *rbtree)
{
    ngx_docker_container_t  *dc;

    while (rbtree->root != rbtree->sentinel) {
        dc = ngx_docker_node(ngx_rbtree_min(rbtree->root, rbtree->sentinel));

        ngx_docker_upstreams_action_remove(dc);
        ngx_rbtree_delete(rbtree, &dc->node);
        ngx_docker_destroy_container(dc);
    }
}


void
ngx_docker_init_http_upstream_actions(ngx_docker_upstream_action_pt add,
    ngx_docker_upstream_action_pt remove, ngx_docker_upstream_action_pt pause)
{
    http_upstream_action.add = add;
    http_upstream_action.remove = remove;
    http_upstream_action.pause = pause;
}


void
ngx_docker_init_stream_upstream_actions(ngx_docker_upstream_action_pt add,
    ngx_docker_upstream_action_pt remove, ngx_docker_upstream_action_pt pause)
{
    stream_upstream_action.add = add;
    stream_upstream_action.remove = remove;
    stream_upstream_action.pause = pause;
}
