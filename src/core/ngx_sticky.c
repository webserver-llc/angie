
/*
 * Copyright (C) 2025 Web Server LLC
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_sticky.h>


typedef struct {
    ngx_rbtree_t                  rbtree;
    ngx_rbtree_node_t             sentinel;
    ngx_queue_t                   queue;
} ngx_sticky_sh_t;


typedef struct {
    ngx_sticky_sh_t              *sh;
    ngx_slab_pool_t              *shpool;
    ngx_str_t                    *host;

    ngx_msec_t                    timeout;
    ngx_event_t                   event;
    ngx_uint_t                    refresh;
} ngx_sticky_learn_db_t;


typedef struct {
    ngx_rbtree_node_t             node;

    ngx_queue_t                   queue;
    ngx_msec_t                    last;

    ngx_md5_key_t                 u;

    u_char                        sid_len;
    u_char                        sid[NGX_STICKY_SID_LEN];
} ngx_sticky_sess_node_t;


#if ((NGX_STICKY_SID_LEN) > UCHAR_MAX)
#error "Error: NGX_STICKY_SID_LEN must fit into UCHAR_MAX"
#endif


static ngx_int_t ngx_sticky_learn_init_zone(ngx_shm_zone_t *shm_zone,
    void *data);
static void ngx_sticky_sessions_timeout_handler(ngx_event_t *ev);
static void ngx_sticky_learn_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_msec_t ngx_sticky_expire_sessions(ngx_sticky_learn_db_t *db,
    ngx_uint_t force);
static ngx_sticky_sess_node_t *ngx_sticky_lookup_session(
    ngx_sticky_learn_db_t *db, ngx_sticky_sess_t *sess);


ngx_shm_zone_t *
ngx_sticky_learn_create_zone(ngx_conf_t *cf, ngx_str_t *name, size_t size,
    ngx_str_t *host, ngx_msec_t timeout, ngx_uint_t refresh, ngx_module_t *mod)
{
    ngx_shm_zone_t         *zone;
    ngx_sticky_learn_db_t  *db;

    zone = ngx_shared_memory_add(cf, name, size, mod);
    if (zone == NULL) {
        return NULL;
    }

    if (zone->data) {
        db = zone->data;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "sticky zone \"%V\" is already used in "
                           "upstream \"%V\"", name, db->host);
        return NULL;
    }

    db = ngx_pcalloc(cf->pool, sizeof(ngx_sticky_learn_db_t));
    if (db == NULL) {
        return NULL;
    }

    db->host = host;

    db->timeout = timeout;
    db->refresh = refresh;

    db->event.data = db;
    db->event.log = &cf->cycle->new_log;
    db->event.handler = ngx_sticky_sessions_timeout_handler;
    db->event.cancelable = 1;

    zone->init = ngx_sticky_learn_init_zone;
    zone->data = db;

    return zone;
}


void
ngx_sticky_start(ngx_shm_zone_t *lz)
{
    ngx_sticky_learn_db_t  *db;

    db = lz->data;

    ngx_add_timer(&db->event, 1);
}


ngx_int_t
ngx_sticky_learn_lookup(ngx_shm_zone_t *lz, ngx_sticky_sess_t *sess,
    ngx_str_t *res)
{
    ngx_sticky_learn_db_t   *db;
    ngx_sticky_sess_node_t  *sn;

    db = lz->data;

    ngx_shmtx_lock(&db->shpool->mutex);

    sn = ngx_sticky_lookup_session(db, sess);
    if (sn == NULL) {
        ngx_shmtx_unlock(&db->shpool->mutex);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, db->event.log, 0,
                       "sticky: session \"%V\" not found", &sess->id);

        return NGX_DECLINED;
    }

    res->len = sn->sid_len;
    res->data = sess->sid;

    ngx_memcpy(res->data, sn->sid, sn->sid_len);

    ngx_shmtx_unlock(&db->shpool->mutex);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, db->event.log, 0,
                   "sticky: session \"%V\", SID \"%V\"", &sess->id, res);

    return NGX_OK;
}


void
ngx_sticky_learn_set_session(ngx_shm_zone_t *learn_zone,
    ngx_sticky_sess_t *sess, ngx_str_t *sid, ngx_uint_t create)
{
    ngx_rbtree_node_t       *node;
    ngx_sticky_learn_db_t   *db;
    ngx_sticky_sess_node_t  *sn;

    db = learn_zone->data;

    ngx_shmtx_lock(&db->shpool->mutex);

    sn = ngx_sticky_lookup_session(db, sess);

    if (sn) {
        /* update */

        if (sid->len != sn->sid_len
            || ngx_memcmp(sid->data, sn->sid, sn->sid_len) != 0)
        {

            if (sid->len > NGX_STICKY_SID_LEN) {
                /*
                 * should never happen as sid->len is taken from peer->sid,
                 * and peer->sid is checked for proper length on creation;
                 * the check exists to guard against a callee error
                 */

                ngx_log_error(NGX_LOG_WARN, db->event.log, 0,
                              "sticky: SID too long (%uz), truncating to %d",
                              sid->len, NGX_STICKY_SID_LEN);
                sn->sid_len = NGX_STICKY_SID_LEN;

            } else {
                sn->sid_len = sid->len;
            }

            ngx_memcpy(sn->sid, sid->data, sn->sid_len);

            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, db->event.log, 0,
                           "sticky: session \"%V\" reused for SID \"%V\"",
                           &sess->id, sid);
        }

        if (db->refresh) {
            sn->last = sess->last;
        }

        ngx_queue_remove(&sn->queue);
        ngx_queue_insert_head(&db->sh->queue, &sn->queue);

        ngx_shmtx_unlock(&db->shpool->mutex);
        return;
    }

    /* sn == NULL */

    if (!create) {
        ngx_shmtx_unlock(&db->shpool->mutex);
        return;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, db->event.log, 0,
                   "sticky: creating session \"%V\", SID \"%V\"",
                   &sess->id, sid);

    sn = ngx_slab_alloc_locked(db->shpool, sizeof(ngx_sticky_sess_node_t));
    if (sn == NULL) {
        ngx_log_error(NGX_LOG_WARN, db->event.log, 0,
                      "could not allocate node%s, expiring least "
                      "recently used session", db->shpool->log_ctx);

        (void) ngx_sticky_expire_sessions(db, 1);

        sn = ngx_slab_alloc_locked(db->shpool, sizeof(ngx_sticky_sess_node_t));
        if (sn == NULL) {
            ngx_log_error(NGX_LOG_ALERT, db->event.log, 0,
                          "could not allocate node%s", db->shpool->log_ctx);

            ngx_shmtx_unlock(&db->shpool->mutex);
            return;
        }
    }

    ngx_memcpy(sn->u.md5, sess->key.md5, 16);

    if (sid->len > NGX_STICKY_SID_LEN) {
        /*
         * should never happen as sid->len is taken from peer->sid,
         * and peer->sid is checked for proper length on creation;
         * the check exists to guard against a callee error
         */

        ngx_log_error(NGX_LOG_WARN, db->event.log, 0,
                      "sticky: SID too long (%uz), truncating to %d",
                      sid->len, NGX_STICKY_SID_LEN);
        sn->sid_len = NGX_STICKY_SID_LEN;

    } else {
        sn->sid_len = sid->len;
    }

    ngx_memcpy(sn->sid, sid->data, sn->sid_len);

    node = &sn->node;
    node->key = sn->u.hash;

    ngx_rbtree_insert(&db->sh->rbtree, node);

    sn->last = sess->last;
    ngx_queue_insert_head(&db->sh->queue, &sn->queue);

    ngx_shmtx_unlock(&db->shpool->mutex);

    if (!db->event.timer_set) {
        ngx_add_timer(&db->event, db->timeout);
    }
}


static ngx_int_t
ngx_sticky_learn_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_sticky_learn_db_t  *odb = data;

    size_t                  len;
    ngx_sticky_learn_db_t  *db;

    db = shm_zone->data;

    if (odb) {

        if (db->host->len != odb->host->len
            || ngx_memcmp(db->host->data, odb->host->data, db->host->len) != 0)
        {
            ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                          "sticky learn zone \"%V\" is used in upstream \"%V\" "
                          "while previously it was used in upstream \"%V\"",
                          &shm_zone->shm.name, db->host, odb->host);

            return NGX_ERROR;
        }

        db->sh = odb->sh;
        db->shpool = odb->shpool;

        return NGX_OK;
    }

    db->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        db->sh = db->shpool->data;
        return NGX_OK;
    }

    db->sh = ngx_slab_alloc(db->shpool, sizeof(ngx_sticky_learn_db_t));
    if (db->sh == NULL) {
        return NGX_ERROR;
    }

    db->shpool->data = db->sh;

    ngx_queue_init(&db->sh->queue);

    ngx_rbtree_init(&db->sh->rbtree, &db->sh->sentinel,
                    ngx_sticky_learn_rbtree_insert_value);

    len = sizeof(" in sticky learn zone \"\"") + shm_zone->shm.name.len;

    db->shpool->log_ctx = ngx_slab_alloc(db->shpool, len);
    if (db->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(db->shpool->log_ctx, " in sticky learn zone \"%V\"%Z",
                &shm_zone->shm.name);

    db->shpool->log_nomem = 0;

    return NGX_OK;
}


static void
ngx_sticky_learn_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t       **p;
    ngx_sticky_sess_node_t   *sn, *snt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            sn = (ngx_sticky_sess_node_t *) node;
            snt = (ngx_sticky_sess_node_t *) temp;

            p = (ngx_memcmp(sn->u.md5, snt->u.md5, 16) < 0)
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static void
ngx_sticky_sessions_timeout_handler(ngx_event_t *ev)
{
    ngx_msec_t              wait;
    ngx_sticky_learn_db_t  *db;

    db = ev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0, "sticky: learn timer");

    ngx_shmtx_lock(&db->shpool->mutex);

    wait = ngx_sticky_expire_sessions(db, 0);

    ngx_shmtx_unlock(&db->shpool->mutex);

    if (wait > 0) {
        ngx_add_timer(&db->event, wait);
    }
}


static ngx_msec_t
ngx_sticky_expire_sessions(ngx_sticky_learn_db_t *db, ngx_uint_t force)
{
    ngx_msec_t               now, wait;
    ngx_time_t              *tp;
    ngx_queue_t             *q;
    ngx_rbtree_node_t       *node;
    ngx_sticky_sess_node_t  *sn;

    tp = ngx_timeofday();
    now = tp->sec * 1000 + tp->msec;

    for ( ;; ) {

        if (ngx_queue_empty(&db->sh->queue)) {
            return 0;
        }

        q = ngx_queue_last(&db->sh->queue);

        sn = ngx_queue_data(q, ngx_sticky_sess_node_t, queue);
        wait = sn->last + db->timeout - now;

        if (!force && (ngx_msec_int_t) wait > 0) {
            break;
        }

        force = 0;

        ngx_queue_remove(q);
        node = &sn->node;
        ngx_rbtree_delete(&db->sh->rbtree, node);
        ngx_slab_free_locked(db->shpool, node);
    }

    return wait;
}


static ngx_sticky_sess_node_t *
ngx_sticky_lookup_session(ngx_sticky_learn_db_t *db, ngx_sticky_sess_t *sess)
{
    u_char                  *md5;
    ngx_int_t                rc;
    ngx_uint_t               hash;
    ngx_rbtree_node_t       *node, *sentinel;
    ngx_sticky_sess_node_t  *sn;

    hash = sess->key.hash;
    md5 = sess->key.md5;

    node = db->sh->rbtree.root;
    sentinel = db->sh->rbtree.sentinel;

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

        do {

            sn = (ngx_sticky_sess_node_t *) node;

            rc = ngx_memcmp(md5, sn->u.md5, 16);

            if (rc == 0) {
                return sn;
            }

            node = (rc < 0) ? node->left : node->right;

        } while (node != sentinel && hash == node->key);

        break;
    }

    return NULL;
}
