
/*
 * Copyright (C) 2023-2024 Web Server LLC
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


#define ngx_stream_upstream_tries(p) ((p)->tries                              \
                                      + ((p)->next ? (p)->next->tries : 0))


static ngx_int_t ngx_stream_upstream_init_round_robin_peers(ngx_conf_t *cf,
    ngx_stream_upstream_srv_conf_t *us, ngx_uint_t backup,
    ngx_stream_upstream_rr_peers_t **peersp);
static ngx_inline ngx_int_t ngx_stream_upstream_set_round_robin_peer(
    ngx_pool_t *pool, ngx_stream_upstream_rr_peer_t *peer, ngx_addr_t *addr,
    ngx_stream_upstream_server_t *server);
static ngx_stream_upstream_rr_peer_t *ngx_stream_upstream_get_peer(
    ngx_stream_upstream_rr_peer_data_t *rrp);
static void ngx_stream_upstream_notify_round_robin_peer(
    ngx_peer_connection_t *pc, void *data, ngx_uint_t state);
#if (NGX_API && NGX_STREAM_UPSTREAM_ZONE)
static void ngx_stream_upstream_stat(ngx_peer_connection_t *pc,
    ngx_stream_upstream_rr_peer_t *peer, ngx_uint_t state);
#endif

#if (NGX_STREAM_SSL)

static ngx_int_t ngx_stream_upstream_set_round_robin_peer_session(
    ngx_peer_connection_t *pc, void *data);
static void ngx_stream_upstream_save_round_robin_peer_session(
    ngx_peer_connection_t *pc, void *data);
static ngx_int_t ngx_stream_upstream_empty_set_session(
    ngx_peer_connection_t *pc, void *data);
static void ngx_stream_upstream_empty_save_session(ngx_peer_connection_t *pc,
    void *data);

#endif


ngx_int_t
ngx_stream_upstream_init_round_robin(ngx_conf_t *cf,
    ngx_stream_upstream_srv_conf_t *us)
{
    ngx_url_t                        u;
    ngx_uint_t                       i, n;
    ngx_stream_upstream_rr_peer_t   *peer, **peerp;
    ngx_stream_upstream_rr_peers_t  *peers, *backup;

    us->peer.init = ngx_stream_upstream_init_round_robin_peer;

    if (us->servers) {

#if (NGX_STREAM_UPSTREAM_ZONE)
        ngx_stream_core_srv_conf_t    *cscf;
        ngx_stream_upstream_server_t  *server;

        server = us->servers->elts;

        for (i = 0; i < us->servers->nelts; i++) {

            if (!server[i].host.len) {
                continue;
            }

            if (us->shm_zone == NULL) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "resolving names at run time requires "
                              "shared memory zone configured for "
                              "upstream \"%V\" in %s:%ui",
                              &us->host, us->file_name, us->line);
                return NGX_ERROR;
            }

            if (!(us->flags & NGX_STREAM_UPSTREAM_CONF)) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "resolving names at run time isn't "
                              "supported by load balancing method "
                              "configured for upstream \"%V\" in %s:%ui",
                              &us->host, us->file_name, us->line);
                return NGX_ERROR;
            }

            cscf = ngx_stream_conf_get_module_srv_conf(cf,
                                                       ngx_stream_core_module);

            if (us->resolver == NULL) {
                us->resolver = cscf->resolver;
            }

            if (us->resolver->connections.nelts == 0) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "no resolver configured for resolving names "
                              "at run time in upstream \"%V\" in %s:%ui",
                              &us->host, us->file_name, us->line);
                return NGX_ERROR;
            }

            ngx_conf_merge_msec_value(us->resolver_timeout,
                                      cscf->resolver_timeout, 30000);

            break;
        }
#endif

        if (ngx_stream_upstream_init_round_robin_peers(cf, us, 0, &peers)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (ngx_stream_upstream_init_round_robin_peers(cf, us, 1, &backup)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        peers->next = backup;
        us->peer.data = peers;

        ngx_stream_upstream_set_round_robin_single(us);

        return NGX_OK;
    }


    /* an upstream implicitly defined by proxy_pass, etc. */

    if (us->port == 0) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "no port in upstream \"%V\" in %s:%ui",
                      &us->host, us->file_name, us->line);
        return NGX_ERROR;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.host = us->host;
    u.port = us->port;

    if (ngx_inet_resolve_host(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "%s in upstream \"%V\" in %s:%ui",
                          u.err, &us->host, us->file_name, us->line);
        }

        return NGX_ERROR;
    }

    n = u.naddrs;

    peers = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_rr_peers_t));
    if (peers == NULL) {
        return NGX_ERROR;
    }

    peer = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_rr_peer_t) * n);
    if (peer == NULL) {
        return NGX_ERROR;
    }

    peers->single = (n == 1);
    peers->number = n;
    peers->total_weight = n;
    peers->tries = n;
    peers->name = &us->host;

    peerp = &peers->peer;

    for (i = 0; i < u.naddrs; i++) {
        if (ngx_stream_upstream_set_round_robin_peer(cf->pool, &peer[i],
                                                     &u.addrs[i], NULL)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        *peerp = &peer[i];
        peerp = &peer[i].next;
    }

    us->peer.data = peers;

    /* implicitly defined upstream has no backup servers */

    return NGX_OK;
}


static ngx_int_t
ngx_stream_upstream_init_round_robin_peers(ngx_conf_t *cf,
    ngx_stream_upstream_srv_conf_t *us, ngx_uint_t backup,
    ngx_stream_upstream_rr_peers_t **peersp)
{
    ngx_uint_t                       i, j, n, r, w, t;
    ngx_stream_upstream_server_t    *server;
    ngx_stream_upstream_rr_peer_t   *peer, **peerp;
    ngx_stream_upstream_rr_peers_t  *peers;
#if (NGX_STREAM_UPSTREAM_ZONE)
    ngx_stream_upstream_rr_peer_t  **rpeerp;
#endif

    server = us->servers->elts;

    n = 0;
    r = 0;
    w = 0;
    t = 0;

    for (i = 0; i < us->servers->nelts; i++) {

        if (server[i].backup != backup) {
            continue;
        }

#if (NGX_STREAM_UPSTREAM_ZONE)
        if (server[i].host.len) {
            r++;

        } else
#endif
        {
            n += server[i].naddrs;
            w += server[i].naddrs * server[i].weight;

            if (!server[i].down) {
                t += server[i].naddrs;
            }
        }
    }

    if (n == 0
#if (NGX_STREAM_UPSTREAM_ZONE)
        && us->shm_zone == NULL
#endif
    ) {
        if (backup) {
            *peersp = NULL;
            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "no servers in upstream \"%V\" in %s:%ui",
                      &us->host, us->file_name, us->line);

        return NGX_ERROR;
    }

    peers = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_rr_peers_t));
    if (peers == NULL) {
        return NGX_ERROR;
    }

    peer = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_rr_peer_t)
                                 * (n + r));
    if (peer == NULL) {
        return NGX_ERROR;
    }

    peers->number = n;
    peers->weighted = (w != n);
    peers->total_weight = w;
    peers->tries = t;
    peers->name = &us->host;

    n = 0;
    peerp = &peers->peer;
#if (NGX_STREAM_UPSTREAM_ZONE)
    rpeerp = &peers->resolve;
#endif

    for (i = 0; i < us->servers->nelts; i++) {
        if (server[i].backup != backup) {
            continue;
        }

#if (NGX_STREAM_UPSTREAM_ZONE)
        if (server[i].host.len) {

            peer[n].host = ngx_pcalloc(cf->pool,
                                       sizeof(ngx_stream_upstream_host_t));
            if (peer[n].host == NULL) {
                return NGX_ERROR;
            }

            peer[n].host->name = server[i].host;
            peer[n].host->service = server[i].service;

            if (ngx_stream_upstream_set_round_robin_peer(cf->pool, &peer[n],
                                                       &server[i].addrs[0],
                                                       &server[i])
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            *rpeerp = &peer[n];
            rpeerp = &peer[n].next;
            n++;

            continue;
        }
#endif

        for (j = 0; j < server[i].naddrs; j++) {

            if (ngx_stream_upstream_set_round_robin_peer(cf->pool, &peer[n],
                                                         &server[i].addrs[j],
                                                         &server[i])
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            *peerp = &peer[n];
            peerp = &peer[n].next;
            n++;
        }
    }

    *peersp = peers;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_upstream_set_round_robin_peer(ngx_pool_t *pool,
    ngx_stream_upstream_rr_peer_t *peer, ngx_addr_t *addr,
    ngx_stream_upstream_server_t *server)
{
    peer->sockaddr = addr->sockaddr;
    peer->socklen = addr->socklen;
    peer->name = addr->name;

    if (server) {

        peer->weight = server->weight;
        peer->effective_weight = server->weight;

        peer->max_conns = server->max_conns;
        peer->max_fails = server->max_fails;
        peer->fail_timeout = server->fail_timeout;
        peer->down = server->down;
        peer->slow_start = server->slow_start;

        peer->server = server->name;

    } else {
        peer->weight = 1;
        peer->effective_weight = 1;

        peer->max_fails = 1;
        peer->fail_timeout = 10;
    }

    return NGX_OK;
}


void
ngx_stream_upstream_set_round_robin_single(ngx_stream_upstream_srv_conf_t *us)
{
    ngx_stream_upstream_rr_peers_t  *peers;

    peers = us->peer.data;

    if (peers->number == 1
        && (peers->next == NULL || peers->next->number == 0))
    {
        peers->single = 1;

    } else {
        peers->single = 0;
    }
}


ngx_int_t
ngx_stream_upstream_init_round_robin_peer(ngx_stream_session_t *s,
    ngx_stream_upstream_srv_conf_t *us)
{
    ngx_uint_t                           n;
    ngx_stream_upstream_rr_peer_data_t  *rrp;

    rrp = s->upstream->peer.data;

    if (rrp == NULL) {
        rrp = ngx_palloc(s->connection->pool,
                         sizeof(ngx_stream_upstream_rr_peer_data_t));
        if (rrp == NULL) {
            return NGX_ERROR;
        }

        s->upstream->peer.data = rrp;
    }

    rrp->peers = us->peer.data;
    rrp->current = NULL;

    ngx_stream_upstream_rr_peers_rlock(rrp->peers);

#if (NGX_STREAM_UPSTREAM_ZONE)
    rrp->generation = rrp->peers->generation ? *rrp->peers->generation : 0;
#endif

    n = rrp->peers->number;

    if (rrp->peers->next && rrp->peers->next->number > n) {
        n = rrp->peers->next->number;
    }

    ngx_stream_upstream_rr_peers_unlock(rrp->peers);

    if (n <= 8 * sizeof(uintptr_t)) {
        rrp->tried = &rrp->data;
        rrp->data = 0;

    } else {
        n = (n + (8 * sizeof(uintptr_t) - 1)) / (8 * sizeof(uintptr_t));

        rrp->tried = ngx_pcalloc(s->connection->pool, n * sizeof(uintptr_t));
        if (rrp->tried == NULL) {
            return NGX_ERROR;
        }
    }

    s->upstream->peer.ctx = s;
    s->upstream->peer.get = ngx_stream_upstream_get_round_robin_peer;
    s->upstream->peer.free = ngx_stream_upstream_free_round_robin_peer;
    s->upstream->peer.notify = ngx_stream_upstream_notify_round_robin_peer;
    s->upstream->peer.tries = ngx_stream_upstream_tries(rrp->peers);
#if (NGX_STREAM_SSL)
    s->upstream->peer.set_session =
                             ngx_stream_upstream_set_round_robin_peer_session;
    s->upstream->peer.save_session =
                             ngx_stream_upstream_save_round_robin_peer_session;
#endif

    return NGX_OK;
}


ngx_int_t
ngx_stream_upstream_create_round_robin_peer(ngx_stream_session_t *s,
    ngx_stream_upstream_resolved_t *ur)
{
    ngx_uint_t                           i, n;
    ngx_addr_t                           addr;
    ngx_stream_upstream_rr_peer_t       *peer, **peerp;
    ngx_stream_upstream_rr_peers_t      *peers;
    ngx_stream_upstream_rr_peer_data_t  *rrp;

    rrp = s->upstream->peer.data;

    if (rrp == NULL) {
        rrp = ngx_palloc(s->connection->pool,
                         sizeof(ngx_stream_upstream_rr_peer_data_t));
        if (rrp == NULL) {
            return NGX_ERROR;
        }

        s->upstream->peer.data = rrp;
    }

    peers = ngx_pcalloc(s->connection->pool,
                        sizeof(ngx_stream_upstream_rr_peers_t));
    if (peers == NULL) {
        return NGX_ERROR;
    }

    peer = ngx_pcalloc(s->connection->pool,
                       sizeof(ngx_stream_upstream_rr_peer_t) * ur->naddrs);
    if (peer == NULL) {
        return NGX_ERROR;
    }

    peers->single = (ur->naddrs == 1);
    peers->number = ur->naddrs;
    peers->tries = ur->naddrs;
    peers->name = &ur->host;

    if (ur->sockaddr) {
        addr.sockaddr = ur->sockaddr;
        addr.socklen = ur->socklen;
        addr.name = ur->name;

        if (ngx_stream_upstream_set_round_robin_peer(s->connection->pool,
                                                     &peer[0], &addr, NULL)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        peers->peer = peer;

    } else {
        peerp = &peers->peer;

        for (i = 0; i < ur->naddrs; i++) {

            addr.socklen = ur->addrs[i].socklen;

            addr.sockaddr = ngx_palloc(s->connection->pool, addr.socklen);
            if (addr.sockaddr == NULL) {
                return NGX_ERROR;
            }

            ngx_memcpy(addr.sockaddr, ur->addrs[i].sockaddr, addr.socklen);
            ngx_inet_set_port(addr.sockaddr, ur->port);

            addr.name.data = ngx_pnalloc(s->connection->pool,
                                         NGX_SOCKADDR_STRLEN);
            if (addr.name.data == NULL) {
                return NGX_ERROR;
            }

            addr.name.len = ngx_sock_ntop(addr.sockaddr, addr.socklen,
                                          addr.name.data,
                                          NGX_SOCKADDR_STRLEN, 1);

            if (ngx_stream_upstream_set_round_robin_peer(s->connection->pool,
                                                         &peer[i], &addr, NULL)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            *peerp = &peer[i];
            peerp = &peer[i].next;
        }
    }

    rrp->peers = peers;
    rrp->current = NULL;
    rrp->generation = 0;

    if (rrp->peers->number <= 8 * sizeof(uintptr_t)) {
        rrp->tried = &rrp->data;
        rrp->data = 0;

    } else {
        n = (rrp->peers->number + (8 * sizeof(uintptr_t) - 1))
                / (8 * sizeof(uintptr_t));

        rrp->tried = ngx_pcalloc(s->connection->pool, n * sizeof(uintptr_t));
        if (rrp->tried == NULL) {
            return NGX_ERROR;
        }
    }

    s->upstream->peer.ctx = s;
    s->upstream->peer.get = ngx_stream_upstream_get_round_robin_peer;
    s->upstream->peer.free = ngx_stream_upstream_free_round_robin_peer;
    s->upstream->peer.tries = ngx_stream_upstream_tries(rrp->peers);
#if (NGX_STREAM_SSL)
    s->upstream->peer.set_session = ngx_stream_upstream_empty_set_session;
    s->upstream->peer.save_session = ngx_stream_upstream_empty_save_session;
#endif

    return NGX_OK;
}


ngx_int_t
ngx_stream_upstream_get_round_robin_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_stream_upstream_rr_peer_data_t *rrp = data;

    ngx_int_t                        rc;
    ngx_uint_t                       i, n;
    ngx_stream_upstream_rr_peer_t   *peer;
    ngx_stream_upstream_rr_peers_t  *peers;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                   "get rr peer, try: %ui", pc->tries);

    pc->connection = NULL;

    peers = rrp->peers;
    ngx_stream_upstream_rr_peers_wlock(peers);

#if (NGX_STREAM_UPSTREAM_ZONE)
    if (peers->generation && rrp->generation != *peers->generation) {
        goto busy;
    }
#endif

    if (peers->single) {
        peer = peers->peer;

        if (peer->down) {
            goto failed;
        }

        if (peer->max_conns && peer->conns >= peer->max_conns) {
            goto failed;
        }

        peer->checked = ngx_time();

        rrp->current = peer;
        ngx_stream_upstream_rr_peer_ref(peers, peer);

    } else {

        /* there are several peers */

        peer = ngx_stream_upstream_get_peer(rrp);

        if (peer == NULL) {
            goto failed;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "get rr peer, current: %p %i",
                       peer, peer->current_weight);
    }

    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;

    peer->conns++;

#if (NGX_API && NGX_STREAM_UPSTREAM_ZONE)
    peer->stats.conns++;
    peer->stats.selected = ngx_time();
#endif

    ngx_stream_upstream_rr_peers_unlock(peers);

    return NGX_OK;

failed:

    if (peers->next) {

        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0, "backup servers");

        rrp->peers = peers->next;

        n = (rrp->peers->number + (8 * sizeof(uintptr_t) - 1))
                / (8 * sizeof(uintptr_t));

        for (i = 0; i < n; i++) {
            rrp->tried[i] = 0;
        }

        ngx_stream_upstream_rr_peers_unlock(peers);

        rc = ngx_stream_upstream_get_round_robin_peer(pc, rrp);

        if (rc != NGX_BUSY) {
            return rc;
        }

        ngx_stream_upstream_rr_peers_wlock(peers);

#if (NGX_STREAM_UPSTREAM_ZONE)
        if (peers->generation && rrp->generation != *peers->generation) {
            goto busy;
        }
#endif
    }

#if (NGX_STREAM_UPSTREAM_ZONE)
busy:
#endif

    ngx_stream_upstream_rr_peers_unlock(peers);

    pc->name = peers->name;

    return NGX_BUSY;
}


static ngx_stream_upstream_rr_peer_t *
ngx_stream_upstream_get_peer(ngx_stream_upstream_rr_peer_data_t *rrp)
{
    time_t                          now;
    uintptr_t                       m;
    ngx_int_t                       total, effective_weight;
    ngx_uint_t                      i, n, p;
    ngx_stream_upstream_rr_peer_t  *peer, *best;

    now = ngx_time();

    best = NULL;
    total = 0;

#if (NGX_SUPPRESS_WARN)
    p = 0;
#endif

    for (peer = rrp->peers->peer, i = 0;
         peer;
         peer = peer->next, i++)
    {
        n = i / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

        if (rrp->tried[n] & m) {
            continue;
        }

        if (peer->down) {
            continue;
        }

        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            continue;
        }

        if (peer->max_conns && peer->conns >= peer->max_conns) {
            continue;
        }

        effective_weight = peer->effective_weight
                           * ngx_stream_upstream_throttle_peer(peer);

        peer->current_weight += effective_weight;
        total += effective_weight;

        if (peer->effective_weight < peer->weight && !peer->slow_start) {
            peer->effective_weight++;
        }

        if (best == NULL || peer->current_weight > best->current_weight) {
            best = peer;
            p = i;
        }
    }

    if (best == NULL) {
        return NULL;
    }

    rrp->current = best;
    ngx_stream_upstream_rr_peer_ref(rrp->peers, best);

    n = p / (8 * sizeof(uintptr_t));
    m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

    rrp->tried[n] |= m;

    best->current_weight -= total;

    if (now - best->checked > best->fail_timeout) {
        best->checked = now;
    }

    return best;
}


void
ngx_stream_upstream_free_round_robin_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_stream_upstream_rr_peer_data_t  *rrp = data;

    time_t                          now;
    ngx_stream_upstream_rr_peer_t  *peer;

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                   "free rr peer %ui %ui", pc->tries, state);

    peer = rrp->current;

    ngx_stream_upstream_rr_peers_rlock(rrp->peers);
    ngx_stream_upstream_rr_peer_lock(rrp->peers, peer);

    if (state & NGX_PEER_FAILED) {
        now = ngx_time();

        peer->fails++;
        peer->accessed = now;
        peer->checked = now;

        if (peer->max_fails) {

            if (!peer->slow_start) {
                peer->effective_weight -= peer->weight / peer->max_fails;

            } else if (peer->fails < peer->max_fails) {

                if (ngx_current_msec - peer->slow_time >= peer->slow_start) {
                    peer->slow_time = ngx_current_msec - peer->slow_start;
                }

                peer->slow_time += peer->slow_start / peer->max_fails;

            } else {
                peer->slow_time = 0;
            }

            if (peer->fails >= peer->max_fails && !rrp->peers->single) {
                ngx_log_error(NGX_LOG_WARN, pc->log, 0,
                              "upstream server temporarily disabled");
            }
        }

        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "free rr peer failed: %p %i",
                       peer, peer->effective_weight);

        if (peer->effective_weight < 0) {
            peer->effective_weight = 0;
        }

    } else {

        /* mark peer live if check passed */

        if (peer->accessed < peer->checked) {

            if (peer->slow_start
                && peer->max_fails && peer->fails >= peer->max_fails)
            {
                peer->slow_time = ngx_current_msec;
            }

            peer->fails = 0;
        }
    }

    peer->conns--;

#if (NGX_API && NGX_STREAM_UPSTREAM_ZONE)
    ngx_stream_upstream_stat(pc, peer, state);
#endif

    if (ngx_stream_upstream_rr_peer_unref(rrp->peers, peer) == NGX_OK) {
        ngx_stream_upstream_rr_peer_unlock(rrp->peers, peer);
    }

    ngx_stream_upstream_rr_peers_unlock(rrp->peers);

    if (pc->tries) {
        pc->tries--;
    }
}


static void
ngx_stream_upstream_notify_round_robin_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t type)
{
    ngx_stream_upstream_rr_peer_data_t  *rrp = data;

    ngx_stream_upstream_rr_peer_t  *peer;

    peer = rrp->current;

    if (type == NGX_STREAM_UPSTREAM_NOTIFY_CONNECT
        && pc->connection->type == SOCK_STREAM)
    {
        ngx_stream_upstream_rr_peers_rlock(rrp->peers);
        ngx_stream_upstream_rr_peer_lock(rrp->peers, peer);

        if (peer->accessed < peer->checked) {

            if (peer->slow_start
                && peer->max_fails && peer->fails >= peer->max_fails)
            {
                peer->slow_time = ngx_current_msec;
            }

            peer->fails = 0;
        }

        ngx_stream_upstream_rr_peer_unlock(rrp->peers, peer);
        ngx_stream_upstream_rr_peers_unlock(rrp->peers);
    }
}


#if (NGX_API && NGX_STREAM_UPSTREAM_ZONE)

static void
ngx_stream_upstream_stat(ngx_peer_connection_t *pc,
    ngx_stream_upstream_rr_peer_t *peer, ngx_uint_t state)
{
    ngx_time_t             *tp;
    ngx_connection_t       *c;
    ngx_stream_session_t   *s;
    ngx_stream_upstream_t  *u;

    s = pc->ctx;
    u = s->upstream;

    if (u->upstream == NULL || u->upstream->shm_zone == NULL) {
        return;
    }

    if (state & NGX_PEER_FAILED) {
        peer->stats.fails++;

        if (peer->max_fails && peer->fails == peer->max_fails) {
            peer->stats.unavailable++;

            tp = ngx_timeofday();
            peer->stats.downstart = (uint64_t) tp->sec * 1000 + tp->msec;
        }

    } else if (peer->accessed < peer->checked) {

        if (peer->stats.downstart != 0) {

            tp = ngx_timeofday();
            peer->stats.downtime += (uint64_t) tp->sec * 1000
                                    + tp->msec
                                    - peer->stats.downstart;
            peer->stats.downstart = 0;
        }
    }

    c = pc->connection;

    if (c == NULL) {
        /*
         * immediate fail of establishing connection
         * in ngx_event_connect_peer()
         */
        return;
    }

    peer->stats.sent += c->sent;
    peer->stats.received += u->received;
}

#endif


#if (NGX_STREAM_SSL)

static ngx_int_t
ngx_stream_upstream_set_round_robin_peer_session(ngx_peer_connection_t *pc,
    void *data)
{
    ngx_stream_upstream_rr_peer_data_t  *rrp = data;

    ngx_int_t                        rc;
    ngx_ssl_session_t               *ssl_session;
    ngx_stream_upstream_rr_peer_t   *peer;
#if (NGX_STREAM_UPSTREAM_ZONE)
    int                              len;
    const u_char                    *p;
    ngx_stream_upstream_rr_peers_t  *peers;
    u_char                           buf[NGX_SSL_MAX_SESSION_SIZE];
#endif

    peer = rrp->current;

#if (NGX_STREAM_UPSTREAM_ZONE)
    peers = rrp->peers;

    if (peers->shpool) {
        ngx_stream_upstream_rr_peers_rlock(peers);
        ngx_stream_upstream_rr_peer_lock(peers, peer);

        if (peer->ssl_session == NULL) {
            ngx_stream_upstream_rr_peer_unlock(peers, peer);
            ngx_stream_upstream_rr_peers_unlock(peers);
            return NGX_OK;
        }

        len = peer->ssl_session_len;

        ngx_memcpy(buf, peer->ssl_session, len);

        ngx_stream_upstream_rr_peer_unlock(peers, peer);
        ngx_stream_upstream_rr_peers_unlock(peers);

        p = buf;
        ssl_session = d2i_SSL_SESSION(NULL, &p, len);

        rc = ngx_ssl_set_session(pc->connection, ssl_session);

        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "set session: %p", ssl_session);

        ngx_ssl_free_session(ssl_session);

        return rc;
    }
#endif

    ssl_session = peer->ssl_session;

    rc = ngx_ssl_set_session(pc->connection, ssl_session);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                   "set session: %p", ssl_session);

    return rc;
}


static void
ngx_stream_upstream_save_round_robin_peer_session(ngx_peer_connection_t *pc,
    void *data)
{
    ngx_stream_upstream_rr_peer_data_t  *rrp = data;

    ngx_ssl_session_t               *old_ssl_session, *ssl_session;
    ngx_stream_upstream_rr_peer_t   *peer;
#if (NGX_STREAM_UPSTREAM_ZONE)
    int                              len;
    u_char                          *p;
    ngx_stream_upstream_rr_peers_t  *peers;
    u_char                           buf[NGX_SSL_MAX_SESSION_SIZE];
#endif

#if (NGX_STREAM_UPSTREAM_ZONE)
    peers = rrp->peers;

    if (peers->shpool) {

        ssl_session = ngx_ssl_get0_session(pc->connection);

        if (ssl_session == NULL) {
            return;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "save session: %p", ssl_session);

        len = i2d_SSL_SESSION(ssl_session, NULL);

        /* do not cache too big session */

        if (len > NGX_SSL_MAX_SESSION_SIZE) {
            return;
        }

        p = buf;
        (void) i2d_SSL_SESSION(ssl_session, &p);

        peer = rrp->current;

        ngx_stream_upstream_rr_peers_rlock(peers);
        ngx_stream_upstream_rr_peer_lock(peers, peer);

        if (len > peer->ssl_session_len) {
            ngx_shmtx_lock(&peers->shpool->mutex);

            if (peer->ssl_session) {
                ngx_slab_free_locked(peers->shpool, peer->ssl_session);
            }

            peer->ssl_session = ngx_slab_alloc_locked(peers->shpool, len);

            ngx_shmtx_unlock(&peers->shpool->mutex);

            if (peer->ssl_session == NULL) {
                peer->ssl_session_len = 0;

                ngx_stream_upstream_rr_peer_unlock(peers, peer);
                ngx_stream_upstream_rr_peers_unlock(peers);
                return;
            }

            peer->ssl_session_len = len;
        }

        ngx_memcpy(peer->ssl_session, buf, len);

        ngx_stream_upstream_rr_peer_unlock(peers, peer);
        ngx_stream_upstream_rr_peers_unlock(peers);

        return;
    }
#endif

    ssl_session = ngx_ssl_get_session(pc->connection);

    if (ssl_session == NULL) {
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                   "save session: %p", ssl_session);

    peer = rrp->current;

    old_ssl_session = peer->ssl_session;
    peer->ssl_session = ssl_session;

    if (old_ssl_session) {

        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "old session: %p", old_ssl_session);

        /* TODO: may block */

        ngx_ssl_free_session(old_ssl_session);
    }
}


static ngx_int_t
ngx_stream_upstream_empty_set_session(ngx_peer_connection_t *pc, void *data)
{
    return NGX_OK;
}


static void
ngx_stream_upstream_empty_save_session(ngx_peer_connection_t *pc, void *data)
{
    return;
}

#endif
