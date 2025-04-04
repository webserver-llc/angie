
/*
 * Copyright (C) 2022 Web Server LLC
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_SLAB_PAGE_MASK   3
#define NGX_SLAB_PAGE        0
#define NGX_SLAB_BIG         1
#define NGX_SLAB_EXACT       2
#define NGX_SLAB_SMALL       3

#if (NGX_PTR_SIZE == 4)

#define NGX_SLAB_PAGE_FREE   0
#define NGX_SLAB_PAGE_BUSY   0xffffffff
#define NGX_SLAB_PAGE_START  0x80000000

#define NGX_SLAB_SHIFT_MASK  0x0000000f
#define NGX_SLAB_MAP_MASK    0xffff0000
#define NGX_SLAB_MAP_SHIFT   16

#define NGX_SLAB_BUSY        0xffffffff

#else /* (NGX_PTR_SIZE == 8) */

#define NGX_SLAB_PAGE_FREE   0
#define NGX_SLAB_PAGE_BUSY   0xffffffffffffffff
#define NGX_SLAB_PAGE_START  0x8000000000000000

#define NGX_SLAB_SHIFT_MASK  0x000000000000000f
#define NGX_SLAB_MAP_MASK    0xffffffff00000000
#define NGX_SLAB_MAP_SHIFT   32

#define NGX_SLAB_BUSY        0xffffffffffffffff

#endif


#define ngx_slab_slots(pool)                                                  \
    (ngx_slab_page_t *) ((u_char *) (pool) + sizeof(ngx_slab_pool_t))

#define ngx_slab_page_type(page)   ((page)->prev & NGX_SLAB_PAGE_MASK)

#define ngx_slab_page_prev(page)                                              \
    (ngx_slab_page_t *) ((page)->prev & ~NGX_SLAB_PAGE_MASK)

#define ngx_slab_page_addr(pool, page)                                        \
    ((((page) - (pool)->pages) << ngx_pagesize_shift)                         \
     + (uintptr_t) (pool)->start)


#if (NGX_DEBUG_MALLOC)

#define ngx_slab_junk(p, size)     ngx_memset(p, 0xA5, size)

#elif (NGX_HAVE_DEBUG_MALLOC)

#define ngx_slab_junk(p, size)                                                \
    if (ngx_debug_malloc)          ngx_memset(p, 0xA5, size)

#else

#define ngx_slab_junk(p, size)

#endif


#define NGX_SLAB_SIGN ngx_value(NGX_PTR_SIZE) ":"                             \
                      ngx_value(NGX_SIG_ATOMIC_T_SIZE) ":"                    \
                      NGX_MODULE_SIGNATURE_20 ":"                             \
                      NGX_MODULE_SIGNATURE_21

#define NGX_SLAB_MAGICK_TXT  "angie-shm-001:" NGX_SLAB_SIGN
#define NGX_SLAB_MAGICK      ((u_char *) NGX_SLAB_MAGICK_TXT)
#define NGX_SLAB_MAGICK_LEN  (sizeof(NGX_SLAB_MAGICK_TXT) - 1)
#define NGX_SLAB_HEADER_LEN  (NGX_SLAB_MAGICK_LEN + NGX_INT64_LEN * 4 + 5)

#define addr_to_u64(ptr)     ((uint64_t) (uintptr_t) ptr)
#define u64_to_addr(val)     ((void *) (uintptr_t) val)


static ngx_slab_page_t *ngx_slab_alloc_pages(ngx_slab_pool_t *pool,
    ngx_uint_t pages);
static void ngx_slab_free_pages(ngx_slab_pool_t *pool, ngx_slab_page_t *page,
    ngx_uint_t pages);
static void ngx_slab_error(ngx_slab_pool_t *pool, ngx_uint_t level,
    char *text);

static ngx_int_t ngx_slab_save_pages(ngx_slab_pool_t *pool, off_t header_off,
    ngx_file_t *file);
static ngx_int_t ngx_slab_read_pages(ngx_slab_pool_t *pool, ngx_file_t *file,
    off_t meta_offset);
static ngx_int_t ngx_slab_write_header(ngx_slab_state_header_t *hdr,
    ngx_file_t *file);
static ngx_int_t ngx_slab_header_next_token(ngx_str_t *token, u_char **p,
    u_char *end);
static ngx_int_t ngx_slab_header_next_hexnum(uint64_t *res, u_char **p,
    u_char *end, ngx_log_t *log);


static ngx_uint_t  ngx_slab_max_size;
static ngx_uint_t  ngx_slab_exact_size;
static ngx_uint_t  ngx_slab_exact_shift;


#if (NGX_API)

static ngx_int_t ngx_api_slabs_iter(ngx_api_iter_ctx_t *ictx,
    ngx_api_ctx_t *actx);
static ngx_int_t ngx_api_slab_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);

static ngx_int_t ngx_api_slab_pages_used_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_slab_slots_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_api_slab_slots_iter(ngx_api_iter_ctx_t *ictx,
    ngx_api_ctx_t *actx);
static ngx_int_t ngx_api_slab_slot_free_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);


static ngx_api_entry_t  ngx_api_slab_pages_entries[] = {

    {
        .name      = ngx_string("used"),
        .handler   = ngx_api_slab_pages_used_handler,
    },

    {
        .name      = ngx_string("free"),
        .handler   = ngx_api_struct_int_handler,
        .data.off  = offsetof(ngx_slab_pool_t, pfree)
    },

    ngx_api_null_entry
};


static ngx_api_entry_t  ngx_api_slab_slot_entries[] = {

    {
        .name      = ngx_string("used"),
        .handler   = ngx_api_struct_int_handler,
        .data.off  = offsetof(ngx_slab_stat_t, used)
    },

    {
        .name      = ngx_string("free"),
        .handler   = ngx_api_slab_slot_free_handler,
    },

    {
        .name      = ngx_string("reqs"),
        .handler   = ngx_api_struct_int_handler,
        .data.off  = offsetof(ngx_slab_stat_t, reqs)
    },

    {
        .name      = ngx_string("fails"),
        .handler   = ngx_api_struct_int_handler,
        .data.off  = offsetof(ngx_slab_stat_t, fails)
    },

    ngx_api_null_entry
};


static ngx_api_entry_t  ngx_api_slab_entries[] = {

    {
        .name      = ngx_string("pages"),
        .handler   = ngx_api_object_handler,
        .data.ents = ngx_api_slab_pages_entries
    },

    {
        .name      = ngx_string("slots"),
        .handler   = ngx_api_slab_slots_handler,
    },

    ngx_api_null_entry
};

#endif


void
ngx_slab_sizes_init(void)
{
    ngx_uint_t  n;

    ngx_slab_max_size = ngx_pagesize / 2;
    ngx_slab_exact_size = ngx_pagesize / (8 * sizeof(uintptr_t));
    for (n = ngx_slab_exact_size; n >>= 1; ngx_slab_exact_shift++) {
        /* void */
    }
}


void
ngx_slab_init(ngx_slab_pool_t *pool)
{
    u_char           *p;
    size_t            size;
    ngx_int_t         m;
    ngx_uint_t        i, n, pages;
    ngx_slab_page_t  *slots, *page;

    pool->min_size = (size_t) 1 << pool->min_shift;

    slots = ngx_slab_slots(pool);

    p = (u_char *) slots;
    size = pool->end - p;

    ngx_slab_junk(p, size);

    n = ngx_pagesize_shift - pool->min_shift;

    for (i = 0; i < n; i++) {
        /* only "next" is used in list head */
        slots[i].slab = 0;
        slots[i].next = &slots[i];
        slots[i].prev = 0;
    }

    p += n * sizeof(ngx_slab_page_t);

    pool->stats = (ngx_slab_stat_t *) p;
    ngx_memzero(pool->stats, n * sizeof(ngx_slab_stat_t));

    p += n * sizeof(ngx_slab_stat_t);

    size -= n * (sizeof(ngx_slab_page_t) + sizeof(ngx_slab_stat_t));

    pages = (ngx_uint_t) (size / (ngx_pagesize + sizeof(ngx_slab_page_t)));

    pool->pages = (ngx_slab_page_t *) p;
    ngx_memzero(pool->pages, pages * sizeof(ngx_slab_page_t));

    page = pool->pages;

    /* only "next" is used in list head */
    pool->free.slab = 0;
    pool->free.next = page;
    pool->free.prev = 0;

    page->slab = pages;
    page->next = &pool->free;
    page->prev = (uintptr_t) &pool->free;

    pool->start = ngx_align_ptr(p + pages * sizeof(ngx_slab_page_t),
                                ngx_pagesize);

    m = pages - (pool->end - pool->start) / ngx_pagesize;
    if (m > 0) {
        pages -= m;
        page->slab = pages;
    }

    pool->last = pool->pages + pages;
    pool->pfree = pages;

    pool->log_nomem = 1;
    pool->log_ctx = &pool->zero;
    pool->zero = '\0';
}


void *
ngx_slab_alloc(ngx_slab_pool_t *pool, size_t size)
{
    void  *p;

    ngx_shmtx_lock(&pool->mutex);

    p = ngx_slab_alloc_locked(pool, size);

    ngx_shmtx_unlock(&pool->mutex);

    return p;
}


void *
ngx_slab_alloc_locked(ngx_slab_pool_t *pool, size_t size)
{
    size_t            s;
    uintptr_t         p, m, mask, *bitmap;
    ngx_uint_t        i, n, slot, shift, map;
    ngx_slab_page_t  *page, *prev, *slots;

    if (size > ngx_slab_max_size) {

        ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                       "slab alloc: %uz", size);

        page = ngx_slab_alloc_pages(pool, (size >> ngx_pagesize_shift)
                                          + ((size % ngx_pagesize) ? 1 : 0));
        if (page) {
            p = ngx_slab_page_addr(pool, page);

        } else {
            p = 0;
        }

        goto done;
    }

    if (size > pool->min_size) {
        shift = 1;
        for (s = size - 1; s >>= 1; shift++) { /* void */ }
        slot = shift - pool->min_shift;

    } else {
        shift = pool->min_shift;
        slot = 0;
    }

    pool->stats[slot].reqs++;

    ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                   "slab alloc: %uz slot: %ui", size, slot);

    slots = ngx_slab_slots(pool);
    page = slots[slot].next;

    if (page->next != page) {

        if (shift < ngx_slab_exact_shift) {

            bitmap = (uintptr_t *) ngx_slab_page_addr(pool, page);

            map = (ngx_pagesize >> shift) / (8 * sizeof(uintptr_t));

            for (n = 0; n < map; n++) {

                if (bitmap[n] != NGX_SLAB_BUSY) {

                    for (m = 1, i = 0; m; m <<= 1, i++) {
                        if (bitmap[n] & m) {
                            continue;
                        }

                        bitmap[n] |= m;

                        i = (n * 8 * sizeof(uintptr_t) + i) << shift;

                        p = (uintptr_t) bitmap + i;

                        pool->stats[slot].used++;

                        if (bitmap[n] == NGX_SLAB_BUSY) {
                            for (n = n + 1; n < map; n++) {
                                if (bitmap[n] != NGX_SLAB_BUSY) {
                                    goto done;
                                }
                            }

                            prev = ngx_slab_page_prev(page);
                            prev->next = page->next;
                            page->next->prev = page->prev;

                            page->next = NULL;
                            page->prev = NGX_SLAB_SMALL;
                        }

                        goto done;
                    }
                }
            }

        } else if (shift == ngx_slab_exact_shift) {

            for (m = 1, i = 0; m; m <<= 1, i++) {
                if (page->slab & m) {
                    continue;
                }

                page->slab |= m;

                if (page->slab == NGX_SLAB_BUSY) {
                    prev = ngx_slab_page_prev(page);
                    prev->next = page->next;
                    page->next->prev = page->prev;

                    page->next = NULL;
                    page->prev = NGX_SLAB_EXACT;
                }

                p = ngx_slab_page_addr(pool, page) + (i << shift);

                pool->stats[slot].used++;

                goto done;
            }

        } else { /* shift > ngx_slab_exact_shift */

            mask = ((uintptr_t) 1 << (ngx_pagesize >> shift)) - 1;
            mask <<= NGX_SLAB_MAP_SHIFT;

            for (m = (uintptr_t) 1 << NGX_SLAB_MAP_SHIFT, i = 0;
                 m & mask;
                 m <<= 1, i++)
            {
                if (page->slab & m) {
                    continue;
                }

                page->slab |= m;

                if ((page->slab & NGX_SLAB_MAP_MASK) == mask) {
                    prev = ngx_slab_page_prev(page);
                    prev->next = page->next;
                    page->next->prev = page->prev;

                    page->next = NULL;
                    page->prev = NGX_SLAB_BIG;
                }

                p = ngx_slab_page_addr(pool, page) + (i << shift);

                pool->stats[slot].used++;

                goto done;
            }
        }

        ngx_slab_error(pool, NGX_LOG_ALERT, "ngx_slab_alloc(): page is busy");
        ngx_debug_point();
    }

    page = ngx_slab_alloc_pages(pool, 1);

    if (page) {
        if (shift < ngx_slab_exact_shift) {
            bitmap = (uintptr_t *) ngx_slab_page_addr(pool, page);

            n = (ngx_pagesize >> shift) / ((1 << shift) * 8);

            if (n == 0) {
                n = 1;
            }

            /* "n" elements for bitmap, plus one requested */

            for (i = 0; i < (n + 1) / (8 * sizeof(uintptr_t)); i++) {
                bitmap[i] = NGX_SLAB_BUSY;
            }

            m = ((uintptr_t) 1 << ((n + 1) % (8 * sizeof(uintptr_t)))) - 1;
            bitmap[i] = m;

            map = (ngx_pagesize >> shift) / (8 * sizeof(uintptr_t));

            for (i = i + 1; i < map; i++) {
                bitmap[i] = 0;
            }

            page->slab = shift;
            page->next = &slots[slot];
            page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_SMALL;

            slots[slot].next = page;

            pool->stats[slot].total += (ngx_pagesize >> shift) - n;

            p = ngx_slab_page_addr(pool, page) + (n << shift);

            pool->stats[slot].used++;

            goto done;

        } else if (shift == ngx_slab_exact_shift) {

            page->slab = 1;
            page->next = &slots[slot];
            page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_EXACT;

            slots[slot].next = page;

            pool->stats[slot].total += 8 * sizeof(uintptr_t);

            p = ngx_slab_page_addr(pool, page);

            pool->stats[slot].used++;

            goto done;

        } else { /* shift > ngx_slab_exact_shift */

            page->slab = ((uintptr_t) 1 << NGX_SLAB_MAP_SHIFT) | shift;
            page->next = &slots[slot];
            page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_BIG;

            slots[slot].next = page;

            pool->stats[slot].total += ngx_pagesize >> shift;

            p = ngx_slab_page_addr(pool, page);

            pool->stats[slot].used++;

            goto done;
        }
    }

    p = 0;

    pool->stats[slot].fails++;

done:

    ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                   "slab alloc: %p", (void *) p);

    return (void *) p;
}


void *
ngx_slab_calloc(ngx_slab_pool_t *pool, size_t size)
{
    void  *p;

    ngx_shmtx_lock(&pool->mutex);

    p = ngx_slab_calloc_locked(pool, size);

    ngx_shmtx_unlock(&pool->mutex);

    return p;
}


void *
ngx_slab_calloc_locked(ngx_slab_pool_t *pool, size_t size)
{
    void  *p;

    p = ngx_slab_alloc_locked(pool, size);
    if (p) {
        ngx_memzero(p, size);
    }

    return p;
}


void
ngx_slab_free(ngx_slab_pool_t *pool, void *p)
{
    ngx_shmtx_lock(&pool->mutex);

    ngx_slab_free_locked(pool, p);

    ngx_shmtx_unlock(&pool->mutex);
}


void
ngx_slab_free_locked(ngx_slab_pool_t *pool, void *p)
{
    size_t            size;
    uintptr_t         slab, m, *bitmap;
    ngx_uint_t        i, n, type, slot, shift, map;
    ngx_slab_page_t  *slots, *page;

    ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0, "slab free: %p", p);

    if ((u_char *) p < pool->start || (u_char *) p > pool->end) {
        ngx_slab_error(pool, NGX_LOG_ALERT, "ngx_slab_free(): outside of pool");
        goto fail;
    }

    n = ((u_char *) p - pool->start) >> ngx_pagesize_shift;
    page = &pool->pages[n];
    slab = page->slab;
    type = ngx_slab_page_type(page);

    switch (type) {

    case NGX_SLAB_SMALL:

        shift = slab & NGX_SLAB_SHIFT_MASK;
        size = (size_t) 1 << shift;

        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        n = ((uintptr_t) p & (ngx_pagesize - 1)) >> shift;
        m = (uintptr_t) 1 << (n % (8 * sizeof(uintptr_t)));
        n /= 8 * sizeof(uintptr_t);
        bitmap = (uintptr_t *)
                             ((uintptr_t) p & ~((uintptr_t) ngx_pagesize - 1));

        if (bitmap[n] & m) {
            slot = shift - pool->min_shift;

            if (page->next == NULL) {
                slots = ngx_slab_slots(pool);

                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_SMALL;
                page->next->prev = (uintptr_t) page | NGX_SLAB_SMALL;
            }

            bitmap[n] &= ~m;

            n = (ngx_pagesize >> shift) / ((1 << shift) * 8);

            if (n == 0) {
                n = 1;
            }

            i = n / (8 * sizeof(uintptr_t));
            m = ((uintptr_t) 1 << (n % (8 * sizeof(uintptr_t)))) - 1;

            if (bitmap[i] & ~m) {
                goto done;
            }

            map = (ngx_pagesize >> shift) / (8 * sizeof(uintptr_t));

            for (i = i + 1; i < map; i++) {
                if (bitmap[i]) {
                    goto done;
                }
            }

            ngx_slab_free_pages(pool, page, 1);

            pool->stats[slot].total -= (ngx_pagesize >> shift) - n;

            goto done;
        }

        goto chunk_already_free;

    case NGX_SLAB_EXACT:

        m = (uintptr_t) 1 <<
                (((uintptr_t) p & (ngx_pagesize - 1)) >> ngx_slab_exact_shift);
        size = ngx_slab_exact_size;

        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        if (slab & m) {
            slot = ngx_slab_exact_shift - pool->min_shift;

            if (slab == NGX_SLAB_BUSY) {
                slots = ngx_slab_slots(pool);

                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_EXACT;
                page->next->prev = (uintptr_t) page | NGX_SLAB_EXACT;
            }

            page->slab &= ~m;

            if (page->slab) {
                goto done;
            }

            ngx_slab_free_pages(pool, page, 1);

            pool->stats[slot].total -= 8 * sizeof(uintptr_t);

            goto done;
        }

        goto chunk_already_free;

    case NGX_SLAB_BIG:

        shift = slab & NGX_SLAB_SHIFT_MASK;
        size = (size_t) 1 << shift;

        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        m = (uintptr_t) 1 << ((((uintptr_t) p & (ngx_pagesize - 1)) >> shift)
                              + NGX_SLAB_MAP_SHIFT);

        if (slab & m) {
            slot = shift - pool->min_shift;

            if (page->next == NULL) {
                slots = ngx_slab_slots(pool);

                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_BIG;
                page->next->prev = (uintptr_t) page | NGX_SLAB_BIG;
            }

            page->slab &= ~m;

            if (page->slab & NGX_SLAB_MAP_MASK) {
                goto done;
            }

            ngx_slab_free_pages(pool, page, 1);

            pool->stats[slot].total -= ngx_pagesize >> shift;

            goto done;
        }

        goto chunk_already_free;

    case NGX_SLAB_PAGE:

        if ((uintptr_t) p & (ngx_pagesize - 1)) {
            goto wrong_chunk;
        }

        if (!(slab & NGX_SLAB_PAGE_START)) {
            ngx_slab_error(pool, NGX_LOG_ALERT,
                           "ngx_slab_free(): page is already free");
            goto fail;
        }

        if (slab == NGX_SLAB_PAGE_BUSY) {
            ngx_slab_error(pool, NGX_LOG_ALERT,
                           "ngx_slab_free(): pointer to wrong page");
            goto fail;
        }

        size = slab & ~NGX_SLAB_PAGE_START;

        ngx_slab_free_pages(pool, page, size);

        ngx_slab_junk(p, size << ngx_pagesize_shift);

        return;
    }

    /* not reached */

    return;

done:

    pool->stats[slot].used--;

    ngx_slab_junk(p, size);

    return;

wrong_chunk:

    ngx_slab_error(pool, NGX_LOG_ALERT,
                   "ngx_slab_free(): pointer to wrong chunk");

    goto fail;

chunk_already_free:

    ngx_slab_error(pool, NGX_LOG_ALERT,
                   "ngx_slab_free(): chunk is already free");

fail:

    return;
}


static ngx_slab_page_t *
ngx_slab_alloc_pages(ngx_slab_pool_t *pool, ngx_uint_t pages)
{
    ngx_slab_page_t  *page, *p;

    for (page = pool->free.next; page != &pool->free; page = page->next) {

        if (page->slab >= pages) {

            if (page->slab > pages) {
                page[page->slab - 1].prev = (uintptr_t) &page[pages];

                page[pages].slab = page->slab - pages;
                page[pages].next = page->next;
                page[pages].prev = page->prev;

                p = (ngx_slab_page_t *) page->prev;
                p->next = &page[pages];
                page->next->prev = (uintptr_t) &page[pages];

            } else {
                p = (ngx_slab_page_t *) page->prev;
                p->next = page->next;
                page->next->prev = page->prev;
            }

            page->slab = pages | NGX_SLAB_PAGE_START;
            page->next = NULL;
            page->prev = NGX_SLAB_PAGE;

            pool->pfree -= pages;

            if (--pages == 0) {
                return page;
            }

            for (p = page + 1; pages; pages--) {
                p->slab = NGX_SLAB_PAGE_BUSY;
                p->next = NULL;
                p->prev = NGX_SLAB_PAGE;
                p++;
            }

            return page;
        }
    }

    if (pool->log_nomem) {
        ngx_slab_error(pool, NGX_LOG_CRIT,
                       "ngx_slab_alloc() failed: no memory");
    }

    return NULL;
}


static void
ngx_slab_free_pages(ngx_slab_pool_t *pool, ngx_slab_page_t *page,
    ngx_uint_t pages)
{
    ngx_slab_page_t  *prev, *join;

    pool->pfree += pages;

    page->slab = pages--;

    if (pages) {
        ngx_memzero(&page[1], pages * sizeof(ngx_slab_page_t));
    }

    if (page->next) {
        prev = ngx_slab_page_prev(page);
        prev->next = page->next;
        page->next->prev = page->prev;
    }

    join = page + page->slab;

    if (join < pool->last) {

        if (ngx_slab_page_type(join) == NGX_SLAB_PAGE) {

            if (join->next != NULL) {
                pages += join->slab;
                page->slab += join->slab;

                prev = ngx_slab_page_prev(join);
                prev->next = join->next;
                join->next->prev = join->prev;

                join->slab = NGX_SLAB_PAGE_FREE;
                join->next = NULL;
                join->prev = NGX_SLAB_PAGE;
            }
        }
    }

    if (page > pool->pages) {
        join = page - 1;

        if (ngx_slab_page_type(join) == NGX_SLAB_PAGE) {

            if (join->slab == NGX_SLAB_PAGE_FREE) {
                join = ngx_slab_page_prev(join);
            }

            if (join->next != NULL) {
                pages += join->slab;
                join->slab += page->slab;

                prev = ngx_slab_page_prev(join);
                prev->next = join->next;
                join->next->prev = join->prev;

                page->slab = NGX_SLAB_PAGE_FREE;
                page->next = NULL;
                page->prev = NGX_SLAB_PAGE;

                page = join;
            }
        }
    }

    if (pages) {
        page[pages].prev = (uintptr_t) page;
    }

    page->prev = (uintptr_t) &pool->free;
    page->next = pool->free.next;

    page->next->prev = (uintptr_t) page;

    pool->free.next = page;
}


static void
ngx_slab_error(ngx_slab_pool_t *pool, ngx_uint_t level, char *text)
{
    ngx_log_error(level, ngx_cycle->log, 0, "%s%s", text, pool->log_ctx);
}


#if (NGX_API)

ngx_int_t
ngx_api_slabs_handler(ngx_api_entry_data_t data, ngx_api_ctx_t *actx, void *ctx)
{
    ngx_list_part_t     part;
    ngx_api_iter_ctx_t  ictx;

    part = ngx_cycle->shared_memory.part;

    ictx.entry.handler = ngx_api_slab_handler;
    ictx.entry.data.ents = ngx_api_slab_entries;
    ictx.elts = &part;

    return ngx_api_object_iterate(ngx_api_slabs_iter, &ictx, actx);
}


static ngx_int_t
ngx_api_slabs_iter(ngx_api_iter_ctx_t *ictx, ngx_api_ctx_t *actx)
{
    ngx_shm_zone_t   *shm_zone;
    ngx_list_part_t  *part;

    part = ictx->elts;

    for ( ;; ) {
        if (part->nelts == 0) {
            if (part->next == NULL) {
                return NGX_DECLINED;
            }

            *part = *part->next;
        }

        shm_zone = part->elts;

        part->elts = shm_zone + 1;
        part->nelts--;

        if (shm_zone->noslab) {
            continue;
        }

        ictx->entry.name = shm_zone->shm.name;
        ictx->ctx = shm_zone->shm.addr;

        return NGX_OK;
    }
}


static ngx_int_t
ngx_api_slab_handler(ngx_api_entry_data_t data, ngx_api_ctx_t *actx, void *ctx)
{
    ngx_slab_pool_t *pool = ctx;

    ngx_int_t  rc;

    ngx_shmtx_lock(&pool->mutex);

    rc = ngx_api_object_handler(data, actx, pool);

    ngx_shmtx_unlock(&pool->mutex);

    return rc;
}


static ngx_int_t
ngx_api_slab_pages_used_handler(ngx_api_entry_data_t data, ngx_api_ctx_t *actx,
    void *ctx)
{
    ngx_slab_pool_t *pool = ctx;

    data.num = pool->last - pool->pages - pool->pfree;

    return ngx_api_number_handler(data, actx, ctx);
}


static ngx_int_t
ngx_api_slab_slots_handler(ngx_api_entry_data_t data, ngx_api_ctx_t *actx,
    void *ctx)
{
    ngx_slab_pool_t *pool = ctx;

    ngx_api_iter_ctx_t  ictx;

    ictx.entry.handler = ngx_api_object_handler;
    ictx.entry.data.ents = ngx_api_slab_slot_entries;
    ictx.ctx = NULL;
    ictx.elts = pool;

    return ngx_api_object_iterate(ngx_api_slab_slots_iter, &ictx, actx);
}


static ngx_int_t
ngx_api_slab_slots_iter(ngx_api_iter_ctx_t *ictx, ngx_api_ctx_t *actx)
{
    size_t            size, idx;
    ngx_str_t        *name;
    ngx_slab_stat_t  *stat;
    ngx_slab_pool_t  *pool;

    stat = ictx->ctx;
    pool = ictx->elts;
    idx = stat ? stat - pool->stats + 1 : 0;

    for ( ;; ) {
        if (idx >= ngx_pagesize_shift - pool->min_shift) {
            return NGX_DECLINED;
        }

        if (pool->stats[idx].reqs) {
            break;
        }

        idx++;
    }

    name = &ictx->entry.name;

    name->data = ngx_pnalloc(actx->pool, NGX_SIZE_T_LEN);
    if (name->data == NULL) {
        return NGX_ERROR;
    }

    size = (size_t) 1 << (idx + pool->min_shift);

    name->len = ngx_sprintf(name->data, "%uz", size) - name->data;

    ictx->ctx = &pool->stats[idx];

    return NGX_OK;
}


static ngx_int_t
ngx_api_slab_slot_free_handler(ngx_api_entry_data_t data, ngx_api_ctx_t *actx,
    void *ctx)
{
    ngx_slab_stat_t *s = ctx;

    data.num = s->total - s->used;

    return ngx_api_number_handler(data, actx, ctx);
}

#endif


static ngx_int_t
ngx_slab_write_header(ngx_slab_state_header_t *hdr, ngx_file_t *file)
{
    size_t            len, size;
    ssize_t           n;
    ngx_str_t        *sign;
    ngx_slab_pool_t  *pool;

    u_char            buf[NGX_SLAB_HEADER_LEN];

    pool = (ngx_slab_pool_t *) hdr->addr;
    sign = &hdr->signature;

    size = (u_char *) pool->end - (u_char *) pool;

    /*
     * header format (ASCII):
     *  "magic_id;<hex_addr>;<hex_size>;<data_offset>;<sign_len>;[fill]"
     * Example:
     *  "angie-shm-001;7cdef54;16384;42;33;***"
     *
     * Signature is written right after header, then data
     */

    /* offset to slab data from file start */
    hdr->offset = NGX_SLAB_HEADER_LEN + sign->len;

    len = ngx_sprintf(buf, "%s;%xL;%xL;%xL;%xL;", NGX_SLAB_MAGICK,
                      addr_to_u64(pool), size, hdr->offset, sign->len)
          - buf;

    /* fill in the rest of buf with asterisks, so we always have full header */
    if (len < sizeof(buf)) {
        ngx_memset(buf + len, '*' ,sizeof(buf) - len);
    }

    n = ngx_write_file(file, buf, sizeof(buf), 0);
    if (n < 0) {
        ngx_log_error(NGX_LOG_ERR, file->log, ngx_errno,
                      "failed to write slab header into \"%V\"", &file->name);

        return NGX_ERROR;
    }

    n = ngx_write_file(file, sign->data, sign->len, NGX_SLAB_HEADER_LEN);
    if (n < 0) {
        ngx_log_error(NGX_LOG_ERR, file->log, ngx_errno,
                      "failed to write zone signature into \"%V\"",
                      &file->name);

        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_slab_read_header(ngx_slab_state_header_t *hdr, ngx_file_t *file)
{
    u_char     *p, *end;
    ssize_t     n;
    ngx_str_t   token, sign;
    uint64_t    addr, size, off;

    u_char      buf[NGX_SLAB_HEADER_LEN];

    n = ngx_read_file(file, buf, sizeof(buf), 0);
    if (n == NGX_ERROR) {
        return NGX_ERROR;
    }

    if ((size_t) n < NGX_SLAB_HEADER_LEN) {
        ngx_log_error(NGX_LOG_ERR, file->log, 0,
                      "zone file \"%V\" is too small", &file->name);
        return NGX_ERROR;
    }

    p = buf;
    end = buf + n;

    if (ngx_slab_header_next_token(&token, &p, end) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, file->log, 0,
                      "failed to get magick from zone file \"%V\"",
                      &file->name);
        return NGX_ERROR;
    }

    if (token.len != NGX_SLAB_MAGICK_LEN
        || ngx_strncmp(token.data, NGX_SLAB_MAGICK, NGX_SLAB_MAGICK_LEN) != 0)
    {
        ngx_log_error(NGX_LOG_ERR, file->log, 0,
                      "bad magick in zone file \"%V\"", &file->name);
        return NGX_ERROR;
    }

    /* zone address */

    if (ngx_slab_header_next_hexnum(&addr, &p, end, file->log) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, file->log, 0,
                      "failed to get addr from zone file \"%V\"", &file->name);
        return NGX_ERROR;
    }

    hdr->addr = u64_to_addr(addr);

    /* zone size */

    if (ngx_slab_header_next_hexnum(&size, &p, end, file->log) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, file->log, 0,
                      "failed to get size from zone file \"%V\"", &file->name);
        return NGX_ERROR;
    }

    hdr->size = size;

    /* data offset in file */

    if (ngx_slab_header_next_hexnum(&off, &p, end, file->log) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, file->log, 0,
                      "failed to get offset from zone file \"%V\"",
                      &file->name);
        return NGX_ERROR;
    }

    hdr->offset = off;

    /* signature len */
    if (ngx_slab_header_next_hexnum(&size, &p, end, file->log) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, file->log, 0,
                      "failed to get signature length from zone file \"%V\"",
                      &file->name);
        return NGX_ERROR;
    }

    if (hdr->signature.len != size) {
        ngx_log_error(NGX_LOG_ERR, file->log, 0,
                      "signature differs in size: expected %ui found %ui "
                      "in zone file \"%V\"",
                      hdr->signature.len, size, &file->name);
        return NGX_ERROR;
    }

    /* reuse header buf which is big enough for any practical signature */
    if (size > sizeof(buf)) {
        ngx_log_error(NGX_LOG_ERR, file->log, 0,
                      "signature length is too big in zone file \"%V\"",
                      &file->name);
        return NGX_ERROR;
    }

    sign.len = size;
    sign.data = buf;

    n = ngx_read_file(file, buf, sign.len, NGX_SLAB_HEADER_LEN);
    if (n == NGX_ERROR) {
        return NGX_ERROR;
    }

    if ((size_t) n != sign.len) {
        ngx_log_error(NGX_LOG_ERR, file->log, 0,
                      "failed to read full signature from zone file \"%V\"",
                      &file->name);
        return NGX_ERROR;
    }

    if (ngx_strncmp(hdr->signature.data, sign.data, sign.len) != 0) {
        ngx_log_error(NGX_LOG_ERR, file->log, 0,
                      "the signature differs: expected: \"%V\" found \"%V\" "
                      "in zone file \"%V\"",
                      &hdr->signature, &sign, &file->name);
        return NGX_DECLINED;
    }

    ngx_log_debug5(NGX_LOG_DEBUG_CORE, file->log, 0,
                   "restored zone addr:%p size:%ui off:%O sign:\"%V\" "
                   "from header of zone file \"%V\"",
                   hdr->addr, hdr->size, hdr->offset, &sign, &file->name);

    return NGX_OK;
}


static ngx_inline ngx_int_t
ngx_slab_header_next_token(ngx_str_t *token, u_char **p, u_char *end)
{
    token->data = *p;

    *p = ngx_strlchr(*p, end, ';');

    if (*p == NULL) {
        return NGX_ERROR;
    }

    token->len = *p - token->data;

    (*p)++;

    return NGX_OK;
}


static ngx_inline ngx_int_t
ngx_slab_header_next_hexnum(uint64_t *res, u_char **p, u_char *end,
    ngx_log_t *log)
{
    ngx_int_t  num;
    ngx_str_t  token;

    if (ngx_slab_header_next_token(&token, p, end) != NGX_OK) {
        return NGX_ERROR;
    }

    num = ngx_hextoi(token.data, token.len);
    if (num == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                      "shm zone file header number conversion failed");
        return NGX_ERROR;
    }

    if (num == 0) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                      "shm zone zero number in file");
        return NGX_ERROR;
    }

    *res = (uint64_t) num;

    return NGX_OK;
}


ngx_int_t
ngx_slab_save_pool(ngx_slab_state_header_t *hdr, ngx_file_t *file)
{
    ssize_t           len, n;
    ngx_slab_pool_t  *pool;

    pool = hdr->addr;

    ngx_shmtx_lock(&pool->mutex);

    /* file start with a magic and base address */
    if (ngx_slab_write_header(hdr, file) != NGX_OK) {
        goto failed;
    }

    /* to keep it simple, dump all pool metadata; read will use needed */
    len = (u_char *) pool->start - (u_char *) pool;

    /* next is slab metadata */
    n = ngx_write_file(file, (u_char *) pool, len, hdr->offset);
    if (n < 0) {
        goto failed;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_CORE, file->log, 0,
                   "saved %z bytes metadata at offset %O to zone file \"%V\"",
                   n, hdr->offset, &file->name);

    /* next are slab pages, each at page offset from metadata start */

    if (ngx_slab_save_pages(pool, hdr->offset, file) != NGX_OK) {
        goto failed;
    }

    ngx_shmtx_unlock(&pool->mutex);

    return NGX_OK;

failed:

    ngx_shmtx_unlock(&pool->mutex);

    return NGX_ERROR;
}


static ngx_int_t
ngx_slab_save_pages(ngx_slab_pool_t *pool, off_t header_off, ngx_file_t *file)
{
    off_t             off;
    ssize_t           n;
    void             *page_addr;
    ngx_uint_t        i, npages;
    ngx_slab_page_t  *page;
#if (NGX_DEBUG)
    ngx_uint_t        pages_saved;

    pages_saved = 0;
#endif

    npages = ((char *) pool->end - (char *) pool->start) / ngx_pagesize;

    for (i = 0; i < npages; i++) {

        page = &pool->pages[i];

        if (page->slab == 0) {
            continue;
        }

#if (NGX_DEBUG)
        pages_saved++;
#endif

        page_addr = (void *) ngx_slab_page_addr(pool, page);

        off = (u_char *) page_addr - (u_char *) pool;
        off += header_off;

        n = ngx_write_file(file, (u_char *) page_addr, ngx_pagesize, off);
        if (n < 0) {
            return NGX_ERROR;
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, file->log, 0,
                   "saved %ui slab pages to zone file \"%V\"",
                   pages_saved, &file->name);

    return NGX_OK;
}


ngx_int_t
ngx_slab_restore_pool(ngx_slab_state_header_t *hdr, ngx_file_t *file)
{
    size_t           ns;
    ssize_t          n;
    ngx_uint_t       i;
    ngx_slab_pool_t  fpool, *pool;

    /*
     * we are are restoring from file:
     *
     * metadata (at hdr.offset):
     * +---------------------------------------------+
     * |- head of free page list and free page count |
     * |- pointers to users' data and log context    |
     * |- array of slots                             |
     * |- array of stats                             |
     * |- array of pages metadata                    |
     * +---------------------------------------------+
     *
     * - pages itself (at offset from pool start + metadata offset)
     */

    if (ngx_slab_read_header(hdr, file) != NGX_OK) {
        return NGX_ERROR;
    }

    pool = (ngx_slab_pool_t *) hdr->addr;

    if ((u_char *) pool != hdr->addr) {
        /*
         * due to some reasons we failed to allocate pool at requested address,
         * or we somehow confused addresses and we are now trying to restore
         * the pool into the wrong address.
         *
         * should not happen normally; this is the last place to check
         * before things will explode
         */

        ngx_log_error(NGX_LOG_ALERT, file->log, 0,
                      "attempt to restore pool into incorrect address, file "
                      "\"%V\"", &file->name);

        return NGX_ERROR;
    }

    n = ngx_read_file(file, (u_char *) &fpool, sizeof(ngx_slab_pool_t),
                      hdr->offset);
    if (n < 0) {
        ngx_log_error(NGX_LOG_ERR, file->log, 0,
                      "failed to read metadata from zone file \"%V\"",
                      &file->name);
        return NGX_ERROR;
    }

    ngx_shmtx_lock(&pool->mutex);

    /* head of list of pages */
    pool->free = fpool.free;
    pool->pages = fpool.pages;
    pool->last = fpool.last;

    /* number of free pages */
    pool->pfree = fpool.pfree;

    /* allocated by pool users from pool */
    pool->data = fpool.data;
    pool->log_ctx = fpool.log_ctx;

    ns = ngx_pagesize_shift - pool->min_shift;

#define ngx_slab_offset(pool, addr) \
    ((((u_char *) addr) - ((u_char *) pool)) + hdr->offset)

#define ngx_slab_part(pool, addr, size) \
    { (u_char *) addr, size, ngx_slab_offset(pool, addr) }

    struct {
        u_char    *dst;
        size_t     size;
        off_t      offset;
    } ngx_slab_parts[] = {
        ngx_slab_part(pool, ngx_slab_slots(pool), sizeof(ngx_slab_page_t) * ns),
        ngx_slab_part(pool, pool->stats, sizeof(ngx_slab_stat_t) * ns),
        ngx_slab_part(pool, pool->pages,
                      sizeof(ngx_slab_page_t) * pool->pages->slab)
    };

    for (i = 0; i < sizeof(ngx_slab_parts) / sizeof(ngx_slab_parts[0]); i++) {

        n = ngx_read_file(file, ngx_slab_parts[i].dst, ngx_slab_parts[i].size,
                          ngx_slab_parts[i].offset);
        if (n < 0) {
            ngx_log_error(NGX_LOG_ERR, file->log, 0,
                          "failed to read %z slab bytes at offset %O "
                          "from zone file \"%V\"", ngx_slab_parts[i].size,
                           ngx_slab_parts[i].offset, &file->name);
            goto failed;
        }
    }

    if (ngx_slab_read_pages(pool, file, hdr->offset) != NGX_OK) {
        goto failed;
    }

    ngx_shmtx_unlock(&pool->mutex);

    return NGX_OK;

failed:

    ngx_shmtx_unlock(&pool->mutex);

    return NGX_ERROR;
}


static ngx_int_t
ngx_slab_read_pages(ngx_slab_pool_t *pool, ngx_file_t *file, off_t meta_offset)
{
    off_t             off;
    void             *page_addr;
    ssize_t           n;
    ngx_uint_t        i, npages;
    ngx_slab_page_t  *page;
#if (NGX_DEBUG)
    ngx_uint_t        pages_read;

    pages_read = 0;
#endif

    npages = ((char *) pool->end - (char *) pool->start) / ngx_pagesize;

    for (i = 0; i < npages; i++) {

        page = &pool->pages[i];

        if (page->slab == 0) {
            continue;
        }

        page_addr = (void *) ngx_slab_page_addr(pool, page);

        off = (u_char *) page_addr - (u_char *) pool;
        off += meta_offset;

        n = ngx_read_file(file, (u_char *) page_addr, ngx_pagesize, off);
        if (n < 0) {
            ngx_log_error(NGX_LOG_ALERT, file->log, 0,
                          "failed to read page at offset %O "
                          "from zone file \"%V\"", off, &file->name);

            return NGX_ERROR;
        }

#if (NGX_DEBUG)
        pages_read++;
#endif
    }

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, file->log, 0,
                   "restored %ui slab pages from zone file \"%V\"",
                   pages_read, &file->name);

    return NGX_OK;
}
