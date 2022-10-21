
/*
 * Copyright (C) 2022 Web Server LLC
 */


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    uint32_t  level;
    uint8_t   more_space;  /* unsigned  more_space:1 */
} ngx_json_pretty_t;


static size_t ngx_json_length(ngx_data_item_t *item,
    ngx_json_pretty_t *pretty);
static u_char *ngx_json_encode(u_char *p, ngx_data_item_t *item,
    ngx_json_pretty_t *pretty);

static size_t ngx_json_object_length(ngx_data_item_t *item,
    ngx_json_pretty_t *pretty);
static u_char *ngx_json_object_encode(u_char *p, ngx_data_item_t *item,
    ngx_json_pretty_t *pretty);

static size_t ngx_json_list_length(ngx_data_item_t *item,
    ngx_json_pretty_t *pretty);
static u_char *ngx_json_list_encode(u_char *p, ngx_data_item_t *item,
    ngx_json_pretty_t *pretty);

static size_t ngx_json_string_length(u_char *start, size_t length);
static u_char *ngx_json_string_encode(u_char *p, u_char *start, size_t length);


#define ngx_json_newline(p)                                                   \
    ((p)[0] = '\r', (p)[1] = '\n', (p) + 2)


static ngx_inline u_char *
ngx_json_indentation(u_char *p, uint32_t level)
{
    while (level) {
        *p++ = '\t';
        level--;
    }

    return p;
}


ngx_buf_t *
ngx_json_render(ngx_pool_t *pool, ngx_data_item_t *item, ngx_uint_t is_pretty)
{
    size_t              len;
    u_char             *p;
    ngx_buf_t          *buf;
    ngx_json_pretty_t   pretty, *pr_p;

    if (is_pretty) {
        pr_p = &pretty;
        ngx_memzero(pr_p, sizeof(ngx_json_pretty_t));

    } else {
        pr_p = NULL;
    }

    len = ngx_json_length(item, pr_p);
    if (len == (size_t) NGX_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, pool->log, 0,
                      "json length calculation failed");
        return NULL;
    }

    buf = ngx_create_temp_buf(pool, len + is_pretty * 2);
    if (buf == NULL) {
        return NULL;
    }

    p = ngx_json_encode(buf->last, item, pr_p);

    if (is_pretty) {
        p = ngx_json_newline(p);
    }

    buf->last = p;

    return buf;
}


static size_t
ngx_json_length(ngx_data_item_t *item, ngx_json_pretty_t *pretty)
{
    switch (item->type) {

    case NGX_DATA_OBJECT_TYPE:
        return ngx_json_object_length(item->data.child, pretty);

    case NGX_DATA_LIST_TYPE:
        return ngx_json_list_length(item->data.child, pretty);

    case NGX_DATA_STR_TYPE:
        return ngx_json_string_length(item->data.str.start,
                                      item->data.str.length);
    case NGX_DATA_STRING_TYPE:
        return ngx_json_string_length(item->data.string.start,
                                      item->data.string.length);
    case NGX_DATA_INTEGER_TYPE:
        return NGX_INT64_LEN;

    case NGX_DATA_BOOLEAN_TYPE:
        return sizeof("false") - 1;

    case NGX_DATA_NULL_TYPE:
        return sizeof("null") - 1;
    }

    return NGX_ERROR;
}


static u_char *
ngx_json_encode(u_char *p, ngx_data_item_t *item, ngx_json_pretty_t *pretty)
{
    switch (item->type) {

    case NGX_DATA_OBJECT_TYPE:
        return ngx_json_object_encode(p, item->data.child, pretty);

    case NGX_DATA_LIST_TYPE:
        return ngx_json_list_encode(p, item->data.child, pretty);

    case NGX_DATA_STR_TYPE:
        return ngx_json_string_encode(p, item->data.str.start,
                                      item->data.str.length);
    case NGX_DATA_STRING_TYPE:
        return ngx_json_string_encode(p, item->data.string.start,
                                      item->data.string.length);
    case NGX_DATA_INTEGER_TYPE:
        return ngx_sprintf(p, "%L", item->data.integer);

    case NGX_DATA_BOOLEAN_TYPE:
        return item->data.boolean ? ngx_cpymem(p, "true", 4)
                                  : ngx_cpymem(p, "false", 5);
    case NGX_DATA_NULL_TYPE:
        return ngx_cpymem(p, "null", 4);
    }

    return NULL;
}


static size_t
ngx_json_object_length(ngx_data_item_t *item, ngx_json_pretty_t *pretty)
{
    size_t  len;

    len = sizeof("{}") - 1;

    if (item != NULL) {
        if (pretty != NULL) {
            pretty->level++;
        }

        do {
            len += ngx_json_length(item, pretty) + 1
                   + ngx_json_length(item->next, pretty) + 1;

            if (pretty != NULL) {
                /* Indentation, space after ":", new line. */
                len += pretty->level + 1 + 2;
            }

            item = item->next->next;

        } while (item != NULL);

        if (pretty != NULL) {
            pretty->level--;

            /*
             * Indentation and new line, and possible additional empty line
             * after a non-empty object in another object.
             */
            len += pretty->level + 2 + 2;
        }
    }

    return len;
}


static u_char *
ngx_json_object_encode(u_char *p, ngx_data_item_t *item,
    ngx_json_pretty_t *pretty)
{
    *p++ = '{';

    if (item != NULL) {
        if (pretty != NULL) {
            p = ngx_json_newline(p);
            pretty->level++;
        }

        for ( ;; ) {
            if (pretty != NULL) {
                p = ngx_json_indentation(p, pretty->level);
            }

            p = ngx_json_encode(p, item, pretty);

            *p++ = ':';

            if (pretty != NULL) {
                *p++ = ' ';
            }

            p = ngx_json_encode(p, item->next, pretty);

            item = item->next->next;

            if (item == NULL) {
                break;
            }

            *p++ = ',';

            if (pretty != NULL) {
                p = ngx_json_newline(p);

                if (pretty->more_space) {
                    pretty->more_space = 0;
                    p = ngx_json_newline(p);
                }
            }
        }

        if (pretty != NULL) {
            p = ngx_json_newline(p);

            pretty->level--;
            p = ngx_json_indentation(p, pretty->level);

            pretty->more_space = 1;
        }
    }

    *p++ = '}';

    return p;
}


static size_t
ngx_json_list_length(ngx_data_item_t *item, ngx_json_pretty_t *pretty)
{
    size_t  len;

    len = sizeof("[]") - 1;

    if (item != NULL) {
        if (pretty != NULL) {
            pretty->level++;
        }

        do {
            len += ngx_json_length(item, pretty) + 1;

            if (pretty != NULL) {
                /* Indentation and new line. */
                len += pretty->level + 2;
            }

            item = item->next;

        } while (item != NULL);

        if (pretty != NULL) {
            pretty->level--;

            /*
             * Indentation and new line, and possible additional empty line
             * after a non-empty list in an object.
             */
            len += pretty->level + 2 + 2;
        }
    }

    return len;
}


static u_char *
ngx_json_list_encode(u_char *p, ngx_data_item_t *item,
    ngx_json_pretty_t *pretty)
{
    *p++ = '[';

    if (item != NULL) {
        if (pretty != NULL) {
            p = ngx_json_newline(p);

            pretty->level++;
            p = ngx_json_indentation(p, pretty->level);
        }

        p = ngx_json_encode(p, item, pretty);

        for (item = item->next; item != NULL; item = item->next) {
            *p++ = ',';

            if (pretty != NULL) {
                p = ngx_json_newline(p);
                p = ngx_json_indentation(p, pretty->level);

                pretty->more_space = 0;
            }

            p = ngx_json_encode(p, item, pretty);
        }

        if (pretty != NULL) {
            p = ngx_json_newline(p);

            pretty->level--;
            p = ngx_json_indentation(p, pretty->level);

            pretty->more_space = 1;
        }
    }

    *p++ = ']';

    return p;
}


static size_t
ngx_json_string_length(u_char *start, size_t length)
{
    return sizeof("\"\"") - 1 + length + ngx_escape_json(NULL, start, length);
}


static u_char *
ngx_json_string_encode(u_char *p, u_char *start, size_t length)
{
    *p++ = '"';

    p = (u_char *) ngx_escape_json(p, start, length);

    *p++ = '"';

    return p;
}
