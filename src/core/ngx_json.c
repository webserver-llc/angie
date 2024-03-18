
/*
 * Copyright (C) 2022-2024 Web Server LLC
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <math.h>


#define NGX_JSON_MAX_NUMBER_LEN  16


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


static u_char *ngx_json_skip_space(u_char *start, u_char *end);

static u_char *ngx_json_parse_value(ngx_data_item_t **item_p, u_char *start,
    u_char *end, ngx_pool_t *pool, ngx_json_parse_error_t *error);
static u_char *ngx_json_parse_object(ngx_data_item_t **item_p, u_char *start,
    u_char *end, ngx_pool_t *pool, ngx_json_parse_error_t *error);
static u_char *ngx_json_parse_array(ngx_data_item_t **item_p, u_char *start,
    u_char *end, ngx_pool_t *pool, ngx_json_parse_error_t *error);
static u_char *ngx_json_parse_string(ngx_data_item_t **item_p, u_char *start,
    u_char *end, ngx_pool_t *pool, ngx_json_parse_error_t *error);
static u_char *ngx_json_parse_number(ngx_data_item_t **item_p, u_char *start,
    u_char *end, ngx_pool_t *pool, ngx_json_parse_error_t *error);

static void *ngx_json_parse_error(ngx_json_parse_error_t *error, u_char *pos,
    u_char *desc, size_t desc_len);

#define ngx_json_parse_error_const(error, pos, desc)                          \
    ngx_json_parse_error((error), (pos), (u_char *) (desc), sizeof(desc) - 1)


ngx_data_item_t *
ngx_json_parse(u_char *start, u_char *end, ngx_pool_t *pool,
    ngx_json_parse_error_t *error)
{
    u_char           *p;
    ngx_data_item_t  *item;

    p = ngx_json_skip_space(start, end);

    if (p == end) {
        return ngx_json_parse_error_const(error, start,
            "Empty JSON payload isn't allowed.  It must be either a literal "
            "(null, true, or false), a number, a string (in double quotes "
            "\"\"), an array (with brackets []), or an object (with braces {})."
        );
    }

    p = ngx_json_parse_value(&item, p, end, pool, error);

    if (p == NULL) {
        return NULL;
    }

    p = ngx_json_skip_space(p, end);

    if (p != end) {
        return ngx_json_parse_error_const(error, p,
            "Unexpected character after the end of a valid JSON value."
        );
    }

    return item;
}


static u_char *
ngx_json_skip_space(u_char *start, u_char *end)
{
    u_char  *p, ch;

    enum {
        sw_normal = 0,
        sw_after_slash,
        sw_single_comment,
        sw_multi_comment,
        sw_after_asterisk,
    } state;

    state = sw_normal;

    for (p = start; p != end; p++) {
        ch = *p;

        switch (state) {

        case sw_normal:
            switch (ch) {
            case ' ':
            case '\t':
            case '\n':
            case '\r':
                continue;
            case '/':
                start = p;
                state = sw_after_slash;
                continue;
            }

            break;

        case sw_after_slash:
            switch (ch) {
            case '/':
                state = sw_single_comment;
                continue;
            case '*':
                state = sw_multi_comment;
                continue;
            }

            break;

        case sw_single_comment:
            if (ch == '\n') {
                state = sw_normal;
            }

            continue;

        case sw_multi_comment:
            if (ch == '*') {
                state = sw_after_asterisk;
            }

            continue;

        case sw_after_asterisk:
            switch (ch) {
            case '/':
                state = sw_normal;
                continue;
            case '*':
                continue;
            }

            state = sw_multi_comment;
            continue;
        }

        break;
    }

    if (state != sw_normal) {
        return start;
    }

    return p;
}


static u_char *
ngx_json_parse_value(ngx_data_item_t **item_p, u_char *start, u_char *end,
    ngx_pool_t *pool, ngx_json_parse_error_t *error)
{
    u_char            ch, *p;
    ngx_data_item_t  *item;

    ch = *start;

    switch (ch) {
    case '{':
        return ngx_json_parse_object(item_p, start, end, pool, error);

    case '[':
        return ngx_json_parse_array(item_p, start, end, pool, error);

    case '"':
        return ngx_json_parse_string(item_p, start, end, pool, error);

    case 't':
        if (end - start >= 4 && ngx_memcmp(start + 1, "rue", 3) == 0) {
            p = start + 4;
            item = ngx_data_new_boolean(1, pool);
            break;
        }

        goto error;

    case 'f':
        if (end - start >= 5 && ngx_memcmp(start + 1, "alse", 4) == 0) {
            p = start + 5;
            item = ngx_data_new_boolean(0, pool);
            break;
        }

        goto error;

    case 'n':
        if (end - start >= 4 && ngx_memcmp(start + 1, "ull", 3) == 0) {
            p = start + 4;
            item = ngx_data_new_null(pool);
            break;
        }

        goto error;

    case '-':
        if (end - start < 2) {
            goto error;
        }

        ch = start[1];

        /* fall through */

    default:
        if (ch - '0' <= 9) {
            p = ngx_json_parse_number(item_p, start, end, pool, error);

            if (p == NULL) {
                return NULL;
            }

            if (p == end) {
                return end;
            }

            switch (*p) {
            case ' ':
            case '\t':
            case '\r':
            case '\n':
            case ',':
            case '}':
            case ']':
            case '{':
            case '[':
            case '"':
            case '/':
                return p;
            }
        }

        goto error;
    }

    if (item == NULL) {
        return NULL;
    }

    *item_p = item;

    return p;

error:

    return ngx_json_parse_error_const(error, start,
        "A valid JSON value is expected here.  It must be either a literal "
        "(null, true, or false), a number, a string (in double quotes \"\"), "
        "an array (with brackets []), or an object (with braces {})."
    );
}


static u_char *
ngx_json_parse_object(ngx_data_item_t **item_p, u_char *start, u_char *end,
    ngx_pool_t *pool, ngx_json_parse_error_t *error)
{
    u_char           *p, *name_pos;
    ngx_str_t         n1, n2, err;
    ngx_data_item_t  *obj, *name, *item;

    obj = ngx_data_new_object(pool);
    if (obj == NULL) {
        return NULL;
    }

    p = start;

    for ( ;; ) {
        p = ngx_json_skip_space(p + 1, end);

        if (p == end) {
            return ngx_json_parse_error_const(error, p,
                "Unexpected end of JSON payload.  There's an object without "
                "a closing brace (})."
            );
        }

        if (*p != '"') {
            if (*p == '}') {
                break;
            }

            return ngx_json_parse_error_const(error, p,
                "A double quote (\") is expected here.  There must be a valid "
                "JSON object member that starts with a name, which is a string "
                "enclosed in double quotes."
            );
        }

        name_pos = p;

        p = ngx_json_parse_string(&name, name_pos, end, pool, error);

        if (p == NULL) {
            return NULL;
        }

        (void) ngx_data_get_string(&n1, name);

        for (item = obj->data.child; item != NULL; item = item->next->next) {
            (void) ngx_data_get_string(&n2, item);

            if (n1.len != n2.len || ngx_memcmp(n1.data, n2.data, n1.len) != 0) {
                continue;
            }

            ngx_str_set(&err, "Duplicate object member \"%V\".  All JSON "
                              "object members must have unique names.");

            p = ngx_pnalloc(pool, err.len - 2 + n1.len);
            if (p == NULL) {
                return NULL;
            }

            err.len = ngx_sprintf(p, (char *) err.data, &n1) - p;
            err.data = p;

            return ngx_json_parse_error(error, name_pos, err.data, err.len);
        }

        p = ngx_json_skip_space(p, end);

        if (p == end) {
            return ngx_json_parse_error_const(error, p,
                "Unexpected end of JSON payload.  There's an object member "
                "without a value."
            );
        }

        if (*p != ':') {
            return ngx_json_parse_error_const(error, p,
                "A colon (:) is expected here.  There must be a colon after "
                "a JSON member name."
            );
        }

        p = ngx_json_skip_space(p + 1, end);

        if (p == end) {
            return ngx_json_parse_error_const(error, p,
                "Unexpected end of JSON payload.  There's an object member "
                "without a value."
            );
        }

        p = ngx_json_parse_value(&item, p, end, pool, error);

        if (p == NULL) {
            return NULL;
        }

        p = ngx_json_skip_space(p, end);

        if (p == end) {
            return ngx_json_parse_error_const(error, p,
                "Unexpected end of JSON payload.  There's an object without "
                "a closing brace (})."
            );
        }

        (void) ngx_data_object_add(obj, name, item);

        if (*p != ',') {
            if (*p == '}') {
                break;
            }

            return ngx_json_parse_error_const(error, p,
                "Either a closing brace (}) or a comma (,) is expected here.  "
                "Each JSON object must be enclosed in braces, and its members "
                "must be separated by commas."
            );
        }
    }

    *item_p = obj;

    return p + 1;
}


static u_char *
ngx_json_parse_array(ngx_data_item_t **item_p, u_char *start, u_char *end,
    ngx_pool_t *pool, ngx_json_parse_error_t *error)
{
    u_char           *p;
    ngx_data_item_t  *list, *item;

    list = ngx_data_new_list(pool);
    if (list == NULL) {
        return NULL;
    }

    p = start;

    for ( ;; ) {
        p = ngx_json_skip_space(p + 1, end);

        if (p == end) {
            return ngx_json_parse_error_const(error, p,
                "Unexpected end of JSON payload.  There's an array without "
                "a closing bracket (])."
            );
        }

        if (*p == ']') {
            break;
        }

        p = ngx_json_parse_value(&item, p, end, pool, error);

        if (p == NULL) {
            return NULL;
        }

        p = ngx_json_skip_space(p, end);

        if (p == end) {
            return ngx_json_parse_error_const(error, p,
                "Unexpected end of JSON payload.  There's an array without "
                "a closing bracket (])."
            );
        }

        (void) ngx_data_list_add(list, item);

        if (*p != ',') {
            if (*p == ']') {
                break;
            }

            return ngx_json_parse_error_const(error, p,
                "Either a closing bracket (]) or a comma (,) is expected "
                "here.  Each array must be enclosed in brackets, and its "
                "members must be separated by commas."
            );
        }
    }

    *item_p = list;

    return p + 1;
}


static u_char *
ngx_json_parse_string(ngx_data_item_t **item_p, u_char *start, u_char *end,
    ngx_pool_t *pool, ngx_json_parse_error_t *error)
{
    u_char           *p, ch, *last, *s;
    size_t            len, surplus;
    uint32_t          utf, utf_high;
    ngx_uint_t        i;
    ngx_data_item_t  *item;
    enum {
        sw_usual = 0,
        sw_escape,
        sw_encoded1,
        sw_encoded2,
        sw_encoded3,
        sw_encoded4,
    } state;

    start++;

    state = 0;
    surplus = 0;

    for (p = start; p != end; p++) {
        ch = *p;

        switch (state) {

        case sw_usual:

            if (ch == '"') {
                break;
            }

            if (ch == '\\') {
                state = sw_escape;
                continue;
            }

            if (ch >= ' ') {
                continue;
            }

            return ngx_json_parse_error_const(error, p,
                "Unexpected character.  All control characters in a JSON "
                "string must be escaped."
            );

        case sw_escape:

            switch (ch) {
            case '"':
            case '\\':
            case '/':
            case 'n':
            case 'r':
            case 't':
            case 'b':
            case 'f':
                surplus++;
                state = sw_usual;
                continue;

            case 'u':
                /*
                 * Basic unicode 6 bytes "\uXXXX" in JSON
                 * and up to 3 bytes in UTF-8.
                 *
                 * Surrogate pair: 12 bytes "\uXXXX\uXXXX" in JSON
                 * and 3 or 4 bytes in UTF-8.
                 */
                surplus += 3;
                state = sw_encoded1;
                continue;
            }

            return ngx_json_parse_error_const(error, p - 1,
                "Unexpected backslash.  A literal backslash in a JSON string "
                "must be escaped with a second backslash (\\\\)."
            );

        case sw_encoded1:
        case sw_encoded2:
        case sw_encoded3:
        case sw_encoded4:

            if ((ch >= '0' && ch <= '9')
                || (ch >= 'A' && ch <= 'F')
                || (ch >= 'a' && ch <= 'f'))
            {
                state = (state == sw_encoded4) ? sw_usual : state + 1;
                continue;
            }

            return ngx_json_parse_error_const(error, p,
                "Invalid escape sequence.  An escape sequence in a JSON "
                "string must start with a backslash, followed by the lowercase "
                "letter u and four hexadecimal digits (\\uXXXX)."
            );
        }

        break;
    }

    if (p == end) {
        return ngx_json_parse_error_const(error, p,
            "Unexpected end of JSON payload.  There's a string without "
            "a final double quote (\")."
        );
    }

    /* Points to the ending quote mark. */
    last = p;

    len = last - start - surplus;

    if (len > NGX_DATA_MAX_STR) {
        if (len > NGX_DATA_MAX_STRING) {
            return ngx_json_parse_error_const(error, start,
                "The string is too long.  Such JSON string values "
                "aren't supported."
            );
        }

        item = ngx_data_new_item(pool, NGX_DATA_STRING_TYPE);
        s = ngx_pnalloc(pool, len);

        if (item == NULL || s == NULL) {
            return NULL;
        }

        item->data.string.length = len;
        item->data.string.start = s;

    } else {
        item = ngx_data_new_item(pool, NGX_DATA_STR_TYPE);
        if (item == NULL) {
            return NULL;
        }

        item->data.str.length = len;
        s = item->data.str.start;
    }

    *item_p = item;

    if (surplus == 0) {
        ngx_memcpy(s, start, len);
        return last + 1;
    }

    p = start;

    do {
        ch = *p++;

        if (ch != '\\') {
            *s++ = ch;
            continue;
        }

        ch = *p++;

        switch (ch) {
        case '"':
        case '\\':
        case '/':
            *s++ = ch;
            continue;

        case 'n':
            *s++ = '\n';
            continue;

        case 'r':
            *s++ = '\r';
            continue;

        case 't':
            *s++ = '\t';
            continue;

        case 'b':
            *s++ = '\b';
            continue;

        case 'f':
            *s++ = '\f';
            continue;
        }

        utf = 0;
        utf_high = 0;

        for ( ;; ) {
            for (i = 0; i < 4; i++) {
                utf = (utf << 4) | (p[i] >= 'A' ? 10 + ((p[i] & ~0x20) - 'A')
                                                : p[i] - '0');
            }

            p += 4;

            if (utf_high != 0) {
                if (utf < 0xDC00 || utf > 0xDFFF) {
                    return ngx_json_parse_error_const(error, p - 12,
                        "Invalid JSON encoding sequence.  This 12-byte "
                        "sequence composes an illegal UTF-16 surrogate pair."
                    );
                }

                utf = ((utf_high - 0xD800) << 10) + (utf - 0xDC00) + 0x10000;

                break;
            }

            if (utf < 0xD800 || utf > 0xDFFF) {
                break;
            }

            if (utf > 0xDBFF || p[0] != '\\' || p[1] != 'u') {
                return ngx_json_parse_error_const(error, p - 6,
                    "Invalid JSON encoding sequence.  This 6-byte sequence "
                    "doesn't represent a valid UTF character."
                );
            }

            p += 2;

            utf_high = utf;
            utf = 0;
        }

        s = ngx_utf8_encode(s, utf);

    } while (p != last);

    if (item->type == NGX_DATA_STR_TYPE) {
        item->data.str.length = s - item->data.str.start;

    } else {
        item->data.string.length = s - item->data.string.start;
    }

    return last + 1;
}


static u_char *
ngx_json_parse_number(ngx_data_item_t **item_p, u_char *start, u_char *end,
    ngx_pool_t *pool, ngx_json_parse_error_t *error)
{
    u_char           *p, *s, ch, c, *dot_pos;
    size_t            size;
    double            num;
    ngx_data_item_t  *item;
    u_char            tmp[NGX_JSON_MAX_NUMBER_LEN + 1];

    s = start;
    ch = *s;

    if (ch == '-') {
        s++;
    }

    dot_pos = NULL;

    for (p = s; p != end; p++) {
        ch = *p;

        /* Values below '0' become >= 208. */
        c = ch - '0';

        if (c > 9) {
            if (ch == '.' && dot_pos == NULL) {
                dot_pos = p;
                continue;
            }

            break;
        }
    }

    if (dot_pos != NULL) {
        if (p - dot_pos <= 1) {
            return ngx_json_parse_error_const(error, s,
                "The number is invalid.  Fraction parts in JSON numbers "
                "must have at least one digit."
            );
        }

    } else {
        dot_pos = p;
    }

    if (dot_pos - s > 1 && *s == '0') {
        return ngx_json_parse_error_const(error, s,
            "The number is invalid.  Leading zeros aren't allowed in JSON "
            "numbers."
        );
    }

    if (ch == 'e' || ch == 'E') {
        p++;
        s = p;

        if (s != end) {
            ch = *s;

            if (ch == '-' || ch == '+') {
                s++;
            }

            for (p = s; p != end; p++) {
                ch = *p;

                /* Values below '0' become >= 208. */
                c = ch - '0';

                if (c > 9) {
                    break;
                }
            }
        }

        if (p == s) {
            return ngx_json_parse_error_const(error, start,
                "The number is invalid.  Exponent parts in JSON numbers "
                "must have at least one digit."
            );
        }
    }

    size = p - start;

    if (size > NGX_JSON_MAX_NUMBER_LEN) {
        return ngx_json_parse_error_const(error, start,
            "The number is too long.  Such JSON number values aren't supported."
        );
    }

    ngx_memcpy(tmp, start, size);
    tmp[size] = '\0';

    ngx_errno = 0;
    end = NULL;

    num = ngx_strtod(tmp, &end);

    if (ngx_errno == NGX_ERANGE || fabs(num) > (double) NGX_MAX_INT64_VALUE) {
        return ngx_json_parse_error_const(error, start,
            "The number is outside the representable range.  Such JSON number "
            "values aren't supported."
        );
    }

    if (end == NULL || *end != '\0') {
        ngx_log_error(NGX_LOG_ALERT, pool->log, ngx_errno,
                      "strtod(\"%s\", %s) failed", tmp,
                      end == NULL ? (u_char *) "NULL" : end);
        return NULL;
    }

    if (num != trunc(num)) {
        return ngx_json_parse_error_const(error, start,
            "Fractional numbers aren't supported."
        );
    }

    item = ngx_data_new_integer(num, pool);
    if (item == NULL) {
        return NULL;
    }

    *item_p = item;

    return p;
}


static void *
ngx_json_parse_error(ngx_json_parse_error_t *error, u_char *pos, u_char *desc,
    size_t desc_len)
{
    if (error != NULL) {
        error->pos = pos;
        error->desc.len = desc_len;
        error->desc.data = desc;
    }

    return NULL;
}


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
