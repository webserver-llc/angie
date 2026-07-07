
/*
 * Copyright (C) 2024 Web Server LLC
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_LOG_H_INCLUDED_
#define _NGX_LOG_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_LOG_STDERR            0
#define NGX_LOG_EMERG             1
#define NGX_LOG_ALERT             2
#define NGX_LOG_CRIT              3
#define NGX_LOG_ERR               4
#define NGX_LOG_WARN              5
#define NGX_LOG_NOTICE            6
#define NGX_LOG_INFO              7
#define NGX_LOG_DEBUG             8

#define NGX_LOG_DEBUG_CORE        0x010
#define NGX_LOG_DEBUG_ALLOC       0x020
#define NGX_LOG_DEBUG_MUTEX       0x040
#define NGX_LOG_DEBUG_EVENT       0x080
#define NGX_LOG_DEBUG_HTTP        0x100
#define NGX_LOG_DEBUG_MAIL        0x200
#define NGX_LOG_DEBUG_STREAM      0x400

/*
 * do not forget to update debug_levels[] in src/core/ngx_log.c
 * after the adding a new debug level
 */

#define NGX_LOG_DEBUG_FIRST       NGX_LOG_DEBUG_CORE
#define NGX_LOG_DEBUG_LAST        NGX_LOG_DEBUG_STREAM
#define NGX_LOG_DEBUG_CONNECTION  0x80000000
#define NGX_LOG_DEBUG_ALL         0x7ffffff0

#if (!defined(ngx_src_file))
#define ngx_src_file()            (ngx_basename(__FILE__))
#endif

typedef struct {
    void                *ctx;
    uint8_t              type;
    unsigned             done:1;
} ngx_log_format_t;


typedef struct ngx_log_tag_s  ngx_log_tag_t;

struct ngx_log_tag_s {
    ngx_str_t            str;
    ngx_log_tag_t       *next;
};


#if (NGX_SSL)
#define NGX_SX(a, b, c) NGX_X(a, b, c)
#else
#define NGX_SX(a, b, c)
#endif

/*
 * the list contains static definitions for the purposes of logging;
 * some entries has no name: those are not properties, but tags.
 * most tags has the same name as properties, so the same list is used
 * to keep both; this avoids having extra set of macros purely for tags;
 *
 * NULLPROP is always at index 0, so that memzero()'ed ngx_log_t refers to it;
 * with it, it is possible to distinguish uninitialized property keys.
 */

#define NGX_CORE_LOG_PROP_LIST                                                \
    NGX_X(NULLPROP,        "",              NGX_LOG_PT_NUM)                   \
    NGX_X(CONTEXT,         "context",       NGX_LOG_PT_OBJ)                   \
    NGX_X(MESSAGE,         "message",       NGX_LOG_PT_STR)                   \
    NGX_X(RESOLVER,        "resolver",      NGX_LOG_PT_STR)                   \
    NGX_X(SYSLOG_SERVER,   "syslog_server", NGX_LOG_PT_STR)                   \
    NGX_X(LISTEN_ADDR,     "listen_addr",   NGX_LOG_PT_STR)                   \
    NGX_SX(OCSP_TAG,       "ocsp",          NGX_LOG_PT_TAG)                   \
    NGX_SX(OCSP_RESPONDER, "responder",     NGX_LOG_PT_STR)                   \
    NGX_SX(OCSP_PEER,      "peer",          NGX_LOG_PT_STR)                   \
    NGX_SX(OCSP_CERT,      "certificate",   NGX_LOG_PT_STR)


enum {
    #define NGX_X(id, name, type)  NGX_CORE_LOG_PROP__##id,
    NGX_CORE_LOG_PROP_LIST
    #undef NGX_X
};


typedef enum {
    NGX_LOG_PT_STR = 0,
    NGX_LOG_PT_NUM = 1,
    NGX_LOG_PT_OBJ = 2,
    NGX_LOG_PT_TAG = 3,
} ngx_log_property_type_t;


typedef struct {
    ngx_uint_t                index;
    ngx_str_t                 name;
    const char               *module;
    ngx_log_property_type_t   type;
    ngx_log_tag_t             tag;
} ngx_log_property_t;

/*
 * wrapper type to use with ngx_log_property(), prohibits
 * accidentall passing of unrelated integer while logging
 */
typedef struct {
    ngx_uint_t           id;
} ngx_log_property_key_t;

typedef struct ngx_log_conf_s  ngx_log_conf_t;

typedef struct ngx_log_filter_s  ngx_log_filter_t;

typedef u_char *(*ngx_log_handler_pt) (ngx_log_t *log, u_char *buf, size_t len);
typedef u_char *(*ngx_log_ext_handler_pt) (ngx_log_t *log, u_char *buf,
    u_char *last, void *data);
typedef void (*ngx_log_writer_pt) (ngx_log_t *log, ngx_uint_t level,
    u_char *buf, size_t len);


typedef struct {
    ngx_uint_t           rate;
    ngx_atomic_t         excess;
    ngx_atomic_t         last;
} ngx_log_limit_t;


struct ngx_log_s {
    ngx_uint_t           log_level;
    ngx_open_file_t     *file;

    ngx_atomic_uint_t    connection;

    ngx_log_handler_pt   handler;
    void                *data;
    ngx_log_property_key_t  handler_name;

    ngx_log_writer_pt    writer;
    void                *wdata;

    /*
     * we declare "action" as "char *" because the actions are usually
     * the static strings and in the "u_char *" case we have to override
     * their types all the time
     */

    char                *action;

    ngx_log_limit_t     *limit;

    ngx_log_t           *next;

    ngx_log_filter_t    *filter;
    ngx_log_conf_t      *conf;
    ngx_log_format_t     format;

    /* only meaningful during the call on the first log in list */
    ngx_log_tag_t       *tags;
    unsigned             busy:1;

    unsigned             need_tags:1;

    NGX_COMPAT_BEGIN(5)
    NGX_COMPAT_END
};


#define NGX_MAX_ERROR_STR   2048

/* used by 3rd-party modules */
#define NGX_HAVE_VARIADIC_MACROS  1

#define ngx_log_error(level, log, ...)                                        \
    if ((log)->log_level >= level)                                            \
        ngx_log_error_core(level, log, ngx_src_file(), __VA_ARGS__)

#define ngx_log_debug(level, log, ...)                                        \
    if ((log)->log_level & level)                                             \
        ngx_log_error_core(NGX_LOG_DEBUG, log, ngx_src_file(), __VA_ARGS__)


#if (NGX_DEBUG)

#define ngx_log_debug0(level, log, err, fmt)                                  \
        ngx_log_debug(level, log, err, fmt)

#define ngx_log_debug1(level, log, err, fmt, arg1)                            \
        ngx_log_debug(level, log, err, fmt, arg1)

#define ngx_log_debug2(level, log, err, fmt, arg1, arg2)                      \
        ngx_log_debug(level, log, err, fmt, arg1, arg2)

#define ngx_log_debug3(level, log, err, fmt, arg1, arg2, arg3)                \
        ngx_log_debug(level, log, err, fmt, arg1, arg2, arg3)

#define ngx_log_debug4(level, log, err, fmt, arg1, arg2, arg3, arg4)          \
        ngx_log_debug(level, log, err, fmt, arg1, arg2, arg3, arg4)

#define ngx_log_debug5(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5)    \
        ngx_log_debug(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5)

#define ngx_log_debug6(level, log, err, fmt,                                  \
                       arg1, arg2, arg3, arg4, arg5, arg6)                    \
        ngx_log_debug(level, log, err, fmt,                                   \
                       arg1, arg2, arg3, arg4, arg5, arg6)

#define ngx_log_debug7(level, log, err, fmt,                                  \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7)              \
        ngx_log_debug(level, log, err, fmt,                                   \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7)

#define ngx_log_debug8(level, log, err, fmt,                                  \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)        \
        ngx_log_debug(level, log, err, fmt,                                   \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)

#else /* !NGX_DEBUG */

#define ngx_log_debug0(level, log, err, fmt)
#define ngx_log_debug1(level, log, err, fmt, arg1)
#define ngx_log_debug2(level, log, err, fmt, arg1, arg2)
#define ngx_log_debug3(level, log, err, fmt, arg1, arg2, arg3)
#define ngx_log_debug4(level, log, err, fmt, arg1, arg2, arg3, arg4)
#define ngx_log_debug5(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5)
#define ngx_log_debug6(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5, arg6)
#define ngx_log_debug7(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5,    \
                       arg6, arg7)
#define ngx_log_debug8(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5,    \
                       arg6, arg7, arg8)

#endif

#define ngx_log_copy_log(dst, src)                                            \
    do {                                                                      \
        (dst)->file = (src)->file;                                            \
        (dst)->limit = (src)->limit;                                          \
        (dst)->next = (src)->next;                                            \
        (dst)->writer = (src)->writer;                                        \
        (dst)->wdata = (src)->wdata;                                          \
        (dst)->filter = (src)->filter;                                        \
        (dst)->conf = (src)->conf;                                            \
        (dst)->format = (src)->format;                                        \
        (dst)->need_tags = (src)->need_tags;                                  \
    } while (0)


void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, const char *filename,
    ngx_err_t err, const char *fmt, ...);
ngx_log_t *ngx_log_init(u_char *prefix, u_char *error_log, ngx_uint_t level);
void ngx_cdecl ngx_log_abort(ngx_err_t err, const char *fmt, ...);
void ngx_cdecl ngx_log_stderr(ngx_err_t err, const char *fmt, ...);
u_char *ngx_log_errno(u_char *buf, u_char *last, ngx_err_t err);
ngx_int_t ngx_log_open_default(ngx_cycle_t *cycle);
ngx_int_t ngx_log_redirect_stderr(ngx_cycle_t *cycle);
ngx_log_t *ngx_log_get_file_log(ngx_log_t *head);
ngx_int_t ngx_log_get_level(u_char *level);
char *ngx_log_set_log(ngx_conf_t *cf, ngx_log_t **head);
void ngx_log_add_tag(ngx_log_t *log, ngx_log_tag_t *ltag);
ngx_int_t ngx_log_add_user_tag(ngx_log_t *log, ngx_str_t *tag,
    ngx_pool_t *pool);

#define ngx_core_log_prop(id)                                                 \
    ((ngx_log_property_key_t)                                                 \
     { ngx_core_log_properties[NGX_CORE_LOG_PROP__##id].index })

#define ngx_core_log_tag(id)                                                  \
    ( &(ngx_core_log_properties[NGX_CORE_LOG_PROP__##id].tag) )

#define ngx_log_prop_decl(name, module, type)                                 \
    { 0, ngx_string(name), module, type,                                      \
      { ngx_string(name), NULL }                                              \
    }

ngx_int_t ngx_log_add_property(ngx_cycle_t *cycle, ngx_log_property_t *prop);
u_char *ngx_log_action(ngx_log_t *log, u_char *buf, u_char *last,
    const char *action);
u_char *ngx_log_property(ngx_log_t *log, u_char *buf, u_char *last,
    ngx_log_property_key_t key, const char *fmt, ...);
u_char *ngx_log_object(ngx_log_t *log, u_char *buf, u_char *last,
    ngx_log_property_key_t key, ngx_log_ext_handler_pt handler, void *data);
void ngx_show_log_filters_info(ngx_cycle_t *cycle);

/*
 * ngx_write_stderr() cannot be implemented as macro, since
 * MSVC does not allow to use #ifdef inside macro parameters.
 *
 * ngx_write_fd() is used instead of ngx_write_console(), since
 * CharToOemBuff() inside ngx_write_console() cannot be used with
 * read only buffer as destination and CharToOemBuff() is not needed
 * for ngx_write_stderr() anyway.
 */
static ngx_inline void
ngx_write_stderr(char *text)
{
    (void) ngx_write_fd(ngx_stderr, text, ngx_strlen(text));
}


static ngx_inline void
ngx_write_stdout(char *text)
{
    (void) ngx_write_fd(ngx_stdout, text, ngx_strlen(text));
}


static ngx_inline const char *
ngx_basename(const char *filename)
{
    const char  *base;

    base = ngx_strrchr(filename, '/');

    return base ? (base + 1) : filename;
}


extern ngx_module_t  ngx_errlog_module;
extern ngx_uint_t    ngx_use_stderr;
extern ngx_log_property_t  ngx_core_log_properties[];


#endif /* _NGX_LOG_H_INCLUDED_ */
