
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


#if (NGX_SSL)
#define NGX_HAS_SSL(x) x
#else
#define NGX_HAS_SSL(x)
#endif

#define NGX_CORE_LOG_PROP_LIST                                                \
    NGX_X(RESOLVER,                   "resolver"     , "resolver")            \
    NGX_X(SYSLOG_SERVER,              "syslog_server", "syslog server")       \
    NGX_X(LISTEN_ADDR,                "listen_addr",   "listen addr")         \
    NGX_HAS_SSL(NGX_X(OCSP_RESPONDER, "responder",     "responder"))          \
    NGX_HAS_SSL(NGX_X(OCSP_PEER,      "peer",          "peer"))               \
    NGX_HAS_SSL(NGX_X(OCSP_CERT,      "certificate",   "certificate"))


enum {
    #define NGX_X(id, key, name)  NGX_CORE_LOG_PROP__##id,
    NGX_CORE_LOG_PROP_LIST
    #undef NGX_X
};

typedef struct {
    ngx_uint_t           index;
    ngx_str_t            key;
    ngx_str_t            name;
    const char          *module;
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

    /* only meaningful during the call on the first log in list */
    ngx_uint_t           busy; /* unsigned busy:1; */

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
void ngx_log_add_str_tag(ngx_log_t *log, ngx_str_t *s);


#define ngx_core_log_prop(id)                                                 \
    ((ngx_log_property_key_t)                                                 \
     { ngx_core_log_properties[NGX_CORE_LOG_PROP__##id].index })

#define ngx_log_prop_decl(key, name, module)                                  \
    { 0, ngx_string(key), ngx_string(name), module}

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

#define ngx_log_add_tag(log, s)                                               \
    do {                                                                      \
        ngx_str_t  tmp;                                                       \
                                                                              \
        tmp.data = (u_char *) s;                                              \
        tmp.len = ngx_strlen(s);                                              \
        ngx_log_add_str_tag(log, &tmp);                                       \
    } while (0)


extern ngx_module_t  ngx_errlog_module;
extern ngx_uint_t    ngx_use_stderr;
extern ngx_log_property_t  ngx_core_log_properties[];


#endif /* _NGX_LOG_H_INCLUDED_ */
