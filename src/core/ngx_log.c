
/*
 * Copyright (C) 2024 Web Server LLC
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#if (NGX_PCRE)
#include <ngx_regex.h>
#endif


typedef enum {
    NGX_LOG_FILTER_MATCH_EXACT,
    NGX_LOG_FILTER_MATCH_SUBSTRING,
    NGX_LOG_FILTER_MATCH_REGEX
} ngx_log_filter_match_type_t;


typedef enum {
    NGX_LOG_FILTER_LOGLINE,
    NGX_LOG_FILTER_MESSAGE,
#if (NGX_DEBUG)
    NGX_LOG_FILTER_FILENAME,
#endif
    NGX_LOG_FILTER_TAG,
    NGX_LOG_FILTER_FIELD
} ngx_log_filter_part_t;


typedef struct {
    ngx_log_t                    *log;
    ngx_str_t                     name;
    ngx_uint_t                    line;
} ngx_log_ref_t;


struct ngx_log_conf_s {
    ngx_array_t                   props;
    ngx_array_t                   logs;
};


typedef struct {
    u_char                       *buf;
    u_char                       *last;
    ngx_uint_t                    level;
    ngx_err_t                     err;
    ngx_uint_t                    console;
    ngx_str_t                     line;
    ngx_str_t                     msg;
    const char                   *filename;
} ngx_log_params_t;


typedef struct {
    ngx_str_t                     pattern;
    ngx_str_t                     field;
    ngx_uint_t                    prop_idx;
    ngx_log_filter_part_t         part;
    ngx_log_filter_match_type_t   type;
#if (NGX_PCRE)
    ngx_regex_t                  *re;
#endif
    ngx_uint_t                    match; /* per-call state */
} ngx_log_filter_rule_t;


struct ngx_log_filter_s {
    ngx_array_t                   rules;  /* of ngx_log_filter_rule_t */
};


static u_char *ngx_log_create_message(ngx_log_t *log, ngx_log_params_t *lp,
    const char *fmt, va_list args);
static ngx_int_t ngx_log_check_rate(ngx_log_t *log, ngx_uint_t level);
static char *ngx_error_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_log_set_params(ngx_conf_t *cf, ngx_log_t *log);
static void ngx_log_insert(ngx_log_t *log, ngx_log_t *new_log);

static char *ngx_log_add_filter(ngx_conf_t *cf, ngx_log_t *log,
    ngx_str_t *value);
static char *ngx_log_filter_set_rule(ngx_conf_t *cf,
    ngx_log_filter_rule_t *rule, ngx_str_t *value);
static ngx_inline void ngx_log_filter_init(ngx_log_filter_t *filter);
static ngx_int_t ngx_log_filter_apply_rules(ngx_log_t *log,
    ngx_log_params_t *lp);

static ngx_int_t ngx_log_filter_rule_match(ngx_log_filter_rule_t *rule,
    ngx_str_t *str);
static u_char *ngx_log_match_substring(ngx_str_t *haystack, ngx_str_t *needle);
static ngx_int_t ngx_log_conf_add_property(ngx_log_conf_t *lcf, ngx_log_t *log,
    ngx_log_property_t *prop);

static void *ngx_log_create_conf(ngx_cycle_t *cycle);
static char *ngx_log_init_conf(ngx_cycle_t *cycle, void *conf);

#if (NGX_DEBUG)

static void ngx_log_memory_writer(ngx_log_t *log, ngx_uint_t level,
    u_char *buf, size_t len);
static void ngx_log_memory_cleanup(void *data);


typedef struct {
    u_char        *start;
    u_char        *end;
    u_char        *pos;
    ngx_atomic_t   written;
} ngx_log_memory_buf_t;

#endif


static ngx_command_t  ngx_errlog_commands[] = {

    { ngx_string("error_log"),
      NGX_MAIN_CONF|NGX_CONF_1MORE,
      ngx_error_log,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_errlog_module_ctx = {
    ngx_string("errlog"),
    ngx_log_create_conf,
    ngx_log_init_conf
};


ngx_module_t  ngx_errlog_module = {
    NGX_MODULE_V1,
    &ngx_errlog_module_ctx,                /* module context */
    ngx_errlog_commands,                   /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_log_t        ngx_log;
static ngx_open_file_t  ngx_log_file;
ngx_uint_t              ngx_use_stderr = 1;


static ngx_str_t err_levels[] = {
    ngx_null_string,
    ngx_string("emerg"),
    ngx_string("alert"),
    ngx_string("crit"),
    ngx_string("error"),
    ngx_string("warn"),
    ngx_string("notice"),
    ngx_string("info"),
    ngx_string("debug")
};

static const char *debug_levels[] = {
    "debug_core", "debug_alloc", "debug_mutex", "debug_event",
    "debug_http", "debug_mail", "debug_stream"
};


ngx_log_property_t  ngx_core_log_properties[] = {
    #define NGX_X(id, key, name)  ngx_log_prop_decl(key, name, "core"),
    NGX_CORE_LOG_PROP_LIST
    #undef NGX_X
};



static u_char *
ngx_log_create_message(ngx_log_t *log, ngx_log_params_t *lp,
    const char *fmt, va_list args)
{
    u_char  *p, *last;

    last = lp->last;

    if (lp->console) {
        p = ngx_cpymem(lp->buf, "angie:", sizeof("angie:") - 1);

    } else {
        p = ngx_cpymem(lp->buf, ngx_cached_err_log_time.data,
                       ngx_cached_err_log_time.len);
    }

    p = ngx_slprintf(p, last, " [%V] ", &err_levels[lp->level]);

    if (lp->console) {
        goto msg;
    }

    /* pid#tid */
    p = ngx_slprintf(p, last, "%P#" NGX_TID_T_FMT ": ",
                     ngx_log_pid, ngx_log_tid);

    if (log->connection) {
        p = ngx_slprintf(p, last, "*%uA ", log->connection);
    }

msg:

    lp->line.data = p;
    lp->msg.data = p;

    p = ngx_vslprintf(p, last, fmt, args);

    lp->msg.len = p - lp->msg.data;

    if (lp->err) {
        p = ngx_log_errno(p, last, lp->err);
    }

    if (lp->level != NGX_LOG_DEBUG && log->handler) {
        p = log->handler(log, p, last - p);
    }

    lp->line.len = p - lp->line.data;

    if (p > last - NGX_LINEFEED_SIZE) {
        p = last - NGX_LINEFEED_SIZE;
    }

    ngx_linefeed(p);

    return p;
}


static u_char *
ngx_log_match_substring(ngx_str_t *haystack, ngx_str_t *needle)
{
    u_char  c1, c2, *s1, *s2;
    size_t  n, len;

    s1 = haystack->data;
    len = haystack->len;

    c2 = needle->data[0];

    s2 = needle->data + 1;
    n = needle->len - 1;

    do {
        do {
            if (len-- == 0) {
                return NULL;
            }

            c1 = *s1++;

        } while (c1 != c2);

        if (n > len) {
            return NULL;
        }

    } while (ngx_strncmp(s1, (u_char *) s2, n) != 0);

    return --s1;
}


void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, const char *filename,
    ngx_err_t err, const char *fmt, ...)
{
    va_list            args;
    u_char            *p;
    ssize_t            n;
    ngx_log_t         *head;
    ngx_uint_t         wrote_stderr, debug_connection;
    u_char             errstr[NGX_MAX_ERROR_STR];
    ngx_log_params_t   lp;

    if (log->busy) {
        return;
    }

    log->busy = 1;

    lp.level = level;
    lp.buf = errstr;
    lp.last = errstr + NGX_MAX_ERROR_STR;
    lp.err = err;
    lp.console = 0;
    lp.line.len = 0;
    lp.msg.len = 0;
    lp.filename = filename;

    wrote_stderr = 0;
    debug_connection = (log->log_level & NGX_LOG_DEBUG_CONNECTION) != 0;

    head = log;

    while (log) {

        if (log->log_level < level && !debug_connection) {
            break;
        }

        log->handler = head->handler;
        log->data = head->data;
        log->connection = head->connection;
        log->action = head->action;

        if (log->filter) {
            ngx_log_filter_init(log->filter);
        }

        va_start(args, fmt);
        p = ngx_log_create_message(log, &lp, fmt, args);
        va_end(args);

        if (log->filter
            && ngx_log_filter_apply_rules(log, &lp) == NGX_DECLINED)
        {
            goto next;
        }

        if (log->limit && !debug_connection) {
            if (ngx_log_check_rate(log, level) == NGX_BUSY) {
                goto next;
            }
        }

        if (log->writer) {
            log->writer(log, level, errstr, p - errstr);
            goto next;
        }

        if (ngx_time() == log->file->disk_full_time) {

            /*
             * on FreeBSD writing to a full filesystem with enabled softupdates
             * may block process for much longer time than writing to non-full
             * filesystem, so we skip writing to a log for one second
             */

            goto next;
        }

        n = ngx_write_fd(log->file->fd, errstr, p - errstr);

        if (n == -1 && ngx_errno == NGX_ENOSPC) {
            log->file->disk_full_time = ngx_time();
        }

        if (log->file->fd == ngx_stderr) {
            wrote_stderr = 1;
        }

    next:

        log = log->next;
    }

    if (!ngx_use_stderr
        || level > NGX_LOG_WARN
        || wrote_stderr)
    {
        head->busy = 0;
        return;
    }

    lp.console = 1;

    va_start(args, fmt);
    p = ngx_log_create_message(head, &lp, fmt, args);
    va_end(args);

    (void) ngx_write_console(ngx_stderr, errstr, p - errstr);

    head->busy = 0;
}


void ngx_cdecl
ngx_log_abort(ngx_err_t err, const char *fmt, ...)
{
    u_char   *p;
    va_list   args;
    u_char    errstr[NGX_MAX_CONF_ERRSTR];

    va_start(args, fmt);
    p = ngx_vsnprintf(errstr, sizeof(errstr) - 1, fmt, args);
    va_end(args);

    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, err,
                  "%*s", p - errstr, errstr);
}


void ngx_cdecl
ngx_log_stderr(ngx_err_t err, const char *fmt, ...)
{
    u_char   *p, *last;
    va_list   args;
    u_char    errstr[NGX_MAX_ERROR_STR];

    last = errstr + NGX_MAX_ERROR_STR;

    p = ngx_cpymem(errstr, "angie: ", 7);

    va_start(args, fmt);
    p = ngx_vslprintf(p, last, fmt, args);
    va_end(args);

    if (err) {
        p = ngx_log_errno(p, last, err);
    }

    if (p > last - NGX_LINEFEED_SIZE) {
        p = last - NGX_LINEFEED_SIZE;
    }

    ngx_linefeed(p);

    (void) ngx_write_console(ngx_stderr, errstr, p - errstr);
}


u_char *
ngx_log_errno(u_char *buf, u_char *last, ngx_err_t err)
{
    if (buf > last - 50) {

        /* leave a space for an error code */

        buf = last - 50;
        *buf++ = '.';
        *buf++ = '.';
        *buf++ = '.';
    }

#if (NGX_WIN32)
    buf = ngx_slprintf(buf, last, ((unsigned) err < 0x80000000)
                                       ? " (%d: " : " (%Xd: ", err);
#else
    buf = ngx_slprintf(buf, last, " (%d: ", err);
#endif

    buf = ngx_strerror(err, buf, last - buf);

    if (buf < last) {
        *buf++ = ')';
    }

    return buf;
}


static ngx_int_t
ngx_log_check_rate(ngx_log_t *log, ngx_uint_t level)
{
    ngx_log_t          temp_log;
    ngx_int_t          excess, changed, burst;
    ngx_atomic_int_t   ms;
    ngx_atomic_uint_t  now, last;

    now = ngx_current_msec;

    last = log->limit->last;
    excess = log->limit->excess;

    ms = (ngx_atomic_int_t) (now - last);

    if (ms < -60000) {
        ms = 1;

    } else if (ms < 0) {
        ms = 0;
    }

    changed = excess - log->limit->rate * ms / 1000 + 1000;

    if (changed < 0) {
        changed = 0;
    }

    burst = (log->log_level - level + 1) * log->limit->rate;

    if (changed > burst) {
        if (excess <= burst) {

            ngx_atomic_fetch_add(&log->limit->excess, 1000);

            /* log message to this log only */

            temp_log = *log;
            temp_log.connection = 0;
            temp_log.handler = NULL;
            temp_log.limit = NULL;
            temp_log.next = NULL;

            ngx_log_error(level, &temp_log, 0,
                          "too many log messages, limiting");
        }

        return NGX_BUSY;
    }

    if (ms > 0
        && ngx_atomic_cmp_set(&log->limit->last, last, now))
    {
        ngx_atomic_fetch_add(&log->limit->excess, changed - excess);

    } else {
        ngx_atomic_fetch_add(&log->limit->excess, 1000);
    }

    return NGX_OK;
}


ngx_log_t *
ngx_log_init(u_char *prefix, u_char *error_log, ngx_uint_t level)
{
    u_char  *p, *name;
    size_t   nlen, plen;

    ngx_log.file = &ngx_log_file;
    ngx_log.log_level = level ? level : NGX_LOG_NOTICE;

    if (error_log == NULL) {
        error_log = (u_char *) NGX_ERROR_LOG_PATH;
    }

    name = error_log;
    nlen = ngx_strlen(name);

    if (nlen == 0) {
        ngx_log_file.fd = ngx_stderr;
        return &ngx_log;
    }

    p = NULL;

#if (NGX_WIN32)
    if (name[1] != ':') {
#else
    if (name[0] != '/') {
#endif

        if (prefix) {
            plen = ngx_strlen(prefix);

        } else {
#ifdef NGX_PREFIX
            prefix = (u_char *) NGX_PREFIX;
            plen = ngx_strlen(prefix);
#else
            plen = 0;
#endif
        }

        if (plen) {
            name = malloc(plen + nlen + 2);
            if (name == NULL) {
                return NULL;
            }

            p = ngx_cpymem(name, prefix, plen);

            if (!ngx_path_separator(*(p - 1))) {
                *p++ = '/';
            }

            ngx_cpystrn(p, error_log, nlen + 1);

            p = name;
        }
    }

    ngx_log_file.fd = ngx_open_file(name, NGX_FILE_APPEND,
                                    NGX_FILE_CREATE_OR_OPEN,
                                    NGX_FILE_DEFAULT_ACCESS);

    if (ngx_log_file.fd == NGX_INVALID_FILE) {
        ngx_log_stderr(ngx_errno,
                       "[alert] could not open error log file: "
                       ngx_open_file_n " \"%s\" failed", name);
#if (NGX_WIN32)
        ngx_event_log(ngx_errno,
                       "could not open error log file: "
                       ngx_open_file_n " \"%s\" failed", name);
#endif

        ngx_log_file.fd = ngx_stderr;
    }

    if (p) {
        ngx_free(p);
    }

    return &ngx_log;
}


ngx_int_t
ngx_log_open_default(ngx_cycle_t *cycle)
{
    ngx_log_t  *log;

    if (ngx_log_get_file_log(&cycle->new_log) != NULL) {
        return NGX_OK;
    }

    if (cycle->new_log.log_level != 0) {
        /* there are some error logs, but no files */

        log = ngx_pcalloc(cycle->pool, sizeof(ngx_log_t));
        if (log == NULL) {
            return NGX_ERROR;
        }

    } else {
        /* no error logs at all */
        log = &cycle->new_log;
    }

    log->log_level = NGX_LOG_ERR;

    log->file = ngx_conf_open_file(cycle, &cycle->error_log);
    if (log->file == NULL) {
        return NGX_ERROR;
    }

    if (log != &cycle->new_log) {
        ngx_log_insert(&cycle->new_log, log);
    }

    return NGX_OK;
}


ngx_int_t
ngx_log_redirect_stderr(ngx_cycle_t *cycle)
{
    ngx_fd_t  fd;

    if (cycle->log_use_stderr) {
        return NGX_OK;
    }

    /* file log always exists when we are called */
    fd = ngx_log_get_file_log(cycle->log)->file->fd;

    if (fd != ngx_stderr) {
        if (ngx_set_stderr(fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          ngx_set_stderr_n " failed");

            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


ngx_log_t *
ngx_log_get_file_log(ngx_log_t *head)
{
    ngx_log_t  *log;

    for (log = head; log; log = log->next) {
        if (log->file != NULL) {
            return log;
        }
    }

    return NULL;
}


ngx_int_t
ngx_log_get_level(u_char *level)
{
    ngx_uint_t  n;

    for (n = 1; n <= NGX_LOG_DEBUG; n++) {
        if (ngx_strcmp(level, err_levels[n].data) == 0) {
            return (n == NGX_LOG_DEBUG) ? NGX_LOG_DEBUG_ALL : n;
        }
    }

    return NGX_ERROR;
}


static char *
ngx_error_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_log_t  *dummy;

    dummy = &cf->cycle->new_log;

    return ngx_log_set_log(cf, &dummy);
}


char *
ngx_log_set_log(ngx_conf_t *cf, ngx_log_t **head)
{
    char               *rv;
    ngx_log_t          *new_log;
    ngx_str_t          *value, name;
    ngx_log_ref_t      *lref;
    ngx_log_conf_t     *lcf;
    ngx_syslog_peer_t  *peer;

    if (*head != NULL && (*head)->log_level == 0) {
        new_log = *head;

    } else {

        new_log = ngx_pcalloc(cf->pool, sizeof(ngx_log_t));
        if (new_log == NULL) {
            return NGX_CONF_ERROR;
        }

        if (*head == NULL) {
            *head = new_log;
        }
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "stderr") == 0) {
        ngx_str_null(&name);
        cf->cycle->log_use_stderr = 1;

        new_log->file = ngx_conf_open_file(cf->cycle, &name);
        if (new_log->file == NULL) {
            return NGX_CONF_ERROR;
        }

    } else if (ngx_strncmp(value[1].data, "memory:", 7) == 0) {

#if (NGX_DEBUG)
        size_t                 size, needed;
        ngx_pool_cleanup_t    *cln;
        ngx_log_memory_buf_t  *buf;

        value[1].len -= 7;
        value[1].data += 7;

        needed = sizeof("MEMLOG  :" NGX_LINEFEED)
                 + cf->conf_file->file.name.len
                 + NGX_SIZE_T_LEN
                 + NGX_INT_T_LEN
                 + NGX_MAX_ERROR_STR;

        size = ngx_parse_size(&value[1]);

        if (size == (size_t) NGX_ERROR || size < needed) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid buffer size \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

        buf = ngx_pcalloc(cf->pool, sizeof(ngx_log_memory_buf_t));
        if (buf == NULL) {
            return NGX_CONF_ERROR;
        }

        buf->start = ngx_pnalloc(cf->pool, size);
        if (buf->start == NULL) {
            return NGX_CONF_ERROR;
        }

        buf->end = buf->start + size;

        buf->pos = ngx_slprintf(buf->start, buf->end, "MEMLOG %uz %V:%ui%N",
                                size, &cf->conf_file->file.name,
                                cf->conf_file->line);

        ngx_memset(buf->pos, ' ', buf->end - buf->pos);

        cln = ngx_pool_cleanup_add(cf->pool, 0);
        if (cln == NULL) {
            return NGX_CONF_ERROR;
        }

        cln->data = new_log;
        cln->handler = ngx_log_memory_cleanup;

        new_log->writer = ngx_log_memory_writer;
        new_log->wdata = buf;

#else
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "Angie was built without debug support");
        return NGX_CONF_ERROR;
#endif

    } else if (ngx_strncmp(value[1].data, "syslog:", 7) == 0) {
        peer = ngx_pcalloc(cf->pool, sizeof(ngx_syslog_peer_t));
        if (peer == NULL) {
            return NGX_CONF_ERROR;
        }

        if (ngx_syslog_process_conf(cf, peer) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }

        new_log->writer = ngx_syslog_writer;
        new_log->wdata = peer;

    } else {
        new_log->file = ngx_conf_open_file(cf->cycle, &value[1]);
        if (new_log->file == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    rv = ngx_log_set_params(cf, new_log);

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (*head != new_log) {
        ngx_log_insert(*head, new_log);
    }

    lcf = (ngx_log_conf_t *) ngx_get_conf(cf->cycle->conf_ctx,
                                          ngx_errlog_module);

    lref = ngx_array_push(&lcf->logs);
    if (lref == NULL) {
        return NGX_CONF_ERROR;
    }

    new_log->conf = lcf;

    lref->log = new_log;
    lref->name = cf->conf_file->file.name;
    lref->line = cf->conf_file->line;

    return NGX_CONF_OK;
}


static char *
ngx_log_set_params(ngx_conf_t *cf, ngx_log_t *log)
{
    char        *rv;
    size_t       len;
    ngx_int_t    rate;
    ngx_uint_t   i, n, d, level_set;
    ngx_str_t   *value;

    value = cf->args->elts;

    level_set = 0;
    rate = 1000;

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "filter=", 7) == 0) {

            value[i].data += 7;
            value[i].len -= 7;

            rv = ngx_log_add_filter(cf, log, &value[i]);

            if (rv != NGX_CONF_OK) {
                return rv;
            }

            continue;
        }

        for (n = 1; n <= NGX_LOG_DEBUG; n++) {
            if (ngx_strcmp(value[i].data, err_levels[n].data) == 0) {

                if (log->log_level != 0) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "duplicate log level \"%V\"",
                                       &value[i]);
                    return NGX_CONF_ERROR;
                }

                log->log_level = n;
                level_set = 1;

                goto next;
            }
        }

        for (n = 0, d = NGX_LOG_DEBUG_FIRST; d <= NGX_LOG_DEBUG_LAST; d <<= 1) {
            if (ngx_strcmp(value[i].data, debug_levels[n++]) == 0) {
                if (log->log_level & ~NGX_LOG_DEBUG_ALL) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "invalid log level \"%V\"",
                                       &value[i]);
                    return NGX_CONF_ERROR;
                }

                log->log_level |= d;
                level_set = 1;

                goto next;
            }
        }

        if (ngx_strncmp(value[i].data, "rate=", 5) == 0) {

            len = value[i].len;

            if (ngx_strncmp(value[i].data + len - 3, "m/s", 3) == 0) {
                len -= 3;
            }

            rate = ngx_atoi(value[i].data + 5, len - 5);
            if (rate < 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid rate \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (log->log_level) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[i]);

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid log level \"%V\"", &value[i]);
        }

        return NGX_CONF_ERROR;

    next:

        continue;
    }

    if (log->log_level == NGX_LOG_DEBUG) {
        log->log_level = NGX_LOG_DEBUG_ALL;
    }

    if (!level_set) {
        log->log_level = NGX_LOG_ERR;
    }

    if (rate > 0
        && log->log_level < NGX_LOG_DEBUG)
    {
        log->limit = ngx_pcalloc(cf->pool, sizeof(ngx_log_limit_t));
        if (log->limit == NULL) {
            return NGX_CONF_ERROR;
        }

        log->limit->rate = rate * 1000;
    }

    return NGX_CONF_OK;
}


static void
ngx_log_insert(ngx_log_t *log, ngx_log_t *new_log)
{
    ngx_log_t  tmp;

    if (new_log->log_level > log->log_level) {

        /*
         * list head address is permanent, insert new log after
         * head and swap its contents with head
         */

        tmp = *log;
        *log = *new_log;
        *new_log = tmp;

        log->next = new_log;
        return;
    }

    while (log->next) {
        if (new_log->log_level > log->next->log_level) {
            new_log->next = log->next;
            log->next = new_log;
            return;
        }

        log = log->next;
    }

    log->next = new_log;
}


#if (NGX_DEBUG)

static void
ngx_log_memory_writer(ngx_log_t *log, ngx_uint_t level, u_char *buf,
    size_t len)
{
    u_char                *p;
    size_t                 avail, written;
    ngx_log_memory_buf_t  *mem;

    mem = log->wdata;

    if (mem == NULL) {
        return;
    }

    written = ngx_atomic_fetch_add(&mem->written, len);

    p = mem->pos + written % (mem->end - mem->pos);

    avail = mem->end - p;

    if (avail >= len) {
        ngx_memcpy(p, buf, len);

    } else {
        ngx_memcpy(p, buf, avail);
        ngx_memcpy(mem->pos, buf + avail, len - avail);
    }
}


static void
ngx_log_memory_cleanup(void *data)
{
    ngx_log_t *log = data;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, log, 0, "destroy memory log buffer");

    log->wdata = NULL;
}

#endif


u_char *
ngx_log_action(ngx_log_t *log, u_char *buf, u_char *last, const char *action)
{
    return ngx_slprintf(buf, last, " while %s", action);
}


static ngx_log_property_t ngx_log_default_property =
    ngx_log_prop_decl("unknown", "unknown", "unknown");

u_char *
ngx_log_property(ngx_log_t *log, u_char *buf, u_char *last,
    ngx_log_property_key_t pkey, const char *fmt, ...)
{
    u_char                 *p;
    va_list                 args;
    ngx_str_t               raw_field;
    ngx_uint_t              i;
    ngx_log_property_t     *prop, **props;
    ngx_log_filter_rule_t  *rules, *rule;

    if (log->conf) {
        props = log->conf->props.elts;
        prop = props[pkey.id];

    } else {
        /* very early or late logging */
        prop = &ngx_log_default_property;
    }

    if (log->filter) {
        u_char  tmp[NGX_MAX_ERROR_STR];

        rules = log->filter->rules.elts;

        for (i = 0; i < log->filter->rules.nelts; i++) {

            rule = &rules[i];

            if (rule->part != NGX_LOG_FILTER_FIELD) {
                continue;
            }

            if (prop->index != rule->prop_idx) {
                continue;
            }

            /* dump found field into temp buffer */
            va_start(args, fmt);
            p = ngx_vslprintf(tmp, tmp + NGX_MAX_ERROR_STR, fmt, args);
            va_end(args);

            raw_field.data = tmp;
            raw_field.len = p - tmp;

            if (ngx_log_filter_rule_match(rule, &raw_field) == NGX_OK) {
                rule->match = 1;
            }

            /* multiple rules on same field are not allowed */
            break;
        }
    }

    p = ngx_slprintf(buf, last, ", %V: \"", &prop->name);

    va_start(args, fmt);
    p = ngx_vslprintf(p, last, fmt, args);
    va_end(args);

    if (last - p < 1) {
        return p;
    }

    *p++ = '"';

    return p;
}


u_char *
ngx_log_object(ngx_log_t *log, u_char *buf, u_char *last,
    ngx_log_property_key_t key, ngx_log_ext_handler_pt handler, void *data)
{
    return handler(log, buf, last, data);
}


static char *
ngx_log_add_filter(ngx_conf_t *cf, ngx_log_t *log, ngx_str_t *value)
{
    u_char                 *p;
    ngx_log_filter_rule_t  *rule;

    if (log->filter == NULL) {
        log->filter = ngx_pcalloc(cf->pool, sizeof(ngx_log_filter_t));
        if (log->filter == NULL) {
            return NGX_CONF_ERROR;
        }

        if (ngx_array_init(&log->filter->rules, cf->pool, 4,
                           sizeof(ngx_log_filter_rule_t))
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    rule = ngx_array_push(&log->filter->rules);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }

    p = (u_char *) ngx_strchr(value->data, ':');

    if (p == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "missing filter type in \"%V\"", value);

        return NGX_CONF_ERROR;
    }

    if (ngx_strncmp(value->data, "logline:", 8) == 0) {

        rule->part = NGX_LOG_FILTER_LOGLINE;
        rule->pattern.len = value->len - 8;
        rule->pattern.data = value->data + 8;

    } else if (ngx_strncmp(value->data, "message:", 8) == 0) {

        rule->part = NGX_LOG_FILTER_MESSAGE;
        rule->pattern.len = value->len - 8;
        rule->pattern.data = value->data + 8;

    } else if (ngx_strncmp(value->data, "sourcefile:", 11) == 0) {

#if (NGX_DEBUG)
        rule->part = NGX_LOG_FILTER_FILENAME;
        rule->pattern.len = value->len - 11;
        rule->pattern.data = value->data + 11;
#else
        return "source file filtering requires debug build";
#endif

    } else if (ngx_strncmp(value->data, "tag:", 4) == 0) {

        rule->part = NGX_LOG_FILTER_TAG;
        rule->pattern.len = value->len - 4;
        rule->pattern.data = value->data + 4;

    } else {

        rule->field.len = p - value->data;
        rule->field.data = value->data;

        p++;

        rule->part = NGX_LOG_FILTER_FIELD;
        rule->pattern.data = p;
        rule->pattern.len = value->len - rule->field.len - 1;
    }

    return ngx_log_filter_set_rule(cf, rule, value);
}


static char *
ngx_log_filter_set_rule(ngx_conf_t *cf, ngx_log_filter_rule_t *rule,
    ngx_str_t *value)
{
    ngx_str_t            *pattern;
#if (NGX_PCRE)
    ngx_regex_compile_t   rc;
    u_char                errstr[NGX_MAX_CONF_ERRSTR];
#endif

    pattern = &rule->pattern;

    if (pattern->len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "empty filter pattern \"%V\"", value);
        return NGX_CONF_ERROR;
    }

    if (pattern->data[0] == '=') {
        rule->type = NGX_LOG_FILTER_MATCH_EXACT;

        pattern->len -= 1;
        pattern->data += 1;

        if (pattern->len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "empty filter pattern \"%V\"", value);
            return NGX_CONF_ERROR;
        }

    } else if (pattern->data[0] == '~') {

        pattern->len -= 1;
        pattern->data += 1;

        if (pattern->len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "empty filter pattern \"%V\"", value);
            return NGX_CONF_ERROR;
        }

#if (NGX_PCRE)

        rule->type = NGX_LOG_FILTER_MATCH_REGEX;

        ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

        rc.pattern = *pattern;
        rc.pool = cf->pool;
        rc.err.len = NGX_MAX_CONF_ERRSTR;
        rc.err.data = errstr;

        if (ngx_regex_compile(&rc) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc.err);
            return NGX_CONF_ERROR;
        }

        rule->re = rc.regex;

#else
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" requires PCRE library", value);

        return NGX_CONF_ERROR;
#endif

    } else {
        rule->type = NGX_LOG_FILTER_MATCH_SUBSTRING;
    }

    return NGX_CONF_OK;
}


static ngx_inline void
ngx_log_filter_init(ngx_log_filter_t *filter)
{
    ngx_uint_t              i;
    ngx_log_filter_rule_t  *rules;

    rules = filter->rules.elts;

    for (i = 0; i < filter->rules.nelts; i++) {
        rules[i].match = 0;
    }
}


static ngx_int_t
ngx_log_filter_apply_rules(ngx_log_t *log, ngx_log_params_t *lp)
{
    ngx_str_t               item;
    ngx_uint_t              i;
    ngx_log_filter_rule_t  *rules;

    rules = log->filter->rules.elts;

    for (i = 0; i < log->filter->rules.nelts; i++) {

        switch (rules[i].part) {

        case NGX_LOG_FILTER_LOGLINE:
            item = lp->line;

            if (ngx_log_filter_rule_match(&rules[i], &item) != NGX_OK) {
                return NGX_DECLINED;
            }

            continue;

#if (NGX_DEBUG)
        case NGX_LOG_FILTER_FILENAME:
            if (lp->filename == NULL) {
                continue;
            }

            item.data = (u_char *) lp->filename;
            item.len = ngx_strlen(lp->filename);

            if (ngx_log_filter_rule_match(&rules[i], &item) != NGX_OK) {
                return NGX_DECLINED;
            }

            continue;
#endif

        case NGX_LOG_FILTER_MESSAGE:
            item = lp->msg;

            if (ngx_log_filter_rule_match(&rules[i], &item) != NGX_OK) {
                return NGX_DECLINED;
            }

            continue;

        case NGX_LOG_FILTER_TAG:

            if (!rules[i].match) {
                return NGX_DECLINED;
            }

            continue;

        case NGX_LOG_FILTER_FIELD:

            if (!rules[i].match) {
                return NGX_DECLINED;
            }

            continue;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_log_filter_rule_match(ngx_log_filter_rule_t *rule, ngx_str_t *str)
{
    switch (rule->type) {
    case NGX_LOG_FILTER_MATCH_SUBSTRING:

        if (ngx_log_match_substring(str, &rule->pattern)) {
            return NGX_OK;
        }

        return NGX_DECLINED;

    case NGX_LOG_FILTER_MATCH_EXACT:

        if (rule->pattern.len != str->len) {
            return NGX_DECLINED;
        }

        if (ngx_strncmp(rule->pattern.data, str->data, str->len) == 0) {
            return NGX_OK;
        }

        return NGX_DECLINED;

#if (NGX_PCRE)
    case NGX_LOG_FILTER_MATCH_REGEX:

        if (ngx_regex_exec(rule->re, str, NULL, 0) >= 0) {
            return NGX_OK;
        }

        return NGX_DECLINED;
#endif

    default:
        return NGX_DECLINED;
    }
}


void
ngx_log_add_str_tag(ngx_log_t *log, ngx_str_t *tag)
{
    ngx_uint_t              i;
    ngx_log_filter_rule_t  *rules;

    if (log->filter == NULL) {
        return;
    }

    rules = log->filter->rules.elts;

    for (i = 0; i < log->filter->rules.nelts; i++) {

        if (rules[i].part != NGX_LOG_FILTER_TAG) {
            continue;
        }

        if (ngx_log_filter_rule_match(&rules[i], tag) == NGX_OK) {
            rules[i].match = 1;
        }
    }
}


static ngx_int_t
ngx_log_conf_add_property(ngx_log_conf_t *lcf, ngx_log_t *log,
    ngx_log_property_t *prop)
{
    ngx_uint_t            i;
    ngx_log_property_t  **props;

    props = lcf->props.elts;

    for (i = 0; i < lcf->props.nelts; i++) {
        if (props[i] == prop) {
            ngx_log_error(NGX_LOG_EMERG, log, 0,
                          "attempt to add duplicate log property: %V",
                          &prop->key);
            return NGX_ERROR;
        }
    }

    props = ngx_array_push(&lcf->props);
    if (props == NULL) {
        return NGX_ERROR;
    }

    *props = prop;

    prop->index = lcf->props.nelts - 1;

    return NGX_OK;
}


ngx_int_t
ngx_log_add_property(ngx_cycle_t *cycle, ngx_log_property_t *prop)
{
    ngx_log_conf_t  *lcf;

    lcf = (ngx_log_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_errlog_module);

    return ngx_log_conf_add_property(lcf, cycle->log, prop);
}


static void *
ngx_log_create_conf(ngx_cycle_t *cycle)
{
    ngx_log_conf_t  *lcf;

    lcf = ngx_pcalloc(cycle->pool, sizeof(ngx_log_conf_t));
    if (lcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&lcf->logs, cycle->pool, 4, sizeof(ngx_log_ref_t))
        != NGX_OK)
    {
        return NULL;
    }

    if (ngx_array_init(&lcf->props, cycle->pool, 4,
                       sizeof(ngx_log_property_t *))
        != NGX_OK)
    {
        return NULL;
    }

#define NGX_X(id, key, name)                                                  \
    if (ngx_log_conf_add_property(lcf, cycle->log,                            \
                           &ngx_core_log_properties[NGX_CORE_LOG_PROP__##id]) \
        != NGX_OK)                                                            \
    {                                                                         \
        return NULL;                                                          \
    }
    NGX_CORE_LOG_PROP_LIST
#undef NGX_X

    return lcf;
}


static char *
ngx_log_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_log_conf_t *lcf = conf;

    ngx_uint_t               i, j, k, found;
    ngx_str_t               *item, *key;
    ngx_log_ref_t           *lref;
    ngx_log_property_t    **props;
    ngx_log_filter_rule_t   *rules, *rule;

    lref = lcf->logs.elts;

    /* process all user-defined logs to check for invalid properties */
    for (i = 0; i < lcf->logs.nelts; i++) {

        if (lref[i].log->filter == NULL) {
            continue;
        }

        rules = lref[i].log->filter->rules.elts;

        /* each log might have multiple filters */
        for (j = 0; j < lref[i].log->filter->rules.nelts; j++) {
            rule = &rules[j];

            /* we only check those that reference properties */
            if (rule->part != NGX_LOG_FILTER_FIELD) {
                continue;
            }

            item = &rule->field;

            found = 0;
            props = lcf->props.elts;
            for (k = 0; k < lcf->props.nelts; k++) {

                key = &props[k]->key;

                if (key->len != item->len) {
                    continue;
                }

                if (ngx_strncmp(key->data, item->data, item->len) == 0) {
                    found = 1;
                    rule->prop_idx = props[k]->index;
                    break;
                }
            }

            if (!found) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                              "error_log directive at %V:%ui has filter "
                              "with unknown property \"%V\"", &lref[i].name,
                              lref[i].line, &rule->field);

                return NGX_CONF_ERROR;
            }
        }
    }

    return NGX_CONF_OK;
}


void
ngx_show_log_filters_info(ngx_cycle_t *cycle)
{
    ngx_uint_t            i;
    ngx_log_conf_t       *lcf;
    ngx_log_property_t  **props;

    lcf = (ngx_log_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_errlog_module);
    if (lcf == NULL) {
        return;
    }

    ngx_write_stderr("Supported log filters:\n");
    ngx_write_stderr("  logline\n");
    ngx_write_stderr("  message\n");
    ngx_write_stderr("  tag\n");
#if (NGX_DEBUG)
    ngx_write_stderr("  sourcefile (debug build)\n");
#endif

    props = lcf->props.elts;

    for (i = 0; i < lcf->props.nelts; i++) {
        ngx_write_stderr("  ");
        ngx_write_fd(ngx_stderr, props[i]->key.data, props[i]->key.len);
        ngx_write_fd(ngx_stderr, " (", 2);
        ngx_write_stderr((char *) props[i]->module);
        ngx_write_fd(ngx_stderr, " module)\n", 9);
    }
}
