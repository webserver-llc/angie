
/*
 * Copyright (C) 2024 Web Server LLC
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_fiber.h>


/* Some timeout constants */

/*
 * How long the ACME client will wait for the ACME server to complete
 * authorization (sec)
 */
#define NGX_ACME_AUTHORIZATION_TIMEOUT  60

/*
 * How long the ACME client will wait for the ACME server to complete
 * a challenge (sec)
 */
#define NGX_ACME_CHALLENGE_TIMEOUT      60

/*
 * How long the ACME client will wait for the ACME server to issue
 * a certificate (sec)
 */
#define NGX_ACME_ISSUANCE_TIMEOUT       60

#define NGX_ACME_MAX_SH_FILE            65535 /* USHRT_MAX */

#define ngx_http_acme_key_supported(type, bits) \
    ((type == NGX_KT_RSA && (bits >= 2048 && bits <= 8192 && !(bits & 7))) \
    || (type == NGX_KT_EC && (bits == 256 || bits == 384 || bits == 521)))

#define NGX_ACME_SLAB_SIZE      (ngx_pagesize / 2)
#define NGX_ACME_MAX_TIME       NGX_MAX_INT_T_VALUE

#define ngx_container_of(ptr, type, member) \
    ((type *) ((u_char *)(ptr) - offsetof(type, member)))

#define ngx_http_acme_get_core_loc_conf(amcf) \
    (amcf)->ctx->loc_conf[ngx_http_core_module.ctx_index]

#define ngx_http_acme_get_main_conf() \
    ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_acme_module)

#ifndef OPENSSL_IS_BORINGSSL
#define X509V3_EXT_conf_nid_f   X509V3_EXT_conf_nid
#define X509V3_EXT_conf_nid_n   "X509V3_EXT_conf_nid()"
#else
#define X509V3_EXT_conf_nid_f   X509V3_EXT_nconf_nid
#define X509V3_EXT_conf_nid_n   "X509V3_EXT_nconf_nid()"
#endif

#if (NGX_DEBUG)

/*
 * We don't want ..._debug0, ..._debug1, ..._debug2, etc stuff here.
 * Instead, we will have double parentheses, e.g. DBG_STATUS((...)).
 * We also want something shorter and something that would allow us
 * to grep the log in a more fine-grained manner,
 * e.g. grep -E 'acme status|acme http' error.log.
 */

#define DBG_STATUS(args)            ngx_log_acme_debug_status args
#define DBG_MEM(args)               ngx_log_acme_debug_mem args
#define DBG_HTTP(args)              ngx_log_acme_debug_http args

#else

#define DBG_STATUS(args)
#define DBG_MEM(args)
#define DBG_HTTP(args)

#endif

/* some shortcuts */
#define NGX_ACME_BEGIN(fiber)   NGX_FIBER_BEGIN(ses->fiber##_state)
#define NGX_ACME_END(fiber)     NGX_FIBER_END(ses->fiber##_state)
#define NGX_ACME_YIELD(fiber)   NGX_FIBER_YIELD(ses->fiber##_state, NGX_AGAIN)
#define NGX_ACME_WAIT_WHILE(fiber, cond)                                      \
    NGX_FIBER_WAIT_WHILE(ses->fiber##_state, cond, NGX_AGAIN)

#define NGX_ACME_TERMINATE(fiber, ret)                                        \
    do {                                                                      \
        ses->fiber##_state = (ngx_fiber_state_t) -1;                          \
        return ret;                                                           \
    } while (0)

#define NGX_ACME_SPAWN(parent, child, args, ret)                              \
    do {                                                                      \
        ngx_int_t __rc;                                                       \
        NGX_FIBER_INIT(ses->child##_state);                                   \
        NGX_FIBER_REMEMBER(ses->parent##_state);                              \
        __rc = ngx_http_acme_##child args ;                                   \
        if (__rc == NGX_AGAIN) {                                              \
            return __rc;                                                      \
        }                                                                     \
        ret = __rc;                                                           \
    } while (0)

#define NGX_ACME_DELAY(fiber, sec)                                            \
    do {                                                                      \
        ses->delay_expire = ngx_time() + sec;                                 \
        NGX_FIBER_REMEMBER(ses->fiber##_state);                               \
        if (ngx_time() < ses->delay_expire) {                                 \
            ngx_http_acme_main_conf_t *__amcf = ngx_http_acme_get_main_conf();\
            ngx_add_timer(&__amcf->timer_event, 10);                          \
            return NGX_AGAIN;                                                 \
        }                                                                     \
    } while (0)


typedef enum {
    NGX_KT_UNSUPPORTED,
    NGX_KT_RSA,
    NGX_KT_EC,
} ngx_keytype_t;


typedef struct {
    ngx_keytype_t               type;
    EVP_PKEY                   *key;
    int                         bits;
    ngx_file_t                  file;
    size_t                      file_size;
} ngx_acme_privkey_t;


typedef struct ngx_acme_client_s           ngx_acme_client_t;
typedef struct ngx_http_acme_main_conf_s   ngx_http_acme_main_conf_t;
typedef struct ngx_http_acme_srv_conf_s    ngx_http_acme_srv_conf_t;
typedef struct ngx_http_acme_session_s     ngx_http_acme_session_t;
typedef struct ngx_http_acme_sh_keyauth_s  ngx_http_acme_sh_keyauth_t;
typedef struct ngx_http_acme_sh_cert_s     ngx_http_acme_sh_cert_t;


struct ngx_acme_client_s {
    ngx_log_t                  *log;
    ngx_str_t                   name;
    ngx_str_t                   path;
    ngx_uint_t                  enabled;
    ngx_uint_t                  cf_line;
    ngx_str_t                   cf_filename;
    ngx_str_t                   server;
    ngx_url_t                   server_url;
    ngx_str_t                   email;
    ngx_array_t                *domains;
    time_t                      renew_before_expiry;
    time_t                      retry_after_error;
    time_t                      expiry_time;
    time_t                      renew_time;
    size_t                      max_cert_size;
    ngx_uint_t                  ssl;
    ngx_acme_privkey_t          account_key;
    ngx_acme_privkey_t          private_key;
    u_char                     *private_key_data;
    ngx_file_t                  certificate_file;
    size_t                      certificate_file_size;
    ngx_http_acme_session_t    *session;
    ngx_http_acme_sh_cert_t    *sh_cert;
};


struct ngx_http_acme_main_conf_s {
    ngx_http_conf_ctx_t        *ctx;
    ngx_acme_client_t          *current;
    ngx_shm_zone_t             *shm_zone;
    /* event ident must be after 3 pointers as in ngx_connection_t */
    ngx_int_t                   dummy;
    ngx_log_t                   log;
    ngx_http_log_ctx_t          log_ctx;
    ngx_array_t                 clients;
    ngx_event_t                 timer_event;
    size_t                      max_key_auth_size;
    ngx_http_acme_sh_keyauth_t *sh;
    ngx_str_t                   path;
    ngx_str_t                   acme_server_var;
};


struct ngx_http_acme_srv_conf_s {
    ngx_array_t                 clients;
};


struct ngx_http_acme_session_s {
    ngx_pool_t                 *pool;
    ngx_log_t                  *log;
    ngx_acme_client_t          *client;
    ngx_int_t                   request_result;
    ngx_str_t                   request_url;
    ngx_data_item_t            *dir;
    ngx_int_t                   status_code;
    ngx_str_t                   body;
    ngx_data_item_t            *json;
    ngx_str_t                   nonce;
    ngx_str_t                   content_type;
    ngx_str_t                   location;
    ngx_str_t                   kid;
    ngx_str_t                   order_url;
    ngx_data_item_t            *auths;
    ngx_data_item_t            *auth;
    ngx_str_t                   auth_url;
    ngx_str_t                   ident;
    ngx_str_t                   thumbprint;
    ngx_str_t                   challenge_url;
    ngx_str_t                   cert_url;
    ngx_str_t                   token;
    ngx_str_t                   key_auth;
    time_t                      delay_expire;
    time_t                      deadline;
    ngx_connection_t            connection;
    ngx_event_t                 read;
    ngx_event_t                 write;
    struct sockaddr             caddr;
    ngx_event_t                 run_event;
    /* fiber variables */
    ngx_fiber_state_t           send_request_state;
    ngx_fiber_state_t           get_state;
    ngx_fiber_state_t           post_state;
    ngx_fiber_state_t           run_state;
    ngx_fiber_state_t           bootstrap_state;
    ngx_fiber_state_t           account_ensure_state;
    ngx_fiber_state_t           cert_issue_state;
    ngx_fiber_state_t           authorize_state;
};


struct ngx_http_acme_sh_keyauth_s {
    ngx_atomic_t                key_auth_lock;
    u_short                     token_len;
    u_short                     key_auth_len;
    u_char                      data_start[1];
};


struct ngx_http_acme_sh_cert_s {
    ngx_atomic_t                lock;
    u_short                     len;
    u_char                      data_start[1];
};


struct ngx_http_acme_sh_key_s {
    u_short                     len;
    u_char                      data_start[1];
};


static u_char *ngx_http_acme_log_error(ngx_log_t *log, u_char *buf, size_t len);
#if (NGX_DEBUG)
static void ngx_log_acme_debug_core(ngx_log_t *log, const char *prefix,
    ngx_str_t *name, const char *fmt, va_list args);
#endif
static void *ngx_http_acme_alg(ngx_acme_privkey_t *key);
static void *ngx_http_acme_crv(ngx_acme_privkey_t *key);
static ngx_int_t ngx_http_acme_bn_encode(ngx_http_acme_session_t *ses,
    ngx_str_t *dst, const BIGNUM *bn, size_t padded_len);
static ngx_int_t ngx_http_acme_encoded_ec_params(ngx_http_acme_session_t *ses,
    ngx_acme_privkey_t *key, ngx_str_t *x, ngx_str_t *y);
static ngx_int_t ngx_http_acme_encoded_rsa_params(ngx_http_acme_session_t *ses,
    ngx_acme_privkey_t *key, ngx_str_t *mod, ngx_str_t *exp);
static ngx_int_t ngx_http_acme_ec_decode(ngx_http_acme_session_t *ses,
    size_t hash_size, ngx_str_t *sig);
static ngx_int_t ngx_http_acme_jwk(ngx_http_acme_session_t *ses,
    ngx_acme_privkey_t *key, ngx_str_t *jwk);
static ngx_int_t ngx_http_acme_protected_jwk(ngx_http_acme_session_t *ses,
    ngx_acme_privkey_t *key, ngx_str_t *url, ngx_str_t *nonce,
    ngx_str_t *protected_jwk);
static ngx_int_t ngx_http_acme_jws_encode(ngx_http_acme_session_t *ses,
    ngx_acme_privkey_t *key, ngx_str_t *protected, ngx_str_t *payload,
    ngx_str_t *jws);
static ngx_int_t ngx_http_acme_protected_header(ngx_http_acme_session_t *ses,
    ngx_acme_privkey_t *key, ngx_str_t *url, ngx_str_t *nonce,
    ngx_str_t *protected_header);
static ngx_int_t ngx_http_acme_extract_uri(ngx_str_t * url, ngx_str_t *uri);
static int ngx_http_extract_header(ngx_pool_t *pool, ngx_list_t *headers,
    char *name, ngx_str_t *value);
static ngx_msec_t ngx_http_acme_timer_interval(ngx_acme_client_t *cli);
static ngx_acme_client_t *ngx_http_acme_nearest_client(
    ngx_http_acme_main_conf_t  *amcf);
static ngx_http_acme_session_t *ngx_http_acme_create_session(
    ngx_acme_client_t *cli);
static void ngx_http_acme_destroy_session(ngx_http_acme_session_t **ses);
static ngx_int_t ngx_http_acme_postconfiguration(ngx_conf_t *cf);
static void ngx_http_acme_fds_close(void *data);
static ngx_int_t ngx_http_acme_header_filter(ngx_http_request_t *r);
static size_t ngx_http_acme_file_size(ngx_file_t *file);
static ngx_int_t ngx_http_acme_init_file(ngx_conf_t *cf, ngx_str_t *path,
    ngx_str_t *filename, ngx_file_t *file);
static ngx_int_t ngx_http_acme_shm_init(ngx_shm_zone_t *shm_zone, void *data);
static void *ngx_http_acme_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_acme_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_acme_create_srv_conf(ngx_conf_t *cf);

static ngx_int_t ngx_http_acme_init_worker(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_acme_file_load(ngx_log_t *log,
    ngx_file_t *open_file, u_char *buf, size_t size);
static ngx_int_t ngx_http_acme_key_init(ngx_conf_t *cf, ngx_acme_client_t *cli,
    ngx_str_t *filename, ngx_acme_privkey_t *key);
static ngx_int_t ngx_http_acme_key_gen(ngx_acme_client_t *cli,
    ngx_acme_privkey_t *key);
static ngx_int_t ngx_http_acme_key_load(ngx_acme_client_t *cli,
    ngx_acme_privkey_t *key);
static void ngx_http_acme_key_free(ngx_acme_privkey_t *key);
static ngx_int_t ngx_http_acme_load_keys(ngx_acme_client_t *cli);
static void ngx_http_acme_free_keys(ngx_acme_client_t *cli);
static ngx_int_t ngx_http_acme_csr_gen(ngx_http_acme_session_t *ses,
    ngx_acme_privkey_t *key, ngx_str_t *csr);
static ngx_int_t ngx_http_acme_identifiers(ngx_http_acme_session_t *ses,
    ngx_str_t *identifiers);
static ngx_int_t ngx_http_acme_jwk_thumbprint(ngx_http_acme_session_t *ses,
    ngx_acme_privkey_t *key, ngx_str_t *thumbprint);
static time_t ngx_http_acme_parse_ssl_time(const ASN1_TIME *asn1time,
    ngx_log_t *log);
static time_t ngx_http_acme_cert_validity(ngx_acme_client_t *cli);
static ngx_int_t ngx_http_acme_full_path(ngx_pool_t *pool, ngx_str_t *name,
    ngx_str_t *filename, ngx_str_t *full_path);
static ngx_int_t ngx_http_acme_init_connection(ngx_http_acme_session_t *ses);
static ngx_http_request_t *ngx_http_acme_init_request(
    ngx_http_acme_session_t *ses, ngx_uint_t method, ngx_str_t *url,
    ngx_str_t *body);
static ngx_int_t ngx_http_acme_add_header(ngx_http_request_t *r,
    char *name, char *value);
static void ngx_http_acme_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);
static ngx_int_t ngx_http_acme_send_request(ngx_http_acme_session_t *ses,
    ngx_uint_t method, ngx_str_t *url, ngx_str_t *body);
static ngx_int_t ngx_http_acme_get(ngx_http_acme_session_t *ses,
    ngx_str_t *url);
static ngx_int_t ngx_http_acme_post(ngx_http_acme_session_t *ses,
    ngx_str_t *url, ngx_str_t *payload);
static void ngx_http_acme_read_handler(ngx_event_t *rev);
static ngx_chain_t *ngx_http_acme_send_chain(ngx_connection_t *c,
    ngx_chain_t *in, off_t limit);
static void ngx_http_acme_connection_cleanup(ngx_connection_t *c);
static ngx_int_t ngx_http_acme_response_handler(ngx_http_acme_session_t *ses,
    ngx_http_request_t *r, ngx_int_t rc);
static int ngx_http_acme_server_error(ngx_http_acme_session_t *ses,
    const char *default_msg);
static void ngx_http_acme_timer_handler(ngx_event_t *ev);
static ngx_int_t ngx_acme_http_challenge_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_acme_run(ngx_http_acme_session_t *ses);
static ngx_int_t ngx_http_acme_bootstrap(ngx_http_acme_session_t *ses);
static ngx_int_t ngx_http_acme_account_ensure(ngx_http_acme_session_t *ses);
static ngx_int_t ngx_http_acme_cert_issue(ngx_http_acme_session_t *ses);
static ngx_int_t ngx_http_acme_authorize(ngx_http_acme_session_t *ses);
static ngx_int_t ngx_http_acme_get_shared_key_auth(ngx_http_request_t *r,
    ngx_str_t *token, ngx_str_t *key_auth);
static ngx_int_t ngx_http_acme_share_key_auth(ngx_http_acme_session_t *ses,
    ngx_str_t *key_auth, u_short token_len);
static char *ngx_http_acme_client(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_acme(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_acme_add_proxy_pass(ngx_conf_t *cf,
    ngx_http_acme_main_conf_t *amcf);
static ngx_int_t ngx_http_acme_create_conf_ctx(ngx_conf_t *cf,
    ngx_http_acme_main_conf_t *amcf);
static ngx_int_t ngx_http_acme_merge_conf_ctx(ngx_conf_t *cf,
    ngx_http_acme_main_conf_t *amcf);
static void ngx_http_acme_merge_conf_ctx_fix(ngx_conf_t *cf,
    ngx_module_t *module, ngx_http_conf_ctx_t *ctx);
static ngx_int_t ngx_http_acme_cert_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_acme_cert_key_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_acme_server_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_acme_client_t *ngx_acme_client_add(ngx_conf_t *cf, ngx_str_t *name);
static ngx_int_t ngx_http_acme_add_client_var(ngx_conf_t *cf,
    ngx_acme_client_t *cli, ngx_http_variable_t *var);
static ngx_data_item_t *ngx_data_object_find(ngx_data_item_t *obj,
    ngx_str_t *name);
static ngx_data_item_t *ngx_data_object_vget_value(ngx_data_item_t *obj,
    va_list args);
static ngx_data_item_t *ngx_data_object_get_value(ngx_data_item_t *obj, ...);
static ngx_int_t ngx_data_object_vget_str(ngx_data_item_t *obj, ngx_str_t *s,
    va_list args);
static ngx_int_t ngx_data_object_get_str(ngx_data_item_t *obj, ngx_str_t *s,
    ...);
static int ngx_data_object_str_eq(ngx_data_item_t *obj, char *value, ...);

static ngx_int_t ngx_str_eq(ngx_str_t *s1, const char *s2);
static ngx_int_t ngx_strcase_eq(ngx_str_t *s1, char *s2);
static ngx_int_t ngx_str_clone(ngx_pool_t *pool, ngx_str_t *dst,
    ngx_str_t *src);
static int ngx_str_is_ip(ngx_str_t *s);
static ngx_uint_t ngx_dec_count(ngx_int_t i);
static int ngx_clone_table_elt(ngx_pool_t *pool, ngx_str_t *dst,
    ngx_table_elt_t *src);


static ngx_command_t  ngx_http_acme_commands[] = {

    { ngx_string("acme_client_path"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_acme_main_conf_t, path),
      NULL },

    { ngx_string("acme_client"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_2MORE,
      ngx_http_acme_client,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("acme"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_acme,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_acme_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_acme_postconfiguration,       /* postconfiguration */

    ngx_http_acme_create_main_conf,        /* create main configuration */
    ngx_http_acme_init_main_conf,          /* init main configuration */

    ngx_http_acme_create_srv_conf,         /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_acme_module = {
    NGX_MODULE_V1,
    &ngx_http_acme_module_ctx,             /* module context */
    ngx_http_acme_commands,                /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_acme_init_worker,             /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t  ngx_http_acme_vars[] = {

    { ngx_string("acme_cert_"), NULL, ngx_http_acme_cert_variable,
      0, 0, 0 },

    { ngx_string("acme_cert_key_"), NULL, ngx_http_acme_cert_key_variable,
      0, 0, 0 },

    ngx_http_null_variable
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;


static u_char *
ngx_http_acme_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char  *p = buf;

    ngx_http_log_ctx_t         *ctx;
    ngx_http_acme_main_conf_t  *amcf;

    ctx = log->data;
    amcf = ngx_container_of(ctx, ngx_http_acme_main_conf_t, log_ctx);

    if (amcf->current != NULL) {
        p = ngx_snprintf(p, len, ", ACME client: %V", &amcf->current->name);
    }

    return p;
}


#if (NGX_DEBUG)

static void ngx_log_acme_debug_core(ngx_log_t *log, const char *prefix,
    ngx_str_t *name, const char *fmt, va_list args)
{
    static const ngx_str_t empty_name = ngx_string("");

    u_char  *p, *last;
    u_char   errstr[NGX_MAX_ERROR_STR];

    last = errstr + NGX_MAX_ERROR_STR - 1;

    /* "acme[ prefix][ name]: " */
    p = ngx_slprintf(errstr, last, "acme%s%s%s%V: ",
                      (prefix || name) ? " " : "",
                      prefix ? prefix : "",
                      (prefix && name) ? " " : "",
                      name ? name : &empty_name);

    p = ngx_vslprintf(p, last, fmt, args);

    *p = 0;

    ngx_log_error(NGX_LOG_DEBUG, log, 0, "%s", errstr);
}


static void
ngx_log_acme_debug_status(ngx_acme_client_t *cli, const char *fmt, ...)
{
    va_list     args;
    ngx_log_t  *log;

    log = cli->log;

    if (!(log->log_level & NGX_LOG_DEBUG_HTTP)) {
        return;
    }

    va_start(args, fmt);
    ngx_log_acme_debug_core(log, "status", &cli->name, fmt, args);
    va_end(args);
}


static void
ngx_log_acme_debug_mem(ngx_acme_client_t *cli, const char *fmt, ...)
{
    va_list     args;
    ngx_log_t  *log;

    log = cli->log;

    if (!(log->log_level & NGX_LOG_DEBUG_HTTP)) {
        return;
    }

    va_start(args, fmt);
    ngx_log_acme_debug_core(log, "mem", &cli->name, fmt, args);
    va_end(args);
}


static void
ngx_log_acme_debug_http(ngx_acme_client_t *cli, const char *fmt, ...)
{
    va_list     args;
    ngx_log_t  *log;

    log = cli->log;

    if (!(log->log_level & NGX_LOG_DEBUG_HTTP)) {
        return;
    }

    va_start(args, fmt);
    ngx_log_acme_debug_core(log, "http", &cli->name, fmt, args);
    va_end(args);
}

#endif


static ngx_int_t
ngx_http_acme_protected_header(ngx_http_acme_session_t *ses,
    ngx_acme_privkey_t *key, ngx_str_t *url, ngx_str_t *nonce,
    ngx_str_t *protected_header)
{
    u_char     *data, *alg;
    size_t      len;
    ngx_int_t   rc;

    if (ses->kid.len == 0) {
        return ngx_http_acme_protected_jwk(ses, key, url, nonce,
                                           protected_header);
    }

    rc = NGX_ERROR;
    alg = ngx_http_acme_alg(key);

    len = sizeof("{\"alg\":\"\",\"nonce\":\"\",\"url\":\"\",\"kid\":\"\"}") - 1;
    len += ngx_strlen(alg);
    len += nonce->len;
    len += url->len;
    len += ses->kid.len;

    data = ngx_pnalloc(ses->pool, len);
    if (data) {
        ngx_snprintf(data, len, "{\"alg\":\"%s\",\"nonce\":\"%V\",\"url\":\""
                     "%V\",\"kid\":\"%V\"}", alg, nonce, url, &ses->kid);
        protected_header->data = data;
        protected_header->len = len;
        rc = NGX_OK;
    }

    return rc;
}


static ngx_int_t
ngx_http_acme_protected_jwk(ngx_http_acme_session_t *ses,
    ngx_acme_privkey_t *key, ngx_str_t *url, ngx_str_t *nonce,
    ngx_str_t *protected_jwk)
{
    u_char     *data, *alg;
    size_t      len;
    ngx_str_t   jwk;
    ngx_int_t   rc;

    if (ngx_http_acme_jwk(ses, key, &jwk) != NGX_OK) {
        return NGX_ERROR;
    }

    rc = NGX_ERROR;
    alg = ngx_http_acme_alg(key);

    if (nonce) {
        len = sizeof("{\"alg\":\"\",\"nonce\":\"\",\"url\":\"\",\"jwk\":}") - 1;
        len += ngx_strlen(alg);
        len += nonce->len;
        len += url->len;
        len += jwk.len;

        data = ngx_pnalloc(ses->pool, len);
        if (data) {
            ngx_snprintf(data, len, "{\"alg\":\"%s\",\"nonce\":\"%V\",\"url\":"
                         "\"%V\",\"jwk\":%V}", alg, nonce, url, &jwk);
            protected_jwk->data = data;
            protected_jwk->len = len;
            rc = NGX_OK;
        }

    } else {
        len = sizeof("{\"alg\":\"\",\"url\":\"\",\"jwk\":}") - 1;
        len += ngx_strlen(alg);
        len += url->len;
        len += jwk.len;

        data = ngx_pnalloc(ses->pool, len);
        if (data) {
            ngx_snprintf(data, len, "{\"alg\":\"%s\","
                    "\"url\":\"%V\",\"jwk\":%V}", alg, url, &jwk);
            protected_jwk->data = data;
            protected_jwk->len = len;
            rc = NGX_OK;
        }

    }

    return rc;
}


static void *
ngx_http_acme_alg(ngx_acme_privkey_t *key)
{
    switch (key->type) {

    case NGX_KT_RSA:
        return "RS256";

    case NGX_KT_EC:
        switch(key->bits) {

        case 256:
            return "ES256";

        case 384:
            return "ES384";

        case 521:
            return "ES512";

        default:
            /* can't happen? */
            return "";
        }

    default:
        /* can't happen? */
        return "";
    }
}


static ngx_int_t
ngx_http_acme_jwk(ngx_http_acme_session_t *ses, ngx_acme_privkey_t *key,
    ngx_str_t *jwk)
{
    u_char     *data, *crv;
    size_t      len;
    ngx_str_t   s1, s2;
    ngx_int_t   rc;

    rc = NGX_ERROR;

    /*
     * The order in which members of a JWK appear in its JSON representation is
     * important. If the JWK is used for creating a JWK Thumbprint, its members
     * must be ordered lexicographically by the Unicode code points of the
     * member names as per RFC7638 sec 3.3.
     */

    if (key->type == NGX_KT_RSA) {
        if (ngx_http_acme_encoded_rsa_params(ses, key, &s1, &s2) != NGX_OK) {
            return NGX_ERROR;
        }

        len = sizeof("{\"e\":\"\",\"kty\":\"RSA\",\"n\":\"\"}") - 1;
        len += s1.len;
        len += s2.len;

        data = ngx_pnalloc(ses->pool, len);
        if (data) {
            ngx_snprintf(data, len,
                         "{\"e\":\"%V\",\"kty\":\"RSA\",\"n\":\"%V\"}",
                         &s2, &s1);
            jwk->data = data;
            jwk->len = len;
            rc = NGX_OK;
        }

    } else if (key->type == NGX_KT_EC) {
        if (ngx_http_acme_encoded_ec_params(ses, key, &s1, &s2) != NGX_OK) {
            return NGX_ERROR;
        }

        crv = ngx_http_acme_crv(key);

        len = sizeof("{\"crv\":\"\",\"kty\":\"EC\",\"x\":\"\",\"y\":\"\"}") - 1;
        len += s1.len;
        len += s2.len;
        len += ngx_strlen(crv);

        data = ngx_pnalloc(ses->pool, len);
        if (data) {
            ngx_snprintf(data, len, "{\"crv\":\"%s\",\"kty\":\"EC\",\"x\":"
                         "\"%V\",\"y\":\"%V\"}", crv, &s1, &s2);
            jwk->data = data;
            jwk->len = len;
            rc = NGX_OK;
        }
    }

    return rc;
}


static ngx_int_t
ngx_http_acme_encoded_ec_params(ngx_http_acme_session_t *ses,
    ngx_acme_privkey_t *key, ngx_str_t *x, ngx_str_t *y)
{
    BIGNUM          *bx, *by;
    ngx_int_t        rc;
    ngx_str_t        sx, sy;
    const EC_KEY    *ec;
    const EC_GROUP  *g;
    const EC_POINT  *pubkey;

    rc = NGX_ERROR;

    bx = BN_new();
    by = BN_new();

    if (!bx || !by) {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0, "BN_new() failed");
        goto failed;
    }

    ec = EVP_PKEY_get0_EC_KEY(key->key);
    if (!ec) {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0,
                      "EVP_PKEY_get0_EC_KEY() failed");
        goto failed;
    }

    g = EC_KEY_get0_group(ec);
    if (!g) {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0, "EC_KEY_get0_group() failed");
        goto failed;
    }

    pubkey = EC_KEY_get0_public_key(ec);
    if (!pubkey) {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0, "EC_KEY_get0_group() failed");
        goto failed;
    }

    if (!EC_POINT_get_affine_coordinates(g, pubkey, bx, by, NULL)) {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0,
                      "EC_POINT_get_affine_coordinates() failed");
        goto failed;
    }

    if (ngx_http_acme_bn_encode(ses, &sx, bx, (key->bits+7)/8) != NGX_OK) {
        goto failed;
    }

    if (ngx_http_acme_bn_encode(ses, &sy, by, (key->bits+7)/8) != NGX_OK) {
        goto failed;
    }

    *x = sx;
    *y = sy;
    rc = NGX_OK;

failed:

    if (bx) {
        BN_free(bx);
    }

    if (by) {
        BN_free(by);
    }

    return rc;
}


static void *
ngx_http_acme_crv(ngx_acme_privkey_t *key)
{
    if (key->type == NGX_KT_EC) {

        switch(key->bits) {

        case 256:
            return "P-256";

        case 384:
            return "P-384";

        case 521:
            return "P-521";
        }
    }

    /* can't happen? */
    return "";
}


static ngx_int_t
ngx_http_acme_encoded_rsa_params(ngx_http_acme_session_t *ses,
    ngx_acme_privkey_t *key, ngx_str_t *mod, ngx_str_t *exp)
{
    const RSA     *rsa;
    ngx_str_t      sm, se;
    const BIGNUM  *bm, *be;

    rsa = EVP_PKEY_get0_RSA(key->key);

    if (!rsa) {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0, "EVP_PKEY_get0_RSA() failed");
        return NGX_ERROR;
    }

    bm = NULL;
    be = NULL;

    RSA_get0_key(rsa, &bm, &be, NULL);

    if (ngx_http_acme_bn_encode(ses, &sm, bm, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_acme_bn_encode(ses, &se, be, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    *mod = sm;
    *exp = se;

    return NGX_OK;
}


static ngx_int_t
ngx_http_acme_bn_encode(ngx_http_acme_session_t *ses, ngx_str_t * dst,
    const BIGNUM *bn, size_t padded_len)
{
    u_char     *p, *bn_data, *padded_buf, *data;
    size_t      n;
    ngx_str_t   src;
    ngx_int_t   rc;

    rc = NGX_ERROR;
    padded_buf = NULL;

    n = BN_num_bytes(bn);

    bn_data = ngx_pcalloc(ses->pool, n);
    if (bn_data == NULL) {
        goto failed;
    }

    if ((size_t) BN_bn2bin(bn, bn_data) != n) {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0, "BN_bn2bin() failed");
        goto failed;
    }

    p = bn_data;

    while (n && !*p) {
        /*
         * Remove leading zero-valued octets as per RFC7518 sec 6.3.1.1.
         * Note, however, RFC7518 sec 6.2.1.2. In that case, we use padded_len,
         * so padding will take into account the necessary zero-valued octets.
         */
        p++;
        n--;
    }

    if (padded_len == 0) {
        padded_len = n;

    } else if (padded_len < n) {
        /* can't happen? */
        ngx_log_error(NGX_LOG_EMERG, ses->log, 0, "padded length too small");
        goto failed;

    } else if (padded_len > n) {
        padded_buf = ngx_pcalloc(ses->pool, padded_len);
        if (!padded_buf) {
            goto failed;
        }

        ngx_memcpy(padded_buf + padded_len - n, p, n);
        p = padded_buf;
    }

    data = ngx_pnalloc(ses->pool, ngx_base64_encoded_length(padded_len));
    if (!data) {
        goto failed;
    }

    src.data = p;
    src.len = padded_len;
    dst->data = data;

    ngx_encode_base64url(dst, &src);
    rc = NGX_OK;

failed:

    return rc;
}


static ngx_int_t
ngx_http_acme_jws_encode(ngx_http_acme_session_t *ses,
    ngx_acme_privkey_t *key, ngx_str_t *protected, ngx_str_t *payload,
    ngx_str_t *jws)
{
    u_char        *data;
    size_t         len, hash_size;
    ngx_int_t      rc;
    ngx_str_t      enc_protected, enc_payload, enc_combined, sig, enc_sig;
    EVP_MD_CTX    *emc;
    const EVP_MD  *hash_type;
    unsigned int   n;

    rc = NGX_ERROR;
    data = NULL;
    emc = NULL;
    enc_combined.data = NULL;
    sig.data = NULL;
    enc_sig.data = NULL;

    /*
     * enc_combined =
     *   BASE64URL(JWS Protected Header) '.' BASE64URL(JWS Payload)
     */

    len = ngx_base64_encoded_length(protected->len)
          + ngx_base64_encoded_length(payload->len)
          + 1; /* '.' */

    data = ngx_pnalloc(ses->pool, len);
    if (data == NULL) {
        return NGX_ERROR;
    }

    enc_combined.data = data;
    enc_protected.data = data;

    ngx_encode_base64url(&enc_protected, protected);

    enc_payload.data = enc_protected.data + enc_protected.len;
    *enc_payload.data++ = '.';

    ngx_encode_base64url(&enc_payload, payload);

    enc_combined.len = enc_protected.len + enc_payload.len + 1;

    /* create a signature */

    if (key->type == NGX_KT_RSA) {
        hash_size = 32;
        hash_type = EVP_sha256();

    } else if (key->type == NGX_KT_EC) {
        if (key->bits == 256) {
            hash_size = 32;
            hash_type = EVP_sha256();

        } else if (key->bits == 384) {
            hash_size = 48;
            hash_type = EVP_sha384();

        } else if (key->bits == 521) {
            hash_size = 66;
            hash_type = EVP_sha512();
        } else {
            /* can't happen? */
            goto failed;
        }
    } else {
        /* can't happen? */
        goto failed;
    }

    emc = EVP_MD_CTX_create();
    if (!emc) {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0, "EVP_MD_CTX_create() failed");
        goto failed;
    }

    sig.len = EVP_PKEY_size(key->key);

    sig.data = ngx_pcalloc(ses->pool, sig.len);
    if (!sig.data) {
        goto failed;
    }

    if (!EVP_SignInit_ex(emc, hash_type, NULL)) {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0, "EVP_SignInit_ex() failed");
        goto failed;
    }

    if (!EVP_SignUpdate(emc, enc_combined.data, enc_combined.len)) {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0, "EVP_SignUpdate() failed");
        goto failed;
    }

    if (!EVP_SignFinal(emc, sig.data, &n, key->key)) {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0, "EVP_SignFinal() failed");
        goto failed;
    }

    sig.len = n;

    if (key->type == NGX_KT_EC
        && ngx_http_acme_ec_decode(ses, hash_size, &sig) != NGX_OK)
    {
        goto failed;
    }

    /* encode the signature */

    enc_sig.len = ngx_base64_encoded_length(sig.len);

    enc_sig.data = ngx_pnalloc(ses->pool, enc_sig.len);
    if (!enc_sig.data) {
        goto failed;
    }

    ngx_encode_base64url(&enc_sig, &sig);

    /* create a JWS */

    len = sizeof("{\"protected\":\"\",\"payload\":\"\",\"signature\":\"\"}")
          - 1;
    len += enc_protected.len;
    len += enc_payload.len;
    len += enc_sig.len;

    data = ngx_pnalloc(ses->pool, len);
    if (!data) {
        goto failed;
    }

    ngx_snprintf(data, len, "{\"protected\":\"%V\",\"payload\":\"%V\","
                 "\"signature\":\"%V\"}", &enc_protected, &enc_payload,
                 &enc_sig);

    jws->data = data;
    jws->len = len;
    rc = NGX_OK;

#if 0
    DBG_HTTP((ses->conf, "enc_protected: \"%V\"", &enc_protected));
    DBG_HTTP((ses->conf, "enc_payload: \"%V\"", &enc_payload));
    DBG_HTTP((ses->conf, "enc_sig: \"%V\"", &enc_sig));
#endif

failed:

    if (emc) {
        EVP_MD_CTX_destroy(emc);
    }

    return rc;
}


static ngx_int_t
ngx_http_acme_ec_decode(ngx_http_acme_session_t *ses, size_t hash_size,
    ngx_str_t *sig)
{
    size_t         n;
    u_char        *new_sig, *p;
    ngx_int_t      rc;
    ECDSA_SIG     *s;
    const u_char  *tmp;
    const BIGNUM  *br, *bs;

    rc = NGX_ERROR;
    new_sig = NULL;
    p = NULL;
    tmp = sig->data;

    s = d2i_ECDSA_SIG(NULL, &tmp, sig->len);

    if (!s) {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0, "d2i_ECDSA_SIG() failed");
        return NGX_ERROR;
    }

    br = NULL;
    bs = NULL;

    ECDSA_SIG_get0(s, &br, &bs);

    new_sig = ngx_pcalloc(ses->pool, hash_size * 2);
    if (!new_sig) {
        goto failed;
    }

    n = BN_num_bytes(br);
    p = ngx_pcalloc(ses->pool, n);

    if (!p) {
        goto failed;
    }

    if ((size_t) BN_bn2bin(br, p) != n) {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0, "BN_bn2bin() failed");
        goto failed;
    }

    if (n >= hash_size) {
        ngx_memcpy(new_sig, p + n - hash_size, hash_size);
    } else {
        ngx_memcpy(new_sig + hash_size - n, p, n);
    }

    n = BN_num_bytes(bs);
    p = ngx_pcalloc(ses->pool, n);

    if (!p) {
        goto failed;
    }

    if ((size_t) BN_bn2bin(bs, p) != n) {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0, "BN_bn2bin() failed");
        goto failed;
    }

    if (n >= hash_size) {
        ngx_memcpy(new_sig + hash_size, p + n - hash_size, hash_size);
    } else {
        ngx_memcpy(new_sig + hash_size * 2 - n, p, n);
    }

    sig->data = new_sig;
    sig->len = hash_size * 2;
    rc = NGX_OK;

failed:

    if (s) {
        ECDSA_SIG_free(s);
    }

    return rc;
}


static ngx_int_t
ngx_http_acme_file_load(ngx_log_t *log, ngx_file_t *file, u_char *buf,
    size_t size)
{
    ssize_t  n;

    n = ngx_read_file(file, buf, size, 0);

    if ((size_t) n != size) {
        ngx_log_error(NGX_LOG_EMERG, file->log, 0,
                      ngx_read_file_n " \"%s\" returned only %z bytes instead "
                      "of %uz", file->name.data, n, size);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_acme_key_init(ngx_conf_t *cf, ngx_acme_client_t *cli,
    ngx_str_t *filename, ngx_acme_privkey_t *key)
{
    ngx_file_t       *file;
    ngx_uint_t        retry;
    ngx_file_info_t   fi;

    file = &key->file;

    if (ngx_http_acme_init_file(cf, &cli->path, filename, file) != NGX_OK) {
        return NGX_ERROR;
    }

    if (file->fd == NGX_INVALID_FILE) {
        file->fd = ngx_open_file(file->name.data, NGX_FILE_RDWR,
                                NGX_FILE_CREATE_OR_OPEN,
                                NGX_FILE_OWNER_ACCESS);

        if (file->fd == NGX_INVALID_FILE) {
            return NGX_ERROR;
        }
    }

    for (retry = 1; /* void */ ; retry--) {

        if (ngx_fd_info(file->fd, &fi) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, cli->log, ngx_errno,
                          ngx_fd_info_n " \"%s\" failed", file->name.data);

            return NGX_ERROR;
        }

        key->file_size = ngx_file_size(&fi);

        if (key->file_size != 0) {
            return NGX_OK;
        }

        if (retry && ngx_http_acme_key_gen(cli, key) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    ngx_log_error(NGX_LOG_ALERT, cli->log, 0, "zero size of key file \"%s\"",
                  file->name.data);

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_acme_key_load(ngx_acme_client_t *cli, ngx_acme_privkey_t *key)
{
    BIO             *bio;
    int              kt, nid, t, bits;
    EVP_PKEY        *k;
    ngx_int_t        rc;
    const EC_KEY    *ec;
    const EC_GROUP  *g;

    if (lseek(key->file.fd, 0, SEEK_SET) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cli->log, ngx_errno,
                      "lseek(\"%V\") failed", &key->file.name);
        return NGX_ERROR;
    }

    bio = BIO_new_fd(key->file.fd, BIO_NOCLOSE);

    if (bio == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, cli->log, 0,
                      "BIO_new_fd(\"%V\") failed", &key->file.name);

        return NGX_ERROR;
    }

    rc = NGX_ERROR;

    /* silence false alarms in some compilers (e.g. clang 16.0.6) */
    t = NGX_KT_UNSUPPORTED;
    bits = 0;

    k = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);

    if (k == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, cli->log, 0,
                      "PEM_read_bio_PrivateKey() failed");

    } else {
        kt = EVP_PKEY_base_id(k);

        if (kt == EVP_PKEY_RSA) {
            t = NGX_KT_RSA;

            bits = EVP_PKEY_bits(k);

            if (bits >= 2048 && bits <= 8192 && !(bits & 7)) {
                rc = NGX_OK;
            }

        } else if (kt == EVP_PKEY_EC) {
            t = NGX_KT_EC;

            ec = EVP_PKEY_get0_EC_KEY(k);

            if (ec != NULL) {
                g = EC_KEY_get0_group(ec);

                if (g != NULL) {
                    rc = NGX_OK;

                    nid = EC_GROUP_get_curve_name(g);

                    if (nid == NID_X9_62_prime256v1) {
                        bits = 256;

                    } else if (nid == NID_secp384r1) {
                        bits = 384;

                    } else if (nid == NID_secp521r1) {
                        bits = 521;

                    } else {
                        rc = NGX_ERROR;
                    }
                }
            }
        }

        if (rc == NGX_OK) {
            key->type = t;
            key->key = k;
            key->bits = bits;

            DBG_STATUS((cli, "key loaded \"%V\"", &key->file.name));

        } else {
            ngx_log_error(NGX_LOG_ALERT, cli->log, 0,
                          "unsupported key in file \"%V\"", &key->file.name);
            EVP_PKEY_free(k);
        }
    }

    BIO_free(bio);

    return rc;
}


static ngx_int_t
ngx_http_acme_key_gen(ngx_acme_client_t *cli, ngx_acme_privkey_t *key)
{
    int            n;
    BIO           *bio;
    EVP_PKEY      *k;
    ngx_int_t      rc;
    EVP_PKEY_CTX  *epc;

    if (key->type == NGX_KT_RSA) {
        n = EVP_PKEY_RSA;

    } else if (key->type == NGX_KT_EC) {
        n = EVP_PKEY_EC;

    } else {
        ngx_ssl_error(NGX_LOG_ALERT, cli->log, 0, "acme: unsupported key type");
        return NGX_ERROR;
    }

    epc = EVP_PKEY_CTX_new_id(n, NULL);

    if (!epc) {
        ngx_ssl_error(NGX_LOG_ALERT, cli->log, 0,
                      "EVP_PKEY_CTX_new_id() failed");
        return NGX_ERROR;
    }

    rc = NGX_ERROR;
    bio = NULL;
    k = NULL;

    if (!EVP_PKEY_keygen_init(epc)) {
        ngx_ssl_error(NGX_LOG_ALERT, cli->log, 0,
                      "EVP_PKEY_keygen_init() failed");
        goto failed;
    }

    if (key->type == NGX_KT_RSA) {
        if (!EVP_PKEY_CTX_set_rsa_keygen_bits(epc, key->bits)) {
            ngx_ssl_error(NGX_LOG_ALERT, cli->log, 0,
                          "EVP_PKEY_CTX_set_rsa_keygen_bits() failed");
            goto failed;
        }

    } else { /* key->type == NGX_KT_EC */
        if (key->bits == 256) {
            n = NID_X9_62_prime256v1;

        } else if (key->bits == 384) {
            n = NID_secp384r1;

        } else if (key->bits == 521) {
            n = NID_secp521r1;

        } else {
            ngx_ssl_error(NGX_LOG_ALERT, cli->log, 0,
                          "acme: unsupported key size");
            goto failed;
        }

        if (!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(epc, n)) {
            ngx_ssl_error(NGX_LOG_ALERT, cli->log, 0,
                          "EVP_PKEY_CTX_set_ec_paramgen_curve_nid");
            goto failed;
        }
    }

    if (!EVP_PKEY_keygen(epc, &k)) {
        ngx_ssl_error(NGX_LOG_ALERT, cli->log, 0, "EVP_PKEY_keygen() failed");
        goto failed;
    }

    bio = BIO_new_fd(key->file.fd, BIO_NOCLOSE);

    if (bio == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, cli->log, 0,
                      "BIO_new_fd(\"%V\") failed", &key->file.name);

        goto failed;
    }

    if (!PEM_write_bio_PrivateKey(bio, k, NULL, NULL, 0, NULL, NULL)) {
        ngx_ssl_error(NGX_LOG_ALERT, cli->log, 0,
                      "PEM_write_bio_PrivateKey() failed");
        goto failed;
    }

    rc = NGX_OK;

    DBG_STATUS((cli, "key generated \"%V\"", &key->file.name));

failed:

    if (bio) {
        BIO_free(bio);
    }

    if (k) {
        EVP_PKEY_free(k);
    }

    if (epc) {
        EVP_PKEY_CTX_free(epc);
    }

    return rc;
}


static void
ngx_http_acme_key_free(ngx_acme_privkey_t *key)
{
    EVP_PKEY_free(key->key);
    key->key = NULL;
}


static ngx_int_t
ngx_http_acme_load_keys(ngx_acme_client_t *cli)
{
    if (ngx_http_acme_key_load(cli, &cli->account_key) != NGX_OK
        || ngx_http_acme_key_load(cli, &cli->private_key) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_http_acme_free_keys(ngx_acme_client_t *cli)
{
    ngx_http_acme_key_free(&cli->private_key);
    ngx_http_acme_key_free(&cli->account_key);
}


static ngx_int_t
ngx_http_acme_csr_gen(ngx_http_acme_session_t *ses, ngx_acme_privkey_t *key,
    ngx_str_t *csr)
{
    int                        csr_size;
    size_t                     len;
    u_char                    *p, *end, *san, *csr_data;
    X509_REQ                  *crq;
    X509_NAME                 *name;
    ngx_int_t                  rc;
    ngx_str_t                  s;
    ngx_uint_t                 i;
    const char                *key_usage;
    ngx_array_t               *domains;
    const EVP_MD              *hash_type;
    X509_EXTENSION            *ext;
    STACK_OF(X509_EXTENSION)  *exts;

    rc = NGX_ERROR;

    if (key->type == NGX_KT_RSA) {
        key_usage = "critical, digitalSignature, keyEncipherment";
        hash_type = EVP_sha256();

    } else if (key->type == NGX_KT_EC) {
        key_usage = "critical, digitalSignature";

        if (key->bits == 256) {
            hash_type = EVP_sha256();

        } else if (key->bits == 384) {
            hash_type = EVP_sha384();

        } else if (key->bits == 521) {
            hash_type = EVP_sha512();

        } else {
            /* can't happen? */
            return NGX_ERROR;
        }

    } else {
        /* can't happen? */
        return NGX_ERROR;
    }

    crq = X509_REQ_new();
    if (!crq) {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0, "X509_REQ_new() failed");
        return NGX_ERROR;
    }

    exts = NULL;

    name = X509_NAME_new();
    if (!name) {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0, "X509_NAME_new() failed");
        goto failed;
    }

    if (!X509_REQ_set_pubkey(crq, key->key)) {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0, "X509_REQ_set_pubkey() failed");
        goto failed;
    }

    domains = ses->client->domains;
    s = ((ngx_str_t*) domains->elts)[0];

    if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, s.data, s.len,
                                    -1, 0))
    {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0,
                      "X509_NAME_add_entry_by_txt() failed");
        goto failed;
    }

    if (!X509_REQ_set_subject_name(crq, name)) {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0,
                      "X509_REQ_set_subject_name() failed");
        goto failed;
    }

    len = domains->nelts; /* separating commas + terminating null */

    for (i = 0; i < domains->nelts; i++) {
        s = ((ngx_str_t*) domains->elts)[i];
        len += sizeof("DNS:") - 1 + s.len;
    }

    san = ngx_pnalloc(ses->pool, len);
    if (!san) {
        goto failed;
    }

    p = san;
    end = san + len;

    for (i = 0; i < domains->nelts; i++) {
        s = ((ngx_str_t*) domains->elts)[i];
        p = ngx_slprintf(p, end, "%sDNS:%V", i ? "," : "", &s);
    }

    *p = 0;

    exts = sk_X509_EXTENSION_new_null();
    if (!exts) {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0,
                      "sk_X509_EXTENSION_new_null() failed");
        goto failed;
    }

    ext = X509V3_EXT_conf_nid_f(NULL, NULL, NID_subject_alt_name, (char *) san);
    if (!ext) {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0,
                      X509V3_EXT_conf_nid_n " failed");
        goto failed;
    }

    sk_X509_EXTENSION_push(exts, ext);

    ext = X509V3_EXT_conf_nid_f(NULL, NULL, NID_key_usage, key_usage);
    if (!ext) {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0,
                      X509V3_EXT_conf_nid_n " failed");
        goto failed;
    }

    sk_X509_EXTENSION_push(exts, ext);

    if (!X509_REQ_add_extensions(crq, exts)) {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0,
                      "X509_REQ_add_extensions() failed");
        goto failed;
    }

    if (!X509_REQ_sign(crq, key->key, hash_type)) {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0, "X509_REQ_sign() failed");
        goto failed;
    }

    csr_size = i2d_X509_REQ(crq, NULL);

    if (csr_size < 0) {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0, "i2d_X509_REQ() failed");
        goto failed;
    }

    csr_data = ngx_pnalloc(ses->pool, csr_size);
    if (!csr_data) {
        goto failed;
    }

    p = csr_data;

    if (i2d_X509_REQ(crq, &p) != csr_size) {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0, "i2d_X509_REQ() failed");
        goto failed;
    }

    p = ngx_pnalloc(ses->pool, ngx_base64_encoded_length(csr_size));
    if (!p) {
        goto failed;
    }

    csr->data = p;
    s.data = csr_data;
    s.len = csr_size;

    ngx_encode_base64url(csr, &s);

    rc = NGX_OK;

failed:

    if (name) {
        X509_NAME_free(name);
    }

    if (crq) {
        X509_REQ_free(crq);
    }

    if (exts) {
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    }

    return rc;
}


static ngx_int_t
ngx_http_acme_identifiers(ngx_http_acme_session_t *ses, ngx_str_t *identifiers)
{
    size_t        len;
    u_char       *p, *end;
    ngx_str_t     s;
    ngx_uint_t    i;
    ngx_array_t  *domains;

    domains = ses->client->domains;
    len = sizeof("{\"identifiers\":[]}") - 1
          + domains->nelts - 1; /* separating commas */

    for (i = 0; i < domains->nelts; i++) {
        s = ((ngx_str_t*) domains->elts)[i];
        len += sizeof("{\"type\":\"dns\",\"value\":\"\"}") - 1 + s.len;
    }

    identifiers->data = ngx_pnalloc(ses->pool, len);
    if (!identifiers->data) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(identifiers->data, "{\"identifiers\":[",
                   sizeof("{\"identifiers\":[") - 1);

    end = identifiers->data + len;

    for (i = 0; i < domains->nelts; i++) {
        s = ((ngx_str_t*) domains->elts)[i];
        p = ngx_slprintf(p, end, "%s{\"type\":\"dns\",\"value\":\"%V\"}",
                         i ? "," : "", &s);
    }

    p = ngx_cpymem(p, "]}", sizeof("]}") - 1);

    identifiers->len = p - identifiers->data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_acme_jwk_thumbprint(ngx_http_acme_session_t *ses,
    ngx_acme_privkey_t *key, ngx_str_t *thumbprint)
{
    u_char       hash[EVP_MAX_MD_SIZE], *p;
    unsigned     size;
    ngx_str_t    jwk, s;
    ngx_int_t    rc;
    EVP_MD_CTX  *emc;

    if (ngx_http_acme_jwk(ses, key, &jwk) != NGX_OK) {
        return NGX_ERROR;
    }

    emc = EVP_MD_CTX_create();
    if (!emc) {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0, "EVP_MD_CTX_create() failed");
        return NGX_ERROR;
    }

    rc = NGX_ERROR;

    if (!EVP_DigestInit_ex(emc, EVP_sha256(), NULL)) {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0, "EVP_DigestInit_ex() failed");
        goto failed;
    }

    if (!EVP_DigestUpdate(emc, jwk.data, jwk.len)) {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0, "EVP_DigestUpdate() failed");
        goto failed;
    }

    if (!EVP_DigestFinal_ex(emc, hash, &size)) {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0, "EVP_DigestFinal_ex() failed");
        goto failed;
    }

    p = ngx_pnalloc(ses->pool, ngx_base64_encoded_length(size));
    if (!p) {
        goto failed;
    }

    thumbprint->data = p;
    s.data = hash;
    s.len = size;

    ngx_encode_base64url(thumbprint, &s);

    rc = NGX_OK;

failed:

    if (emc) {
        EVP_MD_CTX_destroy(emc);
    }

    return rc;
}


static time_t
ngx_http_acme_parse_ssl_time(const ASN1_TIME *asn1time, ngx_log_t *log)
{
    /*
     * TODO This is a slightly modified version of the function
     * ngx_ssl_parse_time defined statically in ngx_event_openssl.c.
     * Should we make it global?
     */
    BIO     *bio;
    char    *value;
    size_t   len;
    time_t   time;

    /*
     * Some OpenSSL versions don't provide a way to convert ASN1_TIME
     * into time_t.  To do this portably, we use ASN1_TIME_print(),
     * which uses the "MMM DD HH:MM:SS YYYY [GMT]" format (e.g.,
     * "Feb  3 00:55:52 2015 GMT"), and parse the result.
     */

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, log, 0, "BIO_new() failed");
        return NGX_ERROR;
    }

    /* fake weekday prepended to match C asctime() format */

    BIO_write(bio, "Tue ", sizeof("Tue ") - 1);

#if OPENSSL_VERSION_NUMBER > 0x10100000L
    ASN1_TIME_print(bio, asn1time);
#else
    ASN1_TIME_print(bio, (ASN1_TIME *) asn1time);
#endif

    len = BIO_get_mem_data(bio, &value);

    time = ngx_parse_http_time((u_char *) value, len);

    BIO_free(bio);

    return time;
}


/*
 * Return values:
 * + expiry time of the certificate if the certificate is valid;
 * + NGX_DECLINED if the certificate is invalid (e.g. expired);
 * + NGX_ERROR if an OpenSSL or system error occurred.
 */
static time_t
ngx_http_acme_cert_validity(ngx_acme_client_t *cli)
{
    int               type, i, found;
#ifndef OPENSSL_IS_BORINGSSL
    int               j;
#else
    size_t            j;
#endif
    BIO              *bio;
    X509             *x509;
    u_char           *s;
    time_t            rc;
    ngx_uint_t        di;
    ngx_str_t         domain;
    X509_NAME        *subj_name;
    ASN1_STRING      *value;
    GENERAL_NAME     *name;
    GENERAL_NAMES    *sans;
    const ASN1_TIME  *t;
    X509_NAME_ENTRY  *entry;

    if (lseek(cli->certificate_file.fd, 0, SEEK_SET) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cli->log, ngx_errno,
                      "lseek(\"%V\") failed",
                      &cli->certificate_file.name);
        return NGX_ERROR;
    }

    bio = BIO_new_fd(cli->certificate_file.fd, BIO_NOCLOSE);

    if (bio == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, cli->log, 0, "BIO_new_fd(\"%V\") failed",
                      &cli->certificate_file.name);
        return NGX_ERROR;
    }

    x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);

    if (x509 == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, cli->log, 0,
                      "PEM_read_bio_X509(\"%V\") failed",
                      &cli->certificate_file.name);
        BIO_free(bio);
        return NGX_ERROR;
    }

#if OPENSSL_VERSION_NUMBER > 0x10100000L
    t = X509_get0_notAfter(x509);
#else
    t = (const ASN1_TIME *) X509_get_notAfter(x509);
#endif

    rc = ngx_http_acme_parse_ssl_time(t, cli->log);

    if (rc == (time_t) NGX_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, cli->log, 0,
                      "couldn't extract time from certificate \"%V\"",
                      &cli->certificate_file.name);
        goto failed;
    }

    if (ngx_time() >= rc) {
        /* expired */
        rc = NGX_DECLINED;
        goto failed;
    }

    sans = X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);

    if (!sans) {
        ngx_log_error(NGX_LOG_ALERT, cli->log, 0,
                      "no SAN entry in certificate \"%V\"",
                      &cli->certificate_file.name);
        rc = NGX_DECLINED;
        goto failed;
    }

    subj_name = X509_get_subject_name(x509);

    for (di = 0; di < cli->domains->nelts; di++) {

        domain = ((ngx_str_t*) cli->domains->elts)[di];
        found = 0;

        for (j = 0; j < sk_GENERAL_NAME_num(sans) && !found; j++) {

            name = sk_GENERAL_NAME_value(sans, j);
            if (!name) {
                continue;
            }

            value = GENERAL_NAME_get0_value(name, &type);
            if (!value) {
                continue;
            }

            if (type == GEN_DNS) {
                s = NULL;

                if (ASN1_STRING_to_UTF8(&s, value) < 0) {
                    ngx_log_error(NGX_LOG_ALERT, cli->log, 0,
                         "ASN1_STRING_to_UTF8(\"%V\") failed",
                          &cli->certificate_file.name);
                    continue;

                } else if (s) {
                    if (ngx_strcase_eq(&domain, (char *) s)) {
                        found = 1;
                    }
                    OPENSSL_free(s);
                }
            }
        }

        if (subj_name && !found) {
            i = -1;

            do {
                 i = X509_NAME_get_index_by_NID(subj_name, NID_commonName, i);
                 if (i < 0) {
                     break;
                 }

                 entry = X509_NAME_get_entry(subj_name, i);

                 if (!entry) {
                     continue;
                 }

                 value = X509_NAME_ENTRY_get_data(entry);

                 if (!value) {
                     continue;
                 }

                 s = NULL;

                 if (ASN1_STRING_to_UTF8(&s, value) < 0) {
                     ngx_log_error(NGX_LOG_ALERT, cli->log, 0,
                         "ASN1_STRING_to_UTF8(\"%V\") failed",
                          &cli->certificate_file.name);
                     continue;

                 } else if (s) {
                    if (ngx_strcase_eq(&domain, (char *) s)) {
                        found = 1;
                    }

                    OPENSSL_free(s);
                }

            } while (!found);
        }

        if (!found) {
            rc = NGX_DECLINED;
            break;
        }
    }

failed:

    X509_free(x509);
    BIO_free(bio);

    return rc;
}


static ngx_int_t
ngx_http_acme_full_path(ngx_pool_t *pool, ngx_str_t *path, ngx_str_t *filename,
    ngx_str_t *full_path)
{
    u_char  *p;
    size_t   len;

    len = path->len + 1 /* '/' */ + filename->len + 1 /* '\0' */;

    p = ngx_pnalloc(pool, len);
    if (!p) {
        return NGX_ERROR;
    }

    ngx_snprintf(p, len, "%V/%V%Z", path, filename);

    full_path->data = p;
    full_path->len = len - 1 /* don't count the terminating null */;

    return NGX_OK;
}


static ngx_int_t
ngx_http_acme_run(ngx_http_acme_session_t *ses)
{
    time_t     t;
    ngx_int_t  rc;

    /*
     * Without this, my gcc 11.4.0 issues an "‘rc’ may be used uninitialized"
     * warning in ngx_http_acme_timer_handler!
     */
    rc = NGX_OK;

    NGX_ACME_BEGIN(run);

    DBG_STATUS((ses->client, "--- start renewal"));

    rc = ngx_http_acme_load_keys(ses->client);

    if (rc != NGX_OK) {
        goto failed;
    }

    NGX_ACME_SPAWN(run, bootstrap, (ses), rc);

    if (rc != NGX_OK) {
        goto failed;
    }

    DBG_STATUS((ses->client, "bootstrap: %i", rc));

    NGX_ACME_SPAWN(run, account_ensure, (ses), rc);

    DBG_STATUS((ses->client, "account_ensure: %i", rc));

    if (rc != NGX_OK) {
        goto failed;
    }

    NGX_ACME_SPAWN(run, cert_issue, (ses), rc);

    DBG_STATUS((ses->client, "cert_issue: %i", rc));

    if (rc != NGX_OK) {
        goto failed;
    }

    t = ngx_http_acme_cert_validity(ses->client);

    if (t != (time_t) NGX_ERROR && t != (time_t) NGX_DECLINED) {
        ses->client->expiry_time = t;
        ses->client->renew_time = t - ses->client->renew_before_expiry;

        t = ngx_time();

        if (ses->client->renew_time <= t) {
            ngx_log_error(NGX_LOG_WARN, ses->log, 0,
                          "certificate's validity period is shorter than "
                          "renew_before_expiry time");
            /* TODO find a better solution? */
            ses->client->renew_time = t + (ses->client->expiry_time - t) / 2;
        }

        rc = NGX_OK;

        ngx_log_error(NGX_LOG_NOTICE, ses->log, 0,
                      "certificate renewed, next renewal date: %s",
                      strtok(ctime(&ses->client->renew_time), "\n"));

    } else {
        /* can't happen? */
        rc = NGX_ERROR;

        ngx_log_error(NGX_LOG_ALERT, ses->log, 0,
                      "renewed certificate is invalid: \"%V\"",
                      &ses->client->certificate_file.name);
    }

failed:

    ngx_http_acme_free_keys(ses->client);

    NGX_ACME_END(run);

    DBG_STATUS((ses->client, "--- end renewal: %i", rc));

    return rc;
}


static ngx_int_t
ngx_http_acme_send_request(ngx_http_acme_session_t *ses, ngx_uint_t method,
    ngx_str_t *url, ngx_str_t *body)
{
    ngx_int_t                   rc;
    ngx_http_request_t         *r;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_acme_main_conf_t  *amcf;

    rc = NGX_OK;
    amcf = ngx_http_acme_get_main_conf();

    NGX_ACME_BEGIN(send_request);

    if (ngx_http_acme_init_connection(ses) != NGX_OK) {
        return NGX_ERROR;
    }

    r = ngx_http_acme_init_request(ses, method, url, body);

    if (r == NULL) {
        ngx_http_acme_connection_cleanup(&ses->connection);
        return NGX_ERROR;
    }

    ses->request_result = NGX_BUSY;
    amcf->acme_server_var = *url;

    DBG_HTTP((ses->client, "--- send request"));

    clcf = ngx_http_acme_get_core_loc_conf(amcf);

    ngx_http_acme_finalize_request(r, clcf->handler(r));

    NGX_ACME_YIELD(send_request);

    rc = ses->request_result;

    NGX_ACME_END(send_request);

    return rc;
}


static ngx_int_t
ngx_http_acme_response_handler(ngx_http_acme_session_t *ses,
    ngx_http_request_t *r, ngx_int_t rc)
{
    u_char                  *s, *end;
    ngx_str_t                str;
    ngx_buf_t               *b;
    ngx_json_parse_error_t   err;

    DBG_HTTP((ses->client, "response handler"));

    ses->request_result = NGX_ERROR;

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ses->log, 0,
                      "ACME server response error (%i)", rc);
        return NGX_ERROR;
    }

    if (r->connection->error) {
        ngx_log_error(NGX_LOG_ERR, ses->log, 0, "ACME server connection error");
        return NGX_ERROR;
    }

    ses->status_code = r->headers_out.status;

    if (ngx_clone_table_elt(ses->pool, &ses->location,
                            r->headers_out.location) == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    if (ngx_str_clone(ses->pool, &ses->content_type,
                      &r->headers_out.content_type) == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    if (ngx_http_extract_header(ses->pool, &r->headers_out.headers,
                                 "Replay-Nonce", &ses->nonce) == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    b = r->out->buf;
    ses->json = NULL;
    ngx_str_null(&ses->body);

    if (b->last > b->pos) {
        s = ses->content_type.data;
        end = s + ses->content_type.len;

        if (s && ngx_strlcasestrn(s, end, (u_char*) "json", 4 - 1)) {
            ses->json = ngx_json_parse(b->pos, b->last, ses->pool, &err);
            if (!ses->json) {
                ngx_log_error(NGX_LOG_ERR, ses->log, 0, "JSON parser error: %V",
                              &err.desc);
                return NGX_ERROR;
            }

        } else {
            str.len = b->last - b->pos;
            str.data = b->pos;

            if (ngx_str_clone(ses->pool, &ses->body, &str) == NGX_ERROR) {
                return NGX_ERROR;
            }
        }
    }

    ses->request_result = NGX_OK;

#if 1
    DBG_HTTP((ses->client, "resp body:"));
    DBG_HTTP((ses->client, "%*s", b->last - b->pos, b->pos));
#endif

    return NGX_OK;
}


/*
 * Return values:
 * + non-zero if a server error was detected and logged;
 * + zero if no server error was detected.
 */
static int
ngx_http_acme_server_error(ngx_http_acme_session_t *ses,
    const char *default_msg)
{
    ngx_str_t         s;
    ngx_data_item_t  *json;

    if (default_msg) {
        ngx_log_error(NGX_LOG_ERR, ses->log, 0,
                      "ACME server error: %s (http status code = %d)",
                      default_msg, ses->status_code);
    }

    json = NULL;

    if (ses->json) {
        if (ngx_strcase_eq(&ses->content_type, "application/problem+json")) {
            json = ses->json;

        } else {
            ngx_str_set(&s, "error");
            json = ngx_data_object_find(ses->json, &s);
        }
    }

    if (json) {
        if (ngx_data_object_get_str(json, &s, "detail", 0) != NGX_OK) {
            ngx_str_set(&s, "N/A");
        }

        ngx_log_error(NGX_LOG_ERR, ses->log, 0, "ACME server error message: %V",
                      &s);
    }

    return !!json;
}


static ngx_int_t
ngx_http_acme_get(ngx_http_acme_session_t *ses, ngx_str_t *url)
{
    ngx_int_t  rc;

    rc = NGX_OK;

    NGX_ACME_BEGIN(get);

    NGX_ACME_SPAWN(get, send_request, (ses, NGX_HTTP_GET, url, NULL), rc);

    NGX_ACME_END(get);

    return rc;
}


static ngx_int_t
ngx_http_acme_post(ngx_http_acme_session_t *ses, ngx_str_t *url,
    ngx_str_t *payload)
{
    ngx_int_t  rc;
    ngx_str_t  protected, jws;

    rc = NGX_ERROR;

    NGX_ACME_BEGIN(post);

    if (ngx_http_acme_protected_header(ses, &ses->client->account_key, url,
        &ses->nonce, &protected) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_acme_jws_encode(ses, &ses->client->account_key, &protected,
        payload, &jws) != NGX_OK)
    {
        return NGX_ERROR;
    }

#if 1
    DBG_HTTP((ses->client, "protected: \"%V\"", &protected));
    DBG_HTTP((ses->client, "payload: \"%V\"", payload));
#endif

    NGX_ACME_SPAWN(post, send_request, (ses, NGX_HTTP_POST, url, &jws), rc);

    NGX_ACME_END(post);

    return rc;
}


static ngx_int_t
ngx_http_acme_bootstrap(ngx_http_acme_session_t *ses)
{
    ngx_int_t         rc;
    ngx_str_t         url;
    ngx_data_item_t  *item;

    NGX_ACME_BEGIN(bootstrap);

    NGX_ACME_SPAWN(bootstrap, get, (ses, &ses->client->server), rc);

    if (rc != NGX_OK) {
        NGX_ACME_TERMINATE(bootstrap, NGX_ERROR);
    }

    if (ses->status_code != 200) {
        ngx_http_acme_server_error(ses, "failed to retrieve directory");
        NGX_ACME_TERMINATE(bootstrap, NGX_ERROR);

    } else if (ngx_http_acme_server_error(ses, NULL)) {
        NGX_ACME_TERMINATE(bootstrap, NGX_ERROR);
    }

    ses->dir = ses->json;

    item = ngx_data_object_get_value(ses->dir, "meta",
                                     "externalAccountRequired", 0);

    if (item && item->type == NGX_DATA_BOOLEAN_TYPE && item->data.boolean) {
        ngx_log_error(NGX_LOG_ERR, ses->log, 0,
                      "ACME server requires external account binding "
                      "(not supported)");
        NGX_ACME_TERMINATE(bootstrap, NGX_ERROR);
    }

    if (ngx_data_object_get_str(ses->dir, &url, "newNonce", 0) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ses->log, 0, "newNonce URL not found");
        NGX_ACME_TERMINATE(bootstrap, NGX_ERROR);
    }

    NGX_ACME_SPAWN(bootstrap, get, (ses, &url), rc);

    if (rc != NGX_OK) {
        NGX_ACME_TERMINATE(bootstrap, NGX_ERROR);
    }

    if (ses->status_code != 204) {
        ngx_http_acme_server_error(ses, "failed to retrieve new nonce");
        NGX_ACME_TERMINATE(bootstrap, NGX_ERROR);

    } else if (ngx_http_acme_server_error(ses, NULL)) {
        NGX_ACME_TERMINATE(bootstrap, NGX_ERROR);
    }

    DBG_HTTP((ses->client, "acme nonce: %V", &ses->nonce));

    NGX_ACME_END(bootstrap);

    return NGX_OK;
}


static ngx_int_t
ngx_http_acme_account_ensure(ngx_http_acme_session_t *ses)
{
    /*
     * This much size for buf should be large enough to hold, among other
     * things, a valid email address of the maximum length (for a discussion
     * on what the maximum length of a valid email address is, see
     * https://www.dominicsayers.com/isemail/#getting-it-right )
     */
    u_char     buf[512], *p;
    ngx_str_t  s;
    ngx_int_t  rc;
    ngx_str_t  payload;

    NGX_ACME_BEGIN(account_ensure);

    if (ngx_data_object_get_str(ses->dir, &ses->request_url, "newAccount", 0)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, ses->log, 0, "newAccount URL not found");
        NGX_ACME_TERMINATE(account_ensure, NGX_ERROR);
    }

    ngx_str_set(&payload, "{\"onlyReturnExisting\":true}");

    NGX_ACME_SPAWN(account_ensure, post, (ses, &ses->request_url, &payload),
                   rc);

    if (rc != NGX_OK) {
        NGX_ACME_TERMINATE(account_ensure, NGX_ERROR);
    }

    rc = NGX_ERROR;

    if (ses->status_code == 200) {
        DBG_STATUS((ses->client, "ACME account already exists"));

        if (ses->location.len == 0) {
            ngx_log_error(NGX_LOG_ERR, ses->log, 0,
                          "existing account's location not found");

        } else {
            ses->kid = ses->location;
            rc = NGX_OK;
        }

        NGX_ACME_TERMINATE(account_ensure, rc);

    } else if (ses->status_code == 400) {
        if (ngx_strcase_eq(&ses->content_type, "application/problem+json")
            && ngx_data_object_str_eq(ses->json,
                               "urn:ietf:params:acme:error:accountDoesNotExist",
                               "type", 0))
        {
            p = ngx_copy(buf, "{\"termsOfServiceAgreed\":true",
                         sizeof("{\"termsOfServiceAgreed\":true") - 1);

            if (ses->client->email.len > 0) {
                size_t n = sizeof(buf) - (p - buf);

                if (ses->client->email.len
                    > n - sizeof(",\"contact\":[\"mailto:\"]") - 1 - 1)
                {
                    ngx_log_error(NGX_LOG_WARN, ses->log, 0,
                                  "invalid email \"%V\", omitted",
                                  &ses->client->email);
                } else {
                    p = ngx_snprintf(p, n, ",\"contact\":[\"mailto:%V\"]",
                                     &ses->client->email);
                }
            }

            p = ngx_copy(p, "}", 1);

            payload.data = buf;
            payload.len = p - buf;

            DBG_HTTP((ses->client, "new account payload %V", &payload));

            NGX_ACME_SPAWN(account_ensure, post,
                (ses, &ses->request_url, &payload), rc);

            if (rc != NGX_OK) {
                NGX_ACME_TERMINATE(account_ensure, NGX_ERROR);
            }

            rc = NGX_ERROR;

            if (ses->status_code == 201) {
                /* Sanity checks */
                if (ngx_data_object_get_str(ses->json, &s, "status", 0)
                    != NGX_OK)
                {
                    ngx_log_error(NGX_LOG_ERR, ses->log, 0,
                                  "newly created account's status not found");

                } else if (!ngx_str_eq(&s, "valid")) {
                    ngx_log_error(NGX_LOG_ERR, ses->log, 0,
                                  "newly created account's status not valid "
                                  "(\"%V\")", &s);

                } else if (ses->location.len == 0) {
                    ngx_log_error(NGX_LOG_ERR, ses->log, 0,
                                  "newly created account's Location not found");

                } else {
                    ses->kid = ses->location;
                    rc = NGX_OK;
                }

                NGX_ACME_TERMINATE(account_ensure, rc);
            }
        }
    }

    ngx_http_acme_server_error(ses, "error creating new account");

    NGX_ACME_END(account_ensure);

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_acme_cert_issue(ngx_http_acme_session_t *ses)
{
    ssize_t    n;
    ngx_fd_t   fd;
    ngx_int_t  rc;
    ngx_str_t  s, csr;

    NGX_ACME_BEGIN(cert_issue);

    DBG_STATUS((ses->client, "creating a new order"));

    rc = ngx_data_object_get_str(ses->dir, &ses->request_url, "newOrder", 0);

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ses->log, 0, "newOrder URL not found");
        NGX_ACME_TERMINATE(cert_issue, NGX_ERROR);
    }

    rc = ngx_http_acme_identifiers(ses, &s);

    if (rc != NGX_OK) {
        NGX_ACME_TERMINATE(cert_issue, NGX_ERROR);
    }

    NGX_ACME_SPAWN(cert_issue, post, (ses, &ses->request_url, &s), rc);

    if (rc != NGX_OK) {
        NGX_ACME_TERMINATE(cert_issue, NGX_ERROR);
    }

    if (ses->status_code != 201) {
        ngx_http_acme_server_error(ses, "failed to create new order");
        NGX_ACME_TERMINATE(cert_issue, NGX_ERROR);
    }

    if (ses->location.len == 0) {
        ngx_log_error(NGX_LOG_ERR, ses->log, 0,
                      "ACME order Location not found");
        NGX_ACME_TERMINATE(cert_issue, NGX_ERROR);
    }

    ses->order_url = ses->location;

    ngx_str_set(&s, "unknown");

    if (ngx_data_object_get_str(ses->json, &s, "status", 0) != NGX_OK
        || (!ngx_str_eq(&s, "ready") && !ngx_str_eq(&s, "pending")))
    {
        ngx_http_acme_server_error(ses, "invalid order status");
        NGX_ACME_TERMINATE(cert_issue, NGX_ERROR);
    }

    DBG_STATUS((ses->client, "order status: %V", &s));

    if (ngx_str_eq(&s, "ready")) {
        goto finalize;
    }

    NGX_ACME_SPAWN(cert_issue, authorize, (ses), rc);

    DBG_STATUS((ses->client, "authorize: %i", rc));

    if (rc != NGX_OK) {
        NGX_ACME_TERMINATE(cert_issue, NGX_ERROR);
    }

    DBG_STATUS((ses->client, "poll authorization status for %d sec",
                NGX_ACME_AUTHORIZATION_TIMEOUT));

    ses->deadline = ngx_time() + NGX_ACME_AUTHORIZATION_TIMEOUT;

poll_status:

    NGX_ACME_DELAY(cert_issue, 1);

    ngx_str_set(&s, "");

    NGX_ACME_SPAWN(cert_issue, post, (ses, &ses->order_url, &s), rc);

    if (rc != NGX_OK) {
        NGX_ACME_TERMINATE(cert_issue, NGX_ERROR);
    }

    if (ses->status_code != 200) {
        ngx_http_acme_server_error(ses, "failed to poll order status");
        NGX_ACME_TERMINATE(cert_issue, NGX_ERROR);
    }

    if (ngx_data_object_get_str(ses->json, &s, "status", 0) != NGX_OK) {
        ngx_http_acme_server_error(ses, "order status not found");
        NGX_ACME_TERMINATE(cert_issue, NGX_ERROR);
    }

    if (ngx_str_eq(&s, "ready")) {
        goto finalize;
    }

    if (!ngx_str_eq(&s, "pending")) {
        ngx_http_acme_server_error(ses, "unexpected order status");
        NGX_ACME_TERMINATE(cert_issue, NGX_ERROR);
    }

    if (ngx_time() >= ses->deadline) {
        ngx_http_acme_server_error(ses,
                                "timeout occurred while polling order status");
        NGX_ACME_TERMINATE(cert_issue, NGX_ERROR);
    }

    goto poll_status;

finalize:

    DBG_STATUS((ses->client, "finalizing"));

    rc = ngx_data_object_get_str(ses->json, &ses->request_url, "finalize", 0);

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ses->log, 0, "finalize URL not found");

        NGX_ACME_TERMINATE(cert_issue, NGX_ERROR);
    }

    rc = ngx_http_acme_csr_gen(ses, &ses->client->private_key, &csr);

    if (rc != NGX_OK) {
        NGX_ACME_TERMINATE(cert_issue, NGX_ERROR);
    }

    s.len = sizeof("{\"csr\":\"\"}") - 1 + csr.len;
    s.data = ngx_pnalloc(ses->pool, s.len);
    if (!s.data) {
        NGX_ACME_TERMINATE(cert_issue, NGX_ERROR);
    }

    ngx_snprintf(s.data, s.len, "{\"csr\":\"%V\"}", &csr);

    NGX_ACME_SPAWN(cert_issue, post, (ses, &ses->request_url, &s), rc);

    if (rc != NGX_OK) {
        NGX_ACME_TERMINATE(cert_issue, NGX_ERROR);
    }

    if (ses->status_code != 200) {
        ngx_http_acme_server_error(ses, "failed to upload CSR");
        NGX_ACME_TERMINATE(cert_issue, NGX_ERROR);
    }

    DBG_STATUS((ses->client, "poll issuance status for %d sec",
                NGX_ACME_ISSUANCE_TIMEOUT));

    ses->deadline = ngx_time() +  NGX_ACME_ISSUANCE_TIMEOUT;

poll_status2:

    ngx_str_set(&s, "");

    NGX_ACME_SPAWN(cert_issue, post, (ses, &ses->order_url, &s), rc);

    if (rc != NGX_OK) {
        NGX_ACME_TERMINATE(cert_issue, NGX_ERROR);
    }

    if (ses->status_code != 200) {
        ngx_http_acme_server_error(ses, "failed to poll issuance status");
        NGX_ACME_TERMINATE(cert_issue, NGX_ERROR);
    }

    if (ngx_data_object_get_str(ses->json, &s, "status", 0) != NGX_OK) {
        ngx_http_acme_server_error(ses, "certificate status not found");
        NGX_ACME_TERMINATE(cert_issue, NGX_ERROR);
    }

    if (ngx_str_eq(&s, "valid")) {
        goto certificate;
    }

    if (!ngx_str_eq(&s, "processing")) {
        ngx_log_error(NGX_LOG_ERR, ses->log, 0, "unexpected status \"%V\"", &s);

        NGX_ACME_TERMINATE(cert_issue, NGX_ERROR);
    }

    if (ngx_time() >= ses->deadline) {
        ngx_http_acme_server_error(ses,
                             "timeout occurred while polling issuance status");
        NGX_ACME_TERMINATE(cert_issue, NGX_ERROR);
    }

    NGX_ACME_DELAY(cert_issue, 1);

    goto poll_status2;

certificate:

    DBG_STATUS((ses->client, "downloading certificate"));

    if (ngx_data_object_get_str(ses->json, &ses->cert_url, "certificate", 0)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, ses->log, 0, "certificate URL not found");
        NGX_ACME_TERMINATE(cert_issue, NGX_ERROR);
    }

    ngx_str_set(&s, "");

    NGX_ACME_SPAWN(cert_issue, post, (ses, &ses->cert_url, &s), rc);

    if (rc != NGX_OK) {
        NGX_ACME_TERMINATE(cert_issue, NGX_ERROR);
    }

    if (ses->status_code != 200) {
        ngx_http_acme_server_error(ses, "failed to download certificate");
        NGX_ACME_TERMINATE(cert_issue, NGX_ERROR);
    }

    fd = ses->client->certificate_file.fd;

    if (lseek(fd, 0, SEEK_SET) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ses->log, ngx_errno, "lseek(\"%V\") failed",
                      &ses->client->certificate_file.name);
        return NGX_ERROR;
    }

    n = ngx_write_fd(fd, ses->body.data, ses->body.len);

    if (n == -1) {
        ngx_log_error(NGX_LOG_ALERT, ses->log, ngx_errno,
                      ngx_write_fd_n "(\"%V\") failed",
                      &ses->client->certificate_file.name);
        return NGX_ERROR;
    }

    if ((size_t) n != ses->body.len) {
        ngx_log_error(NGX_LOG_ALERT, ses->log, 0,
                      ngx_write_fd_n " has written only %z of %uz to \"%V\"",
                      n, ses->body.len, &ses->client->certificate_file.name);
        return NGX_ERROR;
    }

    if (lseek(fd, 0, SEEK_SET) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ses->log, ngx_errno,
                      "lseek(\"%V\") failed",
                      &ses->client->certificate_file.name);
        return NGX_ERROR;
    }

    if (ses->body.len < ses->client->certificate_file_size
        && ftruncate(fd, ses->body.len) != 0)
    {
        ngx_log_error(NGX_LOG_ALERT, ses->log, ngx_errno,
                      "ftruncate(\"%V\") failed",
                      &ses->client->certificate_file.name);
        return NGX_ERROR;
    }

    ngx_rwlock_wlock(&ses->client->sh_cert->lock);

    if (ngx_http_acme_file_load(ses->log, &ses->client->certificate_file,
                                ses->client->sh_cert->data_start + 5,
                                ses->body.len)
        != NGX_OK)
    {
        ses->client->sh_cert->len = 5; /* 5 = size of "data:" prefix */
        ngx_rwlock_unlock(&ses->client->sh_cert->lock);
        return NGX_ERROR;
    }

    ses->client->sh_cert->len = ses->body.len + 5;

    ngx_rwlock_unlock(&ses->client->sh_cert->lock);

    NGX_ACME_END(cert_issue);

    return NGX_OK;
}


static ngx_int_t
ngx_http_acme_authorize(ngx_http_acme_session_t *ses)
{
    ngx_int_t         rc;
    ngx_str_t         s;
    ngx_data_item_t  *item;

    NGX_ACME_BEGIN(authorize);

    ses->auths = ngx_data_object_get_value(ses->json, "authorizations", 0);

    if (!ses->auths || ses->auths->type != NGX_DATA_LIST_TYPE) {
        ngx_log_error(NGX_LOG_ERR, ses->log, 0,
                      "valid ACME authorizations not found");
        NGX_ACME_TERMINATE(authorize, NGX_ERROR);
    }

    if (ngx_http_acme_jwk_thumbprint(ses, &ses->client->account_key,
        &ses->thumbprint) != NGX_OK)
    {
        NGX_ACME_TERMINATE(authorize, NGX_ERROR);
    }

    ses->auth = ses->auths;

next_auth:

    if (ses->auth == ses->auths) {
        ses->auth = ses->auths->data.child;

    } else {
        ses->auth = ses->auth->next;
    }

    if (!ses->auth) {
        goto done;
    }

    if (ngx_data_get_string(&ses->auth_url, ses->auth) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ses->log, 0,
                      "invalid ACME authorization URL");
        NGX_ACME_TERMINATE(authorize, NGX_ERROR);
    }

    ngx_str_set(&s, "");

    NGX_ACME_SPAWN(authorize, post, (ses, &ses->auth_url, &s), rc);

    if (rc != NGX_OK) {
        NGX_ACME_TERMINATE(authorize, NGX_ERROR);
    }

    if (ses->status_code != 200) {
        ngx_http_acme_server_error(ses, "failed to get authorization");
        NGX_ACME_TERMINATE(authorize, NGX_ERROR);
    }

    /*
     * we retrieve the identifier first because we will be using it
     * in subsequent log messages
     */

    item = ngx_data_object_get_value(ses->json, "identifier", 0);

    if (!item) {
        ngx_log_error(NGX_LOG_ERR, ses->log, 0, "identifier object not found");

        NGX_ACME_TERMINATE(authorize, NGX_ERROR);
    }

    if (ngx_data_object_get_str(item, &s, "value", 0) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ses->log, 0, "identifier value not found");

        NGX_ACME_TERMINATE(authorize, NGX_ERROR);
    }

    ses->ident = s;

    if (ngx_data_object_get_str(ses->json, &s, "status", 0) != NGX_OK) {
        ngx_http_acme_server_error(ses, "authorization status not found");
        NGX_ACME_TERMINATE(authorize, NGX_ERROR);
    }

    DBG_STATUS((ses->client, "authorization status for \"%V\": %V", &ses->ident,
                &s));

    if (!ngx_str_eq(&s, "pending")) {
        if (!ngx_str_eq(&s, "valid")) {
            ngx_http_acme_server_error(ses, "unexpected authorization status");

            NGX_ACME_TERMINATE(authorize, NGX_ERROR);
        }

        goto next_auth;
    }

    ngx_str_set(&s, "type not found");

    if (ngx_data_object_get_str(item, &s, "type", 0) != NGX_OK
        || !ngx_str_eq(&s, "dns"))
    {
        ngx_log_error(NGX_LOG_ERR, ses->log, 0,
                      "identifier \"%V\" is of an unsupported type (%V)",
                      &ses->ident, &s);

        NGX_ACME_TERMINATE(authorize, NGX_ERROR);
    }

    item = ngx_data_object_get_value(ses->json, "challenges", 0);

    if (!item || item->type != NGX_DATA_LIST_TYPE) {
        ngx_log_error(NGX_LOG_ERR, ses->log, 0, "valid challenges not found");

        NGX_ACME_TERMINATE(authorize, NGX_ERROR);
    }

    item = item->data.child;

    while (item) {

        if (ngx_data_object_get_str(item, &s, "type", 0) == NGX_OK
            && ngx_str_eq(&s, "http-01")
            && ngx_data_object_get_str(item, &s, "status", 0) == NGX_OK
            && (ngx_str_eq(&s, "pending") || ngx_str_eq(&s, "processing")))
        {
            goto challenge_found;
        }

        item = item->next;
    }

    ngx_log_error(NGX_LOG_ERR, ses->log, 0,
                  "ACME authorization failed: no supported challenge type "
                  "was found for identifier \"%V\"", &ses->ident);

    NGX_ACME_TERMINATE(authorize, NGX_ERROR);

challenge_found:

    if (ngx_data_object_get_str(item, &ses->challenge_url, "url", 0)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, ses->log, 0, "challenge URL not found");

        NGX_ACME_TERMINATE(authorize, NGX_ERROR);
    }

    if (ngx_data_object_get_str(item, &ses->token, "token", 0) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ses->log, 0, "challenge token not found");

        NGX_ACME_TERMINATE(authorize, NGX_ERROR);
    }

    /* keyAuthorization = token '.' base64url(Thumbprint(accountKey)) */

    ses->key_auth.len = ses->token.len + 1 + ses->thumbprint.len;

    ses->key_auth.data = ngx_pnalloc(ses->pool, ses->key_auth.len);
    if (!ses->key_auth.data) {
        NGX_ACME_TERMINATE(authorize, NGX_ERROR);
    }

    ngx_snprintf(ses->key_auth.data, ses->key_auth.len, "%V.%V",
                 &ses->token, &ses->thumbprint);

    if (ngx_http_acme_share_key_auth(ses, &ses->key_auth, ses->token.len)
        != NGX_OK)
    {
        NGX_ACME_TERMINATE(authorize, NGX_ERROR);
    }

    DBG_STATUS((ses->client, "initiating challenge"));

    ngx_str_set(&s, "{}");

    NGX_ACME_SPAWN(authorize, post, (ses, &ses->challenge_url, &s), rc);

    if (rc != NGX_OK) {
        NGX_ACME_TERMINATE(authorize, NGX_ERROR);
    }

    if (ses->status_code != 200) {
        ngx_http_acme_server_error(ses, "failed to start challenge");
        NGX_ACME_TERMINATE(authorize, NGX_ERROR);
    }

    if (ngx_data_object_get_str(ses->json, &s, "status", 0) != NGX_OK) {
        ngx_http_acme_server_error(ses, "challenge status not found");
        NGX_ACME_TERMINATE(authorize, NGX_ERROR);
    }

    if (ngx_str_eq(&s, "valid")) {
        DBG_STATUS((ses->client, "challenge completed for \"%V\"",
                    &ses->ident));

        goto next_auth;
    }

    DBG_STATUS((ses->client, "\"%V\" is ready to respond to challenge",
                &ses->ident));

    DBG_STATUS((ses->client, "poll challenge status for %d sec",
                NGX_ACME_CHALLENGE_TIMEOUT));

    ses->deadline = ngx_time() + NGX_ACME_CHALLENGE_TIMEOUT;

poll_challenge_status:

    NGX_ACME_DELAY(authorize, 1);

    ngx_str_set(&s, "");

    NGX_ACME_SPAWN(authorize, post, (ses, &ses->challenge_url, &s), rc);

    if (rc != NGX_OK) {
        NGX_ACME_TERMINATE(authorize, NGX_ERROR);
    }

    if (ses->status_code != 200) {
        ngx_http_acme_server_error(ses, "failed to poll challenge status");
        NGX_ACME_TERMINATE(authorize, NGX_ERROR);
    }

    if (ngx_data_object_get_str(ses->json, &s, "status", 0) != NGX_OK) {
        ngx_http_acme_server_error(ses, "challenge status not found");
        NGX_ACME_TERMINATE(authorize, NGX_ERROR);
    }

    if (ngx_str_eq(&s, "valid")) {
        DBG_STATUS((ses->client, "challenge completed for \"%V\"",
                   &ses->ident));

        goto next_auth;
    }

    if (!ngx_str_eq(&s, "pending") && !ngx_str_eq(&s, "processing")) {
        ngx_http_acme_server_error(ses,
                             "http-01 challenge failed");
        NGX_ACME_TERMINATE(authorize, NGX_ERROR);
    }

    if (ngx_time() >= ses->deadline) {
        ngx_http_acme_server_error(ses,
                             "timeout occurred while polling challenge status");
        NGX_ACME_TERMINATE(authorize, NGX_ERROR);
    }

    goto poll_challenge_status;

done:

    NGX_ACME_END(authorize);

    return NGX_OK;
}


static ngx_int_t
ngx_http_acme_share_key_auth(ngx_http_acme_session_t *ses, ngx_str_t *key_auth,
    u_short token_len)
{
    ngx_http_acme_main_conf_t  *amcf;

    amcf = ngx_http_acme_get_main_conf();

    if (key_auth->len > amcf->max_key_auth_size) {
        ngx_log_error(NGX_LOG_CRIT, ses->log, 0,
                      "key authorization string received from ACME server "
                      "is too long to fit in shared memory, use "
                      "max_key_auth_size with a value of at least %uz",
                      key_auth->len);
        return NGX_ERROR;

    }

    ngx_rwlock_wlock(&amcf->sh->key_auth_lock);

    amcf->sh->key_auth_len = key_auth->len;
    amcf->sh->token_len = token_len;
    ngx_memcpy(&amcf->sh->data_start, key_auth->data, key_auth->len);

    ngx_rwlock_unlock(&amcf->sh->key_auth_lock);

    return NGX_OK;
}


static ngx_int_t
ngx_acme_http_challenge_handler(ngx_http_request_t *r)
{
    static const ngx_str_t content_type =
                                         ngx_string("application/octet-stream");
    static const ngx_str_t wellknown =
                                     ngx_string("/.well-known/acme-challenge/");

    ngx_int_t     rc;
    ngx_log_t    *log;
    ngx_str_t     token, key_auth;
    ngx_buf_t    *b;
    ngx_chain_t   out;

    if (!(r->method & NGX_HTTP_GET)
        || r->uri.len <= wellknown.len
        || ngx_memcmp(r->uri.data, wellknown.data, wellknown.len) != 0)
    {
        return NGX_DECLINED;
    }

    token.len = r->uri.len - wellknown.len;
    token.data = r->uri.data + wellknown.len;

    rc = ngx_http_acme_get_shared_key_auth(r, &token, &key_auth);

    if (rc != NGX_OK) {
        return rc;
    }

    log = r->connection->log;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                   "acme status: http-01 challenge handler");

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    log->action = "sending response to ACME http-01 challenge";

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_type_len = content_type.len;
    r->headers_out.content_type = content_type;

    r->headers_out.content_length_n = key_auth.len;

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->pos = key_auth.data;
    b->last = key_auth.data + key_auth.len;
    b->memory = 1;
    b->last_buf = 1;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    ngx_http_finalize_request(r, ngx_http_output_filter(r, &out));

    return NGX_DONE;
}


static ngx_int_t
ngx_http_acme_get_shared_key_auth(ngx_http_request_t *r, ngx_str_t *token,
    ngx_str_t *key_auth)
{
    u_char                      *p;
    ngx_int_t                    rc;
    ngx_http_acme_main_conf_t   *amcf;
    ngx_http_acme_sh_keyauth_t  *sh;

    rc = NGX_DECLINED;

    amcf = ngx_http_get_module_main_conf(r, ngx_http_acme_module);
    sh = amcf->sh;

    ngx_rwlock_rlock(&sh->key_auth_lock);

    if (token->len == sh->token_len
        && ngx_memcmp(token->data, &sh->data_start, token->len) == 0)
    {
        p = ngx_pnalloc(r->pool, sh->key_auth_len);

        if (p) {
            key_auth->len = sh->key_auth_len;
            ngx_memcpy(p, &sh->data_start, key_auth->len);
            key_auth->data = p;
            rc = NGX_OK;

        } else {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    ngx_rwlock_unlock(&sh->key_auth_lock);

    return rc;
}


static void
ngx_http_acme_timer_handler(ngx_event_t *ev)
{
    ngx_int_t                   rc;
    ngx_msec_t                  t;
    ngx_acme_client_t          *cli;
    ngx_http_acme_session_t    *ses;
    ngx_http_acme_main_conf_t  *amcf;

    amcf = ev->data;
    cli = amcf->current;

    if (!cli->session) {
        t = ngx_http_acme_timer_interval(cli);

        if (t > 1) {
            /* still waiting... */
            ngx_add_timer(ev, t);
            return;
        }

        cli->session = ngx_http_acme_create_session(cli);
        if (!cli->session) {
            return;
        }
    }

    ses = cli->session;
    rc = NGX_OK;

    if (!NGX_FIBER_IS_ENDED(ses->run_state)) {
        rc = ngx_http_acme_run(ses);
    }

    if (NGX_FIBER_IS_ENDED(ses->run_state)) {
        ngx_http_acme_destroy_session(&cli->session);

        if (rc == NGX_ERROR) {
            if (cli->retry_after_error == NGX_ACME_MAX_TIME) {
                cli->enabled = 0;

                ngx_log_error(NGX_LOG_NOTICE, cli->log, 0,
                              "will not retry to obtain certificate");

            } else {
                cli->renew_time = ngx_time() + cli->retry_after_error;

                ngx_log_error(NGX_LOG_NOTICE, cli->log, 0,
                              "will retry to obtain certificate on %s",
                              strtok(ctime(&cli->renew_time), "\n"));
            }
        }

        amcf->current = ngx_http_acme_nearest_client(amcf);

        if (!amcf->current) {
            ngx_log_error(NGX_LOG_NOTICE, cli->log, 0,
                          "no certificate found for renewal, ACME client quit");
            return;
        }

        ngx_add_timer(ev, ngx_http_acme_timer_interval(amcf->current));

        if (rc == NGX_ERROR && amcf->current != cli) {
            ngx_log_error(NGX_LOG_NOTICE, cli->log, 0,
                          "certificate scheduled for renewal on %s",
                          strtok(ctime(&amcf->current->renew_time), "\n"));
        }
    }
}


static ngx_int_t
ngx_http_acme_init_connection(ngx_http_acme_session_t *ses)
{
    ngx_pool_t          *pool;
    ngx_connection_t    *c;
    struct sockaddr_in  *sin;

    c = &ses->connection;

    pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, ses->log);
    if (pool == NULL) {
        return NGX_ERROR;
    }

    DBG_MEM((ses->client, "create connection pool: %p", pool));

    ngx_memzero(c, sizeof(ngx_connection_t));

    c->read = &ses->read;
    c->read->data = c;
    c->read->index = NGX_INVALID_INDEX;
    c->read->log = ses->log;

    c->write = &ses->write;
    c->write->data = c;
    c->write->index = NGX_INVALID_INDEX;
    c->write->log = ses->log;

    c->log = ses->log;

    c->pool = pool;
    c->shared = 1;
    c->tcp_nodelay = NGX_TCP_NODELAY_DISABLED;
    c->fd = -1;

    /* fake client address: 127.0.0.1:0 */
    sin = (struct sockaddr_in *) &ses->caddr;

    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin->sin_port = htons(0);

    c->sockaddr = &ses->caddr;
    c->local_sockaddr = &ses->caddr;
    c->local_socklen = sizeof(struct sockaddr);

    c->read->handler = ngx_http_acme_read_handler;

    c->read->ready = 1;
    c->write->ready = 1;

    c->type = SOCK_STREAM;
    c->send_chain = ngx_http_acme_send_chain;
    c->sendfile = 0;

    c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
    c->start_time = ngx_current_msec;
    c->log->connection = c->number;

    return NGX_OK;
}


static void
ngx_http_acme_read_handler(ngx_event_t *ev)
{
    ngx_connection_t    *c;
    ngx_http_request_t  *r;

    c = ev->data;
    r = c->data;

    if (ngx_handle_read_event(ev, 0) != NGX_OK) {
        ngx_http_acme_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }
}


static ngx_chain_t *
ngx_http_acme_send_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    /* can't happen */
    ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                  "internal error: send_chain stub called");
    return NGX_CHAIN_ERROR;
}


static ngx_http_request_t *
ngx_http_acme_init_request(ngx_http_acme_session_t *ses, ngx_uint_t method,
    ngx_str_t *url, ngx_str_t *body)
{
    u_char                     *p;
    size_t                      len;
    ngx_buf_t                  *b;
    ngx_str_t                   uri;
    ngx_chain_t                *cl;
    ngx_connection_t           *c;
    ngx_http_request_t         *r;
    ngx_http_connection_t       hc;
    ngx_http_acme_main_conf_t  *amcf;

    c = &ses->connection;
    amcf = ngx_http_acme_get_main_conf();

    ngx_memzero(&hc, sizeof(ngx_http_connection_t));
    hc.conf_ctx = amcf->ctx;

    c->data = &hc;

    r = ngx_http_create_request(c);
    if (r == NULL) {
        return NULL;
    }

    DBG_MEM((ses->client, "create request pool: %p", r->pool));

#if (NGX_STAT_STUB)
    /* revert increments by ngx_http_create_request() */
    (void) ngx_atomic_fetch_add(ngx_stat_reading, -1);
    (void) ngx_atomic_fetch_add(ngx_stat_requests, -1);
    r->stat_reading = 0;

#endif

    c->data = r;

    ngx_http_set_ctx(r, ses, ngx_http_acme_module);

    if (method == NGX_HTTP_POST && body)  {
        r->request_body = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
        if (r->request_body == NULL) {
            goto failed;
        }
    }

    r->header_in = ngx_alloc_buf(r->pool);
    if (r->header_in == NULL) {
        goto failed;
    }

    ngx_http_acme_extract_uri(url, &uri);

    r->uri = uri;
    r->unparsed_uri = r->uri;
    r->valid_unparsed_uri = 1;

    if (ngx_list_init(&r->headers_in.headers, r->pool, 4,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        goto failed;
    }

    /*
     * RFC8555: "ACME clients MUST send a User-Agent header field, in accordance
     * with RFC7231."
     */

    if (ngx_http_acme_add_header(r, "User-Agent", ANGIE_VER " (ACME client)")
        != NGX_OK)
    {
        goto failed;
    }

    if (method == NGX_HTTP_GET) {
        ngx_str_set(&r->method_name, "GET");

    } else if (method == NGX_HTTP_POST) {
        ngx_str_set(&r->method_name, "POST");

    } else {
        /* can't happen? */
        DBG_HTTP((ses->client, "unsupported http method %i", method));
        goto failed;
    }

    r->method = method;

    r->internal_client = 1;
    r->finalize_request = ngx_http_acme_finalize_request;
    r->subrequest_in_memory = 1;

    if (method == NGX_HTTP_POST && body) {
        r->headers_in.content_length_n = body->len;

        if (ngx_http_acme_add_header(r, "Content-Type", "application/jose+json")
            != NGX_OK)
        {
            goto failed;
        }

        len = ngx_dec_count(body->len) + 1;

        p = ngx_pnalloc(r->pool, len);
        if (p == NULL) {
            return NULL;
        }

        ngx_snprintf(p, len, "%z%Z", body->len);

        if (ngx_http_acme_add_header(r, "Content-Length", (char *) p)
            != NGX_OK)
        {
            goto failed;
        }

        b = ngx_create_temp_buf(r->pool, body->len);
        if (b == NULL) {
            goto failed;
        }

        ngx_memcpy(b->start, body->data, body->len);
        b->last = b->end;

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            goto failed;
        }

        cl->buf = b;
        cl->next = NULL;
        r->request_body->bufs = cl;
#if 0
        DBG_HTTP((ses->conf, "req body: %V", body));
#endif
    }

    return r;

failed:

    ngx_destroy_pool(r->pool);
    return NULL;
}


static ngx_int_t
ngx_http_acme_add_header(ngx_http_request_t *r, char *name, char *value)
{
    ngx_table_elt_t            *h;
    ngx_http_header_t          *hh;
    ngx_http_core_main_conf_t  *cmcf;
#if (NGX_DEBUG)
    ngx_http_acme_session_t    *ses;

    ses = ngx_http_get_module_ctx(r, ngx_http_acme_module);

    DBG_HTTP((ses->client, "req header: \"%s: %s\"", name, value));
#endif

    h = ngx_list_push(&r->headers_in.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->key.data = (u_char*) name;
    h->key.len = ngx_strlen(name);

    h->value.data = (u_char*) value;
    h->value.len = ngx_strlen(value);

    h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
    if (h->lowcase_key == NULL) {
        return NGX_ERROR;
    }

    ngx_strlow(h->lowcase_key, h->key.data, h->key.len);

    h->hash = ngx_hash_key(h->lowcase_key, h->key.len);

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    hh = ngx_hash_find(&cmcf->headers_in_hash, h->hash,
                       h->lowcase_key, h->key.len);

    if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_http_acme_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_connection_t           *c;
    ngx_http_acme_session_t    *ses;
    ngx_http_acme_main_conf_t  *amcf;

    ses = ngx_http_get_module_ctx(r, ngx_http_acme_module);

    DBG_HTTP((ses->client, "request completed: %i", rc));

    if (r->count == 0) {
        ngx_log_error(NGX_LOG_ALERT, ses->log, 0, "acme request count is zero");
    }

    r->count--;

    if (r->count) {
        return;
    }

    DBG_HTTP((ses->client, "--- response received"));

    ngx_http_acme_response_handler(ses, r, rc);

    amcf = ngx_http_acme_get_main_conf();

    ngx_add_timer(&amcf->timer_event, 10);

    c = r->connection;

    DBG_MEM((ses->client, "destroy request pool: %p", r->pool));

    ngx_destroy_pool(r->pool);

    ngx_http_acme_connection_cleanup(c);
}


static void
ngx_http_acme_connection_cleanup(ngx_connection_t *c)
{
#if (NGX_DEBUG)
    ngx_http_acme_session_t  *ses;

    ses = ngx_container_of(c, ngx_http_acme_session_t, connection);
#endif

    DBG_HTTP((ses->client, "close connection"));

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    if (c->read->posted) {
        ngx_delete_posted_event(c->read);
    }

    if (c->write->posted) {
        ngx_delete_posted_event(c->write);
    }

    if (c->pool) {
        DBG_MEM((ses->client, "destroy connection pool: %p", c->pool));

        ngx_destroy_pool(c->pool);
        c->pool = NULL;
    }

    c->destroyed = 1;
}


static ngx_int_t
ngx_http_acme_postconfiguration(ngx_conf_t *cf)
{
    size_t                       shm_size, sz;
    ngx_str_t                   *s, name;
    ngx_err_t                    err;
    ngx_uint_t                   i, j, n;
    ngx_acme_client_t           *cli, **clients;
    ngx_pool_cleanup_t          *cln;
    ngx_http_handler_pt         *h;
    ngx_http_variable_t         *v;
    ngx_http_conf_port_t        *port;
    ngx_http_server_name_t      *sn;
    ngx_http_acme_srv_conf_t    *ascf;
    ngx_http_core_srv_conf_t   **cscfp, *cscf;
    ngx_http_core_loc_conf_t    *clcf, *pclcf;
    ngx_http_acme_main_conf_t   *amcf;
    ngx_http_core_main_conf_t   *cmcf;

    amcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_acme_module);

    if (amcf->ctx == NULL) {
        /* no enabled clients, nothing to do */
        return NGX_OK;
    }

    if (ngx_http_acme_merge_conf_ctx(cf, amcf) != NGX_OK) {
        return NGX_ERROR;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    cscfp = cmcf->servers.elts;

    for (i = 0; i < cmcf->servers.nelts; i++) {

        cscf = cscfp[i];
        ascf = cscf->ctx->srv_conf[ngx_http_acme_module.ctx_index];

        clients = ascf->clients.elts;

        for (j = 0; j < ascf->clients.nelts; j++) {

            cli = clients[j];
            if (!cli->enabled) {
                continue;
            }

            if (cli->server.len == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "ACME client \"%V\" is not defined but "
                                   "referenced in %V:%ui", &cli->name,
                                   &cli->cf_filename, cli->cf_line);
                return NGX_ERROR;
            }

            sn = cscf->server_names.elts;

            for (n = 0; n < cscf->server_names.nelts; n++) {
                s = &sn[n].name;

                if (!s->len) {
                    /* may contain an empty server_name */
                    continue;
                }

                if (
#if (NGX_PCRE)
                    sn[n].regex ||
#endif
                       ngx_strlchr(s->data, s->data + s->len, '*')
                    || ngx_strlchr(s->data, s->data + s->len, ':')
                    || ngx_strlchr(s->data, s->data + s->len, '/')
                    || ngx_str_is_ip(s))
                {
                    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                       "unsupported domain format \"%V\" used by "
                                       "ACME client \"%V\", ignored", s,
                                       &cli->name);
                    continue;
                }

                s = ngx_array_push(cli->domains);
                if (s == NULL) {
                    return NGX_ERROR;
                }

                *s = sn[n].name;
            }
        }
    }

    n = 0;

    if (cmcf->ports != NULL) {
        port = cmcf->ports->elts;
        for (i = 0; i < cmcf->ports->nelts; i++) {

            if (port[i].port == 80) {
                n = 1;
                break;
            }
        }
    }

    if (!n) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "this configuration requires a server listening on "
                           "port 80 for ACME http-01 challenge");
    }

    if (ngx_create_dir(amcf->path.data, 0700) == NGX_FILE_ERROR) {
        err = ngx_errno;
        if (err != NGX_EEXIST) {
            ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, err,
                          ngx_create_dir_n " \"%s\" failed", amcf->path.data);
            return NGX_ERROR;
        }
    }

    shm_size = 0;

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_http_acme_fds_close;
    cln->data = &amcf->clients;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    pclcf = ngx_http_acme_get_core_loc_conf(amcf);

    pclcf->resolver = clcf->resolver;

    if (clcf->error_log != NULL) {
        pclcf->error_log = clcf->error_log;
    }

    for (i = 0; i < amcf->clients.nelts; i++) {

        cli = (ngx_acme_client_t *) amcf->clients.elts + i;

        if (!cli->enabled) {
            continue;
        }

        if (cli->server_url.addrs == NULL
            && clcf->resolver->connections.nelts == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "no resolver configured for resolving %V "
                               "at run time for ACME client \"%V\"",
                               &cli->server_url.host, &cli->name);

            return NGX_ERROR;
        }

        cli->log = &amcf->log;

        if (cli->domains->nelts == 0) {
            cf->conf_file->line = cli->cf_line;
            cf->conf_file->file.name = cli->cf_filename;
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                         "no valid domain name defined for ACME client \"%V\"",
                         &cli->name);
            return NGX_ERROR;
        }

        if (ngx_http_acme_full_path(cf->pool, &amcf->path, &cli->name,
                                    &cli->path)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        name.len = cli->name.len;
        name.data = cli->path.data + cli->path.len - name.len;

        ngx_strlow(name.data, name.data, name.len);

        if (ngx_create_dir(cli->path.data, 0700) == NGX_FILE_ERROR) {
            err = ngx_errno;
            if (err != NGX_EEXIST) {
                ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, err,
                              ngx_create_dir_n " \"%s\" failed",
                              cli->path.data);
                return NGX_ERROR;
            }
        }

        ngx_str_set(&name, "account.key");

        if (ngx_http_acme_key_init(cf, cli, &name, &cli->account_key)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        ngx_str_set(&name, "private.key");

        if (ngx_http_acme_key_init(cf, cli, &name, &cli->private_key)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        cli->private_key_data = ngx_pnalloc(cf->pool,
                                            cli->private_key.file_size + 5);
                                            /* 5 = size of "data:" prefix */
        if (cli->private_key_data == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(cli->private_key_data, "data:", 5);

        if (ngx_http_acme_file_load(cli->log, &cli->private_key.file,
                                    cli->private_key_data + 5,
                                    cli->private_key.file_size)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        ngx_str_set(&name, "certificate.pem");

        if (ngx_http_acme_init_file(cf, &cli->path, &name,
                                    &cli->certificate_file)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        /* In case the certificate file already exits. */
        cli->certificate_file_size = ngx_http_acme_file_size(
                                                 &cli->certificate_file);

        if (cli->certificate_file_size > NGX_ACME_MAX_SH_FILE) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "size of file \"%V\" exceeds %d bytes",
                               &cli->certificate_file.name,
                               NGX_ACME_MAX_SH_FILE);
            return NGX_ERROR;
        }

        if (cli->certificate_file_size > cli->max_cert_size) {
            cli->max_cert_size = cli->certificate_file_size;
        }

        /* 5 = size of "data:" prefix */
        sz = sizeof(ngx_http_acme_sh_cert_t) + cli->max_cert_size + 5;

        shm_size += ngx_align(sz, NGX_ALIGNMENT);
    }

    sz = sizeof(ngx_http_acme_sh_keyauth_t) + amcf->max_key_auth_size;

    shm_size += ngx_align(sz, NGX_ALIGNMENT);

    ngx_str_set(&name, "acme_shm");

    amcf->shm_zone = ngx_shared_memory_add(cf, &name, shm_size, 0);
    if (amcf->shm_zone == NULL) {
        return NGX_ERROR;
    }

    amcf->shm_zone->init = ngx_http_acme_shm_init;
    amcf->shm_zone->data = amcf;
    amcf->shm_zone->noslab = 1;
    amcf->shm_zone->noreuse = 1;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_acme_http_challenge_handler;

    ngx_str_set(&name, "__acme_server");

    v = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_NOCACHEABLE);
    if (v == NULL) {
        return NGX_ERROR;
    }

    v->get_handler = ngx_http_acme_server_variable;
    v->data = (uintptr_t) &amcf->acme_server_var;

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_acme_header_filter;

    return NGX_OK;
}


static void
ngx_http_acme_fds_close(void *data)
{
    ngx_array_t  *clients = data;

    ngx_uint_t          i;
    ngx_acme_client_t  *cli;

    for (i = 0; i < clients->nelts; i++) {

        cli = (ngx_acme_client_t *) clients->elts + i;

        if (!cli->enabled) {
            continue;
        }

        if (cli->account_key.file.fd != NGX_INVALID_FILE) {
            (void) ngx_close_file(cli->account_key.file.fd);
        }

        if (cli->private_key.file.fd != NGX_INVALID_FILE) {
            (void) ngx_close_file(cli->private_key.file.fd);
        }

        if (cli->certificate_file.fd != NGX_INVALID_FILE) {
            (void) ngx_close_file(cli->certificate_file.fd);
        }
    }
}


static ngx_int_t
ngx_http_acme_header_filter(ngx_http_request_t *r)
{
    ngx_buf_t                *b;
    ngx_http_acme_session_t  *ses;

    ses = ngx_http_get_module_ctx(r, ngx_http_acme_module);

    if (ses == NULL) {
        return ngx_http_next_header_filter(r);
    }

    b = ngx_create_temp_buf(r->pool, ses->client->max_cert_size);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->last_buf = 1;

    r->out = ngx_alloc_chain_link(r->pool);
    if (r->out == NULL) {
        return NGX_ERROR;
    }

    r->out->buf = b;
    r->out->next = NULL;

    return NGX_OK;
}


static size_t
ngx_http_acme_file_size(ngx_file_t *file)
{
    size_t           size;
    ngx_file_info_t  fi;

    if (file->fd == NGX_INVALID_FILE) {
        return 0;
    }

    size = 0;

    if (ngx_fd_info(file->fd, &fi) != NGX_FILE_ERROR) {
        size = ngx_file_size(&fi);
    }

    return size;
}


static ngx_int_t
ngx_http_acme_init_file(ngx_conf_t *cf, ngx_str_t *path, ngx_str_t *filename,
    ngx_file_t *file)
{
    file->log = cf->log;

    if (ngx_http_acme_full_path(cf->pool, path, filename, &file->name)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    file->fd = ngx_open_file(file->name.data, NGX_FILE_RDWR, NGX_FILE_OPEN, 0);

    return NGX_OK;
}


static ngx_int_t
ngx_http_acme_shm_init(ngx_shm_zone_t *shm_zone, void *data)
{
    char                       *s;
    size_t                      sz;
    u_char                     *p;
    time_t                      t;
    ngx_uint_t                  i;
    ngx_acme_client_t          *cli;
    ngx_http_acme_sh_cert_t    *shc;
    ngx_http_core_loc_conf_t   *pclcf;
    ngx_http_acme_main_conf_t  *amcf;

    if (shm_zone->shm.exists) {
        /* Angie doesn't support Windows, so this probably can't happen... */
        return NGX_ERROR;
    }

    amcf = shm_zone->data;

    pclcf = ngx_http_acme_get_core_loc_conf(amcf);

    ngx_memcpy(&amcf->log, pclcf->error_log, sizeof(ngx_log_t));
    amcf->log.data = &amcf->log_ctx;
    amcf->log.handler = ngx_http_acme_log_error;

    amcf->sh = (ngx_http_acme_sh_keyauth_t *) shm_zone->shm.addr;
    p = (u_char *) amcf->sh;
    sz = sizeof(ngx_http_acme_sh_keyauth_t) + amcf->max_key_auth_size;

    ngx_memzero(p, sz);
    p += ngx_align(sz, NGX_ALIGNMENT);

    for (i = 0; i < amcf->clients.nelts; i++) {

        cli = (ngx_acme_client_t *) amcf->clients.elts + i;

        if (!cli->enabled) {
            continue;
        }

        shc = (ngx_http_acme_sh_cert_t *) p;
        shc->lock = 0;
        shc->len = cli->certificate_file_size + 5;
        /* 5 = size of "data:" prefix */

        ngx_memcpy(shc->data_start, "data:", 5);

        if (shc->len != 5) {
            t = ngx_http_acme_cert_validity(cli);

            if (t != (time_t) NGX_ERROR && t != (time_t) NGX_DECLINED) {
                s = "valid";
                cli->expiry_time = t;
                cli->renew_time = t - cli->renew_before_expiry;

            } else {
                s = "invalid";
                cli->renew_time = ngx_time();
            }

            if (t != (time_t) NGX_ERROR) {
                if (ngx_http_acme_file_load(cli->log, &cli->certificate_file,
                                            shc->data_start + 5,
                                            cli->certificate_file_size)
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }

            } else {
                s = "couldn't parse";
                shc->len = 5;
            }

        } else {
            if (cli->certificate_file.fd == NGX_INVALID_FILE) {
                cli->certificate_file.fd = ngx_open_file(
                                                   cli->certificate_file.name.data,
                                                   NGX_FILE_RDWR,
                                                   NGX_FILE_CREATE_OR_OPEN,
                                                   NGX_FILE_DEFAULT_ACCESS);

                if (cli->certificate_file.fd == NGX_INVALID_FILE) {
                    return NGX_ERROR;
                }
            }

            s = "no";
            cli->renew_time = ngx_time();
        }

        ngx_log_error(NGX_LOG_NOTICE, cli->log, 0,
                      "%s certificate, renewal scheduled %s, ACME client: %V",
                      s, strtok(ctime(&cli->renew_time), "\n"), &cli->name);

        cli->sh_cert = shc;

        sz = sizeof(ngx_http_acme_sh_cert_t) + cli->max_cert_size + 5;

        p += ngx_align(sz, NGX_ALIGNMENT);
    }

    return NGX_OK;
}


static ngx_http_acme_session_t *
ngx_http_acme_create_session(ngx_acme_client_t *cli)
{
    ngx_log_t                *log;
    ngx_pool_t               *pool;
    ngx_http_acme_session_t  *ses;

    log = cli->log;

    pool = ngx_create_pool(cli->max_cert_size * 2, log);
    if (pool == NULL) {
        return NULL;
    }

    DBG_MEM((cli, "create session pool: %p", pool));

    pool->log = log;

    ses = ngx_pcalloc(pool, sizeof(ngx_http_acme_session_t));
    if (ses == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    ses->pool = pool;
    ses->log = log;
    ses->client = cli;

    NGX_FIBER_INIT(ses->run_state);

    return ses;
}


static void
ngx_http_acme_destroy_session(ngx_http_acme_session_t **ses)
{
    ngx_http_acme_main_conf_t *amcf = ngx_http_acme_get_main_conf();

    DBG_MEM(((*ses)->client, "destroy session pool: %p", (*ses)->pool));

    amcf = ngx_http_acme_get_main_conf();

    ngx_str_null(&amcf->acme_server_var);

    ngx_destroy_pool((*ses)->pool);

    *ses = NULL;
}


static ngx_int_t
ngx_http_acme_init_worker(ngx_cycle_t *cycle)
{
    ngx_acme_client_t          *nearest;
    ngx_http_acme_main_conf_t  *amcf;

    if ((ngx_process != NGX_PROCESS_WORKER
        && ngx_process != NGX_PROCESS_SINGLE) || ngx_worker > 0)
    {
        /* we operate in one (1st) worker only */
        return NGX_OK;
    }

    amcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_acme_module);

    if (amcf == NULL || amcf->ctx == NULL) {
        return NGX_OK;
    }

    nearest = ngx_http_acme_nearest_client(amcf);

    if (!nearest) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0,
              "acme status: no enabled clients in configuration; quitting ...");
        return NGX_OK;
    }

    amcf->current = nearest;

    amcf->dummy = -1;
    amcf->timer_event.data = amcf;
    amcf->timer_event.handler = ngx_http_acme_timer_handler;
    amcf->timer_event.log = cycle->log;
    amcf->timer_event.cancelable = 1;

    ngx_add_timer(&amcf->timer_event, ngx_http_acme_timer_interval(nearest));

    DBG_STATUS((nearest, "certificate scheduled for renewal on %s",
                strtok(ctime(&nearest->renew_time), "\n")));

    return NGX_OK;
}


static ngx_acme_client_t *
ngx_http_acme_nearest_client(ngx_http_acme_main_conf_t *amcf)
{
    ngx_uint_t          i;
    ngx_acme_client_t  *cli, *nearest;

    nearest = NULL;

    for (i = 0; i < amcf->clients.nelts; i++) {
        cli = (ngx_acme_client_t *) amcf->clients.elts + i;

        if (!cli->enabled) {
            continue;
        }

        if (!nearest || cli->renew_time < nearest->renew_time) {
            nearest = cli;
        }
    }

    return nearest;
}


static ngx_msec_t
ngx_http_acme_timer_interval(ngx_acme_client_t *cli)
{
    ngx_int_t  t;

    t = cli->renew_time - ngx_time();

    if (t > 60 * 60 * 24) {
        return 60 * 60 * 24 * 1000;
    }

    if (t > 0) {
        return t * 1000;
    }

    return 1;
}


static int
ngx_http_extract_header(ngx_pool_t *pool, ngx_list_t *headers, char *name,
    ngx_str_t *value)
{
    size_t            len;
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *header;

    len = ngx_strlen(name);

    part = &headers->part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (len == header[i].key.len
            && ngx_strncasecmp(header[i].key.data, (u_char*) name, len) == 0)
        {
            value->data = ngx_pstrdup(pool, &header[i].value);
            if (value->data == NULL) {
                return NGX_ERROR;
            }

            value->len = header[i].value.len;

            return NGX_OK;
        }
    }

    ngx_str_null(value);

    return NGX_DECLINED;
}


static ngx_data_item_t *
ngx_data_object_find(ngx_data_item_t *obj, ngx_str_t *name)
{
    ngx_str_t         str;
    ngx_data_item_t  *item;

    if (!obj || obj->type != NGX_DATA_OBJECT_TYPE) {
        return NULL;
    }

    item = obj->data.child;

    while (item) {
        if (ngx_data_get_string(&str, item) != NGX_OK) {
            /* broken object? */
            return NULL;
        }

        item = item->next;

        if (str.len == name->len
            && ngx_strncmp(str.data, name->data, str.len) == 0)
        {
            return item;
        }

        item = item->next;
    }

    return NULL;
}


static ngx_data_item_t *
ngx_data_object_vget_value(ngx_data_item_t *obj, va_list args)
{
    u_char           *name;
    ngx_str_t         s;
    ngx_data_item_t  *item;

    name = NULL;
    item = obj;

    while (item) {
        name = va_arg(args, u_char *);

        if (!name) {
            if (item == obj) {
                item = NULL;
            }

            return item;
        }

        s.data = name;
        s.len = ngx_strlen(name);

        item = ngx_data_object_find(item, &s);
    }

    return NULL;
}


static ngx_data_item_t *
ngx_data_object_get_value(ngx_data_item_t *obj, ...)
{
    va_list           args;
    ngx_data_item_t  *item;

    va_start(args, obj);
    item = ngx_data_object_vget_value(obj, args);
    va_end(args);

    return item;
}


static ngx_int_t
ngx_data_object_vget_str(ngx_data_item_t *obj, ngx_str_t *s, va_list args)
{
    ngx_data_item_t  *item;

    item = ngx_data_object_vget_value(obj, args);

    if (!item) {
        return NGX_ERROR;
    }

    return ngx_data_get_string(s, item);
}


static ngx_int_t
ngx_data_object_get_str(ngx_data_item_t *obj, ngx_str_t *s, ...)
{
    va_list    args;
    ngx_int_t  rc;

    va_start(args, s);
    rc = ngx_data_object_vget_str(obj, s, args);
    va_end(args);

    return rc;
}


static int
ngx_str_is_ip(ngx_str_t *s)
{
#if (NGX_HAVE_INET6)
    u_char  dummy[16];
#endif

    return ngx_inet_addr(s->data, s->len) != INADDR_NONE
#if (NGX_HAVE_INET6)
           || ngx_inet6_addr(s->data, s->len, dummy) == NGX_OK
#endif
    ;
}


static int
ngx_data_object_str_eq(ngx_data_item_t *obj, char *value, ...)
{
    va_list    args;
    ngx_str_t  v;
    ngx_int_t  rc;

    va_start(args, value);
    rc = ngx_data_object_vget_str(obj, &v, args);
    va_end(args);

    return rc == NGX_OK
           && v.len == ngx_strlen(value)
           && ngx_strncmp(v.data, value, v.len) == 0;
}


static ngx_int_t
ngx_http_acme_extract_uri(ngx_str_t *url, ngx_str_t *uri)
{
    u_char  *s, *end;

    s = ngx_strnstr(url->data, "//", url->len);

    if (!s) {
        return NGX_ERROR;
    }

    s += 2;
    end = url->data + url->len;

    s = ngx_strlchr(s, end, '/');
    if (!s) {
        return NGX_ERROR;
    }

    uri->data = s;
    uri->len = end - s;

    return NGX_OK;
}


static void *
ngx_http_acme_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_acme_main_conf_t  *amcf;

    amcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_acme_main_conf_t));
    if (amcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&amcf->clients, cf->pool, 4, sizeof(ngx_acme_client_t))
        != NGX_OK)
    {
        return NULL;
    }

    amcf->max_key_auth_size = NGX_CONF_UNSET_SIZE;

    return amcf;
}


static char *
ngx_http_acme_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_acme_main_conf_t *amcf = conf;

    if (amcf->path.data == NULL) {
        ngx_str_set(&amcf->path, NGX_HTTP_ACME_CLIENT_PATH);

        if (ngx_conf_full_name(cf->cycle, &amcf->path, 0) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    ngx_conf_init_size_value(amcf->max_key_auth_size, 2 * 1024);

    return NGX_CONF_OK;
}


static void *
ngx_http_acme_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_acme_srv_conf_t  *ascf;

    ascf = ngx_pcalloc(cf->pool, sizeof(ngx_http_acme_srv_conf_t));
    if (ascf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&ascf->clients, cf->pool, 4, sizeof(ngx_acme_client_t *))
        != NGX_OK)
    {
        return NULL;
    }

    return ascf;
}


static ngx_int_t
ngx_http_acme_cert_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_acme_client_t *cli = (ngx_acme_client_t *) data;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = !cli->enabled;

    if (v->not_found) {
        return NGX_OK;
    }

    ngx_rwlock_rlock(&cli->sh_cert->lock);

    if (cli->sh_cert->len == 5) { /* 5 = size of "data:" prefix */
        v->not_found = 1;

    } else {
        v->len = cli->sh_cert->len;

        v->data = ngx_pnalloc(r->pool, v->len);
        if (v->data != NULL) {
            ngx_memcpy(v->data, cli->sh_cert->data_start, cli->sh_cert->len);
        }
    }

    ngx_rwlock_unlock(&cli->sh_cert->lock);

    return (v->not_found || v->data != NULL) ? NGX_OK : NGX_ERROR;
}


static ngx_int_t
ngx_http_acme_cert_key_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_acme_client_t *cli = (ngx_acme_client_t *) data;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = !cli->enabled;

    if (v->not_found) {
        return NGX_OK;
    }

    v->len = cli->private_key.file_size + 5 /* 5 = size of "data:" prefix */;
    v->data = cli->private_key_data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_acme_server_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t  *acme_server_var = (ngx_str_t *) data;

    if (acme_server_var->len == 0) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "internal error: ACME server variable not set");
        return NGX_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = acme_server_var->data;
    v->len = acme_server_var->len;

    return NGX_OK;
}


static char *
ngx_http_acme_client(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_acme_main_conf_t *amcf = conf;

    ngx_url_t           u;
    ngx_str_t          *value;
    ngx_uint_t          i;
    ngx_acme_client_t  *cli;

    value = cf->args->elts;

    cli = ngx_acme_client_add(cf, &value[1]);
    if (cli == NULL) {
        return NGX_CONF_ERROR;
    }

    if (cli->server.len != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "ACME client %V is already defined in %V:%ui",
                            &value[1], &cli->cf_filename, cli->cf_line);

        return NGX_CONF_ERROR;
    }

    cli->cf_line = cf->conf_file->line;
    cli->cf_filename = cf->conf_file->file.name;
    cli->server = value[2];

    for (i = 3; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "enabled=", 8) == 0) {

            value[i].data += 8;
            value[i].len -= 8;

            if (ngx_strcasecmp(value[i].data, (u_char *) "on") == 0) {
                cli->enabled = 1;

            } else if (ngx_strcasecmp(value[i].data, (u_char *) "off") == 0) {
                cli->enabled = 0;

            } else {
                return "has an invalid \"enabled\" value";
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "key_type=", 9) == 0) {

            value[i].data += 9;
            value[i].len -= 9;

            if (ngx_strcasecmp(value[i].data, (u_char *) "rsa") == 0) {
                cli->private_key.type = NGX_KT_RSA;

            } else if (ngx_strcasecmp(value[i].data, (u_char *) "ecdsa") == 0) {
                cli->private_key.type = NGX_KT_EC;

            } else {
                return "has an invalid \"key_type\" value";
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "key_bits=", 9) == 0) {

            value[i].data += 9;
            value[i].len -= 9;

            cli->private_key.bits = ngx_atoi(value[i].data, value[i].len);

            if (cli->private_key.bits == NGX_ERROR) {
                return "has an invalid \"key_bits\" value";
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "email=", 6) == 0) {

            value[i].data += 6;
            value[i].len -= 6;

            cli->email = value[i];

            continue;
        }

        if (ngx_strncmp(value[i].data, "renew_before_expiry=", 20) == 0) {

            value[i].data += 20;
            value[i].len -= 20;

            cli->renew_before_expiry = ngx_parse_time(&value[i], 1);

            if (cli->renew_before_expiry == (time_t) NGX_ERROR) {
                return "has an invalid \"renew_before_expiry\" value";
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "retry_after_error=", 18) == 0) {

            value[i].data += 18;
            value[i].len -= 18;

            if (ngx_strcasecmp(value[i].data, (u_char *) "off") == 0) {
                cli->retry_after_error = NGX_ACME_MAX_TIME;

            } else {
                cli->retry_after_error = ngx_parse_time(&value[i], 1);

                if (cli->retry_after_error == (time_t) NGX_ERROR) {
                    return "has an invalid \"retry_after_error\" value";
                }
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "max_cert_size=", 14) == 0) {

            value[i].data += 14;
            value[i].len -= 14;

            cli->max_cert_size = ngx_parse_size(&value[i]);

            if (cli->max_cert_size == (size_t) NGX_ERROR) {
                return "has an invalid \"max_cert_size\" value";
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "max_key_auth_size=", 18) == 0) {

            value[i].data += 18;
            value[i].len -= 18;

            if (amcf->max_key_auth_size != NGX_CONF_UNSET_SIZE) {
                return "has a duplicate \"max_key_auth_size\" parameter";
            }

            amcf->max_key_auth_size = ngx_parse_size(&value[i]);

            if (amcf->max_key_auth_size == (size_t) NGX_ERROR) {
                return "has an invalid \"max_key_auth_size\" value";
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);

        return NGX_CONF_ERROR;
    }

    if (!cli->enabled) {
        return NGX_CONF_OK;
    }

    if (cli->enabled == NGX_CONF_UNSET_UINT) {
        cli->enabled = 1;
    }

    if (cli->private_key.type == NGX_KT_UNSUPPORTED) {
        cli->private_key.type = NGX_KT_EC;
    }

    if (cli->private_key.bits == NGX_CONF_UNSET){
        if (cli->private_key.type == NGX_KT_EC) {
            cli->private_key.bits = 256;

        } else {
            cli->private_key.bits = 2048;
        }
    }

    /*
     * CertBot's parameters for new ACME account keys.
     * TODO Do we want this configurable?
     */
    cli->account_key.type = NGX_KT_RSA;
    cli->account_key.bits = 2048;

    /*
     * Sanity check. Note that some of the key types we support may not
     * be supported by certificate authorities (and vice versa). For example,
     * Let's Encrypt at the time of this writing "accepts only RSA keys that
     * are 2048, 3072, or 4096 bits in length and P-256 or P-384 ECDSA keys"
     * (https://letsencrypt.org/docs/integration-guide/). It is up to the user
     * to choose the appropriate key type.
     */
    if (!ngx_http_acme_key_supported(cli->private_key.type,
                                     cli->private_key.bits))
    {
        return "has an unsupported key_type/key_bits combination";
    }

    if (cli->renew_before_expiry == NGX_CONF_UNSET) {
        cli->renew_before_expiry = 60 * 60 * 24 * 30;
    }

    if (cli->retry_after_error == NGX_CONF_UNSET) {
        cli->retry_after_error = 60 * 60 * 2;
    }

    if (cli->max_cert_size == NGX_CONF_UNSET_SIZE) {
        cli->max_cert_size = 8 * 1024;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = cli->server;
    u.uri_part = 1;
    u.no_resolve = 1;

    if (ngx_strncasecmp(u.url.data, (u_char *) "http://", 7) == 0) {
        u.url.data += 7;
        u.url.len -= 7;
        u.default_port = 80;

    } else if (ngx_strncasecmp(u.url.data, (u_char *) "https://", 8) == 0) {
        u.url.data += 8;
        u.url.len -= 8;
        u.default_port = 443;

        cli->ssl = 1;

    } else {
        return "requires \"http://\" or \"https://\" as URL prefix for "
               "specified ACME server";
    }

    u.uri_part = 1;
    u.no_resolve = 1;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                               "%s in ACME server URL \"%V\"", u.err,
                               &cli->server);

        } else {
            ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                               "invalid ACME server URL \"%V\"", &cli->server);
        }

        return NGX_CONF_ERROR;
    }

    if (u.uri.len == 0) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                           "no path component in ACME server URL \"%V\"",
                           &cli->server);
        return NGX_CONF_ERROR;
    }

    cli->server_url = u;

    if (amcf->ctx == NULL) {
        if (ngx_http_acme_create_conf_ctx(cf, amcf) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        if (ngx_http_acme_add_proxy_pass(cf, amcf) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_acme_create_conf_ctx(ngx_conf_t *cf, ngx_http_acme_main_conf_t *amcf)
{
    ngx_uint_t            mi, m;
    ngx_http_module_t    *module;
    ngx_http_conf_ctx_t  *ctx, *pctx;

    pctx = cf->ctx;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->main_conf = pctx->main_conf;

    ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_ERROR;
    }

    ctx->loc_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
    if (ctx->loc_conf == NULL) {
        return NGX_ERROR;
    }

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        mi = cf->cycle->modules[m]->ctx_index;

        if (module->create_srv_conf) {
            ctx->srv_conf[mi] = module->create_srv_conf(cf);
            if (ctx->srv_conf[mi] == NULL) {
                return NGX_ERROR;
            }
        }

        if (module->create_loc_conf) {
            ctx->loc_conf[mi] = module->create_loc_conf(cf);
            if (ctx->loc_conf[mi] == NULL) {
                return NGX_ERROR;
            }
        }
    }

    amcf->ctx = ctx;

    return NGX_OK;
}


static ngx_int_t
ngx_http_acme_add_proxy_pass(ngx_conf_t *cf, ngx_http_acme_main_conf_t *amcf)
{
    static const ngx_str_t proxy_pass = ngx_string("proxy_pass $__acme_server; "
                                                   "access_log off;");

    char             *rv;
    ngx_buf_t         b;
    ngx_conf_t        pcf;
    ngx_conf_file_t   conf_file;

    ngx_memzero(&conf_file, sizeof(ngx_conf_file_t));
    ngx_memzero(&b, sizeof(ngx_buf_t));

    b.start = proxy_pass.data;
    b.pos = b.start;
    b.last = b.start + proxy_pass.len;
    b.end = b.last;
    b.temporary = 1;

    conf_file.file.fd = NGX_INVALID_FILE;
    conf_file.file.name.data = NULL;
    conf_file.line = 0;

    pcf = *cf;
    cf->ctx = amcf->ctx;

    cf->conf_file = &conf_file;
    cf->conf_file->buffer = &b;

    cf->cmd_type = NGX_HTTP_LOC_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv == NGX_CONF_OK) {
        return NGX_OK;
    }

    if (rv != NGX_CONF_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s", rv);
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_acme_merge_conf_ctx(ngx_conf_t *cf, ngx_http_acme_main_conf_t *amcf)
{
    char                 *rv;
    ngx_uint_t            mi, m;
    ngx_http_module_t    *module;
    ngx_http_conf_ctx_t  *ctx;

    rv = NGX_CONF_OK;
    ctx = amcf->ctx;

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        mi = cf->cycle->modules[m]->ctx_index;

        ngx_http_acme_merge_conf_ctx_fix(cf, cf->cycle->modules[m], ctx);

        if (module->merge_srv_conf) {
            rv = module->merge_srv_conf(cf, ctx->srv_conf[mi],
                                        ctx->srv_conf[mi]);

            if (rv != NGX_CONF_OK) {
                break;
            }
        }

        if (module->merge_loc_conf) {
            rv = module->merge_loc_conf(cf, ctx->loc_conf[mi],
                                        ctx->loc_conf[mi]);

            if (rv != NGX_CONF_OK) {
                break;
            }
        }
    }

    if (rv == NGX_CONF_OK) {
        return NGX_OK;
    }

    if (rv != NGX_CONF_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s", rv);
    }

    return NGX_ERROR;
}


static void
ngx_http_acme_merge_conf_ctx_fix(ngx_conf_t *cf, ngx_module_t *module,
    ngx_http_conf_ctx_t *ctx)
{
    u_char                *conf, *prev;
    ngx_uint_t             ctx_index;
    ngx_command_t         *cmd;
    ngx_http_conf_ctx_t   *prev_ctx;
    ngx_http_module_t     *mod;

    ctx_index = module->ctx_index;
    prev_ctx = cf->ctx;
    mod = module->ctx;

    cmd = module->commands;
    if (cmd == NULL) {
        return;
    }

    for ( /* void */ ; cmd->name.len; cmd++) {
        if (cmd->set != ngx_conf_set_path_slot) {
            continue;
        }

        if (mod->merge_srv_conf && cmd->conf == NGX_HTTP_SRV_CONF_OFFSET) {
            conf = ctx->srv_conf[ctx_index];
            prev = prev_ctx->srv_conf[ctx_index];

        } else if (mod->merge_loc_conf && cmd->conf == NGX_HTTP_LOC_CONF_OFFSET) {
            conf = ctx->loc_conf[ctx_index];
            prev = prev_ctx->loc_conf[ctx_index];

        } else  {
            continue;
        }

        conf += cmd->offset;
        prev += cmd->offset;

        *(ngx_path_t**)conf = *(ngx_path_t**)prev;

    }
}


static char *
ngx_http_acme(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_acme_srv_conf_t *ascf = conf;

    ngx_str_t          *value;
    ngx_uint_t          i;
    ngx_acme_client_t  *cli, **clients;

    value = cf->args->elts;

    cli = ngx_acme_client_add(cf, &value[1]);
    if (cli == NULL) {
        return NGX_CONF_ERROR;
    }

    clients = ascf->clients.elts;

    for (i = 0; i < ascf->clients.nelts; i++) {
        if (cli == clients[i]) {
            ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                               "duplicate \"acme %V\" directive", &cli->name);

            return NGX_CONF_ERROR;
        }
    }

    clients = ngx_array_push(&ascf->clients);
    if (clients == NULL) {
        return NULL;
    }

    *clients = cli;

    return NGX_CONF_OK;
}


static ngx_acme_client_t *
ngx_acme_client_add(ngx_conf_t *cf, ngx_str_t *name)
{
    ngx_uint_t                  i;
    ngx_acme_client_t          *cli;
    ngx_http_variable_t        *v;
    ngx_http_acme_main_conf_t  *amcf;

    if (name->len == 0) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "invalid ACME client name");
        return NULL;
    }

    amcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_acme_module);

    for (i = 0; i < amcf->clients.nelts; i++) {
        cli = (ngx_acme_client_t *) amcf->clients.elts + i;

        if (cli->name.len != name->len
            || ngx_strncasecmp(cli->name.data, name->data, name->len) != 0)
        {
            continue;
        }

        return cli;
    }

    cli = ngx_array_push(&amcf->clients);
    if (cli == NULL) {
        return NULL;
    }

    ngx_memzero(cli, sizeof(ngx_acme_client_t));

    cli->account_key.file.fd = NGX_INVALID_FILE;
    cli->private_key.file.fd = NGX_INVALID_FILE;
    cli->certificate_file.fd = NGX_INVALID_FILE;

    cli->log = cf->log;

    cli->name = *name;
    cli->enabled = NGX_CONF_UNSET_UINT;
    cli->private_key.type = NGX_KT_UNSUPPORTED;
    cli->private_key.bits = NGX_CONF_UNSET;
    cli->renew_before_expiry = NGX_CONF_UNSET;
    cli->retry_after_error = NGX_CONF_UNSET;
    cli->max_cert_size = NGX_CONF_UNSET_SIZE;

    cli->domains = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
    if (cli->domains == NULL) {
        return NULL;
    }

    for (v = ngx_http_acme_vars; v->name.len; v++) {
        if (ngx_http_acme_add_client_var(cf, cli, v) != NGX_OK) {
            return NULL;
        }
    }

    return cli;
}


static ngx_int_t
ngx_http_acme_add_client_var(ngx_conf_t *cf, ngx_acme_client_t *cli,
    ngx_http_variable_t *var)
{
    ngx_str_t             name;
    ngx_http_variable_t  *v;

    name.len = var->name.len + cli->name.len;

    name.data = ngx_pnalloc(cf->pool, name.len);
    if (name.data == NULL) {
        return NGX_ERROR;
    }

    ngx_snprintf(name.data, name.len, "%V%V", &var->name, &cli->name);

    v = ngx_http_add_variable(cf, &name, var->flags);

    if (v == NULL) {
        return NGX_ERROR;
    }

    v->get_handler = var->get_handler;
    v->data = (uintptr_t) cli;

    return NGX_OK;
}


static ngx_int_t
ngx_str_eq(ngx_str_t *s1, const char *s2)
{
    return s1->len == ngx_strlen(s2)
           && ngx_strncmp(s1->data, (u_char *) s2, s1->len) == 0;
}


static ngx_int_t
ngx_strcase_eq(ngx_str_t *s1, char *s2)
{
    return s1->len == ngx_strlen(s2)
           && ngx_strncasecmp(s1->data, (u_char *) s2, s1->len) == 0;
}


static ngx_int_t
ngx_str_clone(ngx_pool_t *pool, ngx_str_t *dst, ngx_str_t *src)
{
    u_char  *p;

    if (src != NULL && src->len != 0) {
        p = ngx_pstrdup(pool, src);
        if (!p) {
            return NGX_ERROR;
        }

        dst->data = p;
        dst->len = src->len;

    } else {
        ngx_str_null(dst);
    }

    return NGX_OK;
}


static ngx_uint_t
ngx_dec_count(ngx_int_t i)
{
    ngx_uint_t  rc;

    rc = 1;

    if (i < 0) {
        i = -1;
        rc++;
    }

    while (i > 9) {
        i /= 10;
        rc++;
    }

    return rc;
}


static int
ngx_clone_table_elt(ngx_pool_t *pool, ngx_str_t *dst,
    ngx_table_elt_t *src)
{
    if (src != NULL && src->value.len != 0) {
        dst->data = ngx_pstrdup(pool, &src->value);
        if (dst->data == NULL) {
            return NGX_ERROR;
        }

        dst->len = src->value.len;

    } else {
        ngx_str_null(dst);
    }

    return NGX_OK;
}

