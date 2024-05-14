
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
            ngx_add_timer(&ses->client->main_conf->timer_event, 10);          \
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
typedef struct ngx_http_acme_loc_conf_s    ngx_http_acme_loc_conf_t;
typedef struct ngx_http_acme_session_s     ngx_http_acme_session_t;
typedef struct ngx_http_acme_sh_keyauth_s  ngx_http_acme_sh_keyauth_t;
typedef struct ngx_http_acme_sh_cert_s     ngx_http_acme_sh_cert_t;
typedef struct ngx_http_acme_sh_key_s      ngx_http_acme_sh_key_t;


struct ngx_acme_client_s {
    ngx_log_t                   log;
    ngx_http_log_ctx_t          log_ctx;
    ngx_http_acme_main_conf_t  *main_conf;
    ngx_http_conf_ctx_t        *conf_ctx;
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
    size_t                      max_cert_key_size;
    ngx_http_upstream_conf_t    upstream;
    ngx_uint_t                  ssl;
    ngx_acme_privkey_t          account_key;
    ngx_acme_privkey_t          private_key;
    ngx_str_t                   certificate;
    ngx_file_t                  certificate_file;
    size_t                      certificate_file_size;
    ngx_http_acme_session_t    *session;
    ngx_http_acme_sh_cert_t    *sh_cert;
    ngx_http_acme_sh_key_t     *sh_cert_key;
};


struct ngx_http_acme_main_conf_s {
    void                       *dummy_ptrs[3];
    /* event ident must be after 3 pointers as in ngx_connection_t */
    ngx_int_t                   dummy;
    ngx_acme_client_t          *current;
    ngx_array_t                 clients;
    ngx_event_t                 timer_event;
    size_t                      max_key_auth_size;
    size_t                      shm_size;
    ngx_shm_zone_t             *shm_zone;
    ngx_http_acme_sh_keyauth_t *sh;
    ngx_str_t                   path;
};


struct ngx_http_acme_srv_conf_s {
    ngx_acme_client_t          *client;
};


struct ngx_http_acme_loc_conf_s {
    ngx_http_conf_ctx_t         conf_ctx;
    ngx_http_core_loc_conf_t   *clcf;
};


struct ngx_http_acme_session_s {
    ngx_pool_t                 *pool;
    ngx_log_t                  *log;
    ngx_acme_client_t          *client;
    ngx_peer_connection_t       peer;
    ngx_http_request_t         *request;
    ngx_http_status_t           response_status;
    ngx_int_t                   request_result;
    ngx_buf_t                  *response;
    ngx_int_t                   response_overflow;
    ngx_str_t                   request_url;
    ngx_data_item_t            *dir;
    ngx_str_t                   status_line;
    ngx_int_t                   status_code;
    ngx_str_t                   headers;
    ngx_str_t                   body;
    ngx_data_item_t            *json;
    ngx_str_t                   nonce;
    ngx_str_t                   content_type;
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
static int ngx_http_extract_header(ngx_str_t * headers, char *name,
    ngx_str_t *value);
static ngx_msec_t ngx_http_acme_timer_interval(ngx_acme_client_t *cli);
static ngx_acme_client_t *ngx_http_acme_nearest_client(
    ngx_http_acme_main_conf_t  *amcf);
static ngx_http_acme_session_t *ngx_http_acme_create_session(
    ngx_acme_client_t *cli);
static void ngx_http_acme_destroy_session(ngx_http_acme_session_t **ses);
static ngx_int_t ngx_http_acme_postconfiguration(ngx_conf_t *cf);
static void ngx_http_acme_fds_close(void *data);
static size_t ngx_http_acme_file_size(ngx_file_t *file);
static ngx_int_t ngx_http_acme_init_file(ngx_conf_t *cf, ngx_str_t *path,
    ngx_str_t *filename, ngx_file_t *file);
static ngx_int_t ngx_http_acme_shm_init(ngx_shm_zone_t *shm_zone, void *data);
static void *ngx_http_acme_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_acme_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_acme_create_srv_conf(ngx_conf_t *cf);
static void *ngx_http_acme_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_acme_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);

static ngx_int_t ngx_http_acme_init_worker(ngx_cycle_t *cycle);
static void ngx_http_acme_dummy_cleanup(void *data);
static void *ngx_http_acme_get_ctx(ngx_http_request_t *r);
static ngx_int_t ngx_http_acme_set_ctx(ngx_http_request_t *r, void *data);
static ngx_int_t ngx_http_acme_init_accounts(ngx_http_acme_main_conf_t *amcf);
static ngx_int_t ngx_http_acme_account_init(ngx_acme_client_t *cli,
     u_char **shmem);
static ngx_int_t ngx_http_acme_file_load(ngx_log_t *log,
    ngx_file_t *open_file, u_char *buf, size_t size);
static ngx_int_t ngx_http_acme_key_init(ngx_acme_client_t *cli,
    ngx_acme_privkey_t *key);
static ngx_int_t ngx_http_acme_key_gen(ngx_acme_client_t *cli,
    ngx_acme_privkey_t *key);
static ngx_int_t ngx_http_acme_key_load(ngx_acme_client_t *cli,
    ngx_acme_privkey_t *key);
static void ngx_http_acme_key_free(ngx_acme_privkey_t *key);
static ngx_int_t ngx_http_acme_load_keys(ngx_acme_client_t *cli);
static void ngx_http_acme_free_keys(ngx_acme_client_t *cli);
static ngx_int_t ngx_http_acme_csr_gen(ngx_http_acme_session_t *ses,
    u_char status_req, ngx_acme_privkey_t *key, ngx_str_t *csr);
static ngx_int_t ngx_http_acme_identifiers(ngx_http_acme_session_t *ses,
    ngx_str_t *identifiers);
static ngx_int_t ngx_http_acme_jwk_thumbprint(ngx_http_acme_session_t *ses,
    ngx_acme_privkey_t *key, ngx_str_t *thumbprint);
static ngx_int_t ngx_http_acme_cert_validity(ngx_acme_client_t *cli);
static ngx_int_t ngx_http_acme_full_path(ngx_pool_t *pool, ngx_str_t *name,
    ngx_str_t *filename, ngx_str_t *full_path);
static ngx_int_t ngx_http_acme_init_connection(ngx_http_acme_session_t *ses);
static ngx_http_request_t *ngx_http_acme_init_request(
    ngx_http_acme_session_t *ses, ngx_uint_t method, ngx_str_t *url,
    ngx_str_t *body);
static void ngx_http_acme_request_cleanup(void *data);
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
static ngx_int_t ngx_http_acme_response_handler(ngx_http_acme_session_t *ses);
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

static ngx_int_t ngx_http_acme_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_http_acme_cert_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_acme_cert_key_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_acme_upstream_set_ssl(ngx_conf_t *cf,
    ngx_acme_client_t *cli);
static ngx_int_t ngx_acme_upstream_handler(ngx_http_request_t *r);
static ngx_int_t ngx_acme_upstream_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_acme_upstream_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_acme_upstream_process_status_line(ngx_http_request_t *r);
static ngx_int_t ngx_acme_upstream_process_header(ngx_http_request_t *r);
static void ngx_acme_upstream_abort_request(ngx_http_request_t *r);
static void ngx_acme_upstream_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);

static ngx_acme_client_t *ngx_acme_client_add(ngx_conf_t *cf, ngx_str_t *name);

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
    ngx_http_acme_preconfiguration,        /* preconfiguration */
    ngx_http_acme_postconfiguration,       /* postconfiguration */

    ngx_http_acme_create_main_conf,        /* create main configuration */
    ngx_http_acme_init_main_conf,          /* init main configuration */

    ngx_http_acme_create_srv_conf,         /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_acme_create_loc_conf,         /* create location configuration */
    ngx_http_acme_merge_loc_conf           /* merge location configuration */
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
      0, NGX_HTTP_VAR_PREFIX, 0 },

    { ngx_string("acme_cert_key_"), NULL, ngx_http_acme_cert_key_variable,
      0, NGX_HTTP_VAR_PREFIX, 0 },

    ngx_http_null_variable
};


static u_char *
ngx_http_acme_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char              *p;
    ngx_acme_client_t   *cli;
    ngx_http_log_ctx_t  *ctx;

    ctx = log->data;
    cli = ngx_container_of(ctx, ngx_acme_client_t, log_ctx);

    p = ngx_snprintf(buf, len, ", ACME client: %V", &cli->name);

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

    log = &cli->log;

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

    log = &cli->log;

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

    log = &cli->log;

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
    int            n;
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

    if (BN_bn2bin(br, p) != n) {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0, "BN_bn2bin() failed");
        goto failed;
    }

    if (n >= (int) hash_size) {
        ngx_memcpy(new_sig, p + n - hash_size, hash_size);
    } else {
        ngx_memcpy(new_sig + hash_size - n, p, n);
    }

    n = BN_num_bytes(bs);
    p = ngx_pcalloc(ses->pool, n);

    if (!p) {
        goto failed;
    }

    if (BN_bn2bin(bs, p) != n) {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0, "BN_bn2bin() failed");
        goto failed;
    }

    if (n >= (int) hash_size) {
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
ngx_http_acme_init_accounts(ngx_http_acme_main_conf_t *amcf)
{
    size_t              len;
    u_char             *p;
    ngx_uint_t          i;
    ngx_acme_client_t  *cli;

    p = (u_char *) amcf->sh;
    len = sizeof(ngx_http_acme_sh_keyauth_t) + amcf->max_key_auth_size;

    ngx_memzero(p, len);
    p += len;

    for (i = 0; i < amcf->clients.nelts; i++) {

        cli = (ngx_acme_client_t *) amcf->clients.elts + i;

        if (!cli->enabled) {
            continue;
        }

        if (ngx_http_acme_account_init(cli, &p) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_acme_account_init(ngx_acme_client_t *cli, u_char **shmem)
{
    u_char                   *p;
    u_short                   size;
    ngx_int_t                 rc;
    ngx_http_acme_sh_key_t   *shk;
    ngx_http_acme_sh_cert_t  *shc;

    /*
     * CertBot's parameters for new ACME account keys.
     * TODO Do we want this configurable?
     */
    cli->account_key.type = NGX_KT_RSA;
    cli->account_key.bits = 2048;

    rc = ngx_http_acme_key_init(cli, &cli->account_key);

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_EMERG, &cli->log, 0,
                      "failed to initialize account key for ACME client \"%V\"",
                      &cli->name);

        return NGX_ERROR;
    }

    size = cli->private_key.file_size;

    rc = ngx_http_acme_key_init(cli, &cli->private_key);

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_EMERG, &cli->log, 0,
                      "failed to initialize private key for ACME client \"%V\"",
                      &cli->name);

        return NGX_ERROR;
    }

    if (size == 0) {
        if (cli->private_key.file_size > cli->max_cert_key_size) {
            ngx_log_error(NGX_LOG_EMERG, &cli->log, 0,
                          "file \"%s\" is too large to fit in shared memory",
                          cli->private_key.file.name.data);

            return NGX_ERROR;
        }

        size = cli->max_cert_key_size;
    }

    p = *shmem;
    shk = (ngx_http_acme_sh_key_t *) p;
    shk->len = cli->private_key.file_size;

    if (ngx_http_acme_file_load(&cli->log, &cli->private_key.file,
                                shk->data_start, shk->len)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    cli->sh_cert_key = shk;

    size += sizeof(ngx_http_acme_sh_key_t);

    p += ngx_align(size, NGX_ALIGNMENT);

    shc = (ngx_http_acme_sh_cert_t *) p;
    shc->lock = 0;
    shc->len = cli->certificate_file_size;

    if (shc->len != 0) {
        rc = ngx_http_acme_cert_validity(cli);

        if (rc > 0) {
            cli->expiry_time = rc;
            cli->renew_time = rc - cli->renew_before_expiry;

        } else {
            cli->renew_time = ngx_time();
        }

        if (rc != NGX_ERROR) {
            if (ngx_http_acme_file_load(&cli->log, &cli->certificate_file,
                                        shc->data_start, shc->len)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

        } else {
            shc->len = 0;
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

        cli->renew_time = ngx_time();
    }

    ngx_log_error(NGX_LOG_NOTICE, &cli->log, 0,
                  "%s certificate, renewal scheduled %s",
                  (shc->len != 0) ? ((rc > 0) ? "valid" : "invalid") : "no",
                  strtok(ctime(&cli->renew_time), "\n"));

    cli->sh_cert = shc;

    p += sizeof(ngx_http_acme_sh_cert_t) + cli->max_cert_size;
    *shmem = p;

    return NGX_OK;
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
ngx_http_acme_key_init(ngx_acme_client_t *cli, ngx_acme_privkey_t *key)
{
    ngx_uint_t       retry;
    ngx_file_info_t  fi;

    if (key->file.fd == NGX_INVALID_FILE) {
        key->file.fd = ngx_open_file(key->file.name.data, NGX_FILE_RDWR,
                                     NGX_FILE_CREATE_OR_OPEN,
                                     NGX_FILE_OWNER_ACCESS);

        if (key->file.fd == NGX_INVALID_FILE) {
            return NGX_ERROR;
        }
    }

    for (retry = 1; /* void */ ; retry--) {

        if (ngx_fd_info(key->file.fd, &fi) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, &cli->log, ngx_errno,
                          ngx_fd_info_n " \"%s\" failed", key->file.name.data);

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

    ngx_log_error(NGX_LOG_ALERT, &cli->log, 0, "zero size of key file \"%s\"",
                  key->file.name.data);

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
        ngx_log_error(NGX_LOG_ALERT, &cli->log, ngx_errno,
                      "lseek() %i failed", (ngx_uint_t) key->file.fd);
        return NGX_ERROR;
    }

    bio = BIO_new_fd(key->file.fd, BIO_NOCLOSE);

    if (bio == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, &cli->log, 0,
                      "BIO_new_fd(\"%i\") failed", (ngx_uint_t) key->file.fd);

        return NGX_ERROR;
    }

    rc = NGX_ERROR;

    /* silence false alarms in some compilers (e.g. clang 16.0.6) */
    t = NGX_KT_UNSUPPORTED;
    bits = 0;

    k = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);

    if (k == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, &cli->log, 0,
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
            ngx_log_error(NGX_LOG_ALERT, &cli->log, 0,
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
        ngx_ssl_error(NGX_LOG_ALERT, &cli->log, 0, "acme: wrong key type");
        return NGX_ERROR;
    }

    epc = EVP_PKEY_CTX_new_id(n, NULL);

    if (!epc) {
        ngx_ssl_error(NGX_LOG_ALERT, &cli->log, 0,
                      "EVP_PKEY_CTX_new_id() failed");
        return NGX_ERROR;
    }

    rc = NGX_ERROR;
    bio = NULL;
    k = NULL;

    if (!EVP_PKEY_keygen_init(epc)) {
        ngx_ssl_error(NGX_LOG_ALERT, &cli->log, 0,
                      "EVP_PKEY_keygen_init() failed");
        goto failed;
    }

    if (key->type == NGX_KT_RSA) {
        if (!EVP_PKEY_CTX_set_rsa_keygen_bits(epc, key->bits)) {
            ngx_ssl_error(NGX_LOG_ALERT, &cli->log, 0,
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
            ngx_ssl_error(NGX_LOG_ALERT, &cli->log, 0, "acme: wrong key size");
            goto failed;
        }

        if (!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(epc, n)) {
            ngx_ssl_error(NGX_LOG_ALERT, &cli->log, 0,
                          "EVP_PKEY_CTX_set_ec_paramgen_curve_nid");
            goto failed;
        }
    }

    if (!EVP_PKEY_keygen(epc, &k)) {
        ngx_ssl_error(NGX_LOG_ALERT, &cli->log, 0, "EVP_PKEY_keygen() failed");
        goto failed;
    }

    bio = BIO_new_fd(key->file.fd, BIO_NOCLOSE);

    if (bio == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, &cli->log, 0,
                      "BIO_new_fd(\"%i\") failed", (ngx_uint_t) key->file.fd);

        goto failed;
    }

    if (!PEM_write_bio_PrivateKey(bio, k, NULL, NULL, 0, NULL, NULL)) {
        ngx_ssl_error(NGX_LOG_ALERT, &cli->log, 0,
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
ngx_http_acme_csr_gen(ngx_http_acme_session_t *ses, u_char status_req,
    ngx_acme_privkey_t *key, ngx_str_t *csr)
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

    ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, (char *) san);
    if (!ext) {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0, "X509V3_EXT_conf_nid() failed");
        goto failed;
    }

    sk_X509_EXTENSION_push(exts, ext);

    ext = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, key_usage);
    if (!ext) {
        ngx_ssl_error(NGX_LOG_ERR, ses->log, 0, "X509V3_EXT_conf_nid() failed");
        goto failed;
    }

    sk_X509_EXTENSION_push(exts, ext);

    if (status_req) {
        /* ocsp must-staple extension */
        ext = X509V3_EXT_conf_nid(NULL, NULL, NID_tlsfeature, "status_request");
        if (!ext) {
            ngx_ssl_error(NGX_LOG_ERR, ses->log, 0,
                          "X509V3_EXT_conf_nid() failed");
            goto failed;
        }

        sk_X509_EXTENSION_push(exts, ext);
    }

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


/*
 * Return values:
 * + expiry time of the certificate if the certificate is valid;
 * + NGX_DECLINED if the certificate is invalid (e.g. expired);
 * + NGX_ERROR if an OpenSSL or system error occurred.
 */
static ngx_int_t
ngx_http_acme_cert_validity(ngx_acme_client_t *cli)
{
    int               type, i, found;
    BIO              *bio;
    X509             *x509;
    u_char           *s;
    struct tm         tm;
    ngx_int_t         rc;
    ngx_uint_t        di;
    ngx_str_t         domain;
    X509_NAME        *subj_name;
    ASN1_STRING      *value;
    GENERAL_NAME     *name;
    GENERAL_NAMES    *sans;
    const ASN1_TIME  *t;
    X509_NAME_ENTRY  *entry;

    if (lseek(cli->certificate_file.fd, 0, SEEK_SET) == -1) {
        ngx_log_error(NGX_LOG_ALERT, &cli->log, ngx_errno,
                      "lseek() %i failed",
                      (ngx_uint_t) cli->certificate_file.fd);
        return NGX_ERROR;
    }

    bio = BIO_new_fd(cli->certificate_file.fd, BIO_NOCLOSE);

    if (bio == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, &cli->log, 0, "BIO_new_fd(\"%i\") failed",
                      (ngx_uint_t) cli->certificate_file.fd);
        return NGX_ERROR;
    }

    x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);

    if (x509 == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, &cli->log, 0,
                      "PEM_read_bio_X509() failed");
        BIO_free(bio);
        return NGX_ERROR;
    }

    ngx_memzero(&tm, sizeof(struct tm));

#if OPENSSL_VERSION_NUMBER > 0x10100000L
    t = X509_get0_notAfter(x509);
#else
    t = X509_get_notAfter(x509);
#endif

    if (!t || !ASN1_TIME_to_tm(t, &tm)) {
        ngx_log_error(NGX_LOG_ALERT, &cli->log, 0,
                      "invalid time in certificate \"%V\"", &cli->certificate);
        rc = NGX_ERROR;
        goto failed;
    }

    rc = timegm(&tm);

    if (ngx_time() >= rc) {
        /* expired */
        rc = NGX_DECLINED;
        goto failed;
    }

    sans = X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);

    if (!sans) {
        ngx_log_error(NGX_LOG_ALERT, &cli->log, 0,
                      "no SAN entry in certificate \"%V\"", &cli->certificate);
        rc = NGX_DECLINED;
        goto failed;
    }

    subj_name = X509_get_subject_name(x509);

    for (di = 0; di < cli->domains->nelts; di++) {

        domain = ((ngx_str_t*) cli->domains->elts)[di];
        found = 0;

        for (i = 0; i < sk_GENERAL_NAME_num(sans); i++) {

            name = sk_GENERAL_NAME_value(sans, i);
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
                    ngx_log_error(NGX_LOG_ALERT, &cli->log, 0,
                         "ASN1_STRING_to_UTF8() failed for certificate \"%V\"",
                          &cli->certificate);
                    continue;

                } else if (s) {
                    if (ngx_strcase_eq(&domain, (char *) s)) {
                        found = 1;
                    }
                    OPENSSL_free(s);
                }
            }

            if (found) {
                break;
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
                     ngx_log_error(NGX_LOG_ALERT, &cli->log, 0,
                         "ASN1_STRING_to_UTF8() failed for certificate \"%V\"",
                          &cli->certificate);
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

    rc = ngx_http_acme_cert_validity(ses->client);

    if (rc > 0) {
        ses->client->expiry_time = rc;
        ses->client->renew_time = rc - ses->client->renew_before_expiry;

        rc = ngx_time();

        if (ses->client->renew_time <= rc) {
            ngx_log_error(NGX_LOG_WARN, ses->log, 0,
                          "certificate's validity period is shorter than "
                          "renew_before_expiry time");
            /* TODO find a better solution? */
            ses->client->renew_time = rc + (ses->client->expiry_time - rc) / 2;
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
                      &ses->client->certificate);
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
    ngx_int_t            rc;
    ngx_http_request_t  *r;

    rc = NGX_OK;

    NGX_ACME_BEGIN(send_request);

    if (ngx_http_acme_init_connection(ses) != NGX_OK) {
        return NGX_ERROR;
    }

    r = ngx_http_acme_init_request(ses, method, url, body);

    if (r == NULL) {
        ngx_http_acme_connection_cleanup(&ses->connection);
        return NGX_ERROR;
    }

    ngx_memzero(&ses->response_status, sizeof(ngx_http_status_t));

    ses->request_result = NGX_BUSY;

    DBG_HTTP((ses->client, "--- send request"));

    ngx_http_acme_finalize_request(r, ngx_acme_upstream_handler(r));

    NGX_ACME_YIELD(send_request);

    rc = ses->request_result;

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ses->log, 0,
                      "couldn't complete request, error code: %i", rc);
    }

    if (rc == NGX_BUSY) {
        /* no response? */
        rc = NGX_ERROR;
    }

    NGX_ACME_END(send_request);

    return rc;
}


static ngx_int_t
ngx_http_acme_response_handler(ngx_http_acme_session_t *ses)
{
    u_char                  *s, *end;
    size_t                    len;
    ngx_int_t                 n;
    ngx_json_parse_error_t    err;

    DBG_HTTP((ses->client, "response handler"));

    ses->request_result = NGX_ERROR;

    if (ses->response_overflow) {
        ses->response_overflow = 0;
        ngx_log_error(NGX_LOG_ERR, ses->log, 0,
                      "ACME server response size exceeded %z byte(s), "
                      "use acme_max_cert_size to enlarge the response buffer",
                      ses->client->max_cert_size);
        return NGX_ERROR;
    }

    len = ses->response->last - ses->response->start;

    s = ngx_strnstr(ses->response->start, CRLF CRLF, len);

    if (!s) {
        ngx_log_error(NGX_LOG_ERR, ses->log, 0, "invalid HTTP response");
        return NGX_ERROR;
    }

    ses->body.data = s + 4;
    ses->body.len = ses->response->last - ses->body.data;

    ses->status_line.data = ses->response->start;
    ses->status_line.len = ngx_strnstr(ses->status_line.data, CRLF, len)
                           - ses->status_line.data;

    ses->headers.data = ses->status_line.data + ses->status_line.len + 2;
    ses->headers.len = s - ses->headers.data;

    n = NGX_ERROR;

    s = ngx_strnstr(ses->status_line.data, " ", ses->status_line.len);

    if (s) {
        end = ses->status_line.data + ses->status_line.len;

        while (s < end && *s == ' ') {
            s++;
        }

        len = 0;

        while (s + len < end && s[len] != ' ') {
            len++;
        }

        n = ngx_atoi(s, len);
    }

    if (n != NGX_ERROR) {
        ses->status_code = n;

    } else {
        ngx_log_error(NGX_LOG_ERR, ses->log, 0, "invalid HTTP status line");
        return NGX_ERROR;
    }

#if 1
    DBG_HTTP((ses->client, "resp status_code: %i", ses->status_code));
    DBG_HTTP((ses->client, "resp status_line: %V", &ses->status_line));
    DBG_HTTP((ses->client, "resp headers:"));
    DBG_HTTP((ses->client, "%V", &ses->headers));
    DBG_HTTP((ses->client, "resp body:"));
    DBG_HTTP((ses->client, "%V", &ses->body));
#endif

    if (ngx_http_extract_header(&ses->headers, "Replay-Nonce", &ses->nonce)
        != NGX_OK)
    {
        ngx_str_null(&ses->nonce);
    }

    if (ngx_http_extract_header(&ses->headers, "Content-Type",
        &ses->content_type) != NGX_OK)
    {
        ngx_str_null(&ses->content_type);
    }

    s = ses->content_type.data;
    end = s + ses->content_type.len;

    if (s && ngx_strlcasestrn(s, end, (u_char*) "json", 4 - 1)
        && ses->body.len)
    {
        ses->json = ngx_json_parse(ses->body.data,
                                   ses->body.data + ses->body.len,
                                   ses->pool, &err);
        if (!ses->json) {
            ngx_log_error(NGX_LOG_ERR, ses->log, 0, "JSON parser error: %V",
                          &err.desc);
            return NGX_ERROR;
        }

    } else {
        ses->json = NULL;
    }

    ses->response->pos = ses->response->start;
    ses->response->last = ses->response->start;

    ses->request_result = NGX_OK;

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

        if (ngx_http_extract_header(&ses->headers, "Location", &s)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, ses->log, 0,
                          "existing account's location not found");

        } else {
            rc = ngx_str_clone(ses->pool, &ses->kid, &s);
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

                } else if (ngx_http_extract_header(&ses->headers, "Location",
                           &s) != NGX_OK)
                {
                    ngx_log_error(NGX_LOG_ERR, ses->log, 0,
                                  "newly created account's Location not found");

                } else {
                    rc = ngx_str_clone(ses->pool, &ses->kid, &s);
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

    if (ngx_http_extract_header(&ses->headers, "Location", &s)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, ses->log, 0,
                      "ACME order Location not found");
        NGX_ACME_TERMINATE(cert_issue, NGX_ERROR);
    }

    if (ngx_str_clone(ses->pool, &ses->order_url, &s) != NGX_OK) {
        NGX_ACME_TERMINATE(cert_issue, NGX_ERROR);
    }

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

    rc = ngx_http_acme_csr_gen(ses, 0, &ses->client->private_key, &csr);

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
        ngx_log_error(NGX_LOG_ALERT, ses->log, ngx_errno, "lseek() %i failed",
                      (ngx_uint_t) fd);
        return NGX_ERROR;
    }

    n = ngx_write_fd(fd, ses->body.data, ses->body.len);

    if (n == -1) {
        ngx_log_error(NGX_LOG_ALERT, ses->log, ngx_errno,
                      ngx_write_fd_n " %i failed", (ngx_uint_t) fd);
        return NGX_ERROR;
    }

    if ((size_t) n != ses->body.len) {
        ngx_log_error(NGX_LOG_ALERT, ses->log, 0,
                      ngx_write_fd_n " has written only %z of %uz to %i",
                      n, ses->body.len, (ngx_uint_t) fd);
        return NGX_ERROR;
    }

    if (lseek(fd, 0, SEEK_SET) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ses->log, ngx_errno, "lseek() %i failed",
                      (ngx_uint_t) fd);
        return NGX_ERROR;
    }

    if (ses->body.len < ses->client->certificate_file_size
        && ftruncate(fd, ses->body.len) != 0)
    {
        ngx_log_error(NGX_LOG_ALERT, ses->log, ngx_errno,
                      "ftruncate() %i failed", (ngx_uint_t) fd);
        return NGX_ERROR;
    }

    ngx_rwlock_wlock(&ses->client->sh_cert->lock);

    if (ngx_http_acme_file_load(ses->log, &ses->client->certificate_file,
                                ses->client->sh_cert->data_start,
                                ses->body.len)
        != NGX_OK)
    {
        ses->client->sh_cert->len = 0;
        ngx_rwlock_unlock(&ses->client->sh_cert->lock);
        return NGX_ERROR;
    }

    ses->client->sh_cert->len = ses->body.len;

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

    amcf = ses->client->main_conf;

    if (key_auth->len > amcf->max_key_auth_size) {
        ngx_log_error(NGX_LOG_CRIT, ses->log, 0,
                      "key authorization string received from ACME server "
                      "is too long to fit in shared memory, use "
                      "acme_max_key_auth_size with a value of at least %uz",
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
    static ngx_str_t content_type = ngx_string("application/octet-stream");
    static ngx_str_t wellknown    = ngx_string("/.well-known/acme-challenge/");

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

                DBG_STATUS((cli, "certificate will not be renewed"));

            } else {
                cli->renew_time = ngx_time() + cli->retry_after_error;

                DBG_STATUS((cli, "certificate scheduled for renewal on %s",
                            strtok(ctime(&cli->renew_time), "\n")));
            }
        }

        cli = ngx_http_acme_nearest_client(amcf);

        if (!cli) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                "acme status: no certificate found for renewal; quitting ...");
            return;
        }

        amcf->current = cli;

        ngx_add_timer(ev, ngx_http_acme_timer_interval(cli));

        DBG_STATUS((cli, "certificate scheduled for renewal on %s",
                    strtok(ctime(&cli->renew_time), "\n")));
    }
}


static ngx_int_t
ngx_http_acme_init_connection(ngx_http_acme_session_t *ses)
{
    ngx_pool_t          *pool;
    ngx_connection_t    *c;
    struct sockaddr_in  *sin;

    c = &ses->connection;

    pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, &ses->client->log);
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

    /* fake client address: 127.0.0.1:1234 */
    sin = (struct sockaddr_in *) &ses->caddr;

    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = INADDR_LOOPBACK;
    sin->sin_port = 1234;

    c->sockaddr = &ses->caddr;
    c->local_sockaddr = &ses->caddr;

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
    size_t                    n;
    ngx_http_acme_session_t  *ses;

    ses = ngx_container_of(c, ngx_http_acme_session_t, connection);

    while (in) {
        if (ngx_buf_special(in->buf)) {
            in = in->next;
            continue;
        }

        n = in->buf->last - in->buf->pos;

        if (n > (size_t) (ses->response->end - ses->response->pos)) {
            n = ses->response->end - ses->response->pos;
            ses->response_overflow = 1;
        }

        if (n) {
            ngx_memcpy(ses->response->pos, in->buf->pos, n);
            ses->response->pos += n;
            ses->response->last = ses->response->pos;
        }

        c->sent += in->buf->last - in->buf->pos;
        in->buf->pos = in->buf->last;
        in = in->next;
    }

    return in;
}


static ngx_http_request_t *
ngx_http_acme_init_request(ngx_http_acme_session_t *ses, ngx_uint_t method,
    ngx_str_t *url, ngx_str_t *body)
{
    u_char                 *p;
    size_t                  len;
    ngx_buf_t              *b;
    ngx_str_t               uri;
    ngx_chain_t            *cl;
    ngx_connection_t       *c;
    ngx_http_request_t     *r;
    ngx_pool_cleanup_t     *cln;
    ngx_http_connection_t   hc;

    c = &ses->connection;

    ngx_memzero(&hc, sizeof(ngx_http_connection_t));
    hc.conf_ctx = ses->client->conf_ctx;

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

    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        goto failed;
    }

    cln->handler = ngx_http_acme_request_cleanup;
    cln->data = ses;

    c->data = r;

    if (ngx_http_acme_set_ctx(r, ses) != NGX_OK) {
        goto failed;
    }

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

    ses->request = r;

    return r;

failed:

    ngx_destroy_pool(r->pool);
    return NULL;
}


static void
ngx_http_acme_request_cleanup(void *data)
{
    ngx_http_acme_session_t *ses = data;

    DBG_HTTP((ses->client, "--- response received"));

    ngx_http_acme_response_handler(ses);

    ngx_add_timer(&ses->client->main_conf->timer_event, 10);
}


static ngx_int_t
ngx_http_acme_add_header(ngx_http_request_t *r, char *name, char *value)
{
    ngx_table_elt_t            *h;
    ngx_http_header_t          *hh;
    ngx_http_core_main_conf_t  *cmcf;
#if (NGX_DEBUG)
    ngx_http_acme_session_t    *ses;

    ses = ngx_http_acme_get_ctx(r);

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
    ngx_connection_t         *c;
    ngx_http_acme_session_t  *ses;

    ses = ngx_http_acme_get_ctx(r);

    DBG_HTTP((ses->client, "request completed: %i", rc));

    if (r->count == 0) {
        ngx_log_error(NGX_LOG_ALERT, ses->log, 0, "acme request count is zero");
    }

    r->count--;

    if (r->count) {
        return;
    }

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
    ngx_acme_client_t           *cli;
    ngx_pool_cleanup_t          *cln;
    ngx_http_handler_pt         *h;
    ngx_http_conf_port_t        *port;
    ngx_http_server_name_t      *sn;
    ngx_http_acme_srv_conf_t    *ascf;
    ngx_http_acme_loc_conf_t    *alcf;
    ngx_http_core_srv_conf_t   **cscfp, *cscf;
    ngx_http_acme_main_conf_t   *amcf;
    ngx_http_core_main_conf_t   *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    cscfp = cmcf->servers.elts;

    for (i = 0; i < cmcf->servers.nelts; i++) {

        cscf = cscfp[i];
        ascf = cscf->ctx->srv_conf[ngx_http_acme_module.ctx_index];

        cli = ascf->client;
        if (!cli || !cli->enabled) {
            continue;
        }

        sn = cscf->server_names.elts;

        for (j  = 0; j < cscf->server_names.nelts; j++) {
            s = &sn[j].name;

            if (!s->len) {
                /* may contain an empty server_name */
                continue;
            }

            if (
#if (NGX_PCRE)
                sn[j].regex ||
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

            *s = sn[j].name;
        }
    }

    shm_size = 0;
    n = 0;

    amcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_acme_module);

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_http_acme_fds_close;
    cln->data = &amcf->clients;

    alcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_acme_module);

    if (alcf->clcf == NULL) {
        /* can't happen? */
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "failed to configure ACME: invalid location conf "
                           "pointer, please report a bug");
        return NGX_ERROR;
    }

    for (i = 0; i < amcf->clients.nelts; i++) {

        cli = (ngx_acme_client_t *) amcf->clients.elts + i;

        if (!cli->enabled) {
            continue;
        }

        n = 1;

        if (cli->cf_line == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                            "ACME client \"%V\" is referenced but not defined",
                            &cli->name);
            return NGX_ERROR;
        }

        if (alcf->clcf->resolver->connections.nelts == 0
            && cli->server_url.addrs == NULL)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "no resolver configured for resolving %V "
                               "at run time for ACME client \"%V\"",
                               &cli->server_url.host, &cli->name);

            return NGX_ERROR;
        }

        ngx_memcpy(&cli->log, alcf->clcf->error_log, sizeof(ngx_log_t));

        cli->log.data = &cli->log_ctx;
        cli->log.handler = ngx_http_acme_log_error;

        cli->conf_ctx = &alcf->conf_ctx;

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

        /*
         * Assign the files that will be opened/created. The ACME client's
         * directories where they will live may not exist at this point yet.
         */

        ngx_str_set(&name, "account.key");

        if (ngx_http_acme_init_file(cf, &cli->path, &name,
                                    &cli->account_key.file)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        ngx_str_set(&name, "private.key");

        if (ngx_http_acme_init_file(cf, &cli->path, &name,
                                    &cli->private_key.file)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        /*
         * The private key file may already exist at this point. If it does,
         * it won't change anymore, so we can safely use its size to allocate
         * shared memory for it. If the file does not exist, we cannot know its
         * size in advance, so we will use the max_cert_key_size value.
         *
         * We could have created the private key file right here, but then we
         * would need its containing directory created first.
         */

        cli->private_key.file_size = ngx_http_acme_file_size(
                                                 &cli->private_key.file);

        if (cli->private_key.file_size > NGX_ACME_MAX_SH_FILE) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "size of file \"%V\" exceeds %d bytes",
                               &cli->private_key.file.name,
                               NGX_ACME_MAX_SH_FILE);
            return NGX_ERROR;
        }

        sz = sizeof(ngx_http_acme_sh_key_t)
             + (cli->private_key.file_size
               ? cli->private_key.file_size : cli->max_cert_key_size);

        shm_size += ngx_align(sz, NGX_ALIGNMENT);

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

        shm_size += sizeof(ngx_http_acme_sh_cert_t) + cli->max_cert_size;
    }

    if (!n) {
        return NGX_OK;
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

    for (i = 0; i < amcf->clients.nelts; i++) {

        cli = (ngx_acme_client_t *) amcf->clients.elts + i;

        if (!cli->enabled) {
            continue;
        }

        if (ngx_create_dir(cli->path.data, 0700) == NGX_FILE_ERROR) {
            err = ngx_errno;
            if (err != NGX_EEXIST) {
                ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, err,
                              ngx_create_dir_n " \"%s\" failed",
                              cli->path.data);
                return NGX_ERROR;
            }
        }
    }

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_acme_http_challenge_handler;

    shm_size += sizeof(ngx_http_acme_sh_keyauth_t) + amcf->max_key_auth_size;

    ngx_str_set(&name, "acme_shm");

    amcf->shm_zone = ngx_shared_memory_add(cf, &name, shm_size, 0);
    if (amcf->shm_zone == NULL) {
        return NGX_ERROR;
    }

    amcf->shm_zone->init = ngx_http_acme_shm_init;
    amcf->shm_zone->data = amcf;
    amcf->shm_zone->noslab = 1;
    amcf->shm_zone->noreuse = 1;

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
    ngx_memzero(file, sizeof(ngx_file_t));
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
    ngx_http_acme_main_conf_t  *amcf;

    if (shm_zone->shm.exists) {
        /* Angie doesn't support Windows, so this probably can't happen... */
        return NGX_ERROR;
    }

    amcf = shm_zone->data;
    amcf->sh = (ngx_http_acme_sh_keyauth_t *) shm_zone->shm.addr;

    /*
     * At this point, all the necessary file descriptors have been created.
     * We can create some of the files if they don't exist yet, and do other
     * initialization.
     */

    if (ngx_http_acme_init_accounts(amcf) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_http_acme_session_t *
ngx_http_acme_create_session(ngx_acme_client_t *cli)
{
    ngx_log_t                *log;
    ngx_pool_t               *pool;
    ngx_http_acme_session_t  *ses;

    log = &cli->log;

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
    ses->response = ngx_create_temp_buf(pool, cli->max_cert_size);

    NGX_FIBER_INIT(ses->run_state);

    return ses;
}


static void
ngx_http_acme_destroy_session(ngx_http_acme_session_t **ses)
{
    DBG_MEM(((*ses)->client, "destroy session pool: %p", (*ses)->pool));

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

    if (amcf == NULL) {
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


static ngx_int_t
ngx_acme_upstream_set_ssl(ngx_conf_t *cf, ngx_acme_client_t *cli)
{
    ngx_str_t            s;
    ngx_pool_cleanup_t  *cln;

    if (ngx_ssl_create(cli->upstream.ssl, (NGX_CONF_BITMASK_SET|NGX_SSL_TLSv1
                       |NGX_SSL_TLSv1_1|NGX_SSL_TLSv1_2|NGX_SSL_TLSv1_3), NULL)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        ngx_ssl_cleanup_ctx(cli->upstream.ssl);
        return NGX_ERROR;
    }

    cln->handler = ngx_ssl_cleanup_ctx;
    cln->data = cli->upstream.ssl;

    ngx_str_set(&s, "DEFAULT");

    if (ngx_ssl_ciphers(cf, cli->upstream.ssl, &s, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_ssl_client_session_cache(cf, cli->upstream.ssl, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_acme_upstream_handler(ngx_http_request_t *r)
{
    ngx_int_t                   rc;
    ngx_http_upstream_t        *u;
    ngx_acme_client_t          *cli;
    ngx_http_acme_main_conf_t  *amcf;

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    amcf = ngx_http_get_module_main_conf(r, ngx_http_acme_module);

    cli = amcf->current;

    u = r->upstream;

    if (cli->ssl) {
        ngx_str_set(&u->schema, "https://");

    } else {
        ngx_str_set(&u->schema, "http://");
    }

    u->ssl = cli->ssl;

    u->output.tag = (ngx_buf_tag_t) &ngx_http_acme_module;

    u->conf = &cli->upstream;

    u->create_request = ngx_acme_upstream_create_request;
    u->reinit_request = ngx_acme_upstream_reinit_request;
    u->process_header = ngx_acme_upstream_process_status_line;
    u->abort_request = ngx_acme_upstream_abort_request;
    u->finalize_request = ngx_acme_upstream_finalize_request;
    r->state = 0;

    u->buffering = cli->upstream.buffering;

    u->pipe = ngx_pcalloc(r->pool, sizeof(ngx_event_pipe_t));
    if (u->pipe == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u->pipe->input_filter = ngx_event_pipe_copy_input_filter;
    u->pipe->input_ctx = r;

    u->accel = 1;

    r->request_body_no_buffering = 1;

    u->resolved = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
    if (u->resolved == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (cli->server_url.addrs) {
        u->resolved->sockaddr = cli->server_url.addrs[0].sockaddr;
        u->resolved->socklen = cli->server_url.addrs[0].socklen;
        u->resolved->name = cli->server_url.addrs[0].name;
        u->resolved->naddrs = 1;
    }

    u->resolved->host = cli->server_url.host;
    u->resolved->port = (in_port_t) (cli->server_url.no_port
                        ? cli->server_url.default_port : cli->server_url.port);
    u->resolved->no_port = cli->server_url.no_port;

    rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static ngx_int_t
ngx_acme_upstream_create_request(ngx_http_request_t *r)
{
    size_t                         len;
    ngx_int_t                      port;
    ngx_buf_t                     *b;
    ngx_str_t                      method, host;
    ngx_uint_t                     i;
    ngx_chain_t                   *cl, *body;
    ngx_list_part_t               *part;
    ngx_table_elt_t               *header;
    ngx_http_upstream_t           *u;
#if (NGX_DEBUG)
    ngx_http_acme_session_t       *ses;

    ses = ngx_http_acme_get_ctx(r);
#endif

    u = r->upstream;
    method = r->method_name;
    host = r->upstream->resolved->host;
    port = r->upstream->resolved->port;

    len = sizeof("  HTTP/1.1"CRLF"Host: :"CRLF"Connection: close" CRLF CRLF) - 1
          + method.len + r->unparsed_uri.len + host.len
          + ngx_dec_count(port);

    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        len += header[i].key.len + sizeof(": ") - 1
               + header[i].value.len + sizeof(CRLF) - 1;
    }

    if (r->headers_in.content_length_n > 0) {
        len = r->headers_in.content_length_n;
    }

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;

    b->last = ngx_snprintf(b->start, len,
                  "%V %V HTTP/1.1"CRLF"Host: %V:%i"CRLF"Connection: close"CRLF,
                  &method, &r->unparsed_uri, &host, port);

    u->uri.data = b->start + method.len + 1;
    u->uri.len = r->unparsed_uri.len;

    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        b->last = ngx_copy(b->last, header[i].key.data, header[i].key.len);

        *b->last++ = ':'; *b->last++ = ' ';

        b->last = ngx_copy(b->last, header[i].value.data,
                           header[i].value.len);

        *b->last++ = CR; *b->last++ = LF;

        DBG_HTTP((ses->client, "header: \"%V: %V\"",
                 &header[i].key, &header[i].value));
    }

    *b->last++ = CR; *b->last++ = LF;

    body = u->request_bufs;
    u->request_bufs = cl;

    while (body) {
        b = ngx_alloc_buf(r->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(b, body->buf, sizeof(ngx_buf_t));

        cl->next = ngx_alloc_chain_link(r->pool);
        if (cl->next == NULL) {
            return NGX_ERROR;
        }

        cl = cl->next;
        cl->buf = b;

        body = body->next;
    }

    b->flush = 1;
    cl->next = NULL;

    return NGX_OK;
}


static ngx_int_t
ngx_acme_upstream_reinit_request(ngx_http_request_t *r)
{
    ngx_http_acme_session_t  *ses;

    ses = ngx_http_acme_get_ctx(r);

    if (ses == NULL) {
        return NGX_OK;
    }

    ses->response_status.code = 0;
    ses->response_status.count = 0;
    ses->response_status.start = NULL;
    ses->response_status.end = NULL;

    r->upstream->process_header = ngx_acme_upstream_process_status_line;
    r->upstream->pipe->input_filter = ngx_event_pipe_copy_input_filter;
    r->state = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_acme_upstream_process_status_line(ngx_http_request_t *r)
{
    size_t                    len;
    ngx_int_t                 rc;
    ngx_http_upstream_t      *u;
    ngx_http_acme_session_t  *ses;

    ses = ngx_http_acme_get_ctx(r);

    if (ses == NULL) {
        /* can't happen? */
        return NGX_ERROR;
    }

    u = r->upstream;

    rc = ngx_http_parse_status_line(r, &u->buffer, &ses->response_status);

    if (rc == NGX_AGAIN) {
        return rc;
    }

    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, ses->log, 0,
                      "ACME server sent an invalid HTTP header");

        r->http_version = NGX_HTTP_VERSION_9;
        u->state->status = NGX_HTTP_OK;
        u->headers_in.connection_close = 1;

        return NGX_OK;
    }

    if (u->state && u->state->status == 0) {
        u->state->status = ses->response_status.code;
    }

    u->headers_in.status_n = ses->response_status.code;

    len = ses->response_status.end - ses->response_status.start;
    u->headers_in.status_line.len = len;

    u->headers_in.status_line.data = ngx_pnalloc(r->pool, len);
    if (u->headers_in.status_line.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(u->headers_in.status_line.data, ses->response_status.start, len);

    DBG_HTTP((ses->client, "ACME server status %ui \"%V\"",
              u->headers_in.status_n, &u->headers_in.status_line));

    if (ses->response_status.http_version < NGX_HTTP_VERSION_11) {
        u->headers_in.connection_close = 1;
    }

    u->process_header = ngx_acme_upstream_process_header;

    return ngx_acme_upstream_process_header(r);
}


static ngx_int_t
ngx_acme_upstream_process_header(ngx_http_request_t *r)
{
    ngx_int_t                       rc;
    ngx_table_elt_t                *h;
    ngx_http_acme_session_t        *ses;
    ngx_http_upstream_header_t     *hh;
    ngx_http_upstream_main_conf_t  *umcf;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    ses = ngx_http_acme_get_ctx(r);

    if (ses == NULL) {
        /* can't happen? */
        return NGX_ERROR;
    }

    for ( ;; ) {

        rc = ngx_http_parse_header_line(r, &r->upstream->buffer, 1);

        if (rc == NGX_OK) {

            /* a header line has been parsed successfully */

            h = ngx_list_push(&r->upstream->headers_in.headers);
            if (h == NULL) {
                return NGX_ERROR;
            }

            h->hash = r->header_hash;

            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;

            h->key.data = ngx_pnalloc(r->pool,
                               h->key.len + 1 + h->value.len + 1 + h->key.len);
            if (h->key.data == NULL) {
                h->hash = 0;
                return NGX_ERROR;
            }

            h->value.data = h->key.data + h->key.len + 1;
            h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;

            ngx_memcpy(h->key.data, r->header_name_start, h->key.len);
            h->key.data[h->key.len] = '\0';
            ngx_memcpy(h->value.data, r->header_start, h->value.len);
            h->value.data[h->value.len] = '\0';

            if (h->key.len == r->lowcase_index) {
                ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);

            } else {
                ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
                               h->lowcase_key, h->key.len);

            if (hh) {
                rc = hh->handler(r, h, hh->offset);

                if (rc != NGX_OK) {
                    return rc;
                }
            }

            DBG_HTTP((ses->client, "header: \"%V: %V\"", &h->key, &h->value));

            continue;
        }

        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

            DBG_HTTP((ses->client, "headers done"));

            return NGX_OK;
        }

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        /* rc == NGX_HTTP_PARSE_INVALID_HEADER */

        ngx_log_error(NGX_LOG_ERR, ses->log, 0,
                      "ACME server sent an invalid header: \"%*s\\x%02xd...\"",
                      r->header_end - r->header_name_start,
                      r->header_name_start, *r->header_end);

        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }
}


static void
ngx_acme_upstream_abort_request(ngx_http_request_t *r)
{
#if (NGX_DEBUG)
    ngx_http_acme_session_t  *ses;

    ses = ngx_http_acme_get_ctx(r);

    DBG_HTTP((ses->client, "abort request"));
#endif
}


static void
ngx_acme_upstream_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
#if (NGX_DEBUG)
    ngx_http_acme_session_t  *ses;

    ses = ngx_http_acme_get_ctx(r);

    DBG_HTTP((ses->client, "finalize request"));
#endif
}


static int
ngx_http_extract_header(ngx_str_t * headers, char *name, ngx_str_t *value)
{
    u_char  *s, *end;
    size_t   len;

    len = ngx_strlen(name);
    end = headers->data + headers->len;

    s = ngx_strlcasestrn(headers->data, end, (u_char*) name, len - 1);

    if (!s) {
        return NGX_DECLINED;
    }

    s += len;

    if (s >= end || *s != ':') {
        return NGX_DECLINED;
    }

    s++;

    while (s < end && isspace(*s)) {
        s++;
    }

    value->data = s;

    while (s < end && *s != '\r' && *s != '\n' && !isspace(*s)) {
        s++;
    }

    value->len = s - value->data;

    return NGX_OK;
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

    return ascf;
}


static void *
ngx_http_acme_create_loc_conf(ngx_conf_t *cf)
{
    return ngx_pcalloc(cf->pool, sizeof(ngx_http_acme_loc_conf_t));
}


static char *
ngx_http_acme_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_acme_loc_conf_t *prev = parent;
    ngx_http_acme_loc_conf_t *conf = child;

    const u_char  *p;

    conf->conf_ctx = *(ngx_http_conf_ctx_t *) cf->ctx;

    p = (const u_char *) &prev->conf_ctx;
    if (*p == 0 && ngx_memcmp(p, p + 1, sizeof(ngx_http_conf_ctx_t) - 1) == 0) {
        /* prev->conf_ctx == { 0, ... } */
        prev->conf_ctx = conf->conf_ctx;
    }

    conf->clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    if (prev->clcf == NULL) {
        prev->clcf = conf->clcf;
    }

    return NGX_CONF_OK;
}


static void
ngx_http_acme_dummy_cleanup(void *data)
{
}


static void *
ngx_http_acme_get_ctx(ngx_http_request_t *r)
{
    ngx_pool_cleanup_t  *cln;

    for (cln = r->pool->cleanup; cln; cln = cln->next) {
        if (cln->handler == ngx_http_acme_dummy_cleanup) {
            return cln->data;
        }
    }

    return NULL;
}


static ngx_int_t
ngx_http_acme_set_ctx(ngx_http_request_t *r, void *data)
{
    ngx_pool_cleanup_t  *cln;

    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_http_acme_dummy_cleanup;
    cln->data = data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_acme_preconfiguration(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_acme_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_acme_cert_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t name = *(ngx_str_t *) data;

    ngx_uint_t                  i;
    ngx_acme_client_t          *cli;
    ngx_http_acme_main_conf_t  *amcf;

    name.data += sizeof("acme_cert_") - 1;
    name.len -= sizeof("acme_cert_") - 1;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 1;

    cli = NULL;
    amcf = ngx_http_get_module_main_conf(r, ngx_http_acme_module);

    for (i = 0; i < amcf->clients.nelts; i++) {
        cli = (ngx_acme_client_t *) amcf->clients.elts + i;

        if (!cli->enabled) {
            continue;
        }

        if (cli->name.len == name.len
            && ngx_strncasecmp(cli->name.data, name.data, name.len) == 0)
        {
            v->not_found = 0;
            break;
        }
    }

    if (v->not_found) {
        return NGX_OK;
    }

    ngx_rwlock_rlock(&cli->sh_cert->lock);

    if (cli->sh_cert->len == 0) {
        v->not_found = 1;

    } else {
        v->len = cli->sh_cert->len + 5 /* 5 == sizeof("data:") - 1 */;

        v->data = ngx_pnalloc(r->pool, v->len);
        if (v->data != NULL) {
            ngx_memcpy(v->data, "data:", 5);
            ngx_memcpy(v->data + 5, cli->sh_cert->data_start,
                    cli->sh_cert->len);
        }
    }

    ngx_rwlock_unlock(&cli->sh_cert->lock);

    return (v->not_found || v->data != NULL) ? NGX_OK : NGX_ERROR;
}


static ngx_int_t
ngx_http_acme_cert_key_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t name = *(ngx_str_t *) data;

    ngx_uint_t                  i;
    ngx_acme_client_t          *cli;
    ngx_http_acme_main_conf_t  *amcf;

    name.data += sizeof("acme_cert_key_") - 1;
    name.len -= sizeof("acme_cert_key_") - 1;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 1;

    cli = NULL;
    amcf = ngx_http_get_module_main_conf(r, ngx_http_acme_module);

    for (i = 0; i < amcf->clients.nelts; i++) {
        cli = (ngx_acme_client_t *) amcf->clients.elts + i;

        if (!cli->enabled) {
            continue;
        }

        if (cli->name.len == name.len
            && ngx_strncasecmp(cli->name.data, name.data, name.len) == 0)
        {
            v->not_found = 0;
            break;
        }
    }

    if (v->not_found) {
        return NGX_OK;
    }

    v->len = cli->sh_cert_key->len + 5 /* 5 == sizeof("data:") - 1 */;

    v->data = ngx_pnalloc(r->pool, v->len);
    if (v->data != NULL) {
        ngx_memcpy(v->data, "data:", 5);
        ngx_memcpy(v->data + 5, cli->sh_cert_key->data_start,
                   cli->sh_cert_key->len);
    }

    return v->data != NULL ? NGX_OK : NGX_ERROR;
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

    /* sanity */
    if (!value[1].len) {
        return "has an empty name";
    }

    if (!value[2].len) {
        return "has an empty server URL";
    }

    cli = ngx_acme_client_add(cf, &value[1]);
    if (cli == NULL) {
        return NGX_CONF_ERROR;
    }

    if (cli->cf_line) {
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

        if (ngx_strncmp(value[i].data, "max_cert_key_size=", 18) == 0) {

            value[i].data += 18;
            value[i].len -= 18;

            cli->max_cert_key_size = ngx_parse_size(&value[i]);

            if (cli->max_cert_key_size == (size_t) NGX_ERROR) {
                return "has an invalid \"max_cert_key_size\" value";
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
        cli->private_key.bits = 256;
    }

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

    if (cli->max_cert_key_size == NGX_CONF_UNSET_SIZE) {
        cli->max_cert_key_size = 2 * 1024;
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

        if (ngx_acme_upstream_set_ssl(cf, cli) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

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

    return NGX_CONF_OK;
}


static char *
ngx_http_acme(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_acme_srv_conf_t *ascf = conf;

    ngx_str_t  *value;

    value = cf->args->elts;

    if (!value[1].len) {
        return "has an empty name";
    }

    if (ascf->client != NULL) {
        return "is duplicate";
    }

    ascf->client = ngx_acme_client_add(cf, &value[1]);
    if (ascf->client == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_acme_client_t *
ngx_acme_client_add(ngx_conf_t *cf, ngx_str_t *name)
{
    ngx_uint_t                  i;
    ngx_hash_init_t             hash;
    ngx_acme_client_t          *cli;
    ngx_http_acme_main_conf_t  *amcf;

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

    ngx_memcpy(&cli->log, cf->log, sizeof(ngx_log_t));
    cli->log.data = &cli->log_ctx;
    cli->log.handler = ngx_http_acme_log_error;

    cli->name = *name;
    cli->enabled = NGX_CONF_UNSET_UINT;
    cli->private_key.type = NGX_KT_UNSUPPORTED;
    cli->private_key.bits = NGX_CONF_UNSET;
    cli->renew_before_expiry = NGX_CONF_UNSET;
    cli->retry_after_error = NGX_CONF_UNSET;
    cli->max_cert_size = NGX_CONF_UNSET_SIZE;
    cli->max_cert_key_size = NGX_CONF_UNSET_SIZE;

    cli->domains = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
    if (cli->domains == NULL) {
        return NULL;
    }

    cli->main_conf = amcf;
    /* TODO proper configuration */
    cli->upstream.connect_timeout = 60000;
    cli->upstream.send_timeout = 60000;
    cli->upstream.read_timeout = 60000;
    cli->upstream.next_upstream_timeout = 0;
    cli->upstream.send_lowat = 0;
    cli->upstream.buffer_size = ngx_pagesize;
    cli->upstream.limit_rate = 0;
    cli->upstream.bufs.num = 8;
    cli->upstream.bufs.size = ngx_pagesize;
    cli->upstream.busy_buffers_size_conf = NGX_CONF_UNSET_SIZE;
    cli->upstream.busy_buffers_size = cli->upstream.buffer_size * 2;
    cli->upstream.max_temp_file_size_conf = NGX_CONF_UNSET_SIZE;
    cli->upstream.max_temp_file_size = 1024 * 1024 * 1024;
    cli->upstream.ignore_headers = NGX_CONF_BITMASK_SET
                                   | NGX_HTTP_UPSTREAM_IGN_XA_REDIRECT
                                   | NGX_HTTP_UPSTREAM_IGN_XA_EXPIRES
                                   | NGX_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE
                                   | NGX_HTTP_UPSTREAM_IGN_XA_BUFFERING
                                   | NGX_HTTP_UPSTREAM_IGN_XA_CHARSET
                                   | NGX_HTTP_UPSTREAM_IGN_EXPIRES
                                   | NGX_HTTP_UPSTREAM_IGN_CACHE_CONTROL
                                   | NGX_HTTP_UPSTREAM_IGN_SET_COOKIE
                                   | NGX_HTTP_UPSTREAM_IGN_VARY;
    cli->upstream.next_upstream = NGX_CONF_BITMASK_SET
                                  | NGX_HTTP_UPSTREAM_FT_ERROR
                                  | NGX_HTTP_UPSTREAM_FT_TIMEOUT;
    cli->upstream.temp_file_write_size_conf = NGX_CONF_UNSET_SIZE;
    cli->upstream.temp_file_write_size = cli->upstream.buffer_size * 2;
    cli->upstream.store_access = 0600;
    cli->upstream.next_upstream_tries = 0;
    cli->upstream.buffering = 0;
    cli->upstream.request_buffering = 1;
    cli->upstream.pass_request_headers = 1;
    cli->upstream.pass_request_body = 1;
    cli->upstream.ignore_client_abort = 0;
    cli->upstream.intercept_errors = 0;
    cli->upstream.cyclic_temp_file = 0;
    cli->upstream.force_ranges = 0;
    cli->upstream.hide_headers = NGX_CONF_UNSET_PTR;
    cli->upstream.pass_headers = NGX_CONF_UNSET_PTR;
    cli->upstream.local = NULL;
    cli->upstream.socket_keepalive = 0;

#if (NGX_HTTP_CACHE)
    cli->upstream.cache_min_uses = 1;
    cli->upstream.cache_max_range_offset = NGX_MAX_OFF_T_VALUE;
    cli->upstream.cache_use_stale = NGX_CONF_BITMASK_SET
                                    | NGX_HTTP_UPSTREAM_FT_OFF;
    cli->upstream.cache_methods = NGX_HTTP_GET | NGX_HTTP_HEAD;
    cli->upstream.cache_lock = 0;
    cli->upstream.cache_lock_timeout = 5000;
    cli->upstream.cache_lock_age = 5000;
    cli->upstream.cache_revalidate = 0;
    cli->upstream.cache_convert_head = 1;
    cli->upstream.cache_background_update = 0;
    cli->upstream.cache_valid = NULL;
    cli->upstream.cache_bypass = NULL;
    cli->upstream.no_cache = NULL;
    cli->upstream.cache = 0;
#endif
    cli->upstream.store = 0;
    cli->upstream.change_buffering = 1;

    cli->upstream.ssl = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
    if (cli->upstream.ssl == NULL) {
        return NULL;
    }

    cli->upstream.ssl->log = cf->log;
    cli->upstream.ssl_session_reuse = 1;
    cli->upstream.ssl_name = NULL;
    cli->upstream.ssl_server_name = 1;
    cli->upstream.ssl_verify = 0;
    cli->upstream.ssl_certificate = NULL;
    cli->upstream.ssl_certificate_key = NULL;
    cli->upstream.ssl_passwords = NULL;

    ngx_str_set(&cli->upstream.module, "acme");

    hash.max_size = 512;
    hash.bucket_size = 64;
    hash.name = "acme_headers_hash";
    hash.hash = &cli->upstream.hide_headers_hash;
    hash.key = ngx_hash_key_lc;
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (ngx_hash_init(&hash, NULL, 0) != NGX_OK) {
        return NULL;
    }

    return cli;
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

    p = ngx_pstrdup(pool, src);
    if (!p) {
        return NGX_ERROR;
    }

    dst->data = p;
    dst->len = src->len;

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
