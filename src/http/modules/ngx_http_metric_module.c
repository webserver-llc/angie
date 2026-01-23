
/*
 * Copyright (C) 2025 Web Server LLC
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <float.h>


#define NGX_HTTP_METRIC_PTR_SIZE   8
#define NGX_HTTP_METRIC_DATA_SIZE  120
#define NGX_HTTP_METRIC_SLAB_SIZE  128

#define NGX_HTTP_METRIC_MAX_LEN    255


typedef struct {
    u_char                       color;  /* ngx_rbtree_node_t */
    ngx_queue_t                  queue;
    ngx_atomic_t                 lock;
    uint8_t                      key_len;
    u_char                       key[1];
} ngx_http_metric_node_t;


typedef struct {
    ngx_queue_t                  queue;
    ngx_atomic_t                 rbt_lock;
    ngx_atomic_t                 queue_lock;
    ngx_rbtree_t                 rbtree;
    ngx_rbtree_node_t            sentinel;
    ngx_http_metric_node_t      *expired;
    ngx_uint_t                   is_expired;
    ngx_uint_t                   discarded;
} ngx_http_metric_shctx_t;


typedef struct ngx_http_metric_ctx_s  ngx_http_metric_ctx_t;

struct ngx_http_metric_ctx_s {
    ngx_str_t                    discard_key;
    ngx_uint_t                   expire;
    ngx_int_t                  (*api)(ngx_api_ctx_t *actx,
                                      ngx_http_metric_ctx_t *mctx,
                                      u_char *pos, u_char *end);
    size_t                       str_size;
    size_t                       data_size;
    ngx_array_t                 *metrics;  /* ngx_http_metric_t * */
    ngx_shm_zone_t              *shm_zone;
    ngx_slab_pool_t             *shpool;
    ngx_http_metric_ctx_t       *next;
    ngx_http_metric_shctx_t     *sh;
};


typedef struct {
    double                       factor;
    ngx_uint_t                   count;
    ngx_msec_t                   window;
} ngx_http_metric_avg_args_t;


typedef struct {
    ngx_str_t                    name;
    double                       value;
} ngx_http_metric_hist_args_t;


typedef union {
    ngx_http_metric_avg_args_t   avg;
    ngx_array_t                 *hist;  /* ngx_http_metric_hist_args_t */
} ngx_http_metric_args_t;


typedef struct {
    double                       value;
    uint64_t                     timestamp;
} ngx_http_metric_avg_cache_t;


typedef struct {
    double                       sum;
    ngx_uint_t                   count;
    ngx_uint_t                   current;
} ngx_http_metric_avg_ctx_t;


typedef union {
    ngx_http_metric_avg_ctx_t    avg;
} ngx_http_metric_mode_ctx_t;


typedef struct {
    ngx_uint_t                   state;
    ngx_http_metric_args_t       args;
    ngx_http_metric_mode_ctx_t   modes;
} ngx_http_metric_state_ctx_t;


typedef struct {
    ngx_str_t                    name;
    uint8_t                      type;  /* unsigned  type:2 */
    char                      *(*conf)(ngx_conf_t *cf, ngx_uint_t start,
                                       ngx_http_metric_ctx_t *mctx,
                                       ngx_http_metric_args_t *args);
    ngx_int_t                  (*init)(ngx_http_metric_state_ctx_t *sctx,
                                       void **pos, void *end);
    ngx_int_t                  (*expire)(ngx_http_metric_state_ctx_t *sctx,
                                         void **pos_e, void *end_e,
                                         void **pos_q, void *end_q);
    ngx_int_t                  (*set)(ngx_http_metric_state_ctx_t *sctx,
                                      void **pos, void *end, double value);
    ngx_int_t                  (*get)(ngx_http_metric_state_ctx_t *sctx,
                                      void **pos, void *end, ngx_str_t *buf);
    ngx_int_t                  (*api)(ngx_api_entry_data_t data,
                                      ngx_api_ctx_t *actx, void *ctx);
} ngx_http_metric_mode_t;


typedef struct {
    ngx_str_t                    name;
    ngx_http_metric_args_t       args;
    ngx_http_metric_mode_t      *mode;
    off_t                        offset;
    size_t                       data_size;
    size_t                       str_size;
} ngx_http_metric_t;


typedef struct {
    void                        *elts;
    u_char                      *pos;
    u_char                      *end;
} ngx_http_metric_iter_ctx_t;


#define NGX_HTTP_METRIC_STAGE_REQUEST   0
#define NGX_HTTP_METRIC_STAGE_RESPONSE  1
#define NGX_HTTP_METRIC_STAGE_END       2


typedef struct {
    ngx_str_t                    key;
    ngx_str_t                    tmp;
    ngx_uint_t                   stage;
    ngx_http_metric_ctx_t       *mctx;
} ngx_http_metric_request_ctx_t;


typedef struct {
    ngx_http_metric_ctx_t       *mctx;
    ngx_http_metric_ctx_t      **next;
} ngx_http_metric_main_conf_t;


typedef struct {
    ngx_http_complex_value_t     key;
    ngx_http_complex_value_t     value;
    ngx_shm_zone_t              *shm_zone;
} ngx_http_metric_stage_t;


typedef struct {
    ngx_array_t                 *request;   /* ngx_http_metric_stage_t */
    ngx_array_t                 *response;  /* ngx_http_metric_stage_t */
    ngx_array_t                 *end;       /* ngx_http_metric_stage_t */
} ngx_http_metric_loc_conf_t;


static ngx_int_t ngx_http_metric_request_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_metric_response_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_metric_end_handler(ngx_http_request_t *r);

static ngx_int_t ngx_http_metric_stage_handler(ngx_http_request_t *r,
    ngx_array_t *stage_zones);


typedef struct {
    const char                  *name;
    ngx_uint_t                   id;
    off_t                        conf_off;
    ngx_int_t                  (*handler)(ngx_http_request_t *r);
} ngx_http_metric_phase_t;


#define NGX_HTTP_METRIC_RESPONSE_PHASE  0xff


static ngx_http_metric_phase_t  ngx_http_metric_phases[] = {

    { "end",
      NGX_HTTP_LOG_PHASE,
      offsetof(ngx_http_metric_loc_conf_t, end),
      ngx_http_metric_end_handler },

    { "response",
      NGX_HTTP_METRIC_RESPONSE_PHASE,
      offsetof(ngx_http_metric_loc_conf_t, response),
      ngx_http_metric_response_handler },

    { "request",
      NGX_HTTP_PRECONTENT_PHASE,
      offsetof(ngx_http_metric_loc_conf_t, request),
      ngx_http_metric_request_handler }
};


typedef struct {
    char                        *fmt;
    size_t                       size;
    void                       (*set)(ngx_http_request_t *r,
                                      ngx_http_variable_value_t *v,
                                      uintptr_t data);
    ngx_int_t                  (*get)(ngx_http_request_t *r,
                                      ngx_http_variable_value_t *v,
                                      uintptr_t data);
} ngx_http_metric_var_t;


static void ngx_http_metric_var_set_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_metric_var_get_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void ngx_http_metric_var_set_key_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_metric_var_get_key_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void ngx_http_metric_var_set_value_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_metric_var_get_value_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_metric_complex_var_get_value_handler(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

static ngx_http_metric_request_ctx_t *ngx_http_metric_get_var_ctx(
    ngx_http_request_t *r);
static ngx_http_metric_request_ctx_t *ngx_http_metric_get_request_ctx(
    ngx_http_request_t *r);
static void ngx_http_metric_request_cleanup(void *data);


static ngx_http_metric_var_t  ngx_http_metric_vars[] = {

    { "metric_%V",                         /* variable format */
      sizeof("metric_"),                   /* variable size */
      ngx_http_metric_var_set_handler,     /* set handler */
      ngx_http_metric_var_get_handler },   /* get handler */

    { "metric_%V_key",
      sizeof("metric__key"),
      ngx_http_metric_var_set_key_handler,
      ngx_http_metric_var_get_key_handler },

    { "metric_%V_value",
      sizeof("metric__value"),
      ngx_http_metric_var_set_value_handler,
      ngx_http_metric_var_get_value_handler }
};


static ngx_http_metric_var_t ngx_http_metric_complex_vars[] = {

    { "metric_%V_value_%V",
      sizeof("metric__value_"),
      NULL,
      ngx_http_metric_complex_var_get_value_handler }
};


static ngx_int_t ngx_http_metric_handler(ngx_http_request_t *r,
    ngx_http_metric_ctx_t *mctx, ngx_str_t key, ngx_str_t val);

static ngx_http_metric_node_t *ngx_http_metric_lookup(
    ngx_http_metric_ctx_t *mctx, ngx_uint_t hash, ngx_str_t key,
    u_char **endptr);
static ngx_http_metric_node_t *ngx_http_metric_find_node_locked(
    ngx_http_metric_ctx_t *mctx, ngx_uint_t hash, ngx_str_t key,
    u_char **endptr);
static void *ngx_http_metric_alloc_locked(ngx_http_metric_ctx_t *mctx);
static ngx_inline void ngx_http_metric_free_locked(ngx_http_metric_ctx_t *mctx,
    ngx_queue_t *q);
static u_char *ngx_http_metric_skip_key_locked(ngx_http_metric_node_t *node);

static ngx_int_t ngx_http_metric_init_zone(ngx_shm_zone_t *shm_zone,
    void *data);
static ngx_inline ngx_int_t ngx_http_metric_init_values(
    ngx_http_metric_ctx_t *mctx, u_char *pos, u_char *end, void **last);

static char *ngx_http_metric_zone_complex(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_metric_zone_inline(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static char *ngx_http_metric_create_complex_vars(ngx_conf_t *cf,
    ngx_http_metric_ctx_t *mctx);
static char *ngx_http_metric_create_vars(ngx_conf_t *cf,
    ngx_http_metric_ctx_t *mctx);

static char *ngx_http_metric(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void ngx_http_metric_parse_key_value(ngx_str_t *key, ngx_str_t *value,
    ngx_str_t src);

static void *ngx_http_metric_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_metric_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_metric_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_metric_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_metric_commands[] = {

    { ngx_string("metric_complex_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE123,
      ngx_http_metric_zone_complex,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("metric_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_2MORE,
      ngx_http_metric_zone_inline,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("metric"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE23,
      ngx_http_metric,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_metric_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_metric_init,                  /* postconfiguration */

    ngx_http_metric_create_main_conf,      /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_metric_create_loc_conf,       /* create location configuration */
    ngx_http_metric_merge_loc_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_metric_module = {
    NGX_MODULE_V1,
    &ngx_http_metric_module_ctx,           /* module context */
    ngx_http_metric_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t ngx_http_metric_api_zone_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_http_metric_api_zone_iter(ngx_api_iter_ctx_t *ictx,
    ngx_api_ctx_t *actx);
static ngx_int_t ngx_http_metric_api_discarded_handler(
    ngx_api_entry_data_t data, ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_http_metric_api_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);
static ngx_int_t ngx_http_metric_api_keys_iter(ngx_api_ctx_t *actx,
    ngx_http_metric_ctx_t *mctx);

static u_char *ngx_http_metric_api_alloc_str(ngx_data_item_t **item,
    ngx_pool_t *pool, size_t len);

static ngx_inline void ngx_http_metric_slab_first_locked(u_char **pos,
    u_char **endptr);
static ngx_inline void ngx_http_metric_slab_next_locked(u_char **pos,
    u_char **endptr);

static ngx_int_t ngx_http_metric_api_inline_handler(ngx_api_ctx_t *actx,
    ngx_http_metric_ctx_t *mctx, u_char *pos, u_char *end);
static ngx_int_t ngx_http_metric_api_complex_handler(ngx_api_ctx_t *actx,
    ngx_http_metric_ctx_t *mctx, u_char *pos, u_char *end);
static ngx_int_t ngx_http_metric_api_complex_iter(ngx_api_iter_ctx_t *ictx,
    ngx_api_ctx_t *actx);


static ngx_api_entry_t  ngx_http_metric_api_zone_entries[] = {

    {
        .name      = ngx_string("discarded"),
        .handler   = ngx_http_metric_api_discarded_handler,
    },

    {
        .name      = ngx_string("metrics"),
        .handler   = ngx_http_metric_api_handler,
    },

    ngx_api_null_entry
};


static ngx_api_entry_t  ngx_http_metric_api_zone_entry = {
    .name    = ngx_string("metric_zones"),
    .handler = ngx_http_metric_api_zone_handler,
};


static ngx_int_t ngx_http_metric_count_init(ngx_http_metric_state_ctx_t *sctx,
    void **pos, void *end);
static ngx_int_t ngx_http_metric_count_expire(
    ngx_http_metric_state_ctx_t *sctx, void **pos_e, void *end_e, void **pos_q,
    void *end_q);
static ngx_int_t ngx_http_metric_count_set(ngx_http_metric_state_ctx_t *sctx,
    void **pos, void *end, double value);
static ngx_int_t ngx_http_metric_count_get(ngx_http_metric_state_ctx_t *sctx,
    void **pos, void *end, ngx_str_t *buf);

static ngx_int_t ngx_http_metric_num_api(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);

static ngx_int_t ngx_http_metric_min_init(ngx_http_metric_state_ctx_t *sctx,
    void **pos, void *end);
static ngx_int_t ngx_http_metric_min_expire(ngx_http_metric_state_ctx_t *sctx,
    void **pos_e, void *end_e, void **pos_q, void *end_q);
static ngx_int_t ngx_http_metric_min_set(ngx_http_metric_state_ctx_t *sctx,
    void **pos, void *end, double value);

static ngx_int_t ngx_http_metric_frac_get(ngx_http_metric_state_ctx_t *sctx,
    void **pos, void *end, ngx_str_t *buf);
static ngx_int_t ngx_http_metric_frac_api(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);

static ngx_int_t ngx_http_metric_max_init(ngx_http_metric_state_ctx_t *sctx,
    void **pos, void *end);
static ngx_int_t ngx_http_metric_max_expire(ngx_http_metric_state_ctx_t *sctx,
    void **pos_e, void *end_e, void **pos_q, void *end_q);
static ngx_int_t ngx_http_metric_max_set(ngx_http_metric_state_ctx_t *sctx,
    void **pos, void *end, double value);

static ngx_int_t ngx_http_metric_last_init(ngx_http_metric_state_ctx_t *sctx,
    void **pos, void *end);
static ngx_int_t ngx_http_metric_last_expire(ngx_http_metric_state_ctx_t *sctx,
    void **pos_e, void *end_e, void **pos_q, void *end_q);
static ngx_int_t ngx_http_metric_last_set(ngx_http_metric_state_ctx_t *sctx,
    void **pos, void *end, double value);

static ngx_int_t ngx_http_metric_gauge_init(ngx_http_metric_state_ctx_t *sctx,
    void **pos, void *end);
static ngx_int_t ngx_http_metric_gauge_expire(
    ngx_http_metric_state_ctx_t *sctx, void **pos_e, void *end_e, void **pos_q,
    void *end_q);
static ngx_int_t ngx_http_metric_gauge_set(ngx_http_metric_state_ctx_t *sctx,
    void **pos, void *end, double value);

static char *ngx_http_metric_avg_mean_conf(ngx_conf_t *cf, ngx_uint_t start,
    ngx_http_metric_ctx_t *mctx, ngx_http_metric_args_t *args);
static ngx_int_t ngx_http_metric_avg_mean_init(
    ngx_http_metric_state_ctx_t *sctx, void **pos, void *end);
static ngx_int_t ngx_http_metric_avg_mean_expire(
    ngx_http_metric_state_ctx_t *sctx, void **pos_e, void *end_e,
    void **pos_q, void *end_q);
static ngx_int_t ngx_http_metric_avg_mean_set(
    ngx_http_metric_state_ctx_t *sctx, void **pos, void *end, double value);
static ngx_int_t ngx_http_metric_avg_mean_get(
    ngx_http_metric_state_ctx_t *sctx, void **pos, void *end, ngx_str_t *buf);
static ngx_int_t ngx_http_metric_avg_mean_api(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);

static char *ngx_http_metric_avg_exp_conf(ngx_conf_t *cf, ngx_uint_t start,
    ngx_http_metric_ctx_t *mctx, ngx_http_metric_args_t *args);
static ngx_int_t ngx_http_metric_avg_exp_init(
    ngx_http_metric_state_ctx_t *sctx, void **pos, void *end);
static ngx_int_t ngx_http_metric_avg_exp_expire(
    ngx_http_metric_state_ctx_t *sctx, void **pos_e, void *end_e,
    void **pos_q, void *end_q);
static ngx_int_t ngx_http_metric_avg_exp_set(ngx_http_metric_state_ctx_t *sctx,
    void **pos, void *end, double value);

static char *ngx_http_metric_hist_conf(ngx_conf_t *cf, ngx_uint_t start,
    ngx_http_metric_ctx_t *mctx, ngx_http_metric_args_t *args);
static ngx_int_t ngx_http_metric_hist_init(ngx_http_metric_state_ctx_t *sctx,
    void **pos, void *end);
static ngx_int_t ngx_http_metric_hist_expire(ngx_http_metric_state_ctx_t *sctx,
    void **pos_e, void *end_e, void **pos_q, void *end_q);
static ngx_int_t ngx_http_metric_hist_set(ngx_http_metric_state_ctx_t *sctx,
    void **pos, void *end, double value);
static ngx_int_t ngx_http_metric_hist_get(ngx_http_metric_state_ctx_t *sctx,
    void **pos, void *end, ngx_str_t *buf);
static ngx_int_t ngx_http_metric_hist_api(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx);

static ngx_int_t ngx_http_metric_api_hist_iter(ngx_api_iter_ctx_t *ictx,
    ngx_api_ctx_t *actx);


#define NGX_HTTP_METRIC_COUNT     0
#define NGX_HTTP_METRIC_FRAC      1
#define NGX_HTTP_METRIC_AVG_MEAN  2
#define NGX_HTTP_METRIC_HIST      3


static ngx_http_metric_mode_t  ngx_http_metric_modes[] = {

    { ngx_string("count"),                 /* mode name */
      NGX_HTTP_METRIC_COUNT,               /* mode type */
      NULL,                                /* configuration */
      ngx_http_metric_count_init,          /* initialization */
      ngx_http_metric_count_expire,        /* expire value */
      ngx_http_metric_count_set,           /* set value */
      ngx_http_metric_count_get,           /* get value */
      ngx_http_metric_num_api },           /* api handler */

    { ngx_string("min"),
      NGX_HTTP_METRIC_FRAC,
      NULL,
      ngx_http_metric_min_init,
      ngx_http_metric_min_expire,
      ngx_http_metric_min_set,
      ngx_http_metric_frac_get,
      ngx_http_metric_frac_api },

    { ngx_string("max"),
      NGX_HTTP_METRIC_FRAC,
      NULL,
      ngx_http_metric_max_init,
      ngx_http_metric_max_expire,
      ngx_http_metric_max_set,
      ngx_http_metric_frac_get,
      ngx_http_metric_frac_api },

    { ngx_string("last"),
      NGX_HTTP_METRIC_FRAC,
      NULL,
      ngx_http_metric_last_init,
      ngx_http_metric_last_expire,
      ngx_http_metric_last_set,
      ngx_http_metric_frac_get,
      ngx_http_metric_frac_api },

    { ngx_string("gauge"),
      NGX_HTTP_METRIC_FRAC,
      NULL,
      ngx_http_metric_gauge_init,
      ngx_http_metric_gauge_expire,
      ngx_http_metric_gauge_set,
      ngx_http_metric_frac_get,
      ngx_http_metric_frac_api },

    { ngx_string("average mean"),
      NGX_HTTP_METRIC_AVG_MEAN,
      ngx_http_metric_avg_mean_conf,
      ngx_http_metric_avg_mean_init,
      ngx_http_metric_avg_mean_expire,
      ngx_http_metric_avg_mean_set,
      ngx_http_metric_avg_mean_get,
      ngx_http_metric_avg_mean_api },

    { ngx_string("average exp"),
      NGX_HTTP_METRIC_FRAC,
      ngx_http_metric_avg_exp_conf,
      ngx_http_metric_avg_exp_init,
      ngx_http_metric_avg_exp_expire,
      ngx_http_metric_avg_exp_set,
      ngx_http_metric_frac_get,
      ngx_http_metric_frac_api },

    { ngx_string("histogram"),
      NGX_HTTP_METRIC_HIST,
      ngx_http_metric_hist_conf,
      ngx_http_metric_hist_init,
      ngx_http_metric_hist_expire,
      ngx_http_metric_hist_set,
      ngx_http_metric_hist_get,
      ngx_http_metric_hist_api }
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;


static ngx_int_t
ngx_http_metric_request_handler(ngx_http_request_t *r)
{
    ngx_int_t                       rc;
    ngx_http_metric_loc_conf_t     *mlcf;
    ngx_http_metric_request_ctx_t  *rctx;

    if (r != r->main) {
        return NGX_DECLINED;
    }

    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_metric_module);

    if (mlcf->request == NULL) {
        return NGX_DECLINED;
    }

    rctx = ngx_http_metric_get_request_ctx(r);
    if (rctx == NULL) {
        return NGX_ERROR;
    }

    if (rctx->stage == NGX_HTTP_METRIC_STAGE_REQUEST) {
        rc = ngx_http_metric_stage_handler(r, mlcf->request);
        if (rc != NGX_OK) {
            return rc;
        }

        rctx->stage = NGX_HTTP_METRIC_STAGE_RESPONSE;
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_metric_response_handler(ngx_http_request_t *r)
{
    ngx_int_t                       rc;
    ngx_http_metric_loc_conf_t     *mlcf;
    ngx_http_metric_request_ctx_t  *rctx;

    if (r != r->main) {
        return ngx_http_next_header_filter(r);
    }

    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_metric_module);

    if (mlcf->request == NULL && mlcf->response == NULL) {
        return ngx_http_next_header_filter(r);
    }

    rctx = ngx_http_metric_get_request_ctx(r);
    if (rctx == NULL) {
        return NGX_ERROR;
    }

    if (rctx->stage == NGX_HTTP_METRIC_STAGE_REQUEST) {
        if (mlcf->request != NULL) {
            rc = ngx_http_metric_stage_handler(r, mlcf->request);
            if (rc != NGX_OK) {
                return rc;
            }
        }
    }

    rctx->stage = NGX_HTTP_METRIC_STAGE_END;

    rc = ngx_http_next_header_filter(r);

    if (mlcf->response != NULL
        && r->header_sent
        && ngx_http_metric_stage_handler(r, mlcf->response) != NGX_OK)
    {
        rc = NGX_ERROR;
    }

    return rc;
}


static ngx_int_t
ngx_http_metric_end_handler(ngx_http_request_t *r)
{
    ngx_int_t                       rc;
    ngx_http_metric_loc_conf_t     *mlcf;
    ngx_http_metric_request_ctx_t  *rctx;

    rc = NGX_DECLINED;

    if (r != r->main) {
        return rc;
    }

    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_metric_module);

    if (mlcf->request == NULL
        && mlcf->response == NULL
        && mlcf->end == NULL)
    {
        return rc;
    }

    rctx = ngx_http_metric_get_request_ctx(r);
    if (rctx == NULL) {
        return NGX_ERROR;
    }

    switch (rctx->stage) {
    case NGX_HTTP_METRIC_STAGE_REQUEST:
        if (mlcf->request != NULL) {
            rc = ngx_http_metric_stage_handler(r, mlcf->request);
            if (rc != NGX_OK) {
                break;
            }
        }

        /* fall through */

    case NGX_HTTP_METRIC_STAGE_RESPONSE:
        if (mlcf->response != NULL) {
            rc = ngx_http_metric_stage_handler(r, mlcf->response);
            if (rc != NGX_OK) {
                break;
            }
        }

        /* fall through */

    case NGX_HTTP_METRIC_STAGE_END:
        if (mlcf->end == NULL) {
            return NGX_DECLINED;
        }

        rc = ngx_http_metric_stage_handler(r, mlcf->end);
    }

    return rc;
}


static ngx_int_t
ngx_http_metric_stage_handler(ngx_http_request_t *r, ngx_array_t *stage_zones)
{
    ngx_int_t                 rc;
    ngx_str_t                 key, val;
    ngx_uint_t                i;
    ngx_http_metric_ctx_t    *mctx;
    ngx_http_metric_stage_t  *stage;

    stage = stage_zones->elts;

    for (i = 0; i < stage_zones->nelts; i++) {

        mctx = stage[i].shm_zone->data;

        if (ngx_http_complex_value(r, &stage[i].key, &key) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_http_complex_value(r, &stage[i].value, &val) != NGX_OK) {
            return NGX_ERROR;
        }

        rc = ngx_http_metric_handler(r, mctx, key, val);

        if (rc == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "failed to update metric \"%V\" with \"%V=%V\"",
                          &mctx->shm_zone->shm.name, &key, &val);
        }
    }

    return NGX_OK;
}


static void
ngx_http_metric_var_set_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_metric_ctx_t  *mctx = (ngx_http_metric_ctx_t *) data;

    ngx_int_t                       rc;
    ngx_str_t                       key, val, tmp;
    ngx_http_metric_request_ctx_t  *rctx;

    rctx = ngx_http_metric_get_var_ctx(r);
    if (rctx == NULL) {
        return;
    }

    tmp.len = v->len;
    tmp.data = v->data;

    ngx_http_metric_parse_key_value(&key, &val, tmp);

    rc = ngx_http_metric_handler(r, mctx, key, val);

    if (rc == NGX_OK) {
        rctx->tmp.len = ngx_min(tmp.len, NGX_HTTP_METRIC_MAX_LEN);
        ngx_memcpy(rctx->tmp.data, tmp.data, rctx->tmp.len);

        rctx->key.len = ngx_min(key.len, NGX_HTTP_METRIC_MAX_LEN);
        ngx_memcpy(rctx->key.data, key.data, rctx->key.len);

        rctx->mctx = mctx;
    }
}


static ngx_int_t
ngx_http_metric_var_get_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_metric_request_ctx_t  *rctx;

    rctx = ngx_http_metric_get_var_ctx(r);
    if (rctx == NULL) {
        return NGX_ERROR;
    }

    if (rctx->tmp.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = rctx->tmp.len;
    v->data = rctx->tmp.data;

    return NGX_OK;
}


static void
ngx_http_metric_var_set_key_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_metric_request_ctx_t  *rctx;

    rctx = ngx_http_metric_get_var_ctx(r);
    if (rctx == NULL) {
        return;
    }

    rctx->key.len = ngx_min(v->len, NGX_HTTP_METRIC_MAX_LEN);
    ngx_memcpy(rctx->key.data, v->data, rctx->key.len);

    rctx->mctx = (ngx_http_metric_ctx_t *) data;
}


static ngx_int_t
ngx_http_metric_var_get_key_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_metric_request_ctx_t  *rctx;

    rctx = ngx_http_metric_get_var_ctx(r);
    if (rctx == NULL) {
        return NGX_ERROR;
    }

    if (rctx->key.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = rctx->key.len;
    v->data = rctx->key.data;

    return NGX_OK;
}


static void
ngx_http_metric_var_set_value_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_metric_ctx_t  *mctx = (ngx_http_metric_ctx_t *) data;

    ngx_int_t                       rc;
    ngx_str_t                      *key, *tmp, val;
    ngx_http_metric_request_ctx_t  *rctx;

    rctx = ngx_http_metric_get_var_ctx(r);
    if (rctx == NULL) {
        return;
    }

    val.data = v->data;
    val.len = v->len;

    rc = ngx_http_metric_handler(r, mctx, rctx->key, val);

    if (rc != NGX_OK) {
        return;
    }

    key = &rctx->key;
    tmp = &rctx->tmp;

    tmp->len = ngx_min(key->len + val.len + 1, NGX_HTTP_METRIC_MAX_LEN);

    ngx_snprintf(tmp->data, tmp->len, "%V=%V", key, &val);
}


static ngx_int_t
ngx_http_metric_var_get_value_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_metric_ctx_t  *mctx = (ngx_http_metric_ctx_t *) data;

    size_t                           size;
    u_char                          *end, *pos, *start;
    ngx_int_t                        rc;
    ngx_str_t                        buf;
    ngx_uint_t                       hash, i;
    ngx_http_metric_t              **metric_ptr;
    ngx_http_metric_node_t          *node;
    ngx_http_metric_state_ctx_t      sctx;
    ngx_http_metric_request_ctx_t   *rctx;

    rctx = ngx_http_metric_get_var_ctx(r);
    if (rctx == NULL) {
        return NGX_ERROR;
    }

    if (rctx->key.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    /* the size contains the number of metrics delimiters */
    size = mctx->str_size + (mctx->metrics->nelts - 1) * 2;

    start = ngx_pnalloc(r->connection->pool, size);
    if (start == NULL) {
        return NGX_ERROR;
    }

    buf.len = 0;
    buf.data = start;

    hash = ngx_crc32_short(rctx->key.data, rctx->key.len);

    ngx_rwlock_rlock(&mctx->sh->rbt_lock);

    node = ngx_http_metric_find_node_locked(mctx, hash, rctx->key, &end);

    if (node == NULL) {
        /* the expired node is not in the rbtree */

        if (mctx->sh->is_expired == 0
            || mctx->discard_key.len != rctx->key.len
            || ngx_memcmp(mctx->discard_key.data, rctx->key.data,
                          rctx->key.len) != 0)
        {
            ngx_rwlock_unlock(&mctx->sh->rbt_lock);
            v->not_found = 1;
            return NGX_OK;
        }

        node = mctx->sh->expired;
        end = ngx_align_ptr(node->key, NGX_HTTP_METRIC_PTR_SIZE);
    }

    ngx_rwlock_rlock(&node->lock);
    ngx_rwlock_unlock(&mctx->sh->rbt_lock);

    ngx_http_metric_slab_first_locked(&pos, &end);

    i = 0;

    metric_ptr = mctx->metrics->elts;

    for ( ;; ) {

        ngx_memzero(&sctx, sizeof(ngx_http_metric_state_ctx_t));

        sctx.args = metric_ptr[i]->args;

        do {
            if (pos == end) {
                ngx_http_metric_slab_next_locked(&pos, &end);
            }

            rc = metric_ptr[i]->mode->get(&sctx, (void **) &pos, end, &buf);

        } while (rc == NGX_AGAIN);

        i++;

        if (i == mctx->metrics->nelts) {
            break;
        }

        buf.len += 2;
        *buf.data++ = ',';
        *buf.data++ = ' ';
    }

    ngx_rwlock_unlock(&node->lock);

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = buf.len;
    v->data = start;

    return NGX_OK;
}


static ngx_int_t
ngx_http_metric_complex_var_get_value_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_metric_t  *metric = (ngx_http_metric_t *) data;

    u_char                         *end, *pos, *start;
    size_t                          chunk, rest;
    ngx_str_t                       buf;
    ngx_int_t                       rc;
    ngx_uint_t                      hash;
    ngx_http_metric_ctx_t          *mctx;
    ngx_http_metric_node_t         *node;
    ngx_http_metric_state_ctx_t     sctx;
    ngx_http_metric_request_ctx_t  *rctx;

    rctx = ngx_http_metric_get_var_ctx(r);
    if (rctx == NULL) {
        return NGX_ERROR;
    }

    if (rctx->key.len == 0 || rctx->mctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    start = ngx_pnalloc(r->connection->pool, metric->str_size);
    if (start == NULL) {
        return NGX_ERROR;
    }

    buf.len = 0;
    buf.data = start;

    hash = ngx_crc32_short(rctx->key.data, rctx->key.len);

    mctx = rctx->mctx;

    ngx_rwlock_rlock(&mctx->sh->rbt_lock);

    node = ngx_http_metric_find_node_locked(mctx, hash, rctx->key, &end);

    if (node == NULL) {
        /* the expired node is not in the rbtree */

        if (mctx->sh->is_expired == 0
            || mctx->discard_key.len != rctx->key.len
            || ngx_memcmp(mctx->discard_key.data, rctx->key.data,
                          rctx->key.len) != 0)
        {
            ngx_rwlock_unlock(&mctx->sh->rbt_lock);
            v->not_found = 1;
            return NGX_OK;
        }

        node = mctx->sh->expired;
        end = ngx_align_ptr(node->key, NGX_HTTP_METRIC_PTR_SIZE);
    }

    ngx_rwlock_rlock(&node->lock);
    ngx_rwlock_unlock(&mctx->sh->rbt_lock);

    ngx_http_metric_slab_first_locked(&pos, &end);

    rest = metric->offset;

    for ( ;; ) {
        chunk = ngx_min((size_t) (end - pos), rest);

        rest -= chunk;

        if (rest == 0) {
            break;
        }

        ngx_http_metric_slab_next_locked(&pos, &end);
    }

    pos += chunk;

    ngx_memzero(&sctx, sizeof(ngx_http_metric_state_ctx_t));

    sctx.args = metric->args;

    do {
        if (pos == end) {
            ngx_http_metric_slab_next_locked(&pos, &end);
        }

        rc = metric->mode->get(&sctx, (void **) &pos, end, &buf);

    } while (rc == NGX_AGAIN);

    ngx_rwlock_unlock(&node->lock);

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = buf.len;
    v->data = start;

    return NGX_OK;
}


static ngx_http_metric_request_ctx_t *
ngx_http_metric_get_var_ctx(ngx_http_request_t *r)
{
    ngx_http_metric_request_ctx_t  *rctx;

    rctx = ngx_http_metric_get_request_ctx(r);
    if (rctx == NULL) {
        return NULL;
    }

    if (rctx->key.data == NULL) {
        rctx->key.data = ngx_pnalloc(r->connection->pool,
                                     NGX_HTTP_METRIC_MAX_LEN);
        if (rctx->key.data == NULL) {
            return NULL;
        }
    }

    if (rctx->tmp.data == NULL) {
        rctx->tmp.data = ngx_pnalloc(r->connection->pool,
                                     NGX_HTTP_METRIC_MAX_LEN);
        if (rctx->tmp.data == NULL) {
            return NULL;
        }
    }

    return rctx;
}


static ngx_http_metric_request_ctx_t *
ngx_http_metric_get_request_ctx(ngx_http_request_t *r)
{
    ngx_pool_cleanup_t             *cln;
    ngx_http_metric_request_ctx_t  *rctx;

    rctx = ngx_http_get_module_ctx(r, ngx_http_metric_module);

    if (rctx != NULL) {
        return rctx;
    }

    /*
     * if module context was reset, the original context
     * can still be found in the cleanup handler
     */

    for (cln = r->pool->cleanup; cln; cln = cln->next) {
        if (cln->handler == ngx_http_metric_request_cleanup) {
            return cln->data;
        }
    }

    cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_http_metric_request_ctx_t));
    if (cln == NULL) {
        return NULL;
    }

    rctx = cln->data;

    ngx_memzero(rctx, sizeof(ngx_http_metric_request_ctx_t));

    cln->handler = ngx_http_metric_request_cleanup;
    ngx_http_set_ctx(r, rctx, ngx_http_metric_module);

    return rctx;
}


static void
ngx_http_metric_request_cleanup(void *data)
{
#if 0
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "metric request cleanup");
#endif
    return;
}


static ngx_int_t
ngx_http_metric_handler(ngx_http_request_t *r, ngx_http_metric_ctx_t *mctx,
    ngx_str_t key, ngx_str_t val)
{
    double                         n;
    u_char                        *end, *endptr, *pos;
    uint32_t                       hash;
    ngx_int_t                      rc;
    ngx_uint_t                     i;
    ngx_http_metric_t            **metric_ptr;
    ngx_http_metric_node_t        *node;
    ngx_http_metric_state_ctx_t    sctx;
    u_char                         s[NGX_HTTP_METRIC_MAX_LEN + 1];

    if (key.len == 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "empty metric key for zone \"%V\"",
                       &mctx->shm_zone->shm.name);
        return NGX_DECLINED;
    }

    if (mctx->discard_key.len == key.len
        && ngx_memcmp(mctx->discard_key.data, key.data, key.len) == 0)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "expired metric cannot be changed");
        return NGX_DECLINED;
    }

    val.len = ngx_min(val.len, NGX_HTTP_METRIC_MAX_LEN);

    ngx_memcpy(s, (char *) val.data, val.len);

    s[val.len] = '\0';

    n = ngx_strtod(s, &endptr);

    if (endptr == s && *endptr != '\0') {
        /*
         * an empty string is handled as 0, while a non-empty string without
         * numbers at the beginning is handled as 1
         */
        n = 1;
    }

    key.len = ngx_min(key.len, NGX_HTTP_METRIC_MAX_LEN);
    hash = ngx_crc32_short(key.data, key.len);

    node = ngx_http_metric_lookup(mctx, hash, key, &end);
    if (node == NULL) {
        return NGX_ERROR;
    }

    /* ngx_rwlock_wlock(&node->lock) via ngx_http_metric_lookup */

    ngx_http_metric_slab_first_locked(&pos, &end);

    metric_ptr = mctx->metrics->elts;

    for (i = 0; i < mctx->metrics->nelts; i++) {

        ngx_memzero(&sctx, sizeof(ngx_http_metric_state_ctx_t));

        sctx.args = metric_ptr[i]->args;

        do {
            if (pos == end) {
                ngx_http_metric_slab_next_locked(&pos, &end);
            }

            rc = metric_ptr[i]->mode->set(&sctx, (void **) &pos, end, n);

        } while (rc == NGX_AGAIN);
    }

    ngx_rwlock_unlock(&node->lock);

    return NGX_OK;
}


static ngx_http_metric_node_t *
ngx_http_metric_lookup(ngx_http_metric_ctx_t *mctx, ngx_uint_t hash,
    ngx_str_t key, u_char **endptr)
{
    void                    **last;
    size_t                    chunk;
    u_char                   *end, *pos;
    ngx_int_t                 rc;
    ngx_rbtree_node_t        *rbt;
    ngx_http_metric_node_t   *node;

    ngx_rwlock_rlock(&mctx->sh->rbt_lock);

    node = ngx_http_metric_find_node_locked(mctx, hash, key, endptr);

    if (node != NULL) {
        ngx_rwlock_wlock(&node->lock);
        ngx_rwlock_unlock(&mctx->sh->rbt_lock);
        return node;
    }

    ngx_rwlock_unlock(&mctx->sh->rbt_lock);

    /* inserting a new node */

    ngx_rwlock_wlock(&mctx->sh->rbt_lock);

    /* a node could be added between the locks */

    node = ngx_http_metric_find_node_locked(mctx, hash, key, endptr);

    if (node != NULL) {
        ngx_rwlock_wlock(&node->lock);
        ngx_rwlock_unlock(&mctx->sh->rbt_lock);
        return node;
    }

    rbt = ngx_http_metric_alloc_locked(mctx);
    if (rbt == NULL) {
        goto done;
    }

    rbt->key = hash;

    node = (ngx_http_metric_node_t *) &rbt->color;

    node->lock = 0;
    node->key_len = (uint8_t) key.len;

    pos = node->key;
    end = (u_char *) rbt + NGX_HTTP_METRIC_DATA_SIZE;

    /* *last is a pointer to the end of data in next slab */

    last = (void **) end;
    *last = NULL;

    for ( ;; ) {
        chunk = ngx_min((size_t) (end - pos), key.len);

        ngx_memcpy(pos, key.data, chunk);

        key.len -= chunk;

        if (key.len == 0) {
            break;
        }

        /* pos == end */

        key.data += chunk;

        pos = ngx_http_metric_alloc_locked(mctx);
        if (pos == NULL) {
            goto cleanup;
        }

        last = (void **) end;

        end = pos + NGX_HTTP_METRIC_DATA_SIZE;
        *(void **) end = NULL;

        *last = end;
    }

    pos = ngx_align_ptr(pos + chunk, NGX_HTTP_METRIC_PTR_SIZE);

    /* to ensure that last_data and pos are located in the same slab */

    if (end - pos < 2 * NGX_HTTP_METRIC_PTR_SIZE) {
        pos = ngx_http_metric_alloc_locked(mctx);
        if (pos == NULL) {
            goto cleanup;
        }

        last = (void **) end;

        end = pos + NGX_HTTP_METRIC_DATA_SIZE;
        *(void **) end = NULL;

        *last = end;
    }

    *endptr = pos;

    rc = ngx_http_metric_init_values(mctx, pos, end, last);

    if (rc == NGX_OK) {
        ngx_rbtree_insert(&mctx->sh->rbtree, rbt);

        ngx_queue_insert_head(&mctx->sh->queue, &node->queue);

        ngx_rwlock_wlock(&node->lock);
        ngx_rwlock_unlock(&mctx->sh->rbt_lock);

        return node;
    }

cleanup:

    end = (u_char *) rbt + NGX_HTTP_METRIC_DATA_SIZE;
    end = *(void **) end;

    while (end) {
        pos = ngx_align_ptr(end - NGX_HTTP_METRIC_SLAB_SIZE,
                            NGX_HTTP_METRIC_SLAB_SIZE);
        end = *(void **) end;

        ngx_slab_free_locked(mctx->shpool, pos);
    }

    ngx_slab_free_locked(mctx->shpool, rbt);

done:

    if (mctx->expire != 0 || mctx->sh->is_expired == 0) {
        ngx_rwlock_unlock(&mctx->sh->rbt_lock);
        return NULL;
    }

    /* expire node */

    node = mctx->sh->expired;

    *endptr = ngx_align_ptr(node->key, NGX_HTTP_METRIC_PTR_SIZE);

    ngx_rwlock_wlock(&node->lock);
    ngx_rwlock_unlock(&mctx->sh->rbt_lock);

    return node;
}


static ngx_http_metric_node_t *
ngx_http_metric_find_node_locked(ngx_http_metric_ctx_t *mctx,
    ngx_uint_t hash, ngx_str_t key, u_char **endptr)
{
    u_char                  *end, *pos;
    size_t                   chunk;
    ngx_int_t                rc;
    ngx_str_t                tmp;
    ngx_rbtree_node_t       *rbt, *sentinel;
    ngx_http_metric_node_t  *node;

    rbt = mctx->sh->rbtree.root;
    sentinel = mctx->sh->rbtree.sentinel;

    while (rbt != sentinel) {

        if (hash < rbt->key) {
            rbt = rbt->left;
            continue;
        }

        if (hash > rbt->key) {
            rbt = rbt->right;
            continue;
        }

        /* hash = rbt->key */

        node = (ngx_http_metric_node_t *) &rbt->color;

        /*
         * the node lock doesn't need to be set,
         * as this part cannot be changed due to the rbtree lock
         */

        if (node->key_len != key.len) {
            rbt = (node->key_len > key.len) ? rbt->left : rbt->right;
            continue;
        }

        /* node->key_len == key.len */

        pos = node->key;
        end = (u_char *) rbt + NGX_HTTP_METRIC_DATA_SIZE;

        tmp = key;

        for ( ;; ) {
            chunk = ngx_min((size_t) (end - pos), tmp.len);

            rc = ngx_memcmp(tmp.data, pos, chunk);

            if (rc != 0) {
                rbt = (rc < 0) ? rbt->left : rbt->right;
                goto next;
            }

            tmp.len -= chunk;

            if (tmp.len == 0) {
                break;
            }

            tmp.data += chunk;

            ngx_http_metric_slab_next_locked(&pos, &end);
        }

        /* rc == 0 */

        pos = ngx_align_ptr(pos + chunk, NGX_HTTP_METRIC_PTR_SIZE);

        if (end - pos < 2 * NGX_HTTP_METRIC_PTR_SIZE) {
            ngx_http_metric_slab_next_locked(&pos, &end);
        }

        if (mctx->expire) {
            ngx_rwlock_wlock(&mctx->sh->queue_lock);
            ngx_queue_remove(&node->queue);
            ngx_queue_insert_head(&mctx->sh->queue, &node->queue);
            ngx_rwlock_unlock(&mctx->sh->queue_lock);
        }

        *endptr = pos;

        return node;

    next:

        continue;
    }

    return NULL;
}


static void *
ngx_http_metric_alloc_locked(ngx_http_metric_ctx_t *mctx)
{
    void                          *mem;
    u_char                        *end_e, *end_q, *pos_e, *pos_q;
    ngx_int_t                      rc;
    ngx_uint_t                     i;
    ngx_queue_t                   *q;
    ngx_http_metric_t            **metric_ptr;
    ngx_http_metric_node_t        *node_e, *node_q;
    ngx_http_metric_state_ctx_t    sctx;

    mem = ngx_slab_alloc_locked(mctx->shpool, NGX_HTTP_METRIC_SLAB_SIZE);
    if (mem != NULL) {
        return mem;
    }

    mctx->sh->discarded++;

    if (ngx_queue_empty(&mctx->sh->queue)) {
        return NULL;
    }

    node_e = mctx->sh->expired;

    if (node_e == NULL) {
        if (mctx->expire == 0) {
            return NULL;
        }

        q = ngx_queue_last(&mctx->sh->queue);

        goto free;
    }

    /* expire node */

    mctx->sh->is_expired = 1;

    if (mctx->expire == 0) {
        return NULL;
    }

    q = ngx_queue_last(&mctx->sh->queue);

    node_q = ngx_queue_data(q, ngx_http_metric_node_t, queue);

    end_q = ngx_http_metric_skip_key_locked(node_q);
    ngx_http_metric_slab_first_locked(&pos_q, &end_q);

    end_e = ngx_align_ptr(node_e->key, NGX_HTTP_METRIC_PTR_SIZE);
    ngx_http_metric_slab_first_locked(&pos_e, &end_e);

    metric_ptr = mctx->metrics->elts;

    ngx_rwlock_rlock(&node_q->lock);
    ngx_rwlock_wlock(&node_e->lock);

    for (i = 0; i < mctx->metrics->nelts; i++) {

        ngx_memzero(&sctx, sizeof(ngx_http_metric_state_ctx_t));

        sctx.args = metric_ptr[i]->args;

        do {
            if (pos_e == end_e) {
                ngx_http_metric_slab_next_locked(&pos_e, &end_e);
            }

            if (pos_q == end_q) {
                ngx_http_metric_slab_next_locked(&pos_q, &end_q);
            }

            rc = metric_ptr[i]->mode->expire(&sctx,
                                             (void **) &pos_e, end_e,
                                             (void **) &pos_q, end_q);
        } while(rc == NGX_AGAIN);
    }

    ngx_rwlock_unlock(&node_e->lock);
    ngx_rwlock_unlock(&node_q->lock);

free:

    ngx_http_metric_free_locked(mctx, q);

    return ngx_slab_alloc_locked(mctx->shpool, NGX_HTTP_METRIC_SLAB_SIZE);
}


static ngx_inline void
ngx_http_metric_free_locked(ngx_http_metric_ctx_t *mctx, ngx_queue_t *q)
{
    u_char                  *end, *pos;
    ngx_rbtree_node_t       *rbt;
    ngx_http_metric_node_t  *node;

    node = ngx_queue_data(q, ngx_http_metric_node_t, queue);

    end = ngx_align_ptr(node->key + 1, NGX_HTTP_METRIC_SLAB_SIZE)
          - NGX_HTTP_METRIC_PTR_SIZE;
    end = *(void **) end;

    ngx_rwlock_wlock(&node->lock);

    while (end) {
        pos = ngx_align_ptr(end - NGX_HTTP_METRIC_SLAB_SIZE,
                            NGX_HTTP_METRIC_SLAB_SIZE);
        end = *(void **) end;

        ngx_slab_free_locked(mctx->shpool, pos);
    }

    ngx_queue_remove(q);

    pos = (u_char *) node - offsetof(ngx_rbtree_node_t, color);
    rbt = (ngx_rbtree_node_t *) pos;

    ngx_rbtree_delete(&mctx->sh->rbtree, rbt);

    ngx_rwlock_unlock(&node->lock);

    ngx_slab_free_locked(mctx->shpool, rbt);
}


static u_char *
ngx_http_metric_skip_key_locked(ngx_http_metric_node_t *node)
{
    size_t   chunk, rest;
    u_char  *end, *pos;

    pos = node->key;
    end = ngx_align_ptr(pos + 1, NGX_HTTP_METRIC_SLAB_SIZE)
          - NGX_HTTP_METRIC_PTR_SIZE;

    rest = node->key_len;

    for ( ;; ) {
        chunk = ngx_min((size_t) (end - pos), rest);

        rest -= chunk;

        if (rest == 0) {
            break;
        }

        ngx_http_metric_slab_next_locked(&pos, &end);
    }

    pos = ngx_align_ptr(pos + chunk, NGX_HTTP_METRIC_PTR_SIZE);

    if (end - pos < 2 * NGX_HTTP_METRIC_PTR_SIZE) {
        ngx_http_metric_slab_next_locked(&pos, &end);
    }

    return pos;
}


static void
ngx_metric_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    size_t                    chunk, rest;
    u_char                   *end_m, *end_t, *key_m, *key_t;
    ngx_rbtree_node_t       **parent;
    ngx_http_metric_node_t   *node_t, *node_m;

    for ( ;; ) {

        if (node->key < temp->key) {

            parent = &temp->left;

        } else if (node->key > temp->key) {

            parent = &temp->right;

        } else { /* node->key == temp->key */

            parent = &temp->right;

            node_m = (ngx_http_metric_node_t *) &node->color;
            node_t = (ngx_http_metric_node_t *) &temp->color;

            if (node_m->key_len != node_t->key_len) {

                if (node_m->key_len < node_t->key_len) {
                    parent = &temp->left;
                }

                break;
            }

            /* node_m->key_len == node_t->key_len */

            key_m = node_m->key;
            key_t = node_t->key;

            end_m = ngx_align_ptr(key_m + 1, NGX_HTTP_METRIC_SLAB_SIZE)
                    - NGX_HTTP_METRIC_PTR_SIZE;
            end_t = ngx_align_ptr(key_t + 1, NGX_HTTP_METRIC_SLAB_SIZE)
                    - NGX_HTTP_METRIC_PTR_SIZE;

            rest = node_m->key_len;

            for ( ;; ) {
                chunk = ngx_min((size_t) (end_m - key_m), rest);

                if (ngx_memcmp(key_m, key_t, chunk) < 0) {
                    parent = &temp->left;
                    break;
                }

                rest -= chunk;

                if (rest == 0) {
                    break;
                }

                ngx_http_metric_slab_next_locked(&key_m, &end_m);
                ngx_http_metric_slab_next_locked(&key_t, &end_t);
            }
        }

        if (*parent == sentinel) {
            break;
        }

        temp = *parent;
    }

    *parent = node;

    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;

    ngx_rbt_red(node);
}


static ngx_int_t
ngx_http_metric_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_metric_ctx_t  *octx = data;

    void                    **last;
    u_char                   *end, *pos;
    ngx_str_t                 tmp;
    ngx_int_t                 rc;
    ngx_http_metric_ctx_t    *mctx;
    ngx_http_metric_node_t   *node;

    mctx = shm_zone->data;

    if (octx) {
        mctx->sh = octx->sh;
        mctx->shpool = octx->shpool;
        return NGX_OK;
    }

    mctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        mctx->sh = mctx->shpool->data;
        return NGX_OK;
    }

    mctx->sh = ngx_slab_alloc(mctx->shpool,
                              ngx_align(sizeof(ngx_http_metric_shctx_t),
                                        NGX_HTTP_METRIC_SLAB_SIZE));
    if (mctx->sh == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(mctx->sh, sizeof(ngx_http_metric_shctx_t));

    mctx->shpool->data = &mctx->sh;

    ngx_rbtree_init(&mctx->sh->rbtree, &mctx->sh->sentinel,
                    ngx_metric_rbtree_insert_value);

    ngx_queue_init(&mctx->sh->queue);

    mctx->shpool->log_ctx = ngx_slab_alloc(mctx->shpool,
                                           NGX_HTTP_METRIC_SLAB_SIZE);
    if (mctx->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    tmp = shm_zone->shm.name;

    if (tmp.len > NGX_HTTP_METRIC_SLAB_SIZE - sizeof(" in metric zone \"\"")) {
        tmp.len = NGX_HTTP_METRIC_SLAB_SIZE - sizeof(" in metric zone \"\"");
    }

    ngx_sprintf(mctx->shpool->log_ctx, " in metric zone \"%V\"%Z", &tmp);

    mctx->shpool->log_nomem = 0;

    if (mctx->discard_key.len == 0) {
        return NGX_OK;
    }

    /* expire node */

    node = ngx_slab_alloc(mctx->shpool, NGX_HTTP_METRIC_SLAB_SIZE);
    if (node == NULL) {
        return NGX_ERROR;
    }

    node->lock = 0;
    node->key_len = 0;

    end = (u_char *) node + NGX_HTTP_METRIC_DATA_SIZE;

    last = (void **) end;
    *last = NULL;

    pos = ngx_align_ptr(node->key, NGX_HTTP_METRIC_PTR_SIZE);

    rc = ngx_http_metric_init_values(mctx, pos, end, last);

    if (rc == NGX_OK) {
        mctx->sh->expired = node;
    }

    return rc;
}


static ngx_inline ngx_int_t
ngx_http_metric_init_values(ngx_http_metric_ctx_t *mctx, u_char *pos,
    u_char *end, void **last)
{
    void                         **last_data;
    u_char                        *mem;
    ngx_int_t                      rc;
    ngx_uint_t                     i, is_first;
    ngx_http_metric_t            **metric_ptr;
    ngx_http_metric_state_ctx_t    sctx;

    /* *last_data is a pointer to the end of data in first data slab */

    last_data = (void **) pos;
    *last_data = end;

    is_first = 1;

    pos += NGX_HTTP_METRIC_PTR_SIZE;

    /* values starts after last_data */

    metric_ptr = mctx->metrics->elts;

    for (i = 0; i < mctx->metrics->nelts; i++) {

        ngx_memzero(&sctx, sizeof(ngx_http_metric_state_ctx_t));

        sctx.args = metric_ptr[i]->args;

        for ( ;; ) {

            if (pos != end) {
                rc = metric_ptr[i]->mode->init(&sctx, (void **) &pos, end);

                if (rc == NGX_OK) {
                    break;
                }
            }

            /* pos == end */

            if (is_first) {
                /* move *last_data to the end of data in current slab */
                last = last_data;
                is_first = 0;
            }

            mem = ngx_http_metric_alloc_locked(mctx);
            if (mem == NULL) {
                return NGX_ERROR;
            }

            *last = pos;
            last = (void **) pos;

            pos = mem;

            end = pos + NGX_HTTP_METRIC_DATA_SIZE;
            *(void **) end = NULL;

            *last = end;
        }
    }

    /* to ensure that *last for the last slab is NULL */

    if (is_first) {
        last = last_data;
    }

    *last = pos;
    *(void **) pos = NULL;

    return NGX_OK;
}


static char *
ngx_http_metric_zone(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    char                    *rv;
    size_t                   size;
    u_char                  *p;
    ngx_str_t                name, *value;
    ngx_uint_t               i, start;
    ngx_http_metric_t       *metric, **metric_ptr;
    ngx_http_metric_ctx_t   *mctx;
    ngx_http_metric_mode_t  *mode;

    value = cf->args->elts;

    name = value[0];

    if (cf->args->nelts < 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "missing value mode after \"%V\"", &name);
        return NGX_CONF_ERROR;
    }

    mctx = cf->ctx;
    metric_ptr = mctx->metrics->elts;

    for (i = 0; i < mctx->metrics->nelts; i++) {
        if (ngx_strcmp(metric_ptr[i]->name.data, name.data) == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicated metric name \"%V\"", &name);
            return NGX_CONF_ERROR;
        }
    }

    mode = ngx_http_metric_modes;
    start = 1;

    do {
        if (value[start].len > mode->name.len) {
            continue;
        }

        p = mode->name.data;

        if (ngx_memcmp(value[start].data, p, value[start].len) != 0) {
            continue;
        }

        if (value[start].len == mode->name.len) {
            start++;
            goto found;
        }

        /* value[start].len < mode->name.len */

        p += value[start].len;

        if (*p++ != ' ') {
            continue;
        }

        if (cf->args->nelts > start + 1
            && ngx_strcmp(value[start + 1].data, p) == 0)
        {
            start += 2;
            goto found;
        }

    } while (++mode != ngx_items_end(ngx_http_metric_modes));

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "unknown mode \"%V\"", &value[start]);
    return NGX_CONF_ERROR;

found:

    if (mode->conf == NULL && cf->args->nelts > start) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "unknown parameter \"%V\"", &value[start]);
        return NGX_CONF_ERROR;
    }

    metric_ptr = ngx_array_push(mctx->metrics);
    if (metric_ptr == NULL) {
        return NGX_CONF_ERROR;
    }

    metric = ngx_pcalloc(cf->pool, sizeof(ngx_http_metric_t));
    if (metric == NULL) {
        return NGX_CONF_ERROR;
    }

    *metric_ptr = metric;

    metric->name = name;
    metric->mode = mode;

    if (mode->conf != NULL) {
        rv = mode->conf(cf, start, mctx, &metric->args);

        if (rv != NGX_CONF_OK) {
            return rv;
        }
    }

    metric->offset = mctx->data_size;

    switch(mode->type) {

    case NGX_HTTP_METRIC_COUNT:
        metric->data_size = sizeof(uint64_t);
        metric->str_size = NGX_INT64_LEN;
        break;

    case NGX_HTTP_METRIC_FRAC:
        metric->data_size = sizeof(double);
        metric->str_size = NGX_DTOA_MAX_LEN;
        break;

    case NGX_HTTP_METRIC_AVG_MEAN:
        size = metric->args.avg.window ? sizeof(ngx_http_metric_avg_cache_t)
                                       : sizeof(double);
        /* size of data index + size of data */
        metric->data_size = sizeof(uint64_t) + size * metric->args.avg.count;
        metric->str_size = NGX_DTOA_MAX_LEN;
        break;

    case NGX_HTTP_METRIC_HIST:
        size = metric->args.hist->nelts;

        metric->data_size = sizeof(uint64_t) * size;
        metric->str_size = (NGX_INT64_LEN + 1) * size - 1;

        break;
    }

    mctx->data_size += metric->data_size;
    mctx->str_size += metric->str_size;

    return NGX_CONF_OK;
}


static char *
ngx_http_metric_zone_complex(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_metric_main_conf_t  *mmcf = conf;

    char                   *rv;
    ngx_str_t              *value;
    ngx_conf_t              save;
    ngx_uint_t              i;
    ngx_shm_zone_t         *shm_zone;
    ngx_http_metric_ctx_t  *mctx;
    ngx_shm_zone_params_t   zp;

    value = cf->args->elts;

    ngx_memzero(&zp, sizeof(ngx_shm_zone_params_t));

    zp.min_size = 8 * ngx_pagesize;

    if (ngx_conf_parse_zone_spec(cf, &zp, &value[1]) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (zp.name.len == 0) {
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &zp.name, zp.size,
                                     &ngx_http_metric_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%V \"%V\" is already exists",
                           &cmd->name, &shm_zone->shm.name);
        return NGX_CONF_ERROR;
    }

    mctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_metric_ctx_t));
    if (mctx == NULL) {
        return NGX_CONF_ERROR;
    }

    mctx->shm_zone = shm_zone;

    shm_zone->data = mctx;
    shm_zone->init = ngx_http_metric_init_zone;

    mctx->api = ngx_http_metric_api_complex_handler;

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "expire=", 7) == 0) {
            value[i].data += 7;
            value[i].len -= 7;

            if (ngx_strcmp(value[i].data, "on") == 0) {
                mctx->expire = 1;
                continue;
            }

            if (ngx_strcmp(value[i].data, "off") == 0) {
                /* mctx->expire = 0; */
                continue;
            }

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "unknown expire mode \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }

        if (ngx_strncmp(value[i].data, "discard_key=", 12) == 0) {
            value[i].data += 12;
            value[i].len -= 12;

            mctx->discard_key = value[i];

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    mctx->metrics = ngx_array_create(cf->pool, 4, sizeof(ngx_http_metric_t *));
    if (mctx->metrics == NULL) {
        return NGX_CONF_ERROR;
    }

    save = *cf;
    cf->ctx = mctx;
    cf->handler = ngx_http_metric_zone;
    cf->handler_conf = conf;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    if (rv == NGX_CONF_OK) {
        rv = ngx_http_metric_create_complex_vars(cf, mctx);

        if (rv == NGX_CONF_OK) {
            *mmcf->next = mctx;
            mmcf->next = &mctx->next;
        }
    }

    return rv;
}


static char *
ngx_http_metric_zone_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_metric_main_conf_t  *mmcf = conf;

    char                    *rv;
    size_t                   size;
    u_char                  *p;
    ngx_str_t               *value;
    ngx_uint_t               start;
    ngx_shm_zone_t          *shm_zone;
    ngx_http_metric_t       *metric, **metric_ptr;
    ngx_http_metric_ctx_t   *mctx;
    ngx_shm_zone_params_t    zp;
    ngx_http_metric_mode_t  *mode;

    value = cf->args->elts;

    ngx_memzero(&zp, sizeof(ngx_shm_zone_params_t));

    zp.min_size = 8 * ngx_pagesize;

    if (ngx_conf_parse_zone_spec(cf, &zp, &value[1]) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (zp.name.len == 0) {
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &zp.name, zp.size,
                                     &ngx_http_metric_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%V \"%V\" is already exists",
                           &cmd->name, &shm_zone->shm.name);
        return NGX_CONF_ERROR;
    }

    mctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_metric_ctx_t));
    if (mctx == NULL) {
        return NGX_CONF_ERROR;
    }

    mctx->shm_zone = shm_zone;

    shm_zone->data = mctx;
    shm_zone->init = ngx_http_metric_init_zone;

    mctx->api = ngx_http_metric_api_inline_handler;

    for (start = 2; start < cf->args->nelts; start++) {

        if (ngx_strncmp(value[start].data, "expire=", 7) == 0) {
            value[start].data += 7;
            value[start].len -= 7;

            if (ngx_strcmp(value[start].data, "on") == 0) {
                mctx->expire = 1;
                continue;
            }

            if (ngx_strcmp(value[start].data, "off") == 0) {
                /* mctx->expire = 0; */
                continue;
            }

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "unknown expire mode \"%V\"", &value[start]);
            return NGX_CONF_ERROR;
        }

        if (ngx_strncmp(value[start].data, "discard_key=", 12) == 0) {
            value[start].data += 12;
            value[start].len -= 12;

            mctx->discard_key = value[start];

            continue;
        }

        break;
    }

    mctx->metrics = ngx_array_create(cf->pool, 1, sizeof(ngx_http_metric_t *));
    if (mctx->metrics == NULL) {
        return NGX_CONF_ERROR;
    }

    if (start == cf->args->nelts) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" missing value mode", &cmd->name);
        return NGX_CONF_ERROR;
    }

    mode = ngx_http_metric_modes;

    do {
        if (value[start].len > mode->name.len) {
            continue;
        }

        p = mode->name.data;

        if (ngx_memcmp(value[start].data, p, value[start].len) != 0) {
            continue;
        }

        if (value[start].len == mode->name.len) {
            start++;
            goto found;
        }

        /* value[start].len < mode->name.len */

        p += value[start].len;

        if (*p++ != ' ') {
            continue;
        }

        if (cf->args->nelts > start + 1
            && ngx_strcmp(value[start + 1].data, p) == 0)
        {
            start += 2;
            goto found;
        }

    } while (++mode != ngx_items_end(ngx_http_metric_modes));

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "unknown mode \"%V\"", &value[start]);
    return NGX_CONF_ERROR;

found:

    if (mode->conf == NULL && cf->args->nelts > start) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "unknown parameter \"%V\"", &value[start]);
        return NGX_CONF_ERROR;
    }

    metric_ptr = ngx_array_push(mctx->metrics);
    if (metric_ptr == NULL) {
        return NGX_CONF_ERROR;
    }

    metric = ngx_pcalloc(cf->pool, sizeof(ngx_http_metric_t));
    if (metric == NULL) {
        return NGX_CONF_ERROR;
    }

    *metric_ptr = metric;

    metric->name = mode->name;
    metric->mode = mode;

    if (mode->conf != NULL) {
        rv = mode->conf(cf, start, mctx, &metric->args);

        if (rv != NGX_CONF_OK) {
            return rv;
        }
    }

    metric->offset = 0;

    switch(mode->type) {

    case NGX_HTTP_METRIC_COUNT:
        metric->data_size = sizeof(uint64_t);
        metric->str_size = NGX_INT64_LEN;
        break;

    case NGX_HTTP_METRIC_FRAC:
        metric->data_size = sizeof(double);
        metric->str_size = NGX_DTOA_MAX_LEN;
        break;

    case NGX_HTTP_METRIC_AVG_MEAN:
        size = metric->args.avg.window ? sizeof(ngx_http_metric_avg_cache_t)
                                       : sizeof(double);
        /* size of data index + size of data */
        metric->data_size = sizeof(uint64_t) + size * metric->args.avg.count;
        metric->str_size = NGX_DTOA_MAX_LEN;
        break;

    case NGX_HTTP_METRIC_HIST:
        size = metric->args.hist->nelts;

        metric->data_size = sizeof(uint64_t) * size;
        metric->str_size = (NGX_INT64_LEN + 1) * size - 1;

        break;
    }

    mctx->data_size = metric->data_size;
    mctx->str_size = metric->str_size;

    rv = ngx_http_metric_create_vars(cf, mctx);

    if (rv == NGX_CONF_OK) {
        *mmcf->next = mctx;
        mmcf->next = &mctx->next;
    }

    return rv;
}


static char *
ngx_http_metric_create_complex_vars(ngx_conf_t *cf,
    ngx_http_metric_ctx_t *mctx)
{
    char                    *rv;
    u_char                  *p;
    size_t                   size;
    ngx_str_t                s, shm_name, name;
    ngx_uint_t               flags, i;
    ngx_http_metric_t      **metric_ptr;
    ngx_http_variable_t     *var;
    ngx_http_metric_var_t   *v;

    rv = ngx_http_metric_create_vars(cf, mctx);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    shm_name = mctx->shm_zone->shm.name;

    flags = NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE;

    metric_ptr = mctx->metrics->elts;

    v = ngx_http_metric_complex_vars;

    do {
        for (i = 0; i < mctx->metrics->nelts; i++) {
            name = metric_ptr[i]->name;

            size = v->size - 1 + shm_name.len + name.len;

            p = ngx_pnalloc(cf->temp_pool, size);
            if (p == NULL) {
                return NGX_CONF_ERROR;
            }

            ngx_snprintf(p, size, v->fmt, &shm_name, &name);

            s.len = size;
            s.data = p;

            var = ngx_http_add_variable(cf, &s, flags);
            if (var == NULL) {
                return NGX_CONF_ERROR;
            }

            var->get_handler = v->get;
            var->set_handler = v->set;
            var->data = (uintptr_t) metric_ptr[i];
        }

    } while (++v != ngx_items_end(ngx_http_metric_complex_vars));

    return NGX_CONF_OK;
}


static char *
ngx_http_metric_create_vars(ngx_conf_t *cf, ngx_http_metric_ctx_t *mctx)
{
    u_char                 *p;
    size_t                  size;
    ngx_str_t               s, shm_name;
    ngx_uint_t              flags;
    ngx_http_variable_t    *var;
    ngx_http_metric_var_t  *v;

    shm_name = mctx->shm_zone->shm.name;

    flags = NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE;

    v = ngx_http_metric_vars;

    do {
        size = v->size - 1 + shm_name.len;

        p = ngx_pnalloc(cf->temp_pool, size);
        if (p == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_snprintf(p, size, v->fmt, &shm_name);

        s.len = size;
        s.data = p;

        var = ngx_http_add_variable(cf, &s, flags);
        if (var == NULL) {
            return NGX_CONF_ERROR;
        }

        var->get_handler = v->get;
        var->set_handler = v->set;
        var->data = (uintptr_t) mctx;

    } while (++v != ngx_items_end(ngx_http_metric_vars));

    return NGX_CONF_OK;
}


static char *
ngx_http_metric(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_metric_loc_conf_t  *mlcf = conf;

    ngx_str_t                          *value, key, val;
    ngx_array_t                       **stage_zones;
    ngx_shm_zone_t                     *shm_zone;
    ngx_http_metric_phase_t            *phase;
    ngx_http_metric_stage_t            *stage;
    ngx_http_compile_complex_value_t    ccv;

    value = cf->args->elts;

    shm_zone = ngx_shared_memory_add(cf, &value[1], 0,
                                     &ngx_http_metric_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_http_metric_parse_key_value(&key, &val, value[2]);

    if (key.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "empty metric \"%V\" key", &shm_zone->shm.name);
        return NGX_CONF_ERROR;
    }

    phase = ngx_http_metric_phases;

    if (cf->args->nelts == 4) {

        if (ngx_strncmp(value[3].data, "on=", 3) != 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[3]);
            return NGX_CONF_ERROR;
        }

        value[3].len -= 3;
        value[3].data += 3;

        while (ngx_strcmp(value[3].data, phase->name) != 0) {
            if (++phase == ngx_items_end(ngx_http_metric_phases)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "unknown stage \"%V\"", &value[3]);
                return NGX_CONF_ERROR;
            }
        }
    }

    stage_zones = (ngx_array_t **) ((char *) mlcf + phase->conf_off);

    if (*stage_zones == NULL) {
        *stage_zones = ngx_array_create(cf->pool, 1,
                                        sizeof(ngx_http_metric_stage_t));
        if (*stage_zones == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    stage = ngx_array_push(*stage_zones);
    if (stage == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &key;
    ccv.complex_value = &stage->key;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &val;
    ccv.complex_value = &stage->value;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    stage->shm_zone = shm_zone;

    return NGX_CONF_OK;
}


static void
ngx_http_metric_parse_key_value(ngx_str_t *key, ngx_str_t *value,
    ngx_str_t src)
{
    key->len = 0;
    key->data = src.data;

    while (key->len < src.len) {

        if (*src.data == '=') {
            src.len--;
            src.data++;

            break;
        }

        key->len++;
        src.data++;
    }

    value->len = src.len - key->len;
    value->data = src.data;
}


static void *
ngx_http_metric_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_metric_main_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_metric_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->mctx = NULL;
     */

    conf->next = &conf->mctx;

    return conf;
}


static void *
ngx_http_metric_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_metric_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_metric_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->request = NULL;
     *     conf->response = NULL;
     *     conf->end = NULL;
     */

    return conf;
}


static char *
ngx_http_metric_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_metric_loc_conf_t  *prev = parent;
    ngx_http_metric_loc_conf_t  *conf = child;

    if (conf->request == NULL
        && conf->response == NULL
        && conf->end == NULL)
    {
        conf->request = prev->request;
        conf->response = prev->response;
        conf->end = prev->end;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_metric_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt          *h;
    ngx_http_metric_phase_t      *phase;
    ngx_http_core_main_conf_t    *cmcf;
    ngx_http_metric_main_conf_t  *mmcf;

    mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_metric_module);
    if (mmcf->mctx == NULL) {
        return NGX_OK;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    phase = ngx_http_metric_phases;

    do {
        if (phase->id == NGX_HTTP_METRIC_RESPONSE_PHASE) {
            ngx_http_next_header_filter = ngx_http_top_header_filter;
            ngx_http_top_header_filter = phase->handler;
            continue;
        }

        h = ngx_array_push(&cmcf->phases[phase->id].handlers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        *h = phase->handler;

    } while (++phase != ngx_items_end(ngx_http_metric_phases));

    if (ngx_api_add(cf->cycle, "/status/http", &ngx_http_metric_api_zone_entry)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_metric_api_zone_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    ngx_api_iter_ctx_t            ictx;
    ngx_http_metric_main_conf_t  *mmcf;

    mmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_http_metric_module);

    ngx_memzero(&ictx, sizeof(ngx_api_iter_ctx_t));

    ictx.entry.handler = ngx_api_object_handler;
    ictx.entry.data.ents = ngx_http_metric_api_zone_entries;
    ictx.elts = mmcf->mctx;
    ictx.read_only = 1;

    return ngx_api_object_iterate(ngx_http_metric_api_zone_iter, &ictx, actx);
}


static ngx_int_t
ngx_http_metric_api_zone_iter(ngx_api_iter_ctx_t *ictx, ngx_api_ctx_t *actx)
{
    ngx_http_metric_ctx_t  *mctx;

    mctx = ictx->elts;

    if (mctx == NULL) {
        return NGX_DECLINED;
    }

    ictx->ctx = mctx;
    ictx->entry.name = mctx->shm_zone->shm.name;

    ictx->elts = mctx->next;

    return NGX_OK;
}


static ngx_int_t
ngx_http_metric_api_discarded_handler(ngx_api_entry_data_t data,
    ngx_api_ctx_t *actx, void *ctx)
{
    ngx_http_metric_ctx_t  *mctx = ctx;

    data.num = (int64_t) mctx->sh->discarded;

    return ngx_api_number_handler(data, actx, ctx);
}


static ngx_int_t
ngx_http_metric_api_handler(ngx_api_entry_data_t data, ngx_api_ctx_t *actx,
    void *ctx)
{
    ngx_http_metric_ctx_t  *mctx = ctx;

    u_char                  *end, *pos;
    uint32_t                 hash;
    ngx_str_t                name;
    ngx_int_t                rc;
    ngx_data_item_t         *obj;
    ngx_http_metric_node_t  *node;

    obj = ngx_data_new_object(actx->pool);
    if (obj == NULL) {
        return NGX_ERROR;
    }

    actx->out = obj;

    if (ngx_api_next_segment(&actx->path, &name) == NGX_DECLINED) {
        return ngx_http_metric_api_keys_iter(actx, mctx);
    }

    if (name.len == NGX_HTTP_METRIC_MAX_LEN + 3
        && ngx_memcmp(name.data + NGX_HTTP_METRIC_MAX_LEN, "...", 3) == 0)
    {
        name.len = NGX_HTTP_METRIC_MAX_LEN;
    }

    hash = ngx_crc32_short(name.data, name.len);

    ngx_rwlock_rlock(&mctx->sh->rbt_lock);

    node = ngx_http_metric_find_node_locked(mctx, hash, name, &end);

    if (node == NULL) {
        /* the expired node is not in the rbtree */

        if (mctx->sh->is_expired == 0
            || mctx->discard_key.len != name.len
            || ngx_memcmp(mctx->discard_key.data, name.data, name.len) != 0)
        {
            ngx_rwlock_unlock(&mctx->sh->rbt_lock);
            return NGX_API_NOT_FOUND;
        }

        node = mctx->sh->expired;
        end = ngx_align_ptr(node->key, NGX_HTTP_METRIC_PTR_SIZE);
    }

    ngx_rwlock_rlock(&node->lock);
    ngx_rwlock_unlock(&mctx->sh->rbt_lock);

    ngx_http_metric_slab_first_locked(&pos, &end);

    rc = mctx->api(actx, mctx, pos, end);

    ngx_rwlock_unlock(&node->lock);

    return rc;
}


static ngx_int_t
ngx_http_metric_api_keys_iter(ngx_api_ctx_t *actx, ngx_http_metric_ctx_t *mctx)
{
    size_t                   chunk, rest;
    u_char                  *end, *p, *pos;
    ngx_int_t                rc;
    ngx_data_item_t         *obj, *str;
    ngx_rbtree_node_t       *rbt, *sentinel;
    ngx_http_metric_node_t  *node;

    obj = actx->out;

    ngx_rwlock_rlock(&mctx->sh->rbt_lock);

    rbt = mctx->sh->rbtree.root;
    sentinel = mctx->sh->rbtree.sentinel;

    rbt = (rbt == sentinel) ? NULL : ngx_rbtree_min(rbt, sentinel);

    while (rbt != NULL) {

        actx->out = NULL;

        node = (ngx_http_metric_node_t *) &rbt->color;

        ngx_rwlock_rlock(&node->lock);

        p = ngx_http_metric_api_alloc_str(&str, actx->pool, node->key_len);
        if (p == NULL) {
            ngx_rwlock_unlock(&node->lock);
            ngx_rwlock_unlock(&mctx->sh->rbt_lock);
            return NGX_ERROR;
        }

        pos = node->key;
        end = ngx_align_ptr(pos + 1, NGX_HTTP_METRIC_SLAB_SIZE)
              - NGX_HTTP_METRIC_PTR_SIZE;

        rest = node->key_len;

        if ((size_t) (end - pos) >= rest) {
            chunk = rest;
            ngx_memcpy(p, pos, chunk);

        } else {
            /* copy key from slabs */

            for ( ;; ) {
                chunk = ngx_min((size_t) (end - pos), rest);

                ngx_memcpy(p, pos, chunk);

                rest -= chunk;

                if (rest == 0) {
                    break;
                }

                p += chunk;

                ngx_http_metric_slab_next_locked(&pos, &end);
            }
        }

        pos = ngx_align_ptr(pos + chunk, NGX_HTTP_METRIC_PTR_SIZE);

        if (end - pos < 2 * NGX_HTTP_METRIC_PTR_SIZE) {
            ngx_http_metric_slab_next_locked(&pos, &end);
        }

        end = pos;

        ngx_http_metric_slab_first_locked(&pos, &end);

        rc = mctx->api(actx, mctx, pos, end);

        ngx_rwlock_unlock(&node->lock);

        if (rc == NGX_OK) {
            rc = ngx_data_object_add(obj, str, actx->out);
        }

        if (rc != NGX_OK) {
            ngx_rwlock_unlock(&mctx->sh->rbt_lock);
            return NGX_ERROR;
        }

        rbt = ngx_rbtree_next(&mctx->sh->rbtree, rbt);
    }

    if (mctx->sh->is_expired) {

        actx->out = NULL;

        node = mctx->sh->expired;

        ngx_rwlock_rlock(&node->lock);

        end = ngx_align_ptr(node->key, NGX_HTTP_METRIC_PTR_SIZE);

        ngx_http_metric_slab_first_locked(&pos, &end);

        rc = mctx->api(actx, mctx, pos, end);

        ngx_rwlock_unlock(&node->lock);

        if (rc == NGX_OK) {
            rc = ngx_data_object_add_const_str(obj, &mctx->discard_key,
                                               actx->out, actx->pool);
        }

        if (rc != NGX_OK) {
            ngx_rwlock_unlock(&mctx->sh->rbt_lock);
            return NGX_ERROR;
        }
    }

    ngx_rwlock_unlock(&mctx->sh->rbt_lock);

    actx->out = obj;

    return NGX_OK;
}


static u_char *
ngx_http_metric_api_alloc_str(ngx_data_item_t **item, ngx_pool_t *pool,
    size_t len)
{
    u_char           *p;
    ngx_uint_t        is_long, is_trunc;
    ngx_data_item_t  *str;

    is_long = (len > NGX_DATA_MAX_STR);

    str = ngx_data_new_item(pool, is_long ? NGX_DATA_STRING_TYPE
                                          : NGX_DATA_STR_TYPE);
    if (str == NULL) {
        return NULL;
    }

    if (is_long) {
        is_trunc = (len == NGX_HTTP_METRIC_MAX_LEN);

        if (is_trunc) {
            len += 3;
        }

        p = ngx_pnalloc(pool, len);
        if (p == NULL) {
            return NULL;
        }

        str->data.string.length = len;
        str->data.string.start = p;

        if (is_trunc) {
            ngx_memcpy(p + NGX_HTTP_METRIC_MAX_LEN, "...", 3);
        }

    } else {
        str->data.str.length = len;
        p = str->data.str.start;
    }

    *item = str;

    return p;
}


static ngx_inline void
ngx_http_metric_slab_first_locked(u_char **pos, u_char **endptr)
{
    u_char  *end;

    end = *endptr;

    *pos = end + NGX_HTTP_METRIC_PTR_SIZE;
    *endptr = *(void **) end;
}


static ngx_inline void
ngx_http_metric_slab_next_locked(u_char **pos, u_char **endptr)
{
    u_char  *end;

    end = *endptr;
    end = *(void **) end;

    *pos = ngx_align_ptr(end - NGX_HTTP_METRIC_SLAB_SIZE,
                         NGX_HTTP_METRIC_SLAB_SIZE);
    *endptr = end;
}


static ngx_int_t
ngx_http_metric_api_inline_handler(ngx_api_ctx_t *actx,
    ngx_http_metric_ctx_t *mctx, u_char *pos, u_char *end)
{
    ngx_http_metric_t           **metric_ptr;
    ngx_api_entry_data_t          data;
    ngx_http_metric_iter_ctx_t    imctx;

    metric_ptr = mctx->metrics->elts;

    imctx.elts = metric_ptr;
    imctx.pos = pos;
    imctx.end = end;

#if (NGX_SUPPRESS_WARN)
    data.ents = NULL;
#endif

    return (*metric_ptr)->mode->api(data, actx, &imctx);
}


static ngx_int_t
ngx_http_metric_api_complex_handler(ngx_api_ctx_t *actx,
    ngx_http_metric_ctx_t *mctx, u_char *pos, u_char *end)
{
    ngx_http_metric_t           **metric_ptr;
    ngx_api_iter_ctx_t            ictx;
    ngx_http_metric_iter_ctx_t    imctx;

    metric_ptr = mctx->metrics->elts;

    imctx.elts = metric_ptr;
    imctx.pos = pos;
    imctx.end = end;

    ngx_memzero(&ictx, sizeof(ngx_api_iter_ctx_t));

    ictx.ctx = &imctx;
    ictx.elts = metric_ptr + mctx->metrics->nelts;
    ictx.read_only = 1;

    return ngx_api_object_iterate(ngx_http_metric_api_complex_iter, &ictx,
                                  actx);
}


static ngx_int_t
ngx_http_metric_api_complex_iter(ngx_api_iter_ctx_t *ictx, ngx_api_ctx_t *actx)
{
    size_t                       chunk, skip;
    ngx_http_metric_t           *metric, **metric_ptr;
    ngx_http_metric_iter_ctx_t  *imctx;

    imctx = ictx->ctx;

    metric_ptr = imctx->elts;

    if (ictx->entry.handler != NULL) {
        skip = (*metric_ptr)->data_size;
        metric_ptr++;

    } else {
        skip = 0;
    }

    if (metric_ptr == ictx->elts) {
        return NGX_DECLINED;
    }

    for ( ;; ) {
        chunk = ngx_min((size_t) (imctx->end - imctx->pos), skip);

        skip -= chunk;

        if (skip == 0) {
            imctx->pos += chunk;
            break;
        }

        ngx_http_metric_slab_next_locked(&imctx->pos, &imctx->end);
    }

    if (imctx->pos == imctx->end) {
        ngx_http_metric_slab_next_locked(&imctx->pos, &imctx->end);
    }

    imctx->elts = metric_ptr;

    metric = *metric_ptr;

    ictx->entry.name = metric->name;
    ictx->entry.handler = metric->mode->api;

    return NGX_OK;
}


static ngx_int_t
ngx_http_metric_count_init(ngx_http_metric_state_ctx_t *sctx, void **pos,
    void *end)
{
    uint64_t  *data = *pos;

    *data++ = 0;
    *pos = data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_metric_count_expire(ngx_http_metric_state_ctx_t *sctx, void **pos_e,
    void *end_e, void **pos_q, void *end_q)
{
    uint64_t  *data_e, *data_q;

    data_e = *pos_e;
    data_q = *pos_q;

    *data_e += *data_q;

    *pos_e = ++data_e;
    *pos_q = ++data_q;

    return NGX_OK;
}


static ngx_int_t
ngx_http_metric_count_set(ngx_http_metric_state_ctx_t *sctx, void **pos,
    void *end, double value)
{
    uint64_t  *data = *pos;

    (*data)++;

    *pos = ++data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_metric_count_get(ngx_http_metric_state_ctx_t *sctx, void **pos,
    void *end, ngx_str_t *buf)
{
    uint64_t  *data = *pos;

    u_char  *p;

    p = buf->data;

    buf->data = ngx_sprintf(p, "%ui", *data);
    buf->len += buf->data - p;

    *pos = ++data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_metric_num_api(ngx_api_entry_data_t data, ngx_api_ctx_t *actx,
    void *ctx)
{
    ngx_http_metric_iter_ctx_t  *imctx = ctx;

    uint64_t  *value;

    value = (uint64_t *) imctx->pos;

    data.num = (int64_t) *value;

    return ngx_api_number_handler(data, actx, ctx);
}


static ngx_int_t
ngx_http_metric_min_init(ngx_http_metric_state_ctx_t *sctx, void **pos,
    void *end)
{
    double  *data = *pos;

    *data++ = DBL_MAX;
    *pos = data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_metric_min_expire(ngx_http_metric_state_ctx_t *sctx, void **pos_e,
    void *end_e, void **pos_q, void *end_q)
{
    double  *data_e, *data_q;

    data_e = *pos_e;
    data_q = *pos_q;

    if (*data_e > *data_q) {
        *data_e = *data_q;
    }

    *pos_e = ++data_e;
    *pos_q = ++data_q;

    return NGX_OK;
}


static ngx_int_t
ngx_http_metric_min_set(ngx_http_metric_state_ctx_t *sctx, void **pos,
    void *end, double value)
{
    double  *data = *pos;

    if (*data > value) {
        *data = value;
    }

    *pos = ++data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_metric_frac_get(ngx_http_metric_state_ctx_t *sctx, void **pos,
    void *end, ngx_str_t *buf)
{
    double  *data = *pos;

    size_t   size;
    u_char  *p;

    p = buf->data;

    size = ngx_dtoa(p, *data);

    buf->data += size;
    buf->len += size;

    *pos = ++data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_metric_frac_api(ngx_api_entry_data_t data, ngx_api_ctx_t *actx,
    void *ctx)
{
    ngx_http_metric_iter_ctx_t  *imctx = ctx;

    double  *value;

    value = (double *) imctx->pos;

    data.frac = *value;

    return ngx_api_fractional_handler(data, actx, ctx);
}


static ngx_int_t
ngx_http_metric_max_init(ngx_http_metric_state_ctx_t *sctx, void **pos,
    void *end)
{
    double  *data = *pos;

    *data++ = -DBL_MAX;
    *pos = data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_metric_max_expire(ngx_http_metric_state_ctx_t *sctx, void **pos_e,
    void *end_e, void **pos_q, void *end_q)
{
    double  *data_e, *data_q;

    data_e = *pos_e;
    data_q = *pos_q;

    if (*data_e < *data_q) {
        *data_e = *data_q;
    }

    *pos_e = ++data_e;
    *pos_q = ++data_q;

    return NGX_OK;
}


static ngx_int_t
ngx_http_metric_max_set(ngx_http_metric_state_ctx_t *sctx, void **pos,
    void *end, double value)
{
    double  *data = *pos;

    if (*data < value) {
        *data = value;
    }

    *pos = ++data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_metric_last_init(ngx_http_metric_state_ctx_t *sctx, void **pos,
    void *end)
{
    double  *data = *pos;

    *data++ = 0;
    *pos = data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_metric_last_expire(ngx_http_metric_state_ctx_t *sctx, void **pos_e,
    void *end_e, void **pos_q, void *end_q)
{
    double  *data_e, *data_q;

    data_e = *pos_e;
    data_q = *pos_q;

    *data_e = *data_q;

    *pos_e = ++data_e;
    *pos_q = ++data_q;

    return NGX_OK;
}


static ngx_int_t
ngx_http_metric_last_set(ngx_http_metric_state_ctx_t *sctx, void **pos,
    void *end, double value)
{
    double  *data = *pos;

    *data = value;

    *pos = ++data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_metric_gauge_init(ngx_http_metric_state_ctx_t *sctx, void **pos,
    void *end)
{
    double  *data = *pos;

    *data++ = 0;
    *pos = data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_metric_gauge_expire(ngx_http_metric_state_ctx_t *sctx, void **pos_e,
    void *end_e, void **pos_q, void *end_q)
{
    double  *data_e, *data_q;

    data_e = *pos_e;
    data_q = *pos_q;

    *data_e += *data_q;

    *pos_e = ++data_e;
    *pos_q = ++data_q;

    return NGX_OK;
}


static ngx_int_t
ngx_http_metric_gauge_set(ngx_http_metric_state_ctx_t *sctx, void **pos,
    void *end, double value)
{
    double  *data = *pos;

    *data += value;

    *pos = ++data;

    return NGX_OK;
}


static char *
ngx_http_metric_avg_mean_conf(ngx_conf_t *cf, ngx_uint_t start,
    ngx_http_metric_ctx_t *mctx, ngx_http_metric_args_t *args)
{
    ngx_int_t    count, window;
    ngx_str_t   *value;
    ngx_uint_t   i;

    count = 10;
    window = 0;

    value = cf->args->elts;

    for (i = start; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "window=", 7) == 0) {
            value[i].len -= 7;
            value[i].data += 7;

            if (ngx_strcmp(value[i].data, "off") == 0) {
                /* window = 0 */

                continue;
            }

            window = ngx_parse_time(&value[i], 0);
            if (window == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "bad window value \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            if (window == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "the average window cannot be zero");
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "count=", 6) == 0) {
            value[i].len -= 6;
            value[i].data += 6;

            count = ngx_atoi(value[i].data, value[i].len);
            if (count == NGX_ERROR) {
                return NGX_CONF_ERROR;
            }

            if (count == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "average count must be greater than 0");
                return NGX_CONF_ERROR;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"",
                           &value[i]);
        return NGX_CONF_ERROR;
    }

    args->avg.count = (ngx_uint_t) count;
    args->avg.window = (ngx_msec_t) window;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_metric_avg_mean_init(ngx_http_metric_state_ctx_t *sctx, void **pos,
    void *end)
{
    double                       *data;
    size_t                        rest;
    uint64_t                     *current;
    ngx_uint_t                    count, i, n;
    ngx_http_metric_avg_cache_t  *cache;

    if (sctx->state == 0) {
        /* index of the processed value in the cache */

        current = *pos;
        *current++ = 0;

        sctx->state++;

        *pos = current;

        if (*pos == end) {
            return NGX_AGAIN;
        }
    }

    /* cache */

    n = sctx->args.avg.count - sctx->state + 1;

    if (sctx->args.avg.window == 0) {
        /* unused timestamps are not stored in the shm */

        rest = (double *) end - (double *) *pos;

        count = ngx_min(n, rest);
        data = *pos;

        for (i = 0; i < count; i++) {
            data[i] = 0;
        }

        *pos = &data[i];

    } else {
        rest = (ngx_http_metric_avg_cache_t *) end
               - (ngx_http_metric_avg_cache_t *) *pos;

        count = ngx_min(n, rest);
        cache = *pos;

        for (i = 0; i < count; i++) {
            cache[i].value = 0;
            cache[i].timestamp = 0;
        }

        *pos = &cache[i];
    }

    if (count != n) {
        sctx->state += count;
        return NGX_AGAIN;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_metric_avg_mean_expire(ngx_http_metric_state_ctx_t *sctx,
    void **pos_e, void *end_e, void **pos_q, void *end_q)
{
    double                       *data_e, *data_q;
    size_t                        rest, rest_e, rest_q;
    uint64_t                     *current_e, *current_q;
    ngx_uint_t                    count, i, n;
    ngx_http_metric_avg_cache_t  *cache_e, *cache_q;

    if (sctx->state == 0) {
        current_e = *pos_e;
        current_q = *pos_q;

        *current_e = *current_q;

        *pos_e = ++current_e;
        *pos_q = ++current_q;

        sctx->state++;
    }

    n = sctx->args.avg.count - sctx->state + 1;

    if (sctx->args.avg.window == 0) {
        rest_e = (double *) end_e - (double *) *pos_e;
        rest_q = (double *) end_q - (double *) *pos_q;

        rest = ngx_min(rest_e, rest_q);
        count = ngx_min(n, rest);

        data_e = *pos_e;
        data_q = *pos_q;

        for (i = 0; i < count; i++) {
            data_e[i] = (data_e[i] + data_q[i]) / 2;
        }

        *pos_e = &data_e[i];
        *pos_q = &data_q[i];

    } else {
        rest_e = (ngx_http_metric_avg_cache_t *) end_e
                 - (ngx_http_metric_avg_cache_t *) *pos_e;

        rest_q = (ngx_http_metric_avg_cache_t *) end_q
                 - (ngx_http_metric_avg_cache_t *) *pos_q;

        rest = ngx_min(rest_e, rest_q);
        count = ngx_min(n, rest);

        cache_e = *pos_e;
        cache_q = *pos_q;

        for (i = 0; i < count; i++) {
            cache_e[i].value = (cache_e[i].value + cache_q[i].value) / 2;
            cache_e[i].timestamp = cache_q[i].timestamp;
        }

        *pos_e = &cache_e[i];
        *pos_q = &cache_q[i];
    }

    if (count != n) {
        sctx->state += count;
        return NGX_AGAIN;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_metric_avg_mean_set(ngx_http_metric_state_ctx_t *sctx, void **pos,
    void *end, double value)
{
    double                       *data;
    size_t                        rest;
    uint64_t                     *current;
    ngx_uint_t                    count, i, n;
    ngx_http_metric_avg_cache_t  *cache;

    if (sctx->state == 0) {
        current = *pos;

        sctx->state++;
        sctx->modes.avg.current = *current % sctx->args.avg.count;

        (*current)++;

        *pos = ++current;

        if (*pos == end) {
            return NGX_AGAIN;
        }
    }

    n = sctx->args.avg.count - sctx->state + 1;

    if (sctx->args.avg.window == 0) {
        rest = (double *) end - (double *) *pos;

        count = ngx_min(n, rest);
        data = *pos;

        for (i = 0; i < count; i++) {
            if (i + sctx->state - 1 == sctx->modes.avg.current) {
                data[i] = value;
            }
        }

        *pos = &data[i];

    } else {
        rest = (ngx_http_metric_avg_cache_t *) end
               - (ngx_http_metric_avg_cache_t *) *pos;

        count = ngx_min(n, rest);
        cache = *pos;

        for (i = 0; i < count; i++) {
            if (i + sctx->state - 1 == sctx->modes.avg.current) {
                cache[i].value = value;
                cache[i].timestamp = (uint64_t) ngx_current_msec;
            }
        }

        *pos = &cache[i];
    }

    if (count != n) {
        sctx->state += count;
        return NGX_AGAIN;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_metric_avg_mean_calculate(ngx_http_metric_state_ctx_t *sctx,
    void **pos, void *end, double *result)
{
    double                       *data;
    size_t                        rest;
    uint64_t                     *current;
    ngx_msec_t                    window;
    ngx_uint_t                    count, i, n;
    ngx_http_metric_avg_cache_t  *cache;

    if (sctx->state == 0) {
        current = *pos;

        sctx->state++;
        sctx->modes.avg.current = ngx_min(*current, sctx->args.avg.count);

        *pos = ++current;

        if (*pos == end) {
            return NGX_AGAIN;
        }
    }

    n = sctx->args.avg.count - sctx->state + 1;

    if (sctx->args.avg.window == 0) {
        rest = (double *) end - (double *) *pos;

        count = ngx_min(n, rest);
        data = *pos;

        for (i = 0; i < count; i++) {
            if (i + sctx->state <= sctx->modes.avg.current) {
                sctx->modes.avg.sum += data[i];
            }
        }

        sctx->modes.avg.count = sctx->modes.avg.current;

        *pos = &data[i];

    } else {
        rest = (ngx_http_metric_avg_cache_t *) end
               - (ngx_http_metric_avg_cache_t *) *pos;

        count = ngx_min(n, rest);
        cache = *pos;

        window = ngx_current_msec - sctx->args.avg.window;

        for (i = 0; i < count; i++) {
            if ((uint64_t) window < cache[i].timestamp) {
                sctx->modes.avg.sum += cache[i].value;
                sctx->modes.avg.count++;
            }
        }

        *pos = &cache[i];
    }

    if (count != n) {
        sctx->state += count;
        return NGX_AGAIN;
    }

    *result = sctx->modes.avg.count
              ? sctx->modes.avg.sum / sctx->modes.avg.count : 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_metric_avg_mean_get(ngx_http_metric_state_ctx_t *sctx, void **pos,
    void *end, ngx_str_t *buf)
{
    double     result;
    size_t     size;
    ngx_int_t  rc;

    rc = ngx_http_metric_avg_mean_calculate(sctx, pos, end, &result);
    if (rc != NGX_OK) {
        return NGX_AGAIN;
    }

    size = ngx_dtoa(buf->data, result);

    buf->len += size;
    buf->data += size;

    return NGX_OK;
}


static ngx_int_t
ngx_http_metric_avg_mean_api(ngx_api_entry_data_t data, ngx_api_ctx_t *actx,
    void *ctx)
{
    ngx_http_metric_iter_ctx_t  *imctx = ctx;

    u_char                        *end, *pos;
    ngx_int_t                      rc;
    ngx_http_metric_t            **metric_ptr;
    ngx_http_metric_state_ctx_t    sctx;

    metric_ptr = imctx->elts;

    ngx_memzero(&sctx, sizeof(ngx_http_metric_state_ctx_t));
    sctx.args = (*metric_ptr)->args;

    pos = imctx->pos;
    end = imctx->end;

    do {
        if (pos == end) {
            ngx_http_metric_slab_next_locked(&pos, &end);
        }

        rc = ngx_http_metric_avg_mean_calculate(&sctx, (void **) &pos, end,
                                                &data.frac);
    } while (rc == NGX_AGAIN);

    return ngx_api_fractional_handler(data, actx, ctx);
}


static char *
ngx_http_metric_avg_exp_conf(ngx_conf_t *cf, ngx_uint_t start,
    ngx_http_metric_ctx_t *mctx, ngx_http_metric_args_t *args)
{
    ngx_int_t    factor;
    ngx_str_t   *value;
    ngx_uint_t   i;

    factor = 90;

    value = cf->args->elts;

    for (i = start; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "factor=", 7) == 0) {
            value[i].len -= 7;
            value[i].data += 7;

            factor = ngx_atoi(value[i].data, value[i].len);

            if (factor == NGX_ERROR || factor > 99) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "bad factor value \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"",
                           &value[i]);
        return NGX_CONF_ERROR;
    }

    args->avg.factor = (double) factor / 100;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_metric_avg_exp_init(ngx_http_metric_state_ctx_t *sctx, void **pos,
    void *end)
{
    double  *data = *pos;

    *data++ = DBL_MAX;
    *pos = data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_metric_avg_exp_expire(ngx_http_metric_state_ctx_t *sctx, void **pos_e,
    void *end_e, void **pos_q, void *end_q)
{
    double  *data_e, *data_q, prev_avg;

    data_e = *pos_e;
    data_q = *pos_q;

    prev_avg = (*data_e == DBL_MAX) ? *data_q : *data_e;
    *data_e = prev_avg + sctx->args.avg.factor * (*data_q - prev_avg);

    *pos_e = ++data_e;
    *pos_q = ++data_q;

    return NGX_OK;
}


static ngx_int_t
ngx_http_metric_avg_exp_set(ngx_http_metric_state_ctx_t *sctx, void **pos,
    void *end, double value)
{
    double  *data, prev_avg;

    data = *pos;

    prev_avg = (*data == DBL_MAX) ? value : *data;
    *data = prev_avg + sctx->args.avg.factor * (value - prev_avg);

    *pos = ++data;

    return NGX_OK;
}


static char *
ngx_http_metric_hist_conf(ngx_conf_t *cf, ngx_uint_t start,
    ngx_http_metric_ctx_t *mctx, ngx_http_metric_args_t *args)
{
    u_char                       *endptr;
    ngx_str_t                    *value;
    ngx_uint_t                    i, j;
    ngx_http_metric_hist_args_t  *arg, *tmp;

    args->hist = ngx_array_create(cf->pool, 5,
                                  sizeof(ngx_http_metric_hist_args_t));
    if (args->hist == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    for (i = start; i < cf->args->nelts; i++) {

        arg = ngx_array_push(args->hist);
        if (arg == NULL) {
            return NGX_CONF_ERROR;
        }

        arg->name = value[i];

        ngx_errno = 0;

        arg->value = ngx_strtod(arg->name.data, &endptr);

        if (ngx_errno == NGX_ERANGE
            || endptr == arg->name.data || *endptr != '\0')
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "bad bucket value \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }

        tmp = args->hist->elts;

        for (j = 0; j < args->hist->nelts - 1; j++) {

            if (arg->value == tmp[j].value) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "duplicated bucket \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }
        }
    }

    if (args->hist->nelts == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "empty histogram");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_metric_hist_init(ngx_http_metric_state_ctx_t *sctx, void **pos,
    void *end)
{
    size_t       rest;
    uint64_t    *data;
    ngx_uint_t   count, i, n;

    n = sctx->args.hist->nelts - sctx->state;
    rest = (uint64_t *) end - (uint64_t *) *pos;

    count = ngx_min(n, rest);
    data = *pos;

    for (i = 0; i < count; i++) {
        data[i] = 0;
    }

    *pos = &data[i];

    if (count != n) {
        sctx->state += count;
        return NGX_AGAIN;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_metric_hist_expire(ngx_http_metric_state_ctx_t *sctx, void **pos_e,
    void *end_e, void **pos_q, void *end_q)
{
    size_t       rest, rest_e, rest_q;
    uint64_t    *data_e, *data_q;
    ngx_uint_t   count, i, n;

    rest_e = (uint64_t *) end_e - (uint64_t *) *pos_e;
    rest_q = (uint64_t *) end_q - (uint64_t *) *pos_q;

    n = sctx->args.hist->nelts - sctx->state;
    rest = ngx_min(rest_e, rest_q);

    count = ngx_min(n, rest);

    data_e = *pos_e;
    data_q = *pos_q;

    for (i = 0; i < count; i++) {
        data_e[i] += data_q[i];
    }

    *pos_e = &data_e[i];
    *pos_q = &data_q[i];

    if (count != n) {
        sctx->state += count;
        return NGX_AGAIN;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_metric_hist_set(ngx_http_metric_state_ctx_t *sctx, void **pos,
    void *end, double value)
{
    size_t                        rest;
    uint64_t                     *data;
    ngx_uint_t                    count, i, n;
    ngx_http_metric_hist_args_t  *args;

    n = sctx->args.hist->nelts - sctx->state;
    rest = (uint64_t *) end - (uint64_t *) *pos;

    count = ngx_min(n, rest);
    data = *pos;

    args = sctx->args.hist->elts;

    for (i = 0; i < count; i++) {
        if (args[i + sctx->state].value >= value) {
            data[i]++;
        }
    }

    *pos = &data[i];

    if (count != n) {
        sctx->state += count;
        return NGX_AGAIN;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_metric_hist_get(ngx_http_metric_state_ctx_t *sctx, void **pos,
    void *end, ngx_str_t *buf)
{
    size_t       size, rest;
    uint64_t    *data;
    ngx_uint_t   count, i, n;

    n = sctx->args.hist->nelts - sctx->state;
    rest = (uint64_t *) end - (uint64_t *) *pos;

    count = ngx_min(n, rest);
    data = *pos;

    i = 0;

    for ( ;; ) {
        size = ngx_sprintf(buf->data, "%ui", data[i]) - buf->data;

        buf->len += size;
        buf->data += size;

        i++;

        if (i == count) {
            break;
        }

        buf->len++;
        *buf->data++ = ' ';
    }

    *pos = &data[i];

    if (count != n) {
        buf->len++;
        *buf->data++ = ' ';

        sctx->state += count;

        return NGX_AGAIN;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_metric_hist_api(ngx_api_entry_data_t data, ngx_api_ctx_t *actx,
    void *ctx)
{
    ngx_http_metric_iter_ctx_t  *imctx = ctx;

    ngx_array_t                  *buckets;
    ngx_http_metric_t           **metric_ptr;
    ngx_api_iter_ctx_t            ictx;
    ngx_http_metric_iter_ctx_t    hist_imctx;

    metric_ptr = imctx->elts;
    buckets = (*metric_ptr)->args.hist;

    hist_imctx.elts = buckets->elts;
    hist_imctx.pos = imctx->pos;
    hist_imctx.end = imctx->end;

    ngx_memzero(&ictx, sizeof(ngx_api_iter_ctx_t));

    ictx.entry.handler = ngx_api_number_handler;
    ictx.ctx = &hist_imctx;
    ictx.elts = (ngx_http_metric_hist_args_t *) buckets->elts + buckets->nelts;
    ictx.read_only = 1;

    return ngx_api_object_iterate(ngx_http_metric_api_hist_iter, &ictx, actx);
}


static ngx_int_t
ngx_http_metric_api_hist_iter(ngx_api_iter_ctx_t *ictx, ngx_api_ctx_t *actx)
{
    uint64_t                     *data;
    ngx_http_metric_iter_ctx_t   *imctx;
    ngx_http_metric_hist_args_t  *bucket;

    imctx = ictx->ctx;
    bucket = imctx->elts;

    if (bucket == ictx->elts) {
        return NGX_DECLINED;
    }

    ictx->entry.name = bucket->name;

    if (imctx->pos == imctx->end) {
        ngx_http_metric_slab_next_locked(&imctx->pos, &imctx->end);
    }

    data = (uint64_t *) imctx->pos;

    ictx->entry.data.num = *data;

    imctx->elts = bucket + 1;
    imctx->pos = (void *) ++data;

    return NGX_OK;
}
