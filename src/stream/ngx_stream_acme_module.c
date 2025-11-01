
/*
 * Copyright (C) 2025 Web Server LLC
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

/*
 * ngx_stream_acme_module requires some declarations from ngx_http_acme_module.
 */
#include <ngx_acme.h>

typedef struct {
    ngx_array_t                 clients;
} ngx_stream_acme_main_conf_t;


typedef struct {
    ngx_array_t                 clients;
} ngx_stream_acme_srv_conf_t;


static ngx_int_t ngx_stream_acme_postconfig(ngx_conf_t *cf);
static void *ngx_stream_acme_create_main_conf(ngx_conf_t *cf);
static void *ngx_stream_acme_create_srv_conf(ngx_conf_t *cf);
static ngx_int_t ngx_stream_acme_add_client_var(ngx_conf_t *cf,
    ngx_acme_client_ref_t *cli, ngx_stream_variable_t *var);
static ngx_int_t ngx_stream_acme_add_vars(ngx_conf_t *cf);
static ngx_int_t ngx_stream_acme_cert_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_stream_acme_cert_key_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data);
static char *ngx_stream_acme(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_stream_acme_commands[] = {

    { ngx_string("acme"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_acme,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_acme_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_stream_acme_postconfig,            /* postconfiguration */

    ngx_stream_acme_create_main_conf,      /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_stream_acme_create_srv_conf,       /* create server configuration */
    NULL,                                  /* merge server configuration */
};


ngx_module_t  ngx_stream_acme_module = {
    NGX_MODULE_V1,
    &ngx_stream_acme_module_ctx,           /* module context */
    ngx_stream_acme_commands,              /* module directives */
    NGX_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_stream_variable_t  ngx_stream_acme_vars[] = {

    { ngx_string("acme_cert_"), NULL, ngx_stream_acme_cert_variable,
      0, 0, 0 },

    { ngx_string("acme_cert_key_"), NULL, ngx_stream_acme_cert_key_variable,
      0, 0, 0 },

    ngx_stream_null_variable
};


static ngx_int_t
ngx_stream_acme_postconfig(ngx_conf_t *cf)
{
    ngx_uint_t                    i, j;
    ngx_acme_client_ref_t        *cli, **cli_p;
    ngx_stream_acme_srv_conf_t   *ascf;
    ngx_stream_core_main_conf_t  *cmcf;
    ngx_stream_core_srv_conf_t   **cscfp, *cscf;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
    cscfp = cmcf->servers.elts;

    for (i = 0; i < cmcf->servers.nelts; i++) {

        cscf = cscfp[i];
        ascf = cscf->ctx->srv_conf[ngx_stream_acme_module.ctx_index];

        cli_p = ascf->clients.elts;

        for (j = 0; j < ascf->clients.nelts; j++) {

            cli = cli_p[j];

            if (cli->ref == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                "ACME client \"%V\" is not defined but "
                                "referenced in %V:%ui", &cli->name,
                                cscf->file_name, cscf->line);

                return NGX_ERROR;
            }

            if (ngx_acme_add_server_names(cf, cli->ref, &cscf->server_names,
                                          cscf->file_name, cscf->line)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
    }

    return ngx_stream_acme_add_vars(cf);
}


static ngx_int_t
ngx_stream_acme_add_vars(ngx_conf_t *cf)
{
    ngx_uint_t                    i;
    ngx_acme_client_ref_t        *cli;
    ngx_stream_variable_t        *v;
    ngx_stream_acme_main_conf_t  *amcf;

    amcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_acme_module);

    for (i = 0; i < amcf->clients.nelts; i++) {

        cli = &((ngx_acme_client_ref_t *) amcf->clients.elts)[i];

        for (v = ngx_stream_acme_vars; v->name.len; v++) {
            if (ngx_stream_acme_add_client_var(cf, cli, v) != NGX_OK) {
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_acme_add_client_var(ngx_conf_t *cf, ngx_acme_client_ref_t *cli,
    ngx_stream_variable_t *var)
{
    ngx_str_t               name, *s;
    ngx_stream_variable_t  *v;

    s = &cli->name;
    name.len = var->name.len + s->len;

    name.data = ngx_pnalloc(cf->pool, name.len);
    if (name.data == NULL) {
        return NGX_ERROR;
    }

    ngx_snprintf(name.data, name.len, "%V%V", &var->name, s);

    v = ngx_stream_add_variable(cf, &name, var->flags);

    if (v == NULL) {
        return NGX_ERROR;
    }

    v->get_handler = var->get_handler;
    v->data = (uintptr_t) cli->ref;

    return NGX_OK;

}


static void *
ngx_stream_acme_create_main_conf(ngx_conf_t *cf)
{
    ngx_stream_acme_main_conf_t  *amcf;

    amcf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_acme_main_conf_t));
    if (amcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&amcf->clients, cf->pool, 4,
                       sizeof(ngx_acme_client_ref_t))
        != NGX_OK)
    {
        return NULL;
    }

    return amcf;
}


static void *
ngx_stream_acme_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_acme_srv_conf_t  *ascf;

    ascf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_acme_srv_conf_t));
    if (ascf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&ascf->clients, cf->pool, 4,
                       sizeof(ngx_acme_client_ref_t *))
        != NGX_OK)
    {
        return NULL;
    }

    return ascf;
}


static char *
ngx_stream_acme(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_acme_srv_conf_t  *ascf = conf;

    ngx_str_t                    *value;
    ngx_uint_t                    i;
    ngx_acme_client_ref_t        *cli, **cli_p;
    ngx_stream_acme_main_conf_t  *amcf;

    amcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_acme_module);

    value = cf->args->elts;

    for (i = 0; i < amcf->clients.nelts; i++) {

        cli = &((ngx_acme_client_ref_t *) amcf->clients.elts)[i];

        if (cli->name.len == value[1].len
            && ngx_strncasecmp(value[1].data, cli->name.data, cli->name.len)
               == 0)
        {
            goto found;
        }
    }

    cli = ngx_array_push(&amcf->clients);
    if (cli == NULL) {
        return NGX_CONF_ERROR;
    }

    cli->name = value[1];

found:

    cli_p = ascf->clients.elts;

    for (i = 0; i < ascf->clients.nelts; i++) {
        if (cli == cli_p[i]) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate \"acme %V\" directive", &cli->name);

            return NGX_CONF_ERROR;
        }
    }

    cli_p = ngx_array_push(&ascf->clients);
    if (cli_p == NULL) {
        return NGX_CONF_ERROR;
    }

    *cli_p = cli;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_stream_acme_cert_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{

    return ngx_acme_handle_cert_variable(s->connection->pool, v,
                                         (ngx_acme_client_t *) data,
                                         s->connection->ssl);
}


static ngx_int_t
ngx_stream_acme_cert_key_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{

    return ngx_acme_handle_cert_key_variable(s->connection->pool, v,
                                             (ngx_acme_client_t *) data,
                                             s->connection->ssl);
}


ngx_acme_client_ref_t *
ngx_stream_acme_find_client(ngx_conf_t *cf, ngx_str_t *name)
{
    ngx_uint_t                    i;
    ngx_acme_client_ref_t        *cli;
    ngx_stream_acme_main_conf_t  *amcf;

    amcf = ngx_stream_cycle_get_module_main_conf(cf->cycle,
                                                 ngx_stream_acme_module);

    if (amcf == NULL) {
        return NULL;
    }

    for (i = 0; i < amcf->clients.nelts; i++) {

        cli = &((ngx_acme_client_ref_t *) amcf->clients.elts)[i];

        if (cli->name.len == name->len
            && ngx_strncasecmp(cli->name.data, name->data, name->len) == 0)
        {
            return cli;
        }
    }

    return NULL;
}

