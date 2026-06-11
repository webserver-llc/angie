
/*
 * Copyright (C) 2026 Web Server LLC
 */


#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_acme.h>


static void *ngx_acme_create_conf(ngx_cycle_t *cycle);


static ngx_core_module_t  ngx_acme_module_ctx = {
    ngx_string("acme"),
    ngx_acme_create_conf,
    NULL
};


ngx_module_t  ngx_acme_module = {
    NGX_MODULE_V1,
    &ngx_acme_module_ctx,                  /* module context */
    NULL,                                  /* module directives */
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


ngx_acme_client_t *
ngx_acme_client_add(ngx_conf_t *cf, ngx_str_t *name)
{
    ngx_uint_t          i;
    ngx_array_t        *clients;
    ngx_acme_client_t  *cli, **cli_p;

    if (name->len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid ACME client name");
        return NULL;
    }

    clients = ngx_acme_clients(cf->cycle);

    for (i = 0; i < clients->nelts; i++) {
        cli = ((ngx_acme_client_t **) clients->elts)[i];

        if (cli->name.len != name->len
            || ngx_strncasecmp(cli->name.data, name->data, name->len) != 0)
        {
            continue;
        }

        return cli;
    }

    cli = ngx_pcalloc(cf->pool, sizeof(ngx_acme_client_t));
    if (cli == NULL) {
        return NULL;
    }

    cli->log = cf->log;
    cli->name = *name;
    cli->enabled = 1;
    cli->cf_line = cf->conf_file->line;
    cli->cf_filename = cf->conf_file->file.name;

    cli->domains = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
    if (cli->domains == NULL) {
        return NULL;
    }

    cli->renew_before_expiry = 60 * 60 * 24 * 30;
    cli->retry_after_error = 60 * 60 * 2;
    /* cli->max_cert_size = 0; */
    cli->challenge = NGX_AC_HTTP_01;
    cli->renew_on_load = 0;
    cli->account_key.file.fd = NGX_INVALID_FILE;
    cli->private_key.file.fd = NGX_INVALID_FILE;
    cli->private_key.type = NGX_KT_UNSUPPORTED;
    cli->private_key.bits = NGX_CONF_UNSET;
    cli->certificate_file.fd = NGX_INVALID_FILE;
    cli->eab_alg = NGX_AEA_HS256;

    cli_p = ngx_array_push(clients);
    if (cli_p == NULL) {
        return NULL;
    }

    *cli_p = cli;

    return cli;
}


ngx_array_t *
ngx_acme_clients(ngx_cycle_t *cycle)
{
    ngx_acme_conf_t  *acf;

    acf = (ngx_acme_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_acme_module);

    return &acf->clients;
}


static void *
ngx_acme_create_conf(ngx_cycle_t *cycle)
{
    ngx_acme_conf_t  *acf;

    acf = ngx_pcalloc(cycle->pool, sizeof(ngx_acme_conf_t));
    if (acf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&acf->clients, cycle->pool, 4,
        sizeof(ngx_acme_client_t *)) != NGX_OK)
    {
        return NULL;
    }

    return acf;
}

