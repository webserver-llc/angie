
/*
 * Copyright (C) 2026 Web Server LLC
 */


#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_acme.h>


static void *ngx_acme_create_conf(ngx_cycle_t *cycle);
static ngx_int_t ngx_acme_check_server_name(ngx_str_t *name, int wildcard_allowed);
static ngx_int_t ngx_acme_add_domain(ngx_acme_client_t *cli, ngx_str_t *domain);


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

    /*
     * set by ngx_pcalloc():
     *
     *    cli->path = { 0, NULL };
     *    cli->server = { 0, NULL };
     *    cli->server_url = { 0, ... };
     *    cli->email = { 0, NULL };
     *    cli->expiry_time = 0;
     *    cli->renew_time = 0;
     *    cli->max_cert_size = 0;
     *    cli->private_key_data = NULL;
     *    cli->certificate_file_size = 0;
     *    cli->session = NULL;
     *    cli->sh_cert = NULL;
     *    cli->hook_clcf = NULL;
     *    cli->hook_ctx = NULL;
     *    cli->hook_uri = NULL;
     *    cli->eab_id = { 0, NULL };
     *    cli->eab_key = { 0, NULL };
     *    cli->profile = { 0, NULL };
     *
     *    cli->renew_on_load = 0;
     *    cli->referenced = 0;
     */

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
    cli->challenge = NGX_AC_HTTP_01;
    cli->account_key.file.fd = NGX_INVALID_FILE;
    cli->private_key.file.fd = NGX_INVALID_FILE;
    cli->private_key.type = NGX_KT_UNSUPPORTED;
    cli->private_key.bits = NGX_CONF_UNSET;
    cli->certificate_file.fd = NGX_INVALID_FILE;
    cli->eab_alg = NGX_AEA_HS256;

    /*
     * to be initialized properly in the http context:
     * cli->hcli = NULL;
     */

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


static ngx_int_t
ngx_acme_check_server_name(ngx_str_t *name, int wildcard_allowed)
{
    u_char  *p, *end;

    /*
     * This is mostly a sanity check with support for wildcard domains.
     * It doesn't check for everything, e.g. hyphens in the wrong places, etc.
     */

    if (ngx_acme_str_is_ip(name)) {
        /* IPs are allowed, but not for DNS-01 challenges. */
        return wildcard_allowed ? NGX_ERROR : NGX_OK;
    }

    p = name->data;

    if (name->len < 3 || *p == '~') {
        /* domains specified with regular expressions are not supported */
        return NGX_ERROR;
    }

    if ((*p == '*' || *p == '.') && !wildcard_allowed) {
        return NGX_ERROR;
    }

    end = p + name->len;

    if (*p == '*') {
        p++;

        if (*p != '.') {
            return NGX_ERROR;
        }
    }

    for ( /* void */ ; p < end; p++) {
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z')
              || (*p >= '0' && *p <= '9') || *p == '-' || *p == '.'))
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_acme_add_server_name(ngx_conf_t *cf, ngx_acme_client_t *cli,
    ngx_str_t *name)
{
    ngx_str_t  s;

    if (name->len == 0) {
        /*
         * server_names arrays used by "server_name" directives may contain
         * empty names
         */
        return NGX_DECLINED;
    }

    if (ngx_acme_check_server_name(name, cli->challenge == NGX_AC_DNS_01)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, cf->log, 0,
                      "unsupported domain format \"%V\" used "
                      "by ACME client \"%V\", ignored", name, &cli->name);
        return NGX_DECLINED;
    }

    if (name->data[0] != '.') {
        return ngx_acme_add_domain(cli, name);
    }

    s.data = ngx_pnalloc(cf->pool, name->len + 1);
    if (s.data == NULL) {
        return NGX_ERROR;
    }

    s.data[0] = '*';
    ngx_memcpy(s.data + 1, name->data, name->len);
    s.len = name->len + 1;

    if (ngx_acme_add_domain(cli, &s) != NGX_OK) {
        return NGX_ERROR;
    }

    s.data = name->data + 1;
    s.len = name->len - 1;

    return ngx_acme_add_domain(cli, &s);
}


static ngx_int_t
ngx_acme_add_domain(ngx_acme_client_t *cli, ngx_str_t *domain)
{
    ngx_str_t   *s;
    ngx_int_t    i;
    ngx_uint_t   wclen;

    for (i = cli->domains->nelts - 1; i >= 0; i--) {
        s = &((ngx_str_t *) cli->domains->elts)[i];

        if (s->len == domain->len
            && ngx_strncasecmp(s->data, domain->data, s->len) == 0)
        {
            /* Duplicate domain, ignore. */
            return NGX_OK;
        }

        if ((s->data[0] == '*') == (domain->data[0] == '*')) {
            /* Non-matching domain, continue searching. */
            continue;
        }

        if (s->data[0] == '*') {
            wclen = s->len - 1;

            if (domain->len > wclen
                && ngx_strncasecmp(domain->data + domain->len - wclen,
                                   s->data + 1, wclen) == 0)
            {
                /*
                 * We are adding a non-wildcard domain that matches a wildcard
                 * domain in the list, ignore it.
                 */
                return NGX_OK;
            }

        } else {
            wclen = domain->len - 1;

            if (s->len > wclen
                && ngx_strncasecmp(s->data + s->len - wclen,
                                   domain->data + 1, wclen) == 0)
            {
                /*
                 * We are adding a wildcard domain that matches a non-wildcard
                 * domain in the list, remove the non-wildcard domain from the
                 * list. We need to remove all the matching non-wildcard
                 * domains from the list and replace them with the wildcard
                 * domain.
                 */
                ngx_memmove(s, &s[1],
                            (cli->domains->nelts - 1 - i) * sizeof(ngx_str_t));

                cli->domains->nelts--;
            }
        }
    }

    s = ngx_array_push(cli->domains);
    if (s == NULL) {
        return NGX_ERROR;
    }

    *s = *domain;

    return NGX_OK;
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


ngx_uint_t
ngx_acme_str_is_ip(ngx_str_t *str)
{
#if (NGX_HAVE_INET6)
    u_char  dummy[16];
#endif

    return ngx_inet_addr(str->data, str->len) != INADDR_NONE
#if (NGX_HAVE_INET6)
           || ngx_inet6_addr(str->data, str->len, dummy) == NGX_OK
#endif
    ;
}
