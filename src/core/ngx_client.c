
/*
 * Copyright (C) Hanada
 */


#include <ngx_config.h>
#include <ngx_core.h>


#if (NGX_EXT && NGX_CLIENT)


ngx_int_t ngx_http_client_create_request(ngx_cycle_t *cycle, ngx_log_t *log,
    ngx_client_http_request_t *request, ngx_client_http_t **pclient,
    ngx_client_http_post_request_t *post);
void ngx_http_client_close_request(ngx_client_http_t *client);

ngx_client_http_server_t *ngx_http_client_add_server(ngx_cycle_t *cycle,
    const ngx_str_t *name);
ngx_int_t ngx_http_client_require(ngx_cycle_t *cycle);

static char *ngx_client_http_register_server(ngx_conf_t *cf, void *post,
    void *conf);


ngx_conf_post_t  ngx_client_http_server_post =
    { ngx_client_http_register_server };


ngx_int_t
ngx_client_http_create_request(ngx_cycle_t *cycle, ngx_log_t *log,
    ngx_client_http_request_t *request, ngx_client_http_t **pclient,
    ngx_client_http_post_request_t *post)
{
    return ngx_http_client_create_request(cycle, log, request, pclient, post);
}


void
ngx_client_http_close_request(ngx_client_http_t *client)
{
    ngx_http_client_close_request(client);
}


ngx_int_t
ngx_client_http_require(ngx_cycle_t *cycle)
{
    return ngx_http_client_require(cycle);
}


static char *
ngx_client_http_register_server(ngx_conf_t *cf, void *post, void *conf)
{
    ngx_client_http_server_t  **slot = conf;

    ngx_str_t  *value;

    if (*slot) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *slot = ngx_http_client_add_server(cf->cycle, &value[1]);
    if (*slot == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


#endif
