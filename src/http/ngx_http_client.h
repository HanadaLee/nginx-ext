
/*
 * Copyright (C) Hanada
 */


#ifndef _NGX_HTTP_CLIENT_H_INCLUDED_
#define _NGX_HTTP_CLIENT_H_INCLUDED_


#include <ngx_config.h>

#if (NGX_EXT && NGX_CLIENT)

#include <ngx_core.h>
#include <ngx_http.h>


ngx_uint_t ngx_http_client_required(ngx_cycle_t *cycle);
ngx_int_t ngx_http_client_bind_servers(ngx_cycle_t *cycle);
char *ngx_http_client_register_server(ngx_conf_t *cf,
    ngx_http_core_srv_conf_t *cscf);
ngx_int_t ngx_http_client_prepare(ngx_conf_t *cf,
    ngx_http_core_main_conf_t *cmcf);

void ngx_http_client_finalize(ngx_http_request_t *r, ngx_int_t rc);
void ngx_http_client_upstream_error(ngx_http_request_t *r, ngx_int_t rc);
void ngx_http_client_reset_upstream_error(ngx_http_request_t *r);


static ngx_inline ngx_int_t
ngx_http_handle_write_event(ngx_http_request_t *r, size_t lowat)
{
    if (r->connection->stub) {
        return NGX_OK;
    }

    return ngx_handle_write_event(r->connection->write, lowat);
}

#endif


#endif /* _NGX_HTTP_CLIENT_H_INCLUDED_ */
