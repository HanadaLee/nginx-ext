
/*
 * Copyright (C) Hanada
 */


#include <ngx_config.h>
#include <ngx_core.h>


#if (NGX_EXT && NGX_CLIENT)


ngx_int_t ngx_http_client_create_request(ngx_cycle_t *cycle, ngx_log_t *log,
    ngx_client_http_request_t *request, ngx_client_http_t **pclient,
    ngx_client_http_post_request_t *post,
    const ngx_client_http_stream_t *stream);
ngx_int_t ngx_http_client_get_response_headers(ngx_client_http_t *client,
    ngx_client_http_response_t **response);
ssize_t ngx_http_client_read_response_body(ngx_client_http_t *client,
    u_char *buf, size_t size);
ssize_t ngx_http_client_write_request_body(ngx_client_http_t *client,
    const u_char *buf, size_t size);
void ngx_http_client_close_request(ngx_client_http_t *client);

ngx_client_http_server_t *ngx_http_client_add_server_reference(
    ngx_cycle_t *cycle, const ngx_str_t *name);
ngx_int_t ngx_http_client_require(ngx_cycle_t *cycle);

static char *ngx_client_http_set_server(ngx_conf_t *cf, void *post,
    void *conf);


ngx_conf_post_t  ngx_client_http_server_post = { ngx_client_http_set_server };


ngx_int_t
ngx_client_http_create_request(ngx_cycle_t *cycle, ngx_log_t *log,
    ngx_client_http_request_t *request, ngx_client_http_t **pclient,
    ngx_client_http_post_request_t *post)
{
    return ngx_http_client_create_request(cycle, log, request, pclient, post,
                                          NULL);
}


ngx_int_t
ngx_client_http_create_streaming_request(ngx_cycle_t *cycle, ngx_log_t *log,
    ngx_client_http_request_t *request, ngx_client_http_t **pclient,
    ngx_client_http_stream_t *stream)
{
    ngx_client_http_post_request_t  post;

    if (stream->notify == NULL
        || (stream->request_body_streaming && request->body.len))
    {
        return NGX_ERROR;
    }

    ngx_memzero(&post, sizeof(ngx_client_http_post_request_t));
    post.check_size = stream->check_size;
    post.data = stream->data;

    return ngx_http_client_create_request(cycle, log, request, pclient, &post,
                                          stream);
}


ngx_int_t
ngx_client_http_get_response_headers(ngx_client_http_t *client,
    ngx_client_http_response_t **response)
{
    return ngx_http_client_get_response_headers(client, response);
}


ssize_t
ngx_client_http_read_response_body(ngx_client_http_t *client, u_char *buf,
    size_t size)
{
    return ngx_http_client_read_response_body(client, buf, size);
}


ssize_t
ngx_client_http_write_request_body(ngx_client_http_t *client, const u_char *buf,
    size_t size)
{
    return ngx_http_client_write_request_body(client, buf, size);
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
ngx_client_http_set_server(ngx_conf_t *cf, void *post, void *conf)
{
    ngx_client_http_server_t  **slot = conf;

    ngx_str_t  *value;

    if (*slot) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *slot = ngx_http_client_add_server_reference(cf->cycle, &value[1]);
    if (*slot == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


#endif
