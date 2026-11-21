
/*
 * Copyright (C) Hanada
 */


#ifndef _NGX_CLIENT_H_INCLUDED_
#define _NGX_CLIENT_H_INCLUDED_


#if (NGX_EXT && NGX_CLIENT)


#define NGX_CLIENT_HTTP_TIMEDOUT   -1000
#define NGX_CLIENT_HTTP_TOO_LARGE  -1001


typedef struct {
    ngx_client_http_server_t        *server;
    const ngx_str_t                 *server_name;
    ngx_str_t                        method;
    ngx_str_t                        url;
    ngx_array_t                     *headers;
    ngx_str_t                        body;
    ngx_msec_t                       timeout;
} ngx_client_http_request_t;


typedef struct {
    ngx_uint_t                       status;
    ngx_array_t                      headers;
    ngx_str_t                        body;
} ngx_client_http_response_t;


/* The response is valid until the completion handler returns. */
typedef void (*ngx_client_http_post_request_pt)(
    ngx_client_http_response_t *response, void *data, ngx_int_t rc);


/* A non-NGX_OK result rejects the prospective sizes and ends the request. */
typedef ngx_int_t (*ngx_client_http_check_size_pt)(void *data,
    size_t header_size, uint64_t body_size);


/* NGX_DONE finishes the request with the headers received so far. */
typedef ngx_int_t (*ngx_client_http_header_pt)(
    ngx_client_http_response_t *response, void *data);


/*
 * Called synchronously for each non-empty body buffer. The buffer is valid
 * only during the call. Return NGX_OK to continue or an error to stop.
 * With this handler, the completion response has an empty body.
 */
typedef ngx_int_t (*ngx_client_http_body_pt)(const u_char *buf, size_t len,
    void *data);


typedef struct {
    ngx_client_http_post_request_pt  handler;
    ngx_client_http_header_pt        header_handler;
    ngx_client_http_body_pt          body_handler;
    ngx_client_http_check_size_pt    check_size;
    void                            *data;
} ngx_client_http_post_request_t;


typedef struct {
    ngx_event_t                     *notify;
    ngx_client_http_check_size_pt    check_size;
    void                            *data;

    unsigned                         request_body_streaming:1;
} ngx_client_http_stream_t;


/*
 * The request URL must be absolute. The default server is @client.
 * NGX_DECLINED indicates an unknown server name. Completion is deferred.
 */
ngx_int_t ngx_client_http_create_request(ngx_cycle_t *cycle, ngx_log_t *log,
    ngx_client_http_request_t *request, ngx_client_http_t **pclient,
    ngx_client_http_post_request_t *post);

/*
 * The caller owns the stream until close, including after EOF.  Notifications
 * are posted when an operation can be retried.  A zero-length write ends the
 * request body.  A read returning zero marks the end of the response body.
 */
ngx_int_t ngx_client_http_create_streaming_request(ngx_cycle_t *cycle,
    ngx_log_t *log, ngx_client_http_request_t *request,
    ngx_client_http_t **pclient, ngx_client_http_stream_t *stream);
ngx_int_t ngx_client_http_get_response_headers(ngx_client_http_t *client,
    ngx_client_http_response_t **response);
ssize_t ngx_client_http_read_response_body(ngx_client_http_t *client,
    u_char *buf, size_t size);
ssize_t ngx_client_http_write_request_body(ngx_client_http_t *client,
    const u_char *buf, size_t size);

/* Closing from a response or size callback stops delivery on return. */
void ngx_client_http_close_request(ngx_client_http_t *client);

ngx_int_t ngx_client_http_require(ngx_cycle_t *cycle);


extern ngx_conf_post_t  ngx_client_http_server_post;

#endif

#endif /* _NGX_CLIENT_H_INCLUDED_ */
