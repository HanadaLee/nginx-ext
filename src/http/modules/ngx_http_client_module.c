
/*
 * Copyright (C) Web Server LLC
 * Copyright (C) Hanada
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#if (NGX_RESTY_EXT && NGX_CLIENT)


#define ngx_http_client_from_connection(c)                                   \
    (ngx_client_http_t *) ((u_char *) (c)                                    \
                           - offsetof(ngx_client_http_t, connection))


struct ngx_client_http_server_s {
    ngx_str_t                       name;
    ngx_http_core_srv_conf_t       *srv_conf;
};


typedef struct {
    ngx_array_t                     servers;
    ngx_array_t                    *references;

    unsigned                        required:1;
} ngx_http_client_conf_t;


struct ngx_client_http_s {
    ngx_connection_t                connection;
    ngx_listening_t                 listening;
    ngx_http_connection_t           http_connection;
    ngx_event_t                     read;
    ngx_event_t                     write;
    ngx_event_t                     event;
    ngx_event_t                     done;
    ngx_event_t                     timeout;
    ngx_log_t                       log;
    ngx_http_log_ctx_t              log_ctx;
    struct sockaddr_in              sockaddr;
    struct sockaddr_in              local_sockaddr;
    ngx_pool_t                     *pool;
    ngx_http_request_t             *request;
    ngx_http_core_srv_conf_t       *server;
    ngx_client_http_post_request_t  post;

    ngx_client_http_response_t      response;
    ngx_chain_t                    *out;
    ngx_chain_t                   **last;
    size_t                          header_size;
    size_t                          length;
    ngx_int_t                       rc;
    ngx_int_t                       error;
    ngx_int_t                       upstream_error;

    unsigned                        in_callback:1;
    unsigned                        closing:1;
};


static char *ngx_http_client(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_http_client_conf_t *ngx_http_client_get_conf(ngx_cycle_t *cycle);
static ngx_http_core_srv_conf_t *ngx_http_client_find_server(ngx_cycle_t *cycle,
    const ngx_str_t *name);
static ngx_int_t ngx_http_client_filter_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_client_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_client_early_hints_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_client_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_client_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_client_body(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_client_init_request(ngx_client_http_t *client,
    ngx_client_http_request_t *request);
static ngx_int_t ngx_http_client_parse_url(ngx_http_request_t *r,
    ngx_str_t *url, ngx_str_t *uri);
static ngx_int_t ngx_http_client_init_headers(ngx_http_request_t *r,
    ngx_client_http_request_t *request);
static void ngx_http_client_start_request(ngx_event_t *ev);
static void ngx_http_client_complete(ngx_event_t *ev);
static void ngx_http_client_timeout(ngx_event_t *ev);
static void ngx_http_client_abort(ngx_event_t *ev);
static void ngx_http_client_request_handler(ngx_event_t *ev);
static u_char *ngx_http_client_log_error(ngx_log_t *log, u_char *buf,
    size_t len);
static ngx_keyval_t *ngx_http_client_add_header(ngx_client_http_t *client,
    ngx_str_t *key, size_t len);
static ngx_int_t ngx_http_client_save_header(ngx_client_http_t *client,
    ngx_str_t *key, ngx_str_t *value);


static ngx_command_t  ngx_http_client_commands[] = {

    { ngx_string("client"),
      NGX_HTTP_SRV_CONF|NGX_CONF_NOARGS,
      ngx_http_client,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_client_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_client_module = {
    NGX_MODULE_V1,
    &ngx_http_client_module_ctx,           /* module context */
    ngx_http_client_commands,              /* module directives */
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


static ngx_http_module_t  ngx_http_client_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_client_filter_init,           /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_client_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_client_filter_module_ctx,    /* module context */
    NULL,                                  /* module directives */
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


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_header_filter_pt  ngx_http_next_early_hints_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_str_t  ngx_http_client_default_name = ngx_string("@client");


/* The final brace terminates the surrounding http block. */

static u_char ngx_http_client_default_conf[] =
"server {\n"
"    client;\n"
"    server_name @client;\n"
"    access_log off;\n"
"    location / {\n"
"        proxy_pass $scheme://$host$is_request_port$request_port;\n"
"        proxy_set_header Host $http_host;\n"
"        proxy_buffering off;\n"
"        proxy_request_buffering off;\n"
#if (NGX_HTTP_SSL)
"        proxy_ssl_server_name on;\n"
"        proxy_ssl_name $http_host;\n"
#endif
"    }\n"
"}\n"
"}\n"
;


ngx_uint_t
ngx_http_client_required(ngx_cycle_t *cycle)
{
    ngx_http_client_conf_t  *ccf;

    ccf = (ngx_http_client_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                  ngx_http_client_module);

    return ccf && (ccf->required || ccf->references);
}


ngx_int_t
ngx_http_client_bind_servers(ngx_cycle_t *cycle)
{
    ngx_uint_t                  i;
    ngx_http_client_conf_t     *ccf;
    ngx_client_http_server_t  **refs;

    ccf = (ngx_http_client_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                  ngx_http_client_module);
    if (ccf == NULL || ccf->references == NULL) {
        return NGX_OK;
    }

    refs = ccf->references->elts;

    for (i = 0; i < ccf->references->nelts; i++) {
        refs[i]->srv_conf = ngx_http_client_find_server(cycle, &refs[i]->name);

        if (refs[i]->srv_conf == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "unknown client server \"%V\"", &refs[i]->name);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


ngx_client_http_server_t *
ngx_http_client_add_server(ngx_cycle_t *cycle, const ngx_str_t *name)
{
    ngx_http_client_conf_t    *ccf;
    ngx_client_http_server_t  *server, **p;

    ccf = ngx_http_client_get_conf(cycle);
    if (ccf == NULL) {
        return NULL;
    }

    if (ccf->references == NULL) {
        ccf->references = ngx_array_create(cycle->pool, 2,
                                           sizeof(ngx_client_http_server_t *));
        if (ccf->references == NULL) {
            return NULL;
        }
    }

    server = ngx_pcalloc(cycle->pool, sizeof(ngx_client_http_server_t));
    if (server == NULL) {
        return NULL;
    }

    p = ngx_array_push(ccf->references);
    if (p == NULL) {
        return NULL;
    }

    server->name = *name;
    *p = server;

    return server;
}


ngx_int_t
ngx_http_client_require(ngx_cycle_t *cycle)
{
    ngx_http_client_conf_t  *ccf;

    ccf = ngx_http_client_get_conf(cycle);
    if (ccf == NULL) {
        return NGX_ERROR;
    }

    ccf->required = 1;

    return NGX_OK;
}


static ngx_http_client_conf_t *
ngx_http_client_get_conf(ngx_cycle_t *cycle)
{
    ngx_http_client_conf_t  *ccf;

    ccf = (ngx_http_client_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                  ngx_http_client_module);
    if (ccf) {
        return ccf;
    }

    ccf = ngx_pcalloc(cycle->pool, sizeof(ngx_http_client_conf_t));
    if (ccf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&ccf->servers, cycle->pool, 2,
                       sizeof(ngx_client_http_server_t))
        != NGX_OK)
    {
        return NULL;
    }

    /*
     * Other subsystems can reference client servers before HTTP is parsed.
     * Use the client module's cycle slot, outside the HTTP block context.
     */
    cycle->conf_ctx[ngx_http_client_module.index] = (void *) ccf;

    return ccf;
}


static char *
ngx_http_client(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_srv_conf_t  *cscf;

    cscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_core_module);

    if (cscf->client) {
        return "is duplicate";
    }

    cscf->client = 1;

    return NGX_CONF_OK;
}


char *
ngx_http_client_register_server(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf)
{
    ngx_http_client_conf_t    *ccf;
    ngx_http_server_name_t    *name;
    ngx_client_http_server_t  *server;

    if (cscf->listen) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"listen\" is not allowed in a client server");
        return NGX_CONF_ERROR;
    }

    name = cscf->server_names.elts;

    if (cscf->server_names.nelts != 1
#if (NGX_PCRE)
        || name->regex
#endif
        || name->name.len < 2 || name->name.data[0] != '@'
        || ngx_strlchr(name->name.data, name->name.data + name->name.len, '*'))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "a client server requires one literal "
                           "\"server_name\" starting with \"@\"");
        return NGX_CONF_ERROR;
    }

    if (ngx_http_client_find_server(cf->cycle, &name->name)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate client server \"%V\"", &name->name);
        return NGX_CONF_ERROR;
    }

    ccf = ngx_http_client_get_conf(cf->cycle);
    if (ccf == NULL) {
        return NGX_CONF_ERROR;
    }

    server = ngx_array_push(&ccf->servers);
    if (server == NULL) {
        return NGX_CONF_ERROR;
    }

    server->name = name->name;
    server->srv_conf = cscf;

    return NGX_CONF_OK;
}


ngx_int_t
ngx_http_client_prepare(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf)
{
    ngx_str_t                  chunk;
    ngx_uint_t                 i, j;
    ngx_http_server_name_t    *names;
    ngx_http_core_srv_conf_t  *cscf, **servers;

    servers = cmcf->servers.elts;

    for (i = 0; i < cmcf->servers.nelts; i++) {
        cscf = servers[i];
        if (cscf->client) {
            continue;
        }

        names = cscf->server_names.elts;

        for (j = 0; j < cscf->server_names.nelts; j++) {

            if (names[j].name.len == ngx_http_client_default_name.len
                && ngx_strncmp(names[j].name.data,
                               ngx_http_client_default_name.data,
                               names[j].name.len)
                   == 0)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "the \"@client\" server "
                                   "requires the \"client\" directive");
                return NGX_ERROR;
            }
        }
    }

    if (ngx_http_client_find_server(cf->cycle, NULL)) {
        return NGX_OK;
    }

    ngx_str_set(&chunk, ngx_http_client_default_conf);

    if (ngx_conf_parse_chunk(cf, &ngx_http_client_default_name, &chunk)
        != NGX_CONF_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_http_core_srv_conf_t *
ngx_http_client_find_server(ngx_cycle_t *cycle, const ngx_str_t *name)
{
    ngx_uint_t                 i;
    ngx_http_client_conf_t    *ccf;
    ngx_client_http_server_t  *servers;

    ccf = (ngx_http_client_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                  ngx_http_client_module);
    if (ccf == NULL) {
        return NULL;
    }

    if (name == NULL) {
        name = &ngx_http_client_default_name;
    }

    servers = ccf->servers.elts;

    for (i = 0; i < ccf->servers.nelts; i++) {
        if (servers[i].name.len == name->len
            && ngx_strncasecmp(servers[i].name.data, name->data, name->len)
               == 0)
        {
            return servers[i].srv_conf;
        }
    }

    return NULL;
}


ngx_int_t
ngx_http_client_create_request(ngx_cycle_t *cycle, ngx_log_t *log,
    ngx_client_http_request_t *request, ngx_client_http_t **pclient,
    ngx_client_http_post_request_t *post)
{
    ngx_pool_t                *pool;
    ngx_connection_t          *c;
    ngx_client_http_t         *client;
    ngx_http_core_srv_conf_t  *server;

    if (request->server) {
        server = request->server->srv_conf;

    } else {
        server = ngx_http_client_find_server(cycle, request->server_name);
    }

    if (server == NULL) {
        return request->server_name ? NGX_DECLINED : NGX_ERROR;
    }

    pool = ngx_create_pool(2048, cycle->log);
    if (pool == NULL) {
        return NGX_ERROR;
    }

    client = ngx_pcalloc(pool, sizeof(ngx_client_http_t));
    if (client == NULL) {
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    client->pool = pool;
    client->server = server;
    client->post = *post;
    client->last = &client->out;
    client->rc = NGX_ERROR;

    client->log = *log;
    client->log.handler = ngx_http_client_log_error;
    client->log.data = &client->log_ctx;
    client->log.action = NULL;
    pool->log = &client->log;

    c = &client->connection;
    client->log_ctx.connection = c;
    c->log = &client->log;
    c->pool = pool;
    c->fd = (ngx_socket_t) -1;
    c->stub = 1;
    c->type = SOCK_STREAM;
    c->tcp_nodelay = NGX_TCP_NODELAY_DISABLED;
    c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
    c->log->connection = c->number;
    c->start_time = ngx_current_msec;

    client->sockaddr.sin_family = AF_INET;
    client->sockaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    c->sockaddr = (struct sockaddr *) &client->sockaddr;
    c->socklen = sizeof(struct sockaddr_in);
    client->local_sockaddr = client->sockaddr;
    c->local_sockaddr = (struct sockaddr *) &client->local_sockaddr;
    c->local_socklen = c->socklen;
    ngx_str_set(&c->addr_text, "127.0.0.1");
    c->listening = &client->listening;
    c->listening->addr_text = c->addr_text;

    c->read = &client->read;
    c->write = &client->write;

    c->read->index = NGX_INVALID_INDEX;
    c->write->index = NGX_INVALID_INDEX;

    c->read->ready = 1;
    c->read->data = c;
    c->read->log = c->log;
    c->read->handler = ngx_http_client_request_handler;

    c->write->write = 1;
    c->write->ready = 1;
    c->write->data = c;
    c->write->log = c->log;
    c->write->handler = ngx_http_client_request_handler;

    client->event.data = client;
    client->event.handler = ngx_http_client_start_request;
    client->event.log = c->log;

    client->done.data = client;
    client->done.handler = ngx_http_client_complete;
    client->done.log = c->log;

    client->timeout.data = client;
    client->timeout.handler = ngx_http_client_timeout;
    client->timeout.log = c->log;

    if (ngx_http_client_init_request(client, request) != NGX_OK) {
        if (client->request) {
            ngx_http_free_request(client->request, 0);
        }

        if (client->done.posted) {
            ngx_delete_posted_event(&client->done);
        }

        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    if (request->timeout) {
        ngx_add_timer(&client->timeout, request->timeout);
    }

    ngx_post_event(&client->event, &ngx_posted_events);

    *pclient = client;

    return NGX_OK;
}


static ngx_int_t
ngx_http_client_init_request(ngx_client_http_t *client,
    ngx_client_http_request_t *request)
{
    size_t                    len;
    u_char                   *p;
    ngx_str_t                 uri;
    ngx_buf_t                *b;
    ngx_chain_t              *cl;
    ngx_connection_t         *c;
    ngx_http_request_t       *r;
    ngx_http_request_body_t  *rb;

    if (request->method.len == 0) {
        return NGX_ERROR;
    }

    c = &client->connection;
    client->http_connection.conf_ctx = client->server->ctx;
    c->data = &client->http_connection;

    r = ngx_http_create_request(c);
    if (r == NULL) {
        return NGX_ERROR;
    }

    client->request = r;
    c->data = r;

    r->internal = 1;
    r->main_filter_need_in_memory = 1;
    r->read_event_handler = ngx_http_request_empty_handler;
    r->write_event_handler = ngx_http_request_empty_handler;

    if (ngx_http_client_parse_url(r, &request->url, &uri) != NGX_OK) {
        return NGX_ERROR;
    }

    len = request->method.len + 1 + uri.len
          + sizeof(" HTTP/1.1" CRLF) - 1;
    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(b->last, request->method.data, request->method.len);
    *p++ = ' ';
    p = ngx_cpymem(p, uri.data, uri.len);
    b->last = ngx_cpymem(p, " HTTP/1.1" CRLF, sizeof(" HTTP/1.1" CRLF) - 1);

    r->header_in = b;

    if (ngx_http_parse_request_line(r, b) != NGX_OK
        || b->pos != b->last
        || r->method_end != b->start + request->method.len - 1
        || r->uri_end != p)
    {
        return NGX_ERROR;
    }

    r->request_line.data = r->request_start;
    r->request_line.len = r->request_end - r->request_start;
    r->method_name.data = r->request_start;
    r->method_name.len = request->method.len;
    ngx_str_set(&r->http_protocol, "HTTP/1.1");

    if (ngx_http_process_request_uri(r) != NGX_OK) {
        if (c->destroyed) {
            client->request = NULL;

        } else if (r->terminated) {
            ngx_http_run_posted_requests(c);
        }

        return NGX_ERROR;
    }

    if (ngx_list_init(&r->headers_in.headers, r->pool, 8,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    r->headers_in.content_length_n = request->body.len;
    r->request_length = len + sizeof(CRLF) - 1 + request->body.len;

    if (ngx_http_client_init_headers(r, request) != NGX_OK) {
        return NGX_ERROR;
    }

    rb = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (rb == NULL) {
        return NGX_ERROR;
    }

    r->request_body = rb;
    rb->last_saved = 1;

    if (request->body.len) {
        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        b = ngx_create_temp_buf(r->pool, request->body.len);
        if (b == NULL) {
            return NGX_ERROR;
        }

        b->last = ngx_cpymem(b->pos, request->body.data, request->body.len);
        b->last_buf = 1;

        cl->buf = b;
        cl->next = NULL;
        rb->bufs = cl;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_client_parse_url(ngx_http_request_t *r, ngx_str_t *url, ngx_str_t *uri)
{
    u_char     *p;
    size_t      prefix;
    ngx_str_t   host;
    ngx_url_t   u;

    ngx_memzero(&u, sizeof(ngx_url_t));

    if (url->len > 7
        && ngx_strncasecmp(url->data, (u_char *) "http://", 7) == 0)
    {
        prefix = 7;
        u.default_port = 80;
        ngx_str_set(&r->schema, "http");

    } else if (url->len > 8
               && ngx_strncasecmp(url->data, (u_char *) "https://", 8) == 0)
    {
        prefix = 8;
        u.default_port = 443;
        ngx_str_set(&r->schema, "https");

    } else {
        return NGX_ERROR;
    }

    u.url.data = url->data + prefix;
    u.url.len = url->len - prefix;
    u.uri_part = 1;
    u.no_resolve = 1;

    if (ngx_parse_url(r->pool, &u) != NGX_OK) {
        return NGX_ERROR;
    }

    if (u.family == AF_UNIX) {
        host.len = sizeof("unix:") - 1 + u.host.len + 1;
        host.data = ngx_pnalloc(r->pool, host.len);
        if (host.data == NULL) {
            return NGX_ERROR;
        }

        p = ngx_cpymem(host.data, "unix:", sizeof("unix:") - 1);
        p = ngx_cpymem(p, u.host.data, u.host.len);
        *p = ':';

    } else {
        host = u.host;

        if (ngx_http_validate_host(&host, NULL, r->pool, 1) != NGX_OK) {
            return NGX_ERROR;
        }

        r->port = u.no_port ? 0 : u.port;
        ngx_inet_set_port(r->connection->local_sockaddr, u.port);
    }

    r->headers_in.server = host;

    *uri = u.uri;

    if (uri->len == 0) {
        ngx_str_set(uri, "/");

    } else if (uri->data[0] == '?') {
        uri->data = ngx_pnalloc(r->pool, u.uri.len + 1);
        if (uri->data == NULL) {
            return NGX_ERROR;
        }

        uri->data[0] = '/';
        ngx_memcpy(uri->data + 1, u.uri.data, u.uri.len);
        uri->len++;

    } else if (uri->data[0] != '/') {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_client_init_headers(ngx_http_request_t *r,
    ngx_client_http_request_t *request)
{
    u_char                     *p, *last, ch;
    ngx_uint_t                  i;
    ngx_keyval_t               *kv;
    ngx_http_header_t          *hh;
    ngx_table_elt_t            *h;
    ngx_http_core_main_conf_t  *cmcf;

    if (request->headers == NULL) {
        return NGX_OK;
    }

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
    kv = request->headers->elts;

    for (i = 0; i < request->headers->nelts; i++) {
        if (kv[i].key.len == 0) {
            return NGX_ERROR;
        }

        p = kv[i].key.data;
        last = p + kv[i].key.len;

        while (p < last) {
            ch = *p++;

            if ((ch >= '0' && ch <= '9')
                || (ngx_tolower(ch) >= 'a' && ngx_tolower(ch) <= 'z')
                || (ch && ngx_strchr("!#$%&'*+-.^_\x60|~", ch)))
            {
                continue;
            }

            return NGX_ERROR;
        }

        for (p = kv[i].value.data, last = p + kv[i].value.len; p < last; p++) {
            if ((*p < ' ' && *p != '\t') || *p == 0x7f) {
                return NGX_ERROR;
            }
        }

        h = ngx_list_push(&r->headers_in.headers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        ngx_memzero(h, sizeof(ngx_table_elt_t));

        h->key.len = kv[i].key.len;
        h->key.data = ngx_pstrdup(r->pool, &kv[i].key);
        h->value.len = kv[i].value.len;
        h->value.data = ngx_pnalloc(r->pool, h->value.len + 1);
        h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);

        if (h->key.data == NULL || h->value.data == NULL
            || h->lowcase_key == NULL)
        {
            return NGX_ERROR;
        }

        p = ngx_cpymem(h->value.data, kv[i].value.data, h->value.len);
        *p = '\0';

        r->request_length += h->key.len + h->value.len
                             + sizeof(": " CRLF) - 1;

        h->hash = ngx_hash_strlow(h->lowcase_key, h->key.data, h->key.len);
        hh = ngx_hash_find(&cmcf->headers_in_hash, h->hash, h->lowcase_key,
                           h->key.len);

        if (hh == NULL) {
            continue;
        }

        if (hh->offset == offsetof(ngx_http_headers_in_t, host)) {
            if (r->headers_in.host) {
                return NGX_ERROR;
            }

            r->headers_in.host = h;
            continue;
        }

        if (hh->offset == offsetof(ngx_http_headers_in_t, content_length)) {
            if (r->headers_in.content_length
                || ngx_atoof(h->value.data, h->value.len)
                   != r->headers_in.content_length_n)
            {
                return NGX_ERROR;
            }

            r->headers_in.content_length = h;
            continue;
        }

        if (hh->offset == offsetof(ngx_http_headers_in_t, transfer_encoding)) {
            return NGX_ERROR;
        }

        if (hh->handler(r, h, hh->offset) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static void
ngx_http_client_start_request(ngx_event_t *ev)
{
    ngx_client_http_t  *client;

    client = ev->data;

    ngx_http_handler(client->request);
    ngx_http_run_posted_requests(&client->connection);
}


static void
ngx_http_client_request_handler(ngx_event_t *ev)
{
    ngx_connection_t    *c;
    ngx_http_request_t  *r;

    c = ev->data;
    r = c->data;

    ngx_http_set_log_request(c->log, r);

    if (ev->delayed && ev->timedout) {
        ev->delayed = 0;
        ev->timedout = 0;
    }

    if (ev->write) {
        r->write_event_handler(r);

    } else {
        r->read_event_handler(r);
    }

    ngx_http_run_posted_requests(c);
}


static void
ngx_http_client_timeout(ngx_event_t *ev)
{
    ngx_client_http_t  *client;

    client = ev->data;

    client->error = NGX_CLIENT_HTTP_TIMEDOUT;
    ngx_http_finalize_request(client->request, NGX_HTTP_REQUEST_TIME_OUT);
    ngx_http_run_posted_requests(&client->connection);
}


void
ngx_http_client_close_request(ngx_client_http_t *client)
{
    ngx_memzero(&client->post, sizeof(ngx_client_http_post_request_t));

    if (client->request == NULL || client->closing) {
        return;
    }

    client->closing = 1;

    if (client->timeout.timer_set) {
        ngx_del_timer(&client->timeout);
    }

    if (client->in_callback) {
        /* The output filter still owns the request on this call stack. */
        client->event.handler = ngx_http_client_abort;
        ngx_post_event(&client->event, &ngx_posted_events);
        return;
    }

    if (client->event.posted) {
        ngx_delete_posted_event(&client->event);
    }

    ngx_http_client_abort(&client->event);
}


static void
ngx_http_client_abort(ngx_event_t *ev)
{
    ngx_client_http_t  *client;

    client = ev->data;

    ngx_http_finalize_request(client->request, NGX_HTTP_CLIENT_CLOSED_REQUEST);
    ngx_http_run_posted_requests(&client->connection);
}


static ngx_int_t
ngx_http_client_check_size(ngx_client_http_t *client, uint64_t body_size)
{
    ngx_int_t  rc;

    if (client->closing) {
        return NGX_ERROR;
    }

    if (client->post.check_size == NULL) {
        return NGX_OK;
    }

    client->in_callback = 1;
    rc = client->post.check_size(client->post.data, client->header_size,
                                 body_size);
    client->in_callback = 0;

    if (client->closing) {
        return NGX_ERROR;
    }

    if (rc != NGX_OK) {
        client->error = rc;
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_keyval_t *
ngx_http_client_add_header(ngx_client_http_t *client, ngx_str_t *key,
    size_t len)
{
    ngx_keyval_t  *kv;

    client->header_size += key->len + len + sizeof(": " CRLF) - 1;

    if (ngx_http_client_check_size(client, 0) != NGX_OK) {
        return NULL;
    }

    kv = ngx_array_push(&client->response.headers);
    if (kv == NULL) {
        return NULL;
    }

    kv->key.len = key->len;
    kv->key.data = ngx_pstrdup(client->pool, key);
    kv->value.len = len;
    kv->value.data = ngx_pnalloc(client->pool, len);

    if (kv->key.data == NULL || kv->value.data == NULL) {
        return NULL;
    }

    return kv;
}


static ngx_int_t
ngx_http_client_save_header(ngx_client_http_t *client, ngx_str_t *key,
    ngx_str_t *value)
{
    ngx_keyval_t  *kv;

    kv = ngx_http_client_add_header(client, key, value->len);
    if (kv == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(kv->value.data, value->data, value->len);

    return NGX_OK;
}


static ngx_int_t
ngx_http_client_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_client_header_filter;

    ngx_http_next_early_hints_filter = ngx_http_top_early_hints_filter;
    ngx_http_top_early_hints_filter = ngx_http_client_early_hints_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_client_body_filter;

    return NGX_OK;
}


static ngx_int_t
ngx_http_client_header_filter(ngx_http_request_t *r)
{
    if (r->connection->stub) {
        return ngx_http_client_header(r);
    }

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_client_early_hints_filter(ngx_http_request_t *r)
{
    if (r->connection->stub) {
        return NGX_OK;
    }

    return ngx_http_next_early_hints_filter(r);
}


static ngx_int_t
ngx_http_client_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    if (r->connection->stub) {
        return ngx_http_client_body(r, in);
    }

    return ngx_http_next_body_filter(r, in);
}


static ngx_int_t
ngx_http_client_header(ngx_http_request_t *r)
{
    u_char                    *p;
    size_t                     len;
    ngx_int_t                  rc;
    ngx_str_t                  key, value;
    ngx_uint_t                 i, status;
    ngx_keyval_t              *kv;
    ngx_list_part_t           *part;
    ngx_table_elt_t           *h;
    ngx_client_http_t         *client;
#if (NGX_HTTP_GZIP)
    ngx_http_core_loc_conf_t  *clcf;
#endif
    u_char                     num[NGX_OFF_T_LEN];

    client = ngx_http_client_from_connection(r->connection);

    r->header_sent = 1;
    status = r->headers_out.status;
    client->response.status = status;

    if (r->method == NGX_HTTP_HEAD || status == NGX_HTTP_NO_CONTENT
        || status == NGX_HTTP_NOT_MODIFIED)
    {
        r->header_only = 1;
    }

    if (status == NGX_HTTP_NO_CONTENT) {
        ngx_str_null(&r->headers_out.content_type);
        ngx_http_clear_content_length(r);
    }

    if (r->headers_out.last_modified_time != -1
        && status != NGX_HTTP_OK
        && status != NGX_HTTP_PARTIAL_CONTENT
        && status != NGX_HTTP_NOT_MODIFIED)
    {
        r->headers_out.last_modified_time = -1;
        r->headers_out.last_modified = NULL;
    }

    client->header_size = sizeof("HTTP/1.1 " CRLF CRLF) - 1;
    client->header_size += r->headers_out.status_line.len
                           ? r->headers_out.status_line.len : sizeof("200") - 1;

    if (ngx_http_client_check_size(client, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_array_init(&client->response.headers, client->pool, 8,
                       sizeof(ngx_keyval_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (r->headers_out.content_type.len) {
        ngx_str_set(&key, "Content-Type");

        len = r->headers_out.content_type.len;

        if (len == r->headers_out.content_type_len
            && r->headers_out.charset.len)
        {
            len += sizeof("; charset=") - 1 + r->headers_out.charset.len;
        }

        kv = ngx_http_client_add_header(client, &key, len);
        if (kv == NULL) {
            return NGX_ERROR;
        }

        p = ngx_cpymem(kv->value.data, r->headers_out.content_type.data,
                       r->headers_out.content_type.len);

        if (len != r->headers_out.content_type.len) {
            p = ngx_cpymem(p, "; charset=", sizeof("; charset=") - 1);
            ngx_memcpy(p, r->headers_out.charset.data,
                       r->headers_out.charset.len);

            r->headers_out.content_type = kv->value;
        }
    }

    if (r->headers_out.content_length == NULL
        && r->headers_out.content_length_n >= 0)
    {
        ngx_str_set(&key, "Content-Length");
        value.data = num;
        value.len = ngx_sprintf(num, "%O", r->headers_out.content_length_n)
                    - num;

        if (ngx_http_client_save_header(client, &key, &value) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        ngx_str_set(&key, "Last-Modified");
        len = sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1;

        kv = ngx_http_client_add_header(client, &key, len);
        if (kv == NULL) {
            return NGX_ERROR;
        }

        ngx_http_time(kv->value.data, r->headers_out.last_modified_time);
    }

#if (NGX_HTTP_GZIP)
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (r->gzip_vary && clcf->gzip_vary) {
        ngx_str_set(&key, "Vary");
        ngx_str_set(&value, "Accept-Encoding");

        if (ngx_http_client_save_header(client, &key, &value) != NGX_OK) {
            return NGX_ERROR;
        }
    }
#endif

    part = &r->headers_out.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].hash == 0) {
            continue;
        }

        if (ngx_http_client_save_header(client, &h[i].key, &h[i].value)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    if (client->post.header_handler) {
        client->in_callback = 1;
        rc = client->post.header_handler(&client->response, client->post.data);
        client->in_callback = 0;

        if (client->closing) {
            return NGX_ERROR;
        }

        if (rc == NGX_DONE) {
            r->header_only = 1;

            if (r->upstream) {
                r->upstream->buffering = 0;
            }

            return NGX_OK;
        }

        if (rc != NGX_OK) {
            client->error = rc;
            return NGX_ERROR;
        }
    }

    if (!r->header_only && r->headers_out.content_length_n >= 0
        && ngx_http_client_check_size(client, r->headers_out.content_length_n)
           != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_client_body(ngx_http_request_t *r, ngx_chain_t *in)
{
    off_t               size;
    ngx_buf_t          *b;
    ngx_int_t           rc;
    ngx_chain_t        *cl;
    ngx_client_http_t  *client;

    client = ngx_http_client_from_connection(r->connection);

    for ( /* void */; in; in = in->next) {
        size = ngx_buf_size(in->buf);

        if (size == 0) {
            continue;
        }

        if (r->header_only) {
            in->buf->pos = in->buf->last;
            in->buf->file_pos = in->buf->file_last;
            continue;
        }

        if ((uint64_t) size > NGX_MAX_SIZE_T_VALUE - client->length
            || ngx_http_client_check_size(client, client->length + size)
               != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (!ngx_buf_in_memory(in->buf)) {
            return NGX_ERROR;
        }

        if (client->post.body_handler) {
            client->in_callback = 1;
            rc = client->post.body_handler(in->buf->pos, (size_t) size,
                                           client->post.data);
            client->in_callback = 0;

            if (client->closing) {
                return NGX_ERROR;
            }

            if (rc != NGX_OK) {
                client->error = rc;
                return NGX_ERROR;
            }

        } else {
            cl = ngx_alloc_chain_link(client->pool);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            b = ngx_create_temp_buf(client->pool, (size_t) size);
            if (b == NULL) {
                return NGX_ERROR;
            }

            b->last = ngx_cpymem(b->pos, in->buf->pos, (size_t) size);

            cl->buf = b;
            cl->next = NULL;
            *client->last = cl;
            client->last = &cl->next;
        }

        client->length += size;
        r->connection->sent += size;

        in->buf->pos = in->buf->last;
        in->buf->file_pos = in->buf->file_last;
    }

    return NGX_OK;
}


void
ngx_http_client_finalize(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_connection_t    *c;
    ngx_client_http_t   *client;

    c = r->connection;
    client = ngx_http_client_from_connection(c);

    if (client->error) {
        client->rc = client->error;

    } else if (client->upstream_error) {
        client->rc = client->upstream_error;

    } else if (rc == NGX_OK && r->header_sent && !r->terminated && !c->error) {
        client->rc = NGX_OK;
    }

    client->request = NULL;
    ngx_http_free_request(r, rc);

    if (client->timeout.timer_set) {
        ngx_del_timer(&client->timeout);
    }

    ngx_close_connection(c);

    if (client->event.posted) {
        ngx_delete_posted_event(&client->event);
    }

    ngx_post_event(&client->done, &ngx_posted_events);
}


static void
ngx_http_client_complete(ngx_event_t *ev)
{
    u_char             *p;
    ngx_chain_t        *cl;
    ngx_client_http_t  *client;

    client = ev->data;

    if (client->post.handler && client->rc == NGX_OK && client->out) {

        p = ngx_pnalloc(client->pool, client->length);
        if (p == NULL) {
            client->rc = NGX_ERROR;

        } else {
            client->response.body.data = p;
            client->response.body.len = client->length;

            for (cl = client->out; cl; cl = cl->next) {
                p = ngx_cpymem(p, cl->buf->pos, cl->buf->last - cl->buf->pos);
            }
        }
    }

    if (client->response.body.data == NULL) {
        ngx_str_set(&client->response.body, "");
    }

    if (client->post.handler) {
        client->post.handler(client->rc == NGX_OK ? &client->response : NULL,
                             client->post.data, client->rc);
    }

    ngx_destroy_pool(client->pool);
}


void
ngx_http_client_reset_upstream_error(ngx_http_request_t *r)
{
    ngx_client_http_t  *client;

    client = ngx_http_client_from_connection(r->connection);
    client->upstream_error = 0;
}


void
ngx_http_client_upstream_error(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_client_http_t  *client;

    client = ngx_http_client_from_connection(r->connection);
    if (client->upstream_error) {
        return;
    }

    if (rc == NGX_HTTP_GATEWAY_TIME_OUT || rc == NGX_HTTP_REQUEST_TIME_OUT)
    {
        client->upstream_error = NGX_CLIENT_HTTP_TIMEDOUT;

    } else {
        client->upstream_error = NGX_ERROR;
    }
}


static u_char *
ngx_http_client_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char              *p;
    ngx_http_request_t  *r;
    ngx_http_log_ctx_t  *ctx;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    ctx = log->data;
    r = ctx->request;

    if (r == NULL) {
        return buf;
    }

    return r->log_handler(r, ctx->current_request, buf, len);
}


#endif
