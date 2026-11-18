
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

#if !(NGX_WIN32)
#include <resolv.h>
#endif


#define NGX_RESOLVER_UDP_SIZE   4096

#define NGX_RESOLVER_TCP_RSIZE  (2 + 65535)
#define NGX_RESOLVER_TCP_WSIZE  8192

#if !(NGX_WIN32)
/*
 * note that 2KB should be more than enough for majority of the
 * resolv.conf files out there. it also acts as a safety guard to prevent
 * abuse.
 */
#define NGX_RESOLVER_FILE_BUF_SIZE  2048
#define NGX_RESOLVER_FILE_NAME      "/etc/resolv.conf"
#endif


typedef struct {
    u_char  ident_hi;
    u_char  ident_lo;
    u_char  flags_hi;
    u_char  flags_lo;
    u_char  nqs_hi;
    u_char  nqs_lo;
    u_char  nan_hi;
    u_char  nan_lo;
    u_char  nns_hi;
    u_char  nns_lo;
    u_char  nar_hi;
    u_char  nar_lo;
} ngx_resolver_hdr_t;


typedef struct {
    u_char  type_hi;
    u_char  type_lo;
    u_char  class_hi;
    u_char  class_lo;
} ngx_resolver_qs_t;


typedef struct {
    u_char  type_hi;
    u_char  type_lo;
    u_char  class_hi;
    u_char  class_lo;
    u_char  ttl[4];
    u_char  len_hi;
    u_char  len_lo;
} ngx_resolver_an_t;


#define ngx_resolver_node(n)  ngx_rbtree_data(n, ngx_resolver_node_t, node)


#if (NGX_RESTY_EXT)

#define NGX_RESOLVER_MIN_TTL_SET   0x0002
#define NGX_RESOLVER_MAX_TTL_SET   0x0004
#define NGX_RESOLVER_NEGATIVE_SET  0x0008
#define NGX_RESOLVER_ERROR_SET     0x0010
#define NGX_RESOLVER_STALE_SET     0x0020

#define NGX_RESOLVE_NS             2
#define NGX_RESOLVE_SOA            6
#define NGX_RESOLVE_OPT            41

/* The response scanner recognizes AAAA independently of socket support. */
#if !(NGX_HAVE_INET6)
#define NGX_RESOLVE_AAAA           28
#endif


typedef struct {
    ngx_str_t                   name;
    ngx_array_t                *servers;
    ngx_array_t                *references;
} ngx_resolver_nameserver_t;


typedef struct {
    ngx_resolver_t             *resolver;
    ngx_str_t                  *names;
    ngx_uint_t                  nelts;
    ngx_uint_t                  target;
    ngx_str_t                   file;
    ngx_uint_t                  line;
    ngx_fd_t                    fd;
} ngx_resolver_reference_t;


typedef struct {
    ngx_addr_t                  addr;
    ngx_resolver_peer_t         peer;
} ngx_resolver_server_t;


typedef struct {
    ngx_uint_t                  references;
    ngx_uint_t                  tries;
    ngx_uint_t                  sequence;
    ngx_msec_t                  start;
    ngx_uint_t                  failures;
    ngx_uint_t                  failure_sequence;
} ngx_resolver_budget_t;


struct ngx_resolver_query_state_s {
    ngx_queue_t                 queue;
    ngx_event_t                 event;
    ngx_resolver_budget_t      *budget;
    ngx_int_t                   last_result;
    u_char                     *service;
    u_char                     *original_name;
    ngx_resolver_node_t        *refresh_node;
    u_char                     *address;

    unsigned                    reverse:1;
    unsigned                    resuming:1;
    unsigned                    background:1;
    unsigned                    last_valid:1;
};


typedef struct {
    ngx_rbtree_node_t           node;
    ngx_resolver_node_t        *resolver_node;
    ngx_uint_t                  qtype;

    unsigned                    active:1;
} ngx_resolver_pending_t;


struct ngx_resolver_node_state_s {
    ngx_event_t                 event;
    ngx_rbtree_t               *tree;
    ngx_queue_t                *resend_queue;
    ngx_queue_t                *expire_queue;
    ngx_resolver_pending_t      queries[2];
    time_t                      negative_valid;
    time_t                      received;
    ngx_int_t                   last_result;
    ngx_uint_t                  failure;
    ngx_uint_t                  tries;
    ngx_uint_t                  sequence;
    ngx_uint_t                  failed_sequence;
    uintptr_t                  *tried;

    unsigned                    retry:1;
    unsigned                    pending:1;
    unsigned                    started:1;
    unsigned                    restart:1;
    unsigned                    reverse:1;
};


struct ngx_resolver_cache_s {
    ngx_resolver_node_t        *stale;
    ngx_resolver_ctx_t         *refresh_ctx;
    time_t                      refresh_after;
    ngx_int_t                   error;

    unsigned                    nxdomain:1;
};


#endif


static ngx_int_t ngx_udp_connect(ngx_resolver_connection_t *rec);
static ngx_int_t ngx_tcp_connect(ngx_resolver_connection_t *rec);


static void ngx_resolver_cleanup(void *data);
static void ngx_resolver_cleanup_tree(ngx_resolver_t *r, ngx_rbtree_t *tree);
static ngx_int_t ngx_resolve_name_locked(ngx_resolver_t *r,
    ngx_resolver_ctx_t *ctx, ngx_str_t *name);
static void ngx_resolver_expire(ngx_resolver_t *r, ngx_rbtree_t *tree,
    ngx_queue_t *queue);
static ngx_int_t ngx_resolver_send_query(ngx_resolver_t *r,
    ngx_resolver_node_t *rn);
static ngx_int_t ngx_resolver_send_udp_query(ngx_resolver_t *r,
    ngx_resolver_connection_t *rec, u_char *query, u_short qlen);
static ngx_int_t ngx_resolver_send_tcp_query(ngx_resolver_t *r,
    ngx_resolver_connection_t *rec, u_char *query, u_short qlen);
static ngx_int_t ngx_resolver_create_name_query(ngx_resolver_t *r,
    ngx_resolver_node_t *rn, ngx_str_t *name);
static ngx_int_t ngx_resolver_create_srv_query(ngx_resolver_t *r,
    ngx_resolver_node_t *rn, ngx_str_t *name);
static ngx_int_t ngx_resolver_create_addr_query(ngx_resolver_t *r,
    ngx_resolver_node_t *rn, ngx_resolver_addr_t *addr);
static void ngx_resolver_resend_handler(ngx_event_t *ev);
static time_t ngx_resolver_resend(ngx_resolver_t *r, ngx_rbtree_t *tree,
    ngx_queue_t *queue);
static ngx_uint_t ngx_resolver_resend_empty(ngx_resolver_t *r);
static void ngx_resolver_udp_read(ngx_event_t *rev);
static void ngx_resolver_tcp_write(ngx_event_t *wev);
static void ngx_resolver_tcp_read(ngx_event_t *rev);
static void ngx_resolver_process_response(ngx_resolver_t *r, u_char *buf,
#if (NGX_RESTY_EXT)
    ngx_int_t scan,
#endif
    size_t n, ngx_uint_t tcp);
static void ngx_resolver_process_a(ngx_resolver_t *r, u_char *buf, size_t n,
#if (NGX_RESTY_EXT)
    ngx_int_t scan,
#endif
    ngx_uint_t ident, ngx_uint_t code, ngx_uint_t qtype,
    ngx_uint_t nan, ngx_uint_t trunc, ngx_uint_t ans);
static void ngx_resolver_process_srv(ngx_resolver_t *r, u_char *buf, size_t n,
#if (NGX_RESTY_EXT)
    ngx_int_t scan,
#endif
    ngx_uint_t ident, ngx_uint_t code, ngx_uint_t nan,
    ngx_uint_t trunc, ngx_uint_t ans);
static void ngx_resolver_process_ptr(ngx_resolver_t *r, u_char *buf, size_t n,
#if (NGX_RESTY_EXT)
    ngx_int_t scan,
#endif
    ngx_uint_t ident, ngx_uint_t code, ngx_uint_t nan);
static ngx_resolver_node_t *ngx_resolver_lookup_name(ngx_resolver_t *r,
    ngx_str_t *name, uint32_t hash);
static ngx_resolver_node_t *ngx_resolver_lookup_srv(ngx_resolver_t *r,
    ngx_str_t *name, uint32_t hash);
static ngx_resolver_node_t *ngx_resolver_lookup_addr(ngx_resolver_t *r,
    in_addr_t addr);
static void ngx_resolver_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_int_t ngx_resolver_copy(ngx_resolver_t *r, ngx_str_t *name,
    u_char *buf, u_char *src, u_char *last);
static ngx_int_t ngx_resolver_set_timeout(ngx_resolver_t *r,
    ngx_resolver_ctx_t *ctx);
static void ngx_resolver_timeout_handler(ngx_event_t *ev);
static void ngx_resolver_free_node(ngx_resolver_t *r, ngx_resolver_node_t *rn);
static void *ngx_resolver_alloc(ngx_resolver_t *r, size_t size);
static void *ngx_resolver_calloc(ngx_resolver_t *r, size_t size);
static void ngx_resolver_free(ngx_resolver_t *r, void *p);
static void ngx_resolver_free_locked(ngx_resolver_t *r, void *p);
static void *ngx_resolver_dup(ngx_resolver_t *r, void *src, size_t size);
static ngx_resolver_addr_t *ngx_resolver_export(ngx_resolver_t *r,
    ngx_resolver_node_t *rn, ngx_uint_t rotate);
static void ngx_resolver_report_srv(ngx_resolver_t *r, ngx_resolver_ctx_t *ctx);
static u_char *ngx_resolver_log_error(ngx_log_t *log, u_char *buf, size_t len);
static void ngx_resolver_resolve_srv_names(ngx_resolver_ctx_t *ctx,
    ngx_resolver_node_t *rn);
static void ngx_resolver_srv_names_handler(ngx_resolver_ctx_t *ctx);
static ngx_int_t ngx_resolver_cmp_srvs(const void *one, const void *two);

#if (NGX_RESTY_EXT)
static ngx_resolver_nameserver_t *ngx_resolver_add_nameserver(ngx_conf_t *cf,
    ngx_array_t **nameservers, ngx_str_t *name);
static char *ngx_resolver_server(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_resolver_nameserver_add_server(ngx_conf_t *cf,
    ngx_resolver_nameserver_t *ns, ngx_str_t *name, ngx_resolver_peer_t *peer);
static ngx_int_t ngx_resolver_nameserver_local(ngx_conf_t *cf,
    ngx_resolver_nameserver_t *ns, ngx_str_t *name, ngx_resolver_peer_t *peer);
static ngx_int_t ngx_resolver_init_nameserver(ngx_conf_t *cf, ngx_resolver_t *r,
    ngx_resolver_nameserver_t *ns);
static int ngx_resolver_cmp_servers(const void *one, const void *two);
static ngx_int_t ngx_resolver_configure(ngx_conf_t *cf, ngx_resolver_t *r,
    ngx_str_t *names, ngx_uint_t n, ngx_array_t **nameservers,
    ngx_str_t **values, ngx_uint_t *nelts);
static ngx_resolver_t *ngx_resolver_create_internal(ngx_conf_t *cf,
    ngx_str_t *names, ngx_uint_t n, ngx_array_t **nameservers);
static ngx_resolver_t *ngx_resolver_init_connections(ngx_conf_t *cf,
    ngx_resolver_t *r, ngx_str_t *names, ngx_uint_t n,
    ngx_resolver_nameserver_t *ns);
static time_t ngx_resolver_valid(ngx_resolver_t *r, time_t ttl);
static ngx_uint_t ngx_resolver_select_peer(ngx_resolver_t *r,
    ngx_resolver_node_t *rn, ngx_uint_t first);
static ngx_uint_t ngx_resolver_all_failed(ngx_resolver_t *r);
static ngx_int_t ngx_resolver_next(ngx_resolver_t *r, ngx_resolver_node_t *rn,
    ngx_uint_t condition, ngx_int_t code);
static ngx_int_t ngx_resolver_prepare_query(ngx_resolver_t *r,
    ngx_resolver_node_t *rn, ngx_resolver_ctx_t *ctx);
static void ngx_resolver_query_handler(ngx_event_t *ev);
static void ngx_resolver_retry_timeout_handler(ngx_event_t *ev);
static void ngx_resolver_retry_wait(ngx_resolver_t *r, ngx_resolver_node_t *rn);
static void ngx_resolver_attempt_handler(ngx_event_t *ev);
static ngx_int_t ngx_resolver_join_query(ngx_resolver_t *r,
    ngx_resolver_node_t *rn, ngx_resolver_ctx_t *ctx);
static void ngx_resolver_query_success(ngx_resolver_t *r,
    ngx_resolver_node_t *rn);
static void ngx_resolver_remove_queries(ngx_resolver_t *r,
    ngx_resolver_node_t *rn);
static ngx_int_t ngx_resolver_register_queries(ngx_resolver_t *r,
    ngx_resolver_node_t *rn);
static ngx_resolver_pending_t *ngx_resolver_lookup_pending(ngx_resolver_t *r,
    ngx_uint_t ident);
static void ngx_resolver_cleanup_contexts(ngx_resolver_t *r);
static ngx_int_t ngx_resolver_get_ident(ngx_resolver_t *r,
    ngx_uint_t *ident);
static ngx_uint_t ngx_resolver_round_complete(ngx_resolver_t *r,
    ngx_resolver_node_t *rn);
static void ngx_resolver_cache_timeout(ngx_resolver_ctx_t *ctx);
static void ngx_resolver_cache_failure(ngx_resolver_t *r,
    ngx_resolver_node_t *rn);
static void ngx_resolver_set_negative_valid(ngx_resolver_node_t *rn,
    uint32_t ttl);
static void ngx_resolver_peer_failed(ngx_resolver_t *r,
    ngx_resolver_node_t *rn);
static void ngx_resolver_peer_live(ngx_resolver_t *r, ngx_resolver_node_t *rn);
static ngx_resolver_node_t *ngx_resolver_lookup_negative(ngx_resolver_t *r,
    ngx_resolver_ctx_t *ctx, ngx_str_t *name, uint32_t hash);
static void ngx_resolver_invalidate_negative(ngx_resolver_t *r,
    ngx_resolver_node_t *rn, ngx_uint_t nxdomain);
static void ngx_resolver_receive_response(ngx_resolver_connection_t *rec,
    u_char *buf, size_t n, ngx_uint_t tcp);
static ngx_int_t ngx_resolver_process_ext_response(
    ngx_resolver_connection_t *rec, u_char *buf, size_t n, ngx_uint_t tcp,
    ngx_int_t *scan);
static ngx_int_t ngx_resolver_scan_response(u_char *buf, size_t n,
    ngx_uint_t *rcode, uint32_t *negative_ttl);
static ngx_int_t ngx_resolver_scan_failure(ngx_resolver_t *r,
    ngx_resolver_node_t *rn, u_char *buf, size_t n, ngx_int_t scan);
static ngx_int_t ngx_resolver_process_failure(ngx_resolver_t *r,
    ngx_resolver_node_t *rn, u_char *buf, size_t n, ngx_uint_t code,
    ngx_int_t scan);
static ngx_int_t ngx_resolver_store_failure(ngx_resolver_t *r,
    ngx_resolver_node_t *rn, ngx_int_t code, ngx_int_t scan);
static void ngx_resolver_report_error(ngx_resolver_ctx_t *ctx,
    ngx_int_t code, time_t valid);
static ngx_int_t ngx_resolver_skip_name(u_char *buf, size_t n, size_t *pos);
static ngx_int_t ngx_resolver_use_stale(ngx_resolver_t *r,
    ngx_resolver_node_t *rn, ngx_resolver_ctx_t *ctx, ngx_uint_t reverse);
static ngx_int_t ngx_resolver_save_stale(ngx_resolver_t *r,
    ngx_resolver_node_t *rn, ngx_uint_t reverse);
static ngx_int_t ngx_resolver_restore_stale(ngx_resolver_t *r,
    ngx_resolver_node_t *rn);
static void ngx_resolver_refresh_handler(ngx_event_t *ev);
static void ngx_resolver_refresh_done(ngx_resolver_ctx_t *ctx);
static void ngx_resolver_free_node_state(ngx_resolver_t *r,
    ngx_resolver_node_t *rn);
static ngx_resolver_cache_t *ngx_resolver_alloc_cache(ngx_resolver_t *r,
    ngx_resolver_node_t *rn);
static void ngx_resolver_free_stale(ngx_resolver_t *r,
    ngx_resolver_cache_t *cache);
static void ngx_resolver_free_cache(ngx_resolver_t *r, ngx_resolver_node_t *rn);
static void ngx_resolver_finish_query(ngx_resolver_ctx_t *ctx, ngx_int_t code);
static ngx_int_t ngx_resolver_check_budget(ngx_resolver_ctx_t *ctx);
static void ngx_resolver_charge_query(ngx_resolver_ctx_t *ctx,
    ngx_uint_t sequence);
static ngx_uint_t ngx_resolver_failure(ngx_uint_t code, ngx_uint_t rcode);
static ngx_resolver_node_t *ngx_resolver_lookup_address(ngx_resolver_t *r,
    u_char *addr, uint32_t hash, ngx_uint_t retry_mask, ngx_int_t ident);
static void ngx_resolver_rbtree_insert_addr_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_uint_t ngx_resolver_retry_mask(ngx_resolver_ctx_t *ctx);
static ngx_resolver_node_t *ngx_resolver_lookup_name_by_mask(ngx_rbtree_t *tree,
    ngx_str_t *name, uint32_t hash, ngx_uint_t retry_mask);
static ngx_resolver_node_t *ngx_resolver_lookup_reply(ngx_rbtree_t *tree,
    ngx_str_t *name, uint32_t hash, ngx_uint_t ident, ngx_uint_t qtype);
static ngx_int_t ngx_resolver_init_query_state(ngx_resolver_ctx_t *ctx);
static ngx_int_t ngx_resolver_alloc_query_state(ngx_resolver_ctx_t *ctx,
    ngx_resolver_budget_t *budget);
static void ngx_resolver_free_query_state(ngx_resolver_ctx_t *ctx);
static ngx_int_t ngx_resolver_start_query(ngx_resolver_t *r,
    ngx_resolver_node_t *rn);
#endif

#if (NGX_HAVE_INET6)
static void ngx_resolver_rbtree_insert_addr6_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_resolver_node_t *ngx_resolver_lookup_addr6(ngx_resolver_t *r,
    struct in6_addr *addr, uint32_t hash);
#endif


#if (NGX_RESTY_EXT)

static ngx_uint_t  ngx_resolver_sequence;


static ngx_conf_bitmask_t  ngx_resolver_next_nameserver_masks[] = {
    { ngx_string("error"), NGX_RESOLVER_FT_ERROR },
    { ngx_string("timeout"), NGX_RESOLVER_FT_TIMEOUT },
    { ngx_string("invalid_response"), NGX_RESOLVER_FT_INVALID_RESPONSE },
    { ngx_string("nodata"), NGX_RESOLVER_FT_NODATA },
    { ngx_string("rcode_formerr"), NGX_RESOLVER_FT_FORMERR },
    { ngx_string("rcode_servfail"), NGX_RESOLVER_FT_SERVFAIL },
    { ngx_string("rcode_nxdomain"), NGX_RESOLVER_FT_NXDOMAIN },
    { ngx_string("rcode_notimp"), NGX_RESOLVER_FT_NOTIMP },
    { ngx_string("rcode_refused"), NGX_RESOLVER_FT_REFUSED },
    { ngx_string("off"), NGX_RESOLVER_FT_OFF },
    { ngx_null_string, 0 }
};

#endif


#if !(NGX_WIN32)
static ngx_int_t
ngx_resolver_read_resolv_conf(ngx_conf_t *cf, ngx_resolver_t *r, u_char *path,
    size_t path_len)
{
    ngx_url_t                        u;
    ngx_resolver_connection_t       *rec;
    ngx_fd_t                         fd;
    ngx_file_t                       file;
    u_char                           buf[NGX_RESOLVER_FILE_BUF_SIZE];
    u_char                           ipv6_buf[NGX_INET6_ADDRSTRLEN];
    ngx_uint_t                       address = 0, j, total = 0;
    ssize_t                          n, i;
    enum {
        sw_nameserver,
        sw_spaces,
        sw_address,
        sw_skip
    } state;

    file.name.data = path;
    file.name.len = path_len;

    if (ngx_conf_full_name(cf->cycle, &file.name, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    fd = ngx_open_file(file.name.data, NGX_FILE_RDONLY,
                       NGX_FILE_OPEN, 0);

    if (fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_open_file_n " \"%s\" failed", file.name.data);

        return NGX_ERROR;
    }

    ngx_memzero(&file, sizeof(ngx_file_t));

    file.fd = fd;
    file.log = cf->log;

    state = sw_nameserver;

    n = ngx_read_file(&file, buf, NGX_RESOLVER_FILE_BUF_SIZE, 0);

    if (n == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_ALERT, cf, ngx_errno,
                           ngx_read_file_n " \"%s\" failed", file.name.data);
    }

    if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_ALERT, cf, ngx_errno,
                           ngx_close_file_n " \"%s\" failed", file.name.data);
    }

    if (n == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (n == 0) {
        return NGX_OK;
    }

    for (i = 0; i < n && total < MAXNS; /* void */) {
        if (state != sw_address && (buf[i] == '#' || buf[i] == ';')) {
            state = sw_skip;
        }

        switch (state) {

        case sw_nameserver:

            if ((size_t) n - i >= sizeof("nameserver") - 1
                && ngx_memcmp(buf + i, "nameserver",
                              sizeof("nameserver") - 1) == 0)
            {
                state = sw_spaces;
                i += sizeof("nameserver") - 1;

                continue;
            }

            break;

        case sw_spaces:
            if (buf[i] == CR || buf[i] == LF) {
                state = sw_nameserver;
                break;
            }

            if (buf[i] != '\t' && buf[i] != ' ') {
                address = i;
                state = sw_address;
                continue;
            }

            break;

        case sw_address:

            if (buf[i] == ' ' || buf[i] == '\t'
                || buf[i] == '#' || buf[i] == ';'
                || buf[i] == CR || buf[i] == LF || i == n - 1)
            {
                state = (buf[i] == CR || buf[i] == LF) ? sw_nameserver : sw_skip;

                ngx_memzero(&u, sizeof(ngx_url_t));

                u.url.data = buf + address;

                if (i == n - 1 && buf[i] != CR && buf[i] != LF
                    && buf[i] != ' ' && buf[i] != '\t'
                    && buf[i] != '#' && buf[i] != ';')
                {
                    u.url.len = n - address;

                } else {
                    u.url.len = i - address;
                }

                u.default_port = 53;

                /* IPv6? */
                if (ngx_strlchr(u.url.data, u.url.data + u.url.len,
                                ':') != NULL)
                {
                    if (ngx_strlchr(u.url.data, u.url.data + u.url.len,
                                    '%') != NULL)
                    {
                        ngx_conf_log_error(NGX_LOG_INFO, cf, 0,
                                           "ignoring IPv6 resolver address"
                                           " with zone ID: \"%V\"", &u.url);

                        break;
                    }

                    if (u.url.len + 2 > sizeof(ipv6_buf)) {
                        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                           "IPv6 resolver address is too long:"
                                           " \"%V\"", &u.url);

                        return NGX_ERROR;
                    }

                    ipv6_buf[0] = '[';
                    ngx_memcpy(ipv6_buf + 1, u.url.data, u.url.len);
                    ipv6_buf[u.url.len + 1] = ']';

                    u.url.data = ipv6_buf;
                    u.url.len = u.url.len + 2;
                }

                if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
                    if (u.err) {
                        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                           "%s in resolver \"%V\"",
                                           u.err, &u.url);
                    }

                    return NGX_ERROR;
                }

                rec = ngx_array_push_n(&r->connections, u.naddrs);
                if (rec == NULL) {
                    return NGX_ERROR;
                }

                ngx_memzero(rec, u.naddrs * sizeof(ngx_resolver_connection_t));

                for (j = 0; j < u.naddrs; j++) {
                    rec[j].sockaddr = u.addrs[j].sockaddr;
                    rec[j].socklen = u.addrs[j].socklen;
                    rec[j].server = u.addrs[j].name;
                    rec[j].resolver = r;
                }

                total++;

#if (NGX_DEBUG)
                /*
                 * logs with level below NGX_LOG_NOTICE will not be printed
                 * in this early phase
                 */
                ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                                   "parsed a resolver: \"%V\"", &u.url);
#endif
            }

            break;

        case sw_skip:
            if (buf[i] == CR || buf[i] == LF) {
                state = sw_nameserver;
            }

            break;
        }

        i++;
    }

    return NGX_OK;
}
#endif


#if (NGX_RESTY_EXT)

ngx_resolver_t *
ngx_resolver_create(ngx_conf_t *cf, ngx_str_t *names, ngx_uint_t n)
{
    return ngx_resolver_create_internal(cf, names, n, NULL);
}


ngx_resolver_t *
ngx_resolver_create_conf(ngx_conf_t *cf, ngx_str_t *names, ngx_uint_t n,
    ngx_array_t **nameservers)
{
    return ngx_resolver_create_internal(cf, names, n, nameservers);
}


static ngx_resolver_t *
ngx_resolver_create_internal(ngx_conf_t *cf, ngx_str_t *names, ngx_uint_t n,
    ngx_array_t **nameservers)

#else

ngx_resolver_t *
ngx_resolver_create(ngx_conf_t *cf, ngx_str_t *names, ngx_uint_t n)

#endif

{
#if (NGX_RESTY_EXT)
    ngx_int_t            rc;
    ngx_resolver_t      *r;
    ngx_pool_cleanup_t  *cln;
#else
    ngx_str_t                   s;
    ngx_url_t                   u;
    ngx_uint_t                  i, j;
    ngx_resolver_t             *r;
    ngx_pool_cleanup_t         *cln;
    ngx_resolver_connection_t  *rec;
#endif

    r = ngx_pcalloc(cf->pool, sizeof(ngx_resolver_t));
    if (r == NULL) {
        return NULL;
    }

    r->event = ngx_pcalloc(cf->pool, sizeof(ngx_event_t));
    if (r->event == NULL) {
        return NULL;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_resolver_cleanup;
    cln->data = r;

    r->ipv4 = 1;

#if (NGX_RESTY_EXT)
    ngx_rbtree_init(&r->queries, &r->queries_sentinel,
                    ngx_rbtree_insert_value);
    ngx_queue_init(&r->contexts);
#endif

    ngx_rbtree_init(&r->name_rbtree, &r->name_sentinel,
                    ngx_resolver_rbtree_insert_value);

    ngx_rbtree_init(&r->srv_rbtree, &r->srv_sentinel,
                    ngx_resolver_rbtree_insert_value);

#if (NGX_RESTY_EXT)
    ngx_rbtree_init(&r->addr_rbtree, &r->addr_sentinel,
                    ngx_resolver_rbtree_insert_addr_value);
#else
    ngx_rbtree_init(&r->addr_rbtree, &r->addr_sentinel,
                    ngx_rbtree_insert_value);
#endif

    ngx_queue_init(&r->name_resend_queue);
    ngx_queue_init(&r->srv_resend_queue);
    ngx_queue_init(&r->addr_resend_queue);

    ngx_queue_init(&r->name_expire_queue);
    ngx_queue_init(&r->srv_expire_queue);
    ngx_queue_init(&r->addr_expire_queue);

#if (NGX_HAVE_INET6)
    r->ipv6 = 1;

    ngx_rbtree_init(&r->addr6_rbtree, &r->addr6_sentinel,
                    ngx_resolver_rbtree_insert_addr6_value);

    ngx_queue_init(&r->addr6_resend_queue);

    ngx_queue_init(&r->addr6_expire_queue);
#endif

    r->event->handler = ngx_resolver_resend_handler;
    r->event->data = r;
    r->event->log = &cf->cycle->new_log;
    r->event->cancelable = 1;
    r->ident = -1;

    r->resend_timeout = 5;
    r->tcp_timeout = 5;
    r->expire = 30;
    r->valid = 0;

    r->log = &cf->cycle->new_log;
    r->log_level = NGX_LOG_ERR;

#if (NGX_RESTY_EXT)

    rc = ngx_resolver_configure(cf, r, names, n, nameservers, &names, &n);

    if (rc == NGX_DONE) {
        return r;
    }

    if (rc != NGX_OK) {
        return NULL;
    }

    return ngx_resolver_init_connections(cf, r, names, n, NULL);
}


static ngx_resolver_t *
ngx_resolver_init_connections(ngx_conf_t *cf, ngx_resolver_t *r,
    ngx_str_t *names, ngx_uint_t n, ngx_resolver_nameserver_t *ns)
{
    ngx_str_t                   s;
    ngx_url_t                   u;
    ngx_uint_t                  i, j;
    ngx_resolver_connection_t  *rec;

#endif

    if (n) {
        if (ngx_array_init(&r->connections, cf->pool, n,
                           sizeof(ngx_resolver_connection_t))
            != NGX_OK)
        {
            return NULL;
        }
    }

    for (i = 0; i < n; i++) {
        if (ngx_strncmp(names[i].data, "valid=", 6) == 0) {
            s.len = names[i].len - 6;
            s.data = names[i].data + 6;

            r->valid = ngx_parse_time(&s, 1);

            if (r->valid == (time_t) NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid parameter: %V", &names[i]);
                return NULL;
            }

            continue;
        }

        if (ngx_strncmp(names[i].data, "ipv4=", 5) == 0) {

            if (ngx_strcmp(&names[i].data[5], "on") == 0) {
                r->ipv4 = 1;

            } else if (ngx_strcmp(&names[i].data[5], "off") == 0) {
                r->ipv4 = 0;

            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid parameter: %V", &names[i]);
                return NULL;
            }

            continue;
        }

        if (ngx_strncmp(names[i].data, "ipv6=", 5) == 0) {

            if (ngx_strcmp(&names[i].data[5], "on") == 0) {
#if (NGX_HAVE_INET6)
                r->ipv6 = 1;
#else
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "no ipv6 support but \"%V\" in resolver",
                                   &names[i]);
                return NULL;
#endif

            } else if (ngx_strcmp(&names[i].data[5], "off") == 0) {
#if (NGX_HAVE_INET6)
                r->ipv6 = 0;
#endif

            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid parameter: %V", &names[i]);
                return NULL;
            }

            continue;
        }

#if !(NGX_WIN32)
        if (ngx_strncmp(names[i].data, "local=", 6) == 0) {

            if (ngx_strcmp(&names[i].data[6], "on") == 0) {
                if (ngx_resolver_read_resolv_conf(cf, r,
                                                  (u_char *)
                                                  NGX_RESOLVER_FILE_NAME,
                                                  sizeof(NGX_RESOLVER_FILE_NAME)
                                                  - 1)
                    != NGX_OK)
                {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "unable to parse local resolver");
                    return NULL;
                }

            } else if (ngx_strcmp(&names[i].data[6], "off") != 0) {
                if (ngx_resolver_read_resolv_conf(cf, r,
                                                  &names[i].data[6],
                                                  names[i].len - 6)
                    != NGX_OK)
                {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "unable to parse local resolver");
                    return NULL;
                }

            }

            continue;
        }
#endif

        ngx_memzero(&u, sizeof(ngx_url_t));

        u.url = names[i];
        u.default_port = 53;

        if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
            if (u.err) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "%s in resolver \"%V\"",
                                   u.err, &u.url);
            }

            return NULL;
        }

        rec = ngx_array_push_n(&r->connections, u.naddrs);
        if (rec == NULL) {
            return NULL;
        }

        ngx_memzero(rec, u.naddrs * sizeof(ngx_resolver_connection_t));

        for (j = 0; j < u.naddrs; j++) {
            rec[j].sockaddr = u.addrs[j].sockaddr;
            rec[j].socklen = u.addrs[j].socklen;
            rec[j].server = u.addrs[j].name;
            rec[j].resolver = r;
        }
    }

#if (NGX_HAVE_INET6)
    if (r->ipv4 + r->ipv6 == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"ipv4\" and \"ipv6\" cannot both be \"off\"");
        return NULL;
    }
#endif

#if (NGX_RESTY_EXT)

    if (ns != NULL) {
        if (ngx_resolver_init_nameserver(cf, r, ns) != NGX_OK) {
            return NULL;
        }
    }

#endif

    if (n && r->connections.nelts == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "no name servers defined");
        return NULL;
    }

    return r;
}


static void
ngx_resolver_cleanup(void *data)
{
    ngx_resolver_t  *r = data;

    ngx_uint_t                  i;
    ngx_resolver_connection_t  *rec;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "cleanup resolver");

#if (NGX_RESTY_EXT)
    ngx_resolver_cleanup_contexts(r);
#endif

    ngx_resolver_cleanup_tree(r, &r->name_rbtree);

    ngx_resolver_cleanup_tree(r, &r->srv_rbtree);

    ngx_resolver_cleanup_tree(r, &r->addr_rbtree);

#if (NGX_HAVE_INET6)
    ngx_resolver_cleanup_tree(r, &r->addr6_rbtree);
#endif

    if (r->event->timer_set) {
        ngx_del_timer(r->event);
    }

    rec = r->connections.elts;

    for (i = 0; i < r->connections.nelts; i++) {
        if (rec[i].udp) {
            ngx_close_connection(rec[i].udp);
        }

        if (rec[i].tcp) {
            ngx_close_connection(rec[i].tcp);
        }

        if (rec[i].read_buf) {
            ngx_resolver_free(r, rec[i].read_buf->start);
            ngx_resolver_free(r, rec[i].read_buf);
        }

        if (rec[i].write_buf) {
            ngx_resolver_free(r, rec[i].write_buf->start);
            ngx_resolver_free(r, rec[i].write_buf);
        }
    }
}


static void
ngx_resolver_cleanup_tree(ngx_resolver_t *r, ngx_rbtree_t *tree)
{
    ngx_resolver_ctx_t   *ctx, *next;
    ngx_resolver_node_t  *rn;

    while (tree->root != tree->sentinel) {

        rn = ngx_resolver_node(ngx_rbtree_min(tree->root, tree->sentinel));

        ngx_queue_remove(&rn->queue);

        for (ctx = rn->waiting; ctx; ctx = next) {
            next = ctx->next;

            if (ctx->event) {
                if (ctx->event->timer_set) {
                    ngx_del_timer(ctx->event);
                }

                ngx_resolver_free(r, ctx->event);
            }

#if (NGX_RESTY_EXT)
            ngx_resolver_free_query_state(ctx);
#endif

            ngx_resolver_free(r, ctx);
        }

        ngx_rbtree_delete(tree, &rn->node);

        ngx_resolver_free_node(r, rn);
    }
}


ngx_resolver_ctx_t *
ngx_resolve_start(ngx_resolver_t *r, ngx_resolver_ctx_t *temp)
{
    in_addr_t            addr;
    ngx_resolver_ctx_t  *ctx;

#if (NGX_RESTY_EXT)
    ngx_resolver_t      *retry;

    retry = NULL;

    if (r->owner) {
        retry = r;
        r = r->owner;
    }
#endif

    if (temp) {
        addr = ngx_inet_addr(temp->name.data, temp->name.len);

        if (addr != INADDR_NONE) {
            temp->resolver = r;
            temp->state = NGX_OK;
            temp->naddrs = 1;
            temp->addrs = &temp->addr;
            temp->addr.sockaddr = (struct sockaddr *) &temp->sin;
            temp->addr.socklen = sizeof(struct sockaddr_in);
            ngx_memzero(&temp->sin, sizeof(struct sockaddr_in));
            temp->sin.sin_family = AF_INET;
            temp->sin.sin_addr.s_addr = addr;
            temp->quick = 1;

            return temp;
        }
    }

    if (r->connections.nelts == 0) {
        return NGX_NO_RESOLVER;
    }

    ctx = ngx_resolver_calloc(r, sizeof(ngx_resolver_ctx_t));

    if (ctx) {
        ctx->resolver = r;

#if (NGX_RESTY_EXT)
        ctx->retry = retry;
#endif
    }

    return ctx;
}


ngx_int_t
ngx_resolve_name(ngx_resolver_ctx_t *ctx)
{
    size_t           slen;
    ngx_int_t        rc;
    ngx_str_t        name;
    ngx_resolver_t  *r;

    r = ctx->resolver;

    if (ctx->name.len > 0 && ctx->name.data[ctx->name.len - 1] == '.') {
        ctx->name.len--;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, r->log, 0,
                   "resolve: \"%V\"", &ctx->name);

    if (ctx->quick) {
        ctx->handler(ctx);
        return NGX_OK;
    }

#if (NGX_RESTY_EXT)

    if (ngx_resolver_init_query_state(ctx) != NGX_OK) {
        goto failed;
    }

#endif

    if (ctx->service.len) {
        slen = ctx->service.len;

        if (ngx_strlchr(ctx->service.data,
                        ctx->service.data + ctx->service.len, '.')
            == NULL)
        {
            slen += sizeof("_._tcp") - 1;
        }

        name.len = slen + 1 + ctx->name.len;

        name.data = ngx_resolver_alloc(r, name.len);
        if (name.data == NULL) {
            goto failed;
        }

        if (slen == ctx->service.len) {
            ngx_sprintf(name.data, "%V.%V", &ctx->service, &ctx->name);

        } else {
            ngx_sprintf(name.data, "_%V._tcp.%V", &ctx->service, &ctx->name);
        }

        /* lock name mutex */

        rc = ngx_resolve_name_locked(r, ctx, &name);

        ngx_resolver_free(r, name.data);

    } else {
        /* lock name mutex */

        rc = ngx_resolve_name_locked(r, ctx, &ctx->name);
    }

    if (rc == NGX_OK) {
        return NGX_OK;
    }

    /* unlock name mutex */

    if (rc == NGX_AGAIN) {
        return NGX_OK;
    }

    /* NGX_ERROR */

    if (ctx->event) {
        ngx_resolver_free(r, ctx->event);
    }

failed:

#if (NGX_RESTY_EXT)
    ngx_resolver_free_query_state(ctx);
#endif

    ngx_resolver_free(r, ctx);

    return NGX_ERROR;
}


void
ngx_resolve_name_done(ngx_resolver_ctx_t *ctx)
{
    ngx_uint_t            i;
    ngx_resolver_t       *r;
    ngx_resolver_ctx_t   *w, **p;
    ngx_resolver_node_t  *rn;

    r = ctx->resolver;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, r->log, 0,
                   "resolve name done: %i", ctx->state);

    if (ctx->quick) {
        return;
    }

    if (ctx->event && ctx->event->timer_set) {
        ngx_del_timer(ctx->event);
    }

    /* lock name mutex */

    if (ctx->nsrvs) {
        for (i = 0; i < ctx->nsrvs; i++) {
            if (ctx->srvs[i].ctx) {
                ngx_resolve_name_done(ctx->srvs[i].ctx);
            }

            if (ctx->srvs[i].addrs) {
                ngx_resolver_free(r, ctx->srvs[i].addrs->sockaddr);
                ngx_resolver_free(r, ctx->srvs[i].addrs);
            }

            ngx_resolver_free(r, ctx->srvs[i].name.data);
        }

        ngx_resolver_free(r, ctx->srvs);
    }

    if (ctx->state == NGX_AGAIN || ctx->state == NGX_RESOLVE_TIMEDOUT) {

        rn = ctx->node;

        if (rn) {
            p = &rn->waiting;
            w = rn->waiting;

            while (w) {
                if (w == ctx) {
                    *p = w->next;

                    goto done;
                }

                p = &w->next;
                w = w->next;
            }

            ngx_log_error(NGX_LOG_ALERT, r->log, 0,
                          "could not cancel %V resolving", &ctx->name);
        }
    }

done:

    if (ctx->service.len) {
        ngx_resolver_expire(r, &r->srv_rbtree, &r->srv_expire_queue);

    } else {
        ngx_resolver_expire(r, &r->name_rbtree, &r->name_expire_queue);
    }

    /* unlock name mutex */

    /* lock alloc mutex */

    if (ctx->event) {
        ngx_resolver_free_locked(r, ctx->event);
    }

#if (NGX_RESTY_EXT)
    ngx_resolver_free_query_state(ctx);
#endif

    ngx_resolver_free_locked(r, ctx);

    /* unlock alloc mutex */

    if (r->event->timer_set && ngx_resolver_resend_empty(r)) {
        ngx_del_timer(r->event);
    }
}


static ngx_int_t
ngx_resolve_name_locked(ngx_resolver_t *r, ngx_resolver_ctx_t *ctx,
    ngx_str_t *name)
{
    uint32_t              hash;
    ngx_int_t             rc;
    ngx_str_t             cname;
    ngx_uint_t            i, naddrs;
    ngx_queue_t          *resend_queue, *expire_queue;
    ngx_rbtree_t         *tree;
    ngx_resolver_ctx_t   *next, *last;
    ngx_resolver_addr_t  *addrs;
    ngx_resolver_node_t  *rn;

    ngx_strlow(name->data, name->data, name->len);

    hash = ngx_crc32_short(name->data, name->len);

#if (NGX_RESTY_EXT)

    rn = ngx_resolver_lookup_negative(r, ctx, name, hash);
    if (rn) {
        ngx_resolver_report_error(ctx, NGX_RESOLVE_NXDOMAIN, rn->valid);
        return NGX_OK;
    }

#endif

    if (ctx->service.len) {

#if (NGX_RESTY_EXT)
        if (r->retry_mask_lookup || ngx_resolver_retry_mask(ctx)) {
            rn = ngx_resolver_lookup_name_by_mask(&r->srv_rbtree, name, hash,
                                                  ngx_resolver_retry_mask(ctx));

        } else {
            rn = ngx_resolver_lookup_srv(r, name, hash);
        }
#else
        rn = ngx_resolver_lookup_srv(r, name, hash);
#endif

        tree = &r->srv_rbtree;
        resend_queue = &r->srv_resend_queue;
        expire_queue = &r->srv_expire_queue;

    } else {

#if (NGX_RESTY_EXT)
        if (r->retry_mask_lookup || ngx_resolver_retry_mask(ctx)) {
            rn = ngx_resolver_lookup_name_by_mask(&r->name_rbtree, name, hash,
                                                  ngx_resolver_retry_mask(ctx));

        } else {
            rn = ngx_resolver_lookup_name(r, name, hash);
        }
#else
        rn = ngx_resolver_lookup_name(r, name, hash);
#endif

        tree = &r->name_rbtree;
        resend_queue = &r->name_resend_queue;
        expire_queue = &r->name_expire_queue;
    }

#if (NGX_RESTY_EXT)

    if (rn) {
        rc = ngx_resolver_use_stale(r, rn, ctx, 0);
        if (rc != NGX_DECLINED) {
            return rc;
        }
    }

#endif

    if (rn) {

        /* ctx can be a list after NGX_RESOLVE_CNAME */
        for (last = ctx; last->next; last = last->next);

        if (rn->valid >= ngx_time()) {

            ngx_log_debug0(NGX_LOG_DEBUG_CORE, r->log, 0, "resolve cached");

            ngx_queue_remove(&rn->queue);

            rn->expire = ngx_time() + r->expire;

            ngx_queue_insert_head(expire_queue, &rn->queue);

#if (NGX_RESTY_EXT)
            if (rn->cache && rn->cache->error) {
                ngx_resolver_report_error(ctx, rn->cache->error, rn->valid);
                return NGX_OK;
            }
#endif

            naddrs = (rn->naddrs == (u_short) -1) ? 0 : rn->naddrs;
#if (NGX_HAVE_INET6)
            naddrs += (rn->naddrs6 == (u_short) -1) ? 0 : rn->naddrs6;
#endif

            if (naddrs) {

                if (naddrs == 1 && rn->naddrs == 1) {
                    addrs = NULL;

                } else {
                    addrs = ngx_resolver_export(r, rn, 1);
                    if (addrs == NULL) {
                        return NGX_ERROR;
                    }
                }

                last->next = rn->waiting;
                rn->waiting = NULL;

                /* unlock name mutex */

                do {
                    ctx->state = NGX_OK;
                    ctx->valid = rn->valid;
                    ctx->naddrs = naddrs;

                    if (addrs == NULL) {
                        ctx->addrs = &ctx->addr;
                        ctx->addr.sockaddr = (struct sockaddr *) &ctx->sin;
                        ctx->addr.socklen = sizeof(struct sockaddr_in);
                        ngx_memzero(&ctx->sin, sizeof(struct sockaddr_in));
                        ctx->sin.sin_family = AF_INET;
                        ctx->sin.sin_addr.s_addr = rn->u.addr;

                    } else {
                        ctx->addrs = addrs;
                    }

                    next = ctx->next;

                    ctx->handler(ctx);

                    ctx = next;
                } while (ctx);

                if (addrs != NULL) {
                    ngx_resolver_free(r, addrs->sockaddr);
                    ngx_resolver_free(r, addrs);
                }

                return NGX_OK;
            }

            if (rn->nsrvs) {
                last->next = rn->waiting;
                rn->waiting = NULL;

                /* unlock name mutex */

                do {
                    next = ctx->next;

                    ngx_resolver_resolve_srv_names(ctx, rn);

                    ctx = next;
                } while (ctx);

                return NGX_OK;
            }

            /* NGX_RESOLVE_CNAME */

            if (ctx->recursion++ < NGX_RESOLVER_MAX_RECURSION) {

                cname.len = rn->cnlen;
                cname.data = rn->u.cname;

                return ngx_resolve_name_locked(r, ctx, &cname);
            }

            last->next = rn->waiting;
            rn->waiting = NULL;

            /* unlock name mutex */

            do {
                ctx->state = NGX_RESOLVE_NXDOMAIN;
                ctx->valid = ngx_time() + (r->valid ? r->valid : 10);
                next = ctx->next;

                ctx->handler(ctx);

                ctx = next;
            } while (ctx);

            return NGX_OK;
        }

        if (rn->waiting) {
            if (ngx_resolver_set_timeout(r, ctx) != NGX_OK) {
                return NGX_ERROR;
            }

#if (NGX_RESTY_EXT)
            if (ngx_resolver_join_query(r, rn, ctx) != NGX_OK) {
                return NGX_ERROR;
            }
#endif

            last->next = rn->waiting;
            rn->waiting = ctx;
            ctx->state = NGX_AGAIN;
            ctx->async = 1;

            do {
                ctx->node = rn;
                ctx = ctx->next;
            } while (ctx);

#if (NGX_RESTY_EXT)
            if (rn->state && rn->state->pending) {
                ngx_resolver_retry_wait(r, rn);
            }
#endif

            return NGX_AGAIN;
        }

#if (NGX_RESTY_EXT)

        if (ngx_resolver_save_stale(r, rn, 0) != NGX_OK) {
            return NGX_ERROR;
        }

#endif

        ngx_queue_remove(&rn->queue);

        /* lock alloc mutex */

        if (rn->query) {
            ngx_resolver_free_locked(r, rn->query);
            rn->query = NULL;
#if (NGX_HAVE_INET6)
            rn->query6 = NULL;
#endif
        }

        if (rn->cnlen) {
            ngx_resolver_free_locked(r, rn->u.cname);
        }

        if (rn->naddrs > 1 && rn->naddrs != (u_short) -1) {
            ngx_resolver_free_locked(r, rn->u.addrs);
        }

#if (NGX_HAVE_INET6)
        if (rn->naddrs6 > 1 && rn->naddrs6 != (u_short) -1) {
            ngx_resolver_free_locked(r, rn->u6.addrs6);
        }
#endif

        if (rn->nsrvs) {
            for (i = 0; i < (ngx_uint_t) rn->nsrvs; i++) {
                if (rn->u.srvs[i].name.data) {
                    ngx_resolver_free_locked(r, rn->u.srvs[i].name.data);
                }
            }

            ngx_resolver_free_locked(r, rn->u.srvs);
        }

        /* unlock alloc mutex */

    } else {

        rn = ngx_resolver_alloc(r, sizeof(ngx_resolver_node_t));
        if (rn == NULL) {
            return NGX_ERROR;
        }

        rn->name = ngx_resolver_dup(r, name->data, name->len);
        if (rn->name == NULL) {
            ngx_resolver_free(r, rn);
            return NGX_ERROR;
        }

        rn->node.key = hash;
        rn->nlen = (u_short) name->len;
        rn->query = NULL;
#if (NGX_HAVE_INET6)
        rn->query6 = NULL;
#endif

#if (NGX_RESTY_EXT)
        rn->state = NULL;
        rn->cache = NULL;
        rn->retry_mask = ngx_resolver_retry_mask(ctx);

        if (rn->retry_mask) {
            r->retry_mask_lookup = 1;
        }
#endif

        ngx_rbtree_insert(tree, &rn->node);
    }

    if (ctx->service.len) {
        rc = ngx_resolver_create_srv_query(r, rn, name);

    } else {
        rc = ngx_resolver_create_name_query(r, rn, name);
    }

    if (rc == NGX_ERROR) {
        goto failed;
    }

    if (rc == NGX_DECLINED) {
        ngx_rbtree_delete(tree, &rn->node);

#if (NGX_RESTY_EXT)
        ngx_resolver_free_node_state(r, rn);
        ngx_resolver_free_cache(r, rn);
#endif

        ngx_resolver_free(r, rn->query);
        ngx_resolver_free(r, rn->name);
        ngx_resolver_free(r, rn);

        do {
            ctx->state = NGX_RESOLVE_NXDOMAIN;
            next = ctx->next;

            ctx->handler(ctx);

            ctx = next;
        } while (ctx);

        return NGX_OK;
    }

#if (NGX_RESTY_EXT)

    if (ngx_resolver_prepare_query(r, rn, ctx) != NGX_OK) {
        goto failed;
    }

#endif

    rn->last_connection = r->last_connection++;
    if (r->last_connection == r->connections.nelts) {
        r->last_connection = 0;
    }

#if (NGX_RESTY_EXT)

    if (r->nameserver) {
        rn->last_connection = ngx_resolver_select_peer(r, rn, 0);
    }

#endif

    rn->naddrs = r->ipv4 ? (u_short) -1 : 0;
    rn->tcp = 0;
#if (NGX_HAVE_INET6)
    rn->naddrs6 = r->ipv6 ? (u_short) -1 : 0;
    rn->tcp6 = 0;
#endif
    rn->nsrvs = 0;

    if (ngx_resolver_send_query(r, rn) != NGX_OK) {

        /* immediately retry once on failure */

        rn->last_connection++;
        if (rn->last_connection == r->connections.nelts) {
            rn->last_connection = 0;
        }

        (void) ngx_resolver_send_query(r, rn);
    }

    if (ngx_resolver_set_timeout(r, ctx) != NGX_OK) {
        goto failed;
    }

    if (ngx_resolver_resend_empty(r)) {
        ngx_add_timer(r->event, (ngx_msec_t) (r->resend_timeout * 1000));
    }

    rn->expire = ngx_time() + r->resend_timeout;

    ngx_queue_insert_head(resend_queue, &rn->queue);

    rn->code = 0;
    rn->cnlen = 0;
    rn->valid = 0;
    rn->ttl = NGX_MAX_UINT32_VALUE;
    rn->waiting = ctx;

    ctx->state = NGX_AGAIN;
    ctx->async = 1;

    do {
        ctx->node = rn;
        ctx = ctx->next;
    } while (ctx);

#if (NGX_RESTY_EXT)

    if (rn->state && rn->state->retry) {
        (void) ngx_resolver_start_query(r, rn);
    }

#endif

    return NGX_AGAIN;

failed:

    ngx_rbtree_delete(tree, &rn->node);

    if (rn->query) {
        ngx_resolver_free(r, rn->query);
    }

    ngx_resolver_free(r, rn->name);

#if (NGX_RESTY_EXT)
    ngx_resolver_free_node_state(r, rn);
    ngx_resolver_free_cache(r, rn);
#endif

    ngx_resolver_free(r, rn);

    return NGX_ERROR;
}


ngx_int_t
ngx_resolve_addr(ngx_resolver_ctx_t *ctx)
{
    u_char               *name;
    in_addr_t             addr;
#if (NGX_RESTY_EXT)
    ngx_int_t             rc;
#endif
    ngx_queue_t          *resend_queue, *expire_queue;
    ngx_rbtree_t         *tree;
    ngx_resolver_t       *r;
    struct sockaddr_in   *sin;
    ngx_resolver_node_t  *rn;
#if (NGX_HAVE_INET6)
    uint32_t              hash;
    struct sockaddr_in6  *sin6;
#endif

#if (NGX_SUPPRESS_WARN)
    addr = 0;
#if (NGX_HAVE_INET6)
    hash = 0;
    sin6 = NULL;
#endif
#endif

    r = ctx->resolver;

#if (NGX_RESTY_EXT)

    if (ngx_resolver_init_query_state(ctx) != NGX_OK) {
        ngx_resolver_free(r, ctx);
        return NGX_ERROR;
    }

    if (ctx->query_state) {
        ctx->query_state->reverse = 1;
    }

#endif

    switch (ctx->addr.sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) ctx->addr.sockaddr;
        hash = ngx_crc32_short(sin6->sin6_addr.s6_addr, 16);

        /* lock addr mutex */

#if (NGX_RESTY_EXT)
        if (r->retry_mask_lookup || ngx_resolver_retry_mask(ctx)) {
            rn = ngx_resolver_lookup_address(r, sin6->sin6_addr.s6_addr,
                                             hash, ngx_resolver_retry_mask(ctx),
                                             -1);

        } else {
            rn = ngx_resolver_lookup_addr6(r, &sin6->sin6_addr, hash);
        }
#else
        rn = ngx_resolver_lookup_addr6(r, &sin6->sin6_addr, hash);
#endif

        tree = &r->addr6_rbtree;
        resend_queue = &r->addr6_resend_queue;
        expire_queue = &r->addr6_expire_queue;

        break;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) ctx->addr.sockaddr;
        addr = ntohl(sin->sin_addr.s_addr);

        /* lock addr mutex */

#if (NGX_RESTY_EXT)
        if (r->retry_mask_lookup || ngx_resolver_retry_mask(ctx)) {
            rn = ngx_resolver_lookup_address(r, NULL, addr,
                                             ngx_resolver_retry_mask(ctx), -1);

        } else {
            rn = ngx_resolver_lookup_addr(r, addr);
        }
#else
        rn = ngx_resolver_lookup_addr(r, addr);
#endif

        tree = &r->addr_rbtree;
        resend_queue = &r->addr_resend_queue;
        expire_queue = &r->addr_expire_queue;
    }

#if (NGX_RESTY_EXT)

    if (rn) {
        rc = ngx_resolver_use_stale(r, rn, ctx, 1);
        if (rc == NGX_ERROR) {
            goto failed_ctx;
        }

        if (rc != NGX_DECLINED) {
            return rc;
        }
    }

#endif

    if (rn) {

        if (rn->valid >= ngx_time()) {

            ngx_log_debug0(NGX_LOG_DEBUG_CORE, r->log, 0, "resolve cached");

            ngx_queue_remove(&rn->queue);

            rn->expire = ngx_time() + r->expire;

            ngx_queue_insert_head(expire_queue, &rn->queue);

#if (NGX_RESTY_EXT)
            if (rn->cache && rn->cache->error) {
                ngx_resolver_report_error(ctx, rn->cache->error, rn->valid);
                return NGX_OK;
            }
#endif

            name = ngx_resolver_dup(r, rn->name, rn->nlen);
            if (name == NULL) {
#if (NGX_RESTY_EXT)
                if (ctx->query_state && ctx->query_state->resuming) {
                    return NGX_ERROR;
                }

                ngx_resolver_free_query_state(ctx);
#endif
                ngx_resolver_free(r, ctx);
                return NGX_ERROR;
            }

            ctx->name.len = rn->nlen;
            ctx->name.data = name;

            /* unlock addr mutex */

            ctx->state = NGX_OK;
            ctx->valid = rn->valid;

            ctx->handler(ctx);

            ngx_resolver_free(r, name);

            return NGX_OK;
        }

        if (rn->waiting) {
            if (ngx_resolver_set_timeout(r, ctx) != NGX_OK) {
                return NGX_ERROR;
            }

#if (NGX_RESTY_EXT)
            if (ngx_resolver_join_query(r, rn, ctx) != NGX_OK) {
                goto failed_ctx;
            }
#endif

            ctx->next = rn->waiting;
            rn->waiting = ctx;
            ctx->state = NGX_AGAIN;
            ctx->async = 1;
            ctx->node = rn;

            /* unlock addr mutex */

#if (NGX_RESTY_EXT)
            if (rn->state && rn->state->pending) {
                ngx_resolver_retry_wait(r, rn);
            }
#endif

            return NGX_OK;
        }

#if (NGX_RESTY_EXT)

        if (ngx_resolver_save_stale(r, rn, 1) != NGX_OK) {
            goto failed_ctx;
        }

#endif

        ngx_queue_remove(&rn->queue);

        ngx_resolver_free(r, rn->query);
        rn->query = NULL;
#if (NGX_HAVE_INET6)
        rn->query6 = NULL;
#endif

    } else {
        rn = ngx_resolver_alloc(r, sizeof(ngx_resolver_node_t));
        if (rn == NULL) {
            goto failed;
        }

        switch (ctx->addr.sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            rn->addr6 = sin6->sin6_addr;
            rn->node.key = hash;
            break;
#endif

        default: /* AF_INET */
            rn->node.key = addr;
        }

        rn->query = NULL;
#if (NGX_HAVE_INET6)
        rn->query6 = NULL;
#endif

#if (NGX_RESTY_EXT)
        rn->state = NULL;
        rn->cache = NULL;
        rn->retry_mask = ngx_resolver_retry_mask(ctx);

        if (rn->retry_mask) {
            r->retry_mask_lookup = 1;
        }
#endif

        ngx_rbtree_insert(tree, &rn->node);
    }

    if (ngx_resolver_create_addr_query(r, rn, &ctx->addr) != NGX_OK) {
        goto failed;
    }

#if (NGX_RESTY_EXT)

    if (ngx_resolver_prepare_query(r, rn, ctx) != NGX_OK) {
        goto failed;
    }

#endif

    rn->last_connection = r->last_connection++;
    if (r->last_connection == r->connections.nelts) {
        r->last_connection = 0;
    }

#if (NGX_RESTY_EXT)

    if (r->nameserver) {
        rn->last_connection = ngx_resolver_select_peer(r, rn, 0);
    }

#endif

    rn->naddrs = (u_short) -1;
    rn->tcp = 0;
#if (NGX_HAVE_INET6)
    rn->naddrs6 = (u_short) -1;
    rn->tcp6 = 0;
#endif
    rn->nsrvs = 0;

    if (ngx_resolver_send_query(r, rn) != NGX_OK) {

        /* immediately retry once on failure */

        rn->last_connection++;
        if (rn->last_connection == r->connections.nelts) {
            rn->last_connection = 0;
        }

        (void) ngx_resolver_send_query(r, rn);
    }

    if (ngx_resolver_set_timeout(r, ctx) != NGX_OK) {
        goto failed;
    }

    if (ngx_resolver_resend_empty(r)) {
        ngx_add_timer(r->event, (ngx_msec_t) (r->resend_timeout * 1000));
    }

    rn->expire = ngx_time() + r->resend_timeout;

    ngx_queue_insert_head(resend_queue, &rn->queue);

    rn->code = 0;
    rn->cnlen = 0;
    rn->name = NULL;
    rn->nlen = 0;
    rn->valid = 0;
    rn->ttl = NGX_MAX_UINT32_VALUE;
    rn->waiting = ctx;

    /* unlock addr mutex */

    ctx->state = NGX_AGAIN;
    ctx->async = 1;
    ctx->node = rn;

#if (NGX_RESTY_EXT)

    if (rn->state && rn->state->retry) {
        (void) ngx_resolver_start_query(r, rn);
    }

#endif

    return NGX_OK;

failed:

    if (rn) {
        ngx_rbtree_delete(tree, &rn->node);

        if (rn->query) {
            ngx_resolver_free(r, rn->query);
        }

#if (NGX_RESTY_EXT)
        ngx_resolver_free_node_state(r, rn);
        ngx_resolver_free_cache(r, rn);
#endif

        ngx_resolver_free(r, rn);
    }

#if (NGX_RESTY_EXT)

failed_ctx:

#endif

    /* unlock addr mutex */

#if (NGX_RESTY_EXT)
    if (ctx->query_state && ctx->query_state->resuming) {
        ctx->node = NULL;
        return NGX_ERROR;
    }
#endif

    if (ctx->event) {
#if (NGX_RESTY_EXT)
        if (ctx->event->timer_set) {
            ngx_del_timer(ctx->event);
        }
#endif
        ngx_resolver_free(r, ctx->event);
    }

#if (NGX_RESTY_EXT)
    ngx_resolver_free_query_state(ctx);
#endif

    ngx_resolver_free(r, ctx);

    return NGX_ERROR;
}


void
ngx_resolve_addr_done(ngx_resolver_ctx_t *ctx)
{
    ngx_queue_t          *expire_queue;
    ngx_rbtree_t         *tree;
    ngx_resolver_t       *r;
    ngx_resolver_ctx_t   *w, **p;
    ngx_resolver_node_t  *rn;

    r = ctx->resolver;

    switch (ctx->addr.sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        tree = &r->addr6_rbtree;
        expire_queue = &r->addr6_expire_queue;
        break;
#endif

    default: /* AF_INET */
        tree = &r->addr_rbtree;
        expire_queue = &r->addr_expire_queue;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, r->log, 0,
                   "resolve addr done: %i", ctx->state);

    if (ctx->event && ctx->event->timer_set) {
        ngx_del_timer(ctx->event);
    }

    /* lock addr mutex */

    if (ctx->state == NGX_AGAIN || ctx->state == NGX_RESOLVE_TIMEDOUT) {

        rn = ctx->node;

#if (NGX_RESTY_EXT)
        if (rn == NULL && ctx->query_state) {
            goto done;
        }
#endif

        if (rn) {
            p = &rn->waiting;
            w = rn->waiting;

            while (w) {
                if (w == ctx) {
                    *p = w->next;

                    goto done;
                }

                p = &w->next;
                w = w->next;
            }
        }

        {
            u_char     text[NGX_SOCKADDR_STRLEN];
            ngx_str_t  addrtext;

            addrtext.data = text;
            addrtext.len = ngx_sock_ntop(ctx->addr.sockaddr, ctx->addr.socklen,
                                         text, NGX_SOCKADDR_STRLEN, 0);

            ngx_log_error(NGX_LOG_ALERT, r->log, 0,
                          "could not cancel %V resolving", &addrtext);
        }
    }

done:

    ngx_resolver_expire(r, tree, expire_queue);

    /* unlock addr mutex */

    /* lock alloc mutex */

    if (ctx->event) {
        ngx_resolver_free_locked(r, ctx->event);
    }

#if (NGX_RESTY_EXT)
    ngx_resolver_free_query_state(ctx);
#endif

    ngx_resolver_free_locked(r, ctx);

    /* unlock alloc mutex */

    if (r->event->timer_set && ngx_resolver_resend_empty(r)) {
        ngx_del_timer(r->event);
    }
}


static void
ngx_resolver_expire(ngx_resolver_t *r, ngx_rbtree_t *tree, ngx_queue_t *queue)
{
    time_t                now;
    ngx_uint_t            i;
    ngx_queue_t          *q;
    ngx_resolver_node_t  *rn;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, r->log, 0, "resolver expire");

    now = ngx_time();

    for (i = 0; i < 2; i++) {
        if (ngx_queue_empty(queue)) {
            return;
        }

        q = ngx_queue_last(queue);

        rn = ngx_queue_data(q, ngx_resolver_node_t, queue);

        if (now <= rn->expire) {
            return;
        }

#if (NGX_RESTY_EXT)

        if (r->stale_valid && rn->valid
            && (rn->cache == NULL || rn->cache->error == 0)
            && now <= rn->valid + r->stale_valid)
        {
            ngx_queue_remove(q);
            rn->expire = now + r->expire;
            ngx_queue_insert_head(queue, q);
            continue;
        }

#endif

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, r->log, 0,
                       "resolver expire \"%*s\"", (size_t) rn->nlen, rn->name);

        ngx_queue_remove(q);

        ngx_rbtree_delete(tree, &rn->node);

        ngx_resolver_free_node(r, rn);
    }
}


static ngx_int_t
ngx_resolver_send_query(ngx_resolver_t *r, ngx_resolver_node_t *rn)
{
    ngx_int_t                   rc;
    ngx_resolver_connection_t  *rec;
#if (NGX_RESTY_EXT)
    uintptr_t                   mask;
    ngx_uint_t                  i;
#endif

#if (NGX_RESTY_EXT)

    if (rn->state && rn->state->retry && !rn->state->started) {
        return NGX_OK;
    }

#endif

    rec = r->connections.elts;
    rec = &rec[rn->last_connection];

#if (NGX_RESTY_EXT)

    if (rn->state && !rn->state->retry) {
        i = rn->last_connection / (8 * sizeof(uintptr_t));
        mask = (uintptr_t) 1 << (rn->last_connection % (8 * sizeof(uintptr_t)));
        rn->state->tried[i] |= mask;
        rn->state->tries++;
    }

#endif

    if (rec->log.handler == NULL) {
        rec->log = *r->log;
        rec->log.handler = ngx_resolver_log_error;
        rec->log.data = rec;
        rec->log.action = "resolving";
    }

    if (rn->query && rn->naddrs == (u_short) -1) {
        rc = rn->tcp ? ngx_resolver_send_tcp_query(r, rec, rn->query, rn->qlen)
                     : ngx_resolver_send_udp_query(r, rec, rn->query, rn->qlen);

        if (rc != NGX_OK) {
            return rc;
        }
    }

#if (NGX_HAVE_INET6)

    if (rn->query6 && rn->naddrs6 == (u_short) -1) {
        rc = rn->tcp6
                    ? ngx_resolver_send_tcp_query(r, rec, rn->query6, rn->qlen)
                    : ngx_resolver_send_udp_query(r, rec, rn->query6, rn->qlen);

        if (rc != NGX_OK) {
            return rc;
        }
    }

#endif

    return NGX_OK;
}


static ngx_int_t
ngx_resolver_send_udp_query(ngx_resolver_t *r, ngx_resolver_connection_t  *rec,
    u_char *query, u_short qlen)
{
    ssize_t  n;

    if (rec->udp == NULL) {
        if (ngx_udp_connect(rec) != NGX_OK) {
            return NGX_ERROR;
        }

        rec->udp->data = rec;
        rec->udp->read->handler = ngx_resolver_udp_read;
        rec->udp->read->resolver = 1;
    }

    n = ngx_send(rec->udp, query, qlen);

    if (n == NGX_ERROR) {
        goto failed;
    }

    if ((size_t) n != (size_t) qlen) {
        ngx_log_error(NGX_LOG_CRIT, &rec->log, 0, "send() incomplete");
        goto failed;
    }

    return NGX_OK;

failed:

    ngx_close_connection(rec->udp);
    rec->udp = NULL;

    return NGX_ERROR;
}


static ngx_int_t
ngx_resolver_send_tcp_query(ngx_resolver_t *r, ngx_resolver_connection_t *rec,
    u_char *query, u_short qlen)
{
    ngx_buf_t  *b;
    ngx_int_t   rc;

    rc = NGX_OK;

    if (rec->tcp == NULL) {
        b = rec->read_buf;

        if (b == NULL) {
            b = ngx_resolver_calloc(r, sizeof(ngx_buf_t));
            if (b == NULL) {
                return NGX_ERROR;
            }

            b->start = ngx_resolver_alloc(r, NGX_RESOLVER_TCP_RSIZE);
            if (b->start == NULL) {
                ngx_resolver_free(r, b);
                return NGX_ERROR;
            }

            b->end = b->start + NGX_RESOLVER_TCP_RSIZE;

            rec->read_buf = b;
        }

        b->pos = b->start;
        b->last = b->start;

        b = rec->write_buf;

        if (b == NULL) {
            b = ngx_resolver_calloc(r, sizeof(ngx_buf_t));
            if (b == NULL) {
                return NGX_ERROR;
            }

            b->start = ngx_resolver_alloc(r, NGX_RESOLVER_TCP_WSIZE);
            if (b->start == NULL) {
                ngx_resolver_free(r, b);
                return NGX_ERROR;
            }

            b->end = b->start + NGX_RESOLVER_TCP_WSIZE;

            rec->write_buf = b;
        }

        b->pos = b->start;
        b->last = b->start;

        rc = ngx_tcp_connect(rec);
        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        rec->tcp->data = rec;
        rec->tcp->write->handler = ngx_resolver_tcp_write;
        rec->tcp->write->cancelable = 1;
        rec->tcp->read->handler = ngx_resolver_tcp_read;
        rec->tcp->read->resolver = 1;

        ngx_add_timer(rec->tcp->write, (ngx_msec_t) (r->tcp_timeout * 1000));
    }

    b = rec->write_buf;

    if (b->end - b->last <  2 + qlen) {
        ngx_log_error(NGX_LOG_CRIT, &rec->log, 0, "buffer overflow");
        return NGX_ERROR;
    }

    *b->last++ = (u_char) (qlen >> 8);
    *b->last++ = (u_char) qlen;
    b->last = ngx_cpymem(b->last, query, qlen);

    if (rc == NGX_OK) {
        ngx_resolver_tcp_write(rec->tcp->write);
    }

    return NGX_OK;
}


static void
ngx_resolver_resend_handler(ngx_event_t *ev)
{
    time_t           timer, atimer, stimer, ntimer;
#if (NGX_HAVE_INET6)
    time_t           a6timer;
#endif
    ngx_resolver_t  *r;

    r = ev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, r->log, 0,
                   "resolver resend handler");

    /* lock name mutex */

    ntimer = ngx_resolver_resend(r, &r->name_rbtree, &r->name_resend_queue);

    stimer = ngx_resolver_resend(r, &r->srv_rbtree, &r->srv_resend_queue);

    /* unlock name mutex */

    /* lock addr mutex */

    atimer = ngx_resolver_resend(r, &r->addr_rbtree, &r->addr_resend_queue);

    /* unlock addr mutex */

#if (NGX_HAVE_INET6)

    /* lock addr6 mutex */

    a6timer = ngx_resolver_resend(r, &r->addr6_rbtree, &r->addr6_resend_queue);

    /* unlock addr6 mutex */

#endif

    timer = ntimer;

    if (timer == 0) {
        timer = atimer;

    } else if (atimer) {
        timer = ngx_min(timer, atimer);
    }

    if (timer == 0) {
        timer = stimer;

    } else if (stimer) {
        timer = ngx_min(timer, stimer);
    }

#if (NGX_HAVE_INET6)

    if (timer == 0) {
        timer = a6timer;

    } else if (a6timer) {
        timer = ngx_min(timer, a6timer);
    }

#endif

    if (timer) {
        ngx_add_timer(r->event, (ngx_msec_t) (timer * 1000));
    }
}


static time_t
ngx_resolver_resend(ngx_resolver_t *r, ngx_rbtree_t *tree, ngx_queue_t *queue)
{
    time_t                now;
    ngx_queue_t          *q;
    ngx_resolver_node_t  *rn;

    now = ngx_time();

    for ( ;; ) {
        if (ngx_queue_empty(queue)) {
            return 0;
        }

        q = ngx_queue_last(queue);

        rn = ngx_queue_data(q, ngx_resolver_node_t, queue);

        if (now < rn->expire) {
            return rn->expire - now;
        }

        ngx_log_debug3(NGX_LOG_DEBUG_CORE, r->log, 0,
                       "resolver resend \"%*s\" %p",
                       (size_t) rn->nlen, rn->name, rn->waiting);

#if (NGX_RESTY_EXT)

        if (rn->state && rn->state->retry && rn->waiting) {
            if (!rn->state->pending && rn->retry_mask
                && !(rn->retry_mask & NGX_RESOLVER_FT_TIMEOUT))
            {
                ngx_queue_remove(q);
                rn->expire = now + r->resend_timeout;
                ngx_queue_insert_head(queue, q);
                continue;
            }

            if (rn->state->pending) {
                (void) ngx_resolver_start_query(r, rn);

            } else {
                (void) ngx_resolver_next(r, rn, NGX_RESOLVER_FT_TIMEOUT,
                                         NGX_RESOLVE_TIMEDOUT);
            }

            if (rn->valid && rn->waiting == NULL) {
                continue;
            }

            if (rn->waiting) {
                ngx_queue_remove(q);
                rn->expire = now + r->resend_timeout;
                ngx_queue_insert_head(queue, q);
                continue;
            }
        }

#endif

        ngx_queue_remove(q);

        if (rn->waiting) {

            if (++rn->last_connection == r->connections.nelts) {
                rn->last_connection = 0;
            }

            (void) ngx_resolver_send_query(r, rn);

            rn->expire = now + r->resend_timeout;

            ngx_queue_insert_head(queue, q);

            continue;
        }

#if (NGX_RESTY_EXT)

        if (rn->cache && rn->cache->stale) {
            ngx_queue_insert_head(queue, q);

            if (ngx_resolver_restore_stale(r, rn) == NGX_OK) {
                continue;
            }

            ngx_queue_remove(q);
        }

#endif

        ngx_rbtree_delete(tree, &rn->node);

        ngx_resolver_free_node(r, rn);
    }
}


static ngx_uint_t
ngx_resolver_resend_empty(ngx_resolver_t *r)
{
    return ngx_queue_empty(&r->name_resend_queue)
           && ngx_queue_empty(&r->srv_resend_queue)
#if (NGX_HAVE_INET6)
           && ngx_queue_empty(&r->addr6_resend_queue)
#endif
           && ngx_queue_empty(&r->addr_resend_queue);
}


static void
ngx_resolver_udp_read(ngx_event_t *rev)
{
    ssize_t                     n;
    ngx_connection_t           *c;
    ngx_resolver_connection_t  *rec;
    u_char                      buf[NGX_RESOLVER_UDP_SIZE];

    c = rev->data;
    rec = c->data;

    do {
        n = ngx_udp_recv(c, buf, NGX_RESOLVER_UDP_SIZE);

        if (n == NGX_AGAIN) {
            break;
        }

        if (n == NGX_ERROR) {
            goto failed;
        }

#if (NGX_RESTY_EXT)
        ngx_resolver_receive_response(rec, buf, n, 0);
#else
        ngx_resolver_process_response(rec->resolver, buf, n, 0);
#endif

    } while (rev->ready);

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        goto failed;
    }

    return;

failed:

    ngx_close_connection(rec->udp);
    rec->udp = NULL;
}


static void
ngx_resolver_tcp_write(ngx_event_t *wev)
{
    off_t                       sent;
    ssize_t                     n;
    ngx_buf_t                  *b;
    ngx_resolver_t             *r;
    ngx_connection_t           *c;
    ngx_resolver_connection_t  *rec;

    c = wev->data;
    rec = c->data;
    b = rec->write_buf;
    r = rec->resolver;

    if (wev->timedout) {
        goto failed;
    }

    sent = c->sent;

    while (wev->ready && b->pos < b->last) {
        n = ngx_send(c, b->pos, b->last - b->pos);

        if (n == NGX_AGAIN) {
            break;
        }

        if (n == NGX_ERROR) {
            goto failed;
        }

        b->pos += n;
    }

    if (b->pos != b->start) {
        b->last = ngx_movemem(b->start, b->pos, b->last - b->pos);
        b->pos = b->start;
    }

    if (c->sent != sent) {
        ngx_add_timer(wev, (ngx_msec_t) (r->tcp_timeout * 1000));
    }

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        goto failed;
    }

    return;

failed:

    ngx_close_connection(c);
    rec->tcp = NULL;
}


static void
ngx_resolver_tcp_read(ngx_event_t *rev)
{
    u_char                     *p;
    size_t                      size;
    ssize_t                     n;
    u_short                     qlen;
    ngx_buf_t                  *b;
#if !(NGX_RESTY_EXT)
    ngx_resolver_t             *r;
#endif
    ngx_connection_t           *c;
    ngx_resolver_connection_t  *rec;

    c = rev->data;
    rec = c->data;
    b = rec->read_buf;
#if !(NGX_RESTY_EXT)
    r = rec->resolver;
#endif

    while (rev->ready) {
        n = ngx_recv(c, b->last, b->end - b->last);

        if (n == NGX_AGAIN) {
            break;
        }

        if (n == NGX_ERROR || n == 0) {
            goto failed;
        }

        b->last += n;

        for ( ;; ) {
            p = b->pos;
            size = b->last - p;

            if (size < 2) {
                break;
            }

            qlen = (u_short) *p++ << 8;
            qlen += *p++;

            if (size < (size_t) (2 + qlen)) {
                break;
            }

#if (NGX_RESTY_EXT)
            ngx_resolver_receive_response(rec, p, qlen, 1);
#else
            ngx_resolver_process_response(r, p, qlen, 1);
#endif

            b->pos += 2 + qlen;
        }

        if (b->pos != b->start) {
            b->last = ngx_movemem(b->start, b->pos, b->last - b->pos);
            b->pos = b->start;
        }
    }

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        goto failed;
    }

    return;

failed:

    ngx_close_connection(c);
    rec->tcp = NULL;
}


static void
#if (NGX_RESTY_EXT)
ngx_resolver_process_response(ngx_resolver_t *r, u_char *buf, ngx_int_t scan,
    size_t n, ngx_uint_t tcp)
#else
ngx_resolver_process_response(ngx_resolver_t *r, u_char *buf, size_t n,
    ngx_uint_t tcp)
#endif
{
    char                 *err;
    ngx_uint_t            i, times, ident, qident, flags, code, nqs, nan, trunc,
                          qtype, qclass;
#if (NGX_HAVE_INET6)
    ngx_uint_t            qident6;
#endif
    ngx_queue_t          *q;
    ngx_resolver_qs_t    *qs;
    ngx_resolver_hdr_t   *response;
    ngx_resolver_node_t  *rn;

    if (n < sizeof(ngx_resolver_hdr_t)) {
        goto short_response;
    }

    response = (ngx_resolver_hdr_t *) buf;

    ident = (response->ident_hi << 8) + response->ident_lo;
    flags = (response->flags_hi << 8) + response->flags_lo;
    nqs = (response->nqs_hi << 8) + response->nqs_lo;
    nan = (response->nan_hi << 8) + response->nan_lo;
    trunc = flags & 0x0200;

    ngx_log_debug6(NGX_LOG_DEBUG_CORE, r->log, 0,
                   "resolver DNS response %ui fl:%04Xi %ui/%ui/%ud/%ud",
                   ident, flags, nqs, nan,
                   (response->nns_hi << 8) + response->nns_lo,
                   (response->nar_hi << 8) + response->nar_lo);

    /* response to a standard query */
    if ((flags & 0xf870) != 0x8000 || (trunc && tcp)) {
        ngx_log_error(r->log_level, r->log, 0,
                      "invalid %s DNS response %ui fl:%04Xi",
                      tcp ? "TCP" : "UDP", ident, flags);
        return;
    }

    code = flags & 0xf;

    if (code == NGX_RESOLVE_FORMERR) {

        times = 0;

        for (q = ngx_queue_head(&r->name_resend_queue);
             q != ngx_queue_sentinel(&r->name_resend_queue) && times++ < 100;
             q = ngx_queue_next(q))
        {
            rn = ngx_queue_data(q, ngx_resolver_node_t, queue);

            if (rn->query) {
                qident = (rn->query[0] << 8) + rn->query[1];

                if (qident == ident) {
                    goto dns_error_name;
                }
            }

#if (NGX_HAVE_INET6)
            if (rn->query6) {
                qident6 = (rn->query6[0] << 8) + rn->query6[1];

                if (qident6 == ident) {
                    goto dns_error_name;
                }
            }
#endif
        }

        goto dns_error;
    }

    if (code > NGX_RESOLVE_REFUSED) {
        goto dns_error;
    }

    if (nqs != 1) {
        err = "invalid number of questions in DNS response";
        goto done;
    }

    i = sizeof(ngx_resolver_hdr_t);

    while (i < (ngx_uint_t) n) {

        if (buf[i] & 0xc0) {
            err = "unexpected compression pointer in DNS response";
            goto done;
        }

        if (buf[i] == '\0') {
            goto found;
        }

        i += 1 + buf[i];
    }

    goto short_response;

found:

    if (i++ == sizeof(ngx_resolver_hdr_t)) {
        err = "zero-length domain name in DNS response";
        goto done;
    }

    if (i + sizeof(ngx_resolver_qs_t) + nan * (2 + sizeof(ngx_resolver_an_t))
        > (ngx_uint_t) n)
    {
        goto short_response;
    }

    qs = (ngx_resolver_qs_t *) &buf[i];

    qtype = (qs->type_hi << 8) + qs->type_lo;
    qclass = (qs->class_hi << 8) + qs->class_lo;

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, r->log, 0,
                   "resolver DNS response qt:%ui cl:%ui", qtype, qclass);

    if (qclass != 1) {
        ngx_log_error(r->log_level, r->log, 0,
                      "unknown query class %ui in DNS response", qclass);
        return;
    }

    switch (qtype) {

    case NGX_RESOLVE_A:
#if (NGX_HAVE_INET6)
    case NGX_RESOLVE_AAAA:
#endif

#if (NGX_RESTY_EXT)
        ngx_resolver_process_a(r, buf, n, scan, ident, code, qtype, nan,
                               trunc, i + sizeof(ngx_resolver_qs_t));
#else
        ngx_resolver_process_a(r, buf, n, ident, code, qtype, nan, trunc,
                               i + sizeof(ngx_resolver_qs_t));
#endif

        break;

    case NGX_RESOLVE_SRV:

#if (NGX_RESTY_EXT)
        ngx_resolver_process_srv(r, buf, n, scan, ident, code, nan, trunc,
                                 i + sizeof(ngx_resolver_qs_t));
#else
        ngx_resolver_process_srv(r, buf, n, ident, code, nan, trunc,
                                 i + sizeof(ngx_resolver_qs_t));
#endif

        break;

    case NGX_RESOLVE_PTR:

#if (NGX_RESTY_EXT)
        ngx_resolver_process_ptr(r, buf, n, scan, ident, code, nan);
#else
        ngx_resolver_process_ptr(r, buf, n, ident, code, nan);
#endif

        break;

    default:
        ngx_log_error(r->log_level, r->log, 0,
                      "unknown query type %ui in DNS response", qtype);
        return;
    }

    return;

short_response:

    err = "short DNS response";

done:

    ngx_log_error(r->log_level, r->log, 0, err);

    return;

dns_error_name:

    ngx_log_error(r->log_level, r->log, 0,
                  "DNS error (%ui: %s), query id:%ui, name:\"%*s\"",
                  code, ngx_resolver_strerror(code), ident,
                  (size_t) rn->nlen, rn->name);
    return;

dns_error:

    ngx_log_error(r->log_level, r->log, 0,
                  "DNS error (%ui: %s), query id:%ui",
                  code, ngx_resolver_strerror(code), ident);
    return;
}


static void
ngx_resolver_process_a(ngx_resolver_t *r, u_char *buf, size_t n,
#if (NGX_RESTY_EXT)
    ngx_int_t scan,
#endif
    ngx_uint_t ident, ngx_uint_t code, ngx_uint_t qtype,
    ngx_uint_t nan, ngx_uint_t trunc, ngx_uint_t ans)
{
    char                       *err;
    u_char                     *cname;
    size_t                      len;
    int32_t                     ttl;
    uint32_t                    hash;
    in_addr_t                  *addr;
    ngx_str_t                   name;
    ngx_uint_t                  type, class, qident, naddrs, a, i, j, start;
#if (NGX_HAVE_INET6)
    struct in6_addr            *addr6;
#endif
    ngx_resolver_an_t          *an;
    ngx_resolver_ctx_t         *ctx, *next;
    ngx_resolver_node_t        *rn;
    ngx_resolver_addr_t        *addrs;
    ngx_resolver_connection_t  *rec;

    if (ngx_resolver_copy(r, &name, buf,
                          buf + sizeof(ngx_resolver_hdr_t), buf + n)
        != NGX_OK)
    {
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, r->log, 0, "resolver qs:%V", &name);

    hash = ngx_crc32_short(name.data, name.len);

    /* lock name mutex */

#if (NGX_RESTY_EXT)
    if (r->retry_mask_lookup) {
        rn = ngx_resolver_lookup_reply(&r->name_rbtree, &name, hash, ident,
                                       qtype);

    } else {
        rn = ngx_resolver_lookup_name(r, &name, hash);
    }
#else
    rn = ngx_resolver_lookup_name(r, &name, hash);
#endif

    if (rn == NULL) {
        ngx_log_error(r->log_level, r->log, 0,
                      "unexpected DNS response for %V", &name);
        ngx_resolver_free(r, name.data);
        goto failed;
    }

    switch (qtype) {

#if (NGX_HAVE_INET6)
    case NGX_RESOLVE_AAAA:

        if (rn->query6 == NULL || rn->naddrs6 != (u_short) -1) {
            ngx_log_error(r->log_level, r->log, 0,
                          "unexpected DNS response for %V", &name);
            ngx_resolver_free(r, name.data);
            goto failed;
        }

        if (trunc && rn->tcp6) {
            ngx_resolver_free(r, name.data);
            goto failed;
        }

        qident = (rn->query6[0] << 8) + rn->query6[1];

        break;
#endif

    default: /* NGX_RESOLVE_A */

        if (rn->query == NULL || rn->naddrs != (u_short) -1) {
            ngx_log_error(r->log_level, r->log, 0,
                          "unexpected DNS response for %V", &name);
            ngx_resolver_free(r, name.data);
            goto failed;
        }

        if (trunc && rn->tcp) {
            ngx_resolver_free(r, name.data);
            goto failed;
        }

        qident = (rn->query[0] << 8) + rn->query[1];
    }

    if (ident != qident) {
        ngx_log_error(r->log_level, r->log, 0,
                      "wrong ident %ui in DNS response for %V, expect %ui",
                      ident, &name, qident);
        ngx_resolver_free(r, name.data);
        goto failed;
    }

    ngx_resolver_free(r, name.data);

#if (NGX_RESTY_EXT)
    if (!trunc && (code || nan == 0)) {
        scan = ngx_resolver_scan_failure(r, rn, buf, n, scan);
    }
#endif

    if (trunc) {

        ngx_queue_remove(&rn->queue);

        if (rn->waiting == NULL) {
            ngx_rbtree_delete(&r->name_rbtree, &rn->node);
            ngx_resolver_free_node(r, rn);
            goto next;
        }

        rec = r->connections.elts;
        rec = &rec[rn->last_connection];

        switch (qtype) {

#if (NGX_HAVE_INET6)
        case NGX_RESOLVE_AAAA:

            rn->tcp6 = 1;

            (void) ngx_resolver_send_tcp_query(r, rec, rn->query6, rn->qlen);

            break;
#endif

        default: /* NGX_RESOLVE_A */

            rn->tcp = 1;

            (void) ngx_resolver_send_tcp_query(r, rec, rn->query, rn->qlen);
        }

        rn->expire = ngx_time() + r->resend_timeout;

        ngx_queue_insert_head(&r->name_resend_queue, &rn->queue);

        goto next;
    }

    if (code == 0 && rn->code) {
        code = rn->code;
    }

    if (code == 0 && nan == 0) {

#if (NGX_HAVE_INET6)
        switch (qtype) {

        case NGX_RESOLVE_AAAA:

            rn->naddrs6 = 0;

            if (rn->naddrs == (u_short) -1) {
                goto next;
            }

            if (rn->naddrs) {
                goto export;
            }

            break;

        default: /* NGX_RESOLVE_A */

            rn->naddrs = 0;

            if (rn->naddrs6 == (u_short) -1) {
                goto next;
            }

            if (rn->naddrs6) {
                goto export;
            }
        }
#endif

        code = NGX_RESOLVE_NXDOMAIN;
    }

    if (code) {

#if (NGX_HAVE_INET6)
        switch (qtype) {

        case NGX_RESOLVE_AAAA:

            rn->naddrs6 = 0;

            if (rn->naddrs == (u_short) -1) {
                rn->code = (u_char) code;
                goto next;
            }

            break;

        default: /* NGX_RESOLVE_A */

            rn->naddrs = 0;

            if (rn->naddrs6 == (u_short) -1) {
                rn->code = (u_char) code;
                goto next;
            }
        }
#endif

#if (NGX_RESTY_EXT)
        if (ngx_resolver_process_failure(r, rn, buf, n, code, scan) == NGX_OK) {
            return;
        }
#endif

        next = rn->waiting;
        rn->waiting = NULL;

        ngx_queue_remove(&rn->queue);

        ngx_rbtree_delete(&r->name_rbtree, &rn->node);

        /* unlock name mutex */

        while (next) {
            ctx = next;
            ctx->state = code;
            ctx->valid = ngx_time() + (r->valid ? r->valid : 10);
            next = ctx->next;

            ctx->handler(ctx);
        }

        ngx_resolver_free_node(r, rn);

        return;
    }

    i = ans;
    naddrs = 0;
    cname = NULL;

    for (a = 0; a < nan; a++) {

        start = i;

        while (i < n) {

            if (buf[i] & 0xc0) {
                i += 2;
                goto found;
            }

            if (buf[i] == 0) {
                i++;
                goto test_length;
            }

            i += 1 + buf[i];
        }

        goto short_response;

    test_length:

        if (i - start < 2) {
            err = "invalid name in DNS response";
            goto invalid;
        }

    found:

        if (i + sizeof(ngx_resolver_an_t) >= n) {
            goto short_response;
        }

        an = (ngx_resolver_an_t *) &buf[i];

        type = (an->type_hi << 8) + an->type_lo;
        class = (an->class_hi << 8) + an->class_lo;
        len = (an->len_hi << 8) + an->len_lo;
        ttl = (an->ttl[0] << 24) + (an->ttl[1] << 16)
            + (an->ttl[2] << 8) + (an->ttl[3]);

        if (class != 1) {
            ngx_log_error(r->log_level, r->log, 0,
                          "unexpected RR class %ui in DNS response", class);
            goto failed;
        }

        if (ttl < 0) {
            ttl = 0;
        }

        rn->ttl = ngx_min(rn->ttl, (uint32_t) ttl);

        i += sizeof(ngx_resolver_an_t);

        switch (type) {

        case NGX_RESOLVE_A:

            if (qtype != NGX_RESOLVE_A) {
                err = "unexpected A record in DNS response";
                goto invalid;
            }

            if (len != 4) {
                err = "invalid A record in DNS response";
                goto invalid;
            }

            if (i + 4 > n) {
                goto short_response;
            }

            naddrs++;

            break;

#if (NGX_HAVE_INET6)
        case NGX_RESOLVE_AAAA:

            if (qtype != NGX_RESOLVE_AAAA) {
                err = "unexpected AAAA record in DNS response";
                goto invalid;
            }

            if (len != 16) {
                err = "invalid AAAA record in DNS response";
                goto invalid;
            }

            if (i + 16 > n) {
                goto short_response;
            }

            naddrs++;

            break;
#endif

        case NGX_RESOLVE_CNAME:

            cname = &buf[i];

            break;

        case NGX_RESOLVE_DNAME:

            break;

        default:

            ngx_log_error(r->log_level, r->log, 0,
                          "unexpected RR type %ui in DNS response", type);
        }

        i += len;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_CORE, r->log, 0,
                   "resolver naddrs:%ui cname:%p ttl:%uD",
                   naddrs, cname, rn->ttl);

    if (naddrs) {

        switch (qtype) {

#if (NGX_HAVE_INET6)
        case NGX_RESOLVE_AAAA:

            if (naddrs == 1) {
                addr6 = &rn->u6.addr6;
                rn->naddrs6 = 1;

            } else {
                addr6 = ngx_resolver_alloc(r, naddrs * sizeof(struct in6_addr));
                if (addr6 == NULL) {
                    goto failed;
                }

                rn->u6.addrs6 = addr6;
                rn->naddrs6 = (u_short) naddrs;
            }

#if (NGX_SUPPRESS_WARN)
            addr = NULL;
#endif

            break;
#endif

        default: /* NGX_RESOLVE_A */

            if (naddrs == 1) {
                addr = &rn->u.addr;
                rn->naddrs = 1;

            } else {
                addr = ngx_resolver_alloc(r, naddrs * sizeof(in_addr_t));
                if (addr == NULL) {
                    goto failed;
                }

                rn->u.addrs = addr;
                rn->naddrs = (u_short) naddrs;
            }

#if (NGX_HAVE_INET6 && NGX_SUPPRESS_WARN)
            addr6 = NULL;
#endif
        }

        j = 0;
        i = ans;

        for (a = 0; a < nan; a++) {

            for ( ;; ) {

                if (buf[i] & 0xc0) {
                    i += 2;
                    break;
                }

                if (buf[i] == 0) {
                    i++;
                    break;
                }

                i += 1 + buf[i];
            }

            an = (ngx_resolver_an_t *) &buf[i];

            type = (an->type_hi << 8) + an->type_lo;
            len = (an->len_hi << 8) + an->len_lo;

            i += sizeof(ngx_resolver_an_t);

            if (type == NGX_RESOLVE_A) {

                addr[j] = htonl((buf[i] << 24) + (buf[i + 1] << 16)
                                + (buf[i + 2] << 8) + (buf[i + 3]));

                if (++j == naddrs) {

#if (NGX_HAVE_INET6)
                    if (rn->naddrs6 == (u_short) -1) {
                        goto next;
                    }
#endif

                    break;
                }
            }

#if (NGX_HAVE_INET6)
            else if (type == NGX_RESOLVE_AAAA) {

                ngx_memcpy(addr6[j].s6_addr, &buf[i], 16);

                if (++j == naddrs) {

                    if (rn->naddrs == (u_short) -1) {
                        goto next;
                    }

                    break;
                }
            }
#endif

            i += len;
        }
    }

    switch (qtype) {

#if (NGX_HAVE_INET6)
    case NGX_RESOLVE_AAAA:

        if (rn->naddrs6 == (u_short) -1) {
            rn->naddrs6 = 0;
        }

        break;
#endif

    default: /* NGX_RESOLVE_A */

        if (rn->naddrs == (u_short) -1) {
            rn->naddrs = 0;
        }
    }

    if (rn->naddrs != (u_short) -1
#if (NGX_HAVE_INET6)
        && rn->naddrs6 != (u_short) -1
#endif
        && rn->naddrs
#if (NGX_HAVE_INET6)
           + rn->naddrs6
#endif
           > 0)
    {

#if (NGX_HAVE_INET6)
    export:
#endif

        naddrs = rn->naddrs;
#if (NGX_HAVE_INET6)
        naddrs += rn->naddrs6;
#endif

        if (naddrs == 1 && rn->naddrs == 1) {
            addrs = NULL;

        } else {
            addrs = ngx_resolver_export(r, rn, 0);
            if (addrs == NULL) {
                goto failed;
            }
        }

        ngx_queue_remove(&rn->queue);

#if (NGX_RESTY_EXT)
        ngx_resolver_query_success(r, rn);
        rn->valid = ngx_resolver_valid(r, rn->ttl);
#else
        rn->valid = ngx_time() + (r->valid ? r->valid : (time_t) rn->ttl);
#endif

        rn->expire = ngx_time() + r->expire;

        ngx_queue_insert_head(&r->name_expire_queue, &rn->queue);

        next = rn->waiting;
        rn->waiting = NULL;

        /* unlock name mutex */

        while (next) {
            ctx = next;
            ctx->state = NGX_OK;
            ctx->valid = rn->valid;
            ctx->naddrs = naddrs;

            if (addrs == NULL) {
                ctx->addrs = &ctx->addr;
                ctx->addr.sockaddr = (struct sockaddr *) &ctx->sin;
                ctx->addr.socklen = sizeof(struct sockaddr_in);
                ngx_memzero(&ctx->sin, sizeof(struct sockaddr_in));
                ctx->sin.sin_family = AF_INET;
                ctx->sin.sin_addr.s_addr = rn->u.addr;

            } else {
                ctx->addrs = addrs;
            }

            next = ctx->next;

            ctx->handler(ctx);
        }

        if (addrs != NULL) {
            ngx_resolver_free(r, addrs->sockaddr);
            ngx_resolver_free(r, addrs);
        }

        ngx_resolver_free(r, rn->query);
        rn->query = NULL;
#if (NGX_HAVE_INET6)
        rn->query6 = NULL;
#endif

        return;
    }

    if (cname) {

        /* CNAME only */

        if (rn->naddrs == (u_short) -1
#if (NGX_HAVE_INET6)
            || rn->naddrs6 == (u_short) -1
#endif
            )
        {
            goto next;
        }

        if (ngx_resolver_copy(r, &name, buf, cname, buf + n) != NGX_OK) {
            goto failed;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, r->log, 0,
                       "resolver cname:\"%V\"", &name);

        ngx_queue_remove(&rn->queue);

        rn->cnlen = (u_short) name.len;
        rn->u.cname = name.data;

#if (NGX_RESTY_EXT)
        ngx_resolver_query_success(r, rn);
        rn->valid = ngx_resolver_valid(r, rn->ttl);
#else
        rn->valid = ngx_time() + (r->valid ? r->valid : (time_t) rn->ttl);
#endif

        rn->expire = ngx_time() + r->expire;

        ngx_queue_insert_head(&r->name_expire_queue, &rn->queue);

        ngx_resolver_free(r, rn->query);
        rn->query = NULL;
#if (NGX_HAVE_INET6)
        rn->query6 = NULL;
#endif

        ctx = rn->waiting;
        rn->waiting = NULL;

        if (ctx) {

            if (ctx->recursion++ >= NGX_RESOLVER_MAX_RECURSION) {

                /* unlock name mutex */

                do {
                    ctx->state = NGX_RESOLVE_NXDOMAIN;
                    next = ctx->next;

                    ctx->handler(ctx);

                    ctx = next;
                } while (ctx);

                return;
            }

            for (next = ctx; next; next = next->next) {
                next->node = NULL;
            }

            (void) ngx_resolve_name_locked(r, ctx, &name);
        }

        /* unlock name mutex */

        return;
    }

    ngx_log_error(r->log_level, r->log, 0,
                  "no A or CNAME types in DNS response");
    return;

short_response:

    err = "short DNS response";

invalid:

    /* unlock name mutex */

    ngx_log_error(r->log_level, r->log, 0, err);

    return;

failed:

next:

    /* unlock name mutex */

    return;
}


static void
ngx_resolver_process_srv(ngx_resolver_t *r, u_char *buf, size_t n,
#if (NGX_RESTY_EXT)
    ngx_int_t scan,
#endif
    ngx_uint_t ident, ngx_uint_t code, ngx_uint_t nan,
    ngx_uint_t trunc, ngx_uint_t ans)
{
    char                       *err;
    u_char                     *cname;
    size_t                      len;
    int32_t                     ttl;
    uint32_t                    hash;
    ngx_str_t                   name;
    ngx_uint_t                  type, qident, class, start, nsrvs, a, i, j;
    ngx_resolver_an_t          *an;
    ngx_resolver_ctx_t         *ctx, *next;
    ngx_resolver_srv_t         *srvs;
    ngx_resolver_node_t        *rn;
    ngx_resolver_connection_t  *rec;

    if (ngx_resolver_copy(r, &name, buf,
                          buf + sizeof(ngx_resolver_hdr_t), buf + n)
        != NGX_OK)
    {
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, r->log, 0, "resolver qs:%V", &name);

    hash = ngx_crc32_short(name.data, name.len);

#if (NGX_RESTY_EXT)
    if (r->retry_mask_lookup) {
        rn = ngx_resolver_lookup_reply(&r->srv_rbtree, &name, hash, ident,
                                       NGX_RESOLVE_SRV);

    } else {
        rn = ngx_resolver_lookup_srv(r, &name, hash);
    }
#else
    rn = ngx_resolver_lookup_srv(r, &name, hash);
#endif

    if (rn == NULL || rn->query == NULL) {
        ngx_log_error(r->log_level, r->log, 0,
                      "unexpected DNS response for %V", &name);
        ngx_resolver_free(r, name.data);
        goto failed;
    }

    if (trunc && rn->tcp) {
        ngx_resolver_free(r, name.data);
        goto failed;
    }

    qident = (rn->query[0] << 8) + rn->query[1];

    if (ident != qident) {
        ngx_log_error(r->log_level, r->log, 0,
                      "wrong ident %ui in DNS response for %V, expect %ui",
                      ident, &name, qident);
        ngx_resolver_free(r, name.data);
        goto failed;
    }

    ngx_resolver_free(r, name.data);

    if (trunc) {

        ngx_queue_remove(&rn->queue);

        if (rn->waiting == NULL) {
            ngx_rbtree_delete(&r->srv_rbtree, &rn->node);
            ngx_resolver_free_node(r, rn);
            return;
        }

        rec = r->connections.elts;
        rec = &rec[rn->last_connection];

        rn->tcp = 1;

        (void) ngx_resolver_send_tcp_query(r, rec, rn->query, rn->qlen);

        rn->expire = ngx_time() + r->resend_timeout;

        ngx_queue_insert_head(&r->srv_resend_queue, &rn->queue);

        return;
    }

    if (code == 0 && rn->code) {
        code = rn->code;
    }

    if (code == 0 && nan == 0) {
        code = NGX_RESOLVE_NXDOMAIN;
    }

    if (code) {
#if (NGX_RESTY_EXT)
        if (ngx_resolver_process_failure(r, rn, buf, n, code, scan) == NGX_OK) {
            return;
        }
#endif

        next = rn->waiting;
        rn->waiting = NULL;

        ngx_queue_remove(&rn->queue);

        ngx_rbtree_delete(&r->srv_rbtree, &rn->node);

        while (next) {
            ctx = next;
            ctx->state = code;
            ctx->valid = ngx_time() + (r->valid ? r->valid : 10);
            next = ctx->next;

            ctx->handler(ctx);
        }

        ngx_resolver_free_node(r, rn);

        return;
    }

    i = ans;
    nsrvs = 0;
    cname = NULL;

    for (a = 0; a < nan; a++) {

        start = i;

        while (i < n) {

            if (buf[i] & 0xc0) {
                i += 2;
                goto found;
            }

            if (buf[i] == 0) {
                i++;
                goto test_length;
            }

            i += 1 + buf[i];
        }

        goto short_response;

    test_length:

        if (i - start < 2) {
            err = "invalid name DNS response";
            goto invalid;
        }

    found:

        if (i + sizeof(ngx_resolver_an_t) >= n) {
            goto short_response;
        }

        an = (ngx_resolver_an_t *) &buf[i];

        type = (an->type_hi << 8) + an->type_lo;
        class = (an->class_hi << 8) + an->class_lo;
        len = (an->len_hi << 8) + an->len_lo;
        ttl = (an->ttl[0] << 24) + (an->ttl[1] << 16)
            + (an->ttl[2] << 8) + (an->ttl[3]);

        if (class != 1) {
            ngx_log_error(r->log_level, r->log, 0,
                          "unexpected RR class %ui in DNS response", class);
            goto failed;
        }

        if (ttl < 0) {
            ttl = 0;
        }

        rn->ttl = ngx_min(rn->ttl, (uint32_t) ttl);

        i += sizeof(ngx_resolver_an_t);

        switch (type) {

        case NGX_RESOLVE_SRV:

            if (i + 6 >= n) {
                goto short_response;
            }

            if (ngx_resolver_copy(r, NULL, buf, &buf[i + 6], buf + n)
                != NGX_OK)
            {
                goto failed;
            }

            nsrvs++;

            break;

        case NGX_RESOLVE_CNAME:

            cname = &buf[i];

            break;

        case NGX_RESOLVE_DNAME:

            break;

        default:

            ngx_log_error(r->log_level, r->log, 0,
                          "unexpected RR type %ui in DNS response", type);
        }

        i += len;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_CORE, r->log, 0,
                   "resolver nsrvs:%ui cname:%p ttl:%uD",
                   nsrvs, cname, rn->ttl);

    if (nsrvs) {

        srvs = ngx_resolver_calloc(r, nsrvs * sizeof(ngx_resolver_srv_t));
        if (srvs == NULL) {
            goto failed;
        }

        rn->u.srvs = srvs;
        rn->nsrvs = (u_short) nsrvs;

        j = 0;
        i = ans;

        for (a = 0; a < nan; a++) {

            for ( ;; ) {

                if (buf[i] & 0xc0) {
                    i += 2;
                    break;
                }

                if (buf[i] == 0) {
                    i++;
                    break;
                }

                i += 1 + buf[i];
            }

            an = (ngx_resolver_an_t *) &buf[i];

            type = (an->type_hi << 8) + an->type_lo;
            len = (an->len_hi << 8) + an->len_lo;

            i += sizeof(ngx_resolver_an_t);

            if (type == NGX_RESOLVE_SRV) {

                srvs[j].priority = (buf[i] << 8) + buf[i + 1];
                srvs[j].weight = (buf[i + 2] << 8) + buf[i + 3];

                if (srvs[j].weight == 0) {
                    srvs[j].weight = 1;
                }

                srvs[j].port = (buf[i + 4] << 8) + buf[i + 5];

                if (ngx_resolver_copy(r, &srvs[j].name, buf, &buf[i + 6],
                                      buf + n)
                    != NGX_OK)
                {
                    goto failed;
                }

                j++;
            }

            i += len;
        }

        ngx_sort(srvs, nsrvs, sizeof(ngx_resolver_srv_t),
                 ngx_resolver_cmp_srvs);

        ngx_resolver_free(r, rn->query);
        rn->query = NULL;

        ngx_queue_remove(&rn->queue);

#if (NGX_RESTY_EXT)
        ngx_resolver_query_success(r, rn);
        rn->valid = ngx_resolver_valid(r, rn->ttl);
#else
        rn->valid = ngx_time() + (r->valid ? r->valid : (time_t) rn->ttl);
#endif

        rn->expire = ngx_time() + r->expire;

        ngx_queue_insert_head(&r->srv_expire_queue, &rn->queue);

        next = rn->waiting;
        rn->waiting = NULL;

        while (next) {
            ctx = next;
            next = ctx->next;

            ngx_resolver_resolve_srv_names(ctx, rn);
        }

        return;
    }

    rn->nsrvs = 0;

    if (cname) {

        /* CNAME only */

        if (ngx_resolver_copy(r, &name, buf, cname, buf + n) != NGX_OK) {
            goto failed;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, r->log, 0,
                       "resolver cname:\"%V\"", &name);

        ngx_queue_remove(&rn->queue);

        rn->cnlen = (u_short) name.len;
        rn->u.cname = name.data;

#if (NGX_RESTY_EXT)
        ngx_resolver_query_success(r, rn);
        rn->valid = ngx_resolver_valid(r, rn->ttl);
#else
        rn->valid = ngx_time() + (r->valid ? r->valid : (time_t) rn->ttl);
#endif

        rn->expire = ngx_time() + r->expire;

        ngx_queue_insert_head(&r->srv_expire_queue, &rn->queue);

        ngx_resolver_free(r, rn->query);
        rn->query = NULL;
#if (NGX_HAVE_INET6)
        rn->query6 = NULL;
#endif

        ctx = rn->waiting;
        rn->waiting = NULL;

        if (ctx) {

            if (ctx->recursion++ >= NGX_RESOLVER_MAX_RECURSION) {

                /* unlock name mutex */

                do {
                    ctx->state = NGX_RESOLVE_NXDOMAIN;
                    next = ctx->next;

                    ctx->handler(ctx);

                    ctx = next;
                } while (ctx);

                return;
            }

            for (next = ctx; next; next = next->next) {
                next->node = NULL;
            }

            (void) ngx_resolve_name_locked(r, ctx, &name);
        }

        /* unlock name mutex */

        return;
    }

    ngx_log_error(r->log_level, r->log, 0, "no SRV type in DNS response");

    return;

short_response:

    err = "short DNS response";

invalid:

    /* unlock name mutex */

    ngx_log_error(r->log_level, r->log, 0, err);

    return;

failed:

    /* unlock name mutex */

    return;
}


static void
ngx_resolver_resolve_srv_names(ngx_resolver_ctx_t *ctx, ngx_resolver_node_t *rn)
{
    ngx_uint_t                i;
    ngx_resolver_t           *r;
    ngx_resolver_ctx_t       *cctx;
    ngx_resolver_srv_name_t  *srvs;

    r = ctx->resolver;

    ctx->node = NULL;
    ctx->state = NGX_OK;
    ctx->valid = rn->valid;
    ctx->count = rn->nsrvs;

    srvs = ngx_resolver_calloc(r, rn->nsrvs * sizeof(ngx_resolver_srv_name_t));
    if (srvs == NULL) {
        goto failed;
    }

    ctx->srvs = srvs;
    ctx->nsrvs = rn->nsrvs;

    if (ctx->event && ctx->event->timer_set) {
        ngx_del_timer(ctx->event);
    }

    for (i = 0; i < (ngx_uint_t) rn->nsrvs; i++) {
        srvs[i].name.data = ngx_resolver_alloc(r, rn->u.srvs[i].name.len);
        if (srvs[i].name.data == NULL) {
            goto failed;
        }

        srvs[i].name.len = rn->u.srvs[i].name.len;
        ngx_memcpy(srvs[i].name.data, rn->u.srvs[i].name.data,
                   srvs[i].name.len);

        cctx = ngx_resolve_start(r, NULL);
        if (cctx == NULL) {
            goto failed;
        }

#if (NGX_RESTY_EXT)

        cctx->retry = ctx->retry;

        if (ctx->query_state) {
            if (ngx_resolver_alloc_query_state(cctx, ctx->query_state->budget)
                != NGX_OK)
            {
                ngx_resolver_free(r, cctx);
                goto failed;
            }
        }

#endif

        cctx->name = srvs[i].name;
        cctx->handler = ngx_resolver_srv_names_handler;
        cctx->data = ctx;
        cctx->srvs = &srvs[i];
        cctx->timeout = ctx->timeout;

        srvs[i].priority = rn->u.srvs[i].priority;
        srvs[i].weight = rn->u.srvs[i].weight;
        srvs[i].port = rn->u.srvs[i].port;
        srvs[i].ctx = cctx;

        if (ngx_resolve_name(cctx) == NGX_ERROR) {
            srvs[i].ctx = NULL;
            goto failed;
        }
    }

    return;

failed:

    ctx->state = NGX_ERROR;
    ctx->valid = ngx_time() + (r->valid ? r->valid : 10);

    ctx->handler(ctx);
}


static void
ngx_resolver_srv_names_handler(ngx_resolver_ctx_t *cctx)
{
    ngx_uint_t                i;
    ngx_addr_t               *addrs;
    ngx_resolver_t           *r;
    ngx_sockaddr_t           *sockaddr;
    ngx_resolver_ctx_t       *ctx;
    ngx_resolver_srv_name_t  *srv;

    r = cctx->resolver;
    ctx = cctx->data;
    srv = cctx->srvs;

    ctx->count--;
    ctx->async |= cctx->async;

    srv->ctx = NULL;
    srv->state = cctx->state;

    if (cctx->naddrs) {

        ctx->valid = ngx_min(ctx->valid, cctx->valid);

        addrs = ngx_resolver_calloc(r, cctx->naddrs * sizeof(ngx_addr_t));
        if (addrs == NULL) {
            srv->state = NGX_ERROR;
            goto done;
        }

        sockaddr = ngx_resolver_alloc(r, cctx->naddrs * sizeof(ngx_sockaddr_t));
        if (sockaddr == NULL) {
            ngx_resolver_free(r, addrs);
            srv->state = NGX_ERROR;
            goto done;
        }

        for (i = 0; i < cctx->naddrs; i++) {
            addrs[i].sockaddr = &sockaddr[i].sockaddr;
            addrs[i].socklen = cctx->addrs[i].socklen;

            ngx_memcpy(&sockaddr[i], cctx->addrs[i].sockaddr,
                       addrs[i].socklen);

            ngx_inet_set_port(addrs[i].sockaddr, srv->port);
        }

        srv->addrs = addrs;
        srv->naddrs = cctx->naddrs;
    }

done:

    ngx_resolve_name_done(cctx);

    if (ctx->count == 0) {
        ngx_resolver_report_srv(r, ctx);
    }
}


static void
ngx_resolver_process_ptr(ngx_resolver_t *r, u_char *buf, size_t n,
#if (NGX_RESTY_EXT)
    ngx_int_t scan,
#endif
    ngx_uint_t ident, ngx_uint_t code, ngx_uint_t nan)
{
    char                 *err;
    size_t                len;
    in_addr_t             addr;
    int32_t               ttl;
    ngx_int_t             octet;
    ngx_str_t             name;
    ngx_uint_t            mask, type, class, qident, a, i, start;
    ngx_queue_t          *expire_queue;
    ngx_rbtree_t         *tree;
    ngx_resolver_an_t    *an;
    ngx_resolver_ctx_t   *ctx, *next;
    ngx_resolver_node_t  *rn;
#if (NGX_HAVE_INET6)
    uint32_t              hash;
    ngx_int_t             digit;
    struct in6_addr       addr6;
#endif

    if (ngx_resolver_copy(r, &name, buf,
                          buf + sizeof(ngx_resolver_hdr_t), buf + n)
        != NGX_OK)
    {
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, r->log, 0, "resolver qs:%V", &name);

    /* AF_INET */

    addr = 0;
    i = sizeof(ngx_resolver_hdr_t);

    for (mask = 0; mask < 32; mask += 8) {
        len = buf[i++];

        octet = ngx_atoi(&buf[i], len);
        if (octet == NGX_ERROR || octet > 255) {
            goto invalid_in_addr_arpa;
        }

        addr += octet << mask;
        i += len;
    }

    if (ngx_strcasecmp(&buf[i], (u_char *) "\7in-addr\4arpa") == 0) {
        i += sizeof("\7in-addr\4arpa");

        /* lock addr mutex */

#if (NGX_RESTY_EXT)
        if (r->retry_mask_lookup) {
            rn = ngx_resolver_lookup_address(r, NULL, addr, 0, ident);

        } else {
            rn = ngx_resolver_lookup_addr(r, addr);
        }
#else
        rn = ngx_resolver_lookup_addr(r, addr);
#endif

        tree = &r->addr_rbtree;
        expire_queue = &r->addr_expire_queue;

        goto valid;
    }

invalid_in_addr_arpa:

#if (NGX_HAVE_INET6)

    i = sizeof(ngx_resolver_hdr_t);

    for (octet = 15; octet >= 0; octet--) {
        if (buf[i++] != '\1') {
            goto invalid_ip6_arpa;
        }

        digit = ngx_hextoi(&buf[i++], 1);
        if (digit == NGX_ERROR) {
            goto invalid_ip6_arpa;
        }

        addr6.s6_addr[octet] = (u_char) digit;

        if (buf[i++] != '\1') {
            goto invalid_ip6_arpa;
        }

        digit = ngx_hextoi(&buf[i++], 1);
        if (digit == NGX_ERROR) {
            goto invalid_ip6_arpa;
        }

        addr6.s6_addr[octet] += (u_char) (digit * 16);
    }

    if (ngx_strcasecmp(&buf[i], (u_char *) "\3ip6\4arpa") == 0) {
        i += sizeof("\3ip6\4arpa");

        /* lock addr mutex */

        hash = ngx_crc32_short(addr6.s6_addr, 16);
#if (NGX_RESTY_EXT)
        if (r->retry_mask_lookup) {
            rn = ngx_resolver_lookup_address(r, addr6.s6_addr, hash,
                                             0, ident);

        } else {
            rn = ngx_resolver_lookup_addr6(r, &addr6, hash);
        }
#else
        rn = ngx_resolver_lookup_addr6(r, &addr6, hash);
#endif

        tree = &r->addr6_rbtree;
        expire_queue = &r->addr6_expire_queue;

        goto valid;
    }

invalid_ip6_arpa:
#endif

    ngx_log_error(r->log_level, r->log, 0,
                  "invalid in-addr.arpa or ip6.arpa name in DNS response");
    ngx_resolver_free(r, name.data);
    return;

valid:

    if (rn == NULL || rn->query == NULL) {
        ngx_log_error(r->log_level, r->log, 0,
                      "unexpected DNS response for %V", &name);
        ngx_resolver_free(r, name.data);
        goto failed;
    }

    qident = (rn->query[0] << 8) + rn->query[1];

    if (ident != qident) {
        ngx_log_error(r->log_level, r->log, 0,
                      "wrong ident %ui in DNS response for %V, expect %ui",
                      ident, &name, qident);
        ngx_resolver_free(r, name.data);
        goto failed;
    }

    ngx_resolver_free(r, name.data);

    if (code == 0 && nan == 0) {
        code = NGX_RESOLVE_NXDOMAIN;
    }

    if (code) {
#if (NGX_RESTY_EXT)
        if (ngx_resolver_process_failure(r, rn, buf, n, code, scan) == NGX_OK) {
            return;
        }
#endif

        next = rn->waiting;
        rn->waiting = NULL;

        ngx_queue_remove(&rn->queue);

        ngx_rbtree_delete(tree, &rn->node);

        /* unlock addr mutex */

        while (next) {
            ctx = next;
            ctx->state = code;
            ctx->valid = ngx_time() + (r->valid ? r->valid : 10);
            next = ctx->next;

            ctx->handler(ctx);
        }

        ngx_resolver_free_node(r, rn);

        return;
    }

    i += sizeof(ngx_resolver_qs_t);

    for (a = 0; a < nan; a++) {

        start = i;

        while (i < n) {

            if (buf[i] & 0xc0) {
                i += 2;
                goto found;
            }

            if (buf[i] == 0) {
                i++;
                goto test_length;
            }

            i += 1 + buf[i];
        }

        goto short_response;

    test_length:

        if (i - start < 2) {
            err = "invalid name in DNS response";
            goto invalid;
        }

    found:

        if (i + sizeof(ngx_resolver_an_t) >= n) {
            goto short_response;
        }

        an = (ngx_resolver_an_t *) &buf[i];

        type = (an->type_hi << 8) + an->type_lo;
        class = (an->class_hi << 8) + an->class_lo;
        len = (an->len_hi << 8) + an->len_lo;
        ttl = (an->ttl[0] << 24) + (an->ttl[1] << 16)
            + (an->ttl[2] << 8) + (an->ttl[3]);

        if (class != 1) {
            ngx_log_error(r->log_level, r->log, 0,
                          "unexpected RR class %ui in DNS response", class);
            goto failed;
        }

        if (ttl < 0) {
            ttl = 0;
        }

        ngx_log_debug3(NGX_LOG_DEBUG_CORE, r->log, 0,
                      "resolver qt:%ui cl:%ui len:%uz",
                      type, class, len);

        i += sizeof(ngx_resolver_an_t);

        switch (type) {

        case NGX_RESOLVE_PTR:

            goto ptr;

        case NGX_RESOLVE_CNAME:

            break;

        default:

            ngx_log_error(r->log_level, r->log, 0,
                          "unexpected RR type %ui in DNS response", type);
        }

        i += len;
    }

    /* unlock addr mutex */

    ngx_log_error(r->log_level, r->log, 0,
                  "no PTR type in DNS response");
    return;

ptr:

    if (ngx_resolver_copy(r, &name, buf, buf + i, buf + n) != NGX_OK) {
        goto failed;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, r->log, 0, "resolver an:%V", &name);

    if (name.len != (size_t) rn->nlen
        || ngx_strncmp(name.data, rn->name, name.len) != 0)
    {
        if (rn->nlen) {
            ngx_resolver_free(r, rn->name);
        }

        rn->nlen = (u_short) name.len;
        rn->name = name.data;

        name.data = ngx_resolver_dup(r, rn->name, name.len);
        if (name.data == NULL) {
            goto failed;
        }
    }

    ngx_queue_remove(&rn->queue);

#if (NGX_RESTY_EXT)
    ngx_resolver_query_success(r, rn);
    rn->valid = ngx_resolver_valid(r, ttl);
#else
    rn->valid = ngx_time() + (r->valid ? r->valid : ttl);
#endif

    rn->expire = ngx_time() + r->expire;

    ngx_queue_insert_head(expire_queue, &rn->queue);

    next = rn->waiting;
    rn->waiting = NULL;

    /* unlock addr mutex */

    while (next) {
        ctx = next;
        ctx->state = NGX_OK;
        ctx->valid = rn->valid;
        ctx->name = name;
        next = ctx->next;

        ctx->handler(ctx);
    }

    ngx_resolver_free(r, name.data);

    return;

short_response:

    err = "short DNS response";

invalid:

    /* unlock addr mutex */

    ngx_log_error(r->log_level, r->log, 0, err);

    return;

failed:

    /* unlock addr mutex */

    return;
}


static ngx_resolver_node_t *
ngx_resolver_lookup_name(ngx_resolver_t *r, ngx_str_t *name, uint32_t hash)
{
    ngx_int_t             rc;
    ngx_rbtree_node_t    *node, *sentinel;
    ngx_resolver_node_t  *rn;

    node = r->name_rbtree.root;
    sentinel = r->name_rbtree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        rn = ngx_resolver_node(node);

        rc = ngx_memn2cmp(name->data, rn->name, name->len, rn->nlen);

        if (rc == 0) {
            return rn;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    /* not found */

    return NULL;
}


static ngx_resolver_node_t *
ngx_resolver_lookup_srv(ngx_resolver_t *r, ngx_str_t *name, uint32_t hash)
{
    ngx_int_t             rc;
    ngx_rbtree_node_t    *node, *sentinel;
    ngx_resolver_node_t  *rn;

    node = r->srv_rbtree.root;
    sentinel = r->srv_rbtree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        rn = ngx_resolver_node(node);

        rc = ngx_memn2cmp(name->data, rn->name, name->len, rn->nlen);

        if (rc == 0) {
            return rn;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    /* not found */

    return NULL;
}


static ngx_resolver_node_t *
ngx_resolver_lookup_addr(ngx_resolver_t *r, in_addr_t addr)
{
    ngx_rbtree_node_t  *node, *sentinel;

    node = r->addr_rbtree.root;
    sentinel = r->addr_rbtree.sentinel;

    while (node != sentinel) {

        if (addr < node->key) {
            node = node->left;
            continue;
        }

        if (addr > node->key) {
            node = node->right;
            continue;
        }

        /* addr == node->key */

        return ngx_resolver_node(node);
    }

    /* not found */

    return NULL;
}


#if (NGX_HAVE_INET6)

static ngx_resolver_node_t *
ngx_resolver_lookup_addr6(ngx_resolver_t *r, struct in6_addr *addr,
    uint32_t hash)
{
    ngx_int_t             rc;
    ngx_rbtree_node_t    *node, *sentinel;
    ngx_resolver_node_t  *rn;

    node = r->addr6_rbtree.root;
    sentinel = r->addr6_rbtree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        rn = ngx_resolver_node(node);

        rc = ngx_memcmp(addr, &rn->addr6, 16);

        if (rc == 0) {
            return rn;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    /* not found */

    return NULL;
}

#endif


static void
ngx_resolver_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t    **p;
    ngx_resolver_node_t   *rn, *rn_temp;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            rn = ngx_resolver_node(node);
            rn_temp = ngx_resolver_node(temp);

            p = (ngx_memn2cmp(rn->name, rn_temp->name, rn->nlen, rn_temp->nlen)
                 < 0) ? &temp->left : &temp->right;

#if (NGX_RESTY_EXT)

            if (rn->retry_mask != rn_temp->retry_mask
                && rn->nlen == rn_temp->nlen
                && ngx_strncmp(rn->name, rn_temp->name, rn->nlen) == 0)
            {
                p = (rn->retry_mask < rn_temp->retry_mask)
                    ? &temp->left : &temp->right;
            }

#endif
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


#if (NGX_HAVE_INET6)

static void
ngx_resolver_rbtree_insert_addr6_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t    **p;
    ngx_resolver_node_t   *rn, *rn_temp;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            rn = ngx_resolver_node(node);
            rn_temp = ngx_resolver_node(temp);

            p = (ngx_memcmp(&rn->addr6, &rn_temp->addr6, 16)
                 < 0) ? &temp->left : &temp->right;

#if (NGX_RESTY_EXT)

            if (rn->retry_mask != rn_temp->retry_mask
                && ngx_memcmp(&rn->addr6, &rn_temp->addr6, 16) == 0)
            {
                p = (rn->retry_mask < rn_temp->retry_mask)
                    ? &temp->left : &temp->right;
            }

#endif
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}

#endif


static ngx_int_t
ngx_resolver_create_name_query(ngx_resolver_t *r, ngx_resolver_node_t *rn,
    ngx_str_t *name)
{
    u_char              *p, *s;
    size_t               len, nlen;
    ngx_uint_t           ident;
    ngx_resolver_qs_t   *qs;
    ngx_resolver_hdr_t  *query;

    nlen = name->len ? (1 + name->len + 1) : 1;

    len = sizeof(ngx_resolver_hdr_t) + nlen + sizeof(ngx_resolver_qs_t);

#if (NGX_HAVE_INET6)
    p = ngx_resolver_alloc(r, len * (r->ipv4 + r->ipv6));
#else
    p = ngx_resolver_alloc(r, len);
#endif
    if (p == NULL) {
        return NGX_ERROR;
    }

    rn->qlen = (u_short) len;
    rn->query = p;

#if (NGX_HAVE_INET6)
    if (r->ipv6) {
        rn->query6 = r->ipv4 ? (p + len) : p;
    }
#endif

    query = (ngx_resolver_hdr_t *) p;

    if (r->ipv4) {
        ident = ngx_random();

#if (NGX_RESTY_EXT)
        if (ngx_resolver_get_ident(r, &ident) != NGX_OK) {
            return NGX_ERROR;
        }
#endif

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, r->log, 0,
                       "resolve: \"%V\" A %i", name, ident & 0xffff);

        query->ident_hi = (u_char) ((ident >> 8) & 0xff);
        query->ident_lo = (u_char) (ident & 0xff);
    }

    /* recursion query */
    query->flags_hi = 1; query->flags_lo = 0;

    /* one question */
    query->nqs_hi = 0; query->nqs_lo = 1;
    query->nan_hi = 0; query->nan_lo = 0;
    query->nns_hi = 0; query->nns_lo = 0;
    query->nar_hi = 0; query->nar_lo = 0;

    p += sizeof(ngx_resolver_hdr_t) + nlen;

    qs = (ngx_resolver_qs_t *) p;

    /* query type */
    qs->type_hi = 0; qs->type_lo = NGX_RESOLVE_A;

    /* IN query class */
    qs->class_hi = 0; qs->class_lo = 1;

    /* convert "www.example.com" to "\3www\7example\3com\0" */

    len = 0;
    p--;
    *p-- = '\0';

    if (name->len == 0)  {
        return NGX_DECLINED;
    }

    for (s = name->data + name->len - 1; s >= name->data; s--) {
        if (*s != '.') {
            *p = *s;
            len++;

        } else {
            if (len == 0 || len > 255) {
                return NGX_DECLINED;
            }

            *p = (u_char) len;
            len = 0;
        }

        p--;
    }

    if (len == 0 || len > 255) {
        return NGX_DECLINED;
    }

    *p = (u_char) len;

#if (NGX_HAVE_INET6)
    if (!r->ipv6) {
        return NGX_OK;
    }

    p = rn->query6;

    if (r->ipv4) {
        ngx_memcpy(p, rn->query, rn->qlen);
    }

    query = (ngx_resolver_hdr_t *) p;

    ident = ngx_random();

#if (NGX_RESTY_EXT)
    if (ngx_resolver_get_ident(r, &ident) != NGX_OK) {
        return NGX_ERROR;
    }
#endif

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, r->log, 0,
                   "resolve: \"%V\" AAAA %i", name, ident & 0xffff);

    query->ident_hi = (u_char) ((ident >> 8) & 0xff);
    query->ident_lo = (u_char) (ident & 0xff);

    p += sizeof(ngx_resolver_hdr_t) + nlen;

    qs = (ngx_resolver_qs_t *) p;

    qs->type_lo = NGX_RESOLVE_AAAA;
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_resolver_create_srv_query(ngx_resolver_t *r, ngx_resolver_node_t *rn,
    ngx_str_t *name)
{
    u_char              *p, *s;
    size_t               len, nlen;
    ngx_uint_t           ident;
    ngx_resolver_qs_t   *qs;
    ngx_resolver_hdr_t  *query;

    nlen = name->len ? (1 + name->len + 1) : 1;

    len = sizeof(ngx_resolver_hdr_t) + nlen + sizeof(ngx_resolver_qs_t);

    p = ngx_resolver_alloc(r, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    rn->qlen = (u_short) len;
    rn->query = p;

    query = (ngx_resolver_hdr_t *) p;

    ident = ngx_random();

#if (NGX_RESTY_EXT)
    if (ngx_resolver_get_ident(r, &ident) != NGX_OK) {
        return NGX_ERROR;
    }
#endif

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, r->log, 0,
                   "resolve: \"%V\" SRV %i", name, ident & 0xffff);

    query->ident_hi = (u_char) ((ident >> 8) & 0xff);
    query->ident_lo = (u_char) (ident & 0xff);

    /* recursion query */
    query->flags_hi = 1; query->flags_lo = 0;

    /* one question */
    query->nqs_hi = 0; query->nqs_lo = 1;
    query->nan_hi = 0; query->nan_lo = 0;
    query->nns_hi = 0; query->nns_lo = 0;
    query->nar_hi = 0; query->nar_lo = 0;

    p += sizeof(ngx_resolver_hdr_t) + nlen;

    qs = (ngx_resolver_qs_t *) p;

    /* query type */
    qs->type_hi = 0; qs->type_lo = NGX_RESOLVE_SRV;

    /* IN query class */
    qs->class_hi = 0; qs->class_lo = 1;

    /* converts "www.example.com" to "\3www\7example\3com\0" */

    len = 0;
    p--;
    *p-- = '\0';

    if (name->len == 0)  {
        return NGX_DECLINED;
    }

    for (s = name->data + name->len - 1; s >= name->data; s--) {
        if (*s != '.') {
            *p = *s;
            len++;

        } else {
            if (len == 0 || len > 255) {
                return NGX_DECLINED;
            }

            *p = (u_char) len;
            len = 0;
        }

        p--;
    }

    if (len == 0 || len > 255) {
        return NGX_DECLINED;
    }

    *p = (u_char) len;

    return NGX_OK;
}


static ngx_int_t
ngx_resolver_create_addr_query(ngx_resolver_t *r, ngx_resolver_node_t *rn,
    ngx_resolver_addr_t *addr)
{
    u_char               *p, *d;
    size_t                len;
    in_addr_t             inaddr;
    ngx_int_t             n;
    ngx_uint_t            ident;
    ngx_resolver_hdr_t   *query;
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    switch (addr->sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        len = sizeof(ngx_resolver_hdr_t)
              + 64 + sizeof(".ip6.arpa.") - 1
              + sizeof(ngx_resolver_qs_t);

        break;
#endif

    default: /* AF_INET */
        len = sizeof(ngx_resolver_hdr_t)
              + sizeof(".255.255.255.255.in-addr.arpa.") - 1
              + sizeof(ngx_resolver_qs_t);
    }

    p = ngx_resolver_alloc(r, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    rn->query = p;
    query = (ngx_resolver_hdr_t *) p;

    ident = ngx_random();

#if (NGX_RESTY_EXT)
    if (ngx_resolver_get_ident(r, &ident) != NGX_OK) {
        return NGX_ERROR;
    }
#endif

    query->ident_hi = (u_char) ((ident >> 8) & 0xff);
    query->ident_lo = (u_char) (ident & 0xff);

    /* recursion query */
    query->flags_hi = 1; query->flags_lo = 0;

    /* one question */
    query->nqs_hi = 0; query->nqs_lo = 1;
    query->nan_hi = 0; query->nan_lo = 0;
    query->nns_hi = 0; query->nns_lo = 0;
    query->nar_hi = 0; query->nar_lo = 0;

    p += sizeof(ngx_resolver_hdr_t);

    switch (addr->sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) addr->sockaddr;

        for (n = 15; n >= 0; n--) {
            p = ngx_sprintf(p, "\1%xd\1%xd",
                            sin6->sin6_addr.s6_addr[n] & 0xf,
                            (sin6->sin6_addr.s6_addr[n] >> 4) & 0xf);
        }

        p = ngx_cpymem(p, "\3ip6\4arpa\0", 10);

        break;
#endif

    default: /* AF_INET */

        sin = (struct sockaddr_in *) addr->sockaddr;
        inaddr = ntohl(sin->sin_addr.s_addr);

        for (n = 0; n < 32; n += 8) {
            d = ngx_sprintf(&p[1], "%ud", (inaddr >> n) & 0xff);
            *p = (u_char) (d - &p[1]);
            p = d;
        }

        p = ngx_cpymem(p, "\7in-addr\4arpa\0", 14);
    }

    /* query type "PTR", IN query class */
    p = ngx_cpymem(p, "\0\14\0\1", 4);

    rn->qlen = (u_short) (p - rn->query);

    return NGX_OK;
}


static ngx_int_t
ngx_resolver_copy(ngx_resolver_t *r, ngx_str_t *name, u_char *buf, u_char *src,
    u_char *last)
{
    char        *err;
    u_char      *p, *dst;
    size_t       len;
    ngx_uint_t   i, n;

    p = src;
    len = 0;

    /*
     * compression pointers allow to create endless loop, so we set limit;
     * 128 pointers should be enough to store 255-byte name
     */

    for (i = 0; i < 128; i++) {
        n = *p++;

        if (n == 0) {
            goto done;
        }

        if (n & 0xc0) {
            if ((n & 0xc0) != 0xc0) {
                err = "invalid label type in DNS response";
                goto invalid;
            }

            if (p >= last) {
                err = "name is out of DNS response";
                goto invalid;
            }

            n = ((n & 0x3f) << 8) + *p;
            p = &buf[n];

        } else {
            len += 1 + n;
            p = &p[n];
        }

        if (p >= last) {
            err = "name is out of DNS response";
            goto invalid;
        }
    }

    err = "compression pointers loop in DNS response";

invalid:

    ngx_log_error(r->log_level, r->log, 0, err);

    return NGX_ERROR;

done:

    if (name == NULL) {
        return NGX_OK;
    }

    if (len == 0) {
        ngx_str_null(name);
        return NGX_OK;
    }

    dst = ngx_resolver_alloc(r, len);
    if (dst == NULL) {
        return NGX_ERROR;
    }

    name->data = dst;

    for ( ;; ) {
        n = *src++;

        if (n == 0) {
            name->len = dst - name->data - 1;
            return NGX_OK;
        }

        if (n & 0xc0) {
            n = ((n & 0x3f) << 8) + *src;
            src = &buf[n];

        } else {
            ngx_strlow(dst, src, n);
            dst += n;
            src += n;
            *dst++ = '.';
        }
    }
}


static ngx_int_t
ngx_resolver_set_timeout(ngx_resolver_t *r, ngx_resolver_ctx_t *ctx)
{
    if (ctx->event || ctx->timeout == 0) {
        return NGX_OK;
    }

    ctx->event = ngx_resolver_calloc(r, sizeof(ngx_event_t));
    if (ctx->event == NULL) {
        return NGX_ERROR;
    }

    ctx->event->handler = ngx_resolver_timeout_handler;
    ctx->event->data = ctx;
    ctx->event->log = r->log;
    ctx->event->cancelable = ctx->cancelable;
    ctx->ident = -1;

    ngx_add_timer(ctx->event, ctx->timeout);

    return NGX_OK;
}


static void
ngx_resolver_timeout_handler(ngx_event_t *ev)
{
    ngx_resolver_ctx_t  *ctx;

    ctx = ev->data;

#if (NGX_RESTY_EXT)
    ngx_resolver_cache_timeout(ctx);
#endif

    ctx->state = NGX_RESOLVE_TIMEDOUT;

    ctx->handler(ctx);
}


static void
ngx_resolver_free_node(ngx_resolver_t *r, ngx_resolver_node_t *rn)
{
    ngx_uint_t  i;

    /* lock alloc mutex */

    if (rn->query) {
        ngx_resolver_free_locked(r, rn->query);
    }

    if (rn->name) {
        ngx_resolver_free_locked(r, rn->name);
    }

    if (rn->cnlen) {
        ngx_resolver_free_locked(r, rn->u.cname);
    }

    if (rn->naddrs > 1 && rn->naddrs != (u_short) -1) {
        ngx_resolver_free_locked(r, rn->u.addrs);
    }

#if (NGX_HAVE_INET6)
    if (rn->naddrs6 > 1 && rn->naddrs6 != (u_short) -1) {
        ngx_resolver_free_locked(r, rn->u6.addrs6);
    }
#endif

    if (rn->nsrvs) {
        for (i = 0; i < (ngx_uint_t) rn->nsrvs; i++) {
            if (rn->u.srvs[i].name.data) {
                ngx_resolver_free_locked(r, rn->u.srvs[i].name.data);
            }
        }

        ngx_resolver_free_locked(r, rn->u.srvs);
    }

#if (NGX_RESTY_EXT)
    ngx_resolver_free_node_state(r, rn);
    ngx_resolver_free_cache(r, rn);
#endif

    ngx_resolver_free_locked(r, rn);

    /* unlock alloc mutex */
}


static void *
ngx_resolver_alloc(ngx_resolver_t *r, size_t size)
{
    u_char  *p;

    /* lock alloc mutex */

    p = ngx_alloc(size, r->log);

    /* unlock alloc mutex */

    return p;
}


static void *
ngx_resolver_calloc(ngx_resolver_t *r, size_t size)
{
    u_char  *p;

    p = ngx_resolver_alloc(r, size);

    if (p) {
        ngx_memzero(p, size);
    }

    return p;
}


static void
ngx_resolver_free(ngx_resolver_t *r, void *p)
{
    /* lock alloc mutex */

    ngx_free(p);

    /* unlock alloc mutex */
}


static void
ngx_resolver_free_locked(ngx_resolver_t *r, void *p)
{
    ngx_free(p);
}


static void *
ngx_resolver_dup(ngx_resolver_t *r, void *src, size_t size)
{
    void  *dst;

    dst = ngx_resolver_alloc(r, size);

    if (dst == NULL) {
        return dst;
    }

    ngx_memcpy(dst, src, size);

    return dst;
}


static ngx_resolver_addr_t *
ngx_resolver_export(ngx_resolver_t *r, ngx_resolver_node_t *rn,
    ngx_uint_t rotate)
{
    ngx_uint_t            d, i, j, n;
    in_addr_t            *addr;
    ngx_sockaddr_t       *sockaddr;
    struct sockaddr_in   *sin;
    ngx_resolver_addr_t  *dst;
#if (NGX_HAVE_INET6)
    struct in6_addr      *addr6;
    struct sockaddr_in6  *sin6;
#endif

    n = rn->naddrs;
#if (NGX_HAVE_INET6)
    n += rn->naddrs6;
#endif

    dst = ngx_resolver_calloc(r, n * sizeof(ngx_resolver_addr_t));
    if (dst == NULL) {
        return NULL;
    }

    sockaddr = ngx_resolver_calloc(r, n * sizeof(ngx_sockaddr_t));
    if (sockaddr == NULL) {
        ngx_resolver_free(r, dst);
        return NULL;
    }

    i = 0;
    d = rotate ? ngx_random() % n : 0;

    if (rn->naddrs) {
        j = rotate ? ngx_random() % rn->naddrs : 0;

        addr = (rn->naddrs == 1) ? &rn->u.addr : rn->u.addrs;

        do {
            sin = &sockaddr[d].sockaddr_in;
            sin->sin_family = AF_INET;
            sin->sin_addr.s_addr = addr[j++];
            dst[d].sockaddr = (struct sockaddr *) sin;
            dst[d++].socklen = sizeof(struct sockaddr_in);

            if (d == n) {
                d = 0;
            }

            if (j == (ngx_uint_t) rn->naddrs) {
                j = 0;
            }
        } while (++i < (ngx_uint_t) rn->naddrs);
    }

#if (NGX_HAVE_INET6)
    if (rn->naddrs6) {
        j = rotate ? ngx_random() % rn->naddrs6 : 0;

        addr6 = (rn->naddrs6 == 1) ? &rn->u6.addr6 : rn->u6.addrs6;

        do {
            sin6 = &sockaddr[d].sockaddr_in6;
            sin6->sin6_family = AF_INET6;
            ngx_memcpy(sin6->sin6_addr.s6_addr, addr6[j++].s6_addr, 16);
            dst[d].sockaddr = (struct sockaddr *) sin6;
            dst[d++].socklen = sizeof(struct sockaddr_in6);

            if (d == n) {
                d = 0;
            }

            if (j == rn->naddrs6) {
                j = 0;
            }
        } while (++i < n);
    }
#endif

    return dst;
}


static void
ngx_resolver_report_srv(ngx_resolver_t *r, ngx_resolver_ctx_t *ctx)
{
    ngx_uint_t                naddrs, nsrvs, nw, i, j, k, l, m, n, w;
    ngx_resolver_addr_t      *addrs;
    ngx_resolver_srv_name_t  *srvs;

    srvs = ctx->srvs;
    nsrvs = ctx->nsrvs;

    naddrs = 0;

    for (i = 0; i < nsrvs; i++) {
        if (srvs[i].state == NGX_ERROR) {
            ctx->state = NGX_ERROR;
            ctx->valid = ngx_time() + (r->valid ? r->valid : 10);

            ctx->handler(ctx);
            return;
        }

        naddrs += srvs[i].naddrs;
    }

    if (naddrs == 0) {
        ctx->state = srvs[0].state;

        for (i = 0; i < nsrvs; i++) {
            if (srvs[i].state == NGX_RESOLVE_NXDOMAIN) {
                ctx->state = NGX_RESOLVE_NXDOMAIN;
                break;
            }
        }

        ctx->valid = ngx_time() + (r->valid ? r->valid : 10);

        ctx->handler(ctx);
        return;
    }

    addrs = ngx_resolver_calloc(r, naddrs * sizeof(ngx_resolver_addr_t));
    if (addrs == NULL) {
        ctx->state = NGX_ERROR;
        ctx->valid = ngx_time() + (r->valid ? r->valid : 10);

        ctx->handler(ctx);
        return;
    }

    i = 0;
    n = 0;

    do {
        nw = 0;

        for (j = i; j < nsrvs; j++) {
            if (srvs[j].priority != srvs[i].priority) {
                break;
            }

            nw += srvs[j].naddrs * srvs[j].weight;
        }

        if (nw == 0) {
            goto next_srv;
        }

        w = ngx_random() % nw;

        for (k = i; k < j; k++) {
            if (w < srvs[k].naddrs * srvs[k].weight) {
                break;
            }

            w -= srvs[k].naddrs * srvs[k].weight;
        }

        for (l = i; l < j; l++) {

            for (m = 0; m < srvs[k].naddrs; m++) {
                addrs[n].socklen = srvs[k].addrs[m].socklen;
                addrs[n].sockaddr = srvs[k].addrs[m].sockaddr;
                addrs[n].name = srvs[k].name;
                addrs[n].priority = srvs[k].priority;
                addrs[n].weight = srvs[k].weight;
                n++;
            }

            if (++k == j) {
                k = i;
            }
        }

next_srv:

        i = j;

    } while (i < ctx->nsrvs);

    ctx->state = NGX_OK;
    ctx->addrs = addrs;
    ctx->naddrs = naddrs;

    ctx->handler(ctx);

    ngx_resolver_free(r, addrs);
}


#if (NGX_RESTY_EXT)

static time_t
ngx_resolver_valid(ngx_resolver_t *r, time_t ttl)
{
    if (r->valid) {
        return ngx_time() + r->valid;
    }

    if (r->min_ttl || r->max_ttl) {
        ttl = ngx_max(ttl, r->min_ttl);

        if (r->max_ttl) {
            ttl = ngx_min(ttl, r->max_ttl);
        }
    }

    return ngx_time() + ttl;
}


static ngx_int_t
ngx_resolver_init_query_state(ngx_resolver_ctx_t *ctx)
{
    ngx_resolver_t  *r;

    r = ctx->resolver;

    if (ctx->query_state) {
        return NGX_OK;
    }

    if (ctx->retry == NULL && !r->nameserver
        && r->negative_valid == 0 && r->error_valid == 0
        && r->stale_valid == 0)
    {
        return NGX_OK;
    }

    return ngx_resolver_alloc_query_state(ctx, NULL);
}


static ngx_int_t
ngx_resolver_alloc_query_state(ngx_resolver_ctx_t *ctx,
    ngx_resolver_budget_t *budget)
{
    ngx_resolver_t              *r;
    ngx_resolver_query_state_t  *qs;

    r = ctx->resolver;

    qs = ngx_resolver_calloc(r, sizeof(ngx_resolver_query_state_t));
    if (qs == NULL) {
        return NGX_ERROR;
    }

    if (budget == NULL) {
        budget = ngx_resolver_calloc(r, sizeof(ngx_resolver_budget_t));
        if (budget == NULL) {
            ngx_resolver_free(r, qs);
            return NGX_ERROR;
        }
    }

    budget->references++;
    qs->budget = budget;
    qs->event.handler = ngx_resolver_query_handler;
    qs->event.data = ctx;
    qs->event.log = r->log;
    qs->event.cancelable = ctx->cancelable;
    ctx->query_state = qs;
    ngx_queue_insert_head(&r->contexts, &qs->queue);

    return NGX_OK;
}


static void
ngx_resolver_free_query_state(ngx_resolver_ctx_t *ctx)
{
    ngx_resolver_cache_t        *cache;
    ngx_resolver_query_state_t  *qs;

    qs = ctx->query_state;

    if (qs == NULL) {
        return;
    }

    if (ctx->handler == ngx_resolver_srv_names_handler) {
        ctx->srvs->ctx = NULL;
    }

    if (qs->event.posted) {
        ngx_delete_posted_event(&qs->event);
    }

    if (qs->event.timer_set) {
        ngx_del_timer(&qs->event);
    }

    if (--qs->budget->references == 0) {
        ngx_resolver_free(ctx->resolver, qs->budget);
    }

    ngx_queue_remove(&qs->queue);

    if (qs->refresh_node) {
        cache = qs->refresh_node->cache;
        cache->refresh_ctx = NULL;

        if (ctx->state != NGX_OK) {
            cache->refresh_after =
                ngx_time() + (ctx->resolver->error_valid
                              ? ctx->resolver->error_valid
                              : ctx->resolver->resend_timeout);

        } else if (cache->error == 0 && cache->stale == NULL) {
            ngx_resolver_free_cache(ctx->resolver, qs->refresh_node);
        }
    }

    ngx_resolver_free(ctx->resolver, qs->service);
    ngx_resolver_free(ctx->resolver, qs->original_name);
    ngx_resolver_free(ctx->resolver, qs->address);
    ngx_resolver_free(ctx->resolver, qs);
}


static ngx_int_t
ngx_resolver_prepare_query(ngx_resolver_t *r, ngx_resolver_node_t *rn,
    ngx_resolver_ctx_t *ctx)
{
    size_t                      size;
    ngx_resolver_node_state_t  *ns;

    if (ctx->query_state == NULL) {
        return NGX_OK;
    }

    size = sizeof(ngx_resolver_node_state_t)
           + ((r->connections.nelts + 8 * sizeof(uintptr_t) - 1)
              / (8 * sizeof(uintptr_t))) * sizeof(uintptr_t);

    ns = rn->state;

    if (ns == NULL) {
        ns = ngx_resolver_calloc(r, size);
        if (ns == NULL) {
            return NGX_ERROR;
        }

        rn->state = ns;
    }

    ngx_resolver_remove_queries(r, rn);

    if (ns->event.posted) {
        ngx_delete_posted_event(&ns->event);
    }

    if (rn->cache) {
        rn->cache->error = 0;
        rn->cache->nxdomain = 0;
        rn->cache->refresh_after = 0;
    }

    ngx_memzero(ns, size);
    ns->tried = (uintptr_t *) (ns + 1);
    ns->event.handler = ngx_resolver_attempt_handler;
    ns->event.data = rn;
    ns->event.log = r->log;
    ns->event.cancelable = 1;
    ns->reverse = ctx->query_state->reverse;
    ns->retry = ctx->retry != NULL || r->nameserver;
    ns->negative_valid = 0;

    if (ns->reverse) {
        ns->tree = &r->addr_rbtree;
        ns->resend_queue = &r->addr_resend_queue;
        ns->expire_queue = &r->addr_expire_queue;
#if (NGX_HAVE_INET6)
        if (ctx->addr.sockaddr->sa_family == AF_INET6) {
            ns->tree = &r->addr6_rbtree;
            ns->resend_queue = &r->addr6_resend_queue;
            ns->expire_queue = &r->addr6_expire_queue;
        }
#endif

    } else if (ctx->service.len) {
        ns->tree = &r->srv_rbtree;
        ns->resend_queue = &r->srv_resend_queue;
        ns->expire_queue = &r->srv_expire_queue;

    } else {
        ns->tree = &r->name_rbtree;
        ns->resend_queue = &r->name_resend_queue;
        ns->expire_queue = &r->name_expire_queue;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_resolver_check_budget(ngx_resolver_ctx_t *ctx)
{
    ngx_resolver_t         *retry;
    ngx_resolver_budget_t  *budget;

    if (ctx->query_state == NULL) {
        return NGX_OK;
    }

    retry = ctx->retry;
    budget = ctx->query_state->budget;

    if (retry && budget->tries) {
        if (retry->next_nameserver_tries
            && budget->tries >= retry->next_nameserver_tries)
        {
            return NGX_DECLINED;
        }

        if (retry->next_nameserver_timeout
            && ngx_current_msec - budget->start
               >= retry->next_nameserver_timeout)
        {
            return NGX_DECLINED;
        }
    }

    return NGX_OK;
}


static void
ngx_resolver_charge_query(ngx_resolver_ctx_t *ctx, ngx_uint_t sequence)
{
    ngx_resolver_budget_t  *budget;

    if (ctx->query_state == NULL) {
        return;
    }

    budget = ctx->query_state->budget;

    if (budget->sequence == sequence) {
        return;
    }

    if (budget->tries == 0) {
        budget->start = ngx_current_msec;
    }

    budget->sequence = sequence;
    budget->tries++;
}


static void
ngx_resolver_finish_query(ngx_resolver_ctx_t *ctx, ngx_int_t code)
{
    ngx_resolver_query_state_t  *qs;

    qs = ctx->query_state;

    if (ctx->event && ctx->event->timer_set) {
        ngx_del_timer(ctx->event);
    }

    if (qs->event.timer_set) {
        ngx_del_timer(&qs->event);
    }

    qs->last_result = code;
    qs->event.handler = ngx_resolver_query_handler;
    ctx->node = NULL;
    ctx->next = NULL;
    ctx->state = NGX_ERROR;

    ngx_post_event(&qs->event, &ngx_posted_events);
}


static void
ngx_resolver_query_handler(ngx_event_t *ev)
{
    ngx_resolver_ctx_t  *ctx;

    ctx = ev->data;
    ctx->state = ctx->query_state->last_result;
    ctx->valid = ngx_time() + (ctx->resolver->valid
                              ? ctx->resolver->valid : 10);

    ctx->handler(ctx);
}


static ngx_uint_t
ngx_resolver_all_failed(ngx_resolver_t *r)
{
    time_t                      now;
    ngx_uint_t                  i;
    ngx_resolver_peer_t        *peer;
    ngx_resolver_connection_t  *rec;

    rec = r->connections.elts;
    now = ngx_time();

    for (i = 0; i < r->connections.nelts; i++) {
        peer = rec[i].peer;

        if (peer->max_fails == 0 || peer->fails < peer->max_fails
            || now - peer->accessed > peer->fail_timeout)
        {
            return 0;
        }
    }

    return 1;
}


static ngx_uint_t
ngx_resolver_select_peer(ngx_resolver_t *r, ngx_resolver_node_t *rn,
    ngx_uint_t first)
{
    time_t                      now;
    uintptr_t                   mask;
    ngx_int_t                   total;
    ngx_uint_t                  i, best, n, ignore;
    ngx_resolver_peer_t        *peer;
    ngx_resolver_connection_t  *rec;

    rec = r->connections.elts;
    total = 0;
    best = NGX_CONF_UNSET_UINT;
    now = ngx_time();
    ignore = ngx_resolver_all_failed(r);

    for (i = first; i < r->connections.nelts; i++) {
        peer = rec[i].peer;

        if (best != NGX_CONF_UNSET_UINT && peer->level != rec[best].peer->level)
        {
            break;
        }

        n = i / (8 * sizeof(uintptr_t));
        mask = (uintptr_t) 1 << (i % (8 * sizeof(uintptr_t)));

        if (rn->state && (rn->state->tried[n] & mask)) {
            continue;
        }

        if (!ignore && peer->max_fails && peer->fails >= peer->max_fails
            && now - peer->accessed <= peer->fail_timeout)
        {
            continue;
        }

        peer->current_weight += peer->weight;
        total += peer->weight;

        if (best == NGX_CONF_UNSET_UINT
            || peer->current_weight > rec[best].peer->current_weight)
        {
            best = i;
        }
    }

    if (best != NGX_CONF_UNSET_UINT) {
        rec[best].peer->current_weight -= total;
    }

    return best;
}


static ngx_int_t
ngx_resolver_start_query(ngx_resolver_t *r, ngx_resolver_node_t *rn)
{
    size_t               size;
    uintptr_t            mask;
    ngx_uint_t           i, sequence;
    ngx_resolver_ctx_t  *ctx, **p;

    if (rn->state->pending) {
        rn->state->pending = 0;

        for (ctx = rn->waiting; ctx; ctx = ctx->next) {
            if (ctx->query_state) {
                ctx->query_state->budget->failures = 0;
            }
        }
    }

    sequence = ++ngx_resolver_sequence;

    if (sequence == 0) {
        sequence = ++ngx_resolver_sequence;
    }

    rn->state->sequence = sequence;

    for (p = &rn->waiting; *p; /* void */) {
        ctx = *p;

        if (ctx->query_state && ctx->query_state->event.timer_set
            && ctx->query_state->event.handler
               == ngx_resolver_retry_timeout_handler)
        {
            ngx_del_timer(&ctx->query_state->event);
        }

        if (ngx_resolver_check_budget(ctx) != NGX_OK) {
            *p = ctx->next;
            ngx_resolver_finish_query(ctx,
                                      ctx->query_state->last_valid
                                      ? ctx->query_state->last_result
                                      : NGX_RESOLVE_TIMEDOUT);
            continue;
        }

        ngx_resolver_charge_query(ctx, sequence);
        p = &ctx->next;
    }

    if (rn->waiting == NULL) {
        ngx_resolver_cache_failure(r, rn);
        return NGX_OK;
    }

    if (rn->state->restart) {
        rn->state->restart = 0;

        size = ((r->connections.nelts + 8 * sizeof(uintptr_t) - 1)
                / (8 * sizeof(uintptr_t))) * sizeof(uintptr_t);
        ngx_memzero(rn->state->tried, size);

        if (r->nameserver) {
            rn->last_connection = ngx_resolver_select_peer(r, rn, 0);
        }
    }

    i = rn->last_connection / (8 * sizeof(uintptr_t));
    mask = (uintptr_t) 1 << (rn->last_connection % (8 * sizeof(uintptr_t)));
    rn->state->tried[i] |= mask;
    rn->state->tries++;
    rn->state->started = 1;

    if (ngx_resolver_register_queries(r, rn) != NGX_OK) {
        while (rn->waiting) {
            ctx = rn->waiting;
            rn->waiting = ctx->next;
            ngx_resolver_finish_query(ctx, NGX_ERROR);
        }

        return NGX_ERROR;
    }

    if (ngx_resolver_send_query(r, rn) != NGX_OK) {
        return ngx_resolver_next(r, rn, NGX_RESOLVER_FT_ERROR, NGX_ERROR);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_resolver_next(ngx_resolver_t *r, ngx_resolver_node_t *rn,
    ngx_uint_t condition, ngx_int_t code)
{
    ngx_uint_t                  mask, first, next, round, delay;
    ngx_resolver_ctx_t         *ctx, **p;
    ngx_resolver_budget_t      *budget;
    ngx_resolver_connection_t  *rec;

    mask = rn->retry_mask ? rn->retry_mask : NGX_RESOLVER_FT_DEFAULT;
    rn->state->failure = condition;
    rn->state->last_result = code;

    if (rn->state->tries) {
        for (ctx = rn->waiting; ctx; ctx = ctx->next) {
            if (ctx->query_state) {
                ctx->query_state->last_result = code;
                ctx->query_state->last_valid = 1;
            }
        }
    }

    if (condition == NGX_RESOLVER_FT_ERROR
        || condition == NGX_RESOLVER_FT_TIMEOUT)
    {
        ngx_resolver_peer_failed(r, rn);
    }

    if (rn->last_connection != NGX_CONF_UNSET_UINT
        && (!(mask & condition) || (mask & NGX_RESOLVER_FT_OFF)))
    {
        if (condition != NGX_RESOLVER_FT_TIMEOUT
            && condition != NGX_RESOLVER_FT_ERROR)
        {
            return NGX_DECLINED;
        }

        while (rn->waiting) {
            ctx = rn->waiting;
            rn->waiting = ctx->next;
            ngx_resolver_finish_query(ctx, code);
        }

        return NGX_OK;
    }

    delay = 0;

    for (p = &rn->waiting; *p; /* void */) {
        ctx = *p;

        if (ngx_resolver_check_budget(ctx) != NGX_OK) {
            *p = ctx->next;
            ngx_resolver_finish_query(ctx, code);
            continue;
        }

        if (ctx->query_state) {
            budget = ctx->query_state->budget;

            if (condition == NGX_RESOLVER_FT_ERROR && rn->state->tries) {
                if (budget->failure_sequence != rn->state->sequence) {
                    budget->failure_sequence = rn->state->sequence;
                    budget->failures++;
                }

                delay |= budget->failures >= 2;

            } else if (condition != NGX_RESOLVER_FT_ERROR) {
                budget->failures = 0;
            }
        }

        p = &ctx->next;
    }

    if (rn->waiting == NULL) {
        ngx_resolver_cache_failure(r, rn);
        return NGX_OK;
    }

    if (r->nameserver) {
        rec = r->connections.elts;
        first = rec[rn->last_connection].peer->level_start;
        next = ngx_resolver_select_peer(r, rn, first);
        round = (next == NGX_CONF_UNSET_UINT);

        if (!round) {
            rn->last_connection = next;
        }

    } else {
        rn->last_connection = (rn->last_connection + 1) % r->connections.nelts;
        round = rn->state->tries % r->connections.nelts == 0;
    }

    rn->state->restart = round;

    if (condition != NGX_RESOLVER_FT_TIMEOUT) {
        if (rn->naddrs > 1 && rn->naddrs != (u_short) -1) {
            ngx_resolver_free(r, rn->u.addrs);
        }

        rn->naddrs = rn->query ? (u_short) -1 : 0;
#if (NGX_HAVE_INET6)
        if (rn->naddrs6 > 1 && rn->naddrs6 != (u_short) -1) {
            ngx_resolver_free(r, rn->u6.addrs6);
        }

        rn->naddrs6 = rn->query6 ? (u_short) -1 : 0;
#endif
        rn->code = 0;
    }

    rn->tcp = 0;
#if (NGX_HAVE_INET6)
    rn->tcp6 = 0;
#endif

    if (delay || (round && condition != NGX_RESOLVER_FT_TIMEOUT)) {
        rn->state->pending = 1;
        ngx_queue_remove(&rn->queue);
        rn->expire = ngx_time() + r->resend_timeout;
        ngx_queue_insert_head(rn->state->resend_queue, &rn->queue);
        ngx_resolver_retry_wait(r, rn);
        return NGX_OK;
    }

    ngx_queue_remove(&rn->queue);
    rn->expire = ngx_time() + r->resend_timeout;
    ngx_queue_insert_head(rn->state->resend_queue, &rn->queue);
    ngx_post_event(&rn->state->event, &ngx_posted_events);

    return NGX_OK;
}


static void
ngx_resolver_attempt_handler(ngx_event_t *ev)
{
    ngx_resolver_node_t  *rn;

    rn = ev->data;

    if (rn->waiting) {
        (void) ngx_resolver_start_query(rn->waiting->resolver, rn);
    }
}


static ngx_int_t
ngx_resolver_join_query(ngx_resolver_t *r, ngx_resolver_node_t *rn,
    ngx_resolver_ctx_t *ctx)
{
    uintptr_t   mask;
    ngx_uint_t  i;

    if (rn->state == NULL && ctx->query_state) {
        if (ngx_resolver_prepare_query(r, rn, ctx) != NGX_OK) {
            return NGX_ERROR;
        }

        rn->state->sequence = ++ngx_resolver_sequence;
        rn->state->tries = 1;
        i = rn->last_connection / (8 * sizeof(uintptr_t));
        mask = (uintptr_t) 1 << (rn->last_connection % (8 * sizeof(uintptr_t)));
        rn->state->tried[i] = mask;
    }

    if (rn->state) {
        if (ctx->retry || r->nameserver) {
            rn->state->retry = 1;
        }

        if (!rn->state->pending) {
            for ( /* void */; ctx; ctx = ctx->next) {
                ngx_resolver_charge_query(ctx, rn->state->sequence);
            }
        }
    }

    return NGX_OK;
}


static void
ngx_resolver_query_success(ngx_resolver_t *r, ngx_resolver_node_t *rn)
{
    ngx_resolver_ctx_t         *ctx;
    ngx_resolver_connection_t  *rec;

    if (rn->state == NULL) {
        return;
    }

    ngx_resolver_free_stale(r, rn->cache);

    if (rn->cache && rn->cache->refresh_ctx == NULL) {
        ngx_resolver_free_cache(r, rn);
    }

    for (ctx = rn->waiting; ctx; ctx = ctx->next) {
        if (ctx->query_state) {
            ctx->query_state->last_valid = 0;
            ctx->query_state->budget->failures = 0;
        }
    }

    ngx_resolver_invalidate_negative(r, rn, 0);

    rec = r->connections.elts;

    if (rec[rn->last_connection].peer) {
        rec[rn->last_connection].peer->fails = 0;
    }

    ngx_resolver_free_node_state(r, rn);
}


static ngx_uint_t
ngx_resolver_failure(ngx_uint_t code, ngx_uint_t rcode)
{
    if (code == NGX_RESOLVE_NXDOMAIN && rcode == 0) {
        return NGX_RESOLVER_FT_NODATA;
    }

    if (code >= NGX_RESOLVE_FORMERR && code <= NGX_RESOLVE_REFUSED) {
        return NGX_RESOLVER_FT_FORMERR << (code - 1);
    }

    return NGX_RESOLVER_FT_INVALID_RESPONSE;
}


static void
ngx_resolver_rbtree_insert_addr_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t   **p;
    ngx_resolver_node_t  *rn, *rn_temp;

    for ( ;; ) {
        if (node->key == temp->key) {
            rn = ngx_resolver_node(node);
            rn_temp = ngx_resolver_node(temp);
            p = (rn->retry_mask < rn_temp->retry_mask)
                ? &temp->left : &temp->right;

        } else {
            p = (node->key < temp->key) ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static ngx_resolver_node_t *
ngx_resolver_lookup_address(ngx_resolver_t *r, u_char *addr, uint32_t hash,
    ngx_uint_t retry_mask, ngx_int_t ident)
{
    ngx_int_t             rc;
    ngx_rbtree_t         *tree;
    ngx_rbtree_node_t    *node, *sentinel, *first;
    ngx_resolver_node_t  *rn, *cached;

    tree = &r->addr_rbtree;
#if (NGX_HAVE_INET6)
    if (addr) {
        tree = &r->addr6_rbtree;
    }
#endif

    node = tree->root;
    sentinel = tree->sentinel;
    first = NULL;
    cached = NULL;

    while (node != sentinel) {
        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        rc = 0;
#if (NGX_HAVE_INET6)
        if (addr) {
            rn = ngx_resolver_node(node);
            rc = ngx_memcmp(addr, &rn->addr6, 16);
        }
#endif

        if (rc == 0) {
            first = node;
        }

        node = (rc <= 0) ? node->left : node->right;
    }

    for (node = first; node; node = ngx_rbtree_next(tree, node)) {
        rn = ngx_resolver_node(node);

        if (node->key != hash) {
            break;
        }

#if (NGX_HAVE_INET6)
        if (addr && ngx_memcmp(addr, &rn->addr6, 16) != 0) {
            break;
        }
#endif

        if (ident >= 0) {
            if (rn->query && ident == (rn->query[0] << 8) + rn->query[1]) {
                return rn;
            }

        } else {
            if (rn->retry_mask == retry_mask) {
                return rn;
            }

            if (rn->waiting == NULL && rn->valid >= ngx_time()
                && (rn->cache == NULL || rn->cache->error == 0))
            {
                cached = rn;
            }
        }
    }

    return cached;
}


static ngx_resolver_pending_t *
ngx_resolver_lookup_pending(ngx_resolver_t *r, ngx_uint_t ident)
{
    ngx_rbtree_node_t  *node, *sentinel;

    node = r->queries.root;
    sentinel = r->queries.sentinel;

    while (node != sentinel) {
        if (ident == node->key) {
            return (ngx_resolver_pending_t *) node;
        }

        node = (ident < node->key) ? node->left : node->right;
    }

    return NULL;
}


static void
ngx_resolver_remove_queries(ngx_resolver_t *r, ngx_resolver_node_t *rn)
{
    ngx_uint_t               i;
    ngx_resolver_pending_t  *pending;

    if (rn->state == NULL) {
        return;
    }

    for (i = 0; i < 2; i++) {
        pending = &rn->state->queries[i];

        if (pending->active) {
            ngx_rbtree_delete(&r->queries, &pending->node);
            pending->active = 0;
        }
    }
}


static ngx_int_t
ngx_resolver_register_queries(ngx_resolver_t *r, ngx_resolver_node_t *rn)
{
    u_char                  *query, *addr;
    ngx_str_t                name;
    ngx_uint_t               i, n, ident, old, qtype;
    ngx_resolver_node_t     *other;
    ngx_resolver_pending_t  *pending;

    ngx_resolver_remove_queries(r, rn);
    rn->state->negative_valid = 0;
    rn->state->received = 0;

    for (i = 0; i < 2; i++) {
        query = rn->query;

        if (i) {
#if (NGX_HAVE_INET6)
            query = rn->query6;
#else
            break;
#endif
        }

        if (query == NULL) {
            continue;
        }

        qtype = (query[rn->qlen - 4] << 8) + query[rn->qlen - 3];
        old = (query[0] << 8) + query[1];
        ident = ngx_random() & 0xffff;

        for (n = 0; n < 65536; n++, ident = (ident + 1) & 0xffff) {
            if (ident == old || ngx_resolver_lookup_pending(r, ident)) {
                continue;
            }

            if (rn->state->reverse) {
                addr = NULL;
#if (NGX_HAVE_INET6)
                if (rn->state->tree == &r->addr6_rbtree) {
                    addr = rn->addr6.s6_addr;
                }
#endif
                other = ngx_resolver_lookup_address(r, addr, rn->node.key,
                                                    0, ident);

            } else {
                name.len = rn->nlen;
                name.data = rn->name;
                other = ngx_resolver_lookup_reply(rn->state->tree, &name,
                                                  rn->node.key, ident, qtype);
            }

            if (other == NULL) {
                break;
            }
        }

        if (n == 65536) {
            ngx_resolver_remove_queries(r, rn);
            return NGX_ERROR;
        }

        query[0] = (u_char) (ident >> 8);
        query[1] = (u_char) ident;
        pending = &rn->state->queries[i];
        pending->node.key = ident;
        pending->resolver_node = rn;
        pending->qtype = qtype;
        pending->active = 1;
        ngx_rbtree_insert(&r->queries, &pending->node);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_resolver_skip_name(u_char *buf, size_t n, size_t *pos)
{
    size_t      p, end, len, label;
    ngx_uint_t  i;

    p = *pos;
    end = 0;
    len = 0;

    for (i = 0; i < 128 && p < n; i++) {
        label = buf[p++];

        if (label == 0) {
            *pos = end ? end : p;
            return NGX_OK;
        }

        if ((label & 0xc0) == 0xc0) {
            if (p == n) {
                return NGX_ERROR;
            }

            if (end == 0) {
                end = p + 1;
            }

            p = ((label & 0x3f) << 8) + buf[p];
            continue;
        }

        if (label > 63 || label > n - p || len + label + 1 > 254) {
            return NGX_ERROR;
        }

        len += label + 1;
        p += label;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_resolver_scan_response(u_char *buf, size_t n, ngx_uint_t *rcode,
    uint32_t *negative_ttl)
{
    size_t      p, end, start, len, name;
    uint32_t    ttl, minimum;
    ngx_uint_t  i, count, answer, authority, type, qclass, opt;

    if (n < sizeof(ngx_resolver_hdr_t) || buf[4] != 0 || buf[5] != 1) {
        return NGX_ERROR;
    }

    p = sizeof(ngx_resolver_hdr_t);

    if (ngx_resolver_skip_name(buf, n, &p) != NGX_OK
        || n - p < sizeof(ngx_resolver_qs_t))
    {
        return NGX_ERROR;
    }

    p += sizeof(ngx_resolver_qs_t);
    answer = (buf[6] << 8) + buf[7];
    authority = (buf[8] << 8) + buf[9];
    count = answer + authority + (buf[10] << 8) + buf[11];
    opt = 0;
    *rcode = buf[3] & 0x0f;
    *negative_ttl = NGX_MAX_UINT32_VALUE;

    for (i = 0; i < count; i++) {
        name = p;

        if (ngx_resolver_skip_name(buf, n, &p) != NGX_OK
            || n - p < sizeof(ngx_resolver_an_t))
        {
            return NGX_ERROR;
        }

        type = (buf[p] << 8) + buf[p + 1];
        qclass = (buf[p + 2] << 8) + buf[p + 3];
        ttl = ((uint32_t) buf[p + 4] << 24) + (buf[p + 5] << 16)
              + (buf[p + 6] << 8) + buf[p + 7];
        len = (buf[p + 8] << 8) + buf[p + 9];
        p += sizeof(ngx_resolver_an_t);

        if (len > n - p) {
            return NGX_ERROR;
        }

        start = p;
        end = p + len;

        if (qclass != 1 && type != NGX_RESOLVE_OPT) {
            p = end;
            continue;
        }

        switch (type) {

        case NGX_RESOLVE_A:

            if (len != 4) {
                return NGX_ERROR;
            }

            break;

        case NGX_RESOLVE_AAAA:

            if (len != 16) {
                return NGX_ERROR;
            }

            break;

        case NGX_RESOLVE_NS:
        case NGX_RESOLVE_CNAME:
        case NGX_RESOLVE_PTR:
        case NGX_RESOLVE_DNAME:

            if (ngx_resolver_skip_name(buf, n, &p) != NGX_OK || p != end) {
                return NGX_ERROR;
            }

            break;

        case NGX_RESOLVE_SOA:

            if (ngx_resolver_skip_name(buf, n, &p) != NGX_OK
                || p >= end
                || ngx_resolver_skip_name(buf, n, &p) != NGX_OK
                || p > end || end - p != 20)
            {
                return NGX_ERROR;
            }

            if (i >= answer && i < answer + authority) {
                minimum = ((uint32_t) buf[p + 16] << 24)
                          + (buf[p + 17] << 16) + (buf[p + 18] << 8)
                          + buf[p + 19];
                ttl = (ttl & 0x80000000) ? 0 : ttl;
                minimum = ngx_min(ttl, minimum);
                *negative_ttl = ngx_min(*negative_ttl, minimum);
            }

            break;

        case NGX_RESOLVE_MX:
        case NGX_RESOLVE_SRV:

            p += (type == NGX_RESOLVE_MX) ? 2 : 6;

            if (p >= end || ngx_resolver_skip_name(buf, n, &p) != NGX_OK
                || p != end)
            {
                return NGX_ERROR;
            }

            break;

        case NGX_RESOLVE_TXT:

            while (p < end) {
                len = buf[p++];

                if (len > end - p) {
                    return NGX_ERROR;
                }

                p += len;
            }

            break;

        case NGX_RESOLVE_OPT:

            if (opt || i < answer + authority || buf[name] != 0) {
                return NGX_ERROR;
            }

            opt = 1;
            *rcode |= (ttl >> 24) << 4;

            for (p = start; p < end; p += len) {
                if (end - p < 4) {
                    return NGX_ERROR;
                }

                len = (buf[p + 2] << 8) + buf[p + 3];
                p += 4;

                if (len > end - p) {
                    return NGX_ERROR;
                }
            }

            break;
        }

        p = end;
    }

    return NGX_OK;
}


static void
ngx_resolver_receive_response(ngx_resolver_connection_t *rec, u_char *buf,
    size_t n, ngx_uint_t tcp)
{
    ngx_int_t  scan;

    scan = NGX_DECLINED;

    if (ngx_resolver_process_ext_response(rec, buf, n, tcp, &scan)
        == NGX_DECLINED)
    {
        ngx_resolver_process_response(rec->resolver, buf, scan, n, tcp);
    }
}


static ngx_int_t
ngx_resolver_process_ext_response(ngx_resolver_connection_t *rec,
    u_char *buf, size_t n, ngx_uint_t tcp, ngx_int_t *scan)
{
    u_char                  *query;
    uint32_t                 ttl;
    ngx_uint_t               i, ident, flags, rcode, condition, mask;
    ngx_resolver_t          *r;
    ngx_resolver_node_t     *rn;
    ngx_resolver_pending_t  *pending;

    r = rec->resolver;

    if (n < 2 || r->queries.root == r->queries.sentinel) {
        return NGX_DECLINED;
    }

    ident = (buf[0] << 8) + buf[1];
    pending = ngx_resolver_lookup_pending(r, ident);

    if (pending == NULL) {
        return NGX_DECLINED;
    }

    rn = pending->resolver_node;

    if (rn->state->pending || rn->state->event.posted) {
        return NGX_OK;
    }

    if (n == sizeof(ngx_resolver_hdr_t)
        && (((buf[2] << 8) + buf[3]) & 0xf87f) == 0x8001
        && ngx_memcmp(buf + 4, "\0\0\0\0\0\0\0\0", 8) == 0)
    {
        mask = rn->retry_mask ? rn->retry_mask : NGX_RESOLVER_FT_DEFAULT;

        if ((mask & NGX_RESOLVER_FT_FORMERR)
            && rec == (ngx_resolver_connection_t *) r->connections.elts
                       + rn->last_connection)
        {
            rn->state->received = ngx_time();
            ngx_resolver_peer_live(r, rn);
            (void) ngx_resolver_next(r, rn, NGX_RESOLVER_FT_FORMERR,
                                     NGX_RESOLVE_FORMERR);
            return NGX_OK;
        }
    }

    query = rn->query;
#if (NGX_HAVE_INET6)
    if (pending->qtype == NGX_RESOLVE_AAAA) {
        query = rn->query6;
    }
#endif

    if (n < rn->qlen || query == NULL) {
        return NGX_DECLINED;
    }

    for (i = 12; i < (ngx_uint_t) rn->qlen - 4; i++) {
        if (ngx_tolower(buf[i]) != query[i]) {
            return NGX_DECLINED;
        }
    }

    if (ngx_memcmp(buf + rn->qlen - 4, query + rn->qlen - 4, 4) != 0) {
        return NGX_DECLINED;
    }

    if (rec != (ngx_resolver_connection_t *) r->connections.elts
               + rn->last_connection)
    {
        return NGX_OK;
    }

    mask = rn->retry_mask ? rn->retry_mask : NGX_RESOLVER_FT_DEFAULT;
    flags = (buf[2] << 8) + buf[3];
    rcode = flags & 0x0f;
    condition = 0;

    if ((flags & 0xf870) != 0x8000 || (tcp && (flags & 0x0200))) {
        condition = NGX_RESOLVER_FT_INVALID_RESPONSE;

    } else if (!(flags & 0x0200)) {
        *scan = ngx_resolver_scan_response(buf, n, &rcode, &ttl);

        if (*scan != NGX_OK) {
            condition = NGX_RESOLVER_FT_INVALID_RESPONSE;

        } else {
            ngx_resolver_set_negative_valid(rn, ttl);
            ngx_resolver_peer_live(r, rn);

            if (rcode == NGX_RESOLVE_FORMERR) {
                condition = NGX_RESOLVER_FT_FORMERR;

            } else if (rcode > NGX_RESOLVE_REFUSED) {
                condition = NGX_RESOLVER_FT_INVALID_RESPONSE;
            }
        }
    }

    if (condition && (mask & condition)) {
        (void) ngx_resolver_next(r, rn, condition,
                                 rcode ? (ngx_int_t) rcode : NGX_ERROR);
        return NGX_OK;
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_resolver_scan_failure(ngx_resolver_t *r, ngx_resolver_node_t *rn,
    u_char *buf, size_t n, ngx_int_t scan)
{
    uint32_t    ttl;
    ngx_uint_t  rcode;

    if (scan != NGX_DECLINED || rn->state == NULL
        || (r->negative_valid == 0 && r->error_valid == 0))
    {
        return scan;
    }

    scan = ngx_resolver_scan_response(buf, n, &rcode, &ttl);

    if (scan == NGX_OK) {
        ngx_resolver_set_negative_valid(rn, ttl);
    }

    return scan;
}


static ngx_int_t
ngx_resolver_process_failure(ngx_resolver_t *r, ngx_resolver_node_t *rn,
    u_char *buf, size_t n, ngx_uint_t code, ngx_int_t scan)
{
    ngx_resolver_ctx_t         *ctx;
    ngx_resolver_node_state_t  *ns;

    ns = rn->state;

    if (ns == NULL) {
        return NGX_DECLINED;
    }

    scan = ngx_resolver_scan_failure(r, rn, buf, n, scan);
    ns->failure = ngx_resolver_failure(code, (buf[3] & 0x0f) || rn->code);

    if (code == NGX_RESOLVE_NXDOMAIN) {
        ngx_resolver_free_stale(r, rn->cache);
    }

    if (ns->retry && ngx_resolver_next(r, rn, ns->failure, code) == NGX_OK) {
        return NGX_OK;
    }

    if (ngx_resolver_store_failure(r, rn, code, scan) == NGX_DECLINED) {
        return NGX_DECLINED;
    }

    ctx = rn->waiting;
    rn->waiting = NULL;
    ngx_resolver_report_error(ctx, code, rn->valid);

    return NGX_OK;
}


/* NGX_DONE retains a stale answer, NGX_OK caches the failure. */

static ngx_int_t
ngx_resolver_store_failure(ngx_resolver_t *r, ngx_resolver_node_t *rn,
    ngx_int_t code, ngx_int_t scan)
{
    time_t                      valid, now;
    ngx_resolver_cache_t       *cache;
    ngx_resolver_node_state_t  *ns;

    if (code != NGX_RESOLVE_NXDOMAIN
        && ngx_resolver_restore_stale(r, rn) == NGX_OK)
    {
        return NGX_DONE;
    }

    ns = rn->state;

    if (scan == NGX_ERROR || ns == NULL) {
        return NGX_DECLINED;
    }

    valid = (code == NGX_RESOLVE_NXDOMAIN) ? r->negative_valid : r->error_valid;

    if (valid == 0) {
        return NGX_DECLINED;
    }

    if (r->valid) {
        valid = ngx_min(valid, r->valid);
    }

    now = ngx_time();

    if (code == NGX_ERROR || code == NGX_RESOLVE_TIMEDOUT) {
        valid += now;

    } else {
        valid += ns->received ? ns->received : now;

        if (ns->negative_valid) {
            valid = ngx_min(valid, ns->negative_valid);
        }
    }

    if (valid <= now) {
        return NGX_DECLINED;
    }

    cache = ngx_resolver_alloc_cache(r, rn);
    if (cache == NULL) {
        return NGX_DECLINED;
    }

    ngx_resolver_free_stale(r, cache);

    ngx_resolver_free(r, rn->query);
    rn->query = NULL;
#if (NGX_HAVE_INET6)
    rn->query6 = NULL;
#endif

    if (rn->naddrs > 1 && rn->naddrs != (u_short) -1) {
        ngx_resolver_free(r, rn->u.addrs);
    }

    rn->naddrs = 0;
#if (NGX_HAVE_INET6)
    if (rn->naddrs6 > 1 && rn->naddrs6 != (u_short) -1) {
        ngx_resolver_free(r, rn->u6.addrs6);
    }

    rn->naddrs6 = 0;
#endif

    cache->error = code;
    cache->nxdomain = (code == NGX_RESOLVE_NXDOMAIN
                       && ns->failure == NGX_RESOLVER_FT_NXDOMAIN);

    rn->valid = valid;
    rn->expire = ngx_time() + r->expire;
    ngx_queue_remove(&rn->queue);
    ngx_queue_insert_head(ns->expire_queue, &rn->queue);

    if (cache->nxdomain) {
        ngx_resolver_invalidate_negative(r, rn, 1);
    }

    ngx_resolver_free_node_state(r, rn);

    return NGX_OK;
}


static void
ngx_resolver_report_error(ngx_resolver_ctx_t *ctx, ngx_int_t code, time_t valid)
{
    ngx_resolver_ctx_t  *next;

    while (ctx) {
        next = ctx->next;
        ctx->node = NULL;
        ctx->state = code;
        ctx->valid = valid;
        ctx->naddrs = 0;
        ctx->handler(ctx);
        ctx = next;
    }
}


static void
ngx_resolver_free_node_state(ngx_resolver_t *r, ngx_resolver_node_t *rn)
{
    if (rn->state == NULL) {
        return;
    }

    ngx_resolver_remove_queries(r, rn);

    if (rn->state->event.posted) {
        ngx_delete_posted_event(&rn->state->event);
    }

    ngx_resolver_free(r, rn->state);
    rn->state = NULL;
}


static ngx_resolver_cache_t *
ngx_resolver_alloc_cache(ngx_resolver_t *r, ngx_resolver_node_t *rn)
{
    if (rn->cache == NULL) {
        rn->cache = ngx_resolver_calloc(r, sizeof(ngx_resolver_cache_t));
    }

    return rn->cache;
}


static void
ngx_resolver_free_stale(ngx_resolver_t *r, ngx_resolver_cache_t *cache)
{
    if (cache && cache->stale) {
        ngx_resolver_free_node(r, cache->stale);
        cache->stale = NULL;
    }
}


static void
ngx_resolver_free_cache(ngx_resolver_t *r, ngx_resolver_node_t *rn)
{
    ngx_resolver_cache_t  *cache;

    cache = rn->cache;

    if (cache == NULL) {
        return;
    }

    if (cache->refresh_ctx) {
        cache->refresh_ctx->query_state->refresh_node = NULL;
    }

    ngx_resolver_free_stale(r, cache);
    ngx_resolver_free(r, cache);
    rn->cache = NULL;
}


static ngx_int_t
ngx_resolver_save_stale(ngx_resolver_t *r, ngx_resolver_node_t *rn,
    ngx_uint_t reverse)
{
    ngx_resolver_node_t   *stale;
    ngx_resolver_cache_t  *cache;

    if (r->stale_valid == 0
        || (rn->cache && (rn->cache->error || rn->cache->stale))
        || rn->valid == 0
        || rn->valid + r->stale_valid < ngx_time())
    {
        return NGX_OK;
    }

    cache = ngx_resolver_alloc_cache(r, rn);
    if (cache == NULL) {
        return NGX_ERROR;
    }

    stale = ngx_resolver_alloc(r, sizeof(ngx_resolver_node_t));
    if (stale == NULL) {
        return NGX_ERROR;
    }

    *stale = *rn;
    stale->state = NULL;
    stale->cache = NULL;
    stale->query = NULL;
#if (NGX_HAVE_INET6)
    stale->query6 = NULL;
#endif
    stale->waiting = NULL;

    if (reverse) {
        rn->name = NULL;
        rn->nlen = 0;

    } else {
        stale->name = NULL;
        stale->nlen = 0;
    }

    cache->stale = stale;
    rn->naddrs = 0;
#if (NGX_HAVE_INET6)
    rn->naddrs6 = 0;
#endif
    rn->nsrvs = 0;
    rn->cnlen = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_resolver_restore_stale(ngx_resolver_t *r, ngx_resolver_node_t *rn)
{
    ngx_uint_t                  i;
    ngx_resolver_node_t        *stale;
    ngx_resolver_cache_t       *cache;
    ngx_resolver_node_state_t  *ns;

    ns = rn->state;
    cache = rn->cache;

    if (ns == NULL || cache == NULL || cache->stale == NULL) {
        return NGX_DECLINED;
    }

    stale = cache->stale;

    if (stale->valid + r->stale_valid < ngx_time()) {
        return NGX_DECLINED;
    }

    if (rn->naddrs > 1 && rn->naddrs != (u_short) -1) {
        ngx_resolver_free(r, rn->u.addrs);
    }
#if (NGX_HAVE_INET6)
    if (rn->naddrs6 > 1 && rn->naddrs6 != (u_short) -1) {
        ngx_resolver_free(r, rn->u6.addrs6);
    }
#endif
    if (rn->cnlen) {
        ngx_resolver_free(r, rn->u.cname);
    }

    if (rn->nsrvs) {
        for (i = 0; i < rn->nsrvs; i++) {
            ngx_resolver_free(r, rn->u.srvs[i].name.data);
        }

        ngx_resolver_free(r, rn->u.srvs);
    }

    if (ns->reverse) {
        ngx_resolver_free(r, rn->name);
        rn->name = stale->name;
        rn->nlen = stale->nlen;
    }

    rn->u = stale->u;
    rn->naddrs = stale->naddrs;
    rn->nsrvs = stale->nsrvs;
    rn->cnlen = stale->cnlen;
#if (NGX_HAVE_INET6)
    rn->u6 = stale->u6;
    rn->naddrs6 = stale->naddrs6;
#endif
    rn->valid = stale->valid;
    rn->ttl = stale->ttl;
    rn->code = 0;
    cache->refresh_after = ngx_time() + (r->error_valid
                                         ? r->error_valid
                                         : r->resend_timeout);
    cache->stale = NULL;
    ngx_resolver_free(r, stale);
    ngx_queue_remove(&rn->queue);
    rn->expire = ngx_time() + r->expire;
    ngx_queue_insert_head(ns->expire_queue, &rn->queue);
    ngx_resolver_free_node_state(r, rn);

    return NGX_OK;
}


static void
ngx_resolver_refresh_handler(ngx_event_t *ev)
{
    ngx_int_t            rc;
    ngx_resolver_ctx_t  *ctx;

    ctx = ev->data;

    if (ctx->query_state->reverse) {
        ctx->query_state->resuming = 1;
        rc = ngx_resolve_addr(ctx);

    } else {
        rc = ngx_resolve_name_locked(ctx->resolver, ctx, &ctx->name);
    }

    if (rc == NGX_ERROR) {
        ngx_resolver_finish_query(ctx, NGX_ERROR);
    }
}


static void
ngx_resolver_refresh_done(ngx_resolver_ctx_t *ctx)
{
    if (ctx->query_state->reverse) {
        ngx_resolve_addr_done(ctx);

    } else {
        ngx_resolve_name_done(ctx);
    }
}


static ngx_int_t
ngx_resolver_use_stale(ngx_resolver_t *r, ngx_resolver_node_t *rn,
    ngx_resolver_ctx_t *ctx, ngx_uint_t reverse)
{
    ngx_int_t                    rc;
    ngx_str_t                    name;
    ngx_uint_t                   naddrs;
    ngx_resolver_ctx_t          *next, *refresh;
    ngx_resolver_addr_t         *addrs;
    ngx_resolver_node_t         *stale;
    ngx_resolver_cache_t        *cache;
    ngx_resolver_query_state_t  *qs;

    cache = rn->cache;

    if (r->stale_valid == 0
        || (cache && cache->error)
        || (ctx->query_state && ctx->query_state->background))
    {
        return NGX_DECLINED;
    }

    stale = (cache && cache->stale) ? cache->stale : rn;

    if (stale->valid == 0 || stale->valid >= ngx_time()
        || stale->valid + r->stale_valid < ngx_time())
    {
        return NGX_DECLINED;
    }

    if (rn->waiting == NULL
        && (cache == NULL
            || (cache->refresh_ctx == NULL
                && cache->refresh_after <= ngx_time())))
    {
        cache = ngx_resolver_alloc_cache(r, rn);
        if (cache == NULL) {
            goto cached;
        }

        refresh = ngx_resolve_start(r, NULL);
        if (refresh == NULL) {
            goto cached;
        }

        refresh->retry = ctx->retry;
        refresh->handler = ngx_resolver_refresh_done;
        refresh->timeout = ctx->timeout;
        refresh->cancelable = 1;

        if (ngx_resolver_init_query_state(refresh) != NGX_OK) {
            ngx_resolver_free(r, refresh);
            goto cached;
        }

        qs = refresh->query_state;
        qs->background = 1;
        qs->refresh_node = rn;
        cache->refresh_ctx = refresh;
        qs->reverse = reverse;

        if (qs->reverse) {
            qs->address = ngx_resolver_dup(r, ctx->addr.sockaddr,
                                           ctx->addr.socklen);
            if (qs->address == NULL) {
                goto failed;
            }

            refresh->addr.sockaddr = (struct sockaddr *) qs->address;
            refresh->addr.socklen = ctx->addr.socklen;

        } else {
            qs->original_name = ngx_resolver_dup(r, rn->name, rn->nlen);
            if (qs->original_name == NULL) {
                goto failed;
            }

            refresh->name.data = qs->original_name;
            refresh->name.len = rn->nlen;

            if (ctx->service.len) {
                qs->service = ngx_resolver_dup(r, ctx->service.data,
                                               ctx->service.len);
                if (qs->service == NULL) {
                    goto failed;
                }

                refresh->service.data = qs->service;
                refresh->service.len = ctx->service.len;
            }
        }

        qs->event.handler = ngx_resolver_refresh_handler;
        ngx_post_event(&qs->event, &ngx_posted_events);
    }

cached:

    if (reverse) {
        name.data = ngx_resolver_dup(r, stale->name, stale->nlen);
        if (name.data == NULL) {
            return NGX_ERROR;
        }

        name.len = stale->nlen;
        ctx->name = name;
        ctx->state = NGX_OK;
        ctx->valid = stale->valid;
        ctx->handler(ctx);
        ngx_resolver_free(r, name.data);
        return NGX_OK;
    }

    naddrs = stale->naddrs;
#if (NGX_HAVE_INET6)
    naddrs += stale->naddrs6;
#endif

    if (naddrs) {
        addrs = ngx_resolver_export(r, stale, 1);
        if (addrs == NULL) {
            return NGX_ERROR;
        }

        do {
            next = ctx->next;
            ctx->state = NGX_OK;
            ctx->valid = stale->valid;
            ctx->naddrs = naddrs;
            ctx->addrs = addrs;
            ctx->handler(ctx);
            ctx = next;
        } while (ctx);

        ngx_resolver_free(r, addrs->sockaddr);
        ngx_resolver_free(r, addrs);
        return NGX_OK;
    }

    if (stale->nsrvs) {
        do {
            next = ctx->next;
            ngx_resolver_resolve_srv_names(ctx, stale);
            ctx = next;
        } while (ctx);

        return NGX_OK;
    }

    if (stale->cnlen && ctx->recursion++ < NGX_RESOLVER_MAX_RECURSION) {
        name.len = stale->cnlen;
        name.data = stale->u.cname;
        rc = ngx_resolve_name_locked(r, ctx, &name);
        return rc;
    }

    ngx_resolver_report_error(ctx, NGX_RESOLVE_NXDOMAIN, stale->valid);
    return NGX_OK;

failed:

    ngx_resolver_free_query_state(refresh);
    ngx_resolver_free(r, refresh);
    goto cached;
}


static void
ngx_resolver_cleanup_contexts(ngx_resolver_t *r)
{
    ngx_queue_t                 *q;
    ngx_resolver_ctx_t          *ctx;
    ngx_resolver_query_state_t  *qs;

    while (!ngx_queue_empty(&r->contexts)) {
        q = ngx_queue_head(&r->contexts);
        qs = ngx_queue_data(q, ngx_resolver_query_state_t, queue);
        ctx = qs->event.data;

        if (qs->reverse) {
            ngx_resolve_addr_done(ctx);

        } else {
            ngx_resolve_name_done(ctx);
        }
    }
}


static ngx_int_t
ngx_resolver_get_ident(ngx_resolver_t *r, ngx_uint_t *ident)
{
    ngx_uint_t  i, value;

    value = *ident & 0xffff;

    for (i = 0; i < 65536; i++, value = (value + 1) & 0xffff) {
        if (ngx_resolver_lookup_pending(r, value) == NULL) {
            *ident = value;
            return NGX_OK;
        }
    }

    return NGX_ERROR;
}


static ngx_uint_t
ngx_resolver_round_complete(ngx_resolver_t *r, ngx_resolver_node_t *rn)
{
    uintptr_t                   mask;
    ngx_uint_t                  i, n, ignore;
    ngx_resolver_peer_t        *peer;
    ngx_resolver_connection_t  *rec;

    if (rn->state == NULL || rn->state->tries == 0) {
        return 0;
    }

    rec = r->connections.elts;
    ignore = r->nameserver && ngx_resolver_all_failed(r);

    for (i = 0; i < r->connections.nelts; i++) {
        n = i / (8 * sizeof(uintptr_t));
        mask = (uintptr_t) 1 << (i % (8 * sizeof(uintptr_t)));

        if (rn->state->tried[n] & mask) {
            continue;
        }

        peer = rec[i].peer;

        if (!ignore && peer && peer->max_fails
            && peer->fails >= peer->max_fails
            && ngx_time() - peer->accessed <= peer->fail_timeout)
        {
            continue;
        }

        return 0;
    }

    return 1;
}


static void
ngx_resolver_cache_timeout(ngx_resolver_ctx_t *ctx)
{
    ngx_resolver_t       *r;
    ngx_resolver_node_t  *rn;

    r = ctx->resolver;
    rn = ctx->node;

    if (rn && rn->waiting == ctx && ctx->next == NULL
        && (rn->state == NULL
            || (!rn->state->pending && !rn->state->event.posted)))
    {
        ngx_resolver_peer_failed(r, rn);
    }

    if (rn == NULL || rn->waiting != ctx || ctx->next
        || r->error_valid == 0
        || !ngx_resolver_round_complete(r, rn))
    {
        return;
    }

    if (ngx_resolver_store_failure(r, rn, NGX_RESOLVE_TIMEDOUT, NGX_DECLINED)
        == NGX_OK)
    {
        ctx->valid = rn->valid;
    }
}


static void
ngx_resolver_peer_failed(ngx_resolver_t *r, ngx_resolver_node_t *rn)
{
    time_t                      now;
    ngx_resolver_peer_t        *peer;
    ngx_resolver_connection_t  *rec;

    if (rn->state == NULL || rn->state->tries == 0
        || rn->last_connection == NGX_CONF_UNSET_UINT
        || rn->state->failed_sequence == rn->state->sequence)
    {
        return;
    }

    rec = r->connections.elts;
    peer = rec[rn->last_connection].peer;

    if (peer == NULL || peer->max_fails == 0) {
        return;
    }

    rn->state->failed_sequence = rn->state->sequence;
    now = ngx_time();

    if (now - peer->accessed > peer->fail_timeout) {
        peer->fails = 0;
    }

    if (peer->fails == 0) {
        peer->accessed = now;
    }

    if (peer->fails < peer->max_fails) {
        peer->fails++;
    }

    if (peer->fails == peer->max_fails) {
        peer->accessed = now;
    }
}


static void
ngx_resolver_peer_live(ngx_resolver_t *r, ngx_resolver_node_t *rn)
{
    ngx_resolver_connection_t  *rec;

    rec = r->connections.elts;

    if (rn->last_connection != NGX_CONF_UNSET_UINT
        && rec[rn->last_connection].peer)
    {
        rec[rn->last_connection].peer->fails = 0;
    }
}


static ngx_resolver_node_t *
ngx_resolver_lookup_negative(ngx_resolver_t *r, ngx_resolver_ctx_t *ctx,
    ngx_str_t *name, uint32_t hash)
{
    ngx_rbtree_t         *tree;
    ngx_resolver_node_t  *rn;

    if (r->negative_valid == 0) {
        return NULL;
    }

    tree = ctx->service.len ? &r->name_rbtree : &r->srv_rbtree;
    rn = ngx_resolver_lookup_name_by_mask(tree, name, hash,
                                          ngx_resolver_retry_mask(ctx));

    if (rn && rn->cache && rn->cache->nxdomain && rn->valid >= ngx_time()) {
        ngx_queue_remove(&rn->queue);
        rn->expire = ngx_time() + r->expire;
        ngx_queue_insert_head(ctx->service.len ? &r->name_expire_queue
                                              : &r->srv_expire_queue,
                              &rn->queue);
        return rn;
    }

    return NULL;
}


static void
ngx_resolver_invalidate_negative(ngx_resolver_t *r, ngx_resolver_node_t *rn,
    ngx_uint_t nxdomain)
{
    ngx_str_t             name;
    ngx_rbtree_t         *tree;
    ngx_resolver_node_t  *other;

    if (r->negative_valid == 0
        || rn->state == NULL || rn->state->reverse)
    {
        return;
    }

    name.data = rn->name;
    name.len = rn->nlen;
    tree = rn->state->tree == &r->name_rbtree ? &r->srv_rbtree
                                            : &r->name_rbtree;
    other = ngx_resolver_lookup_name_by_mask(tree, &name, rn->node.key,
                                             rn->retry_mask);

    if (other == NULL) {
        return;
    }

    if (nxdomain || (other->cache && other->cache->nxdomain)) {
        other->valid = 0;

        if (other->cache && other->cache->stale) {
            other->cache->stale->valid = 0;
        }
    }
}


static void
ngx_resolver_set_negative_valid(ngx_resolver_node_t *rn, uint32_t ttl)
{
    time_t  valid;

    rn->state->received = ngx_time();

    if (ttl == NGX_MAX_UINT32_VALUE) {
        return;
    }

    valid = ngx_time() + (time_t) ttl;

    if (rn->state->negative_valid == 0 || valid < rn->state->negative_valid) {
        rn->state->negative_valid = valid;
    }
}


static void
ngx_resolver_cache_failure(ngx_resolver_t *r, ngx_resolver_node_t *rn)
{
    if (!ngx_resolver_round_complete(r, rn)) {
        return;
    }

    (void) ngx_resolver_store_failure(r, rn, rn->state->last_result,
                                      NGX_DECLINED);
}


static void
ngx_resolver_retry_wait(ngx_resolver_t *r, ngx_resolver_node_t *rn)
{
    ngx_msec_t                   elapsed;
    ngx_resolver_ctx_t          *ctx, **p;
    ngx_resolver_query_state_t  *qs;

    for (p = &rn->waiting; *p; /* void */) {
        ctx = *p;
        qs = ctx->query_state;

        if (qs == NULL) {
            p = &ctx->next;
            continue;
        }

        qs->last_result = rn->state->last_result;
        qs->last_valid = 1;

        if (ngx_resolver_check_budget(ctx) != NGX_OK) {
            *p = ctx->next;
            ngx_resolver_finish_query(ctx, qs->last_result);
            continue;
        }

        if (ctx->retry && ctx->retry->next_nameserver_timeout
            && qs->budget->tries)
        {
            elapsed = ngx_current_msec - qs->budget->start;
            qs->event.handler = ngx_resolver_retry_timeout_handler;
            ngx_add_timer(&qs->event,
                          ctx->retry->next_nameserver_timeout - elapsed);
        }

        p = &ctx->next;
    }

    if (rn->waiting == NULL) {
        ngx_resolver_cache_failure(r, rn);
    }
}


static void
ngx_resolver_retry_timeout_handler(ngx_event_t *ev)
{
    ngx_int_t             code;
    ngx_resolver_t       *r;
    ngx_resolver_ctx_t   *ctx, **p;
    ngx_resolver_node_t  *rn;

    ctx = ev->data;
    r = ctx->resolver;
    rn = ctx->node;
    code = ctx->query_state->last_result;

    if (rn) {
        for (p = &rn->waiting; *p; p = &(*p)->next) {
            if (*p == ctx) {
                *p = ctx->next;
                break;
            }
        }

        if (rn->waiting == NULL) {
            ngx_resolver_cache_failure(r, rn);
        }
    }

    ngx_resolver_finish_query(ctx, code);
}


static ngx_uint_t
ngx_resolver_retry_mask(ngx_resolver_ctx_t *ctx)
{
    return ctx->retry ? ctx->retry->next_nameserver : 0;
}


static ngx_resolver_node_t *
ngx_resolver_lookup_name_by_mask(ngx_rbtree_t *tree, ngx_str_t *name,
    uint32_t hash, ngx_uint_t retry_mask)
{
    ngx_int_t             rc;
    ngx_rbtree_node_t    *node, *sentinel;
    ngx_resolver_node_t  *rn, *cached;

    node = tree->root;
    sentinel = tree->sentinel;
    cached = NULL;

    while (node != sentinel) {
        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        rn = ngx_resolver_node(node);
        rc = ngx_memn2cmp(name->data, rn->name, name->len, rn->nlen);

        if (rc == 0) {
            if (rn->retry_mask == retry_mask) {
                return rn;
            }

            if (rn->waiting == NULL && rn->valid >= ngx_time()
                && (rn->cache == NULL || rn->cache->error == 0))
            {
                cached = rn;
            }

            rc = (retry_mask < rn->retry_mask) ? -1 : 1;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return cached;
}


static ngx_resolver_node_t *
ngx_resolver_lookup_reply(ngx_rbtree_t *tree, ngx_str_t *name, uint32_t hash,
    ngx_uint_t ident, ngx_uint_t qtype)
{
    u_char               *query;
    ngx_int_t             rc;
    ngx_rbtree_node_t    *node, *sentinel, *first;
    ngx_resolver_node_t  *rn;

    node = tree->root;
    sentinel = tree->sentinel;
    first = NULL;

    while (node != sentinel) {
        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        rn = ngx_resolver_node(node);
        rc = ngx_memn2cmp(name->data, rn->name, name->len, rn->nlen);

        if (rc == 0) {
            first = node;
        }

        node = (rc <= 0) ? node->left : node->right;
    }

    for (node = first; node; node = ngx_rbtree_next(tree, node)) {
        rn = ngx_resolver_node(node);

        if (node->key != hash || rn->nlen != name->len
            || ngx_strncmp(rn->name, name->data, name->len) != 0)
        {
            break;
        }

        query = rn->query;
#if (NGX_HAVE_INET6)
        if (qtype == NGX_RESOLVE_AAAA) {
            query = rn->query6;
        }
#endif

        if (query && ident == (ngx_uint_t) ((query[0] << 8) + query[1])) {
            return rn;
        }
    }

    return NULL;
}


static ngx_resolver_nameserver_t *
ngx_resolver_add_nameserver(ngx_conf_t *cf, ngx_array_t **nameservers,
    ngx_str_t *name)
{
    ngx_uint_t                  i;
    ngx_resolver_nameserver_t  *ns;

    if (*nameservers == NULL) {
        *nameservers = ngx_array_create(cf->temp_pool, 2,
                                        sizeof(ngx_resolver_nameserver_t));
        if (*nameservers == NULL) {
            return NULL;
        }
    }

    ns = (*nameservers)->elts;

    for (i = 0; i < (*nameservers)->nelts; i++) {
        if (ns[i].name.len == name->len
            && ngx_strncmp(ns[i].name.data, name->data, name->len) == 0)
        {
            return &ns[i];
        }
    }

    ns = ngx_array_push(*nameservers);
    if (ns == NULL) {
        return NULL;
    }

    ns->name = *name;
    ns->servers = NULL;
    ns->references = NULL;

    return ns;
}


char *
ngx_resolver_nameserver(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                       *rv;
    ngx_str_t                  *value;
    ngx_conf_t                  pcf;
    ngx_array_t               **nameservers;
    ngx_resolver_nameserver_t  *ns;

    value = cf->args->elts;

    if (value[1].len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "empty nameserver name");
        return NGX_CONF_ERROR;
    }

    nameservers = (ngx_array_t **) ((u_char *) conf + cmd->offset);

    ns = ngx_resolver_add_nameserver(cf, nameservers, &value[1]);
    if (ns == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ns->servers != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate nameserver \"%V\"", &ns->name);
        return NGX_CONF_ERROR;
    }

    ns->servers = ngx_array_create(cf->temp_pool, 4,
                                   sizeof(ngx_resolver_server_t));
    if (ns->servers == NULL) {
        return NGX_CONF_ERROR;
    }

    pcf = *cf;
    cf->handler = ngx_resolver_server;
    cf->handler_conf = ns;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (ns->servers->nelts == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "no servers in nameserver \"%V\"", &ns->name);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_resolver_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_resolver_nameserver_t  *ns = conf;

    ngx_str_t           *value, s;
    ngx_int_t            n;
    ngx_uint_t           i, local;
    ngx_resolver_peer_t  peer;

    value = cf->args->elts;

    if (ngx_strcmp(value[0].data, "include") == 0 && cf->args->nelts == 2) {
        return ngx_conf_include(cf, cmd, conf);
    }

    local = ngx_strcmp(value[0].data, "local") == 0;

    if (!local && ngx_strcmp(value[0].data, "server") != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid directive \"%V\" in nameserver",
                           &value[0]);
        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts < 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid number of arguments in \"%V\" directive",
                           &value[0]);
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&peer, sizeof(ngx_resolver_peer_t));
    peer.level = 1;
    peer.weight = 1;
    peer.fail_timeout = 10;

    for (i = 2; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "level=", 6) == 0) {
            n = ngx_atoi(value[i].data + 6, value[i].len - 6);
            if (n <= 0) {
                goto invalid;
            }

            peer.level = n;
            continue;
        }

        if (ngx_strncmp(value[i].data, "weight=", 7) == 0) {
            n = ngx_atoi(value[i].data + 7, value[i].len - 7);
            if (n <= 0) {
                goto invalid;
            }

            peer.weight = n;
            continue;
        }

        if (ngx_strncmp(value[i].data, "max_fails=", 10) == 0) {
            n = ngx_atoi(value[i].data + 10, value[i].len - 10);
            if (n == NGX_ERROR) {
                goto invalid;
            }

            peer.max_fails = n;
            continue;
        }

        if (ngx_strncmp(value[i].data, "fail_timeout=", 13) == 0) {
            s.len = value[i].len - 13;
            s.data = value[i].data + 13;

            peer.fail_timeout = ngx_parse_time(&s, 1);
            if (peer.fail_timeout == (time_t) NGX_ERROR) {
                goto invalid;
            }

            continue;
        }

        goto invalid;
    }

    if (local) {
        if (ngx_resolver_nameserver_local(cf, ns, &value[1], &peer) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

    } else {
        if (ngx_resolver_nameserver_add_server(cf, ns, &value[1], &peer)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[i]);

    return NGX_CONF_ERROR;
}


static ngx_int_t
ngx_resolver_nameserver_add_server(ngx_conf_t *cf,
    ngx_resolver_nameserver_t *ns, ngx_str_t *name, ngx_resolver_peer_t *peer)
{
    ngx_url_t               u;
    ngx_uint_t              i;
    ngx_resolver_server_t  *server;

    ngx_memzero(&u, sizeof(ngx_url_t));
    u.url.data = ngx_pnalloc(cf->pool, name->len + 1);
    if (u.url.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(u.url.data, name->data, name->len);
    u.url.data[name->len] = '\0';
    u.url.len = name->len;
    u.default_port = 53;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in nameserver \"%V\"", u.err, name);
        }

        return NGX_ERROR;
    }

    server = ngx_array_push_n(ns->servers, u.naddrs);
    if (server == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < u.naddrs; i++) {
        server[i].addr = u.addrs[i];
        server[i].peer = *peer;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_resolver_nameserver_local(ngx_conf_t *cf, ngx_resolver_nameserver_t *ns,
    ngx_str_t *name, ngx_resolver_peer_t *peer)
{
    u_char     *p, *last, *start, *end;
    size_t      len;
    ssize_t     n;
    ngx_str_t   path, address;
    ngx_int_t   rc;
    ngx_file_t  file;
    u_char      buf[4096];

#if (NGX_HAVE_INET6)
    u_char  addr6[16];
    u_char  ipv6[NGX_INET6_ADDRSTRLEN + 2];
#endif

    path = *name;

    if (ngx_conf_full_name(cf->cycle, &path, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.name = path;
    file.log = cf->log;
    file.fd = ngx_open_file(path.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);

    if (file.fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_open_file_n " \"%V\" failed", &path);
        return NGX_ERROR;
    }

    rc = NGX_ERROR;
    len = 0;

    for ( ;; ) {
        n = ngx_read_file(&file, buf + len, sizeof(buf) - len, file.offset);
        if (n == NGX_ERROR) {
            goto done;
        }

        last = buf + len + n;
        start = buf;

        for (p = buf; p < last; p++) {
            if (*p != LF && (n != 0 || p + 1 != last)) {
                continue;
            }

            end = (*p == LF) ? p : p + 1;

            while (start < end && (*start == ' ' || *start == '\t')) {
                start++;
            }

            if (end - start >= 10
                && ngx_strncmp(start, "nameserver", 10) == 0
                && (end - start == 10 || start[10] == ' ' || start[10] == '\t'))
            {
                start += 10;

                while (start < end && (*start == ' ' || *start == '\t')) {
                    start++;
                }

                address.data = start;

                while (start < end && *start != ' ' && *start != '\t'
                       && *start != CR && *start != '#' && *start != ';')
                {
                    start++;
                }

                address.len = start - address.data;

                if (address.len == 0) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "empty nameserver in \"%V\"", &path);
                    goto done;
                }

#if (NGX_HAVE_INET6)

                if (address.len <= NGX_INET6_ADDRSTRLEN
                    && ngx_inet6_addr(address.data, address.len, addr6)
                       == NGX_OK)
                {
                    ipv6[0] = '[';
                    ngx_memcpy(ipv6 + 1, address.data, address.len);
                    ipv6[address.len + 1] = ']';
                    address.data = ipv6;
                    address.len += 2;
                }

#endif

                if (ngx_resolver_nameserver_add_server(cf, ns, &address, peer)
                    != NGX_OK)
                {
                    goto done;
                }
            }

            start = p + 1;
        }

        if (n == 0) {
            break;
        }

        len = last - start;

        if (len == sizeof(buf)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "too long line in \"%V\"", &path);
            goto done;
        }

        ngx_memmove(buf, start, len);
    }

    rc = NGX_OK;

done:

    if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_ALERT, cf, ngx_errno,
                           ngx_close_file_n " \"%V\" failed", &path);
    }

    return rc;
}


static ngx_int_t
ngx_resolver_configure(ngx_conf_t *cf, ngx_resolver_t *r, ngx_str_t *names,
    ngx_uint_t n, ngx_array_t **nameservers, ngx_str_t **values,
    ngx_uint_t *nelts)
{
    size_t                      prefix;
    time_t                     *time;
    ngx_str_t                   s, *v;
    ngx_uint_t                  i, j, set, targets, target, local, valid, seen;
    ngx_resolver_reference_t   *ref;
    ngx_resolver_nameserver_t  *ns;

    if (n == 0) {
        return NGX_OK;
    }

    v = ngx_palloc(cf->temp_pool, n * sizeof(ngx_str_t));
    if (v == NULL) {
        return NGX_ERROR;
    }

    targets = 0;
    target = 0;
    local = 0;
    valid = 0;
    seen = 0;
    j = 0;

    for (i = 0; i < n; i++) {
        prefix = 0;
        time = NULL;
        set = 0;

        if (ngx_strncmp(names[i].data, "min_ttl=", 8) == 0) {
            prefix = 8;
            time = &r->min_ttl;
            set = NGX_RESOLVER_MIN_TTL_SET;

        } else if (ngx_strncmp(names[i].data, "max_ttl=", 8) == 0) {
            prefix = 8;
            time = &r->max_ttl;
            set = NGX_RESOLVER_MAX_TTL_SET;

        } else if (ngx_strncmp(names[i].data, "negative_valid=", 15) == 0) {
            prefix = 15;
            time = &r->negative_valid;
            set = NGX_RESOLVER_NEGATIVE_SET;

        } else if (ngx_strncmp(names[i].data, "error_valid=", 12) == 0) {
            prefix = 12;
            time = &r->error_valid;
            set = NGX_RESOLVER_ERROR_SET;

        } else if (ngx_strncmp(names[i].data, "stale_valid=", 12) == 0) {
            prefix = 12;
            time = &r->stale_valid;
            set = NGX_RESOLVER_STALE_SET;
        }

        if (time != NULL) {
            if (seen & set) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "duplicate resolver parameter \"%V\"",
                                   &names[i]);
                return NGX_ERROR;
            }

            seen |= set;
            s.len = names[i].len - prefix;
            s.data = names[i].data + prefix;
            *time = ngx_parse_time(&s, 1);

            if (*time == (time_t) NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid resolver parameter \"%V\"",
                                   &names[i]);
                return NGX_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(names[i].data, "valid=", 6) == 0) {
            valid = 1;

        } else if (ngx_strncmp(names[i].data, "local=", 6) == 0) {
            if (ngx_strcmp(names[i].data + 6, "on") == 0) {
                local = 1;
            }

        } else if (ngx_strncmp(names[i].data, "ipv4=", 5) != 0
                   && ngx_strncmp(names[i].data, "ipv6=", 5) != 0)
        {
            targets++;
            target = j;
        }

        v[j++] = names[i];
    }

    if (valid && (seen & (NGX_RESOLVER_MIN_TTL_SET|NGX_RESOLVER_MAX_TTL_SET))) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"valid\" cannot be used with "
                           "\"min_ttl\" or \"max_ttl\"");
        return NGX_ERROR;
    }

    if (r->max_ttl && r->min_ttl > r->max_ttl) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"min_ttl\" must not exceed \"max_ttl\"");
        return NGX_ERROR;
    }

    if (j == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "no name servers defined");
        return NGX_ERROR;
    }

    if (nameservers == NULL || targets != 1 || local) {
        *values = v;
        *nelts = j;
        return NGX_OK;
    }

    ns = ngx_resolver_add_nameserver(cf, nameservers, &v[target]);
    if (ns == NULL) {
        return NGX_ERROR;
    }

    if (ns->references == NULL) {
        ns->references = ngx_array_create(cf->temp_pool, 1,
                                          sizeof(ngx_resolver_reference_t));
        if (ns->references == NULL) {
            return NGX_ERROR;
        }
    }

    ref = ngx_array_push(ns->references);
    if (ref == NULL) {
        return NGX_ERROR;
    }

    ref->resolver = r;
    ref->names = v;
    ref->nelts = j;
    ref->target = target;
    ref->file = cf->conf_file->file.name;
    ref->line = cf->conf_file->line;
    ref->fd = cf->conf_file->file.fd;

    return NGX_DONE;
}


char *
ngx_resolver_init_nameservers(ngx_conf_t *cf, ngx_array_t **nameservers)
{
    ngx_uint_t                  i, j, n, target;
    ngx_conf_t                  pcf;
    ngx_conf_file_t             file;
    ngx_array_t                *list;
    ngx_resolver_reference_t   *refs;
    ngx_resolver_nameserver_t  *ns, *selected;

    list = *nameservers;

    if (list == NULL) {
        return NGX_CONF_OK;
    }

    pcf = *cf;
    file = *cf->conf_file;
    pcf.conf_file = &file;
    ns = list->elts;

    for (i = 0; i < list->nelts; i++) {
        if (ns[i].references == NULL) {
            continue;
        }

        selected = ns[i].servers ? &ns[i] : NULL;
        refs = ns[i].references->elts;

        for (j = 0; j < ns[i].references->nelts; j++) {
            file.file.name = refs[j].file;
            file.file.fd = refs[j].fd;
            file.line = refs[j].line;

            n = refs[j].nelts;

            if (selected != NULL) {
                target = refs[j].target;
                n--;
                ngx_memmove(&refs[j].names[target], &refs[j].names[target + 1],
                            (n - target) * sizeof(ngx_str_t));
            }

            if (ngx_resolver_init_connections(&pcf, refs[j].resolver,
                                              refs[j].names, n, selected)
                == NULL)
            {
                return NGX_CONF_ERROR;
            }
        }
    }

    *nameservers = NULL;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_resolver_init_nameserver(ngx_conf_t *cf, ngx_resolver_t *r,
    ngx_resolver_nameserver_t *ns)
{
    ngx_uint_t                  i, n, level, total, first;
    ngx_resolver_server_t      *servers, **sorted, *server;
    ngx_resolver_connection_t  *rec;

    n = r->connections.nelts + ns->servers->nelts;
    servers = ngx_pcalloc(cf->pool, n * sizeof(ngx_resolver_server_t));
    sorted = ngx_palloc(cf->temp_pool, n * sizeof(ngx_resolver_server_t *));

    if (servers == NULL || sorted == NULL) {
        return NGX_ERROR;
    }

    rec = r->connections.elts;

    for (i = 0; i < r->connections.nelts; i++) {
        servers[i].addr.sockaddr = rec[i].sockaddr;
        servers[i].addr.socklen = rec[i].socklen;
        servers[i].addr.name = rec[i].server;
        servers[i].peer.level = 1;
        servers[i].peer.weight = 1;
        servers[i].peer.fail_timeout = 10;
    }

    ngx_memcpy(servers + i, ns->servers->elts,
               ns->servers->nelts * sizeof(ngx_resolver_server_t));

    for (i = 0; i < n; i++) {
        sorted[i] = &servers[i];
    }

    ngx_qsort(sorted, (size_t) n, sizeof(ngx_resolver_server_t *),
              ngx_resolver_cmp_servers);

    if (ngx_array_init(&r->connections, cf->pool, n,
                       sizeof(ngx_resolver_connection_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    rec = r->connections.elts;
    ngx_memzero(rec, n * sizeof(ngx_resolver_connection_t));

    level = 0;
    total = 0;
    first = 0;

    for (i = 0; i < n; i++) {
        server = sorted[i];

        if (server->peer.level != level) {
            level = server->peer.level;
            total = 0;
            first = i;
        }

        if (server->peer.weight > (ngx_uint_t) NGX_MAX_INT_T_VALUE - total) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "total weight is too large in nameserver "
                               "\"%V\"", &ns->name);
            return NGX_ERROR;
        }

        total += server->peer.weight;
        server->peer.level_start = first;

        rec[i].sockaddr = server->addr.sockaddr;
        rec[i].socklen = server->addr.socklen;
        rec[i].server = server->addr.name;
        rec[i].resolver = r;
        rec[i].peer = &server->peer;
    }

    r->connections.nelts = n;
    r->nameserver = 1;

    return NGX_OK;
}


static int
ngx_resolver_cmp_servers(const void *one, const void *two)
{
    ngx_resolver_server_t  *first, *second;

    first = *(ngx_resolver_server_t **) one;
    second = *(ngx_resolver_server_t **) two;

    if (first->peer.level != second->peer.level) {
        return (first->peer.level < second->peer.level) ? -1 : 1;
    }

    if (first == second) {
        return 0;
    }

    return (first < second) ? -1 : 1;
}


char *
ngx_resolver_set_next_nameserver(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_command_t  command;

    command = *cmd;
    command.post = ngx_resolver_next_nameserver_masks;

    return ngx_conf_set_bitmask_slot(cf, &command, conf);
}


ngx_int_t
ngx_resolver_set_retry(ngx_conf_t *cf, ngx_resolver_t **resolver,
    ngx_uint_t mask, ngx_uint_t tries, ngx_msec_t timeout)
{
    ngx_resolver_t  *r, *owner;

    r = *resolver;

    if (r == NULL) {
        return NGX_OK;
    }

    if (mask & NGX_RESOLVER_FT_OFF) {
        mask = NGX_RESOLVER_FT_OFF;

    } else if (mask == NGX_RESOLVER_FT_DEFAULT) {
        mask = 0;
    }

    if (r->next_nameserver == mask && r->next_nameserver_tries == tries
        && r->next_nameserver_timeout == timeout)
    {
        return NGX_OK;
    }

    owner = r->owner ? r->owner : r;

    if (mask == 0 && tries == 0 && timeout == 0) {
        *resolver = owner;
        return NGX_OK;
    }

    r = ngx_palloc(cf->pool, sizeof(ngx_resolver_t));
    if (r == NULL) {
        return NGX_ERROR;
    }

    *r = *owner;
    r->owner = owner;
    r->next_nameserver = mask;
    r->next_nameserver_tries = tries;
    r->next_nameserver_timeout = timeout;
    *resolver = r;

    return NGX_OK;
}

#endif


char *
ngx_resolver_strerror(ngx_int_t err)
{
    static char *errors[] = {
        "Format error",     /* FORMERR */
        "Server failure",   /* SERVFAIL */
        "Host not found",   /* NXDOMAIN */
        "Unimplemented",    /* NOTIMP */
        "Operation refused" /* REFUSED */
    };

    if (err > 0 && err < 6) {
        return errors[err - 1];
    }

    if (err == NGX_RESOLVE_TIMEDOUT) {
        return "Operation timed out";
    }

    return "Unknown error";
}


static u_char *
ngx_resolver_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                     *p;
    ngx_resolver_connection_t  *rec;

    p = buf;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
    }

    rec = log->data;

    if (rec) {
        p = ngx_snprintf(p, len, ", resolver: %V", &rec->server);
    }

    return p;
}


static ngx_int_t
ngx_udp_connect(ngx_resolver_connection_t *rec)
{
    int                rc;
    ngx_int_t          event;
    ngx_event_t       *rev, *wev;
    ngx_socket_t       s;
    ngx_connection_t  *c;

    s = ngx_socket(rec->sockaddr->sa_family, SOCK_DGRAM, 0);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, &rec->log, 0, "UDP socket %d", s);

    if (s == (ngx_socket_t) -1) {
        ngx_log_error(NGX_LOG_ALERT, &rec->log, ngx_socket_errno,
                      ngx_socket_n " failed");
        return NGX_ERROR;
    }

    c = ngx_get_connection(s, &rec->log);

    if (c == NULL) {
        if (ngx_close_socket(s) == -1) {
            ngx_log_error(NGX_LOG_ALERT, &rec->log, ngx_socket_errno,
                          ngx_close_socket_n " failed");
        }

        return NGX_ERROR;
    }

    if (ngx_nonblocking(s) == -1) {
        ngx_log_error(NGX_LOG_ALERT, &rec->log, ngx_socket_errno,
                      ngx_nonblocking_n " failed");

        goto failed;
    }

    rev = c->read;
    wev = c->write;

    rev->log = &rec->log;
    wev->log = &rec->log;

    rec->udp = c;

    c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

    c->start_time = ngx_current_msec;

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, &rec->log, 0,
                   "connect to %V, fd:%d #%uA", &rec->server, s, c->number);

    rc = connect(s, rec->sockaddr, rec->socklen);

    if (rc == -1) {
        ngx_log_error(NGX_LOG_CRIT, &rec->log, ngx_socket_errno,
                      "connect() failed");

        goto failed;
    }

    /* UDP sockets are always ready to write */
    wev->ready = 1;

    event = (ngx_event_flags & NGX_USE_CLEAR_EVENT) ?
                /* kqueue, epoll */                 NGX_CLEAR_EVENT:
                /* select, poll, /dev/poll */       NGX_LEVEL_EVENT;
                /* eventport event type has no meaning: oneshot only */

    if (ngx_add_event(rev, NGX_READ_EVENT, event) != NGX_OK) {
        goto failed;
    }

    return NGX_OK;

failed:

    ngx_close_connection(c);
    rec->udp = NULL;

    return NGX_ERROR;
}


static ngx_int_t
ngx_tcp_connect(ngx_resolver_connection_t *rec)
{
    int                rc;
    ngx_int_t          event;
    ngx_err_t          err;
    ngx_uint_t         level;
    ngx_socket_t       s;
    ngx_event_t       *rev, *wev;
    ngx_connection_t  *c;

#if (NGX_HAVE_SOCKET_CLOEXEC)
    s = ngx_socket(rec->sockaddr->sa_family, SOCK_STREAM | SOCK_CLOEXEC, 0);

#else
    s = ngx_socket(rec->sockaddr->sa_family, SOCK_STREAM, 0);

#endif

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, &rec->log, 0, "TCP socket %d", s);

    if (s == (ngx_socket_t) -1) {
        ngx_log_error(NGX_LOG_ALERT, &rec->log, ngx_socket_errno,
                      ngx_socket_n " failed");
        return NGX_ERROR;
    }

    c = ngx_get_connection(s, &rec->log);

    if (c == NULL) {
        if (ngx_close_socket(s) == -1) {
            ngx_log_error(NGX_LOG_ALERT, &rec->log, ngx_socket_errno,
                          ngx_close_socket_n " failed");
        }

        return NGX_ERROR;
    }

    if (ngx_nonblocking(s) == -1) {
        ngx_log_error(NGX_LOG_ALERT, &rec->log, ngx_socket_errno,
                      ngx_nonblocking_n " failed");

        goto failed;
    }

#if (NGX_HAVE_FD_CLOEXEC)
    if (ngx_cloexec(s) == -1) {
        ngx_log_error(NGX_LOG_ALERT, &rec->log, ngx_socket_errno,
                      ngx_cloexec_n " failed");

        goto failed;
    }
#endif

    rev = c->read;
    wev = c->write;

    rev->log = &rec->log;
    wev->log = &rec->log;

    rec->tcp = c;

    c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

    c->start_time = ngx_current_msec;

    if (ngx_add_conn) {
        if (ngx_add_conn(c) == NGX_ERROR) {
            goto failed;
        }
    }

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, &rec->log, 0,
                   "connect to %V, fd:%d #%uA", &rec->server, s, c->number);

    rc = connect(s, rec->sockaddr, rec->socklen);

    if (rc == -1) {
        err = ngx_socket_errno;


        if (err != NGX_EINPROGRESS
#if (NGX_WIN32)
            /* Winsock returns WSAEWOULDBLOCK (NGX_EAGAIN) */
            && err != NGX_EAGAIN
#endif
            )
        {
            if (err == NGX_ECONNREFUSED
#if (NGX_LINUX)
                /*
                 * Linux returns EAGAIN instead of ECONNREFUSED
                 * for unix sockets if listen queue is full
                 */
                || err == NGX_EAGAIN
#endif
                || err == NGX_ECONNRESET
                || err == NGX_ENETDOWN
                || err == NGX_ENETUNREACH
                || err == NGX_EHOSTDOWN
                || err == NGX_EHOSTUNREACH)
            {
                level = NGX_LOG_ERR;

            } else {
                level = NGX_LOG_CRIT;
            }

            ngx_log_error(level, &rec->log, err, "connect() to %V failed",
                          &rec->server);

            ngx_close_connection(c);
            rec->tcp = NULL;

            return NGX_ERROR;
        }
    }

    if (ngx_add_conn) {
        if (rc == -1) {

            /* NGX_EINPROGRESS */

            return NGX_AGAIN;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, &rec->log, 0, "connected");

        wev->ready = 1;

        return NGX_OK;
    }

    if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {

        /* kqueue */

        event = NGX_CLEAR_EVENT;

    } else {

        /* select, poll, /dev/poll */

        event = NGX_LEVEL_EVENT;
    }

    if (ngx_add_event(rev, NGX_READ_EVENT, event) != NGX_OK) {
        goto failed;
    }

    if (rc == -1) {

        /* NGX_EINPROGRESS */

        if (ngx_add_event(wev, NGX_WRITE_EVENT, event) != NGX_OK) {
            goto failed;
        }

        return NGX_AGAIN;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, &rec->log, 0, "connected");

    wev->ready = 1;

    return NGX_OK;

failed:

    ngx_close_connection(c);
    rec->tcp = NULL;

    return NGX_ERROR;
}


static ngx_int_t
ngx_resolver_cmp_srvs(const void *one, const void *two)
{
    ngx_int_t            p1, p2;
    ngx_resolver_srv_t  *first, *second;

    first = (ngx_resolver_srv_t *) one;
    second = (ngx_resolver_srv_t *) two;

    p1 = first->priority;
    p2 = second->priority;

    return p1 - p2;
}
