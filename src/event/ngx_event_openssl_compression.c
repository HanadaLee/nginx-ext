
/*
 * Copyright (C) Hanada
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#if (NGX_EXT && NGX_SSL_CERT_COMPRESSION)

#include <openssl/comp.h>
#include <openssl/sha.h>
#if (NGX_THREADS)
#include <ngx_thread_pool.h>
#endif


#define NGX_SSL_COMP_ENTRIES  32
#define NGX_SSL_COMP_LIMIT    (128 * 1024)


typedef struct ngx_ssl_comp_work_s  ngx_ssl_comp_work_t;


typedef struct {
    ngx_queue_t            queue;
    ngx_uint_t             nelts;
#if (NGX_THREADS)
    ngx_thread_pool_t     *threads;
#endif
} ngx_ssl_comp_cache_t;


typedef struct {
    ngx_queue_t            queue;
    u_char                 key[SHA256_DIGEST_LENGTH];
    int                    algorithm;
    size_t                 original_len;
    size_t                 len;
    u_char                *data;
    ngx_ssl_comp_work_t   *work;
} ngx_ssl_comp_entry_t;


typedef struct {
    ngx_ssl_comp_cache_t  *cache;
    int                    algorithm;
    u_char                 key[SHA256_DIGEST_LENGTH];
    unsigned               capture:1;
    unsigned               stapled:1;
} ngx_ssl_comp_ctx_t;


struct ngx_ssl_comp_work_s {
#if (NGX_THREADS)
    ngx_thread_task_t      task;
#else
    ngx_event_t            event;
#endif
    ngx_ssl_comp_entry_t  *entry;
    size_t                 len;
    u_char                *result;
    u_char                *input;
    int                    algorithm;
    int                    size;
};


static void ngx_ssl_comp_free_entry(ngx_ssl_comp_entry_t *entry);
static void ngx_ssl_comp_cleanup(void *data);
static ngx_int_t ngx_ssl_comp_cache_key(ngx_ssl_conn_t *ssl,
    ngx_ssl_comp_ctx_t *ctx);
static ngx_ssl_comp_entry_t *ngx_ssl_comp_lookup(ngx_ssl_comp_ctx_t *ctx);
static ngx_uint_t ngx_ssl_comp_cacheable(ngx_ssl_conn_t *ssl, const u_char *p,
    size_t len);
static void ngx_ssl_comp_task_handler(void *data, ngx_log_t *log);
static void ngx_ssl_comp_completion_handler(ngx_event_t *ev);
static void ngx_ssl_comp_event_handler(ngx_event_t *ev);


static int                 ngx_ssl_comp_cache_index = -1;
static int                 ngx_ssl_comp_ctx_index = -1;
static ngx_ssl_comp_ctx_t  ngx_ssl_comp_observed;


ngx_int_t
ngx_ssl_cert_compression_init(ngx_conf_t *cf, ngx_ssl_t *ssl)
{
    ngx_pool_cleanup_t    *cln;
    ngx_ssl_comp_cache_t  *cache;

    if (ngx_ssl_comp_cache_index == -1) {
        ngx_ssl_comp_cache_index = SSL_CTX_get_ex_new_index(0, NULL, NULL,
                                                            NULL, NULL);
    }

    if (ngx_ssl_comp_ctx_index == -1) {
        ngx_ssl_comp_ctx_index = SSL_get_ex_new_index(0, NULL, NULL, NULL,
                                                      NULL);
    }

    if (ngx_ssl_comp_cache_index == -1 || ngx_ssl_comp_ctx_index == -1) {
        return NGX_ERROR;
    }

    cln = ngx_pool_cleanup_add(cf->pool, sizeof(ngx_ssl_comp_cache_t));
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cache = cln->data;
    ngx_queue_init(&cache->queue);
    cache->nelts = 0;

#if (NGX_THREADS)
    cache->threads = ngx_thread_pool_add(cf, NULL);
    if (cache->threads == NULL) {
        return NGX_ERROR;
    }
#endif

    if (!SSL_CTX_set_ex_data(ssl->ctx, ngx_ssl_comp_cache_index, cache)) {
        return NGX_ERROR;
    }

    cln->handler = ngx_ssl_comp_cleanup;
    SSL_CTX_clear_options(ssl->ctx, SSL_OP_NO_TX_CERTIFICATE_COMPRESSION);

    return NGX_OK;
}


void
ngx_ssl_cert_compression_hello(ngx_ssl_conn_t *ssl)
{
    int                    alg, *exts;
    size_t                 i, len, nelts;
    SSL_CTX               *sctx;
    const u_char          *p;
    ngx_connection_t      *c;
    ngx_ssl_comp_ctx_t    *ctx;
    ngx_ssl_comp_cache_t  *cache;

    if (ngx_ssl_comp_ctx_index == -1) {
        return;
    }

    c = ngx_ssl_get_connection(ssl);
    sctx = SSL_get_SSL_CTX(ssl);
    cache = SSL_CTX_get_ex_data(sctx, ngx_ssl_comp_cache_index);
    ctx = SSL_get_ex_data(ssl, ngx_ssl_comp_ctx_index);

    if (ctx == NULL) {
        return;
    }

    if (ctx != &ngx_ssl_comp_observed) {
        ctx->algorithm = 0;
        ctx->capture = 0;
        ctx->stapled = 0;
    }

    if (cache == NULL
        || (SSL_get_options(ssl) & SSL_OP_NO_TX_CERTIFICATE_COMPRESSION)
        || !SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_compress_certificate,
                                      &p, &len)
        || len < 3 || p[0] != len - 1 || (len & 1) == 0)
    {
        return;
    }

    for (i = 1; i < len; i += 2) {
        alg = (p[i] << 8) | p[i + 1];

        if ((alg == TLSEXT_comp_cert_zlib && COMP_zlib_oneshot() != NULL)
            || (alg == TLSEXT_comp_cert_brotli && COMP_brotli_oneshot() != NULL)
            || (alg == TLSEXT_comp_cert_zstd && COMP_zstd_oneshot() != NULL))
        {
            break;
        }
    }

    if (i == len) {
        return;
    }

    /* A negotiated custom extension can vary even for the same chain. */

    if (!SSL_client_hello_get1_extensions_present(ssl, &exts, &nelts)) {
        return;
    }

    for (i = 0; i < nelts; i++) {
#if (NGX_QUIC_OPENSSL_COMPAT)
        /* nginx registers QUIC transport parameters in EncryptedExtensions. */
        if (exts[i] == TLSEXT_TYPE_quic_transport_parameters
            && c->listening->quic)
        {
            continue;
        }
#endif

        if (SSL_CTX_has_client_custom_ext(sctx, exts[i])) {
            break;
        }
    }

    OPENSSL_free(exts);

    if (i != nelts) {
        return;
    }

    if (ctx == &ngx_ssl_comp_observed) {
        ctx = ngx_pcalloc(c->pool, sizeof(ngx_ssl_comp_ctx_t));
        if (ctx == NULL || !SSL_set_ex_data(ssl, ngx_ssl_comp_ctx_index, ctx)) {
            return;
        }
    }

    ctx->cache = cache;
    ctx->algorithm = alg;
}


void
ngx_ssl_cert_compression_stapled(ngx_ssl_conn_t *ssl)
{
    ngx_ssl_comp_ctx_t  *ctx;

    if (ngx_ssl_comp_ctx_index != -1) {
        ctx = SSL_get_ex_data(ssl, ngx_ssl_comp_ctx_index);
        if (ctx && ctx != &ngx_ssl_comp_observed) {
            ctx->stapled = 1;
        }
    }
}


void
ngx_ssl_cert_compression_select(ngx_ssl_conn_t *ssl)
{
    ngx_ssl_comp_ctx_t    *ctx;
    ngx_ssl_comp_entry_t  *entry;

    if (ngx_ssl_comp_ctx_index == -1 || SSL_session_reused(ssl)) {
        return;
    }

    ctx = SSL_get_ex_data(ssl, ngx_ssl_comp_ctx_index);
    if (ctx == NULL || ctx->algorithm == 0
        || ngx_ssl_comp_cache_key(ssl, ctx) != NGX_OK)
    {
        return;
    }

    entry = ngx_ssl_comp_lookup(ctx);
    if (entry) {
        if (entry->len
            && !SSL_set1_compressed_cert(ssl, entry->algorithm, entry->data,
                                         entry->len, entry->original_len))
        {
            ERR_clear_error();
        }

        return;
    }

    ctx->capture = 1;
}


void
ngx_ssl_cert_compression_message(int write_p, int version, int content_type,
    const void *buf, size_t len, ngx_ssl_conn_t *ssl, void *arg)
{
    const u_char          *p = buf;

    ngx_queue_t           *q;
    ngx_event_t           *ev;
    ngx_connection_t      *c;
    ngx_ssl_comp_ctx_t    *ctx;
    ngx_ssl_comp_work_t   *work;
    ngx_ssl_comp_entry_t  *entry;

    if (content_type != SSL3_RT_HANDSHAKE || len < 4
        || ngx_ssl_comp_ctx_index == -1)
    {
        return;
    }

    if (!write_p) {
        if (p[0] == SSL3_MT_CLIENT_HELLO
            && SSL_get_ex_data(ssl, ngx_ssl_comp_ctx_index) == NULL)
        {
            (void) SSL_set_ex_data(ssl, ngx_ssl_comp_ctx_index,
                                   &ngx_ssl_comp_observed);
        }

        return;
    }

    if (p[0] != SSL3_MT_CERTIFICATE || len > NGX_SSL_COMP_LIMIT) {
        return;
    }

    ctx = SSL_get_ex_data(ssl, ngx_ssl_comp_ctx_index);
    if (ctx == NULL || !ctx->capture) {
        return;
    }

    ctx->capture = 0;
    c = ngx_ssl_get_connection(ssl);

    if (ngx_ssl_comp_lookup(ctx) != NULL
        || !ngx_ssl_comp_cacheable(ssl, p + 4, len - 4))
    {
        return;
    }

    /* Evict only completed entries; pending jobs own their input and output. */

    if (ctx->cache->nelts == NGX_SSL_COMP_ENTRIES) {
        for (q = ngx_queue_last(&ctx->cache->queue);
             q != ngx_queue_sentinel(&ctx->cache->queue);
             q = ngx_queue_prev(q))
        {
            entry = ngx_queue_data(q, ngx_ssl_comp_entry_t, queue);
            if (entry->work == NULL) {
                ngx_ssl_comp_free_entry(entry);
                ctx->cache->nelts--;
                break;
            }
        }

        if (ctx->cache->nelts == NGX_SSL_COMP_ENTRIES) {
            return;
        }
    }

    entry = ngx_calloc(sizeof(ngx_ssl_comp_entry_t), c->log);
    if (entry == NULL) {
        return;
    }

    len -= 4;
    work = ngx_calloc(sizeof(*work) + 2 * len, c->log);
    if (work == NULL) {
        ngx_free(entry);
        return;
    }

    work->input = (u_char *) (work + 1);
    work->result = work->input + len;

    work->entry = entry;
    work->algorithm = ctx->algorithm;
    work->len = len;
    ngx_memcpy(work->input, p + 4, len);

    entry->algorithm = ctx->algorithm;
    ngx_memcpy(entry->key, ctx->key, sizeof(ctx->key));
    entry->original_len = len;
    entry->work = work;

#if (NGX_THREADS)
    ev = &work->task.event;
#else
    ev = &work->event;
#endif

    ev->data = work;
    ev->log = ngx_cycle->log;

#if (NGX_THREADS)
    if (ngx_process == NGX_PROCESS_WORKER) {
        work->task.ctx = work;
        work->task.handler = ngx_ssl_comp_task_handler;
        ev->handler = ngx_ssl_comp_completion_handler;

        if (ngx_thread_task_post(ctx->cache->threads, &work->task) != NGX_OK) {
            ngx_free(work);
            ngx_free(entry);
            return;
        }

    } else
#endif
    {
        ev->handler = ngx_ssl_comp_event_handler;
        ngx_post_event(ev, &ngx_posted_next_events);
    }

    ngx_queue_insert_head(&ctx->cache->queue, &entry->queue);
    ctx->cache->nelts++;
}


static void
ngx_ssl_comp_free_entry(ngx_ssl_comp_entry_t *entry)
{
    ngx_queue_remove(&entry->queue);

    if (entry->work) {
#if (NGX_THREADS)
        if (entry->work->task.event.posted) {
            ngx_delete_posted_event(&entry->work->task.event);
            ngx_free(entry->work);

        } else {
            /* The thread only uses the work's private buffers. */
            entry->work->entry = NULL;
        }
#else
        ngx_delete_posted_event(&entry->work->event);
        ngx_free(entry->work);
#endif
    }

    if (entry->data) {
        ngx_free(entry->data);
    }

    ngx_free(entry);
}


static void
ngx_ssl_comp_cleanup(void *data)
{
    ngx_ssl_comp_cache_t  *cache = data;

    ngx_queue_t           *q;
    ngx_ssl_comp_entry_t  *entry;

    while (!ngx_queue_empty(&cache->queue)) {
        q = ngx_queue_head(&cache->queue);
        entry = ngx_queue_data(q, ngx_ssl_comp_entry_t, queue);
        ngx_ssl_comp_free_entry(entry);
    }
}


static ngx_int_t
ngx_ssl_comp_cache_key(ngx_ssl_conn_t *ssl, ngx_ssl_comp_ctx_t *ctx)
{
    int              i;
    long             len;
    X509            *cert;
    u_char           digest[SHA256_DIGEST_LENGTH], *response;
    ngx_int_t        rc;
    EVP_MD_CTX      *md;
    STACK_OF(X509)  *chain;

    if (SSL_set_current_cert(ssl, SSL_CERT_SET_SERVER) != 1
        || !SSL_get0_chain_certs(ssl, &chain) || chain == NULL)
    {
        return NGX_DECLINED;
    }

    len = SSL_get_tlsext_status_ocsp_resp(ssl, &response);
    if (len > 0
        && (!ctx->stapled
            || SSL_get_tlsext_status_type(ssl) != TLSEXT_STATUSTYPE_ocsp))
    {
        /* Another status callback owns this response and can decline it. */
        return NGX_DECLINED;
    }

    md = EVP_MD_CTX_new();
    if (md == NULL) {
        return NGX_ERROR;
    }

    rc = NGX_ERROR;

    if (EVP_DigestInit_ex(md, EVP_sha256(), NULL) != 1) {
        goto done;
    }

    cert = SSL_get_certificate(ssl);

    for (i = 0; /* void */; i++) {
        if (!X509_digest(cert, EVP_sha256(), digest, NULL)
            || !EVP_DigestUpdate(md, digest, sizeof(digest)))
        {
            goto done;
        }

        if (i == sk_X509_num(chain)) {
            break;
        }

        cert = sk_X509_value(chain, i);
    }

    if (len > 0 && !EVP_DigestUpdate(md, response, len)) {
        goto done;
    }

    if (EVP_DigestUpdate(md, &i, sizeof(i))
        && EVP_DigestFinal_ex(md, ctx->key, NULL))
    {
        rc = NGX_OK;
    }

done:

    EVP_MD_CTX_free(md);

    return rc;
}


static ngx_ssl_comp_entry_t *
ngx_ssl_comp_lookup(ngx_ssl_comp_ctx_t *ctx)
{
    ngx_queue_t           *q;
    ngx_ssl_comp_entry_t  *entry;

    for (q = ngx_queue_head(&ctx->cache->queue);
         q != ngx_queue_sentinel(&ctx->cache->queue);
         q = ngx_queue_next(q))
    {
        entry = ngx_queue_data(q, ngx_ssl_comp_entry_t, queue);

        if (entry->algorithm == ctx->algorithm
            && ngx_memcmp(entry->key, ctx->key, sizeof(ctx->key)) == 0)
        {
            ngx_queue_remove(q);
            ngx_queue_insert_head(&ctx->cache->queue, q);
            return entry;
        }
    }

    return NULL;
}


/*
 * Only retain the ordinary TLS 1.3 certificate list and the exact OCSP
 * response associated with this handshake.  Leave other extensions to SSL.
 */

static ngx_uint_t
ngx_ssl_comp_cacheable(ngx_ssl_conn_t *ssl, const u_char *p, size_t len)
{
    long           n;
    size_t         size;
    u_char        *response;
    ngx_uint_t     leaf;
    const u_char  *last;

    last = p + len;

    if (len < 4 || p[0] != 0
        || (size_t) ((p[1] << 16) | (p[2] << 8) | p[3]) != len - 4)
    {
        return 0;
    }

    n = SSL_get_tlsext_status_ocsp_resp(ssl, &response);
    leaf = 1;

    for (p += 4; p < last; leaf = 0) {
        if (last - p < 3) {
            return 0;
        }

        size = (p[0] << 16) | (p[1] << 8) | p[2];
        p += 3;

        if ((size_t) (last - p) < size + 2) {
            return 0;
        }

        p += size;
        size = (p[0] << 8) | p[1];
        p += 2;

        if (leaf && n > 0) {
            if ((size_t) (last - p) < size || size != (size_t) n + 8
                || p[0] != 0 || p[1] != TLSEXT_TYPE_status_request
                || (size_t) ((p[2] << 8) | p[3]) != size - 4
                || p[4] != TLSEXT_STATUSTYPE_ocsp
                || ((p[5] << 16) | (p[6] << 8) | p[7]) != n
                || ngx_memcmp(p + 8, response, n) != 0)
            {
                return 0;
            }

            p += size;

        } else if (size) {
            return 0;
        }
    }

    return !leaf;
}


static void
ngx_ssl_comp_task_handler(void *data, ngx_log_t *log)
{
    ngx_ssl_comp_work_t  *work = data;

    COMP_CTX             *ctx;
    COMP_METHOD          *method;

    switch (work->algorithm) {

    case TLSEXT_comp_cert_zlib:
        method = COMP_zlib_oneshot();
        break;

    case TLSEXT_comp_cert_brotli:
        method = COMP_brotli_oneshot();
        break;

    default:
        method = COMP_zstd_oneshot();
    }

    ctx = COMP_CTX_new(method);
    if (ctx) {
        work->size = COMP_compress_block(ctx, work->result, work->len,
                                         work->input, work->len);
        COMP_CTX_free(ctx);
    }

    if (work->size <= 0) {
        ERR_clear_error();
    }
}


static void
ngx_ssl_comp_completion_handler(ngx_event_t *ev)
{
    ngx_ssl_comp_work_t   *work = ev->data;

    ngx_ssl_comp_entry_t  *entry;

    entry = work->entry;
    if (entry != NULL) {
        entry->work = NULL;

        if (work->size > 0 && (size_t) work->size < work->len) {
            entry->data = ngx_alloc(work->size, ngx_cycle->log);

            if (entry->data) {
                ngx_memcpy(entry->data, work->result, work->size);
                entry->len = work->size;
            }
        }
    }

    ngx_free(work);
}


static void
ngx_ssl_comp_event_handler(ngx_event_t *ev)
{
    ngx_ssl_comp_task_handler(ev->data, ev->log);
    ngx_ssl_comp_completion_handler(ev);
}

#endif
