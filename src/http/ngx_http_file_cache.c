
/*
 * Copyright (C) 2025 Web Server LLC
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>
#if (NGX_EXT && NGX_EXPR && !(NGX_WIN32))
#include <ngx_http_expr_module.h>
#endif


#if (NGX_EXT && !(NGX_WIN32))

#define NGX_HTTP_EARLY_BUCKETS   256
#define NGX_HTTP_EARLY_WAYS      4
#define NGX_HTTP_EARLY_SLOTS     (NGX_HTTP_EARLY_BUCKETS * NGX_HTTP_EARLY_WAYS)
#define NGX_HTTP_EARLY_CHANGES   256
#define NGX_HTTP_EARLY_WORDS     ((NGX_MAX_PROCESSES + 31) / 32)


typedef enum {
    NGX_HTTP_EARLY_FREE = 0,
    NGX_HTTP_EARLY_WRITING,
    NGX_HTTP_EARLY_PUBLISHING,
    NGX_HTTP_EARLY_COMPLETE,
    NGX_HTTP_EARLY_FAILED
} ngx_http_cache_early_state_e;


typedef struct {
    ngx_http_file_cache_sh_t      *zone;
    u_char                         key[NGX_HTTP_CACHE_KEY_LEN];
    u_char                         suffix[11];
    u_char                         id[NGX_HTTP_CACHE_KEY_LEN];
    ngx_http_cache_early_state_e   state;
    ngx_msec_t                     lock_time;
    ngx_pid_t                      pid;
    ngx_atomic_uint_t              epoch;
    ngx_file_uniq_t                ino;
    dev_t                          dev;
    off_t                          written;
    off_t                          expected;
    size_t                         body_start;
    time_t                         valid;
    time_t                         started;
    uint32_t                       readers[NGX_HTTP_EARLY_WORDS];
} ngx_http_cache_early_slot_t;


typedef struct {
    u_char                         id[NGX_HTTP_CACHE_KEY_LEN];
    unsigned                       all:1;
} ngx_http_cache_early_change_t;


typedef struct {
    ngx_atomic_t                   epoch;
    ngx_http_cache_early_change_t  changes[NGX_HTTP_EARLY_CHANGES];
    ngx_pid_t                      pids[NGX_MAX_PROCESSES];
    ngx_http_cache_early_slot_t    slots[NGX_HTTP_EARLY_SLOTS];
} ngx_http_cache_early_sh_t;


typedef struct ngx_http_cache_early_wait_s  ngx_http_cache_early_wait_t;


struct ngx_http_cache_early_wait_s {
    ngx_queue_t                    queue;
    ngx_event_t                    event;
    ngx_http_cache_early_wait_t   *next;
    ngx_http_cache_early_slot_t   *slot;
    ngx_uint_t                     index;
    ngx_uint_t                     users;

    ngx_slab_pool_t               *pool;
    ngx_http_cache_early_sh_t     *sh;
    ngx_http_cache_early_state_e   state;
    off_t                          written;
    ngx_atomic_uint_t              epoch;
    ngx_msec_t                     interval;

    unsigned                       recalc:1;
};


struct ngx_http_cache_early_s {
    ngx_http_request_t            *request;
    ngx_slab_pool_t               *pool;
    ngx_http_cache_early_slot_t   *slot;
    ngx_http_cache_early_wait_t   *wait;
    ngx_http_cleanup_t            *cleanup;
    ngx_file_t                     file;
    ngx_queue_t                    queue;
    ngx_event_t                    event;
    ngx_chain_t                   *free;
    ngx_chain_t                   *busy;
    off_t                          cursor;
    off_t                          seen;
    ngx_msec_t                     last_progress;
    ngx_msec_t                     timeout;
    ngx_msec_t                     interval;
    unsigned                       queued:1;
};

#endif


static ngx_int_t ngx_http_file_cache_lock(ngx_http_request_t *r,
    ngx_http_cache_t *c);
static void ngx_http_file_cache_lock_wait_handler(ngx_event_t *ev);
static ngx_int_t ngx_http_file_cache_lock_wait(ngx_http_request_t *r,
    ngx_http_cache_t *c);
static ngx_int_t ngx_http_file_cache_read(ngx_http_request_t *r,
    ngx_http_cache_t *c);
static ssize_t ngx_http_file_cache_aio_read(ngx_http_request_t *r,
    ngx_http_cache_t *c);
#if (NGX_HAVE_FILE_AIO)
static void ngx_http_cache_aio_event_handler(ngx_event_t *ev);
#endif
#if (NGX_THREADS)
static ngx_int_t ngx_http_cache_thread_handler(ngx_thread_task_t *task,
    ngx_file_t *file);
static void ngx_http_cache_thread_event_handler(ngx_event_t *ev);
#endif
static ngx_int_t ngx_http_file_cache_exists(ngx_http_file_cache_t *cache,
    ngx_http_cache_t *c);
static ngx_int_t ngx_http_file_cache_name(ngx_http_request_t *r,
    ngx_path_t *path);
static ngx_http_file_cache_node_t *
    ngx_http_file_cache_lookup(ngx_http_file_cache_t *cache, u_char *key);
static void ngx_http_file_cache_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static void ngx_http_file_cache_vary(ngx_http_request_t *r, u_char *vary,
    size_t len, u_char *hash);
static void ngx_http_file_cache_vary_header(ngx_http_request_t *r,
    ngx_md5_t *md5, ngx_str_t *name);
static ngx_int_t ngx_http_file_cache_reopen(ngx_http_request_t *r,
    ngx_http_cache_t *c);
static ngx_int_t ngx_http_file_cache_update_variant(ngx_http_request_t *r,
    ngx_http_cache_t *c);
static void ngx_http_file_cache_cleanup(void *data);

#if (NGX_EXT)
static void ngx_http_file_cache_expired_pool_cleanup(void *data);
static ngx_uint_t ngx_http_file_cache_commit_busy(ngx_http_cache_t *c);
static ngx_int_t ngx_http_file_cache_commit(ngx_http_request_t *r,
    ngx_http_cache_t *c);

#if !(NGX_WIN32)
static void ngx_http_file_cache_expired_watch(ngx_http_request_t *r);
#endif
#endif

static time_t ngx_http_file_cache_forced_expire(ngx_http_file_cache_t *cache);
static time_t ngx_http_file_cache_expire(ngx_http_file_cache_t *cache);
static void ngx_http_file_cache_delete(ngx_http_file_cache_t *cache,
    ngx_queue_t *q, u_char *name);
static void ngx_http_file_cache_loader_sleep(ngx_http_file_cache_t *cache);
static ngx_int_t ngx_http_file_cache_noop(ngx_tree_ctx_t *ctx,
    ngx_str_t *path);
static ngx_int_t ngx_http_file_cache_manage_file(ngx_tree_ctx_t *ctx,
    ngx_str_t *path);
static ngx_int_t ngx_http_file_cache_manage_directory(ngx_tree_ctx_t *ctx,
    ngx_str_t *path);
static ngx_int_t ngx_http_file_cache_add_file(ngx_tree_ctx_t *ctx,
    ngx_str_t *path);
static ngx_int_t ngx_http_file_cache_add(ngx_http_file_cache_t *cache,
    ngx_http_cache_t *c);
static ngx_int_t ngx_http_file_cache_delete_file(ngx_tree_ctx_t *ctx,
    ngx_str_t *path);
static void ngx_http_file_cache_set_watermark(ngx_http_file_cache_t *cache);


#if (NGX_EXT && !(NGX_WIN32))

static void ngx_http_cache_early_watch(ngx_http_request_t *r);
static ngx_int_t ngx_http_cache_early_open(ngx_http_request_t *r);
static ngx_uint_t ngx_http_cache_early_publishing(ngx_http_request_t *r);
static ngx_int_t ngx_http_cache_early_commit(ngx_http_request_t *r);
static ngx_uint_t ngx_http_cache_early_valid(ngx_http_request_t *r);
static void ngx_http_cache_early_finish(ngx_http_cache_t *c,
    ngx_uint_t complete);
static ngx_int_t ngx_http_cache_early_send(ngx_http_request_t *r);
static ngx_int_t ngx_http_cache_early_init(ngx_shm_zone_t *zone, void *data);
static ngx_uint_t ngx_http_cache_early_current(ngx_http_cache_early_sh_t *sh,
    const u_char *id, ngx_atomic_uint_t *epoch);
static ngx_int_t ngx_http_cache_early_allowed(ngx_http_request_t *r,
    time_t started, u_char *id);
static ngx_int_t ngx_http_cache_early_eligible(ngx_http_request_t *r);
static void ngx_http_cache_early_timer(ngx_event_t *ev, ngx_msec_t delay);
static void ngx_http_cache_early_dequeue(ngx_http_cache_early_t *e);
static void ngx_http_cache_early_tick(ngx_event_t *ev);
static void ngx_http_cache_early_resume(ngx_event_t *ev);
static void ngx_http_cache_early_writer(ngx_http_request_t *r);
static void ngx_http_cache_early_release(ngx_http_cache_early_wait_t *wait,
    ngx_slab_pool_t *pool);
static void ngx_http_cache_early_cleanup(void *data);

#endif


ngx_str_t  ngx_http_cache_status[] = {
    ngx_string("MISS"),
    ngx_string("BYPASS"),
    ngx_string("EXPIRED"),
    ngx_string("STALE"),
    ngx_string("UPDATING"),
    ngx_string("REVALIDATED"),
    ngx_string("HIT")
};


static u_char  ngx_http_file_cache_key[] = { LF, 'K', 'E', 'Y', ':', ' ' };


#if (NGX_EXT && !(NGX_WIN32))
static ngx_http_cache_early_wait_t
    *ngx_http_cache_early_waits[NGX_HTTP_EARLY_SLOTS];
static ngx_str_t  ngx_http_cache_early_name = ngx_string("cache_early_read");
#endif


static ngx_int_t
ngx_http_file_cache_init(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_file_cache_t  *ocache = data;

    size_t                  len;
    ngx_uint_t              n;
    ngx_http_file_cache_t  *cache;
#if (NGX_EXT)
    ngx_queue_t                 *q;
    ngx_http_file_cache_node_t  *fcn;
#endif

    cache = shm_zone->data;

    if (ocache) {
        if (ngx_strcmp(cache->path->name.data, ocache->path->name.data) != 0) {
            ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                          "cache \"%V\" uses the \"%V\" cache path "
                          "while previously it used the \"%V\" cache path",
                          &shm_zone->shm.name, &cache->path->name,
                          &ocache->path->name);

            return NGX_ERROR;
        }

        for (n = 0; n < NGX_MAX_PATH_LEVEL; n++) {
            if (cache->path->level[n] != ocache->path->level[n]) {
                ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                              "cache \"%V\" had previously different levels",
                              &shm_zone->shm.name);
                return NGX_ERROR;
            }
        }

        cache->sh = ocache->sh;

        cache->shpool = ocache->shpool;
        cache->bsize = ocache->bsize;

        cache->max_size /= cache->bsize;

        if (!cache->sh->cold || cache->sh->loading) {
            cache->path->loader = NULL;
        }

        return NGX_OK;
    }

    cache->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        cache->sh = cache->shpool->data;
        cache->bsize = ngx_fs_bsize(cache->path->name.data);
        cache->max_size /= cache->bsize;

#if (NGX_EXT)
        cache->sh->rbtree.insert = ngx_http_file_cache_rbtree_insert_value;
        cache->shpool->log_nomem = 0;

        /*
         * An on-disk snapshot has no surviving refresh or commit owner.
         * A live reload keeps these fields in the ocache branch above.
         */

        for (q = ngx_queue_head(&cache->sh->queue);
             q != ngx_queue_sentinel(&cache->sh->queue);
             q = ngx_queue_next(q))
        {
            fcn = ngx_queue_data(q, ngx_http_file_cache_node_t, queue);
            fcn->lock_commit_pid = 0;

            if (fcn->lock_expired) {
                fcn->lock_expired = 0;
                fcn->updating = 0;
            }
        }
#endif

        return NGX_OK;
    }

    cache->sh = ngx_slab_alloc(cache->shpool, sizeof(ngx_http_file_cache_sh_t));
    if (cache->sh == NULL) {
        return NGX_ERROR;
    }

    cache->shpool->data = cache->sh;

    ngx_rbtree_init(&cache->sh->rbtree, &cache->sh->sentinel,
                    ngx_http_file_cache_rbtree_insert_value);

    ngx_queue_init(&cache->sh->queue);

    cache->sh->cold = 1;
    cache->sh->loading = 0;
    cache->sh->size = 0;
    cache->sh->count = 0;
    cache->sh->watermark = (ngx_uint_t) -1;

    cache->bsize = ngx_fs_bsize(cache->path->name.data);

    cache->max_size /= cache->bsize;

    len = sizeof(" in cache keys zone \"\"") + shm_zone->shm.name.len;

    cache->shpool->log_ctx = ngx_slab_alloc(cache->shpool, len);
    if (cache->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(cache->shpool->log_ctx, " in cache keys zone \"%V\"%Z",
                &shm_zone->shm.name);

    cache->shpool->log_nomem = 0;

    return NGX_OK;
}


ngx_int_t
ngx_http_file_cache_new(ngx_http_request_t *r)
{
    ngx_http_cache_t  *c;

    c = ngx_pcalloc(r->pool, sizeof(ngx_http_cache_t));
    if (c == NULL) {
        return NGX_ERROR;
    }

    if (ngx_array_init(&c->keys, r->pool, 4, sizeof(ngx_str_t)) != NGX_OK) {
        return NGX_ERROR;
    }

    r->cache = c;
    c->file.log = r->connection->log;
    c->file.fd = NGX_INVALID_FILE;

    return NGX_OK;
}


ngx_int_t
ngx_http_file_cache_create(ngx_http_request_t *r)
{
    ngx_http_cache_t       *c;
    ngx_pool_cleanup_t     *cln;
    ngx_http_file_cache_t  *cache;

    c = r->cache;
    cache = c->file_cache;

    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_http_file_cache_cleanup;
    cln->data = c;

    if (ngx_http_file_cache_exists(cache, c) == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (ngx_http_file_cache_name(r, cache->path) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


void
ngx_http_file_cache_create_key(ngx_http_request_t *r)
{
    size_t             len;
    ngx_str_t         *key;
    ngx_uint_t         i;
    ngx_md5_t          md5;
    ngx_http_cache_t  *c;

    c = r->cache;

    len = 0;

    ngx_crc32_init(c->crc32);
    ngx_md5_init(&md5);

    key = c->keys.elts;
    for (i = 0; i < c->keys.nelts; i++) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http cache key: \"%V\"", &key[i]);

        len += key[i].len;

        ngx_crc32_update(&c->crc32, key[i].data, key[i].len);
        ngx_md5_update(&md5, key[i].data, key[i].len);
    }

    c->header_start = sizeof(ngx_http_file_cache_header_t)
                      + sizeof(ngx_http_file_cache_key) + len + 1;

    ngx_crc32_final(c->crc32);
    ngx_md5_final(c->key, &md5);

    ngx_memcpy(c->main, c->key, NGX_HTTP_CACHE_KEY_LEN);
}


ngx_int_t
ngx_http_file_cache_open(ngx_http_request_t *r)
{
    ngx_int_t                  rc, rv;
    ngx_uint_t                 test;
    ngx_http_cache_t          *c;
    ngx_pool_cleanup_t        *cln;
#if (NGX_EXT)
    ngx_pool_t                *pool;
#endif
    ngx_open_file_info_t       of;
    ngx_http_file_cache_t     *cache;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->cache;

    if (c->waiting) {
        return NGX_AGAIN;
    }

    if (c->reading) {
        return ngx_http_file_cache_read(r, c);
    }

#if (NGX_EXT)
    pool = r->pool;

    if (c->lock_expired && c->lock_expired_buffer_size == 0) {
        c->lock_expired_buffer_size = c->body_start;
    }

    if (c->lock_expired_wait) {
        if (c->lock_timeout == 0 || c->lock_expired_uncached
            || (ngx_msec_int_t) (c->wait_time - ngx_current_msec) <= 0)
        {
            c->lock_expired_uncached = 1;
            return NGX_HTTP_CACHE_STALE;
        }

        /*
         * Retain the first fd and buffer in the request pool. Only repeated
         * open attempts use the recyclable pool below.
         */

        if (c->lock_expired_pool) {
            ngx_destroy_pool(c->lock_expired_pool);
        }

        c->lock_expired_pool = ngx_create_pool(512, r->connection->log);
        if (c->lock_expired_pool == NULL) {
            return NGX_ERROR;
        }

        c->file.fd = NGX_INVALID_FILE;
        c->buf = NULL;
        c->body_start = c->lock_expired_buffer_size;
        c->etag.len = 0;
        c->last_modified = -1;
        c->lock_expired_wait = 0;
        r->cached = 0;
    }

    if (c->lock_expired_pool) {
        pool = c->lock_expired_pool;
    }
#endif

    cache = c->file_cache;

    if (c->node == NULL) {
        cln = ngx_pool_cleanup_add(r->pool, 0);
        if (cln == NULL) {
            return NGX_ERROR;
        }

        cln->handler = ngx_http_file_cache_cleanup;
        cln->data = c;
    }

    c->buffer_size = c->body_start;

    rc = ngx_http_file_cache_exists(cache, c);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache exists: %i e:%d", rc, c->exists);

    if (rc == NGX_ERROR) {
        return rc;
    }

    if (rc == NGX_AGAIN) {
        return NGX_HTTP_CACHE_SCARCE;
    }

    if (rc == NGX_OK) {

        if (c->error) {
            return c->error;
        }

        c->temp_file = 1;
        test = c->exists ? 1 : 0;
        rv = NGX_DECLINED;

    } else { /* rc == NGX_DECLINED */

        test = cache->sh->cold ? 1 : 0;

        if (c->min_uses > 1) {

            if (!test) {
                return NGX_HTTP_CACHE_SCARCE;
            }

            rv = NGX_HTTP_CACHE_SCARCE;

        } else {
            c->temp_file = 1;
            rv = NGX_DECLINED;
        }
    }

    if (ngx_http_file_cache_name(r, cache->path) != NGX_OK) {
        return NGX_ERROR;
    }

    if (!test) {
        goto done;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

    of.uniq = c->uniq;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.events = clcf->open_file_cache_events;
    of.directio = NGX_OPEN_FILE_DIRECTIO_OFF;
    of.read_ahead = clcf->read_ahead;

#if (NGX_EXT)
    if (ngx_open_cached_file(clcf->open_file_cache, &c->file.name, &of, pool)
#else
    if (ngx_open_cached_file(clcf->open_file_cache, &c->file.name, &of, r->pool)
#endif
        != NGX_OK)
    {
        switch (of.err) {

        case 0:
            return NGX_ERROR;

        case NGX_ENOENT:
        case NGX_ENOTDIR:
            goto done;

        default:
            ngx_log_error(NGX_LOG_CRIT, r->connection->log, of.err,
                          ngx_open_file_n " \"%s\" failed", c->file.name.data);
            return NGX_ERROR;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache fd: %d", of.fd);

#if (NGX_EXT)
    if (c->uniq != of.uniq) {
        /* the cached header size belongs to a different file */
        c->body_start = c->buffer_size;
    }
#endif

    c->file.fd = of.fd;
    c->file.log = r->connection->log;
    c->uniq = of.uniq;
    c->length = of.size;
    c->fs_size = (of.fs_size + cache->bsize - 1) / cache->bsize;

#if (NGX_EXT)
    c->buf = ngx_create_temp_buf(pool, c->body_start);
#else
    c->buf = ngx_create_temp_buf(r->pool, c->body_start);
#endif
    if (c->buf == NULL) {
        return NGX_ERROR;
    }

    return ngx_http_file_cache_read(r, c);

done:

    if (rv == NGX_DECLINED) {
        return ngx_http_file_cache_lock(r, c);
    }

    return rv;
}


#if (NGX_EXT)

static ngx_msec_t
ngx_http_file_cache_lock_timer(ngx_http_cache_t *c, ngx_msec_t now,
    ngx_msec_t lock_timer)
{
    ngx_msec_t  timer, interval;

    interval = c->lock_poll_interval;

    if (interval == 0 || interval == NGX_CONF_UNSET_MSEC) {
        interval = 500;
    }

    timer = ngx_min(c->wait_time - now, interval);

    if ((ngx_msec_int_t) lock_timer > 0) {
        timer = ngx_min(timer, lock_timer);
    }

    return timer;
}


static void
ngx_http_file_cache_expired_pool_cleanup(void *data)
{
    ngx_http_cache_t  *c = data;

    if (c->lock_expired_pool) {
        ngx_destroy_pool(c->lock_expired_pool);
        c->lock_expired_pool = NULL;
    }
}


/*
 * Called with the cache metadata mutex held; no file I/O is performed here.
 */
static ngx_uint_t
ngx_http_file_cache_commit_busy(ngx_http_cache_t *c)
{
    ngx_pid_t  pid;
#if (NGX_WIN32)
    HANDLE     process;
    DWORD      status;
#endif

    pid = c->node->lock_commit_pid;

    if (pid == 0) {
        return 0;
    }

#if (NGX_WIN32)
    process = OpenProcess(SYNCHRONIZE, 0, pid);

    if (process == NULL) {
        if (ngx_errno != ERROR_INVALID_PARAMETER) {
            return 1;
        }

    } else {
        status = WaitForSingleObject(process, 0);
        CloseHandle(process);

        if (status != WAIT_OBJECT_0) {
            return 1;
        }
    }
#else
    if (kill(pid, 0) != -1 || ngx_errno != NGX_ESRCH) {
        return 1;
    }
#endif

    c->node->lock_commit_pid = 0;

    return 0;
}


static ngx_int_t
ngx_http_file_cache_commit(ngx_http_request_t *r, ngx_http_cache_t *c)
{
    ngx_int_t                       rc;
    ngx_http_upstream_main_conf_t  *umcf;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    if (!umcf->cache_lock_expired && !c->lock_expired_owner
        && !c->node->lock_expired && !c->node->lock_commit_pid)
    {
        return NGX_OK;
    }

    ngx_shmtx_lock(&c->file_cache->shpool->mutex);

    rc = NGX_DECLINED;

    if (!ngx_http_file_cache_commit_busy(c)
        && (!(c->lock_expired_owner || c->node->lock_expired)
            || (c->lock_expired_owner && c->node->lock_expired
                && c->node->updating
                && c->lock_generation == c->node->lock_generation)))
    {
        c->node->lock_commit_pid = ngx_pid;
        c->lock_expired_commit = 1;
        rc = NGX_OK;
    }

    ngx_shmtx_unlock(&c->file_cache->shpool->mutex);

    return rc;
}


ngx_int_t
ngx_http_file_cache_lock_expired_valid(ngx_http_request_t *r)
{
    ngx_uint_t                      valid;
    ngx_http_cache_t               *c;
    ngx_http_file_cache_node_t     *fcn;
#if !(NGX_WIN32)
    ngx_slab_pool_t                *pool;
    ngx_http_upstream_main_conf_t  *umcf;
#endif

    c = r->cache;

    if (!c->lock_expired_owner) {
        return NGX_OK;
    }

    ngx_shmtx_lock(&c->file_cache->shpool->mutex);

    fcn = ngx_http_file_cache_lookup(c->file_cache, c->key);
    valid = fcn && fcn->lock_expired
            && fcn->lock_generation == c->lock_generation;

    ngx_shmtx_unlock(&c->file_cache->shpool->mutex);

    if (!valid) {
        return NGX_DECLINED;
    }

#if !(NGX_WIN32)
    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    if (umcf->cache_early_zone) {
        if (!c->lock_expired_watch) {
            return NGX_DECLINED;
        }

        pool = (ngx_slab_pool_t *) umcf->cache_early_zone->shm.addr;

        ngx_shmtx_lock(&pool->mutex);

        valid = ngx_http_cache_early_current(umcf->cache_early_zone->data,
                                             c->early_id, &c->early_epoch);

        ngx_shmtx_unlock(&pool->mutex);

        if (!valid) {
            return NGX_DECLINED;
        }
    }
#endif

    return NGX_OK;
}


#if !(NGX_WIN32)

static void
ngx_http_file_cache_expired_watch(ngx_http_request_t *r)
{
    ngx_slab_pool_t                *pool;
    ngx_http_cache_t               *c;
    ngx_http_cache_early_sh_t      *sh;
    ngx_http_upstream_main_conf_t  *umcf;

    c = r->cache;
    c->lock_expired_watch = 0;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    if (umcf->cache_early_zone == NULL) {
        return;
    }

    if (ngx_http_cache_early_allowed(r, 0, c->early_id) != NGX_OK) {
        return;
    }

    sh = umcf->cache_early_zone->data;
    pool = (ngx_slab_pool_t *) umcf->cache_early_zone->shm.addr;

    ngx_shmtx_lock(&pool->mutex);

    c->early_epoch = sh->epoch;

    ngx_shmtx_unlock(&pool->mutex);

    c->lock_expired_watch = 1;
}

#endif


ngx_int_t
ngx_http_file_cache_lock_expired(ngx_http_request_t *r)
{
    ngx_msec_t           now, timer;
    ngx_http_cache_t    *c;
    ngx_pool_cleanup_t  *cln;

    c = r->cache;
    now = ngx_current_msec;

    if (c->lock_timeout == 0
        || (c->wait_time && (ngx_msec_int_t) (c->wait_time - now) <= 0)
        || r->main->blocked >= NGX_HTTP_MAX_BLOCKED)
    {
        c->lock_expired_uncached = 1;
        return NGX_HTTP_CACHE_STALE;
    }

    if (!c->lock_expired_pool_cleanup) {
        cln = ngx_pool_cleanup_add(r->pool, 0);
        if (cln == NULL) {
            return NGX_ERROR;
        }

        cln->handler = ngx_http_file_cache_expired_pool_cleanup;
        cln->data = c;
        c->lock_expired_pool_cleanup = 1;
    }

    if (c->wait_time == 0) {
        c->wait_time = now + c->lock_timeout;
        c->wait_event.handler = ngx_http_file_cache_lock_wait_handler;
        c->wait_event.data = r;
        c->wait_event.log = r->connection->log;
    }

    c->lock_expired_wait = 1;
    c->waiting = 1;

    ngx_shmtx_lock(&c->file_cache->shpool->mutex);

    timer = c->node->lock_time - now;

    if (!c->node->updating
        || ((ngx_msec_int_t) timer <= 0
            && !ngx_http_file_cache_commit_busy(c)))
    {
        timer = 1;
    }

    ngx_shmtx_unlock(&c->file_cache->shpool->mutex);

    timer = ngx_http_file_cache_lock_timer(c, now, timer);
    ngx_add_timer(&c->wait_event, timer);

    r->main->blocked++;

    return NGX_AGAIN;
}

#endif


static ngx_int_t
ngx_http_file_cache_lock(ngx_http_request_t *r, ngx_http_cache_t *c)
{
    ngx_msec_t                 now, timer;
    ngx_http_file_cache_t     *cache;
#if (NGX_EXT && !(NGX_WIN32))
    ngx_int_t                  rc;
#endif

    if (!c->lock) {
        return NGX_DECLINED;
    }

#if (NGX_EXT)
    if (c->lock_poll_interval == 0
        || c->lock_poll_interval == NGX_CONF_UNSET_MSEC)
    {
        c->lock_poll_interval = 500;
    }
#endif

#if (NGX_EXT && !(NGX_WIN32))
    if (!c->wait_time && r->upstream && r->upstream->conf
        && r->upstream->conf->cache_early_zone)
    {
        ngx_http_cache_early_watch(r);
    }
#endif

    now = ngx_current_msec;

    cache = c->file_cache;

    ngx_shmtx_lock(&cache->shpool->mutex);

    timer = c->node->lock_time - now;

#if (NGX_EXT && !(NGX_WIN32))
    if ((!c->node->updating
         || ((ngx_msec_int_t) timer <= 0
             && !ngx_http_cache_early_publishing(r)))
        && !ngx_http_file_cache_commit_busy(c))
    {
#elif (NGX_EXT)
    if ((!c->node->updating || ((ngx_msec_int_t) timer <= 0))
        && !ngx_http_file_cache_commit_busy(c))
    {
#else
    if (!c->node->updating || (ngx_msec_int_t) timer <= 0) {
#endif
        c->node->updating = 1;
#if (NGX_EXT)
        c->node->lock_expired = 0;
#endif
        c->node->lock_time = now + c->lock_age;
        c->updating = 1;
        c->lock_time = c->node->lock_time;
    }

    ngx_shmtx_unlock(&cache->shpool->mutex);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache lock u:%d wt:%M",
                   c->updating, c->wait_time);

    if (c->updating) {
        return NGX_DECLINED;
    }

#if (NGX_EXT && !(NGX_WIN32))
    if (c->wait_time && (ngx_msec_int_t) (c->wait_time - now) <= 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "cache lock timeout");
        c->lock_timeout = 0;
    }

    if (c->early_read && (c->lock_timeout || !c->wait_time)) {
        rc = ngx_http_cache_early_open(r);
        if (rc != NGX_DECLINED) {
            return rc;
        }
    }
#endif

    if (c->lock_timeout == 0) {
        return NGX_HTTP_CACHE_SCARCE;
    }

    if (r->main->blocked >= NGX_HTTP_MAX_BLOCKED) {
        return NGX_HTTP_CACHE_SCARCE;
    }

    c->waiting = 1;

    if (c->wait_time == 0) {
        c->wait_time = now + c->lock_timeout;

        c->wait_event.handler = ngx_http_file_cache_lock_wait_handler;
        c->wait_event.data = r;
        c->wait_event.log = r->connection->log;
    }

#if (NGX_EXT)
    timer = ngx_http_file_cache_lock_timer(c, now, timer);
    ngx_add_timer(&c->wait_event, timer);
#else
    timer = c->wait_time - now;
    ngx_add_timer(&c->wait_event, (timer > 500) ? 500 : timer);
#endif

    r->main->blocked++;

    return NGX_AGAIN;
}


static void
ngx_http_file_cache_lock_wait_handler(ngx_event_t *ev)
{
    ngx_int_t            rc;
    ngx_connection_t    *c;
    ngx_http_request_t  *r;

    r = ev->data;
    c = r->connection;

    ngx_http_set_log_request(c->log, r);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http file cache wait: \"%V?%V\"", &r->uri, &r->args);

    rc = ngx_http_file_cache_lock_wait(r, r->cache);

    if (rc == NGX_AGAIN) {
        return;
    }

    r->cache->waiting = 0;
    r->main->blocked--;

    if (r->main->terminated) {
        /*
         * trigger connection event handler if the request was
         * terminated
         */

        c->write->handler(c->write);

    } else {
        r->write_event_handler(r);
        ngx_http_run_posted_requests(c);
    }
}


static ngx_int_t
ngx_http_file_cache_lock_wait(ngx_http_request_t *r, ngx_http_cache_t *c)
{
    ngx_uint_t              wait;
    ngx_msec_t              now, timer;
    ngx_http_file_cache_t  *cache;

    now = ngx_current_msec;

    timer = c->wait_time - now;

    if ((ngx_msec_int_t) timer <= 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "cache lock timeout");
        c->lock_timeout = 0;
        return NGX_OK;
    }

#if (NGX_EXT && !(NGX_WIN32))
    if (c->early_read) {
        return NGX_OK;
    }
#endif

    cache = c->file_cache;
    wait = 0;

    ngx_shmtx_lock(&cache->shpool->mutex);

    timer = c->node->lock_time - now;

#if (NGX_EXT && !(NGX_WIN32))
    if (c->node->updating
        && ((ngx_msec_int_t) timer > 0 || ngx_http_cache_early_publishing(r)))
    {
#else
    if (c->node->updating && (ngx_msec_int_t) timer > 0) {
#endif
        wait = 1;
    }

#if (NGX_EXT)
    if (ngx_http_file_cache_commit_busy(c)) {
        wait = 1;
        timer = c->lock_poll_interval;
    }
#endif

    ngx_shmtx_unlock(&cache->shpool->mutex);

    if (wait) {
#if (NGX_EXT)
        timer = ngx_http_file_cache_lock_timer(c, now, timer);
        ngx_add_timer(&c->wait_event, timer);
#else
        ngx_add_timer(&c->wait_event, (timer > 500) ? 500 : timer);
#endif
        return NGX_AGAIN;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_file_cache_read(ngx_http_request_t *r, ngx_http_cache_t *c)
{
    u_char                        *p;
    time_t                         now;
    ssize_t                        n;
    ngx_str_t                     *key;
    ngx_int_t                      rc;
    ngx_uint_t                     i;
    ngx_http_file_cache_t         *cache;
    ngx_http_file_cache_header_t  *h;

    n = ngx_http_file_cache_aio_read(r, c);

    if (n < 0) {
        return n;
    }

    if ((size_t) n < c->header_start) {
        ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
                      "cache file \"%s\" is too small", c->file.name.data);
        return NGX_DECLINED;
    }

    h = (ngx_http_file_cache_header_t *) c->buf->pos;

    if (h->version != NGX_HTTP_CACHE_VERSION) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "cache file \"%s\" version mismatch", c->file.name.data);
        return NGX_DECLINED;
    }

    if (h->crc32 != c->crc32 || (size_t) h->header_start != c->header_start) {
        ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
                      "cache file \"%s\" has md5 collision", c->file.name.data);
        return NGX_DECLINED;
    }

    p = c->buf->pos + sizeof(ngx_http_file_cache_header_t)
        + sizeof(ngx_http_file_cache_key);

    key = c->keys.elts;
    for (i = 0; i < c->keys.nelts; i++) {
        if (ngx_memcmp(p, key[i].data, key[i].len) != 0) {
            ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
                          "cache file \"%s\" has md5 collision",
                          c->file.name.data);
            return NGX_DECLINED;
        }

        p += key[i].len;
    }

    if ((size_t) h->body_start > c->body_start) {
        ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
                      "cache file \"%s\" has too long header",
                      c->file.name.data);
        return NGX_DECLINED;
    }

    if (h->vary_len > NGX_HTTP_CACHE_VARY_LEN) {
        ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
                      "cache file \"%s\" has incorrect vary length",
                      c->file.name.data);
        return NGX_DECLINED;
    }

    if (h->vary_len) {
        ngx_http_file_cache_vary(r, h->vary, h->vary_len, c->variant);

        if (ngx_memcmp(c->variant, h->variant, NGX_HTTP_CACHE_KEY_LEN) != 0) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http file cache vary mismatch");
            return ngx_http_file_cache_reopen(r, c);
        }
    }

    c->buf->last += n;

    c->valid_sec = h->valid_sec;
    c->updating_sec = h->updating_sec;
    c->error_sec = h->error_sec;
    c->last_modified = h->last_modified;
    c->date = h->date;

#if (NGX_EXT)
    /*
     * Restore the origin policy.
     * Keep the in-memory millisecond value free of policy bits.
     */
    c->must_revalidate =
        (h->valid_msec & NGX_HTTP_CACHE_MUST_REVALIDATE) != 0;
    c->valid_msec = h->valid_msec & ~NGX_HTTP_CACHE_MUST_REVALIDATE;
#else
    c->valid_msec = h->valid_msec;
#endif

    c->body_start = h->body_start;
    c->etag.len = h->etag_len;
    c->etag.data = h->etag;

    r->cached = 1;

    cache = c->file_cache;

    if (cache->sh->cold) {

        ngx_shmtx_lock(&cache->shpool->mutex);

        if (!c->node->exists) {
            c->node->uses = 1;
            c->node->body_start = c->body_start;
            c->node->exists = 1;
            c->node->uniq = c->uniq;
            c->node->fs_size = c->fs_size;

            cache->sh->size += c->fs_size;
        }

        ngx_shmtx_unlock(&cache->shpool->mutex);
    }

#if (NGX_EXT)
    if (c->lock_expired && !c->lock_expired_owner && c->wait_time
        && c->valid_sec < ngx_time()
        && (ngx_msec_int_t) (c->wait_time - ngx_current_msec) <= 0)
    {
        c->lock_expired_uncached = 1;
        return NGX_HTTP_CACHE_STALE;
    }
#endif

    now = ngx_time();

    if (c->valid_sec < now) {
        c->stale_updating = c->valid_sec + c->updating_sec >= now;
        c->stale_error = c->valid_sec + c->error_sec >= now;

        ngx_shmtx_lock(&cache->shpool->mutex);

#if (NGX_EXT)
        if (r->background && r->parent && r->parent->cache
            && r->parent->cache->lock_expired_owner
            && r->parent->cache->node == c->node
            && r->parent->cache->lock_generation == c->node->lock_generation)
        {
            /*
             * Transfer the parent's lease even if the subrequest's conditional
             * configuration disables expired locking.
             */

            c->lock_expired = 1;
            c->lock_expired_buffer_size = c->buffer_size;
            c->updating = 1;
            c->lock_expired_owner = 1;
            c->lock_time = c->node->lock_time;
            c->lock_generation = c->node->lock_generation;

            r->parent->cache->updating = 0;
            r->parent->cache->lock_expired_owner = 0;

            rc = NGX_HTTP_CACHE_STALE;

        } else if (ngx_http_file_cache_commit_busy(c)) {
            rc = NGX_HTTP_CACHE_UPDATING;

        } else if (c->lock_expired && !r->background
                   && (!c->node->updating
                       || (c->node->lock_expired
                           && (ngx_msec_int_t) (c->node->lock_time
                                               - ngx_current_msec) <= 0))
                   && (!c->wait_time
                       || (ngx_msec_int_t) (c->wait_time
                                           - ngx_current_msec) > 0))
        {
            c->node->lock_time = ngx_current_msec + c->lock_age;

            if (++c->node->lock_generation == 0) {
                c->node->lock_generation++;
            }

            c->lock_generation = c->node->lock_generation;
            c->node->lock_expired = 1;
            c->node->updating = 1;
            c->lock_expired_owner = 1;
            c->updating = 1;
            c->lock_time = c->node->lock_time;
            rc = NGX_HTTP_CACHE_STALE;

        } else
#endif
        if (c->node->updating) {
            rc = NGX_HTTP_CACHE_UPDATING;

        } else {
#if (NGX_EXT)
            c->node->lock_expired = 0;
#endif
            c->node->updating = 1;
            c->updating = 1;
            c->lock_time = c->node->lock_time;
            rc = NGX_HTTP_CACHE_STALE;
        }

#if (NGX_EXT && !(NGX_WIN32))
        if (c->lock_expired) {
            c->early_read = 0;
            c->early_watch = 0;
        }
#endif

        ngx_shmtx_unlock(&cache->shpool->mutex);

#if (NGX_EXT && !(NGX_WIN32))
        if (c->lock_expired_owner) {
            ngx_http_file_cache_expired_watch(r);
        }
#endif

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http file cache expired: %i %T %T",
                       rc, c->valid_sec, now);

        return rc;
    }

    return NGX_OK;
}


static ssize_t
ngx_http_file_cache_aio_read(ngx_http_request_t *r, ngx_http_cache_t *c)
{
#if (NGX_HAVE_FILE_AIO || NGX_THREADS)
    ssize_t                    n;
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
#endif

#if (NGX_HAVE_FILE_AIO)

    if (clcf->aio == NGX_HTTP_AIO_ON && ngx_file_aio
        && r->main->blocked < NGX_HTTP_MAX_BLOCKED)
    {
        n = ngx_file_aio_read(&c->file, c->buf->pos, c->body_start, 0, r->pool);

        if (n != NGX_AGAIN) {
            c->reading = 0;
            return n;
        }

        c->reading = 1;

        c->file.aio->data = r;
        c->file.aio->handler = ngx_http_cache_aio_event_handler;

        ngx_add_timer(&c->file.aio->event, 60000);

        r->main->blocked++;
        r->aio = 1;

        return NGX_AGAIN;
    }

#endif

#if (NGX_THREADS)

    if (clcf->aio == NGX_HTTP_AIO_THREADS
        && r->main->blocked < NGX_HTTP_MAX_BLOCKED)
    {
        c->file.thread_task = c->thread_task;
        c->file.thread_handler = ngx_http_cache_thread_handler;
        c->file.thread_ctx = r;

        n = ngx_thread_read(&c->file, c->buf->pos, c->body_start, 0, r->pool);

        c->thread_task = c->file.thread_task;
        c->reading = (n == NGX_AGAIN);

        return n;
    }

#endif

    return ngx_read_file(&c->file, c->buf->pos, c->body_start, 0);
}


#if (NGX_HAVE_FILE_AIO)

static void
ngx_http_cache_aio_event_handler(ngx_event_t *ev)
{
    ngx_event_aio_t     *aio;
    ngx_connection_t    *c;
    ngx_http_request_t  *r;

    aio = ev->data;
    r = aio->data;
    c = r->connection;

    ngx_http_set_log_request(c->log, r);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http file cache aio: \"%V?%V\"", &r->uri, &r->args);

    if (ev->timedout) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "aio operation took too long");
        ev->timedout = 0;
        return;
    }

    if (ev->timer_set) {
        ngx_del_timer(ev);
    }

    r->main->blocked--;
    r->aio = 0;

    if (r->main->terminated) {
        /*
         * trigger connection event handler if the request was
         * terminated
         */

        c->write->handler(c->write);

    } else {
        r->write_event_handler(r);
        ngx_http_run_posted_requests(c);
    }
}

#endif


#if (NGX_THREADS)

static ngx_int_t
ngx_http_cache_thread_handler(ngx_thread_task_t *task, ngx_file_t *file)
{
    ngx_str_t                  name;
    ngx_thread_pool_t         *tp;
    ngx_http_request_t        *r;
    ngx_http_core_loc_conf_t  *clcf;

    r = file->thread_ctx;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    tp = clcf->thread_pool;

    if (tp == NULL) {
        if (ngx_http_complex_value(r, clcf->thread_pool_value, &name)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        tp = ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle, &name);

        if (tp == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "thread pool \"%V\" not found", &name);
            return NGX_ERROR;
        }
    }

    task->event.data = r;
    task->event.handler = ngx_http_cache_thread_event_handler;

    if (ngx_thread_task_post(tp, task) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_add_timer(&task->event, 60000);

    r->main->blocked++;
    r->aio = 1;

    return NGX_OK;
}


static void
ngx_http_cache_thread_event_handler(ngx_event_t *ev)
{
    ngx_connection_t    *c;
    ngx_http_request_t  *r;

    r = ev->data;
    c = r->connection;

    ngx_http_set_log_request(c->log, r);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http file cache thread: \"%V?%V\"", &r->uri, &r->args);

    if (ev->timedout) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "thread operation took too long");
        ev->timedout = 0;
        return;
    }

    if (ev->timer_set) {
        ngx_del_timer(ev);
    }

    r->main->blocked--;
    r->aio = 0;

    if (r->main->terminated) {
        /*
         * trigger connection event handler if the request was
         * terminated
         */

        c->write->handler(c->write);

    } else {
        r->write_event_handler(r);
        ngx_http_run_posted_requests(c);
    }
}

#endif


static ngx_int_t
ngx_http_file_cache_exists(ngx_http_file_cache_t *cache, ngx_http_cache_t *c)
{
    ngx_int_t                    rc;
    ngx_http_file_cache_node_t  *fcn;

    ngx_shmtx_lock(&cache->shpool->mutex);

    fcn = c->node;

    if (fcn == NULL) {
        fcn = ngx_http_file_cache_lookup(cache, c->key);
    }

    if (fcn) {
        ngx_queue_remove(&fcn->queue);

        if (c->node == NULL) {
            fcn->uses++;
            fcn->count++;
        }

        if (fcn->error) {

            if (fcn->valid_sec < ngx_time()) {
                goto renew;
            }

            rc = NGX_OK;

            goto done;
        }

        if (fcn->exists || fcn->uses >= c->min_uses) {

            c->exists = fcn->exists;
            if (fcn->body_start && !c->update_variant) {
                c->body_start = fcn->body_start;
            }

            rc = NGX_OK;

            goto done;
        }

        rc = NGX_AGAIN;

        goto done;
    }

    fcn = ngx_slab_calloc_locked(cache->shpool,
                                 sizeof(ngx_http_file_cache_node_t));
    if (fcn == NULL) {
        ngx_http_file_cache_set_watermark(cache);

        ngx_shmtx_unlock(&cache->shpool->mutex);

        (void) ngx_http_file_cache_forced_expire(cache);

        ngx_shmtx_lock(&cache->shpool->mutex);

        fcn = ngx_slab_calloc_locked(cache->shpool,
                                     sizeof(ngx_http_file_cache_node_t));
        if (fcn == NULL) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "could not allocate node%s", cache->shpool->log_ctx);
            rc = NGX_ERROR;
            goto failed;
        }
    }

    cache->sh->count++;

    ngx_memcpy((u_char *) &fcn->node.key, c->key, sizeof(ngx_rbtree_key_t));

    ngx_memcpy(fcn->key, &c->key[sizeof(ngx_rbtree_key_t)],
               NGX_HTTP_CACHE_KEY_LEN - sizeof(ngx_rbtree_key_t));

    ngx_rbtree_insert(&cache->sh->rbtree, &fcn->node);

    fcn->uses = 1;
    fcn->count = 1;

renew:

    rc = NGX_DECLINED;

    fcn->valid_msec = 0;
    fcn->error = 0;
    fcn->exists = 0;
    fcn->valid_sec = 0;
    fcn->uniq = 0;
    fcn->body_start = 0;
    fcn->fs_size = 0;

done:

    fcn->expire = ngx_time() + cache->inactive;

    ngx_queue_insert_head(&cache->sh->queue, &fcn->queue);

    c->uniq = fcn->uniq;
    c->error = fcn->error;
    c->node = fcn;

failed:

    ngx_shmtx_unlock(&cache->shpool->mutex);

    return rc;
}


static ngx_int_t
ngx_http_file_cache_name(ngx_http_request_t *r, ngx_path_t *path)
{
    u_char            *p;
    ngx_http_cache_t  *c;

    c = r->cache;

    if (c->file.name.len) {
        return NGX_OK;
    }

    c->file.name.len = path->name.len + 1 + path->len
                       + 2 * NGX_HTTP_CACHE_KEY_LEN;

    c->file.name.data = ngx_pnalloc(r->pool, c->file.name.len + 1);
    if (c->file.name.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(c->file.name.data, path->name.data, path->name.len);

    p = c->file.name.data + path->name.len + 1 + path->len;
    p = ngx_hex_dump(p, c->key, NGX_HTTP_CACHE_KEY_LEN);
    *p = '\0';

    ngx_create_hashed_filename(path, c->file.name.data, c->file.name.len);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "cache file: \"%s\"", c->file.name.data);

    return NGX_OK;
}


static ngx_http_file_cache_node_t *
ngx_http_file_cache_lookup(ngx_http_file_cache_t *cache, u_char *key)
{
    ngx_int_t                    rc;
    ngx_rbtree_key_t             node_key;
    ngx_rbtree_node_t           *node, *sentinel;
    ngx_http_file_cache_node_t  *fcn;

    ngx_memcpy((u_char *) &node_key, key, sizeof(ngx_rbtree_key_t));

    node = cache->sh->rbtree.root;
    sentinel = cache->sh->rbtree.sentinel;

    while (node != sentinel) {

        if (node_key < node->key) {
            node = node->left;
            continue;
        }

        if (node_key > node->key) {
            node = node->right;
            continue;
        }

        /* node_key == node->key */

        fcn = (ngx_http_file_cache_node_t *) node;

        rc = ngx_memcmp(&key[sizeof(ngx_rbtree_key_t)], fcn->key,
                        NGX_HTTP_CACHE_KEY_LEN - sizeof(ngx_rbtree_key_t));

        if (rc == 0) {
            return fcn;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    /* not found */

    return NULL;
}


static void
ngx_http_file_cache_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t           **p;
    ngx_http_file_cache_node_t   *cn, *cnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            cn = (ngx_http_file_cache_node_t *) node;
            cnt = (ngx_http_file_cache_node_t *) temp;

            p = (ngx_memcmp(cn->key, cnt->key,
                            NGX_HTTP_CACHE_KEY_LEN - sizeof(ngx_rbtree_key_t))
                 < 0)
                    ? &temp->left : &temp->right;
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


static void
ngx_http_file_cache_vary(ngx_http_request_t *r, u_char *vary, size_t len,
    u_char *hash)
{
    u_char     *p, *last;
    ngx_str_t   name;
    ngx_md5_t   md5;
    u_char      buf[NGX_HTTP_CACHE_VARY_LEN];

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache vary: \"%*s\"", len, vary);

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, r->cache->main, NGX_HTTP_CACHE_KEY_LEN);

    ngx_strlow(buf, vary, len);

    p = buf;
    last = buf + len;

    while (p < last) {

        while (p < last && (*p == ' ' || *p == ',')) { p++; }

        name.data = p;

        while (p < last && *p != ',' && *p != ' ') { p++; }

        name.len = p - name.data;

        if (name.len == 0) {
            break;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http file cache vary: %V", &name);

        ngx_md5_update(&md5, name.data, name.len);
        ngx_md5_update(&md5, (u_char *) ":", sizeof(":") - 1);

        ngx_http_file_cache_vary_header(r, &md5, &name);

        ngx_md5_update(&md5, (u_char *) CRLF, sizeof(CRLF) - 1);
    }

    ngx_md5_final(hash, &md5);
}


static void
ngx_http_file_cache_vary_header(ngx_http_request_t *r, ngx_md5_t *md5,
    ngx_str_t *name)
{
    size_t            len;
    u_char           *p, *start, *last;
    ngx_uint_t        i, multiple, normalize;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *header;

    multiple = 0;
    normalize = 0;

    if (name->len == sizeof("Accept-Charset") - 1
        && ngx_strncasecmp(name->data, (u_char *) "Accept-Charset",
                           sizeof("Accept-Charset") - 1) == 0)
    {
        normalize = 1;

    } else if (name->len == sizeof("Accept-Encoding") - 1
        && ngx_strncasecmp(name->data, (u_char *) "Accept-Encoding",
                           sizeof("Accept-Encoding") - 1) == 0)
    {
        normalize = 1;

    } else if (name->len == sizeof("Accept-Language") - 1
        && ngx_strncasecmp(name->data, (u_char *) "Accept-Language",
                           sizeof("Accept-Language") - 1) == 0)
    {
        normalize = 1;
    }

    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        if (header[i].key.len != name->len) {
            continue;
        }

        if (ngx_strncasecmp(header[i].key.data, name->data, name->len) != 0) {
            continue;
        }

        if (!normalize) {

            if (multiple) {
                ngx_md5_update(md5, (u_char *) ",", sizeof(",") - 1);
            }

            ngx_md5_update(md5, header[i].value.data, header[i].value.len);

            multiple = 1;

            continue;
        }

        /* normalize spaces */

        p = header[i].value.data;
        last = p + header[i].value.len;

        while (p < last) {

            while (p < last && (*p == ' ' || *p == ',')) { p++; }

            start = p;

            while (p < last && *p != ',' && *p != ' ') { p++; }

            len = p - start;

            if (len == 0) {
                break;
            }

            if (multiple) {
                ngx_md5_update(md5, (u_char *) ",", sizeof(",") - 1);
            }

            ngx_md5_update(md5, start, len);

            multiple = 1;
        }
    }
}


static ngx_int_t
ngx_http_file_cache_reopen(ngx_http_request_t *r, ngx_http_cache_t *c)
{
    ngx_http_file_cache_t  *cache;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->file.log, 0,
                   "http file cache reopen");

    if (c->secondary) {
        ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
                      "cache file \"%s\" has incorrect vary hash",
                      c->file.name.data);
        return NGX_DECLINED;
    }

    cache = c->file_cache;

    ngx_shmtx_lock(&cache->shpool->mutex);

    c->node->count--;
    c->node = NULL;

    ngx_shmtx_unlock(&cache->shpool->mutex);

    c->secondary = 1;
    c->file.name.len = 0;
    c->body_start = c->buffer_size;

    ngx_memcpy(c->key, c->variant, NGX_HTTP_CACHE_KEY_LEN);

    return ngx_http_file_cache_open(r);
}


ngx_int_t
ngx_http_file_cache_set_header(ngx_http_request_t *r, u_char *buf)
{
    ngx_http_file_cache_header_t  *h = (ngx_http_file_cache_header_t *) buf;

    u_char            *p;
    ngx_str_t         *key;
    ngx_uint_t         i;
    ngx_http_cache_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache set header");

    c = r->cache;

    ngx_memzero(h, sizeof(ngx_http_file_cache_header_t));

    h->version = NGX_HTTP_CACHE_VERSION;
    h->valid_sec = c->valid_sec;
    h->updating_sec = c->updating_sec;
    h->error_sec = c->error_sec;
    h->last_modified = c->last_modified;
    h->date = c->date;
    h->crc32 = c->crc32;
    h->valid_msec = (u_short) c->valid_msec;

#if (NGX_EXT)
    /*
     * Keep the cache header layout and version unchanged: only the on-disk
     * valid_msec copy carries this flag. c->valid_msec remains a plain
     * millisecond value in memory and is masked back on cache reads.
     */
    if (c->must_revalidate) {
        h->valid_msec |= NGX_HTTP_CACHE_MUST_REVALIDATE;
    }
#endif

    h->header_start = (u_short) c->header_start;
    h->body_start = (u_short) c->body_start;

    if (c->etag.len <= NGX_HTTP_CACHE_ETAG_LEN) {
        h->etag_len = (u_char) c->etag.len;
        ngx_memcpy(h->etag, c->etag.data, c->etag.len);
    }

    if (c->vary.len) {
        if (c->vary.len > NGX_HTTP_CACHE_VARY_LEN) {
            /* should not happen */
            c->vary.len = NGX_HTTP_CACHE_VARY_LEN;
        }

        h->vary_len = (u_char) c->vary.len;
        ngx_memcpy(h->vary, c->vary.data, c->vary.len);

        ngx_http_file_cache_vary(r, c->vary.data, c->vary.len, c->variant);
        ngx_memcpy(h->variant, c->variant, NGX_HTTP_CACHE_KEY_LEN);
    }

    if (ngx_http_file_cache_update_variant(r, c) != NGX_OK) {
        return NGX_ERROR;
    }

    p = buf + sizeof(ngx_http_file_cache_header_t);

    p = ngx_cpymem(p, ngx_http_file_cache_key, sizeof(ngx_http_file_cache_key));

    key = c->keys.elts;
    for (i = 0; i < c->keys.nelts; i++) {
        p = ngx_copy(p, key[i].data, key[i].len);
    }

    *p = LF;

    return NGX_OK;
}


static ngx_int_t
ngx_http_file_cache_update_variant(ngx_http_request_t *r, ngx_http_cache_t *c)
{
    ngx_http_file_cache_t  *cache;
#if (NGX_EXT)
    ngx_uint_t              expired_owner;
#endif

    if (!c->secondary) {
        return NGX_OK;
    }

    if (c->vary.len
        && ngx_memcmp(c->variant, c->key, NGX_HTTP_CACHE_KEY_LEN) == 0)
    {
        return NGX_OK;
    }

    /*
     * if the variant hash doesn't match one we used as a secondary
     * cache key, switch back to the original key
     */

    cache = c->file_cache;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache main key");

    ngx_shmtx_lock(&cache->shpool->mutex);

    c->node->count--;
#if (NGX_EXT)
    expired_owner = c->lock_expired_owner && c->node->lock_expired
                    && c->node->updating
                    && c->lock_generation == c->node->lock_generation;

    if (!c->node->lock_expired || expired_owner) {
        c->node->updating = 0;
    }

    if (c->lock_expired_owner) {
        c->updating = 0;
        c->lock_generation = 0;
    }
#else
    c->node->updating = 0;
#endif
    c->node = NULL;

    ngx_shmtx_unlock(&cache->shpool->mutex);

    c->file.name.len = 0;
    c->update_variant = 1;

    ngx_memcpy(c->key, c->main, NGX_HTTP_CACHE_KEY_LEN);

    if (ngx_http_file_cache_exists(cache, c) == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (ngx_http_file_cache_name(r, cache->path) != NGX_OK) {
        return NGX_ERROR;
    }

#if (NGX_EXT)
    if (expired_owner) {
        ngx_shmtx_lock(&cache->shpool->mutex);

        if (!c->node->updating && !ngx_http_file_cache_commit_busy(c)) {
            c->node->lock_time = ngx_current_msec + c->lock_age;

            if (++c->node->lock_generation == 0) {
                c->node->lock_generation++;
            }

            c->node->lock_expired = 1;
            c->node->updating = 1;
            c->lock_time = c->node->lock_time;
            c->lock_generation = c->node->lock_generation;
            c->updating = 1;
        }

        ngx_shmtx_unlock(&cache->shpool->mutex);
    }
#endif

    return NGX_OK;
}


void
ngx_http_file_cache_update(ngx_http_request_t *r, ngx_temp_file_t *tf)
{
    off_t                   fs_size;
    ngx_int_t               rc;
    ngx_file_uniq_t         uniq;
    ngx_file_info_t         fi;
    ngx_http_cache_t        *c;
    ngx_ext_rename_file_t   ext;
    ngx_http_file_cache_t  *cache;

    c = r->cache;

    if (c->updated) {
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache update");

#if (NGX_EXT && !(NGX_WIN32))
    if (c->early_watch && c->updating
        && (!ngx_http_cache_early_valid(r)
            || ngx_http_cache_early_commit(r) != NGX_OK))
    {
        ngx_http_file_cache_free(c, tf);
        return;
    }
#endif

#if (NGX_EXT)
    if (ngx_http_file_cache_lock_expired_valid(r) != NGX_OK
        || ngx_http_file_cache_commit(r, c) != NGX_OK)
    {
        ngx_http_file_cache_free(c, tf);

        if (c->lock_expired_owner) {
            r->upstream->cacheable = 0;
            r->cache = NULL;
        }

        return;
    }
#endif

    cache = c->file_cache;

    c->updated = 1;
    c->updating = 0;

    uniq = 0;
    fs_size = 0;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache rename: \"%s\" to \"%s\"",
                   tf->file.name.data, c->file.name.data);

    ext.access = NGX_FILE_OWNER_ACCESS;
    ext.path_access = NGX_FILE_OWNER_ACCESS;
    ext.time = -1;
    ext.create_path = 1;
    ext.delete_file = 1;
    ext.log = r->connection->log;

    rc = ngx_ext_rename_file(&tf->file.name, &c->file.name, &ext);

    if (rc == NGX_OK) {

        if (ngx_fd_info(tf->file.fd, &fi) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                          ngx_fd_info_n " \"%s\" failed", tf->file.name.data);

            rc = NGX_ERROR;

        } else {
            uniq = ngx_file_uniq(&fi);
            fs_size = (ngx_file_fs_size(&fi) + cache->bsize - 1) / cache->bsize;
        }
    }

#if (NGX_EXT && !(NGX_WIN32))
    if (rc == NGX_OK && c->early_watch && !ngx_http_cache_early_valid(r)) {
        if (ngx_file_info(c->file.name.data, &fi) != NGX_FILE_ERROR
            && ngx_file_uniq(&fi) == uniq)
        {
            (void) ngx_delete_file(c->file.name.data);
        }

        rc = NGX_ERROR;
        fs_size = 0;
        uniq = 0;
    }
#endif

#if (NGX_EXT)
    if (rc == NGX_OK && ngx_http_file_cache_lock_expired_valid(r) != NGX_OK) {

        /* no replacement may publish until this check is complete */

        if (ngx_file_info(c->file.name.data, &fi) != NGX_FILE_ERROR
            && ngx_file_uniq(&fi) == uniq)
        {
            (void) ngx_delete_file(c->file.name.data);
        }

        rc = NGX_ERROR;
        fs_size = 0;
        uniq = 0;
    }
#endif

    ngx_shmtx_lock(&cache->shpool->mutex);

#if (NGX_EXT)
    if (c->lock_expired_commit) {
        c->node->lock_commit_pid = 0;
        c->lock_expired_commit = 0;
    }
#endif
    c->node->count--;
    c->node->error = 0;
    c->node->uniq = uniq;
    c->node->body_start = c->body_start;

    cache->sh->size += fs_size - c->node->fs_size;
    c->node->fs_size = fs_size;

    if (rc == NGX_OK) {
        c->node->exists = 1;
#if (NGX_EXT)
        c->lock_expired_committed = c->lock_expired_owner;
#endif
    }

    c->node->updating = 0;

    ngx_shmtx_unlock(&cache->shpool->mutex);

#if (NGX_EXT && !(NGX_WIN32))
    if (c->early) {
        ngx_http_cache_early_finish(c, rc == NGX_OK);
    }
#endif
}


void
ngx_http_file_cache_update_header(ngx_http_request_t *r)
{
    ssize_t                        n;
    ngx_err_t                      err;
    ngx_file_t                     file;
    ngx_file_info_t                fi;
    ngx_http_cache_t              *c;
    ngx_http_file_cache_header_t   h;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache update header");

    c = r->cache;

#if (NGX_EXT)
    if (ngx_http_file_cache_lock_expired_valid(r) != NGX_OK
        || ngx_http_file_cache_commit(r, c) != NGX_OK)
    {
        return;
    }
#endif

    ngx_memzero(&file, sizeof(ngx_file_t));

    file.name = c->file.name;
    file.log = r->connection->log;
    file.fd = ngx_open_file(file.name.data, NGX_FILE_RDWR, NGX_FILE_OPEN, 0);

    if (file.fd == NGX_INVALID_FILE) {
        err = ngx_errno;

        /* cache file may have been deleted */

        if (err == NGX_ENOENT) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http file cache \"%s\" not found",
                           file.name.data);
#if (NGX_EXT)
            goto release;
#else
            return;
#endif
        }

        ngx_log_error(NGX_LOG_CRIT, r->connection->log, err,
                      ngx_open_file_n " \"%s\" failed", file.name.data);
#if (NGX_EXT)
        goto release;
#else
        return;
#endif
    }

    /*
     * make sure cache file wasn't replaced;
     * if it was, do nothing
     */

    if (ngx_fd_info(file.fd, &fi) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                      ngx_fd_info_n " \"%s\" failed", file.name.data);
        goto done;
    }

    if (c->uniq != ngx_file_uniq(&fi)
        || c->length != ngx_file_size(&fi))
    {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http file cache \"%s\" changed",
                       file.name.data);
        goto done;
    }

    n = ngx_read_file(&file, (u_char *) &h,
                      sizeof(ngx_http_file_cache_header_t), 0);

    if (n == NGX_ERROR) {
        goto done;
    }

    if ((size_t) n != sizeof(ngx_http_file_cache_header_t)) {
        ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
                      ngx_read_file_n " read only %z of %z from \"%s\"",
                      n, sizeof(ngx_http_file_cache_header_t), file.name.data);
        goto done;
    }

    if (h.version != NGX_HTTP_CACHE_VERSION
        || h.last_modified != c->last_modified
        || h.crc32 != c->crc32
        || (size_t) h.header_start != c->header_start
        || (size_t) h.body_start != c->body_start)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http file cache \"%s\" content changed",
                       file.name.data);
        goto done;
    }

    /*
     * update cache file header with new data,
     * notably h.valid_sec and h.date
     */

    ngx_memzero(&h, sizeof(ngx_http_file_cache_header_t));

    h.version = NGX_HTTP_CACHE_VERSION;
    h.valid_sec = c->valid_sec;
    h.updating_sec = c->updating_sec;
    h.error_sec = c->error_sec;
    h.last_modified = c->last_modified;
    h.date = c->date;
    h.crc32 = c->crc32;
    h.valid_msec = (u_short) c->valid_msec;

#if (NGX_EXT)
    /*
     * Preserve the same high-bit encoding when a 304 response refreshes only
     * the cache file header.  The flag continues to live solely in the
     * serialized valid_msec field, not in the in-memory millisecond value.
     */
    if (c->must_revalidate) {
        h.valid_msec |= NGX_HTTP_CACHE_MUST_REVALIDATE;
    }
#endif

    h.header_start = (u_short) c->header_start;
    h.body_start = (u_short) c->body_start;

    if (c->etag.len <= NGX_HTTP_CACHE_ETAG_LEN) {
        h.etag_len = (u_char) c->etag.len;
        ngx_memcpy(h.etag, c->etag.data, c->etag.len);
    }

    if (c->vary.len) {
        if (c->vary.len > NGX_HTTP_CACHE_VARY_LEN) {
            /* should not happen */
            c->vary.len = NGX_HTTP_CACHE_VARY_LEN;
        }

        h.vary_len = (u_char) c->vary.len;
        ngx_memcpy(h.vary, c->vary.data, c->vary.len);

        ngx_http_file_cache_vary(r, c->vary.data, c->vary.len, c->variant);
        ngx_memcpy(h.variant, c->variant, NGX_HTTP_CACHE_KEY_LEN);
    }

#if (NGX_EXT)
    n = ngx_write_file(&file, (u_char *) &h,
                       sizeof(ngx_http_file_cache_header_t), 0);

    if ((size_t) n == sizeof(ngx_http_file_cache_header_t)
        && ngx_http_file_cache_lock_expired_valid(r) == NGX_OK)
    {
        c->lock_expired_committed = c->lock_expired_owner;

    } else if (c->lock_expired_owner) {

        /* a purge during this write must not leave a refreshed old header */

        if (ngx_file_info(file.name.data, &fi) != NGX_FILE_ERROR
            && ngx_file_uniq(&fi) == c->uniq)
        {
            (void) ngx_delete_file(file.name.data);
        }
    }
#else
    (void) ngx_write_file(&file, (u_char *) &h,
                          sizeof(ngx_http_file_cache_header_t), 0);
#endif

done:

    if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", file.name.data);
    }

#if (NGX_EXT)
release:

    if (c->lock_expired_commit) {
        ngx_shmtx_lock(&c->file_cache->shpool->mutex);
        c->node->lock_commit_pid = 0;
        c->lock_expired_commit = 0;
        ngx_shmtx_unlock(&c->file_cache->shpool->mutex);
    }
#endif
}


ngx_int_t
ngx_http_cache_send(ngx_http_request_t *r)
{
    ngx_int_t          rc;
    ngx_buf_t         *b;
    ngx_chain_t        out;
    ngx_http_cache_t  *c;

    c = r->cache;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache send: %s", c->file.name.data);

#if (NGX_EXT && !(NGX_WIN32))
    if (c->early_reader) {
        return ngx_http_cache_early_send(r);
    }
#endif

    /* we need to allocate all before the header would be sent */

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (b->file == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b->file_pos = c->body_start;
    b->file_last = c->length;

    b->in_file = (c->length - c->body_start) ? 1 : 0;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;
    b->sync = (b->last_buf || b->in_file) ? 0 : 1;

    b->file->fd = c->file.fd;
    b->file->name = c->file.name;
    b->file->log = r->connection->log;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


void
ngx_http_file_cache_free(ngx_http_cache_t *c, ngx_temp_file_t *tf)
{
    ngx_http_file_cache_t       *cache;
    ngx_http_file_cache_node_t  *fcn;

    if (c->updated || c->node == NULL) {
        return;
    }

    cache = c->file_cache;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->file.log, 0,
                   "http file cache free, fd: %d", c->file.fd);

#if (NGX_EXT && !(NGX_WIN32))
    if (c->early) {
        ngx_http_cache_early_finish(c, 0);
    }
#endif

    ngx_shmtx_lock(&cache->shpool->mutex);

    fcn = c->node;
    fcn->count--;

#if (NGX_EXT)
    if (c->updating
        && ((c->lock_expired_owner && fcn->lock_expired
             && c->lock_generation == fcn->lock_generation)
            || (!c->lock_expired_owner && !fcn->lock_expired
                && c->lock_time == fcn->lock_time)))
    {
#else
    if (c->updating && fcn->lock_time == c->lock_time) {
#endif
        fcn->updating = 0;
    }

#if (NGX_EXT)
    if (c->lock_expired_owner
        && (!fcn->lock_expired
            || fcn->lock_generation != c->lock_generation))
    {
        c->error = 0;
    }
#endif

    if (c->error) {
        fcn->error = c->error;

        if (c->valid_sec) {
            fcn->valid_sec = c->valid_sec;
            fcn->valid_msec = c->valid_msec;
        }

    } else if (!fcn->exists && fcn->count == 0 && c->min_uses == 1) {
        ngx_queue_remove(&fcn->queue);
        ngx_rbtree_delete(&cache->sh->rbtree, &fcn->node);
        ngx_slab_free_locked(cache->shpool, fcn);
        cache->sh->count--;
        c->node = NULL;
    }

    ngx_shmtx_unlock(&cache->shpool->mutex);

    c->updated = 1;
    c->updating = 0;

    if (c->temp_file) {
        if (tf && tf->file.fd != NGX_INVALID_FILE) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->file.log, 0,
                           "http file cache incomplete: \"%s\"",
                           tf->file.name.data);

            if (ngx_delete_file(tf->file.name.data) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_CRIT, c->file.log, ngx_errno,
                              ngx_delete_file_n " \"%s\" failed",
                              tf->file.name.data);
            }
        }
    }

    if (c->wait_event.timer_set) {
        ngx_del_timer(&c->wait_event);
    }
}


static void
ngx_http_file_cache_cleanup(void *data)
{
    ngx_http_cache_t  *c = data;

    if (c->updated) {
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->file.log, 0,
                   "http file cache cleanup");

    if (c->updating && !c->background) {
        ngx_log_error(NGX_LOG_ALERT, c->file.log, 0,
                      "stalled cache updating, error:%ui", c->error);
    }

    ngx_http_file_cache_free(c, NULL);
}


static time_t
ngx_http_file_cache_forced_expire(ngx_http_file_cache_t *cache)
{
    u_char                      *name, *p;
    size_t                       len;
    time_t                       wait;
    ngx_uint_t                   tries;
    ngx_path_t                  *path;
    ngx_queue_t                 *q, *sentinel;
    ngx_http_file_cache_node_t  *fcn;
    u_char                       key[2 * NGX_HTTP_CACHE_KEY_LEN];

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "http file cache forced expire");

    path = cache->path;
    len = path->name.len + 1 + path->len + 2 * NGX_HTTP_CACHE_KEY_LEN;

    name = ngx_alloc(len + 1, ngx_cycle->log);
    if (name == NULL) {
        return 10;
    }

    ngx_memcpy(name, path->name.data, path->name.len);

    wait = 10;
    tries = 20;
    sentinel = NULL;

    ngx_shmtx_lock(&cache->shpool->mutex);

    for ( ;; ) {
        if (ngx_queue_empty(&cache->sh->queue)) {
            break;
        }

        q = ngx_queue_last(&cache->sh->queue);

        if (q == sentinel) {
            break;
        }

        fcn = ngx_queue_data(q, ngx_http_file_cache_node_t, queue);

        ngx_log_debug6(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                  "http file cache forced expire: #%d %d %02xd%02xd%02xd%02xd",
                  fcn->count, fcn->exists,
                  fcn->key[0], fcn->key[1], fcn->key[2], fcn->key[3]);

        if (fcn->count == 0) {
            ngx_http_file_cache_delete(cache, q, name);
            wait = 0;
            break;
        }

        if (fcn->deleting) {
            wait = 1;
            break;
        }

        p = ngx_hex_dump(key, (u_char *) &fcn->node.key,
                         sizeof(ngx_rbtree_key_t));
        len = NGX_HTTP_CACHE_KEY_LEN - sizeof(ngx_rbtree_key_t);
        (void) ngx_hex_dump(p, fcn->key, len);

        /*
         * abnormally exited workers may leave locked cache entries,
         * and although it may be safe to remove them completely,
         * we prefer to just move them to the top of the inactive queue
         */

        ngx_queue_remove(q);
        fcn->expire = ngx_time() + cache->inactive;
        ngx_queue_insert_head(&cache->sh->queue, &fcn->queue);

        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                      "ignore long locked inactive cache entry %*s, count:%d",
                      (size_t) 2 * NGX_HTTP_CACHE_KEY_LEN, key, fcn->count);

        if (sentinel == NULL) {
            sentinel = q;
        }

        if (--tries) {
            continue;
        }

        wait = 1;
        break;
    }

    ngx_shmtx_unlock(&cache->shpool->mutex);

    ngx_free(name);

    return wait;
}


static time_t
ngx_http_file_cache_expire(ngx_http_file_cache_t *cache)
{
    u_char                      *name, *p;
    size_t                       len;
    time_t                       now, wait;
    ngx_path_t                  *path;
    ngx_msec_t                   elapsed;
    ngx_queue_t                 *q;
    ngx_http_file_cache_node_t  *fcn;
    u_char                       key[2 * NGX_HTTP_CACHE_KEY_LEN];

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "http file cache expire");

    path = cache->path;
    len = path->name.len + 1 + path->len + 2 * NGX_HTTP_CACHE_KEY_LEN;

    name = ngx_alloc(len + 1, ngx_cycle->log);
    if (name == NULL) {
        return 10;
    }

    ngx_memcpy(name, path->name.data, path->name.len);

    now = ngx_time();

    ngx_shmtx_lock(&cache->shpool->mutex);

    for ( ;; ) {

        if (ngx_quit || ngx_terminate) {
            wait = 1;
            break;
        }

        if (ngx_queue_empty(&cache->sh->queue)) {
            wait = 10;
            break;
        }

        q = ngx_queue_last(&cache->sh->queue);

        fcn = ngx_queue_data(q, ngx_http_file_cache_node_t, queue);

        wait = fcn->expire - now;

        if (wait > 0) {
            wait = wait > 10 ? 10 : wait;
            break;
        }

        ngx_log_debug6(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "http file cache expire: #%d %d %02xd%02xd%02xd%02xd",
                       fcn->count, fcn->exists,
                       fcn->key[0], fcn->key[1], fcn->key[2], fcn->key[3]);

        if (fcn->count == 0) {
            ngx_http_file_cache_delete(cache, q, name);
            goto next;
        }

        if (fcn->deleting) {
            wait = 1;
            break;
        }

        p = ngx_hex_dump(key, (u_char *) &fcn->node.key,
                         sizeof(ngx_rbtree_key_t));
        len = NGX_HTTP_CACHE_KEY_LEN - sizeof(ngx_rbtree_key_t);
        (void) ngx_hex_dump(p, fcn->key, len);

        /*
         * abnormally exited workers may leave locked cache entries,
         * and although it may be safe to remove them completely,
         * we prefer to just move them to the top of the inactive queue
         */

        ngx_queue_remove(q);
        fcn->expire = ngx_time() + cache->inactive;
        ngx_queue_insert_head(&cache->sh->queue, &fcn->queue);

        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                      "ignore long locked inactive cache entry %*s, count:%d",
                      (size_t) 2 * NGX_HTTP_CACHE_KEY_LEN, key, fcn->count);

next:

        if (++cache->files >= cache->manager_files) {
            wait = 0;
            break;
        }

        ngx_time_update();

        elapsed = ngx_abs((ngx_msec_int_t) (ngx_current_msec - cache->last));

        if (elapsed >= cache->manager_threshold) {
            wait = 0;
            break;
        }
    }

    ngx_shmtx_unlock(&cache->shpool->mutex);

    ngx_free(name);

    return wait;
}


static void
ngx_http_file_cache_delete(ngx_http_file_cache_t *cache, ngx_queue_t *q,
    u_char *name)
{
    u_char                      *p;
    size_t                       len;
    ngx_path_t                  *path;
    ngx_http_file_cache_node_t  *fcn;

    fcn = ngx_queue_data(q, ngx_http_file_cache_node_t, queue);

    if (fcn->exists) {
        cache->sh->size -= fcn->fs_size;

        path = cache->path;
        p = name + path->name.len + 1 + path->len;
        p = ngx_hex_dump(p, (u_char *) &fcn->node.key,
                         sizeof(ngx_rbtree_key_t));
        len = NGX_HTTP_CACHE_KEY_LEN - sizeof(ngx_rbtree_key_t);
        p = ngx_hex_dump(p, fcn->key, len);
        *p = '\0';

        fcn->count++;
        fcn->deleting = 1;
        ngx_shmtx_unlock(&cache->shpool->mutex);

        len = path->name.len + 1 + path->len + 2 * NGX_HTTP_CACHE_KEY_LEN;
        ngx_create_hashed_filename(path, name, len);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "http file cache expire: \"%s\"", name);

        if (ngx_delete_file(name) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, ngx_errno,
                          ngx_delete_file_n " \"%s\" failed", name);
        }

        ngx_shmtx_lock(&cache->shpool->mutex);
        fcn->count--;
        fcn->deleting = 0;
    }

    if (fcn->count == 0) {
        ngx_queue_remove(q);
        ngx_rbtree_delete(&cache->sh->rbtree, &fcn->node);
        ngx_slab_free_locked(cache->shpool, fcn);
        cache->sh->count--;
    }
}


static ngx_msec_t
ngx_http_file_cache_manager(void *data)
{
    ngx_http_file_cache_t  *cache = data;

    off_t       size, free;
    time_t      wait;
    ngx_msec_t  elapsed, next;
    ngx_uint_t  count, watermark;

    cache->last = ngx_current_msec;
    cache->files = 0;

    next = (ngx_msec_t) ngx_http_file_cache_expire(cache) * 1000;

    if (next == 0) {
        next = cache->manager_sleep;
        goto done;
    }

    for ( ;; ) {
        ngx_shmtx_lock(&cache->shpool->mutex);

        size = cache->sh->size;
        count = cache->sh->count;
        watermark = cache->sh->watermark;

        ngx_shmtx_unlock(&cache->shpool->mutex);

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "http file cache size: %O c:%ui w:%i",
                       size, count, (ngx_int_t) watermark);

        if (size < cache->max_size && count < watermark) {

            if (!cache->min_free) {
                break;
            }

            free = ngx_fs_available(cache->path->name.data);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                           "http file cache free: %O", free);

            if (free > cache->min_free) {
                break;
            }
        }

        wait = ngx_http_file_cache_forced_expire(cache);

        if (wait > 0) {
            next = (ngx_msec_t) wait * 1000;
            break;
        }

        if (ngx_quit || ngx_terminate) {
            break;
        }

        if (++cache->files >= cache->manager_files) {
            next = cache->manager_sleep;
            break;
        }

        ngx_time_update();

        elapsed = ngx_abs((ngx_msec_int_t) (ngx_current_msec - cache->last));

        if (elapsed >= cache->manager_threshold) {
            next = cache->manager_sleep;
            break;
        }
    }

done:

    elapsed = ngx_abs((ngx_msec_int_t) (ngx_current_msec - cache->last));

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "http file cache manager: %ui e:%M n:%M",
                   cache->files, elapsed, next);

    return next;
}


static void
ngx_http_file_cache_loader(void *data)
{
    ngx_http_file_cache_t  *cache = data;

    ngx_tree_ctx_t  tree;

    if (!cache->sh->cold || cache->sh->loading) {
        return;
    }

    if (!ngx_atomic_cmp_set(&cache->sh->loading, 0, ngx_pid)) {
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "http file cache loader");

    tree.init_handler = NULL;
    tree.file_handler = ngx_http_file_cache_manage_file;
    tree.pre_tree_handler = ngx_http_file_cache_manage_directory;
    tree.post_tree_handler = ngx_http_file_cache_noop;
    tree.spec_handler = ngx_http_file_cache_delete_file;
    tree.data = cache;
    tree.alloc = 0;
    tree.log = ngx_cycle->log;

    cache->last = ngx_current_msec;
    cache->files = 0;

    if (ngx_walk_tree(&tree, &cache->path->name) == NGX_ABORT) {
        cache->sh->loading = 0;
        return;
    }

    cache->sh->cold = 0;
    cache->sh->loading = 0;

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                  "http file cache: %V %.3fM, bsize: %uz",
                  &cache->path->name,
                  ((double) cache->sh->size * cache->bsize) / (1024 * 1024),
                  cache->bsize);
}


static ngx_int_t
ngx_http_file_cache_noop(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    return NGX_OK;
}


static ngx_int_t
ngx_http_file_cache_manage_file(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    ngx_msec_t              elapsed;
    ngx_http_file_cache_t  *cache;

    cache = ctx->data;

    if (ngx_http_file_cache_add_file(ctx, path) != NGX_OK) {
        (void) ngx_http_file_cache_delete_file(ctx, path);
    }

    if (++cache->files >= cache->loader_files) {
        ngx_http_file_cache_loader_sleep(cache);

    } else {
        ngx_time_update();

        elapsed = ngx_abs((ngx_msec_int_t) (ngx_current_msec - cache->last));

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "http file cache loader time elapsed: %M", elapsed);

        if (elapsed >= cache->loader_threshold) {
            ngx_http_file_cache_loader_sleep(cache);
        }
    }

    return (ngx_quit || ngx_terminate) ? NGX_ABORT : NGX_OK;
}


static ngx_int_t
ngx_http_file_cache_manage_directory(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    if (path->len >= 5
        && ngx_strncmp(path->data + path->len - 5, "/temp", 5) == 0)
    {
        return NGX_DECLINED;
    }

    return NGX_OK;
}


static void
ngx_http_file_cache_loader_sleep(ngx_http_file_cache_t *cache)
{
    ngx_msleep(cache->loader_sleep);

    ngx_time_update();

    cache->last = ngx_current_msec;
    cache->files = 0;
}


static ngx_int_t
ngx_http_file_cache_add_file(ngx_tree_ctx_t *ctx, ngx_str_t *name)
{
    u_char                 *p;
    ngx_int_t               n;
    ngx_uint_t              i;
    ngx_http_cache_t        c;
    ngx_http_file_cache_t  *cache;

    if (name->len < 2 * NGX_HTTP_CACHE_KEY_LEN) {
        return NGX_ERROR;
    }

    /*
     * Temporary files in cache have a suffix consisting of a dot
     * followed by 10 digits.
     */

    if (name->len >= 2 * NGX_HTTP_CACHE_KEY_LEN + 1 + 10
        && name->data[name->len - 10 - 1] == '.')
    {
        return NGX_OK;
    }

    if (ctx->size < (off_t) sizeof(ngx_http_file_cache_header_t)) {
        ngx_log_error(NGX_LOG_CRIT, ctx->log, 0,
                      "cache file \"%s\" is too small", name->data);
        return NGX_ERROR;
    }

    ngx_memzero(&c, sizeof(ngx_http_cache_t));
    cache = ctx->data;

    c.length = ctx->size;
    c.fs_size = (ctx->fs_size + cache->bsize - 1) / cache->bsize;

    p = &name->data[name->len - 2 * NGX_HTTP_CACHE_KEY_LEN];

    for (i = 0; i < NGX_HTTP_CACHE_KEY_LEN; i++) {
        n = ngx_hextoi(p, 2);

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

        p += 2;

        c.key[i] = (u_char) n;
    }

    return ngx_http_file_cache_add(cache, &c);
}


static ngx_int_t
ngx_http_file_cache_add(ngx_http_file_cache_t *cache, ngx_http_cache_t *c)
{
    ngx_http_file_cache_node_t  *fcn;

    ngx_shmtx_lock(&cache->shpool->mutex);

    fcn = ngx_http_file_cache_lookup(cache, c->key);

    if (fcn == NULL) {

        fcn = ngx_slab_calloc_locked(cache->shpool,
                                     sizeof(ngx_http_file_cache_node_t));
        if (fcn == NULL) {
            ngx_http_file_cache_set_watermark(cache);

            if (cache->fail_time != ngx_time()) {
                cache->fail_time = ngx_time();
                ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                           "could not allocate node%s", cache->shpool->log_ctx);
            }

            ngx_shmtx_unlock(&cache->shpool->mutex);
            return NGX_ERROR;
        }

        cache->sh->count++;

        ngx_memcpy((u_char *) &fcn->node.key, c->key, sizeof(ngx_rbtree_key_t));

        ngx_memcpy(fcn->key, &c->key[sizeof(ngx_rbtree_key_t)],
                   NGX_HTTP_CACHE_KEY_LEN - sizeof(ngx_rbtree_key_t));

        ngx_rbtree_insert(&cache->sh->rbtree, &fcn->node);

        fcn->uses = 1;
        fcn->exists = 1;
        fcn->fs_size = c->fs_size;

        cache->sh->size += c->fs_size;

    } else {
        ngx_queue_remove(&fcn->queue);
    }

    fcn->expire = ngx_time() + cache->inactive;

    ngx_queue_insert_head(&cache->sh->queue, &fcn->queue);

    ngx_shmtx_unlock(&cache->shpool->mutex);

    return NGX_OK;
}


static ngx_int_t
ngx_http_file_cache_delete_file(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http file cache delete: \"%s\"", path->data);

    if (ngx_delete_file(path->data) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_CRIT, ctx->log, ngx_errno,
                      ngx_delete_file_n " \"%s\" failed", path->data);
    }

    return NGX_OK;
}


static void
ngx_http_file_cache_set_watermark(ngx_http_file_cache_t *cache)
{
    cache->sh->watermark = cache->sh->count - cache->sh->count / 8;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "http file cache watermark: %ui", cache->sh->watermark);
}


#if (NGX_EXT)

time_t
ngx_http_file_cache_valid(ngx_http_request_t *r, ngx_array_t *cache_valid,
    ngx_uint_t status)
{
    ngx_uint_t               i;
    ngx_http_cache_valid_t  *valid;

    if (cache_valid == NULL) {
        return 0;
    }

    valid = cache_valid->elts;
    for (i = 0; i < cache_valid->nelts; i++) {
        if (valid[i].status == 0 || valid[i].status == status) {
            return ngx_http_complex_value_sec(r, valid[i].valid, 0);
        }
    }

    return 0;
}

#else

time_t
ngx_http_file_cache_valid(ngx_array_t *cache_valid, ngx_uint_t status)
{
    ngx_uint_t               i;
    ngx_http_cache_valid_t  *valid;

    if (cache_valid == NULL) {
        return 0;
    }

    valid = cache_valid->elts;
    for (i = 0; i < cache_valid->nelts; i++) {
        if (valid[i].status == 0) {
            return valid[i].valid;
        }

        if (valid[i].status == status) {
            return valid[i].valid;
        }
    }

    return 0;
}

#endif


#if (NGX_EXT && !(NGX_WIN32))

ngx_int_t
ngx_http_cache_early_configure(ngx_conf_t *cf, ngx_shm_zone_t **zone)
{
    ngx_http_upstream_main_conf_t  *umcf;

    *zone = ngx_shared_memory_add(cf, &ngx_http_cache_early_name,
                                  2 * 1024 * 1024, &ngx_http_cache_early_name);
    if (*zone == NULL) {
        return NGX_ERROR;
    }

    (*zone)->init = ngx_http_cache_early_init;

    umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);
    umcf->cache_early_zone = *zone;

#if (NGX_HTTP_CACHE_EARLY_GUARD_REQUIRED)
    (*zone)->data = umcf;
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_http_cache_early_init(ngx_shm_zone_t *zone, void *data)
{
    ngx_slab_pool_t                *pool;
#if (NGX_HTTP_CACHE_EARLY_GUARD_REQUIRED)
    ngx_http_upstream_main_conf_t  *umcf;

    umcf = zone->data;
    if (umcf->cache_early_guard == NULL) {
        ngx_log_error(NGX_LOG_WARN, zone->shm.log, 0,
                      "proxy_cache_lock_early_read disabled: "
                      "no in-flight invalidation handler");
    }
#endif

    if (data != NULL) {
        zone->data = data;
        return NGX_OK;
    }

    pool = (ngx_slab_pool_t *) zone->shm.addr;
    zone->data = ngx_slab_calloc(pool, sizeof(ngx_http_cache_early_sh_t));

    return zone->data ? NGX_OK : NGX_ERROR;
}


static void
ngx_http_cache_early_watch(ngx_http_request_t *r)
{
    ngx_table_elt_t            *range;
    ngx_http_cache_t           *c;
    ngx_http_upstream_t        *u;
    ngx_http_cache_early_sh_t  *sh;

    c = r->cache;
    u = r->upstream;

    if (!c->lock_age || c->file_cache->use_temp_path || !u->buffering
        || r->method != NGX_HTTP_GET || r->background
        || r->headers_in.content_length_n > 0 || r->headers_in.chunked
        || r->headers_in.authorization || r->headers_in.cookie
        || r->headers_in.if_range || r->headers_in.if_match
        || r->headers_in.if_none_match || r->headers_in.if_modified_since
        || r->headers_in.if_unmodified_since)
    {
        return;
    }

    range = r->headers_in.range;
    if (range
        && ngx_strlchr(range->value.data,
                       range->value.data + range->value.len, ','))
    {
        return;
    }

#if (NGX_EXPR)
    if (!ngx_http_get_expr_flag_value(r,
                                      u->conf->cache_lock_early_read_conf))
    {
#else
    if (!u->conf->cache_lock_early_read) {
#endif
        return;
    }

    sh = u->conf->cache_early_zone->data;
    c->early_epoch = sh->epoch;

    if (ngx_http_cache_early_allowed(r, 0, c->early_id) != NGX_OK) {
        return;
    }

    c->early_read = 1;
    c->early_watch = 1;
}


void
ngx_http_cache_early_invalidate(ngx_shm_zone_t *zone, const u_char *id)
{
    ngx_slab_pool_t                *pool;
    ngx_http_cache_early_sh_t      *sh;
    ngx_http_cache_early_change_t  *change;

    if (zone->shm.addr == NULL) {
        return;
    }

    sh = zone->data;
    pool = (ngx_slab_pool_t *) zone->shm.addr;

    ngx_shmtx_lock(&pool->mutex);
    change = &sh->changes[sh->epoch % NGX_HTTP_EARLY_CHANGES];
    change->all = (id == NULL);

    if (id) {
        ngx_memcpy(change->id, id, NGX_HTTP_CACHE_KEY_LEN);
    }

    (void) ngx_atomic_fetch_add(&sh->epoch, 1);
    ngx_shmtx_unlock(&pool->mutex);
}


/* Called with the fill zone locked. An overrun cannot prove freshness. */
static ngx_uint_t
ngx_http_cache_early_current(ngx_http_cache_early_sh_t *sh, const u_char *id,
    ngx_atomic_uint_t *epoch)
{
    ngx_atomic_uint_t               n;
    ngx_http_cache_early_change_t  *change;

    if (sh->epoch - *epoch > NGX_HTTP_EARLY_CHANGES) {
        return 0;
    }

    for (n = *epoch; n != sh->epoch; n++) {
        change = &sh->changes[n % NGX_HTTP_EARLY_CHANGES];
        if (change->all
            || ngx_memcmp(change->id, id, NGX_HTTP_CACHE_KEY_LEN) == 0)
        {
            return 0;
        }
    }

    *epoch = n;

    return 1;
}


static ngx_uint_t
ngx_http_cache_early_bucket(ngx_http_cache_t *c)
{
    return (c->crc32 % NGX_HTTP_EARLY_BUCKETS) * NGX_HTTP_EARLY_WAYS;
}


static ngx_int_t
ngx_http_cache_early_allowed(ngx_http_request_t *r, time_t started, u_char *id)
{
    ngx_http_upstream_main_conf_t  *umcf;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    if (umcf->cache_early_guard) {
        return umcf->cache_early_guard(r, started, id);
    }

#if (NGX_HTTP_CACHE_EARLY_GUARD_REQUIRED)
    return NGX_DECLINED;
#else
    return NGX_OK;
#endif
}


static ngx_int_t
ngx_http_cache_early_eligible(ngx_http_request_t *r)
{
    u_char                          *p, *last, *type;
    off_t                            max;
    ngx_uint_t                       i;
    ngx_list_part_t                 *part;
    ngx_table_elt_t                 *h;
    ngx_http_upstream_headers_in_t  *in;

    static ngx_str_t  byteranges = ngx_string("multipart/byteranges");

    in = &r->upstream->headers_in;
    max = NGX_MAX_OFF_T_VALUE - (off_t) r->cache->body_start;

    if (in->content_length_n <= 0 || in->content_length_n > max
        || in->chunked || in->set_cookie || in->vary
        || r->cache->vary.len || r->cache->secondary || r->cache->purged
        || r->cache->update_variant || r->cache->valid_sec <= ngx_time()
        || (in->status_n != NGX_HTTP_OK
            && in->status_n != NGX_HTTP_PARTIAL_CONTENT))
    {
        return NGX_DECLINED;
    }

    if (in->status_n == NGX_HTTP_PARTIAL_CONTENT && in->content_type) {
        p = in->content_type->value.data;
        last = p + in->content_type->value.len;

        while (p < last && (*p == ' ' || *p == '\t')) { p++; }

        type = p;
        while (p < last && *p != ';' && *p != ' ' && *p != '\t') { p++; }

        if ((size_t) (p - type) == byteranges.len
            && ngx_strncasecmp(type, byteranges.data, byteranges.len) == 0)
        {
            return NGX_DECLINED;
        }
    }

    part = &in->headers.part;
    h = part->elts;

    for (i = 0; /* void */ ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].key.len == sizeof("Content-Encoding") - 1
            && ngx_strncasecmp(h[i].key.data, (u_char *) "Content-Encoding",
                               h[i].key.len)
               == 0)
        {
            return NGX_DECLINED;
        }

        p = h[i].value.data;
        last = p + h[i].value.len;

        if (h[i].key.len == sizeof("Cache-Control") - 1
            && ngx_strncasecmp(h[i].key.data, (u_char *) "Cache-Control",
                               h[i].key.len)
               == 0
            && (ngx_strlcasestrn(p, last, (u_char *) "private", 6)
                || ngx_strlcasestrn(p, last, (u_char *) "no-store", 7)
                || ngx_strlcasestrn(p, last, (u_char *) "no-cache", 7)))
        {
            return NGX_DECLINED;
        }

        if (in->status_n == NGX_HTTP_OK
            && h[i].key.len == sizeof("Content-Range") - 1
            && ngx_strncasecmp(h[i].key.data, (u_char *) "Content-Range",
                               h[i].key.len)
               == 0)
        {
            return NGX_DECLINED;
        }
    }

    return NGX_OK;
}


void
ngx_http_cache_early_progress(ngx_http_request_t *r, ngx_temp_file_t *tf)
{
    off_t                         written;
    uint32_t                      bits;
    ngx_uint_t                    i, b, j, n;
    ngx_file_info_t               fi;
    ngx_http_cache_t             *c;
    ngx_shm_zone_t               *zone;
    ngx_slab_pool_t              *pool;
    ngx_http_cache_early_t       *e;
    ngx_http_cache_early_sh_t    *sh;
    ngx_http_cache_early_slot_t  *slot;

    c = r->cache;

    if (tf == NULL || tf->file.fd == NGX_INVALID_FILE || !c->updating
        || r->upstream->cache_status != NGX_HTTP_CACHE_MISS
        || tf->offset <= (off_t) c->body_start)
    {
        return;
    }

    written = tf->offset - c->body_start;
    e = c->early;

    if (e != NULL) {
        if (written != e->seen) {
            ngx_shmtx_lock(&e->pool->mutex);
            e->slot->written = written;
            ngx_shmtx_unlock(&e->pool->mutex);

            e->seen = written;
        }

        return;
    }

    if (ngx_http_cache_early_allowed(r, r->start_sec, NULL) != NGX_OK
        || tf->file.name.len != c->file.name.len + 11
        || ngx_memcmp(tf->file.name.data, c->file.name.data, c->file.name.len)
        || ngx_http_cache_early_eligible(r) != NGX_OK
        || ngx_fd_info(tf->file.fd, &fi) == NGX_FILE_ERROR)
    {
        c->early_read = 0;
        return;
    }

    zone = r->upstream->conf->cache_early_zone;
    pool = (ngx_slab_pool_t *) zone->shm.addr;
    sh = zone->data;

    e = ngx_pcalloc(r->pool, sizeof(ngx_http_cache_early_t));
    if (e == NULL) {
        c->early_read = 0;
        return;
    }

    b = ngx_http_cache_early_bucket(c);

    ngx_shmtx_lock(&pool->mutex);

    for (i = b; i < b + NGX_HTTP_EARLY_WAYS; i++) {
        slot = &sh->slots[i];

        if (slot->state == NGX_HTTP_EARLY_FREE) {
            break;
        }

        if (slot->state == NGX_HTTP_EARLY_WRITING
            || slot->state == NGX_HTTP_EARLY_PUBLISHING)
        {
            if (kill(slot->pid, 0) == 0 || ngx_errno != NGX_ESRCH) {
                continue;
            }

            slot->state = NGX_HTTP_EARLY_FAILED;
        }

        for (j = 0; j < NGX_HTTP_EARLY_WORDS; j++) {
            bits = slot->readers[j];

            for (n = 0; bits; n++, bits >>= 1) {
                if ((bits & 1) && kill(sh->pids[32 * j + n], 0) == -1
                    && ngx_errno == NGX_ESRCH)
                {
                    slot->readers[j] &= ~((uint32_t) 1 << n);
                }
            }

            if (slot->readers[j]) {
                break;
            }
        }

        if (j == NGX_HTTP_EARLY_WORDS) {
            break;
        }
    }

    if (i == b + NGX_HTTP_EARLY_WAYS) {
        ngx_shmtx_unlock(&pool->mutex);

        c->early_read = 0;
        return;
    }

    slot = &sh->slots[i];
    ngx_memzero(slot, sizeof(ngx_http_cache_early_slot_t));

    slot->zone = c->file_cache->sh;
    ngx_memcpy(slot->key, c->key, NGX_HTTP_CACHE_KEY_LEN);
    ngx_memcpy(slot->suffix, tf->file.name.data + c->file.name.len, 11);
    slot->lock_time = c->lock_time;
    slot->epoch = c->early_epoch;
    ngx_memcpy(slot->id, c->early_id, NGX_HTTP_CACHE_KEY_LEN);
    slot->body_start = c->body_start;
    slot->written = written;
    slot->expected = r->upstream->headers_in.content_length_n;
    slot->ino = ngx_file_uniq(&fi);
    slot->dev = fi.st_dev;
    slot->valid = c->valid_sec;
    slot->started = r->start_sec;
    slot->pid = ngx_pid;
    slot->state = NGX_HTTP_EARLY_WRITING;
    ngx_shmtx_unlock(&pool->mutex);

    e->slot = slot;
    e->pool = pool;
    e->seen = written;
    c->early = e;
}


/* Called with the keys zone locked; the lock order is keys, then fills. */
static ngx_uint_t
ngx_http_cache_early_is_publishing(ngx_http_cache_t *c, ngx_shm_zone_t *zone)
{
    ngx_uint_t                    b, i, active;
    ngx_slab_pool_t              *pool;
    ngx_http_cache_early_sh_t    *sh;
    ngx_http_cache_early_slot_t  *slot;

    if (zone == NULL) {
        return 0;
    }

    sh = zone->data;
    pool = (ngx_slab_pool_t *) zone->shm.addr;
    b = ngx_http_cache_early_bucket(c);
    active = 0;

    ngx_shmtx_lock(&pool->mutex);

    for (i = b; i < b + NGX_HTTP_EARLY_WAYS; i++) {
        slot = &sh->slots[i];

        if (slot->state == NGX_HTTP_EARLY_PUBLISHING
            && slot->zone == c->file_cache->sh
            && ngx_memcmp(slot->key, c->key, NGX_HTTP_CACHE_KEY_LEN) == 0)
        {
            if (kill(slot->pid, 0) == 0 || ngx_errno != NGX_ESRCH) {
                active = 1;
            } else {
                slot->state = NGX_HTTP_EARLY_FAILED;
            }

            break;
        }
    }

    ngx_shmtx_unlock(&pool->mutex);

    return active;
}


static ngx_uint_t
ngx_http_cache_early_publishing(ngx_http_request_t *r)
{
    ngx_http_upstream_main_conf_t  *umcf;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    return ngx_http_cache_early_is_publishing(r->cache,
                                              umcf->cache_early_zone);
}


static ngx_int_t
ngx_http_cache_early_commit(ngx_http_request_t *r)
{
    ngx_int_t                   rc;
    ngx_http_cache_t           *c;
    ngx_http_cache_early_t     *e;
    ngx_http_cache_early_sh_t  *sh;

    c = r->cache;
    e = c->early;
    sh = r->upstream->conf->cache_early_zone->data;

    if (e == NULL) {
        ngx_shmtx_lock(&c->file_cache->shpool->mutex);
        rc = (c->node->updating && !c->node->purged
              && c->node->lock_time == c->lock_time) ? NGX_OK : NGX_DECLINED;
        ngx_shmtx_unlock(&c->file_cache->shpool->mutex);

        return rc;
    }

    rc = ngx_http_cache_early_allowed(r, e->slot->started, NULL);

    ngx_shmtx_lock(&c->file_cache->shpool->mutex);
    ngx_shmtx_lock(&e->pool->mutex);

    if (rc != NGX_OK
        || !ngx_http_cache_early_current(sh, c->early_id, &c->early_epoch)
        || e->slot->written != e->slot->expected
        || c->node->purged)
    {
        e->slot->state = NGX_HTTP_EARLY_FAILED;
        rc = NGX_DECLINED;

    } else if (!c->node->updating || c->node->lock_time != c->lock_time) {
        /* Readers already pinned this inode; only the new owner may rename. */
        e->slot->state = NGX_HTTP_EARLY_COMPLETE;
        rc = NGX_DECLINED;

    } else {
        e->slot->state = NGX_HTTP_EARLY_PUBLISHING;
        rc = NGX_OK;
    }

    ngx_shmtx_unlock(&e->pool->mutex);
    ngx_shmtx_unlock(&c->file_cache->shpool->mutex);

    if (rc == NGX_DECLINED) {
        c->early = NULL;
    }

    return rc;
}


static ngx_uint_t
ngx_http_cache_early_valid(ngx_http_request_t *r)
{
    ngx_uint_t                  valid;
    ngx_http_cache_t           *c;
    ngx_shm_zone_t             *zone;
    ngx_slab_pool_t            *pool;
    ngx_http_cache_early_sh_t  *sh;

    c = r->cache;
    zone = r->upstream->conf->cache_early_zone;
    sh = zone->data;

    if (sh->epoch == c->early_epoch) {
        return 1;
    }

    /* A response outside the early-read policy uses native cache admission. */
    if (c->early == NULL && ngx_http_cache_early_eligible(r) != NGX_OK) {
        return 1;
    }

    pool = (ngx_slab_pool_t *) zone->shm.addr;

    ngx_shmtx_lock(&pool->mutex);
    valid = ngx_http_cache_early_current(sh, c->early_id, &c->early_epoch);
    ngx_shmtx_unlock(&pool->mutex);

    return valid;
}


static void
ngx_http_cache_early_finish(ngx_http_cache_t *c, ngx_uint_t complete)
{
    ngx_http_cache_early_t  *e;

    e = c->early;
    if (e->wait == NULL) {
        ngx_shmtx_lock(&e->pool->mutex);
        e->slot->state = (complete && e->slot->written == e->slot->expected)
                         ? NGX_HTTP_EARLY_COMPLETE : NGX_HTTP_EARLY_FAILED;
        ngx_shmtx_unlock(&e->pool->mutex);
    } else {
        ngx_http_cache_early_cleanup(e);
    }

    c->early = NULL;
}


static ngx_int_t
ngx_http_cache_early_open(ngx_http_request_t *r)
{
    u_char                        *name, *p;
    ngx_fd_t                       fd;
    ngx_int_t                      rc;
    size_t                         size;
    uint32_t                       bit;
    ngx_uint_t                     b, i, j;
    ngx_msec_t                     lock_time;
    ngx_buf_t                     *buf;
    ngx_str_t                     *key;
    ngx_file_info_t                fi;
    ngx_http_cache_t              *c;
    ngx_http_cache_early_t        *e;
    ngx_http_cache_early_sh_t     *sh;
    ngx_http_cache_early_slot_t   *slot;
    ngx_http_cache_early_wait_t   *wait;
    ngx_http_file_cache_header_t  *h;
    ngx_slab_pool_t               *pool;
    ngx_shm_zone_t                *zone;
    ngx_pool_cleanup_t            *cln;
    ngx_pool_cleanup_file_t       *cf;

    c = r->cache;

    if (c->secondary || c->exists || c->purged) {
        c->early_read = 0;
        return NGX_DECLINED;
    }

    zone = r->upstream->conf->cache_early_zone;
    sh = zone->data;
    pool = (ngx_slab_pool_t *) zone->shm.addr;
    b = ngx_http_cache_early_bucket(c);
    j = ngx_process_slot / 32;
    bit = (uint32_t) 1 << (ngx_process_slot % 32);

    ngx_shmtx_lock(&c->file_cache->shpool->mutex);
    lock_time = c->node->lock_time;
    rc = c->node->updating && !c->node->purged ? NGX_OK : NGX_DECLINED;
    ngx_shmtx_unlock(&c->file_cache->shpool->mutex);

    if (rc != NGX_OK) {
        return NGX_DECLINED;
    }

    ngx_shmtx_lock(&pool->mutex);

    if (sh->pids[ngx_process_slot] != ngx_pid) {
        for (i = 0; i < NGX_HTTP_EARLY_SLOTS; i++) {
            sh->slots[i].readers[j] &= ~bit;
        }

        sh->pids[ngx_process_slot] = ngx_pid;
    }

    for (i = b; i < b + NGX_HTTP_EARLY_WAYS; i++) {
        slot = &sh->slots[i];

        if (slot->state == NGX_HTTP_EARLY_WRITING
            && slot->zone == c->file_cache->sh && slot->lock_time == lock_time
            && slot->valid > ngx_time()
            && ngx_memcmp(slot->id, c->early_id, NGX_HTTP_CACHE_KEY_LEN) == 0
            && ngx_http_cache_early_current(sh, slot->id, &slot->epoch)
            && ngx_memcmp(slot->key, c->key, NGX_HTTP_CACHE_KEY_LEN) == 0)
        {
            break;
        }
    }

    if (i == b + NGX_HTTP_EARLY_WAYS) {
        ngx_shmtx_unlock(&pool->mutex);

        return NGX_DECLINED;
    }

    slot->readers[j] |= bit;
    size = slot->body_start;
    c->early_epoch = slot->epoch;
    ngx_shmtx_unlock(&pool->mutex);

    for (wait = ngx_http_cache_early_waits[i]; wait; wait = wait->next) {
        if (wait->slot == slot) {
            break;
        }
    }

    if (wait == NULL) {
        wait = ngx_calloc(sizeof(ngx_http_cache_early_wait_t), ngx_cycle->log);
        if (wait == NULL) {
            ngx_shmtx_lock(&pool->mutex);
            slot->readers[j] &= ~bit;
            ngx_shmtx_unlock(&pool->mutex);

            c->early_read = 0;
            return NGX_DECLINED;
        }

        ngx_queue_init(&wait->queue);
        wait->event.handler = ngx_http_cache_early_tick;
        wait->event.data = wait;
        wait->slot = slot;
        wait->index = i;
        wait->pool = pool;
        wait->sh = sh;
        wait->written = -1;
        wait->next = ngx_http_cache_early_waits[i];
        ngx_http_cache_early_waits[i] = wait;
    }

    wait->event.log = ngx_cycle->log;
    wait->users++;

    rc = NGX_DECLINED;
    fd = NGX_INVALID_FILE;

    if (ngx_http_cache_early_allowed(r, slot->started, NULL) != NGX_OK
        || size <= c->header_start || size > c->body_start)
    {
        goto failed;
    }

    name = ngx_pnalloc(r->pool, c->file.name.len + 12);
    if (name == NULL) {
        goto failed;
    }

    p = ngx_cpymem(name, c->file.name.data, c->file.name.len);
    p = ngx_cpymem(p, slot->suffix, 11);
    *p = '\0';

    fd = ngx_open_file(name, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE || ngx_fd_info(fd, &fi) == NGX_FILE_ERROR
        || ngx_file_uniq(&fi) != slot->ino || fi.st_dev != slot->dev)
    {
        goto failed;
    }

    buf = ngx_create_temp_buf(r->pool, size);
    if (buf == NULL || pread(fd, buf->pos, size, 0) != (ssize_t) size) {
        goto failed;
    }

    h = (ngx_http_file_cache_header_t *) buf->pos;
    if (h->version != NGX_HTTP_CACHE_VERSION || h->valid_sec <= ngx_time()
        || h->body_start != size || h->header_start != c->header_start
        || h->crc32 != c->crc32 || h->vary_len
        || h->etag_len > sizeof(h->etag))
    {
        goto failed;
    }

    p = buf->pos + sizeof(*h) + sizeof("\nKEY: ") - 1;
    key = c->keys.elts;

    for (i = 0; i < c->keys.nelts; i++) {
        if (ngx_memcmp(p, key[i].data, key[i].len) != 0) {
            goto failed;
        }

        p += key[i].len;
    }

    e = ngx_pcalloc(r->pool, sizeof(ngx_http_cache_early_t));
    if (e == NULL) {
        goto failed;
    }

    e->cleanup = ngx_http_cleanup_add(r, 0);
    if (e->cleanup == NULL) {
        goto failed;
    }

    ngx_shmtx_lock(&c->file_cache->shpool->mutex);
    rc = (!c->node->purged && c->node->updating
          && c->node->lock_time == lock_time) ? NGX_OK : NGX_DECLINED;
    ngx_shmtx_unlock(&c->file_cache->shpool->mutex);

    if (rc != NGX_OK) {
        goto failed;
    }

    cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_pool_cleanup_file_t));
    if (cln == NULL) {
        rc = NGX_ERROR;
        goto failed;
    }

    cf = cln->data;
    cf->fd = fd;
    cf->name = name;
    cf->log = r->connection->log;
    cln->handler = ngx_pool_cleanup_file;

    buf->last += size;
    c->file.fd = fd;
    c->file.log = r->connection->log;
    c->uniq = slot->ino;
    c->buf = buf;
    c->body_start = size;
    c->length = size + slot->expected;
    c->valid_sec = h->valid_sec;
    c->last_modified = h->last_modified;
    c->date = h->date;
    c->etag.data = h->etag;
    c->etag.len = h->etag_len;
    c->must_revalidate = (h->valid_msec & NGX_HTTP_CACHE_MUST_REVALIDATE) != 0;
    c->early_reader = 1;
    c->early = e;

    e->cleanup->handler = ngx_http_cache_early_cleanup;
    e->cleanup->data = e;
    e->request = r;
    e->slot = slot;
    e->file = c->file;
    e->file.name.data = name;
    e->file.name.len = c->file.name.len + 11;
    e->wait = wait;
    e->pool = pool;
    e->last_progress = ngx_current_msec;
    e->timeout = r->upstream->read_timeout;
    e->interval = c->lock_poll_interval;

    e->event.data = e;
    e->event.handler = ngx_http_cache_early_resume;
    e->event.log = r->connection->log;

    return NGX_OK;

failed:

    if (fd != NGX_INVALID_FILE) {
        (void) ngx_close_file(fd);
    }

    ngx_http_cache_early_release(wait, pool);
    c->early_read = 0;

    return rc;
}


static void
ngx_http_cache_early_release(ngx_http_cache_early_wait_t *wait,
    ngx_slab_pool_t *pool)
{
    ngx_http_cache_early_wait_t  **next;

    if (--wait->users) {
        wait->event.log = ngx_cycle->log;
        return;
    }

    ngx_shmtx_lock(&pool->mutex);
    wait->slot->readers[ngx_process_slot / 32] &=
                                   ~((uint32_t) 1 << (ngx_process_slot % 32));
    ngx_shmtx_unlock(&pool->mutex);

    next = &ngx_http_cache_early_waits[wait->index];

    while (*next != wait) {
        next = &(*next)->next;
    }

    *next = wait->next;
    ngx_free(wait);
}


static void
ngx_http_cache_early_cleanup(void *data)
{
    ngx_http_cache_early_t  *e = data;

    ngx_http_cache_t  *c;

    if (e->cleanup->handler == NULL) {
        return;
    }

    e->cleanup->handler = NULL;

    ngx_http_cache_early_dequeue(e);

    if (e->event.timer_set) {
        ngx_del_timer(&e->event);
    }

    if (e->event.posted) {
        ngx_delete_posted_event(&e->event);
    }

    ngx_http_cache_early_release(e->wait, e->pool);

    c = e->request->cache;
    if (c && c->early == e) {
        c->early = NULL;
        c->early_reader = 0;
    }
}


static void
ngx_http_cache_early_timer(ngx_event_t *ev, ngx_msec_t delay)
{
    if (ev->timer_set) {
        if ((ngx_msec_int_t) (ngx_current_msec + delay - ev->timer.key) >= 0) {
            return;
        }

        /* do not postpone an earlier deadline with a lazy timer update */

        ngx_del_timer(ev);
    }

    ngx_add_timer(ev, delay);
}


static void
ngx_http_cache_early_dequeue(ngx_http_cache_early_t *e)
{
    ngx_http_cache_early_wait_t  *wait;

    if (!e->queued) {
        return;
    }

    wait = e->wait;
    e->queued = 0;
    ngx_queue_remove(&e->queue);

    if (ngx_queue_empty(&wait->queue)) {
        if (wait->event.timer_set) {
            ngx_del_timer(&wait->event);
        }

        wait->recalc = 0;

    } else if (e->interval == wait->interval) {
        wait->recalc = 1;
    }
}


static void
ngx_http_cache_early_tick(ngx_event_t *ev)
{
    off_t                         written;
    ngx_queue_t                  *q;
    ngx_atomic_uint_t             epoch;
    ngx_http_cache_early_t       *e;
    ngx_http_cache_early_wait_t  *wait;
    ngx_http_cache_early_state_e  state;

    wait = ev->data;

    ngx_shmtx_lock(&wait->pool->mutex);
    written = wait->slot->written;
    state = wait->slot->state;
    epoch = wait->sh->epoch;
    ngx_shmtx_unlock(&wait->pool->mutex);

    if (written == wait->written
        && state == wait->state
        && epoch == wait->epoch)
    {
        if (wait->recalc) {
            wait->interval = NGX_TIMER_INFINITE;

            for (q = ngx_queue_head(&wait->queue);
                 q != ngx_queue_sentinel(&wait->queue);
                 q = ngx_queue_next(q))
            {
                e = ngx_queue_data(q, ngx_http_cache_early_t, queue);
                wait->interval = ngx_min(wait->interval, e->interval);
            }

            wait->recalc = 0;
        }

        ngx_add_timer(ev, wait->interval);
        return;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "http cache early wake: %O state:%ui", written,
                   (ngx_uint_t) state);

    wait->written = written;
    wait->state = state;
    wait->epoch = epoch;
    wait->recalc = 0;

    while (!ngx_queue_empty(&wait->queue)) {
        q = ngx_queue_head(&wait->queue);
        ngx_queue_remove(q);
        e = ngx_queue_data(q, ngx_http_cache_early_t, queue);
        e->queued = 0;
        ngx_post_event(&e->event, &ngx_posted_events);
    }
}


static void
ngx_http_cache_early_resume(ngx_event_t *ev)
{
    ngx_http_cache_early_t  *e = ev->data;

    ngx_connection_t  *c;

    c = e->request->connection;
    ngx_http_cache_early_writer(e->request);
    ngx_http_run_posted_requests(c);
}


static void
ngx_http_cache_early_writer(ngx_http_request_t *r)
{
    ngx_int_t  rc;

    rc = ngx_http_cache_early_send(r);
    if (rc != NGX_DONE) {
        ngx_http_finalize_request(r, rc);
    }
}


ngx_uint_t
ngx_http_cache_early_ready(ngx_http_request_t *r)
{
    ngx_uint_t               failed;
    ngx_http_cache_early_t  *e;

    e = r->cache->early;

    ngx_shmtx_lock(&e->pool->mutex);
    failed = (e->slot->state == NGX_HTTP_EARLY_FAILED);
    ngx_shmtx_unlock(&e->pool->mutex);

    if (!failed && ngx_http_cache_early_valid(r)) {
        return 1;
    }

    /* No response header or body filter has seen the old representation. */
    ngx_http_cache_early_cleanup(e);
    r->cache->early_read = 0;
    r->cache->early_watch = 0;
    r->upstream->cacheable = 0;
    r->cached = 0;

    return 0;
}


static ngx_int_t
ngx_http_cache_early_send(ngx_http_request_t *r)
{
    off_t                         available;
    ngx_int_t                     rc;
    ngx_uint_t                    last, busy;
    ngx_msec_t                    timer;
    ngx_msec_int_t                left;
    ngx_buf_t                    *b;
    ngx_event_t                  *wev;
    ngx_chain_t                  *out;
    ngx_http_cache_t             *c;
    ngx_http_cache_early_t       *e;
    ngx_http_cache_early_state_e  state;
    ngx_http_core_loc_conf_t     *clcf;

    c = r->cache;
    e = c->early;
    wev = r->connection->write;
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (wev->timedout || r->connection->error || r->main->terminated) {
        return NGX_ERROR;
    }

    ngx_shmtx_lock(&e->pool->mutex);
    state = e->slot->state;
    available = e->slot->written;
    ngx_shmtx_unlock(&e->pool->mutex);

    if (state == NGX_HTTP_EARLY_FAILED || available > e->slot->expected
        || !ngx_http_cache_early_valid(r))
    {
        return NGX_ERROR;
    }

    if (!r->header_sent) {
        rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }

        if (r->cache != c || c->early != e) {
            return NGX_DONE;
        }
    }

    if (e->seen != available || wev->delayed || !wev->ready) {
        e->seen = available;
        e->last_progress = ngx_current_msec;
    }

    last = (state == NGX_HTTP_EARLY_COMPLETE);

    if (!last && available == e->slot->expected) {
        available--;
    }

    rc = NGX_OK;
    out = NULL;

    if (!wev->delayed && !r->aio) {
        if (e->busy) {
            last = 0;

        } else if (available > e->cursor || last) {
            out = ngx_chain_get_free_buf(r->pool, &e->free);
            if (out == NULL) {
                return NGX_ERROR;
            }

            b = out->buf;
            ngx_memzero(b, sizeof(ngx_buf_t));

            b->file = &e->file;
            b->file_pos = c->body_start + e->cursor;
            b->file_last = c->body_start + available;
            b->in_file = (available > e->cursor);
            b->last_buf = last && r == r->main;
            b->last_in_chain = last;
            b->flush = !last;
            b->tag = (ngx_buf_tag_t) &ngx_http_cache_early_name;
            e->cursor = available;
        }

        if (out || e->busy || r->buffered || r->connection->buffered) {
            rc = ngx_http_output_filter(r, out);
        }

        ngx_chain_update_chains(r->pool, &e->free, &e->busy, &out,
                                (ngx_buf_tag_t) &ngx_http_cache_early_name);
        if (rc == NGX_ERROR) {
            return rc;
        }

        if (last) {
            r->write_event_handler = ngx_http_request_empty_handler;
            ngx_http_cache_early_cleanup(e);
            return rc;
        }
    }

    r->write_event_handler = ngx_http_cache_early_writer;

    if (rc == NGX_AGAIN || wev->delayed || r->aio) {
        if (ngx_handle_write_event(wev, clcf->send_lowat) != NGX_OK) {
            return NGX_ERROR;
        }

        if (!wev->delayed && !wev->ready && !wev->timer_set) {
            ngx_add_timer(wev, clcf->send_timeout);
        }
    }

    busy = (rc == NGX_AGAIN || wev->delayed || !wev->ready || r->aio
            || e->busy || r->buffered || r->connection->buffered);

    if (!busy && (e->cursor < available || state == NGX_HTTP_EARLY_COMPLETE)) {

        /* the busy chain drained before the new bytes were sent */

        ngx_http_cache_early_dequeue(e);
        ngx_post_event(&e->event, &ngx_posted_events);
        return NGX_DONE;
    }

    timer = e->interval;

    if (!r->aio && !wev->delayed && wev->ready) {
        left = (ngx_msec_int_t) (e->last_progress + e->timeout
                                 - ngx_current_msec);
        if (left <= 0) {
            return NGX_ERROR;
        }

        if (!busy || (ngx_msec_t) left < timer) {
            timer = (ngx_msec_t) left;
        }
    }

    if (busy) {
        ngx_http_cache_early_dequeue(e);

    } else if (!e->queued) {
        if (ngx_queue_empty(&e->wait->queue)
            || e->interval < e->wait->interval)
        {
            e->wait->interval = e->interval;
        }

        ngx_queue_insert_tail(&e->wait->queue, &e->queue);
        e->queued = 1;
        ngx_http_cache_early_timer(&e->wait->event, e->wait->interval);
    }

    /* check the reader timeout even when the shared file is idle */

    ngx_http_cache_early_timer(&e->event, timer);

    return NGX_DONE;
}

#endif /* NGX_EXT && !(NGX_WIN32) */


char *
ngx_http_file_cache_set_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *confp = conf;

    off_t                   max_size, min_free;
    u_char                 *last, *p;
    time_t                  inactive;
    ssize_t                 size;
    ngx_str_t               s, name, *value;
    ngx_int_t               loader_files, manager_files;
    ngx_msec_t              loader_sleep, manager_sleep, loader_threshold,
                            manager_threshold;
    ngx_uint_t              i, n, use_temp_path;
    ngx_array_t            *caches;
    ngx_http_file_cache_t  *cache, **ce;
#if (NGX_EXT)
    ngx_shm_zone_params_t   zp;
#endif

    cache = ngx_pcalloc(cf->pool, sizeof(ngx_http_file_cache_t));
    if (cache == NULL) {
        return NGX_CONF_ERROR;
    }

    cache->path = ngx_pcalloc(cf->pool, sizeof(ngx_path_t));
    if (cache->path == NULL) {
        return NGX_CONF_ERROR;
    }

    use_temp_path = 1;

    inactive = 600;

    loader_files = 100;
    loader_sleep = 50;
    loader_threshold = 200;

    manager_files = 100;
    manager_sleep = 50;
    manager_threshold = 200;

#if (NGX_EXT)
    ngx_memzero(&zp, sizeof(ngx_shm_zone_params_t));
    zp.tag = cmd->post;
    zp.restorable = 1;
#endif

    name.len = 0;
    size = 0;
    max_size = NGX_MAX_OFF_T_VALUE;
    min_free = 0;

    value = cf->args->elts;

    cache->path->name = value[1];

    if (cache->path->name.data[cache->path->name.len - 1] == '/') {
        cache->path->name.len--;
    }

    if (ngx_conf_full_name(cf->cycle, &cache->path->name, 0) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "levels=", 7) == 0) {

            p = value[i].data + 7;
            last = value[i].data + value[i].len;

            for (n = 0; n < NGX_MAX_PATH_LEVEL && p < last; n++) {

                if (*p > '0' && *p < '3') {

                    cache->path->level[n] = *p++ - '0';
                    cache->path->len += cache->path->level[n] + 1;

                    if (p == last) {
                        break;
                    }

                    if (*p++ == ':' && n < NGX_MAX_PATH_LEVEL - 1 && p < last) {
                        continue;
                    }

                    goto invalid_levels;
                }

                goto invalid_levels;
            }

            if (cache->path->len < 10 + NGX_MAX_PATH_LEVEL) {
                continue;
            }

        invalid_levels:

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid \"levels\" \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }

        if (ngx_strncmp(value[i].data, "use_temp_path=", 14) == 0) {

            if (ngx_strcmp(&value[i].data[14], "on") == 0) {
                use_temp_path = 1;

            } else if (ngx_strcmp(&value[i].data[14], "off") == 0) {
                use_temp_path = 0;

            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid use_temp_path value \"%V\", "
                                   "it must be \"on\" or \"off\"",
                                   &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "keys_zone=", 10) == 0) {

            name.data = value[i].data + 10;

            p = (u_char *) ngx_strchr(name.data, ':');

            if (p == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid keys zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            name.len = p - name.data;

            s.data = p + 1;
            s.len = value[i].data + value[i].len - s.data;

            size = ngx_parse_size(&s);

            if (size == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid keys zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            if (size < (ssize_t) (2 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "keys zone \"%V\" is too small", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

#if (NGX_EXT)
        if (ngx_strncmp(value[i].data, "keys_state=", 11) == 0) {
            if (zp.file.data != NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "duplicate keys_state parameter");
                return NGX_CONF_ERROR;
            }

            if (value[i].len == 11) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "keys_state requires a file name");
                return NGX_CONF_ERROR;
            }

            zp.file.data = value[i].data + 11;
            zp.file.len = value[i].len - 11;

            if (ngx_conf_full_name(cf->cycle, &zp.file, 0) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            continue;
        }
#endif

        if (ngx_strncmp(value[i].data, "inactive=", 9) == 0) {

            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            inactive = ngx_parse_time(&s, 1);
            if (inactive == (time_t) NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid inactive value \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "max_size=", 9) == 0) {

            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            max_size = ngx_parse_offset(&s);
            if (max_size < 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid max_size value \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "min_free=", 9) == 0) {

#if (NGX_WIN32 || NGX_HAVE_STATFS || NGX_HAVE_STATVFS)

            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            min_free = ngx_parse_offset(&s);
            if (min_free < 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid min_free value \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

#else
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "min_free is not supported "
                               "on this platform, ignored");
#endif

            continue;
        }

        if (ngx_strncmp(value[i].data, "loader_files=", 13) == 0) {

            loader_files = ngx_atoi(value[i].data + 13, value[i].len - 13);
            if (loader_files == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid loader_files value \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "loader_sleep=", 13) == 0) {

            s.len = value[i].len - 13;
            s.data = value[i].data + 13;

            loader_sleep = ngx_parse_time(&s, 0);
            if (loader_sleep == (ngx_msec_t) NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid loader_sleep value \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "loader_threshold=", 17) == 0) {

            s.len = value[i].len - 17;
            s.data = value[i].data + 17;

            loader_threshold = ngx_parse_time(&s, 0);
            if (loader_threshold == (ngx_msec_t) NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid loader_threshold value \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "manager_files=", 14) == 0) {

            manager_files = ngx_atoi(value[i].data + 14, value[i].len - 14);
            if (manager_files == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid manager_files value \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "manager_sleep=", 14) == 0) {

            s.len = value[i].len - 14;
            s.data = value[i].data + 14;

            manager_sleep = ngx_parse_time(&s, 0);
            if (manager_sleep == (ngx_msec_t) NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid manager_sleep value \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "manager_threshold=", 18) == 0) {

            s.len = value[i].len - 18;
            s.data = value[i].data + 18;

            manager_threshold = ngx_parse_time(&s, 0);
            if (manager_threshold == (ngx_msec_t) NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid manager_threshold value \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (name.len == 0 || size == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"keys_zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    cache->path->manager = ngx_http_file_cache_manager;
    cache->path->loader = ngx_http_file_cache_loader;
    cache->path->data = cache;
    cache->path->conf_file = cf->conf_file->file.name.data;
    cache->path->line = cf->conf_file->line;
    cache->loader_files = loader_files;
    cache->loader_sleep = loader_sleep;
    cache->loader_threshold = loader_threshold;
    cache->manager_files = manager_files;
    cache->manager_sleep = manager_sleep;
    cache->manager_threshold = manager_threshold;

    if (ngx_add_path(cf, &cache->path) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

#if (NGX_EXT)
    zp.name = name;
    zp.size = size;
    zp.signature.len = sizeof(NGX_HTTP_CACHE_SH_SIGNATURE)
                       + 2 * NGX_INT64_LEN + 3;
    zp.signature.data = ngx_pnalloc(cf->pool, zp.signature.len);
    if (zp.signature.data == NULL) {
        return NGX_CONF_ERROR;
    }

    zp.signature.len = ngx_sprintf(zp.signature.data, "%s:%z:%z;",
                                   NGX_HTTP_CACHE_SH_SIGNATURE,
                                   sizeof(ngx_http_file_cache_node_t),
                                   sizeof(ngx_http_file_cache_sh_t))
                       - zp.signature.data;

    cache->shm_zone = ngx_shared_memory_add_ext(cf, &zp);
#else
    cache->shm_zone = ngx_shared_memory_add(cf, &name, size, cmd->post);
#endif
    if (cache->shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (cache->shm_zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate zone \"%V\"", &name);
        return NGX_CONF_ERROR;
    }


    cache->shm_zone->init = ngx_http_file_cache_init;
    cache->shm_zone->data = cache;

    cache->use_temp_path = use_temp_path;

    cache->inactive = inactive;
    cache->max_size = max_size;
    cache->min_free = min_free;

    caches = (ngx_array_t *) (confp + cmd->offset);

    ce = ngx_array_push(caches);
    if (ce == NULL) {
        return NGX_CONF_ERROR;
    }

    *ce = cache;

    return NGX_CONF_OK;
}


char *
ngx_http_file_cache_valid_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    char  *p = conf;

#if (NGX_EXT)
    ngx_str_t                         *value;
    ngx_int_t                          status;
    ngx_uint_t                         i, n;
    ngx_array_t                      **a;
    ngx_http_cache_valid_t            *v;
    static ngx_uint_t                  statuses[] = { 200, 301, 302 };
    ngx_http_complex_value_t          *valid_cv;
    ngx_http_compile_complex_value_t   valid_ccv;
#else
    time_t                    valid;
    ngx_str_t                *value;
    ngx_int_t                 status;
    ngx_uint_t                i, n;
    ngx_array_t             **a;
    ngx_http_cache_valid_t   *v;
    static ngx_uint_t         statuses[] = { 200, 301, 302 };
#endif

    a = (ngx_array_t **) (p + cmd->offset);

    if (*a == NGX_CONF_UNSET_PTR) {
        *a = ngx_array_create(cf->pool, 1, sizeof(ngx_http_cache_valid_t));
        if (*a == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;
    n = cf->args->nelts - 1;

#if (NGX_EXT)
    valid_cv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (valid_cv == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&valid_ccv, sizeof(ngx_http_compile_complex_value_t));
    valid_ccv.cf = cf;
    valid_ccv.value = &value[n];
    valid_ccv.complex_value = valid_cv;

    if (ngx_http_compile_complex_value(&valid_ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (valid_cv->lengths == NULL) {
        valid_cv->u.sec = ngx_parse_time(&valid_cv->value, 1);
        if (valid_cv->u.sec == (time_t) NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid time value \"%V\"", &valid_cv->value);
            return NGX_CONF_ERROR;
        }
    }
#else
    valid = ngx_parse_time(&value[n], 1);
    if (valid == (time_t) NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid time value \"%V\"", &value[n]);
        return NGX_CONF_ERROR;
    }
#endif

    if (n == 1) {

        for (i = 0; i < 3; i++) {
            v = ngx_array_push(*a);
            if (v == NULL) {
                return NGX_CONF_ERROR;
            }

            v->status = statuses[i];

#if (NGX_EXT)
            v->valid = valid_cv;
#else
            v->valid = valid;
#endif
        }

        return NGX_CONF_OK;
    }

    for (i = 1; i < n; i++) {

        if (ngx_strcmp(value[i].data, "any") == 0) {

            status = 0;

        } else {

            status = ngx_atoi(value[i].data, value[i].len);
            if (status < 100 || status > 599) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid status \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }
        }

        v = ngx_array_push(*a);
        if (v == NULL) {
            return NGX_CONF_ERROR;
        }

        v->status = status;

#if (NGX_EXT)
        v->valid = valid_cv;
#else
        v->valid = valid;
#endif
    }

    return NGX_CONF_OK;
}
