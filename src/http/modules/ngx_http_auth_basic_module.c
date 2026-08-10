
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_crypt.h>


#define NGX_HTTP_AUTH_BUF_SIZE  2048


typedef struct {
    ngx_http_complex_value_t  *realm;
    ngx_http_complex_value_t  *user_file;

#if (NGX_RESTY_EXT)
    ngx_array_t               *users;
#endif

} ngx_http_auth_basic_loc_conf_t;


static ngx_int_t ngx_http_auth_basic_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_basic_crypt_handler(ngx_http_request_t *r,
    ngx_str_t *passwd, ngx_str_t *realm);
static ngx_int_t ngx_http_auth_basic_set_realm(ngx_http_request_t *r,
    ngx_str_t *realm);
static void *ngx_http_auth_basic_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_auth_basic_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_auth_basic_init(ngx_conf_t *cf);
static char *ngx_http_auth_basic_user_file(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
#if (NGX_RESTY_EXT)
static char *ngx_http_auth_basic_add_user(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
#endif


static ngx_command_t  ngx_http_auth_basic_commands[] = {

    { ngx_string("auth_basic"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_basic_loc_conf_t, realm),
      NULL },

    { ngx_string("auth_basic_user_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_auth_basic_user_file,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_basic_loc_conf_t, user_file),
      NULL },

#if (NGX_RESTY_EXT)
    { ngx_string("auth_basic_user"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_auth_basic_add_user,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_basic_loc_conf_t, users),
      NULL },
#endif

      ngx_null_command
};


static ngx_http_module_t  ngx_http_auth_basic_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_auth_basic_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_auth_basic_create_loc_conf,   /* create location configuration */
    ngx_http_auth_basic_merge_loc_conf     /* merge location configuration */
};


ngx_module_t  ngx_http_auth_basic_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_basic_module_ctx,       /* module context */
    ngx_http_auth_basic_commands,          /* module directives */
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


static ngx_int_t
ngx_http_auth_basic_handler(ngx_http_request_t *r)
{
    off_t                            offset;
    ssize_t                          n;
    ngx_fd_t                         fd;
    ngx_int_t                        rc;
    ngx_err_t                        err;
    ngx_str_t                        pwd, realm, user_file;
    ngx_uint_t                       i, level, login, left, passwd;
    ngx_file_t                       file;
    ngx_http_auth_basic_loc_conf_t  *alcf;
#if (NGX_RESTY_EXT)
    ngx_str_t                       *u;
    u_char                          *colon;
    size_t                           login_len;
#endif
    u_char                           buf[NGX_HTTP_AUTH_BUF_SIZE];
    enum {
        sw_login,
        sw_passwd,
        sw_skip
    } state;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_basic_module);

#if (NGX_RESTY_EXT)
    if (alcf->realm == NULL) {
        return NGX_DECLINED;
    }

    if (alcf->user_file == NULL
        && (alcf->users == NULL || alcf->users->nelts == 0))
    {
        return NGX_DECLINED;
    }
#else
    if (alcf->realm == NULL || alcf->user_file == NULL) {
        return NGX_DECLINED;
    }
#endif

    if (ngx_http_complex_value(r, alcf->realm, &realm) != NGX_OK) {
        return NGX_ERROR;
    }

    if (realm.len == 3 && ngx_strncmp(realm.data, "off", 3) == 0) {
        return NGX_DECLINED;
    }

    rc = ngx_http_auth_basic_user(r);

    if (rc == NGX_DECLINED) {

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "no user/password was provided for basic authentication");

        return ngx_http_auth_basic_set_realm(r, &realm);
    }

    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

#if (NGX_RESTY_EXT)
    if (alcf->users && alcf->users->nelts > 0) {
        u = alcf->users->elts;

        for (i = 0; i < alcf->users->nelts; i++) {

            colon = (u_char *) ngx_strlchr(u[i].data,
                                           u[i].data + u[i].len, ':');
            if (colon == NULL) {
                continue;
            }

            login_len = (size_t) (colon - u[i].data);

            if (r->headers_in.user.len != login_len) {
                continue;
            }

            if (ngx_strncmp(r->headers_in.user.data, u[i].data,
                login_len) != 0)
            {
                continue;
            }

            pwd.data = colon + 1;
            pwd.len  = u[i].len - (pwd.data - u[i].data);

            rc = ngx_http_auth_basic_crypt_handler(r, &pwd, &realm);

            return rc;
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "user \"%V\" was not found in "
                      "auth_basic_user directives",
                      &r->headers_in.user);

        return ngx_http_auth_basic_set_realm(r, &realm);
    }
#endif

    if (ngx_http_complex_value(r, alcf->user_file, &user_file) != NGX_OK) {
        return NGX_ERROR;
    }

    fd = ngx_open_file(user_file.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);

    if (fd == NGX_INVALID_FILE) {
        err = ngx_errno;

        if (err == NGX_ENOENT) {
            level = NGX_LOG_ERR;
            rc = NGX_HTTP_FORBIDDEN;

        } else {
            level = NGX_LOG_CRIT;
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_log_error(level, r->connection->log, err,
                      ngx_open_file_n " \"%s\" failed", user_file.data);

        return rc;
    }

    ngx_memzero(&file, sizeof(ngx_file_t));

    file.fd = fd;
    file.name = user_file;
    file.log = r->connection->log;

    state = sw_login;
    passwd = 0;
    login = 0;
    left = 0;
    offset = 0;

    for ( ;; ) {
        i = left;

        n = ngx_read_file(&file, buf + left, NGX_HTTP_AUTH_BUF_SIZE - left,
                          offset);

        if (n == NGX_ERROR) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto cleanup;
        }

        if (n == 0) {
            break;
        }

        for (i = left; i < left + n; i++) {
            switch (state) {

            case sw_login:
                if (login == 0) {

                    if (buf[i] == '#' || buf[i] == CR) {
                        state = sw_skip;
                        break;
                    }

                    if (buf[i] == LF) {
                        break;
                    }
                }

                if (buf[i] != r->headers_in.user.data[login]) {
                    state = sw_skip;
                    break;
                }

                if (login == r->headers_in.user.len) {
                    state = sw_passwd;
                    passwd = i + 1;
                }

                login++;

                break;

            case sw_passwd:
                if (buf[i] == LF || buf[i] == CR || buf[i] == ':') {
                    buf[i] = '\0';

                    pwd.len = i - passwd;
                    pwd.data = &buf[passwd];

                    rc = ngx_http_auth_basic_crypt_handler(r, &pwd, &realm);
                    goto cleanup;
                }

                break;

            case sw_skip:
                if (buf[i] == LF) {
                    state = sw_login;
                    login = 0;
                }

                break;
            }
        }

        if (state == sw_passwd) {
            left = left + n - passwd;
            ngx_memmove(buf, &buf[passwd], left);
            passwd = 0;

        } else {
            left = 0;
        }

        offset += n;
    }

    if (state == sw_passwd) {
        pwd.len = i - passwd;
        pwd.data = ngx_pnalloc(r->pool, pwd.len + 1);
        if (pwd.data == NULL) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto cleanup;
        }

        ngx_cpystrn(pwd.data, &buf[passwd], pwd.len + 1);

        rc = ngx_http_auth_basic_crypt_handler(r, &pwd, &realm);
        goto cleanup;
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "user \"%V\" was not found in \"%s\"",
                  &r->headers_in.user, user_file.data);

    rc = ngx_http_auth_basic_set_realm(r, &realm);

cleanup:

    if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", user_file.data);
    }

    ngx_explicit_memzero(buf, NGX_HTTP_AUTH_BUF_SIZE);

    return rc;
}


static ngx_int_t
ngx_http_auth_basic_crypt_handler(ngx_http_request_t *r, ngx_str_t *passwd,
    ngx_str_t *realm)
{
    ngx_int_t   rc;
    u_char     *encrypted;

    rc = ngx_crypt(r->pool, r->headers_in.passwd.data, passwd->data,
                   &encrypted);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "rc: %i user: \"%V\" salt: \"%s\"",
                   rc, &r->headers_in.user, passwd->data);

    if (rc != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_strcmp(encrypted, passwd->data) == 0) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "encrypted: \"%s\"", encrypted);

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "user \"%V\": password mismatch",
                  &r->headers_in.user);

    return ngx_http_auth_basic_set_realm(r, realm);
}


static ngx_int_t
ngx_http_auth_basic_set_realm(ngx_http_request_t *r, ngx_str_t *realm)
{
    size_t            len;
    u_char           *basic, *p;
    ngx_table_elt_t  *h;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    len = sizeof("Basic realm=\"\"") - 1 + realm->len;

    basic = ngx_pnalloc(r->pool, len);
    if (basic == NULL) {
        h->hash = 0;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = ngx_cpymem(basic, "Basic realm=\"", sizeof("Basic realm=\"") - 1);
    p = ngx_cpymem(p, realm->data, realm->len);
    *p = '"';

    h->hash = 1;
    h->next = NULL;
    h->value.data = basic;
    h->value.len = len;

    if (ngx_http_proxy_auth(r)) {
        r->headers_out.proxy_authenticate = h;
        ngx_str_set(&h->key, "Proxy-Authenticate");
        return NGX_HTTP_PROXY_AUTH_REQUIRED;

    } else {
        r->headers_out.www_authenticate = h;
        ngx_str_set(&h->key, "WWW-Authenticate");
        return NGX_HTTP_UNAUTHORIZED;
    }
}


static void *
ngx_http_auth_basic_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_auth_basic_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_basic_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->realm = NGX_CONF_UNSET_PTR;
    conf->user_file = NGX_CONF_UNSET_PTR;
#if (NGX_RESTY_EXT)
    conf->users = NGX_CONF_UNSET_PTR;
#endif

    return conf;
}


static char *
ngx_http_auth_basic_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_auth_basic_loc_conf_t  *prev = parent;
    ngx_http_auth_basic_loc_conf_t  *conf = child;

    ngx_conf_merge_ptr_value(conf->realm, prev->realm, NULL);

#if (NGX_RESTY_EXT)
    if (conf->users == NGX_CONF_UNSET_PTR
        && conf->user_file == NGX_CONF_UNSET_PTR)
    {
        ngx_conf_merge_ptr_value(conf->user_file, prev->user_file, NULL);
        conf->users = (prev->users == NGX_CONF_UNSET_PTR) ? NULL : prev->users;

    } else if (conf->users == NGX_CONF_UNSET_PTR) {
        conf->users = NULL;

    } else if (conf->user_file == NGX_CONF_UNSET_PTR) {
        conf->user_file = NULL;
    }
#else
    ngx_conf_merge_ptr_value(conf->user_file, prev->user_file, NULL);
#endif

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_auth_basic_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_basic_handler;

    return NGX_OK;
}


static char *
ngx_http_auth_basic_user_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_basic_loc_conf_t *alcf = conf;

    ngx_str_t                         *value;
    ngx_http_compile_complex_value_t   ccv;

    if (alcf->user_file != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

#if (NGX_RESTY_EXT)
    if (alcf->users != NGX_CONF_UNSET_PTR) {
        return "is incompatible with \"auth_basic_user\"";
    }
#endif

    alcf->user_file = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (alcf->user_file == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = alcf->user_file;
    ccv.zero = 1;
    ccv.conf_prefix = 1;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


#if (NGX_RESTY_EXT)

static char *
ngx_http_auth_basic_add_user(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_basic_loc_conf_t *alcf = conf;

    ngx_str_t                      *value;
    ngx_str_t                      *user;
    ngx_uint_t                      colons;
    ngx_uint_t                      i;
    ngx_uint_t                      len;

    if (alcf->user_file != NGX_CONF_UNSET_PTR) {
        return "is incompatible with \"auth_basic_user_file\"";
    }

    if (alcf->users == NGX_CONF_UNSET_PTR || alcf->users == NULL) {
        alcf->users = ngx_array_create(cf->pool, 1,
                                       sizeof(ngx_str_t));
        if (alcf->users == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    colons = 0;
    len = value[1].len;
    for (i = 0; i < value[1].len; i++) {
        if (value[1].data[i] == ':') {
            colons++;
            if (colons == 2) {
                len = i;
                break;
            }
        }
    }

    if (colons < 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_basic_user must contain at least one colon");
        return NGX_CONF_ERROR;
    }

    user = ngx_array_push(alcf->users);
    if (user == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(user, sizeof(*user));

    if (colons > 1) {
        user->len = len;

        user->data = ngx_pnalloc(cf->pool, len + 1);
        if (user->data == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memcpy(user->data, value[1].data, len);
        user->data[len] = '\0';

    } else {
        *user = value[1];
    }

    return NGX_CONF_OK;
}

#endif
