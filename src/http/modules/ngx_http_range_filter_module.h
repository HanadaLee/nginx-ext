
/*
 * Copyright (C) Hanada
 */


#ifndef _NGX_HTTP_RANGE_FILTER_MODULE_H_INCLUDED_
#define _NGX_HTTP_RANGE_FILTER_MODULE_H_INCLUDED_


typedef struct {
    off_t                      start;
    off_t                      end;
    ngx_str_t                  content_range;
} ngx_http_range_t;


typedef struct ngx_http_range_filter_s  ngx_http_range_filter_t;

typedef ngx_int_t (*ngx_http_range_filter_pt)(ngx_http_request_t *r,
    ngx_chain_t *in, ngx_http_range_filter_t *filter,
    ngx_http_output_body_filter_pt next);


struct ngx_http_range_filter_s {
    ngx_http_range_filter_pt   handler;
    void                      *data;

    /* Populated only when the range filter accepts a multipart response. */
    ngx_array_t               *ranges;
    ngx_str_t                 *boundary;
    off_t                      offset;
};


void ngx_http_range_set_filter(ngx_http_request_t *r,
    ngx_http_range_filter_t *filter);


#endif /* _NGX_HTTP_RANGE_FILTER_MODULE_H_INCLUDED_ */
