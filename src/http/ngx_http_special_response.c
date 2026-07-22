
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

#if (NGX_RESTY_EXT && NGX_CONDITION)
#include <ngx_http_condition_module.h>
#endif


static ngx_int_t ngx_http_send_error_page(ngx_http_request_t *r,
    ngx_http_err_page_t *err_page);
static ngx_int_t ngx_http_send_special_response(ngx_http_request_t *r,
    ngx_http_core_loc_conf_t *clcf, ngx_uint_t err);
static ngx_int_t ngx_http_send_refresh(ngx_http_request_t *r);
#if (NGX_RESTY_EXT)
static ngx_buf_t *ngx_http_set_server_info(ngx_http_request_t *r);


static u_char ngx_http_error_head[] =
"<!DOCTYPE html><html>" CRLF
"<head>"
;
#endif


static u_char ngx_http_error_full_tail[] =
#if (NGX_RESTY_EXT)
"<p>" NGINX_VER "</p></div>" CRLF
#else
"<hr><center>" NGINX_VER "</center>" CRLF
#endif
"</body>" CRLF
"</html>" CRLF
;


static u_char ngx_http_error_build_tail[] =
#if (NGX_RESTY_EXT)
"<p>" NGINX_VER_BUILD "</p></div>" CRLF
#else
"<hr><center>" NGINX_VER_BUILD "</center>" CRLF
#endif
"</body>" CRLF
"</html>" CRLF
;


static u_char ngx_http_error_tail[] =
#if (NGX_RESTY_EXT)
"</div>" CRLF
#else
"<hr><center>openresty</center>" CRLF
#endif
"</body>" CRLF
"</html>" CRLF
;


#if (NGX_RESTY_EXT)
static u_char ngx_http_error_style[] =
"<style>" CRLF
"body{font-family:Arial,sans-serif;background-color:#f4f4f9;color:#333;"
"margin:0;padding:0;display:flex;height:100vh;"
"justify-content:center;align-items:center}"
"div{background-color:white;border-radius:8px;"
"box-shadow:0 4px 8px rgba(0,0,0,0.1);padding:20px 30px;"
"width:100%;max-width:600px}"
"h1{color:#f90}"
"p{font-size:1.2em}"
"table{width:100%;margin:20px 0;border-collapse:collapse}"
"table td{padding:10px;border:1px solid #ddd;}"
"table td:first-child{font-weight:bold;background-color:#f9f9f9}"
"@media (prefers-color-scheme:dark){body{background-color:#333;color:#f4f4f9}"
"div{background-color:black}"
"table td{border:1px solid #444}"
"table td:first-child{background-color:#3a3a3a}}" CRLF
"</style>" CRLF
;


static u_char ngx_http_error_server_info_head[] =
"<p>Please report this error and provide the following information.</p>" CRLF
"<table><tbody>" CRLF
"<tr>" CRLF
"<td>Date</td>" CRLF
"<td>"
;


static u_char ngx_http_error_server_info_ip[] =
"</td>" CRLF
"</tr>" CRLF
"<tr>" CRLF
"<td>Client IP</td>" CRLF
"<td>"
;


static u_char ngx_http_error_server_info_server[] =
"</td>" CRLF
"</tr>" CRLF
"<tr>" CRLF
"<td>Server</td>" CRLF
"<td>"
;


static u_char ngx_http_error_server_info_id[] =
"</td>" CRLF
"</tr>" CRLF
"<tr>" CRLF
"<td>Request ID</td>" CRLF
"<td>"
;


static u_char ngx_http_error_server_info_tail[] =
"</td>" CRLF
"</tr>" CRLF
"</tbody></table>" CRLF
;
#endif


static u_char ngx_http_msie_padding[] =
"<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
"<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
"<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
"<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
"<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
"<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
;


static u_char ngx_http_msie_refresh_head[] =
"<html><head><meta http-equiv=\"Refresh\" content=\"0; URL=";


static u_char ngx_http_msie_refresh_tail[] =
"\"></head><body></body></html>" CRLF;


static char ngx_http_error_301_page[] =
#if (NGX_RESTY_EXT)
"<title>301 Moved Permanently</title></head>" CRLF
"<body>" CRLF
"<div style=\"text-align:center\">" CRLF
"<h1>301 Moved Permanently</h1>" CRLF
#else
"<html>" CRLF
"<head><title>301 Moved Permanently</title></head>" CRLF
"<body>" CRLF
"<center><h1>301 Moved Permanently</h1></center>" CRLF
#endif
;


static char ngx_http_error_302_page[] =
#if (NGX_RESTY_EXT)
"<title>302 Found</title></head>" CRLF
"<body>" CRLF
"<div style=\"text-align:center\">" CRLF
"<h1>302 Found</h1>" CRLF
#else
"<html>" CRLF
"<head><title>302 Found</title></head>" CRLF
"<body>" CRLF
"<center><h1>302 Found</h1></center>" CRLF
#endif
;


static char ngx_http_error_303_page[] =
#if (NGX_RESTY_EXT)
"<title>303 See Other</title></head>" CRLF
"<body>" CRLF
"<div style=\"text-align:center\">" CRLF
"<h1>303 See Other</h1>" CRLF
#else
"<html>" CRLF
"<head><title>303 See Other</title></head>" CRLF
"<body>" CRLF
"<center><h1>303 See Other</h1></center>" CRLF
#endif
;


static char ngx_http_error_307_page[] =
#if (NGX_RESTY_EXT)
"<title>307 Temporary Redirect</title></head>" CRLF
"<body>" CRLF
"<div style=\"text-align:center\">" CRLF
"<h1>307 Temporary Redirect</h1>" CRLF
#else
"<html>" CRLF
"<head><title>307 Temporary Redirect</title></head>" CRLF
"<body>" CRLF
"<center><h1>307 Temporary Redirect</h1></center>" CRLF
#endif
;


static char ngx_http_error_308_page[] =
#if (NGX_RESTY_EXT)
"<title>308 Permanent Redirect</title></head>" CRLF
"<body>" CRLF
"<div style=\"text-align:center\">" CRLF
"<h1>308 Permanent Redirect</h1>" CRLF
#else
"<html>" CRLF
"<head><title>308 Permanent Redirect</title></head>" CRLF
"<body>" CRLF
"<center><h1>308 Permanent Redirect</h1></center>" CRLF
#endif
;


static char ngx_http_error_400_page[] =
#if (NGX_RESTY_EXT)
"<title>400 Bad Request</title></head>" CRLF
"<body>" CRLF
"<div><h1>400 Bad Request</h1>" CRLF
"<p>Cannot process request due to client error.</p>" CRLF
#else
"<html>" CRLF
"<head><title>400 Bad Request</title></head>" CRLF
"<body>" CRLF
"<center><h1>400 Bad Request</h1></center>" CRLF
#endif
;


static char ngx_http_error_401_page[] =
#if (NGX_RESTY_EXT)
"<title>401 Unauthorized</title></head>" CRLF
"<body>" CRLF
"<div><h1>401 Unauthorized</h1>" CRLF
"<p>Missing or invalid authentication credentials.</p>" CRLF
#else
"<html>" CRLF
"<head><title>401 Authorization Required</title></head>" CRLF
"<body>" CRLF
"<center><h1>401 Authorization Required</h1></center>" CRLF
#endif
;


static char ngx_http_error_402_page[] =
#if (NGX_RESTY_EXT)
"<title>402 Payment Required</title></head>" CRLF
"<body>" CRLF
"<div><h1>402 Payment Required</h1>" CRLF
#else
"<html>" CRLF
"<head><title>402 Payment Required</title></head>" CRLF
"<body>" CRLF
"<center><h1>402 Payment Required</h1></center>" CRLF
#endif
;


static char ngx_http_error_403_page[] =
#if (NGX_RESTY_EXT)
"<title>403 Forbidden</title></head>" CRLF
"<body>" CRLF
"<div><h1>403 Forbidden</h1>" CRLF
"<p>You do not have permission to access the resource.</p>" CRLF
#else
"<html>" CRLF
"<head><title>403 Forbidden</title></head>" CRLF
"<body>" CRLF
"<center><h1>403 Forbidden</h1></center>" CRLF
#endif
;


static char ngx_http_error_404_page[] =
#if (NGX_RESTY_EXT)
"<title>404 Not Found</title></head>" CRLF
"<body>" CRLF
"<div><h1>404 Not Found</h1>" CRLF
"<p>The resource cannot be found.</p>" CRLF
#else
"<html>" CRLF
"<head><title>404 Not Found</title></head>" CRLF
"<body>" CRLF
"<center><h1>404 Not Found</h1></center>" CRLF
#endif
;


static char ngx_http_error_405_page[] =
#if (NGX_RESTY_EXT)
"<title>405 Method Not Allowed</title></head>" CRLF
"<body>" CRLF
"<div><h1>405 Method Not Allowed</h1>" CRLF
"<p>Request method is not supported by the resource.</p>" CRLF
#else
"<html>" CRLF
"<head><title>405 Not Allowed</title></head>" CRLF
"<body>" CRLF
"<center><h1>405 Not Allowed</h1></center>" CRLF
#endif
;


static char ngx_http_error_406_page[] =
#if (NGX_RESTY_EXT)
"<title>406 Not Acceptable</title></head>" CRLF
"<body>" CRLF
"<div><h1>406 Not Acceptable</h1>" CRLF
"<p>Unable to provide a matching response.</p>" CRLF
#else
"<html>" CRLF
"<head><title>406 Not Acceptable</title></head>" CRLF
"<body>" CRLF
"<center><h1>406 Not Acceptable</h1></center>" CRLF
#endif
;


static char ngx_http_error_407_page[] =
#if (NGX_RESTY_EXT)
"<title>407 Proxy Authentication Required</title></head>" CRLF
"<body>" CRLF
"<div><h1>407 Proxy Authentication Required</h1>" CRLF
"<p>Missing or invalid proxy authentication credentials.</p>" CRLF
#else
"<html>" CRLF
"<head><title>407 Proxy Authentication Required</title></head>" CRLF
"<body>" CRLF
"<center><h1>407 Proxy Authentication Required</h1></center>" CRLF
#endif
;


static char ngx_http_error_408_page[] =
#if (NGX_RESTY_EXT)
"<title>408 Request Timeout</title></head>" CRLF
"<body>" CRLF
"<div><h1>408 Request Timeout</h1>" CRLF
"<p>Did not receive a complete request within the waiting time.</p>" CRLF
#else
"<html>" CRLF
"<head><title>408 Request Time-out</title></head>" CRLF
"<body>" CRLF
"<center><h1>408 Request Time-out</h1></center>" CRLF
#endif
;


static char ngx_http_error_409_page[] =
#if (NGX_RESTY_EXT)
"<title>409 Conflict</title></head>" CRLF
"<body>" CRLF
"<div><h1>409 Conflict</h1>" CRLF
"<p>Request conflict with the current state of the resource.</p>" CRLF
#else
"<html>" CRLF
"<head><title>409 Conflict</title></head>" CRLF
"<body>" CRLF
"<center><h1>409 Conflict</h1></center>" CRLF
#endif
;


static char ngx_http_error_410_page[] =
#if (NGX_RESTY_EXT)
"<title>410 Gone</title></head>" CRLF
"<body>" CRLF
"<div><h1>410 Gone</h1>" CRLF
"<p>The resource is no longer available.</p>" CRLF
#else
"<html>" CRLF
"<head><title>410 Gone</title></head>" CRLF
"<body>" CRLF
"<center><h1>410 Gone</h1></center>" CRLF
#endif
;


static char ngx_http_error_411_page[] =
#if (NGX_RESTY_EXT)
"<title>411 Length Required</title></head>" CRLF
"<body>" CRLF
"<div><h1>411 Length Required</h1>" CRLF
"<p>Refused to accept the request without a Content-Length header.</p>" CRLF
#else
"<html>" CRLF
"<head><title>411 Length Required</title></head>" CRLF
"<body>" CRLF
"<center><h1>411 Length Required</h1></center>" CRLF
#endif
;


static char ngx_http_error_412_page[] =
#if (NGX_RESTY_EXT)
"<title>412 Precondition Failed</title></head>" CRLF
"<body>" CRLF
"<div><h1>412 Precondition Failed</h1>" CRLF
"<p>Conditions in the request headers are not met.</p>" CRLF
#else
"<html>" CRLF
"<head><title>412 Precondition Failed</title></head>" CRLF
"<body>" CRLF
"<center><h1>412 Precondition Failed</h1></center>" CRLF
#endif
;


static char ngx_http_error_413_page[] =
#if (NGX_RESTY_EXT)
"<title>413 Content Too Large</title></head>" CRLF
"<body>" CRLF
"<div><h1>413 Content Too Large</h1>" CRLF
"<p>Request entity is larger than limits.</p>" CRLF
#else
"<html>" CRLF
"<head><title>413 Request Entity Too Large</title></head>" CRLF
"<body>" CRLF
"<center><h1>413 Request Entity Too Large</h1></center>" CRLF
#endif
;


static char ngx_http_error_414_page[] =
#if (NGX_RESTY_EXT)
"<title>414 URI Too Long</title></head>" CRLF
"<body>" CRLF
"<div><h1>414 URI Too Long</h1>" CRLF
"<p>Request URI is longer than limits.</p>" CRLF
#else
"<html>" CRLF
"<head><title>414 Request-URI Too Large</title></head>" CRLF
#endif
"<body>" CRLF
"<center><h1>414 Request-URI Too Large</h1></center>" CRLF
;


static char ngx_http_error_415_page[] =
#if (NGX_RESTY_EXT)
"<title>415 Unsupported Media Type</title></head>" CRLF
"<body>" CRLF
"<div><h1>415 Unsupported Media Type</h1>" CRLF
"<p>The message content format is not supported.</p>" CRLF
#else
"<html>" CRLF
"<head><title>415 Unsupported Media Type</title></head>" CRLF
"<body>" CRLF
"<center><h1>415 Unsupported Media Type</h1></center>" CRLF
#endif
;


static char ngx_http_error_416_page[] =
#if (NGX_RESTY_EXT)
"<title>416 Range Not Satisfiable</title></head>" CRLF
"<body>" CRLF
"<div><h1>416 Range Not Satisfiable</h1>" CRLF
"<p>Cannot fulfill the ranges specified in the Range header.</p>" CRLF
#else
"<html>" CRLF
"<head><title>416 Requested Range Not Satisfiable</title></head>" CRLF
"<body>" CRLF
"<center><h1>416 Requested Range Not Satisfiable</h1></center>" CRLF
#endif
;


static char ngx_http_error_421_page[] =
#if (NGX_RESTY_EXT)
"<title>421 Misdirected Request</title></head>" CRLF
"<body>" CRLF
"<div><h1>421 Misdirected Request</h1>" CRLF
"<p>Request was directed to a server that is unable to respond.</p>" CRLF
#else
"<html>" CRLF
"<head><title>421 Misdirected Request</title></head>" CRLF
"<body>" CRLF
"<center><h1>421 Misdirected Request</h1></center>" CRLF
#endif
;


static char ngx_http_error_429_page[] =
#if (NGX_RESTY_EXT)
"<title>429 Too Many Requests</title></head>" CRLF
"<body>" CRLF
"<div><h1>429 Too Many Requests</h1>" CRLF
"<p>The client had sent too many requests in a given amount of time.</p>" CRLF
#else
"<html>" CRLF
"<head><title>429 Too Many Requests</title></head>" CRLF
"<body>" CRLF
"<center><h1>429 Too Many Requests</h1></center>" CRLF
#endif
;


static char ngx_http_error_494_page[] =
#if (NGX_RESTY_EXT)
"<title>400 Bad Request</title></head>" CRLF
"<body>" CRLF
"<div><h1>400 Bad Request</h1>" CRLF
"<p>Request header or cookie too large.</p>" CRLF
#else
"<html>" CRLF
"<head><title>400 Request Header Or Cookie Too Large</title></head>"
CRLF
"<body>" CRLF
"<center><h1>400 Bad Request</h1></center>" CRLF
"<center>Request Header Or Cookie Too Large</center>" CRLF
#endif
;


static char ngx_http_error_495_page[] =
#if (NGX_RESTY_EXT)
"<title>400 Bad Request</title></head>" CRLF
"<body>" CRLF
"<div><h1>400 Bad Request</h1>" CRLF
"<p>SSL certificate error.</p>" CRLF
#else
"<html>" CRLF
"<head><title>400 The SSL certificate error</title></head>"
CRLF
"<body>" CRLF
"<center><h1>400 Bad Request</h1></center>" CRLF
"<center>The SSL certificate error</center>" CRLF
#endif
;


static char ngx_http_error_496_page[] =
#if (NGX_RESTY_EXT)
"<title>400 Bad Request</title></head>" CRLF
"<body>" CRLF
"<div><h1>400 Bad Request</h1>" CRLF
"<p>Missing required SSL certificate.</p>" CRLF
#else
"<html>" CRLF
"<head><title>400 No required SSL certificate was sent</title></head>"
CRLF
"<body>" CRLF
"<center><h1>400 Bad Request</h1></center>" CRLF
"<center>No required SSL certificate was sent</center>" CRLF
#endif
;


static char ngx_http_error_497_page[] =
#if (NGX_RESTY_EXT)
"<title>400 Bad Request</title></head>" CRLF
"<body>" CRLF
"<div><h1>400 Bad Request</h1>" CRLF
"<p>The plain HTTP request was sent to HTTPS port.</p>" CRLF
#else
"<html>" CRLF
"<head><title>400 The plain HTTP request was sent to HTTPS port</title></head>"
CRLF
"<body>" CRLF
"<center><h1>400 Bad Request</h1></center>" CRLF
"<center>The plain HTTP request was sent to HTTPS port</center>" CRLF
#endif
;


static char ngx_http_error_500_page[] =
#if (NGX_RESTY_EXT)
"<title>500 Internal Server Error</title></head>" CRLF
"<body>" CRLF
"<div><h1>500 Internal Server Error</h1>" CRLF
"<p>The server encountered an unexpected issue.</p>" CRLF
#else
"<html>" CRLF
"<head><title>500 Internal Server Error</title></head>" CRLF
"<body>" CRLF
"<center><h1>500 Internal Server Error</h1></center>" CRLF
#endif
;


static char ngx_http_error_501_page[] =
#if (NGX_RESTY_EXT)
"<title>501 Not Implemented</title></head>" CRLF
"<body>" CRLF
"<div><h1>501 Not Implemented</h1>" CRLF
"<p>The server does not support the functionality required.</p>" CRLF
#else
"<html>" CRLF
"<head><title>501 Not Implemented</title></head>" CRLF
"<body>" CRLF
"<center><h1>501 Not Implemented</h1></center>" CRLF
#endif
;


static char ngx_http_error_502_page[] =
#if (NGX_RESTY_EXT)
"<title>502 Bad Gateway</title></head>" CRLF
"<body>" CRLF
"<div><h1>502 Bad Gateway</h1>" CRLF
"<p>The server received an invalid response from upstream.</p>" CRLF
#else
"<html>" CRLF
"<head><title>502 Bad Gateway</title></head>" CRLF
"<body>" CRLF
"<center><h1>502 Bad Gateway</h1></center>" CRLF
#endif
;


static char ngx_http_error_503_page[] =
#if (NGX_RESTY_EXT)
"<title>503 Service Unavailable</title></head>" CRLF
"<body>" CRLF
"<div><h1>503 Service Unavailable</h1>" CRLF
"<p>The server is currently unable to handle the request.</p>" CRLF
#else
"<html>" CRLF
"<head><title>503 Service Temporarily Unavailable</title></head>" CRLF
"<body>" CRLF
"<center><h1>503 Service Temporarily Unavailable</h1></center>" CRLF
#endif
;


static char ngx_http_error_504_page[] =
#if (NGX_RESTY_EXT)
"<title>504 Gateway Timeout</title></head>" CRLF
"<body>" CRLF
"<div><h1>504 Gateway Timeout</h1>" CRLF
"<p>The server did not receive a timely response from upstream.</p>" CRLF
#else
"<html>" CRLF
"<head><title>504 Gateway Time-out</title></head>" CRLF
"<body>" CRLF
"<center><h1>504 Gateway Time-out</h1></center>" CRLF
#endif
;


static char ngx_http_error_505_page[] =
#if (NGX_RESTY_EXT)
"<title>505 HTTP Version Not Supported</title></head>" CRLF
"<body>" CRLF
"<div><h1>505 HTTP Version Not Supported</h1>" CRLF
"<p>The server does not support the version of HTTP used in the request.</p>"
CRLF
#else
"<html>" CRLF
"<head><title>505 HTTP Version Not Supported</title></head>" CRLF
"<body>" CRLF
"<center><h1>505 HTTP Version Not Supported</h1></center>" CRLF
#endif
;


static char ngx_http_error_507_page[] =
#if (NGX_RESTY_EXT)
"<title>507 Insufficient Storage</title></head>" CRLF
"<body>" CRLF
"<div><h1>507 Insufficient Storage</h1>" CRLF
"<p>The server does not have enough available storage.</p>" CRLF
#else
"<html>" CRLF
"<head><title>507 Insufficient Storage</title></head>" CRLF
"<body>" CRLF
"<center><h1>507 Insufficient Storage</h1></center>" CRLF
#endif
;


static ngx_str_t ngx_http_error_pages[] = {

    ngx_null_string,                     /* 201, 204 */

#define NGX_HTTP_LAST_2XX  202
#define NGX_HTTP_OFF_3XX   (NGX_HTTP_LAST_2XX - 201)

    /* ngx_null_string, */               /* 300 */
    ngx_string(ngx_http_error_301_page),
    ngx_string(ngx_http_error_302_page),
    ngx_string(ngx_http_error_303_page),
    ngx_null_string,                     /* 304 */
    ngx_null_string,                     /* 305 */
    ngx_null_string,                     /* 306 */
    ngx_string(ngx_http_error_307_page),
    ngx_string(ngx_http_error_308_page),

#define NGX_HTTP_LAST_3XX  309
#define NGX_HTTP_OFF_4XX   (NGX_HTTP_LAST_3XX - 301 + NGX_HTTP_OFF_3XX)

    ngx_string(ngx_http_error_400_page),
    ngx_string(ngx_http_error_401_page),
    ngx_string(ngx_http_error_402_page),
    ngx_string(ngx_http_error_403_page),
    ngx_string(ngx_http_error_404_page),
    ngx_string(ngx_http_error_405_page),
    ngx_string(ngx_http_error_406_page),
    ngx_string(ngx_http_error_407_page),
    ngx_string(ngx_http_error_408_page),
    ngx_string(ngx_http_error_409_page),
    ngx_string(ngx_http_error_410_page),
    ngx_string(ngx_http_error_411_page),
    ngx_string(ngx_http_error_412_page),
    ngx_string(ngx_http_error_413_page),
    ngx_string(ngx_http_error_414_page),
    ngx_string(ngx_http_error_415_page),
    ngx_string(ngx_http_error_416_page),
    ngx_null_string,                     /* 417 */
    ngx_null_string,                     /* 418 */
    ngx_null_string,                     /* 419 */
    ngx_null_string,                     /* 420 */
    ngx_string(ngx_http_error_421_page),
    ngx_null_string,                     /* 422 */
    ngx_null_string,                     /* 423 */
    ngx_null_string,                     /* 424 */
    ngx_null_string,                     /* 425 */
    ngx_null_string,                     /* 426 */
    ngx_null_string,                     /* 427 */
    ngx_null_string,                     /* 428 */
    ngx_string(ngx_http_error_429_page),

#define NGX_HTTP_LAST_4XX  430
#define NGX_HTTP_OFF_5XX   (NGX_HTTP_LAST_4XX - 400 + NGX_HTTP_OFF_4XX)

    ngx_string(ngx_http_error_494_page), /* 494, request header too large */
    ngx_string(ngx_http_error_495_page), /* 495, https certificate error */
    ngx_string(ngx_http_error_496_page), /* 496, https no certificate */
    ngx_string(ngx_http_error_497_page), /* 497, http to https */
    ngx_string(ngx_http_error_404_page), /* 498, canceled */
    ngx_null_string,                     /* 499, client has closed connection */

    ngx_string(ngx_http_error_500_page),
    ngx_string(ngx_http_error_501_page),
    ngx_string(ngx_http_error_502_page),
    ngx_string(ngx_http_error_503_page),
    ngx_string(ngx_http_error_504_page),
    ngx_string(ngx_http_error_505_page),
    ngx_null_string,                     /* 506 */
    ngx_string(ngx_http_error_507_page)

#define NGX_HTTP_LAST_5XX  508

};


ngx_int_t
ngx_http_special_response_handler(ngx_http_request_t *r, ngx_int_t error)
{
    ngx_uint_t                 i, err;
    ngx_http_err_page_t       *err_page;
    ngx_http_core_loc_conf_t  *clcf;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http special response: %i, \"%V?%V\"",
                   error, &r->uri, &r->args);

    r->err_status = error;

    if (r->keepalive) {
        switch (error) {
            case NGX_HTTP_BAD_REQUEST:
            case NGX_HTTP_REQUEST_ENTITY_TOO_LARGE:
            case NGX_HTTP_REQUEST_URI_TOO_LARGE:
            case NGX_HTTP_TO_HTTPS:
            case NGX_HTTPS_CERT_ERROR:
            case NGX_HTTPS_NO_CERT:
            case NGX_HTTP_INTERNAL_SERVER_ERROR:
            case NGX_HTTP_NOT_IMPLEMENTED:
                r->keepalive = 0;
        }
    }

    if (r->lingering_close) {
        switch (error) {
            case NGX_HTTP_BAD_REQUEST:
            case NGX_HTTP_TO_HTTPS:
            case NGX_HTTPS_CERT_ERROR:
            case NGX_HTTPS_NO_CERT:
                r->lingering_close = 0;
        }
    }

    r->headers_out.content_type.len = 0;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (!r->error_page && clcf->error_pages && r->uri_changes != 0) {

        if (clcf->recursive_error_pages == 0) {
            r->error_page = 1;
        }

        err_page = clcf->error_pages->elts;

        for (i = 0; i < clcf->error_pages->nelts; i++) {
            if (err_page[i].status == error) {

#if (NGX_RESTY_EXT && NGX_CONDITION)
                if (ngx_http_condition_get_expr_result(r, err_page[i].expr_id)
                    != NGX_CONDITION_EXPR_HIT)
                {
                    continue;
                }
#endif

                return ngx_http_send_error_page(r, &err_page[i]);
            }
        }
    }

    r->expect_tested = 1;

    if (ngx_http_discard_request_body(r) != NGX_OK) {
        r->keepalive = 0;
    }

    if (clcf->msie_refresh
        && r->headers_in.msie
        && (error == NGX_HTTP_MOVED_PERMANENTLY
            || error == NGX_HTTP_MOVED_TEMPORARILY))
    {
        return ngx_http_send_refresh(r);
    }

    if (error == NGX_HTTP_CREATED) {
        /* 201 */
        err = 0;

    } else if (error == NGX_HTTP_NO_CONTENT) {
        /* 204 */
        err = 0;

    } else if (error >= NGX_HTTP_MOVED_PERMANENTLY
               && error < NGX_HTTP_LAST_3XX)
    {
        /* 3XX */
        err = error - NGX_HTTP_MOVED_PERMANENTLY + NGX_HTTP_OFF_3XX;

    } else if (error >= NGX_HTTP_BAD_REQUEST
               && error < NGX_HTTP_LAST_4XX)
    {
        /* 4XX */
        err = error - NGX_HTTP_BAD_REQUEST + NGX_HTTP_OFF_4XX;

    } else if (error >= NGX_HTTP_NGINX_CODES
               && error < NGX_HTTP_LAST_5XX)
    {
        /* 49X, 5XX */
        err = error - NGX_HTTP_NGINX_CODES + NGX_HTTP_OFF_5XX;
        switch (error) {
            case NGX_HTTP_TO_HTTPS:
            case NGX_HTTPS_CERT_ERROR:
            case NGX_HTTPS_NO_CERT:
            case NGX_HTTP_REQUEST_HEADER_TOO_LARGE:
                r->err_status = NGX_HTTP_BAD_REQUEST;
        }

    } else {
        /* unknown code, zero body */
        err = 0;
    }

    return ngx_http_send_special_response(r, clcf, err);
}


ngx_int_t
ngx_http_filter_finalize_request(ngx_http_request_t *r, ngx_module_t *m,
    ngx_int_t error)
{
    void       *ctx;
    ngx_int_t   rc;

    ngx_http_clean_header(r);

    ctx = NULL;

    if (m) {
        ctx = r->ctx[m->ctx_index];
    }

    /* clear the modules contexts */
    ngx_memzero(r->ctx, sizeof(void *) * ngx_http_max_module);

    if (m) {
        r->ctx[m->ctx_index] = ctx;
    }

    r->filter_finalize = 1;

    rc = ngx_http_special_response_handler(r, error);

    /* NGX_ERROR resets any pending data */

    switch (rc) {

    case NGX_OK:
    case NGX_DONE:
        return NGX_ERROR;

    default:
        return rc;
    }
}


void
ngx_http_clean_header(ngx_http_request_t *r)
{
    ngx_memzero(&r->headers_out.status,
                sizeof(ngx_http_headers_out_t)
                    - offsetof(ngx_http_headers_out_t, status));

    r->headers_out.headers.part.nelts = 0;
    r->headers_out.headers.part.next = NULL;
    r->headers_out.headers.last = &r->headers_out.headers.part;

    r->headers_out.trailers.part.nelts = 0;
    r->headers_out.trailers.part.next = NULL;
    r->headers_out.trailers.last = &r->headers_out.trailers.part;

    r->headers_out.content_length_n = -1;
    r->headers_out.last_modified_time = -1;
}


static ngx_int_t
ngx_http_send_error_page(ngx_http_request_t *r, ngx_http_err_page_t *err_page)
{
    ngx_int_t                  overwrite;
    ngx_str_t                  uri, args;
    ngx_table_elt_t           *location;
    ngx_http_core_loc_conf_t  *clcf;

    overwrite = err_page->overwrite;

    if (overwrite && overwrite != NGX_HTTP_OK) {
        r->expect_tested = 1;
    }

    if (overwrite >= 0) {
        r->err_status = overwrite;
    }

    if (ngx_http_complex_value(r, &err_page->value, &uri) != NGX_OK) {
        return NGX_ERROR;
    }

    if (uri.len && uri.data[0] == '/') {

        if (err_page->value.lengths) {
            ngx_http_split_args(r, &uri, &args);

        } else {
            args = err_page->args;
        }

        if (r->method != NGX_HTTP_HEAD) {
            r->method = NGX_HTTP_GET;
            r->method_name = ngx_http_core_get_method;
        }

        return ngx_http_internal_redirect(r, &uri, &args);
    }

    if (uri.len && uri.data[0] == '@') {
        return ngx_http_named_location(r, &uri);
    }

    r->expect_tested = 1;

    if (ngx_http_discard_request_body(r) != NGX_OK) {
        r->keepalive = 0;
    }

    location = ngx_list_push(&r->headers_out.headers);

    if (location == NULL) {
        return NGX_ERROR;
    }

    if (overwrite != NGX_HTTP_MOVED_PERMANENTLY
        && overwrite != NGX_HTTP_MOVED_TEMPORARILY
        && overwrite != NGX_HTTP_SEE_OTHER
        && overwrite != NGX_HTTP_TEMPORARY_REDIRECT
        && overwrite != NGX_HTTP_PERMANENT_REDIRECT)
    {
        r->err_status = NGX_HTTP_MOVED_TEMPORARILY;
    }

    location->hash = 1;
    location->next = NULL;
    ngx_str_set(&location->key, "Location");
    location->value = uri;

    ngx_http_clear_location(r);

    r->headers_out.location = location;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (clcf->msie_refresh && r->headers_in.msie) {
        return ngx_http_send_refresh(r);
    }

    return ngx_http_send_special_response(r, clcf, r->err_status
                                                   - NGX_HTTP_MOVED_PERMANENTLY
                                                   + NGX_HTTP_OFF_3XX);
}


static ngx_int_t
ngx_http_send_special_response(ngx_http_request_t *r,
    ngx_http_core_loc_conf_t *clcf, ngx_uint_t err)
{
    u_char       *tail;
    size_t        len;
    ngx_int_t     rc;
    ngx_buf_t    *b;
    ngx_uint_t    msie_padding;

#if (NGX_RESTY_EXT)
    ngx_uint_t    style;
    ngx_chain_t   out[6];
    ngx_buf_t    *ib;
    ngx_uint_t    i;
#else
    ngx_chain_t   out[3];
#endif

    if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_ON) {
        len = sizeof(ngx_http_error_full_tail) - 1;
        tail = ngx_http_error_full_tail;

    } else if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_BUILD) {
        len = sizeof(ngx_http_error_build_tail) - 1;
        tail = ngx_http_error_build_tail;

    } else {
        len = sizeof(ngx_http_error_tail) - 1;
        tail = ngx_http_error_tail;
    }

#if (NGX_RESTY_EXT)
    if (clcf->error_page_server_info && err >= NGX_HTTP_OFF_4XX) {
        ib = ngx_http_set_server_info(r);
        if (ib == NULL) {
            return NGX_ERROR;
        }

    } else {
        ib = NULL;
    }

    style = 0;
#endif

    msie_padding = 0;

    if (ngx_http_error_pages[err].len) {
#if (NGX_RESTY_EXT)
        r->headers_out.content_length_n = sizeof(ngx_http_error_head) - 1
                                          + ngx_http_error_pages[err].len
                                          + (ib ? (ib->last - ib->pos) : 0)
                                          + len;

        if (err >= NGX_HTTP_OFF_4XX) {
            r->headers_out.content_length_n += sizeof(ngx_http_error_style) - 1;
            style = 1;
        }
#else
        r->headers_out.content_length_n = ngx_http_error_pages[err].len + len;
#endif

        if (clcf->msie_padding
            && (r->headers_in.msie || r->headers_in.chrome)
            && r->http_version >= NGX_HTTP_VERSION_10
            && err >= NGX_HTTP_OFF_4XX)
        {
            r->headers_out.content_length_n +=
                                         sizeof(ngx_http_msie_padding) - 1;
            msie_padding = 1;
        }

        r->headers_out.content_type_len = sizeof("text/html") - 1;
        ngx_str_set(&r->headers_out.content_type, "text/html");
        r->headers_out.content_type_lowcase = NULL;

    } else {
        r->headers_out.content_length_n = 0;
    }

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    ngx_http_clear_accept_ranges(r);
    ngx_http_clear_last_modified(r);
    ngx_http_clear_etag(r);

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || r->header_only) {
        return rc;
    }

    if (ngx_http_error_pages[err].len == 0) {
        return ngx_http_send_special(r, NGX_HTTP_LAST);
    }

#if (NGX_RESTY_EXT)
    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->memory = 1;
    b->pos = ngx_http_error_head;
    b->last = ngx_http_error_head + sizeof(ngx_http_error_head) - 1;

    i = 0;
    out[i].buf = b;
    out[i].next = &out[i + 1];
    i++;

    if (style) {
        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }

        b->memory = 1;
        b->pos = ngx_http_error_style;
        b->last = ngx_http_error_style + sizeof(ngx_http_error_style) - 1;

        out[i].buf = b;
        out[i].next = &out[i + 1];
        i++;
    }
#endif

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->memory = 1;
    b->pos = ngx_http_error_pages[err].data;
    b->last = ngx_http_error_pages[err].data + ngx_http_error_pages[err].len;

#if (NGX_RESTY_EXT)
    out[i].buf = b;
    out[i].next = &out[i + 1];
    i++;

    if (ib) {
        out[i].buf = ib;
        out[i].next = &out[i + 1];
        i++;
    }
#else
    out[0].buf = b;
    out[0].next = &out[1];
#endif

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->memory = 1;

    b->pos = tail;
    b->last = tail + len;

#if (NGX_RESTY_EXT)
    out[i].buf = b;
    out[i].next = NULL;
#else
    out[1].buf = b;
    out[1].next = NULL;
#endif

    if (msie_padding) {
        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }

        b->memory = 1;
        b->pos = ngx_http_msie_padding;
        b->last = ngx_http_msie_padding + sizeof(ngx_http_msie_padding) - 1;

#if (NGX_RESTY_EXT)
        out[i].next = &out[i + 1];
        i++;
        out[i].buf = b;
        out[i].next = NULL;
#else
        out[1].next = &out[2];
        out[2].buf = b;
        out[2].next = NULL;
#endif
    }

    if (r == r->main) {
        b->last_buf = 1;
    }

    b->last_in_chain = 1;

    return ngx_http_output_filter(r, &out[0]);
}


static ngx_int_t
ngx_http_send_refresh(ngx_http_request_t *r)
{
    u_char       *p, *location;
    size_t        len, size;
    uintptr_t     escape;
    ngx_int_t     rc;
    ngx_buf_t    *b;
    ngx_chain_t   out;

    len = r->headers_out.location->value.len;
    location = r->headers_out.location->value.data;

    escape = 2 * ngx_escape_uri(NULL, location, len, NGX_ESCAPE_REFRESH);

    size = sizeof(ngx_http_msie_refresh_head) - 1
           + escape + len
           + sizeof(ngx_http_msie_refresh_tail) - 1;

    r->err_status = NGX_HTTP_OK;

    r->headers_out.content_type_len = sizeof("text/html") - 1;
    ngx_str_set(&r->headers_out.content_type, "text/html");
    r->headers_out.content_type_lowcase = NULL;

    r->headers_out.location->hash = 0;
    r->headers_out.location = NULL;

    r->headers_out.content_length_n = size;

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    ngx_http_clear_accept_ranges(r);
    ngx_http_clear_last_modified(r);
    ngx_http_clear_etag(r);

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || r->header_only) {
        return rc;
    }

    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(b->pos, ngx_http_msie_refresh_head,
                   sizeof(ngx_http_msie_refresh_head) - 1);

    if (escape == 0) {
        p = ngx_cpymem(p, location, len);

    } else {
        p = (u_char *) ngx_escape_uri(p, location, len, NGX_ESCAPE_REFRESH);
    }

    b->last = ngx_cpymem(p, ngx_http_msie_refresh_tail,
                         sizeof(ngx_http_msie_refresh_tail) - 1);

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


#if (NGX_RESTY_EXT)
static ngx_buf_t *
ngx_http_set_server_info(ngx_http_request_t *r)
{
    size_t                      size;
    ngx_buf_t                  *b;
    ngx_str_t                   client_ip, request_id;
    ngx_http_variable_value_t  *value;
    ngx_http_core_loc_conf_t   *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (!clcf->error_page_client_ip_var_index) {
        client_ip.data = (u_char *) "-";
        client_ip.len = 1;

    } else {
        value = ngx_http_get_indexed_variable(r,
                    clcf->error_page_client_ip_var_index);

        if (value == NULL || value->not_found) {
            client_ip.data = (u_char *) "-";
            client_ip.len = 1;

        } else {
            client_ip.data = value->data;
            client_ip.len = value->len;
        }
    }

    if (ngx_http_get_request_id(r, &request_id) != NGX_OK
        || request_id.len == 0)
    {
        request_id.data = (u_char *) "-";
        request_id.len = 1;
    }

    size = sizeof(ngx_http_error_server_info_head) - 1
           + ngx_cached_http_time.len
           + sizeof(ngx_http_error_server_info_ip) - 1
           + client_ip.len
           + sizeof(ngx_http_error_server_info_server) - 1
           + ngx_cycle->hostname.len
           + sizeof(ngx_http_error_server_info_id) - 1
           + request_id.len
           + sizeof(ngx_http_error_server_info_tail) - 1;

    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NULL;
    }

    b->last = ngx_cpymem(b->last, ngx_http_error_server_info_head,
                         sizeof(ngx_http_error_server_info_head) - 1);
    b->last = ngx_cpymem(b->last, ngx_cached_http_time.data,
                         ngx_cached_http_time.len);

    b->last = ngx_cpymem(b->last, ngx_http_error_server_info_ip,
                         sizeof(ngx_http_error_server_info_ip) - 1);
    b->last = ngx_cpymem(b->last, client_ip.data,
                         client_ip.len);

    b->last = ngx_cpymem(b->last, ngx_http_error_server_info_server,
                         sizeof(ngx_http_error_server_info_server) - 1);
    b->last = ngx_cpymem(b->last, ngx_cycle->hostname.data,
                         ngx_cycle->hostname.len);

    b->last = ngx_cpymem(b->last, ngx_http_error_server_info_id,
                         sizeof(ngx_http_error_server_info_id) - 1);
    b->last = ngx_cpymem(b->last, request_id.data,
                         request_id.len);

    b->last = ngx_cpymem(b->last, ngx_http_error_server_info_tail,
                         sizeof(ngx_http_error_server_info_tail) - 1);

    return b;
}
#endif
