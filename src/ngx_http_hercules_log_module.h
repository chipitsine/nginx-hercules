#ifndef __NGX_HTTP_HERCULES
#define __NGX_HTTP_HERCULES
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <endian.h>
#include "libhercules.h"

typedef struct {
    size_t    size;
    char      message[];
} ngx_http_hercules_log_t;

typedef struct {
    ngx_buf_t*   buffer;
    ngx_event_t* event;
    ngx_pool_t*  pool;
    ngx_msec_t   flush;
} ngx_http_hercules_loc_conf_t;


static ngx_int_t ngx_http_hercules_handler(ngx_http_request_t* r);
static ngx_int_t ngx_http_hercules_postconf(ngx_conf_t* cf);
static void* ngx_http_hercules_create_loc_conf(ngx_conf_t* cf);
static char* ngx_http_hercules_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child);
static void ngx_http_hercules_flush_handler(ngx_event_t* ev);
static void ngx_http_hercules_flush_buffer(ngx_buf_t* buffer, ngx_log_t* log);
#endif