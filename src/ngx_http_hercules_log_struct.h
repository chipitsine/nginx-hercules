#ifndef __NGX_HTTP_HERCULES_STRUCT
#define __NGX_HTTP_HERCULES_STRUCT
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/*typedef struct {
    ngx_buf_t*         buffer;
    ngx_array_t*       buckets_for_resend;
    ngx_event_t*       event;
    ngx_pool_t*        pool;
    ngx_msec_t         flush;
    int                socket;
    ngx_thread_pool_t* thread_pool;
} ngx_http_hercules_loc_conf_t;*/

typedef struct {
    ngx_buf_t*         buffer;
    ngx_array_t*       buckets_for_resend;
    ngx_event_t*       event;
    ngx_pool_t*        pool;
    ngx_msec_t         flush;
    int                socket;
    ngx_thread_pool_t* thread_pool;
} ngx_http_hercules_main_conf_t;

typedef struct {
    ngx_thread_task_t*            task;
    ngx_http_hercules_main_conf_t* conf;
    ngx_array_t*                  buckets;
} ngx_http_hercules_thread_sender_ctx_t;

typedef struct {
    ngx_buf_t*         buffer;
    uint8_t            counter;
    uint8_t            status;
} ngx_http_hercules_thread_sender_bucket_ctx_t;

#endif