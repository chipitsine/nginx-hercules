#include "ngx_http_hercules_log_module.h"


static ngx_http_module_t  ngx_http_hercules_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_hercules_postconf,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_hercules_create_loc_conf,     /* create location configuration */
    ngx_http_hercules_merge_loc_conf       /* merge location configuration */
};


ngx_module_t  ngx_http_hercules_module = {
    NGX_MODULE_V1,
    &ngx_http_hercules_module_ctx,         /* module context */
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

static ngx_int_t ngx_http_hercules_handler(ngx_http_request_t *r){

    ngx_http_hercules_loc_conf_t* lmcf = ngx_http_get_module_loc_conf(r, ngx_http_hercules_module);

    ngx_log_error(NGX_LOG_INFO,r->connection->log, 0,
                   "ngx_http_hercules_handler");
    
    uint8_t* uuid = malloc(sizeof(uint8_t) * 16);
    generate_uuid_v4(uuid);
    uint64_t timestamp = generate_current_timestamp();
    Event* event = event_create(0x01, timestamp, uuid);

    size_t* event_binary_size = ngx_palloc(r->pool, sizeof(size_t));
    char* event_binary = event_to_bin(event, event_binary_size);

    event_free(event);

    char stream_name[5] = "test";
    uint8_t stream_size = strlen(stream_name);

    size_t message_length = sizeof(uint32_t) + sizeof(uint8_t) + *event_binary_size + stream_size;
    uint32_t be_event_size = htobe32((uint32_t) *event_binary_size);
    
    ngx_log_error(NGX_LOG_INFO,r->connection->log, 0,
                   "buffer size: %d", lmcf->buffer->end - lmcf->buffer->pos);
    
    if((size_t) (lmcf->buffer->end - lmcf->buffer->pos) < message_length){
        ngx_http_hercules_flush_buffer(lmcf->buffer, r->connection->log);
        if(lmcf->event->timer_set){
            ngx_event_del_timer(lmcf->event);
        }
    }

    u_char* pos = lmcf->buffer->pos;
    ((ngx_http_hercules_log_t*) pos)->size = message_length;
    pos = (u_char*) ((ngx_http_hercules_log_t*) pos)->message;

    *pos++ = (uint8_t) (be_event_size  & 0x000000FF);
    *pos++ = (uint8_t) ((be_event_size & 0x0000FF00) >> 8);
    *pos++ = (uint8_t) ((be_event_size & 0x00FF0000) >> 16);
    *pos++ = (uint8_t) ((be_event_size & 0xFF000000) >> 24);
    *pos++ = stream_size;
    ngx_memcpy(pos, event_binary, *event_binary_size);
    pos += *event_binary_size;
    ngx_memcpy(pos, stream_name, stream_size);
    pos += stream_size;
    lmcf->buffer->pos = pos;

    ngx_pfree(r->pool, event_binary_size);
    ngx_free(event_binary);

    lmcf->event->log = r->connection->log;
    if(!lmcf->event->timer_set){
        ngx_event_add_timer(lmcf->event, lmcf->flush);
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_hercules_postconf(ngx_conf_t *cf){
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_handler_pt        *h;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_hercules_handler;

    return NGX_OK;
}

static void* ngx_http_hercules_create_loc_conf(ngx_conf_t* cf){
    ngx_http_hercules_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_hercules_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->buffer = ngx_create_temp_buf(cf->pool, 1024 * 1024 * 8);
    if (conf->buffer == NULL){
        return NULL;
    }

    conf->flush = 10 * 1000; /* 10s */
    conf->event = ngx_pcalloc(cf->pool, sizeof(ngx_event_t));
    if(conf->event == NULL){
        return NULL;
    }
    conf->event->cancelable = 1;
    conf->event->handler = ngx_http_hercules_flush_handler;
    conf->event->data = conf->buffer;
    conf->event->log = &cf->cycle->new_log;

    conf->pool = cf->pool;

    return conf;
}

static char* ngx_http_hercules_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child){
    ngx_http_hercules_loc_conf_t* prev = parent;
    ngx_http_hercules_loc_conf_t* conf = child;

    if(conf->buffer == NULL){
        conf->buffer = prev->buffer;
        conf->event = prev->event;
        conf->flush = prev->flush;
    }

    return NGX_CONF_OK;
}

static void ngx_http_hercules_flush_buffer(ngx_buf_t* buffer, ngx_log_t* log){
    u_char* pos = buffer->start;
    size_t count = 0;
    while(buffer->pos > pos){
        ngx_http_hercules_log_t* log_event = (ngx_http_hercules_log_t*) pos;
        
        //

        count++;
        pos += sizeof(ngx_http_hercules_log_t) + log_event->size;
    }
    ngx_log_error(NGX_LOG_INFO, log, 0, "FLushed %d messages", count);
    buffer->pos = buffer->start;
}

static void ngx_http_hercules_flush_handler(ngx_event_t* ev){
    ngx_log_error(NGX_LOG_INFO, ev->log, 0, "flush_handler");
    ngx_buf_t* buffer = (ngx_buf_t*) ev->data;
    ngx_http_hercules_flush_buffer(buffer, ev->log);
}