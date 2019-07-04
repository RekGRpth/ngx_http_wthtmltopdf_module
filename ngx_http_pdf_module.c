#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "MyWPdfRenderer.h"

#define NGX_HTTP_HTML_START 0
#define NGX_HTTP_HTML_READ 1
#define NGX_HTTP_HTML_PROCESS 2
#define NGX_HTTP_HTML_PASS 3
#define NGX_HTTP_HTML_DONE 4

#define NGX_HTTP_HTML_BUFFERED 0x08

typedef struct {
    ngx_flag_t enable;
    size_t buffer_size;
} ngx_http_pdf_loc_conf_t;

typedef struct {
    size_t len;
    u_char *data;
    u_char *last;
    ngx_uint_t phase;
} ngx_http_pdf_ctx_t;

ngx_module_t ngx_http_pdf_module;

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

static ngx_command_t ngx_http_pdf_commands[] = {
  { .name = ngx_string("pdf"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_FLAG,
    .set = ngx_conf_set_flag_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_pdf_loc_conf_t, enable),
    .post = NULL },
  { .name = ngx_string("pdf_buffer_size"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_size_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_pdf_loc_conf_t, buffer_size),
    .post = NULL },
    ngx_null_command
};

static void *ngx_http_pdf_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_pdf_loc_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_pdf_loc_conf_t));
    if (!conf) return NGX_CONF_ERROR;
    conf->enable = NGX_CONF_UNSET;
    conf->buffer_size = NGX_CONF_UNSET_SIZE;
    return conf;
}

static char *ngx_http_pdf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_pdf_loc_conf_t *prev = parent;
    ngx_http_pdf_loc_conf_t *conf = child;
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size, (size_t)ngx_pagesize);
    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_pdf_header_filter(ngx_http_request_t *r) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "pdf header filter");
    if (r->headers_out.status == NGX_HTTP_NOT_MODIFIED) goto ngx_http_next_header_filter;
    ngx_http_pdf_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_pdf_module);
    if (ctx) { ngx_http_set_ctx(r, NULL, ngx_http_pdf_module); goto ngx_http_next_header_filter; }
    ngx_http_pdf_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_pdf_module);
    if (!conf->enable) goto ngx_http_next_header_filter;
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_pdf_ctx_t));
    if (!ctx) return NGX_ERROR;
    ngx_http_set_ctx(r, ctx, ngx_http_pdf_module);
    off_t len = r->headers_out.content_length_n;
    if (len != -1 && len > (off_t)conf->buffer_size) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "pdf filter: too big response: %O", len); return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE; }
    ctx->len = len == -1 ? conf->buffer_size : (size_t) len;
    if (r->headers_out.refresh) r->headers_out.refresh->hash = 0;
    r->main_filter_need_in_memory = 1;
    r->allow_ranges = 0;
    return NGX_OK;
ngx_http_next_header_filter:
    return ngx_http_next_header_filter(r);
}

static ngx_int_t ngx_http_pdf_html_read(ngx_http_request_t *r, ngx_chain_t *in) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "pdf html read");
    ngx_http_pdf_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_pdf_module);
    if (!ctx->data) {
        ctx->data = ngx_pcalloc(r->pool, ctx->len + 1);
        if (!ctx->data) return NGX_ERROR;
        ctx->last = ctx->data;
    }
    for (ngx_chain_t *cl = in; cl; cl = cl->next) {
        ngx_buf_t *b = cl->buf;
//        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_buf_in_memory = %s", ngx_buf_in_memory(b) ? "true" : "false");
        size_t size = ngx_buf_size(b);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "html size = %uz", size);
        size_t rest = ctx->data + ctx->len - ctx->last;
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "html rest = %uz", rest);
        if (size > rest) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "pdf filter: too big response"); return NGX_ERROR; }
//        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "b->pos = %s", b->pos);
        ctx->last = ngx_cpymem(ctx->last, b->pos, size);
//        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ctx->data = %s", ctx->data);
        if (b->last_buf) return NGX_OK;
    }
    r->connection->buffered |= NGX_HTTP_HTML_BUFFERED;
    return NGX_AGAIN;
}

static void HPDF_STDCALL error_handler(HPDF_STATUS error_no, HPDF_STATUS detail_no, void *user_data) {
    ngx_log_t *log = user_data;
    ngx_log_error(NGX_LOG_ERR, log, 0, "libharu: error_no=%04X, detail_no=%d\n", (unsigned int) error_no, (int) detail_no);
}

static ngx_buf_t *ngx_http_pdf_html_process(ngx_http_request_t *r) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "pdf html process");
    r->connection->buffered &= ~NGX_HTTP_HTML_BUFFERED;
    ngx_buf_t *out = NULL;
    ngx_http_pdf_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_pdf_module);
//    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ctx->data = %s", ctx->data);
    HPDF_Doc pdf = HPDF_New(error_handler, r->connection->log);
    if (!pdf) goto ret;
    if (HPDF_UseUTFEncodings(pdf) != HPDF_OK) goto HPDF_Free;
    HPDF_Page page = HPDF_AddPage(pdf);
    if (!page) goto HPDF_Free;
    if (HPDF_Page_SetSize(page, HPDF_PAGE_SIZE_A4, HPDF_PAGE_PORTRAIT) != HPDF_OK) goto HPDF_Free;
    if (MyWPdfRenderer_render(r->connection->log, pdf, page, (const char *)ctx->data) != NGX_DONE) goto HPDF_Free;
    if (HPDF_SaveToStream(pdf) != HPDF_OK) goto HPDF_Free;
    HPDF_UINT32 size = HPDF_GetStreamSize(pdf);
    if (!size) goto HPDF_Free;
    HPDF_BYTE *buf = ngx_palloc(r->pool, size);
    HPDF_STATUS hs = HPDF_ReadFromStream(pdf, buf, &size);
    if (hs != HPDF_OK && hs != HPDF_STREAM_EOF) goto HPDF_Free;
    out = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (!out) goto HPDF_Free;
    out->pos = (u_char *)buf;
    out->last = (u_char *)buf + size;
    out->memory = 1;
    out->last_buf = 1;
    r->headers_out.content_length_n = size;
    if (r->headers_out.content_length) r->headers_out.content_length->hash = 0;
    r->headers_out.content_length = NULL;
    ngx_http_weak_etag(r);
HPDF_Free:
    HPDF_Free(pdf);
ret:
    return out;
}

static ngx_int_t ngx_http_pdf_html_send(ngx_http_request_t *r, ngx_chain_t *in) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "pdf html send");
    ngx_int_t rc = ngx_http_next_header_filter(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) return NGX_ERROR;
    rc = ngx_http_next_body_filter(r, in);
    ngx_http_pdf_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_pdf_module);
    if (ctx->phase == NGX_HTTP_HTML_DONE) return (rc == NGX_OK) ? NGX_ERROR : rc;
    return rc;
}

static ngx_int_t ngx_http_pdf_body_filter(ngx_http_request_t *r, ngx_chain_t *in) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "pdf body filter");
    if (!in) goto ngx_http_next_body_filter;
    ngx_http_pdf_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_pdf_module);
    if (!ctx) goto ngx_http_next_body_filter;
    switch (ctx->phase) {
        case NGX_HTTP_HTML_START: {
            ngx_str_set(&r->headers_out.content_type, "application/pdf");
            r->headers_out.content_type_lowcase = NULL;
            ctx->phase = NGX_HTTP_HTML_READ;
        }
        /* fall through */
        case NGX_HTTP_HTML_READ: {
            switch (ngx_http_pdf_html_read(r, in)) {
                case NGX_AGAIN: return NGX_OK;
                case NGX_ERROR: goto ngx_http_filter_finalize_request;
            }
            ctx->phase = NGX_HTTP_HTML_PROCESS;
        }
        /* fall through */
        case NGX_HTTP_HTML_PROCESS: {
            ngx_chain_t out = {.buf = ngx_http_pdf_html_process(r), .next = NULL};
            if (!out.buf) goto ngx_http_filter_finalize_request;
            ctx->phase = NGX_HTTP_HTML_PASS;
            return ngx_http_pdf_html_send(r, &out);
        }
        case NGX_HTTP_HTML_PASS: goto ngx_http_next_body_filter;
        default: { /* NGX_HTTP_HTML_DONE */ 
            ngx_int_t rc = ngx_http_next_body_filter(r, NULL);
            return (rc == NGX_OK) ? NGX_ERROR : rc;
        }
    }
ngx_http_next_body_filter:
    return ngx_http_next_body_filter(r, in);
ngx_http_filter_finalize_request:
    return ngx_http_filter_finalize_request(r, &ngx_http_pdf_module, NGX_HTTP_UNSUPPORTED_MEDIA_TYPE);
}

static ngx_int_t ngx_http_pdf_postconfiguration(ngx_conf_t *cf) {
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_pdf_header_filter;
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_pdf_body_filter;
    return NGX_OK;
}

static ngx_http_module_t ngx_http_pdf_module_ctx = {
    .preconfiguration = NULL,
    .postconfiguration = ngx_http_pdf_postconfiguration,
    .create_main_conf = NULL,
    .init_main_conf = NULL,
    .create_srv_conf = NULL,
    .merge_srv_conf = NULL,
    .create_loc_conf = ngx_http_pdf_create_loc_conf,
    .merge_loc_conf = ngx_http_pdf_merge_loc_conf
};

ngx_module_t ngx_http_pdf_module = {
    NGX_MODULE_V1,
    .ctx = &ngx_http_pdf_module_ctx,
    .commands = ngx_http_pdf_commands,
    .type = NGX_HTTP_MODULE,
    .init_master = NULL,
    .init_module = NULL,
    .init_process = NULL,
    .init_thread = NULL,
    .exit_thread = NULL,
    .exit_process = NULL,
    .exit_master = NULL,
    NGX_MODULE_V1_PADDING
};
