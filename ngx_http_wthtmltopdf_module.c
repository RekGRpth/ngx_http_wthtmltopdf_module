#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "MyWPdfRenderer.h"

typedef struct {
    ngx_http_complex_value_t *html;
} ngx_http_wthtmltopdf_loc_conf_t;

ngx_module_t ngx_http_wthtmltopdf_module;

static void HPDF_STDCALL error_handler(HPDF_STATUS error_no, HPDF_STATUS detail_no, void *user_data) {
    ngx_log_t *log = user_data;
    ngx_log_error(NGX_LOG_ERR, log, 0, "libharu: error_no=%04X, detail_no=%d\n", (unsigned int) error_no, (int) detail_no);
}

static ngx_int_t ngx_http_wthtmltopdf_handler(ngx_http_request_t *r) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_wthtmltopdf_handler");
    if (!(r->method & NGX_HTTP_GET)) return NGX_HTTP_NOT_ALLOWED;
    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK && rc != NGX_AGAIN) return rc;
    ngx_http_wthtmltopdf_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_wthtmltopdf_module);
    rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
    ngx_str_t value, out = {0, NULL};
    if (ngx_http_complex_value(r, conf->html, &value) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); goto ret; }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "html = %V", &value);
    HPDF_Doc pdf = HPDF_New(error_handler, r->connection->log);
    if (!pdf) goto ret;
    if (HPDF_SetCompressionMode(pdf, HPDF_COMP_ALL) != HPDF_OK) goto HPDF_Free;
    if (HPDF_UseUTFEncodings(pdf) != HPDF_OK) goto HPDF_Free;
    HPDF_Page page = HPDF_AddPage(pdf);
    if (!page) goto HPDF_Free;
    if (HPDF_Page_SetSize(page, HPDF_PAGE_SIZE_A4, HPDF_PAGE_PORTRAIT) != HPDF_OK) goto HPDF_Free;
    char *html = ngx_pcalloc(r->pool, value.len + 1);
    if (!html) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!html"); goto HPDF_Free; }
    ngx_memcpy(html, value.data, value.len);
    if (MyWPdfRenderer_render(r->connection->log, pdf, page, (const char *)html) != NGX_DONE) goto HPDF_Free;
    if (HPDF_SaveToStream(pdf) != HPDF_OK) goto HPDF_Free;
    HPDF_UINT32 len = HPDF_GetStreamSize(pdf);
    if (!len) goto HPDF_Free;
    out.data = ngx_palloc(r->pool, len);
    if (!out.data) goto HPDF_Free;
    switch (HPDF_ReadFromStream(pdf, (HPDF_BYTE *)out.data, &len)) {
        case HPDF_OK: break;
        case HPDF_STREAM_EOF: break;
        default: goto HPDF_Free;
    }
HPDF_Free:
    page = HPDF_GetCurrentPage(pdf);
    if (page) while (HPDF_Page_GetGStateDepth(page) > 1) HPDF_Page_GRestore(page);
    HPDF_Free(pdf);
    if (out.data) {
        ngx_chain_t ch = {.buf = &(ngx_buf_t){.pos = out.data, .last = out.data + len, .memory = 1, .last_buf = 1}, .next = NULL};
        ngx_str_set(&r->headers_out.content_type, "application/pdf");
        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = len;
        rc = ngx_http_send_header(r);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "rc = %i", rc);
        ngx_http_weak_etag(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only); else rc = ngx_http_output_filter(r, &ch);
    }
ret:
    return rc;
}

static char *ngx_http_wthtmltopdf_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_wthtmltopdf_handler;
    return ngx_http_set_complex_value_slot(cf, cmd, conf);
}

static ngx_command_t ngx_http_wthtmltopdf_commands[] = {
  { .name = ngx_string("wthtmltopdf"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_http_wthtmltopdf_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_wthtmltopdf_loc_conf_t, html),
    .post = NULL },
    ngx_null_command
};

static void *ngx_http_wthtmltopdf_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_wthtmltopdf_loc_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_wthtmltopdf_loc_conf_t));
    if (!conf) return NGX_CONF_ERROR;
    return conf;
}

static char *ngx_http_wthtmltopdf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_wthtmltopdf_loc_conf_t *prev = parent;
    ngx_http_wthtmltopdf_loc_conf_t *conf = child;
    if (!conf->html) conf->html = prev->html;
    return NGX_CONF_OK;
}

static ngx_http_module_t ngx_http_wthtmltopdf_module_ctx = {
    .preconfiguration = NULL,
    .postconfiguration = NULL,
    .create_main_conf = NULL,
    .init_main_conf = NULL,
    .create_srv_conf = NULL,
    .merge_srv_conf = NULL,
    .create_loc_conf = ngx_http_wthtmltopdf_create_loc_conf,
    .merge_loc_conf = ngx_http_wthtmltopdf_merge_loc_conf
};

ngx_module_t ngx_http_wthtmltopdf_module = {
    NGX_MODULE_V1,
    .ctx = &ngx_http_wthtmltopdf_module_ctx,
    .commands = ngx_http_wthtmltopdf_commands,
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
