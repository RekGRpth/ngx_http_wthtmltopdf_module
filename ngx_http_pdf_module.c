#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "MyWPdfRenderer.h"

typedef struct {
    ngx_http_complex_value_t *url;
} ngx_http_pdf_loc_conf_t;

ngx_module_t ngx_http_pdf_module;

static void HPDF_STDCALL error_handler(HPDF_STATUS error_no, HPDF_STATUS detail_no, void *user_data) {
    ngx_log_t *log = user_data;
    ngx_log_error(NGX_LOG_ERR, log, 0, "libharu: error_no=%04X, detail_no=%d\n", (unsigned int) error_no, (int) detail_no);
}

static ngx_int_t ngx_http_pdf_handler(ngx_http_request_t *r) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_pdf_handler");
    if (!(r->method & NGX_HTTP_GET)) return NGX_HTTP_NOT_ALLOWED;
    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK && rc != NGX_AGAIN) return rc;
    HPDF_Doc pdf = HPDF_New(error_handler, r->connection->log);
    if (!pdf) return NGX_ERROR;
    rc = NGX_ERROR;
    if (HPDF_UseUTFEncodings(pdf) != HPDF_OK) goto err;
    HPDF_Page page = HPDF_AddPage(pdf);
    if (!page) goto err;
    if (HPDF_Page_SetSize(page, HPDF_PAGE_SIZE_A4, HPDF_PAGE_PORTRAIT) != HPDF_OK) goto err;
    MyWPdfRenderer_render(pdf, page, "<p style=\"background-color: #c11\">Hello, world !</p>");
    if (HPDF_SaveToStream(pdf) != HPDF_OK) goto err;
    HPDF_UINT32 size = HPDF_GetStreamSize(pdf);
    if (!size) goto err;
    HPDF_BYTE *buf = ngx_palloc(r->pool, size);
    HPDF_STATUS hs = HPDF_ReadFromStream(pdf, buf, &size);
    if (hs != HPDF_OK && hs != HPDF_STREAM_EOF) goto err;
    ngx_chain_t out = {.buf = &(ngx_buf_t){.pos = (u_char *)buf, .last = (u_char *)buf + size, .memory = 1, .last_buf = 1}, .next = NULL};
    ngx_str_set(&r->headers_out.content_type, "application/pdf");
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = size;
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only); else rc = ngx_http_output_filter(r, &out);
err:
    HPDF_Free(pdf);
    return rc;
}

static char *ngx_http_pdf_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_pdf_handler;
    return ngx_http_set_complex_value_slot(cf, cmd, conf);
}

static ngx_command_t ngx_http_pdf_commands[] = {
  { .name = ngx_string("pdf"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_http_pdf_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_pdf_loc_conf_t, url),
    .post = NULL },
    ngx_null_command
};

static void *ngx_http_pdf_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_pdf_loc_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_pdf_loc_conf_t));
    if (!conf) return NGX_CONF_ERROR;
    return conf;
}

static char *ngx_http_pdf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_pdf_loc_conf_t *prev = parent;
    ngx_http_pdf_loc_conf_t *conf = child;
    if (!conf->url) conf->url = prev->url;
    return NGX_CONF_OK;
}

static ngx_http_module_t ngx_http_pdf_module_ctx = {
    .preconfiguration = NULL,
    .postconfiguration = NULL,
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
