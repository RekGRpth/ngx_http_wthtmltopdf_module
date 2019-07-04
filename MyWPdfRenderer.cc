#include <Wt/Render/WPdfRenderer.h>
#include "MyWPdfRenderer.h"

extern "C" {
    ngx_int_t MyWPdfRenderer_render(ngx_log_t *log, HPDF_Doc pdf, HPDF_Page page, const char *html) {
        try {
            Wt::Render::WPdfRenderer(pdf, page).render(html);
            return NGX_OK;
        } catch (const std::exception &e) {
            ngx_log_error(NGX_LOG_ERR, log, 0, "libharu: %s", e.what());
        }
        return NGX_ERROR;
    }
}