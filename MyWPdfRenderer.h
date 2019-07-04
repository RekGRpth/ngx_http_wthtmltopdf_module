#ifndef __MYWPDFRENDERER_HPP
#define __MYWPDFRENDERER_HPP

#ifdef __cplusplus
extern "C" {
#endif

#include <hpdf.h>
#include <ngx_core.h>

ngx_int_t MyWPdfRenderer_render(ngx_log_t *log, HPDF_Doc pdf, HPDF_Page page, const char *html);

#ifdef __cplusplus
}
#endif
#endif