#ifndef __MYWPDFRENDERER_HPP
#define __MYWPDFRENDERER_HPP

#ifdef __cplusplus
extern "C" {
#endif

#include <hpdf.h>

void MyWPdfRenderer_render(const char *html, HPDF_Doc pdf, HPDF_Page page);

#ifdef __cplusplus
}
#endif
#endif