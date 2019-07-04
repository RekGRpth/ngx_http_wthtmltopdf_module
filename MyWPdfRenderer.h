#ifndef __MYWPDFRENDERER_HPP
#define __MYWPDFRENDERER_HPP

#ifdef __cplusplus
extern "C" {
#endif

#include <hpdf.h>

void MyWPdfRenderer_render(HPDF_Doc pdf, HPDF_Page page, const char *html);

#ifdef __cplusplus
}
#endif
#endif