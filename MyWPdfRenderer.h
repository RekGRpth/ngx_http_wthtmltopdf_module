#ifndef __MYWPDFRENDERER_HPP
#define __MYWPDFRENDERER_HPP

#ifdef __cplusplus
extern "C" {
#endif

#include <hpdf.h>

//typedef struct MyWPdfRenderer MyWPdfRenderer;

void MyWPdfRenderer_render(const char *html, HPDF_Doc pdf, HPDF_Page page);

/*MyWPdfRenderer *new_MyWPdfRenderer();

void MyWPdfRenderer_int_set(MyWPdfRenderer* v, int i);

int MyWPdfRenderer_int_get(MyWPdfRenderer* v);

void delete_MyWPdfRenderer(MyWPdfRenderer* v);*/

#ifdef __cplusplus
}
#endif
#endif