#include <Wt/Render/WPdfRenderer.h>
#include "MyWPdfRenderer.h"

extern "C" {
    void MyWPdfRenderer_render(HPDF_Doc pdf, HPDF_Page page, const char *html) {
        Wt::Render::WPdfRenderer(pdf, page).render(html);
    }
}