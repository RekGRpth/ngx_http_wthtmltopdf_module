#include <Wt/Render/WPdfRenderer.h>
#include "MyWPdfRenderer.h"

extern "C" {
    void MyWPdfRenderer_render(const char *html, HPDF_Doc pdf, HPDF_Page page) {
        Wt::Render::WPdfRenderer renderer(pdf, page);
        renderer.render(html);
    }
}