#include <Wt/Render/WPdfRenderer.h>
#include "MyWPdfRenderer.h"

extern "C" {
    void MyWPdfRenderer_render(const char *html, HPDF_Doc pdf, HPDF_Page page) {
        Wt::Render::WPdfRenderer renderer(pdf, page);
        renderer.render(html);
    }

/*    MyWPdfRenderer* new_MyWPdfRenderer() {
        return new MyWPdfRenderer();
    }

    void MyWPdfRenderer_int_set(MyWPdfRenderer* v, int i) {
        v->int_set(i);
    }

    int MyWPdfRenderer_int_get(MyWPdfRenderer* v) {
        return v->int_get();
    }

    void delete_MyWPdfRenderer(MyWPdfRenderer* v) {
        delete v;
    }*/
}