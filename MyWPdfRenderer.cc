#include <Wt/Render/WPdfRenderer.h>
#include "MyWPdfRenderer.h"

namespace Wt { namespace rapidxml {
class parse_error: public std::exception {
public:
    parse_error(const char *what, void *location) : m_what(what), m_where(location) { }
    virtual const char *what() const throw() {
        return m_what;
    }
    template<class Ch> Ch *where() const {
        return reinterpret_cast<Ch *>(m_where);
    }
private:
    const char *m_what;
    void *m_where;
};
}}

extern "C" {
    ngx_int_t MyWPdfRenderer_render(ngx_log_t *log, HPDF_Doc pdf, HPDF_Page page, const char *html) {
        try {
            Wt::Render::WPdfRenderer renderer(pdf, page);
            renderer.setMargin(2.54);
            renderer.setDpi(96);
            renderer.render(html);
            return NGX_DONE;
        } catch (const Wt::rapidxml::parse_error &e) {
            ngx_log_error(NGX_LOG_ERR, log, 0, "wt exception: what = %s, where = %s,", e.what(), e.where<char>());
        } catch (const std::exception &e) {
            ngx_log_error(NGX_LOG_ERR, log, 0, "wt exception: what = %s,", e.what());
        } catch (...) {
            ngx_log_error(NGX_LOG_ERR, log, 0, "wt exception,");
        }
        return NGX_ERROR;
    }
}