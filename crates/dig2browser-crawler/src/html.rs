use crate::{CanonicalUrl, MAX_DISCOVERED_LINKS_PER_COMPLETION, MAX_URL_BYTES};
use scraper::{Html, Selector};
use std::collections::HashSet;

const MAX_HTML_BYTES: usize = 16 * 1024 * 1024;

pub fn extract_links(base: &CanonicalUrl, html: &str) -> Vec<CanonicalUrl> {
    extract_links_bounded(base, html, MAX_DISCOVERED_LINKS_PER_COMPLETION)
}

pub fn extract_links_bounded(
    base: &CanonicalUrl,
    html: &str,
    limit: usize,
) -> Vec<CanonicalUrl> {
    let limit = limit.min(MAX_DISCOVERED_LINKS_PER_COMPLETION);
    if limit == 0 {
        return Vec::new();
    }

    let html = bounded_html(html);
    let document = Html::parse_document(html);
    let base_selector = Selector::parse("base[href]").expect("static base selector is valid");
    let link_selector = Selector::parse("a[href], area[href]")
        .expect("static crawl-link selector is valid");
    let effective_base = document
        .select(&base_selector)
        .find_map(|element| resolve_href(base, element.value().attr("href")?))
        .unwrap_or_else(|| base.clone());

    let mut seen = HashSet::with_capacity(limit.min(4_096));
    let mut links = Vec::with_capacity(limit.min(4_096));
    for element in document.select(&link_selector) {
        let Some(raw) = element.value().attr("href") else {
            continue;
        };
        let Some(link) = resolve_href(&effective_base, raw) else {
            continue;
        };
        if seen.insert(link.clone()) {
            links.push(link);
            if links.len() == limit {
                break;
            }
        }
    }
    links
}

fn resolve_href(base: &CanonicalUrl, raw: &str) -> Option<CanonicalUrl> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > MAX_URL_BYTES {
        return None;
    }
    base.resolve(raw).ok()
}

fn bounded_html(html: &str) -> &str {
    if html.len() <= MAX_HTML_BYTES {
        return html;
    }
    let mut end = MAX_HTML_BYTES;
    while !html.is_char_boundary(end) {
        end -= 1;
    }
    &html[..end]
}

#[cfg(test)]
mod tests {
    use super::{extract_links, extract_links_bounded};
    use crate::CanonicalUrl;

    #[test]
    fn extracts_resolves_and_deduplicates_anchor_links() {
        let base = CanonicalUrl::parse("https://example.com/dir/page").unwrap();
        let links = extract_links(
            &base,
            r#"<A HREF="../next?a=1&amp;b=2#one">first</A>
                <a href='../next?a=1&amp;b=2#two'>duplicate</a>
                <area href=/map>
                <a href="javascript:alert(1)">ignored</a>"#,
        );

        assert_eq!(links.len(), 2);
        assert_eq!(links[0].as_str(), "https://example.com/next?a=1&b=2");
        assert_eq!(links[1].as_str(), "https://example.com/map");
    }

    #[test]
    fn honors_base_and_ignores_markup_fakes() {
        let base = CanonicalUrl::parse("https://example.com/original/").unwrap();
        let links = extract_links_bounded(
            &base,
            r#"<!-- <a href="/comment-fake"> -->
                <script>const fake = '<a href="/script-fake">';</script>
                <div data-markup='<a href="/attribute-fake">'></div>
                <base href="https://assets.example.net/root/">
                <a href="one">one</a><a href="two">two</a>"#,
            1,
        );

        assert_eq!(links.len(), 1);
        assert_eq!(links[0].as_str(), "https://assets.example.net/root/one");
    }
}
