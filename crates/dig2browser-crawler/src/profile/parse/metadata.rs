//! Page metadata extractor.
//!
//! [`MetadataExtractor`] extracts title, description, canonical URL, Open
//! Graph tags, and language from raw HTML without depending on any specific
//! domain schema.

use scraper::{Html, Selector};
use url::Url;

/// All metadata extracted from a single HTML page.
#[derive(Debug, Clone, Default)]
pub struct PageMetadata {
    pub title: Option<String>,
    pub description: Option<String>,
    /// The `<link rel="canonical">` URL, resolved against `base_url`.
    pub canonical_url: Option<Url>,
    /// `<html lang="…">` or `<meta http-equiv="Content-Language">`.
    pub language: Option<String>,
    /// Open Graph tags: key without `og:` prefix → value.
    pub og: std::collections::HashMap<String, String>,
    /// Twitter card tags: key without `twitter:` prefix → value.
    pub twitter: std::collections::HashMap<String, String>,
}

/// Stateless metadata extractor. All methods take `&self` for ergonomics;
/// the struct carries no state.
#[derive(Debug, Default)]
pub struct MetadataExtractor;

impl MetadataExtractor {
    pub fn new() -> Self {
        Self
    }

    /// Extract metadata from `html`, resolving relative URLs against
    /// `base_url` when provided.
    pub fn extract(&self, html: &str, base_url: Option<&Url>) -> PageMetadata {
        let document = Html::parse_document(html);
        PageMetadata {
            title: self.extract_title(&document),
            description: self.extract_description(&document),
            canonical_url: self.extract_canonical(&document, base_url),
            language: self.extract_language(&document),
            og: self.extract_prefixed_meta(&document, "og:"),
            twitter: self.extract_prefixed_meta(&document, "twitter:"),
        }
    }

    fn extract_title(&self, document: &Html) -> Option<String> {
        let sel = Selector::parse("title").expect("static selector");
        let text = document.select(&sel).next()?.text().collect::<String>();
        let trimmed = text.trim().to_owned();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    }

    fn extract_description(&self, document: &Html) -> Option<String> {
        let sel = Selector::parse("meta[name='description']").expect("static selector");
        let el = document.select(&sel).next()?;
        let content = el.value().attr("content")?;
        let trimmed = content.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    }

    fn extract_canonical(&self, document: &Html, base_url: Option<&Url>) -> Option<Url> {
        let sel = Selector::parse("link[rel='canonical']").expect("static selector");
        let el = document.select(&sel).next()?;
        let href = el.value().attr("href")?;

        Url::parse(href)
            .ok()
            .or_else(|| base_url.and_then(|base| base.join(href).ok()))
    }

    fn extract_language(&self, document: &Html) -> Option<String> {
        let html_sel = Selector::parse("html[lang]").expect("static selector");
        if let Some(el) = document.select(&html_sel).next() {
            if let Some(lang) = el.value().attr("lang") {
                let lang = lang.trim();
                if !lang.is_empty() {
                    return Some(lang.to_owned());
                }
            }
        }
        let meta_sel =
            Selector::parse("meta[http-equiv='Content-Language']").expect("static selector");
        if let Some(el) = document.select(&meta_sel).next() {
            if let Some(content) = el.value().attr("content") {
                let lang = content.trim();
                if !lang.is_empty() {
                    return Some(lang.to_owned());
                }
            }
        }
        None
    }

    /// Collect all `<meta property="PREFIX:*" content="…">` tags into a map
    /// with the prefix stripped from the key.
    fn extract_prefixed_meta(
        &self,
        document: &Html,
        prefix: &str,
    ) -> std::collections::HashMap<String, String> {
        let mut map = std::collections::HashMap::new();

        let sel_property_str = "meta[property]".to_owned();
        let sel_name_str = "meta[name]".to_owned();
        let candidates: &[(&str, &str)] =
            &[("property", &sel_property_str), ("name", &sel_name_str)];

        for (attr, sel_str) in candidates {
            if let Ok(sel) = Selector::parse(sel_str) {
                for el in document.select(&sel) {
                    if let Some(prop) = el.value().attr(attr) {
                        if let Some(key) = prop.strip_prefix(prefix) {
                            if let Some(content) = el.value().attr("content") {
                                let content = content.trim();
                                if !content.is_empty() {
                                    map.insert(key.to_owned(), content.to_owned());
                                }
                            }
                        }
                    }
                }
            }
        }
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_title_and_description() {
        let html = r#"
        <html><head>
            <title>  Hello World  </title>
            <meta name="description" content="A test page">
        </head><body></body></html>"#;

        let meta = MetadataExtractor::new().extract(html, None);
        assert_eq!(meta.title.as_deref(), Some("Hello World"));
        assert_eq!(meta.description.as_deref(), Some("A test page"));
    }

    #[test]
    fn test_canonical_absolute() {
        let html = r#"<html><head>
            <link rel="canonical" href="https://example.com/page/">
        </head></html>"#;

        let meta = MetadataExtractor::new().extract(html, None);
        assert_eq!(
            meta.canonical_url.as_ref().map(|u| u.as_str()),
            Some("https://example.com/page/")
        );
    }

    #[test]
    fn test_canonical_relative_resolved() {
        let html = r#"<html><head>
            <link rel="canonical" href="/page/">
        </head></html>"#;

        let base = Url::parse("https://example.com").unwrap();
        let meta = MetadataExtractor::new().extract(html, Some(&base));
        assert_eq!(
            meta.canonical_url.as_ref().map(|u| u.as_str()),
            Some("https://example.com/page/")
        );
    }

    #[test]
    fn test_language_from_html_tag() {
        let html = r#"<html lang="ru"><head></head><body></body></html>"#;
        let meta = MetadataExtractor::new().extract(html, None);
        assert_eq!(meta.language.as_deref(), Some("ru"));
    }

    #[test]
    fn test_language_from_meta() {
        let html = r#"<html><head>
            <meta http-equiv="Content-Language" content="en-US">
        </head></html>"#;
        let meta = MetadataExtractor::new().extract(html, None);
        assert_eq!(meta.language.as_deref(), Some("en-US"));
    }

    #[test]
    fn test_og_tags() {
        let html = r#"<html><head>
            <meta property="og:title" content="OG Title">
            <meta property="og:description" content="OG Desc">
            <meta property="og:image" content="https://example.com/img.jpg">
            <meta property="og:type" content="website">
        </head></html>"#;

        let meta = MetadataExtractor::new().extract(html, None);
        assert_eq!(meta.og.get("title").map(|s| s.as_str()), Some("OG Title"));
        assert_eq!(
            meta.og.get("description").map(|s| s.as_str()),
            Some("OG Desc")
        );
        assert_eq!(
            meta.og.get("image").map(|s| s.as_str()),
            Some("https://example.com/img.jpg")
        );
        assert_eq!(meta.og.get("type").map(|s| s.as_str()), Some("website"));
    }

    #[test]
    fn test_twitter_tags() {
        let html = r#"<html><head>
            <meta name="twitter:card" content="summary_large_image">
            <meta name="twitter:title" content="Twitter Title">
        </head></html>"#;

        let meta = MetadataExtractor::new().extract(html, None);
        assert_eq!(
            meta.twitter.get("card").map(|s| s.as_str()),
            Some("summary_large_image")
        );
        assert_eq!(
            meta.twitter.get("title").map(|s| s.as_str()),
            Some("Twitter Title")
        );
    }

    #[test]
    fn test_empty_page() {
        let meta = MetadataExtractor::new().extract("<html></html>", None);
        assert!(meta.title.is_none());
        assert!(meta.description.is_none());
        assert!(meta.canonical_url.is_none());
        assert!(meta.language.is_none());
        assert!(meta.og.is_empty());
        assert!(meta.twitter.is_empty());
    }
}
