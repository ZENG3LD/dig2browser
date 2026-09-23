//! CSS selector-based item extractor — the fast path that runs without an
//! agent once selectors have been learned.
//!
//! [`SelectorExtractor`] takes a [`SiteProfile`] (container selector + field
//! configs) and raw HTML, and returns a `Vec<serde_json::Value>` where each
//! element is one extracted record.

use crate::profile::types::{ExtractMode, FieldConfig, SiteProfile, Transform};
use regex::Regex;
use scraper::{ElementRef, Html, Selector};

/// Generic CSS-selector extractor. Works with any [`SiteProfile`] — there is
/// no domain-specific logic here.
#[derive(Debug, Default)]
pub struct SelectorExtractor;

impl SelectorExtractor {
    pub fn new() -> Self {
        Self
    }

    /// Extract all items from `html` according to `profile`.
    ///
    /// Returns an empty `Vec` (and emits a `tracing::warn`) if the container
    /// selector is invalid. Invalid per-field selectors are silently skipped.
    pub fn extract(&self, html: &str, profile: &SiteProfile) -> Vec<serde_json::Value> {
        let document = Html::parse_document(html);

        let container_sel = match Selector::parse(&profile.container_selector) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    selector = %profile.container_selector,
                    error = ?e,
                    "invalid container_selector — returning empty result"
                );
                return Vec::new();
            }
        };

        let mut records = Vec::new();
        for container in document.select(&container_sel) {
            let mut obj = serde_json::Map::new();

            for field in &profile.fields {
                if let Some(value) = self.extract_field(&container, field) {
                    obj.insert(field.name.clone(), serde_json::Value::String(value));
                }
            }

            if !obj.is_empty() {
                records.push(serde_json::Value::Object(obj));
            }
        }

        records
    }

    fn extract_field(&self, container: &ElementRef<'_>, field: &FieldConfig) -> Option<String> {
        let sel = Selector::parse(&field.selector)
            .map_err(|e| {
                tracing::debug!(
                    field = %field.name,
                    selector = %field.selector,
                    error = ?e,
                    "invalid field selector — skipping"
                );
            })
            .ok()?;

        let el = container.select(&sel).next()?;

        let raw = match &field.extract {
            ExtractMode::Text => el.text().collect::<String>().trim().to_owned(),
            ExtractMode::Attribute(attr) => el.value().attr(attr.as_str())?.to_owned(),
            ExtractMode::Html => el.inner_html(),
            ExtractMode::OuterHtml => el.html(),
        };

        let prefixed = match &field.prefix {
            Some(prefix) if !raw.starts_with("http://") && !raw.starts_with("https://") => {
                format!("{prefix}{raw}")
            }
            _ => raw,
        };

        let transformed = match &field.transform {
            None => prefixed,
            Some(t) => apply_transform(&prefixed, t)?,
        };

        if transformed.is_empty() {
            None
        } else {
            Some(transformed)
        }
    }
}

fn apply_transform(value: &str, transform: &Transform) -> Option<String> {
    match transform {
        Transform::Trim => Some(value.trim().to_owned()),
        Transform::Lowercase => Some(value.to_lowercase()),
        Transform::Uppercase => Some(value.to_uppercase()),
        Transform::Regex(pattern) => {
            let re = Regex::new(pattern)
                .map_err(|e| tracing::warn!(pattern = %pattern, error = ?e, "invalid regex in Transform::Regex"))
                .ok()?;
            let caps = re.captures(value)?;
            caps.get(1).map(|m| m.as_str().to_owned())
        }
        Transform::Replace(from, to) => Some(value.replace(from.as_str(), to.as_str())),
        Transform::ParseNumber => {
            // Strip everything that isn't a digit, dot, comma, or minus sign,
            // then normalise comma -> dot so "1 500,00 руб." -> "1500.00".
            // A trailing separator can survive the filter when it comes from
            // unrelated punctuation after the number (e.g. the "." that ends
            // an abbreviation like "руб."), which would otherwise leave an
            // invalid trailing "." or "," that fails to parse — drop it.
            let mut digits_only: String = value
                .chars()
                .filter(|c| c.is_ascii_digit() || *c == '.' || *c == ',' || *c == '-')
                .collect();
            while matches!(digits_only.chars().last(), Some('.') | Some(',')) {
                digits_only.pop();
            }
            let normalised = digits_only.replace(',', ".");
            normalised.parse::<f64>().ok().map(|_| normalised)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_profile(container: &str, fields: Vec<FieldConfig>) -> SiteProfile {
        SiteProfile {
            domain: "example.com".to_owned(),
            container_selector: container.to_owned(),
            fields,
            pagination: None,
            requires_browser: false,
            confidence: 1.0,
            validated: true,
            created_at: Utc::now(),
            last_used_at: Utc::now(),
            extraction_mode: crate::profile::types::ExtractionMode::default(),
        }
    }

    fn text_field(name: &str, selector: &str) -> FieldConfig {
        FieldConfig {
            name: name.to_owned(),
            selector: selector.to_owned(),
            extract: ExtractMode::Text,
            prefix: None,
            transform: None,
        }
    }

    fn attr_field(name: &str, selector: &str, attr: &str) -> FieldConfig {
        FieldConfig {
            name: name.to_owned(),
            selector: selector.to_owned(),
            extract: ExtractMode::Attribute(attr.to_owned()),
            prefix: None,
            transform: None,
        }
    }

    #[test]
    fn test_basic_extraction() {
        let html = r#"
            <html><body>
                <div class="product">
                    <h2 class="name">Widget A</h2>
                    <span class="price">1 500 руб.</span>
                    <a href="/catalog/a/">Link</a>
                </div>
                <div class="product">
                    <h2 class="name">Widget B</h2>
                    <span class="price">2 300 руб.</span>
                    <a href="/catalog/b/">Link</a>
                </div>
            </body></html>
        "#;

        let profile = make_profile(
            "div.product",
            vec![
                text_field("name", "h2.name"),
                text_field("price", "span.price"),
                FieldConfig {
                    name: "url".to_owned(),
                    selector: "a[href]".to_owned(),
                    extract: ExtractMode::Attribute("href".to_owned()),
                    prefix: Some("https://example.com".to_owned()),
                    transform: None,
                },
            ],
        );

        let records = SelectorExtractor::new().extract(html, &profile);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["name"], "Widget A");
        assert_eq!(records[0]["price"], "1 500 руб.");
        assert_eq!(records[0]["url"], "https://example.com/catalog/a/");
        assert_eq!(records[1]["name"], "Widget B");
    }

    #[test]
    fn test_absolute_url_not_prefixed() {
        let html = r#"<div class="item"><a href="https://other.com/page">Link</a></div>"#;
        let profile = make_profile(
            "div.item",
            vec![FieldConfig {
                name: "url".to_owned(),
                selector: "a".to_owned(),
                extract: ExtractMode::Attribute("href".to_owned()),
                prefix: Some("https://example.com".to_owned()),
                transform: None,
            }],
        );

        let records = SelectorExtractor::new().extract(html, &profile);
        assert_eq!(records[0]["url"], "https://other.com/page");
    }

    #[test]
    fn test_invalid_container_selector_returns_empty() {
        let profile = make_profile("div[invalid", vec![text_field("name", "h2")]);
        let records = SelectorExtractor::new().extract("<html></html>", &profile);
        assert!(records.is_empty());
    }

    #[test]
    fn test_transform_parse_number() {
        let html = r#"<div class="item"><span class="price">1 500,99 руб.</span></div>"#;
        let profile = make_profile(
            "div.item",
            vec![FieldConfig {
                name: "price".to_owned(),
                selector: "span.price".to_owned(),
                extract: ExtractMode::Text,
                prefix: None,
                transform: Some(Transform::ParseNumber),
            }],
        );

        let records = SelectorExtractor::new().extract(html, &profile);
        assert_eq!(records[0]["price"], "1500.99");
    }

    #[test]
    fn test_transform_regex() {
        let html = r#"<div class="item"><span>Артикул: XY-1234</span></div>"#;
        let profile = make_profile(
            "div.item",
            vec![FieldConfig {
                name: "sku".to_owned(),
                selector: "span".to_owned(),
                extract: ExtractMode::Text,
                prefix: None,
                transform: Some(Transform::Regex(r"Артикул:\s*(\S+)".to_owned())),
            }],
        );

        let records = SelectorExtractor::new().extract(html, &profile);
        assert_eq!(records[0]["sku"], "XY-1234");
    }

    #[test]
    fn test_transform_replace() {
        let html = r#"<div class="item"><span>Price: $42.00</span></div>"#;
        let profile = make_profile(
            "div.item",
            vec![FieldConfig {
                name: "price".to_owned(),
                selector: "span".to_owned(),
                extract: ExtractMode::Text,
                prefix: None,
                transform: Some(Transform::Replace("Price: ".to_owned(), "".to_owned())),
            }],
        );

        let records = SelectorExtractor::new().extract(html, &profile);
        assert_eq!(records[0]["price"], "$42.00");
    }

    #[test]
    fn test_inner_html_extraction() {
        let html = r#"<div class="item"><div class="desc"><b>Bold</b> text</div></div>"#;
        let profile = make_profile(
            "div.item",
            vec![FieldConfig {
                name: "desc".to_owned(),
                selector: "div.desc".to_owned(),
                extract: ExtractMode::Html,
                prefix: None,
                transform: None,
            }],
        );

        let records = SelectorExtractor::new().extract(html, &profile);
        assert!(records[0]["desc"].as_str().unwrap().contains("<b>Bold</b>"));
    }

    #[test]
    fn test_empty_page_returns_empty() {
        let profile = make_profile("div.product", vec![text_field("name", "h2")]);
        let records = SelectorExtractor::new().extract("<html><body></body></html>", &profile);
        assert!(records.is_empty());
    }

    #[test]
    fn test_attr_field() {
        let html = r#"<ul><li><img src="/img/a.jpg" alt="A"></li></ul>"#;
        let profile = make_profile("li", vec![attr_field("img", "img", "src")]);
        let records = SelectorExtractor::new().extract(html, &profile);
        assert_eq!(records[0]["img"], "/img/a.jpg");
    }
}
