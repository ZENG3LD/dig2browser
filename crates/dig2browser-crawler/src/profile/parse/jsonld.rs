//! JSON-LD and microdata extractor.
//!
//! [`JsonLdExtractor`] provides static methods to parse structured data
//! embedded in HTML pages — either as `<script type="application/ld+json">`
//! blocks (JSON-LD) or as `itemscope`/`itemprop` attributes (microdata).

use scraper::{Html, Selector};

/// Extracts JSON-LD blocks and microdata from raw HTML.
#[derive(Debug, Default)]
pub struct JsonLdExtractor;

impl JsonLdExtractor {
    /// Extract all `<script type="application/ld+json">` blocks from `html`.
    ///
    /// Each block is parsed as a `serde_json::Value`. Arrays are flattened
    /// so the returned `Vec` always contains individual objects. Malformed
    /// blocks are silently skipped (a `tracing::debug` message is emitted).
    pub fn extract_jsonld(html: &str) -> Vec<serde_json::Value> {
        let document = Html::parse_document(html);
        // Safety: selector is a string literal and always valid.
        let selector =
            Selector::parse(r#"script[type="application/ld+json"]"#).expect("static selector");
        let mut results = Vec::new();

        for element in document.select(&selector) {
            let text: String = element.text().collect();
            let text = text.trim();
            if text.is_empty() {
                continue;
            }

            match serde_json::from_str::<serde_json::Value>(text) {
                Ok(serde_json::Value::Array(arr)) => results.extend(arr),
                Ok(obj @ serde_json::Value::Object(_)) => results.push(obj),
                Ok(_) => {}
                Err(e) => {
                    tracing::debug!(error = %e, "failed to parse JSON-LD block — skipping");
                }
            }
        }
        results
    }

    /// Extract microdata (`itemscope`/`itemprop`) from `html`.
    ///
    /// Only top-level `[itemscope]` elements are considered. Each is
    /// serialised to a JSON object whose keys are `itemprop` attribute values
    /// and whose `@type` key holds the short name extracted from `itemtype`.
    pub fn extract_microdata(html: &str) -> Vec<serde_json::Value> {
        let document = Html::parse_document(html);
        let scope_selector = Selector::parse("[itemscope]").expect("static selector");
        let prop_selector = Selector::parse("[itemprop]").expect("static selector");
        let mut results = Vec::new();

        for scope_el in document.select(&scope_selector) {
            let mut obj = serde_json::Map::new();

            if let Some(item_type) = scope_el.value().attr("itemtype") {
                let type_name = item_type.rsplit('/').next().unwrap_or(item_type);
                obj.insert(
                    "@type".to_owned(),
                    serde_json::Value::String(type_name.to_owned()),
                );
            }

            for prop_el in scope_el.select(&prop_selector) {
                if let Some(prop_name) = prop_el.value().attr("itemprop") {
                    let value = prop_el
                        .value()
                        .attr("content")
                        .or_else(|| prop_el.value().attr("href"))
                        .or_else(|| prop_el.value().attr("src"))
                        .map(|s| s.to_owned())
                        .unwrap_or_else(|| prop_el.text().collect::<String>().trim().to_owned());

                    if !value.is_empty() {
                        obj.insert(prop_name.to_owned(), serde_json::Value::String(value));
                    }
                }
            }

            if obj.len() > 1 {
                results.push(serde_json::Value::Object(obj));
            }
        }
        results
    }

    /// Filter a slice of JSON-LD objects by their `@type` field.
    pub fn filter_by_type<'a>(
        items: &'a [serde_json::Value],
        type_name: &str,
    ) -> Vec<&'a serde_json::Value> {
        items
            .iter()
            .filter(|item| {
                item.get("@type")
                    .and_then(|t| t.as_str())
                    .is_some_and(|t| t == type_name)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_product_jsonld() {
        let html = r#"
        <html><head>
            <script type="application/ld+json">
            {"@type":"Product","name":"Widget","sku":"W-001","offers":{"price":"1500","priceCurrency":"RUB"}}
            </script>
        </head><body></body></html>"#;

        let results = JsonLdExtractor::extract_jsonld(html);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["@type"], "Product");
        assert_eq!(results[0]["name"], "Widget");
        assert_eq!(results[0]["sku"], "W-001");
    }

    #[test]
    fn test_extract_jsonld_array() {
        let html = r#"<html><head>
            <script type="application/ld+json">
            [{"@type":"Product","name":"A"},{"@type":"Product","name":"B"}]
            </script>
        </head></html>"#;

        let results = JsonLdExtractor::extract_jsonld(html);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["name"], "A");
        assert_eq!(results[1]["name"], "B");
    }

    #[test]
    fn test_extract_multiple_blocks() {
        let html = r#"<html><head>
            <script type="application/ld+json">{"@type":"Product","name":"Widget"}</script>
            <script type="application/ld+json">{"@type":"BreadcrumbList","itemListElement":[]}</script>
        </head></html>"#;

        let results = JsonLdExtractor::extract_jsonld(html);
        assert_eq!(results.len(), 2);

        let products = JsonLdExtractor::filter_by_type(&results, "Product");
        assert_eq!(products.len(), 1);
        assert_eq!(products[0]["name"], "Widget");
    }

    #[test]
    fn test_malformed_block_skipped() {
        let html = r#"<html><head>
            <script type="application/ld+json">not valid json{</script>
            <script type="application/ld+json">{"@type":"Product","name":"OK"}</script>
        </head></html>"#;

        let results = JsonLdExtractor::extract_jsonld(html);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["name"], "OK");
    }

    #[test]
    fn test_extract_microdata() {
        let html = r#"
        <div itemscope itemtype="https://schema.org/Product">
            <meta itemprop="name" content="АТОЛ 77Ф">
            <meta itemprop="brand" content="АТОЛ">
            <img itemprop="image" src="/img/77f.jpg">
            <span itemprop="description">Кассовый аппарат</span>
        </div>"#;

        let results = JsonLdExtractor::extract_microdata(html);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["@type"], "Product");
        assert_eq!(results[0]["name"], "АТОЛ 77Ф");
        assert_eq!(results[0]["brand"], "АТОЛ");
        assert_eq!(results[0]["image"], "/img/77f.jpg");
        assert_eq!(results[0]["description"], "Кассовый аппарат");
    }

    #[test]
    fn test_filter_by_type() {
        let items = vec![
            serde_json::json!({"@type": "Product", "name": "A"}),
            serde_json::json!({"@type": "BreadcrumbList"}),
            serde_json::json!({"@type": "Product", "name": "B"}),
        ];

        let products = JsonLdExtractor::filter_by_type(&items, "Product");
        assert_eq!(products.len(), 2);
    }

    #[test]
    fn test_empty_page() {
        assert!(JsonLdExtractor::extract_jsonld("<html><body></body></html>").is_empty());
        assert!(JsonLdExtractor::extract_microdata("<html><body></body></html>").is_empty());
    }
}
