//! Declarative output-shaping extractor engine (Phase C, axis 7).
//!
//! [`shape`] projects a captured HTML document onto a consumer-declared
//! [`dig2browser_protocol::shape::OutputSchema`], returning typed
//! [`dig2browser_protocol::shape::Row`]s — no consumer-side HTML parsing.
//! Pure and synchronous: no browser, no network, no filesystem access. See
//! `docs/dig2browser/plans/phase-c-declarative-output-shaping.md` (signed)
//! for the design and `docs/dig2browser/audits/html-parse-crate-supply-chain-2026-07-24.md`
//! for the `scraper` dependency decision this crate implements.
//!
//! `Extractor::Regex` is supported: it is matched against the row scope's
//! whole text (the item element's text for `ItemScope`, the document's text
//! for `PageLevel`), returning the declared numbered capture group. See
//! `docs/dig2browser/audits/regex-crate-supply-chain-2026-07-24.md` for the
//! `regex` dependency decision. `Extractor::Json` remains **deferred** to a
//! later slice — a schema that declares one fails closed with
//! [`ShapeError::UnsupportedExtractor`], never a silent null.

mod coerce;
mod extract;

use dig2browser_protocol::shape::{
    Cardinality, Column, ColumnType, CssPick, Extractor, MetaField, OnError, OutputSchema, Row,
    Value,
};
use dig2browser_protocol::ProtocolError;
use scraper::{Html, Selector};

use coerce::coerce;
use extract::{resolve_css, resolve_meta, resolve_regex, Extracted, RowScope};

/// Capture metadata a schema's [`dig2browser_protocol::shape::Extractor::Meta`]
/// columns read from. Only `http_status` is ever an extraction-miss (the
/// other fields are plain owned data, always present even if empty).
#[derive(Debug, Clone, Default)]
pub struct CaptureMeta {
    pub url: String,
    pub final_url: String,
    pub http_status: Option<u16>,
    pub title: String,
    pub ready_state: String,
    pub captured_at: i64,
    pub source_id: String,
}

/// Failure modes for [`shape`].
#[derive(Debug)]
pub enum ShapeError {
    /// A schema-declared CSS selector (row-scope root or a column's `Css`
    /// selector) failed to parse.
    InvalidSelector(String),
    /// A schema-declared `Regex` column's pattern failed to compile (invalid
    /// syntax, or rejected by `regex::Regex`'s always-on compiled-size
    /// limit). Caught once at schema-compile time, before any row scope is
    /// visited — mirrors [`Self::InvalidSelector`].
    InvalidRegex(String),
    /// `Json` extractors are deferred to a later slice; a schema that
    /// declares one fails closed here rather than emitting a silent null
    /// cell. Carries `"json"`.
    UnsupportedExtractor(&'static str),
    /// Reserved for a direct (non-`OnError`-gated) coercion failure path.
    /// Not constructed by `shape()` today: every coercion failure this
    /// engine can produce is an extraction-miss-equivalent and is routed
    /// through the owning column's `OnError` policy (`Null` / `DropRow` /
    /// `Fail` — see [`Self::RowFailed`] for the `Fail` case) per the
    /// signed design's rule 5, not surfaced as a standalone error variant.
    Coercion { column: String, detail: String },
    /// A bound from `dig2browser-protocol` (e.g. `OutputSchema::validate`,
    /// `Row::new`) rejected something.
    Protocol(ProtocolError),
    /// A column with `OnError::Fail` hit an extraction miss or a coercion
    /// failure. Carries the failing column's name. (The design sketch names
    /// this `RowFailed(&'static str)`; a column name is a schema-declared
    /// runtime `String` — not `'static` — so this carries an owned
    /// `String` instead.)
    RowFailed(String),
}

impl std::fmt::Display for ShapeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSelector(detail) => write!(formatter, "invalid CSS selector: {detail}"),
            Self::InvalidRegex(detail) => write!(formatter, "invalid regex: {detail}"),
            Self::UnsupportedExtractor(kind) => {
                write!(formatter, "unsupported extractor `{kind}` (deferred to a later slice)")
            }
            Self::Coercion { column, detail } => {
                write!(formatter, "coercion failed for column `{column}`: {detail}")
            }
            Self::Protocol(error) => write!(formatter, "protocol error: {error}"),
            Self::RowFailed(column) => {
                write!(formatter, "row failed: column `{column}` (OnError::Fail)")
            }
        }
    }
}

impl std::error::Error for ShapeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            _ => None,
        }
    }
}

/// A column's extraction rule after selector/pattern compilation, so an
/// invalid CSS selector, an invalid regex pattern, or a deferred `Json`
/// extractor is caught once for the whole schema, before any row scope is
/// visited.
enum CompiledPlan {
    Meta(MetaField),
    Css { selector: Selector, pick: CssPick },
    Regex { regex: regex::Regex, group: u32 },
    Const(Value),
}

struct CompiledColumn {
    name: String,
    ty: ColumnType,
    on_error: OnError,
    plan: CompiledPlan,
}

/// Project `html` onto `schema`, returning the shaped rows in document
/// order. `html` is decoded as UTF-8 (lossy — invalid byte sequences are
/// replaced, never rejected) before parsing.
pub fn shape(html: &[u8], meta: &CaptureMeta, schema: &OutputSchema) -> Result<Vec<Row>, ShapeError> {
    schema.validate().map_err(ShapeError::Protocol)?;

    let text = String::from_utf8_lossy(html);
    let document = Html::parse_document(&text);
    let plan = compile_schema(schema)?;

    let mut rows = Vec::new();
    match schema.cardinality() {
        Cardinality::PageLevel => {
            let scope = RowScope::Document(&document);
            if let Some(row) = build_row(&plan, &scope, meta)? {
                rows.push(row);
            }
        }
        Cardinality::ItemScope(root_selector) => {
            let selector = Selector::parse(root_selector).map_err(|error| {
                ShapeError::InvalidSelector(format!("row scope `{root_selector}`: {error:?}"))
            })?;
            for element in document.select(&selector) {
                let scope = RowScope::Item(element);
                if let Some(row) = build_row(&plan, &scope, meta)? {
                    rows.push(row);
                }
            }
        }
    }
    Ok(rows)
}

fn compile_schema(schema: &OutputSchema) -> Result<Vec<CompiledColumn>, ShapeError> {
    schema.columns().iter().map(compile_column).collect()
}

fn compile_column(column: &Column) -> Result<CompiledColumn, ShapeError> {
    let plan = match column.extractor() {
        Extractor::Meta(field) => CompiledPlan::Meta(*field),
        Extractor::Css { selector, pick } => {
            let compiled = Selector::parse(selector).map_err(|error| {
                ShapeError::InvalidSelector(format!(
                    "column `{}` selector `{selector}`: {error:?}",
                    column.name()
                ))
            })?;
            CompiledPlan::Css {
                selector: compiled,
                pick: pick.clone(),
            }
        }
        Extractor::Json { .. } => return Err(ShapeError::UnsupportedExtractor("json")),
        Extractor::Regex { pattern, group } => {
            let compiled = regex::Regex::new(pattern).map_err(|error| {
                ShapeError::InvalidRegex(format!(
                    "column `{}` pattern `{pattern}`: {error}",
                    column.name()
                ))
            })?;
            CompiledPlan::Regex {
                regex: compiled,
                group: *group,
            }
        }
        Extractor::Const(value) => CompiledPlan::Const(value.clone()),
    };
    Ok(CompiledColumn {
        name: column.name().to_owned(),
        ty: column.ty(),
        on_error: column.on_error(),
        plan,
    })
}

/// Resolve every column for one row scope, in schema column order. Returns
/// `Ok(None)` when a `DropRow` column discards the whole row.
fn build_row(
    plan: &[CompiledColumn],
    scope: &RowScope<'_>,
    meta: &CaptureMeta,
) -> Result<Option<Row>, ShapeError> {
    let mut values = Vec::with_capacity(plan.len());
    for column in plan {
        let extracted = match &column.plan {
            CompiledPlan::Meta(field) => resolve_meta(*field, meta),
            CompiledPlan::Css { selector, pick } => resolve_css(selector, pick, scope),
            CompiledPlan::Regex { regex, group } => resolve_regex(regex, *group, scope),
            CompiledPlan::Const(value) => Extracted::Value(value.clone()),
        };
        match coerce(extracted, column.ty) {
            Ok(value) => values.push(value),
            Err(()) => match column.on_error {
                OnError::Null => values.push(Value::Null),
                OnError::DropRow => return Ok(None),
                OnError::Fail => return Err(ShapeError::RowFailed(column.name.clone())),
            },
        }
    }
    Row::new(values).map(Some).map_err(ShapeError::Protocol)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig2browser_protocol::shape::{Column, OnError};

    fn meta() -> CaptureMeta {
        CaptureMeta {
            url: "https://example.com/catalog".to_owned(),
            final_url: "https://example.com/catalog?ref=1".to_owned(),
            http_status: Some(200),
            title: "Catalog".to_owned(),
            ready_state: "complete".to_owned(),
            captured_at: 1_784_500_000,
            source_id: "collection-1".to_owned(),
        }
    }

    const CATALOG_HTML: &str = r#"
        <html><body>
            <div class="product-card">
                <span class="name">Widget A</span>
                <span class="price">9.99</span>
                <a href="/products/widget-a">link</a>
                <span class="badge">Sale</span>
            </div>
            <div class="product-card">
                <span class="name">Widget B</span>
                <span class="price">14.5</span>
                <a href="/products/widget-b">link</a>
            </div>
            <div class="product-card">
                <span class="name">Widget C</span>
                <span class="price">not-a-number</span>
                <a href="/products/widget-c">link</a>
            </div>
        </body></html>
    "#;

    const REGEX_CATALOG_HTML: &str = r#"
        <html><body>
            <div class="product-card">
                <span class="name">Widget A</span>
                <span class="sku">SKU-12345</span>
            </div>
            <div class="product-card">
                <span class="name">Widget B</span>
                <span class="sku">SKU-67890</span>
            </div>
        </body></html>
    "#;

    fn item_scope_schema(price_on_error: OnError) -> OutputSchema {
        OutputSchema::new(
            "products".to_owned(),
            Cardinality::ItemScope(".product-card".to_owned()),
            vec![
                Column::new(
                    "name".to_owned(),
                    ColumnType::Text,
                    Extractor::Css {
                        selector: ".name".to_owned(),
                        pick: CssPick::Text,
                    },
                    OnError::Null,
                )
                .expect("name column"),
                Column::new(
                    "price".to_owned(),
                    ColumnType::Real,
                    Extractor::Css {
                        selector: ".price".to_owned(),
                        pick: CssPick::Text,
                    },
                    price_on_error,
                )
                .expect("price column"),
                Column::new(
                    "link".to_owned(),
                    ColumnType::Text,
                    Extractor::Css {
                        selector: "a".to_owned(),
                        pick: CssPick::Attr("href".to_owned()),
                    },
                    OnError::Null,
                )
                .expect("link column"),
                Column::new(
                    "has_badge".to_owned(),
                    ColumnType::Boolean,
                    Extractor::Css {
                        selector: ".badge".to_owned(),
                        pick: CssPick::Exists,
                    },
                    OnError::Null,
                )
                .expect("badge column"),
            ],
        )
        .expect("valid item-scope schema")
    }

    #[test]
    fn item_scope_catalog_yields_exact_rows_in_document_order() {
        let schema = item_scope_schema(OnError::Null);
        let rows = shape(CATALOG_HTML.as_bytes(), &meta(), &schema).expect("shape catalog");

        assert_eq!(rows.len(), 3);

        assert_eq!(
            rows[0].values(),
            &[
                Value::Text("Widget A".to_owned()),
                Value::Real(9.99),
                Value::Text("/products/widget-a".to_owned()),
                Value::Boolean(true),
            ]
        );
        assert_eq!(
            rows[1].values(),
            &[
                Value::Text("Widget B".to_owned()),
                Value::Real(14.5),
                Value::Text("/products/widget-b".to_owned()),
                Value::Boolean(false),
            ]
        );
        // Non-numeric price under OnError::Null -> null cell, row kept.
        assert_eq!(
            rows[2].values(),
            &[
                Value::Text("Widget C".to_owned()),
                Value::Null,
                Value::Text("/products/widget-c".to_owned()),
                Value::Boolean(false),
            ]
        );
    }

    #[test]
    fn page_level_mixes_meta_and_document_css() {
        let schema = OutputSchema::new(
            "page".to_owned(),
            Cardinality::PageLevel,
            vec![
                Column::new(
                    "url".to_owned(),
                    ColumnType::Text,
                    Extractor::Meta(MetaField::Url),
                    OnError::Null,
                )
                .expect("url column"),
                Column::new(
                    "final_url".to_owned(),
                    ColumnType::Text,
                    Extractor::Meta(MetaField::FinalUrl),
                    OnError::Null,
                )
                .expect("final_url column"),
                Column::new(
                    "http_status".to_owned(),
                    ColumnType::Integer,
                    Extractor::Meta(MetaField::HttpStatus),
                    OnError::Null,
                )
                .expect("http_status column"),
                Column::new(
                    "title".to_owned(),
                    ColumnType::Text,
                    Extractor::Meta(MetaField::Title),
                    OnError::Null,
                )
                .expect("title column"),
                Column::new(
                    "first_name".to_owned(),
                    ColumnType::Text,
                    Extractor::Css {
                        selector: ".name".to_owned(),
                        pick: CssPick::Text,
                    },
                    OnError::Null,
                )
                .expect("first_name column"),
            ],
        )
        .expect("valid page-level schema");

        let rows = shape(CATALOG_HTML.as_bytes(), &meta(), &schema).expect("shape page-level");
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].values(),
            &[
                Value::Text("https://example.com/catalog".to_owned()),
                Value::Text("https://example.com/catalog?ref=1".to_owned()),
                Value::Integer(200),
                Value::Text("Catalog".to_owned()),
                Value::Text("Widget A".to_owned()),
            ]
        );
    }

    #[test]
    fn coercion_failure_on_error_null_yields_null_cell() {
        let schema = item_scope_schema(OnError::Null);
        let rows = shape(CATALOG_HTML.as_bytes(), &meta(), &schema).expect("shape");
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[2].values()[1], Value::Null);
    }

    #[test]
    fn coercion_failure_on_error_drop_row_discards_row() {
        let schema = item_scope_schema(OnError::DropRow);
        let rows = shape(CATALOG_HTML.as_bytes(), &meta(), &schema).expect("shape");
        // Widget C (non-numeric price) is dropped; A and B survive.
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].values()[0], Value::Text("Widget A".to_owned()));
        assert_eq!(rows[1].values()[0], Value::Text("Widget B".to_owned()));
    }

    #[test]
    fn coercion_failure_on_error_fail_returns_row_failed() {
        let schema = item_scope_schema(OnError::Fail);
        let error = shape(CATALOG_HTML.as_bytes(), &meta(), &schema).expect_err("must fail");
        match error {
            ShapeError::RowFailed(column) => assert_eq!(column, "price"),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn exists_is_true_when_present_false_when_absent_never_a_miss() {
        let schema = item_scope_schema(OnError::Null);
        let rows = shape(CATALOG_HTML.as_bytes(), &meta(), &schema).expect("shape");
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].values()[3], Value::Boolean(true)); // card A has .badge
        assert_eq!(rows[1].values()[3], Value::Boolean(false)); // card B: absent, legitimate false
        assert_eq!(rows[2].values()[3], Value::Boolean(false)); // card C: absent, legitimate false
    }

    fn link_schema(on_error: OnError) -> OutputSchema {
        OutputSchema::new(
            "products".to_owned(),
            Cardinality::ItemScope(".product-card".to_owned()),
            vec![
                Column::new(
                    "name".to_owned(),
                    ColumnType::Text,
                    Extractor::Css {
                        selector: ".name".to_owned(),
                        pick: CssPick::Text,
                    },
                    OnError::Null,
                )
                .expect("name column"),
                Column::new(
                    "link".to_owned(),
                    ColumnType::Text,
                    Extractor::Css {
                        selector: "a".to_owned(),
                        pick: CssPick::Attr("href".to_owned()),
                    },
                    on_error,
                )
                .expect("link column"),
            ],
        )
        .expect("valid link schema")
    }

    /// Exercises `Null` / `DropRow` / `Fail` against one HTML fixture on the
    /// `link` column's `Css::Attr("href")` extractor.
    fn assert_link_column_on_error_matrix(html: &str) {
        let rows = shape(html.as_bytes(), &meta(), &link_schema(OnError::Null)).expect("null");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].values()[1], Value::Null);

        let rows = shape(html.as_bytes(), &meta(), &link_schema(OnError::DropRow)).expect("drop");
        assert_eq!(rows.len(), 0);

        let error =
            shape(html.as_bytes(), &meta(), &link_schema(OnError::Fail)).expect_err("fail");
        match error {
            ShapeError::RowFailed(column) => assert_eq!(column, "link"),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn missing_element_under_each_on_error() {
        // No `<a>` element at all under the item scope.
        assert_link_column_on_error_matrix(
            r#"<div class="product-card"><span class="name">No Link</span></div>"#,
        );
    }

    #[test]
    fn missing_attribute_under_each_on_error() {
        // `<a>` element is present but carries no `href` attribute.
        assert_link_column_on_error_matrix(
            r#"<div class="product-card"><span class="name">No Href</span><a>text</a></div>"#,
        );
    }

    #[test]
    fn unsupported_json_extractor_fails_closed() {
        let json_schema = OutputSchema::new(
            "frames".to_owned(),
            Cardinality::PageLevel,
            vec![Column::new(
                "value".to_owned(),
                ColumnType::Text,
                Extractor::Json {
                    pointer: "/a/b".to_owned(),
                },
                OnError::Null,
            )
            .expect("json column")],
        )
        .expect("valid schema");
        let error = shape(b"<html></html>", &meta(), &json_schema).expect_err("must fail");
        assert!(matches!(error, ShapeError::UnsupportedExtractor("json")));
    }

    #[test]
    fn unsupported_json_extractor_fails_even_with_zero_matching_rows() {
        // The Unsupported check runs at schema-compile time, before any row
        // scope is visited, so it fires even when the item-scope root would
        // match nothing.
        let schema = OutputSchema::new(
            "frames".to_owned(),
            Cardinality::ItemScope(".does-not-exist".to_owned()),
            vec![Column::new(
                "value".to_owned(),
                ColumnType::Text,
                Extractor::Json {
                    pointer: "/a/b".to_owned(),
                },
                OnError::Null,
            )
            .expect("json column")],
        )
        .expect("valid schema");
        let error = shape(b"<html></html>", &meta(), &schema).expect_err("must fail");
        assert!(matches!(error, ShapeError::UnsupportedExtractor("json")));
    }

    #[test]
    fn regex_item_scope_extracts_capture_group_per_row() {
        let schema = OutputSchema::new(
            "products".to_owned(),
            Cardinality::ItemScope(".product-card".to_owned()),
            vec![Column::new(
                "sku".to_owned(),
                ColumnType::Integer,
                Extractor::Regex {
                    pattern: r"SKU-(\d+)".to_owned(),
                    group: 1,
                },
                OnError::Null,
            )
            .expect("sku column")],
        )
        .expect("valid schema");

        let rows = shape(REGEX_CATALOG_HTML.as_bytes(), &meta(), &schema).expect("shape");
        assert_eq!(rows.len(), 2);
        // Each row's capture group comes from its own item scope's text,
        // not the whole document's.
        assert_eq!(rows[0].values(), &[Value::Integer(12345)]);
        assert_eq!(rows[1].values(), &[Value::Integer(67890)]);
    }

    #[test]
    fn regex_group_zero_returns_whole_match() {
        let schema = OutputSchema::new(
            "products".to_owned(),
            Cardinality::ItemScope(".product-card".to_owned()),
            vec![Column::new(
                "sku".to_owned(),
                ColumnType::Text,
                Extractor::Regex {
                    pattern: r"SKU-\d+".to_owned(),
                    group: 0,
                },
                OnError::Null,
            )
            .expect("sku column")],
        )
        .expect("valid schema");

        let rows = shape(REGEX_CATALOG_HTML.as_bytes(), &meta(), &schema).expect("shape");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].values(), &[Value::Text("SKU-12345".to_owned())]);
        assert_eq!(rows[1].values(), &[Value::Text("SKU-67890".to_owned())]);
    }

    fn regex_no_match_schema(on_error: OnError) -> OutputSchema {
        OutputSchema::new(
            "products".to_owned(),
            Cardinality::ItemScope(".product-card".to_owned()),
            vec![Column::new(
                "sku".to_owned(),
                ColumnType::Text,
                Extractor::Regex {
                    pattern: r"SKU-(\d+)".to_owned(),
                    group: 1,
                },
                on_error,
            )
            .expect("sku column")],
        )
        .expect("valid regex schema")
    }

    /// Exercises `Null` / `DropRow` / `Fail` against one HTML fixture on the
    /// `sku` column's `Regex` extractor when the pattern does not match the
    /// row scope's text.
    fn assert_regex_no_match_on_error_matrix(html: &str) {
        let rows = shape(html.as_bytes(), &meta(), &regex_no_match_schema(OnError::Null))
            .expect("null");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].values()[0], Value::Null);

        let rows = shape(html.as_bytes(), &meta(), &regex_no_match_schema(OnError::DropRow))
            .expect("drop");
        assert_eq!(rows.len(), 0);

        let error = shape(html.as_bytes(), &meta(), &regex_no_match_schema(OnError::Fail))
            .expect_err("fail");
        match error {
            ShapeError::RowFailed(column) => assert_eq!(column, "sku"),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn regex_no_match_under_each_on_error() {
        assert_regex_no_match_on_error_matrix(
            r#"<div class="product-card"><span class="name">No Sku Here</span></div>"#,
        );
    }

    #[test]
    fn regex_out_of_range_group_is_a_miss_not_an_error() {
        let schema = OutputSchema::new(
            "products".to_owned(),
            Cardinality::ItemScope(".product-card".to_owned()),
            vec![Column::new(
                "sku".to_owned(),
                ColumnType::Text,
                Extractor::Regex {
                    pattern: r"SKU-(\d+)".to_owned(),
                    group: 9,
                },
                OnError::Null,
            )
            .expect("sku column")],
        )
        .expect("valid schema");

        // The pattern matches, but group 9 doesn't exist in it —
        // `Captures::get` returns `None`, the same `Extracted::Missing`
        // path as a no-match, folded into `OnError::Null` rather than
        // surfaced as a distinct error.
        let rows = shape(REGEX_CATALOG_HTML.as_bytes(), &meta(), &schema).expect("shape");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].values(), &[Value::Null]);
        assert_eq!(rows[1].values(), &[Value::Null]);
    }

    #[test]
    fn invalid_regex_pattern_fails_even_with_zero_matching_rows() {
        // Mirrors the unsupported-extractor compile-time checks: an invalid
        // pattern is caught once for the whole schema, before any row scope
        // is visited, so it fires even when the item-scope root would match
        // nothing.
        let schema = OutputSchema::new(
            "frames".to_owned(),
            Cardinality::ItemScope(".does-not-exist".to_owned()),
            vec![Column::new(
                "value".to_owned(),
                ColumnType::Text,
                Extractor::Regex {
                    pattern: r"(".to_owned(),
                    group: 0,
                },
                OnError::Null,
            )
            .expect("regex column")],
        )
        .expect("valid schema");
        let error = shape(b"<html></html>", &meta(), &schema).expect_err("must fail");
        assert!(matches!(error, ShapeError::InvalidRegex(_)));
    }

    #[test]
    fn regex_page_level_matches_whole_document_text() {
        const ORDER_HTML: &str = r#"
            <html><body>
                <p>Order confirmation</p>
                <p>Reference: ORD-98765</p>
            </body></html>
        "#;

        let schema = OutputSchema::new(
            "order".to_owned(),
            Cardinality::PageLevel,
            vec![Column::new(
                "order_id".to_owned(),
                ColumnType::Text,
                Extractor::Regex {
                    pattern: r"ORD-(\d+)".to_owned(),
                    group: 1,
                },
                OnError::Fail,
            )
            .expect("order_id column")],
        )
        .expect("valid schema");

        let rows = shape(ORDER_HTML.as_bytes(), &meta(), &schema).expect("shape");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].values(), &[Value::Text("98765".to_owned())]);
    }

    #[test]
    fn empty_item_scope_match_yields_empty_rows_not_an_error() {
        let schema = OutputSchema::new(
            "products".to_owned(),
            Cardinality::ItemScope(".does-not-exist".to_owned()),
            vec![Column::new(
                "name".to_owned(),
                ColumnType::Text,
                Extractor::Css {
                    selector: ".name".to_owned(),
                    pick: CssPick::Text,
                },
                OnError::Null,
            )
            .expect("name column")],
        )
        .expect("valid schema");

        let rows = shape(CATALOG_HTML.as_bytes(), &meta(), &schema).expect("shape empty match");
        assert_eq!(rows, Vec::new());
    }

    #[test]
    fn const_extractor_passes_literal_through_regardless_of_declared_type() {
        let schema = OutputSchema::new(
            "products".to_owned(),
            Cardinality::PageLevel,
            vec![Column::new(
                "source".to_owned(),
                ColumnType::Text,
                Extractor::Const(Value::Text("catalog-crawl".to_owned())),
                OnError::Fail,
            )
            .expect("const column")],
        )
        .expect("valid schema");

        let rows = shape(CATALOG_HTML.as_bytes(), &meta(), &schema).expect("shape const");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].values(), &[Value::Text("catalog-crawl".to_owned())]);
    }
}
