//! Raw (pre-coercion) extraction: resolving a compiled [`crate::CompiledPlan`]
//! against a row scope (whole document or a matched item element) or against
//! [`crate::CaptureMeta`].

use dig2browser_protocol::shape::{CssPick, MetaField, Value};
use scraper::{ElementRef, Html, Selector};

use crate::CaptureMeta;

/// A raw extraction result, before type coercion to the column's declared
/// [`dig2browser_protocol::shape::ColumnType`].
pub(crate) enum Extracted {
    /// No match / missing attribute / absent [`CaptureMeta`] field.
    Missing,
    /// Extracted textual content (`Meta`, `Css::Text`, `Css::Attr`, `Css::Html`).
    Text(String),
    /// `Css::Exists` — a legitimate `false` on no-match, never a miss.
    Bool(bool),
    /// `Const` — already a typed protocol [`Value`], passed through as-is.
    Value(Value),
    /// `shape_json`'s `Extractor::Json` pointer resolution — the pointed-to
    /// `serde_json::Value`, kept typed rather than stringified so numeric
    /// (`Integer`/`Real`) and `Boolean` columns coerce without a round trip
    /// through text.
    Json(serde_json::Value),
}

/// Where a [`dig2browser_protocol::shape::Extractor::Css`] selector resolves:
/// the whole document (`PageLevel`) or a single matched item element
/// (`ItemScope`).
pub(crate) enum RowScope<'a> {
    Document(&'a Html),
    Item(ElementRef<'a>),
}

impl<'a> RowScope<'a> {
    fn select_first(&self, selector: &Selector) -> Option<ElementRef<'a>> {
        match self {
            Self::Document(document) => document.select(selector).next(),
            Self::Item(element) => element.select(selector).next(),
        }
    }

    /// The scope's whole text content, collapsed per [`collapse_whitespace`]:
    /// every descendant text node under the item element for `Item`, or the
    /// whole document's root element for `Document`. This is what
    /// `dig2browser_protocol::shape::Extractor::Regex` matches against.
    pub(crate) fn text(&self) -> String {
        match self {
            Self::Document(document) => {
                collapse_whitespace(&document.root_element().text().collect::<String>())
            }
            Self::Item(element) => collapse_whitespace(&element.text().collect::<String>()),
        }
    }
}

pub(crate) fn resolve_meta(field: MetaField, meta: &CaptureMeta) -> Extracted {
    match field {
        MetaField::Url => Extracted::Text(meta.url.clone()),
        MetaField::FinalUrl => Extracted::Text(meta.final_url.clone()),
        MetaField::HttpStatus => match meta.http_status {
            Some(status) => Extracted::Text(status.to_string()),
            None => Extracted::Missing,
        },
        MetaField::Title => Extracted::Text(meta.title.clone()),
        MetaField::ReadyState => Extracted::Text(meta.ready_state.clone()),
        MetaField::CapturedAt => Extracted::Text(meta.captured_at.to_string()),
        MetaField::SourceId => Extracted::Text(meta.source_id.clone()),
    }
}

pub(crate) fn resolve_css(selector: &Selector, pick: &CssPick, scope: &RowScope<'_>) -> Extracted {
    match pick {
        CssPick::Exists => Extracted::Bool(scope.select_first(selector).is_some()),
        CssPick::Text => match scope.select_first(selector) {
            Some(element) => Extracted::Text(collapse_whitespace(&element.text().collect::<String>())),
            None => Extracted::Missing,
        },
        CssPick::Attr(name) => {
            match scope.select_first(selector).and_then(|element| element.attr(name)) {
                Some(value) => Extracted::Text(value.to_owned()),
                None => Extracted::Missing,
            }
        }
        CssPick::Html => match scope.select_first(selector) {
            Some(element) => Extracted::Text(element.inner_html()),
            None => Extracted::Missing,
        },
    }
}

/// Resolve a compiled regex against the row scope's whole text (see
/// [`RowScope::text`]), returning the numbered capture group `group`
/// (`0` = whole match). A no-match haystack, an out-of-range `group`, or a
/// group that didn't participate in the match are all a normal
/// [`Extracted::Missing`] — not an error — and fold into the column's
/// `OnError` policy same as any other extraction miss.
pub(crate) fn resolve_regex(regex: &regex::Regex, group: u32, scope: &RowScope<'_>) -> Extracted {
    let text = scope.text();
    match regex.captures(&text) {
        Some(captures) => captures.get(group as usize).map_or(Extracted::Missing, |m| {
            Extracted::Text(m.as_str().to_owned())
        }),
        None => Extracted::Missing,
    }
}

/// Resolve a [`dig2browser_protocol::shape::Extractor::Json`] pointer
/// against a `shape_json` row scope (RFC 6901, matching
/// `serde_json::Value::pointer`'s own resolution rules — including that an
/// empty pointer resolves to the whole scope). A pointer that does not
/// resolve is a miss; a pointer that resolves to JSON `null` is *not* a miss
/// here — that distinction is drawn during coercion (`coerce::coerce_json`),
/// mirroring how `resolve_meta`/`resolve_css` hand raw non-missing results
/// to `coerce` uniformly.
pub(crate) fn resolve_json_pointer(scope: &serde_json::Value, pointer: &str) -> Extracted {
    match scope.pointer(pointer) {
        Some(value) => Extracted::Json(value.clone()),
        None => Extracted::Missing,
    }
}

/// Resolve a compiled regex against a `shape_json` row scope's compact JSON
/// serialization (`serde_json::to_string`), returning the numbered capture
/// group `group` (`0` = whole match) — the JSON-source counterpart of
/// [`resolve_regex`]'s HTML-scope text match. A no-match haystack, an
/// out-of-range `group`, or a group that didn't participate in the match are
/// all a normal [`Extracted::Missing`], same as the HTML path.
pub(crate) fn resolve_json_regex(
    regex: &regex::Regex,
    group: u32,
    scope: &serde_json::Value,
) -> Extracted {
    let Ok(text) = serde_json::to_string(scope) else {
        return Extracted::Missing;
    };
    match regex.captures(&text) {
        Some(captures) => captures.get(group as usize).map_or(Extracted::Missing, |m| {
            Extracted::Text(m.as_str().to_owned())
        }),
        None => Extracted::Missing,
    }
}

/// Text whitespace rule: concatenate every descendant text node with no
/// separator, then normalize whitespace — any run of whitespace (spaces,
/// tabs, newlines) collapses to a single ASCII space, and the result is
/// trimmed of leading/trailing whitespace. This is the common
/// "normalize-space" rule (matches the intuition of visually rendered text),
/// not a byte-for-byte copy of the DOM's raw whitespace layout.
pub(crate) fn collapse_whitespace(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut last_was_space = false;
    for ch in input.chars() {
        if ch.is_whitespace() {
            if !last_was_space && !output.is_empty() {
                output.push(' ');
            }
            last_was_space = true;
        } else {
            output.push(ch);
            last_was_space = false;
        }
    }
    if output.ends_with(' ') {
        output.pop();
    }
    output
}

#[cfg(test)]
mod tests {
    use super::collapse_whitespace;

    #[test]
    fn collapses_interior_runs_and_trims_edges() {
        assert_eq!(collapse_whitespace("  hello   world  \n\t"), "hello world");
        assert_eq!(collapse_whitespace("a\nb\tc"), "a b c");
        assert_eq!(collapse_whitespace(""), "");
        assert_eq!(collapse_whitespace("   "), "");
        assert_eq!(collapse_whitespace("single"), "single");
    }
}
