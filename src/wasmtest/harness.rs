//! HTML harness rendering and test output parsing.

/// Rendered test results collected from the browser output.
pub struct TestResult {
    pub passed: usize,
    pub failed: usize,
    pub ignored: usize,
    pub output: String,
}

/// Render the HTML harness page that loads the wasm-bindgen test shim.
///
/// Matches the upstream `wasm-bindgen-test-runner` browser harness contract
/// exactly: `#output` pre, five `console_*` pres, console-wrapping script,
/// and a `<script type=module src='run.js'>` tag.
///
/// `nocapture` — when `true`, `console.log` (and sibling methods) output is
/// **also** appended to `#output` so the runner can scrape it alongside the
/// `test result:` summary.  When `false` (default), console output only goes
/// to the dedicated `#console_*` elements (never read by the runner → kept
/// silent).
pub fn render_html(nocapture: bool) -> String {
    // JS template literals `${...}` are passed through verbatim inside a
    // Rust raw string — they are NOT Rust format arguments.
    let nocapture_js = if nocapture { "true" } else { "false" };
    format!(
        r#"<!DOCTYPE html>
<html>
  <head>
    <meta content="text/html;charset=utf-8" http-equiv="Content-Type"/>
  </head>
  <body>
    <pre id="output">Loading scripts...</pre>
    <pre id="console_debug"></pre>
    <pre id="console_log"></pre>
    <pre id="console_info"></pre>
    <pre id="console_warn"></pre>
    <pre id="console_error"></pre>
    <script>
     const orig = id => (...args) => {{
         const logs = document.getElementById(id);
         for (let msg of args) {{
             logs.textContent += `${{msg}}\n`;
         }}
     }};
     const nocapture = {nocapture_js};
     const wrap = method => {{
         const og = orig(`console_${{method}}`);
         const on_method = `on_console_${{method}}`;
         console[method] = function (...args) {{
             if (nocapture) {{
                 orig("output").apply(this, args);
             }}
             if (window[on_method]) {{
                 window[on_method](args);
             }}
             og.apply(this, args);
         }};
     }};
     wrap("debug");
     wrap("log");
     wrap("info");
     wrap("warn");
     wrap("error");
     window.__wbg_test_invoke = f => f();
    </script>
    <script src='run.js' type=module></script>
  </body>
</html>
"#
    )
}

/// Generate the ES-module `run.js` that imports the wasm-bindgen shim and
/// drives the test suite.
///
/// `stem` — shim basename; files are `{stem}.js` + `{stem}_bg.wasm`.
/// `test_exports` — list of `__wbgt_*` symbol names to include (already
///   filtered to the desired subset — the caller does the filtering).
/// `include_ignored` — forward to `cx.include_ignored(...)`.
/// `filtered_count` — number of tests excluded by name filters; forwarded to
///   `cx.filtered_count(...)`.
/// `per_test_timeout_secs` — when `Some(n)` and `n > 0`, each test function
///   is wrapped in a `Promise.race` against a `n`-second rejection timeout so
///   a single hung test fails instead of stalling the whole suite.  `None` or
///   `Some(0)` → no wrapping (current behavior, zero risk).
pub fn render_run_js(
    stem: &str,
    test_exports: &[String],
    include_ignored: bool,
    filtered_count: usize,
    per_test_timeout_secs: Option<u64>,
) -> String {
    let include_ignored_js = if include_ignored { "true" } else { "false" };

    // Build the per-test timeout wrapper (GAP-3).
    // When active we emit a helper and wrap every test via it.
    let (timeout_helper, map_expr) = match per_test_timeout_secs {
        Some(secs) if secs > 0 => {
            let ms = secs * 1000;
            let helper = format!(
                r#"
function withTimeout(fn, ms) {{
    return function() {{
        const testPromise = fn();
        const timeoutPromise = new Promise((_resolve, reject) => {{
            setTimeout(() => reject(new Error('test timed out after {secs}s')), {ms});
        }});
        return Promise.race([testPromise, timeoutPromise]);
    }};
}}
"#
            );
            // Wrap each resolved wasm export: s => withTimeout(wasm[s], <ms>)
            let map = format!("test.map(s => withTimeout(wasm[s], {ms}))");
            (helper, map)
        }
        _ => (String::new(), "test.map(s => wasm[s])".to_string()),
    };

    let mut out = format!(
        r#"import {{
    WasmBindgenTestContext as Context,
    __wbgtest_console_debug,
    __wbgtest_console_log,
    __wbgtest_console_info,
    __wbgtest_console_warn,
    __wbgtest_console_error,
    default as init,
}} from './{stem}.js';

document.getElementById('output').textContent = "Loading Wasm module...";
{timeout_helper}
async function main(test) {{
    const wasm = await init('./{stem}_bg.wasm');

    const cx = new Context();
    window.on_console_debug = __wbgtest_console_debug;
    window.on_console_log = __wbgtest_console_log;
    window.on_console_info = __wbgtest_console_info;
    window.on_console_warn = __wbgtest_console_warn;
    window.on_console_error = __wbgtest_console_error;

    cx.include_ignored({include_ignored_js});
    cx.filtered_count({filtered_count});

    await cx.run({map_expr});
}}

const tests = [];
"#
    );

    for name in test_exports {
        out.push_str(&format!("tests.push('{name}');\n"));
    }

    out.push_str("main(tests);\n");
    out
}

/// Parse the `test result:` summary line written by `wasm-bindgen-test`.
///
/// Canonical formats:
/// ```text
/// test result: ok. 3 passed; 0 failed; 0 ignored; 0 filtered out
/// test result: FAILED. 2 passed; 1 failed; 0 ignored; 0 filtered out
/// ```
///
/// Returns `None` if no `test result:` line is present.
///
/// Console output lines interleaved by `--nocapture` are harmless — this
/// function only inspects lines that contain `"test result:"`.
pub fn parse_output(text: &str) -> Option<TestResult> {
    let line = text.lines().find(|l| l.contains("test result:"))?;

    let passed = extract_count(line, "passed").unwrap_or(0);
    let failed = extract_count(line, "failed").unwrap_or(0);
    let ignored = extract_count(line, "ignored").unwrap_or(0);

    Some(TestResult {
        passed,
        failed,
        ignored,
        output: text.to_string(),
    })
}

/// Extract `<integer> <keyword>` from a summary line.
///
/// Splits on whitespace and semicolons, then looks for a token immediately
/// followed by `keyword`.
fn extract_count(line: &str, keyword: &str) -> Option<usize> {
    // Tokenize: split on whitespace, semicolons, and dots.
    let tokens: Vec<&str> = line
        .split(|c: char| c.is_whitespace() || c == ';' || c == '.')
        .filter(|t| !t.is_empty())
        .collect();

    for window in tokens.windows(2) {
        if window[1] == keyword {
            if let Ok(n) = window[0].parse::<usize>() {
                return Some(n);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_output ──────────────────────────────────────────────────────────

    #[test]
    fn parse_ok_line() {
        let text =
            "running 3 tests\ntest result: ok. 3 passed; 0 failed; 0 ignored; 0 filtered out\n";
        let r = parse_output(text).expect("should parse");
        assert_eq!(r.passed, 3);
        assert_eq!(r.failed, 0);
        assert_eq!(r.ignored, 0);
        assert_eq!(r.output, text);
    }

    #[test]
    fn parse_failed_line() {
        let text = "test result: FAILED. 2 passed; 1 failed; 0 ignored; 0 filtered out\n";
        let r = parse_output(text).expect("should parse");
        assert_eq!(r.passed, 2);
        assert_eq!(r.failed, 1);
        assert_eq!(r.ignored, 0);
    }

    #[test]
    fn parse_none_when_absent() {
        let text = "nothing useful here\nno summary\n";
        assert!(parse_output(text).is_none());
    }

    #[test]
    fn parse_with_ignored() {
        let text = "test result: ok. 5 passed; 0 failed; 2 ignored; 1 filtered out\n";
        let r = parse_output(text).expect("should parse");
        assert_eq!(r.passed, 5);
        assert_eq!(r.ignored, 2);
    }

    /// Interleaved console.log lines (from --nocapture) must not confuse parse_output.
    #[test]
    fn parse_with_interleaved_console_lines() {
        let text = "running 2 tests\nsome console output\nmore output\ntest result: ok. 2 passed; 0 failed; 0 ignored; 0 filtered out\n";
        let r = parse_output(text).expect("should parse even with console lines");
        assert_eq!(r.passed, 2);
        assert_eq!(r.failed, 0);
    }

    // ── render_html ───────────────────────────────────────────────────────────

    #[test]
    fn render_html_nocapture_false_emits_false() {
        let html = render_html(false);
        assert!(
            html.contains("const nocapture = false;"),
            "expected 'const nocapture = false;' in HTML"
        );
    }

    #[test]
    fn render_html_nocapture_true_emits_true() {
        let html = render_html(true);
        assert!(
            html.contains("const nocapture = true;"),
            "expected 'const nocapture = true;' in HTML"
        );
    }

    #[test]
    fn render_html_has_output_element() {
        let html = render_html(false);
        assert!(html.contains(r#"id="output""#));
    }

    // ── render_run_js ─────────────────────────────────────────────────────────

    #[test]
    fn render_run_js_contains_filtered_count() {
        let tests = vec!["__wbgt_foo_abc".to_string()];
        let js = render_run_js("my_crate", &tests, false, 3, None);
        assert!(
            js.contains("cx.filtered_count(3)"),
            "expected filtered_count(3) in run.js"
        );
    }

    #[test]
    fn render_run_js_no_timeout_uses_direct_map() {
        let tests = vec!["__wbgt_foo_abc".to_string()];
        let js = render_run_js("my_crate", &tests, false, 0, None);
        assert!(
            js.contains("test.map(s => wasm[s])"),
            "expected direct map without wrapper"
        );
        assert!(
            !js.contains("withTimeout"),
            "expected no withTimeout when disabled"
        );
    }

    #[test]
    fn render_run_js_zero_timeout_uses_direct_map() {
        let tests = vec!["__wbgt_foo_abc".to_string()];
        let js = render_run_js("my_crate", &tests, false, 0, Some(0));
        assert!(
            js.contains("test.map(s => wasm[s])"),
            "Some(0) should not enable wrapping"
        );
    }

    #[test]
    fn render_run_js_with_timeout_emits_wrapper() {
        let tests = vec!["__wbgt_foo_abc".to_string()];
        let js = render_run_js("my_crate", &tests, false, 0, Some(5));
        assert!(
            js.contains("withTimeout"),
            "expected withTimeout helper when secs > 0"
        );
        assert!(
            js.contains("5000"),
            "expected timeout in milliseconds (5000)"
        );
        assert!(
            js.contains("test.map(s => withTimeout(wasm[s], 5000))"),
            "expected wrapped map expression"
        );
    }

    #[test]
    fn render_run_js_include_ignored_false() {
        let tests: Vec<String> = vec![];
        let js = render_run_js("stem", &tests, false, 0, None);
        assert!(js.contains("cx.include_ignored(false)"));
    }

    #[test]
    fn render_run_js_include_ignored_true() {
        let tests: Vec<String> = vec![];
        let js = render_run_js("stem", &tests, true, 0, None);
        assert!(js.contains("cx.include_ignored(true)"));
    }
}
