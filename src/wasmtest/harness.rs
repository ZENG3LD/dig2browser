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
pub fn render_html() -> String {
    // JS template literals `${...}` are passed through verbatim inside a
    // Rust raw string — they are NOT Rust format arguments.
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
     const orig = id => (...args) => {
         const logs = document.getElementById(id);
         for (let msg of args) {
             logs.textContent += `${msg}\n`;
         }
     };
     const nocapture = false;
     const wrap = method => {
         const og = orig(`console_${method}`);
         const on_method = `on_console_${method}`;
         console[method] = function (...args) {
             if (nocapture) {
                 orig("output").apply(this, args);
             }
             if (window[on_method]) {
                 window[on_method](args);
             }
             og.apply(this, args);
         };
     };
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
    .to_string()
}

/// Generate the ES-module `run.js` that imports the wasm-bindgen shim and
/// drives the test suite.
///
/// `stem` — shim basename; files are `{stem}.js` + `{stem}_bg.wasm`.
/// `test_exports` — list of `__wbgt_*` symbol names exported by the shim.
/// `include_ignored` — forward to `cx.include_ignored(...)`.
/// `filtered_count` — forward to `cx.filtered_count(...)`.
pub fn render_run_js(
    stem: &str,
    test_exports: &[String],
    include_ignored: bool,
    filtered_count: usize,
) -> String {
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

async function main(test) {{
    const wasm = await init('./{stem}_bg.wasm');

    const cx = new Context();
    window.on_console_debug = __wbgtest_console_debug;
    window.on_console_log = __wbgtest_console_log;
    window.on_console_info = __wbgtest_console_info;
    window.on_console_warn = __wbgtest_console_warn;
    window.on_console_error = __wbgtest_console_error;

    cx.include_ignored({include_ignored});
    cx.filtered_count({filtered_count});

    await cx.run(test.map(s => wasm[s]));
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
}
