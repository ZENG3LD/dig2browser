//! Stealth descriptor E2E: launches real Chrome on `about:blank` (no network
//! traffic) and asserts the patched surfaces have the stock Chrome descriptor
//! shapes — prototype accessors instead of per-instance own properties,
//! native-looking `toString` without own-`toString` properties, coherent
//! outer/inner window sizes, and a monotonic unified time source.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::thread::JoinHandle;

use dig2browser::browser::StealthBrowser;
use dig2browser::detect::{BrowserProfile, LaunchConfig};
use dig2browser::stealth::{LocaleProfile, StealthConfig, StealthLevel};

fn e2e_profile() -> PathBuf {
    std::env::temp_dir().join(format!(
        "dig2browser-stealth-descriptor-e2e-{}",
        uuid::Uuid::new_v4()
    ))
}

/// Minimal local HTTP fixture. `http://127.0.0.1` is a potentially trustworthy
/// origin, so secure-context APIs (`MediaDevices`) exist — they do not on
/// `about:blank`. No traffic leaves the loopback interface.
struct FixtureServer {
    addr: SocketAddr,
    _thread: JoinHandle<()>,
}

impl FixtureServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
        let addr = listener.local_addr().expect("fixture addr");
        let thread = std::thread::spawn(move || {
            while let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0_u8; 4096];
                let _ = stream.read(&mut buffer);
                let body = b"<!doctype html><html><body>stealth-descriptor-e2e</body></html>";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.write_all(body);
            }
        });
        Self {
            addr,
            _thread: thread,
        }
    }

    fn url(&self) -> String {
        format!("http://{}/", self.addr)
    }
}

/// One async IIFE collects every observation; each entry is `true` when the
/// shape matches stock Chrome.
const PROBE_JS: &str = r#"
(async function() {
    const out = {};
    const desc = (obj, prop) => Object.getOwnPropertyDescriptor(obj, prop);

    // ── navigator.webdriver (blocker shape) ──────────────────────────────
    out.webdriver_value = navigator.webdriver === false;
    out.webdriver_not_own = !navigator.hasOwnProperty('webdriver');
    const wd = desc(Navigator.prototype, 'webdriver');
    out.webdriver_descriptor = !!wd && wd.enumerable === true && wd.configurable === true
        && typeof wd.get === 'function';
    out.webdriver_getter_native = !!wd
        && wd.get.toString() === 'function get webdriver() { [native code] }'
        && wd.get.name === 'get webdriver'
        && !('prototype' in wd.get);

    // ── toString hygiene (no own toString on any patched function) ───────
    out.tostring_shim_native = Function.prototype.toString.toString()
        === 'function toString() { [native code] }';
    const gid = CanvasRenderingContext2D.prototype.getImageData;
    out.canvas_getimageData_native = gid.toString()
        === 'function getImageData() { [native code] }';
    out.canvas_no_own_tostring = !Object.getOwnPropertyNames(gid).includes('toString');
    out.date_now_native = Date.now.toString() === 'function now() { [native code] }';
    out.gettime_no_own_tostring = !Object.getOwnPropertyNames(Date.prototype.getTime)
        .includes('toString');
    out.perf_now_native = Performance.prototype.now.toString()
        === 'function now() { [native code] }';
    out.perf_now_not_own = !performance.hasOwnProperty('now');
    const glProto = WebGLRenderingContext.prototype;
    out.webgl_getparameter_native = glProto.getParameter.toString()
        === 'function getParameter() { [native code] }'
        && !Object.getOwnPropertyNames(glProto.getParameter).includes('toString');

    // ── prototype placement of navigator members ─────────────────────────
    for (const prop of ['languages', 'hardwareConcurrency', 'deviceMemory', 'maxTouchPoints']) {
        out['proto_' + prop] = !navigator.hasOwnProperty(prop)
            && !!desc(Navigator.prototype, prop)
            && typeof desc(Navigator.prototype, prop).get === 'function';
        const g = desc(Navigator.prototype, prop).get;
        out['proto_' + prop + '_native'] = g.toString()
            === 'function get ' + prop + '() { [native code] }';
    }
    out.languages_value = JSON.stringify(navigator.languages) === '["en-US","en"]'
        && Object.isFrozen(navigator.languages)
        && navigator.languages === navigator.languages;
    out.hardware_value = navigator.hardwareConcurrency === 8;
    out.memory_value = navigator.deviceMemory === 8;

    // ── plugins / connection: native, unfaked ────────────────────────────
    out.plugins_native = navigator.plugins instanceof PluginArray
        && !navigator.hasOwnProperty('plugins')
        && typeof PluginArray.prototype.item === 'function'
        && navigator.plugins.length >= 3;
    out.connection_native = !navigator.hasOwnProperty('connection')
        && (typeof navigator.connection === 'undefined'
            || navigator.connection instanceof EventTarget);

    // ── screen on Screen.prototype ───────────────────────────────────────
    const sw = desc(Screen.prototype, 'width');
    out.screen_prototype = !!sw && typeof sw.get === 'function'
        && !screen.hasOwnProperty('width')
        && sw.get.toString() === 'function get width() { [native code] }'
        && sw.get.name === 'get width';
    out.screen_values = screen.width === 1920 && screen.height === 1080
        && screen.availHeight === 1040;

    // ── window frame: outer strictly larger than inner by a plausible frame ──
    const hDelta = window.outerHeight - window.innerHeight;
    const wDelta = window.outerWidth - window.innerWidth;
    out.outer_frame = hDelta >= 85 && hDelta <= 130 && wDelta > 0 && wDelta <= 16;
    const oh = desc(window, 'outerHeight');
    out.outer_getter_native = !!oh && oh.get.toString()
        === 'function get outerHeight() { [native code] }';

    // ── window.chrome: native object (headless Chrome ships one) ─────────
    out.chrome_present = typeof window.chrome === 'object' && window.chrome !== null;
    out.chrome_csi = typeof window.chrome.csi === 'function';
    const csi = window.chrome.csi();
    out.chrome_csi_shape = typeof csi.startE === 'number' && csi.startE > 0
        && typeof csi.pageT === 'number' && csi.pageT >= 0
        && typeof csi.onloadT === 'number';
    const lt = window.chrome.loadTimes();
    out.chrome_loadtimes_shape = typeof lt.startLoadTime === 'number' && lt.startLoadTime > 0
        && typeof lt.requestTime === 'number'
        && typeof lt.firstPaintTime === 'number';

    // ── unified, monotonic time source ───────────────────────────────────
    out.time_int_tick_coherent = Date.now() === new Date().getTime()
        && new Date().getTime() === new Date().valueOf();
    let mono = true;
    let last = -1;
    const stop = Date.now() + 35; // spans several 10 ms noise buckets
    while (Date.now() < stop) {
        const t = performance.now();
        if (t < last) mono = false;
        last = t;
    }
    out.perf_now_monotonic = mono;
    const drift = Math.abs(Date.now() - (performance.timeOrigin + performance.now()));
    out.time_sources_agree = drift < 50;

    // ── timezone override (Full level) ───────────────────────────────────
    out.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone === 'Europe/Berlin';
    out.datetimeformat_native = Intl.DateTimeFormat.prototype.resolvedOptions.toString()
        === 'function resolvedOptions() { [native code] }'
        && typeof Intl.DateTimeFormat.supportedLocalesOf === 'function';

    // ── media devices: native MediaDevices instance, patched prototype ───
    out.mediadevices_native = navigator.mediaDevices instanceof EventTarget;
    out.enumerate_native = MediaDevices.prototype.enumerateDevices.toString()
        === 'function enumerateDevices() { [native code] }';
    const devices = await navigator.mediaDevices.enumerateDevices();
    out.enumerate_devices = devices.length === 4
        && devices.every(d => d instanceof MediaDeviceInfo)
        && devices.some(d => d.kind === 'videoinput')
        && devices.every(d => d.label === '');

    // ── permissions: prototype patch, PermissionStatus instances ─────────
    out.query_native = Permissions.prototype.query.toString()
        === 'function query() { [native code] }';
    const status = await navigator.permissions.query({ name: 'push' });
    out.permission_status = status instanceof PermissionStatus
        && status.state === 'prompt';

    // ── WebGL persona strings ────────────────────────────────────────────
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl');
    const dbg = gl && gl.getExtension('WEBGL_debug_renderer_info');
    out.webgl_strings = !!dbg
        && gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) === 'Google Inc. (NVIDIA)'
        && gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)
            === 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1080 Direct3D11 vs_5_0 ps_5_0, D3D11)';

    return JSON.stringify(out);
})()
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stealth_descriptor_shapes_match_stock_chrome_e2e() {
    let profile = e2e_profile();
    let config = StealthConfig {
        level: StealthLevel::Full,
        locale: LocaleProfile {
            locale: "en-US".into(),
            timezone: Some("Europe/Berlin".into()),
        },
        ..StealthConfig::default()
    };
    let browser = StealthBrowser::launch_with(
        LaunchConfig {
            headless: true,
            profile: BrowserProfile::Persistent(profile.clone()),
            ..LaunchConfig::default()
        },
        config,
    )
    .await
    .expect("launch Chrome for the stealth descriptor probe");
    let page = browser.new_blank_page().await.expect("open blank page");
    // addScriptToEvaluateOnNewDocument applies to documents created AFTER
    // registration; the initial about:blank document predates it, so navigate
    // to the loopback fixture — a potentially trustworthy origin, so
    // secure-context APIs (MediaDevices) are exposed.
    let fixture = FixtureServer::start();
    page.goto(&fixture.url()).await.expect("load loopback fixture");

    let value = page.eval(PROBE_JS).await.expect("evaluate the probe");
    let text = value.as_str().expect("probe returns a JSON string");
    let checks: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(text).expect("parse probe JSON");

    browser.close().await.expect("close probe browser");
    let _ = std::fs::remove_dir_all(&profile);

    let mut failures = Vec::new();
    for (name, value) in &checks {
        if value.as_bool() != Some(true) {
            failures.push(name.clone());
        }
    }
    assert!(
        failures.is_empty(),
        "stealth descriptor mismatches: {failures:?}\nfull probe: {text}"
    );
}
