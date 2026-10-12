//! JS script generators for anti-detection overrides.
//!
//! All sections are assembled into ONE combined script (`get_scripts` returns
//! a single-element Vec): every patch shares one closure scope, so the
//! `Function.prototype.toString` shim and its native-source registry exist
//! exactly once and are reachable from every patch without any page-visible
//! global state. Sections run inside per-section try/catch blocks, preserving
//! the failure isolation the previous per-script injection had. CDP registers
//! the combined script via one `addScriptToEvaluateOnNewDocument` call; BiDi
//! wraps it as one preload script.

use crate::stealth::config::{accept_language_tags, StealthConfig, StealthLevel, WebrtcPolicy};

/// Returns stealth scripts for the given config.
pub fn get_scripts(config: &StealthConfig) -> Vec<String> {
    let seed = persona_seed(config);

    // Basic: webdriver + chrome_runtime
    let mut sections = vec![override_navigator_webdriver()];
    // A Firefox persona must not grow a `window.chrome` object at all.
    if !config.user_agent.contains("Firefox/") {
        sections.push(override_chrome_runtime());
    }

    if config.level == StealthLevel::Basic {
        return vec![combine(&sections)];
    }

    // StandardNoWebGL: adds canvas, audio, languages, permissions, hardware,
    //                  memory, touch points
    sections.push(randomize_canvas_fingerprint(seed));
    sections.push(randomize_audio_fingerprint(seed));
    sections.push(override_languages(&config.locale.locale));
    sections.push(override_permissions_all());
    sections.push(override_hardware_concurrency(config.hardware_concurrency));
    sections.push(override_device_memory(config.device_memory_gb));
    sections.push(override_max_touch_points(config.max_touch_points));
    if config.webrtc_policy == WebrtcPolicy::Remove {
        sections.push(override_webrtc_leak());
    }

    if config.level == StealthLevel::StandardNoWebGL {
        return vec![combine(&sections)];
    }

    // Standard: adds webgl + screen_resolution + media_devices
    sections.push(override_webgl_vendor(
        &config.webgl_vendor,
        &config.webgl_renderer,
    ));
    sections.push(override_screen_resolution(
        config.viewport.0,
        config.viewport.1,
        config.device_scale_factor.get(),
    ));
    sections.push(override_media_devices(seed));

    if config.level == StealthLevel::Standard {
        return vec![combine(&sections)];
    }

    // Full: adds timezone + performance_timing + battery
    //       + outer window size + userAgentData
    if let Some(tz) = &config.locale.timezone {
        sections.push(override_timezone(tz));
    }
    sections.push(override_performance_timing());
    sections.push(override_battery_api());
    sections.push(override_outer_size());
    if let Some(profile) = config.resolved_profile_from_user_agent() {
        if profile.full_version.is_some() {
            sections.push(override_user_agent_data(&profile, &config.client_hints));
        }
    }

    vec![combine(&sections)]
}

/// Stable per-persona seed (FNV-1a over the persona's stable identity fields).
///
/// The same persona draws the same canvas/audio noise on every page and every
/// session — a hardware cohort, not a fresh never-before-seen device per page
/// load (a per-page random seed is itself a clustering tell).
fn persona_seed(config: &StealthConfig) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    let mut feed = |bytes: &[u8]| {
        for &byte in bytes {
            hash = (hash ^ u32::from(byte)).wrapping_mul(0x0100_0193);
        }
    };
    feed(config.user_agent.as_bytes());
    feed(config.webgl_vendor.as_bytes());
    feed(config.webgl_renderer.as_bytes());
    feed(config.locale.locale.as_bytes());
    feed(&config.viewport.0.to_le_bytes());
    feed(&config.viewport.1.to_le_bytes());
    feed(&config.hardware_concurrency.to_le_bytes());
    feed(&config.device_memory_gb.to_le_bytes());
    hash
}

/// Shared prelude + one outer closure for all sections.
fn combine(sections: &[String]) -> String {
    /// Native-source registry for patched functions.
    ///
    /// Stock functions inherit `toString` from `Function.prototype`; an own
    /// `toString` property on a patched function is enumerable evidence of the
    /// patch (`Object.getOwnPropertyNames`). Instead, every replacement is
    /// registered here once and this single shim on
    /// `Function.prototype.toString` renders the native-source string for it.
    const PRELUDE: &str = r#"
const _nativeFns = new WeakMap();
const _origFnToString = Function.prototype.toString;
const _shimFnToString = { toString() {
    const spoofed = _nativeFns.get(this);
    return spoofed !== undefined ? spoofed : _origFnToString.call(this);
} }.toString;
_nativeFns.set(_shimFnToString, 'function toString() { [native code] }');
Function.prototype.toString = _shimFnToString;
// Registers `fn` to render as `function <name>() { [native code] }` and fixes
// `fn.name` to the stock binding (accessor getters are named `get <prop>`).
function _regNative(fn, name) {
    try { Object.defineProperty(fn, 'name', { value: name, configurable: true }); } catch (_) {}
    _nativeFns.set(fn, 'function ' + name + '() { [native code] }');
    return fn;
}
"#;

    let mut out = String::with_capacity(
        PRELUDE.len() + sections.iter().map(|s| s.len() + 24).sum::<usize>() + 24,
    );
    out.push_str("(function() {\n");
    out.push_str(PRELUDE);
    for section in sections {
        out.push_str("try {\n");
        out.push_str(section);
        out.push_str("\n} catch (_) {}\n");
    }
    out.push_str("})();\n");
    out
}

/// Override `navigator.webdriver` to hide automation.
///
/// Stock Chrome shape: an accessor on `Navigator.prototype` whose getter is a
/// native function (`function get webdriver() { [native code] }`) with
/// `configurable: true, enumerable: true`.
fn override_navigator_webdriver() -> String {
    r#"
    Object.defineProperty(Navigator.prototype, 'webdriver', {
        get: _regNative(() => false, 'get webdriver'),
        enumerable: true,
        configurable: true,
    });
    "#
    .to_string()
}

/// Provide `window.chrome` where the runtime lacks one.
///
/// A real Chrome (including headless=new) already exposes a genuine
/// `window.chrome` with real `csi()`/`loadTimes()` timing data — that native
/// object is always better than a fake, so this script only fills in what is
/// missing. The fallback computes its values from `performance.timing` of the
/// current document: `startE`/`onloadT`/`*LoadTime` are fixed load-epoch
/// constants (0 before the corresponding event, exactly like stock), and
/// `csi().pageT` is the real Chrome formula, the call-time distance from
/// navigation start.
fn override_chrome_runtime() -> String {
    r#"
    const _timing = (typeof performance !== 'undefined' && performance.timing) || null;
    const _navStart = (_timing && _timing.navigationStart)
        || (typeof performance !== 'undefined' && performance.timeOrigin)
        || Date.now();
    const _firstPaintTime = () => {
        try {
            const entries = performance.getEntriesByType('paint');
            for (let i = 0; i < entries.length; i++) {
                if (entries[i].name === 'first-paint') {
                    return entries[i].startTime ? (_navStart + entries[i].startTime) / 1000 : 0;
                }
            }
        } catch (_) {}
        return 0;
    };
    const _navigationType = () => {
        try {
            switch (performance.navigation.type) {
                case 1: return 'Reload';
                case 2: return 'BackForward';
                default: return 'Other';
            }
        } catch (_) {
            return 'Other';
        }
    };
    const _chromeApp = {
        isInstalled: false,
        InstallState: {
            INSTALLED: 'installed',
            NOT_INSTALLED: 'not_installed',
            DISABLED: 'disabled',
        },
        RunningState: {
            RUNNING: 'running',
            CANNOT_RUN: 'cannot_run',
            READY_TO_RUN: 'ready_to_run',
        },
        getDetails: function() { return null; },
        getIsInstalled: function() { return false; },
        installState: function(cb) { if (cb) cb('not_installed'); },
    };
    const _chromeCsi = _regNative(() => ({
        onloadT: (_timing && _timing.loadEventStart) || 0,
        pageT: Math.max(0, Date.now() - _navStart),
        startE: _navStart,
        tran: 15,
    }), 'csi');
    const _chromeLoadTimes = _regNative(() => ({
        commitLoadTime: ((_timing && _timing.responseStart) || _navStart) / 1000,
        connectionInfo: 'h2',
        finishDocumentLoadTime: (_timing && _timing.domContentLoadedEventEnd)
            ? _timing.domContentLoadedEventEnd / 1000
            : 0,
        finishLoadTime: (_timing && _timing.loadEventEnd) ? _timing.loadEventEnd / 1000 : 0,
        firstPaintAfterLoadTime: 0,
        firstPaintTime: _firstPaintTime(),
        navigationType: _navigationType(),
        npnNegotiatedProtocol: 'h2',
        requestTime: ((_timing && _timing.requestStart) || _navStart) / 1000,
        startLoadTime: _navStart / 1000,
        wasAlternateProtocolAvailable: false,
        wasFetchedViaSpdy: true,
        wasNpnNegotiated: true,
    }), 'loadTimes');
    const _chromeRuntime = {
        OnInstalledReason: {
            CHROME_UPDATE: 'chrome_update',
            INSTALL: 'install',
            SHARED_MODULE_UPDATE: 'shared_module_update',
            UPDATE: 'update',
        },
        OnRestartRequiredReason: {
            APP_UPDATE: 'app_update',
            OS_UPDATE: 'os_update',
            PERIODIC: 'periodic',
        },
        PlatformArch: {
            ARM: 'arm',
            MIPS: 'mips',
            MIPS64: 'mips64',
            X86_32: 'x86-32',
            X86_64: 'x86-64',
        },
        PlatformNaclArch: {
            ARM: 'arm',
            MIPS: 'mips',
            MIPS64: 'mips64',
            X86_32: 'x86-32',
            X86_64: 'x86-64',
        },
        PlatformOs: {
            ANDROID: 'android',
            CROS: 'cros',
            LINUX: 'linux',
            MAC: 'mac',
            OPENBSD: 'openbsd',
            WIN: 'win',
        },
        RequestUpdateCheckStatus: {
            NO_UPDATE: 'no_update',
            THROTTLED: 'throttled',
            UPDATE_AVAILABLE: 'update_available',
        },
        connect: function() {
            return {
                onDisconnect: { addListener: function() {} },
                onMessage: { addListener: function() {} },
                postMessage: function() {},
                disconnect: function() {},
            };
        },
        sendMessage: function() {},
        id: undefined,
    };
    if (typeof window.chrome === 'undefined') {
        // Stock: own data property of window, writable, NON-enumerable,
        // configurable.
        Object.defineProperty(window, 'chrome', {
            value: {
                app: _chromeApp,
                csi: _chromeCsi,
                loadTimes: _chromeLoadTimes,
                runtime: _chromeRuntime,
            },
            writable: true,
            enumerable: false,
            configurable: true,
        });
    } else {
        if (!window.chrome.app) window.chrome.app = _chromeApp;
        if (!window.chrome.csi) window.chrome.csi = _chromeCsi;
        if (!window.chrome.loadTimes) window.chrome.loadTimes = _chromeLoadTimes;
        if (!window.chrome.runtime) window.chrome.runtime = _chromeRuntime;
    }
    "#
    .to_string()
}

/// Add slight noise to canvas pixel data to randomise the fingerprint.
///
/// The noise is seeded from the persona's stable identity fields (see
/// [`persona_seed`]), so one persona produces one stable canvas hash — a
/// hardware cohort. Repeated calls stay consistent within a session:
/// randomising on every call is itself a detectable pattern, since real
/// browsers return identical canvas output for identical drawing operations.
fn randomize_canvas_fingerprint(seed: u32) -> String {
    r#"
    (function() {
        // Persona-cohort seed — stable for this persona across pages/sessions.
        const _seed = __SEED__ >>> 0;
        // Simple xorshift32 — fast, deterministic, non-cryptographic.
        function xorshift(n) {
            n ^= n << 13; n ^= n >>> 17; n ^= n << 5;
            return (n >>> 0);
        }
        // Map seed + pixel index to a stable offset in {-1, 0, +1}.
        function pixelOffset(idx) {
            return (xorshift(_seed ^ (idx * 1664525 + 1013904223)) % 3) - 1;
        }

        const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
        const patchedGetImageData = _regNative({ getImageData() {
            const imageData = origGetImageData.apply(this, arguments);
            for (let i = 0; i < imageData.data.length; i += 4) {
                const delta = pixelOffset(i);
                imageData.data[i] = Math.max(0, Math.min(255, imageData.data[i] + delta));
            }
            return imageData;
        } }.getImageData, 'getImageData');
        CanvasRenderingContext2D.prototype.getImageData = patchedGetImageData;

        const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
        const patchedToDataURL = _regNative({ toDataURL() {
            const ctx = this.getContext('2d');
            if (ctx) {
                // Stable 1x1 pixel draw — same value every call for this persona.
                const alpha = ((xorshift(_seed) % 10) + 1) / 1000;
                ctx.fillStyle = 'rgba(0,0,0,' + alpha + ')';
                ctx.fillRect(0, 0, 1, 1);
            }
            return origToDataURL.apply(this, arguments);
        } }.toDataURL, 'toDataURL');
        HTMLCanvasElement.prototype.toDataURL = patchedToDataURL;

        const origToBlob = HTMLCanvasElement.prototype.toBlob;
        if (origToBlob) {
            const patchedToBlob = _regNative({ toBlob(callback) {
                const ctx = this.getContext('2d');
                if (ctx) {
                    const alpha = ((xorshift(_seed) % 10) + 1) / 1000;
                    ctx.fillStyle = 'rgba(0,0,0,' + alpha + ')';
                    ctx.fillRect(0, 0, 1, 1);
                }
                return origToBlob.apply(this, arguments);
            } }.toBlob, 'toBlob');
            HTMLCanvasElement.prototype.toBlob = patchedToBlob;
        }
    })();
    "#
    .replace("__SEED__", &seed.to_string())
}

/// Add slight noise to the two dominant AudioContext fingerprinting
/// techniques (analyser-based and offline-render-based).
///
/// **This is mitigation, not verification.** Unlike the canvas noise above,
/// there is no "correct" audio fingerprint for a persona to match — real
/// browsers on real hardware naturally vary here. The goal is only to break
/// exact hash stability *across personas* while remaining stable *within* a
/// persona, following the same persona-seeded pattern as
/// `randomize_canvas_fingerprint`. It does not make a probe-checkable claim
/// about what the persona's audio stack should report.
///
/// Two entry points are patched, mirroring the two techniques fingerprint
/// scripts actually use: `AnalyserNode.prototype.getFloatFrequencyData`
/// (oscillator + analyser technique) and `OfflineAudioContext.prototype.
/// startRendering` (render-then-hash technique, perturbed on the resolved
/// `AudioBuffer`'s channel data).
fn randomize_audio_fingerprint(seed: u32) -> String {
    r#"
    (function() {
        // Persona-cohort seed — stable for this persona across pages/sessions.
        const _seed = __SEED__ >>> 0;
        function xorshift(n) {
            n ^= n << 13; n ^= n >>> 17; n ^= n << 5;
            return (n >>> 0);
        }
        // Small noise, deterministic per (seed, sample index) within a
        // persona: enough to move a hash, not enough to be audible or to
        // break legitimate audio analysis.
        function sampleOffset(idx) {
            return ((xorshift(_seed ^ (idx * 2654435761)) % 1000) - 500) / 1000000;
        }

        if (typeof AnalyserNode !== 'undefined') {
            const origGetFloatFrequencyData = AnalyserNode.prototype.getFloatFrequencyData;
            AnalyserNode.prototype.getFloatFrequencyData = _regNative({ getFloatFrequencyData(array) {
                origGetFloatFrequencyData.call(this, array);
                for (let i = 0; i < array.length; i++) {
                    array[i] += sampleOffset(i);
                }
            } }.getFloatFrequencyData, 'getFloatFrequencyData');
        }

        if (typeof OfflineAudioContext !== 'undefined') {
            const origStartRendering = OfflineAudioContext.prototype.startRendering;
            OfflineAudioContext.prototype.startRendering = _regNative({ startRendering() {
                const result = origStartRendering.apply(this, arguments);
                if (result && typeof result.then === 'function') {
                    return result.then(function(buffer) {
                        for (let channel = 0; channel < buffer.numberOfChannels; channel++) {
                            const data = buffer.getChannelData(channel);
                            for (let i = 0; i < data.length; i++) {
                                data[i] += sampleOffset(i);
                            }
                        }
                        return buffer;
                    });
                }
                return result;
            } }.startRendering, 'startRendering');
        }
    })();
    "#
    .replace("__SEED__", &(seed ^ 0x9E37_79B9).to_string())
}

/// Override `navigator.languages` with Chrome's expansion of `locale`.
///
/// The tag list is the same expansion [`accept_language_tags`] produces for
/// the `--accept-lang` launch flag, so JS and the HTTP header always agree.
/// Stock Chrome returns the same frozen array instance on every access.
fn override_languages(locale: &str) -> String {
    let tags = serde_json::to_string(&accept_language_tags(locale))
        .expect("language tags are JSON serializable");
    r#"
    const _languages = Object.freeze(__LANGS__);
    Object.defineProperty(Navigator.prototype, 'languages', {
        get: _regNative(() => _languages, 'get languages'),
        enumerable: true,
        configurable: true,
    });
    "#
    .replace("__LANGS__", &tags)
}

/// Set `navigator.hardwareConcurrency` to `cores`.
///
/// The accessor lives on `Navigator.prototype` (as in stock Chrome), not on
/// the `navigator` instance — a per-instance own property fails
/// `navigator.hasOwnProperty('hardwareConcurrency')` diffs.
fn override_hardware_concurrency(cores: u32) -> String {
    format!(
        r#"
    Object.defineProperty(Navigator.prototype, 'hardwareConcurrency', {{
        get: _regNative(() => {cores}, 'get hardwareConcurrency'),
        enumerable: true,
        configurable: true,
    }});
    "#
    )
}

/// Set `navigator.deviceMemory` to `gb` GB.
fn override_device_memory(gb: u32) -> String {
    format!(
        r#"
    Object.defineProperty(Navigator.prototype, 'deviceMemory', {{
        get: _regNative(() => {gb}, 'get deviceMemory'),
        enumerable: true,
        configurable: true,
    }});
    "#
    )
}

/// Set `navigator.maxTouchPoints` to `points`.
///
/// The CDP `Emulation.setTouchEmulationEnabled` call already sets this as a
/// side effect on the CDP backend's main frame, but relying on the side
/// effect alone leaves two gaps: prototype-chain diffing
/// (`Object.getOwnPropertyDescriptor(Navigator.prototype, 'maxTouchPoints')`)
/// can still see a native, non-overridden descriptor if the emulation call
/// races script injection, and the BiDi/Firefox backend has no equivalent
/// native call at all. Patching `Navigator.prototype` directly closes both
/// gaps and matches the pattern used for `hardwareConcurrency`/`deviceMemory`.
fn override_max_touch_points(points: u8) -> String {
    format!(
        r#"
    Object.defineProperty(Navigator.prototype, 'maxTouchPoints', {{
        get: _regNative(() => {points}, 'get maxTouchPoints'),
        enumerable: true,
        configurable: true,
    }});
    "#
    )
}

/// Spoof WebGL vendor/renderer strings per the configured device class.
///
/// NOTE: this only overrides the two *queried* strings
/// (`UNMASKED_VENDOR_WEBGL` / `UNMASKED_RENDERER_WEBGL`). The underlying GL
/// pipeline (extension list, shader precision, draw-call timing) is still
/// the real host GPU regardless of what these two strings report — a deep
/// WebGL probe can still distinguish a mobile persona from the real desktop
/// GPU behind it. Closing that gap needs a real mobile GPU/runtime, not a
/// string override (see the plan's Phase 3 / `dig2browser-runtime-android`).
fn override_webgl_vendor(vendor: &str, renderer: &str) -> String {
    let vendor = serde_json::to_string(vendor).expect("WebGL vendor string is JSON serializable");
    let renderer =
        serde_json::to_string(renderer).expect("WebGL renderer string is JSON serializable");
    r#"
    (function() {
        function patchGetParameter(ctx) {
            const orig = ctx.prototype.getParameter;
            ctx.prototype.getParameter = _regNative({ getParameter(parameter) {
                const debugInfo = this.getExtension('WEBGL_debug_renderer_info');
                if (debugInfo) {
                    if (parameter === debugInfo.UNMASKED_VENDOR_WEBGL) {
                        return __VENDOR__;
                    }
                    if (parameter === debugInfo.UNMASKED_RENDERER_WEBGL) {
                        return __RENDERER__;
                    }
                }
                return orig.apply(this, arguments);
            } }.getParameter, 'getParameter');
        }
        patchGetParameter(WebGLRenderingContext);
        if (typeof WebGL2RenderingContext !== 'undefined') {
            patchGetParameter(WebGL2RenderingContext);
        }
    })();
    "#
    .replace("__VENDOR__", &vendor)
    .replace("__RENDERER__", &renderer)
}

/// Override `screen.width/height/availWidth/availHeight` to `width × height`.
///
/// The accessors live on `Screen.prototype` (as in stock Chrome), not on the
/// `screen` instance — per-instance own properties are visible to
/// instance-vs-prototype descriptor diffs.
///
/// `availHeight` is evaluated in Rust (not via a JS expression) to avoid any
/// ambiguity with operator precedence in minified contexts. The configured
/// `devicePixelRatio` is shared with the native CDP metrics override.
///
/// NOTE: On the CDP backend this script is superseded by a native
/// `Emulation.setDeviceMetricsOverride` call which is more reliable (survives
/// CSS media query checks, affects visual viewport). The JS override remains
/// here for the BiDi/Firefox backend where no CDP equivalent is available.
fn override_screen_resolution(width: u32, height: u32, device_scale_factor: f64) -> String {
    let avail_height = height.saturating_sub(40);
    format!(
        r#"
    Object.defineProperty(Screen.prototype, 'width', {{
        get: _regNative(() => {width}, 'get width'),
        enumerable: true,
        configurable: true,
    }});
    Object.defineProperty(Screen.prototype, 'height', {{
        get: _regNative(() => {height}, 'get height'),
        enumerable: true,
        configurable: true,
    }});
    Object.defineProperty(Screen.prototype, 'availWidth', {{
        get: _regNative(() => {width}, 'get availWidth'),
        enumerable: true,
        configurable: true,
    }});
    Object.defineProperty(Screen.prototype, 'availHeight', {{
        get: _regNative(() => {avail_height}, 'get availHeight'),
        enumerable: true,
        configurable: true,
    }});
    Object.defineProperty(window, 'devicePixelRatio', {{
        get: _regNative(() => {device_scale_factor}, 'get devicePixelRatio'),
        enumerable: true,
        configurable: true,
    }});
    "#
    )
}

/// Delete `RTCPeerConnection` so it is entirely absent.
///
/// Runs at the fingerprint tier (`StandardNoWebGL` and above — see
/// `get_scripts`) whenever `StealthConfig::webrtc_policy` is
/// `WebrtcPolicy::Remove`. This is a persona-realism behavior, not a
/// `StealthLevel::Full`-only extra: a privacy-cohort persona's real browser
/// authentically has no `RTCPeerConnection`, so its compiled persona sets
/// `webrtc_policy = Remove` and this call makes that declaration take
/// effect at the tier personas actually run at (`Standard`).
///
/// `WebrtcPolicy::Retain` skips this call so `RTCPeerConnection` stays
/// present, matching a real browser for every other persona. Containing the
/// IP-leak surface of a *present* `RTCPeerConnection` (real ICE candidates)
/// is the isolation engine's job (WFP kernel egress containment), not this
/// script's — this function only ever removes or leaves the API alone.
fn override_webrtc_leak() -> String {
    r#"
    window.RTCPeerConnection = undefined;
    // Use delete rather than assigning undefined to avoid creating an own property
    // on window where none existed (detectable via hasOwnProperty).
    try { delete window.webkitRTCPeerConnection; } catch (_) {}
    "#
    .to_string()
}

/// Override `Intl.DateTimeFormat.resolvedOptions` to report timezone `tz`.
///
/// The patch replaces the prototype method once instead of replacing the
/// `Intl.DateTimeFormat` constructor: the native constructor, its
/// `supportedLocalesOf` and its per-instance prototype chain all stay intact.
///
/// NOTE: On the CDP backend this is superseded by `Emulation.setTimezoneOverride`
/// which also fixes `new Date().toString()`. The JS override is kept for the
/// BiDi/Firefox backend where no native CDP equivalent is available.
fn override_timezone(tz: &str) -> String {
    let tz = serde_json::to_string(tz).expect("timezone is JSON serializable");
    r#"
    if (typeof Intl !== 'undefined' && Intl.DateTimeFormat) {
        const _origResolvedOptions = Intl.DateTimeFormat.prototype.resolvedOptions;
        Intl.DateTimeFormat.prototype.resolvedOptions = _regNative({ resolvedOptions() {
            const options = _origResolvedOptions.call(this);
            options.timeZone = __TZ__;
            return options;
        } }.resolvedOptions, 'resolvedOptions');
    }
    "#
    .replace("__TZ__", &tz)
}

/// Fake a realistic device list on `navigator.mediaDevices.enumerateDevices`.
///
/// The `MediaDevices` instance itself is left native (it is an `EventTarget`
/// subclass with real methods); only `enumerateDevices` is patched on
/// `MediaDevices.prototype`. A VM with no audio/video hardware otherwise
/// returns an empty list — a rarity on real desktops. The returned entries
/// are `MediaDeviceInfo`-chained objects with empty labels, matching a
/// browser that has not been granted media permission. Device and group IDs
/// are persona-seeded: stable for the persona, different across personas.
fn override_media_devices(seed: u32) -> String {
    r#"
    (function() {
        if (typeof MediaDevices === 'undefined' || typeof MediaDeviceInfo === 'undefined') return;
        // Persona-seeded hex ids — stable for this persona across sessions.
        let _idState = __SEED__ >>> 0;
        function _hex(len) {
            let s = '';
            for (let i = 0; i < len; i++) {
                _idState ^= _idState << 13; _idState ^= _idState >>> 17; _idState ^= _idState << 5; _idState >>>= 0;
                s += '0123456789abcdef'[_idState % 16];
            }
            return s;
        }
        const _devices = [
            { deviceId: 'default', kind: 'audioinput', label: '', groupId: _hex(64) },
            { deviceId: 'communications', kind: 'audioinput', label: '', groupId: _hex(64) },
            { deviceId: _hex(64), kind: 'videoinput', label: '', groupId: _hex(64) },
            { deviceId: 'default', kind: 'audiooutput', label: '', groupId: _hex(64) },
        ];
        MediaDevices.prototype.enumerateDevices = _regNative({ enumerateDevices() {
            return Promise.resolve(_devices.map(function(d) {
                const info = Object.create(MediaDeviceInfo.prototype);
                Object.defineProperties(info, {
                    deviceId: { value: d.deviceId },
                    kind: { value: d.kind },
                    label: { value: d.label },
                    groupId: { value: d.groupId },
                });
                return info;
            }));
        } }.enumerateDevices, 'enumerateDevices');
    })();
    "#
    .replace("__SEED__", &(seed ^ 0x3C6E_F35F).to_string())
}

/// Add small deterministic offsets to the clock readings pages can observe.
///
/// One time source, one offset schedule: `Date.now`, `Date.prototype.getTime`/
/// `valueOf` and `performance.now` each read their native clock and add the
/// SAME offset, so the three never disagree within a tick (the previous
/// version noised `getTime` but not `Date.now`, a ±6 ms in-tick contradiction).
///
/// Monotonicity: the offset is a non-decreasing ratchet of a deterministic
/// per-10 ms-bucket jitter (0..9 ms). Within a bucket the offset is constant;
/// across a boundary it can only grow, so `performance.now` keeps its
/// strict-monotonic contract and `Date.now` stays non-decreasing — unlike a
/// signed ±5 ms noise, which steps backwards at bucket edges.
fn override_performance_timing() -> String {
    r#"
    (function() {
        const _BUCKET_MS = 10;
        let _offset = 0;
        function _timeOffset(rawMs) {
            const bucket = Math.floor(rawMs / _BUCKET_MS);
            let h = Math.imul(bucket ^ 0x9E3779B9, 2654435761) >>> 0;
            h ^= h >>> 13;
            const jitter = h % _BUCKET_MS;
            if (jitter > _offset) _offset = jitter;
            return _offset;
        }

        const _origDateNow = Date.now;
        Date.now = _regNative({ now() {
            const t = _origDateNow();
            return t + _timeOffset(t);
        } }.now, 'now');

        const _origGetTime = Date.prototype.getTime;
        Date.prototype.getTime = _regNative({ getTime() {
            const t = _origGetTime.call(this);
            return t + _timeOffset(t);
        } }.getTime, 'getTime');

        const _origValueOf = Date.prototype.valueOf;
        Date.prototype.valueOf = _regNative({ valueOf() {
            const t = _origValueOf.call(this);
            return t + _timeOffset(t);
        } }.valueOf, 'valueOf');

        if (typeof Performance !== 'undefined' && Performance.prototype && Performance.prototype.now) {
            const _origPerfNow = Performance.prototype.now;
            Performance.prototype.now = _regNative({ now() {
                const t = _origPerfNow.call(this);
                return t + _timeOffset(t);
            } }.now, 'now');
        }
    })();
    "#
    .to_string()
}

/// Override `navigator.getBattery` to return a fully-charged static profile.
///
/// Guard: Chrome 113+ removed the Battery Status API, so `navigator.getBattery`
/// is `undefined` on modern Chrome. We only override if the API is present;
/// creating a fake `getBattery` where none existed is more suspicious than
/// leaving it absent.
fn override_battery_api() -> String {
    r#"
    if (typeof navigator.getBattery === 'function') {
        Object.defineProperty(Navigator.prototype, 'getBattery', {
            value: _regNative({ getBattery() {
                return Promise.resolve({
                    charging: true,
                    chargingTime: 0,
                    dischargingTime: Infinity,
                    level: 1.0,
                    addEventListener: function() {},
                    removeEventListener: function() {},
                });
            } }.getBattery, 'getBattery'),
            writable: true,
            configurable: true,
        });
    }
    "#
    .to_string()
}

/// Keep `window.outerWidth` / `window.outerHeight` above the inner size.
///
/// A real desktop window always carries a browser frame around the viewport
/// (~85-130 px of tab strip, toolbar and window border on the height axis, a
/// few px of window border on the width axis). Headless Chrome used to report
/// 0; with `--headless=new` + a device-metrics override it reports
/// inner == outer, which is the same headless tell in a different shape. The
/// override is therefore unconditional, and the getters track the live inner
/// size like a real window does.
fn override_outer_size() -> String {
    r#"
    Object.defineProperty(window, 'outerWidth', {
        get: _regNative(() => window.innerWidth + 16, 'get outerWidth'),
        enumerable: true,
        configurable: true,
    });
    Object.defineProperty(window, 'outerHeight', {
        get: _regNative(() => window.innerHeight + 104, 'get outerHeight'),
        enumerable: true,
        configurable: true,
    });
    "#
    .to_string()
}

/// Override `navigator.userAgentData` (User-Agent Client Hints API).
///
/// Modern Chrome exposes this object. Sites like Yandex check
/// `navigator.userAgentData.brands` and `.platform`. Headless Chrome may
/// return a minimal or incorrect object; we provide a realistic profile.
///
/// NOTE: On the CDP backend this is superseded by `Emulation.setUserAgentOverride`
/// with `userAgentMetadata` which sets Client Hints natively (including HTTP headers).
/// This JS version remains for the BiDi/Firefox backend.
fn override_user_agent_data(
    profile: &crate::stealth::config::UserAgentProfile,
    client_hints: &crate::stealth::config::ClientHintsProfile,
) -> String {
    let brands = profile
        .brands()
        .unwrap_or_default()
        .into_iter()
        .map(|(brand, version)| serde_json::json!({ "brand": brand, "version": version }))
        .collect::<Vec<_>>();
    let full_version_list = profile
        .full_version_list()
        .unwrap_or_default()
        .into_iter()
        .map(|(brand, version)| serde_json::json!({ "brand": brand, "version": version }))
        .collect::<Vec<_>>();
    let brands = serde_json::to_string(&brands).expect("UA brands are JSON serializable");
    let full_version_list = serde_json::to_string(&full_version_list)
        .expect("UA full version list is JSON serializable");
    let full_version = serde_json::to_string(profile.full_version.as_deref().unwrap_or_default())
        .expect("UA version is JSON serializable");
    let platform = serde_json::to_string(client_hints.platform())
        .expect("UA platform is JSON serializable");
    let platform_version = serde_json::to_string(client_hints.platform_version())
        .expect("UA platform version is JSON serializable");
    let architecture = serde_json::to_string(client_hints.architecture())
        .expect("UA architecture is JSON serializable");
    let model = serde_json::to_string(client_hints.model())
        .expect("UA model is JSON serializable");
    let mobile = client_hints.mobile().to_string();

    r#"
    if (!navigator.userAgentData) {
        const _uaData = {
            brands: __BRANDS__,
            mobile: __MOBILE__,
            platform: __PLATFORM__,
            getHighEntropyValues: _regNative((hints) => Promise.resolve({
                architecture: __ARCHITECTURE__,
                bitness: '64',
                brands: __BRANDS__,
                fullVersionList: __FULL_VERSION_LIST__,
                mobile: __MOBILE__,
                model: __MODEL__,
                platform: __PLATFORM__,
                platformVersion: __PLATFORM_VERSION__,
                uaFullVersion: __FULL_VERSION__,
            }), 'getHighEntropyValues'),
            toJSON: _regNative(() => ({
                brands: _uaData.brands,
                mobile: _uaData.mobile,
                platform: _uaData.platform,
            }), 'toJSON'),
        };
        Object.defineProperty(Navigator.prototype, 'userAgentData', {
            get: _regNative(() => _uaData, 'get userAgentData'),
            configurable: true,
            enumerable: true,
        });
    }
    "#
    .replace("__BRANDS__", &brands)
    .replace("__FULL_VERSION_LIST__", &full_version_list)
    .replace("__FULL_VERSION__", &full_version)
    .replace("__MOBILE__", &mobile)
    .replace("__PLATFORM__", &platform)
    .replace("__PLATFORM_VERSION__", &platform_version)
    .replace("__ARCHITECTURE__", &architecture)
    .replace("__MODEL__", &model)
}

/// Override `navigator.permissions.query` to handle all permission types.
///
/// The previous implementation only handled `notifications`. Yandex SmartCaptcha
/// tests multiple permission types (`clipboard-read`, `push`, `midi`, etc.).
/// Return `prompt` state for unknown permissions so behaviour matches a real
/// browser that has not yet been asked for those permissions.
///
/// The patch replaces `Permissions.prototype.query` (stock location) rather
/// than assigning an own method onto the `navigator.permissions` instance,
/// and the resolved status objects chain to `PermissionStatus.prototype`.
fn override_permissions_all() -> String {
    r#"
    if (typeof Permissions !== 'undefined' && Permissions.prototype && Permissions.prototype.query) {
        const _fakePermissionStatus = (name, state) => {
            if (typeof PermissionStatus === 'undefined') {
                return { name: name, state: state, onchange: null };
            }
            const status = Object.create(PermissionStatus.prototype);
            Object.defineProperties(status, {
                name: { value: name, enumerable: true },
                state: { value: state, enumerable: true },
                onchange: { value: null, enumerable: true },
            });
            return status;
        };
        Permissions.prototype.query = _regNative({ query(parameters) {
            const name = parameters && parameters.name;
            if (name === 'notifications') {
                return Promise.resolve(_fakePermissionStatus(name,
                    (typeof Notification !== 'undefined') ? Notification.permission : 'default'));
            }
            return Promise.resolve(_fakePermissionStatus(name, 'prompt'));
        } }.query, 'query');
    }
    "#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn screen_script_uses_configured_viewport_and_scale_factor() {
        let mut config = StealthConfig {
            viewport: (393, 852),
            ..Default::default()
        };
        config.set_device_scale_factor(3.0).unwrap();

        let scripts = get_scripts(&config).join("\n");

        assert!(scripts.contains("Object.defineProperty(Screen.prototype, 'width',"));
        assert!(scripts.contains("get: _regNative(() => 393, 'get width')"));
        assert!(scripts.contains("get: _regNative(() => 852, 'get height')"));
        assert!(scripts.contains("get: _regNative(() => 812, 'get availHeight')"));
        assert!(scripts.contains("get: _regNative(() => 3, 'get devicePixelRatio')"));
    }

    /// Proves the removal-gating fix: `webrtc_policy` now takes effect at
    /// `StealthLevel::Standard` (the level personas actually run at), not
    /// only at `Full`.
    #[test]
    fn webrtc_removal_is_gated_on_policy_at_standard_level() {
        let mut config = StealthConfig {
            level: StealthLevel::Standard,
            webrtc_policy: WebrtcPolicy::Remove,
            ..Default::default()
        };
        let removed = get_scripts(&config).join("\n");
        assert!(removed.contains("window.RTCPeerConnection = undefined"));

        config.webrtc_policy = WebrtcPolicy::Retain;
        let retained = get_scripts(&config).join("\n");
        assert!(!retained.contains("window.RTCPeerConnection = undefined"));
    }

    /// All patches share one script and one `Function.prototype.toString`
    /// shim; no patched function carries an own `toString` property.
    #[test]
    fn scripts_are_one_combined_unit_sharing_a_single_tostring_shim() {
        let config = StealthConfig {
            level: StealthLevel::Full,
            ..Default::default()
        };
        let scripts = get_scripts(&config);
        assert_eq!(scripts.len(), 1, "all patches combine into one script");
        let js = &scripts[0];
        assert_eq!(js.matches("Function.prototype.toString = ").count(), 1);
        assert!(
            !js.contains("Object.defineProperty(patched"),
            "patched functions must not carry an own toString"
        );
    }

    /// Stock descriptor shape: `webdriver` is an accessor on
    /// `Navigator.prototype`, configurable + enumerable, with a
    /// native-looking getter.
    #[test]
    fn webdriver_accessor_has_the_stock_descriptor_shape() {
        let js = get_scripts(&StealthConfig::default()).join("\n");
        assert!(js.contains("Object.defineProperty(Navigator.prototype, 'webdriver', {"));
        assert!(js.contains("get: _regNative(() => false, 'get webdriver')"));
        assert!(js.contains("enumerable: true"));
        assert!(js.contains("configurable: true"));
        assert!(!js.contains("configurable: false"));
    }

    /// Instance-level patches that failed `hasOwnProperty` diffs are gone;
    /// `navigator.plugins`/`navigator.connection` are no longer faked at all
    /// (stock Chrome ships a real PluginArray and NetworkInformation, and the
    /// BiDi/Firefox backend authentically lacks `connection`).
    #[test]
    fn navigator_members_live_on_the_prototype_and_fakes_are_gone() {
        let js = get_scripts(&StealthConfig {
            level: StealthLevel::Full,
            ..Default::default()
        })
        .join("\n");
        for prop in ["languages", "hardwareConcurrency", "deviceMemory", "maxTouchPoints"] {
            assert!(
                js.contains(&format!("Object.defineProperty(Navigator.prototype, '{prop}',")),
                "{prop} must be defined on Navigator.prototype"
            );
        }
        assert!(!js.contains("Object.defineProperty(navigator,"));
        assert!(!js.contains("navigator, 'plugins'"));
        assert!(!js.contains("navigator, 'connection'"));
        assert!(js.contains("MediaDevices.prototype.enumerateDevices"));
        assert!(js.contains("Permissions.prototype.query"));
        assert!(js.contains("Performance.prototype.now"));
    }

    /// `navigator.languages` uses Chrome's Accept-Language expansion — the
    /// same list the `--accept-lang` launch flag carries.
    #[test]
    fn languages_mirror_chrome_accept_language_expansion() {
        let en = get_scripts(&StealthConfig::default()).join("\n");
        assert!(en.contains(r#"Object.freeze(["en-US","en"])"#));

        let ru = get_scripts(&StealthConfig {
            locale: crate::stealth::config::LocaleProfile::russian(),
            ..Default::default()
        })
        .join("\n");
        assert!(ru.contains(r#"Object.freeze(["ru-RU","ru","en-US","en"])"#));
    }

    /// A Firefox persona must not grow a `window.chrome` object.
    #[test]
    fn firefox_user_agent_skips_the_chrome_runtime_patch() {
        let firefox = get_scripts(&StealthConfig {
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0".into(),
            ..Default::default()
        })
        .join("\n");
        assert!(!firefox.contains("window.chrome"));

        let chrome = get_scripts(&StealthConfig::default()).join("\n");
        assert!(chrome.contains("window.chrome"));
    }
}
