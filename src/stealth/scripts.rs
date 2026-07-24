//! JS script generators for anti-detection overrides.

use crate::stealth::config::{StealthConfig, StealthLevel, WebrtcPolicy};

/// Returns stealth scripts for the given config.
pub fn get_scripts(config: &StealthConfig) -> Vec<String> {
    let mut scripts = Vec::new();

    // Basic: webdriver + chrome_runtime
    scripts.push(override_navigator_webdriver());
    scripts.push(override_chrome_runtime());

    if config.level == StealthLevel::Basic {
        return scripts;
    }

    // StandardNoWebGL: adds canvas, audio, plugins, languages, permissions,
    //                  hardware, memory, touch points, connection
    scripts.push(randomize_canvas_fingerprint());
    scripts.push(randomize_audio_fingerprint());
    scripts.push(override_plugins());
    scripts.push(override_languages(&config.locale.locale));
    scripts.push(override_permissions_all());
    scripts.push(override_hardware_concurrency(config.hardware_concurrency));
    scripts.push(override_device_memory(config.device_memory_gb));
    scripts.push(override_max_touch_points(config.max_touch_points));
    if config.webrtc_policy == WebrtcPolicy::Remove {
        scripts.push(override_webrtc_leak());
    }
    scripts.push(override_connection_info());

    if config.level == StealthLevel::StandardNoWebGL {
        return scripts;
    }

    // Standard: adds webgl + screen_resolution
    scripts.push(override_webgl_vendor(&config.webgl_vendor, &config.webgl_renderer));
    scripts.push(override_screen_resolution(
        config.viewport.0,
        config.viewport.1,
        config.device_scale_factor.get(),
    ));

    if config.level == StealthLevel::Standard {
        return scripts;
    }

    // Full: adds timezone + media_devices + performance_timing + battery
    //       + outer window size + userAgentData
    if let Some(tz) = &config.locale.timezone {
        scripts.push(override_timezone(tz));
    }
    scripts.push(override_media_devices());
    scripts.push(override_performance_timing());
    scripts.push(override_battery_api());
    scripts.push(override_outer_size());
    if let Some(profile) = config.resolved_profile_from_user_agent() {
        if profile.full_version.is_some() {
            scripts.push(override_user_agent_data(&profile, &config.client_hints));
        }
    }

    scripts
}

/// Override `navigator.webdriver` to hide automation.
///
/// Patches `Navigator.prototype` (not the instance) with `configurable: false`
/// so that anti-bot scripts inspecting the prototype descriptor see the same
/// shape as a real browser rather than detecting a per-instance override.
fn override_navigator_webdriver() -> String {
    r#"
    try {
        delete navigator.__proto__.webdriver;
    } catch (_) {}
    Object.defineProperty(Navigator.prototype, 'webdriver', {
        get: () => false,
        configurable: false,
        enumerable: true,
    });
    "#
    .to_string()
}

/// Fake `window.chrome` to mimic a real Chrome/Edge browser.
///
/// Detection scripts check for `chrome.app`, `chrome.csi()`, `chrome.loadTimes()`,
/// and `chrome.runtime.id`. An empty `{}` for runtime is immediately suspicious.
fn override_chrome_runtime() -> String {
    r#"
    window.chrome = {
        app: {
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
        },
        csi: function() {
            return {
                onloadT: Date.now(),
                startE: Date.now(),
                pageT: Date.now(),
                tran: 15,
            };
        },
        loadTimes: function() {
            return {
                commitLoadTime: Date.now() / 1000,
                connectionInfo: 'h2',
                finishDocumentLoadTime: 0,
                finishLoadTime: 0,
                firstPaintAfterLoadTime: 0,
                firstPaintTime: 0,
                navigationType: 'Other',
                npnNegotiatedProtocol: 'h2',
                requestTime: Date.now() / 1000,
                startLoadTime: Date.now() / 1000,
                wasAlternateProtocolAvailable: false,
                wasFetchedViaSpdy: true,
                wasNpnNegotiated: true,
            };
        },
        runtime: {
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
        },
    };
    "#
    .to_string()
}

/// Add slight noise to canvas pixel data to randomise the fingerprint.
///
/// Uses a deterministic per-session seed (computed once at injection time) so
/// repeated calls return consistent pixel offsets within a session. Randomising
/// on every call is itself a detectable pattern: real browsers return identical
/// canvas output for identical drawing operations.
///
/// `toString()` is spoofed on the patched functions so that
/// `CanvasRenderingContext2D.prototype.getImageData.toString()` returns the
/// native-code string that detectors expect.
fn randomize_canvas_fingerprint() -> String {
    r#"
    (function() {
        // Seed computed once per page context — stable within session.
        const _seed = (Math.random() * 0xFFFFFFFF) >>> 0;
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
        const patchedGetImageData = function getImageData() {
            const imageData = origGetImageData.apply(this, arguments);
            for (let i = 0; i < imageData.data.length; i += 4) {
                const delta = pixelOffset(i);
                imageData.data[i] = Math.max(0, Math.min(255, imageData.data[i] + delta));
            }
            return imageData;
        };
        // Spoof toString so detectors see native-code signature.
        Object.defineProperty(patchedGetImageData, 'toString', {
            value: function() { return 'function getImageData() { [native code] }'; },
            configurable: true,
        });
        CanvasRenderingContext2D.prototype.getImageData = patchedGetImageData;

        const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
        const patchedToDataURL = function toDataURL() {
            const ctx = this.getContext('2d');
            if (ctx) {
                // Stable 1x1 pixel draw — same value every call for this session.
                const alpha = ((xorshift(_seed) % 10) + 1) / 1000;
                ctx.fillStyle = 'rgba(0,0,0,' + alpha + ')';
                ctx.fillRect(0, 0, 1, 1);
            }
            return origToDataURL.apply(this, arguments);
        };
        Object.defineProperty(patchedToDataURL, 'toString', {
            value: function() { return 'function toDataURL() { [native code] }'; },
            configurable: true,
        });
        HTMLCanvasElement.prototype.toDataURL = patchedToDataURL;

        const origToBlob = HTMLCanvasElement.prototype.toBlob;
        if (origToBlob) {
            const patchedToBlob = function toBlob(callback) {
                const ctx = this.getContext('2d');
                if (ctx) {
                    const alpha = ((xorshift(_seed) % 10) + 1) / 1000;
                    ctx.fillStyle = 'rgba(0,0,0,' + alpha + ')';
                    ctx.fillRect(0, 0, 1, 1);
                }
                return origToBlob.apply(this, arguments);
            };
            Object.defineProperty(patchedToBlob, 'toString', {
                value: function() { return 'function toBlob() { [native code] }'; },
                configurable: true,
            });
            HTMLCanvasElement.prototype.toBlob = patchedToBlob;
        }
    })();
    "#
    .to_string()
}

/// Add slight noise to the two dominant AudioContext fingerprinting
/// techniques (analyser-based and offline-render-based).
///
/// **This is mitigation, not verification.** Unlike the canvas noise above,
/// there is no "correct" audio fingerprint for a persona to match — real
/// browsers on real hardware naturally vary here. The goal is only to break
/// exact hash stability *across sessions* while remaining stable *within* a
/// session, following the same seeded-xorshift pattern as
/// `randomize_canvas_fingerprint`. It does not make a probe-checkable claim
/// about what the persona's audio stack should report.
///
/// Two entry points are patched, mirroring the two techniques fingerprint
/// scripts actually use: `AnalyserNode.prototype.getFloatFrequencyData`
/// (oscillator + analyser technique) and `OfflineAudioContext.prototype.
/// startRendering` (render-then-hash technique, perturbed on the resolved
/// `AudioBuffer`'s channel data).
fn randomize_audio_fingerprint() -> String {
    r#"
    (function() {
        // Seed computed once per page context — stable within session.
        const _seed = (Math.random() * 0xFFFFFFFF) >>> 0;
        function xorshift(n) {
            n ^= n << 13; n ^= n >>> 17; n ^= n << 5;
            return (n >>> 0);
        }
        // Small noise, deterministic per (seed, sample index) within a
        // session: enough to move a hash, not enough to be audible or to
        // break legitimate audio analysis.
        function sampleOffset(idx) {
            return ((xorshift(_seed ^ (idx * 2654435761)) % 1000) - 500) / 1000000;
        }

        if (typeof AnalyserNode !== 'undefined') {
            const origGetFloatFrequencyData = AnalyserNode.prototype.getFloatFrequencyData;
            const patchedGetFloatFrequencyData = function getFloatFrequencyData(array) {
                origGetFloatFrequencyData.call(this, array);
                for (let i = 0; i < array.length; i++) {
                    array[i] += sampleOffset(i);
                }
            };
            Object.defineProperty(patchedGetFloatFrequencyData, 'toString', {
                value: function() { return 'function getFloatFrequencyData() { [native code] }'; },
                configurable: true,
            });
            AnalyserNode.prototype.getFloatFrequencyData = patchedGetFloatFrequencyData;
        }

        if (typeof OfflineAudioContext !== 'undefined') {
            const origStartRendering = OfflineAudioContext.prototype.startRendering;
            const patchedStartRendering = function startRendering() {
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
            };
            Object.defineProperty(patchedStartRendering, 'toString', {
                value: function() { return 'function startRendering() { [native code] }'; },
                configurable: true,
            });
            OfflineAudioContext.prototype.startRendering = patchedStartRendering;
        }
    })();
    "#
    .to_string()
}

/// Fake `navigator.plugins` to look like a typical Chrome installation.
fn override_plugins() -> String {
    r#"
    Object.defineProperty(navigator, 'plugins', {
        get: () => {
            return [
                {
                    name: 'Chrome PDF Plugin',
                    description: 'Portable Document Format',
                    filename: 'internal-pdf-viewer',
                    length: 1
                },
                {
                    name: 'Chrome PDF Viewer',
                    description: 'Portable Document Format',
                    filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai',
                    length: 1
                },
                {
                    name: 'Native Client',
                    description: '',
                    filename: 'internal-nacl-plugin',
                    length: 2
                }
            ];
        },
        configurable: true
    });
    "#
    .to_string()
}

/// Override `navigator.languages` with the given locale (e.g. "en-US").
fn override_languages(locale: &str) -> String {
    let lang_base = locale.split('-').next().unwrap_or("en");
    format!(
        r#"
    Object.defineProperty(navigator, 'languages', {{
        get: () => ['{locale}', '{lang_base}'],
        configurable: true
    }});
    "#
    )
}

/// Set `navigator.hardwareConcurrency` to `cores`.
fn override_hardware_concurrency(cores: u32) -> String {
    format!(
        r#"
    Object.defineProperty(navigator, 'hardwareConcurrency', {{
        get: () => {cores},
        configurable: true
    }});
    "#
    )
}

/// Set `navigator.deviceMemory` to `gb` GB.
fn override_device_memory(gb: u32) -> String {
    format!(
        r#"
    Object.defineProperty(navigator, 'deviceMemory', {{
        get: () => {gb},
        configurable: true
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
        get: () => {points},
        configurable: true
    }});
    "#
    )
}

/// Fake `navigator.connection` as a 4G connection.
fn override_connection_info() -> String {
    r#"
    Object.defineProperty(navigator, 'connection', {
        get: () => ({
            effectiveType: '4g',
            rtt: 50,
            downlink: 10,
            saveData: false
        }),
        configurable: true
    });
    "#
    .to_string()
}

/// Spoof WebGL vendor/renderer strings per the configured device class.
///
/// `toString()` is spoofed on the patched `getParameter` so that
/// `WebGLRenderingContext.prototype.getParameter.toString()` returns the
/// native-code string that bot detectors expect.
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
            const patched = function getParameter(parameter) {
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
            };
            // Spoof toString so detectors see native-code signature.
            Object.defineProperty(patched, 'toString', {
                value: function() { return 'function getParameter() { [native code] }'; },
                configurable: true,
            });
            ctx.prototype.getParameter = patched;
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
    Object.defineProperty(screen, 'width', {{
        get: () => {width},
        configurable: true
    }});
    Object.defineProperty(screen, 'height', {{
        get: () => {height},
        configurable: true
    }});
    Object.defineProperty(screen, 'availWidth', {{
        get: () => {width},
        configurable: true
    }});
    Object.defineProperty(screen, 'availHeight', {{
        get: () => {avail_height},
        configurable: true
    }});
    Object.defineProperty(window, 'devicePixelRatio', {{
        get: () => {device_scale_factor},
        configurable: true
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
/// NOTE: On the CDP backend this is superseded by `Emulation.setTimezoneOverride`
/// which also fixes `new Date().toString()`. The JS override is kept for the
/// BiDi/Firefox backend where no native CDP equivalent is available.
fn override_timezone(tz: &str) -> String {
    format!(
        r#"
    const DateTimeFormat = Intl.DateTimeFormat;
    Intl.DateTimeFormat = function(...args) {{
        const fmt = new DateTimeFormat(...args);
        const resolvedOptions = fmt.resolvedOptions;
        fmt.resolvedOptions = function() {{
            const options = resolvedOptions.call(this);
            options.timeZone = '{tz}';
            return options;
        }};
        return fmt;
    }};
    "#
    )
}

/// Fake `navigator.mediaDevices` with a realistic webcam/mic/speaker list.
fn override_media_devices() -> String {
    r#"
    Object.defineProperty(navigator, 'mediaDevices', {
        get: () => ({
            enumerateDevices: () => Promise.resolve([
                {
                    deviceId: 'default',
                    kind: 'audioinput',
                    label: '',
                    groupId: 'audio-input-group-1'
                },
                {
                    deviceId: 'communications',
                    kind: 'audioinput',
                    label: '',
                    groupId: 'audio-input-group-1'
                },
                {
                    deviceId: 'webcam-001',
                    kind: 'videoinput',
                    label: '',
                    groupId: 'video-input-group-1'
                },
                {
                    deviceId: 'speaker-default',
                    kind: 'audiooutput',
                    label: '',
                    groupId: 'audio-output-group-1'
                }
            ]),
            getUserMedia: () => Promise.reject(
                new DOMException('Permission denied', 'NotAllowedError')
            )
        }),
        configurable: true
    });
    "#
    .to_string()
}

/// Add small random noise to `Date.prototype.getTime` and `performance.now()`
/// to disrupt timing-based fingerprinting.
///
/// Uses a time-bucket approach: the same noise offset is returned for calls
/// within the same 10 ms window. This prevents the detectable inconsistency
/// of `new Date().getTime() !== new Date().getTime()` within the same tick.
///
/// `toString()` is spoofed on both patched functions.
fn override_performance_timing() -> String {
    r#"
    (function() {
        // Bucket noise: same offset within each 10 ms window.
        // This avoids the detectable pattern of two identical Date objects
        // returning different values in the same synchronous frame.
        var _lastBucket = -1;
        var _bucketNoise = 0;
        function getBucketNoise() {
            var bucket = Math.floor(Date.now() / 10);
            if (bucket !== _lastBucket) {
                _lastBucket = bucket;
                _bucketNoise = Math.floor(Math.random() * 11) - 5; // -5..+5
            }
            return _bucketNoise;
        }

        var originalGetTime = Date.prototype.getTime;
        var patchedGetTime = function getTime() {
            return originalGetTime.call(this) + getBucketNoise();
        };
        Object.defineProperty(patchedGetTime, 'toString', {
            value: function() { return 'function getTime() { [native code] }'; },
            configurable: true,
        });
        Date.prototype.getTime = patchedGetTime;

        if (typeof performance !== 'undefined' && performance.now) {
            var originalPerfNow = performance.now.bind(performance);
            var patchedPerfNow = function now() {
                return originalPerfNow() + getBucketNoise();
            };
            Object.defineProperty(patchedPerfNow, 'toString', {
                value: function() { return 'function now() { [native code] }'; },
                configurable: true,
            });
            performance.now = patchedPerfNow;
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
        Object.defineProperty(navigator, 'getBattery', {
            value: () => Promise.resolve({
                charging: true,
                chargingTime: 0,
                dischargingTime: Infinity,
                level: 1.0,
                addEventListener: function() {},
                removeEventListener: function() {},
            }),
            configurable: true
        });
    }
    "#
    .to_string()
}

/// Override `window.outerWidth` / `window.outerHeight`.
///
/// Headless Chrome reports 0 for both. Real browsers report the full window
/// frame including browser chrome (~85px overhead for the toolbar).
fn override_outer_size() -> String {
    r#"
    if (window.outerWidth === 0) {
        Object.defineProperty(window, 'outerWidth', {
            get: () => window.innerWidth,
            configurable: true,
        });
        Object.defineProperty(window, 'outerHeight', {
            get: () => window.innerHeight + 85,
            configurable: true,
        });
    }
    "#
    .to_string()
}

/// Override `navigator.userAgentData` (User-Agent Client Hints API).
///
/// Modern Chrome exposes this object. Sites like Yandex check
/// `navigator.userAgentData.brands` and `.platform`. Headless Chrome may
/// return a minimal or incorrect object; we provide a realistic Windows profile.
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
        Object.defineProperty(Navigator.prototype, 'userAgentData', {
            get: () => ({
                brands: __BRANDS__,
                mobile: __MOBILE__,
                platform: __PLATFORM__,
                getHighEntropyValues: function(hints) {
                    return Promise.resolve({
                        architecture: __ARCHITECTURE__,
                        bitness: '64',
                        brands: __BRANDS__,
                        fullVersionList: __FULL_VERSION_LIST__,
                        mobile: __MOBILE__,
                        model: __MODEL__,
                        platform: __PLATFORM__,
                        platformVersion: __PLATFORM_VERSION__,
                        uaFullVersion: __FULL_VERSION__,
                    });
                },
                toJSON: function() {
                    return { brands: this.brands, mobile: this.mobile, platform: this.platform };
                },
            }),
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
fn override_permissions_all() -> String {
    r#"
    if (window.navigator.permissions) {
        window.navigator.permissions.query = function(parameters) {
            if (parameters.name === 'notifications') {
                return Promise.resolve({ state: Notification.permission, onchange: null });
            }
            return Promise.resolve({ state: 'prompt', onchange: null });
        };
    }
    "#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn screen_script_uses_configured_viewport_and_scale_factor() {
        let mut config = StealthConfig::default();
        config.viewport = (393, 852);
        config.set_device_scale_factor(3.0).unwrap();

        let scripts = get_scripts(&config).join("\n");

        assert!(scripts.contains("get: () => 393"));
        assert!(scripts.contains("get: () => 852"));
        assert!(scripts.contains("get: () => 3"));
        assert!(!scripts.contains("devicePixelRatio', {\n        get: () => 1,"));
    }

    /// Proves the removal-gating fix: `webrtc_policy` now takes effect at
    /// `StealthLevel::Standard` (the level personas actually run at), not
    /// only at `Full`.
    #[test]
    fn webrtc_removal_is_gated_on_policy_at_standard_level() {
        let mut config = StealthConfig::default();
        config.level = StealthLevel::Standard;

        config.webrtc_policy = WebrtcPolicy::Remove;
        let removed = get_scripts(&config).join("\n");
        assert!(removed.contains("window.RTCPeerConnection = undefined"));

        config.webrtc_policy = WebrtcPolicy::Retain;
        let retained = get_scripts(&config).join("\n");
        assert!(!retained.contains("window.RTCPeerConnection = undefined"));
    }
}
