//! JS script generators for anti-detection overrides.

use crate::stealth::config::{StealthConfig, StealthLevel};

/// Returns stealth scripts for the given config.
pub fn get_scripts(config: &StealthConfig) -> Vec<String> {
    let mut scripts = Vec::new();

    // Basic: webdriver + chrome_runtime
    scripts.push(override_navigator_webdriver());
    scripts.push(override_chrome_runtime());

    if config.level == StealthLevel::Basic {
        return scripts;
    }

    // StandardNoWebGL: adds canvas, plugins, languages, permissions, hardware, memory, connection
    scripts.push(randomize_canvas_fingerprint());
    scripts.push(override_plugins());
    scripts.push(override_languages(&config.locale.locale));
    scripts.push(override_permissions_all());
    scripts.push(override_hardware_concurrency(config.hardware_concurrency));
    scripts.push(override_device_memory(config.device_memory_gb));
    scripts.push(override_connection_info());

    if config.level == StealthLevel::StandardNoWebGL {
        return scripts;
    }

    // Standard: adds webgl + screen_resolution
    scripts.push(override_webgl_vendor());
    scripts.push(override_screen_resolution(config.viewport.0, config.viewport.1));

    if config.level == StealthLevel::Standard {
        return scripts;
    }

    // Full: adds webrtc + timezone + media_devices + performance_timing + battery
    //       + outer window size + userAgentData
    scripts.push(override_webrtc_leak());
    if let Some(tz) = &config.locale.timezone {
        scripts.push(override_timezone(tz));
    }
    scripts.push(override_media_devices());
    scripts.push(override_performance_timing());
    scripts.push(override_battery_api());
    scripts.push(override_outer_size());
    scripts.push(override_user_agent_data());

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
        CanvasRenderingContext2D.prototype.getImageData = function() {
            const imageData = origGetImageData.apply(this, arguments);
            for (let i = 0; i < imageData.data.length; i += 4) {
                const delta = pixelOffset(i);
                imageData.data[i] = Math.max(0, Math.min(255, imageData.data[i] + delta));
            }
            return imageData;
        };

        const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
        HTMLCanvasElement.prototype.toDataURL = function() {
            const ctx = this.getContext('2d');
            if (ctx) {
                // Stable 1x1 pixel draw — same value every call for this session.
                const alpha = ((xorshift(_seed) % 10) + 1) / 1000;
                ctx.fillStyle = 'rgba(0,0,0,' + alpha + ')';
                ctx.fillRect(0, 0, 1, 1);
            }
            return origToDataURL.apply(this, arguments);
        };
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

/// Spoof WebGL vendor/renderer strings to look like NVIDIA hardware.
fn override_webgl_vendor() -> String {
    r#"
    const getParameter = WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter = function(parameter) {
        const debugInfo = this.getExtension('WEBGL_debug_renderer_info');
        if (debugInfo) {
            if (parameter === debugInfo.UNMASKED_VENDOR_WEBGL) {
                return 'Google Inc. (NVIDIA)';
            }
            if (parameter === debugInfo.UNMASKED_RENDERER_WEBGL) {
                return 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1080 Direct3D11 vs_5_0 ps_5_0, D3D11)';
            }
        }
        return getParameter.apply(this, arguments);
    };

    const getParameter2 = WebGL2RenderingContext.prototype.getParameter;
    WebGL2RenderingContext.prototype.getParameter = function(parameter) {
        const debugInfo = this.getExtension('WEBGL_debug_renderer_info');
        if (debugInfo) {
            if (parameter === debugInfo.UNMASKED_VENDOR_WEBGL) {
                return 'Google Inc. (NVIDIA)';
            }
            if (parameter === debugInfo.UNMASKED_RENDERER_WEBGL) {
                return 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1080 Direct3D11 vs_5_0 ps_5_0, D3D11)';
            }
        }
        return getParameter2.apply(this, arguments);
    };
    "#
    .to_string()
}

/// Override `screen.width/height/availWidth/availHeight` to `width × height`.
///
/// `availHeight` is evaluated in Rust (not via a JS expression) to avoid any
/// ambiguity with operator precedence in minified contexts. Also sets
/// `devicePixelRatio` to 1.0 for consistency on 1080p non-retina displays.
fn override_screen_resolution(width: u32, height: u32) -> String {
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
        get: () => 1,
        configurable: true
    }});
    "#
    )
}

/// Disable WebRTC to prevent IP leaks via ICE candidates.
///
/// Map scraping never requires WebRTC, so the safest approach is to remove it
/// entirely rather than wrapping it with a no-op that leaks local IPs anyway.
fn override_webrtc_leak() -> String {
    r#"
    window.RTCPeerConnection = undefined;
    window.webkitRTCPeerConnection = undefined;
    "#
    .to_string()
}

/// Override `Intl.DateTimeFormat.resolvedOptions` to report timezone `tz`.
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
                    label: 'Default - Microphone Array (Realtek High Definition Audio)',
                    groupId: 'audio-input-group-1'
                },
                {
                    deviceId: 'communications',
                    kind: 'audioinput',
                    label: 'Communications - Microphone Array (Realtek High Definition Audio)',
                    groupId: 'audio-input-group-1'
                },
                {
                    deviceId: 'webcam-001',
                    kind: 'videoinput',
                    label: 'HD WebCam (04f2:b5ce)',
                    groupId: 'video-input-group-1'
                },
                {
                    deviceId: 'speaker-default',
                    kind: 'audiooutput',
                    label: 'Default - Speakers (Realtek High Definition Audio)',
                    groupId: 'audio-output-group-1'
                }
            ]),
            getUserMedia: () => Promise.reject(new Error('Permission denied'))
        }),
        configurable: true
    });
    "#
    .to_string()
}

/// Add small random noise to `Date.prototype.getTime` to disrupt timing fingerprints.
fn override_performance_timing() -> String {
    r#"
    const originalGetTime = Date.prototype.getTime;
    Date.prototype.getTime = function() {
        const time = originalGetTime.call(this);
        return time + Math.floor(Math.random() * 10) - 5;
    };
    "#
    .to_string()
}

/// Override `navigator.getBattery` to return a fully-charged static profile.
fn override_battery_api() -> String {
    r#"
    Object.defineProperty(navigator, 'getBattery', {
        value: () => Promise.resolve({
            charging: true,
            chargingTime: 0,
            dischargingTime: Infinity,
            level: 1.0
        }),
        configurable: true
    });
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
fn override_user_agent_data() -> String {
    r#"
    if (!navigator.userAgentData) {
        Object.defineProperty(Navigator.prototype, 'userAgentData', {
            get: () => ({
                brands: [
                    { brand: 'Chromium', version: '131' },
                    { brand: 'Not_A Brand', version: '24' },
                ],
                mobile: false,
                platform: 'Windows',
                getHighEntropyValues: function(hints) {
                    return Promise.resolve({
                        architecture: 'x86',
                        bitness: '64',
                        brands: [
                            { brand: 'Chromium', version: '131' },
                            { brand: 'Not_A Brand', version: '24' },
                        ],
                        fullVersionList: [
                            { brand: 'Chromium', version: '131.0.6778.140' },
                            { brand: 'Not_A Brand', version: '24.0.0.0' },
                        ],
                        mobile: false,
                        model: '',
                        platform: 'Windows',
                        platformVersion: '15.0.0',
                        uaFullVersion: '131.0.6778.140',
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
    .to_string()
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
