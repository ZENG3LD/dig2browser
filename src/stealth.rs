//! Anti-detection stealth scripts for headless browser automation.
//!
//! Injects a configurable suite of JS overrides before page load to evade
//! WebDriver detection. Supports multiple stealth levels and locale profiles.

use crate::error::BrowserError;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StealthLevel {
    Basic,
    StandardNoWebGL,
    #[default]
    Standard,
    Full,
}

#[derive(Debug, Clone)]
pub struct LocaleProfile {
    pub locale: String,
    pub timezone: Option<String>,
}

impl LocaleProfile {
    pub fn russian() -> Self {
        Self {
            locale: "ru-RU".into(),
            timezone: Some("Europe/Moscow".into()),
        }
    }
    pub fn english() -> Self {
        Self {
            locale: "en-GB".into(),
            timezone: None,
        }
    }
    pub fn english_us() -> Self {
        Self {
            locale: "en-US".into(),
            timezone: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StealthConfig {
    pub level: StealthLevel,
    pub locale: LocaleProfile,
    pub viewport: (u32, u32),
    pub hardware_concurrency: u32,
    pub device_memory_gb: u32,
}

impl Default for StealthConfig {
    fn default() -> Self {
        Self {
            level: StealthLevel::Standard,
            locale: LocaleProfile::english_us(),
            viewport: (1920, 1080),
            hardware_concurrency: 8,
            device_memory_gb: 8,
        }
    }
}

impl StealthConfig {
    pub fn russian() -> Self {
        Self {
            level: StealthLevel::Full,
            locale: LocaleProfile::russian(),
            ..Default::default()
        }
    }
    pub fn english() -> Self {
        Self::default()
    }
}

// ---------------------------------------------------------------------------
// Script selection
// ---------------------------------------------------------------------------

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
    scripts.push(override_permissions());
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
    scripts.push(override_webrtc_leak());
    if let Some(tz) = &config.locale.timezone {
        scripts.push(override_timezone(tz));
    }
    scripts.push(override_media_devices());
    scripts.push(override_performance_timing());
    scripts.push(override_battery_api());

    scripts
}

// ---------------------------------------------------------------------------
// Inject function
// ---------------------------------------------------------------------------

/// Injects all stealth scripts into `page` via `AddScriptToEvaluateOnNewDocument`.
///
/// Call this immediately after creating a page and before any navigation so
/// the scripts run on every subsequent page load in the tab.
pub async fn inject_stealth(
    page: &chromiumoxide::Page,
    config: &StealthConfig,
) -> Result<(), BrowserError> {
    use chromiumoxide::cdp::browser_protocol::page::AddScriptToEvaluateOnNewDocumentParams;

    for script in get_scripts(config) {
        let params = AddScriptToEvaluateOnNewDocumentParams {
            source: script,
            world_name: None,
            include_command_line_api: None,
            run_immediately: None,
        };
        page.execute(params)
            .await
            .map_err(|e| BrowserError::StealthInject(e.to_string()))?;
    }
    Ok(())
}

/// Human-like random delay between 100–300 ms.
pub async fn human_delay() {
    let delay_ms = 100 + (rand::random::<u64>() % 200);
    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
}

/// Simulate a human scrolling the page.
pub async fn human_scroll(page: &chromiumoxide::Page) -> Result<(), BrowserError> {
    let script = r#"
        async function smoothScroll() {
            const totalHeight = document.body.scrollHeight;
            const viewportHeight = window.innerHeight;
            let currentPosition = 0;
            while (currentPosition < totalHeight) {
                window.scrollTo(0, currentPosition);
                currentPosition += viewportHeight * 0.3;
                await new Promise(resolve => setTimeout(resolve, 100 + Math.random() * 200));
            }
            window.scrollTo(0, totalHeight);
        }
        smoothScroll();
    "#;
    page.evaluate(script)
        .await
        .map_err(|e| BrowserError::JsEval(e.to_string()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Individual script generators
// ---------------------------------------------------------------------------

/// Override `navigator.webdriver` to hide automation.
fn override_navigator_webdriver() -> String {
    r#"
    Object.defineProperty(navigator, 'webdriver', {
        get: () => false,
        configurable: true
    });
    "#
    .to_string()
}

/// Fake `window.chrome` to mimic a real Chrome/Edge browser.
fn override_chrome_runtime() -> String {
    r#"
    window.chrome = {
        runtime: {}
    };
    "#
    .to_string()
}

/// Add slight noise to canvas pixel data to randomise the fingerprint.
fn randomize_canvas_fingerprint() -> String {
    r#"
    const getImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function() {
        const imageData = getImageData.apply(this, arguments);
        for (let i = 0; i < imageData.data.length; i += 4) {
            imageData.data[i] = imageData.data[i] + Math.floor(Math.random() * 3) - 1;
        }
        return imageData;
    };

    const toDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function() {
        const context = this.getContext('2d');
        if (context) {
            context.fillStyle = 'rgba(0,0,0,0.01)';
            context.fillRect(0, 0, 1, 1);
        }
        return toDataURL.apply(this, arguments);
    };
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

/// Override the Permissions API to behave like a real browser.
fn override_permissions() -> String {
    r#"
    const originalQuery = window.navigator.permissions.query;
    window.navigator.permissions.query = (parameters) => (
        parameters.name === 'notifications' ?
            Promise.resolve({ state: Notification.permission }) :
            originalQuery(parameters)
    );
    "#
    .to_string()
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
fn override_screen_resolution(width: u32, height: u32) -> String {
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
        get: () => {height} - 40,
        configurable: true
    }});
    "#
    )
}

/// Wrap `RTCPeerConnection` to prevent WebRTC-based IP leaks.
fn override_webrtc_leak() -> String {
    r#"
    const originalRTCPeerConnection = window.RTCPeerConnection;
    window.RTCPeerConnection = function(...args) {
        const pc = new originalRTCPeerConnection(...args);
        const originalCreateDataChannel = pc.createDataChannel;
        pc.createDataChannel = function() {
            const result = originalCreateDataChannel.apply(this, arguments);
            return result;
        };
        return pc;
    };
    window.RTCPeerConnection.prototype = originalRTCPeerConnection.prototype;
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
