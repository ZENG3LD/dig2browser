# dig2browser

Stealth browser automation library for Rust. Custom CDP + WebDriver + BiDi backends — zero external browser-automation dependencies.

Multi-browser support: **Chrome**, **Edge**, **Firefox**. Built-in anti-detection with 16 stealth scripts, cookie management (Chrome DPAPI + Firefox plaintext), and agent-friendly DevTools access.

## Why

Existing Rust browser libraries (`chromiumoxide`, `fantoccini`, `thirtyfour`) each support one protocol. dig2browser implements all three protocols from scratch in ~7.5K lines:

| Protocol | Browsers | What it gives |
|----------|----------|---------------|
| **CDP** (Chrome DevTools Protocol) | Chrome, Edge | Full DevTools: network interception, pre-navigation script injection, DOM access, Input events |
| **W3C WebDriver** | Chrome, Edge, Firefox | Element interaction, screenshots, cookies, Actions API |
| **WebDriver BiDi** | Firefox, Chrome | Pre-navigation scripts (`addPreloadScript`), network interception, typed events — CDP-equivalent for Firefox |

One unified API (`StealthBrowser` / `StealthPage`) regardless of backend.

## Architecture

```
dig2browser/
├── crates/
│   ├── cdp/        # CDP WebSocket client, 8 typed domains (1600 LOC)
│   ├── webdriver/  # W3C WebDriver REST client (1100 LOC)
│   ├── bidi/       # WebDriver BiDi WebSocket client (780 LOC)
│   ├── stealth/    # 16 JS anti-detection scripts (690 LOC)
│   ├── cookie/     # Chrome DPAPI + Firefox plaintext readers (780 LOC)
│   ├── detect/     # Browser binary detection + launch args (280 LOC)
│   └── core/       # StealthBrowser, StealthPage, BrowserPool (2400 LOC)
└── src/lib.rs      # Re-export facade
```

### Dependency Graph

```
dig2browser (facade)
  └── core
        ├── cdp
        ├── webdriver
        ├── bidi
        ├── stealth
        ├── cookie
        └── detect
```

No circular dependencies. Leaf crates (`stealth`, `cookie`, `detect`) have zero protocol deps.

## Quick Start

```rust
use dig2browser::{StealthBrowser, LaunchConfig, BrowserPreference};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Auto-detects Chrome/Edge, launches with stealth
    let browser = StealthBrowser::launch().await?;

    let page = browser.new_page("https://example.com").await?;

    // Get page HTML
    let html = page.html().await?;
    println!("Title length: {}", html.len());

    // Execute JavaScript
    let title = page.eval("document.title").await?;
    println!("Title: {}", title);

    // Find and interact with elements
    let heading = page.find("h1").await?;
    let text = heading.text().await?;
    println!("Heading: {}", text);

    // Screenshot
    let png = page.screenshot().await?;
    std::fs::write("screenshot.png", &png)?;

    browser.close().await?;
    Ok(())
}
```

### Firefox

```rust
use dig2browser::{StealthBrowser, LaunchConfig, StealthConfig, BrowserPreference};

let launch = LaunchConfig {
    browser_pref: BrowserPreference::Firefox,
    geckodriver_url: "http://localhost:4444".into(),
    ..Default::default()
};

// Requires geckodriver running: geckodriver --port 4444
let browser = StealthBrowser::launch_with(launch, StealthConfig::default()).await?;
```

### Wait Builder

```rust
use std::time::Duration;

// Wait for element to appear
let element = page.wait()
    .at_most(Duration::from_secs(10))
    .every(Duration::from_millis(200))
    .for_element(".results")
    .await?;

// Wait for URL change
page.wait()
    .at_most(Duration::from_secs(5))
    .for_url("/dashboard")
    .await?;

// Wait for JS condition
page.wait()
    .for_condition("window.dataLoaded === true")
    .await?;
```

### Browser Pool

```rust
use dig2browser::{BrowserPool, PoolConfig};

let pool = BrowserPool::new(PoolConfig {
    size: 4,
    max_pages_per_browser: 20,
    ..Default::default()
}).await?;

let page = pool.acquire().await?;
page.page().goto("https://example.com").await?;
// Page returned to pool on drop
```

### DevTools Events

```rust
let mut devtools = page.devtools().await?;
while let Some(event) = devtools.next_event().await {
    match event {
        DevToolsEvent::Network(ev) => println!("Request: {} {}", ev.method, ev.url.unwrap_or_default()),
        DevToolsEvent::Console(ev) => println!("[{}] {}", ev.level, ev.text),
    }
}
```

## Features

### Stealth (16 scripts, auto-injected)

- `navigator.webdriver` → `false`
- `window.chrome` mock
- Canvas fingerprint randomization
- WebGL vendor/renderer spoofing
- Plugin/mimeType simulation
- Hardware concurrency + device memory
- Connection type, battery API, media devices
- WebRTC leak prevention
- Screen resolution + outer window size
- Performance timing noise
- UserAgentData branding

### Element Interaction

```rust
let input = page.find("input[name=query]").await?;
input.type_text("search term").await?;

let button = page.find("button[type=submit]").await?;
button.click().await?;

let result = page.find(".result").await?;
let text = result.text().await?;
let html = result.html().await?;
let bbox = result.bounding_box().await?;
```

### Cookies

Cross-protocol cookie management + reading from browser profiles:

```rust
// Read cookies from browser profile (Chrome DPAPI / Firefox plaintext)
use dig2browser::{InterceptConfig, CookieJar};

// Get cookies from current page
let jar = page.get_cookies().await?;

// Set cookies
page.set_cookies(&jar).await?;
```

### PDF Export

```rust
use dig2browser::PrintOptions;

let pdf = page.pdf(PrintOptions {
    landscape: true,
    print_background: true,
    ..Default::default()
}).await?;
std::fs::write("page.pdf", &pdf)?;
```

## CDP Domains

Hand-written typed helpers for 10 domains:

| Domain | Methods |
|--------|---------|
| **Target** | create, attach, close, list |
| **Page** | navigate, content, screenshot, PDF, addScript, frameTree |
| **Runtime** | evaluate, callFunctionOn, addBinding |
| **Network** | getCookies, setCookie, deleteCookies |
| **Fetch** | enable, continue, fail, fulfill, rewrite headers |
| **DOM** | querySelector, getBoxModel, resolveNode, outerHTML, focus, scrollIntoView |
| **Input** | mouse click/move, keyboard type/press, touch |
| **Emulation** | timezone, UA, device metrics, geolocation, locale, media |
| **Security** | ignoreCertificateErrors |
| **Log** | enable (events via typed stream) |

### Typed Event Stream

```rust
use dig2browser_cdp::{EventStream, CdpEventType, FetchRequestPaused, NetworkResponseReceived};

let mut fetch_events: EventStream<FetchRequestPaused> = session.event_stream();
while let Some(event) = fetch_events.next().await {
    println!("Intercepted: {} {}", event.resource_type, event.request.url);
}
```

## WebDriver BiDi

Firefox-equivalent of CDP capabilities:

| Module | Capabilities |
|--------|-------------|
| **script** | `addPreloadScript` (pre-navigation injection), evaluate, callFunction |
| **network** | `addIntercept`, continueRequest, provideResponse, failRequest |
| **browsingContext** | navigate, getTree, create/close, screenshot, print |
| **input** | performActions, releaseActions |
| **log** | subscribe to console/error events |

## Browser Support

| Browser | Protocol | Stealth | Status |
|---------|----------|---------|--------|
| Chrome | CDP | Full (pre-nav injection) | Production |
| Edge | CDP | Full (pre-nav injection) | Production |
| Firefox | WebDriver BiDi | Full (preloadScript) | Production |

## Requirements

- **Chrome/Edge**: No external driver needed — connects directly via CDP
- **Firefox**: Requires [geckodriver](https://github.com/mozilla/geckodriver/releases) running (`geckodriver --port 4444`)
- **Rust**: 1.75+ (2021 edition)

## Roadmap

- [x] Custom CDP client (WebSocket, JSON-RPC)
- [x] Custom WebDriver client (W3C REST)
- [x] Custom BiDi client (WebSocket)
- [x] 16 stealth scripts with auto-injection
- [x] Cookie reading (Chrome DPAPI, Firefox plaintext)
- [x] Browser auto-detection (Chrome, Edge, Firefox)
- [x] Element interaction (find, click, type, text, attribute, bounding box)
- [x] Typed CDP event streams
- [x] Wait builder (element, URL, JS condition)
- [x] Actions API (mouse chains, keyboard, wheel)
- [x] PDF export
- [x] Frame switching
- [x] Screenshot (viewport, full page, element, clip region)
- [x] Network interception (CDP Fetch + BiDi network)
- [x] Geolocation / locale / media emulation
- [x] DevTools event exposure for agents
- [ ] Integration tests with real browsers
- [ ] Shadow DOM traversal
- [ ] JS `expose_function` (bidirectional Rust-JS callbacks)
- [ ] Auth challenge handling
- [ ] File upload/download
- [ ] WebSocket message interception
- [ ] Proxy configuration
- [ ] HAR export
- [ ] Trace recording/replay
- [ ] crates.io publish

## Support the Project

If you find this tool useful, consider supporting development:

| Currency | Network | Address |
|----------|---------|---------|
| USDT | TRC20 | `TNxMKsvVLYViQ5X5sgCYmkzH4qjhhh5U7X` |
| USDC | Arbitrum | `0xEF3B94Fe845E21371b4C4C5F2032E1f23A13Aa6e` |
| ETH | Ethereum | `0xEF3B94Fe845E21371b4C4C5F2032E1f23A13Aa6e` |
| BTC | Bitcoin | `bc1qjgzthxja8umt5tvrp5tfcf9zeepmhn0f6mnt40` |
| SOL | Solana | `DZJjmH8Cs5wEafz5Ua86wBBkurSA4xdWXa3LWnBUR94c` |

## License

MIT
