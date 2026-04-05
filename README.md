# dig2browser

Stealth browser automation library for Rust with **Web Bot Auth** support. Custom CDP + WebDriver + BiDi backends — zero external browser-automation dependencies.

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
│   ├── bot_auth/   # Web Bot Auth: Ed25519 signing, JWKS, key management (250 LOC)
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
        ├── detect
        └── bot_auth (web-bot-auth crate)
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

Works on all three browsers — CDP events on Chrome/Edge, BiDi events on Firefox.

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

## Web Bot Auth

Cryptographic bot identity using [RFC 9421 HTTP Message Signatures](https://datatracker.ietf.org/doc/html/rfc9421). Instead of stealth evasion, your crawler proves its identity to CDN providers (Cloudflare, Akamai, DataDome, HUMAN Security, AWS) with Ed25519 signatures.

One implementation covers all providers — they all support the same [Web Bot Auth standard](https://developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth/).

### Setup

```rust
use dig2browser::bot_auth::*;

// 1. Generate a keypair (or load existing)
let keypair = BotKeyPair::load_or_generate(Path::new("keys/my-bot.key"))?;

// 2. Generate JWKS directory for hosting
let jwks = JwksDirectory::from_keypair(&keypair);
jwks.save_to_file(Path::new("public/.well-known/http-message-signatures-directory"))?;
println!("JWKS:\n{}", jwks.to_json());

// 3. Create identity (from env: BOT_AUTH_JWKS_URL, BOT_AUTH_KEY_PATH)
let identity = BotIdentity::from_env(
    "my-crawler",
    "https://github.com/you/my-crawler",
);
// Or manually:
// let identity = BotIdentity::new(
//     "my-crawler",
//     "https://github.com/you/my-crawler",
//     "https://you.github.io/.well-known/http-message-signatures-directory",
//     "keys/my-bot.key",
// );

// 4. Sign requests
let signer = RequestSigner::from_identity(identity)?;
let headers = signer.sign_request("GET", "https://example.com/data")?;

// 5. Attach to reqwest
let resp = client.get(url)
    .header("Signature-Agent", &headers.signature_agent)
    .header("Signature-Input", &headers.signature_input)
    .header("Signature", &headers.signature)
    .send().await?;
```

### How to Register Your Bot

| Provider | Registration | Docs |
|----------|-------------|------|
| **Cloudflare** | [Verified Bots form](https://developers.cloudflare.com/bots/concepts/bot/#verified-bots) | [Web Bot Auth docs](https://developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth/) |
| **Akamai** | [Bot Registration](https://www.akamai.com/lp/bot-agent-registration) | [Blog post](https://www.akamai.com/blog/security/2025/nov/redefine-trust-web-bot-authentication) |
| **DataDome** | [Bot Authentication](https://docs.datadome.co/docs/bot-authentication) | Automatic if JWKS hosted |
| **HUMAN Security** | Contact via site | [Announcement](https://www.humansecurity.com/newsroom/) |
| **AWS Bedrock** | [AgentCore docs](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/browser-web-bot-auth.html) | Automatic |

**Steps:**
1. Generate keypair: `BotKeyPair::generate()` or `BotKeyPair::load_or_generate(path)`
2. Host the JWKS JSON at a public URL (GitHub Pages works: `/.well-known/http-message-signatures-directory`)
3. Register with each provider using the links above (provide your JWKS URL + bot homepage)
4. Sign all requests with `RequestSigner` — the 3 headers are added automatically

**Environment variables** (set in consumer's `.env`):
| Variable | Description |
|----------|-------------|
| `BOT_AUTH_JWKS_URL` | Public URL where JWKS directory is hosted |
| `BOT_AUTH_KEY_PATH` | Path to Ed25519 private key (32 bytes raw) |

`BotIdentity::from_env(name, homepage)` reads both from env. Panics if missing.

**Security:** Never commit your private key (`*.key`). Add `keys/`, `*.key`, and `.env` to `.gitignore`.

## CDP Domains

Hand-written typed helpers for 10 domains:

| Domain | Methods |
|--------|---------|
| **Target** | create, attach, close, list |
| **Page** | navigate, content, screenshot, PDF, addScript, frameTree |
| **Runtime** | evaluate, callFunctionOn, addBinding |
| **Network** | enable, getCookies, setCookie, deleteCookies, getResponseBody |
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
| **network** | `subscribeNetwork` (events), `addIntercept`, continueRequest, provideResponse, failRequest |
| **browsingContext** | navigate, getTree, create/close, screenshot, print |
| **input** | performActions, releaseActions |
| **log** | subscribe to console/error events |

## Browser Support

| Browser | Protocol | Stealth | Status |
|---------|----------|---------|--------|
| Chrome | CDP | Full (pre-nav injection) | Production |
| Edge | CDP | Full (pre-nav injection) | Production |
| Firefox | WebDriver BiDi | Full (preloadScript) | Production |

## CLI Tools

dig2browser ships two standalone binaries:

### `keygen` — Generate Ed25519 keypair for Web Bot Auth

```bash
cargo run --bin keygen -- keys/my-bot.key
```

### `dev-fetch` — DevTools in your terminal

Fetch a URL through the stealth browser and inspect everything — no code needed.

```bash
# Basic: fetch URL, show title/size/time
dev-fetch https://example.com

# Full DevTools inspection
dev-fetch https://cloud.vk.com/pricing \
  --fingerprint russian.json \
  --network-log \
  --cookies \
  --console \
  --save-html out.html \
  --save-screenshot out.png

# Execute JS
dev-fetch https://example.com --eval "document.title"

# DOM inspection
dev-fetch https://example.com --dom "div.pricing-card"

# Headed mode + keep open for manual inspection
dev-fetch https://example.com --headed --keep-open 60

# With persistent profile (reuse cookies from cookie-auth)
dev-fetch https://yandex.cloud --profile /tmp/dig2crawl-profiles/yandex.cloud --cookies
```

| Flag | Description |
|------|-------------|
| `--fingerprint <PATH>` | JSON fingerprint config (browser, locale, timezone, viewport, stealth level) |
| `--headed` | Visible browser window |
| `--wait-selector <CSS>` | Wait for element before capturing |
| `--save-html <PATH>` | Save HTML to file |
| `--save-screenshot <PATH>` | Save screenshot PNG |
| `--profile <PATH>` | Persistent browser profile directory |
| `--network-log` | Show all network requests/responses |
| `--cookies` | Dump cookies after page load |
| `--console` | Show console.log/warn/error messages |
| `--eval <JS>` | Execute JavaScript and print result |
| `--dom <selector>` | Find elements and print outer HTML |
| `--keep-open <SECONDS>` | Keep browser open (useful with --headed) |

## Process Lifecycle

Browser processes are automatically cleaned up — no zombie Chrome/Edge left behind:

| Layer | Mechanism | Covers |
|-------|-----------|--------|
| **Graceful** | `browser.close()` sends `Browser.close` CDP command + `child.kill()` | Normal exit |
| **kill_on_drop** | `tokio::process::Command::kill_on_drop(true)` | Panic, early return, forgotten close |
| **Drop safety net** | `CdpBrowserBackend::drop()` calls `start_kill()` | Edge cases where Child drop doesn't fire |

For Firefox/BiDi: geckodriver manages Firefox lifecycle. `DELETE /session` tells geckodriver to terminate Firefox.

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
- [x] crates.io publish
- [x] Web Bot Auth (Ed25519 signing, JWKS, RFC 9421)

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
