# dig2browser

Browser-automation substrate for Rust. Two layers:

- **library** (`dig2browser` root crate) — direct in-process browser control: custom CDP / WebDriver / BiDi clients, cookie access, persona/fingerprint configuration, a live DevTools event stream, `dev-fetch`/`dev-attach` CLIs, Web Bot Auth (RFC 9421). No external browser-automation dependency.
- **station** (`crates/dig2browser-station`, binary `dig2browser-stationd`) — a local daemon that is the single owner of browser processes, durable profiles, identity leases, capture traces, and (on Windows) OS-level egress containment. Consumers connect over a named pipe; they do not launch browsers themselves.

## Contract

- **Role**: shared, versioned browser-execution service + the library it is built on.
- **Owns**: browser/driver process trees, durable profiles + identity classes, per-identity leases and capacity, append-only capture traces + content-addressed artifacts, the Windows runtime-mirror catalog and WFP egress filters.
- **Does not own**: target graphs, schedules, source interpretation, case findings, evidence-sink policy (those belong to consumers such as `dig2social`).
- **Exports (crate seams)**: `dig2browser-core` (runtime identity + capability negotiation + persona compiler), `-protocol` (wire codec), `-client` (async/blocking consumer API), `-station` (daemon + leases + IPC), `-runtime-lightweight` (own static-document engine), `-trace` (ledger + CAS), `-crawler` (bounded frontier), `-probe` (observable-transcript check).

Living design + current status: `nemo/docs/dig2social/plans/browser-collection-platform-evolution.md` (authoritative, append-only). This file is the stable in-crate summary.

## Consumer API (`dig2browser-client`)

`StationClient` (async) / `BlockingStationClient` (sync wrapper) → `D2BQ/D2BR v1` over a Windows named pipe → `dig2browser-stationd`. Methods:

- Lifecycle: `connect`, `health`, `status` → `StationStatus` (D2ST: lifecycle/capacity/counters, no secrets), `disconnect`, `shutdown` (gated `--allow-remote-shutdown`).
- One-shot / non-durable: `capture(profile_id, url)`, `run_task(+ _with_persona / _with_identity / _with_progress)`.
- Durable, resumable (crash-recoverable): `begin_collection(+ _with_id / _with_identity)` → `CollectionHandle`; `read_trace(collection_id, cursor, limit)` → `TracePage`; `read_artifact_chunk(collection_id, sha256, offset, max_bytes)` → `ArtifactChunk` (≤256 KiB); `read_collection_receipt` → `CollectionReceipt`; `cancel_collection`.
- Crawl: `begin_crawl(+ _with_id / _with_identity)` → `CrawlJobId`; `crawl_status`; `read_crawl_events(job_id, cursor, limit)` → `CrawlEventPage`; `cancel_crawl`.
- Live capture (raw, gated `--allow-live-events`, see "Live inspection vs snapshot" below): `begin_live_capture(+ _with_id / _with_identity)` → `LiveSessionId`; `read_live_events(session_id, cursor, limit)` → `LiveEventPage`; `stop_live_capture`.
- Identity / auth: `identity_status` (gated `--allow-identity-status`), `update_identity_state` (gated `--allow-session-state-updates`), `begin_auth_session` / `finish_auth_session` (gated `--allow-headful-auth`), `check_auth_session` (gated `--allow-session-health`), `import_session(profile_id, persona, path)` (gated `--allow-session-import`) — install a prepared session from a **local file** into an authenticated profile (see "Cookie capture and reuse").

### Task (`D2TK`, ≤64 steps, atomic under one identity session)

Steps: `Navigate{url}`, `Wait{duration}` (≤2 min cumulative), `WaitForSelector{selector,timeout}`, `Wheel{x,y,dx,dy}`, `KeyPress{key}`, `ClickSelector` / `TypeSelector` / `ReadSelectorText` (selector ≤4 KiB, text ≤64 KiB), `Evaluate{script}` (≤64 KiB), `Capture{policy}`. `Capture` must follow at least one `Navigate`. Capture policy: `StateOnly | HtmlOnly | EvidenceViewport`. `WaitForSelector` blocks until the selector resolves in the DOM or `timeout` elapses (poll via `ResolveElement`, presence-only; `WaitTimeout` on miss); it is **inspect-only** (needs only `L2::Inspect`, ungated) and its `timeout` shares the cumulative wait budget with `Wait` — it lets an agent wait for dynamic content without a blind sleep and without the scripted-task gate. `ClickSelector/TypeSelector/KeyPress/Wheel` are default-deny (`--allow-interactive-tasks`); `Evaluate` is default-deny (`--allow-scripted-tasks`). Negotiation is **fail-closed**: an unsupported feature returns typed `Unsupported` before any profile/process is created — never a silent no-op.

### Live inspection vs snapshot (important scope boundary)

The **library** exposes a live event stream: `StealthPage::devtools()` → `PageDevTools` (broadcast) delivering `DevToolsEvent::{Network(NetworkEvent), Console(ConsoleEvent)}`. The CDP backend forwards **every** `Network.*` event generically (`src/browser/backend/cdp.rs:2601`), so `Network.webSocketFrameReceived/Sent`, `webSocketCreated`, and `eventSource*` frames DO arrive as `NetworkEvent{method, url, status, params}` (frame payload in `params`) once `Network.enable` is set. `dev-attach` and `dev-fetch` consume this stream. There are no typed WebSocket/SSE event structs — WS/SSE frames are only available as generic `Network.*` entries.

The **station IPC surface exposes this stream as a bounded, cursored subscription** (`RequestKind::LiveEvents`, wire family `D2LQ`/`D2LP`/`D2LE`, `crates/dig2browser-station/src/live.rs`): `begin_live_capture`/`read_live_events`/`stop_live_capture` on `dig2browser-client`. `Begin` leases a station-owned worker, navigates it, and subscribes to that page's `PageDevTools` broadcast via a new `BrowserWorker::subscribe_devtools()` side-channel (`src/agentic/worker.rs`) gated by `L3Capability::Capture`; events are pushed into a per-session bounded ring buffer (`MAX_LIVE_EVENTS = 64` retained, drop-oldest, cumulative `dropped` counter surfaced on every `Read`). Filterable to `network`/`websocket_only`/`console`. **Unlike every other station path, live events are raw and unsanitized** — real URLs, HTTP status, and WebSocket/SSE frame payloads (bounded to `MAX_LIVE_NETWORK_PARAMS_BYTES = 64 KiB` per event, truncated not dropped) cross the wire as-is, because observing a page's actual live traffic is the point. This is why it is the one station capability gated by a single hard default-deny flag, `--allow-live-events`, rather than sanitized like `capture`/`Collection`/`Crawl`. Sessions are ephemeral (RAM-only, no trace/crawl-root durability) and are not connection-scoped (same design as crawl/collection job IDs) — `Stop`, a soft idle TTL (reaped opportunistically on `Begin`/`Read`, 5 minutes), and station shutdown all release the held lease. There is still **no consumer-facing SOCKS5/proxy endpoint** over the pipe — SOCKS5 remains an *outbound* browser transport only (`--socks5-proxy-route`, `--proxy-server=socks5://…`), never an inbound endpoint a caller can tunnel its own client through (see the evolution doc's P1.X rejection).

## Runtimes (`--runtime chrome|edge|firefox|lightweight|auto`)

| Runtime | Transport | State |
|---|---|---|
| Chrome, Edge | CDP | production |
| Firefox | WebDriver/BiDi via reviewed GeckoDriver | experimental |
| lightweight | own HTML/DOM engine, no child process | static-document only (bounded HTTP, redirects revalidated, no JS/subresources/persona emulation) |
| auto | Chrome-first, Edge-fallback | never selects Firefox/lightweight |

Chrome/Edge/Firefox derive UA + Client Hints from the actual launched runtime, not a stale default.

### Headless vs headful

`LaunchConfig.headless` defaults to `true`; all ordinary `capture`/`run_task`/`begin_collection`/crawl execution is headless. Headful is used **only** for operator authentication: `begin_auth_session` sets `headless=false` and opens a visible login window (gated `--allow-headful-auth`); `finish_auth_session` returns the profile to the headless pool. There is no `headless` bit in `CollectionTask`/`CrawlSpec` — a caller cannot request a visible window for ordinary tasks over the wire.

## Crawler (`dig2browser-crawler` + station `crawl.rs`)

`CrawlEngine` over a durable frontier: `Pending → InFlight{Lease} → Completed|Failed`, lease-based (crash-safe, exactly-once page dispatch across restarts). Scope: `SeedOrigins | Origins{} | Hosts{include_subdomains} | AnyHttp`, checked before enqueue. Limits: `MAX_PAGES=10_000`, `MAX_DEPTH=64`, `MAX_ATTEMPTS_PER_URL=8`, snapshot ≤128 MiB. State is an append-only journal (`FileStore`, 3 rotating slots, checksums, torn-write tolerant); the crawl root is single-owner (`.dig2browser-crawl.lock`), one journal file per job, one background runner per job. **Each page is captured through the same collection/trace path** — `[Navigate, Capture(HtmlOnly)]` with a deterministic `collection_id = sha256(job+url+attempt)`; on restart prior attempts are matched by receipt (no duplicate fetch). Wire: `D2WQ/D2WP/D2WE`, events `JobStarted/UrlQueued/PageStarted/PageSucceeded(+PageArtifact ref)/PageFailed/RetryScheduled/Recovered/Job{Succeeded,Failed,Cancelled}`. Crawl execution requires **all four** flags: `--allow-crawl-read/write` + `--allow-durable-read/write`; `Public` profiles by default. An **authenticated crawl** — reuse a session harvested in-engine (`begin_auth_session`) so the crawler fetches logged-in pages — additionally requires `--allow-authenticated-crawl` (subordinate to the four): `execute_page` then leases the profile's `Authenticated` identity instead of a public persona. The per-identity `session_gate` serializes access (one writer per session), the sequential per-job runner keeps single-writer, and a job persisted as authenticated does **not** resume if the flag is later disabled (fail-closed). `profile_class` is already carried in the persisted crawl binding, so this needed no durable-format change.

## Persona / fingerprint (`dig2browser-core` + `src/stealth`)

A persona is a versioned coherent preset (`ChromeWindowsDesktopV1`, `EdgeWindowsDesktopV1`, `FirefoxWindowsDesktopV1`, `ChromiumDesktopPrivacyCohortV1`, `ChromeAndroidPixel7MobileWebV1`) binding: viewport, DPR, `max_touch_points`, locale, timezone, `navigator.platform`, platform version, device model. `apply_persona` (`station/src/lib.rs`) pushes these to the runtime via CDP: `Emulation.setUserAgentOverride`+`userAgentMetadata` (drives JS + `Sec-CH-UA*` headers), `setTimezoneOverride`, `setDeviceMetricsOverride`, `setTouchEmulationEnabled`. Plus 18 injection scripts in `src/stealth/scripts.rs` (`navigator.webdriver=false`, `window.chrome`, canvas noise, plugins, languages, WebGL parameter strings, screen, WebRTC removal, media-devices, permissions, UA-data, etc.). `dig2browser-probe` validates a browser-visible↔server-visible↔persona matrix (incl. per-preset UA-token grammar) and rejects `webdriver:true`.

### Coverage — emulated vs declared (mobile persona reality)

Consistent (CDP-native, drives headers + media queries): UA / Client Hints, viewport / screen / DPR, touch + `pointer:coarse` / `hover:none`, `navigator.platform`, timezone; locale via launch flags (`--lang`/`--accept-lang`; `Emulation.setLocaleOverride` is defined but unused).

Known gaps that contradict a mobile claim under fingerprinting (leak the real desktop host):

| Surface | State |
|---|---|
| WebGL `UNMASKED_RENDERER`/`VENDOR` | Hardcoded `Google Inc. (NVIDIA)` / D3D11-ANGLE for **every** persona, not device-class gated (`scripts.rs`). Real Pixel 7 = Mali/Adreno GLES. Underlying GL behavior is the real desktop GPU regardless. |
| TLS ClientHello (JA3/JA4) | Not addressed — compiled-in BoringSSL of the real Windows binary; matches desktop Chrome, not Chrome-for-Android. |
| Media codecs (`canPlayType`) | Not patched — desktop set leaks. |
| AudioContext, fonts | Not patched — real host leaks. |
| `hardwareConcurrency` / `deviceMemory` | Hardcoded 8/8 for **all** personas; `apply_persona` never sets them from the persona. |
| `maxTouchPoints` | Not JS-patched (relies on the CDP touch-emulation side effect only). |
| WebRTC | `RTCPeerConnection` deleted entirely — a real mobile Chrome keeps it; absence is itself an automation signal. |

The code declares this honestly: `dig2browser-probe` attests only the allowlisted browser/server transcript, and `ChromiumRuntimeFactory` declares `MobileWebEmulation` as `SupportLevel::Emulated` (never `Native`) with `RuntimeLimitation::{NoNativeMobileApis, NoCarrierState, NoHardwareAttestation}`. Mobile personas pass server-side + basic JS checks but are distinguishable by GPU/TLS/codec/audio/font probes.

## Egress and process containment

- **Station loopback proxy**: canonicalizes target, resolves DNS itself, rejects the whole answer set if any resolved peer is disallowed, pins TCP to a validated `SocketAddr`, rechecks the connected peer. Transports: HostDirect, HTTP proxy, SOCKS5 (outbound only). Does not decode TLS (no MITM) — sees ciphertext, not WS/HTTP payloads on HTTPS.
- **Exact-origin policy** (`--allow-origin` / OpenWeb): checked before profile creation; every redirect and the lightweight runtime revalidate.
- **WFP egress containment (Windows)** — kernel backstop for sockets the proxy cannot see (WebRTC/QUIC UDP). A per-launch runtime mirror gives the browser a unique App-ID; `dig2browser-wfp-broker` (self-elevated; station + browser stay medium-integrity) installs a filter scoped to that App-ID: permit TCP to the one loopback proxy, drop all other egress (TCP/UDP/QUIC, IPv4+IPv6). Retained until the process tree exits, released fail-closed on broker loss. **Status: all four elevated acceptance scenarios pass.** Non-Windows containment is a design target, not implemented.
- **Process containment**: a Windows Job Object terminates the process tree on hard kill. Default Chrome/Edge control uses inherited NUL-delimited CDP pipes (no TCP DevTools listener).

## Identity, profiles, cookies

Durable profiles under `--profiles-root/<profile_id>` carry manifests: `.dig2browser-profile-class-v1` (`Public|Authenticated`), `.dig2browser-persona-v1`, `.dig2browser-profile-binding-v2` (cross-checks persona+class+runtime+route), `.dig2browser-session-state-v1` (append-only, TTL auto-expiry `Ready→Expired`). Over the wire only `D2SS` states (`Unknown|Ready|ReauthRequired|Expired`) are exposed; cookie names/values/tokens never cross IPC. An existing profile is never silently promoted `Public→Authenticated`.

### Cookie stores

- Chrome/Edge: `<profile>/Default/Network/Cookies` (SQLite, table `cookies`: `name, value, encrypted_value, host_key, path, is_secure, is_httponly, expires_utc`). `encrypted_value` = AES-256-GCM (`v10`/`v11`); master key from `<profile>/Local State` `os_crypt.encrypted_key`, DPAPI-unwrapped (`CryptUnprotectData`). Chrome 127+ app-bound adds a 32-byte binary prefix before the UTF-8 value. Code: `src/cookies/{sqlite,decrypt}.rs`.
- Firefox: `<profile>/cookies.sqlite` (table `moz_cookies`, **plaintext**). Code: `src/cookies/firefox.rs`.

### Cookie capture and reuse

Two capture paths (not wired together): (1) post-close SQLite extraction (`src/cookies/interceptor.rs` — visible browser, wait for exit, WAL-flush pause, copy DB to temp with retries, DPAPI+AES decrypt); (2) live CDP (`Network.getCookies`/`setCookie`/`deleteCookies`, `src/cdp/domains/network.rs`). Reuse = **persistent profile-directory reuse** — Chrome's own encrypted cookie DB persists in the reused directory; nothing exports/re-injects values.

**Prepared-session import** (gated `--allow-session-import`): `import_session(profile_id, persona, path)` installs a session prepared out of band. The station reads a **local file** itself (`crates/dig2browser-station/src/session_import.rs`, typed JSON `{version, cookies:[{name,value,domain,path?,secure?,http_only?,expires_unix?}]}`), leases a headless worker for the `Authenticated` identity, installs the cookies via `AgentCommand::SetCookies` → CDP `Network.setCookie`, and marks the session `Ready`. **Cookie material never crosses IPC** — the wire request (`RequestKind::ImportSession`) carries the path, not the bytes. Fail-closed: a non-authenticated identity is rejected and an existing `Public` profile cannot be promoted. Chrome then owns the encrypted store, so no custom cookie DB. The imported profile is reusable by ordinary tasks and by an authenticated crawl (`--allow-authenticated-crawl`). Durability nuance: `set_cookie` (`src/cdp/domains/network.rs`) supplies a synthesized `scheme://host/` URL because Chrome rejects a bare-domain cookie set from `about:blank`, and omits `expires` when `None`. Installed cookies are held in the leased worker (immediate reuse is reliable); Chrome flushes them to the on-disk store on its own timer, and `browser.close()` is a hard process kill that does **not** flush — so a session imported and then immediately force-restarted before the flush is not yet on disk. E2E: `in_process_station_chrome_session_import_reuse_e2e` (`tests/station_daemon_e2e.rs`) proves import → authenticated navigation transmits the cookie. There is **no OS-encrypted cookie-snapshot artifact** ("OS-encrypted profile reuse" means Chrome's own on-disk encryption surviving because the directory is reused). `CookieJar::save_to_insecure_file`/`load_from_insecure_file` exist but are `#[deprecated]` plaintext escape hatches.

## Evidence, storage, and consumer read schema (`dig2browser-trace`)

Under `--trace-root` (enforced disjoint from `--profiles-root`): `collections/<id>/<cursor>.event` (`D2CE`, kinds `Started{task_sha256,step_count,runtime} | ArtifactCommitted{step_index,role,ArtifactRef} | Terminal{outcome,steps} | Interrupted{SuccessorReconciliation|ShutdownTimeout}`), `artifacts/<sha256>.blob` (content-addressed, deduped, re-hashed+length-checked on every read), and receipts. Atomic writes (temp + `durable_rename`); a crashed prior owner's non-terminal collection gets a synthetic `Interrupted(SuccessorReconciliation)` exactly once.

A consumer receives a typed schema over IPC, never files/paths: `read_trace` → `TracePage` of `TraceEvent`; `read_artifact_chunk` → `ArtifactChunk` (reassemble by sha256); `read_collection_receipt` → `CollectionReceipt{collection_id, task_sha256, final_url, http_status, title, ready_state, capture_duration_ms, html: ArtifactRef, viewport_png: Option<ArtifactRef>, collector/protocol versions}`. Task path returns `EvidenceCapture{completeness: Complete|Partial|Unavailable, requested/final_url, http_status, title, ready_state, html, png, html_sha256, png_sha256, versions}`. Cookie values are absent from all of these.

## Configuration (`dig2browser-stationd`)

`--pipe-name`, `--profiles-root` (required), `--trace-root`, `--crawl-root` (requires trace-root), `--max-resident` (16), `--max-in-flight` (32), `--max-connections` (64), `--runtime`, `--geckodriver-path`/`--geckodriver-url`, `--windows-containment off|required`, `--windows-wfp-broker-pipe`, `--direct-route-ref`, `--http-proxy-route REF=IP:PORT`, `--socks5-proxy-route REF=IP:PORT`, `--allow-origin`, `--allow-private-peer`, `--timeout-seconds` (task execution, 90), `--close-timeout-seconds` (worker close/teardown; falls back to `--timeout-seconds`), `--restart-after-pages` (500), `--drain-seconds` (15). Default-deny gates: `--allow-remote-shutdown`, `--allow-interactive-tasks`, `--allow-scripted-tasks`, `--allow-session-state-updates`, `--allow-identity-status`, `--allow-headful-auth`, `--allow-session-health`, `--allow-durable-read`/`--allow-durable-write`, `--allow-crawl-read`/`--allow-crawl-write`, `--allow-authenticated-crawl` (reuse an authenticated session in a crawl; subordinate to the crawl/durable gates), `--allow-live-events` (raw/unsanitized, single flag — see "Live inspection vs snapshot"), `--allow-session-import` (import a prepared session from a local file into an authenticated profile; cookie bytes read locally, never over the pipe). Single-owner in three layers (profiles-root guard, `first_pipe_instance` on the pipe, writer-locks on trace/crawl roots); exit is one machine-readable JSON line.

## Windows containment internals (for maintainers)

- **Runtime-mirror catalog**: `%LOCALAPPDATA%\dig2browser\runtime-mirrors` (hardcoded in `src/windows_runtime_mirror.rs` — `local_app_data_path`/`ensure_mirror_base`/`existing_mirror_base`). Ready mirrors are content-keyed (64-hex) and reused across launches; the cold materialization cost is paid once per content version, not per launch.
- **Orphan `.staging-` reconciliation** (`windows_runtime_mirror.rs`): runs once per process from `ensure_mirror_base`; reclaims only entries whose name parses to the versioned `v2` scheme (`.staging-v2-<key>-<pid>-<creation_filetime>-<nonce>-<seq>`) **and** whose creator is provably dead / PID-reused. Fail-closed (retain on uncertainty), rejects reparse points, never matches by prefix alone. Pre-`v2` names carry no verifiable creator identity and are always retained.
- **Timeouts** (`src/agentic/worker.rs`): `command_timeout` bounds task execution + startup; `close_timeout` (`--close-timeout-seconds`, `None`→`command_timeout`) bounds close/drain/teardown. The WFP broker separates `LEASE_GRANT_TIMEOUT` from `ACQUIRE_TIMEOUT` so cold materialization is not cut off during grant.
- **Same-profile relaunch** (`src/browser/backend/cdp.rs`): a failed launch drains its prior process tree deterministically (Job Object emptiness) before returning; a bounded retry keyed on the Chromium `ProcessSingleton` lock signature (exit 21 / `ERROR_SHARING_VIOLATION`) handles the OS lock-release lag.

## Tests

WFP/containment E2E live in `crates/dig2browser-station/tests/navigation_policy_e2e.rs` behind `--features containment-test-hooks`, marked `#[ignore]`. The four elevated WFP tests require a **medium-integrity (non-elevated)** test process and a **UAC prompt** for the broker; run from a normal terminal (`cargo test -p dig2browser-station --features containment-test-hooks --test navigation_policy_e2e <name> -- --ignored --nocapture`). An elevated shell fails: the broker launcher rejects an elevated parent. Non-elevated mirror/route/product/lightweight/crawler E2E are also `#[ignore]` and need installed browsers (and a reviewed `GECKODRIVER` for Firefox).
