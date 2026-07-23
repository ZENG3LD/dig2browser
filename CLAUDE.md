# dig2browser

Browser-automation substrate for Rust. Two layers:

- **library** (`dig2browser` root crate) — direct in-process browser control: custom CDP / WebDriver / BiDi clients, cookie access, persona/fingerprint configuration, `dev-fetch`/`dev-attach` CLIs, Web Bot Auth (RFC 9421). No external browser-automation dependency.
- **station** (`crates/dig2browser-station`, binary `dig2browser-stationd`) — a local daemon that is the single owner of browser processes, durable profiles, identity leases, capture traces, and (on Windows) OS-level egress containment. Consumers connect to it; they do not launch browsers themselves.

## Contract

- **Role**: shared, versioned browser-execution service + the library it is built on.
- **Owns**: browser/driver process trees, durable profiles + identity classes, per-identity leases and capacity, append-only capture traces and content-addressed artifacts, the Windows runtime-mirror catalog and WFP egress filters.
- **Does not own**: target graphs, schedules, source interpretation, case findings, evidence-sink policy (those belong to consumers such as `dig2social`).
- **Exports (crate seams)**: `dig2browser-core` (runtime identity + capability negotiation), `-protocol` (wire codec), `-client` (async/blocking consumer API), `-station` (daemon + leases + IPC), `-runtime-lightweight` (own static-document engine), `-trace` (ledger + CAS), `-crawler` (bounded frontier), `-probe` (observable-transcript check).

Living design + current status: `nemo/docs/dig2social/plans/browser-collection-platform-evolution.md` (authoritative, append-only). This file is the stable in-crate summary; that doc is the detail.

## Consumer surface

Path: `dig2browser-client` (reconnect, request correlation, cancellation) → `D2BQ/D2BR v1` over a Windows named pipe → `dig2browser-stationd`. A request is a typed bounded task (`D2TK`, up to 64 steps) run atomically under one identity session. Capability negotiation is **fail-closed**: an unsupported feature returns a typed `Unsupported` before any profile is created or process is spawned — a task never succeeds as a silent no-op.

### Runtimes (`--runtime chrome|edge|firefox|lightweight|auto`)

| Runtime | Transport | State |
|---|---|---|
| Chrome, Edge | CDP | production |
| Firefox | WebDriver/BiDi via reviewed GeckoDriver | experimental (only proven capabilities are advertised) |
| lightweight | own HTML/DOM engine, no child process | static-document collection only (bounded HTTP, every redirect revalidated, no JS/subresources/persona emulation) |
| auto | Chrome-first, Edge-fallback | — |

Chrome/Edge/Firefox derive UA + Client Hints from the actual launched runtime, not a stale default. `auto` never selects Firefox or lightweight.

### Persona / fingerprint consistency (`D2IP`)

Versioned coherent presets bind UA + native Client Hints, viewport/DPR/touch, `navigator.platform`, screen metrics, locale, and timezone as one validated contract (not independent overrides). Desktop and mobile-web presets (Chrome/Edge desktop, privacy-cohort, Chrome Pixel 7). 16 anti-detection scripts are auto-injected (`navigator.webdriver=false`, `window.chrome` mock, etc.). `dig2browser-probe` records the observable transcript and checks it against the negotiated feature/limitation record — the target is **measured transcript consistency, not universal indistinguishability**; a runtime advertises only what it can prove. Web Bot Auth (RFC 9421 Ed25519 signatures) is the alternative path where a crawler asserts a verifiable identity to a CDN instead of matching a persona.

### Egress control

- **Station loopback proxy**: canonicalizes the target, resolves DNS itself, rejects the whole answer set if any resolved peer is disallowed, pins TCP to a validated `SocketAddr`, rechecks the connected peer. Transports: HostDirect, HTTP proxy, SOCKS5.
- **Exact-origin policy**: an allowlist of canonical origins (`--allow-origin`) or `OpenWeb`, checked before profile creation; every redirect and the lightweight runtime revalidate.
- **WFP egress containment (Windows)** — the kernel-level backstop for what the proxy cannot see (a socket opened outside the proxy, e.g. WebRTC/QUIC UDP). A per-launch runtime mirror gives the browser a unique application identity; a `dig2browser-wfp-broker` process (elevated on its own; the station and browser stay medium-integrity) installs a WFP filter scoped to that App-ID: **permit TCP to the one loopback proxy, drop all other egress (TCP/UDP/QUIC, IPv4 + IPv6)**. Filters are retained until the browser process tree exits and released fail-closed if the broker is lost. Browser launch flags (`--no-proxy-server`, QUIC/`disable_non_proxied_udp`) remain mitigation only; the WFP filter is the enforced boundary. **Status: all four elevated acceptance scenarios pass (Chrome/Edge proxy-only enforcement, broker-crash fail-closed, worker-close-timeout retention).** Non-Windows egress containment (Linux netns/cgroup/nftables, macOS NetworkExtension) is a design target, not implemented.
- **Process containment**: a Windows Job Object terminates the browser process tree if the owning worker/station is hard-terminated. Default Windows Chrome/Edge control uses inherited NUL-delimited CDP pipes, so there is no TCP DevTools listener.

### Identity, cookies, auth

Durable profiles carry an explicit `public` vs `authenticated` class (fail-closed; an existing profile is never silently promoted). Headful operator authentication (`D2AI`) opens a visible station-owned Chromium (`begin`/`finish`) and returns no secrets. Session health (`D2HP`) runs a station-local check and returns only lifecycle state. Cookie continuity survives restart (HTTP and HTTPS `Secure`) via OS-encrypted profile reuse; no plaintext export. Secrets never cross IPC — cookie names/values/tokens stay station-local; over the wire only `D2SS` states (`unknown|ready|reauth-required|expired`) are exposed.

### Evidence and diagnostics

- `D2TR` capture envelope: requested + final URL, timestamps, duration, HTTP status, title, DOM/HTML, viewport PNG, SHA-256, and `complete|partial|unavailable` state.
- Append-only trace (`D2CE`) + content-addressed artifacts, resumable cursors, hard-kill reconciliation, exactly-once successor recovery; durable collections with idempotent receipts; bounded crawler (`D2WE`).
- Diagnostics are sanitized — no secrets, URLs, or filesystem paths in logs, status, or errors. Per-run artifacts (`manifest.json`, `events.jsonl`, `panic.log`, `*.diagnostic.log`, `*.runtime.log`, `*.browser-stderr.log`, and for WFP runs `broker-bootstrap.jsonl`) are written under the run directory. `D2ST` status exposes lifecycle/capacity/counters without secrets.
- Script evaluation is a separate, size-bounded, default-deny capability, excluded from ordinary monitoring.

### Configuration (`dig2browser-stationd`)

`--runtime`, `--profiles-root`, `--pipe-name`, `--allow-origin` / OpenWeb, `--windows-containment required|off`, `--windows-wfp-broker-pipe`, `--*-proxy-route`, `--timeout-seconds` (task/command execution), **`--close-timeout-seconds`** (worker close/teardown budget, separate from command execution; unset falls back to `--timeout-seconds`). Default-deny gates: `--allow-headful-auth`, `--allow-session-health`, script/interaction flags, `--trace-root`, `--allow-durable-read`/`--allow-durable-write`, crawl roots. Deployment is single-owner (exclusive ownership of the pipe endpoint and profiles root); exit is one machine-readable JSON line.

## Windows containment internals (for maintainers)

- **Runtime-mirror catalog**: `%LOCALAPPDATA%\dig2browser\runtime-mirrors` (hardcoded in `src/windows_runtime_mirror.rs` — `local_app_data_path`/`ensure_mirror_base`/`existing_mirror_base`). Ready mirrors are content-keyed (64-hex) and reused across launches; the cold materialization cost is paid once per content version, not per launch.
- **Orphan `.staging-` reconciliation** (`windows_runtime_mirror.rs`): interrupted materialization leaves a `.staging-*` directory. Reconciliation runs once per process from `ensure_mirror_base` and reclaims only entries whose name parses to the versioned `v2` scheme (`.staging-v2-<key>-<pid>-<creation_filetime>-<nonce>-<seq>`) **and** whose creator process is provably dead or PID-reused. It is fail-closed (retain on any parse/liveness uncertainty), rejects reparse points, and never matches by prefix alone. Pre-`v2` staging names carry no verifiable creator identity and are always retained.
- **Timeouts** (`src/agentic/worker.rs`): `command_timeout` bounds task execution and runtime startup; `close_timeout` (from `--close-timeout-seconds`, `None` → `command_timeout`) bounds worker close/drain/teardown. The WFP broker separates its lease-grant budget (`LEASE_GRANT_TIMEOUT`) from `ACQUIRE_TIMEOUT` so cold materialization is not cut off during grant.
- **Same-profile relaunch** (`src/browser/backend/cdp.rs`): a failed launch drains its prior process tree deterministically (Job Object emptiness) before returning, and a bounded retry keyed on the Chromium `ProcessSingleton` lock signature (exit code 21 / `ERROR_SHARING_VIOLATION`) handles the OS lock-release lag.

## Tests

- WFP/containment E2E live in `crates/dig2browser-station/tests/navigation_policy_e2e.rs` behind `--features containment-test-hooks`, marked `#[ignore]`.
- The four elevated WFP acceptance tests require a **medium-integrity** (non-elevated) test process and a **UAC prompt** for the broker; run from a normal terminal, e.g.:
  ```
  cargo test -p dig2browser-station --features containment-test-hooks --test navigation_policy_e2e <test_name> -- --ignored --nocapture
  ```
  Running from an elevated shell fails: the broker launcher rejects an elevated parent.
- Non-elevated mirror/route/product/lightweight/crawler E2E are also `#[ignore]` and require installed browsers (and, for Firefox, a reviewed `GECKODRIVER`).
