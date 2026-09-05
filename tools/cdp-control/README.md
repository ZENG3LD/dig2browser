# cdp-control

Python CDP control panel for an **already-open** headed Chrome/Edge.

Does **not** launch a browser. Attaches to the owner's debug port
(default `:9222`) and drives one tab: list, trusted click/drag/wheel,
screenshot, eval, reload, perf, hud.

Source: Kimi's `nemo/.tmp/cdp_tabs.py` (2026-08). Trusted mouse is
`mouseMoved` then `mousePressed`/`mouseReleased` with `clickCount`.

```bash
python tools/cdp-control/cdp_control.py tabs
python tools/cdp-control/cdp_control.py --tab dev shot NAME
python tools/cdp-control/cdp_control.py --tab prod click 100 200
python tools/cdp-control/cdp_control.py --prefix http://127.0.0.1:17499 eval "location.href"
python tools/cdp-control/cdp_control.py --id F4009E81 shot NAME
python tools/cdp-control/cdp_control.py --tab prod perf 60 --interval 1 --json out.jsonl
python tools/cdp-control/cdp_control.py --tab dev hud on
python tools/cdp-control/cdp_control.py --tab dev hud off
python tools/cdp-control/cdp_control.py --activate --tab dev shot NAME
```

`--tab dev` / `--tab prod` are MLC aliases (`:17499` / `mylittlechart.org`).
Screenshots default to `nemo/.tmp/<NAME>.png` (`--out` to change).

Requires `websocket-client`. All mouse/keyboard input is CDP-synthetic
(`Input.dispatch*Event`) — the tool never touches the system mouse or
keyboard. It also never raises or focuses the owner's window
(`Target.activateTarget`) unless `--activate` is passed — by default the
tab it addresses is driven wherever it already is, in the background if
that's where it is. Pass `--activate` when the command needs the tab
actually on top (e.g. `shot`/`Page.captureScreenshot` Internal-errors on a
backgrounded page). Never pass `--viewport` against the owner's window
(pins `innerWidth`).

## perf / hud — dev metrics from `window.__MLC_PERF()`

The chart exposes one on-demand JS function, `window.__MLC_PERF()`, that
returns a frame-timing/memory snapshot (or `{"busy":true}` mid-frame — the
tool retries on the next poll). All display and collection of that data
lives **here**, never in the chart bundle.

- `perf [seconds] [--interval s] [--json PATH]` — poll `__MLC_PERF()` every
  `interval` seconds (default `1.0`) for `seconds` (default `60`), printing
  one compact line per poll (`p50/p95/max`, `>50/>100` slow-frame counts,
  worst phase, wasm/heap memory, persist writes, last frame time). Each
  distinct long frame (deduped by `at_ms`) prints once as its own `LONG …`
  line with the full per-phase breakdown. `--json PATH` appends every raw
  poll result as JSON lines. Ctrl-C ends the poll early; a summary
  (samples, p95 min/median/max, distinct long frames, top dominant phases)
  always prints at the end. If `__MLC_PERF` is not defined, the tool prints
  `__MLC_PERF() not present in this page (bundle without the perf export?)`
  and exits `2`. If a poll returns `busy` or the `frames` counter stalls
  between two successful polls (both can mean the tab is backgrounded and
  throttled), the tool prints a one-line hint (`hint: tab may be throttled
  in the background; rerun with --activate if the owner is not using
  Chrome`) once per run.
- `hud on|off` — inject/remove a small on-page overlay
  (`<div id="d2b-perf-hud">`, fixed top-left, monospace, dark translucent,
  `pointer-events:none`) that polls `__MLC_PERF()` every 500 ms via a
  `setInterval` stored on `window.__d2bPerfHudTimer` and shows the same
  frame/memory/persist/long-frame summary. Both directions are idempotent —
  `hud on` twice re-installs cleanly, `hud off` with no HUD present is a
  no-op. The HUD JS is a string constant inside `cdp_control.py`; it is
  injected at runtime and is never part of the chart bundle.
