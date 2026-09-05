#!/usr/bin/env python3
"""CDP control panel for an already-open Chrome/Edge.

Never launches a browser. Connects to the owner's headed instance
(default :9222) and drives one tab: list, click, drag, wheel, type, key,
shot, eval, perf, hud.

Origin: Kimi's nemo/.tmp/cdp_tabs.py (2026-08) — trusted mouse is
move → press → release with clickCount. All mouse/keyboard input is
CDP-synthetic (Input.dispatch*Event) — the tool never touches the system
mouse or keyboard. It also never raises/focuses the owner's window unless
`--activate` is passed (see Target.activateTarget below).

Usage:
  python cdp_control.py tabs
  python cdp_control.py --tab dev shot NAME
  python cdp_control.py --tab prod click 100 200
  python cdp_control.py --prefix http://127.0.0.1:17499 eval 'location.href'
  python cdp_control.py --id F4009E81 shot NAME
  python cdp_control.py --tab prod perf 60 --interval 1 --json out.jsonl
  python cdp_control.py --tab dev hud on
  python cdp_control.py --activate --tab dev click 100 200
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import statistics
import sys
import time
import urllib.request

import websocket

DEFAULT_PORT = 9222
DEFAULT_SHOT_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "..", "..", ".tmp",
)
TAB_ALIASES = {
    "dev": "http://127.0.0.1:17499",
    "prod": "https://mylittlechart.org",
}


def json_list(port: int):
    url = f"http://127.0.0.1:{port}/json/list"
    return json.load(urllib.request.urlopen(url, timeout=5))


def list_tabs(port: int):
    tabs = json_list(port)
    for t in tabs:
        if t.get("type") != "page":
            continue
        print(f"{t['id'][:8]}  {t.get('title', '')[:40]:40}  {t.get('url', '')}")
    return tabs


def pick_tab(port: int, *, prefix: str | None, tab_id: str | None):
    tabs = json_list(port)
    pages = [t for t in tabs if t.get("type") == "page"]
    if tab_id:
        for t in pages:
            if t["id"].startswith(tab_id):
                return t
        raise SystemExit(f"no tab id starting with {tab_id!r} on :{port}")
    if prefix:
        hits = [t for t in pages if t.get("url", "").startswith(prefix)]
        if not hits:
            raise SystemExit(f"no page starting with {prefix!r} on :{port}")
        return hits[0]
    raise SystemExit("need --tab / --prefix / --id")


def activate_tab(port: int, target_id: str):
    """Bring the tab to the front (raises/focuses the owner's window).
    Opt-in only — called from main() when --activate is passed. Needed for
    captureScreenshot, which Internal-errors on a backgrounded page; most
    other verbs work fine against a tab that is merely open, not focused."""
    ver = json.load(urllib.request.urlopen(
        f"http://127.0.0.1:{port}/json/version", timeout=5))
    bws = websocket.create_connection(
        ver["webSocketDebuggerUrl"], timeout=10, suppress_origin=True)
    try:
        bws.send(json.dumps({
            "id": 1,
            "method": "Target.activateTarget",
            "params": {"targetId": target_id},
        }))
        json.loads(bws.recv())
    finally:
        bws.close()


class CDP:
    def __init__(self, ws):
        self.ws = ws
        self.mid = 0

    def send(self, method, params=None):
        self.mid += 1
        self.ws.send(json.dumps({"id": self.mid, "method": method, "params": params or {}}))
        while True:
            m = json.loads(self.ws.recv())
            if m.get("id") == self.mid:
                if "error" in m:
                    raise RuntimeError(f"{method}: {m['error']}")
                return m.get("result", {})

    def mouse(self, mtype, x, y, cc=0, dy=None):
        p = {"type": mtype, "x": float(x), "y": float(y)}
        if mtype == "mouseWheel":
            p.update(deltaX=0, deltaY=float(dy or 0))
        elif mtype != "mouseMoved":
            p.update(button="left", clickCount=int(cc))
        self.send("Input.dispatchMouseEvent", p)

    def click(self, x, y):
        self.mouse("mouseMoved", x, y)
        time.sleep(0.04)
        self.mouse("mousePressed", x, y, 1)
        time.sleep(0.05)
        self.mouse("mouseReleased", x, y, 1)

    def dblclick(self, x, y):
        self.mouse("mouseMoved", x, y)
        self.mouse("mousePressed", x, y, 1)
        self.mouse("mouseReleased", x, y, 1)
        self.mouse("mousePressed", x, y, 2)
        self.mouse("mouseReleased", x, y, 2)

    def drag(self, x1, y1, x2, y2):
        self.mouse("mouseMoved", x1, y1)
        time.sleep(0.05)
        self.send("Input.dispatchMouseEvent", {
            "type": "mousePressed", "x": float(x1), "y": float(y1),
            "button": "left", "clickCount": 1,
        })
        steps = 12
        for i in range(1, steps + 1):
            xi = x1 + (x2 - x1) * i / steps
            yi = y1 + (y2 - y1) * i / steps
            self.send("Input.dispatchMouseEvent", {
                "type": "mouseMoved", "x": float(xi), "y": float(yi),
                "button": "left",
            })
            time.sleep(0.03)
        self.send("Input.dispatchMouseEvent", {
            "type": "mouseReleased", "x": float(x2), "y": float(y2),
            "button": "left", "clickCount": 1,
        })

    # ── keyboard ──────────────────────────────────────────────────────────
    # The wasm shell (uzor-window-web) listens to window `keydown`/`keyup`:
    # `ev.code()` drives the positional KeyCode (Enter/Escape/Backspace/…)
    # and a single-scalar `ev.key()` on keydown becomes TextInput, so a
    # printable char needs both `key` and `code`; named keys need their
    # `code` plus the Windows VK so Chrome synthesises a real key event.
    _NAMED_VK = {
        "Enter": 13, "Escape": 27, "Backspace": 8, "Tab": 9, "Delete": 46,
        "Space": 32, "ArrowLeft": 37, "ArrowUp": 38, "ArrowRight": 39,
        "ArrowDown": 40, "Home": 36, "End": 35, "PageUp": 33, "PageDown": 34,
    }

    def key(self, name):
        vk = self._NAMED_VK.get(name)
        if vk is None:
            raise SystemExit(f"key: unknown named key {name!r}; "
                             f"one of {sorted(self._NAMED_VK)}")
        key = " " if name == "Space" else name
        base = {"key": key, "code": name, "windowsVirtualKeyCode": vk,
                "nativeVirtualKeyCode": vk}
        p = dict(base, type="rawKeyDown")
        if name == "Space":
            p.update(type="keyDown", text=" ", unmodifiedText=" ")
        self.send("Input.dispatchKeyEvent", p)
        time.sleep(0.02)
        self.send("Input.dispatchKeyEvent", dict(base, type="keyUp"))

    @staticmethod
    def _code_for(ch):
        if ch.isascii() and ch.isalpha():
            return "Key" + ch.upper()
        if ch.isdigit():
            return "Digit" + ch
        return "Space" if ch == " " else "Unidentified"

    def type_text(self, text):
        for ch in text:
            if ch == "\n":
                self.key("Enter")
                continue
            code = self._code_for(ch)
            base = {"key": ch, "code": code}
            self.send("Input.dispatchKeyEvent",
                      dict(base, type="keyDown", text=ch, unmodifiedText=ch))
            time.sleep(0.015)
            self.send("Input.dispatchKeyEvent", dict(base, type="keyUp"))
            time.sleep(0.015)

    def shot(self, name, out_dir):
        os.makedirs(out_dir, exist_ok=True)
        r = self.send("Page.captureScreenshot", {
            "format": "png",
            "fromSurface": True,
            "captureBeyondViewport": False,
        })
        path = os.path.join(out_dir, f"{name}.png")
        with open(path, "wb") as f:
            f.write(base64.b64decode(r["data"]))
        print(path)


PERF_MISSING_MSG = "__MLC_PERF() not present in this page (bundle without the perf export?)"
PERF_THROTTLE_HINT = (
    "hint: tab may be throttled in the background; "
    "rerun with --activate if the owner is not using Chrome"
)

# Fixed order of the 10 per-phase timings inside a long_frames entry's
# "phases" object — mirrors the field order of window.__MLC_PERF()'s "last".
PERF_PHASE_NAMES = (
    "events", "tick_chart", "tick_drains", "tick_cloud", "drains",
    "persist", "render_setup", "render_chart", "render_overlay",
    "render_present",
)

PERF_EVAL_JS = (
    "(() => { if (typeof window.__MLC_PERF !== 'function') "
    "return {__missing: true}; return window.__MLC_PERF(); })()"
)

# HUD lives entirely in this tool — the JS below is injected on demand and
# is never part of the chart bundle.
HUD_INSTALL_JS = r"""
(() => {
  if (window.__d2bPerfHudTimer) { clearInterval(window.__d2bPerfHudTimer); window.__d2bPerfHudTimer = null; }
  let el = document.getElementById('d2b-perf-hud');
  if (!el) {
    el = document.createElement('div');
    el.id = 'd2b-perf-hud';
    el.style.cssText = [
      'position:fixed', 'top:0', 'left:0', 'z-index:2147483647',
      'font-family:monospace', 'font-size:11px', 'line-height:1.4',
      'background:rgba(0,0,0,0.72)', 'color:#0f0', 'padding:6px 8px',
      'white-space:pre', 'pointer-events:none',
    ].join(';');
    document.body.appendChild(el);
  }
  const fmt1 = (v) => (v === null || v === undefined) ? 'n/a' : v.toFixed(1);
  const render = () => {
    if (typeof window.__MLC_PERF !== 'function') {
      el.textContent = '__MLC_PERF() not present';
      return;
    }
    const d = window.__MLC_PERF();
    if (!d || d.busy) return;
    const w = d.window, m = d.memory, p = d.persist;
    const lf = (d.long_frames && d.long_frames.length)
      ? d.long_frames[d.long_frames.length - 1] : null;
    const growth = (m.wasm_growth_mb >= 0 ? '+' : '') + fmt1(m.wasm_growth_mb);
    el.textContent = [
      `frame p50=${fmt1(w.p50)} p95=${fmt1(w.p95)} max=${fmt1(w.max)}`,
      `>50=${w.over_50} >100=${w.over_100} worst=${w.worst_phase}`,
      `wasm=${fmt1(m.wasm_mb)}MiB(${growth}) heap=${fmt1(m.heap_mb)}`,
      `persist writes=${p.writes} last=${fmt1(p.last_ms)}ms max=${fmt1(p.max_ms)}ms`,
      lf ? `LONG ${fmt1(lf.total)}ms dominant=${lf.dominant} events_drained=${lf.events_drained}`
         : 'LONG: none',
    ].join('\n');
  };
  render();
  window.__d2bPerfHudTimer = setInterval(render, 500);
  return 'hud on';
})()
"""

HUD_REMOVE_JS = r"""
(() => {
  if (window.__d2bPerfHudTimer) { clearInterval(window.__d2bPerfHudTimer); window.__d2bPerfHudTimer = null; }
  const el = document.getElementById('d2b-perf-hud');
  if (el) el.remove();
  return 'hud off';
})()
"""


def eval_perf(c):
    """Call window.__MLC_PERF() in the page. Returns the parsed object, or
    None if the page returned no value at all."""
    r = c.send("Runtime.evaluate", {
        "expression": PERF_EVAL_JS, "returnByValue": True,
    })
    return r.get("result", {}).get("value")


def fmt_memory(mem):
    wasm_mb = mem.get("wasm_mb")
    growth = mem.get("wasm_growth_mb")
    heap = mem.get("heap_mb")
    wasm_s = f"{wasm_mb:.1f}MiB({growth:+.1f})" if wasm_mb is not None else "n/a"
    heap_s = f"{heap:.1f}" if heap is not None else "n/a"
    return wasm_s, heap_s


def perf_line(t, data):
    w = data["window"]
    last = data["last"]
    persist = data["persist"]
    wasm_s, heap_s = fmt_memory(data["memory"])
    return (
        f"t={t:.1f}s p50={w['p50']:.1f} p95={w['p95']:.1f} max={w['max']:.1f} "
        f">50={w['over_50']} >100={w['over_100']} worst={w['worst_phase']} "
        f"wasm={wasm_s} heap={heap_s} persist={persist['writes']}w "
        f"last={last['total']:.1f}ms"
    )


def long_frame_line(lf):
    phases = lf.get("phases", {})
    parts = " ".join(f"{name}={phases.get(name, 0.0):.1f}" for name in PERF_PHASE_NAMES)
    return (
        f"LONG {lf['total']:.1f}ms dominant={lf['dominant']} {parts} "
        f"events_drained={lf['events_drained']}"
    )


def print_perf_summary(n_samples, n_busy, p95_samples, long_frames):
    print("--- perf summary ---")
    print(f"samples={n_samples} busy={n_busy}")
    if p95_samples:
        print(
            f"p95: min={min(p95_samples):.1f} "
            f"median={statistics.median(p95_samples):.1f} "
            f"max={max(p95_samples):.1f}"
        )
    else:
        print("p95: no samples")
    print(f"long_frames={len(long_frames)}")
    if long_frames:
        counts: dict[str, int] = {}
        for lf in long_frames:
            dom = lf.get("dominant", "?")
            counts[dom] = counts.get(dom, 0) + 1
        top = sorted(counts.items(), key=lambda kv: -kv[1])[:3]
        print("top_dominant=" + ", ".join(f"{k}:{v}" for k, v in top))


def cmd_perf(c, seconds, interval, json_path):
    start = time.time()
    end = start + seconds
    seen_long: set = set()
    long_frames: list = []
    p95_samples: list = []
    n_samples = 0
    n_busy = 0
    last_frames = None
    hint_shown = False
    jf = open(json_path, "a", encoding="utf-8") if json_path else None
    try:
        while time.time() < end:
            poll_t0 = time.time()
            data = eval_perf(c)
            if data is None:
                print(f"t={poll_t0 - start:.1f}s no data", file=sys.stderr)
            elif data.get("__missing"):
                print(PERF_MISSING_MSG, file=sys.stderr)
                raise SystemExit(2)
            elif data.get("busy"):
                n_busy += 1
                print(f"t={poll_t0 - start:.1f}s busy")
                if not hint_shown:
                    print(PERF_THROTTLE_HINT)
                    hint_shown = True
            else:
                n_samples += 1
                print(perf_line(poll_t0 - start, data))
                p95_samples.append(data["window"]["p95"])
                if jf is not None:
                    jf.write(json.dumps(data, ensure_ascii=False) + "\n")
                    jf.flush()
                for lf in data.get("long_frames", []):
                    key = lf.get("at_ms")
                    if key not in seen_long:
                        seen_long.add(key)
                        long_frames.append(lf)
                        print(long_frame_line(lf))
                frames = data.get("frames")
                if (not hint_shown and last_frames is not None
                        and frames is not None and frames == last_frames):
                    print(PERF_THROTTLE_HINT)
                    hint_shown = True
                last_frames = frames
            elapsed = time.time() - poll_t0
            time.sleep(max(0.0, interval - elapsed))
    except KeyboardInterrupt:
        print()
    finally:
        if jf is not None:
            jf.close()
    print_perf_summary(n_samples, n_busy, p95_samples, long_frames)


def cmd_hud(c, state):
    if state not in ("on", "off"):
        raise SystemExit(f"hud: expected on|off, got {state!r}")
    js = HUD_INSTALL_JS if state == "on" else HUD_REMOVE_JS
    r = c.send("Runtime.evaluate", {"expression": js, "returnByValue": True})
    print(r.get("result", {}).get("value"))


def main():
    ap = argparse.ArgumentParser(description="CDP control panel — attach only, never spawn")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--tab", choices=sorted(TAB_ALIASES), help="MLC alias: dev / prod")
    ap.add_argument("--prefix", help="URL prefix of the target tab")
    ap.add_argument("--id", dest="tab_id", help="tab id prefix from `tabs`")
    ap.add_argument("--out", default=os.path.normpath(DEFAULT_SHOT_DIR),
                    help="screenshot directory")
    ap.add_argument("--interval", type=float, default=1.0,
                    help="perf: seconds between polls")
    ap.add_argument("--json", dest="json_path", default=None,
                    help="perf: append each poll as a JSON line to PATH")
    ap.add_argument("--activate", action="store_true",
                    help="bring the tab to front first (Target.activateTarget) "
                         "— raises the owner's window; opt-in only, off by default")
    ap.add_argument("cmd")
    ap.add_argument("args", nargs="*")
    ns = ap.parse_args()

    if ns.cmd == "tabs":
        list_tabs(ns.port)
        return

    prefix = ns.prefix or TAB_ALIASES.get(ns.tab or "")
    tab = pick_tab(ns.port, prefix=prefix, tab_id=ns.tab_id)
    print(f"tab: {tab['url']}", file=sys.stderr)
    if ns.activate:
        activate_tab(ns.port, tab["id"])
        time.sleep(0.25)
    ws = websocket.create_connection(
        tab["webSocketDebuggerUrl"], timeout=30, suppress_origin=True,
    )
    c = CDP(ws)
    a = ns.args
    try:
        if ns.cmd == "shot":
            c.shot(a[0], ns.out)
        elif ns.cmd == "click":
            c.click(int(a[0]), int(a[1]))
            print("click", a[0], a[1])
        elif ns.cmd == "dblclick":
            c.dblclick(int(a[0]), int(a[1]))
            print("dblclick", a[0], a[1])
        elif ns.cmd == "move":
            c.mouse("mouseMoved", int(a[0]), int(a[1]))
            print("move", a[0], a[1])
        elif ns.cmd == "drag":
            c.drag(int(a[0]), int(a[1]), int(a[2]), int(a[3]))
            print("drag", a[0], a[1], "->", a[2], a[3])
        elif ns.cmd == "wheel":
            c.mouse("mouseWheel", int(a[0]), int(a[1]), dy=int(a[2]))
            print("wheel", a[2])
        elif ns.cmd == "type":
            text = " ".join(a)
            c.type_text(text)
            print("type", len(text), "chars")
        elif ns.cmd == "key":
            repeat = int(a[1]) if len(a) > 1 else 1
            for _ in range(repeat):
                c.key(a[0])
            print("key", a[0], "x", repeat)
        elif ns.cmd == "reload":
            c.send("Page.enable")
            c.send("Page.reload", {"ignoreCache": True})
            time.sleep(float(a[0]) if a else 6.0)
            print("reloaded")
        elif ns.cmd == "eval":
            js = " ".join(a)
            r = c.send("Runtime.evaluate", {
                "expression": js, "returnByValue": True,
            })
            print(json.dumps(r.get("result", {}).get("value"), ensure_ascii=False))
        elif ns.cmd == "perf":
            seconds = float(a[0]) if a else 60.0
            cmd_perf(c, seconds, ns.interval, ns.json_path)
        elif ns.cmd == "hud":
            if not a:
                raise SystemExit("hud: expected on|off")
            cmd_hud(c, a[0])
        else:
            raise SystemExit(f"unknown cmd {ns.cmd}")
    finally:
        ws.close()


if __name__ == "__main__":
    main()
