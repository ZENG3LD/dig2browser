#!/usr/bin/env python3
"""Tor CDP panel for the spare dig2browser --tor Chrome.

Attaches to a launcher that was started with --tor. Refuses 9222 and 9223.
`up` and `live` start only a spare --tor launcher. Does not print a .onion hostname.

  python tor_cdp.py live --wait 40
  python tor_cdp.py status
  python tor_cdp.py trace --reload --wait 20
  python tor_cdp.py console
  python tor_cdp.py net --reload
  python tor_cdp.py eval "document.readyState"
  python tor_cdp.py shot boot
  python tor_cdp.py click 200 200
  python tor_cdp.py key Escape
  python tor_cdp.py type hello
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
from urllib.parse import urlparse

FORBIDDEN_PORTS = {9222, 9223}
ONION_RE = re.compile(r"[a-z2-7]{16,56}\.onion", re.I)
CDP_CONTROL = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "cdp-control", "cdp_control.py"
))
DEFAULT_OUT = os.environ.get("TOR_CDP_OUT") or os.path.join(tempfile.gettempdir(), "tor-cdp")

STATUS_JS = r"""(() => {
  const clip = (value) => String(value == null ? "" : value)
    .replace(/[a-z2-7]{16,56}\.onion/ig, "[onion]")
    .slice(0, 240);
  const loc = {
    protocol: location.protocol,
    onion: !!(location.hostname && location.hostname.endsWith(".onion")),
    path: location.pathname
  };
  const text = (document.body && document.body.innerText) || "";
  const resources = performance.getEntriesByType("resource").map((entry) => {
    let path = "";
    let onion = false;
    let port = "";
    try {
      const url = new URL(entry.name);
      path = url.pathname.slice(0, 80);
      onion = url.hostname.endsWith(".onion");
      port = url.port || (url.protocol === "https:" ? "443" : "80");
    } catch (err) {}
    return {path, onion, port, type: entry.initiatorType, transfer: entry.transferSize || 0};
  });
  const rows = (list) => (list || []).slice(-12).map((row) => {
    const copy = {};
    Object.keys(row).forEach((key) => { copy[key] = clip(row[key]); });
    return copy;
  });
  return JSON.stringify({
    ready: document.readyState,
    loc,
    title: clip(document.title),
    bodyLen: text.length,
    text: clip(text),
    boot: !!document.getElementById("boot"),
    wasm: typeof window.__MLC_WASM,
    painted: window.__MLC_UI_PAINTED__ === true,
    secure: window.isSecureContext === true,
    uuid: typeof (window.crypto && window.crypto.randomUUID),
    errCount: window.__MLC_ERROR_COUNT__ || 0,
    err: clip(window.__MLC_FIRST_ERROR__),
    bootErr: clip((document.getElementById("boot-err") || {}).textContent),
    fetches: rows(window.__FETCH_LOG__),
    ws: rows(window.__WS_LOG__),
    resources
  });
})()"""


def redact(text) -> str:
    return ONION_RE.sub("[onion]", "" if text is None else str(text))


def say(text="") -> None:
    print(redact(text), flush=True)


def load_cdp():
    spec = importlib.util.spec_from_file_location("cdp_control", CDP_CONTROL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def discover_tor_launch():
    script = r"""
Get-CimInstance Win32_Process -Filter "Name = 'dev-launch-debug.exe'" | ForEach-Object {
  if ($_.CommandLine -match '(?i)(^|\s)--tor(\s|$)') {
    $port = 0
    if ($_.CommandLine -match '--port\s+(\d+)') { $port = [int]$Matches[1] }
    '{0} {1}' -f $_.ProcessId, $port
  }
}
"""
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-Command", script],
        capture_output=True, text=True, errors="replace", timeout=20,
    )
    found = []
    for line in (proc.stdout or "").splitlines():
        parts = line.split()
        if len(parts) != 2 or not parts[0].isdigit() or not parts[1].isdigit():
            continue
        found.append((int(parts[0]), int(parts[1])))
    return found


def resolve_port(explicit):
    if explicit is not None:
        if explicit in FORBIDDEN_PORTS:
            raise SystemExit(f"refusing operator port {explicit}")
        return explicit, None
    found = [(pid, port) for pid, port in discover_tor_launch() if port not in FORBIDDEN_PORTS and port > 0]
    if not found:
        raise SystemExit("no --tor launcher")
    if len(found) > 1:
        say("multiple --tor launchers: " + ", ".join(f"pid={pid} port={port}" for pid, port in found))
        raise SystemExit("pass --port")
    return found[0][1], found[0][0]


def json_list(port):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=5) as handle:
        return json.load(handle)


def pick_page(port):
    pages = [tab for tab in json_list(port) if tab.get("type") == "page"]
    for tab in pages:
        url = tab.get("url") or ""
        if ".onion" in url.lower():
            return tab
    for tab in pages:
        if (tab.get("url") or "").startswith("http"):
            return tab
    if pages:
        return pages[0]
    raise SystemExit(f"no page on :{port}")


def describe(url):
    if not url:
        return "scheme= empty onion=false port= path="
    try:
        parsed = urlparse(url)
    except Exception:
        return "scheme=bad onion=false port= path="
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else "")
    return "scheme=%s onion=%s port=%s path=%s" % (
        parsed.scheme or "other",
        str(host.endswith(".onion")).lower(),
        port,
        (parsed.path or "/")[:90],
    )


def connect(port):
    cdp = load_cdp()
    tab = pick_page(port)
    ws = cdp.websocket.create_connection(
        tab["webSocketDebuggerUrl"], timeout=30, suppress_origin=True
    )
    return cdp, cdp.CDP(ws), ws, tab


def cmd_status(cdp_client):
    result = cdp_client.send("Runtime.evaluate", {
        "expression": STATUS_JS,
        "returnByValue": True,
    })
    value = (result.get("result") or {}).get("value")
    say(value if isinstance(value, str) else json.dumps(value, ensure_ascii=False))


def classify_event(msg):
    method = msg.get("method") or ""
    params = msg.get("params") or {}
    if method == "Network.requestWillBeSent":
        req = params.get("request") or {}
        return "REQ %s %s" % (params.get("type"), describe(req.get("url")))
    if method == "Network.responseReceived":
        resp = params.get("response") or {}
        return "RESP status=%s %s %s" % (resp.get("status"), params.get("type"), describe(resp.get("url")))
    if method == "Network.loadingFailed":
        return "FAIL type=%s error=%s canceled=%s" % (
            params.get("type"), params.get("errorText"), params.get("canceled")
        )
    if method == "Network.loadingFinished":
        return "FINISH bytes=%s" % params.get("encodedDataLength")
    if method == "Runtime.exceptionThrown":
        details = params.get("exceptionDetails") or {}
        exc = details.get("exception") or {}
        frames = []
        for frame in ((details.get("stackTrace") or {}).get("callFrames") or [])[:8]:
            frames.append("%s:%s" % (frame.get("functionName") or "?", frame.get("lineNumber")))
        text = exc.get("description") or details.get("text") or ""
        return "EXC %s | %s" % (text[:500], " ".join(frames))
    if method == "Runtime.consoleAPICalled":
        bits = []
        for arg in params.get("args") or []:
            bits.append(str(arg.get("value") if "value" in arg else arg.get("description") or arg.get("type")))
        return "CON %s %s" % (params.get("type"), " ".join(bits)[:400])
    if method == "Log.entryAdded":
        entry = params.get("entry") or {}
        return "LOG %s %s" % (entry.get("level"), str(entry.get("text"))[:400])
    if method in ("Page.loadEventFired", "Page.domContentEventFired", "Page.javascriptDialogOpening"):
        if method == "Page.javascriptDialogOpening":
            return "DIALOG %s %s" % (params.get("type"), str(params.get("message"))[:200])
        return method
    if method == "Page.frameNavigated":
        frame = params.get("frame") or {}
        return "NAV %s" % describe(frame.get("url"))
    return ""


def read_one(ws, seconds):
    ws.settimeout(seconds)
    try:
        raw = ws.recv()
    except Exception as exc:
        name = type(exc).__name__
        if "Timeout" in name:
            return None
        if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError)) or "ConnectionClosed" in name:
            say("CDP closed: %s" % name)
            return False
        raise
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def cmd_trace(ws, reload, wait, kinds):
    mid = 0
    pending = {}

    def emit(method, params=None):
        nonlocal mid
        mid += 1
        pending[mid] = method
        ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))

    # Runtime has to be enabled before the navigation. Otherwise the
    # exception the user sees in F12 is already gone and this drain is empty.
    emit("Page.enable")
    if "net" in kinds:
        emit("Network.enable")
    if "console" in kinds:
        emit("Runtime.enable")
        emit("Log.enable")
    arm = time.time() + 5
    while pending and time.time() < arm:
        msg = read_one(ws, max(0.1, arm - time.time()))
        if msg is False:
            return
        if not msg:
            continue
        if msg.get("id") in pending:
            if "error" in msg:
                say("CDP_ERR %s %s" % (pending[msg["id"]], msg["error"]))
            pending.pop(msg["id"], None)
            continue
        line = classify_event(msg)
        if line:
            say(line)
    if pending:
        say("F12 enable incomplete: %s" % ",".join(sorted(set(pending.values()))))
    else:
        say("F12 on")
    if reload:
        emit("Page.reload", {"ignoreCache": True})
        say("RELOAD")
    deadline = time.time() + wait
    while time.time() < deadline:
        msg = read_one(ws, min(1.0, max(0.1, deadline - time.time())))
        if msg is False:
            return
        if not msg:
            continue
        if msg.get("id"):
            if "error" in msg:
                say("CDP_ERR %s" % msg["error"])
            pending.pop(msg["id"], None)
            continue
        line = classify_event(msg)
        if not line:
            continue
        if line.startswith(("REQ", "RESP", "FAIL", "FINISH", "NAV")) and "net" not in kinds:
            continue
        if line.startswith(("EXC", "CON", "LOG", "DIALOG")) and "console" not in kinds:
            continue
        say(line)


EXE = os.environ.get("TOR_CDP_EXE") or ""
MIRRORS = os.environ.get("TOR_CDP_MIRRORS") or ""
LOG_PATH = os.path.join(DEFAULT_OUT, "launcher.log")
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_NEW_CONSOLE = 0x00000010


def onion_url():
    if not MIRRORS:
        raise SystemExit("set TOR_CDP_MIRRORS")
    host = ""
    with open(MIRRORS, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if line.startswith("utah.onion="):
                host = line.split("=", 1)[1].strip()
                break
    if not host.endswith(".onion") or not ONION_RE.fullmatch(host):
        raise SystemExit("mirror host is not an onion")
    return "http://" + host + "/"


def port_open(port):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version", timeout=1) as handle:
            return handle.status == 200
    except Exception:
        return False


def spare_port():
    forced = os.environ.get("TOR_CDP_PORT")
    if forced:
        port = int(forced)
        if port in FORBIDDEN_PORTS:
            raise SystemExit("forbidden port")
        return port
    for port in range(9336, 9346):
        if port in FORBIDDEN_PORTS or port_open(port):
            continue
        return port
    raise SystemExit("no spare port")


def pump_log(log, seen, path):
    log.flush()
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            text = redact(handle.read())
    except OSError:
        text = seen
    if text == seen:
        return seen
    fresh = text[len(seen):] if text.startswith(seen) else text
    for line in fresh.splitlines():
        if any(token in line for token in (
            "preflight", "socks:", "bootstrap:", "launching:", "ready", "error", "failed",
        )):
            say(line)
    return text


def start_spare(browser):
    browser = browser or "chrome"
    if browser not in ("chrome", "edge", "firefox"):
        raise SystemExit("browser must be chrome, edge, or firefox")
    # A second Chrome would fight the window the operator is watching.
    # Edge and Firefox are separate launches, each with its own Tor.
    if browser == "chrome":
        existing = [(pid, port) for pid, port in discover_tor_launch() if port not in FORBIDDEN_PORTS and port > 0]
        if existing:
            pid, port = existing[0]
            say("already up pid=%s port=%s" % (pid, port))
            return None, None, port, LOG_PATH
    if not EXE or not os.path.isfile(EXE):
        raise SystemExit("set TOR_CDP_EXE to the dev-launch-debug binary")
    port = spare_port()
    profile = os.path.join(tempfile.gettempdir(), "dig2browser-debug-%s" % port)
    os.makedirs(DEFAULT_OUT, exist_ok=True)
    log_path = LOG_PATH if browser == "chrome" else os.path.join(DEFAULT_OUT, "launcher-%s.log" % browser)
    log = open(log_path, "w", encoding="utf-8", errors="replace")
    argv = [EXE, "--port", str(port), "--profile", profile, "--browser", browser, "--tor", "--url", onion_url()]
    proc = subprocess.Popen(
        argv,
        creationflags=CREATE_NEW_PROCESS_GROUP | CREATE_NEW_CONSOLE,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    say("pid=%s port=%s browser=%s" % (proc.pid, port, browser))
    return proc, log, port, log_path


SHIM_JS = r"""(function(){
  var c = globalThis.crypto;
  if (!c || typeof c.randomUUID === "function") return;
  var fn = function() {
    var bytes = new Uint8Array(16);
    c.getRandomValues(bytes);
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    var hex = "";
    for (var i = 0; i < 16; i++) hex += bytes[i].toString(16).padStart(2, "0");
    return hex.slice(0,8)+"-"+hex.slice(8,12)+"-"+hex.slice(12,16)+"-"+hex.slice(16,20)+"-"+hex.slice(20);
  };
  try { Object.defineProperty(c, "randomUUID", { value: fn, configurable: true }); }
  catch (e) { c.randomUUID = fn; }
})();"""


def cmd_shim(ws):
    """Bind randomUUID before the next document. Chromium only."""
    emit_id = 1
    ws.send(json.dumps({
        "id": emit_id,
        "method": "Page.addScriptToEvaluateOnNewDocument",
        "params": {"source": SHIM_JS},
    }))
    deadline = time.time() + 5
    while time.time() < deadline:
        msg = read_one(ws, max(0.1, deadline - time.time()))
        if msg is False:
            return
        if msg and msg.get("id") == emit_id:
            if "error" in msg:
                say("CDP_ERR %s" % msg["error"])
                return
            break
    ws.send(json.dumps({"id": 2, "method": "Page.reload", "params": {"ignoreCache": True}}))
    say("shim armed")


def cmd_up(browser):
    proc, log, port, log_path = start_spare(browser)
    if proc is None:
        return
    seen = ""
    deadline = time.time() + 200
    while time.time() < deadline:
        time.sleep(2)
        seen = pump_log(log, seen, log_path)
        if proc.poll() is not None:
            say("launcher exit %s" % proc.poll())
            log.close()
            return
        if "DevTools ws URL" in seen or "ready —" in seen or "ready -" in seen:
            say("browser up port=%s" % port)
            log.close()
            return
    say("browser not ready port=%s left up pid=%s" % (port, proc.pid))
    log.close()


def cmd_live(browser, wait):
    """Launch the spare and drain F12 from the moment the debugging port answers."""
    proc, log, port, log_path = start_spare(browser or "chrome")
    seen = ""
    deadline = time.time() + 200
    while time.time() < deadline and not port_open(port):
        time.sleep(0.5)
        if log is not None:
            seen = pump_log(log, seen, log_path)
        if proc is not None and proc.poll() is not None:
            say("launcher exit %s" % proc.poll())
            log.close()
            return
    if not port_open(port):
        say("port not open port=%s" % port)
        if log is not None:
            log.close()
        return
    ws = None
    for _ in range(40):
        try:
            _cdp, _client, ws, tab = connect(port)
            say("page %s" % describe(tab.get("url")))
            break
        except Exception as exc:
            say("cdp wait %s" % type(exc).__name__)
            time.sleep(0.5)
    if ws is None:
        say("cdp not open port=%s" % port)
        if log is not None:
            log.close()
        return
    try:
        cmd_trace(ws, False, wait, {"net", "console"})
    finally:
        ws.close()
        if log is not None:
            log.close()


def main():
    parser = argparse.ArgumentParser(description="Tor CDP panel. Refuses ports 9222 and 9223.")
    parser.add_argument("--port", type=int)
    parser.add_argument("--wait", type=float, default=12.0)
    parser.add_argument("--reload", action="store_true")
    parser.add_argument("--out", default=DEFAULT_OUT)
    parser.add_argument("--browser", choices=("chrome", "edge", "firefox"))
    parser.add_argument("cmd")
    parser.add_argument("args", nargs="*")
    ns = parser.parse_args()

    if ns.cmd == "up":
        cmd_up(ns.browser)
        return
    if ns.cmd == "live":
        cmd_live(ns.browser, ns.wait)
        return

    port, pid = resolve_port(ns.port)
    say("port=%s launcher=%s" % (port, pid if pid is not None else "-"))
    _cdp, client, ws, tab = connect(port)
    say("page %s" % describe(tab.get("url")))
    try:
        cmd = ns.cmd
        if cmd == "shim":
            cmd_shim(ws)
        elif cmd == "status":
            cmd_status(client)
        elif cmd == "eval":
            if not ns.args:
                raise SystemExit("eval: expected an expression")
            result = client.send("Runtime.evaluate", {
                "expression": " ".join(ns.args),
                "returnByValue": True,
                "awaitPromise": True,
            })
            value = (result.get("result") or {}).get("value")
            say(value if isinstance(value, str) else json.dumps(value, ensure_ascii=False))
        elif cmd == "shot":
            name = ns.args[0] if ns.args else "shot"
            client.shot(name, ns.out)
        elif cmd == "click":
            client.click(int(ns.args[0]), int(ns.args[1]))
            say("click %s %s" % (ns.args[0], ns.args[1]))
        elif cmd == "key":
            client.key(ns.args[0])
            say("key %s" % ns.args[0])
        elif cmd == "type":
            client.type_text(" ".join(ns.args))
            say("type %s chars" % len(" ".join(ns.args)))
        elif cmd == "reload":
            client.send("Page.enable")
            client.send("Page.reload", {"ignoreCache": True})
            say("reloaded")
        elif cmd in ("trace", "net", "console"):
            kinds = {"net", "console"} if cmd == "trace" else {cmd if cmd != "console" else "console"}
            if cmd == "net":
                kinds = {"net"}
            cmd_trace(ws, ns.reload, ns.wait, kinds)
        else:
            raise SystemExit(f"unknown cmd {cmd}")
    finally:
        ws.close()


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        pass
