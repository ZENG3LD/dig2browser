# dev-attach

Attach to an existing headed Chrome/Edge browser and debug it live via CDP.

Unlike `dev-fetch` (which always spawns a new browser), `dev-attach` connects
to a browser the owner keeps open manually. The browser is **never killed**
when `dev-attach` exits.

## Step 1: Launch Chrome with debug port open

```sh
# Windows / macOS / Linux
chrome --remote-debugging-port=9222 --user-data-dir=%TEMP%\mlc-debug http://127.0.0.1:17499/index.html
# or Edge:
msedge --remote-debugging-port=9222 --user-data-dir=%TEMP%\mlc-debug http://127.0.0.1:17499/index.html
```

The `--user-data-dir` flag is required on some systems to allow the debug port.

## Step 2: Attach and watch

```sh
# Poll every 2 s: print MLC_FRAMES + dimensions + any new console messages
dev-attach --port 9222 --target http://127.0.0.1:17499 --watch-console

# One-shot JS eval (exits immediately after printing result)
dev-attach --port 9222 --eval "JSON.stringify({frames: window.MLC_FRAMES})"

# One-shot screenshot
dev-attach --port 9222 --screenshot ./snap.png

# Periodic screenshots every 5 seconds (combined with poll loop)
dev-attach --port 9222 --screenshot ./snap.png --interval 5
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--port N` | `9222` | Chrome/Edge remote-debugging port |
| `--target PREFIX` | first non-blank tab | Attach to the first tab whose URL starts with PREFIX |
| `--eval "JS"` | — | Run JS once, print result, exit |
| `--watch-console` | off | Print console messages in the poll loop |
| `--screenshot PATH` | — | Save a screenshot (one-shot or periodic) |
| `--interval N` | 0 (one-shot) | Repeat `--screenshot` every N seconds |

## Poll loop output format

```
[t=4s] frames=120 | client=1280x800 | screen=1920x1080 | canvas=1280x800
  console: [log] wasm initialized
  console: [warn] slow frame 42ms
```

`frames` reads `window.MLC_FRAMES`; shows `?` if the global is not set yet.

## Hang forensics — `--hang-report`

For a page whose main thread has stopped: it prints nothing to the console,
because a blocked thread emits no events at all. The log being empty IS the
symptom, so the diagnosis has to come from outside the page.

```bash
# what is this page spending itself on (works on a healthy page too)
dev-attach --port 9222 --hang-report --hang-seconds 3

# same, then take the tab back
dev-attach --port 9222 --hang-report --recover
```

What it does, in order:

1. **Probe** — one bounded `Runtime.evaluate("1")`. Two seconds without an
   answer and the page counts as BLOCKED.
2. **Healthy page** → CPU-profile the isolate and print the hottest frames by
   self time. Rust/wasm frames come back with their real symbol names from the
   dev build's name section, e.g.
   `uzor::core::render::svg::parse_number::h4717…`.
3. **Blocked page** → the profiler is served BY the stuck thread and answers
   nothing (measured, not assumed), so it tries `Debugger.pause`, whose
   `Debugger.paused` event carries the stack that is spinning.
4. **`--recover`** (opt-in, and only after the evidence attempt):
   `Runtime.terminateExecution` → re-probe → `Page.reload` → re-probe → as a
   last resort open a replacement tab at the same URL and close the wedged one.

Everything here speaks raw CDP over the **browser** endpoint with a flat
session (`Target.attachToTarget {flatten:true}`), never the library's attach
path and never the page's own socket:

* the attach path negotiates with the page, so it hangs on exactly the pages
  this command exists for;
* a session opened directly onto a page is a legacy session and every command
  queues behind the main thread — the thread that is stuck. A flat session
  from the browser endpoint is what DevTools itself uses.

**Recovery is opt-in on purpose.** A wedged renderer is the only place the
state that caused it still exists; reloading or recycling the tab destroys it,
and then the bug is a story instead of a stack.
