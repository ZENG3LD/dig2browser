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
