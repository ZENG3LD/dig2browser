# dig2browser — wasm-bindgen test runner

**Спека от digdigdig3 team. 2026-05-28.**

## Что нужно

Запустить `cargo test --target wasm32-unknown-unknown` на любом nemo-crate **без установки Firefox/Chrome/geckodriver/chromedriver** через PATH. dig2browser уже умеет WebDriver — добавить over it: автоматический запуск driver server + wasm-bindgen-test runner harness.

## Зачем

Сейчас у каждого crate-консьюмера wasm-кода (digdigdig3, mylittlechart future demo, etc.) есть тесты вроде:

```rust
// crates/digdigdig3/tests/wasm_smoke.rs
#![cfg(target_arch = "wasm32")]
use wasm_bindgen_test::*;
wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn binance_ws_handshake_succeeds() { ... }
```

Чтобы их запустить, нужен либо:
- `wasm-pack test --headless --firefox crates/X --test wasm_smoke` (требует firefox+geckodriver на PATH)
- `wasm-pack test --headless --chrome ...` (chromedriver на PATH)

На dev машинах у нас часто Edge **без** chromedriver/msedgedriver. dig2browser уже общается с Edge/Chrome/Firefox — он может запускать driver сам.

## Реальная архитектура wasm-pack

`wasm-pack test` под капотом делает:

1. `cargo build --target wasm32-unknown-unknown --tests`
2. Берёт `.wasm` файл + сгенерированный JS shim
3. Запускает **внутренний HTTP сервер** на localhost:N (отдаёт wasm + shim + test harness HTML)
4. Запускает driver (chromedriver/geckodriver) через `webdriver::ServerLauncher`
5. Создаёт WebDriver session, навигирует на свой URL
6. Test harness JS гоняет тесты и отчитывается обратно через `console.log`
7. wasm-pack читает console output, парсит pass/fail per `#[wasm_bindgen_test]`

То есть driver — **обязательный** компонент. wasm-pack ожидает его как отдельный бинарь на PATH.

## Что предлагаю добавить в dig2browser

### A) Новый бинарь `dig2-test-driver`

```bash
dig2-test-driver --browser auto --port 4444
```

- `--browser auto` — детект что есть (Edge/Chrome/Firefox), скачать matching driver если нужно
- `--port 4444` — где слушать WebDriver protocol
- Stays running until SIGTERM

Behind the scenes:
1. Detect installed browser (dig2browser уже умеет — `detect/` module)
2. Match driver version (Edge 148 → msedgedriver 148, etc.)
3. Download driver binary в `~/.cache/dig2browser/drivers/<version>/`
4. Spawn driver process on `--port`
5. Pipe through stdout/stderr

**Сейчас в dig2browser:**
- `src/detect/` — детект Edge/Chrome/Firefox installed: ✅
- `src/webdriver/client.rs` — WebDriver client (consumer side): ✅
- **Нет**: spawn driver SERVER. Это новое.

### B) Driver auto-download

Edge driver: `https://msedgedriver.azureedge.net/<version>/edgedriver_win64.zip`
Chrome driver: `https://googlechromelabs.github.io/chrome-for-testing/known-good-versions-with-downloads.json`
Firefox/geckodriver: `https://github.com/mozilla/geckodriver/releases/download/v<version>/geckodriver-v<version>-win64.zip`

Один URL-template per OS+browser. Кэш в `~/.cache/dig2browser/drivers/`. Verify SHA если возможно.

### C) Bin `dig2-wasm-test` — wrapper над wasm-pack

```bash
cd <crate>
dig2-wasm-test --test wasm_smoke
```

Делает:
1. Запускает `dig2-test-driver --port 0` в фоне, ждёт ready signal
2. Берёт port из driver, exposes как `$WASM_BINDGEN_TEST_DRIVER`
3. Запускает `wasm-pack test --headless --chromedriver $DRIVER_PATH <args>` (или передаёт driver port через env)
4. Парсит wasm-pack output, форвардит exit code
5. На exit убивает driver

Альтернатива (более чистая): использовать **`wasm-bindgen-test-runner`** напрямую без wasm-pack. Это бинарь который ставится через `cargo install wasm-bindgen-cli`. Он принимает driver через env:
```
GECKODRIVER=path/to/geckodriver
CHROMEDRIVER=path/to/chromedriver
```

`dig2-wasm-test` экспортирует ту env переменную, запускает `cargo test --target wasm32-unknown-unknown <args>` (cargo автоматически вызывает `wasm-bindgen-test-runner` для wasm32 target если оно установлено).

### D) Cargo integration recipe

В целевом crate (`digdigdig3`, и т.д.) добавить:

```toml
# .cargo/config.toml
[target.wasm32-unknown-unknown]
runner = "dig2-wasm-test"
```

Тогда вызов:
```bash
cargo test --target wasm32-unknown-unknown -p digdigdig3 --test wasm_smoke
```

Cargo автоматически делегирует `dig2-wasm-test` который поднимает driver, гонит test, возвращает exit code. **Никаких ручных установок ничего.**

## Минимальный scope для v1

Что **точно нужно**:

1. **`dig2-test-driver` бинарь**: auto-detect Edge, auto-download matching msedgedriver, spawn on `--port`. Windows-only OK для v1. Linux/Mac follow-up.
2. **`dig2-wasm-test` бинарь**: orchestrator (driver up → cargo test → driver down).
3. **README** с примером для digdigdig3.

Что **не нужно** в v1:
- Multi-browser support (just Edge/msedgedriver сначала)
- Driver SHA verification
- Concurrent test runs (one driver per invocation)
- BiDi protocol (WebDriver classic достаточно)
- Stealth features (we control the test page, not scraping)

## Сторонние тулы для inspiration

- [`wasm-bindgen-test-runner`](https://docs.rs/wasm-bindgen-test/) — это **то** что wasm-pack уже использует под капотом. Можно скопировать spawn logic из их кода.
- [`webdriver-install`](https://crates.io/crates/webdriver-install) — Rust crate для auto-download driver. Можно как dependency.
- [`puppeteer-fetcher`](https://github.com/puppeteer/puppeteer/tree/main/packages/browsers) — JS, но протокол скачивания общий.

## Эстимат

- `dig2-test-driver`: ~200 LOC (detect + download + spawn). Reuses `detect/` уже имеющийся в dig2browser.
- `dig2-wasm-test`: ~150 LOC (orchestrate driver + cargo test).
- README + example: ~100 LOC.

Итого **~450 LOC + driver-download dependency**. Один-два дня для одного разработчика. Один новый Cargo dep (`webdriver-install` или эквивалент).

## Acceptance

После того как dig2browser выкатит v0.4.12 (или какая версия):

В `digdigdig3` repo:
```toml
# .cargo/config.toml
[target.wasm32-unknown-unknown]
runner = "dig2-wasm-test"

[dev-dependencies]
# unchanged
```

Команда:
```bash
cd c:/Users/VA PC/CODING/ML_TRADING/nemo/digdigdig3
cargo test --target wasm32-unknown-unknown -p digdigdig3 --test wasm_smoke
```

Должно:
1. Запустить msedgedriver автоматом
2. Скомпилить wasm test
3. Прогнать в headless Edge
4. Распечатать `test result: ok. 2 passed; 0 failed` или соответствующее fail
5. Driver на выход — убит чисто

## Контекст со стороны digdigdig3

- digdigdig3 v0.3.11 (текущий) + Wave 2 wasm work (5 локальных commits, не запушено)
- `crates/digdigdig3/tests/wasm_smoke.rs` готов, ждёт runner
- `cargo check --target wasm32-unknown-unknown -p digdigdig3` = 0 errors уже
- 9 connectors доступны через wasm: Binance, Bybit, OKX, Bitget, Bitstamp, Coinbase, Kraken, Deribit, HTX

Без real wasm test runner мы не можем валидировать что wsadapter работает в реальном Edge — только compile-time гарантии. Это блокирует release wave 2 на crates.io.

## Контакт

digdigdig3 team нужно это для блокировки MLC demo. Ping когда v0.4.12 готов и я сразу подключусь.
