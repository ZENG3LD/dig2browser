//! Cargo test runner for `wasm32-unknown-unknown`.
//! Invoked by cargo as: dig2-wasm-test <test.wasm> [filter args...]
use std::path::PathBuf;

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let wasm = match args.next() {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("usage: dig2-wasm-test <test.wasm> [args...]");
            std::process::exit(2);
        }
    };
    let rest: Vec<String> = args.collect();
    match dig2browser::wasmtest::run(&wasm, &rest).await {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("dig2-wasm-test: error: {e}");
            std::process::exit(1);
        }
    }
}
