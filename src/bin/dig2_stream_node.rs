//! Node entry: own Chrome, push frame bytes to C2, apply input that comes back.
//!
//! Dials C2 only. HQ never appears in the arguments.

use std::path::PathBuf;
use std::time::Duration;

use dig2browser::browser_stream::{run_node, NodeOptions};

#[tokio::main]
async fn main() {
    let mut c2 = None;
    let mut session = None;
    let mut profile = None;
    let mut evidence = None;
    let mut click_wait = 90u64;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--c2" => c2 = Some(need(&arg, args.next())),
            "--session" => session = Some(need(&arg, args.next())),
            "--profile" => profile = Some(PathBuf::from(need(&arg, args.next()))),
            "--evidence" => evidence = Some(PathBuf::from(need(&arg, args.next()))),
            "--click-wait-secs" => {
                click_wait = need(&arg, args.next())
                    .parse()
                    .unwrap_or_else(|_| fail("--click-wait-secs is not an integer"));
            }
            "--help" | "-h" => {
                eprintln!(
                    "dig2-stream-node --c2 http://HOST:PORT --session ID --profile DIR --evidence FILE"
                );
                return;
            }
            other => fail(&format!("unknown argument: {other}")),
        }
    }
    let options = NodeOptions {
        c2: c2.unwrap_or_else(|| fail("--c2 is required")),
        session: session.unwrap_or_else(|| fail("--session is required")),
        profile: profile.unwrap_or_else(|| fail("--profile is required")),
        evidence: evidence.unwrap_or_else(|| fail("--evidence is required")),
        click_wait: Duration::from_secs(click_wait),
    };
    match run_node(options).await {
        Ok(proof) => {
            eprintln!(
                "[stream-node] click landed dom={} frames_sent={}",
                proof.dom, proof.frames_sent
            );
        }
        Err(err) => fail(&err.to_string()),
    }
}

fn need(flag: &str, value: Option<String>) -> String {
    value.unwrap_or_else(|| fail(&format!("{flag} requires a value")))
}

fn fail(message: &str) -> ! {
    eprintln!("dig2-stream-node: {message}");
    std::process::exit(2);
}
