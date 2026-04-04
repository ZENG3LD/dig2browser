//! Generate Ed25519 keypair for Web Bot Auth and output JWKS directory.
//!
//! Usage: cargo run --bin keygen -- <key-file-path>
//! Example: cargo run --bin keygen -- keys/dig2crawl.key

use dig2browser::bot_auth::{BotKeyPair, JwksDirectory};
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let key_path = args.get(1).map(|s| s.as_str()).unwrap_or("keys/bot.key");

    let path = Path::new(key_path);
    let keypair = BotKeyPair::load_or_generate(path).expect("Failed to load or generate keypair");

    let jwks = JwksDirectory::from_keypair(&keypair);

    println!("Key file: {}", path.display());
    println!("Thumbprint (keyid): {}", keypair.thumbprint);
    println!("Public key (b64url): {}", keypair.public_key_b64);
    println!();
    println!("=== JWKS Directory (host at /.well-known/http-message-signatures-directory) ===");
    println!("{}", jwks.to_json());
    println!();
    println!("=== Data URL (for inline Signature-Agent) ===");
    println!("{}", jwks.to_data_url());
}
