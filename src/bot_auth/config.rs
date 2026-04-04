use std::path::PathBuf;

/// Identity of a verified bot/crawler for Web Bot Auth
#[derive(Clone, Debug)]
pub struct BotIdentity {
    /// Human-readable bot name (e.g. "dig2crawl")
    pub name: String,
    /// Homepage URL where the bot is described
    pub homepage: String,
    /// URL where the JWKS directory is hosted (e.g. "https://example.com/.well-known/http-message-signatures-directory")
    /// Can also be a data: URL for inline JWKS
    pub jwks_url: String,
    /// Path to the Ed25519 private key file (32 bytes raw)
    pub private_key_path: PathBuf,
    /// Signature validity duration in seconds (default: 300 = 5 minutes)
    pub signature_ttl_secs: u64,
}

impl BotIdentity {
    /// Create a new bot identity
    pub fn new(
        name: impl Into<String>,
        homepage: impl Into<String>,
        jwks_url: impl Into<String>,
        key_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            name: name.into(),
            homepage: homepage.into(),
            jwks_url: jwks_url.into(),
            private_key_path: key_path.into(),
            signature_ttl_secs: 300,
        }
    }

    /// Set custom signature TTL
    pub fn with_ttl(mut self, secs: u64) -> Self {
        self.signature_ttl_secs = secs;
        self
    }
}
