use base64::engine::general_purpose;
use base64::Engine as _;
use serde::Serialize;

use super::BotKeyPair;

/// A JWKS directory for Web Bot Auth — hosted at `/.well-known/http-message-signatures-directory`
#[derive(Serialize)]
pub struct JwksDirectory {
    /// List of JWK entries
    pub keys: Vec<JwkEntry>,
}

/// Individual JWK entry for an Ed25519 signing key
#[derive(Serialize)]
pub struct JwkEntry {
    /// Key type — always "OKP" for Ed25519
    pub kty: String,
    /// Curve — always "Ed25519"
    pub crv: String,
    /// Base64url-encoded public key (x coordinate for OKP)
    pub x: String,
    /// Key ID (JWK thumbprint per RFC 7638)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// Key use — "sig" for signing keys
    #[serde(rename = "use")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
}

impl JwksDirectory {
    /// Create a JWKS directory from a keypair
    pub fn from_keypair(keypair: &BotKeyPair) -> Self {
        Self {
            keys: vec![JwkEntry {
                kty: "OKP".into(),
                crv: "Ed25519".into(),
                x: keypair.public_key_b64.clone(),
                kid: Some(keypair.thumbprint.clone()),
                use_: Some("sig".into()),
            }],
        }
    }

    /// Serialize to pretty-printed JSON string
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self)
            .expect("JWKS serialization is infallible for well-formed JwkEntry values")
    }

    /// Generate a `data:` URL containing the JWKS inline, suitable for the `Signature-Agent` header
    pub fn to_data_url(&self) -> String {
        let json = serde_json::to_string(self)
            .expect("JWKS serialization is infallible for well-formed JwkEntry values");
        let encoded = general_purpose::STANDARD.encode(json.as_bytes());
        format!("data:application/http-message-signatures-directory;base64,{encoded}")
    }

    /// Save JWKS JSON to a file for hosting at `/.well-known/http-message-signatures-directory`
    pub fn save_to_file(&self, path: &std::path::Path) -> std::io::Result<()> {
        std::fs::write(path, self.to_json())
    }
}
