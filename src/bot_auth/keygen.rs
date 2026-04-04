use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::path::Path;

/// Generated Ed25519 keypair for Web Bot Auth
pub struct BotKeyPair {
    /// Raw 32-byte private key
    pub private_key: [u8; 32],
    /// Raw 32-byte public key
    pub public_key: [u8; 32],
    /// JWK thumbprint (RFC 7638) — used as keyid in signatures
    pub thumbprint: String,
    /// Base64url-encoded public key (for JWKS)
    pub public_key_b64: String,
}

impl BotKeyPair {
    /// Generate a new random Ed25519 keypair
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self::from_signing_key(&signing_key)
    }

    /// Load private key from a 32-byte raw file
    pub fn from_private_key_file(path: &Path) -> std::io::Result<Self> {
        let bytes = std::fs::read(path)?;
        if bytes.len() != 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Expected 32-byte Ed25519 private key, got {} bytes", bytes.len()),
            ));
        }
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&bytes);
        let signing_key = SigningKey::from_bytes(&private_key);
        Ok(Self::from_signing_key(&signing_key))
    }

    /// Save private key to a 32-byte raw file
    pub fn save_private_key(&self, path: &Path) -> std::io::Result<()> {
        std::fs::write(path, &self.private_key)
    }

    /// Load or generate: if file exists, load it; otherwise generate and save
    pub fn load_or_generate(path: &Path) -> std::io::Result<Self> {
        if path.exists() {
            Self::from_private_key_file(path)
        } else {
            let kp = Self::generate();
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            kp.save_private_key(path)?;
            Ok(kp)
        }
    }

    fn from_signing_key(signing_key: &SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        let private_key = signing_key.to_bytes();
        let public_key = verifying_key.to_bytes();
        let public_key_b64 = general_purpose::URL_SAFE_NO_PAD.encode(public_key);
        let jwk_json = format!(
            "{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{}\"}}",
            public_key_b64
        );
        let thumbprint =
            general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(jwk_json.as_bytes()));
        Self {
            private_key,
            public_key,
            thumbprint,
            public_key_b64,
        }
    }
}
