use base64::{engine::general_purpose, Engine as _};
use indexmap::IndexMap;
use rand::RngCore;
use web_bot_auth::components::{CoveredComponent, DerivedComponent, HTTPField, HTTPFieldParametersSet};
use web_bot_auth::keyring::Algorithm;
use web_bot_auth::message_signatures::{MessageSigner, UnsignedMessage};

use super::{BotIdentity, BotKeyPair};

/// Signed request headers ready to be attached to an HTTP request
#[derive(Clone, Debug)]
pub struct SignedHeaders {
    /// Value for the `Signature-Agent` header
    pub signature_agent: String,
    /// Value for the `Signature-Input` header (includes `sig1=` label prefix)
    pub signature_input: String,
    /// Value for the `Signature` header (includes `sig1=` label prefix)
    pub signature: String,
}

/// Signs HTTP requests with Web Bot Auth headers
pub struct RequestSigner {
    identity: BotIdentity,
    keypair: BotKeyPair,
}

impl RequestSigner {
    /// Create a new request signer from identity and keypair
    pub fn new(identity: BotIdentity, keypair: BotKeyPair) -> Self {
        Self { identity, keypair }
    }

    /// Create from identity, loading/generating key from `identity.private_key_path` automatically
    pub fn from_identity(identity: BotIdentity) -> std::io::Result<Self> {
        let keypair = BotKeyPair::load_or_generate(&identity.private_key_path)?;
        Ok(Self { identity, keypair })
    }

    /// Get the JWK thumbprint used as the keyid in signatures
    pub fn keyid(&self) -> &str {
        &self.keypair.thumbprint
    }

    /// Sign a request to the given URL with the given HTTP method.
    ///
    /// Returns the three headers to attach to the outgoing request:
    /// - `Signature-Agent`
    /// - `Signature-Input`
    /// - `Signature`
    pub fn sign_request(&self, method: &str, url: &str) -> Result<SignedHeaders, SignError> {
        let parsed_url = url::Url::parse(url).map_err(|e| SignError::InvalidUrl(e.to_string()))?;
        let authority = match parsed_url.port() {
            Some(port) => format!("{}:{}", parsed_url.host_str().unwrap_or(""), port),
            None => parsed_url.host_str().unwrap_or("").to_string(),
        };

        // Signature-Agent header value (SFV bare string item pointing to JWKS URL)
        let signature_agent = format!("\"{}\"", self.identity.jwks_url);

        let mut msg = RequestMessage {
            method: method.to_uppercase(),
            authority,
            signature_agent: signature_agent.clone(),
            signature_input: String::new(),
            signature_header: String::new(),
        };

        let nonce = generate_nonce();
        let signer = MessageSigner {
            keyid: self.keypair.thumbprint.clone(),
            nonce,
            tag: "web-bot-auth".into(),
        };

        signer
            .generate_signature_headers_content(
                &mut msg,
                time::Duration::seconds(self.identity.signature_ttl_secs as i64),
                Algorithm::Ed25519,
                &self.keypair.private_key,
            )
            .map_err(|e| SignError::SigningFailed(format!("{e:?}")))?;

        Ok(SignedHeaders {
            signature_agent,
            signature_input: format!("sig1={}", msg.signature_input),
            signature: format!("sig1={}", msg.signature_header),
        })
    }
}

/// Internal message type implementing web-bot-auth traits
struct RequestMessage {
    method: String,
    authority: String,
    signature_agent: String,
    signature_input: String,
    signature_header: String,
}

impl UnsignedMessage for RequestMessage {
    fn fetch_components_to_cover(&self) -> IndexMap<CoveredComponent, String> {
        IndexMap::from_iter([
            (
                CoveredComponent::Derived(DerivedComponent::Method { req: false }),
                self.method.clone(),
            ),
            (
                CoveredComponent::Derived(DerivedComponent::Authority { req: false }),
                self.authority.clone(),
            ),
            (
                CoveredComponent::HTTP(HTTPField {
                    name: "signature-agent".to_string(),
                    parameters: HTTPFieldParametersSet(vec![]),
                }),
                self.signature_agent.clone(),
            ),
        ])
    }

    fn register_header_contents(&mut self, signature_input: String, signature_header: String) {
        self.signature_input = signature_input;
        self.signature_header = signature_header;
    }
}

/// Errors that can occur during request signing
#[derive(Debug)]
pub enum SignError {
    /// URL could not be parsed
    InvalidUrl(String),
    /// Signing failed
    SigningFailed(String),
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUrl(e) => write!(f, "invalid URL: {e}"),
            Self::SigningFailed(e) => write!(f, "signing failed: {e}"),
        }
    }
}

impl std::error::Error for SignError {}

fn generate_nonce() -> String {
    let mut bytes = [0u8; 48];
    rand::thread_rng().fill_bytes(&mut bytes);
    general_purpose::STANDARD.encode(bytes)
}
