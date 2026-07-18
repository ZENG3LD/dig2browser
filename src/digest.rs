//! Content digests shared by collection services without duplicating crypto dependencies.

use sha2::{Digest, Sha256};

pub fn sha256_bytes(content: &[u8]) -> [u8; 32] {
    Sha256::digest(content).into()
}
