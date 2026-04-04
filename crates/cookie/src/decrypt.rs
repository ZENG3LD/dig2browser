//! AES-256-GCM and DPAPI decryption for Chrome cookie values.

use std::path::Path;

use crate::CookieError;

/// Wrapper around a 32-byte AES-256 key derived from Chrome's Local State via DPAPI.
pub struct AesKey(pub [u8; 32]);

/// Read `{profile_dir}/Local State`, extract and DPAPI-decrypt the AES-256 master key
/// that Chrome uses to encrypt cookie values.
pub fn derive_aes_key(profile_dir: &Path) -> Result<AesKey, CookieError> {
    use base64::Engine;

    let local_state_path = profile_dir.join("Local State");

    if !local_state_path.exists() {
        return Err(CookieError::LocalStateMissing {
            path: local_state_path.display().to_string(),
        });
    }

    let raw = std::fs::read_to_string(&local_state_path)?;

    let json: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| CookieError::LocalStateJson(format!("JSON parse error: {e}")))?;

    let b64 = json
        .get("os_crypt")
        .and_then(|v| v.get("encrypted_key"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            CookieError::LocalStateJson("os_crypt.encrypted_key not found in Local State".into())
        })?;

    let mut encrypted_key = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| CookieError::LocalStateJson(format!("Base64 decode error: {e}")))?;

    if encrypted_key.len() <= 5 {
        return Err(CookieError::LocalStateJson(
            "os_crypt.encrypted_key too short".into(),
        ));
    }

    // Strip the "DPAPI" ASCII prefix (5 bytes).
    let dpapi_blob = encrypted_key.split_off(5);

    let key_bytes = dpapi_decrypt(&dpapi_blob)?;

    if key_bytes.len() != 32 {
        return Err(CookieError::LocalStateJson(format!(
            "DPAPI returned {} bytes instead of 32",
            key_bytes.len()
        )));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    Ok(AesKey(key))
}

/// Decrypt a single Chrome cookie `encrypted_value` blob.
///
/// Chrome uses three formats depending on version:
/// - `v10`/`v11` prefix (3 bytes) → AES-256-GCM with DPAPI-derived key
/// - `\x01\x00\x00\x00` prefix → raw DPAPI (pre-Chrome 80)
/// - Empty → unencrypted, return empty string
/// - Other → try as UTF-8 plaintext
pub fn decrypt_value(encrypted: &[u8], key: &AesKey) -> Result<String, CookieError> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    if encrypted.is_empty() {
        return Ok(String::new());
    }

    // AES-256-GCM: v10 or v11 prefix (3 bytes).
    if encrypted.len() >= 3 && (encrypted.starts_with(b"v10") || encrypted.starts_with(b"v11")) {
        let without_prefix = &encrypted[3..];

        if without_prefix.len() < 12 {
            return Err(CookieError::AesGcm);
        }

        let nonce_bytes = &without_prefix[..12];
        let ciphertext = &without_prefix[12..];

        let cipher = Aes256Gcm::new_from_slice(&key.0).map_err(|_| CookieError::AesGcm)?;
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| CookieError::AesGcm)?;

        // Happy path: valid UTF-8 directly.
        if let Ok(s) = String::from_utf8(plaintext.clone()) {
            return Ok(s);
        }

        // Chrome 127+ app-bound encryption: 32-byte binary prefix before the real value.
        if plaintext.len() > 32 {
            if let Ok(s) = String::from_utf8(plaintext[32..].to_vec()) {
                return Ok(s);
            }
        }

        return Err(CookieError::AesGcm);
    }

    // Legacy DPAPI blob: starts with 0x01 0x00 0x00 0x00.
    if encrypted.len() > 4 && encrypted[..4] == [0x01, 0x00, 0x00, 0x00] {
        let plaintext = dpapi_decrypt(encrypted)?;
        return Ok(String::from_utf8_lossy(&plaintext).into_owned());
    }

    // Fallback: try as UTF-8 plaintext.
    Ok(String::from_utf8_lossy(encrypted).into_owned())
}

// LocalFree was removed from the windows crate 0.58; declare it directly.
#[cfg(target_os = "windows")]
extern "system" {
    fn LocalFree(hmem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
}

/// Call `CryptUnprotectData` and return the decrypted plaintext bytes.
#[cfg(target_os = "windows")]
pub(crate) fn dpapi_decrypt(ciphertext: &[u8]) -> Result<Vec<u8>, CookieError> {
    use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};

    let mut input = CRYPT_INTEGER_BLOB {
        cbData: ciphertext.len() as u32,
        pbData: ciphertext.as_ptr() as *mut u8,
    };

    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    unsafe {
        CryptUnprotectData(&input, None, None, None, None, 0, &mut output).map_err(|_| {
            CookieError::DpapiDecrypt { code: 0 }
        })?;
    }

    let result = unsafe {
        std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec()
    };

    unsafe {
        LocalFree(output.pbData.cast());
    }

    Ok(result)
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn dpapi_decrypt(_ciphertext: &[u8]) -> Result<Vec<u8>, CookieError> {
    Err(CookieError::LocalStateJson(
        "DPAPI decryption only available on Windows".into(),
    ))
}
