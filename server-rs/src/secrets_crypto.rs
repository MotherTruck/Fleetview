//! Reversible at-rest encryption for integration credentials, hand-implemented
//! to match Python's `cryptography.fernet.Fernet` wire format byte-for-byte
//! (AES-128-CBC + HMAC-SHA256, base64url-encoded) so integration credentials
//! encrypted by the Python server stay decryptable after cutover with zero
//! data migration. See server/app/secrets_crypto.py for the reference.
//!
//! Token layout (before base64url encoding): 1 byte version (0x80) ||
//! 8 bytes big-endian timestamp || 16 bytes IV || ciphertext (PKCS7-padded)
//! || 32 bytes HMAC-SHA256 over everything before it. The Fernet key itself
//! is 32 base64url-decoded bytes: first 16 are the HMAC signing key, last 16
//! are the AES encryption key.
use aes::Aes128;
use base64::engine::general_purpose::URL_SAFE;
use base64::Engine;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

type Aes128CbcEnc = cbc::Encryptor<Aes128>;
type Aes128CbcDec = cbc::Decryptor<Aes128>;
type HmacSha256 = Hmac<Sha256>;

const FERNET_VERSION: u8 = 0x80;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error(
        "FLEETVIEW_SECRET_KEY is not set. Generate one with: python3 -c \"from cryptography.fernet \
         import Fernet; print(Fernet.generate_key().decode())\" and set it in your .env file before \
         configuring any integration."
    )]
    SecretKeyNotConfigured,
    #[error(
        "Could not decrypt stored credentials -- FLEETVIEW_SECRET_KEY may have changed since they \
         were saved. Re-enter this integration's credentials."
    )]
    DecryptionFailed,
}

struct FernetKey {
    signing_key: [u8; 16],
    encryption_key: [u8; 16],
}

fn parse_key(raw: &str) -> Result<FernetKey, CryptoError> {
    let bytes = URL_SAFE.decode(raw.trim()).map_err(|_| CryptoError::SecretKeyNotConfigured)?;
    if bytes.len() != 32 {
        return Err(CryptoError::SecretKeyNotConfigured);
    }
    let mut signing_key = [0u8; 16];
    let mut encryption_key = [0u8; 16];
    signing_key.copy_from_slice(&bytes[..16]);
    encryption_key.copy_from_slice(&bytes[16..]);
    Ok(FernetKey { signing_key, encryption_key })
}

fn key() -> Result<FernetKey, CryptoError> {
    let raw = std::env::var("FLEETVIEW_SECRET_KEY").unwrap_or_default();
    if raw.is_empty() {
        return Err(CryptoError::SecretKeyNotConfigured);
    }
    parse_key(&raw)
}

pub fn encrypt_text(plaintext: &str) -> Result<String, CryptoError> {
    let k = key()?;
    let timestamp = chrono::Utc::now().timestamp() as u64;
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    let ciphertext = Aes128CbcEnc::new_from_slices(&k.encryption_key, &iv)
        .expect("valid key/iv length")
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext.as_bytes());

    let mut payload = Vec::with_capacity(1 + 8 + 16 + ciphertext.len());
    payload.push(FERNET_VERSION);
    payload.extend_from_slice(&timestamp.to_be_bytes());
    payload.extend_from_slice(&iv);
    payload.extend_from_slice(&ciphertext);

    let mut mac = HmacSha256::new_from_slice(&k.signing_key).expect("hmac accepts any key length");
    mac.update(&payload);
    let tag = mac.finalize().into_bytes();

    let mut token = payload;
    token.extend_from_slice(&tag);
    Ok(URL_SAFE.encode(token))
}

pub fn decrypt_text(ciphertext: &str) -> Result<String, CryptoError> {
    let k = key()?;
    let token = URL_SAFE.decode(ciphertext.trim()).map_err(|_| CryptoError::DecryptionFailed)?;
    if token.len() < 1 + 8 + 16 + 32 {
        return Err(CryptoError::DecryptionFailed);
    }
    let (payload, tag) = token.split_at(token.len() - 32);
    if payload[0] != FERNET_VERSION {
        return Err(CryptoError::DecryptionFailed);
    }

    let mut mac = HmacSha256::new_from_slice(&k.signing_key).expect("hmac accepts any key length");
    mac.update(payload);
    mac.verify_slice(tag).map_err(|_| CryptoError::DecryptionFailed)?;

    let iv = &payload[9..25];
    let body = &payload[25..];
    let plaintext = Aes128CbcDec::new_from_slices(&k.encryption_key, iv)
        .map_err(|_| CryptoError::DecryptionFailed)?
        .decrypt_padded_vec_mut::<Pkcs7>(body)
        .map_err(|_| CryptoError::DecryptionFailed)?;
    String::from_utf8(plaintext).map_err(|_| CryptoError::DecryptionFailed)
}

// Mirrors secrets_crypto.py's secret_key_configured/generate_key, which
// are likewise unused outside tests and the `python -m app.secrets_crypto`
// key-generation helper in the Python codebase.
#[allow(dead_code)]
pub fn secret_key_configured() -> bool {
    key().is_ok()
}

#[allow(dead_code)]
pub fn generate_key() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE.encode(bytes)
}

// FLEETVIEW_SECRET_KEY is process-global and Rust runs tests on multiple
// threads by default, so mutating it needs a lock to avoid cross-test races.
// Shared by every #[cfg(test)] mod in this file that touches the env var --
// mod tests and mod interop each used to declare their own ENV_LOCK, which
// only serialized races *within* that module, not against each other, so a
// test in one module could still clear/overwrite the var out from under a
// test running concurrently in the other (observed in CI as a spurious
// SecretKeyNotConfigured in round_trip).
#[cfg(test)]
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    fn with_key<T>(key: &str, f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("FLEETVIEW_SECRET_KEY", key);
        let result = f();
        std::env::remove_var("FLEETVIEW_SECRET_KEY");
        result
    }

    #[test]
    fn round_trip() {
        with_key(&generate_key(), || {
            let token = encrypt_text("hello world").unwrap();
            assert_eq!(decrypt_text(&token).unwrap(), "hello world");
        });
    }

    #[test]
    fn rejects_tampered_token() {
        with_key(&generate_key(), || {
            let mut token = URL_SAFE.decode(encrypt_text("secret").unwrap()).unwrap();
            let last = token.len() - 1;
            token[last] ^= 0xFF;
            let tampered = URL_SAFE.encode(token);
            assert!(decrypt_text(&tampered).is_err());
        });
    }

    #[test]
    fn missing_key_errors() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("FLEETVIEW_SECRET_KEY");
        assert!(!secret_key_configured());
        assert!(matches!(encrypt_text("x"), Err(CryptoError::SecretKeyNotConfigured)));
    }
}

#[cfg(test)]
mod interop {
    //! Regression test for a real cross-language round trip verified during
    //! development: this exact key/token/plaintext triple was generated by
    //! Python's `cryptography.fernet.Fernet`, and a Rust-encrypted token for
    //! the same key/plaintext was independently confirmed decryptable by
    //! Python's `Fernet.decrypt`.
    use super::*;

    const KEY: &str = "yu30SfPizM0xv2LEurXELmKigTYar_BTRm1vgp8ricc=";
    const PY_TOKEN: &str = "gAAAAABqvHoBCDapNKpjaFYw0_OolAGrXrS-iCMi1qzxskWFUKHie03VADEAqBcCfSXrwaKBNGG-dDJiscPYeB4PLVc4kXRbhOMUYc4KBzKOATpDfPw6pvY=";
    const PLAINTEXT: &str = "proxmox-token-secret-value-123";

    #[test]
    fn rust_decrypts_python_token() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("FLEETVIEW_SECRET_KEY", KEY);
        let decrypted = decrypt_text(PY_TOKEN).unwrap();
        std::env::remove_var("FLEETVIEW_SECRET_KEY");
        assert_eq!(decrypted, PLAINTEXT);
    }
}
