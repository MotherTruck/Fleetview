//! Mirrors server/app/security.py exactly, including the on-disk password
//! hash format (`pbkdf2_sha256$<iterations>$<salt-hex>$<digest-hex>`) and
//! token_hash's plain SHA-256 hex digest, so existing rows created by the
//! Python server (password hashes, agent/session/enrollment token hashes)
//! stay valid without any data migration.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const PBKDF2_ITERATIONS: u32 = 600_000;

pub fn token_hash(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    hex::encode(digest)
}

fn token_urlsafe(n_bytes: usize) -> String {
    let mut bytes = vec![0u8; n_bytes];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn new_agent_token() -> String {
    token_urlsafe(48)
}

pub fn new_enrollment_token() -> String {
    // Fixed prefix: recognizable in logs/secret scanners, and guarantees
    // the token never starts with "-" so it's always a safe shell argument.
    format!("fv_{}", token_urlsafe(32))
}

pub fn secure_equal(left: &str, right: &str) -> bool {
    let (a, b) = (left.as_bytes(), right.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

pub fn password_hash(value: &str) -> String {
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let mut digest = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(value.as_bytes(), &salt, PBKDF2_ITERATIONS, &mut digest);
    format!(
        "pbkdf2_sha256${}${}${}",
        PBKDF2_ITERATIONS,
        hex::encode(salt),
        hex::encode(digest)
    )
}

pub fn verify_password(value: &str, encoded: &str) -> bool {
    let parts: Vec<&str> = encoded.splitn(4, '$').collect();
    let [algorithm, iterations, salt_hex, expected_hex] = parts.as_slice() else {
        return false;
    };
    if *algorithm != "pbkdf2_sha256" {
        return false;
    }
    let Ok(iterations) = iterations.parse::<u32>() else {
        return false;
    };
    let Ok(salt) = hex::decode(salt_hex) else {
        return false;
    };
    let Ok(expected) = hex::decode(expected_hex) else {
        return false;
    };
    let mut digest = vec![0u8; expected.len()];
    pbkdf2::pbkdf2_hmac::<Sha256>(value.as_bytes(), &salt, iterations, &mut digest);
    digest.ct_eq(&expected).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_round_trips() {
        let encoded = password_hash("correct horse battery staple");
        assert!(verify_password("correct horse battery staple", &encoded));
        assert!(!verify_password("wrong password", &encoded));
    }

    #[test]
    fn verify_password_accepts_a_hash_actually_generated_by_the_python_server() {
        // Captured by running server/app/security.py's own
        // password_hash("hunter2test") in this repo's Python server --
        // proves real interop (an existing user's stored hash stays valid
        // after cutover), not just that Rust's own round trip works.
        let python_generated = "pbkdf2_sha256$600000$875eaf2566172e7990387508d9c75a32$d4d62573a002301851bdf07e86090a4f5417c05a7b4661d14377a7ac4acf17d2";
        assert!(verify_password("hunter2test", python_generated));
        assert!(!verify_password("wrong", python_generated));
    }

    #[test]
    fn secure_equal_rejects_different_lengths_and_content() {
        assert!(secure_equal("abc", "abc"));
        assert!(!secure_equal("abc", "abcd"));
        assert!(!secure_equal("abc", "abd"));
    }

    #[test]
    fn token_hash_matches_pythons_hashlib_sha256() {
        // hashlib.sha256(b"hello").hexdigest(), computed independently in
        // this repo's Python to cross-check, not just recalled.
        assert_eq!(
            token_hash("hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn new_agent_token_and_enrollment_token_are_url_safe_and_distinct() {
        let a = new_agent_token();
        let b = new_agent_token();
        assert_ne!(a, b);
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));

        let enrollment = new_enrollment_token();
        assert!(enrollment.starts_with("fv_"));
        assert!(!enrollment.starts_with("fv_-"));
    }
}
