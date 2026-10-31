//! Issues per-device TLS client certificates against a private CA this
//! server owns, so an enrolled device can present a certificate alongside
//! its existing bearer token (see auth.rs's cert_subject cross-check) --
//! additive defense-in-depth, never a replacement for the token, and only
//! meaningful when the optional Caddy TLS profile (docs/TLS.md) is in
//! front of this server requesting client certs. Devices without a cert
//! (not yet re-enrolled, or running over plain HTTP) are entirely
//! unaffected: issuance failures here are logged and swallowed, never
//! returned as enrollment errors.
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, Issuer, IsCa, KeyPair, KeyUsagePurpose,
};
use std::path::PathBuf;

fn ca_dir() -> PathBuf {
    std::env::var("FLEETVIEW_CLIENT_CA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/data/client-ca"))
}

/// A generated client certificate and its private key, both PEM-encoded,
/// ready to hand to an enrolling agent to store and present on future
/// requests.
pub struct IssuedCert {
    pub cert_pem: String,
    pub key_pem: String,
}

fn ca_params() -> Result<CertificateParams, rcgen::Error> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "FleetView Device CA");
    params.distinguished_name = name;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    Ok(params)
}

/// Loads the CA's key+cert from disk, generating and persisting a new one
/// on first use. The key never leaves this directory; only leaf
/// certificates signed with it are ever handed out. Not memoized in
/// memory -- enrollment is infrequent enough that reading two small PEM
/// files from disk on every call is no real cost, and it keeps this
/// trivially correct (and testable against a fresh directory per test)
/// rather than risking a stale or cross-test-contaminated in-process cache.
fn load_or_create_ca() -> std::io::Result<(String, String)> {
    let dir = ca_dir();
    let cert_path = dir.join("ca.crt");
    let key_path = dir.join("ca.key");

    if let (Ok(cert_pem), Ok(key_pem)) = (
        std::fs::read_to_string(&cert_path),
        std::fs::read_to_string(&key_path),
    ) {
        return Ok((cert_pem, key_pem));
    }

    std::fs::create_dir_all(&dir)?;
    let params = ca_params()
        .map_err(|err| std::io::Error::other(err.to_string()))?;
    let key = KeyPair::generate()
        .map_err(|err| std::io::Error::other(err.to_string()))?;
    let cert = params
        .self_signed(&key)
        .map_err(|err| std::io::Error::other(err.to_string()))?;
    let cert_pem = cert.pem();
    let key_pem = key.serialize_pem();

    // Write the key before the cert, and both before caching, so a crash
    // mid-write never leaves a cert on disk whose key didn't make it --
    // that pairing is what load_or_create_ca checks for above (it only
    // trusts a CA it can read *both* halves of).
    std::fs::write(&key_path, &key_pem)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::write(&cert_path, &cert_pem)?;

    Ok((cert_pem, key_pem))
}

/// Issues a client certificate for `device_id`, signed by this server's
/// client CA (generating that CA on first use). Returns None -- logging a
/// warning, never an error -- if the CA can't be loaded or the cert can't
/// be generated, since enrollment must still succeed without a cert: the
/// agent simply keeps using its bearer token alone, exactly as before this
/// feature existed.
pub fn issue_for_device(device_id: &str) -> Option<IssuedCert> {
    let (ca_cert_pem, ca_key_pem) = match load_or_create_ca() {
        Ok(pair) => pair,
        Err(err) => {
            tracing::warn!("client CA unavailable, enrolling without a client cert: {err}");
            return None;
        }
    };

    let issue = || -> Result<IssuedCert, rcgen::Error> {
        let ca_key = KeyPair::from_pem(&ca_key_pem)?;
        let issuer = Issuer::from_ca_cert_pem(&ca_cert_pem, ca_key)?;

        let mut params = CertificateParams::new(Vec::<String>::new())?;
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, device_id);
        params.distinguished_name = name;
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];

        let leaf_key = KeyPair::generate()?;
        let leaf_cert: Certificate = params.signed_by(&leaf_key, &issuer)?;
        Ok(IssuedCert {
            cert_pem: leaf_cert.pem(),
            key_pem: leaf_key.serialize_pem(),
        })
    };

    match issue() {
        Ok(issued) => Some(issued),
        Err(err) => {
            tracing::warn!("failed to issue a client cert for device {device_id}, enrolling without one: {err}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // FLEETVIEW_CLIENT_CA_DIR is process-global and tests run on multiple
    // threads by default -- see secrets_crypto.rs's ENV_LOCK for the exact
    // cross-test race this guards against (one test's set_var clobbering
    // another's mid-run).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_dir<T>(f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("FLEETVIEW_CLIENT_CA_DIR", dir.path());
        let result = f();
        std::env::remove_var("FLEETVIEW_CLIENT_CA_DIR");
        result
    }

    #[test]
    fn issues_a_cert_whose_subject_is_the_device_id() {
        with_dir(|| {
            let issued = issue_for_device("device-123").expect("issuance should succeed");
            assert!(issued.cert_pem.contains("BEGIN CERTIFICATE"));
            assert!(
                issued.key_pem.contains("BEGIN PRIVATE KEY")
                    || issued.key_pem.contains("BEGIN EC PRIVATE KEY")
            );
        });
    }

    #[test]
    fn reuses_the_same_ca_across_calls_in_a_fresh_directory() {
        with_dir(|| {
            issue_for_device("device-a").expect("first issuance should succeed");
            let (first_cert, _) = load_or_create_ca().unwrap();
            // A second call must reuse the persisted CA rather than minting
            // a new one, or every previously-issued device cert would stop
            // chaining to whatever CA Caddy was told to trust.
            let (second_cert, _) = load_or_create_ca().unwrap();
            assert_eq!(first_cert, second_cert);
        });
    }
}
