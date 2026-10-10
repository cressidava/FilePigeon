use anyhow::{Context, Result};
use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::path::Path;

/// A device's long-term Ed25519 key plus a self-signed certificate wrapping it.
/// The certificate is only a container for TLS; trust comes from pinning the key.
pub struct Identity {
    key: KeyPair,
    cert: CertificateDer<'static>,
    public_key: [u8; 32],
}

impl Identity {
    pub fn load_or_create(path: &Path) -> Result<Self> {
        let key = if path.exists() {
            let pem = std::fs::read_to_string(path)?;
            KeyPair::from_pem(&pem).context("identity key file is corrupt")?
        } else {
            let key = KeyPair::generate_for(&PKCS_ED25519)?;
            write_secret(path, key.serialize_pem().as_bytes())?;
            key
        };
        Self::from_key(key)
    }

    /// A throwaway identity that lives only in memory. Used where TLS just
    /// carries bytes and something else (SPAKE2) authenticates, so the
    /// device's real, long-term key is never shown to an unverified party.
    pub fn ephemeral() -> Result<Self> {
        Self::from_key(KeyPair::generate_for(&PKCS_ED25519)?)
    }

    fn from_key(key: KeyPair) -> Result<Self> {
        let cert = CertificateParams::new(vec!["filepigeon".to_string()])?.self_signed(&key)?;
        let public_key = key
            .public_key_raw()
            .try_into()
            .context("identity is not an Ed25519 key")?;
        Ok(Self { cert: cert.der().clone(), key, public_key })
    }

    pub fn cert(&self) -> CertificateDer<'static> {
        self.cert.clone()
    }

    pub fn private_key(&self) -> PrivateKeyDer<'static> {
        PrivatePkcs8KeyDer::from(self.key.serialize_der()).into()
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    pub fn device_id(&self) -> String {
        device_id(&self.public_key)
    }

    /// The raw 32-byte Ed25519 seed (from the PKCS#8 container). Used only to
    /// derive pairwise secrets for DHT discovery; never leaves this process.
    pub fn ed25519_seed(&self) -> Result<[u8; 32]> {
        let der = self.key.serialize_der();
        // PKCS#8 wraps the seed as OCTET STRING { OCTET STRING (32 bytes) }.
        let marker = [0x04, 0x22, 0x04, 0x20];
        let at = der
            .windows(marker.len())
            .position(|w| w == marker)
            .context("unexpected private key encoding")?
            + marker.len();
        der.get(at..at + 32).context("truncated private key")?.try_into().context("bad seed length")
    }
}

/// Short, stable identifier derived from the public key.
pub fn device_id(public_key: &[u8; 32]) -> String {
    hex::encode(&blake3::hash(public_key).as_bytes()[..10])
}

fn write_secret(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    use std::io::Write;
    opts.open(path)
        .with_context(|| format!("cannot create {}", path.display()))?
        .write_all(data)?;
    Ok(())
}
