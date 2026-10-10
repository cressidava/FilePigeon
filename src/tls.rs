//! QUIC/TLS configuration. Both sides always present a certificate, and each
//! side only accepts the specific Ed25519 keys it expects (key pinning).
//! There are no certificate authorities involved at all.

use crate::config::{load_json, Peer};
use crate::identity::Identity;
use anyhow::{anyhow, bail, Context, Result};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{IdleTimeout, TransportConfig, VarInt};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, SignatureScheme};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

pub const ALPN_PEER: &[u8] = b"filepigeon/1";
pub const ALPN_RDV: &[u8] = b"pigeon-rdv/1";
/// Local-network pairing. TLS here only carries bytes; SPAKE2 does the authenticating.
pub const ALPN_PAIR: &[u8] = b"filepigeon-pair/1";

/// Which remote keys a handshake may succeed with.
#[derive(Debug, Clone)]
pub enum KeyPolicy {
    /// Any valid Ed25519 key (rendezvous server: devices identify themselves by key).
    Any,
    /// Exactly these keys.
    Only(HashSet<[u8; 32]>),
    /// Whoever is in the peers file *right now* (re-read on every handshake,
    /// so unpairing takes effect immediately).
    PairedPeers(PathBuf),
}

impl KeyPolicy {
    pub fn only(key: [u8; 32]) -> Self {
        Self::Only(HashSet::from([key]))
    }

    fn allows(&self, key: &[u8; 32]) -> bool {
        match self {
            KeyPolicy::Any => true,
            KeyPolicy::Only(keys) => keys.contains(key),
            // Peers you've hidden from can't complete a handshake either.
            KeyPolicy::PairedPeers(path) => load_json::<Vec<Peer>>(path)
                .map(|peers| peers.iter().any(|p| !p.hidden && p.key().as_ref() == Some(key)))
                .unwrap_or(false),
        }
    }
}

#[derive(Debug)]
struct PinVerifier {
    policy: KeyPolicy,
    provider: Arc<CryptoProvider>,
}

impl PinVerifier {
    fn check(&self, cert: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        let key = cert_public_key(cert).map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        if self.policy.allows(&key) {
            Ok(())
        } else {
            Err(rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure))
        }
    }

    fn verify13(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.check(end_entity).map(|_| ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not allowed".into()))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verify13(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

impl ClientCertVerifier for PinVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.check(end_entity).map(|_| ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not allowed".into()))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verify13(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Tuned for bulk transfer: large flow-control windows so throughput is not
/// capped on high-latency internet links.
pub fn transport() -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();
    t.max_idle_timeout(Some(IdleTimeout::try_from(Duration::from_secs(60)).unwrap()));
    t.keep_alive_interval(Some(Duration::from_secs(10)));
    t.stream_receive_window(VarInt::from_u32(16 << 20));
    t.receive_window(VarInt::from_u32(64 << 20));
    t.send_window(64 << 20);
    t.max_concurrent_uni_streams(VarInt::from_u32(0));
    t.max_concurrent_bidi_streams(VarInt::from_u32(8));
    Arc::new(t)
}

/// For the rendezvous server: it only ever carries small control messages,
/// so tiny flow-control windows stop anyone parking megabytes in its memory.
pub fn small_transport() -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();
    t.max_idle_timeout(Some(IdleTimeout::try_from(Duration::from_secs(60)).unwrap()));
    t.keep_alive_interval(Some(Duration::from_secs(10)));
    t.stream_receive_window(VarInt::from_u32(64 << 10));
    t.receive_window(VarInt::from_u32(256 << 10));
    t.send_window(1 << 20);
    t.max_concurrent_uni_streams(VarInt::from_u32(0));
    t.max_concurrent_bidi_streams(VarInt::from_u32(8));
    Arc::new(t)
}

pub fn server_config(id: &Identity, policy: KeyPolicy, alpn: &[u8]) -> Result<quinn::ServerConfig> {
    server_config_with(id, policy, alpn, transport())
}

pub fn server_config_with(
    id: &Identity,
    policy: KeyPolicy,
    alpn: &[u8],
    transport: Arc<TransportConfig>,
) -> Result<quinn::ServerConfig> {
    let provider = provider();
    let verifier = Arc::new(PinVerifier { policy, provider: provider.clone() });
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![id.cert()], id.private_key())?;
    tls.alpn_protocols = vec![alpn.to_vec()];
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    cfg.transport_config(transport);
    Ok(cfg)
}

pub fn client_config(id: &Identity, policy: KeyPolicy, alpn: &[u8]) -> Result<quinn::ClientConfig> {
    let provider = provider();
    let verifier = Arc::new(PinVerifier { policy, provider: provider.clone() });
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![id.cert()], id.private_key())?;
    tls.alpn_protocols = vec![alpn.to_vec()];
    let mut cfg = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
    cfg.transport_config(transport());
    Ok(cfg)
}

/// Extract the raw Ed25519 public key from a certificate.
pub fn cert_public_key(der: &[u8]) -> Result<[u8; 32]> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).map_err(|e| anyhow!("bad certificate: {e}"))?;
    let spki = cert.public_key();
    if spki.algorithm.algorithm.to_id_string() != "1.3.101.112" {
        bail!("certificate is not Ed25519");
    }
    spki.subject_public_key
        .data
        .as_ref()
        .try_into()
        .context("bad Ed25519 key length")
}

/// The authenticated public key of whoever is on the other end of `conn`.
pub fn peer_public_key(conn: &quinn::Connection) -> Result<[u8; 32]> {
    let identity = conn.peer_identity().context("peer presented no certificate")?;
    let certs = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| anyhow!("unexpected peer identity type"))?;
    cert_public_key(certs.first().context("peer presented no certificate")?)
}
