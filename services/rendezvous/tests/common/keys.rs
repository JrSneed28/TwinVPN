//! Ephemeral RFC 7250 key material for the tests, and the TLS client that uses
//! it.
//!
//! # Why keys are generated rather than committed
//!
//! A checked-in private key is a private key in the repository, and
//! `CLAUDE.md`'s rule is unqualified. `aws-lc-rs` is already in the dependency
//! graph — `rustls` links it as its default provider — so naming it as a
//! **dev-dependency** mints a fresh P-256 keypair per test run without adding a
//! crate to the lockfile, without a runtime cryptographic dependency in the
//! service, and without requiring `openssl` on the host.

#![allow(dead_code)]

use std::io::Write as _;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, ServerName, SubjectPublicKeyInfoDer, UnixTime,
};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};

/// A generated device identity: its PKCS#8 private key and its SPKI.
pub struct TestKey {
    pkcs8: Vec<u8>,
    /// The `SubjectPublicKeyInfo`, i.e. what the peer sees as the identity.
    pub spki: Vec<u8>,
}

impl TestKey {
    /// Mints a fresh P-256 keypair.
    pub fn generate() -> Self {
        use aws_lc_rs::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
        let doc = EcdsaKeyPair::generate_pkcs8(
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            &aws_lc_rs::rand::SystemRandom::new(),
        )
        .expect("a P-256 keypair");
        let pkcs8 = doc.as_ref().to_vec();
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let signing = provider
            .key_provider
            .load_private_key(PrivateKeyDer::try_from(pkcs8.clone()).expect("pkcs8"))
            .expect("rustls loads it");
        let spki = signing.public_key().expect("an SPKI").to_vec();
        Self { pkcs8, spki }
    }

    /// Writes the key to a PEM file the service can load, returning its path.
    ///
    /// The file lands in the crate's `target/` so it is never a repository
    /// artifact and is removed by `cargo clean`.
    pub fn write_pem(&self, name: &str) -> std::path::PathBuf {
        let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
        std::fs::create_dir_all(dir).expect("tmpdir");
        let path = dir.join(format!("{name}.key"));
        let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
        let b64 = base64(&self.pkcs8);
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).expect("ascii"));
            pem.push('\n');
        }
        pem.push_str("-----END PRIVATE KEY-----\n");
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(pem.as_bytes()).expect("write");
        path
    }

    /// A rustls client that presents this key as an RFC 7250 raw public key and
    /// pins `server_spki`.
    pub fn client_config(&self, server_spki: &[u8]) -> Arc<ClientConfig> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let signing = provider
            .key_provider
            .load_private_key(PrivateKeyDer::try_from(self.pkcs8.clone()).expect("pkcs8"))
            .expect("rustls loads it");
        let certified = Arc::new(rustls::sign::CertifiedKey::new(
            vec![CertificateDer::from(self.spki.clone())],
            signing,
        ));
        let verifier = Arc::new(PinnedRawKeyServerVerifier {
            pinned: server_spki.to_vec(),
            supported: provider.signature_verification_algorithms,
        });
        Arc::new(
            ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .expect("tls13")
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_client_cert_resolver(Arc::new(
                    rustls::client::AlwaysResolvesClientRawPublicKeys::new(certified),
                )),
        )
    }

    /// A rustls client that offers **TLS 1.2 only**.
    ///
    /// Used to prove the server does not fall back: a 1.2 downgrade is a
    /// downgrade of the authentication itself, because the RFC 9266
    /// `tls-exporter` binding ADR-0002 N-2 needs is a 1.3 property.
    pub fn tls12_only_client_config(server_spki: &[u8]) -> Arc<ClientConfig> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let verifier = Arc::new(PinnedRawKeyServerVerifier {
            pinned: server_spki.to_vec(),
            supported: provider.signature_verification_algorithms,
        });
        Arc::new(
            ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS12])
                .expect("tls12")
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth(),
        )
    }

    /// A rustls client that presents **no** client key.
    pub fn anonymous_client_config(server_spki: &[u8]) -> Arc<ClientConfig> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let verifier = Arc::new(PinnedRawKeyServerVerifier {
            pinned: server_spki.to_vec(),
            supported: provider.signature_verification_algorithms,
        });
        Arc::new(
            ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .expect("tls13")
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth(),
        )
    }
}

/// The name a test client asks for. The pinned verifier ignores it; RFC 7250
/// has no subject to match against.
pub fn server_name() -> ServerName<'static> {
    ServerName::try_from("rendezvous.invalid").expect("a valid DNS name")
}

/// Pins the server's raw public key, which is what ADR-0001's "pinned
/// control-plane public key set, shipped in the build" means in practice.
#[derive(Debug)]
struct PinnedRawKeyServerVerifier {
    pinned: Vec<u8>,
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedRawKeyServerVerifier {
    fn requires_raw_public_keys(&self) -> bool {
        true
    }

    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.pinned.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.supported,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

/// Minimal base64, so the PEM writer needs no dependency of its own.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}
