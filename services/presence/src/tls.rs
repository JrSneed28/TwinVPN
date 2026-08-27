//! TLS 1.3 termination with **mutual RFC 7250 raw-public-key** authentication.
//!
//! **Authority:** ADR-0001 §11 item 3 and §7.2's L-CONTROL block, verbatim:
//!
//! ```text
//! Transport     : QUIC + TLS 1.3, mutual authentication
//! Client auth   : RFC 7250 raw public key = DeviceIdentityKey (P-256 ECDSA)
//! Server auth   : pinned control-plane public key set, shipped in the build
//! 0-RTT         : PROHIBITED (R8)
//! Resumption    : permitted, but resumed sessions MUST NOT carry early data
//! ```
//!
//! # Why raw public keys and not certificates
//!
//! A `device_id` **is** a hash of the device's own identity key
//! (`identifiers.md` §2), so device identity is self-certifying and there is no
//! authority to chain to. A PKI here would be a second, weaker naming system
//! layered over a self-certifying one — and ADR-0001 §6 already rejects
//! "certificate/PKI baggage" for exactly that reason. RFC 7250 carries the
//! `SubjectPublicKeyInfo` alone, which is the whole of what a device is.
//!
//! # What this module authenticates, and what it does not
//!
//! It proves, cryptographically, that the peer on this connection **holds the
//! private half of the public key it presented** — TLS 1.3's `CertificateVerify`
//! is a signature over the handshake transcript, and rustls will not complete a
//! handshake without it. That key is captured as the [`ChannelIdentity`] and is
//! the value `BIND` is bound to (see [`crate::binding`]).
//!
//! It does **not** decide *which* keys may connect. This service is a hint
//! aggregator with no trust store, and presence is `EVENTUAL` and never a gate
//! (S-11, architecture.md §2.13); consulting the control plane per connection
//! would make a hint service a dependency of the thing it hints about. Any
//! well-formed key may therefore connect — but it may only speak for itself,
//! which is the property that closes the impersonation hole.
//!
//! # 0-RTT
//!
//! Prohibited structurally rather than by configuration: `max_early_data_size`
//! is left at its default of 0 and [`assert_no_early_data`] is called on every
//! constructed config, so a future edit that enables it fails at startup and in
//! a test rather than shipping.

use std::io;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, SubjectPublicKeyInfoDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::AlwaysResolvesServerRawPublicKeys;
use rustls::{DigitallySignedStruct, DistinguishedName, ServerConfig, SignatureScheme};

/// A generous ceiling on a presented `SubjectPublicKeyInfo`.
const MAX_SPKI_BYTES: usize = 1024;

/// The authenticated identity of the peer on a connection: its RFC 7250
/// `SubjectPublicKeyInfo`, exactly as presented.
///
/// This is the **only** identity this service trusts. Everything a peer *claims*
/// — an `ATTACH`'s `device_id`, a `CALL`'s target — is a claim; this is not.
///
/// `Debug` prints a length and nothing else. A public key is not a secret, but a
/// stable per-device identifier in a log line is a correlation handle
/// (`README.md` §7), and there is no reason for this value ever to be rendered.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ChannelIdentity(Arc<[u8]>);

impl ChannelIdentity {
    /// Wraps a presented SPKI.
    #[must_use]
    pub fn new(spki: &[u8]) -> Self {
        Self(Arc::from(spki))
    }

    /// The SPKI octets.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for ChannelIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChannelIdentity({} B, <not rendered>)", self.0.len())
    }
}

/// TLS could not be brought up.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// The key file could not be read.
    #[error("the TLS private key at {path} could not be read")]
    KeyUnreadable {
        /// Which file.
        path: String,
    },
    /// The file contained no private key, or one this provider will not load.
    #[error("the TLS private key at {path} is not a usable private key")]
    KeyUnusable {
        /// Which file.
        path: String,
    },
    /// rustls refused the configuration.
    #[error("the TLS configuration was refused: {0}")]
    Config(#[from] rustls::Error),
    /// A future edit enabled early data.
    #[error("0-RTT early data is enabled; ADR-0001 R8 prohibits it")]
    EarlyDataEnabled,
}

/// Builds the server configuration: TLS 1.3 only, mutual raw public keys,
/// client authentication **mandatory**, no early data.
///
/// The server's own identity is its key: in RFC 7250 mode there is no
/// certificate, so `key_path` is the whole of the server's identity and
/// [`server_public_key`] returns the SPKI an operator pins — ADR-0001's "pinned
/// control-plane public key set, shipped in the build".
///
/// # Errors
///
/// [`TlsError`]. A key that cannot be read or parsed is a **startup failure**,
/// never a fallback to an unauthenticated listener.
pub fn server_config(key_path: &Path) -> Result<Arc<ServerConfig>, TlsError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let signing_key = load_signing_key(&provider, key_path)?;
    let spki = public_key_of(&signing_key, key_path)?;
    let certified = Arc::new(rustls::sign::CertifiedKey::new(
        vec![CertificateDer::from(spki)],
        signing_key,
    ));

    let verifier = Arc::new(RawPublicKeyClientVerifier {
        supported: provider.signature_verification_algorithms,
    });

    let config = ServerConfig::builder_with_provider(provider)
        // TLS 1.3 only. TLS 1.2 is not a rung this service falls back to: the
        // channel binding ADR-0002 N-2 needs is the RFC 9266 `tls-exporter`, and
        // a 1.2 downgrade is a downgrade of the authentication itself.
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(certified)));

    assert_no_early_data(&config)?;
    Ok(Arc::new(config))
}

/// The SPKI a client pins for this server, so an operator can publish it.
///
/// # Errors
///
/// [`TlsError`], for the same reasons as [`server_config`].
pub fn server_public_key(key_path: &Path) -> Result<Vec<u8>, TlsError> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let signing_key = load_signing_key(&provider, key_path)?;
    public_key_of(&signing_key, key_path)
}

/// Refuses a configuration that permits 0-RTT.
///
/// ADR-0001 R8, and ADR-0002 S-5: the prohibition "removes the
/// replayable-early-data vector entirely". Checked rather than assumed, because
/// "we left the default alone" is not a property.
///
/// # Errors
///
/// [`TlsError::EarlyDataEnabled`].
pub fn assert_no_early_data(config: &ServerConfig) -> Result<(), TlsError> {
    if config.max_early_data_size == 0 {
        Ok(())
    } else {
        Err(TlsError::EarlyDataEnabled)
    }
}

fn load_signing_key(
    provider: &rustls::crypto::CryptoProvider,
    path: &Path,
) -> Result<Arc<dyn rustls::sign::SigningKey>, TlsError> {
    let key = load_private_key(path)?;
    provider
        .key_provider
        .load_private_key(key)
        .map_err(|_| TlsError::KeyUnusable {
            path: path.display().to_string(),
        })
}

fn public_key_of(
    key: &Arc<dyn rustls::sign::SigningKey>,
    path: &Path,
) -> Result<Vec<u8>, TlsError> {
    key.public_key()
        .map(|spki| spki.to_vec())
        .ok_or_else(|| TlsError::KeyUnusable {
            path: path.display().to_string(),
        })
}

/// Reads the first private key in a PEM file.
fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    let unreadable = || TlsError::KeyUnreadable {
        path: path.display().to_string(),
    };
    let bytes = std::fs::read(path).map_err(|_| unreadable())?;
    let mut reader = io::BufReader::new(bytes.as_slice());
    rustls_pemfile::private_key(&mut reader)
        .map_err(|_| unreadable())?
        .ok_or_else(|| TlsError::KeyUnusable {
            path: path.display().to_string(),
        })
}

/// Requires every client to present an RFC 7250 raw public key and to prove
/// possession of it, and accepts any key that does both.
///
/// **`client_auth_mandatory` is `true` and is not configurable.** A connection
/// that presents no key does not reach the framing layer at all, so the
/// unauthenticated `ATTACH` this service previously accepted is not merely
/// refused — it is unreachable.
#[derive(Debug)]
struct RawPublicKeyClientVerifier {
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for RawPublicKeyClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // There is no certificate authority to hint at: device identity is
        // self-certifying (`identifiers.md` §2).
        &[]
    }

    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        // An RFC 7250 peer sends exactly one entry — the SPKI — and no chain. A
        // chain here means the peer is speaking X.509 at a raw-public-key
        // listener, which is a protocol confusion and not something to tolerate.
        if !intermediates.is_empty() {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        }
        // Bounded before anything is done with it — the same discipline the C4
        // caps apply, on the other pre-authentication input this service has.
        if end_entity.is_empty() || end_entity.len() > MAX_SPKI_BYTES {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        }
        // Acceptance here is not authorisation. Possession is proved by
        // `verify_tls13_signature` below, which rustls calls before the
        // handshake completes; *which* keys may connect is deliberately not this
        // service's question (see the module docs).
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Unreachable: the config offers TLS 1.3 only. Refused rather than
        // implemented, so enabling 1.2 later cannot silently acquire a weaker
        // verification path.
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // THIS is the authentication. The peer signs the handshake transcript
        // with the private half of the key it presented; without a valid
        // signature the handshake does not complete and no framing is read.
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

/// The peer identity of an accepted connection, or `None` if the peer presented
/// nothing.
///
/// With `client_auth_mandatory`, `None` cannot occur on a completed handshake;
/// the signature keeps the impossible case visible rather than unwrapping it.
#[must_use]
pub fn peer_identity(conn: &rustls::ServerConnection) -> Option<ChannelIdentity> {
    conn.peer_certificates()
        .and_then(<[CertificateDer<'_>]>::first)
        .map(|spki| ChannelIdentity::new(spki.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_key_file_is_a_startup_failure_not_a_plaintext_listener() {
        let err = server_config(Path::new("/nonexistent/tls.key")).unwrap_err();
        assert!(matches!(err, TlsError::KeyUnreadable { .. }), "{err:?}");
    }

    #[test]
    fn a_file_that_is_not_a_key_is_a_startup_failure() {
        let err = server_config(Path::new("Cargo.toml")).unwrap_err();
        assert!(matches!(err, TlsError::KeyUnusable { .. }), "{err:?}");
    }

    #[test]
    fn a_channel_identity_never_renders_its_bytes() {
        let id = ChannelIdentity::new(&[0xab; 64]);
        let rendered = format!("{id:?}");
        assert!(!rendered.contains("ab"), "{rendered}");
        assert!(rendered.contains("64 B"));
    }
}
