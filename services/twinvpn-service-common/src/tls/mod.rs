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
//! # Provenance
//!
//! `rendezvous-connectivity` wrote this, correctly, and then wrote it **again**
//! byte-for-byte in `services/presence` — and `relay-plane` would have been the
//! third copy. That is the R-31 divergence this crate exists to prevent, so the
//! module moved here rather than spreading. The generalisation is on the three
//! axes the four services genuinely differ on (subject, trust store, transport);
//! every security property below is unchanged and every one is load-bearing.
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
//! the value a claimed subject is bound to (see [`crate::binding`]).
//!
//! It does **not** decide *which* keys may connect. **No server-side artifact in
//! this system holds a trust store, and none may fetch one per connection**: for
//! the rendezvous the `CALL` bodies are Rule-B signed end to end and opaque to
//! it; for presence, a hint service that consulted the control plane would become
//! a dependency of the thing it hints about; and for either, a per-connection
//! control-plane call would put the control plane back in the reconnect path
//! (**I5**). Any well-formed key may therefore connect — but it may only speak
//! for itself, which is the property that closes the impersonation hole.
//!
//! That is a named, replaceable [`ClientKeyPolicy`] rather than an implicit
//! behaviour, so a future service that genuinely does hold a **static** key set
//! has a seam — and so the I5 prohibition on doing I/O there is stated on the
//! trait rather than remembered.
//!
//! # 0-RTT
//!
//! Prohibited structurally rather than by configuration: `max_early_data_size`
//! is left at its default of 0 and [`assert_no_early_data`] runs on **every**
//! constructed config, so a future edit that enables it fails at startup and in
//! a test rather than shipping.
//!
//! # Transport
//!
//! The [`rustls::ServerConfig`] this module returns is the one a `quinn`
//! endpoint takes unchanged: TLS 1.3 only, which
//! `quinn::crypto::rustls::QuicServerConfig` requires, and ALPN settable through
//! [`ServerTlsBuilder::with_alpn`], which QUIC makes mandatory (RFC 9001 §8.1)
//! and TCP does not use. Nothing here is TCP-specific except
//! [`accept_with_deadline`], which is a `tokio_rustls` convenience and is not on
//! the path a QUIC endpoint takes.

#[cfg(feature = "test-support")]
pub mod testkit;
mod verifier;

pub use verifier::{AcceptAnyWellFormedKey, ClientKeyPolicy};

use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::AlwaysResolvesServerRawPublicKeys;
use rustls::ServerConfig;

use verifier::RawPublicKeyClientVerifier;

/// A generous ceiling on a presented `SubjectPublicKeyInfo`.
///
/// Bounded before anything is done with it — the same discipline the envelope
/// caps apply, on the other pre-authentication input a server has
/// (`ownership.md` §6 rules 9 and 10).
pub const MAX_SPKI_BYTES: usize = 1024;

/// The authenticated identity of the peer on a connection: its RFC 7250
/// `SubjectPublicKeyInfo`, exactly as presented.
///
/// This is the **only** identity a server-side artifact trusts. Everything a
/// peer *claims* — an `ATTACH`'s `device_id`, a `BIND`'s, a `CALL`'s target — is
/// a claim; this is not.
///
/// `Debug` prints a length and nothing else. A public key is not a secret, but a
/// stable per-device identifier in a log line is a correlation handle, and
/// `twinvpn.device_id` is on the collector's forbidden-key list precisely because
/// O-13 forbids infrastructure retaining one. There is no reason for this value
/// ever to be rendered.
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

    /// How many octets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the identity is empty. It never is on a completed handshake.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for ChannelIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChannelIdentity({} B, <not rendered>)", self.0.len())
    }
}

/// TLS could not be brought up, or a handshake did not complete.
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
    /// The peer did not complete a handshake inside its deadline.
    #[error("the TLS handshake did not complete within its deadline")]
    HandshakeTimeout,
    /// The peer's handshake failed: no key, an unprovable key, a TLS 1.2 hello,
    /// or plaintext. **Deliberately undifferentiated** — a peer learns only that
    /// the handshake failed, which is one fewer oracle than naming the reason.
    #[error("the TLS handshake failed")]
    HandshakeFailed,
}

/// Where the server's own key comes from.
///
/// In RFC 7250 mode there is no certificate, so the key is the whole of the
/// server's identity.
#[derive(Debug, Clone)]
pub enum KeySource {
    /// A PEM file on disk — the deployment shape
    /// (`/run/secrets/<service>/tls.key`).
    PemFile(std::path::PathBuf),
    /// PKCS#8 DER already in memory: a test, or a key vended by a secret store
    /// rather than discovered on a filesystem.
    Pkcs8Der(Vec<u8>),
}

/// Builds the server configuration.
#[derive(Debug)]
pub struct ServerTlsBuilder {
    key: KeySource,
    alpn: Vec<Vec<u8>>,
    policy: Arc<dyn ClientKeyPolicy>,
}

impl ServerTlsBuilder {
    /// Reads the server key from a PEM file.
    #[must_use]
    pub fn from_pem_file(path: impl Into<std::path::PathBuf>) -> Self {
        Self::new(KeySource::PemFile(path.into()))
    }

    /// Takes the server key as PKCS#8 DER.
    #[must_use]
    pub fn from_pkcs8_der(der: Vec<u8>) -> Self {
        Self::new(KeySource::Pkcs8Der(der))
    }

    /// A builder over `key`.
    #[must_use]
    pub fn new(key: KeySource) -> Self {
        Self {
            key,
            alpn: Vec::new(),
            policy: Arc::new(AcceptAnyWellFormedKey),
        }
    }

    /// Sets the ALPN protocol list.
    ///
    /// **Required for QUIC** (RFC 9001 §8.1) and unused on the TCP rungs. Empty
    /// by default, so a TCP listener does not advertise a protocol it does not
    /// speak.
    #[must_use]
    pub fn with_alpn<I, P>(mut self, protocols: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: AsRef<[u8]>,
    {
        self.alpn = protocols.into_iter().map(|p| p.as_ref().to_vec()).collect();
        self
    }

    /// Replaces the client-key policy. See [`ClientKeyPolicy`] for the I5
    /// constraint an implementation is under.
    #[must_use]
    pub fn with_client_key_policy(mut self, policy: Arc<dyn ClientKeyPolicy>) -> Self {
        self.policy = policy;
        self
    }

    /// Builds the configuration: TLS 1.3 only, mutual raw public keys, client
    /// authentication **mandatory**, no early data.
    ///
    /// # Errors
    ///
    /// [`TlsError`]. A key that cannot be read or parsed is a **startup
    /// failure**, never a fallback to an unauthenticated listener: there is no
    /// code path in this module that produces a plaintext or
    /// client-auth-optional configuration.
    pub fn build(self) -> Result<ServerTls, TlsError> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let label = match &self.key {
            KeySource::PemFile(p) => p.display().to_string(),
            KeySource::Pkcs8Der(_) => "<in-memory pkcs8>".to_owned(),
        };
        let key = match &self.key {
            KeySource::PemFile(p) => load_private_key(p)?,
            KeySource::Pkcs8Der(der) => {
                PrivateKeyDer::try_from(der.clone()).map_err(|_| TlsError::KeyUnusable {
                    path: label.clone(),
                })?
            }
        };
        let signing_key =
            provider
                .key_provider
                .load_private_key(key)
                .map_err(|_| TlsError::KeyUnusable {
                    path: label.clone(),
                })?;
        let spki = signing_key
            .public_key()
            .map(|s| s.to_vec())
            .ok_or(TlsError::KeyUnusable { path: label })?;

        let certified = Arc::new(rustls::sign::CertifiedKey::new(
            vec![CertificateDer::from(spki.clone())],
            signing_key,
        ));

        let verifier = Arc::new(RawPublicKeyClientVerifier {
            supported: provider.signature_verification_algorithms,
            policy: self.policy,
        });

        let mut config = ServerConfig::builder_with_provider(provider)
            // TLS 1.3 only. TLS 1.2 is not a rung any service falls back to: the
            // channel binding ADR-0002 N-2 needs is the RFC 9266 `tls-exporter`,
            // and a 1.2 downgrade is a downgrade of the AUTHENTICATION itself.
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(certified)));
        config.alpn_protocols = self.alpn;

        assert_no_early_data(&config)?;
        Ok(ServerTls {
            config: Arc::new(config),
            public_key: spki,
        })
    }
}

/// A built server configuration, and the public key a client pins for it.
#[derive(Debug, Clone)]
pub struct ServerTls {
    config: Arc<ServerConfig>,
    public_key: Vec<u8>,
}

impl ServerTls {
    /// The configuration, ready for `tokio_rustls::TlsAcceptor::from` or for
    /// `quinn::crypto::rustls::QuicServerConfig::try_from`.
    #[must_use]
    pub fn config(&self) -> Arc<ServerConfig> {
        self.config.clone()
    }

    /// The SPKI a client pins for this server, so an operator can publish it —
    /// ADR-0001's "pinned control-plane public key set, shipped in the build".
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

/// Builds a server configuration from a PEM key file.
///
/// The one-line form, for a TCP listener with no ALPN and the shipped key
/// policy.
///
/// # Errors
///
/// [`TlsError`].
pub fn server_config(key_path: &Path) -> Result<Arc<ServerConfig>, TlsError> {
    Ok(ServerTlsBuilder::from_pem_file(key_path).build()?.config())
}

/// The SPKI a client pins for the server keyed by `key_path`.
///
/// # Errors
///
/// [`TlsError`], for the same reasons as [`server_config`].
pub fn server_public_key(key_path: &Path) -> Result<Vec<u8>, TlsError> {
    Ok(ServerTlsBuilder::from_pem_file(key_path)
        .build()?
        .public_key)
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

/// Completes a TLS handshake under a deadline, yielding the stream and the
/// authenticated peer identity.
///
/// **The handshake takes the same stall deadline a partial frame does.** A peer
/// that opens a socket and then stalls mid-handshake is the slowloris case one
/// layer down, and rustls will wait as long as the peer makes it.
///
/// # Errors
///
/// [`TlsError::HandshakeTimeout`] or [`TlsError::HandshakeFailed`]. The two are
/// distinguished for the *server's* metrics and never for the peer: a caller
/// answers neither, because a peer that failed a handshake has no session on
/// which to be told anything.
pub async fn accept_with_deadline<IO>(
    acceptor: &tokio_rustls::TlsAcceptor,
    stream: IO,
    deadline: Duration,
) -> Result<(tokio_rustls::server::TlsStream<IO>, ChannelIdentity), TlsError>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let tls = match tokio::time::timeout(deadline, acceptor.accept(stream)).await {
        Err(_) => return Err(TlsError::HandshakeTimeout),
        Ok(Err(_)) => return Err(TlsError::HandshakeFailed),
        Ok(Ok(tls)) => tls,
    };
    // `client_auth_mandatory` means a completed handshake always presented a
    // key. If that ever stops being true, refuse rather than serve an
    // unidentified peer.
    let identity = peer_identity(tls.get_ref().1).ok_or(TlsError::HandshakeFailed)?;
    Ok((tls, identity))
}
