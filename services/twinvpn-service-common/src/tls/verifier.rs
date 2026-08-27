//! The RFC 7250 client verifier, and the policy seam over it.
//!
//! Split out of `tls/mod.rs` to keep both files under the 500-line limit in
//! `CLAUDE.md`. `tls` re-exports the public items.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, SubjectPublicKeyInfoDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};

use super::MAX_SPKI_BYTES;

/// Which client keys are admitted at the TLS layer.
///
/// # This runs inside the handshake, so it MUST NOT do I/O
///
/// An implementation runs on the connection-accept path, before any application
/// framing. A policy that opened a socket, queried a database or called the
/// control plane would put that dependency in the reconnect path of every
/// device — which is **I5**, and is the reason no server-side artifact in this
/// system holds a per-connection trust lookup. Decide from memory, or admit.
///
/// Admission here is **not** authorisation. Possession of the private half is
/// proved by the TLS `CertificateVerify` regardless of what this returns, and
/// *what a peer may then say* is decided by [`crate::binding`], not here.
pub trait ClientKeyPolicy: std::fmt::Debug + Send + Sync + 'static {
    /// Whether a peer presenting `spki` may complete the handshake.
    ///
    /// `spki` has already been bounded to [`MAX_SPKI_BYTES`] and checked
    /// non-empty.
    fn admit(&self, spki: &[u8]) -> bool;
}

/// The shipped policy: any well-formed key may connect.
///
/// The correct policy for all six current artifacts, for the reasons in the
/// module docs. A named type rather than an absence, so that a service choosing
/// it has chosen it.
#[derive(Debug, Clone, Copy, Default)]
pub struct AcceptAnyWellFormedKey;

impl ClientKeyPolicy for AcceptAnyWellFormedKey {
    fn admit(&self, _spki: &[u8]) -> bool {
        true
    }
}

/// Requires every client to present an RFC 7250 raw public key and to prove
/// possession of it.
///
/// **`client_auth_mandatory` is `true` and is not configurable.** A connection
/// that presents no key does not reach the framing layer at all, so an
/// unauthenticated claim is not merely refused — it is unreachable.
#[derive(Debug)]
pub(super) struct RawPublicKeyClientVerifier {
    pub(super) supported: rustls::crypto::WebPkiSupportedAlgorithms,
    pub(super) policy: Arc<dyn ClientKeyPolicy>,
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
        // Bounded before anything is done with it.
        if end_entity.is_empty() || end_entity.len() > MAX_SPKI_BYTES {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        }
        if !self.policy.admit(end_entity.as_ref()) {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        // Acceptance here is not authorisation. Possession is proved by
        // `verify_tls13_signature` below, which rustls calls before the
        // handshake completes; *which* keys may connect is deliberately not a
        // question these services ask (see the module docs).
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
        // verification path. A 1.2 downgrade would downgrade the AUTHENTICATION,
        // because the RFC 9266 `tls-exporter` binding ADR-0002 N-2 needs is a
        // 1.3 property, and 1.2 has no raw-public-key client auth of the shape
        // ADR-0001 §7.2 specifies.
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
