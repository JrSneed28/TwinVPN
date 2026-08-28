//! The server side of mutual authentication: RFC 7250 raw public keys, pinned.
//!
//! **Authority:** ADR-0001 §11 item 3 ("server auth against a pinned key set"),
//! §6 (TwinVPN has no naming system, so there is no certificate to chain and no
//! name to check), RFC 7250, RFC 8446 §4.4.3.
//!
//! # Two things a reader will want to check, both stated at the code
//!
//! **TLS 1.2 is refused rather than merely not offered.** The client config
//! names `TLS13` alone, so [`PinnedServerKey::verify_tls12_signature`] should
//! be unreachable; it returns an error anyway, because "unreachable" is a claim
//! about a configuration and this is the fail-closed direction if that
//! configuration ever changes. The channel binding ADR-0002 N-2 depends on is a
//! TLS 1.3 exporter, so a 1.2 fallback would not weaken the binding — it would
//! silently **remove** it.
//!
//! **The 1.3 verification uses the raw-key entry point.** The X.509 variant
//! parses its argument as a certificate to extract a key; under RFC 7250 the
//! argument *is* the `SubjectPublicKeyInfo`, so that parse fails and the
//! handshake dies with `BadEncoding` — reported by the client, about a server
//! that did nothing wrong, and logged by the server as a rejected handshake.
//! Both ends then blame the other and neither is at fault. The lab paid an hour
//! for that; the note travels with the code.

use std::sync::Arc;

use quinn::rustls;

use super::identity::ServerPins;

/// Verifies the server's presented raw public key against the pinned set.
///
/// Holds no policy of its own beyond the pin set: no name check (there are no
/// names), no expiry check (an SPKI has no validity window), no chain (there is
/// no issuer). What ADR-0001 asks for is byte equality against the enrolment
/// record, and that is the whole of `verify_server_cert`.
#[derive(Debug)]
pub(super) struct PinnedServerKey {
    pins: ServerPins,
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl PinnedServerKey {
    pub(super) fn new(
        pins: ServerPins,
        supported: rustls::crypto::WebPkiSupportedAlgorithms,
    ) -> Arc<Self> {
        Arc::new(Self { pins, supported })
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedServerKey {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if self.pins.accepts(end_entity.as_ref()) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            // The alert says "unknown issuer" because that is the closest thing
            // TLS has to "this key is not one I pin". The presented key is NOT
            // included: it would reach the peer in an alert, and a verifier
            // that echoes what it rejected tells a scanner what it would have
            // accepted.
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature_with_raw_key(
            message,
            &rustls::pki_types::SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.supported,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported.supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        // RFC 7250. This is what makes rustls send `server_certificate_type` =
        // RawPublicKey and treat the presented blob as an SPKI rather than an
        // X.509 chain. It must agree with the server's
        // `PeerIdentityVerifier`, which accepts "only RFC 7250 raw public keys
        // …, never a general PKI chain".
        true
    }
}
