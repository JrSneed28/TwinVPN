//! The **L-CONTROL binding**: rung 1 of ADR-0002 §11.2, as a real QUIC client.
//!
//! **Authority:** ADR-0001 §11 item 3 (L-CONTROL is QUIC + TLS 1.3 with mutual
//! RFC 7250 raw-public-key authentication to `DeviceIdentityKey`, **0-RTT
//! prohibited**), ADR-0002 §11.2 (the ladder), N-1 (one connection per device
//! carrying both C1 and C2), N-2 (the RFC 9266 `tls-exporter` channel binding),
//! ADR-0018 CB-1 (the socket lives at the platform seam, so the *binding* is
//! supplied at construction).
//!
//! # What this closes
//!
//! `twinvpn-cp-client`'s [`ControlTransport`] is a trait and nothing in `core/`
//! implements it — deliberately: CB-1 puts the socket at the platform seam, and
//! that crate's own documentation lists binding it as an outstanding
//! integration item. The consequence was that **no device could speak to the
//! control plane at all**, so the local environment could exercise the relay
//! data path end to end and not one control-plane ceremony.
//!
//! This is that binding, in the never-shipped lab. It is NOT the product's
//! composition root and must not be mistaken for one:
//!
//! - The product's root belongs on the platform seam, per target, under CB-1.
//!   This one is a lab client that runs on Linux and nowhere else.
//! - It pins the server's raw public key by **learning it on first sight**
//!   ([`ServerKey::Trusted`] is the pinning mode; [`ServerKey::LearnOnFirstUse`]
//!   is not and says so). A device pins from its enrolment record.
//! - It holds a *fixture* identity, not an enrolled `DeviceIdentityKey`.
//!
//! What it does prove, and what nothing else could: that a client honouring
//! §11.2's rung-1 policy completes a mutually-authenticated handshake against
//! the **real** `twinvpn-control-plane` binary, derives the same channel
//! binding, and gets a real answer to a real C1 command.
//!
//! # The framing decision, which `core/` does not make
//!
//! [`ControlConnection::request`] takes `body: &[u8]` and no command code, so
//! *something* has to decide where the code goes — and no document in `core/`
//! says. The server does: `services/control-plane/src/wire.rs` puts
//! `u16 command_code | u32 body_len | body` on the stream.
//!
//! This binding therefore treats `request`'s argument as the **complete C1
//! frame**, header included, and [`Attached::command`] is the convenience that
//! builds one. The choice is recorded here rather than buried because a second
//! binding that split it differently would be silently incompatible with this
//! one, and both would look correct.

use std::net::SocketAddr;
use std::sync::Arc;

use quinn::rustls;
use twinvpn_cp_client::transport::{
    ControlConnection, ControlTransport, EventStream, Rung, TransportConfig, TransportError,
};
use twinvpn_cp_client::ReceivedOctets;

/// The ALPN identifier for the TwinVPN control channel.
///
/// RFC 9001 §8.1 makes ALPN mandatory for QUIC, and rung 1 shares UDP:443 with
/// whatever else an operator runs there. Must equal the server's `quic::ALPN`.
pub const ALPN: &[u8] = b"twinvpn-c1/1";

/// The RFC 9266 exporter label. 32 bytes, empty context.
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-Channel-Binding";

/// The channel binding's exact width.
pub const CHANNEL_BINDING_BYTES: usize = 32;

/// The C1 frame header: `u16 command_code | u32 body_len`.
pub const C1_HEADER_BYTES: usize = 6;

/// How the client treats the server's raw public key.
#[derive(Debug, Clone)]
pub enum ServerKey {
    /// The pinned key. **This is the only mode that is authentication.**
    Trusted(Vec<u8>),
    /// Accept whatever is presented and report it.
    ///
    /// Not pinning, and named so it cannot be mistaken for it. A device pins
    /// from its enrolment record (ADR-0001 §7.2); a lab client bootstrapping
    /// against a freshly generated development key has nothing to pin from
    /// yet, and pretending otherwise would make the local environment's
    /// authentication story a fiction. Every run that uses this prints the key
    /// it learned so the next run can pass it as `Trusted`.
    LearnOnFirstUse,
}

/// A QUIC L-CONTROL transport.
pub struct QuicControlTransport {
    endpoint: quinn::Endpoint,
    server: SocketAddr,
    server_name: String,
    client_config: quinn::ClientConfig,
    learned: Arc<std::sync::Mutex<Option<Vec<u8>>>>,
}

impl QuicControlTransport {
    /// Builds a transport that presents `identity_pkcs8` / `identity_spki` as
    /// its RFC 7250 raw public key.
    ///
    /// # Errors
    ///
    /// A socket that cannot be bound, or key material rustls will not load.
    pub fn new(
        local: SocketAddr,
        server: SocketAddr,
        server_name: &str,
        identity_pkcs8: Vec<u8>,
        identity_spki: Vec<u8>,
        server_key: ServerKey,
    ) -> anyhow::Result<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let signing = provider
            .key_provider
            .load_private_key(
                rustls::pki_types::PrivateKeyDer::try_from(identity_pkcs8).map_err(|e| {
                    anyhow::anyhow!("the device identity key is not valid PKCS#8: {e}")
                })?,
            )
            .map_err(|e| anyhow::anyhow!("rustls will not load the device identity key: {e}"))?;
        let certified = Arc::new(rustls::sign::CertifiedKey::new(
            vec![rustls::pki_types::CertificateDer::from(identity_spki)],
            signing,
        ));

        let learned = Arc::new(std::sync::Mutex::new(None));
        let verifier = Arc::new(RawKeyServerVerifier {
            expect: server_key,
            learned: Arc::clone(&learned),
            supported: provider.signature_verification_algorithms,
        });

        // TLS 1.3 ONLY. ADR-0001 L-CONTROL names 1.3; offering 1.2 as well would
        // make the version a negotiation an attacker participates in — and the
        // `tls-exporter` binding N-2 depends on is a 1.3 property, so a 1.2
        // fallback silently removes the channel binding rather than weakening
        // it.
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| anyhow::anyhow!("TLS 1.3 client config: {e}"))?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_cert_resolver(Arc::new(
                rustls::client::AlwaysResolvesClientRawPublicKeys::new(certified),
            ));
        tls.alpn_protocols = vec![ALPN.to_vec()];
        // 0-RTT. ADR-0001 R8 prohibits early data absolutely, and
        // `twinvpn_cp_client`'s `EarlyData` enum has no `Permitted` variant to
        // express the opposite. `enable_early_data` defaults to false; it is set
        // here EXPLICITLY, because "we left the default alone" is not a
        // property and a future rustls default is not ours to rely on.
        tls.enable_early_data = false;

        let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|e| anyhow::anyhow!("QUIC client config: {e}"))?;
        let client_config = quinn::ClientConfig::new(Arc::new(quic_tls));

        let endpoint =
            quinn::Endpoint::client(local).map_err(|e| anyhow::anyhow!("binding {local}: {e}"))?;

        Ok(Self {
            endpoint,
            server,
            server_name: server_name.to_owned(),
            client_config,
            learned,
        })
    }

    /// The server key this transport learned, once a handshake has completed.
    #[must_use]
    pub fn learned_server_key(&self) -> Option<Vec<u8>> {
        self.learned.lock().ok().and_then(|g| g.clone())
    }

    /// Attaches, returning the concrete connection.
    ///
    /// # Errors
    ///
    /// [`TransportError::RungFailed`] for a connect failure and
    /// [`TransportError::HandshakeRejected`] for a refused identity. The two
    /// are kept apart: the first is the network, the second is the control
    /// plane declining to serve this key, and an operator does different things
    /// about them.
    pub async fn attach_quic(&self) -> Result<Attached, TransportError> {
        let connecting = self
            .endpoint
            .connect_with(self.client_config.clone(), self.server, &self.server_name)
            .map_err(|_| TransportError::RungFailed(Rung::Quic))?;
        let connection = connecting
            .await
            .inspect_err(|e| {
                // The mapped error deliberately says only "rejected" — a client
                // must not turn a server's refusal into a diagnosis. The raw
                // reason still has to reach a developer, though, or a lab
                // handshake failure is undebuggable from either side, so it goes
                // to the log rather than into the returned value.
                tracing::warn!(error = %e, "rung 1 handshake did not complete");
            })
            .map_err(|e| match e {
                // A TLS alert is the server refusing this identity; anything
                // else is the path.
                quinn::ConnectionError::ConnectionClosed(_)
                | quinn::ConnectionError::TransportError(_) => TransportError::HandshakeRejected,
                _ => TransportError::RungFailed(Rung::Quic),
            })?;
        Ok(Attached { connection })
    }
}

impl ControlTransport for QuicControlTransport {
    fn attach<'a>(
        &'a self,
        config: &'a TransportConfig,
    ) -> futures_core::future::BoxFuture<'a, Result<Box<dyn ControlConnection>, TransportError>>
    {
        Box::pin(async move {
            // The config's own admissibility rules are honoured rather than
            // bypassed: rung 3 in mobile background is refused by ADR-0002
            // §11.10 and a binding that ignored it would let a test pass that
            // the product forbids.
            config
                .admissible()
                .map_err(|_| TransportError::RungFailed(config.rung))?;
            if config.rung != Rung::Quic {
                // This binding is rung 1 only, and says so instead of quietly
                // serving rung 2 traffic over QUIC — which would make a ladder
                // test measure nothing.
                return Err(TransportError::RungFailed(config.rung));
            }
            let attached = self.attach_quic().await?;
            Ok(Box::new(attached) as Box<dyn ControlConnection>)
        })
    }
}

/// One attached control connection.
pub struct Attached {
    connection: quinn::Connection,
}

impl Attached {
    /// One C1 command: builds the frame, sends it, reads the response.
    ///
    /// # Errors
    ///
    /// [`TransportError::Closed`] for a stream that went away mid-exchange.
    pub async fn command(&self, code: u16, body: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
        let mut frame = Vec::with_capacity(C1_HEADER_BYTES + body.len());
        frame.extend_from_slice(&code.to_be_bytes());
        frame.extend_from_slice(
            &u32::try_from(body.len())
                .map_err(|_| TransportError::Closed)?
                .to_be_bytes(),
        );
        frame.extend_from_slice(body);

        let (mut send, mut recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|_| TransportError::Closed)?;
        send.write_all(&frame)
            .await
            .map_err(|_| TransportError::Closed)?;
        // FIN, so the server's `read_exact` on the body cannot block on a
        // client that has said everything it intends to.
        let _ = send.finish();

        let mut header = [0_u8; C1_HEADER_BYTES];
        recv.read_exact(&mut header)
            .await
            .map_err(|_| TransportError::Closed)?;
        let response_code = u16::from_be_bytes([header[0], header[1]]);
        let len = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
        // Bounded before allocation. The declared length is the server's claim
        // and this is a lab client, but a client that allocated from a peer's
        // u32 would be the same defect `ownership.md` §6 rule 10 names on the
        // server side, and the lab is not exempt from it.
        anyhow_cap(len).map_err(|()| TransportError::Closed)?;
        let mut out = vec![0_u8; len];
        recv.read_exact(&mut out)
            .await
            .map_err(|_| TransportError::Closed)?;
        Ok((response_code, out))
    }

    /// The server's raw public key, as presented on this connection.
    #[must_use]
    pub fn server_key(&self) -> Option<Vec<u8>> {
        self.connection
            .peer_identity()?
            .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
            .ok()
            .and_then(|chain| chain.first().map(|c| c.as_ref().to_vec()))
    }
}

/// The C1 envelope cap, `contracts/registry/limits.json`
/// `envelope.c1_c2_c7_max_bytes`.
const C1_MAX_BYTES: usize = 65_536;

fn anyhow_cap(len: usize) -> Result<(), ()> {
    if len > C1_MAX_BYTES {
        return Err(());
    }
    Ok(())
}

impl ControlConnection for Attached {
    fn channel_binding(&self) -> twinvpn_types::ChannelBinding {
        let mut out = [0_u8; CHANNEL_BINDING_BYTES];
        // Read from the LIVE CONNECTION, never from a message on it. That is
        // what makes the binding a binding (ADR-0002 N-2): a value a peer sent
        // proves only that the peer can send values.
        //
        // An exporter that cannot be read leaves `out` as zeros, and that is a
        // value the control plane will reject rather than one it will accept:
        // `check_channel_binding` compares against the exporter IT read, which
        // is never all-zero for a completed TLS 1.3 handshake. Failing that
        // comparison is the correct outcome, and it is louder than a panic here
        // would be useful.
        let _ = self
            .connection
            .export_keying_material(&mut out, EXPORTER_LABEL, b"");
        twinvpn_types::ChannelBinding::from_array(out)
    }

    fn rung(&self) -> Rung {
        Rung::Quic
    }

    fn proto_version(&self) -> u32 {
        // ADR-0014 §11.1 V-3: fixed for the life of the connection. The launch
        // `ProtocolEpoch` is 1 (ownership.md §8 W-27, from `EPOCH_TABLE`), and
        // it is a constant here rather than something negotiated because
        // nothing on this wire negotiates it yet.
        1
    }

    fn request<'a>(
        &'a self,
        body: &'a [u8],
    ) -> futures_core::future::BoxFuture<'a, Result<ReceivedOctets, TransportError>> {
        Box::pin(async move {
            // `body` is the COMPLETE C1 frame here — see the module docs on why
            // that decision has to be made somewhere and is made here.
            if body.len() < C1_HEADER_BYTES {
                return Err(TransportError::Closed);
            }
            let code = u16::from_be_bytes([body[0], body[1]]);
            let (_, out) = self.command(code, &body[C1_HEADER_BYTES..]).await?;
            Ok(ReceivedOctets::from_wire_owned(out))
        })
    }

    fn subscribe(
        &self,
        _from_net_seq: u64,
    ) -> futures_core::future::BoxFuture<'_, Result<Box<dyn EventStream>, TransportError>> {
        Box::pin(async move {
            // NOT IMPLEMENTED, and returning an error rather than an empty
            // stream is the point. C2 is `SubscribeEvents` on its own stream
            // (ADR-0002 §11.6); a binding that returned a stream which simply
            // never yielded would make every C2 test pass by producing no
            // events, which is the failure mode a lab exists to avoid.
            Err(TransportError::RungFailed(Rung::Quic))
        })
    }

    fn close(&self) -> futures_core::future::BoxFuture<'_, ()> {
        Box::pin(async move {
            self.connection.close(0u32.into(), b"bye");
        })
    }
}

/// Verifies (or learns) the server's RFC 7250 raw public key.
#[derive(Debug)]
struct RawKeyServerVerifier {
    expect: ServerKey,
    learned: Arc<std::sync::Mutex<Option<Vec<u8>>>>,
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl rustls::client::danger::ServerCertVerifier for RawKeyServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let presented = end_entity.as_ref();
        if let Ok(mut g) = self.learned.lock() {
            *g = Some(presented.to_vec());
        }
        match &self.expect {
            ServerKey::Trusted(pinned) => {
                // Constant-time is not required: both values are public keys,
                // and the comparison leaks nothing an observer of the handshake
                // does not already have.
                if pinned.as_slice() == presented {
                    Ok(rustls::client::danger::ServerCertVerified::assertion())
                } else {
                    Err(rustls::Error::General(
                        "the server's raw public key does not match the pin".into(),
                    ))
                }
            }
            ServerKey::LearnOnFirstUse => {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // TLS 1.2 is not offered, so reaching here is a rustls bug or a
        // configuration change. Refusing is the fail-closed direction and keeps
        // the 1.3-only claim true rather than merely intended.
        Err(rustls::Error::General("TLS 1.2 is not offered".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // `verify_tls13_signature_with_raw_key`, NOT `verify_tls13_signature`.
        //
        // The X.509 variant parses `cert` as a certificate to extract the key.
        // Under RFC 7250 there is no certificate: `cert` IS the
        // SubjectPublicKeyInfo, so that parse fails and the handshake dies with
        // `invalid peer certificate: BadEncoding` — from the CLIENT, about a
        // server that did nothing wrong, and reported to the server as an
        // alert 42 it then logs as CONTROL.HANDSHAKE_REJECTED. Both ends blame
        // the other and neither is at fault. That cost an hour; the note stays.
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
        // X.509 chain — ADR-0001 §6 rejected the naming system a certificate
        // implies, so there is no chain to build and no name to check.
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_alpn_and_exporter_label_match_the_servers() {
        // Copied constants, asserted rather than trusted: they are duplicated
        // across an artifact boundary (`services/control-plane/src/quic.rs`),
        // and a mismatch is a handshake that fails with no diagnosis on either
        // side. `.github/workflows/lab-t1.yml` greps the server for both.
        assert_eq!(ALPN, b"twinvpn-c1/1");
        assert_eq!(EXPORTER_LABEL, b"EXPORTER-Channel-Binding");
        assert_eq!(CHANNEL_BINDING_BYTES, 32);
    }

    #[test]
    fn the_c1_header_is_six_octets_of_code_and_length() {
        assert_eq!(C1_HEADER_BYTES, 2 + 4);
    }

    #[test]
    fn a_declared_length_above_the_envelope_cap_is_refused_before_allocation() {
        assert!(anyhow_cap(C1_MAX_BYTES).is_ok());
        assert!(anyhow_cap(C1_MAX_BYTES + 1).is_err());
    }

    #[test]
    fn learn_on_first_use_is_named_so_it_cannot_be_mistaken_for_pinning() {
        // A behavioural assertion would need a TLS handshake; this is a
        // documentation assertion, and it is here because the failure it guards
        // against is somebody reading `ServerKey::LearnOnFirstUse` as trust.
        let s = format!("{:?}", ServerKey::LearnOnFirstUse);
        assert!(s.contains("LearnOnFirstUse"));
        assert!(!s.contains("Trusted"));
    }
}
