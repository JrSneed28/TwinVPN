//! The listener the rung-1 tests attach to, and the production-shaped `Env`
//! that drives them.
//!
//! A **test double for `services/control-plane/src/quic.rs`**, built with the
//! same rustls shapes the real server uses (`with_client_cert_verifier` +
//! `AlwaysResolvesServerRawPublicKeys`, TLS 1.3 only, `max_early_data_size = 0`,
//! the same ALPN and the same exporter label), speaking `wire.rs`'s framing.
//!
//! What it deliberately does **not** do is authorise: which device keys may
//! connect is the control plane's question, and answering it here would test
//! this file rather than the client.
//!
//! Key material comes from `twinvpn_crypto::testkit::FixtureIdentity`, whose own
//! documentation says it is exactly what "a lab client that wants to attach to a
//! control plane needs" — CD-I2 covers dev-dependencies, so the P-256 encoding
//! comes from the one crate permitted to do it.
//!
//! `#![allow(dead_code)]`: this module is compiled once per integration-test
//! binary, and a binary that uses only part of it would otherwise warn about the
//! rest.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use quinn::rustls;
use twinvpn_cp_client::quic::{
    ControlEndpoint, DeviceIdentity, QuicControlTransport, ServerPins, ALPN, C1_HEADER_BYTES,
    EXPORTER_CONTEXT, EXPORTER_LABEL,
};
use twinvpn_cp_client::testing::{CountingEntropy, CountingRngSource};
use twinvpn_cp_client::{AttachFamilies, Rung, TransportConfig};
use twinvpn_env::binding::system::{SystemMonotonicClock, SystemWallClock, WallClockTrust};
use twinvpn_env::binding::tokio_rt::TokioRuntime;
use twinvpn_env::{ElapsedInstant, Env, EnvParts, MonotonicClock};

/// The name in SNI. The verifiers on both sides ignore it — ADR-0001 §6
/// rejected the naming system a certificate implies — but rustls still requires
/// a well-formed `ServerName`, so there is one.
pub const SERVER_NAME: &str = "cp.test.invalid";

/// A command code the listener answers with **its own** exporter value rather
/// than an echo. Outside `wire.rs`'s assigned range on purpose: it is a probe
/// this harness invents, not a C1 command.
pub const PROBE_CHANNEL_BINDING: u16 = 0xFF01;

/// A command code after which the listener opens the C2 unidirectional stream,
/// standing in for `wire.rs`'s `SubscribeEvents` (60).
pub const PROBE_SUBSCRIBE: u16 = 0xFF02;

// ---------------------------------------------------------------------------
// the environment (CD-2: every capability is bound at construction)
// ---------------------------------------------------------------------------

pub fn production_env() -> (Env, Arc<TokioRuntime>) {
    let runtime = Arc::new(TokioRuntime::work_stealing().expect("a work-stealing runtime"));
    let monotonic: Arc<dyn MonotonicClock> = Arc::new(SystemMonotonicClock::new());
    let timer = runtime.timer(Arc::clone(&monotonic));
    let env = Env::new(EnvParts {
        monotonic: Arc::clone(&monotonic),
        // Nothing in the attach path reads the suspend-inclusive clock — every
        // timer here is `Timer`, which takes `MonotonicInstant` — so a constant
        // reader is honest rather than a stub that would drift. `twinvpn-env`
        // ships no production `ElapsedClock` on purpose (LC-8), and inventing
        // one here from `Instant` is the exact defect CD-3 denies.
        elapsed: twinvpn_env::binding::system::ElapsedClockFn::shared(|| {
            ElapsedInstant::from_micros(0)
        }),
        wall: Arc::new(SystemWallClock::new(WallClockTrust::Synchronised)),
        timer,
        runtime: Arc::clone(&runtime) as Arc<dyn twinvpn_env::Runtime>,
        entropy: Arc::new(CountingEntropy::new()),
        rng: Arc::new(CountingRngSource::new()),
    });
    (env, runtime)
}

pub fn drive<F>(env: &Env, fut: F) -> F::Output
where
    F: core::future::Future + Send,
    F::Output: Send,
{
    let cell = Arc::new(Mutex::new(None));
    let sink = Arc::clone(&cell);
    env.runtime().block_on(Box::pin(async move {
        let out = fut.await;
        *sink.lock().expect("not poisoned") = Some(out);
    }));
    let mut guard = cell.lock().expect("not poisoned");
    guard.take().expect("the future completed")
}

// ---------------------------------------------------------------------------
// the listener: a test double for services/control-plane/src/quic.rs
// ---------------------------------------------------------------------------

/// Requires an RFC 7250 raw public key from every client and proves possession.
///
/// The same shape as the control plane's `RawPublicKeyClientVerifier`:
/// `client_auth_mandatory` is true and there is no way to unset it, so a
/// connection that presents no key never reaches the framing layer.
#[derive(Debug)]
struct RequireRawPublicKey {
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
    seen: Arc<Mutex<Option<Vec<u8>>>>,
}

impl rustls::server::danger::ClientCertVerifier for RequireRawPublicKey {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
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
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        // An RFC 7250 peer sends exactly one entry and no chain.
        assert!(intermediates.is_empty(), "a chain at a raw-key listener");
        *self.seen.lock().expect("not poisoned") = Some(end_entity.as_ref().to_vec());
        Ok(rustls::server::danger::ClientCertVerified::assertion())
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
        // THIS is the authentication: the peer signs the handshake transcript
        // with the private half of the key it presented.
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
}

pub struct Listener {
    pub endpoint: quinn::Endpoint,
    pub server_spki: Vec<u8>,
    pub client_key_seen: Arc<Mutex<Option<Vec<u8>>>>,
}

pub fn listen(bind: SocketAddr, seed: &[u8]) -> Listener {
    let fixture = twinvpn_crypto::testkit::FixtureIdentity::from_seed(seed);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let supported = provider.signature_verification_algorithms;
    let key = rustls::pki_types::PrivateKeyDer::try_from(fixture.pkcs8_der()).expect("PKCS#8");
    let signing = provider
        .key_provider
        .load_private_key(key)
        .expect("the provider loads a P-256 key");
    let server_spki = fixture.spki_der();
    let certified = Arc::new(rustls::sign::CertifiedKey::new(
        vec![rustls::pki_types::CertificateDer::from(server_spki.clone())],
        signing,
    ));
    let client_key_seen = Arc::new(Mutex::new(None));
    let verifier = Arc::new(RequireRawPublicKey {
        supported,
        seen: Arc::clone(&client_key_seen),
    });

    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 only")
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(
            rustls::server::AlwaysResolvesServerRawPublicKeys::new(certified),
        ));
    tls.alpn_protocols = vec![ALPN.to_vec()];
    // The server's half of the 0-RTT prohibition, mirrored here so the client
    // is tested against a listener that would refuse early data even if it were
    // offered.
    tls.max_early_data_size = 0;
    tls.send_half_rtt_data = false;

    let quic =
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("a QUIC server config");
    let config = quinn::ServerConfig::with_crypto(Arc::new(quic));
    let endpoint = quinn::Endpoint::server(config, bind).expect("binds the loopback listener");
    Listener {
        endpoint,
        server_spki,
        client_key_seen,
    }
}

/// Serves one connection: `wire.rs`'s C1 framing, plus the C2 uni stream.
pub async fn serve_one(endpoint: quinn::Endpoint) {
    let Some(incoming) = endpoint.accept().await else {
        return;
    };
    // Never `into_0rtt`: awaiting is the 1-RTT path, on this side too.
    let Ok(connection) = incoming.await else {
        return;
    };
    let mut binding = [0u8; 32];
    connection
        .export_keying_material(&mut binding, EXPORTER_LABEL, EXPORTER_CONTEXT)
        .expect("a completed TLS 1.3 handshake has an exporter");

    while let Ok((mut send, mut recv)) = connection.accept_bi().await {
        let mut header = [0u8; C1_HEADER_BYTES];
        if recv.read_exact(&mut header).await.is_err() {
            break;
        }
        let code = u16::from_be_bytes([header[0], header[1]]);
        let len = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
        let mut body = vec![0u8; len];
        if recv.read_exact(&mut body).await.is_err() {
            break;
        }
        let payload = if code == PROBE_CHANNEL_BINDING {
            binding.to_vec()
        } else {
            body
        };
        let _ = send.write_all(&frame(code, &payload)).await;
        let _ = send.finish();

        if code == PROBE_SUBSCRIBE {
            // §11.6: C2 gets its own stream, opened by the server, so an event
            // backlog cannot consume the RPC window. One record, then FIN.
            if let Ok(mut uni) = connection.open_uni().await {
                let event = b"a C2 record".to_vec();
                let mut record = Vec::new();
                record.extend_from_slice(&u32::try_from(event.len()).expect("fits").to_be_bytes());
                record.extend_from_slice(&event);
                let _ = uni.write_all(&record).await;
                let _ = uni.finish();
            }
        }
    }
    connection.closed().await;
}

pub fn frame(code: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(C1_HEADER_BYTES + body.len());
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(&u32::try_from(body.len()).expect("fits").to_be_bytes());
    out.extend_from_slice(body);
    out
}

// ---------------------------------------------------------------------------
// the rig
// ---------------------------------------------------------------------------

pub fn families_for(addr: SocketAddr) -> AttachFamilies {
    AttachFamilies {
        v4: addr.is_ipv4(),
        v6: addr.is_ipv6(),
        nat64: false,
    }
}

pub fn transport_for(
    env: &Env,
    addr: SocketAddr,
    pins: Vec<Vec<u8>>,
) -> (QuicControlTransport, TransportConfig) {
    let client = twinvpn_crypto::testkit::FixtureIdentity::from_seed(b"twinvpn/cp-client/device");
    let identity = DeviceIdentity::software_key(client.pkcs8_der()).expect("a loadable key");
    let transport = QuicControlTransport::new(
        env.clone(),
        &identity,
        ServerPins::new(pins).expect("a non-empty pin set"),
        vec![ControlEndpoint::new(SERVER_NAME.to_owned(), vec![addr]).expect("resolved")],
        None,
    )
    .expect("a usable rung-1 configuration");
    let config = TransportConfig::new(
        vec![SERVER_NAME.to_owned()],
        families_for(addr),
        Rung::Quic,
        false,
    );
    (transport, config)
}
