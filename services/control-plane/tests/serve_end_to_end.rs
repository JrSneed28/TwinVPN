//! The service, end to end, over a real mutually authenticated QUIC connection.
//!
//! **Authority:** ADR-0001 §7.2 L-CONTROL and ADR-0007 **N-32** (the
//! `DeviceIdentityKey` *is* the RFC 7250 raw public key), ADR-0002 §11.2 rung 1,
//! N-1, N-2, N-8, `README.md` §7.1 (the C1 framing).
//!
//! # Why this file exists
//!
//! Every other test in this crate drives the store directly, which is the right
//! seam for a transaction and the wrong one for an *authenticated API*. The
//! properties below cannot be observed from there at all: that the caller is the
//! key the peer proved possession of, that a body's `device_id` is a claim the
//! server refuses, that a stale channel binding is caught, and that a C2 record
//! actually reaches a device. Each is asserted here against octets that crossed
//! a socket.
//!
//! The handshake, the exporter, the framing, the dispatch, the transaction and
//! the event stream are all **real**. Two things are doubles, and both are the
//! ones this host cannot bind: the signature verifier
//! ([`ScriptedVerifier`] rather than a live `Owner` anchor) and the store
//! (`MemStore` rather than PostgreSQL, per `README.md` §9).

mod common;

use std::sync::Arc;
use std::time::Duration;

use prost::Message;
use svc::tls::testkit::TestKey;
use twinvpn_control_plane as cp;
use twinvpn_control_plane::verify::testing::ScriptedVerifier;
use twinvpn_control_plane::verify::Delegation;
use twinvpn_control_plane::{C1Frame, CommandCode};
use twinvpn_crypto::statements::OskPower;
use twinvpn_schema::v1;
use twinvpn_service_common as svc;

const TWINNET: &str = "twn_e2e";

/// A running front-end, and everything a test needs to talk to it.
struct Fixture {
    addr: std::net::SocketAddr,
    server_spki: Vec<u8>,
    store: Arc<cp::store::mem::MemStore>,
    shutdown: Arc<svc::Shutdown>,
}

impl Fixture {
    /// Starts a control plane on an ephemeral loopback port.
    fn start() -> Self {
        let metrics = svc::Metrics::new();
        let server_key = TestKey::generate();
        let tls = svc::tls::ServerTlsBuilder::from_pkcs8_der(server_key.pkcs8().to_vec())
            // RFC 9001 §8.1: QUIC makes ALPN mandatory, and rung 1 shares
            // UDP:443 with whatever else an operator runs there.
            .with_alpn([cp::quic::ALPN])
            .build()
            .expect("server TLS");
        let server_spki = tls.public_key().to_vec();

        let server_config = cp::quic::from_rustls(tls.config()).expect("QUIC config");
        let endpoint =
            cp::quic::bind("127.0.0.1:0".parse().expect("addr"), server_config).expect("binds");
        let addr = endpoint.local_addr().expect("bound");

        let store = Arc::new(cp::store::mem::MemStore::new());
        let cfg = cp::ControlPlaneConfig::load(&TestEnv).expect("config");
        let plane = Arc::new(cp::serve::ControlPlane::new(
            Arc::clone(&store) as Arc<dyn cp::store::ControlStore>,
            // The ORK signs, and the enrolment proof it presents grants
            // `ENROLL`. Both halves are needed: `RegisterDevice`'s
            // authorisation is the delegation INSIDE the proof, not whoever
            // signed it.
            Arc::new(ScriptedVerifier::owner().granting(Delegation {
                osk_id: "osk-enroll".to_owned(),
                osk_pub_cose: vec![0xa5; 8],
                powers: vec![OskPower::Enroll],
                anchor_version: 1,
                not_after_ms: 0,
            })),
            Arc::new(cp::identity::ChannelDerivedIdentity),
            metrics.clone(),
            &cfg,
            vec!["cp.twinvpn.example".to_owned()],
        ));
        let shutdown = Arc::new(svc::Shutdown::new(
            svc::shutdown::ShutdownConfig::default(),
            metrics,
        ));
        tokio::spawn(plane.serve(endpoint, shutdown.handle()));

        Self {
            addr,
            server_spki,
            store,
            shutdown,
        }
    }
}

/// The environment a fixture's configuration is read from.
///
/// `TWINVPN_CP_DATABASE_URL` has no default and is refused when it still says
/// `CHANGE-ME`, so the fixture supplies one. Nothing connects to it: this
/// fixture runs on `MemStore`, and the value exists only to satisfy the same
/// validation the process performs at startup.
struct TestEnv;

impl svc::config::EnvSource for TestEnv {
    fn get(&self, key: &str) -> Option<String> {
        match key {
            "TWINVPN_CP_DATABASE_URL" => Some("postgres://cp@127.0.0.1/twinvpn_cp".to_owned()),
            _ => None,
        }
    }
}

/// A device: its TLS key, and the identity that key derives to.
struct Device {
    key: TestKey,
    device_id: [u8; 32],
    identity_cose_key: Vec<u8>,
}

impl Device {
    fn new() -> Self {
        let key = TestKey::generate();
        let channel = svc::ChannelIdentity::new(&key.spki);
        let identity_cose_key =
            svc::binding::spki_to_es256_cose_key(channel.as_bytes()).expect("a P-256 key");
        let device_id = svc::binding::derive_device_id_for(&channel)
            .expect("derives")
            .to_array();
        Self {
            key,
            device_id,
            identity_cose_key,
        }
    }
}

/// One connected client.
struct Client {
    connection: quinn::Connection,
    /// This connection's RFC 9266 `tls-exporter` value, computed by the CLIENT.
    ///
    /// The server computes its own from its own side of the handshake and
    /// compares. That the two agree is the whole content of ADR-0002 N-2, and it
    /// is a property of TLS rather than of either implementation — which is why
    /// a test that faked it would prove nothing.
    binding: [u8; 32],
    _endpoint: quinn::Endpoint,
}

impl Client {
    /// Connects `device` to `fixture`.
    async fn connect(fixture: &Fixture, device: &Device) -> Self {
        Self::connect_with(fixture, device.key.client_config(&fixture.server_spki)).await
    }

    async fn connect_with(fixture: &Fixture, tls: Arc<quinn::rustls::ClientConfig>) -> Self {
        let mut tls = Arc::try_unwrap(tls).expect("sole owner");
        tls.alpn_protocols = vec![cp::quic::ALPN.to_vec()];
        let quic = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls))
            .expect("TLS 1.3 client");
        let mut endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().expect("addr")).expect("client endpoint");
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));

        let connection = endpoint
            .connect(fixture.addr, "twinvpn-service.invalid")
            .expect("connects")
            .await
            .expect("handshake");
        let mut binding = [0u8; 32];
        connection
            .export_keying_material(&mut binding, cp::quic::EXPORTER_LABEL, b"")
            .expect("an RFC 9266 exporter");
        Self {
            connection,
            binding,
            _endpoint: endpoint,
        }
    }

    /// Sends one C1 request and returns the response octets.
    async fn request(&self, code: CommandCode, body: &[u8]) -> Vec<u8> {
        let (mut send, mut recv) = self.connection.open_bi().await.expect("opens a C1 stream");
        let header = C1Frame::header_bytes(code, body.len()).expect("within the cap");
        send.write_all(&header).await.expect("header");
        send.write_all(body).await.expect("body");
        send.finish().expect("finish");

        let mut header = [0u8; cp::wire::HEADER_BYTES];
        recv.read_exact(&mut header)
            .await
            .expect("a response header");
        let frame = C1Frame::parse_header(&header).expect("a well-formed response");
        assert_eq!(frame.code, code, "the response echoes the command code");
        let mut body = vec![0u8; frame.body_len];
        recv.read_exact(&mut body).await.expect("a response body");
        body
    }
}

/// `MessageMetadata` carrying this connection's binding and an idempotency key.
fn meta(binding: &[u8; 32], idempotency_key: &[u8]) -> Option<v1::MessageMetadata> {
    Some(v1::MessageMetadata {
        proto_version: 1,
        twinnet_id: TWINNET.to_owned(),
        idempotency_key: idempotency_key.to_vec(),
        auth: Some(v1::Auth {
            channel_binding: binding.to_vec(),
            ..Default::default()
        }),
        ..Default::default()
    })
}

/// A `RegisterDeviceRequest` a device makes about itself.
fn register_request(device: &Device, binding: &[u8; 32], claimed: [u8; 32]) -> Vec<u8> {
    v1::RegisterDeviceRequest {
        metadata: meta(binding, b"register-key-0001"),
        identity: Some(v1::DeviceIdentity {
            identity_id: claimed.to_vec(),
            device_id: claimed.to_vec(),
            generation: 0,
            identity_public_key: device.identity_cose_key.clone(),
            identity_key_algorithm: v1::IdentityKeyAlgorithm::Es256 as i32,
            tunnel_public_key: vec![7u8; 32],
            tunnel_key_algorithm: v1::TunnelKeyAlgorithm::X25519 as i32,
            tk_generation: 0,
            tunnel_key_binding: Some(signed_statement()),
            hardware_backed: false,
            created_at_ms: 0,
        }),
        key_attestation: Vec::new(),
        platform: None,
        declared_roles: vec![v1::DeviceRole::Client as i32],
        protocol_version: Some(v1::ProtocolVersion { v_max: 1, v_min: 1 }),
        capabilities: None,
        enrollment_proof: Some(signed_statement()),
    }
    .encode_to_vec()
}

/// A non-empty COSE_Sign1 stand-in. CBOR-shaped, deliberately not protobuf.
fn signed_statement() -> v1::SignedStatement {
    v1::SignedStatement {
        cose_sign1: vec![0xd2, 0x84, 0x43, b'c', b'o', b's', b'e'],
        statement_type: v1::SignedStatementType::Unspecified as i32,
    }
}

/// Registers `device` and returns the decoded response.
async fn register(client: &Client, device: &Device) -> v1::RegisterDeviceResponse {
    let body = register_request(device, &client.binding, device.device_id);
    let response = client.request(CommandCode::RegisterDevice, &body).await;
    v1::RegisterDeviceResponse::decode(response.as_slice()).expect("decodes")
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_device_registers_over_a_real_mutually_authenticated_connection() {
    let fixture = Fixture::start();
    let device = Device::new();
    let client = Client::connect(&fixture, &device).await;

    let response = register(&client, &device).await;
    assert!(response.error.is_none(), "{:?}", response.error);
    assert_eq!(
        response.device_id_echo,
        device.device_id.to_vec(),
        "an echo of the value the DEVICE derived, never an assignment"
    );
    assert_eq!(response.twinnet_id, TWINNET);
    assert!(
        response.assigned_twinnet_addr_v4.is_some() && response.assigned_twinnet_addr_v6.is_some(),
        "S-08: BOTH families are assigned, even on a v4-only or v6-only network"
    );

    // The record landed under the name derived from the key on the wire.
    let state = fixture.store.snapshot(TWINNET).expect("the TwinNet exists");
    let record = state.devices.get(&device.device_id).expect("enrolled");
    assert_eq!(record.identity_public_key, device.identity_cose_key);
    drop(fixture.shutdown);
}

#[tokio::test]
async fn a_device_cannot_register_under_another_devices_name_over_the_wire() {
    // The end-to-end form of the `AUTH.IDENTITY_MISMATCH` unit test: the caller
    // is the key that completed the handshake, and the `device_id` in the body
    // is a claim. Here the two genuinely differ — two real keypairs, one real
    // connection — which is the case a store-level test cannot construct.
    let fixture = Fixture::start();
    let device = Device::new();
    let victim = Device::new();
    let client = Client::connect(&fixture, &device).await;

    let body = register_request(&device, &client.binding, victim.device_id);
    let response = client.request(CommandCode::RegisterDevice, &body).await;
    let decoded = v1::RegisterDeviceResponse::decode(response.as_slice()).expect("decodes");
    let error = decoded.error.expect("refused");
    assert_eq!(error.reason_code, "AUTH.IDENTITY_MISMATCH");
    assert!(
        decoded.device_id_echo.is_empty(),
        "a refusal echoes nothing back"
    );
    assert!(
        fixture
            .store
            .snapshot(TWINNET)
            .is_none_or(|s| s.devices.is_empty()),
        "and nothing was enrolled"
    );
    drop(fixture.shutdown);
}

#[tokio::test]
async fn a_channel_binding_that_is_not_this_connections_is_refused() {
    // ADR-0002 N-2. The exporter is read from the LIVE connection on the server
    // side, so a value lifted from anywhere else — another connection, an older
    // session, a guess — cannot match. That is what makes the binding a binding
    // and what stops a Rule-A message being replayed onto a different channel.
    let fixture = Fixture::start();
    let device = Device::new();
    let client = Client::connect(&fixture, &device).await;

    let body = register_request(&device, &[0xABu8; 32], device.device_id);
    let response = client.request(CommandCode::RegisterDevice, &body).await;
    let error = v1::RegisterDeviceResponse::decode(response.as_slice())
        .expect("decodes")
        .error
        .expect("refused");
    assert_eq!(error.reason_code, "CONTROL.CHANNEL_BINDING_MISMATCH");
    drop(fixture.shutdown);
}

#[tokio::test]
async fn a_request_carrying_no_binding_at_all_is_refused_the_same_way() {
    // An absent binding and a wrong one are the same answer: neither is this
    // connection's exporter, and reporting them differently would leak the shape
    // of what was expected. Fail-closed — a message with no `Auth` is not a
    // message that skips the check.
    let fixture = Fixture::start();
    let device = Device::new();
    let client = Client::connect(&fixture, &device).await;

    let mut request = v1::RegisterDeviceRequest::decode(
        register_request(&device, &client.binding, device.device_id).as_slice(),
    )
    .expect("decodes");
    if let Some(md) = request.metadata.as_mut() {
        md.auth = None;
    }
    let response = client
        .request(CommandCode::RegisterDevice, &request.encode_to_vec())
        .await;
    let error = v1::RegisterDeviceResponse::decode(response.as_slice())
        .expect("decodes")
        .error
        .expect("refused");
    assert_eq!(error.reason_code, "CONTROL.CHANNEL_BINDING_MISMATCH");
    drop(fixture.shutdown);
}

#[tokio::test]
async fn an_idempotent_retry_returns_the_recorded_outcome_over_the_wire() {
    // ADR-0008 N-5, observed where a client observes it: the same
    // `idempotency_key` on a second BeginPairing returns the ORIGINAL
    // `pairing_id` and window, with `idempotent_replay` set, and appends nothing.
    let fixture = Fixture::start();
    let device = Device::new();
    let client = Client::connect(&fixture, &device).await;
    register(&client, &device).await;

    let body = v1::BeginPairingRequest {
        metadata: meta(&client.binding, b"begin-pairing-key"),
        pairing: Some(v1::PairingRequest {
            pairing_id: vec![3u8; 16],
            twinnet_id: TWINNET.to_owned(),
            peer_hint: Vec::new(),
            ceremony_type: v1::PairingCeremonyType::Unspecified as i32,
            owner_challenge: None,
            capabilities: None,
        }),
    }
    .encode_to_vec();

    let first = v1::BeginPairingResponse::decode(
        client
            .request(CommandCode::BeginPairing, &body)
            .await
            .as_slice(),
    )
    .expect("decodes");
    assert!(first.error.is_none(), "{:?}", first.error);
    let head_after_first = fixture
        .store
        .snapshot(TWINNET)
        .expect("state")
        .head_net_seq();

    let retry = v1::BeginPairingResponse::decode(
        client
            .request(CommandCode::BeginPairing, &body)
            .await
            .as_slice(),
    )
    .expect("decodes");
    assert!(retry.error.is_none(), "{:?}", retry.error);
    assert!(
        retry.result.expect("a result").idempotent_replay,
        "the retry says so, in the field ADR-0008 §10.2 makes observable"
    );
    assert_eq!(
        fixture
            .store
            .snapshot(TWINNET)
            .expect("state")
            .head_net_seq(),
        head_after_first,
        "and the log did not grow"
    );
    drop(fixture.shutdown);
}

#[tokio::test]
async fn the_c2_stream_delivers_the_durable_events_the_device_missed() {
    // The C1→C2 seam, which no store-level test reaches: SubscribeEvents answers
    // on the C1 stream with the priority pair, and the server then OPENS a
    // unidirectional stream and writes the log from the cursor.
    let fixture = Fixture::start();
    let device = Device::new();
    let client = Client::connect(&fixture, &device).await;
    register(&client, &device).await;

    let body = v1::SubscribeEventsRequest {
        metadata: meta(&client.binding, b"subscribe-key-001"),
        from_net_seq: 0,
    }
    .encode_to_vec();
    let response = v1::SubscribeEventsResponse::decode(
        client
            .request(CommandCode::SubscribeEvents, &body)
            .await
            .as_slice(),
    )
    .expect("decodes");
    assert!(response.error.is_none(), "{:?}", response.error);
    assert_eq!(
        response.current_net_seq, 1,
        "§11.6: the head arrives in the attach response, before any event body"
    );

    let mut recv = tokio::time::timeout(Duration::from_secs(5), client.connection.accept_uni())
        .await
        .expect("the server opens C2")
        .expect("a unidirectional stream");

    let mut header = [0u8; cp::wire::C2_HEADER_BYTES];
    tokio::time::timeout(Duration::from_secs(5), recv.read_exact(&mut header))
        .await
        .expect("a record arrives")
        .expect("its header");
    let len = cp::wire::parse_c2_length(&header).expect("within the cap");
    let mut record = vec![0u8; len];
    recv.read_exact(&mut record).await.expect("its body");

    let event = v1::ControlEvent::decode(record.as_slice()).expect("a ControlEvent");
    assert_eq!(
        event.publisher,
        cp::EventKind::DeviceRegistered.sole_publisher().to_wire(),
        "the sole publisher, which the device checks too"
    );
    assert_eq!(event.metadata.expect("metadata").net_seq, 1);
    match event.event {
        Some(v1::control_event::Event::DeviceRegistered(r)) => {
            assert_eq!(
                r.device.expect("the whole record, not a delta").device_id,
                device.device_id.to_vec()
            );
        }
        other => panic!("wrong event on C2: {other:?}"),
    }
    drop(fixture.shutdown);
}

#[tokio::test]
async fn an_unassigned_command_code_is_refused_and_never_guessed() {
    // §7.1: `CommandCode::from_wire` has no default arm. There is no command, so
    // there is no response message whose `error` could carry the refusal — the
    // connection closes with an application error code instead of the server
    // inventing a shape.
    let fixture = Fixture::start();
    let device = Device::new();
    let client = Client::connect(&fixture, &device).await;

    let (mut send, mut recv) = client.connection.open_bi().await.expect("opens");
    // Code 0xFFFF is assigned to nothing and never will be: a code is a wire
    // identity and re-pointing one would make an old client's RevokeDevice
    // arrive as something else.
    send.write_all(&[0xFF, 0xFF, 0, 0, 0, 0])
        .await
        .expect("header");
    send.finish().expect("finish");

    let closed = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(64))
        .await
        .expect("the server answers rather than hanging");
    assert!(closed.is_err(), "no response body is invented");
    drop(fixture.shutdown);
}

#[tokio::test]
async fn a_client_that_presents_no_key_cannot_complete_a_handshake() {
    // Client authentication is MANDATORY. Without it `Auth`'s Rule A is empty:
    // every `ctx.caller` check in the domain would be checking a value an
    // attacker chose, and C1 would be served to anyone who could reach the port.
    let fixture = Fixture::start();
    let anonymous = TestKey::anonymous_client_config(&fixture.server_spki);
    let mut tls = Arc::try_unwrap(anonymous).expect("sole owner");
    tls.alpn_protocols = vec![cp::quic::ALPN.to_vec()];
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls)).expect("client");
    let mut endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse().expect("addr")).expect("endpoint");
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));

    let outcome = endpoint
        .connect(fixture.addr, "twinvpn-service.invalid")
        .expect("attempts")
        .await;
    assert!(outcome.is_err(), "an unidentified peer is not served");
    drop(fixture.shutdown);
}

#[tokio::test]
async fn a_second_connection_for_one_identity_closes_the_older_one() {
    // ADR-0002 N-1: the OLDER one is closed, not the newer. A device that
    // reattached did so because its old connection was, from its side, already
    // gone — and one identity with two C1 streams would have two independent
    // cursors over one log.
    let fixture = Fixture::start();
    let device = Device::new();
    let first = Client::connect(&fixture, &device).await;
    register(&first, &device).await;

    let second = Client::connect(&fixture, &device).await;
    // The newer connection serves.
    let body = v1::DiscoverPeersRequest {
        metadata: meta(&second.binding, b"discover-key-0001"),
        since_net_seq: 0,
    }
    .encode_to_vec();
    let response = v1::DiscoverPeersResponse::decode(
        second
            .request(CommandCode::DiscoverPeers, &body)
            .await
            .as_slice(),
    )
    .expect("decodes");
    assert!(response.error.is_none(), "{:?}", response.error);

    // And the older one is closed rather than left running beside it.
    let closed = tokio::time::timeout(Duration::from_secs(5), first.connection.closed())
        .await
        .expect("the older connection is closed, not merely ignored");
    let _ = closed;
    drop(fixture.shutdown);
}
