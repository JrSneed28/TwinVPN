//! A **real device** and a **real relay**, for the integration matrix.
//!
//! # Nothing here is a cryptographic stand-in
//!
//! `services/relay/README.md` §11 used to record two gaps: no leg could be
//! established, and the COSE_Sign1 token path had no valid-token test because
//! "producing a *valid* token needs an Ed25519 keypair this build cannot sign
//! with". Both are closed here, and closed the same way — by doing the real
//! thing rather than by widening a double:
//!
//! | Piece | What runs |
//! |---|---|
//! | the token | a real COSE_Sign1, signed by `twinvpn_crypto::testkit::FixtureIdentity` |
//! | the issuer key set | that fixture's real COSE_Key, loaded through `IssuerKeySet::parse` |
//! | `cnf` | the device's real `RLK_pub`, encoded by the **one** shared encoder |
//! | the leg | a real `Noise_IK` handshake against the relay's real static key |
//! | `K_leg` | derived independently at both ends; nothing is copied across |
//! | every frame MAC | real keyed BLAKE2s under the derived `K_leg` |
//! | the transport | a real `tokio::net::UdpSocket` on loopback |
//!
//! The one thing that is *not* real is the L-DATA payload, and it deliberately
//! is not: the relay must forward bytes it cannot interpret, so the tests send
//! byte patterns chosen to be hostile to a forwarder that peeks — including
//! octets that would decode as protobuf with an unknown field, which is W-4's
//! trap.
//!
//! # The device does not import a device implementation
//!
//! `twinvpn-relay-client` is the device leg, and it is in the **other**
//! workspace: ADR-0018 §11.2 makes the server side a separate artifact that does
//! not link the core, and `services/Cargo.toml` permits exactly three edges.
//! Importing it here would be a fourth.
//!
//! So this harness re-derives the wire format from the relay's own public
//! constants — `twinvpn_relay::control`'s encoders, `twinvpn_relay::frame`'s
//! header — which means these tests assert *self-consistency*, not
//! interoperability. Interoperability is a separate obligation and is called out
//! in the README rather than implied by a green test here.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use twinvpn_crypto::emit::{encode, int_item, Item};
use twinvpn_crypto::relay_leg::{Entropy, LegInitiator};
use twinvpn_crypto::testkit::{x25519_cose_key, FixtureIssuer};
use twinvpn_relay::admit::{LegSetup, TokenPresentation, FLAG_CARRIES_COOKIE};
use twinvpn_relay::config::RelayConfig;
use twinvpn_relay::control::{self, BindBody, Family};
use twinvpn_relay::drr::TwoTierDrr;
use twinvpn_relay::entropy::SystemEntropy;
use twinvpn_relay::frame::{FrameType, HEADER_LEN, VERSION};
use twinvpn_relay::issuer::IssuerKeySet;
use twinvpn_relay::leg::{CookieJar, LegRegistry};
use twinvpn_relay::loop_udp::{serve_udp, RelayRuntime};
use twinvpn_relay::provider::CryptoProvider;
use twinvpn_relay::RelayEngine;
use twinvpn_service_common::config::MapEnv;

/// The operator group every fixture shares. A token's `aud` is this, never a
/// `relay_id` — which is what makes one token work across a whole ranked set.
pub const OPERATOR_GROUP: &str = "test-operator";

/// The issuer key id the fixture publishes.
pub const ISSUER_KEY_ID: &str = "fixture-issuer";

/// The relay's static Noise private key in these tests.
pub const RELAY_STATIC_PRIVATE: [u8; 32] = [0x51; 32];

/// The trust epoch every fixture token is issued at.
pub const EPOCH: u64 = 7;

/// A wall-clock instant inside every fixture token's validity window.
pub const NOW_MS: u64 = 1_700_000_000_000;

// ===========================================================================
// The issuer
// ===========================================================================

/// The Owner-rooted relay-credential issuer, with a real signing key.
pub struct Issuer {
    identity: FixtureIssuer,
}

impl Issuer {
    /// A deterministic issuer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            identity: FixtureIssuer::from_seed(b"twinvpn-relay-test-issuer"),
        }
    }

    /// The key set a relay loads, as `issuer-keys.json` spells it.
    #[must_use]
    pub fn key_set_json(&self) -> String {
        format!(
            r#"{{"operator_group_id":"{OPERATOR_GROUP}","issuers":[
               {{"key_id":"{ISSUER_KEY_ID}","alg":"Ed25519","cose_key_hex":"{}"}}]}}"#,
            hex(&self.identity.cose_key())
        )
    }

    /// Mints a real `RelayCapabilityToken`, CDDL §13's field numbering.
    ///
    /// Every claim is a parameter, because most of the admission matrix is
    /// "this token but with one claim wrong" and a builder that hid a claim
    /// would hide the test that needs it.
    #[must_use]
    pub fn mint(&self, claims: &TokenSpec) -> Vec<u8> {
        let payload = Item::Map(vec![
            (Item::Uint(1), Item::Text(claims.issuer_key_id.clone())),
            (Item::Uint(2), Item::Text(claims.audience.clone())),
            (Item::Uint(3), Item::Bytes(claims.subject.to_vec())),
            (Item::Uint(4), Item::Bytes(claims.confirmation_key.clone())),
            (Item::Uint(5), Item::Uint(claims.not_before_ms)),
            (Item::Uint(6), Item::Uint(claims.not_after_ms)),
            (Item::Uint(7), Item::Uint(claims.epoch)),
            (
                Item::Uint(8),
                Item::Map(vec![
                    (Item::Uint(1), Item::Uint(u64::from(claims.max_flows))),
                    (Item::Uint(2), Item::Uint(u64::from(claims.max_kbps))),
                    (Item::Uint(3), Item::Uint(claims.max_bytes_per_hour)),
                    (
                        Item::Uint(4),
                        Item::Uint(u64::from(claims.max_binds_per_min)),
                    ),
                ]),
            ),
            (Item::Uint(9), Item::Bytes(claims.jti.to_vec())),
            (Item::Uint(10), Item::Bool(false)),
        ]);
        self.identity.sign(&payload)
    }
}

impl Default for Issuer {
    fn default() -> Self {
        Self::new()
    }
}

/// Every claim of a `RelayCapabilityToken`, so a test can bend exactly one.
#[derive(Debug, Clone)]
pub struct TokenSpec {
    pub issuer_key_id: String,
    pub audience: String,
    pub subject: [u8; 16],
    pub confirmation_key: Vec<u8>,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
    pub epoch: u64,
    pub max_flows: u32,
    pub max_kbps: u32,
    pub max_bytes_per_hour: u64,
    pub max_binds_per_min: u32,
    pub jti: [u8; 16],
}

impl TokenSpec {
    /// A token that admits: correct audience, inside its window, at the relay's
    /// epoch, bound to `rlk_pub`.
    #[must_use]
    pub fn valid_for(rlk_pub: &[u8; 32], subject: u8, jti: u8) -> Self {
        Self {
            issuer_key_id: ISSUER_KEY_ID.into(),
            audience: OPERATOR_GROUP.into(),
            subject: [subject; 16],
            confirmation_key: x25519_cose_key(rlk_pub),
            not_before_ms: NOW_MS - 60_000,
            not_after_ms: NOW_MS + 86_400_000,
            epoch: EPOCH,
            max_flows: 64,
            max_kbps: 20_000,
            max_bytes_per_hour: 21_474_836_480,
            max_binds_per_min: 30,
            jti: [jti; 16],
        }
    }
}

// ===========================================================================
// The device
// ===========================================================================

/// One device's relay leg: an `RLK`, a token, and the derived `K_leg`.
pub struct Device {
    /// The device's relay-leg static private key. Distinct from its L-DATA
    /// static by construction — nothing here ever sees one.
    pub rlk_private: [u8; 32],
    /// Its public half, which the token's `cnf` binds to.
    pub rlk_public: [u8; 32],
    /// `K_leg`, once the handshake completes.
    pub k_leg: Option<[u8; 32]>,
    /// The flow this device was given, once bound.
    pub flow_id: Option<u32>,
    /// Its own send counter on the leg.
    pub counter: u64,
    entropy: Arc<dyn Entropy>,
}

impl Device {
    /// A device with a deterministic `RLK`.
    ///
    /// The `RLK` is deterministic and the *ephemeral* is not: the entropy source
    /// is the real CSPRNG, because a reproducible ephemeral is not
    /// forward-secret and a harness that used one would be testing a different
    /// protocol.
    #[must_use]
    pub fn new(seed: u8) -> Self {
        let rlk_private = [seed; 32];
        let rlk_public =
            twinvpn_crypto::relay_leg::static_public_key(&rlk_private).expect("32 bytes");
        Self {
            rlk_private,
            rlk_public,
            k_leg: None,
            flow_id: None,
            counter: 0,
            entropy: Arc::new(SystemEntropy::open().expect("/dev/urandom")),
        }
    }

    /// Runs the leg handshake against `relay` and keeps `K_leg`.
    ///
    /// Returns the raw response so a test can assert on a cookie challenge
    /// instead of a completion.
    pub async fn establish(
        &mut self,
        socket: &tokio::net::UdpSocket,
        relay: SocketAddr,
        relay_static_public: &[u8; 32],
        token: &[u8],
        cookie: Option<&[u8]>,
    ) -> Option<Vec<u8>> {
        let mut initiator =
            LegInitiator::new(&self.entropy, &self.rlk_private, relay_static_public)
                .expect("initiator");
        let presentation = TokenPresentation {
            issuer_key_id: ISSUER_KEY_ID.into(),
            cose_sign1: token.to_vec(),
        }
        .encode();
        let msg1 = initiator.initiate(&presentation).expect("msg1");

        let mut body = Vec::new();
        let mut flags = 0_u8;
        if let Some(c) = cookie {
            flags |= FLAG_CARRIES_COOKIE;
            body.extend_from_slice(c);
        }
        body.extend_from_slice(&msg1);

        let mut datagram = vec![FrameType::HandshakeInit.to_wire(), (VERSION << 4) | flags];
        datagram.extend_from_slice(&0_u16.to_be_bytes());
        datagram.extend_from_slice(&0_u32.to_be_bytes());
        datagram.extend_from_slice(&[0_u8; 8]);
        datagram.extend_from_slice(&body);

        socket.send_to(&datagram, relay).await.expect("send");
        let reply = recv(socket).await?;
        if reply.first().copied() == Some(FrameType::HandshakeResp.to_wire()) {
            let completed = initiator.complete(&reply[HEADER_LEN..]).expect("complete");
            self.k_leg = Some(*completed.k_leg());
        }
        Some(reply)
    }

    /// Establishes a leg, answering a cookie challenge if one comes back.
    ///
    /// This is what a real device does, and above ADR-0005 §11.5's threshold of
    /// 20 handshakes/s per source /24 it is the **only** thing that works: the
    /// relay does no asymmetric operation for an unvalidated source address, so
    /// the first attempt is answered with a challenge and nothing else. Every
    /// test that opens more than a handful of legs from loopback — where all of
    /// `127.0.0.0/8` is one /24 — goes through here.
    pub async fn establish_answering_challenges(
        &mut self,
        socket: &tokio::net::UdpSocket,
        relay: SocketAddr,
        relay_static_public: &[u8; 32],
        token: &[u8],
    ) -> bool {
        let Some(reply) = self
            .establish(socket, relay, relay_static_public, token, None)
            .await
        else {
            return false;
        };
        if reply.first().copied() == Some(FrameType::HandshakeResp.to_wire()) {
            return true;
        }
        if reply.first().copied() != Some(FrameType::CookieChallenge.to_wire()) {
            return false;
        }
        // The challenge body is the cookie. Present it and try once more — a
        // second challenge would mean the relay is not honouring its own cookie,
        // and looping here would hide that.
        let cookie = reply[HEADER_LEN..].to_vec();
        let Some(reply) = self
            .establish(socket, relay, relay_static_public, token, Some(&cookie))
            .await
        else {
            return false;
        };
        reply.first().copied() == Some(FrameType::HandshakeResp.to_wire())
    }

    /// Sends a `BIND` for `pair_tag` and returns the relay's reply.
    pub async fn bind(
        &mut self,
        socket: &tokio::net::UdpSocket,
        relay: SocketAddr,
        pair_tag: [u8; 16],
        bucket: u64,
    ) -> Option<Vec<u8>> {
        let body = BindBody {
            pair_tag,
            bucket,
            carriage: twinvpn_relay::config::Carriage::Udp,
            family: Family::of(socket.local_addr().expect("local")),
        }
        .encode();
        let reply = self
            .send_control(socket, relay, FrameType::Bind, 0, &body)
            .await?;
        if reply.first().copied() == Some(FrameType::Bound.to_wire()) {
            self.flow_id = Some(u32::from_be_bytes([reply[4], reply[5], reply[6], reply[7]]));
        }
        Some(reply)
    }

    /// Sends one MACed control frame and waits briefly for a reply.
    pub async fn send_control(
        &mut self,
        socket: &tokio::net::UdpSocket,
        relay: SocketAddr,
        kind: FrameType,
        flow_id: u32,
        body: &[u8],
    ) -> Option<Vec<u8>> {
        let datagram = self.encode(kind, flow_id, body);
        socket.send_to(&datagram, relay).await.expect("send");
        recv(socket).await
    }

    /// Sends one `DATA` frame. No reply is awaited — it goes to the *peer*.
    pub async fn send_data(
        &mut self,
        socket: &tokio::net::UdpSocket,
        relay: SocketAddr,
        payload: &[u8],
    ) {
        let flow = self.flow_id.expect("bound");
        let datagram = self.encode(FrameType::Data, flow, payload);
        socket.send_to(&datagram, relay).await.expect("send");
    }

    /// Assembles and MACs one frame under this device's `K_leg`.
    #[must_use]
    pub fn encode(&mut self, kind: FrameType, flow_id: u32, body: &[u8]) -> Vec<u8> {
        let k = self.k_leg.expect("a leg is established");
        self.counter += 1;
        let counter = self.counter;
        let mac_input = control::mac_input(kind, flow_id, counter, body);
        let tag = twinvpn_crypto::frame_mac(&k, &mac_input);
        control::encode_frame(kind, flow_id, counter as u16, tag, body)
    }

    /// Whether an inbound frame's MAC verifies under this device's `K_leg`.
    ///
    /// The device checks the relay's frames too — an unauthenticated `DRAIN` or
    /// `RELAY_STATUS` would be an injection primitive for anyone who can spoof a
    /// source address, and a test that skipped this would not notice a relay
    /// that stopped signing.
    #[must_use]
    pub fn verify(&self, datagram: &[u8], counter_full: u64) -> bool {
        let Some(k) = self.k_leg else { return false };
        if datagram.len() < HEADER_LEN {
            return false;
        }
        let kind = FrameType::from_wire(datagram[0]).expect("known type");
        let flow_id = u32::from_be_bytes([datagram[4], datagram[5], datagram[6], datagram[7]]);
        let mut tag = [0_u8; 8];
        tag.copy_from_slice(&datagram[8..16]);
        let mac_input = control::mac_input(kind, flow_id, counter_full, &datagram[HEADER_LEN..]);
        twinvpn_crypto::verify_frame_mac(&k, &mac_input, &tag)
    }
}

// ===========================================================================
// The relay
// ===========================================================================

/// A relay serving on loopback, with everything real.
pub struct TestRelay {
    /// Where to send.
    pub addr: SocketAddr,
    /// The shared runtime, for a test that needs to inspect or perturb it.
    pub runtime: Arc<Mutex<RelayRuntime>>,
    /// The relay's static public key, as a device gets it from a verified map.
    pub static_public: [u8; 32],
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl TestRelay {
    /// Starts a relay with the default limits.
    pub async fn start(issuer: &Issuer) -> Self {
        Self::start_with(issuer, |_| {}).await
    }

    /// Starts a relay whose leg table is deliberately small.
    ///
    /// The ceilings are `main`'s additions rather than `limits.json` values, so
    /// they are parameters here rather than configuration: a test that bent them
    /// through `RelayConfig` would be asserting a variable that does not exist.
    pub async fn start_bounded(issuer: &Issuer, max_legs: usize, max_per_prefix: usize) -> Self {
        Self::start_inner(issuer, |_| {}, max_legs, max_per_prefix).await
    }

    /// Starts a relay, letting a test bend the configuration first.
    pub async fn start_with(issuer: &Issuer, tweak: impl FnOnce(&mut RelayConfig)) -> Self {
        Self::start_inner(issuer, tweak, 1_024, 1_024).await
    }

    async fn start_inner(
        issuer: &Issuer,
        tweak: impl FnOnce(&mut RelayConfig),
        max_legs: usize,
        max_per_prefix: usize,
    ) -> Self {
        let mut cfg = relay_config();
        tweak(&mut cfg);
        let issuers = IssuerKeySet::parse(&issuer.key_set_json(), OPERATOR_GROUP, "test")
            .expect("issuer key set parses");
        let runtime = Arc::new(Mutex::new(RelayRuntime {
            engine: RelayEngine::new(cfg, issuers, EPOCH),
            legs: LegRegistry::new(max_legs, max_per_prefix, 900_000),
            scheduler: TwoTierDrr::with_default_quantum(),
            setup: Some(Arc::new(leg_setup())),
        }));
        let socket = Arc::new(
            tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("relay socket"),
        );
        let addr = socket.local_addr().expect("addr");
        let (stop, rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(serve_udp(
            socket,
            Arc::clone(&runtime),
            Arc::new(CryptoProvider::new()),
            || NOW_MS,
            async move {
                let _ = rx.await;
            },
        ));
        Self {
            addr,
            runtime,
            static_public: twinvpn_crypto::relay_leg::static_public_key(&RELAY_STATIC_PRIVATE)
                .expect("32 bytes"),
            stop: Some(stop),
            task: Some(task),
        }
    }

    /// Stops the receive loop. Everything the relay held dies with it — S-29 is
    /// "NON-DURABLE BY REQUIREMENT" and nothing is written anywhere.
    pub async fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }

    /// How many legs are established.
    #[must_use]
    pub fn leg_count(&self) -> usize {
        self.runtime.lock().expect("lock").legs.len()
    }

    /// How many half-flows are bound.
    #[must_use]
    pub fn bound_count(&self) -> usize {
        self.runtime
            .lock()
            .expect("lock")
            .engine
            .table()
            .bound_count()
    }

    /// How many pending slots are waiting for a partner.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.runtime
            .lock()
            .expect("lock")
            .engine
            .table()
            .pending_count()
    }
}

/// The relay's leg-establishment material, all real.
fn leg_setup() -> LegSetup {
    let mut key = RELAY_STATIC_PRIVATE;
    let static_private = twinvpn_crypto::LockedBytes::adopt(&mut key).expect("locked");
    let entropy: Arc<dyn Entropy> = Arc::new(SystemEntropy::open().expect("/dev/urandom"));
    let cookies = CookieJar::new(&entropy).expect("cookie secret");
    LegSetup {
        static_private,
        entropy,
        cookies,
    }
}

/// A configuration with the frozen limits and a routable endpoint.
pub fn relay_config() -> RelayConfig {
    RelayConfig::load(
        &MapEnv::new()
            .with("TWINVPN_RELAY_ID", "00000000000000a1")
            .with("TWINVPN_RELAY_REGION", "test-region-1")
            .with("TWINVPN_RELAY_FAILURE_DOMAIN", "fd-test-a")
            .with("TWINVPN_RELAY_OPERATOR_GROUP_ID", OPERATOR_GROUP)
            .with(
                "TWINVPN_RELAY_ISSUER_KEYS_PATH",
                concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
            )
            .with(
                "TWINVPN_RELAY_STATIC_KEY_PATH",
                concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
            )
            .with("TWINVPN_RELAY_LISTEN_UDP", "127.0.0.1:41641"),
    )
    .expect("configuration loads")
}

// ===========================================================================
// small helpers
// ===========================================================================

/// A client socket on loopback.
pub async fn client_socket() -> tokio::net::UdpSocket {
    client_socket_on("127.0.0.1").await
}

/// A client socket on a specific loopback address.
///
/// Every `127.0.0.0/8` address is reachable on Linux without configuration, and
/// they all share one `/24` prefix — which is exactly what the per-prefix leg
/// ceiling groups by, so this is how that ceiling is exercised for real.
pub async fn client_socket_on(host: &str) -> tokio::net::UdpSocket {
    tokio::net::UdpSocket::bind(format!("{host}:0"))
        .await
        .expect("client socket")
}

/// Waits briefly for one datagram. `None` means the relay sent **zero bytes**,
/// which is the correct answer to most of the hostile inputs in this matrix.
pub async fn recv(socket: &tokio::net::UdpSocket) -> Option<Vec<u8>> {
    let mut buf = vec![0_u8; 2_048];
    match tokio::time::timeout(
        std::time::Duration::from_millis(300),
        socket.recv_from(&mut buf),
    )
    .await
    {
        Ok(Ok((len, _))) => {
            buf.truncate(len);
            Some(buf)
        }
        _ => None,
    }
}

/// The bucket a `pair_tag` is derived for, at the harness's fixed clock.
#[must_use]
pub const fn bucket_now() -> u64 {
    NOW_MS / 1_000 / 600
}

/// Lowercase hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// A payload that would decode as a protobuf record with an unknown field.
///
/// W-4's trap, kept as a named corpus entry rather than an inline literal: a
/// forwarder that decoded and re-encoded would drop the unknown field and the
/// bytes out would differ from the bytes in.
#[must_use]
pub fn protobuf_shaped_payload() -> Vec<u8> {
    let mut v = encode(&Item::Map(vec![(Item::Uint(1), int_item(-1))])).expect("encode");
    v.extend_from_slice(&[0xFA, 0x01, 0x02, 0x03]);
    v
}
