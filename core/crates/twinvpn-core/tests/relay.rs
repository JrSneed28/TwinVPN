//! **The relay leg, against a relay stand-in that speaks the shipped wire.**
//!
//! # The defect these tests close
//!
//! `twinvpn-relay-client` had **no production caller anywhere in the tree**:
//! before `twinvpn_core::relay`,
//! `grep -rn "twinvpn_relay_client::" core/crates/twinvpn-core/src shells/ lab/`
//! matched nothing. The crate could rank every relay in a verified map and
//! could not put one byte on the wire to any of them, so relay fallback — the
//! whole answer to *the direct path failed* — did not happen.
//!
//! Every assertion below is therefore about **octets that crossed a socket**,
//! or about a decision made on octets that did. The relay stand-in encodes its
//! side from `services/relay/src/{control,status,frame}.rs` byte for byte and
//! never from this crate's encoder, so a test passing means the two ends agree
//! rather than that one end agrees with itself.
//!
//! # The seal is real, and it is not this module's
//!
//! `twinvpn_crypto::aead` stands in for `twinvpn-tunnel`'s L-DATA seal. The
//! property under test is the **relay leg's** — that it carries an opaque
//! payload and holds nothing that could open one — and ADR-0005 §7.1 fixes the
//! oracle: *"dump the relay's complete key material at any instant, feed the
//! union to the reference decryptor, and assert that no captured frame
//! decrypts."* The stand-in's whole inventory is two keys, and
//! [`the_relay_sees_only_ciphertext`] enumerates both.

#![cfg(feature = "full")]

use core::future::Future;
use core::task::{Context, Poll, Waker};
use std::sync::Arc;
use std::time::Duration;

use twinvpn_core::relay::{
    self, BindOutcome, DrainNotice, Failover, Inbound, LegParams, RelayLeg, RelayPair, RelayReject,
    Sealed, TokenPresentation,
};
use twinvpn_core::testing;
use twinvpn_crypto::relay_leg::{static_public_key, LegResponder, STATIC_KEY_LEN};
use twinvpn_crypto::{aead, frame_mac};
use twinvpn_env::{Entropy, Env, EnvError, EnvParts, SystemRngSource, WallClockReading};
use twinvpn_platform::mock::{MockAdapter, MockNetwork, MockOptions};
use twinvpn_platform::socket::{SocketFamily, SocketOptions, UdpBindSpec, UdpSocket};
use twinvpn_platform::PlatformAdapter as _;
use twinvpn_relay_client::frame::{HEADER_LEN, MAX_DATA_PAYLOAD_BYTES, VERSION};
use twinvpn_relay_client::map::Carriage;
use twinvpn_relay_client::standby::{Conditions, PowerPosture, Role};
use twinvpn_types::{AddressFamily, Endpoint, IpAddr, PairTag, Port, RelayId, V4Addr, V6Addr};

// ---------------------------------------------------------------------------
// a relay stand-in that speaks the shipped wire
// ---------------------------------------------------------------------------

const T_DATA: u8 = 0x01;
const T_BIND: u8 = 0x10;
const T_BOUND: u8 = 0x11;
const T_DRAIN: u8 = 0x14;
const T_STATUS: u8 = 0x15;
const T_HS_INIT: u8 = 0x18;
const T_HS_RESP: u8 = 0x19;
const T_COOKIE: u8 = 0x1A;
const FLOW: u32 = 0x0A0B_0C0D;

/// `services/relay/src/control.rs::mac_input` — `type ‖ ver|flags ‖ counter_full
/// ‖ flow_id ‖ body`.
fn mac_input(kind: u8, flow: u32, counter_full: u64, body: &[u8]) -> Vec<u8> {
    let mut v = vec![kind, VERSION << 4];
    v.extend_from_slice(&counter_full.to_be_bytes());
    v.extend_from_slice(&flow.to_be_bytes());
    v.extend_from_slice(body);
    v
}

/// `services/relay/src/control.rs::encode_frame`, with the relay's fixed
/// counter of zero for every control frame.
fn relay_frame(kind: u8, flow: u32, k_leg: &[u8; 32], body: &[u8]) -> Vec<u8> {
    let tag = frame_mac(k_leg, &mac_input(kind, flow, 0, body));
    let mut v = vec![kind, VERSION << 4, 0, 0];
    v.extend_from_slice(&flow.to_be_bytes());
    v.extend_from_slice(&tag);
    v.extend_from_slice(body);
    v
}

/// `services/relay/src/status.rs::encode_body`.
fn status_body(code: &str, retry_after_ms: u32) -> Vec<u8> {
    let mut v = vec![u8::try_from(code.len()).expect("short code"), 0, 0, 0];
    v.extend_from_slice(&retry_after_ms.to_be_bytes());
    v.extend_from_slice(code.as_bytes());
    v
}

/// `services/relay/src/control.rs::DrainBody::encode`.
fn drain_body(deadline_ms: u64, suggestions: &[RelayId]) -> Vec<u8> {
    let mut v = deadline_ms.to_be_bytes().to_vec();
    v.push(u8::try_from(suggestions.len()).expect("bounded"));
    v.extend_from_slice(&[0, 0, 0]);
    for id in suggestions {
        v.extend_from_slice(&id.to_array());
    }
    v
}

/// What the stand-in answers a `BIND` with.
#[derive(Clone)]
enum OnBind {
    Bound,
    Pending(u32),
    Refuse(&'static str, u32),
}

/// The relay, as far as the device can tell.
struct StandIn {
    socket: Box<dyn UdpSocket>,
    static_private: [u8; STATIC_KEY_LEN],
    k_leg: Option<[u8; 32]>,
    on_bind: OnBind,
    challenge_first: bool,
    /// Every `DATA` payload the relay observed — its whole view of the traffic.
    observed: Vec<Vec<u8>>,
    /// The token presentation recovered from the encrypted handshake payload.
    token_seen: Option<Vec<u8>>,
    binds: usize,
    datagrams_in: usize,
}

impl StandIn {
    fn new(socket: Box<dyn UdpSocket>, on_bind: OnBind) -> Self {
        Self {
            socket,
            static_private: [7_u8; STATIC_KEY_LEN],
            k_leg: None,
            on_bind,
            challenge_first: false,
            observed: Vec::new(),
            token_seen: None,
            binds: 0,
            datagrams_in: 0,
        }
    }

    fn public(&self) -> [u8; STATIC_KEY_LEN] {
        static_public_key(&self.static_private).expect("a static public half")
    }

    fn endpoint(&self) -> Endpoint {
        self.socket.local_endpoint().expect("bound")
    }

    /// One synchronous turn: take a datagram if one is queued, answer it.
    fn step(&mut self, entropy: &Arc<dyn Entropy>) {
        let mut buf = vec![0_u8; HEADER_LEN + MAX_DATA_PAYLOAD_BYTES];
        let Some(meta) = poll_once(self.socket.recv_from(&mut buf)) else {
            return;
        };
        let meta = meta.expect("the fabric delivered");
        assert!(!meta.truncated, "the stand-in's buffer is the wire maximum");
        buf.truncate(meta.len);
        let from = meta.source;
        self.datagrams_in += 1;
        let body = &buf[HEADER_LEN..];

        let reply = match buf[0] {
            T_HS_INIT if self.challenge_first => {
                self.challenge_first = false;
                Some(leg_setup(T_COOKIE, 0, &[0xC7_u8; 16]))
            }
            T_HS_INIT => {
                // ADR-0005 §11.5's cookie gate: the flag says whether one rode
                // along, and the stand-in strips it exactly as `admit.rs` does.
                let noise = if buf[1] & 0x01 == 0 {
                    body
                } else {
                    &body[16..]
                };
                let responder =
                    LegResponder::new(entropy, &self.static_private).expect("a responder");
                let (msg2, completed) = responder.respond(noise, &[]).expect("message 2");
                self.token_seen = Some(completed.payload().to_vec());
                self.k_leg = Some(*completed.k_leg());
                Some(leg_setup(T_HS_RESP, 0, &msg2))
            }
            T_BIND => {
                let k = self.k_leg.expect("a BIND arrives on an established leg");
                self.binds += 1;
                Some(match self.on_bind.clone() {
                    OnBind::Bound => relay_frame(T_BOUND, FLOW, &k, &[1, 0, 0, 0, 0, 0, 0, 0]),
                    OnBind::Pending(ttl) => {
                        let mut b = vec![0, 0, 0, 0];
                        b.extend_from_slice(&ttl.to_be_bytes());
                        relay_frame(T_BOUND, FLOW, &k, &b)
                    }
                    OnBind::Refuse(code, retry) => {
                        relay_frame(T_STATUS, FLOW, &k, &status_body(code, retry))
                    }
                })
            }
            T_DATA => {
                self.observed.push(body.to_vec());
                None
            }
            _ => None,
        };
        if let Some(datagram) = reply {
            poll_once(self.socket.send_to(&datagram, &from))
                .expect("the mock send is ready on first poll")
                .expect("delivered");
        }
    }

    /// Originates a `DRAIN` on the bound flow, as ADR-0005 §11.5 permits.
    fn drain(&mut self, to: Endpoint, deadline_ms: u64, suggestions: &[RelayId]) {
        let k = self.k_leg.expect("an established leg");
        let d = relay_frame(T_DRAIN, FLOW, &k, &drain_body(deadline_ms, suggestions));
        poll_once(self.socket.send_to(&d, &to))
            .expect("ready")
            .expect("delivered");
    }
}

/// `services/relay/src/admit.rs` sends every leg-setup frame with a zero
/// counter, a zero flow and a zero tag: there is no `K_leg` yet.
fn leg_setup(kind: u8, flags: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![kind, (VERSION << 4) | flags, 0, 0, 0, 0, 0, 0];
    v.extend_from_slice(&[0_u8; 8]);
    v.extend_from_slice(body);
    v
}

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

fn poll_once<F: Future>(future: F) -> Option<F::Output> {
    let mut future = Box::pin(future);
    let waker = Waker::noop();
    match future.as_mut().poll(&mut Context::from_waker(waker)) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

/// Drives one client future, letting the stand-in answer whenever it stalls.
///
/// That interleaving *is* the deployment: a device sends, a relay answers, a
/// device reads. Doing it explicitly keeps the ordering reproducible, which is
/// what `VirtualTime`'s own runtime doc calls for.
fn drive<T>(future: impl Future<Output = T>, relay: &mut StandIn, entropy: &Arc<dyn Entropy>) -> T {
    let mut future = Box::pin(future);
    let waker = Waker::noop();
    for _ in 0..32 {
        if let Poll::Ready(v) = future.as_mut().poll(&mut Context::from_waker(waker)) {
            return v;
        }
        relay.step(entropy);
    }
    panic!("the exchange did not settle in 32 turns");
}

fn endpoint(family: AddressFamily, last: u8, port: u16) -> Endpoint {
    let address = match family {
        AddressFamily::V4 => IpAddr::V4(V4Addr::from_slice(&[192, 0, 2, last]).expect("v4")),
        AddressFamily::V6 => IpAddr::V6(
            V6Addr::from_slice(
                &[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, last],
                0,
            )
            .expect("v6"),
        ),
    };
    Endpoint::new(address, Port::new(port).expect("port"))
}

fn socket_at(adapter: &Arc<MockAdapter>, at: Endpoint) -> Box<dyn UdpSocket> {
    let spec = UdpBindSpec {
        family: match at.address.family() {
            AddressFamily::V4 => SocketFamily::V4,
            AddressFamily::V6 => SocketFamily::V6Only,
        },
        local: Some(at),
        options: SocketOptions::default(),
    };
    poll_once(adapter.sockets().bind_udp(&spec))
        .expect("the mock bind is ready on first poll")
        .expect("bound")
}

/// The `RelayCapabilityToken` as it is presented: an issuer key id and a
/// COSE_Sign1 envelope, forwarded to verification exactly as it arrived.
fn token() -> TokenPresentation {
    TokenPresentation {
        issuer_key_id: "issuer-2026-01".to_owned(),
        cose_sign1: vec![
            0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26, 0xA0, 0x4C, 0x74, 0x6F, 0x6B,
        ],
    }
}

const RLK_PRIVATE: [u8; STATIC_KEY_LEN] = [3_u8; STATIC_KEY_LEN];

struct Leg {
    env: Env,
    entropy: Arc<dyn Entropy>,
    client: Box<dyn UdpSocket>,
    relay: StandIn,
    leg: RelayLeg,
}

/// Opens a real leg over the fabric, both families through the same path.
fn open(family: AddressFamily, on_bind: OnBind, challenge_first: bool) -> Leg {
    let net = MockNetwork::new();
    let (env, _time) = testing::env();
    let entropy: Arc<dyn Entropy> = Arc::clone(env.entropy());
    let adapter = Arc::new(MockAdapter::on_network(&net, &MockOptions::default()));

    let client = socket_at(&adapter, endpoint(family, 10, 51_000));
    let mut relay = StandIn::new(socket_at(&adapter, endpoint(family, 20, 52_000)), on_bind);
    relay.challenge_first = challenge_first;

    let relay_public = relay.public();
    let params = LegParams {
        relay: RelayId::from_array([0xAA; 8]),
        endpoint: relay.endpoint(),
        carriage: Carriage::Udp,
        relay_static_public_from_verified_map: &relay_public,
        rlk_private: &RLK_PRIVATE,
        token: &token(),
    };
    let deadline = env.now_monotonic().saturating_add(Duration::from_secs(30));
    let leg = drive(
        relay::open_leg(&env, client.as_ref(), params, deadline),
        &mut relay,
        &entropy,
    )
    .expect("the leg opens");

    Leg {
        env,
        entropy,
        client,
        relay,
        leg,
    }
}

fn bind(h: &mut Leg) -> BindOutcome {
    let deadline = h
        .env
        .now_monotonic()
        .saturating_add(Duration::from_secs(30));
    let bucket = 4_242_u64;
    drive(
        relay::bind(
            &h.env,
            h.client.as_ref(),
            &mut h.leg,
            PairTag::from_array([0x5A; 16]),
            bucket,
            deadline,
        ),
        &mut h.relay,
        &h.entropy,
    )
    .expect("the relay answers a BIND")
}

// ---------------------------------------------------------------------------
// 1. a BIND completes and a sealed frame round-trips, ciphertext only
// ---------------------------------------------------------------------------

#[test]
fn the_relay_sees_only_ciphertext() {
    const PLAINTEXT: &[u8] = b"SENTINEL-overlay-packet-that-must-never-reach-a-relay";

    let mut h = open(AddressFamily::V4, OnBind::Bound, false);
    assert_eq!(
        bind(&mut h),
        BindOutcome::Bound { flow_id: FLOW },
        "the second BIND on a tag binds it (ADR-0005 §11.1(4))"
    );
    assert!(h.leg.is_bound());

    // The token reached the relay INSIDE the encrypted handshake — never on the
    // wire in the clear, and never in a following frame.
    let presented = h.relay.token_seen.as_ref().expect("a token was presented");
    assert_eq!(presented, &token().encode());
    // Decoded the way `services/relay/src/admit.rs::TokenPresentation::decode`
    // does, so "the token arrived" means the relay could actually read it:
    // `[version:u8][key_id_len:u8][reserved:u16][issuer_key_id][cose_sign1 …]`.
    assert_eq!(presented[0], 1, "the envelope version");
    let id_len = usize::from(presented[1]);
    assert_eq!(&presented[2..4], &[0, 0], "reserved is zero on send");
    assert_eq!(&presented[4..4 + id_len], token().issuer_key_id.as_bytes());
    assert_eq!(
        &presented[4 + id_len..],
        &token().cose_sign1[..],
        "the COSE_Sign1 envelope is forwarded to verification EXACTLY as issued"
    );

    // A real AEAD seal under a key the relay never holds.
    let mut secret = [0x11_u8; 32];
    let tunnel_key = aead::StoreKey::adopt_sek(&mut secret).expect("a key");
    let boxed = aead::seal(&h.env, &tunnel_key, b"twinvpn/l-data", PLAINTEXT).expect("sealed");
    let mut wire = boxed.nonce.to_vec();
    wire.extend_from_slice(&boxed.ciphertext);

    let sealed = Sealed::from_tunnel(wire.clone()).expect("inside the ceiling");
    assert_eq!(
        format!("{sealed:?}"),
        format!("Sealed(<{} B opaque>)", wire.len())
    );
    drive(
        relay::send_sealed(h.client.as_ref(), &mut h.leg, &sealed),
        &mut h.relay,
        &h.entropy,
    )
    .expect("the datagram leaves");
    h.relay.step(&h.entropy);

    // §11.1(5): forwarded byte for byte, never fragmented, never reassembled.
    assert_eq!(
        h.relay.observed.len(),
        1,
        "one DATA frame reached the relay"
    );
    assert_eq!(h.relay.observed[0], wire, "byte for byte");

    // ADR-0005 §7.1's oracle: the relay's COMPLETE key inventory is two keys.
    // Feed both to the reference decryptor and assert nothing opens.
    let inventory = [h.relay.k_leg.expect("K_leg"), {
        let mut s = [0_u8; 32];
        s.copy_from_slice(&h.relay.static_private);
        s
    }];
    for mut candidate in inventory {
        let key = aead::StoreKey::adopt_sek(&mut candidate).expect("a key");
        assert!(
            aead::open(&key, &boxed.nonce, b"twinvpn/l-data", &boxed.ciphertext).is_err(),
            "a relay key opened a payload — I1 is broken"
        );
    }
    for observed in &h.relay.observed {
        assert!(
            !observed.windows(PLAINTEXT.len()).any(|w| w == PLAINTEXT),
            "the plaintext appeared on the wire"
        );
    }
}

#[test]
fn the_relay_leg_holds_no_key_that_could_open_a_payload() {
    // A source assertion, for the same reason `services/relay/tests/cannot_decrypt.rs`
    // uses one: a decrypt path is something that must not EXIST, and only
    // reading the source can assert absence. A behavioural test can only show
    // that the paths taken today do not decrypt.
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/src/relay");
    let mut sources =
        vec![
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/relay.rs"))
                .expect("the module root"),
        ];
    // ENUMERATED, never listed. A hardcoded module list is a hole exactly the
    // size of the next module somebody adds, and the property asserted here is
    // about the whole module — so the directory is the list.
    for entry in std::fs::read_dir(root).expect("the module directory") {
        let path = entry.expect("an entry").path();
        assert_eq!(
            path.extension().and_then(std::ffi::OsStr::to_str),
            Some("rs"),
            "a file in src/relay/ went unscanned: {}",
            path.display()
        );
        sources.push(std::fs::read_to_string(&path).expect("a submodule"));
    }
    assert!(
        sources.len() >= 8,
        "only {} sources were scanned; the module has more than that",
        sources.len()
    );
    // Prose may name the forbidden things — that is how the property is
    // explained — so only code lines are scanned.
    let code: String = sources
        .iter()
        .flat_map(|s| s.lines())
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    for forbidden in [
        "twinvpn_tunnel",
        "aead",
        "decrypt",
        "::open(",
        "TransportKeys",
        "SessionKeys",
    ] {
        assert!(
            !code.contains(forbidden),
            "the relay leg names `{forbidden}`; it must hold nothing that could open a payload"
        );
    }
    // And the payload type has exactly the readers it is documented to have.
    let sealed = std::fs::read_to_string(format!("{root}/sealed.rs")).expect("sealed.rs");
    assert!(!sealed.contains("impl core::ops::Deref"));
    assert!(!sealed.contains("impl AsRef"));
    assert!(!sealed.contains("impl core::fmt::Display"));
    assert!(sealed.contains("pub(super) fn as_wire"));
}

// ---------------------------------------------------------------------------
// 2. each refusal is its own outcome and its own registered code
// ---------------------------------------------------------------------------

#[test]
fn each_refusal_is_a_distinct_outcome_with_its_own_registered_code() {
    let cases: [(&'static str, u32, &'static str); 5] = [
        (
            "RELAY.FLOW_LIMIT_REACHED",
            5_000,
            "RELAY.FLOW_LIMIT_REACHED",
        ),
        ("RELAY.BIND_RATE_LIMITED", 60_000, "RELAY.BIND_RATE_LIMITED"),
        ("RELAY.RATE_LIMITED", 1_000, "RELAY.RATE_LIMITED"),
        ("RELAY.QUOTA_EXCEEDED", 3_600_000, "RELAY.QUOTA_EXCEEDED"),
        // What the relay in this tree actually emits for all four, per
        // `services/relay/src/condition.rs`. It is its own outcome, not a
        // guess at which of the four it was.
        ("RELAY.CAPACITY_REJECTED", 5_000, "RELAY.CAPACITY_REJECTED"),
    ];

    let mut seen: Vec<String> = Vec::new();
    for (wire, retry_ms, expected_code) in cases {
        let mut h = open(AddressFamily::V4, OnBind::Refuse(wire, retry_ms), false);
        let BindOutcome::Refused(refusal) = bind(&mut h) else {
            panic!("{wire} must refuse the BIND, and must never do it silently");
        };
        let code = refusal
            .reason_code()
            .expect("the refusal names a REGISTERED code");
        assert_eq!(code.as_str(), expected_code);
        assert_eq!(
            refusal.retry_after(),
            Duration::from_millis(u64::from(retry_ms)),
            "ADR-0006 §11.7 rule 3 makes retry_after_ms binding"
        );
        let rendered = format!("{refusal:?}");
        assert!(
            !seen.contains(&rendered),
            "{wire} collapsed onto an outcome another refusal already produced"
        );
        seen.push(rendered);
    }
    assert_eq!(seen.len(), 5, "five refusals, five distinct outcomes");
}

#[test]
fn a_pending_slot_is_not_a_bound_flow() {
    let mut h = open(AddressFamily::V4, OnBind::Pending(30_000), false);
    assert_eq!(
        bind(&mut h),
        BindOutcome::Pending {
            flow_id: FLOW,
            // The re-BIND cadence comes from the RELAY's number, not a
            // compiled-in copy of it.
            pending_ttl: Duration::from_millis(30_000),
        }
    );
    assert!(!h.leg.is_bound(), "a pending slot carries nothing");
}

#[test]
fn a_cookie_challenge_restarts_the_handshake_and_the_leg_still_opens() {
    // ADR-0005 §11.5's stateless cookie gate, from the device's side.
    let mut h = open(AddressFamily::V4, OnBind::Bound, true);
    assert_eq!(bind(&mut h), BindOutcome::Bound { flow_id: FLOW });
}

// ---------------------------------------------------------------------------
// 3. the drain draw is inside [0, deadline - 60 s], and it comes from Env
// ---------------------------------------------------------------------------

/// A seeded entropy source, so "drawn from `Env`" is checkable over a
/// population rather than asserted about one device.
#[derive(Debug)]
struct SeededEntropy(std::sync::Mutex<u64>);

impl Entropy for SeededEntropy {
    fn fill(&self, dst: &mut [u8]) -> Result<(), EnvError> {
        let mut s = self.0.lock().map_err(|_| EnvError::EntropyUnavailable)?;
        for b in dst.iter_mut() {
            // SplitMix64: cheap, well-distributed, and obviously not a CSPRNG —
            // a test source that looked cryptographic would be worse.
            *s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = *s;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            *b = u8::try_from((z ^ (z >> 31)) & 0xFF).unwrap_or(0);
        }
        Ok(())
    }
}

fn seeded_env(seed: u64) -> Env {
    let entropy: Arc<dyn Entropy> = Arc::new(SeededEntropy(std::sync::Mutex::new(seed)));
    let vt = twinvpn_env::virtual_time::VirtualTime::new(WallClockReading::Unset);
    Env::new(EnvParts {
        monotonic: vt.monotonic(),
        elapsed: vt.elapsed(),
        wall: vt.wall(),
        timer: vt.timer(),
        runtime: vt.runtime(),
        entropy: Arc::clone(&entropy),
        rng: Arc::new(SystemRngSource::new(entropy)),
    })
}

#[test]
fn a_drain_schedules_a_migration_inside_the_announced_window() {
    // `docs/reliability.md` §8.3 and ADR-0006 §11.7: uniformly from
    // `[0, deadline - 60 s]`, so a fleet leaving a draining relay spreads
    // across the window instead of arriving at its replacement together. The
    // reserve exists so a device whose migration fails still has a full
    // T_MIGRATE budget and one retry before the deadline.
    let deadline = Duration::from_secs(120);
    let reserve = Duration::from_secs(60);
    let notice = DrainNotice {
        relay: RelayId::from_array([1; 8]),
        deadline,
        suggested: Vec::new(),
    };

    let mut distinct = std::collections::BTreeSet::new();
    for seed in 0..256_u64 {
        let env = seeded_env(seed);
        let schedule = notice
            .schedule_migration(&env)
            .expect("the draw propagates a failure rather than substituting a constant");
        assert!(
            schedule.offset <= deadline - reserve,
            "seed {seed} was told to move inside the reserved tail: {:?}",
            schedule.offset
        );
        assert_eq!(
            schedule.at,
            env.now_monotonic().saturating_add(schedule.offset),
            "the instant is on the INJECTED monotonic clock (CD-1)"
        );
        distinct.insert(schedule.offset.as_millis());
    }
    // The sharpest form of the property: the draw is a draw. A constant would
    // satisfy every bound above and be exactly the herd the mechanism exists
    // to prevent.
    assert!(
        distinct.len() > 200,
        "256 seeds produced only {} distinct instants — this is not a draw",
        distinct.len()
    );
}

#[test]
fn a_drain_deadline_inside_the_reserve_moves_now_rather_than_never() {
    let notice = DrainNotice {
        relay: RelayId::from_array([1; 8]),
        deadline: Duration::from_secs(30),
        suggested: Vec::new(),
    };
    let env = seeded_env(9);
    assert_eq!(
        notice.schedule_migration(&env).expect("draws").offset,
        Duration::ZERO,
        "a window inside which no move is legal means move now, not schedule never"
    );
}

#[test]
fn a_drain_arrives_over_the_wire_and_its_suggestions_are_re_checked() {
    let mut h = open(AddressFamily::V4, OnBind::Bound, false);
    assert_eq!(bind(&mut h), BindOutcome::Bound { flow_id: FLOW });

    let known = RelayId::from_array([0xBB; 8]);
    let unknown = RelayId::from_array([0xCC; 8]);
    let client_endpoint = h.client.local_endpoint().expect("bound");
    h.relay.drain(client_endpoint, 120_000, &[known, unknown]);

    let deadline = h
        .env
        .now_monotonic()
        .saturating_add(Duration::from_secs(30));
    let inbound = drive(
        relay::receive(&h.env, h.client.as_ref(), &mut h.leg, deadline),
        &mut h.relay,
        &h.entropy,
    )
    .expect("a DRAIN is a frame the leg understands");
    let Inbound::Drain(notice) = inbound else {
        panic!("expected a DRAIN");
    };
    assert_eq!(notice.deadline, Duration::from_millis(120_000));
    // `relay.proto`: a relay can ASK a device to leave but can NEVER REDIRECT a
    // session. A suggestion absent from the verified map is inert.
    assert_eq!(relay::admissible(&notice.suggested, &[known]), vec![known]);
    assert!(relay::admissible(&notice.suggested, &[]).is_empty());
}

// ---------------------------------------------------------------------------
// 4. failover to the warm standby, with no fresh selection round
// ---------------------------------------------------------------------------

fn conditions() -> Conditions {
    Conditions {
        carrier: twinvpn_types::PathClass::Relayed,
        carrier_duration: Duration::from_secs(60),
        role: Role::Peer,
        power: PowerPosture {
            metered: false,
            battery_pct: Some(90),
            parked: false,
        },
        admissible_relays: 3,
        mains_or_unmetered: true,
    }
}

/// §11.4's relay-failure row: three missed leg PING/PONG is `T_LEG_DEAD`.
fn relay_is_dead() -> twinvpn_relay_client::failover::Observation {
    twinvpn_relay_client::failover::Observation {
        missed_leg_pings: 3,
        leg_hard_signal: false,
        drain_deadline_reached: false,
        half_flow_silent: false,
        quality_violated: false,
        all_legs_on_interface_dead: false,
        capacity_rejected: false,
        region_failed: false,
    }
}

#[test]
fn failover_to_a_warm_standby_needs_no_fresh_selection() {
    let mut primary = open(AddressFamily::V4, OnBind::Bound, false);
    assert_eq!(bind(&mut primary), BindOutcome::Bound { flow_id: FLOW });
    let mut alternate = open(AddressFamily::V4, OnBind::Bound, false);
    assert_eq!(bind(&mut alternate), BindOutcome::Bound { flow_id: FLOW });

    let primary_id = primary.leg.relay();
    let mut pair = RelayPair::new(primary.leg);
    pair.adopt_standby(alternate.leg, conditions())
        .expect("a bound leg may be adopted");
    assert!(pair.posture().is_warm(), "a bound standby is warm");

    let binds_before = alternate.relay.binds;
    let datagrams_before = alternate.relay.datagrams_in;

    let outcome = pair.on_observation(relay_is_dead());
    assert!(
        matches!(outcome, Failover::PromotedStandby { .. }),
        "a bound standby must be promoted, not re-selected"
    );
    let Failover::PromotedStandby { from, .. } = outcome else {
        unreachable!()
    };
    assert_eq!(from, primary_id);
    assert!(
        outcome.is_make_before_break(),
        "T19, not T20: there is a carrying path throughout"
    );
    assert_eq!(
        outcome.reason_code().map(twinvpn_types::ReasonCode::as_str),
        Some("RELAY.FAILOVER_VALIDATED")
    );

    // THE ASSERTION THE MECHANISM EXISTS FOR: promotion cost nothing on the
    // wire. No selection, no leg handshake, no second BIND — which is the only
    // way a 300 ms T_FAILOVER_TARGET is reachable at all.
    assert_eq!(alternate.relay.binds, binds_before);
    assert_eq!(alternate.relay.datagrams_in, datagrams_before);
    assert!(
        pair.standby().is_none(),
        "the standby was moved, not copied"
    );
}

#[test]
fn an_unbound_leg_is_never_reported_as_a_warm_standby() {
    let primary = open(AddressFamily::V4, OnBind::Bound, false);
    let cold = open(AddressFamily::V4, OnBind::Bound, false);
    let mut pair = RelayPair::new(primary.leg);
    // §11.2: "the failover posture … is GENUINELY WEAKER, and saying so is the
    // point." A leg with no BIND cannot be promoted without the round trip the
    // standby exists to avoid, so it is refused rather than adopted.
    assert!(pair.adopt_standby(cold.leg, conditions()).is_err());
    assert!(!pair.posture().is_warm());
    assert!(matches!(
        pair.on_observation(relay_is_dead()),
        Failover::NeedsSelection { .. }
    ));
}

#[test]
fn peer_loss_on_a_live_leg_does_not_move_relay() {
    // §11.4: "a working relay is not the problem, and moving costs a migration
    // that cannot help."
    let primary = open(AddressFamily::V4, OnBind::Bound, false);
    let mut pair = RelayPair::new(primary.leg);
    let mut observation = relay_is_dead();
    observation.missed_leg_pings = 0;
    observation.half_flow_silent = true;
    assert!(matches!(
        pair.on_observation(observation),
        Failover::NoMove {
            attribution: twinvpn_relay_client::failover::Attribution::PeerLoss
        }
    ));
}

// ---------------------------------------------------------------------------
// 5. both families, one code path (ADR-0010 R1)
// ---------------------------------------------------------------------------

#[test]
fn both_address_families_bind_and_carry_over_the_same_code_path() {
    for family in [AddressFamily::V4, AddressFamily::V6] {
        let mut h = open(family, OnBind::Bound, false);
        assert_eq!(
            h.leg.family(),
            family,
            "the family is DERIVED from the endpoint, never chosen beside it"
        );
        assert_eq!(bind(&mut h), BindOutcome::Bound { flow_id: FLOW });

        let sealed = Sealed::from_tunnel(vec![0xAB; 512]).expect("inside the ceiling");
        drive(
            relay::send_sealed(h.client.as_ref(), &mut h.leg, &sealed),
            &mut h.relay,
            &h.entropy,
        )
        .expect("the datagram leaves");
        h.relay.step(&h.entropy);
        assert_eq!(
            h.relay.observed,
            vec![vec![0xAB; 512]],
            "{family:?} carried the payload byte for byte"
        );
    }
}

// ---------------------------------------------------------------------------
// 6. bounded before allocation
// ---------------------------------------------------------------------------

#[test]
fn a_declared_count_over_its_ceiling_is_refused_before_anything_is_sized() {
    // The ceiling is checked FIRST and independently of how many octets
    // arrived, so a body claiming 255 suggestions is refused whether or not it
    // carries the 2 040 octets to back the claim. Both forms are asserted,
    // because only the second distinguishes "bounded before allocation" from
    // "bounded by running out of input".
    let mut starved = drain_body(120_000, &[]);
    starved[8] = 255;
    let mut fed = starved.clone();
    fed.extend_from_slice(&vec![0_u8; 255 * 8]);

    for body in [starved, fed] {
        let err = relay::DrainBody::decode(&body).expect_err("refused");
        assert!(matches!(
            err,
            RelayReject::DeclaredCountTooLarge {
                declared: 255,
                ceiling: 3
            }
        ));
        assert_eq!(err.reason_code().as_str(), "PROTO.SIZE_EXCEEDED");
    }

    // The same for a status body's two declared lengths.
    let mut status = status_body("RELAY.RATE_LIMITED", 1_000);
    status[1] = 200;
    assert!(matches!(
        relay::StatusBody::decode(&status),
        Err(RelayReject::DeclaredCountTooLarge {
            declared: 200,
            ceiling: 3
        })
    ));
    let mut long_code = status_body("RELAY.RATE_LIMITED", 1_000);
    long_code[0] = 200;
    assert!(matches!(
        relay::StatusBody::decode(&long_code),
        Err(RelayReject::DeclaredCountTooLarge {
            declared: 200,
            ceiling: 64
        })
    ));
}

#[test]
fn an_oversized_or_malformed_frame_is_rejected_not_truncated() {
    let mut h = open(AddressFamily::V4, OnBind::Bound, false);

    // Past ADR-0005 §9.2's derived ceiling: refused BEFORE the vector is
    // retained, and never split — §11.1(5) forbids fragmentation on this leg.
    let err = Sealed::from_tunnel(vec![0; MAX_DATA_PAYLOAD_BYTES + 1]).expect_err("refused");
    assert!(matches!(
        err,
        RelayReject::PayloadTooLarge {
            observed: 1_457,
            limit: 1_456
        }
    ));
    assert_eq!(err.reason_code().as_str(), "PROTO.SIZE_EXCEEDED");
    assert!(Sealed::from_tunnel(vec![0; MAX_DATA_PAYLOAD_BYTES]).is_ok());

    // Shorter than the 16-byte header, an unknown type, and a forged tag are
    // all silent drops with registered codes — never a partial accept.
    assert!(matches!(
        h.leg.on_datagram(&[0x01, 0x10, 0, 0]),
        Err(RelayReject::Malformed)
    ));
    let k = h.relay.k_leg.expect("K_leg");
    let mut forged = relay_frame(T_BOUND, FLOW, &k, &[1, 0, 0, 0, 0, 0, 0, 0]);
    forged[8] ^= 0xFF;
    let err = h
        .leg
        .on_datagram(&forged)
        .expect_err("a bad MAC is refused");
    assert_eq!(err.reason_code().as_str(), "CRYPTO.REPLAY_DETECTED");
    assert!(!h.leg.is_bound(), "a refused frame changed no state");

    // A BOUND body that is short is refused rather than read past.
    let short = relay_frame(T_BOUND, FLOW, &k, &[1, 0, 0]);
    assert!(matches!(
        h.leg.on_datagram(&short),
        Err(RelayReject::Malformed)
    ));

    // W-32: a frame only a DEVICE sends, arriving from a genuinely keyed relay.
    // It authenticates, and the direction check is what refuses it.
    let wrong_way = relay_frame(T_BIND, FLOW, &k, &[0_u8; 28]);
    let err = h
        .leg
        .on_datagram(&wrong_way)
        .expect_err("a relay may not send a BIND");
    assert!(matches!(err, RelayReject::WrongDirection));
    assert_eq!(err.reason_code().as_str(), "RELAY.MAP_UNVERIFIED");
}

#[test]
fn a_bind_body_carries_no_peer_identifier_of_any_kind() {
    // `identifiers.md` and `protocol.md` §16 row 21: `peer_key_id` was
    // withdrawn because a tag observed at one relay is useless at another,
    // "which is what a `peer_key_id` field would have destroyed". The encoded
    // width is the assertion — 16 + 8 + 1 + 1 + 2 admits nothing more.
    let body = relay::BindBody {
        pair_tag: [0x5A; 16],
        bucket: 4_242,
        carriage: Carriage::Udp,
        family: AddressFamily::V6,
    }
    .encode();
    assert_eq!(
        body.len(),
        28,
        "no field fits beside the four that are there"
    );
    assert_eq!(&body[..16], &[0x5A; 16]);
    assert_eq!(&body[16..24], &4_242_u64.to_be_bytes());
    assert_eq!(body[25], 2, "v6 is one octet of one body, not a namespace");
    assert_eq!(&body[26..], &[0, 0], "reserved is zero on send (ADR-0014)");
}

#[test]
fn the_pair_tag_bucket_defers_rather_than_inventing_one() {
    // CD-1a: an RTC-less device between power-on and its first offset is in a
    // normal operating state. Inventing a bucket would derive a `pair_tag` the
    // peer cannot match and produce an unexplainable RELAY.PAIR_UNMATCHED.
    let (env, _t) = testing::env();
    assert!(
        relay::pair_tag_bucket(&env).is_none(),
        "an Unset wall clock yields `not yet`, never a number"
    );
    assert!(relay::bucket_accepted(100, 99) && relay::bucket_accepted(100, 101));
    assert!(!relay::bucket_accepted(100, 102));
    assert!(
        relay::bucket_accepted(0, 0),
        "written as comparisons, so a u64 underflow cannot accept everything"
    );
}

#[test]
fn the_wire_constants_match_the_relay() {
    // `services/relay` is a SEPARATE cargo workspace (ownership.md §1), so this
    // crate cannot link it and cannot assert its constants by naming them. It
    // can read them, which is enough to fail the moment either side moves —
    // and failing is the point: these are two implementations of one wire, and
    // a silent disagreement is every frame dropped with both ends looking
    // correctly configured.
    let relay_src = |name: &str| {
        std::fs::read_to_string(format!(
            "{}/../../../services/relay/src/{name}.rs",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap_or_else(|e| panic!("services/relay/src/{name}.rs: {e}"))
    };
    let control = relay_src("control");
    let status = relay_src("status");
    let leg = relay_src("leg");
    let frame = relay_src("frame");

    for (source, declaration) in [
        // The three body widths this module encodes and decodes.
        (
            &control,
            "pub const BIND_BODY_BYTES: usize = PAIR_TAG_BYTES + 8 + 1 + 1 + 2;",
        ),
        (&control, "pub const BOUND_BODY_BYTES: usize = 1 + 3 + 4;"),
        (
            &control,
            "pub const CAPS_BODY_BYTES: usize = 1 + 1 + 2 + 2 + 2;",
        ),
        (&control, "pub const DRAIN_PREFIX_BYTES: usize = 8 + 1 + 3;"),
        // The two ceilings that decide whether a decode allocates.
        (&control, "pub const MAX_SUGGESTED_RELAYS: usize = 3;"),
        (&status, "pub const MAX_SUGGESTED_ALTERNATIVES: usize = 3;"),
        (&status, "pub const MAX_REASON_CODE_BYTES: usize = 64;"),
        // The cookie width, and the header this module builds by hand.
        (&leg, "pub const COOKIE_BYTES: usize = 16;"),
        (&frame, "pub const HEADER_LEN: usize = 16;"),
        (&frame, "pub const VERSION: u8 = 1;"),
        (&frame, "pub const MAX_DATA_PAYLOAD_BYTES: usize = 1_456;"),
        // The three type bytes the device crate has no variant for.
        (&frame, "0x18 => Some(FrameType::HandshakeInit),"),
        (&frame, "0x19 => Some(FrameType::HandshakeResp),"),
        (&frame, "0x1A => Some(FrameType::CookieChallenge),"),
    ] {
        assert!(
            source.contains(declaration),
            "the relay no longer declares `{declaration}` — this module's copy has drifted"
        );
    }

    // And the values this module actually uses, so the check above is not just
    // a grep over prose.
    assert_eq!(relay::codec::BIND_BODY_BYTES, 28);
    assert_eq!(relay::codec::BOUND_BODY_BYTES, 8);
    assert_eq!(relay::codec::CAPS_BODY_BYTES, 8);
    assert_eq!(relay::codec::DRAIN_PREFIX_BYTES, 12);
    assert_eq!(relay::codec::MAX_SUGGESTED_RELAYS, 3);
    assert_eq!(relay::codec::MAX_REASON_CODE_BYTES, 64);
    assert_eq!(relay::legsetup::COOKIE_BYTES, 16);
    assert_eq!(relay::LegSetupType::HandshakeInit.to_wire(), 0x18);
    assert_eq!(relay::LegSetupType::HandshakeResp.to_wire(), 0x19);
    assert_eq!(relay::LegSetupType::CookieChallenge.to_wire(), 0x1A);
    assert_eq!(relay::MAX_RELAY_DATAGRAM_BYTES, 16 + 1_456);
}
