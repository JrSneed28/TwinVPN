//! **Two seeded cores, one real `Noise_IKpsk2` handshake, and not one tick.**
//!
//! **Authority:** ADR-0001 §7.2, §7.3.1; ADR-0007 N-4; ADR-0010 R1;
//! `docs/reliability.md` §4.4 (`T_HE_BIAS`), §4.5 (`Steady`); ADR-0018 CD-5
//! (*"the whole composed core on a plain Linux CI runner"*).
//!
//! # The question this file answers
//!
//! `Core::tick` documents itself as *"the step a daemon runs on each wake, and
//! the reason a one-shot `session.connect` is not enough: §4.4 races candidates
//! staggered by the family bias, so a v4 candidate is not due until `T_HE_BIAS`
//! after a v6 one. Without a tick the delayed half of the race is never
//! probed."* **No shell in this repository calls it**, and the kill-switch
//! lane's peer endpoint is IPv4 — so either the lane needs a ticking service or
//! the doc's "not enough" is about probing and not about establishment.
//!
//! It is about probing. The two are separable and this file separates them:
//!
//! * `establish::probe` chooses its socket by the **peer endpoint's** family and
//!   skips a candidate of the other one, and `Race::schedule` puts a v4
//!   candidate's first probe at `T_HE_BIAS` — so with a v4 endpoint **no probe
//!   is sent at `t=0` at all**, ticked or not;
//! * `execute::establishment::direct` reads `entry.sockets.first()` and
//!   `entry.peer_endpoint` and drives the whole handshake **inside the
//!   `session.connect` that `net.up` runs**, so `path_validated` — and with it
//!   `Steady` — is set before `submit` returns.
//!
//! Both ends below are composed [`twinvpn_core::Core`]s built exactly as the
//! service builds one, seeded exactly as `TWINVPN_LAB_SEED_FILE` seeds one, and
//! **nothing in this file calls `tick`**. If establishment ever comes to need
//! one, this test fails and the service gains a tick loop.
//!
//! # Why the ports are literals
//!
//! `MockNetwork` allocates ephemeral ports from 49152 upwards under one mutex,
//! and `establish::gather` binds v4 before v6. The responder is started first
//! and the initiator waits for its two binds, so the four ports are determined
//! rather than guessed — which is what lets each half be seeded with the other's
//! endpoint *before* either exists, the way `twinpeer seed` writes both files
//! before either end runs.

#![cfg(all(feature = "lab-seed", not(windows)))]

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use twinvpn_crypto::locked::LockedBytes;
use twinvpn_mgmt::{CoreCommand, Submission};
use twinvpn_platform::iface::{InterfaceFacts, InterfaceIndex, InterfaceName, LinkClass};
use twinvpn_platform::mock::{MockAdapter, MockNetwork, MockOptions};
use twinvpn_platform::PlatformAdapter;
use twinvpn_types::{InterfaceAddress, IpAddr, V4Addr, V6Addr};
use twinvpnsvc::lab_seed::Seed;
use twinvpnsvc::service::runtime;

/// The responder's v4 socket: the first bind on a fresh fabric.
const RESPONDER_V4_PORT: u16 = 49_152;
/// The initiator's v4 socket: the third, after the responder's v6.
const INITIATOR_V4_PORT: u16 = 49_154;

/// Both ends' `local.device_id`, ordered so the initiator sorts first —
/// `execute::handshake::role_for` gives the lower id `Role::Initiator`.
const INITIATOR_ID: u8 = 0x11;
const RESPONDER_ID: u8 = 0x99;

// ---------------------------------------------------------------------------
// The two halves of one `twinpeer seed` run
// ---------------------------------------------------------------------------

/// One end's document.
///
/// Every field the two halves must agree on — the PSK inputs, the negotiation
/// binding, the anchor state — is a literal shared by both calls. That is the
/// property `twinpeer seed` has by construction and this fixture has by
/// repetition.
fn document(local: End, peer: End, peer_port: u16) -> String {
    format!(
        r#"{{
  "twinnet_id": "tn-lab",
  "local": {{
    "device_id": "{local_id}",
    "static_private": "{local_private}",
    "overlay_v4": "100.64.1.{local_host}",
    "overlay_v6": "fd7c:9e5d:2a10:1::{local_host}"
  }},
  "peer": {{
    "device_id": "{peer_id}",
    "static_public": "{peer_public}",
    "overlay_v4": "100.64.1.{peer_host}",
    "overlay_v6": "fd7c:9e5d:2a10:1::{peer_host}",
    "endpoint": "0.0.0.0:{peer_port}"
  }},
  "psk": {{
    "pair_secret": "{pair}",
    "epoch_seed": "{seed}",
    "epoch": 1
  }},
  "negotiation": {{
    "h_initiator": "{h_init}",
    "h_responder": "{h_resp}",
    "selection_dcbor": "7477696e706565722d6c61622d73656c656374696f6e2d7631"
  }},
  "anchor_version": 1,
  "delegation_set_digest": "{digest}",
  "trust_epoch": 0
}}"#,
        local_id = hex(local.id),
        local_private = hex(local.private_seed),
        local_host = local.overlay_host,
        peer_id = hex(peer.id),
        peer_public = hex_bytes(&public_of(peer.private_seed)),
        peer_host = peer.overlay_host,
        pair = hex(0x41),
        seed = hex(0x51),
        h_init = hex(0x61),
        h_resp = hex(0x71),
        digest = hex(0x81),
    )
}

/// What one end is, in the two places the document names it.
#[derive(Clone, Copy)]
struct End {
    id: u8,
    private_seed: u8,
    overlay_host: u8,
}

const INITIATOR: End = End {
    id: INITIATOR_ID,
    private_seed: 0x21,
    overlay_host: 1,
};
const RESPONDER: End = End {
    id: RESPONDER_ID,
    private_seed: 0x31,
    overlay_host: 2,
};

/// The X25519 public key for a static built from one repeated byte.
///
/// `twinvpn_crypto::noise::static_public_key` and not a second X25519 here: a
/// fixture that derived the public key its own way could disagree with the
/// handshake about what the private key names, and that failure looks exactly
/// like a wrong peer.
fn public_of(private_seed: u8) -> [u8; 32] {
    let locked = LockedBytes::new_with(32, |dst| dst.fill(private_seed)).expect("locks 32 bytes");
    twinvpn_crypto::noise::static_public_key(&locked).expect("a 32-byte static has a public key")
}

fn hex(byte: u8) -> String {
    hex_bytes(&[byte; 32])
}

fn hex_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

// ---------------------------------------------------------------------------
// One composed end, built the way the service builds one
// ---------------------------------------------------------------------------

/// A counting CSPRNG, deterministic and obviously so.
///
/// Two ends must not share a stream: identical "randomness" on both sides
/// would give the two Noise ephemerals the same value, which is a degenerate
/// case no real handshake has and no test should silently rely on.
struct CountingEntropy(std::sync::atomic::AtomicU64);

impl twinvpn_env::Entropy for CountingEntropy {
    fn fill(&self, dst: &mut [u8]) -> Result<(), twinvpn_env::EnvError> {
        for byte in dst.iter_mut() {
            let n = self.0.fetch_add(1, Ordering::Relaxed);
            *byte = u8::try_from(n & 0xff).unwrap_or(0);
        }
        Ok(())
    }
}

struct Composed {
    core: Arc<twinvpn_core::Core>,
    adapter: Arc<MockAdapter>,
    /// Held for the process's sake: the `Env` owns the runtime the handshake
    /// blocks on.
    _runtime: Arc<twinvpn_env::binding::tokio_rt::TokioRuntime>,
}

fn compose(net: &MockNetwork, entropy_start: u64, document: &str) -> Composed {
    let adapter = Arc::new(MockAdapter::on_network(net, &MockOptions::default()));
    adapter
        .interfaces_mock()
        .set_interfaces(vec![dual_stack_interface()]);
    let (env, runtime) = runtime::build_env_with(Arc::new(CountingEntropy(
        std::sync::atomic::AtomicU64::new(entropy_start),
    )))
    .expect("the three clocks and a tokio runtime bind on this host");
    let core = Arc::new(
        runtime::build_core(
            &env,
            Arc::clone(&adapter) as Arc<dyn PlatformAdapter>,
            false,
            "core-held:test",
        )
        .expect("the core is created"),
    );
    Seed::parse(document)
        .expect("the seed document parses")
        .install(&core);
    Composed {
        core,
        adapter,
        _runtime: runtime,
    }
}

/// The underlay the candidates are gathered from. Both families, so the race
/// covers both and the v4 half is the one `T_HE_BIAS` delays — which is the
/// stagger this test is about.
fn dual_stack_interface() -> InterfaceFacts {
    InterfaceFacts {
        index: InterfaceIndex(2),
        name: InterfaceName::new("eth0").expect("valid"),
        addresses: vec![
            InterfaceAddress::new(IpAddr::V4(V4Addr::from_octets([192, 0, 2, 10])), 24)
                .expect("v4 address"),
            InterfaceAddress::new(
                IpAddr::V6(
                    V6Addr::from_slice(
                        &[0xfd, 0x77, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10],
                        0,
                    )
                    .expect("v6"),
                ),
                64,
            )
            .expect("v6 address"),
        ],
        has_default_route_v4: true,
        has_default_route_v6: true,
        is_overlay: false,
        is_up: true,
        mtu: 1500,
        link_class: LinkClass::Ethernet,
    }
}

// ---------------------------------------------------------------------------
// The proof
// ---------------------------------------------------------------------------

#[test]
fn a_seeded_pair_reaches_steady_on_net_up_alone_with_no_tick() {
    let net = MockNetwork::new();

    // The responder is composed and started first, so it owns the fabric's
    // first two ephemeral ports and is already listening when the initiation
    // arrives. `execute::handshake::drive` does not retransmit — the initiator
    // sends once — so "already bound" is a precondition and not a preference.
    let responder = compose(
        &net,
        0x9000,
        &document(RESPONDER, INITIATOR, INITIATOR_V4_PORT),
    );
    let initiator = compose(
        &net,
        0x1000,
        &document(INITIATOR, RESPONDER, RESPONDER_V4_PORT),
    );

    let responder_core = Arc::clone(&responder.core);
    let far_end = std::thread::spawn(move || {
        // `net.up` and not `session.connect`: it is the command the lane runs,
        // and it connects every seeded session before it arms.
        let _ = responder_core.submit(&Submission::bare(CoreCommand::NetUp));
        responder_core.any_session_connected()
    });

    // Both of the responder's sockets, so the port arithmetic above holds.
    let deadline = Instant::now() + Duration::from_secs(30);
    while responder.adapter.sockets_mock().opened() < 2 {
        assert!(
            Instant::now() < deadline,
            "the responder never bound its sockets"
        );
        std::thread::sleep(Duration::from_millis(1));
    }

    let (delivered_before, _) = net.counters();
    let _ = initiator.core.submit(&Submission::bare(CoreCommand::NetUp));

    // THE ASSERTION. Not one `tick` was called on either core, by this file or
    // by anything the service does, and the session is carrying.
    assert!(
        initiator.core.any_session_connected(),
        "the initiator did not reach Steady inside `net.up`: the handshake needs \
         something this test did not do, and a periodic `Core::tick` in the \
         Windows service is the thing to reconsider"
    );
    assert!(
        far_end.join().expect("the responder thread did not panic"),
        "the responder did not reach Steady"
    );

    // The round trip, counted on the fabric: an initiation and a response.
    // Without this a `Steady` reached some other way would still pass.
    let (delivered_after, dropped) = net.counters();
    assert!(
        delivered_after >= delivered_before + 2,
        "a completed handshake is two datagrams; the fabric delivered {} \
         (dropped {dropped})",
        delivered_after - delivered_before
    );
}

#[test]
fn with_nothing_at_the_endpoint_the_same_seeding_does_not_report_connected() {
    // The negative half, and the reason the test above is not an artefact of
    // the harness: one seeded core with nothing listening at the peer endpoint
    // runs exactly the same code and does NOT reach a steady state. `Steady` is
    // therefore a fact about the handshake and not about the seeding.
    let net = MockNetwork::new();
    let alone = compose(
        &net,
        0x5000,
        &document(INITIATOR, RESPONDER, RESPONDER_V4_PORT),
    );
    // Nothing is listening at the peer endpoint, so the handshake cannot
    // complete however long it waits.
    let _ = alone.core.submit(&Submission::bare(CoreCommand::NetUp));
    assert!(
        !alone.core.any_session_connected(),
        "a session with no reachable peer must not report itself connected"
    );
}
