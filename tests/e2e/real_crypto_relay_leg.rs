//! **End-to-end.** The same real-`Noise_IKpsk2` crossing, carried over a relay
//! leg — and the relay sees only ciphertext.
//!
//! **Authority:** ADR-0001 **I1** and §11 items 1 and 2; ADR-0005 **RQ1**, §7.1,
//! §7.3, §9.1, §11.1(4) and §11.1(5); ADR-0006 §11.2; ADR-0010 **R1**;
//! ADR-0018 CB-1, CD-2, CD-3; `docs/testing-strategy.md` §6.5 blocker **B-7**;
//! `docs/implementation/ownership.md` §6 rules 9, 10 and 11.
//!
//! # What is new here
//!
//! Two things this repository could not previously assert together.
//!
//! **The payload is a real L-DATA record.**
//! `core/crates/twinvpn-core/tests/relay.rs::the_relay_sees_only_ciphertext`
//! proves the leg carries an opaque payload, and says plainly that its seal is
//! `twinvpn_crypto::aead` standing in for `twinvpn-tunnel`'s — because a
//! `VerifiedTunnelKey` is out of reach from that crate. Here the octets on the
//! leg are produced by `twinvpn_core::datapath::Pump` sealing under production
//! `SessionKeys` from a genuine handshake, and are opened at the far end by the
//! peer's pump. The relay carries the real thing.
//!
//! **The relay side is the shipped relay's own code.** `core/` and `services/`
//! are separate cargo workspaces, so every previous relay test transcribed the
//! other side's wire by hand. `tests/` links both, so
//! [`standin::RelayStandIn`] uses `twinvpn_relay`'s `LegHandshake`,
//! `RelayFrame::parse`, `CounterWindow`, `control::encode_frame`,
//! `RelayFrame::reframe` and the production `CryptoProvider` MAC. A green test
//! here means the two ends agree, not that one end agrees with itself.
//!
//! # The path a packet takes
//!
//! ```text
//! TUN → Pump → Tunnel::seal (Noise_IKpsk2) → L-DATA datagram
//!     → Sealed::from_tunnel → RelayLeg DATA frame → the relay
//!     → reframe (flow_id and counter_low, nothing else) → the peer's leg
//!     → Sealed::into_tunnel → Pump → Tunnel::open → TUN
//! ```
//!
//! # What this file does not prove
//!
//! - **That a relay cannot decrypt.** That is held structurally and is proved
//!   elsewhere: `services/relay/tests/cannot_decrypt.rs` on the server side, and
//!   `core/crates/twinvpn-core/tests/relay.rs`'s
//!   `the_relay_leg_holds_no_key_that_could_open_a_payload` on the device side.
//!   What is decidable *here* is stated at each assertion, and the reference
//!   decryptor pass below is explicitly labelled as necessary and not
//!   sufficient.
//! - **Admission, tokens, quotas, drain or DRR.** [`standin::RelayStandIn`] is
//!   the datagram path only; the policy is `services/relay`'s own suite's.
//! - **That the peer's pump reads from its relay socket.** A `Pump` owns one
//!   socket, and this rig keeps the relay fabric separate from the direct one.
//!   The octets that crossed the relay are delivered into the peer's pump
//!   verbatim and are asserted to be the same octets, so what is proved is that
//!   *what the relay carried opens at the peer* — not that a single socket
//!   carries both carriages. Wiring a leg into a live session is the
//!   integration lead's edit, and nothing in `twinvpn-core` does it yet.
//! - **Failover, standby, drain scheduling.** `chaos/outage_and_failover.rs` and
//!   `core/crates/twinvpn-core/tests/relay.rs`.

use std::sync::Arc;
use std::time::Duration;

use twinvpn_core::datapath::Step;
use twinvpn_core::relay::{
    self, BindOutcome, Inbound, LegParams, RelayLeg, Sealed, TokenPresentation,
};
use twinvpn_crypto::relay_leg::STATIC_KEY_LEN;
use twinvpn_platform::mock::{MockAdapter, MockNetwork, MockOptions};
use twinvpn_platform::socket::{SocketFamily, SocketOptions, UdpBindSpec, UdpSocket};
use twinvpn_platform::PlatformAdapter as _;
use twinvpn_relay_client::map::Carriage;
use twinvpn_types::{AddressFamily, Endpoint, PairTag, RelayId};

use twinvpn_system_tests::block_on;
use twinvpn_system_tests::crossing::{contains, endpoint, Crossing, Direction};
use twinvpn_system_tests::noise::crypto_env;

#[path = "relay_leg/standin.rs"]
mod standin;

use standin::{drive, RelayStandIn};

/// ADR-0010 R1: one story covering both. The leg's family is derived from its
/// endpoint, so this loop is the whole of the family coverage.
const BOTH: [AddressFamily; 2] = [AddressFamily::V4, AddressFamily::V6];

/// A payload long enough that a substring search for it cannot match by
/// accident.
const SENTINEL: &[u8] = b"SENTINEL-overlay-packet-that-must-never-be-readable-by-a-relay-operator";

/// The reference decryptor's nonce width.
const NONCE_BYTES: usize = 24;

/// The `pair_tag` both half-flows bind. ADR-0005 §11.1(4): the first `BIND` on a
/// tag opens a pending slot, the second binds it.
const PAIR_TAG: [u8; 16] = [0x5A; 16];

// ---------------------------------------------------------------------------
// The rig
// ---------------------------------------------------------------------------

/// Two device legs and the relay between them, on their own fabric.
struct RelayRig {
    env: twinlab::LabEnv,
    relay: RelayStandIn,
    left_socket: Arc<dyn UdpSocket>,
    right_socket: Arc<dyn UdpSocket>,
    left_leg: RelayLeg,
    right_leg: RelayLeg,
}

fn socket_at(adapter: &Arc<MockAdapter>, at: Endpoint) -> Arc<dyn UdpSocket> {
    let spec = UdpBindSpec {
        family: match at.address.family() {
            AddressFamily::V4 => SocketFamily::V4,
            AddressFamily::V6 => SocketFamily::V6Only,
        },
        local: Some(at),
        options: SocketOptions::default(),
    };
    Arc::from(block_on(adapter.sockets().bind_udp(&spec)).expect("the mock binds"))
}

fn token() -> TokenPresentation {
    TokenPresentation {
        issuer_key_id: "issuer-2026-01".to_owned(),
        cose_sign1: vec![
            0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26, 0xA0, 0x4C, 0x74, 0x6F, 0x6B,
        ],
    }
}

impl RelayRig {
    /// Opens two legs to one relay and binds both to [`PAIR_TAG`].
    fn open(family: AddressFamily) -> Self {
        let env = crypto_env(0x5b);
        let net = MockNetwork::new();
        let make = || Arc::new(MockAdapter::on_network(&net, &MockOptions::default()));

        let left_socket = socket_at(&make(), endpoint(family, 31, 61_001));
        let right_socket = socket_at(&make(), endpoint(family, 32, 61_002));
        let relay_socket = socket_at(&make(), endpoint(family, 33, 61_003));

        // ADR-0010 R1, made non-vacuous: the leg's family is derived from its
        // endpoint, so a rig that silently bound v4 for the v6 arm would make
        // the family loop decorative.
        for socket in [&left_socket, &right_socket, &relay_socket] {
            assert_eq!(
                socket.local_endpoint().expect("bound").address.family(),
                family,
                "the relay rig was asked for {family:?} and bound another family"
            );
        }

        let mut relay = RelayStandIn::new(relay_socket, Arc::clone(env.env().entropy()));
        let relay_public = relay.public();
        let relay_endpoint = relay.endpoint();
        let deadline = env
            .env()
            .now_monotonic()
            .saturating_add(Duration::from_secs(30));

        let open_one =
            |socket: &Arc<dyn UdpSocket>, rlk: &[u8; STATIC_KEY_LEN], relay: &mut RelayStandIn| {
                let params = LegParams {
                    relay: RelayId::from_array([0xAA; 8]),
                    endpoint: relay_endpoint,
                    carriage: Carriage::Udp,
                    relay_static_public_from_verified_map: &relay_public,
                    rlk_private: rlk,
                    token: &token(),
                };
                drive(
                    relay::open_leg(env.env(), socket.as_ref(), params, deadline),
                    relay,
                )
                .expect("the leg opens against the shipped relay's own responder")
            };

        let mut left_leg = open_one(&left_socket, &[3; STATIC_KEY_LEN], &mut relay);
        let mut right_leg = open_one(&right_socket, &[4; STATIC_KEY_LEN], &mut relay);

        // §11.1(4): the first BIND opens a pending slot, the second binds it.
        let first = drive(
            relay::bind(
                env.env(),
                left_socket.as_ref(),
                &mut left_leg,
                PairTag::from_array(PAIR_TAG),
                4_242,
                deadline,
            ),
            &mut relay,
        )
        .expect("the relay answers a BIND");
        assert!(
            matches!(first, BindOutcome::Pending { .. }),
            "the first BIND on a tag opens a pending slot, not a bound flow"
        );

        let second = drive(
            relay::bind(
                env.env(),
                right_socket.as_ref(),
                &mut right_leg,
                PairTag::from_array(PAIR_TAG),
                4_242,
                deadline,
            ),
            &mut relay,
        )
        .expect("the relay answers a BIND");
        assert!(
            matches!(second, BindOutcome::Bound { .. }),
            "the second BIND on the same tag binds the flow"
        );

        Self {
            env,
            relay,
            left_socket,
            right_socket,
            left_leg,
            right_leg,
        }
    }

    fn deadline(&self) -> twinvpn_env::MonotonicInstant {
        self.env
            .env()
            .now_monotonic()
            .saturating_add(Duration::from_secs(30))
    }

    /// Puts one sealed L-DATA datagram on the left leg and returns what the
    /// right leg received.
    fn carry(&mut self, datagram: Vec<u8>) -> Inbound {
        let sealed = Sealed::from_tunnel(datagram).expect("inside ADR-0005 §9.2's ceiling");
        drive(
            relay::send_sealed(self.left_socket.as_ref(), &mut self.left_leg, &sealed),
            &mut self.relay,
        )
        .expect("the datagram leaves the device");
        self.relay.settle();
        let deadline = self.deadline();
        drive(
            relay::receive(
                self.env.env(),
                self.right_socket.as_ref(),
                &mut self.right_leg,
                deadline,
            ),
            &mut self.relay,
        )
        .expect("the peer's leg reads what the relay forwarded")
    }
}

// ---------------------------------------------------------------------------
// 1. The crossing, over the relay leg
// ---------------------------------------------------------------------------

/// **The headline.** A real IP packet crosses between two composed endpoints
/// over a relay leg, and the relay sees only ciphertext.
///
/// # How this is known to fail for the right reason
///
/// Four independent controls, all in this test:
///
/// - The relay's forwarded payload is asserted **byte-identical** to the
///   datagram the sender's pump produced (§11.1(5): `flow_id` and `counter_low`
///   are rewritten, *nothing else is touched*). A relay that re-encoded the
///   payload fails here rather than downstream.
/// - The plaintext-absence check is paired with a positive control: the same
///   `contains` call is run against the plaintext itself and asserted to fire,
///   so a silent detector cannot report a silent success (B-7).
/// - The delivered octets are asserted to open at the peer's pump and to arrive
///   on its TUN device byte-identical. A relay that dropped, truncated or
///   reordered the payload fails there.
/// - `mac_failures` is asserted to be zero, so the relay actually **verified**
///   the device's frames rather than forwarding whatever arrived. A stand-in
///   that skipped verification would carry a forged frame just as happily.
#[test]
fn a_real_ip_packet_crosses_over_a_relay_leg_and_the_relay_sees_only_ciphertext() {
    for family in BOTH {
        let crossing = Crossing::open(family);
        let mut rig = RelayRig::open(family);

        // The real pump seals the real packet under production `SessionKeys`.
        let wire = crossing.emit(Direction::LeftToRight, SENTINEL);

        let inbound = rig.carry(wire.clone());
        let Inbound::Data(sealed) = inbound else {
            panic!("{family:?}: the relay forwarded something that was not DATA");
        };
        assert_eq!(
            format!("{sealed:?}"),
            format!("Sealed(<{} B opaque>)", wire.len()),
            "{family:?}: §6 rule 11 — a payload renders as a length, never as octets"
        );

        // §11.1(5), on both sides of the relay.
        assert_eq!(
            rig.relay.observed.len(),
            1,
            "{family:?}: exactly one DATA frame reached the relay"
        );
        assert_eq!(
            rig.relay.observed[0], wire,
            "{family:?}: the relay did not forward the payload byte for byte"
        );
        assert_eq!(rig.relay.forwarded, 1);
        assert_eq!(
            rig.relay.mac_failures, 0,
            "{family:?}: the shipped relay's verifier rejected the device's own frame"
        );

        // Positive control for the leak detector, before its silence is read as
        // a result (B-7).
        assert!(
            contains(SENTINEL, SENTINEL),
            "{family:?}: the leak detector did not find a plaintext handed to it directly"
        );
        assert!(
            !contains(&rig.relay.observed[0], SENTINEL),
            "{family:?}: the plaintext was readable in what the relay carried"
        );
        assert!(
            !contains(&rig.relay.observed[0], &SENTINEL[..16]),
            "{family:?}: a 16-byte prefix of the plaintext was readable at the relay"
        );

        // And the octets the relay carried open at the peer.
        let back = sealed.into_tunnel();
        assert_eq!(back, wire, "{family:?}: the leg changed the datagram");
        assert_eq!(
            crossing.deliver(Direction::LeftToRight, &back),
            Step::Moved(SENTINEL.len()),
            "{family:?}: what the relay carried did not open at the peer"
        );
        assert_eq!(
            crossing.right.written(),
            vec![SENTINEL.to_vec()],
            "{family:?}: the packet that arrived is not the packet that was sent"
        );
    }
}

/// ADR-0005 §7.1's oracle, run over the relay's **complete** key inventory.
///
/// > "dump the relay's complete key material at any instant, feed the union to
/// > the reference decryptor, and assert that no captured frame decrypts."
///
/// # What this establishes, and what it does not
///
/// The inventory is enumerated rather than described — the static private key
/// and one `K_leg` per leg — and each is fed to `twinvpn_crypto::aead::open`
/// over the captured record. That pass is **necessary and not sufficient**: the
/// record is a Noise transport record and the reference decryptor is a
/// different construction, so its refusal does not by itself separate "the key
/// is wrong" from "the construction is wrong".
///
/// What carries the weight is the two facts around it, and they are the ones
/// asserted:
///
/// - the inventory is **closed at two kinds** — ADR-0005 §7.3 says the relay's
///   static "is **NOT** an input to the L-DATA `Noise_IKpsk2` handshake", and
///   `K_leg` is derived from the leg handshake, which this relay ran and the two
///   devices' L-DATA handshake did not involve at all;
/// - the record demonstrably opens under the peer's `SessionKeys` and under
///   nothing else this rig can produce, which is
///   `real_crypto_crossing.rs::a_datagram_from_another_session_does_not_open_at_this_receiver`.
///
/// The structural half — that the relay's code holds no type that could open a
/// payload — is `services/relay/tests/cannot_decrypt.rs`'s and
/// `core/crates/twinvpn-core/tests/relay.rs`'s, and is not restated here.
#[test]
fn the_relays_complete_key_inventory_opens_nothing_it_carried() {
    for family in BOTH {
        let crossing = Crossing::open(family);
        let mut rig = RelayRig::open(family);
        let wire = crossing.emit(Direction::LeftToRight, SENTINEL);
        let _ = rig.carry(wire);

        let inventory = rig.relay.key_inventory();
        assert_eq!(
            inventory.len(),
            3,
            "{family:?}: the inventory is one static plus one K_leg per leg — a relay that grew a \
             fourth key needs this test read again, not extended"
        );
        let captured = &rig.relay.observed[0];

        for (index, mut candidate) in inventory.into_iter().enumerate() {
            let key = twinvpn_crypto::aead::StoreKey::adopt_sek(&mut candidate).expect("a key");
            // Every nonce split the captured record could plausibly carry: at
            // the head, and immediately after the 16-byte L-DATA header.
            for split in [0_usize, twinvpn_core::datapath::HEADER_BYTES] {
                let nonce_end = split + NONCE_BYTES;
                if captured.len() <= nonce_end {
                    continue;
                }
                let mut nonce = [0_u8; NONCE_BYTES];
                nonce.copy_from_slice(&captured[split..nonce_end]);
                assert!(
                    twinvpn_crypto::aead::open(
                        &key,
                        &nonce,
                        b"twinvpn/l-data",
                        &captured[nonce_end..]
                    )
                    .is_err(),
                    "{family:?}: relay key {index} opened a payload it carried — I1 is broken"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 2. The adversarial cases on the relay leg
// ---------------------------------------------------------------------------

/// **Attack test.** A relay that alters what it carries cannot make the change
/// stick: the peer's tunnel refuses the record.
///
/// ADR-0001 I1 has two halves. The one everybody states is that a relay must not
/// be able to *read* a payload; the one that matters just as much is that it
/// must not be able to *change* one undetectably. An on-path relay is the most
/// natural place for that attack, and this is it.
///
/// # How this is known to fail for the right reason
///
/// The unaltered datagram is delivered afterwards, on the same rig, and
/// asserted to cross. That is the positive control: the refusal above is
/// attributable to the altered byte, not to a receiver that had stopped
/// working. The altered copy is delivered **first** so it cannot be refused as
/// a replay of the good one.
#[test]
fn a_relay_that_alters_the_payload_is_refused_by_the_peers_tunnel() {
    for family in BOTH {
        let crossing = Crossing::open(family);
        let mut rig = RelayRig::open(family);
        let wire = crossing.emit(Direction::LeftToRight, SENTINEL);

        let inbound = rig.carry(wire.clone());
        let Inbound::Data(sealed) = inbound else {
            panic!("{family:?}: expected DATA");
        };
        let carried = sealed.into_tunnel();

        // The relay flips one byte of the record it is carrying.
        let mut altered = carried.clone();
        let last = altered.len() - 1;
        altered[last] ^= 0x01;
        assert_eq!(
            crossing.deliver(Direction::LeftToRight, &altered),
            Step::Rejected(twinvpn_core::datapath::Reject::Unauthenticated),
            "{family:?}: a relay-altered record opened at the peer"
        );
        assert!(
            crossing.right.written().is_empty(),
            "{family:?}: a refused record must leave no plaintext behind"
        );

        // Positive control.
        assert_eq!(
            crossing.deliver(Direction::LeftToRight, &carried),
            Step::Moved(SENTINEL.len()),
            "{family:?}: the unaltered record did not cross, so the refusal above is not \
             attributable to the alteration"
        );
        assert_eq!(crossing.right.written(), vec![SENTINEL.to_vec()]);
    }
}

/// **Attack test.** A `DATA` frame whose leg MAC does not verify is dropped by
/// the relay and never forwarded.
///
/// ADR-0005 §9.1's frame MAC is the relay's only authentication of a device, and
/// §11.5 gives an unauthenticated source zero bytes in reply. A relay that
/// forwarded on a bad MAC would let any off-path source inject into a bound
/// flow.
///
/// # How this is known to fail for the right reason
///
/// The forged frame is a **copy of a genuine one** with a single tag byte
/// flipped, sent from the same device socket, so everything except the MAC is
/// acceptable. The genuine frame is then sent on the same rig and asserted to be
/// forwarded — the positive control that separates "the MAC was checked" from
/// "the relay forwards nothing".
#[test]
fn a_forged_leg_mac_is_dropped_by_the_relay_and_never_forwarded() {
    for family in BOTH {
        let crossing = Crossing::open(family);
        let mut rig = RelayRig::open(family);
        let wire = crossing.emit(Direction::LeftToRight, SENTINEL);

        // A genuine frame, captured by asking the leg to build one and putting
        // it on the wire ourselves with one tag byte flipped.
        let sealed = Sealed::from_tunnel(wire.clone()).expect("inside the ceiling");
        let mut forged = rig
            .left_leg
            .data_datagram(&sealed)
            .expect("the leg frames a DATA");
        forged[8] ^= 0x01; // the first octet of the 64-bit frame MAC

        let relay_endpoint = rig.relay.endpoint();
        block_on(rig.left_socket.send_to(&forged, &relay_endpoint)).expect("the mock delivers");
        rig.relay.settle();

        assert_eq!(
            rig.relay.mac_failures, 1,
            "{family:?}: the relay did not reject a frame whose MAC was wrong"
        );
        assert!(
            rig.relay.observed.is_empty(),
            "{family:?}: a frame that failed its MAC reached the relay's forwarding path"
        );
        assert_eq!(
            rig.relay.forwarded, 0,
            "{family:?}: the relay forwarded a frame it could not authenticate"
        );

        // Positive control: a genuine frame on the same rig is carried.
        let inbound = rig.carry(wire.clone());
        assert!(matches!(inbound, Inbound::Data(_)));
        assert_eq!(rig.relay.forwarded, 1);
        assert_eq!(rig.relay.observed, vec![wire]);
    }
}
