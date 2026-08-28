//! Fuzzing the **pre-authentication** handshake reader and the platform
//! adapter's parsers.
//!
//! **Owner:** `test-engineering`.
//!
//! Two groups, and both are outside the reach of the other three files.
//!
//! # 1. The responder's handshake reader
//!
//! `Handshake::read_message` is the single most exposed decoder in the product
//! that is not the relay frame: anyone who can send a UDP datagram to the tunnel
//! port reaches it, **before any key has authorised anything**. ADR-0001 A1's
//! "silence on unauthenticated input" is what a caller is supposed to do with a
//! failure; a *panic* would be neither silence nor a failure.
//!
//! A responder is used because a responder needs no `VerifiedTunnelKey` up
//! front — `IK` has it learn the peer's static from the initiation — which is
//! also precisely why the responder, not the initiator, is the side an unsolicited
//! datagram reaches.
//!
//! **Not covered here:** `TransportSession::open`. Reaching it needs a completed
//! handshake, which needs a `VerifiedTunnelKey`, which is only constructible
//! through a signed and verified `TunnelKeyBinding`. Its replay behaviour is
//! covered by `integration/tunnel_wire_agreement.rs` and its window by
//! `e2e/scenario_matrix.rs`; its AEAD is `snow`'s. Stated rather than left as an
//! unexplained gap.
//!
//! # 2. The platform adapter's parsers
//!
//! `twinvpn-platform-linux` parses three things this process did not write: a
//! netlink receive buffer, `nft --json`'s output, and a resolver restore point
//! from disk. The kernel is trusted; **a declared length arriving from a socket
//! is still a declared length**, and `ownership.md` §6 rule 9 makes an unbounded
//! allocation from one a defect wherever it came from. The restore point is read
//! by `twinvpn-unblock` and by the boot restore unit with the agent absent, so a
//! panic there is a machine that will not restore its resolver.

use std::sync::Arc;

use twinvpn_crypto::locked::LockedBytes;
use twinvpn_crypto::noise::{Handshake, HandshakeConfig, Role};
use twinvpn_crypto::prologue::{IdentityBinding, NegotiationBinding, Prologue, TwinnetTag};
use twinvpn_crypto::psk::TwinNetPsk;
use twinvpn_env::virtual_time::VirtualTime;
use twinvpn_env::{Entropy, Env, EnvError, EnvParts, SystemRngSource, WallClockReading};
use twinvpn_system_tests::fuzz::{corpus, fuzz, outcome_of, Outcome};

const SEED: u64 = 0x7717_4E17_5EED_0004;
const ITERATIONS: usize = 400;

/// Per-shape iterations for the handshake target only.
///
/// Two orders of magnitude below the others, and the reason is measured rather
/// than guessed: every input needs a **fresh** `Handshake`, because
/// `read_message` mutates state and a reused one would make the engine's
/// determinism check compare two different machines. A `Handshake::new` is a
/// `snow` builder, a prologue, a PSK slot and an X25519 static — about 8 ms in a
/// debug build, which is 45 s at `ITERATIONS` and 5 s here.
///
/// `tests/README.md` §6 records the whole suite's cost, and a fuzz target that
/// dominated it would be the first one somebody disabled.
const HANDSHAKE_ITERATIONS: usize = 50;

// ---------------------------------------------------------------------------
// 1. The responder handshake.
// ---------------------------------------------------------------------------

/// A deterministic, **non-cryptographic** entropy source.
///
/// Reaching for the platform CSPRNG in a test would be a CD-3 violation as well
/// as a source of flakiness. A handshake's *rejection* of a hostile message does
/// not depend on its ephemerals being unpredictable; only its forward secrecy
/// does, and that is a property of the production binding.
struct CountingEntropy(std::sync::Mutex<u64>);

impl Entropy for CountingEntropy {
    fn fill(&self, dst: &mut [u8]) -> Result<(), EnvError> {
        let mut s = self.0.lock().expect("test mutex");
        for b in dst.iter_mut() {
            *s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            #[allow(clippy::cast_possible_truncation)]
            {
                *b = (*s >> 33) as u8;
            }
        }
        Ok(())
    }
}

fn env(seed: u64) -> Env {
    let vt = VirtualTime::new(WallClockReading::Unset);
    let entropy: Arc<dyn Entropy> = Arc::new(CountingEntropy(std::sync::Mutex::new(seed)));
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

fn static_key(seed: u8) -> LockedBytes {
    LockedBytes::new_with(32, |dst| {
        dst.fill(seed);
        dst[0] = seed | 0x01;
    })
    .expect("locked static")
}

fn prologue() -> Prologue {
    Prologue::new(
        &IdentityBinding {
            twinnet: TwinnetTag::from_twinnet_id("tn-fuzz"),
            device_id_init: [0x01; 32],
            device_id_resp: [0x02; 32],
            trust_epoch: 1,
            psk_epoch: 1,
            anchor_version: 1,
            delegation_set_digest: [0x03; 32],
        },
        &NegotiationBinding {
            h_initiator: [0x04; 32],
            h_responder: [0x05; 32],
            selection_dcbor: vec![0xa0],
        },
    )
}

/// A **fresh** responder for every input.
///
/// `read_message` mutates handshake state, so reusing one across inputs would
/// make the engine's determinism check compare two different machines and report
/// the decoder as non-deterministic when it is the harness that is.
fn responder(psk: &TwinNetPsk, prologue: &Prologue, local: &LockedBytes) -> Handshake {
    Handshake::new(
        &env(2),
        Role::Responder,
        &HandshakeConfig {
            local_static: local,
            remote_static: None,
            psk,
            prologue,
        },
    )
    .expect("a responder needs no remote static")
}

#[test]
fn the_responder_handshake_reader_is_total_over_arbitrary_datagrams() {
    let psk = TwinNetPsk::derive(b"pair-secret", &[0x77; 32], "tn-fuzz", 1).expect("psk");
    let pro = prologue();
    let local = static_key(0x42);

    // An `IK` initiation is 48 bytes of key material plus tags; the corpus is
    // seeded with plausible lengths as well as random ones, because a decoder
    // that rejects on length before parsing is only fuzzed by inputs that get
    // past the length check.
    let seeds = vec![vec![0u8; 96], vec![0xff; 96], vec![0u8; 48], Vec::new()];
    let inputs = corpus(SEED, HANDSHAKE_ITERATIONS, 1_500, &seeds);

    let report = fuzz("crypto::Handshake::read_message[responder]", &inputs, |b| {
        let mut hs = responder(&psk, &pro, &local);
        let mut out = vec![0u8; 4096];
        outcome_of(&hs.read_message(b, &mut out))
    });
    // No `reached_accept` assertion: a responder accepting an unauthenticated
    // datagram it did not solicit would be the defect, not the coverage. Every
    // input in this corpus SHOULD be rejected, and the property under test is
    // that it is rejected rather than crashed on.
    assert_eq!(
        report.accepted, 0,
        "a forged initiation was accepted: {report:?}",
    );
    assert!(report.reached_reject(), "{report:?}");
}

#[test]
fn a_short_output_buffer_is_a_refusal_rather_than_an_overflow() {
    // The caller supplies `out`. A decoder that wrote past it would be a memory
    // defect reachable from the network in a crate that `#![forbid(unsafe_code)]`
    // only protects from directly.
    let psk = TwinNetPsk::derive(b"pair-secret", &[0x77; 32], "tn-fuzz", 1).expect("psk");
    let pro = prologue();
    let local = static_key(0x42);
    for out_len in [0usize, 1, 15, 16, 47, 48] {
        let mut hs = responder(&psk, &pro, &local);
        let mut out = vec![0u8; out_len];
        assert!(
            hs.read_message(&[0x11; 148], &mut out).is_err(),
            "out_len={out_len}",
        );
    }
}

// ---------------------------------------------------------------------------
// 2. Netlink.
// ---------------------------------------------------------------------------

#[test]
fn the_netlink_message_splitter_is_total_and_never_reads_past_the_buffer() {
    use twinvpn_platform_linux::netlink;

    // A well-formed 32-byte RTM_NEWLINK-shaped message, so the corpus has
    // something valid to mutate: len, type, flags, seq, pid, then a body.
    let mut valid = Vec::new();
    valid.extend_from_slice(&32u32.to_ne_bytes());
    valid.extend_from_slice(&16u16.to_ne_bytes());
    valid.extend_from_slice(&0u16.to_ne_bytes());
    valid.extend_from_slice(&1u32.to_ne_bytes());
    valid.extend_from_slice(&0u32.to_ne_bytes());
    valid.extend_from_slice(&[0u8; 16]);
    let mut two = valid.clone();
    two.extend_from_slice(&valid);

    let inputs = corpus(SEED ^ 0x11, ITERATIONS * 4, 2_048, &[valid, two]);
    let report = fuzz("platform_linux::netlink::parse_messages", &inputs, |b| {
        let messages = netlink::parse_messages(b);
        // Rule 10: what the parser returns must be bounded by what the buffer
        // held. A declared length longer than the buffer must stop the walk, not
        // allocate from it.
        let total: usize = messages.iter().map(|m| m.body.len()).sum();
        assert!(
            total <= b.len(),
            "the parser produced {total} B of bodies from a {} B buffer",
            b.len(),
        );
        if messages.is_empty() {
            Outcome::reject("no whole message")
        } else {
            Outcome::accept(format!("{} messages, {total} B", messages.len()))
        }
    });
    assert!(report.reached_accept(), "{report:?}");
    assert!(report.reached_reject(), "{report:?}");
}

#[test]
fn the_netlink_attribute_walker_is_total_over_arbitrary_bodies_and_offsets() {
    use twinvpn_platform_linux::netlink;

    // `offset` is supplied by the caller from a per-message-type table, so it is
    // fuzzed alongside the body rather than fixed at zero.
    let mut valid = Vec::new();
    valid.extend_from_slice(&8u16.to_ne_bytes()); // rta_len
    valid.extend_from_slice(&3u16.to_ne_bytes()); // rta_type
    valid.extend_from_slice(b"eth0");
    let inputs = corpus(SEED ^ 0x12, ITERATIONS * 4, 1_024, &[valid]);
    let report = fuzz("platform_linux::netlink::parse_attrs", &inputs, |b| {
        let mut fingerprint = String::new();
        for offset in [0usize, 1, 4, 16, 1_000, usize::MAX / 2] {
            let attrs = netlink::parse_attrs(b, offset);
            let total: usize = attrs.iter().map(|(_, v)| v.len()).sum();
            assert!(total <= b.len(), "walked past the body at offset {offset}");
            fingerprint.push_str(&format!("{}:{total};", attrs.len()));
        }
        Outcome::accept(fingerprint)
    });
    assert!(report.reached_accept(), "{report:?}");
}

// ---------------------------------------------------------------------------
// 3. `nft --json`, and the resolver restore point.
// ---------------------------------------------------------------------------

#[test]
fn the_nft_state_reader_is_total_over_arbitrary_json() {
    use twinvpn_platform_linux::nft;

    let valid = br#"{"nftables":[{"counter":{"table":"twinvpn","family":"inet","name":"posture_blocked","packets":0,"bytes":0}}]}"#.to_vec();
    let inputs = corpus(SEED ^ 0x21, ITERATIONS * 4, 1_024, &[valid, b"{}".to_vec()]);
    let report =
        fuzz(
            "platform_linux::nft::parse_installed",
            &inputs,
            |b| match core::str::from_utf8(b) {
                Ok(json) => nft::parse_installed(json).map_or_else(
                    || Outcome::reject("not our table"),
                    |installed| Outcome::accept(format!("{installed:?}")),
                ),
                Err(e) => Outcome::reject(format!("{e:?}")),
            },
        );
    assert!(report.reached_reject(), "{report:?}");

    // The positive control, so a corpus that stopped producing parseable JSON
    // would fail rather than pass vacuously.
    let valid = r#"{"nftables":[{"counter":{"table":"twinvpn","family":"inet","name":"posture_blocked","packets":0,"bytes":0}}]}"#;
    let installed = nft::parse_installed(valid).expect("our own table parses");
    assert_eq!(installed.ruleset, twinvpn_platform::Ruleset::Blocked);

    // O-18's fail-safe direction: an unreadable answer is NOT "protected". A
    // parser that returned a default posture here would report a machine as
    // protected on the strength of output it could not read.
    assert!(nft::parse_installed("not json at all").is_none());
    assert!(nft::parse_installed("").is_none());
    assert!(nft::parse_installed(r#"{"nftables":[]}"#).is_none());

    // And a counter of the same name in SOMEBODY ELSE'S table is not ours:
    // reading it would let a third party dictate our reported posture.
    let foreign = r#"{"nftables":[{"counter":{"table":"someone_else","family":"inet","name":"posture_protected","packets":0,"bytes":0}}]}"#;
    assert!(nft::parse_installed(foreign).is_none());
}

#[test]
fn the_resolver_restore_point_decoder_is_total_over_arbitrary_files() {
    use twinvpn_platform_linux::resolver::RestorePoint;

    let valid = RestorePoint {
        path: std::path::PathBuf::from("/etc/resolv.conf"),
        contents: b"nameserver 192.0.2.1\nnameserver 2001:db8::1\n".to_vec(),
        existed: true,
        mode: 0o644,
    };
    let seeds = vec![
        valid.encode(),
        RestorePoint {
            contents: Vec::new(),
            existed: false,
            ..valid.clone()
        }
        .encode(),
    ];
    let inputs = corpus(SEED ^ 0x22, ITERATIONS * 4, 1_024, &seeds);
    let report = fuzz("platform_linux::RestorePoint::decode", &inputs, |b| {
        RestorePoint::decode(b).map_or_else(
            || Outcome::reject("malformed restore point"),
            |rp| Outcome::accept(format!("{rp:?}")),
        )
    });
    assert!(report.reached_accept(), "{report:?}");
    assert!(report.reached_reject(), "{report:?}");

    // Round trip, both families in the preserved contents, because DN-23
    // requires the underlay's configuration to be "preserved exactly" and a
    // decoder that dropped the v6 nameserver would satisfy every other
    // assertion here.
    assert_eq!(RestorePoint::decode(&valid.encode()), Some(valid));
}

// ---------------------------------------------------------------------------
// 4. Reason codes arriving as text.
//
// A peer chooses this string. `ObservedReasonCode::parse` runs on it before
// anything in the diagnostics path knows what it is, and the closed set of
// sixteen domains is what stops a peer inventing a seventeenth.
// ---------------------------------------------------------------------------

#[test]
fn the_reason_code_parser_is_total_and_admits_no_seventeenth_domain() {
    use twinvpn_types::ObservedReasonCode;

    let seeds = vec![
        b"NAT.PUNCH_TIMEOUT".to_vec(),
        b"RELAY.SOMETHING_ADDED_LATER".to_vec(),
        b"AUTH.PAIRING.EXPIRED".to_vec(),
        vec![b'.'; 128],
        vec![b'A'; 128],
    ];
    let inputs = corpus(SEED ^ 0x31, ITERATIONS * 4, 256, &seeds);
    let mut domains = std::collections::BTreeSet::new();
    let report = fuzz(
        "types::ObservedReasonCode::parse",
        &inputs,
        |b| match core::str::from_utf8(b) {
            Ok(text) => outcome_of(&ObservedReasonCode::parse(text)),
            Err(e) => Outcome::reject(format!("{e:?}")),
        },
    );
    assert!(report.reached_accept(), "{report:?}");
    assert!(report.reached_reject(), "{report:?}");

    // The closed set, measured over the whole corpus rather than asserted from
    // the type: a parser that accepted a domain outside the sixteen would be a
    // peer choosing its own namespace.
    for input in &inputs {
        if let Ok(text) = core::str::from_utf8(input) {
            if let Ok(code) = ObservedReasonCode::parse(text) {
                domains.insert(code.domain().as_str());
            }
        }
    }
    assert!(
        domains.len() <= 16,
        "the parser admitted {} domains: {domains:?}",
        domains.len(),
    );
}
