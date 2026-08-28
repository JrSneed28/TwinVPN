//! The **production** crypto binding: a real `Noise_IKpsk2` handshake, a real
//! sealed record, and the refusals that must have no weaker second path.
//!
//! **Authority:** ADR-0001 §7.2, §7.3 D1/D2, §7.3.1 P-1..P-3, §7.5, §11 items 1
//! and 2; ADR-0014 §11 (`H_X`), N-8, N-9; ADR-0018 CD-I2, CD-2, CD-3.
//!
//! # Why this file exists beside `l_data.rs`
//!
//! `l_data.rs` drives the engine against a stub and proves it never crosses the
//! crypto boundary. That is the right test for the engine and it is *blind to
//! the boundary itself*: a trait with no implementation passes it exactly as
//! well as a trait with a correct one. Everything here runs over
//! [`twinvpn_tunnel::bind`], so the assertions are about cryptography that
//! actually happened.

use std::sync::Mutex;

use twinvpn_crypto::locked::LockedBytes;
use twinvpn_crypto::noise::{static_public_key, HandshakeConfig, Role};
use twinvpn_crypto::prologue::{
    IdentityBinding, NegotiationBinding, Prologue as CryptoPrologue, TwinnetTag,
};
use twinvpn_crypto::psk::TwinNetPsk;
use twinvpn_crypto::{
    verify_cose_sign1, verify_tunnel_key_binding, x25519_cose_key, PublicVerifyingKey,
    StatementKind, VerifiedTunnelKey,
};
use twinvpn_env::virtual_time::VirtualTime;
use twinvpn_env::{
    Entropy, Env, EnvError, EnvParts, MonotonicInstant, SystemRngSource, WallClockReading,
};
use twinvpn_tunnel::bind::{establish_tunnel, NoiseBinding, NoiseTranscript};
use twinvpn_tunnel::crypto::{
    CryptoUnavailable, NoiseHandshake, Prologue, Transcript, TransportKeys,
};
use twinvpn_tunnel::engine::{TunnelError, TunnelState};
use twinvpn_types::{Endpoint, IpAddr, Port, SessionId, TunnelId, V4Addr};

const TWINNET: &str = "tn-binding";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A deterministic, **non-cryptographic** entropy source.
///
/// Not the platform CSPRNG: reaching for that here would be an ADR-0018 CD-3
/// violation as well as a source of flakiness. A handshake's *correctness* does
/// not depend on unpredictable ephemerals — only its forward secrecy does, and
/// that is a property of the `Env` a production caller injects, not of this
/// test.
struct CountingEntropy {
    state: Mutex<u64>,
}

impl Entropy for CountingEntropy {
    fn fill(&self, dst: &mut [u8]) -> Result<(), EnvError> {
        let mut s = self.state.lock().expect("test mutex");
        for b in dst.iter_mut() {
            *s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            *b = (*s >> 33) as u8;
        }
        Ok(())
    }
}

fn test_env(seed: u64) -> Env {
    let vt = VirtualTime::new(WallClockReading::Unset);
    let entropy: std::sync::Arc<dyn Entropy> = std::sync::Arc::new(CountingEntropy {
        state: Mutex::new(seed),
    });
    Env::new(EnvParts {
        monotonic: vt.monotonic(),
        elapsed: vt.elapsed(),
        wall: vt.wall(),
        timer: vt.timer(),
        runtime: vt.runtime(),
        entropy: std::sync::Arc::clone(&entropy),
        rng: std::sync::Arc::new(SystemRngSource::new(entropy)),
    })
}

fn static_key(seed: u8) -> LockedBytes {
    LockedBytes::new_with(32, |dst| {
        dst.fill(seed);
        dst[0] = seed | 0x01;
    })
    .expect("locked static")
}

fn psk(epoch: u64, seed: &[u8; 32]) -> TwinNetPsk {
    TwinNetPsk::derive(b"pair-secret", seed, TWINNET, epoch).expect("psk")
}

/// A `VerifiedTunnelKey`, built the only way one can be: by signing a
/// `TunnelKeyBinding`, verifying the COSE_Sign1 over its octets, and verifying
/// the binding. There is no shortcut, which is ADR-0007 N-4/N-5 made structural
/// — and the reason this test file needs `twinvpn-crypto`'s `test-support`
/// rather than a `p256` dev-dependency CD-I2 would refuse.
fn verified_tunnel_key(tk_pub: &[u8; 32], tag: u8) -> VerifiedTunnelKey {
    use twinvpn_crypto::emit::Item;
    use twinvpn_crypto::testkit::FixtureIdentity;

    let device = [tag; 32];
    let identity = [tag ^ 0xff; 32];
    let signer = FixtureIdentity::from_seed(&[tag; 8]);
    let payload = Item::Map(vec![
        (Item::Uint(1), Item::Bytes(device.to_vec())),
        (Item::Uint(2), Item::Bytes(identity.to_vec())),
        (Item::Uint(3), Item::Bytes(x25519_cose_key(tk_pub))),
        (Item::Uint(4), Item::Uint(1)),
        (Item::Uint(5), Item::Uint(2_000_000_000_000)),
        (
            Item::Uint(6),
            Item::Array(vec![Item::Text("tk_generation".to_owned())]),
        ),
    ]);
    let octets = signer.sign(&payload);
    let key =
        PublicVerifyingKey::from_cose_key(&signer.cose_key(), StatementKind::TunnelKeyBinding)
            .expect("verifying key");
    let verified =
        verify_cose_sign1(&octets, StatementKind::TunnelKeyBinding, &key).expect("cose verifies");
    verify_tunnel_key_binding(&verified, &device, &identity).expect("binding verifies")
}

/// The same 83 bytes in both representations.
///
/// [`twinvpn_tunnel::crypto::Prologue`] and
/// [`twinvpn_crypto::prologue::Prologue`] are two types over one normative
/// field, and P-1 says "no other document may define, extend, or reorder it".
/// Building both from one [`IdentityBinding`]/[`NegotiationBinding`] pair is how
/// this file makes them one field rather than two.
struct Bound {
    crypto: CryptoPrologue,
    tunnel: Prologue,
}

fn bound(trust_epoch: u64, psk_epoch: u64, selection: &[u8]) -> Bound {
    let identity = IdentityBinding {
        twinnet: TwinnetTag::from_twinnet_id(TWINNET),
        device_id_init: [0x11; 32],
        device_id_resp: [0x22; 32],
        trust_epoch,
        psk_epoch,
        anchor_version: 1,
        delegation_set_digest: [0x33; 32],
    };
    let negotiation = NegotiationBinding {
        h_initiator: [0x44; 32],
        h_responder: [0x55; 32],
        selection_dcbor: selection.to_vec(),
    };
    Bound {
        tunnel: Prologue::new(identity.hash(), negotiation.hash()),
        crypto: CryptoPrologue::new(&identity, &negotiation),
    }
}

/// Everything one end of a handshake owns.
struct Peer {
    local: LockedBytes,
    psk: TwinNetPsk,
    public: [u8; 32],
}

fn peer(seed: u8, epoch: u64, epoch_seed: &[u8; 32]) -> Peer {
    let local = static_key(seed);
    let public = static_public_key(&local).expect("public half");
    Peer {
        local,
        psk: psk(epoch, epoch_seed),
        public,
    }
}

#[allow(clippy::type_complexity)]
fn handshake(
    initiator: &Peer,
    responder: &Peer,
    init_prologue: &Bound,
    resp_prologue: &Bound,
) -> Result<(Box<dyn TransportKeys>, Box<dyn TransportKeys>), CryptoUnavailable> {
    let responder_key = verified_tunnel_key(&responder.public, 0x22);
    let initiator_key = verified_tunnel_key(&initiator.public, 0x11);

    let mut init = NoiseBinding::new(
        &test_env(1),
        Role::Initiator,
        &HandshakeConfig {
            local_static: &initiator.local,
            remote_static: Some(&responder_key),
            psk: &initiator.psk,
            prologue: &init_prologue.crypto,
        },
        &responder_key,
    )?;
    let mut resp = NoiseBinding::new(
        &test_env(2),
        Role::Responder,
        &HandshakeConfig {
            local_static: &responder.local,
            remote_static: None,
            psk: &responder.psk,
            prologue: &resp_prologue.crypto,
        },
        &initiator_key,
    )?;

    let mut m1 = Vec::new();
    init.write_initiation(&init_prologue.tunnel, &mut m1)?;
    let mut m2 = Vec::new();
    let resp_keys = resp.read_initiation_write_response(&resp_prologue.tunnel, &m1, &mut m2)?;
    let init_keys = init.read_response(&m2)?;

    assert!(
        init.handshake_hash().is_some(),
        "initiator recorded its hash"
    );
    assert_eq!(
        init.handshake_hash(),
        resp.handshake_hash(),
        "both ends must agree on the Noise handshake hash, or §7.3 D2's \
         confirmation is bound to two different handshakes"
    );
    Ok((init_keys, resp_keys))
}

fn endpoint(last: u8) -> Endpoint {
    Endpoint::new(
        IpAddr::V4(V4Addr::from_octets([203, 0, 113, last])),
        Port::new(51820).expect("port"),
    )
}

// ---------------------------------------------------------------------------
// The handshake completes
// ---------------------------------------------------------------------------

/// The headline: two agreeing peers complete `Noise_IKpsk2` over the production
/// types, with nothing stubbed anywhere in the path.
#[test]
fn a_full_initiator_and_responder_handshake_completes_over_the_production_types() {
    let a = peer(0x41, 1, &[0x5d; 32]);
    let b = peer(0x42, 1, &[0x5d; 32]);
    let p = bound(1, 1, b"\xa0");
    let (init, resp) = handshake(&a, &b, &p, &p).expect("the handshake must complete");
    // Both ends produced usable keys; the seal/open pair below proves they are
    // the *same* keys rather than merely two objects.
    let mut sealed = Vec::new();
    init.seal(0, b"ready", &mut sealed)
        .expect("initiator seals");
    let mut opened = Vec::new();
    resp.open(0, &sealed, &mut opened).expect("responder opens");
    assert_eq!(opened, b"ready");
}

/// A sealed record crosses in both directions and is authenticated, not merely
/// transformed: flipping one byte of the ciphertext must make it unopenable.
#[test]
fn a_sealed_packet_is_opened_by_the_peer_and_a_tampered_one_is_not() {
    let a = peer(0x41, 1, &[0x5d; 32]);
    let b = peer(0x42, 1, &[0x5d; 32]);
    let p = bound(1, 1, b"\xa0");
    let (init, resp) = handshake(&a, &b, &p, &p).expect("handshake");

    let mut sealed = Vec::new();
    init.seal(0, b"initiator to responder", &mut sealed)
        .expect("seal");
    assert_ne!(
        &sealed[..],
        b"initiator to responder",
        "a sealed record must not be its own plaintext"
    );
    let mut opened = Vec::new();
    resp.open(0, &sealed, &mut opened).expect("open");
    assert_eq!(opened, b"initiator to responder");

    // The other direction uses the other key, so it must work independently.
    let mut back = Vec::new();
    resp.seal(0, b"responder to initiator", &mut back)
        .expect("seal back");
    let mut opened_back = Vec::new();
    init.open(0, &back, &mut opened_back).expect("open back");
    assert_eq!(opened_back, b"responder to initiator");

    // **Attack test.** One flipped bit and the AEAD refuses. A failed open is a
    // drop, never a degraded accept.
    let mut tampered = Vec::new();
    init.seal(1, b"tamper me", &mut tampered).expect("seal");
    tampered[0] ^= 0x01;
    let mut nothing = Vec::new();
    assert_eq!(
        resp.open(1, &tampered, &mut nothing),
        Err(CryptoUnavailable)
    );
    assert!(
        nothing.is_empty(),
        "a failed open must leave no plaintext behind for a caller to use"
    );
}

// ---------------------------------------------------------------------------
// The refusals — and there is no weaker second path behind any of them
// ---------------------------------------------------------------------------

/// **Attack test — ADR-0001 §7.5 item 2, the hard revocation lever.** A device
/// holding a valid static but the *wrong* `TwinNetPSK` must not complete a
/// handshake. This is what makes revocation cryptographic rather than advisory,
/// and it is the single most important thing the `psk2` slot buys.
#[test]
fn a_wrong_psk_fails_the_handshake_and_produces_no_keys() {
    let a = peer(0x41, 1, &[0x01; 32]);
    // Same epoch number, different `EpochSeed`: the shape of a device that was
    // not a recipient of the new seal and is presenting stale material.
    let b = peer(0x42, 1, &[0x02; 32]);
    let p = bound(1, 1, b"\xa0");
    assert_eq!(
        handshake(&a, &b, &p, &p).err(),
        Some(CryptoUnavailable),
        "a PSK mismatch must fail the handshake without producing key-derivation \
         output — never a PSK-less retry"
    );

    // And a *stale epoch* is the same refusal, so the two cannot be told apart
    // by an observer: §7.3.1 P-3's indistinguishability.
    let stale = peer(0x42, 2, &[0x02; 32]);
    assert_eq!(handshake(&a, &stale, &p, &p).err(), Some(CryptoUnavailable));
}

/// **Attack test — ADR-0018 CD-I2 / `ownership.md` §6.** A missing or unusable
/// key is [`CryptoUnavailable`] and nothing else. There is no unauthenticated
/// handshake, no PSK-less handshake and no partially built session to fall back
/// to — the binding either exists complete or does not exist.
#[test]
fn a_crypto_unavailable_path_never_downgrades_to_a_weaker_handshake() {
    let b = peer(0x42, 1, &[0x5d; 32]);
    let key = verified_tunnel_key(&b.public, 0x22);
    let p = bound(1, 1, b"\xa0");

    // A local static of the wrong width. `twinvpn-crypto` refuses it, and the
    // refusal arrives here as the one error this boundary has.
    let short = LockedBytes::new_with(16, |dst| dst.fill(0x07)).expect("locked");
    assert!(
        NoiseBinding::new(
            &test_env(3),
            Role::Initiator,
            &HandshakeConfig {
                local_static: &short,
                remote_static: Some(&key),
                psk: &b.psk,
                prologue: &p.crypto,
            },
            &key,
        )
        .is_err(),
        "a key that cannot be used must not yield a binding that works anyway"
    );

    // The initiator's *pinned* static and its *expected* static must be the same
    // value. Pinning one key and checking another is the confused-deputy shape
    // this constructor exists to make unrepresentable.
    let other = peer(0x43, 1, &[0x5d; 32]);
    let other_key = verified_tunnel_key(&other.public, 0x43);
    assert!(NoiseBinding::new(
        &test_env(4),
        Role::Initiator,
        &HandshakeConfig {
            local_static: &b.local,
            remote_static: Some(&key),
            psk: &b.psk,
            prologue: &p.crypto,
        },
        &other_key,
    )
    .is_err());

    // A responder asked to write an initiation, and an initiator asked to answer
    // one, are both refused — a role is not a hint.
    let mut responder = NoiseBinding::new(
        &test_env(5),
        Role::Responder,
        &HandshakeConfig {
            local_static: &b.local,
            remote_static: None,
            psk: &b.psk,
            prologue: &p.crypto,
        },
        &key,
    )
    .expect("responder binding");
    let mut out = Vec::new();
    assert_eq!(
        responder.write_initiation(&p.tunnel, &mut out),
        Err(CryptoUnavailable)
    );
    assert!(out.is_empty(), "a refused write must emit nothing");
    assert!(responder.read_response(&[0u8; 48]).is_err());
}

/// **Attack test — §7.3.1 P-1.** The 83 bytes a caller passes at each step must
/// be the 83 bytes the binding was built with. Two constructions of one
/// normative field that disagree are a handshake that does not happen, not a
/// handshake against whichever copy was handier.
#[test]
fn a_disagreeing_prologue_refuses_the_handshake() {
    let a = peer(0x41, 1, &[0x5d; 32]);
    let b = peer(0x42, 1, &[0x5d; 32]);
    let built = bound(1, 1, b"\xa0");
    let key = verified_tunnel_key(&b.public, 0x22);

    let mut init = NoiseBinding::new(
        &test_env(6),
        Role::Initiator,
        &HandshakeConfig {
            local_static: &a.local,
            remote_static: Some(&key),
            psk: &a.psk,
            prologue: &built.crypto,
        },
        &key,
    )
    .expect("binding");

    // A different `trust_epoch` — the divergence that occurs when one end has
    // learned of a revocation and the other has not.
    let divergent = bound(2, 1, b"\xa0");
    let mut out = Vec::new();
    assert_eq!(
        init.write_initiation(&divergent.tunnel, &mut out),
        Err(CryptoUnavailable)
    );
    assert!(out.is_empty());
    // The binding is still usable with the right prologue: a refusal is not a
    // teardown, and P-3 wants a mismatch to look like nothing happened.
    assert!(init.write_initiation(&built.tunnel, &mut out).is_ok());
    assert!(!out.is_empty());
}

/// **Attack test — ADR-0007 N-4/N-5.** A responder must refuse a peer whose
/// static is not the one a verified `TunnelKeyBinding` named, **before** it
/// writes a response. `IK` proves the peer holds *a* static; the binding is what
/// proves that static belongs to that identity, and neither alone is enough.
#[test]
fn a_responder_refuses_a_peer_that_is_not_its_verified_tunnel_key() {
    let a = peer(0x41, 1, &[0x5d; 32]);
    let b = peer(0x42, 1, &[0x5d; 32]);
    let impostor = peer(0x44, 1, &[0x5d; 32]);
    let p = bound(1, 1, b"\xa0");

    let b_key = verified_tunnel_key(&b.public, 0x22);
    // The responder expects `impostor`, and `a` is the one that calls.
    let expected = verified_tunnel_key(&impostor.public, 0x44);

    let mut init = NoiseBinding::new(
        &test_env(7),
        Role::Initiator,
        &HandshakeConfig {
            local_static: &a.local,
            remote_static: Some(&b_key),
            psk: &a.psk,
            prologue: &p.crypto,
        },
        &b_key,
    )
    .expect("initiator");
    let mut resp = NoiseBinding::new(
        &test_env(8),
        Role::Responder,
        &HandshakeConfig {
            local_static: &b.local,
            remote_static: None,
            psk: &b.psk,
            prologue: &p.crypto,
        },
        &expected,
    )
    .expect("responder");

    let mut m1 = Vec::new();
    init.write_initiation(&p.tunnel, &mut m1).expect("initiate");
    let mut m2 = Vec::new();
    assert_eq!(
        resp.read_initiation_write_response(&p.tunnel, &m1, &mut m2)
            .err(),
        Some(CryptoUnavailable)
    );
    assert!(
        m2.is_empty(),
        "§7.2's silence on unauthenticated input: an unexpected peer gets no \
         response it can measure"
    );
    assert!(resp.handshake_hash().is_none(), "no state was written");
}

/// An over-long or truncated message is refused before the allocation it would
/// drive — `ownership.md` §6 rules 9 and 10.
#[test]
fn untrusted_lengths_are_bounded_before_any_allocation() {
    let a = peer(0x41, 1, &[0x5d; 32]);
    let b = peer(0x42, 1, &[0x5d; 32]);
    let p = bound(1, 1, b"\xa0");
    let (init, resp) = handshake(&a, &b, &p, &p).expect("handshake");

    let mut out = Vec::new();
    // Shorter than the AEAD tag: it cannot be a record, and the length
    // arithmetic must refuse rather than underflow.
    for len in 0..twinvpn_tunnel::bind::AEAD_TAG_BYTES {
        assert_eq!(
            resp.open(0, &vec![0u8; len], &mut out),
            Err(CryptoUnavailable)
        );
    }
    // Past Noise's own 65535-byte ceiling, in both directions.
    let oversize = vec![0u8; twinvpn_tunnel::bind::NOISE_MAX_MESSAGE_BYTES + 1];
    assert_eq!(resp.open(0, &oversize, &mut out), Err(CryptoUnavailable));
    assert_eq!(init.seal(0, &oversize, &mut out), Err(CryptoUnavailable));
}

/// The engine owns the send counter; the session issues the nonce. They are in
/// lockstep, and a divergence is a **refusal** rather than a record sealed under
/// the wrong nonce — which under a stream cipher is the worst outcome available.
#[test]
fn seal_refuses_a_counter_that_is_not_the_sessions_next_nonce() {
    let a = peer(0x41, 1, &[0x5d; 32]);
    let b = peer(0x42, 1, &[0x5d; 32]);
    let p = bound(1, 1, b"\xa0");
    let (init, _resp) = handshake(&a, &b, &p, &p).expect("handshake");

    let mut out = Vec::new();
    assert_eq!(
        init.seal(1, b"skipped ahead", &mut out),
        Err(CryptoUnavailable)
    );
    // And the refusal consumed nothing: counter 0 is still the next one.
    init.seal(0, b"in step", &mut out).expect("seal at 0");
    assert_eq!(init.seal(0, b"replayed", &mut out), Err(CryptoUnavailable));
    init.seal(1, b"in step", &mut out).expect("seal at 1");
}

/// §7.2's `REJECT_AFTER_TIME`: "keys are unusable and are **zeroed**". After
/// [`TransportKeys::zeroize`] there is nothing left to seal or open with.
#[test]
fn zeroized_keys_refuse_every_operation() {
    let a = peer(0x41, 1, &[0x5d; 32]);
    let b = peer(0x42, 1, &[0x5d; 32]);
    let p = bound(1, 1, b"\xa0");
    let (mut init, resp) = handshake(&a, &b, &p, &p).expect("handshake");

    let mut sealed = Vec::new();
    init.seal(0, b"before", &mut sealed).expect("seal");
    init.zeroize();
    let mut out = Vec::new();
    assert_eq!(init.seal(1, b"after", &mut out), Err(CryptoUnavailable));
    assert_eq!(init.open(0, &sealed, &mut out), Err(CryptoUnavailable));
    // Zeroizing one end does not disturb the other.
    let mut opened = Vec::new();
    resp.open(0, &sealed, &mut opened)
        .expect("peer still works");
    assert_eq!(opened, b"before");
}

// ---------------------------------------------------------------------------
// The transcript
// ---------------------------------------------------------------------------

/// ADR-0014 §11: `H_X = SHA-256("TWINVPN-NEG-HALF-v1" || det_CBOR(...))`, and
/// the label is part of the formula rather than decoration — two hashes over the
/// same bytes under different labels must differ.
#[test]
fn the_half_advertisement_hash_is_adr_0014s_formula() {
    let t = NoiseTranscript;
    let a = t.half_advertisement_hash(b"\xa0");
    assert_eq!(
        a,
        twinvpn_crypto::kdf::sha256_parts(&[b"TWINVPN-NEG-HALF-v1", b"\xa0"])
    );
    assert_ne!(a, twinvpn_crypto::sha256(b"\xa0"), "the label is bound in");
    assert_ne!(a, t.half_advertisement_hash(b"\xa1\x01\x02"));
}

/// The negotiation hash is computed here from a borrowed slice rather than
/// through `NegotiationBinding`, so that nothing an untrusted input sizes gets
/// allocated by a function with no error channel. This pins the two against each
/// other, so the field ordering cannot drift apart.
#[test]
fn the_negotiation_hash_agrees_with_twinvpn_cryptos_own() {
    let h_i = [0x44; 32];
    let h_r = [0x55; 32];
    let selection = b"\xa1\x01\x02";
    assert_eq!(
        NoiseTranscript.negotiation_hash(&h_i, &h_r, selection),
        NegotiationBinding {
            h_initiator: h_i,
            h_responder: h_r,
            selection_dcbor: selection.to_vec(),
        }
        .hash()
    );
    // And it is the value that goes into the prologue's second half, which is
    // what makes D1's "advertisements are claims" enforceable at all.
    let b = bound(1, 1, selection);
    assert_eq!(
        &b.tunnel.as_bytes()[51..83],
        &NoiseTranscript.negotiation_hash(&h_i, &h_r, selection)
    );
}

// ---------------------------------------------------------------------------
// The path from a completed handshake to a live tunnel
// ---------------------------------------------------------------------------

/// The blocker this module closes, end to end: two peers handshake, get real
/// tunnels, confirm the negotiation, and carry a packet — with `Tunnel::absent`
/// nowhere in the path except as the private starting point the constructor
/// walks past.
#[test]
fn two_established_tunnels_carry_a_packet_over_the_production_binding() {
    let a = peer(0x41, 1, &[0x5d; 32]);
    let b = peer(0x42, 1, &[0x5d; 32]);
    let p = bound(1, 1, b"\xa0");
    let (init_keys, resp_keys) = handshake(&a, &b, &p, &p).expect("handshake");
    let now = MonotonicInstant::ORIGIN;

    let mut left = establish_tunnel(
        TunnelId::from_array([1; 16]),
        SessionId::from_array([2; 16]),
        init_keys,
        endpoint(1),
        1,
        now,
    );
    let mut right = establish_tunnel(
        TunnelId::from_array([3; 16]),
        SessionId::from_array([4; 16]),
        resp_keys,
        endpoint(2),
        1,
        now,
    );

    // N-8/N-9: keys exist, but nothing carries traffic until the transcript
    // matches. The gap is a named state, not an implicit one.
    assert_eq!(left.state(), TunnelState::Confirming);
    assert!(!left.state().carries_traffic());
    let mut refused = Vec::new();
    assert_eq!(
        left.seal(b"too early", &mut refused),
        Err(TunnelError::NotEstablished)
    );

    let ours = NoiseTranscript.negotiation_hash(&[0x44; 32], &[0x55; 32], b"\xa0");
    left.confirm_negotiation(&ours, &ours).expect("confirm");
    right.confirm_negotiation(&ours, &ours).expect("confirm");
    assert_eq!(left.state(), TunnelState::Established);

    let mut wire = Vec::new();
    let counter = left.seal(b"a real packet", &mut wire).expect("seal");
    assert_eq!(counter, 0, "unmodified WireGuard's first transport nonce");
    let mut plain = Vec::new();
    right.open(counter, &wire, &mut plain).expect("open");
    assert_eq!(plain, b"a real packet");

    // W-31's regression, now over real cryptography: the first record of every
    // tunnel is counter 0, and replaying it is `CRYPTO.REPLAY_DETECTED` —
    // `FATAL` — not the weaker "authentication failed" a doubled replay window
    // would have produced.
    let mut again = Vec::new();
    assert_eq!(
        right.open(counter, &wire, &mut again),
        Err(TunnelError::Replay)
    );
}

/// §7.3 D2: a `NegotiationConfirm` that does not match is
/// `PROTO.TRANSCRIPT_MISMATCH` — "a **security event**, not a network error" —
/// so the tunnel closes and the real keys are zeroized rather than left live
/// behind a state flag.
#[test]
fn a_transcript_mismatch_closes_the_tunnel_and_zeroizes_real_keys() {
    let a = peer(0x45, 1, &[0x5d; 32]);
    let b = peer(0x46, 1, &[0x5d; 32]);
    let p = bound(1, 1, b"\xa0");
    let (init_keys, _resp_keys) = handshake(&a, &b, &p, &p).expect("handshake");

    let mut tunnel = establish_tunnel(
        TunnelId::from_array([5; 16]),
        SessionId::from_array([6; 16]),
        init_keys,
        endpoint(3),
        1,
        MonotonicInstant::ORIGIN,
    );
    let ours = NoiseTranscript.negotiation_hash(&[0x44; 32], &[0x55; 32], b"\xa0");
    let mut theirs = ours;
    theirs[0] ^= 0x01;
    assert_eq!(
        tunnel.confirm_negotiation(&ours, &theirs),
        Err(TunnelError::TranscriptMismatch)
    );
    assert_eq!(tunnel.state(), TunnelState::Closed);
    let mut out = Vec::new();
    assert_eq!(
        tunnel.seal(b"after the teardown", &mut out),
        Err(TunnelError::NotEstablished)
    );
}
