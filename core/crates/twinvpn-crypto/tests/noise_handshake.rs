//! End-to-end `Noise_IKpsk2`, and the attacks the composition must refuse.
//!
//! **Authority:** ADR-0001 §7.2, §7.3.1, §7.5, §11 items 1 and 2.

use std::sync::Arc;

use twinvpn_crypto::locked::LockedBytes;
use twinvpn_crypto::noise::{static_public_key, Handshake, HandshakeConfig, Role};
use twinvpn_crypto::prologue::{IdentityBinding, NegotiationBinding, Prologue, TwinnetTag};
use twinvpn_crypto::psk::TwinNetPsk;
use twinvpn_crypto::CryptoError;
use twinvpn_env::virtual_time::VirtualTime;
use twinvpn_env::{Entropy, Env, EnvError, EnvParts, SystemRngSource, WallClockReading};

/// A deterministic, **non-cryptographic** entropy source for tests.
///
/// It is not the platform CSPRNG — reaching for that in a test would be an
/// ADR-0018 CD-3 violation as well as a source of flakiness. A handshake's
/// *correctness* does not depend on its ephemerals being unpredictable, only its
/// forward secrecy does, and that is a property of the production binding rather
/// than of this test.
struct CountingEntropy {
    state: std::sync::Mutex<u64>,
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
    let entropy: Arc<dyn Entropy> = Arc::new(CountingEntropy {
        state: std::sync::Mutex::new(seed),
    });
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
        // X25519 clamping is applied by the implementation; a fixed pattern is
        // a valid scalar.
        dst[0] = seed | 0x01;
    })
    .expect("locked static")
}

fn prologue(trust_epoch: u64, psk_epoch: u64, selection: &[u8]) -> Prologue {
    Prologue::new(
        &IdentityBinding {
            twinnet: TwinnetTag::from_twinnet_id("tn-1"),
            device_id_init: [0x01; 32],
            device_id_resp: [0x02; 32],
            trust_epoch,
            psk_epoch,
            anchor_version: 1,
            delegation_set_digest: [0x03; 32],
        },
        &NegotiationBinding {
            h_initiator: [0x04; 32],
            h_responder: [0x05; 32],
            selection_dcbor: selection.to_vec(),
        },
    )
}

fn psk(epoch: u64, seed: &[u8]) -> TwinNetPsk {
    TwinNetPsk::derive(b"pair-secret", seed, epoch, &[0x01; 32], &[0x02; 32]).expect("psk")
}

/// Runs a full handshake and returns both transport sessions, or the first
/// error either side reported.
#[allow(clippy::type_complexity)]
fn run_handshake(
    init_prologue: &Prologue,
    resp_prologue: &Prologue,
    init_psk: &TwinNetPsk,
    resp_psk: &TwinNetPsk,
    init_static: &LockedBytes,
    resp_static: &LockedBytes,
    responder_public_seen_by_initiator: &[u8; 32],
) -> Result<
    (
        twinvpn_crypto::noise::TransportSession,
        twinvpn_crypto::noise::TransportSession,
    ),
    CryptoError,
> {
    // The initiator needs the responder's static, and the only type that can
    // carry one is `VerifiedTunnelKey`. This test builds one the way production
    // does — through a signed, verified `TunnelKeyBinding` — because there is no
    // other constructor, which is the property under test as much as the
    // handshake is.
    let remote = crate::binding_fixture::verified_tunnel_key(responder_public_seen_by_initiator);

    let env = test_env(1);
    let mut initiator = Handshake::new(
        &env,
        Role::Initiator,
        &HandshakeConfig {
            local_static: init_static,
            remote_static: Some(&remote),
            psk: init_psk,
            prologue: init_prologue,
        },
    )?;
    let mut responder = Handshake::new(
        &test_env(2),
        Role::Responder,
        &HandshakeConfig {
            local_static: resp_static,
            remote_static: None,
            psk: resp_psk,
            prologue: resp_prologue,
        },
    )?;

    let mut buf1 = [0u8; 1024];
    let n = initiator.write_message(&[], &mut buf1)?;
    let mut out = [0u8; 1024];
    responder.read_message(&buf1[..n], &mut out)?;

    let mut buf2 = [0u8; 1024];
    let n = responder.write_message(&[], &mut buf2)?;
    initiator.read_message(&buf2[..n], &mut out)?;

    assert!(initiator.is_finished());
    assert!(responder.is_finished());
    Ok((initiator.into_transport()?, responder.into_transport()?))
}

mod binding_fixture {
    //! Builds a `VerifiedTunnelKey` the only way one can be built: by signing a
    //! `TunnelKeyBinding`, verifying the COSE_Sign1 over its octets, and
    //! verifying the binding. There is no shortcut, and that is the point.

    use p256::ecdsa::signature::Signer;
    use twinvpn_crypto::emit::{encode, int_item, Item, StatementToSign};
    use twinvpn_crypto::{verify_cose_sign1, StatementKind, VerifiedTunnelKey};

    const DEVICE: [u8; 32] = [0x02; 32];
    const IDENTITY: [u8; 32] = [0x12; 32];

    pub fn verified_tunnel_key(tk_pub: &[u8; 32]) -> VerifiedTunnelKey {
        let mut scalar = twinvpn_crypto::sha256(b"responder-ik");
        scalar[0] = 0x01;
        let signing = p256::ecdsa::SigningKey::from_bytes(&scalar.into()).expect("scalar");
        let point = signing.verifying_key().to_sec1_point(false);
        let sec1 = point.as_ref();
        let ik_cose = encode(&Item::Map(vec![
            (Item::Uint(1), Item::Uint(2)),
            (int_item(-1), Item::Uint(1)),
            (int_item(-2), Item::Bytes(sec1[1..33].to_vec())),
            (int_item(-3), Item::Bytes(sec1[33..65].to_vec())),
        ]))
        .expect("ik cose");
        let tk_cose = encode(&Item::Map(vec![
            (Item::Uint(1), Item::Uint(1)),
            (int_item(-1), Item::Uint(4)),
            (int_item(-2), Item::Bytes(tk_pub.to_vec())),
        ]))
        .expect("tk cose");
        let payload = Item::Map(vec![
            (Item::Uint(1), Item::Bytes(DEVICE.to_vec())),
            (Item::Uint(2), Item::Bytes(IDENTITY.to_vec())),
            (Item::Uint(3), Item::Bytes(tk_cose)),
            (Item::Uint(4), Item::Uint(1)),
            (Item::Uint(5), Item::Uint(2_000_000_000_000)),
            (
                Item::Uint(6),
                Item::Array(vec![Item::Text("tk_generation".to_owned())]),
            ),
        ]);
        let unsigned = StatementToSign::new(&payload, -7, None).expect("build");
        let sig: p256::ecdsa::Signature = signing.sign(unsigned.to_be_signed());
        let octets = unsigned.assemble(&sig.to_bytes()).expect("assemble");
        let key = twinvpn_crypto::PublicVerifyingKey::from_cose_key(
            &ik_cose,
            StatementKind::TunnelKeyBinding,
        )
        .expect("verifying key");
        let verified =
            verify_cose_sign1(&octets, StatementKind::TunnelKeyBinding, &key).expect("verify");
        twinvpn_crypto::verify_tunnel_key_binding(&verified, &DEVICE, &IDENTITY).expect("binding")
    }
}

#[test]
fn two_peers_that_agree_complete_the_handshake_and_carry_data() {
    let init_static = static_key(0x11);
    let resp_static = static_key(0x22);
    let resp_pub = static_public_key(&resp_static).expect("public");
    let p = prologue(1, 1, b"\xa0");
    let (mut a, mut b) = run_handshake(
        &p,
        &p,
        &psk(1, b"seed"),
        &psk(1, b"seed"),
        &init_static,
        &resp_static,
        &resp_pub,
    )
    .expect("handshake");

    let mut wire = [0u8; 256];
    let (nonce, n) = a.seal(b"hello", &mut wire).expect("seal");
    let mut plain = [0u8; 256];
    let m = b.open(nonce, &wire[..n], &mut plain).expect("open");
    assert_eq!(&plain[..m], b"hello");

    // And the peer's static is the one the binding named, not merely some key
    // that completed a handshake.
    assert_eq!(a.remote_static(), Some(&resp_pub[..]));
}

/// **Attack test — ADR-0001 §7.5 item 2, the hard revocation lever.** A device
/// still holding a valid static but at the *old* PSK epoch must not be able to
/// complete a handshake with a peer that has advanced. This is what makes
/// revocation cryptographic rather than advisory.
#[test]
fn a_peer_at_a_stale_psk_epoch_cannot_complete_the_handshake() {
    let init_static = static_key(0x11);
    let resp_static = static_key(0x22);
    let resp_pub = static_public_key(&resp_static).expect("public");
    let p = prologue(1, 1, b"\xa0");
    let err = run_handshake(
        &p,
        &p,
        // The revoked device is not a recipient of EpochSeed(2), so it can only
        // present the epoch-1 PSK.
        &psk(1, b"seed-1"),
        &psk(2, b"seed-2"),
        &init_static,
        &resp_static,
        &resp_pub,
    )
    .expect_err("must not complete");
    assert!(matches!(err, CryptoError::HandshakeRejected { .. }));
    assert_eq!(err.reason_code().as_str(), "CRYPTO.HANDSHAKE_REJECTED");
}

/// **Attack test — ADR-0001 §7.3.1.** A prologue mismatch must fail the
/// handshake without producing session keys. Here the two sides disagree on the
/// `trust_epoch`, which is exactly the divergence that occurs when one has
/// learned of a revocation and the other has not.
#[test]
fn a_divergent_trust_epoch_in_the_prologue_fails_the_handshake() {
    let init_static = static_key(0x11);
    let resp_static = static_key(0x22);
    let resp_pub = static_public_key(&resp_static).expect("public");
    let err = run_handshake(
        &prologue(1, 1, b"\xa0"),
        &prologue(2, 1, b"\xa0"),
        &psk(1, b"seed"),
        &psk(1, b"seed"),
        &init_static,
        &resp_static,
        &resp_pub,
    )
    .expect_err("must not complete");
    assert!(matches!(err, CryptoError::HandshakeRejected { .. }));
}

/// **Attack test — ADR-0001 §7.3 D1/D2.** A tampered `Selection` changes
/// `negotiation_hash`, which changes the prologue, which fails the handshake.
/// This is what makes an advertisement "a claim, not a decision".
#[test]
fn a_tampered_negotiation_selection_fails_the_handshake() {
    let init_static = static_key(0x11);
    let resp_static = static_key(0x22);
    let resp_pub = static_public_key(&resp_static).expect("public");
    let err = run_handshake(
        &prologue(1, 1, b"\xa0"),
        &prologue(1, 1, b"\xa1\x01\x02"),
        &psk(1, b"seed"),
        &psk(1, b"seed"),
        &init_static,
        &resp_static,
        &resp_pub,
    )
    .expect_err("must not complete");
    assert!(matches!(err, CryptoError::HandshakeRejected { .. }));
}

/// **Attack test.** A replayed transport frame must be refused after the session
/// is established, and the AEAD must not be spent on an obviously stale
/// counter.
#[test]
fn a_replayed_transport_frame_is_refused() {
    let init_static = static_key(0x11);
    let resp_static = static_key(0x22);
    let resp_pub = static_public_key(&resp_static).expect("public");
    let p = prologue(1, 1, b"\xa0");
    let (mut a, mut b) = run_handshake(
        &p,
        &p,
        &psk(1, b"seed"),
        &psk(1, b"seed"),
        &init_static,
        &resp_static,
        &resp_pub,
    )
    .expect("handshake");

    let mut wire = [0u8; 256];
    let (nonce, n) = a.seal(b"once", &mut wire).expect("seal");
    let mut plain = [0u8; 256];
    b.open(nonce, &wire[..n], &mut plain).expect("first");
    let err = b
        .open(nonce, &wire[..n], &mut plain)
        .expect_err("replay must be refused");
    assert!(matches!(err, CryptoError::ReplayDetected { .. }));
    assert_eq!(err.reason_code().as_str(), "CRYPTO.REPLAY_DETECTED");
}

/// **Attack test.** A forged frame must not advance the replay window: if it
/// did, an attacker could send a burst of forgeries at high counters and lock
/// the real peer out. The window moves only after the AEAD succeeds.
#[test]
fn a_forged_frame_does_not_advance_the_replay_window() {
    let init_static = static_key(0x11);
    let resp_static = static_key(0x22);
    let resp_pub = static_public_key(&resp_static).expect("public");
    let p = prologue(1, 1, b"\xa0");
    let (mut a, mut b) = run_handshake(
        &p,
        &p,
        &psk(1, b"seed"),
        &psk(1, b"seed"),
        &init_static,
        &resp_static,
        &resp_pub,
    )
    .expect("handshake");

    // A forgery at a high counter.
    let forged = [0xffu8; 64];
    let mut plain = [0u8; 256];
    assert!(b.open(500_000, &forged, &mut plain).is_err());

    // The genuine peer's next frame, at a low counter, must still be accepted.
    let mut wire = [0u8; 256];
    let (nonce, n) = a.seal(b"genuine", &mut wire).expect("seal");
    let m = b
        .open(nonce, &wire[..n], &mut plain)
        .expect("genuine frame");
    assert_eq!(&plain[..m], b"genuine");
}

/// ADR-0001 §7.2's parameter string, asserted rather than assumed: this is
/// L-DATA's entire cryptographic identity and there is no negotiation that could
/// change it.
#[test]
fn the_protocol_is_the_wireguard_suite_and_nothing_else() {
    assert_eq!(
        twinvpn_crypto::noise::NOISE_PARAMS,
        "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
    );
    assert_eq!(twinvpn_crypto::noise::PSK_SLOT, 2);
    assert_eq!(
        twinvpn_crypto::noise::REKEY_AFTER_TIME,
        std::time::Duration::from_secs(120)
    );
    assert_eq!(
        twinvpn_crypto::noise::REJECT_AFTER_TIME,
        std::time::Duration::from_secs(180)
    );
    assert_eq!(
        twinvpn_crypto::noise::REKEY_ATTEMPT_TIME,
        std::time::Duration::from_secs(90)
    );
}

/// An initiator with no verified peer static cannot even be constructed, which
/// is the `TunnelKeyBinding` gate expressed as a compile-time shape and checked
/// here at run time for the one case the types cannot express (`None`).
#[test]
fn an_initiator_without_a_verified_peer_static_is_refused() {
    let env = test_env(1);
    let s = static_key(0x11);
    let p = prologue(1, 1, b"\xa0");
    let k = psk(1, b"seed");
    let err = Handshake::new(
        &env,
        Role::Initiator,
        &HandshakeConfig {
            local_static: &s,
            remote_static: None,
            psk: &k,
            prologue: &p,
        },
    )
    .expect_err("must refuse");
    assert!(matches!(err, CryptoError::HandshakeRejected { .. }));
}
