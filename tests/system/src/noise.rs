//! The real `Noise_IKpsk2` fixtures every crossing test handshakes through.
//!
//! **Owner:** `test-engineering`. Never shipped.
//!
//! **Authority:** ADR-0001 §7.2, §7.3 D1/D2, §7.3.1 P-1..P-3, §7.5, §11 items 1
//! and 2; ADR-0007 N-4/N-5; ADR-0014 §11, N-8, N-9; ADR-0018 CD-1, CD-2, CD-3,
//! CD-I2.
//!
//! # The gap this module exists to close
//!
//! `core/crates/twinvpn-core/tests/datapath/support.rs` builds its two facing
//! tunnels on `StubKeys`, which its own header calls "**not cryptography**". It
//! is honest about why: reaching `twinvpn_tunnel::bind::SessionKeys` needs a
//! `VerifiedTunnelKey`, which needs a signed `TunnelKeyBinding`, which needs
//! `twinvpn-crypto`'s `test-support` fixtures — a dev-dependency feature
//! `twinvpn-core`'s manifest does not enable. So the strongest proof that a
//! packet crosses the composed data path ran **through a stub cipher**, and
//! nothing in the repository asserted that a real IP packet crosses between two
//! composed endpoints under real cryptography.
//!
//! This workspace can enable that feature — `tests/Cargo.toml` turns on
//! `twinvpn-crypto/test-support` — so these fixtures produce the production
//! `SessionKeys` and nothing below is a stand-in for a primitive.
//!
//! # What this module is a fixture *for*, and what it is not
//!
//! It builds key material. It asserts almost nothing: the assertions live in
//! `tests/e2e/real_crypto_crossing.rs` and `tests/e2e/real_crypto_relay_leg.rs`.
//! The cryptographic primitives themselves are `twinvpn-crypto`'s and are
//! proven against known vectors there and in
//! `core/crates/twinvpn-tunnel/tests/l_data_binding.rs`; this module only
//! composes them.

use std::sync::{Arc, Mutex};

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
use twinvpn_env::{Entropy, Env, EnvError, WallClockReading};
use twinvpn_tunnel::bind::{NoiseBinding, NoiseTranscript};
use twinvpn_tunnel::crypto::{
    CryptoUnavailable, NoiseHandshake, Prologue, Transcript, TransportKeys,
};

/// The `twinnet_id` every fixture below is bound to.
///
/// One value, because the `TwinnetTag` is part of the 83-byte prologue and two
/// peers that disagree about it do not handshake — which is a property under
/// test elsewhere, not a variable here.
pub const TWINNET: &str = "tn-e2e-crossing";

/// The selection dCBOR both ends advertise, and the two half-advertisement
/// hashes that go with it.
///
/// Fixed rather than negotiated: ADR-0014's negotiation is `twinvpn-session`'s
/// and is tested there. What matters here is that both ends compute the *same*
/// [`NegotiationBinding`], because the resulting hash is what
/// `Tunnel::confirm_negotiation` compares under §7.3 D2.
pub const SELECTION: &[u8] = b"\xa0";

/// The initiator's half-advertisement hash, `H_I`.
pub const H_INITIATOR: [u8; 32] = [0x44; 32];
/// The responder's half-advertisement hash, `H_R`.
pub const H_RESPONDER: [u8; 32] = [0x55; 32];

// ---------------------------------------------------------------------------
// Entropy
// ---------------------------------------------------------------------------

/// A deterministic, **non-cryptographic** entropy source.
///
/// A `Noise_IKpsk2` handshake cannot run on [`twinlab::LabEnv`]'s default
/// `RefusingEntropy` — it needs bytes for its ephemeral — and reaching the
/// platform CSPRNG would be an ADR-0018 CD-3 violation as well as a source of
/// flakiness. This is the same trade
/// `core/crates/twinvpn-tunnel/tests/l_data_binding.rs` makes and for the same
/// reason: a handshake's *correctness* does not depend on unpredictable
/// ephemerals. Only its **forward secrecy** does, and that is a property of the
/// `Env` a production shell injects (W-7 names `Entropy` as a required shell
/// interface), not of anything asserted here.
///
/// `twinlab::CountingEntropy` is deliberately not used: it has no seed
/// parameter, so both ends of a handshake would draw the *same* ephemeral. That
/// still completes a handshake, and a fixture whose two peers are
/// indistinguishable is a fixture that cannot show a bug that swaps them.
pub struct SeededEntropy {
    state: Mutex<u64>,
}

impl SeededEntropy {
    /// A source whose stream is a pure function of `seed`.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            state: Mutex::new(seed),
        }
    }
}

impl Entropy for SeededEntropy {
    fn fill(&self, dst: &mut [u8]) -> Result<(), EnvError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| EnvError::EntropyUnavailable)?;
        for byte in dst.iter_mut() {
            *state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *byte = (*state >> 33) as u8;
        }
        Ok(())
    }
}

/// A deterministic [`twinlab::LabEnv`] whose entropy produces bytes.
///
/// TwinLab's virtual clocks and CD-4 seeded RNG streams are kept — this is the
/// same `Env` every other system test runs on — and only the `Entropy`
/// capability is replaced, for the reason [`SeededEntropy`] states. Every end
/// of every fixture gets its own `seed`, so no two peers share a stream.
#[must_use]
pub fn crypto_env(seed: u8) -> twinlab::LabEnv {
    twinlab::LabEnv::with_entropy(
        twinlab::ScenarioSeed::from_bytes([seed; 16]),
        WallClockReading::Unset,
        Arc::new(SeededEntropy::new(u64::from(seed) | 1)),
    )
}

// ---------------------------------------------------------------------------
// The identity half: a VerifiedTunnelKey, built the only way one can be
// ---------------------------------------------------------------------------

/// A [`VerifiedTunnelKey`] over `tk_pub`, signed and then verified.
///
/// There is no shortcut and that is ADR-0007 N-4/N-5 made structural: a
/// `TunnelKeyBinding` is signed, the COSE_Sign1 is verified over its octets,
/// and the binding is verified against the device and identity it names. This
/// is the step that needs `twinvpn-crypto`'s `test-support` fixtures rather
/// than a `p256` dev-dependency, which CD-I2 would refuse.
///
/// # Panics
///
/// If the fixture identity cannot sign or the statement does not verify — a
/// broken fixture, not a test failure with a diagnosis.
#[must_use]
pub fn verified_tunnel_key(tk_pub: &[u8; 32], tag: u8) -> VerifiedTunnelKey {
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
            .expect("the fixture's COSE key is a verifying key");
    let verified = verify_cose_sign1(&octets, StatementKind::TunnelKeyBinding, &key)
        .expect("the fixture's own signature verifies");
    verify_tunnel_key_binding(&verified, &device, &identity)
        .expect("the binding names the device and identity it was built for")
}

// ---------------------------------------------------------------------------
// The prologue: 83 bytes, in both of the two representations
// ---------------------------------------------------------------------------

/// The same 83 bytes in the two types that spell them.
///
/// `twinvpn_tunnel::crypto::Prologue` and `twinvpn_crypto::prologue::Prologue`
/// are two views of one normative field, and ADR-0001 §7.3.1 P-1 says "no other
/// document may define, extend, or reorder it". Building both from one
/// [`IdentityBinding`]/[`NegotiationBinding`] pair is how a fixture keeps them
/// one field rather than two.
pub struct Bound {
    /// The `twinvpn-crypto` view, which the handshake is constructed against.
    pub crypto: CryptoPrologue,
    /// The `twinvpn-tunnel` view, which each write and read step is checked
    /// against.
    pub tunnel: Prologue,
}

/// The prologue both ends of a fixture handshake agree on.
#[must_use]
pub fn bound(trust_epoch: u64, psk_epoch: u64) -> Bound {
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
        h_initiator: H_INITIATOR,
        h_responder: H_RESPONDER,
        selection_dcbor: SELECTION.to_vec(),
    };
    Bound {
        tunnel: Prologue::new(identity.hash(), negotiation.hash()),
        crypto: CryptoPrologue::new(&identity, &negotiation),
    }
}

/// The negotiation hash both ends confirm on, ADR-0014 §11's formula applied to
/// [`SELECTION`].
///
/// `Tunnel::confirm_negotiation` compares this value on both sides; §7.3 D2
/// makes a mismatch `PROTO.TRANSCRIPT_MISMATCH`, a security event.
#[must_use]
pub fn transcript() -> [u8; 32] {
    NoiseTranscript.negotiation_hash(&H_INITIATOR, &H_RESPONDER, SELECTION)
}

// ---------------------------------------------------------------------------
// A peer, and the handshake between two of them
// ---------------------------------------------------------------------------

/// Everything one end of a handshake owns.
pub struct Peer {
    /// The static X25519 private key.
    pub local: LockedBytes,
    /// The pairwise `TwinNetPSK` filling Noise's `psk2` slot.
    pub psk: TwinNetPsk,
    /// The public half of [`Peer::local`], which the peer pins.
    pub public: [u8; 32],
    /// The tag the peer's `TunnelKeyBinding` fixture is built under.
    pub tag: u8,
}

/// One end, with a static derived from `seed` and a PSK derived from
/// `epoch`/`epoch_seed`.
///
/// `epoch_seed` is the `EpochSeed` a device receives when it is a recipient of a
/// `TwinNetPSK` seal (ADR-0007 §7.7). Two peers handed different seeds are the
/// shape of a device that was **not** a recipient of the current seal, which is
/// ADR-0001 §7.5 item 2's hard revocation lever.
///
/// # Panics
///
/// If the fixture key material is malformed — a broken fixture.
#[must_use]
pub fn peer(seed: u8, tag: u8, epoch: u64, epoch_seed: &[u8; 32]) -> Peer {
    let local = LockedBytes::new_with(32, |dst| {
        dst.fill(seed);
        dst[0] = seed | 0x01;
    })
    .expect("a 32-byte locked static");
    let public = static_public_key(&local).expect("the public half of a valid static");
    Peer {
        local,
        psk: TwinNetPsk::derive(b"pair-secret", epoch_seed, TWINNET, epoch).expect("a PSK"),
        public,
        tag,
    }
}

/// Drives a complete `Noise_IKpsk2` handshake and returns both ends' transport
/// keys.
///
/// The two `Env`s are separate on purpose: each end draws its ephemeral from its
/// own entropy stream, so a defect that let one end's material stand in for the
/// other's would produce two peers that agree with themselves and with nothing
/// else.
///
/// # Errors
///
/// [`CryptoUnavailable`], which is the **only** error this boundary has: ADR-0001
/// §7.3.1 P-3 makes a PSK mismatch, a stale epoch and an unexpected peer
/// indistinguishable to an observer, so they are indistinguishable here too.
///
/// # Panics
///
/// If the two ends complete but disagree on the Noise handshake hash — §7.3 D2's
/// confirmation would then be bound to two different handshakes, which is a
/// defect in the binding rather than a case a caller handles.
#[allow(clippy::type_complexity)]
pub fn handshake(
    initiator_env: &Env,
    responder_env: &Env,
    initiator: &Peer,
    responder: &Peer,
    prologue: &Bound,
) -> Result<(Box<dyn TransportKeys>, Box<dyn TransportKeys>), CryptoUnavailable> {
    let responder_key = verified_tunnel_key(&responder.public, responder.tag);
    let initiator_key = verified_tunnel_key(&initiator.public, initiator.tag);

    let mut init = NoiseBinding::new(
        initiator_env,
        Role::Initiator,
        &HandshakeConfig {
            local_static: &initiator.local,
            remote_static: Some(&responder_key),
            psk: &initiator.psk,
            prologue: &prologue.crypto,
        },
        &responder_key,
    )?;
    let mut resp = NoiseBinding::new(
        responder_env,
        Role::Responder,
        &HandshakeConfig {
            local_static: &responder.local,
            remote_static: None,
            psk: &responder.psk,
            prologue: &prologue.crypto,
        },
        &initiator_key,
    )?;

    let mut message_1 = Vec::new();
    init.write_initiation(&prologue.tunnel, &mut message_1)?;
    let mut message_2 = Vec::new();
    let responder_keys =
        resp.read_initiation_write_response(&prologue.tunnel, &message_1, &mut message_2)?;
    let initiator_keys = init.read_response(&message_2)?;

    assert_eq!(
        init.handshake_hash(),
        resp.handshake_hash(),
        "both ends must agree on the Noise handshake hash, or §7.3 D2's \
         confirmation is bound to two different handshakes"
    );
    assert!(
        init.handshake_hash().is_some(),
        "a completed handshake records its hash (N-9)"
    );
    Ok((initiator_keys, responder_keys))
}
