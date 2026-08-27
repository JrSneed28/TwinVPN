//! Derived-preferred binding, and the SPKI → COSE_Key conversion under it.
//!
//! Tested by both halves throughout: a proven claim **displaces** a pinned
//! holder, and a pinned claim **does not** displace a proven one. Either
//! assertion alone passes against an implementation that ignores provenance
//! entirely.
//!
//! The rotation case is the one that would be easiest to get wrong in the safe-
//! looking direction: requiring the derivation would close first-contact
//! impersonation *and* lock out every device that has ever rotated (ADR-0007
//! §11). `a_non_deriving_key_still_binds` is the test that says we did not.

use std::time::{Duration, Instant};

use twinvpn_service_common::binding::{
    spki_to_es256_cose_key, Binding, BindingLimits, ChannelPinned, Claim, DerivedPreferred,
    Provenance, Refusal, SpkiError,
};
use twinvpn_service_common::tls::testkit::TestKey;
use twinvpn_service_common::tls::ChannelIdentity;
use twinvpn_service_common::Component;

type Device = [u8; 32];

/// The fixed 26-byte prefix of a P-256 SPKI. Written out here **independently**
/// of the implementation, so a test oracle that agreed with a wrong constant
/// would have to be wrong the same way twice.
const SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
    0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// Builds a P-256 SPKI carrying the uncompressed point `(x, y)`.
fn spki_of(x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
    let mut v = SPKI_PREFIX.to_vec();
    v.push(0x04);
    v.extend_from_slice(x);
    v.extend_from_slice(y);
    v
}

/// The NIST P-256 generator `G` (SP 800-186 / SEC 2) — a publicly specified
/// point that is genuinely on the curve, so the checked derivation accepts it.
fn generator() -> ([u8; 32], [u8; 32]) {
    let gx: [u8; 32] = [
        0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40,
        0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98,
        0xC2, 0x96,
    ];
    let gy: [u8; 32] = [
        0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E,
        0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF,
        0x51, 0xF5,
    ];
    (gx, gy)
}

/// A `ChannelIdentity` for a freshly minted, real P-256 key — the exact SPKI a
/// rustls peer presents.
fn real_channel() -> (ChannelIdentity, Device) {
    let key = TestKey::generate();
    let channel = ChannelIdentity::new(&key.spki);
    let derived = twinvpn_service_common::binding::derive_device_id_for(&channel)
        .expect("a real P-256 key derives");
    let mut d = [0u8; 32];
    use twinvpn_types::Identifier as _;
    d.copy_from_slice(derived.as_bytes());
    (channel, d)
}

/// A channel identity that cannot derive: not a P-256 SPKI at all.
fn unprovable_channel(n: u8) -> ChannelIdentity {
    ChannelIdentity::new(&[n; 64])
}

// ---------------------------------------------------------------------------
// The conversion
// ---------------------------------------------------------------------------

#[test]
fn the_conversion_produces_the_canonical_identity_cose_key() {
    // The known-answer half. The oracle builds the same COSE_Key from the
    // published generator coordinates through `twinvpn-crypto`'s own encoder,
    // and the two must agree byte for byte — which is what catches a wrong
    // offset, a swapped x/y, or a dropped label.
    use twinvpn_crypto::emit::{encode, int_item, Item};
    let (gx, gy) = generator();

    let expected = encode(&Item::Map(vec![
        (Item::Uint(1), Item::Uint(2)),
        (int_item(-1), Item::Uint(1)),
        (int_item(-2), Item::Bytes(gx.to_vec())),
        (int_item(-3), Item::Bytes(gy.to_vec())),
    ]))
    .expect("oracle encodes");

    let got = spki_to_es256_cose_key(&spki_of(&gx, &gy)).expect("a canonical P-256 SPKI");
    assert_eq!(
        got, expected,
        "the conversion is not the specified encoding"
    );

    // ...and the derivation the whole thing exists to feed accepts it.
    let id = twinvpn_crypto::derive_device_id_checked(&got).expect("checked derivation accepts");
    let oracle = twinvpn_crypto::derive_device_id_checked(&expected).expect("accepts");
    assert_eq!(id, oracle);
}

#[test]
fn swapping_the_coordinates_yields_a_different_name_which_is_why_offsets_matter() {
    // The negative control for the test above: if the oracle and the conversion
    // could disagree and still pass, this would fail.
    let (gx, gy) = generator();
    let right = spki_to_es256_cose_key(&spki_of(&gx, &gy)).expect("ok");
    let swapped = spki_to_es256_cose_key(&spki_of(&gy, &gx)).expect("still well formed");
    assert_ne!(right, swapped);
}

#[test]
fn a_malformed_spki_is_refused_rather_than_converted_into_some_other_name() {
    let (gx, gy) = generator();

    // Too short, too long.
    assert_eq!(spki_to_es256_cose_key(&[]), Err(SpkiError::WrongLength));
    assert_eq!(
        spki_to_es256_cose_key(&[0u8; 90]),
        Err(SpkiError::WrongLength)
    );
    let mut padded = spki_of(&gx, &gy);
    padded.push(0);
    assert_eq!(spki_to_es256_cose_key(&padded), Err(SpkiError::WrongLength));

    // Right length, wrong algorithm identifier — an Ed25519 or RSA key, or a
    // deliberately mangled one.
    let mut wrong_oid = spki_of(&gx, &gy);
    wrong_oid[6] = 0x2B;
    assert_eq!(
        spki_to_es256_cose_key(&wrong_oid),
        Err(SpkiError::NotP256Uncompressed)
    );

    // Right length and prefix, compressed point.
    let mut compressed = spki_of(&gx, &gy);
    compressed[26] = 0x02;
    assert_eq!(
        spki_to_es256_cose_key(&compressed),
        Err(SpkiError::NotP256Uncompressed)
    );
}

#[test]
fn a_point_not_on_the_curve_is_refused_by_the_checked_derivation() {
    // The conversion is a re-encoding and cannot know the point is bogus; the
    // CHECKED derivation is the reason a wrong conversion cannot be hashed into
    // a wrong name. This asserts that second gate is really in the path.
    let bogus = spki_of(&[0x11; 32], &[0x22; 32]);
    assert!(
        spki_to_es256_cose_key(&bogus).is_ok(),
        "a re-encoding of the right shape succeeds"
    );
    let channel = ChannelIdentity::new(&bogus);
    assert!(
        twinvpn_service_common::binding::derive_device_id_for(&channel).is_err(),
        "a coordinate pair that is not a point was hashed into a device name"
    );
}

#[test]
fn a_real_rustls_key_derives() {
    // The shape assumption, checked against a real TLS stack rather than
    // against itself: the SPKI aws-lc-rs produces and rustls presents is the one
    // the conversion expects.
    let key = TestKey::generate();
    assert_eq!(key.spki.len(), 91, "a P-256 SPKI is 91 bytes");
    let channel = ChannelIdentity::new(&key.spki);
    assert!(twinvpn_service_common::binding::derive_device_id_for(&channel).is_ok());
}

#[test]
fn a_derivation_error_carries_no_key_material() {
    let err = twinvpn_service_common::binding::derive_device_id_for(&unprovable_channel(0xAB))
        .expect_err("64 bytes of 0xAB is not an SPKI");
    let rendered = format!("{err} {err:?}");
    assert!(!rendered.contains("171"), "{rendered}");
    assert!(!rendered.contains("ab"), "{rendered}");
}

// ---------------------------------------------------------------------------
// Derived-preferred, both halves
// ---------------------------------------------------------------------------

#[test]
fn a_proven_claim_displaces_a_pinned_holder() {
    // THE ATTACK, and the close. An impostor pins a device_id first; the real
    // device connects, derives to that exact name, and takes it back.
    let mut b: DerivedPreferred<Device> = DerivedPreferred::default();
    let now = Instant::now();
    let (victim_channel, device) = real_channel();
    let impostor = unprovable_channel(9);

    assert_eq!(b.claim(&impostor, device, now), Claim::Accepted);
    assert_eq!(b.provenance_of(&device), Some(Provenance::Pinned));

    assert_eq!(
        b.claim(&victim_channel, device, now),
        Claim::Accepted,
        "the device that can PROVE the name did not get it back"
    );
    assert_eq!(b.provenance_of(&device), Some(Provenance::Proven));
    assert_eq!(b.displacements(), 1);

    // And the impostor is now out: its next claim is refused.
    assert_eq!(
        b.claim(&impostor, device, now),
        Claim::Refused(Refusal::SubjectHeldByAnotherChannel)
    );
}

#[test]
fn a_pinned_claim_does_not_displace_a_proven_holder() {
    // The other half. Without it, the test above passes against an
    // implementation where the LAST claim always wins.
    let mut b: DerivedPreferred<Device> = DerivedPreferred::default();
    let now = Instant::now();
    let (real, device) = real_channel();

    assert_eq!(b.claim(&real, device, now), Claim::Accepted);
    assert_eq!(b.provenance_of(&device), Some(Provenance::Proven));

    for n in 0..4u8 {
        assert_eq!(
            b.claim(&unprovable_channel(n), device, now),
            Claim::Refused(Refusal::SubjectHeldByAnotherChannel),
            "a pinned claim displaced a proven holder"
        );
    }
    assert_eq!(b.provenance_of(&device), Some(Provenance::Proven));
    assert_eq!(b.displacements(), 0);
}

#[test]
fn a_proven_holder_is_not_displaced_by_another_provable_key() {
    // A different real key derives to a different name, so it cannot prove THIS
    // one and gets the ordinary refusal.
    let mut b: DerivedPreferred<Device> = DerivedPreferred::default();
    let now = Instant::now();
    let (real, device) = real_channel();
    let (other, other_device) = real_channel();
    assert_ne!(device, other_device);

    assert_eq!(b.claim(&real, device, now), Claim::Accepted);
    assert_eq!(
        b.claim(&other, device, now),
        Claim::Refused(Refusal::SubjectHeldByAnotherChannel)
    );
}

#[test]
fn a_non_deriving_key_still_binds() {
    // THE ROTATION CASE, and the reason this is derived-PREFERRED. ADR-0007 §11:
    // `device_id` pins the generation-0 key and does not change across rotation,
    // so a rotated device presents a generation-N key that derives to something
    // else. Requiring the derivation would lock it out for ever.
    let mut b: DerivedPreferred<Device> = DerivedPreferred::default();
    let now = Instant::now();
    let rotated = unprovable_channel(7);
    let device = [0x5Au8; 32];

    assert_eq!(
        b.claim(&rotated, device, now),
        Claim::Accepted,
        "a device that cannot derive was locked out"
    );
    assert_eq!(b.provenance_of(&device), Some(Provenance::Pinned));
    assert_eq!(b.unprovable_keys(), 1);

    // It keeps its binding across a reconnect, exactly as pinning always did.
    b.release(&rotated, &device, now);
    assert_eq!(b.claim(&rotated, device, now), Claim::Accepted);
    assert_eq!(
        b.claim(&unprovable_channel(8), device, now),
        Claim::Refused(Refusal::SubjectHeldByAnotherChannel)
    );
}

#[test]
fn a_proven_holder_reclaiming_its_own_subject_is_not_downgraded() {
    let mut b: DerivedPreferred<Device> = DerivedPreferred::default();
    let now = Instant::now();
    let (real, device) = real_channel();

    assert_eq!(b.claim(&real, device, now), Claim::Accepted);
    b.release(&real, &device, now);
    assert_eq!(b.claim(&real, device, now), Claim::Accepted);
    assert_eq!(
        b.provenance_of(&device),
        Some(Provenance::Proven),
        "a device lost its proof by reconnecting"
    );
    assert_eq!(b.displacements(), 0);
}

#[test]
fn a_lapsed_proof_does_not_outlive_its_binding() {
    // The stale-proof case: once a binding lapses, the next claimant must not
    // inherit the proof that belonged to it.
    let mut b: DerivedPreferred<Device> = DerivedPreferred::default();
    let t0 = Instant::now();
    let (real, device) = real_channel();

    assert_eq!(b.claim(&real, device, t0), Claim::Accepted);
    b.release(&real, &device, t0);
    let later = t0 + Duration::from_millis(600_001);

    let squatter = unprovable_channel(3);
    assert_eq!(b.claim(&squatter, device, later), Claim::Accepted);
    assert_eq!(
        b.provenance_of(&device),
        Some(Provenance::Pinned),
        "a pinned claimant inherited a lapsed holder's proof"
    );
    // ...and the real device can still take it back, which is the point.
    assert_eq!(b.claim(&real, device, later), Claim::Accepted);
    assert_eq!(b.provenance_of(&device), Some(Provenance::Proven));
}

#[test]
fn provenance_is_forgotten_when_the_table_forgets_the_subject() {
    let mut b: DerivedPreferred<Device> = DerivedPreferred::default();
    let t0 = Instant::now();
    let (real, device) = real_channel();
    b.claim(&real, device, t0);
    b.release(&real, &device, t0);
    assert_eq!(b.provenance_of(&device), Some(Provenance::Proven));
    b.sweep(t0 + Duration::from_millis(600_001));
    assert_eq!(b.provenance_of(&device), None);
    assert_eq!(b.len(), 0);
}

// ---------------------------------------------------------------------------
// The properties inherited from ChannelPinned must not have been lost
// ---------------------------------------------------------------------------

#[test]
fn the_refusal_still_names_no_device() {
    let mut b: DerivedPreferred<Device> = DerivedPreferred::default();
    let now = Instant::now();
    let (real, device) = real_channel();
    b.claim(&real, device, now);
    let refusal = b
        .claim(&unprovable_channel(2), device, now)
        .refusal()
        .expect("refused");

    let env = refusal.to_error(Component::RendezvousClient).envelope();
    assert_eq!(env.reason_code, "CONTROL.CHANNEL_BINDING_MISMATCH");
    assert!(env.evidence.is_empty(), "the refusal carried evidence");
    let encoded = format!("{env:?}");
    assert!(
        !encoded.contains("90"),
        "the refusal rendered the contested device_id: {encoded}"
    );
}

#[test]
fn the_debug_prints_counts_and_never_a_subject() {
    let mut b: DerivedPreferred<Device> = DerivedPreferred::default();
    let now = Instant::now();
    let (real, device) = real_channel();
    b.claim(&real, device, now);
    let rendered = format!("{b:?}");
    assert!(rendered.contains("bound: 1"), "{rendered}");
    assert!(rendered.contains("proven: 1"), "{rendered}");
    assert!(!rendered.contains(&format!("{}", device[0])), "{rendered}");
}

#[test]
fn a_held_binding_is_still_never_evicted_for_capacity() {
    let mut b: DerivedPreferred<Device> = DerivedPreferred::new(BindingLimits {
        max_bindings: 2,
        ..BindingLimits::default()
    });
    let now = Instant::now();
    b.claim(&unprovable_channel(1), [1u8; 32], now);
    b.claim(&unprovable_channel(2), [2u8; 32], now);
    assert_eq!(
        b.claim(&unprovable_channel(3), [3u8; 32], now),
        Claim::Refused(Refusal::TableAtCapacity)
    );
}

#[test]
fn a_capacity_refusal_is_still_not_a_binding_mismatch() {
    // `rendezvous` counts binding mismatches as a security metric. Counting a
    // full table there would make it lie during a capacity incident.
    assert_eq!(
        Refusal::TableAtCapacity.reason_code(),
        twinvpn_service_common::codes::CONTROL_ADMISSION_DEFERRED
    );
}

#[test]
fn the_pinned_table_is_unchanged_for_a_service_that_cannot_derive() {
    // `DerivedPreferred` delegates; a service binding something that is not a
    // device_id keeps `ChannelPinned` and loses nothing.
    let mut b: ChannelPinned<String> = ChannelPinned::default();
    let now = Instant::now();
    assert_eq!(
        b.claim(&unprovable_channel(1), "relay-sub".to_owned(), now),
        Claim::Accepted
    );
    assert_eq!(
        b.claim(&unprovable_channel(2), "relay-sub".to_owned(), now),
        Claim::Refused(Refusal::SubjectHeldByAnotherChannel)
    );
}
