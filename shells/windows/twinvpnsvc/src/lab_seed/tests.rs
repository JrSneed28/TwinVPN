//! The seed document, parsed on this host.
//!
//! **This host is Linux**, and everything below runs here: the parse is plain
//! Rust and `TunnelKeying::new` is the composed core's own constructor, so the
//! whole of what `lab-seed` decides is checkable without Windows and without a
//! service.
//!
//! What each test would catch:
//!
//! * a field silently defaulted instead of refused — every negative case
//!   asserts the refusal **names the field**, because a lab that started with
//!   half a seed would measure something nobody could name;
//! * the round trip: a fixture generated the way `twinpeer seed` generates one
//!   parses into key material the handshake would accept, so a drift in the
//!   document's shape fails here rather than as a handshake that never
//!   completes in a guest nobody can attach a debugger to.

use super::{Seed, SEED_FILE_VAR};

/// The `twinpeer seed` document, as `design-tunnel-lane.md` specifies it.
///
/// The two device ids are ordered so the GUEST is the initiator (`role_for`
/// gives the lower id `Role::Initiator`), which is the ordering the lane
/// depends on.
fn fixture() -> String {
    document(&[])
}

/// The fixture with `patch`'s `(needle, replacement)` substitutions applied, so
/// a negative case states exactly the one field it corrupted.
fn document(patch: &[(&str, &str)]) -> String {
    let mut text = format!(
        r#"{{
  "twinnet_id": "tn-lab",
  "local": {{
    "device_id": "{guest_id}",
    "static_private": "{guest_static}",
    "overlay_v4": "100.64.1.1",
    "overlay_v6": "fd7c:9e5d:2a10:1::1"
  }},
  "peer": {{
    "device_id": "{peer_id}",
    "static_public": "{peer_static}",
    "overlay_v4": "100.64.1.2",
    "overlay_v6": "fd7c:9e5d:2a10:1::2",
    "endpoint": "10.77.0.1:51820"
  }},
  "psk": {{
    "pair_secret": "{pair_secret}",
    "epoch_seed": "{epoch_seed}",
    "epoch": 1
  }},
  "negotiation": {{
    "h_initiator": "{h_initiator}",
    "h_responder": "{h_responder}",
    "selection_dcbor": "7477696e706565722d6c61622d73656c656374696f6e2d7631"
  }},
  "anchor_version": 1,
  "delegation_set_digest": "{digest}",
  "trust_epoch": 0
}}"#,
        guest_id = hex(0x11),
        guest_static = hex(0x21),
        peer_id = hex(0x99),
        peer_static = hex(0x31),
        pair_secret = hex(0x41),
        epoch_seed = hex(0x51),
        h_initiator = hex(0x61),
        h_responder = hex(0x71),
        digest = hex(0x81),
    );
    for (needle, replacement) in patch {
        assert!(
            text.contains(needle),
            "the fixture no longer contains `{needle}`, so this test is testing nothing"
        );
        text = text.replace(needle, replacement);
    }
    text
}

fn hex(byte: u8) -> String {
    use std::fmt::Write as _;
    (0..32).fold(String::with_capacity(64), |mut out, _| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// The refusal `text` produces.
///
/// `expect_err` is not usable and deliberately so: [`Seed`] holds a
/// `TunnelKeying`, which has no `Debug` because printing one would print key
/// material. A test helper is the smaller price.
fn refusal_for(text: &str, what: &str) -> super::StartupRefusal {
    match Seed::parse(text) {
        Ok(_) => panic!("{what} must be refused, not accepted"),
        Err(refusal) => refusal,
    }
}

#[test]
fn the_generated_fixture_parses_into_key_material() {
    // The round trip: every constructor the handshake needs ran, including
    // `TwinNetPsk::derive`, `testkit::verified_tunnel_key` and
    // `TunnelKeying::new` — which refuses a local static of the wrong width and
    // is therefore the width check as well.
    let seed = Seed::parse(&fixture()).expect("the specified document parses");

    assert_eq!(seed.twinnet.as_str(), "tn-lab");
    assert_eq!(seed.local_device.to_array(), [0x11; 32]);
    assert_eq!(seed.peer_device.to_array(), [0x99; 32]);
    assert!(
        seed.local_device < seed.peer_device,
        "the guest must sort below the peer or it is not the initiator"
    );
    assert_eq!(seed.peer_endpoint.port.get(), 51820);
    assert_eq!(seed.local_overlay.v4.octets(), [100, 64, 1, 1]);
    assert_eq!(seed.peer_overlay.v4.octets(), [100, 64, 1, 2]);
    assert_eq!(seed.peer_overlay.v6.octets()[15], 2);
    // The keying carries the TwinNet it was built for; the prologue binds it.
    assert_eq!(seed.keying.twinnet().as_str(), "tn-lab");
}

#[test]
fn the_variable_width_field_is_decoded_not_copied() {
    // `selection_dcbor` is `det_CBOR(Selection)`: hex of any even length, and
    // the one field in the document that is not 32 bytes. The peer's half must
    // decode to the same octets or the two prologues differ and the handshake
    // fails with no reason a log could show.
    assert_eq!(
        super::hex_bytes("negotiation.selection_dcbor", "7477696e70656572").expect("even-length"),
        b"twinpeer"
    );
    assert!(super::hex_bytes("t", "abc").is_err(), "odd length");
    assert!(super::hex_bytes("t", "ab\u{00e9}").is_err(), "non-ASCII");
}

/// Every malformed field, with the substring the refusal must contain.
///
/// One table rather than nine functions: the property is uniform — the refusal
/// names the field — and a table makes a field that stops being checked visible
/// as a missing row.
#[test]
fn a_malformed_field_refuses_the_start_by_name() {
    let cases: &[(&str, &str, &str)] = &[
        // (what is replaced, with what, the field the refusal must name)
        (
            r#""twinnet_id": "tn-lab""#,
            r#""twinnet_id": """#,
            "twinnet_id",
        ),
        (
            r#""device_id": "1111111111111111111111111111111111111111111111111111111111111111""#,
            r#""device_id": "1111""#,
            "local.device_id",
        ),
        (
            r#""static_private": "2121212121212121212121212121212121212121212121212121212121212121""#,
            r#""static_private": "zz21212121212121212121212121212121212121212121212121212121212121""#,
            "local.static_private",
        ),
        (
            r#""overlay_v4": "100.64.1.1""#,
            r#""overlay_v4": "not-an-address""#,
            "local.overlay_v4",
        ),
        (
            r#""overlay_v6": "fd7c:9e5d:2a10:1::1""#,
            r#""overlay_v6": "100.64.1.1""#,
            "local.overlay_v6",
        ),
        (
            r#""endpoint": "10.77.0.1:51820""#,
            r#""endpoint": "10.77.0.1""#,
            "peer.endpoint",
        ),
        (
            r#""endpoint": "10.77.0.1:51820""#,
            r#""endpoint": "10.77.0.1:0""#,
            "peer.endpoint",
        ),
        (
            r#""epoch_seed": "5151515151515151515151515151515151515151515151515151515151515151""#,
            r#""epoch_seed": "515151""#,
            "psk.epoch_seed",
        ),
        (
            r#""h_responder": "7171717171717171717171717171717171717171717171717171717171717171""#,
            r#""h_responder": "717""#,
            "negotiation.h_responder",
        ),
        (
            r#""delegation_set_digest": "8181818181818181818181818181818181818181818181818181818181818181""#,
            r#""delegation_set_digest": "81""#,
            "delegation_set_digest",
        ),
        (r#""trust_epoch": 0"#, r#""trust_epoch": 3"#, "trust_epoch"),
    ];

    for (needle, replacement, field) in cases {
        let refusal = refusal_for(&document(&[(needle, replacement)]), field);
        assert_eq!(refusal.code, "PLATFORM.ADAPTER_UNAVAILABLE");
        assert!(
            refusal.detail.contains(field),
            "the refusal for `{field}` says `{}` and names no field a lab \
             operator could act on",
            refusal.detail
        );
        assert_eq!(refusal.exit, 71);
    }
}

#[test]
fn a_field_this_build_does_not_understand_is_refused() {
    // `deny_unknown_fields`: a generator half that grew a field is a mismatch
    // between the two ends of one lab, and starting anyway would hide it.
    let text = document(&[(
        r#""anchor_version": 1"#,
        r#""anchor_version": 1, "surprise": 7"#,
    )]);
    let refusal = refusal_for(&text, "an unknown field");
    assert!(
        refusal.detail.contains("surprise"),
        "the refusal must name the field it did not understand: {}",
        refusal.detail
    );
}

#[test]
fn a_truncated_document_is_refused_rather_than_half_applied() {
    let whole = fixture();
    let refusal = refusal_for(&whole[..whole.len() / 2], "half a document");
    assert!(refusal.detail.contains("guest.json"), "{}", refusal.detail);
}

#[test]
fn no_environment_variable_means_no_seeding_and_no_refusal() {
    // The feature is compiled in; the variable is what turns it on. A build
    // that seeded without being asked would be a build whose behaviour depends
    // on a file nobody named.
    assert_eq!(SEED_FILE_VAR, "TWINVPN_LAB_SEED_FILE");
    assert!(
        std::env::var_os(SEED_FILE_VAR).is_none(),
        "this test asserts the unset case and the variable is set in this process"
    );
}

#[test]
fn an_oversized_file_is_refused_before_it_is_read() {
    let path = std::env::temp_dir().join(format!(
        "twinvpn-lab-seed-oversized-{}.json",
        std::process::id()
    ));
    let oversized = usize::try_from(super::MAX_SEED_BYTES + 1).expect("fits on this host");
    std::fs::write(&path, vec![b'x'; oversized]).expect("writes");
    let refusal = super::read_bounded(&path).expect_err("an oversized file is refused");
    std::fs::remove_file(&path).ok();
    assert!(refusal.detail.contains("bounded at"), "{}", refusal.detail);
}
