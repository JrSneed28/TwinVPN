//! **The single most important property in this service, asserted structurally.**
//!
//! *"The relay MUST NEVER be able to decrypt or interpret what it forwards"* —
//! I1, invariant P1, ADR-0005 RQ1 and §7.1, testing-strategy P14.
//!
//! ADR-0005 §7.1 says how to prove it, and it is not a statistical observation:
//!
//! > **P14's oracle becomes an enumeration over a three-element key inventory
//! > rather than a statistical observation over traffic**: dump the relay's
//! > complete key material at any instant, feed the union to the reference L-DATA
//! > decryptor, and assert that no captured frame decrypts.
//!
//! This file is that enumeration, done against the *code* rather than a running
//! process, in four parts. Each is a property a reviewer can check by reading a
//! failing assertion, not by reading the whole crate.
//!
//! | # | Property | How it is checked here |
//! |---|---|---|
//! | 1 | The key inventory is closed at three, and none is an L-DATA key | `the_key_inventory_is_exactly_three_items` reads `crypto.rs` |
//! | 2 | No API in the crate yields plaintext from ciphertext | `no_decrypt_operation_exists_anywhere` greps the public surface |
//! | 3 | The payload type has no decoder | `the_payload_type_has_no_reader` |
//! | 4 | Bytes out equal bytes in, including for protobuf-shaped payloads (W-4) | `the_payload_survives_forwarding_byte_for_byte` |
//!
//! Parts 1 and 2 are **source assertions**. That is deliberate: a decrypt path is
//! something that must not *exist*, and only reading the source can assert
//! absence. A behavioural test can only show that the paths taken today do not
//! decrypt.

use std::path::{Path, PathBuf};

use bytes::Bytes;
use twinvpn_relay::crypto::{IssuerPublicKey, LegKey, RelayCrypto};
use twinvpn_relay::flow::{BindOutcome, PairTable, PairTag};
use twinvpn_relay::forward::Forwarder;
use twinvpn_relay::frame::{RelayFrame, HEADER_LEN};
use twinvpn_relay::RelaySub;

fn src(name: &str) -> String {
    let p: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

fn all_sources() -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("src/ is readable") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "rs") {
            let name = path
                .file_name()
                .expect("file name")
                .to_string_lossy()
                .into_owned();
            out.push((name, std::fs::read_to_string(&path).expect("read")));
        }
    }
    assert!(
        out.len() >= 15,
        "expected the whole module set, found {}",
        out.len()
    );
    out
}

/// Strips `//!` and `///` doc lines and `//` comments, so a *description* of a
/// forbidden thing is not mistaken for the thing.
fn code_only(source: &str) -> String {
    source
        .lines()
        .map(|l| {
            let t = l.trim_start();
            if t.starts_with("//") {
                ""
            } else {
                l
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ===========================================================================
// 1. The key inventory is closed at three, and none of them decrypts L-DATA.
// ===========================================================================

#[test]
fn the_key_inventory_is_exactly_three_items() {
    // ADR-0005 §7.1's table:
    //   - relay static X25519       — not an input to L-DATA's Noise_IKpsk2
    //   - issuer public-key set     — verification-only, public
    //   - per-leg K_leg             — domain-separated; MAC only
    //
    // Only the last two are ever *held as a value* by this crate: the static key
    // is a path in configuration, and nothing here parses it.
    let crypto = src("crypto.rs");
    assert!(crypto.contains("pub struct LegKey"));
    assert!(crypto.contains("pub struct IssuerPublicKey"));

    let cfg = code_only(&src("config.rs"));
    assert!(
        cfg.contains("pub static_key_path: PathBuf"),
        "the relay's own static key is a PATH in configuration"
    );
    assert!(
        !cfg.contains("static_key_bytes") && !cfg.contains("read_to_string(&self.static_key_path)"),
        "this crate must not load the static Noise key into memory — it has no \
         use for it that is not a Noise handshake, which lives behind the \
         RelayCrypto seam"
    );

    // And no fourth key type appears anywhere.
    for (name, source) in all_sources() {
        let code = code_only(&source);
        for forbidden in [
            "SessionKey",
            "TunnelKey",
            "LDataKey",
            "TransportKey",
            "PresharedKey",
            "TwinNetPSK",
            "EpochSeed",
            "PairSecret",
        ] {
            assert!(
                !code.contains(forbidden),
                "{name} names `{forbidden}`: a fourth key would break the closed \
                 three-element inventory ADR-0005 §7.1 depends on"
            );
        }
    }
}

// ===========================================================================
// 2. No API anywhere in this crate turns ciphertext into plaintext.
// ===========================================================================

#[test]
fn no_decrypt_operation_exists_anywhere() {
    // `RelayCrypto` is the ONLY route to a cryptographic operation in this
    // crate, and its method set is closed. If a decrypt ever appears, it appears
    // here first.
    let crypto = code_only(&src("crypto.rs"));
    for method in [
        "fn decrypt",
        "fn open",
        "fn unseal",
        "fn plaintext",
        "fn aead",
    ] {
        assert!(
            !crypto.contains(method),
            "crypto.rs declares `{method}`: I1 forbids the relay any interpretive \
             access to what it forwards, and the trait's SHAPE is half of that \
             argument"
        );
    }
    // The four permitted operations, named so a fifth is a visible edit.
    for method in [
        "fn verify_signature",
        "fn verify_frame_mac",
        "fn frame_mac",
        "fn digest16",
    ] {
        assert!(crypto.contains(method), "crypto.rs lost `{method}`");
    }
    // Counted inside the trait declaration only, so an implementation's methods
    // do not mask a fifth on the trait itself.
    let start = crypto
        .find("pub trait RelayCrypto")
        .expect("the trait is declared in crypto.rs");
    let body = &crypto[start..];
    let end = body.find("\n}\n").expect("the trait declaration is closed");
    let declared = body[..end].matches("    fn ").count();
    assert_eq!(
        declared, 4,
        "RelayCrypto declares {declared} methods; it must declare exactly the \
         four in ADR-0005 §7.1's inventory"
    );

    // And nothing else in the crate reaches for a decryption verb.
    for (name, source) in all_sources() {
        let code = code_only(&source);
        for forbidden in ["decrypt(", "open_in_place", "decrypt_in_place", "unseal("] {
            assert!(
                !code.contains(forbidden),
                "{name} calls `{forbidden}`: the relay has no decryption path"
            );
        }
    }
}

// ===========================================================================
// 3. The payload type has no reader.
// ===========================================================================

#[test]
fn the_payload_type_has_no_reader() {
    let frame = code_only(&src("frame.rs"));
    // `Opaque` is the payload carrier. Its surface is closed.
    for forbidden in [
        "impl std::fmt::Display for Opaque",
        "impl Serialize for Opaque",
        "impl AsRef<[u8]> for Opaque",
        "impl Deref for Opaque",
        "fn decode(",
        "fn parse_payload",
    ] {
        assert!(
            !frame.contains(forbidden),
            "frame.rs provides `{forbidden}` on the payload carrier"
        );
    }

    // And its Debug prints a length, never octets — checked behaviourally.
    let f = RelayFrame::parse(datagram(1, 1, b"SENTINEL-PLAINTEXT-MARKER")).expect("parses");
    let rendered = format!("{:?}", f.payload());
    assert!(!rendered.contains("SENTINEL"));
    assert!(rendered.contains("25 bytes"));

    // The whole frame's Debug too: a `#[derive(Debug)]` on an enclosing type is
    // exactly how a payload reaches a log.
    let whole = format!("{f:?}");
    assert!(
        !whole.contains("SENTINEL"),
        "the frame's Debug rendered its payload"
    );
}

// ===========================================================================
// 4. Bytes out equal bytes in — including for payloads that WOULD decode.
// ===========================================================================

#[test]
fn the_payload_survives_forwarding_byte_for_byte() {
    // W-4's trap: `prost` 0.13 drops unknown fields, so a decode-then-re-encode
    // round trip looks correct until an unknown field is present. The corpus
    // therefore includes bytes that are valid protobuf WITH an unknown field —
    // the case a careless forwarder silently corrupts.
    let corpus: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x00],
        b"plain ascii".to_vec(),
        // valid protobuf: field 1 varint 1, then field 31 (unknown) varint
        vec![0x08, 0x01, 0xF8, 0x01, 0x2A],
        // a WireGuard-shaped L-DATA datagram
        {
            let mut v = vec![4_u8, 0, 0, 0];
            v.extend_from_slice(&0xDEAD_BEEF_u32.to_le_bytes());
            v.extend_from_slice(&42_u64.to_le_bytes());
            v.extend_from_slice(&[0xC3; 96]);
            v
        },
        // high-entropy ciphertext, and every byte value
        (0..=255_u8).collect(),
        vec![0xFF; 1_200],
    ];

    for payload in corpus {
        let (mut table, ingress) = bound_pair();
        let frame = RelayFrame::parse(datagram(ingress, 1, &payload)).expect("parses");
        let out = Forwarder::new(&MacOk)
            .forward(
                &frame,
                &mut table,
                &LegKey::new([1; 32]),
                &LegKey::new([2; 32]),
                0,
            )
            .expect("forwards");

        assert!(
            out.payload_is_verbatim(&payload),
            "a {}-byte payload did not leave byte for byte",
            payload.len()
        );
        assert_eq!(&out.datagram[HEADER_LEN..], &payload[..]);
        assert_eq!(
            out.datagram.len(),
            HEADER_LEN + payload.len(),
            "the relay never pads and never truncates"
        );
    }
}

#[test]
fn forwarding_never_needed_a_key_that_could_decrypt() {
    // A provider that MACs but cannot sign, cannot digest, and — by the trait's
    // shape — cannot decrypt, forwards traffic perfectly. That is the whole
    // point: nothing on the forwarding path wants a decryption capability, so
    // nothing on it can be induced into using one.
    let (mut table, ingress) = bound_pair();
    let payload = vec![0xAB; 512];
    let frame = RelayFrame::parse(datagram(ingress, 1, &payload)).expect("parses");
    let out = Forwarder::new(&MacOk)
        .forward(
            &frame,
            &mut table,
            &LegKey::new([1; 32]),
            &LegKey::new([2; 32]),
            0,
        )
        .expect("forwards");
    assert!(out.payload_is_verbatim(&payload));
}

// --- helpers ---------------------------------------------------------------

struct MacOk;
impl RelayCrypto for MacOk {
    fn verify_signature(&self, _: &IssuerPublicKey, _: &[u8], _: &[u8]) -> bool {
        false
    }
    fn verify_frame_mac(&self, _: &LegKey, _: &[u8], _: [u8; 8]) -> bool {
        true
    }
    fn frame_mac(&self, _: &LegKey, _: &[u8]) -> Option<[u8; 8]> {
        Some([0; 8])
    }
    fn digest16(&self, _: &[u8], _: &[u8]) -> Option<[u8; 16]> {
        None
    }
}

fn datagram(flow: u32, counter: u16, payload: &[u8]) -> Bytes {
    let mut v = vec![0x01, 0x10];
    v.extend_from_slice(&counter.to_be_bytes());
    v.extend_from_slice(&flow.to_be_bytes());
    v.extend_from_slice(&[0xAA; 8]);
    v.extend_from_slice(payload);
    Bytes::from(v)
}

fn bound_pair() -> (PairTable, u32) {
    let mut t = PairTable::new(30_000, 900_000, 1_000);
    let tag = PairTag::from_wire(&[1; 16]).expect("16 bytes");
    let BindOutcome::Pending { flow_id: a } = t.bind(
        tag,
        "[::1]:1".parse().expect("addr"),
        RelaySub::from_verified_claim([1; 16]),
        0,
    ) else {
        panic!("first bind pends");
    };
    let _ = t.bind(
        tag,
        "192.0.2.9:2".parse().expect("addr"),
        RelaySub::from_verified_claim([2; 16]),
        0,
    );
    (t, a.get())
}
