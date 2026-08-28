//! The B3 parser as a **property**, not a list of examples.
//!
//! `contracts/docs/trust-boundaries.md` §2 says the decode-outcome contract has
//! exactly three outcomes and that "a panic, an abort, a hang, an allocation
//! proportional to a declared length, or a silent accept is a **P1 defect
//! regardless of perceived exploitability**." A defect stated that way is a
//! property over all inputs, and the only honest way to test it is to generate
//! them.

use proptest::prelude::*;
use twinvpn_rendezvous::frame::{self, Frame, Opcode, HEADER_LEN, MAX_BODY_LEN};
use twinvpn_rendezvous::testkit;
use twinvpn_schema::{limits, Reject};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// Outcome 1 or outcome 2, for any byte string whatsoever. Never a panic,
    /// never a hang, never a third thing.
    #[test]
    fn arbitrary_bytes_produce_an_accept_or_a_typed_reject(
        bytes in proptest::collection::vec(any::<u8>(), 0..4096)
    ) {
        match Frame::parse(&bytes) {
            Ok(_) => {}
            Err(r) => {
                // Outcome 2 requires a *specific* PROTO.* code. A bare error is
                // not a reject.
                let code = r.reason_code().as_str().to_owned();
                prop_assert!(
                    code.starts_with("PROTO."),
                    "a reject must carry a PROTO.* code, got {code}"
                );
            }
        }
    }

    /// A header is a pure function of eight bytes and never accepts a
    /// declaration past the cap — the check that must precede every allocation.
    #[test]
    fn a_header_never_admits_a_declaration_past_the_cap(header in any::<[u8; HEADER_LEN]>()) {
        if let Ok((_, declared)) = frame::parse_header(&header) {
            prop_assert!(declared <= MAX_BODY_LEN);
        }
    }

    /// Whatever a well-formed CALL carries, it comes back byte for byte.
    /// This is finding W-4 as a property: the parser has no path that rewrites
    /// a payload, because it has no path that decodes one.
    #[test]
    fn a_well_formed_call_preserves_its_payload_exactly(
        target in any::<[u8; 32]>(),
        len in 2usize..=limits::C4_MAX_BYTES,
    ) {
        let payload = testkit::payload(len);
        let bytes = testkit::call_frame(target, &payload);
        let parsed = Frame::parse(&bytes);
        prop_assert!(parsed.is_ok(), "{:?}", parsed.err());
        if let Ok(Frame::Call { target: t, payload: v }) = parsed {
            prop_assert_eq!(t, target);
            prop_assert_eq!(v.as_bytes(), &payload[..]);
        } else {
            prop_assert!(false, "a CALL parsed as something else");
        }
    }

    /// A truncated frame is refused, never completed with padding and never
    /// accepted short. `trust-boundaries.md` §8: "never a truncation, never a
    /// pad."
    #[test]
    fn any_prefix_of_a_valid_frame_is_refused(
        target in any::<[u8; 32]>(),
        cut in 0usize..(HEADER_LEN + 32 + 64),
    ) {
        let bytes = testkit::call_frame(target, &testkit::payload(64));
        let cut = cut.min(bytes.len().saturating_sub(1));
        prop_assert!(Frame::parse(&bytes[..cut]).is_err());
    }

    /// Any trailing octet is a framing error. A tolerated tail is a place to
    /// smuggle bytes past a length check.
    #[test]
    fn any_suffix_appended_to_a_valid_frame_is_refused(
        target in any::<[u8; 32]>(),
        tail in proptest::collection::vec(any::<u8>(), 1..64),
    ) {
        let mut bytes = testkit::call_frame(target, &testkit::payload(16));
        bytes.extend_from_slice(&tail);
        let unparseable = matches!(Frame::parse(&bytes), Err(Reject::Unparseable { .. }));
        prop_assert!(unparseable, "a trailing octet must be a framing error");
    }

    /// An ATTACH is accepted at exactly one width and at no other, in either
    /// direction.
    #[test]
    fn attach_is_accepted_at_exactly_one_width(len in 0usize..=128) {
        let bytes = frame::encode(Opcode::Attach, &vec![0x5au8; len]);
        let parsed = Frame::parse(&bytes);
        prop_assert_eq!(parsed.is_ok(), len == limits::DEVICE_ID_BYTES);
    }

    /// A declared length larger than the body present is refused, whatever the
    /// two numbers are.
    #[test]
    fn a_declaration_larger_than_the_body_is_always_refused(
        declared in 1u16..=2000,
        present in 0usize..64,
    ) {
        let body = vec![0x08u8; present];
        if usize::from(declared) <= present {
            return Ok(());
        }
        let bytes = testkit::declared_length_frame(Opcode::Call, declared, &body);
        prop_assert!(Frame::parse(&bytes).is_err());
    }

    /// Nesting past the C4 depth cap is refused at every depth above it, and
    /// accepted at every depth at or below it.
    #[test]
    fn the_depth_cap_is_exact(depth in 1usize..=8) {
        let bytes = testkit::call_frame([1u8; 32], &testkit::nested(depth));
        let parsed = Frame::parse(&bytes);
        // The payload sits inside the CALL body, so its own nesting is what the
        // guard counts.
        prop_assert_eq!(
            parsed.is_ok(),
            depth <= limits::C4_MAX_DEPTH,
            "depth {} against a cap of {}",
            depth,
            limits::C4_MAX_DEPTH
        );
    }
}
