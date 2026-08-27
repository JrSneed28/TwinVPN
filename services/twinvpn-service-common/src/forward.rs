//! Forward-verbatim: carrying a message through a hop without losing what this
//! build does not understand.
//!
//! **Authority:** ADR-0003 §11 B1 (unknown fields MUST be **preserved and
//! forwarded**), `contracts/docs/phase1-conflicts.md` CF-2, `core/README.md` §8
//! and `twinvpn-schema`'s measured
//! `unknown_fields_are_dropped_by_prost_0_13`.
//!
//! # The trap this module exists to close
//!
//! `prost` 0.13 **discards unknown fields on decode and cannot re-emit them.**
//! `core-foundation` measured it rather than assuming it. CF-2 states the
//! consequence:
//!
//! > Any language chosen for a component that *forwards* a message it does not
//! > fully understand — the coordination service, the rendezvous, a relay
//! > carrying an opaque `CALL` — must use a runtime with preserve-and-forward.
//!
//! Rust with `prost` is not such a runtime. So the forwarding rule cannot be
//! "use a preserving runtime"; it has to be **"do not decode-then-re-encode"**.
//! Three of the four server domains forward: the control plane relays events it
//! did not author, the rendezvous carries an opaque `CALL` body, and a relay
//! carries a leg it must never interpret. Each rediscovering this independently
//! is the R-31 divergence this crate exists to prevent, and two of the three
//! would rediscover it as a compatibility bug in production rather than as a
//! constraint at design time.
//!
//! # The shape of the fix
//!
//! [`Verbatim`] holds the **exact received octets**. [`Forwarded`] pairs those
//! octets with a decoded *view* used only for inspection — routing, authorising,
//! counting — and forwards the octets, never the view.
//!
//! There is deliberately no `view_mut()` and no `encode()`. The one way to
//! produce different bytes is
//! [`Forwarded::rewrite_dropping_unknown_fields`], whose name is the
//! documentation: calling it is a decision to discard everything this build does
//! not know about, and a reviewer sees it at the call site.
//!
//! This is the same rule `Auth.signed_payload` already states — "the verifier
//! MUST verify over the exact received octets of `signed_payload` and MUST NOT
//! re-serialize" — generalised from one field to any forwarded message.

use bytes::Bytes;
use twinvpn_schema::{depth, Channel, Reject};

/// The exact octets a message arrived as.
///
/// Constructed only through [`Verbatim::from_received`], which applies the
/// channel's byte cap and depth cap **before** anything proportional to a
/// declared length is allocated (`ownership.md` §6 rules 9 and 10). `Bytes` is
/// reference-counted, so forwarding through several hops copies nothing.
#[derive(Clone, PartialEq, Eq)]
pub struct Verbatim {
    bytes: Bytes,
    channel: Channel,
}

impl Verbatim {
    /// Validates and retains `bytes`.
    ///
    /// # Errors
    ///
    /// [`Reject::SizeExceeded`] or [`Reject::DepthExceeded`], each carrying the
    /// `limits.json` bound it violated. Never a truncation, never a pad.
    pub fn from_received(bytes: Bytes, channel: Channel) -> Result<Self, Reject> {
        let limit = channel.max_bytes();
        if bytes.len() > limit {
            return Err(Reject::SizeExceeded {
                parser_id: channel.parser_id(),
                observed: bytes.len(),
                limit,
            });
        }
        depth::check(&bytes, channel)?;
        Ok(Self { bytes, channel })
    }

    /// The octets, unchanged.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The octets, cheaply cloned for the next hop.
    #[must_use]
    pub fn to_bytes(&self) -> Bytes {
        self.bytes.clone()
    }

    /// Consumes the wrapper, yielding the octets.
    #[must_use]
    pub fn into_bytes(self) -> Bytes {
        self.bytes
    }

    /// The channel whose caps were applied.
    #[must_use]
    pub const fn channel(&self) -> Channel {
        self.channel
    }

    /// The length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the message is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl std::fmt::Debug for Verbatim {
    /// Length and channel only.
    ///
    /// The octets of a forwarded message are, by construction, content this
    /// process is not entitled to interpret — a relay's leg is ciphertext (I1),
    /// a rendezvous `CALL` body is opaque. Rendering them would be exactly the
    /// payload capture ADR-0015 O-12 forbids.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Verbatim({} B on {}, <not rendered>)",
            self.bytes.len(),
            self.channel.parser_id()
        )
    }
}

/// A message decoded **for inspection** while its original octets are retained
/// for forwarding.
///
/// ```text
///   received octets ──┬──▶ decode ──▶ view()   inspect: route, authorise, count
///                     └────────────────────────▶ forward()   the ORIGINAL octets
/// ```
#[derive(Clone)]
pub struct Forwarded<M> {
    verbatim: Verbatim,
    view: M,
}

impl<M: prost::Message + Default> Forwarded<M> {
    /// Validates, retains and decodes.
    ///
    /// The caps are applied to the raw octets first, so a hostile declared length
    /// never reaches `prost`.
    ///
    /// # Errors
    ///
    /// [`Reject::SizeExceeded`], [`Reject::DepthExceeded`] or
    /// [`Reject::Unparseable`].
    pub fn decode(bytes: Bytes, channel: Channel) -> Result<Self, Reject> {
        let verbatim = Verbatim::from_received(bytes, channel)?;
        let view = M::decode(verbatim.as_bytes()).map_err(|_| Reject::Unparseable {
            parser_id: channel.parser_id(),
        })?;
        Ok(Self { verbatim, view })
    }

    /// The decoded view.
    ///
    /// **Advisory.** It is missing every field this build does not know about.
    /// Read it to decide *what to do*; never to decide *what to send*.
    #[must_use]
    pub const fn view(&self) -> &M {
        &self.view
    }

    /// The original octets.
    #[must_use]
    pub const fn verbatim(&self) -> &Verbatim {
        &self.verbatim
    }

    /// The octets to put on the next hop: **the ones that arrived**.
    #[must_use]
    pub fn forward(&self) -> Bytes {
        self.verbatim.to_bytes()
    }

    /// Consumes the wrapper, yielding the octets to forward.
    #[must_use]
    pub fn into_forwarded(self) -> Bytes {
        self.verbatim.into_bytes()
    }

    /// Re-encodes after mutating the view, **discarding every field this build
    /// does not understand**.
    ///
    /// The name is the whole point. ADR-0003 §11 B1 requires unknown fields to
    /// be preserved and forwarded; `prost` 0.13 cannot, so a component that
    /// genuinely must alter a message it forwards is choosing to break that
    /// requirement for this message. That is sometimes correct — a control plane
    /// re-authoring an event it owns is not forwarding, it is originating — and
    /// it is never accidental.
    ///
    /// Prefer originating a fresh message over rewriting a received one.
    #[must_use]
    pub fn rewrite_dropping_unknown_fields(mut self, f: impl FnOnce(&mut M)) -> Bytes {
        f(&mut self.view);
        Bytes::from(self.view.encode_to_vec())
    }
}

impl<M> std::fmt::Debug for Forwarded<M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Forwarded")
            .field("verbatim", &self.verbatim)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message as _;
    use twinvpn_schema::v1;

    /// A protobuf key/varint pair for a field number this build does not know.
    fn append_unknown_varint_field(buf: &mut Vec<u8>, field_number: u32, value: u64) {
        let mut tag = u64::from(field_number) << 3; // wire type 0 = varint
        loop {
            let mut byte = u8::try_from(tag & 0x7f).expect("masked");
            tag >>= 7;
            if tag != 0 {
                byte |= 0x80;
            }
            buf.push(byte);
            if tag == 0 {
                break;
            }
        }
        let mut v = value;
        loop {
            let mut byte = u8::try_from(v & 0x7f).expect("masked");
            v >>= 7;
            if v != 0 {
                byte |= 0x80;
            }
            buf.push(byte);
            if v == 0 {
                break;
            }
        }
    }

    /// A `MessageMetadata` plus a field number 1000 that `twinvpn.v1` does not
    /// define — a future peer's additive extension, exactly the case ADR-0003
    /// §11 B1's preserve-and-forward rule exists for.
    fn message_with_an_unknown_field() -> Bytes {
        let known = v1::MessageMetadata {
            proto_version: 1,
            message_id: vec![7u8; 16],
            twinnet_id: "tn-1".to_owned(),
            ..Default::default()
        };
        let mut buf = known.encode_to_vec();
        append_unknown_varint_field(&mut buf, 1000, 42);
        Bytes::from(buf)
    }

    #[test]
    fn the_failing_control_decode_then_re_encode_drops_the_unknown_field() {
        // This half is the reason the other half exists. If this ever starts
        // passing, `prost` gained preserve-and-forward and CF-2's constraint on
        // this crate can be revisited.
        let original = message_with_an_unknown_field();
        let decoded = v1::MessageMetadata::decode(original.clone()).expect("decodes");
        let re_encoded = Bytes::from(decoded.encode_to_vec());

        assert_ne!(
            re_encoded, original,
            "prost 0.13 is expected to DROP unknown fields; if this passes, \
             re-read contracts/docs/phase1-conflicts.md CF-2"
        );
        assert!(
            re_encoded.len() < original.len(),
            "the dropped field should make the re-encoding shorter"
        );
    }

    #[test]
    fn forward_verbatim_preserves_the_unknown_field() {
        let original = message_with_an_unknown_field();
        let f = Forwarded::<v1::MessageMetadata>::decode(
            original.clone(),
            Channel::ControlAndTelemetry,
        )
        .expect("valid");

        // The view is usable for routing decisions...
        assert_eq!(f.view().twinnet_id, "tn-1");
        assert_eq!(f.view().proto_version, 1);

        // ...and what goes on the wire is what arrived, byte for byte.
        assert_eq!(f.forward(), original);
    }

    #[test]
    fn the_two_halves_disagree_which_is_the_whole_finding() {
        let original = message_with_an_unknown_field();
        let re_encoded = Bytes::from(
            v1::MessageMetadata::decode(original.clone())
                .unwrap()
                .encode_to_vec(),
        );
        let forwarded = Forwarded::<v1::MessageMetadata>::decode(
            original.clone(),
            Channel::ControlAndTelemetry,
        )
        .unwrap()
        .forward();

        assert_eq!(forwarded, original);
        assert_ne!(re_encoded, original);
        assert_ne!(forwarded, re_encoded);
    }

    #[test]
    fn the_explicit_rewrite_really_does_drop_it() {
        let original = message_with_an_unknown_field();
        let rewritten = Forwarded::<v1::MessageMetadata>::decode(
            original.clone(),
            Channel::ControlAndTelemetry,
        )
        .unwrap()
        .rewrite_dropping_unknown_fields(|m| m.proto_version = 2);

        assert_ne!(rewritten, original);
        let back = v1::MessageMetadata::decode(rewritten).unwrap();
        assert_eq!(back.proto_version, 2);
    }

    #[test]
    fn an_oversized_message_is_refused_before_any_decode() {
        let big = Bytes::from(vec![0u8; Channel::PeerDatagram.max_bytes() + 1]);
        let e = Verbatim::from_received(big, Channel::PeerDatagram).expect_err("must reject");
        assert!(matches!(
            e,
            Reject::SizeExceeded {
                parser_id: "c4",
                ..
            }
        ));
        assert_eq!(e.reason_code(), twinvpn_types::codes::PROTO_SIZE_EXCEEDED);
    }

    #[test]
    fn c4_gets_the_tighter_bound_because_b3_is_the_hostile_boundary() {
        // limits.json: c4_max_bytes = 1200, c1_c2_c7_max_bytes = 65536.
        let mid = Bytes::from(vec![0u8; 2000]);
        assert!(Verbatim::from_received(mid.clone(), Channel::PeerDatagram).is_err());
        // The same octets are within the control channel's cap; whether they
        // parse is a separate question, which is why this asserts only the cap.
        assert!(mid.len() < Channel::ControlAndTelemetry.max_bytes());
    }

    #[test]
    fn debug_never_renders_the_octets() {
        let v = Verbatim::from_received(
            Bytes::from_static(b"\x08\x01secret-looking-payload"),
            Channel::ControlAndTelemetry,
        );
        // Whether it validates is irrelevant; what matters is that if it does,
        // its Debug carries no content.
        if let Ok(v) = v {
            let d = format!("{v:?}");
            assert!(!d.contains("secret-looking-payload"), "{d}");
            assert!(d.contains("<not rendered>"), "{d}");
        }
    }

    #[test]
    fn forwarding_several_hops_is_still_the_original_octets() {
        let original = message_with_an_unknown_field();
        let mut carried = original.clone();
        for _ in 0..5 {
            carried =
                Forwarded::<v1::MessageMetadata>::decode(carried, Channel::ControlAndTelemetry)
                    .unwrap()
                    .into_forwarded();
        }
        assert_eq!(carried, original);
    }
}
