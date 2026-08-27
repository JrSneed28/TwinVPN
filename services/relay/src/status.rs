//! `RELAY_STATUS` — overload is never silent (ADR-0005 §11.5, I6, RQ9).
//!
//! > Whenever the relay throttles, sheds, or drains, it MUST emit
//! > `RELAY_STATUS{reason_code, retry_after_ms, suggested_alternatives[]}` on the
//! > affected flow. **A relay that drops without a status frame is a defect.**
//!
//! ADR-0006 §11.7's third stampede control depends on this frame carrying a
//! *usable* answer: "The device MUST honour `retry_after_ms`, MUST try a
//! suggested alternative before retrying the same relay, and MUST ignore any
//! suggestion absent from the verified map."
//!
//! # The body encoding is proposed, not frozen — stated plainly
//!
//! ADR-0005 §9.1 fixes the 16-byte `RelayFrame` header and assigns
//! `RELAY_STATUS` the type byte `0x15`. It does **not** specify the body, and
//! there is no schema to borrow: ADR-0003 R7 puts zero serialization framework on
//! the B4 packet path, and `contracts/README.md` records that B4's schema artifact
//! is *absent by design*. So a body encoding has to exist and cannot be looked up.
//!
//! The one below is deliberately the smallest thing that satisfies the two ADRs —
//! fixed-width integers, one length-prefixed ASCII code, one length-prefixed list
//! of 8-byte relay ids, no framework, no nesting — and it is **contributed for
//! confirmation by ADR-0005's owner**, not asserted as settled. It is versioned by
//! the frame's own `ver` nibble, so changing it is an ADR-0014 event rather than a
//! silent break.
//!
//! ```text
//!  0                   1                   2                   3
//! +---------------+---------------+-------------------------------+
//! | code_len (u8) | n_alts  (u8)  |        reserved (u16 = 0)     |  4 B
//! +---------------+---------------+-------------------------------+
//! |                   retry_after_ms (u32, big-endian)            |  4 B
//! +---------------------------------------------------------------+
//! |          reason_code, `code_len` bytes of ASCII                |
//! +---------------------------------------------------------------+
//! |          n_alts x 8-byte relay_id                              |
//! +---------------------------------------------------------------+
//! ```
//!
//! The code travels **as a string, never an enum** —
//! `contracts/registry/reason_codes.json` says so in as many words
//! (`carried_on_wire_as: "string, never an enum"`), and stability rule 5 requires
//! a receiver to degrade on an unknown code rather than fail, which an enum
//! makes impossible.

use crate::condition::Condition;
use crate::frame::{FrameType, HEADER_LEN, VERSION};

/// `limits.json`-adjacent bound: a reason code is ≤ 64 bytes by the registry's
/// own format rule, so `code_len` never exceeds it.
pub const MAX_REASON_CODE_BYTES: usize = 64;

/// ADR-0005 §11.5's `suggested_alternatives[]`, bounded.
///
/// Not an ADR number: ADR-0006 §11.5 has devices `BIND` `k = 3` in parallel and
/// §11.7 wants "a usable answer", so three is the number a device can act on.
/// Bounding it at all is `ownership.md` §6 rule 10 — this list is emitted, but the
/// same shape arrives on other paths and an unbounded list is an unbounded write.
pub const MAX_SUGGESTED_ALTERNATIVES: usize = 3;

/// A `RELAY_STATUS` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayStatus {
    /// The registered code, as a string.
    pub reason_code: &'static str,
    /// How long the device should wait before retrying **this** relay.
    pub retry_after_ms: u32,
    /// Relay ids the device may try instead. A **hint**: `relay.proto` is explicit
    /// that a device "MUST NOT bind a relay absent from a verified map", so a
    /// suggestion this relay invents is inert rather than dangerous.
    pub suggested_relay_ids: Vec<[u8; twinvpn_schema::limits::RELAY_ID_BYTES]>,
}

impl RelayStatus {
    /// The status frame for `condition`.
    ///
    /// Every throttle, shed and drain goes through here, so there is one place
    /// where "did we tell the device?" can be answered.
    #[must_use]
    pub fn for_condition(condition: Condition, retry_after_ms: u32) -> Self {
        Self {
            reason_code: condition.reason_code().as_str(),
            retry_after_ms,
            suggested_relay_ids: Vec::new(),
        }
    }

    /// Adds a suggested alternate, up to [`MAX_SUGGESTED_ALTERNATIVES`].
    #[must_use]
    pub fn suggesting(mut self, relay_id: [u8; twinvpn_schema::limits::RELAY_ID_BYTES]) -> Self {
        if self.suggested_relay_ids.len() < MAX_SUGGESTED_ALTERNATIVES
            && !self.suggested_relay_ids.contains(&relay_id)
        {
            self.suggested_relay_ids.push(relay_id);
        }
        self
    }

    /// The body octets.
    #[must_use]
    pub fn encode_body(&self) -> Vec<u8> {
        let code = self.reason_code.as_bytes();
        let code_len = code.len().min(MAX_REASON_CODE_BYTES);
        let alts = &self.suggested_relay_ids[..self
            .suggested_relay_ids
            .len()
            .min(MAX_SUGGESTED_ALTERNATIVES)];

        let mut out =
            Vec::with_capacity(8 + code_len + alts.len() * twinvpn_schema::limits::RELAY_ID_BYTES);
        out.push(u8::try_from(code_len).unwrap_or(0));
        out.push(u8::try_from(alts.len()).unwrap_or(0));
        out.extend_from_slice(&0_u16.to_be_bytes()); // reserved: zero on send
        out.extend_from_slice(&self.retry_after_ms.to_be_bytes());
        out.extend_from_slice(&code[..code_len]);
        for id in alts {
            out.extend_from_slice(id);
        }
        out
    }

    /// The complete datagram: a `RelayFrame` header plus this body.
    ///
    /// `flow_id` is the **affected flow**, so a device with several half-flows on
    /// one leg knows which one is being shed. `auth_tag` comes from the caller,
    /// because only the caller holds `K_leg` — and when no MAC is available the
    /// caller must not send at all, which [`crate::pump`] enforces.
    #[must_use]
    pub fn encode_frame(&self, flow_id: u32, counter_low: u16, auth_tag: [u8; 8]) -> Vec<u8> {
        let body = self.encode_body();
        let mut out = Vec::with_capacity(HEADER_LEN + body.len());
        out.push(FrameType::RelayStatus.to_wire());
        out.push(VERSION << 4);
        out.extend_from_slice(&counter_low.to_be_bytes());
        out.extend_from_slice(&flow_id.to_be_bytes());
        out.extend_from_slice(&auth_tag);
        out.extend_from_slice(&body);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_status_carries_a_registered_code_as_a_string() {
        let s = RelayStatus::for_condition(Condition::RateLimited, 250);
        assert_eq!(s.reason_code, "RELAY.CAPACITY_REJECTED");
        let body = s.encode_body();
        assert_eq!(body[0] as usize, s.reason_code.len());
        assert_eq!(&body[8..8 + s.reason_code.len()], s.reason_code.as_bytes());
        assert_eq!(&body[4..8], &250_u32.to_be_bytes());
    }

    #[test]
    fn every_shed_condition_has_a_status_frame() {
        // ADR-0005 §11.5: "A relay that drops without a status frame is a defect."
        for c in [
            Condition::RateLimited,
            Condition::QuotaExceeded,
            Condition::FlowLimitReached,
            Condition::BindRateLimited,
            Condition::Overloaded,
            Condition::Draining,
            Condition::PairUnmatched,
            Condition::PairCollision,
            Condition::FlowIdleTimeout,
        ] {
            let s = RelayStatus::for_condition(c, 1_000);
            assert!(!s.reason_code.is_empty());
            assert!(s.reason_code.starts_with("RELAY."));
            assert!(s.encode_body().len() >= 8);
        }
    }

    #[test]
    fn the_frame_is_a_sixteen_byte_header_plus_the_body() {
        let s = RelayStatus::for_condition(Condition::Draining, 120_000);
        let f = s.encode_frame(42, 7, [0xAB; 8]);
        assert_eq!(f.len(), HEADER_LEN + s.encode_body().len());
        assert_eq!(f[0], FrameType::RelayStatus.to_wire());
        assert_eq!(f[1] >> 4, VERSION);
        assert_eq!(&f[2..4], &7_u16.to_be_bytes());
        assert_eq!(&f[4..8], &42_u32.to_be_bytes());
        assert_eq!(&f[8..16], &[0xAB; 8]);
    }

    #[test]
    fn suggestions_are_bounded_and_deduplicated() {
        let s = RelayStatus::for_condition(Condition::Overloaded, 0)
            .suggesting([1; 8])
            .suggesting([2; 8])
            .suggesting([3; 8])
            .suggesting([4; 8])
            .suggesting([1; 8]);
        assert_eq!(s.suggested_relay_ids.len(), MAX_SUGGESTED_ALTERNATIVES);
        let body = s.encode_body();
        assert_eq!(body[1] as usize, MAX_SUGGESTED_ALTERNATIVES);
        assert_eq!(
            body.len(),
            8 + s.reason_code.len() + MAX_SUGGESTED_ALTERNATIVES * 8
        );
    }

    #[test]
    fn the_reserved_field_is_zero_on_send() {
        // ADR-0014 forward compatibility: reserved bits are zero on send and
        // ignored on receive.
        let body = RelayStatus::for_condition(Condition::Draining, 0).encode_body();
        assert_eq!(&body[2..4], &[0, 0]);
    }

    #[test]
    fn the_body_carries_no_pair_tag_no_subject_and_no_peer() {
        // O-13: a status frame goes to ONE device about ONE of its own flows. It
        // must not tell that device anything about the other end.
        let s = RelayStatus::for_condition(Condition::RateLimited, 500).suggesting([9; 8]);
        let body = s.encode_body();
        // Exactly: header(8) + code + 8 bytes of relay_id. Nothing else fits.
        assert_eq!(body.len(), 8 + s.reason_code.len() + 8);
    }

    #[test]
    fn a_status_frame_is_never_larger_than_the_data_payload_bound() {
        // It rides the same path, so it obeys the same ceiling.
        let s = RelayStatus::for_condition(Condition::Overloaded, u32::MAX)
            .suggesting([1; 8])
            .suggesting([2; 8])
            .suggesting([3; 8]);
        assert!(s.encode_body().len() <= crate::frame::MAX_DATA_PAYLOAD_BYTES);
    }
}
