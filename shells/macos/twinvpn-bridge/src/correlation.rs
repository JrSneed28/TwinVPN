//! The correlation identifier, bounded before it is stored.
//!
//! **Authority:** `docs/implementation/ownership.md` §6 rule 6 (preserve
//! `correlation_id` and `causation_id` across **every** component boundary) and
//! rule 9 (validate every untrusted input against
//! `contracts/registry/limits.json` *before* any allocation proportional to a
//! declared length); ADR-0015 §11.2.
//!
//! # The bound, and the fact that it is a choice
//!
//! `limits.json` has `identifiers.correlation_id_bytes = 16`. That is the width
//! of the **binary** identifier the wire protocols carry, and it is not what
//! arrives here: `Logging.swift`'s `Correlation.wireBytes` sends
//! `Array(UUID().uuidString.utf8)` — the canonical hyphenated **text** of a
//! 16-byte value, which is 36 bytes.
//!
//! Three ways out, and the reasoning for the one taken:
//!
//! - *Reject anything but 16 bytes.* Every call from the shell already written
//!   would fail. The Swift is the authority on the call shape.
//! - *Parse the text back to 16 bytes and keep those.* Then the Rust log prints
//!   a hex form of a chain the Swift log prints as a UUID string, and an
//!   operator correlating the two sides by eye cannot. That defeats the point of
//!   carrying it at all.
//! - **Keep the caller's bytes verbatim and bound the length.** Both sides print
//!   the same characters, and the bound is what rule 9 actually asks for.
//!
//! [`MAX_CORRELATION_BYTES`] is **64**, and it is this domain's choice rather
//! than a registry value: it admits the 36-byte text form with headroom, and 64
//! is the largest identifier bound the registry itself uses
//! (`identifiers.idempotency_key_max_bytes`). The divergence between
//! `correlation_id_bytes = 16` and what the ABI actually carries is reported as
//! a finding, not resolved here.
//!
//! # A gap this type cannot close
//!
//! `causation_id` has **no field in the C ABI**, so rule 6's second half is not
//! satisfied across this hop. `Correlation.causationID` exists on the Swift side
//! and is dropped at the boundary. Reported.

use twinvpn_types::evidence::EvidenceValue;
use twinvpn_types::{codes, Component, Diagnostic};

/// `contracts/registry/limits.json` `identifiers.correlation_id_bytes`.
///
/// Named so the divergence below is visible rather than implied.
pub const REGISTRY_CORRELATION_ID_BYTES: usize = 16;

/// The bound this crate enforces. **This domain's choice** — see the module
/// documentation.
pub const MAX_CORRELATION_BYTES: usize = 64;

/// A bounded correlation identifier.
///
/// Constructed only through [`CorrelationId::validated`], so there is no path by
/// which an unbounded caller-supplied byte string reaches an allocation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CorrelationId {
    bytes: Vec<u8>,
}

impl CorrelationId {
    /// The absent identifier — an empty slice, which the ABI permits.
    ///
    /// A call with no correlation is a call whose chain begins here. That is a
    /// legitimate state (the OS initiated it and there is no parent) and is not
    /// an error.
    #[must_use]
    pub const fn absent() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Validates `bytes` **before** copying them.
    ///
    /// # Errors
    ///
    /// A `PROTO.SIZE_EXCEEDED` diagnostic when the length exceeds
    /// [`MAX_CORRELATION_BYTES`]. Rule 9: "never a truncation, never a pad,
    /// never a silent accept" — so an over-long identifier is refused with its
    /// observed length and its limit as declared evidence, and the call fails
    /// rather than proceeding with half a chain.
    pub fn validated(bytes: &[u8]) -> Result<Self, Diagnostic> {
        // The length check happens against the borrowed slice, BEFORE `to_vec`.
        // Reversing those two lines is exactly the defect rule 9 names.
        if bytes.len() > MAX_CORRELATION_BYTES {
            return Err(Diagnostic::builder(
                codes::PROTO_SIZE_EXCEEDED,
                Component::ManagementInterface,
            )
            .evidence(
                "parser_id",
                EvidenceValue::Text("tvb.correlation".to_owned()),
            )
            .evidence("observed", EvidenceValue::Uint(bytes.len() as u64))
            .evidence("limit", EvidenceValue::Uint(MAX_CORRELATION_BYTES as u64))
            .build());
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Whether no identifier was supplied.
    #[must_use]
    pub fn is_absent(&self) -> bool {
        self.bytes.is_empty()
    }

    /// How many bytes it carries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether it is empty. Present because clippy asks for it beside `len`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The form that goes on a log line.
    ///
    /// The caller's own characters where they are printable ASCII — so an
    /// operator reading the `os_log` line and the `tracing` line sees the same
    /// chain — and lowercase hex otherwise, so a non-text identifier is still
    /// greppable and a control byte cannot reach a log.
    #[must_use]
    pub fn display(&self) -> String {
        if self.bytes.is_empty() {
            return "-".to_owned();
        }
        let printable = self
            .bytes
            .iter()
            .all(|b| b.is_ascii_graphic() || *b == b' ');
        if printable {
            // Valid ASCII graphic bytes are valid UTF-8 by construction.
            String::from_utf8_lossy(&self.bytes).into_owned()
        } else {
            use core::fmt::Write as _;
            let mut hex = String::with_capacity(self.bytes.len() * 2);
            for byte in &self.bytes {
                // Infallible: writing to a `String` cannot fail, and a `?` here
                // would put an error path on a log-formatting function.
                let _ = write!(hex, "{byte:02x}");
            }
            hex
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_uuid_text_the_swift_side_actually_sends_is_accepted() {
        // `Logging.swift`: `Array(UUID().uuidString.utf8)` — 36 bytes.
        let uuid = b"A1B2C3D4-0000-0000-0000-0000000000FF";
        assert_eq!(uuid.len(), 36);
        let id = CorrelationId::validated(uuid).expect("accepted");
        assert_eq!(id.len(), 36);
        assert_eq!(id.display(), "A1B2C3D4-0000-0000-0000-0000000000FF");
    }

    #[test]
    fn the_binary_width_the_registry_names_is_also_accepted() {
        // The day the ABI carries the 16-byte form instead, nothing here changes.
        let raw = [0xABu8; REGISTRY_CORRELATION_ID_BYTES];
        let id = CorrelationId::validated(&raw).expect("accepted");
        assert_eq!(id.len(), 16);
        assert_eq!(id.display(), "ab".repeat(16));
    }

    #[test]
    fn an_absent_identifier_is_a_state_and_not_an_error() {
        let id = CorrelationId::validated(&[]).expect("accepted");
        assert!(id.is_absent());
        assert_eq!(id.display(), "-");
        assert_eq!(CorrelationId::absent(), id);
    }

    #[test]
    fn an_over_long_identifier_is_refused_and_never_truncated() {
        // §6 rule 9: "never a truncation, never a pad, never a silent accept".
        let long = vec![b'x'; MAX_CORRELATION_BYTES + 1];
        let error = CorrelationId::validated(&long).expect_err("refused");
        assert_eq!(error.code().as_str(), "PROTO.SIZE_EXCEEDED");
        // The evidence names what was seen and what was allowed, so a support
        // case does not have to guess which bound fired.
        let doc = crate::envelope::document(&error);
        assert_eq!(doc["evidence"]["observed"], serde_json::json!(65));
        assert_eq!(doc["evidence"]["limit"], serde_json::json!(64));
        assert_eq!(doc["evidence"]["parser_id"], "tvb.correlation");

        // And the boundary itself is accepted.
        assert!(CorrelationId::validated(&[b'x'; MAX_CORRELATION_BYTES]).is_ok());
    }

    #[test]
    fn a_control_byte_never_reaches_a_log_line() {
        let nasty = CorrelationId::validated(b"\x00\x1b[2Jwiped").expect("bounded");
        let shown = nasty.display();
        assert!(
            !shown.contains('\x1b'),
            "an escape sequence reached the log"
        );
        assert!(!shown.contains('\0'));
        // Hex, so it is still greppable.
        assert!(shown.starts_with("001b"));
    }

    #[test]
    fn the_bound_is_wider_than_the_registrys_binary_width_and_says_so() {
        // The divergence is a finding, and the constants sit beside each other
        // so a reader meets it rather than discovering it.
        assert_eq!(REGISTRY_CORRELATION_ID_BYTES, 16);
        assert_eq!(MAX_CORRELATION_BYTES, 64);
        // The 36-byte text form the Swift side actually sends fits in the bound
        // this domain chose and does not fit in the registry's binary width.
        // That IS the divergence, expressed as the thing it breaks.
        assert!(CorrelationId::validated(&[b'x'; 36]).is_ok());
        assert!(
            CorrelationId::validated(&[b'x'; REGISTRY_CORRELATION_ID_BYTES + 1]).is_ok(),
            "a value wider than the registry's binary width still has to be              accepted, because the ABI carries the TEXT form"
        );
    }
}
