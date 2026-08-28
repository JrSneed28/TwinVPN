//! The bridge's log surface — **structurally incapable of carrying a payload**.
//!
//! **Authority:** `docs/implementation/ownership.md` §6 rule 11 ("**Never log**
//! private keys, session keys, raw tunnel payloads, pairing secrets, or
//! authentication tokens. Observability must never capture tunnel payloads") and
//! rule 6 (correlation across every boundary); ADR-0015 §11.4 (the
//! classification ladder).
//!
//! # Why this is a module and not a discipline
//!
//! Rule 11 is the one rule in this crate that a reviewer cannot check by reading
//! call sites, because the dangerous call — `tracing::debug!(?packet)` — looks
//! exactly like the safe one. So the API is built so the dangerous call does not
//! typecheck: **no function here takes a `&[u8]`, a `Vec<u8>`, or anything
//! generic.** A packet's *length* is a `usize` and a family is a `&'static str`;
//! there is no parameter a payload could be passed as.
//!
//! `grep -n "fn " src/log.rs` is the whole review.

use crate::correlation::CorrelationId;

/// The `tracing` target every line in this crate is emitted under.
///
/// One target, so `RUST_LOG=twinvpn.bridge=trace` is the one thing an operator
/// needs and "where does this crate write to the log" has one answer.
pub const TARGET: &str = "twinvpn.bridge";

/// A boundary crossing that succeeded.
pub fn entered(call: &'static str, correlation: &CorrelationId) {
    tracing::debug!(target: TARGET, call, correlation_id = %correlation.display(), "bridge call");
}

/// A boundary crossing that failed, named by its registered code.
///
/// The `reason_code` and nothing else: §4.2 makes the code the user-facing
/// error, and the envelope carries the rest.
pub fn refused(call: &'static str, reason_code: &str, correlation: &CorrelationId) {
    tracing::warn!(
        target: TARGET,
        call,
        reason_code,
        correlation_id = %correlation.display(),
        "bridge call refused"
    );
}

/// A panic caught at the boundary (F-7).
///
/// **`error!`, never `debug!`, and never silent.** ADR-0015 classes
/// `INTERNAL.CORE_PANIC` as `FATAL`/`CRITICAL` and its condition text is
/// explicit that the instance is poisoned — a caught panic that produced no log
/// line would be a defect nobody could find. The panic's own message is
/// deliberately **not** logged: it is arbitrary text from an arbitrary
/// `panic!`, and a formatted secret is exactly what rule 11 forbids.
pub fn panicked(call: &'static str, correlation: &CorrelationId) {
    tracing::error!(
        target: TARGET,
        call,
        reason_code = "INTERNAL.CORE_PANIC",
        correlation_id = %correlation.display(),
        "a panic was caught at the ABI boundary; the instance is poisoned and \
         ENFORCEMENT STAYS INSTALLED"
    );
}

/// One packet crossed the boundary.
///
/// `bytes` is a **length**. There is no parameter on this function that a packet
/// could be passed as, which is rule 11 as a signature rather than as a
/// convention. `family` is `"v4"` or `"v6"` — a product-neutral tag, not an
/// address.
pub fn packet(call: &'static str, family: &'static str, bytes: usize) {
    tracing::trace!(target: TARGET, call, family, bytes, "packet");
}

/// A count of something, for a diagnostic that is not per-packet.
pub fn counted(call: &'static str, what: &'static str, count: u64, correlation: &CorrelationId) {
    tracing::debug!(
        target: TARGET,
        call,
        what,
        count,
        correlation_id = %correlation.display(),
        "bridge counter"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_log_entry_point_takes_a_length_or_a_tag_and_never_bytes() {
        // Rule 11, as a compile-time property. If a future edit added a
        // `payload: &[u8]` parameter to any function in this module, this file's
        // own source would no longer match — which is what the assertion below
        // checks, crudely but effectively.
        let source = include_str!("log.rs");
        // Only the signatures, so the prose above does not trip it.
        for line in source
            .lines()
            .filter(|l| l.trim_start().starts_with("pub fn "))
        {
            for forbidden in ["&[u8]", "Vec<u8>", "impl AsRef<[u8]>", "&[", "u8]"] {
                assert!(
                    !line.contains(forbidden),
                    "a log entry point can take a payload: {line}"
                );
            }
        }
    }

    #[test]
    fn the_lines_carry_the_correlation_the_caller_supplied() {
        // Not observable through `tracing` without a subscriber, so what is
        // checked is that every entry point that has a chain takes one — the
        // parameter cannot be forgotten because it is not optional.
        let id = CorrelationId::validated(b"chain-1").expect("bounded");
        entered("tvb_ext_sleep", &id);
        refused("tvb_ext_sleep", "MGMT.UNAVAILABLE", &id);
        panicked("tvb_ext_sleep", &id);
        counted("tvb_ext_sleep", "events", 3, &id);
        // The per-packet path deliberately has NO correlation parameter: a
        // datapath that wrote a correlated line per packet would make the log the
        // outage. Its rate limiting is the caller's.
        packet("tvb_ext_next_outbound", "v6", 1280);
    }
}
