//! `relay_sub` — the only subject a relay ever knows, and how it reaches a log.
//!
//! ADR-0005 §11.3: `sub` is
//! `HKDF-Expand(HKDF-Extract("", DeviceIdentityPub), "twinvpn/relay-sub/v1" ‖
//! operator_group_id ‖ epoch_day, 16)` — a **per-operator, per-day pseudonym,
//! never `device_id`**. The relay receives it inside a verified token; it never
//! derives it and cannot invert it.
//!
//! §7.2 states the residual honestly: *within one operator group and one day the
//! relay CAN link all of a device's flows*. That is structurally required, because
//! quota enforcement needs a stable subject (§13). What §10 then requires is that
//! the **logs** cannot: "logs carry aggregated counters keyed by a *daily re-hash*
//! of `relay_sub`, so operational logs cannot link a device across days."
//!
//! [`RelaySub`] is the in-memory quota key. [`LogSubject`] is the daily re-hash,
//! and it is the **only** form that may be rendered. `RelaySub` has no `Display`
//! and a redacted `Debug`, so the raw pseudonym has no path to a log line.

use twinvpn_service_common::redact::hex_lower;

use crate::crypto::RelayCrypto;

/// The 16-byte per-operator, per-day pseudonym from a verified token's `sub`.
///
/// # Not renderable
///
/// No `Display`, no `Serialize`, redacted `Debug`. Metering keys on it; logging
/// keys on [`LogSubject`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelaySub([u8; 16]);

impl RelaySub {
    /// The domain separator for the daily log re-hash.
    const LOG_DOMAIN: &'static [u8] = b"twinvpn/relay-log-sub/v1";

    /// Takes the 16 bytes of a verified token's `sub` claim.
    #[must_use]
    pub const fn from_verified_claim(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The raw bytes, for the in-memory quota map key only.
    #[must_use]
    pub const fn as_quota_key(&self) -> &[u8; 16] {
        &self.0
    }

    /// The daily re-hashed label this subject may appear as in a log.
    ///
    /// `epoch_day` is the caller's — the relay's own day counter, not the
    /// device's — so the rotation is the relay's and cannot be pinned by a peer.
    /// Returns `None` when no digest provider is installed, in which case **no
    /// subject label is emitted at all**. That is the fail-closed direction for
    /// a privacy control: losing a log dimension is cheaper than emitting a
    /// cross-day-linkable one.
    #[must_use]
    pub fn log_subject(&self, crypto: &dyn RelayCrypto, epoch_day: u64) -> Option<LogSubject> {
        let mut input = [0_u8; 24];
        input[..16].copy_from_slice(&self.0);
        input[16..].copy_from_slice(&epoch_day.to_be_bytes());
        crypto.digest16(Self::LOG_DOMAIN, &input).map(LogSubject)
    }
}

impl std::fmt::Debug for RelaySub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RelaySub(<redacted>)")
    }
}

/// A `relay_sub` re-hashed for the current day. The only renderable form.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct LogSubject([u8; 16]);

impl LogSubject {
    /// Lowercase hex, truncated to 8 bytes — enough to aggregate within a day,
    /// short enough that it is obviously not a key.
    #[must_use]
    pub fn label(&self) -> String {
        hex_lower(&self.0[..8])
    }
}

impl std::fmt::Debug for LogSubject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LogSubject({})", self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::VerifiedClaims;
    use crate::crypto::{FailClosed, IssuerPublicKey, LegKey, Statement};

    /// A deterministic, NON-CRYPTOGRAPHIC stand-in. It exists only so the
    /// rotation property can be tested without a real digest; it is `cfg(test)`
    /// and no production path can reach it.
    struct CountingDigest;

    impl RelayCrypto for CountingDigest {
        fn verify_statement(
            &self,
            _: &IssuerPublicKey,
            _: Statement,
            _: &[u8],
        ) -> Option<VerifiedClaims> {
            None
        }
        fn verify_frame_mac(&self, _: &LegKey, _: &[u8], _: [u8; 8]) -> bool {
            false
        }
        fn frame_mac(&self, _: &LegKey, _: &[u8]) -> Option<[u8; 8]> {
            None
        }
        fn digest16(&self, domain: &[u8], input: &[u8]) -> Option<[u8; 16]> {
            let mut out = [0_u8; 16];
            for (i, slot) in out.iter_mut().enumerate() {
                let mut acc = 0_u8;
                for (j, b) in domain.iter().chain(input.iter()).enumerate() {
                    acc = acc.wrapping_add(b.wrapping_mul((i as u8) ^ (j as u8)).wrapping_add(1));
                }
                *slot = acc;
            }
            Some(out)
        }
    }

    #[test]
    fn a_relay_sub_has_no_rendering_path() {
        let s = RelaySub::from_verified_claim([0xDE; 16]);
        assert_eq!(format!("{s:?}"), "RelaySub(<redacted>)");
    }

    #[test]
    fn the_log_label_changes_across_days() {
        let s = RelaySub::from_verified_claim([7; 16]);
        let c = CountingDigest;
        let d1 = s.log_subject(&c, 20_000).expect("digest").label();
        let d2 = s.log_subject(&c, 20_001).expect("digest").label();
        assert_ne!(
            d1, d2,
            "operational logs must not link a device across days (ADR-0005 §10)"
        );
    }

    #[test]
    fn the_log_label_is_stable_within_a_day() {
        let s = RelaySub::from_verified_claim([7; 16]);
        let c = CountingDigest;
        assert_eq!(
            s.log_subject(&c, 20_000).expect("digest").label(),
            s.log_subject(&c, 20_000).expect("digest").label()
        );
    }

    #[test]
    fn with_no_digest_provider_no_subject_label_exists_at_all() {
        let s = RelaySub::from_verified_claim([7; 16]);
        assert!(s.log_subject(&FailClosed, 20_000).is_none());
    }
}
