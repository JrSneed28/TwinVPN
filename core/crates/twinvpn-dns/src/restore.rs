//! S-34's `HostResolverRestorePoint`: written before the mutation, verified by
//! read-back, and restorable without a healthy agent.
//!
//! **Authority:** ADR-0011 DN-18, DN-19, DN-20, DN-21; ADR-0009 R-9;
//! `contracts/proto/twinvpn/v1/dns.proto` `DnsProtectionAssertion`;
//! `docs/architecture.md` S-34.
//!
//! # Why the token exists
//!
//! `DnsProtectionAssertion.restore_point_valid` is documented as "whether a
//! `HostResolverRestorePoint` (S-34) is present **and its `restore_token`
//! matches the installed configuration**. A stale restore point means teardown
//! would restore the wrong thing, surfaced as `DNS.STUB.TEARDOWN_INCOMPLETE`."
//!
//! So the token is a digest of what we *installed*, not of what we *saved*, and
//! [`RestorePoint::matches_installed`] is the comparison that makes the
//! staleness detectable rather than latent.

use twinvpn_types::{codes, Component, Diagnostic, EvidenceValue, ReasonCode};

/// The verbatim prior host resolver configuration, plus what is needed to put it
/// back.
///
/// DN-18: written and flushed **before** the mutation, never after.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestorePoint {
    /// The prior configuration, byte-for-byte as the platform reported it.
    ///
    /// Opaque here: what it means is per platform (a `resolv.conf`, an NRPT rule
    /// set, a `systemd-resolved` link config), and CB-3 forbids this crate from
    /// knowing which.
    prior: Vec<u8>,
    /// The platform object identifiers needed to restore it.
    object_ids: Vec<String>,
    /// A digest of the configuration **we installed**, so a later teardown can
    /// tell whether something else has changed it since.
    restore_token: [u8; 32],
    /// The owner tag, so a fresh process can reclaim it after an unclean exit
    /// (ADR-0012 KS-20).
    owner_tag: String,
}

impl RestorePoint {
    /// Records the prior configuration ahead of a mutation.
    #[must_use]
    pub fn new(
        prior: Vec<u8>,
        object_ids: Vec<String>,
        restore_token: [u8; 32],
        owner_tag: String,
    ) -> Self {
        Self {
            prior,
            object_ids,
            restore_token,
            owner_tag,
        }
    }

    /// The saved configuration.
    #[must_use]
    pub fn prior(&self) -> &[u8] {
        &self.prior
    }

    /// The platform object identifiers.
    #[must_use]
    pub fn object_ids(&self) -> &[String] {
        &self.object_ids
    }

    /// The owner tag.
    #[must_use]
    pub fn owner_tag(&self) -> &str {
        &self.owner_tag
    }

    /// Whether the installed configuration is still the one this point was
    /// written against.
    ///
    /// A mismatch is `DNS.STUB.TEARDOWN_INCOMPLETE`: restoring anyway would put
    /// back a configuration that is no longer the one we replaced.
    #[must_use]
    pub fn matches_installed(&self, installed_token: &[u8; 32]) -> bool {
        // Constant time is not required — neither value is secret — but a plain
        // comparison is stated rather than assumed so nobody "fixes" it later.
        self.restore_token == *installed_token
    }
}

impl core::fmt::Debug for RestorePointRedactionMarker {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("<redacted>")
    }
}

#[doc(hidden)]
pub struct RestorePointRedactionMarker;

/// The assertion §11.6(1) of ADR-0015 requires: **protection is asserted, not
/// assumed**.
///
/// Mirrors `twinvpn.v1.DnsProtectionAssertion`. Every field is an *observation*
/// obtained by querying the enforcement layer or reading configuration back —
/// never the agent's belief about what it configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
// Six independent observations. Collapsing them would make "the stub is up but
// the host is not pointed at it" indistinguishable from "everything is fine",
// which is the exact D7 defect DN-19 exists to prevent.
pub struct ProtectionAssertion {
    /// The policy version this was evaluated against.
    pub policy_version: u64,
    /// Both IPv4 listeners are answering.
    pub stub_listening_v4: bool,
    /// Both IPv6 listeners are answering.
    pub stub_listening_v6: bool,
    /// The host resolver configuration observed **by read-back** matches intent.
    pub host_resolver_matches_intent: bool,
    /// A restore point is present and its token matches.
    pub restore_point_valid: bool,
    /// A resolver on the path was observed rewriting answers.
    pub interception_detected: bool,
    /// The monotonic instant of the assertion.
    pub asserted_at_micros: u64,
    /// The window after which this becomes `UNKNOWN` rather than `PROTECTED`.
    pub freshness_window_ms: u64,
}

/// What a surface may render from an assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Posture {
    /// Every observation is positive and the assertion is fresh.
    Protected,
    /// The assertion is stale. **Never `Protected`** (ADR-0015 O-18): "a hung,
    /// crashed, killed, or suspended agent [must not leave] a reassuring green
    /// indicator."
    Unknown,
    /// An observation is negative, with the code that says which.
    Unprotected(ReasonCode),
}

impl ProtectionAssertion {
    /// The posture at `now_micros`.
    ///
    /// Staleness is checked **first**: an old assertion says nothing about now,
    /// however positive its fields were when it was taken.
    #[must_use]
    pub fn posture(&self, now_micros: u64) -> Posture {
        let age_us = now_micros.saturating_sub(self.asserted_at_micros);
        if age_us > self.freshness_window_ms.saturating_mul(1000) {
            return Posture::Unknown;
        }
        if !self.stub_listening_v4 || !self.stub_listening_v6 {
            return Posture::Unprotected(codes::DNS_STUB_BIND_FAILED);
        }
        if !self.host_resolver_matches_intent {
            return Posture::Unprotected(codes::DNS_STUB_TEARDOWN_INCOMPLETE);
        }
        if !self.restore_point_valid {
            return Posture::Unprotected(codes::DNS_STUB_TEARDOWN_INCOMPLETE);
        }
        if self.interception_detected {
            return Posture::Unprotected(codes::DNS_INTERCEPTION_DETECTED);
        }
        Posture::Protected
    }

    /// The diagnostic for a negative posture.
    #[must_use]
    pub fn diagnostic(&self, now_micros: u64) -> Option<Diagnostic> {
        match self.posture(now_micros) {
            Posture::Protected => None,
            Posture::Unknown => Some(
                Diagnostic::builder(codes::DNS_STUB_NOT_READY, Component::Dns)
                    .evidence(
                        "age_ms",
                        EvidenceValue::DurationMs(
                            now_micros.saturating_sub(self.asserted_at_micros) / 1000,
                        ),
                    )
                    .build(),
            ),
            Posture::Unprotected(code) => Some(Diagnostic::builder(code, Component::Dns).build()),
        }
    }
}
