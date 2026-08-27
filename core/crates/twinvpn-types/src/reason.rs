//! The `reason_code` taxonomy: the closed domain set, the frozen registry, and
//! the two kinds of code — one this build can emit, one it can only observe.
//!
//! **Authority:** ADR-0015 §11.2 (format, closed domain set, stability rules,
//! required attributes), `contracts/registry/reason_codes.json` (the 201 codes),
//! `contracts/proto/twinvpn/v1/errors.proto` (`ResolvedAttributes`).
//!
//! # The two types, and why there are two
//!
//! [`ReasonCode`] is a code **this build can emit**. It is a pointer into the
//! embedded registry table, so it cannot name a code the registry does not
//! contain: there is no constructor from an arbitrary string, only
//! [`codes`] constants and [`ReasonCode::lookup`]. That is what makes
//! `ownership.md` §6 rule 12 — "expose registered `reason_code`s, never raw
//! internal errors" — a compile-time property.
//!
//! [`ObservedReasonCode`] is a code **received from a peer**. ADR-0015 §11.2
//! rule 5 requires a receiver to hold an unrecognised code's *text* and degrade
//! on its `DOMAIN`, so an unknown code must survive receipt rather than be
//! rejected. It is deliberately a different type: a received code is a claim,
//! and letting it flow into the emit path would let a peer put an unregistered
//! string into our own diagnostics.
//!
//! # No user-visible strings (ADR-0018 CB-4)
//!
//! Nothing here is localised or renderable. `summary_key` and `next_action_key`
//! are catalogue **lookup keys**; the catalogue lookup is a pure function of
//! `(code, evidence, locale, platform_ctx)` and lives in `twinvpn-diag`.

use core::fmt;

use crate::error::TypeError;

include!(concat!(env!("OUT_DIR"), "/reason_registry.rs"));

/// ADR-0015 §11.2 `class`: how a condition behaves over time, which is what
/// decides whether a caller may retry.
///
/// Mirrors `twinvpn.v1.ErrorClass` one-for-one; `twinvpn-schema` asserts the
/// discriminants match the frozen enum, so the two cannot drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ErrorClass {
    /// Expected to clear on its own; retry under the `reliability.md` backoff regime.
    Transient = 1,
    /// Will not clear without a change in the world; retry is futile until then.
    Persistent = 2,
    /// A deliberate refusal by policy. Retrying without changing the policy is wrong.
    Policy = 3,
    /// A security event or an invariant violation. Never retried automatically.
    Fatal = 4,
}

/// ADR-0015 §11.2 `severity`. Mirrors `twinvpn.v1.ErrorSeverity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ErrorSeverity {
    /// Informational.
    Info = 1,
    /// A warning.
    Warn = 2,
    /// An error.
    Error = 3,
    /// Critical.
    Critical = 4,
}

/// The shape of the remediation, independent of the specific wording, so a
/// surface can pick an affordance for a code it has never seen (ADR-0018 F-4).
/// Mirrors `twinvpn.v1.RemediationClass`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RemediationClass {
    /// Nothing to do; it will clear or it is informational.
    None = 1,
    /// Wait; the system is already retrying.
    Wait = 2,
    /// The Owner must act on THIS device.
    LocalAction = 3,
    /// The Owner must act on the PEER device named in the evidence.
    PeerAction = 4,
    /// The Owner must change a policy or a permission.
    PolicyChange = 5,
    /// Software on this device or on the peer must be updated.
    UpdateRequired = 6,
    /// The network or its operator is the obstacle.
    NetworkChange = 7,
    /// An OS permission or entitlement must be granted.
    PermissionGrant = 8,
    /// Report it. Every occurrence is a defect (the `INTERNAL` domain).
    ReportDefect = 9,
}

/// The scope a condition applies to. Decides what a surface may render it
/// against — a device-scope condition must not be drawn on one `Session`'s row.
/// Mirrors `twinvpn.v1.DiagnosticScope`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DiagnosticScope {
    /// One `Session`.
    Session = 1,
    /// The whole `TwinNet`.
    Twinnet = 2,
    /// This `Device`.
    Device = 3,
    /// One `Path`.
    Path = 4,
    /// One relay.
    Relay = 5,
}

/// Registry lifecycle of a code (ADR-0015 §11.2 stability rules 1, 3, 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CodeStatus {
    /// In force.
    Active,
    /// Superseded; still accepted for three epochs or twelve months.
    Deprecated,
    /// No longer accepted. Its identifier is never reused.
    Retired,
}

/// One row of the frozen registry, as compiled into this build.
///
/// Constructed only by the build script. It is `pub` so that
/// [`ReasonCode`]'s accessors can return borrowed data, and has no public
/// constructor for the same reason `ReasonCode` has none.
#[derive(Debug)]
pub struct ReasonCodeEntry {
    code: &'static str,
    domain: Domain,
    class: ErrorClass,
    severity: ErrorSeverity,
    terminal: bool,
    user_actionable: bool,
    remediation_class: RemediationClass,
    scope: DiagnosticScope,
    doc_anchor: &'static str,
    summary_key: &'static str,
    next_action_key: Option<&'static str>,
    status: CodeStatus,
    evidence_fields: &'static [&'static str],
}

/// A code **this build can emit**: by construction, a member of the frozen
/// registry.
///
/// `Copy` and pointer-sized. Equality is by identity of the registry row, which
/// is equality of the code string because the table holds each code once.
#[derive(Clone, Copy)]
pub struct ReasonCode(pub(crate) &'static ReasonCodeEntry);

impl ReasonCode {
    /// The code's wire spelling, e.g. `"PROTO.MALFORMED_MESSAGE"`.
    ///
    /// This is a stable machine identifier, not user-visible text: CB-4 forbids
    /// the core to own a rendered string, and ADR-0015 §11.2 rule 4 requires
    /// automation to key on the code and never on rendered text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0.code
    }

    /// The code's domain — the only segment with registry meaning.
    #[must_use]
    pub const fn domain(self) -> Domain {
        self.0.domain
    }

    /// ADR-0015 §11.2 `class`.
    #[must_use]
    pub const fn class(self) -> ErrorClass {
        self.0.class
    }

    /// ADR-0015 §11.2 `severity`.
    #[must_use]
    pub const fn severity(self) -> ErrorSeverity {
        self.0.severity
    }

    /// Whether this condition ends the current attempt.
    ///
    /// Read alongside [`Self::scope`]: ADR-0015 §11.2.1 notes that
    /// `INTERNAL.CORE_PANIC` is terminal for the core *instance* and not for the
    /// `Session`, so a consumer that assumes `Session` scope reads it wrongly.
    #[must_use]
    pub const fn terminal(self) -> bool {
        self.0.terminal
    }

    /// Whether an Owner can do anything about it. When true,
    /// [`Self::next_action_key`] is `Some` — asserted by the build script and by
    /// `registry_user_actionable_codes_declare_a_next_action`.
    #[must_use]
    pub const fn user_actionable(self) -> bool {
        self.0.user_actionable
    }

    /// The shape of the remediation.
    #[must_use]
    pub const fn remediation_class(self) -> RemediationClass {
        self.0.remediation_class
    }

    /// What the condition applies to.
    #[must_use]
    pub const fn scope(self) -> DiagnosticScope {
        self.0.scope
    }

    /// Stable documentation anchor, e.g. `"adr-0011#dn-11"`.
    #[must_use]
    pub const fn doc_anchor(self) -> &'static str {
        self.0.doc_anchor
    }

    /// i18n catalogue **lookup key** for the summary. Not text.
    #[must_use]
    pub const fn summary_key(self) -> &'static str {
        self.0.summary_key
    }

    /// i18n catalogue **lookup key** for the next action. Not text.
    #[must_use]
    pub const fn next_action_key(self) -> Option<&'static str> {
        self.0.next_action_key
    }

    /// Registry lifecycle state.
    #[must_use]
    pub const fn status(self) -> CodeStatus {
        self.0.status
    }

    /// The exact set of evidence keys this code may attach (ADR-0015 §11.3).
    ///
    /// An evidence entry whose key is not in this set must be dropped by a
    /// receiver: an undeclared key is an unclassified key, and an unclassified
    /// key cannot be redacted correctly.
    #[must_use]
    pub const fn evidence_fields(self) -> &'static [&'static str] {
        self.0.evidence_fields
    }

    /// Whether `key` is declared for this code.
    #[must_use]
    pub fn declares_evidence(self, key: &str) -> bool {
        self.0.evidence_fields.contains(&key)
    }

    /// Looks a code up in the frozen registry.
    ///
    /// This is the only string-driven entry point, and it **cannot** mint a code
    /// the registry does not contain. Use it when decoding; use a [`codes`]
    /// constant when emitting.
    #[must_use]
    pub fn lookup(code: &str) -> Option<ReasonCode> {
        ENTRIES
            .binary_search_by(|e| e.code.cmp(code))
            .ok()
            .map(|i| ReasonCode(&ENTRIES[i]))
    }

    /// Every code in the frozen registry, in sorted order.
    pub fn all() -> impl Iterator<Item = ReasonCode> {
        ENTRIES.iter().map(ReasonCode)
    }
}

impl fmt::Debug for ReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.code)
    }
}

impl fmt::Display for ReasonCode {
    /// Writes the code's wire spelling.
    ///
    /// This is not a CB-4 violation: the code is a machine identifier that
    /// `docs/protocol.md` §17 requires to be stable and greppable. Rendering it
    /// as the *primary user-facing signal* is forbidden — that is the shell's
    /// obligation under ADR-0015 §11.2 rule 5, not something a `Display` impl
    /// can enforce.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.code)
    }
}

impl PartialEq for ReasonCode {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.0, other.0)
    }
}

impl Eq for ReasonCode {}

impl core::hash::Hash for ReasonCode {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.code.hash(state);
    }
}

/// A syntactically valid `reason_code` **observed from a peer**.
///
/// ADR-0015 §11.2 rule 5: a receiver meeting an unknown code must hold its text
/// and degrade on the `DOMAIN`, never swallow it and never render the raw code
/// as the primary user-facing signal. That obligation is why this type exists
/// separately from [`ReasonCode`], which can only name a registered code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservedReasonCode {
    /// The code is in this build's registry. Prefer the local entry's
    /// attributes over any carried claim (ADR-0015 §11.2 rule 5).
    Registered(ReasonCode),
    /// Syntactically valid, in the closed domain set, but not in this build's
    /// registry — a code shipped after this build. Degrade on `domain`.
    Unregistered {
        /// The code's exact received text, at most 64 bytes.
        code: alloc_string::CodeText,
        /// Its first segment, which is in the closed set.
        domain: Domain,
    },
}

impl ObservedReasonCode {
    /// Parses a received code against ADR-0015 §11.2's format rules.
    ///
    /// Rejects, rather than guesses at: an empty string, more than 64 bytes,
    /// fewer than two or more than three segments, a non-uppercase-ASCII byte,
    /// an empty segment, and a first segment outside the closed domain set. A
    /// first segment outside the set cannot be degraded correctly, and guessing
    /// is how a local-agent failure comes to render as "check your internet
    /// connection".
    pub fn parse(code: &str) -> Result<Self, TypeError> {
        validate_syntax(code)?;
        if let Some(known) = ReasonCode::lookup(code) {
            return Ok(ObservedReasonCode::Registered(known));
        }
        let domain_str = code.split('.').next().unwrap_or_default();
        let domain = Domain::parse(domain_str).ok_or(TypeError::ReasonCodeUnknownDomain)?;
        Ok(ObservedReasonCode::Unregistered {
            code: alloc_string::CodeText::new(code)?,
            domain,
        })
    }

    /// The code's text, registered or not.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            ObservedReasonCode::Registered(c) => c.as_str(),
            ObservedReasonCode::Unregistered { code, .. } => code.as_str(),
        }
    }

    /// The code's domain — always in the closed set.
    #[must_use]
    pub fn domain(&self) -> Domain {
        match self {
            ObservedReasonCode::Registered(c) => c.domain(),
            ObservedReasonCode::Unregistered { domain, .. } => *domain,
        }
    }

    /// The registered code, when this build knows it.
    #[must_use]
    pub fn registered(&self) -> Option<ReasonCode> {
        match self {
            ObservedReasonCode::Registered(c) => Some(*c),
            ObservedReasonCode::Unregistered { .. } => None,
        }
    }
}

/// Validates a `reason_code` string against ADR-0015 §11.2 rule 7 and the
/// `diagnostics.max_reason_code_bytes` cap, without consulting the registry.
///
/// Exposed because `twinvpn-schema` validates the `ErrorEnvelope.reason_code`
/// field before it decides whether the code is known.
pub fn validate_syntax(code: &str) -> Result<(), TypeError> {
    if code.is_empty() {
        return Err(TypeError::ReasonCodeMalformed);
    }
    if code.len() > MAX_REASON_CODE_BYTES {
        return Err(TypeError::ReasonCodeTooLong {
            observed: code.len(),
        });
    }
    let mut segments = 0usize;
    for segment in code.split('.') {
        segments += 1;
        if segment.is_empty() {
            return Err(TypeError::ReasonCodeMalformed);
        }
        if !segment
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(TypeError::ReasonCodeMalformed);
        }
    }
    if !(MIN_REASON_CODE_SEGMENTS..=MAX_REASON_CODE_SEGMENTS).contains(&segments) {
        return Err(TypeError::ReasonCodeSegments { observed: segments });
    }
    Ok(())
}

/// `contracts/registry/limits.json` `diagnostics.max_reason_code_bytes`.
///
/// Restated here rather than read from the registry because `twinvpn-types`
/// carries no JSON parser; `twinvpn-schema`'s `limits_match_twinvpn_types`
/// test asserts this constant equals the frozen value, so it cannot drift.
pub const MAX_REASON_CODE_BYTES: usize = 64;
/// `contracts/registry/limits.json` `diagnostics.min_reason_code_segments`.
pub const MIN_REASON_CODE_SEGMENTS: usize = 2;
/// `contracts/registry/limits.json` `diagnostics.max_reason_code_segments`.
pub const MAX_REASON_CODE_SEGMENTS: usize = 3;

/// A bounded, inline `reason_code` text, so receiving an unregistered code
/// drives no heap allocation proportional to attacker input.
pub mod alloc_string {
    use super::{TypeError, MAX_REASON_CODE_BYTES};
    use core::fmt;

    /// At most [`MAX_REASON_CODE_BYTES`] of uppercase ASCII, stored inline.
    #[derive(Clone, Copy, PartialEq, Eq, Hash)]
    pub struct CodeText {
        bytes: [u8; MAX_REASON_CODE_BYTES],
        len: u8,
    }

    impl CodeText {
        /// Stores `s`, which the caller has already validated.
        pub(super) fn new(s: &str) -> Result<Self, TypeError> {
            if s.len() > MAX_REASON_CODE_BYTES {
                return Err(TypeError::ReasonCodeTooLong { observed: s.len() });
            }
            let mut bytes = [0u8; MAX_REASON_CODE_BYTES];
            bytes[..s.len()].copy_from_slice(s.as_bytes());
            #[allow(clippy::cast_possible_truncation)]
            Ok(Self {
                bytes,
                len: s.len() as u8,
            })
        }

        /// The stored text.
        #[must_use]
        pub fn as_str(&self) -> &str {
            // The constructor only ever stores the bytes of a `&str` that
            // `validate_syntax` proved to be uppercase ASCII, so this is UTF-8.
            core::str::from_utf8(&self.bytes[..usize::from(self.len)]).unwrap_or("")
        }
    }

    impl fmt::Debug for CodeText {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.as_str())
        }
    }

    impl fmt::Display for CodeText {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.as_str())
        }
    }
}
