//! The construction-time rejection type, and its mapping into the registered
//! taxonomy.
//!
//! [`TypeError`] is what a *constructor* in this crate returns: a wrong
//! identifier length, a non-canonical prefix, a link-local IPv6 address with no
//! zone index. It is deliberately **not** the thing that crosses a component
//! boundary. `ownership.md` §6 rule 12 requires every exposed error to be a
//! registered `reason_code`, so [`TypeError::reason_code`] maps each variant
//! onto one, and [`crate::Diagnostic`] is what actually travels.
//!
//! The mapping is total and it is `const`-checked by exhaustive `match`: adding a
//! variant without choosing its code does not compile.

use crate::reason::{codes, ReasonCode};

/// A value rejected at construction.
///
/// Every variant carries enough to build the registry-declared evidence for its
/// code — `observed` and `limit` for a cap violation, the offending field for a
/// malformed one — so a rejection never degrades into "invalid input".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TypeError {
    /// A fixed-width identifier arrived at the wrong length.
    ///
    /// `contracts/docs/identifiers.md` §5: "A length mismatch is
    /// `PROTO.MALFORMED_MESSAGE` — never a truncation and never a pad, because
    /// both would silently convert one identifier into another."
    #[error("{kind}: expected exactly {expected} bytes, observed {observed}")]
    IdentifierLength {
        /// The identifier's registry name, e.g. `"device_id_bytes"`.
        kind: &'static str,
        /// The exact width the registry declares.
        expected: usize,
        /// What arrived.
        observed: usize,
    },

    /// A variable-width identifier fell outside its declared range.
    #[error("{kind}: expected {min}..={max} bytes, observed {observed}")]
    IdentifierRange {
        /// The identifier's registry name, e.g. `"idempotency_key"`.
        kind: &'static str,
        /// Inclusive lower bound.
        min: usize,
        /// Inclusive upper bound.
        max: usize,
        /// What arrived.
        observed: usize,
    },

    /// A bounded text identifier exceeded its cap or was not valid for its kind.
    #[error("{kind}: {observed} bytes exceeds the {limit}-byte cap")]
    TextIdentifierTooLong {
        /// The identifier's registry name, e.g. `"twinnet_id_max_bytes"`.
        kind: &'static str,
        /// The cap.
        limit: usize,
        /// What arrived.
        observed: usize,
    },

    /// An IPv6 address in `fe80::/10` arrived without the RFC 4007 scope zone
    /// index that `docs/protocol.md` §10.4 requires, or a non-link-local address
    /// carried one.
    #[error("IPv6 zone index: link-local requires a non-zero zone, others require zero")]
    Ipv6ZoneIndex,

    /// An IPv4-mapped IPv6 address (`::ffff:0:0/96`) was offered where a
    /// canonical IPv6 address is required.
    ///
    /// `common.proto`: rejected, "not silently unmapped: accepting it would let
    /// one logical address arrive under two encodings and defeat every
    /// set-membership and prefix-match check that depends on a canonical form."
    #[error("IPv4-mapped IPv6 address is not a canonical IPv6 address")]
    Ipv4MappedIpv6,

    /// A prefix length exceeded its family's maximum.
    #[error("prefix length {observed} exceeds {limit} for this address family")]
    PrefixLength {
        /// What arrived.
        observed: u32,
        /// 32 for IPv4, 128 for IPv6.
        limit: u32,
    },

    /// A prefix carried set bits below its prefix length.
    ///
    /// `common.proto`: "A non-canonical prefix (10.0.0.1/24) MUST be REJECTED,
    /// never normalized — normalizing attacker input before a policy check is
    /// how a rule intended to match one network comes to match another."
    #[error("prefix is not in canonical form: host bits are set below the prefix length")]
    PrefixNotCanonical,

    /// A prefix carried a scope zone index. A zone scopes an *address* to an
    /// interface; a prefix has no interface.
    #[error("a prefix must not carry an RFC 4007 scope zone index")]
    PrefixHasZone,

    /// Port 0 is malformed (`common.proto` `Endpoint.port` is 1..=65535).
    #[error("port 0 is malformed")]
    PortZero,

    /// A NAT64 prefix length was not one of RFC 6052's six.
    #[error("NAT64 prefix length {observed} is not one of 32, 40, 48, 56, 64, 96")]
    Nat64PrefixLength {
        /// What arrived.
        observed: u32,
    },

    /// An RFC 6052 prefix had non-zero bits where the standard requires zero.
    #[error("NAT64 prefix has non-zero suffix or u-octet bits")]
    Nat64PrefixNotCanonical,

    /// A `reason_code` was not two or three segments.
    #[error("reason_code has {observed} segments; two or three are permitted")]
    ReasonCodeSegments {
        /// What arrived.
        observed: usize,
    },

    /// A `reason_code` exceeded 64 bytes.
    #[error("reason_code is {observed} bytes; the cap is 64")]
    ReasonCodeTooLong {
        /// What arrived.
        observed: usize,
    },

    /// A `reason_code` was not uppercase dot-separated ASCII.
    #[error("reason_code is not uppercase dot-separated ASCII")]
    ReasonCodeMalformed,

    /// A `reason_code`'s first segment is outside the closed set of sixteen
    /// domains, so it cannot be degraded correctly (ADR-0015 §11.2).
    #[error("reason_code domain is outside the closed set of sixteen")]
    ReasonCodeUnknownDomain,

    /// An evidence key is not `lower_snake_case` or exceeded 48 bytes.
    #[error("evidence key is not lower_snake_case within 48 bytes")]
    EvidenceKeyMalformed,

    /// An evidence key is not declared for its `reason_code`.
    ///
    /// ADR-0015 §11.3: "An evidence entry whose key is not declared for its code
    /// MUST be dropped by the receiver — an undeclared key is an unclassified
    /// key, and an unclassified key cannot be redacted correctly." This crate
    /// refuses to *construct* one, so an emitter cannot produce the condition.
    #[error("evidence key `{key}` is not declared for `{code}`")]
    EvidenceKeyUndeclared {
        /// The offending key.
        key: String,
        /// The code it was offered against.
        code: &'static str,
    },

    /// A `ConnectionState` wire value was outside the frozen twelve.
    #[error("connection state {observed} is outside the frozen vocabulary")]
    ConnectionStateUnknown {
        /// The wire value.
        observed: i32,
    },

    /// A wire enum arrived as its `UNSPECIFIED` zero value where a real value is
    /// required. Proto3 cannot distinguish "absent" from "zero", so a zero here
    /// is a missing required field, not a default to fill in.
    #[error("{enum_name} arrived UNSPECIFIED where a value is required")]
    EnumUnspecified {
        /// The enum's proto name.
        enum_name: &'static str,
    },
}

impl TypeError {
    /// The registered `reason_code` this rejection is exposed as.
    ///
    /// Every cap violation is `PROTO.MALFORMED_MESSAGE`, whose registry-declared
    /// evidence is `{cap_violated, observed, limit}` — exactly the shape of these
    /// variants. `PROTO.SIZE_EXCEEDED` and `PROTO.DEPTH_EXCEEDED` are reserved for
    /// the *envelope* caps in `twinvpn-schema`, which is where the byte and
    /// nesting limits live.
    #[must_use]
    pub const fn reason_code(&self) -> ReasonCode {
        match self {
            TypeError::IdentifierLength { .. }
            | TypeError::IdentifierRange { .. }
            | TypeError::TextIdentifierTooLong { .. }
            | TypeError::Ipv6ZoneIndex
            | TypeError::Ipv4MappedIpv6
            | TypeError::PrefixLength { .. }
            | TypeError::PrefixNotCanonical
            | TypeError::PrefixHasZone
            | TypeError::PortZero
            | TypeError::Nat64PrefixLength { .. }
            | TypeError::Nat64PrefixNotCanonical
            | TypeError::ReasonCodeSegments { .. }
            | TypeError::ReasonCodeTooLong { .. }
            | TypeError::ReasonCodeMalformed
            | TypeError::ReasonCodeUnknownDomain
            | TypeError::EvidenceKeyMalformed
            | TypeError::EvidenceKeyUndeclared { .. }
            | TypeError::ConnectionStateUnknown { .. }
            | TypeError::EnumUnspecified { .. } => codes::PROTO_MALFORMED_MESSAGE,
        }
    }

    /// The `cap_violated` evidence value for this rejection, when it has one.
    ///
    /// `PROTO.MALFORMED_MESSAGE` declares `{cap_violated, observed, limit}`; this
    /// is the first of the three, and it names the *registry key* that was
    /// violated so a support case can be answered from the registry alone.
    #[must_use]
    pub const fn cap_violated(&self) -> Option<&'static str> {
        match self {
            TypeError::IdentifierLength { kind, .. }
            | TypeError::IdentifierRange { kind, .. }
            | TypeError::TextIdentifierTooLong { kind, .. } => Some(*kind),
            TypeError::ReasonCodeTooLong { .. } => Some("max_reason_code_bytes"),
            TypeError::ReasonCodeSegments { .. } => Some("reason_code_segments"),
            TypeError::EvidenceKeyMalformed => Some("max_evidence_key_bytes"),
            TypeError::PrefixLength { .. } => Some("max_prefix_len"),
            _ => None,
        }
    }
}
