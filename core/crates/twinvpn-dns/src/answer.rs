//! DN-11's typed-failure table, and DN-12…DN-17's A/AAAA rules.
//!
//! **Authority:** ADR-0011 §11.5 (DN-11's table, normative), §11.6 (DN-12 …
//! DN-17), ADR-0010 R1; RFC 8914 (extended DNS errors).
//!
//! # NXDOMAIN is never a substitute for a failure
//!
//! DN-11: "NXDOMAIN is an assertion that a name does not exist; using it for a
//! blocked or failed resolution is a lie that gets negatively cached and breaks
//! unrelated software."
//!
//! [`Outcome::rcode`] returns `NXDOMAIN` for exactly one outcome — the one where
//! it is true — and a test asserts that.

use twinvpn_types::{codes, AddressFamily, ReasonCode};

/// DNS RCODEs this crate emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
pub enum Rcode {
    NoError = 0,
    ServFail = 2,
    NxDomain = 3,
    Refused = 5,
}

/// The negative outcomes DN-11 enumerates, plus success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// An answer was produced.
    Answered,
    /// Protected scope, no authorized secure path.
    BlockedFailClosed,
    /// Policy refuses the name.
    RefusedByPolicy,
    /// A family was withheld because the tunnel cannot carry it (DN-14a).
    FamilyWithheld(AddressFamily),
    /// Upstream unreachable through the tunnel.
    UpstreamUnreachable,
    /// Upstream timed out.
    TimeoutFailClosed,
    /// DNSSEC bogus.
    DnssecBogus,
    /// The validation chain was unavailable.
    DnssecChainUnavailable,
    /// The stub is not yet bound and answering.
    StubNotReady,
    /// A `TwinNet` name with no contract entry. The **only** true NXDOMAIN.
    TwinnetUnknown,
}

impl Outcome {
    /// DN-11's RCODE column.
    #[must_use]
    pub const fn rcode(self) -> Rcode {
        match self {
            Outcome::Answered | Outcome::FamilyWithheld(_) => Rcode::NoError,
            Outcome::RefusedByPolicy => Rcode::Refused,
            // Authoritative, and true.
            Outcome::TwinnetUnknown => Rcode::NxDomain,
            Outcome::BlockedFailClosed
            | Outcome::UpstreamUnreachable
            | Outcome::TimeoutFailClosed
            | Outcome::DnssecBogus
            | Outcome::DnssecChainUnavailable
            | Outcome::StubNotReady => Rcode::ServFail,
        }
    }

    /// DN-11's RFC 8914 extended-error column. `None` for the two outcomes that
    /// carry none.
    #[must_use]
    pub const fn extended_error(self) -> Option<u16> {
        match self {
            Outcome::Answered | Outcome::TwinnetUnknown => None,
            Outcome::BlockedFailClosed => Some(15),
            Outcome::RefusedByPolicy => Some(18),
            Outcome::FamilyWithheld(_) => Some(17),
            Outcome::UpstreamUnreachable => Some(22),
            Outcome::TimeoutFailClosed => Some(23),
            Outcome::DnssecBogus => Some(6),
            Outcome::DnssecChainUnavailable => Some(9),
            Outcome::StubNotReady => Some(14),
        }
    }

    /// DN-11's `reason_code` column. Every one is in the frozen registry.
    #[must_use]
    pub const fn reason_code(self) -> Option<ReasonCode> {
        match self {
            Outcome::Answered => None,
            Outcome::BlockedFailClosed => Some(codes::DNS_RESOLUTION_BLOCKED_FAIL_CLOSED),
            Outcome::RefusedByPolicy => Some(codes::DNS_RESOLUTION_REFUSED_BY_POLICY),
            Outcome::FamilyWithheld(_) => Some(codes::DNS_RECORDS_FAMILY_WITHHELD),
            Outcome::UpstreamUnreachable => Some(codes::DNS_RESOLUTION_UPSTREAM_UNREACHABLE),
            Outcome::TimeoutFailClosed => Some(codes::DNS_RESOLUTION_TIMEOUT_FAIL_CLOSED),
            Outcome::DnssecBogus => Some(codes::DNS_DNSSEC_VALIDATION_FAILED),
            Outcome::DnssecChainUnavailable => Some(codes::DNS_DNSSEC_CHAIN_UNAVAILABLE),
            Outcome::StubNotReady => Some(codes::DNS_STUB_NOT_READY),
            Outcome::TwinnetUnknown => Some(codes::DNS_NAME_TWINNET_UNKNOWN),
        }
    }

    /// The EXTRA-TEXT an EDE carries.
    ///
    /// DN-11: "Every EDE carries EXTRA-TEXT containing the `reason_code`, so the
    /// `reason_code` is visible to `dig` without a debug build (R-23, O-02)."
    #[must_use]
    pub fn extra_text(self) -> Option<&'static str> {
        self.reason_code().map(ReasonCode::as_str)
    }
}

/// Which families to answer for an in-`TwinNet` name.
///
/// DN-12: "Every `Device` has both an overlay v4 and an overlay v6 address at
/// all times (ADR-0010 R1), so an in-`TwinNet` name returns **both** an A and an
/// AAAA. Neither is synthesized; both come from the contract."
///
/// DN-13: "A stub MUST NOT filter AAAA because the underlay is v4-only. This is
/// the single most common way a v6-aware design degrades into a v4-only one, and
/// it is forbidden here by name." Hence there is no `underlay` parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FamilyAnswer {
    /// Whether an A record is returned.
    pub a: bool,
    /// Whether an AAAA record is returned.
    pub aaaa: bool,
    /// The outcome for the withheld family, when one is withheld.
    pub withheld: Option<Outcome>,
}

/// Decides which families an in-`TwinNet` answer carries.
///
/// `enforcement_will_drop` is the DN-14(a) input: a family the enforcement layer
/// will drop (e.g. an overlay AAAA while the negotiated tunnel covers only v4,
/// ADR-0012 KS-6). Withholding it makes the application fail fast instead of
/// waiting for a connect timeout.
///
/// DN-15 is why this function's name says nothing about leaks: "Record filtering
/// aligns resolution with enforcement so applications fail fast; it is **not**,
/// and MUST NOT be documented, tested, or sold as, leak prevention."
///
/// DN-17 is why a *working* family is never withheld: "the stub MUST NOT
/// withhold a working family to influence preference, because withholding a
/// working AAAA is a deliberate degradation of the network."
#[must_use]
pub fn twinnet_families(enforcement_will_drop: twinvpn_types::PerFamily<bool>) -> FamilyAnswer {
    let drop_v4 = *enforcement_will_drop.get(AddressFamily::V4);
    let drop_v6 = *enforcement_will_drop.get(AddressFamily::V6);
    FamilyAnswer {
        a: !drop_v4,
        aaaa: !drop_v6,
        withheld: match (drop_v4, drop_v6) {
            (false, false) => None,
            (true, _) => Some(Outcome::FamilyWithheld(AddressFamily::V4)),
            (_, true) => Some(Outcome::FamilyWithheld(AddressFamily::V6)),
        },
    }
}

/// DN-16: the stub **MUST NOT** synthesize AAAA from A.
///
/// A function so the rule is greppable and testable rather than a comment
/// somebody can quietly not implement. TwinVPN's own endpoint-literal synthesis
/// uses PREF64 and is ADR-0010 §11.7's, and it "MUST NOT consume this stub's
/// answers, which is what keeps `networking.md` §3.8's circular dependency
/// closed".
#[must_use]
pub const fn may_synthesize_aaaa_from_a() -> bool {
    false
}
