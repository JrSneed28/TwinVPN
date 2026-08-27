//! Route errors, each mapped to a **registered** `ROUTE.*` code.
//!
//! **Authority:** ADR-0010 §11.8, ADR-0015 §11.2, `ownership.md` §6 rule 12
//! ("expose registered `reason_code`s, never raw internal errors").
//!
//! # A defect found, and reported rather than patched
//!
//! ADR-0010 §11.8 registers `ROUTE.FAMILY_ASYMMETRY` (PERSISTENT/WARN). It is
//! **not** in `contracts/registry/reason_codes.json`. §11.8 also classifies
//! `ROUTE.IFACE_MISSING` as `TRANSIENT`, while the frozen registry classifies it
//! `PERSISTENT`. Both are reported to the integration lead; this crate emits the
//! nearest registered code and says so in [`RouteError::reason_code`].

use twinvpn_types::{
    codes, Component, DeviceId, Diagnostic, EvidenceValue, IpPrefix, ReasonCode, TypeError,
};

/// Why a route computation or installation was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RouteError {
    /// A peer advertised a prefix outside what its `AccessPolicy` permits — in
    /// practice, a non-`ExitNode` advertising a default route (P6).
    #[error("route scope violation")]
    ScopeViolation {
        /// The refused prefix.
        prefix: IpPrefix,
        /// Who advertised it.
        advertiser: Option<DeviceId>,
    },
    /// Full tunnel with exactly one family granted and the other not blocked.
    ///
    /// "A v4-only exit grant with v6 leaking to the local ISP is the exact IPv6
    /// leak this product must never ship."
    #[error("a default route was granted for only one family")]
    DefaultSingleFamily {
        /// The family that was granted.
        granted: twinvpn_types::AddressFamily,
    },
    /// An accepted route overlaps a pre-existing system route and scope could
    /// not resolve it. **Never resolved by overwriting.**
    #[error("route conflict unresolved")]
    ConflictUnresolved {
        /// The prefix in contention.
        prefix: IpPrefix,
    },
    /// An assigned TwinNet address collides with an on-link prefix.
    #[error("overlay address collides with an on-link prefix")]
    AddressCollision {
        /// The colliding address.
        prefix: IpPrefix,
    },
    /// Per-app routing was requested on a target that cannot express it.
    ///
    /// A **named** refusal: `networking.md` §7.1 forbids a silent downgrade.
    #[error("per-app routing is not available on this target")]
    PerAppUnsupported,
    /// The OS refused a route or address installation.
    #[error("route programming denied by the platform")]
    ProgrammingDenied,
    /// The overlay interface disappeared beneath a live `Session`.
    #[error("the overlay interface is missing")]
    InterfaceMissing,
    /// One family's routes installed and the other's did not — non-conforming
    /// under §11.3.
    #[error("route family asymmetry")]
    FamilyAsymmetry,
    /// The installed table no longer matches the applied generation.
    #[error("installed routes have drifted from the applied generation")]
    DriftDetected,
    /// A `twinvpn-types` constructor rejected a value.
    #[error("address construction failed: {0}")]
    Address(TypeError),
}

impl RouteError {
    /// The registered code this condition surfaces as.
    #[must_use]
    pub const fn reason_code(&self) -> ReasonCode {
        match self {
            RouteError::ScopeViolation { .. } => codes::ROUTE_SCOPE_VIOLATION,
            RouteError::ConflictUnresolved { .. } => codes::ROUTE_CONFLICT_UNRESOLVED,
            RouteError::AddressCollision { .. } => codes::ROUTE_ADDRESS_COLLISION,
            RouteError::ProgrammingDenied => codes::ROUTE_PROGRAMMING_DENIED,
            RouteError::InterfaceMissing => codes::ROUTE_IFACE_MISSING,
            // `ROUTE.FAMILY_ASYMMETRY` is named by ADR-0010 §11.8 and is absent
            // from the frozen registry. `ROUTE.DEFAULT_SINGLE_FAMILY` is the
            // nearest registered condition and is what this build emits.
            RouteError::DefaultSingleFamily { .. } | RouteError::FamilyAsymmetry => {
                codes::ROUTE_DEFAULT_SINGLE_FAMILY
            }
            RouteError::DriftDetected => codes::ROUTE_DRIFT_DETECTED,
            RouteError::PerAppUnsupported | RouteError::Address(_) => codes::ROUTE_IFACE_CONFLICT,
        }
    }

    /// The full diagnostic, with the evidence the registry declares for the code.
    ///
    /// P5 requires a conflict to name "both prefixes, both sources, and the
    /// winner"; the prefix half of that is attached here and the rest rides on
    /// [`crate::conflict::Conflict`].
    #[must_use]
    pub fn diagnostic(&self) -> Diagnostic {
        let mut b = Diagnostic::builder(self.reason_code(), Component::RoutingEngine);
        match self {
            RouteError::ScopeViolation { prefix, advertiser } => {
                b = b.evidence("prefix", EvidenceValue::Prefix(*prefix));
                if let Some(d) = advertiser {
                    b = b.evidence(
                        "advertiser_device_id",
                        EvidenceValue::Text(d.fingerprint()),
                    );
                }
            }
            RouteError::DefaultSingleFamily { granted } => {
                b = b.evidence("family", EvidenceValue::Family(*granted));
            }
            RouteError::ConflictUnresolved { prefix }
            | RouteError::AddressCollision { prefix } => {
                b = b.evidence("prefix", EvidenceValue::Prefix(*prefix));
            }
            _ => {}
        }
        b.build()
    }
}

/// The unregistered spellings this crate had to substitute for.
///
/// Asserted absent by a test, so registering one turns into a build failure that
/// points at the line to delete.
pub const UNREGISTERED_SPELLINGS: &[(&str, &str)] = &[(
    "ROUTE.FAMILY_ASYMMETRY",
    "ADR-0010 §11.8; substituted with ROUTE.DEFAULT_SINGLE_FAMILY",
)];
