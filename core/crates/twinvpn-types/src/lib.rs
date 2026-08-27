//! `twinvpn-types` — the domain vocabulary every other core crate speaks.
//!
//! **Authority:** ADR-0018 §11.7 (this crate sits at the root of the dependency
//! arrows and depends on nothing in the workspace), `contracts/` (frozen: the
//! `.proto` files, `docs/identifiers.md`, and the three registries).
//!
//! **Owner:** `core-foundation`.
//!
//! # What this crate is for
//!
//! Four other domains build on it, so it carries **vocabulary and invariants,
//! never behaviour**. There is no I/O here, no clock, no randomness, no
//! allocation that an untrusted length can drive, and no `Display` on anything a
//! surface might be tempted to render.
//!
//! | Module | Carries | Enforced at construction |
//! |---|---|---|
//! | [`id`], [`idvar`] | every identifier in `limits.json` §`identifiers` | exact widths, ranges, caps, control-character rejection |
//! | [`net`] | IPv4, IPv6, prefixes, endpoints, NAT64, dual-stack | zone-index rule, v4-mapped rejection, canonical prefixes, port ≠ 0 |
//! | [`state`] | the frozen `ConnectionState` vocabulary | wire values outside the twelve |
//! | [`reason`] | the 201 registered `reason_code`s | membership of the registry; format and the closed domain set |
//! | [`evidence`] | typed, registry-declared evidence | declared keys only; the 32-entry and 4 KiB caps |
//! | [`diagnostic`] | the one failure carrier | a diagnostic always has a registered code |
//!
//! # Three rules that shape every type here
//!
//! 1. **Reject, never normalize.** `common.proto` is explicit: normalizing
//!    attacker input before a policy check is how a rule intended to match one
//!    network comes to match another. Every constructor returns `Result`.
//! 2. **IPv4 and IPv6 are co-equal** (ADR-0010 R1). [`net::OverlayAddresses`] has
//!    two non-optional fields and [`net::PerFamily`] makes forgetting the v6 half
//!    a compile error. Address family is carried as *evidence*
//!    ([`evidence::EvidenceValue::Family`]), never as a namespace.
//! 3. **No user-visible strings** (ADR-0018 CB-4). Nothing here is localised or
//!    rendered. `summary_key` and `next_action_key` are catalogue lookup keys;
//!    resolution is a pure function of `(code, evidence, locale, platform_ctx)`
//!    and lives in `twinvpn-diag`.
//!
//! # Dependencies
//!
//! No workspace crate, and three external ones that implement no domain logic:
//! `thiserror` for the error derive, `zeroize` for the scrub behind
//! [`idvar::ChannelBinding`]'s `ZeroizeOnDrop`, and `subtle` for its
//! constant-time comparison. Neither `zeroize` nor `subtle` is a cryptographic
//! implementation, so CD-I2 does not restrict them here — see the exemption and
//! its reasoning in `core/xtask/src/checks.rs`.
//!
//! # Time, randomness, and this crate
//!
//! There is none. ADR-0018 CD-1 puts every clock, timer and RNG behind
//! `twinvpn-env`, and CD-3's deny-list — run by `cargo run -p xtask -- lint` —
//! fails the build if one appears here. A timestamp in this crate is always a
//! value somebody supplied, never one this crate read.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
// `doc_markdown` fires on every occurrence of IPv4, IPv6, NAT64, TwinVPN and
// TwinNet in prose. Those are product and protocol nouns, not code identifiers,
// and back-ticking them would make the ADR quotations this crate carries harder
// to read than the lint is worth.
#![allow(clippy::doc_markdown)]
// Every fallible function in this crate returns exactly one error type, and
// `TypeError`'s own documentation enumerates every variant with the condition
// that produces it. A per-function `# Errors` section would restate that table
// once per constructor without adding a fact.
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]

pub mod diagnostic;
pub mod error;
pub mod evidence;
pub mod id;
pub mod idvar;
pub mod net;
pub mod reason;
pub mod state;

pub use diagnostic::{
    Component, Diagnostic, DiagnosticBuilder, ResolvedAttributes, StateTransition,
};
pub use error::TypeError;
pub use evidence::{Evidence, EvidenceSet, EvidenceValue};
pub use id::{
    CandidateId, CausationId, CorrelationId, DeviceId, Digest, FieldClassification, IdScope,
    Identifier, IdentityId, MessageId, Opacity, PairTag, PairingId, PathId, RelayId, Reuse,
    SessionId, SessionNonce, TunnelId,
};
pub use idvar::{
    CausalityToken, ChannelBinding, IdempotencyKey, PolicyId, RegionId, SignerKeyId, TwinnetId,
};
pub use net::{
    AddressFamily, Endpoint, IpAddr, IpPrefix, Nat64Prefix, OverlayAddresses, PerFamily, Port,
    UnderlayFamilies, V4Addr, V6Addr, ZoneIndex,
};
pub use reason::{
    codes, CodeStatus, DiagnosticScope, Domain, ErrorClass, ErrorSeverity, ObservedReasonCode,
    ReasonCode, ReasonCodeEntry, RemediationClass, REASON_REGISTRY_VERSION,
};
pub use state::{ConnectionState, PathClass, TrafficDisposition};
