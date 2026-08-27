//! `twinvpn-platform` — the platform adapter TRAIT only - ADR-0018 §11.6, this crate is the seam.
//!
//! **Authority:** ADR-0018 §11.7 (module decomposition and the dependency
//! arrows that enforce I5), plus the ADRs named in the crate role above.
//!
//! **Owner:** `core-foundation`. Another implementation domain MUST NOT edit this crate
//! without the integration lead's coordination.
//!
//! Nothing is implemented yet. This is the integration lead's skeleton: the
//! crate exists, compiles, and carries its ownership and its lint posture, so
//! that the owning agent adds behaviour rather than negotiating structure.
#![forbid(unsafe_code)]
#![warn(missing_docs)]
