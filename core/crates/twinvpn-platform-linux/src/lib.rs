//! `twinvpn-platform-linux` — the Linux/OpenWrt implementation of the twinvpn-platform trait (CB-3 permits cfg here).
//!
//! **Authority:** ADR-0018 §11.7 (module decomposition and the dependency
//! arrows that enforce I5), plus the ADRs named in the crate role above.
//!
//! **Owner:** `desktop-linux`. Another implementation domain MUST NOT edit this crate
//! without the integration lead's coordination.
//!
//! Nothing is implemented yet. This is the integration lead's skeleton: the
//! crate exists, compiles, and carries its ownership and its lint posture, so
//! that the owning agent adds behaviour rather than negotiating structure.
// DP-4 unsafe allowlist member: `unsafe` is permitted here and NOWHERE else.
// Every `unsafe` block MUST carry a `// SAFETY:` comment stating the invariant.
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
