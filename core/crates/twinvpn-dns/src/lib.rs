//! `twinvpn-dns` — the stub resolver's decisions: scopes, policy, classification,
//! typed failures, and restore-point bookkeeping.
//!
//! **Authority:** ADR-0011 (the whole ADR), ADR-0012 §11.2 class 6 / 6b and
//! §11.5's `RESOLVER` socket class, ADR-0010 R1, `docs/protocol.md` §13.4,
//! `contracts/proto/twinvpn/v1/dns.proto` (frozen).
//!
//! **Owner:** `core-dataplane`.
//!
//! # Three rules this crate exists to hold
//!
//! 1. **An absent field is never a permission.** `servers_declared_v4/v6` and
//!    `block_fallback_v4/v6` are explicit-presence bits, and
//!    [`policy::validate`] refuses a policy that leaves any of them unset.
//!    `docs/protocol.md` §13.4 forbids expressing "v4 configured, v6 left to the
//!    OS", and refusing is the only reading of an absent deny-shaped field that
//!    cannot leak.
//! 2. **Scope never changes on failure.** DN-10 clause 2, implemented as
//!    [`scope::retry_scope`] returning its argument and
//!    [`scope::may_reach_preexisting_resolver`] answering `false` for the two
//!    scopes that must never reach one — under **any** condition, including stub
//!    error, upstream timeout, `SERVFAIL`, tunnel loss and policy expiry.
//! 3. **Never NXDOMAIN for a failure.** [`answer::Outcome::rcode`] returns
//!    `NXDOMAIN` for exactly one outcome, the one where it is true.
//!
//! # What this crate does not do
//!
//! It does not open a socket, bind a listener, write a resolver configuration or
//! parse a DNS wire message. Those are the adapter's, reached through
//! `twinvpn-platform`; CB-2 puts every *decision* here and no *mechanism*.
//! [`stub::accepts`] decides admissibility from a parsed shape the adapter or a
//! parser supplies — it does not do the parsing.
//!
//! # And what it deliberately does not claim
//!
//! DN-15: record filtering "is **not**, and MUST NOT be documented, tested, or
//! sold as, leak prevention. A build that filters records but does not block
//! egress is a leaking build that produces prettier timeouts." The leak
//! guarantee is `twinvpn-enforce`'s Tier 2.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]

pub mod answer;
pub mod cache;
pub mod classify;
pub mod policy;
pub mod restore;
pub mod scope;
pub mod stub;

pub use answer::{Outcome, Rcode};
pub use classify::{Class, Classification};
pub use policy::{Disposition, Dnspolicy, Mode, PolicyError};
pub use restore::{Posture, ProtectionAssertion, RestorePoint};
pub use scope::Scope;
