//! `twinvpn-path` — candidate gathering, the NAT ladder, racing, authenticated
//! path validation, and the candidate ledger.
//!
//! **Authority:** ADR-0004 (the whole ADR), `docs/networking.md` §3 and §4,
//! `docs/reliability.md` §7, ADR-0010 §11.4 and §11.7, ADR-0018 CB-2, CB-3,
//! CD-I2; `contracts/proto/twinvpn/v1/candidate.proto` (frozen).
//!
//! **Owner:** `core-dataplane`.
//!
//! # Four rules this crate exists to hold
//!
//! 1. **No user traffic on an unvalidated path, ever.**
//!    [`ledger::Standing::may_carry_traffic`] answers `true` for exactly three
//!    standings, and every one of them has passed
//!    [`validate::Validation::is_validated`]. Migration is make-before-break:
//!    [`validate::Migration`] refuses to commit an unvalidated path and refuses
//!    to release a live old one.
//! 2. **Both families, concurrently.** [`candidate::GatherPlan::new`] starts
//!    both and the relay at the same instant, and
//!    [`race::Race::covers_both_families`] is assertable rather than intended.
//!    `docs/reliability.md` §4.4 says `DISCOVERING` gathers "for v4 and v6
//!    **concurrently**", and this is that.
//! 3. **The relay from t = 0.** §7.2 and ADR-0004 §11 both forbid gathering it
//!    "after direct fails"; [`ledger::Ledger::relay_gathered_from_t_zero`] is
//!    P01's structural assertion, decidable from the ledger alone.
//! 4. **`CandidateSet` is B3.** [`candidate::validate_set`] applies the count cap
//!    before it validates a single endpoint, and
//!    `twinvpn_schema::validate::decode` has already applied C4's 1200-byte and
//!    depth-4 envelope caps before this crate sees anything.
//!
//! # No cryptography here (CD-I2)
//!
//! ADR-0004 §11: the disco probe is "authenticated under ADR-0001's primitives.
//! **No new cryptographic primitive** (I2)." [`validate::DiscoAuth`] is the trait
//! `twinvpn-crypto` supplies; this crate decides *when* a path is validated and
//! never *how* a probe is sealed.
//!
//! # No OS branch (CB-3)
//!
//! [`nat::NatClass`] is a *measured* fact and [`candidate::Kind`] a *domain*
//! one. Neither asks which operating system it is on, which is what lets the
//! whole ladder be exercised against `twinvpn-platform`'s mock adapter on a
//! plain Linux CI runner (CD-5).

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]

pub mod candidate;
pub mod codes;
pub mod ledger;
pub mod nat;
pub mod race;
pub mod score;
pub mod validate;

pub use candidate::{Candidate, GatherPlan, Kind};
pub use ledger::{Ledger, Report, Standing};
pub use nat::{Filtering, Mapping, NatClass, Traversability};
pub use race::{Pair, Race};
pub use score::{AntiFlap, Inputs};
pub use validate::{DiscoAuth, Hysteresis, Migration, Validation};
