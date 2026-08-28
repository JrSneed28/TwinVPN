//! `twinsim` — the simulated devices and gateways of the local multi-node
//! environment, and the development credentials that make it reachable.
//!
//! **Owner:** `test-engineering`. **Never shipped** (ADR-0018 §11.12).
//!
//! # What this crate is for
//!
//! `docker-compose.yml` brings up seven server artifacts and an observability
//! stack. Nothing in it *uses* them: there is no device, so no leg is ever
//! established, no `pair_tag` is ever bound, no `DATA` frame is ever forwarded,
//! and every dashboard reads zero. A topology with no traffic is a topology
//! whose health checks are the only thing under test.
//!
//! `twinsim` is the other half — the peers that make the local plane do work.
//!
//! | Module | What it holds |
//! |---|---|
//! | [`wire`] | the ADR-0005 §9.1 header and framing, derived independently of the relay |
//! | [`control`] | the token presentation, `BIND` and `BOUND` bodies |
//! | [`issuer`] | the **development** relay-credential issuer, and why the empty default stays |
//! | [`map`] | how a simulator learns a relay's static key, and why that is not a `RelayMap` |
//! | [`pairing`] | the `pair_tag` two peers meet under |
//! | [`device`] | one simulated device's leg: `Noise_IK`, the cookie ladder, `BIND`, `DATA` |
//! | [`run`] | the client and gateway run loops |
//! | [`lcontrol`] | the **L-CONTROL binding**: rung 1 as a real QUIC client |
//! | [`admin`] | `/healthz`, `/readyz`, `/metrics` |
//!
//! # The three honesty rules this crate is built on
//!
//! `docs/testing-strategy.md` §3.1 forbids a condition produced by a flag
//! inside the product, and TwinLab's `Verdict::Unavailable` exists so that
//! "we could not produce the condition" is never reported as "the condition
//! held". The same discipline applies here, in three specific places:
//!
//! 1. **[`wire`] is a second implementation on purpose.** The relay's own
//!    harness re-derives the wire from the relay's constants and says it
//!    therefore asserts "self-consistency, not interoperability". This crate
//!    reads ADR-0005 and the contract instead, so agreement means something.
//! 2. **[`map`] carries no signature and says so.** A `twinsim` bind is not
//!    evidence that ADR-0006's map verification works, because this simulator
//!    never verifies a map.
//! 3. **[`run`] drives the relay path, not a TwinVPN session.** There is no
//!    L-CONTROL binding in `core/` to drive — `twinvpn-cp-client`'s transport
//!    is a trait by CB-1's design — so no control-plane ceremony is simulated
//!    and none is claimed.
//!
//! # Nothing here is a production credential path
//!
//! [`issuer::DevIssuer`] signs with `twinvpn_crypto::testkit`, behind the
//! never-shipped `test-support` feature, from a seed generated per machine and
//! written under `infra/secrets/` where `check-compose.py` asks git to confirm
//! it is unreachable. There is no committed seed, no default seed and no
//! fallback: a missing seed is generated, a malformed one is an error.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
// Product and protocol nouns — TwinVPN, TwinLab, TwinNet, IPv4, IPv6, NAT — and
// the specification quotations that carry them read worse back-ticked.
#![allow(clippy::doc_markdown)]
#![allow(clippy::module_name_repetitions)]
// Every fallible function here returns `anyhow::Error` with the condition in
// its message; a per-function `# Errors` section restating "an I/O failure"
// once per constructor is noise, and the ones that say something specific keep
// theirs.
#![allow(clippy::missing_errors_doc)]

pub mod admin;
pub mod control;
pub mod device;
pub mod issuer;
pub mod lcontrol;
pub mod map;
pub mod pairing;
pub mod run;
pub mod wire;

pub use control::{BindBody, BoundBody, Carriage, Family, TokenPresentation};
pub use device::{BindOutcome, LegOutcome, SimDevice};
pub use issuer::{DevIssuer, TokenSpec, DEV_ISSUER_KEY_ID, DEV_OPERATOR_GROUP};
pub use map::{DevRelayMap, RelayEntry};
pub use pairing::RelayPairKey;
pub use wire::FrameType;
