//! `twinvpn-relay` — the ciphertext-only relay data plane (ADR-0005).
//!
//! **Owner:** `relay-plane` (`docs/implementation/ownership.md` §2).
//!
//! # The one property everything else is subordinate to
//!
//! **I1 / invariant P1: relay infrastructure must never require plaintext access
//! to TwinVPN tunnel payloads.** ADR-0005 §7.1 makes that structural by
//! enumerating the relay's *entire* key inventory as a closed set of three
//! items, none of which is an input to the L-DATA `Noise_IKpsk2` key schedule:
//!
//! | Key | Where it lives here | Relationship to L-DATA |
//! |---|---|---|
//! | relay static X25519 | [`config::RelayConfig::static_key_path`] — bytes, never parsed by this crate | not a party to L-DATA |
//! | issuer public-key set | [`issuer::IssuerKeySet`] | verification-only, public |
//! | per-leg `K_leg` | [`crypto::LegKey`] | domain-separated; used only for the 64-bit frame MAC |
//!
//! The structural argument is enforced in the type system rather than asserted
//! in prose: the forwarding path's payload type is
//! [`twinvpn_service_common::Verbatim`], which has **no decode, no parse and no
//! `Display`** — its `Debug` prints a length and a channel. See
//! [`forward`] and `tests/cannot_decrypt.rs`.
//!
//! # What this crate does
//!
//! - [`config`] — every `TWINVPN_RELAY_*` variable, validated at startup.
//! - [`crypto`] — the injected primitive seam. The default provider refuses
//!   everything, so an unconfigured relay is a closed relay.
//! - [`issuer`] — the issuer public-key set. **Empty means no token verifies.**
//! - [`token`] — offline `RelayCapabilityToken` verification, a pure function.
//! - [`epoch`] — the monotone, Owner-signed `RelayEpochFloor`.
//! - [`replay`] — the bounded `jti` replay cache.
//! - [`frame`] — the 16-byte `RelayFrame` header and RFC 9147 §4.2.2 counter
//!   reconstruction.
//! - [`flow`] — S-29: the `pair_tag`-keyed pending-slot and half-flow table,
//!   **in memory, `LOCAL`, never persisted or replicated**.
//! - [`resource`] — ADR-0005 §11.5 limits, quotas and the cookie threshold.
//! - [`drr`] — two-tier deficit round robin.
//! - [`drain`] — herd-safe drain (ADR-0005 §8, reliability §8.3, T37).
//! - [`forward`] — the forwarding engine, which cannot interpret what it carries.
//! - [`observe`] — ADR-0015 O-13: severed parent links, deleted correlation ids,
//!   and a daily re-hashed subject label.
//! - [`condition`] — every ADR-0005 §11.7 condition, mapped to a **registered**
//!   `reason_code`.
//! - [`engine`] — the glue: a `RelayEngine` that owns the tables and the limits.
//! - [`net`] — the `R-UDP` carriage over a real dual-stack socket.
//!
//! # What it deliberately does not do
//!
//! - **It never calls the control plane.** Not at startup, not in readiness, not
//!   per bind, not per packet (I5, ADR-0005 RQ2, architecture A-12). There is no
//!   HTTP client and no control-plane address in [`config`].
//! - **It persists nothing about a flow, a peer, a pair or a token** (RQ10).
//!   Nothing in [`flow`] derives `serde::Serialize`, and
//!   `tests/s29_is_not_persistable.rs` asserts that from the source.
//! - **It reconstructs no pairing.** `peer_key_id` was removed from the contract
//!   on purpose (`relay.proto`); no log line, metric label, span attribute or
//!   public type here carries two peers' identifiers together.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod condition;
pub mod config;
pub mod crypto;
pub mod drain;
pub mod drr;
pub mod engine;
pub mod epoch;
pub mod flow;
pub mod forward;
pub mod frame;
pub mod issuer;
pub mod net;
pub mod observe;
pub mod replay;
pub mod resource;
pub mod subject;
pub mod token;

pub use condition::{Condition, Fidelity};
pub use config::{RelayConfig, RelayConfigError};
pub use crypto::{FailClosed, LegKey, RelayCrypto};
pub use engine::RelayEngine;
pub use flow::{FlowId, PairTable, PairTag};
pub use subject::RelaySub;

/// The component every `ServiceError` from this crate is observed by.
pub const COMPONENT: twinvpn_types::Component = twinvpn_types::Component::RelayServer;
