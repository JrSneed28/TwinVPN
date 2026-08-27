//! `twinvpn-rendezvous` — the C4 ephemeral signaling meeting point.
//!
//! **Owner:** `rendezvous-connectivity` (`docs/implementation/ownership.md` §2).
//!
//! # What this service is
//!
//! Two devices that cannot yet reach each other exchange `ConnectOffer` /
//! `ConnectAnswer` / `CandidateSet` blobs through this process
//! (`docs/architecture.md` §2.9, `docs/protocol.md` §10.1, ADR-0002 §11.5).
//! It is an **untrusted courier**. It is deliberately **not** a control-plane
//! RPC: `docs/protocol.md` §10.1 states the reason — "the coordination service
//! must not be in the critical path of every reconnect (**I5**)".
//!
//! # What this service is not
//!
//! It is **not** the NAT traversal implementation. Candidate gathering, racing,
//! validation and the ADR-0004 ladder live in `core/crates/twinvpn-path`, owned
//! by `core-dataplane` (ADR-0018 §11.2 row 2.10). Nothing here decides a path.
//!
//! # The four properties that shape every line below
//!
//! 1. **B3 is the boundary** (`contracts/docs/trust-boundaries.md` §2):
//!    pre-authentication, forwarded blind, reachable by anyone who can send a
//!    datagram. Every byte is validated against `limits.json`'s C4 caps —
//!    **1200 bytes, depth 4** — *before* any allocation proportional to a
//!    declared length. A violation is a typed reject with a `PROTO.*` code and
//!    **no answer**: answering would confirm the target exists.
//! 2. **At-most-once, unordered, TTL'd, never logged**
//!    (`contracts/docs/contract-matrix.md` §1 category 4). There is no durable
//!    store in this crate and no code path that could add one: [`mailbox`] holds
//!    `Verbatim` octets in memory behind a TTL and three ceilings, and ADR-0002
//!    N-9 forbids it from being anything else.
//! 3. **Forward verbatim** (wave-1 finding W-4). `prost` 0.13 drops unknown
//!    fields, so the `CALL` body is carried as
//!    [`twinvpn_service_common::Verbatim`] and re-emitted byte for byte. This
//!    crate never decodes a `CALL` payload at all — not even to inspect it.
//! 4. **Learn as little as possible.** The `CALL` frame names the target by
//!    `DeviceId` and never by a caller-supplied address (ADR-0002 S-5, so this
//!    service cannot be a reflector). A delivered `CALL` carries **no sender
//!    field**: the blob is Rule-B signed and already names its signer, so
//!    adding one would tell the courier a pairing it does not need. Device
//!    identifiers never reach a log line; [`label`] maps them to a per-process
//!    sequential pseudonym instead.
//!
//! [`mailbox`]: crate::mailbox
//! [`label`]: crate::label

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::module_name_repetitions)]

pub mod admission;
pub mod attach;
pub mod binding;
pub mod codec;
pub mod config;
pub mod frame;
pub mod ingress;
pub mod label;
pub mod mailbox;
pub mod server;
pub mod testkit;
pub mod tls;

/// The `errors.proto` component this service reports itself as.
///
/// **There is no `COMPONENT_RENDEZVOUS_SERVICE`.** `errors.proto`'s enum has
/// `COMPONENT_RENDEZVOUS_CLIENT` (7), which is the device-side component, and
/// `COMPONENT_COORDINATION_SERVICE` (21). The rendezvous is a control-plane
/// service in `docs/architecture.md` §2.9's own table, so 21 is the closest
/// truthful answer; the gap is reported to the integration lead rather than
/// papered over by claiming to be the client.
pub const COMPONENT: twinvpn_types::Component = twinvpn_types::Component::CoordinationService;

/// The `errors.proto` enum name `ServiceConfig::load` wants.
pub const COMPONENT_NAME: &str = "COMPONENT_COORDINATION_SERVICE";

/// The default `TWINVPN_SERVICE_NAME`, matching `docker-compose.yml`.
pub const SERVICE_NAME: &str = "rendezvous";
