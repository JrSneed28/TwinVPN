//! `twinvpn-control-plane` — the server side of channels **C1** (request /
//! response) and **C2** (the resumable durable event stream).
//!
//! **Owner:** `control-plane` (`docs/implementation/ownership.md` §2).
//! **Client:** [`twinvpn-cp-client`], a different artifact in a different
//! workspace. This crate is its exact counterpart and links none of the core
//! but `twinvpn-schema` and `twinvpn-types` (ADR-0018 §11.2 row 2.8).
//!
//! # The one sentence that shapes every design decision here
//!
//! **This service is authenticated but not trusted.** `policy.proto` says the
//! coordination service "WAREHOUSES AND DISTRIBUTES; IT CANNOT AUTHOR", and
//! `protocol.md` §7 says a coordination service that could mint routes could
//! redirect an `Owner`'s subnet to an attacker. So every capability that would
//! let this process *create* authority is removed structurally rather than by
//! policy:
//!
//! - It cannot author a `PolicyBundle`, a `RevocationStatement`, a
//!   `RouteAdvertisement` or an `ExitNodeOffer`. Each arrives as an opaque
//!   opaque [`Verbatim`](twinvpn_service_common::forward::Verbatim) and is admitted only if a
//!   [`verify::StatementVerifier`] says it verified **over the received
//!   octets** against the authority `required_authority` names for its type.
//!   With no verifier bound, every one of them is **refused** — fail closed.
//! - It never re-encodes anything it forwards
//!   ([`twinvpn_service_common::forward::Verbatim`], finding W-4).
//! - The `LogHead` signing key is online and carries no trust power, so nothing
//!   in this crate takes a trust decision from one.
//! - `device_id` is echoed, never assigned ([`domain::device`]).
//!
//! # The two-signer rule
//!
//! `RevokeDevice` and `PutPolicy` have **two signers with two authorities**:
//! the `Owner` authorizes by signing, and this service *orders* by assigning
//! `trust_epoch` / `net_seq` under a fenced lease. [`domain::device::revoke`]
//! and [`domain::policy::put`] are written so the ordering half cannot run
//! without the authorizing half having verified first.
//!
//! # Module map
//!
//! | Module | Question it answers |
//! |---|---|
//! | [`config`] | what does `TWINVPN_CP_*` say, and what happens when it says nothing? |
//! | [`wire`] | how does a C1 frame arrive, and how is it bounded before allocation? |
//! | [`command`] | which command is this, and what class does the contract matrix give it? |
//! | [`event`] | is this event durable or ephemeral, and who is its sole publisher? |
//! | [`model`] | what per-`TwinNet` state exists, and which parts are monotone? |
//! | [`tx`] | how do a mutation and its event become one atomic step? |
//! | [`domain`] | what does each command actually do? |
//! | [`store`] | where does that state live, and how is the write serialised? |
//! | [`verify`] | who signed this, and may they have signed it? |
//! | [`quic`] | how does a device attach, and how is 0-RTT made unreachable? |
//! | [`identity`] | which device is the key on this connection? |
//! | [`serve`] | the accept loop: one connection, its C1 streams and its C2 stream |
//! | [`session`] | how is one attached device served, drained and compacted? |
//! | [`codes`] | which registered `reason_code` names this failure? |

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
// Product and protocol nouns — TwinVPN, TwinNet, IPv4, IPv6, Postgres, QUIC —
// appear throughout the ADR quotations this crate carries. The same allowance
// `twinvpn-service-common` and `twinvpn-types` take.
#![allow(clippy::doc_markdown)]
#![allow(clippy::module_name_repetitions)]
// `ServiceError` is 128 bytes because it carries a `Diagnostic` with its typed
// evidence set — which is exactly what `ownership.md` §6 rule 12 asks for.
// Boxing it to satisfy `result_large_err` would put an allocation on every
// refusal path in a service whose refusals *are* its security controls, and
// would make `Result<T, Box<ServiceError>>` the shape of every signature here.
// The size is the evidence; it is allowed deliberately, once, with a reason.
#![allow(clippy::result_large_err)]

pub mod codes;
pub mod command;
pub mod config;
pub mod dispatch;
pub mod domain;
pub mod event;
pub mod identity;
pub mod model;
pub mod quic;
pub mod serve;
pub mod session;
pub mod store;
pub mod tx;
pub mod verify;
pub mod wire;

pub use command::Command;
pub use config::ControlPlaneConfig;
pub use event::{Durability, DurableEvent, EphemeralEvent, EventKind, Publisher};
pub use tx::NetTx;
pub use wire::{C1Frame, CommandCode};

/// The `errors.proto` component this service reports as.
pub const COMPONENT: twinvpn_types::Component = twinvpn_types::Component::CoordinationService;

/// The default service name, and the `TWINVPN_SERVICE_NAME` fallback.
pub const SERVICE_NAME: &str = "control-plane";
