//! `twinvpn-gateway` — admission, per-peer policy, and accounting and fairness
//! decisions. **Forwarding is kernel-side, via the adapter.**
//!
//! **Authority:** ADR-0013 (the whole ADR), ADR-0012 KS-2, ADR-0010 §11.1 and
//! §11.5, `docs/networking.md` §7.6, ADR-0018 CB-2, CB-3;
//! `contracts/proto/twinvpn/v1/gateway.proto` (frozen).
//!
//! **Owner:** `core-dataplane`.
//!
//! # This crate decides; it does not forward
//!
//! CB-2 puts every decision in the core and none in the shell, and CB-1 puts the
//! packet path in the kernel through the adapter. So [`peer_table::PeerTable`]
//! answers "may this packet be attributed to this peer, and where does it go",
//! [`grant`] answers "what is this client entitled to", [`quota`] answers "may
//! this flow be admitted" — and none of them touches a packet.
//!
//! # Three rules this crate exists to hold
//!
//! 1. **The grant is the gateway's, and the client's view is advisory** (S-36).
//!    [`grant::decide`] runs on the gateway side, and a grant belongs to exactly
//!    one peer: "a grant issued to peer A creates **no reachability for peer
//!    B**."
//! 2. **An absent grant is a denial, never a permission** (CF-10).
//!    [`grant::Granted::from_optional`] is the only reader of the schema's
//!    explicit-presence bits and it maps `None` to `false`.
//! 3. **Both families, in the same table, the same checks and the same
//!    counters** (MG-3). [`peer_table::PeerTable::admit`] refuses a single-family
//!    peer row outright, "mirroring ADR-0012 KS-5".
//!
//! # MG-4 is the anti-spoofing control, and RPF is not
//!
//! [`peer_table::PeerTable::attribute_ingress`] runs at the decapsulation stage,
//! before route lookup, before conntrack, before policy — because "the binding of
//! key to identity … is only worth something if the address in the inner header
//! is checked against it". [`peer_table::rpf_is_the_antispoofing_control`]
//! answers `false` so a reviewer cannot mistake the two.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]

pub mod grant;
pub mod peer_table;
pub mod quota;

pub use grant::{GatewayPolicy, Grant, Granted, Refusal as GrantRefusal, Request};
pub use peer_table::{AdmitError, AllowedSources, PeerRow, PeerTable, Refusal};
pub use quota::{Capacity, PeerQuota, PeerUsage, QuotaRefusal};
