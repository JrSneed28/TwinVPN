//! `twinvpn-relay-directory` — the Relay-Selection Service (ADR-0006, S-09/S-10).
//!
//! **Owner:** `relay-plane`.
//!
//! # Why this service owns the registry as well as the ranking
//!
//! `docs/architecture.md` §2.8's prose calls the Control Plane "the single
//! authoritative writer for … relay-fleet registry", while §5 row **S-09** assigns
//! "`Relay` fleet registry + ranking" to the Relay-Selection Service (2.12). Both
//! cannot hold under I8. Finding **W-3** in `docs/implementation/ownership.md` §8
//! rules that **§5 wins**, because architecture.md names §5 as its own authority
//! for single-writer questions: registry *and* ranking are this service's, and the
//! control plane keeps **S-30**, the `RelayCapabilityToken` issuance record.
//! `infra/postgres/initdb/10-databases.sh` already reflects that split.
//!
//! # The three properties that shape every type here
//!
//! 1. **The ranked set is cached state, never a per-connection call.** ADR-0006
//!    C1 and §11.3 rule 4: selection "never runs on the packet path", and relay
//!    failover must work with the control plane down. So the device-facing surface
//!    ([`api`]) serves **one document** — the whole signed map — and has **no
//!    route parameterised by a session, a device, a peer or a pair**. A
//!    per-connection dependency is not expressible, and
//!    `tests/not_per_connection.rs` asserts it against the router.
//! 2. **The client's own measurement overrides this service's ranking.** S-31,
//!    R-12, ADR-0006 §11.2: the server's total contribution is capped at **+100**
//!    while the measurement terms are worth up to **−410**, so "any relay with a
//!    ≥100 ms measured RTT advantage outranks any server preference,
//!    unconditionally". [`rank`] implements that arithmetic and
//!    [`rank::ServerAdvice`] is named for what it is.
//! 3. **A cached set of size 1 is a design error.** ADR-0006 §11.1 rule 3 and
//!    architecture §2.12: ≥2 `ACTIVE` relays per region across ≥2
//!    `failure_domain`s, enforced at publication ([`map::PublicationFloor`]) and
//!    self-healing at the edge.
//!
//! # Modules
//!
//! | Module | Question |
//! |---|---|
//! | [`config`] | what does `TWINVPN_RELAYDIR_*` say? |
//! | [`fleet`] | what relays exist (S-09's registry half)? |
//! | [`map`] | what does the published `RelayMap` contain, and may it be published? |
//! | [`sign`] | who signs it, and what happens when nobody can? |
//! | [`rank`] | the advisory score, and the HRW spread |
//! | [`api`] | the device-facing surface — one document, no per-connection input |

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod api;
pub mod config;
pub mod fleet;
pub mod map;
pub mod map_cbor;
pub mod rank;
pub mod sign;

pub use config::{DirectoryConfig, DirectoryConfigError};
pub use fleet::{FleetStore, InMemoryFleet, RelayRecord};
pub use map::{PublicationFloor, RelayMap};

/// The component every `ServiceError` from this crate is observed by.
///
/// `RelaySelection`, not `RelayServer`: this is architecture §2.12's service, and
/// a diagnostic that named the data plane would send a reader to the wrong
/// component.
pub const COMPONENT: twinvpn_types::Component = twinvpn_types::Component::RelaySelection;
