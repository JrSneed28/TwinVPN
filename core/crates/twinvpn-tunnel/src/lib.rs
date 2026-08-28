//! `twinvpn-tunnel` — the L-DATA engine: handshake driver, rekey scheduling,
//! replay window and key state, **driving `twinvpn-crypto` and never
//! implementing cryptography**.
//!
//! **Authority:** ADR-0001 (§7.2, §7.3, §7.3.1, §7.6, §8, §11), ADR-0014
//! (negotiation, the monotonic floor, N-10/N-11), ADR-0018 CB-2, CB-3, CD-I2,
//! CD-1; `contracts/proto/twinvpn/v1/tunnel.proto` and `capability.proto`
//! (frozen).
//!
//! **Owner:** `core-dataplane`.
//!
//! # CD-I2: this crate declares no cryptographic dependency
//!
//! `ownership.md` §6: "Do not invent cryptographic primitives." ADR-0001 §11
//! fixes L-DATA as **unmodified WireGuard** `Noise_IKpsk2` — X25519,
//! ChaCha20-Poly1305, BLAKE2s. Every primitive arrives through
//! [`crypto::NoiseHandshake`], [`crypto::TransportKeys`] or
//! [`crypto::Transcript`], and this crate does scheduling, counters, windows and
//! state.
//!
//! # Where the production implementations live
//!
//! [`bind`] supplies them. Declaring a trait and shipping no implementation of
//! it is a gate that passes over a product with no tunnel, so [`bind`] closes
//! that: [`bind::NoiseBinding`] is the real `Noise_IKpsk2` handshake,
//! [`bind::SessionKeys`] the real transport keys, [`bind::NoiseTranscript`] the
//! real §7.3 D2 hashes, and [`bind::establish_tunnel`] the path from a completed
//! handshake to a live [`engine::Tunnel`]. All four are newtypes over
//! `twinvpn-crypto`, which this crate already depends on — so CD-I2 is
//! untouched and no cryptography moved.
//!
//! # The composition rule
//!
//! ADR-0001 §7.2 calls it "the single most important composition rule in this
//! ADR":
//!
//! > The transport mode is a property of the `Path`, not of the `Session`.
//! > Switching modes MUST NOT re-run the L-DATA handshake, MUST NOT reset the
//! > L-DATA nonce counter or replay window, and MUST NOT alter any L-DATA
//! > security property.
//!
//! [`engine::Tunnel::switch_transport`] touches exactly one field and returns a
//! [`transport::SecuritySnapshot`] so the property is **measured** rather than
//! asserted in prose.
//!
//! # Endpoint migration is authenticated and path-validated
//!
//! §7.6. [`engine::Tunnel::offer_endpoint`] stages a candidate that "MAY receive
//! only the validation probe"; the previous endpoint stays authoritative until
//! [`engine::Tunnel::commit_endpoint`] is called with a validated probe; and a
//! failed validation changes nothing, because "failed validation MUST NOT tear
//! down the `Session`".
//!
//! # Negotiation is confirmed inside the tunnel, with a monotonic floor
//!
//! D1 and N-8: advertisements are claims, `NegotiationConfirm` is the decision,
//! and [`negotiate::MonotonicFloor::record`] refuses to write anything the caller
//! has not confirmed in-session (P-4). The floor covers the epoch and the
//! `security_relevant` subset **only** — N-19's reason is that a wider floor
//! would leave an honest device whose OS revoked a permission "permanently
//! unable to reconnect".

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]

pub mod bind;
pub mod crypto;
pub mod engine;
pub mod negotiate;
pub mod rekey;
pub mod replay;
pub mod transport;

pub use bind::{establish_tunnel, NoiseBinding, NoiseTranscript, SessionKeys};
pub use crypto::{CryptoUnavailable, NoiseHandshake, Prologue, Transcript, TransportKeys};
pub use engine::{Tunnel, TunnelError, TunnelState};
pub use negotiate::{Advertisement, MonotonicFloor, Selection};
pub use rekey::{Action, KeepalivePolicy, KeyState};
pub use replay::{ReplayWindow, SendCounter};
pub use transport::{SecuritySnapshot, TransportMode};
