//! `twinvpn-trust` — identity, pairing, revocation and the Owner root of trust.
//!
//! **Authority:** [ADR-0007](../../../../docs/adr/ADR-0007-device-identity-and-pairing.md)
//! in full; `docs/architecture.md` §2.22 and §4.5; ADR-0018 CB-5, CD-I4, CD-I5;
//! ADR-0008 N-3 and N-7; ADR-0009 §11.4 and §11.5;
//! `contracts/cddl/twinvpn/v1/signed_statements.cddl`.
//!
//! **Owner:** `core-security`.
//!
//! # What this crate decides
//!
//! `twinvpn-crypto` answers "does this signature verify over these octets".
//! This crate answers the questions that follow: **whose** key was that,
//! **may** that key do this, **is this newer** than what we hold, and **what
//! happens now**. It holds the device's trust state and nothing else — no
//! sockets, no sessions, no policy enforcement.
//!
//! | Module | Answers |
//! |---|---|
//! | [`identity`] | who this device is (N-2), and what a `hardware_backed` claim is worth (N-6) |
//! | [`owner`] | which anchor is pinned (S-32), which OSK may do what (N-11) |
//! | [`peer`] | may this peer's key be trusted (N-4), is it newer (N-22), how fresh is our trust (N-27) |
//! | [`revocation`] | is this peer refused (N-25(1)), and what epoch are we at (N-25(2)) |
//! | [`policy`] | did the Owner author this, and is it newer than what we enforce |
//! | [`pairing`] | did the ceremony complete on **both** devices, and is this a replay |
//!
//! # CD-I5: the control-plane side of the diagram
//!
//! > "`twinvpn-trust` sits on the control-plane-client side of the diagram. Do
//! > not depend on any data-plane crate."
//!
//! This crate's manifest names `twinvpn-{types,env,schema,crypto,store,platform}`
//! and nothing else. `cargo run -p xtask -- lint` enforces it.
//!
//! # CD-I4: no identity private scalar
//!
//! Every signing operation is a vtable call through [`identity::SignerHandle`],
//! which names *which* element-resident key and carries none. There is no key
//! generation in this crate either — N-7 forbids replacing a missing identity,
//! and the way to make that true is to have no code that could.
//!
//! # The three rules a reviewer should check first
//!
//! 1. **No `un_revoke`.** [`revocation::RevocationState`] holds a set that only
//!    grows and an epoch that only rises (ADR-0008 N-7).
//! 2. **No unverified tunnel key.** [`peer::TrustedPeer`] can only be built from
//!    a [`twinvpn_crypto::VerifiedTunnelKey`], which has no public constructor
//!    (N-4).
//! 3. **No policy from a non-Owner.** [`policy::PolicyState::offer`] checks the
//!    signer **before** the version, so a wrong-signer bundle can never advance
//!    the high-water mark whatever version it claims.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]

pub mod error;
pub mod identity;
pub mod owner;
pub mod pairing;
pub mod peer;
pub mod policy;
pub mod revocation;

#[cfg(any(test, feature = "test-support"))]
pub mod testkit;

pub use error::{Result, TrustError};
pub use identity::{
    check_device_id_echo, derive_device_id, derive_identity_id, AttestationRecord, HardwareBacking,
    SignerHandle,
};
pub use owner::{AnchorChain, Operation, VerifiedSigner};
pub use pairing::{CeremonyType, Pairing, PairingLedger, PairingOutcome, PairingState};
pub use peer::{HardExpiry, PeerTrust, TrustedPeer};
pub use policy::{effective_killswitch, PolicyDisposition, PolicyState};
pub use revocation::{RefusalOutcome, RevocationState};
