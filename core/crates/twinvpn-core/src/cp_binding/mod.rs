//! Binding `twinvpn-cp-client`'s three ports — **all three of them** — to what
//! the composed core actually holds. This is CD-I5's control-plane half.
//!
//! **Authority:** [ADR-0018](../../../../../docs/adr/ADR-0018-shared-core-and-build-architecture.md)
//! §11.7 CD-I5 and CD-I2, §11.6 (the platform seam), CB-1 (where resolution
//! lives), CB-5 / invariant **I4** (identity private keys stay inside the
//! element); [ADR-0001](../../../../../docs/adr/ADR-0001-cryptographic-architecture.md)
//! §11 item 3 and **R8**, §7.2 (the enrolment record);
//! [ADR-0002](../../../../../docs/adr/ADR-0002-control-plane-messaging-and-event-bus.md)
//! §11.2 (the four-rung ladder), **N-1**, **N-2**, §11.7;
//! [ADR-0007](../../../../../docs/adr/ADR-0007-identity-lifecycle-and-revocation.md)
//! N-11 and S-32; [ADR-0010](../../../../../docs/adr/ADR-0010-ipv4-ipv6-routing.md)
//! **R1**; finding **W-12** in `docs/implementation/ownership.md` §8;
//! `twinvpn_cp_client::ports`' own module docs ("Each trait below is a
//! **request** to `core-security`, stated as a signature. When the real crates
//! land, the composition root binds an adapter").
//!
//! This module is that adapter. It is compiled only under the `full` feature,
//! because `core-lite` contains no control-plane client (§11.12).
//!
//! # What is bound here
//!
//! | `twinvpn-cp-client` port | Bound to | Where |
//! |---|---|---|
//! | `ControlPlaneStore` | [`crate::planes::ControlPlanePort`] → [`crate::bridge::StoreBridge`] → `twinvpn_store::Store` | [`store`] |
//! | `ControlTransport` | `twinvpn_cp_client::quic::QuicControlTransport` — rung 1: QUIC + TLS 1.3, mutual RFC 7250 raw-public-key auth, server keys pinned, 0-RTT unreachable | [`transport`] |
//! | `StatementVerifier` | `twinvpn_crypto::verify_cose_sign1` over the received octets, against `twinvpn_trust::AnchorChain`'s Owner keys | [`verifier`] |
//!
//! **Every row of that table used to read "not bound".** Two of them were true
//! statements about the workspace and are no longer; this section records what
//! changed, because a stale "unimplemented" note is read as a live instruction
//! and the last one was.
//!
//! ## What W-12's split actually resolved to
//!
//! W-12 rules that `rustls` — the TLS implementation, the raw-public-key
//! verifier, the cipher policy, the `CryptoProvider` — belongs to
//! **`twinvpn-crypto`** under CD-I2, and that `quinn` is "a transport protocol
//! implementation … that takes its cryptography from rustls and implements none
//! itself", so **`twinvpn-cp-client`** may declare it, with `twinvpn-core`
//! wiring the two.
//!
//! `twinvpn-cp-client` has now declared its half: `src/quic/` is a production
//! `ControlTransport`, `quinn` is hoisted in `core/Cargo.toml`, and
//! `tests/quic_loopback.rs` drives it against a real QUIC listener.
//! `twinvpn-crypto` has **not** declared its half — it still ships no TLS module
//! and no configured `CryptoProvider` — so `src/quic/` carries that half as a
//! *seam* rather than an implementation: the device's private key never appears
//! there, only a `rustls::sign::SigningKey` capability, and the server side is
//! byte-equality pinning, which is not cryptography. The wiring W-12 assigns to
//! this crate therefore has both ends to wire, and [`transport`] is it.
//!
//! Nothing here names `quinn` or `rustls`. The composition root speaks only in
//! `twinvpn_cp_client::quic`'s vocabulary — [`transport::DeviceIdentity`],
//! [`transport::ServerPins`], [`transport::ControlEndpoint`] — so CD-I2's bound
//! holds at this crate's manifest as well as at `twinvpn-cp-client`'s.
//!
//! # What is still open, stated rather than implied
//!
//! 1. **Rungs 2, 3 and 4 of the ADR-0002 §11.2 ladder are unimplemented
//!    anywhere.** [`transport::ControlTransportBinding`] attaches on rung 1 and
//!    refuses to pretend otherwise, so **a device that cannot reach UDP:443 has
//!    no control channel at all.** I5 bounds the consequence — established
//!    sessions are unaffected and a cached `TrustedPeer` still reconnects — but
//!    the ladder's fallback does not exist and the summed 23 s budget in
//!    `Rung::budget` describes a ladder with three missing rungs.
//! 2. **`DeviceIdentity::software_key` is a live CB-5 / I4 hole.** See
//!    [`transport::ControlTransportBinding::bind`]: this crate refuses to call
//!    it, but nothing stops a shell from doing so on a target with no element.
//! 3. **ADR-0002 §11.7 rule 1's drain has no carrier on rung 1.** The rule names
//!    an HTTP/3 `GOAWAY`; the shipped server speaks C1 directly over QUIC with
//!    no HTTP/3 layer, so `TransportError::Draining` has no producer and the
//!    uniform-reattach path it schedules is unreachable. Recorded in the ADR;
//!    not this module's to fix.
//! 4. **The core holds no `DeviceIdentityKey` for a peer**, so
//!    [`verifier::AnchorStatementVerifier`] refuses every `Device`-authority
//!    statement until the composition root supplies the key set. See that
//!    module's docs for why [`crate::planes::PeerRecord`] cannot carry one.
//! 5. **Power scoping (ADR-0007 N-11) is not applied to a verified Owner
//!    signature**, and [`verifier`] says exactly what that does and does not
//!    buy rather than implying the quorum ran.
//! 6. **`AnchorChain` cannot enumerate its own delegation set**, so an Owner
//!    statement signed by an OSK is refused unless the composition root named
//!    that `osk_id` through
//!    [`verifier::AnchorStatementVerifier::with_owner_delegations`]. An
//!    `AnchorChain::osk_ids()` from `core-security` would close it; the gap
//!    fails closed meanwhile.
//!
//! # Fail closed, by name
//!
//! Every refusal in this module carries a code that exists in
//! `contracts/registry/reason_codes.json`, and the two that are easiest to
//! conflate are kept apart deliberately:
//!
//! - **`AUTH.KEY_UNAVAILABLE`** — this device has no usable identity. A locked
//!   device, a revoked entitlement, an element that lost its backing. Nothing
//!   about the network is known.
//! - **`CONTROL.UNREACHABLE`** — this device has an identity and could not reach
//!   a control plane with it.
//!
//! An operator does different things about those two, and a user sees different
//! text. Collapsing them is the defect the `trust_guards` work established:
//! a single "could not connect" makes a locked keychain look like an outage.
//! There is no third answer in which an unauthenticated transport is used
//! instead — no code path in this module produces a `ControlTransport` that
//! presents no key or pins nothing.

pub mod store;
pub mod transport;
pub mod verifier;

pub use store::ControlPlaneBinding;
pub use transport::{ControlPlaneEnrolment, ControlTransportBinding};
pub use verifier::AnchorStatementVerifier;
