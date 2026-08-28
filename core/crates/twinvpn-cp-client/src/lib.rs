//! `twinvpn-cp-client` — the control-plane **CLIENT**. CD-I5: MUST NOT depend on
//! any data-plane crate.
//!
//! **Authority:** [ADR-0002](../../../docs/adr/ADR-0002-control-plane-messaging-and-event-bus.md)
//! (the whole document), [`docs/protocol.md`](../../../docs/protocol.md) §2–§9
//! and §16, [ADR-0008](../../../docs/adr/ADR-0008-idempotency.md),
//! [ADR-0009](../../../docs/adr/ADR-0009-state-consistency.md),
//! [ADR-0014](../../../docs/adr/ADR-0014-protocol-versioning-and-capability-negotiation.md),
//! [ADR-0001](../../../docs/adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) §11 item 3,
//! `docs/architecture.md` §4, `docs/reliability.md` §9,
//! `contracts/docs/contract-matrix.md`.
//!
//! **Owner:** `core-controlplane`. The **server** side is a different artifact,
//! owned by the `control-plane` domain; this crate is the client only.
//!
//! ---
//!
//! # The five properties this crate exists to hold
//!
//! ## 1. The control plane is **authenticated but not trusted**
//!
//! L-CONTROL is QUIC + TLS 1.3 with mutual raw-public-key authentication to
//! `DeviceIdentityKey`, **0-RTT prohibited** ([`transport::EarlyData`] has one
//! variant and no setter), plus end-to-end per-message signatures. [`quic`] is
//! the production rung-1 binding — server keys pinned from the enrolment record,
//! with no learn-on-first-use to select. None of that makes what the control
//! plane *says* true. Anything Owner-signed is verified
//! against the Owner chain ([`ports::StatementKind::required_authority`]); a
//! `PolicyBundle` that verified against a device key is not a policy bundle.
//!
//! Signing goes out through `twinvpn_platform::custody::IdentityCustody`
//! (CD-I4): **no private scalar exists in this crate**, and none can — the
//! custody trait has no type in its signature that could hold one.
//!
//! ## 2. Exactly-once **effect**, never exactly-once delivery
//!
//! No hop claims exactly-once. The client's contribution is a **stable
//! `idempotency_key` across retries** plus `if_version` preconditions.
//! [`idempotency::Ceremony`] mints its key once and [`idempotency::Ceremony::retry`]
//! returns the same one; there is no `with_new_key`, because a retry that mints a
//! fresh key is a duplicated `CEREMONY`, and a duplicated `CompletePairing` is
//! how two devices end up disagreeing about whether they trust each other.
//!
//! ## 3. Durability is **carried on the wire and asserted by the receiver**
//!
//! [`events::classify`] is a total match over the `ControlEvent` oneof, checked
//! against *both* the `EventDurability` enum and the `net_seq != 0` rule.
//! Treating a durable event as ephemeral is a **security** failure; the reverse
//! is a cost, privacy and freshness failure. Neither is expressible without
//! failing a test in [`events`].
//!
//! ## 4. Sole publisher is enforced **at the receiver**, not merely at the log
//!
//! [`events::admit`] rejects an event whose publisher does not match
//! `protocol.md` §7 with `CONTROL.EVENT_WRONG_PUBLISHER`, `FATAL`/`CRITICAL`,
//! **treated as a security event**.
//!
//! ## 5. The outage path is the property that matters most
//!
//! A total control-plane outage never prevents re-establishing a session with an
//! already-known `TrustedPeer`. [`cache::Ttl::baseline_reachability_permitted`],
//! [`cache::TrustStateBand::baseline_peer_connectivity`] and
//! [`health::ChannelHealth::permits_data_plane_reconnect`] all return `true`
//! unconditionally, and each has a test that says so — so a change that made one
//! conditional would have to delete an assertion rather than merely slip past a
//! review. Revocation is the deliberate exception
//! (`architecture.md` §4.5), implemented in [`revocation`] with the highest
//! `trust_epoch` winning and any lower epoch refused as a rollback.
//!
//! ---
//!
//! # Where prost's dropped unknown fields bind this crate
//!
//! `prost` 0.13 discards unknown protobuf fields, measured by `core-foundation`.
//! `contracts/docs/phase1-conflicts.md` CF-2 requires anything that *forwards* a
//! message it does not fully understand to preserve and forward them. This crate
//! therefore never re-encodes anything it forwards: [`transport::ControlConnection`]
//! hands back [`octets::ReceivedOctets`], and every signed statement travels to
//! the store as those exact bytes. See [`octets`] for the full argument.
//!
//! # The only bridge between the planes
//!
//! [`ports::ControlPlaneStore`]. This crate names no data-plane crate and knows
//! nothing about a `Session` — including that one exists. That is ADR-0002
//! §11.8's structural proof of **I5**, and `cargo run -p xtask -- lint` asserts
//! it over the transitive crate graph.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
// As in `twinvpn-types` and `twinvpn-env`: `doc_markdown` fires on TwinVPN,
// TwinNet, IPv4, IPv6 and NAT64 in prose, and back-ticking them would make the
// ADR quotations this crate carries harder to read than the lint is worth.
#![allow(clippy::doc_markdown)]
// Every fallible function here returns `CpError`, whose own documentation
// enumerates each variant with the condition that produces it. A per-function
// `# Errors` section would restate that table once per method.
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]

pub mod apply;
pub mod cache;
pub mod client;
pub mod commands;
pub mod cursor;
pub mod error;
pub mod events;
pub mod freshness;
pub mod health;
pub mod idempotency;
pub mod metadata;
pub mod octets;
pub mod ports;
pub mod quic;
pub mod retry;
pub mod revocation;
pub mod signing;
pub mod state;
pub mod transport;

#[cfg(any(test, feature = "test-support"))]
pub mod testing;

pub use apply::Effect;
pub use cache::{Band, ExpiryEffect, TrustStateBand, TrustStateThresholds, Ttl};
pub use client::{ClientParts, ControlPlaneClient};
pub use commands::{DesiredSet, DiscoverPeers, DiscoveryFallback, Mutation, StateDocumentPull};
pub use cursor::{Cursor, ResumeOutcome};
pub use error::{CpError, CpResult, COMPONENT};
pub use events::{Admitted, Durability, EventClass, Publisher};
pub use freshness::{Drain, FreshnessTracker, InfrastructureBackoff};
pub use health::ChannelHealth;
pub use idempotency::{Ceremony, Command, OperationClass};
pub use metadata::{Causality, InboundMetadata, MetadataFactory};
pub use octets::ReceivedOctets;
pub use ports::{
    ControlPlaneStore, SigningAuthority, StatementKind, StatementVerifier, StoreFailure,
    VerifiedStatement, VerifyFailure,
};
pub use quic::{
    ControlEndpoint, DeviceIdentity, Nat64Prefix, QuicConnection, QuicControlTransport,
    QuicEventStream, ServerPins,
};
pub use retry::Retry;
pub use revocation::{
    EpochAdmission, MonotoneVersion, RevocationEffect, RotationMarks, TrustEpoch, VersionAdmission,
};
pub use signing::AuthMode;
pub use state::{CachedPeer, DocumentType, PolicyMark, StoredDocumentMark};
pub use transport::{
    AttachFamilies, ControlConnection, ControlTransport, EarlyData, EventStream, Rung,
    TransportConfig, TransportError,
};

/// The channel this crate validates untrusted input against.
///
/// C1, C2 and C7 share one envelope cap (65536 bytes) and one depth cap (8).
/// Every decode in this crate goes through `twinvpn_schema::validate::decode`
/// with this value, so the byte cap and the depth cap are applied to the raw
/// bytes **before** `prost` allocates or recurses.
pub const CHANNEL: twinvpn_schema::Channel = twinvpn_schema::Channel::ControlAndTelemetry;

/// Decodes an inbound C1 or C2 body, applying both caps first.
///
/// The single decode entry point for this crate. A caller that reached for
/// `prost::Message::decode` directly would have skipped both caps, which is the
/// allocation lever `ownership.md` §6 rules 9 and 10 exist to close.
///
/// # Errors
///
/// [`CpError::Rejected`] carrying the violated `limits.json` key.
pub fn decode<M: prost::Message + Default>(bytes: &[u8]) -> CpResult<M> {
    twinvpn_schema::validate::decode(bytes, CHANNEL).map_err(CpError::Rejected)
}

/// Decodes an inbound C2 event from its received octets.
///
/// # Errors
///
/// [`CpError::Rejected`] on a cap or shape violation.
pub fn decode_event(octets: &ReceivedOctets) -> CpResult<twinvpn_schema::v1::ControlEvent> {
    decode(octets.as_slice())
}

/// Rejects an inline C2 document above the 16 KiB cap.
///
/// The cap is lower than the envelope's on purpose: "so a single policy bundle
/// cannot monopolise a stream. Larger documents are announced by reference and
/// pulled."
///
/// # Errors
///
/// [`CpError::Rejected`] past 16 KiB.
pub fn check_inline_document(bytes: &[u8]) -> CpResult<()> {
    twinvpn_schema::validate::check_c2_inline_document(bytes).map_err(CpError::Rejected)
}

#[cfg(test)]
mod tests {
    use super::{check_inline_document, decode, CHANNEL};
    use twinvpn_schema::v1;

    #[test]
    fn an_oversized_envelope_is_rejected_before_prost_allocates() {
        let oversized = vec![0u8; CHANNEL.max_bytes() + 1];
        let err = decode::<v1::ControlEvent>(&oversized).expect_err("over the 64 KiB cap");
        assert_eq!(err.reason_code().as_str(), "PROTO.SIZE_EXCEEDED");
    }

    #[test]
    fn the_inline_document_cap_is_lower_than_the_envelope_cap() {
        let cap = twinvpn_schema::limits::C2_INLINE_DOCUMENT_MAX_BYTES;
        assert!(cap < CHANNEL.max_bytes());
        assert!(check_inline_document(&vec![0u8; cap]).is_ok());
        let err = check_inline_document(&vec![0u8; cap + 1]).expect_err("over 16 KiB");
        assert_eq!(err.reason_code().as_str(), "PROTO.SIZE_EXCEEDED");
    }

    #[test]
    fn garbage_is_a_typed_reject_and_never_a_panic() {
        // trust-boundaries.md §2: exactly three decode outcomes exist, and a
        // panic, an abort or a hang is not one of them.
        for garbage in [
            &[0xffu8, 0xff, 0xff, 0xff][..],
            &[0x08][..],
            &[0x0a, 0xff, 0xff, 0xff, 0xff, 0x0f][..],
        ] {
            let outcome = decode::<v1::ControlEvent>(garbage);
            if let Err(err) = outcome {
                assert_eq!(err.reason_code().domain().as_str(), "PROTO");
            }
        }
    }
}
