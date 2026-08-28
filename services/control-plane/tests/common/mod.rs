//! The harness the component tests share.
//!
//! Everything here drives the **real** dispatch path — `wire` bounds, the dedup
//! log, the write budget, the domain handler, the journal, the commit — through
//! [`twinvpn_control_plane::store::mem::MemStore`]. Nothing is stubbed except
//! the two ports this build cannot bind on this host: signature verification
//! (`twinvpn-crypto`'s, CD-I2) and the raw-public-key peer verifier.
//!
//! `now` and `now_ms` are **parameters**, never clock reads, so a 24-hour dedup
//! window and a 120-second ceremony expiry cost no wall time and a failure
//! reproduces from its inputs (`architecture.md` §5.2 R-DET-1).

#![allow(dead_code)]
// `ServiceError` is 128 bytes because it carries a `Diagnostic` with its typed
// evidence set — see `src/lib.rs` for the reason the crate accepts that. The
// harness returns the crate's own error type, so it inherits the allowance.
#![allow(clippy::result_large_err)]

use std::time::{Duration, Instant};

use prost::Message;
use twinvpn_control_plane as cp;
use twinvpn_control_plane::store::{Committed, ControlStore, Request};
use twinvpn_control_plane::verify::testing::ScriptedVerifier;
use twinvpn_control_plane::verify::Delegation;
use twinvpn_control_plane::verify::{RefuseUnverifiable, StatementVerifier};
use twinvpn_control_plane::{CommandCode, EventKind};
use twinvpn_crypto::statements::OskPower;
use twinvpn_schema::v1;
use twinvpn_service_common::{Correlation, ServiceError};

pub const TWINNET: &str = "twn_test";

/// A `TwinNet` under test.
pub struct Net {
    pub store: cp::store::mem::MemStore,
    pub endpoints: Vec<String>,
    pub base: Instant,
}

impl Net {
    #[must_use]
    pub fn new() -> Self {
        Self {
            store: cp::store::mem::MemStore::new(),
            endpoints: vec!["cp.twinvpn.example".to_owned()],
            base: Instant::now(),
        }
    }

    /// Runs one command. `now_ms` is wall-clock evidence; `elapsed` drives the
    /// rate limiters, and both are supplied rather than read.
    pub fn run(
        &self,
        caller: [u8; 32],
        code: CommandCode,
        body: &[u8],
        now_ms: u64,
        elapsed: Duration,
        verifier: &dyn StatementVerifier,
    ) -> Result<Committed, ServiceError> {
        futures::executor::block_on(self.store.execute(Request {
            twinnet_id: TWINNET,
            caller,
            caller_identity_key: None,
            now_ms,
            now: self.base + elapsed,
            verifier,
            quorum_available: true,
            correlation: Correlation::empty(),
            coordination_endpoints: &self.endpoints,
            code,
            body,
        }))
    }

    /// [`Net::run`] with quorum unreachable, for the E-1 refusal.
    pub fn run_without_quorum(
        &self,
        caller: [u8; 32],
        code: CommandCode,
        body: &[u8],
        now_ms: u64,
        verifier: &dyn StatementVerifier,
    ) -> Result<Committed, ServiceError> {
        futures::executor::block_on(self.store.execute(Request {
            twinnet_id: TWINNET,
            caller,
            caller_identity_key: None,
            now_ms,
            now: self.base,
            verifier,
            quorum_available: false,
            correlation: Correlation::empty(),
            coordination_endpoints: &self.endpoints,
            code,
            body,
        }))
    }

    /// [`Net::run`] with a proven channel key behind the caller.
    ///
    /// This is what the transport supplies on a real connection
    /// (`serve::Peer::identity_cose_key`): the COSE_Key form of the RFC 7250 raw
    /// public key the peer proved possession of in the handshake. The tests that
    /// need it are the ones about *which* key a claim is checked against —
    /// enrolment binding, and a rotated device's successor.
    #[allow(clippy::too_many_arguments)]
    pub fn run_with_channel_key(
        &self,
        caller: [u8; 32],
        channel_key: &[u8],
        code: CommandCode,
        body: &[u8],
        now_ms: u64,
        elapsed: Duration,
        verifier: &dyn StatementVerifier,
    ) -> Result<Committed, ServiceError> {
        futures::executor::block_on(self.store.execute(Request {
            twinnet_id: TWINNET,
            caller,
            caller_identity_key: Some(channel_key),
            now_ms,
            now: self.base + elapsed,
            verifier,
            quorum_available: true,
            correlation: Correlation::empty(),
            coordination_endpoints: &self.endpoints,
            code,
            body,
        }))
    }

    /// The `device_id` a presented identity currently resolves to.
    pub fn device_for_identity(&self, identity_id: [u8; 32]) -> Option<[u8; 32]> {
        futures::executor::block_on(self.store.device_for_identity(TWINNET, identity_id))
            .expect("the lookup answers")
    }

    /// The stored record for `device_id`.
    pub fn record(&self, device_id: [u8; 32]) -> Option<cp::model::DeviceRecord> {
        self.store
            .snapshot(TWINNET)
            .and_then(|s| s.devices.get(&device_id).cloned())
    }

    /// The durable events after `from`.
    pub fn events(&self, from: u64) -> Result<Vec<cp::model::StoredEvent>, ServiceError> {
        futures::executor::block_on(self.store.events_from(TWINNET, from, 4096))
    }

    /// The event types appended, in order.
    pub fn event_types(&self) -> Vec<EventKind> {
        self.events(0)
            .expect("retained")
            .into_iter()
            .map(|e| e.event_type)
            .collect()
    }

    /// The current head position.
    pub fn head(&self) -> u64 {
        futures::executor::block_on(self.store.head(TWINNET)).expect("head")
    }

    /// The current trust epoch.
    pub fn trust_epoch(&self) -> u64 {
        futures::executor::block_on(self.store.trust_epoch(TWINNET)).expect("epoch")
    }
}

impl Default for Net {
    fn default() -> Self {
        Self::new()
    }
}

/// A delegation carrying `powers`, for an OSK named `osk_id`.
///
/// Real deployments decode these from ORK-signed `OwnerDelegation` statements;
/// a test builds one directly so it can ask what happens when a power is
/// **missing**, which is the case that matters.
#[must_use]
pub fn delegation(osk_id: &str, powers: &[OskPower]) -> Delegation {
    Delegation {
        osk_id: osk_id.to_owned(),
        osk_pub_cose: vec![0xa5; 8],
        powers: powers.to_vec(),
        anchor_version: 1,
        not_after_ms: 0,
    }
}

/// A verifier that attributes every statement to the `Owner` **root**.
///
/// The ORK is unscoped by construction — it is the key every delegation chains
/// to — so this double needs no powers for the statements it signs. It still
/// has to *grant* `ENROLL` on the enrolment proof it presents, because
/// `RegisterDevice`'s authorisation is the delegation inside the proof rather
/// than whoever signed it.
#[must_use]
pub fn owner() -> ScriptedVerifier {
    ScriptedVerifier::owner().granting(delegation("osk-enroll", &[OskPower::Enroll]))
}

/// An `Owner` verifier whose **signer** is an OSK holding exactly `powers`.
///
/// This is what a real deployment looks like: the root is offline and a
/// per-device signing key does the work. A test that wants a refusal asks for a
/// key without the power the operation needs.
#[must_use]
pub fn owner_osk(powers: &[OskPower]) -> ScriptedVerifier {
    ScriptedVerifier::owner()
        .held_by(delegation("osk-1", powers))
        .granting(delegation("osk-1", powers))
}

/// A verifier that attributes every statement to a device.
#[must_use]
pub fn device() -> ScriptedVerifier {
    ScriptedVerifier::device()
}

/// A device verifier that reports an attestation for ceremony `pairing_id`.
///
/// `CompletePairing` refuses an attestation that does not name the ceremony it
/// is completing, so a double that reported none would make every completion
/// fail — and a check that the double could not satisfy is a check no test could
/// distinguish from a broken one.
#[must_use]
pub fn device_attesting(pairing_id: u8) -> ScriptedVerifier {
    ScriptedVerifier::device().attesting_to([pairing_id; 16])
}

/// The fail-closed verifier this build ships.
pub const NO_ANCHOR: RefuseUnverifiable = RefuseUnverifiable;

/// A non-empty COSE_Sign1 stand-in. Deliberately CBOR-shaped, not protobuf.
#[must_use]
pub fn cose(tag: u8) -> v1::SignedStatement {
    v1::SignedStatement {
        cose_sign1: vec![0xd2, 0x84, 0x43, tag],
        statement_type: 0,
    }
}

/// A `device_id`, filled with `n`.
#[must_use]
pub fn dev(n: u8) -> [u8; 32] {
    [n; 32]
}

/// An idempotency key of the frozen minimum width, filled with `n`.
#[must_use]
pub fn key(n: u8) -> Vec<u8> {
    vec![n; 16]
}

/// `MessageMetadata` carrying an idempotency key.
#[must_use]
pub fn meta(k: &[u8]) -> Option<v1::MessageMetadata> {
    Some(v1::MessageMetadata {
        proto_version: 1,
        twinnet_id: TWINNET.to_owned(),
        idempotency_key: k.to_vec(),
        ..Default::default()
    })
}

/// A well-formed `RegisterDeviceRequest` for `id`.
#[must_use]
pub fn register_request(id: u8, k: &[u8]) -> Vec<u8> {
    v1::RegisterDeviceRequest {
        metadata: meta(k),
        identity: Some(v1::DeviceIdentity {
            identity_id: dev(id).to_vec(),
            device_id: dev(id).to_vec(),
            generation: 0,
            identity_public_key: vec![id, id, id, id],
            identity_key_algorithm: v1::IdentityKeyAlgorithm::Es256 as i32,
            tunnel_public_key: vec![id],
            tunnel_key_algorithm: v1::TunnelKeyAlgorithm::X25519 as i32,
            tk_generation: 0,
            tunnel_key_binding: Some(cose(id)),
            hardware_backed: false,
            created_at_ms: 0,
        }),
        key_attestation: Vec::new(),
        platform: None,
        declared_roles: vec![v1::DeviceRole::Client as i32],
        protocol_version: Some(v1::ProtocolVersion { v_max: 1, v_min: 1 }),
        capabilities: None,
        enrollment_proof: Some(cose(id)),
    }
    .encode_to_vec()
}

/// Registers `id` and returns the committed response.
pub fn register(net: &Net, id: u8, now_ms: u64) -> Committed {
    net.run(
        dev(id),
        CommandCode::RegisterDevice,
        &register_request(id, &key(id)),
        now_ms,
        Duration::from_secs(u64::from(id) * 60),
        &owner(),
    )
    .expect("registers")
}

/// A `BeginPairingRequest`.
#[must_use]
pub fn begin_pairing_request(pairing_id: u8, k: &[u8]) -> Vec<u8> {
    v1::BeginPairingRequest {
        metadata: meta(k),
        pairing: Some(v1::PairingRequest {
            pairing_id: vec![pairing_id; 16],
            twinnet_id: TWINNET.to_owned(),
            ..Default::default()
        }),
    }
    .encode_to_vec()
}

/// A `CompletePairingRequest` at `if_version`.
#[must_use]
pub fn complete_pairing_request(pairing_id: u8, k: &[u8], if_version: u64, attest: u8) -> Vec<u8> {
    v1::CompletePairingRequest {
        metadata: meta(k),
        pairing_id: vec![pairing_id; 16],
        attestation: Some(v1::PairingAttestation {
            statement: Some(cose(attest)),
            attesting_device_id: Vec::new(),
        }),
        precondition: Some(v1::VersionPrecondition {
            precondition: Some(v1::version_precondition::Precondition::IfVersion(
                if_version,
            )),
        }),
    }
    .encode_to_vec()
}

/// A `RevokeDeviceRequest` for `target`.
#[must_use]
pub fn revoke_request(target: u8, k: &[u8]) -> Vec<u8> {
    v1::RevokeDeviceRequest {
        metadata: meta(k),
        target_device_id: dev(target).to_vec(),
        revocation_statement: Some(cose(target)),
        reason_code: "AUTH.DEVICE_REVOKED".to_owned(),
    }
    .encode_to_vec()
}

/// A `PutPolicyRequest` at `version`, conditional on `if_version`.
#[must_use]
pub fn put_policy_request(version: u64, if_version: u64, k: &[u8], content: u8) -> Vec<u8> {
    v1::PutPolicyRequest {
        metadata: meta(k),
        bundle: Some(v1::PolicyBundle {
            twinnet_id: TWINNET.to_owned(),
            policy_version: version,
            policy_id: "pol".to_owned(),
            signed: Some(cose(content)),
            ..Default::default()
        }),
        precondition: Some(v1::VersionPrecondition {
            precondition: Some(v1::version_precondition::Precondition::IfVersion(
                if_version,
            )),
        }),
    }
    .encode_to_vec()
}

/// A `PutRouteAdvertisementRequest` at `epoch`.
#[must_use]
pub fn put_route_request(advertiser: u8, epoch: u64) -> Vec<u8> {
    v1::PutRouteAdvertisementRequest {
        metadata: meta(&[]),
        advertisement: Some(v1::RouteAdvertisement {
            advertiser_device_id: dev(advertiser).to_vec(),
            twinnet_id: TWINNET.to_owned(),
            prefixes_v4: vec![v1::RoutePrefix {
                prefix: Some(v1::IpPrefix {
                    address: Some(v1::IpAddress {
                        address: Some(v1::ip_address::Address::V4(v1::IPv4Address {
                            octets: vec![10, 7, 0, 0],
                        })),
                    }),
                    prefix_len: 24,
                }),
                metric: 10,
            }],
            prefixes_v6: Vec::new(),
            advertisement_epoch: epoch,
            not_after_ms: 0,
            requires_capability: Vec::new(),
            signed: Some(cose(advertiser)),
        }),
    }
    .encode_to_vec()
}

/// Decodes a `MutationResult` out of any mutating response.
#[must_use]
pub fn mutation_of<M: Message + Default>(
    bytes: &[u8],
    get: impl Fn(&M) -> Option<v1::MutationResult>,
) -> v1::MutationResult {
    let msg = M::decode(bytes).expect("the response decodes");
    get(&msg).expect("a mutating response carries a MutationResult")
}
