//! §2.13's database outage, against the control plane's real store seam.
//!
//! **Authority:** `docs/testing-strategy.md` §2.13 and §3.4's fault rows;
//! ADR-0002 §11.3 and N-4; ADR-0009 §11.2; `docs/architecture.md` **I5**;
//! `infra/README.md` §5.
//!
//! # Why the outage is injected at `ControlStore` and not at a socket
//!
//! `PgStore` **has never been run**: this host has no PostgreSQL and no Docker,
//! and `services/control-plane/README.md` §9 says so rather than leaving it to be
//! discovered. Killing a database that is not there would test nothing.
//!
//! What *is* real is the seam. [`ControlStore`] is the trait every command goes
//! through, `MemStore` and `PgStore` both implement it, and every rule the
//! outage could break — the dedup log, `net_seq` allocation inside the mutating
//! transaction, the never-shrinking revoked set — lives in `domain` and `tx`
//! **above** it. So a store that starts failing exercises the same refusal path
//! a database outage would, and the two properties that matter are decidable:
//! the refusal is typed, and nothing is left half-applied.
//!
//! Stated plainly so nobody reads more into it: this shows the control plane
//! behaves correctly when its store fails. It does **not** show that
//! PostgreSQL's failure modes are the ones modelled here. That claim needs a
//! PostgreSQL, and this host has none.
//!
//! # The two outages, kept apart
//!
//! `infra/README.md` §5 makes readiness two facts, and §3.4 asks for them
//! separately:
//!
//! | Outage | What fails | What must still work |
//! |---|---|---|
//! | **unreachable** | everything | nothing — but the refusal must be typed and the probe must say so |
//! | **no write lease** (ADR-0002 N-4) | mutations only | every read. A control plane that stopped answering reads because it could not write would turn a leader election into a total outage |

#![allow(clippy::result_large_err)]

use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

use futures::future::BoxFuture;
use prost::Message;
use twinvpn_control_plane::store::{Committed, ControlStore, Request, StoreHealth};
use twinvpn_control_plane::verify::testing::ScriptedVerifier;
use twinvpn_control_plane::verify::{Delegation, StatementVerifier};
use twinvpn_control_plane::CommandCode;
use twinvpn_crypto::statements::OskPower;
use twinvpn_schema::v1;
use twinvpn_service_common::{Correlation, ServiceError};
use twinvpn_types::codes;

const TWINNET: &str = "twn_outage";

/// What the store is doing right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    /// Healthy.
    None = 0,
    /// The datastore does not answer at all.
    Unreachable = 1,
    /// The datastore answers; this process cannot obtain the write lease.
    NoWriteLease = 2,
}

/// A [`ControlStore`] that can be made to fail, wrapping the real one.
///
/// Everything it does not fail is delegated, so a command that gets through
/// takes the identical path it takes with no wrapper at all. A double that
/// re-implemented the store would be a second answer to "may this epoch go
/// backwards", and only one of them would get tested.
struct FaultyStore {
    inner: twinvpn_control_plane::store::mem::MemStore,
    fault: AtomicU8,
}

impl FaultyStore {
    fn new() -> Self {
        FaultyStore {
            inner: twinvpn_control_plane::store::mem::MemStore::new(),
            fault: AtomicU8::new(Fault::None as u8),
        }
    }

    fn set(&self, fault: Fault) {
        self.fault.store(fault as u8, Ordering::SeqCst);
    }

    fn fault(&self) -> Fault {
        match self.fault.load(Ordering::SeqCst) {
            1 => Fault::Unreachable,
            2 => Fault::NoWriteLease,
            _ => Fault::None,
        }
    }
}

/// The refusal an unreachable datastore produces.
fn unreachable() -> ServiceError {
    // The registered code, taken from the frozen registry rather than typed as
    // a string here: a fault injector that invented a code would be testing
    // that this file agrees with itself.
    ServiceError::new(
        codes::CONTROL_WRITE_LEADER_UNAVAILABLE,
        twinvpn_service_common::Component::CoordinationService,
    )
    .build()
}

impl ControlStore for FaultyStore {
    fn execute<'a>(
        &'a self,
        request: Request<'a>,
    ) -> BoxFuture<'a, Result<Committed, ServiceError>> {
        // Both faults refuse a mutation, and both refuse it BEFORE the inner
        // store sees it. That ordering is the property: a refusal that happened
        // after the transaction would leave the effect behind.
        if self.fault() != Fault::None {
            return Box::pin(async { Err(unreachable()) });
        }
        self.inner.execute(request)
    }

    fn events_from<'a>(
        &'a self,
        twinnet_id: &'a str,
        from_net_seq: u64,
        max: usize,
    ) -> BoxFuture<'a, Result<Vec<twinvpn_control_plane::model::StoredEvent>, ServiceError>> {
        if self.fault() == Fault::Unreachable {
            return Box::pin(async { Err(unreachable()) });
        }
        self.inner.events_from(twinnet_id, from_net_seq, max)
    }

    fn device_for_identity<'a>(
        &'a self,
        twinnet_id: &'a str,
        identity_id: twinvpn_control_plane::model::DeviceKey,
    ) -> BoxFuture<'a, Result<Option<twinvpn_control_plane::model::DeviceKey>, ServiceError>> {
        if self.fault() == Fault::Unreachable {
            return Box::pin(async { Err(unreachable()) });
        }
        self.inner.device_for_identity(twinnet_id, identity_id)
    }

    fn head<'a>(&'a self, twinnet_id: &'a str) -> BoxFuture<'a, Result<u64, ServiceError>> {
        if self.fault() == Fault::Unreachable {
            return Box::pin(async { Err(unreachable()) });
        }
        self.inner.head(twinnet_id)
    }

    fn trust_epoch<'a>(&'a self, twinnet_id: &'a str) -> BoxFuture<'a, Result<u64, ServiceError>> {
        if self.fault() == Fault::Unreachable {
            return Box::pin(async { Err(unreachable()) });
        }
        self.inner.trust_epoch(twinnet_id)
    }

    fn probe(&self) -> BoxFuture<'_, Result<StoreHealth, ServiceError>> {
        let fault = self.fault();
        Box::pin(async move {
            Ok(StoreHealth {
                reachable: fault != Fault::Unreachable,
                lease_held: fault == Fault::None,
            })
        })
    }
}

// ---------------------------------------------------------------------------

fn owner() -> ScriptedVerifier {
    ScriptedVerifier::owner().granting(Delegation {
        osk_id: "osk-enroll".to_owned(),
        osk_pub_cose: vec![0xa5; 8],
        powers: vec![OskPower::Enroll],
        anchor_version: 1,
        not_after_ms: 0,
    })
}

fn cose(tag: u8) -> v1::SignedStatement {
    v1::SignedStatement {
        cose_sign1: vec![0xd2, 0x84, 0x43, tag],
        statement_type: 0,
    }
}

fn register_body(id: u8, key: u8) -> Vec<u8> {
    v1::RegisterDeviceRequest {
        metadata: Some(v1::MessageMetadata {
            idempotency_key: vec![key; 16],
            ..Default::default()
        }),
        identity: Some(v1::DeviceIdentity {
            identity_id: [id; 32].to_vec(),
            device_id: [id; 32].to_vec(),
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

struct Net {
    store: FaultyStore,
    base: Instant,
    endpoints: Vec<String>,
}

impl Net {
    fn new() -> Self {
        Net {
            store: FaultyStore::new(),
            base: Instant::now(),
            endpoints: vec!["cp.twinvpn.example".to_owned()],
        }
    }

    fn register(&self, id: u8, key: u8) -> Result<Committed, ServiceError> {
        let body = register_body(id, key);
        let verifier = owner();
        futures::executor::block_on(self.store.execute(Request {
            twinnet_id: TWINNET,
            caller: [id; 32],
            caller_identity_key: None,
            now_ms: 10_000 + u64::from(id),
            now: self.base + Duration::from_secs(u64::from(id) * 60),
            verifier: &verifier as &dyn StatementVerifier,
            quorum_available: true,
            correlation: Correlation::empty(),
            coordination_endpoints: &self.endpoints,
            code: CommandCode::RegisterDevice,
            body: &body,
        }))
    }

    fn head(&self) -> Result<u64, ServiceError> {
        futures::executor::block_on(self.store.head(TWINNET))
    }

    fn net_seqs(&self) -> Vec<u64> {
        futures::executor::block_on(self.store.events_from(TWINNET, 0, 1024))
            .expect("the log must be readable")
            .iter()
            .map(|e| e.net_seq)
            .collect()
    }
}

// ===========================================================================

#[test]
fn a_mutation_during_a_store_outage_is_refused_with_a_registered_code() {
    let net = Net::new();
    // V3: the precondition is asserted. A command that could not succeed
    // healthy would be refused during the outage for the wrong reason.
    net.register(1, 1)
        .expect("the precondition: a healthy store commits");
    let before = net.head().expect("a head");

    net.store.set(Fault::Unreachable);
    let refused = net
        .register(2, 2)
        .expect_err("an unreachable store must refuse");
    // The envelope is what a caller actually receives, so that is what the
    // code is read from — not a field of the internal error type.
    assert_eq!(
        refused.envelope().reason_code,
        "CONTROL.WRITE_LEADER_UNAVAILABLE",
        "the refusal must carry a registered code, not a bare error: {refused:?}"
    );

    net.store.set(Fault::None);
    let after = net.head().expect("a head");
    assert_eq!(
        before, after,
        "the log head moved across a refused mutation: {before} -> {after}. A store \
         failure must leave nothing behind — `net_seq` is allocated inside the mutating \
         transaction (ADR-0002 §11.3 B-3), so a consumed sequence number would mean a \
         partially applied command."
    );
}

#[test]
fn the_log_stays_dense_across_an_outage_so_a_failed_write_consumes_no_position() {
    let net = Net::new();
    net.register(1, 1).expect("the first registration commits");

    net.store.set(Fault::Unreachable);
    assert!(net.register(2, 2).is_err(), "the outage must refuse");
    net.store.set(Fault::None);

    net.register(3, 3)
        .expect("the store recovered and the command commits");

    let seqs = net.net_seqs();
    assert!(
        seqs.len() >= 2,
        "two commands committed and the log holds {} events",
        seqs.len()
    );
    let dense = seqs.windows(2).all(|w| w[1] == w[0] + 1);
    assert!(
        dense,
        "the durable log has a gap after an outage: {seqs:?}. A consumer replaying it \
         cannot tell a gap from a lost event."
    );
}

#[test]
fn the_readiness_probe_reports_the_outage_rather_than_leaving_it_silent() {
    let net = Net::new();
    let healthy = futures::executor::block_on(net.store.probe()).expect("a probe");
    assert!(
        healthy.is_ready(),
        "a healthy store must be ready, or the two assertions below mean nothing"
    );

    net.store.set(Fault::Unreachable);
    let down = futures::executor::block_on(net.store.probe()).expect("a probe");
    assert!(
        !down.reachable && !down.is_ready(),
        "an unreachable datastore reported ready: {down:?}"
    );

    // ADR-0002 N-4: one writer per TwinNet, under a lease. A follower is
    // reachable and cannot write — and the product's answer is that it is
    // **still ready**, which this test asserts rather than second-guesses:
    //
    // > Mutations are refused with `CONTROL.WRITE_LEADER_UNAVAILABLE`, which is
    // > TRANSIENT and retryable. Taking every follower out of service during a
    // > normal leader handover would turn a handover into an outage.
    //
    // This assertion was originally written the other way round — that a
    // lease-less writer must report not-ready — and it was wrong. It asserted a
    // design this test's author assumed instead of the one the service
    // documents, and the service is right: readiness is about serving traffic,
    // and a follower serves reads.
    //
    // The property that must hold is that the condition is **visible**, and it
    // is: `lease_held` says so, and it is a separate fact from `reachable`
    // precisely so an operator can tell a handover from an outage.
    net.store.set(Fault::NoWriteLease);
    let follower = futures::executor::block_on(net.store.probe()).expect("a probe");
    assert!(
        follower.reachable,
        "a lease-less writer's datastore is still reachable"
    );
    assert!(
        !follower.lease_held,
        "the lease-less condition must be visible in the probe, or an operator cannot \
         tell a leader handover from a healthy writer: {follower:?}"
    );
    assert!(
        follower.is_ready(),
        "a reachable follower must stay in service; taking every follower out during a \
         normal handover would turn a handover into an outage: {follower:?}"
    );
}

#[test]
fn a_lease_less_writer_refuses_mutations_and_still_answers_reads() {
    let net = Net::new();
    net.register(1, 1).expect("the precondition commits");
    let head = net.head().expect("a head");
    let seqs = net.net_seqs();

    net.store.set(Fault::NoWriteLease);
    assert!(
        net.register(2, 2).is_err(),
        "a writer without the lease must refuse a mutation (ADR-0002 N-4)"
    );

    // The half that matters operationally: a leader election is not a total
    // outage. A control plane that stopped answering reads because it could not
    // write would take every reader down with the writer — and I5 says an
    // outage must not tear down what is already established.
    assert_eq!(
        net.head().expect("reads must still be answered"),
        head,
        "a lease-less writer stopped answering the head"
    );
    assert_eq!(
        net.net_seqs(),
        seqs,
        "a lease-less writer stopped serving the durable log"
    );
}

#[test]
fn the_same_command_succeeds_once_the_store_comes_back() {
    let net = Net::new();
    net.store.set(Fault::Unreachable);
    let body_key = 9;
    assert!(
        net.register(4, body_key).is_err(),
        "the outage must refuse the first attempt"
    );

    net.store.set(Fault::None);
    let recovered = net
        .register(4, body_key)
        .expect("the identical command must commit once the store returns");
    assert!(
        recovered.committed_at_net_seq > 0,
        "the recovered command committed at position {}",
        recovered.committed_at_net_seq
    );
    assert!(
        !recovered.idempotent_replay,
        "the refused attempt reached the dedup log, so the retry was served as a replay \
         of a command that never committed"
    );

    // And it is not a duplicate of anything: the refused attempt never reached
    // the dedup log, so this is a first execution rather than a replayed one.
    let seqs = net.net_seqs();
    assert_eq!(
        seqs.len(),
        1,
        "the refused attempt left a record behind: {seqs:?}"
    );
}
