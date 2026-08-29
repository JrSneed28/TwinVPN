//! The fixtures both pairing test targets share.
//!
//! Not a test target of its own: cargo builds `tests/*.rs`, so a file one level
//! down is a module to be included rather than a binary to be run. Both
//! `tests/pairing.rs` and `tests/pairing_refusals.rs` pull it in with `#[path]`,
//! which is why the unused-item allows below are here and not at either call
//! site — each target uses a different subset, and that is the point of sharing.

#![allow(dead_code, unused_imports)]

use std::sync::Arc;
use std::time::Duration;

use twinvpn_core::pairing::{Ceremony, PairingEnrolment, PAIRING_ID_BYTES};
use twinvpn_core::testing;
use twinvpn_core::Core;
use twinvpn_crypto::statements::{OskPower, OwnerDelegation};
use twinvpn_crypto::testkit::FixtureIdentity;
use twinvpn_env::virtual_time::VirtualTime;
use twinvpn_env::{WallClockReading, WallMillis};
use twinvpn_mgmt::{CoreCommand, Submission};
use twinvpn_platform::mock::MockAdapter;
use twinvpn_trust::owner::VerifiedSigner;
use twinvpn_trust::{AnchorChain, RevocationState};
use twinvpn_types::ReasonCode;

/// A plausible UTC reading. ADR-0007 §7.4 field 7 is `issued + 120 000`, so the
/// ceremony's whole arithmetic hangs off this one number.
pub const WALL_MS: u64 = 1_800_000_000_000;

/// The `osk_id` the fixture Owner delegates to.
pub const APPROVER: &str = "osk-enrolment";

/// The seed behind this device's identity key in every fixture below.
pub const DEVICE_IK_SEED: &[u8] = b"this-device-ik";

/// `pair.status`'s state byte for a running ceremony (`twinvpn_core::pairing`).
pub const PENDING: u8 = 1;
/// Its byte for one the 120-second window has passed.
pub const EXPIRED: u8 = 3;
/// Its byte for one a participant cancelled.
pub const ABORTED: u8 = 4;

/// A mock-bound core whose element, clock and Owner chain are all set up for a
/// C-B ceremony.
pub struct Enrolled {
    /// The composed core.
    pub core: Core,
    /// The adapter it is bound to, for asserting what the element was asked.
    pub adapter: Arc<MockAdapter>,
    /// The virtual clock, so N-17's window costs no wall time.
    pub time: VirtualTime,
}

/// A delegation carrying exactly `powers`.
pub fn delegation(powers: Vec<OskPower>) -> OwnerDelegation {
    OwnerDelegation {
        twinnet_id: "tn-test".to_owned(),
        osk_id: APPROVER.to_owned(),
        osk_pub_cose: FixtureIdentity::from_seed(b"osk").cose_key(),
        powers,
        anchor_version: 0,
        not_after_ms: WALL_MS + 86_400_000,
    }
}

/// A mock-bound core with a usable clock and a signing element, and nothing
/// else — the state a device is in before anyone enrols it.
pub fn bare() -> (Core, Arc<MockAdapter>, VirtualTime) {
    let (parts, adapter, time) = testing::parts();
    let core = Core::create(parts).expect("create");
    time.set_wall(WallClockReading::Trusted {
        millis: WallMillis::from_millis(WALL_MS),
    });
    adapter.identity_mock().allow_insecure_stub_signer();
    (core, adapter, time)
}

/// Builds a core, points the mock element at the fixture key, and installs an
/// enrolment record whose approver carries `powers`.
///
/// The element's `identity_id` is **moved to match** the injected `COSE_Key`
/// rather than the other way round: ADR-0007 N-2 makes `identity_id` the digest
/// of that key, and `twinvpn_core::pairing` refuses the pair unless they agree.
/// A fixture that did not line them up would be testing the mismatch path.
pub fn enrolled_with(powers: Vec<OskPower>, revocation: RevocationState) -> Enrolled {
    let (core, adapter, time) = bare();

    let cose = FixtureIdentity::from_seed(DEVICE_IK_SEED).cose_key();
    adapter
        .identity_mock()
        .rotate(twinvpn_trust::derive_identity_id(&cose));

    let mut chain = AnchorChain::new();
    chain
        .install_delegation(delegation(powers))
        .expect("install the delegation");

    let enrolment = PairingEnrolment::new(
        chain,
        vec![VerifiedSigner::osk(APPROVER)],
        revocation,
        cose,
        "rv.example".to_owned(),
    )
    .expect("a well-formed enrolment record");
    core.install_pairing_enrolment(enrolment);

    Enrolled {
        core,
        adapter,
        time,
    }
}

/// The common case: an approver holding `ENROLL`, and nothing revoked.
pub fn enrolled() -> Enrolled {
    enrolled_with(vec![OskPower::Enroll], RevocationState::new())
}

/// A `pair.begin` submission for `ceremony`, under `key`.
pub fn begin_with(ceremony: Ceremony, key: &[u8]) -> Submission {
    Submission {
        op: CoreCommand::PairBegin,
        params: vec![ceremony.to_params()],
        idempotency_key: Some(key.to_vec()),
        if_version: None,
        actor_principal: None,
    }
}

/// The ordinary C-B begin.
pub fn begin(key: &[u8]) -> Submission {
    begin_with(Ceremony::ConfidentialChannel, key)
}

/// A `pair.cancel` or `pair.status` naming `pairing_id`.
pub fn named(op: CoreCommand, pairing_id: &[u8; PAIRING_ID_BYTES]) -> Submission {
    Submission {
        op,
        params: pairing_id.to_vec(),
        idempotency_key: None,
        if_version: None,
        actor_principal: None,
    }
}

/// The body a completed operation published, read off the **one ordered event
/// stream** rather than out of a return value.
///
/// `submit` is documented to report through the stream, so a test that read
/// anywhere else would not be exercising the path a shell uses.
pub fn body_from_events(core: &Core, op: CoreCommand) -> Vec<u8> {
    while let Some(event) = core.next_event(Duration::ZERO) {
        if let twinvpn_core::CoreEventKind::CommandCompleted { op: seen, result } = event.kind {
            if seen == op.name() {
                return result;
            }
        }
    }
    panic!("{} published no CommandCompleted", op.name());
}

/// The `pairing_id` a completed `pair.begin` published.
pub fn pairing_id_from_events(core: &Core) -> [u8; PAIRING_ID_BYTES] {
    <[u8; PAIRING_ID_BYTES]>::try_from(body_from_events(core, CoreCommand::PairBegin).as_slice())
        .expect("pair.begin answers with a pairing_id")
}

/// The state byte `pair.status` reports for `pairing_id`.
pub fn status_of(core: &Core, pairing_id: &[u8; PAIRING_ID_BYTES]) -> u8 {
    core.submit(&named(CoreCommand::PairStatus, pairing_id))
        .expect("pair.status");
    body_from_events(core, CoreCommand::PairStatus)[0]
}

/// The registered code a refusal carries.
pub fn refused(core: &Core, submission: &Submission) -> ReasonCode {
    core.submit(submission)
        .expect_err("this submission must be refused")
        .code()
}
