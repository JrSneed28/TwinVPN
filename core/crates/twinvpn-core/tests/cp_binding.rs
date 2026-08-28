//! **The composed core's control-plane binding**: does it build a real
//! L-CONTROL transport from what the core holds, and does every way of failing
//! fail closed with the code that names the actual fact?
//!
//! **Authority:** [ADR-0018](../../../../docs/adr/ADR-0018-shared-core-and-build-architecture.md)
//! §11.7 CD-I5, CB-1, CB-3, CB-5 / **I4**, CD-2, CD-5 (the whole composed core
//! on a plain Linux CI runner); [ADR-0001](../../../../docs/adr/ADR-0001-cryptographic-architecture.md)
//! §11 item 3, §7.2; [ADR-0002](../../../../docs/adr/ADR-0002-control-plane-messaging-and-event-bus.md)
//! §11.2; [ADR-0007](../../../../docs/adr/ADR-0007-identity-lifecycle-and-revocation.md)
//! S-32; [ADR-0010](../../../../docs/adr/ADR-0010-ipv4-ipv6-routing.md) **R1**;
//! `ownership.md` §8 **W-12**.
//!
//! # What this file establishes, and — read this before citing it — what it does not
//!
//! **Establishes.** That `ControlTransportBinding::bind` sources the arguments
//! the composition root is responsible for from core-held state and from the
//! platform adapter, that it refuses by name when a value is genuinely absent,
//! and that the object it builds is a **real** transport — `attach` opens a
//! socket and speaks QUIC at a real address, rather than a scripted double that
//! returns success without presenting a key.
//!
//! **Does not establish.** Handshake success, mutual RFC 7250 raw-public-key
//! authentication, the pinned key being the one presented, the RFC 9266 channel
//! binding agreeing between the ends, C2 on its own stream, or ADR-0002 N-1's
//! supersession. Each needs something that terminates TLS, and each is already
//! proved against a real QUIC listener by
//! **`core/crates/twinvpn-cp-client/tests/quic_loopback.rs`** — named rather
//! than implied, because a connect-only test's failure mode is a reader
//! inferring end-to-end coverage from it.
//!
//! A second QUIC server double under `twinvpn-core` was considered and declined
//! by the integration lead: it re-proves one property the existing harness
//! already proves, and it puts `quinn` in the composition root's manifest, which
//! W-12 assigns to `twinvpn-cp-client`.
//!
//! # `software_key` is used here, and it is the hole `cp_binding` names
//!
//! Every test below builds its `DeviceIdentity` with
//! `DeviceIdentity::software_key`, because a CI runner has no platform element
//! and `MockIdentity` truthfully reports `hardware_backed: false` — which is the
//! CB-5 / I4 gap `cp_binding::transport`'s docs record. The production path
//! never calls it: `bind` takes a `DeviceIdentity` the shell constructed, and no
//! line of `src/cp_binding/` names `software_key`.

#![cfg(feature = "full")]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};

use twinvpn_core::cp_binding::transport::{ControlEndpoint, DeviceIdentity};
use twinvpn_core::cp_binding::{
    AnchorStatementVerifier, ControlPlaneEnrolment, ControlTransportBinding,
};
use twinvpn_core::testing::CountingEntropy;
use twinvpn_cp_client::ports::{StatementKind, StatementVerifier, VerifyFailure};
use twinvpn_cp_client::ReceivedOctets;
use twinvpn_crypto::emit::Item;
use twinvpn_crypto::statements::OwnerTrustAnchor;
use twinvpn_crypto::testkit::FixtureIdentity;
use twinvpn_env::binding::system::{
    ElapsedClockFn, SystemMonotonicClock, SystemWallClock, WallClockTrust,
};
use twinvpn_env::binding::tokio_rt::TokioRuntime;
use twinvpn_env::{ElapsedInstant, Entropy, Env, EnvParts, MonotonicClock, SystemRngSource};
use twinvpn_platform::mock::{MockAdapter, MockOptions};
use twinvpn_platform::PlatformAdapter;
use twinvpn_trust::AnchorChain;
use twinvpn_types::{Nat64Prefix, PerFamily, UnderlayFamilies};

// ---------------------------------------------------------------------------
// scaffolding
// ---------------------------------------------------------------------------

const SERVER_NAME: &str = "cp.test.invalid";

/// An `Env` over the **real** clock and a real tokio runtime.
///
/// CD-2: every capability is bound at construction. The virtual clock cannot be
/// used here — quinn registers a socket on tokio's I/O driver and a virtual
/// timer only advances when its own runtime drives it, so mixing the two hangs
/// rather than running fast. The `ElapsedClock` is a constant reader, which is
/// honest rather than a stub: nothing in the attach path reads the
/// suspend-inclusive clock, and `twinvpn-env` ships no production one (LC-8).
fn production_env() -> (Env, Arc<TokioRuntime>) {
    let runtime = Arc::new(TokioRuntime::work_stealing().expect("a work-stealing runtime"));
    let monotonic: Arc<dyn MonotonicClock> = Arc::new(SystemMonotonicClock::new());
    let timer = runtime.timer(Arc::clone(&monotonic));
    let entropy: Arc<dyn Entropy> = Arc::new(CountingEntropy::default());
    let env = Env::new(EnvParts {
        monotonic: Arc::clone(&monotonic),
        elapsed: ElapsedClockFn::shared(|| ElapsedInstant::from_micros(0)),
        wall: Arc::new(SystemWallClock::new(WallClockTrust::Synchronised)),
        timer,
        runtime: Arc::clone(&runtime) as Arc<dyn twinvpn_env::Runtime>,
        entropy: Arc::clone(&entropy),
        rng: Arc::new(SystemRngSource::new(entropy)),
    });
    (env, runtime)
}

/// Runs a future to completion on the bound runtime.
fn drive<F>(env: &Env, fut: F) -> F::Output
where
    F: core::future::Future + Send,
    F::Output: Send,
{
    let cell = Arc::new(Mutex::new(None));
    let sink = Arc::clone(&cell);
    env.runtime().block_on(Box::pin(async move {
        *sink.lock().expect("not poisoned") = Some(fut.await);
    }));
    let mut guard = cell.lock().expect("not poisoned");
    guard.take().expect("the future completed")
}

/// The device's identity. See this file's docs on `software_key`.
fn identity(seed: &[u8]) -> DeviceIdentity {
    DeviceIdentity::software_key(FixtureIdentity::from_seed(seed).pkcs8_der())
        .expect("the provider loads a PKCS#8 ES256 key")
}

/// A pinned enrolment aimed at `addr`.
fn enrolment(addr: SocketAddr, pins: Vec<Vec<u8>>) -> ControlPlaneEnrolment {
    let endpoint =
        ControlEndpoint::new(SERVER_NAME.to_owned(), vec![addr]).expect("one resolved address");
    ControlPlaneEnrolment::new(pins, vec![endpoint]).expect("a non-empty pin set")
}

/// A pin set that is well formed and matches nothing. Structure is what these
/// tests exercise; whether the pin matches is `quic_loopback.rs`'s question.
fn a_pin() -> Vec<Vec<u8>> {
    vec![FixtureIdentity::from_seed(b"twinvpn/core/cp-binding/server").spki_der()]
}

/// A loopback UDP port with **nothing listening on it**.
///
/// Bound and immediately released, so the number is one the OS just confirmed
/// was free rather than one this test guessed. What reaches it is a real QUIC
/// initial from a real socket — the property this file can prove without a
/// second server double.
fn a_closed_loopback_port() -> SocketAddr {
    let probe = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("binds an ephemeral port");
    let addr = probe.local_addr().expect("bound");
    drop(probe);
    addr
}

/// A mock adapter. Its default link facts are a dual-stack host's.
fn adapter() -> Arc<MockAdapter> {
    Arc::new(MockAdapter::new(&MockOptions::default()))
}

/// One `bind`, aimed at `addr`, with everything else held constant.
async fn bind_at(
    env: &Env,
    adapter: &Arc<MockAdapter>,
    addr: SocketAddr,
) -> Result<ControlTransportBinding, Box<twinvpn_types::Diagnostic>> {
    ControlTransportBinding::bind(
        env,
        adapter.as_ref() as &dyn PlatformAdapter,
        &identity(b"twinvpn/core/cp-binding/device"),
        enrolment(addr, a_pin()),
    )
    .await
}

/// Overrides what the host says it carries. ADR-0010 R1: family is data.
fn set_families(adapter: &Arc<MockAdapter>, families: UnderlayFamilies) {
    adapter
        .config_mock()
        .set_link_facts(twinvpn_platform::config::LinkFacts {
            mtu: 1500,
            families,
            default_routes: PerFamily::new(true, true),
            resolvers: PerFamily::new(Vec::new(), Vec::new()),
            metered: false,
            low_power: false,
        });
}

// ---------------------------------------------------------------------------
// the transport binding
// ---------------------------------------------------------------------------

#[test]
fn the_composed_core_builds_a_real_control_transport_from_core_held_state() {
    let (env, _runtime) = production_env();
    let adapter = adapter();
    let addr = a_closed_loopback_port();

    let binding = drive(&env, bind_at(&env, &adapter, addr))
        .expect("the composed core builds its L-CONTROL transport");

    // The families are the HOST's, read through the platform seam (CB-3), not a
    // constant this crate chose. The mock reports dual-stack.
    let families = binding.families();
    assert!(families.v4 && families.v6, "both families, ADR-0010 R1");
    assert!(!families.nat64, "a dual-stack host discovers no PREF64");

    // The attach config carries the coordination NAME, which is what goes in
    // SNI. A literal there would break a GeoDNS front-end answering one name
    // from several regions.
    let config = binding.attach_config(false);
    assert_eq!(config.coordination_endpoints, vec![SERVER_NAME]);
    assert_eq!(config.rung, twinvpn_cp_client::Rung::Quic);
    // ADR-0001 R8, asserted at the composition root as well as inside the
    // transport: there is no value of this type but `Prohibited`, so a binding
    // that wanted early data could not spell it.
    assert_eq!(
        config.early_data(),
        twinvpn_cp_client::transport::EarlyData::Prohibited
    );
}

#[test]
fn an_unreachable_control_plane_is_control_unreachable_and_a_missing_key_is_not() {
    // The pair, in one test, because the property is that they DIFFER. Two
    // separate tests could both pass while both paths returned the same code,
    // which is the defect the trust_guards work established: a single "could
    // not connect" makes a locked keychain look like a network outage.
    let (env, _runtime) = production_env();
    let addr = a_closed_loopback_port();

    // (a) A device with an identity, and nothing listening. A real socket is
    //     opened and a real QUIC initial goes out; rung 1's 3 s budget expires.
    let healthy = adapter();
    let unreachable = drive(&env, async {
        let binding = bind_at(&env, &healthy, addr).await.expect("binds");
        // `Box<dyn ControlConnection>` has no `Debug` — deliberately, since it
        // holds the connection's crypto state — so the success arm is unwrapped
        // by hand rather than through `expect_err`.
        match binding.attach(false).await {
            Ok(_) => panic!("a port with nothing listening must not attach"),
            Err(diagnostic) => diagnostic,
        }
    });
    assert_eq!(unreachable.code().as_str(), "CONTROL.UNREACHABLE");

    // (b) A device whose element cannot report an identity. Refused at BIND
    //     time, before a socket is opened — the verdict every attach under it
    //     would reach, stated once.
    let locked = adapter();
    locked.identity_mock().set_unavailable(true);
    let no_key = drive(&env, bind_at(&env, &locked, addr)).expect_err("no usable identity");
    assert_eq!(no_key.code().as_str(), "AUTH.KEY_UNAVAILABLE");

    assert_ne!(
        unreachable.code().as_str(),
        no_key.code().as_str(),
        "an operator does different things about these two, and a user sees \
         different text; collapsing them is the defect, not the shortcut"
    );
}

#[test]
fn an_empty_pin_set_is_refused_at_construction() {
    // ADR-0001 §7.2: a device pins from its enrolment record, and there is no
    // learn-on-first-use. An empty set accepts NO server, so it is refused
    // before a socket is bound rather than once per connection.
    let addr = a_closed_loopback_port();
    let endpoint = ControlEndpoint::new(SERVER_NAME.to_owned(), vec![addr]).expect("resolved");

    let err = ControlPlaneEnrolment::new(Vec::new(), vec![endpoint.clone()])
        .expect_err("nothing is pinned");
    assert_eq!(err.code().as_str(), "CONTROL.HANDSHAKE_REJECTED");

    let err =
        ControlPlaneEnrolment::new(vec![Vec::new()], vec![endpoint]).expect_err("an empty pin");
    assert_eq!(err.code().as_str(), "CONTROL.HANDSHAKE_REJECTED");
}

#[test]
fn the_hosts_families_and_pref64_are_read_from_the_platform_and_never_guessed() {
    // ADR-0010 R1 forbids "a v4 story and a v6 story". The half that is easy to
    // get wrong in the other direction is that a v6-only underlay is an
    // ORDINARY host, not an error — and §11.7's PREF64 is what lets one reach a
    // v4-only front-end. Both readings come from one derivation over the
    // platform's own report.
    //
    // Note what this test CANNOT reach. `UnderlayFamilies` has no variant
    // carrying neither family, so `bind`'s `can_attach` refusal is unreachable
    // through the platform seam today. That branch is documented at `bind` as a
    // guard against the seam widening, not as a path any adapter can take.
    let (env, _runtime) = production_env();
    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443);

    for (declared, expect_nat64) in [
        (UnderlayFamilies::V6Only { nat64: None }, false),
        (
            UnderlayFamilies::V6Only {
                nat64: Some(Nat64Prefix::well_known()),
            },
            true,
        ),
    ] {
        let adapter = adapter();
        set_families(&adapter, declared);
        let binding = drive(&env, bind_at(&env, &adapter, addr))
            .expect("a v6-only host binds; it is not a refusal");

        let families = binding.families();
        assert!(!families.v4 && families.v6, "{declared:?}");
        assert_eq!(
            families.nat64, expect_nat64,
            "{declared:?}: a discovered 64:ff9b::/96 is carried through, and an \
             absent prefix stays absent rather than defaulting to it"
        );
    }
}

// ---------------------------------------------------------------------------
// the statement verifier
// ---------------------------------------------------------------------------

/// A `RelayEpochFloor` payload — an Owner-authority statement, four fields and
/// a `crit` set the CDDL requires to name `epoch_floor`.
fn relay_epoch_floor(epoch: u64) -> Item {
    Item::Map(vec![
        (Item::Uint(1), Item::Text("tn-cp-binding".to_owned())),
        (Item::Uint(2), Item::Text("og-1".to_owned())),
        (Item::Uint(3), Item::Uint(epoch)),
        (Item::Uint(4), Item::Uint(2_000_000_000_000)),
        (
            Item::Uint(5),
            Item::Array(vec![Item::Text("epoch_floor".to_owned())]),
        ),
    ])
}

/// The Owner root every test below pins to.
fn ork() -> FixtureIdentity {
    FixtureIdentity::from_seed(b"twinvpn/core/cp-binding/ork")
}

/// One `RelayEpochFloor`, signed by `signer`, as it arrives on the wire.
fn signed_floor(signer: &FixtureIdentity) -> ReceivedOctets {
    ReceivedOctets::from_wire_owned(signer.sign(&relay_epoch_floor(7)))
}

/// A chain pinned to `ork`'s public half, as enrolment would pin it (S-32).
fn chain_pinned_to(ork: &FixtureIdentity) -> AnchorChain {
    let mut chain = AnchorChain::new();
    chain
        .offer_anchor(OwnerTrustAnchor {
            twinnet_id: "tn-cp-binding".to_owned(),
            anchor_version: 1,
            ork_pub_cose: ork.cose_key(),
            not_after_ms: 2_000_000_000_000,
        })
        .expect("the first anchor is accepted");
    chain
}

#[test]
fn the_verifier_accepts_a_statement_the_pinned_owner_root_signed() {
    let ork = ork();
    let verifier = AnchorStatementVerifier::new(chain_pinned_to(&ork));

    let octets = signed_floor(&ork);
    let verified = verifier
        .verify(&octets, StatementKind::RelayEpochFloor)
        .expect("signed by the pinned root");

    assert_eq!(verified.kind, StatementKind::RelayEpochFloor);
    assert_eq!(
        verified.authority,
        StatementKind::RelayEpochFloor.required_authority(),
        "the authority must be the one the TYPE requires; apply.rs re-checks this"
    );
    // The octets come back AS THEY ARRIVED. A re-encoded COSE_Sign1 stops
    // verifying, so forwarding one would forward something nobody signed.
    assert_eq!(verified.payload.as_slice(), octets.as_slice());
    // The window is read from the SIGNED payload, not invented. A fabricated
    // one would make the freshness ladder run on fiction.
    assert_eq!(verified.window.not_after_ms, Some(2_000_000_000_000));
    assert_eq!(
        verified.window.not_before_ms, None,
        "signed_statements.cddl declares no nbf on this statement"
    );
}

#[test]
fn the_verifier_refuses_a_statement_signed_by_an_untrusted_anchor() {
    let ork = ork();
    let impostor = FixtureIdentity::from_seed(b"twinvpn/core/cp-binding/impostor");
    let verifier = AnchorStatementVerifier::new(chain_pinned_to(&ork));

    // A well-formed statement, correctly encoded, signed by a key that is not
    // the pinned root. The transport being authenticated is not verification.
    let octets = signed_floor(&impostor);
    let failure = verifier
        .verify(&octets, StatementKind::RelayEpochFloor)
        .expect_err("not the pinned root");
    assert_eq!(failure, VerifyFailure::BadSignature);
}

#[test]
fn a_payload_that_is_not_the_kind_it_was_dispatched_as_is_a_type_mismatch() {
    // The ports contract: "an implementation MUST compare `expected` against the
    // type inside the verified payload and fail on a mismatch rather than
    // trusting the caller or the wire." Here the signature verifies and the
    // payload is a RelayEpochFloor, but the caller dispatched a PolicyBundle —
    // whose frozen Schema refuses it.
    let ork = ork();
    let verifier = AnchorStatementVerifier::new(chain_pinned_to(&ork));
    let octets = signed_floor(&ork);

    let failure = verifier
        .verify(&octets, StatementKind::PolicyBundle)
        .expect_err("the payload is not a policy bundle");
    assert_eq!(failure, VerifyFailure::TypeMismatch);
}

#[test]
fn an_authority_with_no_key_material_refuses_rather_than_admitting() {
    // A control plane that could get an unverified PolicyBundle or
    // RevocationStatement admitted would be granting authority it does not have.
    //
    // The Device rows are the live gap: the core holds no peer
    // `DeviceIdentityKey`, because `PeerRecord` — CD-I5's transfer shape —
    // carries no public key. Refusing is the fail-closed half of that, asserted
    // here so widening `PeerRecord` later breaks a test rather than rotting a
    // comment.
    let unpinned = AnchorStatementVerifier::new(AnchorChain::new());
    let no_device_keys = AnchorStatementVerifier::new(chain_pinned_to(&ork()));
    let octets = signed_floor(&ork());

    for (verifier, kind) in [
        (&unpinned, StatementKind::RelayEpochFloor),
        (&unpinned, StatementKind::PolicyBundle),
        (&unpinned, StatementKind::RevocationStatement),
        (&unpinned, StatementKind::TrustEpochBundle),
        // protocol.md §7 Rule B: the advertiser signs, never the coordinator.
        (&no_device_keys, StatementKind::RouteAdvertisement),
        (&no_device_keys, StatementKind::ExitNodeOffer),
        (&no_device_keys, StatementKind::IdentitySuccession),
    ] {
        assert_eq!(
            verifier.verify(&octets, kind).expect_err("no key material"),
            VerifyFailure::NoAnchor,
            "{kind:?} must be refused, never admitted on trust"
        );
    }
}

#[test]
fn a_log_head_key_is_not_folded_into_the_owner_set() {
    // ADR-0002 S-3: the LogHead key is an ONLINE control-plane key carrying no
    // delegated trust power, so a compromised control plane "can forge freshness
    // and nothing else". Neither set may vouch for the other.
    let ork = ork();
    let online = FixtureIdentity::from_seed(b"twinvpn/core/cp-binding/loghead");
    let octets = signed_floor(&ork);

    let owner_only = AnchorStatementVerifier::new(chain_pinned_to(&ork));
    assert_eq!(
        owner_only
            .verify(&octets, StatementKind::LogHead)
            .expect_err("no LogHead key is configured"),
        VerifyFailure::NoAnchor,
        "an Owner anchor does not vouch for an online control-plane key"
    );

    let freshness_only = AnchorStatementVerifier::new(AnchorChain::new())
        .with_log_head_keys(vec![online.cose_key()]);
    assert_eq!(
        freshness_only
            .verify(&octets, StatementKind::RelayEpochFloor)
            .expect_err("no Owner anchor"),
        VerifyFailure::NoAnchor,
        "a freshness key confers no trust; ADR-0002 S-3"
    );
}

#[test]
fn a_tunnel_key_binding_is_refused_here_rather_than_half_checked() {
    // `verify_tunnel_key_binding` needs the expected device_id and identity_id
    // of the identity being evaluated, and `StatementVerifier::verify` carries
    // neither. Without them the check degrades into "some device signed some
    // binding", which ADR-0007 N-4 says is not a binding at all — so this
    // refuses, even WITH a device key set, rather than returning an unbounded
    // window that would silently disable an expiry gate the statement has.
    let device = FixtureIdentity::from_seed(b"twinvpn/core/cp-binding/peer");
    let verifier = AnchorStatementVerifier::new(chain_pinned_to(&ork()))
        .with_device_keys(vec![device.cose_key()]);
    let octets = signed_floor(&device);

    assert_eq!(
        verifier
            .verify(&octets, StatementKind::TunnelKeyBinding)
            .expect_err("not verifiable at this seam"),
        VerifyFailure::NoAnchor
    );
}
