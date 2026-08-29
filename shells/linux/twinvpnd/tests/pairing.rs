//! **F-2, end to end through the composed agent.** ADR-0007 §7.4's C-B ceremony,
//! performed by the same composition `twinvpnd`'s `main` builds.
//!
//! **Authority:** [ADR-0007](../../../../docs/adr/ADR-0007-device-identity-and-pairing.md)
//! §7.4 (C-B, C-D, the `PairingOffer` field list), §7.5, N-2, N-4;
//! [ADR-0017](../../../../docs/adr/ADR-0017-local-management-interface.md)
//! §11.9 (the `pair.begin` row), **§11.15 MI-P1**, §11.17;
//! [ADR-0023](../../../../docs/adr/ADR-0023-embedded-and-headless-operation.md)
//! EM-22 **E1**/**E2**; ADR-0018 §11.16 (l).
//!
//! # What this file exists to prove, and what it deliberately does not repeat
//!
//! `core/crates/twinvpn-core/tests/pairing*.rs` drive the ceremony with a mock
//! adapter and a virtual clock — CB-2's falsification test, "with every shell
//! deleted the core must still make every decision correctly". They prove the
//! *decisions*.
//!
//! This file proves the **composition**: that a real
//! [`twinvpn_platform_linux::LinuxPlatformAdapter`], a real
//! [`twinvpn_core::Core`], the real
//! [`twinvpnd::agent::enrolment::enrol_at_startup`] `main` calls, and the real
//! MI application boundary together perform a ceremony that a shell can render
//! and a peer can consume. Nothing here calls `install_pairing_enrolment`: the
//! record is installed by the production startup path reading files from a
//! provisioned state directory, exactly as the daemon does.
//!
//! # The two substitutions, named
//!
//! 1. **The element.** [`FixtureElement`] replaces `AbsentElement`, through the
//!    injected `LinuxAdapterParts::identity_element` seam — the same field
//!    `main`'s `build_adapter` fills. A host with no element is the *other*
//!    test here ([`a_host_with_no_element_refuses_to_begin_a_pairing`]), and it
//!    binds the production `AbsentElement`.
//! 2. **The principal.** `mgmt.admin` is granted at attach "only to root", so no
//!    `ADMINISTER` operation is reachable over a real socket from an
//!    unprivileged runner. The tests call [`server::dispatch`] — the MI
//!    application boundary — with the [`Principal`] the kernel would have
//!    reported. Everything below that call is production code.
//!
//! Neither substitution touches a decision: the adapter, the core, the
//! enrolment reader, the catalogue check, the §11.14 ceremony, the idempotency
//! precondition and the MI-P1 response path are all the shipped ones.
//!
//! # What is not here, and where it is
//!
//! **Expiry.** N-17's 120-second window needs a clock a test can move, and this
//! composition binds the host's real `CLOCK_REALTIME` (`runtime::build_env`).
//! Waiting 120 s in a test is not a test. The window is driven with
//! `twinvpn_env::virtual_time::VirtualTime` in
//! `core/crates/twinvpn-core/tests/pairing_refusals.rs`, which is where the
//! clock is injectable.

use std::sync::Arc;

use twinvpn_crypto::emit::Item;
use twinvpn_crypto::pairing_offer;
use twinvpn_crypto::testkit::FixtureIdentity;
use twinvpn_crypto::{StatementKind, VerifiedStatement};
use twinvpn_platform::custody::{IdentityKeyRef, IdentityPublic, PeerPublicKey, Signature};
use twinvpn_platform::PlatformError;
use twinvpn_platform_linux::SigningElement;
use twinvpnd::agent::{enrolment, events, peer, runtime, server};
use twinvpnd::mi::wire::{Request, Response};
use twinvpnd::mi::{PlatformCtx, Scopes};

/// This device's identity key. The whole ceremony's arithmetic hangs off it:
/// N-2 makes `identity_id` its digest, and the composition proves the encoding
/// against exactly that.
const IK_SEED: &[u8] = b"twinvpnd-pairing-device-ik";
/// The Owner root. §7.5's ORK, whose public half is the pin.
const ORK_SEED: &[u8] = b"twinvpnd-pairing-ork";
/// The delegated `OwnerSigningKey` that approves enrolments (C-D).
const OSK_SEED: &[u8] = b"twinvpnd-pairing-osk";
/// Its `osk_id`.
const OSK_ID: &str = "osk-enrolment";
/// The `TwinNet` every fixture statement names.
const TWINNET: &str = "tn-linux";
/// A `not_after_ms` far enough out that no fixture expires mid-suite.
const STATEMENT_NOT_AFTER_MS: u64 = 4_000_000_000_000;
/// `twinvpn_core::pairing::Ceremony::ConfidentialChannel`'s selector byte.
const CEREMONY_C_B: u8 = 1;
/// `Ceremony::HumanCode`'s.
const CEREMONY_C_A: u8 = 2;
/// The width of the `pairing_id` that prefixes a `pair.begin` response body.
const PAIRING_ID_BYTES: usize = twinvpn_core::pairing::PAIRING_ID_BYTES;

// ---------------------------------------------------------------------------
// The element
// ---------------------------------------------------------------------------

/// An element with a real ES256 key that signs **inside itself**.
///
/// `tests/mi_roundtrip.rs`'s `PublicOnlyElement` refuses `sign`, which is right
/// for a transport test and useless here: `pairing_offer.cddl` field 4 is a
/// `COSE_Sign1` the element produces, and ADR-0007 N-4 makes a receiver verify
/// it "BEFORE writing TK into `TrustedPeer`". A fixture that stubbed the
/// signature would let this suite pass while the product emitted an offer no
/// peer would accept.
///
/// `public_key` is a **`SubjectPublicKeyInfo`**, which is what
/// `twinvpn_crypto::cose::es256_cose_key_from_verifying_key` documents as the
/// device's own IK path — so the composition's N-2 proof runs against the
/// encoding a real element vends, not against a `COSE_Key` handed to it.
struct FixtureElement {
    ik: FixtureIdentity,
}

impl FixtureElement {
    fn new() -> Self {
        Self {
            ik: FixtureIdentity::from_seed(IK_SEED),
        }
    }
}

impl std::fmt::Debug for FixtureElement {
    /// Names the element and nothing else, which is the rule
    /// `LinuxIdentityCustody`'s own `Debug` follows: a derive here would walk
    /// into a signing key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FixtureElement")
    }
}

impl SigningElement for FixtureElement {
    fn name(&self) -> &'static str {
        "test-fixture-es256"
    }

    fn hardware_backed(&self) -> bool {
        // Truthfully false. §11.16 (l): the flag records custody, and a fixture
        // key is in this process's memory.
        false
    }

    fn public_identity(&self) -> Result<IdentityPublic, PlatformError> {
        let cose = self.ik.cose_key();
        Ok(IdentityPublic {
            device_id: twinvpn_crypto::derive_device_id(&cose),
            identity_id: twinvpn_crypto::derive_identity_id(&cose),
            generation: 0,
            public_key: self.ik.spki_der(),
        })
    }

    fn sign(&self, _key: IdentityKeyRef, message: &[u8]) -> Result<Signature, PlatformError> {
        Ok(Signature::new(self.ik.sign_bytes(message)))
    }

    fn agree(
        &self,
        _key: IdentityKeyRef,
        _peer: &PeerPublicKey,
    ) -> Result<twinvpn_platform::custody::SharedSecret, PlatformError> {
        // §11.16 (c): in-element agree is not required on every target, and a
        // fixture claiming it would be claiming more than the Linux build has.
        Err(PlatformError::OsUnsupported(None))
    }

    fn attestation(&self) -> Option<(Vec<u8>, &'static str)> {
        None
    }
}

// ---------------------------------------------------------------------------
// Owner material, as the operator provisions it
// ---------------------------------------------------------------------------

fn crit(names: &[&str]) -> Item {
    Item::Array(names.iter().map(|n| Item::Text((*n).to_owned())).collect())
}

/// An ORK-signed `OwnerTrustAnchor` carrying that same ORK's public half.
fn anchor_octets(ork: &FixtureIdentity) -> Vec<u8> {
    ork.sign(&Item::Map(vec![
        (Item::Uint(1), Item::Text(TWINNET.to_owned())),
        (Item::Uint(2), Item::Uint(1)),
        (Item::Uint(3), Item::Bytes(ork.cose_key())),
        (Item::Uint(4), Item::Uint(STATEMENT_NOT_AFTER_MS)),
        (Item::Uint(5), crit(&["anchor_version"])),
    ]))
}

/// An ORK-signed `OwnerDelegation` naming `powers`.
fn delegation_octets(ork: &FixtureIdentity, osk: &FixtureIdentity, powers: &[&str]) -> Vec<u8> {
    ork.sign(&Item::Map(vec![
        (Item::Uint(1), Item::Text(TWINNET.to_owned())),
        (Item::Uint(2), Item::Text(OSK_ID.to_owned())),
        (Item::Uint(3), Item::Bytes(osk.cose_key())),
        (
            Item::Uint(4),
            Item::Array(powers.iter().map(|p| Item::Text((*p).to_owned())).collect()),
        ),
        (Item::Uint(5), Item::Uint(1)),
        (Item::Uint(6), Item::Uint(STATEMENT_NOT_AFTER_MS)),
        (Item::Uint(7), crit(&["powers"])),
    ]))
}

/// Writes the Owner material into `$STATE_DIRECTORY/owner/`, the way a
/// provisioning step does. `None` leaves the directory absent entirely.
fn provision_owner(state_dir: &std::path::Path, powers: Option<&[&str]>) {
    let Some(powers) = powers else { return };
    let ork = FixtureIdentity::from_seed(ORK_SEED);
    let osk = FixtureIdentity::from_seed(OSK_SEED);
    let owner = state_dir.join(enrolment::OWNER_DIR);
    let delegations = owner.join(enrolment::DELEGATIONS_DIR);
    std::fs::create_dir_all(&delegations).expect("creates the owner directory");
    std::fs::write(owner.join(enrolment::ORK_FILE), ork.cose_key()).expect("writes the pin");
    std::fs::write(owner.join(enrolment::ANCHOR_FILE), anchor_octets(&ork))
        .expect("writes the anchor");
    std::fs::write(
        delegations.join(format!("{OSK_ID}.cose")),
        delegation_octets(&ork, &osk, powers),
    )
    .expect("writes the delegation");
}

// ---------------------------------------------------------------------------
// The composition
// ---------------------------------------------------------------------------

/// A composed agent on a private state directory.
struct Agent {
    dir: std::path::PathBuf,
    /// `Option` so [`Drop`] can move it out — see below.
    context: Option<Arc<server::ServerContext>>,
    fanout: Arc<events::Fanout>,
}

impl Agent {
    fn context(&self) -> &Arc<server::ServerContext> {
        self.context.as_ref().expect("live for the test's lifetime")
    }

    fn core(&self) -> &Arc<twinvpn_core::Core> {
        &self.context().core
    }
}

impl Drop for Agent {
    /// **Torn down off the runtime**, for the same reason it is built off one.
    ///
    /// The context holds the injected `Env`, which holds the tokio runtime, and
    /// dropping a tokio runtime from inside an async context is tokio's "Cannot
    /// drop a runtime in a context where blocking is not allowed". `main` drops
    /// it on its own thread; the tests hand it to a plain one.
    fn drop(&mut self) {
        self.fanout.close();
        let Some(context) = self.context.take() else {
            return;
        };
        context.core.wake();
        let dir = std::mem::take(&mut self.dir);
        let _ = std::thread::spawn(move || {
            drop(context);
            let _ = std::fs::remove_dir_all(dir);
        })
        .join();
    }
}

/// Builds the agent `main` builds: the real adapter, the real core, the real
/// startup enrolment, the real event drain.
///
/// The only thing that differs from `main` is `identity_element` and the state
/// directory's location — both of which `main` itself takes as injections
/// (CB-7: "the path is INJECTED, never discovered").
///
/// **On a plain thread, never on a runtime worker.** `enrol_at_startup` reaches
/// the element through `Core::block_on_adapter`, which drives an adapter future
/// to completion on the injected runtime — and `block_on` inside an async
/// context is tokio's "Cannot start a runtime from within a runtime". `main`
/// calls it from its own thread for exactly this reason, so the tests do too.
fn agent(element: Arc<dyn SigningElement>, powers: Option<&'static [&'static str]>) -> Agent {
    std::thread::spawn(move || build_agent(element, powers))
        .join()
        .expect("the composition thread does not panic")
}

fn build_agent(element: Arc<dyn SigningElement>, powers: Option<&[&str]>) -> Agent {
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "twinvpn-pairing-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("creates");
    provision_owner(&dir, powers);

    let (env, _rt) = runtime::build_env().expect("the three clocks bind");
    let adapter = Arc::new(twinvpn_platform_linux::LinuxPlatformAdapter::new(
        twinvpn_platform_linux::LinuxAdapterParts {
            enforcement: twinvpn_platform_linux::EnforcementConfig {
                overlay_interface: "twin0".to_owned(),
                firewall_mark: twinvpn_platform_linux::DEFAULT_FWMARK,
                cgroup_path: None,
                local_network_access: true,
                on_link_prefixes: Vec::new(),
                doh_endpoints: Vec::new(),
            },
            store_root: dir.join("store"),
            resolver_restore_point: dir.join("resolver.restore"),
            identity_element: element,
        },
    ));
    let core = Arc::new(
        twinvpn_core::Core::create(twinvpn_core::CoreParts {
            env: env.clone(),
            adapter,
            abi_major_expected: twinvpn_core::ABI_MAJOR,
            abi_major: twinvpn_core::ABI_MAJOR,
            abi_minor: twinvpn_core::ABI_MINOR,
            schema_digest: Vec::new(),
            crypto_provider: "test".to_owned(),
            sek_custody: "core-held".to_owned(),
            hardware_backed: false,
            ledger_capacity: 64,
            event_capacity: 64,
        })
        .expect("the ABI matches"),
    );

    // **The production call, and the whole point of this file.** `main` runs
    // exactly this at §11.6 step (5c).
    enrolment::enrol_at_startup(&core, &dir);

    let fanout = Arc::new(events::Fanout::new());
    let context = Arc::new(server::ServerContext {
        core: Arc::clone(&core),
        env,
        groups: Arc::new(peer::GroupSource::load()),
        platform_ctx: PlatformCtx {
            platform: "linux".to_owned(),
            os_version: "test".to_owned(),
        },
        submission: Arc::new(tokio::sync::Mutex::new(())),
        fanout: Arc::clone(&fanout),
    });

    // `Core::submit` publishes rather than returns, so without a drain the
    // dispatcher's completion is never settled and every body is empty.
    std::thread::Builder::new()
        .name("twinvpn-pairing-drain".to_owned())
        .spawn({
            let core = Arc::clone(&core);
            let fanout = Arc::clone(&fanout);
            move || events::drain(&core, &fanout, std::time::Duration::from_millis(20))
        })
        .expect("spawns");

    Agent {
        dir,
        context: Some(context),
        fanout,
    }
}

/// The principal `SO_PEERCRED` would report for a root caller — the only kind
/// that holds `mgmt.admin`. See this module's header for why it is supplied.
fn root() -> peer::Principal {
    peer::Principal {
        uid: 0,
        gid: 0,
        pid: std::process::id() as i32,
        name: Some("root".to_owned()),
    }
}

/// Every grantable scope, as a root principal holds them.
fn admin_scopes() -> Scopes {
    Scopes::from_scopes([
        twinvpn_mgmt::Scope::Status,
        twinvpn_mgmt::Scope::Events,
        twinvpn_mgmt::Scope::Diagnostics,
        twinvpn_mgmt::Scope::Connect,
        twinvpn_mgmt::Scope::Settings,
        twinvpn_mgmt::Scope::Admin,
    ])
}

/// One MI call, through the production application boundary.
async fn call(agent: &Agent, operation: &str, params: Vec<u8>, key: &[u8]) -> Response {
    server::dispatch(
        agent.context(),
        &root(),
        &admin_scopes(),
        None,
        &Request {
            operation: operation.to_owned(),
            params,
            if_version: None,
        },
        key,
    )
    .await
}

/// A `pair.begin` for C-B under `key`.
async fn begin(agent: &Agent, key: &[u8]) -> Response {
    call(agent, "pair.begin", vec![CEREMONY_C_B], key).await
}

/// The registered code a refused response carries.
fn code(response: &Response) -> String {
    assert!(!response.ok, "this call was supposed to be refused");
    response
        .diagnostic
        .as_ref()
        .expect("a refusal carries a diagnostic")
        .reason_code
        .clone()
}

/// Splits a `pair.begin` body into its two halves.
fn split(body: &[u8]) -> ([u8; PAIRING_ID_BYTES], &[u8]) {
    let (id, offer) = body.split_at(PAIRING_ID_BYTES);
    (<[u8; PAIRING_ID_BYTES]>::try_from(id).expect("16"), offer)
}

// ---------------------------------------------------------------------------
// Device A: the production composition mints an offer
// ---------------------------------------------------------------------------

/// **F-2A and F-2B together.** A provisioned host with an identity begins a C-B
/// ceremony through the shipped composition and gets back an offer.
///
/// Nothing in this test constructs a `PairingEnrolment`: the record came from
/// [`enrolment::enrol_at_startup`] reading `$STATE_DIRECTORY/owner/`, which is
/// the call `main` makes.
#[tokio::test]
async fn a_provisioned_host_begins_a_ceremony_and_answers_with_the_offer() {
    let agent = agent(Arc::new(FixtureElement::new()), Some(&["ENROLL"]));

    let response = begin(&agent, b"idempotency-key-0000000000000001").await;
    assert!(
        response.ok,
        "pair.begin was refused: {:?}",
        response.diagnostic
    );

    let (pairing_id, offer_octets) = split(&response.result);
    assert!(
        !offer_octets.is_empty(),
        "ADR-0017 §11.9: pair.begin returns the PairingOffer material to render"
    );

    // The offer is the one the id names — `pairing_id = SHA-256(secret)[0..16]`,
    // derived by the one function that owns that derivation.
    let offer = pairing_offer::decode(offer_octets).expect("the response carries a valid offer");
    assert_eq!(offer.pairing_id(), pairing_id);

    // And `pair.status` sees the ceremony the same call opened.
    let status = call(&agent, "pair.status", pairing_id.to_vec(), &[]).await;
    assert!(
        status.ok,
        "pair.status was refused: {:?}",
        status.diagnostic
    );
    assert_eq!(status.result[0], 1, "the ceremony is Pending");
}

/// **The shell can render both of ADR-0023 EM-22's C-B channels from the
/// response, and neither needs anything the response did not carry.**
///
/// E1 is a QR of *these bytes* and E2 is Crockford base32 of *these bytes* —
/// `pairing_offer.cddl` encoding rule 1 is what makes "the same dCBOR bytes"
/// true of both. So the test for "a shell can render the offer" is that the
/// response body **is** the QR payload and that `render_text` produces E2 from
/// it.
#[tokio::test]
async fn a_shell_renders_the_qr_payload_and_the_e2_text_from_the_response() {
    let agent = agent(Arc::new(FixtureElement::new()), Some(&["ENROLL"]));
    let response = begin(&agent, b"idempotency-key-0000000000000002").await;
    assert!(response.ok, "{:?}", response.diagnostic);
    let (_, qr_payload) = split(&response.result);

    let offer = pairing_offer::decode(qr_payload).expect("decodes");

    // **E1.** The QR payload is the response's own bytes: re-encoding the
    // decoded offer must reproduce them exactly, or the two channels would carry
    // two different offers.
    assert_eq!(
        pairing_offer::encode(&offer).expect("re-encodes"),
        qr_payload,
        "ADR-0023 E1 renders THESE bytes; encoding rule 1 makes that byte-exact"
    );

    // **E2.** Crockford base32 in groups of eight, and it round-trips back to
    // the same offer — which is what makes a pasted block and a photographed QR
    // reach the same peer state.
    let text = pairing_offer::render_text(&offer).expect("renders E2");
    assert!(!text.is_empty());
    let pasted = pairing_offer::parse_text(&text).expect("an admin device pastes it back");
    assert_eq!(pasted.pairing_id(), offer.pairing_id());
}

// ---------------------------------------------------------------------------
// Device B: consuming the offer
// ---------------------------------------------------------------------------

/// **Device B consumes the offer through the approved path.**
///
/// The four steps ADR-0007 N-4 puts before a peer may write `TK` into a
/// `TrustedPeer`, in order, and the third is the one the rule exists for: the
/// `TunnelKeyBinding` is verified **over the received octets**, under the
/// `ik_pub` the offer itself carries, and it must name the device that offer
/// names.
#[tokio::test]
async fn a_peer_consumes_the_offer_and_verifies_the_binding_before_trusting_tk() {
    let agent = agent(Arc::new(FixtureElement::new()), Some(&["ENROLL"]));
    let response = begin(&agent, b"idempotency-key-0000000000000003").await;
    assert!(response.ok, "{:?}", response.diagnostic);
    let (_, octets) = split(&response.result);

    // 1. Decode, which enforces every bound `pairing_offer.cddl` declares.
    let offer = pairing_offer::decode(octets).expect("Device B decodes it");

    // 2. Encoding rule 5's receiver half: the window is inside
    //    `pairing.ceremony_expiry_ms` of Device B's own clock.
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after 1970")
        .as_millis() as u64;
    pairing_offer::check_window(&offer, now_ms).expect("the offer's window is honest");

    // 3. **N-4.** The binding, verified over the received octets under the
    //    offer's own `ik_pub`, and required to name this device.
    let ik = twinvpn_crypto::PublicVerifyingKey::from_cose_key(
        offer.ik_pub_cose(),
        StatementKind::TunnelKeyBinding,
    )
    .expect("field 2 is an ES256 COSE_Key");
    let verified: VerifiedStatement =
        twinvpn_crypto::verify_cose_sign1(offer.binding(), StatementKind::TunnelKeyBinding, &ik)
            .expect("field 4 is a COSE_Sign1 the offering device's element produced");

    let device_id = twinvpn_crypto::derive_device_id(offer.ik_pub_cose());
    let identity_id = twinvpn_crypto::derive_identity_id(offer.ik_pub_cose());
    let tk = twinvpn_crypto::verify_tunnel_key_binding(
        &verified,
        &<[u8; 32]>::try_from(twinvpn_types::Identifier::as_bytes(&device_id)).expect("32"),
        &<[u8; 32]>::try_from(twinvpn_types::Identifier::as_bytes(&identity_id)).expect("32"),
    )
    .expect("the binding names the device the offer names");

    // The TK the binding vouches for is the one the offer carries: a peer that
    // wrote field 3 without this check would trust a key nobody signed for.
    assert_eq!(tk.tk_pub(), offer.tk_pub());
    assert_eq!(
        tk.tk_generation(),
        twinvpn_core::pairing::FIRST_TK_GENERATION
    );

    // 4. The ceremony channel key derives, which every subsequent message is
    //    wrapped under.
    offer.derive_k_pair().expect("K_pair derives");
}

/// **A replayed offer.** The same octets presented twice decode twice — the
/// offer is not itself single-use, the `pairing_id` is. So a replay is refused
/// where single-use lives: the ceremony, on the offering device.
#[tokio::test]
async fn a_replayed_offer_cannot_open_a_second_ceremony() {
    let agent = agent(Arc::new(FixtureElement::new()), Some(&["ENROLL"]));
    let first = begin(&agent, b"idempotency-key-0000000000000004").await;
    assert!(first.ok, "{:?}", first.diagnostic);
    let (pairing_id, octets) = split(&first.result);

    // Device B may decode the same bytes any number of times; nothing about the
    // payload prevents that, and pretending otherwise would be a false claim.
    let a = pairing_offer::decode(octets).expect("first read");
    let b = pairing_offer::decode(octets).expect("second read");
    assert_eq!(a.pairing_id(), b.pairing_id());

    // What is single-use is the identifier. Cancelling burns it, and it is
    // "never reissued, not even after expiry or cancellation" — so the second
    // presentation of a consumed id reaches a terminal state, not a fresh
    // ceremony.
    let cancelled = call(&agent, "pair.cancel", pairing_id.to_vec(), &[]).await;
    assert!(cancelled.ok, "{:?}", cancelled.diagnostic);
    assert_eq!(cancelled.result[0], 4, "Aborted");

    let again = call(&agent, "pair.cancel", pairing_id.to_vec(), &[]).await;
    assert!(again.ok, "a replay returns the recorded outcome");
    assert_eq!(again.result[0], 4, "still Aborted, not re-opened");
}

/// **A cancelled offer stops crossing MI.** Its secret is dropped when the
/// ceremony ends, so the response for a replayed `pair.begin` shrinks to the
/// `pairing_id` ADR-0008 records as the outcome.
///
/// This is MI-P1 rule 3's observable: the agent does not keep the offer.
#[tokio::test]
async fn a_cancelled_ceremony_stops_returning_its_offer() {
    let agent = agent(Arc::new(FixtureElement::new()), Some(&["ENROLL"]));
    let key = b"idempotency-key-0000000000000005";
    let first = begin(&agent, key).await;
    assert!(first.ok, "{:?}", first.diagnostic);
    let (pairing_id, octets) = split(&first.result);
    assert!(!octets.is_empty());

    let cancelled = call(&agent, "pair.cancel", pairing_id.to_vec(), &[]).await;
    assert!(cancelled.ok, "{:?}", cancelled.diagnostic);

    // ADR-0008: the duplicate returns the ORIGINAL `pairing_id`. It no longer
    // returns an offer, because there is no longer one to return.
    let replay = begin(&agent, key).await;
    assert!(replay.ok, "{:?}", replay.diagnostic);
    assert_eq!(
        replay.result,
        pairing_id.to_vec(),
        "the recorded outcome is the pairing_id alone once the offer is gone"
    );
}

/// **A duplicate `pair.begin` mints one ceremony**, and both calls can render.
///
/// ADR-0008 N-4's retry: the client lost the first response, so the second call
/// must be usable — which means it must still carry the offer while the
/// ceremony is in flight, not only the id.
#[tokio::test]
async fn a_duplicate_begin_returns_the_same_ceremony_and_the_same_offer() {
    let agent = agent(Arc::new(FixtureElement::new()), Some(&["ENROLL"]));
    let key = b"idempotency-key-0000000000000006";
    let first = begin(&agent, key).await;
    let second = begin(&agent, key).await;
    assert!(first.ok && second.ok);
    assert_eq!(first.result, second.result, "one ceremony, one offer");
}

// ---------------------------------------------------------------------------
// MI-P1
// ---------------------------------------------------------------------------

/// **MI-P1 rule 1, asserted where it could break.**
///
/// The offer crosses in the `pair.begin` **response** and in nothing else. The
/// §11.10 event stream — which fans out to every subscribed client — carries the
/// 16-byte `pairing_id`, which `pairing_offer.cddl` classifies PUBLIC.
///
/// This is the assertion that would fail if someone "simplified" the response
/// path by putting the offer in `Outcome::result`.
#[tokio::test]
async fn the_offer_reaches_the_caller_and_never_the_event_stream() {
    let agent = agent(Arc::new(FixtureElement::new()), Some(&["ENROLL"]));
    // A subscriber attached BEFORE the call, exactly as a `mi.events.subscribe`
    // client would be.
    let subscriber = agent.fanout.subscribe(64);

    let response = begin(&agent, b"idempotency-key-0000000000000007").await;
    assert!(response.ok, "{:?}", response.diagnostic);
    let (pairing_id, octets) = split(&response.result);
    let secret = pairing_offer::decode(octets)
        .expect("decodes")
        .pairing_secret()
        .to_vec();

    // Everything a **subscribed MI client** would have received, read through
    // the same fan-out `pump_events` reads. This is the surface MI-P1 rule 1 is
    // about: the response goes to one connection, the stream goes to all of
    // them.
    let mut delivered = Vec::new();
    while let Some(frame) = agent.fanout.next_for(subscriber) {
        if let twinvpnd::agent::events::Delivery::Event { event, .. } = frame {
            delivered.push(event);
        }
    }
    assert!(
        !delivered.is_empty(),
        "the fan-out delivered nothing, so this test asserts nothing"
    );
    for event in &delivered {
        assert!(
            !event.payload.windows(secret.len()).any(|w| w == secret),
            "pairing_secret reached the {} topic, which every subscribed MI \
             client reads (ADR-0017 MI-P1 rule 1)",
            event.topic
        );
    }
    // And what the stream DID carry for `pair.begin` is the public handle.
    assert!(
        delivered
            .iter()
            .any(|e| e.op.as_deref() == Some("pair.begin") && e.payload == pairing_id),
        "the event stream must still carry the pairing_id, which \
         pairing_offer.cddl classifies PUBLIC"
    );
}

/// **MI-P1 rule 1, the other half:** no other operation returns it.
/// `pair.status` and `pair.cancel` answer with state bytes, and a caller that
/// missed the `pair.begin` response cannot ask for the offer again.
#[tokio::test]
async fn no_operation_other_than_pair_begin_returns_the_offer() {
    let agent = agent(Arc::new(FixtureElement::new()), Some(&["ENROLL"]));
    let response = begin(&agent, b"idempotency-key-0000000000000008").await;
    assert!(response.ok, "{:?}", response.diagnostic);
    let (pairing_id, octets) = split(&response.result);
    let secret = pairing_offer::decode(octets)
        .expect("decodes")
        .pairing_secret()
        .to_vec();

    for op in ["pair.status", "pair.cancel"] {
        let answer = call(&agent, op, pairing_id.to_vec(), &[]).await;
        assert!(answer.ok, "{op} was refused: {:?}", answer.diagnostic);
        assert!(
            answer.result.len() <= 2,
            "{op} answers with state bytes, never with offer material"
        );
        assert!(!answer.result.windows(secret.len()).any(|w| w == secret));
    }
}

// ---------------------------------------------------------------------------
// The refusals, through the same composition
// ---------------------------------------------------------------------------

/// **A host with no element refuses, and with the identity spelling.**
///
/// This is the Linux agent's shipped state: `main`'s `build_adapter` binds
/// `AbsentElement`, which ADR-0018 §11.16 (l) makes the *specified* behaviour on
/// a host with no secure element — "the core MUST NOT substitute a file-backed
/// signer silently". So the enrolment record is not installed and `pair.begin`
/// refuses `AUTH.IDENTITY_MISSING`.
///
/// **Not `AUTH.PAIRING_NOT_AUTHORIZED`.** The Owner material below is fully
/// provisioned and carries `ENROLL`; what is missing is this device's identity,
/// and an operator sent hunting for an OSK approval would be looking in the
/// wrong place.
#[tokio::test]
async fn a_host_with_no_element_refuses_to_begin_a_pairing() {
    let agent = agent(
        Arc::new(twinvpn_platform_linux::AbsentElement),
        Some(&["ENROLL"]),
    );
    let response = begin(&agent, b"idempotency-key-0000000000000009").await;
    assert_eq!(code(&response), "AUTH.IDENTITY_MISSING");
}

/// **An unprovisioned host refuses, and with the authorization spelling.**
///
/// The mirror of the test above, and the pair is the point: the identity is
/// known, so the missing fact is the Owner's approval (ADR-0007 §7.4 C-D). A
/// build that merged the two codes would fail one of these two tests.
#[tokio::test]
async fn a_host_with_an_identity_and_no_owner_material_is_not_authorized() {
    let agent = agent(Arc::new(FixtureElement::new()), None);
    let response = begin(&agent, b"idempotency-key-0000000000000010").await;
    assert_eq!(code(&response), "AUTH.PAIRING_NOT_AUTHORIZED");
}

/// **An approver without `ENROLL` cannot authorize an enrolment.**
///
/// The delegation verifies under the pinned ORK and is installed; it simply does
/// not carry the power §7.4 requires, and `AnchorChain::authorize` says so.
#[tokio::test]
async fn a_delegation_without_enroll_power_cannot_begin_a_pairing() {
    let agent = agent(Arc::new(FixtureElement::new()), Some(&["POLICY", "REVOKE"]));
    let response = begin(&agent, b"idempotency-key-0000000000000011").await;
    assert_eq!(code(&response), "AUTH.PAIRING_NOT_AUTHORIZED");
}

/// **Owner material signed by a key that is not the pinned root is dropped.**
///
/// The provisioned `ork.cose-key` names one root and the anchor is signed by
/// another, so the anchor does not verify, nothing is pinned, and no delegation
/// under it is installed. The device ends up with an identity and no approval —
/// which is the fail-closed direction, and the same verdict as an empty
/// directory.
#[tokio::test]
async fn owner_material_signed_by_an_unpinned_root_authorizes_nothing() {
    let agent = agent(Arc::new(FixtureElement::new()), Some(&["ENROLL"]));

    // Replace the pin with a different root's key and re-run the startup step.
    let impostor = FixtureIdentity::from_seed(b"not-the-owner-root");
    std::fs::write(
        agent
            .dir
            .join(enrolment::OWNER_DIR)
            .join(enrolment::ORK_FILE),
        impostor.cose_key(),
    )
    .expect("writes");
    // On a plain thread, for the reason `agent` is.
    std::thread::scope(|s| {
        s.spawn(|| enrolment::enrol_at_startup(agent.core(), &agent.dir));
    });

    let response = begin(&agent, b"idempotency-key-0000000000000012").await;
    assert_eq!(code(&response), "AUTH.PAIRING_NOT_AUTHORIZED");
}

/// **A malformed offer is refused, and the two kinds of malformation are
/// caught by two different checks.**
///
/// Driven against octets the composed agent actually produced, so the negatives
/// are perturbations of a real offer rather than of an invented one.
///
/// The second half is the more interesting one and is why the offer carries a
/// signature at all: a byte flipped **inside** field 4 is invisible to the
/// schema — the CDDL calls the binding "opaque octets", so a decoder that
/// refused it would be refusing something it cannot see. ADR-0007 N-4's
/// signature check over the received octets is what catches it, and the rule
/// says so in terms: the receiver MUST verify the binding before writing TK, and
/// "the check MUST NOT be skippable".
#[tokio::test]
async fn a_malformed_offer_is_refused_by_the_receiver() {
    let agent = agent(Arc::new(FixtureElement::new()), Some(&["ENROLL"]));
    let response = begin(&agent, b"idempotency-key-0000000000000013").await;
    assert!(response.ok, "{:?}", response.diagnostic);
    let (_, octets) = split(&response.result);

    // Structural: truncated, so not a canonical map. Refused, never repaired.
    assert!(pairing_offer::decode(&octets[..octets.len() - 1]).is_err());

    // Structural: over `pairing.max_offer_bytes`, which encoding rule 2 checks
    // "FIRST, BEFORE ANY FIELD IS PARSED".
    let mut too_long = octets.to_vec();
    too_long.extend(std::iter::repeat_n(0u8, 1024));
    assert!(pairing_offer::decode(&too_long).is_err());

    // Structural: the outermost header, which stops it being a map at all.
    let mut not_a_map = octets.to_vec();
    not_a_map[0] ^= 0xff;
    assert!(pairing_offer::decode(&not_a_map).is_err());

    // Cryptographic: a byte inside the opaque `binding`. It still decodes — the
    // schema cannot see into field 4 — and the signature check refuses it.
    let offer = pairing_offer::decode(octets).expect("the honest offer decodes");
    let binding_at = octets
        .windows(offer.binding().len())
        .position(|w| w == offer.binding())
        .expect("field 4 is in the encoding");
    let mut tampered = octets.to_vec();
    tampered[binding_at + offer.binding().len() / 2] ^= 0x01;

    let received = pairing_offer::decode(&tampered)
        .expect("a corrupted opaque field is not a schema violation");
    let ik = twinvpn_crypto::PublicVerifyingKey::from_cose_key(
        received.ik_pub_cose(),
        StatementKind::TunnelKeyBinding,
    )
    .expect("field 2 still parses");
    assert!(
        twinvpn_crypto::verify_cose_sign1(received.binding(), StatementKind::TunnelKeyBinding, &ik)
            .is_err(),
        "N-4: the binding is verified over the RECEIVED octets, so a tampered \
         one must not verify — a skipped check here is a full authentication \
         bypass"
    );
}

/// **C-A is refused by name**, through the composed agent, so the one ceremony
/// this build performs is the one it says it performs (N-15, W-22).
#[tokio::test]
async fn the_human_code_ceremony_is_refused_through_the_composed_agent() {
    let agent = agent(Arc::new(FixtureElement::new()), Some(&["ENROLL"]));
    let response = call(
        &agent,
        "pair.begin",
        vec![CEREMONY_C_A],
        b"idempotency-key-0000000000000014",
    )
    .await;
    assert_eq!(code(&response), "PROTO.CAPABILITY_MISSING");
}

/// **A `pair.begin` with no idempotency key is refused**, which is ADR-0008's
/// `CEREMONY` precondition reaching the core through the MI.
///
/// This used to be unreachable in the other direction: the server dropped the
/// envelope's `idempotency_key`, so *every* `pair.begin` was refused
/// `MGMT.PRECONDITION_FAILED` no matter what a client sent, and C-B could not be
/// performed over MI at all. Both halves are asserted — the empty key refuses,
/// and every test above supplies one and succeeds.
#[tokio::test]
async fn a_ceremony_without_an_idempotency_key_is_refused() {
    let agent = agent(Arc::new(FixtureElement::new()), Some(&["ENROLL"]));
    let response = call(&agent, "pair.begin", vec![CEREMONY_C_B], &[]).await;
    assert!(!response.ok);
}

/// **`pair.confirm` still refuses, and says what for.**
///
/// ADR-0007 N-18 confirms a ceremony on both devices or on neither, so it needs
/// both `PairingAttestation`s. This build can produce neither half — see the
/// report accompanying this work — so the operation is refused by name rather
/// than half-performed.
#[tokio::test]
async fn pair_confirm_is_still_refused_through_the_composed_agent() {
    let agent = agent(Arc::new(FixtureElement::new()), Some(&["ENROLL"]));
    let response = call(
        &agent,
        "pair.confirm",
        Vec::new(),
        b"idempotency-key-0000000000000015",
    )
    .await;
    assert!(!response.ok, "pair.confirm cannot complete in this build");
}
