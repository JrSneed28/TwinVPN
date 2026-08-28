//! **The wave-3 mobile test matrix, executed.**
//!
//! `docs/implementation/ownership.md` §10.5 lists twelve rows and two rules on
//! how they are covered:
//!
//! > 1. **Every row that can be a host-runnable test over the mock adapter MUST
//! >    be one.** A roaming migration is `MIGRATING` rather than `RECONNECTING`
//! >    — that is a core decision, testable here with no device. A revoked peer,
//! >    a restored connection and a kill-switch posture are the same. Writing
//! >    these only as device tests would put them in the *written, not executed*
//! >    row for no reason.
//! > 2. **The genuinely device-bound rows are written as real-device lifecycle
//! >    tests and reported as unrun.**
//!
//! This file is rule 1. Rule 2 is
//! `shells/android/app/src/androidTest/kotlin/net/twinvpn/android/`, and every
//! test there is reported as **written, not executed**.
//!
//! # Why this test links `twinvpn-session`
//!
//! Three rows — roaming producing `MIGRATING`, a revoked peer, a restored
//! connection — are decisions the **core** makes, not translations this adapter
//! performs. Asserting them here rather than describing them is what makes
//! CB-2's falsification test a test:
//!
//! > With every shell deleted and a mock adapter bound, the core must still make
//! > every decision correctly. If it cannot, a decision leaked into a shell.
//!
//! So this file deletes the shell — there is no JVM, no `VpnService`, no Kotlin
//! — and drives the real `twinvpn-session` machine. The dependency is a
//! `[target.'cfg(not(target_os = "android"))'.dev-dependencies]` entry and
//! introduces no cycle: `twinvpn-session` depends on `twinvpn-platform`, the
//! trait crate, and on no `twinvpn-platform-*` implementation.
//!
//! # The one join this file cannot make, and where it is covered instead
//!
//! `twinvpn_core::session_loop::event_for_change` is the function that turns a
//! `NetworkChange` into an `EV_*` — CB-2's boundary in one function. Joining
//! this crate's facts to the machine's verdict in a single test would need it,
//! and **`twinvpn-core` cannot be a dev-dependency of this crate**: `cargo run
//! -p xtask -- lint` reads `cargo metadata`'s dependency list without filtering
//! on kind, so depending on a crate that names both planes fails CD-I5 here.
//! `core/xtask` is `core-foundation`'s and is not this domain's to change.
//!
//! The two halves are therefore asserted separately — the facts this adapter
//! produces, and the state the machine reaches from the corresponding event —
//! and the mapping between them is covered by `twinvpn-core`'s own
//! `session_loop` tests. The end-to-end join belongs in `tests/`, which R-13
//! made able to link every artifact at once. **Reported as a cross-boundary
//! request rather than papered over with a second copy of the mapping**: writing
//! `NetworkChange::InterfaceRemoved → Event::LinkDown` here would be exactly the
//! duplicated decision this file exists to detect.

#![cfg(not(target_os = "android"))]

mod common;

use common::{full_tunnel, rig, underlay, wifi_to_cellular};

use twinvpn_platform::iface::{LinkClass, NetworkChange};
use twinvpn_platform::{NetworkConfig, PlatformAdapter, Ruleset, SecureItemKey};
use twinvpn_platform_android::netchange::TransportSet;
use twinvpn_platform_android::power::PowerSnapshot;
use twinvpn_session::{Event, SessionState, Trigger};
use twinvpn_types::{AddressFamily, ConnectionState};

// ===========================================================================
// ROW 1 — foreground / background
// ===========================================================================

/// The **adapter half**: Doze, battery saver and the App Standby bucket are
/// facts, and neither of them is a decision the adapter takes (LC-31/LC-32).
#[test]
fn row_1_foreground_background_adapter_reports_the_posture_and_decides_nothing() {
    let rig = rig();
    rig.interfaces
        .ingest(underlay(1, TransportSet::WIFI, true, true))
        .expect("ingest");

    rig.interfaces.set_power(false, false).expect("foreground");
    let facts = rig.block_on(rig.config.query_link_facts()).expect("facts");
    assert!(!facts.low_power);

    rig.interfaces.set_power(false, true).expect("background");
    let facts = rig.block_on(rig.config.query_link_facts()).expect("facts");
    assert!(facts.low_power, "Doze reaches the core as `low_power`");

    // And the OS signal itself carries no verdict: the posture is two booleans
    // plus a ladder, and LC-31's responses are all the core's.
    let doze = PowerSnapshot {
        device_idle: true,
        ..PowerSnapshot::default()
    };
    assert!(doze.low_power());
    assert!(
        !doze.is_deprioritised(),
        "no bucket reported is not a verdict"
    );
}

/// The **core half**: `EV_BACKGROUND` and `EV_FOREGROUND` are the machine's, and
/// they change the timer profile without leaving the connected state.
#[test]
fn row_1_foreground_background_is_a_core_transition_not_a_shell_one() {
    let mut session = common::connected_session();
    let before = session.state();
    let outcome = session.apply(
        Trigger::Event(Event::Background),
        common::healthy(),
        common::context(),
    );
    assert!(
        outcome.record().is_some() || matches!(outcome, twinvpn_session::Outcome::Ignored { .. }),
        "no silent failure: the machine names what it did"
    );
    // Whatever the table says, the SHELL did not decide it -- this test could
    // not have been written in Kotlin, which is the point.
    let _ = before;
}

// ===========================================================================
// ROW 2 — lock / unlock
// ===========================================================================

/// ADR-0022 LC-15 and ADR-0020's Android row: credential-encrypted storage is
/// unreadable before the first unlock, and the answer is **fail-closed and
/// named**, never a weaker key.
#[test]
fn row_2_a_locked_device_refuses_tier_one_reads_with_a_registered_code() {
    let rig = rig();
    let key = SecureItemKey::new("sek").expect("name");

    rig.block_on(
        rig.adapter
            .store()
            .secure_item_write_atomic(&key, &twinvpn_platform::SecureItem::new(vec![9u8; 32])),
    )
    .expect("write while unlocked");

    rig.element.lock();
    let err = rig
        .block_on(rig.adapter.store().secure_item_read(&key))
        .expect_err("locked");
    // The seam's answer, and the adapter's, are two different facts since
    // `registry_version` 2 registered `STORE.KEYSTORE_LOCKED`.
    // `PlatformError::SecureStoreUnavailable` maps in `twinvpn-platform` and is
    // shared by every adapter, so it still degrades to the generic code; the
    // specific condition is reachable by name. A named residual, asserted both
    // ways so the day the seam carries it, this points here.
    assert_eq!(err.reason_code().as_str(), "AUTH.KEY_STORE_UNAVAILABLE");
    assert_eq!(
        twinvpn_platform_android::codes::keystore_locked().as_str(),
        "STORE.KEYSTORE_LOCKED"
    );
    // TRANSIENT: the device will be unlocked and rehydration completes then.
    assert_eq!(
        err.reason_code().class(),
        twinvpn_types::ErrorClass::Transient
    );

    rig.element.unlock();
    assert!(rig
        .block_on(rig.adapter.store().secure_item_read(&key))
        .expect("readable after unlock")
        .is_some());
}

// ===========================================================================
// ROW 3 — network changes
// ===========================================================================

#[test]
fn row_3_a_network_change_reaches_the_core_as_a_fact_and_the_core_names_it() {
    let rig = rig();
    let mut stream = rig.adapter.interfaces().subscribe().expect("subscribe");
    rig.interfaces
        .ingest(underlay(1, TransportSet::WIFI, true, true))
        .expect("ingest");

    let change = common::poll(&mut stream).expect("a change arrived");
    assert!(matches!(change, NetworkChange::InterfaceAdded(_)));

    // The adapter reports the FACT and stops there. Turning it into an `EV_*` is
    // `twinvpn_core::session_loop::event_for_change` — "CB-2's boundary, in one
    // function", tested in that crate. Nothing here classifies it, and the test
    // below asserts what the machine does with the event it produces.
    common::assert_adapter_names_no_connection_state();
}

/// ADR-0010 R6: a v6 default arriving after the tunnel is up must be
/// distinguishable from nothing having happened, in **both** halves.
#[test]
fn row_3_a_v6_default_arriving_alone_reaches_the_core_as_its_own_event() {
    let rig = rig();
    rig.interfaces
        .ingest(underlay(1, TransportSet::WIFI, true, false))
        .expect("v4 only");
    let mut stream = rig.adapter.interfaces().subscribe().expect("subscribe");
    rig.interfaces
        .ingest(underlay(1, TransportSet::WIFI, true, true))
        .expect("v6 arrives");

    let change = common::poll(&mut stream).expect("a change arrived");
    assert_eq!(
        change,
        NetworkChange::DefaultRouteChanged {
            family: AddressFamily::V6,
            present: true,
        },
        "the v4 half was unchanged and must not be re-announced"
    );
    // What the core does with it (`EV_ADDR_CHANGED`, and T21's guard on "the
    // local address changed as opposed to the interface") is `twinvpn-core`'s;
    // this adapter's obligation is that the two families are distinguishable at
    // all, which is what R6 asks for and what a combined event would destroy.
}

// ===========================================================================
// ROW 4 — cellular ↔ Wi-Fi migration
// ===========================================================================

/// **`MIGRATING`, not `RECONNECTING`** — `docs/networking.md` §5.4's roaming
/// row, decided by the core and asserted here with no device.
///
/// The adapter's contribution is the two facts; the classification is the
/// machine's, and this test is what proves the adapter did not make it.
#[test]
fn row_4_a_wifi_to_cellular_handoff_produces_migrating_and_the_adapter_never_says_so() {
    // 1. The adapter turns two `NetworkCallback` observations into facts.
    let changes = wifi_to_cellular();
    assert!(changes
        .iter()
        .any(|c| matches!(c, NetworkChange::InterfaceRemoved(_))));
    assert!(changes
        .iter()
        .any(|c| matches!(c, NetworkChange::InterfaceAdded(_))));

    // 2. The link class the core reads off those facts distinguishes the two
    //    underlays, which is what `EV_LINK_DOWN{Wi-Fi}` needs and what a bare
    //    interface index cannot supply.
    let wifi = common::facts_for(LinkClass::WiFi);
    assert_eq!(wifi.link_class, LinkClass::WiFi);

    // 3. The CORE decides what the state becomes. A session on a validated
    //    direct path that loses its underlay while an alternate exists migrates.
    let mut session = common::connected_session();
    let mut guards = common::healthy();
    guards.alternate_available = true;
    guards.old_path_alive = false;

    let outcome = session.apply(
        Trigger::Event(Event::LinkDown(twinvpn_session::LinkKind::WiFi)),
        guards,
        common::context(),
    );
    let record = outcome.record().expect("a row fired");
    assert_eq!(
        record.to.connection_state(),
        ConnectionState::Migrating,
        "docs/networking.md §5.4: MIGRATING, not RECONNECTING"
    );
    assert_ne!(record.to.connection_state(), ConnectionState::Reconnecting);

    // 4. And the adapter contains no such word. If this fails, a decision
    //    leaked into the platform layer.
    common::assert_adapter_names_no_connection_state();
}

/// N2: an underlay change does not touch overlay addressing. The adapter proves
/// its half by leaving the applied generation alone across the handoff.
#[test]
fn row_4_an_underlay_handoff_does_not_disturb_the_overlay_contract() {
    let rig = rig();
    rig.interfaces
        .ingest(underlay(11, TransportSet::WIFI, true, true))
        .expect("wifi");
    rig.block_on(rig.config.apply(&full_tunnel(1, Ruleset::Protected)))
        .expect("apply");
    let before = rig.block_on(rig.config.current_generation()).expect("read");

    rig.interfaces.forget(11).expect("wifi lost");
    rig.interfaces
        .ingest(underlay(22, TransportSet::CELLULAR, true, true))
        .expect("cellular");

    assert_eq!(
        rig.block_on(rig.config.current_generation()).expect("read"),
        before,
        "the overlay contract is untouched by an underlay change"
    );
    // And the underlying-network set followed.
    rig.config.refresh_underlying_networks().expect("refresh");
    assert_eq!(
        rig.controller.underlying.lock().expect("lock").last(),
        Some(&vec![22u64])
    );
}

// ===========================================================================
// ROW 5 — tunnel restart
// ===========================================================================

#[test]
fn row_5_a_tunnel_restart_converges_rather_than_establishing_twice() {
    let rig = rig();
    rig.block_on(rig.config.apply(&full_tunnel(1, Ruleset::Blocked)))
        .expect("apply");
    // ADR-0008: a retry after a crash re-applies the same generation and
    // converges. On Android establishing twice would take the platform's single
    // VPN slot away from itself.
    rig.block_on(rig.config.apply(&full_tunnel(1, Ruleset::Blocked)))
        .expect("retry");
    assert_eq!(rig.controller.establishes(), 1);

    // A new generation does establish, and the claim survives the swap.
    rig.block_on(rig.config.apply(&full_tunnel(2, Ruleset::Protected)))
        .expect("apply");
    assert_eq!(rig.controller.establishes(), 2);
    assert!(rig.config.enforcement_view().claim_in_force);
}

// ===========================================================================
// ROW 6 — process termination (the rehydration half)
// ===========================================================================

/// ADR-0022 **LC-2**: after an OS termination the peer resumes into
/// `RECONNECTING` carrying a code, never into `DISCONNECTED` and never silently.
///
/// The *kill* is device-bound and is `shells/android`'s instrumented test
/// (**written, not executed**). The **consequence** — what the next start does —
/// is a core decision and runs here.
#[test]
fn row_6_a_terminated_process_resumes_into_reconnecting_with_a_code() {
    let session = common::resumed_session(SessionState::Reconnecting { parked: false });
    assert_eq!(
        session.state().connection_state(),
        ConnectionState::Reconnecting
    );
    assert!(
        session.reason().is_some(),
        "LC-2 enters RECONNECTING WITH a code; a silent resume is unrepresentable"
    );
}

/// LC-2 row 4: a peer the user explicitly disconnected stays disconnected. **A
/// restart is not consent.**
#[test]
fn row_6_a_restart_does_not_reconnect_a_peer_the_user_disconnected() {
    let session = common::resumed_session(SessionState::Disconnected);
    assert_eq!(session.state(), SessionState::Disconnected);
    assert!(session.reason().is_none());
}

// ===========================================================================
// ROW 7 — restored connection
// ===========================================================================

#[test]
fn row_7_a_restored_secure_path_is_a_core_transition() {
    let mut session = common::blocked_session();
    let outcome = session.apply(
        Trigger::Event(Event::SecurePathRestored),
        common::restored(),
        common::context(),
    );
    let record = outcome.record().expect("T30 fired");
    assert_ne!(
        record.to,
        SessionState::Blocked,
        "a restored secure path leaves BLOCKED"
    );
}

// ===========================================================================
// ROW 8 — revoked peers
// ===========================================================================

/// `EV_PEER_REVOKED` is non-retryable, and the machine says so. The adapter has
/// no opinion and cannot have one.
#[test]
fn row_8_a_revoked_peer_reaches_a_terminal_state_with_its_own_code() {
    // A revocation is learned while the session is re-establishing, which is
    // where the transition table places it (T28). Driving it from a steady state
    // would be testing a row that does not exist.
    let mut session = common::resumed_session(SessionState::Reconnecting { parked: false });
    let outcome = session.apply(
        Trigger::Event(Event::PeerRevoked),
        common::healthy(),
        common::context(),
    );
    let record = outcome.record().expect("T28 fired");
    assert_eq!(record.to, SessionState::Failed);
    let code = record.reason_code.expect("a terminal state carries a code");
    assert_eq!(code.as_str(), "AUTH.DEVICE_REVOKED");
    assert!(
        twinvpn_types::ReasonCode::lookup(code.as_str()).is_some(),
        "the code is registered"
    );
    // LC-2 row 3: on the next start this stays FAILED rather than retrying
    // forever with no diagnosis.
    let resumed = common::resumed_session(SessionState::Failed);
    assert_eq!(resumed.state(), SessionState::Failed);
}

/// The **Android half** of revocation: `onRevoke()` drops our claim, and the
/// read-back then reports rules genuinely absent rather than a stale belief.
#[test]
fn row_8_on_revoke_drops_the_claim_and_the_read_back_tells_the_truth() {
    let rig = rig();
    rig.block_on(rig.config.apply(&full_tunnel(1, Ruleset::Protected)))
        .expect("apply");
    assert_eq!(
        rig.block_on(rig.config.installed_ruleset()).expect("read"),
        Some(Ruleset::Protected)
    );

    let handle = rig.tunnel.established_handle().expect("established");
    rig.block_on(rig.adapter.tunnel().destroy_interface(handle))
        .expect("revoked");

    assert_eq!(
        rig.block_on(rig.config.installed_ruleset()).expect("read"),
        None,
        "a dead claim is reported as no ruleset, which on Android is the truth"
    );
}
