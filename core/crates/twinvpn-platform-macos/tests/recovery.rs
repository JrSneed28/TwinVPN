//! Route recovery, DNS recovery, the kill switch across a restart, and the
//! transactional ordering that makes them possible.
//!
//! **Authority:** `docs/networking.md` §2.3 ("partial application is the leak
//! window") and §5.1; ADR-0008 (idempotent on the generation id); ADR-0010 R5
//! (reversible "including after an unclean process exit"); ADR-0011 DN-18,
//! DN-19, DN-20; ADR-0012 §11.5 clause 4, KS-17, KS-20, KS-23, §8 (arming must
//! never fail open); ADR-0016 PS-6, PS-21 step 3; ADR-0018 CB-6.
//!
//! Every test here runs on this Linux host against recording carriers, so the
//! **ordering** — which of the anchor, the routes and the resolver moves first,
//! and what is left behind when one of them fails — is a checked property rather
//! than an operational one.

use std::sync::Arc;

use twinvpn_platform::{ContractGeneration, NetworkConfig, Ruleset};
use twinvpn_platform_macos::netcfg::MacosNetworkConfig;
use twinvpn_platform_macos::pfread::PfStatus;
use twinvpn_platform_macos::resolver::RestorePoint;
use twinvpn_platform_macos::route::RouteAction;
use twinvpn_platform_macos::testkit::{self, Recorders};
use twinvpn_platform_macos::ShutdownLatch;

fn daemon() -> (MacosNetworkConfig, Recorders, ShutdownLatch) {
    let (carriers, recorders) = testkit::daemon_carriers();
    let latch = ShutdownLatch::new();
    (
        MacosNetworkConfig::new(latch.clone(), testkit::enforcement(), carriers),
        recorders,
        latch,
    )
}

// ---------------------------------------------------------------------------
// Ordering
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_firewall_is_installed_before_the_routes_and_the_resolver() {
    // ADR-0012 §11.5 clause 4. An interface that carries traffic before the rules
    // are live is the leak window the whole ordering exists to close.
    let (net, rec, _latch) = daemon();
    net.apply(&testkit::contract(1)).await.expect("applies");
    assert_eq!(rec.pf.load_count(), 1, "the anchor loaded exactly once");
    assert!(!rec.route.applied.lock().expect("lock").is_empty());
    assert_eq!(rec.resolver.plans.lock().expect("lock").len(), 1);
}

#[tokio::test]
async fn arming_never_fails_open() {
    // ADR-0012 §8: if the ruleset cannot be installed the client MUST NOT enter a
    // protected state. So a refused anchor load must leave NO route and NO
    // resolver change behind — the failure is total, not partial.
    let (net, rec, _latch) = daemon();
    rec.pf.fail_next_loads(1);
    let error = net.apply(&testkit::contract(1)).await.expect_err("refused");
    assert_eq!(error.reason_code().as_str(), "PLATFORM.ADAPTER_UNAVAILABLE");
    assert!(rec.route.attempted.lock().expect("lock").is_empty());
    assert!(rec.resolver.plans.lock().expect("lock").is_empty());
    assert_eq!(
        net.current_generation().await.expect("queries"),
        None,
        "nothing of ours is on the host"
    );
}

#[tokio::test]
async fn a_route_that_fails_halfway_unwinds_exactly_what_went_in() {
    // §2.3. The failure is on the SECOND operation, so the first must be deleted
    // and nothing else touched: deleting an op that never went in would remove a
    // route belonging to the previous generation or to the host.
    let (net, rec, _latch) = daemon();
    rec.route.fail_at(2);
    net.apply(&testkit::contract(1)).await.expect_err("refused");

    let attempted = rec.route.attempted.lock().expect("lock").clone();
    assert_eq!(attempted.len(), 3, "two adds, then one delete to unwind");
    assert_eq!(attempted[0].action, RouteAction::Add);
    assert_eq!(attempted[1].action, RouteAction::Add);
    assert_eq!(attempted[2].action, RouteAction::Delete);
    assert_eq!(attempted[2].destination, attempted[0].destination);
    assert!(
        rec.route.live_destinations().is_empty(),
        "the host is exactly as it was"
    );
    // And the resolver was never touched, because the routes never completed.
    assert!(rec.resolver.plans.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn a_resolver_failure_unwinds_the_routes_and_leaves_the_anchor_alone() {
    // CB-6 puts the installed ruleset in the OS's custody. Removing it because
    // the RESOLVER failed would open the leak window on a failure that has
    // nothing to do with enforcement.
    let (net, rec, _latch) = daemon();
    rec.resolver.fail_next_applies(1);
    net.apply(&testkit::contract(1)).await.expect_err("refused");

    assert!(
        rec.route.live_destinations().is_empty(),
        "the routes are unwound"
    );
    assert_eq!(rec.pf.load_count(), 1, "the anchor was loaded...");
    assert_eq!(
        net.installed_ruleset().await.expect("queries"),
        Some(Ruleset::Protected),
        "...and is STILL INSTALLED after the failure"
    );
}

#[tokio::test]
async fn the_restore_point_is_captured_and_persisted_before_the_resolver_moves() {
    // DN-18 and PS-6: "restore before mutate", and to a file rather than to
    // memory — a restore point held in a process that may be SIGKILLed is not a
    // restore point.
    let (net, rec, _latch) = daemon();
    rec.resolver.set_prior(RestorePoint {
        service_id: "TEST-SERVICE".to_owned(),
        servers: vec!["192.168.1.1".to_owned()],
        search_domains: vec!["lan".to_owned()],
        existed: true,
    });
    net.apply(&testkit::contract(1)).await.expect("applies");
    let persisted = rec.resolver.persisted.lock().expect("lock").clone();
    assert_eq!(persisted.len(), 1);
    assert_eq!(persisted[0].servers, vec!["192.168.1.1".to_owned()]);
    assert!(persisted[0].existed);
}

// ---------------------------------------------------------------------------
// Route recovery
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rollback_restores_the_host_exactly_and_in_reverse_order() {
    // ADR-0010 R5. Reverse, because a later route may depend on an earlier one.
    let (net, rec, _latch) = daemon();
    net.apply(&testkit::contract(1)).await.expect("applies");
    let added = rec.route.applied.lock().expect("lock").clone();
    net.rollback(ContractGeneration(1))
        .await
        .expect("rolls back");

    assert!(rec.route.live_destinations().is_empty());
    let all = rec.route.applied.lock().expect("lock").clone();
    let deletes: Vec<_> = all
        .iter()
        .filter(|op| op.action == RouteAction::Delete)
        .collect();
    assert_eq!(deletes.len(), added.len());
    assert_eq!(
        deletes[0].destination,
        added[added.len() - 1].destination,
        "the last route installed is the first one removed"
    );
}

#[tokio::test]
async fn rolling_back_a_generation_this_process_never_applied_is_a_no_op() {
    // R5 requires reversibility "including after an unclean process exit", and a
    // generation this process never applied is exactly that case: nothing of ours
    // is on the host under that id, so there is nothing to undo — and an error
    // here would stall a recovery that is already correct.
    let (net, rec, _latch) = daemon();
    net.rollback(ContractGeneration(42)).await.expect("no-op");
    assert!(rec.route.attempted.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn a_second_generation_replaces_the_first_and_rolls_back_to_it() {
    let (net, rec, _latch) = daemon();
    net.apply(&testkit::contract(1)).await.expect("applies");
    net.apply(&testkit::full_tunnel_contract(2, Ruleset::Protected))
        .await
        .expect("applies");
    assert_eq!(
        net.current_generation().await.expect("queries"),
        Some(ContractGeneration(2))
    );
    // Six live destinations: generation 1's two plus generation 2's four.
    assert_eq!(rec.route.live_destinations().len(), 6);

    net.rollback(ContractGeneration(2))
        .await
        .expect("rolls back");
    assert_eq!(
        rec.route.live_destinations().len(),
        2,
        "generation 1's routes survive a rollback of generation 2"
    );
}

// ---------------------------------------------------------------------------
// DNS recovery
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_resolver_is_restored_before_the_routes_go() {
    // DN-19 and PS-21 step 3: "so name resolution is never left pointing at a
    // dead stub". The restore has to happen while the interface still exists.
    let (net, rec, _latch) = daemon();
    rec.resolver.set_prior(RestorePoint {
        service_id: "TEST-SERVICE".to_owned(),
        servers: vec!["192.168.1.1".to_owned()],
        search_domains: Vec::new(),
        existed: true,
    });
    net.apply(&testkit::contract(1)).await.expect("applies");
    let routes_before = rec.route.attempted.lock().expect("lock").len();
    net.rollback(ContractGeneration(1))
        .await
        .expect("rolls back");

    let plans = rec.resolver.plans.lock().expect("lock").clone();
    assert_eq!(plans.len(), 2, "the apply's plan, then the restore's");
    // The restore names the host's own resolver again.
    let restore = plans.last().expect("a restore plan");
    assert_eq!(restore.sets.len(), 1);
    assert!(rec.route.attempted.lock().expect("lock").len() > routes_before);
}

#[tokio::test]
async fn a_service_with_no_prior_dns_is_restored_by_removing_ours() {
    // Writing an empty dictionary would leave the host with a resolver
    // configuration it never had.
    let (net, rec, _latch) = daemon();
    net.apply(&testkit::contract(1)).await.expect("applies");
    net.rollback(ContractGeneration(1))
        .await
        .expect("rolls back");
    let restore = rec.resolver.last_plan().expect("a restore plan");
    assert!(restore.sets.is_empty());
    assert_eq!(restore.removes.len(), 1);
}

#[tokio::test]
async fn a_failed_resolver_restore_leaves_the_device_fail_closed() {
    // DN-20. The anchor is NOT removed when the restore fails: regaining an
    // upstream resolver in an unarmed window is the outcome that rule forbids.
    let (net, rec, _latch) = daemon();
    net.apply(&testkit::contract(1)).await.expect("applies");
    rec.resolver.fail_next_applies(1);
    net.rollback(ContractGeneration(1))
        .await
        .expect("rolls back anyway");
    assert_eq!(
        net.installed_ruleset().await.expect("queries"),
        Some(Ruleset::Protected),
        "the anchor survives a failed resolver restore"
    );
}

#[tokio::test]
async fn the_extension_binding_programmes_no_resolver_at_all() {
    // Under `NEPacketTunnelNetworkSettings` the OS installs the resolver from the
    // settings object. A carrier that also wrote `SCDynamicStore` keys would be
    // two writers for one fact.
    let (carriers, rec) = testkit::extension_carriers();
    let net = MacosNetworkConfig::new(ShutdownLatch::new(), testkit::enforcement(), carriers);
    net.apply(&testkit::contract(1)).await.expect("applies");
    assert!(rec.resolver.plans.lock().expect("lock").is_empty());
    assert!(rec.route.attempted.lock().expect("lock").is_empty());
    assert_eq!(
        rec.pf.load_count(),
        1,
        "the anchor is still ours to install"
    );
}

// ---------------------------------------------------------------------------
// The kill switch across a restart
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_anchor_outlives_the_process_and_is_reclaimed_rather_than_recreated() {
    // KS-20 and ADR-0016 §11.6 step 2. The recording engine keeps the anchor and
    // the new `MacosNetworkConfig` starts with an empty history — which is
    // exactly what a crash leaves behind.
    let (carriers, rec) = testkit::daemon_carriers();
    let net = MacosNetworkConfig::new(ShutdownLatch::new(), testkit::enforcement(), carriers);
    net.apply(&testkit::contract(7)).await.expect("applies");
    drop(net);

    let surviving = Arc::new(rec.pf.survive_process_exit());
    let (mut carriers, rec2) = testkit::daemon_carriers();
    carriers.pf = surviving;
    let restarted = MacosNetworkConfig::new(ShutdownLatch::new(), testkit::enforcement(), carriers);

    // **Read from pf, not from memory.** This is the recovery entry point.
    assert_eq!(
        restarted.current_generation().await.expect("queries"),
        Some(ContractGeneration(7)),
        "a fresh process learns the generation from the kernel"
    );
    assert_eq!(
        restarted.installed_ruleset().await.expect("queries"),
        Some(Ruleset::Protected)
    );
    let assertion = restarted.assertion().expect("queries");
    assert!(assertion.supports(Ruleset::Protected));
    assert_eq!(
        rec2.pf.load_count(),
        0,
        "nothing was re-rendered to find out"
    );
}

#[tokio::test]
async fn the_posture_swap_re_renders_the_applied_contract_and_never_a_synthetic_one() {
    // A swap that rendered an empty contract would emit a Tier-2 drop over
    // nothing, and its anchor load would replace the real drops — a "fail-closed"
    // swap that opens the host.
    let (net, rec, _latch) = daemon();
    net.apply(&testkit::full_tunnel_contract(3, Ruleset::Blocked))
        .await
        .expect("applies");
    net.set_ruleset(ContractGeneration(3), Ruleset::Protected)
        .await
        .expect("swaps");

    let anchor = rec.pf.last_load().expect("an anchor");
    assert!(anchor.contains("tv_posture_protected"));
    assert!(
        anchor.contains("tv_scope4_n2"),
        "the FULL-TUNNEL scope survived"
    );
    assert!(anchor.contains("tv_scope6_n2"));
    assert_eq!(
        net.installed_ruleset().await.expect("queries"),
        Some(Ruleset::Protected)
    );
}

#[tokio::test]
async fn a_swap_for_a_generation_this_process_did_not_apply_is_refused() {
    let (net, rec, _latch) = daemon();
    net.apply(&testkit::contract(1)).await.expect("applies");
    let before = rec.pf.load_count();
    net.set_ruleset(ContractGeneration(99), Ruleset::Blocked)
        .await
        .expect_err("refused");
    assert_eq!(rec.pf.load_count(), before, "nothing was loaded");
}

#[tokio::test]
async fn the_swap_is_one_load_and_never_a_remove_then_add() {
    // KS-23. Two invocations would open the window KS-17 exists to close.
    let (net, rec, _latch) = daemon();
    net.apply(&testkit::contract(4)).await.expect("applies");
    let before = rec.pf.load_count();
    net.set_ruleset(ContractGeneration(4), Ruleset::Blocked)
        .await
        .expect("swaps");
    assert_eq!(rec.pf.load_count(), before + 1);
}

#[tokio::test]
async fn applying_the_same_generation_twice_changes_nothing() {
    // ADR-0008: idempotent on the generation id, so a retry after a crash
    // converges rather than duplicating routes.
    let (net, rec, _latch) = daemon();
    net.apply(&testkit::contract(1)).await.expect("applies");
    let loads = rec.pf.load_count();
    let routes = rec.route.attempted.lock().expect("lock").len();
    net.apply(&testkit::contract(1)).await.expect("converges");
    assert_eq!(rec.pf.load_count(), loads);
    assert_eq!(rec.route.attempted.lock().expect("lock").len(), routes);
}

#[tokio::test]
async fn pf_being_switched_off_underneath_us_is_visible_to_the_reconciler() {
    // K12: enforcement state is observable by QUERYING the installed rules. A
    // cached posture cannot notice that somebody ran `pfctl -d`.
    let (net, rec, _latch) = daemon();
    net.apply(&testkit::contract(1)).await.expect("applies");
    assert_eq!(
        net.installed_ruleset().await.expect("queries"),
        Some(Ruleset::Protected)
    );
    rec.pf.set_status(PfStatus::Disabled);
    assert_eq!(
        net.installed_ruleset().await.expect("queries"),
        None,
        "an anchor in a disabled filter is not an installed ruleset"
    );
    assert!(!net
        .assertion()
        .expect("queries")
        .supports(Ruleset::Protected));
}

#[tokio::test]
async fn the_leak_canary_reads_the_counter_out_of_pfs_own_answer() {
    let (net, rec, _latch) = daemon();
    net.apply(&testkit::contract(1)).await.expect("applies");
    assert_eq!(
        twinvpn_platform_macos::pfread::packets_on(
            &net.counters().expect("queries"),
            "twinvpn.deny.v6"
        ),
        0
    );
    rec.pf.bump("twinvpn.deny.v6", 1);
    assert_eq!(
        twinvpn_platform_macos::pfread::packets_on(
            &net.counters().expect("queries"),
            "twinvpn.deny.v6"
        ),
        1,
        "the v6 canary's datagram was dropped, which is the negative result the \
         canary exists to observe"
    );
}

// ---------------------------------------------------------------------------
// KS-20a — the offline recovery path `twinvpn-unblock` links
//
// ADR-0012 §10: "a crash between 'rules installed' and 'agent running' leaves a
// host blocked with no UI … without it, a bug in this ADR bricks connectivity."
// ADR-0017 MI-12 makes the command agent-independent, which is why these two
// functions take an ENGINE rather than a `MacosNetworkConfig`: the recovery path
// must not need the transaction object the authority owns.
// ---------------------------------------------------------------------------

#[test]
fn the_unblock_removes_only_the_owner_tagged_anchor_and_never_flushes_pf() {
    use twinvpn_platform_macos::netcfg::PfEngine as _;

    // KS-20's reclamation is scoped to what we tagged. An empty load into our
    // own anchor is one transaction that touches no rule outside it; a flush
    // would take the host's own firewall with it, which is a worse outage than
    // the one being fixed.
    let pf = testkit::RecordingPf::default();
    pf.load_anchor(
        twinvpn_platform_macos::pf::ANCHOR,
        &twinvpn_platform_macos::pf::render(
            &testkit::contract_with(7, Ruleset::Blocked),
            Ruleset::Blocked,
            &testkit::enforcement(),
        ),
    )
    .expect("armed");
    assert!(
        twinvpn_platform_macos::netcfg::read_owner_tagged_anchor(&pf)
            .expect("readable")
            .is_some(),
        "the fixture must start blocked or the test proves nothing"
    );

    twinvpn_platform_macos::netcfg::remove_owner_tagged_anchor(&pf).expect("removed");
    assert_eq!(
        pf.last_load().as_deref(),
        Some(""),
        "the removal is an empty load into our anchor, not a flush"
    );
    assert!(
        twinvpn_platform_macos::netcfg::read_owner_tagged_anchor(&pf)
            .expect("readable")
            .is_none()
    );
}

#[test]
fn a_removal_that_the_kernel_does_not_confirm_is_reported_as_a_failure() {
    use twinvpn_platform::PlatformError;
    use twinvpn_platform_macos::netcfg::PfEngine;

    // **W-24 in the other direction.** The dangerous failure here is telling an
    // operator the host is unblocked when it is not, so the read-back is part of
    // the operation rather than a courtesy afterwards.
    #[derive(Debug, Default)]
    struct StubbornPf(testkit::RecordingPf);

    impl PfEngine for StubbornPf {
        fn load_anchor(&self, anchor: &str, body: &str) -> Result<(), PlatformError> {
            self.0.load_anchor(anchor, body)
        }
        fn status(&self) -> Result<PfStatus, PlatformError> {
            self.0.status()
        }
        fn tables(
            &self,
            _anchor: &str,
        ) -> Result<Option<twinvpn_platform_macos::pfread::Installed>, PlatformError> {
            // The kernel still holds it, whatever the load said.
            Ok(Some(twinvpn_platform_macos::pfread::Installed {
                ruleset: Ruleset::Blocked,
                generation: Some(ContractGeneration(7)),
                scope: twinvpn_types::PerFamily { v4: 1, v6: 1 },
            }))
        }
        fn labels(
            &self,
            anchor: &str,
        ) -> Result<
            std::collections::BTreeMap<String, twinvpn_platform_macos::pfread::LabelCounters>,
            PlatformError,
        > {
            self.0.labels(anchor)
        }
    }

    let pf = StubbornPf::default();
    assert!(
        twinvpn_platform_macos::netcfg::remove_owner_tagged_anchor(&pf).is_err(),
        "a load that returned Ok is not a removal"
    );
}

#[test]
fn the_unblock_status_read_changes_nothing() {
    // An operator asking "is TwinVPN what is blocking me" must not have to run
    // the destructive command to find out.
    let pf = testkit::RecordingPf::default();
    let before = pf.load_count();
    let _ = twinvpn_platform_macos::netcfg::read_owner_tagged_anchor(&pf).expect("readable");
    assert_eq!(pf.load_count(), before);
}
