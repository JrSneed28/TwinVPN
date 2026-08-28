//! `NetworkConfig` over a `socketpair`-backed controller, so `apply`,
//! `rollback`, the KS-17 swap and the read-back are **executed** on this host.

use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

use super::*;
use crate::hostcall::RawFd;
use crate::netchange::AndroidNetwork;
use crate::power::KeepalivePlan;
use crate::testkit::{contract, host_v4, host_v6, route};
use twinvpn_platform::iface::InterfaceName;
use twinvpn_platform::TunnelDevice;
use twinvpn_types::IpPrefix;

mod facts;

/// A controller that hands out `socketpair` descriptors and records what it was
/// asked to do.
#[derive(Debug)]
struct FakeController {
    establishes: AtomicUsize,
    underlying: Mutex<Vec<Vec<u64>>>,
    open: Mutex<Vec<RawFd>>,
    refuse_establish: bool,
}

impl FakeController {
    fn new(refuse_establish: bool) -> Arc<Self> {
        Arc::new(Self {
            establishes: AtomicUsize::new(0),
            underlying: Mutex::new(Vec::new()),
            open: Mutex::new(Vec::new()),
            refuse_establish,
        })
    }
}

impl Drop for FakeController {
    fn drop(&mut self) {
        for fd in self.open.lock().expect("lock").drain(..) {
            // SAFETY: every descriptor in `open` is the far end of a
            // `socketpair` this value created and nothing else owns.
            unsafe { libc::close(fd) };
        }
    }
}

impl TunnelController for FakeController {
    fn name(&self) -> &'static str {
        "fake-vpnservice"
    }
    fn establish(&self, _programme: &Programme) -> Result<RawFd, PlatformError> {
        if self.refuse_establish {
            return Err(PlatformError::VpnPermissionDenied(None));
        }
        self.establishes.fetch_add(1, AtomicOrdering::SeqCst);
        let mut fds = [0 as RawFd; 2];
        // SAFETY: `socketpair` writes exactly two ints through the pointer it is
        // given; `fds` is a live array of exactly that size.
        let rc = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM,
                0,
                fds.as_mut_ptr().cast::<libc::c_int>(),
            )
        };
        assert_eq!(rc, 0, "socketpair");
        self.open.lock().expect("lock").push(fds[0]);
        Ok(fds[1])
    }
    fn close_tun(&self, _fd: RawFd) -> Result<(), PlatformError> {
        Ok(())
    }
    fn set_underlying_networks(&self, handles: &[u64]) -> Result<(), PlatformError> {
        self.underlying.lock().expect("lock").push(handles.to_vec());
        Ok(())
    }
    fn protect_socket(&self, _fd: RawFd) -> Result<(), PlatformError> {
        Ok(())
    }
    fn request_keepalive(&self, _fd: RawFd, _plan: KeepalivePlan) -> Result<(), PlatformError> {
        Ok(())
    }
}

struct Rig {
    controller: Arc<FakeController>,
    tunnel: AndroidTunnelDevice,
    interfaces: AndroidInterfaceProvider,
    config: AndroidNetworkConfig,
    handle: TunnelHandle,
}

async fn rig(refuse_establish: bool) -> Rig {
    let latch = ShutdownLatch::new();
    let controller = FakeController::new(refuse_establish);
    let tunnel = AndroidTunnelDevice::new(controller.clone(), latch.clone());
    let interfaces = AndroidInterfaceProvider::new(latch.clone());
    let config = AndroidNetworkConfig::new(
        controller.clone(),
        tunnel.clone(),
        interfaces.clone(),
        VpnConfig::default(),
        latch,
    );
    let name = InterfaceName::new("twin0").expect("name");
    let handle = tunnel.create_interface(&name, 1400).await.expect("create");
    config.bind_handle(handle);
    Rig {
        controller,
        tunnel,
        interfaces,
        config,
        handle,
    }
}

fn underlay(handle: u64, transports: u32, v4: bool, v6: bool) -> AndroidNetwork {
    AndroidNetwork {
        handle,
        name: InterfaceName::new("wlan0").expect("name"),
        transports: TransportSet::from_bits(transports),
        addresses: Vec::new(),
        default_routes: PerFamily::new(v4, v6),
        resolvers: vec![host_v4([192, 168, 1, 1]), host_v6(0x53)],
        mtu: 1500,
        metered: false,
        nat64: None,
        private_dns_active: false,
        is_up: true,
    }
}

fn full_tunnel(generation: u64, ruleset: Ruleset) -> NetworkContract {
    let mut c = contract(generation, ruleset);
    c.routes.v4.push(route("0.0.0.0/0"));
    c.routes.v6.push(route("::/0"));
    c
}

// ---------------------------------------------------------------------------
// apply
// ---------------------------------------------------------------------------

#[tokio::test]
async fn apply_establishes_once_and_records_the_generation() {
    let rig = rig(false).await;
    rig.config
        .apply(&full_tunnel(1, Ruleset::Blocked))
        .await
        .expect("apply");
    assert_eq!(rig.controller.establishes.load(AtomicOrdering::SeqCst), 1);
    assert_eq!(
        rig.config.current_generation().await.expect("read"),
        Some(ContractGeneration(1))
    );
    assert!(rig.tunnel.claim_in_force(rig.handle));
}

/// ADR-0008: idempotent on the generation id, so a retry after a crash
/// converges rather than establishing twice — which on Android would take the
/// platform's single VPN slot away from itself.
#[tokio::test]
async fn re_applying_the_generation_in_force_establishes_nothing() {
    let rig = rig(false).await;
    rig.config
        .apply(&full_tunnel(1, Ruleset::Blocked))
        .await
        .expect("apply");
    rig.config
        .apply(&full_tunnel(1, Ruleset::Blocked))
        .await
        .expect("again");
    assert_eq!(rig.controller.establishes.load(AtomicOrdering::SeqCst), 1);
}

/// §5.1's all-or-nothing half: on failure the system is exactly as it was.
#[tokio::test]
async fn a_refused_establish_leaves_no_generation_and_no_claim() {
    let rig = rig(true).await;
    let err = rig
        .config
        .apply(&full_tunnel(1, Ruleset::Blocked))
        .await
        .expect_err("refused");
    assert_eq!(err.reason_code().as_str(), "PLATFORM.VPN_PERMISSION_DENIED");
    assert_eq!(rig.config.current_generation().await.expect("read"), None);
    assert_eq!(rig.config.installed_ruleset().await.expect("read"), None);
}

/// A contract that cannot be expressed fails **before** anything is touched.
#[tokio::test]
async fn an_unrenderable_contract_fails_with_nothing_established() {
    let rig = rig(false).await;
    let mut bad = full_tunnel(1, Ruleset::Protected);
    bad.mtu = 1000;
    assert!(rig.config.apply(&bad).await.is_err());
    assert_eq!(rig.controller.establishes.load(AtomicOrdering::SeqCst), 0);
    assert_eq!(rig.config.current_generation().await.expect("read"), None);
}

// ---------------------------------------------------------------------------
// the KS-17 swap and the read-back
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_ruleset_swap_changes_no_claim_and_is_reported_from_the_os_observed_half() {
    let rig = rig(false).await;
    rig.config
        .apply(&full_tunnel(1, Ruleset::Blocked))
        .await
        .expect("apply");
    let before = rig.config.enforcement_view();
    assert_eq!(
        rig.config.installed_ruleset().await.expect("read"),
        Some(Ruleset::Blocked)
    );

    rig.config
        .set_ruleset(ContractGeneration(1), Ruleset::Protected)
        .await
        .expect("swap");
    let after = rig.config.enforcement_view();

    assert_eq!(
        rig.config.installed_ruleset().await.expect("read"),
        Some(Ruleset::Protected)
    );
    assert_eq!(rig.controller.establishes.load(AtomicOrdering::SeqCst), 1);
    assert_eq!(before.claims_default, after.claims_default);
    assert_eq!(before.claim_in_force, after.claim_in_force);
}

#[tokio::test]
async fn a_swap_against_a_generation_we_do_not_hold_is_refused() {
    let rig = rig(false).await;
    rig.config
        .apply(&full_tunnel(1, Ruleset::Blocked))
        .await
        .expect("apply");
    assert!(rig
        .config
        .set_ruleset(ContractGeneration(9), Ruleset::Protected)
        .await
        .is_err());
    assert_eq!(
        rig.config.installed_ruleset().await.expect("read"),
        Some(Ruleset::Blocked),
        "a stale caller must not unblock"
    );
}

/// Blocking during shutdown is permitted; unblocking is not. A refusal in the
/// dangerous direction is not a refusal worth having.
#[tokio::test]
async fn blocking_is_always_permitted_and_unblocking_is_not() {
    let latch = ShutdownLatch::new();
    let controller = FakeController::new(false);
    let tunnel = AndroidTunnelDevice::new(controller.clone(), latch.clone());
    let interfaces = AndroidInterfaceProvider::new(latch.clone());
    let config = AndroidNetworkConfig::new(
        controller,
        tunnel.clone(),
        interfaces,
        VpnConfig::default(),
        latch.clone(),
    );
    let name = InterfaceName::new("twin0").expect("name");
    let handle = tunnel.create_interface(&name, 1400).await.expect("create");
    config.bind_handle(handle);
    config
        .apply(&full_tunnel(1, Ruleset::Protected))
        .await
        .expect("apply");
    config
        .set_ruleset(ContractGeneration(1), Ruleset::Protected)
        .await
        .expect("protect");

    latch.begin();
    config
        .set_ruleset(ContractGeneration(1), Ruleset::Blocked)
        .await
        .expect("blocking during shutdown is always permitted");
    assert!(
        config
            .set_ruleset(ContractGeneration(1), Ruleset::Protected)
            .await
            .is_err(),
        "unblocking during shutdown is refused"
    );
}

/// ADR-0012 §11.6's Android limitation row, read back from the adapter.
#[tokio::test]
async fn custody_reports_the_android_residual_until_lockdown_is_confirmed() {
    let rig = rig(false).await;
    rig.config
        .apply(&full_tunnel(1, Ruleset::Protected))
        .await
        .expect("apply");

    let custody = rig.config.enforcement_custody();
    assert!(custody.swap_is_atomic);
    assert!(
        !custody.survives_core_exit(),
        "the descriptor dies with the process: 'everything, until the user enables lockdown'"
    );
    assert_eq!(rig.config.lockdown(), LockdownPosture::Unverified);

    rig.config.set_lockdown_report(Some(true));
    assert!(rig.config.enforcement_custody().survives_core_exit());
    rig.config.set_lockdown_report(None);
    assert!(
        !rig.config.enforcement_custody().survives_core_exit(),
        "an unreported posture is UNVERIFIED, which presents as unprotected"
    );
}

// ---------------------------------------------------------------------------
// rollback
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rollback_restores_the_generation_before_the_named_one() {
    let rig = rig(false).await;
    rig.config
        .apply(&full_tunnel(1, Ruleset::Blocked))
        .await
        .expect("g1");
    rig.config
        .apply(&full_tunnel(2, Ruleset::Protected))
        .await
        .expect("g2");
    assert_eq!(
        rig.config.current_generation().await.expect("read"),
        Some(ContractGeneration(2))
    );

    rig.config
        .rollback(ContractGeneration(2))
        .await
        .expect("rollback");
    assert_eq!(
        rig.config.current_generation().await.expect("read"),
        Some(ContractGeneration(1))
    );
    assert_eq!(
        rig.controller.establishes.load(AtomicOrdering::SeqCst),
        3,
        "the rollback re-establishes; the window is real and is not hidden"
    );
}

#[tokio::test]
async fn a_rollback_to_a_generation_we_do_not_hold_is_refused_not_approximated() {
    let rig = rig(false).await;
    rig.config
        .apply(&full_tunnel(1, Ruleset::Blocked))
        .await
        .expect("g1");
    // No generation before the first one.
    assert!(rig.config.rollback(ContractGeneration(1)).await.is_err());
    // And an unknown generation entirely.
    assert!(rig.config.rollback(ContractGeneration(99)).await.is_err());
    assert_eq!(
        rig.config.current_generation().await.expect("read"),
        Some(ContractGeneration(1)),
        "a refused rollback changes nothing"
    );
}

#[tokio::test]
async fn the_generation_history_is_bounded_and_an_aged_out_rollback_is_refused() {
    let rig = rig(false).await;
    for id in 1..=(GENERATION_HISTORY as u64 + 2) {
        rig.config
            .apply(&full_tunnel(id, Ruleset::Blocked))
            .await
            .expect("apply");
    }
    assert!(
        rig.config.rollback(ContractGeneration(2)).await.is_err(),
        "generation 1 has aged out; approximating it would install a contract \
         the core never asked for"
    );
}
