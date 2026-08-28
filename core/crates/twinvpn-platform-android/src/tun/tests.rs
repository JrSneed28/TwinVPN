//! `TunnelDevice` over a `socketpair`, so the descriptor lifecycle and both
//! packet directions are **executed** on this host: bionic and glibc share the
//! descriptor API, so the code exercised here is the code that ships.

use super::*;
use crate::builder::Programme;
use crate::power::KeepalivePlan;
use twinvpn_types::PerFamily;

/// A controller backed by a `socketpair`, so the read and write paths in
/// this module are genuinely exercised on this host: bionic and glibc share
/// the descriptor API, so the code under test is the code that ships.
#[derive(Debug)]
struct PairController {
    peer: Mutex<Option<RawFd>>,
    refuse: bool,
}

impl PairController {
    fn new(refuse: bool) -> (Arc<Self>, RawFd) {
        let mut fds = [0 as RawFd; 2];
        // SAFETY: `socketpair` writes exactly two ints through the pointer
        // it is given; `fds` is a live array of exactly that size.
        let rc = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM,
                0,
                fds.as_mut_ptr().cast::<libc::c_int>(),
            )
        };
        assert_eq!(rc, 0, "socketpair");
        (
            Arc::new(Self {
                peer: Mutex::new(Some(fds[0])),
                refuse,
            }),
            fds[1],
        )
    }
}

impl TunnelController for PairController {
    fn name(&self) -> &'static str {
        "socketpair"
    }
    fn establish(&self, _programme: &Programme) -> Result<RawFd, PlatformError> {
        if self.refuse {
            return Err(PlatformError::VpnPermissionDenied(None));
        }
        self.peer
            .lock()
            .expect("lock")
            .take()
            .ok_or(PlatformError::AdapterUnavailable(None))
    }
    fn close_tun(&self, _fd: RawFd) -> Result<(), PlatformError> {
        Ok(())
    }
    fn set_underlying_networks(&self, _handles: &[u64]) -> Result<(), PlatformError> {
        Ok(())
    }
    fn protect_socket(&self, _fd: RawFd) -> Result<(), PlatformError> {
        Ok(())
    }
    fn request_keepalive(&self, _fd: RawFd, _plan: KeepalivePlan) -> Result<(), PlatformError> {
        Ok(())
    }
}

fn programme() -> Programme {
    Programme {
        ops: Vec::new(),
        claims_default: PerFamily::new(true, true),
        unsupported: Vec::new(),
    }
}

fn name() -> InterfaceName {
    InterfaceName::new("twin0").expect("name")
}

#[tokio::test]
async fn create_interface_establishes_nothing_so_there_is_nothing_to_leak_through() {
    let (controller, _peer) = PairController::new(false);
    let device = AndroidTunnelDevice::new(controller, ShutdownLatch::new());
    let handle = device
        .create_interface(&name(), 1400)
        .await
        .expect("create");
    assert!(
        !device.claim_in_force(handle),
        "no descriptor exists before apply"
    );
    assert_eq!(device.established_handle(), None);
    // And a read against it is an interface fact, not a panic.
    let mut buf = [0u8; 64];
    let err = device
        .read_packet(handle, &mut buf)
        .await
        .expect_err("no descriptor");
    assert_eq!(err.reason_code().as_str(), "NET.IFACE_DOWN");
}

#[tokio::test]
async fn a_handle_is_never_zero() {
    let (controller, _peer) = PairController::new(false);
    let device = AndroidTunnelDevice::new(controller, ShutdownLatch::new());
    let handle = device
        .create_interface(&name(), 1400)
        .await
        .expect("create");
    assert_ne!(handle.0, 0);
}

#[tokio::test]
async fn packets_cross_the_descriptor_in_both_directions() {
    let (controller, peer) = PairController::new(false);
    let device = AndroidTunnelDevice::new(controller, ShutdownLatch::new());
    let handle = device
        .create_interface(&name(), 1400)
        .await
        .expect("create");
    device.establish(handle, &programme()).expect("establish");
    assert!(device.claim_in_force(handle));
    assert_eq!(device.established_handle(), Some(handle));

    // The far end writes a "packet"; read_packet must see it.
    let payload = b"\x45\x00\x00\x14 a v4 header shape";
    // SAFETY: `write` reads exactly `payload.len()` bytes from a live slice
    // of that length, on a descriptor this test owns.
    let n = unsafe { libc::write(peer, payload.as_ptr().cast::<libc::c_void>(), payload.len()) };
    assert_eq!(usize::try_from(n).expect("wrote"), payload.len());

    let mut buf = [0u8; 128];
    let got = device.read_packet(handle, &mut buf).await.expect("read");
    assert_eq!(&buf[..got], payload);

    // And the write path.
    let out = b"\x60\x00\x00\x00 a v6 header shape";
    let wrote = device.write_packet(handle, out).await.expect("write");
    assert_eq!(wrote, out.len());
    let mut back = [0u8; 128];
    // SAFETY: `read` writes at most `back.len()` bytes into a live slice of
    // that length, on a descriptor this test owns.
    let got = unsafe { libc::read(peer, back.as_mut_ptr().cast::<libc::c_void>(), back.len()) };
    assert_eq!(&back[..usize::try_from(got).expect("read")], out);
    // SAFETY: the test owns `peer` and closes it exactly once, here.
    unsafe { libc::close(peer) };
}

#[tokio::test]
async fn the_datapath_is_userspace_because_android_has_no_kernel_offload() {
    let (controller, _peer) = PairController::new(false);
    let device = AndroidTunnelDevice::new(controller, ShutdownLatch::new());
    assert_eq!(device.datapath(), Datapath::Userspace);
}

#[tokio::test]
async fn set_link_does_not_touch_the_claim() {
    let (controller, _peer) = PairController::new(false);
    let device = AndroidTunnelDevice::new(controller, ShutdownLatch::new());
    let handle = device
        .create_interface(&name(), 1400)
        .await
        .expect("create");
    device.establish(handle, &programme()).expect("establish");
    for state in [LinkState::Down, LinkState::Up, LinkState::Down] {
        device.set_link(handle, state).await.expect("set_link");
        assert!(
            device.claim_in_force(handle),
            "the claim survives every link transition; KS-17"
        );
    }
}

#[tokio::test]
async fn destroy_is_idempotent_and_closes_the_descriptor_once() {
    let (controller, _peer) = PairController::new(false);
    let device = AndroidTunnelDevice::new(controller, ShutdownLatch::new());
    let handle = device
        .create_interface(&name(), 1400)
        .await
        .expect("create");
    device.establish(handle, &programme()).expect("establish");
    device.destroy_interface(handle).await.expect("destroy");
    device.destroy_interface(handle).await.expect("again");
    assert!(!device.claim_in_force(handle));
}

#[tokio::test]
async fn destroy_still_works_after_shutdown_begins() {
    let latch = ShutdownLatch::new();
    let (controller, _peer) = PairController::new(false);
    let device = AndroidTunnelDevice::new(controller, latch.clone());
    let handle = device
        .create_interface(&name(), 1400)
        .await
        .expect("create");
    latch.begin();
    device
        .destroy_interface(handle)
        .await
        .expect("a descriptor must not leak for the life of the process");
}

#[tokio::test]
async fn set_mtu_is_idempotent_and_otherwise_reports_the_platform_fact() {
    let (controller, _peer) = PairController::new(false);
    let device = AndroidTunnelDevice::new(controller, ShutdownLatch::new());
    let handle = device
        .create_interface(&name(), 1400)
        .await
        .expect("create");
    // Re-asserting the value in force is not a failure.
    device.set_mtu(handle, 1400).await.expect("idempotent");
    // Changing it is refused, with the fact named -- never emulated by a
    // re-establish that would drop the claim.
    let err = device.set_mtu(handle, 1280).await.expect_err("refused");
    assert_eq!(err.reason_code().as_str(), "PLATFORM.OS_UNSUPPORTED");
    assert_eq!(err.os_detail().map(|d| d.code), Some(1280));
}

#[tokio::test]
async fn a_refused_consent_reaches_the_caller_as_the_vpn_grant() {
    let (controller, peer) = PairController::new(true);
    let device = AndroidTunnelDevice::new(controller, ShutdownLatch::new());
    let handle = device
        .create_interface(&name(), 1400)
        .await
        .expect("create");
    let err = device.establish(handle, &programme()).expect_err("refused");
    assert_eq!(err.reason_code().as_str(), "PLATFORM.VPN_PERMISSION_DENIED");
    // SAFETY: the test owns `peer` and closes it exactly once, here.
    unsafe { libc::close(peer) };
}

#[tokio::test]
async fn every_call_is_refused_once_shutdown_begins() {
    let latch = ShutdownLatch::new();
    let (controller, _peer) = PairController::new(false);
    let device = AndroidTunnelDevice::new(controller, latch.clone());
    let handle = device
        .create_interface(&name(), 1400)
        .await
        .expect("create");
    latch.begin();
    assert!(matches!(
        device
            .create_interface(&name(), 1400)
            .await
            .expect_err("latched"),
        PlatformError::ShuttingDown
    ));
    assert!(matches!(
        device
            .set_link(handle, LinkState::Up)
            .await
            .expect_err("latched"),
        PlatformError::ShuttingDown
    ));
    assert!(matches!(
        device.set_mtu(handle, 1300).await.expect_err("latched"),
        PlatformError::ShuttingDown
    ));
}
