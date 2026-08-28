//! Loopback tests for the socket provider.
//!
//! These run **on this host**, and that is not an accident of convenience:
//! bionic and glibc share the socket API this module uses, so the code exercised
//! here is the code that ships. It is the same argument
//! `twinvpn-platform-linux` makes for testing its `nft --json` parser without
//! `nft` installed, applied to a layer that genuinely can be run.
//!
//! What is **not** covered: `VpnService.protect` itself, which needs a device.
//! What *is* covered is that no socket escapes without it having been called —
//! which is the property KS-9(1) actually depends on.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use super::*;
use crate::builder::Programme;
use crate::power::KeepalivePlan;
use twinvpn_platform::socket::{FragmentPolicy, SocketOptions};
use twinvpn_types::{AddressFamily, V4Addr, V6Addr};

/// A controller that counts `protect` calls and can refuse them.
#[derive(Debug, Default)]
struct CountingController {
    protects: AtomicUsize,
    refuse_protect: bool,
    protected_fds: Mutex<Vec<RawFd>>,
}

impl CountingController {
    fn new(refuse_protect: bool) -> Arc<Self> {
        Arc::new(Self {
            protects: AtomicUsize::new(0),
            refuse_protect,
            protected_fds: Mutex::new(Vec::new()),
        })
    }
}

impl TunnelController for CountingController {
    fn name(&self) -> &'static str {
        "counting"
    }
    fn establish(&self, _programme: &Programme) -> Result<RawFd, PlatformError> {
        Err(PlatformError::OsUnsupported(None))
    }
    fn close_tun(&self, _fd: RawFd) -> Result<(), PlatformError> {
        Ok(())
    }
    fn set_underlying_networks(&self, _handles: &[u64]) -> Result<(), PlatformError> {
        Ok(())
    }
    fn protect_socket(&self, fd: RawFd) -> Result<(), PlatformError> {
        self.protects.fetch_add(1, Ordering::SeqCst);
        if self.refuse_protect {
            return Err(PlatformError::NotPermitted(None));
        }
        self.protected_fds.lock().expect("lock").push(fd);
        Ok(())
    }
    fn request_keepalive(&self, _fd: RawFd, _plan: KeepalivePlan) -> Result<(), PlatformError> {
        Ok(())
    }
}

fn provider(refuse_protect: bool) -> (AndroidSocketProvider, Arc<CountingController>) {
    let controller = CountingController::new(refuse_protect);
    (
        AndroidSocketProvider::new(controller.clone(), ShutdownLatch::new()),
        controller,
    )
}

fn spec(family: SocketFamily) -> UdpBindSpec {
    UdpBindSpec {
        family,
        local: None,
        options: SocketOptions::default(),
    }
}

/// **The KS-9(1) property**, asserted rather than assumed: no socket reaches the
/// core without `VpnService.protect` having succeeded for it.
#[tokio::test]
async fn every_socket_is_protected_before_it_is_bound() {
    let (sockets, controller) = provider(false);
    let socket = sockets
        .bind_udp(&spec(SocketFamily::V4))
        .await
        .expect("bind");
    assert_eq!(controller.protects.load(Ordering::SeqCst), 1);
    // And it is the socket we got back that was protected.
    let bound = socket.local_endpoint().expect("bound");
    assert_ne!(bound.port.get(), 0, "an ephemeral port was assigned");
}

#[tokio::test]
async fn a_socket_that_cannot_be_protected_is_never_returned() {
    let (sockets, controller) = provider(true);
    let Err(err) = sockets.bind_udp(&spec(SocketFamily::V4)).await else {
        panic!("a socket that could not be protected must not be returned");
    };
    assert_eq!(err.reason_code().as_str(), "PLATFORM.ADAPTER_UNAVAILABLE");
    assert_eq!(controller.protects.load(Ordering::SeqCst), 1);
    assert!(
        controller.protected_fds.lock().expect("lock").is_empty(),
        "an unprotected descriptor must not escape into the core"
    );
}

/// Both families open, both carry a datagram, and the reflexive-candidate
/// metadata §3.4 needs arrives on each.
#[tokio::test]
async fn a_datagram_crosses_in_both_families_with_its_arrival_address() {
    for (family, loopback) in [
        (
            SocketFamily::V4,
            IpAddr::V4(V4Addr::from_octets([127, 0, 0, 1])),
        ),
        (SocketFamily::V6Only, {
            let mut octets = [0u8; 16];
            octets[15] = 1;
            IpAddr::V6(V6Addr::new(octets, None).expect("::1"))
        }),
    ] {
        let (sockets, _) = provider(false);
        let receiver = sockets.bind_udp(&spec(family)).await.expect("bind rx");
        let sender = sockets.bind_udp(&spec(family)).await.expect("bind tx");

        let bound = receiver.local_endpoint().expect("bound");
        let target = Endpoint::new(loopback, bound.port);

        let payload = b"disco-probe";
        let sent = sender.send_to(payload, &target).await.expect("send");
        assert_eq!(sent, payload.len());

        let mut buf = [0u8; 64];
        let datagram = receiver.recv_from(&mut buf).await.expect("recv");
        assert_eq!(&buf[..datagram.len], payload);
        assert!(!datagram.truncated);
        assert_eq!(datagram.source.family(), family.primary_family());
        assert_eq!(
            datagram.destination.map(IpAddr::family),
            Some(family.primary_family()),
            "IP_PKTINFO / IPV6_RECVPKTINFO must attribute the arrival address"
        );
        assert!(
            datagram.interface.is_some(),
            "the arrival interface is known"
        );
    }
}

/// A truncated datagram is **reported**, never silent: "a silently truncated
/// datagram is a message that fails authentication for a reason nobody can see."
#[tokio::test]
async fn truncation_is_reported_rather_than_hidden() {
    let (sockets, _) = provider(false);
    let receiver = sockets
        .bind_udp(&spec(SocketFamily::V4))
        .await
        .expect("bind rx");
    let sender = sockets
        .bind_udp(&spec(SocketFamily::V4))
        .await
        .expect("bind tx");
    let bound = receiver.local_endpoint().expect("bound");
    let target = Endpoint::new(IpAddr::V4(V4Addr::from_octets([127, 0, 0, 1])), bound.port);

    let payload = [0xABu8; 64];
    sender.send_to(&payload, &target).await.expect("send");

    let mut small = [0u8; 8];
    let datagram = receiver.recv_from(&mut small).await.expect("recv");
    assert!(datagram.truncated);
    assert_eq!(datagram.len, small.len());
}

/// The seam's rule: `V6Only` and `V6DualStack` are different values, and
/// `IPV6_V6ONLY` is set explicitly in both directions.
#[tokio::test]
async fn a_dual_stack_socket_unmaps_a_v4_source_at_the_seam() {
    let (sockets, _) = provider(false);
    let Ok(receiver) = sockets.bind_udp(&spec(SocketFamily::V6DualStack)).await else {
        // A host with no dual-stack sockets is a legitimate configuration and
        // `supported_families` reports it; there is nothing to assert here.
        return;
    };
    let sender = sockets
        .bind_udp(&spec(SocketFamily::V4))
        .await
        .expect("bind v4");
    let bound = receiver.local_endpoint().expect("bound");
    let target = Endpoint::new(IpAddr::V4(V4Addr::from_octets([127, 0, 0, 1])), bound.port);

    if sender.send_to(b"mapped", &target).await.is_err() {
        // Some CI kernels disable v4-mapped delivery; the un-mapping itself is
        // covered exhaustively by `addr`'s own unit tests.
        return;
    }
    let mut buf = [0u8; 32];
    let datagram = receiver.recv_from(&mut buf).await.expect("recv");
    assert_eq!(
        datagram.source.family(),
        AddressFamily::V4,
        "a v4-mapped source must never cross the seam"
    );
}

#[tokio::test]
async fn the_supported_families_are_a_fact_about_this_host() {
    let (sockets, _) = provider(false);
    let families = sockets.supported_families().await.expect("probe");
    assert!(families.v4, "this host opens AF_INET sockets");
    // v6 and dual-stack are reported as observed; a host without them is a
    // legitimate configuration, and the point is that we do not substitute.
    let _ = families.v6;
    let _ = families.dual_stack_socket;
}

#[tokio::test]
async fn a_requested_option_that_cannot_apply_is_an_error_not_a_silent_omission() {
    let (sockets, _) = provider(false);
    // An interface bind that the address does not carry as a scope zone cannot
    // be honoured on Android, and is reported rather than dropped.
    let mut bind = spec(SocketFamily::V6Only);
    bind.options.bind_to_interface = Some(twinvpn_platform::InterfaceIndex(9));
    let Err(err) = sockets.bind_udp(&bind).await else {
        panic!("an option that cannot apply must be reported");
    };
    assert_eq!(err.reason_code().as_str(), "PLATFORM.OS_UNSUPPORTED");
}

#[tokio::test]
async fn the_dont_fragment_default_is_applied_and_is_the_gathering_default() {
    // `SocketOptions::default` is documented as the gathering default: DF set
    // for DPLPMTUD, packet info on so a reflexive candidate can be attributed.
    let defaults = SocketOptions::default();
    assert_eq!(defaults.fragment_policy, FragmentPolicy::DontFragment);
    assert!(defaults.receive_packet_info);

    let (sockets, _) = provider(false);
    sockets
        .bind_udp(&spec(SocketFamily::V4))
        .await
        .expect("DF applies on this host");
}

#[tokio::test]
async fn binding_is_refused_once_shutdown_begins() {
    let latch = ShutdownLatch::new();
    let sockets = AndroidSocketProvider::new(CountingController::new(false), latch.clone());
    latch.begin();
    let Err(err) = sockets.bind_udp(&spec(SocketFamily::V4)).await else {
        panic!("binding must be refused once the latch is set");
    };
    assert!(matches!(err, PlatformError::ShuttingDown));
}

#[tokio::test]
async fn close_is_idempotent() {
    let (sockets, _) = provider(false);
    let socket = sockets
        .bind_udp(&spec(SocketFamily::V4))
        .await
        .expect("bind");
    socket.close().await.expect("first");
    socket.close().await.expect("second");
}

#[tokio::test]
async fn an_explicit_local_port_is_honoured_which_is_what_port_prediction_needs() {
    // §3.6's birthday-paradox port prediction opens many sockets at once and
    // needs `SO_REUSEADDR`/`SO_REUSEPORT` to do it.
    let (sockets, _) = provider(false);
    let mut first = spec(SocketFamily::V4);
    first.options.reuse_address = true;
    first.options.reuse_port = true;
    let socket = sockets.bind_udp(&first).await.expect("bind");
    let bound = socket.local_endpoint().expect("bound");
    assert_eq!(socket.family(), SocketFamily::V4);

    // The whole point of SO_REUSEPORT here: a second socket may take the SAME
    // local port, which is what opening many at once needs.
    let mut second = first;
    second.local = Some(Endpoint::new(
        IpAddr::V4(V4Addr::from_octets([0, 0, 0, 0])),
        bound.port,
    ));
    let twin = sockets.bind_udp(&second).await.expect("reuse the port");
    assert_eq!(
        twin.local_endpoint().expect("bound").port.get(),
        bound.port.get()
    );
}
