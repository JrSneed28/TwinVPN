//! Sockets: v4, v6, dual-stack and IPv6-only, plus the options the NAT ladder
//! needs and the multicast LAN discovery uses.
//!
//! **Authority:** `docs/networking.md` §3 (candidate gathering, the disco probe,
//! port prediction), §8 (LAN discovery), §6 (MTU and DF), ADR-0010 R1 and §11.7,
//! ADR-0004 (the NAT ladder), ADR-0018 CB-2.
//!
//! # Nothing here is a decision
//!
//! Every method is a *mechanism*. Which candidates to gather, which pairs to
//! race, when to punch, when to give up and take a relay — all of that is
//! `twinvpn-path`'s, and CB-2's falsification test is what keeps it there: with
//! every shell deleted and a mock bound, the core must still make every one of
//! those calls in the same order.
//!
//! # Both families, always
//!
//! [`SocketFamily`] has no "default" and no `Option`. A caller states which of
//! the three shapes it wants, and `V6DualStack` and `V6Only` are **different
//! values** rather than a flag on one — because `IPV6_V6ONLY` genuinely differs
//! per platform, and "we forgot to set it" is how a v6 socket silently starts
//! accepting v4-mapped traffic that `common.proto` rejects everywhere else.

use core::time::Duration;

use futures_core::future::BoxFuture;
use twinvpn_types::{AddressFamily, Endpoint, IpAddr};

use crate::error::PlatformError;
use crate::iface::InterfaceIndex;

/// Which socket shape to open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SocketFamily {
    /// An `AF_INET` socket.
    V4,
    /// An `AF_INET6` socket with `IPV6_V6ONLY` **set**: it carries v6 only.
    ///
    /// The shape every gathering path uses, so that a v4 candidate and a v6
    /// candidate are two sockets with two independent fates — ADR-0010 R8's
    /// "MUST NOT stall on a broken family", expressed at the socket layer.
    V6Only,
    /// An `AF_INET6` socket with `IPV6_V6ONLY` **clear**: it also carries v4 as
    /// v4-mapped addresses.
    ///
    /// Available because some platforms offer no other way to accept both on one
    /// port. A caller that takes it **must** be prepared for a v4-mapped source
    /// address, which the adapter un-maps before it reaches
    /// [`Datagram::source`] — `common.proto` forbids a v4-mapped address in any
    /// canonical position, so the un-mapping happens at the seam and never in the
    /// core.
    V6DualStack,
}

impl SocketFamily {
    /// The address family this socket can originate traffic in.
    #[must_use]
    pub const fn primary_family(self) -> AddressFamily {
        match self {
            SocketFamily::V4 => AddressFamily::V4,
            SocketFamily::V6Only | SocketFamily::V6DualStack => AddressFamily::V6,
        }
    }
}

/// How a datagram socket should behave for path-MTU discovery.
///
/// `docs/networking.md` §6.2 selects "1280 floor + DPLPMTUD, never classic
/// PMTUD", and DPLPMTUD needs the don't-fragment bit set so a too-large probe is
/// dropped rather than fragmented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FragmentPolicy {
    /// Set DF (`IP_DONTFRAG` / `IPV6_DONTFRAG` / `IP_MTU_DISCOVER=PROBE`).
    DontFragment,
    /// Leave the platform default.
    PlatformDefault,
}

/// Options a socket is opened with.
///
/// Applied **at open**, not afterwards: several of them cannot be changed on a
/// bound socket on at least one target, and an option that silently failed to
/// apply is a NAT ladder that behaves differently from the one that was tested.
#[derive(Debug, Clone, PartialEq, Eq)]
// NOT `#[non_exhaustive]`: BOTH sides of the seam construct this. The adapter
// implementations live in other crates (`twinvpn-platform-*`, the shells) and the
// core builds the values it hands across, so sealing construction would make the
// trait unimplementable outside this crate. Adding a field here SHOULD break every
// implementor — that is a seam change, and a silent default is how one side comes
// to believe a fact the other never supplied.
pub struct SocketOptions {
    /// `SO_REUSEADDR`.
    pub reuse_address: bool,
    /// `SO_REUSEPORT`, where the platform has it.
    ///
    /// The birthday-paradox port prediction of `docs/networking.md` §3.6 opens
    /// many sockets at once, and on Linux that needs this.
    pub reuse_port: bool,
    /// The don't-fragment policy.
    pub fragment_policy: FragmentPolicy,
    /// TTL (v4) or hop limit (v6).
    ///
    /// One field, not two, because a socket has exactly one family and carrying
    /// both would make "which one applies" a question the core has to answer.
    pub hop_limit: Option<u8>,
    /// DSCP / traffic class.
    pub dscp: Option<u8>,
    /// Bind to one interface (`SO_BINDTODEVICE` or the platform equivalent).
    ///
    /// Required for a link-local v6 candidate and for LAN discovery on a
    /// multi-homed host, which is the same reason `V6Addr` demands a zone index.
    pub bind_to_interface: Option<InterfaceIndex>,
    /// Request the destination address and arrival interface on each datagram.
    ///
    /// `IP_PKTINFO` / `IPV6_RECVPKTINFO`. Without it a socket bound to the
    /// wildcard cannot tell which of its addresses a probe arrived on, which the
    /// disco probe of §3.4 needs to attribute a reflexive candidate correctly.
    pub receive_packet_info: bool,
    /// A firewall mark, where the platform has one.
    ///
    /// Linux `SO_MARK`. `docs/networking.md` §5.2 routes TwinVPN's own traffic
    /// through policy table 52 by `fwmark`; without it the tunnel's own packets
    /// would match the default route it just installed.
    pub firewall_mark: Option<u32>,
    /// Join these multicast groups at open.
    pub multicast: Option<MulticastOptions>,
    /// Send and receive buffer sizes, where the caller has a reason to set them.
    pub send_buffer_bytes: Option<u32>,
    /// Receive buffer size.
    pub receive_buffer_bytes: Option<u32>,
}

impl Default for SocketOptions {
    /// The gathering default: DF set for DPLPMTUD, packet info on so a reflexive
    /// candidate can be attributed, everything else left to the platform.
    fn default() -> Self {
        Self {
            reuse_address: false,
            reuse_port: false,
            fragment_policy: FragmentPolicy::DontFragment,
            hop_limit: None,
            dscp: None,
            bind_to_interface: None,
            receive_packet_info: true,
            firewall_mark: None,
            multicast: None,
            send_buffer_bytes: None,
            receive_buffer_bytes: None,
        }
    }
}

/// Multicast configuration for LAN discovery (`docs/networking.md` §8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MulticastOptions {
    /// The group to join.
    pub group: IpAddr,
    /// The interface to join it on.
    ///
    /// Not optional. A multicast join on "any interface" means something
    /// different on every platform, and LAN discovery's whole point is to know
    /// which segment an announcement came from.
    pub interface: InterfaceIndex,
    /// Whether this host should receive its own announcements.
    ///
    /// `false` in production; a mock or a single-host test wants `true`.
    pub loopback: bool,
    /// Multicast TTL / hop limit. `1` keeps an announcement on the local segment,
    /// which is what §8.2's privacy discussion assumes.
    pub hop_limit: u8,
}

/// What to bind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpBindSpec {
    /// The socket shape.
    pub family: SocketFamily,
    /// The local endpoint, or `None` for "any address, ephemeral port".
    pub local: Option<Endpoint>,
    /// Options, applied at open.
    pub options: SocketOptions,
}

/// A received datagram's metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
// NOT `#[non_exhaustive]`: BOTH sides of the seam construct this. The adapter
// implementations live in other crates (`twinvpn-platform-*`, the shells) and the
// core builds the values it hands across, so sealing construction would make the
// trait unimplementable outside this crate. Adding a field here SHOULD break every
// implementor — that is a seam change, and a silent default is how one side comes
// to believe a fact the other never supplied.
pub struct Datagram {
    /// How many bytes were written into the caller's buffer.
    pub len: usize,
    /// The peer. Never a v4-mapped v6 address: the adapter un-maps before this
    /// crosses the seam.
    pub source: Endpoint,
    /// Which of our addresses it arrived on, when `receive_packet_info` was set.
    pub destination: Option<IpAddr>,
    /// Which interface it arrived on, when known.
    pub interface: Option<InterfaceIndex>,
    /// Whether the datagram was truncated because the caller's buffer was too
    /// small.
    ///
    /// **Reported, never silent.** A silently truncated datagram is a message
    /// that fails authentication for a reason nobody can see.
    pub truncated: bool,
}

/// A bound UDP socket.
///
/// # Cancellation, timeouts and shutdown
///
/// - **Cancellation is dropping the future.** An adapter must release whatever
///   the operation held.
/// - **The adapter imposes no timeout of its own.** A caller composes one from
///   `twinvpn_env::Timer`, so every deadline in the system runs on the injected
///   monotonic clock (CD-1) rather than on a timeout the platform chose.
/// - **[`UdpSocket::close`] is idempotent** and safe after a crash, matching
///   `destroy_interface`'s contract in `docs/networking.md` §5.1.
pub trait UdpSocket: Send + Sync {
    /// The endpoint actually bound, with the ephemeral port resolved.
    ///
    /// # Errors
    ///
    /// [`PlatformError`] if the socket has been closed or the OS refuses.
    fn local_endpoint(&self) -> Result<Endpoint, PlatformError>;

    /// Sends one datagram.
    ///
    /// Returns the bytes written. A short write on a datagram socket is an
    /// adapter defect, not a partial send to retry.
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        destination: &'a Endpoint,
    ) -> BoxFuture<'a, Result<usize, PlatformError>>;

    /// Receives one datagram into `buf`.
    fn recv_from<'a>(&'a self, buf: &'a mut [u8])
        -> BoxFuture<'a, Result<Datagram, PlatformError>>;

    /// Joins a multicast group after open.
    ///
    /// # Errors
    ///
    /// [`PlatformError`] if the interface is gone or the OS refuses.
    fn join_multicast(&self, options: &MulticastOptions) -> Result<(), PlatformError>;

    /// Leaves a multicast group.
    fn leave_multicast(&self, options: &MulticastOptions) -> Result<(), PlatformError>;

    /// The socket's family.
    fn family(&self) -> SocketFamily;

    /// Closes the socket. Idempotent.
    fn close(&self) -> BoxFuture<'_, Result<(), PlatformError>>;
}

/// Opens sockets.
pub trait SocketProvider: Send + Sync {
    /// Binds a UDP socket.
    ///
    /// # Errors
    ///
    /// [`PlatformError::OsUnsupported`] if the requested [`SocketFamily`] is not
    /// available on this host — which is a **fact about the host**, reported so
    /// the core can decide, not a reason for the adapter to substitute another
    /// family. Substituting is how a v6-only network silently becomes a v4-only
    /// session.
    fn bind_udp<'a>(
        &'a self,
        spec: &'a UdpBindSpec,
    ) -> BoxFuture<'a, Result<Box<dyn UdpSocket>, PlatformError>>;

    /// Which socket shapes this host can open.
    ///
    /// A **capability fact**, so the core branches on capability rather than on
    /// OS (CB-3). Reported per family so "this host has no v6 stack" and "this
    /// host has no dual-stack sockets" are different answers.
    fn supported_families(&self) -> BoxFuture<'_, Result<SupportedFamilies, PlatformError>>;
}

/// Which socket shapes a host offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupportedFamilies {
    /// `AF_INET` sockets can be opened.
    pub v4: bool,
    /// `AF_INET6` sockets can be opened.
    pub v6: bool,
    /// A single `AF_INET6` socket can carry both families.
    pub dual_stack_socket: bool,
}

/// How long an adapter may take before a call is considered hung.
///
/// Advisory, and **not enforced by the adapter**: it exists so a shell can
/// document its own contract, and so the core's watchdog has a declared figure
/// to compare against. The actual deadline is the core's, on the injected
/// monotonic clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdapterResponseBudget(pub Duration);
