//! The stub's listeners, DN-5's bind-before-pointing ordering, and DN-4's
//! "a DNS server, not a proxy" acceptance rules.
//!
//! **Authority:** ADR-0011 §11.2 (normative), DN-2, DN-4, DN-5, DN-18…DN-21;
//! ADR-0012 §11.5's `RESOLVER` socket class and KS-10's "a `RESOLVER` socket
//! MUST NOT be usable for any non-DNS payload".

use twinvpn_types::{IpAddr, PerFamily, V4Addr, V6Addr};

/// The IPv4 overlay anycast listener: `100.127.255.53`.
pub const ANYCAST_V4: [u8; 4] = [100, 127, 255, 53];
/// The IPv6 overlay anycast listener: `fd7c:9e5d:2a10:ffff::53`.
pub const ANYCAST_V6: [u8; 16] = [
    0xfd, 0x7c, 0x9e, 0x5d, 0x2a, 0x10, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0x53,
];
/// The IPv4 loopback listener: `127.0.0.53`.
pub const LOOPBACK_V4: [u8; 4] = [127, 0, 0, 53];
/// The DNS port.
pub const DNS_PORT: u16 = 53;

/// The four addresses §11.2 requires the stub to answer on.
///
/// # Errors
///
/// Propagates a `twinvpn-types` constructor rejection, which the constants
/// cannot trigger.
pub fn listen_addresses() -> Result<PerFamily<Vec<IpAddr>>, twinvpn_types::TypeError> {
    let v6_loopback = {
        let mut o = [0u8; 16];
        o[15] = 1;
        V6Addr::new(o, None)?
    };
    Ok(PerFamily::new(
        vec![
            IpAddr::V4(V4Addr::from_octets(LOOPBACK_V4)),
            IpAddr::V4(V4Addr::from_octets(ANYCAST_V4)),
        ],
        vec![
            IpAddr::V6(v6_loopback),
            IpAddr::V6(V6Addr::new(ANYCAST_V6, None)?),
        ],
    ))
}

/// DN-2: the anycast addresses are answered **locally and never routed**.
///
/// > They MUST NOT appear in any `Route` advertisement, MUST NOT be forwarded to
/// > a peer, and MUST be dropped if received on the overlay from a peer.
#[must_use]
pub fn is_service_anycast(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => a.octets() == ANYCAST_V4,
        IpAddr::V6(a) => a.octets() == ANYCAST_V6,
    }
}

/// DN-2's advertisement rule, as a predicate a route advertiser calls.
#[must_use]
pub fn may_advertise(addr: IpAddr) -> bool {
    !is_service_anycast(addr)
}

/// The stub's readiness, per family and per listener.
///
/// DN-5: the stub "MUST be bound and answering on **all four** addresses before
/// the host resolver is pointed at it, and the host MUST be pointed away before
/// the stub is unbound. If any listener cannot bind, `DNS.STUB.BIND_FAILED` is
/// raised and the client MUST NOT enter a protected state — the same disposition
/// as `POLICY.KILLSWITCH.ARM_FAILED`."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StubReadiness {
    /// Both IPv4 listeners are bound and answering.
    pub v4_listening: bool,
    /// Both IPv6 listeners are bound and answering.
    pub v6_listening: bool,
}

impl StubReadiness {
    /// DN-5's precondition for pointing the host at us, and for entering a
    /// protected state at all.
    #[must_use]
    pub const fn may_point_host(self) -> bool {
        self.v4_listening && self.v6_listening
    }
}

/// DN-19's ordering, as an explicit sequence.
///
/// ```text
/// apply:    stub bound & answering -> RestorePoint persisted
///           -> platform scoped-DNS applied -> reconciler confirms -> ready
/// teardown: point host away (restore) -> reconciler confirms -> unbind stub
///           (NEVER unbind-then-restore)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ApplyStep {
    /// Bind and answer on all four addresses.
    BindStub,
    /// Persist the owner-tagged `RestorePoint` (DN-18), **before** any mutation.
    PersistRestorePoint,
    /// Apply the platform's scoped-DNS configuration.
    ApplyScopedDns,
    /// Confirm `actual == intended` by read-back.
    ConfirmReadBack,
}

impl ApplyStep {
    /// The apply order.
    pub const SEQUENCE: [ApplyStep; 4] = [
        ApplyStep::BindStub,
        ApplyStep::PersistRestorePoint,
        ApplyStep::ApplyScopedDns,
        ApplyStep::ConfirmReadBack,
    ];
}

/// DN-19's teardown order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TeardownStep {
    /// Point the host away, by restoring the `RestorePoint`.
    RestoreHostResolver,
    /// Confirm by read-back.
    ConfirmReadBack,
    /// Only now, unbind the stub.
    UnbindStub,
}

impl TeardownStep {
    /// The teardown order. Never unbind-then-restore.
    pub const SEQUENCE: [TeardownStep; 3] = [
        TeardownStep::RestoreHostResolver,
        TeardownStep::ConfirmReadBack,
        TeardownStep::UnbindStub,
    ];
}

/// DN-4's acceptance rules: "the stub is a DNS server, not a proxy".
///
/// > It accepts only well-formed DNS messages (RFC 1035 + EDNS(0) RFC 6891),
/// > parses every message fully before any action, enforces a `bufsize` ceiling,
/// > refuses messages with `QDCOUNT ≠ 1`, refuses unknown OPCODEs, and MUST NOT
/// > carry, tunnel, or relay any payload that is not a DNS RR.
///
/// This is what keeps the listener from becoming the egress interface ADR-0012
/// KS-10 forbids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageShape {
    /// The header's QDCOUNT.
    pub qdcount: u16,
    /// The header's OPCODE.
    pub opcode: u8,
    /// The EDNS(0) advertised UDP payload size, if an OPT record was present.
    pub edns_bufsize: Option<u16>,
    /// The received length.
    pub length: usize,
}

/// The EDNS(0) `bufsize` ceiling. 1232 is the DNS Flag Day 2020 value: it is the
/// IPv6 minimum MTU less IPv6 and UDP headers, so an answer at this size never
/// needs fragmentation on any path.
pub const EDNS_BUFSIZE_CEILING: u16 = 1232;

/// The largest DNS message the stub will parse.
pub const MAX_MESSAGE_BYTES: usize = 65_535;

/// Whether a received message is admissible under DN-4.
///
/// Rejection is the answer for anything else: DN-4 says "parses every message
/// fully **before any action**", so a caller must run this before it does
/// anything at all with the bytes.
#[must_use]
pub fn accepts(shape: MessageShape) -> bool {
    shape.qdcount == 1
        // OPCODE 0 is QUERY. Everything else — IQUERY, STATUS, NOTIFY, UPDATE —
        // is refused rather than ignored.
        && shape.opcode == 0
        && shape.length <= MAX_MESSAGE_BYTES
        && shape
            .edns_bufsize
            .is_none_or(|b| b <= EDNS_BUFSIZE_CEILING)
}

/// The ports a `RESOLVER` socket may reach **on the strength of the port
/// alone**.
///
/// KS-10: "DNS only: UDP/TCP 53, TCP 853, and **the known-DoH endpoint list**."
///
/// 443 is deliberately **absent**. DoH is a real upstream transport — ADR-0011
/// DN-23 makes it selectable for the `protected` scope — but KS-10 authorises it
/// by **destination**, not by port, and a port-only predicate cannot express
/// "443 to a known-DoH endpoint". Permitting 443 here (defect D-5) let a
/// `RESOLVER` socket reach *any* host on 443 on the strength of the port.
///
/// Use [`resolver_socket_permitted`] for the real check.
#[must_use]
pub const fn resolver_socket_port_permitted(port: u16) -> bool {
    matches!(port, 53 | 853)
}

/// Whether a `RESOLVER`-class socket may carry traffic to `port`.
///
/// The full KS-10 rule, with DN-23's DoH case expressed the way KS-10 bounds it:
///
/// | Port | Permitted when |
/// |---|---|
/// | 53 | always — Do53, UDP or TCP |
/// | 853 | always — DoT (RFC 7858) |
/// | 443 | **only** when the destination is in the known-DoH endpoint list (RFC 8484) |
/// | anything else | never |
///
/// The list itself is `twinvpn-enforce`'s and ships with the build (ADR-0011
/// §11.9); this crate takes the membership answer rather than holding the list,
/// because the same list is what the enforcement layer denies off-overlay.
#[must_use]
pub const fn resolver_socket_permitted(port: u16, destination_is_known_doh: bool) -> bool {
    match port {
        53 | 853 => true,
        443 => destination_is_known_doh,
        _ => false,
    }
}
