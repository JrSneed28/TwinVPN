//! ADR-0012 §11.2's traffic classes, and KS-9's bootstrap predicate — "the
//! narrowest exception in this table and the most dangerous".
//!
//! **Authority:** ADR-0012 §11.2 (the class table), KS-3, KS-3a, KS-4, KS-9,
//! KS-9a, KS-10, KS-10a, KS-11, KS-12; ADR-0011 §11.13(b).
//!
//! # KS-12: the exception does not widen on failure
//!
//! > If socket registration fails, the socket is not exempt and its traffic is
//! > dropped. There is no "register everything on error" path.
//!
//! [`SocketRegistry::class_of`] returns `None` for an unregistered socket and
//! [`Disposition::for_class`] maps `None` to `DroppedFailClosed`. There is no
//! constructor that registers a socket without naming its class.

use twinvpn_types::{AddressFamily, IpAddr, TrafficDisposition};

/// §11.2's traffic classes, numbered as the table numbers them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Class {
    /// 1 — protected peer traffic. Always protected, in every mode.
    ProtectedPeer,
    /// 2 — exit-node-routed Internet traffic, per family.
    ExitRouted,
    /// 3 — LAN-gateway-routed traffic to an accepted `Route` prefix.
    LanGatewayRouted,
    /// 4 — local physical LAN traffic. Permitted iff KS-4 allows it.
    LocalPhysicalLan,
    /// 5 — DHCP / DHCPv6 / ND / RA on the underlay, link-local scope only.
    UnderlayControl,
    /// 6 — DNS for names in the Tier-1 protected scope, plus **all** DNS in
    /// full-tunnel mode.
    ProtectedDns,
    /// 6b — `SPLIT`-mode out-of-scope DNS on a `RESOLVER` socket.
    SplitOutOfScopeDns,
    /// 7 — TwinVPN's own control-plane, rendezvous, relay and peer traffic.
    Bootstrap,
    /// 8 — loopback.
    Loopback,
    /// 9 — link-local unicast on a non-overlay physical interface.
    LinkLocalUnicast,
    /// 10 — mDNS and link-local multicast. Follows class 4.
    LinkLocalMulticast,
    /// 11 — the captive-portal conversation, under a live grant only.
    PortalConversation,
    /// 12 — platform-mandated exempt traffic. Permitted **and disclosed**.
    PlatformMandated,
    /// 13 — the captive-portal **detection** probe.
    PortalDetection,
}

/// What happens to a class when no authorized secure path exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Disposition;

impl Disposition {
    /// §11.2's disposition column.
    ///
    /// `local_network_allowed` is KS-4's setting, and `portal_grant_live` is
    /// §11.7's. Both default to the restrictive answer at the call site.
    #[must_use]
    pub const fn for_class(
        class: Class,
        local_network_allowed: bool,
        portal_grant_live: bool,
    ) -> TrafficDisposition {
        match class {
            Class::ProtectedPeer
            | Class::ExitRouted
            | Class::LanGatewayRouted
            | Class::ProtectedDns => TrafficDisposition::DroppedFailClosed,
            Class::LocalPhysicalLan | Class::LinkLocalMulticast => {
                if local_network_allowed {
                    TrafficDisposition::UnprotectedAnnounced
                } else {
                    TrafficDisposition::DroppedFailClosed
                }
            }
            Class::PortalConversation => {
                if portal_grant_live {
                    TrafficDisposition::UnprotectedAnnounced
                } else {
                    TrafficDisposition::DroppedFailClosed
                }
            }
            Class::UnderlayControl
            | Class::SplitOutOfScopeDns
            | Class::Bootstrap
            | Class::Loopback
            | Class::LinkLocalUnicast
            | Class::PlatformMandated
            | Class::PortalDetection => TrafficDisposition::UnprotectedAnnounced,
        }
    }

    /// KS-3: "a packet in that scope which matches no class is protected and is
    /// dropped. Ambiguity resolves closed."
    #[must_use]
    pub const fn unmatched_in_scope() -> TrafficDisposition {
        TrafficDisposition::DroppedFailClosed
    }
}

/// KS-10's socket registry classes.
///
/// Three disjoint classes, each with its own permitted payloads and destination
/// scope. The table is KS-10's, and the classes are deliberately not a single
/// "exempt" flag: `BOOTSTRAP` is destination-unbounded for two of its three
/// payloads, and `RESOLVER` and `UPDATE` are both destination-**bounded**.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SocketClass {
    /// Agent control-plane, rendezvous, relay and peer sockets, plus the
    /// class-13 detection probe.
    Bootstrap,
    /// The stub's **outbound** resolution sockets only.
    ///
    /// KS-10 is explicit that this class is **not** covered by the "nothing else
    /// can get bytes onto these sockets" argument, "because the stub is by
    /// construction a listener that accepts queries from other processes". Its
    /// safety rests on ADR-0011's DN-4, its bounded destination set, and DN-10.
    Resolver,
    /// The privileged updater's fetch socket only.
    ///
    /// KS-10a: modelled on class 13, **not** on destination-unbounded
    /// `BOOTSTRAP`, and bounded to the pinned update origins of `UpdatePolicy`
    /// (S-59). It exists because ADR-0014 N-31(4)(b) names a successful
    /// self-update as the recovery path from a version block, and that fetch was
    /// otherwise dropped — "N-31's own recovery path was unreachable by
    /// construction".
    Update,
}

impl SocketClass {
    /// Whether this class's destination set is bounded.
    #[must_use]
    pub const fn destination_bounded(self) -> bool {
        match self {
            // Destination-unbounded, necessarily: relay and peer endpoints are
            // legitimately arbitrary Internet addresses.
            SocketClass::Bootstrap => false,
            SocketClass::Resolver | SocketClass::Update => true,
        }
    }
}

/// KS-9's predicate. **All three clauses**, and there is no two-of-three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootstrapPredicate {
    /// 1 — locally originated by the TwinVPN agent process, by an OS-mediated
    /// predicate (cgroup + `fwmark`, WFP app-id + user SID, a `pf` anchor keyed
    /// to the provider's uid, or implicit on iOS/Android).
    pub agent_originated: bool,
    /// 2 — emitted on a socket **registered with the enforcement layer at bind
    /// time**.
    ///
    /// KS-9a corrects the original wording: registration MUST NOT be specified
    /// as IPC. On `HC-1`/`HC-3` the sockets and the enforcement layer are in the
    /// same process, "and an intra-process call is not IPC". Requiring one would
    /// mandate a local endpoint whose entire purpose is granting egress
    /// exemptions.
    pub registered_at_bind: bool,
    /// 3 — **not** on the forwarding path (KS-2).
    pub not_forwarded: bool,
}

impl BootstrapPredicate {
    /// Whether the packet matches the bootstrap exception.
    #[must_use]
    pub const fn matches(self) -> bool {
        self.agent_originated && self.registered_at_bind && self.not_forwarded
    }
}

/// The registry KS-10 describes, with KS-12's failure direction built in.
#[derive(Debug, Default)]
pub struct SocketRegistry {
    entries: std::collections::HashMap<u64, SocketClass>,
}

impl SocketRegistry {
    /// An empty registry. Nothing is exempt until it is registered.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a socket **at bind time**, in a named class.
    ///
    /// There is no `register()` without a class, so KS-10's disjoint classes
    /// cannot collapse into one "exempt" bit.
    pub fn register(&mut self, socket_token: u64, class: SocketClass) {
        self.entries.insert(socket_token, class);
    }

    /// Removes a socket. Called on close, and on a **failed** registration.
    pub fn unregister(&mut self, socket_token: u64) {
        self.entries.remove(&socket_token);
    }

    /// The class of a socket, or `None` when it is not registered.
    ///
    /// KS-9: "Unregistered sockets of the same process do not match."
    #[must_use]
    pub fn class_of(&self, socket_token: u64) -> Option<SocketClass> {
        self.entries.get(&socket_token).copied()
    }

    /// KS-12: registration failed, so the socket is **not** exempt.
    ///
    /// Named as an operation rather than left implicit, because "there is no
    /// 'register everything on error' path" is a rule somebody has to be able to
    /// find in the code.
    pub fn registration_failed(&mut self, socket_token: u64) {
        self.unregister(socket_token);
    }

    /// How many sockets each class holds, for KS-11's accounting.
    #[must_use]
    pub fn count(&self, class: SocketClass) -> usize {
        self.entries.values().filter(|c| **c == class).count()
    }
}

/// KS-11's accounting: exempt egress compared against our own frame accounting.
///
/// > The enforcement layer MUST export byte and packet counters for the exempt
/// > rule, **per family**. The agent MUST compare exempt egress against its own
/// > tunnel and control-plane frame accounting; a divergence beyond a declared
/// > tolerance raises `POLICY.EXEMPT.EGRESS_ANOMALY` at `CRITICAL` and drives
/// > `EV_POLICY_VIOLATION` → `BLOCKED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExemptAccounting {
    /// Bytes the enforcement layer counted on the exempt rule.
    pub observed_bytes: u64,
    /// Bytes the agent believes it sent.
    pub accounted_bytes: u64,
}

impl ExemptAccounting {
    /// Whether the divergence exceeds `tolerance_bytes`.
    ///
    /// The comparison is one-sided: **more** on the wire than we accounted for
    /// is the anomaly. Less is ordinary (a dropped packet, a counter read
    /// between two sends).
    #[must_use]
    pub const fn is_anomalous(self, tolerance_bytes: u64) -> bool {
        self.observed_bytes > self.accounted_bytes.saturating_add(tolerance_bytes)
    }
}

/// Class 5's link-local control traffic, by port and message type.
///
/// Permitted "because blocking them breaks the underlay itself; they are
/// permitted as **link-local control traffic only**, and never as an egress path
/// for protected traffic".
#[must_use]
pub const fn is_underlay_control(
    family: AddressFamily,
    port: u16,
    icmpv6_type: Option<u8>,
) -> bool {
    match family {
        AddressFamily::V4 => matches!(port, 67 | 68),
        AddressFamily::V6 => {
            if matches!(port, 546 | 547) {
                return true;
            }
            match icmpv6_type {
                // 133-137: RS, RA, NS, NA, Redirect.
                Some(t) => t >= 133 && t <= 137,
                None => false,
            }
        }
    }
}

/// Class 9's link-local unicast ranges.
#[must_use]
pub fn is_link_local_unicast(addr: IpAddr) -> bool {
    match addr {
        // 169.254.0.0/16
        IpAddr::V4(a) => a.octets()[0] == 169 && a.octets()[1] == 254,
        // fe80::/10
        IpAddr::V6(a) => a.is_link_local(),
    }
}

/// Class 13's rate limits: "≤ 4 probes per interface attach, ≤ 1/s".
pub const PORTAL_DETECTION_MAX_PROBES: u32 = 4;
/// Minimum spacing between detection probes.
pub const PORTAL_DETECTION_MIN_SPACING: core::time::Duration = core::time::Duration::from_secs(1);
