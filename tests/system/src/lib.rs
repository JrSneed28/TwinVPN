//! The rig every system test composes.
//!
//! **Owner:** `test-engineering`. Never shipped.
//!
//! # Why this crate exists
//!
//! Every other test in this repository lives inside one domain: `core-dataplane`
//! tests `twinvpn-route` against fakes, `control-plane` tests its own handlers,
//! `relay-plane` tests the relay. Nothing tests what happens when
//! `twinvpn-route`'s plan meets `twinvpn-enforce`'s contract assembler meets
//! `twinvpn-platform`'s adapter — and that is where the wave's cross-domain
//! defects are.
//!
//! [`Rig`] is the smallest composition that is still a *system*: a deterministic
//! [`twinlab::LabEnv`], a [`twinvpn_platform::mock::MockAdapter`] bound as the
//! platform (**CD-5**), the real [`twinvpn_session::SessionMachine`], and the
//! real route / DNS / enforcement pipeline. It is parameterised by address
//! family, because ADR-0010 **R1** is one story covering both and a rig that
//! could only be built for IPv4 would quietly make that untestable.
//!
//! # What the rig does not do
//!
//! It does not drive `twinvpn-core`. At the time this was written
//! `core/crates/twinvpn-core/src/lib.rs` contains no items at all — the
//! composition root is being built by `core-composition` in parallel. The rig
//! therefore composes the leaf crates directly and
//! [`composition_root_is_populated`] records that fact as an executable
//! observation, so the day the composition root lands, this crate is told.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use twinlab::{LabEnv, ScenarioSeed};
use twinvpn_enforce::contract::ContractInputs;
use twinvpn_enforce::{ArmingPolicy, Latch, ProtectedPreconditions};
use twinvpn_platform::mock::{MockAdapter, MockOptions};
use twinvpn_platform::socket::SupportedFamilies;
use twinvpn_platform::{
    ContractGeneration, InterfaceIndex, NetworkContract, PlatformAdapter, Ruleset,
};
use twinvpn_route::program::{compute, PlanInputs, RoutePlan, RoutingMode};
use twinvpn_session::{SessionMachine, SessionState};
use twinvpn_types::{
    AddressFamily, IpAddr, IpPrefix, OverlayAddresses, PerFamily, SessionId, V4Addr, V6Addr,
};

/// Which address families the host offers. §2.5's `Family` axis, and **L-5**'s
/// three required instantiations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostFamily {
    /// An IPv4-only underlay — the cafe network.
    V4Only,
    /// An IPv6-only underlay — the mobile network.
    V6Only,
    /// Both.
    Dual,
}

impl HostFamily {
    /// The three L-5 requires.
    pub const ALL: [HostFamily; 3] = [HostFamily::V4Only, HostFamily::V6Only, HostFamily::Dual];

    /// A name for an assertion message.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            HostFamily::V4Only => "v4-only",
            HostFamily::V6Only => "v6-only",
            HostFamily::Dual => "dual",
        }
    }

    /// What the mock host reports it can open.
    #[must_use]
    pub const fn supported(self) -> SupportedFamilies {
        match self {
            HostFamily::V4Only => SupportedFamilies {
                v4: true,
                v6: false,
                dual_stack_socket: false,
            },
            HostFamily::V6Only => SupportedFamilies {
                v4: false,
                v6: true,
                dual_stack_socket: false,
            },
            HostFamily::Dual => SupportedFamilies {
                v4: true,
                v6: true,
                dual_stack_socket: true,
            },
        }
    }

    /// Whether the underlay carries `family`.
    #[must_use]
    pub const fn underlay_carries(self, family: AddressFamily) -> bool {
        !matches!(
            (self, family),
            (HostFamily::V4Only, AddressFamily::V6) | (HostFamily::V6Only, AddressFamily::V4)
        )
    }
}

/// Polls an in-memory future to completion.
///
/// The mock adapter's futures never yield to a reactor — there is nothing to
/// wait for — so a full runtime would add a dependency and a scheduler to a test
/// that needs neither. The iteration cap turns a future that *would* block into
/// a named panic rather than a hung suite.
///
/// # Panics
///
/// If the future is still pending after 1024 polls, which for a mock means the
/// adapter grew a real wait and this helper is no longer the right tool.
pub fn block_on<T>(future: impl Future<Output = T>) -> T {
    let mut fut = Box::pin(future);
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    for _ in 0..1024 {
        if let Poll::Ready(v) = Pin::new(&mut fut).poll(&mut cx) {
            return v;
        }
    }
    panic!("an in-memory future did not complete in 1024 polls; it now needs a real runtime");
}

/// The overlay addresses every rig hands out.
///
/// Both families, always — `docs/networking.md` §2.1: "Every `Device` receives
/// one IPv4 address and one IPv6 address, and both are always present on the
/// interface **even when the underlay is single-stack**." That sentence is the
/// whole reason [`Rig`] is parameterised by *underlay* family and not by overlay
/// family.
#[must_use]
pub fn overlay_addresses(last_octet: u8) -> OverlayAddresses {
    OverlayAddresses {
        v4: V4Addr::from_octets([100, 64, 0, last_octet]),
        v6: V6Addr::new(
            [
                0xfd, 0x7c, 0x9e, 0x5d, 0x2a, 0x10, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, last_octet,
            ],
            None,
        )
        .expect("a ULA address inside the product prefix"),
    }
}

/// The overlay prefixes for a rig.
#[must_use]
pub fn twinnet_prefixes() -> PerFamily<Vec<IpPrefix>> {
    PerFamily::new(
        vec![
            IpPrefix::new(IpAddr::V4(V4Addr::from_octets([100, 64, 0, 0])), 22)
                .expect("a /22 inside the TwinNet v4 space"),
        ],
        vec![IpPrefix::new(
            IpAddr::V6(
                V6Addr::new(
                    [
                        0xfd, 0x7c, 0x9e, 0x5d, 0x2a, 0x10, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0,
                    ],
                    None,
                )
                .expect("a /64 inside the product ULA"),
            ),
            64,
        )
        .expect("a /64")],
    )
}

/// A composed system: deterministic env, mock platform, real state machine, real
/// route and enforcement pipeline.
pub struct Rig {
    /// The deterministic environment. CD-2: every component takes it at
    /// construction.
    pub env: LabEnv,
    /// The platform, bound to the mock (CD-5).
    pub adapter: MockAdapter,
    /// The authoritative connection state machine.
    pub session: SessionMachine,
    /// The kill-switch latch.
    pub latch: Latch,
    /// Which families the underlay offers.
    pub host_family: HostFamily,
    /// The overlay interface index the rig installs on.
    pub interface: InterfaceIndex,
    generation: u64,
}

impl Rig {
    /// Builds a rig for `host_family` at `seed`.
    #[must_use]
    pub fn new(host_family: HostFamily, seed: u8) -> Self {
        let env = LabEnv::new(ScenarioSeed::from_bytes([seed; 16]));
        let adapter = MockAdapter::new(&MockOptions {
            supported_families: host_family.supported(),
            ..MockOptions::default()
        });
        let session = SessionMachine::new(env.env_owned(), SessionId::from_array([seed; 16]));
        Self {
            env,
            adapter,
            session,
            latch: Latch::new(ArmingPolicy::Always),
            host_family,
            interface: InterfaceIndex(42),
            generation: 0,
        }
    }

    /// The next contract generation.
    pub fn next_generation(&mut self) -> ContractGeneration {
        self.generation += 1;
        ContractGeneration(self.generation)
    }

    /// The route plan for this rig, in `mode`.
    ///
    /// # Errors
    ///
    /// Propagates `twinvpn-route`'s refusal, which is a typed
    /// `ROUTE.*` condition and never a silent partial plan.
    pub fn route_plan(
        &mut self,
        mode: RoutingMode,
        exit_grant: PerFamily<bool>,
    ) -> Result<RoutePlan, twinvpn_route::RouteError> {
        let generation = self.next_generation();
        let inputs = PlanInputs {
            mode,
            overlay: overlay_addresses(2),
            twinnet_prefixes: twinnet_prefixes(),
            accepted: Vec::new(),
            on_link: Vec::new(),
            excluded: Vec::new(),
            interface: self.interface,
            selected_exit_node: None,
            mtu: 1420,
            exit_grant,
        };
        compute(&inputs, generation)
    }

    /// The network contract for a plan, assembled the way the product does.
    ///
    /// # Errors
    ///
    /// `twinvpn-enforce`'s `ContractError::FamilyAsymmetry`, which is the
    /// condition ADR-0010 R1 exists to make impossible.
    pub fn contract(
        &mut self,
        plan: &RoutePlan,
        dns: &twinvpn_dns::Dnspolicy,
        stub: PerFamily<Vec<IpAddr>>,
        ruleset: Ruleset,
    ) -> Result<NetworkContract, twinvpn_enforce::ContractError> {
        twinvpn_enforce::contract::assemble(
            &ContractInputs {
                route_plan: plan,
                dns_policy: dns,
                stub_addresses: stub,
                ruleset,
            },
            plan.generation,
        )
    }

    /// Applies a contract through the platform seam and returns the generation
    /// the adapter reports afterwards.
    ///
    /// # Panics
    ///
    /// If the adapter refuses. A refusal is a real condition worth asserting, so
    /// callers that want it should use the adapter directly.
    pub fn apply(&self, contract: &NetworkContract) -> Option<ContractGeneration> {
        block_on(self.adapter.network_config().apply(contract)).expect("apply");
        block_on(self.adapter.network_config().current_generation()).expect("current_generation")
    }

    /// Drives the session to `Established` over `carrier`, the way the product's
    /// happy path does, and returns the states it passed through.
    ///
    /// This is the sequence `docs/reliability.md` §4.5's rows T01, T03, T05 and
    /// T08/T09/T10 describe, applied through the one choke point.
    pub fn establish(&mut self, carrier: twinvpn_types::PathClass) -> Vec<SessionState> {
        use twinvpn_session::{Context as SessionContext, Event, Guards, Trigger};
        let mut path = Vec::new();
        let guards = Guards {
            credentials_valid: true,
            peer_authorized: true,
            usable_candidate: true,
            path_validated: true,
            relay_set_nonempty: true,
            retry_budget_available: true,
            // §4.5 T09 and T10 carry these: a WAN handshake only wins when no L2
            // path won, and a relay handshake only when no direct path did. They
            // are set to match `carrier` rather than set unconditionally, so a
            // caller asking for RELAYED does not silently also assert that no
            // direct path exists when one does.
            no_l2_path_won: carrier != twinvpn_types::PathClass::LocalDirect,
            no_direct_path_won: carrier == twinvpn_types::PathClass::Relayed,
            enforcement: Some(twinvpn_session::EnforcementMode::FailClosed),
            ..Guards::default()
        };
        for trigger in [
            Trigger::Event(Event::ConnectRequested),
            Trigger::Event(Event::CandidatesReady),
            Trigger::Event(Event::NegotiationOk),
            Trigger::Event(Event::HandshakeOk(carrier)),
        ] {
            self.session
                .apply(trigger, guards, SessionContext::default());
            path.push(self.session.state());
        }
        path
    }
}

/// Whether `twinvpn-core`'s composition root has any items yet.
///
/// An executable observation rather than a comment: this domain programmed
/// against the leaf crates because the composition root was empty while
/// `core-composition` built it, and this is how that assumption announces that
/// it has expired.
#[must_use]
pub fn composition_root_is_populated() -> bool {
    const CORE_LIB: &str = include_str!("../../../core/crates/twinvpn-core/src/lib.rs");
    CORE_LIB.lines().any(|l| {
        let t = l.trim_start();
        t.starts_with("pub mod ") || t.starts_with("pub struct ") || t.starts_with("pub fn ")
    })
}

/// A minimal, valid `DnsPolicy` for a rig.
///
/// Built through `twinvpn_dns::policy::validate` rather than by struct literal,
/// because `Dnspolicy` has a private field on purpose: an unvalidated policy is
/// exactly the "servers not declared" condition ADR-0011 refuses.
///
/// # Panics
///
/// If the constructed message does not validate, which would mean the rig and
/// the policy validator disagree — worth failing loudly.
#[must_use]
pub fn dns_policy(mode: twinvpn_dns::Mode, block_fallback: bool) -> twinvpn_dns::Dnspolicy {
    use twinvpn_schema::v1;
    let msg = v1::DnsPolicy {
        dnspolicy_id: "rig".to_owned(),
        version: 1,
        mode: match mode {
            twinvpn_dns::Mode::Split => 1,
            twinvpn_dns::Mode::Full => 2,
            twinvpn_dns::Mode::Off => 3,
        },
        servers_v4: vec![v1::IPv4Address {
            octets: vec![100, 127, 255, 53],
        }],
        servers_v6: vec![v1::IPv6Address {
            octets: vec![
                0xfd, 0x7c, 0x9e, 0x5d, 0x2a, 0x10, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0x53,
            ],
            zone_index: 0,
        }],
        servers_declared_v4: Some(true),
        servers_declared_v6: Some(true),
        split_domains: Vec::new(),
        search_domains: Vec::new(),
        block_fallback_v4: Some(block_fallback),
        block_fallback_v6: Some(block_fallback),
        dnssec_validate: true,
        upstream_dot: true,
        not_after_ms: 0,
    };
    twinvpn_dns::policy::validate(&msg).expect("the rig's DNS policy must validate")
}

/// The stub resolver addresses, both families.
#[must_use]
pub fn stub_addresses() -> PerFamily<Vec<IpAddr>> {
    twinvpn_dns::stub::listen_addresses().expect("the stub's own listen addresses")
}

/// The preconditions that permit leaving `BLOCKED`, for a given plan.
#[must_use]
pub fn preconditions(plan: &RoutePlan, path_validated: bool) -> ProtectedPreconditions {
    ProtectedPreconditions {
        path_validated,
        ruleset_present: PerFamily::new(
            plan.carries(AddressFamily::V4),
            plan.carries(AddressFamily::V6),
        ),
    }
}
