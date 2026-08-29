//! **The data plane, composed.** `twinvpn-route` → `twinvpn-dns` →
//! `twinvpn-enforce` → the adapter's `TunnelDevice` and `NetworkConfig`.
//!
//! **Authority:** ADR-0018 CB-6 and CD-I5; ADR-0012 §11.8 (the arm and teardown
//! sequences), KS-5, KS-17a, KS-18, KS-19, MI-K1; ADR-0010 §11.3 and R1;
//! `docs/networking.md` §2.3 ("partial application is the leak window") and
//! §5.1; ADR-0015 §11.6 rule 1.
//!
//! # Review findings R-2 and R-7
//!
//! > **R-2.** Nine core crates are compiled but never composed. […] There is no
//! > production caller of `PlatformAdapter::apply` or `set_ruleset` anywhere.
//!
//! > **R-7.** The boot artifact is the only enforcement that exists, and it
//! > governs only the overlay prefixes. Because `apply` has no caller, the boot
//! > table is never replaced. **I3 does not hold for the composed product.**
//!
//! `twinvpn_route::program::compute`, `twinvpn_enforce::contract::assemble` and
//! `twinvpn_enforce::latch::Latch` all existed, were tested, and were reachable
//! from nothing but `tests/` and `lab/`. Each *computes*; none *installs* — by
//! design, because CB-6's first clause is "the core computes the desired
//! rule-set generation" and `twinvpn-enforce`'s own module docs say it "returns
//! a `NetworkContract` and calls nothing".
//!
//! **This module is CB-6's second clause.** It is the only place in the tree
//! that holds a `RoutePlan`, a `Dnspolicy`, a `Latch` and a `PlatformAdapter` at
//! the same time, which is exactly the composition-root privilege CD-I5 grants
//! `twinvpn-core` and no one else.
//!
//! # The order is `ArmStep`'s, not a convenience
//!
//! ```text
//! RULESET_BLOCKED live -> create iface (DOWN) -> link up
//!   -> apply(contract) -> path validated + assertion -> swap -> PROTECTED
//! ```
//!
//! The interface is created **down**, because one that comes up before its
//! addresses, routes and rules exist is §2.3's partial-application leak window.
//! The link comes up before `apply` and that is **KS-17a**: an address can be
//! added to a down interface, a route cannot — `RTM_NEWROUTE` answers
//! `ENETDOWN`. No guarantee moves, because `RULESET_BLOCKED` is live across the
//! whole interval and it is the routes that carry traffic.
//!
//! # Every failure path tightens
//!
//! No path through this module can leave the host less protected than it found
//! it. A failure at any step calls [`block`], which is `set_ruleset(Blocked)` —
//! unconditional, because tightening never needs a precondition. That is the
//! fail condition the review register names: *"tunnel failure silently falls
//! back to unprotected Internet while fail-closed mode is enabled."*

use twinvpn_enforce::contract::{self, ArmStep, ContractInputs};
use twinvpn_enforce::latch::{ArmingPolicy, Latch, ProtectedPreconditions};
use twinvpn_platform::config::{ContractGeneration, LinkState, NetworkContract, Ruleset};
use twinvpn_platform::iface::{InterfaceIndex, InterfaceName};
use twinvpn_platform::{PlatformError, TunnelHandle};
use twinvpn_route::program::{PlanInputs, RoutingMode};
use twinvpn_schema::v1;
use twinvpn_types::{codes, Component, Diagnostic, IpAddr, IpPrefix, OverlayAddresses, PerFamily};

use crate::core::Core;

/// The overlay interface this core programs.
///
/// Fixed by the product rather than discovered: ADR-0012's
/// `EnforcementConfig.overlay_interface` names it on the *adapter* side, and the
/// two must agree — a `RULESET_PROTECTED` exception written for an interface
/// that does not exist is a rule that permits nothing while reading as if it
/// permits the tunnel.
pub const OVERLAY_INTERFACE: &str = "twin0";

/// The overlay MTU this build programs.
///
/// The IPv6 minimum and nothing above it: `docs/networking.md` §6.3 floors a
/// path at 1280 and DPLPMTUD raises it from there. Starting at the floor cannot
/// produce a black hole; starting at a guess can.
pub const MTU: u32 = 1280;

/// The composed enforcement state.
///
/// One per [`Core`], behind the same mutex discipline as the session table
/// (F-6: exactly one thread mutates at a time).
#[derive(Debug)]
pub struct Enforcement {
    /// ADR-0012's latch. Starts `Blocked` — KS-19's direction, "the deny
    /// predates the first packet the host can emit".
    latch: Latch,
    /// The generation counter. **Monotone, allocated here**: ADR-0008 N-8
    /// requires the desired state to be computed whole before any mutation, and
    /// `apply` is idempotent on this id so a retry after a crash converges.
    next_generation: u64,
    /// The overlay interface handle, once created.
    handle: Option<TunnelHandle>,
    /// The generation currently applied.
    applied: Option<ContractGeneration>,
}

impl Default for Enforcement {
    fn default() -> Self {
        Self {
            // M2 — fail-closed while intended-up. ADR-0012 names it the
            // default, and it is written out rather than derived because
            // `ArmingPolicy` deliberately has no `Default`: which of M1/M2/M4 a
            // device runs under is a policy decision, not a fallback.
            latch: Latch::new(ArmingPolicy::WhileIntendedUp),
            // Generation 0 means "no contract has been applied" — the value the
            // shell's startup arming uses — so the first real contract is 1.
            next_generation: 1,
            handle: None,
            applied: None,
        }
    }
}

impl Enforcement {
    /// The ruleset the latch currently wants.
    #[must_use]
    pub const fn desired(&self) -> Ruleset {
        self.latch.desired()
    }

    /// The generation currently applied, if any.
    #[must_use]
    pub const fn applied(&self) -> Option<ContractGeneration> {
        self.applied
    }

    /// Whether an overlay interface exists.
    #[must_use]
    pub const fn has_interface(&self) -> bool {
        self.handle.is_some()
    }

    /// The overlay interface, once one has been created.
    ///
    /// **Read-only, and there is deliberately no setter.** The handle is
    /// allocated by [`arm`] and cleared by [`teardown`], so those two are the
    /// only places it can move; exposing it lets the packet path pump into the
    /// interface this module created rather than creating a second one of its
    /// own. A second interface would be a second `RULESET_PROTECTED` exception's
    /// worth of divergence between what the contract permits and what carries
    /// traffic, which is the shape §2.3 calls the leak window.
    #[must_use]
    pub const fn handle(&self) -> Option<TunnelHandle> {
        self.handle
    }
}

/// What arming produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Armed {
    /// The generation installed.
    pub generation: ContractGeneration,
    /// The posture in force **after the read-back**, never the one this process
    /// intended.
    ///
    /// ADR-0015 §11.6 rule 1: *"A `ProtectionAssertion` is produced by querying
    /// the enforcement layer … never of the agent's belief about what it
    /// configured."*
    pub ruleset: Ruleset,
}

/// Arms the data plane: computes one contract and installs it.
///
/// # The two facts this refuses without
///
/// * **this device's own overlay allocation** — the contract's `addresses` are
///   the overlay interface's own, R1 requires both families, and inventing one
///   would put a fabricated address on a real interface;
/// * **at least one authorized peer** — a TwinNet-only contract with no peer
///   routes nothing, and installing an empty tunnel while reporting protection
///   is the shape R-6 named on the adapter side.
///
/// Both are absent while no `ControlTransport` exists (W-12), so on a build with
/// no control plane this refuses **by name** and the host stays `Blocked`. That
/// is the correct posture and it is meant to be visible: the alternative is a
/// product that reports itself armed over an empty ruleset.
///
/// # Errors
///
/// A [`Diagnostic`] carrying a registered code. **The host is left `Blocked` on
/// every error path**, including the ones that fail after the interface exists.
pub fn arm(core: &Core) -> Result<Armed, Box<Diagnostic>> {
    let view = core.data_plane_view();
    let Some((twinnet, local)) = view.local_overlay() else {
        // No allocation, no contract. `AUTH.IDENTITY_MISSING` because the
        // overlay allocation arrives inside this device's own identity record
        // (S-08), so its absence is exactly "this device is not enrolled".
        return Err(Box::new(refuse(core, codes::AUTH_IDENTITY_MISSING)));
    };
    let authorized: Vec<OverlayAddresses> = view
        .peers(&twinnet)
        .iter()
        .filter(|p| p.tunnel_key_binding_verified)
        .map(|p| p.overlay)
        .collect();
    if authorized.is_empty() {
        return Err(Box::new(refuse(core, codes::AUTH_PEER_UNTRUSTED)));
    }

    let generation = {
        let mut enforcement = core.enforcement();
        let generation = ContractGeneration(enforcement.next_generation);
        enforcement.next_generation = enforcement.next_generation.saturating_add(1);
        generation
    };

    let contract = match assemble(local, &authorized, generation) {
        Ok(contract) => contract,
        Err(diagnostic) => {
            block(core);
            return Err(diagnostic);
        }
    };

    install(core, generation, &contract)
}

/// Computes one contract from the three data-plane crates. **Touches nothing.**
fn assemble(
    local: OverlayAddresses,
    peers: &[OverlayAddresses],
    generation: ContractGeneration,
) -> Result<NetworkContract, Box<Diagnostic>> {
    // 1. `twinvpn-route`. The TwinNet's prefixes are the authorized peers' own
    //    overlay addresses as HOST routes: every peer this device may reach is
    //    reachable and nothing else is. A summary prefix would pull traffic for
    //    peers this device is *not* authorized to reach into the tunnel, where
    //    it would be dropped rather than refused — a silent failure in place of
    //    a named one.
    let twinnet_prefixes = host_prefixes(peers).map_err(|_| {
        Box::new(
            Diagnostic::builder(codes::AUTH_IDENTITY_MISSING, Component::RoutingEngine).build(),
        )
    })?;
    let inputs = PlanInputs {
        mode: RoutingMode::TwinnetOnly,
        overlay: local,
        twinnet_prefixes,
        accepted: Vec::new(),
        on_link: Vec::new(),
        excluded: Vec::new(),
        // The kernel index is the adapter's to know. The routes carry the
        // interface the contract is applied *to*, and `apply` is a single
        // transaction against one interface, so the index is not a fact this
        // computation needs — and guessing one would be a fact it invented.
        interface: InterfaceIndex(0),
        selected_exit_node: None,
        mtu: MTU,
        // No exit node, so no default route in either family — and therefore no
        // asymmetry: KS-6's uncovered-family case needs one family granted and
        // the other not, and here neither is.
        exit_grant: PerFamily::new(false, false),
    };
    let plan = twinvpn_route::program::compute(&inputs, generation)
        .map_err(|e| Box::new(e.diagnostic()))?;

    // 2. `twinvpn-dns`. No Owner-signed bundle exists without a control plane,
    //    and DN-20 makes the absence fail-closed rather than permissive: `OFF`
    //    with no upstream servers and `block_fallback` set in **both** families
    //    means nothing resolves off-tunnel. `off_mode_permitted` holds because
    //    the routing mode is TwinNet-only and no ExitNode is engaged.
    let dns_policy = twinvpn_dns::policy::validate(&denied_dns_policy()).map_err(|_| {
        Box::new(
            Diagnostic::builder(codes::DNS_RESOLUTION_BLOCKED_FAIL_CLOSED, Component::Dns).build(),
        )
    })?;

    // 3. `twinvpn-enforce`. One contract carrying all four halves, because §2.3
    //    makes partial application the leak window and `apply` is
    //    all-or-nothing per generation.
    contract::assemble(
        &ContractInputs {
            route_plan: &plan,
            dns_policy: &dns_policy,
            // No stub is bound in this build, so the host is pointed at no
            // resolver rather than at an upstream one: DN-20's fail-closed
            // direction, and the reason `is_default_resolver` stays false.
            stub_addresses: PerFamily::new(Vec::new(), Vec::new()),
            // The contract is applied while the latch is still BLOCKED. The
            // swap to PROTECTED is a separate call, after the read-back —
            // `ArmStep`'s order, not an optimisation.
            ruleset: Ruleset::Blocked,
            tunnel_remote_address: None,
        },
        generation,
    )
    .map_err(|e| Box::new(Diagnostic::builder(e.reason_code(), Component::KillSwitch).build()))
}

/// Installs the contract, in `ArmStep` order, and **reads the result back**.
fn install(
    core: &Core,
    generation: ContractGeneration,
    contract: &NetworkContract,
) -> Result<Armed, Box<Diagnostic>> {
    let Ok(name) = InterfaceName::new(OVERLAY_INTERFACE) else {
        return Err(Box::new(Diagnostic::invariant_violated(
            Component::PlatformAdapter,
            "the overlay interface name is not nameable",
        )));
    };
    let existing = core.enforcement().handle;

    let outcome: Result<(TunnelHandle, Option<Ruleset>), (ArmStep, PlatformError)> = core
        .block_on_adapter(|_env, adapter| {
            Box::pin(async move {
                // ArmStep::BlockedLive — asserted, not assumed. The shell's
                // startup arming installed it; if anything removed it since,
                // this reinstates it before the interface exists.
                adapter
                    .network_config()
                    .set_ruleset(ContractGeneration(0), Ruleset::Blocked)
                    .await
                    .map_err(|e| (ArmStep::BlockedLive, e))?;

                // ArmStep::CreateInterfaceDown. Idempotent across arms: an
                // interface that already exists is reused rather than
                // duplicated, which is what makes a re-arm converge.
                let handle = match existing {
                    Some(handle) => handle,
                    None => adapter
                        .tunnel()
                        .create_interface(&name, contract.mtu)
                        .await
                        .map_err(|e| (ArmStep::CreateInterfaceDown, e))?,
                };

                // ArmStep::LinkUp, before the contract. KS-17a: a route cannot
                // be added to a down interface.
                adapter
                    .tunnel()
                    .set_link(handle, LinkState::Up)
                    .await
                    .map_err(|e| (ArmStep::LinkUp, e))?;

                // ArmStep::ApplyContract — addresses, routes, DNS and ruleset
                // as ONE all-or-nothing transaction. **This is the call the
                // whole product was missing (R-2/R-7).**
                adapter
                    .network_config()
                    .apply(contract)
                    .await
                    .map_err(|e| (ArmStep::ApplyContract, e))?;

                // The assertion is produced by QUERYING the enforcement layer.
                let installed = adapter
                    .network_config()
                    .installed_ruleset()
                    .await
                    .map_err(|e| (ArmStep::PathValidatedAndAsserted, e))?;
                Ok((handle, installed))
            })
        });

    let (handle, installed) = match outcome {
        Ok(pair) => pair,
        Err((step, error)) => {
            // The interface may now exist and be up with no contract on it.
            // `Blocked` is what makes that state safe rather than a hole, and
            // it is applied unconditionally before the failure is reported.
            block(core);
            return Err(Box::new(
                Diagnostic::builder(error.reason_code(), Component::KillSwitch)
                    .evidence(
                        "arm_step",
                        twinvpn_types::EvidenceValue::Text(format!("{step:?}")),
                    )
                    .build(),
            ));
        }
    };

    {
        let mut enforcement = core.enforcement();
        enforcement.handle = Some(handle);
        enforcement.applied = Some(generation);
    }

    // ArmStep::PathValidatedAndAsserted. KS-18: `RULESET_PROTECTED` may be
    // entered only after **both** (a) an authenticated bidirectional path
    // validation and (b) an assertion that the intended rules are installed for
    // **both families**. Either failing keeps `RULESET_BLOCKED`.
    //
    // (b) comes from the read-back above: a `None` means the adapter cannot
    // report a posture, and an unreadable posture is not an asserted one.
    let asserted = installed.is_some();
    let pre = ProtectedPreconditions {
        path_validated: core.any_session_connected(),
        ruleset_present: PerFamily::new(asserted, asserted),
    };
    let desired = core.enforcement().latch.leave_blocked(pre);

    // ArmStep::SwapToProtected — or not, and truthfully either way.
    let ruleset = swap(core, generation, desired)?;
    Ok(Armed {
        generation,
        ruleset,
    })
}

/// Performs the atomic swap and **reads back what is actually installed**.
fn swap(
    core: &Core,
    generation: ContractGeneration,
    desired: Ruleset,
) -> Result<Ruleset, Box<Diagnostic>> {
    let outcome: Result<Option<Ruleset>, PlatformError> = core.block_on_adapter(|_env, adapter| {
        Box::pin(async move {
            adapter
                .network_config()
                .set_ruleset(generation, desired)
                .await?;
            adapter.network_config().installed_ruleset().await
        })
    });
    match outcome {
        // The read-back is the answer, not `desired`. An adapter that cannot
        // report a posture has not asserted a protected one, so `None` reads as
        // `Blocked` — the direction that cannot over-claim.
        Ok(installed) => Ok(installed.unwrap_or(Ruleset::Blocked)),
        Err(error) => {
            block(core);
            Err(Box::new(
                Diagnostic::builder(error.reason_code(), Component::KillSwitch).build(),
            ))
        }
    }
}

/// Swaps to `RULESET_BLOCKED`. **Always permitted, never refused.**
///
/// ADR-0012 §11.8: tightening needs no precondition. **MI-K1 is satisfied** —
/// this does not clear the latch, it raises the posture, and only §11.14's
/// authenticated ceremony can lower one.
///
/// Deliberately returns nothing: this is the path a failure takes, and a failure
/// handler that can itself fail leaves nobody to handle the second one. A
/// refusal from the adapter is published as a diagnostic, because a host that is
/// now neither blocked nor protected is something nobody can fix from here and
/// saying so is the only honest action left.
pub fn block(core: &Core) {
    let generation = core.enforcement().applied.unwrap_or(ContractGeneration(0));
    core.enforcement().latch.enter_blocked();

    let outcome: Result<(), PlatformError> = core.block_on_adapter(|_env, adapter| {
        Box::pin(async move {
            adapter
                .network_config()
                .set_ruleset(generation, Ruleset::Blocked)
                .await
        })
    });
    if let Err(error) = outcome {
        core.publish_diagnostic(
            &Diagnostic::builder(error.reason_code(), Component::KillSwitch).build(),
        );
    }
}

/// §11.8's teardown: link down → swap to `RULESET_BLOCKED` → destroy interface.
///
/// **The rules stay live.** `TeardownStep` puts the swap *before* the interface
/// is destroyed and never removes a rule set, because CB-6 puts the installed
/// rules in the OS's custody precisely so the tunnel going away cannot drop
/// protection.
pub fn teardown(core: &Core) {
    let handle = core.enforcement().handle;
    let Some(handle) = handle else {
        // No interface: the swap is still worth making, because the latch's
        // posture is what protects the host and it must not be left Protected
        // over a tunnel that no longer carries anything.
        block(core);
        return;
    };

    // TeardownStep::LinkDown, first. Enforcement rules stay installed — the two
    // are separate facts, which is why they are separate calls.
    let down: Result<(), PlatformError> = core.block_on_adapter(|_env, adapter| {
        Box::pin(async move { adapter.tunnel().set_link(handle, LinkState::Down).await })
    });
    if let Err(error) = down {
        core.publish_diagnostic(
            &Diagnostic::builder(error.reason_code(), Component::TunnelEngine).build(),
        );
    }

    // TeardownStep::SwapToBlocked, before anything is destroyed.
    block(core);

    // TeardownStep::DestroyInterface. Idempotent and safe after a crash.
    let destroyed: Result<(), PlatformError> = core.block_on_adapter(|_env, adapter| {
        Box::pin(async move { adapter.tunnel().destroy_interface(handle).await })
    });
    match destroyed {
        Ok(()) => {
            let mut enforcement = core.enforcement();
            enforcement.handle = None;
            enforcement.applied = None;
        }
        Err(error) => core.publish_diagnostic(
            &Diagnostic::builder(error.reason_code(), Component::TunnelEngine).build(),
        ),
    }
}

/// Every authorized peer's overlay address, as host prefixes per family.
fn host_prefixes(
    peers: &[OverlayAddresses],
) -> Result<PerFamily<Vec<IpPrefix>>, twinvpn_types::TypeError> {
    let mut v4 = Vec::with_capacity(peers.len());
    let mut v6 = Vec::with_capacity(peers.len());
    for overlay in peers {
        v4.push(IpPrefix::new(IpAddr::V4(overlay.v4), 32)?);
        v6.push(IpPrefix::new(IpAddr::V6(overlay.v6), 128)?);
    }
    Ok(PerFamily::new(v4, v6))
}

/// The deny-shaped `DnsPolicy` a device with no Owner bundle runs under.
///
/// Every presence bit is `Some(true)` because §13.4 makes an *absent*
/// deny-shaped field malformed rather than permissive, and both `block_fallback`
/// bits are set: with no policy, nothing resolves off-tunnel. DN-20's direction.
fn denied_dns_policy() -> v1::DnsPolicy {
    v1::DnsPolicy {
        dnspolicy_id: "twinvpn/default-denied".to_owned(),
        version: 0,
        // OFF. Permitted here and only here: `off_mode_permitted` requires
        // TwinNet-only routing and no engaged ExitNode, which is exactly the
        // plan `assemble` computes.
        // 3 == `DNS_MODE_OFF`. `Mode` decodes from the wire and deliberately
        // does not encode to it — this is the one place the product authors a
        // policy rather than receiving one.
        mode: 3,
        servers_v4: Vec::new(),
        servers_v6: Vec::new(),
        servers_declared_v4: Some(true),
        servers_declared_v6: Some(true),
        split_domains: Vec::new(),
        search_domains: Vec::new(),
        block_fallback_v4: Some(true),
        block_fallback_v6: Some(true),
        dnssec_validate: false,
        upstream_dot: false,
        not_after_ms: 0,
    }
}

/// Blocks the host, then names the refusal.
///
/// The order is the point: the tightening happens whether or not the caller
/// ever looks at the returned diagnostic.
fn refuse(instance: &Core, code: twinvpn_types::ReasonCode) -> Diagnostic {
    block(instance);
    Diagnostic::builder(code, Component::KillSwitch).build()
}
