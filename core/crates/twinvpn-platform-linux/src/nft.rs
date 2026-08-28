//! The `nftables` enforcement layer: **the core computes, the adapter installs,
//! the OS holds** (CB-6).
//!
//! **Authority:** ADR-0012 §11.1 (the two-tier model), §11.2 (the traffic-class
//! table), §11.3 KS-5, §11.5 KS-9…KS-12 (the bootstrap exemption), §11.6 (Linux:
//! `table inet twinvpn`), §11.8 KS-17/KS-18/KS-20, §11.9 (the leak canary);
//! ADR-0010 §11.5 clause 1 (**one object, both families**); ADR-0011 §11.13(b)
//! (DNS containment); ADR-0015 §11.6 rule 1 (the `ProtectionAssertion`);
//! ADR-0016 §11.5 (owner-tagged, reclaimed not recreated).
//!
//! # KS-5, made structural rather than disciplinary
//!
//! > An implementation that can install the Tier-2 rule set for one family
//! > without the other is **non-conforming**, not degraded. There is no partial-
//! > install success result.
//!
//! There is exactly one table, `inet twinvpn`, and `inet` matches IPv4 and IPv6
//! together. **There is no code path in this module that emits a v4 rule without
//! its v6 counterpart, because there is no separate v6 object to forget.** That
//! is ADR-0010 §11.5's "structural guarantee, not a discipline", realized as a
//! renderer that writes one script.
//!
//! # KS-17: two rulesets, never zero
//!
//! The whole table is replaced in **one `nft -f` transaction** — `add table` to
//! make the delete safe, `delete table`, then the new definition. `nft` applies a
//! script atomically, so there is no instant at which the host has no TwinVPN
//! table. A `flush`-then-`add` in two invocations would open exactly the window
//! KS-17 exists to close, and `remove-then-add` is what KS-23 forbids on update.
//!
//! # W-24: the assertion here is a **query**, not a belief
//!
//! ADR-0015 §11.6 rule 1 requires the `ProtectionAssertion` to be produced by
//! *querying the enforcement layer*, "never of the agent's belief", and
//! `twinvpn.h`'s F-9 vtable offers `set_ruleset` with **no getter** — so a shell
//! bound only to the C ABI cannot produce one at all (W-24).
//!
//! This adapter is bound as a Rust crate, so it does not have that limit.
//! [`LinuxEnforcement::installed`] runs `nft --json list table inet twinvpn` and
//! reads the posture out of **the kernel's own answer**. Nothing is cached: the
//! reconciler's job is to notice that something else changed the rules, and a
//! cache cannot. If the query fails the answer is an error, never a remembered
//! value — `Ok(None)` would read as "no ruleset installed", which is the
//! dangerous direction.
//!
//! # The posture and the generation live in the kernel
//!
//! Two nftables **named counters** carry them: `posture_blocked` xor
//! `posture_protected`, and `gen_<n>`. They are objects in our own table, so
//! they survive a core crash (CB-6), are removed with the table by an uninstall,
//! and are readable by `twinvpn-unblock` with the agent absent (ADR-0016 PS-6).
//! Encoding state as a counter rather than a comment is deliberate: `nft --json`
//! reports objects structurally, and a comment is free text that a parser has to
//! guess at.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use twinvpn_platform::{
    ContractGeneration, EnforcementCustody, NetworkContract, PlatformError, Ruleset,
};
use twinvpn_types::{AddressFamily, IpPrefix};

use crate::addr::prefix_text;

/// The one owned table. ADR-0012 §11.6's Linux row, verbatim.
pub const TABLE: &str = "twinvpn";

/// The `inet` family — the whole of KS-5's structural guarantee.
pub const FAMILY: &str = "inet";

/// The posture counter's name when `RULESET_BLOCKED` is installed.
pub const POSTURE_BLOCKED: &str = "posture_blocked";

/// The posture counter's name when `RULESET_PROTECTED` is installed.
pub const POSTURE_PROTECTED: &str = "posture_protected";

/// The prefix of the generation counter's name: `gen_<decimal>`.
pub const GENERATION_PREFIX: &str = "gen_";

/// The deny counter the leak canary reads (ADR-0012 §11.9), per family.
///
/// > the agent emits a uniquely marked datagram from a **non-exempt** socket to
/// > a destination in the protected scope and asserts that the enforcement
/// > layer's deny counter for that family incremented.
///
/// Two counters, named per family, because the canary runs per family and a
/// single combined counter would let a v6 leak hide behind v4 drops.
pub const DENY_COUNTER: [(&str, AddressFamily); 2] = [
    ("deny_v4", AddressFamily::V4),
    ("deny_v6", AddressFamily::V6),
];

/// The exempt counter KS-11 requires, per family.
///
/// > The enforcement layer MUST export byte and packet counters for the exempt
/// > rule, per family.
pub const EXEMPT_COUNTER: [(&str, AddressFamily); 2] = [
    ("exempt_v4", AddressFamily::V4),
    ("exempt_v6", AddressFamily::V6),
];

/// The DNS containment deny counter (ADR-0011 §11.12's negative canary).
///
/// Its own counter, **not** one of [`DENY_COUNTER`]'s, for two reasons. The
/// containment rule is genuinely dual-family in one nftables expression
/// (`meta l4proto { tcp, udp } th dport`), so charging it to `deny_v4` would
/// make the two per-family canary counters asymmetric for a reason that has
/// nothing to do with a leak. And ADR-0011's negative canary asks a different
/// question from ADR-0012's — "was my off-tunnel DNS query dropped" rather than
/// "was my off-tunnel protected packet dropped" — so it needs its own number.
pub const DNS_DENY_COUNTER: &str = "deny_dns";

/// What the adapter needs that the seam does not carry.
///
/// **Each field here is a reported gap, not a decision this adapter made up.**
/// [`NetworkContract`] carries addresses, routes, DNS, the ruleset selector and
/// the MTU — and nothing that names the agent's own `fwmark`, its cgroup, or the
/// `local_network_access` setting of ADR-0012 KS-4. Those are facts the shell
/// knows about its own process and its own installation, so they are injected at
/// construction (CD-2) rather than discovered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcementConfig {
    /// The overlay interface name. Tier 2 is **interface-scoped**, so this is
    /// the one name the whole ruleset turns on.
    pub overlay_interface: String,
    /// The `fwmark` the agent sets with `SO_MARK`, and the same mark the §5.2
    /// policy-routing rule matches.
    ///
    /// **No value is pinned anywhere in the Phase 1 corpus** — `docs/networking.md`
    /// §5.2 and ADR-0010 §11.3 fix table `52` and leave the mark open. Reported
    /// as a gap; [`DEFAULT_FWMARK`] is this adapter's choice, recorded as one.
    pub firewall_mark: u32,
    /// The agent's cgroup v2 path, for KS-9(1)'s **other** half.
    ///
    /// KS-9(1) on Linux is "`cgroup v2` path match **and** `fwmark` set via
    /// `SO_MARK` by the agent" — **and**, not or. With `None` the exemption rests
    /// on the mark alone, which is weaker than KS-9 specifies, so the absence is
    /// reported by [`EnforcementConfig::ks9_complete`] rather than hidden.
    pub cgroup_path: Option<String>,
    /// Whether ADR-0012 KS-4's `local_network_access` is `ALLOW` (its default in
    /// all three routing modes).
    pub local_network_access: bool,
    /// The on-link prefixes of the non-overlay interfaces.
    ///
    /// KS-4: "the permitted set is *on-link prefixes only*, recomputed on every
    /// network-change event, and never includes a destination reachable only via
    /// a router."
    pub on_link_prefixes: Vec<IpPrefix>,
}

/// This adapter's `fwmark`, chosen because the corpus pins none.
///
/// `0x7677` is ASCII `vw` — a value outside the ranges systemd-networkd,
/// NetworkManager and `wg-quick` are known to use, and outside the low integers
/// an operator is likely to have chosen by hand. Recorded as a decision.
pub const DEFAULT_FWMARK: u32 = 0x7677;

impl EnforcementConfig {
    /// Whether KS-9(1)'s Linux predicate is satisfiable as configured.
    ///
    /// `false` means the bootstrap exemption rests on the `fwmark` alone. That
    /// is a **weaker** predicate than KS-9 specifies and the shell reports it;
    /// it is not silently upgraded to "close enough".
    #[must_use]
    pub const fn ks9_complete(&self) -> bool {
        self.cgroup_path.is_some()
    }
}

/// The desired ruleset, as text for `nft -f -`.
///
/// **A pure function.** No I/O, no clock, no ambient state — so the rendering is
/// unit-testable on a host with no `nft` at all, which is what makes the
/// contents of the ruleset a checked property rather than an operational one.
///
/// # CB-2: nothing here is a decision
///
/// The Tier-1 protected scope is taken **verbatim from the contract's route
/// destinations**. That is not this adapter choosing a scope: `twinvpn-route`
/// computes which destinations go through the overlay, and ADR-0012 §11.1's
/// three routing modes are already expressed in that set — full tunnel arrives
/// as the four `/1` routes of `docs/networking.md` §7.2, which *is* §11.1's
/// complement form. This function translates; it does not decide.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn render(contract: &NetworkContract, ruleset: Ruleset, config: &EnforcementConfig) -> String {
    let overlay = &config.overlay_interface;
    let posture = match ruleset {
        Ruleset::Blocked => POSTURE_BLOCKED,
        Ruleset::Protected => POSTURE_PROTECTED,
    };
    let generation = contract.generation.0;

    // The Tier-1 protected scope, both families, from the contract's routes.
    // Sorted and de-duplicated so the rendered script is DETERMINISTIC: two
    // renders of one contract must produce identical bytes, or a reconciler
    // comparing them would see drift that is not there.
    let mut scope_v4: BTreeSet<String> = BTreeSet::new();
    let mut scope_v6: BTreeSet<String> = BTreeSet::new();
    for route in &contract.routes.v4 {
        scope_v4.insert(prefix_text(route.destination));
    }
    for route in &contract.routes.v6 {
        scope_v6.insert(prefix_text(route.destination));
    }
    let mut on_link_v4: BTreeSet<String> = BTreeSet::new();
    let mut on_link_v6: BTreeSet<String> = BTreeSet::new();
    for prefix in &config.on_link_prefixes {
        match prefix.family() {
            AddressFamily::V4 => on_link_v4.insert(prefix_text(*prefix)),
            AddressFamily::V6 => on_link_v6.insert(prefix_text(*prefix)),
        };
    }

    let mut s = String::with_capacity(4096);

    // KS-17 / KS-23: ONE transaction. `add table` makes the `delete` safe when
    // the table is absent (first start), and `nft -f` applies the whole script
    // atomically — so there is no instant with no TwinVPN table, and this is a
    // swap rather than a remove-then-add.
    let _ = writeln!(s, "add table {FAMILY} {TABLE}");
    let _ = writeln!(s, "delete table {FAMILY} {TABLE}");
    let _ = writeln!(s, "table {FAMILY} {TABLE} {{");

    // The posture and the generation, held by the kernel (CB-6) and readable by
    // `twinvpn-unblock` with the agent absent (ADR-0016 PS-6, KS-20a).
    let _ = writeln!(s, "  counter {posture} {{ }}");
    let _ = writeln!(s, "  counter {GENERATION_PREFIX}{generation} {{ }}");
    for (name, _) in DENY_COUNTER {
        let _ = writeln!(s, "  counter {name} {{ }}");
    }
    for (name, _) in EXEMPT_COUNTER {
        let _ = writeln!(s, "  counter {name} {{ }}");
    }
    let _ = writeln!(s, "  counter {DNS_DENY_COUNTER} {{ }}");

    // ---- the output hook: locally originated traffic -----------------------
    // Priority `filter` (0) rather than `raw`, so a host firewall's own rules
    // coexist: §11.11 requires that we install into our OWN table so a "reset
    // firewall" action does not remove us and we do not remove them.
    let _ = writeln!(s, "  chain output {{");
    let _ = writeln!(
        s,
        "    type filter hook output priority filter; policy accept;"
    );

    // Class 8 — loopback. Always permitted; the stub's own listeners of
    // ADR-0011 §11.2 live here.
    let _ = writeln!(s, "    oifname \"lo\" accept");

    // Return traffic for an already-permitted flow. Without this the exemption
    // would have to be re-derived for every reply and the DNS stub could not
    // receive an answer it was permitted to ask for.
    let _ = writeln!(s, "    ct state established,related accept");

    // Class 7 — the bootstrap exemption (KS-9). BOTH halves where the cgroup is
    // known: "cgroup v2 path match AND fwmark set via SO_MARK by the agent".
    // The exempt counter is KS-11's, per family, so a divergence between our own
    // accounting and the kernel's is detectable (`POLICY.EXEMPT.EGRESS_ANOMALY`).
    if let Some(path) = &config.cgroup_path {
        let _ = writeln!(
            s,
            "    meta mark {mark:#x} socket cgroupv2 level 2 \"{path}\" meta nfproto ipv4 \
             counter name \"exempt_v4\" accept",
            mark = config.firewall_mark
        );
        let _ = writeln!(
            s,
            "    meta mark {mark:#x} socket cgroupv2 level 2 \"{path}\" meta nfproto ipv6 \
             counter name \"exempt_v6\" accept",
            mark = config.firewall_mark
        );
    } else {
        // Weaker than KS-9(1) specifies, and reported as such by
        // `ks9_complete()` rather than presented as equivalent.
        let _ = writeln!(
            s,
            "    meta mark {mark:#x} meta nfproto ipv4 counter name \"exempt_v4\" accept",
            mark = config.firewall_mark
        );
        let _ = writeln!(
            s,
            "    meta mark {mark:#x} meta nfproto ipv6 counter name \"exempt_v6\" accept",
            mark = config.firewall_mark
        );
    }

    // Class 5 — underlay DHCP / DHCPv6 / ND / RA. Permitted as link-local
    // control traffic only, and never as an egress path for protected traffic:
    // ADR-0010 §11.5 clause 5 is explicit that blocking them breaks the underlay
    // itself. Scoped OFF the overlay so they cannot be a hole in the tunnel.
    let _ = writeln!(
        s,
        "    oifname != \"{overlay}\" udp dport {{ 67, 68 }} accept"
    );
    let _ = writeln!(
        s,
        "    oifname != \"{overlay}\" udp dport {{ 546, 547 }} accept"
    );
    let _ = writeln!(
        s,
        "    oifname != \"{overlay}\" icmpv6 type {{ nd-router-solicit, nd-router-advert, \
         nd-neighbor-solicit, nd-neighbor-advert, nd-redirect }} accept"
    );

    // Class 9 — link-local unicast on a non-overlay interface, both families.
    let _ = writeln!(
        s,
        "    oifname != \"{overlay}\" ip daddr 169.254.0.0/16 accept"
    );
    let _ = writeln!(s, "    oifname != \"{overlay}\" ip6 daddr fe80::/10 accept");

    // Classes 4 and 10 — the local physical LAN and link-local multicast, which
    // follow it. On-link prefixes ONLY, both families, and only when KS-4's
    // `local_network_access` is ALLOW.
    if config.local_network_access {
        for prefix in &on_link_v4 {
            let _ = writeln!(s, "    oifname != \"{overlay}\" ip daddr {prefix} accept");
        }
        for prefix in &on_link_v6 {
            let _ = writeln!(s, "    oifname != \"{overlay}\" ip6 daddr {prefix} accept");
        }
        let _ = writeln!(
            s,
            "    oifname != \"{overlay}\" ip daddr 224.0.0.0/24 ip ttl 1 accept"
        );
        let _ = writeln!(
            s,
            "    oifname != \"{overlay}\" ip6 daddr ff02::/16 ip6 hoplimit 1 accept"
        );
    }

    // Class 6 — DNS containment (ADR-0011 §11.13(b)): "a single dual-family
    // object denying UDP/TCP 53, TCP 853, and the known-DoH endpoint list on
    // every non-overlay interface". The stub's own outbound sockets carry the
    // mark and were accepted above, so this denies everything else.
    let _ = writeln!(
        s,
        "    oifname != \"{overlay}\" meta l4proto {{ tcp, udp }} th dport {{ 53, 853 }} \
         counter name \"{DNS_DENY_COUNTER}\" drop"
    );

    match ruleset {
        Ruleset::Blocked => {
            // RULESET_BLOCKED — "no protected egress on any interface",
            // INCLUDING the overlay, because in this posture the path is not
            // validated and the ProtectionAssertion has not been made (KS-18).
            emit_scope_drop(&mut s, &scope_v4, &scope_v6, None);
        }
        Ruleset::Protected => {
            // RULESET_PROTECTED — protected egress permitted ONLY via the
            // overlay. Tier 2 is interface-scoped and default-deny, which is why
            // a v6 address or a whole new interface appearing AFTER this is
            // installed is denied with NO rule update required for correctness
            // (ADR-0010 §11.5 clause 2).
            emit_scope_drop(&mut s, &scope_v4, &scope_v6, Some(overlay));
        }
    }
    let _ = writeln!(s, "  }}");

    // ---- the forward hook: KS-2 -------------------------------------------
    // "Forwarded traffic is protected by the same Tier-2 rule and is NEVER
    // eligible for any exemption in §11.2." So this chain carries the scope drop
    // and nothing else — no mark match, no cgroup match, no LAN allowance.
    let _ = writeln!(s, "  chain forward {{");
    let _ = writeln!(
        s,
        "    type filter hook forward priority filter; policy accept;"
    );
    let _ = writeln!(s, "    ct state established,related accept");
    match ruleset {
        Ruleset::Blocked => emit_scope_drop(&mut s, &scope_v4, &scope_v6, None),
        Ruleset::Protected => emit_scope_drop(&mut s, &scope_v4, &scope_v6, Some(overlay)),
    }
    let _ = writeln!(s, "  }}");

    let _ = writeln!(s, "}}");
    s
}

/// Emits the Tier-2 drop for **both** families.
///
/// One function, called once per chain, so there is no call site that can emit
/// the v4 half without the v6 half — KS-5 as a code shape rather than a rule to
/// remember. `permit_via` is `Some(interface)` in `RULESET_PROTECTED` and `None`
/// in `RULESET_BLOCKED`; both are fail-closed, and the only difference between
/// the two rulesets is whether the overlay is an exception.
fn emit_scope_drop(
    s: &mut String,
    scope_v4: &BTreeSet<String>,
    scope_v6: &BTreeSet<String>,
    permit_via: Option<&str>,
) {
    if let Some(overlay) = permit_via {
        for prefix in scope_v4 {
            let _ = writeln!(s, "    oifname \"{overlay}\" ip daddr {prefix} accept");
        }
        for prefix in scope_v6 {
            let _ = writeln!(s, "    oifname \"{overlay}\" ip6 daddr {prefix} accept");
        }
    }
    for prefix in scope_v4 {
        let _ = writeln!(s, "    ip daddr {prefix} counter name \"deny_v4\" drop");
    }
    for prefix in scope_v6 {
        let _ = writeln!(s, "    ip6 daddr {prefix} counter name \"deny_v6\" drop");
    }
}

/// What a read-back of the installed table reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Installed {
    /// The posture the kernel is holding.
    pub ruleset: Ruleset,
    /// The generation the kernel is holding.
    pub generation: Option<ContractGeneration>,
}

/// Reads the posture and generation out of `nft --json list table inet twinvpn`.
///
/// **This is the query half of W-24.** It reads the kernel's answer and nothing
/// else: there is no cached value to fall back on and no default to assume.
///
/// Returns `None` when the table exists but carries **neither** posture counter
/// — a table somebody else built under our name, or one this build does not
/// recognise. That is deliberately not "unprotected": the caller turns it into a
/// refusal, and O-18's fail-safe direction renders the indicator `UNKNOWN`.
#[must_use]
pub fn parse_installed(json: &str) -> Option<Installed> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    let items = value.get("nftables")?.as_array()?;

    let mut ruleset = None;
    let mut generation = None;
    for item in items {
        let Some(counter) = item.get("counter") else {
            continue;
        };
        // Only objects in OUR table count. A counter of the same name in another
        // table is somebody else's, and reading it would let a third party
        // dictate our reported posture.
        if counter.get("table").and_then(serde_json::Value::as_str) != Some(TABLE) {
            continue;
        }
        if counter.get("family").and_then(serde_json::Value::as_str) != Some(FAMILY) {
            continue;
        }
        let Some(name) = counter.get("name").and_then(serde_json::Value::as_str) else {
            continue;
        };
        match name {
            POSTURE_BLOCKED => ruleset = Some(Ruleset::Blocked),
            POSTURE_PROTECTED => ruleset = Some(Ruleset::Protected),
            other => {
                if let Some(digits) = other.strip_prefix(GENERATION_PREFIX) {
                    if let Ok(n) = digits.parse::<u64>() {
                        generation = Some(ContractGeneration(n));
                    }
                }
            }
        }
    }
    ruleset.map(|ruleset| Installed {
        ruleset,
        generation,
    })
}

/// Linux's enforcement custody, declared truthfully.
///
/// Both are `true`, and both are properties of nftables rather than of this
/// code: the table is kernel-resident so it outlives the process (CB-6's normal
/// case), and `nft -f` applies a script as one transaction so the swap has no
/// window with no rules (KS-17). On a target where either were false the honest
/// answer would be `false` and the residual would be a stated one.
#[must_use]
pub const fn custody() -> EnforcementCustody {
    EnforcementCustody {
        survives_core_exit: true,
        swap_is_atomic: true,
    }
}

/// The error a caller gets when the enforcement layer cannot be reached.
///
/// Named rather than returned as a bare `io::Error`, because arming must never
/// fail open: ADR-0012 §8 requires that if the ruleset cannot be installed the
/// client refuses to enter a protected state.
#[must_use]
pub fn unreachable(call: &'static str, code: i32) -> PlatformError {
    crate::oserr::unavailable(call, code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_platform::{DnsConfig, RouteEntry};
    use twinvpn_types::{IpAddr, PerFamily, V4Addr, V6Addr};

    fn v4(a: [u8; 4], len: u32) -> IpPrefix {
        IpPrefix::new(IpAddr::V4(V4Addr::from_octets(a)), len).expect("canonical")
    }

    fn v6(first: u8, second: u8, len: u32) -> IpPrefix {
        let mut o = [0u8; 16];
        o[0] = first;
        o[1] = second;
        IpPrefix::new(IpAddr::V6(V6Addr::new(o, None).expect("valid")), len).expect("canonical")
    }

    fn contract(generation: u64, ruleset: Ruleset) -> NetworkContract {
        NetworkContract {
            generation: ContractGeneration(generation),
            addresses: PerFamily::new(vec![v4([100, 64, 0, 1], 32)], vec![v6(0xfd, 0x7c, 128)]),
            routes: PerFamily::new(
                vec![RouteEntry {
                    destination: v4([100, 64, 0, 0], 12),
                    via: None,
                    interface: twinvpn_platform::InterfaceIndex(9),
                    metric: None,
                }],
                vec![RouteEntry {
                    destination: v6(0xfd, 0x7c, 48),
                    via: None,
                    interface: twinvpn_platform::InterfaceIndex(9),
                    metric: None,
                }],
            ),
            dns: DnsConfig {
                resolvers: PerFamily::new(Vec::new(), Vec::new()),
                search_domains: Vec::new(),
                split_domains: Vec::new(),
                is_default_resolver: false,
            },
            ruleset,
            mtu: 1280,
        }
    }

    fn config() -> EnforcementConfig {
        EnforcementConfig {
            overlay_interface: "twin0".to_owned(),
            firewall_mark: DEFAULT_FWMARK,
            cgroup_path: Some("system.slice/twinvpnd.service".to_owned()),
            local_network_access: true,
            // A ULA rather than `fe80::/10`: `twinvpn-types` cannot represent a
            // link-local PREFIX at all — `V6Addr::new` requires a zone on
            // `fe80::/10` and `IpPrefix::new` rejects one — which is the defect
            // recorded at `iface::a_link_local_prefix_is_unrepresentable`. The
            // class-9 link-local allowance is emitted as a literal instead.
            on_link_prefixes: vec![v4([192, 168, 1, 0], 24), v6(0xfd, 0x00, 8)],
        }
    }

    #[test]
    fn ks5_every_v4_rule_has_its_v6_counterpart_in_the_one_inet_table() {
        for ruleset in [Ruleset::Blocked, Ruleset::Protected] {
            let script = render(&contract(1, ruleset), ruleset, &config());
            assert!(script.contains("table inet twinvpn {"));
            // Exactly one table, and it is `inet`. There is no second object to
            // forget, which is the structural half of KS-5.
            assert_eq!(script.matches("table inet twinvpn {").count(), 1);
            assert!(!script.contains("table ip twinvpn"));
            assert!(!script.contains("table ip6 twinvpn"));
            // Both families appear in the Tier-2 drop, in both chains.
            assert_eq!(
                script.matches("counter name \"deny_v4\" drop").count(),
                script.matches("counter name \"deny_v6\" drop").count(),
                "a v4 drop with no v6 counterpart is KS-5 non-conformance"
            );
            assert!(script.contains("ip daddr 100.64.0.0/12"));
            assert!(script.contains("ip6 daddr fd7c::/48"));
        }
    }

    #[test]
    fn ks17_the_swap_is_one_transaction_and_never_a_remove_then_add() {
        let script = render(
            &contract(4, Ruleset::Protected),
            Ruleset::Protected,
            &config(),
        );
        let lines: Vec<&str> = script.lines().collect();
        // `add` before `delete` is what makes the delete safe on first start,
        // and `nft -f` applies the whole file atomically — so there is no
        // instant with no TwinVPN table. KS-23 forbids remove-then-add.
        assert_eq!(lines[0], "add table inet twinvpn");
        assert_eq!(lines[1], "delete table inet twinvpn");
        assert_eq!(lines[2], "table inet twinvpn {");
        assert!(
            !script.contains("flush ruleset"),
            "flushing the whole ruleset would remove other products' tables, \
             which §11.11 forbids"
        );
    }

    #[test]
    fn blocked_permits_no_protected_egress_on_any_interface_including_the_overlay() {
        let script = render(&contract(1, Ruleset::Blocked), Ruleset::Blocked, &config());
        assert!(
            !script.contains("oifname \"twin0\" ip daddr 100.64.0.0/12 accept"),
            "RULESET_BLOCKED is 'no protected egress on ANY interface' (KS-17)"
        );
        assert!(script.contains("ip daddr 100.64.0.0/12 counter name \"deny_v4\" drop"));
        assert!(script.contains("ip6 daddr fd7c::/48 counter name \"deny_v6\" drop"));
    }

    #[test]
    fn protected_permits_the_scope_only_via_the_overlay_and_still_drops_elsewhere() {
        let script = render(
            &contract(1, Ruleset::Protected),
            Ruleset::Protected,
            &config(),
        );
        assert!(script.contains("oifname \"twin0\" ip daddr 100.64.0.0/12 accept"));
        assert!(script.contains("oifname \"twin0\" ip6 daddr fd7c::/48 accept"));
        // Both rulesets are fail-closed. The drop is still there.
        assert!(script.contains("ip daddr 100.64.0.0/12 counter name \"deny_v4\" drop"));
        assert!(script.contains("ip6 daddr fd7c::/48 counter name \"deny_v6\" drop"));
    }

    #[test]
    fn ks2_the_forward_path_gets_no_exemption_at_all() {
        let script = render(
            &contract(1, Ruleset::Protected),
            Ruleset::Protected,
            &config(),
        );
        let forward = script
            .split("chain forward {")
            .nth(1)
            .expect("a forward chain exists");
        assert!(
            !forward.contains("meta mark"),
            "KS-2: forwarded traffic is NEVER eligible for any §11.2 exemption"
        );
        assert!(!forward.contains("cgroupv2"));
        assert!(!forward.contains("udp dport { 67, 68 }"));
        assert!(forward.contains("counter name \"deny_v4\" drop"));
        assert!(forward.contains("counter name \"deny_v6\" drop"));
    }

    #[test]
    fn ks9_uses_both_halves_of_the_linux_predicate_when_the_cgroup_is_known() {
        let script = render(&contract(1, Ruleset::Blocked), Ruleset::Blocked, &config());
        // "cgroup v2 path match AND fwmark set via SO_MARK by the agent" — and,
        // not or, and on one rule so a socket with the mark but the wrong cgroup
        // does not match.
        assert!(script.contains(
            "meta mark 0x7677 socket cgroupv2 level 2 \"system.slice/twinvpnd.service\""
        ));
        assert!(config().ks9_complete());
    }

    #[test]
    fn a_missing_cgroup_weakens_ks9_and_says_so_rather_than_claiming_equivalence() {
        let weaker = EnforcementConfig {
            cgroup_path: None,
            ..config()
        };
        assert!(!weaker.ks9_complete());
        let script = render(&contract(1, Ruleset::Blocked), Ruleset::Blocked, &weaker);
        assert!(script.contains("meta mark 0x7677 meta nfproto ipv4"));
        assert!(!script.contains("cgroupv2"));
    }

    #[test]
    fn ks11_exports_exempt_and_deny_counters_per_family_for_the_canary() {
        let script = render(&contract(1, Ruleset::Blocked), Ruleset::Blocked, &config());
        for (name, _) in EXEMPT_COUNTER {
            assert!(script.contains(&format!("counter {name} {{ }}")), "{name}");
        }
        for (name, _) in DENY_COUNTER {
            assert!(script.contains(&format!("counter {name} {{ }}")), "{name}");
        }
    }

    #[test]
    fn dns_containment_denies_53_and_853_off_the_overlay_for_both_families() {
        // ADR-0011 §11.13(b): one dual-family object, interface-scoped. `meta
        // l4proto { tcp, udp } th dport` matches both families in one rule,
        // which is why there is no v4/v6 pair here to keep in step.
        let script = render(&contract(1, Ruleset::Blocked), Ruleset::Blocked, &config());
        assert!(
            script.contains("oifname != \"twin0\" meta l4proto { tcp, udp } th dport { 53, 853 }")
        );
        // Its own counter, so the per-family canary counters stay symmetric.
        assert!(script.contains("counter name \"deny_dns\" drop"));
        assert!(script.contains("counter deny_dns { }"));
    }

    #[test]
    fn ks4_local_network_access_permits_on_link_prefixes_only_and_can_be_denied() {
        let allow = render(&contract(1, Ruleset::Blocked), Ruleset::Blocked, &config());
        assert!(allow.contains("oifname != \"twin0\" ip daddr 192.168.1.0/24 accept"));
        assert!(allow.contains("oifname != \"twin0\" ip6 daddr fd00::/8 accept"));

        let deny = EnforcementConfig {
            local_network_access: false,
            ..config()
        };
        let script = render(&contract(1, Ruleset::Blocked), Ruleset::Blocked, &deny);
        assert!(!script.contains("ip daddr 192.168.1.0/24 accept"));
        assert!(!script.contains("ip6 daddr fd00::/8 accept"));
        assert!(!script.contains("224.0.0.0/24"), "class 10 follows class 4");
        // The link-local UNICAST allowance of class 9 is not the same rule and
        // stays: blocking ND/RA breaks the underlay itself.
        assert!(script.contains("ip6 daddr fe80::/10 accept"));
    }

    #[test]
    fn the_render_is_deterministic_so_a_reconciler_sees_no_drift_that_is_not_there() {
        let a = render(
            &contract(3, Ruleset::Protected),
            Ruleset::Protected,
            &config(),
        );
        let b = render(
            &contract(3, Ruleset::Protected),
            Ruleset::Protected,
            &config(),
        );
        assert_eq!(a, b);
    }

    #[test]
    fn the_kernel_holds_the_posture_and_the_generation() {
        let script = render(
            &contract(42, Ruleset::Protected),
            Ruleset::Protected,
            &config(),
        );
        assert!(script.contains("counter posture_protected { }"));
        assert!(!script.contains("counter posture_blocked"));
        assert!(script.contains("counter gen_42 { }"));
    }

    // ---- the W-24 read-back ------------------------------------------------

    /// The shape `nft --json list table inet twinvpn` produces, recorded so the
    /// parser is tested on a host with no `nft` — which this one is.
    const NFT_JSON: &str = r#"{"nftables":[
      {"metainfo":{"version":"1.0.9","json_schema_version":1}},
      {"table":{"family":"inet","name":"twinvpn","handle":7}},
      {"counter":{"family":"inet","name":"posture_protected","table":"twinvpn","handle":1,"packets":0,"bytes":0}},
      {"counter":{"family":"inet","name":"gen_42","table":"twinvpn","handle":2,"packets":0,"bytes":0}},
      {"counter":{"family":"inet","name":"deny_v4","table":"twinvpn","handle":3,"packets":11,"bytes":880}},
      {"counter":{"family":"inet","name":"deny_v6","table":"twinvpn","handle":4,"packets":3,"bytes":240}},
      {"chain":{"family":"inet","table":"twinvpn","name":"output","handle":5,"type":"filter","hook":"output","prio":0,"policy":"accept"}}
    ]}"#;

    #[test]
    fn the_protection_assertion_is_a_query_of_the_kernels_own_answer() {
        // W-24: ADR-0015 §11.6 rule 1 requires the assertion to come from
        // querying the enforcement layer, "never of the agent's belief". This
        // parser reads the kernel's JSON; nothing here consults a cached value.
        let installed = parse_installed(NFT_JSON).expect("the table reports a posture");
        assert_eq!(installed.ruleset, Ruleset::Protected);
        assert_eq!(installed.generation, Some(ContractGeneration(42)));
    }

    #[test]
    fn a_counter_in_somebody_elses_table_cannot_dictate_our_posture() {
        let foreign = r#"{"nftables":[
          {"counter":{"family":"inet","name":"posture_protected","table":"someone_else","handle":1}}
        ]}"#;
        assert_eq!(parse_installed(foreign), None);
        let wrong_family = r#"{"nftables":[
          {"counter":{"family":"ip","name":"posture_protected","table":"twinvpn","handle":1}}
        ]}"#;
        assert_eq!(parse_installed(wrong_family), None);
    }

    #[test]
    fn a_table_with_no_posture_counter_is_unknown_and_never_read_as_unprotected() {
        // O-18's fail-safe direction: `None` here becomes UNKNOWN at the
        // indicator, not "no ruleset installed", which is the opposite of the
        // truth and the dangerous direction.
        let bare = r#"{"nftables":[{"table":{"family":"inet","name":"twinvpn","handle":7}}]}"#;
        assert_eq!(parse_installed(bare), None);
        assert_eq!(parse_installed("not json"), None);
        assert_eq!(parse_installed("{}"), None);
    }

    #[test]
    fn a_blocked_posture_reads_back_as_blocked() {
        let blocked = NFT_JSON.replace("posture_protected", "posture_blocked");
        let installed = parse_installed(&blocked).expect("reads back");
        assert_eq!(installed.ruleset, Ruleset::Blocked);
    }

    #[test]
    fn linux_custody_is_declared_truthfully() {
        let c = custody();
        assert!(c.survives_core_exit, "nftables is kernel-resident (CB-6)");
        assert!(
            c.swap_is_atomic,
            "`nft -f` applies a script as one transaction"
        );
    }
}
