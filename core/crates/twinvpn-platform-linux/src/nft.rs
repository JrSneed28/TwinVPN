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
//! [`twinvpn_platform::NetworkConfig::installed_ruleset`] runs
//! `nft --json list table inet twinvpn` and
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
    BootEnforcement, ContractGeneration, EnforcementCustody, NetworkContract, PlatformError,
    Ruleset, RulesetCustody,
};
use twinvpn_types::{AddressFamily, IpPrefix, PerFamily};

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
    /// ADR-0011 §11.9's "known-DoH endpoint list", which the class-6 containment
    /// rule denies on TCP 443 off the overlay.
    ///
    /// **A reported gap, filled from the product's own registry.** The seam's
    /// [`twinvpn_platform::DnsConfig`] carries resolvers, search domains and
    /// split domains, and nothing that names the encrypted-resolver endpoints a
    /// build should deny — so this is injected, exactly as `on_link_prefixes` is,
    /// and exactly as the macOS adapter's field of the same name already was.
    /// The value the shell injects comes from `twinvpn_enforce::doh`, which
    /// parses `contracts/registry/encrypted_resolvers.json`; this adapter does
    /// not choose the list and does not hold a copy of it (CB-2).
    ///
    /// **Additive, never a substitute.** The registry's own `consumer_rule` is
    /// normative: "An enforcement layer MUST treat this list as ADDITIVE to the
    /// port-based denial, never as a substitute for it. An empty or unparseable
    /// list MUST NOT weaken the port rules, and MUST NOT be a reason to fail
    /// open." [`render`] honours that structurally — the 53/853 rule is written
    /// unconditionally, before this field is read at all, so an empty vector
    /// costs the endpoint rules and nothing else.
    ///
    /// **And it is not a guarantee.** The registry states it: "a resolver absent
    /// from this list is not thereby permitted — it is merely not specifically
    /// denied, and the class-6 + Tier-2 default-deny is what actually contains
    /// it." ADR-0011 §11.9 residual 5 is unchanged: "a novel embedded resolver
    /// speaking HTTPS to an arbitrary host is not detectable at this layer."
    pub doh_endpoints: Vec<IpPrefix>,
}

/// The prefix of the scope-cardinality counters: `scope_v4_<n>`, `scope_v6_<n>`.
///
/// **R-6's detector.** The posture counter says which ruleset was *intended*;
/// these say how many prefixes the Tier-2 drop actually covers. Without them a
/// table holding `posture_blocked` and **zero drop rules** reads back as
/// `Blocked` and the reconciler is satisfied — which is exactly the failure
/// review finding R-6 names. With them, "BLOCKED over nothing" is a value
/// [`parse_installed`] returns and a caller can refuse.
pub const SCOPE_PREFIX: [(&str, AddressFamily); 2] = [
    ("scope_v4_", AddressFamily::V4),
    ("scope_v6_", AddressFamily::V6),
];

/// The Tier-1 protected set that is true of **every** TwinVPN host, whatever
/// contract is in force: the overlay address space itself.
///
/// ADR-0010 §11.1 and AP-1 fix both — IPv4 `100.64.0.0/10` (RFC 6598) and the
/// pinned product ULA `fd7c:9e5d:2a10::/48`, "a pinned constant, identical in
/// every build". These are the same two prefixes `packaging/killswitch.nft`
/// carries, and they are a **constant of the product**, not a policy this
/// adapter chose (CB-2).
///
/// # Why a baseline exists at all
///
/// Review finding **R-6**: `set_ruleset(_, Blocked)` used to render a contract
/// with an empty route set, and `emit_scope_drop` is two loops over that set —
/// so it emitted **zero rules**, under `policy accept`, and the script's
/// `delete table` then replaced the real drops a previous `apply` had installed.
/// A "fail-closed" swap that opened the host.
///
/// The baseline makes an empty-scope ruleset **unrepresentable**: every rendered
/// table drops at least the overlay space, in both families.
///
/// **A stated limit, referred rather than resolved.** KS-3a makes the Tier-1
/// protected set *mode-dependent*, and this baseline is only complete for
/// TwinNet-only mode. On a full-tunnel host the protected set is everything, and
/// a baseline of two prefixes under-covers it — which is why the baseline is a
/// **floor beneath a real contract's scope, never a substitute for it**, and why
/// `set_ruleset` re-renders the applied contract rather than this. Referred to
/// ADR-0012's owner as R-7's second half.
#[must_use]
pub fn baseline_protected() -> Vec<IpPrefix> {
    let mut out = Vec::new();
    if let Ok(v4) = IpPrefix::new(
        twinvpn_types::IpAddr::V4(twinvpn_types::V4Addr::from_octets([100, 64, 0, 0])),
        10,
    ) {
        out.push(v4);
    }
    let mut ula = [0u8; 16];
    ula[0] = 0xfd;
    ula[1] = 0x7c;
    ula[2] = 0x9e;
    ula[3] = 0x5d;
    ula[4] = 0x2a;
    ula[5] = 0x10;
    if let Ok(address) = twinvpn_types::V6Addr::new(ula, None) {
        if let Ok(v6) = IpPrefix::new(twinvpn_types::IpAddr::V6(address), 48) {
            out.push(v6);
        }
    }
    out
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

    // **R-6.** A rendered table never drops nothing. An empty family's scope
    // falls back to the product's own address space, so `emit_scope_drop`'s
    // loops always have something to emit and a swap can never replace real
    // drops with none. This is a FLOOR: where the contract names a scope, the
    // contract's scope is what is installed, and the baseline adds nothing.
    for prefix in baseline_protected() {
        match prefix.family() {
            AddressFamily::V4 => {
                if scope_v4.is_empty() {
                    scope_v4.insert(prefix_text(prefix));
                }
            }
            AddressFamily::V6 => {
                if scope_v6.is_empty() {
                    scope_v6.insert(prefix_text(prefix));
                }
            }
        }
    }
    let mut on_link_v4: BTreeSet<String> = BTreeSet::new();
    let mut on_link_v6: BTreeSet<String> = BTreeSet::new();
    for prefix in &config.on_link_prefixes {
        match prefix.family() {
            AddressFamily::V4 => on_link_v4.insert(prefix_text(*prefix)),
            AddressFamily::V6 => on_link_v6.insert(prefix_text(*prefix)),
        };
    }
    // The known-DoH endpoints, split per family, sorted and de-duplicated for the
    // same determinism reason the scope sets are.
    let mut doh_v4: BTreeSet<String> = BTreeSet::new();
    let mut doh_v6: BTreeSet<String> = BTreeSet::new();
    for prefix in &config.doh_endpoints {
        match prefix.family() {
            AddressFamily::V4 => doh_v4.insert(prefix_text(*prefix)),
            AddressFamily::V6 => doh_v6.insert(prefix_text(*prefix)),
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
    // The scope's cardinality, held by the kernel beside the posture — so a
    // read-back can tell `BLOCKED over 4 prefixes` from `BLOCKED over nothing`.
    let _ = writeln!(s, "  counter {}{} {{ }}", SCOPE_PREFIX[0].0, scope_v4.len());
    let _ = writeln!(s, "  counter {}{} {{ }}", SCOPE_PREFIX[1].0, scope_v6.len());

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

    // **X-9.** An on-link prefix inside RFC 6598 shared address space is the
    // host's own underlay path, not its LAN: a subscriber behind CGNAT holds an
    // address in the very `/10` AP-1 carves the overlay out of. It is accepted
    // off the overlay UNCONDITIONALLY, because KS-4's DENY is meant to cost the
    // user their printer and not their internet — and because the overlay's own
    // traffic egresses the overlay interface and is untouched either way.
    // `twinvpn_platform::on_link_is_underlay_path` carries the reasoning, once,
    // for this adapter and `twinvpn-platform-macos` both.
    for prefix in &config.on_link_prefixes {
        if twinvpn_platform::on_link_is_underlay_path(*prefix) {
            let _ = writeln!(
                s,
                "    oifname != \"{overlay}\" ip daddr {} accept",
                prefix_text(*prefix)
            );
        }
    }

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
    //
    // TWO halves, and the ORDER of the two statements below is the registry's
    // `consumer_rule`, not a stylistic choice:
    //
    //   1. The PORT half, written unconditionally. UDP/TCP 53 and TCP/UDP 853
    //      (`th dport` reaches both transports' port field, so DoQ on 853 is
    //      covered with DoT). This is the half that is a constant of the
    //      protocol, and nothing about `config.doh_endpoints` can suppress it —
    //      "an empty or unparseable list MUST NOT weaken the port rules, and
    //      MUST NOT be a reason to fail open."
    //   2. The ENDPOINT half, ADDITIVE to it: TCP 443 to the known-encrypted-
    //      resolver endpoints of `contracts/registry/encrypted_resolvers.json`.
    //      443 cannot be denied wholesale — it is the web — so this half is
    //      necessarily destination-scoped and necessarily incomplete.
    //
    // Until this rule existed, this adapter emitted the port half alone under a
    // comment that named all three, which is the defect F-3 records. The
    // endpoint half is now real, and the comment says only what is installed.
    //
    // **What this does NOT claim.** The registry is "a detection aid, never a
    // guarantee": a resolver it does not name is not permitted, it is merely not
    // specifically denied, and what actually contains such a resolver is class 6
    // plus the Tier-2 default-deny below. ADR-0011 §11.9 residual 5 stands
    // unchanged. This matters most in SPLIT tunnel, where Tier 1 covers only the
    // contract's own routes; in full tunnel the complement-form scope already
    // drops it and the endpoint half is defence in depth.
    //
    // **And a second, narrower limit, stated because it is easy to misread the
    // paragraph above as denying it: the endpoint half is TCP 443 ONLY, so DoH
    // over HTTP/3 — the same endpoints on UDP 443 — is NOT denied by this rule.**
    // The registry's `ports` object names `doh_tcp: 443` and no UDP counterpart,
    // and this renderer deliberately does not invent one: the list and its ports
    // are the contract's, not this adapter's (CB-2). Firefox and Chrome both
    // negotiate HTTP/3 for DoH against endpoints on this list, so in SPLIT tunnel
    // that path is contained by nothing here. Closing it is a change to
    // `contracts/registry/encrypted_resolvers.json` and therefore an ADR-0011
    // owner's, not a line to add here quietly.
    let _ = writeln!(
        s,
        "    oifname != \"{overlay}\" meta l4proto {{ tcp, udp }} th dport {{ 53, 853 }} \
         counter name \"{DNS_DENY_COUNTER}\" drop"
    );
    // Both families or neither: `twinvpn_enforce::doh` refuses a registry that
    // covers only one, so a config carrying a v4 endpoint and no v6 one is not a
    // shape the supported path can produce — KS-5 held by the producer rather
    // than re-checked here. The port `443` is the registry's own `ports.doh_tcp`.
    if !doh_v4.is_empty() {
        let _ = writeln!(
            s,
            "    oifname != \"{overlay}\" ip daddr {{ {} }} tcp dport 443 \
             counter name \"{DNS_DENY_COUNTER}\" drop",
            doh_v4.iter().cloned().collect::<Vec<_>>().join(", ")
        );
    }
    if !doh_v6.is_empty() {
        let _ = writeln!(
            s,
            "    oifname != \"{overlay}\" ip6 daddr {{ {} }} tcp dport 443 \
             counter name \"{DNS_DENY_COUNTER}\" drop",
            doh_v6.iter().cloned().collect::<Vec<_>>().join(", ")
        );
    }

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
    /// How many prefixes the Tier-2 drop covers, per family.
    ///
    /// **R-6.** A posture counter records what was *intended*; this records what
    /// the rules actually cover. `PerFamily::new(0, 0)` alongside
    /// `Ruleset::Blocked` is a table that claims to be fail-closed and drops
    /// nothing — the exact state review finding R-6 named, now a **value** a
    /// caller can see rather than an invisible one.
    pub scope: PerFamily<usize>,
}

impl Installed {
    /// Whether the installed rules actually cover anything, in **both**
    /// families.
    ///
    /// KS-5: "an implementation that can install the Tier-2 rule set for one
    /// family without the other is **non-conforming**, not degraded". So this is
    /// an `&&`, not an `||` — one family covered and the other not is `false`.
    #[must_use]
    pub const fn covers_a_scope(&self) -> bool {
        self.scope.v4 > 0 && self.scope.v6 > 0
    }
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
    let mut scope = PerFamily::new(0usize, 0usize);
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
                for (prefix, family) in SCOPE_PREFIX {
                    if let Some(digits) = other.strip_prefix(prefix) {
                        if let Ok(n) = digits.parse::<usize>() {
                            *scope.get_mut(family) = n;
                        }
                    }
                }
            }
        }
    }
    ruleset.map(|ruleset| Installed {
        ruleset,
        generation,
        scope,
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
        ruleset_custody: RulesetCustody::OsHeld,
        swap_is_atomic: true,
        // ADR-0012 §11.6's Linux boot row: `twinvpn-killswitch.service`,
        // `Before=network-pre.target`, restoring `/etc/twinvpn/killswitch.nft`.
        // The artifact is **package-owned** and the unit loads it before the
        // network stack, so the deny predates the first packet the host can emit
        // (KS-19) — but it is loaded by the supervisor rather than held by the
        // kernel from power-on, which is Windows' stronger answer.
        //
        // §11.6's own Linux residual is "single-user/emergency targets do not
        // reach the unit". That is NOT `ExemptBootModes`: the disclosure column
        // states why — "single-user brings up no network by default" — so there
        // is no interval in which this host can emit a packet with no rule set.
        // macOS's Recovery does have a network, which is why its row is the
        // other value.
        boot_enforcement: BootEnforcement::PackageArtifactLoadedAtBoot,
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
    use twinvpn_types::{InterfaceAddress, IpAddr, PerFamily, V4Addr, V6Addr};

    fn v4(a: [u8; 4], len: u32) -> IpPrefix {
        IpPrefix::new(IpAddr::V4(V4Addr::from_octets(a)), len).expect("canonical")
    }

    fn v6(first: u8, second: u8, len: u32) -> IpPrefix {
        let mut o = [0u8; 16];
        o[0] = first;
        o[1] = second;
        IpPrefix::new(IpAddr::V6(V6Addr::new(o, None).expect("valid")), len).expect("canonical")
    }

    fn iface_v4(a: [u8; 4], len: u32) -> InterfaceAddress {
        InterfaceAddress::new(IpAddr::V4(V4Addr::from_octets(a)), len).expect("valid")
    }

    fn iface_v6(first: u8, second: u8, len: u32) -> InterfaceAddress {
        let mut o = [0u8; 16];
        o[0] = first;
        o[1] = second;
        InterfaceAddress::new(IpAddr::V6(V6Addr::new(o, None).expect("valid")), len).expect("valid")
    }

    fn contract(generation: u64, ruleset: Ruleset) -> NetworkContract {
        NetworkContract {
            generation: ContractGeneration(generation),
            addresses: PerFamily::new(
                vec![iface_v4([100, 64, 0, 1], 32)],
                vec![iface_v6(0xfd, 0x7c, 128)],
            ),
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
            tunnel_remote_address: None,
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
            // THE REAL ARTIFACT, not a hand-written stand-in. A fixture list
            // here would let `contracts/registry/encrypted_resolvers.json` gain
            // a provider that no rule ever denies, and the test would still be
            // green -- which is the shape of the defect F-3 records.
            doh_endpoints: registry().endpoints(),
        }
    }

    /// The product's own encrypted-resolver registry, parsed by the one shared
    /// consumer every platform reads.
    ///
    /// `twinvpn-enforce` is a DEV-dependency of this crate and not a dependency:
    /// the adapter takes the list injected (CD-2) and holds no copy of it, so the
    /// production crate graph is unchanged. The test reaches for the consumer
    /// because asserting against the registry's real contents is the only way to
    /// prove that what is denied is what ships.
    fn registry() -> twinvpn_enforce::doh::KnownResolvers {
        twinvpn_enforce::doh::KnownResolvers::embedded().expect("the shipped registry parses")
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

    /// A split-tunnel contract: only the TwinNet's own prefixes are protected.
    ///
    /// The default fixture already is one; naming it makes the DoH tests below
    /// say which routing mode they are about, which is the whole distinction
    /// F-3 turns on.
    fn split_tunnel(generation: u64, ruleset: Ruleset) -> NetworkContract {
        contract(generation, ruleset)
    }

    /// A full-tunnel contract: ADR-0012 §11.1's complement form, which reaches
    /// this adapter as `docs/networking.md` §7.2's four `/1` routes.
    fn full_tunnel(generation: u64, ruleset: Ruleset) -> NetworkContract {
        let route = |destination| RouteEntry {
            destination,
            via: None,
            interface: twinvpn_platform::InterfaceIndex(9),
            metric: None,
        };
        NetworkContract {
            routes: PerFamily::new(
                vec![route(v4([0, 0, 0, 0], 1)), route(v4([128, 0, 0, 0], 1))],
                vec![route(v6(0x00, 0x00, 1)), route(v6(0x80, 0x00, 1))],
            ),
            ..contract(generation, ruleset)
        }
    }

    /// The rendered class-6 endpoint rules, v4 and v6.
    fn doh_rules(script: &str) -> (Vec<&str>, Vec<&str>) {
        let v4_rules = script
            .lines()
            .filter(|l| l.contains(" ip daddr ") && l.contains("tcp dport 443"))
            .collect();
        let v6_rules = script
            .lines()
            .filter(|l| l.contains(" ip6 daddr ") && l.contains("tcp dport 443"))
            .collect();
        (v4_rules, v6_rules)
    }

    /// **F-3, the exposed case.** In SPLIT tunnel Tier 1 protects only the
    /// contract's own prefixes, so a browser with a pinned DoH resolver reaches
    /// `1.1.1.1:443` off-overlay with nothing in its way — unless class 6 denies
    /// the endpoint. This asserts that it now does, in BOTH families, against the
    /// shipped registry's real contents rather than a fixture that could drift
    /// from it.
    #[test]
    fn split_tunnel_denies_the_known_doh_endpoints_in_both_families() {
        for ruleset in [Ruleset::Blocked, Ruleset::Protected] {
            let script = render(&split_tunnel(1, ruleset), ruleset, &config());

            // The precondition that makes this test mean anything: Tier 1 here
            // does NOT cover the public internet, so the endpoint rule is the
            // only thing between this host and an off-tunnel DoH resolution.
            assert!(
                !script.contains("ip daddr 0.0.0.0/1"),
                "this fixture must be split tunnel, or the test proves nothing"
            );

            let (v4_rules, v6_rules) = doh_rules(&script);
            assert_eq!(v4_rules.len(), 1, "one dual-family pair, v4 half");
            assert_eq!(v6_rules.len(), 1, "one dual-family pair, v6 half");
            for rule in v4_rules.iter().chain(&v6_rules) {
                assert!(rule.starts_with("    oifname != \"twin0\" "), "{rule}");
                assert!(rule.ends_with("counter name \"deny_dns\" drop"), "{rule}");
            }
            // Every endpoint the shipped registry names, in the family it names
            // it in. A provider added to the artifact and not to the rule fails
            // here rather than shipping as a silent hole.
            let per_family = registry().per_family();
            for prefix in &per_family.v4 {
                assert!(
                    v4_rules[0].contains(&prefix_text(*prefix)),
                    "{} is missing from the v4 endpoint rule",
                    prefix_text(*prefix)
                );
            }
            for prefix in &per_family.v6 {
                assert!(
                    v6_rules[0].contains(&prefix_text(*prefix)),
                    "{} is missing from the v6 endpoint rule",
                    prefix_text(*prefix)
                );
            }
            // Two named providers, spelled out, so the test reads as a claim
            // about behaviour and not only as a loop over an artifact.
            assert!(v4_rules[0].contains("1.1.1.1/32"));
            assert!(v6_rules[0].contains("2606:4700:4700::1111/128"));
        }
    }

    /// **F-3, the already-contained case, kept contained.** Full tunnel drops
    /// everything at Tier 1 anyway; the endpoint rules are defence in depth and
    /// must still be installed, because the difference between the two routing
    /// modes is the contract's route set and never the containment object.
    #[test]
    fn full_tunnel_carries_the_same_doh_endpoint_rules() {
        let script = render(
            &full_tunnel(2, Ruleset::Protected),
            Ruleset::Protected,
            &config(),
        );
        // Tier 1 here really is the complement form, in both families.
        assert!(script.contains("ip daddr 0.0.0.0/1 counter name \"deny_v4\" drop"));
        assert!(script.contains("ip6 daddr ::/1 counter name \"deny_v6\" drop"));

        let (v4_rules, v6_rules) = doh_rules(&script);
        assert_eq!(v4_rules.len(), 1);
        assert_eq!(v6_rules.len(), 1);
        assert!(v4_rules[0].contains("1.1.1.1/32"));
        assert!(v6_rules[0].contains("2606:4700:4700::1111/128"));

        // And the two modes render the SAME class-6 object, which is what makes
        // "split tunnel was the exposed case" a statement about Tier 1 and not
        // about DNS containment.
        let split = render(
            &split_tunnel(2, Ruleset::Protected),
            Ruleset::Protected,
            &config(),
        );
        assert_eq!(doh_rules(&split), (v4_rules, v6_rules));
    }

    /// The registry's `consumer_rule`, verbatim: "ADDITIVE to the port-based
    /// denial, never as a substitute for it."
    #[test]
    fn the_doh_rules_are_additive_to_the_port_rule_and_never_replace_it() {
        let script = render(
            &split_tunnel(1, Ruleset::Protected),
            Ruleset::Protected,
            &config(),
        );
        let port_rule = script
            .lines()
            .position(|l| l.contains("th dport { 53, 853 }"))
            .expect("the port half is written unconditionally");
        let first_endpoint_rule = script
            .lines()
            .position(|l| l.contains("tcp dport 443"))
            .expect("the endpoint half is written too");
        assert!(
            port_rule < first_endpoint_rule,
            "the port denial is the base; the endpoint denial is added on top"
        );
    }

    /// "An empty or unparseable list MUST NOT weaken the port rules, and MUST
    /// NOT be a reason to fail open."
    ///
    /// An empty list cannot arise from `twinvpn_enforce::doh`, which refuses
    /// one — but the field is a plain `Vec`, so what the renderer does with an
    /// empty one is asserted rather than assumed.
    #[test]
    fn an_empty_doh_list_leaves_the_port_rule_and_tier_2_fully_intact() {
        let empty = EnforcementConfig {
            doh_endpoints: Vec::new(),
            ..config()
        };
        let script = render(
            &split_tunnel(1, Ruleset::Protected),
            Ruleset::Protected,
            &empty,
        );
        assert!(
            script.contains(
                "oifname != \"twin0\" meta l4proto { tcp, udp } th dport { 53, 853 } \
                 counter name \"deny_dns\" drop"
            ),
            "the port half is untouched by an empty endpoint list"
        );
        assert!(script.contains("counter deny_dns { }"));
        assert_eq!(doh_rules(&script), (Vec::new(), Vec::new()));
        // Tier 2 is likewise untouched: an absent list is never a fail-open.
        assert!(script.contains("ip daddr 100.64.0.0/12 counter name \"deny_v4\" drop"));
        assert!(script.contains("ip6 daddr fd7c::/48 counter name \"deny_v6\" drop"));

        // And the ONLY difference between the two renders is the endpoint rules.
        let populated = render(
            &split_tunnel(1, Ruleset::Protected),
            Ruleset::Protected,
            &config(),
        );
        let stripped: Vec<&str> = populated
            .lines()
            .filter(|l| !l.contains("tcp dport 443"))
            .collect();
        assert_eq!(stripped, script.lines().collect::<Vec<_>>());
    }

    /// KS-5 over the endpoint half: a v4 rule with no v6 counterpart is
    /// non-conformance, not degradation.
    #[test]
    fn ks5_the_doh_endpoint_rules_are_emitted_as_a_pair() {
        for ruleset in [Ruleset::Blocked, Ruleset::Protected] {
            let script = render(&split_tunnel(1, ruleset), ruleset, &config());
            let (v4_rules, v6_rules) = doh_rules(&script);
            assert_eq!(
                v4_rules.len(),
                v6_rules.len(),
                "a v4 endpoint rule with no v6 counterpart is KS-5 non-conformance"
            );
        }
    }

    #[test]
    fn x9_a_cgnat_underlay_prefix_is_passed_even_when_ks4_denies_the_lan() {
        // **X-9.** A subscriber behind CGNAT holds an on-link address inside the
        // very RFC 6598 /10 the Tier-1 baseline protects. Denying it does not
        // protect anything — the overlay's own traffic leaves by the overlay
        // interface either way — it only severs the underlay, which is the same
        // argument ADR-0010 §11.5 clause 5 makes for DHCP.
        let deny = EnforcementConfig {
            local_network_access: false,
            on_link_prefixes: vec![v4([100, 96, 0, 0], 12), v4([192, 168, 1, 0], 24)],
            ..config()
        };
        let script = render(&contract(1, Ruleset::Blocked), Ruleset::Blocked, &deny);
        assert!(
            script.contains("oifname != \"twin0\" ip daddr 100.96.0.0/12 accept"),
            "the underlay path is passed off-overlay regardless of KS-4"
        );
        // And KS-4 is NOT widened: the ordinary LAN is still denied.
        assert!(
            !script.contains("oifname != \"twin0\" ip daddr 192.168.1.0/24 accept"),
            "KS-4 still costs the user their printer when they ask it to"
        );
        // The overlay space is still dropped off-overlay for everything else.
        assert!(script.contains("counter name \"deny_v4\" drop"));
    }

    #[test]
    fn x9_does_not_pass_the_overlay_space_out_of_the_overlay_interface() {
        // The exemption is scoped to a prefix the HOST holds on a non-overlay
        // interface, and it is `oifname != overlay`. A peer at 100.64.0.7 is
        // still reached through the tunnel and nowhere else.
        let deny = EnforcementConfig {
            local_network_access: false,
            on_link_prefixes: vec![v4([100, 96, 0, 0], 12)],
            ..config()
        };
        let script = render(&contract(1, Ruleset::Blocked), Ruleset::Blocked, &deny);
        for line in script.lines().filter(|l| l.contains("100.96.0.0/12")) {
            assert!(
                line.contains("oifname != \"twin0\""),
                "every X-9 rule is off-overlay: {line}"
            );
        }
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

    /// **R-6, at the renderer.** No contract, in any posture, renders a table
    /// that drops nothing.
    #[test]
    fn no_rendered_table_ever_drops_nothing() {
        let empty = NetworkContract {
            routes: PerFamily::new(Vec::new(), Vec::new()),
            ..contract(1, Ruleset::Blocked)
        };
        for ruleset in [Ruleset::Blocked, Ruleset::Protected] {
            let script = render(&empty, ruleset, &config());
            assert!(
                script.contains("counter name \"deny_v4\" drop"),
                "an empty v4 scope rendered zero drop rules under `policy accept` \
                 — and the script's `delete table` would replace the real ones"
            );
            assert!(script.contains("counter name \"deny_v6\" drop"));
            // The baseline is the product's own address space, both families.
            assert!(script.contains("ip daddr 100.64.0.0/10"));
            assert!(script.contains("ip6 daddr fd7c:9e5d:2a10::/48"));
        }
    }

    #[test]
    fn the_baseline_is_a_floor_and_never_replaces_a_real_scope() {
        // Where the contract names a scope, the CONTRACT's scope is installed
        // and the baseline adds nothing — otherwise a full-tunnel host would be
        // silently narrowed to the overlay space.
        let script = render(&contract(1, Ruleset::Blocked), Ruleset::Blocked, &config());
        assert!(script.contains("ip daddr 100.64.0.0/12 counter name \"deny_v4\" drop"));
        assert!(
            !script.contains("ip daddr 100.64.0.0/10"),
            "the baseline must not be added beside a real scope"
        );
        assert!(script.contains("counter scope_v4_1 { }"));
    }

    #[test]
    fn the_baseline_is_the_same_pair_the_boot_artifact_carries() {
        // `packaging/killswitch.nft` drops exactly these two, and a divergence
        // between the boot table and the first arm would be a window.
        let text: Vec<String> = baseline_protected()
            .into_iter()
            .map(crate::addr::prefix_text)
            .collect();
        assert_eq!(
            text,
            vec!["100.64.0.0/10".to_owned(), "fd7c:9e5d:2a10::/48".to_owned()]
        );
    }

    /// **R-6's detector.** `BLOCKED` over nothing is now a value, not silence.
    #[test]
    fn a_read_back_reports_the_scope_cardinality_so_blocked_over_nothing_is_visible() {
        let hollow = r#"{"nftables":[
          {"counter":{"family":"inet","name":"posture_blocked","table":"twinvpn","handle":1}},
          {"counter":{"family":"inet","name":"scope_v4_0","table":"twinvpn","handle":2}},
          {"counter":{"family":"inet","name":"scope_v6_0","table":"twinvpn","handle":3}}
        ]}"#;
        let installed = parse_installed(hollow).expect("a posture is reported");
        assert_eq!(installed.ruleset, Ruleset::Blocked);
        assert_eq!(installed.scope, PerFamily::new(0, 0));
        assert!(
            !installed.covers_a_scope(),
            "a table claiming BLOCKED while dropping nothing must be detectable"
        );

        let real = hollow
            .replace("scope_v4_0", "scope_v4_4")
            .replace("scope_v6_0", "scope_v6_4");
        let installed = parse_installed(&real).expect("reads");
        assert_eq!(installed.scope, PerFamily::new(4, 4));
        assert!(installed.covers_a_scope());
    }

    #[test]
    fn ks5_one_family_covered_and_the_other_not_is_non_conforming_not_degraded() {
        let lopsided = r#"{"nftables":[
          {"counter":{"family":"inet","name":"posture_protected","table":"twinvpn","handle":1}},
          {"counter":{"family":"inet","name":"scope_v4_4","table":"twinvpn","handle":2}},
          {"counter":{"family":"inet","name":"scope_v6_0","table":"twinvpn","handle":3}}
        ]}"#;
        let installed = parse_installed(lopsided).expect("reads");
        assert!(
            !installed.covers_a_scope(),
            "KS-5: v4 protected and v6 not is NON-CONFORMING, and must not read \
             as covered"
        );
    }

    #[test]
    fn linux_custody_is_declared_truthfully() {
        let c = custody();
        assert!(c.survives_core_exit(), "nftables is kernel-resident (CB-6)");
        assert!(
            c.swap_is_atomic,
            "`nft -f` applies a script as one transaction"
        );
    }
}
