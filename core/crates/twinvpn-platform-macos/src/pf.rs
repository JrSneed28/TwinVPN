//! The `pf` anchor: **the core computes, the adapter installs, the OS holds**
//! (CB-6).
//!
//! **Authority:** ADR-0012 §11.1 (the two-tier model), §11.2 (the traffic-class
//! table, reproduced as the rule order below), §11.3 KS-5, §11.5 KS-9…KS-12 (the
//! bootstrap exemption), §11.6 (the macOS row: "`pf` anchor `twinvpn` (both
//! families)"), §11.8 KS-17/KS-18/KS-23, §11.9 (the leak canary), §11.11
//! (coexistence); ADR-0010 §11.5 clause 1 (**one object, both families**);
//! ADR-0011 §11.9 (the macOS containment row: "`pf` anchor `twinvpn`, both
//! families, denying 53/853/known-DoH off-overlay"); ADR-0016 §11.5 (owner-tagged,
//! reclaimed not recreated, `/etc/twinvpn/pf.anchor` referenced from
//! `/etc/pf.conf`).
//!
//! # A pure function, so the ruleset is a checked property
//!
//! [`render`] does no I/O, reads no clock and touches no ambient state, so every
//! assertion about what the anchor denies runs under `cargo test` **on this Linux
//! host, with no `pfctl` present** — exactly as the Linux adapter tests its
//! nftables text. `tests/leaks.rs` is where the family-by-family assertions live.
//!
//! # KS-5, made structural rather than disciplinary
//!
//! > An implementation that can install the Tier-2 rule set for one family
//! > without the other is **non-conforming**, not degraded.
//!
//! [`emit_scope`] is the only function that writes a Tier-2 rule and it writes
//! **both families or neither**. There is no call site that can emit the v4 half
//! without the v6 half, because there is no separate v6 emitter to forget.
//!
//! # The permitted classes are ADR-0012 §11.2's, and **only** those
//!
//! Every `pass` this module can emit carries a label from a closed set, and each
//! label names one row of ADR-0012 §11.2's traffic-class table. `tests/leaks.rs`
//! asserts the set equality in both directions: no rendered rule exists that the
//! table does not authorise, and no authorised class is silently absent. That is
//! KS-6's "every permitted exception MUST be enumerated" as a checked property.
//!
//! **A qualifier that was tried and is deliberately absent.** An earlier draft
//! added `to ! <tv_scope4>` to classes 5, 9, 4 and 10, so that no permitted class
//! could ever cover a destination inside the Tier-1 scope. It is wrong. In
//! full-tunnel mode the Tier-1 scope arrives as the four `/1` routes, which
//! contain `169.254.0.0/16`, `fe80::/10`, the DHCP server's address and the
//! on-link LAN prefix — so the qualifier would have blocked DHCP renewal, ND and
//! RA, which is precisely the failure ADR-0010 §11.5 clause 5 names ("blocking
//! them breaks the underlay itself"), and would have made `local_network_access =
//! ALLOW` behave as `DENY`. The classes are permitted because §11.2 permits them;
//! their safety is KS-4's on-link-only restriction and the fact that link-local
//! is not routable off-link, not a scope exclusion this adapter invented.
//!
//! # KS-17: two rulesets, never zero
//!
//! The whole anchor is replaced in **one `pfctl -a twinvpn -f -` load**, which pf
//! applies as a single transaction — so there is no instant at which the host
//! has our anchor half-populated. A flush-then-load in two invocations would open
//! exactly the window KS-17 exists to close, and remove-then-add is what KS-23
//! forbids on update.
//!
//! # W-24 on this platform: the posture is held by the kernel, not by us
//!
//! pf has no named counters, so the posture, the contract generation and the
//! scope cardinality are carried as **`persist` tables** in our own anchor.
//! Tables are objects `pfctl -a twinvpn -s Tables` reports structurally, they
//! survive a core crash (CB-6), they go with the anchor on uninstall, and they
//! are readable by a privileged local unblock command with the authority absent
//! (KS-20a). [`crate::pfread`] parses them; nothing is cached.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use twinvpn_platform::{
    BootEnforcement, EnforcementCustody, NetworkContract, Ruleset, RulesetCustody,
};
use twinvpn_types::{AddressFamily, IpPrefix};

use crate::addr::prefix_text;

/// The one owned anchor. ADR-0012 §11.6's macOS row, verbatim.
pub const ANCHOR: &str = "twinvpn";

/// Where the **package** installs the boot-time anchor body. ADR-0016 §11.5's
/// macOS row. PS-7: package-owned; the authority never rewrites it.
pub const ANCHOR_FILE: &str = "/etc/twinvpn/pf.anchor";

/// The `pf` table-name budget. `PF_TABLE_NAME_SIZE` is 32 in `<net/pfvar.h>`,
/// including the terminating NUL, so a name may be at most 31 bytes.
pub const MAX_TABLE_NAME: usize = 31;

/// The Tier-1 protected scope, held as two tables so the drop rules name a table
/// rather than repeating a prefix list.
pub const SCOPE_TABLE: [(&str, AddressFamily); 2] = [
    ("tv_scope4", AddressFamily::V4),
    ("tv_scope6", AddressFamily::V6),
];

/// The on-link prefixes of the non-overlay interfaces (KS-4).
pub const ONLINK_TABLE: [(&str, AddressFamily); 2] = [
    ("tv_onlink4", AddressFamily::V4),
    ("tv_onlink6", AddressFamily::V6),
];

/// The known-DoH endpoints ADR-0011 §11.9 requires the containment rule to deny.
pub const DOH_TABLE: [(&str, AddressFamily); 2] = [
    ("tv_doh4", AddressFamily::V4),
    ("tv_doh6", AddressFamily::V6),
];

/// The captive-portal grant tables of KS-15 — "a `pf` table entry with expiry
/// sweep". Declared `persist` and **empty**; the ≤300 s sweep is the authority's,
/// and no rule here references them until a grant is live.
pub const PORTAL_TABLE: [(&str, AddressFamily); 2] = [
    ("tv_portal4", AddressFamily::V4),
    ("tv_portal6", AddressFamily::V6),
];

/// The marker table whose presence means `RULESET_BLOCKED` is installed.
pub const POSTURE_BLOCKED: &str = "tv_posture_blocked";

/// The marker table whose presence means `RULESET_PROTECTED` is installed.
pub const POSTURE_PROTECTED: &str = "tv_posture_protected";

/// The prefix of the generation marker table: `tv_gen_<decimal>`.
pub const GENERATION_PREFIX: &str = "tv_gen_";

/// The prefixes of the scope-cardinality marker tables, per family.
///
/// The posture table says which ruleset was *intended*; these say how many
/// prefixes the Tier-2 drop actually covers. Without them an anchor holding
/// `tv_posture_blocked` and an **empty** scope table reads back as `Blocked` and a
/// reconciler is satisfied — which is the failure the Linux adapter's review
/// finding R-6 named. With them, "BLOCKED over nothing" is a value
/// [`crate::pfread::parse_tables`] returns and a caller can refuse.
pub const SCOPE_COUNT_PREFIX: [(&str, AddressFamily); 2] = [
    ("tv_scope4_n", AddressFamily::V4),
    ("tv_scope6_n", AddressFamily::V6),
];

/// The `label` on the Tier-2 drop, per family — the leak canary's counter
/// (ADR-0012 §11.9). Two labels, because the canary runs per family and a single
/// combined counter would let a v6 leak hide behind v4 drops.
pub const DENY_LABEL: [(&str, AddressFamily); 2] = [
    ("twinvpn.deny.v4", AddressFamily::V4),
    ("twinvpn.deny.v6", AddressFamily::V6),
];

/// The `label` on the bootstrap exemption, per family — KS-11's requirement that
/// "the enforcement layer MUST export byte and packet counters for the exempt
/// rule, per family".
pub const EXEMPT_LABEL: [(&str, AddressFamily); 2] = [
    ("twinvpn.exempt.v4", AddressFamily::V4),
    ("twinvpn.exempt.v6", AddressFamily::V6),
];

/// The DNS containment counter (ADR-0011 §11.12's negative canary).
///
/// Its own label and not one of [`DENY_LABEL`]'s: the containment rule is
/// genuinely dual-family in one pf expression, so charging it to `twinvpn.deny.v4`
/// would make the two per-family canary counters asymmetric for a reason that has
/// nothing to do with a leak — and the question it answers ("was my off-tunnel
/// DNS query dropped") is not the question ADR-0012's canary answers.
pub const DNS_DENY_LABEL: &str = "twinvpn.deny.dns";

/// How KS-9(1)'s macOS predicate is satisfiable in this installation.
///
/// > **KS-9(1), macOS:** "`pf` anchor keyed to the tunnel provider's owning uid
/// > **plus the provider's socket set**."
///
/// pf has no primitive that matches a *registered socket set*: `user` and `group`
/// are the only socket-derived selectors its rule language offers. So the second
/// half of the predicate is not expressible in the anchor, and this enum records
/// which of the two shapes an installation actually has rather than presenting
/// them as equivalent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExemptPredicate {
    /// The NE **system extension** path. The uid is matched in the anchor and the
    /// socket-set half is supplied by the NE runtime, which excludes the
    /// provider's own sockets from the tunnel it is serving. Both halves of
    /// KS-9(1) hold, by two different mechanisms.
    ProviderUidAndSocketSet {
        /// The provider's owning uid.
        uid: u32,
    },
    /// The bare `LaunchDaemon` path. There is no NE runtime, so the exemption
    /// rests on the uid **alone**. That is **weaker** than KS-9(1) specifies and
    /// [`EnforcementConfig::ks9_complete`] reports it rather than hiding it.
    UidOnly {
        /// The daemon's owning uid.
        uid: u32,
    },
}

impl ExemptPredicate {
    /// The uid the anchor matches on.
    #[must_use]
    pub const fn uid(self) -> u32 {
        match self {
            ExemptPredicate::ProviderUidAndSocketSet { uid } | ExemptPredicate::UidOnly { uid } => {
                uid
            }
        }
    }
}

/// What the adapter needs that the seam does not carry.
///
/// **Each field here is a reported gap, not a decision this adapter made up.**
/// [`NetworkContract`] carries addresses, routes, DNS, the ruleset selector and
/// the MTU — and nothing that names the authority's own uid, the KS-4
/// `local_network_access` setting, or ADR-0011's known-DoH list. Those are facts
/// the shell knows about its own process and its own installation, so they are
/// injected at construction (CD-2) rather than discovered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcementConfig {
    /// The overlay interface name. Tier 2 is **interface-scoped**, so this is the
    /// one name the whole ruleset turns on.
    pub overlay_interface: String,
    /// How KS-9(1) is satisfiable here.
    pub exempt: ExemptPredicate,
    /// Whether ADR-0012 KS-4's `local_network_access` is `ALLOW` (its default in
    /// all three routing modes).
    pub local_network_access: bool,
    /// The on-link prefixes of the non-overlay interfaces.
    ///
    /// KS-4: "the permitted set is *on-link prefixes only*, recomputed on every
    /// network-change event, and never includes a destination reachable only via
    /// a router."
    pub on_link_prefixes: Vec<IpPrefix>,
    /// ADR-0011 §11.9's "known-DoH endpoint list", which the containment rule
    /// denies on port 443 off-overlay.
    ///
    /// **A reported gap:** the seam's [`twinvpn_platform::DnsConfig`] carries
    /// resolvers, search domains and split domains, and nothing that names the
    /// DoH endpoints a build should deny. Injected, so the list is the shell's
    /// installation fact and never this adapter's invention.
    pub doh_endpoints: Vec<IpPrefix>,
}

impl EnforcementConfig {
    /// Whether KS-9(1)'s macOS predicate is satisfiable **in full** as configured.
    ///
    /// `false` means the bootstrap exemption rests on the uid alone. That is a
    /// weaker predicate than KS-9 specifies; the shell reports it, and it is not
    /// silently upgraded to "close enough".
    #[must_use]
    pub const fn ks9_complete(&self) -> bool {
        matches!(self.exempt, ExemptPredicate::ProviderUidAndSocketSet { .. })
    }
}

/// The Tier-1 protected set that is true of **every** TwinVPN host, whatever
/// contract is in force: the overlay address space itself.
///
/// ADR-0010 §11.1 and AP-1 fix both — IPv4 `100.64.0.0/10` (RFC 6598) and the
/// pinned product ULA `fd7c:9e5d:2a10::/48`, "a pinned constant, identical in
/// every build". A **constant of the product**, not a policy this adapter chose
/// (CB-2), and the same two prefixes the package-owned boot anchor carries.
///
/// # Why a baseline exists at all
///
/// It makes an empty-scope ruleset **unrepresentable**: every rendered anchor
/// drops at least the overlay space, in both families, so a posture swap can
/// never replace real drops with none.
///
/// **A stated limit, referred rather than resolved.** KS-3a makes the Tier-1
/// protected set *mode-dependent*, and this baseline is only complete for
/// TwinNet-only mode. On a full-tunnel host the protected set is everything, and
/// a baseline of two prefixes under-covers it — which is why the baseline is a
/// **floor beneath a real contract's scope, never a substitute for it**, and why
/// [`crate::netcfg`]'s posture swap re-renders the applied contract rather than
/// this.
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

/// The scope a contract puts in force, per family, with the baseline as a floor.
///
/// Sorted and de-duplicated, so two renders of one contract produce identical
/// bytes: a reconciler comparing them must not see drift that is not there.
fn scopes(contract: &NetworkContract) -> [BTreeSet<String>; 2] {
    let mut v4: BTreeSet<String> = contract
        .routes
        .v4
        .iter()
        .map(|r| prefix_text(r.destination))
        .collect();
    let mut v6: BTreeSet<String> = contract
        .routes
        .v6
        .iter()
        .map(|r| prefix_text(r.destination))
        .collect();
    for prefix in baseline_protected() {
        match prefix.family() {
            AddressFamily::V4 => {
                if v4.is_empty() {
                    v4.insert(prefix_text(prefix));
                }
            }
            AddressFamily::V6 => {
                if v6.is_empty() {
                    v6.insert(prefix_text(prefix));
                }
            }
        }
    }
    [v4, v6]
}

/// Splits the injected prefixes into a per-family pair of sorted sets.
fn per_family(prefixes: &[IpPrefix]) -> [BTreeSet<String>; 2] {
    let mut v4 = BTreeSet::new();
    let mut v6 = BTreeSet::new();
    for prefix in prefixes {
        match prefix.family() {
            AddressFamily::V4 => v4.insert(prefix_text(*prefix)),
            AddressFamily::V6 => v6.insert(prefix_text(*prefix)),
        };
    }
    [v4, v6]
}

/// Writes one `persist` table, with its members if it has any.
fn emit_table(s: &mut String, name: &str, members: &BTreeSet<String>) {
    if members.is_empty() {
        // `persist` is what keeps an empty or unreferenced table loaded. Without
        // it pf discards a table nothing names, and the marker tables — which
        // deliberately have no members and no references — would vanish, taking
        // the read-back's answer with them.
        let _ = writeln!(s, "table <{name}> persist");
    } else {
        let joined: Vec<&str> = members.iter().map(String::as_str).collect();
        let _ = writeln!(s, "table <{name}> persist {{ {} }}", joined.join(", "));
    }
}

/// The desired anchor body, as text for `pfctl -a twinvpn -f -`.
///
/// # CB-2: nothing here is a decision
///
/// The Tier-1 protected scope is taken **verbatim from the contract's route
/// destinations**. That is not this adapter choosing a scope: `twinvpn-route`
/// computes which destinations go through the overlay, and ADR-0012 §11.1's three
/// routing modes are already expressed in that set — full tunnel arrives as the
/// four `/1` routes of `docs/networking.md` §7.2, which *is* §11.1's complement
/// form. This function translates; it does not decide.
#[must_use]
pub fn render(contract: &NetworkContract, ruleset: Ruleset, config: &EnforcementConfig) -> String {
    let overlay = &config.overlay_interface;
    let uid = config.exempt.uid();
    let [scope4, scope6] = scopes(contract);
    let [onlink4, onlink6] = per_family(&config.on_link_prefixes);
    let [doh4, doh6] = per_family(&config.doh_endpoints);
    let posture = match ruleset {
        Ruleset::Blocked => POSTURE_BLOCKED,
        Ruleset::Protected => POSTURE_PROTECTED,
    };

    let mut s = String::with_capacity(4096);
    let _ = writeln!(
        s,
        "# generated by twinvpn-platform-macos; loaded into anchor \"{ANCHOR}\" as one\n\
         # transaction (KS-17). Do not edit: the authority re-renders it on every apply."
    );

    // ---- the tables ------------------------------------------------------
    emit_table(&mut s, SCOPE_TABLE[0].0, &scope4);
    emit_table(&mut s, SCOPE_TABLE[1].0, &scope6);
    emit_table(&mut s, ONLINK_TABLE[0].0, &onlink4);
    emit_table(&mut s, ONLINK_TABLE[1].0, &onlink6);
    emit_table(&mut s, DOH_TABLE[0].0, &doh4);
    emit_table(&mut s, DOH_TABLE[1].0, &doh6);
    // KS-15's grant tables: declared, empty, and referenced by no rule until the
    // authority adds a grant. Their presence is what lets a grant be added
    // without re-rendering the anchor.
    emit_table(&mut s, PORTAL_TABLE[0].0, &BTreeSet::new());
    emit_table(&mut s, PORTAL_TABLE[1].0, &BTreeSet::new());
    // The read-back's answer, held by the kernel (CB-6).
    emit_table(&mut s, posture, &BTreeSet::new());
    emit_table(
        &mut s,
        &format!("{GENERATION_PREFIX}{}", contract.generation.0),
        &BTreeSet::new(),
    );
    emit_table(
        &mut s,
        &format!("{}{}", SCOPE_COUNT_PREFIX[0].0, scope4.len()),
        &BTreeSet::new(),
    );
    emit_table(
        &mut s,
        &format!("{}{}", SCOPE_COUNT_PREFIX[1].0, scope6.len()),
        &BTreeSet::new(),
    );

    // ---- class 8: loopback -----------------------------------------------
    // Cannot egress by construction, which is why it needs no scope qualifier.
    let _ = writeln!(
        s,
        "pass quick on lo0 all no state label \"twinvpn.loopback\""
    );

    // ---- class 7: the bootstrap exemption (KS-9) --------------------------
    // Destination-unbounded, because KS-10's BOOTSTRAP payloads are: mTLS 1.3 to
    // the control plane and rendezvous, encapsulated tunnel frames to relays and
    // peers, and the rate-limited class-13 probe. The `user` selector is what
    // makes KS-2 structural: pf resolves `user` from the packet's local socket,
    // and a FORWARDED packet has none, so no forwarded packet can ever match
    // this rule. That is KS-2's "never eligible for any exemption" as a property
    // of the selector rather than of a separate chain.
    for (label, family) in EXEMPT_LABEL {
        let af = match family {
            AddressFamily::V4 => "inet",
            AddressFamily::V6 => "inet6",
        };
        let _ = writeln!(
            s,
            "pass out quick {af} from any to any user = {uid} keep state label \"{label}\""
        );
    }

    // ---- class 5: DHCP / DHCPv6 / ND / RA on the underlay -----------------
    // Permitted as link-local control traffic only. Scoped OFF the overlay so it
    // cannot be a hole in the tunnel, and NOT scope-excluded — see the module
    // documentation for why the exclusion was tried and removed.
    emit_underlay(&mut s, overlay);

    // ---- class 9: link-local unicast on a non-overlay interface -----------
    // Not routable off-link, which is why §11.2 permits it unconditionally.
    let _ = writeln!(
        s,
        "pass out quick on ! {overlay} inet from any to 169.254.0.0/16 keep state \
         label \"twinvpn.linklocal.v4\""
    );
    let _ = writeln!(
        s,
        "pass out quick on ! {overlay} inet6 from any to fe80::/10 keep state \
         label \"twinvpn.linklocal.v6\""
    );

    // ---- X-9: the host's own underlay path, where it collides with the
    // overlay's address space -------------------------------------------------
    // A subscriber behind CGNAT holds an on-link address inside the very RFC
    // 6598 `/10` AP-1 carves the overlay out of. That prefix is not the user's
    // LAN — it is the path every packet leaves by — so it is passed off the
    // overlay UNCONDITIONALLY, and KS-4's DENY keeps costing the user their
    // printer rather than their internet. The overlay's own traffic egresses
    // the overlay interface and is untouched either way.
    //
    // `twinvpn_platform::on_link_is_underlay_path` carries the reasoning, once,
    // for this adapter and `twinvpn-platform-linux` both. X-9 was recorded as
    // "deliberately not worked around by one platform alone", and this is that
    // one place.
    for prefix in &config.on_link_prefixes {
        if twinvpn_platform::on_link_is_underlay_path(*prefix) {
            let _ = writeln!(
                s,
                "pass out quick on ! {overlay} inet from any to {} keep state \
                 label \"twinvpn.underlay.cgnat\"",
                prefix_text(*prefix)
            );
        }
    }

    // ---- classes 4 and 10: the local physical LAN, and the link-local
    // multicast that follows it. On-link prefixes ONLY, both families, and only
    // when KS-4's `local_network_access` is ALLOW. The safety here is KS-4's own:
    // "the permitted set is on-link prefixes only, recomputed on every
    // network-change event, and never includes a destination reachable only via a
    // router."
    if config.local_network_access {
        emit_local_network(&mut s, overlay, &onlink4, &onlink6);
    }

    // ---- class 6: DNS containment (ADR-0011 §11.9) ------------------------
    // "a `pf` anchor `twinvpn`, both families, denying 53/853/known-DoH
    // off-overlay". The authority's own resolver sockets carry its uid and were
    // passed by class 7 above, so this denies everything else. One dual-family
    // rule, hence one label of its own.
    let _ = writeln!(
        s,
        "block drop out quick on ! {overlay} proto {{ tcp, udp }} from any to any \
         port {{ 53, 853 }} label \"{DNS_DENY_LABEL}\""
    );
    if !doh4.is_empty() {
        let _ = writeln!(
            s,
            "block drop out quick on ! {overlay} inet proto tcp from any to <{}> \
             port 443 label \"{DNS_DENY_LABEL}\"",
            DOH_TABLE[0].0
        );
    }
    if !doh6.is_empty() {
        let _ = writeln!(
            s,
            "block drop out quick on ! {overlay} inet6 proto tcp from any to <{}> \
             port 443 label \"{DNS_DENY_LABEL}\"",
            DOH_TABLE[1].0
        );
    }

    // ---- Tier 2 ------------------------------------------------------------
    emit_scope(&mut s, overlay, ruleset);
    s
}

/// Class 5, both families.
fn emit_underlay(s: &mut String, overlay: &str) {
    let _ = writeln!(
        s,
        "pass out quick on ! {overlay} inet proto udp from any to any \
         port {{ 67, 68 }} keep state label \"twinvpn.underlay.dhcp4\""
    );
    let _ = writeln!(
        s,
        "pass out quick on ! {overlay} inet6 proto udp from any to any \
         port {{ 546, 547 }} keep state label \"twinvpn.underlay.dhcp6\""
    );
    // ICMPv6 133-137: router solicit/advert, neighbour solicit/advert, redirect.
    // ADR-0010 §11.5 clause 5 is explicit that blocking them breaks the underlay
    // itself.
    let _ = writeln!(
        s,
        "pass out quick on ! {overlay} inet6 proto ipv6-icmp from any to any \
         icmp6-type {{ routersol, routeradv, neighbrsol, neighbradv, redir }} \
         keep state label \"twinvpn.underlay.nd\""
    );
}

/// Classes 4 and 10, both families.
fn emit_local_network(
    s: &mut String,
    overlay: &str,
    onlink4: &BTreeSet<String>,
    onlink6: &BTreeSet<String>,
) {
    if !onlink4.is_empty() {
        let _ = writeln!(
            s,
            "pass out quick on ! {overlay} inet from any to <{}> keep state \
             label \"twinvpn.lan.v4\"",
            ONLINK_TABLE[0].0
        );
    }
    if !onlink6.is_empty() {
        let _ = writeln!(
            s,
            "pass out quick on ! {overlay} inet6 from any to <{}> keep state \
             label \"twinvpn.lan.v6\"",
            ONLINK_TABLE[1].0
        );
    }
    // Class 10 — link-local multicast, TTL/hop-limit 1, following class 4.
    let _ = writeln!(
        s,
        "pass out quick on ! {overlay} inet from any to 224.0.0.0/24 \
         no state label \"twinvpn.mcast.v4\""
    );
    let _ = writeln!(
        s,
        "pass out quick on ! {overlay} inet6 from any to ff02::/16 \
         no state label \"twinvpn.mcast.v6\""
    );
}

/// Emits the Tier-2 rules for **both** families.
///
/// One function, called once, so there is no call site that can emit the v4 half
/// without the v6 half — KS-5 as a code shape rather than a rule to remember.
/// `Protected` differs from `Blocked` in exactly one thing: whether the overlay
/// is an exception to the drop. Both are fail-closed.
fn emit_scope(s: &mut String, overlay: &str, ruleset: Ruleset) {
    if matches!(ruleset, Ruleset::Protected) {
        // Tier 2 is INTERFACE-scoped, which is why a v6 address or a whole new
        // interface appearing AFTER this is installed is denied with no rule
        // update required for correctness (ADR-0010 §11.5 clause 2).
        let _ = writeln!(
            s,
            "pass out quick on {overlay} inet from any to <{}> keep state \
             label \"twinvpn.protected.v4\"",
            SCOPE_TABLE[0].0
        );
        let _ = writeln!(
            s,
            "pass out quick on {overlay} inet6 from any to <{}> keep state \
             label \"twinvpn.protected.v6\"",
            SCOPE_TABLE[1].0
        );
    }
    // In `Blocked` there is no protected egress on ANY interface, including the
    // overlay, because in that posture the path is not validated and the
    // ProtectionAssertion has not been made (KS-18).
    let _ = writeln!(
        s,
        "block drop out quick inet from any to <{}> label \"{}\"",
        SCOPE_TABLE[0].0, DENY_LABEL[0].0
    );
    let _ = writeln!(
        s,
        "block drop out quick inet6 from any to <{}> label \"{}\"",
        SCOPE_TABLE[1].0, DENY_LABEL[1].0
    );
}

/// macOS's enforcement custody, declared truthfully.
///
/// Both are `true`, and both are properties of pf rather than of this code:
/// ADR-0012 §11.6's macOS durability row records that "`pf` rules are
/// kernel-resident" and survive crash, `SIGKILL`, update and reboot, and a single
/// `pfctl -f` load of an anchor is applied as one transaction so the swap has no
/// window with no rules (KS-17).
///
/// **The residual §11.6 states, and the type can now carry it:** "Recovery and
/// safe boot do not load the LaunchDaemon. Residual exposure: a device booted to
/// Recovery is unprotected." That is a **hole**, not Windows' availability gap,
/// and `EnforcementCustody::boot_enforcement` is where it is now declared rather
/// than left to the shell's posture report and this README to carry.
#[must_use]
pub const fn custody() -> EnforcementCustody {
    EnforcementCustody {
        ruleset_custody: RulesetCustody::OsHeld,
        swap_is_atomic: true,
        // The boot anchor exists and `/etc/pf.conf` references it, but the
        // `LaunchDaemon` that loads it is not loaded in Recovery or safe boot,
        // and Recovery HAS a network. So there is a boot mode in which this host
        // can emit packets with no TwinVPN rule set at all.
        boot_enforcement: BootEnforcement::ExemptBootModes,
    }
}
