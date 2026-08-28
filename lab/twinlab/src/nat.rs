//! §3.3's NAT class matrix — personalities, their real mechanism, and the
//! class-pair expectations **generated from** `docs/networking.md` §3.2.
//!
//! **Authority:** `docs/testing-strategy.md` §3.3, §2.10, §3.6;
//! `docs/networking.md` §3.1, §3.2, §3.6; ADR-0004.
//!
//! # Generated, not restated
//!
//! §3.3 is explicit:
//!
//! > The mapping is mechanical and MUST be generated from §3.2 rather than
//! > restated here, so a change to §3.2 cannot silently diverge from the lab.
//!
//! So [`TRAVERSABILITY_MD`] is a compile-time include of `docs/networking.md`
//! and [`Traversability::parse`] reads §3.2's markdown table. Editing that table
//! changes the lab; deleting it fails the build. There is no second copy of the
//! matrix in this repository.
//!
//! # The mechanism, and what this host can run
//!
//! Every personality is realized by real `nftables` and real `conntrack` state,
//! never by a flag. [`Personality::ruleset`] emits the actual `nft` script §3.3
//! specifies, and [`Personality::required_facilities`] names what the host must
//! provide. Where the host lacks it, the scenario yields
//! [`crate::outcome::Verdict::Unavailable`] — never a pass.

use crate::capability::Facility;
use crate::outcome::OutcomeClass;

/// `docs/networking.md`, included so §3.2's table is the single source.
pub const TRAVERSABILITY_MD: &str = include_str!("../../../docs/networking.md");

/// RFC 4787 mapping behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Mapping {
    /// No translation at all — routed, the IPv6 default.
    None,
    /// Endpoint-Independent Mapping.
    EndpointIndependent,
    /// Address-and-Port-Dependent Mapping, uniform allocation. The
    /// birthday-prediction target (`docs/networking.md` §3.6).
    AddressPortDependentRandom,
    /// Address-and-Port-Dependent Mapping, monotone allocator. The
    /// delta-prediction target.
    AddressPortDependentSequential,
}

/// RFC 4787 filtering behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Filtering {
    /// No filtering.
    None,
    /// Endpoint-Independent Filtering — unsolicited inbound is accepted.
    EndpointIndependent,
    /// Address-Dependent Filtering.
    AddressDependent,
    /// Address-and-Port-Dependent Filtering.
    AddressPortDependent,
}

/// The port-mapping protocol offered by the middlebox. `None` is the default so
/// that a test must **ask** for the easy path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum PortMap {
    /// No port-mapping daemon.
    None,
    /// RFC 6887 PCP.
    Pcp,
    /// NAT-PMP.
    NatPmp,
    /// UPnP IGDv2.
    UpnpIgd2,
}

/// How a personality is produced.
///
/// Recorded in the run record next to the personality, because "N-EIM-APDF" is
/// not a complete description of what ran: two realizations of one personality
/// can disagree, and §3.4.2's conformance suite exists precisely to catch the
/// one that has drifted. A record that named the personality and not the
/// realization would make that disagreement unattributable a year later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Realization {
    /// The `nft` ruleset and `conntrack` state §3.3's table specifies.
    Nftables,
    /// `twinnet::nat`: a real middlebox process on the path, holding the RFC
    /// 4787 state in userspace.
    UserspaceMiddlebox,
}

impl Realization {
    /// A name for a run record.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Realization::Nftables => "nftables",
            Realization::UserspaceMiddlebox => "userspace-middlebox",
        }
    }
}

/// §3.3's personalities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Personality {
    /// Forwarding only; no `nat` chain. The IPv6 default.
    Routed,
    /// Full cone. `snat … persistent` plus a conntrack-event `cone` helper.
    EimEif,
    /// Address-restricted cone.
    EimAdf,
    /// Port-restricted cone. Linux's stock behaviour.
    EimApdf,
    /// Symmetric, uniform allocation.
    ApdmApdfRand,
    /// Symmetric, monotone allocation.
    ApdmApdfSeq,
    /// CGNAT: `N-EIM-APDF` at the CPE chained into a shared APDM carrier tier.
    Cgnat,
    /// v6-only access plus stateful NAT64.
    Nat64,
}

impl Personality {
    /// Every personality §3.3 defines.
    pub const ALL: [Personality; 8] = [
        Personality::Routed,
        Personality::EimEif,
        Personality::EimAdf,
        Personality::EimApdf,
        Personality::ApdmApdfRand,
        Personality::ApdmApdfSeq,
        Personality::Cgnat,
        Personality::Nat64,
    ];

    /// The §3.3 spelling.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Personality::Routed => "N-ROUTED",
            Personality::EimEif => "N-EIM-EIF",
            Personality::EimAdf => "N-EIM-ADF",
            Personality::EimApdf => "N-EIM-APDF",
            Personality::ApdmApdfRand => "N-APDM-APDF-RAND",
            Personality::ApdmApdfSeq => "N-APDM-APDF-SEQ",
            Personality::Cgnat => "N-CGNAT",
            Personality::Nat64 => "N-NAT64",
        }
    }

    /// The mapping axis, configured independently of filtering (§3.3).
    #[must_use]
    pub const fn mapping(self) -> Mapping {
        match self {
            Personality::Routed | Personality::Nat64 => Mapping::None,
            Personality::EimEif | Personality::EimAdf | Personality::EimApdf => {
                Mapping::EndpointIndependent
            }
            Personality::ApdmApdfRand | Personality::Cgnat => Mapping::AddressPortDependentRandom,
            Personality::ApdmApdfSeq => Mapping::AddressPortDependentSequential,
        }
    }

    /// The filtering axis.
    #[must_use]
    pub const fn filtering(self) -> Filtering {
        match self {
            Personality::Routed | Personality::Nat64 => Filtering::None,
            Personality::EimEif => Filtering::EndpointIndependent,
            Personality::EimAdf => Filtering::AddressDependent,
            Personality::EimApdf
            | Personality::ApdmApdfRand
            | Personality::ApdmApdfSeq
            | Personality::Cgnat => Filtering::AddressPortDependent,
        }
    }

    /// The column of `docs/networking.md` §3.2 this personality occupies.
    ///
    /// `N-NAT64` maps to the native-IPv6 column because a 464XLAT access network
    /// gives the device working IPv6 to the peer, which is the property §3.2's
    /// last row is about. Recorded here rather than assumed silently.
    #[must_use]
    pub const fn matrix_label(self) -> &'static str {
        match self {
            Personality::Routed | Personality::Nat64 => "Native IPv6",
            Personality::EimEif => "EIM/EIF",
            Personality::EimAdf => "EIM/ADF",
            Personality::EimApdf => "EIM/APDF",
            Personality::ApdmApdfRand | Personality::ApdmApdfSeq => "APDM",
            Personality::Cgnat => "CGNAT",
        }
    }

    /// What the host must provide to realize this personality for real, under a
    /// named realization.
    ///
    /// **Why there are two.** §3.3's `Realization` column names `nftables` and
    /// `conntrack`, and that is *a* mechanism rather than the definition of the
    /// personality. §3.1's rule constrains the **observable semantics**, not the
    /// kernel subsystem that produces them:
    ///
    /// > Every condition TwinLab reproduces MUST be produced by a mechanism with
    /// > the same observable semantics as the real thing, never by a flag inside
    /// > TwinVPN.
    ///
    /// `twinnet::nat` is a second realization: a real middlebox process holding
    /// a real RFC 4787 mapping table with real filtering behaviour and real
    /// timers, forwarding real frames between two real `veth`s. It is not weaker
    /// than the `nftables` one and it is not stronger; it is a different way to
    /// produce the same observable behaviour, and §3.4.2's conformance suite —
    /// an RFC 5780-style prober that is not TwinVPN code — is what decides
    /// whether either of them actually did.
    ///
    /// A host that has neither still reports the personality as unavailable.
    /// What changed is the number of ways to have it, not the rule about not
    /// having it.
    #[must_use]
    pub fn required_facilities_for(self, realization: Realization) -> Vec<Facility> {
        match realization {
            Realization::Nftables => self.required_facilities(),
            // The userspace middlebox needs a namespace, a `veth` pair and a raw
            // packet socket, and nothing else — for every personality, because
            // the mapping table is the same code in all of them.
            Realization::UserspaceMiddlebox => {
                vec![Facility::NetworkNamespaces, Facility::Veth]
            }
        }
    }

    /// What the host must provide to realize this personality with `nftables`,
    /// which is the realization §3.3's table names.
    #[must_use]
    pub fn required_facilities(self) -> Vec<Facility> {
        let mut f = vec![Facility::NetworkNamespaces, Facility::Veth];
        match self {
            // Forwarding only — no nat chain, so no nftables is needed.
            Personality::Routed => {}
            // §3.3: "There is no pure-nftables full cone; the helper is the
            // honest mechanism", and the helper subscribes to conntrack events.
            Personality::EimEif | Personality::EimAdf => {
                f.push(Facility::Nftables);
                f.push(Facility::Conntrack);
            }
            Personality::Nat64 => {
                f.push(Facility::Nftables);
                f.push(Facility::Ipv6);
            }
            _ => f.push(Facility::Nftables),
        }
        f
    }

    /// The real `nft` ruleset §3.3 specifies for this personality.
    ///
    /// This is the mechanism, written out. It is emitted verbatim into the run
    /// record so a reviewer can check the emulator against RFC 4787 without
    /// reading Rust — and so that a personality that has drifted is visible.
    #[must_use]
    pub fn ruleset(
        self,
        external: &str,
        internal_cidr: &str,
        port_range: Option<(u16, u16)>,
    ) -> String {
        let table = "table inet twinlab_nat";
        match self {
            Personality::Routed => format!(
                "# {name}: forwarding only, no nat chain (§3.3, the IPv6 default)\n\
                 {table} {{\n\
                 \x20 chain forward {{ type filter hook forward priority 0;\n\
                 \x20   accept;\n\
                 \x20 }}\n\
                 }}\n",
                name = self.name()
            ),
            // EIM comes from NF_NAT_RANGE_PERSISTENT; the filtering axis is the
            // `cone` helper's dnat scope, installed from conntrack NEW events.
            Personality::EimEif => format!(
                "# {name}: EIM via `persistent`; EIF via the conntrack `cone` helper\n\
                 {table} {{\n\
                 \x20 chain postrouting {{ type nat hook postrouting priority 100;\n\
                 \x20   ip saddr {internal_cidr} snat to {external} persistent; }}\n\
                 \x20 chain prerouting {{ type nat hook prerouting priority -100; }}\n\
                 }}\n\
                 # helper: on each conntrack NEW, install\n\
                 #   add rule inet twinlab_nat prerouting udp dport <ext_port> dnat to <int>:<port>\n\
                 # with NO saddr qualifier — that absence is what makes filtering EIF.\n",
                name = self.name()
            ),
            Personality::EimAdf => format!(
                "# {name}: EIM via `persistent`; ADF via a saddr-qualified helper rule\n\
                 {table} {{\n\
                 \x20 chain postrouting {{ type nat hook postrouting priority 100;\n\
                 \x20   ip saddr {internal_cidr} snat to {external} persistent; }}\n\
                 \x20 chain prerouting {{ type nat hook prerouting priority -100; }}\n\
                 }}\n\
                 # helper: dnat rule carries `ip saddr <observed peer address>` (and\n\
                 # `ip6 saddr` for v6), so a different ADDRESS is filtered and a\n\
                 # different PORT is not. That is the whole difference from EIF.\n",
                name = self.name()
            ),
            Personality::EimApdf => format!(
                "# {name}: EIM via `persistent`; APDF is stock conntrack reply matching\n\
                 # (no helper at all — §3.3: this needs the least machinery)\n\
                 {table} {{\n\
                 \x20 chain postrouting {{ type nat hook postrouting priority 100;\n\
                 \x20   ip saddr {internal_cidr} snat to {external} persistent; }}\n\
                 }}\n",
                name = self.name()
            ),
            Personality::ApdmApdfRand => format!(
                "# {name}: fresh source port per destination tuple, uniform allocation\n\
                 {table} {{\n\
                 \x20 chain postrouting {{ type nat hook postrouting priority 100;\n\
                 \x20   ip saddr {internal_cidr} masquerade fully-random; }}\n\
                 }}\n\
                 # plus a per-destination `ct mark` so an allocation cannot be\n\
                 # coincidentally reused, which would look like EIM to a prober.\n",
                name = self.name()
            ),
            Personality::ApdmApdfSeq => format!(
                "# {name}: monotone allocator — the delta-prediction target (§3.6)\n\
                 {table} {{\n\
                 \x20 chain postrouting {{ type nat hook postrouting priority 100;\n\
                 \x20   meta l4proto {{ tcp, udp }} ip saddr {internal_cidr} \\\n\
                 \x20     snat to {external}:1024-65535; }}\n\
                 }}\n\
                 # `snat to <ext>:<lo>-<hi>` WITHOUT `fully-random` allocates\n\
                 # monotonically, which is the observable §3.6 distinguishes.\n",
                name = self.name()
            ),
            Personality::Cgnat => {
                let (lo, hi) = port_range.unwrap_or((10_000, 11_023));
                format!(
                    "# {name}: N-EIM-APDF at the CPE chained into a SHARED APDM carrier tier\n\
                     # (shared by >= 2 subscriber trees — a single-subscriber CGNAT does not\n\
                     #  reproduce port exhaustion or hairpin behaviour, §3.2)\n\
                     {table} {{\n\
                     \x20 chain postrouting {{ type nat hook postrouting priority 100;\n\
                     \x20   meta l4proto {{ tcp, udp }} ip saddr {internal_cidr} \\\n\
                     \x20     snat to {external}:{lo}-{hi}; }}\n\
                     }}\n\
                     # the capped range is what makes port exhaustion REACHABLE (§3.4.2).\n",
                    name = self.name()
                )
            }
            Personality::Nat64 => Self::nat64_ruleset(table, external, internal_cidr),
        }
    }

    /// The nft ruleset for `N-NAT64`, and why it installs no `nat` chain.
    ///
    /// # nftables cannot do the translation, and this says so
    ///
    /// There is no NAT64 statement in nft: stateful 6-to-4 translation is an
    /// out-of-tree job (Jool, tayga) or a userspace middlebox. An earlier
    /// revision of this function emitted `dnat ip to 64:ff9b::/96 map {}`,
    /// which is not nft syntax at all — and had never been fed to `nft`,
    /// because the tests compared the emitted string to expected substrings
    /// rather than loading it.
    ///
    /// What is emitted is the part nft really owns: the policy that traffic to
    /// the well-known prefix is forwarded to the translator rather than routed
    /// as ordinary v6. It is deliberately **not** a `nat` chain, because a nat
    /// chain here would look like a translator and translate nothing — a
    /// personality reported as realized and not realized, the one outcome
    /// `docs/testing-strategy.md` §3.1 exists to prevent.
    ///
    /// `twinnet::nat`'s userspace realization is the one that can actually
    /// translate; [`crate::capability::Facility::UserspaceNat`] is what a host
    /// needs for this class.
    fn nat64_ruleset(table: &str, external: &str, internal_cidr: &str) -> String {
        format!(
            "# {name}: stateful NAT64, v6-only access\n\
             # pref64 advertised BOTH ways and independently switchable:\n\
             #   - RFC 8781 PREF64 in RAs (the path networking.md §3.8 prefers)\n\
             #   - RFC 7050 ipv4only.arpa\n\
             # The TRANSLATION itself is not nft's; see this function's docs.\n\
             {table} {{\n\
             \x20 chain forward {{ type filter hook forward priority 0;\n\
             \x20   ip6 daddr 64:ff9b::/96 accept;\n\
             \x20   accept;\n\
             \x20 }}\n\
             }}\n\
             # ({external}, {internal_cidr} are the v4 pool and the v6 access prefix)\n",
            name = Personality::Nat64.name()
        )
    }
}

/// §3.2's traversability matrix, parsed from `docs/networking.md`.
#[derive(Debug, Clone)]
pub struct Traversability {
    labels: Vec<String>,
    /// `cells[row][col]` — `"D"`, `"D*"` or `"R"`.
    cells: Vec<Vec<String>>,
}

impl Traversability {
    /// Parses §3.2's markdown table out of `docs/networking.md`.
    ///
    /// # Panics
    ///
    /// If §3.2's table is missing or has changed shape. That is deliberate: a
    /// lab that silently loses its expectations is worse than one that does not
    /// build, and §3.3 makes this table the source.
    #[must_use]
    pub fn parse(markdown: &str) -> Self {
        let section = markdown
            .split("### 3.2 Traversability matrix")
            .nth(1)
            .expect("docs/networking.md §3.2 is missing; §3.3 makes it the source of the matrix");
        let mut labels = Vec::new();
        let mut cells = Vec::new();
        for line in section.lines() {
            let t = line.trim();
            if !t.starts_with('|') {
                if !labels.is_empty() && !cells.is_empty() {
                    break;
                }
                continue;
            }
            // Strip markdown **bold** only. A lone trailing `*` is `D*` — the
            // probabilistic cell — and eating it would silently promote every
            // port-prediction pair to DIRECT_EXPECTED, which is precisely the
            // B-6 misreading this whole module exists to prevent.
            let cols: Vec<String> = t
                .trim_matches('|')
                .split('|')
                .map(|c| {
                    let c = c.trim();
                    let c = c.strip_prefix("**").unwrap_or(c);
                    let c = c.strip_suffix("**").unwrap_or(c);
                    c.trim().to_owned()
                })
                .collect();
            if cols
                .iter()
                .all(|c| c.chars().all(|ch| ch == '-' || ch == ':') && !c.is_empty())
            {
                continue;
            }
            if labels.is_empty() {
                // The header row: an empty first cell, then the column labels.
                assert!(
                    cols.first().is_some_and(String::is_empty),
                    "§3.2's header row must start with an empty corner cell"
                );
                labels = cols[1..].to_vec();
            } else {
                assert_eq!(
                    cols.len(),
                    labels.len() + 1,
                    "§3.2 row `{}` has {} cells, expected {}",
                    cols[0],
                    cols.len(),
                    labels.len() + 1
                );
                cells.push(cols);
            }
        }
        assert!(!labels.is_empty(), "§3.2's matrix header was not found");
        assert_eq!(
            cells.len(),
            labels.len(),
            "§3.2's matrix must be square: {} rows against {} columns",
            cells.len(),
            labels.len()
        );
        Self { labels, cells }
    }

    /// The column labels, in order.
    #[must_use]
    pub fn labels(&self) -> &[String] {
        &self.labels
    }

    /// The raw cell for an ordered pair of §3.2 labels.
    #[must_use]
    pub fn cell(&self, local: &str, remote: &str) -> Option<&str> {
        let col = self.labels.iter().position(|l| l == remote)? + 1;
        let row = self.cells.iter().find(|r| r[0] == local)?;
        Some(row[col].as_str())
    }
}

/// The expected outcome class for an ordered personality pair.
///
/// Derived from §3.2's cell, then refined by §3.6's per-pair budget table. A
/// pair whose label is absent from §3.2 has no expectation and returns `None`
/// rather than a guessed one.
///
/// # Panics
///
/// If §3.2 grows a cell value that is not `D`, `D*` or `R`. That is deliberate:
/// a new outcome class is a change to §2.10, and guessing what it means would be
/// exactly the silent divergence §3.3 forbids.
#[must_use]
pub fn expected_class(
    matrix: &Traversability,
    local: Personality,
    remote: Personality,
    portmap: PortMap,
) -> Option<OutcomeClass> {
    // §3.2's last row and column: "if both ends have working IPv6, every cell is D."
    let cell = matrix.cell(local.matrix_label(), remote.matrix_label())?;
    Some(match cell {
        "D" => OutcomeClass::DirectExpected,
        "R" => OutcomeClass::RelayExpected,
        "D*" => direct_possible_budget(local, remote, portmap),
        other => panic!("§3.2 cell `{other}` is not one of D, D*, R"),
    })
}

/// §3.6's per-pair direct-success budgets, applied to a `D*` cell.
fn direct_possible_budget(
    local: Personality,
    remote: Personality,
    portmap: PortMap,
) -> OutcomeClass {
    // "EIM×APDM with portmap = PCP | 20 | >= 95 %"
    if !matches!(portmap, PortMap::None) {
        return OutcomeClass::DirectPossible {
            runs: 20,
            min_success_pct: 95,
        };
    }
    let seq = local == Personality::ApdmApdfSeq || remote == Personality::ApdmApdfSeq;
    if seq {
        // "EIM×N-APDM-APDF-SEQ, no port mapping | 50 | >= 80 %"
        OutcomeClass::DirectPossible {
            runs: 50,
            min_success_pct: 80,
        }
    } else {
        // "EIM×N-APDM-APDF-RAND, no port mapping | 50 | >= 60 %"
        OutcomeClass::DirectPossible {
            runs: 50,
            min_success_pct: 60,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matrix() -> Traversability {
        Traversability::parse(TRAVERSABILITY_MD)
    }

    #[test]
    fn the_matrix_parses_and_is_square() {
        let m = matrix();
        assert_eq!(
            m.labels(),
            [
                "EIM/EIF",
                "EIM/ADF",
                "EIM/APDF",
                "APDM",
                "CGNAT",
                "Native IPv6"
            ]
        );
    }

    #[test]
    fn every_personality_has_a_column_in_section_3_2() {
        let m = matrix();
        for p in Personality::ALL {
            assert!(
                m.labels().iter().any(|l| l == p.matrix_label()),
                "{} maps to §3.2 label `{}`, which §3.2 does not define — the \
                 lab and the matrix have diverged",
                p.name(),
                p.matrix_label()
            );
        }
    }

    #[test]
    fn the_relay_by_design_cells_are_relay_expected() {
        // networking.md §3.2: "The genuinely hard cells — APDM<->APDM and
        // CGNAT<->CGNAT over IPv4 only — are declared relay by design (N4)."
        let m = matrix();
        for (a, b) in [
            (Personality::ApdmApdfRand, Personality::ApdmApdfRand),
            (Personality::Cgnat, Personality::Cgnat),
            (Personality::Cgnat, Personality::ApdmApdfRand),
            (Personality::EimApdf, Personality::Cgnat),
        ] {
            assert_eq!(
                expected_class(&m, a, b, PortMap::None),
                Some(OutcomeClass::RelayExpected),
                "{} x {} must be RELAY_EXPECTED",
                a.name(),
                b.name()
            );
        }
    }

    #[test]
    fn every_ipv6_cell_is_direct_expected() {
        // "Read the last row and column first: if both ends have working IPv6,
        // every cell is D." A v4-only regression must fail here.
        let m = matrix();
        for p in Personality::ALL {
            assert_eq!(
                expected_class(&m, Personality::Routed, p, PortMap::None),
                Some(OutcomeClass::DirectExpected),
                "N-ROUTED x {} must be DIRECT_EXPECTED — §3.2's last row is \
                 unqualified and §3.6 gives it a 100% budget",
                p.name()
            );
            assert_eq!(
                expected_class(&m, p, Personality::Routed, PortMap::None),
                Some(OutcomeClass::DirectExpected),
                "{} x N-ROUTED must be DIRECT_EXPECTED",
                p.name()
            );
        }
    }

    #[test]
    fn eim_by_eim_is_direct_expected_in_every_filtering_combination() {
        // §3.6: "EIM x EIM (any filtering) over v4 | 20 | 100 %".
        let m = matrix();
        let eims = [
            Personality::EimEif,
            Personality::EimAdf,
            Personality::EimApdf,
        ];
        for a in eims {
            for b in eims {
                assert_eq!(
                    expected_class(&m, a, b, PortMap::None),
                    Some(OutcomeClass::DirectExpected),
                    "{} x {}",
                    a.name(),
                    b.name()
                );
            }
        }
    }

    #[test]
    fn port_mapping_raises_the_budget_and_a_monotone_allocator_lowers_it() {
        let m = matrix();
        assert_eq!(
            expected_class(
                &m,
                Personality::EimEif,
                Personality::ApdmApdfRand,
                PortMap::None
            ),
            Some(OutcomeClass::DirectPossible {
                runs: 50,
                min_success_pct: 60
            })
        );
        assert_eq!(
            expected_class(
                &m,
                Personality::EimEif,
                Personality::ApdmApdfSeq,
                PortMap::None
            ),
            Some(OutcomeClass::DirectPossible {
                runs: 50,
                min_success_pct: 80
            })
        );
        assert_eq!(
            expected_class(
                &m,
                Personality::EimEif,
                Personality::ApdmApdfRand,
                PortMap::Pcp
            ),
            Some(OutcomeClass::DirectPossible {
                runs: 20,
                min_success_pct: 95
            })
        );
    }

    #[test]
    fn mapping_and_filtering_are_independent_axes() {
        // §3.3's stated reason for configuring them separately: the legacy
        // vocabulary conflates them. Three personalities share one mapping and
        // differ only in filtering, which is what proves the axes are separate.
        for p in [
            Personality::EimEif,
            Personality::EimAdf,
            Personality::EimApdf,
        ] {
            assert_eq!(p.mapping(), Mapping::EndpointIndependent);
        }
        assert_ne!(
            Personality::EimEif.filtering(),
            Personality::EimApdf.filtering()
        );
    }

    #[test]
    fn a_ruleset_is_real_nftables_and_names_its_mechanism() {
        // The realization principle in miniature: a personality that claims to
        // translate must emit a real nat chain, and one that cannot must not
        // pretend to.
        //
        // THREE cases, not two, and the third is the honest one:
        //
        //   - `N-ROUTED` forwards and does not translate. No nat chain.
        //   - `N-NAT64` translates, and **nftables cannot do it**: there is no
        //     NAT64 statement in nft, it is Jool/tayga or a userspace
        //     middlebox. So its nft ruleset carries the forwarding policy and
        //     NO nat chain. A nat chain here would look like a translator and
        //     translate nothing — a personality reported as realized and not
        //     realized, which is the one outcome §3.1 exists to prevent.
        //     `twinnet::nat` is the realization that can actually translate.
        //   - Everything else installs a real nat chain.
        for p in Personality::ALL {
            let rs = p.ruleset("198.51.100.10", "192.168.1.0/24", None);
            assert!(rs.contains(p.name()), "{} does not name itself", p.name());
            match p {
                Personality::Routed | Personality::Nat64 => assert!(
                    !rs.contains("type nat hook"),
                    "{} must have no nat chain: it either does not translate, or \
                     nftables cannot translate for it",
                    p.name()
                ),
                _ => assert!(
                    rs.contains("type nat hook"),
                    "{} must install a real nat chain",
                    p.name()
                ),
            }
        }
    }

    #[test]
    fn every_ruleset_is_syntactically_loadable_nftables() {
        // A STRUCTURAL check, because the real one needs `nft` and a host may
        // not have it — `.github/workflows/lab-t1.yml` feeds every personality
        // to a real `nft -f` and asserts it loads.
        //
        // This is the cheap half, and it is here because the expensive half did
        // not exist and ALL EIGHT personalities emitted nft that does not parse:
        // every rule ran straight into its chain's closing `}` with no `;`,
        // `N-NAT64` emitted `dnat ip to … map { }` which is not nft syntax at
        // all, and the two port-range personalities omitted the
        // transport-protocol match `snat to <ip>:<lo>-<hi>` requires.
        //
        // Nothing caught it because the other tests assert that the emitted
        // string CONTAINS an expected substring — which it did, while being
        // unloadable. A ruleset nobody applies is a NAT class nobody realizes.
        for p in Personality::ALL {
            let rs = p.ruleset("198.51.100.10", "192.168.1.0/24", None);
            let code: String = rs
                .lines()
                .filter(|l| !l.trim_start().starts_with('#'))
                .collect::<Vec<_>>()
                .join("\n");

            let opens = code.matches('{').count();
            let closes = code.matches('}').count();
            assert_eq!(opens, closes, "{}: unbalanced braces in\n{code}", p.name());

            // The defect, made mechanical. TWO rules, and they are the two
            // things `nft` actually refused:
            //
            //   1. `} }` on one line — two BLOCK terminators with no separator.
            //      That was `N-ROUTED`, and nft says "unexpected '}'".
            //   2. A line ending in `}` whose statement does not end in `;`.
            //      That was the other six.
            //
            // Only a `}` at END OF LINE is treated as a block terminator. A `}`
            // mid-line closes a SET literal — `meta l4proto { tcp, udp }` — and
            // an earlier version of this check flagged it, which would have
            // forced the emitter to break a rule that nft accepts.
            assert!(
                !code.contains("} }"),
                "{}: two block terminators on one line need a `;` or a newline \
                 between them:\n{code}",
                p.name()
            );
            for line in code.lines() {
                let trimmed = line.trim_end();
                if !trimmed.ends_with('}') {
                    continue;
                }
                let before = trimmed[..trimmed.len() - 1].trim_end();
                assert!(
                    before.is_empty() || before.ends_with(';') || before.ends_with('{'),
                    "{}: a statement runs into a block-closing `}}` with no `;`:\n  {line}",
                    p.name()
                );
            }
        }
    }

    #[test]
    fn the_symmetric_variants_emit_different_allocators() {
        // -RAND and -SEQ are distinct §3.6 prediction targets, so an emulator
        // that emitted the same rule for both would silently make the SEQ
        // budget unreachable.
        let rule = |p: Personality| {
            p.ruleset("198.51.100.10", "192.168.1.0/24", None)
                .lines()
                .filter(|l| !l.trim_start().starts_with('#'))
                .collect::<Vec<_>>()
                .join("\n")
        };
        let rand = rule(Personality::ApdmApdfRand);
        let seq = rule(Personality::ApdmApdfSeq);
        assert!(rand.contains("masquerade fully-random"), "{rand}");
        assert!(
            !seq.contains("fully-random"),
            "the SEQ allocator must be monotone: {seq}"
        );
        assert!(seq.contains("snat to 198.51.100.10:1024-65535"), "{seq}");
        assert_ne!(rand, seq);
    }

    #[test]
    fn the_cgnat_port_budget_is_capped_so_exhaustion_is_reachable() {
        let rs = Personality::Cgnat.ruleset("100.80.0.1", "100.80.1.0/24", Some((10_000, 10_099)));
        assert!(rs.contains("10000-10099"), "{rs}");
    }

    #[test]
    fn a_personality_names_the_facilities_it_actually_needs() {
        assert!(Personality::EimEif
            .required_facilities()
            .contains(&Facility::Conntrack));
        // N-ROUTED is forwarding only: demanding nftables for it would make
        // every IPv6 scenario unavailable on a host that has none, which would
        // hide exactly the results §3.2's last row cares about.
        assert!(!Personality::Routed
            .required_facilities()
            .contains(&Facility::Nftables));
    }
}
