//! §3.2's topology — namespaces, `veth` legs, bridges, and their lifecycle.
//!
//! **Authority:** `docs/testing-strategy.md` §3.1 (realization principle), §3.2.
//!
//! # What is real here, and what this host could actually run
//!
//! A node is a Linux network namespace ([`NodeKind`] says which kind), joined by
//! `veth` pairs, with an L2 segment realized as a bridge. [`Topology`] is the
//! declarative half — it can be built, validated against §3.2's address realism
//! rule and rendered into the exact `ip` commands, with no privilege at all.
//! [`LinuxNamespaceBackend`] is the executing half.
//!
//! The split is not an abstraction for its own sake: it is what lets the address
//! plan, the naming, the per-node routing and the run record be **tested
//! deterministically** while the execution stays a real kernel mechanism. There
//! is no second, simulated backend, because a simulated one would be exactly the
//! thing §3.1 forbids.
//!
//! # Namespace realization, honestly
//!
//! `ip netns add` needs `CAP_NET_ADMIN` in the initial user namespace and a
//! writable `/var/run/netns`, which an unprivileged CI runner does not have.
//! [`LinuxNamespaceBackend::realization`] reports which of the two mechanisms is
//! available:
//!
//! | Mechanism | Needs | What it gives |
//! |---|---|---|
//! | [`Realization::PersistentNetns`] | `CAP_NET_ADMIN`, writable `/var/run/netns` | named namespaces, `ip netns exec`, survives the orchestrator |
//! | [`Realization::UnprivilegedUserNs`] | unprivileged `CLONE_NEWUSER \| CLONE_NEWNET` | real namespaces, real veth, real netem, real IPv6 — but no `ip netns` name table, so each node is addressed by pid |
//! | [`Realization::Unavailable`] | — | nothing is executed and every scenario needing a node is `Unavailable` |

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::addressing::{AddressPlan, Tier};
use crate::capability::{Facility, HostCapabilities};
use crate::error::LabError;
use crate::exec::Runner;

/// What a node is, in §3.2's table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum NodeKind {
    /// A namespace running the real agent binary.
    Device,
    /// A namespace with forwarding on and a NAT personality.
    Middlebox,
    /// A namespace shared by ≥ 2 subscriber trees.
    CarrierNat,
    /// A namespace carrying the impairment qdiscs.
    Transit,
    /// A namespace running the real relay binary.
    Relay,
    /// The control plane.
    ControlPlane,
    /// The rendezvous service.
    Rendezvous,
    /// The relay-selection service.
    RelaySelection,
    /// A simulated Internet host.
    Destination,
    /// The lab's authoritative + recursive DNS server.
    Resolver,
}

/// A node in the topology.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Node {
    /// A short, stable name — also the namespace name where one exists.
    pub name: String,
    /// What it is.
    pub kind: NodeKind,
    /// Whether IPv4/IPv6 forwarding is enabled.
    pub forwarding: bool,
}

/// An L2 segment: a bridge plus one `veth` leg per attached node.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Segment {
    /// The bridge name.
    pub name: String,
    /// The namespace the bridge lives in.
    pub host: String,
    /// Attached node names.
    pub members: Vec<String>,
    /// Whether the bridge enforces client isolation, which is what produces a
    /// genuine hairpin failure rather than a configured one.
    pub client_isolation: bool,
}

/// A point-to-point `veth` between two nodes.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Link {
    /// The node holding the `a` end.
    pub a: String,
    /// The node holding the `b` end.
    pub b: String,
    /// The `a`-side address, if assigned.
    pub a_v4: Option<Ipv4Addr>,
    /// The `b`-side address.
    pub b_v4: Option<Ipv4Addr>,
    /// The `a`-side IPv6 address. **L-5 makes this not optional in practice.**
    pub a_v6: Option<Ipv6Addr>,
    /// The `b`-side IPv6 address.
    pub b_v6: Option<Ipv6Addr>,
    /// Which tier the addresses belong to, for the §3.2 realism check.
    pub tier: Tier,
}

impl Link {
    /// The interface name on the `a` side. Interface names are capped at 15
    /// bytes by the kernel, so they are derived and truncated deterministically
    /// rather than assembled ad hoc.
    #[must_use]
    pub fn if_a(&self) -> String {
        iface_name(&self.a, &self.b)
    }

    /// The interface name on the `b` side.
    #[must_use]
    pub fn if_b(&self) -> String {
        iface_name(&self.b, &self.a)
    }
}

fn iface_name(local: &str, peer: &str) -> String {
    let mut s = format!("v-{local}-{peer}");
    s.truncate(15);
    s
}

/// A whole §3.2 topology.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Topology {
    /// Nodes.
    pub nodes: Vec<Node>,
    /// L2 segments.
    pub segments: Vec<Segment>,
    /// Point-to-point links.
    pub links: Vec<Link>,
}

impl Topology {
    /// An empty topology.
    #[must_use]
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            segments: Vec::new(),
            links: Vec::new(),
        }
    }

    /// Adds a node.
    #[must_use]
    pub fn node(mut self, name: &str, kind: NodeKind, forwarding: bool) -> Self {
        self.nodes.push(Node {
            name: name.to_owned(),
            kind,
            forwarding,
        });
        self
    }

    /// Adds a point-to-point link.
    #[must_use]
    pub fn link(mut self, link: Link) -> Self {
        self.links.push(link);
        self
    }

    /// Adds an L2 segment.
    #[must_use]
    pub fn segment(mut self, segment: Segment) -> Self {
        self.segments.push(segment);
        self
    }

    /// §3.2's preconditions, checked rather than assumed.
    ///
    /// # Errors
    ///
    /// [`LabError::Addressing`] for an address-realism violation, and
    /// [`LabError::Mechanism`] for a structural one — a link naming an
    /// undeclared node, a duplicate node name, or a CGNAT tier with fewer than
    /// two subscriber trees, which §3.2 says "does not reproduce the
    /// port-exhaustion or hairpin properties".
    pub fn validate(&self, plan: AddressPlan) -> Result<(), LabError> {
        let mut seen: Vec<&str> = Vec::new();
        for n in &self.nodes {
            if seen.contains(&n.name.as_str()) {
                return Err(LabError::Mechanism {
                    detail: format!("duplicate node `{}`", n.name),
                });
            }
            seen.push(&n.name);
        }
        for l in &self.links {
            for end in [&l.a, &l.b] {
                if !seen.contains(&end.as_str()) {
                    return Err(LabError::Mechanism {
                        detail: format!("link names undeclared node `{end}`"),
                    });
                }
            }
            for ip in [l.a_v4, l.b_v4].into_iter().flatten() {
                plan.check_underlay(l.tier, ip)?;
            }
            for ip in [l.a_v6, l.b_v6].into_iter().flatten() {
                plan.check_underlay_v6(l.tier, ip)?;
            }
        }
        for s in &self.segments {
            for m in &s.members {
                if !seen.contains(&m.as_str()) {
                    return Err(LabError::Mechanism {
                        detail: format!("segment `{}` names undeclared node `{m}`", s.name),
                    });
                }
            }
        }
        // §3.2: "A single-subscriber 'CGNAT' does not reproduce the
        // port-exhaustion or hairpin properties."
        for carrier in self.nodes.iter().filter(|n| n.kind == NodeKind::CarrierNat) {
            let trees = self
                .links
                .iter()
                .filter(|l| l.a == carrier.name || l.b == carrier.name)
                .count();
            if trees < 3 {
                return Err(LabError::Mechanism {
                    detail: format!(
                    "carrier NAT `{}` has {} link(s); §3.2 requires >= 2 subscriber trees plus an \
                     uplink, because a single-subscriber CGNAT reproduces neither port exhaustion \
                     nor hairpinning",
                    carrier.name, trees
                ),
                });
            }
        }
        Ok(())
    }

    /// The exact `ip` commands that build this topology, as the run record
    /// carries them. Rendered without executing anything, so the plan is
    /// reviewable and testable on any host.
    #[must_use]
    pub fn ip_commands(&self) -> Vec<Vec<String>> {
        let a = |s: &str| s.to_owned();
        let mut out = Vec::new();
        for n in &self.nodes {
            out.push(vec![a("netns"), a("add"), n.name.clone()]);
            out.push(vec![
                a("netns"),
                a("exec"),
                n.name.clone(),
                a("ip"),
                a("link"),
                a("set"),
                a("lo"),
                a("up"),
            ]);
        }
        for s in &self.segments {
            out.push(vec![
                a("netns"),
                a("exec"),
                s.host.clone(),
                a("ip"),
                a("link"),
                a("add"),
                a("name"),
                s.name.clone(),
                a("type"),
                a("bridge"),
            ]);
        }
        for l in &self.links {
            out.push(vec![
                a("link"),
                a("add"),
                l.if_a(),
                a("netns"),
                l.a.clone(),
                a("type"),
                a("veth"),
                a("peer"),
                a("name"),
                l.if_b(),
                a("netns"),
                l.b.clone(),
            ]);
            for (ns, iface, v4, v6) in [
                (&l.a, l.if_a(), l.a_v4, l.a_v6),
                (&l.b, l.if_b(), l.b_v4, l.b_v6),
            ] {
                if let Some(ip) = v4 {
                    out.push(vec![
                        a("-n"),
                        ns.clone(),
                        a("addr"),
                        a("add"),
                        format!("{ip}/24"),
                        a("dev"),
                        iface.clone(),
                    ]);
                }
                if let Some(ip) = v6 {
                    out.push(vec![
                        a("-n"),
                        ns.clone(),
                        a("-6"),
                        a("addr"),
                        a("add"),
                        format!("{ip}/64"),
                        a("dev"),
                        iface.clone(),
                    ]);
                }
                out.push(vec![
                    a("-n"),
                    ns.clone(),
                    a("link"),
                    a("set"),
                    iface,
                    a("up"),
                ]);
            }
        }
        out
    }
}

impl Default for Topology {
    fn default() -> Self {
        Self::new()
    }
}

/// Which namespace mechanism this host offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Realization {
    /// `ip netns` named namespaces — the full §3.2 mechanism.
    PersistentNetns,
    /// Unprivileged `unshare --user --net`. Real namespaces, real veth, real
    /// netem, no `ip netns` name table.
    UnprivilegedUserNs,
    /// No namespace mechanism at all.
    Unavailable,
}

impl Realization {
    /// Whether a scenario needing a real node can run.
    #[must_use]
    pub const fn can_build_nodes(self) -> bool {
        !matches!(self, Realization::Unavailable)
    }

    /// Whether the `ip netns` name table exists, which `ip netns exec` and the
    /// `-n <name>` shorthand both need.
    #[must_use]
    pub const fn has_name_table(self) -> bool {
        matches!(self, Realization::PersistentNetns)
    }
}

/// The executing half. Owns nothing until [`LinuxNamespaceBackend::build`] runs.
#[derive(Debug)]
pub struct LinuxNamespaceBackend {
    runner: Runner,
    caps: HostCapabilities,
    created: Vec<String>,
}

impl LinuxNamespaceBackend {
    /// Probes the host and prepares a backend.
    #[must_use]
    pub fn probe() -> Self {
        Self {
            runner: Runner::new(),
            caps: HostCapabilities::probe(),
            created: Vec::new(),
        }
    }

    /// The probed capabilities.
    #[must_use]
    pub fn capabilities(&self) -> &HostCapabilities {
        &self.caps
    }

    /// Which mechanism this host offers.
    #[must_use]
    pub fn realization(&mut self) -> Realization {
        if !self.caps.has(Facility::NetworkNamespaces) {
            return Realization::Unavailable;
        }
        // `ip netns list` succeeds without privilege; `ip netns add` is the
        // capability that matters, so it is probed with a throwaway name and
        // removed again.
        let probe = "twinlab-probe-ns";
        let added = self.runner.run("ip", &["netns", "add", probe]).is_ok();
        if added {
            let _ = self.runner.run("ip", &["netns", "delete", probe]);
            Realization::PersistentNetns
        } else {
            Realization::UnprivilegedUserNs
        }
    }

    /// Builds `topology` for real.
    ///
    /// # Errors
    ///
    /// [`LabError::FacilityUnavailable`] when this host cannot create a
    /// namespace, which is **not** a test failure — see
    /// [`crate::outcome::Verdict::Unavailable`]. [`LabError::Mechanism`] when a
    /// command that should have worked did not.
    pub fn build(&mut self, topology: &Topology, plan: AddressPlan) -> Result<(), LabError> {
        topology.validate(plan)?;
        match self.realization() {
            Realization::PersistentNetns => {}
            Realization::UnprivilegedUserNs => {
                return Err(LabError::FacilityUnavailable {
                    facility: "persistent network namespaces",
                    detail: "this host permits only unprivileged `unshare --user --net`, which \
                             creates real namespaces but no `ip netns` name table, so a \
                             multi-node topology cannot be addressed by name"
                        .to_owned(),
                })
            }
            Realization::Unavailable => {
                return Err(LabError::FacilityUnavailable {
                    facility: "network namespaces",
                    detail: "CLONE_NEWNET is not permitted for this process".to_owned(),
                })
            }
        }
        for argv in topology.ip_commands() {
            let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
            self.runner.run("ip", &refs)?;
            if refs.first() == Some(&"netns") && refs.get(1) == Some(&"add") {
                if let Some(name) = refs.get(2) {
                    self.created.push((*name).to_owned());
                }
            }
        }
        for n in topology.nodes.iter().filter(|n| n.forwarding) {
            // Both families, always. A v4-only forwarding node is the exact
            // asymmetry ADR-0010 R1 forbids, and it is invisible until a v6
            // scenario fails for no apparent reason.
            for key in ["net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1"] {
                self.runner.run_in(Some(&n.name), "sysctl", &["-w", key])?;
            }
        }
        Ok(())
    }

    /// Removes everything this backend created.
    ///
    /// Idempotent, and it runs even after a failed build: a namespace left
    /// behind is the lab's own version of the route-not-removed defect §2.9
    /// calls out.
    pub fn teardown(&mut self) {
        let created = std::mem::take(&mut self.created);
        for name in created {
            let _ = self.runner.run("ip", &["netns", "delete", &name]);
        }
    }

    /// Every command this backend executed, for the run record.
    #[must_use]
    pub fn log(&self) -> &[crate::exec::Invocation] {
        self.runner.log()
    }
}

impl Drop for LinuxNamespaceBackend {
    fn drop(&mut self) {
        self.teardown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn two_site_topology() -> Topology {
        Topology::new()
            .node("dev-a1", NodeKind::Device, false)
            .node("nat-a", NodeKind::Middlebox, true)
            .node("isp-a", NodeKind::Transit, true)
            .link(Link {
                a: "dev-a1".into(),
                b: "nat-a".into(),
                a_v4: Some(Ipv4Addr::new(192, 168, 1, 2)),
                b_v4: Some(Ipv4Addr::new(192, 168, 1, 1)),
                a_v6: None,
                b_v6: None,
                tier: Tier::Subscriber,
            })
            .link(Link {
                a: "nat-a".into(),
                b: "isp-a".into(),
                a_v4: Some(Ipv4Addr::new(198, 51, 100, 10)),
                b_v4: Some(Ipv4Addr::new(198, 51, 100, 1)),
                a_v6: Some("2001:db8:1::10".parse().unwrap()),
                b_v6: Some("2001:db8:1::1".parse().unwrap()),
                tier: Tier::Public,
            })
    }

    #[test]
    fn a_well_formed_topology_validates() {
        two_site_topology()
            .validate(AddressPlan::default())
            .expect("valid");
    }

    #[test]
    fn a_link_to_an_undeclared_node_is_refused() {
        let t = two_site_topology().link(Link {
            a: "dev-a1".into(),
            b: "ghost".into(),
            a_v4: None,
            b_v4: None,
            a_v6: None,
            b_v6: None,
            tier: Tier::Public,
        });
        assert!(t.validate(AddressPlan::default()).is_err());
    }

    #[test]
    fn a_public_link_using_real_internet_space_is_refused() {
        let mut t = two_site_topology();
        t.links[1].a_v4 = Some(Ipv4Addr::new(1, 1, 1, 1));
        let err = t.validate(AddressPlan::default()).expect_err("must refuse");
        assert!(err.to_string().contains("documentation space"), "{err}");
    }

    #[test]
    fn a_single_subscriber_cgnat_is_refused_because_it_is_not_a_cgnat() {
        let t = Topology::new()
            .node("cgnat-a", NodeKind::CarrierNat, true)
            .node("nat-a", NodeKind::Middlebox, true)
            .node("isp-a", NodeKind::Transit, true)
            .link(Link {
                a: "nat-a".into(),
                b: "cgnat-a".into(),
                a_v4: Some(Ipv4Addr::new(100, 80, 0, 2)),
                b_v4: Some(Ipv4Addr::new(100, 80, 0, 1)),
                a_v6: None,
                b_v6: None,
                tier: Tier::Carrier,
            })
            .link(Link {
                a: "cgnat-a".into(),
                b: "isp-a".into(),
                a_v4: Some(Ipv4Addr::new(198, 51, 100, 20)),
                b_v4: Some(Ipv4Addr::new(198, 51, 100, 1)),
                a_v6: None,
                b_v6: None,
                tier: Tier::Public,
            });
        let err = t.validate(AddressPlan::default()).expect_err("must refuse");
        assert!(err.to_string().contains("2 subscriber trees"), "{err}");
    }

    #[test]
    fn positive_control_two_subscriber_trees_validate() {
        // Without this the test above could be passing because the check is
        // always-on rather than because it counts trees.
        let t = Topology::new()
            .node("cgnat-a", NodeKind::CarrierNat, true)
            .node("nat-a", NodeKind::Middlebox, true)
            .node("nat-b", NodeKind::Middlebox, true)
            .node("isp-a", NodeKind::Transit, true)
            .link(Link {
                a: "nat-a".into(),
                b: "cgnat-a".into(),
                a_v4: Some(Ipv4Addr::new(100, 80, 0, 2)),
                b_v4: Some(Ipv4Addr::new(100, 80, 0, 1)),
                a_v6: None,
                b_v6: None,
                tier: Tier::Carrier,
            })
            .link(Link {
                a: "nat-b".into(),
                b: "cgnat-a".into(),
                a_v4: Some(Ipv4Addr::new(100, 80, 0, 3)),
                b_v4: Some(Ipv4Addr::new(100, 80, 0, 1)),
                a_v6: None,
                b_v6: None,
                tier: Tier::Carrier,
            })
            .link(Link {
                a: "cgnat-a".into(),
                b: "isp-a".into(),
                a_v4: Some(Ipv4Addr::new(198, 51, 100, 20)),
                b_v4: Some(Ipv4Addr::new(198, 51, 100, 1)),
                a_v6: None,
                b_v6: None,
                tier: Tier::Public,
            });
        t.validate(AddressPlan::default()).expect("two trees");
    }

    #[test]
    fn interface_names_fit_the_kernels_fifteen_byte_limit() {
        let l = Link {
            a: "a-very-long-node-name".into(),
            b: "another-very-long-name".into(),
            a_v4: None,
            b_v4: None,
            a_v6: None,
            b_v6: None,
            tier: Tier::Public,
        };
        assert!(l.if_a().len() <= 15, "{}", l.if_a());
        assert!(l.if_b().len() <= 15);
        assert_ne!(l.if_a(), l.if_b(), "the two ends must be distinguishable");
    }

    #[test]
    fn the_rendered_commands_create_every_node_and_address_both_families() {
        let cmds = two_site_topology().ip_commands();
        let flat: Vec<String> = cmds.iter().map(|c| c.join(" ")).collect();
        for n in ["dev-a1", "nat-a", "isp-a"] {
            assert!(
                flat.iter().any(|c| c == &format!("netns add {n}")),
                "no creation for {n}"
            );
        }
        assert!(
            flat.iter()
                .any(|c| c.contains("-6 addr add 2001:db8:1::10/64")),
            "the v6 half of the public link was not addressed"
        );
        assert!(flat.iter().any(|c| c.contains("addr add 198.51.100.10/24")));
    }

    #[test]
    fn realization_reports_what_this_host_actually_offers() {
        let mut b = LinuxNamespaceBackend::probe();
        let r = b.realization();
        // No assertion about WHICH one: this test runs on hosts that differ, and
        // asserting a particular answer would make it a test of the runner
        // rather than of the reporting. What must hold is that the answer is
        // consistent with the probe.
        if r.can_build_nodes() {
            assert!(b.capabilities().has(Facility::NetworkNamespaces));
        } else {
            assert!(!b.capabilities().has(Facility::NetworkNamespaces));
        }
        assert_eq!(r.has_name_table(), r == Realization::PersistentNetns);
    }

    #[test]
    fn building_on_a_host_without_a_name_table_is_unavailable_and_not_a_failure() {
        let mut b = LinuxNamespaceBackend::probe();
        if b.realization().has_name_table() {
            return; // this host can build for real; the other test covers it
        }
        let err = b
            .build(&two_site_topology(), AddressPlan::default())
            .expect_err("must not claim success");
        assert!(
            matches!(err, LabError::FacilityUnavailable { .. }),
            "a host that cannot build a topology must say so as an absence of \
             evidence, never as a failed assertion: {err}"
        );
    }
}
