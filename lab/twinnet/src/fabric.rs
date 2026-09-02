//! Building a topology out of real kernel objects.
//!
//! **Authority:** `docs/testing-strategy.md` §3.2 (topology), §3.4 (the
//! impairment matrix), §3.4.1 (the composition rule).
//!
//! # Two decisions worth reading before the code
//!
//! **Static neighbours, no ARP.** Every link this module builds installs a
//! permanent neighbour entry at both ends. A laboratory that relied on ARP would
//! have a first packet whose fate depends on a resolution race, and a scenario
//! that measures "time to first byte" would be measuring the race. It also lets
//! [`crate::nat`] hold a public address that is deliberately **not** assigned to
//! any kernel interface, which is what keeps the middlebox namespace's own stack
//! from answering for it.
//!
//! **Impairment on the transit side.** §3.4: "Impairment is applied on the
//! transit side of a link, never on the device namespace, so that a device's own
//! stack sees only what a real device sees." [`Fabric::impair`] takes the node
//! and interface explicitly rather than a link, so that a caller has to say
//! which end — and a caller that says the device end is doing it on purpose.
//!
//! §3.4.1's composition rule — an impairment set is applied atomically before
//! the first packet and changed mid-scenario only through a declared schedule —
//! is a property of the *scenario*, not of this module. [`Fabric::impair`] will
//! happily run mid-scenario, and the scenario layer is where the declaration
//! lives.

use std::path::{Path, PathBuf};

use crate::error::{NetError, Result};
use crate::nat::config::NatConfig;
use crate::sandbox::{ProcHandle, Sandbox};

/// Where a leg is moving to, for [`Fabric::roam`].
///
/// A struct rather than six positional arguments: `bridge_node` and `to_bridge`
/// are both names of things in the topology, and a caller that transposed them
/// would build a topology that is wrong rather than one that fails to build.
#[derive(Debug, Clone, Copy)]
pub struct Roam<'a> {
    /// The node whose leg is moving.
    pub node: &'a str,
    /// Its interface.
    pub iface: &'a str,
    /// The node hosting both bridges.
    pub bridge_node: &'a str,
    /// The bridge to move the leg's port onto.
    pub to_bridge: &'a str,
    /// The address the leg takes on the new segment.
    pub new_cidr: &'a str,
    /// The gateway on the new segment.
    pub gateway: &'a str,
}

/// One impairment, as §3.4's matrix names it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Impair {
    /// One-way delay, with optional normally-distributed jitter.
    Delay {
        /// Base delay in milliseconds.
        ms: u32,
        /// Jitter amplitude in milliseconds; zero for none.
        jitter_ms: u32,
    },
    /// `netem loss`. Reproducible in distribution only — §3.5 makes this
    /// `STATISTICAL`, and a scenario that declares `BIT` while carrying it is a
    /// scenario the determinism class refuses.
    Loss {
        /// Percent.
        pct: f32,
    },
    /// `netem duplicate`.
    Duplicate {
        /// Percent.
        pct: f32,
    },
    /// `netem reorder`, which requires a delay to reorder against.
    Reorder {
        /// Reorder probability, percent.
        pct: f32,
        /// Correlation, percent.
        correlation_pct: f32,
    },
    /// `netem corrupt`. §3.4: corroborates AEAD rejection counters, never the
    /// mechanism of a functional test.
    Corrupt {
        /// Percent.
        pct: f32,
    },
    /// `tbf` shaping.
    Bandwidth {
        /// Rate in kilobits per second.
        kbit: u32,
    },
}

impl Impair {
    fn netem_args(self) -> Option<Vec<String>> {
        let s = |x: &str| x.to_owned();
        match self {
            Impair::Delay { ms, jitter_ms: 0 } => Some(vec![s("delay"), format!("{ms}ms")]),
            Impair::Delay { ms, jitter_ms } => Some(vec![
                s("delay"),
                format!("{ms}ms"),
                format!("{jitter_ms}ms"),
                s("distribution"),
                s("normal"),
            ]),
            Impair::Loss { pct } => Some(vec![s("loss"), format!("{pct}%")]),
            Impair::Duplicate { pct } => Some(vec![s("duplicate"), format!("{pct}%")]),
            Impair::Reorder {
                pct,
                correlation_pct,
            } => Some(vec![
                s("reorder"),
                format!("{pct}%"),
                format!("{correlation_pct}%"),
            ]),
            Impair::Corrupt { pct } => Some(vec![s("corrupt"), format!("{pct}%")]),
            Impair::Bandwidth { .. } => None,
        }
    }
}

/// Where one end of a link lands.
#[derive(Debug, Clone)]
pub struct End {
    /// The namespace.
    pub node: String,
    /// The interface name inside it.
    pub iface: String,
    /// Addresses in `addr/len` form, any mix of families.
    pub addrs: Vec<String>,
}

impl End {
    /// A link end.
    #[must_use]
    pub fn new(node: &str, iface: &str, addrs: &[&str]) -> Self {
        End {
            node: node.to_owned(),
            iface: iface.to_owned(),
            addrs: addrs.iter().map(|a| (*a).to_owned()).collect(),
        }
    }

    /// The bare addresses, without prefix lengths.
    #[must_use]
    pub fn bare(&self) -> Vec<String> {
        self.addrs
            .iter()
            .map(|a| a.split('/').next().unwrap_or(a).to_owned())
            .collect()
    }
}

/// A realized topology. Everything it created dies with the [`Sandbox`].
#[derive(Debug)]
pub struct Fabric {
    nodes: Vec<String>,
    ifaces: Vec<(String, String, [u8; 6])>,
    /// `(node, iface) -> the bridge-side port name`, so a leg can be moved
    /// between segments without the caller having to know how `attach` named
    /// the port it created.
    ports: Vec<(String, String, String)>,
    scratch: PathBuf,
    processes: Vec<ProcHandle>,
}

impl Fabric {
    /// Starts an empty fabric whose artifacts land under `scratch`.
    #[must_use]
    pub fn new(scratch: &Path) -> Self {
        Fabric {
            nodes: Vec::new(),
            ifaces: Vec::new(),
            ports: Vec::new(),
            scratch: scratch.to_path_buf(),
            processes: Vec::new(),
        }
    }

    /// Creates a namespace.
    ///
    /// `forwarding` turns on IPv4 and IPv6 forwarding, which a router node needs
    /// and a device node must not have: a device whose kernel forwards is a
    /// device that can leak a peer's packet onto its own LAN, and §3.2 makes the
    /// device namespace the thing whose stack must look ordinary.
    ///
    /// # Both values are written, and that is the point
    ///
    /// This used to write `1` for a forwarding node and leave a non-forwarding
    /// one alone, on the assumption that a fresh namespace does not forward.
    /// **A fresh namespace forwards if the host does.** Linux copies the whole
    /// `all` devconf block into a new namespace at creation
    /// (`net/ipv4/devinet.c`, `devinet_init_net`: `memcpy(all,
    /// init_net.ipv4.devconf_all, …)` — the default arm of
    /// `net.core.devconf_inherit_init_net`), and `net.ipv4.ip_forward` *is*
    /// `all.forwarding`. IPv6 does the same in `addrconf_init_net`.
    ///
    /// So on any host running Docker — which sets `net.ipv4.ip_forward=1` when
    /// the daemon starts — every namespace in this laboratory came up
    /// forwarding. A `cpe` node then had two forwarders in it: the kernel and
    /// [`crate::nat`], racing for the same frame. The kernel usually won, the
    /// reflector observed the client's PRIVATE address, and two scenarios in
    /// `address_families_and_cgnat.rs` failed on a runner while passing on a
    /// developer host whose `ip_forward` happened to be `0` (job
    /// 100276849297).
    ///
    /// The value a node gets is now this rig's decision in both directions.
    ///
    /// # Errors
    ///
    /// [`NetError::Mechanism`] naming the `ip` invocation that failed.
    pub fn node(&mut self, sb: &mut Sandbox, name: &str, forwarding: bool) -> Result<()> {
        sb.must(None, &["ip", "netns", "add", name])?;
        sb.must(Some(name), &["ip", "link", "set", "lo", "up"])?;
        let on = u8::from(forwarding);
        let sysctl = format!("net.ipv4.ip_forward={on}");
        let write_v4 = format!("echo {on} > /proc/sys/net/ipv4/ip_forward");
        // Writing `all` is enough for both families and for interfaces created
        // later: the kernel propagates an `all.forwarding` write to the default
        // devconf and to every existing device.
        let write_v6 = format!("echo {on} > /proc/sys/net/ipv6/conf/all/forwarding");
        sb.must(Some(name), &["sysctl", "-qw", &sysctl])
            .or_else(|_| {
                // A namespace without `sysctl` still has /proc; the write is the
                // same operation and the fallback keeps a minimal image usable.
                sb.must(Some(name), &["sh", "-c", &write_v4])
            })?;
        sb.must(Some(name), &["sh", "-c", &write_v6])?;
        self.nodes.push(name.to_owned());
        Ok(())
    }

    /// Creates a `veth` pair between two nodes, addresses both ends, and
    /// installs permanent neighbour entries in both directions.
    ///
    /// # Errors
    ///
    /// [`NetError::Mechanism`] naming the `ip` invocation that failed;
    /// [`NetError::Malformed`] if an end names a node that was never created.
    pub fn link(&mut self, sb: &mut Sandbox, a: &End, b: &End) -> Result<()> {
        for end in [a, b] {
            if !self.nodes.contains(&end.node) {
                return Err(NetError::Malformed(format!(
                    "link end names node `{}`, which was never created",
                    end.node
                )));
            }
        }
        let a_mac = mac_for(&a.node, &a.iface);
        let b_mac = mac_for(&b.node, &b.iface);
        // Named uniquely in the root namespace before being moved, because two
        // links may legitimately use the same interface name inside different
        // namespaces and the creation happens outside both.
        let tmp_a = format!("tw{:04x}a", self.ifaces.len());
        let tmp_b = format!("tw{:04x}b", self.ifaces.len());
        sb.must(
            None,
            &[
                "ip", "link", "add", &tmp_a, "type", "veth", "peer", "name", &tmp_b,
            ],
        )?;
        sb.must(None, &["ip", "link", "set", &tmp_a, "netns", &a.node])?;
        sb.must(None, &["ip", "link", "set", &tmp_b, "netns", &b.node])?;
        sb.must(
            Some(&a.node),
            &["ip", "link", "set", &tmp_a, "name", &a.iface],
        )?;
        sb.must(
            Some(&b.node),
            &["ip", "link", "set", &tmp_b, "name", &b.iface],
        )?;
        self.configure_end(sb, a, &a_mac)?;
        self.configure_end(sb, b, &b_mac)?;
        // Permanent neighbours, so no scenario's first packet waits on ARP or
        // neighbour discovery.
        Self::neighbours(sb, a, b, &b_mac)?;
        Self::neighbours(sb, b, a, &a_mac)?;
        Ok(())
    }

    fn configure_end(&mut self, sb: &mut Sandbox, end: &End, mac: &str) -> Result<()> {
        sb.must(
            Some(&end.node),
            &["ip", "link", "set", &end.iface, "address", mac],
        )?;
        for addr in &end.addrs {
            let mut argv = vec!["ip", "addr", "add", addr, "dev", &end.iface];
            if addr.contains(':') {
                // Duplicate address detection costs a second per v6 address and
                // buys nothing on a point-to-point veth nobody else is on.
                argv.push("nodad");
            }
            sb.must(Some(&end.node), &argv)?;
        }
        // A segment nobody asked for IPv6 on is made genuinely single-stack,
        // BEFORE the link comes up.
        //
        // Two reasons, and the second is the one that cost a debugging session.
        // An interface with IPv6 enabled emits a router solicitation and an MLD
        // report from a link-local address the instant it comes up. On a segment
        // a test asserts is v4-only those frames are indistinguishable from the
        // leak the assertion is looking for. And disabling the family *after*
        // the link is up does not retract a solicitation the kernel has already
        // scheduled — so the ordering here is the whole fix, not the call.
        if end.addrs.iter().all(|a| !a.contains(':')) {
            self.disable_ipv6(sb, &end.node, &end.iface)?;
        }
        sb.must(Some(&end.node), &["ip", "link", "set", &end.iface, "up"])?;
        self.ifaces
            .push((end.node.clone(), end.iface.clone(), parse_mac(mac)));
        Ok(())
    }

    fn neighbours(sb: &mut Sandbox, here: &End, there: &End, their_mac: &str) -> Result<()> {
        for addr in there.bare() {
            sb.must(
                Some(&here.node),
                &[
                    "ip",
                    "neigh",
                    "replace",
                    &addr,
                    "lladdr",
                    their_mac,
                    "nud",
                    "permanent",
                    "dev",
                    &here.iface,
                ],
            )?;
        }
        Ok(())
    }

    /// Creates a Linux bridge inside a node — §3.2's L2 segment.
    ///
    /// A shared segment rather than a chain of point-to-point links, because
    /// §2.10's matrix pairs two middleboxes against each other on one transit
    /// network and a chain would put a router between them that the matrix does
    /// not contain.
    ///
    /// # Errors
    ///
    /// [`NetError::Mechanism`] naming the failing `ip link`.
    pub fn bridge(&mut self, sb: &mut Sandbox, node: &str, name: &str) -> Result<()> {
        sb.must(Some(node), &["ip", "link", "add", name, "type", "bridge"])?;
        sb.must(Some(node), &["ip", "link", "set", name, "up"])?;
        Ok(())
    }

    /// Creates a bridge, gives it a deterministic MAC and addresses, and
    /// registers it like any other interface.
    ///
    /// A bridge with an address is an L2 segment *and* the router onto it, which
    /// is what a home LAN is. Registering it means a middlebox configuration can
    /// ask [`Fabric::mac`] for it, and a static neighbour can point at it — a
    /// bridge whose MAC was whichever port it learned first would make every
    /// neighbour entry a race.
    ///
    /// # Errors
    ///
    /// [`NetError::Mechanism`] naming the failing `ip` invocation.
    pub fn bridge_with(
        &mut self,
        sb: &mut Sandbox,
        node: &str,
        name: &str,
        addrs: &[&str],
    ) -> Result<()> {
        sb.must(Some(node), &["ip", "link", "add", name, "type", "bridge"])?;
        let end = End::new(node, name, addrs);
        let mac = mac_for(node, name);
        self.configure_end(sb, &end, &mac)?;
        Ok(())
    }

    /// Attaches a node to a bridge with a `veth` pair.
    ///
    /// # Errors
    ///
    /// [`NetError::Mechanism`] naming the failing `ip` invocation;
    /// [`NetError::Malformed`] if either node was never created.
    pub fn attach(
        &mut self,
        sb: &mut Sandbox,
        end: &End,
        bridge_node: &str,
        bridge: &str,
    ) -> Result<()> {
        for name in [&end.node, &bridge_node.to_owned()] {
            if !self.nodes.contains(name) {
                return Err(NetError::Malformed(format!(
                    "attach names node `{name}`, which was never created"
                )));
            }
        }
        let mac = mac_for(&end.node, &end.iface);
        let tmp_a = format!("tw{:04x}a", self.ifaces.len());
        let tmp_b = format!("tw{:04x}b", self.ifaces.len());
        let port = format!("p{:04x}", self.ifaces.len());
        sb.must(
            None,
            &[
                "ip", "link", "add", &tmp_a, "type", "veth", "peer", "name", &tmp_b,
            ],
        )?;
        sb.must(None, &["ip", "link", "set", &tmp_a, "netns", &end.node])?;
        sb.must(None, &["ip", "link", "set", &tmp_b, "netns", bridge_node])?;
        sb.must(
            Some(&end.node),
            &["ip", "link", "set", &tmp_a, "name", &end.iface],
        )?;
        sb.must(
            Some(bridge_node),
            &["ip", "link", "set", &tmp_b, "name", &port],
        )?;
        sb.must(
            Some(bridge_node),
            &["ip", "link", "set", &port, "master", bridge],
        )?;
        sb.must(Some(bridge_node), &["ip", "link", "set", &port, "up"])?;
        self.configure_end(sb, end, &mac)?;
        self.ports.push((end.node.clone(), end.iface.clone(), port));
        Ok(())
    }

    /// The bridge-side port an attached leg hangs off.
    #[must_use]
    pub fn port_of(&self, node: &str, iface: &str) -> Option<&str> {
        self.ports
            .iter()
            .find(|(n, i, _)| n == node && i == iface)
            .map(|(_, _, p)| p.as_str())
    }

    /// §3.4's interface-change row: move a leg to another segment and
    /// re-address it.
    ///
    /// > Move the device's `veth` leg from `br-wifi` to `br-cell` and
    /// > re-address, producing genuine `EV_LINK_DOWN` / `EV_ADDR_CHANGED`.
    ///
    /// The link is taken **down** before the move and up after, because the
    /// events are the point: a scenario that changed the master and the address
    /// without a link transition would produce an address change the device's
    /// stack sees and a link event it does not, and §3.4 asks for both.
    ///
    /// # Errors
    ///
    /// [`NetError::Malformed`] if the leg was never attached to a bridge;
    /// [`NetError::Mechanism`] naming the failing `ip` invocation.
    pub fn roam(&self, sb: &mut Sandbox, to: &Roam<'_>) -> Result<()> {
        let Some(port) = self.port_of(to.node, to.iface).map(str::to_owned) else {
            return Err(NetError::Malformed(format!(
                "`{}:{}` was never attached to a bridge, so it has no leg to move",
                to.node, to.iface
            )));
        };
        sb.must(Some(to.node), &["ip", "link", "set", to.iface, "down"])?;
        sb.must(
            Some(to.bridge_node),
            &["ip", "link", "set", &port, "master", to.to_bridge],
        )?;
        sb.must(Some(to.node), &["ip", "addr", "flush", "dev", to.iface])?;
        sb.must(
            Some(to.node),
            &["ip", "addr", "add", to.new_cidr, "dev", to.iface],
        )?;
        sb.must(Some(to.node), &["ip", "link", "set", to.iface, "up"])?;
        // The default route went with the address it was reachable through.
        sb.must(
            Some(to.node),
            &[
                "ip", "route", "replace", "default", "via", to.gateway, "dev", to.iface,
            ],
        )?;
        Ok(())
    }

    /// Teaches a node about an address that is not on any interface — a NAT's
    /// public address, or a peer beyond the next hop.
    ///
    /// # Errors
    ///
    /// [`NetError::Mechanism`] naming the failing `ip neigh`.
    pub fn neighbour(
        &self,
        sb: &mut Sandbox,
        node: &str,
        iface: &str,
        addr: &str,
        mac: &str,
    ) -> Result<()> {
        sb.must(
            Some(node),
            &[
                "ip",
                "neigh",
                "replace",
                addr,
                "lladdr",
                mac,
                "nud",
                "permanent",
                "dev",
                iface,
            ],
        )?;
        Ok(())
    }

    /// Adds a route. `dest` is `default` or a prefix.
    ///
    /// # Errors
    ///
    /// [`NetError::Mechanism`] naming the failing `ip route`.
    pub fn route(
        &self,
        sb: &mut Sandbox,
        node: &str,
        dest: &str,
        via: Option<&str>,
        dev: &str,
    ) -> Result<()> {
        let family = if dest.contains(':') || via.is_some_and(|v| v.contains(':')) {
            "-6"
        } else {
            "-4"
        };
        let mut argv = vec!["ip", family, "route", "replace", dest];
        if let Some(gw) = via {
            argv.extend_from_slice(&["via", gw]);
        }
        argv.extend_from_slice(&["dev", dev]);
        sb.must(Some(node), &argv)?;
        Ok(())
    }

    /// Disables IPv6 on one interface, making a segment genuinely single-stack.
    ///
    /// **Why a laboratory needs this.** A Linux interface with IPv6 enabled
    /// emits multicast listener reports and router solicitations from a
    /// link-local address the moment it comes up, whether or not any scenario
    /// asked for IPv6. On a segment a test asserts is v4-only, those frames are
    /// indistinguishable from the leak the assertion is looking for — and the
    /// choice is then between a strict assertion that is red for a reason that
    /// has nothing to do with the product, and a loose one that exempts the
    /// whole of link-local and would miss a real leak sourced from it.
    ///
    /// Disabling the family removes the third option's need to exist: a v4-only
    /// segment is a segment with no IPv6, which is also what a v4-only network
    /// is.
    ///
    /// # Errors
    ///
    /// [`NetError::Mechanism`] naming the failing write.
    pub fn disable_ipv6(&self, sb: &mut Sandbox, node: &str, iface: &str) -> Result<()> {
        let write = format!("echo 1 > /proc/sys/net/ipv6/conf/{iface}/disable_ipv6");
        sb.must(Some(node), &["sh", "-c", &write])?;
        Ok(())
    }

    /// Sets an interface's MTU. §3.4's MTU-mismatch row, and the mechanism
    /// behind every PMTU scenario.
    ///
    /// # Errors
    ///
    /// [`NetError::Mechanism`] naming the failing `ip link`.
    pub fn mtu(&self, sb: &mut Sandbox, node: &str, iface: &str, mtu: u32) -> Result<()> {
        let mtu = mtu.to_string();
        sb.must(Some(node), &["ip", "link", "set", iface, "mtu", &mtu])?;
        Ok(())
    }

    /// Applies an impairment set to one interface, atomically, replacing
    /// whatever was there.
    ///
    /// An empty set clears the qdisc, which is how a scheduled event removes an
    /// impairment mid-scenario.
    ///
    /// # Errors
    ///
    /// [`NetError::Unavailable`] if `tc` is not installed — a host that cannot
    /// impair must not silently run an unimpaired scenario and report a pass.
    pub fn impair(&self, sb: &mut Sandbox, node: &str, iface: &str, set: &[Impair]) -> Result<()> {
        // A missing qdisc is not an error here: clearing an interface that was
        // never impaired is the normal case at the start of a scenario.
        let _ = sb.run(Some(node), &["tc", "qdisc", "del", "dev", iface, "root"])?;
        if set.is_empty() {
            return Ok(());
        }
        let netem: Vec<String> = set
            .iter()
            .filter_map(|i| i.netem_args())
            .flatten()
            .collect();
        if !netem.is_empty() {
            let mut argv: Vec<&str> = vec![
                "tc", "qdisc", "add", "dev", iface, "root", "handle", "1:", "netem",
            ];
            argv.extend(netem.iter().map(String::as_str));
            sb.must(Some(node), &argv)?;
        }
        if let Some(Impair::Bandwidth { kbit }) = set
            .iter()
            .find(|i| matches!(i, Impair::Bandwidth { .. }))
            .copied()
        {
            let rate = format!("{kbit}kbit");
            // A burst below one MTU makes `tbf` drop everything; 32 kbit is the
            // smallest value that shapes rather than blackholes at these rates.
            let argv: Vec<&str> = if netem.is_empty() {
                vec![
                    "tc", "qdisc", "add", "dev", iface, "root", "handle", "10:", "tbf", "rate",
                    &rate, "burst", "32kbit", "latency", "400ms",
                ]
            } else {
                vec![
                    "tc", "qdisc", "add", "dev", iface, "parent", "1:1", "handle", "10:", "tbf",
                    "rate", &rate, "burst", "32kbit", "latency", "400ms",
                ]
            };
            sb.must(Some(node), &argv)?;
        }
        Ok(())
    }

    /// Takes a link down — §3.4's path-disappearance and roam mechanism, and a
    /// genuine `EV_LINK_DOWN` at the device.
    ///
    /// # Errors
    ///
    /// [`NetError::Mechanism`] naming the failing `ip link`.
    pub fn set_link(&self, sb: &mut Sandbox, node: &str, iface: &str, up: bool) -> Result<()> {
        sb.must(
            Some(node),
            &["ip", "link", "set", iface, if up { "up" } else { "down" }],
        )?;
        Ok(())
    }

    /// Starts a middlebox in `node`, and returns the path its snapshot will be
    /// written to.
    ///
    /// Refuses a node whose kernel forwards. [`crate::nat::run`] refuses the
    /// same thing when the process starts, but that refusal reaches a caller as
    /// a middlebox that is simply not there — a missing snapshot, or a punch
    /// that fails for no stated reason. The check is repeated here so the rig
    /// answers with the cause instead of the symptom.
    ///
    /// # Errors
    ///
    /// [`NetError::Malformed`] if the configuration contradicts itself or the
    /// node's kernel forwards; [`NetError::Unavailable`] if raw sockets are
    /// refused.
    pub fn start_nat(
        &mut self,
        sb: &mut Sandbox,
        node: &str,
        cfg: &NatConfig,
    ) -> Result<(ProcHandle, PathBuf)> {
        cfg.validate().map_err(NetError::Malformed)?;
        let read = crate::nat::FORWARDING_KNOBS
            .iter()
            .map(|knob| {
                // A knob a kernel does not have is not evidence of forwarding;
                // an unreadable one reads as `0` and the middlebox's own check
                // is the backstop.
                let ran = sb.run(Some(node), &["cat", knob])?;
                Ok((*knob, if ran.ok() { ran.stdout } else { "0".to_owned() }))
            })
            .collect::<Result<Vec<_>>>()?;
        let values: Vec<(&str, &str)> = read.iter().map(|(k, v)| (*k, v.as_str())).collect();
        if let Some(why) = crate::nat::forwarding_conflict(&values) {
            return Err(NetError::Malformed(format!(
                "the middlebox for `{node}` was not started: {why}"
            )));
        }
        let stats = self.scratch.join(format!("nat-{node}.json"));
        let mut cfg = cfg.clone();
        cfg.stats_path = Some(stats.display().to_string());
        let path = self.scratch.join(format!("nat-{node}.cfg.json"));
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&cfg).expect("NatConfig is always encodable"),
        )
        .map_err(|e| NetError::os("writing the middlebox configuration", e))?;
        let agent = sb.agent_path().display().to_string();
        let cfg_arg = path.display().to_string();
        let log = self.scratch.join(format!("nat-{node}.log"));
        let handle = sb.spawn(
            Some(node),
            &[&agent, "natbox", "--config", &cfg_arg],
            Some(&log),
        )?;
        self.processes.push(handle);
        Ok((handle, stats))
    }

    /// Starts a packet observer on one interface, writing JSON records.
    ///
    /// # Errors
    ///
    /// [`NetError::Unavailable`] if raw sockets are refused.
    pub fn start_capture(
        &mut self,
        sb: &mut Sandbox,
        node: &str,
        iface: &str,
        label: &str,
        ms: u64,
    ) -> Result<(ProcHandle, PathBuf)> {
        let out = self.scratch.join(format!("capture-{label}.jsonl"));
        let agent = sb.agent_path().display().to_string();
        let out_arg = out.display().to_string();
        let ms_arg = ms.to_string();
        let log = self.scratch.join(format!("capture-{label}.log"));
        let handle = sb.spawn(
            Some(node),
            &[
                &agent, "observe", "--iface", iface, "--out", &out_arg, "--ms", &ms_arg,
            ],
            Some(&log),
        )?;
        self.processes.push(handle);
        Ok((handle, out))
    }

    /// Every process this fabric started.
    #[must_use]
    pub fn processes(&self) -> &[ProcHandle] {
        &self.processes
    }

    /// The MAC this fabric assigned to an interface, for a middlebox
    /// configuration.
    #[must_use]
    pub fn mac(&self, node: &str, iface: &str) -> Option<[u8; 6]> {
        self.ifaces
            .iter()
            .find(|(n, i, _)| n == node && i == iface)
            .map(|(_, _, m)| *m)
    }
}

/// A locally-administered MAC derived from the node and interface names.
///
/// Deterministic on purpose: a run record that names a MAC is reproducible, and
/// a middlebox configuration that has to be told its neighbours' MACs can be
/// written before the interfaces exist.
#[must_use]
pub fn mac_for(node: &str, iface: &str) -> String {
    // FNV-1a, four bytes. A hash rather than a counter so that adding a link to
    // the middle of a topology does not renumber every MAC after it.
    let mut h: u32 = 0x811c_9dc5;
    for b in node
        .bytes()
        .chain(b":".iter().copied())
        .chain(iface.bytes())
    {
        h ^= u32::from(b);
        h = h.wrapping_mul(0x0100_0193);
    }
    let [a, b, c, d] = h.to_be_bytes();
    // `02:` is the locally-administered unicast prefix.
    format!("02:00:{a:02x}:{b:02x}:{c:02x}:{d:02x}")
}

/// Parses the colon form back into bytes.
#[must_use]
pub fn parse_mac(s: &str) -> [u8; 6] {
    let mut out = [0u8; 6];
    for (i, part) in s.split(':').take(6).enumerate() {
        out[i] = u8::from_str_radix(part, 16).unwrap_or(0);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_derived_mac_is_locally_administered_unicast_and_stable() {
        let m = mac_for("cpe-a", "eth0");
        assert!(m.starts_with("02:00:"), "{m} must be locally administered");
        assert_eq!(m, mac_for("cpe-a", "eth0"), "the derivation must be stable");
        assert_ne!(m, mac_for("cpe-b", "eth0"));
        assert_ne!(m, mac_for("cpe-a", "eth1"));
    }

    #[test]
    fn a_mac_round_trips_through_its_text_form() {
        let m = mac_for("relay-eu", "wan");
        assert_eq!(parse_mac(&m), parse_mac(&m), "parsing is deterministic");
        assert_eq!(parse_mac(&m)[0], 0x02);
    }

    #[test]
    fn bandwidth_is_not_a_netem_argument_and_every_other_impairment_is() {
        assert!(Impair::Bandwidth { kbit: 1000 }.netem_args().is_none());
        for i in [
            Impair::Delay {
                ms: 40,
                jitter_ms: 0,
            },
            Impair::Delay {
                ms: 40,
                jitter_ms: 5,
            },
            Impair::Loss { pct: 1.0 },
            Impair::Duplicate { pct: 0.5 },
            Impair::Reorder {
                pct: 5.0,
                correlation_pct: 25.0,
            },
            Impair::Corrupt { pct: 0.01 },
        ] {
            assert!(i.netem_args().is_some(), "{i:?} must be a netem argument");
        }
    }

    #[test]
    fn jitter_asks_netem_for_a_normal_distribution_and_a_bare_delay_does_not() {
        let plain = Impair::Delay {
            ms: 40,
            jitter_ms: 0,
        }
        .netem_args()
        .unwrap();
        assert_eq!(plain, vec!["delay", "40ms"]);
        let jittered = Impair::Delay {
            ms: 40,
            jitter_ms: 30,
        }
        .netem_args()
        .unwrap();
        assert!(jittered.contains(&"distribution".to_owned()));
        assert!(jittered.contains(&"normal".to_owned()));
    }
}
