//! Prebuilt topologies: the rigs every scenario in this laboratory is run on.
//!
//! **Why these live in the library rather than in a test helper.** They were a
//! `tests/common/mod.rs` first, and that was wrong in one specific way: the
//! `twinlab-scenarios run` subcommand has to build the SAME topology a test
//! builds, or a scenario that passes in CI is not the scenario the catalogue
//! describes. §3.1's realization principle is about the product not being able
//! to detect the laboratory; §3.6's reproducibility is about two runs of one
//! scenario id being the same experiment, and two copies of a topology is the
//! shortest path to breaking it.
//!
//! # The three rigs
//!
//! | Rig | Shape | What it is for |
//! |---|---|---|
//! | [`build_single_site`] | `client ─ cpe ─ reflector` | one middlebox, measured from behind: §3.4.2's personality conformance, the impairment matrix, the CGNAT tier |
//! | [`build_two_site`] | two middleboxes on one bridged transit, two relays, a v4 and a v6 reflector | §2.10's class-pair matrix, relay fallback and failover, the chaos family |
//! | [`build_tunnel_site`] | device with a TUN, an exit, a control plane, a rogue resolver, a LAN | the fail-closed oracle: full tunnel, split tunnel, LAN access, kill switch |
//!
//! Every one of them dies with its [`Sandbox`]: the namespaces have no process
//! in them and no bind mount holding them open once the agent exits, so a
//! panicking scenario leaks nothing onto a shared runner.

#![allow(clippy::too_many_lines)]

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use crate::error::NetError;
use crate::fabric::{End, Fabric};
use crate::nat::config::{Egress, Filtering, Mapping, NatConfig, Neighbour};
use crate::sandbox::Sandbox;

/// The reflector's primary address.
pub const REFLECT_A: &str = "203.0.113.10";
/// The reflector's alternate address.
pub const REFLECT_B: &str = "203.0.113.11";
/// The middlebox's external address, owned in userspace.
pub const PUBLIC_V4: &str = "198.51.100.7";
/// The client's address behind the middlebox.
pub const CLIENT_V4: &str = "10.0.1.2";
/// A second client behind the same middlebox, for hairpinning and CGNAT.
pub const CLIENT2_V4: &str = "10.0.1.3";
/// The reflector's primary port.
pub const PORT_A: u16 = 3478;
/// The reflector's alternate port.
pub const PORT_B: u16 = 3479;

/// The facilities every fabric test needs. A host missing one of these produces
/// `Unavailable`, never a pass.
pub const REQUIRED: &[&str] = &["network-namespaces", "veth", "af-packet", "userspace-nat"];

/// A built rig, alive until it is dropped.
pub struct Rig {
    /// The sandbox. Public because a test drives processes through it.
    pub sb: Sandbox,
    /// The fabric.
    pub fabric: Fabric,
    /// Where artifacts land.
    pub scratch: PathBuf,
    /// The infrastructure processes, by node name, so a chaos scenario can
    /// terminate one by the name the topology calls it.
    pub relays: Vec<(String, crate::ProcHandle)>,
    /// The address the device binds its underlay socket to.
    ///
    /// Behind a middlebox this is the device's PRIVATE address, and its public
    /// one is the middlebox's. Recorded on the rig rather than assumed by the
    /// caller, because a tunnel that bound the public address on a device that
    /// does not have it fails with `EADDRNOTAVAIL` — a failure that looks
    /// nothing like "the scenario has a NAT in it now".
    pub device_bind: String,
}

impl Rig {
    /// The handle for a named infrastructure process.
    #[must_use]
    pub fn process(&self, node: &str) -> Option<crate::ProcHandle> {
        self.relays.iter().find(|(n, _)| n == node).map(|(_, h)| *h)
    }
}

/// Starts a sandbox, or reports the facility this host lacks.
///
/// Returns [`NetError::Unavailable`] — never a panic and never a silent
/// success — when the host cannot realize what a rig needs. A caller converts
/// that into `Verdict::Unavailable`; nothing in this crate converts it into a
/// pass.
///
/// # Errors
///
/// [`NetError::Unavailable`] naming the missing facility and the evidence of
/// its absence.
pub fn sandbox() -> Result<Sandbox, NetError> {
    let sb = Sandbox::start()?;
    sb.require(REQUIRED)?;
    Ok(sb)
}

/// A scratch directory for one test's artifacts.
pub fn scratch(label: &str) -> PathBuf {
    let base = std::env::var("TWINNET_SCRATCH")
        .map_or_else(|_| std::env::temp_dir().join("twinnet"), PathBuf::from);
    let dir = base.join(label);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

/// A personality, in the two independent axes §3.3 insists on.
pub struct Personality {
    /// §3.3's name.
    pub name: &'static str,
    /// The mapping axis.
    pub mapping: Mapping,
    /// The filtering axis.
    pub filtering: Filtering,
}

/// §3.3's table, minus `N-NAT64`, which is a different topology rather than a
/// different middlebox.
pub const PERSONALITIES: &[Personality] = &[
    Personality {
        name: "N-ROUTED",
        mapping: Mapping::None,
        filtering: Filtering::None,
    },
    Personality {
        name: "N-EIM-EIF",
        mapping: Mapping::EndpointIndependent,
        filtering: Filtering::EndpointIndependent,
    },
    Personality {
        name: "N-EIM-ADF",
        mapping: Mapping::EndpointIndependent,
        filtering: Filtering::AddressDependent,
    },
    Personality {
        name: "N-EIM-APDF",
        mapping: Mapping::EndpointIndependent,
        filtering: Filtering::AddressPortDependent,
    },
    Personality {
        name: "N-APDM-APDF-RAND",
        mapping: Mapping::AddressPortDependentRandom,
        filtering: Filtering::AddressPortDependent,
    },
    Personality {
        name: "N-APDM-APDF-SEQ",
        mapping: Mapping::AddressPortDependentSequential,
        filtering: Filtering::AddressPortDependent,
    },
];

/// Builds the standard three-node topology and starts the reflector.
///
/// # Errors
///
/// Any [`NetError`] from the fabric; a caller asserts on it rather than
/// unwrapping so a mechanism failure names the `ip` line that produced it.
pub fn build_single_site(label: &str, second_client: bool) -> Result<Rig, NetError> {
    let mut sb = sandbox()?;
    let scratch = scratch(label);
    let mut fabric = Fabric::new(&scratch);

    fabric.node(&mut sb, "client", false)?;
    fabric.node(&mut sb, "cpe", false)?;
    fabric.node(&mut sb, "reflector", false)?;
    if second_client {
        fabric.node(&mut sb, "client2", false)?;
    }

    // The LAN is a bridge, not a point-to-point link: two hosts on one segment
    // is what makes a local-direct path and a shared carrier tier expressible,
    // and a chain of /30s would make every "two devices on the same network"
    // scenario a different topology from the one it claims to be.
    fabric.bridge_with(&mut sb, "cpe", "lan", &["10.0.1.1/24"])?;
    fabric.attach(
        &mut sb,
        &End::new("client", "lan", &["10.0.1.2/24"]),
        "cpe",
        "lan",
    )?;
    fabric.link(
        &mut sb,
        &End::new("cpe", "wan", &["203.0.113.1/24"]),
        &End::new("reflector", "wan", &["203.0.113.10/24", "203.0.113.11/24"]),
    )?;
    if second_client {
        // A second host on the SAME segment, so hairpinning, a local-direct path
        // and a shared public address all have two subscribers to be about.
        fabric.attach(
            &mut sb,
            &End::new("client2", "lan", &["10.0.1.3/24"]),
            "cpe",
            "lan",
        )?;
        fabric.route(&mut sb, "client2", "default", Some("10.0.1.1"), "lan")?;
        let gw = fabric.mac("cpe", "lan").expect("the LAN gateway's MAC");
        fabric.neighbour(&mut sb, "client2", "lan", "10.0.1.1", &mac_text(gw))?;
        // The two hosts know each other's link-layer address, so a local-direct
        // exchange does not begin with an ARP race.
        let a = fabric.mac("client", "lan").expect("client's MAC");
        let b = fabric.mac("client2", "lan").expect("client2's MAC");
        fabric.neighbour(&mut sb, "client", "lan", CLIENT2_V4, &mac_text(b))?;
        fabric.neighbour(&mut sb, "client2", "lan", CLIENT_V4, &mac_text(a))?;
    }

    fabric.route(&mut sb, "client", "default", Some("10.0.1.1"), "lan")?;
    let gw = fabric.mac("cpe", "lan").expect("the LAN gateway's MAC");
    fabric.neighbour(&mut sb, "client", "lan", "10.0.1.1", &mac_text(gw))?;
    // The reflector reaches the middlebox's userspace-owned public address by a
    // host route with a permanent neighbour: nothing answers ARP for it, on
    // purpose.
    fabric.route(&mut sb, "reflector", PUBLIC_V4, None, "wan")?;
    let cpe_wan_mac = fabric
        .mac("cpe", "wan")
        .expect("the fabric assigned the cpe's wan MAC");
    fabric.neighbour(
        &mut sb,
        "reflector",
        "wan",
        PUBLIC_V4,
        &mac_text(cpe_wan_mac),
    )?;
    // `N-ROUTED` translates nothing, so the client's own address arrives at the
    // reflector and needs a way back. Installed unconditionally: a return route
    // that exists only for one personality would make `N-ROUTED` the odd case
    // in the topology as well as in the middlebox, and a difference in the
    // topology is a difference the scenario did not ask for.
    fabric.route(&mut sb, "reflector", "10.0.1.0/24", None, "wan")?;
    for host in [CLIENT_V4, CLIENT2_V4] {
        fabric.neighbour(&mut sb, "reflector", "wan", host, &mac_text(cpe_wan_mac))?;
    }

    let agent = sb.agent_path().display().to_string();
    let log = scratch.join("reflector.log");
    let reflector = sb.spawn(
        Some("reflector"),
        &[
            &agent,
            "reflect",
            "--primary",
            REFLECT_A,
            "--alternate",
            REFLECT_B,
            "--port-a",
            &PORT_A.to_string(),
            "--port-b",
            &PORT_B.to_string(),
            "--ms",
            "120000",
        ],
        Some(&log),
    )?;

    Ok(Rig {
        sb,
        fabric,
        scratch,
        relays: vec![("reflector".to_owned(), reflector)],
        device_bind: DEVICE_UNDERLAY.to_owned(),
    })
}

/// A middlebox configuration for one personality on the standard rig.
#[must_use]
pub fn single_site_nat(rig: &Rig, p: &Personality) -> NatConfig {
    NatConfig {
        pref64: None,
        egress_mtu: None,
        drop_pmtu_icmp: false,
        outside_neighbours: Vec::new(),
        inside_prefixes: vec!["10.0.1.0/24".to_owned()],
        personality: p.name.to_owned(),
        mapping: p.mapping,
        filtering: p.filtering,
        inside_if: "lan".to_owned(),
        outside_if: "wan".to_owned(),
        inside_mac: rig.fabric.mac("cpe", "lan").expect("the cpe lan MAC"),
        outside_mac: rig.fabric.mac("cpe", "wan").expect("the cpe wan MAC"),
        inside_peer_mac: rig.fabric.mac("client", "lan").expect("the client's MAC"),
        outside_peer_mac: rig
            .fabric
            .mac("reflector", "wan")
            .expect("the reflector's MAC"),
        public_v4: Some(PUBLIC_V4.parse().expect("a literal")),
        public_v6: None,
        port_low: 40_000,
        port_high: 40_500,
        mapping_lifetime_ms: 30_000,
        hairpin: false,
        seed: 0x5EED,
        egress: Egress::Allow,
        stats_path: None,
    }
}

/// `02:00:…` text form, for `ip neigh`.
#[must_use]
pub fn mac_text(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// The client's address as an [`IpAddr`].
#[must_use]
pub fn client_ip() -> IpAddr {
    IpAddr::V4(CLIENT_V4.parse::<Ipv4Addr>().expect("a literal"))
}

/// Reads a middlebox snapshot, waiting until it reflects something that has
/// already happened.
///
/// **Why this is not a sleep.** A middlebox writes its snapshot on a timer, so a
/// test that read the file the instant after its traffic finished could read the
/// snapshot from *before* that traffic and conclude the middlebox did nothing —
/// which is what happened, and it reported "something else carried the traffic"
/// about a translator that had carried it correctly.
///
/// The predicate is the observation the caller is waiting for, and the deadline
/// is what keeps it a test rather than a hang. When the deadline passes the last
/// snapshot is returned anyway, so the caller's own assertion fails with the
/// real numbers instead of this function inventing an error.
///
/// It cannot make a failing assertion pass: waiting longer for a counter that
/// never moves returns a snapshot in which it has not moved.
///
/// # Errors
///
/// [`NetError::Os`] if the snapshot never appears at all, which means the
/// middlebox never started.
pub fn await_snapshot(
    path: &std::path::Path,
    timeout: std::time::Duration,
    ready: impl Fn(&serde_json::Value) -> bool,
) -> Result<serde_json::Value, NetError> {
    let deadline = std::time::Instant::now() + timeout;
    let mut last = None;
    loop {
        if let Ok(text) = std::fs::read_to_string(path) {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
                if ready(&value) {
                    return Ok(value);
                }
                last = Some(value);
            }
        }
        if std::time::Instant::now() >= deadline {
            return last.ok_or_else(|| {
                NetError::os(
                    format!("no middlebox snapshot ever appeared at {}", path.display()),
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "the middlebox never started, or never wrote one",
                    ),
                )
            });
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
}

/// A counter out of a snapshot, or zero.
#[must_use]
pub fn counter(snapshot: &serde_json::Value, name: &str) -> u64 {
    snapshot["counters"][name].as_u64().unwrap_or(0)
}

/// Gives a spawned process a moment to bind before traffic is aimed at it.
///
/// A fixed sleep rather than a readiness handshake, and it is worth saying why:
/// the processes involved are a UDP reflector and a raw-socket middlebox, and
/// neither has a readiness surface that is not itself a socket this rig would
/// then have to poll. The sleep is generous, bounded, and cannot make a test
/// pass that would otherwise fail — a middlebox that never started produces no
/// traffic and the assertion fails.
pub fn settle() {
    std::thread::sleep(std::time::Duration::from_millis(600));
}

// ===========================================================================
// The two-site rig: §2.10's matrix needs two middleboxes on one transit
// segment, not a client and a server.
// ===========================================================================

/// Site A's public address.
pub const PUBLIC_A: &str = "198.51.100.7";
/// Site B's public address.
pub const PUBLIC_B: &str = "198.51.100.8";
/// The primary relay, in the first region.
pub const RELAY_EU: &str = "203.0.113.20";
/// The standby relay, in a second region.
pub const RELAY_US: &str = "203.0.113.21";
/// The port both relays listen on.
pub const RELAY_PORT: u16 = 7777;
/// The reflector's primary IPv6 address. §3.2's last row — "if both ends have
/// working IPv6, every cell is D" — is the single highest-leverage claim in the
/// traversal design, and a laboratory with no v6 reflector cannot test it.
pub const REFLECT_A6: &str = "2001:db8:113::10";
/// Its alternate IPv6 address.
pub const REFLECT_B6: &str = "2001:db8:113::11";
/// Site A's IPv6 LAN prefix. Native, not translated: §3.2's last row is the
/// case that must keep working.
pub const SITE_A_V6: &str = "2001:db8:a::2";
/// Site B's.
pub const SITE_B_V6: &str = "2001:db8:b::2";

/// A two-site topology sharing one L2 transit segment.
///
/// ```text
///  peer-a ─ lan ─[ cpe-a ]─┐                 ┌─[ cpe-b ]─ lan ─ peer-b
///  10.0.1.2      10.0.1.1  ├── br0 (transit) ┤  10.0.2.1       10.0.2.2
///                203.0.113.1│                 │203.0.113.2
///                           └── reflector ────┘
///                              203.0.113.10/.11
/// ```
///
/// The transit is a bridge rather than a chain of point-to-point links: §2.10
/// pairs two middleboxes against each other, and a router between them would be
/// a third middlebox the matrix does not contain.
pub fn build_two_site(label: &str) -> Result<Rig, NetError> {
    let mut sb = sandbox()?;
    let scratch = scratch(label);
    let mut fabric = Fabric::new(&scratch);

    for node in [
        "peer-a",
        "peer-b",
        "cpe-a",
        "cpe-b",
        "reflector",
        "relay-eu",
        "relay-us",
        "transit",
    ] {
        fabric.node(&mut sb, node, false)?;
    }
    fabric.bridge(&mut sb, "transit", "br0")?;

    fabric.link(
        &mut sb,
        &End::new("peer-a", "lan", &["10.0.1.2/24", "2001:db8:a::2/64"]),
        &End::new("cpe-a", "lan", &["10.0.1.1/24", "2001:db8:a::1/64"]),
    )?;
    fabric.link(
        &mut sb,
        &End::new("peer-b", "lan", &["10.0.2.2/24", "2001:db8:b::2/64"]),
        &End::new("cpe-b", "lan", &["10.0.2.1/24", "2001:db8:b::1/64"]),
    )?;
    fabric.attach(
        &mut sb,
        &End::new("cpe-a", "wan", &["203.0.113.1/24", "2001:db8:113::1/64"]),
        "transit",
        "br0",
    )?;
    fabric.attach(
        &mut sb,
        &End::new("cpe-b", "wan", &["203.0.113.2/24", "2001:db8:113::2/64"]),
        "transit",
        "br0",
    )?;
    fabric.attach(
        &mut sb,
        &End::new(
            "reflector",
            "wan",
            &[
                "203.0.113.10/24",
                "203.0.113.11/24",
                "2001:db8:113::10/64",
                "2001:db8:113::11/64",
            ],
        ),
        "transit",
        "br0",
    )?;

    // Dual-stack, like every other node on this transit segment. A v4-only
    // relay would be a different topology from the one §3.2's last row is about,
    // and the rig would then have to explain why the v6 routes it installs skip
    // two of its nodes.
    for (node, v4, v6) in [
        ("relay-eu", RELAY_EU, "2001:db8:113::20"),
        ("relay-us", RELAY_US, "2001:db8:113::21"),
    ] {
        fabric.attach(
            &mut sb,
            &End::new(node, "wan", &[&format!("{v4}/24"), &format!("{v6}/64")]),
            "transit",
            "br0",
        )?;
    }

    fabric.route(&mut sb, "peer-a", "default", Some("10.0.1.1"), "lan")?;
    fabric.route(&mut sb, "peer-b", "default", Some("10.0.2.1"), "lan")?;
    // Rule L-5: every scenario is instantiated for v4-only, v6-only and dual, so
    // the topology carries both from the start rather than a v6 half bolted on
    // for the tests that ask for it.
    fabric.route(&mut sb, "peer-a", "default", Some("2001:db8:a::1"), "lan")?;
    fabric.route(&mut sb, "peer-b", "default", Some("2001:db8:b::1"), "lan")?;

    // The reflector reaches both userspace-owned public addresses, and both LANs
    // for `N-ROUTED`, through host routes with permanent neighbours. Nothing
    // answers ARP for any of them, on purpose.
    let mac_a = fabric.mac("cpe-a", "wan").expect("cpe-a wan MAC");
    let mac_b = fabric.mac("cpe-b", "wan").expect("cpe-b wan MAC");
    for dest in [PUBLIC_A, PUBLIC_B, "10.0.1.0/24", "10.0.2.0/24"] {
        fabric.route(&mut sb, "reflector", dest, None, "wan")?;
    }
    for (addr, mac) in [
        (PUBLIC_A, mac_a),
        (PUBLIC_B, mac_b),
        ("10.0.1.2", mac_a),
        ("10.0.2.2", mac_b),
        (SITE_A_V6, mac_a),
        (SITE_B_V6, mac_b),
    ] {
        for node in ["reflector", "relay-eu", "relay-us"] {
            fabric.route(&mut sb, node, addr, None, "wan")?;
            fabric.neighbour(&mut sb, node, "wan", addr, &mac_text(mac))?;
        }
    }
    // Each middlebox must reach the other site's native v6 address and the v6
    // reflector directly: nothing translates v6 here, which is precisely §3.2's
    // last row.
    let reflector_mac = fabric.mac("reflector", "wan").expect("the reflector's MAC");
    for (node, mac, peer) in [("cpe-a", mac_b, SITE_B_V6), ("cpe-b", mac_a, SITE_A_V6)] {
        fabric.neighbour(&mut sb, node, "wan", peer, &mac_text(mac))?;
        for r in [REFLECT_A6, REFLECT_B6] {
            fabric.neighbour(&mut sb, node, "wan", r, &mac_text(reflector_mac))?;
        }
    }

    let agent = sb.agent_path().display().to_string();
    let log = scratch.join("reflector.log");
    let mut relays = Vec::new();
    let reflector = sb.spawn(
        Some("reflector"),
        &[
            &agent,
            "reflect",
            "--primary",
            REFLECT_A,
            "--alternate",
            REFLECT_B,
            "--port-a",
            &PORT_A.to_string(),
            "--port-b",
            &PORT_B.to_string(),
            "--ms",
            "600000",
        ],
        Some(&log),
    )?;
    relays.push(("reflector".to_owned(), reflector));
    let log6 = scratch.join("reflector6.log");
    let reflector6 = sb.spawn(
        Some("reflector"),
        &[
            &agent,
            "reflect",
            "--primary",
            REFLECT_A6,
            "--alternate",
            REFLECT_B6,
            "--port-a",
            &PORT_A.to_string(),
            "--port-b",
            &PORT_B.to_string(),
            "--ms",
            "600000",
        ],
        Some(&log6),
    )?;
    relays.push(("reflector6".to_owned(), reflector6));

    for (node, log) in [("relay-eu", "relay-eu.log"), ("relay-us", "relay-us.log")] {
        let addr = if node == "relay-eu" {
            RELAY_EU
        } else {
            RELAY_US
        };
        let bind = format!("{addr}:{RELAY_PORT}");
        let log = scratch.join(log);
        let handle = sb.spawn(
            Some(node),
            &[&agent, "relay", "--bind", &bind, "--ms", "600000"],
            Some(&log),
        )?;
        relays.push((node.to_owned(), handle));
    }

    Ok(Rig {
        sb,
        fabric,
        scratch,
        relays,
        device_bind: DEVICE_UNDERLAY.to_owned(),
    })
}

/// The middlebox configuration for one site of the two-site rig.
#[must_use]
pub fn site_nat(rig: &Rig, site: &str, p: &Personality) -> NatConfig {
    let (cpe, peer, public, other_public, other_cpe, other_lan) = if site == "a" {
        ("cpe-a", "peer-a", PUBLIC_A, PUBLIC_B, "cpe-b", "10.0.2.2")
    } else {
        ("cpe-b", "peer-b", PUBLIC_B, PUBLIC_A, "cpe-a", "10.0.1.2")
    };
    let reflector_mac = rig.fabric.mac("reflector", "wan").expect("reflector MAC");
    let other_mac = rig.fabric.mac(other_cpe, "wan").expect("the other cpe MAC");
    NatConfig {
        personality: p.name.to_owned(),
        mapping: p.mapping,
        filtering: p.filtering,
        inside_if: "lan".to_owned(),
        outside_if: "wan".to_owned(),
        inside_mac: rig.fabric.mac(cpe, "lan").expect("cpe lan MAC"),
        outside_mac: rig.fabric.mac(cpe, "wan").expect("cpe wan MAC"),
        inside_peer_mac: rig.fabric.mac(peer, "lan").expect("peer MAC"),
        outside_peer_mac: reflector_mac,
        public_v4: Some(public.parse().expect("a literal")),
        public_v6: None,
        port_low: 40_000,
        port_high: 40_500,
        mapping_lifetime_ms: 30_000,
        hairpin: false,
        seed: 0x5EED,
        egress: Egress::Allow,
        stats_path: None,
        pref64: None,
        egress_mtu: None,
        drop_pmtu_icmp: false,
        inside_prefixes: vec![if site == "a" {
            "10.0.1.0/24".to_owned()
        } else {
            "10.0.2.0/24".to_owned()
        }],
        outside_neighbours: vec![
            Neighbour {
                addr: REFLECT_A.to_owned(),
                mac: reflector_mac,
            },
            Neighbour {
                addr: REFLECT_B.to_owned(),
                mac: reflector_mac,
            },
            Neighbour {
                addr: other_public.to_owned(),
                mac: other_mac,
            },
            // `N-ROUTED` puts the peer's own LAN address on the transit segment.
            Neighbour {
                addr: other_lan.to_owned(),
                mac: other_mac,
            },
            Neighbour {
                addr: RELAY_EU.to_owned(),
                mac: rig.fabric.mac("relay-eu", "wan").expect("relay-eu MAC"),
            },
            Neighbour {
                addr: RELAY_US.to_owned(),
                mac: rig.fabric.mac("relay-us", "wan").expect("relay-us MAC"),
            },
            // Native IPv6 passes through untranslated, so the middlebox still
            // has to know where to send it.
            Neighbour {
                addr: REFLECT_A6.to_owned(),
                mac: reflector_mac,
            },
            Neighbour {
                addr: REFLECT_B6.to_owned(),
                mac: reflector_mac,
            },
            Neighbour {
                addr: if site == "a" {
                    SITE_B_V6.to_owned()
                } else {
                    SITE_A_V6.to_owned()
                },
                mac: other_mac,
            },
        ],
    }
}

// ===========================================================================
// The tunnel site: the topology a fail-closed oracle needs.
// ===========================================================================

/// The `TwinNet` IPv4 overlay half this laboratory allocates from
/// (`twinlab::addressing`, §3.2's realism rule read as its purpose).
pub const OVERLAY_V4: &str = "100.64.0.0/12";
/// The product's fixed IPv6 ULA, `docs/networking.md` §2.1.
pub const OVERLAY_V6: &str = "fd7c:9e5d:2a10::/48";
/// The device's overlay address.
pub const DEVICE_OVERLAY_V4: &str = "100.64.0.2";
/// The exit's overlay address.
pub const EXIT_OVERLAY_V4: &str = "100.64.0.3";
/// The device's overlay v6 address.
pub const DEVICE_OVERLAY_V6: &str = "fd7c:9e5d:2a10::2";
/// The exit's overlay v6 address.
pub const EXIT_OVERLAY_V6: &str = "fd7c:9e5d:2a10::3";
/// The device's underlay address.
pub const DEVICE_UNDERLAY: &str = "198.18.0.2";
/// The tunnel's far end on the underlay.
pub const EXIT_UNDERLAY: &str = "198.18.0.3";
/// A resolver that is NOT the tunnel's. Every query that reaches it is a leak.
pub const ROGUE_UNDERLAY: &str = "198.18.0.9";
/// The control plane, on the underlay. Reachable, killable, blackholeable — and
/// carrying nothing an established tunnel needs.
pub const CP_UNDERLAY: &str = "198.18.0.4";
/// The device's address on the private segment, when a middlebox is in front of
/// it. Its *public* address is still [`DEVICE_UNDERLAY`], which is the
/// middlebox's — so every endpoint the far side and the leak policy name is
/// unchanged whether or not the middlebox is there.
pub const DEVICE_PRIVATE: &str = "10.64.0.2";
/// The middlebox's address on the device's private segment.
pub const DEVICE_GATEWAY: &str = "10.64.0.1";
/// The underlay port the tunnel runs on.
pub const TUNNEL_PORT: u16 = 51_820;
/// A LAN the device must keep reaching when local network access is on.
pub const LAN_PREFIX: &str = "192.168.77.0/24";
/// A host on that LAN.
pub const LAN_HOST: &str = "192.168.77.5";

/// Builds the device / exit / rogue / lan topology on one transit segment.
///
/// ```text
///   lan-host ─ lan ─ device ─ wan ─┬── br0 ──┬─ exit   (the tunnel's far end)
///  192.168.77.5    198.18.0.2      │         └─ rogue  (an off-tunnel resolver)
///                  tun0 100.64.0.2 │            198.18.0.9
/// ```
///
/// No middlebox: the question this topology answers is *what left the device*,
/// and a NAT between the device and the observer would translate the very
/// addresses the oracle is looking for.
pub fn build_tunnel_site(label: &str) -> Result<Rig, NetError> {
    build_tunnel_site_with(label, None)
}

/// The tunnel site, optionally behind a §3.3 middlebox.
///
/// **Why the option exists.** The `S-KS-*` documents declare a site behind
/// `N-EIM-APDF`. Running them on a rig with no middlebox would produce a PASS
/// against a topology that is not the one the scenario describes — which is the
/// drift §3.6 exists to prevent, and is why those scenarios reported
/// `NOT-EXECUTABLE` rather than being run on the wrong shape.
///
/// The device's *public* address is unchanged either way: with a middlebox it
/// is the middlebox's public address, and without one it is the device's own.
/// So the far end, the control plane, the rogue resolver and every leak policy
/// name the same endpoints in both topologies, and the only thing that differs
/// is what is in the path.
///
/// # Errors
///
/// Any [`NetError`] from the fabric.
pub fn build_tunnel_site_with(
    label: &str,
    middlebox: Option<&Personality>,
) -> Result<Rig, NetError> {
    let mut sb = sandbox()?;
    sb.require(&["tun"])?;
    let scratch = scratch(label);
    let mut fabric = Fabric::new(&scratch);

    for node in ["device", "exit", "rogue", "cp", "lan-host", "transit"] {
        fabric.node(&mut sb, node, false)?;
    }
    if middlebox.is_some() {
        fabric.node(&mut sb, "cpe", false)?;
    }
    fabric.bridge(&mut sb, "transit", "br0")?;

    for (node, v4, v6) in [
        ("exit", "198.18.0.3/24", "2001:db8:18::3/64"),
        ("rogue", "198.18.0.9/24", "2001:db8:18::9/64"),
        ("cp", "198.18.0.4/24", "2001:db8:18::4/64"),
    ] {
        fabric.attach(&mut sb, &End::new(node, "wan", &[v4, v6]), "transit", "br0")?;
    }
    if middlebox.is_some() {
        // The device sits on a private segment behind the middlebox, whose own
        // outside leg is on the transit bridge. `198.18.0.2` becomes the
        // middlebox's userspace-owned public address rather than an address on
        // any interface.
        fabric.bridge_with(&mut sb, "cpe", "lan", &[&format!("{DEVICE_GATEWAY}/24")])?;
        fabric.attach(
            &mut sb,
            &End::new("device", "wan", &[&format!("{DEVICE_PRIVATE}/24")]),
            "cpe",
            "lan",
        )?;
        fabric.attach(
            &mut sb,
            &End::new("cpe", "wan", &["198.18.0.20/24", "2001:db8:18::20/64"]),
            "transit",
            "br0",
        )?;
        fabric.route(&mut sb, "device", "default", Some(DEVICE_GATEWAY), "wan")?;
        let gw = fabric.mac("cpe", "lan").expect("the cpe's lan MAC");
        fabric.neighbour(&mut sb, "device", "wan", DEVICE_GATEWAY, &mac_text(gw))?;
    } else {
        fabric.attach(
            &mut sb,
            &End::new("device", "wan", &["198.18.0.2/24", "2001:db8:18::2/64"]),
            "transit",
            "br0",
        )?;
    }
    fabric.link(
        &mut sb,
        &End::new("device", "lan", &["192.168.77.1/24"]),
        &End::new("lan-host", "lan", &["192.168.77.5/24"]),
    )?;

    // One L2 segment, so every underlay pair is on-link and no scenario depends
    // on a router the topology does not draw.
    let on_transit: &[(&str, &str, &str)] = if middlebox.is_some() {
        &[
            ("cpe", "198.18.0.20", "2001:db8:18::20"),
            ("exit", "198.18.0.3", "2001:db8:18::3"),
            ("cp", "198.18.0.4", "2001:db8:18::4"),
            ("rogue", "198.18.0.9", "2001:db8:18::9"),
        ]
    } else {
        &[
            ("device", "198.18.0.2", "2001:db8:18::2"),
            ("exit", "198.18.0.3", "2001:db8:18::3"),
            ("cp", "198.18.0.4", "2001:db8:18::4"),
            ("rogue", "198.18.0.9", "2001:db8:18::9"),
        ]
    };
    for (node, _, _) in on_transit {
        for (owner, v4, v6) in on_transit {
            if owner == node {
                continue;
            }
            let mac = fabric.mac(owner, "wan").expect("a wan MAC");
            fabric.neighbour(&mut sb, node, "wan", v4, &mac_text(mac))?;
            fabric.neighbour(&mut sb, node, "wan", v6, &mac_text(mac))?;
        }
    }
    if middlebox.is_some() {
        // Everything on the transit segment reaches the device through the
        // middlebox's userspace-owned public address. Nothing answers ARP for
        // it, on purpose.
        let cpe_wan = fabric.mac("cpe", "wan").expect("the cpe's wan MAC");
        for node in ["exit", "cp", "rogue"] {
            fabric.route(&mut sb, node, DEVICE_UNDERLAY, None, "wan")?;
            fabric.neighbour(&mut sb, node, "wan", DEVICE_UNDERLAY, &mac_text(cpe_wan))?;
        }
    }

    // The services the device can talk to. Each is a plain echo: what matters in
    // every scenario below is whether the datagrams arrive, never what they say.
    let agent = sb.agent_path().display().to_string();
    let mut relays = Vec::new();
    for (node, addr, port, log) in [
        ("cp", CP_UNDERLAY, 8443u16, "cp.log"),
        ("rogue", ROGUE_UNDERLAY, 53, "rogue-dns.log"),
        ("rogue", ROGUE_UNDERLAY, 9, "rogue-echo.log"),
    ] {
        let bind = format!("{addr}:{port}");
        let log = scratch.join(log);
        let handle = sb.spawn(
            Some(node),
            &[&agent, "udp-echo", "--bind", &bind, "--ms", "120000"],
            Some(&log),
        )?;
        relays.push((format!("{node}:{port}"), handle));
    }

    let device_bind = if middlebox.is_some() {
        DEVICE_PRIVATE.to_owned()
    } else {
        DEVICE_UNDERLAY.to_owned()
    };
    let mut rig = Rig {
        sb,
        fabric,
        scratch,
        relays,
        device_bind,
    };
    if let Some(p) = middlebox {
        let cfg = tunnel_site_nat(&rig, p);
        let mut fabric = std::mem::replace(&mut rig.fabric, Fabric::new(&rig.scratch));
        let started = fabric.start_nat(&mut rig.sb, "cpe", &cfg);
        rig.fabric = fabric;
        started?;
        settle();
    }
    Ok(rig)
}

/// Installs ADR-0012's kill switch as a blackhole route for each overlay
/// prefix.
///
/// **This is the mechanism, not a stand-in for it.** ADR-0012 puts the kill
/// switch at OS level, locally authoritative, surviving process death — and a
/// blackhole route is exactly that: the kernel drops protected traffic, the rule
/// outlives the process that installed it, and nothing in the tunnel can
/// countermand it.
///
/// The blackhole covers the **same prefix** the tunnel route does, so it is
/// distinguished by **metric**, not by length. The tunnel's route carries the
/// default metric and wins while `tun0` exists; the blackhole carries a high one
/// and is what is left when the tunnel dies and its route dies with the device.
///
/// The first version of this used `ip route replace` at the same metric and
/// silently *overwrote* the tunnel's route — arming the kill switch severed the
/// tunnel it was supposed to protect, and the symptom was a rig that carried no
/// traffic at all. Two routes for one prefix need two metrics.
///
/// # Why a scenario has to ask for it
///
/// Without it, a device with a default route sends protected traffic **in the
/// clear** the moment the tunnel drops. That is not hypothetical: it is what the
/// behind-NAT rig does when this is not called, and the leak oracle catches it.
/// A rig that armed the kill switch implicitly would make every fail-closed
/// assertion pass without anyone choosing to arm anything.
///
/// # Errors
///
/// [`NetError::Mechanism`] naming the failing `ip route`.
pub fn arm_kill_switch(rig: &mut Rig) -> Result<(), NetError> {
    for (family, prefix) in [("-4", OVERLAY_V4), ("-6", OVERLAY_V6)] {
        rig.sb.must(
            Some("device"),
            &[
                "ip",
                family,
                "route",
                "replace",
                "blackhole",
                prefix,
                "metric",
                KILL_SWITCH_METRIC,
            ],
        )?;
    }
    Ok(())
}

/// The metric the kill switch's blackhole carries.
///
/// High enough that the tunnel's own route always wins while it exists, and
/// present at all so the two routes for one prefix can coexist.
const KILL_SWITCH_METRIC: &str = "1000";

/// Removes it again — the mutant a fail-closed assertion is read against.
///
/// # Errors
///
/// [`NetError::Mechanism`] naming the failing `ip route`.
pub fn disarm_kill_switch(rig: &mut Rig) -> Result<(), NetError> {
    for (family, prefix) in [("-4", OVERLAY_V4), ("-6", OVERLAY_V6)] {
        let _ = rig.sb.run(
            Some("device"),
            &[
                "ip",
                family,
                "route",
                "del",
                "blackhole",
                prefix,
                "metric",
                KILL_SWITCH_METRIC,
            ],
        )?;
    }
    Ok(())
}

/// Both ends of the tunnel, so a chaos scenario can kill either one.
///
/// The two are named rather than returned as a bare pair because the scenarios
/// that use them are about the difference: a client restart and a gateway
/// restart are different failures with different recoveries, and a tuple would
/// let a test kill the wrong end and still look plausible.
#[derive(Debug, Clone, Copy)]
pub struct TunnelEnds {
    /// The device's tunnel process.
    pub device: crate::ProcHandle,
    /// The far end's — the gateway.
    pub exit: crate::ProcHandle,
}

/// Starts both ends of the tunnel and addresses the two TUN devices.
///
/// # Errors
///
/// Any [`NetError`] from the fabric or the sandbox.
pub fn start_tunnel(rig: &mut Rig) -> Result<TunnelEnds, NetError> {
    let agent = rig.sb.agent_path().display().to_string();
    let device_log = rig.scratch.join("tunnel-device.log");
    let exit_log = rig.scratch.join("tunnel-exit.log");
    let device_bind = format!("{}:{TUNNEL_PORT}", rig.device_bind);
    let exit_bind = format!("{EXIT_UNDERLAY}:{TUNNEL_PORT}");

    let device = rig.sb.spawn(
        Some("device"),
        &[
            &agent,
            "tunnel",
            "--dev",
            "tun0",
            "--bind",
            &device_bind,
            "--peer",
            &exit_bind,
            "--ms",
            "120000",
        ],
        Some(&device_log),
    )?;
    // The far end is given no peer: behind a middlebox the device's mapped
    // endpoint is allocated by the NAT and cannot be configured, and with no
    // middlebox the first datagram teaches it the same address it would have
    // been told. One code path, correct in both topologies.
    let exit = rig.sb.spawn(
        Some("exit"),
        &[
            &agent, "tunnel", "--dev", "tun0", "--bind", &exit_bind, "--ms", "120000",
        ],
        Some(&exit_log),
    )?;
    settle();

    for (node, v4, v6) in [
        ("device", DEVICE_OVERLAY_V4, DEVICE_OVERLAY_V6),
        ("exit", EXIT_OVERLAY_V4, EXIT_OVERLAY_V6),
    ] {
        let v4_cidr = format!("{v4}/32");
        let v6_cidr = format!("{v6}/128");
        rig.sb
            .must(Some(node), &["ip", "addr", "add", &v4_cidr, "dev", "tun0"])?;
        rig.sb.must(
            Some(node),
            &["ip", "addr", "add", &v6_cidr, "dev", "tun0", "nodad"],
        )?;
        rig.sb
            .must(Some(node), &["ip", "link", "set", "tun0", "up"])?;
        // The overlay reaches the far end through the tunnel in both families.
        rig.sb.must(
            Some(node),
            &["ip", "-4", "route", "replace", OVERLAY_V4, "dev", "tun0"],
        )?;
        rig.sb.must(
            Some(node),
            &["ip", "-6", "route", "replace", OVERLAY_V6, "dev", "tun0"],
        )?;
    }
    // The far end answers inside the overlay, so a scenario can ask "did the
    // tunnel carry anything" rather than only "did anything leak".
    let agent = rig.sb.agent_path().display().to_string();
    let echo = format!("{EXIT_OVERLAY_V4}:9");
    let dns = format!("{EXIT_OVERLAY_V4}:53");
    let log = rig.scratch.join("exit-echo.log");
    for bind in [&echo, &dns] {
        rig.sb.spawn(
            Some("exit"),
            &[&agent, "udp-echo", "--bind", bind, "--ms", "120000"],
            Some(&log),
        )?;
    }
    settle();
    Ok(TunnelEnds { device, exit })
}

// ===========================================================================
// The NAT64 site: §3.3's `N-NAT64` row, and the mobile access network it is
// about.
// ===========================================================================

/// The v6-only client's address.
pub const NAT64_CLIENT_V6: &str = "2001:db8:64::2";
/// The translator's address on the v6 LAN — the client's default router.
pub const NAT64_GATEWAY_V6: &str = "2001:db8:64::1";
/// The laboratory resolver, on the v6 LAN.
pub const NAT64_RESOLVER_V6: &str = "2001:db8:64::53";
/// The translator's public IPv4 address, owned in userspace.
pub const NAT64_PUBLIC_V4: &str = "198.51.100.7";
/// The v4-only destination.
pub const NAT64_SERVER_V4: &str = "203.0.113.10";
/// The name that destination answers to.
pub const NAT64_NAME: &str = "v4only.twinvpn.invalid";
/// RFC 6052's well-known translation prefix.
pub const NAT64_PREF64: &str = "64:ff9b::";

/// Builds a v6-only access network in front of a v4-only destination.
///
/// ```text
///   client6 ─┐                                    ┌─ server4 (v4 only)
///  2001:db8:64::2  br-lan (v6 only) ─[ nat64 ]─ wan   203.0.113.10
///   dns64  ─┘      2001:db8:64::1     public    203.0.113.1
///  2001:db8:64::53                 198.51.100.7
/// ```
///
/// **The client has no IPv4 address at all.** That is the point: a rig where the
/// client could reach the destination directly would pass whether or not the
/// translator worked.
///
/// The three prefix advertisements are separate arguments because §3.3 requires
/// them to be independently switchable: `synthesize` is the DNS64's AAAA for the
/// destination, `rfc7050` is `ipv4only.arpa`, and `advertise_ra` is RFC 8781's
/// PREF64 option in a Router Advertisement — the path `docs/networking.md` §3.8
/// prefers, and the only one that touches no resolver.
///
/// # Errors
///
/// Any [`NetError`] from the fabric.
pub fn build_nat64_site(
    label: &str,
    synthesize: bool,
    rfc7050: bool,
    advertise_ra: bool,
) -> Result<Rig, NetError> {
    let mut sb = sandbox()?;
    let scratch = scratch(label);
    let mut fabric = Fabric::new(&scratch);

    for node in ["client6", "dns", "nat64", "server4"] {
        fabric.node(&mut sb, node, false)?;
    }
    fabric.bridge_with(
        &mut sb,
        "nat64",
        "lan",
        &[&format!("{NAT64_GATEWAY_V6}/64")],
    )?;
    for (node, addr) in [("client6", NAT64_CLIENT_V6), ("dns", NAT64_RESOLVER_V6)] {
        fabric.attach(
            &mut sb,
            &End::new(node, "lan", &[&format!("{addr}/64")]),
            "nat64",
            "lan",
        )?;
        fabric.route(&mut sb, node, "default", Some(NAT64_GATEWAY_V6), "lan")?;
    }
    fabric.link(
        &mut sb,
        &End::new("nat64", "wan", &["203.0.113.1/24"]),
        &End::new("server4", "wan", &[&format!("{NAT64_SERVER_V4}/24")]),
    )?;

    // The v4-only destination reaches the translator's userspace-owned public
    // address through a host route with a permanent neighbour. Nothing answers
    // ARP for it, on purpose.
    let nat_wan = fabric
        .mac("nat64", "wan")
        .expect("the translator's wan MAC");
    fabric.route(&mut sb, "server4", NAT64_PUBLIC_V4, None, "wan")?;
    fabric.neighbour(
        &mut sb,
        "server4",
        "wan",
        NAT64_PUBLIC_V4,
        &mac_text(nat_wan),
    )?;
    // The two LAN hosts know each other, so a name lookup does not begin with
    // neighbour discovery.
    for (here, there, addr) in [
        ("client6", "dns", NAT64_RESOLVER_V6),
        ("dns", "client6", NAT64_CLIENT_V6),
    ] {
        let mac = fabric.mac(there, "lan").expect("a LAN MAC");
        fabric.neighbour(&mut sb, here, "lan", addr, &mac_text(mac))?;
    }
    let gw = fabric.mac("nat64", "lan").expect("the gateway's MAC");
    for node in ["client6", "dns"] {
        fabric.neighbour(&mut sb, node, "lan", NAT64_GATEWAY_V6, &mac_text(gw))?;
    }

    let agent = sb.agent_path().display().to_string();
    let mut relays = Vec::new();
    let resolver_bind = format!("[{NAT64_RESOLVER_V6}]:53");
    let map = format!("{NAT64_NAME}={NAT64_SERVER_V4}");
    let dns_log = scratch.join("dns64.log");
    relays.push((
        "dns".to_owned(),
        sb.spawn(
            Some("dns"),
            &[
                &agent,
                "dns64",
                "--bind",
                &resolver_bind,
                "--map",
                &map,
                "--pref64",
                NAT64_PREF64,
                "--synthesize",
                if synthesize { "true" } else { "false" },
                "--rfc7050",
                if rfc7050 { "true" } else { "false" },
                "--ms",
                "120000",
            ],
            Some(&dns_log),
        )?,
    ));
    if advertise_ra {
        // Advertised from the translator's own LAN interface, which is what a
        // NAT64 gateway on a mobile access network is.
        let ra_log = scratch.join("ra.log");
        relays.push((
            "ra".to_owned(),
            sb.spawn(
                Some("nat64"),
                &[
                    &agent,
                    "ra-advertise",
                    "--iface",
                    "lan",
                    "--pref64",
                    NAT64_PREF64,
                    "--lifetime-s",
                    "600",
                    "--interval-ms",
                    "200",
                    "--ms",
                    "120000",
                ],
                Some(&ra_log),
            )?,
        ));
    }

    let echo_bind = format!("{NAT64_SERVER_V4}:9");
    let echo_log = scratch.join("server4.log");
    relays.push((
        "server4".to_owned(),
        sb.spawn(
            Some("server4"),
            &[&agent, "udp-echo", "--bind", &echo_bind, "--ms", "120000"],
            Some(&echo_log),
        )?,
    ));

    Ok(Rig {
        sb,
        fabric,
        scratch,
        relays,
        device_bind: DEVICE_UNDERLAY.to_owned(),
    })
}

/// The middlebox configuration for the tunnel site's `cpe`.
#[must_use]
pub fn tunnel_site_nat(rig: &Rig, p: &Personality) -> NatConfig {
    NatConfig {
        personality: p.name.to_owned(),
        mapping: p.mapping,
        filtering: p.filtering,
        inside_if: "lan".to_owned(),
        outside_if: "wan".to_owned(),
        inside_mac: rig.fabric.mac("cpe", "lan").expect("the cpe lan MAC"),
        outside_mac: rig.fabric.mac("cpe", "wan").expect("the cpe wan MAC"),
        inside_peer_mac: rig.fabric.mac("device", "wan").expect("the device MAC"),
        outside_peer_mac: rig.fabric.mac("exit", "wan").expect("the exit MAC"),
        public_v4: Some(DEVICE_UNDERLAY.parse().expect("a literal")),
        public_v6: None,
        pref64: None,
        port_low: 40_000,
        port_high: 40_500,
        mapping_lifetime_ms: 120_000,
        hairpin: false,
        seed: 0x5EED,
        egress: Egress::Allow,
        egress_mtu: None,
        drop_pmtu_icmp: false,
        stats_path: None,
        inside_prefixes: vec!["10.64.0.0/24".to_owned()],
        outside_neighbours: ["exit", "cp", "rogue"]
            .into_iter()
            .zip([EXIT_UNDERLAY, CP_UNDERLAY, ROGUE_UNDERLAY])
            .map(|(node, addr)| Neighbour {
                addr: addr.to_owned(),
                mac: rig.fabric.mac(node, "wan").expect("a transit MAC"),
            })
            .collect(),
    }
}

/// The translator's configuration for [`build_nat64_site`].
#[must_use]
pub fn nat64_config(rig: &Rig) -> NatConfig {
    NatConfig {
        personality: "N-NAT64".to_owned(),
        // A stateful NAT64 is address-and-port-dependent on both axes: RFC 6146
        // allocates per destination tuple and admits only the endpoint that was
        // written to. Configured here rather than assumed, like every other
        // personality in §3.3.
        mapping: Mapping::AddressPortDependentRandom,
        filtering: Filtering::AddressPortDependent,
        inside_if: "lan".to_owned(),
        outside_if: "wan".to_owned(),
        inside_mac: rig.fabric.mac("nat64", "lan").expect("the lan MAC"),
        outside_mac: rig.fabric.mac("nat64", "wan").expect("the wan MAC"),
        inside_peer_mac: rig.fabric.mac("client6", "lan").expect("the client's MAC"),
        outside_peer_mac: rig.fabric.mac("server4", "wan").expect("the server's MAC"),
        public_v4: Some(NAT64_PUBLIC_V4.parse().expect("a literal")),
        public_v6: None,
        pref64: Some(crate::nat::xlat::Pref64 {
            prefix: NAT64_PREF64.parse().expect("a literal"),
            len: 96,
        }),
        port_low: 40_000,
        port_high: 40_500,
        mapping_lifetime_ms: 30_000,
        hairpin: false,
        seed: 0x5EED,
        egress: Egress::Allow,
        egress_mtu: None,
        drop_pmtu_icmp: false,
        stats_path: None,
        inside_prefixes: vec!["2001:db8:64::/64".to_owned()],
        outside_neighbours: vec![Neighbour {
            addr: NAT64_SERVER_V4.to_owned(),
            mac: rig.fabric.mac("server4", "wan").expect("the server's MAC"),
        }],
    }
}

// ===========================================================================
// The roam site: §3.4's interface-change row, and network migration.
// ===========================================================================

/// The device's address on the Wi-Fi access network.
pub const ROAM_WIFI_ADDR: &str = "198.18.0.2";
/// Its gateway there.
pub const ROAM_WIFI_GW: &str = "198.18.0.1";
/// The device's address on the cellular access network.
pub const ROAM_CELL_ADDR: &str = "198.19.0.2";
/// Its gateway there.
pub const ROAM_CELL_GW: &str = "198.19.0.1";
/// The tunnel's far end, on a third segment behind the router.
pub const ROAM_EXIT_ADDR: &str = "198.20.0.2";

/// Two access networks and one exit behind a router.
///
/// ```text
///   device ── br-wifi ─┐                     ┌── exit
///  198.18.0.2          ├─[ transit router ]──┤   198.20.0.2
///            br-cell ──┘  .1 on each segment └   tun0 100.64.0.3
///  198.19.0.2
/// ```
///
/// **Why a router and not one flat segment.** A roam that kept the same
/// gateway, the same subnet and the same path would change an address and
/// nothing else. Two access networks behind a router is what a phone leaving
/// Wi-Fi actually does: new address, new gateway, new path — and the same far
/// end, which is the thing the session has to survive to.
///
/// # Errors
///
/// Any [`NetError`] from the fabric.
pub fn build_roam_site(label: &str) -> Result<Rig, NetError> {
    let mut sb = sandbox()?;
    sb.require(&["tun"])?;
    let scratch = scratch(label);
    let mut fabric = Fabric::new(&scratch);

    fabric.node(&mut sb, "device", false)?;
    fabric.node(&mut sb, "exit", false)?;
    // The one node in this laboratory whose kernel forwards: it is a router.
    fabric.node(&mut sb, "transit", true)?;

    fabric.bridge_with(
        &mut sb,
        "transit",
        "br-wifi",
        &[&format!("{ROAM_WIFI_GW}/24")],
    )?;
    fabric.bridge_with(
        &mut sb,
        "transit",
        "br-cell",
        &[&format!("{ROAM_CELL_GW}/24")],
    )?;
    fabric.attach(
        &mut sb,
        &End::new("device", "wan", &[&format!("{ROAM_WIFI_ADDR}/24")]),
        "transit",
        "br-wifi",
    )?;
    fabric.link(
        &mut sb,
        &End::new("transit", "core", &["198.20.0.1/24"]),
        &End::new("exit", "wan", &[&format!("{ROAM_EXIT_ADDR}/24")]),
    )?;

    fabric.route(&mut sb, "device", "default", Some(ROAM_WIFI_GW), "wan")?;
    // The exit reaches both access networks through the router, so the far end
    // does not have to change when the device does.
    for prefix in ["198.18.0.0/24", "198.19.0.0/24"] {
        fabric.route(&mut sb, "exit", prefix, Some("198.20.0.1"), "wan")?;
    }
    let gw = fabric
        .mac("transit", "core")
        .expect("the router's core MAC");
    fabric.neighbour(&mut sb, "exit", "wan", "198.20.0.1", &mac_text(gw))?;

    Ok(Rig {
        sb,
        fabric,
        scratch,
        relays: Vec::new(),
        device_bind: ROAM_WIFI_ADDR.to_owned(),
    })
}

/// Brings the tunnel up on the roam site.
///
/// The far end is given no peer, so the device's endpoint after a roam is
/// learned rather than configured — which is the whole reason a session can
/// survive one.
///
/// # Errors
///
/// Any [`NetError`] from the fabric or the sandbox.
pub fn start_roam_tunnel(rig: &mut Rig) -> Result<crate::ProcHandle, NetError> {
    let agent = rig.sb.agent_path().display().to_string();
    // The wildcard address, not `ROAM_WIFI_ADDR`. A socket bound to a specific
    // address stops working the moment that address goes away, which is exactly
    // what a roam does — and the failure is `EADDRNOTAVAIL` on every send, for
    // ever. A real client binds the port and lets the routing table choose the
    // source, which is what makes a session survivable across an interface
    // change at all.
    let device_bind = format!("0.0.0.0:{TUNNEL_PORT}");
    let exit_bind = format!("{ROAM_EXIT_ADDR}:{TUNNEL_PORT}");
    let device_log = rig.scratch.join("roam-device.log");
    let exit_log = rig.scratch.join("roam-exit.log");

    let device = rig.sb.spawn(
        Some("device"),
        &[
            &agent,
            "tunnel",
            "--dev",
            "tun0",
            "--bind",
            &device_bind,
            "--peer",
            &exit_bind,
            "--ms",
            "120000",
        ],
        Some(&device_log),
    )?;
    rig.sb.spawn(
        Some("exit"),
        &[
            &agent, "tunnel", "--dev", "tun0", "--bind", &exit_bind, "--ms", "120000",
        ],
        Some(&exit_log),
    )?;
    settle();

    for (node, addr) in [("device", DEVICE_OVERLAY_V4), ("exit", EXIT_OVERLAY_V4)] {
        let cidr = format!("{addr}/32");
        rig.sb
            .must(Some(node), &["ip", "addr", "add", &cidr, "dev", "tun0"])?;
        rig.sb
            .must(Some(node), &["ip", "link", "set", "tun0", "up"])?;
        rig.sb.must(
            Some(node),
            &["ip", "-4", "route", "replace", OVERLAY_V4, "dev", "tun0"],
        )?;
    }
    let agent = rig.sb.agent_path().display().to_string();
    let echo = format!("{EXIT_OVERLAY_V4}:9");
    let log = rig.scratch.join("roam-echo.log");
    rig.sb.spawn(
        Some("exit"),
        &[&agent, "udp-echo", "--bind", &echo, "--ms", "120000"],
        Some(&log),
    )?;
    settle();
    Ok(device)
}

/// Moves the device from the Wi-Fi access network to the cellular one.
///
/// The tunnel process is **not** restarted: the point of the scenario is that
/// the session survives, and a scenario that restarted it would be measuring a
/// reconnection.
///
/// # Errors
///
/// Any [`NetError`] from the fabric.
pub fn roam_to_cell(rig: &mut Rig) -> Result<(), NetError> {
    let fabric = std::mem::replace(&mut rig.fabric, Fabric::new(&rig.scratch));
    let cidr = format!("{ROAM_CELL_ADDR}/24");
    let result = fabric.roam(
        &mut rig.sb,
        &crate::fabric::Roam {
            node: "device",
            iface: "wan",
            bridge_node: "transit",
            to_bridge: "br-cell",
            new_cidr: &cidr,
            gateway: ROAM_CELL_GW,
        },
    );
    rig.fabric = fabric;
    result
}
