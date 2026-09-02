//! What this host can actually realize, probed rather than assumed.
//!
//! **Authority:** `docs/testing-strategy.md` §3.1 (realization principle), §3.2
//! (a node is a Linux network namespace), §3.4.2 rule **L-1** (no traversal,
//! leak or relay test runs against a personality that has not passed its
//! conformance suite in the same lab instantiation).
//!
//! # Why this module exists at all
//!
//! §3.2 makes a namespace the unit of a node, and §3.3 makes `conntrack` and
//! `nftables` the mechanism behind every NAT personality. Neither is guaranteed:
//! a container runner may forbid `CLONE_NEWNET`, and a WSL2 kernel commonly ships
//! `iproute2` without `nftables` userspace. The honest response to that is to
//! *probe*, publish the result, and let every scenario that needs a missing
//! facility return [`crate::outcome::Verdict::Unavailable`].
//!
//! The dishonest response — the one this module exists to make impossible — is a
//! fallback that simulates the missing mechanism and reports a pass.

use core::fmt::Write as _;

use crate::exec::Runner;

/// One probed facility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Facility {
    /// Unprivileged user + network namespace creation (`CLONE_NEWUSER|CLONE_NEWNET`).
    NetworkNamespaces,
    /// `veth` pair creation and cross-namespace attachment.
    Veth,
    /// Linux bridge creation — §3.2's L2 segment.
    Bridge,
    /// `tc` with the `netem` qdisc — §3.4's impairment mechanism.
    Netem,
    /// `tc` with a shaping qdisc (`tbf`) — §3.4's bandwidth restriction.
    Shaping,
    /// `nftables` userspace — every NAT personality in §3.3 and every `nft`
    /// blackhole and egress filter in §3.4.
    Nftables,
    /// `conntrack` state inspection — §3.4.2's mapping-lifetime conformance.
    Conntrack,
    /// IPv6 forwarding and addressing inside a namespace — rule **L-5** requires
    /// every family, so the absence of this is not a detail.
    Ipv6,
    /// An eBPF `tc` classifier — §3.5's seeded drop schedule, the only mechanism
    /// that gives a loss scenario `BIT` determinism.
    EbpfTcClassifier,
    /// A container runtime, for the service artifacts `infra/` composes.
    Containers,
    /// Whether the kernel forwarding state of a namespace this laboratory
    /// creates is **ours to set** rather than the host's to donate.
    ///
    /// A new namespace does not start neutral: Linux copies the initial
    /// namespace's `all` devconf into it, and `net.ipv4.ip_forward` is a member
    /// of that block (`net/ipv4/devinet.c`, `devinet_init_net`; IPv6 does the
    /// same in `addrconf_init_net`). So on a host running Docker — which turns
    /// `ip_forward` on when its daemon starts — every namespace arrives
    /// forwarding, and a userspace middlebox placed in one has the kernel
    /// racing it for every frame.
    ///
    /// This is probed rather than assumed because it is the difference between
    /// a NAT personality being realized and a scenario measuring the kernel:
    /// the runner that found it passed the `network-namespaces`, `veth` and
    /// `af-packet` rows and still could not realize a middlebox.
    ForwardingControl,
}

impl Facility {
    /// Every facility, so a report cannot silently omit one.
    pub const ALL: [Facility; 11] = [
        Facility::NetworkNamespaces,
        Facility::Veth,
        Facility::Bridge,
        Facility::Netem,
        Facility::Shaping,
        Facility::Nftables,
        Facility::Conntrack,
        Facility::Ipv6,
        Facility::EbpfTcClassifier,
        Facility::Containers,
        Facility::ForwardingControl,
    ];

    /// The name used in a run record and in a skip message.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Facility::NetworkNamespaces => "network-namespaces",
            Facility::Veth => "veth",
            Facility::Bridge => "bridge",
            Facility::Netem => "netem",
            Facility::Shaping => "shaping",
            Facility::Nftables => "nftables",
            Facility::Conntrack => "conntrack",
            Facility::Ipv6 => "ipv6",
            Facility::EbpfTcClassifier => "ebpf-tc-classifier",
            Facility::Containers => "containers",
            Facility::ForwardingControl => "forwarding-control",
        }
    }
}

/// The probe's verdict for one facility.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Probe {
    /// Which facility.
    pub facility: Facility,
    /// Whether it is usable.
    pub available: bool,
    /// How the probe decided — a command that ran, or a tool that was absent.
    pub evidence: String,
}

/// Everything this host can realize.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HostCapabilities {
    /// One entry per [`Facility::ALL`], in that order.
    pub probes: Vec<Probe>,
    /// `uname -r`, for the run record (§3.6 requires the kernel version).
    pub kernel: String,
}

impl HostCapabilities {
    /// Probes the host. Cheap enough to run per test binary; each probe is a
    /// single short-lived process.
    #[must_use]
    pub fn probe() -> Self {
        let mut runner = Runner::new();
        let kernel = runner.run("uname", &["-r"]).ok().map_or_else(
            || "unknown".to_owned(),
            |o| String::from_utf8_lossy(&o.stdout).trim().to_owned(),
        );

        let netns = probe_netns(&mut runner);
        let veth = if netns.available {
            probe_in_ns(
                &mut runner,
                Facility::Veth,
                "ip link add v0 type veth peer name v1 && ip link set v0 up",
            )
        } else {
            unavailable(Facility::Veth, "requires network namespaces")
        };
        let bridge = if netns.available {
            probe_in_ns(
                &mut runner,
                Facility::Bridge,
                "ip link add name br0 type bridge && ip link set br0 up",
            )
        } else {
            unavailable(Facility::Bridge, "requires network namespaces")
        };
        let netem = if netns.available {
            probe_in_ns(
                &mut runner,
                Facility::Netem,
                "ip link add v0 type veth peer name v1 && ip link set v0 up \
                 && tc qdisc add dev v0 root netem delay 10ms",
            )
        } else {
            unavailable(Facility::Netem, "requires network namespaces")
        };
        let shaping = if netns.available {
            probe_in_ns(
                &mut runner,
                Facility::Shaping,
                "ip link add v0 type veth peer name v1 && ip link set v0 up \
                 && tc qdisc add dev v0 root tbf rate 10mbit burst 32kbit latency 50ms",
            )
        } else {
            unavailable(Facility::Shaping, "requires network namespaces")
        };
        let ipv6 = if netns.available {
            probe_in_ns(
                &mut runner,
                Facility::Ipv6,
                "ip link add v0 type veth peer name v1 \
                 && ip -6 addr add 2001:db8::1/64 dev v0 && ip link set v0 up \
                 && sysctl -w net.ipv6.conf.all.forwarding=1",
            )
        } else {
            unavailable(Facility::Ipv6, "requires network namespaces")
        };

        let forwarding = if netns.available {
            probe_forwarding_control(&mut runner)
        } else {
            unavailable(Facility::ForwardingControl, "requires network namespaces")
        };

        let nftables = probe_tool(Facility::Nftables, "nft");
        let conntrack = probe_tool(Facility::Conntrack, "conntrack");
        let ebpf = probe_tool(Facility::EbpfTcClassifier, "bpftool");
        let containers = if Runner::tool_present("docker") {
            Probe {
                facility: Facility::Containers,
                available: true,
                evidence: "docker on PATH".to_owned(),
            }
        } else if Runner::tool_present("podman") {
            Probe {
                facility: Facility::Containers,
                available: true,
                evidence: "podman on PATH".to_owned(),
            }
        } else {
            unavailable(Facility::Containers, "neither docker nor podman on PATH")
        };

        Self {
            probes: vec![
                netns, veth, bridge, netem, shaping, nftables, conntrack, ipv6, ebpf, containers,
                forwarding,
            ],
            kernel,
        }
    }

    /// Whether `facility` is usable on this host.
    #[must_use]
    pub fn has(&self, facility: Facility) -> bool {
        self.probes
            .iter()
            .any(|p| p.facility == facility && p.available)
    }

    /// The first facility in `required` that this host lacks.
    #[must_use]
    pub fn missing(&self, required: &[Facility]) -> Option<Facility> {
        required.iter().copied().find(|f| !self.has(*f))
    }

    /// A one-line-per-facility summary, for a run record and for `twinlab
    /// capabilities`.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut s = format!("kernel {}\n", self.kernel);
        for p in &self.probes {
            // `write!` into a String cannot fail; the result is discarded rather
            // than unwrapped so producing a summary can never panic a probe.
            let _ = writeln!(
                s,
                "  {:<20} {:<13} {}",
                p.facility.name(),
                if p.available {
                    "AVAILABLE"
                } else {
                    "unavailable"
                },
                p.evidence
            );
        }
        s
    }
}

fn unavailable(facility: Facility, why: &str) -> Probe {
    Probe {
        facility,
        available: false,
        evidence: why.to_owned(),
    }
}

fn probe_tool(facility: Facility, program: &str) -> Probe {
    if Runner::tool_present(program) {
        Probe {
            facility,
            available: true,
            evidence: format!("`{program}` on PATH"),
        }
    } else {
        unavailable(facility, &format!("`{program}` is not installed"))
    }
}

fn probe_netns(runner: &mut Runner) -> Probe {
    if !Runner::tool_present("unshare") {
        return unavailable(Facility::NetworkNamespaces, "`unshare` is not installed");
    }
    match runner.run("unshare", &["--user", "--net", "--map-root-user", "true"]) {
        Ok(_) => Probe {
            facility: Facility::NetworkNamespaces,
            available: true,
            evidence: "unshare --user --net --map-root-user succeeded".to_owned(),
        },
        Err(e) => unavailable(Facility::NetworkNamespaces, &e.to_string()),
    }
}

/// What a fresh namespace's kernel forwarding state is, and whether it can be
/// changed.
///
/// **This one publishes its measurement, not just its verdict.** The other
/// probes answer "can this host do X"; this one also has to answer "and what
/// did it hand us", because the value a namespace inherits is the whole reason
/// [`Facility::ForwardingControl`] exists. A runner that reports
/// `AVAILABLE … came up ip_forward=1` is telling the reader that its namespaces
/// arrive forwarding and that every topology in this laboratory is turning that
/// off — which is exactly the fact that was missing while two NAT scenarios
/// failed on it.
fn probe_forwarding_control(runner: &mut Runner) -> Probe {
    // `sysctl` first, /proc as the fallback, matching what `twinnet::fabric`
    // does — a probe that used a mechanism the fabric does not would answer a
    // question nobody asked.
    let script = "\
        v4=$(cat /proc/sys/net/ipv4/ip_forward); \
        v6=$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo absent); \
        { sysctl -qw net.ipv4.ip_forward=0 2>/dev/null || \
          echo 0 > /proc/sys/net/ipv4/ip_forward; } && \
        after=$(cat /proc/sys/net/ipv4/ip_forward) && \
        echo \"a fresh namespace came up ip_forward=$v4 \
ipv6.conf.all.forwarding=$v6; writing 0 left ip_forward=$after\" && \
        [ \"$after\" = 0 ]";
    match runner.run(
        "unshare",
        &["--user", "--net", "--map-root-user", "sh", "-c", script],
    ) {
        Ok(out) => Probe {
            facility: Facility::ForwardingControl,
            available: true,
            evidence: String::from_utf8_lossy(&out.stdout).trim().to_owned(),
        },
        Err(e) => unavailable(Facility::ForwardingControl, &e.to_string()),
    }
}

/// Runs a probe script inside a throwaway user+net namespace.
fn probe_in_ns(runner: &mut Runner, facility: Facility, script: &str) -> Probe {
    match runner.run(
        "unshare",
        &["--user", "--net", "--map-root-user", "sh", "-c", script],
    ) {
        Ok(_) => Probe {
            facility,
            available: true,
            evidence: "probed inside an unprivileged user+net namespace".to_owned(),
        },
        Err(e) => unavailable(facility, &e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_facility_is_probed_exactly_once() {
        let caps = HostCapabilities::probe();
        assert_eq!(caps.probes.len(), Facility::ALL.len());
        for f in Facility::ALL {
            assert_eq!(
                caps.probes.iter().filter(|p| p.facility == f).count(),
                1,
                "{} must be probed exactly once — a facility with no probe would \
                 default to `unavailable` and silently disable a scenario family",
                f.name()
            );
        }
    }

    #[test]
    fn missing_names_the_first_absent_facility() {
        let caps = HostCapabilities::probe();
        // Whatever this host provides, asking for a facility it does not have
        // must name it. `Containers` is the one most likely absent here, but the
        // assertion is written to hold either way.
        let all = Facility::ALL;
        let absent: Vec<_> = all.iter().copied().filter(|f| !caps.has(*f)).collect();
        match caps.missing(&all) {
            Some(f) => assert_eq!(Some(f), absent.first().copied()),
            None => assert!(
                absent.is_empty(),
                "missing() said nothing is absent while {absent:?} are"
            ),
        }
    }

    #[test]
    fn probe_of_an_absent_tool_is_unavailable_with_a_reason() {
        let p = probe_tool(Facility::Nftables, "twinlab-no-such-tool-9f1c");
        assert!(!p.available);
        assert!(
            p.evidence.contains("not installed"),
            "an unavailable facility must say why: {}",
            p.evidence
        );
    }
}
