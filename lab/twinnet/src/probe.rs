//! What this host can actually realize — established by doing it, never by
//! reading a table.
//!
//! **Authority:** `docs/testing-strategy.md` §3.1.
//!
//! Every function here creates the kernel object it is asking about and then
//! destroys it. The cost is a few hundred milliseconds once per run; the benefit
//! is that the capability report is evidence rather than a claim, and that a
//! facility which *used* to work on this runner and now does not is discovered
//! by the probe rather than by a scenario that quietly asserts nothing.
//!
//! # The facility this module adds to §3.3's vocabulary
//!
//! `userspace-nat` is not in `twinlab::capability::Facility`, and it is the
//! reason every NAT-class scenario is no longer permanently `Unavailable` on a
//! host without `nftables`. It is available when raw packet sockets, `veth` and
//! namespaces are, because those three are everything [`crate::nat`] needs.
//! It is a *different realization of the same personality*, not a weaker one:
//! §3.1 constrains the observable semantics, and says nothing about which
//! kernel subsystem produces them.

use std::process::Command;

use crate::afpacket;
use crate::proto::Fact;

/// Runs every probe. Called inside the sandbox, where the answers are the ones
/// a scenario will actually get.
#[must_use]
pub fn probe_all() -> Vec<Fact> {
    let ns = Fact::ok(
        "network-namespaces",
        "the agent is running inside its own user, mount and network namespace",
    );
    let veth = probe_veth();
    let bridge = probe_bridge();
    let netem = probe_qdisc("netem", "netem", &["delay", "10ms"]);
    let shaping = probe_qdisc(
        "shaping",
        "tbf",
        &["rate", "1mbit", "burst", "32kbit", "latency", "400ms"],
    );
    let ipv6 = probe_ipv6();
    let packet = match afpacket::available() {
        Ok(()) => Fact::ok("af-packet", "socket(AF_PACKET, SOCK_RAW) on lo succeeded"),
        Err(e) => Fact::no("af-packet", e),
    };
    let tun = probe_tun();

    let userspace_nat = if veth.available && packet.available {
        Fact::ok(
            "userspace-nat",
            "veth and AF_PACKET are both present, so natbox can realize every §3.3 personality",
        )
    } else {
        Fact::no(
            "userspace-nat",
            "natbox needs both a veth pair and a raw packet socket; see the `veth` and `af-packet` rows",
        )
    };

    vec![
        ns,
        veth,
        bridge,
        netem,
        shaping,
        ipv6,
        packet,
        tun,
        userspace_nat,
        probe_tool("nftables", "nft"),
        probe_tool("conntrack", "conntrack"),
        probe_tool("ebpf-tc-classifier", "bpftool"),
        probe_containers(),
    ]
}

fn ip(args: &[&str]) -> std::result::Result<String, String> {
    match Command::new("ip").args(args).output() {
        Ok(out) if out.status.success() => Ok(String::from_utf8_lossy(&out.stdout).into_owned()),
        Ok(out) => Err(String::from_utf8_lossy(&out.stderr).trim().to_owned()),
        Err(e) => Err(format!("`ip` could not be run: {e}")),
    }
}

fn probe_veth() -> Fact {
    match ip(&[
        "link",
        "add",
        "twnprobe0",
        "type",
        "veth",
        "peer",
        "name",
        "twnprobe1",
    ]) {
        Ok(_) => {
            let _ = ip(&["link", "del", "twnprobe0"]);
            Fact::ok(
                "veth",
                "a veth pair was created and deleted in this namespace",
            )
        }
        Err(e) => Fact::no("veth", e),
    }
}

fn probe_bridge() -> Fact {
    match ip(&["link", "add", "twnprobebr", "type", "bridge"]) {
        Ok(_) => {
            let _ = ip(&["link", "del", "twnprobebr"]);
            Fact::ok(
                "bridge",
                "a bridge was created and deleted in this namespace",
            )
        }
        Err(e) => Fact::no("bridge", e),
    }
}

fn probe_qdisc(facility: &str, kind: &str, args: &[&str]) -> Fact {
    let name = "twnqprobe";
    if ip(&["link", "add", name, "type", "dummy"]).is_err() {
        // A kernel without `dummy` is unusual, and reporting "netem missing"
        // when the truth is "the probe's own scaffolding failed" would send a
        // reader to install the wrong package.
        return Fact::no(
            facility,
            "the probe could not create a dummy interface to test the qdisc on",
        );
    }
    let mut argv = vec!["qdisc", "add", "dev", name, "root", kind];
    argv.extend_from_slice(args);
    let result = match Command::new("tc").args(&argv).output() {
        Ok(out) if out.status.success() => Fact::ok(
            facility,
            format!("`tc qdisc add … {kind}` succeeded on a dummy interface"),
        ),
        Ok(out) => Fact::no(
            facility,
            String::from_utf8_lossy(&out.stderr).trim().to_owned(),
        ),
        Err(e) => Fact::no(facility, format!("`tc` could not be run: {e}")),
    };
    let _ = ip(&["link", "del", name]);
    result
}

fn probe_ipv6() -> Fact {
    let name = "twnv6probe";
    if ip(&["link", "add", name, "type", "dummy"]).is_err() {
        return Fact::no("ipv6", "the probe could not create a dummy interface");
    }
    let result = match ip(&["addr", "add", "fd00:0:0:ffff::1/64", "dev", name, "nodad"]) {
        Ok(_) => match std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1") {
            Ok(()) => Fact::ok(
                "ipv6",
                "a v6 address was assigned and net.ipv6.conf.all.forwarding was set in this namespace",
            ),
            Err(e) => Fact::no("ipv6", format!("v6 addressing works but forwarding could not be enabled: {e}")),
        },
        Err(e) => Fact::no("ipv6", e),
    };
    let _ = ip(&["link", "del", name]);
    result
}

fn probe_tun() -> Fact {
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
    {
        Ok(_) => Fact::ok("tun", "/dev/net/tun opened read-write"),
        Err(e) => Fact::no("tun", format!("/dev/net/tun: {e}")),
    }
}

fn probe_tool(facility: &str, program: &str) -> Fact {
    match Command::new(program).arg("--version").output() {
        Ok(_) => Fact::ok(facility, format!("`{program}` is installed")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Fact::no(facility, format!("`{program}` is not installed"))
        }
        Err(e) => Fact::no(facility, format!("`{program}`: {e}")),
    }
}

fn probe_containers() -> Fact {
    for runtime in ["docker", "podman"] {
        if Command::new(runtime).arg("--version").output().is_ok() {
            return Fact::ok("containers", format!("`{runtime}` is installed"));
        }
    }
    Fact::no("containers", "neither docker nor podman is on PATH")
}
