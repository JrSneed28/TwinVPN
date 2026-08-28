//! Fail-closed, decided by the wire.
//!
//! **Authority:** `docs/testing-strategy.md` §4 rule **PT-2**; ADR-0011 §11.12
//! (P08's conformance surface); ADR-0012 §11.9 (P07 and P09's).
//!
//! > For every test that asserts a *security* property, an independent
//! > wire-capture oracle MUST corroborate it, because a system reporting on
//! > itself is not sufficient evidence for a security property.
//!
//! The rule these tests exist to enforce:
//!
//! > **A test MUST fail if protected IPv4, IPv6 or DNS traffic escapes through
//! > an unauthorized path.**
//!
//! # Every assertion here is paired with something that breaks it
//!
//! `tests/README.md` §3: "a test that cannot fail is not a test." A capture that
//! recorded nothing — because the observer bound the wrong interface, or started
//! after the traffic, or was silently denied a raw socket — is indistinguishable
//! from a perfectly sealed tunnel and produces the identical green line. So each
//! sealed-tunnel assertion in this file is preceded, **in the same test**, by a
//! deliberate leak that the same oracle on the same capture must catch.
//!
//! # What this rig does and does not establish
//!
//! It establishes that protected addressing and plaintext name resolution do not
//! appear on the underlay, judged by reading the underlay. It does **not**
//! establish confidentiality: [`twinnet::tun`] is a real encapsulation and not a
//! real cryptographic tunnel, and no assertion here claims a payload was
//! unreadable.

mod common;

use common::{
    settle, DEVICE_UNDERLAY, EXIT_OVERLAY_V4, EXIT_UNDERLAY, LAN_HOST, OVERLAY_V4, OVERLAY_V6,
    ROGUE_UNDERLAY, TUNNEL_PORT,
};
use twinnet::observer::{Prefix, Reason};
use twinnet::{Capture, LeakPolicy};

/// The prefixes that must never appear in the clear on the underlay.
fn protected() -> (Prefix, Prefix) {
    (
        Prefix::parse(OVERLAY_V4).expect("the overlay v4 prefix parses"),
        Prefix::parse(OVERLAY_V6).expect("the overlay v6 prefix parses"),
    )
}

/// The policy a full tunnel is judged by: nothing leaves except the tunnel
/// itself.
fn full_tunnel_policy() -> LeakPolicy {
    let (v4, v6) = protected();
    LeakPolicy::sealed().protecting(v4).protecting(v6).allowing(
        EXIT_UNDERLAY.parse().expect("a literal"),
        Some(TUNNEL_PORT),
        "the tunnel's own underlay endpoint",
    )
}

/// Starts a capture on the device's underlay and returns where it will land.
fn observe(rig: &mut common::Rig, label: &str, ms: u64) -> std::path::PathBuf {
    let mut fabric = std::mem::replace(&mut rig.fabric, twinnet::fabric::Fabric::new(&rig.scratch));
    let (_, path) = fabric
        .start_capture(&mut rig.sb, "device", "wan", label, ms)
        .expect("the observer must start");
    rig.fabric = fabric;
    settle();
    path
}

fn agent(rig: &common::Rig) -> String {
    rig.sb.agent_path().display().to_string()
}

/// Sends one plaintext DNS query from the device.
fn dns(rig: &mut common::Rig, server: &str, name: &str) {
    let a = agent(rig);
    let server = format!("{server}:53");
    let _ = rig.sb.run(
        Some("device"),
        &[
            &a,
            "dns-query",
            "--server",
            &server,
            "--name",
            name,
            "--wait-ms",
            "250",
        ],
    );
}

/// Sends UDP from the device to an overlay address.
fn to_overlay(rig: &mut common::Rig, dst: &str) -> twinnet::Ran {
    let a = agent(rig);
    // An IPv6 literal needs brackets before a port. Without them the sender's
    // address parse fails, the command exits non-zero, and the capture is
    // silent — which reads exactly like a sealed tunnel. This is the shape of
    // mistake the positive control exists to catch, and it caught it.
    let to = if dst.contains(':') {
        format!("[{dst}]:9")
    } else {
        format!("{dst}:9")
    };
    let bind = if dst.contains(':') {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    rig.sb
        .run(
            Some("device"),
            &[
                &a,
                "udp-send",
                "--to",
                &to,
                "--bind",
                bind,
                "--count",
                "3",
                "--interval-ms",
                "30",
                "--wait-ms",
                "80",
            ],
        )
        .expect("the sender must run")
}

fn load(path: &std::path::Path) -> Capture {
    // The observer writes as it goes; give the last packet time to land.
    std::thread::sleep(std::time::Duration::from_millis(700));
    Capture::load(path).expect("the capture must exist — a missing one is not an empty one")
}

// ===========================================================================

#[test]
fn plaintext_dns_to_an_unauthorized_resolver_is_caught_and_names_the_leaked_name() {
    let Some(mut rig) = common::or_skip(
        "leak-dns-positive-control",
        common::build_tunnel_site("leak-dns-positive-control"),
    ) else {
        return;
    };
    let path = observe(&mut rig, "dns-control", 4_000);
    dns(&mut rig, ROGUE_UNDERLAY, "canary.twinvpn.invalid");
    let capture = load(&path);

    assert!(
        !capture.is_silent(),
        "the observer saw nothing at all, so no assertion about leaks on this \
         interface would have meant anything"
    );
    let escapes = full_tunnel_policy()
        .resolver(EXIT_OVERLAY_V4.parse().expect("a literal"))
        .audit(&capture);
    let dns_leaks: Vec<_> = escapes
        .iter()
        .filter(|e| matches!(e.reason, Reason::UnauthorizedDns { .. }))
        .collect();
    assert!(
        !dns_leaks.is_empty(),
        "a plaintext DNS query to {ROGUE_UNDERLAY} left the device and the oracle did not \
         catch it. Every sealed-tunnel assertion in this file is worthless if this one fails."
    );
    let named = dns_leaks.iter().any(|e| {
        matches!(&e.reason, Reason::UnauthorizedDns { qname } if qname.as_deref() == Some("canary.twinvpn.invalid"))
    });
    assert!(
        named,
        "the oracle caught a DNS leak but could not say which name leaked: {}",
        dns_leaks
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ")
    );
}

#[test]
fn a_full_tunnel_puts_no_protected_address_and_no_plaintext_name_on_the_underlay() {
    let Some(mut rig) = common::or_skip(
        "full-tunnel-sealed",
        common::build_tunnel_site("full-tunnel-sealed"),
    ) else {
        return;
    };
    common::start_tunnel(&mut rig).expect("the tunnel must come up");
    let path = observe(&mut rig, "full-tunnel", 6_000);

    // The positive control first, on the same capture: a deliberate leak the
    // oracle must catch, so the silence that follows means something.
    dns(&mut rig, ROGUE_UNDERLAY, "control.twinvpn.invalid");
    let control = load(&path);
    let policy = full_tunnel_policy().resolver(EXIT_OVERLAY_V4.parse().expect("a literal"));
    let caught = policy.audit(&control);
    assert!(
        caught
            .iter()
            .any(|e| matches!(e.reason, Reason::UnauthorizedDns { .. })),
        "the positive control did not leak, so this capture proves nothing"
    );
    let control_len = control.records.len();

    // Now the protected traffic. Both families, because ADR-0010 R1 is one story
    // covering both and a v4-only assertion would leave the v6 half uncertified.
    to_overlay(&mut rig, EXIT_OVERLAY_V4);
    to_overlay(&mut rig, common::EXIT_OVERLAY_V6);
    dns(&mut rig, EXIT_OVERLAY_V4, "inside.twinvpn.invalid");
    let after = load(&path);

    assert!(
        after.records.len() > control_len,
        "the capture did not grow while protected traffic was being sent, so the \
         observer stopped seeing the interface"
    );
    let (v4, v6) = protected();
    let protected_escapes: Vec<_> = policy
        .audit(&after)
        .into_iter()
        .filter(|e| {
            matches!(
                e.reason,
                Reason::ProtectedSource { .. } | Reason::ProtectedDestination { .. }
            )
        })
        .collect();
    assert!(
        protected_escapes.is_empty(),
        "protected addressing appeared in the clear on the underlay. \
         {v4:?} and {v6:?} must never be an outer source or destination:\n  {}",
        protected_escapes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n  ")
    );

    // The in-tunnel resolver's query must not appear as plaintext DNS either:
    // it is inside the encapsulation, and an oracle that saw it would be
    // reporting that the tunnel did not encapsulate.
    let inside_names: Vec<_> = after
        .matching(|r| r.dns_qname.as_deref() == Some("inside.twinvpn.invalid"))
        .into_iter()
        .map(|r| format!("{:?} -> {:?}", r.src, r.dst))
        .collect();
    assert!(
        inside_names.is_empty(),
        "a query sent to the in-tunnel resolver was readable on the underlay: {inside_names:?}"
    );
}

#[test]
fn a_protected_prefix_routed_out_the_underlay_is_caught_in_both_families() {
    let Some(mut rig) = common::or_skip(
        "leak-protected-prefix",
        common::build_tunnel_site("leak-protected-prefix"),
    ) else {
        return;
    };
    // No tunnel. The overlay prefixes are pointed at the underlay instead, which
    // is the shape of every real leak: a route that outlived the interface it
    // was written for.
    rig.sb
        .must(
            Some("device"),
            &[
                "ip",
                "-4",
                "route",
                "replace",
                OVERLAY_V4,
                "via",
                EXIT_UNDERLAY,
                "dev",
                "wan",
            ],
        )
        .expect("the mutant route must install");
    rig.sb
        .must(
            Some("device"),
            &[
                "ip",
                "-6",
                "route",
                "replace",
                OVERLAY_V6,
                "via",
                "2001:db8:18::3",
                "dev",
                "wan",
            ],
        )
        .expect("the mutant v6 route must install");

    let path = observe(&mut rig, "protected-leak", 5_000);
    to_overlay(&mut rig, EXIT_OVERLAY_V4);
    to_overlay(&mut rig, common::EXIT_OVERLAY_V6);
    let capture = load(&path);

    let escapes = full_tunnel_policy().audit(&capture);
    let v4_caught = escapes.iter().any(
        |e| matches!(&e.reason, Reason::ProtectedDestination { prefix } if prefix.addr.is_ipv4()),
    );
    let v6_caught = escapes.iter().any(
        |e| matches!(&e.reason, Reason::ProtectedDestination { prefix } if prefix.addr.is_ipv6()),
    );
    assert!(
        v4_caught,
        "an IPv4 overlay destination went out the underlay and the oracle missed it. \
         Observed: {}",
        escapes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ")
    );
    assert!(
        v6_caught,
        "an IPv6 overlay destination went out the underlay and the oracle missed it. \
         A v4-only leak oracle certifies nothing about the v6 half. Observed: {}",
        escapes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ")
    );
}

#[test]
fn a_split_tunnel_keeps_the_overlay_off_the_underlay_while_the_rest_still_flows() {
    let Some(mut rig) = common::or_skip("split-tunnel", common::build_tunnel_site("split-tunnel"))
    else {
        return;
    };
    common::start_tunnel(&mut rig).expect("the tunnel must come up");
    let path = observe(&mut rig, "split-tunnel", 6_000);

    // Protected traffic goes through the tunnel; unprotected traffic goes out
    // the underlay, which is what makes this a split tunnel rather than a full
    // one.
    to_overlay(&mut rig, EXIT_OVERLAY_V4);
    let a = agent(&rig);
    let rogue = format!("{ROGUE_UNDERLAY}:9");
    let _ = rig.sb.run(
        Some("device"),
        &[
            &a,
            "udp-send",
            "--to",
            &rogue,
            "--count",
            "2",
            "--wait-ms",
            "80",
        ],
    );
    let capture = load(&path);

    let (v4, v6) = protected();
    let policy = LeakPolicy::sealed()
        .protecting(v4)
        .protecting(v6)
        .protected_only();
    let escapes = policy.audit(&capture);
    assert!(
        escapes.is_empty(),
        "a split tunnel still may not put protected addressing on the underlay:\n  {}",
        escapes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n  ")
    );

    // And the negative half: the unprotected traffic MUST be visible, or this
    // test would pass just as well against a device with no network at all.
    let unprotected =
        capture.matching(|r| r.dst.as_deref() == Some(ROGUE_UNDERLAY) && r.dport == Some(9));
    assert!(
        !unprotected.is_empty(),
        "no unprotected traffic reached the underlay, so `nothing protected leaked` is \
         a statement about a dead interface"
    );
}

#[test]
fn local_network_access_reaches_the_lan_without_putting_the_overlay_on_it() {
    let Some(mut rig) = common::or_skip("lan-access", common::build_tunnel_site("lan-access"))
    else {
        return;
    };
    common::start_tunnel(&mut rig).expect("the tunnel must come up");
    let mut fabric = std::mem::replace(&mut rig.fabric, twinnet::fabric::Fabric::new(&rig.scratch));
    let (_, lan_path) = fabric
        .start_capture(&mut rig.sb, "device", "lan", "lan-access", 5_000)
        .expect("the LAN observer must start");
    rig.fabric = fabric;
    settle();

    let a = agent(&rig);
    let lan = format!("{LAN_HOST}:9");
    let _ = rig.sb.run(
        Some("device"),
        &[
            &a,
            "udp-send",
            "--to",
            &lan,
            "--count",
            "2",
            "--wait-ms",
            "80",
        ],
    );
    to_overlay(&mut rig, EXIT_OVERLAY_V4);
    let capture = load(&lan_path);

    let reached_lan = capture.matching(|r| r.dst.as_deref() == Some(LAN_HOST));
    assert!(
        !reached_lan.is_empty(),
        "local network access is a named default in ADR-0012 and the LAN was not reached"
    );

    let (v4, v6) = protected();
    let escapes = LeakPolicy::sealed()
        .protecting(v4)
        .protecting(v6)
        .protected_only()
        .audit(&capture);
    assert!(
        escapes.is_empty(),
        "overlay addressing appeared on the LAN segment. Reaching the LAN must not mean \
         exposing the TwinNet to it:\n  {}",
        escapes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n  ")
    );
    let _ = DEVICE_UNDERLAY;
}
