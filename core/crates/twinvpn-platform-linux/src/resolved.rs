//! The **`systemd-resolved` scoped-resolver path**: ADR-0011 DN-21's preferred
//! Linux form.
//!
//! **Authority:** [ADR-0011](../../../../docs/adr/ADR-0011-dns-handling.md)
//! DN-18, DN-19, DN-21, §11.9's Linux row; ADR-0016 PS-6.
//!
//! > **DN-21 — prefer configuration owned by the tunnel object.** Where the
//! > platform lets the resolver configuration live *inside* the tunnel object,
//! > that form MUST be used, because **it dies with the object and needs no
//! > restoration at all**.
//!
//! DN-21's Linux table names exactly two forms. This is the first:
//!
//! | Form | Dies with the tunnel object | Restoration path |
//! |---|---|---|
//! | `SetLinkDNS` + `SetLinkDomains(["~."])` + `SetLinkDefaultRoute(true)` | ✔ per-link config is discarded with the link | none needed; the `RestorePoint` is belt-and-braces |
//! | Owner-tagged `/etc/resolv.conf` rewrite | ✘ | `RestorePoint` + boot restore unit. "**The weakest desktop case**", and it races NetworkManager/`dhclient` |
//!
//! Wave 1 implemented only the second and reported the first as absent, because
//! `org.freedesktop.resolve1` is a **D-Bus** API and no D-Bus client is in the
//! workspace's dependency set — and `core/Cargo.toml` is the integration lead's.
//!
//! # How this reaches `org.freedesktop.resolve1` without a D-Bus dependency
//!
//! Through **`resolvectl(1)`**, which is `systemd`'s own client for that
//! interface and ships with `systemd-resolved` itself. Every subcommand below is
//! a one-to-one front end for the D-Bus method DN-21 names:
//!
//! | DN-21's method | `resolvectl` invocation |
//! |---|---|
//! | `SetLinkDNS(ifindex, addrs)` | `resolvectl dns <link> <addr>…` |
//! | `SetLinkDomains(ifindex, ["~."])` | `resolvectl domain <link> ~.` |
//! | `SetLinkDefaultRoute(ifindex, true)` | `resolvectl default-route <link> yes` |
//! | *(revert)* | `resolvectl revert <link>` |
//!
//! **This is a deliberate trade and it is worth naming.** Spawning a process is
//! slower than a method call, and it puts a `systemd` binary on the critical
//! path. Against that: it needs no new workspace dependency, it is the same
//! mechanism this crate already uses for `nft(8)` — which is likewise a
//! front end for a kernel interface with no stable C-callable form we may take —
//! and the D-Bus method names are `resolvectl`'s own, so there is no second
//! encoding of the interface to drift. The alternative was a hand-written D-Bus
//! marshaller in a crate that has no other use for one, which is a larger and
//! less reviewable surface than four `Command` invocations.
//!
//! The cost is stated rather than hidden: a host running `systemd-resolved`
//! **without** `resolvectl` installed falls back to the `resolv.conf` path and
//! is told so by name, exactly as wave 1's build was.
//!
//! # The guarantee does not move
//!
//! ADR-0011 §11.9 is explicit, and this module does not change it:
//!
//! > **Containment is always ADR-0012 §11.2 class 6 + Tier 2 — one dual-family
//! > object, interface-scoped, default-deny — and it is the guarantee.**
//!
//! [`crate::nft`]'s class-6 denial of 53/853 off the overlay is installed
//! whichever path is taken. What this module improves is *steering*, which
//! DN-15 is careful to say is not security: "a build that filters records but
//! does not block egress is a leaking build that produces prettier timeouts".
//!
//! # DN-18 still applies, and is why `apply` writes the restore point first
//!
//! DN-21's table says a per-link configuration "needs no restoration at all",
//! and then adds "the `RestorePoint` is belt-and-braces". Belt-and-braces is
//! kept: [`crate::resolver::apply_scoped`] persists the restore point **before**
//! the mutation on this path too, because DN-18 admits no exception and because
//! a `resolved` that is restarted while our link exists is a real way for the
//! per-link configuration to survive us in a form nobody expected.

use std::process::{Command, Stdio};

use twinvpn_platform::{DnsConfig, PlatformError};

use crate::addr::addr_text;
use crate::oserr::{self, Context};

/// `systemd`'s client for `org.freedesktop.resolve1`.
pub const RESOLVECTL_BIN: &str = "/usr/bin/resolvectl";

/// The path on a host that puts it in `/bin`.
pub const RESOLVECTL_BIN_ALT: &str = "/bin/resolvectl";

/// The routing domain that makes our link the **default route** for DNS.
///
/// ADR-0011 DN-21's Linux row names it literally: `SetLinkDomains(["~."])`. The
/// `~` prefix makes it a *routing-only* domain — names under it are routed to
/// this link's servers without the domain being appended to short names — and
/// `.` is the root, so it covers everything. `.` without the tilde would be a
/// **search** domain and would append the root label to every lookup, which is
/// a different and wrong thing.
pub const DEFAULT_ROUTE_DOMAIN: &str = "~.";

/// Whether this host can take DN-21's preferred path.
///
/// Both halves are required, and they are different questions: `resolved` must
/// be **in force** (its stub is what the host actually resolves through), and
/// `resolvectl` must be **present** (it is how we reach the D-Bus interface).
/// A host with one and not the other takes the `resolv.conf` path and is told
/// which half was missing.
#[must_use]
pub fn binary() -> Option<&'static str> {
    [RESOLVECTL_BIN, RESOLVECTL_BIN_ALT]
        .into_iter()
        .find(|c| std::path::Path::new(c).exists())
}

/// The three calls DN-21 names, as one ordered application.
///
/// # The order is DN-21's and is not rearranged
///
/// 1. `SetLinkDNS` — the servers. Nothing is routed to a link with no servers,
///    so this must precede the routing domain or there is a window in which the
///    link is the default route for DNS and has nowhere to send it.
/// 2. `SetLinkDomains(["~."])` — the routing domain.
/// 3. `SetLinkDefaultRoute(true)` — the link becomes the default route for
///    names no other link claims.
///
/// **Both families, always.** ADR-0011 DN-13: "a stub MUST NOT filter AAAA
/// because the underlay is v4-only", and ADR-0010 R1 makes a v4-only resolver
/// list the asymmetry the whole design forbids. The v4 and v6 servers go in one
/// `resolvectl dns` invocation, so a host can never end up with one family
/// configured and the other not.
///
/// # Errors
///
/// [`PlatformError`] naming the `resolvectl` invocation that failed and its exit
/// status as typed evidence. **Never a partial success**: a failure at step 2 or
/// 3 leaves the link configured with servers it does not route to, which is a
/// steering failure rather than a leak — containment is unaffected — but it is
/// reported rather than swallowed, and the caller reverts.
pub fn apply(link: &str, config: &DnsConfig) -> Result<(), PlatformError> {
    let binary = binary().ok_or_else(|| oserr::unavailable("resolvectl", libc::ENOENT))?;

    let mut servers: Vec<String> = Vec::new();
    for address in config.resolvers.v4.iter().chain(config.resolvers.v6.iter()) {
        servers.push(addr_text(*address));
    }
    if servers.is_empty() {
        // A link with no servers that is also the DNS default route is a black
        // hole for every name on the host. Refused rather than applied.
        return Err(oserr::unavailable("resolvectl.dns", libc::EINVAL));
    }

    // 1. SetLinkDNS
    let mut args = vec!["dns".to_owned(), link.to_owned()];
    args.extend(servers);
    run(binary, &args)?;

    // 2. SetLinkDomains(["~."]) — plus the search domains, which are ordinary
    //    (non-`~`) entries beside the routing one.
    let mut args = vec![
        "domain".to_owned(),
        link.to_owned(),
        DEFAULT_ROUTE_DOMAIN.to_owned(),
    ];
    for domain in &config.search_domains {
        // The same validation the `resolv.conf` path applies, for the same
        // reason: a domain is untrusted input at this boundary regardless of
        // which mechanism consumes it. A rejected domain is dropped, never
        // escaped into something that parses differently.
        if crate::resolver::is_safe_domain(domain) {
            args.push(domain.clone());
        }
    }
    run(binary, &args)?;

    // 3. SetLinkDefaultRoute(true)
    run(
        binary,
        &[
            "default-route".to_owned(),
            link.to_owned(),
            "yes".to_owned(),
        ],
    )
}

/// `resolvectl revert <link>`: discards **all** per-link configuration.
///
/// DN-19's teardown clause — "point host away … never unbind-then-restore" — is
/// satisfied structurally on this path: reverting the link removes our servers
/// and our routing domain in one call, and the host's prior configuration was
/// never overwritten to begin with, because per-link configuration is additive.
/// That is precisely why DN-21 prefers this form.
///
/// # Errors
///
/// The invocation's failure. A revert of a link that no longer exists is **not**
/// an error: the link dying is what discards the configuration, so the desired
/// state has been reached by another route.
pub fn revert(link: &str) -> Result<(), PlatformError> {
    let binary = binary().ok_or_else(|| oserr::unavailable("resolvectl", libc::ENOENT))?;
    match run(binary, &["revert".to_owned(), link.to_owned()]) {
        Ok(()) => Ok(()),
        // The link is gone, which is the outcome we wanted.
        Err(error)
            if error
                .os_detail()
                .is_some_and(|d| d.code == i64::from(libc::ENODEV)) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// Reads back what `resolved` holds for a link.
///
/// The same discipline as the nftables read-back: what the *service* says, not
/// what our call returned. `resolvectl status <link>` is the query, and its text
/// is scanned for the two facts that matter — that our servers are there, and
/// that the link is the DNS default route.
///
/// # Errors
///
/// The invocation's failure.
pub fn read_back(link: &str) -> Result<LinkState, PlatformError> {
    let binary = binary().ok_or_else(|| oserr::unavailable("resolvectl", libc::ENOENT))?;
    let output = Command::new(binary)
        .args(["status", link])
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        // ADR-0016 Q10: no inherited search path, preload variable or plugin
        // directory reaches a privileged process from here.
        .env_clear()
        .output()
        .map_err(|e| oserr::from_errno(&e, "spawn(resolvectl status)", Context::Resolver))?;
    if !output.status.success() {
        return Err(oserr::unavailable(
            "resolvectl status",
            output.status.code().unwrap_or(libc::EIO),
        ));
    }
    Ok(parse_status(&String::from_utf8_lossy(&output.stdout)))
}

/// What `resolvectl status <link>` reports.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LinkState {
    /// The servers `resolved` holds for this link, as text.
    pub servers: Vec<String>,
    /// Whether the link is the DNS default route (`SetLinkDefaultRoute(true)`).
    pub default_route: bool,
    /// Whether `~.` is among the link's domains.
    pub routes_everything: bool,
}

impl LinkState {
    /// Whether the link is configured the way [`apply`] intended.
    ///
    /// All three, because any two without the third is a steering failure with a
    /// different shape: servers without the routing domain means names are not
    /// sent to us; the routing domain without the default route means only
    /// explicitly-matched names are; and either without servers is a black hole.
    #[must_use]
    pub fn is_scoped(&self) -> bool {
        !self.servers.is_empty() && self.default_route && self.routes_everything
    }
}

/// Parses `resolvectl status <link>`'s human output.
///
/// Its `--json` mode exists but has changed shape across `systemd` versions,
/// where the three lines below have been stable since v239. Parsing is therefore
/// deliberately narrow: it looks for the three facts and ignores everything
/// else, so a new field in the output cannot break it.
///
/// # The continuation-line rule, and why it is not "a line with no colon"
///
/// `resolvectl` wraps a long server list onto following lines with no key. The
/// obvious rule — "a line containing a colon is a new key" — is **wrong here**,
/// because an IPv6 server address is full of colons, and a parser using it
/// reports a v4-only link on a host that has both. That is precisely the
/// asymmetry ADR-0010 R1 forbids, arriving through the parser rather than
/// through the configuration.
///
/// So a continuation line is one that **parses as an IP address**. That is
/// exact: it cannot swallow a key line, and it cannot miss a wrapped address of
/// either family.
#[must_use]
pub fn parse_status(text: &str) -> LinkState {
    let mut state = LinkState::default();
    let mut in_servers = false;
    for line in text.lines() {
        let trimmed = line.trim();

        // The continuation rule, checked FIRST so an IPv6 address is never taken
        // for a key.
        if in_servers && trimmed.parse::<std::net::IpAddr>().is_ok() {
            state.servers.push(trimmed.to_owned());
            continue;
        }
        in_servers = false;

        if let Some(rest) = trimmed.strip_prefix("DNS Servers:") {
            state
                .servers
                .extend(rest.split_whitespace().map(str::to_owned));
            in_servers = true;
        } else if let Some(rest) = trimmed.strip_prefix("DNS Domain:") {
            if rest.split_whitespace().any(|d| d == DEFAULT_ROUTE_DOMAIN) {
                state.routes_everything = true;
            }
        } else if let Some(rest) = trimmed.strip_prefix("Default Route setting:") {
            state.default_route = rest.trim() == "yes";
        }
    }
    state
}

/// One `resolvectl` invocation.
fn run(binary: &str, args: &[String]) -> Result<(), PlatformError> {
    let output = Command::new(binary)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .env_clear()
        .output()
        .map_err(|e| oserr::from_errno(&e, "spawn(resolvectl)", Context::Resolver))?;
    if output.status.success() {
        return Ok(());
    }
    // The tool's own text goes to the log, never to the user: §4.2 requires a
    // registered reason code as the user-facing error, and this is platform
    // detail for a support case.
    tracing::error!(
        target: "twinvpn.platform.linux.resolver",
        exit = output.status.code().unwrap_or(-1),
        argv = ?args,
        detail = %String::from_utf8_lossy(&output.stderr).trim(),
        "resolvectl refused a scoped-resolver call"
    );
    Err(oserr::unavailable(
        "resolvectl",
        output.status.code().unwrap_or(libc::EIO),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_routing_domain_is_dn21s_and_not_a_search_domain() {
        // `~.` is routing-only: names under it go to this link's servers and the
        // domain is NOT appended to short names. A bare `.` would be a search
        // domain and would append the root label to every lookup — a different
        // and wrong thing that looks nearly identical in a diff.
        assert_eq!(DEFAULT_ROUTE_DOMAIN, "~.");
        assert!(DEFAULT_ROUTE_DOMAIN.starts_with('~'));
    }

    #[test]
    fn a_scoped_link_needs_all_three_facts() {
        // Any two without the third is a steering failure with its own shape.
        let full = LinkState {
            servers: vec!["100.127.255.53".to_owned()],
            default_route: true,
            routes_everything: true,
        };
        assert!(full.is_scoped());
        assert!(!LinkState {
            servers: Vec::new(),
            ..full.clone()
        }
        .is_scoped());
        assert!(!LinkState {
            default_route: false,
            ..full.clone()
        }
        .is_scoped());
        assert!(!LinkState {
            routes_everything: false,
            ..full
        }
        .is_scoped());
    }

    #[test]
    fn a_status_read_back_finds_both_families_and_the_default_route() {
        // Real `resolvectl status` shape, both families present — ADR-0010 R1's
        // parity, read back from the service rather than assumed from our call.
        let text = "\
Link 7 (twin0)
    Current Scopes: DNS
         Protocols: -DefaultRoute +LLMNR +mDNS
Default Route setting: yes
       DNS Servers: 100.127.255.53 fd7c:9e5d:2a10:ffff::53
        DNS Domain: ~.
";
        let state = parse_status(text);
        assert!(state.servers.contains(&"100.127.255.53".to_owned()));
        assert!(
            state
                .servers
                .contains(&"fd7c:9e5d:2a10:ffff::53".to_owned()),
            "a v4-only read-back is the asymmetry ADR-0010 R1 forbids"
        );
        assert!(state.default_route);
        assert!(state.routes_everything);
        assert!(state.is_scoped());
    }

    #[test]
    fn a_link_that_is_not_the_default_route_is_not_scoped() {
        // The steering failure §11.9's Linux row names: `resolved` queries ALL
        // links when no link is the DNS default route.
        let text = "\
Link 7 (twin0)
Default Route setting: no
       DNS Servers: 100.127.255.53 fd7c::53
        DNS Domain: ~.
";
        let state = parse_status(text);
        assert!(!state.default_route);
        assert!(!state.is_scoped());
    }

    #[test]
    fn wrapped_server_lines_are_read() {
        // `resolvectl` wraps a long server list onto continuation lines with no
        // key. A parser that stopped at the first line would report a v4-only
        // link on a host that has both.
        let text = "\
       DNS Servers: 100.127.255.53
                    fd7c:9e5d:2a10:ffff::53
        DNS Domain: ~.
Default Route setting: yes
";
        let state = parse_status(text);
        assert_eq!(state.servers.len(), 2);
        assert!(state.is_scoped());
    }

    #[test]
    fn an_empty_status_is_an_unscoped_link_and_never_a_scoped_one() {
        // The fail-safe direction: unable to confirm is not the same as
        // confirmed, and the caller must not read silence as success.
        assert!(!parse_status("").is_scoped());
        assert!(!parse_status("Link 7 (twin0)\n").is_scoped());
    }

    #[test]
    fn the_preferred_path_needs_resolvectl_present_and_says_so_when_it_is_not() {
        // Two different questions: is `resolved` in force, and can we reach its
        // D-Bus interface. This host has neither, and the honest answer is that
        // the binary is absent rather than that the path was taken.
        if let Some(path) = binary() {
            assert!(std::path::Path::new(path).exists());
        } else {
            let error = apply("twin0", &empty_config()).expect_err("no resolvectl");
            assert_eq!(
                error.os_detail().map(|d| d.code),
                Some(i64::from(libc::ENOENT)),
                "the absence is named, not guessed at"
            );
        }
    }

    #[test]
    fn a_link_with_no_servers_is_refused_rather_than_black_holed() {
        // A link that is the DNS default route and has no servers swallows every
        // name on the host. Refused before the first call rather than applied.
        if binary().is_some() {
            let error = apply("twin0", &empty_config()).expect_err("refused");
            assert_eq!(
                error.os_detail().map(|d| d.code),
                Some(i64::from(libc::EINVAL))
            );
        }
    }

    fn empty_config() -> DnsConfig {
        DnsConfig {
            resolvers: twinvpn_types::PerFamily::new(Vec::new(), Vec::new()),
            search_domains: Vec::new(),
            split_domains: Vec::new(),
            is_default_resolver: true,
        }
    }
}
