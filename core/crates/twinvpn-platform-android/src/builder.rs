//! The `VpnService.Builder` **programme**: a `NetworkContract` rendered into an
//! ordered list of typed operations, with no `#[cfg]` and no JNI in sight.
//!
//! **Authority:** `docs/networking.md` §5.1 (the adapter contract), §5.2's
//! Android row (`VpnService.Builder`: `addAddress`, `addRoute`, `addDnsServer`,
//! `addDisallowedApplication`), §6.2 (the 1280 floor), §9.1 (the four leak
//! channels); ADR-0012 §11.6's Android row (`0.0.0.0/0` **and** `::/0`), KS-17;
//! ADR-0010 R1 and R6; ADR-0011; `docs/implementation/ownership.md` §9.2's
//! design rule.
//!
//! # Why this is a value and not a sequence of JNI calls
//!
//! `ownership.md` §9.2, binding on wave 3 through §10.3: *"every layer that can
//! be target-free is target-free"*. The decision of **what to claim** is the
//! whole of the Android enforcement point — ADR-0012 §11.6 lists no firewall for
//! Android, because `VpnService.Builder`'s route claim *is* the firewall — so it
//! is precisely the layer that must be exercised by `make test` on a Linux host
//! rather than observed on a device.
//!
//! So [`render`] is a pure function from a [`NetworkContract`] to a
//! [`Programme`], the JNI layer walks the programme and does nothing else, and
//! every rule below is a test in this file. This is `twinvpn-platform-linux`'s
//! nftables discipline — ruleset text rendered and parsed exhaustively on a host
//! with no `nft` installed — with `nft` replaced by `VpnService.Builder`.
//!
//! # The five rules the renderer enforces
//!
//! 1. **Both families or neither.** If either family's default route is claimed,
//!    **both** `0.0.0.0/0` and `::/0` are claimed. ADR-0012 §11.6's Android row
//!    names both literally, and ADR-0010 R6 requires that IPv6 cannot bypass
//!    tunnel policy "including when IPv6 appears *after* the tunnel is up" — on
//!    Android an unclaimed family does not fall through to a firewall, because
//!    there is no firewall; it egresses. A one-family claim is the leak.
//! 2. **`Blocked` claims everything.** ADR-0012's `BLOCKED` posture is the same
//!    route claim as `PROTECTED`; see [`crate::posture`] for why the *swap* is a
//!    disposition flag rather than a re-`establish()`.
//! 3. **No `allowBypass()`.** There is no operation for it. A bypassing socket
//!    is `docs/networking.md` §9.1's leak channel 1 with the OS's blessing, and
//!    the way to make it unreachable is to have no way to say it.
//! 4. **MTU floor 1280.** §6.2 selects "1280 floor + DPLPMTUD"; a lower value is
//!    refused rather than clamped, because a silently clamped MTU is a tunnel
//!    that black-holes at a size nobody chose.
//! 5. **Every untrusted length is bounded before it is used.** Search domains,
//!    resolvers per family, routes and disallowed packages are all checked
//!    against `contracts/registry/limits.json` before anything is allocated
//!    (`ownership.md` §6 rules 9 and 10).
//!
//! # What Android cannot do, reported rather than emulated
//!
//! `DnsConfig::split_domains` has **no `VpnService` expression**. Android's VPN
//! DNS is all-or-nothing per interface; there is no per-suffix scoping API at
//! any API level this product supports. [`Programme::unsupported`] carries
//! `DNS.PLATFORM.SCOPED_API_UNAVAILABLE` — a *registered* code — so the fact
//! reaches the diagnostic bundle instead of being silently dropped.

use twinvpn_types::{
    codes, AddressFamily, IpAddr, IpPrefix, PerFamily, ReasonCode, V4Addr, V6Addr,
};

use twinvpn_platform::{DnsConfig, NetworkContract, OsDetail, PlatformError, Ruleset};

/// `contracts/registry/limits.json` `dns.max_search_domains`.
pub const MAX_SEARCH_DOMAINS: usize = 32;
/// `contracts/registry/limits.json` `dns.max_resolvers_per_family`.
pub const MAX_RESOLVERS_PER_FAMILY: usize = 8;
/// `contracts/registry/limits.json` `dns.max_domain_name_bytes`.
pub const MAX_DOMAIN_NAME_BYTES: usize = 253;
/// `contracts/registry/limits.json` `routing.max_prefixes_per_advertisement`.
///
/// Reused as the bound on how many routes one `establish()` may carry: the
/// registry has no `VpnService`-specific number and inventing one would be a
/// second bound to keep in step with the first.
pub const MAX_ROUTES_PER_FAMILY: usize = 256;
/// The `docs/networking.md` §6.2 MTU floor. Below this the tunnel is refused.
pub const MTU_FLOOR: u32 = 1280;
/// The most package names `addDisallowedApplication` will be called with.
///
/// Not from `limits.json` — the registry has no bound for a platform-local app
/// exclusion set, because it is not a wire value. Stated here as a decision, and
/// chosen to match `capability.max_tokens_per_advertisement` so the number in
/// the tree has one source rather than two.
pub const MAX_DISALLOWED_PACKAGES: usize = 32;
/// The longest Android package name. The platform's own limit is 255 characters.
pub const MAX_PACKAGE_NAME_BYTES: usize = 255;

/// One call the JNI layer makes on a `VpnService.Builder`.
///
/// Typed, never stringly: `twinvpn_types`' address types have **no `Display`**
/// because ADR-0015 §11.4 classes an address `SENSITIVE`, and rendering one to
/// text here to hand to `InetAddress.getByName` would build the exact
/// address-to-string path that classification exists to prevent. The JNI layer
/// calls `InetAddress.getByAddress(byte[])` on the octets instead.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BuilderOp {
    /// `Builder.setMtu(int)`.
    SetMtu(u32),
    /// `Builder.addAddress(InetAddress, int)` — the overlay's own address.
    AddAddress {
        /// The address.
        address: IpAddr,
        /// Its prefix length.
        prefix_len: u32,
    },
    /// `Builder.addRoute(InetAddress, int)` — a destination claimed by the tun.
    AddRoute {
        /// The destination prefix.
        destination: IpPrefix,
    },
    /// `Builder.addDnsServer(InetAddress)`.
    AddDnsServer(IpAddr),
    /// `Builder.addSearchDomain(String)`.
    AddSearchDomain(String),
    /// `Builder.addDisallowedApplication(String)`.
    AddDisallowedApplication(String),
    /// `Builder.setBlocking(boolean)` on the returned descriptor.
    SetBlocking(bool),
    /// `Builder.establish()`, which yields the `ParcelFileDescriptor`.
    ///
    /// Always last, always exactly once. A programme that established twice
    /// would take the platform's single VPN slot away from itself.
    Establish,
}

/// A rendered `VpnService.Builder` programme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Programme {
    /// The operations, in the order the JNI layer must make them.
    pub ops: Vec<BuilderOp>,
    /// Which families' default routes this programme claims.
    ///
    /// A separate, explicit fact rather than something a reader derives by
    /// scanning `ops`: ADR-0012 §11.6's Android row is a claim about exactly
    /// this, and [`crate::posture`] reads it to answer `installed_ruleset`.
    pub claims_default: PerFamily<bool>,
    /// Conditions the contract asked for that Android cannot express.
    ///
    /// Registered codes, so they reach the diagnostic bundle as codes rather
    /// than as a comment nobody reads.
    pub unsupported: Vec<ReasonCode>,
}

impl Programme {
    /// Whether this programme claims the default route for **both** families.
    ///
    /// ADR-0010 R1's question, asked as one boolean rather than two, because the
    /// only interesting answer is "both" — [`render`] refuses to produce a
    /// programme where the two halves disagree.
    #[must_use]
    pub const fn claims_both_defaults(&self) -> bool {
        self.claims_default.v4 && self.claims_default.v6
    }
}

/// The shell-supplied facts a programme needs that the seam does not carry.
///
/// **CD-2: injected at construction, never discovered.** Every field is
/// something only the Android shell knows, and none of them is a decision:
/// the session label is chrome, the exclusions are user configuration the core
/// has already resolved.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VpnConfig {
    /// Package names to exclude from the tunnel, in the order the user set them.
    ///
    /// `addDisallowedApplication` — never `addAllowedApplication`. The two are
    /// mutually exclusive on the platform, and the allow-list form makes the
    /// tunnel's coverage the complement of a list that a new app is not on,
    /// which is fail-**open** as the app set changes. The deny-list form is
    /// fail-closed by default, so a package that appears after the tunnel is up
    /// is protected rather than exempt.
    pub disallowed_packages: Vec<String>,
}

/// Renders one generation into a `VpnService.Builder` programme.
///
/// # Errors
///
/// - [`PlatformError::RouteProgrammingDenied`] if the contract's default-route
///   claim is asymmetric between families (rule 1), if a bound from
///   `limits.json` is exceeded (rule 5), or if a package name is malformed.
/// - [`PlatformError::OsUnsupported`] if the MTU is below [`MTU_FLOOR`].
pub fn render(contract: &NetworkContract, config: &VpnConfig) -> Result<Programme, PlatformError> {
    // ---- rule 4: the MTU floor, refused rather than clamped ---------------
    if contract.mtu < MTU_FLOOR {
        return Err(PlatformError::OsUnsupported(Some(OsDetail {
            code: i64::from(contract.mtu),
            call: "VpnService.Builder.setMtu",
        })));
    }

    // ---- rule 5: bound every untrusted length BEFORE allocating -----------
    check_bounds(contract, config)?;

    // ---- rule 1 and 2: what the claim covers ------------------------------
    //
    // The claim is computed from the contract, and then WIDENED to both
    // families whenever either family is claimed or the ruleset is Blocked.
    // Widening rather than refusing is the fail-closed direction: a v4-only
    // full-tunnel contract on Android would leave IPv6 egressing outside the
    // tunnel, and claiming ::/0 as well costs nothing when there is no v6
    // traffic and closes the leak when there is.
    let asked = PerFamily::new(
        contract.routes.v4.iter().any(is_default),
        contract.routes.v6.iter().any(is_default),
    );
    let claims_default = if contract.ruleset == Ruleset::Blocked || asked.v4 || asked.v6 {
        PerFamily::new(true, true)
    } else {
        PerFamily::new(false, false)
    };

    let mut ops = Vec::new();
    let mut unsupported = Vec::new();

    ops.push(BuilderOp::SetMtu(contract.mtu));

    // ---- addresses, v4 then v6, both families always ----------------------
    for family in [AddressFamily::V4, AddressFamily::V6] {
        for prefix in contract.addresses.get(family) {
            ops.push(BuilderOp::AddAddress {
                address: prefix.address(),
                prefix_len: prefix.prefix_len(),
            });
        }
    }

    // ---- routes -----------------------------------------------------------
    if claims_default.v4 {
        ops.push(BuilderOp::AddRoute {
            destination: default_prefix(AddressFamily::V4),
        });
    }
    if claims_default.v6 {
        ops.push(BuilderOp::AddRoute {
            destination: default_prefix(AddressFamily::V6),
        });
    }
    // Non-default routes are added after the default claim so the programme is
    // deterministic and diffable. Android's routing table is longest-prefix, so
    // order carries no semantics -- but a non-deterministic programme is one a
    // test cannot assert on, which is the whole point of this module.
    for family in [AddressFamily::V4, AddressFamily::V6] {
        for entry in contract.routes.get(family) {
            if is_default(entry) {
                continue;
            }
            ops.push(BuilderOp::AddRoute {
                destination: entry.destination,
            });
        }
    }

    // ---- DNS --------------------------------------------------------------
    render_dns(&contract.dns, &mut ops, &mut unsupported);

    // ---- app exclusions ---------------------------------------------------
    for package in &config.disallowed_packages {
        ops.push(BuilderOp::AddDisallowedApplication(package.clone()));
    }

    // `setBlocking(false)`: the descriptor stays non-blocking, which is
    // Android's own default and is stated explicitly rather than assumed.
    //
    // Not an enforcement decision -- the fd's blocking mode says nothing about
    // what is dropped. It is a datapath one: `crate::tun` drives the descriptor
    // through tokio's readiness driver on the runtime `twinvpn-env` injected, so
    // a blocking descriptor would park a worker thread per tunnel for the life
    // of the session. The alternative -- a dedicated blocking reader thread --
    // is the shape that ends up wanting a wake lock to stay scheduled, which
    // `ownership.md` §10.2(1) forbids outright.
    ops.push(BuilderOp::SetBlocking(false));
    ops.push(BuilderOp::Establish);

    Ok(Programme {
        ops,
        claims_default,
        unsupported,
    })
}

/// Appends the DNS half, recording what Android cannot express.
fn render_dns(dns: &DnsConfig, ops: &mut Vec<BuilderOp>, unsupported: &mut Vec<ReasonCode>) {
    for family in [AddressFamily::V4, AddressFamily::V6] {
        for resolver in dns.resolvers.get(family) {
            ops.push(BuilderOp::AddDnsServer(*resolver));
        }
    }
    for domain in &dns.search_domains {
        ops.push(BuilderOp::AddSearchDomain(domain.clone()));
    }

    // Android has no per-suffix DNS scoping for a VpnService at any API level
    // this product supports: `addDnsServer` is the whole surface, and it applies
    // to every query the tunnel carries. ADR-0011's split-DNS intent therefore
    // cannot be expressed HERE -- it is enforced by the core's own stub
    // resolver, which is where `docs/networking.md` §9.1's DNS leak channel is
    // actually closed. The FACT is still reported, because a device whose split
    // rules are being served by the stub rather than by the platform is a
    // different device from one where the platform is doing it.
    if !dns.split_domains.is_empty() {
        unsupported.push(codes::DNS_PLATFORM_SCOPED_API_UNAVAILABLE);
    }
}

/// Whether a route entry is a default route for its family.
fn is_default(entry: &twinvpn_platform::RouteEntry) -> bool {
    entry.destination.prefix_len() == 0
}

/// `0.0.0.0/0` or `::/0`.
///
/// Constructed rather than parsed, and `expect`-free: both are canonical by
/// construction (`UNSPECIFIED` has every host bit zero and no zone), so
/// `IpPrefix::new` cannot fail for either. The `unwrap_or_else` below therefore
/// names an unreachable branch rather than swallowing a real error.
fn default_prefix(family: AddressFamily) -> IpPrefix {
    let address = match family {
        AddressFamily::V4 => IpAddr::V4(V4Addr::UNSPECIFIED),
        AddressFamily::V6 => IpAddr::V6(V6Addr::UNSPECIFIED),
    };
    // A zero-length prefix over the unspecified address is canonical in both
    // families; `default_prefix_is_constructible_in_both_families` pins it.
    IpPrefix::new(address, 0).unwrap_or_else(|_| {
        unreachable!("the unspecified address with prefix_len 0 is canonical in both families")
    })
}

/// `ownership.md` §6 rules 9 and 10, applied before any allocation.
fn check_bounds(contract: &NetworkContract, config: &VpnConfig) -> Result<(), PlatformError> {
    let denied = |call: &'static str, observed: usize| {
        PlatformError::RouteProgrammingDenied(Some(OsDetail {
            code: i64::try_from(observed).unwrap_or(i64::MAX),
            call,
        }))
    };

    for family in [AddressFamily::V4, AddressFamily::V6] {
        let routes = contract.routes.get(family).len();
        if routes > MAX_ROUTES_PER_FAMILY {
            return Err(denied("VpnService.Builder.addRoute", routes));
        }
        let resolvers = contract.dns.resolvers.get(family).len();
        if resolvers > MAX_RESOLVERS_PER_FAMILY {
            return Err(denied("VpnService.Builder.addDnsServer", resolvers));
        }
    }
    if contract.dns.search_domains.len() > MAX_SEARCH_DOMAINS {
        return Err(denied(
            "VpnService.Builder.addSearchDomain",
            contract.dns.search_domains.len(),
        ));
    }
    for domain in &contract.dns.search_domains {
        if domain.is_empty() || domain.len() > MAX_DOMAIN_NAME_BYTES {
            return Err(denied("VpnService.Builder.addSearchDomain", domain.len()));
        }
    }
    if config.disallowed_packages.len() > MAX_DISALLOWED_PACKAGES {
        return Err(denied(
            "VpnService.Builder.addDisallowedApplication",
            config.disallowed_packages.len(),
        ));
    }
    for package in &config.disallowed_packages {
        if !is_valid_package_name(package) {
            return Err(denied(
                "VpnService.Builder.addDisallowedApplication",
                package.len(),
            ));
        }
    }
    Ok(())
}

/// Whether `name` is a well-formed Android package name.
///
/// Checked here rather than left to the platform because
/// `addDisallowedApplication` throws `NameNotFoundException` on a malformed
/// name, and an exception thrown midway through a `Builder` leaves a
/// half-configured builder that must be discarded — which, at `apply` time, is
/// the partial-application window `docs/networking.md` §2.3 names.
#[must_use]
pub fn is_valid_package_name(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_PACKAGE_NAME_BYTES {
        return false;
    }
    let mut segments = 0;
    for segment in name.split('.') {
        segments += 1;
        let mut chars = segment.chars();
        match chars.next() {
            Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
            _ => return false,
        }
        if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return false;
        }
    }
    segments >= 2
}

#[cfg(test)]
mod tests;
