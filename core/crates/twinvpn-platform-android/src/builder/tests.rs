//! The `VpnService.Builder` programme, asserted as a value.
//!
//! Every rule the renderer enforces is a test here, which is what makes
//! ADR-0012 §11.6's Android row and ADR-0010 R1 **executed** rather than
//! reviewed.

use super::*;
use crate::testkit::{contract, host_v4, host_v6, route};

fn cfg() -> VpnConfig {
    VpnConfig::default()
}

#[test]
fn default_prefix_is_constructible_in_both_families() {
    assert_eq!(default_prefix(AddressFamily::V4).prefix_len(), 0);
    assert_eq!(default_prefix(AddressFamily::V6).prefix_len(), 0);
    assert_eq!(
        default_prefix(AddressFamily::V4).family(),
        AddressFamily::V4
    );
    assert_eq!(
        default_prefix(AddressFamily::V6).family(),
        AddressFamily::V6
    );
}

/// ADR-0012 §11.6's Android row, and ADR-0010 R1, as one assertion.
#[test]
fn a_full_tunnel_claims_both_zero_zero_and_colon_colon() {
    let mut c = contract(1, Ruleset::Protected);
    c.routes.v4.push(route("0.0.0.0/0"));
    c.routes.v6.push(route("::/0"));
    let p = render(&c, &cfg()).expect("render");

    assert!(p.claims_both_defaults());
    let routes: Vec<_> = p
        .ops
        .iter()
        .filter_map(|op| match op {
            BuilderOp::AddRoute { destination } => Some(*destination),
            _ => None,
        })
        .collect();
    assert!(routes.contains(&default_prefix(AddressFamily::V4)));
    assert!(routes.contains(&default_prefix(AddressFamily::V6)));
}

/// **The IPv6 leak, closed in the renderer.** A contract that asks for a v4
/// default and no v6 default is the shape ADR-0010 R6 forbids: on Android
/// there is no firewall behind the claim, so an unclaimed family egresses.
#[test]
fn a_v4_only_default_claim_is_widened_to_v6_rather_than_leaking() {
    let mut c = contract(1, Ruleset::Protected);
    c.routes.v4.push(route("0.0.0.0/0"));
    // NOTE: no v6 default asked for.
    let p = render(&c, &cfg()).expect("render");
    assert!(
        p.claims_default.v6,
        "an unclaimed v6 default on Android egresses outside the tunnel"
    );
    assert!(p.claims_both_defaults());
}

/// The mirror case, which is the one a v4-first implementation forgets.
#[test]
fn a_v6_only_default_claim_is_widened_to_v4_rather_than_leaking() {
    let mut c = contract(1, Ruleset::Protected);
    c.routes.v6.push(route("::/0"));
    let p = render(&c, &cfg()).expect("render");
    assert!(p.claims_default.v4);
    assert!(p.claims_both_defaults());
}

/// ADR-0012 KS-17: `BLOCKED` is not "no rules", it is a claim over
/// everything with nothing forwarded.
#[test]
fn the_blocked_ruleset_claims_both_families_even_with_no_routes_asked_for() {
    let c = contract(1, Ruleset::Blocked);
    assert!(c.routes.v4.is_empty() && c.routes.v6.is_empty());
    let p = render(&c, &cfg()).expect("render");
    assert!(
        p.claims_both_defaults(),
        "BLOCKED that claims nothing is BLOCKED that blocks nothing"
    );
}

/// A split-tunnel contract asks for neither default, and gets neither. The
/// widening rule fires on "either", not on "always".
#[test]
fn a_split_tunnel_contract_claims_no_default_in_either_family() {
    let mut c = contract(1, Ruleset::Protected);
    c.routes.v4.push(route("100.64.0.0/10"));
    let p = render(&c, &cfg()).expect("render");
    assert!(!p.claims_default.v4 && !p.claims_default.v6);
    assert_eq!(
        p.ops
            .iter()
            .filter(|op| matches!(op, BuilderOp::AddRoute { destination } if destination.prefix_len() == 0))
            .count(),
        0
    );
}

/// Rule 3, asserted structurally: there is no operation that can turn on
/// `allowBypass`, so no programme can contain one.
#[test]
fn no_programme_can_express_allow_bypass() {
    let mut c = contract(1, Ruleset::Protected);
    c.routes.v4.push(route("0.0.0.0/0"));
    c.routes.v6.push(route("::/0"));
    let p = render(&c, &cfg()).expect("render");
    // Every variant of BuilderOp, enumerated. If a `Bypass` variant is ever
    // added this match stops compiling, which is the tripwire.
    for op in &p.ops {
        match op {
            BuilderOp::SetMtu(_)
            | BuilderOp::AddAddress { .. }
            | BuilderOp::AddRoute { .. }
            | BuilderOp::AddDnsServer(_)
            | BuilderOp::AddSearchDomain(_)
            | BuilderOp::AddDisallowedApplication(_)
            | BuilderOp::SetBlocking(_)
            | BuilderOp::Establish => {}
        }
    }
}

#[test]
fn establish_is_last_and_happens_exactly_once() {
    let p = render(&contract(1, Ruleset::Blocked), &cfg()).expect("render");
    assert_eq!(p.ops.last(), Some(&BuilderOp::Establish));
    assert_eq!(
        p.ops.iter().filter(|o| **o == BuilderOp::Establish).count(),
        1
    );
}

#[test]
fn an_mtu_below_the_1280_floor_is_refused_never_clamped() {
    let mut c = contract(1, Ruleset::Protected);
    c.mtu = 1279;
    let err = render(&c, &cfg()).expect_err("below the floor");
    assert_eq!(err.reason_code().as_str(), "PLATFORM.OS_UNSUPPORTED");
    assert_eq!(err.os_detail().map(|d| d.code), Some(1279));

    c.mtu = MTU_FLOOR;
    let p = render(&c, &cfg()).expect("at the floor");
    assert_eq!(p.ops.first(), Some(&BuilderOp::SetMtu(1280)));
}

#[test]
fn both_families_of_resolver_reach_the_builder() {
    let mut c = contract(1, Ruleset::Protected);
    c.dns.resolvers.v4.push(host_v4([100, 64, 0, 53]));
    c.dns.resolvers.v6.push(host_v6(0x53));
    let p = render(&c, &cfg()).expect("render");
    let servers: Vec<_> = p
        .ops
        .iter()
        .filter_map(|op| match op {
            BuilderOp::AddDnsServer(a) => Some(a.family()),
            _ => None,
        })
        .collect();
    assert!(servers.contains(&AddressFamily::V4));
    assert!(servers.contains(&AddressFamily::V6));
}

#[test]
fn split_dns_is_reported_as_unavailable_rather_than_silently_dropped() {
    let mut c = contract(1, Ruleset::Protected);
    c.dns.split_domains.push("corp.example".to_owned());
    let p = render(&c, &cfg()).expect("render");
    assert!(p
        .unsupported
        .contains(&codes::DNS_PLATFORM_SCOPED_API_UNAVAILABLE));
    // And it is a REGISTERED code, not an invented spelling.
    assert!(twinvpn_types::ReasonCode::lookup("DNS.PLATFORM.SCOPED_API_UNAVAILABLE").is_some());
}

#[test]
fn a_contract_with_no_split_rules_reports_nothing_unsupported() {
    let p = render(&contract(1, Ruleset::Protected), &cfg()).expect("render");
    assert!(p.unsupported.is_empty());
}

#[test]
fn every_limits_json_bound_is_checked_before_anything_is_allocated() {
    let mut c = contract(1, Ruleset::Protected);
    for i in 0..=MAX_RESOLVERS_PER_FAMILY {
        c.dns
            .resolvers
            .v6
            .push(host_v6(0x100 + u16::try_from(i).expect("small")));
    }
    let err = render(&c, &cfg()).expect_err("over the resolver bound");
    assert_eq!(err.reason_code().as_str(), "ROUTE.PROGRAMMING_DENIED");

    let mut c = contract(1, Ruleset::Protected);
    for i in 0..=MAX_SEARCH_DOMAINS {
        c.dns.search_domains.push(format!("d{i}.example"));
    }
    assert!(render(&c, &cfg()).is_err());

    let mut c = contract(1, Ruleset::Protected);
    for i in 0..=MAX_ROUTES_PER_FAMILY {
        c.routes
            .v4
            .push(route(&format!("10.{}.{}.0/24", i / 256, i % 256)));
    }
    assert!(render(&c, &cfg()).is_err());
}

#[test]
fn a_malformed_package_name_is_refused_before_the_builder_is_touched() {
    assert!(is_valid_package_name("com.example.app"));
    assert!(is_valid_package_name("com.example"));
    assert!(!is_valid_package_name("example"), "one segment");
    assert!(!is_valid_package_name(""), "empty");
    assert!(!is_valid_package_name("com..example"), "empty segment");
    assert!(!is_valid_package_name("com.1example"), "digit first");
    assert!(!is_valid_package_name("com.exa mple"), "space");
    assert!(!is_valid_package_name(&"a.".repeat(200)));

    let config = VpnConfig {
        disallowed_packages: vec!["not a package".to_owned()],
    };
    let err = render(&contract(1, Ruleset::Protected), &config).expect_err("malformed");
    assert_eq!(err.reason_code().as_str(), "ROUTE.PROGRAMMING_DENIED");
}

#[test]
fn app_exclusions_are_a_deny_list_and_appear_in_the_users_order() {
    let config = VpnConfig {
        disallowed_packages: vec!["com.example.b".to_owned(), "com.example.a".to_owned()],
    };
    let p = render(&contract(1, Ruleset::Protected), &config).expect("render");
    let excluded: Vec<_> = p
        .ops
        .iter()
        .filter_map(|op| match op {
            BuilderOp::AddDisallowedApplication(n) => Some(n.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(excluded, vec!["com.example.b", "com.example.a"]);
}

/// The programme is a pure function of its inputs, which is what makes
/// asserting on it worth anything.
#[test]
fn rendering_is_deterministic() {
    let mut c = contract(7, Ruleset::Protected);
    c.routes.v4.push(route("0.0.0.0/0"));
    c.routes.v6.push(route("::/0"));
    c.dns.resolvers.v4.push(host_v4([100, 64, 0, 53]));
    assert_eq!(render(&c, &cfg()).unwrap(), render(&c, &cfg()).unwrap());
}
