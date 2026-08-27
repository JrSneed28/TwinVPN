//! The rules that make a DNS leak unrepresentable, asserted.

use twinvpn_dns::answer::{self, Outcome, Rcode};
use twinvpn_dns::cache::ScopedCaches;
use twinvpn_dns::classify::{self, Class};
use twinvpn_dns::policy::{self, Disposition, PolicyError};
use twinvpn_dns::restore::{Posture, ProtectionAssertion};
use twinvpn_dns::scope::{self, Scope};
use twinvpn_dns::stub::{self, ApplyStep, MessageShape, StubReadiness, TeardownStep};
use twinvpn_schema::v1;
use twinvpn_types::{AddressFamily, PerFamily};

fn well_formed_policy() -> v1::DnsPolicy {
    v1::DnsPolicy {
        dnspolicy_id: "p1".into(),
        version: 3,
        mode: 1, // SPLIT
        servers_v4: vec![v1::IPv4Address {
            octets: vec![9, 9, 9, 9],
        }],
        servers_v6: vec![v1::IPv6Address {
            octets: vec![
                0x26, 0x20, 0x00, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09,
            ],
            zone_index: 0,
        }],
        servers_declared_v4: Some(true),
        servers_declared_v6: Some(true),
        split_domains: Vec::new(),
        search_domains: vec!["home.tnet.twinvpn.net".into()],
        block_fallback_v4: Some(true),
        block_fallback_v6: Some(true),
        dnssec_validate: true,
        upstream_dot: true,
        not_after_ms: 0,
    }
}

// ---------------------------------------------------------------------------
// CF-10 / protocol.md §13.4 — the explicit-presence fields
// ---------------------------------------------------------------------------

#[test]
fn a_policy_that_leaves_ipv6_resolvers_to_the_os_is_malformed_not_unconfigured() {
    let mut p = well_formed_policy();
    p.servers_declared_v6 = None;
    assert_eq!(
        policy::validate(&p),
        Err(PolicyError::ServersNotDeclared(AddressFamily::V6)),
        "§13.4 forbids expressing 'v4 configured, v6 left to the OS'"
    );
    // False is equally malformed: the bit exists to be affirmed.
    p.servers_declared_v6 = Some(false);
    assert_eq!(
        policy::validate(&p),
        Err(PolicyError::ServersNotDeclared(AddressFamily::V6))
    );
}

#[test]
fn an_absent_block_fallback_is_a_refusal_not_a_permission() {
    for family in [AddressFamily::V4, AddressFamily::V6] {
        let mut p = well_formed_policy();
        match family {
            AddressFamily::V4 => p.block_fallback_v4 = None,
            AddressFamily::V6 => p.block_fallback_v6 = None,
        }
        assert_eq!(
            policy::validate(&p),
            Err(PolicyError::BlockFallbackNotDeclared(family))
        );
    }
}

#[test]
fn an_empty_server_list_is_a_value_meaning_block_this_family() {
    let mut p = well_formed_policy();
    p.servers_v6.clear();
    // Declared-but-empty is well formed, and means "block this family".
    let validated = policy::validate(&p).expect("empty list is a value, not an absence");
    assert!(validated.servers.get(AddressFamily::V6).is_empty());
    assert!(validated.block_fallback(AddressFamily::V6));
}

#[test]
fn an_expired_bundle_can_only_become_more_restrictive() {
    let mut p = well_formed_policy();
    p.block_fallback_v4 = Some(false);
    p.block_fallback_v6 = Some(false);
    let mut validated = policy::validate(&p).unwrap();
    assert!(!validated.block_fallback(AddressFamily::V4));
    validated.suspend_grants_on_expiry();
    assert!(validated.block_fallback(AddressFamily::V4));
    assert!(validated.block_fallback(AddressFamily::V6));
}

#[test]
fn dn_8_rejects_a_tie_at_bundle_validation_rather_than_coin_flipping_at_runtime() {
    let mut p = well_formed_policy();
    p.split_domains = vec![
        v1::SplitDomainRule {
            suffix: "example.com".into(),
            exact_match: false,
            disposition: 2,
        },
        v1::SplitDomainRule {
            suffix: "example.com".into(),
            exact_match: false,
            disposition: 3,
        },
    ];
    assert_eq!(policy::validate(&p), Err(PolicyError::RuleConflict));
}

#[test]
fn a_lower_policy_version_is_never_accepted() {
    assert!(policy::accepts_version(3, 4));
    assert!(!policy::accepts_version(3, 3));
    assert!(!policy::accepts_version(3, 2));
}

#[test]
fn off_mode_is_refused_with_full_routing_or_an_engaged_exit_node() {
    assert!(policy::off_mode_permitted(false, false));
    assert!(!policy::off_mode_permitted(true, false));
    assert!(!policy::off_mode_permitted(false, true));
}

// ---------------------------------------------------------------------------
// §11.4 classification and DN-9
// ---------------------------------------------------------------------------

fn zone() -> Vec<Vec<u8>> {
    classify::wire_labels("home.tnet.twinvpn.net")
}

#[test]
fn dn_9_matches_whole_labels_and_never_a_string_suffix() {
    let suffix = classify::wire_labels("example.com");
    assert!(classify::is_suffix_of(
        &suffix,
        &classify::wire_labels("a.example.com")
    ));
    assert!(classify::is_suffix_of(
        &suffix,
        &classify::wire_labels("example.com")
    ));
    assert!(
        !classify::is_suffix_of(&suffix, &classify::wire_labels("notexample.com")),
        "a presentation-string suffix test would match this, and must not"
    );
    // RFC 4343 case-insensitivity.
    assert!(classify::is_suffix_of(
        &suffix,
        &classify::wire_labels("A.Example.COM")
    ));
}

#[test]
fn precedence_is_exact_then_twinnet_then_reserved_then_longest_suffix_then_default() {
    let mut p = well_formed_policy();
    p.split_domains = vec![
        v1::SplitDomainRule {
            suffix: "corp.example.com".into(),
            exact_match: false,
            disposition: 2,
        },
        v1::SplitDomainRule {
            suffix: "example.com".into(),
            exact_match: false,
            disposition: 3,
        },
        v1::SplitDomainRule {
            suffix: "www.example.com".into(),
            exact_match: true,
            disposition: 1,
        },
    ];
    let pol = policy::validate(&p).unwrap();

    // 1 — the exact rule wins over both suffix rules.
    let c = classify::classify("www.example.com", &pol, &zone(), false);
    assert_eq!(c.class, Class::ExactRule);
    assert_eq!(c.disposition, Disposition::Twinnet);

    // 2 — a TwinNet zone name beats every policy rule and is never forwarded.
    let c = classify::classify("nas.home.tnet.twinvpn.net", &pol, &zone(), false);
    assert_eq!(c.class, Class::TwinnetZone);
    assert_eq!(c.scope, Scope::Twinnet);

    // 3 — protocol-reserved names are never forwarded.
    for name in ["printer.local", "foo.home.arpa", "x.invalid"] {
        let c = classify::classify(name, &pol, &zone(), false);
        assert_eq!(c.class, Class::ProtocolReserved, "{name}");
        assert_eq!(c.disposition, Disposition::Refuse);
    }

    // 4 — the LONGEST matching suffix, not the first.
    let c = classify::classify("a.corp.example.com", &pol, &zone(), false);
    assert_eq!(c.class, Class::SuffixRule);
    assert_eq!(c.disposition, Disposition::ProtectedUpstream);

    // 5 — default.
    let c = classify::classify("unrelated.test-domain.net", &pol, &zone(), false);
    assert_eq!(c.class, Class::Default);
}

#[test]
fn the_twinnet_reverse_zones_cover_the_whole_slash_ten_and_the_product_ula() {
    for n in [64u16, 100, 127] {
        assert!(classify::is_twinnet_reverse(&classify::wire_labels(
            &format!("7.0.{n}.100.in-addr.arpa")
        )));
    }
    assert!(!classify::is_twinnet_reverse(&classify::wire_labels(
        "7.0.63.100.in-addr.arpa"
    )));
    assert!(!classify::is_twinnet_reverse(&classify::wire_labels(
        "7.0.128.100.in-addr.arpa"
    )));
    // fd7c:9e5d:2a10::/48 reversed.
    assert!(classify::is_twinnet_reverse(&classify::wire_labels(
        "0.1.a.2.d.5.e.9.c.7.d.f.ip6.arpa"
    )));
}

#[test]
fn full_tunnel_makes_every_default_class_query_protected_upstream() {
    let pol = policy::validate(&well_formed_policy()).unwrap();
    // SPLIT + not full tunnel: out-of-scope names go to the host's upstream on a
    // RESOLVER socket. Deliberate forwarding, not fallback (ADR-0012 class 6b).
    let c = classify::classify("news.example-site.net", &pol, &zone(), false);
    assert_eq!(c.scope, Scope::Bootstrap);
    // Full tunnel or an engaged ExitNode: DN-10 clause 3 — everything is
    // PROTECTED_UPSTREAM by construction and there is no underlay DNS at all.
    let c = classify::classify("news.example-site.net", &pol, &zone(), true);
    assert_eq!(c.scope, Scope::Protected);
    assert_eq!(c.disposition, Disposition::ProtectedUpstream);
}

// ---------------------------------------------------------------------------
// DN-10 — scope never changes on failure
// ---------------------------------------------------------------------------

#[test]
fn scope_never_changes_on_failure_and_the_two_closed_scopes_stay_closed() {
    for s in Scope::ALL {
        assert_eq!(scope::retry_scope(s), s);
    }
    assert!(!scope::may_reach_preexisting_resolver(Scope::Twinnet));
    assert!(!scope::may_reach_preexisting_resolver(Scope::Protected));
    // bootstrap and portal reach one BY DEFINITION, which is not fallback.
    assert!(scope::may_reach_preexisting_resolver(Scope::Bootstrap));
    assert!(scope::may_reach_preexisting_resolver(Scope::Portal));
}

#[test]
fn dn_0_keeps_bootstrap_servable_in_blocked_and_closed_to_host_processes() {
    assert!(Scope::Bootstrap.servable_while_blocked());
    assert!(Scope::Twinnet.servable_while_blocked());
    assert!(!Scope::Protected.servable_while_blocked());
    assert!(!Scope::Bootstrap.open_to_host_processes());
    assert!(Scope::Protected.open_to_host_processes());
}

// ---------------------------------------------------------------------------
// DN-1 / KS-16 — cache separation
// ---------------------------------------------------------------------------

#[test]
fn an_answer_learned_in_one_scope_is_never_served_in_another() {
    use core::time::Duration;
    use twinvpn_env::MonotonicInstant;

    let mut c = ScopedCaches::new();
    let now = MonotonicInstant::ORIGIN;
    c.insert(
        Scope::Portal,
        b"login.example".to_vec(),
        vec![1, 2, 3],
        Duration::from_secs(60),
        Some(Duration::from_secs(300)),
        now,
    );
    assert!(c.get(Scope::Portal, b"login.example", now).is_some());
    // KS-16: a portal answer must not enter the protected path or its cache.
    assert!(c.get(Scope::Protected, b"login.example", now).is_none());
    assert!(c.get(Scope::Bootstrap, b"login.example", now).is_none());
    assert!(c.get(Scope::Twinnet, b"login.example", now).is_none());

    // A portal answer never outlives the grant.
    let mut c2 = ScopedCaches::new();
    c2.insert(
        Scope::Portal,
        b"x".to_vec(),
        vec![1],
        Duration::from_secs(3600),
        Some(Duration::from_secs(10)),
        now,
    );
    let later = now.saturating_add(Duration::from_secs(11));
    assert!(c2.get(Scope::Portal, b"x", later).is_none());

    // bootstrap is TTL-clamped to 300 s.
    let mut c3 = ScopedCaches::new();
    c3.insert(
        Scope::Bootstrap,
        b"cp".to_vec(),
        vec![1],
        Duration::from_secs(86_400),
        None,
        now,
    );
    assert!(c3
        .get(
            Scope::Bootstrap,
            b"cp",
            now.saturating_add(Duration::from_secs(301))
        )
        .is_none());

    // DN-22: no scope is ever persisted.
    for s in Scope::ALL {
        assert!(!twinvpn_dns::cache::may_persist(s));
    }
}

// ---------------------------------------------------------------------------
// DN-11 — typed failures, never NXDOMAIN
// ---------------------------------------------------------------------------

#[test]
fn nxdomain_is_used_for_exactly_one_outcome_and_it_is_the_true_one() {
    let all = [
        Outcome::Answered,
        Outcome::BlockedFailClosed,
        Outcome::RefusedByPolicy,
        Outcome::FamilyWithheld(AddressFamily::V6),
        Outcome::UpstreamUnreachable,
        Outcome::TimeoutFailClosed,
        Outcome::DnssecBogus,
        Outcome::DnssecChainUnavailable,
        Outcome::StubNotReady,
        Outcome::TwinnetUnknown,
    ];
    let nx: Vec<_> = all
        .iter()
        .filter(|o| o.rcode() == Rcode::NxDomain)
        .collect();
    assert_eq!(nx.len(), 1);
    assert_eq!(*nx[0], Outcome::TwinnetUnknown);

    // Every negative outcome carries a registered code and, except the true
    // NXDOMAIN, an extended DNS error whose EXTRA-TEXT is that code.
    for o in all {
        if o == Outcome::Answered {
            continue;
        }
        let code = o.reason_code().expect("every negative outcome is typed");
        if o != Outcome::TwinnetUnknown {
            assert!(o.extended_error().is_some(), "{o:?}");
            assert_eq!(o.extra_text(), Some(code.as_str()));
        }
    }
}

#[test]
fn dn_11s_rcode_and_ede_table_matches_the_adr() {
    assert_eq!(Outcome::BlockedFailClosed.rcode(), Rcode::ServFail);
    assert_eq!(Outcome::BlockedFailClosed.extended_error(), Some(15));
    assert_eq!(Outcome::RefusedByPolicy.rcode(), Rcode::Refused);
    assert_eq!(Outcome::RefusedByPolicy.extended_error(), Some(18));
    assert_eq!(
        Outcome::FamilyWithheld(AddressFamily::V6).rcode(),
        Rcode::NoError
    );
    assert_eq!(
        Outcome::FamilyWithheld(AddressFamily::V6).extended_error(),
        Some(17)
    );
    assert_eq!(Outcome::UpstreamUnreachable.extended_error(), Some(22));
    assert_eq!(Outcome::TimeoutFailClosed.extended_error(), Some(23));
    assert_eq!(Outcome::DnssecBogus.extended_error(), Some(6));
    assert_eq!(Outcome::DnssecChainUnavailable.extended_error(), Some(9));
    assert_eq!(Outcome::StubNotReady.extended_error(), Some(14));
}

// ---------------------------------------------------------------------------
// DN-12 … DN-17 — A and AAAA with equal rigor
// ---------------------------------------------------------------------------

#[test]
fn both_families_are_answered_and_a_working_one_is_never_withheld() {
    // DN-12/DN-13: no underlay parameter exists, so "filter AAAA because the
    // underlay is v4-only" is not expressible.
    let both = answer::twinnet_families(PerFamily::new(false, false));
    assert!(both.a && both.aaaa && both.withheld.is_none());

    // DN-14(a): a family the enforcement layer WILL drop is withheld, so the
    // application fails fast instead of waiting for a connect timeout.
    let v6_dropped = answer::twinnet_families(PerFamily::new(false, true));
    assert!(v6_dropped.a);
    assert!(!v6_dropped.aaaa);
    assert_eq!(
        v6_dropped.withheld,
        Some(Outcome::FamilyWithheld(AddressFamily::V6))
    );

    // DN-16: no DNS64 synthesis by us, ever.
    assert!(!answer::may_synthesize_aaaa_from_a());
}

// ---------------------------------------------------------------------------
// §11.2 / DN-2 / DN-4 / DN-5 — the stub
// ---------------------------------------------------------------------------

#[test]
fn the_stub_answers_on_all_four_addresses_and_the_anycasts_are_never_routed() {
    let addrs = stub::listen_addresses().unwrap();
    assert_eq!(addrs.get(AddressFamily::V4).len(), 2);
    assert_eq!(addrs.get(AddressFamily::V6).len(), 2);
    for family in [AddressFamily::V4, AddressFamily::V6] {
        let anycast = addrs
            .get(family)
            .iter()
            .find(|a| stub::is_service_anycast(**a))
            .expect("each family has one service anycast");
        assert!(
            !stub::may_advertise(*anycast),
            "DN-2: the anycasts MUST NOT appear in any Route advertisement"
        );
    }
}

#[test]
fn dn_5_refuses_to_point_the_host_until_both_families_are_answering() {
    assert!(!StubReadiness::default().may_point_host());
    assert!(!StubReadiness {
        v4_listening: true,
        v6_listening: false
    }
    .may_point_host());
    assert!(StubReadiness {
        v4_listening: true,
        v6_listening: true
    }
    .may_point_host());
}

#[test]
fn dn_19_never_unbinds_before_restoring() {
    let t = TeardownStep::SEQUENCE;
    let restore = t
        .iter()
        .position(|s| *s == TeardownStep::RestoreHostResolver)
        .unwrap();
    let unbind = t
        .iter()
        .position(|s| *s == TeardownStep::UnbindStub)
        .unwrap();
    assert!(restore < unbind, "never unbind-then-restore");
    // And the restore point is persisted BEFORE the mutation.
    let a = ApplyStep::SEQUENCE;
    let persist = a
        .iter()
        .position(|s| *s == ApplyStep::PersistRestorePoint)
        .unwrap();
    let apply = a
        .iter()
        .position(|s| *s == ApplyStep::ApplyScopedDns)
        .unwrap();
    assert!(
        persist < apply,
        "DN-18: written and flushed BEFORE the mutation"
    );
}

#[test]
fn dn_4_refuses_anything_that_is_not_one_well_formed_query() {
    let ok = MessageShape {
        qdcount: 1,
        opcode: 0,
        edns_bufsize: Some(1232),
        length: 100,
    };
    assert!(stub::accepts(ok));
    assert!(!stub::accepts(MessageShape { qdcount: 0, ..ok }));
    assert!(!stub::accepts(MessageShape { qdcount: 2, ..ok }));
    // Unknown OPCODE — IQUERY, UPDATE, NOTIFY — is refused, not ignored.
    assert!(!stub::accepts(MessageShape { opcode: 5, ..ok }));
    assert!(!stub::accepts(MessageShape {
        edns_bufsize: Some(4096),
        ..ok
    }));
    // A RESOLVER socket carries DNS and nothing else.
    assert!(stub::resolver_socket_port_permitted(53));
    assert!(stub::resolver_socket_port_permitted(853));
    assert!(!stub::resolver_socket_port_permitted(22));
    assert!(!stub::resolver_socket_port_permitted(1080));
}

// ---------------------------------------------------------------------------
// S-34 / ADR-0015 O-17, O-18 — protection is asserted, and assertions expire
// ---------------------------------------------------------------------------

#[test]
fn a_stale_assertion_is_unknown_and_never_protected() {
    let a = ProtectionAssertion {
        policy_version: 3,
        stub_listening_v4: true,
        stub_listening_v6: true,
        host_resolver_matches_intent: true,
        restore_point_valid: true,
        interception_detected: false,
        asserted_at_micros: 0,
        freshness_window_ms: 10_000,
    };
    assert_eq!(a.posture(5_000_000), Posture::Protected);
    assert_eq!(
        a.posture(11_000_000),
        Posture::Unknown,
        "a hung, crashed, killed or suspended agent must not leave a green indicator"
    );
    assert!(a.diagnostic(11_000_000).is_some());
}

#[test]
fn every_negative_observation_names_which_one_it_was() {
    let base = ProtectionAssertion {
        policy_version: 3,
        stub_listening_v4: true,
        stub_listening_v6: true,
        host_resolver_matches_intent: true,
        restore_point_valid: true,
        interception_detected: false,
        asserted_at_micros: 0,
        freshness_window_ms: 10_000,
    };
    for (mutate, expect) in [
        (
            ProtectionAssertion {
                stub_listening_v6: false,
                ..base
            },
            "DNS.STUB.BIND_FAILED",
        ),
        (
            ProtectionAssertion {
                host_resolver_matches_intent: false,
                ..base
            },
            "DNS.STUB.TEARDOWN_INCOMPLETE",
        ),
        (
            ProtectionAssertion {
                restore_point_valid: false,
                ..base
            },
            "DNS.STUB.TEARDOWN_INCOMPLETE",
        ),
        (
            ProtectionAssertion {
                interception_detected: true,
                ..base
            },
            "DNS.INTERCEPTION_DETECTED",
        ),
    ] {
        match mutate.posture(0) {
            Posture::Unprotected(code) => assert_eq!(code.as_str(), expect),
            other => panic!("expected Unprotected({expect}), got {other:?}"),
        }
    }
}

#[test]
fn a_restore_point_whose_token_no_longer_matches_is_detected() {
    use twinvpn_dns::restore::RestorePoint;
    let rp = RestorePoint::new(
        b"nameserver 192.0.2.1\n".to_vec(),
        vec!["link:3".into()],
        [7u8; 32],
        "twinvpn".into(),
    );
    assert!(rp.matches_installed(&[7u8; 32]));
    assert!(
        !rp.matches_installed(&[8u8; 32]),
        "a stale restore point would restore the wrong thing"
    );
}
