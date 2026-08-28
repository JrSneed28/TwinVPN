//! §3.4.2's simulator conformance suite, run against a real middlebox by a
//! prober that is not TwinVPN code.
//!
//! **Authority:** `docs/testing-strategy.md` §3.4.2, rule **L-1**:
//!
//! > No traversal, leak, or relay test may run against a personality or
//! > impairment that has not passed its conformance suite **in the same lab
//! > instantiation, on the same day**.
//!
//! Before this file existed, `twinlab::conformance::ConformanceSuite::
//! nat_personality` returned `Unavailable` for every personality, and **L-1**
//! therefore forbade running a traversal test against any of them. That was the
//! correct state and it was also a dead end: the missing piece was not a rule,
//! it was a middlebox and a prober.
//!
//! Each test here configures one personality, measures it from behind, and
//! asserts the measurement equals the configuration on **both** axes. A
//! personality that fails its own conformance test makes every traversal result
//! taken from it `Void` — which is what `Verdict::Void` is for.

mod common;

use common::{settle, Personality, PERSONALITIES, PORT_A, PORT_B, REFLECT_A, REFLECT_B};
use twinnet::prober::{Behaviour, Report};

/// Runs the prober from inside `client` and returns what it measured.
fn measure(rig: &mut common::Rig, hairpin_target: Option<&str>) -> Report {
    let agent = rig.sb.agent_path().display().to_string();
    let port_a = PORT_A.to_string();
    let port_b = PORT_B.to_string();
    let mut argv = vec![
        agent.as_str(),
        "probe",
        "--primary",
        REFLECT_A,
        "--alternate",
        REFLECT_B,
        "--port-a",
        &port_a,
        "--port-b",
        &port_b,
        "--wait-ms",
        "700",
    ];
    if let Some(t) = hairpin_target {
        argv.push("--hairpin-target");
        argv.push(t);
    }
    let ran = rig
        .sb
        .run(Some("client"), &argv)
        .expect("the prober must run");
    assert!(
        ran.ok(),
        "the prober exited {:?}: {}",
        ran.status,
        ran.stderr
    );
    serde_json::from_str(ran.stdout.trim())
        .unwrap_or_else(|e| panic!("the prober's report was undecodable ({e}): {}", ran.stdout))
}

fn expected(p: &Personality) -> (Behaviour, Behaviour) {
    use twinnet::nat::config::{Filtering, Mapping};
    let mapping = match p.mapping {
        Mapping::None => Behaviour::None,
        Mapping::EndpointIndependent => Behaviour::EndpointIndependent,
        Mapping::AddressPortDependentRandom | Mapping::AddressPortDependentSequential => {
            Behaviour::AddressPortDependent
        }
    };
    let filtering = match p.filtering {
        Filtering::None => Behaviour::EndpointIndependent,
        Filtering::EndpointIndependent => Behaviour::EndpointIndependent,
        Filtering::AddressDependent => Behaviour::AddressDependent,
        Filtering::AddressPortDependent => Behaviour::AddressPortDependent,
    };
    (mapping, filtering)
}

/// One personality, configured and then measured.
fn conformance_for(p: &Personality) {
    let label = format!("conformance-{}", p.name.to_lowercase());
    let Some(mut rig) = common::or_skip(&label, common::build(&label, false)) else {
        return; // The skip reason was printed by the rig.
    };
    let mut cfg = common::nat_config(&rig, p);
    cfg.stats_path = None;
    let (_, _stats) = {
        let mut fabric =
            std::mem::replace(&mut rig.fabric, twinnet::fabric::Fabric::new(&rig.scratch));
        let out = fabric
            .start_nat(&mut rig.sb, "cpe", &cfg)
            .expect("the middlebox must start");
        rig.fabric = fabric;
        out
    };
    settle();

    let report = measure(&mut rig, None);
    let (want_mapping, want_filtering) = expected(p);

    assert_ne!(
        report.mapping,
        Behaviour::Unreachable,
        "{}: nothing reached the reflector, so no behaviour was measured. \
         An unreachable path is never evidence of a NAT class.\nevidence:\n  {}",
        p.name,
        report.evidence.join("\n  ")
    );
    assert_eq!(
        report.mapping,
        want_mapping,
        "{}: configured mapping {:?}, the prober measured {:?}\nevidence:\n  {}",
        p.name,
        want_mapping,
        report.mapping,
        report.evidence.join("\n  ")
    );
    assert_eq!(
        report.filtering,
        want_filtering,
        "{}: configured filtering {:?}, the prober measured {:?}\nevidence:\n  {}",
        p.name,
        want_filtering,
        report.filtering,
        report.evidence.join("\n  ")
    );
}

#[test]
fn n_routed_translates_nothing_and_the_prober_says_so() {
    conformance_for(&PERSONALITIES[0]);
}

#[test]
fn n_eim_eif_maps_endpoint_independently_and_filters_nothing() {
    conformance_for(&PERSONALITIES[1]);
}

#[test]
fn n_eim_adf_filters_an_address_and_admits_a_different_port_from_it() {
    conformance_for(&PERSONALITIES[2]);
}

#[test]
fn n_eim_apdf_reuses_one_mapping_and_filters_both_axes() {
    conformance_for(&PERSONALITIES[3]);
}

#[test]
fn n_apdm_apdf_rand_allocates_per_destination_tuple() {
    conformance_for(&PERSONALITIES[4]);
}

#[test]
fn n_apdm_apdf_seq_allocates_per_destination_tuple_monotonically() {
    conformance_for(&PERSONALITIES[5]);
}
