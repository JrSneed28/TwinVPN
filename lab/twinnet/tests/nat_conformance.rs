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

// ===========================================================================
// The negative control for every test above: a middlebox that is not the only
// forwarder in its namespace is not the thing being measured.
// ===========================================================================

/// A node built for a middlebox does not forward, and one that also forwards is
/// refused rather than measured.
///
/// **The defect this holds shut.** A new network namespace does not start
/// neutral — Linux copies the initial namespace's `all` devconf into it
/// (`net/ipv4/devinet.c`, `devinet_init_net`), and `net.ipv4.ip_forward` is a
/// member of that block. A host running Docker has `ip_forward=1`, so every
/// namespace this laboratory created on such a host arrived forwarding, and the
/// `cpe` node then had two forwarders in it: the kernel and `twinnet::nat`. The
/// kernel usually won the race, the reflector observed the client's PRIVATE
/// address, and the CGNAT and dual-stack scenarios failed on a GitHub runner
/// while passing on a developer host whose `ip_forward` was `0`
/// (job 100276849297).
///
/// The failure was silent in the only way that matters: the middlebox ran, its
/// counters moved, and every conformance test above would have gone on
/// reporting a personality that the kernel had already carried the traffic
/// around. So the assertion is in two halves — the fabric turns forwarding off,
/// and the middlebox refuses to start if anything turns it back on.
///
/// The forwarding state is INJECTED, so this runs on a host whose own
/// `ip_forward` is `0` — which is every host that never saw the defect.
#[test]
fn a_middlebox_refuses_a_namespace_whose_kernel_forwards_around_it() {
    let Some(mut rig) = common::or_skip(
        "kernel-forwarding",
        common::build("kernel-forwarding", false),
    ) else {
        return; // The skip reason was printed by the rig.
    };
    let read = |rig: &mut common::Rig, knob: &str| -> String {
        rig.sb
            .must(Some("cpe"), &["cat", knob])
            .expect("a node's forwarding knob must be readable")
            .trim()
            .to_owned()
    };
    for knob in twinnet::nat::FORWARDING_KNOBS {
        assert_eq!(
            read(&mut rig, knob),
            "0",
            "the fabric left `{knob}` at whatever the host donated. A middlebox node \
             must be built NOT forwarding, whatever the initial namespace's value is"
        );
    }

    let cfg = common::nat_config(&rig, &PERSONALITIES[3]);
    let start = |rig: &mut common::Rig| {
        let mut fabric =
            std::mem::replace(&mut rig.fabric, twinnet::fabric::Fabric::new(&rig.scratch));
        let out = fabric.start_nat(&mut rig.sb, "cpe", &cfg);
        rig.fabric = fabric;
        out
    };

    for knob in twinnet::nat::FORWARDING_KNOBS {
        rig.sb
            .must(Some("cpe"), &["sh", "-c", &format!("echo 1 > {knob}")])
            .expect("the injection must take");
        let err = start(&mut rig)
            .err()
            .unwrap_or_else(|| panic!("`{knob}` was 1 and the middlebox started anyway"));
        let text = err.to_string();
        assert!(
            text.contains(knob),
            "the refusal must name the knob that is on: {text}"
        );
        assert!(
            !err.is_unavailable(),
            "a namespace this rig built wrong is a defect in the rig, not a facility \
             this host lacks — spelling it `Unavailable` would buy a silent skip: {text}"
        );
        rig.sb
            .must(Some("cpe"), &["sh", "-c", &format!("echo 0 > {knob}")])
            .expect("the injection must be reversible");
    }

    // The positive control, and the reason the refusals above are about the
    // knob rather than about anything else in this rig.
    start(&mut rig).expect("with forwarding off, the same middlebox must start");
}
