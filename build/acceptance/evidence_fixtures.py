#!/usr/bin/env python3
"""Evidence and oracle reports that SHOULD pass, so a test can break exactly one.

Every builder here returns the most complete, most correct file its criterion
can produce: the right commit, the right run, the right attempt, a full
environment attestation, a real artifact digest and -- where the criterion makes
an egress claim -- an oracle report whose sentinel held, whose positive controls
fired, whose attempt count is well over the floor and whose two path identities
are distinct.

That is the entire point of the file. A test that constructs its own broken
evidence proves that broken evidence fails, which is easy and worth nothing: the
same assertion passes if the gate rejects EVERYTHING, including the real thing.
The negative cases in `test_report_prerequisites.py` each take one of these,
change ONE property, and assert the row stops being green -- so the case is only
meaningful because the unmutated fixture is green, and the positive-control
tests are what keep that true.

These are fixtures, not examples. They are not a schema and not documentation of
what a job must emit; `platform-evidence.schema.json` is that.
"""

from __future__ import annotations

COMMIT = "0123456789abcdef0123456789abcdef01234567"
RUN_ID = "424242"
RUN_ATTEMPT = "2"
REPOSITORY = "twinvpn/twinvpn"

# Distinct on purpose. A single shared constant would let a test that swaps two
# artifacts pass for the wrong reason.
DIGESTS = {
    "app-release.apk": "a" * 64,
    "TwinVPN.ipa": "b" * 64,
    "TwinVPN.app.zip": "c" * 64,
    "TwinVPN.app/Contents/MacOS/TwinVPN": "d" * 64,
    "com.twinvpn.app.sysext.systemextension": "e" * 64,
    "twinvpnsvc.exe": "f" * 64,
    # The SIMULATOR build's executable, distinct from both the IPA and the
    # macOS app: a simulator row that accepted either would be grading a
    # device archive.
    "TwinVPN.app/TwinVPN": "1" * 64,
    "twinvpn-ksd": "2" * 64,
}


def _base(platform: str, criterion: str, stem: str, artifacts: list[str],
          **overrides) -> dict:
    ev = {
        "schema_version": 2,
        "platform": platform,
        "criterion": criterion,
        "job_name": stem,
        "runner": "pinned-runner-image",
        "runner_kind": "self-hosted",
        "repository": REPOSITORY,
        "github_run_id": RUN_ID,
        "github_run_attempt": RUN_ATTEMPT,
        "commit": COMMIT,
        "toolchain": {},
        "artifact_digests": {k: DIGESTS[k] for k in artifacts},
        "environment": {},
        "leak_oracle": None,
        "compiled": True,
        "linked_real_core": True,
        "loaded": True,
        "invoked_core": True,
        "received_result": True,
        "lifecycle_transitions": ["CONNECTED->TERMINATED"],
        "graceful_shutdown": True,
        "verdict": "PASS",
        "generated_at": "2026-08-30T00:00:00Z",
    }
    ev.update(overrides)
    return ev


def _paths(**over) -> dict:
    """The two-path attestation every egress criterion carries, plus the two
    keys that say where the oracle and the sentinel stood.

    THREE DISTINCT ADDRESSES, and they are documentation-range literals so no
    reader mistakes one for a real deployment. `in-box` is the default because
    it is the topology the reconciled lanes build for themselves; the external
    deployment is `_paths(oracle_topology="external")` and is equally green,
    which is the point of the key -- it records what was done rather than
    permitting only one answer.
    """
    env = {
        "protected_path_established": True,
        "unprotected_path_established": True,
        "protected_path_identity": "203.0.113.7",
        "unprotected_path_identity": "198.51.100.9",
        "probe_host": "device",
        "oracle_topology": "in-box",
        "sentinel_egress_identity": "192.0.2.11",
    }
    env.update(over)
    return env


def _oracle_ref(session: str, criterion: str, claimed: str = "PASS") -> dict:
    return {"session_id": session, "url": "https://oracle.example",
            "criterion": criterion, "verdict_claimed": claimed}


def windows(**env_over) -> dict:
    env = _paths()
    env.update({
        "privileged": True,
        "bfe_running": True,
        "wfp_write_probe": True,
        "twinvpn_filters_installed": True,
        "guest_kind": "nested-hyperv-guest",
        "guest_disposable": True,
    })
    env.update(env_over)
    # HOSTED `windows-2025`, building its own nested guest, its own oracle and
    # its own sentinel. `guest_kind` is unchanged because the fact is unchanged.
    return _base("windows", "WINDOWS-WFP-KILLSWITCH", "windows-killswitch",
                 ["twinvpnsvc.exe"], privileged=True, environment=env,
                 runner_kind="github-hosted",
                 leak_oracle=_oracle_ref("sess-win", "WINDOWS-WFP-KILLSWITCH"))


def android(**env_over) -> dict:
    env = {
        "page_size": 16384,
        "zipalign_p16": True,
        "apk_variant": "release",
        "jni_pending_exception": False,
        "underlay_excludes_vpn": True,
        "abi_load_alignment": {
            "arm64-v8a": {"aligned": True, "min_p_align": 16384, "libraries": 2},
            "x86_64": {"aligned": True, "min_p_align": 16384, "libraries": 2},
        },
        "api_level": 36,
        "build_fingerprint": "google/sdk_gphone64_x86_64/generic:16/AP4A/x:user",
        "kernel_release": "6.6.30-android15-8",
        "emulator_version": "Android emulator version 35.4.9.0",
        "system_image_package": "system-images;android-36;google_apis_ps16k;x86_64",
        "system_image_revision": "4",
    }
    env.update(env_over)
    return _base("android", "ANDROID-16K-PAGE-SIZE", "android-16k",
                 ["app-release.apk"], runner_kind="github-hosted", environment=env,
                 lifecycle_transitions=["INITIALIZED->STARTED"])


def macos_sysext(**env_over) -> dict:
    env = _paths()
    env.update({
        "macos_version": "26.0",
        "sip_config": "custom (system extensions allowed)",
        "team_id": "ABCDE12345",
        "extension_bundle_id": "com.twinvpn.app.sysext",
        "systemextensionsctl_state": "activated enabled",
    })
    env.update(env_over)
    return _base("macos", "MACOS-SYSEXT-LIFECYCLE", "macos-sysext",
                 ["TwinVPN.app/Contents/MacOS/TwinVPN",
                  "com.twinvpn.app.sysext.systemextension"], environment=env,
                 leak_oracle=_oracle_ref("sess-mac", "MACOS-SYSEXT-LIFECYCLE"))


def macos_signature(**env_over) -> dict:
    env = {
        "team_id": "ABCDE12345",
        "signing_authority": "Developer ID Application: TwinVPN (ABCDE12345)",
        "signature_intact": True,
        "notarized": True,
        "stapled": True,
        # The nested extension's ticket, which the three above cannot speak for:
        # spctl assesses only the top-level bundle and the ticket is stapled to
        # the outer one.
        "sysext_notarized": True,
    }
    env.update(env_over)
    # ARTIFACT-ONLY: it inspects a downloaded product and drives no lifecycle,
    # so the execution booleans report what they truthfully are.
    return _base("macos", "MACOS-PRODUCTION-SIGNATURE", "macos-signature",
                 ["TwinVPN.app/Contents/MacOS/TwinVPN", "TwinVPN.app.zip"], environment=env,
                 compiled=False, linked_real_core=False, loaded=False,
                 invoked_core=False, received_result=False,
                 lifecycle_transitions=[])


def macos_pf_anchor(**env_over) -> dict:
    """The hosted pf row. No oracle: its anchor denies RFC 6598 and ULA space
    that never reaches one, so the instrument is the local read-back."""
    env = {
        "macos_version": "26.0",
        "sip_config": "unknown (Custom Configuration)",
        "pf_enabled": True,
        "anchor_referenced_in_main_ruleset": True,
        "anchor_rule_count": 14,
        "read_back_tables": "twinvpn_posture, twinvpn_generation, twinvpn_v4, twinvpn_v6",
        "covered_prefix_connect_refused": True,
        "control_connect_succeeded": True,
        "ksd_status_exit": 0,
        "bridge_tests_as_root": True,
        "bridge_test_count": 9,
    }
    env.update(env_over)
    return _base("macos", "MACOS-PF-BOOT-ANCHOR", "macos-pf-anchor",
                 ["twinvpn-ksd"], privileged=True, environment=env,
                 runner_kind="github-hosted",
                 lifecycle_transitions=["START->RULESET_RECLAIMED"])


def ios_ne(**env_over) -> dict:
    """The DEVICE row. No executor exists for it; the fixture is what a
    provisioned iPhone would produce, and it is what keeps the negative cases
    against the simulator rows meaningful."""
    env = _paths()
    env.update({
        "real_network_extension_invoked": True,
        "device_kind": "provisioned-iphone",
        "entitlement_packet_tunnel_provider": True,
        "product_mode": "consumer",
    })
    env.update(env_over)
    return _base("ios", "IOS-NE-FAIL-CLOSED", "ios-ne-failclosed",
                 ["TwinVPN.ipa"], environment=env,
                 leak_oracle=_oracle_ref("sess-ios", "IOS-NE-FAIL-CLOSED"))


def _simulator(**over) -> dict:
    """What a simulator row attests, including the three FALSE booleans.

    They are measured facts, not omissions: the provider did not run, the OS
    enforced nothing, and the build carries no packet-tunnel entitlement. That
    is what makes a simulator file unusable as device evidence and a device
    file unusable here.
    """
    env = {
        "execution": "simulator",
        "real_network_extension_invoked": False,
        "os_enforcement_exercised": False,
        "device_kind": "ios-simulator",
        "product_mode": "consumer",
        "entitlement_packet_tunnel_provider": False,
        "assertion_source": "in-process-object-state",
        "simulator_runtime": "iOS 26.5",
        "simulator_udid": "1E5A0C3D-0000-4000-8000-000000000001",
        "xcode_version": "26.6",
        "app_group_container_resolved": True,
        "test_count": 17,
    }
    env.update(over)
    return env


def ios_failclosed_configuration(**env_over) -> dict:
    return _base("ios", "IOS-FAILCLOSED-CONFIGURATION",
                 "ios-failclosed-configuration", ["TwinVPN.app/TwinVPN"],
                 environment=_simulator(**env_over),
                 runner_kind="github-hosted",
                 lifecycle_transitions=["INITIALIZED->CONFIGURED"])


def ios_profile_removal(**env_over) -> dict:
    env = _simulator(
        reported_not_protected=True,
        green_shield_impossible=True,
        connected_state_cleared=True,
        protection_lost_actionable=True,
        no_continued_killswitch_claim=True,
    )
    env.update(env_over)
    return _base("ios", "IOS-PROFILE-REMOVAL-HONESTY", "ios-profile-removal",
                 ["TwinVPN.app/TwinVPN"], environment=env,
                 runner_kind="github-hosted",
                 lifecycle_transitions=["CONFIGURED->REMOVED"])


def ios_supervised(**env_over) -> dict:
    env = _paths()
    env.update({
        "real_network_extension_invoked": True,
        "device_kind": "provisioned-iphone",
        "product_mode": "supervised",
        "always_on_payload_installed": True,
        "user_removal_blocked": True,
    })
    env.update(env_over)
    return _base("ios", "IOS-SUPERVISED-ALWAYS-ON", "ios-supervised",
                 ["TwinVPN.ipa"], environment=env,
                 leak_oracle=_oracle_ref("sess-sup", "IOS-SUPERVISED-ALWAYS-ON"))


def oracle(session: str = "sess-win",
           criterion: str = "WINDOWS-WFP-KILLSWITCH", **overrides) -> dict:
    """A session that genuinely proved what a green row claims.

    Well over the attempt floor, zero forbidden arrivals, a sentinel that never
    gapped, a positive control on all three families, and two distinguishable
    path identities per family.
    """
    rep = {
        "schema_version": 2,
        "session_id": session,
        "commit": COMMIT,
        "run_id": RUN_ID,
        "run_attempt": RUN_ATTEMPT,
        "platform": "windows",
        "criterion": criterion,
        "phases": [],
        "unauthorized_observations": [],
        "families_proven_live": ["ipv4", "ipv6", "dns"],
        "failures": [],
        "inconclusive": [],
        "dns_resolver_identity_ambiguous": False,
        # Surfaced by the report, gated on by nothing -- see
        # `oracle_adjudication.sentinel_note`.
        "sentinel_host": "oracle.example",
        "verdict": "PASS",
    }
    for family in ("ipv4", "ipv6", "dns"):
        rep[f"{family}_attempts"] = 120
        rep[f"{family}_observed"] = 0
        rep[f"{family}_sentinel_continuous"] = True
        rep[f"{family}_identity_distinct"] = True
    rep.update(overrides)
    return rep
