#!/usr/bin/env python3
"""Assert the OTel collector's privacy controls are still STRUCTURAL.

docs/testing-strategy.md §6.2 lists "the redaction lint feeding PB-7" among
T1's contents. This is the infrastructure half of it. The emitter-side half --
schema field classification, ADR-0015 O-14 -- belongs to the services and to
contracts/, and this script does not and cannot substitute for it.

What it checks, and why each check is a check rather than a comment:

  1. `allow_all_keys: false`.
     This one line IS the security property. A denylist "only catches what
     someone thought of", and ADR-0015 O-12 says tunnel plaintext, packet
     payloads, private key material, pairing secrets and pre-shared material
     "MUST NEVER be written to any log, metric, trace, crash artifact, or
     diagnostic bundle at any log level, IN ANY BUILD, INCLUDING DEBUG BUILDS".
     That is not a property a denylist can have. Flipping this to `true` would
     turn a structural control into a decorative one, silently, in a config
     file nobody diffs closely.

  2. Every pipeline passes through both the forbidden-key filter and the
     allowlist. A pipeline added without them is an unredacted export path.

  3. The forbidden-key filter runs BEFORE the allowlist. Order is load-bearing:
     the allowlist would silently DELETE a leaked key, whereas the filter DROPS
     THE WHOLE RECORD and increments a counter. A silently sanitised leak is a
     leak nobody fixes.

  4. `abi_major` / `abi_minor` are stripped on the Tier-2 pipeline.
     ADR-0018 VR-2 consequence 3: "abi_* MUST be OMITTED from Tier-2 aggregate
     telemetry ... an ABI pair is build-identifying and has no aggregate
     meaning." Consequence 1 permits it in a Tier-1 bundle, so the strip must
     be SCOPED to Tier 2 and not applied globally.

  5. `correlation_id` and `causation_id` survive the allowlist.
     ownership.md rule 6 requires them preserved across every component
     boundary. An allowlist that dropped them would satisfy every privacy check
     here and destroy the causal chain, so their PRESENCE is asserted with the
     same force as the forbidden keys' absence.

  6. No SECRET-class or peer-linking key appears in the allowlist.
     The two lists must not overlap; an overlap is a control that contradicts
     itself.

  7. Nothing re-enables a cross-component service graph.
     ADR-0015 §6 called that "FATAL ON PRIVACY" when it rejected Alternative A:
     "a cross-component trace correlating client, rendezvous, and relay IS a
     peer-graph and movement record". Tempo's metrics generator and Grafana's
     node graph are both off, in two files, because one of them is the one
     someone will re-enable.
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML is required: pip install pyyaml")

REPO_ROOT = Path(__file__).resolve().parents[2]
COLLECTOR = REPO_ROOT / "infra" / "otel" / "collector-config.yaml"
TEMPO = REPO_ROOT / "infra" / "tempo" / "tempo.yaml"
DATASOURCES = (REPO_ROOT / "infra" / "grafana" / "provisioning" /
               "datasources" / "datasources.yaml")

# ADR-0015 §11.4 SECRET class, plus the SENSITIVE identifiers O-13 forbids
# infrastructure from retaining. None of these may ever be allowlisted.
MUST_NEVER_BE_ALLOWED = {
    "twinvpn.session_id", "twinvpn.path_id", "twinvpn.pair_tag",
    "twinvpn.flow_id", "twinvpn.device_id", "twinvpn.identity_id",
    "twinvpn.peer_id", "twinvpn.peer_device_id", "twinvpn.owner_id",
    "twinvpn.pairing_id", "twinvpn.twinnet_id",
    "twinvpn.pair_secret", "twinvpn.psk", "twinvpn.private_key",
    "twinvpn.session_key", "twinvpn.leg_key", "twinvpn.rlk",
    "twinvpn.auth_token", "authorization", "cookie", "set-cookie",
    "twinvpn.payload", "twinvpn.packet", "twinvpn.plaintext",
    "twinvpn.dns_query_name", "twinvpn.destination",
    "twinvpn.endpoint", "twinvpn.ssid", "twinvpn.interface_name",
    "net.peer.ip", "net.peer.name", "client.address", "server.address",
    "url.full", "http.request.body",
    "exception.message", "exception.stacktrace",
}

# ownership.md rule 6. These MUST be allowlisted or the causal chain dies.
MUST_BE_ALLOWED = {
    "twinvpn.correlation_id",
    "twinvpn.causation_id",
    "twinvpn.reason_code",
}

# ADR-0018 VR-2 consequence 3.
TIER2_MUST_STRIP = {"twinvpn.abi_major", "twinvpn.abi_minor"}

problems: list[str] = []


def fail(msg: str) -> None:
    problems.append(msg)


def check_collector() -> None:
    if not COLLECTOR.is_file():
        fail(f"missing {COLLECTOR}")
        return
    doc = yaml.safe_load(COLLECTOR.read_text())
    procs = doc.get("processors", {}) or {}

    # --- 1. the allowlist is an allowlist --------------------------------
    allowlists = {k: v for k, v in procs.items() if k.startswith("redaction")}
    if not allowlists:
        fail("no `redaction` processor is configured. ADR-0015 O-12's 'never, in "
             "any build' is not a property a denylist can have.")
    for name, cfg in allowlists.items():
        if cfg.get("allow_all_keys") is not False:
            fail(f"processor {name}: allow_all_keys is not false. THAT ONE LINE IS "
                 f"THE SECURITY PROPERTY - with it true, every attribute a service "
                 f"emits is exported, including ones added tomorrow with no "
                 f"classification and nobody's review.")
        allowed = set(cfg.get("allowed_keys", []) or [])
        if not allowed:
            fail(f"processor {name}: allowed_keys is empty")

        # --- 6. the two lists must not contradict each other -------------
        overlap = allowed & MUST_NEVER_BE_ALLOWED
        if overlap:
            fail(f"processor {name}: allowlists key(s) ADR-0015 §11.4 classifies "
                 f"SECRET or O-13 forbids on infrastructure: {sorted(overlap)}")

        # --- 5. correlation and causation survive ------------------------
        missing = MUST_BE_ALLOWED - allowed
        if missing:
            fail(f"processor {name}: {sorted(missing)} not allowlisted. "
                 f"docs/implementation/ownership.md rule 6 requires "
                 f"correlation_id and causation_id preserved across EVERY "
                 f"component boundary; an allowlist that drops them passes every "
                 f"privacy check and destroys the causal chain.")

        # ADR-0015 §11.2 rule 5 forbids a second text authority outside the
        # registry: "A carrier MUST NOT add a localized summary, message, or
        # title field - that would place a second text authority outside the
        # registry and defeat rule 4."
        text_authority = allowed & {"twinvpn.summary", "twinvpn.message",
                                    "twinvpn.title", "summary", "message", "title"}
        if text_authority:
            fail(f"processor {name}: allowlists {sorted(text_authority)}. ADR-0015 "
                 f"§11.2 rule 5 forbids a localized text field on any carrier of a "
                 f"Diagnostic - 'the code is the contract; the human text is not'.")

    # --- 2 and 3. every pipeline is redacted, filter first ----------------
    pipelines = ((doc.get("service", {}) or {}).get("pipelines", {}) or {})
    if not pipelines:
        fail("no pipelines configured")
    for name, pipe in pipelines.items():
        chain = list(pipe.get("processors", []) or [])
        filters = [i for i, p in enumerate(chain) if p.startswith("filter/forbidden")]
        redactions = [i for i, p in enumerate(chain) if p.startswith("redaction")]
        if not redactions:
            fail(f"pipeline {name}: no redaction processor. This is an UNREDACTED "
                 f"EXPORT PATH.")
        if not filters:
            fail(f"pipeline {name}: no filter/forbidden. The allowlist alone would "
                 f"SILENTLY DELETE a leaked SECRET-class key; the filter DROPS the "
                 f"record and counts it, which is what makes the leak fixable.")
        if filters and redactions and min(filters) > min(redactions):
            fail(f"pipeline {name}: filter/forbidden runs AFTER redaction. By then "
                 f"the allowlist has already deleted the evidence, so the leak is "
                 f"sanitised instead of reported.")

    # --- 4. Tier-2 strips abi_* ------------------------------------------
    tier2 = [n for n in pipelines if "tier2" in n or "aggregate" in n]
    if not tier2:
        fail("no Tier-2 aggregate pipeline. ADR-0018 VR-2 consequence 3 requires "
             "abi_* to be OMITTED from Tier-2, which needs a pipeline where the "
             "omission happens.")
    for name in tier2:
        chain = list(pipelines[name].get("processors", []) or [])
        stripped: set[str] = set()
        for pname in chain:
            cfg = procs.get(pname, {}) or {}
            for action in cfg.get("actions", []) or []:
                if action.get("action") == "delete":
                    stripped.add(action.get("key"))
        missing = TIER2_MUST_STRIP - stripped
        if missing:
            fail(f"pipeline {name}: does not delete {sorted(missing)}. ADR-0018 VR-2 "
                 f"consequence 3: 'abi_* MUST be omitted from Tier-2 aggregate "
                 f"telemetry ... an ABI pair is build-identifying and has no "
                 f"aggregate meaning.'")

    # The strip must be SCOPED to Tier 2. Consequence 1 permits abi_* in a
    # Tier-1 diagnostic bundle and in CoreBuildIdentity, so a global delete
    # would break a legitimate use.
    for name, pipe in pipelines.items():
        if name in tier2:
            continue
        for pname in pipe.get("processors", []) or []:
            cfg = procs.get(pname, {}) or {}
            for action in cfg.get("actions", []) or []:
                if action.get("action") == "delete" and action.get("key") in TIER2_MUST_STRIP:
                    fail(f"pipeline {name}: strips {action.get('key')} outside Tier 2. "
                         f"ADR-0018 VR-2 consequence 1 PERMITS abi_* in a Tier-1 "
                         f"bundle and in CoreBuildIdentity; a global strip breaks "
                         f"that legitimate use.")

    # --- O-13, the relay --------------------------------------------------
    relay_transform = [n for n in procs if n.startswith("transform/relay")]
    if not relay_transform:
        fail("no relay-specific transform. ADR-0015 §11.1 forbids trace context "
             "propagation ACROSS A RELAY, and §7 calls relay-side observability "
             "'the sharpest risk': a relay that logged both ends of a session "
             "would hold the peer graph, defeating I1 in metadata even though it "
             "never sees plaintext.")


def check_no_service_graph() -> None:
    """ADR-0015 §6, on rejecting Alternative A: a cross-component trace
    correlating client, rendezvous and relay IS a peer-graph and movement
    record. Two files, because one of them is the one someone re-enables."""
    if TEMPO.is_file():
        doc = yaml.safe_load(TEMPO.read_text())
        gen = (((doc.get("overrides", {}) or {}).get("defaults", {}) or {})
               .get("metrics_generator", {}) or {})
        if gen.get("processors"):
            fail(f"{TEMPO.name}: metrics_generator processors are enabled "
                 f"({gen['processors']}). service-graphs derived from spans across "
                 f"control-plane, rendezvous, presence and relay reconstruct, from "
                 f"permitted per-component traces, the cross-component correlation "
                 f"ADR-0015 §6 called FATAL ON PRIVACY.")
    else:
        fail(f"missing {TEMPO}")

    if DATASOURCES.is_file():
        doc = yaml.safe_load(DATASOURCES.read_text())
        for ds in doc.get("datasources", []) or []:
            if ds.get("type") != "tempo":
                continue
            jd = ds.get("jsonData", {}) or {}
            if (jd.get("nodeGraph", {}) or {}).get("enabled"):
                fail("grafana datasources: Tempo nodeGraph is enabled. Same argument "
                     "as the Tempo generator above.")
            if jd.get("serviceMap"):
                fail("grafana datasources: Tempo serviceMap is configured.")
    else:
        fail(f"missing {DATASOURCES}")


def main() -> int:
    check_collector()
    check_no_service_graph()

    for p in problems:
        print(f"FAIL  {p}")
    if problems:
        print(f"\n{len(problems)} problem(s)")
        return 1
    print("collector redaction is structural: allowlist, filter-first, "
          "Tier-2 abi_* stripped, correlation preserved, no service graph")
    return 0


if __name__ == "__main__":
    sys.exit(main())
