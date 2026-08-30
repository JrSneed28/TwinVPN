#!/usr/bin/env python3
"""The First Implementation Wave acceptance report, computed rather than asserted.

WHAT THIS IS FOR
================
The wave's acceptance criterion is not "a reviewer read the code and agreed".
It is that each blocker is closed by EXECUTABLE EVIDENCE. So this script does
not read a catalogue of hand-maintained PASS/FAIL flags -- there is no such
catalogue, deliberately. Every row below names a probe, the probe runs, and the
row's verdict is whatever the probe returned.

That is the whole design. A row cannot be turned green by editing this file:
to move a row you have to move the thing it probes.

THE VOCABULARY
==============
  PASS          the probe ran and succeeded.
  FAIL          the probe ran and failed. Red.
  NOT-EXECUTED  the probe did not run -- no evidence file, no runner, skipped.
                This is an ABSENCE OF EVIDENCE. It is NOT a pass, and the gate
                counts it against Phase 5 eligibility exactly as a FAIL does.
                It is a separate word only so a reader can tell "we ran it and
                it broke" from "we never ran it", which are different problems.

  DEFERRED      not a verdict. A row's probe still runs and still reports PASS,
                FAIL or NOT-EXECUTED truthfully; `deferred` records that the
                row has been moved OUT OF WAVE-1 SCOPE by a named decision, so
                it no longer counts toward eligibility. This is the ONE thing
                in this file that a human sets by hand, and it is deliberately
                not a verdict: a deferred row that fails still prints FAIL with
                its real numbers, and the deferral reason prints beside it.
                Deferring a row is a scope decision that must be recorded in
                docs/implementation/ownership.md; it is NOT a way to make a red
                row look green, and nothing here will make it look green.

ENVIRONMENTAL PREREQUISITES
==========================
A verdict is not enough on its own. Every boolean a platform job writes
describes what the TEST did; none of them describes whether the MACHINE was
capable of the claim. So each platform criterion names the `environment` keys
that must have been MEASURED and must hold -- `page_size == 16384`,
`privileged == true`, `systemextensionsctl_state == "activated enabled"` -- and
`PREREQUISITES` below is checked BEFORE any test result is read.

An environment that failed its prerequisite attestation cannot produce a green
criterion. An unmeasured prerequisite is not a pass either: absence is what a
job that forgot to measure produces, and it fails exactly as a false
measurement does.

THE EGRESS CLAIMS ARE NOT ADJUDICATED HERE, OR ON THE DEVICE
============================================================
A kill-switch criterion cannot be graded by the platform under test: a filter
set that was never installed, a flushed firewall anchor and a dead
NetworkExtension all leave the platform's own status API saying "protected"
while packets leave. `lab/twinoracle` runs off-device and records what actually
arrived; the acceptance job fetches ITS report over the oracle's control API and
drops it in `build/ci/evidence/oracle/`. `check_oracle` reads that -- never the
`verdict_claimed` the job under test wrote -- and names any disagreement between
the two.

An oracle verdict of INCONCLUSIVE is NOT a pass. It is what the oracle returns
when the sequence never proved it could observe the device at all, which is the
state in which zero observations during the armed window mean nothing.

PHASE 5 ELIGIBILITY is the conjunction of every required row. It is computed on
the last line of this file from the rows above it. Nothing sets it directly.

Usage:  build/acceptance/report.py [--run] [--json PATH] [--markdown PATH]

  --run   execute the probes. Without it the script prints the criteria and
          marks every executable row NOT-EXECUTED, which is the cheap shape a
          documentation check can afford and is never mistaken for a pass.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import job_results  # noqa: E402
from adjudication import (  # noqa: E402
    PATH_IDENTITY_PREREQUISITES,
    REQUIRED,
    android_environment_problems,
    check_run_binding,
    path_identity_problems,
)
from oracle_adjudication import (  # noqa: E402
    check_oracle_adjudication,
    sentinel_note,
)

REPO = Path(__file__).resolve().parents[2]
EVIDENCE_DIR = REPO / "build" / "ci" / "evidence"
# The oracle's OWN reports, fetched by the acceptance job from the oracle's
# control API. Never written by a platform job -- that is the point.
ORACLE_DIR = EVIDENCE_DIR / "oracle"
MUTATION_REPORT = REPO / "build" / "proof" / "mutation-report.json"

PASS, FAIL, NOT_EXECUTED = "PASS", "FAIL", "NOT-EXECUTED"


# ---------------------------------------------------------------------------
# Probes. Each returns (verdict, detail).
# ---------------------------------------------------------------------------

def probe_command(workspace: str, command: str, run: bool):
    """Run a shell command in `workspace` under the pinned toolchain."""
    if not run:
        return NOT_EXECUTED, "not run (pass --run)"
    wd = REPO / workspace
    if not wd.is_dir():
        return FAIL, f"no such workspace: {workspace}"
    shell = f'set -euo pipefail; source "{REPO}/build/toolchain/env.sh"; {command}'
    proc = subprocess.run(
        ["bash", "-c", shell], cwd=wd, capture_output=True, text=True, timeout=5400
    )
    out = proc.stdout + proc.stderr
    if proc.returncode != 0:
        tail = out.strip().splitlines()[-12:]
        return FAIL, command + "\n" + "\n".join(tail)

    # A VACUOUS RUN IS NOT A PASS.
    #
    # `cargo test <filter>` exits 0 when the filter matches nothing, so a
    # renamed or deleted test turns this probe green while proving nothing --
    # which is precisely the failure mode the whole gate exists to catch, and
    # it would be embarrassing to ship it inside the gate itself. If every
    # reported test result ran zero tests, the probe found no evidence and
    # says so.
    results = re.findall(r"^test result: \w+\. (\d+) passed", out, re.MULTILINE)
    if results and all(int(n) == 0 for n in results):
        return FAIL, (command + "\n"
                      + "ran 0 tests -- the filter matched nothing, so this "
                        "probe found no evidence. A vacuous run is not a pass.")
    return PASS, command


def probe_no_unwired_entrypoint(symbols: list[str], run: bool):
    """A crypto/pairing entry point is wired only if a NON-TEST caller exists.

    This is the probe that F-1 and F-2 exist for. `grep` is sufficient and
    deliberate: the claim being checked is "some file that is not a test names
    this function", and a heavier tool would not make that claim truer.
    """
    if not run:
        return NOT_EXECUTED, "not run (pass --run)"
    unwired = []
    for sym in symbols:
        # Word-boundaried on purpose. A substring match would count
        # `disarm_resumption` as a caller of `arm_resumption` and report the
        # entry point wired when nothing calls it -- the exact false PASS this
        # probe exists to prevent.
        call = re.compile(rf"(?<![A-Za-z0-9_])\.?{re.escape(sym)}\s*\(")
        define = re.compile(rf"^(pub(\([^)]*\))?\s+)?(const\s+)?(async\s+)?fn\s+{re.escape(sym)}\b")
        proc = subprocess.run(
            ["grep", "-rn", "--include=*.rs", "-w", sym, "core", "services", "shells"],
            cwd=REPO, capture_output=True, text=True,
        )
        callers = []
        for line in proc.stdout.splitlines():
            parts = line.split(":", 2)
            if len(parts) < 3:
                continue
            path, lineno, body = parts
            if "/tests/" in path or path.endswith("_test.rs") or "/target/" in path:
                continue
            body = body.lstrip()
            # Comments describe; they do not call. The definition site is not
            # a caller of itself.
            if body.startswith(("///", "//!", "//")) or define.match(body):
                continue
            if not call.search(body):
                continue
            callers.append(f"{path}:{lineno}")
        if not callers:
            unwired.append(sym)
    if unwired:
        return FAIL, "no non-test caller for: " + ", ".join(unwired)
    return PASS, f"every entry point has a non-test caller: {', '.join(symbols)}"


def probe_source_absent(path: str, needle: str, run: bool):
    """Assert a weak signature is GONE from production source.

    Used for F-1B/F-1C: `handshake_secret: &[u8]` and a caller-supplied
    `local_role` must not exist any more, and a test that greps for them fails
    the moment somebody puts them back.
    """
    if not run:
        return NOT_EXECUTED, "not run (pass --run)"
    f = REPO / path
    if not f.is_file():
        return FAIL, f"no such file: {path}"
    if needle in f.read_text():
        return FAIL, f"{path} still contains `{needle}`"
    return PASS, f"{path} no longer contains `{needle}`"


def probe_mutation(field: str, run: bool):
    """Read one number out of the F-5 machine-readable mutation report."""
    if not MUTATION_REPORT.is_file():
        return NOT_EXECUTED, f"no {MUTATION_REPORT.relative_to(REPO)}"
    try:
        data = json.loads(MUTATION_REPORT.read_text())
    except json.JSONDecodeError as exc:
        return FAIL, f"mutation report is not valid JSON: {exc}"
    if field not in data:
        return FAIL, f"mutation report has no `{field}`"
    return data[field], f"{field} = {data[field]}"


# ---------------------------------------------------------------------------
# ENVIRONMENTAL PREREQUISITES
# ===========================================================================
#
# THE FAILURE THIS TABLE EXISTS FOR.
#
# Every boolean in a platform evidence file describes what the TEST did. None of
# them describes whether the MACHINE was capable of the claim. So all of these
# produced perfectly well-formed evidence with `verdict: PASS`:
#
#   * a Windows kill-switch run whose caller was never actually elevated, so no
#     WFP filter was ever installed and the "armed" window was an unprotected
#     host that happened to have no network;
#   * an Android 16 KiB run on a 4096-byte-page emulator, where the alignment
#     flag the criterion is about was applied to every ABI and exercised by
#     nothing;
#   * a macOS extension run on a host where activation silently failed, leaving
#     the test measuring an app with no extension behind it.
#
# In each case the row went green and the criterion was undischarged. So each
# criterion below names the environment keys that MUST be present and MUST
# hold, and they are checked BEFORE any test result is read. An environment that
# failed its prerequisite attestation cannot produce a green criterion.
#
# `REQUIRED` means "present, and truthy". A tuple means "present, and equal to
# one of these". An ABSENT key is never a pass: absence is what a job that
# forgot to measure produces, and it must be distinguishable from a measurement
# that came back false only in that both fail.
#
# `REQUIRED` itself is defined in `adjudication.py` and imported above: the
# path-identity rows there extend this table, and a second `object()` sentinel
# would never compare equal to this one, so every REQUIRED key it added would be
# silently graded as "must equal this opaque object" and always fail.

PREREQUISITES = {
    "WINDOWS-WFP-KILLSWITCH": {
        "privileged": (True,),
        "bfe_running": (True,),
        "wfp_write_probe": (True,),
        "twinvpn_filters_installed": (True,),
        # The kill switch installs persistent filters that survive the process by
        # design (CB-6). A run on anything but a throwaway guest either cut the
        # CI controller off the network or did not really arm.
        "guest_kind": ("nested-hyperv-guest",),
        "guest_disposable": (True,),
    },
    "ANDROID-16K-PAGE-SIZE": {
        # THE WHOLE CRITERION. A 4096 here is a vacuous pass and is refused.
        "page_size": (16384,),
        "zipalign_p16": (True,),
        # The production APK, not the debug one: C-12's claim is about the `.so`
        # inside the SHIPPED artifact.
        "apk_variant": ("release",),
        # False means "measured, and clean". Absent means "never measured".
        "jni_pending_exception": (False,),
        # THE PRODUCT-CORRECTNESS ASSERTION, which the test was proving and
        # nothing was recording: a tunnel must never carry itself. `null` is
        # what a run where that test did not execute writes, and it must not
        # read as a pass.
        "underlay_excludes_vpn": (True,),
        # Read off the BOOTED device, not from configuration. The 16 KiB lane
        # exits non-zero when any of them is unreadable, so a file that arrives
        # here without them came from somewhere else.
        "api_level": REQUIRED,
        "build_fingerprint": REQUIRED,
        "kernel_release": REQUIRED,
        "system_image_revision": REQUIRED,
    },
    "MACOS-SYSEXT-LIFECYCLE": {
        "macos_version": REQUIRED,
        "sip_config": REQUIRED,
        "team_id": REQUIRED,
        "extension_bundle_id": REQUIRED,
        "systemextensionsctl_state": ("activated enabled",),
    },
    "MACOS-PRODUCTION-SIGNATURE": {
        "team_id": REQUIRED,
        "signing_authority": REQUIRED,
        "signature_intact": (True,),
        # Gatekeeper's acceptance IS the notarization check; there is no local
        # query for it. Stapling is separate and is the one that fails offline.
        "notarized": (True,),
        "stapled": (True,),
    },
    "IOS-NE-FAIL-CLOSED": {
        "real_network_extension_invoked": (True,),
        "device_kind": REQUIRED,
        "entitlement_packet_tunnel_provider": (True,),
        "product_mode": REQUIRED,
    },
    "IOS-PROFILE-REMOVAL-HONESTY": {
        "real_network_extension_invoked": (True,),
        "device_kind": REQUIRED,
        # CONSUMER, explicitly. The supervised/managed criterion is stronger and
        # separate, and a consumer-mode file must never be readable as it.
        "product_mode": ("consumer",),
        # THE FIVE THINGS THIS CRITERION ACTUALLY ASSERTS.
        #
        # This row is the one criterion in the table whose claim is about what
        # the app SAYS rather than about what leaves the device, and it carries
        # no leak-oracle session because on consumer iOS removing the VPN
        # configuration REVOKES TwinVPN's authority: egress afterwards is
        # expected and correct, and a silence phase over that window would test
        # a promise the product does not make.
        #
        # Which left the row with nothing to check but "the NE was invoked and
        # the device is a consumer device" -- both true of a build that responds
        # to profile removal by continuing to display a green shield, which is
        # the exact dishonesty the criterion is named for. So the five
        # conditions of `ProfileRemovalAcceptanceTests.swift` are attested here,
        # individually, and the last one is the subtle one: `blocked` is as
        # wrong as `protected`, because both assert TwinVPN is still deciding
        # what leaves the device when it no longer is.
        "reported_not_protected": (True,),
        "green_shield_impossible": (True,),
        "connected_state_cleared": (True,),
        "protection_lost_actionable": (True,),
        "no_continued_killswitch_claim": (True,),
    },
    # THE STRONGER CRITERION, and the one the consumer rows must never be read
    # as. On a supervised device under MDM the Always-On payload cannot be
    # removed by the user, so "zero egress outside the tunnel, ever" is both
    # true and testable -- including across configuration removal, which on
    # consumer iOS revokes the authority and therefore cannot be tested that
    # way. `product_mode` is pinned to `supervised` here and to `consumer`
    # above, which is what makes the two files unswappable.
    "IOS-SUPERVISED-ALWAYS-ON": {
        "real_network_extension_invoked": (True,),
        "device_kind": REQUIRED,
        "product_mode": ("supervised",),
        "always_on_payload_installed": (True,),
        "user_removal_blocked": (True,),
    },
}

# Which criteria make an EGRESS claim, and therefore require an external
# leak-oracle report. The others do not, and requiring one of them would be
# theatre: `ANDROID-16K-PAGE-SIZE` is about page size and the JNI/VpnService
# boundary, and `IOS-PROFILE-REMOVAL-HONESTY` is about what the app SAYS after
# its authority is revoked -- egress there is expected and correct.
ORACLE_REQUIRED = {
    "WINDOWS-WFP-KILLSWITCH",
    "MACOS-SYSEXT-LIFECYCLE",
    "IOS-NE-FAIL-CLOSED",
    "IOS-SUPERVISED-ALWAYS-ON",
}

# EVERY EGRESS CRITERION ALSO ATTESTS ITS TWO PATHS, and the merge is driven off
# `ORACLE_REQUIRED` rather than written out four times on purpose: the set of
# criteria that need an external adjudicator and the set that must prove they
# established a protected and an unprotected path are the SAME set, by
# definition -- a criterion with only one path has nothing for the oracle to
# compare and its silence is unattributable. Adding a fifth egress criterion to
# `ORACLE_REQUIRED` therefore cannot leave its path attestation behind, which is
# exactly the kind of half-applied requirement a hand-maintained second list
# accumulates.
for _criterion in ORACLE_REQUIRED:
    PREREQUISITES.setdefault(_criterion, {}).update(PATH_IDENTITY_PREREQUISITES)

# Criteria that inspect an artifact rather than run it. For these the execution
# booleans are meaningless and are not required -- demanding `loaded: true` of a
# signature check would only teach a job to write it untruthfully.
ARTIFACT_ONLY = {"MACOS-PRODUCTION-SIGNATURE"}


def expected_commit() -> str:
    """The commit this report is about.

    In CI it is the workflow's head SHA, which is the thing every piece of
    evidence must agree with; locally it is HEAD. Rule C-5: a verdict is bound
    to an exact commit, and evidence from a different one is a rumour.
    """
    return os.environ.get("GITHUB_SHA") or subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True
    ).stdout.strip()


def check_environment(criterion: str, ev: dict) -> list[str]:
    """Every prerequisite failure, not just the first."""
    env = ev.get("environment")
    if not isinstance(env, dict):
        return [f"the evidence carries no `environment` map, so nothing about "
                f"the machine {criterion} ran on was attested"]
    problems = []
    for key, expected in PREREQUISITES.get(criterion, {}).items():
        if key not in env:
            problems.append(f"`{key}` was never measured")
            continue
        got = env[key]
        if expected is REQUIRED:
            if got in (None, "", False):
                problems.append(f"`{key}` is empty")
        elif got not in expected:
            want = " or ".join(repr(v) for v in expected)
            problems.append(f"`{key}` is {got!r}, not {want}")
    # The one rule that compares two keys instead of grading one. Two identical
    # path identities pass every check above -- both present, both non-empty --
    # and mean the protected and unprotected legs are the same path.
    problems += path_identity_problems(criterion, env, ORACLE_REQUIRED)
    # Same reason, different shape: a nested per-ABI map and a substring, neither
    # of which "this key equals this value" can state.
    problems += android_environment_problems(criterion, env)
    return problems


def check_oracle(criterion: str, ev: dict, commit: str) -> list[str]:
    """Re-derive the egress verdict from the ORACLE'S OWN report.

    The evidence file's `leak_oracle.verdict_claimed` is written by the job
    under test and is never believed. The acceptance workflow fetches the
    oracle's report for the named session over the oracle's control API and
    drops it in `build/ci/evidence/oracle/`; this reads THAT.

    An INCONCLUSIVE oracle report is not a pass. It is what the oracle returns
    when the sequence never proved it could observe the device at all -- the
    state in which zero observations during the armed window mean nothing.
    """
    ref = ev.get("leak_oracle")
    if not isinstance(ref, dict) or not ref.get("session_id"):
        return ["the evidence names no leak-oracle session, so its egress claim "
                "was adjudicated by the system under test"]
    session = ref["session_id"]
    path = ORACLE_DIR / f"{session}.json"
    if not path.is_file():
        return [f"no oracle report at build/ci/evidence/oracle/{session}.json -- "
                f"the acceptance job could not retrieve it from the oracle, so "
                f"the egress claim is unadjudicated"]
    try:
        rep = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        return [f"the oracle report for {session} is not valid JSON: {exc}"]

    problems = []
    if rep.get("commit") != commit:
        problems.append(f"the oracle session was opened at commit "
                        f"{rep.get('commit')!r}, not {commit}")
    if rep.get("criterion") != criterion:
        problems.append(f"the oracle session was opened for "
                        f"{rep.get('criterion')!r}, not {criterion}")
    verdict = rep.get("verdict")
    if verdict != PASS:
        reasons = (rep.get("failures") or []) + (rep.get("inconclusive") or [])
        problems.append(f"the oracle returned {verdict}: "
                        + ("; ".join(reasons) if reasons else "no reason given"))
    leaks = rep.get("unauthorized_observations") or []
    if leaks:
        problems.append(f"{len(leaks)} unauthorized observation(s), first from "
                        f"{leaks[0].get('source')} on {leaks[0].get('family')}")
    # AND THE DISAGREEMENT CHECK. A job whose file claims PASS while the oracle
    # says otherwise is a job that is lying or reading a different session, and
    # either one is worth naming rather than silently overriding.
    claimed = ref.get("verdict_claimed")
    if claimed is not None and claimed != verdict:
        problems.append(f"the job's evidence claims {claimed} while the oracle "
                        f"says {verdict}")

    # AND THE ORACLE'S VERDICT IS ITSELF RE-DERIVED, from the oracle's own
    # numbers. Refusing anything that is not `PASS` is necessary and not
    # sufficient: a `PASS` written by an oracle that lost its sentinel, never
    # saw the device, counted four probe attempts, or could not tell the
    # protected resolver from the unprotected one is a summary of a session that
    # measured nothing. Those facts are all in the report the oracle just
    # returned, and `check_oracle_adjudication` refuses to let any of them
    # default to the safe-looking value.
    problems += check_oracle_adjudication(criterion, rep, ev)
    return problems


def probe_criterion(stem: str, criterion: str, require_privileged: bool = False):
    """Read one criterion's evidence and re-derive its verdict from scratch.

    The job's own `verdict` is NOT trusted: the environment attestation, the
    commit binding, the run binding, every boolean and -- where the criterion
    makes an egress claim -- the ORACLE'S report are all re-checked here. A job
    that writes PASS with `lifecycle_transitions: []`, on a 4 KiB emulator, at
    the wrong commit, or with no oracle session is caught rather than believed.
    """
    path = EVIDENCE_DIR / f"{stem}.json"
    # WHY THE JOB'S OWN OUTCOME IS READ AT ALL, when this script grades files.
    #
    # Because four different problems produce the same absent file, and one of
    # them -- a SKIP, because a self-hosted runner is not registered -- is the
    # one that most resembles routine absence and is the least routine thing in
    # the list. "No evidence" is true of all four and useful about none of them.
    results = job_results.load(EVIDENCE_DIR)
    job_problem = job_results.problem(stem, criterion, results)
    if not path.is_file():
        why = job_problem or (
            "no job outcome was recorded either, so nothing says whether it "
            "failed, was cancelled, was skipped for want of a runner, or never "
            "existed")
        return (NOT_EXECUTED,
                f"no evidence at build/ci/evidence/{stem}.json -- {why}", {})
    try:
        ev = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        return FAIL, f"{stem}.json is not valid JSON: {exc}", {}

    # A JOB THAT WROTE EVIDENCE AND THEN DID NOT SUCCEED. The file exists, it is
    # well-formed, every boolean in it is true -- and the job it came from was
    # cancelled by its own timeout halfway through the sequence, or failed in a
    # later step, or was skipped and is carrying an artifact restored from a
    # cache. The file describes the part of the run that happened; the outcome
    # describes whether the run finished. Both have to be right.
    if job_problem:
        return FAIL, f"{criterion}: {job_problem}", ev

    # A JOB THAT DECLARES ITS OWN ABSENCE. `verdict: NOT-EXECUTED` is a job
    # saying it ran and deliberately discharged nothing. Believing it costs
    # nothing -- the row is not a pass either way -- and re-deriving it as FAIL
    # would erase the distinction between "we ran it and it broke" and "we never
    # ran it", which is the only reason the third word exists.
    if ev.get("verdict") == NOT_EXECUTED:
        return (NOT_EXECUTED,
                f"{criterion}: the job wrote evidence declaring NOT-EXECUTED "
                f"({ev.get('notes') or 'no reason given'})", ev)

    problems: list[str] = []
    commit = expected_commit()

    # -- the bindings, first. Evidence about a different commit or a different
    # run is not weak evidence; it is evidence about something else.
    if ev.get("commit") != commit:
        problems.append(f"recorded commit {ev.get('commit')!r} is not {commit}")
    expected_run = os.environ.get("TWINVPN_EXPECTED_RUN_ID") or os.environ.get("GITHUB_RUN_ID")
    if expected_run and str(ev.get("github_run_id")) != str(expected_run):
        problems.append(f"recorded run {ev.get('github_run_id')!r} is not the "
                        f"acceptance run {expected_run}")
    if ev.get("criterion") and ev["criterion"] != criterion:
        problems.append(f"this file discharges {ev['criterion']!r}, not {criterion}")
    if ev.get("schema_version") != 2:
        problems.append(f"schema_version is {ev.get('schema_version')!r}; version 2 "
                        f"is the first that carries an environment attestation, and "
                        f"a criterion cannot be discharged without one")
    # The rest of the binding tuple: repository, run ATTEMPT, and the SHA-256 of
    # the artifact the criterion is a claim about. The commit and the run id
    # above are not enough on their own -- a re-run of the same commit keeps
    # both and changes neither, so an artifact left behind by a previous, failed
    # attempt satisfies every check above while describing a machine that was
    # torn down hours ago.
    problems += check_run_binding(criterion, ev)

    # -- the environment, before any test result is read.
    problems += check_environment(criterion, ev)

    # -- the execution booleans.
    if criterion not in ARTIFACT_ONLY:
        required = ["compiled", "linked_real_core", "loaded",
                    "invoked_core", "received_result"]
        problems += [f"`{k}` was not recorded" for k in required if k not in ev]
        problems += [f"`{k}` is not true" for k in required
                     if k in ev and ev[k] is not True]
        if not ev.get("lifecycle_transitions"):
            problems.append("no lifecycle transition was driven "
                            "(compile-only is insufficient)")
    if require_privileged and not ev.get("privileged", False):
        problems.append("hosted evidence only; the privileged criterion is undischarged")

    # -- the egress claim, adjudicated off-device.
    if criterion in ORACLE_REQUIRED:
        problems += check_oracle(criterion, ev, commit)

    if problems:
        return FAIL, f"{criterion}: " + "; ".join(problems), ev

    detail = "{} on {} ({}), {} transition(s): {}".format(
        ev.get("job_name", "?"), ev.get("runner", "?"), ev.get("runner_kind", "?"),
        len(ev.get("lifecycle_transitions", [])),
        ", ".join(ev.get("lifecycle_transitions", [])) or "n/a (artifact inspection)",
    )
    if ev.get("leak_oracle"):
        session = ev["leak_oracle"]["session_id"]
        detail += f"  oracle session {session}"
        detail += sentinel_note(ORACLE_DIR / f"{session}.json")
    if ev.get("github_run_url"):
        detail += f"  {ev['github_run_url']}"
    return PASS, detail, ev


def probe_platform(platform: str, require_privileged: bool = False):
    """The version-1 hosted link/run rows, unchanged.

    These are the COMPILE-LINK-LOAD-INVOKE rows, which make no egress claim and
    no environmental claim beyond the runner they name. They keep the old shape
    on purpose: widening the version-2 requirement to them would fail five
    working rows for the absence of an attestation none of their criteria needs.
    """
    path = EVIDENCE_DIR / f"{platform}.json"
    if not path.is_file():
        return NOT_EXECUTED, f"no evidence at build/ci/evidence/{platform}.json", {}
    try:
        ev = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        return FAIL, f"{platform}.json is not valid JSON: {exc}", {}

    required = [
        "compiled", "linked_real_core", "loaded",
        "invoked_core", "received_result", "graceful_shutdown",
    ]
    missing = [k for k in required if k not in ev]
    if missing:
        return FAIL, f"{platform}.json omits {', '.join(missing)}", ev
    false = [k for k in required if ev[k] is not True]
    if false:
        return FAIL, f"{platform}: {', '.join(false)} is not true", ev
    if not ev.get("lifecycle_transitions"):
        return FAIL, f"{platform}: no lifecycle transition was driven (compile-only is insufficient)", ev
    if require_privileged and not ev.get("privileged", False):
        return FAIL, f"{platform}: hosted evidence only; the privileged/physical criterion is undischarged", ev
    detail = "{} on {} ({}), {} transition(s): {}".format(
        ev.get("job_name", "?"), ev.get("runner", "?"), ev.get("runner_kind", "?"),
        len(ev["lifecycle_transitions"]), ", ".join(ev["lifecycle_transitions"]),
    )
    if ev.get("github_run_url"):
        detail += f"  {ev['github_run_url']}"
    return PASS, detail, ev


# ---------------------------------------------------------------------------
# The criteria, exactly as the acceptance gate states them.
# ---------------------------------------------------------------------------

def build_rows(run: bool):
    rows = []

    def add(section, name, verdict, detail, required=True, deferred=None):
        # `deferred` is a reason string, not a verdict. It drops the row out of
        # the eligibility conjunction and is carried into the JSON and the
        # markdown so the reason travels with the row.
        rows.append({
            "section": section, "criterion": name,
            "verdict": verdict, "detail": detail,
            "required": required and deferred is None,
            "deferred": deferred,
        })

    # -- F-1 ---------------------------------------------------------------
    v, d = probe_no_unwired_entrypoint(["arm_resumption"], run)
    add("F-1", "crypto producer wired", v, d)
    v, d = probe_no_unwired_entrypoint(["accept_resume_offer", "resume_on_wire"], run)
    add("F-1", "crypto consumer wired", v, d)
    v, d = probe_command("core", "cargo test -q -p twinvpn-core --test crypto_carriage", run)
    add("F-1", "real datagram roundtrip", v, d)
    v, d = probe_source_absent(
        "core/crates/twinvpn-core/src/resume/driver.rs", "handshake_secret: &[u8]", run)
    add("F-1", "handshake secret type safety", v, d)
    v, d = probe_source_absent(
        "core/crates/twinvpn-core/src/resume/driver.rs", "local_role: Role", run)
    add("F-1", "local role type/state safety", v, d)
    # `replay` is a unit-test module inside src/replay.rs, not an integration
    # target, so this is a filter rather than a `--test`.
    v, d = probe_command("core", "cargo test -p twinvpn-crypto --lib replay::tests", run)
    add("F-1", "replay commit-last regression", v, d)
    v, d = probe_command(
        "core", "cargo test -q -p twinvpn-core --test resume reflected", run)
    add("F-1", "reflection rejection", v, d)
    # F-1B/F-1C are enforced by the type system, which a test run cannot
    # observe -- a compiler that rejects the bad call emits no test result. So
    # `resume_api_shape` asserts the two absences at source level, and this row
    # runs it.
    v, d = probe_command(
        "core", "cargo test -q -p twinvpn-core --test resume_api_shape", run)
    add("F-1", "handshake/role API shape asserted", v, d)
    v, d = probe_command(
        "core", "cargo test -q -p twinvpn-core --test resume_lifecycle", run)
    add("F-1", "RS-6 regression", v, d)

    # -- F-2 ---------------------------------------------------------------
    v, d = probe_no_unwired_entrypoint(["install_pairing_enrolment"], run)
    add("F-2", "production enrolment installation", v, d)
    v, d = probe_command("core", "cargo test -q -p twinvpn-core --test pairing", run)
    add("F-2", "pair.begin production path", v, d)
    # These three run against the SHIPPED COMPOSITION -- real
    # LinuxPlatformAdapter, real Core, real enrol_at_startup, real MI
    # boundary. `twinvpnd`'s pairing suite is the evidence, not the core's:
    # F-2C's whole point is that a test calling `install_pairing_enrolment`
    # directly proves nothing about the composition that ships.
    v, d = probe_command(
        "shells/linux",
        "cargo test -q -p twinvpnd --test pairing "
        "a_provisioned_host_begins_a_ceremony_and_answers_with_the_offer", run)
    add("F-2", "complete MI-P1 PairingOffer returned", v, d)
    v, d = probe_command(
        "shells/linux",
        "cargo test -q -p twinvpnd --test pairing "
        "a_shell_renders_the_qr_payload_and_the_e2_text_from_the_response", run)
    add("F-2", "QR/text carriage available", v, d)
    v, d = probe_command("shells/linux", "cargo test -q -p twinvpnd --test pairing", run)
    add("F-2", "C-B integration flow", v, d)
    # MI-P1 rule 1 is the one a refactor breaks silently: the offer is SECRET
    # and must leave only inside a pair.begin response, never on the event
    # stream that every subscriber reads.
    v, d = probe_command(
        "shells/linux",
        "cargo test -q -p twinvpnd --test pairing "
        "the_offer_reaches_the_caller_and_never_the_event_stream", run)
    add("F-2", "MI-P1 rule 1: offer never on the event stream", v, d)
    v, d = probe_command(
        "shells/linux",
        "cargo test -q -p twinvpnd --test pairing a_host_with_no_element_refuses_to_begin_a_pairing", run)
    add("F-2", "missing identity reason (AUTH.IDENTITY_MISSING)", v, d)

    # -- F-5 ---------------------------------------------------------------
    counts = {}
    for field in ("specified", "executable", "executed", "discharged",
                  "survived", "missing", "b1_specified", "b1_discharged"):
        val, _ = probe_mutation(field, run)
        counts[field] = val if isinstance(val, int) else None
    ok = (
        counts["specified"] == 144
        and counts["missing"] == 0
        and counts["survived"] == 0
        and counts["executed"] == counts["executable"] == counts["specified"]
        and counts["b1_specified"] == 22
        and counts["b1_discharged"] == 22
    )
    have = all(v is not None for v in counts.values())
    # DEFERRED past Wave 1 by integration-lead decision of 2026-08-30
    # (docs/implementation/ownership.md, wave-1 gate decisions). B-1 is
    # discharged only on a CONJUNCTION -- mutation-gate.sh §5 requires
    # register.tsv STATUS `IMPLEMENTED` *and* every specified mutant killed --
    # and no register row is IMPLEMENTED (21 PARTIAL, 1 NOT-RUNNABLE). So B-1
    # is 0/22 on the oracle half independent of the mutant count, and killing
    # all 144 mutants would still not discharge it. The remaining 120 mutants
    # are capability-blocked, and the largest groups (three desktop GUIs for
    # P17/P18, an updater crate that does not exist for P12/P20) are product
    # builds, not test gaps. The row is not closable in Wave 1 under any
    # sequencing, so it leaves the eligibility conjunction rather than holding
    # a truthful report hostage.
    #
    # The probe is UNCHANGED and still runs. This row still prints its real
    # verdict and its real counts. The threshold above is untouched -- it is
    # absolute (missing == 0, executed == executable == specified == 144,
    # b1_discharged == 22) and was deliberately not relaxed, because relaxing
    # it would have made the row lie instead of making it out of scope.
    add("F-5", "mutation obligations discharged",
        (PASS if ok else FAIL) if have else NOT_EXECUTED,
        "specified={specified} executable={executable} executed={executed} "
        "discharged/killed={discharged} survived={survived} missing={missing} "
        "B-1 {b1_discharged}/{b1_specified}".format(**counts)
        if have else "no machine-readable mutation report",
        deferred="B-1 deferred past Wave 1 (2026-08-30): 0/22 register rows "
                 "IMPLEMENTED, so the row is undischargeable regardless of "
                 "mutant count")
    rows[-1]["counts"] = counts

    # -- Platforms ---------------------------------------------------------
    for plat, label in (("linux", "Linux"), ("windows", "Windows link/run"),
                        ("macos", "macOS link/run"), ("ios", "iOS link/run"),
                        ("android", "Android link/run")):
        v, d, ev = probe_platform(plat)
        add("Platforms", label, v, d)
        rows[-1]["evidence"] = ev

    # -- Environment-attested platform criteria ----------------------------
    #
    # THESE ROWS REPLACED THE FOUR "privileged / physical" ROWS, AND THE
    # REPLACEMENT IS NOT A RELAXATION.
    #
    # The old rows required LOCAL OR USER-OWNED HARDWARE: a Windows rig on a
    # desk, a Mac mini, an iPhone on a cable, a 16 KiB-page Android phone with
    # an unlocked bootloader. Every one of them was undischargeable by anyone
    # without physical access, which made the wave's last four blockers a
    # purchasing decision rather than an engineering one.
    #
    # Each is now a REMOTELY EXECUTABLE, ENVIRONMENT-ATTESTED probe, and each
    # is strictly harder to fake than the row it replaced:
    #
    #   * the three that make an egress claim are adjudicated by an EXTERNAL
    #     leak oracle that the device can only reach by emitting a packet that
    #     left it. `privileged: true` never proved anything about egress; a
    #     third party's observation does.
    #   * every one carries an `environment` attestation whose keys
    #     `PREREQUISITES` above checks BEFORE any test result is read, so a
    #     machine that was never capable of the claim cannot produce a green
    #     row however well its tests ran.
    #   * every one is bound to this exact commit and this exact workflow run.
    #
    # THE macOS ROW BECAME TWO, and that is the point of splitting it.
    # `MACOS-SYSEXT-LIFECYCLE` runs in developer mode, which accepts an
    # extension a customer's Mac would refuse. While there was one macOS row, a
    # green developer-mode lifecycle read as "the signed, notarized product
    # works". `MACOS-PRODUCTION-SIGNATURE` is that other claim, and it can now
    # be red while the lifecycle is green -- which is the true state of affairs
    # more often than not.
    #
    # No runner, no instance, or no oracle still means no file, means
    # NOT-EXECUTED, means Phase 5 is not eligible. Absence of evidence is not
    # evidence of absence of defects, and it never became cheaper to fake.
    for stem, criterion, label in (
        ("windows-killswitch", "WINDOWS-WFP-KILLSWITCH",
         "Windows WFP kill switch (disposable nested guest, external oracle)"),
        ("android-16k", "ANDROID-16K-PAGE-SIZE",
         "Android 16 KiB page size (official 16 KB emulator image)"),
        ("macos-sysext", "MACOS-SYSEXT-LIFECYCLE",
         "macOS system-extension lifecycle (EC2 Mac, external oracle)"),
        ("macos-signature", "MACOS-PRODUCTION-SIGNATURE",
         "macOS production signature, notarization and stapling"),
        ("ios-corellium", "IOS-NE-FAIL-CLOSED",
         "iOS NetworkExtension fail-closed under injected failure (Corellium)"),
        ("ios-profile-removal", "IOS-PROFILE-REMOVAL-HONESTY",
         "iOS consumer profile removal is reported honestly"),
    ):
        v, d, ev = probe_criterion(stem, criterion)
        add("Platform criteria", label, v, d)
        rows[-1]["evidence"] = ev
        rows[-1]["criterion_id"] = criterion

    # -- The supervised/managed iOS criterion, OPTIONAL AND SEPARATE ---------
    #
    # `IOS-SUPERVISED-ALWAYS-ON` is the STRONGER criterion: on a supervised
    # device carrying an MDM Always-On VPN payload the user cannot remove,
    # "zero egress outside the tunnel, ever" is both true and testable.
    #
    # It is `required=False` because supervised mode is a PRODUCT MODE that may
    # not be implemented, and a criterion for an unbuilt mode should not hold
    # the wave. What it must never do is be satisfied by the consumer row: it
    # reads its own evidence file, its own criterion string, and
    # `PREREQUISITES` pins the consumer file's `product_mode` to `consumer` so
    # the two cannot be swapped.
    v, d, ev = probe_criterion("ios-supervised", "IOS-SUPERVISED-ALWAYS-ON")
    add("Platform criteria",
        "iOS supervised/managed Always-On (stronger; only if that mode ships)",
        v, d, required=False)
    rows[-1]["evidence"] = ev
    rows[-1]["criterion_id"] = "IOS-SUPERVISED-ALWAYS-ON"

    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", action="store_true", help="execute the probes")
    ap.add_argument("--json", type=Path,
                    default=REPO / "build" / "acceptance" / "first-wave-acceptance.json")
    ap.add_argument("--markdown", type=Path,
                    default=REPO / "build" / "acceptance" / "first-wave-acceptance.md")
    args = ap.parse_args()

    rows = build_rows(args.run)
    required = [r for r in rows if r["required"]]
    deferred = [r for r in rows if r.get("deferred")]
    green = [r for r in required if r["verdict"] == PASS]
    eligible = len(green) == len(required)

    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO,
                            capture_output=True, text=True).stdout.strip()
    dirty = bool(subprocess.run(["git", "status", "--porcelain"], cwd=REPO,
                                capture_output=True, text=True).stdout.strip())

    doc = {
        "schema_version": 1,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "commit": commit,
        "worktree_dirty": dirty,
        "probes_executed": args.run,
        "rows": rows,
        "required_total": len(required),
        "required_pass": len(green),
        "deferred_total": len(deferred),
        "phase_5_eligibility": PASS if eligible else FAIL,
    }
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(doc, indent=2) + "\n")

    lines = ["# First Implementation Wave — acceptance report", "",
             f"Commit `{commit}`{' (DIRTY WORKTREE — not release evidence)' if dirty else ''}",
             f"Probes executed: **{args.run}**", ""]
    section = None
    for r in rows:
        if r["section"] != section:
            section = r["section"]
            lines += ["", f"## {section}", "",
                      "| criterion | verdict | evidence |", "|---|---|---|"]
        lines.append("| {} | **{}**{} | {} |".format(
            r["criterion"], r["verdict"],
            " — DEFERRED, not gating" if r.get("deferred") else "",
            r["detail"].splitlines()[0].replace("|", "\\|")))
    lines += ["", "## Phase 5 eligibility", "",
              f"`{len(green)}` of `{len(required)}` required criteria are PASS.", ""]
    if deferred:
        lines += [f"`{len(deferred)}` row(s) are DEFERRED and excluded from the "
                  "conjunction. A deferred row still ran and still shows its real "
                  "verdict above; it is out of Wave-1 SCOPE, which is not the same "
                  "as passing:", ""]
        lines += [f"- **{r['criterion']}** — {r['verdict']} — {r['deferred']}"
                  for r in deferred]
        lines.append("")
    lines += [f"**Phase 5 eligibility: {doc['phase_5_eligibility']}**", ""]
    if not eligible:
        lines.append("Not eligible. The rows above that are not PASS are the reason; "
                     "`NOT-EXECUTED` counts against eligibility exactly as `FAIL` does, "
                     "because an absence of evidence is not evidence of absence of defects.")
    args.markdown.write_text("\n".join(lines) + "\n")

    print("\n".join(lines))
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as fh:
            fh.write("\n".join(lines) + "\n")

    return 0 if eligible else 1


if __name__ == "__main__":
    sys.exit(main())
