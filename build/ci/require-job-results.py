#!/usr/bin/env python3
"""Fail the acceptance gate when any required job did not actually SUCCEED.

===========================================================================
THE HOLE THIS CLOSES
===========================================================================
`first-wave-acceptance` runs under `if: always()`, which is what makes it print
a report on the path where a platform job went red. `always()` also means every
one of its `needs:` is satisfied by a job that FAILED, was CANCELLED, or was
SKIPPED -- and a skip stays possible even now that every required job runs on a
GitHub-hosted runner, because a job can still be skipped by a fork guard, by a
`vars.*` condition, or by an edit to the `needs:` list nobody mirrored here.

So the gate's redness rests entirely on `build/acceptance/report.py`. That is a
good mechanism and it is not a complete one: report.py grades EVIDENCE FILES,
and a job that never ran wrote no file. It reads that row as NOT-EXECUTED, which
is correct -- but it cannot distinguish it from a criterion that has no row at
all, it cannot see `core-crypto` failing (that job writes no platform evidence),
and it cannot see the difference between "this criterion is unprovisioned" and
"this criterion's runner died". Job results are the only place that information
exists, and this script is the only thing in the run that reads them.

The specific failure it prevents: GREEN BY ABSENCE. A gating variable left
false, a renamed job, a cancelled job -- each one removes a criterion from the
run rather than failing it, and every mechanism downstream of the removal then
has nothing to complain about.

TWO CRITERIA HAVE NO JOB AT ALL, deliberately: `MACOS-SYSEXT-LIFECYCLE` and
`IOS-NE-FAIL-CLOSED` need a capability nobody can currently execute (an Apple
entitlement grant plus a human or MDM approval; a provisioned iPhone whose IPA
keeps the packet-tunnel-provider entitlement). They are ABSENT from `REQUIRED`
below rather than listed and expected to skip, because a job that does not exist
cannot report a result -- and `report.py` still prints both rows as NOT-EXECUTED
with the missing capability named, which is what keeps them counting against
Phase 5 eligibility.

===========================================================================
WHAT COUNTS AS A PASS
===========================================================================
`success`, and nothing else. Not `skipped`, not `cancelled`, not `failure`, not
a job missing from `needs` entirely (which means somebody edited the `needs:`
list and not this file, and the criterion silently stopped being required).

===========================================================================
USAGE
===========================================================================
    NEEDS='${{ toJSON(needs) }}' python3 build/ci/require-job-results.py
    python3 build/ci/require-job-results.py --self-check
"""

import json
import os
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]

# The acceptance report `make test-first-wave-gate` must have produced. Its
# ABSENCE is its own failure: it means the report step never reached its write,
# and without it there is no machine-readable answer to "which rows are red".
REPORT = REPO / "build/acceptance/first-wave-acceptance.json"

# Every job that must have SUCCEEDED, and -- for the ones that can vanish rather
# than fail -- exactly what makes them vanish. The second half is the whole
# point: "macos-signature was skipped" is not actionable, and
# "vars.TWINVPN_NOTARIZED_APP_URL is unset, so there is no published product to
# fetch" is.
#
# EVERY JOB HERE NOW RUNS ON A GITHUB-HOSTED RUNNER. No entry may name
# TWINVPN_AZURE_L1_REGISTERED, TWINVPN_EC2_MAC_REGISTERED,
# TWINVPN_CORELLIUM_ENABLED or TWINVPN_SENTINEL_HOST: none of those four gates
# exists any more, the kill-switch lane builds its own guest, its own oracle and
# its own sentinel in-box, and a remedy naming a variable nobody can set is
# worse than no remedy -- it sends a reader to provision a machine that is not
# the reason the row is red. `self_check` asserts all four names are gone.
#
# `mutation-proof` is DELIBERATELY ABSENT. It is not in `needs:` either: B-1 is
# deferred past Wave 1 by the integration lead (2026-08-30) and report.py marks
# the F-5 row deferred rather than counting it toward eligibility. Adding it here
# would re-impose the gating edge the deferral removed.
REQUIRED = {
    "core-crypto": None,
    "pairing-mi": None,
    "linux-link-run": None,
    "windows-link-run": None,
    "macos-link-run": None,
    "ios-link-run": None,
    "android-link-run": None,
    "windows-killswitch":
        "this job is HOSTED on windows-2025 and builds its own nested Hyper-V "
        "guest, its own in-box oracle and its own sentinel, so it can neither "
        "skip for want of a runner nor wait on a standing host: a non-success "
        "here is a real failure of the criterion. Look first at whether the "
        "guest reached Running, whether both internal switches carried their "
        "addresses with no NAT between guest and oracle, and whether the oracle "
        "saw all three families before the guest armed -- "
        "build/ci/logs/windows/ has all three",
    "android-16k":
        "this job is HOSTED and its four release-signing secrets are "
        "configured, so it can neither skip for want of a runner nor fail for "
        "want of a keystore: a non-success here is a real failure of the "
        "criterion. Look first at whether a stable google_apis_ps16k image was "
        "found (the sweep refuses previews and CANARY), whether the booted "
        "device reported a 16384-byte page, and whether any shipped ABI is "
        "under-aligned -- build/ci/logs/android/ has all three",
    "ios-acceptance":
        "this job is HOSTED on macos-26 and runs the two iOS SIMULATOR rows, "
        "which need no device, no farm and no signing identity: a non-success "
        "here is a real failure of the criteria. It writes BOTH "
        "build/ci/evidence/ios-failclosed-configuration.json and "
        "build/ci/evidence/ios-profile-removal.json, so a run that dies between "
        "them leaves one row NOT-EXECUTED. Look first at whether a simulator "
        "booted and at the test count read out of the .xcresult bundle -- a "
        "filter that matched nothing exits 0 and proves nothing",
    "macos-pf-anchor":
        "this job is HOSTED on macos-26 and needs no Team ID, no oracle and no "
        "sentinel, only passwordless root: a non-success here is a real failure "
        "of the criterion. Look first at whether "
        "shells/macos/packaging/install.sh validated the rendered anchor with "
        "`pfctl -n -f` and spliced /etc/pf.conf, whether `pfctl -s rules` still "
        "carries the exact anchor \"twinvpn\" reference (the wildcard form is inert), "
        "and whether the deny-label evaluations and packets both rose on the connect "
        "into the covered prefix was refused while the control connect "
        "succeeded -- build/ci/logs/macos/ has all three",
    "macos-signature":
        "set vars.TWINVPN_NOTARIZED_APP_URL and vars.TWINVPN_NOTARIZED_APP_SHA256. "
        "The job itself is HOSTED on macos-26 and needs no registered runner, "
        "but this criterion inspects a product the RELEASE pipeline published "
        "rather than anything the gate built, so without the pinned URL and its "
        "digest there is nothing to fetch and nothing to assess. It also needs "
        "vars.TWINVPN_TEAM_ID",
}

# What each non-success means, said in the terms a reader of the checks list
# needs. `skipped` gets the longest one because it is the only result that looks
# like nothing went wrong.
MEANING = {
    "skipped": "DID NOT RUN. A criterion that did not run is not a criterion "
               "that passed: no evidence was produced, so its row reads "
               "NOT-EXECUTED and it counts against eligibility exactly as a "
               "failure does",
    "cancelled": "was CANCELLED -- a timeout expiry, a superseding run, or a "
                 "manual stop. Whatever it had proved up to that point is not "
                 "a verdict",
    "failure": "FAILED",
}


def check(needs: dict, report_exists: bool) -> list[str]:
    """Every problem, not just the first. A reader fixing provisioning wants the
    whole list in one run rather than one variable per red build."""
    problems = []
    for job, remedy in sorted(REQUIRED.items()):
        entry = needs.get(job)
        if entry is None:
            problems.append(
                f"{job} is REQUIRED but is not in this job's `needs:` at all, "
                f"so its result was never consulted. Either it was removed from "
                f"`needs:` without being removed from REQUIRED in "
                f"build/ci/require-job-results.py, or the job was renamed and "
                f"the criterion silently stopped being required."
            )
            continue
        result = entry.get("result")
        if result == "success":
            continue
        meaning = MEANING.get(result, f"reported an unrecognised result {result!r}")
        line = f"{job} {meaning}."
        if remedy:
            line += f" To provision it: {remedy}."
        problems.append(line)

    if not report_exists:
        problems.append(
            f"no acceptance report was written to {REPORT.relative_to(REPO)}. "
            f"`make test-first-wave-gate` did not reach its own write, so there "
            f"is no machine-readable statement of which rows are red -- and an "
            f"absent report must never be read as an empty list of problems."
        )
    return problems


def main() -> int:
    raw = os.environ.get("NEEDS", "")
    if not raw.strip():
        print("::error::NEEDS is empty. This step must be given "
              "`NEEDS: ${{ toJSON(needs) }}`; without it nothing here is "
              "checked and the gate would pass for want of input.",
              file=sys.stderr)
        return 1
    try:
        needs = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"::error::NEEDS is not valid JSON: {exc}", file=sys.stderr)
        return 1

    problems = check(needs, REPORT.is_file())

    print(f"{'job':<22} result")
    for job in sorted(REQUIRED):
        print(f"{job:<22} {needs.get(job, {}).get('result', '<absent>')}")

    if not problems:
        print("\nevery required job succeeded and an acceptance report exists")
        return 0
    print()
    for p in problems:
        print(f"::error::{p}", file=sys.stderr)
    print(f"::error::{len(problems)} required result(s) are not a pass. The "
          f"First Implementation Wave gate is RED. A criterion that could not "
          f"run is not a criterion that passed.", file=sys.stderr)
    return 1


def self_check() -> int:
    """The smallest thing that fails if the logic above breaks."""
    all_green = {j: {"result": "success"} for j in REQUIRED}
    assert check(all_green, True) == [], "all green + report must be clean"

    assert len(check(all_green, False)) == 1, "a missing report is its own problem"

    for bad in ("skipped", "cancelled", "failure", "weird"):
        one = dict(all_green, **{"windows-killswitch": {"result": bad}})
        got = check(one, True)
        assert len(got) == 1 and got[0].startswith("windows-killswitch"), (bad, got)
    # The remedy text is what makes a skip actionable; losing it is a silent
    # regression that still exits 1 and still says nothing useful.
    skipped = dict(all_green, **{"macos-signature": {"result": "skipped"}})
    assert "TWINVPN_NOTARIZED_APP_URL" in check(skipped, True)[0]

    # AND NO REMEDY MAY SEND A READER AFTER INFRASTRUCTURE THAT NO LONGER
    # GATES ANYTHING. Each of these four named a machine or a variable the
    # reconciled workflow does not use; a remedy that keeps naming one is a
    # provisioning instruction for a rig that is not the reason the row is red.
    for retired in ("TWINVPN_AZURE_L1_REGISTERED", "TWINVPN_EC2_MAC_REGISTERED",
                    "TWINVPN_CORELLIUM_ENABLED", "TWINVPN_SENTINEL_HOST"):
        assert not any(retired in (r or "") for r in REQUIRED.values()), retired
    # The two criteria with no executor have no job, so they cannot be required
    # to report a result. report.py prints them NOT-EXECUTED with the reason.
    for absent in ("ios-corellium", "macos-sysext", "ios-ne-failclosed"):
        assert absent not in REQUIRED, absent

    missing = {j: v for j, v in all_green.items() if j != "ios-acceptance"}
    assert len(check(missing, True)) == 1
    assert "not in this job's `needs:`" in check(missing, True)[0]

    # Every non-success is a problem, including several at once.
    assert len(check({}, True)) == len(REQUIRED)
    print(f"self-check passed ({len(REQUIRED)} required jobs)")
    return 0


if __name__ == "__main__":
    sys.exit(self_check() if "--self-check" in sys.argv else main())
