#!/usr/bin/env python3
"""`build/ci/xcresult_summary.py`, which is what stops a vacuous iOS pass.

===========================================================================
THE DEFECT THIS EXISTS FOR
===========================================================================
`xcodebuild test` exits 0 for a bundle in which nothing was selected. So the
acceptance lane's exit status cannot tell "every assertion held" from "the
`-only-testing:` filter matched no case", and the second one is what a renamed
test class produces -- silently, on a green run.

The COUNT is what separates them, and the five honesty booleans are derived from
named cases' own results. Both come out of this parser, so a bug in it is a bug
in what `IOS-PROFILE-REMOVAL-HONESTY` means. It is graded here on documents
shaped like `xcresulttool`'s and on documents shaped like nothing at all,
because the second kind is what a toolchain change produces and the parser's
answer to it must be zero rather than a guess.

Run by `make test-acceptance-gate-logic`, through
`test_report_prerequisites.py`'s star import.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PARSER = REPO / "build" / "ci" / "xcresult_summary.py"

NAMES = [
    "testTheAppReportsNotProtected",
    "testAGreenShieldIsImpossibleAfterRemoval",
    "testTheConnectedStateIsCleared",
    "testTheUserGetsAnActionableProtectionLostState",
    "testNoContinuedKillSwitchClaimIsMade",
]


def run(summary, tests, names=NAMES) -> dict[str, str]:
    """Run the parser over two documents and return its output as a map."""
    with tempfile.TemporaryDirectory() as tmp:
        paths = []
        for name, doc in (("summary", summary), ("tests", tests)):
            path = Path(tmp) / f"{name}.json"
            if doc is not None:
                path.write_text(json.dumps(doc), encoding="utf-8")
            paths.append(str(path))
        proc = subprocess.run([sys.executable, str(PARSER), *paths, *names],
                              capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    out = {}
    for line in proc.stdout.splitlines():
        key, _, value = line.partition("=")
        out[key] = value
    return out


def a_bundle(results: dict[str, str], total: int | None = None) -> tuple[dict, dict]:
    """A summary and a tests tree shaped the way `xcresulttool` shapes them."""
    summary = {"title": "Test", "result": "Passed"}
    if total is not None:
        summary["totalTestCount"] = total
    tests = {
        "testNodes": [{
            "nodeType": "Test Plan",
            "name": "TwinVPNAcceptance",
            "result": "Passed",
            "children": [{
                "nodeType": "Test Suite",
                "name": "ProfileRemovalHonestyTests",
                "result": "Passed",
                "children": [
                    {"nodeType": "Test Case", "name": f"{name}()",
                     "result": outcome}
                    for name, outcome in results.items()
                ],
            }],
        }],
    }
    return summary, tests


class XcresultSummary(unittest.TestCase):

    def test_a_passing_bundle_reports_its_count_and_every_case_true(self):
        summary, tests = a_bundle({n: "Passed" for n in NAMES}, total=5)
        out = run(summary, tests)
        self.assertEqual(out["count"], "5")
        for name in NAMES:
            self.assertEqual(out[name], "true", name)

    def test_one_failed_case_is_false_and_the_others_are_not(self):
        # THE CASE THE FIVE BOOLEANS EXIST FOR. A run where four honesty
        # conditions hold and one does not must write four `true` and one
        # `false`, so the evidence names which one -- not a single verdict that
        # loses the answer.
        results = {n: "Passed" for n in NAMES}
        results["testNoContinuedKillSwitchClaimIsMade"] = "Failed"
        out = run(*a_bundle(results, total=5))
        self.assertEqual(out["testNoContinuedKillSwitchClaimIsMade"], "false")
        self.assertEqual(out["testTheAppReportsNotProtected"], "true")

    def test_a_skipped_case_is_not_a_pass(self):
        results = {n: "Passed" for n in NAMES}
        results["testTheConnectedStateIsCleared"] = "Skipped"
        out = run(*a_bundle(results, total=5))
        self.assertEqual(out["testTheConnectedStateIsCleared"], "false")

    def test_an_expected_failure_is_not_a_pass(self):
        # An expected failure is a case whose assertion did not hold. A
        # criterion attesting that a condition IS true must not be satisfied by
        # one, however green the run looks.
        results = {n: "Passed" for n in NAMES}
        results["testAGreenShieldIsImpossibleAfterRemoval"] = "Expected Failure"
        out = run(*a_bundle(results, total=5))
        self.assertEqual(out["testAGreenShieldIsImpossibleAfterRemoval"], "false")

    def test_a_case_that_is_absent_from_the_bundle_is_false(self):
        # A RENAMED OR UNSELECTED CASE. This is the vacuous pass in its most
        # likely real form: the class is renamed, `-only-testing:` matches
        # nothing, the run exits 0, and the row must not go green.
        results = {n: "Passed" for n in NAMES[:4]}
        out = run(*a_bundle(results, total=4))
        self.assertEqual(out["testNoContinuedKillSwitchClaimIsMade"], "false")

    def test_an_empty_run_reports_zero_rather_than_an_absence(self):
        out = run({"result": "Passed", "totalTestCount": 0}, {"testNodes": []})
        self.assertEqual(out["count"], "0")
        self.assertTrue(all(out[n] == "false" for n in NAMES))

    def test_a_bundle_with_no_count_key_is_derived_from_the_tree(self):
        # THE TOOLCHAIN-CHANGE CASE. `xcresulttool`'s shape has moved between
        # Xcode releases; a summary that no longer carries a count must produce
        # the real number from the tree rather than zero, because zero here is a
        # FAILURE about the toolchain wearing the costume of one about the
        # product.
        out = run(*a_bundle({n: "Passed" for n in NAMES}, total=None))
        self.assertEqual(out["count"], "5")

    def test_unreadable_documents_produce_zero_and_no_passes(self):
        # Fail closed. An absent or corrupt bundle is not a reason to raise --
        # the lane still has to write evidence -- and it is certainly not a
        # reason to report a pass.
        out = run(None, None)
        self.assertEqual(out["count"], "0")
        self.assertTrue(all(out[n] == "false" for n in NAMES))

    def test_a_suite_node_sharing_a_leaf_name_cannot_overwrite_a_case(self):
        # First wins, walking outside-in, so a parent's aggregate result cannot
        # be read as the case's own.
        tests = {"testNodes": [{
            "name": "testTheAppReportsNotProtected",
            "result": "Failed",
            "children": [{"name": "testTheAppReportsNotProtected()",
                          "result": "Passed"}],
        }]}
        out = run({"totalTestCount": 1}, tests)
        self.assertEqual(out["testTheAppReportsNotProtected"], "false")


if __name__ == "__main__":
    unittest.main(verbosity=2)
