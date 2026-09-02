#!/usr/bin/env python3
"""What an `.xcresult` says ran, and which named cases passed.

    xcresult_summary.py <summary.json> <tests.json> [testMethodName ...]

Prints, on stdout:

    count=<integer>            how many test CASES the bundle recorded
    <testMethodName>=true      once per name asked for, false when it did not
    <testMethodName>=false     pass or could not be found

===========================================================================
WHY THIS IS NOT THREE LINES OF `jq`
===========================================================================

A VACUOUS RUN IS NOT A PASS. `xcodebuild test` exits 0 for a bundle in which
nothing was selected, so the exit status cannot distinguish "every assertion
held" from "the filter matched no case". The count is what separates them, and
it has to come from the result bundle rather than from the lane's own belief.

AND THE SHAPE OF THAT BUNDLE IS NOT A CONTRACT. `xcresulttool`'s JSON has
changed between Xcode releases, and its `test-results` subcommands are newer
than the format they replaced. A reader written against one fixed path reports
zero tests on the next release -- which, read as a count, is a FAILURE, and
would be a failure about the toolchain wearing the costume of a failure about
the product. So both documents are walked GENERICALLY: every nested object is
searched for the keys this needs, wherever they sit.

EVERY UNKNOWN IS A FAILURE. A name that cannot be found in the tree is reported
`false`, never omitted and never `true`: "we could not tell" and "it passed"
must not be the same value, and the direction they collapse in must be the safe
one.
"""

from __future__ import annotations

import json
import sys

# What `result` values `xcresulttool` uses for a case that held. `Expected
# Failure` is deliberately NOT among them: an expected failure is a case whose
# assertion did not hold, and a criterion attesting that a condition is true
# must not be satisfied by one.
PASSED = {"passed", "success", "succeeded"}

# Count keys, most specific first. Whichever appears is believed; if none does,
# the count is derived from the tree instead.
COUNT_KEYS = ("totalTestCount", "totalTests", "testsCount")


def walk(node):
    """Every dict in a JSON document, at any depth."""
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from walk(value)


def load(path: str):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        # An unreadable document contributes nothing. It must not raise: the
        # lane still has to write evidence, and evidence that says zero tests
        # ran is the correct evidence for a run whose bundle could not be read.
        return None


def case_results(tests_doc) -> dict[str, str]:
    """Every node that carries both a name and a result, keyed by name.

    A test METHOD is what the lane asks about, and a method's node name is the
    method's name -- sometimes with a trailing `()`. Both spellings are keyed so
    a caller can ask with either.
    """
    found: dict[str, str] = {}
    if tests_doc is None:
        return found
    for node in walk(tests_doc):
        name = node.get("name") or node.get("nodeIdentifier") or node.get("identifier")
        result = node.get("result")
        if not isinstance(name, str) or not isinstance(result, str):
            continue
        # `TwinVPNAcceptanceTests/ProfileRemovalHonestyTests/testFoo()` and
        # `testFoo()` both reduce to `testFoo`.
        leaf = name.rsplit("/", 1)[-1].removesuffix("()")
        # FIRST WINS, so a parent node that happens to share a leaf name cannot
        # overwrite the case's own result with the suite's.
        found.setdefault(leaf, result)
    return found


def test_count(summary_doc, results: dict[str, str]) -> int:
    for node in walk(summary_doc):
        for key in COUNT_KEYS:
            value = node.get(key)
            if isinstance(value, int):
                return value
    # No count key anywhere. Derive it from the tree: a node named like a test
    # method and carrying a result IS a case that ran.
    return sum(1 for name in results if name.startswith("test"))


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print("usage: xcresult_summary.py <summary.json> <tests.json> [name ...]",
              file=sys.stderr)
        return 2

    summary_doc = load(argv[1])
    tests_doc = load(argv[2])
    results = case_results(tests_doc)

    print(f"count={test_count(summary_doc, results)}")
    for name in argv[3:]:
        key = name.rsplit("/", 1)[-1].removesuffix("()")
        outcome = results.get(key, "")
        print(f"{key}={'true' if outcome.strip().lower() in PASSED else 'false'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
