#!/usr/bin/env python3
"""Assert the machine-readable registries changed append-only.

ADR-0015 §11.2 rule 1: "The registry is APPEND-ONLY. A code MUST NOT be renamed,
and its semantics MUST NOT change once ACTIVE." Rule 2: "A retired code's
identifier MUST NOT be reused for different semantics, ever." Rule 6 requires the
diff to be checked in CI, and a non-append-only diff to FAIL THE BUILD.

ADR-0014 §10 applies the same discipline to the capability registry.

Usage: check_registry_append_only.py <git-ref>
"""
import json
import subprocess
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Attributes that MUST NOT change once a code is ACTIVE. `summary_key` and
# `next_action_key` are absent on purpose: rule 4 says the code is the contract
# and the human text is not, so the strings those keys resolve to - and the keys
# themselves - may be reworded.
FROZEN_REASON_ATTRS = [
    "domain", "class", "severity", "terminal", "user_actionable",
    "remediation_class", "scope",
]
FROZEN_CAP_ATTRS = [
    "name", "major", "security_relevant", "session_critical",
]


def at_ref(ref, path):
    r = subprocess.run(
        ["git", "show", f"{ref}:{path}"], capture_output=True, cwd=str(ROOT)
    )
    if r.returncode != 0:
        return None  # new file; nothing to compare against
    return json.loads(r.stdout)


def check_reasons(old, new):
    errs = []
    o = {e["reason_code"]: e for e in old["reason_codes"]}
    n = {e["reason_code"]: e for e in new["reason_codes"]}

    for code in o:
        if code not in n:
            errs.append(
                f"{code} was REMOVED. The registry is append-only; retire it with "
                f"status RETIRED instead, and never reuse the identifier"
            )
            continue
        a, b = o[code], n[code]
        if a.get("status") == "ACTIVE":
            for attr in FROZEN_REASON_ATTRS:
                if a.get(attr) != b.get(attr):
                    errs.append(
                        f"{code}.{attr} changed {a.get(attr)!r} -> {b.get(attr)!r} "
                        f"while ACTIVE. Semantics MUST NOT change once ACTIVE; add a "
                        f"new code and mark this one DEPRECATED with alias_of"
                    )
        if a.get("status") == "RETIRED" and b.get("status") != "RETIRED":
            errs.append(f"{code} was un-retired. A retired identifier is never reused")
        if b.get("status") == "DEPRECATED" and not b.get("alias_of"):
            errs.append(f"{code} is DEPRECATED without alias_of")
    return errs


def check_caps(old, new):
    errs = []
    o = {(e["name"], e["major"]): e for e in old["capabilities"]}
    n = {(e["name"], e["major"]): e for e in new["capabilities"]}
    for key in o:
        if key not in n:
            errs.append(
                f"capability {key[0]}/{key[1]} was REMOVED. Mark it DEPRECATED; a "
                f"removed token that a peer still advertises must remain nameable"
            )
            continue
        a, b = o[key], n[key]
        if a.get("status") == "ACTIVE":
            for attr in FROZEN_CAP_ATTRS:
                if a.get(attr) != b.get(attr):
                    errs.append(
                        f"{key[0]}/{key[1]}.{attr} changed while ACTIVE. "
                        f"security_relevant in particular participates in the S-37 "
                        f"monotonic floor, so changing it is a compatibility event"
                    )
    return errs


def main():
    if len(sys.argv) != 2:
        print("usage: check_registry_append_only.py <git-ref>")
        return 2
    ref = sys.argv[1]
    errs = []

    for path, fn in (
        ("contracts/registry/reason_codes.json", check_reasons),
        ("contracts/registry/capabilities.json", check_caps),
    ):
        old = at_ref(ref, path)
        if old is None:
            print(f"    {path}: new file, nothing to compare")
            continue
        new = json.loads((ROOT / path).read_text())
        found = fn(old, new)
        errs += found
        print(f"    {path}: {'OK' if not found else f'{len(found)} violation(s)'}")

    for e in errs:
        print(f"append-only violation: {e}")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
