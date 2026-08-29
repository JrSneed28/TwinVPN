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

REPO = Path(__file__).resolve().parents[2]
EVIDENCE_DIR = REPO / "build" / "ci" / "evidence"
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


def probe_platform(platform: str, require_privileged: bool = False):
    """Read one platform's machine-readable link/run evidence and re-derive it.

    The job's own `verdict` is NOT trusted on its own: every boolean is
    re-checked here, so a job that writes PASS with `lifecycle_transitions: []`
    is caught rather than believed.
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

    def add(section, name, verdict, detail, required=True):
        rows.append({
            "section": section, "criterion": name,
            "verdict": verdict, "detail": detail, "required": required,
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
    v, d = probe_command(
        "core", "cargo test -q -p twinvpn-core --test pairing_production", run)
    add("F-2", "complete MI-P1 PairingOffer returned", v, d)
    v, d = probe_command(
        "core", "cargo test -q -p twinvpn-crypto --test pairing_offer", run)
    add("F-2", "QR/text carriage available", v, d)
    v, d = probe_command("shells/linux", "cargo test -q --workspace", run)
    add("F-2", "C-B integration flow", v, d)
    v, d = probe_command(
        "core", "cargo test -q -p twinvpn-core --test pairing_refusals", run)
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
    add("F-5", "mutation obligations discharged",
        (PASS if ok else FAIL) if have else NOT_EXECUTED,
        "specified={specified} executable={executable} executed={executed} "
        "discharged/killed={discharged} survived={survived} missing={missing} "
        "B-1 {b1_discharged}/{b1_specified}".format(**counts)
        if have else "no machine-readable mutation report")
    rows[-1]["counts"] = counts

    # -- Platforms ---------------------------------------------------------
    for plat, label in (("linux", "Linux"), ("windows", "Windows link/run"),
                        ("macos", "macOS link/run"), ("ios", "iOS link/run"),
                        ("android", "Android link/run")):
        v, d, ev = probe_platform(plat)
        add("Platforms", label, v, d)
        rows[-1]["evidence"] = ev

    # -- Privileged / physical lifecycle -----------------------------------
    #
    # A hosted runner proves linking and execution. It does not prove
    # privileged platform behaviour, and this section exists so that the two
    # can never be conflated: these rows read SEPARATE evidence files, and a
    # file whose `privileged` is false fails the row no matter how green the
    # job that wrote it was.
    #
    # No self-hosted runner registered means no file, means NOT-EXECUTED,
    # means Phase 5 is not eligible. That is the intended behaviour: the
    # privileged criterion is undischarged until somebody actually discharges
    # it on real hardware.
    # `android-device` is here rather than optional for three reasons the
    # hosted emulator job cannot reach: `arm64-v8a` is PACKAGED by
    # android-link-run and LOADED NOWHERE (the emulator runs the x86_64 .so);
    # C-12's 16 KiB LOAD alignment flag is applied on every ABI and tested on
    # none, because the pinned API-30 image has 4 KiB pages; and ADR-0020's
    # assurance ladder reports its bottom rung on an emulator, so hardware
    # custody is unproven. Shipping the ARM library on the strength of an
    # x86_64 run is exactly the substitution this gate exists to refuse.
    for stem, label in (("windows-privileged", "Windows privileged lifecycle"),
                        ("macos-privileged", "macOS NetworkExtension lifecycle"),
                        ("ios-device", "iOS physical-device lifecycle"),
                        ("android-device", "Android physical-device lifecycle")):
        v, d, ev = probe_platform(stem, require_privileged=True)
        add("Privileged / physical", label, v, d)
        rows[-1]["evidence"] = ev

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
        lines.append("| {} | **{}** | {} |".format(
            r["criterion"], r["verdict"],
            r["detail"].splitlines()[0].replace("|", "\\|")))
    lines += ["", "## Phase 5 eligibility", "",
              f"`{len(green)}` of `{len(required)}` required criteria are PASS.", "",
              f"**Phase 5 eligibility: {doc['phase_5_eligibility']}**", ""]
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
