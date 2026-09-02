#!/usr/bin/env python3
"""The REAL evidence writers, graded by the REAL adjudicator.

===========================================================================
THE DEFECT THIS EXISTS FOR, WHICH IT ALREADY CAUGHT ONCE
===========================================================================
`check_run_binding` refuses evidence that records no `repository` whenever the
environment names one -- which, under Actions, is always. Not one writer under
`build/ci/` emitted the key. So every platform criterion would have failed on
every real run, while all 76 cases in `test_report_prerequisites.py` passed:
those grade the checker against `evidence_fixtures.py`, and the fixture and the
checker were written together. A PRODUCER/CHECKER DIVERGENCE IS INVISIBLE TO A
TEST WHOSE PRODUCER IS THE FIXTURE.

So nothing here constructs an evidence dict. Each case RENDERS THE WRITER'S OWN
HEREDOC, out of the shell source, with bash, and hands the result to the
adjudicator the acceptance gate runs. If a writer stops emitting a key the
checker requires, or emits a key the schema does not define, this fails --
without anyone having remembered to mirror the change into a fixture.

===========================================================================
HOW THE HEREDOC IS RENDERED, AND WHAT IS AND IS NOT REAL ABOUT IT
===========================================================================
The writers are the last hundred lines of scripts that need an emulator, a
simulator, a nested guest or a provisioned device to reach, so the script cannot
be run. What CAN be run is the heredoc itself: it is extracted verbatim,
`cat > "$FILE"` is turned
into `cat`, and it is evaluated with `digest.sh` sourced -- so
`twinvpn_repository_json` and `twinvpn_run_attempt_json` are the real ones and
`GITHUB_*` come from the environment exactly as they do in Actions.

REAL: every key, every helper call, every `${VAR:-default}`, and the whole JSON
structure -- which is what this file is about.

STUBBED: the runtime values. A variable the heredoc interpolates gets `null`
unless `_STUBS` names it, because `null` is the one literal that is valid JSON
in a bare position and still a string when quoted. `_STUBS` covers the handful
whose bare position needs a real shape (an object fragment, an array, a digest
map). A writer that introduces another one fails here with "is not valid JSON",
naming the script -- loudly, which is the right direction to fail in.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from adjudication import ARTIFACT_DIGEST_REQUIRED, check_run_binding  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
CI = REPO / "build" / "ci"
SCHEMA = json.loads(
    (REPO / "build" / "acceptance" / "platform-evidence.schema.json").read_text())

# The run this evidence is pretended to come from. The repository is deliberately
# NOT this checkout's own remote: the binding must be shown to carry whatever the
# environment says, and a value that happened to match anyway would prove nothing.
RUN = {
    "GITHUB_REPOSITORY": "twinvpn-example/twinvpn",
    "GITHUB_RUN_ID": "33318702367",
    "GITHUB_RUN_ATTEMPT": "2",
    "GITHUB_SERVER_URL": "https://github.com",
    "GITHUB_ACTIONS": "true",
    "GITHUB_JOB": "rendered-writer",
    "RUNNER_NAME": "rendered-runner",
}
HEX = "a" * 64

# Bare-position interpolations whose shape `null` cannot stand in for. Keyed by
# variable NAME, not by script: the writers share these names, so a new writer
# built from the same idiom needs no entry here.
_STUBS = {
    "environment": '"stub_attestation": true',   # `{ $environment, ... }`
    "artifacts": "[]",
    "transitions": "[]",
    "oracle": "null",
    "IPA_SHA256": HEX,
}

# `cat > "$SOMEWHERE" <<JSON` ... `JSON`, indented or not. Every evidence writer
# in build/ci/ uses exactly this form and nothing else in those scripts does.
HEREDOC = re.compile(r"^[ \t]*cat > (?P<dest>\S+) <<JSON\n(?P<body>.*?)^JSON$",
                     re.MULTILINE | re.DOTALL)
# The function whose stdout BECOMES four of the signature writer's booleans.
# See the case at the bottom of this file for why that is worth extracting.
CHECK_RUNNER = re.compile(r"^run_check\(\) \{\n.*?^\}$", re.MULTILINE | re.DOTALL)
VARREF = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)")

# `test_report_prerequisites.py` star-imports this module to keep ONE command
# running every case; only the TestCase should cross that import.
__all__ = ["EvidenceWriters"]


def writers() -> list[tuple[Path, str, list[str]]]:
    """Every evidence heredoc in build/ci/, as (script, body, criteria).

    The criteria come from the SCRIPT, not the heredoc: the heredoc interpolates
    `$CRITERION`, and the literal it will hold is assigned above it. A script
    that names none -- the version-1 link/run writers -- renders once under `""`,
    which is what `ARTIFACT_DIGEST_REQUIRED` calls "this criterion tests no
    artifact".
    """
    out = []
    for script in sorted(CI.glob("ci-*.sh")):
        text = script.read_text()
        named = sorted(c for c in ARTIFACT_DIGEST_REQUIRED if f'"{c}"' in text)
        for m in HEREDOC.finditer(text):
            out.append((script, m.group("body"), named or [""]))
    return out


def hermetic_path() -> str:
    """`PATH` with Windows interop removed.

    THE PREMISE THIS RESTORES. A writer's `$(...)` substitutions name the tools
    of the platform it runs ON -- `cmd.exe //c ver`, `xcodebuild`, `codesign`,
    `rustc` -- and this file renders all of them on ONE host. On a Linux runner
    that host cannot execute any of them, so every such substitution is empty
    and the render is about the writer's SHAPE, which is what the cases below
    grade.

    Under WSL2 that premise is false: Windows interop puts `/mnt/c/WINDOWS/
    system32` and friends on `PATH`, so `cmd.exe` really runs. From a
    `\\\\wsl.localhost\\...` working directory it prints a UNC-path warning
    whose literal backslashes are not a valid JSON escape, and every case that
    parses the Windows writer fails with `Invalid \\escape` -- a fact about the
    developer's laptop wearing the costume of a defect in the lane script. It is
    also slow: each interop call costs seconds.

    Dropping `/mnt/...` is the whole fix. It removes exactly the guest-platform
    tools and nothing this render legitimately needs -- `git`, `date`, `tr`,
    `head` and the `digest.sh` helpers are all native and stay reachable -- so
    it makes this host behave like the runner rather than making the assertion
    weaker. Nothing is skipped and nothing is loosened.
    """
    return ":".join(p for p in os.environ.get("PATH", "").split(":")
                    if p and not p.startswith("/mnt/"))


def render(body: str, criterion: str, env_over: dict | None = None) -> str:
    """Evaluate one writer's heredoc and return the JSON text it produces."""
    names = sorted(set(VARREF.findall(body)))
    digests = {n: HEX for n in ARTIFACT_DIGEST_REQUIRED.get(criterion, ())}
    lines = ["set +u", f'REPO={REPO!s}', f'. "{CI}/digest.sh"']
    for name in names:
        if name in RUN or name == "REPO":
            continue
        if name == "ARTIFACT_DIGESTS":
            value = json.dumps(digests)
        elif name in ("CRITERION", "criterion"):
            value = criterion
        else:
            value = _STUBS.get(name, "null")
        lines.append(f"{name}={value!r}".replace("\\'", "'\\''"))
    lines.append("cat <<JSON\n" + body + "JSON")

    env = {**os.environ, **RUN, **(env_over or {}), "PATH": hermetic_path()}
    proc = subprocess.run(["bash", "-c", "\n".join(lines)], env=env,
                          capture_output=True, text=True)
    if proc.returncode != 0:
        raise AssertionError(f"rendering the writer failed: {proc.stderr}")
    return proc.stdout


class EvidenceWriters(unittest.TestCase):
    """Every writer, rendered from source and graded by the real checker."""

    def setUp(self):
        # The CHECKER reads the expected run out of this process's environment,
        # the same way it does in the acceptance job. Without this the binding
        # has nothing to bind to and every case below passes vacuously.
        patch = unittest.mock.patch.dict(os.environ, RUN)
        patch.start()
        self.addCleanup(patch.stop)

    def test_every_writer_is_discovered(self):
        # If the heredoc form ever changes, every case below would silently
        # grade an empty list. A FLOOR rather than an equality: the lane set
        # grows as criteria are reconciled, and a count that has to be bumped by
        # whoever adds a lane fails for the wrong reason. Nine is the set after
        # the 2026-09-02 reconciliation (the Corellium lane gone, the hosted
        # simulator lane `ci-ios-acceptance.sh` added), and a discovery that
        # finds fewer has broken.
        found = writers()
        self.assertGreaterEqual(len(found), 9, [str(p) for p, _, _ in found])

    def test_rendered_evidence_is_valid_json(self):
        for script, body, criteria in writers():
            for criterion in criteria:
                with self.subTest(script=script.name, criterion=criterion):
                    json.loads(render(body, criterion))

    def test_the_real_adjudicator_accepts_what_the_writers_emit(self):
        # THE CASE THAT WOULD HAVE CAUGHT THE MISSING `repository`. It grades a
        # rendered writer, not a fixture, so it fails the moment the producer and
        # the checker disagree about a key.
        checked = 0
        for script, body, criteria in writers():
            for criterion in criteria:
                with self.subTest(script=script.name, criterion=criterion):
                    ev = json.loads(render(body, criterion))
                    self.assertEqual(check_run_binding(criterion, ev), [])
                    checked += 1
        self.assertGreaterEqual(checked, 9)

    def test_the_binding_carries_the_environment_and_not_a_constant(self):
        # A writer that hard-coded the right repository would satisfy the case
        # above. Rendered under a DIFFERENT repository, the checker must object.
        body = next(b for s, b, _ in writers() if s.name == "ci-android.sh")
        criterion = "ANDROID-16K-PAGE-SIZE"
        ev = json.loads(render(body, criterion,
                               {"GITHUB_REPOSITORY": "someone-else/fork"}))
        self.assertEqual(ev["repository"], "someone-else/fork")
        problems = check_run_binding(criterion, ev)
        self.assertTrue(any("not " + RUN["GITHUB_REPOSITORY"] in p
                            for p in problems), problems)

    def test_dropping_the_key_the_writers_now_emit_is_refused(self):
        # The negative control for the case two above: it is only meaningful if
        # the checker would have complained about the key's absence.
        body = next(b for s, b, _ in writers()
                    if s.name == "ci-windows-killswitch.sh")
        criterion = "WINDOWS-WFP-KILLSWITCH"
        ev = json.loads(render(body, criterion))
        ev.pop("repository")
        self.assertTrue(any("no `repository`" in p
                            for p in check_run_binding(criterion, ev)))

    def test_version_2_writers_emit_every_key_the_schema_requires(self):
        required = set(SCHEMA["required"])
        allowed = set(SCHEMA["properties"])
        seen = 0
        for script, body, criteria in writers():
            for criterion in criteria:
                ev = json.loads(render(body, criterion))
                if ev.get("schema_version") != 2:
                    continue
                seen += 1
                with self.subTest(script=script.name, criterion=criterion):
                    self.assertEqual(required - set(ev), set())
                    self.assertEqual(set(ev) - allowed, set())
        # The six version-2 criteria of the wave, and no fewer.
        self.assertGreaterEqual(seen, 6)

    def test_the_signature_lanes_check_runner_returns_only_the_boolean(self):
        # THE HALF `render()` STUBS, WHICH IS WHERE THE VALUES COME FROM.
        #
        # Everything above grades the SHAPE of the heredoc, with every
        # interpolation replaced by `null`. That is deliberate and it is also a
        # blind spot: `ci-macos-signature.sh` interpolates four booleans in BARE
        # position, and each of them is `$(run_check ...)`. The function printed
        # its `::group::` markers and the whole captured log to STDOUT, so the
        # command substitution swallowed them and `signature_intact` held
        # `::group::codesign-verify\n…\ntrue` -- not valid JSON in that position,
        # never equal to `true`, and invisible to every other case here.
        #
        # So the function is extracted from the lane and RUN, against a command
        # that succeeds and one that fails. It is the smallest thing that fails
        # if the console output ever returns to stdout.
        fn = CHECK_RUNNER.search((CI / "ci-macos-signature.sh").read_text())
        self.assertIsNotNone(fn, "run_check() is no longer extractable from "
                                 "ci-macos-signature.sh; this case is grading "
                                 "nothing")
        with tempfile.TemporaryDirectory() as tmp:
            for command, expected in (("true", True), ("false", False)):
                with self.subTest(command=command):
                    proc = subprocess.run(
                        ["bash", "-c", "set -euo pipefail\n"
                                       f"LOGDIR={tmp}\n{fn.group(0)}\n"
                                       f'printf %s "$(run_check probe {command})"'],
                        capture_output=True, text=True)
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    self.assertIs(json.loads(proc.stdout), expected)
                    # And the human output is not merely gone: it still reaches
                    # the job log, on the stream this lane already writes its
                    # `::error::` commands to.
                    self.assertIn("::group::probe", proc.stderr)

    def test_a_local_run_names_no_repository_rather_than_inventing_one(self):
        # `null`, never a guess: a developer's laptop is not a run of any
        # repository, and the checker only requires the key when one is named.
        body = next(b for s, b, _ in writers()
                    if s.name == "ci-macos-sysext.sh")
        ev = json.loads(render(body, "MACOS-SYSEXT-LIFECYCLE",
                               {"GITHUB_REPOSITORY": ""}))
        self.assertIsNone(ev["repository"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
