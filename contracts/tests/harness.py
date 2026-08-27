"""Minimal zero-dependency assertion harness for the TwinVPN contract tests.

Deliberately not pytest: the contract gate must run identically on a developer
laptop, in CI, and on a machine with nothing installed but python3 and the
pinned buf binary. A test tier that needs its own dependency tree is a test
tier that will be skipped on the box where it matters.
"""
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
REPO = ROOT.parent
BUF = REPO / "node_modules" / ".bin" / "buf"

_failures = []
_checks = 0
_current = "?"


def buf(*args, stdin=None):
    """Run the pinned buf binary and return stdout bytes."""
    proc = subprocess.run(
        [str(BUF), *args], input=stdin, capture_output=True, cwd=str(REPO)
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"buf {' '.join(args)} failed:\n{proc.stderr.decode(errors='replace')}"
        )
    return proc.stdout


def image():
    """The compiled FileDescriptorSet as plain JSON."""
    return json.loads(buf("build", "contracts", "-o", "-#format=json"))


def registry(name):
    return json.loads((ROOT / "registry" / f"{name}.json").read_text())


def limits():
    return registry("limits")


def case(name):
    global _current
    _current = name


def check(condition, message):
    global _checks
    _checks += 1
    if not condition:
        _failures.append(f"{_current}: {message}")


def check_eq(actual, expected, message):
    check(actual == expected, f"{message} (got {actual!r}, want {expected!r})")


def run(modules):
    for mod in modules:
        print(f"  {mod.__name__}")
        mod.run()
    print(f"\n{_checks} checks, {len(_failures)} failures")
    for f in _failures:
        print(f"  FAIL  {f}")
    return 1 if _failures else 0
