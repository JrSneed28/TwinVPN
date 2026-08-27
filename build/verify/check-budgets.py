#!/usr/bin/env python3
"""Check built artifacts against build/budgets.toml.

ADR-0018 BM-4: "A size or RSS breach at T4 is a failure, not a re-run."
ADR-0018 BM-5: "A target that cannot be built or budgeted is withdrawn
explicitly" -- named in the support matrix in the same release.

Those two rules together forbid a third outcome that checkers usually have:
"we could not measure it, so it passed". This script therefore has three
verdicts, not two, and the third is loud:

    PASS        measured, within budget
    FAIL        measured, over budget                      -> exit 1
    UNMEASURED  no artifact found for a gated target       -> exit 2 unless
                                                              --allow-unmeasured

`--allow-unmeasured` exists for wave 1, where rows 1-5 and 8-9 cannot be built
at all on a Linux host (ADR-0018 BM-3, ownership.md §5) and pretending otherwise
would be the failure the wave-1 objective names in its last line. It is NOT for
CI on a runner that can build the row.

Usage:
    check-budgets.py --artifacts <dir> [--row N] [--allow-unmeasured]
    check-budgets.py --list
    check-budgets.py --check-image-pins

Artifacts are matched by target triple: the script looks for
<artifacts>/<triple>/<any file> and takes the largest regular file as the
artifact. RSS is not measured here -- it is a runtime measurement belonging to
the T4 rigs, and this script REPORTS the budget rather than inventing a way to
satisfy it.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BUDGETS = REPO_ROOT / "build" / "budgets.toml"
IMAGE_LOCK = REPO_ROOT / "infra" / "docker" / "base-images.lock"

PASS, FAIL, UNMEASURED = "PASS", "FAIL", "UNMEASURED"


def load() -> dict:
    if not BUDGETS.is_file():
        sys.exit(f"missing {BUDGETS}")
    with BUDGETS.open("rb") as fh:
        doc = tomllib.load(fh)

    # Resolve `same_as_row`. ADR-0018 §11.9 row 2 says "as row 1" and row 10
    # says "as rows 6-8 by host"; that is an inheritance, not an absence, and
    # collapsing the two would report a real budget as a gap.
    by_row = {t["row"]: t for t in doc.get("target", [])}
    for t in doc.get("target", []):
        src = t.get("same_as_row")
        if src is None or src not in by_row:
            continue
        for field in ("artifact_max_bytes", "rss_max_bytes", "rss_at_peers",
                      "artifact_scope", "triples", "core_artifact", "linkage"):
            if field not in t and field in by_row[src]:
                t[field] = by_row[src][field]
        t["inherited_from_row"] = src
    return doc


def human(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024.0
    return str(n)


def largest_file(directory: Path) -> Path | None:
    best = None
    best_size = -1
    for path in directory.rglob("*"):
        if path.is_file() and not path.is_symlink():
            size = path.stat().st_size
            if size > best_size:
                best, best_size = path, size
    return best


def cmd_list(doc: dict) -> int:
    print(f"{'row':>3}  {'target':<22} {'wave':>4}  {'gate':<8} {'artifact':>12}  {'rss':>12}")
    print("-" * 78)
    for t in doc["target"]:
        art = human(t["artifact_max_bytes"]) if "artifact_max_bytes" in t else "-"
        rss = human(t["rss_max_bytes"]) if "rss_max_bytes" in t else "-"
        print(f"{t['row']:>3}  {t['name']:<22} {t.get('wave', '?'):>4}  "
              f"{t.get('gate', '?'):<8} {art:>12}  {rss:>12}")
    print()
    print("A '-' is an ABSENT budget, not a missing check: ADR-0018 §11.9 gives")
    print("no number for that field and build/budgets.toml refuses to invent one.")
    print()
    for name, b in doc.get("observability_budget", {}).items():
        cpu = f", CPU <= {b['cpu_percent_max']}%" if "cpu_percent_max" in b else ""
        print(f"observability/{name}: RSS <= {human(b['rss_max_bytes'])}{cpu}  ({b['source']})")
    return 0


def cmd_check_image_pins() -> int:
    """ADR-0018 §11.11 DP-2: dependencies are pinned by digest, not by tag.

    A tag is mutable. This reports how many base images are still tag-only, and
    fails when TWINVPN_REQUIRE_IMAGE_DIGESTS=1 -- so the reproducibility gap is
    a named, gateable fact rather than a comment nobody reads.
    """
    if not IMAGE_LOCK.is_file():
        print(f"UNMEASURED  {IMAGE_LOCK} is missing")
        return 2

    unpinned, pinned = [], []
    for raw in IMAGE_LOCK.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 3 and parts[2].startswith("sha256:"):
            pinned.append(parts[0])
        else:
            unpinned.append(parts[0] if parts else line)

    for key in pinned:
        print(f"PASS        {key}: digest-pinned")
    for key in unpinned:
        print(f"UNMEASURED  {key}: TAG ONLY, no digest resolved")

    if unpinned:
        print()
        print(f"{len(unpinned)} of {len(pinned) + len(unpinned)} base images are pinned by "
              f"MUTABLE TAG only.")
        print("Run build/verify/pin-base-images.sh on a host with registry access.")
        if os.environ.get("TWINVPN_REQUIRE_IMAGE_DIGESTS") == "1":
            print("TWINVPN_REQUIRE_IMAGE_DIGESTS=1 -> this is a FAILURE.")
            return 1
        print("Set TWINVPN_REQUIRE_IMAGE_DIGESTS=1 to make this a failure.")
        return 2
    return 0


def cmd_check(doc: dict, artifacts: Path, only_row: int | None,
              allow_unmeasured: bool) -> int:
    if not artifacts.is_dir():
        sys.exit(f"artifact directory not found: {artifacts}")

    verdicts: list[tuple[str, str]] = []

    for t in doc["target"]:
        if only_row is not None and t["row"] != only_row:
            continue
        if t.get("gate") != "release":
            continue

        name = t["name"]
        limit = t.get("artifact_max_bytes")
        if limit is None:
            print(f"SKIP        row {t['row']:>2} {name:<22} no artifact budget stated in "
                  f"ADR-0018 §11.9")
            continue

        for triple in t.get("triples", []):
            d = artifacts / triple
            if not d.is_dir():
                verdicts.append((UNMEASURED,
                                 f"row {t['row']:>2} {name:<22} {triple:<34} "
                                 f"no artifacts at {d}"))
                continue
            art = largest_file(d)
            if art is None:
                verdicts.append((UNMEASURED,
                                 f"row {t['row']:>2} {name:<22} {triple:<34} "
                                 f"directory is empty"))
                continue
            size = art.stat().st_size
            verdict = PASS if size <= limit else FAIL
            pct = 100.0 * size / limit
            verdicts.append((verdict,
                             f"row {t['row']:>2} {name:<22} {triple:<34} "
                             f"{human(size):>10} / {human(limit):>10} ({pct:.0f}%)  "
                             f"{art.relative_to(artifacts)}"))

        if "rss_max_bytes" in t:
            peers = t.get("rss_at_peers")
            at = f" at {peers} peers" if peers else ""
            print(f"NOTE        row {t['row']:>2} {name:<22} RSS budget "
                  f"{human(t['rss_max_bytes'])}{at} is a RUNTIME measurement on the T4 "
                  f"rigs; this script does not and must not fake it")

    for verdict, line in verdicts:
        print(f"{verdict:<11} {line}")

    failed = sum(1 for v, _ in verdicts if v == FAIL)
    unmeasured = sum(1 for v, _ in verdicts if v == UNMEASURED)
    passed = sum(1 for v, _ in verdicts if v == PASS)

    print()
    print(f"{passed} pass, {failed} FAIL, {unmeasured} unmeasured")

    if failed:
        print()
        print("ADR-0018 BM-4: a size breach at T4 is a FAILURE, NOT A RE-RUN.")
        print("Do not raise the budget. Raising a budget is a reviewed change to")
        print("ADR-0018 §11.9's table, per rule C-1.")
        return 1

    if unmeasured and not allow_unmeasured:
        print()
        print("ADR-0018 BM-5: a target that cannot be BUILT or BUDGETED is withdrawn")
        print("EXPLICITLY from the supported matrix in the same release, and reported")
        print("at runtime as PLATFORM.OS_UNSUPPORTED. An unmeasured gated target is")
        print("not a pass. Pass --allow-unmeasured only where the row genuinely")
        print("cannot be built on this runner (ADR-0018 BM-3).")
        return 2

    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--artifacts", type=Path, help="directory of <triple>/<artifact>")
    ap.add_argument("--row", type=int, help="check only this §11.9 row")
    ap.add_argument("--allow-unmeasured", action="store_true",
                    help="treat an unbuildable gated row as a warning, not a failure")
    ap.add_argument("--list", action="store_true", help="print the budget table and exit")
    ap.add_argument("--check-image-pins", action="store_true",
                    help="report base images still pinned by mutable tag (DP-2)")
    args = ap.parse_args()

    doc = load()

    if args.list:
        return cmd_list(doc)
    if args.check_image_pins:
        return cmd_check_image_pins()
    if args.artifacts:
        return cmd_check(doc, args.artifacts, args.row, args.allow_unmeasured)

    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
