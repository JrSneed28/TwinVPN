#!/usr/bin/env python3
"""Verify that every relative link in the contract documentation resolves.

A contract document whose citation of a Phase 1 ADR does not resolve is a
citation nobody can check, which is how a contract drifts from the architecture
it claims to implement.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
LINK = re.compile(r"\[[^\]]*\]\(([^)#\s]+)(?:#[^)\s]*)?\)")

TARGETS = sorted(
    list((ROOT / "contracts").rglob("*.md")) + [ROOT / "contracts" / "README.md"]
)

def main():
    bad = []
    for md in TARGETS:
        if not md.exists():
            continue
        for m in LINK.finditer(md.read_text()):
            target = m.group(1)
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            resolved = (md.parent / target).resolve()
            if not resolved.exists():
                bad.append(f"{md.relative_to(ROOT)} -> {target}")
    for b in bad:
        print(f"broken link: {b}")
    if bad:
        return 1
    print(f"    {len(TARGETS)} documents, all links resolve")
    return 0

if __name__ == "__main__":
    sys.exit(main())
