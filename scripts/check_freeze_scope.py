#!/usr/bin/env python3
"""Assert the Phase 2 contract freeze is still in force.

The Phase 2 objective: "Do not implement any TwinVPN production service,
networking engine, daemon, relay, application or UI until the shared-contract
gate passes."

This check makes that a property of the build rather than of everyone's memory.
It fails if a production component directory appears while the freeze marker is
absent - which is the shape the mistake actually takes: a well-meaning parallel
agent starting early because the contracts "look done".

To lift the freeze, create contracts/FROZEN with the frozen schema digest. That
is a deliberate, reviewable act.
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
FROZEN = ROOT / "contracts" / "FROZEN"

# Directories that would hold a production component under ADR-0018 §11.12's
# layout. Their presence means implementation has begun.
PRODUCTION_PATHS = [
    "core", "shells", "services", "relay-server", "coordination",
    "rendezvous", "daemon", "apps",
]


def main():
    started = [p for p in PRODUCTION_PATHS if (ROOT / p).is_dir()]

    if FROZEN.exists():
        digest = FROZEN.read_text().strip().splitlines()[0] if FROZEN.read_text().strip() else ""
        print(f"    contract freeze DECLARED (digest {digest[:16]}...)")
        print(f"    production implementation is permitted")
        current = (ROOT / "contracts" / "SCHEMA_DIGEST")
        if current.exists() and digest and current.read_text().strip() != digest:
            print()
            print("::error::The schema has CHANGED since the freeze was declared.")
            print(f"  frozen:  {digest}")
            print(f"  current: {current.read_text().strip()}")
            print("  Re-declare the freeze deliberately, or revert the schema change.")
            return 1
        return 0

    if started:
        print()
        print("::error::Production implementation has begun before the contract freeze.")
        for p in started:
            print(f"  found: {p}/")
        print()
        print("  The Phase 2 objective blocks every production service, networking")
        print("  engine, daemon, relay, application and UI until the shared-contract")
        print("  gate passes AND the freeze is declared.")
        print("  To lift it: run 'make gate', disposition the open Phase 1 conflicts")
        print("  in contracts/docs/phase1-conflicts.md, then write the schema digest")
        print("  to contracts/FROZEN.")
        return 1

    print("    contract freeze IN FORCE; no production component present")
    return 0


if __name__ == "__main__":
    sys.exit(main())
