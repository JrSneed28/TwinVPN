#!/usr/bin/env python3
"""The TwinVPN contract test suite.

Run with:  make test-contracts   (or: python3 contracts/tests/run_tests.py)

This suite is the behavioural half of the Phase 2 contract freeze gate. It runs
before any production service exists, because its whole purpose is to freeze the
boundaries those services will implement against.

Requires only python3, node, and the pinned buf binary in node_modules/.bin.
"""
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import harness
import test_schema_structure
import test_registries
import test_semantics
import test_wire
import test_compatibility

MODULES = [
    test_schema_structure,   # structural invariants of the schema itself
    test_registries,         # reason codes, capabilities, limits
    test_semantics,          # identifiers, presence, idempotency, durability
    test_wire,               # round-trip, unknown fields/enums, hostile input
    test_compatibility,      # breaking-change detection, deterministic codegen
]

if __name__ == "__main__":
    print("TwinVPN contract tests")
    sys.exit(harness.run(MODULES))
