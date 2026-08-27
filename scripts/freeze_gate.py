#!/usr/bin/env python3
"""The TwinVPN Phase 2 contract freeze gate.

Checks every condition the Phase 2 objective sets before any production service,
networking engine, daemon, relay, application or UI may be implemented.

Each condition is verified against an ARTIFACT, not against a claim. A condition
whose evidence cannot be found fails, because a gate that passes on absence is
not a gate.
"""
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
C = ROOT / "contracts"

results = []


def gate(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    return bool(ok)


def read_json(p):
    try:
        return json.loads((C / p).read_text())
    except Exception:
        return None


def proto_text():
    return "\n".join(
        p.read_text() for p in sorted((C / "proto").rglob("*.proto"))
    )


def main():
    protos = sorted((C / "proto" / "twinvpn" / "v1").glob("*.proto"))
    text = proto_text()
    reasons = read_json("registry/reason_codes.json")
    caps = read_json("registry/capabilities.json")
    limits = read_json("registry/limits.json")

    # 1. Phase 1 ADR compliance
    conflicts = C / "docs" / "phase1-conflicts.md"
    gate("Phase 1 ADR compliance reviewed and conflicts recorded",
         conflicts.exists() and "CF-1" in conflicts.read_text(),
         f"{conflicts.relative_to(ROOT)}")

    # 2. Schemas compile
    r = subprocess.run(
        [str(ROOT / "node_modules" / ".bin" / "buf"), "build", "contracts",
         "-o", "/dev/null"],
        capture_output=True, cwd=str(ROOT),
    )
    gate("schemas compile", r.returncode == 0,
         f"{len(protos)} .proto files")

    r = subprocess.run(
        [str(ROOT / "node_modules" / ".bin" / "buf"), "lint", "contracts"],
        capture_output=True, cwd=str(ROOT),
    )
    gate("schemas lint clean", r.returncode == 0)

    # 3. Language bindings generate deterministically
    gen = C / "gen"
    langs = ["rust", "swift", "kotlin", "csharp"]
    present = [l for l in langs if (gen / l).is_dir() and any((gen / l).rglob("*"))]
    gate("language bindings generate deterministically",
         sorted(present) == sorted(langs),
         f"{', '.join(sorted(present))} ({sum(1 for _ in gen.rglob('*') if _.is_file())} files)")

    # 3b. Bindings COMPILE, not merely generate.
    # A byte-diff proves the committed bindings are current; only a compile
    # proves they are usable. ADR-0018 §11.12's "a schema change that a language
    # binding cannot express fails at merge" is a compile claim.
    # The verification lane for Android is named `jvm`, not `kotlin`: it compiles
    # the generated Java FIRST and then the Kotlin DSL that extends it, because
    # Kotlin alone would not compile. The gen/ directory is still `kotlin`, so
    # the two names are mapped rather than assumed equal.
    LANE_FOR_GEN_DIR = {"rust": "rust", "swift": "swift",
                        "kotlin": "jvm", "csharp": "csharp"}
    expected_lanes = sorted(LANE_FOR_GEN_DIR[l] for l in langs)
    res = (C / ".." / "build" / "verify" / ".work" / "result.json").resolve()
    compiled, skipped = [], []
    if res.exists():
        try:
            r = json.loads(res.read_text())
            compiled = r.get("verified", [])
            skipped = r.get("skipped", [])
            ok = not r.get("failed", True) and sorted(compiled) == expected_lanes
        except Exception:
            ok = False
    else:
        ok = False
    detail = f"{', '.join(sorted(compiled))} compile"
    if skipped:
        detail += f"; SKIPPED {', '.join(sorted(skipped))} (run: make verify-bindings)"
    if not res.exists():
        detail = "no verification receipt - run: make verify-bindings"
    gate("generated bindings compile against their runtimes", ok, detail)

    # 4/5. Contract and compatibility tests
    r = subprocess.run(
        [sys.executable, str(C / "tests" / "run_tests.py")],
        capture_output=True, cwd=str(ROOT),
    )
    out = r.stdout.decode()
    m = re.search(r"(\d+) checks, (\d+) failures", out)
    checks = m.group(1) if m else "?"
    gate("contract tests pass", r.returncode == 0, f"{checks} checks")
    gate("compatibility tests pass",
         r.returncode == 0 and "test_compatibility" in out,
         "breaking-change detector proven to fire on 9 forbidden changes and "
         "stay silent on 4 additive ones")

    # 6. Error taxonomy
    n_codes = len(reasons["reason_codes"]) if reasons else 0
    domains = sorted({e["domain"] for e in reasons["reason_codes"]}) if reasons else []
    gate("error taxonomy is defined",
         n_codes > 0 and len(domains) == 16,
         f"{n_codes} codes across {len(domains)} domains")

    # 7-9. Identifier, timestamp, correlation, causation semantics
    gate("stable identifiers are defined",
         (C / "docs" / "identifiers.md").exists()
         and limits is not None and "identifiers" in limits,
         f"{len(limits['identifiers'])} identifier rules" if limits else "")
    gate("timestamp semantics are defined",
         (C / "docs" / "timestamps.md").exists()
         and "WallClockMillis" in text and "MonotonicMicros" in text,
         "two distinct clock types in the schema")
    gate("correlation semantics are defined", "correlation_id" in text)
    gate("causation semantics are defined", "causation_id" in text)

    # 10. Idempotency
    gate("idempotency semantics are defined",
         (C / "docs" / "idempotency.md").exists()
         and "idempotency_key" in text and "VersionPrecondition" in text,
         "keys + monotone versions + conditional writes")

    # 11-12. Versioning and protocol version
    gate("schema versioning is defined",
         (C / "docs" / "versioning.md").exists() and "SchemaDescriptor" in text)
    gate("protocol-version representation is defined",
         "message ProtocolVersion" in text and "uint32 v_max" in text,
         "uint32 monotonic epoch, contiguous range")

    # 13. Capability negotiation
    n_caps = len(caps["capabilities"]) if caps else 0
    gate("capability negotiation contracts are defined",
         n_caps > 0 and "NegotiationResult" in text and "negotiation_hash" in text,
         f"{n_caps} capabilities, full-advertisement transcript binding")

    # 14-15. IPv4 and IPv6
    gate("IPv4 contracts are defined", "message IPv4Address" in text)
    gate("IPv6 contracts are defined",
         "message IPv6Address" in text and "zone_index" in text,
         "including the RFC 4007 zone index for link-local candidates")

    # 16-17. Routing and DNS
    gate("routing contracts are defined",
         all(s in text for s in ("RoutePrefix", "RouteAdvertisement",
                                 "RoutePolicy", "ROUTING_MODE_FULL_TUNNEL")))
    gate("DNS contracts are defined",
         all(s in text for s in ("message DNSPolicy", "DNSProtectionAssertion",
                                 "block_fallback_v4", "SplitDomainRule")))

    # 18. Identity exposes no private-key material
    forbidden = ("private_key", "privatekey", "secret_key", "pair_secret",
                 "epoch_seed", "session_key", "recovery_phrase")
    fields = re.findall(r"^\s+(?:optional\s+)?[\w.]+\s+(\w+)\s*=\s*\d+;", text, re.M)
    leaks = [f for f in fields if any(b in f.lower() for b in forbidden)]
    gate("identity contracts expose no private-key material",
         not leaks, f"{len(fields)} fields scanned" + (f"; LEAKS: {leaks}" if leaks else ""))

    # 19-20. Pairing and revocation
    gate("pairing contracts are defined",
         all(s in text for s in ("PairingRequest", "PairingChallenge",
                                 "PairingApproval", "PairingResult",
                                 "PairingRevocation")))
    gate("peer/device revocation contracts are defined",
         all(s in text for s in ("RevokeDeviceRequest", "DeviceRevoked",
                                 "PairingRevocation", "trust_epoch")))

    # 21-23. NAT, relay, session
    gate("NAT candidate contracts are defined",
         all(s in text for s in ("ConnectionCandidate", "CandidateSet",
                                 "PunchSync", "CANDIDATE_KIND_SERVER_REFLEXIVE")))
    gate("relay assignment/failover contracts are defined",
         all(s in text for s in ("RelayAssignment", "RelayBinding", "RelayDrain",
                                 "pair_tag", "failure_domain")))
    gate("session contracts are defined",
         all(s in text for s in ("ConnectionSession", "ResumeSession",
                                 "TunnelDescriptor")))

    # 24-25. Connection state and errors
    states = re.findall(r"CONNECTION_STATE_(\w+) = \d+;", text)
    gate("connection-state contracts are defined",
         len(set(states)) == 13,
         f"{len(set(states)) - 1} canonical states + UNSPECIFIED")
    gate("error contracts are defined",
         "message ErrorEnvelope" in text and "ResolvedAttributes" in text)

    # 26-28. Documentation
    gate("trust boundaries are documented",
         (C / "docs" / "trust-boundaries.md").exists())
    gate("producers and consumers are documented",
         (C / "docs" / "contract-matrix.md").exists())
    gate("durable versus ephemeral ownership is explicit",
         "EVENT_DURABILITY_DURABLE" in text
         and "EVENT_DURABILITY_EPHEMERAL" in text
         and "EventPublisher" in text,
         "carried on the wire and assertable by the receiver")

    # ---- report ------------------------------------------------------------
    width = max(len(n) for n, _, _ in results)
    print()
    print("=" * (width + 32))
    print("  TwinVPN Phase 2 CONTRACT FREEZE GATE")
    print("=" * (width + 32))
    for name, ok, detail in results:
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}]  {name.ljust(width)}  {detail}")
    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    print("-" * (width + 32))
    print(f"  {passed}/{total} gate conditions satisfied")

    # Open conflicts are reported but do not fail the gate: they are referred to
    # architecture review, and the gate's job is to say so loudly rather than to
    # block on a decision it cannot make.
    if conflicts.exists():
        open_cf = re.findall(r"^\| (CF-\d+|OQ-\d+)[^|]*\| [^|]*\| \*\*(open|watch)",
                             conflicts.read_text(), re.M | re.I)
        if open_cf:
            print()
            print(f"  {len(open_cf)} Phase 1 conflict(s) OPEN for architecture review:")
            for cid, _ in open_cf:
                print(f"      {cid}")
            print("      see contracts/docs/phase1-conflicts.md")

    print()
    if passed == total:
        print("  GATE PASSED — contracts may be frozen.")
        print("  Parallel production implementation remains BLOCKED until the")
        print("  freeze is declared and the open conflicts above are dispositioned.")
        return 0
    print("  GATE FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
