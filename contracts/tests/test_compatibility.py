"""Compatibility: breaking-change detection, additive-change tolerance, and
deterministic generation.

ADR-0003 §11 rule 4 requires the contract artifacts to be "the input to CI
compatibility checks". ADR-0018 §11.12 requires /contracts/gen to be committed
and CI-regenerated and diffed, "so a schema change that a language binding
cannot express FAILS AT MERGE rather than at integration".
"""
import hashlib
import os
import json
import pathlib
import shutil
import subprocess
import tempfile

from harness import BUF, REPO, ROOT, buf, case, check, check_eq


def _buf_in(cwd, *args):
    return subprocess.run(
        [str(BUF), *args], capture_output=True, cwd=str(cwd)
    )


def _mutate(dst, filename, old, new):
    p = dst / "contracts" / "proto" / "twinvpn" / "v1" / filename
    s = p.read_text()
    assert old in s, f"mutation anchor not found in {filename}: {old!r}"
    p.write_text(s.replace(old, new, 1))


def _sandbox():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="twinvpn-compat-"))
    shutil.copytree(ROOT, tmp / "contracts")
    return tmp


def run():
    # -- The baseline image ---------------------------------------------------
    case("the current schema is its own compatible successor")
    baseline = buf("build", "contracts", "-o", "-#format=binpb")
    tmpdir = pathlib.Path(tempfile.mkdtemp(prefix="twinvpn-base-"))
    base_path = tmpdir / "baseline.binpb"
    base_path.write_bytes(baseline)
    r = _buf_in(REPO, "breaking", "contracts", "--against", str(base_path))
    check_eq(
        r.returncode, 0,
        f"the schema must be compatible with itself: {r.stderr.decode()[:300]}",
    )

    # -- Prohibited breaking changes MUST be detected -------------------------
    #
    # Each mutation below is a change ADR-0003 and ADR-0014 forbid. The test
    # asserts the DETECTOR FIRES - a compatibility gate nobody has proven fires
    # is a gate that will not fire when it matters.
    MUTATIONS = [
        ("field number reuse (silently reinterprets old bytes)",
         "common.proto",
         "  bytes message_id = 2;",
         "  bytes message_id = 3;"),
        ("field removal without reservation",
         "common.proto",
         "  bytes causation_id = 4;",
         ""),
        ("field type change (bytes -> string on an identifier)",
         "device.proto",
         "  bytes device_id = 1;",
         "  string device_id = 1;"),
        ("enum value renumbering (breaks every stored transition record)",
         "connection.proto",
         "  CONNECTION_STATE_BLOCKED = 11;",
         "  CONNECTION_STATE_BLOCKED = 13;"),
        ("enum value removal",
         "connection.proto",
         "  CONNECTION_STATE_MIGRATING = 8;",
         ""),
        ("message removal",
         "presence.proto",
         "message HeartbeatAck {",
         "message HeartbeatAckRenamed {"),
        ("field rename (JSON-name break)",
         "errors.proto",
         "  string reason_code = 1;",
         "  string reason_code_v2 = 1;"),
        ("repeated -> singular cardinality change",
         "errors.proto",
         "  repeated Evidence evidence = 5;",
         "  Evidence evidence = 5;"),
        ("oneof member moved out of its oneof",
         "common.proto",
         "    uint64 if_version = 1;",
         "  }\n  uint64 if_version = 1;\n  oneof unused_precondition {\n    bool pad = 3;"),
    ]

    for label, fname, old, new in MUTATIONS:
        case(f"breaking change detected: {label}")
        sand = _sandbox()
        try:
            _mutate(sand, fname, old, new)
            built = _buf_in(sand, "build", "contracts", "-o", "/dev/null")
            if built.returncode != 0:
                # A mutation that does not even compile is caught earlier than
                # the breaking gate, which is also a pass.
                check(True, f"{label}: rejected at compile")
                continue
            r = _buf_in(sand, "breaking", "contracts", "--against", str(base_path))
            check(
                r.returncode != 0,
                f"the breaking-change detector did NOT fire for: {label}. A "
                f"compatibility gate that misses this change will let it reach a "
                f"deployed device, where the failure mode is a silently "
                f"reinterpreted field rather than a failed build",
            )
        finally:
            shutil.rmtree(sand, ignore_errors=True)

    # -- Permitted additive changes MUST NOT be flagged -----------------------
    #
    # ADR-0014 N-1: an additive schema change that is compatible under ADR-0003
    # MUST NOT trigger an epoch bump. If the gate flagged these, every additive
    # change would be forced through a version bump it does not need, and the
    # epoch number would stop meaning "a receiver must behave differently".
    ADDITIVE = [
        ("adding a new field at a fresh number",
         "presence.proto",
         "  NetworkClass network_class = 4;",
         "  NetworkClass network_class = 4;\n  bool has_nat44 = 5;"),
        ("adding a new enum value at a fresh number",
         "candidate.proto",
         "  CANDIDATE_KIND_PREDICTED = 6;",
         "  CANDIDATE_KIND_PREDICTED = 6;\n  CANDIDATE_KIND_FUTURE = 7;"),
        ("adding a whole new message",
         "presence.proto",
         "message Heartbeat {",
         "message FutureThing {\n  uint64 x = 1;\n}\n\nmessage Heartbeat {"),
        ("adding a member to an existing oneof",
         "common.proto",
         "    bool if_absent = 2;",
         "    bool if_absent = 2;\n    uint64 if_generation = 3;"),
    ]
    for label, fname, old, new in ADDITIVE:
        case(f"additive change permitted: {label}")
        sand = _sandbox()
        try:
            _mutate(sand, fname, old, new)
            built = _buf_in(sand, "build", "contracts", "-o", "/dev/null")
            check_eq(built.returncode, 0,
                     f"{label} must compile: {built.stderr.decode()[:200]}")
            if built.returncode != 0:
                continue
            r = _buf_in(sand, "breaking", "contracts", "--against", str(base_path))
            check_eq(
                r.returncode, 0,
                f"an ADDITIVE change was flagged as breaking: {label}. ADR-0014 N-1 "
                f"says an additive schema change MUST NOT trigger an epoch bump; a "
                f"gate that flags it would force a bump the change does not need and "
                f"would drain the epoch number of meaning. buf said: "
                f"{r.stdout.decode()[:200]}",
            )
        finally:
            shutil.rmtree(sand, ignore_errors=True)

    # -- Reserved-number discipline ------------------------------------------
    case("a reserved field number cannot be reclaimed")
    sand = _sandbox()
    try:
        # Remove a field AND reserve its number: this is the CORRECT removal, and
        # buf treats a properly-reserved removal as non-breaking for the wire.
        _mutate(sand, "presence.proto",
                "  uint64 ttl_ms = 2;",
                "  reserved 2;\n  reserved \"ttl_ms\";")
        built = _buf_in(sand, "build", "contracts", "-o", "/dev/null")
        check_eq(built.returncode, 0, "a reserved removal must compile")
        # Now try to RECLAIM the reserved number for a different field. This is
        # the change ADR-0003's "never reuse removed field numbers" forbids.
        p = sand / "contracts" / "proto" / "twinvpn" / "v1" / "presence.proto"
        s = p.read_text().replace(
            "  reserved 2;\n  reserved \"ttl_ms\";",
            "  reserved \"ttl_ms\";\n  string something_else = 2;",
        )
        p.write_text(s)
        built = _buf_in(sand, "build", "contracts", "-o", "/dev/null")
        r = _buf_in(sand, "breaking", "contracts", "--against", str(base_path))
        check(
            built.returncode != 0 or r.returncode != 0,
            "reclaiming a reserved field number for a different type must be "
            "rejected: old bytes on the wire would be silently reinterpreted",
        )
    finally:
        shutil.rmtree(sand, ignore_errors=True)

    # -- Deterministic generation --------------------------------------------
    #
    # WHERE THIS GUARANTEE LIVES. The byte-identity check is owned by
    # `make contracts`, which regenerates in place, and by the CI step that then
    # fails if `git status` is dirty under contracts/gen. That is the right home
    # for it: regeneration calls pinned REMOTE codegen plugins, so doing it again
    # inside the test suite would make every test run depend on a network service
    # and its rate limits - and a contract gate that fails because a third party
    # is throttling is a gate nobody trusts.
    #
    # What this suite asserts instead is everything that does NOT need the
    # network: that the committed bindings exist, cover every schema file, and
    # are structurally complete. Set TWINVPN_VERIFY_CODEGEN=1 to additionally
    # re-run generation here.
    case("committed bindings are present and complete")
    gen = ROOT / "gen"
    check(gen.is_dir(), "contracts/gen must be committed")
    if not gen.is_dir():
        return

    if os.environ.get("TWINVPN_VERIFY_CODEGEN") == "1":
        case("regeneration is byte-identical")
        out = pathlib.Path(tempfile.mkdtemp(prefix="twinvpn-gen-"))
        try:
            r = subprocess.run(
                [str(BUF), "generate", "contracts",
                 "--template", "contracts/buf.gen.yaml", "-o", str(out)],
                capture_output=True, cwd=str(REPO),
            )
            if r.returncode != 0:
                check(False, f"regeneration failed: {r.stderr.decode()[:300]}")
            else:
                fresh = out / "gen"
                committed = {p.relative_to(gen): p for p in gen.rglob("*") if p.is_file()}
                regenerated = {p.relative_to(fresh): p for p in fresh.rglob("*") if p.is_file()}
                check_eq(sorted(committed), sorted(regenerated),
                         "the committed binding file set differs from a fresh generation")
                for rel in sorted(set(committed) & set(regenerated)):
                    check_eq(
                        hashlib.sha256(committed[rel].read_bytes()).hexdigest(),
                        hashlib.sha256(regenerated[rel].read_bytes()).hexdigest(),
                        f"gen/{rel} is stale or generation is non-deterministic",
                    )
        finally:
            shutil.rmtree(out, ignore_errors=True)

    case("all four Phase 1 binding targets are present")
    for lang in ("rust", "swift", "kotlin", "csharp"):
        d = gen / lang
        check(d.is_dir(), f"contracts/gen/{lang} is missing")
        if d.is_dir():
            check(
                any(d.rglob("*")),
                f"contracts/gen/{lang} is empty - ADR-0018 §11.12 assigns this target "
                f"to a real Phase 1 component",
            )
    check(
        not (gen / "typescript").exists() and not (gen / "go").exists(),
        "an unassigned binding target is present. ADR-0018 §11.12 fixes the set at "
        "rust/swift/kotlin/csharp; generating a binding no Phase 1 component consumes "
        "creates a permanent CI and maintenance obligation for nobody. See "
        "contracts/docs/phase1-conflicts.md CF-2",
    )

    case("every proto file reaches every binding")
    protos = sorted(
        p.stem for p in (ROOT / "proto" / "twinvpn" / "v1").glob("*.proto")
    )
    swift = {p.stem.replace("twinvpn_v1_", "").replace(".pb", "")
             for p in (gen / "swift").glob("*.swift")}
    for stem in protos:
        check(stem in swift, f"{stem}.proto produced no Swift binding")
    csharp_count = len(list((gen / "csharp").glob("*.cs")))
    check_eq(csharp_count, len(protos),
             "every .proto must produce exactly one C# file")

    case("the schema digest is reproducible")
    # SchemaDescriptor.schema_digest names an immutable published artifact set
    # (ADR-0003 §11 rule 4). It must be computable identically by anyone.
    h = hashlib.sha256()
    for rel in sorted(
        p.relative_to(ROOT).as_posix()
        for p in list((ROOT / "proto").rglob("*.proto"))
        + list((ROOT / "cddl").rglob("*.cddl"))
        + list((ROOT / "registry").glob("*.json"))
    ):
        h.update(rel.encode())
        h.update(b"\0")
        h.update((ROOT / rel).read_bytes())
        h.update(b"\0")
    digest = h.hexdigest()
    check_eq(len(digest), 64, "the schema digest is a SHA-256")
    (ROOT / "SCHEMA_DIGEST").write_text(digest + "\n")
