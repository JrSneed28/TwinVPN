#!/usr/bin/env python3
"""Structural checks over the TwinVPN compose topology.

`docker compose config` validates the SCHEMA. It does not check any of the
things this repository actually cares about, and it needs Docker, which not
every host has. This script checks the invariants, needs only PyYAML, and is
the reason the infra lane can fail for a real reason rather than a syntax one.

What it enforces, and why each one is here:

  1. NO SECRET HAS A DEFAULT.
     Every `${VAR}` whose name matches a secret-shaped pattern must use the
     `${VAR:?message}` form, so an unset value is a readable startup error and
     never a silent fallback to a known value. CLAUDE.md: "NEVER commit
     secrets, credentials, or .env files"; the corollary is that a default IS
     a committed credential.

  2. NO `.env` IS COMMITTED, AND NO KEY UNDER infra/secrets/ IS REACHABLE BY
     GIT. A generated development key is still a key.

     This check ASKS GIT rather than printing advice. For every file under
     infra/secrets/ it consults `git check-ignore` and `git ls-files`: ignored
     and untracked is a PASS, said quietly; tracked, or not ignored, is a
     FAIL that stops the build. An earlier revision warned instead, which made
     `--strict` fail on exactly the files `infra/scripts/bootstrap-local.sh`
     is supposed to create - and a check whose normal-path outcome is "5
     warnings, exit 1" trains people to run it with `--strict` off, which is
     how the real finding gets missed later. A check that can verify its own
     claim must verify it.

  3. EVERY BIND MOUNT SOURCE EXISTS.
     Docker silently creates a missing bind source as a ROOT-OWNED directory,
     which then fails at runtime as a permission error three layers away from
     the typo that caused it.

  4. NO HOST PORT IS PUBLISHED TWICE ON ONE ADDRESS.
     Compose reports this at `up` time, per-service, after some containers have
     already started.

  5. EVERY LONG-RUNNING SERVICE HAS BOTH A HEALTH AND A READINESS PATH.
     ownership.md rule 4 requires both. They answer different questions and a
     readiness probe that returns 200 unconditionally is not one.

  6. NO SERVICE PUBLISHES A PORT ON A WILDCARD ADDRESS.
     A development stack reachable from the LAN is a development stack on
     someone else's network.

  7. THE RELAY HAS NO CONTROL-PLANE DEPENDENCY.
     ADR-0005 §11.3 and architecture.md A-12: relay admission verifies an
     Owner-rooted token offline, so a relay must come up and stay up with the
     whole control plane down. A `depends_on` edge would make I5 quietly untrue
     in the local topology, and I5 is exactly the invariant a local topology is
     most likely to erode.

  8. THE RELAY FLEET MEETS THE >=2 ALTERNATES / >=2 FAILURE DOMAINS FLOOR.
     ADR-0006 §11.1 rule 3; architecture.md §2.12 calls a set of size 1 a
     design error.

  9. THE IPv6-ONLY OVERRIDE COVERS EVERY SERVICE THE BASE FILE PUBLISHES.
     A service left with a v4-only publication in the v6-only topology fails
     for a reason that has nothing to do with the code under test, which is
     how a v6 lane quietly stops being run.

 10. EVERY `TWINVPN_*` VARIABLE COMPOSE SETS IS ACTUALLY READ BY THAT SERVICE.
     This check exists because the mismatch shipped: compose set
     `TWINVPN_DATABASE_URL` and `TWINVPN_DB_MAX_CONNECTIONS` on `control-plane`
     while the service reads `TWINVPN_CP_DATABASE_URL` and
     `TWINVPN_CP_DATABASE_MAX_CONNECTIONS`, so a fully configured stack would
     still have died at startup on a missing required variable. A variable
     nobody reads is either a typo or a rename that only landed on one side,
     and both are invisible until something refuses to boot.

 11. PRESENCE HAS NO DATABASE.
     `docs/protocol.md` §6.1 and `contracts/docs/contract-matrix.md` §1
     category 4 make a DURABLE presence record "a permanent movement and IP
     history of the Owner" — the privacy defect itself. No database URL, no
     Postgres dependency.

 12. RENDEZVOUS AND PRESENCE DO NOT GATE STARTUP ON THE CONTROL PLANE.
     Both declared `ReadinessPolicy::NoControlPlaneCalls`, because a rendezvous
     pulled from the load balancer on a control-plane blip stops candidate
     exchange, which puts the control plane back in every reconnect — I5
     violated by way of a health check. A `service_healthy` startup gate is the
     same mistake one step earlier.

Usage:  check-compose.py [--strict]
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML is required: pip install pyyaml")

REPO_ROOT = Path(__file__).resolve().parents[2]
BASE = REPO_ROOT / "docker-compose.yml"
OVERRIDES = [
    REPO_ROOT / "infra" / "compose" / "ipv6-only.yml",
    REPO_ROOT / "infra" / "compose" / "ipv4-only.yml",
]

SECRET_NAME = re.compile(
    r"(PASSWORD|PASSWD|SECRET|TOKEN|DATABASE_URL|_DSN|PRIVATE_KEY|SIGNING_KEY|API_KEY)",
    re.IGNORECASE,
)
INTERPOLATION = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(:?[-?][^}]*)?\}")

# Anything that looks like committed key material.
KEYLIKE = re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")

problems: list[str] = []
warnings: list[str] = []


def fail(msg: str) -> None:
    problems.append(msg)


def warn(msg: str) -> None:
    warnings.append(msg)


def git(*args: str) -> int:
    """Run a git command in the repository and return its exit status.

    Returns 127 when git cannot be run at all, which the caller distinguishes
    from a real non-zero verdict: "git says no" and "git could not be asked"
    are different facts and must not collapse into one.
    """
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=REPO_ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return 127
    return proc.returncode


def walk_strings(node, path="") -> list[tuple[str, str]]:
    out = []
    if isinstance(node, dict):
        for k, v in node.items():
            out += walk_strings(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            out += walk_strings(v, f"{path}[{i}]")
    elif isinstance(node, str):
        out.append((path, node))
    return out


def check_secret_defaults(doc: dict) -> None:
    for path, text in walk_strings(doc):
        for m in INTERPOLATION.finditer(text):
            var, modifier = m.group(1), (m.group(2) or "")
            if not SECRET_NAME.search(var):
                continue
            if modifier.startswith(":?") or modifier.startswith("?"):
                continue
            fail(
                f"secret-shaped variable ${{{var}}} at {path} has a DEFAULT or no "
                f"required-marker. Use ${{{var}:?message}} - a default for a secret "
                f"is a committed credential."
            )


def check_no_committed_secrets() -> None:
    env = REPO_ROOT / ".env"
    if env.exists():
        fail(".env exists in the repository root. It must never be committed; "
             "verify it is ignored and remove it from any staged change.")

    secrets_dir = REPO_ROOT / "infra" / "secrets"
    if not secrets_dir.is_dir():
        return
    gitignore = secrets_dir / ".gitignore"
    if not gitignore.is_file():
        fail("infra/secrets/.gitignore is missing. Without it a locally generated "
             "key can be committed by `git add -A`.")
    else:
        body = gitignore.read_text()
        if "*" not in body:
            fail("infra/secrets/.gitignore does not ignore everything ('*').")

    # ------------------------------------------------------------------
    # Every file under infra/secrets/ is key material by construction - that
    # is what the directory is for - so every file is checked, not only the
    # PEM-bearing ones. The relays' 32-byte raw Noise static keys carry no
    # header to match on and are exactly as sensitive as the PEM files.
    #
    # THE CHECK ASKS GIT. `infra/scripts/bootstrap-local.sh` is SUPPOSED to
    # create these files, so their existence is the normal path and must not
    # be a finding. What matters is whether git can reach them, and git can
    # answer that:
    #
    #     git check-ignore -q <p>        exit 0 => ignored
    #     git ls-files --error-unmatch   exit 0 => TRACKED
    #
    # ignored AND untracked  -> PASS, silently.
    # tracked, or unignored  -> FAIL. A private key git can see is precisely
    #                           the thing this check exists to catch, and it
    #                           should stop the build rather than print advice.
    #
    # An earlier revision warned in the ignored-and-untracked case, which made
    # `--strict` exit 1 on a correctly bootstrapped tree. A check whose normal
    # outcome is a wall of warnings teaches people to drop `--strict`, and the
    # real finding is then missed later.
    # ------------------------------------------------------------------
    candidates = sorted(
        p for p in secrets_dir.rglob("*")
        if p.is_file() and not p.is_symlink() and p.name != ".gitignore"
    )
    if not candidates:
        return

    if git("rev-parse", "--git-dir") != 0:
        for path in candidates:
            warn(f"{path.relative_to(REPO_ROOT)} holds key material and could NOT be "
                 f"verified: git is unavailable or this is not a work tree, so "
                 f"neither `git check-ignore` nor `git ls-files` can be consulted. "
                 f"Confirm by hand that it is ignored and untracked.")
        return

    for path in candidates:
        rel = path.relative_to(REPO_ROOT).as_posix()

        try:
            pem = bool(KEYLIKE.search(path.read_bytes()[:512]))
        except OSError:
            pem = False
        what = "PEM private key material" if pem else "key material"

        # Tracked is the worse of the two failures and is reported first: an
        # ignore rule cannot save a file git already has.
        if git("ls-files", "--error-unmatch", "--", rel) == 0:
            fail(f"{rel} contains {what} and is TRACKED BY GIT. An ignore rule does "
                 f"not untrack an already-tracked file. Remove it from the index "
                 f"(`git rm --cached -- {rel}`), rotate the key, and check whether "
                 f"it reached a published commit.")
            continue

        if git("check-ignore", "-q", "--", rel) != 0:
            fail(f"{rel} contains {what} and is NOT IGNORED by git. One `git add -A` "
                 f"commits it. infra/secrets/.gitignore is supposed to cover "
                 f"everything under this directory; find out why it does not.")
            continue

        # ignored and untracked: the intended state. Say nothing.


def check_bind_sources(doc: dict) -> None:
    for name, svc in doc.get("services", {}).items():
        for vol in svc.get("volumes", []) or []:
            src = None
            if isinstance(vol, dict) and vol.get("type") == "bind":
                src = vol.get("source")
            elif isinstance(vol, str) and vol.startswith("./"):
                src = vol.split(":")[0]
            if not src or not src.startswith("."):
                continue
            target = (REPO_ROOT / src).resolve()
            if not target.exists():
                fail(f"{name}: bind mount source {src} does not exist. Docker would "
                     f"create it root-owned and the failure would surface elsewhere.")


PORT_RE = re.compile(
    r"^(?:(?P<host_ip>\[[0-9a-fA-F:]+\]|\d+\.\d+\.\d+\.\d+):)?"
    r"(?P<published>\d+):(?P<target>\d+)(?:/(?P<proto>tcp|udp))?$"
)


def parse_ports(svc: dict) -> list[tuple[str, str, str]]:
    """-> [(host_ip, published, proto)]"""
    out = []
    for p in svc.get("ports", []) or []:
        if isinstance(p, dict):
            out.append((str(p.get("host_ip", "*")), str(p.get("published")),
                        str(p.get("protocol", "tcp"))))
            continue
        m = PORT_RE.match(str(p))
        if not m:
            warn(f"unparsed port spec {p!r}")
            continue
        out.append((m.group("host_ip") or "*", m.group("published"),
                    m.group("proto") or "tcp"))
    return out


def check_ports(doc: dict, label: str) -> None:
    seen: dict[tuple[str, str, str], str] = {}
    for name, svc in doc.get("services", {}).items():
        for host_ip, published, proto in parse_ports(svc):
            if host_ip == "*":
                fail(f"[{label}] {name}: publishes {published}/{proto} on a WILDCARD "
                     f"address. A development stack reachable from the LAN is a "
                     f"development stack on someone else's network.")
            key = (host_ip, published, proto)
            if key in seen:
                fail(f"[{label}] host port collision: {host_ip}:{published}/{proto} "
                     f"claimed by both {seen[key]} and {name}")
            else:
                seen[key] = name


TWINVPN_SERVICES = {
    "control-plane", "rendezvous", "presence",
    "relay-a", "relay-b", "relay-directory", "relay-health",
}

# Which crate's sources back each compose service. Both relays run one binary.
SERVICE_SOURCES = {
    "control-plane": ["services/control-plane/src"],
    "rendezvous": ["services/rendezvous/src"],
    "presence": ["services/presence/src"],
    "relay-a": ["services/relay/src"],
    "relay-b": ["services/relay/src"],
    "relay-directory": ["services/relay-directory/src"],
    "relay-health": ["services/relay-health/src"],
}
COMMON_SOURCES = ["services/twinvpn-service-common/src"]

ENV_KEY_IN_RUST = re.compile(r'"(TWINVPN_[A-Z0-9_]+|OTEL_[A-Z0-9_]+)"')

# Variables compose sets that are deliberately NOT read by the Rust config
# loader. Each needs a reason, because "it is on a list" is how a genuine
# mismatch gets waved through.
ENV_CONSUMED_ELSEWHERE = {
    # Read by the image's HEALTHCHECK command, not by the service.
    "TWINVPN_HEALTHCHECK_URL",
    # Read by the OpenTelemetry SDK itself rather than by our config loader.
    # `OTEL_EXPORTER_OTLP_ENDPOINT` and `OTEL_TRACES_SAMPLER_ARG` ARE read by
    # twinvpn-service-common and are deliberately absent from this list.
    "OTEL_EXPORTER_OTLP_PROTOCOL",
    "OTEL_RESOURCE_ATTRIBUTES",
    "OTEL_SERVICE_NAME",
    "OTEL_TRACES_SAMPLER",
    # Supplied ahead of its consumer: twinvpn-service-common takes instance_id
    # as a caller argument and does not yet read this. infra/README.md §10
    # request 1 tracks it; the variable is set now so the fleet identity is
    # stable the moment the services adopt it.
    "TWINVPN_INSTANCE_ID",
}


def check_health_and_readiness(doc: dict) -> None:
    dockerfile = REPO_ROOT / "infra" / "docker" / "Dockerfile.service"
    if not dockerfile.is_file():
        fail("infra/docker/Dockerfile.service is missing")
        return
    body = dockerfile.read_text()
    if "HEALTHCHECK" not in body:
        fail("Dockerfile.service declares no HEALTHCHECK. ownership.md rule 4 "
             "requires health AND readiness on every long-running service.")
    if "/readyz" not in body:
        fail("Dockerfile.service's HEALTHCHECK does not target /readyz. Dependency "
             "ordering needs READINESS, which reflects dependency availability; "
             "liveness does not.")
    if "/healthz" not in body:
        fail("Dockerfile.service does not document a /healthz liveness path. Health "
             "and readiness are different checks and both are required.")

    for name in sorted(TWINVPN_SERVICES):
        svc = doc.get("services", {}).get(name)
        if svc is None:
            fail(f"service {name} is missing from the compose topology")
            continue
        env = svc.get("environment", {}) or {}
        if "TWINVPN_HEALTHCHECK_URL" not in env:
            fail(f"{name}: no TWINVPN_HEALTHCHECK_URL, so the image HEALTHCHECK "
                 f"cannot know where to probe")
        if "TWINVPN_ADMIN_ADDR" not in env:
            fail(f"{name}: no TWINVPN_ADMIN_ADDR, so /healthz, /readyz and /metrics "
                 f"have no listener")


def _rust_env_keys(dirs: list[str]) -> set[str]:
    """Every `"TWINVPN_*"` / `"OTEL_*"` string literal under the given roots."""
    found: set[str] = set()
    for d in dirs:
        root = REPO_ROOT / d
        if not root.is_dir():
            continue
        for path in root.rglob("*.rs"):
            try:
                found |= set(ENV_KEY_IN_RUST.findall(path.read_text()))
            except OSError:
                continue
    return found


def check_env_key_coverage(doc: dict) -> None:
    """Every TWINVPN_* variable compose sets must be read by that service.

    A variable nobody reads is either a typo or a rename that landed on one
    side only, and both are invisible until something refuses to boot. This
    check exists because exactly that shipped: compose set
    TWINVPN_DATABASE_URL / TWINVPN_DB_MAX_CONNECTIONS on control-plane while
    the service reads TWINVPN_CP_DATABASE_URL /
    TWINVPN_CP_DATABASE_MAX_CONNECTIONS.

    Note the direction. This does NOT assert that compose sets every variable a
    service reads: most have defaults, and requiring compose to restate a
    default would make the compose file a second source of truth for values the
    service already owns. It asserts the reverse, which is the direction that
    fails at startup.
    """
    common = _rust_env_keys(COMMON_SOURCES)
    if not common:
        warn("no service sources found under services/; env-key coverage NOT "
             "checked. This is expected only outside a full checkout.")
        return

    for name, dirs in SERVICE_SOURCES.items():
        svc = doc.get("services", {}).get(name)
        if svc is None:
            continue
        read = _rust_env_keys(dirs) | common
        for key in sorted((svc.get("environment", {}) or {}).keys()):
            if not key.startswith(("TWINVPN_", "OTEL_")):
                continue
            if key in ENV_CONSUMED_ELSEWHERE or key in read:
                continue
            fail(f"{name}: compose sets {key}, which nothing in "
                 f"{dirs[0]} or twinvpn-service-common reads. Either the name "
                 f"is wrong on one side, or the variable is dead. A service "
                 f"whose real key is unset dies at startup on a fully "
                 f"configured stack.")


def check_presence_has_no_database(doc: dict) -> None:
    """docs/protocol.md §6.1, contracts/docs/contract-matrix.md §1 category 4.

    A DURABLE presence record is "a permanent movement and IP history of the
    Owner" — the privacy defect itself, arriving as an infrastructure
    convenience. presence.proto classifies presence as ephemeral for the same
    reason. So this is not a tidiness check; it is the one place a database
    could be reintroduced without anyone noticing.
    """
    svc = doc.get("services", {}).get("presence")
    if svc is None:
        fail("service presence is missing from the compose topology")
        return

    for key in (svc.get("environment", {}) or {}):
        if "DATABASE" in key.upper() or "_DSN" in key.upper():
            fail(f"presence: compose sets {key}. Presence MUST NOT have a "
                 f"database: docs/protocol.md §6.1 and contract-matrix.md §1 "
                 f"category 4 make a durable presence record 'a permanent "
                 f"movement and IP history of the Owner'. Its state is a "
                 f"bounded in-memory table with a TTL, and losing it on "
                 f"restart is correct (architecture.md §2.13).")

    if "postgres" in (svc.get("depends_on") or {}):
        fail("presence: depends_on postgres. Presence has no database client "
             "and must not acquire one — see above. The dependency would also "
             "stop presence starting while Postgres is down, converting a hint "
             "service into an availability dependency.")


def check_owner_anchor(doc: dict) -> None:
    """ADR-0007 / architecture.md A-04, S-32.

    The control plane verifies Owner-signed statements against a pinned
    OwnerTrustAnchor set and nothing else. Without a compose mount,
    Owner-authority commands cannot work anywhere but a unit test — a whole
    capability silently absent from every local run.
    """
    svc = doc.get("services", {}).get("control-plane")
    if svc is None:
        return

    env = svc.get("environment", {}) or {}
    anchor = env.get("TWINVPN_CP_OWNER_ANCHOR_PATH")
    if not anchor:
        fail("control-plane: no TWINVPN_CP_OWNER_ANCHOR_PATH. Without the "
             "pinned OwnerTrustAnchor set (S-32) every Owner-authority "
             "statement is refused with AUTH.KEY_UNAVAILABLE — a capability "
             "lost on every local run rather than a startup failure anyone "
             "would notice.")
        return

    mounted = False
    for vol in svc.get("volumes", []) or []:
        target = vol.get("target") if isinstance(vol, dict) else None
        if target and str(anchor).startswith(str(target).rstrip("/") + "/"):
            mounted = True
            break
    if not mounted:
        fail(f"control-plane: TWINVPN_CP_OWNER_ANCHOR_PATH is {anchor}, which "
             f"no bind mount covers. The file cannot exist in the container, "
             f"so Owner-authority commands cannot work outside a unit test.")


def check_readiness_edges(doc: dict) -> None:
    """rendezvous and presence declared ReadinessPolicy::NoControlPlaneCalls.

    Their reasoning: a rendezvous that reports NOT READY on a control-plane
    blip is pulled from the load balancer, which stops candidate exchange,
    which puts the control plane back in the critical path of every reconnect —
    I5 violated by way of a health check.

    A `service_healthy` startup gate is the same mistake one step earlier: it
    makes the service unstartable while the control plane is unhealthy.
    Ordering is useful; gating is not.
    """
    for name in ("rendezvous", "presence"):
        svc = doc.get("services", {}).get(name)
        if svc is None:
            continue
        dep = (svc.get("depends_on") or {}).get("control-plane")
        if isinstance(dep, dict) and dep.get("condition") == "service_healthy":
            fail(f"{name}: depends_on control-plane with condition "
                 f"service_healthy. This service declared "
                 f"ReadinessPolicy::NoControlPlaneCalls precisely so that a "
                 f"control-plane blip cannot take it out; a startup gate "
                 f"reintroduces that coupling one step earlier. Use "
                 f"service_started — ordering is useful, gating is not.")


def check_relay_independence(doc: dict) -> None:
    for name in ("relay-a", "relay-b"):
        svc = doc.get("services", {}).get(name, {})
        deps = set((svc.get("depends_on") or {}).keys())
        forbidden = deps & {"control-plane", "rendezvous", "presence",
                            "relay-directory", "postgres"}
        if forbidden:
            fail(f"{name}: depends_on {sorted(forbidden)}. ADR-0005 §11.3 and "
                 f"architecture.md A-12 make relay admission control-plane-free: it "
                 f"verifies an Owner-rooted token OFFLINE. A startup edge here makes "
                 f"I5 untrue in the local topology.")


def check_relay_floor(doc: dict) -> None:
    regions: dict[str, set[str]] = {}
    for name, svc in doc.get("services", {}).items():
        env = svc.get("environment", {}) or {}
        if env.get("TWINVPN_SERVICE_NAME") != "relay":
            continue
        region = str(env.get("TWINVPN_RELAY_REGION", "?"))
        # Strip a ${VAR:-default} wrapper down to its default for comparison.
        m = re.match(r"^\$\{[^:}]+:-([^}]*)\}$", region)
        if m:
            region = m.group(1)
        regions.setdefault(region, set()).add(str(env.get("TWINVPN_RELAY_FAILURE_DOMAIN")))
    if not regions:
        fail("no relay services found in the topology")
    for region, domains in regions.items():
        if len(domains) < 2:
            fail(f"region {region!r} has {len(domains)} failure domain(s). "
                 f"ADR-0006 §11.1 rule 3 requires >=2 ACTIVE relays across >=2 "
                 f"failure_domains; architecture.md §2.12 calls a set of size 1 a "
                 f"DESIGN ERROR.")

    relay_ids = [
        (svc.get("environment", {}) or {}).get("TWINVPN_RELAY_ID")
        for svc in doc.get("services", {}).values()
        if (svc.get("environment", {}) or {}).get("TWINVPN_SERVICE_NAME") == "relay"
    ]
    if len(relay_ids) != len(set(relay_ids)):
        fail(f"duplicate TWINVPN_RELAY_ID in the fleet: {relay_ids}")
    for rid in relay_ids:
        if rid is None or not re.fullmatch(r"[0-9a-f]{16}", str(rid)):
            fail(f"TWINVPN_RELAY_ID {rid!r} is not 16 hex characters. "
                 f"contracts/registry/limits.json identifiers.relay_id_bytes = 8.")


def check_ipv6_override(base: dict, override: dict) -> None:
    net = (override.get("networks", {}) or {}).get("twinvpn", {})
    cfg = (net.get("ipam", {}) or {}).get("config", []) or []
    if not cfg:
        fail("ipv6-only.yml declares no IPAM config; it would inherit the "
             "dual-stack network and test nothing.")
    for entry in cfg:
        if ":" not in str(entry.get("subnet", "")):
            fail(f"ipv6-only.yml carries a non-v6 subnet {entry.get('subnet')!r}")
    if not net.get("enable_ipv6"):
        fail("ipv6-only.yml does not set enable_ipv6: true")

    base_publishers = {
        n for n, s in base.get("services", {}).items() if s.get("ports")
    }
    override_publishers = {
        n for n, s in (override.get("services", {}) or {}).items() if s.get("ports")
    }
    missing = base_publishers - override_publishers
    if missing:
        fail(f"ipv6-only.yml does not re-declare ports for {sorted(missing)}. A "
             f"leftover v4 publication asks docker-proxy to forward to a container "
             f"v4 address that does not exist, and the run fails for a reason that "
             f"has nothing to do with the service under test.")

    for name, svc in (override.get("services", {}) or {}).items():
        for host_ip, published, proto in parse_ports(svc):
            if not host_ip.startswith("["):
                fail(f"ipv6-only.yml {name}: publishes on {host_ip}, not a v6 address")

    # The product ULA is OVERLAY space and must never appear as underlay.
    for doc, label in ((base, "docker-compose.yml"), (override, "ipv6-only.yml")):
        for _, text in walk_strings(doc.get("networks", {})):
            if "fd7c:9e5d:2a10" in text:
                fail(f"{label} uses the product ULA fd7c:9e5d:2a10::/48 as an "
                     f"UNDERLAY prefix. ADR-0010 §11 AP-1 pins it as the TwinNet "
                     f"OVERLAY plan; a local run must not exercise an address plan "
                     f"the product forbids.")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--strict", action="store_true",
                    help="treat warnings as failures")
    args = ap.parse_args()

    if not BASE.is_file():
        sys.exit(f"missing {BASE}")

    base = yaml.safe_load(BASE.read_text())

    check_secret_defaults(base)
    check_no_committed_secrets()
    check_bind_sources(base)
    check_ports(base, "base")
    check_health_and_readiness(base)
    check_relay_independence(base)
    check_relay_floor(base)
    check_env_key_coverage(base)
    check_presence_has_no_database(base)
    check_owner_anchor(base)
    check_readiness_edges(base)

    for path in OVERRIDES:
        if not path.is_file():
            fail(f"missing override {path.relative_to(REPO_ROOT)}")
            continue
        doc = yaml.safe_load(path.read_text())
        check_secret_defaults(doc)
        check_ports(doc, path.name)
        if path.name == "ipv6-only.yml":
            check_ipv6_override(base, doc)

    for w in warnings:
        print(f"WARN  {w}")
    for p in problems:
        print(f"FAIL  {p}")

    if problems:
        print(f"\n{len(problems)} problem(s)")
        return 1
    if warnings and args.strict:
        print(f"\n{len(warnings)} warning(s), --strict")
        return 1
    print(f"compose topology OK ({len(warnings)} warning(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
