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

  2. NO `.env` IS COMMITTED, AND NO KEY MATERIAL SITS IN infra/secrets/.
     A generated development key is still a key.

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

Usage:  check-compose.py [--strict]
"""

from __future__ import annotations

import argparse
import re
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

    for path in secrets_dir.rglob("*"):
        if path.is_file() and path.name != ".gitignore":
            try:
                head = path.read_bytes()[:200]
            except OSError:
                continue
            if KEYLIKE.search(head):
                warn(f"{path.relative_to(REPO_ROOT)} contains PEM private key material. "
                     f"It is gitignored; confirm it is not staged.")


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
