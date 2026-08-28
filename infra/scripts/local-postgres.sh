#!/usr/bin/env bash
# A PostgreSQL the control plane can use, WITHOUT root and WITHOUT a container.
#
# ===========================================================================
# WHY THIS EXISTS
# ===========================================================================
# `docker-compose.yml` runs Postgres in a container, and that is the right
# answer when a container runtime is available. It was not available here:
# rootless podman needs `newuidmap`, a SETUID binary that only root can
# install, so `docker compose up postgres` cannot run on this host at all.
#
# Without a database the control plane cannot start, and without the control
# plane the local environment could exercise the relay data path end to end and
# NOT ONE control-plane ceremony. That gap was recorded as a limitation until it
# turned out not to be one: PostgreSQL's own binaries run perfectly well as an
# unprivileged user out of any directory.
#
# ===========================================================================
# WHAT THIS IS NOT
# ===========================================================================
# It is not a deployment, and it is not what CI or production should use. It is
# a DEVELOPMENT database for a DEVELOPMENT plane:
#
#   - It listens on 127.0.0.1 only, on a non-default port.
#   - It uses `--auth=trust`, which is safe ONLY because of the line above and
#     is why the port is loopback-bound rather than configurable.
#   - Its data directory is under $TMPDIR and is destroyed by `reset`.
#
# `docker compose` remains the supported topology. This is the fallback that
# makes the plane runnable on a host that cannot run one.
#
# Usage:
#   local-postgres.sh up      fetch (once), initdb (once), start
#   local-postgres.sh down    stop
#   local-postgres.sh reset   stop and DESTROY the data directory
#   local-postgres.sh url     print the DSN the control plane wants

set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# ---------------------------------------------------------------------------
# The binaries. PINNED BY VERSION AND BY SHA-256.
#
# ADR-0018 §11.11 DP-1/DP-2 wants a supply chain that cannot move underneath a
# build. A tag is mutable and a digest is not, so the digest is the real pin —
# the same reasoning `infra/docker/base-images.lock` applies to base images, and
# the same reason this script REFUSES to proceed on a mismatch rather than
# warning about one.
#
# 16.4 rather than the 17.2 `docker-compose.yml` pins, and the difference is
# recorded rather than hidden: this is the newest release the portable bundle
# publishes. Nothing the control plane uses differs between them — the schema is
# ordinary SQL and the event bus is LISTEN/NOTIFY, both stable since long
# before 16 — but a local run is therefore NOT a version-parity run, and a
# migration that depended on a 17-only feature would pass in compose and fail
# here.
# ---------------------------------------------------------------------------
PG_VERSION=16.4.0
PG_SHA256=14a5cf546aee7d327a2f5b46be6c571f2f724a2b485c270d46f3e44a1ac3df18
PG_URL="https://repo1.maven.org/maven2/io/zonky/test/postgres/embedded-postgres-binaries-linux-amd64/${PG_VERSION}/embedded-postgres-binaries-linux-amd64-${PG_VERSION}.jar"

cache="${TWINVPN_PG_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/twinvpn/pgsql-${PG_VERSION}}"
data="${TWINVPN_PG_DATA:-${TMPDIR:-/tmp}/twinvpn-pgdata}"
port="${TWINVPN_PG_PORT:-55432}"
user=twinvpn
db=postgres

log() { printf '%s\n' "$*"; }
die() { printf '!! %s\n' "$*" >&2; exit 1; }

url() { printf 'postgres://%s@127.0.0.1:%s/%s?sslmode=disable' "$user" "$port" "$db"; }

fetch() {
  [ -x "$cache/bin/postgres" ] && return 0
  command -v curl >/dev/null 2>&1 || die "curl is required to fetch the PostgreSQL binaries"
  log "==> fetching PostgreSQL ${PG_VERSION} (once, into $cache)"
  mkdir -p "$cache"
  local jar="$cache/bundle.jar"
  curl -fsSL -o "$jar" "$PG_URL" || die "could not download $PG_URL"

  # The pin, checked before anything is extracted. A bundle that does not match
  # is not unpacked at all: the failure mode of a substituted archive is a
  # database binary running on a developer's machine, and "warn and continue"
  # is not a defensible response to that.
  local got
  got=$(sha256sum "$jar" | awk '{print $1}')
  if [ "$got" != "$PG_SHA256" ]; then
    rm -f "$jar"
    die "PostgreSQL bundle sha256 mismatch
    expected ${PG_SHA256}
    got      ${got}
  The archive was NOT unpacked. Either the pin is stale (update it in this
  script, deliberately, in a reviewable commit) or the artifact changed."
  fi

  # The jar is a zip containing one .txz. `python3` rather than `unzip`, which
  # is not installed everywhere and is one more thing to require.
  python3 -c "import zipfile,sys; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" "$jar" "$cache"
  tar xJf "$cache/postgres-linux-x86_64.txz" -C "$cache"
  [ -x "$cache/bin/postgres" ] || die "the bundle did not contain bin/postgres"
  log "    ok: $("$cache/bin/postgres" --version)"
}

init() {
  [ -f "$data/PG_VERSION" ] && return 0
  log "==> initdb into $data"
  mkdir -p "$data"
  # `--locale=C` and UTF-8, matching docker-compose.yml's POSTGRES_INITDB_ARGS
  # exactly, so a local run and a compose run SORT IDENTICALLY. A collation
  # difference here would make an ordering test pass in one and fail in the
  # other, for a reason nobody would look for.
  LC_ALL=C "$cache/bin/initdb" -D "$data" -U "$user" \
    --auth=trust --encoding=UTF8 --locale=C >/dev/null \
    || die "initdb failed"
}

running() {
  "$cache/bin/pg_ctl" -D "$data" status >/dev/null 2>&1
}

case "${1:-up}" in
  up)
    fetch
    init
    if running; then
      log "==> PostgreSQL already running on 127.0.0.1:${port}"
    else
      log "==> starting PostgreSQL on 127.0.0.1:${port}"
      # Loopback only. `--auth=trust` above is a development choice and it is
      # only defensible while nothing off this host can reach the socket.
      "$cache/bin/pg_ctl" -D "$data" -l "$data/pg.log" -w -t 30 \
        -o "-p ${port} -k ${data} -c listen_addresses=127.0.0.1" start >/dev/null \
        || { tail -20 "$data/pg.log" >&2; die "PostgreSQL did not start"; }
    fi
    log "    $(url)"
    ;;
  down)
    if running; then
      "$cache/bin/pg_ctl" -D "$data" -m fast stop >/dev/null && log "==> stopped"
    else
      log "==> not running"
    fi
    ;;
  reset)
    running && "$cache/bin/pg_ctl" -D "$data" -m immediate stop >/dev/null || true
    rm -rf "$data"
    log "==> data directory destroyed: $data"
    ;;
  url) url; echo ;;
  *) die "usage: local-postgres.sh {up|down|reset|url}" ;;
esac
