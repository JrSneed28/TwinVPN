#!/usr/bin/env bash
# Bring up a local multi-node TwinVPN data plane WITHOUT a container runtime.
#
# ===========================================================================
# WHY THIS EXISTS ALONGSIDE docker-compose.yml
# ===========================================================================
# `docker compose up` is the full environment: seven services, Postgres, and
# the whole observability stack. It needs Docker.
#
# This script is the subset that needs nothing but a Rust toolchain: two
# relays, two simulated devices, and the development credentials that make
# them reach each other. It exists because the thing most worth reproducing —
# a real `Noise_IK` leg carrying a real COSE_Sign1 token, a real `pair_tag`
# rendezvous, and real `DATA` forwarding between two peers — needs no
# container at all, and making it depend on one would mean nobody could run it
# on a host without Docker.
#
# It is also what found the defect in `services/relay/src/main.rs` that made
# the relay refuse every legitimate token (see that file's clock comment). The
# in-crate integration tests could not find it, because they inject a
# wall-clock constant and so never exercise the clock the binary actually runs
# with. A process started by this script does.
#
# ===========================================================================
# NOTHING HERE IS A PRODUCTION CREDENTIAL PATH
# ===========================================================================
# The issuer seed is generated per machine from OS entropy into
# infra/secrets/, which infra/secrets/.gitignore covers and
# build/verify/check-compose.py asks git itself to confirm is unreachable. The
# signer is `twinvpn_crypto::testkit`, behind the never-shipped `test-support`
# feature. No password, no database and no network egress is involved.
#
# Usage:
#   infra/scripts/local-plane.sh up [--v6]   start relays and peers
#   infra/scripts/local-plane.sh probe       one-shot: exit 0 iff a leg binds
#   infra/scripts/local-plane.sh ceremony    one-shot: exit 0 iff a device ATTACHES
#   infra/scripts/local-plane.sh status      what is running, and its metrics
#   infra/scripts/local-plane.sh down        stop everything this script started
#
# `up` starts the DATA plane (relays + simulated peers). `ceremony` additionally
# starts PostgreSQL and the CONTROL plane, because an L-CONTROL attach needs
# both and neither is needed to forward a relay frame. Keeping them apart is why
# `probe` still runs on a host with no database at all.

set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo"

run_dir="${TWINVPN_LOCAL_PLANE_DIR:-${TMPDIR:-/tmp}/twinvpn-local-plane}"
secrets="$repo/infra/secrets"
issuer_dir="$secrets/dev-issuer"
seed="$issuer_dir/seed.bin"

# ---------------------------------------------------------------------------
# Ports. Deliberately high and deliberately NOT the product's own numbers.
#
# ADR-0005 §9.1 puts R-UDP on 41641 and the 443 carriages on 443; 443 needs
# privilege, and a script that asked for it would either need root or fail on
# every developer machine. So every listener here is offset into the ephemeral
# range and the relay is told so explicitly. The consequence is stated rather
# than hidden: THIS SCRIPT DOES NOT EXERCISE THE 443 CARRIAGES. `docker
# compose` does, because a container has its own port namespace.
# ---------------------------------------------------------------------------
#
# Every number below is overridable from the environment, because a port is a
# property of the HOST and not of the design: 41641 is also Tailscale's default,
# and on a machine already running one -- or on WSL2, where a Windows-side
# listener occupies the same number -- the relay's first bind fails EADDRINUSE
# with nothing visible holding it. Overriding beats editing the script.
V4_HOST=${V4_HOST:-127.0.0.1}
V6_HOST=${V6_HOST:-'[::1]'}
RELAY_A_UDP=${RELAY_A_UDP:-41641}
RELAY_B_UDP=${RELAY_B_UDP:-41642}
RELAY_A_ADMIN=${RELAY_A_ADMIN:-19090}
RELAY_B_ADMIN=${RELAY_B_ADMIN:-19091}
ALICE_ADMIN=${ALICE_ADMIN:-19190}
BOB_ADMIN=${BOB_ADMIN:-19191}
CP_QUIC=${CP_QUIC:-14430}
CP_TCP=${CP_TCP:-14431}
CP_ADMIN=${CP_ADMIN:-19095}

family=v4
host=$V4_HOST
local_bind='127.0.0.1:0'

# ---------------------------------------------------------------------------
# The two relay identities.
#
# TWO relays in TWO failure domains, never one. ADR-0006 §11.1 rule 3 requires
# at least two alternates across at least two failure domains, and
# architecture.md §2.12 calls a set of size one a design error. `twinsim map
# init` refuses to write a map below that floor, so a one-relay shortcut here
# would not merely be unrealistic, it would not start.
#
# The ids are 16 hex characters because contracts/registry/limits.json puts
# `relay_id_bytes` at 8. A 32-character id -- the width `pair_tag` and `jti`
# use -- fails the relay at startup with `RelayIdWidth(8)`.
# ---------------------------------------------------------------------------
RELAY_A_ID=aaaaaaaaaaaaaaaa
RELAY_B_ID=bbbbbbbbbbbbbbbb

log() { printf '%s\n' "$*"; }
die() { printf '!! %s\n' "$*" >&2; exit 1; }

cargo_bin() {
  # The toolchain env is sourced rather than assumed: `make bootstrap` writes
  # it, and a developer who has not run that gets a readable message instead of
  # "cargo: command not found" from three levels down.
  # shellcheck disable=SC1091
  [ -f build/toolchain/env.sh ] && . build/toolchain/env.sh >/dev/null 2>&1
  command -v cargo >/dev/null 2>&1 || die "cargo is not on PATH; run 'make toolchains' first"
}

# Where a workspace's binaries land. Cargo honours CARGO_TARGET_DIR, which
# redirects every workspace's artifacts into one shared directory and leaves the
# per-workspace `target/` absent -- so the path is asked for, never assumed.
bin_dir() { echo "${CARGO_TARGET_DIR:-$repo/$1/target}/debug"; }

build() {
  cargo_bin
  log "==> building the relay and the simulator"
  ( cd services && cargo build --quiet -p twinvpn-relay )
  ( cd lab && cargo build --quiet -p twinsim )
}

sim() { "$(bin_dir lab)/twinsim" "$@"; }

# ---------------------------------------------------------------------------
# Process control by PID FILE, never by name.
#
# `pkill -f twinvpn-relay` is the obvious spelling and it is wrong: the pattern
# matches the shell whose own command line contains the string, so it kills the
# caller. That is not hypothetical -- it happened while this script was being
# written, twice.
# ---------------------------------------------------------------------------
start() {
  local name=$1; shift
  mkdir -p "$run_dir"
  nohup "$@" > "$run_dir/$name.log" 2>&1 &
  echo $! > "$run_dir/$name.pid"
  log "    $name: pid $(cat "$run_dir/$name.pid")  log $run_dir/$name.log"
}

stop_one() {
  local name=$1
  local pidfile="$run_dir/$name.pid"
  [ -f "$pidfile" ] || return 0
  local pid; pid=$(cat "$pidfile")
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    log "    stopped $name (pid $pid)"
  fi
  rm -f "$pidfile"
}

wait_ready() {
  # Polls the service's OWN readiness endpoint, not a TCP connect. A socket
  # that accepts is not a service that can serve, and `ownership.md` rule 4
  # makes the two different questions on purpose.
  local url=$1 name=$2 tries=${3:-40}
  for _ in $(seq "$tries"); do
    if curl -fsS -o /dev/null --max-time 1 "$url" 2>/dev/null; then
      log "    $name ready"
      return 0
    fi
    sleep 0.25
  done
  log "!!  $name never became ready; see $run_dir/$name.log"
  return 1
}

start_relay() {
  local name=$1 id=$2 domain=$3 udp=$4 admin=$5
  # Every carriage gets an explicit unprivileged port. The relay binds each
  # configured listener whether or not the carriage is in TWINVPN_RELAY_CARRIAGES,
  # so leaving the 443 defaults in place fails with EACCES for an unprivileged
  # process -- which reads as "the relay is broken" rather than "port 443 needs
  # root".
  TWINVPN_RELAY_ID="$id" \
  TWINVPN_RELAY_REGION=local \
  TWINVPN_RELAY_FAILURE_DOMAIN="$domain" \
  TWINVPN_RELAY_OPERATOR_GROUP_ID=local-operator \
  TWINVPN_RELAY_ISSUER_KEYS_PATH="$secrets/$name/issuer-keys.json" \
  TWINVPN_RELAY_STATIC_KEY_PATH="$secrets/$name/static-noise.key" \
  TWINVPN_RELAY_CARRIAGES=R-UDP \
  TWINVPN_RELAY_LISTEN_UDP="$host:$udp" \
  TWINVPN_RELAY_LISTEN_UDP_443="$host:$((udp + 1000))" \
  TWINVPN_RELAY_LISTEN_QUIC="$host:$((udp + 2000))" \
  TWINVPN_RELAY_LISTEN_TLS="$host:$((udp + 3000))" \
  TWINVPN_ADMIN_ADDR="$host:$admin" \
  TWINVPN_SERVICE_NAME=relay \
  TWINVPN_LIMITS_PATH="$repo/contracts/registry/limits.json" \
  TWINVPN_REASON_CODES_PATH="$repo/contracts/registry/reason_codes.json" \
  start "$name" "$(bin_dir services)/twinvpn-relay"
}

start_peer() {
  local name=$1 admin=$2 pairs=${3:-1}
  start "$name" "$(bin_dir lab)/twinsim" peer \
    --relay-id "$RELAY_A_ID" \
    --map "$issuer_dir/relay-map.json" \
    --seed "$seed" \
    --local "$local_bind" \
    --peer-seed "$name" \
    --pair-secret local-pair \
    --pairs "$pairs" \
    --admin "$host:$admin"
}

credentials() {
  log "==> development credentials"
  # Idempotent: an existing seed is reused. Rotating it would invalidate every
  # token a running relay is holding, and the symptom -- binds refused for no
  # visible reason -- is the hardest one in this system to diagnose.
  sim issuer init \
    --seed "$seed" \
    --relay-secrets "$secrets/relay-a" \
    --relay-secrets "$secrets/relay-b" \
    --operator-group local-operator

  sim map init \
    --out "$issuer_dir/relay-map.json" \
    --operator-group local-operator \
    --relay "$RELAY_A_ID=$host:$RELAY_A_UDP=local=domain-a=$secrets/relay-a/static-noise.key" \
    --relay "$RELAY_B_ID=$host:$RELAY_B_UDP=local=domain-b=$secrets/relay-b/static-noise.key"
}

cmd_up() {
  bash "$repo/infra/scripts/bootstrap-local.sh" >/dev/null
  build
  credentials
  log "==> relays"
  start_relay relay-a "$RELAY_A_ID" domain-a "$RELAY_A_UDP" "$RELAY_A_ADMIN"
  start_relay relay-b "$RELAY_B_ID" domain-b "$RELAY_B_UDP" "$RELAY_B_ADMIN"
  wait_ready "http://$host:$RELAY_A_ADMIN/readyz" relay-a
  wait_ready "http://$host:$RELAY_B_ADMIN/readyz" relay-b
  log "==> simulated peers"
  start_peer alice "$ALICE_ADMIN"
  start_peer bob   "$BOB_ADMIN"
  wait_ready "http://$host:$ALICE_ADMIN/readyz" alice
  wait_ready "http://$host:$BOB_ADMIN/readyz" bob
  log
  log "    the plane is up on $family. 'local-plane.sh status' for metrics,"
  log "    'local-plane.sh down' to stop it."
}

cmd_probe() {
  bash "$repo/infra/scripts/bootstrap-local.sh" >/dev/null
  build
  credentials
  start_relay relay-a "$RELAY_A_ID" domain-a "$RELAY_A_UDP" "$RELAY_A_ADMIN"
  # A trap, so a probe that fails still stops the relay it started. Without it
  # a failed CI lane leaves a listener behind and the NEXT run's BIND is
  # refused as a duplicate on a still-bound tag.
  trap 'stop_one relay-a' EXIT
  wait_ready "http://$host:$RELAY_A_ADMIN/readyz" relay-a
  log "==> probe"
  sim probe \
    --relay-id "$RELAY_A_ID" \
    --map "$issuer_dir/relay-map.json" \
    --seed "$seed" \
    --local "$local_bind" \
    --peer-seed probe \
    --pair-secret local-pair
}

# ---------------------------------------------------------------------------
# The CONTROL plane. Needs a database; the data plane does not.
#
# ADR-0002 B-3 makes the durable event log a TABLE in the same transactional
# store as control-plane state, so there is no "run it without persistence"
# mode to reach for and none is invented here. `local-postgres.sh` supplies a
# real PostgreSQL as an unprivileged user instead.
# ---------------------------------------------------------------------------
cp_env() {
  local secrets_cp="$repo/infra/secrets/control-plane"
  CP_ENV=(
    "TWINVPN_CP_DATABASE_URL=$(bash "$repo/infra/scripts/local-postgres.sh" url)"
    "TWINVPN_CP_LISTEN_QUIC=$host:$CP_QUIC"
    "TWINVPN_CP_LISTEN_TCP=$host:$CP_TCP"
    "TWINVPN_CP_TLS_CERT_PATH=$secrets_cp/tls.crt"
    "TWINVPN_CP_TLS_KEY_PATH=$secrets_cp/tls.key"
    "TWINVPN_CP_OWNER_ANCHOR_PATH=$secrets_cp/owner-anchors.hex"
    "TWINVPN_ADMIN_ADDR=$host:$CP_ADMIN"
    "TWINVPN_SERVICE_NAME=control-plane"
    "TWINVPN_LIMITS_PATH=$repo/contracts/registry/limits.json"
    "TWINVPN_REASON_CODES_PATH=$repo/contracts/registry/reason_codes.json"
  )
}

start_control_plane() {
  cp_env
  # The schema is migrated by a SEPARATE, deliberate act and never by the
  # serving process: `services/control-plane/src/main.rs` explains that a
  # service which migrated on boot would mutate a schema from every replica at
  # once with no operator present. `migrate` is idempotent and safe to re-run.
  env "${CP_ENV[@]}" "$(bin_dir services)/twinvpn-control-plane" migrate     || die "the control-plane schema could not be migrated"
  # Exported rather than passed through `env`, because `start` is a shell
  # function and `env` can only invoke a program. The subshell keeps them off
  # every later command in this script.
  (
    for kv in "${CP_ENV[@]}"; do export "${kv?}"; done
    start control-plane "$(bin_dir services)/twinvpn-control-plane"
  )
}

cmd_ceremony() {
  bash "$repo/infra/scripts/bootstrap-local.sh" >/dev/null
  cargo_bin
  log "==> building the control plane and the simulator"
  ( cd services && cargo build --quiet -p twinvpn-control-plane )
  ( cd lab && cargo build --quiet -p twinsim )

  bash "$repo/infra/scripts/local-postgres.sh" up
  log "==> control plane"
  start_control_plane
  trap 'stop_one control-plane' EXIT
  wait_ready "http://$host:$CP_ADMIN/readyz" control-plane

  log "==> L-CONTROL ceremony"
  # `--local` follows the family this run was asked for, so the v6 profile
  # attaches over IPv6 and the v4 profile over IPv4 — the same single value that
  # decides which family a relay leg runs on.
  sim ceremony \
    --cp "$host:$CP_QUIC" \
    --local "$local_bind" \
    --device-seed "twinsim-device-1"
}

cmd_status() {
  for n in relay-a relay-b alice bob control-plane; do
    local pidfile="$run_dir/$n.pid"
    if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
      log "$n: running (pid $(cat "$pidfile"))"
    else
      log "$n: not running"
    fi
  done
  log
  for p in "$ALICE_ADMIN" "$BOB_ADMIN"; do
    log "--- http://$host:$p/metrics ---"
    curl -fsS --max-time 2 "http://$host:$p/metrics" 2>/dev/null \
      | grep -v '^#' | grep -v ' 0$' || log "    (unreachable)"
  done
}

cmd_down() {
  log "==> stopping"
  for n in alice bob relay-a relay-b control-plane; do stop_one "$n"; done
  # PostgreSQL is left running on purpose: `up` never started it, and stopping a
  # database this invocation did not start would be a surprise. `local-postgres.sh
  # down` is its own act.
}

action="${1:-}"; shift || true
for arg in "$@"; do
  case "$arg" in
    --v6) family=v6; host=$V6_HOST; local_bind='[::]:0' ;;
    --v4) family=v4; host=$V4_HOST; local_bind='127.0.0.1:0' ;;
    *) die "unknown option $arg" ;;
  esac
done

case "$action" in
  up)       cmd_up ;;
  probe)    cmd_probe ;;
  ceremony) cmd_ceremony ;;
  status) cmd_status ;;
  down)   cmd_down ;;
  *) die "usage: local-plane.sh {up|probe|ceremony|status|down} [--v4|--v6]" ;;
esac
