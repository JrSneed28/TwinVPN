#!/usr/bin/env bash
#
# leak-probe.sh -- the device half of the external leak oracle.
#
# ===========================================================================
# WHAT THIS IS FOR
# ===========================================================================
# A kill-switch criterion cannot be discharged by asking the platform whether it
# is blocking: a WFP filter set that was never installed, a pf anchor that was
# flushed and a NetworkExtension that died all leave the platform's own status
# API saying "protected" while packets leave. So the observation moves off the
# device entirely -- `lab/twinoracle` runs somewhere the device can only reach
# by emitting a packet that leaves it, and this script is what emits them.
#
# It makes NO judgement. It opens a session, declares phase boundaries, beacons,
# reports how many attempts it made, and closes. The verdict is computed by the
# oracle from what actually arrived, and `build/acceptance/report.py` fetches
# that verdict FROM THE ORACLE rather than from anything this script wrote --
# which is the whole reason a lying job cannot manufacture a green row.
#
# ===========================================================================
# THE POSITIVE CONTROL IS NOT OPTIONAL
# ===========================================================================
# Zero observations because the kill switch worked and zero observations because
# the oracle was unreachable are the same bytes. Three separate mechanisms keep
# those apart, and all three are needed:
#
#   * an OBSERVE phase FIRST, on all three families, so the oracle has proof it
#     could hear this device at all before any silence is credited;
#   * ATTEMPT COUNTS, reported by this script after every beacon window. A
#     SILENCE phase during which the probe made four attempts because the
#     process was starved is not evidence of blocking, and the oracle refuses it
#     as INCONCLUSIVE rather than reading it as a pass;
#   * a SENTINEL, which is NOT this device. See the block below.
#
# ===========================================================================
# THE SENTINEL, AND WHY IT IS A STANDING PROCESS RATHER THAN A CI STEP
# ===========================================================================
# The attempt count closes the "the probe stopped trying" hole. It does not
# close the "the ORACLE stopped listening" hole: an oracle that died, a listener
# that stopped binding, a data-plane route that broke mid-run all produce a
# perfect SILENCE phase from a completely unprotected device.
#
# So an independent heartbeat runs continuously: a source that is NOT the DUT
# and whose packets do not traverse the DUT's network, hitting the same three
# listeners on a fixed cadence with a `sentinel_token` distinct from every
# `probe_token`. A SILENCE phase is creditable only if every gap in the beats
# over that window is inside the oracle's `--sentinel-max-gap-ms`. Absent beats
# are NEVER read as continuity -- a family with zero beats is not continuous,
# and the oracle returns INCONCLUSIVE.
#
# IT IS NOT STARTED BY ANY CI JOB, AND THAT IS THE CORRECTION.
#
# A per-session sentinel started by the job needs a host that is not the DUT,
# and the oracle now CHECKS that rather than assuming it: an IPv4/IPv6 beat
# whose source address the device was also observed egressing from is not
# counted as continuity, and one arriving during a SILENCE phase is a FAIL. Two
# of the three lanes cannot satisfy that from inside the job --
#
#   * `ios-corellium` runs both the probe and any job-started sentinel on the
#     same ubuntu controller, so they share a source address;
#   * `macos-sysext` runs on the EC2 Mac, which IS the DUT;
#   * `windows-killswitch` looks safe (L1 host vs L2 guest) and is not, if the
#     guest's switch NATs through the L1 host -- which is the ordinary Hyper-V
#     configuration and would make every beat device-sourced.
#
# So the heartbeat is a STANDING process on a third machine, run with
# `leak-probe.sh sentinel` below against the long-lived token the oracle was
# started with (`--sentinel-token-file`). Its beats are recorded in every
# currently-open session, because "the listeners were alive" is a fact about the
# oracle rather than about any one run. The CI jobs only DECLARE where it runs,
# via TWINVPN_SENTINEL_HOST, and refuse to produce evidence without it -- the
# real enforcement is the oracle's, which reports no beats as no continuity.
#
# ===========================================================================
# PATH IDENTITY
# ===========================================================================
# "No DNS leaked" is not the claim. The claim is that the PROTECTED resolver and
# the UNPROTECTED resolver are DIFFERENT resolvers -- a run where both legs went
# out through the same box proves nothing about interception, however few packets
# arrived. So every phase declares its path with `--path`: `p` protected, `u`
# unprotected, `n` no claim; and every DNS query in that phase carries the letter
# in its name, `<seq>.<probe_token>.<path_tag>.<zone>`.
#
# The oracle NEVER trusts that letter alone -- it derives the resolver's identity
# from the source address the query actually ARRIVED from, and the letter is only
# the intent half of the comparison. A disagreement during SILENCE is a FAIL; an
# arrival from a resolver the oracle cannot map is INCONCLUSIVE, never a pass.
# Authoritative servers do not see the original client, which is exactly why the
# intent has to be carried in the name.
#
# ===========================================================================
# USAGE
# ===========================================================================
#   export TWINVPN_ORACLE_URL=https://oracle.example:8443
#   export TWINVPN_ORACLE_TOKEN=...            # control bearer, from a secret
#
#   leak-probe.sh open  --platform windows --criterion WINDOWS-WFP-KILLSWITCH
#   leak-probe.sh phase BASELINE  OBSERVE --path u
#   leak-probe.sh beacon --seconds 10
#   leak-probe.sh phase ARMED     SILENCE --path p
#   leak-probe.sh beacon --seconds 60          # must produce NOTHING at the oracle
#   leak-probe.sh phase RESTORED  OBSERVE --path p --subset-of TUNNELLED
#   leak-probe.sh beacon --seconds 10
#   leak-probe.sh close
#   leak-probe.sh report > build/ci/evidence/oracle/<session>.json
#
# State lives in build/ci/evidence/oracle/session.env so the steps above may be
# separate CI steps, or separate processes inside a disposable guest.
#
# And, on a third machine that is neither the oracle nor any DUT, forever:
#
#   leak-probe.sh sentinel --token-file /etc/twinoracle/sentinel-token \
#     --beacon-v4 http://198.51.100.7/b --beacon-v6 'http://[2001:db8::7]/b' \
#     --zone leak.oracle.twinvpn.example

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ORACLE_DIR="$REPO/build/ci/evidence/oracle"
STATE="$ORACLE_DIR/session.env"
# The CURRENT phase's path tag, in its own file rather than in $STATE: the
# phases are frequently separate processes (separate CI steps, or a PowerShell
# Direct invocation per step inside the guest), and a variable set by one of
# them is gone by the next.
PATHTAG="$ORACLE_DIR/path-tag"
mkdir -p "$ORACLE_DIR"

die() { echo "::error::leak-probe: $*" >&2; exit 1; }

need_env() {
  [ -n "${TWINVPN_ORACLE_URL:-}" ] || die "TWINVPN_ORACLE_URL is unset"
  [ -n "${TWINVPN_ORACLE_TOKEN:-}" ] || die "TWINVPN_ORACLE_TOKEN is unset"
}

# The control plane. `--fail-with-body` so a 401 or a 404 is an error AND its
# body is printed: a silent failure here would look exactly like a probe that
# ran and found nothing, which is the confusion this whole file exists to end.
ctl() {
  local method="$1" path="$2" body="${3:-}"
  local args=(-sS --fail-with-body --max-time 20
              -X "$method" -H "Authorization: Bearer $TWINVPN_ORACLE_TOKEN")
  [ -n "$body" ] && args+=(-H 'Content-Type: application/json' -d "$body")
  curl "${args[@]}" "$TWINVPN_ORACLE_URL$path"
}

load_state() {
  [ -f "$STATE" ] || die "no open session; run \`leak-probe.sh open\` first"
  # shellcheck disable=SC1090
  . "$STATE"
}

# jq is NOT assumed. This runs inside a disposable Windows guest and on an EC2
# Mac, and adding a package install to a fail-closed proof path is a way for the
# proof path to fail for reasons unrelated to the product. Python 3 is on every
# runner this repository uses, and `report.py` already requires it.
json_get() {
  python3 -c 'import json,sys; print(json.load(sys.stdin).get(sys.argv[1], ""))' "$1"
}

cmd_open() {
  need_env
  local platform="" criterion=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --platform)  platform="$2"; shift 2 ;;
      --criterion) criterion="$2"; shift 2 ;;
      *) die "open: unknown flag $1" ;;
    esac
  done
  [ -n "$platform" ] && [ -n "$criterion" ] || die "open needs --platform and --criterion"

  local commit run_id run_attempt resp
  commit="$(cd "$REPO" && git rev-parse HEAD)"
  run_id="${GITHUB_RUN_ID:-local}"
  run_attempt="${GITHUB_RUN_ATTEMPT:-1}"

  resp="$(ctl POST /v1/sessions \
    "{\"commit\":\"$commit\",\"run_id\":\"$run_id\",\"run_attempt\":\"$run_attempt\",\
\"platform\":\"$platform\",\"criterion\":\"$criterion\"}")"

  {
    echo "TWINVPN_ORACLE_SESSION=$(printf '%s' "$resp" | json_get session_id)"
    echo "TWINVPN_ORACLE_BEACON_V4=$(printf '%s' "$resp" | json_get beacon_v4)"
    echo "TWINVPN_ORACLE_BEACON_V6=$(printf '%s' "$resp" | json_get beacon_v6)"
    echo "TWINVPN_ORACLE_PROBE_TOKEN=$(printf '%s' "$resp" | json_get probe_token)"
    echo "TWINVPN_ORACLE_ZONE=$(printf '%s' "$resp" | json_get zone)"
    echo "TWINVPN_ORACLE_CRITERION=$criterion"
    echo "TWINVPN_ORACLE_COMMIT=$commit"
    echo "TWINVPN_ORACLE_RUN_ID=$run_id"
    echo "TWINVPN_ORACLE_RUN_ATTEMPT=$run_attempt"
  } > "$STATE"
  echo n > "$PATHTAG"

  # shellcheck disable=SC1090
  . "$STATE"
  [ -n "$TWINVPN_ORACLE_SESSION" ] || die "the oracle returned no session id: $resp"
  # The DNS leg is built from the token and the zone rather than from a
  # pre-joined suffix, because the path tag goes BETWEEN them
  # (`<seq>.<probe_token>.<path_tag>.<zone>`) and a suffix cannot be split back
  # apart safely once an operator's zone contains a label that looks like a
  # token. An oracle that returns neither cannot be probed for DNS at all, and
  # that must be loud here rather than silently producing zero DNS attempts.
  [ -n "$TWINVPN_ORACLE_PROBE_TOKEN" ] && [ -n "$TWINVPN_ORACLE_ZONE" ] \
    || die "the oracle returned no probe_token/zone pair, so no DNS beacon name \
can be constructed and the DNS family would silently record zero attempts: $resp"
  # THE BEACON TARGET IS NOT ALLOWED TO BE A LOOPBACK OR PRIVATE ADDRESS.
  # An oracle on the same host as the device observes nothing -- loopback egress
  # is not egress -- and a kill switch that permits it would still pass.
  case "$TWINVPN_ORACLE_BEACON_V4" in
    *//127.*|*//10.*|*//192.168.*|*//169.254.*|*//localhost*)
      die "the oracle advertises $TWINVPN_ORACLE_BEACON_V4, which is not off-device. \
Egress to it is not egress and cannot discharge a kill-switch criterion." ;;
  esac
  echo "session $TWINVPN_ORACLE_SESSION opened for $criterion on $platform (attempt $run_attempt)"
}

cmd_phase() {
  need_env; load_state
  local name="$1" expectation="$2"; shift 2
  local disjoint="null" subset="null" tag=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --disjoint-from) disjoint="\"$2\""; shift 2 ;;
      --subset-of)     subset="\"$2\"";   shift 2 ;;
      --path)          tag="$2";          shift 2 ;;
      *) die "phase: unknown flag $1" ;;
    esac
  done
  case "$expectation" in OBSERVE|SILENCE) : ;; *) die "expectation must be OBSERVE or SILENCE" ;; esac
  # `n` -- no path claim -- is the default and is a MEASUREMENT, not a gap: the
  # oracle must be able to tell "this phase asserted nothing about path
  # identity" apart from "this phase asserted protected". A missing flag must
  # never be read as either `p` or `u`.
  case "${tag:=n}" in p|u|n) : ;; *) die "--path must be p (protected), u (unprotected) or n (no claim)" ;; esac
  printf '%s\n' "$tag" > "$PATHTAG"

  # Every OBSERVE phase requires all three families. A phase that only proved
  # IPv4 could get out cannot support a claim about IPv6 or DNS being blocked,
  # and the oracle enforces that -- this is the client half saying so out loud.
  local families='[]'
  [ "$expectation" = "OBSERVE" ] && families='["ipv4","ipv6","dns"]'

  ctl POST "/v1/sessions/$TWINVPN_ORACLE_SESSION/phase" \
    "{\"phase\":\"$name\",\"expectation\":\"$expectation\",\"require_families\":$families,\
\"path_tag\":\"$tag\",\"sources_disjoint_from\":$disjoint,\"sources_subset_of\":$subset}" >/dev/null
  echo "phase $name ($expectation, path=$tag)"
}

# One DNS lookup through the SYSTEM RESOLVER. Not a hand-built UDP packet: the
# egress path a user leaks through is the OS resolver's, and a raw query to port
# 53 would test something else and pass when the real path is blocked. It is
# also the only way the oracle gets to see the RESOLVER's source address, which
# is what the path-identity check is derived from.
#
# A ladder rather than one command, because the three hosts that run this do not
# share one: git-bash on Windows has `nslookup`, macOS has `dscacheutil` and
# `nslookup`, Linux has `getent`. `python3` is the floor.
resolve_once() {
  local name="$1"
  if command -v nslookup >/dev/null 2>&1; then
    nslookup "$name" >/dev/null 2>&1 || true
  elif command -v getent >/dev/null 2>&1; then
    getent ahosts "$name" >/dev/null 2>&1 || true
  else
    python3 -c 'import socket,sys
try: socket.getaddrinfo(sys.argv[1], None)
except OSError: pass' "$name" || true
  fi
}

# THE ATTEMPT COUNTS, REPORTED BY THE DEVICE, AND WHY THEY ARE POSTED LAST.
#
# The oracle needs to know the DENOMINATOR: zero arrivals out of 120 attempts is
# a kill switch working, and zero arrivals out of 3 attempts is a probe that was
# starved by a boot storm. It cannot derive that -- by construction it sees only
# what arrived, and during a SILENCE phase that is nothing.
#
# So this is self-report, and it is safe in exactly one direction: a probe can
# under-report attempts (making the oracle stricter, and eventually
# INCONCLUSIVE) but over-reporting cannot manufacture a pass, because arrivals
# are still counted by the oracle alone. A FAILED post therefore drops the
# counts rather than retrying into a double-count: fewer attempts is the safe
# error.
post_attempts() {
  local v4="$1" v6="$2" dns="$3"
  ctl POST "/v1/sessions/$TWINVPN_ORACLE_SESSION/attempts" \
    "{\"ipv4\":$v4,\"ipv6\":$v6,\"dns\":$dns}" >/dev/null 2>&1 \
    || echo "::warning::leak-probe: the oracle would not accept the attempt \
counts for this window ($v4/$v6/$dns). They are dropped rather than retried; \
the session will look like it tried FEWER times than it did, which the oracle \
reads as INCONCLUSIVE rather than as a pass."
}

cmd_beacon() {
  need_env; load_state
  local seconds=10
  while [ $# -gt 0 ]; do
    case "$1" in
      --seconds) seconds="$2"; shift 2 ;;
      *) die "beacon: unknown flag $1" ;;
    esac
  done
  local tag="n"
  [ -f "$PATHTAG" ] && tag="$(cat "$PATHTAG")"

  local deadline=$(( $(date +%s) + seconds )) seq=0
  local n4=0 n6=0 ndns=0
  while [ "$(date +%s)" -lt "$deadline" ]; do
    seq=$((seq + 1))
    # `-4` and `-6` are the point: the family of the attempt is chosen here and
    # confirmed at the oracle by which socket accepted it, so a kill switch that
    # blocks one family and not the other is caught rather than averaged.
    #
    # EVERY ONE IS `|| true`. A blocked beacon MUST NOT fail this script: during
    # the ARMED phase failure is the expected and desired outcome, and a
    # non-zero exit there would abort the sequence before it could be closed and
    # reported. The evidence is what ARRIVED at the oracle, never this exit
    # code -- which is why swallowing the status here is not the swallowed
    # failure the CI scripts otherwise forbid.
    #
    # The counter increments on the ATTEMPT, not on success. A beacon that was
    # blocked is exactly the attempt the denominator is about.
    if [ -n "$TWINVPN_ORACLE_BEACON_V4" ]; then
      n4=$((n4 + 1))
      curl -4 -sS --max-time 3 -o /dev/null "$TWINVPN_ORACLE_BEACON_V4/$seq" 2>/dev/null || true
    fi
    if [ -n "$TWINVPN_ORACLE_BEACON_V6" ]; then
      n6=$((n6 + 1))
      curl -6 -sS --max-time 3 -o /dev/null "$TWINVPN_ORACLE_BEACON_V6/$seq" 2>/dev/null || true
    fi
    ndns=$((ndns + 1))
    resolve_once "$seq.$TWINVPN_ORACLE_PROBE_TOKEN.$tag.$TWINVPN_ORACLE_ZONE"
    sleep 1
  done
  post_attempts "$n4" "$n6" "$ndns"
  echo "beaconed for ${seconds}s (path=$tag; attempts ipv4=$n4 ipv6=$n6 dns=$ndns)"
}

# ---------------------------------------------------------------------------
# THE SENTINEL -- a standing process, run on a machine that is not any DUT
# ---------------------------------------------------------------------------
#
# FOREGROUND, and no session. It is a systemd unit or a container entrypoint on
# a third machine, not a CI step: see the header for why a job-started sentinel
# cannot satisfy the oracle's independence check in any of the three lanes. It
# needs no control-plane credential, only the long-lived token the oracle was
# started with (`--sentinel-token-file`), so the machine running it holds
# nothing that could open, close or read a session.
#
# The token comes from a FILE, never a flag: a token on a command line is in
# every `ps` listing on the host.
cmd_sentinel() {
  local token_file="" v4="" v6="" zone="" interval_ms=2000 token nap seq=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --token-file)  token_file="$2"; shift 2 ;;
      --beacon-v4)   v4="$2";         shift 2 ;;
      --beacon-v6)   v6="$2";         shift 2 ;;
      --zone)        zone="$2";       shift 2 ;;
      --interval-ms) interval_ms="$2"; shift 2 ;;
      *) die "sentinel: unknown flag $1" ;;
    esac
  done
  [ -n "$token_file" ] && [ -n "$zone" ] \
    || die "sentinel needs --token-file and --zone (and at least one of \
--beacon-v4 / --beacon-v6). All four come from the oracle's own configuration; \
the sentinel is part of the deployment, not of a run."
  [ -f "$token_file" ] || die "no sentinel token at $token_file"
  token="$(tr -d ' \t\r\n' < "$token_file")"
  [ -n "$v4" ] || [ -n "$v6" ] || die "sentinel needs at least one beacon URL"

  # THE GUARD. A sentinel on the device under test proves the DUT can reach the
  # oracle, which is the one thing a SILENCE phase asserts is impossible. The
  # disposable Windows guest marks itself, so that case is refused outright; for
  # the rest, placement is the operator's decision and the oracle now CHECKS it
  # -- a beat from an address the device was seen egressing from is discarded as
  # continuity and reported as a FAIL inside SILENCE.
  [ "${TWINVPN_DISPOSABLE_GUEST:-}" != "1" ] \
    || die "this is the disposable guest, which is the DEVICE UNDER TEST"

  # `sleep` takes fractional seconds on every shell this runs under. Computed
  # once rather than per beat, so a slow arithmetic expansion cannot stretch the
  # cadence past the oracle's sentinel_max_gap_ms and report a gap the network
  # never had.
  nap="$(python3 -c 'import sys; print(int(sys.argv[1])/1000.0)' "$interval_ms")"
  echo "sentinel beating every ${interval_ms}ms into $zone (ctrl-c to stop)"
  while :; do
    seq=$((seq + 1))
    [ -n "$v4" ] && curl -4 -sS --max-time 3 -o /dev/null "$v4/$token/$seq" 2>/dev/null || true
    [ -n "$v6" ] && curl -6 -sS --max-time 3 -o /dev/null "$v6/$token/$seq" 2>/dev/null || true
    # NO PATH TAG. `dns::beacon_labels` treats the last label before the zone as
    # a path tag only when it is `p` or `u`; any other letter is not stripped, so
    # it becomes the TOKEN and the real token becomes part of the sequence. A
    # `.s` label here would make every DNS beat unmatchable -- reported as a dead
    # sentinel that was in fact alive, and every session INCONCLUSIVE. The token
    # alone already says which index a beat belongs to, and a sentinel has no
    # path to declare.
    resolve_once "$seq.$token.$zone"
    sleep "$nap"
  done
}

cmd_close() {
  need_env; load_state
  ctl POST "/v1/sessions/$TWINVPN_ORACLE_SESSION/close" >/dev/null
  echo "session $TWINVPN_ORACLE_SESSION closed"
}

cmd_report() {
  need_env; load_state
  ctl GET "/v1/sessions/$TWINVPN_ORACLE_SESSION/report"
}

cmd_session_id() { load_state; printf '%s\n' "$TWINVPN_ORACLE_SESSION"; }

case "${1:-}" in
  open)       shift; cmd_open "$@" ;;
  phase)      shift; cmd_phase "$@" ;;
  beacon)     shift; cmd_beacon "$@" ;;
  sentinel)   shift; cmd_sentinel "$@" ;;
  close)      shift; cmd_close ;;
  report)     shift; cmd_report ;;
  session-id) shift; cmd_session_id ;;
  *)
    echo "usage: leak-probe.sh {open|phase|beacon|sentinel|close|report|session-id} ..." >&2
    exit 2 ;;
esac
