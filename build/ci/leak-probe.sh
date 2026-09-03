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
# THE SENTINEL
# ===========================================================================
# Independence is SOURCE-ADDRESS DISJOINTNESS and the oracle checks it, which
# admits a standing process on a third machine and an in-box fabric with
# disjoint addresses, and nothing else. The reasoning, both deployments, the
# residual weakness of the in-box one and `cmd_sentinel` itself all live in
# build/ci/leak-probe-sentinel.sh, sourced below.
#
# ===========================================================================
# WHO HOLDS THE CONTROL TOKEN -- THE CONTROLLER, NEVER THE DEVICE
# ===========================================================================
# A CORRECT kill switch blocks every packet the device originates while armed,
# and the control plane is reached by a packet. A device that posts its own
# phase boundaries and attempt counts therefore loses exactly the ARMED
# window's posts, the session looks like it tried FEWER times than it did, and
# the oracle reads that shortfall as INCONCLUSIVE: the evidence destroyed by
# the product working. `TWINVPN_ORACLE_CONTROL_BY=controller` splits them --
#
#   CONTROLLER (holds TWINVPN_ORACLE_TOKEN):  open, phase, attempts, close,
#                                             report, sentinel, sentinel-claim
#   DEVICE     (holds no control credential): beacon --counts-file
#
# -- so the device writes its counts to a file the controller reads back over a
# management channel and posts. `probe_host` stays `device` because every
# beacon still leaves the device; what moved is the bookkeeping, not the
# egress. Ambiguous combinations are fatal, not half-applied: see `cmd_beacon`.
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
# Split across a controller and a device (build/ci/ci-windows-killswitch.sh):
# the controller exports TWINVPN_ORACLE_CONTROL_BY=controller and runs `open`,
# `phase`, `attempts --from-file`, `close` and `report`; the device runs only
# `beacon --seconds N --counts-file <path>` and hands the file back.
#
# State lives in build/ci/evidence/oracle/session.env so the steps above may be
# separate CI steps, or separate processes inside a disposable guest.
#
# And, on a third machine that is neither the oracle nor any DUT, forever:
#
#   leak-probe.sh sentinel --token-file /etc/twinoracle/sentinel-token \
#     --beacon-v4 http://198.51.100.7/b --beacon-v6 'http://[2001:db8::7]/b' \
#     --zone leak.oracle.twinvpn.example
#
# `leak-probe.sh --self-check` runs the beacon-target rule against fabricated
# hosts and the mode refusals against this script itself. It needs no oracle.

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

# `twinvpn_python`, because the interpreter is called `python.exe` on a hosted
# Windows runner and `python3` on every other host this runs on. One definition,
# beside the other shared shell helpers.
# shellcheck disable=SC1091
. "$REPO/build/ci/digest.sh"

# THE TWO CHECKED RULES: is the beacon target off the device, and are these
# attempt counts something the device under test wrote that we may trust. Both
# have a security consequence and both have a self-check.
# shellcheck disable=SC1091
. "$REPO/build/ci/leak-probe-rules.sh"
# The sentinel half: `cmd_sentinel`, `cmd_sentinel_claim`, and the argument for
# why a heartbeat that is not independent is worse than no heartbeat.
# shellcheck disable=SC1091
. "$REPO/build/ci/leak-probe-sentinel.sh"

# Which half of the split this process is. `controller` means the control token
# lives here and the beacons happen on another machine; anything else means the
# legacy shape, where one process does both.
control_by() { printf '%s' "${TWINVPN_ORACLE_CONTROL_BY:-probe}"; }

assert_known_mode() {
  case "$(control_by)" in
    probe|controller) : ;;
    *) die "TWINVPN_ORACLE_CONTROL_BY is '$(control_by)'; it must be \
'controller' (this process holds the control token and something else beacons) \
or unset/'probe' (this process does both). An unrecognised value would silently \
pick one of them." ;;
  esac
}

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

# jq is NOT assumed. This runs on a CI controller, inside a disposable Windows
# guest and on an EC2 Mac, and adding a package install to a fail-closed proof
# path is a way for the proof path to fail for reasons unrelated to the product.
# Python 3 is on every host this repository uses, under one of two names --
# `twinvpn_python` is the ladder.
json_get() {
  twinvpn_python -c 'import json,sys; print(json.load(sys.stdin).get(sys.argv[1], ""))' "$1"
}

cmd_open() {
  assert_known_mode; need_env
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
  # THE BEACON TARGET, ON BOTH FAMILIES. See build/ci/leak-probe-target.sh for
  # the rule and for why it is no longer a private-address blocklist.
  #
  # Rule 3 -- "an address this host owns" -- is checked HERE only when this
  # process is also the one that beacons. In controller mode the controller
  # legitimately owns the oracle's addresses, and checking them here would
  # refuse the correct topology while telling us nothing about the device; the
  # device applies rule 3 itself, in `cmd_beacon`.
  local own=""
  if [ "$(control_by)" != "controller" ]; then
    own="$(host_addresses)" || die "this host's own addresses cannot be \
enumerated, so the beacon target cannot be checked against them. That check is \
the one that survives a topology change and it must not be skipped."
  fi
  local problem
  problem="$(beacon_target_problem "the oracle's IPv4 beacon" "$TWINVPN_ORACLE_BEACON_V4" "$own")"
  [ -z "$problem" ] || die "$problem."
  problem="$(beacon_target_problem "the oracle's IPv6 beacon" "$TWINVPN_ORACLE_BEACON_V6" "$own")"
  [ -z "$problem" ] || die "$problem."
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
# The optional second argument names the server to ask, and exists for the
# SENTINEL alone: a heartbeat host whose system resolver knows nothing about the
# beacon zone emits DNS beats that never arrive, which the oracle reports as no
# DNS continuity -- a fact about the heartbeat host, read as one about the
# device. It is deliberately NOT offered to `cmd_beacon`: the DEVICE must
# resolve the way a user does, through whatever resolver its own stack chose,
# because that is the path a leak takes.
resolve_once() {
  local name="$1" server="${2:-}"
  if [ -n "$server" ]; then
    command -v nslookup >/dev/null 2>&1 || die "a resolver was named \
($server) and this host has no nslookup to send the query with. Falling back to \
the system resolver would silently ask a different server and report a gap the \
network never had."
    nslookup "-timeout=${TWINVPN_PROBE_TIMEOUT_S:-3}" -retry=1 "$name" "$server" >/dev/null 2>&1 || true
    return 0
  fi
  if command -v nslookup >/dev/null 2>&1; then
    # `-timeout`/`-retry` are accepted by both Windows nslookup and BIND's.
    # The default matches curl's --max-time below; a lab whose every hop is
    # local sets TWINVPN_PROBE_TIMEOUT_S lower so a blocked window still
    # produces the attempt counts the oracle's floor needs.
    nslookup "-timeout=${TWINVPN_PROBE_TIMEOUT_S:-3}" -retry=1 "$name" >/dev/null 2>&1 || true
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
  assert_known_mode
  local seconds=10 counts_file=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --seconds)     seconds="$2";     shift 2 ;;
      --counts-file) counts_file="$2"; shift 2 ;;
      *) die "beacon: unknown flag $1" ;;
    esac
  done

  # THE TWO HALVES MUST AGREE, AND A DISAGREEMENT IS FATAL RATHER THAN GUESSED.
  # Posting from a device the kill switch is about to block loses the ARMED
  # window's counts; writing a file nobody reads loses them just as completely
  # and does it silently.
  if [ "$(control_by)" = "controller" ]; then
    [ -n "$counts_file" ] || die "TWINVPN_ORACLE_CONTROL_BY=controller says the \
control token is not on this machine, so this beacon cannot post its attempt \
counts. Pass --counts-file <path> and have the controller post the file with \
\`leak-probe.sh attempts --from-file\`."
  else
    [ -z "$counts_file" ] || die "--counts-file was given but \
TWINVPN_ORACLE_CONTROL_BY is not 'controller', so nothing would ever post the \
file and this window's attempts would vanish. Set it, or drop the flag."
    need_env
  fi
  load_state

  # RULE 3, HERE, BECAUSE THIS IS THE ONE COMMAND THAT ONLY EVER RUNS ON THE
  # DEVICE. A beacon aimed at an address this machine holds never leaves it.
  local own problem
  own="$(host_addresses)" || die "this device's own addresses cannot be \
enumerated, so the beacon target cannot be checked against them."
  for problem in "$(beacon_target_problem "the IPv4 beacon" "$TWINVPN_ORACLE_BEACON_V4" "$own")" \
                 "$(beacon_target_problem "the IPv6 beacon" "$TWINVPN_ORACLE_BEACON_V6" "$own")"; do
    [ -z "$problem" ] || die "$problem."
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
      curl -4 -sS --max-time "${TWINVPN_PROBE_TIMEOUT_S:-3}" -o /dev/null "$TWINVPN_ORACLE_BEACON_V4/$seq" 2>/dev/null || true
    fi
    if [ -n "$TWINVPN_ORACLE_BEACON_V6" ]; then
      n6=$((n6 + 1))
      curl -6 -sS --max-time "${TWINVPN_PROBE_TIMEOUT_S:-3}" -o /dev/null "$TWINVPN_ORACLE_BEACON_V6/$seq" 2>/dev/null || true
    fi
    ndns=$((ndns + 1))
    resolve_once "$seq.$TWINVPN_ORACLE_PROBE_TOKEN.$tag.$TWINVPN_ORACLE_ZONE"
    sleep 1
  done
  if [ -n "$counts_file" ]; then
    # A FILE, not a post. The controller reads it back over the management
    # channel -- PowerShell Direct in the Windows lane -- which is exactly the
    # channel the kill switch cannot touch.
    printf 'ipv4=%s\nipv6=%s\ndns=%s\n' "$n4" "$n6" "$ndns" > "$counts_file"
  else
    post_attempts "$n4" "$n6" "$ndns"
  fi
  echo "beaconed for ${seconds}s (path=$tag; attempts ipv4=$n4 ipv6=$n6 dns=$ndns)"
}

# The controller half of the split: post counts the DEVICE measured.
#
# THE FILE CROSSES A TRUST BOUNDARY. It was written on the device under test,
# which is the machine whose honesty the whole criterion is about, so it is
# parsed rather than sourced and every field must be a plain non-negative
# integer. Over-reporting cannot manufacture a pass -- arrivals are still
# counted by the oracle alone -- but a shell-injectable file would be a way to
# run the device's text on the controller.
cmd_attempts() {
  need_env; load_state
  local file="" counts
  while [ $# -gt 0 ]; do
    case "$1" in
      --from-file) file="$2"; shift 2 ;;
      *) die "attempts: unknown flag $1" ;;
    esac
  done
  [ -n "$file" ] || die "attempts needs --from-file <path>"
  [ -f "$file" ] || die "no attempt counts at $file. The device's beacon window \
either never ran or never wrote them, and posting nothing is safer than posting \
a guess -- the oracle reads a shortfall as INCONCLUSIVE."
  counts="$(attempt_counts_from_file "$file")" \
    || die "$file does not carry three non-negative integers as ipv4=/ipv6=/dns=. \
It came from the device under test and is not trusted enough to be sourced."
  # shellcheck disable=SC2086
  post_attempts $counts
  echo "posted attempts from the device ($counts)"
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
  open)           shift; cmd_open "$@" ;;
  phase)          shift; cmd_phase "$@" ;;
  beacon)         shift; cmd_beacon "$@" ;;
  attempts)       shift; cmd_attempts "$@" ;;
  sentinel)       shift; cmd_sentinel "$@" ;;
  sentinel-claim) shift; cmd_sentinel_claim "$@" ;;
  close)          shift; cmd_close ;;
  report)         shift; cmd_report ;;
  session-id)     shift; cmd_session_id ;;
  # No oracle, no session, no network: the refusals that must never silently
  # pass, driven against fabricated hosts and against this script itself.
  --self-check)
    ok=0
    leak_probe_target_self_check || ok=1
    leak_probe_mode_self_check   || ok=1
    leak_probe_sentinel_self_check || ok=1
    [ "$ok" -eq 0 ] && echo "leak-probe self-check passed"
    exit "$ok" ;;
  *)
    echo "usage: leak-probe.sh {open|phase|beacon|attempts|sentinel|sentinel-claim|close|report|session-id|--self-check} ..." >&2
    exit 2 ;;
esac
