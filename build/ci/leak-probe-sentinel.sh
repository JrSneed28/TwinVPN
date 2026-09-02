#!/usr/bin/env bash
#
# leak-probe-sentinel.sh -- the heartbeat that makes a SILENCE phase creditable.
#
# Sourced by build/ci/leak-probe.sh; it is not run directly.
#
# ===========================================================================
# WHAT INDEPENDENCE ACTUALLY MEANS
# ===========================================================================
# The attempt count closes the "the probe stopped trying" hole. It does not
# close the "the ORACLE stopped listening" hole: an oracle that died, a listener
# that stopped binding, a data-plane route that broke mid-run all produce a
# perfect SILENCE phase from a completely unprotected device.
#
# So an independent heartbeat runs continuously: a source that is NOT the DUT,
# hitting the same three listeners on a fixed cadence with a `sentinel_token`
# distinct from every `probe_token`. A SILENCE phase is creditable only if every
# gap in the beats over that window is inside the oracle's
# `--sentinel-max-gap-ms`. Absent beats are NEVER read as continuity -- a family
# with zero beats is not continuous, and the oracle returns INCONCLUSIVE.
#
# INDEPENDENCE IS SOURCE-ADDRESS DISJOINTNESS, AND THE ORACLE CHECKS IT. An
# IPv4/IPv6 beat whose source address the device was also observed egressing
# from is not counted as continuity, and one arriving during a SILENCE phase is
# a FAIL. That admits exactly two deployments, and no others:
#
#   * A STANDING process on a third machine, beating the long-lived token the
#     oracle was started with (`--sentinel-token-file`). The CI jobs only
#     DECLARE where it runs, via TWINVPN_SENTINEL_HOST. This is what an
#     internet-facing oracle uses, and it is why `ios-corellium` (probe and
#     sentinel would share the controller's address) and `macos-sysext` (the
#     runner IS the DUT) cannot start their own.
#   * An IN-BOX fabric where disjointness holds BY CONSTRUCTION rather than by
#     luck: the device presents its own link's address, and the sentinel
#     presents an address on a segment the device neither owns nor reaches
#     on-link. `--source` is what makes that honest -- it pins the address the
#     beats present with `curl --interface`, prints it, and the lane records it
#     as `sentinel_egress_identity` so the claim is checkable downstream
#     instead of asserted.
#
# The residual weakness of an in-box sentinel, stated rather than hidden: it
# catches an oracle that died and a listener that stopped binding completely,
# because a beat only succeeds if the listener is bound and accepting. It cannot
# catch a broken data-plane route between the sentinel and the oracle, because
# on one host there is no such route to break.
#
# The DUT guard in `cmd_sentinel` is unchanged and is not negotiable: a sentinel
# inside the disposable guest would prove the DUT can reach the oracle, which is
# the one thing a SILENCE phase asserts is impossible.
#

# Record WHERE the sentinel runs, on the session. The response carries the
# session's own sentinel token and is deliberately discarded: this deployment
# beats the oracle's STANDING token, and printing a second one would put a
# credential in a CI log for no reason.
cmd_sentinel_claim() {
  need_env; load_state
  local host=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --host) host="$2"; shift 2 ;;
      *) die "sentinel-claim: unknown flag $1" ;;
    esac
  done
  [ -n "$host" ] || die "sentinel-claim needs --host <identity>"
  ctl POST "/v1/sessions/$TWINVPN_ORACLE_SESSION/sentinel" \
    "{\"host\":\"$host\"}" >/dev/null
  echo "sentinel host recorded on the session: $host"
}

# ---------------------------------------------------------------------------
# THE SENTINEL -- a standing process, run on a machine that is not any DUT
# ---------------------------------------------------------------------------
#
# FOREGROUND, and no session. On an internet-facing deployment it is a systemd
# unit or a container entrypoint on a third machine; on an in-box fabric it is
# started by the lane's controller before the first phase and stopped after
# `close`, with `--source` pinning the address its beats present. Either way it
# needs no control-plane credential, only the long-lived token the oracle was
# started with (`--sentinel-token-file`), so the process holds nothing that
# could open, close or read a session.
#
# The token comes from a FILE, never a flag: a token on a command line is in
# every `ps` listing on the host.
cmd_sentinel() {
  local token_file="" v4="" v6="" zone="" interval_ms=2000 token nap seq=0
  local source4="" source6="" dns_server=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --token-file)  token_file="$2"; shift 2 ;;
      --beacon-v4)   v4="$2";         shift 2 ;;
      --beacon-v6)   v6="$2";         shift 2 ;;
      --zone)        zone="$2";       shift 2 ;;
      --interval-ms) interval_ms="$2"; shift 2 ;;
      # THE ADDRESS THE BEATS PRESENT. Repeatable, once per family: `curl
      # --interface <addr>` binds before connecting, so the source address the
      # oracle records is this one rather than whichever the routing table
      # happened to pick. On a multi-homed host -- which an in-box fabric always
      # is -- that difference is the entire independence claim.
      --source)      case "$2" in *:*) source6="$2" ;; *) source4="$2" ;; esac; shift 2 ;;
      # The server to send the DNS beat to. See `resolve_once`.
      --dns-server)  dns_server="$2"; shift 2 ;;
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
  # never had. `awk` rather than an interpreter: the sentinel now runs on the CI
  # controller as well as on a standing host, and this is a division.
  nap="$(awk -v ms="$interval_ms" 'BEGIN { printf "%.3f", ms / 1000 }')"

  # THE IDENTITY, PRINTED. The lane captures this line and records it as
  # `sentinel_egress_identity`, which must differ from both path identities.
  # Printed even when it is empty, because "the sentinel did not pin a source"
  # is the fact a reader needs in order to know the claim is weaker.
  local presented="${source4:-<unpinned>}/${source6:-<unpinned>}"
  echo "TWINVPN_SENTINEL_EGRESS_IDENTITY $presented"
  echo "sentinel beating every ${interval_ms}ms into $zone (ctrl-c to stop)"
  local bind4=() bind6=()
  [ -n "$source4" ] && bind4=(--interface "$source4")
  [ -n "$source6" ] && bind6=(--interface "$source6")
  while :; do
    seq=$((seq + 1))
    [ -n "$v4" ] && curl -4 -sS --max-time 3 "${bind4[@]}" -o /dev/null "$v4/$token/$seq" 2>/dev/null || true
    [ -n "$v6" ] && curl -6 -sS --max-time 3 "${bind6[@]}" -o /dev/null "$v6/$token/$seq" 2>/dev/null || true
    # NO PATH TAG. `dns::beacon_labels` treats the last label before the zone as
    # a path tag only when it is `p` or `u`; any other letter is not stripped, so
    # it becomes the TOKEN and the real token becomes part of the sequence. A
    # `.s` label here would make every DNS beat unmatchable -- reported as a dead
    # sentinel that was in fact alive, and every session INCONCLUSIVE. The token
    # alone already says which index a beat belongs to, and a sentinel has no
    # path to declare.
    resolve_once "$seq.$token.$zone" "$dns_server"
    sleep "$nap"
  done
}

# The refusals a sentinel must never skip, driven against this script itself.
# `leak-probe.sh --self-check` runs it; it opens no session and sends nothing.
leak_probe_sentinel_self_check() {
  local probe="$REPO/build/ci/leak-probe.sh" rc=0 out token_file
  token_file="$(mktemp)"; printf 'x%.0s' $(seq 1 40) > "$token_file"

  # The DUT guard. This is the one that must never be relaxed: a heartbeat from
  # the device under test proves the device could reach the oracle.
  out="$(TWINVPN_DISPOSABLE_GUEST=1 "$probe" sentinel --token-file "$token_file" \
        --zone leak.test --beacon-v4 http://198.51.100.7/b 2>&1)" && rc=1
  case "$out" in
    *"DEVICE UNDER TEST"*) : ;;
    *) echo "self-check FAILED: the disposable guest was allowed to be a sentinel: $out" >&2; rc=1 ;;
  esac

  # A sentinel with no token file must refuse rather than beat with an empty
  # token, which the oracle would file as an unknown arrival and nobody would
  # see -- reported as a dead sentinel that was in fact running.
  out="$("$probe" sentinel --token-file /nonexistent/sentinel.token --zone leak.test \
        --beacon-v4 http://198.51.100.7/b 2>&1)" && rc=1
  case "$out" in
    *"no sentinel token"*) : ;;
    *) echo "self-check FAILED: a missing token file was not refused: $out" >&2; rc=1 ;;
  esac

  rm -f "$token_file"
  return $rc
}
