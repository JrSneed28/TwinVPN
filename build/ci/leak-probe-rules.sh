#!/usr/bin/env bash
#
# leak-probe-rules.sh -- the leak probe's two checked rules.
#
# ===========================================================================
# WHY THESE ARE THEIR OWN FILE
# ===========================================================================
# Two rules, each with a security consequence and each driven by
# `leak-probe.sh --self-check`: IS THIS BEACON TARGET OFF THE DEVICE, and ARE
# THESE ATTEMPT COUNTS SOMETHING A DEVICE UNDER TEST WROTE THAT WE MAY TRUST.
# Both live beside their checks so neither can be changed without the check
# noticing.
#
# THE BEACON TARGET. It is the one rule in the leak probe with an immediate
# security consequence: a beacon
# target the device can reach without emitting a packet that LEAVES it makes
# every SILENCE phase pass for free. It replaces this glob, which shipped in
# `cmd_open` and was wrong three ways --
#
#     *//127.*|*//10.*|*//192.168.*|*//169.254.*|*//localhost*
#
# it never looked at the IPv6 beacon at all, it omitted `172.16.0.0/12`, and it
# refused every RFC 1918 address, which made an in-box lab fabric impossible to
# express even when the fabric was the only way to exercise IPv6 at all.
#
# So the rule is stated as an invariant instead of as a blocklist, it is applied
# to BOTH families, and it lives beside its own self-check
# (`leak-probe.sh --self-check`), which drives every branch with fake host
# address lists rather than with whatever the machine running the test owns.
#
# THE INVARIANT, in order:
#
#   1 loopback and `localhost` are refused on both families, always;
#   2 link-local (169.254.0.0/16, fe80::/10) is refused on both families,
#     always -- the Windows kill switch PERMITS link-local by design
#     (`filters.rs` class 9), so a link-local oracle would be reachable while
#     armed and the SILENCE phase would fail for a reason that is not a leak;
#   3 an address THE PROBE HOST ITSELF OWNS is refused, always. This is the
#     rule that survives a topology change: whatever the addressing plan, a
#     packet to an address on this machine never left it;
#   4 any other non-global address is refused UNLESS the caller has declared
#     `TWINVPN_ORACLE_TOPOLOGY=in-box`. The external deployment keeps its
#     guard; an in-box fabric has to say so out loud, and `report.py` grades
#     the declaration because the lane records it in `environment`.
#
# WHERE EACH HALF RUNS, which the control-plane split made matter. `open` runs
# on the CONTROLLER in the Windows lane and the controller legitimately owns the
# oracle's addresses, so rule 3 is checked where the beacons are actually
# emitted -- in `cmd_beacon`, which only ever runs on the device. Rules 1, 2
# and 4 are checked at `open`, as early as possible.

# NO `set -e` HERE: sourced into scripts that set their own options.

# The host part of a beacon URL. `http://10.78.0.1/b/tok` -> `10.78.0.1`;
# `http://[fd78:7717:d0c::1]:80/b/tok` -> `fd78:7717:d0c::1`. Parameter
# expansion rather than sed: this is called on a Windows guest whose PATH is
# whatever PowerShell Direct handed the shell.
beacon_host() {
  local hostport="${1#*://}"
  hostport="${hostport%%/*}"
  case "$hostport" in
    \[*)                                     # [v6] or [v6]:port
      hostport="${hostport#\[}"
      printf '%s' "${hostport%%]*}" ;;
    *:*:*) printf '%s' "$hostport" ;;        # bare v6, no port
    *:*)   printf '%s' "${hostport%%:*}" ;;  # host:port
    *)     printf '%s' "$hostport" ;;
  esac
}

# The addresses THIS machine holds, one per line. Empty output is not "none":
# a host whose addresses cannot be enumerated cannot answer rule 3, and the
# caller treats that as fatal rather than as a pass.
host_addresses() {
  if command -v powershell.exe >/dev/null 2>&1; then
    # `%zone` suffixes are stripped: `fe80::1%12` and `fe80::1` are the same
    # address and only one of the two spellings would ever match.
    powershell.exe -NoProfile -NonInteractive -Command \
      '(Get-NetIPAddress).IPAddress' 2>/dev/null | tr -d '\r' | sed 's/%.*$//'
  elif command -v ip >/dev/null 2>&1; then
    ip -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1
  elif command -v ifconfig >/dev/null 2>&1; then
    # macOS prints `inet6 fe80::1%en0 prefixlen 64`; the zone suffix is stripped
    # for the same reason as above, so both spellings of one address match.
    ifconfig 2>/dev/null | awk '/^[ \t]*inet6? /{print $2}' | cut -d/ -f1 | sed 's/%.*$//'
  else
    return 1
  fi
}

# 127.0.0.0/8, ::1, and the name.
_target_is_loopback() {
  case "$1" in
    127.*|::1|0:0:0:0:0:0:0:1|localhost|localhost.*) return 0 ;;
  esac
  return 1
}

# 169.254.0.0/16 and fe80::/10.
_target_is_link_local() {
  case "$1" in
    169.254.*|fe8*:*|fe9*:*|fea*:*|feb*:*) return 0 ;;
  esac
  return 1
}

# Not routable on the public internet. Deliberately not exhaustive about every
# reserved block -- it names the ranges a lab fabric is actually built on, and
# anything it fails to classify still has to survive rules 1 to 3.
#
# The RFC 5737 documentation ranges are deliberately ABSENT. They are not
# globally routable either, but every example in this repository and in
# `lab/twinoracle/README.md` uses `198.51.100.7` and `2001:db8::7` as stand-ins
# for the external oracle's public addresses, and classifying them here would
# refuse the documented external deployment while catching no hazard: a
# documentation address is not an address this device holds.
#
# ponytail: prefix globs, not a CIDR engine. If this ever needs a fifth range
# it is time for python3, which every host running this already has.
_target_is_non_global() {
  case "$1" in
    10.*|192.168.*) return 0 ;;                                  # RFC 1918
    172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;           # RFC 1918
    100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 0 ;;  # CGNAT
    198.1[89].*) return 0 ;;                                     # benchmarking
    fc*:*|fd*:*) return 0 ;;                                     # ULA fc00::/7
  esac
  return 1
}

# THE RULE. Prints one line saying why the target is unusable, or nothing.
#
#   beacon_target_problem <label> <url> <own-addresses>
#
# `<own-addresses>` is passed in rather than read here so that the self-check
# can drive rule 3 with a fabricated host, and so that a caller which is NOT the
# device (the controller, at `open`) can pass an empty list deliberately instead
# of accidentally checking the wrong machine's addresses.
beacon_target_problem() {
  local label="$1" url="$2" own="$3" host lower addr
  [ -n "$url" ] && [ "$url" != "null" ] || {
    printf "%s is empty, so that family would silently record zero attempts" "$label"
    return 0
  }
  host="$(beacon_host "$url")"
  lower="$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')"
  if [ -z "$lower" ]; then
    printf '%s (%s) has no host part' "$label" "$url"
    return 0
  fi
  if _target_is_loopback "$lower"; then
    printf "%s advertises %s, which is on this device. Egress to loopback is \
not egress and cannot discharge a kill-switch criterion" "$label" "$host"
    return 0
  fi
  if _target_is_link_local "$lower"; then
    printf "%s advertises %s, which is link-local. The kill switch PERMITS \
link-local egress by design, so a SILENCE phase against it would fail for a \
reason that is not a leak" "$label" "$host"
    return 0
  fi
  for addr in $own; do
    if [ "$lower" = "$(printf '%s' "$addr" | tr '[:upper:]' '[:lower:]')" ]; then
      printf "%s advertises %s, which is an address THIS HOST owns. A packet to \
it never leaves the machine the criterion is about" "$label" "$host"
      return 0
    fi
  done
  if _target_is_non_global "$lower" && [ "${TWINVPN_ORACLE_TOPOLOGY:-}" != "in-box" ]; then
    printf "%s advertises %s, which is not globally routable. Set \
TWINVPN_ORACLE_TOPOLOGY=in-box if the oracle really is on a lab fabric this \
device reaches only by emitting a packet; the declaration is recorded in the \
evidence and graded there" "$label" "$host"
    return 0
  fi
  return 0
}

# ---------------------------------------------------------------------------
# THE ATTEMPT COUNTS THE DEVICE REPORTS
# ---------------------------------------------------------------------------
# `<v4> <v6> <dns>` on stdout, or nothing and a non-zero status.
#
# THE FILE CROSSES A TRUST BOUNDARY: it is written on the device under test,
# whose honesty is the whole subject of the criterion. So it is PARSED rather
# than sourced, and every field must be a plain non-negative integer.
# Over-reporting cannot manufacture a pass -- arrivals are counted by the oracle
# alone -- but a shell-injectable file would be a way to run the device's text
# on the controller.
attempt_counts_from_file() {
  local file="$1" v4 v6 dns clean
  [ -f "$file" ] || return 1
  clean="$(tr -d ' \t\r' < "$file")"
  v4="$(printf '%s\n' "$clean" | sed -n 's/^ipv4=\([0-9][0-9]*\)$/\1/p' | head -1)"
  v6="$(printf '%s\n' "$clean" | sed -n 's/^ipv6=\([0-9][0-9]*\)$/\1/p' | head -1)"
  dns="$(printf '%s\n' "$clean" | sed -n 's/^dns=\([0-9][0-9]*\)$/\1/p' | head -1)"
  [ -n "$v4" ] && [ -n "$v6" ] && [ -n "$dns" ] || return 1
  printf '%s %s %s' "$v4" "$v6" "$dns"
}

# ---------------------------------------------------------------------------
# THE SELF-CHECK -- `leak-probe.sh --self-check`
# ---------------------------------------------------------------------------
# The repo's idiom (`build/ci/require-job-results.py --self-check`): the
# smallest runnable thing that fails if the logic above breaks. Every branch,
# with fabricated hosts, so it grades the rule rather than the machine.
_expect_problem() {
  local why="$1" label="$2" url="$3" own="$4" got
  got="$(beacon_target_problem "$label" "$url" "$own")"
  [ -n "$got" ] || { echo "self-check FAILED: $why -- $url was accepted" >&2; return 1; }
}

_expect_ok() {
  local why="$1" label="$2" url="$3" own="$4" got
  got="$(beacon_target_problem "$label" "$url" "$own")"
  [ -z "$got" ] || { echo "self-check FAILED: $why -- $url was refused: $got" >&2; return 1; }
}

leak_probe_target_self_check() {
  local own="10.77.0.10 fd77:7717:d0c::10 169.254.13.7"
  local rc=0

  # Parsing, which every rule below depends on.
  [ "$(beacon_host 'http://10.78.0.1/b/tok')" = "10.78.0.1" ] || { echo "self-check FAILED: v4 host parse" >&2; rc=1; }
  [ "$(beacon_host 'http://[fd78:7717:d0c::1]/b/tok')" = "fd78:7717:d0c::1" ] || { echo "self-check FAILED: v6 host parse" >&2; rc=1; }
  [ "$(beacon_host 'http://[fd78:7717:d0c::1]:8080/b')" = "fd78:7717:d0c::1" ] || { echo "self-check FAILED: v6 host:port parse" >&2; rc=1; }
  [ "$(beacon_host 'http://198.51.100.7:80/b')" = "198.51.100.7" ] || { echo "self-check FAILED: v4 host:port parse" >&2; rc=1; }

  # Rules 1 and 2: refused on both families whatever the topology says.
  local topo
  for topo in "" "in-box"; do
    TWINVPN_ORACLE_TOPOLOGY="$topo"
    _expect_problem "loopback v4 ($topo)"     v4 'http://127.0.0.1/b/t'        "$own" || rc=1
    _expect_problem "loopback name ($topo)"   v4 'http://localhost/b/t'        "$own" || rc=1
    _expect_problem "loopback v6 ($topo)"     v6 'http://[::1]/b/t'            "$own" || rc=1
    _expect_problem "link-local v4 ($topo)"   v4 'http://169.254.7.7/b/t'      "$own" || rc=1
    _expect_problem "link-local v6 ($topo)"   v6 'http://[fe80::7]/b/t'        "$own" || rc=1
    # Rule 3: an address this host owns, in either family, whatever the topology.
    _expect_problem "own v4 ($topo)"          v4 'http://10.77.0.10/b/t'       "$own" || rc=1
    _expect_problem "own v6 ($topo)"          v6 'http://[fd77:7717:d0c::10]/b/t' "$own" || rc=1
    # An empty URL is a problem in both, because a family with no beacon
    # records zero attempts and reads as INCONCLUSIVE rather than as absent.
    _expect_problem "empty ($topo)"           v6 ''                            "$own" || rc=1
  done

  # Rule 4: non-global needs the declaration. Both families, and the IPv6 half
  # is the one the shipped glob never looked at.
  TWINVPN_ORACLE_TOPOLOGY=""
  _expect_problem "rfc1918 without the declaration"  v4 'http://10.78.0.1/b/t'         "$own" || rc=1
  _expect_problem "172.16/12 without the declaration" v4 'http://172.20.4.4/b/t'       "$own" || rc=1
  _expect_problem "ULA without the declaration"      v6 'http://[fd78:7717:d0c::1]/b/t' "$own" || rc=1
  _expect_ok      "a global v4 target"               v4 'http://198.51.100.7/b/t'      "$own" || rc=1

  TWINVPN_ORACLE_TOPOLOGY="in-box"
  _expect_ok "the in-box v4 oracle" v4 'http://10.78.0.1/b/t'          "$own" || rc=1
  _expect_ok "the in-box v6 oracle" v6 'http://[fd78:7717:d0c::1]/b/t' "$own" || rc=1
  # 172.16/12 and 198.18/15 are the two the shipped glob missed; in-box they
  # are legitimate, and the point is that they are now CLASSIFIED either way.
  _expect_ok "172.16/12 in-box" v4 'http://172.20.4.4/b/t'  "$own" || rc=1
  _expect_ok "198.18/15 in-box" v4 'http://198.18.0.1/b/t'  "$own" || rc=1
  unset TWINVPN_ORACLE_TOPOLOGY

  return $rc
}

# THE MODE REFUSALS. Half a control-plane split is worse than none: a device
# that posts nothing and a controller that reads nothing both end in a session
# that looks like it tried fewer times than it did, which the oracle grades as
# INCONCLUSIVE and `report.py` counts against eligibility exactly as a failure.
# So every ambiguous combination has to be fatal, and this is what proves it.
leak_probe_mode_self_check() {
  local probe="$REPO/build/ci/leak-probe.sh" rc=0 out tmp

  out="$(TWINVPN_ORACLE_CONTROL_BY=sometimes "$probe" beacon --seconds 1 2>&1)" && rc=1
  case "$out" in
    *"TWINVPN_ORACLE_CONTROL_BY is 'sometimes'"*) : ;;
    *) echo "self-check FAILED: an unknown control-plane mode was accepted: $out" >&2; rc=1 ;;
  esac

  out="$("$probe" beacon --seconds 1 --counts-file /tmp/twinvpn-selfcheck.counts 2>&1)" && rc=1
  case "$out" in
    *"nothing would ever post the file"*) : ;;
    *) echo "self-check FAILED: --counts-file was accepted outside controller mode: $out" >&2; rc=1 ;;
  esac

  out="$(TWINVPN_ORACLE_CONTROL_BY=controller "$probe" beacon --seconds 1 2>&1)" && rc=1
  case "$out" in
    *"Pass --counts-file"*) : ;;
    *) echo "self-check FAILED: controller mode beaconed without a counts file: $out" >&2; rc=1 ;;
  esac

  # The counts file crosses a trust boundary: it is written on the device under
  # test. Anything but three plain integers is refused rather than interpreted.
  tmp="$(mktemp)"
  printf 'ipv4=12\nipv6=12\ndns=12\n' > "$tmp"
  [ "$(attempt_counts_from_file "$tmp")" = "12 12 12" ] \
    || { echo "self-check FAILED: a well-formed counts file was rejected" >&2; rc=1; }
  # shellcheck disable=SC2016
  # The single quotes are the point: `$(touch ...)` must reach the parser as
  # literal text, because that is exactly what a hostile device would write.
  for hostile in 'ipv4=12
ipv6=12
dns=$(touch /tmp/pwned)' 'ipv4=-1
ipv6=2
dns=3' 'ipv4=12
ipv6=12' 'ipv4=0x10
ipv6=1
dns=1'; do
    printf '%s\n' "$hostile" > "$tmp"
    if attempt_counts_from_file "$tmp" >/dev/null; then
      echo "self-check FAILED: hostile counts file accepted: $hostile" >&2; rc=1
    fi
  done
  rm -f "$tmp"
  return $rc
}
