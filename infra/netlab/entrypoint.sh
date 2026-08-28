#!/usr/bin/env bash
# Realize one NAT personality and one impairment inside this container.
#
# ===========================================================================
# THE ONE RULE, INHERITED FROM docs/testing-strategy.md §3.1
# ===========================================================================
#   "Every condition TwinLab reproduces MUST be produced by a mechanism with
#    the same observable semantics as the real thing, never by a flag inside
#    TwinVPN."
#
# The consequence for this script is blunt and is the reason for every `exit 1`
# below: A FACILITY THIS CONTAINER CANNOT PROVIDE IS A FAILURE TO START, NEVER
# A DEGRADED MODE. If `nft` cannot load the ruleset, this container must not
# come up as a transparent router — because a transparent router traverses
# everything, and the scenario would report DIRECT for a NAT class that was
# never applied. That is `Verdict::Unavailable` reported as `Pass`, which
# twinlab's whole type design exists to prevent.
#
# ===========================================================================
# THE RULES ARE NOT WRITTEN HERE
# ===========================================================================
# `twinlab-scenarios nat-ruleset` and `twinlab-scenarios impair-argv` print
# them, out of `twinlab::nat::Personality::ruleset` and
# `twinlab::impair::Impairment::tc_argv`. This script applies what they print
# and never edits it. If the rules were re-typed here, this container and the
# namespace lab would be two definitions of §3.3, and the container one would
# be the one nothing tests.
#
# Usage:
#   netlab-entrypoint run       apply, then forward until stopped
#   netlab-entrypoint verify    assert what is applied is still applied
#   netlab-entrypoint show      print the ruleset and qdisc without applying
#   netlab-entrypoint gateway   hold a namespace whose default route is the NAT

set -euo pipefail

personality="${TWINVPN_NETLAB_PERSONALITY:-}"
impairment="${TWINVPN_NETLAB_IMPAIRMENT:-}"
ext_if="${TWINVPN_NETLAB_EXTERNAL_IF:-eth0}"
internal_cidr="${TWINVPN_NETLAB_INTERNAL_CIDR:-}"

die() { printf '!! netlab: %s\n' "$*" >&2; exit 1; }
log() { printf '   netlab: %s\n' "$*"; }

# ---------------------------------------------------------------------------
# The external address is READ FROM THE INTERFACE, never configured.
#
# A NAT translates to the address it actually egresses from. Taking it from an
# environment variable would let the two disagree, and the failure is silent:
# `snat to <wrong address>` produces packets the peer never answers, which
# reads as "the NAT class is untraversable" — a plausible-looking result for a
# class that would have traversed.
# ---------------------------------------------------------------------------
external_address() {
  local addr
  addr=$(ip -4 -brief addr show dev "$ext_if" 2>/dev/null | awk '{print $3}' | cut -d/ -f1)
  [ -n "$addr" ] || die "no IPv4 address on $ext_if; a NAT with no external address cannot translate"
  printf '%s' "$addr"
}

require_config() {
  [ -n "$personality" ] || die "TWINVPN_NETLAB_PERSONALITY is required. A netlab container with no personality is a transparent router, and a transparent router traverses everything."
  [ -n "$internal_cidr" ] || die "TWINVPN_NETLAB_INTERNAL_CIDR is required: it is the ruleset's saddr match, and an empty one matches nothing."
}

# ---------------------------------------------------------------------------
# Forwarding. Both families, always.
#
# ADR-0010 R1 makes IPv4 and IPv6 one story, and infra/README.md §3 says a
# service that works on only one is broken. A netlab that forwarded v4 and
# silently black-holed v6 would make every dual-stack scenario report a v6
# failure that is the lab's, not the product's.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# What matters is that forwarding IS ON, not that this script turned it on.
#
# `/proc/sys` is mounted READ-ONLY inside a rootless container, so `sysctl -w`
# fails with EPERM even when `NET_ADMIN` is granted and even when the value is
# already correct. The container runtime sets it at creation instead — that is
# what `sysctls:` in docker-compose.yml is for, and it is the right mechanism
# because it happens before PID 1 exists.
#
# An earlier revision treated the write failing as forwarding being off and
# refused to start. That is the correct DIRECTION (a netlab that cannot forward
# must not come up) applied to the wrong FACT, and it made the container
# unstartable under exactly the runtime the compose file targets. The three
# cases are now distinguished:
#
#   already 1              -> fine, whoever set it
#   0 and writable         -> set it
#   0 and not writable     -> REFUSE. This is the real failure, and it means
#                             the `sysctls:` entry is missing from compose.
# ---------------------------------------------------------------------------
ensure_forwarding() {
  local key=$1 path=$2 family=$3
  local now
  now=$(cat "$path" 2>/dev/null || echo "")
  if [ "$now" = "1" ]; then
    log "$family forwarding already on (set by the container runtime)"
    return 0
  fi
  if sysctl -qw "$key=1" 2>/dev/null; then
    log "$family forwarding enabled"
    return 0
  fi
  die "$family forwarding is off ($path = '${now:-unreadable}') and $key is not writable.
  /proc/sys is read-only in a rootless container, so this must be set at CREATION:
      sysctls:
        $key: \"1\"
  A netlab that cannot forward is not a middlebox, and coming up anyway would
  make every scenario behind it fail for a reason that is not the product's."
}

enable_forwarding() {
  # Both families, always. ADR-0010 R1 makes IPv4 and IPv6 one story, and a
  # netlab that forwarded v4 and silently black-holed v6 would make every
  # dual-stack scenario report a v6 failure that is the lab's, not the
  # product's.
  ensure_forwarding net.ipv4.ip_forward /proc/sys/net/ipv4/ip_forward IPv4
  ensure_forwarding net.ipv6.conf.all.forwarding /proc/sys/net/ipv6/conf/all/forwarding IPv6
}

apply_nat() {
  local ruleset
  ruleset=$(twinlab-scenarios nat-ruleset "$personality" \
              --external "$(external_address)" \
              --internal "$internal_cidr") \
    || die "twinlab does not define a personality named '$personality'"

  printf '%s\n' "$ruleset" > /run/netlab-ruleset.nft

  # `nft -c -f` first: a check pass, then a load. A partially applied ruleset
  # is worse than none — half a NAT is a class nobody named.
  nft -c -f /run/netlab-ruleset.nft \
    || die "the ruleset for $personality does not load on this kernel. This is UNAVAILABLE, not a pass; see /run/netlab-ruleset.nft"
  nft -f /run/netlab-ruleset.nft \
    || die "loading the ruleset for $personality failed"
  log "applied $personality"
}

apply_impairment() {
  [ -n "$impairment" ] || { log "no impairment requested"; return 0; }
  local argv
  argv=$(twinlab-scenarios impair-argv "$impairment" --dev "$ext_if") \
    || die "twinlab cannot realize '$impairment' through tc"
  # Unquoted on purpose: this IS an argument vector, printed by twinlab as
  # one. `shellcheck disable` rather than an array read, because splitting is
  # the intent.
  # shellcheck disable=SC2086
  tc $argv || die "applying '$impairment' failed"
  log "applied impairment $impairment"
}

# ---------------------------------------------------------------------------
# `verify` is the health check, and it asks whether the CONDITION still holds.
#
# Not "is the process alive" — the process is `sleep`. A container whose
# ruleset was flushed (a `nft flush ruleset` from a neighbouring test, a kernel
# module unload) is still running and is no longer a NAT, and every scenario
# behind it would silently start traversing. This is what catches that.
# ---------------------------------------------------------------------------
verify() {
  case "$personality" in
    # N-ROUTED is forwarding only and installs no nat chain, so the presence of
    # a nat chain is not what proves it. Forwarding is.
    N-ROUTED|n-routed)
      # Read from /proc directly: `sysctl -n` shells out for a value a file
      # already holds, and in a read-only /proc/sys it is the only thing that
      # works consistently.
      [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" = "1" ] \
        || die "IPv4 forwarding is off"
      [ "$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null)" = "1" ] \
        || die "IPv6 forwarding is off"
      ;;
    *)
      nft list table inet twinlab_nat >/dev/null 2>&1 \
        || die "the twinlab_nat table is gone: this container is no longer a $personality"
      ;;
  esac
  if [ -n "$impairment" ]; then
    tc qdisc show dev "$ext_if" | grep -qE 'netem|tbf' \
      || die "the impairment qdisc is gone from $ext_if: '$impairment' is no longer applied"
  fi
  return 0
}

# ---------------------------------------------------------------------------
# `gateway` — the namespace a natted peer joins.
#
# Docker gives every container on a bridge a default route to THE BRIDGE, not
# to another container, and compose cannot express a static route. So a peer
# that must egress through `netlab-nat` cannot simply be attached to the same
# network and hope.
#
# This mode is the answer: one container per natted peer, on the access network
# only, which replaces its own default route with the NAT's address and then
# does nothing. The peer joins it with `network_mode: "service:<this>"` and
# inherits the namespace, the address and the route.
#
# The alternative — giving the twinsim image NET_ADMIN and an `ip route` shim —
# was rejected: it puts a capability and a shell into the image that simulates a
# DEVICE, and a device does not configure the network it is behind. Keeping all
# NET_ADMIN in the netlab image is also what lets twinsim stay distroless.
gateway() {
  local via="${TWINVPN_NETLAB_GATEWAY_V4:-}"
  local via6="${TWINVPN_NETLAB_GATEWAY_V6:-}"
  [ -n "$via" ] || [ -n "$via6" ] \
    || die "gateway mode needs TWINVPN_NETLAB_GATEWAY_V4 and/or _V6: without one, this namespace keeps Docker's default route and the peer inside it BYPASSES the NAT entirely -- which would report DIRECT for a class that was never traversed."
  if [ -n "$via" ]; then
    ip -4 route replace default via "$via" \
      || die "cannot route IPv4 via $via; is NET_ADMIN granted?"
    log "IPv4 default route now via $via"
  fi
  if [ -n "$via6" ]; then
    ip -6 route replace default via "$via6" \
      || die "cannot route IPv6 via $via6; is NET_ADMIN granted?"
    log "IPv6 default route now via $via6"
  fi
  exec sleep infinity
}

case "${1:-run}" in
  gateway)
    gateway
    ;;
  show)
    require_config
    twinlab-scenarios nat-ruleset "$personality" --external "$(external_address)" --internal "$internal_cidr"
    [ -n "$impairment" ] && twinlab-scenarios impair-argv "$impairment" --dev "$ext_if"
    ;;
  verify)
    # A gateway namespace has no personality and no ruleset; what proves it is
    # still doing its job is the route it installed. Checking for a nat table
    # here would fail a container that is working perfectly.
    if [ -z "$personality" ]; then
      ip route show default | grep -q . || die "the default route is gone; the peer in this namespace would bypass the NAT"
      exit 0
    fi
    require_config
    verify
    ;;
  run)
    require_config
    enable_forwarding
    apply_nat
    apply_impairment
    verify
    log "ready: $personality on $ext_if, internal $internal_cidr, impairment '${impairment:-none}'"
    # PID 1 forwards nothing itself — the kernel does. This process exists to
    # hold the network namespace open and to receive SIGTERM.
    exec sleep infinity
    ;;
  *)
    die "usage: netlab-entrypoint {run|verify|show}"
    ;;
esac
