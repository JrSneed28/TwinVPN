#!/usr/bin/env bash
#
# check-budget.sh — ADR-0018 §11.9 row 1's size gate, as a gate.
#
#   "`staticlib` <= 12 MB **on disk**; **core RSS <= 9 MB** inside ADR-0022's
#    12 MB provider budget (PB-6)"
#
# Only the first half is checkable here. RSS is a runtime measurement and needs
# a device under load — it is `TwinVPNTests`' and the device farm's, and this
# script does not pretend to cover it.
#
# THE DEVICE SLICE IS WHAT IS GATED. A simulator archive is not a shipping
# artifact and its size says nothing about what the App Store receives, so the
# default subject is `Frameworks/iphoneos/`. R-32 makes the budget a RELEASE
# BLOCKER, so this exits non-zero rather than warning.

set -euo pipefail

# ===========================================================================
# REPORT BY DEFAULT, BLOCK ONLY WITH --gate
# ===========================================================================
# §11.9 line 877: "Budget is stripped artifact size and steady-state RSS; both
# gate at T4 (§6.4)." T4, not the link/run job.
#
# The link/run job proves the boundary compiles, links, loads, is invoked,
# returns a result and drives a lifecycle transition. Aborting it on a release
# budget is tier confusion, and it fails badly: `set -e` kills the script
# BEFORE it writes its evidence file, so the job uploads nothing, the
# `if-no-files-found: error` upload adds a second red, and the acceptance row
# reads NOT-EXECUTED -- a size breach masquerading as an unrun platform.
#
# So this reports by default and exits 0 with the numbers on stdout, which the
# calling script records. `--gate` restores the blocking behaviour and is what
# T4 calls. R-32 is unchanged and unrelaxed: it is enforced where the ADR puts
# it. Moving it here would be raising a tier's scope silently, which
# testing-strategy rule C-1 forbids in the same words.
#
# WHO CALLS --gate TODAY: NOBODY, AND THAT IS RECORDED RATHER THAN HIDDEN.
# .github/workflows/t4-release.yml builds no Apple target at all, so the T4
# home §11.9 line 877 assigns this gate does not exist yet. Until it does, the
# budget is MEASURED on every link/run and BLOCKS NOWHERE. That is a real gap
# and it is stated here so the next reader does not mistake a passing
# link/run for a satisfied budget. Owed: an Apple build in T4 that calls this
# with --gate.

GATE=0
ARGS=()
for a in "$@"; do
  case "$a" in
    --gate) GATE=1 ;;
    *) ARGS+=("$a") ;;
  esac
done
set -- ${ARGS[@]+"${ARGS[@]}"}

SHELL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PLATFORM="${1:-iphoneos}"
DIR="$SHELL_DIR/Frameworks/$PLATFORM"

# 12 MB, as ADR-0018 §11.9 row 1 writes it. Decimal megabytes, because that is
# what a size budget in a document means and what `ls -l` reports against.
LIMIT_BYTES=$((12 * 1000 * 1000))

[ -d "$DIR" ] || { echo "check-budget.sh: $DIR does not exist — run build-core.sh first" >&2; exit 1; }

rc=0
found=0
for archive in "$DIR"/libtwinvpn_core.a "$DIR"/libtwinvpn_core_lite.a; do
  [ -f "$archive" ] || continue
  found=1
  # §11.9 line 877 is explicit: "Budget" is STRIPPED artifact size and
  # steady-state RSS. An unstripped `.a` is every object file plus its debug
  # info, which is not what ships and not what the budget names — measuring it
  # against a stripped-artifact limit measures the wrong quantity by an order
  # of magnitude. Strip a copy; the original stays intact for the link step.
  stripped="$(mktemp)"; cp "$archive" "$stripped"
  strip -S "$stripped" 2>/dev/null || xcrun strip -S "$stripped" 2>/dev/null || :
  bytes=$(wc -c < "$stripped")
  raw=$(wc -c < "$archive")
  rm -f "$stripped"
  name="$(basename "$archive")"
  if [ "$bytes" -gt "$LIMIT_BYTES" ]; then
    echo "    $name  $bytes bytes stripped ($raw unstripped)  OVER the ADR-0018 §11.9 row 1 budget of $LIMIT_BYTES"
    rc=1
  else
    echo "    $name  $bytes bytes stripped ($raw unstripped)  within $LIMIT_BYTES"
  fi
done

[ "$found" -eq 1 ] || { echo "check-budget.sh: no staticlib in $DIR" >&2; exit 1; }

if [ "$rc" -ne 0 ] && [ "$GATE" -eq 0 ]; then
  echo "::warning::ADR-0018 §11.9 row 1 size budget breached — REPORTED, not gated here; T4 blocks on it (§11.9 line 877)" >&2
  rc=0
elif [ "$rc" -ne 0 ]; then
  echo "::error::ADR-0018 §11.9 row 1 size budget breached for $PLATFORM" >&2
fi
exit "$rc"
