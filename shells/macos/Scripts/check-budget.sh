#!/usr/bin/env bash
#
# check-budget.sh — ADR-0018 §11.9 row 5's size gate, as a gate.
#
#   macOS | aarch64-apple-darwin, x86_64-apple-darwin (universal 2) | Xcode |
#   staticlib into the system extension | static | macOS 11 | <= 10 MB PER ARCH
#
# PER ARCH is the whole point of measuring the slices rather than the universal
# archive: a universal binary is roughly the sum of its slices, so gating the
# fat file against a per-arch budget would either pass everything (at 2x the
# budget) or fail everything (at 1x). `build-bridge.sh` keeps the slices under
# `Frameworks/<arch>/` for exactly this.
#
# R-32 makes the budget a RELEASE BLOCKER — "MUST block the release if it cannot
# be built or its budget is breached" — so this exits non-zero rather than
# warning.

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
DEST="$SHELL_DIR/Frameworks"

# 10 MB, as ADR-0018 §11.9 row 5 writes it. Decimal megabytes, because that is
# what a size budget in a document means.
LIMIT_BYTES=$((10 * 1000 * 1000))

[ -d "$DEST" ] || { echo "check-budget.sh: $DEST does not exist — run build-bridge.sh first" >&2; exit 1; }

rc=0
found=0
for arch in arm64 x86_64; do
  archive="$DEST/$arch/libtwinvpn_bridge.a"
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
  if [ "$bytes" -gt "$LIMIT_BYTES" ]; then
    echo "    $arch  $bytes bytes stripped ($raw unstripped)  OVER the ADR-0018 §11.9 row 5 budget of $LIMIT_BYTES"
    rc=1
  else
    echo "    $arch  $bytes bytes stripped ($raw unstripped)  within $LIMIT_BYTES"
  fi
done

if [ "$found" -eq 0 ]; then
  echo "check-budget.sh: no per-arch slice under $DEST — run build-bridge.sh first" >&2
  exit 1
fi

if [ "$rc" -ne 0 ] && [ "$GATE" -eq 0 ]; then
  echo "::warning::ADR-0018 §11.9 row 5 size budget breached — REPORTED, not gated here; T4 blocks on it (§11.9 line 877)" >&2
  rc=0
elif [ "$rc" -ne 0 ]; then
  echo "::error::ADR-0018 §11.9 row 5 size budget breached" >&2
fi
exit "$rc"
