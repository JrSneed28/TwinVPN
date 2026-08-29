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
  bytes=$(wc -c < "$archive")
  if [ "$bytes" -gt "$LIMIT_BYTES" ]; then
    echo "    $arch  $bytes bytes  OVER the ADR-0018 §11.9 row 5 budget of $LIMIT_BYTES"
    rc=1
  else
    echo "    $arch  $bytes bytes  within $LIMIT_BYTES"
  fi
done

if [ "$found" -eq 0 ]; then
  echo "check-budget.sh: no per-arch slice under $DEST — run build-bridge.sh first" >&2
  exit 1
fi

if [ "$rc" -ne 0 ]; then
  echo "::error::ADR-0018 §11.9 row 5 size budget breached" >&2
fi
exit "$rc"
