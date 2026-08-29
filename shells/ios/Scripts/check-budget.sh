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
  bytes=$(wc -c < "$archive")
  name="$(basename "$archive")"
  if [ "$bytes" -gt "$LIMIT_BYTES" ]; then
    echo "    $name  $bytes bytes  OVER the ADR-0018 §11.9 row 1 budget of $LIMIT_BYTES"
    rc=1
  else
    echo "    $name  $bytes bytes  within $LIMIT_BYTES"
  fi
done

[ "$found" -eq 1 ] || { echo "check-budget.sh: no staticlib in $DIR" >&2; exit 1; }

if [ "$rc" -ne 0 ]; then
  echo "::error::ADR-0018 §11.9 row 1 size budget breached for $PLATFORM" >&2
fi
exit "$rc"
