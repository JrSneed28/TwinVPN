#!/usr/bin/env bash
#
# stage-headers.sh — puts `twinvpn.h` where the module map already says it is.
#
# `Sources/TwinVPNBridge/include/module.modulemap` declares TWO modules:
# `TwinVPNBridge` over the committed internal header, and `TwinVPNCore` over
# `twinvpn.h` — which is NOT committed here, because a second copy of an ABI of
# record is a second thing that can drift from it (README §2, module.modulemap's
# own header).
#
# So the header is COPIED from `core/ffi/include/twinvpn.h` at build time and
# the copy is git-ignored. This script is the one place that copy happens; if
# it ever needs to become a symlink or a header search path instead, it changes
# here and nowhere else.
#
# The copy is made READ-ONLY on the way in. `core-composition` owns that file
# (F-1: every exported function is a compatibility obligation forever), and a
# writable copy inside this shell is an invitation to "fix" the ABI on the wrong
# side of the boundary.

set -euo pipefail

SHELL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="$(cd "$SHELL_DIR/../.." && pwd)"

SRC="$REPO/core/ffi/include/twinvpn.h"
DEST="$SHELL_DIR/Sources/TwinVPNBridge/include/twinvpn.h"

[ -f "$SRC" ] || { echo "stage-headers.sh: $SRC does not exist" >&2; exit 1; }

rm -f "$DEST"
cp "$SRC" "$DEST"
chmod a-w "$DEST"
echo "==> staged $(basename "$SRC") -> Sources/TwinVPNBridge/include/ (read-only)"
