#!/usr/bin/env bash
#
# fetch-wintun.sh -- stage the pinned Wintun driver into build/ci/.cache.
#
# ADR-0021 §11: the upstream Microsoft-signed Wintun binaries ship app-locally
# beside the service, and `build_adapter` refuses to start without `wintun.dll`
# beside it (PS-18). The MSI stages it from `$(var.WinTunDir)`; this lane stages
# it the same way, from the release wintun.net publishes together with its
# SHA-256. The zip carries every architecture; only the amd64 DLL comes out.
#
# WHY THIS IS ITS OWN FILE, AND NOT STILL INLINE IN THE LANE.
#
# There are now TWO consumers on two different sides of the run, and only one
# pinned URL and digest may exist:
#
#   * the DISPOSABLE GUEST, which needs the DLL copied in beside the service --
#     `ci-windows-killswitch.sh`, which runs after the guest exists;
#   * the LAB PEER on L1, which creates its Wintun adapter inside
#     `twinvpn-l1.ps1 -Action Start-Observers` -- BEFORE the guest exists and
#     before that script ever runs.
#
# So the workflow calls this once before `-Action run`, the lane calls it again
# and finds the work already done, and the pin lives in one place. Idempotent:
# an existing zip is re-verified rather than re-downloaded, and the DLL is
# re-extracted from the verified zip every time, so a truncated or hand-edited
# DLL cannot survive a second call.
#
# Prints the absolute path of the DLL on stdout and nothing else, so a caller
# can capture it. Everything else goes to stderr.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck disable=SC1091
. "$REPO/build/ci/digest.sh"

WINTUN_URL='https://www.wintun.net/builds/wintun-0.14.1.zip'
WINTUN_SHA256='07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
CACHE="$REPO/build/ci/.cache"
ZIP="$CACHE/wintun.zip"
DLL="$CACHE/wintun.dll"

mkdir -p "$CACHE"
[ -f "$ZIP" ] || curl -sS --fail --location --retry 3 -o "$ZIP" "$WINTUN_URL" >&2
twinvpn_verify_digest "$ZIP" "$WINTUN_SHA256" "Wintun 0.14.1" >&2

twinvpn_python - "$ZIP" "$DLL" >&2 <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as z, open(sys.argv[2], "wb") as out:
    out.write(z.read("wintun/bin/amd64/wintun.dll"))
PY

[ -s "$DLL" ] || { echo "::error::wintun.dll is empty after extraction" >&2; exit 1; }
echo "staged the pinned Wintun 0.14.1 amd64 driver at $DLL" >&2
echo "$DLL"
