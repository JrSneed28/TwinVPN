#!/usr/bin/env bash
#
# build-bridge.sh — the staticlib `TwinVPNTunnel` links.
#
# ===========================================================================
# WHAT IT PRODUCES
# ===========================================================================
# ADR-0018 §11.9 row 5: macOS is a UNIVERSAL 2 target —
# `aarch64-apple-darwin` and `x86_64-apple-darwin` — and the core reaches it as
# a `staticlib` linked into the system extension, statically. So this builds
# BOTH slices and `lipo`s them into one archive:
#
#   Frameworks/libtwinvpn_bridge.a       universal 2 (arm64 + x86_64)
#   Frameworks/arm64/libtwinvpn_bridge.a   the per-arch slices the budget gate
#   Frameworks/x86_64/libtwinvpn_bridge.a  measures, because the budget is
#                                          "<= 10 MB PER ARCH"
#
# `twinvpn-bridge` and NOT `twinvpn-ffi`: on macOS the authority is the system
# extension (PS-22), and `twinvpn-bridge` is the crate that hosts the `Core`,
# the adapter, the key handle, the datapath and the MI. `twinvpn.h` is not this
# shell's boundary — `twinvpn_bridge.h` is, and README §1 gives the W-24/W-25
# reasons.
#
# ===========================================================================
# WHY A SINGLE ARCH IS AN OPTION AND NOT THE DEFAULT
# ===========================================================================
# `--arch <name>` builds one slice, for a CI job that is only proving the link
# and does not need a shippable universal binary. It is NOT the default,
# because a universal build is what row 5 says ships and a lane that only ever
# built the host's own arch would let the other one rot — which is R-32's
# failure mode exactly.
#
# NOTHING HERE HAS RUN ON A DARWIN BUILDER. `build/ci/ci-macos.sh` is what runs
# it.

set -euo pipefail

SHELL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="$(cd "$SHELL_DIR/../.." && pwd)"

PROFILE="release"
ARCHES=(arm64 x86_64)

while [ $# -gt 0 ]; do
  case "$1" in
    --profile) PROFILE="$2"; shift 2 ;;
    --arch)    ARCHES=("$2"); shift 2 ;;
    *) echo "build-bridge.sh: unknown argument '$1'" >&2; exit 2 ;;
  esac
done

triple_for() {
  case "$1" in
    arm64)  echo "aarch64-apple-darwin" ;;
    x86_64) echo "x86_64-apple-darwin" ;;
    *) echo "build-bridge.sh: unknown arch '$1'" >&2; exit 2 ;;
  esac
}

# The target directory is ASKED FOR, not assumed: this repository shares one
# `CARGO_TARGET_DIR` across its workspaces, so `shells/macos/target` is not
# where the archive lands.
TARGET_DIR="$(cd "$SHELL_DIR" && cargo metadata --format-version 1 --no-deps \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
OUTDIR="$PROFILE"
[ "$PROFILE" = "dev" ] && OUTDIR="debug"

DEST="$SHELL_DIR/Frameworks"
mkdir -p "$DEST"

SLICES=()
for arch in "${ARCHES[@]}"; do
  triple="$(triple_for "$arch")"
  echo "==> cargo build twinvpn-bridge --target $triple --profile $PROFILE"
  # `--locked`, so "which dependency graph produced this archive" is a
  # checkable fact rather than whatever cargo felt like resolving (rule C-5).
  ( cd "$SHELL_DIR" && cargo build --locked -p twinvpn-bridge \
      --profile "$PROFILE" --target "$triple" )

  src="$TARGET_DIR/$triple/$OUTDIR/libtwinvpn_bridge.a"
  [ -f "$src" ] || { echo "build-bridge.sh: cargo produced no $src" >&2; exit 1; }
  mkdir -p "$DEST/$arch"
  cp "$src" "$DEST/$arch/libtwinvpn_bridge.a"
  SLICES+=("$DEST/$arch/libtwinvpn_bridge.a")
  echo "    staged Frameworks/$arch/libtwinvpn_bridge.a ($(wc -c < "$src") bytes)"
done

if [ "${#SLICES[@]}" -gt 1 ]; then
  lipo -create "${SLICES[@]}" -output "$DEST/libtwinvpn_bridge.a"
  echo "==> universal 2: Frameworks/libtwinvpn_bridge.a"
else
  # One slice: copy rather than lipo, so the file at the linked path is always
  # present and `project.yml` needs no conditional.
  cp "${SLICES[0]}" "$DEST/libtwinvpn_bridge.a"
  echo "==> single-arch (${ARCHES[0]}): Frameworks/libtwinvpn_bridge.a"
  echo "    NOT a shippable artifact — ADR-0018 §11.9 row 5 ships universal 2."
fi
