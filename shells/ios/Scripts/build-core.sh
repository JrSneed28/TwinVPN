#!/usr/bin/env bash
#
# build-core.sh — the two staticlibs `shells/ios/project.yml` links.
#
# ===========================================================================
# WHAT IT PRODUCES, AND WHY THE LAYOUT IS PER-PLATFORM
# ===========================================================================
# ADR-0018 §11.9 row 1: the core reaches iOS as a `staticlib` linked into the
# NE extension, statically, with the system libraries dynamic. §11.12 gives the
# app the `core-lite` profile of the SAME source (schema, crypto VERIFICATION
# ONLY, store, trust, diag — and no data-plane crate), and S-46 records which
# profile a build carries.
#
# The device and the simulator are DIFFERENT TRIPLES producing archives that
# cannot be interchanged, so the output is keyed by Xcode's own `PLATFORM_NAME`:
#
#   Frameworks/iphoneos/libtwinvpn_core.a           full,      aarch64-apple-ios
#   Frameworks/iphoneos/libtwinvpn_core_lite.a      core-lite, aarch64-apple-ios
#   Frameworks/iphonesimulator/libtwinvpn_core.a    full,      *-apple-ios-sim
#   Frameworks/iphonesimulator/libtwinvpn_core_lite.a
#
# `project.yml` sets LIBRARY_SEARCH_PATHS to
# `$(SRCROOT)/Frameworks/$(PLATFORM_NAME)`, so one project builds for both and
# neither can silently link the other's archive — which is the failure a single
# flat `Frameworks/` directory invites.
#
# ===========================================================================
# WHY `twinvpn-ffi` AND NOT `twinvpn-core`
# ===========================================================================
# CD-I5: a shell links the ABI crate, never the core crate directly.
# `twinvpn-ffi` is the `twinvpn.h` surface and the only crate that exports it;
# its `[lib] crate-type` already carries `staticlib`. The archive is RENAMED on
# the way out — `libtwinvpn_ffi.a` -> `libtwinvpn_core.a` — because
# `project.yml` and `Package.swift` both name `-ltwinvpn_core`, and the two
# profiles must be distinguishable by filename inside one directory.
#
# NOTHING HERE HAS RUN ON A DARWIN BUILDER. It is written against the
# documented cargo and Xcode behaviour; `build/ci/ci-ios.sh` is what runs it,
# and the first person with a Mac should expect to correct it.

set -euo pipefail

SHELL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="$(cd "$SHELL_DIR/../.." && pwd)"

TARGET=""
PROFILE="release"
FEATURES=""

while [ $# -gt 0 ]; do
  case "$1" in
    --target)   TARGET="$2"; shift 2 ;;
    --profile)  PROFILE="$2"; shift 2 ;;
    --features) FEATURES="$2"; shift 2 ;;
    *) echo "build-core.sh: unknown argument '$1'" >&2; exit 2 ;;
  esac
done

[ -n "$TARGET" ] || { echo "build-core.sh: --target is required" >&2; exit 2; }

# Xcode's own name for the platform, so the staging directory and
# LIBRARY_SEARCH_PATHS cannot disagree.
case "$TARGET" in
  *-apple-ios-sim|x86_64-apple-ios) PLATFORM_NAME="iphonesimulator" ;;
  *-apple-ios)                      PLATFORM_NAME="iphoneos" ;;
  *) echo "build-core.sh: '$TARGET' is not an iOS triple" >&2; exit 2 ;;
esac

# `core-lite` is a NO-DEFAULT-FEATURES selection, not an addition: `full` and
# `core-lite` are alternatives on `twinvpn-ffi`, and enabling both would build
# the data-plane crates into the archive the APP links — exactly what §11.12's
# profile split exists to prevent.
ARCHIVE="libtwinvpn_core.a"
FEATURE_ARGS=()
if [ "$FEATURES" = "core-lite" ]; then
  ARCHIVE="libtwinvpn_core_lite.a"
  FEATURE_ARGS=(--no-default-features --features core-lite)
elif [ -n "$FEATURES" ]; then
  echo "build-core.sh: --features accepts only 'core-lite' (default is the shipped 'full')" >&2
  exit 2
fi

echo "==> cargo build twinvpn-ffi --target $TARGET --profile $PROFILE ${FEATURE_ARGS[*]:-(full)}"
( cd "$REPO/core" && cargo build --locked -p twinvpn-ffi \
    --profile "$PROFILE" --target "$TARGET" "${FEATURE_ARGS[@]}" )

# `--profile dev` writes to `debug/`; every other profile writes to its own
# name. The target directory itself is asked for rather than assumed: this
# repository shares one `CARGO_TARGET_DIR` across its workspaces, so
# `core/target` is NOT where the archive lands.
TARGET_DIR="$(cd "$REPO/core" && cargo metadata --format-version 1 --no-deps \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
OUTDIR="$PROFILE"
[ "$PROFILE" = "dev" ] && OUTDIR="debug"

SRC="$TARGET_DIR/$TARGET/$OUTDIR/libtwinvpn_ffi.a"
[ -f "$SRC" ] || { echo "build-core.sh: cargo produced no $SRC" >&2; exit 1; }

DEST="$SHELL_DIR/Frameworks/$PLATFORM_NAME"
mkdir -p "$DEST"
cp "$SRC" "$DEST/$ARCHIVE"
echo "    staged $DEST/$ARCHIVE ($(wc -c < "$DEST/$ARCHIVE") bytes)"
