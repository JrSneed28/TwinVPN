#!/usr/bin/env bash
#
# ci-common-apple.sh — the parts `ci-macos.sh` and `ci-ios.sh` must not
# duplicate: the Xcode pin, the toolchain banner, and the assertion that the
# selected Xcode carries the Swift this repository pins.
#
# SOURCED, never executed. It defines functions and one variable and runs
# nothing.
#
# ===========================================================================
# THE XCODE PIN, AND WHERE THE REQUIREMENT COMES FROM
# ===========================================================================
# ADR-0018 §11.3 requires "one exact toolchain version pinned … advanced only by
# a reviewed commit that re-runs the full §11.9 matrix", and `build/toolchain/
# env.sh` applies that discipline to all four toolchains, not only Rust:
#
#     export TWINVPN_SWIFT_VERSION=6.1.2        build/toolchain/env.sh:10
#
# That is the SWIFT pin, and it is the authority here. Xcode is how a Darwin
# builder obtains a Swift compiler, and **Xcode 16.4 is the release that ships
# Swift 6.1.2** — so pinning Xcode is how the Swift pin is honoured on macOS.
# The two move together or not at all, and `require_pinned_swift` below turns
# that from a comment into a check: if the selected Xcode's `swift --version`
# does not report `TWINVPN_SWIFT_VERSION`, the job fails and names both numbers.
#
# The FLOOR is separately documented and is lower: `shells/ios/README.md:79`
# says "Prerequisites: Xcode 15+". 15 is what the sources need; 16.4 is what
# this repository pins. A pin is not a floor and the two must not be conflated —
# a job that accepted "15 or newer" would drift silently, which is precisely the
# R-32 failure ("it does not build for that target any more") arriving one
# runner-image update at a time.
#
# TO CHANGE IT: change `TWINVPN_SWIFT_VERSION` in `build/toolchain/env.sh` and
# `TWINVPN_XCODE_VERSION` here, in ONE commit, and re-run the §11.9 matrix.
# Changing either alone makes every Apple job fail, which is the intended
# behaviour rather than an inconvenience.
#
# WHAT HAPPENS IF THE RUNNER DOES NOT HAVE IT: the job fails, loudly, naming the
# Xcodes it did find. It does NOT fall back to the runner default. A pinned
# toolchain that silently accepts whatever is installed is not a pin.

# The pinned Xcode. See the header for the authority and for how to change it.
TWINVPN_XCODE_VERSION="${TWINVPN_XCODE_VERSION:-16.4}"

# ---------------------------------------------------------------------------
# The developer path of the pinned Xcode.
#
# Prints ONE line on stdout — the path — and every diagnostic on stderr, because
# callers use it as `sudo xcode-select -s "$(ci-macos.sh --print-xcode-path)"`
# and a stray informational line would become part of the path.
# ---------------------------------------------------------------------------
apple_xcode_developer_path() {
  local want="$TWINVPN_XCODE_VERSION"
  local candidate found=""

  # GitHub's macOS images install side-by-side Xcodes as `Xcode_<version>.app`.
  # The exact-version form is tried first; the glob catches point releases that
  # spell themselves `Xcode_16.4.0.app`.
  for candidate in "/Applications/Xcode_${want}.app" "/Applications/Xcode_${want}"*.app; do
    if [ -x "$candidate/Contents/Developer/usr/bin/xcodebuild" ]; then
      found="$candidate"
      break
    fi
  done

  # The default `Xcode.app` counts ONLY if it reports the pinned version. It is
  # checked last, so an image with both a pinned and a default Xcode selects the
  # pinned one.
  if [ -z "$found" ] && [ -x "/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild" ]; then
    if DEVELOPER_DIR="/Applications/Xcode.app/Contents/Developer" \
       xcodebuild -version 2>/dev/null | grep -qx "Xcode ${want}\(\..*\)\?"; then
      found="/Applications/Xcode.app"
    fi
  fi

  if [ -z "$found" ]; then
    {
      echo "no Xcode ${want} on this runner, and this job will not fall back to the default."
      echo "ADR-0018 §11.3 pins one exact toolchain; build/toolchain/env.sh pins Swift"
      echo "${TWINVPN_SWIFT_VERSION:-6.1.2}, and Xcode ${want} is the release that ships it."
      echo "What IS installed:"
      ls -d /Applications/Xcode*.app 2>/dev/null || echo "  (no /Applications/Xcode*.app at all)"
    } >&2
    return 1
  fi

  echo "$found/Contents/Developer"
}

# ---------------------------------------------------------------------------
# The toolchain banner. Every version this job depends on, printed BEFORE any
# work, so a failure report carries the versions that produced it.
# ---------------------------------------------------------------------------
apple_toolchain_banner() {
  local sdk="$1"   # macosx | iphoneos | iphonesimulator

  echo "=== toolchain ==="
  xcodebuild -version
  echo "developer dir: $(xcode-select -p)"
  swift --version
  rustc --version
  cargo --version
  echo "SDK ($sdk): $(xcrun --sdk "$sdk" --show-sdk-version 2>/dev/null || echo unavailable)"
  echo "SDK path:    $(xcrun --sdk "$sdk" --show-sdk-path 2>/dev/null || echo unavailable)"
  echo "xcodegen:    $(xcodegen --version 2>/dev/null || echo 'NOT INSTALLED')"
  sw_vers
  echo
}

# ---------------------------------------------------------------------------
# ADR-0018 §11.3, mechanically: the compiler in the selected Xcode must be the
# version this repository pins.
#
# There is no `|| true` and no warning-only mode. A Swift that is not the pinned
# one produces a different binary, and a lane that tolerated it would report a
# green tick for a toolchain nobody reviewed.
# ---------------------------------------------------------------------------
apple_require_pinned_swift() {
  local want="${TWINVPN_SWIFT_VERSION:?build/toolchain/env.sh was not sourced}"
  local reported
  reported="$(swift --version 2>&1 | head -1)"
  # `swift --version` prints e.g. "Apple Swift version 6.1.2 (swiftlang-…)".
  case "$reported" in
    *"Swift version $want"*) : ;;
    *)
      {
        echo "::error::the selected Xcode carries the wrong Swift."
        echo "  pinned by build/toolchain/env.sh: $want"
        echo "  reported by this toolchain:       $reported"
        echo "  ADR-0018 §11.3: one exact toolchain version, advanced only by a"
        echo "  reviewed commit that re-runs the full §11.9 matrix. Change"
        echo "  TWINVPN_SWIFT_VERSION and TWINVPN_XCODE_VERSION together."
      } >&2
      return 1
      ;;
  esac
  echo "swift ${want} — matches build/toolchain/env.sh"
}

# ---------------------------------------------------------------------------
# XcodeGen. Both shells keep a `project.yml` rather than a committed
# `.xcodeproj`, so the generator is a hard prerequisite and not an optional
# convenience.
# ---------------------------------------------------------------------------
apple_require_xcodegen() {
  if command -v xcodegen >/dev/null; then
    return 0
  fi
  if command -v brew >/dev/null; then
    echo "==> installing xcodegen (brew)"
    brew install --quiet xcodegen
    command -v xcodegen >/dev/null && return 0
  fi
  {
    echo "::error::xcodegen is not installed and could not be installed."
    echo "  Both Apple shells keep an XcodeGen spec rather than a committed"
    echo "  .xcodeproj (shells/ios/project.yml §4). Without the generator there"
    echo "  is no project to build."
  } >&2
  return 1
}

# ---------------------------------------------------------------------------
# The transitions a suite actually observed, as a JSON array.
#
# READ OUT OF THE TEST'S OWN OUTPUT, never written by the caller. A script that
# hard-coded the array would report the same transitions whether or not the test
# drove any — the compile-only-job-dressed-as-a-lifecycle-job the acceptance
# gate exists to reject. An empty array is the correct answer for a run that
# proved linking and nothing else, and `build/acceptance/report.py` fails a PASS
# that claims one.
# ---------------------------------------------------------------------------
apple_transitions_from() {
  # Several logs are accepted, because a platform's transitions may come from
  # more than one vehicle — the evidence file's `notes` says which. A log that
  # does not exist contributes nothing rather than failing: a run that never
  # reached the XCTest step still has a native log worth reading, and the empty
  # array a fully-failed run produces is the CORRECT evidence for it.
  local present=()
  local log
  for log in "$@"; do
    [ -f "$log" ] && present+=("$log")
  done
  if [ "${#present[@]}" -eq 0 ]; then
    echo '[]'
    return 0
  fi
  cat "${present[@]}" \
    | tr -d '\r' \
    | grep -oE '^TWINVPN_LIFECYCLE_TRANSITION [A-Z_]+->[A-Z_]+$' \
    | awk '{print $2}' | sort -u \
    | python3 -c 'import json,sys; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))'
}
