#!/usr/bin/env bash
#
# ci-common-apple.sh — the parts `ci-macos.sh` and `ci-ios.sh` must not
# duplicate: the Xcode pin, the toolchain banner, and the assertion that the
# selected Xcode carries the Swift this repository pins.
#
# SOURCED, never executed. It defines functions and two variables and runs
# nothing.
#
# ===========================================================================
# THE XCODE PIN, AND WHERE THE REQUIREMENT COMES FROM
# ===========================================================================
# ADR-0018 §11.3 requires "one exact toolchain version pinned … advanced only by
# a reviewed commit that re-runs the full §11.9 matrix". §11.9 rows 1, 2 and 5
# name the Apple toolchain as "Xcode + pinned Rust" — so on a Darwin builder the
# thing that must be pinned to one exact version is XCODE, and the Swift
# compiler is whatever that Xcode ships.
#
# TWO CONSTANTS, AND THEY ARE ONE FACT
#
#     TWINVPN_XCODE_VERSION=26.6           the pin
#     TWINVPN_XCODE_SWIFT_VERSION=6.3.3    the Swift that pin ships
#
# The second is not an independent choice. It is derived from the first, from
# swift.org's own release index — `_data/builds/swift_releases.yml` in
# swiftlang/swift-org-website, which carries `- name: "6.3.3" … xcode: Xcode
# 26.6, xcode_release: true`:
#
#   https://raw.githubusercontent.com/swiftlang/swift-org-website/main/_data/builds/swift_releases.yml
#
# `apple_require_pinned_swift` below asserts it at run time, so a runner-image
# update that quietly moved Swift under a same-named Xcode fails the job instead
# of changing the binary nobody reviewed.
#
# WHY 26.6 AND NOT SOMETHING ELSE. Both Apple jobs run on `macos-26`, and the
# runner image ships Xcode 26.0.1 … 26.6 side by side with **26.6 as the image
# default** (`/Applications/Xcode_26.6.app`, build 17F113, aliased as
# `/Applications/Xcode.app`):
#
#   https://github.com/actions/runner-images/blob/main/images/macos/macos-26-Readme.md
#
# Pinning the image default is the version with the longest life on that image
# and the one Apple's own tooling treats as current.
#
# ===========================================================================
# WHY THIS IS NOT `TWINVPN_SWIFT_VERSION`
# ===========================================================================
# `build/toolchain/env.sh:9` sets `TWINVPN_SWIFT_VERSION=6.1.2`, and an earlier
# revision of this file read that variable as the Darwin Swift pin. It is not
# one, and reading it as one is what put `TWINVPN_XCODE_VERSION=16.4` here —
# a version `macos-26` does not carry at all, so `--print-xcode-path` resolved
# to the empty string and `xcode-select -s ""` failed both Apple jobs in their
# first step.
#
# What that variable actually governs is the LINUX-HOSTED Swift toolchain: the
# user-local install `build/toolchain/install-swift.sh` unpacks into
# `$SWIFT_HOME`, which `make swift-parse` then uses to `swiftc -parse` the two
# Apple shells on a host with no Darwin SDK. That toolchain never compiles a
# shipped Apple artifact — `shells/macos/README.md:32` says so directly ("Swift
# 6.1.2 here is the Linux toolchain with no Darwin SDK") — and its version is
# fixed independently at `install-swift.sh:16`, which does not read
# `TWINVPN_SWIFT_VERSION` either.
#
# So the two pins are genuinely separate toolchains with separate jobs, and
# neither has to equal the other. Nothing forces them together: both Apple
# shells set the Xcode build setting `SWIFT_VERSION: "5.9"` (`shells/*/
# project.yml`), which is the LANGUAGE MODE, not the compiler version, and every
# Swift 6.x compiler implements it. The Linux parse check running an OLDER
# compiler than the Darwin build is the conservative direction: syntax Linux
# accepts, Darwin accepts.
#
# TO CHANGE THE APPLE PIN: change `TWINVPN_XCODE_VERSION` and
# `TWINVPN_XCODE_SWIFT_VERSION` here, in ONE commit, re-derived from the
# swift.org index above, and re-run the §11.9 matrix. Changing either alone
# makes every Apple job fail at `apple_require_pinned_swift`, which is the
# intended behaviour rather than an inconvenience.
#
# THE FLOOR IS SEPARATE AND LOWER: `shells/ios/README.md` says "Prerequisites:
# Xcode 15+". 15 is what the sources need; 26.6 is what this repository pins. A
# pin is not a floor and the two must not be conflated — a job that accepted "15
# or newer" would drift silently, which is precisely the R-32 failure ("it does
# not build for that target any more") arriving one runner-image update at a
# time.
#
# WHAT HAPPENS IF THE RUNNER DOES NOT HAVE IT: the job fails, loudly, naming the
# Xcodes it did find. It does NOT fall back to the runner default. A pinned
# toolchain that silently accepts whatever is installed is not a pin.

# The pinned Xcode. See the header for the authority and for how to change it.
TWINVPN_XCODE_VERSION="${TWINVPN_XCODE_VERSION:-26.6}"

# The Swift that pinned Xcode ships, per swift.org's release index. DERIVED from
# the line above, never chosen independently; `apple_require_pinned_swift`
# asserts it.
TWINVPN_XCODE_SWIFT_VERSION="${TWINVPN_XCODE_SWIFT_VERSION:-6.3.3}"

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
  # spell themselves `Xcode_26.6.0.app`.
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
      echo "ADR-0018 §11.3 pins one exact toolchain. build/ci/ci-common-apple.sh pins"
      echo "Xcode ${want}, which ships Swift ${TWINVPN_XCODE_SWIFT_VERSION}."
      echo "If this runner image no longer carries that Xcode, the fix is a REVIEWED"
      echo "commit that moves TWINVPN_XCODE_VERSION and TWINVPN_XCODE_SWIFT_VERSION"
      echo "together and re-runs the ADR-0018 §11.9 matrix — not a fallback here."
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
# one this repository's Xcode pin ships.
#
# The expected version is `TWINVPN_XCODE_SWIFT_VERSION` — declared at the top of
# this file and DERIVED from `TWINVPN_XCODE_VERSION` via swift.org's release
# index — and NOT `TWINVPN_SWIFT_VERSION`, which pins the Linux-hosted parse
# toolchain and never compiles a Darwin artifact. The header says why.
#
# What it fails on. Three cases, all loudly, with no `|| true` and no
# warning-only mode:
#
#   1. `swift --version` printing no parsable version at all — a broken or
#      absent toolchain, which must not read as a pass.
#   2. A version that is not EXACTLY the expected one. Exactly: `6.3` is not
#      `6.3.3`, and the substring match this function used to do would have let
#      a point release through.
#   3. `TWINVPN_XCODE_SWIFT_VERSION` unset, i.e. this file not sourced.
#
# A Swift that is not the pinned one produces a different binary, and a lane
# that tolerated it would report a green tick for a toolchain nobody reviewed.
# ---------------------------------------------------------------------------
apple_require_pinned_swift() {
  local want="${TWINVPN_XCODE_SWIFT_VERSION:?build/ci/ci-common-apple.sh was not sourced}"
  local reported detected

  # On an Xcode toolchain the first line is
  #   "Apple Swift version 6.3.3 (swiftlang-6.3.3.x.y clang-…)"
  # sometimes prefixed by "swift-driver version: 1.x ". The number is EXTRACTED
  # and compared for equality rather than substring-matched, so "6.3" cannot
  # satisfy an assertion that wants "6.3.3".
  reported="$(swift --version 2>&1 | head -1)"
  detected="$(printf '%s' "$reported" | sed -n 's/.*Swift version \([0-9][0-9.]*\).*/\1/p')"

  if [ "$detected" = "$want" ]; then
    echo "swift ${want} — matches the Xcode ${TWINVPN_XCODE_VERSION} pin in build/ci/ci-common-apple.sh"
    return 0
  fi

  {
    echo "::error::the selected Xcode carries the wrong Swift."
    echo "  pinned Xcode:                  ${TWINVPN_XCODE_VERSION} (build/ci/ci-common-apple.sh)"
    echo "  Swift that Xcode should ship:  $want"
    if [ -n "$detected" ]; then
      echo "  Swift this toolchain reports:  $detected"
    else
      echo "  Swift this toolchain reports:  (no version could be parsed)"
    fi
    echo "  raw \`swift --version\`:         $reported"
    echo "  developer dir:                 $(xcode-select -p 2>&1)"
    echo
    echo "  ADR-0018 §11.3: one exact toolchain version, advanced only by a"
    echo "  reviewed commit that re-runs the full §11.9 matrix. If the runner"
    echo "  image moved Swift under this Xcode, re-derive the pair from"
    echo "  swift.org's release index and change TWINVPN_XCODE_VERSION and"
    echo "  TWINVPN_XCODE_SWIFT_VERSION together. Do not relax this check."
  } >&2
  return 1
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
# WHY A FAILURE HAS TO BE ECHOED A SECOND TIME
#
# In run 33286355061 the iOS job refused with "the shared core did not compile
# for aarch64-apple-ios and/or aarch64-apple-ios-sim" and the reason — one line
# from bash — sat inside a collapsed `::group::`, between four hundred
# `Downloaded` lines and a `::error::` annotation emitted twenty-four seconds
# later that named only the verdict. The macOS job printed its `E0463` in the
# clear and was diagnosable in one round trip; the iOS job was not, and cost a
# whole one. A proof script that refuses without saying why is not cheaper than
# no proof script — it is more expensive, once per iteration.
#
# So the failure path re-states the diagnostic in a group of ITS OWN, opened
# after the step's group has been closed: GitHub does not nest groups, and a
# diagnostic reachable only by expanding the group it drowned in is the failure
# this function exists to prevent. The full output stays in `$log` for the
# diagnostics artifact — this is in ADDITION to the capture, never instead of it.
#
# `awk` and not `grep`, because `grep` exits 1 when nothing matches and these
# scripts forbid `|| true`; `awk` always exits 0 and can say so itself.
# ---------------------------------------------------------------------------
apple_show_failure() {
  local label="$1" log="$2"

  echo "::group::FAILED: $label — the diagnostic, repeated"
  if [ -s "$log" ]; then
    echo "--- lines matching a diagnostic pattern, from $log ---"
    # The `(^|[^a-z])` prefix is what keeps `Compiling thiserror v2.0.20` out of
    # a list that is supposed to be only the reasons the step failed.
    awk '
      tolower($0) ~ /(^|[^a-z])(error|fatal|panicked|cannot find|could not compile|undefined symbol|unbound variable|no such file|not installed|linker command failed|ld: )/ {
        print; matched++
      }
      END {
        if (!matched)
          print "(nothing matched; the tail below and the diagnostics artifact carry the rest)"
      }
    ' "$log" | tail -n 100
    echo "--- last 40 lines of $log ---"
    tail -n 40 "$log"
  else
    echo "(the step produced NO output at all; $log is empty or absent)"
  fi
  echo "::endgroup::"
}

# ---------------------------------------------------------------------------
# One build step: grouped, streamed, CAPTURED, and explained when it fails.
#
#   apple_build_step "<label>" "<log>" <command> [args...]
#
# `tee` rather than a plain redirect, so a PASSING run still shows progress live
# and a reader is not left watching a silent runner for two minutes. The status
# returned is the STEP's, taken from `PIPESTATUS`, never `tee`'s — which is
# always 0 and would turn every failure into a pass.
#
# There is no `|| true`: a caller that wants to continue past a failure has to
# say so with its own `||`, in the open.
# ---------------------------------------------------------------------------
apple_build_step() {
  local label="$1" log="$2"
  shift 2
  local rc=0

  mkdir -p "$(dirname "$log")"
  echo "::group::$label"
  set +e
  "$@" 2>&1 | tee "$log"
  rc=${PIPESTATUS[0]}
  set -e
  echo "::endgroup::"

  if [ "$rc" -ne 0 ]; then
    apple_show_failure "$label (exit $rc)" "$log"
  fi
  return "$rc"
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
  local found=0
  local log
  for log in "$@"; do
    # `if`, not `[ -f ] &&`. Under `set -e` a `for` loop's exit status is its
    # last command's, so a final iteration whose test is FALSE returned 1 and
    # killed the caller -- for the ordinary reason that the last log named does
    # not exist yet.
    if [ -f "$log" ]; then
      present+=("$log")
      found=$((found + 1))
    fi
  done
  # A COUNTER, not `${#present[@]}`.
  #
  # macOS ships bash 3.2.57, where an empty array under `set -u` is an unbound
  # variable -- the same trap that killed every `full`-profile core build until
  # build-core.sh got `${FEATURE_ARGS[@]+...}`. `${#present[@]}` on an empty
  # array is that trap a second time, and it fires on exactly the path this
  # function exists to serve: a run where none of the named logs was written.
  # A plain integer has no such edge, and the expansion below is guarded the
  # same way build-core.sh's is.
  if [ "$found" -eq 0 ]; then
    echo '[]'
    return 0
  fi
  # ONE `awk`, not `grep | awk`.
  #
  # The banner above this function says "`awk` and not `grep`, because `grep`
  # exits 1 when nothing matches and these scripts forbid `|| true`" -- and
  # then this pipeline used `grep`. Under `set -o pipefail` a log with no
  # marker made grep exit 1, the pipeline inherit it, and `set -e` kill the
  # script BEFORE it wrote its evidence file.
  #
  # That is every failing run. It is why build/ci/evidence/ has only
  # linux.json: a real macOS or iOS failure destroyed the evidence that would
  # have named it, the `if-no-files-found: error` upload stacked a second red
  # on top, and build/acceptance/report.py then read NOT-EXECUTED -- making a
  # genuine failure indistinguishable from a platform that never ran.
  #
  # An empty array is the CORRECT evidence for a run that reached no
  # transition. It must be produced, not thrown.
  cat ${present[@]+"${present[@]}"} \
    | tr -d '\r' \
    | awk '/^TWINVPN_LIFECYCLE_TRANSITION [A-Z_]+->[A-Z_]+$/ { print $2 }' \
    | sort -u \
    | python3 -c 'import json,sys; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))'
}
