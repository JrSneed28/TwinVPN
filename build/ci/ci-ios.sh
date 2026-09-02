#!/usr/bin/env bash
#
# ci-ios.sh — the iOS/iPadOS platform link/run evidence.
#
# ===========================================================================
# WHAT THIS PROVES, AND WHAT IT REFUSES TO CLAIM
# ===========================================================================
# The boundary on this platform is `core/ffi/include/twinvpn.h` — the ABI OF
# RECORD — reached from Swift through
# `shells/ios/Sources/TwinVPNBridge/include/module.modulemap`. ADR-0018 §11.9
# row 1 says the core arrives as a `staticlib` linked into the NE extension, and
# §11.12 gives the app the `core-lite` profile of the same source. Both are
# built and both are linked here, into the REAL production targets.
#
# Two modes, two evidence files, and they are DIFFERENT EVIDENCE:
#
#   (default)  HOSTED SIMULATOR  -> build/ci/evidence/ios.json
#              privileged: false. Builds the real app target and the real
#              packet-tunnel NetworkExtension target for the device SDK, links
#              the approved shared core into both, boots a simulator, and runs
#              `TwinVPNIntegrationTests` — which crosses `tw_core_create`,
#              submits the four ADR-0018 §11.16 (e) lifecycle phases, and reads
#              each completion back off `tw_core_next_event`.
#
#   --device   SELF-HOSTED, PHYSICAL DEVICE -> build/ci/evidence/ios-device.json
#              NO LONGER PART OF THE ACCEPTANCE GATE. The criteria it used to
#              discharge are `build/ci/ci-ios-corellium.sh`'s, on a
#              non-jailbroken Corellium virtual iPhone, because local hardware is
#              no longer an acceptable dependency for the gate. Kept: it is still
#              the way to reproduce a run on a phone you own.
#              privileged: true. Runs `TwinVPNTests` — the suite that skips
#              itself on a simulator — against a provisioned iPhone or iPad,
#              where a NetworkExtension can actually be activated.
#
# **THE SIMULATOR RUN IS NOT THE DEVICE RUN.** `shells/ios/TwinVPNTests/
# LifecycleTests.swift` says why in its own header: "The simulator has no Secure
# Enclave, no jetsam, and no real `includeAllNetworks`, so every assertion here
# is vacuous on it." The two write different files, carry different `privileged`
# values, and neither may be read as the other.
#
# ===========================================================================
# NOTHING HERE HAS EVER RUN
# ===========================================================================
# Written on a Linux host with no Xcode, no Darwin SDK, no XcodeGen and no
# simulator. What HAS been verified locally is narrow and is stated in the wave
# report. Every `xcodebuild` and `simctl` invocation below is unrun.
#
# There is no `|| true` anywhere below.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# `twinvpn_run_attempt_json`, `twinvpn_sha256`, `twinvpn_verify_digest` and
# `twinvpn_digest_json`. Sourced rather than reimplemented per script: the
# sha256 command differs on every host this repository runs on, and a digest
# helper that silently produced nothing on one of them would bind the evidence
# to no bytes at all.
# shellcheck disable=SC1091
. "$REPO/build/ci/digest.sh"
SHELL_DIR="$REPO/shells/ios"
LOGDIR="$REPO/build/ci/logs/ios"

MODE="link-run"
case "${1:-}" in
  --print-xcode-path) MODE="print-xcode-path" ;;
  --reset)            MODE="reset" ;;
  --device)           MODE="device" ;;
  --acceptance)       MODE="acceptance" ;;
  --cleanup)          MODE="cleanup" ;;
  "")                 MODE="link-run" ;;
  *) echo "ci-ios.sh: unknown argument '$1'" >&2; exit 2 ;;
esac

# --------------------------------------------------------------------------
# --acceptance: the HOSTED-SIMULATOR acceptance rows,
# `IOS-FAILCLOSED-CONFIGURATION` and `IOS-PROFILE-REMOVAL-HONESTY`.
#
# A SEPARATE SCRIPT, dispatched here so there is one entry point per platform
# and `make ci-ios` stays the door everything goes through. It is separate
# because it is a different claim with different evidence — two version-2 files
# with an environment attestation, against this file's one version-1 link/run
# row — and because folding it in would put this file well past the 500-line
# limit `CLAUDE.md` sets.
#
# `exec`, so the acceptance lane's exit status is this script's with nothing in
# between to swallow it.
# --------------------------------------------------------------------------
if [ "$MODE" = "acceptance" ]; then
  exec "$REPO/build/ci/ci-ios-acceptance.sh"
fi

# shellcheck disable=SC1091
source "$REPO/build/toolchain/env.sh"
# shellcheck disable=SC1091
source "$REPO/build/ci/ci-common-apple.sh"

if [ "$MODE" = "print-xcode-path" ]; then
  apple_xcode_developer_path
  exit 0
fi

# --------------------------------------------------------------------------
# --cleanup: `if: always()`, so idempotent, tolerant of a run that never
# started, and never the cause of a job failure.
#
# On iOS there is no host firewall and no route table of ours to unwind — the
# tunnel state lives inside the device's own VPN configuration. What a device
# run CAN leave behind is an installed VPN profile and a booted simulator, and
# both are removed here. Uninstalling the app is what removes its profile:
# `TwinVPNTests`' own header notes that "no API removes our own profile".
# --------------------------------------------------------------------------
if [ "$MODE" = "cleanup" ]; then
  echo "=== cleanup: returning the runner to a known state ==="
  mkdir -p "$LOGDIR"
  {
    if command -v xcrun >/dev/null; then
      echo "--- booted simulators ---"
      xcrun simctl list devices booted 2>&1 || echo "(simctl unavailable)"
      # Shut every booted simulator, then uninstall our bundles from all of
      # them. `simctl shutdown all` is idempotent and succeeds with none booted.
      xcrun simctl shutdown all 2>&1 || echo "(nothing to shut down)"
      xcrun simctl uninstall booted net.twinvpn.client 2>&1 || echo "(no app on a booted simulator)"
      # And the acceptance lane's own bundle, which `--acceptance` installs
      # alongside the app. Listed explicitly rather than left to the app
      # uninstall: it is a separate bundle identifier and a separate install.
      xcrun simctl uninstall booted net.twinvpn.client.acceptancetests 2>&1 \
        || echo "(no acceptance bundle on a booted simulator)"
    fi

    # A physical device, when one is attached. `devicectl` is Xcode 15+'s
    # supported path; uninstalling the container app removes the extension and
    # the VPN configuration it installed with it.
    if command -v xcrun >/dev/null && [ -n "${TWINVPN_IOS_DEVICE_UDID:-}" ]; then
      echo "--- uninstalling from device ${TWINVPN_IOS_DEVICE_UDID} ---"
      xcrun devicectl device uninstall app \
        --device "$TWINVPN_IOS_DEVICE_UDID" net.twinvpn.client 2>&1 \
        || echo "(nothing installed, or devicectl declined)"
    fi
  } | tee "$LOGDIR/cleanup.log"
  echo "=== cleanup done ==="
  exit 0
fi

# --------------------------------------------------------------------------
# --reset: rule C-5 binds a verdict to an exact commit or immutable snapshot,
# and a generated project, a staged archive or a stale evidence file is none of
# those.
# --------------------------------------------------------------------------
if [ "$MODE" = "reset" ]; then
  echo "=== reset: discarding generated and staged artifacts ==="
  rm -rf "$SHELL_DIR/TwinVPN.xcodeproj" "$SHELL_DIR/Frameworks"
  rm -f "$SHELL_DIR/Sources/TwinVPNBridge/include/twinvpn.h"
  rm -rf "$LOGDIR"
  rm -f "$REPO/build/ci/evidence/ios.json" "$REPO/build/ci/evidence/ios-device.json" \
        "$REPO/build/ci/evidence/ios-failclosed-configuration.json" \
        "$REPO/build/ci/evidence/ios-profile-removal.json"
  "$0" --cleanup
  echo "=== reset done ==="
  exit 0
fi

# ==========================================================================
# The link/run itself.
# ==========================================================================
PRIVILEGED=false
EVIDENCE="$REPO/build/ci/evidence/ios.json"
JOB_DEFAULT="ios-link-run"
if [ "$MODE" = "device" ]; then
  PRIVILEGED=true
  EVIDENCE="$REPO/build/ci/evidence/ios-device.json"
  JOB_DEFAULT="ios-device-lifecycle"
fi

mkdir -p "$(dirname "$EVIDENCE")" "$LOGDIR"

apple_toolchain_banner iphoneos
apple_require_pinned_swift
apple_require_xcodegen

compiled=false
linked=false
loaded=false
invoked=false
received=false
shutdown=false
transitions='[]'
notes=""
exit_code=0

# The Rust targets §11.9 row 1 needs, plus the simulator triple the integration
# suite runs on. `rustup target add` is idempotent.
rustup target add aarch64-apple-ios aarch64-apple-ios-sim >/dev/null

# --- 1. compile the shared core for both profiles and both platforms --------
#
# FOUR archives, and each pair is required:
#   device / full        the NE extension's, ADR-0018 §11.9 row 1
#   device / core-lite   the app's, ADR-0018 §11.12 (S-46 records the profile)
#   sim    / full        what the integration suite links
#   sim    / core-lite   so a simulator build of the APP links the same profile
#                        the device build does, rather than silently the other
#
# One `apple_build_step` per archive rather than one group around all four: the
# output is captured for the diagnostics artifact AND, when a build fails, its
# diagnostic is echoed again outside the group it failed inside. Run
# 33286355061 is why — see `apple_show_failure`'s header in ci-common-apple.sh.
core_ok=true
for target in aarch64-apple-ios aarch64-apple-ios-sim; do
  apple_build_step "compile twinvpn-ffi (full) for $target" \
    "$LOGDIR/core-$target-full.log" \
    "$SHELL_DIR/Scripts/build-core.sh" --target "$target" --profile release \
    || core_ok=false
  apple_build_step "compile twinvpn-ffi (core-lite) for $target" \
    "$LOGDIR/core-$target-core-lite.log" \
    "$SHELL_DIR/Scripts/build-core.sh" --target "$target" --profile release --features core-lite \
    || core_ok=false
done
if [ "$core_ok" = true ]; then
  compiled=true
else
  notes="the shared core did not compile for aarch64-apple-ios and/or aarch64-apple-ios-sim; the failing build's diagnostic is echoed above and the whole log is in build/ci/logs/ios/core-*.log"
fi

# --- 1b. the size budget, which R-32 makes a blocker ------------------------
#
# The DEVICE slice only. A simulator archive is not a shipping artifact and its
# size says nothing about what the App Store receives.
if [ "$compiled" = true ]; then
  echo "::group::ADR-0018 §11.9 row 1 size budget (device slice)"
  "$SHELL_DIR/Scripts/check-budget.sh" iphoneos
  echo "::endgroup::"
fi

# --- 1c. chrome strings stay off the reason-code path -----------------------
#
# Cheap, Linux-runnable, and it guards a defect that shipped: eleven UI chrome
# strings were resolved as REASON CODES through tw_render_diagnostic, so
# ObservedReasonCode::parse rejected the lowercase `ui`, the domain fell back
# to INTERNAL, and every tab, title and button rendered "TwinVPN hit a defect
# in itself." on a VPN. It is a PC-3 prohibited rendering and nothing in the
# build caught it, because a wrong reason code is a valid string.
#
# This runs BEFORE the project is generated, so a regression costs seconds
# rather than a full simulator round trip.
echo "::group::chrome strings are not reason codes"
"$SHELL_DIR/Scripts/check-chrome-strings.sh"
echo "::endgroup::"

# --- 2. stage the ABI of record and generate the project --------------------
if [ "$compiled" = true ]; then
  echo "::group::stage twinvpn.h and generate the project"
  "$SHELL_DIR/Scripts/stage-headers.sh"
  set +e
  ( cd "$SHELL_DIR" && xcodegen generate ) 2>&1 | tee "$LOGDIR/xcodegen.log"
  gen_rc=${PIPESTATUS[0]}
  set -e
  echo "::endgroup::"
  # Fatal — there is no project to build — but the generator's own complaint is
  # echoed outside the group first. Before this, `set -e` killed the script
  # mid-group and the reason stayed folded away.
  if [ "$gen_rc" -ne 0 ]; then
    apple_show_failure "xcodegen generate (exit $gen_rc)" "$LOGDIR/xcodegen.log"
    exit "$gen_rc"
  fi
fi

# --- 3. BUILD THE PRODUCTION TARGETS, for the real device SDK ---------------
#
# `TwinVPN` (the app) and `TwinVPNProvider` (the packet-tunnel
# NetworkExtension), for `generic/platform=iOS` — the DEVICE SDK, not the
# simulator's. This is the build that proves the approved shared core links into
# the production targets, and doing it against the device SDK is the point: a
# simulator-only build would not exercise `aarch64-apple-ios` at all.
#
# Unsigned. A hosted runner has no provisioning profile carrying
# `packet-tunnel-provider`, and ADR-0021's signing is a release concern. What is
# being proven here is the LINK, and a link does not need a signature.
if [ "$compiled" = true ]; then
  echo "::group::build TwinVPN.app + TwinVPNProvider.appex (device SDK)"
  set +e
  xcodebuild build \
    -project "$SHELL_DIR/TwinVPN.xcodeproj" \
    -scheme TwinVPNIntegration \
    -destination 'generic/platform=iOS' \
    -derivedDataPath "$LOGDIR/DerivedData" \
    CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY="" \
    2>&1 | tee "$LOGDIR/build-products.log"
  build_rc=${PIPESTATUS[0]}
  set -e
  echo "::endgroup::"

  if [ "$build_rc" -eq 0 ]; then
    linked=true
  else
    apple_show_failure "build TwinVPN.app + TwinVPNProvider.appex (exit $build_rc)" \
      "$LOGDIR/build-products.log"
    notes="${notes:+$notes; }the iOS app and/or NetworkExtension did not link the shared core; see build/ci/logs/ios/build-products.log"
    exit_code=$build_rc
  fi
fi

# --- 4/5/6. boot the target, cross the production bridge, drive the ----------
#            lifecycle, and shut down.
if [ "$linked" = true ]; then
  if [ "$MODE" = "device" ]; then
    # ------------------------------------------------------------------
    # THE PHYSICAL-DEVICE PATH. A different suite, a different claim.
    # ------------------------------------------------------------------
    # No apostrophe in this message: bash parses `${VAR:?word}` before the
    # enclosing double quotes, so a `'` here terminates nothing and unbalances
    # the whole file. Found by `bash -n`, which is why `bash -n` is in the
    # verification list.
    DEVICE_UDID="${TWINVPN_IOS_DEVICE_UDID:?--device needs TWINVPN_IOS_DEVICE_UDID, the identifier of the provisioned device}"
    SCHEME="TwinVPN"
    TEST_CMD="xcodebuild test -scheme TwinVPN -destination id=$DEVICE_UDID"
    RESULT_BUNDLE="$LOGDIR/TwinVPNTests-device.xcresult"

    echo "::group::XCTest on a provisioned physical device"
    set +e
    # SIGNED, because a NetworkExtension cannot be activated otherwise. The
    # identity and the team come from the runner keychain and from the runner
    # environment, and NEITHER is interpolated into any string this script
    # prints, echoes or writes into the evidence file. `xcodebuild` does not
    # print a private key at any verbosity, and nothing here raises the
    # verbosity or adds `-showBuildSettings` (which would dump the whole
    # environment, provisioning identifiers included).
    xcodebuild test \
      -project "$SHELL_DIR/TwinVPN.xcodeproj" \
      -scheme "$SCHEME" \
      -destination "id=$DEVICE_UDID" \
      -derivedDataPath "$LOGDIR/DerivedData" \
      -resultBundlePath "$RESULT_BUNDLE" \
      -allowProvisioningUpdates \
      2>&1 | tee "$LOGDIR/xctest-device.log"
    test_rc=${PIPESTATUS[0]}
    set -e
    echo "::endgroup::"
    TEST_LOG="$LOGDIR/xctest-device.log"
  else
    # ------------------------------------------------------------------
    # THE SIMULATOR PATH.
    # ------------------------------------------------------------------
    SCHEME="TwinVPNIntegration"
    RESULT_BUNDLE="$LOGDIR/TwinVPNIntegrationTests.xcresult"

    echo "::group::boot a simulator"
    # The selection rule and the iOS 15 floor live in `ci-common-apple.sh`, so
    # that this lane and `ci-ios-acceptance.sh` cannot disagree about which
    # runtime is acceptable.
    SIM_UDID="$(apple_boot_ios_simulator "$LOGDIR/simulators.log")"
    echo "::endgroup::"

    TEST_CMD="xcodebuild test -scheme TwinVPNIntegration -destination id=$SIM_UDID"

    echo "::group::XCTest across the production shared-core bridge (simulator)"
    set +e
    xcodebuild test \
      -project "$SHELL_DIR/TwinVPN.xcodeproj" \
      -scheme "$SCHEME" \
      -destination "id=$SIM_UDID" \
      -derivedDataPath "$LOGDIR/DerivedData" \
      -resultBundlePath "$RESULT_BUNDLE" \
      CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY="" \
      2>&1 | tee "$LOGDIR/xctest.log"
    test_rc=${PIPESTATUS[0]}
    set -e
    echo "::endgroup::"
    TEST_LOG="$LOGDIR/xctest.log"
  fi

  if [ "$test_rc" -eq 0 ]; then
    # The bundle ran, so the archive loaded. The suite's first case compares
    # `tw_abi_major()` against the header's `TW_ABI_MAJOR`, and its second reads
    # S-46's `CoreBuildIdentity` out of the artifact — neither can pass unless
    # real, built core code executed.
    loaded=true
    invoked=true
    received=true
    shutdown=true
  else
    apple_show_failure "XCTest ($SCHEME, exit $test_rc)" "$TEST_LOG"
    notes="${notes:+$notes; }the XCTest bundle failed; see $TEST_LOG"
    exit_code=$test_rc
  fi

  transitions="$(apple_transitions_from "$TEST_LOG")"
  if [ "$transitions" = "[]" ]; then
    notes="${notes:+$notes; }no TWINVPN_LIFECYCLE_TRANSITION marker was emitted, so this run proves linking and execution and NOT a lifecycle transition"
  fi
fi

if [ "$PRIVILEGED" = false ]; then
  notes="${notes:+$notes; }hosted SIMULATOR run: NOT privileged and NOT device evidence. The simulator has no Secure Enclave, no jetsam and no real includeAllNetworks, so NetworkExtension activation, the extension memory-limit kill and every leak row are NOT exercised here — see build/ci/jobs/ios-device-lifecycle.yml"
else
  notes="${notes:+$notes; }physical-device run against a provisioned iPhone/iPad. ADR-0018 §11.9 lists iPadOS as a DISTINCT farm entry, so a run on one device model does not discharge the other's row"
fi

verdict="FAIL"
if [ "$compiled" = true ] && [ "$linked" = true ] && [ "$loaded" = true ] \
   && [ "$invoked" = true ] && [ "$received" = true ] && [ "$shutdown" = true ] \
   && [ "$transitions" != "[]" ]; then
  verdict="PASS"
fi

cat > "$EVIDENCE" <<JSON
{
  "schema_version": 1,
  "platform": "ios",
  "job_name": "${GITHUB_JOB:-$JOB_DEFAULT}",
  "runner": "${RUNNER_NAME:-local}",
  "runner_kind": "$([ -n "${GITHUB_ACTIONS:-}" ] && { [ "$PRIVILEGED" = true ] && echo self-hosted || echo github-hosted; } || echo local)",
  "privileged": $PRIVILEGED,
  "github_run_id": $([ -n "${GITHUB_RUN_ID:-}" ] && echo "\"$GITHUB_RUN_ID\"" || echo null),
  "github_run_attempt": $(twinvpn_run_attempt_json),
  "repository": $(twinvpn_repository_json),
  "artifact_digests": {},
  "github_run_url": $([ -n "${GITHUB_RUN_ID:-}" ] && echo "\"${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-}/actions/runs/$GITHUB_RUN_ID\"" || echo null),
  "commit": "$(cd "$REPO" && git rev-parse HEAD)",
  "toolchain": {
    "xcodebuild": "$(xcodebuild -version | head -1)",
    "swift": "$(swift --version 2>&1 | head -1)",
    "rustc": "$(rustc --version)",
    "sdk_device": "iphoneos $(xcrun --sdk iphoneos --show-sdk-version 2>/dev/null || echo unknown)",
    "sdk_simulator": "iphonesimulator $(xcrun --sdk iphonesimulator --show-sdk-version 2>/dev/null || echo unknown)",
    "macos": "$(sw_vers -productVersion 2>/dev/null || echo unknown)"
  },
  "compiled": $compiled,
  "linked_real_core": $linked,
  "loaded": $loaded,
  "invoked_core": $invoked,
  "received_result": $received,
  "lifecycle_transitions": $transitions,
  "graceful_shutdown": $shutdown,
  "test_command": "${TEST_CMD:-<not reached>}",
  "test_exit_code": $exit_code,
  "artifacts": [
    "build/ci/logs/ios/core-aarch64-apple-ios-full.log",
    "build/ci/logs/ios/core-aarch64-apple-ios-core-lite.log",
    "build/ci/logs/ios/core-aarch64-apple-ios-sim-full.log",
    "build/ci/logs/ios/core-aarch64-apple-ios-sim-core-lite.log",
    "build/ci/logs/ios/xcodegen.log",
    "build/ci/logs/ios/build-products.log",
    "build/ci/logs/ios/xctest.log",
    "build/ci/logs/ios/simulators.log"
  ],
  "notes": "$notes",
  "verdict": "$verdict",
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON

echo
if [ "$PRIVILEGED" = true ]; then kind="physical device"; else kind="simulator"; fi
echo "=== ios evidence ($kind) ==="
cat "$EVIDENCE"

[ "$verdict" = "PASS" ] || {
  echo "::error::ios link/run did not pass: $notes" >&2
  exit 1
}
