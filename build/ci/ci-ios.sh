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
SHELL_DIR="$REPO/shells/ios"
LOGDIR="$REPO/build/ci/logs/ios"

MODE="link-run"
case "${1:-}" in
  --print-xcode-path) MODE="print-xcode-path" ;;
  --reset)            MODE="reset" ;;
  --device)           MODE="device" ;;
  --cleanup)          MODE="cleanup" ;;
  "")                 MODE="link-run" ;;
  *) echo "ci-ios.sh: unknown argument '$1'" >&2; exit 2 ;;
esac

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
  rm -f "$REPO/build/ci/evidence/ios.json" "$REPO/build/ci/evidence/ios-device.json"
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
echo "::group::compile the shared core (twinvpn-ffi: device + simulator, full + core-lite)"
core_ok=true
for target in aarch64-apple-ios aarch64-apple-ios-sim; do
  "$SHELL_DIR/Scripts/build-core.sh" --target "$target" --profile release || core_ok=false
  "$SHELL_DIR/Scripts/build-core.sh" --target "$target" --profile release --features core-lite || core_ok=false
done
if [ "$core_ok" = true ]; then
  compiled=true
else
  notes="the shared core did not compile for aarch64-apple-ios and/or aarch64-apple-ios-sim"
fi
echo "::endgroup::"

# --- 1b. the size budget, which R-32 makes a blocker ------------------------
#
# The DEVICE slice only. A simulator archive is not a shipping artifact and its
# size says nothing about what the App Store receives.
if [ "$compiled" = true ]; then
  echo "::group::ADR-0018 §11.9 row 1 size budget (device slice)"
  "$SHELL_DIR/Scripts/check-budget.sh" iphoneos
  echo "::endgroup::"
fi

# --- 2. stage the ABI of record and generate the project --------------------
if [ "$compiled" = true ]; then
  echo "::group::stage twinvpn.h and generate the project"
  "$SHELL_DIR/Scripts/stage-headers.sh"
  ( cd "$SHELL_DIR" && xcodegen generate )
  echo "::endgroup::"
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
    # Any available iPhone runtime. The DEVICE MODEL is not pinned: ADR-0018
    # §11.9 rows 1 and 2 make iPadOS a distinct FARM entry, not a distinct
    # binary, and a simulator model cannot discharge either row — so pinning one
    # here would imply a coverage claim the simulator cannot support.
    #
    # The iOS VERSION floor is asserted, because that IS a product constraint:
    # row 1 fixes the minimum at iOS 15, and a runtime below it would be testing
    # a configuration the product does not support.
    xcrun simctl list devices available | tee "$LOGDIR/simulators.log"
    SIM_UDID="$(xcrun simctl list devices available --json \
      | python3 -c '
import json, sys
data = json.load(sys.stdin)["devices"]
best = None
for runtime, devices in data.items():
    if "iOS" not in runtime:
        continue
    # com.apple.CoreSimulator.SimRuntime.iOS-18-2 -> (18, 2)
    tail = runtime.rsplit(".", 1)[-1].removeprefix("iOS-")
    try:
        version = tuple(int(part) for part in tail.split("-"))
    except ValueError:
        continue
    if version < (15,):
        continue          # ADR-0018 §11.9 row 1: iOS 15 is the floor
    for device in devices:
        if device.get("isAvailable") and "iPhone" in device.get("name", ""):
            if best is None or version > best[0]:
                best = (version, device["udid"])
if best is None:
    sys.exit("no available iPhone simulator at iOS 15 or newer")
print(best[1])
')"
    echo "simulator: $SIM_UDID"
    xcrun simctl boot "$SIM_UDID"
    xcrun simctl bootstatus "$SIM_UDID" -b
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
