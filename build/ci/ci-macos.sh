#!/usr/bin/env bash
#
# ci-macos.sh — the macOS platform link/run evidence.
#
# ===========================================================================
# WHAT THIS PROVES, AND WHAT IT REFUSES TO CLAIM
# ===========================================================================
# The First Implementation Wave criterion is that the shared core/platform
# boundary COMPILES, LINKS, LOADS, INVOKES core code, RECEIVES a result back,
# and executes lifecycle state transitions. On macOS that boundary is
# `shells/macos/twinvpn-bridge/include/twinvpn_bridge.h`: ADR-0016 amendment
# PS-22 puts the `Core`, the platform adapter, the key handle, the datapath and
# the management interface INSIDE the NetworkExtension system extension, so the
# archive the Swift extension links IS the shared core on this platform.
#
# Two modes, two evidence files, and they are never the same claim:
#
#   (default)      HOSTED, UNPRIVILEGED -> build/ci/evidence/macos.json
#                  privileged: false. Builds the app and the system extension,
#                  links the real archive into the extension, runs the XCTest
#                  bundle against it, crosses `tvb_ext_start` and reads back a
#                  TYPED refusal (ADR-0016 §11.6 stops at `privilege_posture`
#                  when not root, and PS-18 forbids starting anyway), and
#                  executes the lifecycle transitions a hosted runner honestly
#                  can. It does NOT activate a NetworkExtension.
#
#   --privileged   SELF-HOSTED, SIGNED  -> build/ci/evidence/macos-privileged.json
#                  privileged: true. The same suite on a runner that is root and
#                  has the signing identity and entitlements, where
#                  `tvb_ext_start` succeeds and the full ABI lifecycle runs.
#
# **A hosted run is not a NetworkExtension lifecycle pass and this script will
# not write one.** `privileged` is set from the MODE, and the transitions are
# read out of the tests' own output — so a hosted run cannot be configured into
# producing the privileged evidence and vice versa.
#
# ===========================================================================
# NOTHING HERE HAS EVER RUN
# ===========================================================================
# It was written on a Linux host with no Xcode, no Darwin SDK and no XcodeGen.
# What HAS been verified locally is stated in the wave report and is narrow:
# `bash -n`, the YAML fragments, and the Rust lifecycle test this script runs
# (which passes on Linux). The Swift, the XcodeGen spec and every `xcodebuild`
# invocation below are unrun. The first Darwin run should expect to correct
# them; that is the point of having the job.
#
# There is no `|| true` anywhere below. A proof path that swallows a failure is
# worse than no proof path.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SHELL_DIR="$REPO/shells/macos"
LOGDIR="$REPO/build/ci/logs/macos"

MODE="link-run"
case "${1:-}" in
  --print-xcode-path) MODE="print-xcode-path" ;;
  --reset)            MODE="reset" ;;
  --privileged)       MODE="privileged" ;;
  --cleanup)          MODE="cleanup" ;;
  "")                 MODE="link-run" ;;
  *) echo "ci-macos.sh: unknown argument '$1'" >&2; exit 2 ;;
esac

# shellcheck disable=SC1091
source "$REPO/build/toolchain/env.sh"
# shellcheck disable=SC1091
source "$REPO/build/ci/ci-common-apple.sh"

# --------------------------------------------------------------------------
# --print-xcode-path: one line, so a caller can `xcode-select -s "$(...)"`.
# The pin lives in ci-common-apple.sh and therefore in ONE place, rather than
# being restated in every workflow that needs it.
# --------------------------------------------------------------------------
if [ "$MODE" = "print-xcode-path" ]; then
  apple_xcode_developer_path
  exit 0
fi

# --------------------------------------------------------------------------
# --cleanup: runs under `if: always()`, so it must be idempotent, must tolerate
# a run that never got started, and must not itself fail the job.
#
# It tears down what a PRIVILEGED run can leave behind on a self-hosted Mac:
# a running system extension, an owner-tagged `pf` anchor, and the overlay
# interface. It deliberately does NOT flush `pf` wholesale — ADR-0012 CB-6 puts
# the rule set in the OS's custody and KS-19's boot anchor is PACKAGE-owned
# (PS-7); a cleanup that removed it would leave the runner less protected than
# it found it, and `twinvpn-unblock` is the sanctioned removal path (KS-20a).
# --------------------------------------------------------------------------
if [ "$MODE" = "cleanup" ]; then
  echo "=== cleanup: returning the runner to a known state ==="
  mkdir -p "$LOGDIR"
  {
    echo "--- systemextensionsctl list (before) ---"
    systemextensionsctl list 2>&1 || echo "(systemextensionsctl unavailable)"

    # The owner-tagged anchor, and ONLY it. `twinvpn-unblock` is the
    # package-owned, privileged removal command KS-20a defines for exactly this;
    # using it rather than raw `pfctl -F` means the cleanup path and the
    # supported recovery path are the same code.
    # The target directory is asked for, never assumed: this repository shares
    # one CARGO_TARGET_DIR across its workspaces.
    unblock=""
    if command -v cargo >/dev/null; then
      target_dir="$(cd "$SHELL_DIR" && cargo metadata --format-version 1 --no-deps 2>/dev/null \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])' 2>/dev/null || true)"
      for candidate in "$target_dir/release/twinvpn-unblock" "$target_dir/debug/twinvpn-unblock"; do
        [ -x "$candidate" ] && { unblock="$candidate"; break; }
      done
    fi
    if [ -n "$unblock" ]; then
      # `sudo -n`: a teardown must never block waiting for a password. This is
      # the one place a non-zero status is tolerated and it is NOT a proof path
      # — `if: always()` teardown that failed the job would hide the real
      # failure it was cleaning up after.
      sudo -n "$unblock" --yes 2>&1 \
        || echo "(twinvpn-unblock reported a failure or sudo was unavailable; see above)"
    else
      echo "(twinvpn-unblock not built in this run; nothing owner-tagged to remove)"
    fi

    # The overlay interface, if a run left one. `ifconfig <utun> destroy` is the
    # documented way; a missing interface is not an error here.
    if ifconfig utun7 >/dev/null 2>&1; then
      sudo -n ifconfig utun7 destroy 2>&1 || echo "(utun7 would not destroy)"
    fi

    echo "--- routes mentioning utun7 ---"
    netstat -rn 2>/dev/null | grep -F utun7 || echo "(none)"

    echo "--- systemextensionsctl list (after) ---"
    systemextensionsctl list 2>&1 || echo "(systemextensionsctl unavailable)"
  } | tee "$LOGDIR/cleanup.log"
  echo "=== cleanup done ==="
  exit 0
fi

# --------------------------------------------------------------------------
# --reset: a known-clean starting point, before anything is built.
#
# Rule C-5 binds a verdict to an exact commit or immutable snapshot, and a
# generated project or a staged archive left over from a previous run is
# neither. So the generated and staged artifacts go, and the evidence file goes
# with them: a stale `macos.json` from a previous run is worse than none,
# because the acceptance report cannot tell it from this run's.
# --------------------------------------------------------------------------
if [ "$MODE" = "reset" ]; then
  echo "=== reset: discarding generated and staged artifacts ==="
  rm -rf "$SHELL_DIR/TwinVPN.xcodeproj" "$SHELL_DIR/Frameworks"
  rm -rf "$LOGDIR"
  rm -f "$REPO/build/ci/evidence/macos.json" "$REPO/build/ci/evidence/macos-privileged.json"
  # And the runner's own state, by the same path the cleanup step uses.
  "$0" --cleanup
  echo "=== reset done ==="
  exit 0
fi

# ==========================================================================
# The link/run itself.
# ==========================================================================
PRIVILEGED=false
EVIDENCE="$REPO/build/ci/evidence/macos.json"
JOB_DEFAULT="macos-link-run"
if [ "$MODE" = "privileged" ]; then
  PRIVILEGED=true
  EVIDENCE="$REPO/build/ci/evidence/macos-privileged.json"
  JOB_DEFAULT="macos-privileged-lifecycle"
fi

mkdir -p "$(dirname "$EVIDENCE")" "$LOGDIR"

apple_toolchain_banner macosx
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

SCHEME="TwinVPNBridge"
RESULT_BUNDLE="$LOGDIR/TwinVPNBridgeTests.xcresult"
TEST_CMD="xcodebuild test -project shells/macos/TwinVPN.xcodeproj -scheme $SCHEME -destination platform=macOS"

# The Rust targets §11.9 row 5 needs. `rustup target add` is idempotent.
#
# BOTH, and this is not optional: row 5 ships universal 2, `build-bridge.sh`
# builds `aarch64-apple-darwin` and `x86_64-apple-darwin` and `lipo`s them, and a
# `macos-26` runner is arm64 and installs only its own host target. Run
# 33286355061 is what that costs — the arm64 slice built in 68 seconds and the
# x86_64 one died on the first crate with
# `error[E0463]: can't find crate for core … the x86_64-apple-darwin target may
# not be installed`.
rustup target add aarch64-apple-darwin x86_64-apple-darwin >/dev/null

# --- 1. compile the shared core for this target -----------------------------
#
# ADR-0018 §11.9 row 5 is universal 2, so BOTH slices are built. This is the
# first time `twinvpn-bridge` is compiled with a Darwin C toolchain in its
# `full` profile: `make cross-check` can only reach `core-lite` on Linux,
# because `ring` (via twinvpn-cp-client -> quinn -> rustls) needs an Apple SDK.
# So a failure here is genuinely new information.
#
# Through `apple_build_step`, so the output is captured for the diagnostics
# artifact AND the compiler's own diagnostic is echoed outside the group when
# the build fails — see `apple_show_failure`'s header in ci-common-apple.sh.
if apple_build_step "compile the shared core (twinvpn-bridge, universal 2, release)" \
     "$LOGDIR/build-core.log" \
     "$SHELL_DIR/Scripts/build-bridge.sh" --profile release; then
  compiled=true
else
  notes="the shared core did not compile for aarch64-apple-darwin / x86_64-apple-darwin; the diagnostic is echoed above and the whole log is in build/ci/logs/macos/build-core.log"
fi

# --- 1b. the size budget, which R-32 makes a blocker ------------------------
if [ "$compiled" = true ]; then
  echo "::group::ADR-0018 §11.9 row 5 size budget"
  "$SHELL_DIR/Scripts/check-budget.sh"
  echo "::endgroup::"
fi

# --- 1c. the lifecycle transitions a Darwin host can execute natively -------
#
# `shells/macos/twinvpn-bridge/tests/lifecycle.rs`, run NATIVELY on macOS. It is
# the same file that runs on Linux, so this is not new coverage — what is new is
# the ARCHITECTURE it runs on, and the mach timebase arithmetic, the `PF_ROUTE`
# decoder and the power state machine underneath it have never executed on
# Darwin before. It prints one `TWINVPN_LIFECYCLE_TRANSITION` marker per
# transition it observes, and those markers are collected below.
if [ "$compiled" = true ]; then
  echo "::group::native macOS lifecycle transitions (cargo test)"
  set +e
  ( cd "$SHELL_DIR" && cargo test --locked -p twinvpn-bridge --test lifecycle -- --nocapture ) \
    2>&1 | tee "$LOGDIR/lifecycle-native.log"
  native_rc=${PIPESTATUS[0]}
  set -e
  echo "::endgroup::"
  if [ "$native_rc" -ne 0 ]; then
    apple_show_failure "native macOS lifecycle test (exit $native_rc)" \
      "$LOGDIR/lifecycle-native.log"
    notes="${notes:+$notes; }the native macOS lifecycle test failed; see build/ci/logs/macos/lifecycle-native.log"
    exit_code=$native_rc
  fi
fi

# --- 2. generate the project and BUILD THE PRODUCTION TARGETS ---------------
#
# The app and the NetworkExtension SYSTEM extension. This is where the shared
# core is linked into a real product bundle rather than into a test harness:
# `project.yml` links `libtwinvpn_bridge.a` into `TwinVPNTunnel` and into
# nothing else, so a green build here IS the link claim.
#
# Unsigned. A hosted runner has no Developer ID and ADR-0021's signing,
# notarization and stapling are a release concern, not a link one. The extension
# cannot be ACTIVATED unsigned — which is exactly why the activation claim lives
# in the privileged job and not here.
if [ "$compiled" = true ]; then
  echo "::group::xcodegen generate"
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

  echo "::group::build TwinVPN.app + TwinVPNTunnel.systemextension"
  set +e
  xcodebuild build \
    -project "$SHELL_DIR/TwinVPN.xcodeproj" \
    -scheme TwinVPN \
    -destination 'platform=macOS' \
    -derivedDataPath "$LOGDIR/DerivedData" \
    CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY="" \
    2>&1 | tee "$LOGDIR/build-products.log"
  build_rc=${PIPESTATUS[0]}
  set -e
  echo "::endgroup::"

  if [ "$build_rc" -eq 0 ]; then
    linked=true
  else
    apple_show_failure "build TwinVPN.app + TwinVPNTunnel.systemextension (exit $build_rc)" \
      "$LOGDIR/build-products.log"
    notes="${notes:+$notes; }the system extension did not link the shared core; see build/ci/logs/macos/build-products.log"
    exit_code=$build_rc
  fi
fi

# --- 3/4/5/6. load the archive, cross the production bridge, drive the -------
#              lifecycle, and shut down.
if [ "$linked" = true ]; then
  echo "::group::XCTest across the production bridge"
  set +e
  xcodebuild test \
    -project "$SHELL_DIR/TwinVPN.xcodeproj" \
    -scheme "$SCHEME" \
    -destination 'platform=macOS' \
    -derivedDataPath "$LOGDIR/DerivedData" \
    -resultBundlePath "$RESULT_BUNDLE" \
    CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY="" \
    2>&1 | tee "$LOGDIR/xctest.log"
  test_rc=${PIPESTATUS[0]}
  set -e
  echo "::endgroup::"

  if [ "$test_rc" -eq 0 ]; then
    # The bundle ran, so the archive loaded; the suite's first case compares
    # `tvb_abi_major()` against the header's constant, which cannot pass unless
    # real code from the archive executed.
    loaded=true
    invoked=true
    received=true
    shutdown=true
    exit_code=${exit_code:-0}
  else
    apple_show_failure "XCTest ($SCHEME, exit $test_rc)" "$LOGDIR/xctest.log"
    notes="${notes:+$notes; }the XCTest bundle failed; see build/ci/logs/macos/xctest.log"
    exit_code=$test_rc
  fi
fi

# --- the transitions, READ OUT OF THE TESTS ---------------------------------
#
# Two vehicles on this platform, and the evidence says so rather than blurring
# them: the native `cargo test` lifecycle suite, and the XCTest suite that
# crosses `twinvpn_bridge.h`. Both print the same marker format; neither is
# hard-coded here.
transitions="$(apple_transitions_from "$LOGDIR/lifecycle-native.log" "$LOGDIR/xctest.log")"
if [ "$transitions" = "[]" ]; then
  notes="${notes:+$notes; }no TWINVPN_LIFECYCLE_TRANSITION marker was emitted, so this run proves linking and execution and NOT a lifecycle transition"
fi

if [ "$PRIVILEGED" = false ]; then
  notes="${notes:+$notes; }hosted runner: NOT privileged. tvb_ext_start refuses at ADR-0016 §11.6's privilege_posture step because the process is not root, so NetworkExtension activation, pf programming and the signed system-extension lifecycle are NOT exercised here — see build/ci/jobs/macos-privileged-lifecycle.yml"
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
  "platform": "macos",
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
    "sdk": "macosx $(xcrun --sdk macosx --show-sdk-version 2>/dev/null || echo unknown)",
    "macos": "$(sw_vers -productVersion 2>/dev/null || echo unknown)"
  },
  "compiled": $compiled,
  "linked_real_core": $linked,
  "loaded": $loaded,
  "invoked_core": $invoked,
  "received_result": $received,
  "lifecycle_transitions": $transitions,
  "graceful_shutdown": $shutdown,
  "test_command": "$TEST_CMD",
  "test_exit_code": $exit_code,
  "artifacts": [
    "build/ci/logs/macos/build-core.log",
    "build/ci/logs/macos/xcodegen.log",
    "build/ci/logs/macos/lifecycle-native.log",
    "build/ci/logs/macos/build-products.log",
    "build/ci/logs/macos/xctest.log",
    "build/ci/logs/macos/TwinVPNBridgeTests.xcresult"
  ],
  "notes": "$notes",
  "verdict": "$verdict",
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON

echo
echo "=== macos evidence ($([ "$PRIVILEGED" = true ] && echo privileged || echo hosted)) ==="
cat "$EVIDENCE"

[ "$verdict" = "PASS" ] || {
  echo "::error::macos link/run did not pass: $notes" >&2
  exit 1
}
