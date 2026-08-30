#!/usr/bin/env bash
#
# ci-android.sh -- the Android platform link/run evidence.
#
# `make ci-android` runs this, on an `ubuntu-24.04` runner. ADR-0018 BM-3 puts
# Android in the "cross-buildable from Linux" row, so unlike Windows there is no
# foreign build host here -- what Android needs instead is a DEVICE, and an
# emulator is the version of one CI can have.
#
# ===========================================================================
# WHAT THIS PROVES, AT EXACTLY ITS STRENGTH
# ===========================================================================
# The criterion is that the shared core/platform boundary compiles, links,
# LOADS, INVOKES core code, RECEIVES a result back, and executes lifecycle state
# transitions. On Android every one of those words means something a JVM or
# Robolectric test cannot reach:
#
#   compiled          the CDYLIB builds for all four ABIs against a real NDK
#   linked_real_core  `libtwinvpn_android_jni.so` links `twinvpn-ffi` ->
#                     `twinvpn-core`, and BOTH `.so`s are packaged in the APK
#   loaded            `System.loadLibrary` succeeded on a real Android runtime
#   invoked_core      `tw_core_create` / `tw_core_submit` ran across JNI
#   received_result   an F-4 envelope and an event frame came back
#   transitions       `TwinVpnService` was created, started and destroyed BY THE
#                     SYSTEM, observed through `ActivityManager`
#
# The run is `shells/android/app/src/androidTest/.../NativeLinkRunTest.kt`.
# The three device-farm suites beside it (`LifecycleMatrixTest`,
# `DozeAndRevocationTest`, `LeakMeasurementTest`) are DELIBERATELY NOT RUN: every
# helper in them is `TODO("device farm")` and `shells/android/README.md` §3.4
# says they fail by design. Running them here would turn a truthful "not yet
# measured" into a red square that teaches people to ignore red squares. The
# class filter below is the mechanism, and it names exactly one class so that
# adding a second is a visible edit.
#
# There is no `|| true` anywhere on a proof path.
#
# ===========================================================================
# THE EMULATOR: avdmanager/emulator DIRECTLY, not a third-party action
# ===========================================================================
# `reactivecircus/android-emulator-runner` is the usual choice and would work.
# This script boots the emulator itself instead, for two reasons that both come
# down to determinism:
#
#   1. `make ci-android` has to be ONE entry point that does the whole job. If
#      the emulator lived in the workflow, `make ci-android` would silently do
#      less than CI does, which is the drift the Makefile/CI single-definition
#      rule exists to prevent.
#   2. The system image is pinned HERE, next to the API level the app targets,
#      rather than in an action input whose defaults move between action
#      versions.
#
# The image is pinned below. If a device is already attached -- a physical one
# under `--privileged`, or an emulator someone else booted -- it is used as-is
# and nothing is booted.
#
# ===========================================================================
# MODES
# ===========================================================================
#   (no flag)      build all four ABIs, assemble, boot the pinned emulator,
#                  install, instrument, write evidence. `android-link-run`.
#   --reset        wipe the AVD and clear stale evidence and logs, so a run
#                  cannot inherit an installed package or a dirty data dir.
#   --privileged   use the ATTACHED PHYSICAL DEVICE (ANDROID_SERIAL) and boot no
#                  emulator. `android-device-lifecycle`, self-hosted.
#   --cleanup      uninstall the packages and kill the emulator, on every path.
#                  Safe under `if: always()`; never fails the job.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EVIDENCE="$REPO/build/ci/evidence/android.json"
LOGDIR="$REPO/build/ci/logs/android"
GRADLE_DIR="$REPO/shells/android"
JNILIBS="$GRADLE_DIR/app/src/main/jniLibs"
mkdir -p "$(dirname "$EVIDENCE")" "$LOGDIR"

# The Gradle assemble's captured output. Named here rather than at the call site
# so `--reset`'s `rm -rf "$LOGDIR"/*` and the diagnostics artifact are talking
# about the same file.
GRADLE_LOG="$LOGDIR/gradle-assemble.log"

# ---------------------------------------------------------------------------
# WHY A GRADLE FAILURE HAS TO BE PRINTED A SECOND TIME
#
# In run 33288074040 this script refused with
#
#     the Gradle build failed; the native libraries built but the app did not
#
# and the actual cause -- `Could not find androidx.test:rules:1.6.2`, a
# coordinate that has never been published -- was, in practice, unreadable.
# THREE separate defects, all of them this script's:
#
#   1. Gradle writes its `* What went wrong:` report to STDERR and its task list
#      to STDOUT. Un-tee'd, the two are buffered independently, so the block
#      surfaced AFTER `BUILD FAILED in 3m 11s` and after `37 actionable tasks`
#      -- below where a reader looking for the reason stops.
#   2. All of it sat inside the step's collapsed `::group::`, between the task
#      list and a Gradle-10 deprecation notice.
#   3. NOTHING was captured. `build/ci/logs/android/` was empty on this path, so
#      `diagnostics-android-link-run` uploaded zero files -- "No files were found
#      with the provided path" -- and the artifact could not answer either.
#
# A proof script that refuses without saying why is not cheaper than no proof
# script; it is one whole CI round trip more expensive, per iteration. This is
# the same defect `ci-common-apple.sh` fixed for the Apple lanes, in the same
# shape, with one deliberate difference: `apple_show_failure` re-states the
# diagnostic in a `::group::` of its own, and a top-level group is still
# COLLAPSED by default. Here it is printed ungrouped, in the clear.
#
# `awk` and not `grep`, because `grep` exits 1 when nothing matches and this
# script runs under `set -o pipefail` with no `|| true` permitted anywhere on a
# proof path. `awk` always exits 0 and reports for itself when it matched
# nothing.
# ---------------------------------------------------------------------------
android_show_failure() {
  local label="$1" log="$2"

  echo
  echo "=================================================================="
  echo "FAILED: $label"
  echo "=================================================================="
  if [ ! -s "$log" ]; then
    echo "(the step produced NO output at all; $log is empty or absent)"
    echo "=================================================================="
    echo
    return 0
  fi

  echo "--- Gradle's own failure report, lifted out of $log ---"
  # Three things in one pass, because Gradle spreads the answer over three
  # places: the FAILED task line names WHERE, the `* What went wrong:` block
  # names WHY along with its indented `> ` cause chain, and a `Caused by:` may
  # appear on its own for a failure that carries no standard envelope.
  awk '
    /^> Task .* FAILED$/       { print; matched++; next }
    /^\* What went wrong:/     { inblock = 1 }
    inblock                    { print; matched++ }
    /^\* Get more help/        { inblock = 0; next }
    !inblock && /Caused by:/   { print; matched++ }
    END {
      if (!matched)
        print "(this log carries no `* What went wrong:` block; the tail below and the diagnostics artifact carry the rest)"
    }
  ' "$log"

  echo "--- last 40 lines of $log ---"
  tail -n 40 "$log"
  echo "--- the whole log is in the diagnostics artifact as ${log#"$REPO/"} ---"
  echo "=================================================================="
  echo
}

# ---------------------------------------------------------------------------
# One build step: grouped, streamed, CAPTURED, and explained when it fails.
#
#   android_build_step "<label>" "<log>" "<workdir>" <command> [args...]
#
# `tee` rather than a plain redirect, so a PASSING run still shows progress live
# and a reader is not left watching a silent runner for three minutes. The status
# returned is the STEP's, taken from `PIPESTATUS`, never `tee`'s -- which is
# always 0 and would turn every failure into a pass.
#
# `2>&1` is what puts Gradle's stderr failure report into the same stream as its
# stdout task list, so the captured log holds both and their order is the pipe's
# rather than two independently flushed buffers'.
#
# There is no `|| true`: a caller that wants to continue past a failure has to
# say so with its own `||`, in the open.
#
# CALL IT FROM AN `if`, as the one call site below does. Like
# `apple_build_step`, it re-enables `set -e` unconditionally after reading
# `PIPESTATUS`, so the `set +e; android_build_step …; rc=$?` shape would abort
# the script on the `return` instead of reaching the caller's error handling.
# An `if` condition suppresses errexit for the whole compound and is correct.
# ---------------------------------------------------------------------------
android_build_step() {
  local label="$1" log="$2" workdir="$3"
  shift 3
  local rc=0

  mkdir -p "$(dirname "$log")"
  echo "::group::$label"
  set +e
  ( cd "$workdir" && "$@" ) 2>&1 | tee "$log"
  rc=${PIPESTATUS[0]}
  set -e
  echo "::endgroup::"

  [ "$rc" -eq 0 ] || android_show_failure "$label (exit $rc)" "$log"
  return "$rc"
}

# ---------------------------------------------------------------------------
# Pins. Every one of these is a version this evidence is about.
# ---------------------------------------------------------------------------

# `app/build.gradle.kts`: minSdk 26. The NDK's per-API clang wrapper is named
# after it, and building against a HIGHER one would produce a `.so` that refuses
# to load on the minimum the product claims to support.
readonly ANDROID_API_MIN=26

# The emulator image. API 30 rather than 35 on purpose: the app's `targetSdk` is
# 35, so its behaviour is targetSdk-35 behaviour on any device, while the
# DEVICE's API level decides which runtime gates apply. API 30 avoids the
# API-33 POST_NOTIFICATIONS runtime grant and the API-34 foreground-service-type
# enforcement, neither of which this test is about -- both are `LifecycleMatrixTest`'s
# and the device farm's. `google_apis` rather than `default`: the plain image
# omits services the AndroidX test runner expects.
readonly EMULATOR_API=30
readonly EMULATOR_IMAGE="system-images;android-${EMULATOR_API};google_apis;x86_64"
readonly AVD_NAME="twinvpn-ci-api${EMULATOR_API}"

readonly APPLICATION_ID="net.twinvpn.android"
readonly TEST_PACKAGE="net.twinvpn.android.test"
readonly TEST_CLASS="net.twinvpn.android.NativeLinkRunTest"
readonly INSTRUMENTATION="$TEST_PACKAGE/androidx.test.runner.AndroidJUnitRunner"

# ADR-0018 §11.9 row 3: "aarch64-linux-android, armv7-linux-androideabi,
# x86_64-linux-android, i686-linux-android", "cdylib in the AAB", "<= 6 MB per
# ABI", "LOAD alignment >= 0x4000 (C-12)". `shells/android/app/build.gradle.kts`
# line 30 lists the same four in Android's spelling. Both are the source; the
# pairs below are the mapping, and `--abi` on either side alone would be a
# second list to keep in step.
readonly ABIS=(
  "arm64-v8a:aarch64-linux-android:aarch64-linux-android"
  "armeabi-v7a:armv7-linux-androideabi:armv7a-linux-androideabi"
  "x86_64:x86_64-linux-android:x86_64-linux-android"
  "x86:i686-linux-android:i686-linux-android"
)

do_reset=false
do_privileged=false
do_cleanup=false
do_run=true

for arg in "$@"; do
  case "$arg" in
    --reset)      do_reset=true ;;
    --privileged) do_privileged=true ;;
    --cleanup)    do_cleanup=true; do_run=false ;;
    *)
      echo "ci-android.sh: unknown flag: $arg" >&2
      echo "usage: ci-android.sh [--reset] [--privileged] [--cleanup]" >&2
      exit 2
      ;;
  esac
done

sdk_root="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
adb() { "$sdk_root/platform-tools/adb" "$@"; }

# ---------------------------------------------------------------------------
# cleanup -- runs with `if: always()`, so it must not fail the job
# ---------------------------------------------------------------------------
if [ "$do_cleanup" = true ]; then
  echo "=== cleanup ==="
  if [ -n "$sdk_root" ] && [ -x "$sdk_root/platform-tools/adb" ]; then
    # The tunnel: `TwinVpnService` holds no OS-level claim once its process is
    # gone (`EnforcementView::custody` reports `survives_core_exit: false`
    # unless lockdown is CONFIRMED), so uninstalling the package IS the teardown
    # of routes and the VPN slot on this platform. Stated rather than assumed.
    for pkg in "$TEST_PACKAGE" "$APPLICATION_ID"; do
      if adb shell pm list packages 2>/dev/null | grep -q "package:$pkg\$"; then
        echo "uninstalling $pkg"
        adb uninstall "$pkg" >/dev/null 2>&1 || echo "  (uninstall refused)"
      fi
    done
    if [ "$do_privileged" = true ]; then
      echo "physical device: left attached, package removed"
    else
      echo "stopping the emulator"
      adb emu kill >/dev/null 2>&1 || echo "  (no emulator to stop)"
    fi
  else
    echo "no Android SDK on PATH; nothing to clean up"
  fi
  exit 0
fi

# ---------------------------------------------------------------------------
# reset
# ---------------------------------------------------------------------------
if [ "$do_reset" = true ]; then
  echo "=== reset ==="
  rm -f "$EVIDENCE"
  rm -rf "${LOGDIR:?}"/*
  rm -rf "${JNILIBS:?}"
  mkdir -p "$LOGDIR"
  if [ "$do_privileged" = true ]; then
    if [ -z "${ANDROID_SERIAL:-}" ]; then
      echo "::error::--privileged --reset needs ANDROID_SERIAL naming the physical device" >&2
      exit 1
    fi
    echo "physical device $ANDROID_SERIAL: removing any previous install"
    for pkg in "$TEST_PACKAGE" "$APPLICATION_ID"; do
      if adb shell pm list packages 2>/dev/null | grep -q "package:$pkg\$"; then
        adb uninstall "$pkg" >/dev/null
      fi
    done
  elif [ -n "$sdk_root" ] && [ -x "$sdk_root/cmdline-tools/latest/bin/avdmanager" ]; then
    echo "deleting AVD $AVD_NAME so this run cannot inherit its data dir"
    "$sdk_root/cmdline-tools/latest/bin/avdmanager" delete avd -n "$AVD_NAME" >/dev/null 2>&1 \
      || echo "  (no such AVD)"
  fi
fi

[ "$do_run" = true ] || exit 0

# ---------------------------------------------------------------------------
# toolchain -- printed, and recorded in the evidence
# ---------------------------------------------------------------------------
#
# `build/toolchain/env.sh` IS sourced, because on the dev host cargo is not on
# PATH without it and `make ci-android` has to work there too. But it sets
# `JAVA_HOME="$HOME/.local/jdk"`, which is this project's DEV HOST layout and
# does not exist on a runner -- and Gradle reads `JAVA_HOME`, so letting that
# through would point the Android build at a directory that is not there and
# produce a failure reading as a Gradle problem. So the JDK the caller already
# had (a runner's `actions/setup-java`, pinned to the same
# `TWINVPN_JDK_VERSION`) wins whenever env.sh's own path is not a real JDK.
runner_java_home="${JAVA_HOME:-}"
# shellcheck disable=SC1091
source "$REPO/build/toolchain/env.sh"
if [ ! -x "${JAVA_HOME:-}/bin/java" ]; then
  if [ -n "$runner_java_home" ]; then
    export JAVA_HOME="$runner_java_home"
  else
    unset JAVA_HOME
  fi
fi

ndk_root="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-${ANDROID_NDK_LATEST_HOME:-}}}"

echo "=== toolchain ==="
rustc --version
cargo --version
java -version 2>&1 | head -1
if [ -z "$sdk_root" ]; then
  echo "::error::ANDROID_SDK_ROOT / ANDROID_HOME is unset; there is no SDK to build against" >&2
  exit 2
fi
if [ -z "$ndk_root" ] || [ ! -d "$ndk_root" ]; then
  echo "::error::ANDROID_NDK_HOME is unset or missing. ADR-0018 §11.9 row 3 requires NDK r26+; shells/android/README.md §3.1 asks for r27+ for C-12's 16 KiB alignment." >&2
  exit 2
fi
ndk_version="$(basename "$ndk_root")"
echo "sdk: $sdk_root"
echo "ndk: $ndk_root ($ndk_version)"

# Gradle. There is deliberately NO wrapper checked in: `shells/android` has no
# `gradlew`, so the version comes from the runner and is named in the evidence
# rather than assumed. A wrapper would be the better answer and belongs to
# `build/`, which this domain may not edit.
if [ -x "$GRADLE_DIR/gradlew" ]; then
  GRADLE="$GRADLE_DIR/gradlew"
elif command -v gradle >/dev/null; then
  GRADLE="$(command -v gradle)"
else
  echo "::error::no gradlew in shells/android and no gradle on PATH" >&2
  exit 2
fi
gradle_version="$("$GRADLE" --version 2>/dev/null | awk '/^Gradle / { print $2; exit }')"
echo "gradle: $GRADLE ($gradle_version)"

NDK_BIN="$ndk_root/toolchains/llvm/prebuilt/linux-x86_64/bin"
[ -d "$NDK_BIN" ] || { echo "::error::no linux-x86_64 prebuilt toolchain under $ndk_root" >&2; exit 2; }
"$NDK_BIN/clang" --version | head -1
echo

compiled=false
linked=false
loaded=false
invoked=false
received=false
shutdown=false
transitions='[]'
notes=""
exit_code=0

TEST_CMD="adb shell am instrument -w -e class $TEST_CLASS $INSTRUMENTATION"

# ---------------------------------------------------------------------------
# 1. the shared core, per ABI, against the real NDK
# ---------------------------------------------------------------------------
#
# Two libraries, not one. CD-I5 forbids `twinvpn-platform-android` to name
# `twinvpn-core`, so the core's JNI entries live in their own crate and their
# own `.so`, and `NativeBridge`'s `init` loads both. Merging them to save a load
# would invert exactly that arrow.
#
# `-Wl,-z,max-page-size=16384` is C-12 and is not cosmetic: a 4 KiB-aligned
# `.so` REFUSES TO LOAD on a device with a 16 KiB page size, and the failure
# lands at install time on a user's device rather than here.
echo "::group::build the CDYLIBs for every Phase-1 ABI"
core_ok=true
for entry in "${ABIS[@]}"; do
  abi="${entry%%:*}"
  rest="${entry#*:}"
  triple="${rest%%:*}"
  clang_prefix="${rest#*:}"
  cc="$NDK_BIN/${clang_prefix}${ANDROID_API_MIN}-clang"
  [ -x "$cc" ] || { echo "::error::$cc is missing; the NDK does not carry API $ANDROID_API_MIN for $abi" >&2; core_ok=false; break; }

  triple_env="$(echo "$triple" | tr 'a-z-' 'A-Z_')"
  export CC_${triple//-/_}="$cc"
  export AR_${triple//-/_}="$NDK_BIN/llvm-ar"
  export CARGO_TARGET_${triple_env}_LINKER="$cc"
  export CARGO_TARGET_${triple_env}_RUSTFLAGS="-C link-arg=-Wl,-z,max-page-size=16384"

  rustup target add "$triple" >/dev/null

  echo "--- $abi ($triple) ---"
  if ! (cd "$REPO/core" && cargo build --locked --release -q \
        -p twinvpn-platform-android --target "$triple" \
        --target-dir "$REPO/build/ci/android-target/core"); then
    core_ok=false; notes="twinvpn-platform-android did not build for $triple"; break
  fi
  if ! (cd "$REPO/shells/android/jni" && cargo build --locked --release -q \
        --target "$triple" \
        --target-dir "$REPO/build/ci/android-target/jni"); then
    core_ok=false; notes="twinvpn-android-jni did not link the shared core for $triple"; break
  fi

  mkdir -p "$JNILIBS/$abi"
  cp "$REPO/build/ci/android-target/core/$triple/release/libtwinvpn_platform_android.so" "$JNILIBS/$abi/"
  cp "$REPO/build/ci/android-target/jni/$triple/release/libtwinvpn_android_jni.so" "$JNILIBS/$abi/"
  ls -l "$JNILIBS/$abi/"
done
echo "::endgroup::"

if [ "$core_ok" = true ]; then
  compiled=true
  # The JNI library names `twinvpn-ffi` by path, which names `twinvpn-core` by
  # path, with the shipping `full` profile. A `.so` that exists therefore linked
  # the REAL core -- there is no stub in the dependency graph to link instead.
  linked=true
fi

# ---------------------------------------------------------------------------
# 2. the app, and the ABI packaging assertion on the RELEASE artifact
# ---------------------------------------------------------------------------
release_abis=""
if [ "$linked" = true ]; then
  if android_build_step "assemble the app, the test package and the release artifact" \
       "$GRADLE_LOG" "$GRADLE_DIR" \
       "$GRADLE" --no-daemon :app:assembleDebug :app:assembleDebugAndroidTest :app:assembleRelease
  then
    :
  else
    linked=false
    notes="the Gradle build failed; the native libraries built but the app did not. The reason is printed in the clear above and in build/ci/logs/android/gradle-assemble.log"
  fi
fi

if [ "$linked" = true ]; then
  # C-12 and §11.9 row 3, asserted against the SHIPPED artifact rather than
  # against the emulator's own ABI. An APK carrying only `x86_64` would pass
  # every on-device test in this suite and fail on a user's phone with
  # `UnsatisfiedLinkError`, which VR-4 classes as a packaging defect.
  release_apk="$(find "$GRADLE_DIR/app/build/outputs/apk/release" -name '*.apk' -print -quit)"
  if [ -z "$release_apk" ]; then
    linked=false
    notes="no release APK was produced, so the ABI packaging assertion cannot be made"
  else
    echo "release artifact: $release_apk"
    release_abis="$(unzip -Z1 "$release_apk" | awk -F/ '/^lib\/.*\.so$/ { print $2 }' | sort -u | paste -sd, -)"
    echo "release ABIs: $release_abis"
    missing=""
    for entry in "${ABIS[@]}"; do
      abi="${entry%%:*}"
      unzip -Z1 "$release_apk" "lib/$abi/libtwinvpn_android_jni.so" >/dev/null 2>&1 \
        || missing="$missing $abi"
    done
    if [ -n "$missing" ]; then
      linked=false
      notes="the release APK is missing the core's JNI library for:$missing (ADR-0018 §11.9 row 3, app/build.gradle.kts:30)"
      echo "::error::$notes" >&2
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 3. a device
# ---------------------------------------------------------------------------
device_ready=false
if [ "$linked" = true ]; then
  echo "::group::device"
  adb start-server >/dev/null
  if [ "$do_privileged" = true ]; then
    if [ -z "${ANDROID_SERIAL:-}" ]; then
      echo "::error::--privileged needs ANDROID_SERIAL naming the attached physical device" >&2
      exit 2
    fi
    echo "physical device: $ANDROID_SERIAL"
  elif adb devices | awk 'NR>1 && $2=="device" { found=1 } END { exit !found }'; then
    echo "a device is already attached; not booting an emulator"
  else
    echo "booting the pinned emulator: $EMULATOR_IMAGE"
    # NOT `yes |`. This script runs under `set -o pipefail`, and an INFINITE
    # writer into a command that exits is a guaranteed pipeline failure rather
    # than an occasional one: `sdkmanager` closes its end as soon as the install
    # is done, and the pipeline then takes `yes`'s status -- 141 where SIGPIPE
    # kills it, 1 where SIGPIPE is ignored and the write returns EPIPE. Run
    # 33292510333 recorded the second form, "yes: standard output: Broken pipe",
    # as the only line between "booting the pinned emulator" and `make`'s
    # Error 1. The install had already succeeded; `sdkmanager` printed no
    # diagnostic of its own, and the emulator was never reached.
    #
    # A BOUNDED writer cannot reach that state. 64 lines is ~128 bytes and a
    # pipe buffer is 64 KiB, so `printf` completes its single write and exits 0
    # before `sdkmanager` reads anything, whatever `sdkmanager` then does. The
    # prompt is one `y` per package whose licence is not already accepted and
    # there are three packages here, so 64 is a ceiling with room in it rather
    # than a count that has to be kept in step with the list.
    printf 'y\n%.0s' $(seq 64) \
      | "$sdk_root/cmdline-tools/latest/bin/sdkmanager" --install \
        "$EMULATOR_IMAGE" "platform-tools" "emulator" >/dev/null
    echo no | "$sdk_root/cmdline-tools/latest/bin/avdmanager" create avd \
      -n "$AVD_NAME" -k "$EMULATOR_IMAGE" --force
    # `-no-snapshot`: every run starts from the freshly created image, so a run
    # cannot inherit state from the one before it. `-no-window` because there is
    # no display. Backgrounded and then waited for, rather than `-wait-for-boot`,
    # which the emulator has no such flag for.
    "$sdk_root/emulator/emulator" -avd "$AVD_NAME" \
      -no-window -no-audio -no-boot-anim -no-snapshot -gpu swiftshader_indirect \
      -camera-back none -camera-front none \
      > "$LOGDIR/emulator.log" 2>&1 &
    # BOUNDED. `adb wait-for-device` blocks forever by design -- it has no
    # timeout flag and no equivalent -- so an emulator that dies at launch, or
    # never registers with the daemon, hangs this script until the JOB's
    # `timeout-minutes: 120` kills it. That is the worst failure this script can
    # have: a job timeout is a CANCELLATION, `if: failure()` is false on one, and
    # the step that uploads `emulator.log` is therefore skipped. Two hours, and
    # the one artifact that says why.
    #
    # Run 33294161379 spent that way. The AVD was created -- "Auto-selecting
    # single ABI x86_64" is `avdmanager`'s last line -- and nothing followed,
    # which is only possible here: the boot poll below is bounded at 180 * 5s and
    # would have reported itself.
    #
    # 300s is generous for ATTACHING, which is not booting: the device appears in
    # `adb devices` long before `sys.boot_completed`, and the 15 minutes that
    # takes are the poll's below. There is no `|| true` -- the failure falls
    # through to `device_ready`, which reports it with the message it already has.
    if ! timeout 300 adb wait-for-device; then
      echo "the emulator did not attach to adb within 300s"
    fi
  fi

  # Booted is not attached. `sys.boot_completed` is the property the framework
  # sets last, and installing before it is set fails in ways that read as a
  # packaging problem.
  for _ in $(seq 1 180); do
    if [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; then
      device_ready=true
      break
    fi
    sleep 5
  done
  if [ "$device_ready" != true ]; then
    notes="the device never reported sys.boot_completed=1"
    echo "::error::$notes" >&2
  else
    adb shell getprop ro.build.version.sdk | tr -d '\r' | sed 's/^/device API: /'
    adb shell getprop ro.product.cpu.abi | tr -d '\r' | sed 's/^/device ABI: /'
  fi
  echo "::endgroup::"
fi

# ---------------------------------------------------------------------------
# 4/5/6. install, instrument, and drive the lifecycle
# ---------------------------------------------------------------------------
device_abi=""
if [ "$device_ready" = true ]; then
  device_abi="$(adb shell getprop ro.product.cpu.abi | tr -d '\r')"
  echo "::group::install and instrument"
  app_apk="$(find "$GRADLE_DIR/app/build/outputs/apk/debug" -name '*.apk' -print -quit)"
  test_apk="$(find "$GRADLE_DIR/app/build/outputs/apk/androidTest/debug" -name '*.apk' -print -quit)"
  [ -n "$app_apk" ] && [ -n "$test_apk" ] || {
    echo "::error::the debug APK or the androidTest APK is missing" >&2; exit 1;
  }
  adb install -r -g "$app_apk"
  adb install -r "$test_apk"

  # A clean logcat, so the markers this run produces cannot be confused with a
  # previous run's.
  adb logcat -c
  set +e
  adb shell am instrument -w -e class "$TEST_CLASS" "$INSTRUMENTATION" \
    2>&1 | tee "$LOGDIR/instrumentation.log"
  exit_code=${PIPESTATUS[0]}
  set -e
  adb logcat -d > "$LOGDIR/logcat.txt"
  echo "::endgroup::"

  # **`am instrument` exits 0 even when every test fails.** The verdict is in
  # the stream, and reading only the exit code is how an Android job goes green
  # on a suite that did not pass. Both are checked, and the OK line must be
  # present rather than merely the failure line absent -- a run that crashed
  # before the first test produces neither.
  # `tr -d '\r'`: `adb shell` may allocate a pty and hand back CRLF, which would
  # make the anchored match miss. It fails SAFE either way -- a missed OK line
  # is a FAIL, never a false PASS -- but it would fail for the wrong reason.
  tr -d '\r' < "$LOGDIR/instrumentation.log" > "$LOGDIR/instrumentation.txt"
  if [ "$exit_code" -eq 0 ] \
     && grep -qE '^OK \([0-9]+ tests?\)$' "$LOGDIR/instrumentation.txt" \
     && ! grep -q 'FAILURES!!!' "$LOGDIR/instrumentation.txt"; then
    loaded=true
    invoked=true
    received=true
    shutdown=true
  else
    exit_code=1
    notes="the instrumentation run failed; see build/ci/logs/android/instrumentation.log and logcat.txt"
  fi

  # THE TRANSITIONS ARE READ OUT OF THE TEST, NOT WRITTEN HERE.
  #
  # The test logs each marker as it OBSERVES the transition, so logcat is the
  # transport and this is the extraction. The markers are re-emitted one per
  # line into `lifecycle.log` first, because a logcat line carries a timestamp
  # and a tag before the message and the schema's format is anchored -- so the
  # same `^TWINVPN_LIFECYCLE_TRANSITION FROM->TO$` grep that `ci-linux.sh` uses
  # applies to the normalised file.
  #
  # `awk` rather than `grep`, because grep exits 1 on no match and this runs
  # under `set -o pipefail`; masking that with `|| true` would be the swallowed
  # failure this file's header forbids. No markers means an empty array, which
  # is what makes the verdict FAIL for a run that proved linking and nothing
  # else.
  awk 'match($0, /TWINVPN_LIFECYCLE_TRANSITION [A-Z_]+->[A-Z_]+/) {
         print substr($0, RSTART, RLENGTH)
       }' "$LOGDIR/logcat.txt" | sort -u > "$LOGDIR/lifecycle.log"
  transitions="$(
    awk '/^TWINVPN_LIFECYCLE_TRANSITION [A-Z_]+->[A-Z_]+$/ { print $2 }' \
      "$LOGDIR/lifecycle.log" | sort -u | sed 's/.*/"&"/' | paste -sd, -
  )"
  transitions="[${transitions}]"
  if [ "$transitions" = "[]" ] && [ -z "$notes" ]; then
    notes="the instrumentation passed but emitted no TWINVPN_LIFECYCLE_TRANSITION marker, so this run proves linking and execution and NOT a lifecycle transition"
  fi
fi

verdict="FAIL"
if [ "$compiled" = true ] && [ "$linked" = true ] && [ "$loaded" = true ] \
   && [ "$invoked" = true ] && [ "$received" = true ] && [ "$shutdown" = true ] \
   && [ "$transitions" != "[]" ]; then
  verdict="PASS"
fi

runner_kind="local"
if [ -n "${GITHUB_ACTIONS:-}" ]; then
  runner_kind="github-hosted"
  if [ "${RUNNER_ENVIRONMENT:-github-hosted}" != "github-hosted" ]; then
    runner_kind="self-hosted"
  fi
fi

# The artifact list. `logcat.txt` is a device log: it carries reason codes,
# package names and stack traces. It carries NO private device key, NO pairing
# secret, NO authentication token and NO tunnel payload -- `NativeLinkRunTest`
# never establishes a tunnel and ADR-0015 §11.4 classes an address SENSITIVE, so
# nothing in this shell logs one. It is uploaded on failure only.
cat > "$EVIDENCE" <<JSON
{
  "schema_version": 1,
  "platform": "android",
  "job_name": "${GITHUB_JOB:-android-link-run}",
  "runner": "${RUNNER_NAME:-local}",
  "runner_kind": "$runner_kind",
  "privileged": $do_privileged,
  "github_run_id": $([ -n "${GITHUB_RUN_ID:-}" ] && echo "\"$GITHUB_RUN_ID\"" || echo null),
  "github_run_url": $([ -n "${GITHUB_RUN_ID:-}" ] && echo "\"${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-}/actions/runs/$GITHUB_RUN_ID\"" || echo null),
  "commit": "$(cd "$REPO" && git rev-parse HEAD)",
  "toolchain": {
    "rustc": "$(rustc --version)",
    "cargo": "$(cargo --version)",
    "ndk": "$ndk_version",
    "gradle": "${gradle_version:-unknown}",
    "jdk": "$(java -version 2>&1 | head -1 | tr -d '"')",
    "emulator_image": "$([ "$do_privileged" = true ] && echo "physical device" || echo "$EMULATOR_IMAGE")",
    "device_abi": "$device_abi",
    "release_abis": "$release_abis"
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
  "artifacts": ["build/ci/logs/android/gradle-assemble.log","build/ci/logs/android/instrumentation.log","build/ci/logs/android/logcat.txt","build/ci/logs/android/emulator.log"],
  "notes": "$notes",
  "verdict": "$verdict",
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON

echo
echo "=== android evidence ==="
cat "$EVIDENCE"

[ "$verdict" = "PASS" ] || {
  echo "::error::android link/run did not pass: $notes" >&2
  exit 1
}
