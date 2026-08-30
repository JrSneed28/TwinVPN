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
#                  emulator. NO LONGER PART OF THE ACCEPTANCE GATE -- the 16 KiB
#                  criterion it used to discharge is `--pagesize16k` below, on
#                  Google's official 16 KB emulator image, because local or
#                  user-owned hardware is no longer an acceptable dependency for
#                  the gate. Kept: it is still the fastest way to reproduce a
#                  run on a phone you own.
#   --pagesize16k  ANDROID-16K-PAGE-SIZE. Discovers Google's 16 KB page-size
#                  system image, REFUSES to continue unless the device reports
#                  `getconf PAGE_SIZE` = 16384, runs `zipalign -c -P 16 -v 4` on
#                  the release APK, and installs the PRODUCTION APK. Writes
#                  build/ci/evidence/android-16k.json.
#   --cleanup      uninstall the packages and kill the emulator, on every path.
#                  Safe under `if: always()`; never fails the job.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# `twinvpn_run_attempt_json`, `twinvpn_sha256`, `twinvpn_verify_digest` and
# `twinvpn_digest_json`. Sourced rather than reimplemented per script: the
# sha256 command differs on every host this repository runs on, and a digest
# helper that silently produced nothing on one of them would bind the evidence
# to no bytes at all.
# shellcheck disable=SC1091
. "$REPO/build/ci/digest.sh"
EVIDENCE="$REPO/build/ci/evidence/android.json"
# `{}` until an APK is actually installed. An ABSENT key and an empty map mean
# different things to report.py -- "the field was never written" versus "this run
# tested no artifact" -- and a run that died before the device was ready is
# honestly the second.
ARTIFACT_DIGESTS="{}"
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
EMULATOR_IMAGE="system-images;android-${EMULATOR_API};google_apis;x86_64"
AVD_NAME="twinvpn-ci-api${EMULATOR_API}"

# THE 16 KiB IMAGE IS DISCOVERED, NOT GUESSED.
#
# Google ships the page-size images under a `google_apis_ps16k` tag, and the tag
# has moved once already (it was `google_apis_ps16k_experimental` while the
# feature was pre-release). Hard-coding one package id means a rename turns this
# lane into "package not found" and somebody eventually deletes the assertion to
# make CI green. So the script asks `sdkmanager --list` which page-size images
# this SDK actually offers, takes the highest API level for the wanted ABI, and
# prints it -- and FAILS LOUDLY, naming what it did find, when there is none.
#
# `docs`: Support 16 KB page sizes, developer.android.com/guide/practices/page-sizes.
readonly PS16K_ABI="${TWINVPN_PS16K_ABI:-x86_64}"
readonly PS16K_MIN_API=35   # Android 15. The images do not exist below it.
# THE CEILING IS THE POINT, NOT THE FLOOR.
#
# `sys-img2-3.xml` publishes `google_apis_ps16k` for android-35 and android-36
# and ALSO for android-36.1, android-37.0, android-37.1, android-37.2 and the
# CANARY channel. "Highest wins" therefore drifts onto a preview platform the
# moment Google publishes one, and a criterion discharged on a beta is a
# criterion discharged on an OS no user has -- with the failure arriving as an
# unrelated-looking emulator or AndroidX incompatibility rather than as "this is
# a preview". So the sweep takes the highest STABLE level at or below this
# ceiling, and raising it is a reviewed edit.
#
# STABLE also means an INTEGER label. `36.1` is a preview of 37 and would have
# parsed as `36` under `part[2] + 0` -- scoring equal to the real android-36 and
# winning or losing by listing order, which is the worst possible way to choose.
readonly PS16K_MAX_API=36   # Android 16. Raise deliberately, never to chase a beta.

discover_ps16k_image() {
  local sdkmanager="$1" listing
  listing="$("$sdkmanager" --list 2>/dev/null | tr -d '\r')" || true
  printf '%s\n' "$listing" \
    | awk -v abi="$PS16K_ABI" -v min="$PS16K_MIN_API" -v max="$PS16K_MAX_API" '
        # The API label must be PURELY numeric: `android-36.1` and
        # `android-37.2` are previews and are excluded by the regex itself
        # rather than by arithmetic that would silently truncate them.
        match($0, /system-images;android-[0-9]+;[A-Za-z0-9_]*ps16k[A-Za-z0-9_]*;[A-Za-z0-9_-]+/) {
          pkg = substr($0, RSTART, RLENGTH);
          split(pkg, part, ";");
          sub(/android-/, "", part[2]);
          if (part[2] !~ /^[0-9]+$/) next;
          if (tolower(pkg) ~ /canary|preview|experimental/) next;
          # THE TAG DIRECTORY, MATCHED EXACTLY. `[A-Za-z0-9_]*ps16k[A-Za-z0-9_]*`
          # above also matches `google_apis_playstore_ps16k`, which sorts before
          # `google_apis_ps16k` in `sdkmanager --list` and therefore wins the
          # strict `>` below -- so the sweep silently selected the Play Store
          # image. That is a `user` build: no `adb root`, and the app-compat
          # properties this lane sets are refused on it. It still contains
          # `ps16k`, so `adjudication.py` would have accepted the row.
          #
          # An exact match rather than one more exclusion: a deny-list is
          # defeated by the next variant Google publishes, and naming the one
          # image this criterion is about cannot be.
          if (part[3] != "google_apis_ps16k") next;
          if (part[4] == abi && part[2] + 0 >= min && part[2] + 0 <= max && part[2] + 0 > best) {
            best = part[2] + 0; found = pkg;
          }
        }
        END { if (found) print found; }'
}

readonly APPLICATION_ID="net.twinvpn.android"
readonly TEST_PACKAGE="net.twinvpn.android.test"
TEST_CLASS="net.twinvpn.android.NativeLinkRunTest"
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
do_pagesize16k=false
do_run=true

for arg in "$@"; do
  case "$arg" in
    --reset)        do_reset=true ;;
    --privileged)   do_privileged=true ;;
    --pagesize16k)  do_pagesize16k=true ;;
    --cleanup)      do_cleanup=true; do_run=false ;;
    *)
      echo "ci-android.sh: unknown flag: $arg" >&2
      echo "usage: ci-android.sh [--reset] [--privileged] [--pagesize16k] [--cleanup]" >&2
      exit 2
      ;;
  esac
done

# THE TWO PRIVILEGED-ish MODES ARE MUTUALLY EXCLUSIVE.
#
# `--privileged` means "use the attached physical device and boot nothing";
# `--pagesize16k` means "boot Google's 16 KB page-size image". Together they
# would boot nothing and then assert a page size the attached device chose,
# which is neither criterion. Refuse rather than pick one.
if [ "$do_privileged" = true ] && [ "$do_pagesize16k" = true ]; then
  echo "::error::--privileged and --pagesize16k are different criteria and cannot be combined" >&2
  exit 2
fi

# `--pagesize16k` writes a DIFFERENT evidence file and discharges a DIFFERENT
# criterion. Two lanes writing `android.json` would let whichever finished last
# decide what the acceptance report says, and an emulator PASS must never be
# readable as the 16 KiB criterion's, nor the reverse.
CRITERION="ANDROID-LINK-RUN"
if [ "$do_pagesize16k" = true ]; then
  CRITERION="ANDROID-16K-PAGE-SIZE"
  EVIDENCE="$REPO/build/ci/evidence/android-16k.json"
  # SET HERE, NOT WHERE THE IMAGE IS DISCOVERED.
  #
  # `--reset` deletes the AVD by name and runs long before the emulator block
  # that discovers the image. Leaving the rename until then would make
  # `--reset --pagesize16k` delete the API-30 link/run AVD and leave the 16 KiB
  # one carrying the previous run's data dir -- so a reset would corrupt the
  # other lane and fail to reset this one.
  AVD_NAME="twinvpn-ci-ps16k"
fi

sdk_root="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
adb() { "$sdk_root/platform-tools/adb" "$@"; }

# ---------------------------------------------------------------------------
# WHERE THE AVD LIVES, said out loud, because the two tools disagree by default
# ---------------------------------------------------------------------------
#
# `avdmanager` and `emulator` resolve the AVD directory by DIFFERENT rules, and
# on a GitHub-hosted `ubuntu-24.04` runner those rules land in different places.
# Run 33297181847 is what that looks like: `avdmanager create avd` exits 0, and
# the emulator then reports
#
#     ERROR | Unknown AVD name [twinvpn-ci-api30]
#     ERROR | HOME is defined but there is no file twinvpn-ci-api30.ini
#             in $HOME/.android/avd
#
# **The AVD was created.** It went to `$XDG_CONFIG_HOME/.android/avd`, which the
# runner image sets to `/home/runner/.config`. cmdline-tools 12.0 -- the version
# that image pins -- resolves its `.android` folder in
# `AbstractAndroidLocations.computeAndroidFolder()` as
#
#     singlePathOf(ANDROID_USER_HOME, ANDROID_PREFS_ROOT, ANDROID_SDK_HOME)
#       ?: firstPathOf(TEST_TMPDIR, XDG_CONFIG_HOME, USER_HOME, HOME)/.android
#
# with `XDG_CONFIG_HOME` AHEAD OF `HOME`. The emulator's
# `ConfigDirs::getAvdRootDirectory()` consults `ANDROID_AVD_HOME`,
# `$ANDROID_SDK_HOME/avd` and `$HOME/.android/avd`, and never `XDG_CONFIG_HOME`
# -- which is exactly the three-entry list emulator 37.1.11 printed above.
#
# `ANDROID_AVD_HOME` is the ONE variable both tools honour, so it is the one
# that makes them agree. `ANDROID_USER_HOME` would dodge the `mkdir` below --
# it is the only one of these with `mustExist = false` -- but emulator 37.1.11
# DOES NOT READ IT: its own message above lists exactly three, and
# `ConfigDirs::getAvdRootDirectory()` agrees. Setting it would work only by the
# coincidence that `$ANDROID_USER_HOME/avd` equalled the emulator's last-resort
# fallback, and would break silently the moment the value changed.
# (`developer.android.com/tools/variables` claims the emulator searches
# `$ANDROID_USER_HOME/avd/`; the emulator's own runtime output disagrees, and
# the emulator wins.)
#
# It is set HERE, at the top, rather than beside the create, because three entry
# points need it and only one of them creates: the bare script, `--cleanup`, and
# `--reset`. `--reset` is the one that matters -- `avdmanager delete avd` below
# resolves through the same `AndroidLocations`, so without this it would look in
# the XDG path and silently delete nothing, leaving a stale AVD to survive the
# reset that exists to remove it. (`--cleanup` does not touch the AVD at all; it
# uninstalls the packages and kills the emulator.)
#
# This is a 22.04 -> 24.04 REGRESSION, not an OS difference: cmdline-tools 9.0,
# which the ubuntu-22.04 image pinned, has no XDG lookup in that chain at all.
#
# **THE `mkdir` IS LOAD-BEARING, NOT TIDINESS.** `ANDROID_AVD_HOME` carries
# `mustExist = true` in both implementations: `PathLocator.handlePath()` returns
# null for a directory that is absent and then drops the variable entirely, and
# the emulator's own read is guarded by `pathIsDir`. Exporting it at a path that
# does not exist yet is therefore SILENTLY IGNORED by both halves, which fails
# exactly as it does today while looking like the fix is in place.
# `:-` so a self-hosted rig can point this somewhere else and keep it; `set -u`
# safe, and `mkdir -p` is idempotent and still fails loudly on an unusable path.
export ANDROID_AVD_HOME="${ANDROID_AVD_HOME:-$HOME/.android/avd}"
mkdir -p "$ANDROID_AVD_HOME"

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

# The 16 KiB criterion runs BOTH classes: `NativeLinkRunTest` is the boundary
# proof and `PageSize16kTest` is the criterion's own -- the page size, the
# pending-JNI check, the service restart and the underlay exclusion. Naming both
# rather than replacing one keeps the boundary proof inside the criterion's
# evidence, so a 16 KiB run that broke the JNI carriage cannot pass on the
# strength of the page-size assertion alone.
if [ "$do_pagesize16k" = true ]; then
  TEST_CLASS="net.twinvpn.android.NativeLinkRunTest,net.twinvpn.android.PageSize16kTest"
fi
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
  # BOTH PAGE-SIZE FLAGS. They control different properties of the output and
  # only one of them is about `p_align`:
  #
  #   * `max-page-size` sets the PT_LOAD `p_align`, which is what the kernel
  #     refuses on and what `elf-align.py` reads back;
  #   * `common-page-size` sets the alignment lld rounds the END OF RELRO up to
  #     (`lld/ELF/LinkerScript.cpp`: "If .relro_padding is present, round up the
  #     end to a common-page-size boundary to protect the last page").
  #
  # Leaving the second at 4096 leaves writable data sharing the final 16 KiB
  # page with RELRO, and bionic deliberately over-protects: it mprotects every
  # page TOUCHED by the segment read-only (`linker/linker_phdr.cpp`: "We're
  # going to be over-protective here"). The library then SIGSEGVs with
  # `SEGV_ACCERR` on a 16 KiB device while `p_align` is correct and
  # `zipalign -c -P 16` passes -- a crash neither of this lane's two alignment
  # checks can see. lld clamps commonPageSize to <= maxPageSize, so 16384/16384
  # is the pairing that holds.
  export CARGO_TARGET_${triple_env}_RUSTFLAGS="-C link-arg=-Wl,-z,max-page-size=16384 -C link-arg=-Wl,-z,common-page-size=16384"

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
  # THE 16 KiB LANE BUILDS AND INSTALLS THE PRODUCTION APK.
  #
  # The debug build is a different artifact: unminified, not shrunk, and
  # packaged by a different code path. C-12's alignment claim is about the
  # `.so` inside the SHIPPED APK, so the criterion installs the release one --
  # which means the release build must be SIGNED, and the instrumentation
  # package must be signed by the same key or `adb install` refuses it. Hence
  # `-Ptwinvpn.testBuildType=release` and the four signing properties, which
  # `app/build.gradle.kts` deliberately gives no silent fallback for.
  gradle_targets=(:app:assembleDebug :app:assembleDebugAndroidTest :app:assembleRelease)
  gradle_props=()
  if [ "$do_pagesize16k" = true ]; then
    for var in TWINVPN_RELEASE_KEYSTORE TWINVPN_RELEASE_STORE_PASSWORD \
               TWINVPN_RELEASE_KEY_ALIAS TWINVPN_RELEASE_KEY_PASSWORD; do
      if [ -z "${!var:-}" ]; then
        echo "::error::$var is unset. $CRITERION installs the PRODUCTION APK, which \
must be signed; a debug-signed substitute would make the evidence say 'release' and \
the disk say otherwise." >&2
        exit 2
      fi
    done
    gradle_targets=(:app:assembleRelease :app:assembleReleaseAndroidTest)
    gradle_props=(
      "-Ptwinvpn.testBuildType=release"
      "-Ptwinvpn.release.storeFile=$TWINVPN_RELEASE_KEYSTORE"
      "-Ptwinvpn.release.storePassword=$TWINVPN_RELEASE_STORE_PASSWORD"
      "-Ptwinvpn.release.keyAlias=$TWINVPN_RELEASE_KEY_ALIAS"
      "-Ptwinvpn.release.keyPassword=$TWINVPN_RELEASE_KEY_PASSWORD"
    )
  fi
  if android_build_step "assemble the app, the test package and the release artifact" \
       "$GRADLE_LOG" "$GRADLE_DIR" \
       "$GRADLE" --no-daemon "${gradle_targets[@]}" "${gradle_props[@]}"
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
# 2b. C-12's alignment, asserted on the ARTIFACT by the SDK's own checker
# ---------------------------------------------------------------------------
#
# `zipalign -c -P 16 -v 4` is the command developer.android.com's page-size
# guide names, and it answers a question no on-device test can: whether every
# shared library inside the APK is 16 KiB-aligned, including the ABIs this
# emulator will never load. The on-device half proves the ONE library the
# emulator maps; this proves all four.
#
# It runs in BOTH lanes -- the check is cheap and the answer is about the
# shipped artifact either way -- but only the 16 KiB lane makes it fatal,
# because only that lane's criterion is about alignment.
zipalign_p16=false
if [ "$linked" = true ] && [ -n "${release_apk:-}" ]; then
  zipalign_bin="$(find "$sdk_root/build-tools" -name zipalign -type f 2>/dev/null | sort -V | tail -1)"
  if [ -z "$zipalign_bin" ]; then
    # A CHECK THAT DID NOT RUN CANNOT DISCHARGE A CRITERION.
    #
    # In the link/run lane this is a warning and stays one: alignment is not
    # that lane's claim. In the 16 KiB lane it is the claim, and leaving
    # `zipalign_p16=false` with only a `::warning::` meant a missing SDK
    # component produced a row that read like a measured negative. Absence and
    # measurement must not share a value, and here absence must be loud.
    if [ "$do_pagesize16k" = true ]; then
      echo "::error::no zipalign under $sdk_root/build-tools. $CRITERION is a \
claim about 16 KiB alignment IN THE SHIPPED ARTIFACT, and the SDK's own checker \
is what makes it; a run that could not execute the check has not made the claim. \
Install a build-tools package on this runner." >&2
      exit 1
    fi
    echo "::warning::no zipalign in $sdk_root/build-tools; the 16 KiB alignment of the APK was not checked"
  else
    echo "::group::zipalign -c -P 16 -v 4 (C-12, on the release artifact)"
    set +e
    "$zipalign_bin" -c -P 16 -v 4 "$release_apk" > "$LOGDIR/zipalign.log" 2>&1
    zipalign_exit=$?
    set -e
    tail -20 "$LOGDIR/zipalign.log"
    echo "::endgroup::"
    if [ "$zipalign_exit" -eq 0 ]; then
      zipalign_p16=true
    else
      echo "::error::zipalign -c -P 16 reports the release APK is NOT 16 KiB aligned; see build/ci/logs/android/zipalign.log" >&2
      if [ "$do_pagesize16k" = true ]; then
        linked=false
        notes="the release APK failed zipalign -c -P 16 -v 4, so its shared libraries cannot be mapped on a 16 KiB kernel"
      fi
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 2c. C-12's alignment in the ELF ITSELF, for EVERY shipped ABI
# ---------------------------------------------------------------------------
#
# THE THIRD CHECK, AND THE ONLY ONE THAT COVERS THE ABI USERS ACTUALLY RUN.
#
# `zipalign -c -P 16` (2b) proves each `.so` is 16 KiB-aligned WITHIN THE ZIP,
# so the loader can map it straight out of the APK -- a property of the
# archive's layout. `PageSize16kTest` proves the ONE library the emulator maps
# loads on a 16 KiB kernel, and the emulator is x86_64. Neither says anything
# about arm64-v8a's own ELF program headers, which is what every real phone
# loads and what `-Wl,-z,max-page-size=16384` is supposed to set.
#
# Those three fail independently. A build where the link flag was dropped for
# one ABI still zipaligns perfectly and still passes on an x86_64 emulator, and
# the defect surfaces as an install-time refusal on a user's arm64 device. So
# this reads `p_align` of every PT_LOAD segment of every `.so` in the release
# APK, per ABI, and requires >= 16384 from all of them.
#
# `elf-align.py` parses the program header table directly rather than scraping
# `readelf` -- GNU and LLVM readelf disagree about whether the Align column is
# on the LOAD line or its continuation, and a scraper tuned to one finds zero
# rows under the other, which reads exactly like "no libraries".
abi_alignment='{}'
if [ "$linked" = true ] && [ -n "${release_apk:-}" ]; then
  echo "::group::PT_LOAD alignment, every ABI in the release APK"
  set +e
  abi_alignment="$("$REPO/build/ci/elf-align.py" --apk "$release_apk")"
  abi_align_exit=$?
  set -e
  echo "::endgroup::"
  [ -n "$abi_alignment" ] || abi_alignment='{}'
  if [ "$abi_align_exit" -ne 0 ]; then
    # Fatal in the 16 KiB lane only, for the same reason zipalign is: alignment
    # is this criterion's whole claim, and it is not the link/run lane's.
    if [ "$do_pagesize16k" = true ]; then
      linked=false
      notes="a shipped ABI's .so cannot be mapped on a 16 KiB kernel -- either \
its PT_LOAD p_align is below 16384 or it is DEFLATED in the APK, both of which \
the x86_64 emulator can run past; see the ::error:: line above for which"
    else
      echo "::warning::a shipped ABI is not 16 KiB load-aligned; \
ANDROID-16K-PAGE-SIZE would fail on it"
    fi
  fi

  # THE BYTES THE ABI SWEEP WAS ABOUT. Recorded here rather than only at install
  # time, so a run that measured the artifact and then failed to boot a device
  # still names which APK it measured.
  ARTIFACT_DIGESTS="$(twinvpn_digest_json "app-${apk_variant:-release}.apk" "$release_apk")"
fi

# ---------------------------------------------------------------------------
# 2d. THE PREFLIGHT GATE: every class the instrumentation needs, DEFINED
# ---------------------------------------------------------------------------
#
# THIS REPLACES ONE 40-MINUTE CI ROUND TRIP PER MISSING CLASS.
#
# The 16 KiB lane builds the androidTest APK against the RELEASE variant, which
# is minified. AGP wraps the androidTest runtime classpath in a
# `SubtractingArtifactCollection` against the tested variant
# (`VariantDependencies.kt:265`), so every dependency artifact that is on BOTH
# runtime classpaths is packaged ONLY in the app APK -- and therefore has to
# survive the APP's R8 pass to exist at all.
#
# The androidTest R8 run cannot catch a casualty. It is handed the app's PRE-R8
# classes, as `TESTED_CODE` in `referencedButNotMergedScopes`
# (`ProguardConfigurableTask.kt:458-460`), so every class it needs resolves at
# BUILD time and is gone at RUN time. The build is structurally incapable of
# reporting this, and it has only ever arrived as a device crash before the
# first test method executed -- one class per run, one run per class:
#
#   33322921169  NoClassDefFoundError androidx.tracing.Trace
#   33324089343  NoClassDefFoundError kotlin.LazyKt
#   (the run after)  NoClassDefFoundError kotlin.collections.SetsKt, from
#                    `NativeLinkRunTest.kt:109`'s own `setOf` -- OUR test code,
#                    which is why the keep file derived from the LIBRARIES alone
#                    could not have contained it
#
# The question is STATIC, though: a class the test APK REFERENCES that NEITHER
# APK DEFINES cannot resolve on any device, and `apkanalyzer` answers it against
# the two built artifacts in seconds. So this enumerates ALL of them at once and
# refuses BEFORE the emulator is booted, which turns "one crash per run" into one
# list.
#
# WHY THE ANSWER IS NOT MOSTLY FALSE POSITIVES:
#
#   * the ANDROID RUNTIME's own packages are in neither APK by design and never
#     were -- `android.`, `java.`, `javax.`, `dalvik.`, `org.w3c.`, `org.xml.`,
#     `org.json.`, `org.apache.http.`;
#   * array descriptors (`com.example.Foo[]`) are printed as rows of their own
#     and name no class that anything could keep;
#   * COMPILE-ONLY annotations are deliberately absent from every runtime
#     classpath, and R8 is ALREADY told so by name. That list is READ OUT OF THE
#     `-dontwarn` LINES rather than restated here: a second copy would drift from
#     the one R8 actually obeys, and this way the fix for a new one is a single
#     edit that both consume.
#
# A class R8 RENAMED but kept is NOT a false-positive source: AGP hands the test
# APK the app's mapping (`-applymapping`), so its references were rewritten to
# the obfuscated names at build time and match what the app APK defines.
#
# The link/run lane does not run this. Its tested variant is `debug`, which is
# not minified, so nothing can have been shrunk out of it.

# `apkanalyzer` writes its answer to stdout and its complaints to stderr. A
# failure has to say WHICH APK and WHAT, rather than aborting on `set -e` with a
# bare status and no line -- the same defect `android_show_failure` exists for.
android_apkanalyzer_dex() {
  local out="$1" apk="$2"
  shift 2
  if ! "$apkanalyzer_bin" dex packages "$@" "$apk" > "$out" 2> "$out.err"; then
    echo "::error::apkanalyzer dex packages $* failed on $apk" >&2
    cat "$out.err" >&2
    return 1
  fi
}

if [ "$linked" = true ] && [ "$do_pagesize16k" = true ]; then
  # `|| true` ON A DISCOVERY, NOT ON A PROOF, and it is the same reasoning
  # `discover_ps16k_image` uses: `find` exits 1 when its directory is absent, and
  # under `set -e` an assignment from a failing command substitution ABORTS this
  # script with a bare status and no line -- so the careful `::error::` two lines
  # below would never be reached. What grades the result is the emptiness test,
  # not the exit code.
  preflight_test_apk="$(find "$GRADLE_DIR/app/build/outputs/apk/androidTest/release" \
    -name '*.apk' -print -quit 2>/dev/null || true)"
  if [ -z "$preflight_test_apk" ] || [ -z "${release_apk:-}" ]; then
    echo "::error::the preflight gate compares the two RELEASE APKs and one of them \
is absent (app='${release_apk:-}', androidTest='$preflight_test_apk'). \
:app:assembleReleaseAndroidTest is what produces the second." >&2
    exit 1
  fi

  apkanalyzer_bin="$sdk_root/cmdline-tools/latest/bin/apkanalyzer"
  if [ ! -x "$apkanalyzer_bin" ]; then
    # Same discovery-not-proof `|| true` as above: a runner whose cmdline-tools
    # layout differs must reach the diagnosis below, not die on `find`'s status.
    apkanalyzer_bin="$(find "$sdk_root/cmdline-tools" -name apkanalyzer -type f 2>/dev/null \
      | sort -V | tail -1 || true)"
  fi
  if [ -z "$apkanalyzer_bin" ] || [ ! -x "$apkanalyzer_bin" ]; then
    # NOT SKIPPED, for the same reason a missing `zipalign` is not skipped in 2b:
    # a check that did not run has made no claim, and the alternative to running
    # it here is discovering the same answer on the device forty minutes later,
    # one class at a time.
    echo "::error::no apkanalyzer under $sdk_root/cmdline-tools. It ships in \
cmdline-tools and is what makes 'the instrumentation references a class the app \
APK no longer defines' answerable before the emulator boots; without it this lane \
can only find that out by crashing on the device. Install a cmdline-tools package \
on this runner." >&2
    exit 1
  fi

  echo "::group::preflight: every class the instrumentation references, resolved"
  pf="$LOGDIR/preflight"
  rm -rf "${pf:?}"
  mkdir -p "$pf"
  echo "apkanalyzer: $apkanalyzer_bin"
  echo "app APK:     $release_apk"
  echo "test APK:    $preflight_test_apk"

  if ! android_apkanalyzer_dex "$pf/test-dex.txt"      "$preflight_test_apk" \
     || ! android_apkanalyzer_dex "$pf/app-defined.txt"  "$release_apk"        --defined-only \
     || ! android_apkanalyzer_dex "$pf/test-defined.txt" "$preflight_test_apk" --defined-only
  then
    echo "::endgroup::"
    exit 1
  fi

  # THE COLUMNS, PRINTED RAW, so the `$1`/`$2`/`$NF` below can be CHECKED against
  # what this SDK's apkanalyzer actually emitted rather than taken on faith.
  # Column 1 is the node type (`P` package, `C` class, `M` method, `F` field),
  # column 2 its state (`d` defined, `r` referenced, `k` kept, `x` removed), and
  # the last field of a `C` row is the class name.
  #
  # `head` reads the FILE and not a pipe from apkanalyzer: under `set -o
  # pipefail` a closed pipe would take a working run down with SIGPIPE.
  echo "--- apkanalyzer dex packages, first 5 rows, raw ---"
  head -5 "$pf/test-dex.txt"
  echo "---"

  # `LC_ALL=C` on every `sort` AND on the `comm`. `comm` requires its two inputs
  # ordered by the same collation it compares in, and a runner whose locale is
  # not C orders case differently -- which produces a WRONG set difference,
  # silently, in BOTH directions: invented missing classes and missed real ones.
  awk '$1=="C" && $2=="r" { print $NF }' "$pf/test-dex.txt"     | LC_ALL=C sort -u > "$pf/refs"
  awk '$1=="C" && $2=="d" { print $NF }' "$pf/app-defined.txt"  | LC_ALL=C sort -u > "$pf/app-defs"
  awk '$1=="C" && $2=="d" { print $NF }' "$pf/test-defined.txt" | LC_ALL=C sort -u > "$pf/test-defs"
  LC_ALL=C sort -u "$pf/app-defs" "$pf/test-defs" > "$pf/defs"

  refs_n="$(wc -l < "$pf/refs")"
  defs_n="$(wc -l < "$pf/defs")"
  echo "referenced by the test APK, defined elsewhere: $refs_n"
  echo "defined by the app APK and the test APK:       $defs_n"

  # THE PARSE ITSELF, CHECKED. If apkanalyzer's column layout ever moves, the awk
  # above extracts nothing and this gate would report every class in the project
  # as missing -- a wall of noise that reads like a catastrophic regression and is
  # really a tool upgrade. Zero on either side is a broken parse and never a real
  # answer: an APK always defines classes, and an instrumentation APK always
  # references some.
  if [ "$refs_n" -eq 0 ] || [ "$defs_n" -eq 0 ]; then
    echo "::endgroup::"
    echo "::error::the preflight gate parsed $refs_n referenced and $defs_n defined \
classes out of apkanalyzer's output, and neither of those can legitimately be zero. \
The column layout this gate reads has moved; the raw rows are printed above and the \
whole output is in build/ci/logs/android/preflight/." >&2
    exit 1
  fi

  # The compile-only packages, TAKEN FROM THE R8 CONFIGURATION rather than kept
  # as a second list here. `-dontwarn com.google.errorprone.annotations.**`
  # becomes the prefix `com.google.errorprone.annotations.`; a bare `-dontwarn`
  # names no prefix and is skipped, which can only make this gate stricter.
  {
    # `org.xmlpull.` is FRAMEWORK-PROVIDED, not missing: XmlSerializer ships in
    # android.jar, so R8 resolves it and emits no keep rule, while apkanalyzer --
    # which only ever sees the two APKs and never the framework -- reports it as
    # referenced by neither. Run 33328620759 listed it for exactly that reason.
    printf '%s\n' android. java. javax. dalvik. org.w3c. org.xml. org.xmlpull. org.json. org.apache.http.
    awk '$1=="-dontwarn" && NF>1 { p=$2; sub(/\**$/,"",p); if (p != "") print p }' \
      "$GRADLE_DIR/app/proguard-rules.pro" \
      "$GRADLE_DIR/app/proguard-androidtest-keep.pro"
  } | LC_ALL=C sort -u > "$pf/ignored-prefixes"
  echo "--- prefixes this gate does not report ---"
  cat "$pf/ignored-prefixes"

  LC_ALL=C comm -23 "$pf/refs" "$pf/defs" > "$pf/undefined"
  awk '
    NR==FNR { prefix[++n] = $0; next }
    /\[\]$/ { next }
    {
      for (i = 1; i <= n; i++)
        if (index($0, prefix[i]) == 1) next
      print
    }
  ' "$pf/ignored-prefixes" "$pf/undefined" > "$pf/missing"
  echo "::endgroup::"

  if [ -s "$pf/missing" ]; then
    echo "::error::the instrumentation APK references $(wc -l < "$pf/missing") class(es) \
that NEITHER APK DEFINES. Each one is a NoClassDefFoundError waiting for the device, and \
they are listed together so that fixing them costs one CI run rather than one run each." >&2
    echo "--- referenced by the test APK, defined by neither ---" >&2
    cat "$pf/missing" >&2
    echo "--- what to do with that list ---" >&2
    echo "Each entry is one of two things. If R8 shrank it out of the app APK -- which is \
what AGP's SubtractingArtifactCollection makes possible for anything on both runtime \
classpaths -- REGENERATE shells/android/app/proguard-androidtest-keep.pro with \
TraceReferences over the CURRENT androidTest sources; that file's header carries the \
command and the standing cost. If it is a compile-only annotation that is on no runtime \
classpath, add a -dontwarn for it to shells/android/app/proguard-rules.pro, which is the \
single list both R8 and this gate read. Do NOT hand-append a keep rule." >&2
    exit 1
  fi
  echo "preflight: all $refs_n referenced classes resolve inside the two APKs"
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
    if [ "$do_pagesize16k" = true ]; then
      # The image is discovered here rather than pinned above, so the failure
      # when Google renames the tag is "this SDK offers no ps16k image for
      # x86_64" with the listing to look at, not "package not found".
      found="$(discover_ps16k_image "$sdk_root/cmdline-tools/latest/bin/sdkmanager")"
      if [ -z "$found" ]; then
        echo "::error::this SDK offers no 16 KB page-size system image for $PS16K_ABI at API >= $PS16K_MIN_API." >&2
        echo "--- every page-size image sdkmanager does list ---" >&2
        "$sdk_root/cmdline-tools/latest/bin/sdkmanager" --list 2>/dev/null \
          | tr -d '\r' | grep -i 'ps16k' >&2 || echo "  (none at all)" >&2
        exit 1
      fi
      EMULATOR_IMAGE="$found"
      echo "16 KB page-size image discovered: $EMULATOR_IMAGE"
    fi
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
    # CAPTURED, and then CHECKED. `avdmanager` writes its prompts to stderr
    # without a trailing newline, so on the console its output interleaves with
    # everything else on the same line -- run 33295999765 shows
    # "Do you wish to create a custom hardware profile? [no]" with this script's
    # next echo run into it, and whatever avdmanager said after that is lost.
    # Its own log is the only place it can be read.
    avd_log="$LOGDIR/avdmanager.log"
    if ! echo no | "$sdk_root/cmdline-tools/latest/bin/avdmanager" create avd \
        -n "$AVD_NAME" -k "$EMULATOR_IMAGE" --force >"$avd_log" 2>&1; then
      echo "::error::avdmanager create avd failed for $AVD_NAME" >&2
      cat "$avd_log" >&2
      exit 1
    fi

    # **`avdmanager` CAN EXIT 0 WITHOUT WRITING AN AVD**, and that is what run
    # 33295999765 did: it selected the ABI -- so the system image was installed
    # and it found it -- prompted about a hardware profile, exited successfully,
    # and left no `.ini`. The emulator then reported, in `emulator.log` and
    # nowhere else:
    #
    #     ERROR | Unknown AVD name [twinvpn-ci-api30], use -list-avds
    #     ERROR | HOME is defined but there is no file twinvpn-ci-api30.ini
    #             in $HOME/.android/avd
    #
    # and exited immediately, leaving `adb wait-for-device` to hang and the boot
    # poll to spend its full 15 minutes on a device that was never launched.
    #
    # The exit code is therefore not evidence and is not treated as any. This
    # asks the EMULATOR -- the consumer, whose search path is the one that
    # matters -- whether the AVD it is about to be told to boot exists.
    #
    # It is kept now that `ANDROID_AVD_HOME` is exported above, because the check
    # is what proves the export WORKED. That variable is silently ignored when
    # its directory is absent, so a regression in the `mkdir` would reinstate the
    # original defect with no other symptom until the boot poll times out fifteen
    # minutes later. This says so in one line instead.
    #
    # A NOTE ON READING `avdmanager`'s LOG, because it misled once: a SUCCESSFUL
    # create prints nothing after "Do you wish to create a custom hardware
    # profile? [no]". `AvdManagerCli.createAvd()` has no success line, and
    # `AvdManager` carries only "AVD '%s' moved." and "AVD '%s' deleted." -- the
    # "Created AVD" string belongs to the retired `android create avd`. Silence
    # there is not evidence of anything.
    if ! "$sdk_root/emulator/emulator" -list-avds | grep -qx "$AVD_NAME"; then
      echo "::error::avdmanager exited 0 but the emulator cannot see $AVD_NAME" >&2
      echo "--- avdmanager said ---" >&2
      cat "$avd_log" >&2
      echo "--- emulator -list-avds ---" >&2
      "$sdk_root/emulator/emulator" -list-avds >&2
      echo "--- \$HOME/.android/avd ---" >&2
      ls -la "$HOME/.android/avd" >&2 || echo "  (no such directory)" >&2
      echo "ANDROID_AVD_HOME=${ANDROID_AVD_HOME:-<unset>}" >&2
      echo "ANDROID_SDK_HOME=${ANDROID_SDK_HOME:-<unset>}" >&2
      exit 1
    fi
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
    #
    # THE BINARY, NOT THE `adb` FUNCTION at the top of this file. `timeout`
    # EXECS its argument, and a shell function is not an executable -- so
    # `timeout 300 adb …` fails instantly with "timeout: failed to run command
    # 'adb': No such file or directory", which reads like a missing SDK and is
    # not one. Every other call site in this script wants the function, and this
    # one call site cannot have it.
    if ! timeout 300 "$sdk_root/platform-tools/adb" wait-for-device; then
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
# 3a. 16 KB APP COMPAT, TURNED OFF AND THEN READ BACK
# ---------------------------------------------------------------------------
#
# THIS IS DIAGNOSIS, NOT CORRECTNESS. Android's 16 KB app-compat mode presents
# 4096 to a process whose libraries are 4 KiB-aligned, so a run under compat
# FAILS `PageSize16kTest.the_running_kernel_uses_16_kib_pages` -- that test asks
# `Os.sysconf(_SC_PAGESIZE)` from INSIDE the app process, while the
# `getconf PAGE_SIZE` below is toybox, outside it. The two disagreeing is the
# signature of compat mode, and the lane already fails on it. What it does not
# do is SAY so: the failure reads as "wrong image".
#
# So the properties are turned off before anything is installed, and then READ
# BACK, because a `setprop` that was refused and a `setprop` that took look
# identical from the exit code. On a `user` build there is no `adb root` and the
# write may simply be ignored -- which is a fact about the run worth recording,
# not a reason to fail here. The readback is what the evidence carries.
#
# THE `|| true` IS NOT A SWALLOWED FAILURE, and this is the one place in this
# script where that is true. `setprop`'s exit code is not evidence of anything:
# it reports whether the write was accepted, and a refusal is a legitimate
# outcome on a `user` build. What the criterion is graded on is the GETPROP
# below, and a failed write shows up there as the value it did not change.
linker_16kb_app_compat="not attempted"
pm_16kb_app_compat_disabled="not attempted"
if [ "$do_pagesize16k" = true ] && [ "$device_ready" = true ]; then
  echo "::group::16 KB app compat"
  adb shell setprop bionic.linker.16kb.app_compat.enabled false 2>&1 || true
  adb shell setprop pm.16kb.app_compat.disabled true 2>&1 || true
  linker_16kb_app_compat="$(adb shell getprop bionic.linker.16kb.app_compat.enabled \
    2>/dev/null | tr -d '\r')"
  pm_16kb_app_compat_disabled="$(adb shell getprop pm.16kb.app_compat.disabled \
    2>/dev/null | tr -d '\r')"
  : "${linker_16kb_app_compat:=unset}"
  : "${pm_16kb_app_compat_disabled:=unset}"
  echo "bionic.linker.16kb.app_compat.enabled = $linker_16kb_app_compat"
  echo "pm.16kb.app_compat.disabled = $pm_16kb_app_compat_disabled"
  echo "::endgroup::"
fi

# ---------------------------------------------------------------------------
# 3b. THE PAGE SIZE, ASSERTED BEFORE ANYTHING IS INSTALLED
# ---------------------------------------------------------------------------
#
# `-Wl,-z,max-page-size=16384` is applied on every ABI and exercised by NOTHING
# unless the `.so` is actually mapped by a kernel with 16 KiB pages: a 4 KiB
# aligned library loads perfectly well on a 4 KiB device. So a 4096-byte-page
# emulator takes this lane green, writes evidence with every boolean true, and
# flips the criterion while leaving the alignment tested nowhere. That is a
# VACUOUS PASS and it is worse than a red row, because it is indistinguishable
# from a real one in the report.
#
# `getconf PAGE_SIZE` is the on-device answer: toybox reads
# `sysconf(_SC_PAGESIZE)`, which is the RUNNING kernel's page size and not a
# build-time constant, so it cannot be right about the wrong thing. It is
# checked here, before the APK is pushed, so a wrong image costs seconds rather
# than a whole instrumented run.
device_page_size=""
if [ "$device_ready" = true ]; then
  device_page_size="$(adb shell getconf PAGE_SIZE 2>/dev/null | tr -d '\r')"
  echo "device page size: $device_page_size"
  if [ "$do_pagesize16k" = true ] && [ "$device_page_size" != "16384" ]; then
    echo "::error::the device reports a ${device_page_size}-byte page. $CRITERION is \
about 16 KiB pages and nothing else discharges it; a green run here would be a vacuous \
pass. Boot Google's 16 KB page-size system image ($EMULATOR_IMAGE)." >&2
    exit 1
  fi
fi

# ---------------------------------------------------------------------------
# 3b. what this run actually ran on -- MEASURED, never assumed
# ---------------------------------------------------------------------------
#
# THE DIFFERENCE BETWEEN CONFIGURED AND OBSERVED IS THE WHOLE POINT.
#
# `EMULATOR_IMAGE` is what the script ASKED sdkmanager for. It is not evidence
# that the emulator booted that image: a stale AVD carrying a previous run's
# data dir, a `--force` create that silently reused an existing target, an
# sdkmanager that resolved the package to a different revision -- each leaves
# the configured string right and the running system different. So every fact
# below is read out of the BOOTED DEVICE, and the package revision out of the
# installed package's own `source.properties`, and report.py grades those.
#
# `ro.build.fingerprint` is the single most useful of them: it names the build
# id, the platform version and the incremental, so two runs that disagree can be
# told apart without anyone guessing which image moved.
device_fingerprint=""
device_api_level=""
device_kernel=""
emulator_version=""
image_revision=""
if [ "$device_ready" = true ]; then
  echo "::group::what booted"
  # `|| true` ON EVERY ONE OF THESE, AND IT IS NOT SLOPPINESS.
  #
  # These are MEASUREMENTS, and the code below already knows how to describe one
  # that could not be taken: each has a `<unreadable>` fallback, and the 16 KiB
  # lane then fails deliberately, by name, saying which fact is missing. Under a
  # bare `set -e` an assignment whose command substitution exits non-zero kills
  # the script instead -- and it kills it with the raw status and no message, so
  # run 33321779286 reported `make: *** [ci-android] Error 127` and named
  # nothing. An unreadable fact must reach the attestation as unreadable, not
  # abort the run before the attestation is written.
  device_fingerprint="$(adb shell getprop ro.build.fingerprint 2>/dev/null | tr -d '\r' || true)"
  device_api_level="$(adb shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r' || true)"
  device_kernel="$(adb shell uname -r 2>/dev/null | tr -d '\r' || true)"
  if [ "$do_privileged" != true ] && [ -x "$sdk_root/emulator/emulator" ]; then
    emulator_version="$("$sdk_root/emulator/emulator" -version 2>/dev/null \
      | tr -d '\r' | head -1 || true)"
  fi
  # The REVISION of the system image that is installed, from the package's own
  # `source.properties`. `EMULATOR_IMAGE` is a package PATH and carries no
  # version, so two runs a month apart can name the same path and boot different
  # bits; without this the evidence could not tell them apart.
  image_dir="$sdk_root/$(printf '%s' "$EMULATOR_IMAGE" | tr ';' '/')"
  if [ -f "$image_dir/source.properties" ]; then
    image_revision="$(tr -d '\r' < "$image_dir/source.properties" \
      | awk -F= '/^Pkg.Revision=/ { print $2; exit }')"
  fi
  echo "fingerprint: ${device_fingerprint:-<unreadable>}"
  echo "api level:   ${device_api_level:-<unreadable>}"
  echo "kernel:      ${device_kernel:-<unreadable>}"
  echo "emulator:    ${emulator_version:-<n/a>}"
  echo "image:       $EMULATOR_IMAGE rev ${image_revision:-<unknown>}"
  echo "::endgroup::"

  # Each of these is part of the criterion's environment attestation, so an
  # unreadable one is a gap rather than a detail: report.py cannot check what
  # the evidence does not carry. Fatal only in the 16 KiB lane, whose row is the
  # one that claims something about the machine.
  if [ "$do_pagesize16k" = true ]; then
    for fact in device_fingerprint device_api_level device_kernel image_revision; do
      if [ -z "${!fact}" ]; then
        echo "::error::$fact could not be read from the booted device or the \
installed package. $CRITERION's evidence must name the exact system it ran on, \
and a row whose environment cannot be attested is not a discharged criterion." >&2
        exit 1
      fi
    done
  fi
fi

# ---------------------------------------------------------------------------
# 4/5/6. install, instrument, and drive the lifecycle
# ---------------------------------------------------------------------------
device_abi=""
if [ "$device_ready" = true ]; then
  device_abi="$(adb shell getprop ro.product.cpu.abi | tr -d '\r')"
  echo "::group::install and instrument"
  apk_variant="debug"
  [ "$do_pagesize16k" = true ] && apk_variant="release"
  app_apk="$(find "$GRADLE_DIR/app/build/outputs/apk/$apk_variant" -name '*.apk' -print -quit)"
  test_apk="$(find "$GRADLE_DIR/app/build/outputs/apk/androidTest/$apk_variant" -name '*.apk' -print -quit)"
  [ -n "$app_apk" ] && [ -n "$test_apk" ] || {
    echo "::error::the $apk_variant APK or its androidTest APK is missing" >&2; exit 1;
  }
  # NAMED, so the log says which artifact answered. An `-unsigned` suffix here
  # is the signing config not having applied, and `adb install` would refuse it
  # a line later with a message that does not mention signing.
  echo "installing: $app_apk"
  echo "installing: $test_apk"

  # THE BYTES THAT WERE INSTALLED, NAMED. Computed here rather than after the
  # run, so the digest is of the file `adb install` is about to push and not of
  # whatever a later Gradle task leaves in `outputs/apk`. The 16 KiB criterion is
  # entirely about the `.so` inside the SHIPPED APK, and a cached Gradle build
  # that served a stale release APK produces a green ANDROID-16K-PAGE-SIZE row
  # about an artifact nobody can point at.
  ARTIFACT_DIGESTS="$(twinvpn_digest_json \
    "app-$apk_variant.apk" "$app_apk" \
    "app-androidTest-$apk_variant.apk" "$test_apk")"
  echo "artifact digests: $ARTIFACT_DIGESTS"
  case "$app_apk" in
    *unsigned*)
      echo "::error::the release APK is unsigned; the four twinvpn.release.* properties did not reach Gradle" >&2
      exit 1 ;;
  esac
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

  # A CONTAINED REFUSAL IS INVISIBLE TO THE INSTRUMENTATION TEST.
  #
  # `bridge::entry` no longer throws. It cannot: every entry there is a platform
  # callback, and a Java exception crossing back out of one is
  # `Process.killProcess`, not a report. A refused Android fact is therefore
  # logged and the entry returns -- which is correct, and is exactly why this
  # check has to exist. `NativeLinkRunTest` asserts LIFECYCLE ONLY; it says
  # nothing about network facts reaching the core. So a run in which the bridge
  # refused every observation still produces `startForegroundService`, every
  # transition, and `OK (n tests)`. Without the grep below, green would mean the
  # process SURVIVED not working, and the loud `FATAL EXCEPTION` this replaced
  # would have become a silent PASS.
  #
  # Same reasoning as the `am instrument` exit-code check above, one layer down:
  # the verdict is in the stream, not in the status. `tr -d '\r'` for the same
  # reason it is done there, and `awk` rather than `grep` because grep exits 1 on
  # no match under `set -o pipefail` -- masking that with `|| true` would be the
  # swallowed failure this file's header forbids.
  #
  # `received` is the boolean this flips, and it is the honest one: a refusal at
  # the bridge means the fact did NOT reach the core. `TWINVPN_BRIDGE_REFUSED`
  # and its tag are an interface with the Rust side, not a detail -- see
  # `bridge::entry`'s `LOG_TAG`.
  tr -d '\r' < "$LOGDIR/logcat.txt" > "$LOGDIR/logcat.norm"
  refusals="$(
    awk 'match($0, /TWINVPN_BRIDGE_REFUSED [A-Za-z]+ [A-Z0-9_.]+/) {
           print substr($0, RSTART, RLENGTH)
         }' "$LOGDIR/logcat.norm" | sort -u | paste -sd';' -
  )"
  if [ -n "$refusals" ]; then
    received=false
    exit_code=1
    echo "::error::the Rust bridge refused an Android fact, so it never reached the core: $refusals" >&2
    refusal_note="the bridge refused an Android fact ($refusals); the instrumentation suite asserts lifecycle only and cannot see this"
    if [ -z "$notes" ]; then
      notes="$refusal_note"
    else
      notes="$notes; $refusal_note"
    fi
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
# THE ENVIRONMENT ATTESTATION.
#
# Every value here is MEASURED -- the page size from the running kernel, the
# alignment from the SDK's own checker, the variant from the file that was
# actually installed, the pending-exception answer from the instrumented run's
# own logcat marker. `build/acceptance/report.py` refuses a PASS for
# ANDROID-16K-PAGE-SIZE unless `page_size` is exactly 16384, so a 4 KiB
# emulator cannot produce green evidence for this criterion no matter how well
# every test in it ran.
#
# `jni_pending_exception` is derived from the ABSENCE of the marker being
# false, and the marker is only printed by a run that survived 64 crossings --
# under CheckJNI a pending exception aborts the process, so an aborted run
# prints nothing and the key stays absent, which report.py reads as NOT
# MEASURED rather than as `false`. Absence is not a pass.
jni_clean="null"
if [ -f "$LOGDIR/logcat.norm" ] \
   && grep -q 'TWINVPN_ATTESTATION jni_pending_exception=false' "$LOGDIR/logcat.norm"; then
  jni_clean="false"
fi

# THE UNDERLAY EXCLUSION, WHICH THE TEST PROVED AND NOTHING RECORDED.
#
# `PageSize16kTest.the_underlay_set_never_contains_our_own_vpn_interface` asserts
# that no network carrying TRANSPORT_VPN reaches the set the adapter treats as
# underlay -- the defect being a tunnel carried by itself, whose symptom is a
# connection that comes up and then stalls with no error anywhere. It logs
# `TWINVPN_ATTESTATION underlay_excludes_vpn=true`, and until now this script
# scraped only the JNI line, so a proven property left no trace in the evidence
# and report.py had nothing to grade.
#
# `null` when absent, exactly like `jni_pending_exception`: a test that did not
# run and a test that ran and found a VPN in the underlay must not share a value.
underlay_excludes_vpn="null"
if [ -f "$LOGDIR/logcat.norm" ] \
   && grep -q 'TWINVPN_ATTESTATION underlay_excludes_vpn=true' "$LOGDIR/logcat.norm"; then
  underlay_excludes_vpn="true"
fi

cat > "$EVIDENCE" <<JSON
{
  "schema_version": 2,
  "platform": "android",
  "criterion": "$CRITERION",
  "job_name": "${GITHUB_JOB:-android-link-run}",
  "runner": "${RUNNER_NAME:-local}",
  "runner_kind": "$runner_kind",
  "privileged": $do_privileged,
  "environment": {
    "page_size": ${device_page_size:-null},
    "zipalign_p16": $zipalign_p16,
    "apk_variant": "${apk_variant:-none}",
    "jni_pending_exception": $jni_clean,
    "underlay_excludes_vpn": $underlay_excludes_vpn,
    "abi": "$device_abi",
    "abi_load_alignment": $abi_alignment,
    "api_level": ${device_api_level:-null},
    "build_fingerprint": "$device_fingerprint",
    "kernel_release": "$device_kernel",
    "emulator_version": "$emulator_version",
    "system_image_package": "$([ "$do_privileged" = true ] && echo "physical device" || echo "$EMULATOR_IMAGE")",
    "system_image_revision": "$image_revision",
    "linker_16kb_app_compat": "$linker_16kb_app_compat",
    "pm_16kb_app_compat_disabled": "$pm_16kb_app_compat_disabled",
    "emulator_image": "$([ "$do_privileged" = true ] && echo "physical device" || echo "$EMULATOR_IMAGE")"
  },
  "leak_oracle": null,
  "github_run_id": $([ -n "${GITHUB_RUN_ID:-}" ] && echo "\"$GITHUB_RUN_ID\"" || echo null),
  "github_run_attempt": $(twinvpn_run_attempt_json),
  "repository": $(twinvpn_repository_json),
  "artifact_digests": $ARTIFACT_DIGESTS,
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
  "artifacts": ["build/ci/logs/android/gradle-assemble.log","build/ci/logs/android/instrumentation.log","build/ci/logs/android/logcat.txt","build/ci/logs/android/emulator.log","build/ci/logs/android/avdmanager.log"],
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
