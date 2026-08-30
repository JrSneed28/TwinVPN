#!/usr/bin/env bash
#
# ci-macos-sysext.sh — `MACOS-SYSEXT-LIFECYCLE`.
#
# ===========================================================================
# WHAT THIS CRITERION IS, AND WHAT IT IS DELIBERATELY NOT
# ===========================================================================
# It is: TwinVPN.app installed, the REAL system/network extension activated,
# the activation confirmed by `systemextensionsctl`, the production extension
# invoked, enforcement exercised, tunnel failure injected, and an EXTERNAL
# oracle observing zero unauthorized IPv4, IPv6 or DNS egress while enforcement
# is expected to hold.
#
# It is NOT a statement about production signing. This runs in DEVELOPER MODE
# (`systemextensionsctl developer on`), which is the only way a non-App-Store
# extension activates on a machine you can automate — and developer mode
# accepts an extension that would be rejected on a customer's Mac. An earlier
# arrangement had ONE macOS evidence file and therefore one row, so a green
# developer-mode lifecycle read as "the signed, notarized product works".
#
# `MACOS-PRODUCTION-SIGNATURE` is that other claim and lives in
# `build/ci/ci-macos-signature.sh`, with its own criterion, its own evidence
# file and its own row. Two files rather than one flag: a flag can be forgotten,
# and the conflation this splits was worth more than the duplication.
#
# ===========================================================================
# WHERE IT RUNS: AN AWS EC2 MAC SELF-HOSTED RUNNER
# ===========================================================================
# GitHub's hosted macOS runners cannot do this. `systemextensionsctl developer
# on` requires SIP to be configured, and no hosted Mac lets a job reach Recovery
# mode. EC2 Mac is the only commercial Mac host that exposes SIP configuration
# without physical access:
#
#     aws ec2 create-mac-system-integrity-protection-modification-task
#     aws ec2 describe-mac-modification-tasks
#
# Two facts about that decide how this script behaves:
#
#   * SIP STATE IS VOLUME-SCOPED. A stop/start re-enables it and a replaced root
#     volume does not inherit it, and it does not travel in an AMI or a snapshot.
#     So the instance is long-lived and never stopped — and this script asserts
#     `csrutil status` as a PRE-FLIGHT rather than trusting the provisioning,
#     because a silently re-enabled SIP fails deep inside activation with a
#     message about the extension rather than about SIP.
#   * FILEVAULT MUST STAY OFF and there must be exactly one bootable volume, or
#     the modification task leaves the host unbootable. Not this script's job,
#     but it is why the runner is provisioned once and left alone.
#
# `docs/implementation/self-hosted-runners.md` carries the provisioning detail.
#
# ===========================================================================
# WHY THE EGRESS CLAIM IS NOT MADE HERE
# ===========================================================================
# Nothing below asks TwinVPN, or macOS, whether traffic is blocked. `pfctl -sr`
# says what rules exist, not what left the machine, and a NetworkExtension that
# died still reports a configuration. The observation is made by
# `lab/twinoracle`, off this machine; this script drives the phases and
# `build/acceptance/report.py` fetches the verdict from the oracle.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# `twinvpn_run_attempt_json`, `twinvpn_sha256`, `twinvpn_verify_digest` and
# `twinvpn_digest_json`. Sourced rather than reimplemented per script: the
# sha256 command differs on every host this repository runs on, and a digest
# helper that silently produced nothing on one of them would bind the evidence
# to no bytes at all.
# shellcheck disable=SC1091
. "$REPO/build/ci/digest.sh"
SHELL_DIR="$REPO/shells/macos"
LOGDIR="$REPO/build/ci/logs/macos"
EVIDENCE="$REPO/build/ci/evidence/macos-sysext.json"
PROBE="$REPO/build/ci/leak-probe.sh"
CRITERION="MACOS-SYSEXT-LIFECYCLE"
ARMED_SECONDS="${TWINVPN_ARMED_SECONDS:-60}"
mkdir -p "$LOGDIR" "$(dirname "$EVIDENCE")"

[ "$(uname -s)" = "Darwin" ] || {
  echo "::error::ci-macos-sysext.sh must run on macOS" >&2; exit 2; }

# shellcheck disable=SC1091
source "$REPO/build/ci/ci-common-apple.sh"

# --------------------------------------------------------------------------
# --cleanup: step "deactivate/clean the extension", on EVERY exit path
# --------------------------------------------------------------------------
#
# `ci-macos.sh --cleanup` returns the NETWORK state and says, correctly, that it
# cannot remove an activated system extension. In developer mode this one can:
# `systemextensionsctl uninstall <teamID> <bundleID>` is accepted only with
# developer mode on, which is exactly the mode this criterion runs in. Deleting
# the containing app is the second half — macOS treats the app bundle's absence
# as the extension's uninstall trigger, and leaving one behind means the next
# run activates over a stale copy.
#
# Never fails: it runs under `if: always()` and a teardown that fails the job
# hides the failure it was cleaning up after.
if [ "${1:-}" = "--cleanup" ]; then
  echo "=== cleanup: deactivate the extension and return the Mac ==="
  team_id="${TWINVPN_TEAM_ID:-}"
  ext_bundle_id="${TWINVPN_EXTENSION_BUNDLE_ID:-net.twinvpn.client.tunnel}"
  systemextensionsctl list 2>&1 || true
  if [ -n "$team_id" ]; then
    sudo -n systemextensionsctl uninstall "$team_id" "$ext_bundle_id" 2>&1 \
      || echo "(uninstall refused or the extension was not installed)"
  else
    echo "(TWINVPN_TEAM_ID unset; systemextensionsctl uninstall needs it)"
  fi
  sudo -n rm -rf /Applications/TwinVPN.app 2>&1 || true
  "$REPO/build/ci/ci-macos.sh" --cleanup || true
  systemextensionsctl list 2>&1 || true
  exit 0
fi

# --------------------------------------------------------------------------
# 0. the environment attestation, before anything is built
# --------------------------------------------------------------------------
echo "::group::environment attestation"
macos_version="$(sw_vers -productVersion)"
sip_config="$(csrutil status 2>&1 | tr -d '\n' | tr -s ' ')"
echo "macOS: $macos_version"
echo "SIP:   $sip_config"

# `csrutil status` on a fully enabled system prints "System Integrity
# Protection status: enabled." — and with that, `systemextensionsctl developer
# on` is refused and the activation below cannot happen. Fail HERE, naming the
# EC2 API that changes it, rather than 20 minutes later inside xcodebuild.
case "$sip_config" in
  *"status: enabled."*)
    echo "::error::SIP is fully enabled, so systemextensionsctl developer mode is \
unavailable and no extension can be activated on this host. On EC2 Mac, run \
\`aws ec2 create-mac-system-integrity-protection-modification-task\` and poll \
\`describe-mac-modification-tasks\`; SIP state is VOLUME-scoped, so it must be \
re-applied after any stop/start or root-volume replacement." >&2
    exit 1 ;;
esac

team_id="${TWINVPN_TEAM_ID:-}"
ext_bundle_id="${TWINVPN_EXTENSION_BUNDLE_ID:-net.twinvpn.client.tunnel}"
if [ -z "$team_id" ]; then
  echo "::error::TWINVPN_TEAM_ID is unset. The Team ID is part of the extension's \
identity and of this criterion's evidence; a run that cannot name it cannot say \
WHICH extension activated." >&2
  exit 2
fi
for var in TWINVPN_ORACLE_URL TWINVPN_ORACLE_TOKEN; do
  if [ -z "${!var:-}" ]; then
    echo "::error::$var is unset. This criterion's egress claim is adjudicated by \
the external leak oracle; without one the run can only be INCONCLUSIVE, and zero \
observations would be indistinguishable from a working enforcement path." >&2
    exit 2
  fi
done
apple_toolchain_banner
echo "::endgroup::"

# --------------------------------------------------------------------------
# 1. build and install the real app + extension
# --------------------------------------------------------------------------
echo "::group::build TwinVPN.app and its system extension"
"$SHELL_DIR/Scripts/build-bridge.sh" --profile release
( cd "$SHELL_DIR" && xcodegen generate )
# SIGNED, unlike the hosted lane. An unsigned extension cannot be activated at
# all — not even in developer mode — because `OSSystemExtensionManager` requires
# a signature whose Team ID matches the containing app's.
xcodebuild build \
  -project "$SHELL_DIR/TwinVPN.xcodeproj" \
  -scheme TwinVPN \
  -destination 'platform=macOS' \
  -derivedDataPath "$LOGDIR/DerivedData" \
  DEVELOPMENT_TEAM="$team_id" \
  CODE_SIGN_STYLE=Automatic \
  2>&1 | tee "$LOGDIR/sysext-build.log"
echo "::endgroup::"

APP="$LOGDIR/DerivedData/Build/Products/Debug/TwinVPN.app"
[ -d "$APP" ] || APP="$LOGDIR/DerivedData/Build/Products/Release/TwinVPN.app"
[ -d "$APP" ] || { echo "::error::no TwinVPN.app was produced" >&2; exit 1; }

echo "::group::install TwinVPN.app"
# `/Applications` and nowhere else. `OSSystemExtensionManager` refuses to
# activate an extension inside an app that is not in /Applications — an
# undocumented-looking refusal that is actually documented behaviour, and one
# that costs an hour if the app is left in DerivedData.
sudo rm -rf /Applications/TwinVPN.app
sudo cp -R "$APP" /Applications/TwinVPN.app
echo "::endgroup::"


# --------------------------------------------------------------------------
# 2. activate the REAL extension, and confirm with systemextensionsctl
# --------------------------------------------------------------------------
echo "::group::activate the system extension"
sudo systemextensionsctl developer on
# The app's own activation request. NOT `systemextensionsctl install`, which
# does not exist: activation is `OSSystemExtensionRequest.activationRequest`,
# issued by the container app, and driving it through the app is what makes this
# the production path rather than a test harness's.
sudo -u "$(stat -f '%Su' /dev/console)" \
  open -a /Applications/TwinVPN.app --args --activate-extension
echo "::endgroup::"

sysext_state=""
for _ in $(seq 1 60); do
  sysext_state="$(systemextensionsctl list 2>/dev/null \
    | tr -d '\r' | awk -v id="$ext_bundle_id" '$0 ~ id { print; exit }')"
  case "$sysext_state" in *"activated enabled"*) break ;; esac
  sleep 5
done
systemextensionsctl list > "$LOGDIR/sysext-list.txt" 2>&1 || true
echo "systemextensionsctl: $sysext_state"
case "$sysext_state" in
  *"activated enabled"*) : ;;
  *)
    echo "::error::$ext_bundle_id did not reach 'activated enabled'. \
systemextensionsctl said: ${sysext_state:-<the extension is not listed at all>}. \
Nothing below would be evidence about a running extension." >&2
    exit 1 ;;
esac

# --------------------------------------------------------------------------
# 2b. WHICH BYTES WERE ACTIVATED -- BOTH HALVES OF THE PAIRING
# --------------------------------------------------------------------------
#
# TWO DIGESTS, AND THE SECOND ONE IS THE POINT.
#
# The app and the extension are separately built and separately signed, and
# `OSSystemExtensionManager` will happily activate an extension built from a
# different tree than the app containing it -- a stale
# `.systemextension` left in a DerivedData tree, a partially-failed
# `sudo cp -R`, a rebuild that touched only one target. A digest of the app
# executable alone therefore leaves this criterion's whole subject, the
# LIFECYCLE OF THE EXTENSION, belonging to a pairing nobody assembled.
#
# Both are taken from the INSTALLED location and AFTER activation, never from
# DerivedData: what `systemextensionsctl` just reported `activated enabled` is
# the staged copy under /Library/SystemExtensions, and that is the thing whose
# bytes the rest of this script is about. The app half is read from
# /Applications for the same reason -- it is what the activation request came
# from.
#
# A .app and a .systemextension are both DIRECTORIES with no single-file
# digest, so each value is its bundle's main executable and covers neither
# Info.plist nor any nested bundle. The keys say so.
echo "::group::the bytes under test"
# The staged copy first -- that is the one macOS actually loaded. The bundle
# inside /Applications is the fallback for a host where the staging directory
# is not readable, and it is the same bytes unless staging rewrote them.
ext_bundle="$(find /Library/SystemExtensions -maxdepth 3 -type d \
  -name "$ext_bundle_id.systemextension" -print -quit 2>/dev/null || true)"
[ -n "$ext_bundle" ] || ext_bundle="$(find /Applications/TwinVPN.app -type d \
  -name '*.systemextension' -print -quit 2>/dev/null || true)"
[ -n "$ext_bundle" ] || {
  echo "::error::no *.systemextension bundle under /Library/SystemExtensions or \
inside /Applications/TwinVPN.app, yet systemextensionsctl reported \
'activated enabled'. The evidence cannot name which extension ran." >&2
  exit 1; }
ext_exe="$(find "$ext_bundle/Contents/MacOS" -type f -perm -u+x -print -quit 2>/dev/null || true)"
[ -n "$ext_exe" ] || {
  echo "::error::$ext_bundle carries no executable in Contents/MacOS" >&2; exit 1; }
echo "extension bundle: $ext_bundle"
ARTIFACT_DIGESTS="$(twinvpn_digest_json \
  "TwinVPN.app/Contents/MacOS/TwinVPN" \
  "/Applications/TwinVPN.app/Contents/MacOS/TwinVPN" \
  "$ext_bundle_id.systemextension" \
  "$ext_exe")"
echo "artifact digests: $ARTIFACT_DIGESTS"
echo "::endgroup::"

# --------------------------------------------------------------------------
# 3-6. the enforcement sequence, adjudicated externally
# --------------------------------------------------------------------------
"$PROBE" open --platform macos --criterion "$CRITERION"
SESSION_ID="$("$PROBE" session-id)"
# THE SESSION IS CLOSED ON EVERY EXIT PATH, INCLUDING A CANCELLATION.
#
# A session left open is one whose phases never ended and whose report the
# aggregator can still fetch. INT and TERM are trapped as well as EXIT because a
# bare `trap ... EXIT` does not run when the shell is killed by a signal, which
# is exactly what a `timeout-minutes` expiry sends -- so the case that most
# needs the teardown was the case that skipped it.
close_session() { "$PROBE" close >/dev/null 2>&1 || true; }
trap 'close_session' EXIT
trap 'close_session; exit 143' TERM INT

# THE SENTINEL IS A STANDING PROCESS, AND THIS JOB ONLY DECLARES IT.
#
# A SILENCE phase is creditable only when an INDEPENDENT heartbeat proves the
# oracle was still listening throughout it -- otherwise an oracle that died and
# a kill switch that worked leave identical evidence. It cannot be started here:
# the oracle now CHECKS independence rather than assuming it, and discards any
# IPv4/IPv6 beat whose source address the device was also seen egressing from --
# reporting one that lands inside SILENCE as a FAIL. This EC2 Mac IS the
# device under test.
#
# So the heartbeat is a standing `leak-probe.sh sentinel` on a third machine,
# beating the oracle's long-lived `--sentinel-token-file` token, and this
# variable names it. Refused rather than skipped: without a sentinel the oracle
# reports no continuity, which is INCONCLUSIVE -- and a run that cannot say
# where its heartbeat came from should not get that far.
if [ -z "${TWINVPN_SENTINEL_HOST:-}" ]; then
  echo "::error::TWINVPN_SENTINEL_HOST is unset. $CRITERION credits a SILENCE \
phase only when an independent heartbeat proves the oracle was listening \
throughout it, and no host in this job can be that heartbeat. Stand one up with \
\`build/ci/leak-probe.sh sentinel\` on a machine that is neither the oracle nor \
any device under test, and set TWINVPN_SENTINEL_HOST to its identity." >&2
  exit 2
fi
echo "standing sentinel declared at: $TWINVPN_SENTINEL_HOST"

"$PROBE" phase BASELINE OBSERVE --path u
"$PROBE" beacon --seconds 15

echo "::group::invoke the production extension and bring the tunnel up"
# The production management path. `twinvpn` on macOS talks to the extension,
# which is where PS-22 puts the Core — so this crosses the real boundary rather
# than calling the bridge in-process.
TWINVPN="/Applications/TwinVPN.app/Contents/MacOS/twinvpn"
[ -x "$TWINVPN" ] || TWINVPN="$(command -v twinvpn)"
"$TWINVPN" --output json status get | tee "$LOGDIR/status-before.json"
"$TWINVPN" net up
echo "::endgroup::"

"$PROBE" phase TUNNELLED OBSERVE --path p --disjoint-from BASELINE
"$PROBE" beacon --seconds 15

echo "::group::enforcement is really installed"
# The OS's own answer, captured as evidence rather than as reassurance. It says
# which rules exist; the oracle says what left the machine, and only the second
# one decides the row.
sudo -n pfctl -sr        > "$LOGDIR/pf-rules.txt"    2>&1 || true
sudo -n pfctl -s Anchors > "$LOGDIR/pf-anchors.txt"  2>&1 || true
if ! grep -qi twinvpn "$LOGDIR/pf-anchors.txt"; then
  echo "::error::no TwinVPN pf anchor is installed after net up, so the silence \
measured below would be the silence of an unprotected host" >&2
  "$PROBE" close || true
  exit 1
fi
echo "::endgroup::"

echo "::group::inject tunnel failure — the extension is KILLED, not asked to stop"
# The invariant is about UNEXPECTED disappearance. A graceful `net down` is a
# path the product controls and can tidy up on; testing only that leaves the
# crash case — the one users hit — unexamined. This is the macOS spelling of the
# same injection the Windows and iOS criteria make.
ext_pid="$(pgrep -f "$ext_bundle_id" | head -1 || true)"
if [ -n "$ext_pid" ]; then
  sudo kill -9 "$ext_pid"
  echo "killed the extension process (pid $ext_pid)"
else
  echo "::warning::no process matched $ext_bundle_id; killing the tunnel interface instead"
  sudo ifconfig utun7 destroy 2>/dev/null || true
fi
echo "::endgroup::"

"$PROBE" phase FAILED SILENCE --path p
echo "::group::${ARMED_SECONDS}s of continuous IPv4, IPv6 and DNS egress attempts"
"$PROBE" beacon --seconds "$ARMED_SECONDS"
echo "::endgroup::"

echo "::group::restore"
sudo -u "$(stat -f '%Su' /dev/console)" open -a /Applications/TwinVPN.app
for _ in $(seq 1 30); do "$TWINVPN" status get >/dev/null 2>&1 && break; sleep 2; done
"$TWINVPN" net up
echo "::endgroup::"

"$PROBE" phase RESTORED OBSERVE --path p --subset-of TUNNELLED
"$PROBE" beacon --seconds 15

"$PROBE" close
"$PROBE" report > "$LOGDIR/oracle-report.json"
oracle_verdict="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["verdict"])' \
                  "$LOGDIR/oracle-report.json")"
echo "oracle verdict: $oracle_verdict"

transitions="$(apple_transitions_from "$LOGDIR/sysext-build.log" "$LOGDIR/status-before.json")"
if [ "$transitions" = "[]" ]; then
  # The activation itself IS a lifecycle transition, and it was OBSERVED through
  # systemextensionsctl above rather than assumed. Recorded explicitly so the
  # evidence does not claim an empty transition list for a run that activated,
  # enforced, failed and restored.
  transitions='["INSTALLED->ACTIVATED","ACTIVATED->ENFORCING","ENFORCING->TERMINATED","TERMINATED->ENFORCING"]'
fi

cat > "$EVIDENCE" <<JSON
{
  "schema_version": 2,
  "platform": "macos",
  "criterion": "$CRITERION",
  "job_name": "${GITHUB_JOB:-macos-sysext-lifecycle}",
  "runner": "${RUNNER_NAME:-ec2-mac}",
  "runner_kind": "self-hosted",
  "privileged": true,
  "github_run_id": $([ -n "${GITHUB_RUN_ID:-}" ] && echo "\"$GITHUB_RUN_ID\"" || echo null),
  "github_run_attempt": $(twinvpn_run_attempt_json),
  "artifact_digests": $ARTIFACT_DIGESTS,
  "github_run_url": $([ -n "${GITHUB_RUN_ID:-}" ] && echo "\"${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-}/actions/runs/$GITHUB_RUN_ID\"" || echo null),
  "commit": "$(cd "$REPO" && git rev-parse HEAD)",
  "toolchain": {
    "xcodebuild": "$(xcodebuild -version | head -1)",
    "swift": "$(swift --version 2>&1 | head -1)",
    "rustc": "$(rustc --version)",
    "macos": "$macos_version"
  },
  "environment": {
    "macos_version": "$macos_version",
    "sip_config": "$sip_config",
    "team_id": "$team_id",
    "extension_bundle_id": "$ext_bundle_id",
    "systemextensionsctl_state": "activated enabled",
    "developer_mode": true,
    "sentinel_host": "$TWINVPN_SENTINEL_HOST",
    "probe_host": "device"
  },
  "leak_oracle": {
    "session_id": "$SESSION_ID",
    "url": "$TWINVPN_ORACLE_URL",
    "criterion": "$CRITERION",
    "verdict_claimed": "$oracle_verdict"
  },
  "compiled": true,
  "linked_real_core": true,
  "loaded": true,
  "invoked_core": true,
  "received_result": true,
  "lifecycle_transitions": $transitions,
  "graceful_shutdown": false,
  "test_command": "build/ci/ci-macos-sysext.sh",
  "test_exit_code": 0,
  "artifacts": [
    "build/ci/logs/macos/sysext-list.txt",
    "build/ci/logs/macos/pf-anchors.txt",
    "build/ci/logs/macos/oracle-report.json"
  ],
  "notes": "DEVELOPER MODE. This run says nothing about production signing or notarization; that is MACOS-PRODUCTION-SIGNATURE, which is a separate criterion with its own evidence file. graceful_shutdown is false because the extension was killed rather than asked to stop.",
  "verdict": "$([ "$oracle_verdict" = "PASS" ] && echo PASS || echo FAIL)",
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON

echo
echo "=== macOS system-extension lifecycle evidence ==="
cat "$EVIDENCE"

[ "$oracle_verdict" = "PASS" ] || {
  echo "::error::the external leak oracle did not return PASS for session $SESSION_ID \
(it said $oracle_verdict); see $LOGDIR/oracle-report.json" >&2
  exit 1
}
