#!/usr/bin/env bash
#
# ci-windows-killswitch.sh -- the black-box WFP kill-switch criterion,
# `WINDOWS-WFP-KILLSWITCH`.
#
# ===========================================================================
# WHERE THIS RUNS, AND WHY THAT IS NOT A DETAIL
# ===========================================================================
# INSIDE THE DISPOSABLE NESTED GUEST. Never on the CI controller.
#
# The product's Windows kill switch installs PERSISTENT WFP filters and, by
# ADR-0018 CB-6 and ADR-0022 §11.4, shutdown MUST NOT remove them. A correct
# fail-closed run therefore leaves the machine it ran on unable to reach the
# network -- which, on a GitHub Actions controller, means the runner agent loses
# its connection to GitHub mid-job and the run is lost with no evidence. Correct
# product behaviour would look exactly like an infrastructure failure.
#
# So the L1 runner (an Azure Windows VM registered as a self-hosted runner)
# creates a throwaway L2 Hyper-V guest, copies the tree in, runs THIS script
# there over PowerShell Direct -- a VMBus channel that does not use the guest's
# network stack and therefore survives the guest being cut off -- copies the
# evidence back out, and destroys the guest. `scripts/twinvpn-azure-l1.ps1` is
# that controller. The L1 runner is outside the filters for the whole run.
#
# ===========================================================================
# WHAT MAKES THIS EVIDENCE RATHER THAN A SELF-REPORT
# ===========================================================================
# Nothing here asks TwinVPN whether it is blocking. The observation is made by
# `lab/twinoracle`, which runs off this machine and can only be reached by a
# packet that actually left. This script drives the phases; the oracle records
# what arrived; `build/acceptance/report.py` fetches the oracle's verdict from
# the oracle. See build/ci/leak-probe.sh.
#
# The ten steps, and where each one is below:
#
#    1 baseline unprotected egress            phase BASELINE
#    2 connect TwinVPN                        `twinvpn net up`
#    3 the oracle sees TUNNEL egress          phase TUNNELLED, sources disjoint
#    4 arm the real WFP protection            asserted by readback, not assumed
#    5 terminate the tunnel                   the service is KILLED, not asked
#    6 attempt IPv4, IPv6 and DNS egress      phase ARMED, continuous
#    7 require zero unauthorized observations the oracle's SILENCE phase
#    8 restore the tunnel                     service restart + `net up`
#    9 traffic resumes only through TwinVPN   phase RESTORED, sources subset
#   10 destroy the guest                      the L1 controller, not this script
#
# ===========================================================================
# PRECONDITIONS ARE MEASURED BEFORE ANY OF THAT
# ===========================================================================
# A run on an unprivileged caller, or a host whose Base Filtering Engine is
# stopped, or a host where a WFP write is refused, produces well-formed evidence
# that means nothing. `tests/wfp_preconditions.rs` measures those; this script
# scrapes its `TWINVPN_PRECONDITION` lines into the evidence's `environment`,
# and report.py refuses a PASS for the criterion if any is absent or false.
#
# ===========================================================================
# USAGE
# ===========================================================================
#   TWINVPN_ORACLE_URL=...  TWINVPN_ORACLE_TOKEN=...  ci-windows-killswitch.sh
#
# Optional: TWINVPN_ARMED_SECONDS (default 60) -- how long step 6 attempts
# egress. Longer is strictly better evidence and strictly slower.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EVIDENCE="$REPO/build/ci/evidence/windows-killswitch.json"
LOGDIR="$REPO/build/ci/logs/windows"
PROBE="$REPO/build/ci/leak-probe.sh"
ARMED_SECONDS="${TWINVPN_ARMED_SECONDS:-60}"
CRITERION="WINDOWS-WFP-KILLSWITCH"
mkdir -p "$(dirname "$EVIDENCE")" "$LOGDIR"

# shellcheck disable=SC1091
. "$REPO/build/ci/digest.sh"

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*|Windows_NT) : ;;
  *)
    echo "::error::ci-windows-killswitch.sh must run on Windows, inside the disposable guest" >&2
    exit 2 ;;
esac

# THE CONTROLLER GUARD.
#
# If this ever runs on the L1 runner, a correct fail-closed result disconnects
# the runner and the run dies with no evidence -- and the failure looks like
# flaky infrastructure rather than like a script in the wrong place. The guest
# is marked by the controller; refuse without the mark.
if [ "${TWINVPN_DISPOSABLE_GUEST:-}" != "1" ]; then
  echo "::error::TWINVPN_DISPOSABLE_GUEST=1 is not set. This script installs \
persistent WFP filters that survive the process by design (CB-6); running it \
anywhere but the throwaway L2 guest would cut the host off the network and take \
the CI controller with it." >&2
  exit 2
fi

echo "=== toolchain ==="
rustc --version
cargo --version
cmd.exe //c ver 2>/dev/null | tr -d '\r' || true

# ---------------------------------------------------------------------------
# 0. preconditions -- measured, scraped, and fatal
# ---------------------------------------------------------------------------
PRECOND_LOG="$LOGDIR/wfp-preconditions.log"
echo "::group::preconditions"
set +e
(cd "$REPO/core" && TWINVPN_WINDOWS_TEST=1 cargo test --locked -q \
   -p twinvpn-platform-windows --test wfp_preconditions -- --nocapture --test-threads=1) \
  2>&1 | tee "$PRECOND_LOG"
precond_exit=${PIPESTATUS[0]}
set -e
echo "::endgroup::"
if [ "$precond_exit" -ne 0 ]; then
  echo "::error::the environment attestation failed; this machine cannot produce \
$CRITERION evidence. See $PRECOND_LOG" >&2
  exit 1
fi

# The facts, as a JSON object, built from what the test PRINTED. `awk` rather
# than grep so that "no facts at all" is an empty object rather than a pipeline
# failure -- an empty `environment` is what report.py reads as NOT MEASURED, and
# it must reach the report rather than abort the run.
scrape_env() {
  tr -d '\r' < "$1" \
    | awk '/^TWINVPN_PRECONDITION [A-Za-z0-9_]+=/ {
             sub(/^TWINVPN_PRECONDITION /, "");
             i = index($0, "="); k = substr($0, 1, i-1); v = substr($0, i+1);
             # true/false/integers stay JSON scalars; everything else is a string.
             if (v == "true" || v == "false" || v ~ /^-?[0-9]+$/) printf "%s\"%s\": %s", sep, k, v;
             else { gsub(/"/, "", v); printf "%s\"%s\": \"%s\"", sep, k, v; }
             sep = ", ";
           }'
}

# ---------------------------------------------------------------------------
# 1-3. baseline, connect, tunnelled
# ---------------------------------------------------------------------------
TWINVPN="$REPO/shells/windows/target/release/twinvpnctl.exe"
SVC="$REPO/shells/windows/target/release/twinvpnsvc.exe"

echo "::group::build the shipped binaries"
(cd "$REPO/shells/windows" && cargo build --locked --release -p twinvpnctl -p twinvpnsvc)
echo "::endgroup::"
[ -x "$TWINVPN" ] && [ -x "$SVC" ] || {
  echo "::error::the release binaries are missing after a successful build" >&2; exit 1; }

# THE BYTES UNDER TEST, NAMED. Recorded here, immediately after the build and
# before the service is registered, so the digest is of the image that
# `sc.exe create` is about to point at rather than of whatever is on disk when
# the evidence is finally written. A cached `target/` that served a stale
# `twinvpnsvc.exe` produces a green row about a build nobody can point at, and
# this is the line that makes that visible.
ARTIFACT_DIGESTS="$(twinvpn_digest_json \
  twinvpnsvc.exe "$SVC" \
  twinvpnctl.exe "$TWINVPN")"
echo "artifact digests: $ARTIFACT_DIGESTS"

install_service() {
  # The SHIPPED service, registered the way the MSI registers it, so what runs
  # is the product and not a test harness impersonating it.
  sc.exe create TwinVPNService binPath= "$(cygpath -w "$SVC")" start= demand >/dev/null
  sc.exe start TwinVPNService >/dev/null
  # The management pipe is bound at step 7 of the start sequence; poll rather
  # than sleep a guessed interval.
  for _ in $(seq 1 30); do
    "$TWINVPN" status get >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "::error::TwinVPNService started but never bound its management endpoint" >&2
  return 1
}

echo "::group::open the oracle session"
"$PROBE" open --platform windows --criterion "$CRITERION"
SESSION_ID="$("$PROBE" session-id)"
# THE SESSION IS CLOSED ON EVERY EXIT PATH, INCLUDING A CANCELLATION.
#
# An open session is state the oracle holds. A run that dies between `open` and
# `close` -- a `set -e` abort, a `timeout-minutes` expiry, the guest being torn
# down -- leaves one behind, and a session left open is a session whose phases
# never ended and whose report can still be fetched by the aggregator. Closing
# here is idempotent and never fails the script: the exit code is already
# decided by whatever got us here.
#
# INT and TERM are trapped as well as EXIT. A bare `trap ... EXIT` does NOT run
# when the shell is killed by a signal, which is exactly what a job timeout
# sends -- so the case that most needs the teardown was the case that skipped it.
close_session() { "$PROBE" close >/dev/null 2>&1 || true; }
trap 'close_session' EXIT
trap 'close_session; exit 143' TERM INT
echo "::endgroup::"

# THE SENTINEL IS A STANDING PROCESS, AND THIS JOB ONLY DECLARES IT.
#
# A SILENCE phase is creditable only when an INDEPENDENT heartbeat proves the
# oracle was still listening throughout it -- otherwise an oracle that died and
# a kill switch that worked leave identical evidence. It cannot be started here:
# the oracle now CHECKS independence rather than assuming it, and discards any
# IPv4/IPv6 beat whose source address the device was also seen egressing from --
# reporting one that lands inside SILENCE as a FAIL. This guest is the device
# under test, and the L1 controller that could have run one is on the other
# side of a Hyper-V switch that ordinarily NATs the guest through the L1
# host's own address -- so an L1 heartbeat would be device-sourced too.
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

echo "::group::step 2 — connect TwinVPN"
install_service
"$TWINVPN" --output json status get | tee "$LOGDIR/status-before.json"
"$TWINVPN" net up
echo "::endgroup::"

"$PROBE" phase TUNNELLED OBSERVE --path p --disjoint-from BASELINE
"$PROBE" beacon --seconds 15

# ---------------------------------------------------------------------------
# 4. the filters are ARMED -- read back from the engine, never assumed
# ---------------------------------------------------------------------------
ARMED_LOG="$LOGDIR/wfp-armed.log"
echo "::group::step 4 — TwinVPN's own filters must be installed"
set +e
(cd "$REPO/core" && TWINVPN_EXPECT_FILTERS=1 cargo test --locked -q \
   -p twinvpn-platform-windows --test wfp_preconditions -- --nocapture --test-threads=1 \
   twinvpns_own_filters_are_installed_right_now) 2>&1 | tee "$ARMED_LOG"
armed_exit=${PIPESTATUS[0]}
set -e
echo "::endgroup::"
if [ "$armed_exit" -ne 0 ]; then
  echo "::error::TwinVPN's WFP filters are not installed after net up, so the \
armed window below would measure an unprotected host" >&2
  "$PROBE" close || true
  exit 1
fi

# ---------------------------------------------------------------------------
# 5-7. terminate the tunnel, then attempt egress on all three families
# ---------------------------------------------------------------------------
#
# `taskkill /F` rather than `twinvpn net down` or `sc stop`, deliberately. The
# invariant is about UNEXPECTED disappearance: a graceful stop is a path the
# product controls and can tidy up on, and testing only that path would leave
# the crash case -- the one users hit -- unexamined. This is the Windows
# spelling of the same injection the iOS criterion makes against the
# NetworkExtension provider.
echo "::group::step 5 — terminate the tunnel abruptly"
taskkill //F //IM twinvpnsvc.exe //T 2>&1 | tr -d '\r' || echo "(already gone)"
# Confirm it is actually gone before the silence window opens. Silence while the
# service is still running would be a different claim entirely.
for _ in $(seq 1 20); do
  tasklist //FI "IMAGENAME eq twinvpnsvc.exe" 2>/dev/null | grep -qi twinvpnsvc || break
  sleep 1
done
if tasklist //FI "IMAGENAME eq twinvpnsvc.exe" 2>/dev/null | grep -qi twinvpnsvc; then
  echo "::error::twinvpnsvc.exe is still running; the tunnel was not terminated" >&2
  "$PROBE" close || true
  exit 1
fi
echo "::endgroup::"

"$PROBE" phase ARMED SILENCE --path p
echo "::group::steps 6-7 — ${ARMED_SECONDS}s of continuous IPv4, IPv6 and DNS egress attempts"
"$PROBE" beacon --seconds "$ARMED_SECONDS"
echo "::endgroup::"

# ---------------------------------------------------------------------------
# 8-9. restore, and verify traffic resumes only through TwinVPN
# ---------------------------------------------------------------------------
echo "::group::step 8 — restore the tunnel"
sc.exe delete TwinVPNService >/dev/null 2>&1 || true
install_service
"$TWINVPN" net up
echo "::endgroup::"

"$PROBE" phase RESTORED OBSERVE --path p --subset-of TUNNELLED
"$PROBE" beacon --seconds 15

"$PROBE" close
"$PROBE" report > "$LOGDIR/oracle-report.json"

# The oracle's own verdict, read from the report it just returned. It is
# recorded as `verdict_claimed` and is NOT what decides the row: the acceptance
# job fetches the same report from the oracle itself and compares.
oracle_verdict="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["verdict"])' \
                  "$LOGDIR/oracle-report.json")"
echo "oracle verdict: $oracle_verdict"

environment="$( { scrape_env "$PRECOND_LOG"; printf ", "; scrape_env "$ARMED_LOG"; } )"

cat > "$EVIDENCE" <<JSON
{
  "schema_version": 2,
  "platform": "windows",
  "criterion": "$CRITERION",
  "job_name": "${GITHUB_JOB:-windows-killswitch}",
  "runner": "${RUNNER_NAME:-disposable-nested-guest}",
  "runner_kind": "self-hosted",
  "privileged": true,
  "github_run_id": $([ -n "${GITHUB_RUN_ID:-}" ] && echo "\"$GITHUB_RUN_ID\"" || echo null),
  "github_run_attempt": $(twinvpn_run_attempt_json),
  "repository": $(twinvpn_repository_json),
  "artifact_digests": $ARTIFACT_DIGESTS,
  "github_run_url": $([ -n "${GITHUB_RUN_ID:-}" ] && echo "\"${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-}/actions/runs/$GITHUB_RUN_ID\"" || echo null),
  "commit": "$(cd "$REPO" && git rev-parse HEAD)",
  "toolchain": {
    "rustc": "$(rustc --version)",
    "cargo": "$(cargo --version)",
    "windows": "$(cmd.exe //c ver 2>/dev/null | tr -d '\r' | tr -s '\n' ' ')"
  },
  "environment": { $environment,
    "guest_kind": "nested-hyperv-guest",
    "guest_disposable": true },
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
  "lifecycle_transitions": ["DISCONNECTED->CONNECTED","CONNECTED->TERMINATED","TERMINATED->CONNECTED"],
  "graceful_shutdown": false,
  "test_command": "build/ci/ci-windows-killswitch.sh",
  "test_exit_code": 0,
  "artifacts": ["build/ci/logs/windows/oracle-report.json"],
  "notes": "graceful_shutdown is FALSE and that is the point: step 5 kills the service rather than asking it to stop, because the invariant under test is unexpected disappearance.",
  "verdict": "$([ "$oracle_verdict" = "PASS" ] && echo PASS || echo FAIL)",
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON

echo
echo "=== windows kill-switch evidence ==="
cat "$EVIDENCE"

[ "$oracle_verdict" = "PASS" ] || {
  echo "::error::the external leak oracle did not return PASS for session $SESSION_ID \
(it said $oracle_verdict); see $LOGDIR/oracle-report.json" >&2
  exit 1
}
