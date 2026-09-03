#!/usr/bin/env bash
#
# ci-windows-killswitch.sh -- the black-box WFP kill-switch criterion,
# `WINDOWS-WFP-KILLSWITCH`.
#
# ===========================================================================
# WHERE THIS RUNS, AND WHY THAT IS NOT A DETAIL
# ===========================================================================
# ON THE L1 CONTROLLER -- a GitHub-hosted `windows-2025` runner -- driving a
# DISPOSABLE NESTED GUEST over PowerShell Direct. The product steps and every
# beacon happen in the guest; the oracle bookkeeping happens here.
#
# The product's Windows kill switch installs PERSISTENT WFP filters and, by
# ADR-0018 CB-6 and ADR-0022 §11.4, shutdown MUST NOT remove them. A correct
# fail-closed run therefore leaves the machine it ran on unable to reach the
# network -- which, on a CI runner, means the agent loses its connection to
# GitHub mid-job and the run is lost with no evidence. Correct product
# behaviour would look exactly like an infrastructure failure. So the filters
# are installed in a throwaway L2 guest that `scripts/twinvpn-l1.ps1` builds,
# drives and destroys. PowerShell Direct is a VMBus channel: it does not use the
# guest's network stack and survives the guest cutting itself off.
#
# THE CONTROL PLANE IS HERE AND THE DATA PLANE IS THERE, and that split is
# load-bearing rather than tidy. A correct kill switch blocks every packet the
# guest originates while armed, including a POST to the oracle's control API,
# so a guest reporting its own attempt counts would lose exactly the ARMED
# window's counts and the oracle would grade that shortfall INCONCLUSIVE -- the
# evidence destroyed by the product working. So this host opens the session,
# declares every phase, posts the counts the guest measured and closes; the
# guest runs `leak-probe.sh beacon --counts-file` and the product steps, and
# holds no oracle credential. `probe_host` is still `device`, because every
# beacon still leaves the guest.
#
# ===========================================================================
# WHAT MAKES THIS EVIDENCE RATHER THAN A SELF-REPORT
# ===========================================================================
# Nothing here asks TwinVPN whether it is blocking. The observation is made by
# `lab/twinoracle`, which the guest can reach only by emitting a packet that
# leaves it: it listens on a SECOND internal switch that is off-link for the
# guest, so its address is decided by TwinVPN's scope-deny filter exactly as an
# internet address would be. `scripts/twinvpn-l1.ps1` carries the address plan
# and the four ranges it must avoid.
#
# The ten steps, and where each one is below:
#    1 baseline unprotected egress            phase BASELINE, path u
#    2 connect TwinVPN                        `twinvpnctl net up`
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
# STEP 2 REFUSES TODAY, AND THIS SCRIPT RECORDS THAT RATHER THAN DYING ON IT
# ===========================================================================
# `net.up` cannot arm: the device has no overlay allocation, so `enforce::arm`
# (core/crates/twinvpn-core/src/enforce.rs:185) returns AUTH.IDENTITY_MISSING,
# blocks the host on the way out, and `twinvpnctl` exits non-zero. Four product
# walls stand behind it -- no production writer for `put_local_overlay`, no peer
# with a verified tunnel key binding, `RoutingMode::TwinnetOnly` installing no
# default route, and no protected resolver bound anywhere. Under `set -e` that
# killed the run at the `net up` line and produced nothing at all. The refusal
# is now CAPTURED -- exit code and message, verbatim -- and the remaining steps
# still execute, so the row is a measured FAIL that names its blocker instead of
# an absence. Nothing is weakened by continuing: an unarmed ARMED window
# BEACONS, so the oracle sees arrivals and the session fails. There is no path
# from a missing filter set to a pass.
#
# ===========================================================================
# USAGE
# ===========================================================================
# Not run directly. `scripts/twinvpn-l1.ps1 -Action run` sets the environment
# below and invokes it: TWINVPN_ORACLE_{URL,TOKEN}, TWINVPN_ORACLE_CONTROL_BY,
# TWINVPN_ORACLE_TOPOLOGY, TWINVPN_SENTINEL_{HOST,EGRESS_IDENTITY},
# TWINVPN_L1_CONTROLLER and TWINVPN_GUEST_VM. Optional: TWINVPN_ARMED_SECONDS
# (default 60), how long step 6 attempts egress -- longer is strictly better
# evidence and strictly slower.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EVIDENCE="$REPO/build/ci/evidence/windows-killswitch.json"
LOGDIR="$REPO/build/ci/logs/windows"
ORACLE_DIR="$REPO/build/ci/evidence/oracle"
PROBE="$REPO/build/ci/leak-probe.sh"
GUESTLOG="$LOGDIR/guest.log"
PRECOND_LOG="$LOGDIR/wfp-preconditions.log"
ARMED_LOG="$LOGDIR/wfp-armed.log"
ARMED_SECONDS="${TWINVPN_ARMED_SECONDS:-60}"
CRITERION="WINDOWS-WFP-KILLSWITCH"
GUEST_ROOT='C:\twinvpn'
mkdir -p "$(dirname "$EVIDENCE")" "$LOGDIR" "$ORACLE_DIR"
: > "$GUESTLOG"

# shellcheck disable=SC1091
. "$REPO/build/ci/digest.sh"

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*|Windows_NT) : ;;
  *)
    echo "::error::ci-windows-killswitch.sh must run on the Windows L1 controller" >&2
    exit 2 ;;
esac

# THE PLACEMENT GUARD, INVERTED FROM WHAT IT USED TO BE. This script used to run
# INSIDE the guest and refused unless it was marked as the disposable guest. It
# now runs on the CONTROLLER and drives the guest, so both halves are checked:
# the controller must have set us up, and we must NOT be the machine that is
# about to install persistent WFP filters.
if [ "${TWINVPN_L1_CONTROLLER:-}" != "1" ] || [ -z "${TWINVPN_GUEST_VM:-}" ]; then
  echo "::error::this script is the L1 half of the kill-switch lane and is \
started by \`scripts/twinvpn-l1.ps1 -Action run\`, which creates the disposable \
guest and exports TWINVPN_L1_CONTROLLER=1 and TWINVPN_GUEST_VM. Run by hand it \
would have no guest to drive." >&2
  exit 2
fi
if [ "${TWINVPN_DISPOSABLE_GUEST:-}" = "1" ]; then
  echo "::error::TWINVPN_DISPOSABLE_GUEST=1 is set, so this is the device under \
test. The controller half must not run here: it holds the oracle's control \
token, and the kill switch is about to block every packet this machine sends." >&2
  exit 2
fi
for v in TWINVPN_ORACLE_URL TWINVPN_ORACLE_TOKEN TWINVPN_SENTINEL_HOST \
         TWINVPN_SENTINEL_EGRESS_IDENTITY; do
  [ -n "${!v:-}" ] || { echo "::error::$v is unset; the controller sets it." >&2; exit 2; }
done

L1PS="$(cygpath -w "$REPO/scripts/twinvpn-l1.ps1")"
l1() {
  # pwsh (PowerShell 7), the engine the job's own steps run the controller
  # under, and with MSYS told not to rewrite PSModulePath: launched from
  # git-bash, Windows PowerShell 5.1 could not load Microsoft.PowerShell.Security
  # ("found ... but the module could not be loaded") and ConvertTo-SecureString
  # vanished with it, which is how run 4 died copying the payload.
  MSYS2_ENV_CONV_EXCL="PSModulePath${MSYS2_ENV_CONV_EXCL:+;$MSYS2_ENV_CONV_EXCL}" \
  pwsh.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$L1PS" "$@" 2>&1 | tr -d '\r'
}
# Every guest step's output is teed into one log: the precondition facts, the
# lifecycle markers and the `net up` refusal are all scraped back out of it.
# Absent arguments are OMITTED rather than passed as empty strings, which
# `powershell.exe -File` does not carry reliably across the shell boundary.
guest() {
  local step="$1"; shift
  local args=(-Action guest-exec -Step "$step")
  if [ $# -ge 1 ]; then args+=(-Arg1 "$1"); fi
  if [ $# -ge 2 ]; then args+=(-Arg2 "$2"); fi
  l1 "${args[@]}" | tee -a "$GUESTLOG"
}

echo "=== L1 toolchain ==="
rustc --version
cargo --version
cmd.exe //c ver 2>/dev/null | tr -d '\r' || true

# ---------------------------------------------------------------------------
# BUILD ON L1, RUN IN THE GUEST
# ---------------------------------------------------------------------------
# The guest carries no Rust toolchain, no MSVC and no package cache: a machine
# with a compiler on it does not resemble a user's, and the evidence would be
# about the wrong host. Everything is built here and copied in.
echo "::group::build the shipped binaries and the precondition test"
(cd "$REPO/shells/windows" && cargo build --locked --release -p twinvpnctl -p twinvpnsvc)
TWINVPN="$REPO/shells/windows/target/release/twinvpnctl.exe"
SVC="$REPO/shells/windows/target/release/twinvpnsvc.exe"
[ -x "$TWINVPN" ] && [ -x "$SVC" ] || {
  echo "::error::the release binaries are missing after a successful build" >&2; exit 1; }

# `--no-run` prints the executable's path in its JSON message stream; globbing
# `target/debug/deps` for the newest match would pick up a stale binary from a
# cached target dir, the exact mistake `artifact_digests` exists to catch.
PRECOND_EXE="$(cd "$REPO/core" && cargo test --locked --no-run \
   -p twinvpn-platform-windows --test wfp_preconditions --message-format=json 2>/dev/null \
   | twinvpn_python -c '
import json, sys
found = ""
for line in sys.stdin:
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("reason") == "compiler-artifact" and m.get("executable") \
       and m.get("target", {}).get("name") == "wfp_preconditions":
        found = m["executable"]
print(found)')"
[ -n "$PRECOND_EXE" ] || { echo "::error::cargo did not report a wfp_preconditions executable" >&2; exit 1; }
PRECOND_EXE="$(cygpath -u "$PRECOND_EXE")"
echo "precondition test binary: $PRECOND_EXE"
echo "::endgroup::"

# THE TUNNEL DRIVER, PINNED. ADR-0021 §11: the upstream Microsoft-signed Wintun
# binaries ship app-locally beside the service, and `build_adapter` refuses to
# start without `wintun.dll` beside it (PS-18). The MSI stages it from
# `$(var.WinTunDir)`; this lane stages it the same way, from the release
# wintun.net publishes together with its SHA-256. The zip carries every
# architecture; only the amd64 DLL goes in.
WINTUN_URL='https://www.wintun.net/builds/wintun-0.14.1.zip'
WINTUN_SHA256='07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
CACHE="$REPO/build/ci/.cache"
mkdir -p "$CACHE"
echo "::group::the tunnel driver"
[ -f "$CACHE/wintun.zip" ] || \
  curl -sS --fail --location --retry 3 -o "$CACHE/wintun.zip" "$WINTUN_URL"
twinvpn_verify_digest "$CACHE/wintun.zip" "$WINTUN_SHA256" "Wintun 0.14.1"
twinvpn_python - "$CACHE/wintun.zip" "$CACHE/wintun.dll" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as z, open(sys.argv[2], "wb") as out:
    out.write(z.read("wintun/bin/amd64/wintun.dll"))
PY
WINTUN_DLL="$CACHE/wintun.dll"
echo "::endgroup::"

# THE BYTES UNDER TEST, NAMED ON THIS SIDE OF THE COPY. The guest re-digests
# them afterwards and the two must agree: a digest taken only where the bytes
# were built says nothing about what arrived over VMBus.
ARTIFACT_DIGESTS="$(twinvpn_digest_json \
  twinvpnsvc.exe "$SVC" \
  twinvpnctl.exe "$TWINVPN" \
  wfp_preconditions.exe "$PRECOND_EXE" \
  wintun.dll "$WINTUN_DLL")"
echo "artifact digests: $ARTIFACT_DIGESTS"

# THE GUEST'S SHELL, PINNED. `leak-probe.sh` is bash and a stock Windows image
# has none. Git for Windows publishes the full tree as a tarball with a
# SHA-256 GitHub itself records; MinGit is smaller and was the obvious choice
# until it turned out to ship `usr/bin/sh.exe` (dash) and NO bash at all.
#
# It is decompressed HERE and copied in as a plain tar, so the guest needs no
# compression codec: in-box `tar.exe` is libarchive and reads uncompressed tar
# by definition. The five MSYS `/dev` and `/etc/mtab` symlinks are dropped --
# the msys runtime provides those at run time, and a symlink that Windows
# refuses to create would make `tar` exit non-zero for a reason unrelated to
# anything under test.
GIT_URL='https://github.com/git-for-windows/git/releases/download/v2.55.0.windows.5/Git-2.55.0.5-64-bit.tar.bz2'
GIT_SHA256='58fdf5679db11901697d2257cd076c8cdc49d64fe641b3e64ad158f1c5bf9b8d'
echo "::group::the guest's shell"
[ -f "$CACHE/git.tar.bz2" ] || \
  curl -sS --fail --location --retry 3 -o "$CACHE/git.tar.bz2" "$GIT_URL"
twinvpn_verify_digest "$CACHE/git.tar.bz2" "$GIT_SHA256" "Git for Windows 2.55.0.5"
twinvpn_python - "$CACHE/git.tar.bz2" "$CACHE/git.tar" <<'PY'
import sys, tarfile
src, dst = sys.argv[1], sys.argv[2]
with tarfile.open(src, "r:bz2") as inp, tarfile.open(dst, "w") as out:
    for m in inp:
        if m.issym():
            continue
        out.addfile(m, inp.extractfile(m) if m.isfile() else None)
print(f"repacked {src} as an uncompressed {dst}")
PY
echo "::endgroup::"

echo "::group::copy the payload into the guest"
guest stage
for pair in "$CACHE/git.tar:git.tar" "$SVC:bin\\twinvpnsvc.exe" "$TWINVPN:bin\\twinvpnctl.exe" \
            "$PRECOND_EXE:bin\\wfp_preconditions.exe" \
            "$WINTUN_DLL:bin\\wintun.dll" \
            "$REPO/build/ci/leak-probe.sh:build\\ci\\leak-probe.sh" \
            "$REPO/build/ci/leak-probe-rules.sh:build\\ci\\leak-probe-rules.sh" \
            "$REPO/build/ci/leak-probe-sentinel.sh:build\\ci\\leak-probe-sentinel.sh" \
            "$REPO/build/ci/digest.sh:build\\ci\\digest.sh"; do
  l1 -Action push -LocalPath "$(cygpath -w "${pair%%:*}")" \
                  -RemotePath "$GUEST_ROOT\\${pair#*:}"
done
echo "::endgroup::"

echo "::group::unpack the guest's shell and configure its network"
guest unpack-shell
guest prepare
echo "::endgroup::"

# The digests, compared across the copy. A mismatch means the guest is about to
# test bytes this job did not build.
for name in twinvpnsvc.exe twinvpnctl.exe wfp_preconditions.exe wintun.dll; do
  here="$(twinvpn_python -c '
import json, sys
print(json.loads(sys.argv[1]).get(sys.argv[2], ""))' "$ARTIFACT_DIGESTS" "$name")"
  there="$(grep -E "^TWINVPN_GUEST_DIGEST $name=" "$GUESTLOG" | tail -1 | sed 's/.*=//')"
  [ -n "$there" ] && [ "$here" = "$there" ] || {
    echo "::error::$name digests differ across the copy: L1 has ${here:-<none>}, \
the guest has ${there:-<none>}. The guest would be testing bytes this job did \
not build." >&2
    exit 1; }
done

# ---------------------------------------------------------------------------
# 0. preconditions -- measured in the guest, scraped here, and fatal
# ---------------------------------------------------------------------------
echo "::group::preconditions"
set +e
guest preconditions > "$PRECOND_LOG" 2>&1
precond_exit=$?
set -e
cat "$PRECOND_LOG"
echo "::endgroup::"
if [ "$precond_exit" -ne 0 ]; then
  echo "::error::the environment attestation failed; the guest cannot produce \
$CRITERION evidence. See $PRECOND_LOG" >&2
  exit 1
fi

# The facts, as a JSON fragment, built from what the test PRINTED. `awk` over
# both logs in one pass, so "no facts at all" is an empty string rather than a
# pipeline failure or a stray comma.
scrape_env() {
  awk '/^TWINVPN_PRECONDITION [A-Za-z0-9_]+=/ {
         sub(/\r$/, ""); sub(/^TWINVPN_PRECONDITION /, "");
         i = index($0, "="); k = substr($0, 1, i-1); v = substr($0, i+1);
         if (v == "true" || v == "false" || v ~ /^-?[0-9]+$/) printf "%s\"%s\": %s", sep, k, v;
         else { gsub(/"/, "", v); printf "%s\"%s\": \"%s\"", sep, k, v; }
         sep = ", ";
       }' "$@"
}

echo "::group::open the oracle session"
"$PROBE" open --platform windows --criterion "$CRITERION"
SESSION_ID="$("$PROBE" session-id)"
# THE SESSION IS CLOSED ON EVERY EXIT PATH, INCLUDING A CANCELLATION: one left
# open is a session whose phases never ended. INT and TERM are trapped as well
# as EXIT, because a bare `trap ... EXIT` does not run when the shell is killed
# by a signal -- which is exactly what a job timeout sends.
close_session() { "$PROBE" close >/dev/null 2>&1 || true; }
trap 'close_session' EXIT
trap 'close_session; exit 143' TERM INT
# WHERE THE HEARTBEAT RUNS, recorded on the session. It is this host, which is
# also the oracle's host: that catches an oracle that died and a listener that
# stopped binding, and cannot catch a broken route between sentinel and oracle,
# because on one host there is no such route. Said plainly here and in
# `sentinel_host` rather than left for a reader to work out.
"$PROBE" sentinel-claim --host "$TWINVPN_SENTINEL_HOST"
# The device needs the session's beacon URLs and probe token -- and nothing
# else. The control token stays here.
l1 -Action push -LocalPath "$(cygpath -w "$ORACLE_DIR/session.env")" \
                -RemotePath "$GUEST_ROOT\\build\\ci\\evidence\\oracle\\session.env"
echo "::endgroup::"

# One beacon window: in the guest, counts back over VMBus, posted from here.
beacon_window() {
  local seconds="$1" tag="$2"
  guest beacon "$seconds" "$tag"
  l1 -Action fetch -RemotePath "$GUEST_ROOT\\counts.env" \
                   -LocalPath "$(cygpath -w "$ORACLE_DIR/counts.env")"
  "$PROBE" attempts --from-file "$ORACLE_DIR/counts.env"
}

# The UNPROTECTED leg, MEASURED from the guest's routing table before TwinVPN
# touches it. `PATH_IDENTITY_PREREQUISITES` refuses a row whose two identities
# are equal, and a pair of differing constants would satisfy that check while
# describing nothing.
UNPROTECTED_PATH_IDENTITY="$(guest route-identity | grep -E '^if[0-9]+:' | tail -1 || true)"
echo "unprotected path identity: ${UNPROTECTED_PATH_IDENTITY:-<unreadable>}"

"$PROBE" phase BASELINE OBSERVE --path u
beacon_window 15 u

echo "::group::step 2 — connect TwinVPN"
# CAPTURED, not fatal, for the same reason as `net up` below: a service that
# will not start is a measured fact about the product on this host, and dying
# here would replace a red row that names it with a NOT-EXECUTED that does not.
set +e
guest service-up
SERVICE_UP_EXIT=$?
guest net-up
net_up_step_exit=$?
set -e
NET_UP_EXIT="$(grep -E '^TWINVPN_NET_UP_EXIT ' "$GUESTLOG" | head -1 | awk '{print $2}')"
NET_UP_EXIT="${NET_UP_EXIT:-$net_up_step_exit}"
NET_UP_REFUSAL="$(awk '/^TWINVPN_NET_UP_OUTPUT_BEGIN$/{f=1;next} /^TWINVPN_NET_UP_OUTPUT_END$/{f=0} f' \
                   "$GUESTLOG" | twinvpn_python -c 'import json,sys; print(json.dumps(sys.stdin.read().strip()[:2000]))')"
echo "::endgroup::"

PROTECTED_PATH_IDENTITY="$(guest route-identity | grep -E '^if[0-9]+:' | tail -1 || true)"
echo "protected path identity: ${PROTECTED_PATH_IDENTITY:-<unreadable>}"

"$PROBE" phase TUNNELLED OBSERVE --path p --disjoint-from BASELINE
beacon_window 15 p

# ---------------------------------------------------------------------------
# 4. the filters are ARMED -- read back from the engine, never assumed
# ---------------------------------------------------------------------------
echo "::group::step 4 — TwinVPN's own filters must be installed"
set +e
guest armed-check > "$ARMED_LOG" 2>&1
armed_step_exit=$?
set -e
cat "$ARMED_LOG"
echo "::endgroup::"
ARMED_EXIT="$(grep -E '^TWINVPN_ARMED_CHECK_EXIT ' "$ARMED_LOG" | head -1 | awk '{print $2}')"
ARMED_EXIT="${ARMED_EXIT:-$armed_step_exit}"
if [ "$ARMED_EXIT" -ne 0 ]; then
  echo "::warning::TwinVPN's WFP filters are not installed, so the window below \
measures an unprotected host. The run continues because an unprotected host \
BEACONS -- the oracle sees the arrivals and the session fails -- and stopping \
here would replace a measured failure with an absence of evidence."
fi

# ---------------------------------------------------------------------------
# 5-7. terminate the tunnel, then attempt egress on all three families
# ---------------------------------------------------------------------------
echo "::group::step 5 — terminate the tunnel abruptly"
guest kill
echo "::endgroup::"

"$PROBE" phase ARMED SILENCE --path p
echo "::group::steps 6-7 — ${ARMED_SECONDS}s of continuous IPv4, IPv6 and DNS egress attempts"
beacon_window "$ARMED_SECONDS" p
echo "::endgroup::"

# ---------------------------------------------------------------------------
# 8-9. restore, and verify traffic resumes only through TwinVPN
# ---------------------------------------------------------------------------
echo "::group::step 8 — restore the tunnel"
set +e
guest restore
set -e
echo "::endgroup::"

"$PROBE" phase RESTORED OBSERVE --path p --subset-of TUNNELLED
beacon_window 15 p

"$PROBE" close
# THE ORACLE'S OWN REPORT, WRITTEN WHERE `report.py` LOOKS FOR IT. On the
# external deployment a LATER job fetched this from the oracle's control API,
# which is what made the verdict independent of anything a lane wrote. An
# in-box oracle dies with the runner, so there is no later fetch to make: this
# lane writes the oracle's answer byte for byte, unmodified, and the job
# uploads it. The narrowing belongs in the diff rather than in a reader's head:
# the report is still COMPUTED by the oracle from what arrived, and
# `check_oracle_adjudication` still re-derives the verdict from its contents,
# but the chain of custody between the oracle and the gate is now this job.
"$PROBE" report > "$ORACLE_DIR/$SESSION_ID.json"
cp "$ORACLE_DIR/$SESSION_ID.json" "$LOGDIR/oracle-report.json"

oracle_verdict="$(twinvpn_python -c 'import json,sys; print(json.load(open(sys.argv[1]))["verdict"])' \
                  "$LOGDIR/oracle-report.json")"
echo "oracle verdict: $oracle_verdict"

# THE TRANSITIONS ARE READ OUT OF WHAT THE GUEST DID, NOT WRITTEN HERE. This
# lane used to interpolate a literal `["DISCONNECTED->CONNECTED", ...]`, which
# reported the same three transitions whether or not anything happened -- and
# named session states nothing in the tree produces. What the guest emits are
# the management-interface transitions it actually observed.
transitions="$(grep -oE '^TWINVPN_LIFECYCLE_TRANSITION [A-Z_]+->[A-Z_]+$' "$GUESTLOG" \
  | awk '{print $2}' | sort -u \
  | twinvpn_python -c 'import json,sys; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))')"

environment="$(scrape_env "$PRECOND_LOG" "$ARMED_LOG")"
[ -n "$environment" ] || environment='"wfp_preconditions_measured": false'

# THE NOTES ARE READ OUT OF WHAT THE GUEST MEASURED, NOT WRITTEN HERE. This
# lane used to interpolate a fixed story that ended at `net up` refusing
# AUTH.IDENTITY_MISSING, which was a source-review prediction and not a
# measurement: the first guest run that got this far found the service never
# reaching SERVICE_RUNNING, and the story would have said otherwise.
net_up_reason="$(sed -n '/^TWINVPN_NET_UP_OUTPUT_BEGIN/,/^TWINVPN_NET_UP_OUTPUT_END/p' "$GUESTLOG" \
  | grep -oE '"reason_code":"[^"]+"' | head -1 | cut -d'"' -f4)"
if [ "$SERVICE_UP_EXIT" = "0" ]; then
  service_note="TwinVPNService started and bound its management endpoint"
else
  service_note="TwinVPNService did not start: the guest's service-up step exited $SERVICE_UP_EXIT; guest.log carries sc.exe's error (1053 is the SCM's start timeout, which a process that never calls StartServiceCtrlDispatcherW always earns)"
fi
notes="the L1 controller holds the oracle control token and the guest holds none, so the ARMED window's attempt counts survive a working kill switch. EXECUTED: guest built and booted, binaries copied and digest-verified on both sides, WFP preconditions measured in the guest, oracle and sentinel up in-box with a measured sentinel egress identity, BASELINE OBSERVE seen by the oracle, service-up and net up attempted. MEASURED: $service_note; net up exited $NET_UP_EXIT with reason_code ${net_up_reason:-<none>}; the armed read-back exited $ARMED_EXIT. NOT YET REACHED, known from source review: once the service runs, enforce::arm refuses AUTH.IDENTITY_MISSING without an overlay allocation (enforce.rs:185), and four product walls stand behind it: no production writer for put_local_overlay, no peer with a verified tunnel key binding, RoutingMode::TwinnetOnly installing no default route, and no protected resolver bound anywhere. The remaining phases still ran and their results are measured, not assumed. graceful_shutdown is FALSE and that is the point: step 5 kills the service rather than asking it to stop."

verdict=FAIL
if [ "$oracle_verdict" = "PASS" ] && [ "$SERVICE_UP_EXIT" = "0" ] \
   && [ "$NET_UP_EXIT" = "0" ] && [ "$ARMED_EXIT" = "0" ]; then
  verdict=PASS
fi

cat > "$EVIDENCE" <<JSON
{
  "schema_version": 2,
  "platform": "windows",
  "criterion": "$CRITERION",
  "job_name": "${GITHUB_JOB:-windows-killswitch}",
  "runner": "${RUNNER_NAME:-hosted-windows-2025}",
  "runner_kind": "$([ -n "${GITHUB_ACTIONS:-}" ] && echo github-hosted || echo local)",
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
    "guest_disposable": true,
    "probe_host": "device",
    "oracle_topology": "in-box",
    "sentinel_egress_identity": "$TWINVPN_SENTINEL_EGRESS_IDENTITY",
    "dns_protected_resolver": "absent-in-product",
    "net_up_exit_code": ${NET_UP_EXIT:-null},
    "net_up_refusal": $NET_UP_REFUSAL,
    "service_up_exit_code": ${SERVICE_UP_EXIT:-null},
    "wfp_armed_check_exit_code": ${ARMED_EXIT:-null},
    "unprotected_path_established": $([ -n "$UNPROTECTED_PATH_IDENTITY" ] && echo true || echo false),
    "protected_path_established": $([ -n "$PROTECTED_PATH_IDENTITY" ] && echo true || echo false),
    "unprotected_path_identity": "$UNPROTECTED_PATH_IDENTITY",
    "protected_path_identity": "$PROTECTED_PATH_IDENTITY" },
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
  "test_command": "build/ci/ci-windows-killswitch.sh",
  "test_exit_code": $([ "$verdict" = PASS ] && echo 0 || echo 1),
  "artifacts": ["build/ci/evidence/oracle/$SESSION_ID.json",
                "build/ci/logs/windows/oracle-report.json", "build/ci/logs/windows/guest.log"],
  "notes": "$notes",
  "verdict": "$verdict",
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON

echo
echo "=== windows kill-switch evidence ==="
cat "$EVIDENCE"

[ "$verdict" = PASS ] || {
  echo "::error::$CRITERION did not pass: the oracle said $oracle_verdict, \
\`net up\` exited $NET_UP_EXIT and the armed readback exited $ARMED_EXIT. The \
evidence names what executed and what it is blocked on; see \
$LOGDIR/oracle-report.json and $GUESTLOG." >&2
  exit 1
}
