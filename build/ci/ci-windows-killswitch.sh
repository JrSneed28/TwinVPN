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
# STEP 2 USED TO REFUSE, AND WHAT NOW STANDS IN FOR THE MISSING WRITERS
# ===========================================================================
# `enforce::arm` (core/crates/twinvpn-core/src/enforce.rs:185) returns
# AUTH.IDENTITY_MISSING unless the device has a local overlay allocation AND one
# peer with a verified tunnel-key binding. Both live only in memory, both are
# written only through `ControlPlanePort`, and NEITHER HAS A PRODUCTION WRITER
# YET -- so `net up` refused, blocked the host on the way out, and `twinvpnctl`
# exited non-zero on every run.
#
# What closes it here is a LAB SEED and nothing else: `twinpeer seed` on L1
# generates one tunnel's key material, the guest half is pushed in below, and a
# `--features lab-seed` build of the service installs it at startup. THIS IS NOT
# A PRODUCT PATH and the evidence must never be read as if it were: the feature
# is off in `default`, does nothing without TWINVPN_LAB_SEED_FILE, and the
# service logs a WARN naming itself as a non-release artifact. What the criterion
# tests is downstream of the seed -- that an armed host blocks egress when the
# tunnel dies -- and that is unaffected by how the tunnel came to exist.
#
# The lane still CAPTURES a refusal rather than dying on it: exit code and
# message, verbatim, with the remaining steps executed, so a row that goes red
# names its blocker instead of being an absence. Nothing is weakened by
# continuing -- an unarmed ARMED window BEACONS, the oracle sees the arrivals
# and the session fails. There is no path from a missing filter set to a pass.
#
# ===========================================================================
# USAGE
# ===========================================================================
# Not run directly. `scripts/twinvpn-l1.ps1 -Action run` sets the environment
# below and invokes it: TWINVPN_ORACLE_{URL,TOKEN}, TWINVPN_ORACLE_CONTROL_BY,
# TWINVPN_ORACLE_TOPOLOGY, TWINVPN_SENTINEL_{HOST,EGRESS_IDENTITY},
# TWINVPN_L1_CONTROLLER and TWINVPN_GUEST_VM. Optional: TWINVPN_ARMED_SECONDS
# (default 120), how long step 6 attempts egress -- longer is strictly better
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
# 120 s, NOT 60, AND THE REASON IS THE ATTEMPT DENOMINATOR. `oracle_adjudication`
# requires 60 self-reported attempts PER FAMILY over the whole session, and the
# ARMED window is the one where every iteration pays for being blocked: two
# `curl --max-time 3` and an `nslookup` that has to time out. The four windows
# nominally yield about 165 at 1 Hz, but a DNS lookup that costs eight seconds
# instead of one drops the session's DNS total under the floor -- and the
# shortfall then surfaces as an oracle INCONCLUSIVE that nobody attributes to
# the loop having been slowed by the blocking it was measuring. The floor is
# also asserted outright below, so a shortfall names itself.
ARMED_SECONDS="${TWINVPN_ARMED_SECONDS:-180}"
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
         TWINVPN_SENTINEL_EGRESS_IDENTITY TWINVPN_L1_RUNDIR; do
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
#
# `--features lab-seed`, AND THE WORKFLOW'S OWN BUILD STEP PASSES THE SAME FLAG.
# The feature is off in `default` and does nothing without TWINVPN_LAB_SEED_FILE,
# but it changes the bytes: if the two commands disagreed, the workflow would
# build one twinvpnsvc.exe, this would rebuild another, and `artifact_digests`
# would name a binary that is not the one the guest ran. It is what lets
# `enforce::arm` find a local overlay allocation and a peer with a verified
# tunnel-key binding, neither of which has a production writer yet.
echo "::group::build the shipped binaries and the precondition test"
(cd "$REPO/shells/windows" && cargo build --locked --release -p twinvpnctl -p twinvpnsvc --features lab-seed)
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

# THE TUNNEL DRIVER, PINNED, and staged by `build/ci/fetch-wintun.sh` rather
# than here. There are two consumers now and only one pin may exist: the guest
# needs the DLL beside the service, and the LAB PEER on L1 needs it BEFORE this
# script runs at all, because `twinvpn-l1.ps1 -Action run` brings the peer's
# Wintun adapter up in `Start-Observers` and only then starts this sequence. The
# workflow calls the same script before `-Action run`; this call re-verifies the
# download rather than repeating it.
CACHE="$REPO/build/ci/.cache"
echo "::group::the tunnel driver"
WINTUN_DLL="$("$REPO/build/ci/fetch-wintun.sh")"
[ -s "$WINTUN_DLL" ] || { echo "::error::fetch-wintun.sh named no driver" >&2; exit 1; }
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
  # NOT anchored at the line start: under `--nocapture` the harness prints
  # `test <name> ... ` without a newline, so a test's first fact shares that
  # line, and an anchored match dropped three of the four facts.
  awk '/TWINVPN_PRECONDITION [A-Za-z0-9_]+=/ {
         sub(/\r$/, ""); sub(/^.*TWINVPN_PRECONDITION /, "");
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
#
# The per-family totals are ACCUMULATED here as well as posted, because the
# oracle sums them across windows (`twinoracle/src/control.rs:253`) and the gate
# then demands 60 per family. Reading them back on this side is what lets a
# shortfall be REFUSED by name below instead of arriving as an oracle
# INCONCLUSIVE with no attributable cause.
ATTEMPTS_IPV4=0; ATTEMPTS_IPV6=0; ATTEMPTS_DNS=0
beacon_window() {
  local seconds="$1" tag="$2"
  guest beacon "$seconds" "$tag"
  l1 -Action fetch -RemotePath "$GUEST_ROOT\\counts.env" \
                   -LocalPath "$(cygpath -w "$ORACLE_DIR/counts.env")"
  "$PROBE" attempts --from-file "$ORACLE_DIR/counts.env"
  # PARSED, not sourced: the file was written on the device under test, which is
  # the machine whose honesty this criterion is about. `leak-probe.sh` already
  # refuses one that is not three non-negative integers; this reads the same
  # three with a grep that cannot execute anything.
  local n fam
  for fam in ipv4 ipv6 dns; do
    n="$(grep -E "^$fam=[0-9]+$" "$ORACLE_DIR/counts.env" | tail -1 | cut -d= -f2 || true)"
    case "$fam" in
      ipv4) ATTEMPTS_IPV4=$((ATTEMPTS_IPV4 + ${n:-0})) ;;
      ipv6) ATTEMPTS_IPV6=$((ATTEMPTS_IPV6 + ${n:-0})) ;;
      dns)  ATTEMPTS_DNS=$((ATTEMPTS_DNS  + ${n:-0})) ;;
    esac
  done
}

# The UNPROTECTED leg, MEASURED from the guest's routing table before TwinVPN
# touches it. `PATH_IDENTITY_PREREQUISITES` refuses a row whose two identities
# are equal, and a pair of differing constants would satisfy that check while
# describing nothing.
UNPROTECTED_PATH_IDENTITY="$(guest route-identity | grep -E '^if[0-9]+:' | tail -1 || true)"
echo "unprotected path identity: ${UNPROTECTED_PATH_IDENTITY:-<unreadable>}"

"$PROBE" phase BASELINE OBSERVE --path u
beacon_window 15 u

# THE LAB SEED, INTO THE GUEST AND ONLY NOW. `Start-Observers` generated it on
# L1 with `twinpeer seed`; the guest half names the guest's own static key, the
# peer's public key and endpoint, and the overlay pair. The `lab-seed` build of
# the service reads it from TWINVPN_LAB_SEED_FILE, which
# `Register-TwinVpnService` puts in the service's `Environment` value -- so it
# has to be in place before `service-up`, and it must survive the restart in
# `restore`, which re-registers the service and reads it again.
#
# It is pushed AFTER the BASELINE window deliberately: BASELINE has to measure a
# guest carrying no TwinVPN state at all.
echo "::group::the lab tunnel seed"
SEED_SRC="$(cygpath -u "$TWINVPN_L1_RUNDIR")/guest.json"
[ -f "$SEED_SRC" ] || {
  echo "::error::no lab seed at $SEED_SRC. \`twinvpn-l1.ps1 -Action run\` writes it \
in Start-Observers with \`twinpeer seed\`; without it the service has no overlay \
allocation and no verified peer, and \`net up\` refuses AUTH.IDENTITY_MISSING." >&2
  exit 1; }
l1 -Action push -LocalPath "$(cygpath -w "$SEED_SRC")" \
                -RemotePath "$GUEST_ROOT\\lab-seed.json"
echo "::endgroup::"

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
# `|| true` ON EVERY SCRAPE, AND WITHOUT IT THE FALLBACK BESIDE IT IS DEAD CODE.
# Under `set -euo pipefail` an assignment whose command substitution ends in a
# `grep` that matched nothing adopts the pipeline's exit 1 and kills the script,
# so the `${VAR:-<fallback>}` on the next line never ran and the run died at
# exactly the moment the guest failed to print something. That inverts this
# lane's rule: a missing measurement must be a red row that names itself, never
# an aborted run with no evidence at all.
NET_UP_EXIT="$(grep -E '^TWINVPN_NET_UP_EXIT ' "$GUESTLOG" | head -1 | awk '{print $2}' || true)"
NET_UP_EXIT="${NET_UP_EXIT:-$net_up_step_exit}"
NET_UP_REFUSAL="$(awk '/^TWINVPN_NET_UP_OUTPUT_BEGIN$/{f=1;next} /^TWINVPN_NET_UP_OUTPUT_END$/{f=0} f' \
                   "$GUESTLOG" | twinvpn_python -c 'import json,sys; print(json.dumps(sys.stdin.read().strip()[:2000]))')"
echo "::endgroup::"

# THE STUB RESOLVER MOVES ONTO THE TUNNEL, and it is the LAB that moves it. The
# product programs no resolver of its own -- `assemble` uses
# `denied_dns_policy()` with empty stub addresses (enforce.rs:265-289) and the
# Windows DNS programme only ever touches the OVERLAY interface -- so with the
# guest still pointed at 10.78.0.53 the TUNNELLED window would record ZERO DNS
# arrivals: filter class 6 blocks port 53 on every non-overlay interface in both
# postures, and TUNNELLED would grade INCONCLUSIVE for `dns`.
#
# The stub is SWITCHED, never extended -- Windows would query both servers and a
# `p`-tagged phase would collect an arrival mapped `u` -- and it is deliberately
# NOT switched back before the ARMED window: that window has to test the
# tunnelled configuration with the tunnel dead.
guest dns-protected

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
ARMED_EXIT="$(grep -E '^TWINVPN_ARMED_CHECK_EXIT ' "$ARMED_LOG" | head -1 | awk '{print $2}' || true)"
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

# THE SECOND `net up`, WHICH NOTHING USED TO READ. The guest has printed
# TWINVPN_RESTORE_NET_UP_EXIT since the restore step existed; step 9's claim is
# that traffic RESUMES, and a restore whose `net up` refused cannot be a PASS
# even if the RESTORED window happens to be well formed. It joins the PASS
# condition and the evidence beside `net_up_exit_code`.
RESTORE_NET_UP_EXIT="$(grep -E '^TWINVPN_RESTORE_NET_UP_EXIT ' "$GUESTLOG" | tail -1 | awk '{print $2}' || true)"
echo "restore net up exit: ${RESTORE_NET_UP_EXIT:-<unreadable>}"

# The service restarted, so its DNS programme ran again and the overlay adapter
# is a new one. Re-pointing the stub is idempotent when nothing moved it and is
# the difference between a measured RESTORED window and an INCONCLUSIVE one
# when something did.
guest dns-protected

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

# THE DENOMINATOR, CHECKED HERE AS WELL AS BY THE GATE. `oracle_adjudication.py`
# refuses a family under 60 attempts, and by then the only symptom is an
# INCONCLUSIVE that reads like a leak-detection failure. The likeliest cause is
# mundane and entirely ours: an ARMED iteration that pays a `curl --max-time 3`
# twice plus an `nslookup` timeout runs far slower than 1 Hz, so the window
# yields fewer attempts than its seconds. Named here, the next run knows to
# raise TWINVPN_ARMED_SECONDS rather than to go looking at the product.
ATTEMPT_FLOOR=60
attempt_shortfall=""
for pair in "ipv4:$ATTEMPTS_IPV4" "ipv6:$ATTEMPTS_IPV6" "dns:$ATTEMPTS_DNS"; do
  if [ "${pair#*:}" -lt "$ATTEMPT_FLOOR" ]; then
    attempt_shortfall="${attempt_shortfall}${attempt_shortfall:+, }${pair%%:*} ${pair#*:}"
  fi
done
echo "attempts posted: ipv4=$ATTEMPTS_IPV4 ipv6=$ATTEMPTS_IPV6 dns=$ATTEMPTS_DNS (floor $ATTEMPT_FLOOR each)"
if [ -n "$attempt_shortfall" ]; then
  echo "::warning::the device reported fewer than $ATTEMPT_FLOOR attempts for: \
$attempt_shortfall. The oracle grades that INCONCLUSIVE, so this run cannot \
pass; raise TWINVPN_ARMED_SECONDS (currently $ARMED_SECONDS) rather than \
reading the verdict as a statement about the kill switch."
fi

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
  | grep -oE '"reason_code":"[^"]+"' | head -1 | cut -d'"' -f4 || true)"
# What the SCM reported and what the service itself wrote, both scraped from
# the guest's own lines. No fixed story: this note used to assert a 1053 start
# timeout for any non-zero exit, and run 11's service had passed the SCM
# handshake and refused three steps later.
service_state="$(grep -E '^TWINVPN_SERVICE_STATE ' "$GUESTLOG" | head -1 | sed 's/^TWINVPN_SERVICE_STATE //' || true)"
service_said="$(sed -n '/^TWINVPN_SERVICE_LOG_BEGIN$/,/^TWINVPN_SERVICE_LOG_END$/p' "$GUESTLOG" \
  | grep -E 'the service cannot start' | head -1 | tr -d '"' | cut -c1-600 || true)"
[ -n "$service_said" ] || service_said="$(sed -n '/^TWINVPN_SERVICE_LOG_BEGIN$/,/^TWINVPN_SERVICE_LOG_END$/p' "$GUESTLOG" \
  | grep -E '"level":"(ERROR|WARN)"' | head -1 | tr -d '"' | cut -c1-400 || true)"
if [ "$SERVICE_UP_EXIT" = "0" ]; then
  service_note="TwinVPNService started and bound its management endpoint (${service_state:-state unrecorded})"
else
  service_note="TwinVPNService did not reach its management endpoint: the guest's service-up step exited $SERVICE_UP_EXIT; sc.exe query reported ${service_state:-nothing (the state line is missing from guest.log)}; the service's own log said: ${service_said:-nothing (no error line was captured)}"
fi
notes="the L1 controller holds the oracle control token and the guest holds none, so the ARMED window's attempt counts survive a working kill switch. EXECUTED: guest built and booted, binaries copied and digest-verified on both sides, WFP preconditions measured in the guest, lab peer up on L1 holding the overlay addresses the oracle binds, oracle and sentinel up in-box with a measured sentinel egress identity, BASELINE OBSERVE seen by the oracle, lab seed pushed, service-up and net up attempted, stub resolver switched onto the tunnel, all four phases declared and closed. MEASURED: $service_note; net up exited $NET_UP_EXIT with reason_code ${net_up_reason:-<none>}; the armed read-back exited $ARMED_EXIT; the restore net up exited ${RESTORE_NET_UP_EXIT:-<unreadable>}; the device posted ipv4=$ATTEMPTS_IPV4 ipv6=$ATTEMPTS_IPV6 dns=$ATTEMPTS_DNS attempts against a floor of 60 each. TWO THINGS IN THIS RUN ARE THE LAB AND NOT THE PRODUCT, and the row means nothing if they are read as product behaviour: the overlay allocation and the verified peer binding come from a --features lab-seed build reading twinpeer's seed file, because neither has a production writer; and the protected resolver is a stateless relay on the peer overlay, because enforce.rs:265-289 assembles denied_dns_policy() with empty stub addresses and TwinVPN binds no DNS listener. Neither touches what the criterion asserts -- that an armed host blocks egress once the tunnel dies -- which is measured by an oracle the guest can only reach by emitting a packet that left it. The beacon target is the peer OVERLAY address deliberately: in RoutingMode::TwinnetOnly the Tier-1 protected scope is the baseline floor plus the peers' host routes and nothing else, so a target outside it is not governed at all and an armed host would permit it. graceful_shutdown is FALSE and that is the point: step 5 kills the service rather than asking it to stop."

# EVERY CONJUNCT DEFAULTS TO FAILURE WHEN ABSENT, including the two added here:
# an unreadable restore exit is an empty string, which is not "0", and a family
# whose attempts were never posted is 0, which is under the floor.
verdict=FAIL
if [ "$oracle_verdict" = "PASS" ] && [ "$SERVICE_UP_EXIT" = "0" ] \
   && [ "$NET_UP_EXIT" = "0" ] && [ "$ARMED_EXIT" = "0" ] \
   && [ "${RESTORE_NET_UP_EXIT:-}" = "0" ] && [ -z "$attempt_shortfall" ]; then
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
    "dns_protected_resolver": "lab-relay-on-peer-overlay (100.64.1.2 / fd7c:9e5d:2a10:1::2, presenting 10.78.0.54 / fd78:7717:d0c::54 to the oracle as twinvpn-dns:p). THE PRODUCT BINDS NONE: enforce.rs:265-289 assembles denied_dns_policy() with empty stub_addresses, so the lane points the guest's stub at a stateless relay reachable only through the tunnel. The claim under test is that an armed host BLOCKS it, not that TwinVPN configured it.",
    "net_up_exit_code": ${NET_UP_EXIT:-null},
    "restore_net_up_exit_code": ${RESTORE_NET_UP_EXIT:-null},
    "attempts_posted_ipv4": $ATTEMPTS_IPV4,
    "attempts_posted_ipv6": $ATTEMPTS_IPV6,
    "attempts_posted_dns": $ATTEMPTS_DNS,
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
\`net up\` exited $NET_UP_EXIT, the armed readback exited $ARMED_EXIT, the restore \
\`net up\` exited ${RESTORE_NET_UP_EXIT:-<unreadable>} and the attempt shortfall was \
'${attempt_shortfall:-none}'. The evidence names what executed and what it is \
blocked on; see $LOGDIR/oracle-report.json and $GUESTLOG." >&2
  exit 1
}
