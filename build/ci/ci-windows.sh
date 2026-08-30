#!/usr/bin/env bash
#
# ci-windows.sh -- the Windows platform link/run evidence.
#
# `make ci-windows` runs this. It is written for a WINDOWS runner and will
# refuse to run anywhere else: ADR-0018 BM-3 is explicit that Windows "cannot be
# cross-built from Linux -- the MSVC ABI is required for WFP, IP Helper and
# Authenticode", so a Linux host cannot produce this evidence and must not
# produce something that reads like it.
#
# ===========================================================================
# WHAT THIS PROVES, AT EXACTLY ITS STRENGTH
# ===========================================================================
# The acceptance criterion is that the shared core/platform boundary compiles,
# links, LOADS, INVOKES core code, RECEIVES a result back, and executes
# lifecycle state transitions. A compilation-only run is not evidence, and this
# script cannot emit a PASS for one: `lifecycle_transitions` is read out of the
# test binary's own stdout, so an empty array is what a compile-only run
# produces and build/acceptance/report.py fails on it.
#
# The run is `shells/windows/twinvpnsvc/tests/windows_link_run.rs`. Read its
# header for what it does and does not claim -- in particular that the
# unprivileged pass binds the MOCK platform adapter under a REAL core, because
# the real adapter needs `wintun.dll` and a writable Base Filtering Engine
# session. That half is `--privileged`, on the self-hosted rig, and its evidence
# carries `privileged: true`.
#
# There is no `|| true` anywhere on a proof path, on purpose. A proof path that
# swallows a failure is worse than no proof path.
#
# ===========================================================================
# MODES
# ===========================================================================
#   (no flag)      the hosted smoke run: compile, link, load, invoke, transition,
#                  shut down. What `windows-link-run` calls.
#   --reset        assert a known-clean rig and clear stale evidence and logs.
#                  Fails loudly when the machine still carries TwinVPN state,
#                  because a privileged run that starts dirty proves nothing.
#   --privileged   additionally exercise the real WFP/driver surface. Sets
#                  TWINVPN_WINDOWS_TEST=1, which is the SAME opt-in
#                  twinvpn-platform-windows' own tests/windows_host.rs uses.
#   --cleanup      tear down what this script can, on every path. Safe to run
#                  with `if: always()`; it never fails the job.
#
# The flags compose in the order given and may be combined.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# `twinvpn_run_attempt_json`, `twinvpn_sha256`, `twinvpn_verify_digest` and
# `twinvpn_digest_json`. Sourced rather than reimplemented per script: the
# sha256 command differs on every host this repository runs on, and a digest
# helper that silently produced nothing on one of them would bind the evidence
# to no bytes at all.
# shellcheck disable=SC1091
. "$REPO/build/ci/digest.sh"
EVIDENCE="$REPO/build/ci/evidence/windows.json"
LOGDIR="$REPO/build/ci/logs/windows"
mkdir -p "$(dirname "$EVIDENCE")" "$LOGDIR"

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
      echo "ci-windows.sh: unknown flag: $arg" >&2
      echo "usage: ci-windows.sh [--reset] [--privileged] [--cleanup]" >&2
      exit 2
      ;;
  esac
done

# `build/toolchain/env.sh` is DELIBERATELY NOT SOURCED. It sets a Linux
# JAVA_HOME, a Linux LD_LIBRARY_PATH and a Linux sysroot, none of which exist
# here, and the only thing this script needs from it -- the exact Rust version
# -- is already pinned by rust-toolchain.toml, which rustup honours by itself.
# Sourcing it would put four nonexistent directories on PATH and hide the
# difference between "the pin applied" and "a stray toolchain answered".
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*|Windows_NT) : ;;
  *)
    echo "::error::ci-windows.sh must run on a Windows runner (ADR-0018 BM-3: the MSVC ABI cannot be cross-built from Linux). uname says: $(uname -s)" >&2
    exit 2
    ;;
esac

# ---------------------------------------------------------------------------
# cleanup -- runs with `if: always()`, so it must not fail the job
# ---------------------------------------------------------------------------
if [ "$do_cleanup" = true ]; then
  echo "=== cleanup ==="
  # The service, if a privileged run registered one. `sc.exe` reports its own
  # errors; a service that is not there is the state we want and is not an
  # error, which is why the query gates the stop rather than the stop being
  # blindly issued and its failure ignored.
  if sc.exe query TwinVPNService >/dev/null 2>&1; then
    echo "stopping and deleting TwinVPNService"
    sc.exe stop TwinVPNService >/dev/null 2>&1 || echo "  (already stopped)"
    sc.exe delete TwinVPNService >/dev/null 2>&1 || echo "  (already deleted)"
  else
    echo "TwinVPNService: not registered"
  fi

  # Overlay adapters. `twinvpn_platform_windows::OVERLAY_PREFIX` is "TwinVPN",
  # and `is_overlay` is answered by that prefix rather than by the driver
  # identity -- so this deletes exactly what we could have created.
  echo "--- interfaces named TwinVPN* ---"
  netsh interface show interface 2>&1 | grep -i twinvpn || echo "none"

  # WFP state, for the diagnostics artifact. It is a firewall dump: no key, no
  # pairing secret, no tunnel payload. It is NOT uploaded on success.
  echo "capturing WFP state to $LOGDIR/wfp-state-after.txt"
  netsh wfp show state file="$LOGDIR/wfp-state-after.xml" >/dev/null 2>&1 \
    && echo "  captured" \
    || echo "  netsh wfp show state was refused (this process is not elevated)"

  # THE HONEST LIMIT, stated rather than papered over.
  #
  # ADR-0022 §11.4's Windows row and ADR-0018 CB-6 require persistent WFP
  # filters to SURVIVE the process: "shutdown MUST NOT remove enforcement".
  # There is therefore no supported in-process remover, and inventing one here
  # would contradict the invariant the privileged job exists to test. A rig
  # carrying the `twinvpn-vpn-lifecycle` label is restored by its own snapshot
  # or reboot step, which is why the job fragment requires one.
  echo
  echo "NOTE: persistent WFP filters installed by a privileged run are CB-6"
  echo "      survivors BY DESIGN and are not removed here. DESTROYING THE GUEST"
  echo "      is what removes them: the kill-switch criterion runs inside a"
  echo "      throwaway nested Hyper-V guest that scripts/twinvpn-azure-l1.ps1"
  echo "      deletes on every exit path, so nothing needs cleaning between runs."
  exit 0
fi

# ---------------------------------------------------------------------------
# reset -- a privileged run that starts dirty proves nothing
# ---------------------------------------------------------------------------
if [ "$do_reset" = true ]; then
  echo "=== reset ==="
  rm -f "$EVIDENCE"
  rm -rf "${LOGDIR:?}"/*
  mkdir -p "$LOGDIR"

  if sc.exe query TwinVPNService >/dev/null 2>&1; then
    echo "::error::the rig still has TwinVPNService registered; it was not restored between runs" >&2
    exit 1
  fi
  if netsh interface show interface 2>/dev/null | grep -qi twinvpn; then
    echo "::error::the rig still has a TwinVPN overlay adapter; it was not restored between runs" >&2
    netsh interface show interface | grep -i twinvpn >&2
    exit 1
  fi
  echo "rig is clean: no TwinVPNService, no TwinVPN overlay adapter"
fi

[ "$do_run" = true ] || exit 0

# ---------------------------------------------------------------------------
# toolchain -- printed, and recorded in the evidence
# ---------------------------------------------------------------------------
echo "=== toolchain ==="
rustc --version
cargo --version
echo "host target: $(rustc -vV | awk '/^host:/ {print $2}')"
rustup target list --installed

# The MSVC linker. Not on PATH in git-bash, so it is located the way cargo
# locates it: through the Visual Studio installer's own `vswhere`. Reported
# rather than required -- if it is genuinely missing, the link below fails with
# a linker error, which is a better message than anything this block could
# print.
VSWHERE="/c/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe"
msvc="unknown"
if [ -x "$VSWHERE" ]; then
  vsroot="$("$VSWHERE" -latest -products '*' -property installationPath 2>/dev/null | tr -d '\r')"
  vsver="$("$VSWHERE" -latest -products '*' -property installationVersion 2>/dev/null | tr -d '\r')"
  if [ -n "$vsroot" ]; then
    toolset="$(ls "$(cygpath -u "$vsroot")/VC/Tools/MSVC" 2>/dev/null | sort -V | tail -1)"
    msvc="VisualStudio $vsver, MSVC toolset $toolset"
  fi
else
  echo "vswhere.exe not found; the MSVC version cannot be reported"
fi
echo "msvc: $msvc"
echo "windows: $(cmd.exe /c ver 2>/dev/null | tr -d '\r' | tr -s '\n' ' ')"
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

TEST_CMD='cargo test --locked -p twinvpnsvc --test windows_link_run -- --nocapture --test-threads=1'
if [ "$do_privileged" = true ]; then
  export TWINVPN_WINDOWS_TEST=1
  echo "TWINVPN_WINDOWS_TEST=1: the real WFP/Wintun surface will be exercised"
fi

# --- 1. compile the shared core for this target -----------------------------
#
# `--locked` refuses to move the lockfile. ADR-0018 DP-1 commits one lockfile
# per workspace; a CI run that silently updated it would make the lockfile
# decorative and this evidence would name a dependency set nobody reviewed.
echo "::group::compile the shared core (x86_64-pc-windows-msvc)"
if (cd "$REPO/core" && cargo build --locked -q -p twinvpn-core -p twinvpn-platform-windows); then
  compiled=true
else
  notes="the shared core did not compile for x86_64-pc-windows-msvc"
fi
echo "::endgroup::"

# --- 2/3. build and link the Windows service against the REAL core ----------
#
# `twinvpnsvc` names `twinvpn-core` and `twinvpn-platform-windows` by path with
# `core-host` on by default, so a successful build IS the link against the real
# artifacts: ADR-0018 §11.9 row 4 makes the core a `staticlib` linked into the
# service, and there is no stub in the dependency graph to link instead.
# `--all-targets` is what links the test binary this script then runs.
if [ "$compiled" = true ]; then
  echo "::group::build and link twinvpnsvc + twinvpnctl"
  if (cd "$REPO/shells/windows" && cargo build --locked -q --workspace --all-targets); then
    linked=true
  else
    notes="the Windows service did not link against the shared core"
  fi
  echo "::endgroup::"
fi

# --- 4/5/6. cross the production boundary and drive the lifecycle -----------
if [ "$linked" = true ]; then
  echo "::group::lifecycle across the production boundary"
  set +e
  (cd "$REPO/shells/windows" && eval "$TEST_CMD") 2>&1 | tee "$LOGDIR/lifecycle.log"
  exit_code=${PIPESTATUS[0]}
  set -e
  echo "::endgroup::"

  if [ "$exit_code" -eq 0 ]; then
    # `loaded` is separate from `linked` on purpose. The test binary ran, which
    # means the OS loaded the image, resolved every import in `windows-sys` and
    # executed `BCryptGenRandom`, `QueryUnbiasedInterruptTimePrecise` and
    # `FwpmEngineOpen0` -- none of which a successful link proves.
    loaded=true
    invoked=true
    received=true
    shutdown=true

    # THE TRANSITIONS ARE READ OUT OF THE TEST, NOT WRITTEN HERE.
    #
    # `awk` rather than `grep`, because grep exits 1 on no match and this
    # pipeline runs under `set -o pipefail`: masking that with `|| true` would
    # be the swallowed failure this file's header forbids. awk reports nothing
    # and exits 0, so "no markers" becomes an empty array -- which is exactly
    # what makes the verdict FAIL for a run that proved linking and nothing
    # else.
    #
    # `tr -d '\r'` first: this is a Windows runner and a stray CR before the
    # anchored `$` would make every marker miss. It would fail SAFE -- an empty
    # array is a FAIL, not a false PASS -- but it would fail for the wrong
    # reason and send someone looking at the test.
    transitions="$(
      tr -d '\r' < "$LOGDIR/lifecycle.log" \
        | awk '/^TWINVPN_LIFECYCLE_TRANSITION [A-Z_]+->[A-Z_]+$/ { print $2 }' \
        | sort -u | sed 's/.*/"&"/' | paste -sd, -
    )"
    transitions="[${transitions}]"
    if [ "$transitions" = "[]" ]; then
      notes="the link/run test passed but emitted no TWINVPN_LIFECYCLE_TRANSITION marker, so this run proves linking and execution and NOT a lifecycle transition"
    else
      # The §11.6 line the test prints, verbatim, so a reader of the evidence
      # sees which start-sequence steps this run actually satisfied rather than
      # inferring it from the platform. Quotes are stripped because this lands
      # inside a JSON string.
      notes="$(
        tr -d '\r' < "$LOGDIR/lifecycle.log" \
          | awk '/^start sequence \(ADR-0016/ { print; exit }' \
          | tr -d '"\\' | tr -s ' '
      )"
    fi
  else
    notes="the link/run test failed; see build/ci/logs/windows/lifecycle.log"
  fi
fi

# --- the privileged addition: the adapter's own mutating suite --------------
#
# Run AFTER the evidence-bearing test, so a mutating failure cannot be mistaken
# for a boundary failure. Its result is folded into the exit code and named in
# the notes; it does not change the six booleans, which are the boundary's.
privileged_ok=true
if [ "$do_privileged" = true ] && [ "$linked" = true ]; then
  echo "::group::privileged: twinvpn-platform-windows mutating suite"
  set +e
  (cd "$REPO/core" && cargo test --locked -p twinvpn-platform-windows --test windows_host \
      -- --nocapture --test-threads=1) 2>&1 | tee "$LOGDIR/windows-host.log"
  host_exit=${PIPESTATUS[0]}
  set -e
  echo "::endgroup::"
  if [ "$host_exit" -ne 0 ]; then
    privileged_ok=false
    notes="$notes | the privileged windows_host suite failed (exit $host_exit); see build/ci/logs/windows/windows-host.log"
  fi
fi

verdict="FAIL"
if [ "$compiled" = true ] && [ "$linked" = true ] && [ "$loaded" = true ] \
   && [ "$invoked" = true ] && [ "$received" = true ] && [ "$shutdown" = true ] \
   && [ "$transitions" != "[]" ] && [ "$privileged_ok" = true ]; then
  verdict="PASS"
fi

artifacts='["build/ci/logs/windows/lifecycle.log"]'
if [ "$do_privileged" = true ]; then
  artifacts='["build/ci/logs/windows/lifecycle.log","build/ci/logs/windows/windows-host.log"]'
fi

runner_kind="local"
if [ -n "${GITHUB_ACTIONS:-}" ]; then
  runner_kind="github-hosted"
  # A self-hosted runner is DIFFERENT EVIDENCE and the schema says so. The
  # privileged rig is self-hosted by definition, and RUNNER_ENVIRONMENT is what
  # the runner itself reports.
  if [ "${RUNNER_ENVIRONMENT:-github-hosted}" != "github-hosted" ]; then
    runner_kind="self-hosted"
  fi
fi

cat > "$EVIDENCE" <<JSON
{
  "schema_version": 1,
  "platform": "windows",
  "job_name": "${GITHUB_JOB:-windows-link-run}",
  "runner": "${RUNNER_NAME:-local}",
  "runner_kind": "$runner_kind",
  "privileged": $do_privileged,
  "github_run_id": $([ -n "${GITHUB_RUN_ID:-}" ] && echo "\"$GITHUB_RUN_ID\"" || echo null),
  "github_run_attempt": $(twinvpn_run_attempt_json),
  "repository": $(twinvpn_repository_json),
  "artifact_digests": {},
  "github_run_url": $([ -n "${GITHUB_RUN_ID:-}" ] && echo "\"${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-}/actions/runs/$GITHUB_RUN_ID\"" || echo null),
  "commit": "$(cd "$REPO" && git rev-parse HEAD)",
  "toolchain": {
    "rustc": "$(rustc --version)",
    "cargo": "$(cargo --version)",
    "target": "$(rustc -vV | awk '/^host:/ {print $2}')",
    "msvc": "$msvc"
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
  "artifacts": $artifacts,
  "notes": "$notes",
  "verdict": "$verdict",
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON

echo
echo "=== windows evidence ==="
cat "$EVIDENCE"

[ "$verdict" = "PASS" ] || {
  echo "::error::windows link/run did not pass: $notes" >&2
  exit 1
}
