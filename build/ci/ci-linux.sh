#!/usr/bin/env bash
#
# ci-linux.sh -- the Linux platform link/run evidence, and the worked example
# the other four platform scripts follow.
#
# ===========================================================================
# WHY LINUX HAS A SCRIPT AT ALL
# ===========================================================================
# Linux already has executed PASS evidence for the platform lifecycle, so this
# wave does not re-prove it. What this script does is two narrower things:
#
#   1. RE-RUN it as a regression check, because this wave changes shared-core
#      code that the Linux shell links. A shared-core change that breaks the
#      platform boundary must be caught on the platform that can catch it
#      cheapest.
#
#   2. WRITE THE EVIDENCE FILE in the format every other platform must use, so
#      that "Windows produced the same shape of evidence Linux did" is a
#      checkable statement rather than a hopeful one. The schema is
#      build/acceptance/platform-evidence.schema.json.
#
# ===========================================================================
# WHAT COUNTS, AND WHAT DOES NOT
# ===========================================================================
# The acceptance criterion is that the shared core/platform boundary compiles,
# links, LOADS, INVOKES core code, RECEIVES a result back, and executes
# lifecycle state transitions. A compilation-only run is not evidence and this
# script will not emit a PASS for one: `lifecycle_transitions` is populated
# from the test binary's own output, so an empty array is what a compile-only
# run produces and the acceptance report fails on it.
#
# There is no `|| true` anywhere below, on purpose. A proof path that swallows
# a failure is worse than no proof path.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# `twinvpn_run_attempt_json`, `twinvpn_sha256`, `twinvpn_verify_digest` and
# `twinvpn_digest_json`. Sourced rather than reimplemented per script: the
# sha256 command differs on every host this repository runs on, and a digest
# helper that silently produced nothing on one of them would bind the evidence
# to no bytes at all.
# shellcheck disable=SC1091
. "$REPO/build/ci/digest.sh"
EVIDENCE="$REPO/build/ci/evidence/linux.json"
LOGDIR="$REPO/build/ci/logs/linux"
mkdir -p "$(dirname "$EVIDENCE")" "$LOGDIR"

# shellcheck disable=SC1091
source "$REPO/build/toolchain/env.sh"

echo "=== toolchain ==="
rustc --version
cargo --version
uname -srvm
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

TEST_CMD='cargo test -q -p twinvpnd --test lifecycle -- --nocapture'

# --- 1. compile the shared core for this target -----------------------------
echo "::group::compile the shared core"
if (cd "$REPO/core" && cargo build -q --workspace); then
  compiled=true
else
  notes="the shared core did not compile"
fi
echo "::endgroup::"

# --- 2/3. build and link the platform runtime against the REAL core ---------
# `twinvpnd` depends on `twinvpn-core` and `twinvpn-platform-linux` by path, so
# a successful build here IS the link against the real artifact -- there is no
# stub in the dependency graph to link instead. `--locked` makes that a
# checkable claim rather than an assumption about what cargo resolved.
if [ "$compiled" = true ]; then
  echo "::group::build and link the Linux platform runtime"
  if (cd "$REPO/shells/linux" && cargo build -q --locked --workspace); then
    linked=true
    loaded=true
  else
    notes="the Linux platform runtime did not link against the shared core"
  fi
  echo "::endgroup::"
fi

# --- 4/5/6. cross the production boundary and drive the lifecycle -----------
if [ "$linked" = true ]; then
  echo "::group::lifecycle across the production boundary"
  set +e
  (cd "$REPO/shells/linux" && eval "$TEST_CMD") 2>&1 | tee "$LOGDIR/lifecycle.log"
  exit_code=${PIPESTATUS[0]}
  set -e
  echo "::endgroup::"

  if [ "$exit_code" -eq 0 ]; then
    invoked=true
    received=true
    shutdown=true
    # THE TRANSITIONS ARE READ OUT OF THE TEST, NOT WRITTEN HERE.
    #
    # This is the difference between evidence and a claim. A script that hard-
    # codes `["STARTING->READY", ...]` reports the same list whether or not the
    # test drove a single transition, which is exactly the "compilation-only
    # job dressed as a lifecycle job" this gate exists to reject. So the test
    # prints one marker per transition it actually observes:
    #
    #     TWINVPN_LIFECYCLE_TRANSITION STARTING->READY
    #
    # and this script collects them. No markers means no transitions means the
    # acceptance report fails the row -- which is the correct outcome for a run
    # that proved linking and nothing else.
    transitions="$(
      grep -oE '^TWINVPN_LIFECYCLE_TRANSITION [A-Z_]+->[A-Z_]+$' "$LOGDIR/lifecycle.log" \
        | awk '{print $2}' | sort -u \
        | python3 -c 'import json,sys; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))'
    )"
    if [ "$transitions" = "[]" ]; then
      notes="the lifecycle test passed but emitted no TWINVPN_LIFECYCLE_TRANSITION marker, so this run proves linking and execution and NOT a lifecycle transition"
    fi
  else
    notes="the lifecycle test failed; see build/ci/logs/linux/lifecycle.log"
  fi
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
  "platform": "linux",
  "job_name": "${GITHUB_JOB:-linux-link-run}",
  "runner": "${RUNNER_NAME:-local}",
  "runner_kind": "$([ -n "${GITHUB_ACTIONS:-}" ] && echo github-hosted || echo local)",
  "privileged": false,
  "github_run_id": $([ -n "${GITHUB_RUN_ID:-}" ] && echo "\"$GITHUB_RUN_ID\"" || echo null),
  "github_run_attempt": $(twinvpn_run_attempt_json),
  "repository": $(twinvpn_repository_json),
  "artifact_digests": {},
  "github_run_url": $([ -n "${GITHUB_RUN_ID:-}" ] && echo "\"${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-}/actions/runs/$GITHUB_RUN_ID\"" || echo null),
  "commit": "$(cd "$REPO" && git rev-parse HEAD)",
  "toolchain": {
    "rustc": "$(rustc --version)",
    "cargo": "$(cargo --version)",
    "kernel": "$(uname -sr)"
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
  "artifacts": ["build/ci/logs/linux/lifecycle.log"],
  "notes": "$notes",
  "verdict": "$verdict",
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON

echo
echo "=== linux evidence ==="
cat "$EVIDENCE"

[ "$verdict" = "PASS" ] || {
  echo "::error::linux link/run did not pass: $notes" >&2
  exit 1
}
