#!/usr/bin/env bash
#
# run-mutants.sh — rule PT-1's mechanism, executed rather than described.
#
# ===========================================================================
# WHAT THIS IS
# ===========================================================================
# docs/testing-strategy.md rule PT-1 (V2 is a gate):
#
#   "Each mutant is a real, buildable, version-controlled patch against the
#    release commit. The mutant run is part of the test, not a thought
#    experiment: P0N is PASS only if the clean build passes AND every mutant in
#    its set fails, each with the expected oracle. A mutant that unexpectedly
#    passes is a defect in the test, filed at the same severity as a product
#    defect."
#
# Each patch under build/mutants/ carries a metadata preamble that git apply
# ignores and this script reads:
#
#   Mutant:      M-P07-2
#   Proof:       P07
#   Spec:        the document section that specifies this mutant
#   Description: what the defective build does differently
#   Workspace:   the cargo workspace the oracle runs in (core, lab, tests, ...)
#   Oracle:      the command that must pass clean and fail mutated
#   Fails:       the string that must appear in the mutant run's output
#
# The patch is the single source of truth for its own metadata, so there is no
# separate manifest to fall out of step with the patches it describes.
#
# ===========================================================================
# WHY A SCRATCH WORKTREE, AND WHY NOT cargo-mutants
# ===========================================================================
# PT-1 binds the mutant to the RELEASE COMMIT, and rule C-5 binds every verdict
# to an exact commit or immutable snapshot. A `git worktree` at an explicit
# revision gives both for free and cannot leave a mutated file behind in the
# tree the operator is working in — which matters, because a mutant left applied
# is a defect that ships.
#
# cargo-mutants was considered and rejected for this job. It GENERATES mutants
# by mechanically rewriting function bodies; PT-1 requires NAMED mutants, each
# one the specific defective build a document enumerated ("Tier 1
# prefix-enumerated rather than complement-form in full-tunnel mode"), each with
# a named expected oracle. A generator cannot produce that set, and the set is
# what the acceptance criteria are written against. cargo-mutants remains a
# reasonable *additional* tool for the level-14 property tests, where the
# question is coverage rather than conformance; it is not a substitute here.
#
# ===========================================================================
# THREE OUTCOMES, AND ONLY ONE OF THEM IS EVIDENCE
# ===========================================================================
#   CAUGHT       the patch built and the named oracle failed. This is the pass.
#   NOT-CAUGHT   the patch built and the oracle passed anyway. PT-1: a defect in
#                the TEST, at product severity. Blocks.
#   UNBUILDABLE  the patch did not compile. PT-1 requires a *buildable* patch, so
#                this is a defect in the MUTANT, not evidence about the test.
#                Blocks, and is reported as a different word so the two are never
#                confused.
#
# A clean run that fails blocks before any mutant is attempted: a mutant run
# against a red baseline says nothing.
#
# Usage:  build/proof/run-mutants.sh [--rev <commit>] [--proof P07] [MUTANT_ID ...]

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MUTANT_DIR="$REPO/build/mutants"
REV="HEAD"
WANT_PROOF=""
declare -a WANT_IDS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --rev)   REV="$2"; shift 2 ;;
    --proof) WANT_PROOF="$2"; shift 2 ;;
    -h|--help) sed -n '2,60p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) WANT_IDS+=("$1"); shift ;;
  esac
done

field() { sed -n "s/^$2:[[:space:]]*//p" "$1" | head -1; }

# ---------------------------------------------------------------------------
# The rig: one detached worktree at the exact revision under test.
# ---------------------------------------------------------------------------
RIG="$(mktemp -d -t twinvpn-mutants-XXXXXX)"
cleanup() {
  git -C "$REPO" worktree remove --force "$RIG/rig" >/dev/null 2>&1 || true
  rm -rf "$RIG"
}
trap cleanup EXIT

COMMIT="$(git -C "$REPO" rev-parse "$REV")"
if [ -n "$(git -C "$REPO" status --porcelain)" ] && [ "$REV" = "HEAD" ]; then
  echo "note: the working tree is dirty. The rig is built from HEAD ($COMMIT)," >&2
  echo "      so uncommitted changes are NOT under test. C-5 binds evidence to a" >&2
  echo "      commit; this is that binding being honest rather than convenient." >&2
fi
git -C "$REPO" worktree add --detach "$RIG/rig" "$COMMIT" >/dev/null 2>&1 || {
  echo "could not create the rig worktree at $COMMIT" >&2; exit 2; }

# shellcheck disable=SC1091
source "$RIG/rig/build/toolchain/env.sh"

# The rig gets its OWN target directory, and this is not a performance choice.
#
# `build/toolchain/env.sh` points CARGO_TARGET_DIR at a shared cache. Sharing it
# with the rig poisons the HOST's build: `xtask` bakes `CARGO_MANIFEST_DIR` in at
# compile time, so a rig-built `xtask` left in the shared cache makes a later
# `make arch-lint` on the host fail with
#
#     cargo metadata failed: manifest path `<rig>/core/Cargo.toml` does not exist
#
# long after the rig has been deleted. That is a proof harness corrupting the
# gate it exists to feed, and it is silent until someone reads the message
# carefully. It is also the reason P15's oracle - which IS `xtask lint` - went
# red on a tree whose lints were clean.
#
# Overriding after the source is deliberate: env.sh is the rig's own file and
# will keep setting the shared path, so the last word has to be here.
export CARGO_TARGET_DIR="$RIG/target"

echo "PT-1 mutant run"
echo "  commit: $COMMIT"
echo "  rig:    $RIG/rig"
echo

# ---------------------------------------------------------------------------
# Collect the mutants under test.
# ---------------------------------------------------------------------------
declare -a PATCHES=()
for p in "$MUTANT_DIR"/*.patch; do
  [ -e "$p" ] || continue
  id="$(field "$p" Mutant)"
  proof="$(field "$p" Proof)"
  if [ ${#WANT_IDS[@]} -gt 0 ]; then
    match=0
    for w in "${WANT_IDS[@]}"; do [ "$w" = "$id" ] && match=1; done
    [ "$match" = 1 ] || continue
  fi
  if [ -n "$WANT_PROOF" ] && [ "$proof" != "$WANT_PROOF" ]; then continue; fi
  PATCHES+=("$p")
done

if [ ${#PATCHES[@]} -eq 0 ]; then
  echo "no mutants selected" >&2
  exit 2
fi

# ---------------------------------------------------------------------------
# Step 1 — every distinct oracle must pass on the CLEAN rig.
#
# Run once per distinct (workspace, oracle) pair, not once per mutant: two
# mutants sharing an oracle do not need the baseline established twice, and
# C-1's budget rule makes the difference matter at T3.
# ---------------------------------------------------------------------------
declare -A CLEAN_SEEN=()
clean_failures=0
echo "=== clean baseline ==="
for p in "${PATCHES[@]}"; do
  ws="$(field "$p" Workspace)"; oracle="$(field "$p" Oracle)"
  key="$ws|$oracle"
  [ -n "${CLEAN_SEEN[$key]+x}" ] && continue
  CLEAN_SEEN[$key]=1
  out="$(cd "$RIG/rig/$ws" && eval "$oracle" 2>&1)"; rc=$?
  if [ "$rc" -eq 0 ]; then
    printf '  PASS         %s\n' "$oracle"
  else
    printf '  CLEAN-FAILED %s\n' "$oracle"
    echo "$out" | sed 's/^/               /' | tail -20
    clean_failures=$((clean_failures + 1))
  fi
done
echo

if [ "$clean_failures" -gt 0 ]; then
  echo "::error::$clean_failures clean oracle(s) failed. A mutant run against a red"
  echo "baseline is evidence of nothing, so no mutant was attempted (PT-1)."
  exit 1
fi

# ---------------------------------------------------------------------------
# Step 2 — every mutant must be buildable AND caught.
# ---------------------------------------------------------------------------
echo "=== mutants ==="
caught=0; not_caught=0; unbuildable=0
declare -a VERDICTS=()

for p in "${PATCHES[@]}"; do
  id="$(field "$p" Mutant)"; proof="$(field "$p" Proof)"
  ws="$(field "$p" Workspace)"; oracle="$(field "$p" Oracle)"
  fails="$(field "$p" Fails)"; desc="$(field "$p" Description)"

  git -C "$RIG/rig" checkout --quiet -- .
  if ! git -C "$RIG/rig" apply "$p" 2>/dev/null; then
    printf '  %-10s %-5s UNBUILDABLE  the patch does not apply to %s\n' "$id" "$proof" "${COMMIT:0:12}"
    VERDICTS+=("$id UNBUILDABLE does-not-apply")
    unbuildable=$((unbuildable + 1))
    continue
  fi

  out="$(cd "$RIG/rig/$ws" && eval "$oracle" 2>&1)"; rc=$?
  git -C "$RIG/rig" checkout --quiet -- .

  # A compile error is not a caught mutant. PT-1 asks for a BUILDABLE patch, so
  # a patch that does not compile is a defect in the mutant and must never be
  # counted as the test having caught anything.
  #
  # The pattern is deliberately narrow. `error: test failed, to rerun pass ...`
  # is what cargo prints when a test ASSERTION fails, which is the outcome this
  # script exists to detect; matching a bare `^error: ` swept every caught mutant
  # into UNBUILDABLE and reported a working mechanism as broken. Only rustc's own
  # diagnostics count: a numbered `error[E….]`, `could not compile`, and the
  # `aborting due to` summary line.
  if grep -qE '^error\[E[0-9]+\]:|^error: could not compile|^error: aborting due to' <<<"$out"; then
    printf '  %-10s %-5s UNBUILDABLE  the patch does not compile\n' "$id" "$proof"
    grep -E '^error' <<<"$out" | head -3 | sed 's/^/               /'
    VERDICTS+=("$id UNBUILDABLE does-not-compile")
    unbuildable=$((unbuildable + 1))
    continue
  fi

  if [ "$rc" -eq 0 ]; then
    printf '  %-10s %-5s NOT-CAUGHT   the oracle passed against a build that %s\n' "$id" "$proof" "$desc"
    printf '               PT-1: this is a DEFECT IN THE TEST, at product severity.\n'
    VERDICTS+=("$id NOT-CAUGHT $oracle")
    not_caught=$((not_caught + 1))
    continue
  fi

  if ! grep -qF "$fails" <<<"$out"; then
    # It failed, but not for the stated reason. PT-1 says "each with the
    # EXPECTED oracle" - a mutant caught by the wrong assertion is not the
    # evidence the proof test claims, so it is reported rather than counted.
    printf '  %-10s %-5s NOT-CAUGHT   failed, but `%s` is absent from the output;\n' "$id" "$proof" "$fails"
    printf '               the expected oracle is not what rejected this build.\n'
    VERDICTS+=("$id NOT-CAUGHT wrong-oracle")
    not_caught=$((not_caught + 1))
    continue
  fi

  printf '  %-10s %-5s CAUGHT       %s\n' "$id" "$proof" "$fails"
  VERDICTS+=("$id CAUGHT $fails")
  caught=$((caught + 1))
done

echo
echo "=== verdict ==="
printf '  %d caught, %d not caught, %d unbuildable, out of %d\n' \
  "$caught" "$not_caught" "$unbuildable" "${#PATCHES[@]}"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### PT-1 mutant run — \`${COMMIT:0:12}\`"
    echo
    echo "| Mutant | Verdict | Oracle |"
    echo "|---|---|---|"
    for v in "${VERDICTS[@]}"; do
      set -- $v
      printf '| `%s` | %s | `%s` |\n' "$1" "$2" "${*:3}"
    done
  } >> "$GITHUB_STEP_SUMMARY"
fi

if [ "$not_caught" -gt 0 ] || [ "$unbuildable" -gt 0 ]; then
  echo "::error::PT-1 not satisfied. A proof test whose mutant set is not demonstrably"
  echo "caught is not known to test anything (V2), and release blocker B-1 applies."
  exit 1
fi
echo "  PT-1 satisfied for the mutants above. It says NOTHING about the mutants that"
echo "  build/mutants/ does not yet contain — build/proof/register.tsv is where that"
echo "  gap is recorded honestly."
exit 0
