#!/usr/bin/env bash
#
# mutation-gate.sh — release blocker B-1, decided rather than asserted.
#
# ===========================================================================
# WHAT THIS GATE IS FOR
# ===========================================================================
# docs/testing-strategy.md §6.5 B-1:
#
#   "Any of P01–P22 failing, or passing while any mutant in its set also
#    passes, or lacking a green positive control in the same session (PT-1, V2,
#    V4). ... a procedure that is merely *skipped* is a failure."
#
# And rule PT-1: "P0N is PASS only if the clean build passes AND every mutant in
# its set fails, each with the expected oracle."
#
# Both halves. A proof test with a complete, fully-caught mutant set and a
# partly-runnable oracle is NOT discharged, and P07 is exactly that today: five
# of five mutants killed, and still undischarged, because ADR-0012 §11.9's
# oracle also wants `ruleset_digest` and a wire capture. This script exists so
# that distinction is arithmetic rather than a matter of who reads the report.
#
# ===========================================================================
# WHAT IT REFUSES TO DO
# ===========================================================================
# It never prints "mutation tests pass". It prints six numbers that add up, and
# a verdict derived from them:
#
#   KILLED               the patch built and its named oracle rejected it. The
#                        only outcome that is evidence.
#   SURVIVED             the patch built and the oracle passed anyway, or failed
#                        for some other reason. PT-1: a defect in the TEST, at
#                        product severity. Blocks.
#   TIMEOUT              the oracle neither passed nor failed inside the budget.
#                        The test said nothing. Blocks, and is counted apart
#                        from SURVIVED because the two have different fixes.
#   UNVIABLE             the patch did not apply or did not compile. A defect in
#                        the MUTANT. Blocks.
#   MISSING              the specification names this mutation and no patch
#                        exists. UNDISCHARGED — never killed, never waived, and
#                        never silently absent from a total.
#   NOT-EXECUTED         a patch exists and this run did not reach a verdict for
#                        it. Blocks: an unrun mutant is not a passed one.
#
# ===========================================================================
# THE FIVE FAILURE CONDITIONS
# ===========================================================================
#   1. a required mutation obligation is missing from build/proof/obligations.tsv
#      — checked against the specifications themselves, not against a copy;
#   2. a required mutation is not executed;
#   3. a prohibited mutant survives (or times out, or is unviable);
#   4. B-1 is below 22/22 discharged;
#   5. the catalogue and the executable set disagree — a row claiming
#      IMPLEMENTED with no patch on disk, or a patch on disk with no row.
#
# 1 and 5 are defects in this evidence machinery and block in EVERY tier, the
# shape-only one included. 2, 3 and 4 are facts about a run, so the tier that is
# forbidden to run the mutants reports them and does not fail on them — see the
# escape below, which is the only place that distinction is exercised.
#
# ===========================================================================
# THE T1/T2 ESCAPE, AND WHY IT CANNOT BE MISTAKEN FOR A PASS
# ===========================================================================
# Rule C-3 (§6.2, and the header of .github/workflows/t3-proof.yml): "the mutant
# sets run only in T3 and T4, because a proof test without its mutants is not
# known to test anything". A T1 or T2 job that ran this gate's mutant half would
# be spending a tier's budget on work its tier is forbidden to do, and rule C-1
# forbids raising a budget to absorb it.
#
# So `--tier T1` (or `--tier T2`) runs the catalogue and reconciliation checks
# ONLY — they are seconds — and skips the mutant run. It exits 0 when the
# catalogue is sound. To make that impossible to read as a discharge it:
#
#   * prints `VERDICT: SHAPE-ONLY — NOT A PASS` as its last line;
#   * writes `"verdict": "SHAPE-ONLY-NOT-A-PASS"`, `"mutants_executed": false`,
#     `"killed": 0` and `"b1_discharged": 0` into the report;
#   * counts every patch it declined to run as NOT-EXECUTED in the totals;
#   * and still fails on a broken catalogue, because that is a defect here and
#     not a fact about a run it declined to make.
#
# There is no flag that makes this script report B-1 discharged without running
# the mutants, and the escape cannot raise `killed` above zero.
#
# Usage:
#   build/proof/mutation-gate.sh [--tier T1|T2|T3|T4] [--report <path>]
#                                [--verdicts <path>] [--rev <commit>]
#
#   --tier      default T3. T1/T2 take the documented shape-only path above.
#   --report    where the JSON artifact goes. Default build/proof/mutation-report.json
#   --verdicts  reuse an existing run-mutants.sh verdict TSV instead of running
#               the rig again. For composing with a T3 job that already ran it.
#   --rev       passed through to run-mutants.sh (C-5 binds evidence to a commit).

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CATALOGUE="$REPO/build/proof/obligations.tsv"
REGISTER="$REPO/build/proof/register.tsv"
MUTANT_DIR="$REPO/build/mutants"

TIER="T3"
REPORT="$REPO/build/proof/mutation-report.json"
VERDICTS=""
REV=""

while [ $# -gt 0 ]; do
  case "$1" in
    --tier)     TIER="$2"; shift 2 ;;
    --report)   REPORT="$2"; shift 2 ;;
    --verdicts) VERDICTS="$2"; shift 2 ;;
    --rev)      REV="$2"; shift 2 ;;
    -h|--help)  sed -n '2,85p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

case "$TIER" in T1|T2|T3|T4) ;; *) echo "unknown tier: $TIER" >&2; exit 2 ;; esac

# Two counters, because they block in different tiers.
#
#   problems  the catalogue is wrong, or disagrees with build/mutants/. That is
#             a defect in this evidence machinery itself and blocks EVERYWHERE,
#             including the T1/T2 shape-only path.
#   blockers  a mutant survived, timed out, was unviable or was not executed, or
#             B-1 is short. These are facts about the RUN, so a tier that is
#             forbidden to run the mutants (C-3) does not get to fail on them —
#             it reports them and says, in words, that it did not run.
problems=0
blockers=0
fail() { printf '::error::%s\n' "$*"; problems=$((problems + 1)); }
block() { printf '::error::%s\n' "$*"; blockers=$((blockers + 1)); }

[ -f "$CATALOGUE" ] || { echo "no catalogue at $CATALOGUE" >&2; exit 2; }

# ---------------------------------------------------------------------------
# 1. The catalogue against the SPECIFICATIONS.
#
# §4.3 places P16–P22's sixty-five mutants in their owning ADRs and not in
# testing-strategy.md, so a catalogue derived from testing-strategy.md alone is
# sixty-four rows short and looks complete. This check reads both.
# ---------------------------------------------------------------------------
spec_ids="$(grep -ohE 'M-P[0-9]{2}-[0-9]+' \
  "$REPO/docs/testing-strategy.md" "$REPO/docs/adr/"*.md | sort -u)"
cat_ids="$(grep -v '^#' "$CATALOGUE" | grep -v '^[[:space:]]*$' | cut -f1 | sort -u)"

SPEC_TOTAL="$(wc -l <<<"$spec_ids")"
CAT_ROWS="$(grep -vc '^#' "$CATALOGUE" 2>/dev/null || true)"
CAT_ROWS="$(grep -v '^#' "$CATALOGUE" | grep -vc '^[[:space:]]*$')"

while read -r missing; do
  [ -n "$missing" ] || continue
  fail "obligation \`$missing\` is specified and is NOT in build/proof/obligations.tsv"
done < <(comm -23 <(echo "$spec_ids") <(echo "$cat_ids"))

while read -r extra; do
  [ -n "$extra" ] || continue
  fail "build/proof/obligations.tsv names \`$extra\`, which no specification does"
done < <(comm -13 <(echo "$spec_ids") <(echo "$cat_ids"))

[ "$CAT_ROWS" -eq "$SPEC_TOTAL" ] ||
  fail "the catalogue has $CAT_ROWS rows against $SPEC_TOTAL specified mutations"

# The declared shared mutant: 144 obligations, 143 distinct patches.
SHARED_ROWS="$(grep -v '^#' "$CATALOGUE" | cut -f8 | grep -c '^SHARED-WITH:' || true)"
DISTINCT_REQUIRED=$((SPEC_TOTAL - SHARED_ROWS))

# ---------------------------------------------------------------------------
# 2. The catalogue against register.tsv's per-proof arithmetic.
# ---------------------------------------------------------------------------
while IFS=$'\t' read -r id _ _ _ mut_spec _; do
  [ -n "$id" ] || continue
  have="$(cut -f1 "$CATALOGUE" | grep -c "^M-$id-" || true)"
  [ "$have" = "$mut_spec" ] ||
    fail "$id: register.tsv says $mut_spec specified mutants, the catalogue enumerates $have"
done < <(grep -v '^#' "$REGISTER" | grep -v '^[[:space:]]*$')

# ---------------------------------------------------------------------------
# 3. The catalogue against what is on disk. Failure condition 5.
# ---------------------------------------------------------------------------
declare -A ON_DISK=()
for p in "$MUTANT_DIR"/*.patch; do
  [ -e "$p" ] || continue
  ON_DISK["$(sed -n 's/^Mutant:[[:space:]]*//p' "$p" | head -1)"]="$p"
done

declare -A CLAIMED=()
declare -A PROOF_OF=()
while IFS=$'\t' read -r id proof _ _ _ _ owner status _; do
  [ -n "$id" ] || continue
  PROOF_OF["$id"]="$proof"
  case "$status" in
    IMPLEMENTED)
      CLAIMED["$id"]=1
      [ -n "${ON_DISK[$id]+x}" ] ||
        fail "$id says IMPLEMENTED and build/mutants/ has no patch for it"
      [ "$owner" = "-" ] &&
        fail "$id says IMPLEMENTED and names no test owner"
      ;;
    SHARED-WITH:*) ;;
    MISSING-UNIMPLEMENTED|MISSING-NO-ORACLE)
      [ -n "${ON_DISK[$id]+x}" ] &&
        fail "$id is catalogued as $status and a patch for it exists on disk"
      ;;
    *) fail "$id has unknown catalogue status \`$status\`" ;;
  esac
done < <(grep -v '^#' "$CATALOGUE" | grep -v '^[[:space:]]*$')

for id in "${!ON_DISK[@]}"; do
  [ -n "${PROOF_OF[$id]+x}" ] ||
    fail "build/mutants/ holds a patch for \`$id\`, which the catalogue does not name"
done

IMPLEMENTED="${#CLAIMED[@]}"
MISSING=$((SPEC_TOTAL - IMPLEMENTED))

# ---------------------------------------------------------------------------
# 4. The mutant run. Failure conditions 2 and 3.
# ---------------------------------------------------------------------------
KILLED=0; SURVIVED=0; TIMEOUT=0; UNVIABLE=0; NOT_EXECUTED=0
declare -A VERDICT=()
RAN=0

if [ "$TIER" = "T1" ] || [ "$TIER" = "T2" ]; then
  NOT_EXECUTED="$IMPLEMENTED"
elif [ "$IMPLEMENTED" -eq 0 ]; then
  : # nothing to run; every obligation is already counted MISSING.
else
  if [ -z "$VERDICTS" ]; then
    VERDICTS="$(mktemp -t mutation-verdicts-XXXXXX.tsv)"
    trap 'rm -f "$VERDICTS"' EXIT
    echo "=== running the mutant rig (build/proof/run-mutants.sh) ==="
    if [ -n "$REV" ]; then
      MUTANT_VERDICTS="$VERDICTS" "$REPO/build/proof/run-mutants.sh" --rev "$REV"
    else
      MUTANT_VERDICTS="$VERDICTS" "$REPO/build/proof/run-mutants.sh"
    fi
    echo
  fi
  RAN=1
  while IFS=$'\t' read -r id _ verdict _; do
    [ -n "$id" ] || continue
    VERDICT["$id"]="$verdict"
  done < "$VERDICTS"

  for id in "${!CLAIMED[@]}"; do
    case "${VERDICT[$id]:-NOT-EXECUTED}" in
      KILLED)   KILLED=$((KILLED + 1)) ;;
      SURVIVED) SURVIVED=$((SURVIVED + 1))
                block "$id SURVIVED its oracle. PT-1: a defect in the test, at product severity." ;;
      TIMEOUT)  TIMEOUT=$((TIMEOUT + 1))
                block "$id TIMED OUT. The oracle said nothing, which is not a kill." ;;
      UNVIABLE) UNVIABLE=$((UNVIABLE + 1))
                block "$id is UNVIABLE — the patch does not apply or does not compile." ;;
      *)        NOT_EXECUTED=$((NOT_EXECUTED + 1))
                block "$id has a patch and this run reached no verdict for it." ;;
    esac
  done
fi

EXECUTABLE="$IMPLEMENTED"
EXECUTED=$((KILLED + SURVIVED + TIMEOUT + UNVIABLE))

# ---------------------------------------------------------------------------
# 5. B-1, per proof test. Failure condition 4.
#
# BOTH HALVES OF PT-1. A proof test is discharged only if register.tsv declares
# its oracle IMPLEMENTED — the register's own vocabulary for "the full oracle
# runs" — AND every one of its specified mutants was killed in this run.
# ---------------------------------------------------------------------------
B1_SPECIFIED=0
B1_DISCHARGED=0
declare -a B1_ROWS=()

while IFS=$'\t' read -r proof status _ _ mut_spec _ _ needs; do
  [ -n "$proof" ] || continue
  B1_SPECIFIED=$((B1_SPECIFIED + 1))
  killed_here=0
  for id in $(cut -f1 "$CATALOGUE" | grep "^M-$proof-" || true); do
    [ "${VERDICT[$id]:-}" = "KILLED" ] && killed_here=$((killed_here + 1))
  done
  oracle_full="no"; [ "$status" = "IMPLEMENTED" ] && oracle_full="yes"
  if [ "$oracle_full" = "yes" ] && [ "$killed_here" -eq "$mut_spec" ]; then
    B1_DISCHARGED=$((B1_DISCHARGED + 1))
    B1_ROWS+=("$proof|DISCHARGED|$killed_here/$mut_spec|-")
  else
    why="oracle is $status (PT-1 needs the full oracle); mutants killed $killed_here/$mut_spec"
    B1_ROWS+=("$proof|UNDISCHARGED|$killed_here/$mut_spec|$why — needs: $needs")
  fi
done < <(grep -v '^#' "$REGISTER" | grep -v '^[[:space:]]*$')

[ "$B1_DISCHARGED" -eq "$B1_SPECIFIED" ] ||
  block "release blocker B-1 is $B1_DISCHARGED/$B1_SPECIFIED discharged. §6.5: a procedure that is merely skipped is a failure."

# ---------------------------------------------------------------------------
# 6. The totals, printed as numbers that add up.
# ---------------------------------------------------------------------------
SUMMARY="${REPORT%.json}-summary.txt"
{
echo "=== B-1 mutation coverage — tier $TIER ==="
printf '  specified                 %4d   (%d distinct patches; M-P20-3 is declared the same mutant as M-P09-3)\n' \
  "$SPEC_TOTAL" "$DISTINCT_REQUIRED"
printf '  executable (patch exists) %4d\n' "$EXECUTABLE"
printf '  executed                  %4d\n' "$EXECUTED"
echo
printf '  killed                    %4d   <- the only outcome that is evidence\n' "$KILLED"
printf '  survived                  %4d\n' "$SURVIVED"
printf '  timeout                   %4d\n' "$TIMEOUT"
printf '  unviable                  %4d\n' "$UNVIABLE"
printf '  missing (no patch at all) %4d   <- specified, UNDISCHARGED, never a kill\n' "$MISSING"
printf '  not-executed              %4d\n' "$NOT_EXECUTED"
echo
printf '  B-1: %d of %d proof tests discharged (%d undischarged)\n' \
  "$B1_DISCHARGED" "$B1_SPECIFIED" $((B1_SPECIFIED - B1_DISCHARGED))
echo
echo "=== per proof test ==="
printf '  %-5s %-13s %-9s %s\n' PROOF B-1 KILLED WHY
for row in "${B1_ROWS[@]}"; do
  IFS='|' read -r pr st ct wy <<<"$row"
  printf '  %-5s %-13s %-9s %s\n' "$pr" "$st" "$ct" "$wy"
done
echo
} | tee "$SUMMARY"

# ---------------------------------------------------------------------------
# 7. The machine-readable artifact.
# ---------------------------------------------------------------------------
if [ "$TIER" = "T1" ] || [ "$TIER" = "T2" ]; then
  VERDICT_WORD="SHAPE-ONLY-NOT-A-PASS"
elif [ "$problems" -eq 0 ] && [ "$blockers" -eq 0 ]; then
  VERDICT_WORD="B1-DISCHARGED"
else
  VERDICT_WORD="B1-UNDISCHARGED"
fi

{
  echo '{'
  printf '  "schema": "twinvpn.mutation-report.v1",\n'
  printf '  "tier": "%s",\n' "$TIER"
  printf '  "verdict": "%s",\n' "$VERDICT_WORD"
  printf '  "commit": "%s",\n' "$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo unknown)"
  printf '  "worktree_dirty": %s,\n' \
    "$([ -n "$(git -C "$REPO" status --porcelain 2>/dev/null)" ] && echo true || echo false)"
  printf '  "mutants_executed": %s,\n' "$([ "$RAN" -eq 1 ] && echo true || echo false)"
  printf '  "specified": %d,\n' "$SPEC_TOTAL"
  printf '  "distinct_patches_required": %d,\n' "$DISTINCT_REQUIRED"
  printf '  "executable": %d,\n' "$EXECUTABLE"
  printf '  "executed": %d,\n' "$EXECUTED"
  printf '  "discharged": %d,\n' "$KILLED"
  printf '  "killed": %d,\n' "$KILLED"
  printf '  "survived": %d,\n' "$SURVIVED"
  printf '  "timeout": %d,\n' "$TIMEOUT"
  printf '  "unviable": %d,\n' "$UNVIABLE"
  printf '  "missing": %d,\n' "$MISSING"
  printf '  "not_executed": %d,\n' "$NOT_EXECUTED"
  printf '  "b1_specified": %d,\n' "$B1_SPECIFIED"
  printf '  "b1_discharged": %d,\n' "$B1_DISCHARGED"
  printf '  "problems": %d,\n' "$problems"
  printf '  "blockers": %d,\n' "$blockers"
  printf '  "proofs": [\n'
  sep=""
  for row in "${B1_ROWS[@]}"; do
    IFS='|' read -r pr st ct wy <<<"$row"
    printf '%s    {"proof": "%s", "b1": "%s", "killed_of_specified": "%s", "why": "%s"}' \
      "$sep" "$pr" "$st" "$ct" "$(sed 's/"/\\"/g; s/\\$//' <<<"$wy")"
    sep=$',\n'
  done
  printf '\n  ],\n'
  printf '  "obligations": [\n'
  sep=""
  while IFS=$'\t' read -r id proof _ _ mutation _ owner status needs; do
    [ -n "$id" ] || continue
    v="${VERDICT[$id]:-}"
    if [ -z "$v" ]; then
      case "$status" in
        IMPLEMENTED)   v="NOT-EXECUTED" ;;
        SHARED-WITH:*) v="SHARED" ;;
        *)             v="MISSING" ;;
      esac
    fi
    printf '%s    {"id": "%s", "proof": "%s", "verdict": "%s", "catalogue_status": "%s", "owner": "%s", "mutation": "%s", "needs": "%s"}' \
      "$sep" "$id" "$proof" "$v" "$status" \
      "$(sed 's/"/\\"/g; s/\\$//' <<<"$owner")" \
      "$(sed 's/"/\\"/g; s/\\$//' <<<"$mutation")" \
      "$(sed 's/"/\\"/g; s/\\$//' <<<"$needs")"
    sep=$',\n'
  done < <(grep -v '^#' "$CATALOGUE" | grep -v '^[[:space:]]*$')
  printf '\n  ]\n'
  echo '}'
} > "$REPORT"
echo "report:  $REPORT"
echo "summary: $SUMMARY"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### B-1 mutation coverage — tier $TIER"
    echo
    echo "\`$SPEC_TOTAL\` specified · \`$EXECUTABLE\` executable · \`$EXECUTED\` executed · \`$KILLED\` killed · \`$SURVIVED\` survived · \`$TIMEOUT\` timeout · \`$UNVIABLE\` unviable · \`$MISSING\` missing · \`$NOT_EXECUTED\` not executed"
    echo
    echo "**B-1: $B1_DISCHARGED of $B1_SPECIFIED discharged.**"
    echo
    echo '| Proof | B-1 | Killed / specified | Why not |'
    echo '|---|---|---|---|'
    for row in "${B1_ROWS[@]}"; do
      IFS='|' read -r pr st ct wy <<<"$row"
      printf '| %s | %s | %s | %s |\n' "$pr" "$st" "$ct" "$wy"
    done
  } >> "$GITHUB_STEP_SUMMARY"
fi

# ---------------------------------------------------------------------------
# 8. The verdict.
# ---------------------------------------------------------------------------
if [ "$TIER" = "T1" ] || [ "$TIER" = "T2" ]; then
  echo "Rule C-3 places the mutant sets in T3 and T4 and nowhere else, so tier $TIER"
  echo "checked the catalogue's shape and its reconciliation with build/mutants/ and"
  echo "ran no mutant. $EXECUTABLE patch(es) were NOT EXECUTED and $MISSING obligation(s)"
  echo "have no patch at all. B-1 is reported as 0 of $B1_SPECIFIED discharged, which is"
  echo "the only honest number a tier that ran no mutant can produce."
  if [ "$problems" -gt 0 ]; then
    echo
    echo "VERDICT: SHAPE-ONLY — NOT A PASS, and $problems catalogue problem(s) block."
    exit 1
  fi
  echo
  echo "VERDICT: SHAPE-ONLY — NOT A PASS"
  exit 0
fi

if [ "$problems" -gt 0 ] || [ "$blockers" -gt 0 ]; then
  echo "$problems catalogue problem(s) and $blockers run blocker(s). B-1 is $B1_DISCHARGED of $B1_SPECIFIED discharged."
  echo
  echo "VERDICT: B-1 UNDISCHARGED — $MISSING of $SPEC_TOTAL specified mutations have no"
  echo "patch, $SURVIVED survived, $TIMEOUT timed out, $UNVIABLE were unviable, and"
  echo "$NOT_EXECUTED were not executed. This gate is red because that is true."
  exit 1
fi

echo "VERDICT: B-1 DISCHARGED — $KILLED of $SPEC_TOTAL specified mutations killed,"
echo "$B1_DISCHARGED of $B1_SPECIFIED proof tests carrying both halves of PT-1."
exit 0
