#!/usr/bin/env bash
#
# status.sh — the P01–P22 acceptance register, checked rather than asserted.
#
# ===========================================================================
# WHAT THIS IS FOR
# ===========================================================================
# docs/testing-strategy.md §4: the twenty-two proof tests "are the acceptance
# criteria for the whole architecture ... A release that cannot show all
# twenty-two green, each with its mutant set demonstrably caught and its
# positive control demonstrably green, has not been shown to be TwinVPN." §4
# adds: "The count is load-bearing."
#
# build/proof/register.tsv is that enumeration. This script is what stops it
# from being a document that merely looks like evidence. It:
#
#   1. asserts the count is exactly twenty-two and the ids are P01..P22, so a
#      row cannot go missing without the check going red;
#   2. reconciles each row's mutant count against the patches that actually
#      exist in build/mutants/, so a register cannot claim a mutant set that is
#      not on disk;
#   3. RUNS the evidence command each row names and reports what happened,
#      rather than reprinting what the row claims;
#   4. refuses a row whose declared status is stronger than its evidence — a
#      row cannot say IMPLEMENTED without both a runnable oracle and at least
#      one real mutant patch (V2, PT-1).
#
# ===========================================================================
# THE VOCABULARY, AND WHY `PASS` IS NOT IN IT
# ===========================================================================
# This script never prints PASS for a proof test, because PT-1 defines PASS as
# "the clean build passes AND every mutant in its set fails, each with the
# expected oracle" — and only build/proof/run-mutants.sh can decide the second
# half. What this script reports is narrower and true:
#
#   OK           the row's evidence command ran and exited zero on this host.
#   FAILED       the row's evidence command ran and exited non-zero. Red.
#   UNAVAILABLE  the row names no evidence command, because the procedure needs
#                infrastructure this host does not have. This is an ABSENCE OF
#                EVIDENCE. It is not a pass and it is not a failure, and §3.1
#                requires it to be printed as its own word rather than folded
#                into either.
#   INCONSISTENT the row's declared status is not supported by what is on disk.
#                Red, because a register that overstates is worse than none.
#
# Usage:  build/proof/status.sh [--run] [--with-catalogue]
#
#   --run             execute the evidence commands. Without it the script only
#                     validates the register's shape, which is the cheap check a
#                     T1-budget job can afford.
#   --with-catalogue  additionally resolve every scenario id the register names
#                     against lab/'s twinlab-scenarios catalogue, so a register
#                     cannot cite a scenario that does not exist. Off by default
#                     because it builds the lab workspace.

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REGISTER="$REPO/build/proof/register.tsv"
MUTANT_DIR="$REPO/build/mutants"

DO_RUN=0
DO_CATALOGUE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --run) DO_RUN=1; shift ;;
    --with-catalogue) DO_CATALOGUE=1; shift ;;
    -h|--help) sed -n '2,50p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ -f "$REGISTER" ] || { echo "no register at $REGISTER" >&2; exit 2; }

problems=0
note() { printf '::error::%s\n' "$*"; problems=$((problems + 1)); }

# ---------------------------------------------------------------------------
# 1. The count is load-bearing (§4).
# ---------------------------------------------------------------------------
mapfile -t ROWS < <(grep -v '^#' "$REGISTER" | grep -v '^[[:space:]]*$')
if [ "${#ROWS[@]}" -ne 22 ]; then
  note "the register has ${#ROWS[@]} rows, not 22. §4: 'The count is load-bearing.'"
fi

expected=1
for row in "${ROWS[@]}"; do
  id="${row%%$'\t'*}"
  want="$(printf 'P%02d' "$expected")"
  [ "$id" = "$want" ] || note "register row $expected is \`$id\`, expected \`$want\`"
  expected=$((expected + 1))
done

# ---------------------------------------------------------------------------
# 2. What is actually on disk under build/mutants/.
# ---------------------------------------------------------------------------
declare -A ON_DISK=()
for p in "$MUTANT_DIR"/*.patch; do
  [ -e "$p" ] || continue
  proof="$(sed -n 's/^Proof:[[:space:]]*//p' "$p" | head -1)"
  mid="$(sed -n 's/^Mutant:[[:space:]]*//p' "$p" | head -1)"
  for req in Mutant Proof Spec Description Workspace Oracle Fails; do
    grep -q "^$req:" "$p" || note "$(basename "$p") has no \`$req:\` header"
  done
  [[ "$mid" == "M-$proof-"* ]] || note "$(basename "$p"): mutant id \`$mid\` does not name proof \`$proof\`"
  ON_DISK[$proof]=$(( ${ON_DISK[$proof]:-0} + 1 ))
done

# ---------------------------------------------------------------------------
# 3. Row by row.
# ---------------------------------------------------------------------------
printf '%-5s %-13s %-9s %-12s %s\n' ID STATUS MUTANTS EVIDENCE ORACLE
printf '%-5s %-13s %-9s %-12s %s\n' ----- ------------- --------- ------------ ------
ran_ok=0; ran_failed=0; unavailable=0

for row in "${ROWS[@]}"; do
  IFS=$'\t' read -r id status oracle mut_impl mut_spec scenarios evidence needs <<<"$row"

  # 3a. the mutant arithmetic must match the patches on disk.
  disk="${ON_DISK[$id]:-0}"
  if [ "$mut_impl" != "$disk" ]; then
    note "$id claims $mut_impl implemented mutant(s); build/mutants/ holds $disk for it"
  fi
  if [ "$mut_impl" -gt "$mut_spec" ] 2>/dev/null; then
    note "$id has more implemented mutants ($mut_impl) than the specification names ($mut_spec)"
  fi

  # 3b. the declared status must not outrun the evidence.
  case "$status" in
    IMPLEMENTED)
      [ "$evidence" = "-" ] && note "$id says IMPLEMENTED with no evidence command"
      [ "$disk" -eq 0 ] && note "$id says IMPLEMENTED with no mutant patch — V2: a test never demonstrated to fail is not known to test anything"
      [ "$mut_impl" -lt "$mut_spec" ] 2>/dev/null && note "$id says IMPLEMENTED but only $mut_impl of $mut_spec specified mutants exist; PT-1 makes the whole set the gate"
      ;;
    PARTIAL)
      [ "$evidence" = "-" ] && note "$id says PARTIAL with no evidence command; PARTIAL means some clause is executed"
      ;;
    NOT-RUNNABLE)
      [ "$evidence" = "-" ] || note "$id says NOT-RUNNABLE but names an evidence command; one of the two is wrong"
      [ "$disk" -eq 0 ] || note "$id says NOT-RUNNABLE but has $disk mutant patch(es); a mutant with no clean baseline cannot be run"
      ;;
    *) note "$id has unknown status \`$status\`" ;;
  esac

  # 3c. run it.
  verdict="UNAVAILABLE"
  if [ "$evidence" = "-" ]; then
    unavailable=$((unavailable + 1))
  elif [ "$DO_RUN" -eq 0 ]; then
    verdict="not-run"
  else
    verdict="OK"
    IFS=';' read -ra CMDS <<<"$evidence"
    for entry in "${CMDS[@]}"; do
      entry="${entry# }"; [ -n "$entry" ] || continue
      ws="${entry%%::*}"; cmd="${entry#*::}"
      out="$(cd "$REPO/$ws" && eval "$cmd" 2>&1)"; rc=$?
      if [ "$rc" -ne 0 ]; then
        verdict="FAILED"
        printf '::group::%s — %s\n%s\n::endgroup::\n' "$id" "$cmd" "$(tail -30 <<<"$out")"
      fi
    done
    if [ "$verdict" = "OK" ]; then ran_ok=$((ran_ok + 1)); else ran_failed=$((ran_failed + 1)); fi
  fi

  printf '%-5s %-13s %-9s %-12s %s\n' "$id" "$status" "$mut_impl/$mut_spec" "$verdict" "$oracle"
done

# ---------------------------------------------------------------------------
# 4. The scenario ids the register cites must resolve against lab/'s catalogue.
# ---------------------------------------------------------------------------
if [ "$DO_CATALOGUE" -eq 1 ]; then
  echo
  echo "=== scenario ids, resolved against lab/'s catalogue ==="
  # shellcheck disable=SC1091
  source "$REPO/build/toolchain/env.sh"
  for row in "${ROWS[@]}"; do
    IFS=$'\t' read -r id _ _ _ _ scenarios _ _ <<<"$row"
    [ "$scenarios" = "-" ] && continue
    IFS=',' read -ra IDS <<<"$scenarios"
    for sid in "${IDS[@]}"; do
      sid="${sid# }"
      if (cd "$REPO/lab" && cargo run -q -p twinlab-scenarios -- show "$sid" >/dev/null 2>&1); then
        printf '  %-5s %-34s resolved\n' "$id" "$sid"
      else
        printf '  %-5s %-34s NOT IN THE CATALOGUE\n' "$id" "$sid"
        note "$id cites scenario \`$sid\`, which lab/'s catalogue does not define"
      fi
    done
  done
fi

# ---------------------------------------------------------------------------
# 5. The summary, stated in the only terms this script is entitled to.
# ---------------------------------------------------------------------------
echo
echo "=== register summary ==="
printf '  %d row(s) with a runnable oracle that ran green on this host\n' "$ran_ok"
printf '  %d row(s) with a runnable oracle that ran RED on this host\n' "$ran_failed"
printf '  %d row(s) NOT VERIFIED — no oracle is executable here\n' "$unavailable"
echo
echo "  None of the above is a PT-1 PASS. PT-1 requires the clean build to pass AND"
echo "  every mutant in the set to fail with its expected oracle; the second half is"
echo "  build/proof/run-mutants.sh's verdict, and today it covers only the mutants"
echo "  build/mutants/ contains. Release blocker B-1 is UNDISCHARGED until all"
echo "  twenty-two rows carry both halves."

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### P01–P22 acceptance register"
    echo
    echo "\`$ran_ok\` green · \`$ran_failed\` red · \`$unavailable\` not verified · B-1 undischarged"
    echo
    echo '| Proof | Status | Mutants impl/spec | Needs |'
    echo '|---|---|---|---|'
    for row in "${ROWS[@]}"; do
      IFS=$'\t' read -r id status _ mi ms _ _ needs <<<"$row"
      printf '| %s | %s | %s/%s | %s |\n' "$id" "$status" "$mi" "$ms" "$needs"
    done
  } >> "$GITHUB_STEP_SUMMARY"
fi

[ "$problems" -eq 0 ] || { echo "::error::$problems register inconsistency/ies"; exit 1; }
[ "$ran_failed" -eq 0 ] || exit 1
exit 0
