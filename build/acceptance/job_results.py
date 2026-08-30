#!/usr/bin/env python3
"""What a GitHub job's own outcome is allowed to mean here.

THE HOLE THIS CLOSES
====================
`report.py` grades EVIDENCE FILES, and a job that never got as far as writing
one leaves nothing behind. That is correct and it is nearly silent: the row
reads `no evidence at build/ci/evidence/<stem>.json`, which is true of a job
that failed in setup, a job that was cancelled by its own timeout, a job that
was SKIPPED because its self-hosted runner is not registered, and a job that
does not exist in the workflow at all. Four different problems, one sentence,
and the most dangerous of them -- the skip -- is the one that looks most like
routine absence. A rig that quietly stopped existing should be as loud as a rig
that failed, and under the old wording it was quieter.

So the acceptance job writes `build/ci/evidence/job-results.json`, a flat map of
job name to the `needs.<job>.result` GitHub reports for it, and this module says
what each of those outcomes is worth. There is exactly one value that is not a
problem, and it is `success`.

WHY A SKIP IS RED AND NOT A SHRUG
=================================
A self-hosted platform job is gated on a repository variable so that an
unregistered runner makes it SKIP rather than queue for twenty-four hours. That
is the right failure mode for the WORKFLOW -- a check that cannot go red is not
a gate -- and it must not become the wrong failure mode for the REPORT. A
skipped `windows-killswitch` means nobody tested the Windows kill switch, which
is exactly as much evidence about the kill switch as a failed run: none. The
skip is a fact about the fleet, not about the product, and the report says so in
those words rather than printing the same "no evidence" line it prints for a
crash.

`NOT-EXECUTED` is the verdict for all of these. It is not a softer `FAIL`: the
eligibility conjunction counts it identically, and it exists only so a reader
can tell "we ran it and it broke" from "we never ran it".
"""

from __future__ import annotations

import json
from pathlib import Path

JOB_RESULTS_FILE = "job-results.json"

# Every GitHub job conclusion, and what it is worth as evidence. `success` is
# the only key whose value is None, and that asymmetry is the whole module: a
# result this table does not recognise is treated as a problem rather than
# ignored, because an unrecognised conclusion is a GitHub behaviour change and
# the safe reading of a behaviour change is not "probably fine".
JOB_RESULT_MEANING = {
    "success": None,
    "failure": ("FAILED, so whatever it wrote about {criterion} describes a run "
                "that did not complete"),
    "cancelled": ("was CANCELLED -- which is also what a `timeout-minutes` "
                  "expiry produces, so the run most likely to have been cut off "
                  "mid-sequence is the one that reports this"),
    "skipped": ("was SKIPPED: its specialized runner or its gating repository "
                "variable is not configured, so nobody tested {criterion} in "
                "this run. An absent rig is a fact about the fleet, not "
                "evidence about the product"),
    "neutral": ("returned `neutral`, which is not a pass and is not a claim "
                "about {criterion} either way"),
    "action_required": ("is waiting on a manual action and therefore has not "
                        "adjudicated {criterion}"),
    # The platform jobs write this into their own evidence when they ran but
    # deliberately did nothing -- and a job that says so about itself is
    # believed, because nothing else in the run contradicts it.
    "NOT-EXECUTED": ("reports NOT-EXECUTED: it ran and deliberately did not "
                     "discharge {criterion}"),
    "INCONCLUSIVE": ("reports INCONCLUSIVE: the sequence never proved it could "
                     "observe {criterion} at all, which is the state in which a "
                     "clean result means nothing"),
}


def load(evidence_dir: Path) -> dict | None:
    """The map the acceptance job wrote, or None when it wrote none.

    None and `{}` are deliberately different. None means the report is being run
    somewhere that does not know about GitHub jobs at all -- a laptop, a
    documentation check -- and there is nothing to say about job outcomes. An
    empty map means the acceptance job ran and found no results, which IS worth
    saying about every row.
    """
    path = Path(evidence_dir) / JOB_RESULTS_FILE
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def problem(job: str, criterion: str, results: dict | None) -> str | None:
    """One sentence naming why this job's outcome is not a pass, or None."""
    if results is None:
        return None
    if job not in results:
        return (f"the `{job}` job reported no result at all: it is not in this "
                f"workflow run, so {criterion} was never scheduled, let alone "
                f"adjudicated")
    result = results[job]
    if result in (None, ""):
        return (f"the `{job}` job's result is empty, so nothing says whether it "
                f"ran")
    if result in JOB_RESULT_MEANING:
        meaning = JOB_RESULT_MEANING[result]
        if meaning is None:
            return None
        return f"the `{job}` job " + meaning.format(criterion=criterion)
    return (f"the `{job}` job reported the unrecognised result {result!r}; only "
            f"`success` is a pass, and an unfamiliar conclusion is not assumed "
            f"to be one")
