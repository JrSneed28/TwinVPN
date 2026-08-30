#!/usr/bin/env python3
"""Whether the oracle's own report supports the verdict the oracle wrote.

`adjudication.py` answers "is this evidence about the right run and the right
artifact". This answers the next question, and the nastier one: the oracle can
only report what ARRIVED, so "nothing arrived" means "the kill switch held" ONLY
if the oracle was demonstrably still listening, the device was demonstrably
still probing, the family was demonstrably reachable before the armed window,
and the two paths being compared were demonstrably distinct.

Those are four independent facts. They are all in the report the oracle just
returned, and EVERY ONE OF THEM DEFAULTS TO FAILURE WHEN ABSENT -- absence is
what a crashed observer, a truncated upload and a version skew all produce, and
reading an absent `ipv4_sentinel_continuous` as `true` would make a dead
observer the strongest possible evidence of safety in the whole report.

Refusing any verdict that is not `PASS` is `report.py`'s job and is necessary.
It is not sufficient, and this module is the difference.
"""

from __future__ import annotations

import json

# ---------------------------------------------------------------------------
# WHICH FAMILIES EACH EGRESS CRITERION IS IN PLAY FOR, AND HOW MANY ATTEMPTS
# ===========================================================================
#
# `None` means the criterion GENUINELY HAS NO LEG of that family, and it is the
# ONLY thing that makes a `null` in the oracle's identity fields acceptable.
# That is why this is a table and not an inference: the alternative is a script
# that sees `ipv6_identity_distinct: null`, decides the lane probably has no
# IPv6, and passes a row whose IPv6 kill switch was never tested. Every entry
# below is `60` deliberately -- no lane has been shown to lack an IPv6 leg, and
# the strict direction of the guess is RED. If a lane really cannot carry IPv6
# the fix is to set it to `None` HERE, in a diff, with a reason.
#
# THE MINIMUM ITSELF. 60 attempts is the floor at which "zero arrived" is a
# measurement rather than an anecdote: the probes run at roughly 1 Hz, so it is
# about a minute of a device continuously trying to get out while the filters
# are armed. Below that the silence is as easily explained by a device that
# stopped probing -- which is the failure mode a kill-switch test cannot
# distinguish from success without counting attempts, and the reason the count
# is re-checked here rather than trusted from the oracle's own threshold.
ORACLE_FAMILY_MINIMUM_ATTEMPTS = {
    "WINDOWS-WFP-KILLSWITCH": {"ipv4": 60, "ipv6": 60, "dns": 60},
    "MACOS-SYSEXT-LIFECYCLE": {"ipv4": 60, "ipv6": 60, "dns": 60},
    "IOS-NE-FAIL-CLOSED": {"ipv4": 60, "ipv6": 60, "dns": 60},
    "IOS-SUPERVISED-ALWAYS-ON": {"ipv4": 60, "ipv6": 60, "dns": 60},
}


# ---------------------------------------------------------------------------
# THE ORACLE'S OWN NUMBERS
# ---------------------------------------------------------------------------

def check_oracle_adjudication(criterion: str, rep: dict, ev: dict) -> list[str]:
    """Re-derive the oracle's verdict from the oracle's own fields.

    `report.py` already refuses any oracle verdict that is not PASS. That is
    necessary and it is not sufficient: the fields below are what MAKE a PASS
    meaningful, and an oracle that wrote PASS without them is either an older
    build or a broken one. Every check here defaults to failure on an absent
    value, because absence is precisely what a crashed observer, a truncated
    upload and a version skew all produce -- and treating any of them as `true`
    makes a dead oracle the strongest evidence in the report.
    """
    families = ORACLE_FAMILY_MINIMUM_ATTEMPTS.get(criterion)
    if families is None:
        return [f"{criterion} requires an oracle but names no family/attempt "
                f"configuration in ORACLE_FAMILY_MINIMUM_ATTEMPTS, so there is "
                f"no standard to hold its report to"]

    problems: list[str] = []
    # THE ORACLE'S OWN SCHEMA. Version 2 is the first that carries the sentinel,
    # the attempt counts and the per-family path identities -- everything below
    # this line. A version-1 report is not a weaker report; it is a report that
    # cannot answer any of the questions this function asks, and reading its
    # absent fields as passing values is exactly the default-to-safe-looking
    # mistake the whole adjudicator exists to refuse.
    if rep.get("schema_version") != 2:
        problems.append(f"the oracle report is schema_version "
                        f"{rep.get('schema_version')!r}; version 2 is the first "
                        f"that records the sentinel, the attempt counts and the "
                        f"path identities, and none of them can be inferred "
                        f"from a version-1 report")
    problems += _run_attempt_agreement(rep, ev)
    proven = rep.get("families_proven_live")

    for family, minimum in sorted(families.items()):
        observed = rep.get(f"{family}_observed")
        # A forbidden arrival is a leak whether or not the family is nominally
        # in play, so this is checked before the in-play test.
        if isinstance(observed, int) and not isinstance(observed, bool) and observed > 0:
            problems.append(f"{observed} forbidden {family} arrival(s) were "
                            f"observed during a SILENCE phase")

        if minimum is None:
            # THE ONE CASE WHERE A NULL IDENTITY IS LEGITIMATE, and the only
            # value that is. All three identity fields are Option<bool>, so a
            # family the criterion has no leg for must come back `null`:
            # `false` says the oracle measured an overlap on a leg that was
            # never exercised, and `true` is worse -- it is a positive claim
            # that two distinct paths were compared when there was only ever
            # one, and it is the value somebody writes to make a row go green.
            # Either way the report and this table disagree about what was
            # tested, and that disagreement is the finding.
            got = rep.get(f"{family}_identity_distinct")
            if got is not None:
                problems.append(f"`{family}_identity_distinct` is {got!r} for a "
                                f"family this criterion has no leg for; only "
                                f"null is meaningful there, so the report and "
                                f"the table disagree about what was tested")
            continue

        if observed is None:
            problems.append(f"`{family}_observed` was never recorded, so nothing "
                            f"says whether {family} traffic arrived")
        elif not isinstance(observed, int) or isinstance(observed, bool):
            problems.append(f"`{family}_observed` is {observed!r}, which is not a "
                            f"count of arrivals")

        # THE SENTINEL. An independent heartbeat that is not the DUT and does
        # not traverse the DUT's network: the only thing that distinguishes "no
        # packets left the device" from "the oracle stopped listening". Anything
        # other than exactly `true` -- false, absent, null, a string -- is a
        # window in which zero arrivals mean nothing at all.
        #
        # This reads the BOOLEAN, and the report also carries `sentinel_beats`:
        # the beats themselves, timestamps and all. That field is deliberately
        # not consulted here -- re-implementing the continuity arithmetic in a
        # second place is a second thing to get wrong -- but it is there so a
        # human reviewing a disputed row can re-derive the gaps against
        # `sentinel_max_gap_ms` instead of believing this boolean, which is the
        # only way to catch an oracle whose arithmetic is the thing that broke.
        if rep.get(f"{family}_sentinel_continuous") is not True:
            got = rep.get(f"{family}_sentinel_continuous", "absent")
            problems.append(
                f"`{family}_sentinel_continuous` is {got!r}, not true: the "
                f"independent heartbeat had a gap, so for part of the armed "
                f"window the oracle cannot distinguish a device that sent "
                f"nothing from an observer that heard nothing")

        # THE ATTEMPTS. Zero arrivals proves the kill switch held only if the
        # device was trying. A run whose probe loop died on the first iteration
        # reports a perfectly silent window.
        attempts = rep.get(f"{family}_attempts")
        if not isinstance(attempts, int) or isinstance(attempts, bool):
            problems.append(f"`{family}_attempts` is {attempts!r}, so nothing "
                            f"says the device ever tried to emit {family} "
                            f"traffic; silence from a device that never probed "
                            f"is not a kill switch")
        elif attempts < minimum:
            problems.append(f"only {attempts} {family} probe attempt(s), below "
                            f"the {minimum} this criterion requires: too small a "
                            f"sample for silence to mean anything")

        # THE POSITIVE CONTROL. Before the armed window, the oracle must have
        # SEEN this family arrive -- otherwise the listener, the route, the
        # firewall in front of the oracle, or the family itself was never
        # working, and the whole session measured a path that never carried
        # traffic in the first place.
        if not isinstance(proven, list):
            if not any(p.startswith("`families_proven_live`") for p in problems):
                problems.append("`families_proven_live` is missing, so no "
                                "positive control proves the oracle could "
                                "observe this device on any family at all")
        elif family not in proven:
            problems.append(f"{family} is not in `families_proven_live`: the "
                            f"oracle never once saw {family} arrive from this "
                            f"device, so its later silence is unremarkable")

        # THE PATH IDENTITY. Protected and unprotected legs must be
        # distinguishable in the arrival record, or a control probe and a leak
        # are the same observation.
        distinct = rep.get(f"{family}_identity_distinct")
        if distinct is not True:
            problems.append(
                f"`{family}_identity_distinct` is {distinct!r}, not true: this "
                f"criterion has a {family} leg, so the protected and "
                f"unprotected identities must be known and different -- null "
                f"means unmeasured and false means they overlapped, and either "
                f"way an arrival cannot be attributed to a leg")

    # THE RESOLVER MAP. A DNS arrival that maps to no known resolver is an
    # arrival whose leg is unknown, which is not the same as an arrival on the
    # unprotected leg and must never be graded as one.
    ambiguous = rep.get("dns_resolver_identity_ambiguous")
    if ambiguous is not False:
        problems.append(
            f"`dns_resolver_identity_ambiguous` is {ambiguous!r}, not false: at "
            f"least one DNS query arrived from a resolver the oracle could not "
            f"map to a leg, so it cannot say whether the protected resolver or "
            f"an unprotected one asked")

    return problems


def _run_attempt_agreement(rep: dict, ev: dict) -> list[str]:
    """The oracle session must belong to the same run attempt as the evidence.

    An oracle keeps sessions by id, and a re-run that reuses a session id -- or
    a job that recorded the id of the attempt before it -- fetches a report
    describing a device that is no longer running. The commit matches, the
    session id matches, and the report is about a different attempt.
    """
    problems = []
    ev_attempt = ev.get("github_run_attempt")
    rep_attempt = rep.get("run_attempt")
    if rep_attempt in (None, ""):
        problems.append("the oracle report records no `run_attempt`, so it "
                        "cannot be tied to the attempt that produced this "
                        "evidence")
    elif ev_attempt not in (None, "") and str(rep_attempt) != str(ev_attempt):
        problems.append(f"the oracle session was opened on run attempt "
                        f"{rep_attempt!r} while the evidence was produced on "
                        f"attempt {ev_attempt!r}: they are not the same run")
    ev_run, rep_run = ev.get("github_run_id"), rep.get("run_id")
    if rep_run is not None and ev_run is not None and str(rep_run) != str(ev_run):
        problems.append(f"the oracle session belongs to run {rep_run!r}, not "
                        f"run {ev_run!r}")
    return problems


def sentinel_note(path) -> str:
    """`sentinel_host`, CARRIED TO BE READ AND NOT TRUSTED.

    It names whatever posted the heartbeat, and it is SELF-DECLARED by that
    poster and unverifiable from here -- so it is printed for a human and is
    checked by nothing. Gating on it would add a boolean a misconfigured
    deployment sets truthfully and a hostile one sets falsely, which is worse
    than no check: it would read as an independence guarantee while providing
    none.

    THE REAL GUARANTEE IS ALREADY INHERITED, and it is not a string. The
    sentinel token used to be handed to the device under test in the
    open-session response, so the DUT could beat it from its own address --
    emitting exactly the packet the kill switch exists to stop, and having the
    oracle file it as proof the oracle was alive. A vacuous SILENCE laundered
    through the mechanism built to detect vacuous SILENCE. The oracle now keeps
    the token on its own endpoint AND excludes any IPv4/IPv6 beat arriving from
    an address the device was seen egressing from, failing the session if one
    lands during SILENCE. That exclusion reaches this report through
    `*_sentinel_continuous`, which IS gated on. DNS beats are exempt by
    construction: a DNS beat arrives from a resolver either way, so its address
    cannot separate the sentinel from the device.
    """
    try:
        host = json.loads(path.read_text()).get("sentinel_host")
    except (OSError, json.JSONDecodeError, AttributeError):
        return ""
    return f", sentinel host {host} (self-declared, not checked)" if host else ""
