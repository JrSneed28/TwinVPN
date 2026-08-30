#!/usr/bin/env python3
"""The runnable proof that `report.py`'s guards are load-bearing.

`report.py` decides whether a criterion may go green, from four independent
things -- the run binding, the environment attestation, the artifact digest and
the external oracle's own numbers -- and every one of them exists because a
perfectly well-formed, entirely green evidence file once passed without it. A
4096-byte-page emulator, an unprivileged Windows host, a Mac whose extension
never activated, an artifact left behind by a previous run attempt, an oracle
that had stopped listening: none look wrong in any field a reader would check.

So each case below takes evidence from `evidence_fixtures.py` that is PERFECT,
changes ONE property, and asserts the row is not PASS. If a case ever starts
passing, the gate has a hole exactly the shape of that case.

AND THE POSITIVE CONTROLS ARE NOT OPTIONAL: every negative case is also
satisfied by a gate that rejects everything, so an unusable gate would be
indistinguishable from a strict one. `PositiveControls` is first for that
reason.

Usage:  build/acceptance/test_report_prerequisites.py  (non-zero on failure)
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import oracle_adjudication  # noqa: E402
import evidence_fixtures as fx  # noqa: E402
import report  # noqa: E402
from gate_harness import GateCase  # noqa: E402
# Imported for its TestCase classes: `unittest.main()` collects from THIS
# module's namespace, so the star import is what keeps one command running
# every case after the environment tests moved to their own file.
from test_environment_attestation import *  # noqa: E402,F401,F403
# And the producer half: everything above grades the CHECKER against a fixture,
# which is exactly why a writer that stopped emitting a required key went
# unnoticed. `test_evidence_writers` renders the real writers and grades those.
from test_evidence_writers import *  # noqa: E402,F401,F403


class PositiveControls(GateCase):
    """Correct evidence passes. Without these, everything below is vacuous."""
    def test_windows_killswitch_passes(self):
        self.assertGreen("windows-killswitch", "WINDOWS-WFP-KILLSWITCH",
                         fx.windows(), fx.oracle())

    def test_android_16k_passes(self):
        self.assertGreen("android-16k", "ANDROID-16K-PAGE-SIZE", fx.android())

    def test_macos_sysext_passes(self):
        self.assertGreen("macos-sysext", "MACOS-SYSEXT-LIFECYCLE",
                         fx.macos_sysext(),
                         fx.oracle("sess-mac", "MACOS-SYSEXT-LIFECYCLE"))

    def test_macos_signature_passes(self):
        self.assertGreen("macos-signature", "MACOS-PRODUCTION-SIGNATURE",
                         fx.macos_signature())

    def test_ios_fail_closed_passes(self):
        self.assertGreen("ios-corellium", "IOS-NE-FAIL-CLOSED", fx.ios_ne(),
                         fx.oracle("sess-ios", "IOS-NE-FAIL-CLOSED"))

    def test_ios_profile_removal_passes(self):
        self.assertGreen("ios-profile-removal", "IOS-PROFILE-REMOVAL-HONESTY",
                         fx.ios_profile_removal())

    def test_ios_supervised_passes(self):
        self.assertGreen("ios-supervised", "IOS-SUPERVISED-ALWAYS-ON",
                         fx.ios_supervised(),
                         fx.oracle("sess-sup", "IOS-SUPERVISED-ALWAYS-ON"))

    def test_a_green_row_survives_a_job_result_of_success(self):
        self.assertGreen("android-16k", "ANDROID-16K-PAGE-SIZE", fx.android(),
                         jobs={"android-16k": "success"})


class RunBinding(GateCase):
    """Evidence about another run is not weak evidence; it is about something else."""

    def test_another_commit_is_refused(self):
        self.assertRefused("windows-killswitch", "WINDOWS-WFP-KILLSWITCH",
                           fx.windows() | {"commit": "f" * 40}, fx.oracle())

    def test_another_run_id_is_refused(self):
        self.assertRefused("windows-killswitch", "WINDOWS-WFP-KILLSWITCH",
                           fx.windows() | {"github_run_id": "999"}, fx.oracle())

    def test_the_previous_run_attempt_is_refused(self):
        # THE STALE-BUT-CORRECT-SHA CASE. Same commit, same run, attempt 1 --
        # an artifact the failed first attempt left in the run's store.
        detail = self.assertRefused(
            "windows-killswitch", "WINDOWS-WFP-KILLSWITCH",
            fx.windows() | {"github_run_attempt": "1"}, fx.oracle())
        self.assertIn("attempt", detail)

    def test_evidence_with_no_run_attempt_cannot_be_bound(self):
        ev = fx.windows()
        del ev["github_run_attempt"]
        self.assertRefused("windows-killswitch", "WINDOWS-WFP-KILLSWITCH", ev,
                           fx.oracle())

    def test_another_repository_is_refused(self):
        self.assertRefused("android-16k", "ANDROID-16K-PAGE-SIZE",
                           fx.android() | {"repository": "someone/else"})

    def test_a_file_discharging_another_criterion_is_refused(self):
        self.assertRefused("windows-killswitch", "WINDOWS-WFP-KILLSWITCH",
                           fx.windows() | {"criterion": "MACOS-SYSEXT-LIFECYCLE"},
                           fx.oracle())

    def test_schema_version_1_cannot_discharge_an_attested_criterion(self):
        self.assertRefused("windows-killswitch", "WINDOWS-WFP-KILLSWITCH",
                           fx.windows() | {"schema_version": 1}, fx.oracle())


class ArtifactDigests(GateCase):
    """A criterion is a claim about a specific built thing, or about nothing."""

    def test_a_missing_or_empty_digest_map_is_refused(self):
        ev = fx.android()
        del ev["artifact_digests"]
        self.assertRefused("android-16k", "ANDROID-16K-PAGE-SIZE", ev)
        self.assertRefused("android-16k", "ANDROID-16K-PAGE-SIZE",
                           fx.android() | {"artifact_digests": {}})

    def test_a_missing_required_digest_is_refused(self):
        # An app can activate an extension built from a different tree.
        ev = fx.macos_sysext()
        del ev["artifact_digests"]["net.twinvpn.client.tunnel.systemextension"]
        self.assertRefused("macos-sysext", "MACOS-SYSEXT-LIFECYCLE", ev,
                           fx.oracle("sess-mac", "MACOS-SYSEXT-LIFECYCLE"))
        # No pinned `TwinVPN.app.zip`: not the shipped product.
        ev = fx.macos_signature()
        del ev["artifact_digests"]["TwinVPN.app.zip"]
        self.assertRefused("macos-signature", "MACOS-PRODUCTION-SIGNATURE", ev)

    def test_a_malformed_digest_is_refused(self):
        # Uppercase is refused, not normalised: a different tool produced it.
        for bad in ("A" * 64, "ab12", "z" * 64, 1234):
            self.assertRefused("android-16k", "ANDROID-16K-PAGE-SIZE",
                               fx.android() | {"artifact_digests":
                                               {"app-release.apk": bad}})

    def test_a_digest_that_disagrees_with_the_download_is_refused(self):
        # Self-report vs recomputed: disagreement means graded != built bytes.
        os.environ["TWINVPN_EXPECTED_ARTIFACT_DIGESTS"] = json.dumps(
            {"app-release.apk": "9" * 64})
        detail = self.assertRefused("android-16k", "ANDROID-16K-PAGE-SIZE",
                                    fx.android())
        self.assertIn("not the build", detail)


class PathIdentity(GateCase):
    """Two paths were established, and they were two."""

    def test_overlapping_path_identities_are_refused(self):
        # Both legs out of one interface. Every arrival is attributable to
        # either, so the silence attributable to neither.
        detail = self.assertRefused(
            "windows-killswitch", "WINDOWS-WFP-KILLSWITCH",
            fx.windows(protected_path_identity="203.0.113.7",
                       unprotected_path_identity="203.0.113.7"),
            fx.oracle())
        self.assertIn("source identity", detail)

    def test_an_unestablished_control_path_is_refused(self):
        # Without the unprotected leg, a silent window is equally well explained
        # by a device with no working network at all.
        self.assertRefused("windows-killswitch", "WINDOWS-WFP-KILLSWITCH",
                           fx.windows(unprotected_path_established=False),
                           fx.oracle())

    def test_a_probe_run_on_the_controller_is_refused(self):
        # `ci-ios-corellium.sh` probes from the ubuntu controller, not the
        # virtual iPhone. Every oracle number is then about the controller's
        # egress while staying internally consistent -- sentinel held, attempts
        # high, identities distinct -- and the device may have leaked.
        detail = self.assertRefused("ios-corellium", "IOS-NE-FAIL-CLOSED",
                                    fx.ios_ne(probe_host="controller"),
                                    fx.oracle("sess-ios", "IOS-NE-FAIL-CLOSED"))
        self.assertIn("probe_host", detail)

    def test_an_unmeasured_path_identity_is_refused(self):
        ev = fx.ios_ne()
        del ev["environment"]["protected_path_identity"]
        self.assertRefused("ios-corellium", "IOS-NE-FAIL-CLOSED", ev,
                           fx.oracle("sess-ios", "IOS-NE-FAIL-CLOSED"))


class OracleAdjudication(GateCase):
    """The oracle's verdict re-derived from the oracle's own numbers."""

    def win(self, **over):
        return self.assertRefused("windows-killswitch", "WINDOWS-WFP-KILLSWITCH",
                                  fx.windows(), fx.oracle(**over))

    def test_a_version_1_oracle_report_is_refused(self):
        # It cannot answer any of the questions below -- no sentinel, no attempt
        # counts, no path identities -- and its absent fields must not be read
        # as the passing values they resemble.
        self.assertIn("schema_version", self.win(schema_version=1))

    def test_a_family_out_of_play_must_be_null_and_nothing_else(self):
        # `null` is legitimate ONLY where the table says the criterion has no
        # such leg -- and there, `true` is the dangerous value: a positive claim
        # that two paths were compared when only one was ever exercised.
        table = oracle_adjudication.ORACLE_FAMILY_MINIMUM_ATTEMPTS
        original = table["WINDOWS-WFP-KILLSWITCH"]
        table["WINDOWS-WFP-KILLSWITCH"] = {"ipv4": 60, "ipv6": None, "dns": 60}
        try:
            self.assertGreen("windows-killswitch", "WINDOWS-WFP-KILLSWITCH",
                             fx.windows(),
                             fx.oracle(ipv6_identity_distinct=None,
                                       families_proven_live=["ipv4", "dns"]))
            for lie in (True, False):
                self.assertIn("no leg for", self.win(
                    ipv6_identity_distinct=lie,
                    families_proven_live=["ipv4", "dns"]))
        finally:
            table["WINDOWS-WFP-KILLSWITCH"] = original

    def test_sentinel_host_is_surfaced_and_never_gated_on(self):
        # Self-declared by whoever posts the beat and unverifiable from here, so
        # it is printed for a human and checked by nothing. The independence
        # guarantee is the oracle's address-based beat exclusion, which arrives
        # here as `*_sentinel_continuous`. A hostile or absent value must move
        # no verdict -- if either of these ever fails, it has become a gate.
        _, detail, _ = self.probe("windows-killswitch", "WINDOWS-WFP-KILLSWITCH",
                                  fx.windows(),
                                  fx.oracle(sentinel_host="beacon.example"))
        self.assertIn("beacon.example", detail)
        for host in (None, "the-device-under-test"):
            self.assertGreen("windows-killswitch", "WINDOWS-WFP-KILLSWITCH",
                             fx.windows(), fx.oracle(sentinel_host=host))

    def test_a_missing_oracle_report_is_refused(self):
        self.assertRefused("windows-killswitch", "WINDOWS-WFP-KILLSWITCH",
                           fx.windows(), None)

    def test_an_egress_criterion_naming_no_session_is_refused(self):
        self.assertRefused("windows-killswitch", "WINDOWS-WFP-KILLSWITCH",
                           fx.windows() | {"leak_oracle": None}, None)

    def test_an_inconclusive_verdict_is_not_a_pass(self):
        self.win(verdict="INCONCLUSIVE",
                 inconclusive=["ipv6 sentinel gapped"])

    def test_a_failing_oracle_beats_a_job_claiming_pass(self):
        # THE LIE. The evidence says PASS, the observer says FAIL.
        detail = self.win(verdict="FAIL", failures=["1 unauthorized arrival"])
        self.assertIn("claims PASS", detail)

    def test_one_forbidden_arrival_fails_the_row(self):
        self.win(ipv6_observed=1)

    def test_an_oracle_report_for_another_commit_or_run_is_refused(self):
        self.win(commit="f" * 40)
        self.win(run_id="999")

    def test_an_oracle_report_for_another_run_attempt_is_refused(self):
        detail = self.win(run_attempt="1")
        self.assertIn("attempt", detail)

    def test_an_oracle_report_with_no_run_attempt_is_refused(self):
        rep = fx.oracle()
        del rep["run_attempt"]
        self.assertRefused("windows-killswitch", "WINDOWS-WFP-KILLSWITCH",
                           fx.windows(), rep)

    def test_a_missing_sentinel_section_is_refused(self):
        # An oracle build that never measured continuity. Absent must never read
        # as true: it is what a crashed observer and a version skew both write.
        rep = fx.oracle()
        for family in ("ipv4", "ipv6", "dns"):
            del rep[f"{family}_sentinel_continuous"]
        detail = self.assertRefused("windows-killswitch",
                                    "WINDOWS-WFP-KILLSWITCH", fx.windows(), rep)
        self.assertIn("sentinel_continuous", detail)

    def test_a_single_interrupted_sentinel_fails_the_row(self):
        # One family, one gap. For that window the oracle cannot tell a device
        # that sent nothing from an observer that heard nothing. `null` is the
        # same hole with a politer name.
        self.win(ipv6_sentinel_continuous=False)
        self.win(dns_sentinel_continuous=None)

    def test_insufficient_or_unrecorded_probe_attempts_are_refused(self):
        # Silence from a device that stopped probing is not a kill switch, and
        # an unrecorded count says nothing about whether it ever tried.
        self.assertIn("12", self.win(ipv4_attempts=12))
        rep = fx.oracle()
        del rep["dns_attempts"]
        self.assertRefused("windows-killswitch", "WINDOWS-WFP-KILLSWITCH",
                           fx.windows(), rep)

    def test_missing_positive_controls_are_refused(self):
        # The oracle never once saw this device -- on any family, or on one of
        # them -- so its later silence is unremarkable.
        self.assertIn("positive control", self.win(families_proven_live=None))
        self.win(families_proven_live=["ipv4", "dns"])

    def test_an_overlapping_family_identity_is_refused(self):
        self.win(ipv4_identity_distinct=False)

    def test_a_null_family_identity_is_refused_where_the_leg_exists(self):
        # `null` is permitted only for a leg the criterion genuinely does not
        # have, and that is a table entry, never an inference from a missing
        # value. Every lane in the table has all three legs.
        self.win(ipv6_identity_distinct=None)

    def test_an_ambiguous_dns_resolver_identity_is_refused(self):
        # A query from a resolver the oracle cannot map to a leg is not an
        # arrival on the unprotected leg, and must never be graded as one.
        self.assertIn("resolver", self.win(dns_resolver_identity_ambiguous=True))
        rep = fx.oracle()
        del rep["dns_resolver_identity_ambiguous"]
        self.assertRefused("windows-killswitch", "WINDOWS-WFP-KILLSWITCH",
                           fx.windows(), rep)


class JobOutcome(GateCase):
    """`failure`, `cancelled`, `skipped`, missing and NOT-EXECUTED are each their own red."""

    def test_a_skipped_job_is_red_and_says_so(self):
        # The dangerous one: an unregistered self-hosted runner makes the job
        # skip, and a skip is the absence that looks most like routine absence.
        verdict, detail, _ = self.probe("windows-killswitch",
                                        "WINDOWS-WFP-KILLSWITCH", None, None,
                                        {"windows-killswitch": "skipped"})
        self.assertEqual(verdict, report.NOT_EXECUTED)
        self.assertIn("SKIPPED", detail)

    def test_a_cancelled_job_is_red_and_says_so(self):
        _, detail, _ = self.probe("macos-sysext", "MACOS-SYSEXT-LIFECYCLE",
                                  None, None, {"macos-sysext": "cancelled"})
        self.assertIn("CANCELLED", detail)

    def test_a_failed_job_is_red_and_says_so(self):
        _, detail, _ = self.probe("ios-corellium", "IOS-NE-FAIL-CLOSED", None,
                                  None, {"ios-corellium": "failure"})
        self.assertIn("FAILED", detail)

    def test_a_job_absent_from_the_run_is_red_and_says_so(self):
        _, detail, _ = self.probe("macos-signature", "MACOS-PRODUCTION-SIGNATURE",
                                  None, None, {"android-16k": "success"})
        self.assertIn("never scheduled", detail)

    def test_an_unrecognised_job_result_is_not_assumed_to_be_a_pass(self):
        self.assertRefused("android-16k", "ANDROID-16K-PAGE-SIZE", fx.android(),
                           jobs={"android-16k": "probably-fine"})

    def test_green_evidence_from_a_job_that_did_not_succeed_is_refused(self):
        # The file describes the part of the run that happened; the outcome
        # describes whether the run finished. Both have to be right.
        detail = self.assertRefused("android-16k", "ANDROID-16K-PAGE-SIZE",
                                    fx.android(),
                                    jobs={"android-16k": "cancelled"})
        self.assertIn("CANCELLED", detail)

    def test_evidence_declaring_not_executed_stays_not_executed(self):
        # It ran and deliberately discharged nothing. Re-deriving that as FAIL
        # would erase the only distinction the third word exists for.
        verdict, detail, _ = self.probe(
            "ios-supervised", "IOS-SUPERVISED-ALWAYS-ON",
            fx.ios_supervised() | {"verdict": "NOT-EXECUTED",
                                   "notes": "supervised mode does not ship yet"})
        self.assertEqual(verdict, report.NOT_EXECUTED)
        self.assertIn("does not ship yet", detail)

    def test_a_missing_file_with_no_job_map_is_still_not_executed(self):
        verdict, detail, _ = self.probe("android-16k", "ANDROID-16K-PAGE-SIZE",
                                        None)
        self.assertEqual(verdict, report.NOT_EXECUTED)
        self.assertIn("no evidence", detail)


if __name__ == "__main__":
    unittest.main(verbosity=2)
