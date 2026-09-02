#!/usr/bin/env python3
"""Every environment key `report.py` demands, emitted by the writer that produces it.

===========================================================================
THE DEFECT THIS EXISTS FOR
===========================================================================
`report.py` grades each platform criterion's `environment` against
`PREREQUISITES`, and `PATH_IDENTITY_PREREQUISITES` extends that table for every
criterion in `ORACLE_REQUIRED`. Separately, a shell script under `build/ci/`
produces the evidence. NOTHING ASSERTED THAT THE TWO AGREED. The checker's
demands and the producers' output drifted apart in silence:
`ci-windows-killswitch.sh` emitted none of the five path-identity keys,
`ci-macos-sysext.sh` emitted one of the five, and `ci-ios-corellium.sh` still
emits none of the five conditions `IOS-PROFILE-REMOVAL-HONESTY` is about -- it
collapses them into one local boolean that picks a verdict and is then dropped.
Every one of those rows would have gone red on the ENVIRONMENT CHECK, before
the oracle verdict was ever read, on fully provisioned infrastructure.

`test_report_prerequisites.py` could not see it: it grades the CHECKER against
`evidence_fixtures.py`, and A PRODUCER/CHECKER DIVERGENCE IS INVISIBLE TO A TEST
WHOSE PRODUCER IS THE FIXTURE. `test_evidence_writers.py` renders the real
writers and does see the producer -- but it grades whatever the heredoc happens
to CONTAIN. Neither asks the question this file asks: does the writer emit
EVERYTHING its criterion requires? That question is the one the drift survived.

===========================================================================
HOW IT IS ANSWERED, AND WHAT IS AND IS NOT REAL ABOUT IT
===========================================================================
No environment key here is found by grepping a shell script for a word, and
nothing here hand-copies a key name. The `environment` object is obtained by RENDERING the writer's own heredoc
with bash -- `test_evidence_writers.writers()` and `.render()`, reused rather
than reimplemented -- and the required keys come from the real `PREREQUISITES`,
after `report.py` has merged `PATH_IDENTITY_PREREQUISITES` into every
`ORACLE_REQUIRED` criterion. Adding an egress criterion to `ORACLE_REQUIRED`
therefore extends this file with no edit to it.

REAL: which keys the writer emits. That is read off the rendered JSON, so a key
in a comment, in a `grep` marker, or in prose does not count -- which matters,
because `ci-ios-corellium.sh` names `protection_lost_actionable` in the console
marker it searches for and emits no such key.

NOT CHECKED HERE: the VALUES. `render()` stubs the writer's interpolations, so
this file is about key coverage only. `ci-ios-corellium.sh` emits
`"probe_host": "controller"` where `PATH_IDENTITY_PREREQUISITES` accepts only
`"device"`, and this file passes it. Values are `check_environment`'s job and
are graded at report time; the failure this file exists to catch is the one that
happens when there is no value to grade at all.

ALSO NOT CHECKED: whether a writer emits its keys on every branch, and whether a
criterion has a lane that ever RUNS. A criterion whose script is never invoked
produces no evidence and lands NOT-EXECUTED, which is `job_results.py`'s
problem.

===========================================================================
THE PRODUCER THAT DOES NOT EXIST YET
===========================================================================
Derivation cannot see a lane nobody has written. `UNPRODUCED` says a criterion
has no writer; `PRODUCER_PINS` says WHICH FILE is supposed to become one, and
fails once, by path, until it does. It is also the only place a digest key is
checked as text, because `test_evidence_writers.render()` builds the digest map
out of the adjudicator's own names and therefore cannot see a lane that spells
one differently.

===========================================================================
THE INDIRECT PRODUCER
===========================================================================
`ci-windows-killswitch.sh` does not write its own environment inline: it
interpolates `$environment`, built by `scrape_env` out of the
`TWINVPN_PRECONDITION <key>=<value>` lines that
`core/crates/twinvpn-platform-windows/tests/wfp_preconditions.rs` prints. That
is a bare JSON fragment, so `test_evidence_writers._STUBS` replaces it with
`"stub_attestation": true` and the rendered environment cannot show
`privileged`, `bfe_running`, `wfp_write_probe` or `twinvpn_filters_installed`.

Treating that as four missing keys would be a false failure; ignoring it would
let a genuinely missing one hide. So `SCRAPED` names the file, the keys are
taken from its `fact("<key>", ...)` CALLS rather than from a text search, and
three assertions keep the entry honest: the producer must mention the scraped
file, the extraction must find keys at all, and the rendered environment must
actually carry the stub marker that says the fragment was stubbed. If any of
those stops holding, this fails loudly instead of quietly widening.
"""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from adjudication import ARTIFACT_DIGEST_REQUIRED, PATH_IDENTITY_PREREQUISITES  # noqa: E402
from report import ORACLE_REQUIRED, PREREQUISITES  # noqa: E402
from test_evidence_writers import render, writers  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
CI = REPO / "build" / "ci"

# The `fact()` helper in wfp_preconditions.rs is the ONLY thing that prints a
# `TWINVPN_PRECONDITION` line, so its call sites are the exhaustive list of keys
# that reach the evidence by that route. A text search would also match the
# doc comment that names the format.
FACT = re.compile(r'\bfact\("([A-Za-z0-9_]+)"')

# Files a producer SCRAPES rather than writes inline. See THE INDIRECT PRODUCER.
SCRAPED: dict[str, tuple[str, ...]] = {
    "WINDOWS-WFP-KILLSWITCH": (
        "core/crates/twinvpn-platform-windows/tests/wfp_preconditions.rs",
    ),
}

# Criteria with no evidence writer at all. `report.py` marks the supervised row
# `required=False` because supervised mode is a PRODUCT MODE that may not ship
# -- but "not required" is not "not checked", and a criterion with no producer
# is a fact this file states rather than one it discovers by finding no keys.
UNPRODUCED: dict[str, str] = {
    "IOS-SUPERVISED-ALWAYS-ON":
        "supervised/managed Always-On has no lane script; nothing writes "
        "build/ci/evidence/ios-supervised.json. Closed when that lane lands.",
    "IOS-FAILCLOSED-CONFIGURATION":
        "the hosted simulator lane is build/ci/ci-ios.sh and is being written "
        "in parallel with this table; nothing writes "
        "build/ci/evidence/ios-failclosed-configuration.json yet. PRODUCER_PINS "
        "names the file, so this entry is a statement of the gap and not a "
        "substitute for it. Closed when that branch lands.",
    "MACOS-PF-BOOT-ANCHOR":
        "the hosted pf lane is build/ci/ci-macos-pf-anchor.sh and does not "
        "exist yet; nothing writes build/ci/evidence/macos-pf-anchor.json. "
        "PRODUCER_PINS names the file. Closed when that lane lands.",
}

# THE LANE SCRIPTS THE RECONCILED CRITERIA ARE BEING WRITTEN TO, PINNED BY NAME.
#
# Everything else in this file is DERIVED -- keys off the real tables, emitted
# keys off a real render -- and derivation cannot see a producer that does not
# exist yet. `UNPRODUCED` above states that a criterion has no writer; it does
# not say WHICH file is supposed to become one, so an entry could sit there
# indefinitely while the row read NOT-EXECUTED and nobody could tell whether the
# lane was late or abandoned.
#
# These entries name the file and the strings it must carry, which also covers
# the blind spot at test_evidence_writers.py:150: `render()` stubs
# `ARTIFACT_DIGESTS` from the ADJUDICATOR'S OWN key names, so a lane that spells
# a digest key differently renders as if it agreed. Each digest key below is
# therefore pinned as TEXT against the script that must write it -- the same
# thing the macOS system-extension case at the bottom of this file does for
# `com.twinvpn.app.sysext.systemextension`.
#
# A missing file fails ONCE, naming the path and everything it owes. That is
# deliberate: thirty subtest failures for one absent script tell a reader less
# than one failure that names the script.
PRODUCER_PINS: dict[str, tuple[str, ...]] = {
    # Both simulator rows come out of the existing iOS lane, which today is the
    # version-1 link/run writer only.
    "build/ci/ci-ios.sh": (
        "IOS-FAILCLOSED-CONFIGURATION", "IOS-PROFILE-REMOVAL-HONESTY",
        "TwinVPN.app/TwinVPN", "execution", "assertion_source",
        "simulator_runtime", "xcode_version", "test_count",
        "os_enforcement_exercised",
    ),
    "build/ci/ci-macos-pf-anchor.sh": (
        "MACOS-PF-BOOT-ANCHOR", "twinvpn-ksd", "pf_enabled",
        "anchor_referenced_in_main_ruleset", "anchor_rule_count",
        "read_back_tables", "covered_prefix_connect_refused",
        "control_connect_succeeded", "ksd_status_exit",
        "bridge_tests_as_root", "bridge_test_count",
    ),
    # The two keys the in-box topology added to every egress criterion. The
    # kill-switch lane is the one that can measure them: it builds the oracle
    # and the sentinel it is attesting.
    "build/ci/ci-windows-killswitch.sh": (
        "oracle_topology", "sentinel_egress_identity",
    ),
}

# THE GAPS THAT ARE OPEN RIGHT NOW, each with what closes it.
#
# An allowlist of KNOWN drift, not permission for drift. Every entry is checked
# from both ends: a key here that `PREREQUISITES` no longer requires fails, and
# a key here that the writer has SINCE STARTED EMITTING fails too, with an
# instruction to delete the entry. The list can only shrink, and it cannot rot
# into a standing exemption.
KNOWN_GAPS: dict[str, tuple[str, tuple[str, ...]]] = {
    "IOS-NE-FAIL-CLOSED": (
        "the leak probe runs on the ubuntu controller, not on the device, so "
        "the existing lane has no honest value to write for either leg's "
        "identity -- it would be attesting the CONTROLLER's paths, which is "
        "the exact substitution `probe_host` exists to catch. The topology and "
        "the sentinel's egress identity are unmeasurable for the same reason, "
        "and this criterion additionally has NO EXECUTOR at all: it needs a "
        "provisioned iPhone whose IPA keeps the packet-tunnel-provider "
        "entitlement. Closed by moving the probe onto a DUT that exists. NOT "
        "closed by writing the keys, and this entry is here rather than the "
        "keys for that reason.",
        ("protected_path_established", "unprotected_path_established",
         "protected_path_identity", "unprotected_path_identity",
         "oracle_topology", "sentinel_egress_identity"),
    ),
    "MACOS-SYSEXT-LIFECYCLE": (
        "the two topology keys arrived with the in-box fabric, and this "
        "criterion has NO EXECUTOR to measure them on: activation needs "
        "Apple's packet-tunnel-provider-systemextension grant and then an "
        "approval a CI job cannot give, so ci-macos-sysext.sh cannot run at "
        "all. Writing the keys would be attesting a topology nothing stood up. "
        "Closed when an executor exists, not before.",
        ("oracle_topology", "sentinel_egress_identity"),
    ),
    "WINDOWS-WFP-KILLSWITCH": (
        "the two topology keys arrived with the in-box fabric and the lane is "
        "being rewritten to build that fabric in the same change. It is the "
        "one criterion that CAN measure them -- it stands up the oracle and "
        "the sentinel it attests -- so this entry is short-lived by "
        "construction and PRODUCER_PINS names the file that closes it: "
        "build/ci/ci-windows-killswitch.sh.",
        ("oracle_topology", "sentinel_egress_identity"),
    ),
    "IOS-PROFILE-REMOVAL-HONESTY": (
        "the criterion was redefined as SIMULATOR logic, so its producer is "
        "build/ci/ci-ios.sh rather than the device lane that names it today. "
        "The device lane correctly emits none of the simulator attestation: it "
        "does not run on a simulator, and a device lane writing "
        "`execution: simulator` would be the exact conflation the pins exist "
        "to prevent. Closed when ci-ios.sh writes "
        "build/ci/evidence/ios-profile-removal.json -- PRODUCER_PINS names it.",
        ("execution", "os_enforcement_exercised", "assertion_source",
         "simulator_runtime", "xcode_version", "test_count"),
    ),
}

_CACHE: dict[str, list[tuple[str, dict]]] | None = None


def producers() -> dict[str, list[tuple[str, dict]]]:
    """Criterion -> [(script name, the `environment` its writer produces)].

    Rendering is a bash subprocess per writer, so it is done once and cached:
    every case below reads the same rendering.
    """
    global _CACHE
    if _CACHE is None:
        _CACHE = {}
        for script, body, criteria in writers():
            for criterion in criteria:
                if criterion not in PREREQUISITES:
                    continue          # a version-1 writer, or another criterion
                ev = json.loads(render(body, criterion))
                env = ev.get("environment")
                _CACHE.setdefault(criterion, []).append(
                    (script.name, env if isinstance(env, dict) else {}))
    return _CACHE


def scraped_keys(criterion: str) -> set[str]:
    keys: set[str] = set()
    for rel in SCRAPED.get(criterion, ()):
        keys |= set(FACT.findall((REPO / rel).read_text()))
    return keys


def emitted(criterion: str) -> set[str]:
    """Every environment key this criterion's evidence can actually carry."""
    keys = scraped_keys(criterion)
    for _, env in producers().get(criterion, []):
        keys |= set(env)
    return keys


class ProducerKeyCoverage(unittest.TestCase):
    """The checker's demands, checked against what the writers emit."""

    def test_every_criterion_has_a_writer_or_is_declared_unproduced(self):
        # The totality assertion. A criterion added to `PREREQUISITES` whose
        # writer nobody wrote is a FAILURE here, not a row that quietly grades
        # nothing -- which is how a table-driven test rots.
        self.assertGreater(len(PREREQUISITES), 0)
        for criterion in sorted(PREREQUISITES):
            with self.subTest(criterion=criterion):
                self.assertTrue(
                    criterion in producers() or criterion in UNPRODUCED,
                    f"no evidence writer under build/ci/ produces {criterion}, "
                    f"and it is not declared in UNPRODUCED")

    def test_the_indirect_producer_is_still_indirect(self):
        # `SCRAPED` is only legitimate while the producer really does build its
        # environment out of that file. Three ways it could stop being true, all
        # of which must fail rather than widen the set of keys that look emitted.
        for criterion, rels in sorted(SCRAPED.items()):
            with self.subTest(criterion=criterion):
                self.assertIn(criterion, PREREQUISITES)
                self.assertTrue(scraped_keys(criterion),
                                f"no `fact(\"...\")` calls found in "
                                f"{rels}; the extraction has gone stale and is "
                                f"now hiding nothing rather than proving it")
                envs = [env for _, env in producers()[criterion]]
                self.assertTrue(
                    any("stub_attestation" in env for env in envs),
                    f"{criterion}'s rendered environment no longer carries the "
                    f"`$environment` stub, so the writer emits its keys inline "
                    f"now: drop its SCRAPED entry and let the render prove it")
            sources = "\n".join((CI / name).read_text()
                                for name, _ in producers()[criterion])
            for rel in rels:
                path = REPO / rel
                with self.subTest(criterion=criterion, scraped=path.name):
                    self.assertTrue(path.is_file(), f"{path} does not exist")
                    self.assertIn(path.stem, sources,
                                  f"{criterion}'s writer never mentions "
                                  f"{path.name}, so it is not a source of that "
                                  f"criterion's environment")

    def test_every_required_key_is_emitted_by_its_producer(self):
        # THE CASE THE DRIFT WOULD HAVE FAILED, driven off the real tables so a
        # key added to `PREREQUISITES` -- or to `PATH_IDENTITY_PREREQUISITES`,
        # which `report.py` merges into every `ORACLE_REQUIRED` criterion -- is
        # demanded of the writer without anyone remembering to mirror it here.
        checked = 0
        for criterion, keys in sorted(PREREQUISITES.items()):
            if criterion in UNPRODUCED:
                continue
            allowed = KNOWN_GAPS.get(criterion, ("", ()))[1]
            have = emitted(criterion)
            scripts = ", ".join(s for s, _ in producers().get(criterion, []))
            for key in sorted(keys):
                checked += 1
                if key in allowed:
                    continue
                with self.subTest(criterion=criterion, key=key):
                    self.assertIn(
                        key, have,
                        f"{criterion} requires `{key}` in its evidence's "
                        f"`environment`, and {scripts} does not emit it. The "
                        f"row fails the environment check before its verdict "
                        f"is read, on fully provisioned infrastructure. Fix "
                        f"the writer; add it to KNOWN_GAPS only if the value "
                        f"genuinely cannot be measured truthfully yet.")
        # A run that graded nothing is not a pass: the tables are imported, and
        # an empty one would make every case above vacuous.
        self.assertGreater(checked, 30, "the prerequisite tables came back "
                                        "nearly empty; nothing was graded")

    def test_the_allowlist_names_only_real_requirements(self):
        # Drift the other way: a key renamed in `PREREQUISITES` leaves behind an
        # exemption that silently covers nothing.
        for criterion, (_, keys) in sorted(KNOWN_GAPS.items()):
            with self.subTest(criterion=criterion):
                self.assertIn(criterion, PREREQUISITES)
                self.assertNotIn(criterion, UNPRODUCED)
            for key in keys:
                with self.subTest(criterion=criterion, key=key):
                    self.assertIn(key, PREREQUISITES[criterion],
                                  f"KNOWN_GAPS exempts {criterion}.{key}, "
                                  f"which PREREQUISITES no longer requires")

    def test_the_allowlist_is_not_stale(self):
        # An allowlist that outlives its gap is permanent permission. Every
        # entry must still BE a gap, so a fix that lands forces the entry out.
        for criterion, (reason, keys) in sorted(KNOWN_GAPS.items()):
            have = emitted(criterion)
            for key in keys:
                with self.subTest(criterion=criterion, key=key):
                    self.assertNotIn(
                        key, have,
                        f"{criterion}.{key} is emitted now, so the KNOWN_GAPS "
                        f"entry is stale: delete it. It said: {reason}")

    def test_the_unproduced_criteria_are_still_unproduced(self):
        # The same staleness rule for a whole missing lane, and the reason it is
        # separate: "no script writes this" is a different problem from "the
        # script that writes this forgot a key", and it is detected differently.
        for criterion, reason in sorted(UNPRODUCED.items()):
            with self.subTest(criterion=criterion):
                self.assertIn(criterion, PREREQUISITES)
                self.assertNotIn(
                    criterion, producers(),
                    f"a writer produces {criterion} now; delete its UNPRODUCED "
                    f"entry so its keys are graded. It said: {reason}")

    def test_path_identity_reaches_every_egress_criterion(self):
        # `report.py` merges `PATH_IDENTITY_PREREQUISITES` into each
        # `ORACLE_REQUIRED` criterion at import time, which is what makes a
        # fifth egress criterion extend this file for free. Pinned here because
        # everything above depends on that merge: if it stopped, the
        # path-identity keys would leave the tables and every gap would read as
        # closed.
        self.assertGreater(len(ORACLE_REQUIRED), 0)
        self.assertGreater(len(PATH_IDENTITY_PREREQUISITES), 0)
        for criterion in sorted(ORACLE_REQUIRED):
            with self.subTest(criterion=criterion):
                self.assertLessEqual(set(PATH_IDENTITY_PREREQUISITES),
                                     set(PREREQUISITES[criterion]))

    def test_the_named_lane_scripts_exist_and_carry_what_they_owe(self):
        # THE PIN THAT DERIVATION CANNOT PROVIDE. Everything above is computed
        # from the tables and from a render, so a producer that does not exist
        # yet is invisible to all of it -- `UNPRODUCED` records that a criterion
        # has no writer, and nothing records WHICH file was supposed to be one.
        #
        # It is also the only check that can see a misspelled digest key:
        # `render()` builds the digest map from `ARTIFACT_DIGEST_REQUIRED`
        # itself, so a lane writing `TwinVPN.app/TwinVPNApp` would render as if
        # it agreed with the adjudicator. Text, therefore, and one failure per
        # file naming everything that file owes.
        self.assertTrue(PRODUCER_PINS, "the pin table is empty; nothing graded")
        for rel, needles in sorted(PRODUCER_PINS.items()):
            path = REPO / rel
            with self.subTest(script=rel):
                self.assertTrue(
                    path.is_file(),
                    f"{rel} does not exist. It is the producer for: "
                    f"{', '.join(needles)}. Until it lands, every criterion "
                    f"and key in that list is unproduced and its row reads "
                    f"NOT-EXECUTED.")
                text = path.read_text()
                absent = [n for n in needles if n not in text]
                self.assertEqual(
                    absent, [],
                    f"{rel} exists but never mentions {', '.join(absent)}. A "
                    f"criterion name that is absent means the lane writes no "
                    f"evidence for it; a KEY that is absent means the row fails "
                    f"its environment check before its verdict is read; a "
                    f"DIGEST name that is absent means the run binding fails, "
                    f"and it is the one kind of drift the rendered writers "
                    f"cannot see, because they stub the digest map from the "
                    f"adjudicator's own names.")

    def test_the_extension_digest_key_names_the_extension_project_yml_builds(self):
        # THE DRIFT `render()` CANNOT SEE. It stubs `ARTIFACT_DIGESTS` from the
        # adjudicator's own key names, so a producer that spells a key
        # differently renders as if it agreed. 54d1977 moved the sysext lane's
        # default bundle id to the target `shells/macos/project.yml` builds and
        # left `ARTIFACT_DIGEST_REQUIRED` naming the iOS provider id it
        # replaced: the lane wrote `com.twinvpn.app.sysext.systemextension`,
        # the adjudicator demanded `net.twinvpn.client.tunnel.systemextension`,
        # and the row would have failed its run-binding check on a fully
        # provisioned Mac. The lane builds the key from its own default, so the
        # default is read as TEXT here -- the one place this file does that,
        # and it does it because the alternative is evaluating bash.
        project = (REPO / "shells" / "macos" / "project.yml").read_text()
        self.assertEqual(project.count("type: system-extension"), 1,
                         "one system-extension target is what the key names")
        built = re.search(r"type: system-extension.*?PRODUCT_BUNDLE_IDENTIFIER:\s*(\S+)",
                          project, re.S).group(1)
        self.assertIn(f"{built}.systemextension",
                      ARTIFACT_DIGEST_REQUIRED["MACOS-SYSEXT-LIFECYCLE"],
                      "the adjudicator names an extension nobody builds")
        lane = (CI / "ci-macos-sysext.sh").read_text()
        self.assertIn(f"${{TWINVPN_EXTENSION_BUNDLE_ID:-{built}}}", lane,
                      "the lane's default is not the extension project.yml builds")
        self.assertIn('"$ext_bundle_id.systemextension"', lane,
                      "the lane no longer keys the digest by that default")


if __name__ == "__main__":
    unittest.main(verbosity=2)
