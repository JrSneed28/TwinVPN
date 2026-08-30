#!/usr/bin/env python3
"""The throwaway tree one gate case runs in.

Split out of `test_report_prerequisites.py` only to keep that file under this
project's 500-line limit; there is nothing here but setup. Every case gets its
own temporary evidence directory, its own oracle directory and its own
`job-results.json`, and `report`'s module-level directory globals are pointed at
them and restored afterwards -- so no case can be influenced by the real
`build/ci/evidence/` tree or by the case before it. `TWINVPN_EXPECTED_*` is set
rather than `GITHUB_*` because a developer running the suite inside Actions
would otherwise be graded against that run's real SHA.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence_fixtures as fx  # noqa: E402
import report  # noqa: E402

NOT_PASS = (report.FAIL, report.NOT_EXECUTED)


class GateCase(unittest.TestCase):
    """Runs one criterion against one evidence file in a throwaway tree."""

    def setUp(self) -> None:
        self._env = dict(os.environ)
        self._dirs = (report.EVIDENCE_DIR, report.ORACLE_DIR)
        for stale in ("TWINVPN_EXPECTED_ARTIFACT_DIGESTS",):
            os.environ.pop(stale, None)
        os.environ.update({
            "GITHUB_SHA": fx.COMMIT,
            "TWINVPN_EXPECTED_RUN_ID": fx.RUN_ID,
            "TWINVPN_EXPECTED_RUN_ATTEMPT": fx.RUN_ATTEMPT,
            "TWINVPN_EXPECTED_REPOSITORY": fx.REPOSITORY,
        })

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self._env)
        report.EVIDENCE_DIR, report.ORACLE_DIR = self._dirs

    def probe(self, stem, criterion, evidence, oracle=None, jobs=None):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "oracle").mkdir()
            if evidence is not None:
                (root / f"{stem}.json").write_text(json.dumps(evidence))
            if oracle is not None:
                (root / "oracle" / f"{oracle['session_id']}.json").write_text(
                    json.dumps(oracle))
            if jobs is not None:
                (root / "job-results.json").write_text(json.dumps(jobs))
            report.EVIDENCE_DIR = root
            report.ORACLE_DIR = root / "oracle"
            return report.probe_criterion(stem, criterion)

    def assertGreen(self, stem, criterion, evidence, oracle=None, jobs=None):
        verdict, detail, _ = self.probe(stem, criterion, evidence, oracle, jobs)
        self.assertEqual(verdict, report.PASS,
                         f"correct evidence was refused: {detail}")

    def assertRefused(self, stem, criterion, evidence, oracle=None, jobs=None):
        verdict, detail, _ = self.probe(stem, criterion, evidence, oracle, jobs)
        self.assertIn(verdict, NOT_PASS,
                      f"expected a refusal, got {verdict}: {detail}")
        return detail


