"""Hadolint adapter and the line-only check in the container engine, on real Hadolint 2.15.1 output.

`tests/fixtures/container/hadolint-2.15.1.real.json` is `hadolint -f json` on the container fixture
Dockerfile. Hadolint gives no code block, so its findings can only be checked for an existing line.
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from engine import universal, universal_run
from engine.checkov_adapter import CheckovAdapter
from engine.hadolint_adapter import HadolintAdapter
from engine.trivy_config_adapter import TrivyConfigAdapter
from engine.universal import UNKNOWN

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "container"
REAL = FIXTURES / "hadolint-2.15.1.real.json"
PROJECT = FIXTURES / "project"


def load():
    return json.loads(REAL.read_text(encoding="utf-8"))


def assess(document, project_dir):
    findings, _ = HadolintAdapter().parse(document, {"target": "t"})
    return universal.assess_all(findings, universal_run.build_registry(),
                                {"project_dir": Path(project_dir), "exposure": "unknown"})


class HadolintTest(unittest.TestCase):
    def test_real_output_is_container_findings_that_stay_unknown(self):
        (finding,) = assess(load(), PROJECT)
        self.assertEqual(finding["category"], "CONTAINER")
        self.assertEqual(finding["vulnerability"]["rule_id"], "DL3042")
        self.assertEqual(finding["assessment"]["verdict"], UNKNOWN)
        self.assertIn("no image or runtime context", finding["assessment"]["reason"])

    def test_line_past_the_end_of_the_file_is_stale(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "Dockerfile").write_text("FROM python:3.13-slim\n", encoding="utf-8")
        (finding,) = assess(load(), tmp)
        self.assertEqual(finding["assessment"]["verdict"], UNKNOWN)
        self.assertIn("stale", finding["assessment"]["reason"])

    def test_detection_separates_it_from_other_list_formats(self):
        self.assertTrue(HadolintAdapter().detect(load()))
        self.assertFalse(HadolintAdapter().detect([{"ident": "x", "determinations": {}, "locations": []}]))
        self.assertFalse(HadolintAdapter().detect(json.loads(
            (FIXTURES / "checkov-3.4.0-dockerfile.real.json").read_text(encoding="utf-8"))))
        self.assertFalse(TrivyConfigAdapter().detect(load()))
        self.assertFalse(CheckovAdapter().detect(load()))


if __name__ == "__main__":
    unittest.main()
