"""Runs the dependency regression cases in tests/eval/dependency/cases.json.

The expected verdicts are the engine's written rules, so a change in any of them is a regression to explain. The file
does not measure accuracy: nothing here is independently established ground truth.
"""

import json
import unittest
from pathlib import Path

from engine import dependency

CASES = json.loads((Path(__file__).parent / "eval" / "dependency" / "cases.json").read_text(encoding="utf-8"))["cases"]


class DependencyBenchmarkTest(unittest.TestCase):
    def test_every_case_gets_its_expected_version_status_and_verdict(self):
        for case in CASES:
            with self.subTest(case=case["id"]):
                record = {"ecosystem": case["ecosystem"], "name": "pkg", "version": case["installed"] or None,
                          "fixed_version": case["fixed"] or None}
                status = dependency.version_status(record)
                self.assertEqual(status["status"], case["expected_version_status"])
                verdict = "NOT_AFFECTED" if status["status"] == dependency.FIXED_INSTALLED else "UNKNOWN"
                self.assertEqual(verdict, case["expected_verdict"])


if __name__ == "__main__":
    unittest.main()
