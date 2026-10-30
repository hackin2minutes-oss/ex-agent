"""Checkov adapter and IaC engine, on real Checkov output plus targeted cases.

`tests/fixtures/iac/checkov-3.4.0.real.json` is `checkov -d . -o json` output from Checkov 3.4.0
run on `tests/fixtures/iac/project`. The fixture includes a terraform_plan document with one
parse error, because no plan file was given. That error must surface as a diagnostic.
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from engine import universal, universal_run
from engine.checkov_adapter import CheckovAdapter
from engine.semgrep_adapter import SemgrepAdapter
from engine.universal import ModelError, POTENTIALLY_EXPLOITABLE, UNKNOWN

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "iac"
REAL = FIXTURES / "checkov-3.4.0.real.json"
PROJECT = FIXTURES / "project"
SAST_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "sast"


def load_real():
    return json.loads(REAL.read_text(encoding="utf-8"))


def assess_document(document, project_dir, exposure="unknown"):
    registry = universal_run.build_registry()
    findings, _ = CheckovAdapter().parse(document, {"target": "test"})
    for finding in findings:
        finding["exploitability_context"]["exposure"] = exposure
    return universal.assess_all(findings, registry,
                                {"project_dir": Path(project_dir), "exposure": exposure})


def by_rule_and_line(assessed):
    return {(f["vulnerability"]["rule_id"], f["location"]["start_line"]): f["assessment"]
            for f in assessed}


class RealCheckovFixtureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.assessed = assess_document(load_real(), PROJECT)
        cls.by_key = by_rule_and_line(cls.assessed)

    def test_detects_real_output_and_keeps_failed_checks_only(self):
        self.assertTrue(CheckovAdapter().detect(load_real()))
        self.assertEqual(len(self.assessed), 12)
        for finding in self.assessed:
            self.assertEqual(finding["category"], "IAC")
            self.assertEqual(finding["provenance"]["scanner"], "checkov")
            self.assertEqual(finding["provenance"]["version"], "3.4.0")
            self.assertEqual(finding["original"]["check_result"]["result"], "FAILED")

    def test_open_ingress_rule_is_potentially_exploitable(self):
        assessment = self.by_key[("CKV_AWS_24", 1)]
        self.assertEqual(assessment["verdict"], POTENTIALLY_EXPLOITABLE)
        self.assertEqual(assessment["confidence"]["level"], "MEDIUM")
        self.assertTrue(any("0.0.0.0/0" in item["detail"] for item in assessment["evidence"]))

    def test_restricted_ingress_rule_is_unknown_not_exploitable(self):
        self.assertEqual(self.by_key[("CKV_AWS_23", 12)]["verdict"], UNKNOWN)

    def test_non_exposure_rule_on_an_open_block_is_not_exposure(self):
        # CKV_AWS_23 is "has a description". Its block has 0.0.0.0/0, but the rule is not about it.
        assessment = self.by_key[("CKV_AWS_23", 1)]
        self.assertEqual(assessment["verdict"], UNKNOWN)
        self.assertIn("no attacker path", assessment["reason"])

    def test_storage_configuration_is_unknown(self):
        self.assertEqual(self.by_key[("CKV_AWS_21", 23)]["verdict"], UNKNOWN)

    def test_no_iac_result_is_confirmed_even_with_internet_exposure(self):
        for item in assess_document(load_real(), PROJECT, exposure="internet"):
            self.assertNotEqual(item["assessment"]["verdict"], "CONFIRMED_EXPLOITABLE")
            self.assertNotEqual(item["assessment"]["verdict"], "NOT_EXPLOITABLE")

    def test_parse_error_and_counts_are_diagnostics(self):
        _, diagnostics = CheckovAdapter().parse(load_real(), {"target": "t"})
        self.assertTrue(any("terraform_plan" in d and "failed to parse" in d for d in diagnostics))
        self.assertTrue(any("terraform: 12 failed, 13 passed" in d for d in diagnostics))


class StaleAndPathCaseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.project = self.tmp / "project"
        shutil.copytree(PROJECT, self.project)

    def test_changed_source_makes_the_scan_stale_and_unknown(self):
        main = self.project / "main.tf"
        main.write_text(main.read_text(encoding="utf-8").replace(
            'cidr_blocks = ["0.0.0.0/0"]', 'cidr_blocks = ["10.1.0.0/16"]'), encoding="utf-8")
        assessed = by_rule_and_line(assess_document(load_real(), self.project))
        self.assertEqual(assessed[("CKV_AWS_24", 1)]["verdict"], UNKNOWN)
        self.assertIn("stale", assessed[("CKV_AWS_24", 1)]["reason"])

    def test_path_leaving_the_project_is_refused(self):
        document = load_real()
        document[0]["results"]["failed_checks"] = [
            dict(document[0]["results"]["failed_checks"][0], file_path="/../outside.tf")]
        (self.tmp / "outside.tf").write_text(
            'resource "x" "y" {\n  cidr_blocks = ["0.0.0.0/0"]\n}\n', encoding="utf-8")
        assessed = assess_document(document, self.project)
        self.assertEqual(assessed[0]["assessment"]["verdict"], UNKNOWN)
        self.assertIn("leaves the project", assessed[0]["assessment"]["reason"])

    def test_missing_file_is_unknown(self):
        (self.project / "main.tf").unlink()
        assessed = assess_document(load_real(), self.project)
        self.assertTrue(all(f["assessment"]["verdict"] == UNKNOWN for f in assessed))
        self.assertIn("not found", assessed[0]["assessment"]["reason"])


class CheckovAdapterTest(unittest.TestCase):
    def test_single_document_form_is_accepted(self):
        single = load_real()[0]
        self.assertTrue(CheckovAdapter().detect(single))
        findings, _ = CheckovAdapter().parse(single, {"target": "t"})
        self.assertEqual(len(findings), 12)

    def test_other_scanner_formats_are_not_detected(self):
        self.assertFalse(CheckovAdapter().detect({"results": [], "version": "1", "paths": {}}))
        self.assertFalse(CheckovAdapter().detect({"SchemaVersion": 2, "Results": []}))
        self.assertFalse(SemgrepAdapter().detect(load_real()))

    def test_failed_check_without_line_range_is_rejected_not_dropped(self):
        document = load_real()
        del document[0]["results"]["failed_checks"][0]["file_line_range"]
        with self.assertRaises(ModelError):
            CheckovAdapter().parse(document, {"target": "t"})

    def test_failed_check_without_path_is_rejected(self):
        document = load_real()
        document[0]["results"]["failed_checks"][0]["file_path"] = None
        with self.assertRaises(ModelError):
            CheckovAdapter().parse(document, {"target": "t"})


class IacEndToEndTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.out = self.tmp / "out"

    def test_run_writes_json_sarif_markdown_and_keeps_columns_out_of_sarif(self):
        summary = universal_run.run(REAL, PROJECT, self.out)
        self.assertEqual(summary["findings"], 12)
        self.assertEqual(summary["verdicts"]["POTENTIALLY_EXPLOITABLE"], 1)
        self.assertEqual(summary["adapters"], ["checkov"])

        sarif = json.loads((self.out / "universal.sarif").read_text(encoding="utf-8"))
        results = sarif["runs"][0]["results"]
        exposure = [r for r in results if r["ruleId"] == "CKV_AWS_24"][0]
        self.assertEqual(exposure["level"], "warning")
        region = exposure["locations"][0]["physicalLocation"]["region"]
        self.assertEqual(region, {"startLine": 1, "endLine": 10})
        self.assertTrue(all("reported by: checkov" in r["message"]["text"] for r in results))

        markdown = (self.out / "universal-report.md").read_text(encoding="utf-8")
        self.assertIn("| POTENTIALLY_EXPLOITABLE | MEDIUM | `CKV_AWS_24` | main.tf:1 |", markdown)
        self.assertIn("terraform_plan", markdown)

    def test_both_adapters_coexist_in_the_registry(self):
        registry = universal_run.build_registry()
        self.assertEqual(registry.detect_adapter(load_real()).name, "checkov")
        semgrep = json.loads((SAST_FIXTURES / "semgrep-1.183.0.real.json").read_text(encoding="utf-8"))
        self.assertEqual(registry.detect_adapter(semgrep).name, "semgrep")
        self.assertEqual(registry.engines(),
                         ["cicd-trigger-analysis", "iac-block-exposure", "sast-call-site"])


if __name__ == "__main__":
    unittest.main()
