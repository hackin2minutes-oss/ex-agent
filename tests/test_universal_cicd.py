"""Zizmor adapter and CI/CD engine, on real Zizmor output plus targeted workflow edits.

`tests/fixtures/cicd/zizmor-1.31.1.real.json` is `zizmor --offline --format json` output from
zizmor 1.31.1 on `tests/fixtures/cicd/project/.github/workflows`. Offline mode means the GitHub
API audits did not run. `risky.yml` is a deliberately unsafe workflow. `pinned.yml` is clean,
and Zizmor reports nothing for it.
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from engine import universal, universal_run
from engine.universal import NOT_EXPLOITABLE, POTENTIALLY_EXPLOITABLE, UNKNOWN
from engine.zizmor_adapter import ZizmorAdapter

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "cicd"
REAL = FIXTURES / "zizmor-1.31.1.real.json"
PROJECT = FIXTURES / "project"
RISKY = ".github/workflows/risky.yml"


def load_real():
    return json.loads(REAL.read_text(encoding="utf-8"))


def assess_document(document, project_dir):
    registry = universal_run.build_registry()
    findings, _ = ZizmorAdapter().parse(document, {"target": "test"})
    return universal.assess_all(findings, registry,
                                {"project_dir": Path(project_dir), "exposure": "unknown"})


def by_rule_and_line(assessed):
    return {(f["vulnerability"]["rule_id"], f["location"]["start_line"]): f["assessment"]
            for f in assessed}


class RealZizmorFixtureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.assessed = assess_document(load_real(), PROJECT)
        cls.by_key = by_rule_and_line(cls.assessed)

    def test_detects_real_output_and_converts_rows_to_lines(self):
        self.assertTrue(ZizmorAdapter().detect(load_real()))
        self.assertEqual(len(self.assessed), 4)
        # Zizmor row 15 (zero-based) is line 16 of risky.yml, where the title expression sits.
        self.assertIn(("template-injection", 16), self.by_key)

    def test_untrusted_title_in_shell_step_with_external_trigger_is_potentially_exploitable(self):
        assessment = self.by_key[("template-injection", 16)]
        self.assertEqual(assessment["verdict"], POTENTIALLY_EXPLOITABLE)
        self.assertTrue(any("pull_request_target" in e["detail"] for e in assessment["evidence"]))

    def test_pull_request_target_with_head_checkout_is_potentially_exploitable(self):
        assessment = self.by_key[("dangerous-triggers", 3)]
        self.assertEqual(assessment["verdict"], POTENTIALLY_EXPLOITABLE)
        self.assertIn("head", assessment["reason"])

    def test_hygiene_rules_are_unknown_not_safe(self):
        self.assertEqual(self.by_key[("unpinned-uses", 12)]["verdict"], UNKNOWN)
        self.assertEqual(self.by_key[("artipacked", 12)]["verdict"], UNKNOWN)

    def test_no_cicd_result_is_confirmed_even_with_internet_exposure(self):
        registry = universal_run.build_registry()
        for finding in assess_document(load_real(), PROJECT):
            self.assertNotEqual(finding["assessment"]["verdict"], "CONFIRMED_EXPLOITABLE")
        findings, _ = ZizmorAdapter().parse(load_real(), {"target": "t"})
        for finding in findings:
            finding["exploitability_context"]["exposure"] = "internet"
            result = universal.assess_finding(finding, registry,
                                              {"project_dir": PROJECT, "exposure": "internet"})
            self.assertNotEqual(result["verdict"], "CONFIRMED_EXPLOITABLE")


class EditedWorkflowTest(unittest.TestCase):
    """Edits keep the line count, so the scanner's line numbers still apply."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.project = self.tmp / "project"
        shutil.copytree(PROJECT, self.project)
        self.workflow = self.project / RISKY

    def edit(self, old, new):
        text = self.workflow.read_text(encoding="utf-8")
        self.assertIn(old, text)
        self.workflow.write_text(text.replace(old, new), encoding="utf-8")

    def test_writer_only_trigger_makes_template_injection_not_exploitable(self):
        self.edit("  pull_request_target:\n    types: [opened, synchronize]",
                  "  push:\n    branches: [main]")
        assessed = by_rule_and_line(assess_document(load_real(), self.project))
        assessment = assessed[("template-injection", 16)]
        self.assertEqual(assessment["verdict"], NOT_EXPLOITABLE)
        self.assertEqual(assessment["conditions"]["reachable"]["status"], "NOT_CONFIRMED")
        self.assertIn("writer-only", assessment["reason"])

    def test_checkout_of_base_ref_clears_dangerous_trigger_to_unknown(self):
        self.edit("          ref: ${{ github.event.pull_request.head.sha }}",
                  "          ref: ${{ github.sha }}")
        assessed = by_rule_and_line(assess_document(load_real(), self.project))
        self.assertEqual(assessed[("dangerous-triggers", 3)]["verdict"], UNKNOWN)
        self.assertIn("not an exploit path", assessed[("dangerous-triggers", 3)]["reason"])

    def test_changed_line_makes_the_scan_stale(self):
        self.edit('echo "Thanks ${{ github.event.pull_request.title }}"',
                  'echo "Thanks ${{ github.sha }}"')
        assessed = by_rule_and_line(assess_document(load_real(), self.project))
        assessment = assessed[("template-injection", 16)]
        self.assertEqual(assessment["verdict"], UNKNOWN)
        self.assertIn("stale", assessment["reason"])

    def test_unparseable_yaml_is_unknown(self):
        self.workflow.write_text("jobs: [unclosed\n", encoding="utf-8")
        assessed = assess_document(load_real(), self.project)
        self.assertTrue(all(f["assessment"]["verdict"] == UNKNOWN for f in assessed))

    def test_path_leaving_the_project_is_refused(self):
        document = load_real()
        document[0]["locations"][0]["symbolic"]["key"]["Local"]["verbatim_path"] = "../outside.yml"
        assessed = assess_document(document, self.project)
        self.assertEqual(assessed[0]["assessment"]["verdict"], UNKNOWN)
        self.assertIn("leaves the project", assessed[0]["assessment"]["reason"])


class ZizmorAdapterTest(unittest.TestCase):
    def test_empty_output_is_no_findings_not_an_error(self):
        findings, diagnostics = ZizmorAdapter().parse([], {"target": "t"})
        self.assertEqual(findings, [])
        self.assertEqual(diagnostics, ["zizmor reported no findings"])

    def test_suppressed_findings_are_counted_not_assessed(self):
        document = load_real()
        document[0]["ignored"] = True
        findings, diagnostics = ZizmorAdapter().parse(document, {"target": "t"})
        self.assertEqual(len(findings), 3)
        self.assertTrue(any("suppressed" in d for d in diagnostics))

    def test_finding_without_locations_is_rejected(self):
        document = load_real()
        document[0]["locations"] = []
        with self.assertRaises(universal.ModelError):
            ZizmorAdapter().parse(document, {"target": "t"})

    def test_other_formats_are_not_detected(self):
        self.assertFalse(ZizmorAdapter().detect({"results": []}))
        self.assertFalse(ZizmorAdapter().detect([{"SchemaVersion": 2}]))


class CicdEndToEndTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.out = self.tmp / "out"

    def test_run_writes_all_outputs(self):
        summary = universal_run.run(REAL, PROJECT, self.out)
        self.assertEqual(summary["findings"], 4)
        self.assertEqual(summary["verdicts"]["POTENTIALLY_EXPLOITABLE"], 2)
        self.assertEqual(summary["adapters"], ["zizmor"])
        sarif = json.loads((self.out / "universal.sarif").read_text(encoding="utf-8"))
        results = {r["ruleId"]: r for r in sarif["runs"][0]["results"]}
        self.assertEqual(results["template-injection"]["level"], "warning")
        self.assertEqual(results["unpinned-uses"]["level"], "note")
        markdown = (self.out / "universal-report.md").read_text(encoding="utf-8")
        self.assertIn("`template-injection`", markdown)


if __name__ == "__main__":
    unittest.main()
