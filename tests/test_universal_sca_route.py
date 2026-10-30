"""The SCA route: Trivy vulnerability and OSV-Scanner reports run through the existing SCA pipeline and
are projected onto the universal model. Several reports can be given in one run.

Real inputs:
- tests/fixtures/scanner-exports/trivy-fs-python-app.real.json: `trivy fs --scanners vuln --format json`
  (Trivy 0.58.1, vulnerability database from the public mirror) on tests/fixtures/python-app.
- tests/fixtures/scanner-exports/osv-python-app.real.json: OSV-Scanner export of the same project.
The project is shared by every report in one run, so the SAST report used here is not paired with it.
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from engine import pipeline, universal_run
from engine.universal import ModelError

ROOT = Path(__file__).resolve().parent.parent
TRIVY = ROOT / "tests" / "fixtures" / "scanner-exports" / "trivy-fs-python-app.real.json"
OSV = ROOT / "tests" / "fixtures" / "scanner-exports" / "osv-python-app.real.json"
GRYPE = ROOT / "tests" / "fixtures" / "scanner-exports" / "grype-python-app.real.json"
PROJECT = ROOT / "tests" / "fixtures" / "python-app"
SEMGREP = ROOT / "tests" / "fixtures" / "sast" / "semgrep-1.183.0.real.json"


class ScaRouteTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def run_case(self, inputs, out="out"):
        return universal_run.run(inputs, PROJECT, self.tmp / out, offline=True)

    def findings(self, out="out"):
        return json.loads((self.tmp / out / "universal-findings.json").read_text(encoding="utf-8"))["findings"]

    def test_trivy_report_runs_through_the_sca_pipeline(self):
        summary = self.run_case([TRIVY])
        self.assertEqual(summary["inputs"], [{"input": TRIVY.name, "route": "sca", "records": 3}])
        self.assertIn("sca-pipeline", summary["adapters"])
        self.assertTrue((self.tmp / "out" / "sca" / "evidence.json").exists())
        findings = self.findings()
        self.assertEqual({f["vulnerability"]["rule_id"] for f in findings},
                         {"CVE-2017-18342", "CVE-2026-27205", "CVE-2020-14343"})
        for finding in findings:
            self.assertEqual(finding["category"], "SCA")
            self.assertEqual(finding["asset"]["type"], "dependency")
            self.assertIn(finding["asset"]["name"], ("pyyaml@5.0.0", "flask@2.3.2"))
            self.assertEqual(finding["assessment"]["engine"], "sca-legacy-projection")
            self.assertIn(finding["assessment"]["verdict"], ("UNKNOWN",))

    def test_same_vulnerability_from_two_scanners_is_one_finding_with_both_sources(self):
        self.run_case([TRIVY, OSV])
        findings = self.findings()
        self.assertEqual(len(findings), 3)
        for finding in findings:
            self.assertEqual([s["scanner"] for s in finding["sources"]], ["trivy", "osv-scanner"])

    def test_grype_report_runs_through_the_sca_route(self):
        summary = self.run_case([GRYPE])
        self.assertEqual(summary["inputs"], [{"input": GRYPE.name, "route": "sca", "records": 3}])
        findings = self.findings()
        # The rule is the CVE. The GHSA identifiers Grype reported are kept among the identifiers.
        self.assertEqual({f["vulnerability"]["rule_id"] for f in findings},
                         {"CVE-2017-18342", "CVE-2020-14343", "CVE-2026-27205"})
        self.assertTrue(all(any(i.startswith("GHSA-") for i in f["vulnerability"]["ids"]) for f in findings))

    def test_three_scanners_on_one_vulnerability_keep_all_three_sources(self):
        self.run_case([GRYPE, TRIVY, OSV])
        findings = self.findings()
        self.assertEqual(len(findings), 3)
        for finding in findings:
            self.assertEqual(sorted(s["scanner"] for s in finding["sources"]), ["grype", "osv-scanner", "trivy"])

    def test_one_failing_sca_analysis_is_reported_and_does_not_stop_other_reports(self):
        with mock.patch.object(pipeline, "run", side_effect=OSError("advisory service unreachable")):
            summary = self.run_case([TRIVY, SEMGREP])
        findings = self.findings()
        sca = [f for f in findings if f["category"] == "SCA"]
        sast = [f for f in findings if f["category"] == "SAST"]
        self.assertEqual(len(sca), 3)
        for finding in sca:
            self.assertEqual(finding["assessment"]["verdict"], "ANALYSIS_INCOMPLETE")
            self.assertIn("advisory service unreachable", finding["assessment"]["reason"])
        self.assertTrue(sast, "the SAST report must still be assessed")
        self.assertTrue(any("SCA analysis failed" in d for d in summary["diagnostics"]))

    def test_unreadable_report_is_skipped_with_a_diagnostic(self):
        bad = self.tmp / "bad.json"
        bad.write_text("not json", encoding="utf-8")
        summary = self.run_case([bad, TRIVY])
        self.assertEqual(summary["inputs"][0]["route"], "skipped")
        self.assertEqual(summary["inputs"][1]["route"], "sca")
        self.assertTrue(any("skipped bad.json" in d for d in summary["diagnostics"]))

    def test_no_usable_report_is_refused(self):
        bad = self.tmp / "bad.json"
        bad.write_text("not json", encoding="utf-8")
        with self.assertRaises(ModelError):
            self.run_case([bad])

    def test_repeated_runs_give_identical_findings(self):
        self.run_case([TRIVY, OSV], out="first")
        self.run_case([TRIVY, OSV], out="second")
        first = json.loads((self.tmp / "first" / "universal-findings.json").read_text(encoding="utf-8"))
        second = json.loads((self.tmp / "second" / "universal-findings.json").read_text(encoding="utf-8"))
        self.assertEqual(first["findings"], second["findings"])

    def test_sarif_for_sca_findings_is_valid_and_keeps_reporters(self):
        self.run_case([TRIVY, OSV])
        sarif = json.loads((self.tmp / "out" / "universal.sarif").read_text(encoding="utf-8"))
        results = sarif["runs"][0]["results"]
        self.assertEqual(len(results), 3)
        for result in results:
            self.assertIn("reported by: trivy", result["message"]["text"])


if __name__ == "__main__":
    unittest.main()
