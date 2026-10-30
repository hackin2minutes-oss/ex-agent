"""End-to-end: an imported scanner finding reaches the final JSON and SARIF reports.

Two inputs, reported separately:
- synthetic: tests/fixtures/scanner-exports/trivy-python-app.synthetic.json, written by hand in
  Trivy's documented JSON shape. It is not a Trivy output.
- real: tests/fixtures/scanner-exports/osv-python-app.real.json, an OSV-scanner 2.7.0 export.

The verdicts come from the analysis, not from the scanner. These tests check that imported
findings reach the report, with their source, and do not change dependency discovery.
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from engine import findings, pipeline
from tests.support import combined_rules_dir

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "tests" / "fixtures" / "python-app"
EXPORTS = ROOT / "tests" / "fixtures" / "scanner-exports"


def run_with(imported_file: Path | None, output: Path) -> dict:
    imported = None
    if imported_file is not None:
        detected = findings.detect(imported_file.read_text(encoding="utf-8"))
        imported = findings.merge_findings(detected[1])
    return pipeline.run(APP, APP / "requirements.txt", combined_rules_dir(), output, "confirmed_reachable",
                        offline=True, codeql_path="/nonexistent", exposure="internet",
                        imported_findings=imported)


class EndToEndTest(unittest.TestCase):
    def setUp(self):
        self.out = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.out, ignore_errors=True)

    def test_synthetic_trivy_finding_reaches_json_and_sarif(self):
        summary = run_with(EXPORTS / "trivy-python-app.synthetic.json", self.out)
        evidence = json.loads((self.out / "evidence.json").read_text())
        cves = {f["vulnerability"]["cve"]: f for f in evidence["findings"]}
        self.assertIn("CVE-2017-18342", cves)
        scanners = [s["scanner"] for s in cves["CVE-2017-18342"]["vulnerability"]["scanner_sources"]]
        self.assertEqual(scanners, ["trivy"])
        sarif = json.loads((self.out / "findings.sarif").read_text())
        texts = [r["message"]["text"] for r in sarif["runs"][0]["results"]]
        self.assertTrue(any("[reported by: trivy]" in t for t in texts))
        self.assertGreaterEqual(summary["findings"], 1)

    def test_real_osv_export_reaches_the_report_with_its_source(self):
        run_with(EXPORTS / "osv-python-app.real.json", self.out)
        evidence = json.loads((self.out / "evidence.json").read_text())
        pyyaml = [f for f in evidence["findings"] if f["library"] == "pyyaml"]
        self.assertTrue(pyyaml)
        for f in pyyaml:
            self.assertEqual({s["scanner"] for s in f["vulnerability"]["scanner_sources"]}, {"osv-scanner"})
        sarif = json.loads((self.out / "findings.sarif").read_text())
        self.assertTrue(any("[reported by: osv-scanner]" in r["message"]["text"]
                            for r in sarif["runs"][0]["results"]))

    def test_without_imported_findings_the_report_has_no_scanner_source(self):
        run_with(None, self.out)
        evidence = json.loads((self.out / "evidence.json").read_text())
        for f in evidence["findings"]:
            self.assertEqual(f["vulnerability"].get("scanner_sources", []), [])
        sarif = json.loads((self.out / "findings.sarif").read_text())
        self.assertFalse(any("reported by" in r["message"]["text"] for r in sarif["runs"][0]["results"]))

    def test_discovery_still_finds_the_curated_rule_without_a_scanner(self):
        run_with(None, self.out)
        evidence = json.loads((self.out / "evidence.json").read_text())
        self.assertTrue(any(f["vulnerability"]["cve"] == "CVE-2017-18342" for f in evidence["findings"]))

    def test_unknown_ecosystem_is_counted_in_the_notes_not_analysed(self):
        doc = json.dumps({"Results": [{"Target": "os", "Type": "debian", "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2020-9999", "PkgName": "libx", "InstalledVersion": "1.0"}]}]})
        path = self.out / "debian.json"
        path.write_text(doc)
        summary = run_with(path, self.out)
        self.assertTrue(any("skipped" in n for n in summary["notes"]))
        evidence = json.loads((self.out / "evidence.json").read_text())
        self.assertFalse(any(f["library"] == "libx" for f in evidence["findings"]))

    def test_summary_json_carries_the_analysis_block(self):
        run_with(EXPORTS / "trivy-python-app.synthetic.json", self.out)
        summary = json.loads((self.out / "summary.json").read_text())
        self.assertIn("bounded_analysis_complete", summary["analysis"])


if __name__ == "__main__":
    unittest.main()
