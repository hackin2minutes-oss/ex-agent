import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from engine import pipeline, versions

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
VULNERABLE = ROOT / "tests" / "fixtures" / "go-app"
SAFE = ROOT / "tests" / "fixtures" / "go-app-safe"


class GoVersionTest(unittest.TestCase):
    def test_release_versions_compare_with_leading_v(self):
        self.assertEqual(versions.compare("Go", "v1.10.0", "v1.9.1"), 1)
        self.assertTrue(versions.is_affected("Go", "v1.8.1", "0.0.0", "1.9.1"))
        self.assertFalse(versions.is_affected("Go", "v1.9.1", "0.0.0", "1.9.1"))

    def test_pseudo_versions_are_unsupported(self):
        self.assertIsNone(versions.compare("Go", "v1.3.1-0.20190301021747-ccb9e902956d", "v1.9.1"))


class GoPipelineTest(unittest.TestCase):
    def run_app(self, project):
        out = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, out, ignore_errors=True)
        pipeline.run(project, project / "go.sum", RULES, out, "confirmed_reachable",
                     offline=True, codeql_path="/nonexistent")
        return json.loads((out / "evidence.json").read_text())["findings"]

    def test_vulnerable_app_matches_the_advisory(self):
        findings = self.run_app(VULNERABLE)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["vulnerability"]["cve"], "CVE-2023-29401")
        self.assertEqual(finding["dependency"]["version"], "v1.8.1")
        call = next(e for e in finding["evidence"] if e["type"] == "call_site")
        self.assertEqual((call["locations"][0]["file"], call["locations"][0]["line"]), ("main.go", 9))
        self.assertEqual(finding["classification"], "vulnerable_component_only")

    def test_safe_app_has_a_call_but_no_request_input_is_claimed(self):
        findings = self.run_app(SAFE)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["vulnerability"]["cve"], "CVE-2023-29401")

    def test_gin_route_is_an_entry_point(self):
        findings = self.run_app(VULNERABLE)
        entry = next(e for e in findings[0]["evidence"] if e["type"] == "entry_point")
        self.assertEqual(entry["routes"][0]["route"], "/download")

    def test_rule_regex_matches_the_vulnerable_call(self):
        rule = json.loads((RULES / "CVE-2023-29401.json").read_text())
        pattern = rule["preconditions"][0]["regex"]
        self.assertRegex((VULNERABLE / "main.go").read_text(), re.compile(pattern))


if __name__ == "__main__":
    unittest.main()
