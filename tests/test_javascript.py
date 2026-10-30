import json
import shutil
import tempfile
import unittest
from pathlib import Path

from engine import pipeline

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
VULNERABLE = ROOT / "tests" / "fixtures" / "js-app"
SAFE = ROOT / "tests" / "fixtures" / "js-app-safe"


class JavaScriptPipelineTest(unittest.TestCase):
    def run_app(self, project):
        out = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, out, ignore_errors=True)
        summary = pipeline.run(project, project / "package-lock.json", RULES, out, "confirmed_reachable",
                               offline=True, codeql_path="/nonexistent")
        findings = json.loads((out / "evidence.json").read_text())["findings"]
        return summary, findings

    def test_vulnerable_app_has_call_site_route_and_precondition(self):
        _, findings = self.run_app(VULNERABLE)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["vulnerability"]["cve"], "CVE-2019-10744")
        self.assertEqual(finding["dependency"]["version"], "4.17.11")
        call = next(e for e in finding["evidence"] if e["type"] == "call_site")
        self.assertEqual(call["locations"][0]["file"], "app.js")
        self.assertEqual(call["locations"][0]["line"], 10)
        entry = next(e for e in finding["evidence"] if e["type"] == "entry_point")
        self.assertEqual(entry["routes"][0]["route"], "/settings")
        self.assertEqual(finding["preconditions"], "satisfied")
        # Lexical call site only: reachability stays UNKNOWN without CodeQL.
        self.assertEqual(finding["classification"], "vulnerable_component_only")

    def test_safe_app_has_no_call_site(self):
        _, findings = self.run_app(SAFE)
        finding = findings[0]
        call = next(e for e in finding["evidence"] if e["type"] == "call_site")
        self.assertEqual(call["locations"], [])
        self.assertEqual(finding["preconditions"], "unverified")

    def test_lodash_fixed_version_is_not_a_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "app"
            shutil.copytree(VULNERABLE, project)
            lock = json.loads((project / "package-lock.json").read_text())
            lock["packages"]["node_modules/lodash"]["version"] = "4.17.12"
            (project / "package-lock.json").write_text(json.dumps(lock))
            summary, findings = self.run_app(project)
            self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
