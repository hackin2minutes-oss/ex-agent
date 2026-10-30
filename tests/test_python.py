import json
import shutil
import tempfile
import unittest
from pathlib import Path

from engine import callsites, context, pipeline

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
VULNERABLE = ROOT / "tests" / "fixtures" / "python-app"
SAFE = ROOT / "tests" / "fixtures" / "python-app-safe"
NO_CODEQL = "/nonexistent/codeql"


class PythonCallSiteTest(unittest.TestCase):
    def test_finds_unsafe_yaml_load_call(self):
        hits = callsites.scan_call_sites(VULNERABLE, "yaml.load", "python")
        self.assertEqual([(h["file"], h["line"]) for h in hits], [("app/views.py", 11)])

    def test_safe_loader_is_not_a_load_call(self):
        self.assertEqual(callsites.scan_call_sites(SAFE, "yaml.load", "python"), [])

    def test_requires_import_of_the_module(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "x.py").write_text("def f(yaml):\n    return yaml.load(data)\n")
            self.assertEqual(callsites.scan_call_sites(Path(tmp), "yaml.load", "python"), [])

    def test_python_reflection_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "x.py").write_text("def f(s):\n    return eval(s)\n")
            self.assertEqual(len(callsites.reflection_indicators(Path(tmp))), 1)


class PythonEntryPointTest(unittest.TestCase):
    def test_flask_route_is_found(self):
        routes = context.find_python_entry_points(VULNERABLE)
        self.assertEqual(routes, [{"file": "app/views.py", "line": 7, "kind": "ROUTE", "route": "/config"}])

    def test_no_routes_without_a_web_framework(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "x.py").write_text("@app.route('/x')\ndef f():\n    pass\n")
            self.assertEqual(context.find_python_entry_points(Path(tmp)), [])


class PythonPipelineTest(unittest.TestCase):
    def run_app(self, project):
        out = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, out, ignore_errors=True)
        summary = pipeline.run(project, project / "requirements.txt", RULES, out, "confirmed_reachable",
                               offline=True, codeql_path=NO_CODEQL)
        finding = json.loads((out / "evidence.json").read_text())["findings"][0]
        return summary, finding

    def test_vulnerable_app_is_component_only_without_codeql(self):
        summary, finding = self.run_app(VULNERABLE)
        self.assertEqual(finding["vulnerability"]["cve"], "CVE-2017-18342")
        self.assertEqual(finding["dependency"]["version"], "5.0.0")
        self.assertEqual(finding["classification"], "vulnerable_component_only")
        # The unsafe call matches 'requires'; no mitigation is found, but absence is not proof, so the aggregate is unverified.
        self.assertEqual(finding["preconditions"], "unverified")
        self.assertEqual(finding["stages"]["H_preconditions"], "UNKNOWN")
        call = next(e for e in finding["evidence"] if e["type"] == "call_site")
        self.assertEqual(call["locations"][0]["file"], "app/views.py")
        self.assertFalse(summary["gate_failed"])

    def test_safe_app_has_its_mitigation_recognised(self):
        _, finding = self.run_app(SAFE)
        # yaml.safe_load() is present, so the precondition is positively not met.
        self.assertEqual(finding["preconditions"], "not_satisfied")
        self.assertEqual(finding["stages"]["H_preconditions"], "NOT_CONFIRMED")
        self.assertEqual(finding["classification"], "vulnerable_component_only")


if __name__ == "__main__":
    unittest.main()
