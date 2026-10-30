import json
import shutil
import tempfile
import unittest
from pathlib import Path

from engine import intel as intel_module, pipeline

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "app"
RULES = ROOT / "rules"
NO_CODEQL = "/nonexistent/codeql"  # forces the text-scan path, so results do not depend on the host


class PipelineTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def run_pipeline(self, project, deps, rules=RULES, **kwargs):
        out = self.tmp / "report"
        summary = pipeline.run(project, deps, rules, out, kwargs.pop("fail_on", "confirmed_reachable"),
                               offline=True, codeql_path=NO_CODEQL, **kwargs)
        return summary, out


class FixturePipelineTest(PipelineTestCase):
    def test_fixture_text_scan_is_component_only_with_full_evidence(self):
        summary, out = self.run_pipeline(FIXTURE, FIXTURE / "resolved-deps.json")
        finding = json.loads((out / "evidence.json").read_text())["findings"][0]

        # A lexical call-site match is not call-graph reachability, so the stage stays UNKNOWN.
        self.assertEqual(finding["reachability"], "potentially")
        self.assertEqual(finding["preconditions"], "unverified")
        self.assertEqual(finding["classification"], "vulnerable_component_only")
        self.assertEqual(finding["stages"]["E_function_reachability"], "UNKNOWN")
        self.assertEqual(finding["verdict"], "unknown")
        self.assertEqual(finding["scope"]["analysis_mode"], "text_scan")

        call = next(e for e in finding["evidence"] if e["type"] == "call_site")
        self.assertEqual(call["locations"][0]["file"], "src/main/java/com/example/app/Handler.java")
        self.assertEqual(call["locations"][0]["line"], 7)

        taint = next(e for e in finding["evidence"] if e["type"] == "taint_path")
        self.assertEqual(taint["result"], "not_analysed")

        self.assertEqual(summary["intel"]["osv"], "skipped: offline")
        self.assertFalse(summary["gate_failed"])

    def test_all_output_files_are_written(self):
        _, out = self.run_pipeline(FIXTURE, FIXTURE / "resolved-deps.json")
        for name in ["evidence.json", "summary.json", "findings.sarif", "call-graph.json", "report.md"]:
            self.assertTrue((out / name).is_file(), name)
        sarif = json.loads((out / "findings.sarif").read_text())
        self.assertEqual(sarif["version"], "2.1.0")

    def test_no_call_site_is_unknown_not_not_reachable(self):
        project = self.tmp / "app"
        shutil.copytree(FIXTURE, project)
        handler = project / "src/main/java/com/example/app/Handler.java"
        handler.write_text(handler.read_text().replace("Parser.parse(input)", "input"))

        _, out = self.run_pipeline(project, FIXTURE / "resolved-deps.json")
        finding = json.loads((out / "evidence.json").read_text())["findings"][0]
        self.assertEqual(finding["reachability"], "unknown")
        self.assertEqual(finding["verdict"], "unknown")

    def test_fixed_version_produces_no_finding(self):
        deps = self.tmp / "deps.json"
        data = json.loads((FIXTURE / "resolved-deps.json").read_text())
        data["dependencies"][0]["version"] = "2.4.1"
        deps.write_text(json.dumps(data))
        summary, _ = self.run_pipeline(FIXTURE, deps)
        self.assertEqual(summary["findings"], 0)

    def test_absent_dependency_produces_no_finding(self):
        deps = self.tmp / "deps.json"
        deps.write_text(json.dumps({"dependencies": []}))
        summary, _ = self.run_pipeline(FIXTURE, deps)
        self.assertEqual(summary["findings"], 0)

    def test_test_scope_is_excluded(self):
        deps = self.tmp / "deps.json"
        data = json.loads((FIXTURE / "resolved-deps.json").read_text())
        data["dependencies"][0]["scope"] = "test"
        deps.write_text(json.dumps(data))
        summary, _ = self.run_pipeline(FIXTURE, deps)
        self.assertEqual(summary["findings"], 0)


class PolicyGateTest(PipelineTestCase):
    """The policy file decides the gate when one is supplied."""

    def write_policy(self, text):
        path = self.tmp / "policy.yml"
        path.write_text(text)
        return path

    def test_policy_that_blocks_component_only_fails_the_gate(self):
        policy_file = self.write_policy(
            "version: 1\nexploitability:\n  vulnerable_component_only:\n    action: block\n")
        summary, out = self.run_pipeline(FIXTURE, FIXTURE / "resolved-deps.json", policy_path=policy_file)
        self.assertTrue(summary["gate_failed"])
        self.assertEqual(summary["policy"]["decisions"]["block"], 1)
        finding = json.loads((out / "evidence.json").read_text())["findings"][0]
        self.assertEqual(finding["policy"]["action"], "block")

    def test_policy_that_reports_component_only_passes_the_gate(self):
        policy_file = self.write_policy(
            "version: 1\nexploitability:\n  vulnerable_component_only:\n    action: report\n")
        summary, _ = self.run_pipeline(FIXTURE, FIXTURE / "resolved-deps.json", policy_path=policy_file)
        self.assertFalse(summary["gate_failed"])

    def test_invalid_policy_stops_the_run(self):
        from engine.policy import PolicyError
        policy_file = self.write_policy("version: 1\nexploitability:\n  confirmed_exploitabel:\n    action: block\n")
        with self.assertRaises(PolicyError):
            self.run_pipeline(FIXTURE, FIXTURE / "resolved-deps.json", policy_path=policy_file)


class OsvDrivenPipelineTest(PipelineTestCase):
    """A dependency with no curated rule: advisory from OSV, symbols derived from the fix commit."""

    def setUp(self):
        super().setUp()
        self.project = self.tmp / "app"
        (self.project / "src/main/java/app").mkdir(parents=True)
        (self.project / "src/main/java/app/Handler.java").write_text(
            "package app;\nimport com.acme.Parser;\n"
            "public class Handler {\n"
            "  Object handle(String input) { return Parser.parse(input); }\n}\n")
        self.deps = self.tmp / "deps.json"
        self.deps.write_text(json.dumps({"dependencies": [{
            "ecosystem": "Maven", "name": "com.acme:lib", "version": "1.0.0", "scope": "runtime"}]}))
        self.fix_diffs = self.tmp / "diffs"
        self.fix_diffs.mkdir()
        (self.fix_diffs / "abc123.diff").write_text(
            "+++ b/src/main/java/com/acme/Parser.java\n"
            "-    public Object parse(String input) {\n"
            "+    public Object parse(String input, boolean strict) {\n")

    def fake_intel(self, osv_vulns):
        def fetch(url, body=None):
            if url == intel_module.OSV_URL:
                return json.dumps({"vulns": osv_vulns}).encode()
            if url.startswith(intel_module.EPSS_URL):
                return json.dumps({"data": [{"cve": "CVE-2099-0001", "epss": "0.42"}]}).encode()
            if url == intel_module.KEV_URL:
                return json.dumps({"vulnerabilities": [{"cveID": "CVE-2099-0001"}]}).encode()
            raise OSError(f"unexpected {url}")
        return intel_module.Intel(fetch=fetch)

    def osv_vuln(self):
        return {
            "id": "GHSA-aaaa-bbbb-cccc",
            "aliases": ["CVE-2099-0001"],
            "summary": "Unsafe parsing",
            "references": [{"type": "FIX", "url": "https://github.com/acme/lib/commit/abc123"}],
        }

    def test_advisory_symbols_enrichment_and_verdict(self):
        summary, out = self.run_pipeline(
            self.project, self.deps, rules=self.tmp / "no-rules", fix_diffs_dir=self.fix_diffs,
            intel=self.fake_intel([self.osv_vuln()]))
        finding = json.loads((out / "evidence.json").read_text())["findings"][0]

        self.assertEqual(finding["vulnerability"]["cve"], "CVE-2099-0001")
        self.assertEqual(finding["vulnerability"]["epss"], 0.42)
        self.assertTrue(finding["vulnerability"]["kev"])
        symbols = next(e for e in finding["evidence"] if e["type"] == "vulnerable_symbols")
        self.assertEqual(symbols["detail"], ["com.acme.Parser.parse"])
        self.assertIn("fix-commit", symbols["source"])
        self.assertEqual(finding["stages"]["L_threat_intelligence"], "CONFIRMED")
        self.assertEqual(finding["classification"], "vulnerable_component_only")
        self.assertEqual(summary["findings"], 1)

    def test_no_symbols_means_unknown(self):
        vuln = self.osv_vuln()
        vuln["references"] = []
        _, out = self.run_pipeline(
            self.project, self.deps, rules=self.tmp / "no-rules", fix_diffs_dir=self.fix_diffs,
            intel=self.fake_intel([vuln]))
        finding = json.loads((out / "evidence.json").read_text())["findings"][0]
        self.assertEqual(finding["reachability"], "unknown")

    def test_unavailable_osv_is_reported_in_summary(self):
        def failing(url, body=None):
            raise ConnectionError("gateway answered 403")
        summary, _ = self.run_pipeline(
            self.project, self.deps, rules=self.tmp / "no-rules",
            intel=intel_module.Intel(fetch=failing))
        self.assertEqual(summary["findings"], 0)
        self.assertTrue(summary["intel"]["osv"].startswith("unavailable"))

    def test_run_without_offline_flag_uses_injected_intel(self):
        summary = pipeline.run(self.project, self.deps, self.tmp / "no-rules", self.tmp / "out", "confirmed_reachable",
                               codeql_path=NO_CODEQL, fix_diffs_dir=self.fix_diffs,
                               intel=self.fake_intel([self.osv_vuln()]))
        self.assertEqual(summary["findings"], 1)


if __name__ == "__main__":
    unittest.main()
