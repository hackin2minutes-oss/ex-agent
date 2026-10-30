import json

import tempfile
import unittest
from pathlib import Path

from engine import codeql, report, verdict

TEMPLATE_ROOT = codeql.TEMPLATES_DIR


class CodeqlTemplateTest(unittest.TestCase):
    def test_split_symbol(self):
        self.assertEqual(codeql.split_symbol("com.example.Parser.parse"),
                         ("com.example", "Parser", "parse"))

    def test_rendered_pack_has_no_placeholders_and_names_the_method(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = codeql.render_pack(Path(tmp) / "pack", "com.example.Parser.parse")
            call = paths["call_site"].read_text()
            taint = paths["taint"].read_text()
            self.assertNotIn("{{", call)
            self.assertNotIn("{{", taint)
            self.assertIn('hasQualifiedName("com.example", "Parser")', call)
            self.assertIn('hasName("parse")', taint)
            self.assertTrue((Path(tmp) / "pack" / "qlpack.yml").is_file())

    def test_templates_exist(self):
        self.assertTrue((TEMPLATE_ROOT / "call_site.ql.tmpl").is_file())
        self.assertTrue((TEMPLATE_ROOT / "taint.ql.tmpl").is_file())


class SarifParseTest(unittest.TestCase):
    def test_parses_locations_relative_to_project(self):
        sarif = {"runs": [{"results": [{
            "message": {"text": "Calls Parser.parse"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "/work/app/src/Handler.java"},
                "region": {"startLine": 7}}}],
        }]}]}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.sarif"
            path.write_text(json.dumps(sarif))
            results = codeql.parse_sarif(path, Path("/work/app"))
        self.assertEqual(results, [{"file": "src/Handler.java", "line": 7,
                                    "message": "Calls Parser.parse"}])


FINDING = {
    "id": "CVE-XXXX-XXXX@com.example:lib:2.4.0",
    "vulnerability": {"id": "CVE-XXXX-XXXX", "cve": "CVE-XXXX-XXXX", "summary": "s",
                      "epss": None, "kev": None},
    "library": "com.example:lib",
    "dependency": {"version": "2.4.0", "manifest": "pom.xml"},
    "reachability": "potentially",
    "preconditions": "unverified",
    "verdict": "potentially_exploitable",
    "confidence": "medium",
    "evidence": [
        {"type": "call_site", "result": "confirmed",
         "locations": [{"file": "src/Handler.java", "line": 7, "text": "x"}]},
        {"type": "entry_point", "result": "present_unlinked",
         "routes": [{"file": "src/Api.java", "line": 11, "kind": "POST", "route": "/parse"}]},
        {"type": "taint_path", "result": "confirmed", "locations": [
            {"file": "src/Api.java", "line": 13, "source": "src/Api.java:13",
             "sink": "src/Handler.java:7", "message": "flow"}]},
    ],
}
SUMMARY = {"analysis_mode": "text_scan", "fail_on": "confirmed_reachable", "gate_failed": False,
           "intel": {"osv": "skipped: offline"}}


class ReportTest(unittest.TestCase):
    def test_sarif_structure_and_level(self):
        sarif = report.to_sarif([FINDING], "0.1.0")
        self.assertEqual(sarif["version"], "2.1.0")
        result = sarif["runs"][0]["results"][0]
        self.assertEqual(result["level"], "warning")
        self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                         "src/Handler.java")

    def test_call_graph_draws_only_evidenced_edges(self):
        graph = report.call_graph([FINDING])
        self.assertEqual(len(graph["edges"]), 1)
        self.assertTrue(graph["edges"][0]["proven"])
        kinds = {n["kind"] for n in graph["nodes"]}
        self.assertEqual(kinds, {"entry_point", "vulnerable_call"})

    def test_markdown_lists_classification_and_scope_caveat(self):
        finding = dict(FINDING, classification="reachable_preconditions_unknown",
                       policy={"action": "warn", "rule": "x"})
        text = report.summary_markdown(SUMMARY, [finding])
        self.assertIn("`reachable_preconditions_unknown`", text)
        self.assertIn("`warn`", text)
        self.assertIn("does not mean the CVE is harmless", text)

    def test_no_findings_message(self):
        self.assertIn("No vulnerable dependency", report.summary_markdown(SUMMARY, []))

    def test_pr_comment_skipped_for_forks(self):
        with tempfile.TemporaryDirectory() as tmp:
            event = Path(tmp) / "event.json"
            event.write_text(json.dumps({"pull_request": {"number": 5, "head": {"repo": {
                "full_name": "someone/fork"}}}}))
            env = {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_EVENT_PATH": str(event),
                   "GITHUB_REPOSITORY": "org/app"}
            self.assertIsNone(report.pr_number_if_postable(env))
            env["GITHUB_REPOSITORY"] = "someone/fork"
            self.assertEqual(report.pr_number_if_postable(env), 5)

    def test_pr_comment_request_uses_bearer_token(self):
        captured = {}

        class Response:
            status = 201

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def opener(request, timeout):
            captured["url"] = request.full_url
            captured["auth"] = request.get_header("Authorization")
            return Response()

        env = {"GITHUB_REPOSITORY": "org/app", "GITHUB_TOKEN": "t0k"}
        status = report.post_pr_comment("hello", 9, env=env, opener=opener)
        self.assertEqual(status, 201)
        self.assertEqual(captured["url"], "https://api.github.com/repos/org/app/issues/9/comments")
        self.assertEqual(captured["auth"], "Bearer t0k")


class VerdictGateTest(unittest.TestCase):
    def test_confirmed_exploitable_gate(self):
        self.assertFalse(verdict.gate_failed("confirmed_exploitable", "confirmed", "potentially_exploitable"))
        self.assertTrue(verdict.gate_failed("confirmed_exploitable", "confirmed", "confirmed_exploitable"))

    def test_unknown_gate_value_is_rejected(self):
        with self.assertRaises(ValueError):
            verdict.gate_failed("everything", "confirmed", "confirmed_exploitable")


if __name__ == "__main__":
    unittest.main()
