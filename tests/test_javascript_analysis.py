"""JavaScript and TypeScript call-site analysis, checked against tests/fixtures/js-analysis-app. Each sink carries a
marker comment, so tests find the line they assess by its marker."""

import unittest
from pathlib import Path

from engine import sast
from engine.languages import analyzer_for, capability_report
from engine.languages.javascript import JavaScriptAnalyzer, analyse
from engine.universal import CONFIRMED, NOT_CONFIRMED, NOT_EXPLOITABLE, POTENTIALLY_EXPLOITABLE, UNKNOWN, make_finding

PROJECT = Path(__file__).parent / "fixtures" / "js-analysis-app"
JS = "routes/search.js"
TS = "routes/items.ts"


def source(path: str) -> bytes:
    return (PROJECT / path).read_bytes()


def line_of(path: str, marker: str) -> int:
    for number, text in enumerate(source(path).decode().splitlines(), 1):
        if f"// SINK:{marker}" in text:
            return number
    raise AssertionError(f"no marker {marker} in {path}")


def assess(path: str, marker: str, exposure: str = "unknown"):
    return JavaScriptAnalyzer().assess(source(path), {"path": path, "start_line": line_of(path, marker),
                                                      "start_col": None},
                                       engine="sast-call-site", exposure=exposure)


class JavaScriptCallSiteTest(unittest.TestCase):
    def test_a_request_query_reaching_the_sink_through_a_template_is_attacker_input(self):
        result = assess(JS, "tainted-local")
        self.assertEqual(result.conditions["attacker_influence"].status, CONFIRMED)
        self.assertEqual(result.verdict, POTENTIALLY_EXPLOITABLE)

    def test_an_express_handler_is_an_entry_point(self):
        result = assess(JS, "tainted-local")
        self.assertEqual(result.conditions["reachable"].status, CONFIRMED)
        self.assertIn('app.get("/search")', result.conditions["reachable"].evidence[0])

    def test_a_request_body_concatenated_directly_is_attacker_input(self):
        result = assess(JS, "concat-direct")
        self.assertEqual(result.conditions["attacker_influence"].status, CONFIRMED)

    def test_literal_arguments_are_not_exploitable_with_evidence(self):
        result = assess(JS, "constant")
        self.assertEqual(result.verdict, NOT_EXPLOITABLE)
        self.assertEqual(result.conditions["attacker_influence"].status, NOT_CONFIRMED)

    def test_a_clean_reassignment_removes_the_taint(self):
        result = assess(JS, "reassigned")
        self.assertNotEqual(result.conditions["attacker_influence"].status, CONFIRMED)
        self.assertEqual(result.verdict, UNKNOWN)

    def test_an_unrouted_function_is_not_reachable_and_its_argument_is_unknown(self):
        result = assess(JS, "unrouted")
        self.assertEqual(result.verdict, UNKNOWN)
        self.assertNotEqual(result.conditions["reachable"].status, CONFIRMED)

    def test_a_typescript_handler_with_an_annotated_request_is_handled(self):
        result = assess(TS, "typescript-template")
        self.assertEqual(result.conditions["attacker_influence"].status, CONFIRMED)
        self.assertEqual(result.conditions["reachable"].status, CONFIRMED)

    def test_no_verdict_is_confirmed_because_preconditions_are_not_modelled(self):
        for path, marker in ((JS, "tainted-local"), (JS, "concat-direct"), (TS, "typescript-template")):
            result = assess(path, marker, exposure="internet")
            self.assertNotEqual(result.verdict, "CONFIRMED_EXPLOITABLE", marker)
            self.assertEqual(result.conditions["preconditions"].status, "UNKNOWN", marker)

    def test_a_line_with_no_call_is_unknown_and_says_so(self):
        result = JavaScriptAnalyzer().assess(
            source(JS), {"path": JS, "start_line": 4, "start_col": None}, engine="sast-call-site", exposure="unknown")
        self.assertEqual(result.verdict, UNKNOWN)
        self.assertIn("no call expression starts at line 4", result.limitations[0])

    def test_a_column_that_matches_is_used(self):
        line = line_of(JS, "tainted-local")
        text = source(JS).decode().splitlines()[line - 1]
        self.assertEqual(analyse(source(JS), JS, line, text.index("db.query") + 1).match, "column")

    def test_a_column_that_does_not_match_falls_back_to_the_line(self):
        self.assertEqual(analyse(source(JS), JS, line_of(JS, "tainted-local"), 999).match, "line")


class JavaScriptRegistryTest(unittest.TestCase):
    def test_every_javascript_and_typescript_extension_resolves(self):
        for name in ("a.js", "a.jsx", "a.mjs", "a.cjs", "a.ts", "a.tsx"):
            self.assertEqual(analyzer_for(name).name, "javascript", name)

    def test_the_capability_report_lists_javascript_as_implemented_and_java_and_go_as_not(self):
        report = {record["language"]: record for record in capability_report()}
        self.assertEqual(report["javascript"]["status"], "IMPLEMENTED_NOT_EXTERNALLY_VERIFIED")
        self.assertEqual(report["java"]["status"], "NOT_IMPLEMENTED")
        self.assertEqual(report["go"]["status"], "NOT_IMPLEMENTED")
        self.assertEqual(report["javascript"]["test_corpus"], ["tests/fixtures/js-analysis-app"])


class JavaScriptThroughSastTest(unittest.TestCase):
    def test_a_javascript_finding_is_assessed_by_the_javascript_analyzer(self):
        line = line_of(JS, "tainted-local")
        finding = make_finding(category="SAST", rule_id="js.sink", title="rule",
                               asset={"type": "source_location", "name": JS},
                               location={"path": JS, "start_line": line, "end_line": line, "start_col": None,
                                         "end_col": None},
                               severity_reported="error", provenance={"scanner": "test"}, original={})
        finding["exploitability_context"]["exposure"] = "internet"
        result = sast.SastEngine().assess(finding, {"project_dir": PROJECT})
        self.assertEqual(result.engine, "sast-call-site")
        self.assertEqual(result.verdict, POTENTIALLY_EXPLOITABLE)


if __name__ == "__main__":
    unittest.main()
