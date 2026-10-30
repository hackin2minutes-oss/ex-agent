"""C# call-site analysis, checked against tests/fixtures/csharp-app. Each sink in the fixture carries a marker comment,
so the tests find the line they assess by its marker rather than by a hard-coded number."""

import unittest
from pathlib import Path

from engine import sast
from engine.languages import capability_report, analyzer_for
from engine.languages.csharp import analyse, assess_call
from engine.universal import (
    CONFIRMED, NOT_CONFIRMED, NOT_EXPLOITABLE, POTENTIALLY_EXPLOITABLE, UNKNOWN, make_finding,
)

PROJECT = Path(__file__).parent / "fixtures" / "csharp-app"
FILE = "Controllers/SearchController.cs"
SOURCE = (PROJECT / FILE).read_bytes()


def line_of(marker: str) -> int:
    for number, text in enumerate(SOURCE.decode().splitlines(), 1):
        if f"// SINK:{marker}" in text:
            return number
    raise AssertionError(f"no sink marker {marker}")


def assess(marker: str, exposure: str = "unknown"):
    return assess_call(SOURCE, {"path": FILE, "start_line": line_of(marker), "start_col": None},
                       engine="sast-call-site", exposure=exposure)


class CSharpCallSiteTest(unittest.TestCase):
    def test_a_request_parameter_reaching_the_sink_through_a_local_is_attacker_input(self):
        result = assess("tainted-local")
        self.assertEqual(result.verdict, POTENTIALLY_EXPLOITABLE)
        self.assertEqual(result.conditions["attacker_influence"].status, CONFIRMED)
        self.assertIn("parameter term bound from the request", result.conditions["attacker_influence"].evidence[0])

    def test_a_route_attribute_makes_the_method_an_entry_point(self):
        result = assess("tainted-local")
        self.assertEqual(result.conditions["reachable"].status, CONFIRMED)
        self.assertIn("HttpGet", result.conditions["reachable"].evidence[0])

    def test_a_direct_request_member_is_attacker_input(self):
        result = assess("direct-request")
        self.assertEqual(result.conditions["attacker_influence"].status, CONFIRMED)
        self.assertEqual(result.verdict, POTENTIALLY_EXPLOITABLE)

    def test_interpolation_of_attacker_input_is_traced(self):
        result = assess("interpolated")
        self.assertEqual(result.conditions["attacker_influence"].status, CONFIRMED)

    def test_literal_arguments_are_not_exploitable_with_evidence(self):
        result = assess("constant")
        self.assertEqual(result.verdict, NOT_EXPLOITABLE)
        self.assertEqual(result.conditions["attacker_influence"].status, NOT_CONFIRMED)
        self.assertEqual(result.confidence, "HIGH")

    def test_a_clean_reassignment_removes_the_taint_and_stays_unknown(self):
        result = assess("reassigned")
        self.assertNotEqual(result.conditions["attacker_influence"].status, CONFIRMED)
        self.assertEqual(result.verdict, UNKNOWN)

    def test_an_unrouted_method_is_not_reachable_and_its_argument_is_unknown(self):
        result = assess("unrouted")
        self.assertEqual(result.verdict, UNKNOWN)
        self.assertNotEqual(result.conditions["reachable"].status, CONFIRMED)

    def test_no_verdict_is_confirmed_because_preconditions_are_not_modelled(self):
        for marker in ("tainted-local", "direct-request", "interpolated"):
            result = assess(marker, exposure="internet")
            self.assertNotEqual(result.verdict, "CONFIRMED_EXPLOITABLE", marker)
            self.assertEqual(result.conditions["preconditions"].status, "UNKNOWN", marker)

    def test_every_result_states_the_analysis_limits(self):
        result = assess("tainted-local")
        self.assertIn("no call between methods is followed: a value passed in from a caller is not traced",
                      result.limitations)
        self.assertTrue(result.coverage["not_analysed"])

    def test_a_line_with_no_call_is_unknown_and_says_so(self):
        result = analyse(SOURCE, 1, None)
        self.assertFalse(result.found)
        assessed = assess_call(SOURCE, {"path": FILE, "start_line": 1, "start_col": None},
                               engine="sast-call-site", exposure="unknown")
        self.assertEqual(assessed.verdict, UNKNOWN)
        self.assertIn("no call expression starts at line 1", assessed.limitations[0])

    def test_a_column_that_does_not_match_falls_back_to_the_line(self):
        site = analyse(SOURCE, line_of("tainted-local"), 999)
        self.assertTrue(site.found)
        self.assertEqual(site.match, "line")

    def test_a_column_that_matches_is_used(self):
        line = line_of("tainted-local")
        text = SOURCE.decode().splitlines()[line - 1]
        column = text.index("cmd.ExecuteReader") + 1
        self.assertEqual(analyse(SOURCE, line, column).match, "column")


class LanguageRegistryTest(unittest.TestCase):
    def test_a_cs_file_resolves_to_the_csharp_analyzer(self):
        self.assertEqual(analyzer_for("src/Program.cs").name, "csharp")
        self.assertIsNone(analyzer_for("src/app.py"))

    def test_the_capability_report_names_every_language_in_priority_order(self):
        report = {record["language"]: record for record in capability_report()}
        self.assertEqual([r["language"] for r in capability_report()],
                         ["python", "csharp", "javascript", "java", "go"])
        self.assertEqual(report["javascript"]["status"], "NOT_IMPLEMENTED")
        self.assertEqual(report["java"]["status"], "NOT_IMPLEMENTED")
        self.assertEqual(report["go"]["status"], "NOT_IMPLEMENTED")
        self.assertEqual(report["csharp"]["test_corpus"], ["tests/fixtures/csharp-app"])
        self.assertEqual(report["csharp"]["measured_accuracy"],
                         "not measured: no labelled C# corpus exists in this repository")
        self.assertTrue(report["csharp"]["unsupported"])
        self.assertTrue(report["python"]["unsupported"])


class SastRoutingTest(unittest.TestCase):
    def _finding(self, marker: str, title: str = "rule without a CWE", tags=None):
        line = line_of(marker)
        original = {"properties": {"tags": tags or []}}
        return make_finding(category="SAST", rule_id="cs.sink", title=title,
                            asset={"type": "source_location", "name": FILE},
                            location={"path": FILE, "start_line": line, "end_line": line,
                                      "start_col": None, "end_col": None},
                            severity_reported="error", provenance={"scanner": "test"}, original=original,
                            summary=title)

    def test_a_csharp_finding_is_assessed_by_the_csharp_analyzer_with_routing_recorded(self):
        finding = self._finding("tainted-local")
        finding["exploitability_context"]["exposure"] = "internet"
        result = sast.SastEngine().assess(finding, {"project_dir": PROJECT})
        self.assertEqual(result.engine, "sast-call-site")
        self.assertEqual(result.verdict, POTENTIALLY_EXPLOITABLE)
        self.assertTrue(any(item["kind"] == "routing" for item in result.evidence))

    def test_an_inferred_class_caps_a_confirmed_verdict(self):
        from engine.universal import make_assessment, Condition
        finding = self._finding("tainted-local", title="SQL injection in search")
        finding["exploitability_context"]["exposure"] = "internet"
        confirmed = make_assessment(
            "CONFIRMED_EXPLOITABLE", reason="test", engine="sast-call-site",
            conditions={"reachable": Condition(CONFIRMED, ["r"]),
                        "attacker_influence": Condition(CONFIRMED, ["a"]),
                        "preconditions": Condition(CONFIRMED, ["p"])},
            evidence=[{"condition": "reachable", "kind": "x", "detail": "r"},
                      {"condition": "attacker_influence", "kind": "x", "detail": "a"},
                      {"condition": "preconditions", "kind": "x", "detail": "p"}],
            confidence="HIGH", exposure="internet")
        from engine import weakness
        chosen = weakness.route(finding)
        self.assertEqual(chosen["route"], "inferred")
        self.assertEqual(weakness.apply_route(confirmed, chosen, "internet").verdict, POTENTIALLY_EXPLOITABLE)


if __name__ == "__main__":
    unittest.main()
