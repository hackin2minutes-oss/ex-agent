"""Weakness classification and routing: verified CWE, inferred class with confidence, category fallback, generic
investigation when the class is ambiguous, and the verdict ceiling that applies to an unverified class."""

import unittest

from engine import weakness
from engine.universal import (
    CONFIRMED, CONFIRMED_EXPLOITABLE, NOT_CONFIRMED, NOT_EXPLOITABLE, POTENTIALLY_EXPLOITABLE, Condition,
    make_assessment, make_finding,
)


def finding(title: str = "a rule", summary: str = "", cwe_tags=()):
    original = {"properties": {"tags": [f"external/cwe/cwe-{n}" for n in cwe_tags]}}
    return make_finding(category="SAST", rule_id="rule.x", title=title,
                        asset={"type": "source_location", "name": "app.py"}, location=None,
                        severity_reported="error", provenance={"scanner": "test"}, original=original,
                        summary=summary)


def confirmed(engine="sast-call-site"):
    return make_assessment(
        CONFIRMED_EXPLOITABLE, reason="all conditions met", engine=engine,
        conditions={"reachable": Condition(CONFIRMED, ["r"]), "attacker_influence": Condition(CONFIRMED, ["a"]),
                    "preconditions": Condition(CONFIRMED, ["p"])},
        evidence=[{"condition": "reachable", "kind": "x", "detail": "r"},
                  {"condition": "attacker_influence", "kind": "x", "detail": "a"},
                  {"condition": "preconditions", "kind": "x", "detail": "p"}],
        confidence="HIGH", exposure="internet")


class RouteTest(unittest.TestCase):
    def test_a_verified_cwe_routes_to_its_class_with_no_ceiling(self):
        chosen = weakness.route(finding(cwe_tags=[89]))
        self.assertEqual(chosen["route"], weakness.ROUTE_VERIFIED)
        self.assertEqual(chosen["weakness_class"], "SQL_INJECTION")
        self.assertIsNone(chosen["ceiling"])

    def test_an_unknown_cwe_does_not_stop_the_investigation(self):
        chosen = weakness.route(finding(cwe_tags=[99999], title="something odd"))
        self.assertIsNone(chosen["weakness_class"])
        self.assertEqual(chosen["route"], weakness.ROUTE_CATEGORY)

    def test_an_unknown_cwe_with_a_recognisable_description_is_inferred(self):
        chosen = weakness.route(finding(cwe_tags=[99999], title="SQL injection in the search handler"))
        self.assertEqual(chosen["route"], weakness.ROUTE_INFERRED)
        self.assertEqual(chosen["weakness_class"], "SQL_INJECTION")
        self.assertEqual(chosen["confidence"], "MEDIUM")
        self.assertEqual(chosen["ceiling"], POTENTIALLY_EXPLOITABLE)

    def test_an_ambiguous_description_is_investigated_generically(self):
        chosen = weakness.route(finding(title="Command Line Execution through SQL Injection"))
        self.assertEqual(chosen["route"], weakness.ROUTE_GENERIC)
        self.assertIsNone(chosen["weakness_class"])
        self.assertEqual(chosen["confidence"], "LOW")
        self.assertIn("SQL_INJECTION", chosen["reason"])
        self.assertIn("COMMAND_INJECTION", chosen["reason"])

    def test_no_cwe_and_no_description_falls_back_to_the_category_with_no_class_claimed(self):
        chosen = weakness.route(finding(title="a rule"))
        self.assertEqual(chosen["route"], weakness.ROUTE_CATEGORY)
        self.assertIsNone(chosen["ceiling"])
        self.assertIn("claims no weakness class", chosen["reason"])

    def test_the_text_is_read_from_the_title_and_summary_only(self):
        self.assertIsNone(weakness.infer(finding(title="a rule", summary="nothing relevant here")))
        self.assertEqual(weakness.infer(finding(title="x", summary="reflected XSS in the view"))["classes"], ["XSS"])


class CapTest(unittest.TestCase):
    def test_an_unverified_class_caps_a_confirmed_verdict(self):
        chosen = weakness.route(finding(title="SQL injection in the search handler"))
        capped = weakness.apply_route(confirmed(), chosen, "internet")
        self.assertEqual(capped.verdict, POTENTIALLY_EXPLOITABLE)
        self.assertTrue(any("capped" in item for item in capped.limitations))
        self.assertEqual(capped.confidence, "MEDIUM")

    def test_a_verified_class_leaves_a_confirmed_verdict_alone(self):
        chosen = weakness.route(finding(cwe_tags=[89]))
        kept = weakness.apply_route(confirmed(), chosen, "internet")
        self.assertEqual(kept.verdict, CONFIRMED_EXPLOITABLE)
        self.assertEqual(kept.confidence, "HIGH")

    def test_the_routing_decision_is_recorded_as_evidence(self):
        chosen = weakness.route(finding(cwe_tags=[89]))
        recorded = weakness.apply_route(confirmed(), chosen, "internet")
        routing = [item for item in recorded.evidence if item["kind"] == "routing"]
        self.assertEqual(len(routing), 1)
        self.assertIn("verified", routing[0]["detail"])

    def test_a_negative_verdict_is_not_changed_by_routing(self):
        negative = make_assessment(
            NOT_EXPLOITABLE, reason="literal", engine="sast-call-site",
            conditions={"attacker_influence": Condition(NOT_CONFIRMED, ["l"])},
            evidence=[{"condition": "attacker_influence", "kind": "constant", "detail": "l"}],
            confidence="HIGH", exposure="unknown")
        chosen = weakness.route(finding(title="SQL injection"))
        self.assertEqual(weakness.apply_route(negative, chosen, "unknown").verdict, NOT_EXPLOITABLE)

    def test_the_existing_classify_shape_is_unchanged(self):
        record = weakness.classify(finding(cwe_tags=[89]))
        self.assertEqual(set(record), {"cwe", "classes", "reason"})


if __name__ == "__main__":
    unittest.main()
