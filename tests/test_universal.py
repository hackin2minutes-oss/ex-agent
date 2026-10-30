"""Universal model: verdict rules, registry behaviour and the reporting path.

These tests cover the rules in engine/universal.py. They do not test any domain's analysis.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

from engine import universal
from engine.universal import (
    ANALYSIS_INCOMPLETE, CONFIRMED, CONFIRMED_EXPLOITABLE, Condition, Engine, MITIGATED,
    ModelError, NOT_AFFECTED, NOT_CONFIRMED, NOT_EXPLOITABLE, POTENTIALLY_EXPLOITABLE, Registry,
    UNKNOWN, UNKNOWN_STATUS, make_assessment, make_finding,
)

PROVENANCE = {"scanner": "test", "version": "0", "format": "test", "target": "t"}


def sast_finding(exposure="unknown"):
    return make_finding(
        category="SAST", rule_id="r.one", title="one",
        asset={"type": "source_location", "name": "a.py"},
        location={"path": "a.py", "start_line": 1, "start_col": 1, "end_line": 1, "end_col": 5},
        severity_reported="ERROR", provenance=PROVENANCE, original={}, exposure=exposure)


def evidence(condition, detail="checked"):
    return {"condition": condition, "kind": "test", "detail": detail}


class ModelFieldsTest(unittest.TestCase):
    def test_exactly_the_mandate_verdicts(self):
        self.assertEqual(universal.VERDICTS, (
            "CONFIRMED_EXPLOITABLE", "POTENTIALLY_EXPLOITABLE", "NOT_EXPLOITABLE",
            "NOT_AFFECTED", "MITIGATED", "UNKNOWN", "ANALYSIS_INCOMPLETE"))

    def test_rejects_unknown_category_and_asset_type(self):
        with self.assertRaises(ModelError):
            make_finding(category="NOPE", rule_id="r", title="t",
                         asset={"type": "source_location"}, location=None,
                         severity_reported=None, provenance=PROVENANCE, original={})
        with self.assertRaises(ModelError):
            make_finding(category="SAST", rule_id="r", title="t", asset={"type": "pod"},
                         location=None, severity_reported=None, provenance=PROVENANCE,
                         original={})

    def test_rejects_unknown_exposure_and_missing_scanner(self):
        with self.assertRaises(ModelError):
            sast_finding(exposure="public")
        with self.assertRaises(ModelError):
            make_finding(category="SAST", rule_id="r", title="t",
                         asset={"type": "source_location"}, location=None,
                         severity_reported=None, provenance={"scanner": ""}, original={})

    def test_severity_is_normalised_but_reported_value_is_kept(self):
        finding = make_finding(category="SAST", rule_id="r", title="t",
                               asset={"type": "source_location", "name": "a"}, location=None,
                               severity_reported="ERROR", provenance=PROVENANCE, original={})
        self.assertEqual(finding["severity"], {"reported": "ERROR", "normalised": "high"})
        self.assertEqual(universal.normalise_severity("Blocker??"), "unknown")
        self.assertEqual(universal.normalise_severity(None), "unknown")

    def test_finding_id_is_stable_and_depends_on_location(self):
        first = sast_finding()
        second = sast_finding()
        self.assertEqual(first["id"], second["id"])
        moved = make_finding(
            category="SAST", rule_id="r.one", title="one",
            asset={"type": "source_location", "name": "a.py"},
            location={"path": "a.py", "start_line": 9, "start_col": 1, "end_line": 9, "end_col": 5},
            severity_reported="ERROR", provenance=PROVENANCE, original={})
        self.assertNotEqual(first["id"], moved["id"])


class VerdictRulesTest(unittest.TestCase):
    def test_not_exploitable_is_refused_when_nothing_is_confirmed_not_present(self):
        with self.assertRaises(ModelError):
            make_assessment(NOT_EXPLOITABLE, reason="x", engine="e")

    def test_unknown_condition_with_evidence_does_not_allow_not_exploitable(self):
        # UNKNOWN is never a substitute for NOT_CONFIRMED, even when evidence is attached.
        with self.assertRaises(ModelError):
            make_assessment(NOT_EXPLOITABLE, reason="x", engine="e",
                            conditions={"reachable": Condition(UNKNOWN_STATUS, ["maybe"])},
                            evidence=[evidence("reachable")])

    def test_not_exploitable_with_backed_not_confirmed_condition_is_allowed(self):
        result = make_assessment(
            NOT_EXPLOITABLE, reason="x", engine="e",
            conditions={"attacker_influence": Condition(NOT_CONFIRMED, ["literal"])},
            evidence=[evidence("attacker_influence")])
        self.assertEqual(result.verdict, NOT_EXPLOITABLE)

    def test_not_affected_needs_vulnerability_absence_with_evidence(self):
        with self.assertRaises(ModelError):
            make_assessment(NOT_AFFECTED, reason="x", engine="e",
                            conditions={"vulnerability_exists": Condition(NOT_CONFIRMED)},
                            evidence=[evidence("vulnerability_exists")])
        make_assessment(NOT_AFFECTED, reason="x", engine="e",
                        conditions={"vulnerability_exists": Condition(NOT_CONFIRMED, ["fixed"])},
                        evidence=[evidence("vulnerability_exists")])

    def test_mitigated_needs_verified_mitigation_not_configuration(self):
        with self.assertRaises(ModelError):
            make_assessment(MITIGATED, reason="x", engine="e",
                            conditions={"mitigation_effective": Condition(UNKNOWN_STATUS, ["flag set"])},
                            evidence=[evidence("mitigation_effective")])
        with self.assertRaises(ModelError):
            make_assessment(MITIGATED, reason="x", engine="e",
                            conditions={"mitigation_effective": Condition(CONFIRMED)})
        result = make_assessment(
            MITIGATED, reason="x", engine="e",
            conditions={"mitigation_effective": Condition(CONFIRMED, ["blocked on the path"])},
            evidence=[evidence("mitigation_effective")])
        self.assertEqual(result.verdict, MITIGATED)

    def test_confirmed_exploitable_needs_all_conditions_and_internet_exposure(self):
        conditions = {
            name: Condition(CONFIRMED, ["seen"])
            for name in ("reachable", "attacker_influence", "preconditions")
        }
        evidences = [evidence(name) for name in conditions]
        with self.assertRaises(ModelError):
            make_assessment(CONFIRMED_EXPLOITABLE, reason="x", engine="e",
                            conditions=conditions, evidence=evidences, exposure="unknown")
        with self.assertRaises(ModelError):
            make_assessment(CONFIRMED_EXPLOITABLE, reason="x", engine="e",
                            conditions=conditions, evidence=evidences[:2], exposure="internet")
        result = make_assessment(CONFIRMED_EXPLOITABLE, reason="x", engine="e",
                                 conditions=conditions, evidence=evidences, exposure="internet")
        self.assertEqual(result.verdict, CONFIRMED_EXPLOITABLE)

    def test_unknown_and_incomplete_need_a_stated_limitation(self):
        with self.assertRaises(ModelError):
            make_assessment(UNKNOWN, reason="x", engine="e")
        with self.assertRaises(ModelError):
            make_assessment(ANALYSIS_INCOMPLETE, reason="x", engine="e")

    def test_unknown_verdict_name_and_confidence_are_refused(self):
        with self.assertRaises(ModelError):
            make_assessment("SAFE", reason="x", engine="e")
        with self.assertRaises(ModelError):
            make_assessment(POTENTIALLY_EXPLOITABLE, reason="x", engine="e", confidence="SURE")

    def test_condition_names_and_statuses_are_checked(self):
        with self.assertRaises(ModelError):
            make_assessment(POTENTIALLY_EXPLOITABLE, reason="x", engine="e",
                            conditions={"exploited": Condition(CONFIRMED)})
        with self.assertRaises(ModelError):
            make_assessment(POTENTIALLY_EXPLOITABLE, reason="x", engine="e",
                            conditions={"reachable": Condition("MAYBE")})


class LegacyMappingTest(unittest.TestCase):
    def test_legacy_classes_map_to_mandate_verdicts(self):
        self.assertEqual(universal.from_legacy("confirmed_exploitable"), CONFIRMED_EXPLOITABLE)
        self.assertEqual(universal.from_legacy("not_affected"), NOT_AFFECTED)
        self.assertEqual(universal.from_legacy("analysis_failed"), ANALYSIS_INCOMPLETE)
        self.assertEqual(universal.from_legacy("not_reachable_within_analysed_scope"),
                         NOT_EXPLOITABLE)

    def test_unlisted_or_component_only_classes_never_become_a_safe_verdict(self):
        self.assertEqual(universal.from_legacy("vulnerable_component_only"), UNKNOWN)
        self.assertEqual(universal.from_legacy("some_new_class"), UNKNOWN)
        for legacy in universal.LEGACY_TO_VERDICT:
            self.assertNotEqual(universal.from_legacy(legacy), MITIGATED)


class FakeEngine(Engine):
    name = "fake"
    categories = ("SAST",)

    def __init__(self, behaviour):
        self.behaviour = behaviour

    def assess(self, finding, context):
        return self.behaviour(finding, context)


class RegistryTest(unittest.TestCase):
    def test_duplicate_or_unknown_registrations_are_refused(self):
        registry = Registry()
        registry.register_engine(FakeEngine(None))
        with self.assertRaises(ModelError):
            registry.register_engine(FakeEngine(None))
        bad = FakeEngine(None)
        bad.name = "bad"
        bad.categories = ("TELEPATHY",)
        with self.assertRaises(ModelError):
            registry.register_engine(bad)

    def test_engine_applies_only_to_its_categories(self):
        registry = Registry()
        registry.register_engine(FakeEngine(None))
        self.assertIsNotNone(registry.engine_for(sast_finding()))
        sca = dict(sast_finding(), category="SCA")
        self.assertIsNone(registry.engine_for(sca))

    def test_missing_engine_gives_unknown_with_reason_never_a_safe_verdict(self):
        result = universal.assess_finding(dict(sast_finding(), category="IAC"), Registry(), {})
        self.assertEqual(result["verdict"], UNKNOWN)
        self.assertIn("IAC", result["reason"])
        self.assertTrue(result["limitations"])

    def test_engine_exception_becomes_analysis_incomplete(self):
        def boom(finding, context):
            raise RuntimeError("bad state")

        registry = Registry()
        registry.register_engine(FakeEngine(boom))
        result = universal.assess_finding(sast_finding(), registry, {})
        self.assertEqual(result["verdict"], ANALYSIS_INCOMPLETE)
        self.assertIn("RuntimeError", result["reason"])

    def test_engine_producing_an_invalid_assessment_is_not_hidden(self):
        def invalid(finding, context):
            return universal.Assessment(NOT_EXPLOITABLE, "no evidence", {}, [], "LOW", "",
                                        {}, [], "fake")

        registry = Registry()
        registry.register_engine(FakeEngine(invalid))
        with self.assertRaises(ModelError):
            universal.assess_finding(sast_finding(), registry, {})


class ReportingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_step_summary_is_written_only_when_the_variable_is_set(self):
        from engine import report

        summary_file = self.tmp / "summary.md"
        self.assertFalse(report.append_job_summary("x", env={}))
        self.assertTrue(report.append_job_summary("## Hi\n", env={"GITHUB_STEP_SUMMARY": str(summary_file)}))
        self.assertEqual(summary_file.read_text(encoding="utf-8"), "## Hi\n")


if __name__ == "__main__":
    unittest.main()
