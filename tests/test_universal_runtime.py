"""IAST and RASP runtime evidence: schema conformance, adapters, engines and the universal pipeline.

The fixtures in tests/fixtures/runtime are SYNTHETIC. Their `agent.simulated` is true. They were written to
exercise the schemas and the engines, not to report any observed behaviour. No raw input value appears in them:
each is represented by a SHA-256 digest of an example string.
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from engine import universal, universal_run
from engine.iast import IastAdapter
from engine.rasp import RaspAdapter
from engine.universal import (
    CONFIRMED_EXPLOITABLE, MITIGATED, ModelError, POTENTIALLY_EXPLOITABLE, UNKNOWN,
)

ROOT = Path(__file__).resolve().parent.parent
RUNTIME = ROOT / "tests" / "fixtures" / "runtime"
PROJECT = RUNTIME / "project"
IAST_DOC = RUNTIME / "iast-synthetic.json"
RASP_DOC = RUNTIME / "rasp-synthetic.json"
IAST_SCHEMA = ROOT / "docs" / "schemas" / "sawone-iast-1.schema.json"
RASP_SCHEMA = ROOT / "docs" / "schemas" / "sawone-rasp-1.schema.json"


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def assess(document, exposure="unknown"):
    adapter = IastAdapter() if document.get("schema") == "sawone.iast/1" else RaspAdapter()
    findings, _ = adapter.parse(document, {"target": "fixture"})
    for finding in findings:
        finding["exploitability_context"]["exposure"] = exposure
    return universal.assess_all(findings, universal_run.build_registry(),
                                {"project_dir": PROJECT, "exposure": exposure})


def by_request(assessed):
    return {f["original"]["request_id"]: f for f in assessed}


class SchemaConformanceTest(unittest.TestCase):
    def test_fixtures_conform_to_the_documented_schemas(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema is not installed; install it to run the schema check")
        for doc, schema in ((IAST_DOC, IAST_SCHEMA), (RASP_DOC, RASP_SCHEMA)):
            jsonschema.Draft202012Validator(load(schema)).validate(load(doc))

    def test_both_fixtures_are_labelled_simulated(self):
        self.assertTrue(load(IAST_DOC)["agent"]["simulated"])
        self.assertTrue(load(RASP_DOC)["agent"]["simulated"])


class IastTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.by = by_request(assess(load(IAST_DOC)))

    def test_sanitizer_verified_in_source_gives_mitigated_for_that_path(self):
        self.assertEqual(self.by["req-201"]["assessment"]["verdict"], MITIGATED)
        self.assertEqual(self.by["req-201"]["assessment"]["confidence"]["level"], "MEDIUM")

    def test_unsanitized_observed_path_is_potentially_exploitable_without_declared_exposure(self):
        assessment = self.by["req-202"]["assessment"]
        self.assertEqual(assessment["verdict"], POTENTIALLY_EXPLOITABLE)
        self.assertEqual(assessment["confidence"]["level"], "HIGH")
        self.assertIn("this one observed path", assessment["reason"])

    def test_claimed_sanitizer_missing_from_source_is_not_credited(self):
        assessment = self.by["req-203"]["assessment"]
        self.assertEqual(assessment["verdict"], POTENTIALLY_EXPLOITABLE)
        self.assertTrue(any("claimed but not found" in e["detail"] for e in assessment["evidence"]))

    def test_sink_not_observed_executing_is_unknown_not_safe(self):
        assessment = self.by["req-204"]["assessment"]
        self.assertEqual(assessment["verdict"], UNKNOWN)
        self.assertIn("not observed executing", assessment["reason"])

    def test_observation_whose_sink_line_moved_is_stale(self):
        assessment = self.by["req-205"]["assessment"]
        self.assertEqual(assessment["verdict"], UNKNOWN)
        self.assertIn("stale", assessment["reason"])

    def test_internet_declaration_confirms_only_the_observed_unsanitized_path(self):
        assessed = by_request(assess(load(IAST_DOC), exposure="internet"))
        self.assertEqual(assessed["req-202"]["assessment"]["verdict"], CONFIRMED_EXPLOITABLE)
        self.assertEqual(assessed["req-201"]["assessment"]["verdict"], MITIGATED)
        self.assertIn("one observed path", assessed["req-202"]["assessment"]["reason"])

    def test_two_requests_to_one_sink_stay_two_findings(self):
        assessed = assess(load(IAST_DOC))
        lines = [f["location"]["start_line"] for f in assessed if f["location"]["start_line"] == 10]
        self.assertEqual(len(lines), 3)
        self.assertEqual(len({f["id"] for f in assessed}), len(assessed))

    def test_raw_value_is_refused(self):
        document = load(IAST_DOC)
        document["observations"][0]["value"] = "<b>probe</b>"
        with self.assertRaises(ModelError):
            IastAdapter().parse(document, {"target": "t"})

    def test_malformed_observation_is_refused_not_guessed(self):
        document = load(IAST_DOC)
        del document["observations"][0]["request_id"]
        with self.assertRaises(ModelError):
            IastAdapter().parse(document, {"target": "t"})


class RaspTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.by = by_request(assess(load(RASP_DOC)))

    def test_blocked_attack_is_mitigated_for_that_request_only(self):
        assessment = self.by["req-301"]["assessment"]
        self.assertEqual(assessment["verdict"], MITIGATED)
        self.assertIn("not that the underlying weakness is absent", assessment["reason"])
        self.assertIn("other inputs and paths", " ".join(assessment["limitations"]))

    def test_allowed_attack_is_potentially_exploitable(self):
        self.assertEqual(self.by["req-302"]["assessment"]["verdict"], POTENTIALLY_EXPLOITABLE)

    def test_disabled_protection_is_unknown_even_when_marked_blocked(self):
        assessment = self.by["req-303"]["assessment"]
        self.assertEqual(assessment["verdict"], UNKNOWN)
        self.assertIn("disabled", assessment["reason"])

    def test_block_naming_no_protected_sink_is_unknown(self):
        assessment = self.by["req-304"]["assessment"]
        self.assertEqual(assessment["verdict"], UNKNOWN)

    def test_no_rasp_event_is_confirmed_or_not_exploitable(self):
        for finding in assess(load(RASP_DOC), exposure="internet"):
            self.assertNotIn(finding["assessment"]["verdict"], ("CONFIRMED_EXPLOITABLE", "NOT_EXPLOITABLE"))

    def test_raw_input_value_is_refused(self):
        document = load(RASP_DOC)
        document["events"][0]["input"]["value"] = "' OR 1=1 --"
        with self.assertRaises(ModelError):
            RaspAdapter().parse(document, {"target": "t"})

    def test_unknown_action_is_refused(self):
        document = load(RASP_DOC)
        document["events"][0]["action"] = "logged"
        with self.assertRaises(ModelError):
            RaspAdapter().parse(document, {"target": "t"})


class RuntimeEndToEndTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_iast_and_rasp_reports_together_in_one_run(self):
        summary = universal_run.run([IAST_DOC, RASP_DOC], PROJECT, self.tmp / "out", offline=True)
        self.assertEqual(set(summary["categories"]), {"IAST", "RASP"})
        self.assertEqual(summary["findings"], 9)
        findings = json.loads((self.tmp / "out" / "universal-findings.json").read_text(encoding="utf-8"))["findings"]
        for finding in findings:
            self.assertTrue(finding["sources"][0]["simulated"])
        sarif = json.loads((self.tmp / "out" / "universal.sarif").read_text(encoding="utf-8"))
        self.assertEqual(len(sarif["runs"][0]["results"]), 9)


if __name__ == "__main__":
    unittest.main()
