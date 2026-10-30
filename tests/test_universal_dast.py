"""Nuclei adapter and DAST engine, on a real Nuclei 3.3.7 export against a local fixture target.

`tests/fixtures/dast/nuclei-export.real.json` is the JSON export of Nuclei 3.3.7 run with a local
template (`tests/fixtures/dast/reflected-input.yaml`) against `tests/fixtures/dast/target.py` on
127.0.0.1. The target is a fixture that exists only for these tests.
"""

import json
import shutil
import socket
import tempfile
import unittest
from pathlib import Path

from engine import universal, universal_run
from engine.nuclei_adapter import NucleiAdapter
from engine.universal import ModelError, POTENTIALLY_EXPLOITABLE, UNKNOWN

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "dast"
REAL = FIXTURES / "nuclei-export.real.json"


def load():
    return json.loads(REAL.read_text(encoding="utf-8"))


def assess(document, exposure="unknown"):
    findings, _ = NucleiAdapter().parse(document, {"target": "t"})
    for finding in findings:
        finding["exploitability_context"]["exposure"] = exposure
    return universal.assess_all(findings, universal_run.build_registry(),
                                {"project_dir": FIXTURES, "exposure": exposure})


class RealNucleiTest(unittest.TestCase):
    def test_reflected_input_is_potentially_exploitable_with_high_confidence(self):
        (finding,) = assess(load())
        self.assertEqual(finding["category"], "DAST")
        self.assertEqual(finding["asset"]["type"], "endpoint")
        self.assertIsNone(finding["location"])
        self.assertEqual(finding["assessment"]["verdict"], POTENTIALLY_EXPLOITABLE)
        self.assertEqual(finding["assessment"]["confidence"]["level"], "HIGH")
        self.assertIn("one path", finding["assessment"]["reason"])

    def test_internet_declaration_still_does_not_confirm_one_recorded_path(self):
        (finding,) = assess(load(), exposure="internet")
        self.assertNotEqual(finding["assessment"]["verdict"], "CONFIRMED_EXPLOITABLE")

    def test_engine_sends_no_new_traffic(self):
        original = socket.socket

        def refuse(*args, **kwargs):
            raise AssertionError("the DAST engine must not open a socket")

        socket.socket = refuse
        try:
            assess(load())
        finally:
            socket.socket = original


class DastNegativeTest(unittest.TestCase):
    def finding_with_response(self, body):
        document = load()
        head = document[0]["response"].split("\r\n\r\n", 1)[0]
        document[0]["response"] = head + "\r\n\r\n" + body
        return assess(document)[0]["assessment"]

    def test_escaped_input_is_unknown_not_not_exploitable(self):
        assessment = self.finding_with_response("<html><body><p>Results for &lt;b&gt;probe&lt;/b&gt;</p></body></html>")
        self.assertEqual(assessment["verdict"], UNKNOWN)
        self.assertIn("no decoded input", assessment["reason"])

    def test_response_without_the_value_is_unknown(self):
        assessment = self.finding_with_response("<html><body><p>No results.</p></body></html>")
        self.assertEqual(assessment["verdict"], UNKNOWN)

    def test_missing_response_is_unknown(self):
        document = load()
        document[0]["response"] = ""
        self.assertEqual(assess(document)[0]["assessment"]["verdict"], UNKNOWN)

    def test_response_without_a_status_line_is_unknown(self):
        document = load()
        document[0]["response"] = "garbage without a status line"
        assessment = assess(document)[0]["assessment"]
        self.assertEqual(assessment["verdict"], UNKNOWN)
        self.assertIn("no usable request or status line", assessment["reason"])


class NucleiAdapterTest(unittest.TestCase):
    def test_result_without_matched_at_is_rejected(self):
        document = load()
        del document[0]["matched-at"]
        self.assertFalse(NucleiAdapter().detect(document))
        with self.assertRaises(ModelError):
            NucleiAdapter().parse([dict(document[0], **{"matched-at": 5})], {"target": "t"})

    def test_other_formats_are_not_detected(self):
        self.assertFalse(NucleiAdapter().detect([{"ident": "x", "determinations": {}, "locations": []}]))
        self.assertFalse(NucleiAdapter().detect(json.loads(
            (FIXTURES.parent / "iac" / "checkov-3.4.0.real.json").read_text(encoding="utf-8"))))


class DastEndToEndTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_run_writes_outputs_with_endpoint_and_no_region(self):
        out = self.tmp / "out"
        summary = universal_run.run(REAL, FIXTURES, out)
        self.assertEqual(summary["categories"], ["DAST"])
        self.assertEqual(summary["verdicts"]["POTENTIALLY_EXPLOITABLE"], 1)
        sarif = json.loads((out / "universal.sarif").read_text(encoding="utf-8"))
        self.assertEqual(sarif["runs"][0]["results"][0]["level"], "warning")
        self.assertNotIn("locations", sarif["runs"][0]["results"][0])
        markdown = (out / "universal-report.md").read_text(encoding="utf-8")
        self.assertIn("| POTENTIALLY_EXPLOITABLE | HIGH | `fixture-reflected-input` | - |", markdown)


if __name__ == "__main__":
    unittest.main()
