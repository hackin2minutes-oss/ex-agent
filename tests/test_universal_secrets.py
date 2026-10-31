"""Gitleaks adapter and secrets engine, on real Gitleaks output plus targeted cases.

`tests/fixtures/secrets/gitleaks-8.24.2.real.json` is `gitleaks detect --report-format json` output
from Gitleaks 8.24.2 on `tests/fixtures/secrets/project`. The credential in `config.py` is a
fabricated value in the shape of an AWS access key. It is not a credential for any service.

These tests also check that the credential value does not appear in any output file.
"""

import json
import shutil
import tempfile
import zlib
import unittest
from pathlib import Path

from engine import universal, universal_run
from engine.gitleaks_adapter import GitleaksAdapter, REDACTED, digest
from engine.universal import ModelError, POTENTIALLY_EXPLOITABLE, UNKNOWN

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "secrets"
REAL = FIXTURES / "gitleaks-8.24.2.real.json"
PROJECT = FIXTURES / "project"
FABRICATED = "AKIAZ7Q3M5XW2KB4RT6N"


def load_real():
    return json.loads(REAL.read_text(encoding="utf-8"))


def assess_document(document, project_dir, exposure="unknown"):
    registry = universal_run.build_registry()
    findings, _ = GitleaksAdapter().parse(document, {"target": "test"})
    for finding in findings:
        finding["exploitability_context"]["exposure"] = exposure
    return universal.assess_all(findings, registry,
                                {"project_dir": Path(project_dir), "exposure": exposure})



def _readable_bytes(path: Path) -> bytes:
    """The bytes a reader could see. A PDF's text is in compressed streams, so those are decompressed first."""
    data = path.read_bytes()
    if not path.name.endswith(".pdf"):
        return data
    streams = []
    position = 0
    while True:
        start = data.find(b"stream", position)
        if start < 0:
            break
        begin = data.find(b"\n", start) + 1
        end = data.find(b"endstream", begin)
        if end < 0:
            break
        try:
            streams.append(zlib.decompress(data[begin:end]))
        except zlib.error:
            streams.append(data[begin:end])
        position = end + len(b"endstream")
    return data + b"".join(streams)

class RealGitleaksFixtureTest(unittest.TestCase):
    def test_finding_is_potentially_exploitable_with_medium_confidence(self):
        (assessed,) = assess_document(load_real(), PROJECT)
        assessment = assessed["assessment"]
        self.assertEqual(assessed["category"], "SECRET")
        self.assertEqual(assessment["verdict"], POTENTIALLY_EXPLOITABLE)
        self.assertEqual(assessment["confidence"]["level"], "MEDIUM")
        self.assertEqual(assessment["conditions"]["vulnerability_exists"]["status"], "UNKNOWN")

    def test_no_secret_value_reaches_any_output_file(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        universal_run.run(REAL, PROJECT, tmp / "out", exposure="internet")
        for path in (tmp / "out").iterdir():
            if path.is_dir():
                continue
            self.assertNotIn(FABRICATED.encode(), _readable_bytes(path), path.name)

    def test_redacted_record_keeps_a_digest_not_the_value(self):
        findings, _ = GitleaksAdapter().parse(load_real(), {"target": "t"})
        original = findings[0]["original"]
        self.assertEqual(original["Match"], REDACTED)
        self.assertEqual(original["Secret"], REDACTED)
        self.assertEqual(original["match_sha256"], digest(FABRICATED))
        self.assertEqual(original["match_length"], len(FABRICATED))
        self.assertEqual(original["RuleID"], "aws-access-token")

    def test_no_secret_gets_confirmed_even_with_internet_exposure(self):
        (assessed,) = assess_document(load_real(), PROJECT, exposure="internet")
        self.assertNotEqual(assessed["assessment"]["verdict"], "CONFIRMED_EXPLOITABLE")


class SecretsEdgeCaseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.project = self.tmp / "project"
        shutil.copytree(PROJECT, self.project)

    def record(self, **changes):
        document = load_real()
        document[0].update(changes)
        return document

    def test_test_fixture_path_is_unknown_not_a_finding(self):
        (self.project / "tests").mkdir()
        shutil.copy(self.project / "config.py", self.project / "tests" / "config.py")
        (assessed,) = assess_document(self.record(File="tests/config.py"), self.project)
        self.assertEqual(assessed["assessment"]["verdict"], UNKNOWN)
        self.assertIn("test, example or documentation path", assessed["assessment"]["reason"])

    def test_changed_source_makes_the_scan_stale(self):
        config = self.project / "config.py"
        config.write_text(config.read_text(encoding="utf-8").replace(FABRICATED, "AKIAQQQQQQQQQQQQQQQQ"),
                          encoding="utf-8")
        (assessed,) = assess_document(load_real(), self.project)
        self.assertEqual(assessed["assessment"]["verdict"], UNKNOWN)
        self.assertIn("stale", assessed["assessment"]["reason"])

    def test_finding_pointing_at_an_environment_read_is_not_verified(self):
        # Line 5 reads the token from the environment. A finding that points there is not a
        # verified credential in source.
        (assessed,) = assess_document(self.record(StartLine=5, EndLine=5), self.project)
        self.assertEqual(assessed["assessment"]["verdict"], UNKNOWN)
        self.assertIn("stale", assessed["assessment"]["reason"])

    def test_multi_line_match_is_not_verified(self):
        (assessed,) = assess_document(self.record(EndLine=6), self.project)
        self.assertEqual(assessed["assessment"]["verdict"], UNKNOWN)
        self.assertIn("multi-line", assessed["assessment"]["reason"])

    def test_very_long_line_is_not_searched(self):
        long_line = "x = '" + "a" * 11_000 + FABRICATED + "'\n"
        (self.project / "long.py").write_text(long_line, encoding="utf-8")
        (assessed,) = assess_document(self.record(File="long.py", StartLine=1, EndLine=1),
                                      self.project)
        self.assertEqual(assessed["assessment"]["verdict"], UNKNOWN)
        self.assertIn("not searched", assessed["assessment"]["reason"])

    def test_secret_without_a_recorded_digest_is_unknown_not_a_crash(self):
        # Only the Gitleaks adapter records the digest. A secret from another source has none to check against.
        from engine.secrets_engine import SecretsEngine
        finding = {"location": {"path": "config.py", "start_line": 1, "end_line": 1}, "original": {},
                   "exploitability_context": {"exposure": "unknown"}}
        assessment = SecretsEngine().assess(finding, {"project_dir": self.project}).to_dict()
        self.assertEqual(assessment["verdict"], UNKNOWN)
        self.assertIn("digest", assessment["reason"])

    def test_path_leaving_the_project_is_refused(self):
        (assessed,) = assess_document(self.record(File="../outside.py"), self.project)
        self.assertEqual(assessed["assessment"]["verdict"], UNKNOWN)
        self.assertIn("leaves the project", assessed["assessment"]["reason"])


class GitleaksAdapterTest(unittest.TestCase):
    def test_empty_list_is_not_detected_and_needs_an_explicit_adapter(self):
        self.assertFalse(GitleaksAdapter().detect([]))

    def test_record_without_required_fields_is_rejected(self):
        document = load_real()
        del document[0]["Fingerprint"]
        self.assertFalse(GitleaksAdapter().detect(document))
        document = load_real()
        document[0]["StartLine"] = 0
        with self.assertRaises(ModelError):
            GitleaksAdapter().parse(document, {"target": "t"})

    def test_other_scanner_formats_are_not_detected(self):
        self.assertFalse(GitleaksAdapter().detect([{"ident": "x", "determinations": {}, "locations": []}]))


class GitleaksEndToEndTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.out = self.tmp / "out"

    def test_empty_output_needs_the_explicit_adapter_and_is_no_secrets(self):
        empty = self.tmp / "empty.json"
        empty.write_text("[]", encoding="utf-8")
        with self.assertRaises(ModelError):
            universal_run.run(empty, PROJECT, self.out)
        summary = universal_run.run(empty, PROJECT, self.out, adapter_name="gitleaks")
        self.assertEqual(summary["findings"], 0)
        self.assertIn("gitleaks reported no secrets", summary["diagnostics"])

    def test_command_line_accepts_adapter_name(self):
        empty = self.tmp / "empty.json"
        empty.write_text("[]", encoding="utf-8")
        self.assertEqual(universal_run.main(["--input", str(empty), "--adapter", "gitleaks",
                                             "--project-dir", str(PROJECT),
                                             "--output-dir", str(self.out)]), 0)

    def test_sarif_marks_secret_as_warning_and_omits_the_value(self):
        universal_run.run(REAL, PROJECT, self.out)
        sarif = (self.out / "universal.sarif").read_text(encoding="utf-8")
        self.assertNotIn(FABRICATED, sarif)
        results = json.loads(sarif)["runs"][0]["results"]
        self.assertEqual(results[0]["level"], "warning")
        summary = json.loads((self.out / "universal-findings.json").read_text(encoding="utf-8"))["summary"]
        self.assertEqual(summary["verdicts"]["NOT_EXPLOITABLE"], 0)


if __name__ == "__main__":
    unittest.main()
