"""Semgrep adapter and SAST engine, on real Semgrep output plus targeted cases.

The fixture `tests/fixtures/sast/semgrep-1.183.0.real.json` is `semgrep --json` output from
Semgrep 1.183.0 run on `tests/fixtures/sast/project` with the local rules in
`tests/fixtures/sast/rules.yml`. Those rules are for the fixture only.
"""

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from engine import sast, universal, universal_run
from engine.semgrep_adapter import SemgrepAdapter
from engine.universal import ModelError, NOT_EXPLOITABLE, POTENTIALLY_EXPLOITABLE, UNKNOWN, make_finding

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "sast"
REAL = FIXTURES / "semgrep-1.183.0.real.json"
PROJECT = FIXTURES / "project"


def load_real():
    return json.loads(REAL.read_text(encoding="utf-8"))


def assess_document(document, project_dir):
    """Run adapter and engine on a Semgrep document. Returns the assessed findings."""
    registry = universal_run.build_registry()
    findings, _ = SemgrepAdapter().parse(document, {"target": "test"})
    return universal.assess_all(findings, registry,
                                {"project_dir": Path(project_dir), "exposure": "unknown"})


def verdict_by_location(assessed):
    return {(f["location"]["path"], f["location"]["start_line"]): f["assessment"]
            for f in assessed}


class RealSemgrepFixtureTest(unittest.TestCase):
    """Positive and negative SAST cases using real Semgrep output."""

    @classmethod
    def setUpClass(cls):
        cls.assessed = assess_document(load_real(), PROJECT)
        cls.by_location = verdict_by_location(cls.assessed)

    def test_adapter_detects_real_output_and_keeps_verbatim_records(self):
        document = load_real()
        self.assertTrue(SemgrepAdapter().detect(document))
        self.assertEqual(len(self.assessed), 3)
        for finding in self.assessed:
            self.assertEqual(finding["provenance"]["scanner"], "semgrep")
            self.assertEqual(finding["provenance"]["version"], "1.183.0")
            self.assertIn("check_id", finding["original"])

    def test_parameter_derived_sql_argument_is_potentially_exploitable(self):
        assessment = self.by_location[("app.py", 6)]
        self.assertEqual(assessment["verdict"], POTENTIALLY_EXPLOITABLE)
        self.assertEqual(assessment["confidence"]["level"], "LOW")
        self.assertIn("username", " ".join(item["detail"] for item in assessment["evidence"]))

    def test_literal_sql_argument_is_not_exploitable_at_that_call_site(self):
        assessment = self.by_location[("app.py", 12)]
        self.assertEqual(assessment["verdict"], NOT_EXPLOITABLE)
        self.assertEqual(assessment["conditions"]["attacker_influence"]["status"], "NOT_CONFIRMED")
        self.assertIn("literal", assessment["reason"])

    def test_javascript_match_is_analysed_and_stays_unknown_without_a_request_in_scope(self):
        # handler.js is a helper, not a route, so its req parameter has no known caller here: the analysis runs, and
        # the argument is not traced to a request, so the verdict is UNKNOWN with LOW confidence.
        assessment = self.by_location[("handler.js", 2)]
        self.assertEqual(assessment["verdict"], UNKNOWN)
        self.assertEqual(assessment["confidence"]["level"], "LOW")
        self.assertIn("traced to a request value", assessment["reason"])

    def test_a_language_with_no_analyzer_is_unknown_with_low_confidence(self):
        finding = make_finding(category="SAST", rule_id="java.rule", title="rule",
                               asset={"type": "source_location", "name": "App.java"},
                               location={"path": "App.java", "start_line": 2, "end_line": 2, "start_col": None,
                                         "end_col": None},
                               severity_reported="error", provenance={"scanner": "test"}, original={})
        finding["exploitability_context"]["exposure"] = "unknown"
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "App.java").write_text("class App {}\n", encoding="utf-8")
            assessment = sast.SastEngine().assess(finding, {"project_dir": Path(tmp)})
        self.assertEqual(assessment.verdict, UNKNOWN)
        self.assertEqual(assessment.confidence, "LOW")
        self.assertIn("no source-level analysis", assessment.reason)

    def test_no_sast_result_is_confirmed_exploitable_even_with_internet_exposure(self):
        for finding in self.assessed:
            finding["exploitability_context"]["exposure"] = "internet"
        registry = universal_run.build_registry()
        for finding in self.assessed:
            result = universal.assess_finding(finding, registry,
                                              {"project_dir": PROJECT, "exposure": "internet"})
            self.assertNotEqual(result["verdict"], "CONFIRMED_EXPLOITABLE")

    def test_cwe_metadata_becomes_identifier(self):
        sql = [f for f in self.assessed if f["location"]["start_line"] == 6][0]
        self.assertEqual(sql["vulnerability"]["ids"], ["CWE-89"])


class SemgrepAdapterTest(unittest.TestCase):
    def setUp(self):
        self.document = load_real()

    def test_does_not_detect_other_scanner_formats(self):
        self.assertFalse(SemgrepAdapter().detect({"Results": [], "SchemaVersion": 2}))
        self.assertFalse(SemgrepAdapter().detect({"results": []}))

    def test_malformed_result_is_rejected_not_dropped(self):
        del self.document["results"][0]["start"]
        with self.assertRaises(ModelError):
            SemgrepAdapter().parse(self.document, {"target": "t"})

    def test_result_without_path_is_rejected(self):
        self.document["results"][0]["path"] = ""
        with self.assertRaises(ModelError):
            SemgrepAdapter().parse(self.document, {"target": "t"})

    def test_scanner_errors_are_reported_as_diagnostics(self):
        self.document["errors"] = [{"type": "PartialParsing", "message": "cannot parse line 4"}]
        _, diagnostics = SemgrepAdapter().parse(self.document, {"target": "t"})
        self.assertTrue(any("PartialParsing" in text for text in diagnostics))


class SastEngineCaseTest(unittest.TestCase):
    """Synthetic files for cases the real fixture does not cover."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.project = self.tmp / "project"
        self.project.mkdir()

    def document_for(self, source_name, source, line, col=1, end_line=None, end_col=None):
        """Semgrep-shaped document whose span covers the whole single line `line` by default."""
        (self.project / source_name).write_text(source, encoding="utf-8")
        if end_line is None:
            end_line = line
            end_col = len(source.splitlines()[line - 1]) + 1
        return {
            "version": "1.183.0",
            "results": [{
                "check_id": "case.rule",
                "path": source_name,
                "start": {"line": line, "col": col, "offset": 0},
                "end": {"line": end_line, "col": end_col, "offset": 0},
                "extra": {"message": "m", "severity": "WARNING", "lines": "", "metadata": {}},
            }],
            "errors": [],
            "paths": {"scanned": [source_name]},
        }

    def test_literal_concatenation_is_constant_but_an_interpolated_field_is_not(self):
        doc = self.document_for("d.py", 'run("SELECT " + "1")\n', 1)
        self.assertEqual(verdict_by_location(assess_document(doc, self.project))[("d.py", 1)]["verdict"],
                         NOT_EXPLOITABLE)
        # An f-string field is a FormattedValue, even when its content is a literal. Stay potential.
        doc = self.document_for("c.py", 'run(f"SELECT {1}")\n', 1)
        self.assertEqual(verdict_by_location(assess_document(doc, self.project))[("c.py", 1)]["verdict"],
                         POTENTIALLY_EXPLOITABLE)

    def test_location_that_matches_no_call_is_unknown_not_a_verdict(self):
        source = "value = 1\nrun(name)\n"
        doc = self.document_for("e.py", source, 2, 1, 2, 5)  # span does not match "run(name)"
        assessment = assess_document(doc, self.project)[0]["assessment"]
        self.assertEqual(assessment["verdict"], UNKNOWN)
        self.assertIn("no call expression", assessment["reason"])

    def test_missing_file_is_unknown(self):
        doc = self.document_for("present.py", "run(x)\n", 1)
        (self.project / "present.py").unlink()
        assessment = assess_document(doc, self.project)[0]["assessment"]
        self.assertEqual(assessment["verdict"], UNKNOWN)
        self.assertIn("not found", assessment["reason"])

    def test_path_leaving_the_project_is_refused_and_not_read(self):
        outside = self.tmp / "outside.py"
        outside.write_text("run('constant')\n", encoding="utf-8")
        doc = self.document_for("ok.py", "run('x')\n", 1)
        doc["results"][0]["path"] = "../outside.py"
        assessment = assess_document(doc, self.project)[0]["assessment"]
        self.assertEqual(assessment["verdict"], UNKNOWN)
        self.assertIn("leaves the project", assessment["reason"])

    def test_unparseable_python_is_unknown(self):
        doc = self.document_for("broken.py", "def (:\n", 1)
        assessment = assess_document(doc, self.project)[0]["assessment"]
        self.assertEqual(assessment["verdict"], UNKNOWN)
        self.assertIn("does not parse", assessment["reason"])

    def test_copy_of_real_document_with_changed_span_is_unknown(self):
        document = copy.deepcopy(load_real())
        document["results"][0]["end"]["col"] = 10
        assessed = assess_document(document, PROJECT)
        by_location = verdict_by_location(assessed)
        self.assertEqual(by_location[("app.py", 6)]["verdict"], UNKNOWN)


class UniversalRunEndToEndTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.out = self.tmp / "out"

    def test_real_output_produces_json_sarif_markdown_and_summary(self):
        summary = universal_run.run(REAL, PROJECT, self.out)

        self.assertEqual(summary["findings"], 3)
        # This project has no route. The SQL call's argument is not a request value, so no attack path is known and
        # the call is UNKNOWN, not potential. A non-Python match has no source-level analysis, so it is UNKNOWN too.
        self.assertEqual(summary["verdicts"]["UNKNOWN"], 2)
        self.assertEqual(summary["verdicts"]["POTENTIALLY_EXPLOITABLE"], 0)
        self.assertEqual(summary["verdicts"]["NOT_EXPLOITABLE"], 1)
        self.assertEqual(summary["verdicts"]["CONFIRMED_EXPLOITABLE"], 0)

        document = json.loads((self.out / "universal-findings.json").read_text(encoding="utf-8"))
        self.assertEqual(document["schema"], "sawone.universal/0")
        self.assertEqual(len(document["findings"]), 3)

        sarif = json.loads((self.out / "universal.sarif").read_text(encoding="utf-8"))
        self.assertEqual(sarif["version"], "2.1.0")
        levels = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                  + ":" + str(r["locations"][0]["physicalLocation"]["region"]["startLine"]):
                  r["level"] for r in sarif["runs"][0]["results"]}
        self.assertEqual(levels, {"app.py:6": "note", "app.py:12": "note",
                                  "handler.js:2": "note"})
        messages = [r["message"]["text"] for r in sarif["runs"][0]["results"]]
        self.assertTrue(all("reported by: semgrep" in m for m in messages))

        markdown = (self.out / "universal-report.md").read_text(encoding="utf-8")
        self.assertIn("| UNKNOWN | LOW | `fixture-sql-execute` | app.py:6 |", markdown)
        self.assertIn("### Limitations", markdown)

    def test_step_summary_receives_the_markdown(self):
        from engine import report

        summary_file = self.tmp / "step.md"
        universal_run.run(REAL, PROJECT, self.out)
        markdown = (self.out / "universal-report.md").read_text(encoding="utf-8")
        report.append_job_summary(markdown, env={"GITHUB_STEP_SUMMARY": str(summary_file)})
        self.assertIn("Universal exploitability assessment", summary_file.read_text(encoding="utf-8"))

    def test_internet_declaration_does_not_create_a_confirmed_sast_verdict(self):
        summary = universal_run.run(REAL, PROJECT, self.out, exposure="internet")
        self.assertEqual(summary["verdicts"]["CONFIRMED_EXPLOITABLE"], 0)
        self.assertEqual(summary["exposure"], "internet")

    def test_unrecognised_report_is_refused_when_nothing_else_is_usable(self):
        # An empty Trivy vulnerability report is valid SCA input now (the SCA route handles it).
        # A document no adapter or SCA format recognises is still refused.
        unknown = self.tmp / "unknown.json"
        unknown.write_text(json.dumps({"something": "else"}), encoding="utf-8")
        with self.assertRaises(ModelError):
            universal_run.run(unknown, PROJECT, self.out)

    def test_command_line_exit_codes(self):
        self.assertEqual(universal_run.main(["--input", str(REAL), "--project-dir", str(PROJECT),
                                             "--output-dir", str(self.out)]), 0)
        self.assertEqual(universal_run.main(["--input", str(self.tmp / "missing.json"),
                                             "--project-dir", str(PROJECT),
                                             "--output-dir", str(self.out)]), 2)


if __name__ == "__main__":
    unittest.main()
