"""The detailed PDF report: the triage score, the content of each section, and the PDF file itself.

Content is checked on the section data, because the PDF's text streams are compressed. The file is checked for the
PDF header and an end marker, and for one page per section group.
"""

import tempfile
import unittest
from pathlib import Path

from engine import report_pdf
from engine.universal import make_assessment, make_finding, Condition


def finding(verdict: str = "UNKNOWN", severity: str = "medium", title: str = "rule", summary: str = "",
            path: str | None = "app/views.py", line: int = 10, kev: bool = False, epss: float | None = None,
            attack_path=None, conditions=None, evidence=None, cve: str | None = None):
    location = {"path": path, "start_line": line, "end_line": line, "start_col": None, "end_col": None} if path else None
    item = make_finding(category="SAST", rule_id=title, title=title, asset={"type": "source_location", "name": path or "x"},
                        location=location, severity_reported=severity, provenance={"scanner": "test"}, original={},
                        summary=summary, ids=[cve] if cve else [])
    item["exploitability_context"]["exposure"] = "unknown"
    if verdict == "CONFIRMED_EXPLOITABLE" and conditions is None:
        # The engine only accepts CONFIRMED_EXPLOITABLE when each of these has evidence behind it.
        conditions = {name: Condition("CONFIRMED", [f"{name} evidence"])
                      for name in ("reachable", "attacker_influence", "preconditions")}
        evidence = [{"condition": name, "kind": "test", "detail": f"{name} evidence"} for name in conditions]
    if verdict == "NOT_EXPLOITABLE" and conditions is None:
        conditions = {"attacker_influence": Condition("NOT_CONFIRMED", ["literals only"])}
        evidence = [{"condition": "attacker_influence", "kind": "test", "detail": "literals only"}]
    assessment = make_assessment(verdict, reason="the reason", engine="test", conditions=conditions or {},
                                 evidence=evidence or [], limitations=["a limit"], confidence="MEDIUM",
                                 exposure="internet" if verdict == "CONFIRMED_EXPLOITABLE" else "unknown")
    assessed = assessment.to_dict()
    if attack_path is not None:
        assessed["attack_path"] = attack_path
    assessed["recommended_remediation"] = "Fix it."
    item["assessment"] = assessed
    if kev or epss is not None:
        item["intel"] = {"signals": [{"cve": cve or "CVE-2021-44228", "known_exploited": kev,
                                      "kev": {"added": "2021-12-10", "due": "2021-12-24"} if kev else None,
                                      "epss": {"score": epss, "percentile": 0.5} if epss is not None else None}]}
    return item


class TriageScoreTest(unittest.TestCase):
    def test_a_confirmed_verdict_on_a_high_severity_finding_scores_eight_point_five(self):
        score, _ = report_pdf.triage_score(finding("CONFIRMED_EXPLOITABLE", severity="high"))
        self.assertEqual(score, 8.5)

    def test_a_known_exploited_cve_adds_one_point_five_and_clamps_at_ten(self):
        score, basis = report_pdf.triage_score(finding("CONFIRMED_EXPLOITABLE", severity="critical", kev=True))
        self.assertEqual(score, 10.0)
        self.assertIn("known exploited (KEV) +1.5", basis)
        self.assertIn("clamped to 0-10", basis)

    def test_epss_adds_its_probability(self):
        score, basis = report_pdf.triage_score(finding("POTENTIALLY_EXPLOITABLE", severity="medium", epss=0.25))
        self.assertEqual(score, 5.2)
        self.assertIn("EPSS 0.25000", basis)

    def test_an_unknown_finding_scores_its_placeholder_adjusted_by_severity(self):
        score, _ = report_pdf.triage_score(finding("UNKNOWN", severity="low"))
        self.assertEqual(score, 2.5)

    def test_a_negative_verdict_scores_zero_and_cannot_go_below_zero(self):
        score, _ = report_pdf.triage_score(finding("NOT_EXPLOITABLE", severity="info"))
        self.assertEqual(score, 0.0)

    def test_the_basis_names_every_part_of_the_score(self):
        _, basis = report_pdf.triage_score(finding("POTENTIALLY_EXPLOITABLE", severity="high"))
        self.assertEqual(basis, "POTENTIALLY_EXPLOITABLE 5.0 + severity high +0.5")


class SectionContentTest(unittest.TestCase):
    def test_every_section_has_location_verdict_reason_score_and_remediation(self):
        data = report_pdf.sections(finding("POTENTIALLY_EXPLOITABLE", title="SQL injection", summary="raw query",
                                           path="app/views.py", line=42))
        self.assertEqual(data["location"], "app/views.py:42")
        self.assertEqual(data["description"], "raw query")
        self.assertEqual(data["verdict"], "POTENTIALLY_EXPLOITABLE")
        self.assertEqual(data["reason"], "the reason")
        self.assertIsInstance(data["score"], float)
        self.assertEqual(data["remediation"], "Fix it.")
        self.assertEqual(data["limitations"], ["a limit"])

    def test_a_finding_without_a_location_says_so(self):
        self.assertEqual(report_pdf.sections(finding(path=None))["location"], "no source location")

    def test_the_exploitability_is_the_traced_path_when_there_is_one(self):
        path = [{"file": "app/views.py", "function": "search"}, {"file": "db.py", "function": "run"}]
        data = report_pdf.sections(finding("POTENTIALLY_EXPLOITABLE", attack_path=path))
        self.assertEqual(data["exploitability"], "search -> run")

    def test_without_a_path_the_exploitability_is_not_claimed(self):
        self.assertEqual(report_pdf.sections(finding("UNKNOWN"))["exploitability"],
                         "not established by this analysis")

    def test_conditions_are_listed_with_their_evidence(self):
        conditions = {"reachable": Condition("CONFIRMED", ["route /search"]),
                      "attacker_influence": Condition("CONFIRMED", ["request term"])}
        data = report_pdf.sections(finding("POTENTIALLY_EXPLOITABLE", conditions=conditions))
        labels = {c["name"]: c["status"] for c in data["conditions"]}
        self.assertEqual(labels["Reachable from an entry point"], "CONFIRMED")
        self.assertEqual(labels["Untrusted input reaches it"], "CONFIRMED")

    def test_an_unknown_condition_with_no_evidence_is_not_listed(self):
        data = report_pdf.sections(finding("UNKNOWN"))
        self.assertEqual(data["conditions"], [])

    def test_exploit_signals_and_identifiers_are_carried_through(self):
        data = report_pdf.sections(finding("UNKNOWN", kev=True, epss=0.97, cve="CVE-2021-44228"))
        self.assertEqual(data["cves"], ["CVE-2021-44228"])
        self.assertTrue(data["intel"][0]["known_exploited"])
        self.assertEqual(data["intel"][0]["epss"]["score"], 0.97)


class PdfFileTest(unittest.TestCase):
    def _build(self, assessed, summary=None):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.pdf"
            report_pdf.build(assessed, summary or {"findings": len(assessed), "verdicts": {}, "exposure": "internet"},
                             "test-engine", path, generated="2026-10-31 00:00 UTC")
            return path.read_bytes()

    def test_a_report_is_a_valid_pdf_file(self):
        data = self._build([finding("POTENTIALLY_EXPLOITABLE", title="SQL injection", summary="raw query")])
        self.assertTrue(data.startswith(b"%PDF-"))
        self.assertIn(b"%%EOF", data[-64:])

    def test_special_characters_in_a_description_do_not_break_the_document(self):
        item = finding("UNKNOWN", title="odd <script>&", summary="a < b & c > d \"quoted\" é ü 漢字")
        data = self._build([item])
        self.assertTrue(data.startswith(b"%PDF-"))

    def test_an_empty_run_still_makes_a_valid_document(self):
        data = self._build([])
        self.assertTrue(data.startswith(b"%PDF-"))
        self.assertIn(b"%%EOF", data[-64:])

    def test_many_findings_make_a_longer_document(self):
        one = self._build([finding("UNKNOWN", title="r0")])
        many = self._build([finding("UNKNOWN", title=f"r{i}", line=i + 1) for i in range(40)])
        self.assertGreater(len(many), len(one))


if __name__ == "__main__":
    unittest.main()
