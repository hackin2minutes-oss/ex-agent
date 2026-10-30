"""Per-alert guidance: every alert gets a fix, an UNKNOWN fix is labelled as generic, and a SAST fix is the injection fix
only when the weakness is an injection class. The report shows one block per alert."""

import unittest

from engine import guidance, universal_report
from engine.universal import UNKNOWN, make_assessment, make_finding


def unknown_alert(category: str, title: str, message: str, path: str = "a.yml"):
    finding = make_finding(category=category, rule_id=title, title=title,
                           asset={"type": "source_location", "name": path},
                           location={"path": path, "start_line": 3, "end_line": 3, "start_col": None,
                                     "end_col": None},
                           severity_reported="warning", provenance={"scanner": "test"}, original={},
                           summary=message)
    finding["exploitability_context"]["exposure"] = "unknown"
    finding["assessment"] = make_assessment(UNKNOWN, reason="no analysis for this file type", engine="test",
                                            limitations=["no analysis"], exposure="unknown").to_dict()
    return finding


class GuidanceTest(unittest.TestCase):
    def test_a_yaml_rule_gets_the_scanners_guidance_not_the_injection_fix(self):
        finding = guidance.enrich(unknown_alert(
            "SAST", "mutable-action-tag", "GitHub Actions step uses a mutable tag or branch reference."))
        remediation = finding["assessment"]["recommended_remediation"]
        self.assertTrue(remediation.startswith("Generic fix, not a verdict"))
        self.assertIn("mutable tag or branch reference", remediation)
        self.assertNotIn("parameterised", remediation)

    def test_an_injection_class_gets_the_injection_fix_labelled_generic(self):
        finding = guidance.enrich(unknown_alert("SAST", "rule", "SQL injection in the search handler"))
        remediation = finding["assessment"]["recommended_remediation"]
        self.assertIn("parameterised", remediation)
        self.assertIn("not a verdict", remediation)

    def test_a_non_sast_alert_gets_its_category_fix(self):
        finding = guidance.enrich(unknown_alert("CICD", "zizmor/unpinned-uses", "unpinned action",
                                                path=".github/workflows/x.yml"))
        self.assertIn("pin", finding["assessment"]["recommended_remediation"])

    def test_a_non_sast_alert_is_not_asked_to_trace_attacker_input(self):
        finding = guidance.enrich(unknown_alert("SECRET", "rule", "hard-coded key", path="config.json"))
        self.assertNotIn("attacker", finding["assessment"]["next_investigation"])
        self.assertIn("Confirm the flagged file", finding["assessment"]["next_investigation"])

    def test_every_alert_has_a_remediation(self):
        finding = guidance.enrich(unknown_alert("IAC", "rule", "public bucket"))
        self.assertTrue(finding["assessment"]["recommended_remediation"])


class ReportTest(unittest.TestCase):
    def test_the_report_has_one_block_per_alert_with_verdict_how_and_remediation(self):
        alerts = [guidance.enrich(unknown_alert("SAST", "mutable-action-tag", "mutable tag", path="hyt.yml")),
                  guidance.enrich(unknown_alert("CICD", "zizmor/artipacked", "credentials kept", path="lomn.yml"))]
        summary = {"findings": 2, "verdicts": {"UNKNOWN": 2}, "exposure": "unknown", "adapters": ["sarif"],
                   "engines": [], "diagnostics": [], "limitations": []}
        markdown = universal_report.to_markdown(summary, alerts)
        self.assertIn("### Per-alert detail", markdown)
        self.assertEqual(markdown.count("#### "), 2)
        self.assertIn("**Verdict:** UNKNOWN", markdown)
        self.assertIn("**How it could be exploited:** not established by this analysis", markdown)
        self.assertEqual(markdown.count("**Remediation:**"), 2)

    def test_an_empty_run_has_no_detail_section(self):
        summary = {"findings": 0, "verdicts": {}, "exposure": "unknown", "adapters": [], "engines": [],
                   "diagnostics": [], "limitations": []}
        self.assertNotIn("Per-alert detail", universal_report.to_markdown(summary, []))


if __name__ == "__main__":
    unittest.main()
