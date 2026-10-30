import tempfile
import unittest
from pathlib import Path

from engine import exploitability, policy

POLICY = """
version: 1
exploitability:
  confirmed_exploitable:
    critical: block
    high: block
    medium: block
  potentially_exploitable:
    critical: block
    high: warn
    medium: warn
  reachable_preconditions_unknown:
    action: warn
  vulnerable_component_only:
    action: report
  not_reachable_within_analysed_scope:
    action: report
  unknown:
    action: warn
  analysis_failed:
    action: warn
intelligence:
  kev:
    increase_priority: true
"""


class PolicyTest(unittest.TestCase):
    def load(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.yml"
            path.write_text(text)
            return policy.load_policy(path)

    def test_documented_example_loads(self):
        loaded = self.load(POLICY)
        self.assertEqual(loaded["exploitability"]["confirmed_exploitable"]["critical"], "block")

    def test_severity_rule_selects_action(self):
        loaded = self.load(POLICY)
        self.assertEqual(policy.action_for(loaded, "potentially_exploitable", "high"),
                         ("warn", "exploitability.potentially_exploitable.high"))

    def test_critical_confirmed_exploitable_blocks(self):
        loaded = self.load(POLICY)
        self.assertEqual(policy.action_for(loaded, "confirmed_exploitable", "CRITICAL")[0], "block")

    def test_class_level_action(self):
        loaded = self.load(POLICY)
        self.assertEqual(policy.action_for(loaded, "reachable_preconditions_unknown", "high")[0], "warn")

    def test_unknown_severity_warns_not_silently_reports(self):
        loaded = self.load(POLICY)
        self.assertEqual(policy.action_for(loaded, "not_reachable_within_analysed_scope", None)[0], "report")
        self.assertEqual(policy.action_for(loaded, "unknown", None)[0], "warn")

    def test_unlisted_classification_defaults_to_report(self):
        loaded = self.load("version: 1\n")
        self.assertEqual(policy.action_for(loaded, "not_affected", "high")[0], "report")

    def test_evaluate_marks_blocking_findings(self):
        loaded = self.load(POLICY)
        findings = [
            {"classification": "confirmed_exploitable", "vulnerability": {"severity": "critical"}},
            {"classification": "vulnerable_component_only", "vulnerability": {"severity": "high"}},
        ]
        summary = policy.evaluate(loaded, findings)
        self.assertTrue(summary["blocked"])
        self.assertEqual(summary["decisions"]["block"], 1)
        self.assertEqual(findings[1]["policy"]["action"], "report")

    def test_every_documented_classification_is_accepted_as_a_key(self):
        for name in exploitability.CLASSIFICATIONS:
            self.load(f"version: 1\nexploitability:\n  {name}:\n    action: report\n")

    def test_rejects_unknown_top_level_key(self):
        with self.assertRaises(policy.PolicyError):
            self.load("version: 1\nexploit: {}\n")

    def test_rejects_unknown_classification(self):
        with self.assertRaises(policy.PolicyError):
            self.load("version: 1\nexploitability:\n  confirmed_exploitabel:\n    action: block\n")

    def test_rejects_invalid_action(self):
        with self.assertRaises(policy.PolicyError):
            self.load("version: 1\nexploitability:\n  confirmed_exploitable:\n    action: allow\n")

    def test_rejects_unknown_severity(self):
        with self.assertRaises(policy.PolicyError):
            self.load("version: 1\nexploitability:\n  confirmed_exploitable:\n    severe: block\n")

    def test_rejects_wrong_version(self):
        with self.assertRaises(policy.PolicyError):
            self.load("version: 2\n")

    def test_rejects_non_mapping(self):
        with self.assertRaises(policy.PolicyError):
            self.load("- a\n- b\n")


if __name__ == "__main__":
    unittest.main()
