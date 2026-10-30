import json
import shutil
import tempfile
import unittest
from pathlib import Path

from engine import pipeline

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "app"


class ConfigurationStageTest(unittest.TestCase):
    """Stage I comes from configuration checks in a rule. No shipped rule has them yet."""

    def run_with_rule(self, configuration, config_text=None):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        rules = tmp / "rules"
        rules.mkdir()
        rule = json.loads((ROOT / "rules" / "CVE-XXXX-XXXX.json").read_text())
        rule["configuration"] = configuration
        (rules / "rule.json").write_text(json.dumps(rule))
        project = tmp / "app"
        shutil.copytree(FIXTURE, project)
        if config_text is not None:
            (project / "application.properties").write_text(config_text)
        out = tmp / "out"
        pipeline.run(project, FIXTURE / "resolved-deps.json", rules, out, "confirmed_reachable",
                     offline=True, codeql_path="/nonexistent")
        return json.loads((out / "evidence.json").read_text())["findings"][0]

    def check(self, regex, kind="requires"):
        return [{"id": "cfg", "kind": kind, "glob": "**/*.properties", "regex": regex}]

    def test_no_configuration_checks_leaves_stage_unknown(self):
        finding = self.run_with_rule(None)
        self.assertEqual(finding["stages"]["I_configuration"], "UNKNOWN")

    def test_enabled_configuration_is_confirmed(self):
        finding = self.run_with_rule(self.check(r"parser\.strict=true"),
                                     config_text="parser.strict=true\n")
        self.assertEqual(finding["stages"]["I_configuration"], "CONFIRMED")
        self.assertTrue(any(e["type"] == "configuration" for e in finding["evidence"]))

    def test_disabling_configuration_is_not_confirmed(self):
        finding = self.run_with_rule(self.check(r"parser\.strict=true", kind="mitigated_by"),
                                     config_text="parser.strict=true\n")
        self.assertEqual(finding["stages"]["I_configuration"], "NOT_CONFIRMED")

    def test_absent_configuration_stays_unknown(self):
        finding = self.run_with_rule(self.check(r"parser\.strict=true"), config_text="other=1\n")
        self.assertEqual(finding["stages"]["I_configuration"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
