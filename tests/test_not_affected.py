"""NOT_AFFECTED is emitted only with a verified range outside the affected range and no
contradicting source. Missing or unsupported version information is never NOT_AFFECTED."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from engine import intel as intel_module, pipeline
from tests.support import combined_rules_dir

ROOT = Path(__file__).resolve().parent.parent
RULES = combined_rules_dir()
APP = ROOT / "tests" / "fixtures" / "app"


class NotAffectedTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def deps(self, version, ecosystem="Maven", name="com.example:vulnerable-library"):
        path = self.tmp / "deps.json"
        path.write_text(json.dumps({"dependencies": [
            {"ecosystem": ecosystem, "name": name, "version": version, "scope": "runtime"}]}))
        return path

    def run_case(self, deps_path, intel=None):
        out = self.tmp / "out"
        pipeline.run(APP, deps_path, RULES, out, "confirmed_reachable", offline=True,
                     codeql_path="/nonexistent", intel=intel)
        return json.loads((out / "evidence.json").read_text())["findings"]

    def test_affected_version_is_not_reported_as_not_affected(self):
        findings = self.run_case(self.deps("2.4.0"))
        self.assertEqual(findings[0]["classification"], "vulnerable_component_only")

    def test_fixed_version_with_verified_range_is_not_affected(self):
        findings = self.run_case(self.deps("2.4.1"))
        self.assertEqual(findings[0]["classification"], "not_affected")
        self.assertEqual(findings[0]["stages"]["B_version"], "NOT_CONFIRMED")

    def test_prerelease_below_the_fix_is_still_affected(self):
        # 2.4.1-RC1 sorts below 2.4.1, so it is inside the affected range [2.0.0, 2.4.1).
        findings = self.run_case(self.deps("2.4.1-RC1"))
        self.assertEqual(findings[0]["classification"], "vulnerable_component_only")

    def test_missing_version_is_never_not_affected(self):
        findings = self.run_case(self.deps(""))
        self.assertTrue(all(f["classification"] != "not_affected" for f in findings))

    def test_conflicting_advisory_makes_version_unknown(self):
        def fetch(url, body=None):
            if url == intel_module.OSV_URL:
                return json.dumps({"vulns": [{"id": "SYNTHETIC-0001", "aliases": [],
                                              "summary": "x"}]}).encode()
            raise OSError("not recorded")
        intel = intel_module.Intel(fetch=fetch, sleep=lambda s: None)
        findings = self.run_case(self.deps("2.4.1"), intel=intel)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["stages"]["B_version"], "UNKNOWN")
        self.assertEqual(findings[0]["classification"], "unknown")
        self.assertTrue(any("another source says affected" in lim
                            for lim in findings[0]["scope"]["limitations"]))


if __name__ == "__main__":
    unittest.main()
