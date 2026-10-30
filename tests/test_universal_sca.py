"""Read-only projection of SCA evidence onto the universal model.

The SCA pipeline is run on a small PyYAML project (offline, curated rules only). Its evidence.json is
hashed before and after projection, to show the projection does not change SCA output.
"""

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from engine import pipeline, sca_universal
from engine.universal import ANALYSIS_INCOMPLETE, MITIGATED, NOT_AFFECTED, UNKNOWN

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ScaProjectionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.project = self.tmp / "project"
        (self.project / "src").mkdir(parents=True)
        (self.project / "src" / "app.py").write_text(
            "import yaml\n\ndef load(text):\n    return yaml.load(text)\n", encoding="utf-8")

    def scan(self, version):
        deps = self.tmp / f"deps-{version}.json"
        deps.write_text(json.dumps({"dependencies": [
            {"ecosystem": "PyPI", "name": "pyyaml", "version": version, "scope": "runtime"}]}),
            encoding="utf-8")
        out = self.tmp / f"out-{version}"
        pipeline.run(self.project, deps, RULES, out, "confirmed_reachable", offline=True,
                     codeql_path="/nonexistent")
        return out / "evidence.json"

    def test_affected_version_projects_to_unknown_and_leaves_evidence_unchanged(self):
        evidence = self.scan("5.0.0")
        before = sha(evidence)
        projected = sca_universal.project_evidence(evidence)
        self.assertEqual(sha(evidence), before)
        (finding,) = projected
        self.assertEqual(finding["category"], "SCA")
        self.assertEqual(finding["assessment"]["verdict"], UNKNOWN)
        self.assertEqual(finding["assessment"]["conditions"]["vulnerability_exists"]["status"],
                         "CONFIRMED")
        self.assertEqual(finding["location"]["path"], "src/app.py")
        self.assertEqual(finding["vulnerability"]["rule_id"], "CVE-2017-18342")

    def test_fixed_version_projects_to_not_affected_with_stage_evidence(self):
        evidence = self.scan("5.1")
        (finding,) = sca_universal.project_evidence(evidence)
        self.assertEqual(finding["assessment"]["verdict"], NOT_AFFECTED)
        self.assertEqual(finding["assessment"]["conditions"]["vulnerability_exists"]["status"],
                         "NOT_CONFIRMED")
        self.assertTrue(any(e["condition"] == "vulnerability_exists" for e in finding["assessment"]["evidence"]))

    def test_projection_never_produces_mitigated(self):
        for version in ("5.0.0", "5.1"):
            for finding in sca_universal.project_evidence(self.scan(version)):
                self.assertNotEqual(finding["assessment"]["verdict"], MITIGATED)

    def test_legacy_verdict_the_stages_do_not_support_is_incomplete_not_a_verdict(self):
        record = {
            "id": "CVE-X", "library": "x", "classification": "not_reachable_within_analysed_scope",
            "classification_reason": "claimed not reachable", "confidence": "low",
            "vulnerability": {"id": "CVE-X", "summary": "s", "aliases": []},
            "dependency": {"manifest": "m"}, "evidence": [],
            "stages": {"E_function_reachability": "UNKNOWN"},
        }
        finding = sca_universal.project_record(record)
        self.assertEqual(finding["assessment"]["verdict"], ANALYSIS_INCOMPLETE)
        self.assertIn("not supported by its stages", finding["assessment"]["reason"])


if __name__ == "__main__":
    unittest.main()
