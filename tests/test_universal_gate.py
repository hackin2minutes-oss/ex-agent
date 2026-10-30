"""Gate for the universal runner. The default gate fails only on CONFIRMED_EXPLOITABLE. The stricter
gate also fails on POTENTIALLY_EXPLOITABLE. No engine in this build produces CONFIRMED_EXPLOITABLE
for real input, so the default gate is tested with a stub engine that does."""

import shutil
import tempfile
import unittest
from pathlib import Path

from engine import universal_run
from engine.universal import (
    CONFIRMED, CONFIRMED_EXPLOITABLE, Condition, Engine, ModelError, Registry, make_assessment,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "sast"
REAL = FIXTURES / "semgrep-1.183.0.real.json"
PROJECT = FIXTURES / "project"


class ConfirmingEngine(Engine):
    name = "stub-confirm"
    categories = ("SAST",)

    def assess(self, finding, context):
        conditions = {n: Condition(CONFIRMED, ["stub"]) for n in
                      ("reachable", "attacker_influence", "preconditions")}
        evidence = [{"condition": n, "kind": "stub", "detail": "stub"} for n in conditions]
        return make_assessment(CONFIRMED_EXPLOITABLE, reason="stub", engine=self.name,
                               conditions=conditions, evidence=evidence,
                               exposure=context["exposure"])


class GateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.out = self.tmp / "out"

    def test_default_gate_passes_on_potential_only_results(self):
        summary = universal_run.run(REAL, PROJECT, self.out)
        self.assertEqual(summary["gate"], {"fail_on": "confirmed_exploitable", "failed": False,
                                           "failing_findings": []})
        self.assertEqual(universal_run.main(["--input", str(REAL), "--project-dir", str(PROJECT),
                                             "--output-dir", str(self.out)]), 0)

    def test_stricter_gate_fails_on_potential_results(self):
        self.assertEqual(universal_run.main(["--input", str(REAL), "--project-dir", str(PROJECT),
                                             "--output-dir", str(self.out),
                                             "--fail-on", "potentially_exploitable"]), 1)

    def test_default_gate_fails_on_a_confirmed_verdict(self):
        registry = Registry()
        registry.register_adapter(universal_run.build_registry().adapter("semgrep"))
        registry.register_engine(ConfirmingEngine())
        summary = universal_run.run(REAL, PROJECT, self.out, exposure="internet", registry=registry)
        self.assertTrue(summary["gate"]["failed"])
        self.assertEqual(len(summary["gate"]["failing_findings"]), 3)  # the stub confirms every SAST finding

    def test_unknown_gate_is_refused(self):
        with self.assertRaises(ModelError):
            universal_run.run(REAL, PROJECT, self.out, fail_on="everything")


if __name__ == "__main__":
    unittest.main()
