"""Resource budgets, list input and the wall-clock timeout of the universal runner."""

import io
import json
import shutil
import tempfile
import time
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

from engine import universal_run

ROOT = Path(__file__).resolve().parent.parent
SEMGREP = ROOT / "tests" / "fixtures" / "sast" / "semgrep-1.183.0.real.json"
SAST_PROJECT = ROOT / "tests" / "fixtures" / "sast" / "project"
TRIVY = ROOT / "tests" / "fixtures" / "scanner-exports" / "trivy-fs-python-app.real.json"
PYTHON_APP = ROOT / "tests" / "fixtures" / "python-app"


class LimitsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_report_over_the_byte_budget_is_skipped_with_a_diagnostic(self):
        # The budget sits between the two sizes (Semgrep ~2.7 kB, Trivy ~11 kB), so only Trivy is over it.
        summary = universal_run.run([SEMGREP, TRIVY], SAST_PROJECT, self.tmp / "out",
                                    max_report_bytes=5000)
        routes = {item["input"]: item["route"] for item in summary["inputs"]}
        self.assertEqual(routes[TRIVY.name], "skipped")
        self.assertEqual(routes[SEMGREP.name], "semgrep")
        self.assertTrue(any("exceeds the 5000-byte budget" in d for d in summary["diagnostics"]))

    def test_every_report_over_budget_refuses_the_run(self):
        with self.assertRaises(universal_run.ModelError):
            universal_run.run([SEMGREP, TRIVY], SAST_PROJECT, self.tmp / "out", max_report_bytes=1000)

    def test_report_over_the_record_budget_is_skipped_not_truncated(self):
        with self.assertRaises(universal_run.ModelError):
            universal_run.run([SEMGREP], SAST_PROJECT, self.tmp / "out", max_records=1)

    def test_comma_separated_list_is_read_as_several_reports(self):
        out = self.tmp / "out"
        listed = f"{SEMGREP},{TRIVY}"
        code = universal_run.main(["--inputs", listed, "--project-dir", str(PYTHON_APP),
                                   "--output-dir", str(out), "--offline", "true"])
        self.assertEqual(code, 0)
        summary = json.loads((out / "universal-findings.json").read_text(encoding="utf-8"))["summary"]
        self.assertEqual({item["input"] for item in summary["inputs"]}, {SEMGREP.name, TRIVY.name})

    def test_no_input_is_a_usage_error(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            universal_run.main(["--project-dir", str(PYTHON_APP), "--output-dir", str(self.tmp / "out")])

    def test_run_that_exceeds_the_timeout_exits_with_the_timeout_code(self):
        def slow(*args, **kwargs):
            time.sleep(5)

        err = io.StringIO()
        with mock.patch.object(universal_run, "run", side_effect=slow), redirect_stderr(err):
            code = universal_run.main(["--input", str(SEMGREP), "--project-dir", str(SAST_PROJECT),
                                       "--output-dir", str(self.tmp / "out"), "--timeout-seconds", "1"])
        self.assertEqual(code, universal_run.EXIT_TIMEOUT)
        self.assertIn("exceeded 1 seconds", err.getvalue())


if __name__ == "__main__":
    unittest.main()


class RulesDirTest(unittest.TestCase):
    """An empty rules path must mean the rules shipped with the engine. Resolving it against the current
    directory silently loaded zero rules, which gave zero SCA findings in the container."""

    def test_empty_rules_path_resolves_to_shipped_rules(self):
        from engine import __main__ as sca_main
        self.assertEqual(sca_main.SHIPPED_RULES, universal_run.DEFAULT_RULES)
        self.assertTrue(any(universal_run.DEFAULT_RULES.glob("*.json")))

    def test_universal_run_without_rules_dir_uses_shipped_rules(self):
        self.assertEqual(universal_run.DEFAULT_RULES, ROOT / "rules")
