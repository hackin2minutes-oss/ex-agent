"""The investigation command line. The offline run needs no key. The anthropic run without a key must refuse, not fall back."""

import contextlib
import io
import json
import os
import unittest
from pathlib import Path
from unittest import mock

from engine.investigation.__main__ import main

PROJECT = Path(__file__).resolve().parent / "fixtures" / "investigation" / "project"


class CommandLineTest(unittest.TestCase):
    def _run(self, *extra):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(["--project-dir", str(PROJECT), "--path", "app.py", "--line", "6", "--symbol", "eval",
                         *extra])
        return code, json.loads(out.getvalue())

    def test_offline_run_prints_the_result_as_json(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            code, result = self._run("--planner", "offline")
        self.assertEqual(code, 0)
        self.assertEqual(result["planner"], "offline")
        self.assertEqual(result["verdict"], "UNKNOWN")
        self.assertTrue(result["missing_evidence"])

    def test_anthropic_without_a_key_exits_2_and_says_why(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            code, result = self._run("--planner", "anthropic")
        self.assertEqual(code, 2)
        self.assertEqual(result["verdict"], "ANALYSIS_INCOMPLETE")
        self.assertIn("ANTHROPIC_API_KEY", result["reason"])


if __name__ == "__main__":
    unittest.main()
