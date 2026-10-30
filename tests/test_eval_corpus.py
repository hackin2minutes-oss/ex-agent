"""Regression tests for the evaluation corpus (tests/eval/corpus). Each case's verdict is pinned to the expected verdict in
its case.json. A verdict that changes is a deliberate change: update the case and say why in the commit.

Known limits are pinned too, so they cannot change silently. Case 12 is a known false positive, and its expected
verdict is the current (wrong) one, with the reason in its description.
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from engine import universal_run

CORPUS = Path(__file__).resolve().parent / "eval" / "corpus"


def run_case(case_dir: Path, out: Path) -> dict:
    case = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
    universal_run.run([case_dir / "semgrep.json"], case_dir, out, exposure=case["exposure"], offline=True)
    return {"case": case, "findings": json.loads((out / "universal-findings.json").read_text(encoding="utf-8"))["findings"]}


class CorpusRegressionTest(unittest.TestCase):
    def test_every_case_gets_its_expected_verdict(self):
        scratch = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, scratch, ignore_errors=True)
        cases = sorted(p for p in CORPUS.iterdir() if p.is_dir())
        self.assertGreaterEqual(len(cases), 14)
        for case_dir in cases:
            with self.subTest(case=case_dir.name):
                result = run_case(case_dir, scratch / case_dir.name)
                if case_dir.name == "11_unparseable_python":
                    # The scanner could not parse it either, so no finding is reported and none is assessed.
                    self.assertEqual(result["findings"], [])
                    continue
                self.assertEqual(len(result["findings"]), 1)
                self.assertEqual(result["findings"][0]["assessment"]["verdict"], result["case"]["expected_verdict"])


class ReachabilityRulesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def project(self, files):
        root = self.tmp / "project"
        for rel, text in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        return root

    def reach(self, root, rel, line):
        from engine.application import Application
        return Application(root).reachability(rel, line)

    ROUTE = "from flask import Flask\napp = Flask(__name__)\n\n\n@app.route('/x')\ndef handler():\n    return helper()\n\n\n"

    def test_helper_on_a_route_path_is_confirmed(self):
        root = self.project({"v.py": self.ROUTE + "def helper():\n    return 1\n"})
        reach = self.reach(root, "v.py", 11)
        self.assertEqual(reach.status, "CONFIRMED")
        self.assertIn("/x", reach.reason)

    def test_unreached_helper_is_not_reachable_only_when_the_search_is_complete(self):
        root = self.project({"v.py": self.ROUTE + "def orphan():\n    return 1\n"})
        self.assertEqual(self.reach(root, "v.py", 11).status, "NOT_CONFIRMED")

    def test_no_routes_means_the_attack_surface_is_unknown(self):
        root = self.project({"lib.py": "def helper():\n    return 1\n"})
        reach = self.reach(root, "lib.py", 2)
        self.assertEqual(reach.status, "UNKNOWN")
        self.assertFalse(reach.surface_known)

    def test_callback_reference_is_a_possible_entry_not_an_attack_path(self):
        # The route does not call helper. The only link is a dispatch table that references it as a value.
        route = ("from flask import Flask\napp = Flask(__name__)\n\n\n@app.route('/x')\ndef handler():\n"
                 "    return 'ok'\n\n\n")
        root = self.project({"v.py": route + "def helper():\n    return 1\n\n\nTABLE = {'h': helper}\n"})
        reach = self.reach(root, "v.py", 11)
        self.assertEqual(reach.status, "UNKNOWN")
        self.assertIn("may run without a route", reach.reason)

    def test_dynamic_dispatch_makes_an_unreached_function_unknown(self):
        root = self.project({"v.py": self.ROUTE + "def helper():\n    return 1\n\n\n"
                                     "def dispatch(name):\n    return getattr(obj, name)()\n"})
        reach = self.reach(root, "v.py", 11)
        self.assertNotEqual(reach.status, "NOT_CONFIRMED")

    def test_unresolved_call_with_a_project_name_makes_the_search_incomplete(self):
        root = self.project({
            "db.py": "def run(name):\n    return name\n",
            "v.py": "from flask import Flask\napp = Flask(__name__)\n\n\n@app.route('/x')\ndef handler(obj):\n"
                    "    return obj.run('x')\n",
        })
        self.assertNotEqual(self.reach(root, "db.py", 2).status, "NOT_CONFIRMED")

    def test_sibling_import_resolves_across_modules(self):
        root = self.project({
            "app/__init__.py": "",
            "app/db.py": "def run(name):\n    return name\n",
            "app/v.py": "from flask import Flask\nfrom db import run\napp = Flask(__name__)\n\n\n"
                        "@app.route('/x')\ndef handler():\n    return run('x')\n",
        })
        self.assertEqual(self.reach(root, "app/db.py", 2).status, "CONFIRMED")


if __name__ == "__main__":
    unittest.main()
