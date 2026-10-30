"""Argument-aware precondition checks (F-03).

A sink check is satisfied only when the sink argument is request-derived. Constants,
unresolved values, sanitisers and absent sinks must never satisfy it.
"""

import tempfile
import unittest
from pathlib import Path

from engine import preconditions

PY_YAML = {"id": "unsafe", "kind": "requires", "glob": "**/*.py", "sink": "yaml.load", "argument": 0}
GO_FILE = {"id": "attach", "kind": "requires", "glob": "**/*.go", "sink": "FileAttachment", "argument": 1}
JS_MERGE = {"id": "merge", "kind": "requires", "glob": "**/*.[jt]s", "sink": "defaultsDeep", "argument": "any"}


def run_check(check, files: dict[str, str]) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for name, text in files.items():
            (root / name).write_text(text, encoding="utf-8")
        status, details = preconditions.evaluate([check], root)
    return {"status": status, "result": details[0]}


class PythonSinkTests(unittest.TestCase):
    def assertUnverified(self, outcome):
        self.assertEqual(outcome["status"], "unverified", outcome["result"])
        self.assertEqual(outcome["result"]["result"], "unverified")

    def test_request_data_as_argument_satisfies(self):
        outcome = run_check(PY_YAML, {"app.py": "import yaml\ndef f():\n    return yaml.load(request.data)\n"})
        self.assertEqual(outcome["status"], "satisfied")
        self.assertEqual(outcome["result"]["locations"][0]["argument_class"], "request")

    def test_constant_argument_never_satisfies(self):
        outcome = run_check(PY_YAML, {"app.py": 'import yaml\nyaml.load("a: 1")\n'})
        self.assertUnverified(outcome)
        self.assertIn("constant", outcome["result"]["reason"])

    def test_request_value_through_assignment_satisfies(self):
        source = "import yaml\ndef f():\n    raw = request.get_data()\n    return yaml.load(raw)\n"
        self.assertEqual(run_check(PY_YAML, {"app.py": source})["status"], "satisfied")

    def test_constant_assigned_to_a_variable_does_not_satisfy(self):
        source = 'import yaml\ndef f():\n    raw = "a: 1"\n    return yaml.load(raw)\n'
        self.assertUnverified(run_check(PY_YAML, {"app.py": source}))

    def test_argument_from_unanalysed_helper_is_unknown(self):
        source = "import yaml\ndef f():\n    return yaml.load(helper())\n"
        outcome = run_check(PY_YAML, {"app.py": source})
        self.assertUnverified(outcome)
        self.assertIn("not established", outcome["result"]["reason"])

    def test_sanitised_request_data_is_unknown_not_constant(self):
        source = "import yaml\ndef f():\n    return yaml.load(int(request.args['n']))\n"
        self.assertUnverified(run_check(PY_YAML, {"app.py": source}))

    def test_request_in_the_wrong_argument_position_does_not_satisfy(self):
        source = 'import yaml\ndef f():\n    return yaml.load("a: 1", Loader=request.args.get("l"))\n'
        self.assertUnverified(run_check(PY_YAML, {"app.py": source}))

    def test_one_request_driven_call_among_constant_calls_satisfies(self):
        source = ('import yaml\ndef f():\n    yaml.load("a: 1")\n'
                  'def g():\n    return yaml.load(request.form["doc"])\n')
        outcome = run_check(PY_YAML, {"app.py": source})
        self.assertEqual(outcome["status"], "satisfied")
        self.assertEqual([loc["line"] for loc in outcome["result"]["locations"]], [5])

    def test_absent_sink_is_unverified(self):
        self.assertUnverified(run_check(PY_YAML, {"app.py": "print('hi')\n"}))

    def test_unparseable_file_is_unverified(self):
        outcome = run_check(PY_YAML, {"app.py": "def broken(:\n"})
        self.assertUnverified(outcome)

    def test_nul_byte_in_source_is_unverified_not_a_crash(self):
        outcome = run_check(PY_YAML, {"app.py": "yaml.load(request.data)\n\x00"})
        self.assertUnverified(outcome)

    def test_pathologically_deep_argument_is_unknown_not_a_crash(self):
        # Parses fine, but the classifier would recurse ~3000 levels deep.
        deep = "+".join(["x"] * 3000)
        source = f"import yaml\ndef f(x):\n    return yaml.load({deep})\n"
        outcome = run_check(PY_YAML, {"app.py": source})
        self.assertUnverified(outcome)
        self.assertEqual(outcome["result"]["locations"][0]["argument_class"], "unknown")


class LexicalSinkTests(unittest.TestCase):
    def test_go_request_filename_satisfies(self):
        source = 'package main\nfunc h(c *gin.Context) {\n\tc.FileAttachment("report.pdf", c.Query("name"))\n}\n'
        self.assertEqual(run_check(GO_FILE, {"main.go": source})["status"], "satisfied")

    def test_go_constant_filename_is_unverified(self):
        source = 'package main\nfunc h(c *gin.Context) {\n\tc.FileAttachment("report.pdf", "report.pdf")\n}\n'
        outcome = run_check(GO_FILE, {"main.go": source})
        self.assertEqual(outcome["status"], "unverified")
        self.assertIn("constant", outcome["result"]["reason"])

    def test_go_request_value_through_assignment_satisfies(self):
        source = ('package main\nfunc h(c *gin.Context) {\n\tname := c.Query("n")\n'
                  '\tc.FileAttachment("report.pdf", name)\n}\n')
        self.assertEqual(run_check(GO_FILE, {"main.go": source})["status"], "satisfied")

    def test_go_call_spanning_lines_is_unknown(self):
        source = 'package main\nfunc h(c *gin.Context) {\n\tc.FileAttachment("report.pdf",\n\t\tc.Query("n"))\n}\n'
        outcome = run_check(GO_FILE, {"main.go": source})
        self.assertEqual(outcome["status"], "unverified")

    def test_js_request_body_satisfies(self):
        source = "app.post('/x', (req, res) => {\n  res.json(_.defaultsDeep(req.body, defaults));\n});\n"
        self.assertEqual(run_check(JS_MERGE, {"app.js": source})["status"], "satisfied")

    def test_js_constant_objects_are_unverified(self):
        source = "const out = _.defaultsDeep({ a: 1 }, defaults);\n"
        self.assertEqual(run_check(JS_MERGE, {"app.js": source})["status"], "unverified")

    def test_js_unrelated_name_is_not_tainted(self):
        source = ("const req = makeFake();\nconst body = { a: 1 };\n"
                  "const out = _.defaultsDeep(body, defaults);\n")
        self.assertEqual(run_check(JS_MERGE, {"app.js": source})["status"], "unverified")

    def test_unsupported_language_is_unverified(self):
        check = {"id": "x", "kind": "requires", "glob": "**/*.java", "sink": "defaultsDeep", "argument": 0}
        outcome = run_check(check, {"Main.java": "defaultsDeep(req.body);\n"})
        self.assertEqual(outcome["status"], "unverified")
        self.assertIn("no taint model", outcome["result"]["locations"][0]["reason"])


class ValidationTests(unittest.TestCase):
    def test_sink_on_mitigated_by_is_rejected(self):
        bad = {"id": "x", "kind": "mitigated_by", "glob": "**/*.py", "sink": "yaml.load", "argument": 0}
        with self.assertRaises(ValueError):
            run_check(bad, {"a.py": "yaml.load(x)\n"})

    def test_invalid_argument_position_is_rejected(self):
        bad = {"id": "x", "kind": "requires", "glob": "**/*.py", "sink": "yaml.load", "argument": -1}
        with self.assertRaises(ValueError):
            run_check(bad, {"a.py": "yaml.load(x)\n"})


if __name__ == "__main__":
    unittest.main()
