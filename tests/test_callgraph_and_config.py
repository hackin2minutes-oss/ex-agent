import json
import shutil
import tempfile
import unittest
from pathlib import Path

from engine import callgraph, pipeline

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"


class PythonCallGraphTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def write(self, name, text):
        path = self.tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def test_route_reaches_sink_through_a_helper(self):
        self.write("app.py", "from flask import Flask\napp = Flask(__name__)\n"
                             "@app.route('/x')\ndef handler():\n    return helper(1)\n"
                             "def helper(v):\n    return sink(v)\n"
                             "def sink(v):\n    return v\n")
        graph = callgraph.build(self.tmp)
        paths = callgraph.paths_to(graph, {"app:sink"})
        self.assertEqual(paths, [["app:handler", "app:helper", "app:sink"]])
        self.assertTrue(all(e["resolution"] == "ast-same-module" for e in graph.edges))

    def test_cycles_do_not_loop(self):
        self.write("app.py", "@app.route('/x')\ndef a():\n    b()\n"
                             "def b():\n    a()\n    target()\n"
                             "def target():\n    pass\n")
        graph = callgraph.build(self.tmp)
        self.assertEqual(callgraph.paths_to(graph, {"app:target"}), [["app:a", "app:b", "app:target"]])

    def test_depth_is_bounded(self):
        chain = "".join(f"def f{i}():\n    f{i + 1}()\n" for i in range(12)) + "def f12():\n    pass\n"
        self.write("app.py", "@app.route('/x')\ndef start():\n    f0()\n" + chain)
        graph = callgraph.build(self.tmp)
        self.assertEqual(callgraph.paths_to(graph, {"app:f12"}), [])

    def test_imported_callee_is_resolved_and_attribute_calls_are_unresolved(self):
        self.write("lib.py", "def sink(v):\n    return v\n")
        self.write("app.py", "from lib import sink\n@app.route('/x')\ndef handler(obj):\n"
                             "    obj.method()\n    sink(1)\n")
        graph = callgraph.build(self.tmp)
        self.assertIn("ast-import", {e["resolution"] for e in graph.edges})
        self.assertIn("method", {u["name"] for u in graph.unresolved})

    def test_syntax_error_is_reported_not_fatal(self):
        self.write("broken.py", "def (:\n")
        graph = callgraph.build(self.tmp)
        self.assertEqual(len(graph.parse_errors), 1)


class PipelineCallPathTest(unittest.TestCase):
    def test_vulnerable_python_app_has_a_call_path_from_its_route(self):
        out = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, out, ignore_errors=True)
        fixture = ROOT / "tests" / "fixtures" / "python-app"
        pipeline.run(fixture, fixture / "requirements.txt", RULES, out, "confirmed_reachable",
                     offline=True, codeql_path="/nonexistent")
        finding = json.loads((out / "evidence.json").read_text())["findings"][0]
        paths = next(e for e in finding["evidence"] if e["type"] == "call_paths")
        self.assertEqual(paths["result"], "confirmed")
        self.assertEqual(paths["paths"][0]["route"], "/config")


class WerkzeugConfigurationTest(unittest.TestCase):
    def run_fixture(self):
        out = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, out, ignore_errors=True)
        fixture = ROOT / "tests" / "fixtures" / "werkzeug-app"
        pipeline.run(fixture, fixture / "requirements.txt", RULES, out, "confirmed_reachable",
                     offline=True, codeql_path="/nonexistent")
        return json.loads((out / "evidence.json").read_text())["findings"]

    def test_debugger_enabled_configuration_is_confirmed(self):
        findings = self.run_fixture()
        werkzeug = [f for f in findings if f["vulnerability"]["cve"] == "CVE-2024-34069"]
        self.assertEqual(len(werkzeug), 1)
        self.assertEqual(werkzeug[0]["stages"]["I_configuration"], "CONFIRMED")
        self.assertEqual(werkzeug[0]["stages"]["B_version"], "CONFIRMED")
        self.assertEqual(werkzeug[0]["classification"], "vulnerable_component_only")


if __name__ == "__main__":
    unittest.main()
