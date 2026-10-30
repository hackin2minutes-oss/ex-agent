"""Verification of the F-01 call-graph remediation.

Each test corresponds to one check in the F-01 verification request. They exercise the
construction code and the pipeline function that turns a graph into a call-path result.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

from engine import callgraph, pipeline, report
from tests.test_callgraph_scale import make_project


class CallGraphVerificationTest(unittest.TestCase):
    def setUp(self):
        self.dirs = []
        self.addCleanup(lambda: [shutil.rmtree(d, ignore_errors=True) for d in self.dirs])

    def tmp(self, files: dict[str, str]) -> Path:
        root = Path(tempfile.mkdtemp())
        self.dirs.append(root)
        for name, text in files.items():
            (root / name).write_text(text)
        return root

    def project(self, *args, **kwargs) -> Path:
        root = make_project(*args, **kwargs)
        self.dirs.append(root)
        return root

    # 2. Limits are enforced during construction, not afterwards.
    def test_node_limit_is_never_exceeded(self):
        g = callgraph.build(self.project(60), max_nodes=500)
        self.assertEqual(len(g.nodes), 500)
        self.assertEqual(g.skipped_nodes, 60 * 30 + 1 - 500)

    def test_edge_limit_is_never_exceeded(self):
        g = callgraph.build(self.project(20), max_edges=123)
        self.assertEqual(len(g.edges), 123)
        self.assertEqual(g.summary()["skipped_edges"] > 0, True)

    # 3. Every retained edge references retained nodes.
    def assertEdgesReferenceRetainedNodes(self, g):
        for edge in g.edges:
            self.assertIn(edge["from"], g.nodes, edge)
            self.assertIn(edge["to"], g.nodes, edge)
        # The adjacency view must agree with the edge list.
        adjacency = {(e["from"], e["to"]) for e in g.edges}
        for source in {e["from"] for e in g.edges}:
            for target in g.successors(source):
                self.assertIn((source, target), adjacency)

    def test_edges_reference_retained_nodes_when_nodes_are_truncated(self):
        g = callgraph.build(self.project(120), max_nodes=1000)
        self.assertGreater(g.skipped_nodes, 0)
        self.assertGreater(len(g.edges), 0)
        self.assertEdgesReferenceRetainedNodes(g)

    def test_edges_reference_retained_nodes_when_edges_are_truncated(self):
        g = callgraph.build(self.project(20), max_edges=200)
        self.assertGreater(g.skipped_edges, 0)
        self.assertEdgesReferenceRetainedNodes(g)

    def test_edges_reference_retained_nodes_at_default_scale(self):
        g = callgraph.build(self.project(2000))
        self.assertFalse(g.complete)
        self.assertEdgesReferenceRetainedNodes(g)

    # 4. Truncation metadata reaches the pipeline evidence.
    def test_summary_carries_truncation_metadata(self):
        g = callgraph.build(self.project(120), max_nodes=500)
        summary = g.summary()
        self.assertFalse(summary["complete"])
        self.assertIn("node_limit", summary["incomplete_reasons"])
        self.assertEqual(summary["skipped_nodes"], g.skipped_nodes)

    def test_pipeline_call_paths_evidence_carries_graph_summary(self):
        root = self.project(120)
        g = callgraph.build(root, max_nodes=500)
        hits = [{"file": "m00000.py", "line": 1, "symbol": "x"}]
        _, _, summary = pipeline._python_call_paths(hits, root, {"python_graph": g})
        self.assertFalse(summary["complete"])
        self.assertEqual(summary["skipped_nodes"], g.skipped_nodes)

    # 5. An incomplete graph never yields a definitive "not found" call-path result.
    def test_truncated_graph_without_a_path_is_incomplete_not_not_found(self):
        # Module a holds the route and the target. The route does not reach the target, and
        # the graph is truncated by the cap, so the absence of a path is unknown.
        root = self.tmp({
            "a.py": "@app.route('/a')\ndef entry():\n    pass\ndef target():\n    pass\n",
            "b.py": "def other():\n    pass\n",
        })
        # Three functions exist, so a cap of two skips b.py's function.
        g = callgraph.build(root, max_nodes=2)
        self.assertFalse(g.complete)
        result, paths, _ = pipeline._python_call_paths(
            [{"file": "a.py", "line": 5, "symbol": "x"}], root, {"python_graph": g})
        self.assertEqual(paths, [])
        self.assertEqual(result, "incomplete")

    def test_hit_outside_any_retained_node_is_incomplete(self):
        root = self.project(120)
        g = callgraph.build(root, max_nodes=50)
        last = sorted(p.name for p in root.glob("*.py"))[-1]
        result, _, _ = pipeline._python_call_paths(
            [{"file": last, "line": 2, "symbol": "x"}], root, {"python_graph": g})
        self.assertEqual(result, "incomplete")

    # 6. Unresolved calls mark the affected searches as incomplete.
    def test_unresolved_call_on_the_path_makes_absence_unknown(self):
        root = self.tmp({"app.py": "@app.route('/x')\ndef entry(obj):\n    obj.load()\n"
                                   "def target():\n    pass\n"})
        g = callgraph.build(root)
        self.assertIn("app:entry", g.unresolved_from)
        paths, search_complete = callgraph.paths_to(g, {"app:target"})
        self.assertEqual(paths, [])
        self.assertFalse(search_complete)

    def test_unresolved_call_elsewhere_does_not_affect_a_path_that_exists(self):
        root = self.tmp({"app.py": "@app.route('/x')\ndef entry():\n    target()\n"
                                   "    obj.load()\ndef target():\n    pass\n"})
        g = callgraph.build(root)
        paths, _ = callgraph.paths_to(g, {"app:target"})
        self.assertEqual(paths, [["app:entry", "app:target"]])

    # 7. A genuinely complete search with no path returns a definitive no-path result.
    def test_complete_search_with_no_path_is_definitive(self):
        root = self.tmp({
            "a.py": "@app.route('/a')\ndef entry():\n    helper()\ndef helper():\n    pass\n"
                    "def target():\n    pass\n",
        })
        g = callgraph.build(root)
        self.assertTrue(g.complete)
        paths, search_complete = callgraph.paths_to(g, {"a:target"})
        self.assertEqual(paths, [])
        self.assertTrue(search_complete)
        result, _, _ = pipeline._python_call_paths(
            [{"file": "a.py", "line": 6, "symbol": "x"}], root, {"python_graph": g})
        self.assertEqual(result, "not_found")

    def test_complete_cyclic_graph_without_path_is_definitive(self):
        root = self.tmp({"a.py": "@app.route('/a')\ndef entry():\n    loop()\n"
                                 "def loop():\n    loop()\n    entry()\ndef target():\n    pass\n"})
        g = callgraph.build(root)
        self.assertTrue(g.complete)
        paths, search_complete = callgraph.paths_to(g, {"a:target"})
        self.assertEqual(paths, [])
        self.assertTrue(search_complete)

    # 8. Disconnected, cyclic, oversized, unresolved and parser-failure inputs.
    def test_disconnected_components_report_no_path_definitively(self):
        root = self.tmp({
            "a.py": "@app.route('/a')\ndef ea():\n    pass\n",
            "b.py": "def target_b():\n    pass\n",
        })
        g = callgraph.build(root)
        result, _, _ = pipeline._python_call_paths(
            [{"file": "b.py", "line": 2, "symbol": "x"}], root, {"python_graph": g})
        self.assertEqual(result, "not_found")

    def test_parser_failure_does_not_remove_a_valid_path_already_found(self):
        root = self.tmp({
            "a.py": "@app.route('/a')\ndef entry():\n    target()\ndef target():\n    pass\n",
            "broken.py": "def (:\n",
        })
        g = callgraph.build(root)
        self.assertFalse(g.complete)
        self.assertIn("parse_error", g.incomplete_reasons)
        result, paths, _ = pipeline._python_call_paths(
            [{"file": "a.py", "line": 4, "symbol": "x"}], root, {"python_graph": g})
        # A path that exists is still a valid path. The incomplete graph only affects absence.
        self.assertEqual(result, "confirmed")
        self.assertEqual(paths[0]["path"], ["a:entry", "a:target"])

    def test_parser_failure_makes_absence_incomplete(self):
        root = self.tmp({
            "a.py": "@app.route('/a')\ndef entry():\n    pass\ndef target():\n    pass\n",
            "broken.py": "def (:\n",
        })
        g = callgraph.build(root)
        result, _, _ = pipeline._python_call_paths(
            [{"file": "a.py", "line": 5, "symbol": "x"}], root, {"python_graph": g})
        self.assertEqual(result, "incomplete")

    def test_builtin_calls_make_absence_unknown_by_design(self):
        # Calls to builtins such as print() are unresolved by name, so they mark the caller
        # incomplete. This is conservative: it cannot produce a false "no path".
        root = self.tmp({"a.py": "@app.route('/a')\ndef entry():\n    print('x')\n"
                                 "def target():\n    pass\n"})
        g = callgraph.build(root)
        self.assertIn("a:entry", g.unresolved_from)
        _, search_complete = callgraph.paths_to(g, {"a:target"})
        self.assertFalse(search_complete)

    def test_oversized_project_path_within_retained_nodes_is_still_found(self):
        root = self.project(300)
        g = callgraph.build(root, max_nodes=2000)
        paths, _ = callgraph.paths_to(g, {"m00000:f1"})
        self.assertEqual(paths, [["m00000:entry", "m00000:f1"]])


class RandomizedOracleTest(unittest.TestCase):
    """Independent oracle: reachability by plain BFS over the graph's own edge list.

    The oracle does not use paths_to. It checks that paths_to finds a path exactly when
    the target is reachable from an entry, for random graphs that are complete, and that
    every returned path is a real chain of edges with no repeated node."""

    def test_paths_agree_with_an_independent_reachability_oracle(self):
        import random
        rng = random.Random(20260330)
        for trial in range(60):
            root = Path(tempfile.mkdtemp())
            self.addCleanup(shutil.rmtree, root, ignore_errors=True)
            names = [f"f{i}" for i in range(rng.randint(3, 9))]
            lines = ["@app.route('/e')\ndef entry():\n    " + "\n    ".join(f"{n}()" for n in names[:2]) + "\n"]
            for name in names:
                callees = rng.sample(names, rng.randint(0, 3))
                body = "\n    ".join(f"{c}()" for c in callees) or "pass"
                lines.append(f"def {name}():\n    {body}\n")
            (root / "m.py").write_text("".join(lines))

            g = callgraph.build(root)
            self.assertTrue(g.complete, trial)
            target = f"m:{rng.choice(names)}"

            adjacency = {}
            for edge in g.edges:
                adjacency.setdefault(edge["from"], []).append(edge["to"])
            reachable = set()
            frontier = [n for n, meta in g.nodes.items() if meta["entry"]]
            while frontier:
                node = frontier.pop()
                if node in reachable:
                    continue
                reachable.add(node)
                frontier.extend(adjacency.get(node, []))

            paths, search_complete = callgraph.paths_to(g, {target}, max_depth=50)
            self.assertEqual(bool(paths), target in reachable, (trial, target))
            self.assertTrue(search_complete, trial)
            for path in paths:
                self.assertEqual(len(set(path)), len(path))
                for a, b in zip(path, path[1:]):
                    self.assertIn(b, adjacency.get(a, []))


class TruncationVisibilityTest(unittest.TestCase):
    """Truncation must reach the human-readable report, not only evidence.json."""

    def finding(self, call_graph: dict):
        limitations = pipeline._graph_limitations(call_graph)
        return {"vulnerability": {"cve": "CVE-2017-18342", "id": "CVE-2017-18342", "severity": "high"},
                "library": "pyyaml", "dependency": {"version": "5.3"},
                "classification": "potentially_exploitable", "evidence": [],
                "scope": {"limitations": limitations}}

    def summary(self):
        return {"analysis_mode": "codeql", "fail_on": "confirmed_reachable", "gate_failed": False,
                "intel": {"osv": "ok"}, "unresolved_dependencies": 0}

    def test_incomplete_graph_produces_a_limitation(self):
        lines = pipeline._graph_limitations({"complete": False, "incomplete_reasons": ["node_limit"]})
        self.assertEqual(len(lines), 1)
        self.assertIn("node_limit", lines[0])
        self.assertIn("absence of a call path is unknown", lines[0])

    def test_complete_or_absent_graph_produces_no_limitation(self):
        self.assertEqual(pipeline._graph_limitations({"complete": True, "incomplete_reasons": []}), [])
        self.assertEqual(pipeline._graph_limitations({}), [])

    def test_markdown_report_shows_the_truncation(self):
        text = report.summary_markdown(self.summary(), [self.finding(
            {"complete": False, "incomplete_reasons": ["node_limit"]})])
        self.assertIn("Incomplete analysis", text)
        self.assertIn("Python call graph is incomplete (node_limit)", text)

    def test_markdown_report_has_no_truncation_section_for_a_complete_graph(self):
        text = report.summary_markdown(self.summary(), [self.finding(
            {"complete": True, "incomplete_reasons": []})])
        self.assertNotIn("Incomplete analysis", text)


if __name__ == "__main__":
    unittest.main()
