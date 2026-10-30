"""Call-graph integrity: limits, edge preservation, disconnected and cyclic graphs,
dynamic dispatch, partial failures and determinism. Projects are generated in temporary
directories, so no large fixtures are committed."""

import shutil
import tempfile
import unittest
from pathlib import Path

from engine import callgraph


def make_project(files: int, functions_per_file: int = 30, root_route: bool = True) -> Path:
    """`files` modules, each a chain of functions. Module 0 holds a route that reaches sink `m0:f1`."""
    root = Path(tempfile.mkdtemp())
    for i in range(files):
        body = []
        for j in range(functions_per_file):
            body.append(f"def f{j}(x):\n    return f{(j + 1) % functions_per_file}(x)\n")
        text = "".join(body)
        if i == 0 and root_route:
            text = ("@app.route('/entry')\ndef entry(x):\n    return f1(x)\n") + text
        (root / f"m{i:05d}.py").write_text(text)
    return root


class ScaleTest(unittest.TestCase):
    def setUp(self):
        self.projects = []
        self.addCleanup(lambda: [shutil.rmtree(p, ignore_errors=True) for p in self.projects])

    def project(self, *args, **kwargs):
        p = make_project(*args, **kwargs)
        self.projects.append(p)
        return p

    def test_100_files_are_complete(self):
        g = callgraph.build(self.project(100))
        self.assertTrue(g.complete)
        self.assertEqual(len(g.nodes), 100 * 30 + 1)  # the route function in module 0 is one extra node

    def test_1000_files_are_complete(self):
        g = callgraph.build(self.project(1000))
        self.assertTrue(g.complete)
        self.assertEqual(len(g.nodes), 1000 * 30 + 1)

    def test_2000_files_truncate_but_keep_the_route_and_its_edges(self):
        g = callgraph.build(self.project(2000))
        self.assertFalse(g.complete)
        self.assertIn("node_limit", g.incomplete_reasons)
        self.assertLessEqual(len(g.nodes), callgraph.MAX_NODES)
        self.assertGreater(len(g.edges), 0)
        paths, _ = callgraph.paths_to(g, {"m00000:f1"})
        self.assertEqual(paths, [["m00000:entry", "m00000:f1"]])

    def test_4000_files_bounded_and_edges_survive(self):
        g = callgraph.build(self.project(4000))
        self.assertLessEqual(len(g.nodes), callgraph.MAX_NODES)
        self.assertFalse(g.complete)
        self.assertGreater(len(g.edges), 0.9 * len(g.nodes))
        self.assertEqual(g.summary()["skipped_nodes"], 4000 * 30 + 1 - callgraph.MAX_NODES)
        paths, _ = callgraph.paths_to(g, {"m00000:f1"})
        self.assertTrue(paths)

    def test_node_limit_is_enforced_during_construction(self):
        g = callgraph.build(self.project(50), max_nodes=100)
        self.assertEqual(len(g.nodes), 100)
        self.assertEqual(g.skipped_nodes, 50 * 30 + 1 - 100)
        self.assertIn("node_limit", g.incomplete_reasons)

    def test_edge_limit_is_enforced_and_reported(self):
        g = callgraph.build(self.project(5), max_edges=40)
        self.assertEqual(len(g.edges), 40)
        self.assertIn("edge_limit", g.incomplete_reasons)
        self.assertGreater(g.skipped_edges, 0)

    def test_disconnected_components_do_not_interfere(self):
        root = Path(tempfile.mkdtemp())
        self.projects.append(root)
        (root / "a.py").write_text("@app.route('/a')\ndef ea():\n    left()\ndef left():\n    target_a()\n"
                                   "def target_a():\n    pass\n")
        (root / "b.py").write_text("@app.route('/b')\ndef eb():\n    pass\ndef target_b():\n    pass\n")
        g = callgraph.build(root)
        self.assertEqual(callgraph.paths_to(g, {"a:target_a"})[0], [["a:ea", "a:left", "a:target_a"]])
        self.assertEqual(callgraph.paths_to(g, {"b:target_b"})[0], [])
        self.assertTrue(g.complete)

    def test_cycles_terminate(self):
        root = self.project(1, functions_per_file=5)
        g = callgraph.build(root)
        paths, _ = callgraph.paths_to(g, {"m00000:f3"})
        self.assertTrue(paths)
        self.assertTrue(all(len(set(p)) == len(p) for p in paths))

    def test_unresolved_dynamic_dispatch_makes_absence_unknown(self):
        root = Path(tempfile.mkdtemp())
        self.projects.append(root)
        (root / "app.py").write_text("@app.route('/x')\ndef handler(obj):\n    obj.dispatch()\n"
                                     "def target():\n    pass\n")
        g = callgraph.build(root)
        self.assertIn("app:handler", g.unresolved_from)
        paths, search_complete = callgraph.paths_to(g, {"app:target"})
        self.assertEqual(paths, [])
        self.assertFalse(search_complete)

    def test_partial_failure_marks_graph_incomplete(self):
        root = self.project(3, functions_per_file=3)
        (root / "broken.py").write_text("def (:\n")
        g = callgraph.build(root)
        self.assertFalse(g.complete)
        self.assertIn("parse_error", g.incomplete_reasons)
        self.assertEqual(len(g.parse_errors), 1)

    def test_build_is_deterministic(self):
        root = self.project(200)
        a = callgraph.build(root)
        b = callgraph.build(root)
        self.assertEqual(a.edges, b.edges)
        self.assertEqual(a.summary(), b.summary())

    def test_truncated_graph_is_incomplete_so_absence_is_not_reported(self):
        g = callgraph.build(self.project(2000))
        paths, search_complete = callgraph.paths_to(g, {"not:a_node"})
        self.assertEqual(paths, [])
        self.assertFalse(search_complete)  # the depth bound cut the search short
        self.assertFalse(g.complete)       # and the graph itself is truncated

    def test_shallow_search_on_complete_graph_is_complete(self):
        g = callgraph.build(self.project(1, functions_per_file=3))
        paths, search_complete = callgraph.paths_to(g, {"m00000:f1"})
        self.assertTrue(paths)
        self.assertTrue(search_complete)


if __name__ == "__main__":
    unittest.main()
