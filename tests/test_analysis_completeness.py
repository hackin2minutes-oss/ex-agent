"""Analysis completeness in summary.json and SARIF.

Truncated or incomplete call-graph analysis must be visible in the machine-readable
outputs. These tests do not claim that an analysis is exhaustive: when no incompleteness
is detected, the field only says that none was detected.
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from engine import callgraph, pipeline, report
from tests.test_callgraph_scale import make_project

ROOT = Path(__file__).resolve().parent.parent


class AnalysisSummaryTest(unittest.TestCase):
    def setUp(self):
        self.dirs = []
        self.addCleanup(lambda: [shutil.rmtree(d, ignore_errors=True) for d in self.dirs])

    def project(self, files: int) -> Path:
        root = make_project(files)
        self.dirs.append(root)
        return root

    def finding(self, result: str) -> dict:
        return {"id": "CVE-X@lib:1.0", "evidence": [{"type": "call_paths", "result": result}]}

    def test_no_python_graph_is_not_reported_as_truncated(self):
        summary = pipeline.analysis_summary({}, [])
        self.assertEqual(summary["python_call_graph"], {"built": False})
        self.assertEqual(summary["incomplete_reasons"], [])
        self.assertTrue(summary["bounded_analysis_complete"])

    def test_limits_are_always_reported(self):
        summary = pipeline.analysis_summary({}, [])
        self.assertEqual(summary["limits"]["max_nodes"], callgraph.MAX_NODES)
        self.assertEqual(summary["limits"]["max_edges"], callgraph.MAX_EDGES)
        self.assertEqual(summary["limits"]["max_depth"], callgraph.MAX_DEPTH)

    def test_truncated_graph_is_incomplete_with_counts(self):
        graph = callgraph.build(self.project(50), max_nodes=200)
        summary = pipeline.analysis_summary({"python_graph": graph}, [])
        call_graph = summary["python_call_graph"]
        self.assertTrue(call_graph["built"])
        self.assertFalse(call_graph["complete"])
        self.assertIn("node_limit", summary["incomplete_reasons"])
        self.assertEqual(call_graph["skipped_nodes"], graph.skipped_nodes)
        self.assertFalse(summary["bounded_analysis_complete"])

    def test_edge_limited_graph_is_incomplete(self):
        graph = callgraph.build(self.project(5), max_edges=40)
        summary = pipeline.analysis_summary({"python_graph": graph}, [])
        self.assertIn("edge_limit", summary["incomplete_reasons"])
        self.assertFalse(summary["bounded_analysis_complete"])

    def test_finding_with_incomplete_search_is_listed(self):
        summary = pipeline.analysis_summary({}, [self.finding("incomplete"), self.finding("not_found")])
        self.assertEqual(summary["findings_with_incomplete_call_paths"], ["CVE-X@lib:1.0"])
        self.assertFalse(summary["bounded_analysis_complete"])

    def test_complete_graph_with_definitive_no_path_is_complete(self):
        graph = callgraph.build(self.project(1))
        summary = pipeline.analysis_summary({"python_graph": graph}, [self.finding("not_found")])
        self.assertTrue(graph.complete)
        self.assertTrue(summary["bounded_analysis_complete"])


class SarifAnalysisTest(unittest.TestCase):
    def runs(self, sarif):
        return sarif["runs"][0]

    def test_sarif_without_analysis_is_unchanged(self):
        sarif = report.to_sarif([], "0.0.0")
        self.assertNotIn("invocations", self.runs(sarif))

    def test_incomplete_analysis_becomes_standard_notifications(self):
        analysis = {"incomplete_reasons": ["node_limit"], "findings_with_incomplete_call_paths": ["X"]}
        invocation = self.runs(report.to_sarif([], "0.0.0", analysis))["invocations"][0]
        self.assertTrue(invocation["executionSuccessful"])
        texts = [n["message"]["text"] for n in invocation["toolExecutionNotifications"]]
        self.assertEqual(len(texts), 2)
        self.assertIn("node_limit", texts[0])
        self.assertIn("1 finding", texts[1])
        self.assertTrue(all(n["level"] == "warning" for n in invocation["toolExecutionNotifications"]))

    def test_complete_analysis_has_no_notifications(self):
        analysis = {"incomplete_reasons": [], "findings_with_incomplete_call_paths": []}
        invocation = self.runs(report.to_sarif([], "0.0.0", analysis))["invocations"][0]
        self.assertEqual(invocation["toolExecutionNotifications"], [])

    def test_no_unsupported_custom_properties_are_added(self):
        analysis = {"incomplete_reasons": ["node_limit"], "findings_with_incomplete_call_paths": []}
        run = self.runs(report.to_sarif([], "0.0.0", analysis))
        self.assertEqual(set(run), {"tool", "results", "invocations"})
        self.assertNotIn("properties", run)


class OutputFilesTest(unittest.TestCase):
    def test_write_all_puts_analysis_in_summary_json_and_sarif(self):
        out = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, out, ignore_errors=True)
        analysis = {"incomplete_reasons": ["node_limit"], "findings_with_incomplete_call_paths": [],
                    "bounded_analysis_complete": False}
        summary = {"analysis_mode": "none", "fail_on": "confirmed_reachable", "gate_failed": False,
                   "intel": {}, "unresolved_dependencies": 0, "analysis": analysis}
        report.write_all(out, [], summary, "0.0.0")
        written = json.loads((out / "summary.json").read_text())
        self.assertFalse(written["analysis"]["bounded_analysis_complete"])
        sarif = json.loads((out / "findings.sarif").read_text())
        self.assertIn("node_limit", json.dumps(sarif["runs"][0]["invocations"]))


class EndToEndTest(unittest.TestCase):
    def test_pipeline_run_writes_analysis_to_summary(self):
        out = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, out, ignore_errors=True)
        summary = pipeline.run(ROOT / "tests/fixtures/go-app", ROOT / "tests/fixtures/go-app/go.sum",
                               ROOT / "rules", out, "confirmed_reachable", offline=True,
                               codeql_path="/nonexistent")
        self.assertIn("analysis", summary)
        written = json.loads((out / "summary.json").read_text())
        self.assertIn("bounded_analysis_complete", written["analysis"])
        self.assertIn("limits", written["analysis"])


if __name__ == "__main__":
    unittest.main()
