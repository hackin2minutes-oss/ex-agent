"""The evidence graph: provenance and evidence on every edge, exact-key correlation only, and paths that are not verdicts."""

import json
import unittest

from engine import deployment_context, evidence_graph
from engine.universal import ModelError, make_finding


def finding(fid: str, category: str, path=None, line=None, *, name=None, attacker=False, method=None,
            verdict="UNKNOWN"):
    location = {"path": path, "start_line": line, "end_line": line, "start_col": None, "end_col": None} if path else None
    evidence = []
    conditions = {}
    if attacker:
        conditions["attacker_influence"] = {"status": "CONFIRMED", "evidence": ["taint"]}
        evidence.append({"condition": "attacker_influence", "kind": "taint", "detail": "parameter q from the request"})
    if method:
        evidence.append({"condition": None, "kind": "enclosing_method", "detail": method, "attributes": []})
    item = make_finding(category=category, rule_id=f"rule.{fid}", title=fid,
                        asset={"type": "source_location" if path else "container_image", "name": name or path or fid},
                        location=location, severity_reported="error", provenance={"scanner": "test"},
                        original={}, identity=(fid,))
    item["id"] = fid
    item["assessment"] = {"verdict": verdict, "reason": "test reason", "conditions": conditions,
                          "evidence": evidence, "limitations": ["x"], "coverage": {}}
    return item


def context(document):
    return deployment_context.load({"schema": "sawone-context-1", **document})


class GraphRulesTest(unittest.TestCase):
    def test_an_edge_needs_provenance_and_evidence(self):
        graph = evidence_graph.EvidenceGraph()
        graph.node("a", "finding")
        graph.node("b", "finding")
        with self.assertRaises(ModelError):
            graph.link("a", "b", "rel", rule="sast.taint", confidence="HIGH", evidence=[])
        with self.assertRaises(ModelError):
            graph.link("a", "b", "rel", rule="made.up", confidence="HIGH",
                       evidence=[{"kind": "k", "ref": "r"}])
        with self.assertRaises(ModelError):
            graph.link("a", "b", "rel", rule="sast.taint", confidence="CERTAIN", evidence=[{"kind": "k", "ref": "r"}])
        with self.assertRaises(ModelError):
            graph.link("a", "missing", "rel", rule="sast.taint", confidence="HIGH", evidence=[{"kind": "k", "ref": "r"}])
        with self.assertRaises(ModelError):
            graph.link("a", "b", "rel", rule="sast.taint", confidence="HIGH", evidence=[{"kind": "k"}])

    def test_a_valid_edge_records_its_rule_and_its_evidence(self):
        graph = evidence_graph.EvidenceGraph()
        graph.node("a", "finding")
        graph.node("b", "finding")
        edge = graph.link("a", "b", "rel", rule="sast.taint", confidence="MEDIUM",
                          evidence=[{"kind": "taint", "ref": "f1", "detail": "x"}])
        self.assertEqual(edge["provenance"]["rule"], "sast.taint")
        self.assertEqual(edge["evidence"][0]["ref"], "f1")

    def test_a_node_cannot_change_kind(self):
        graph = evidence_graph.EvidenceGraph()
        graph.node("n", "finding")
        with self.assertRaises(ModelError):
            graph.node("n", "endpoint")

    def test_taint_links_the_input_to_the_finding_and_cites_the_finding(self):
        findings = [finding("f1", "SAST", "app/views.py", 10, attacker=True)]
        graph = evidence_graph.correlate(findings, deployment_context.repository_only())
        edges = [e for e in graph.edges if e["relation"] == "carries_input_to"]
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0]["provenance"]["rule"], "sast.taint")
        self.assertEqual(edges[0]["confidence"], "MEDIUM")
        self.assertEqual(edges[0]["evidence"][0]["ref"], "f1")

    def test_a_taint_edge_still_has_a_citation_when_the_engine_recorded_no_item(self):
        item = finding("f1", "SAST", "app/views.py", 10)
        item["assessment"]["conditions"] = {"attacker_influence": {"status": "CONFIRMED", "evidence": ["x"]}}
        item["assessment"]["evidence"] = []
        graph = evidence_graph.correlate([item], deployment_context.repository_only())
        edge = [e for e in graph.edges if e["relation"] == "carries_input_to"][0]
        self.assertTrue(edge["evidence"][0]["detail"] == "test reason")

    def test_a_repository_only_run_has_no_deployment_nodes(self):
        findings = [finding("f1", "SAST", "app/views.py", 10, attacker=True)]
        graph = evidence_graph.correlate(findings, deployment_context.repository_only())
        kinds = {node["kind"] for node in graph.nodes.values()}
        self.assertEqual(kinds, {"finding", "attacker_input"})


class CorrelationTest(unittest.TestCase):
    def test_a_runtime_observation_links_only_at_the_exact_file_and_line(self):
        ctx = context({"runtime_observations": [
            {"id": "obs-1", "file": "app/views.py", "line": 10, "outcome": "reached"},
            {"id": "obs-2", "file": "app/views.py", "line": 11, "outcome": "reached"},
        ]})
        findings = [finding("f1", "SAST", "app/views.py", 10)]
        graph = evidence_graph.correlate(findings, ctx)
        observed = [e for e in graph.edges if e["relation"] == "observed_at"]
        self.assertEqual([e["evidence"][0]["ref"] for e in observed], ["obs-1"])

    def test_a_shared_filename_at_another_line_is_not_a_link(self):
        ctx = context({"runtime_observations": [
            {"id": "obs-1", "file": "app/views.py", "line": 99, "outcome": "reached"}]})
        graph = evidence_graph.correlate([finding("f1", "SAST", "app/views.py", 10)], ctx)
        self.assertFalse([e for e in graph.edges if e["relation"] == "observed_at"])

    def test_a_secret_is_linked_to_an_identity_only_at_the_exact_location(self):
        ctx = context({"identities": [
            {"id": "id-db", "kind": "service_account", "secret_refs": [{"file": "appsettings.json", "line": 12}]}]})
        exact = finding("s1", "SECRET", "appsettings.json", 12)
        same_name_other_line = finding("s2", "SECRET", "appsettings.json", 40)
        graph = evidence_graph.correlate([exact, same_name_other_line], ctx)
        linked = [e["source"] for e in graph.edges if e["relation"] == "credential_of"]
        self.assertEqual(linked, ["finding:s1"])

    def test_a_container_finding_is_linked_only_to_the_same_image_digest(self):
        digest = "sha256:" + "a" * 64
        ctx = context({"workloads": [{"id": "wl", "environment": "prod", "image_digest": digest}]})
        same = finding("c1", "CONTAINER", name=digest)
        other = finding("c2", "CONTAINER", name="sha256:" + "b" * 64)
        graph = evidence_graph.correlate([same, other], ctx)
        self.assertEqual([e["source"] for e in graph.edges if e["relation"] == "runs_in"], ["finding:c1"])

    def test_a_cloud_resource_is_linked_only_by_its_identifier(self):
        ctx = context({"resources": [{"id": "bucket-logs", "type": "storage"}]})
        graph = evidence_graph.correlate([finding("i1", "IAC", name="bucket-logs"),
                                          finding("i2", "IAC", name="bucket-other")], ctx)
        self.assertEqual([e["source"] for e in graph.edges if e["relation"] == "configures"], ["finding:i1"])

    def test_a_ci_finding_is_linked_only_to_a_workflow_that_declares_deploy_credentials(self):
        ctx = context({"ci_workflows": [
            {"id": "deploy", "path": ".github/workflows/deploy.yml", "deploy_credentials": ["AZURE_CREDENTIALS"]},
            {"id": "lint", "path": ".github/workflows/lint.yml"}]})
        graph = evidence_graph.correlate([finding("w1", "CICD", ".github/workflows/deploy.yml"),
                                          finding("w2", "CICD", ".github/workflows/lint.yml")], ctx)
        self.assertEqual([e["source"] for e in graph.edges if e["relation"] == "deploys_with"], ["finding:w1"])

    def test_a_declared_endpoint_handler_is_linked_by_file_and_method(self):
        ctx = context({"endpoints": [{"id": "ep", "route": "/search", "exposure": "public",
                                      "handler": {"file": "app/views.py", "symbol": "search"}}]})
        graph = evidence_graph.correlate([finding("f1", "SAST", "app/views.py", 10, method="search"),
                                          finding("f2", "SAST", "app/views.py", 30, method="other")], ctx)
        handled = [e["source"] for e in graph.edges if e["relation"] == "handled_by"]
        self.assertEqual(handled, ["finding:f1"])


class AttackPathTest(unittest.TestCase):
    def _graph(self, exposure: str):
        ctx = context({"endpoints": [{"id": "ep", "route": "/search", "exposure": exposure,
                                      "handler": {"file": "app/views.py", "symbol": "search"}}]})
        findings = [finding("f1", "SAST", "app/views.py", 10, attacker=True, method="search")]
        return evidence_graph.correlate(findings, ctx)

    def test_a_path_from_input_through_handler_to_public_exposure_is_reported_as_a_path_not_a_verdict(self):
        paths = evidence_graph.attack_paths(self._graph("public"))
        self.assertEqual(len(paths), 1)
        path = paths[0]
        self.assertEqual(path["status"], "path_present")
        self.assertEqual(path["confidence"], "MEDIUM", "the weakest edge sets the path confidence")
        self.assertIn("not an exploitability verdict", path["note"])
        self.assertEqual(path["hops"][-1], "exposure:public")

    def test_an_unknown_exposure_gives_no_path_to_the_internet(self):
        self.assertEqual(evidence_graph.attack_paths(self._graph("unknown")), [])

    def test_a_private_endpoint_gives_no_path_to_the_internet(self):
        self.assertEqual(evidence_graph.attack_paths(self._graph("private")), [])

    def test_the_paths_serialise_to_json(self):
        json.dumps(evidence_graph.attack_paths(self._graph("public")))


if __name__ == "__main__":
    unittest.main()
