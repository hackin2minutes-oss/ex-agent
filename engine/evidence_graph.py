"""Evidence graph: findings, observations and deployment records as nodes, and the relationships between them as edges.

Every edge carries its provenance (the rule that made it and the producer that supplied the facts), a confidence level,
and at least one evidence record that the edge cites by `ref`. Nothing is linked because two records share a filename,
a package name or a similar description. An edge is made only when an exact key matches: the same file and line, the
same image digest, the same resource identifier, the same handler file and symbol.

A path through the graph is evidence that the links exist. It is not an exploitability verdict. Verdicts come from the
engines, and `attack_paths` says so in every result it returns.
"""

from engine.deployment_context import Context
from engine.universal import CONFIRMED, ModelError

LEVELS = ("LOW", "MEDIUM", "HIGH")
RULES = {
    "sast.taint": "attacker input reaches a call in the same method (taint assessment)",
    "runtime.location": "a runtime observation reached the finding's exact file and line",
    "handler.endpoint": "the finding's file and enclosing method are a declared endpoint's handler",
    "endpoint.exposure": "the declared endpoint's exposure",
    "endpoint.authentication": "the declared endpoint's authentication",
    "secret.identity": "a declared identity lists the secret's exact file and line",
    "image.workload": "a declared workload runs the finding's exact image digest",
    "resource.identifier": "a declared resource has the finding's exact resource identifier",
    "workflow.path": "the declared CI workflow file is the finding's exact file, and declares deploy credentials",
}
NOT_CORRELATED = (
    "dependency to application function: no call-site record for dependency symbols is produced in this build",
    "threat-model entry to code, infrastructure or runtime: no exact correlation key exists for threats",
)
ATTACK_PATH_NOTE = ("a path is evidence that records are linked. It is not an exploitability verdict; "
                    "verdicts come from the engines")


class EvidenceGraph:
    def __init__(self):
        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []

    def node(self, node_id: str, kind: str, **attributes) -> str:
        if node_id in self.nodes:
            if self.nodes[node_id]["kind"] != kind:
                raise ModelError(f"node {node_id} is already a {self.nodes[node_id]['kind']}, not a {kind}")
            return node_id
        self.nodes[node_id] = {"id": node_id, "kind": kind, **attributes}
        return node_id

    def link(self, source: str, target: str, relation: str, *, rule: str, confidence: str,
             evidence: list[dict]) -> dict:
        if source not in self.nodes or target not in self.nodes:
            raise ModelError(f"both ends of {relation} must be nodes in the graph")
        if rule not in RULES:
            raise ModelError(f"unknown rule {rule!r}")
        if confidence not in LEVELS:
            raise ModelError(f"unknown confidence {confidence!r}")
        if not evidence:
            raise ModelError(f"an edge ({relation}) needs at least one evidence record")
        for item in evidence:
            if not item.get("kind") or not item.get("ref"):
                raise ModelError("each evidence record needs a kind and a ref to the record it cites")
        edge = {"source": source, "target": target, "relation": relation, "confidence": confidence,
                "provenance": {"rule": rule, "producer": RULES[rule]}, "evidence": list(evidence)}
        self.edges.append(edge)
        return edge

    def paths(self, source: str, target: str, max_hops: int = 8) -> list[dict]:
        """Every simple path from source to target, with the weakest edge confidence as the path's confidence."""
        out: list[dict] = []

        def walk(current: str, trail: list[dict]) -> None:
            if current == target and trail:
                weakest = min((edge["confidence"] for edge in trail), key=LEVELS.index)
                out.append({"hops": [source] + [edge["target"] for edge in trail], "edges": list(trail),
                            "confidence": weakest, "status": "path_present", "note": ATTACK_PATH_NOTE})
                return
            if len(trail) >= max_hops:
                return
            visited = {source} | {edge["target"] for edge in trail}
            for edge in self.edges:
                if edge["source"] == current and edge["target"] not in visited:
                    walk(edge["target"], trail + [edge])

        walk(source, [])
        return out


def _location_key(finding: dict):
    location = finding.get("location") or {}
    return location.get("path"), location.get("start_line")


def correlate(findings: list[dict], context: Context | None) -> EvidenceGraph:
    """Build the graph from assessed findings and the deployment context. Each rule links on an exact key only.
    Missing context adds no nodes for it, so a repository-only run has findings and taint edges and nothing else."""
    graph = EvidenceGraph()
    finding_nodes = {}
    for finding in findings:
        node_id = graph.node(f"finding:{finding['id']}", "finding", category=finding["category"],
                             verdict=(finding.get("assessment") or {}).get("verdict"))
        finding_nodes[finding["id"]] = node_id

    for finding in findings:
        assessment = finding.get("assessment") or {}
        conditions = assessment.get("conditions") or {}
        taint = conditions.get("attacker_influence") or {}
        if taint.get("status") == CONFIRMED and finding.get("location"):
            path, line = _location_key(finding)
            input_node = graph.node(f"input:{path}:{line}", "attacker_input", path=path, line=line)
            # The edge cites the finding's own assessment: each evidence item it recorded, or the reason when the
            # engine recorded none, so every edge has at least one citation.
            cited = [{"kind": "assessment", "ref": finding["id"], "detail": item.get("detail", "")}
                     for item in assessment.get("evidence", [])]
            cited = cited or [{"kind": "assessment", "ref": finding["id"], "detail": assessment.get("reason", "")}]
            graph.link(input_node, finding_nodes[finding["id"]], "carries_input_to", rule="sast.taint",
                       confidence="MEDIUM", evidence=cited)

    if context is None:
        return graph

    for observation in context.records["runtime_observations"]:
        if observation.get("outcome") != "reached":
            continue
        observed = graph.node(f"observation:{observation['id']}", "observation", source=observation.get("source"))
        for finding in findings:
            if _location_key(finding) == (observation["file"], observation["line"]):
                graph.link(observed, finding_nodes[finding["id"]], "observed_at", rule="runtime.location",
                           confidence="HIGH",
                           evidence=[{"kind": "runtime_observation", "ref": observation["id"],
                                       "detail": f"{observation['file']}:{observation['line']} reached"}])

    for endpoint in context.records["endpoints"]:
        endpoint_node = graph.node(f"endpoint:{endpoint['id']}", "endpoint", route=endpoint.get("route"))
        exposure = graph.node(f"exposure:{endpoint.get('exposure', 'unknown')}", "exposure")
        graph.link(endpoint_node, exposure, "exposed_as", rule="endpoint.exposure", confidence="HIGH",
                   evidence=[{"kind": "declared_exposure", "ref": endpoint["id"],
                              "detail": f"exposure {endpoint.get('exposure', 'unknown')}"}])
        handler = endpoint.get("handler") or {}
        for finding in findings:
            path, _ = _location_key(finding)
            if path and handler.get("file") == path and handler.get("symbol") and _enclosing(finding) == handler["symbol"]:
                graph.link(finding_nodes[finding["id"]], endpoint_node, "handled_by", rule="handler.endpoint",
                           confidence="HIGH",
                           evidence=[{"kind": "handler", "ref": endpoint["id"],
                                      "detail": f"{path} {handler['symbol']}"}])
        if isinstance(endpoint.get("authentication"), dict):
            auth = graph.node(f"auth:{endpoint['id']}", "authentication",
                              required=endpoint["authentication"].get("required", "unknown"))
            graph.link(endpoint_node, auth, "guarded_by", rule="endpoint.authentication", confidence="HIGH",
                       evidence=[{"kind": "declared_authentication", "ref": endpoint["id"],
                                  "detail": f"required {endpoint['authentication'].get('required', 'unknown')}"}])

    for identity in context.records["identities"]:
        identity_node = graph.node(f"identity:{identity['id']}", "identity",
                                   principal_kind=identity.get("kind"))
        for ref in identity.get("secret_refs") or []:
            for finding in findings:
                if finding["category"] == "SECRET" and _location_key(finding) == (ref.get("file"), ref.get("line")):
                    graph.link(finding_nodes[finding["id"]], identity_node, "credential_of", rule="secret.identity",
                               confidence="HIGH",
                               evidence=[{"kind": "declared_secret_ref", "ref": identity["id"],
                                          "detail": f"{ref.get('file')}:{ref.get('line')}"}])

    for workload in context.records["workloads"]:
        workload_node = graph.node(f"workload:{workload['id']}", "workload", environment=workload.get("environment"))
        digest = workload.get("image_digest")
        for finding in findings:
            if finding["category"] == "CONTAINER" and digest and finding["asset"].get("name") == digest:
                graph.link(finding_nodes[finding["id"]], workload_node, "runs_in", rule="image.workload",
                           confidence="HIGH",
                           evidence=[{"kind": "declared_image_digest", "ref": workload["id"], "detail": digest}])

    for resource in context.records["resources"]:
        resource_node = graph.node(f"resource:{resource['id']}", "resource", type=resource.get("type"))
        for finding in findings:
            if finding["category"] in ("IAC", "CONFIG") and finding["asset"].get("name") == resource["id"]:
                graph.link(finding_nodes[finding["id"]], resource_node, "configures", rule="resource.identifier",
                           confidence="HIGH",
                           evidence=[{"kind": "declared_resource", "ref": resource["id"],
                                      "detail": resource["id"]}])

    for workflow in context.records["ci_workflows"]:
        if not workflow.get("deploy_credentials"):
            continue
        workflow_node = graph.node(f"workflow:{workflow['id']}", "workflow", path=workflow.get("path"))
        for finding in findings:
            if finding["category"] == "CICD" and _location_key(finding)[0] == workflow.get("path"):
                graph.link(finding_nodes[finding["id"]], workflow_node, "deploys_with", rule="workflow.path",
                           confidence="MEDIUM",
                           evidence=[{"kind": "declared_deploy_credentials", "ref": workflow["id"],
                                      "detail": ", ".join(map(str, workflow["deploy_credentials"]))}])
    return graph


def _enclosing(finding: dict) -> str | None:
    """The enclosing method the taint assessment recorded, when the analyzer named one."""
    for item in (finding.get("assessment") or {}).get("evidence", []):
        if item.get("kind") == "enclosing_method" and item.get("detail") != "none":
            return item["detail"]
    return None


def attack_paths(graph: EvidenceGraph) -> list[dict]:
    """Paths from each attacker-input node to an internet exposure node. Each is labelled as evidence of linked
    records, not as an exploit."""
    results = []
    for node_id, node in graph.nodes.items():
        if node["kind"] != "attacker_input":
            continue
        for target_id, target in graph.nodes.items():
            if target["kind"] == "exposure" and target_id == "exposure:public":
                results.extend(graph.paths(node_id, target_id))
    return results
