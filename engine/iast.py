"""IAST evidence: adapter and engine for runtime observations (schema sawone.iast/1, docs/schemas/).

An IAST agent reports sink executions it observed at runtime. Each observation becomes one IAST finding at
the sink's source location. The engine checks the observation against the source and against the sanitizers
the observation names. It never accepts a sanitizer's claim without checking it against a fixed table.

Verdicts:
- MITIGATED: the observation shows a sanitizer on the path that is effective for this sink kind (table below).
  It is a statement about this observed path only.
- CONFIRMED_EXPLOITABLE: only when the sink executed, the attacker's value reached it from a request source,
  no effective sanitizer was applied, and the application is declared internet-facing. One observed path
  still proves one path, so confidence is HIGH but the reason says so.
- POTENTIALLY_EXPLOITABLE: the sink executed with request-derived input, but a condition above is not met
  (for example, exposure is not declared internet).
- UNKNOWN: not correlated to a request, sink not observed executing, no request-derived input observed, or
  the sink line no longer matches the source (stale observation).

No observation becomes NOT_EXPLOITABLE: not executing in the observed traffic is not proof of safety.
"""

import re

from engine.universal import (
    CONFIRMED, CONFIRMED_EXPLOITABLE, MITIGATED, NOT_CONFIRMED, POTENTIALLY_EXPLOITABLE, Adapter, Condition,
    Engine, ModelError, make_assessment, make_finding, resolve_project_file, unknown_assessment,
)

SCHEMA = "sawone.iast/1"
SOURCE_KINDS = ("http_query", "http_body", "http_header", "http_path", "cookie")
SINK_KINDS = ("sql_execution", "html_output", "shell_command", "file_path", "outbound_request", "code_evaluation")

# Sanitizers known to be effective for a sink kind. This table is the trust anchor for MITIGATED: an agent's
# statement that a sanitizer was applied is not enough unless the sanitizer is listed here for that sink.
EFFECTIVE_SANITIZERS = {
    "sql_execution": frozenset({"parameterized_query"}),
    "html_output": frozenset({"html.escape", "markupsafe.escape"}),
    "shell_command": frozenset({"shlex.quote"}),
    "file_path": frozenset({"os.path.realpath_within_base"}),
    "outbound_request": frozenset({"allowlist_host"}),
    "code_evaluation": frozenset(),
}

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _check_observation(item, index: int) -> None:
    """Structural check of one observation. A malformed observation is refused, not guessed at."""
    if not isinstance(item, dict):
        raise ModelError(f"iast observation {index} is not an object")
    for key in ("id", "request_id"):
        if not isinstance(item.get(key), str) or not item[key]:
            raise ModelError(f"iast observation {index} has no {key}")
    source, sink = item.get("source"), item.get("sink")
    if not isinstance(source, dict) or source.get("kind") not in SOURCE_KINDS:
        raise ModelError(f"iast observation {index} has no valid source")
    if not isinstance(sink, dict) or sink.get("kind") not in SINK_KINDS:
        raise ModelError(f"iast observation {index} has no valid sink kind")
    if not isinstance(sink.get("file"), str) or not isinstance(sink.get("line"), int) or sink["line"] < 1:
        raise ModelError(f"iast observation {index} has no valid sink location")
    if not isinstance(sink.get("function"), str) or not sink["function"]:
        raise ModelError(f"iast observation {index} has no sink function")
    for flag in ("executed", "payload_observed"):
        if not isinstance(item.get(flag), bool):
            raise ModelError(f"iast observation {index} has no boolean {flag}")
    if "value" in item or "payload" in item:
        raise ModelError(f"iast observation {index} carries a raw value; send value_sha256 instead")
    if item.get("value_sha256") is not None and not _HEX64.match(str(item["value_sha256"])):
        raise ModelError(f"iast observation {index} has an invalid value_sha256")


class IastAdapter(Adapter):
    name = "sawone-iast"
    formats = (SCHEMA,)
    categories = ("IAST",)

    def detect(self, document) -> bool:
        return isinstance(document, dict) and document.get("schema") == SCHEMA

    def parse(self, document, provenance: dict) -> tuple[list[dict], list[str]]:
        agent = document.get("agent")
        if not isinstance(agent, dict) or not isinstance(agent.get("name"), str):
            raise ModelError("iast report has no agent")
        observations = document.get("observations")
        if not isinstance(observations, list):
            raise ModelError("iast report has no observations list")
        simulated = agent.get("simulated") is True
        findings = []
        for index, item in enumerate(observations):
            _check_observation(item, index)
            sink = item["sink"]
            findings.append(make_finding(
                category="IAST",
                rule_id=f"iast-{sink['kind']}",
                title=f"{sink['function']} executed with request-derived input",
                asset={"type": "source_location", "name": sink["file"]},
                location={"path": sink["file"], "start_line": sink["line"], "end_line": sink["line"],
                          "start_col": None, "end_col": None},
                severity_reported=None,
                provenance={"scanner": agent["name"], "version": agent.get("version"),
                            "format": SCHEMA, "target": provenance.get("target"),
                            "simulated": simulated},
                original=dict(item),
                summary=f"observed at runtime for request {item['request_id']}",
                identity=(item["id"], item["request_id"]),
            ))
        label = "simulated agent output" if simulated else "agent output"
        return findings, [f"iast: {len(findings)} observation(s), {label}"]


class IastEngine(Engine):
    name = "iast-observation"
    categories = ("IAST",)
    techniques = ("sink line verification", "observed taint path check", "sanitizer table check")
    limits = (
        "only the observed requests are covered; other inputs and paths are not",
        "the attacker's value is taken from the agent's observation, not re-sent",
        "sanitizers are credited only when listed in the effective table for the sink kind",
        "exposure is taken from the declaration, not verified",
    )

    @staticmethod
    def _line(context: dict, item: dict) -> str:
        target, _ = resolve_project_file(context["project_dir"], item["file"])
        if target is None:
            return ""
        lines = target.read_text(encoding="utf-8", errors="strict").splitlines()
        return lines[item["line"] - 1] if 1 <= item["line"] <= len(lines) else ""

    def assess(self, finding: dict, context: dict):
        observation = finding["original"]
        location = finding["location"]
        target, problem = resolve_project_file(context["project_dir"], location["path"])
        if target is None:
            return unknown_assessment(problem, engine=self.name)
        lines = target.read_text(encoding="utf-8", errors="strict").splitlines()
        span = f"{location['path']}:{location['start_line']}"
        function = observation["sink"]["function"].split(".")[-1]
        if location["start_line"] > len(lines) or function not in lines[location["start_line"] - 1]:
            return unknown_assessment(f"the sink {function} is not at {span}; the observation is stale",
                                      engine=self.name)
        if not observation["executed"]:
            return unknown_assessment(f"{function} was not observed executing at {span}",
                                      engine=self.name, limitation="sink not observed executing")
        if not observation["payload_observed"]:
            return unknown_assessment(f"no request-derived input was observed at {span}",
                                      engine=self.name, limitation="attacker value not observed")
        if not observation.get("taint_path") or observation["source"]["kind"] not in SOURCE_KINDS:
            return unknown_assessment(f"no source-to-sink path was observed for {span}",
                                      engine=self.name, limitation="taint path not observed")

        sink_kind = observation["sink"]["kind"]
        effective = EFFECTIVE_SANITIZERS.get(sink_kind, frozenset())
        applied = [s["function"] for s in observation.get("sanitizers", []) if s.get("applied")]
        # A sanitizer is credited only if it is in the table for this sink AND its name is in the source
        # lines of the observed path. The agent's claim alone is not enough.
        path_lines = [self._line(context, item) for item in observation.get("taint_path", [])] + [lines[location["start_line"] - 1]]
        effective_applied = [name for name in applied
                             if name in effective and any(name.split(".")[-1] in text for text in path_lines if text)]
        unverified = [name for name in applied if name in effective and name not in effective_applied]
        span_request = f"request {observation['request_id']}"
        route = observation.get("endpoint", {}).get("route", "")
        coverage = {"analysed": [f"{span} observed for {span_request}"], "not_analysed": list(self.limits)}
        evidence = [
            {"condition": "reachable", "kind": "observation",
             "detail": f"{span_request} reached {function} at {span}" + (f" via {route}" if route else "")},
            {"condition": "attacker_influence", "kind": "observation",
             "detail": f"request-derived value via {observation['source']['kind']} {observation['source']['name']}"},
        ]
        if unverified:
            evidence.append({"condition": None, "kind": "observation",
                             "detail": f"sanitizer {unverified[0]} claimed but not found in the source of the path"})

        if effective_applied:
            return make_assessment(
                MITIGATED,
                reason=(f"an effective sanitizer ({effective_applied[0]}) was applied on the observed path "
                        f"to {function}; this is a statement about that path only"),
                engine=self.name,
                conditions={"mitigation_effective": Condition(CONFIRMED, [effective_applied[0]])},
                evidence=evidence + [{"condition": "mitigation_effective", "kind": "observation",
                                      "detail": f"{effective_applied[0]} applied and effective for {sink_kind}"}],
                confidence="MEDIUM",
                confidence_reason="one observed path; other paths to the same sink are not covered",
                coverage=coverage,
                limitations=list(self.limits),
                exposure=finding["exploitability_context"]["exposure"],
            )

        conditions = {
            "reachable": Condition(CONFIRMED, [span_request]),
            "attacker_influence": Condition(CONFIRMED, [observation["source"]["name"]]),
            "preconditions": Condition(NOT_CONFIRMED if applied else CONFIRMED,
                                       ["no effective sanitizer on the observed path"]),
        }
        exposure = finding["exploitability_context"]["exposure"]
        if exposure == "internet" and not applied:
            return make_assessment(
                CONFIRMED_EXPLOITABLE,
                reason=("the sink executed with the attacker's value from a request, with no sanitizer on "
                        "the observed path, and the application is declared internet-facing; this is one "
                        "observed path"),
                engine=self.name,
                conditions=conditions,
                evidence=evidence + [{"condition": "preconditions", "kind": "observation",
                                      "detail": "no sanitizer applied on the observed path"}],
                confidence="HIGH",
                confidence_reason="runtime observation of the full path, for one request",
                coverage=coverage,
                limitations=list(self.limits),
                exposure=exposure,
            )
        return make_assessment(
            POTENTIALLY_EXPLOITABLE,
            reason=("the sink executed with request-derived input on this one observed path; exposure is not "
                    "declared internet-facing, or a sanitizer was applied that is not effective for this sink"),
            engine=self.name,
            conditions=conditions,
            evidence=evidence,
            confidence="HIGH",
            confidence_reason="runtime observation of the path for one request",
            coverage=coverage,
            limitations=list(self.limits),
            exposure=exposure,
        )
