"""Deployment and runtime context: optional evidence that sharpens an assessment, in a versioned JSON document.

SAWONE works from repository evidence alone when no context is given. Every field is optional. A field that is not
given is UNKNOWN, never assumed safe or exposed: `field()` returns {"state": "unknown"} for it, and an exposure that is
not declared does not change the exposure the finding already has.

Document shape: see docs/CONTEXT_SCHEMA.md and docs/schemas/sawone-context-1.schema.json. Unknown top-level keys are
refused unless they start with `x-`, which is the extension point for a deployment's own fields.

Runtime evidence can only add to an assessment: an observation that a sink was reached raises the `reachable` and
`runtime_observed` conditions to CONFIRMED. It never lowers a verdict, and it never makes a finding CONFIRMED_EXPLOITABLE
on its own, because preconditions still need their own evidence.
"""

from engine.languages import analyzer_for
from engine.universal import (
    CONFIRMED, POTENTIALLY_EXPLOITABLE, UNKNOWN, Condition, ModelError, make_assessment, resolve_project_file,
)

SCHEMA = "sawone-context-1"
SECTIONS = {
    "applications": ("id",),
    "environments": ("id",),
    "endpoints": ("id",),
    "workloads": ("id",),
    "resources": ("id",),
    "identities": ("id",),
    "ci_workflows": ("id",),
    "security_controls": ("id",),
    "mitigations": ("id",),
    "runtime_observations": ("id",),
    "runtime_protection_events": ("id",),
}
EXPOSURE_VALUES = ("public", "private", "unknown")
EXPOSURE_TO_LEVEL = {"public": "internet", "private": "internal", "unknown": "unknown"}
OUTCOMES = ("reached", "not_reached", "error")
PROTECTION_ACTIONS = ("blocked", "alerted", "allowed")


def field(record: dict | None, name: str) -> dict:
    """A field of a record as {"state": "known", "value": ...}, or {"state": "unknown"} when it is not given."""
    if not isinstance(record, dict) or record.get(name) is None:
        return {"state": "unknown"}
    return {"state": "known", "value": record[name]}


class Context:
    """A loaded, validated deployment context. An empty context is the repository-only case."""

    def __init__(self, document: dict):
        self.document = document
        self.records = {section: list(document.get(section) or []) for section in SECTIONS}

    def exposure_for(self, path: str | None, symbol: str | None) -> str:
        """The exposure of the handler at `path` and `symbol`, as the engine levels: internet, internal or unknown."""
        if not path or not symbol:
            return "unknown"
        for endpoint in self.records["endpoints"]:
            handler = endpoint.get("handler") or {}
            if handler.get("file") == path and handler.get("symbol") == symbol:
                declared = endpoint.get("exposure", "unknown")
                return EXPOSURE_TO_LEVEL[declared]
        return "unknown"

    def runtime_observations_at(self, path: str | None, line: int | None) -> list[dict]:
        """Observations that reached exactly this file and line. Path and line must both match."""
        if not path or line is None:
            return []
        return [obs for obs in self.records["runtime_observations"]
                if obs.get("file") == path and obs.get("line") == line and obs.get("outcome") == "reached"]

    def protection_events_at(self, path: str | None, line: int | None) -> list[dict]:
        if not path or line is None:
            return []
        return [event for event in self.records["runtime_protection_events"]
                if event.get("file") == path and event.get("line") == line]


def _check_record(section: str, index: int, record) -> None:
    where = f"{section}[{index}]"
    if not isinstance(record, dict):
        raise ModelError(f"{where} is not an object")
    for key in SECTIONS[section]:
        if not isinstance(record.get(key), str) or not record[key]:
            raise ModelError(f"{where} needs a non-empty string `{key}`")
    if section == "endpoints":
        exposure = record.get("exposure", "unknown")
        if exposure not in EXPOSURE_VALUES:
            raise ModelError(f"{where} exposure must be one of {EXPOSURE_VALUES}, not {exposure!r}")
    if section == "runtime_observations":
        if record.get("outcome") not in OUTCOMES:
            raise ModelError(f"{where} outcome must be one of {OUTCOMES}")
        if not isinstance(record.get("file"), str) or not isinstance(record.get("line"), int) or record["line"] < 1:
            raise ModelError(f"{where} needs a file and a line of 1 or more")
    if section == "runtime_protection_events":
        if record.get("action") not in PROTECTION_ACTIONS:
            raise ModelError(f"{where} action must be one of {PROTECTION_ACTIONS}")


def load(document) -> Context:
    """Validate a context document. Raises ModelError on a wrong schema version, an unknown key, a bad record, or a
    duplicated id. Every section may be absent."""
    if not isinstance(document, dict):
        raise ModelError("the context document is not an object")
    if document.get("schema") != SCHEMA:
        raise ModelError(f"the context schema must be {SCHEMA!r}, not {document.get('schema')!r}")
    for key in document:
        if key == "schema" or key in SECTIONS or key.startswith("x-"):
            continue
        raise ModelError(f"unknown context key {key!r}; extension keys start with x-")
    for section, _ in SECTIONS.items():
        records = document.get(section, [])
        if not isinstance(records, list):
            raise ModelError(f"{section} must be a list")
        seen: set[str] = set()
        for index, record in enumerate(records):
            _check_record(section, index, record)
            if record["id"] in seen:
                raise ModelError(f"{section} has a duplicate id {record['id']!r}")
            seen.add(record["id"])
    return Context(document)


def repository_only() -> Context:
    return Context({"schema": SCHEMA})


def apply_runtime(result, finding: dict, context: dict | None):
    """Raise the reachability of an assessment when a runtime observation reached the finding's line. The verdict only
    moves up from UNKNOWN to POTENTIALLY_EXPLOITABLE, and only when attacker input is already confirmed."""
    deployment = (context or {}).get("deployment")
    if deployment is None or result.verdict not in (UNKNOWN, POTENTIALLY_EXPLOITABLE):
        return result
    location = finding.get("location") or {}
    observed = deployment.runtime_observations_at(location.get("path"), location.get("start_line"))
    if not observed:
        return result
    ids = [obs["id"] for obs in observed]
    description = f"runtime observation {', '.join(ids)} reached {location['path']}:{location['start_line']}"
    conditions = dict(result.conditions)
    conditions["reachable"] = Condition(CONFIRMED, ids)
    conditions["runtime_observed"] = Condition(CONFIRMED, ids)
    evidence = list(result.evidence) + [
        {"condition": "reachable", "kind": "runtime_observation", "detail": description},
        {"condition": "runtime_observed", "kind": "runtime_observation", "detail": description},
    ]
    verdict = result.verdict
    if verdict == UNKNOWN and conditions["attacker_influence"].status == CONFIRMED:
        verdict = POTENTIALLY_EXPLOITABLE
    limitations = list(result.limitations) or ["runtime evidence is one observation, not the whole input space"]
    return make_assessment(verdict, reason=f"{result.reason}; {description}", engine=result.engine,
                           conditions=conditions, evidence=evidence, confidence=result.confidence,
                           confidence_reason=result.confidence_reason, coverage=result.coverage,
                           limitations=limitations, exposure=finding["exploitability_context"]["exposure"])


def _enclosing_method(finding: dict, project_dir) -> str | None:
    """The method a flagged line sits in, from a language analyzer. None when no analyzer covers the file."""
    location = finding.get("location") or {}
    analyzer = analyzer_for(location.get("path") or "")
    if analyzer is None:
        return None
    target, _ = resolve_project_file(project_dir, location["path"])
    if target is None:
        return None
    return analyzer.analyse_call(target.read_bytes(), location).method


def apply_exposure(findings: list[dict], context: Context, project_dir) -> list[dict]:
    """Set each finding's exposure from the declared endpoint whose handler it is in. An undeclared endpoint leaves
    the exposure the finding already has."""
    for finding in findings:
        location = finding.get("location") or {}
        if not location.get("path"):
            continue
        declared = context.exposure_for(location["path"], _enclosing_method(finding, project_dir))
        if declared != "unknown":
            finding["exploitability_context"]["exposure"] = declared
    return findings
