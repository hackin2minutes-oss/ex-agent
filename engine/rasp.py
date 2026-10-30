"""RASP evidence: adapter and engine for protection events (schema sawone.rasp/1, docs/schemas/).

A RASP agent reports attack events: what input arrived at which endpoint, which rule saw it, and whether the
protection blocked it. Each event becomes one RASP finding. The raw input value is never accepted. Only its
SHA-256 is, so the report cannot carry attacker or user data into SAWONE's outputs.

Verdicts:
- MITIGATED: the protection blocked this attack request, the protection is enabled, and the event names the
  sink it protects. This is a statement about this request and endpoint. A blocked request is not proof that
  the underlying weakness is absent: other inputs and paths are not covered.
- POTENTIALLY_EXPLOITABLE: the attack was allowed through the protection to the application. Whether the
  sink then executed is not established by the event alone.
- UNKNOWN: the protection was disabled, the action is not blocked or allowed, the event is not correlated to
  a request, or the event is internally inconsistent (for example, blocked while protection is disabled).

No event becomes NOT_EXPLOITABLE or CONFIRMED_EXPLOITABLE. A block does not prove absence, and one allowed
event does not prove the sink executed.
"""

from engine.universal import (
    CONFIRMED, MITIGATED, POTENTIALLY_EXPLOITABLE, UNKNOWN_STATUS, Adapter, Condition, Engine, ModelError,
    make_assessment, make_finding, resolve_project_file, unknown_assessment,
)

SCHEMA = "sawone.rasp/1"
CATEGORIES = ("sql_injection", "command_injection", "path_traversal", "ssrf", "xss", "deserialization", "other")
LOCATIONS = ("query", "body", "header", "path", "cookie")


def _check_event(item, index: int) -> None:
    if not isinstance(item, dict):
        raise ModelError(f"rasp event {index} is not an object")
    for key in ("id", "request_id", "rule_id"):
        if not isinstance(item.get(key), str) or not item[key]:
            raise ModelError(f"rasp event {index} has no {key}")
    if item.get("category") not in CATEGORIES:
        raise ModelError(f"rasp event {index} has an unknown category")
    if item.get("action") not in ("blocked", "allowed"):
        raise ModelError(f"rasp event {index} has an action other than blocked or allowed")
    endpoint, values, protection = item.get("endpoint"), item.get("input"), item.get("protection")
    if not isinstance(endpoint, dict) or not isinstance(endpoint.get("route"), str):
        raise ModelError(f"rasp event {index} has no endpoint route")
    if not isinstance(values, dict) or values.get("location") not in LOCATIONS:
        raise ModelError(f"rasp event {index} has no valid input location")
    if "value" in values or "raw" in values:
        raise ModelError(f"rasp event {index} carries a raw input value; send value_sha256 instead")
    digest = values.get("value_sha256")
    if not isinstance(digest, str) or len(digest) != 64:
        raise ModelError(f"rasp event {index} has no value_sha256")
    if not isinstance(protection, dict) or not isinstance(protection.get("enabled"), bool):
        raise ModelError(f"rasp event {index} has no protection.enabled flag")


class RaspAdapter(Adapter):
    name = "sawone-rasp"
    formats = (SCHEMA,)
    categories = ("RASP",)

    def detect(self, document) -> bool:
        return isinstance(document, dict) and document.get("schema") == SCHEMA

    def parse(self, document, provenance: dict) -> tuple[list[dict], list[str]]:
        agent = document.get("agent")
        if not isinstance(agent, dict) or not isinstance(agent.get("name"), str):
            raise ModelError("rasp report has no agent")
        events = document.get("events")
        if not isinstance(events, list):
            raise ModelError("rasp report has no events list")
        simulated = agent.get("simulated") is True
        findings = []
        blocked = 0
        for index, item in enumerate(events):
            _check_event(item, index)
            blocked += item["action"] == "blocked"
            context = item.get("application_context") or {}
            location = None
            if isinstance(context.get("file"), str) and isinstance(context.get("line"), int) and context["line"] >= 1:
                location = {"path": context["file"], "start_line": context["line"],
                            "end_line": context["line"], "start_col": None, "end_col": None}
            findings.append(make_finding(
                category="RASP",
                rule_id=item["rule_id"],
                title=f"{item['category']} attempt on {item['endpoint']['route']}",
                asset={"type": "endpoint", "name": f"{item['endpoint'].get('method', '')} {item['endpoint']['route']}".strip()},
                location=location,
                severity_reported=None,
                provenance={"scanner": agent["name"], "version": agent.get("version"),
                            "format": SCHEMA, "target": provenance.get("target"), "simulated": simulated},
                original=dict(item),
                summary=f"{item['action']} by {item['rule_id']} for request {item['request_id']}",
                identity=(item["id"], item["request_id"]),
            ))
        label = "simulated agent output" if simulated else "agent output"
        return findings, [f"rasp: {len(findings)} event(s), {blocked} blocked, {label}"]


class RaspEngine(Engine):
    name = "rasp-protection-event"
    categories = ("RASP",)
    techniques = ("protection state check", "block versus allow classification", "event consistency check")
    limits = (
        "only the observed request is covered; other inputs and paths to the same endpoint are not",
        "a blocked request does not show that the underlying weakness is absent",
        "the protection's rule coverage is taken from the agent, not verified here",
        "whether an allowed attack reached a sink is not established by the event",
    )

    def assess(self, finding: dict, context: dict):
        event = finding["original"]
        span = f"{event['endpoint'].get('method', '')} {event['endpoint']['route']}".strip()
        coverage = {"analysed": [f"request {event['request_id']} on {span}"], "not_analysed": list(self.limits)}
        if not event["protection"]["enabled"]:
            return unknown_assessment(
                f"the protection was disabled for request {event['request_id']}; no protection state is "
                "established for this event", engine=self.name, limitation="protection disabled")
        ctx = event.get("application_context") or {}
        if ctx.get("file") and finding.get("location"):
            target, problem = resolve_project_file(context["project_dir"], ctx["file"])
            if target is None:
                return unknown_assessment(problem, engine=self.name)
        evidence = [{"condition": "attacker_influence", "kind": "event",
                     "detail": f"{event['category']} input in {event['input']['location']} "
                               f"{event['input']['name']!r} for {event['rule_id']}"}]

        if event["action"] == "blocked":
            if not event["protection"].get("sinks_protected") and event["category"] != "other":
                return unknown_assessment(
                    "the block names no protected sink, so the protection's coverage of this path is not "
                    "established", engine=self.name, limitation="protected sinks not named")
            return make_assessment(
                MITIGATED,
                reason=(f"{event['rule_id']} blocked this {event['category']} request on {span}; this shows "
                        "the protection stopped this request, not that the underlying weakness is absent"),
                engine=self.name,
                conditions={"mitigation_effective": Condition(CONFIRMED, [event["id"]]),
                            "attacker_influence": Condition(CONFIRMED, [event["input"]["name"]])},
                evidence=evidence + [{"condition": "mitigation_effective", "kind": "event",
                                      "detail": f"blocked by {event['rule_id']} (event {event['id']})"}],
                confidence="MEDIUM",
                confidence_reason="one blocked request; other inputs and paths are not covered",
                coverage=coverage,
                limitations=list(self.limits),
                exposure=finding["exploitability_context"]["exposure"],
            )

        return make_assessment(
            POTENTIALLY_EXPLOITABLE,
            reason=(f"{event['rule_id']} did not block this {event['category']} request on {span}; the "
                    "attack reached the application, and whether the sink executed is not established"),
            engine=self.name,
            conditions={"attacker_influence": Condition(CONFIRMED, [event["input"]["name"]]),
                        "reachable": Condition(UNKNOWN_STATUS)},
            evidence=evidence,
            confidence="MEDIUM",
            confidence_reason="the allowed event is observed; its effect is not",
            coverage=coverage,
            limitations=list(self.limits),
            exposure=finding["exploitability_context"]["exposure"],
        )
