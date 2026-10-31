"""Planners choose the next investigation step.

A planner only proposes. The toolbox runs each proposed tool, and each proposed conclusion goes through citation checks
and the UNKNOWN gate before it is accepted.

Proposals have one of two shapes:
  {"action": "tool", "tool": "<name>", "args": {...}}
  {"action": "conclude", "conclusion": {"verdict", "reason", "claims": [{"text", "evidence": [ids]}],
                                         "missing_evidence": [{"what", "resolves_with"}]}}

OfflinePlanner is deterministic and needs no model. It gathers source around the finding and searches for the symbol
it is about. It cannot judge exploitability, so it concludes UNKNOWN and says what it could not establish.
"""

from engine.universal import UNKNOWN


class OfflinePlanner:
    name = "offline"

    def next_step(self, state: dict) -> dict:
        finding = state["finding"]
        done = [entry["tool"] for entry in state["log"]]  # attempted, so a failed call is not retried forever
        path, line = finding.get("path"), finding.get("line")
        if path and line and "read_source" not in done:
            return {"action": "tool", "tool": "read_source", "args": {"path": path, "line": line}}
        symbol = finding.get("symbol")
        if symbol and len(symbol) >= 3 and "search_source" not in done:
            return {"action": "tool", "tool": "search_source", "args": {"text": symbol}}
        return {"action": "conclude", "conclusion": self._unknown(state)}

    def _unknown(self, state: dict) -> dict:
        finding_id = state["evidence"][0]["id"] if state["evidence"] else None
        claims = [{"text": "The offline planner has no model to judge exploitability. It gathered the checks listed "
                           "below and stopped.",
                   "evidence": [finding_id] if finding_id else []}]
        return {
            "verdict": UNKNOWN,
            "reason": "the offline planner cannot decide exploitability from source text alone",
            "claims": claims,
            "missing_evidence": [
                {"what": "whether an entry point from outside reaches this code",
                 "resolves_with": "route and call-graph analysis from the application's entry points"},
                {"what": "whether input is validated on the path",
                 "resolves_with": "a model planner or a reviewer reading the code around each call"},
                {"what": "whether the route is exposed in the deployed configuration",
                 "resolves_with": "deployment configuration or a request against a running instance"},
            ],
        }
