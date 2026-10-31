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

import os

from engine.universal import UNKNOWN

PLANNER_ENV = "SAWONE_PLANNER"       # "offline" (default) or "anthropic"
API_KEY_ENV = "ANTHROPIC_API_KEY"    # read from the environment only; never stored in a result or log
MODEL_ENV = "SAWONE_MODEL"           # optional model id for the anthropic planner


class PlannerError(RuntimeError):
    """A planner could not produce a step. The loop ends the investigation as ANALYSIS_INCOMPLETE with this message."""


def select_planner(name: str | None = None, env=os.environ, *, transport=None):
    """The planner named by `name`, else by SAWONE_PLANNER, else the offline planner.

    An unknown name, or a named planner whose key is missing, is an error. It is never a silent fallback to offline,
    because a silent fallback would look like a model verdict.
    """
    chosen = (name or env.get(PLANNER_ENV) or "offline").strip().lower()
    if chosen == "offline":
        return OfflinePlanner()
    if chosen == "anthropic":
        from engine.investigation.anthropic_planner import DEFAULT_MODEL, AnthropicPlanner
        return AnthropicPlanner(env.get(API_KEY_ENV, ""), model=env.get(MODEL_ENV) or DEFAULT_MODEL,
                                transport=transport)
    raise PlannerError(f"unknown planner {chosen!r}; use 'offline' or 'anthropic'")


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
