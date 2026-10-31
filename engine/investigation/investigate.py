"""The investigation loop: ingest a finding, let the planner take steps, and accept only a conclusion that checks out.

Verdicts that this loop can return are the engine's own verdict names. Three rules hold regardless of the planner:

1. Citations are checked (citations.py). A conclusion that cites a missing record, or a line that is not in the file,
   is refused. The result is ANALYSIS_INCOMPLETE, never a guessed verdict.
2. Static evidence cannot confirm exploitation. A CONFIRMED_EXPLOITABLE conclusion with no demonstrated evidence is
   reported as POTENTIALLY_EXPLOITABLE, and the reason is recorded.
3. UNKNOWN is allowed only when the investigation ran at least two different tools successfully, and the conclusion
   lists the evidence still missing, with what would resolve each item. Otherwise it is refused as ANALYSIS_INCOMPLETE.

The loop stops at a step budget. Running out of budget is ANALYSIS_INCOMPLETE, with the steps taken recorded.
"""

from dataclasses import dataclass, field
from pathlib import Path

from engine.investigation.citations import check_conclusion, demonstrated_for
from engine.investigation.evidence import EvidenceStore
from engine.investigation.planner import PlannerError
from engine.investigation.tools import Toolbox, ToolError
from engine.universal import ANALYSIS_INCOMPLETE, CONFIRMED_EXPLOITABLE, POTENTIALLY_EXPLOITABLE, UNKNOWN

DEFAULT_MAX_STEPS = 12
MIN_TOOL_RUNS_FOR_UNKNOWN = 2
MIN_DISTINCT_TOOLS_FOR_UNKNOWN = 2


@dataclass
class Result:
    verdict: str
    reason: str
    evidence: list[dict] = field(default_factory=list)
    log: list[dict] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    missing_evidence: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"verdict": self.verdict, "reason": self.reason, "evidence": self.evidence, "log": self.log,
                "problems": self.problems, "missing_evidence": self.missing_evidence}


def unknown_gate(conclusion: dict, log: list[dict]) -> list[str]:
    """Why an UNKNOWN conclusion is refused. Empty when the investigation earned it."""
    runs = [entry for entry in log if entry.get("evidence")]
    problems = []
    if len(runs) < MIN_TOOL_RUNS_FOR_UNKNOWN:
        problems.append(f"UNKNOWN needs at least {MIN_TOOL_RUNS_FOR_UNKNOWN} successful tool runs; there were {len(runs)}")
    if len({entry["tool"] for entry in runs}) < MIN_DISTINCT_TOOLS_FOR_UNKNOWN:
        problems.append("UNKNOWN needs at least two different tools to have been run")
    missing = conclusion.get("missing_evidence") or []
    if not missing:
        problems.append("UNKNOWN must list the evidence that is missing")
    for item in missing:
        if not item.get("what") or not item.get("resolves_with"):
            problems.append(f"missing evidence needs 'what' and 'resolves_with': {item}")
    return problems


def _incomplete(reason: str, problems: list[str], evidence: EvidenceStore, log: list[dict]) -> Result:
    return Result(verdict=ANALYSIS_INCOMPLETE, reason=reason, evidence=[e.to_dict() for e in evidence.all()],
                  log=log, problems=problems)


def investigate(finding: dict, project_dir: Path, planner, *, max_steps: int = DEFAULT_MAX_STEPS) -> Result:
    store = EvidenceStore()
    toolbox = Toolbox(project_dir, store)
    store.add(kind="finding", tool="ingest", summary=finding.get("title", "finding"), path=finding.get("path"),
              line=finding.get("line"))
    log: list[dict] = []
    for _ in range(max_steps):
        state = {"finding": finding, "evidence": [e.to_dict() for e in store.all()], "log": log,
                 "tools": toolbox.describe()}
        try:
            step = planner.next_step(state)
        except PlannerError as error:
            return _incomplete("the planner could not produce a step", [str(error)], store, log)
        if step.get("action") == "tool":
            entry = {"tool": step.get("tool"), "args": step.get("args", {})}
            try:
                found = toolbox.run(step.get("tool"), step.get("args", {}))
                entry["evidence"] = [e.id for e in found]
            except ToolError as error:
                entry["error"] = str(error)
            log.append(entry)
            continue
        if step.get("action") == "conclude":
            return _conclude(step.get("conclusion") or {}, store, project_dir, log)
        return _incomplete(f"planner returned an unknown action {step.get('action')!r}", [], store, log)
    return _incomplete(f"the investigation used its {max_steps}-step budget before concluding", [], store, log)


def _conclude(conclusion: dict, store: EvidenceStore, project_dir: Path, log: list[dict]) -> Result:
    problems = check_conclusion(conclusion, store, project_dir)
    if problems:
        return _incomplete("the conclusion failed its citation checks", problems, store, log)
    verdict = conclusion["verdict"]
    reason = conclusion.get("reason", "")
    if verdict == CONFIRMED_EXPLOITABLE and not demonstrated_for(conclusion, store):
        verdict = POTENTIALLY_EXPLOITABLE
        reason = f"{reason}; static evidence alone cannot confirm exploitation, so this is potentially exploitable".strip("; ")
    if verdict == UNKNOWN:
        problems = unknown_gate(conclusion, log)
        if problems:
            return _incomplete("UNKNOWN was refused", problems, store, log)
    return Result(verdict=verdict, reason=reason, evidence=[e.to_dict() for e in store.all()], log=log,
                  missing_evidence=conclusion.get("missing_evidence") or [])
