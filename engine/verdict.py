"""Decision logic.

Reachability and exploitability are separate fields. The verdict is derived from
both. "Not reachable" is reported only when the analysis is complete for its scope.
"""

TAINT_CONFIRMED = "confirmed"


def reachability(call_sites: list[dict], taint: str, analysis_complete: bool) -> str:
    """Return one of: confirmed, potentially, not_reachable, unknown."""
    if call_sites:
        return "confirmed" if taint == TAINT_CONFIRMED else "potentially"
    return "not_reachable" if analysis_complete else "unknown"


def verdict(reach: str, preconditions: str) -> str:
    if reach == "confirmed":
        if preconditions == "satisfied":
            return "confirmed_exploitable"
        if preconditions == "not_satisfied":
            return "not_exploitable_in_scope"
        return "potentially_exploitable"
    if reach == "potentially":
        return "potentially_exploitable"
    if reach == "not_reachable":
        return "not_reachable_in_scope"
    return "unknown"


def confidence(analysis_complete: bool, taint: str) -> str:
    if not analysis_complete:
        return "low"
    return "high" if taint == TAINT_CONFIRMED else "medium"


_GATES = {
    "confirmed_reachable": lambda reach, v: reach == "confirmed",
    "confirmed_exploitable": lambda reach, v: v == "confirmed_exploitable",
}


def gate_failed(fail_on: str, reach: str, final_verdict: str) -> bool:
    if fail_on not in _GATES:
        raise ValueError(f"unknown fail_on value: {fail_on}")
    return _GATES[fail_on](reach, final_verdict)
