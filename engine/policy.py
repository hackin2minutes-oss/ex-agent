"""Policy-as-code.

A policy file (YAML) sets the action for each classification and severity. The
action is one of: block, warn, report. Anything not listed is "report", except
that an unknown severity defaults to "warn", so a finding is never silently
dropped.

The policy is validated on load. Unknown keys, unknown classifications and invalid
actions are rejected, so a typo cannot quietly weaken enforcement.
"""

from pathlib import Path

import yaml

from engine import exploitability

ACTIONS = ("block", "warn", "report")
SEVERITIES = ("critical", "high", "medium", "low", "unknown")
TOP_KEYS = {"version", "exploitability", "intelligence"}
INTELLIGENCE_KEYS = {"kev", "epss", "stale_data"}
SUPPORTED_VERSION = 1

POLICY_CLASSES = set(exploitability.CLASSIFICATIONS)


class PolicyError(ValueError):
    pass


def _action(value, where: str) -> str:
    if value not in ACTIONS:
        raise PolicyError(f"{where}: action must be one of {ACTIONS}, got {value!r}")
    return value


def _validate_exploitability(section: dict) -> dict:
    result: dict = {}
    for key, value in section.items():
        if key not in POLICY_CLASSES:
            raise PolicyError(f"exploitability.{key}: unknown classification")
        if isinstance(value, str):
            result[key] = {"action": _action(value, f"exploitability.{key}")}
        elif isinstance(value, dict):
            entry: dict = {}
            for sub, sub_value in value.items():
                if sub == "action":
                    entry["action"] = _action(sub_value, f"exploitability.{key}")
                elif sub in SEVERITIES:
                    entry[sub] = _action(sub_value, f"exploitability.{key}.{sub}")
                else:
                    raise PolicyError(f"exploitability.{key}.{sub}: unknown severity or key")
            result[key] = entry
        else:
            raise PolicyError(f"exploitability.{key}: expected an action or a severity map")
    return result


def _validate_intelligence(section: dict) -> dict:
    for key in section:
        if key not in INTELLIGENCE_KEYS:
            raise PolicyError(f"intelligence.{key}: unknown key")
    return section


def load_policy(path: Path) -> dict:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise PolicyError("policy must be a mapping")
    for key in data:
        if key not in TOP_KEYS:
            raise PolicyError(f"{key}: unknown top-level key")
    if data.get("version") != SUPPORTED_VERSION:
        raise PolicyError(f"version must be {SUPPORTED_VERSION}")
    return {
        "version": SUPPORTED_VERSION,
        "exploitability": _validate_exploitability(data.get("exploitability", {}) or {}),
        "intelligence": _validate_intelligence(data.get("intelligence", {}) or {}),
    }


def action_for(policy: dict, classification: str, severity: str | None) -> tuple[str, str]:
    """Return (action, rule) for one finding."""
    sev = (severity or "unknown").lower()
    if sev not in SEVERITIES:
        sev = "unknown"
    entry = policy["exploitability"].get(classification)
    if entry is None:
        return "report", f"default for {classification}"
    if sev in entry:
        return entry[sev], f"exploitability.{classification}.{sev}"
    if "action" in entry:
        return entry["action"], f"exploitability.{classification}"
    fallback = "warn" if sev == "unknown" else "report"
    return fallback, f"exploitability.{classification}.{sev} (no rule; default {fallback})"


def evaluate(policy: dict, findings: list[dict]) -> dict:
    """Attach a policy decision to each finding and return a summary."""
    counts = {action: 0 for action in ACTIONS}
    for finding in findings:
        action, rule = action_for(policy, finding["classification"],
                                  (finding.get("vulnerability") or {}).get("severity"))
        finding["policy"] = {"action": action, "rule": rule}
        counts[action] += 1
    return {"policy_version": policy["version"], "decisions": counts,
            "blocked": counts["block"] > 0}
