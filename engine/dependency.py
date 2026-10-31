"""Version status of an installed dependency against the fixed versions its advisory names.

This is one dimension of a dependency finding. It answers only "is the installed version at or past a fixed version
on its release line?". It does not say the component is used, that the vulnerable code runs, or that an attacker can
reach it. Those are other dimensions, and no status here implies them.

The fixed versions come from the scanner's own record, so the status is traceable to that source. Each status carries
the reason, so a reader can see which comparison was made.
"""

import re

from engine import versions

FIXED_INSTALLED = "FIXED_INSTALLED"
BELOW_FIXED = "BELOW_FIXED"
NO_FIX_FOR_LINE = "NO_FIX_FOR_LINE"
NO_FIX_RECORDED = "NO_FIX_RECORDED"
VERSION_MISSING = "VERSION_MISSING"
UNSUPPORTED_ECOSYSTEM = "UNSUPPORTED_ECOSYSTEM"
UNCOMPARABLE = "UNCOMPARABLE"

_LINE = re.compile(r"^[vV]?(\d+)(?:\.(\d+))?")


def release_line(version: str) -> str | None:
    """The major and minor numbers, which name the release line: '1.4.1' is line '1.4', and '0.7.4' is '0.7'. A fix
    on another minor line does not cover this version, because the record does not say the line is fixed."""
    match = _LINE.match(version or "")
    if not match:
        return None
    return f"{match.group(1)}.{match.group(2) or '0'}"


def fixed_candidates(record: dict) -> list[str]:
    fixed = record.get("fixed_version") or ""
    return [part.strip() for part in fixed.split(",") if part.strip()]


def version_status(record: dict) -> dict:
    """{'status', 'reason', 'fixed'} for a normalised dependency record (see engine/findings.py)."""
    ecosystem = record.get("ecosystem") or "unknown"
    installed = record.get("version")
    name = record.get("name") or "unknown"
    if not installed:
        return {"status": VERSION_MISSING, "reason": f"the installed version of {name} is not recorded",
                "fixed": None}
    candidates = fixed_candidates(record)
    if not candidates:
        return {"status": NO_FIX_RECORDED,
                "reason": f"the scanner records no fixed version for {name}@{installed}", "fixed": None}
    if versions.compare(ecosystem, installed, installed) is None:
        return {"status": UNSUPPORTED_ECOSYSTEM,
                "reason": f"version comparison is not supported for ecosystem {ecosystem}", "fixed": None}
    line = release_line(installed)
    same_line = [c for c in candidates if release_line(c) == line]
    if not same_line:
        return {"status": NO_FIX_FOR_LINE,
                "reason": f"no fixed version on the {installed} release line in the scanner's record",
                "fixed": None}
    for fixed in same_line:
        order = versions.compare(ecosystem, installed, fixed)
        if order is None:
            return {"status": UNCOMPARABLE,
                    "reason": f"{installed} and {fixed} cannot be ordered for ecosystem {ecosystem}", "fixed": fixed}
        if order >= 0:
            return {"status": FIXED_INSTALLED,
                    "reason": f"installed {installed} is at or after the fixed version {fixed} on its release line",
                    "fixed": fixed}
    return {"status": BELOW_FIXED,
            "reason": (f"installed {installed} is below the fixed version {same_line[0]} on its release line; "
                       "the version the vulnerability was introduced in is not established"),
            "fixed": same_line[0]}
