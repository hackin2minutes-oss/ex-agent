"""CVE-specific precondition checks, from curated rules.

A rule lists checks of two kinds:

- "requires": the precondition holds when the pattern is found. A match gives
  "satisfied". No match gives "unverified", because absence in text does not
  prove the configuration is absent at runtime.
- "mitigated_by": a mitigation is in place when the pattern is found. A match
  gives "not_satisfied". No match gives "unverified".

Checks are static text matches. They do not read runtime configuration, so the
result is always scoped to the analysed files.

The aggregate is "satisfied" only if every check is satisfied. It is
"not_satisfied" if any check is not satisfied. Otherwise it is "unverified".
"""

import re
from fnmatch import fnmatch
from pathlib import Path

_KINDS = {"requires", "mitigated_by"}


def _glob_matches(relative: str, glob: str) -> bool:
    # A leading "**/" also matches files at the root.
    if fnmatch(relative, glob):
        return True
    return glob.startswith("**/") and fnmatch(relative, glob[3:])


def _matching_files(source_root: Path, glob: str):
    for path in sorted(source_root.rglob("*")):
        if path.is_file() and _glob_matches(path.relative_to(source_root).as_posix(), glob):
            yield path


def _check_one(check: dict, source_root: Path) -> dict:
    kind = check["kind"]
    if kind not in _KINDS:
        raise ValueError(f"unknown precondition kind: {kind}")
    pattern = re.compile(check["regex"])
    hits = []
    for path in _matching_files(source_root, check.get("glob", "**/*")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), 1):
            if pattern.search(line):
                hits.append({"file": path.relative_to(source_root).as_posix(), "line": lineno})
    found = bool(hits)
    if kind == "requires":
        result = "satisfied" if found else "unverified"
    else:
        result = "not_satisfied" if found else "unverified"
    return {"id": check["id"], "kind": kind, "description": check.get("description", ""),
            "result": result, "locations": hits}


def evaluate(rule_checks: list[dict] | None, source_root: Path) -> tuple[str, list[dict]]:
    if not rule_checks:
        return "unverified", [{"result": "unverified", "reason": "No curated precondition rule"}]
    results = [_check_one(c, source_root) for c in rule_checks]
    outcomes = {r["result"] for r in results}
    if "not_satisfied" in outcomes:
        aggregate = "not_satisfied"
    elif outcomes == {"satisfied"}:
        aggregate = "satisfied"
    else:
        aggregate = "unverified"
    return aggregate, results
