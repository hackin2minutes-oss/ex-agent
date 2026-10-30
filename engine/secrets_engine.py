"""Secrets engine: checks where a credential is stored. It does not check whether it works.

For each SECRET finding with a location:
1. Resolves the file inside the project.
2. Finds the scanner's match in the reported line by content, and compares a hash of each window
   of the same length. The match is not located by Gitleaks' columns, which were measured to be
   off by one in the output this was built on. A line that no longer contains the match gives
   UNKNOWN: the scan is stale.
3. A match in a test, example, fixture, sample or documentation path gives UNKNOWN. Whether such a
   value is live is not established. A match in any other path gives POTENTIALLY_EXPLOITABLE: a
   credential-shaped value is stored in the source, and its validity is not checked.

No live validation is done. Validating a credential would contact the service it belongs to, and
that is not authorised for this engine (docs/UNIVERSAL_ARCHITECTURE.md, decision 4). So a verdict
is never CONFIRMED_EXPLOITABLE, NOT_EXPLOITABLE or MITIGATED.
"""

from pathlib import PurePosixPath

from engine.gitleaks_adapter import digest
from engine.universal import (
    POTENTIALLY_EXPLOITABLE, UNKNOWN_STATUS, Condition, Engine, make_assessment,
    resolve_project_file, unknown_assessment,
)

NAME = "secret-location"
MAX_LINE = 10_000  # a window search is quadratic in line length
NON_PRODUCTION_PARTS = frozenset({
    "test", "tests", "testdata", "fixture", "fixtures", "example", "examples",
    "sample", "samples", "doc", "docs", "mock", "mocks",
})


def _non_production(path: str) -> bool:
    parts = {part.lower() for part in PurePosixPath(path).parts}
    return bool(parts & NON_PRODUCTION_PARTS)


def _window_matches(line: str, length: int, expected: str) -> bool:
    for start in range(0, len(line) - length + 1):
        if digest(line[start:start + length]) == expected:
            return True
    return False


class SecretsEngine(Engine):
    name = NAME
    categories = ("SECRET",)
    techniques = ("location verification by hash", "path classification")
    limits = (
        "no live validation: whether the credential works, and what it can access, is not checked",
        "git history is not assessed by this run; only the scanned files are",
        "the credential's scope and permissions are not known",
        "a value read from the environment or a secret store is not a finding and is not assessed",
        "the match is located by content, not by Gitleaks' column offsets",
    )

    def assess(self, finding: dict, context: dict):
        location = finding.get("location")
        if not location:
            return unknown_assessment("the finding has no source location", engine=self.name)
        target, problem = resolve_project_file(context["project_dir"], location["path"])
        if target is None:
            return unknown_assessment(problem, engine=self.name)

        lines = target.read_text(encoding="utf-8", errors="strict").splitlines()
        row = location["start_line"] - 1
        original = finding["original"]
        span = f"{location['path']}:{location['start_line']}"
        if location["end_line"] != location["start_line"]:
            return unknown_assessment(f"{span} is a multi-line match, which is not verified",
                                      engine=self.name)
        if row < len(lines) and len(lines[row]) > MAX_LINE:
            return unknown_assessment(f"{span} is longer than {MAX_LINE} characters and was not searched",
                                      engine=self.name)
        if row >= len(lines) or not _window_matches(lines[row], original["match_length"],
                                                    original["match_sha256"]):
            return unknown_assessment(
                f"the reported credential no longer appears at {span}; the scan is stale",
                engine=self.name)

        coverage = {"analysed": [f"{span} match located by content"],
                    "not_analysed": list(self.limits)}
        evidence = [{"condition": None, "kind": "source",
                     "detail": f"a value matching the scanner's digest is at {span}"}]
        if _non_production(location["path"]):
            return unknown_assessment(
                f"{location['path']} is a test, example or documentation path; whether the "
                "value is a live credential is not established", engine=self.name)

        return make_assessment(
            POTENTIALLY_EXPLOITABLE,
            reason=("a credential-shaped value is stored in a non-test source file; its validity "
                    "and scope were not checked"),
            engine=self.name,
            conditions={
                "vulnerability_exists": Condition(UNKNOWN_STATUS, ["validity not checked"]),
                "reachable": Condition(UNKNOWN_STATUS),
            },
            evidence=evidence,
            confidence="MEDIUM",
            confidence_reason="the value's location is verified; its validity is not",
            coverage=coverage,
            limitations=list(self.limits),
            exposure=finding["exploitability_context"]["exposure"],
        )
