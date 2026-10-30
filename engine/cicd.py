"""CI/CD engine: checks a Zizmor finding against the workflow and its trigger list.

For each CICD finding with a location:
1. Resolves the workflow file inside the project, as the other engines do.
2. Checks that the Primary location's text appears on the reported line. A mismatch means the
   scan does not describe the file, so the verdict is UNKNOWN.
3. Parses the workflow and reads its triggers. Whether an external actor can start the workflow
   depends on the trigger list only. This engine does not see repository settings.
4. Applies one rule per audit it understands:
   - template-injection: a `${{ }}` expression that names an attacker-writable field
     (title, body, head_ref and similar) in a workflow an external actor can trigger gives
     POTENTIALLY_EXPLOITABLE. If every trigger is writer-only (push, workflow_dispatch,
     schedule, release), no external actor can start it, so the verdict is NOT_EXPLOITABLE,
     backed by the trigger list.
   - dangerous-triggers: `pull_request_target` with a checkout of the pull request's head
     runs the attacker's code with the base repository's secrets. That gives POTENTIALLY_EXPLOITABLE.
     Without such a checkout the trigger alone is not an exploit path, so the verdict is UNKNOWN.
   - every other audit (unpinned-uses, artipacked, excessive-permissions, ...) is a hygiene or
     supply-chain rule with no exploitation path analysed here. Its verdict is UNKNOWN.

It never returns CONFIRMED_EXPLOITABLE, because reachability depends on repository settings
(first-time contributor approval, fork policy, environment protection) that the engine cannot
see. It never returns MITIGATED.
"""

import re

import yaml

from engine.universal import (
    NOT_CONFIRMED, NOT_EXPLOITABLE, POTENTIALLY_EXPLOITABLE, UNKNOWN_STATUS, CONFIRMED,
    Condition, Engine, make_assessment, resolve_project_file, unknown_assessment,
)

NAME = "cicd-trigger-analysis"

# Triggers an external actor can start, even on a fork or a public issue.
EXTERNAL_TRIGGERS = frozenset({
    "pull_request", "pull_request_target", "pull_request_review", "pull_request_review_comment",
    "issue_comment", "issues", "discussion", "discussion_comment", "workflow_run",
})
# Triggers only a user with write access, or no user, can start.
WRITER_ONLY_TRIGGERS = frozenset({"push", "workflow_dispatch", "schedule", "release"})

EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
# Context fields whose value an outside author writes (title, body, branch name, and similar).
ATTACKER_WRITABLE = re.compile(r"\.(title|body|head_ref|message|label|name)\b|head_ref")


def _triggers(document) -> set[str]:
    if not isinstance(document, dict):
        return set()
    # YAML 1.1 reads a bare `on:` key as the boolean True.
    raw = document["on"] if "on" in document else document.get(True)
    if isinstance(raw, str):
        return {raw}
    if isinstance(raw, list):
        return {str(item) for item in raw}
    if isinstance(raw, dict):
        return {str(key) for key in raw}
    return set()


def _checks_out_pull_request_head(document) -> bool:
    jobs = document.get("jobs") if isinstance(document, dict) else None
    for job in (jobs or {}).values():
        for step in (job or {}).get("steps") or []:
            uses = step.get("uses", "") if isinstance(step, dict) else ""
            if not uses.startswith("actions/checkout"):
                continue
            ref = str((step.get("with") or {}).get("ref", ""))
            if "pull_request.head" in ref or "head.sha" in ref or "head.ref" in ref:
                return True
    return False


def _primary(finding: dict) -> dict | None:
    for location in finding["original"].get("locations", []):
        if location.get("symbolic", {}).get("kind") == "Primary":
            return location
    return None


class CicdEngine(Engine):
    name = NAME
    categories = ("CICD",)
    techniques = ("scanner text re-verification", "trigger list analysis",
                  "pull_request_target checkout analysis", "expression field analysis")
    limits = (
        "repository settings are not visible: fork approval, environment protection, "
        "first-time contributor gates",
        "a writer with access can still change the workflow or its inputs; the rules here are "
        "about external actors",
        "GitHub API audits (impostor commits, ref checks) are not run in offline mode",
        "only the Primary location of each finding is checked",
        "secrets available to the job are not analysed",
    )

    def assess(self, finding: dict, context: dict):
        location = finding.get("location")
        if not location:
            return unknown_assessment("the finding has no source location", engine=self.name)
        target, problem = resolve_project_file(context["project_dir"], location["path"])
        if target is None:
            return unknown_assessment(problem, engine=self.name)

        lines = target.read_text(encoding="utf-8", errors="strict").splitlines()
        primary = _primary(finding)
        if primary is None:
            return unknown_assessment("the scanner gave no primary location", engine=self.name)
        feature = primary["concrete"].get("feature", "")
        first = feature.splitlines()[0].strip() if feature.strip() else ""
        row = location["start_line"] - 1
        if not first or row >= len(lines) or first not in lines[row]:
            return unknown_assessment(
                f"the scanned text does not appear at {location['path']}:{location['start_line']}; "
                "the scan is stale", engine=self.name)

        document = self._workflow("\n".join(lines))
        if document is None:
            return unknown_assessment(f"{location['path']} does not parse as YAML", engine=self.name)

        span = f"{location['path']}:{location['start_line']}"
        ident = finding["vulnerability"]["rule_id"]
        check = _Check(finding, span, feature, document, self.limits)
        if ident == "template-injection":
            return self._template_injection(check)
        if ident == "dangerous-triggers":
            return self._dangerous_triggers(check)
        return unknown_assessment(
            f"{ident} is a hygiene or supply-chain rule; no exploitation path is analysed for it",
            engine=self.name, limitation=f"{ident} rules give no exploitation path in this engine")

    def _workflow(self, text: str):
        try:
            return yaml.safe_load(text)
        except yaml.YAMLError:
            return None

    def _template_injection(self, check):
        triggers = _triggers(check.document)
        expressions = [e.strip() for e in EXPRESSION.findall(check.feature)]
        writable = [e for e in expressions if ATTACKER_WRITABLE.search(e)]

        if writable and triggers & EXTERNAL_TRIGGERS:
            external = sorted(triggers & EXTERNAL_TRIGGERS)
            return make_assessment(
                POTENTIALLY_EXPLOITABLE,
                reason=("an expression puts text that an outside author writes into a shell step, "
                        "and an external actor can start this workflow"),
                engine=self.name,
                conditions={
                    "attacker_influence": Condition(CONFIRMED, [f"{check.span} {writable[0]}"]),
                    "reachable": Condition(UNKNOWN_STATUS),
                },
                evidence=check.verified + [
                    {"condition": "attacker_influence", "kind": "source",
                     "detail": f"expression {writable[0]} is written by the event author"},
                    {"condition": None, "kind": "trigger",
                     "detail": f"external triggers: {', '.join(external)}"}],
                confidence="MEDIUM",
                confidence_reason="the field and trigger are read from the file; repository "
                                  "gates are not visible",
                coverage=check.coverage,
                limitations=list(self.limits),
                exposure=check.exposure,
            )

        if triggers and triggers <= WRITER_ONLY_TRIGGERS:
            names = ", ".join(sorted(triggers))
            return make_assessment(
                NOT_EXPLOITABLE,
                reason="every trigger is writer-only, so no external actor can start this workflow",
                engine=self.name,
                conditions={"reachable": Condition(NOT_CONFIRMED, [f"triggers: {names}"])},
                evidence=check.verified + [{"condition": "reachable", "kind": "trigger",
                                            "detail": f"triggers {names} need write access"}],
                confidence="MEDIUM",
                confidence_reason="the trigger list is read from the file",
                coverage=check.coverage,
                limitations=list(self.limits) + [
                    "this verdict is against an external attacker, not against a writer"],
                exposure=check.exposure,
            )

        return unknown_assessment(
            "the expression's trigger is neither clearly external nor writer-only",
            engine=self.name, limitation="trigger reachability is not established")

    def _dangerous_triggers(self, check):
        if "pull_request_target" not in _triggers(check.document):
            return unknown_assessment("pull_request_target is not a trigger of this workflow",
                                      engine=self.name)
        if not _checks_out_pull_request_head(check.document):
            return unknown_assessment(
                "pull_request_target runs without a checkout of the pull request's head; the "
                "trigger alone is not an exploit path", engine=self.name)
        return make_assessment(
            POTENTIALLY_EXPLOITABLE,
            reason=("pull_request_target checks out the pull request's head, so the outside "
                    "author's code runs with the base repository's secrets"),
            engine=self.name,
            conditions={
                "attacker_influence": Condition(CONFIRMED, [f"{check.span} checks out the head ref"]),
                "reachable": Condition(UNKNOWN_STATUS),
            },
            evidence=check.verified + [{"condition": "attacker_influence", "kind": "source",
                                        "detail": f"checkout of pull request head at {check.span}"}],
            confidence="MEDIUM",
            confidence_reason="the trigger and checkout are read from the file",
            coverage=check.coverage,
            limitations=list(self.limits),
            exposure=check.exposure,
        )


class _Check:
    """The values one finding's rule needs, gathered once in CicdEngine.assess."""

    def __init__(self, finding, span, feature, document, limits):
        self.span = span
        self.feature = feature
        self.document = document
        self.exposure = finding["exploitability_context"]["exposure"]
        self.verified = [{"condition": None, "kind": "source", "detail": f"text verified at {span}"}]
        self.coverage = {"analysed": [f"{span} scanner text matches the workflow"],
                         "not_analysed": list(limits)}
