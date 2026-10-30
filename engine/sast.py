"""SAST engine: checks a scanner's flagged call site in the analysed source.

What it does, for each SAST finding with a location:
1. Resolves the path inside the project. A path that escapes the project is refused.
2. For Python files, parses the file and finds the call expression that spans the flagged
   location (start and end line and column must match). The call's arguments are checked:
   if every argument is a literal constant, no attacker data reaches this call, so the
   verdict is NOT_EXPLOITABLE for this call site. Otherwise the verdict is
   POTENTIALLY_EXPLOITABLE, because the engine does not follow data flow.
3. For other languages, no source-level analysis is done. The scanner's match is reported
   as POTENTIALLY_EXPLOITABLE with LOW confidence.

It never returns CONFIRMED_EXPLOITABLE. That needs confirmed data flow from an entry
point, preconditions, and declared internet exposure, and this engine checks none of them.
It never returns MITIGATED, because no mitigation is verified.
"""

import ast

from engine.universal import (
    NOT_CONFIRMED, NOT_EXPLOITABLE, POTENTIALLY_EXPLOITABLE, UNKNOWN_STATUS, Condition, Engine,
    make_assessment, resolve_project_file, unknown_assessment,
)

NAME = "sast-call-site"


def _is_constant(node: ast.AST) -> bool:
    """True only when the expression is built from literals. A name is never a constant here,
    because its value depends on code this engine does not follow."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.JoinedStr):
        return all(isinstance(v, ast.Constant) for v in node.values)
    if isinstance(node, ast.BinOp):
        return _is_constant(node.left) and _is_constant(node.right)
    if isinstance(node, (ast.Tuple, ast.List)):
        return all(_is_constant(e) for e in node.elts)
    return False


def _call_spanning(tree: ast.AST, location: dict) -> ast.Call | None:
    """The call whose start and end match the scanner's location exactly, or None."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if (node.lineno == location["start_line"]
                and node.col_offset + 1 == location["start_col"]
                and node.end_lineno == location["end_line"]
                and node.end_col_offset + 1 == location["end_col"]):
            return node
    return None


class SastEngine(Engine):
    name = NAME
    categories = ("SAST",)
    techniques = ("location resolution", "python ast call-site lookup", "literal-argument check")
    limits = (
        "no interprocedural data flow: an argument's value is not traced into callers",
        "no sanitiser model: a call to a sanitiser is treated as non-constant",
        "non-Python files get no source-level analysis",
        "other sinks in the same file are not assessed by a single finding",
        "exposure and authentication are not assessed",
    )

    def assess(self, finding: dict, context: dict):
        location = finding.get("location")
        if not location:
            return unknown_assessment("the finding has no source location", engine=self.name)

        target, problem = resolve_project_file(context["project_dir"], location["path"])
        if target is None:
            return unknown_assessment(problem, engine=self.name)

        coverage_common = {
            "analysed": [f"{location['path']}:{location['start_line']} location resolved"],
            "not_analysed": list(self.limits),
        }
        base_limits = list(self.limits)

        if target.suffix != ".py":
            return make_assessment(
                POTENTIALLY_EXPLOITABLE,
                reason="scanner pattern matched; no source-level analysis exists for this file type",
                engine=self.name,
                conditions={"attacker_influence": Condition(UNKNOWN_STATUS)},
                evidence=[{"condition": None, "kind": "location",
                           "detail": f"{location['path']} exists"}],
                confidence="LOW",
                confidence_reason="only the scanner's pattern match is available",
                coverage=coverage_common,
                limitations=base_limits,
                exposure=finding["exploitability_context"]["exposure"],
            )

        try:
            source = target.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return unknown_assessment(f"{location['path']} is not valid UTF-8", engine=self.name)
        try:
            tree = ast.parse(source, filename=location["path"])
        except (SyntaxError, ValueError):
            return unknown_assessment(f"{location['path']} does not parse as Python",
                                      engine=self.name)

        call = _call_spanning(tree, location)
        if call is None:
            return unknown_assessment(
                "no call expression matches the scanner's location, so the site was not verified",
                engine=self.name)

        arguments = list(call.args) + [kw.value for kw in call.keywords]
        if not arguments:
            return unknown_assessment("the flagged call has no arguments to check",
                                      engine=self.name)

        span = f"{location['path']}:{location['start_line']}"
        if all(_is_constant(arg) for arg in arguments):
            return make_assessment(
                NOT_EXPLOITABLE,
                reason=("every argument of the flagged call is a literal constant, so no "
                        "attacker data reaches this call site"),
                engine=self.name,
                conditions={"attacker_influence": Condition(NOT_CONFIRMED, [f"{span} literal arguments"])},
                evidence=[{"condition": "attacker_influence", "kind": "ast",
                           "detail": f"all {len(arguments)} argument(s) at {span} are literals"}],
                confidence="MEDIUM",
                confidence_reason="single call site, arguments checked by the Python AST",
                coverage=coverage_common,
                limitations=base_limits + [
                    "a literal argument does not clear other sinks or other rules for this file"],
                exposure=finding["exploitability_context"]["exposure"],
            )

        non_literal = [ast.unparse(arg)[:120] for arg in arguments if not _is_constant(arg)]
        return make_assessment(
            POTENTIALLY_EXPLOITABLE,
            reason=("the flagged call has an argument that is not a literal; whether attacker "
                    "data reaches it is not established by this engine"),
            engine=self.name,
            conditions={"attacker_influence": Condition(UNKNOWN_STATUS)},
            evidence=[{"condition": "attacker_influence", "kind": "ast",
                       "detail": f"non-literal argument at {span}: {non_literal[0]}"}],
            confidence="LOW",
            confidence_reason="data flow into the argument is not traced",
            coverage=coverage_common,
            limitations=base_limits,
            exposure=finding["exploitability_context"]["exposure"],
        )
