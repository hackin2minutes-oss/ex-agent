"""SAST engine: checks a scanner's flagged call site in the analysed source.

For each SAST finding with a location:
1. Resolves the path inside the project. A path that escapes the project is refused.
2. For Python files, finds the call expression that spans the flagged location (start and end line and column
   must match). If every argument is a literal constant, no attacker data reaches the call: NOT_EXPLOITABLE.
3. Otherwise, with the shared application analysis (engine/application.py) it asks two questions:
   - Reachability: is the function containing the call reached from a route, and by which path?
   - Attacker influence: do the arguments carry a request value, traced through assignments in that function?
   Parameterised queries (constant SQL text with bound values) and numeric conversions (int, float) are
   recognised and reported as MITIGATED on that call, because the injection channel is closed there.
4. Verdict: CONFIRMED_EXPLOITABLE only when the call is reached from a route, the request value reaches it,
   no mitigation is present, and the application is declared internet-facing. NOT_REACHABLE only when the
   search of the whole application is complete and no route reaches the function. POTENTIALLY_EXPLOITABLE
   otherwise, with the conditions that are unverified.
5. Without the shared analysis (for example, a single file check), the call is POTENTIALLY_EXPLOITABLE, because
   the engine cannot tell whether the argument is attacker-controlled.
6. Other languages get no source-level analysis: UNKNOWN, LOW confidence.

Static analysis is not a demonstrated exploit. A CONFIRMED_EXPLOITABLE here means the static conditions are
satisfied on the traced path. No request was sent.
"""

import ast

from engine import deployment_context, preconditions, weakness
from engine.languages import analyzer_for
from engine.universal import (
    CONFIRMED, CONFIRMED_EXPLOITABLE, MITIGATED, NOT_CONFIRMED, NOT_EXPLOITABLE, NOT_REACHABLE, UNKNOWN,
    POTENTIALLY_EXPLOITABLE, UNKNOWN_STATUS, Condition, Engine, make_assessment, resolve_project_file,
    unknown_assessment,
)

NAME = "sast-call-site"
NUMERIC = "numeric"
REQUEST = preconditions.REQUEST
CONSTANT = preconditions.CONSTANT
UNKNOWN_ARG = preconditions.UNKNOWN_ARG
NUMERIC_CASTS = {"int", "float", "bool"}
SQL_EXECUTORS = {"execute", "executemany"}
# Escaping and encoding calls. Their output is not raw attacker text, but whether the result is safe depends on the
# sink, so they are not credited here. They are UNKNOWN.
SANITISER_NAMES = {"escape", "quote", "html", "secure_filename", "basename", "clean", "markup"}


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


def _callee_name(call: ast.Call) -> str:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return ""


def _combine(classes: set[str]) -> str:
    if REQUEST in classes:
        return REQUEST
    if UNKNOWN_ARG in classes or not classes:
        return UNKNOWN_ARG
    if NUMERIC in classes:
        return NUMERIC if classes <= {NUMERIC, CONSTANT} else UNKNOWN_ARG
    return CONSTANT


def _classify(node: ast.AST, names: dict, depth: int = 0) -> str:
    """REQUEST, NUMERIC, CONSTANT or UNKNOWN_ARG. A numeric cast (int, float, bool) turns any input into a number,
    which cannot carry an injection. Other sanitisers and unknown values stay UNKNOWN."""
    if depth > preconditions.MAX_ASSIGNMENT_DEPTH:
        return UNKNOWN_ARG
    if isinstance(node, ast.Call) and _callee_name(node) in NUMERIC_CASTS:
        return NUMERIC
    if isinstance(node, ast.Constant):
        return CONSTANT
    if isinstance(node, ast.JoinedStr) and any(isinstance(v, ast.FormattedValue) for v in node.values):
        # An interpolated field is a value, even when its content is a literal. It stays UNKNOWN, as in _is_constant.
        return UNKNOWN_ARG
    if isinstance(node, ast.Name):
        values = names.get(node.id)
        if not values:
            return UNKNOWN_ARG
        return _combine({_classify(v, names, depth + 1) for v in values})
    if preconditions.classify_python_argument(node, {}) == REQUEST:
        return REQUEST
    if isinstance(node, ast.Call) and _callee_name(node) in SANITISER_NAMES:
        return UNKNOWN_ARG
    if isinstance(node, ast.Call):
        # The callee's name is not a value. The result of an unknown call depends on its arguments.
        children = list(node.args) + [kw.value for kw in node.keywords]
    else:
        children = [c for c in ast.iter_child_nodes(node) if isinstance(c, ast.expr)]
    if not children:
        return UNKNOWN_ARG
    return _combine({_classify(c, names, depth) for c in children})


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


def _with_path(assessment, app, reach):
    """Attach the traced route-to-sink path to an assessment. Each hop names its file, function and line."""
    hops = []
    for node in reach.path:
        meta = app.graph.nodes[node]
        hops.append({"file": meta["file"], "function": meta["id"].split(":")[-1], "line": meta["line"]})
    assessment.attack_path = hops
    return assessment


class SastEngine(Engine):
    name = NAME
    categories = ("SAST",)
    techniques = ("location resolution", "python ast call-site lookup", "literal-argument check")
    limits = (
        "no interprocedural data flow: an argument's value is not traced into callers",
        "no sanitiser model: a call to a sanitiser is treated as non-constant",
        "only Python, C#, JavaScript and TypeScript files get source-level analysis; other languages are UNKNOWN",
        "other sinks in the same file are not assessed by a single finding",
        "exposure and authentication are not assessed",
    )

    def assess(self, finding: dict, context: dict):
        """Route the finding, assess its call site, add any runtime observation, then cap the verdict by the
        routing decision. The weakness class decides the cap; the call-site check decides the rest."""
        chosen = weakness.route(finding)
        result = self._assess_location(finding, context)
        result = deployment_context.apply_runtime(result, finding, context)
        return weakness.apply_route(result, chosen, finding["exploitability_context"]["exposure"])

    def _assess_location(self, finding: dict, context: dict):
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

        analyzer = analyzer_for(location["path"])
        if analyzer is not None:
            try:
                source_bytes = target.read_bytes()
            except OSError as exc:
                return unknown_assessment(f"the file could not be read ({type(exc).__name__})", engine=self.name)
            return analyzer.assess(source_bytes, location, engine=self.name,
                                   exposure=finding["exploitability_context"]["exposure"])

        if target.suffix != ".py":
            # A pattern match with no analysis behind it says nothing about exploitability, so it is UNKNOWN.
            return make_assessment(
                UNKNOWN,
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
        function = None
        names: dict = {}
        app = context.get("application")
        if app is not None:
            function = app.function_def(location["path"], location["start_line"])
            if function is not None:
                names = preconditions.assignments_in(function)

        # A parameterised query: the SQL text is the first argument, and the values are bound after it.
        bound = []
        text_args = arguments
        if isinstance(call.func, ast.Attribute) and call.func.attr in SQL_EXECUTORS and len(call.args) >= 2:
            text_args = [call.args[0]]
            bound = list(call.args[1:]) + [kw.value for kw in call.keywords]
        text_class = _combine({_classify(a, names) for a in text_args})

        if text_class == CONSTANT and bound:
            return make_assessment(
                MITIGATED,
                reason=("the SQL text is a constant and the values are bound parameters, so a request value cannot "
                        "change the statement's structure at this call"),
                engine=self.name,
                conditions={"mitigation_effective": Condition(CONFIRMED, [f"{span} bound parameters"])},
                evidence=[{"condition": "mitigation_effective", "kind": "ast",
                           "detail": f"{span}: {call.func.attr} with a constant statement and {len(bound)} bound value(s)"}],
                confidence="MEDIUM",
                confidence_reason="the statement and the call are read from the AST; the driver's binding is not",
                coverage=coverage_common,
                limitations=base_limits + ["the mitigation covers this call only, not other queries"],
                exposure=finding["exploitability_context"]["exposure"],
            )
        if text_class == NUMERIC:
            return make_assessment(
                MITIGATED,
                reason=("the only non-constant parts of the call are numeric conversions, which cannot carry an "
                        "injection; this mitigates the call as written"),
                engine=self.name,
                conditions={"mitigation_effective": Condition(CONFIRMED, [f"{span} numeric conversion"])},
                evidence=[{"condition": "mitigation_effective", "kind": "ast",
                           "detail": f"arguments at {span} are numeric conversions (int, float, bool) or constants"}],
                confidence="MEDIUM",
                confidence_reason="the conversion is read from the AST; the value's range is not checked",
                coverage=coverage_common,
                limitations=base_limits + ["the mitigation covers this call only, not other queries"],
                exposure=finding["exploitability_context"]["exposure"],
            )
        if text_class == CONSTANT and not bound:
            return make_assessment(
                NOT_EXPLOITABLE,
                reason="every argument of the flagged call is a literal constant, so no attacker data reaches this call site",
                engine=self.name,
                conditions={"attacker_influence": Condition(NOT_CONFIRMED, [f"{span} literal arguments"])},
                evidence=[{"condition": "attacker_influence", "kind": "ast",
                           "detail": f"arguments at {span} are literals"}],
                confidence="MEDIUM",
                confidence_reason="single call site, arguments checked by the Python AST",
                coverage=coverage_common,
                limitations=base_limits,
                exposure=finding["exploitability_context"]["exposure"],
            )

        exposure = finding["exploitability_context"]["exposure"]
        reach = app.reachability(location["path"], location["start_line"]) if app is not None else None
        reach_status = reach.status if reach is not None else UNKNOWN_STATUS
        reach_detail = (f"{reach.reason}; path: {app.describe_path(reach.path)}"
                        if reach is not None and reach.path else (reach.reason if reach is not None else
                                                                 "no shared application analysis was run"))
        attacker = REQUEST if text_class == REQUEST else UNKNOWN_ARG
        evidence = [{"condition": "reachable", "kind": "application-analysis", "detail": reach_detail}]
        if attacker == REQUEST:
            evidence.append({"condition": "attacker_influence", "kind": "ast",
                             "detail": f"a request value reaches the statement at {span}"})
        else:
            evidence.append({"condition": "attacker_influence", "kind": "ast",
                             "detail": f"non-literal argument at {span}: {non_literal[0]}; its source is not traced "
                                       "to a request value"})
        coverage = {"analysed": [f"{span} call site", f"reachability: {reach_status}"],
                    "not_analysed": list(self.limits)}

        if reach_status == CONFIRMED and attacker == REQUEST and exposure == "internet":
            return _with_path(make_assessment(
                CONFIRMED_EXPLOITABLE,
                reason=("a route reaches the call, a request value reaches it without a sanitiser on the traced path, "
                        "and the application is declared internet-facing; this is a static path, not a demonstrated exploit"),
                engine=self.name,
                conditions={
                    "reachable": Condition(CONFIRMED, [reach.route or "route"]),
                    "attacker_influence": Condition(CONFIRMED, [f"request value at {span}"]),
                    "preconditions": Condition(CONFIRMED, ["no sanitiser on the traced path"]),
                },
                evidence=evidence + [{"condition": "preconditions", "kind": "ast",
                                      "detail": "the request value is not passed through a sanitiser"}],
                confidence="MEDIUM",
                confidence_reason="static path; the injection is not demonstrated at runtime",
                coverage=coverage,
                limitations=base_limits + ["static evidence only: no request was sent and no runtime path was observed"],
                exposure=exposure,
            ), app, reach)
        if reach_status == CONFIRMED and attacker == REQUEST:
            return _with_path(make_assessment(
                POTENTIALLY_EXPLOITABLE,
                reason=("a route reaches the call and a request value reaches it, but the application is not declared "
                        "internet-facing, so attacker reach is not established"),
                engine=self.name,
                conditions={
                    "reachable": Condition(CONFIRMED, [reach.route or "route"]),
                    "attacker_influence": Condition(CONFIRMED, [f"request value at {span}"]),
                    "preconditions": Condition(CONFIRMED, ["no sanitiser on the traced path"]),
                },
                evidence=evidence,
                confidence="MEDIUM",
                confidence_reason="static path; exposure is not established",
                coverage=coverage,
                limitations=base_limits,
                exposure=exposure,
            ), app, reach)
        if reach_status == NOT_CONFIRMED:
            return make_assessment(
                NOT_REACHABLE,
                reason=("no route reaches the function containing the call, in a complete search of the application; "
                        "code called from outside the application is not covered"),
                engine=self.name,
                conditions={"reachable": Condition(NOT_CONFIRMED, ["complete search, no route"])},
                evidence=evidence,
                confidence="MEDIUM",
                confidence_reason="the search is complete for the application's own call graph",
                coverage=coverage,
                limitations=base_limits + ["the application's call graph is static; dynamic dispatch is not followed"],
                exposure=exposure,
            )
        if reach is not None and not reach.surface_known and attacker != REQUEST:
            # No credible attack path is known: no route exists, and the argument is not a request value.
            return make_assessment(
                UNKNOWN,
                reason=("the flagged call has a non-literal argument, but the project has no route entry point and the "
                        "argument is not a request value, so no attack path is known to assess"),
                engine=self.name,
                conditions={"reachable": Condition(UNKNOWN_STATUS, ["no route entry point"])},
                evidence=evidence,
                confidence="LOW",
                confidence_reason="the attack surface is not known",
                coverage=coverage,
                limitations=base_limits + ["callers outside this project are not analysed"],
                exposure=exposure,
            )
        potential = make_assessment(
            POTENTIALLY_EXPLOITABLE,
            reason=("the flagged call has an argument that is not a literal, and its exposure to attacker input or "
                    "reachability is not established"),
            engine=self.name,
            conditions={
                "reachable": Condition(CONFIRMED, [reach.route]) if reach_status == CONFIRMED else Condition(UNKNOWN_STATUS),
                "attacker_influence": Condition(UNKNOWN_STATUS),
            },
            evidence=evidence,
            confidence="LOW",
            confidence_reason="data flow into the argument is not traced to a request value",
            coverage=coverage,
            limitations=base_limits,
            exposure=exposure,
        )
        if reach_status == CONFIRMED:
            return _with_path(potential, app, reach)
        return potential
