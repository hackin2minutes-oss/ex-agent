"""C# call-site analysis on a real syntax tree (tree-sitter-c-sharp).

For the call expression a scanner flagged, the analyzer:
1. Finds the invocation expression that starts at the flagged line (and column, when the scanner gives one).
2. Finds the enclosing method and its attributes. An ASP.NET route attribute (`[HttpGet]`, `[Route]`, ...) makes the
   method an entry point: the framework calls it for a request, so it is reachable.
3. Treats request-bound parameters (`[FromQuery]`, `[FromBody]`, ...) and `Request.Query`, `Request.Form`, ... member
   accesses as attacker input.
4. Propagates attacker input through local declarations and assignments in that method, in textual order.
5. Classifies the receiver and each argument as constant (literals only), attacker-influenced, or unknown.

Limits that every result carries: no call between methods is followed; no value is traced into a caller or a field;
loops and branches are not merged; no sanitiser is modelled, so preconditions stay UNKNOWN and a verdict made here
cannot be CONFIRMED_EXPLOITABLE; dependency injection, minimal-API lambdas and middleware are not resolved.
"""

import re
from dataclasses import dataclass, field

import tree_sitter_c_sharp
from tree_sitter import Language, Parser

from engine.languages.base import LanguageAnalyzer
from engine.universal import (
    CONFIRMED, NOT_CONFIRMED, NOT_EXPLOITABLE, POTENTIALLY_EXPLOITABLE, UNKNOWN, UNKNOWN_STATUS, Condition,
    make_assessment,
)

LITERALS = frozenset({"string_literal", "verbatim_string_literal", "raw_string_literal", "integer_literal",
                      "real_literal", "boolean_literal", "null_literal", "character_literal"})
BINDING_ATTRIBUTES = frozenset({"FromQuery", "FromBody", "FromRoute", "FromForm", "FromHeader"})
ENTRY_ATTRIBUTES = frozenset({"HttpGet", "HttpPost", "HttpPut", "HttpDelete", "HttpPatch", "HttpHead",
                              "HttpOptions", "Route", "AcceptVerbs"})
REQUEST_MEMBER = re.compile(r"^(?:HttpContext\.)?Request\.(?:Query|Form|Headers|Cookies|Path|QueryString|Body|"
                            r"RouteValues)\b")
METHODS = ("method_declaration", "constructor_declaration")

LIMITS = (
    "no call between methods is followed: a value passed in from a caller is not traced",
    "fields, properties and base-class state are not traced",
    "loops and branches are not merged: assignments are followed in textual order",
    "no sanitiser or validation is modelled, so preconditions are UNKNOWN",
    "dependency injection, minimal-API lambdas and middleware are not resolved",
    "reflection and dynamic dispatch are not resolved",
)

_PARSER = Parser(Language(tree_sitter_c_sharp.language()))


@dataclass
class CallSite:
    found: bool
    reason: str
    match: str = ""
    method: str | None = None
    attributes: list[str] = field(default_factory=list)
    entry_point: bool = False
    sources: list[dict] = field(default_factory=list)


def _walk(node):
    """Every node under `node`, in document order."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def _text(node) -> str:
    return node.text.decode("utf-8", errors="replace")


def _base_name(name: str) -> str:
    """The attribute's own name: `Microsoft.AspNetCore.Mvc.HttpGetAttribute` is `HttpGet`."""
    last = name.split(".")[-1]
    return last[: -len("Attribute")] if last.endswith("Attribute") and len(last) > len("Attribute") else last


def _attribute_names(node) -> list[str]:
    names = []
    for child in node.children:
        if child.type != "attribute_list":
            continue
        for attribute in child.named_children:
            name = attribute.child_by_field_name("name") if attribute.type == "attribute" else None
            if name is not None:
                names.append(_base_name(_text(name)))
    return names


def _find_call(root, line: int, column: int | None):
    calls = [node for node in _walk(root) if node.type == "invocation_expression" and node.start_point[0] == line - 1]
    if not calls:
        return None, ""
    if column is not None:
        exact = [node for node in calls if node.start_point[1] == column - 1]
        if exact:
            return exact[0], "column"
    return calls[0], "line"


def _enclosing_method(node):
    current = node.parent
    while current is not None and current.type not in METHODS:
        current = current.parent
    return current


def _is_constant(node) -> bool:
    if node.type in LITERALS:
        return True
    if node.type == "interpolated_string_expression":
        return not any(child.type == "interpolation" for child in _walk(node))
    if node.type in ("binary_expression", "parenthesized_expression"):
        return all(_is_constant(child) for child in node.named_children)
    return False


def _attacker_reason(node, tainted: dict[str, str]) -> str | None:
    """Why the expression carries attacker input, or None. Member names are not variables, so `x.name` is not `name`."""
    for current in _walk(node):
        if current.type == "member_access_expression" and REQUEST_MEMBER.match(_text(current)):
            return _text(current)
        if current.type == "identifier" and _text(current) in tainted:
            parent = current.parent
            if parent is not None and parent.type == "member_access_expression":
                name_node = parent.child_by_field_name("name")
                if name_node is not None and name_node.start_byte == current.start_byte:
                    continue
            return tainted[_text(current)]
    return None


def _propagate(method, tainted: dict[str, str]) -> None:
    """Follow local declarations and assignments inside the method, in textual order."""
    for node in _walk(method):
        if node.type == "variable_declarator":
            name = node.child_by_field_name("name")
            values = node.named_children[1:]
            if name is None or not values:
                continue
            target, value = _text(name), values[-1]
        elif node.type == "assignment_expression":
            left, value = node.child_by_field_name("left"), node.child_by_field_name("right")
            if left is None or value is None or left.type != "identifier":
                continue
            target = _text(left)
        else:
            continue
        reason = _attacker_reason(value, tainted)
        if reason:
            tainted[target] = f"local {target} from {reason}"
        else:
            tainted.pop(target, None)


def _source(role: str, index: int, node, tainted: dict[str, str]) -> dict:
    if node is None:
        return {"role": role, "index": index, "text": "", "kind": "unknown", "via": "no expression"}
    text = _text(node)[:120]
    reason = _attacker_reason(node, tainted)
    if reason:
        return {"role": role, "index": index, "text": text, "kind": "attacker", "via": reason}
    if _is_constant(node):
        return {"role": role, "index": index, "text": text, "kind": "constant", "via": "literal"}
    return {"role": role, "index": index, "text": text, "kind": "unknown",
            "via": "not a literal, and not traced to a request value in this method"}


def analyse(source: bytes, line: int, column: int | None = None) -> CallSite:
    root = _PARSER.parse(source).root_node
    call, match = _find_call(root, line, column)
    if call is None:
        return CallSite(False, f"no call expression starts at line {line}")

    method = _enclosing_method(call)
    tainted: dict[str, str] = {}
    attributes: list[str] = []
    if method is not None:
        attributes = _attribute_names(method)
        parameters = method.child_by_field_name("parameters")
        for parameter in (parameters.named_children if parameters is not None else []):
            if parameter.type != "parameter":
                continue
            name = parameter.child_by_field_name("name")
            if name is None:
                continue
            if BINDING_ATTRIBUTES.intersection(_attribute_names(parameter)):
                tainted[_text(name)] = f"parameter {_text(name)} bound from the request"
        _propagate(method, tainted)

    sources = []
    function = call.child_by_field_name("function")
    if function is not None and function.type == "member_access_expression":
        sources.append(_source("receiver", 0, function.child_by_field_name("expression"), tainted))
    arguments = call.child_by_field_name("arguments")
    for index, argument in enumerate(arguments.named_children if arguments is not None else []):
        value = argument.named_children[-1] if argument.named_children else None
        sources.append(_source("argument", index, value, tainted))

    entry = sorted(ENTRY_ATTRIBUTES.intersection(attributes))
    return CallSite(True, f"call expression at line {line} ({match} match)", match=match,
                    method=_text(method.child_by_field_name("name")) if method is not None else None,
                    attributes=attributes, entry_point=bool(entry), sources=sources)


class CSharpAnalyzer(LanguageAnalyzer):
    name = "csharp"
    extensions = (".cs",)
    implemented = (
        "AST call-site location (invocation expressions at the flagged line and column)",
        "enclosing method and its attributes",
        "ASP.NET route attributes make a method an entry point",
        "request-bound parameters ([FromQuery], [FromBody], [FromRoute], [FromForm], [FromHeader])",
        "Request.Query / Form / Headers / Cookies / Path / QueryString / Body / RouteValues as attacker input",
        "intra-method propagation through locals, assignments, concatenation and interpolation",
        "literal-only argument check",
    )
    unsupported = LIMITS
    call_graph = "intra-method only: no call edge is followed"
    data_flow = "intra-method, flow-insensitive over textual order; no interprocedural or field flow"
    test_corpus = ("tests/fixtures/csharp-app",)
    measured_accuracy = "not measured: no labelled C# corpus exists in this repository"

    def analyse_call(self, source: bytes, location: dict) -> CallSite:
        return analyse(source, location["start_line"], location.get("start_col"))


def assess_call(source: bytes, location: dict, *, engine: str, exposure: str):
    """The universal assessment for a flagged C# call. Attacker input reaching the call makes it at most
    POTENTIALLY_EXPLOITABLE here, because preconditions are not modelled. A call whose arguments are all literals
    is NOT_EXPLOITABLE, because no attacker-controlled data reaches it."""
    site = analyse(source, location["start_line"], location.get("start_col"))
    where = f"{location['path']}:{location['start_line']}"
    if not site.found:
        return make_assessment(UNKNOWN, reason=f"{where}: {site.reason}", engine=engine,
                               limitations=[site.reason, *LIMITS], exposure=exposure)

    arguments = [s for s in site.sources if s["role"] == "argument"]
    attacker = next((s for s in site.sources if s["kind"] == "attacker"), None)
    constant = attacker is None and bool(arguments) and all(s["kind"] == "constant" for s in arguments)
    entry = sorted(ENTRY_ATTRIBUTES.intersection(site.attributes))

    evidence = [
        {"condition": None, "kind": "location", "detail": f"{where} call expression located ({site.match} match)"},
        {"condition": None, "kind": "enclosing_method", "detail": site.method or "none",
         "attributes": site.attributes},
    ]
    conditions = {}
    if site.entry_point:
        conditions["reachable"] = Condition(CONFIRMED, [f"{site.method} carries [{entry[0]}]"])
        evidence.append({"condition": "reachable", "kind": "entry_point",
                         "detail": f"{site.method} carries [{entry[0]}], which ASP.NET routes requests to"})
    if attacker is not None:
        conditions["attacker_influence"] = Condition(CONFIRMED, [attacker["via"]])
        evidence.append({"condition": "attacker_influence", "kind": "taint",
                         "detail": f"{attacker['role']} {attacker['index']} `{attacker['text']}` carries "
                                   f"{attacker['via']}"})
    elif constant:
        conditions["attacker_influence"] = Condition(NOT_CONFIRMED, ["every argument is a literal"])
        evidence.append({"condition": "attacker_influence", "kind": "constant",
                         "detail": "every argument is a literal constant, and the receiver is not attacker input"})

    if constant:
        return make_assessment(NOT_EXPLOITABLE, reason="every argument is a literal, so no attacker-controlled data "
                               "reaches the call", engine=engine, conditions=conditions, evidence=evidence,
                               confidence="HIGH", confidence_reason="a literal-only argument list is decided by the "
                               "syntax tree", coverage={"analysed": [where], "not_analysed": list(LIMITS)},
                               limitations=list(LIMITS), exposure=exposure)
    if attacker is not None:
        return make_assessment(POTENTIALLY_EXPLOITABLE, reason=f"attacker input reaches the call: {attacker['via']}",
                               engine=engine, conditions=conditions, evidence=evidence, confidence="MEDIUM",
                               confidence_reason="traced within one method; preconditions and callers are not",
                               coverage={"analysed": [where], "not_analysed": list(LIMITS)},
                               limitations=list(LIMITS), exposure=exposure)
    return make_assessment(UNKNOWN, reason="no argument is a literal, and none is traced to a request value in this "
                           "method", engine=engine, conditions={"attacker_influence": Condition(UNKNOWN_STATUS)},
                           evidence=evidence, confidence="LOW",
                           confidence_reason="the argument source is outside the analysed method",
                           coverage={"analysed": [where], "not_analysed": list(LIMITS)},
                           limitations=list(LIMITS), exposure=exposure)
