"""JavaScript and TypeScript call-site analysis on a real syntax tree (tree-sitter).

For the call expression a scanner flagged, the analyzer:
1. Finds the call expression that starts at the flagged line (and column, when the scanner gives one).
2. Finds the enclosing function. When that function is the handler of an Express route (`app.get('/x', handler)`, or
   `router`, `server`, `api`, `routes`), the function is an entry point: the framework calls it for a request.
3. Takes the handler's first parameter as the request object. Its `query`, `body`, `params`, `headers` and `cookies`
   members are attacker input.
4. Propagates attacker input through variable declarations and assignments in that function, in textual order.
5. Classifies the receiver and each argument as constant (literals only), attacker-influenced, or unknown.

Grammar is chosen from the file: .ts uses the TypeScript grammar, .tsx the TSX grammar, and everything else the
JavaScript grammar.

Limits: no call between functions is followed; no value is traced into a caller, a module, or a property; loops and
branches are not merged; no sanitiser is modelled, so preconditions are UNKNOWN; middleware that changes the request
is not followed; dynamic dispatch and eval are not resolved.
"""

import re

import tree_sitter_javascript
import tree_sitter_typescript
from tree_sitter import Language, Parser

from engine.languages.base import CallSite, LanguageAnalyzer

LITERALS = frozenset({"string", "number", "true", "false", "null", "undefined", "regex"})
FUNCTIONS = frozenset({"function_declaration", "function_expression", "arrow_function", "method_definition",
                       "generator_function_declaration"})
ROUTE_METHODS = frozenset({"get", "post", "put", "delete", "patch", "all", "head", "options"})
ROUTER_NAMES = frozenset({"app", "router", "server", "api", "routes"})
REQUEST_MEMBERS = ("query", "body", "params", "headers", "cookies")

LIMITS = (
    "no call between functions is followed: a value passed in from a caller is not traced",
    "modules, properties and shared state are not traced",
    "loops and branches are not merged: assignments are followed in textual order",
    "no sanitiser or validation is modelled, so preconditions are UNKNOWN",
    "middleware that changes the request is not followed",
    "dynamic dispatch, eval and dynamic property access are not resolved",
)

_PARSERS = {
    "javascript": Parser(Language(tree_sitter_javascript.language())),
    "typescript": Parser(Language(tree_sitter_typescript.language_typescript())),
    "tsx": Parser(Language(tree_sitter_typescript.language_tsx())),
}


def _grammar(path: str) -> str:
    if path.endswith(".tsx"):
        return "tsx"
    if path.endswith(".ts"):
        return "typescript"
    return "javascript"


def _walk(node):
    """Every node under `node`, in document order."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def _text(node) -> str:
    return node.text.decode("utf-8", errors="replace")


def _find_call(root, line: int, column: int | None):
    calls = [node for node in _walk(root) if node.type == "call_expression" and node.start_point[0] == line - 1]
    if not calls:
        return None, ""
    if column is not None:
        exact = [node for node in calls if node.start_point[1] == column - 1]
        if exact:
            return exact[0], "column"
    return calls[0], "line"


def _enclosing_function(node):
    current = node.parent
    while current is not None and current.type not in FUNCTIONS:
        current = current.parent
    return current


def _function_name(function) -> str | None:
    if function.type in ("function_declaration", "generator_function_declaration", "method_definition"):
        name = function.child_by_field_name("name")
        return _text(name) if name is not None else None
    parent = function.parent
    if parent is not None and parent.type == "variable_declarator":
        name = parent.child_by_field_name("name")
        return _text(name) if name is not None and name.type == "identifier" else None
    return None


def _first_parameter(function) -> str | None:
    parameters = function.child_by_field_name("parameters")
    if parameters is None and function.type == "arrow_function":
        parameter = function.child_by_field_name("parameter")
        return _text(parameter) if parameter is not None and parameter.type == "identifier" else None
    if parameters is None:
        return None
    for child in parameters.named_children:
        if child.type == "identifier":
            return _text(child)
        if child.type in ("required_parameter", "optional_parameter"):
            pattern = child.child_by_field_name("pattern")
            if pattern is not None and pattern.type == "identifier":
                return _text(pattern)
        return None
    return None


def _route_registration(function):
    """(object, method, path) when the function is the handler of an Express-style route, else None."""
    arguments = function.parent
    if arguments is None or arguments.type != "arguments":
        return None
    call = arguments.parent
    if call is None or call.type != "call_expression":
        return None
    callee = call.child_by_field_name("function")
    if callee is None or callee.type != "member_expression":
        return None
    obj = callee.child_by_field_name("object")
    prop = callee.child_by_field_name("property")
    if obj is None or prop is None or obj.type != "identifier":
        return None
    if _text(obj) not in ROUTER_NAMES or _text(prop) not in ROUTE_METHODS:
        return None
    path_node = next((child for child in arguments.named_children if child.type == "string"), None)
    path = _text(path_node).strip("'\"`") if path_node is not None else ""
    return _text(obj), _text(prop), path


def _attacker_reason(node, tainted: dict[str, str], request: str | None) -> str | None:
    """Why the expression carries attacker input, or None."""
    pattern = re.compile(rf"^{re.escape(request)}\.(?:{'|'.join(REQUEST_MEMBERS)})\b") if request else None
    for current in _walk(node):
        if pattern is not None and current.type == "member_expression" and pattern.match(_text(current)):
            return _text(current)
        if current.type == "identifier" and _text(current) in tainted:
            return tainted[_text(current)]
    return None


def _is_constant(node) -> bool:
    if node.type in LITERALS:
        return True
    if node.type == "template_string":
        return not any(child.type == "template_substitution" for child in node.named_children)
    if node.type == "binary_expression":
        return all(_is_constant(child) for child in node.named_children if child.type != "comment")
    if node.type == "parenthesized_expression":
        return all(_is_constant(child) for child in node.named_children)
    return False


def _propagate(function, tainted: dict[str, str], request: str | None) -> None:
    """Follow declarations and assignments inside the function, in textual order."""
    for node in _walk(function):
        if node.type == "variable_declarator":
            name = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if name is None or value is None or name.type != "identifier":
                continue
            target = _text(name)
        elif node.type == "assignment_expression":
            left, value = node.child_by_field_name("left"), node.child_by_field_name("right")
            if left is None or value is None or left.type != "identifier":
                continue
            target = _text(left)
        else:
            continue
        reason = _attacker_reason(value, tainted, request)
        if reason:
            tainted[target] = f"local {target} from {reason}"
        else:
            tainted.pop(target, None)


def _source(role: str, index: int, node, tainted: dict[str, str], request: str | None) -> dict:
    if node is None:
        return {"role": role, "index": index, "text": "", "kind": "unknown", "via": "no expression"}
    text = _text(node)[:120]
    reason = _attacker_reason(node, tainted, request)
    if reason:
        return {"role": role, "index": index, "text": text, "kind": "attacker", "via": reason}
    if _is_constant(node):
        return {"role": role, "index": index, "text": text, "kind": "constant", "via": "literal"}
    return {"role": role, "index": index, "text": text, "kind": "unknown",
            "via": "not a literal, and not traced to a request value in this function"}


def analyse(source: bytes, path: str, line: int, column: int | None = None) -> CallSite:
    root = _PARSERS[_grammar(path)].parse(source).root_node
    call, match = _find_call(root, line, column)
    if call is None:
        return CallSite(False, f"no call expression starts at line {line}")

    function = _enclosing_function(call)
    tainted: dict[str, str] = {}
    request = None
    entry = ""
    attributes: list[str] = []
    name = None
    if function is not None:
        name = _function_name(function)
        registration = _route_registration(function)
        if registration is not None:
            obj, method, route = registration
            entry = f'{obj}.{method}("{route}")'
            attributes = [f"{obj}.{method}"]
            request = _first_parameter(function)
        _propagate(function, tainted, request)

    sources = []
    callee = call.child_by_field_name("function")
    if callee is not None and callee.type == "member_expression":
        sources.append(_source("receiver", 0, callee.child_by_field_name("object"), tainted, request))
    arguments = call.child_by_field_name("arguments")
    index = 0
    for argument in (arguments.named_children if arguments is not None else []):
        if argument.type == "comment":
            continue
        sources.append(_source("argument", index, argument, tainted, request))
        index += 1

    return CallSite(True, f"call expression at line {line} ({match} match)", match=match, method=name,
                    attributes=attributes, entry_point=bool(entry), entry=entry, sources=sources)


class JavaScriptAnalyzer(LanguageAnalyzer):
    name = "javascript"
    extensions = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")
    implemented = (
        "AST call-site location for JavaScript, JSX, TypeScript and TSX",
        "enclosing function, including named functions, methods and arrow functions bound to a name",
        "Express route handlers (app, router, server, api, routes with get, post, put, delete, patch, all, head, "
        "options) as entry points",
        "request object from the handler's first parameter, including a TypeScript annotation",
        "request members query, body, params, headers and cookies as attacker input",
        "intra-function propagation through declarations, assignments, template strings and concatenation",
        "literal-only argument check",
    )
    unsupported = LIMITS
    call_graph = "intra-function only: no call edge is followed"
    data_flow = "intra-function, flow-insensitive over textual order; no module, property or interprocedural flow"
    test_corpus = ("tests/fixtures/js-analysis-app",)
    measured_accuracy = "not measured: no labelled JavaScript corpus exists in this repository"

    def analyse_call(self, source: bytes, location: dict) -> CallSite:
        return analyse(source, location["path"], location["start_line"], location.get("start_col"))
