"""CVE-specific precondition checks, from curated rules.

A rule lists checks of two kinds:

- "requires": the precondition holds when attacker-controlled data reaches the
  vulnerable sink. A check with a "sink" names the call and the argument position
  (an integer, or "any"). The argument must be request-derived. Otherwise the
  result is "unverified". A constant argument never satisfies the check.
- "mitigated_by": a mitigation is in place when the pattern is found. A match
  gives "not_satisfied". No match gives "unverified".

Checks without a "sink" are regex text matches. They are used only for
configuration facts such as a debugger flag, where no argument carries data.

Sink checks are scoped to the analysed files:

- Python uses the ast module. Each call is classified by tracing assignments in
  its enclosing function (or module). Request data comes from a name rooted at
  "request". Sanitisers and anything unresolved are "unknown".
- Go and JavaScript use lexical matching. The taint is file-scoped: a name is
  tainted when it is assigned from a request accessor, directly or through other
  tainted names. Calls that span lines are "unknown".

Results are never "satisfied" from absence or from a constant. Interprocedural
flow, aliasing and runtime configuration are not analysed.

The aggregate is "satisfied" only if every check is satisfied. It is
"not_satisfied" if any check is not satisfied. Otherwise it is "unverified".
"""

import ast
import re
from fnmatch import fnmatch
from pathlib import Path

_KINDS = {"requires", "mitigated_by"}
MAX_ASSIGNMENT_DEPTH = 5

REQUEST = "request"
CONSTANT = "constant"
UNKNOWN_ARG = "unknown"

# Attacker-controlled request accessors for the lexical languages.
_LEXICAL_REQUEST = {
    ".go": re.compile(
        r"\b(?:r|req|request)\.(?:FormValue|PostFormValue|Form|PostForm|Body|URL\.Query|Header|Cookie)\b"
        r"|\bc\.(?:Query|PostForm|Param|GetHeader|Cookie|Bind\w*|ShouldBind\w*)\("),
    ".js": re.compile(r"\b(?:req|request)\.(?:body|query|params|headers|cookies)\b"),
    ".ts": re.compile(r"\b(?:req|request)\.(?:body|query|params|headers|cookies)\b"),
}

# Calls that remove or transform attacker data in a way this check does not model.
# Their result is "unknown", never "constant" or "request".
_SANITISERS = {
    "int", "float", "bool", "secure_filename", "basename", "os.path.basename",
    "quote", "shlex.quote", "escape", "html.escape", "markupsafe.escape", "bleach.clean",
}

_STRING = re.compile(r'"[^"\\]*"|\'[^\'\\]*\'|`[^`]*`')
_LITERAL = re.compile(r'"[^"\\]*"|\'[^\'\\]*\'|`[^`]*`|\d+(?:\.\d+)?')
_IDENT = re.compile(r"[A-Za-z_]\w*")
_ASSIGN = re.compile(r"(?<![\w.])(\w+)\s*(?::=|=)(?![=>])\s*(.+)$")


def _glob_matches(relative: str, glob: str) -> bool:
    # A leading "**/" also matches files at the root.
    if fnmatch(relative, glob):
        return True
    return glob.startswith("**/") and fnmatch(relative, glob[3:])


def _matching_files(source_root: Path, glob: str):
    for path in sorted(source_root.rglob("*")):
        if path.is_file() and _glob_matches(path.relative_to(source_root).as_posix(), glob):
            yield path


def _combine(classes: set[str]) -> str:
    if REQUEST in classes:
        return REQUEST
    if classes == {CONSTANT}:
        return CONSTANT
    return UNKNOWN_ARG


def _pick(items: list, argument, classify) -> str:
    """Classify the argument at the given position, or every argument for "any"."""
    if argument == "any":
        return _combine({classify(item) for item in items}) if items else UNKNOWN_ARG
    if argument >= len(items):
        return UNKNOWN_ARG
    return classify(items[argument])


def _dotted(node) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def _root_name(node) -> str | None:
    while True:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            node = node.value
        elif isinstance(node, ast.Call):
            node = node.func
        elif isinstance(node, ast.Subscript):
            node = node.value
        else:
            return None


def _python_arg_class(node, names: dict, depth: int = 0) -> str:
    if depth > MAX_ASSIGNMENT_DEPTH:
        return UNKNOWN_ARG
    if _root_name(node) == "request":
        return REQUEST
    if isinstance(node, ast.Constant):
        return CONSTANT
    if isinstance(node, ast.Call) and _dotted(node.func) in _SANITISERS:
        return UNKNOWN_ARG
    if isinstance(node, ast.Name):
        values = names.get(node.id)
        if not values:
            # A parameter or a global. Its value is not known here.
            return UNKNOWN_ARG
        return _combine({_python_arg_class(v, names, depth + 1) for v in values})
    children = [c for c in ast.iter_child_nodes(node) if isinstance(c, ast.expr)]
    if not children:
        return UNKNOWN_ARG
    return _combine({_python_arg_class(c, names, depth) for c in children})


def _python_sink_sites(text: str, sink: str, argument) -> list[dict]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        # ValueError: the source contains a NUL byte.
        return [{"line": None, "argument_class": UNKNOWN_ARG, "reason": "file does not parse"}]

    # Innermost enclosing scope for every node. ast.walk is breadth-first, so a nested
    # function comes after its parent and overwrites the parent's entries.
    scopes = [tree] + [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    owner: dict[int, ast.AST] = {}
    for scope in scopes:
        for node in ast.walk(scope):
            owner[id(node)] = scope

    names_by_scope: dict[int, dict] = {id(s): {} for s in scopes}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and node.value is not None and isinstance(node.target, ast.Name):
            targets = [node.target.id]
        else:
            continue
        value = node.value
        names = names_by_scope[id(owner[id(node)])]
        for name in targets:
            names.setdefault(name, []).append(value)

    sites = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or _dotted(node.func) != sink:
            continue
        names = names_by_scope[id(owner[id(node)])]
        items = node.args + [kw.value for kw in node.keywords] if argument == "any" else node.args
        try:
            arg_class = _pick(items, argument, lambda item: _python_arg_class(item, names))
        except RecursionError:
            # Pathologically nested expressions cannot be classified. That is "unknown", not a crash.
            arg_class = UNKNOWN_ARG
        sites.append({"line": node.lineno, "argument_class": arg_class})
    return sites


def _split_call_args(line: str, open_index: int) -> list[str] | None:
    """Return the top-level argument texts of the call opened at open_index, or None if unclosed."""
    depth = 0
    quote = None
    args: list[str] = []
    current: list[str] = []
    for ch in line[open_index + 1:]:
        if quote:
            current.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                args.append("".join(current))
                return [a for a in args if a.strip()]
            depth -= 1
        elif ch == "," and depth == 0:
            args.append("".join(current))
            current = []
            continue
        current.append(ch)
    return None


def _lexical_taint(text: str, request_re) -> set[str]:
    assignments = []
    for line in text.splitlines():
        match = _ASSIGN.search(line)
        if match:
            assignments.append((match.group(1), match.group(2)))
    tainted: set[str] = set()
    changed = True
    while changed:
        changed = False
        for name, rhs in assignments:
            if name in tainted:
                continue
            code = _STRING.sub('""', rhs)
            if request_re.search(rhs) or any(tok in tainted for tok in _IDENT.findall(code)):
                tainted.add(name)
                changed = True
    return tainted


def _text_arg_class(arg: str, tainted: set[str], request_re) -> str:
    stripped = arg.strip()
    if _LITERAL.fullmatch(stripped):
        return CONSTANT
    if request_re.search(stripped):
        return REQUEST
    code = _STRING.sub('""', stripped)
    if any(tok in tainted for tok in _IDENT.findall(code)):
        return REQUEST
    return UNKNOWN_ARG


def _lexical_sink_sites(text: str, sink: str, argument, request_re) -> list[dict]:
    tainted = _lexical_taint(text, request_re)
    call = re.compile(r"\b" + re.escape(sink) + r"\s*\(")
    sites = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for match in call.finditer(line):
            args = _split_call_args(line, match.end() - 1)
            if args is None:
                sites.append({"line": lineno, "argument_class": UNKNOWN_ARG,
                              "reason": "call continues onto another line"})
                continue
            arg_class = _pick(args, argument, lambda a: _text_arg_class(a, tainted, request_re))
            sites.append({"line": lineno, "argument_class": arg_class})
    return sites


def _sink_sites(path: Path, sink: str, argument) -> list[dict]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix == ".py":
        return _python_sink_sites(text, sink, argument)
    request_re = _LEXICAL_REQUEST.get(path.suffix)
    if request_re is None:
        return [{"line": None, "argument_class": UNKNOWN_ARG, "reason": "no taint model for this language"}]
    return _lexical_sink_sites(text, sink, argument, request_re)


def _sink_check(check: dict, source_root: Path) -> dict:
    if check["kind"] != "requires":
        raise ValueError("a sink is only valid on a requires check")
    argument = check.get("argument", 0)
    if argument != "any" and not (isinstance(argument, int) and argument >= 0):
        raise ValueError(f"invalid argument position: {argument!r}")

    sites = []
    for path in _matching_files(source_root, check.get("glob", "**/*")):
        relative = path.relative_to(source_root).as_posix()
        for site in _sink_sites(path, check["sink"], argument):
            sites.append({"file": relative, **site})

    taint_sites = [s for s in sites if s["argument_class"] == REQUEST]
    if taint_sites:
        result, reason, locations = "satisfied", "attacker-controlled data reaches the sink", taint_sites
    elif not sites:
        result, reason, locations = "unverified", "sink not found in the analysed files", []
    elif all(s["argument_class"] == CONSTANT for s in sites):
        result, reason, locations = "unverified", "the sink argument is a constant", sites
    else:
        result, reason, locations = "unverified", "the origin of the sink argument is not established", sites
    return {"id": check["id"], "kind": check["kind"], "description": check.get("description", ""),
            "result": result, "reason": reason, "locations": locations}


def _check_one(check: dict, source_root: Path) -> dict:
    kind = check["kind"]
    if kind not in _KINDS:
        raise ValueError(f"unknown precondition kind: {kind}")
    if "sink" in check:
        return _sink_check(check, source_root)
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
