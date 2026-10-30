"""Bounded call graph for Python, built from the standard library's ast module.

Nodes are functions and methods (`module:qualname`). Edges are calls. Resolution is by
name:
- "ast-same-module": the callee name is a function defined in the same module.
- "ast-import": the callee name was imported with `from X import name` and is defined in X.
- unresolved: anything else (attribute calls on objects, dynamic dispatch, library code).
Unresolved calls are recorded as uncertainty, not dropped and not assumed absent.

Traversal from entry points to target functions is breadth-first, bounded by depth,
node count and path count, and never revisits a node on the same path (cycles).
Python only. Other languages have no call graph in this release.
"""

import ast
from collections import deque
from pathlib import Path

MAX_DEPTH = 8
MAX_NODES = 5000
MAX_PATHS = 20
ROUTE_ATTRS = {"route", "get", "post", "put", "delete", "patch"}


class Graph:
    def __init__(self):
        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []
        self.unresolved: list[dict] = []
        self.parse_errors: list[str] = []
        self.truncated = False
        self._adjacency: dict[str, list[str]] = {}

    def add_edge(self, source: str, target: str, line: int, resolution: str) -> None:
        self.edges.append({"from": source, "to": target, "line": line, "resolution": resolution})
        self._adjacency.setdefault(source, []).append(target)

    def successors(self, node: str) -> list[str]:
        return self._adjacency.get(node, [])


def _module_name(root: Path, path: Path) -> str:
    return ".".join(path.relative_to(root).with_suffix("").parts)


def _route_of(node) -> str | None:
    for decorator in node.decorator_list:
        if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute) \
                and decorator.func.attr in ROUTE_ATTRS:
            if decorator.args and isinstance(decorator.args[0], ast.Constant) \
                    and isinstance(decorator.args[0].value, str):
                return decorator.args[0].value
            return "/"
    return None


def _calls_in_body(body) -> list[ast.Call]:
    """Calls made by this function body. Nested functions and classes have their own nodes."""
    calls: list[ast.Call] = []
    stack = list(body)
    while stack:
        current = stack.pop()
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(current, ast.Call):
            calls.append(current)
        stack.extend(ast.iter_child_nodes(current))
    return calls


def _callee_name(call: ast.Call) -> str | None:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return None


def build(root: Path) -> Graph:
    graph = Graph()
    defined: dict[str, dict[str, list[str]]] = {}   # module -> simple name -> node ids
    imports: dict[str, dict[str, str]] = {}         # module -> local name -> source module
    calls: list[tuple[str, str, int]] = []           # (caller id, callee name, line)
    spans: dict[str, list[tuple[int, int, str]]] = {}  # file -> (start, end, node id)

    for path in sorted(root.rglob("*.py")):
        module = _module_name(root, path)
        relative = path.relative_to(root).as_posix()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError as exc:
            graph.parse_errors.append(f"{relative}: {exc.msg} (line {exc.lineno})")
            continue
        defined.setdefault(module, {})
        imports.setdefault(module, {})
        for stmt in ast.walk(tree):
            if isinstance(stmt, ast.ImportFrom) and stmt.module:
                for alias in stmt.names:
                    imports[module][alias.asname or alias.name] = stmt.module

        def visit(body, prefix=""):
            for node in body:
                if isinstance(node, ast.ClassDef):
                    visit(node.body, f"{prefix}{node.name}.")
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    qualname = f"{prefix}{node.name}"
                    node_id = f"{module}:{qualname}"
                    route = _route_of(node)
                    graph.nodes[node_id] = {"id": node_id, "file": relative, "line": node.lineno,
                                            "end_line": node.end_lineno or node.lineno,
                                            "entry": route is not None, "route": route}
                    defined[module].setdefault(node.name, []).append(node_id)
                    spans.setdefault(relative, []).append((node.lineno, node.end_lineno or node.lineno, node_id))
                    for inner in _calls_in_body(node.body):
                        name = _callee_name(inner)
                        if name:
                            calls.append((node_id, name, inner.lineno))
                    visit(node.body, f"{qualname}.<locals>.")

        visit(tree.body)

    for caller, name, line in calls:
        module = caller.split(":", 1)[0]
        if len(graph.nodes) > MAX_NODES:
            graph.truncated = True
            break
        if name in defined.get(module, {}):
            for target in defined[module][name]:
                graph.add_edge(caller, target, line, "ast-same-module")
        elif name in imports.get(module, {}):
            source = imports[module][name]
            targets = defined.get(source, {}).get(name, [])
            if targets:
                for target in targets:
                    graph.add_edge(caller, target, line, "ast-import")
            else:
                graph.unresolved.append({"from": caller, "name": name, "line": line})
        else:
            graph.unresolved.append({"from": caller, "name": name, "line": line})

    graph.spans = spans
    return graph


def enclosing_function(graph: Graph, file: str, line: int) -> str | None:
    best = None
    for start, end, node_id in getattr(graph, "spans", {}).get(file, []):
        if start <= line <= end and (best is None or (end - start) < (best[1] - best[0])):
            best = (start, end, node_id)
    return best[2] if best else None


def paths_to(graph: Graph, targets: set[str], max_depth: int = MAX_DEPTH) -> list[list[str]]:
    """Paths from each entry point to any target function, bounded and cycle-free."""
    found: list[list[str]] = []
    entries = [n for n, meta in graph.nodes.items() if meta["entry"]]
    for entry in entries:
        queue = deque([[entry]])
        while queue and len(found) < MAX_PATHS:
            path = queue.popleft()
            node = path[-1]
            if node in targets:
                found.append(path)
                continue
            if len(path) > max_depth:
                continue
            for successor in graph.successors(node):
                if successor not in path:
                    queue.append(path + [successor])
    return found
