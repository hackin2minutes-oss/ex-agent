"""Bounded call graph for Python, built from the standard library's ast module.

Nodes are functions and methods (`module:qualname`). Edges are calls. Resolution is by name:
- "ast-same-module": the callee is a function defined in the same module.
- "ast-import": the callee was imported with `from X import name` and defined in X.
- unresolved: anything else (attribute calls, dynamic dispatch, library code).

Limits are enforced while the graph is built, not after:
- MAX_NODES caps function nodes. Functions beyond the cap are skipped and counted.
- MAX_EDGES caps call edges. Edges beyond the cap are skipped and counted.
- A file that cannot be read or parsed is recorded and marks the graph incomplete.

Every edge between two retained nodes is kept, even when other nodes were skipped.
The graph reports `complete` and the reasons it is not complete. A caller must treat an
incomplete graph as "paths unknown", never as "no path".

Traversal from entry points is breadth-first, bounded by depth, path count and an
expansion budget, and never revisits a node on the same path.
"""

import ast
from collections import deque
from pathlib import Path

MAX_NODES = 50_000
MAX_EDGES = 250_000
MAX_DEPTH = 8
MAX_PATHS = 20
MAX_EXPANSIONS = 200_000
ROUTE_ATTRS = {"route", "get", "post", "put", "delete", "patch"}


class Graph:
    def __init__(self, max_edges: int = MAX_EDGES):
        self.max_edges = max_edges
        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []
        self.unresolved: list[dict] = []
        self.unresolved_from: set[str] = set()
        self.parse_errors: list[str] = []
        self.skipped_nodes = 0
        self.skipped_edges = 0
        self.incomplete_reasons: list[str] = []
        self.spans: dict[str, list[tuple[int, int, str]]] = {}
        self._adjacency: dict[str, list[str]] = {}

    @property
    def complete(self) -> bool:
        return not self.incomplete_reasons

    def add_edge(self, source: str, target: str, line: int, resolution: str) -> bool:
        if len(self.edges) >= self.max_edges:
            self.skipped_edges += 1
            if "edge_limit" not in self.incomplete_reasons:
                self.incomplete_reasons.append("edge_limit")
            return False
        self.edges.append({"from": source, "to": target, "line": line, "resolution": resolution})
        self._adjacency.setdefault(source, []).append(target)
        return True

    def successors(self, node: str) -> list[str]:
        return self._adjacency.get(node, [])

    def summary(self) -> dict:
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "unresolved_calls": len(self.unresolved),
            "skipped_nodes": self.skipped_nodes,
            "skipped_edges": self.skipped_edges,
            "parse_errors": len(self.parse_errors),
            "complete": self.complete,
            "incomplete_reasons": list(self.incomplete_reasons),
        }


def _import_candidates(package: str, module: str, level: int) -> list[str]:
    """Module names a `from ... import` could refer to in this project. An absolute import is tried as written,
    and also as a sibling inside the importer's package, which is how a flat package layout resolves it. A relative
    import (level > 0) is resolved from the importer's package."""
    if level:
        parts = package.split(".") if package else []
        base = parts[:len(parts) - (level - 1)] if level - 1 <= len(parts) else []
        prefix = ".".join(base)
        return [".".join(p for p in (prefix, module) if p)]
    candidates = [module]
    if package:
        candidates.append(f"{package}.{module}")
    return candidates


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


def _callee_name(call: ast.Call) -> str | None:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
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


def build(root: Path, max_nodes: int = MAX_NODES, max_edges: int = MAX_EDGES) -> Graph:
    graph = Graph(max_edges=max_edges)
    defined: dict[str, dict[str, list[str]]] = {}
    imports: dict[str, dict[str, str]] = {}
    calls: list[tuple[str, str, int]] = []

    for path in sorted(root.rglob("*.py")):
        module = _module_name(root, path)
        relative = path.relative_to(root).as_posix()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except (SyntaxError, ValueError, OSError) as exc:
            graph.parse_errors.append(f"{relative}: {type(exc).__name__}")
            if "parse_error" not in graph.incomplete_reasons:
                graph.incomplete_reasons.append("parse_error")
            continue
        defined.setdefault(module, {})
        imports.setdefault(module, {})
        package = module.rsplit(".", 1)[0] if "." in module else ""
        for stmt in ast.walk(tree):
            if isinstance(stmt, ast.ImportFrom) and (stmt.module or stmt.level):
                for candidate in _import_candidates(package, stmt.module or "", stmt.level):
                    for alias in stmt.names:
                        imports[module].setdefault(alias.asname or alias.name, []).append(candidate)

        def visit(body, prefix=""):
            for node in body:
                if isinstance(node, ast.ClassDef):
                    visit(node.body, f"{prefix}{node.name}.")
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    qualname = f"{prefix}{node.name}"
                    node_id = f"{module}:{qualname}"
                    if len(graph.nodes) >= max_nodes:
                        graph.skipped_nodes += 1
                        if "node_limit" not in graph.incomplete_reasons:
                            graph.incomplete_reasons.append("node_limit")
                        visit(node.body, f"{qualname}.<locals>.")
                        continue
                    route = _route_of(node)
                    graph.nodes[node_id] = {"id": node_id, "file": relative, "line": node.lineno,
                                            "end_line": node.end_lineno or node.lineno,
                                            "entry": route is not None, "route": route}
                    defined[module].setdefault(node.name, []).append(node_id)
                    graph.spans.setdefault(relative, []).append(
                        (node.lineno, node.end_lineno or node.lineno, node_id))
                    for inner in _calls_in_body(node.body):
                        name = _callee_name(inner)
                        if name:
                            calls.append((node_id, name, inner.lineno))
                    visit(node.body, f"{qualname}.<locals>.")

        visit(tree.body)

    # Edges are added only between retained nodes, in a deterministic order.
    for caller, name, line in calls:
        if caller not in graph.nodes:
            continue
        module = caller.split(":", 1)[0]
        if name in defined.get(module, {}):
            targets, resolution = defined[module][name], "ast-same-module"
        elif name in imports.get(module, {}):
            targets, resolution = [], "ast-import"
            for source in imports[module][name]:
                targets = defined.get(source, {}).get(name, [])
                if targets:
                    break
        else:
            targets = []
        if not targets:
            graph.unresolved.append({"from": caller, "name": name, "line": line})
            graph.unresolved_from.add(caller)
            continue
        for target in targets:
            if target in graph.nodes:
                graph.add_edge(caller, target, line, resolution)
    return graph


def enclosing_function(graph: Graph, file: str, line: int) -> str | None:
    best = None
    for start, end, node_id in graph.spans.get(file, []):
        if start <= line <= end and (best is None or (end - start) < (best[1] - best[0])):
            best = (start, end, node_id)
    return best[2] if best else None


def paths_to(graph: Graph, targets: set[str], max_depth: int = MAX_DEPTH) -> tuple[list[list[str]], bool]:
    """Return (paths, search_complete). search_complete is False when the expansion budget ran out."""
    found: list[list[str]] = []
    expansions = 0
    search_complete = True
    # A function with calls the graph cannot resolve may hide a path (dynamic dispatch, library
    # code). Expanding such a function makes "no path" unknown rather than absent.
    entries = sorted(n for n, meta in graph.nodes.items() if meta["entry"])
    for entry in entries:
        queue = deque([[entry]])
        while queue and len(found) < MAX_PATHS:
            path = queue.popleft()
            node = path[-1]
            if node in targets:
                found.append(path)
                continue
            if len(path) > max_depth:
                search_complete = False
                continue
            if node in graph.unresolved_from:
                search_complete = False
            for successor in graph.successors(node):
                if successor in path:
                    continue
                expansions += 1
                if expansions > MAX_EXPANSIONS:
                    return found, False
                queue.append(path + [successor])
    return found, search_complete and len(found) < MAX_PATHS
