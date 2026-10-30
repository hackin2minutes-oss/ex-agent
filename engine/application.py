"""Shared analysis of one application: built once per run, reused by every finding.

It holds the bounded Python call graph (engine/callgraph.py), the entry points, and the reachability searches over
that graph. Per-finding questions are answered from these shared results.

Entry points come in two kinds:
- Route entry points: handlers registered with a web route decorator. A path from one of them is an attack path.
- Possible entry points: functions that may run without a route. Reasons: a non-route decorator (a command, task or
  event hook), a reference to the function as a value (a callback, a dispatch table), or a call from top-level
  code. A reach from one of these is a credible path that is not an HTTP attack surface. It gives UNKNOWN.

Completeness: a search is complete when it is not cut by depth, path or expansion limits, and no reached function
makes a dynamic call (getattr, eval, exec, __import__, globals and similar). Calls into library code cannot reach
project code except through a value, and values are covered by the possible entry points, so unresolved library
calls do not make a search incomplete.

Answers are never "not reachable" unless the relevant search is complete.
"""

import ast
from dataclasses import dataclass
from pathlib import Path

from engine import callgraph

MAX_FILE_BYTES = 2_000_000
CONFIRMED = "CONFIRMED"
NOT_CONFIRMED = "NOT_CONFIRMED"
UNKNOWN = "UNKNOWN"
DYNAMIC_CALLS = {"getattr", "eval", "exec", "__import__", "globals", "locals", "vars", "setattr"}
ROUTE_ATTRS = callgraph.ROUTE_ATTRS


@dataclass
class Reach:
    status: str
    reason: str
    path: list[str]
    route: str | None = None
    surface_known: bool = True


def _last_name(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


class Application:
    def __init__(self, root: Path, max_depth: int = callgraph.MAX_DEPTH):
        self.root = Path(root).resolve()
        self.max_depth = max_depth
        self.graph = callgraph.build(self.root)
        self._trees: dict[str, ast.Module | None] = {}
        self._name_of: dict[str, str] = {n: meta["id"].split(":")[-1] for n, meta in self.graph.nodes.items()}
        self._by_location = {(meta["file"], meta["line"]): n for n, meta in self.graph.nodes.items()}
        self.module_level_called_names: set[str] = set()
        self.possible_entries: set[str] = set()
        self.dynamic_nodes: set[str] = set()
        self.uncertain_nodes: set[str] = set()
        self._scan_project()
        # A call the graph could not resolve, whose name is a function this project defines, may be a call to that
        # function. Such a caller makes any search through it incomplete. Library calls with other names cannot.
        defined_names = set(self._name_of.values())
        self.uncertain_nodes = {u["from"] for u in self.graph.unresolved if u["name"] in defined_names}
        self._route_parent, self._route_reasons = self._search(self._route_sources())
        self._possible_parent, self._possible_reasons = self._search(sorted(self.possible_entries))
        if any(n.endswith(":<module>") for n in self.dynamic_nodes):
            # A dynamic call at top level can start any function, so the possible-entry search cannot be complete.
            self._possible_reasons = sorted(set(self._possible_reasons) | {"dynamic_call_at_module_level"})

    # ----- parsing and project scan, shared ----------------------------------------------------------------------

    def tree(self, relative: str) -> ast.Module | None:
        if relative not in self._trees:
            tree = None
            target = (self.root / relative).resolve()
            if target.is_file() and target.is_relative_to(self.root) and target.stat().st_size <= MAX_FILE_BYTES:
                try:
                    tree = ast.parse(target.read_text(encoding="utf-8"), filename=relative)
                except (SyntaxError, ValueError, UnicodeDecodeError):
                    tree = None
            self._trees[relative] = tree
        return self._trees[relative]

    def _scan_project(self) -> None:
        defined_names = set(self._name_of.values())
        referenced_values: set[str] = set()
        for relative in self.graph.spans:
            tree = self.tree(relative)
            if tree is None:
                continue
            call_funcs = {id(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}
            for node in ast.walk(tree):
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and id(node) not in call_funcs:
                    referenced_values.add(node.id)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    node_id = self._by_location.get((relative, node.lineno))
                    if node_id is None:
                        continue
                    if any(_last_name(d.func if isinstance(d, ast.Call) else d) not in ROUTE_ATTRS
                           for d in node.decorator_list):
                        self.possible_entries.add(node_id)
                    if any(isinstance(c, ast.Call) and _last_name(c.func) in DYNAMIC_CALLS for c in ast.walk(node)):
                        self.dynamic_nodes.add(node_id)
            for statement in tree.body:
                if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                                          ast.Import, ast.ImportFrom)):
                    continue
                for node in ast.walk(statement):
                    if isinstance(node, ast.Call):
                        name = _last_name(node.func)
                        if name in defined_names:
                            self.module_level_called_names.add(name)
                        if name in DYNAMIC_CALLS:
                            # Top-level dynamic call: the functions it may reach are unknown, so the whole
                            # possible-entry search is treated as incomplete.
                            self.dynamic_nodes.add(f"{relative}:<module>")
        for node_id, name in self._name_of.items():
            if name in referenced_values or name in self.module_level_called_names:
                self.possible_entries.add(node_id)

    # ----- searches ------------------------------------------------------------------------------------------------

    def _route_sources(self) -> list[str]:
        return sorted(n for n, meta in self.graph.nodes.items() if meta["entry"])

    def entries(self) -> list[dict]:
        """Attack surface: every route handler in the graph, sorted for determinism."""
        found = [{"node": node, "route": meta["route"], "file": meta["file"], "line": meta["line"]}
                 for node, meta in self.graph.nodes.items() if meta["entry"]]
        return sorted(found, key=lambda e: (e["file"], e["line"], e["node"]))

    def _search(self, sources: list[str]) -> tuple[dict[str, str | None], list[str]]:
        """Breadth-first search from the sources. Returns parent links (the shortest path to each node) and the
        reasons the search is not complete."""
        parent: dict[str, str | None] = {}
        frontier: list[tuple[str, int]] = []
        for source in sources:
            parent[source] = None
            frontier.append((source, 0))
        reasons: set[str] = set()
        expansions = 0
        index = 0
        while index < len(frontier):
            node, depth = frontier[index]
            index += 1
            if node in self.dynamic_nodes:
                reasons.add("dynamic_call_on_path")
            if node in self.uncertain_nodes:
                reasons.add("unresolved_project_call_on_path")
            if depth >= self.max_depth:
                if self.graph.successors(node):
                    reasons.add("depth_limit")
                continue
            for successor in self.graph.successors(node):
                expansions += 1
                if expansions > callgraph.MAX_EXPANSIONS:
                    reasons.add("expansion_budget")
                    return parent, sorted(reasons)
                if successor in parent:
                    continue
                parent[successor] = node
                frontier.append((successor, depth + 1))
        reasons.update(self.graph.incomplete_reasons)
        return parent, sorted(reasons)

    def search_summary(self) -> dict:
        return {
            "entry_points": len(self.entries()),
            "possible_entry_points": len(self.possible_entries),
            "route_nodes_reached": len(self._route_parent),
            "route_search_complete": not self._route_reasons,
            "route_search_incomplete_reasons": list(self._route_reasons),
            "possible_search_complete": not self._possible_reasons,
            "graph": self.graph.summary(),
            "module_level_called_functions": len(self.module_level_called_names),
            "dynamic_call_sites": len(self.dynamic_nodes),
        }

    def _path_to(self, parent: dict, node: str) -> list[str]:
        path = [node]
        while parent.get(path[-1]) is not None:
            path.append(parent[path[-1]])
        return list(reversed(path))

    def describe_path(self, path: list[str]) -> str:
        return " -> ".join(self._name_of.get(n, n) for n in path)

    # ----- per-finding questions -----------------------------------------------------------------------------------

    def reachability(self, relative: str, line: int) -> Reach:
        if relative in {entry.split(":")[0] for entry in self.graph.parse_errors}:
            return Reach(UNKNOWN, f"{relative} did not parse, so its call sites are unknown", [])
        node = callgraph.enclosing_function(self.graph, relative, line)
        if node is None:
            return Reach(UNKNOWN, "the location is not inside a function, so no route is known to reach it", [])
        if not self.entries():
            return Reach(UNKNOWN, "no route entry point was found, so the attack surface is not known", [],
                         None, surface_known=False)
        if node in self._route_parent and not self._route_reasons:
            path = self._path_to(self._route_parent, node)
            route = self.graph.nodes[path[0]]["route"]
            return Reach(CONFIRMED, f"reached from route {route}", path, route)
        if node in self._route_parent:
            # A route path was found, so the path is credible. The search is incomplete elsewhere, which the caller
            # is told, but a found path does not depend on the rest of the search.
            path = self._path_to(self._route_parent, node)
            route = self.graph.nodes[path[0]]["route"]
            return Reach(CONFIRMED, f"reached from route {route}; the search was incomplete: "
                                    + ", ".join(self._route_reasons), path, route)
        if node in self._possible_parent:
            path = self._path_to(self._possible_parent, node)
            return Reach(UNKNOWN, "reached only from code that may run without a route (decorator, callback or "
                                  "top-level call); not an HTTP attack path", path)
        if self._route_reasons:
            return Reach(UNKNOWN, "the route search was incomplete: " + ", ".join(self._route_reasons), [])
        if self._possible_reasons:
            return Reach(UNKNOWN, "the search of possible entry points was incomplete: "
                                  + ", ".join(self._possible_reasons), [])
        return Reach(NOT_CONFIRMED, "no route and no possible entry point reaches the function, in complete searches "
                                    "of the application", [], None)

    def function_def(self, relative: str, line: int) -> ast.AST | None:
        """The innermost function definition that contains the line."""
        tree = self.tree(relative)
        if tree is None:
            return None
        best = None
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                end = getattr(node, "end_lineno", node.lineno)
                if node.lineno <= line <= end and (best is None or (end - node.lineno) < (
                        best.end_lineno - best.lineno)):
                    best = node
        return best
