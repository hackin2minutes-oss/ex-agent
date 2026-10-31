"""Investigation tools. Each tool reads the project and returns evidence records. No tool sends traffic or runs project code.

Each tool's limits are part of its description, so a planner can see what the tool cannot establish.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from engine.investigation.evidence import Evidence, EvidenceStore

WINDOW = 3          # lines either side of a line that read_source returns
MAX_HITS = 50       # most hits search_source returns
MIN_NEEDLE = 3      # shortest text search_source accepts
SOURCE_SUFFIXES = (".py", ".js", ".jsx", ".ts", ".tsx", ".cs", ".java", ".go", ".rb", ".php", ".yaml", ".yml", ".json",
                   ".tf", ".toml", ".cfg", ".ini", ".sh", ".txt", ".html")
SKIP_DIRECTORIES = {"node_modules", "venv", ".venv", "vendor", "dist", "build", "__pycache__", ".git"}


class ToolError(ValueError):
    pass


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    limits: str
    run: Callable[..., list[Evidence]]


class Toolbox:
    def __init__(self, project_dir: Path, store: EvidenceStore):
        self.root = project_dir.resolve()
        self.store = store
        self._tools = {tool.name: tool for tool in (
            Tool("read_source",
                 "Read the lines around one line of a project file. Args: path (relative), line (int).",
                 "Only the lines around the given line. It does not follow calls or imports.",
                 self._read_source),
            Tool("search_source",
                 "Find every line in the project that contains a literal text. Args: text (at least 3 characters).",
                 f"Literal text only, no regular expressions. At most {MAX_HITS} hits. It cannot tell a call from a "
                 "comment, or a value from a parameter name.",
                 self._search_source),
        )}

    def describe(self) -> list[dict]:
        return [{"name": t.name, "description": t.description, "limits": t.limits} for t in self._tools.values()]

    def run(self, name: str, args: dict) -> list[Evidence]:
        tool = self._tools.get(name)
        if tool is None:
            raise ToolError(f"no tool named {name!r}")
        if not isinstance(args, dict):
            raise ToolError("tool arguments must be an object")
        try:
            return tool.run(**args)
        except TypeError as error:
            raise ToolError(f"bad arguments for {name}: {error}")

    def _inside(self, relative: str) -> Path:
        target = (self.root / relative).resolve()
        try:
            target.relative_to(self.root)
        except ValueError:
            raise ToolError(f"{relative} is outside the project")
        if not target.is_file():
            raise ToolError(f"{relative} is not a file in the project")
        return target

    def _lines(self, target: Path) -> list[str]:
        return target.read_text(encoding="utf-8", errors="replace").splitlines()

    def _read_source(self, path: str, line: int) -> list[Evidence]:
        if not isinstance(path, str) or not isinstance(line, int):
            raise ToolError("read_source needs path (text) and line (integer)")
        target = self._inside(path)
        lines = self._lines(target)
        if not 1 <= line <= len(lines):
            raise ToolError(f"line {line} is not in {path}")
        rel = target.relative_to(self.root).as_posix()
        found = []
        for number in range(max(1, line - WINDOW), min(len(lines), line + WINDOW) + 1):
            text = lines[number - 1]
            found.append(self.store.add(kind="source", tool="read_source", summary=f"{rel}:{number}", path=rel,
                                        line=number, excerpt=text))
        return found

    def _search_source(self, text: str) -> list[Evidence]:
        if not isinstance(text, str) or len(text) < MIN_NEEDLE:
            raise ToolError(f"search_source needs text of at least {MIN_NEEDLE} characters")
        found = []
        for path in sorted(self.root.rglob("*")):
            if len(found) >= MAX_HITS:
                break
            if not path.is_file() or not path.name.endswith(SOURCE_SUFFIXES):
                continue
            parts = path.relative_to(self.root).parts[:-1]
            if any(part in SKIP_DIRECTORIES or part.startswith(".") for part in parts):
                continue
            if not path.resolve().is_relative_to(self.root):
                continue
            rel = path.relative_to(self.root).as_posix()
            for number, line in enumerate(self._lines(path), 1):
                if text in line:
                    found.append(self.store.add(kind="source", tool="search_source",
                                                summary=f"'{text}' at {rel}:{number}", path=rel, line=number,
                                                excerpt=line))
                    if len(found) >= MAX_HITS:
                        break
        return found
