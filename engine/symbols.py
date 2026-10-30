"""Vulnerable symbols and curated rules.

Curated rules (rules/*.json) are authoritative when present. Without them, symbols
are derived from the upstream fix commit: the methods the fix removed or changed.
That derivation over-approximates (refactors also appear), so its symbols are
tagged "fix-commit" and reported with that source.
"""

import json
import re
from pathlib import Path

_STATEMENT_START = re.compile(r"\s*(return|throw|new|else|case|yield|if|for|while|switch|catch|do)\b")
_METHOD_DECL = re.compile(
    r"^\s*(?:@\w+(?:\([^)]*\))?\s+)*"
    r"(?:(?:public|protected|private|static|final|synchronized|abstract|native|default)\s+)*"
    r"(?:<[^>]+>\s+)?[\w.$]+(?:<[^;{}()]*>)?(?:\[\])?\s+(?P<name>\w+)\s*\("
)
_SOURCE_MARKER = "src/main/java/"


def load_rules(rules_dir: Path) -> list[dict]:
    if not rules_dir.is_dir():
        return []
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(rules_dir.glob("*.json"))]


def fqcn_from_path(path: str) -> str:
    relative = path.split(_SOURCE_MARKER, 1)[1] if _SOURCE_MARKER in path else path
    return relative.removesuffix(".java").replace("/", ".")


def symbols_from_diff(diff: str) -> list[str]:
    """Return `package.Class.method` for each Java method the diff removes or changes."""
    symbols: set[str] = set()
    path = None
    for line in diff.splitlines():
        if line.startswith("+++ "):
            path = line[4:].removeprefix("b/").strip()
            continue
        if path is None or not path.endswith(".java"):
            continue
        if not line.startswith("-") or line.startswith("---"):
            continue
        body = line[1:]
        if _STATEMENT_START.match(body):
            continue
        match = _METHOD_DECL.match(body)
        if not match:
            continue
        fqcn = fqcn_from_path(path)
        if match["name"] == fqcn.rsplit(".", 1)[-1]:
            continue  # a constructor, not a method
        symbols.add(f"{fqcn}.{match['name']}")
    return sorted(symbols)
