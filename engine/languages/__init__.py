"""Language analyzers, and the capability report for every language the project names.

Priority: Python (the existing call-site engine in engine/sast.py), C#, JavaScript and TypeScript, Java, Go. A
language with no analyzer is NOT_IMPLEMENTED here, and its findings are UNKNOWN.
"""

from engine.languages.base import LanguageAnalyzer
from engine.languages.csharp import CSharpAnalyzer
from engine.languages.javascript import JavaScriptAnalyzer

ANALYZERS: tuple[LanguageAnalyzer, ...] = (CSharpAnalyzer(), JavaScriptAnalyzer())

# Languages the project names, in priority order, that have no analyzer yet. Their query templates exist under
# queries/, but no call-site analysis is wired to them, so they are reported NOT_IMPLEMENTED rather than estimated.
PLANNED = (("java", (".java",)), ("go", (".go",)))


def analyzer_for(path: str) -> LanguageAnalyzer | None:
    suffix = "." + path.rsplit(".", 1)[-1].lower() if "." in path else ""
    for analyzer in ANALYZERS:
        if suffix in analyzer.extensions:
            return analyzer
    return None


def capability_report() -> list[dict]:
    """One record per language, in priority order. Python's record names the existing engine's limits."""
    from engine.sast import SastEngine

    python = {
        "language": "python",
        "status": "IMPLEMENTED_NOT_EXTERNALLY_VERIFIED",
        "implemented": ["AST call-site location", "literal-argument check", "request-value trace within a function",
                        "reachability from Flask/FastAPI/Werkzeug routes"],
        "unsupported": list(SastEngine.limits),
        "call_graph": "per-application entry-point search (engine/context.py); no whole-program call graph",
        "data_flow": "within one function, through assignments",
        "test_corpus": ["tests/fixtures/python-app", "tests/fixtures/python-app-safe", "tests/fixtures/werkzeug-app"],
        "measured_accuracy": "not measured: no labelled Python corpus exists in this repository",
    }
    records = [python] + [analyzer.capabilities() for analyzer in ANALYZERS]
    for name, extensions in PLANNED:
        records.append({"language": name, "status": "NOT_IMPLEMENTED", "extensions": list(extensions),
                        "implemented": [], "unsupported": ["all call-site and data-flow analysis"],
                        "call_graph": "not implemented", "data_flow": "not implemented", "test_corpus": [],
                        "measured_accuracy": "not measured"})
    return records
