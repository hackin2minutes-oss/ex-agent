"""Measure the shared analysis and the per-run cost on generated applications of increasing size.

Each application has N modules. Each module has F functions in a call chain, one route in every tenth module, and a
SQL sink fed by a request value in every fifth module. The sinks are the findings. Times are wall-clock on this machine.

Run: python3 tests/eval/perf.py [sizes...]    (default: 50 200 500 modules)
"""

import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

from engine import universal_run
from engine.application import Application


def generate(root: Path, modules: int, functions: int) -> list[dict]:
    """Write the application under root and return a Semgrep-shaped report of its sinks (one per fifth module)."""
    results = []
    for m in range(modules):
        lines = ["from flask import Flask, request", "app = Flask(__name__)", ""]
        for f in range(functions):
            callee = f"helper_{f + 1}()" if f + 1 < functions else "0"
            lines += [f"def helper_{f}():", f"    return {callee}", ""]
        if m % 10 == 0:
            lines += ["@app.route('/m%d')" % m, "def handler():", "    return helper_0()", ""]
        if m % 5 == 0:
            lines += [f"def sink_{m}(cur):",
                      "    name = request.args.get('name')",
                      "    cur.execute(\"SELECT * FROM t WHERE n = '\" + name + \"'\")", ""]
            line_no = len(lines) - 2 + 1
            results.append({"check_id": "corpus-sql-execute", "path": f"m{m}.py",
                            "start": {"line": line_no, "col": 5, "offset": 0},
                            "end": {"line": line_no, "col": 5 + len("cur.execute(\"SELECT * FROM t WHERE n = '\" + name + \"'\")"), "offset": 0},
                            "extra": {"message": "sql", "severity": "ERROR", "lines": "", "metadata": {}}})
        (root / f"m{m}.py").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return results


def measure(modules: int, functions: int) -> dict:
    root = Path(tempfile.mkdtemp())
    try:
        results = generate(root, modules, functions)
        report = root / "report.json"
        report.write_text(json.dumps({"version": "1.183.0", "results": results, "errors": [], "paths": {"scanned": []}}),
                          encoding="utf-8")
        started = time.perf_counter()
        app = Application(root)
        shared = time.perf_counter() - started
        out = root / "out"
        started = time.perf_counter()
        summary = universal_run.run([report], root, out, exposure="internet", offline=True)
        total = time.perf_counter() - started
        return {"modules": modules, "functions_per_module": functions,
                "functions": len(app.graph.nodes), "edges": len(app.graph.edges),
                "findings": summary["findings"], "verdicts": summary["verdicts"],
                "shared_analysis_seconds": round(shared, 3), "full_run_seconds": round(total, 3),
                "search_complete": not app._route_reasons, "route_entries": len(app.entries())}
    finally:
        shutil.rmtree(root, ignore_errors=True)


def main(argv: list[str]) -> int:
    sizes = [int(a) for a in argv] or [50, 200, 500]
    rows = [measure(size, 10) for size in sizes]
    print(json.dumps(rows, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
