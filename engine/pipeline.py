"""Analysis pipeline.

dependencies → advisories (OSV) → enrichment (EPSS, KEV) → vulnerable symbols
(curated or fix-commit) → call sites and taint (CodeQL, or text fallback) →
preconditions → verdict → reports.
"""

import subprocess
from pathlib import Path

from engine import callsites, codeql, context, ingest, intel as intel_module, preconditions
from engine import report, symbols, verdict

SHIPPED_SCOPE_EXCLUDED = {"test", "dev"}
ECOSYSTEMS_QUERIED = {"Maven", "npm", "PyPI"}
TOOL_VERSION = "0.1.0"


def _failure_text(exc: Exception) -> str:
    """Describe a failed subprocess on one line, including the tail of its stderr."""
    if isinstance(exc, subprocess.CalledProcessError):
        stderr = (exc.stderr or "").strip().splitlines()[-8:]
        tail = " | ".join(line.strip() for line in stderr if line.strip())
        return f"exit {exc.returncode}: {tail}" if tail else f"exit {exc.returncode}"
    return str(exc)


def _cve_or_id(vuln_id: str, cve: str | None) -> str:
    return cve or vuln_id


def collect_candidates(deps: list[dict], rules: list[dict], intel) -> dict:
    """One candidate per (advisory, dependency version). OSV and curated rules both feed in."""
    candidates: dict[tuple, dict] = {}

    for dep in deps:
        if dep["ecosystem"] not in ECOSYSTEMS_QUERIED:
            continue
        for advisory in intel.osv_advisories(dep["ecosystem"], dep["name"], dep["version"]) or []:
            key = (_cve_or_id(advisory["id"], advisory["cve"]), dep["ecosystem"], dep["name"],
                   dep["version"])
            candidates.setdefault(key, {
                "key": key,
                "cve": advisory["cve"],
                "vuln_id": advisory["id"],
                "aliases": advisory["aliases"],
                "summary": advisory["summary"],
                "fix_commits": advisory["fix_commits"],
                "dependency": dep,
                "curated": None,
                "sources": ["osv"],
            })

    for rule in rules:
        for dep in deps:
            if dep["ecosystem"] != rule.get("ecosystem", "Maven") or dep["name"] != rule["library"]:
                continue
            if not ingest.is_affected(dep["version"], rule["affected"]["introduced"],
                                      rule["affected"]["fixed"]):
                continue
            key = (rule["cve"], dep["ecosystem"], dep["name"], dep["version"])
            cand = candidates.setdefault(key, {
                "key": key,
                "cve": rule["cve"],
                "vuln_id": rule["cve"],
                "aliases": [rule["cve"]],
                "summary": rule.get("summary", ""),
                "fix_commits": [],
                "dependency": dep,
                "curated": None,
                "sources": [],
            })
            cand["curated"] = rule
            cand["sources"].append("curated")

    return candidates


def _sha(commit_url: str) -> str:
    return commit_url.rstrip("/").rsplit("/", 1)[-1]


def candidate_symbols(cand: dict, intel, fix_diffs_dir: Path | None) -> tuple[list[str], str]:
    if cand["curated"]:
        return [s["name"] for s in cand["curated"]["symbols"]], "curated"
    derived: set[str] = set()
    for url in cand["fix_commits"]:
        diff = None
        if fix_diffs_dir is not None and (fix_diffs_dir / f"{_sha(url)}.diff").is_file():
            diff = (fix_diffs_dir / f"{_sha(url)}.diff").read_text(encoding="utf-8", errors="replace")
        else:
            diff = intel.commit_diff(url)
        if diff:
            derived.update(symbols.symbols_from_diff(diff))
    if derived:
        return sorted(derived), "fix-commit (derived, over-approximate)"
    return [], "none"


def _taint_locations(flows: list[dict]) -> list[dict]:
    return [{"file": f["file"], "line": f["line"], "source": None, "sink": f"{f['file']}:{f['line']}",
             "message": f["message"]} for f in flows]


def analyse_candidate(cand: dict, project_dir: Path, ctx: dict) -> dict:
    dep = cand["dependency"]
    symbol_names, symbol_source = candidate_symbols(cand, ctx["intel"], ctx["fix_diffs_dir"])
    notes: list[str] = []

    hits: list[dict] = []
    taint_flows: list[dict] = []
    mode = "text_scan"
    if ctx["codeql_bin"] and ctx["db_dir"] and symbol_names:
        try:
            for symbol in symbol_names:
                result = codeql.analyse_symbol(ctx["codeql_bin"], ctx["db_dir"], ctx["pack_dir"],
                                               symbol, project_dir)
                for item in result["call_sites"]:
                    hits.append({**item, "symbol": symbol})
                taint_flows.extend(result["taint_flows"])
            mode = "codeql"
        except (subprocess.CalledProcessError, OSError) as exc:
            notes.append(f"CodeQL failed, text fallback used: {_failure_text(exc)}")
            hits, taint_flows, mode = [], [], "text_scan"

    if mode == "text_scan":
        for symbol in symbol_names:
            hits.extend({**item, "symbol": symbol} for item in callsites.scan_call_sites(project_dir, symbol))

    if taint_flows:
        taint = verdict.TAINT_CONFIRMED
    elif mode == "codeql":
        taint = "not_found"
    else:
        taint = "not_analysed"

    analysis_complete = bool(symbol_names) and mode == "codeql" and not ctx["reflection"]
    reach = verdict.reachability(hits, taint, analysis_complete)

    pre_status, pre_details = preconditions.evaluate(
        cand["curated"]["preconditions"] if cand["curated"] else None, project_dir)
    final_verdict = verdict.verdict(reach, pre_status)

    entry_points = context.find_entry_points(project_dir)
    auth_hints = context.access_control_hints(project_dir)

    vuln = {
        "id": cand["vuln_id"],
        "cve": cand["cve"],
        "aliases": cand["aliases"],
        "summary": cand["summary"],
        "severity": cand["curated"]["severity"] if cand["curated"] else None,
        "cvss": cand["curated"]["cvss"] if cand["curated"] else None,
        "epss": ctx["epss"].get(cand["cve"]),
        "kev": (cand["cve"] in ctx["kev"]) if ctx["kev"] is not None and cand["cve"] else None,
    }

    evidence = [
        {"type": "dependency_present", "result": "confirmed",
         "detail": f"{dep['name']}:{dep['version']} ({dep['scope']})",
         "resolved_via": dep["resolved_via"], "manifest": dep["manifest"]},
        {"type": "advisory", "result": "confirmed", "sources": cand["sources"],
         "ids": cand["aliases"]},
        {"type": "vulnerable_symbols", "result": "confirmed" if symbol_names else "missing",
         "detail": symbol_names, "source": symbol_source},
        {"type": "call_site", "result": "confirmed" if hits else "not_found",
         "locations": hits, "method": mode},
        {"type": "entry_point", "result": "present_unlinked" if entry_points else "not_found",
         "routes": entry_points},
        {"type": "access_control", "result": "hints_present" if auth_hints else "not_found",
         "locations": auth_hints, "note": "Informational. Does not change the verdict."},
        {"type": "taint_path", "result": taint, "locations": _taint_locations(taint_flows)},
        {"type": "preconditions", "result": pre_status, "checks": pre_details},
    ]
    if ctx["reflection"]:
        evidence.append({"type": "reflection", "result": "incomplete",
                         "locations": ctx["reflection"][:20],
                         "note": "Reflective or dynamic calls make 'not reachable' unavailable."})

    limitations = [
        "library-internal calls are not analysed (scope is application code)",
        "preconditions use static text matches, not runtime configuration",
        "access-control hints are not proven to cover the route that reaches the sink",
    ]
    if mode == "codeql":
        limitations.append("call sites and taint come from CodeQL global data flow with RemoteFlowSource as source")
    else:
        limitations += [
            "text-scan fallback: no type resolution, taint not analysed",
            "CodeQL CLI not available or failed; reachability is partial",
        ]
    limitations += notes

    return {
        "id": f"{cand['cve'] or cand['vuln_id']}@{dep['name']}:{dep['version']}",
        "vulnerability": vuln,
        "library": dep["name"],
        "dependency": {"ecosystem": dep["ecosystem"], "version": dep["version"], "scope": dep["scope"],
                       "resolved_via": dep["resolved_via"], "manifest": dep["manifest"]},
        "reachability": reach,
        "preconditions": pre_status,
        "verdict": final_verdict,
        "confidence": verdict.confidence(analysis_complete, taint),
        "evidence": evidence,
        "scope": {"analysed": [str(project_dir)], "analysis_mode": mode, "limitations": limitations},
    }


def run(project_dir: Path, deps_path: Path | None, rules_dir: Path, output_dir: Path, fail_on: str,
        *, offline: bool = False, cache_dir: Path | None = None, fix_diffs_dir: Path | None = None,
        codeql_path: str | None = None, build_command: str | None = None,
        intel: intel_module.Intel | None = None) -> dict:
    deps = [d for d in ingest.resolve(project_dir, deps_path)
            if d["scope"] not in SHIPPED_SCOPE_EXCLUDED]
    rules = symbols.load_rules(rules_dir)
    intel = intel or intel_module.Intel(cache_dir=cache_dir, offline=offline)

    candidates = collect_candidates(deps, rules, intel)
    cves = [c["cve"] for c in candidates.values() if c["cve"]]
    epss = intel.epss_scores(cves) if cves else {}
    kev = intel.kev_cves() if cves else None

    notes: list[str] = []
    codeql_bin = codeql.find_codeql(codeql_path)
    db_dir = pack_dir = None
    if codeql_bin is None:
        notes.append("CodeQL CLI not found; call sites use the text-scan fallback")
    elif candidates:
        work = output_dir / "codeql-work"
        db_dir, pack_dir = work / "db", work / "pack"
        try:
            codeql.build_database(codeql_bin, project_dir, db_dir, build_command)
        except (subprocess.CalledProcessError, OSError) as exc:
            notes.append(f"CodeQL database creation failed, text-scan fallback used: {_failure_text(exc)}")
            db_dir = None

    ctx = {
        "intel": intel,
        "fix_diffs_dir": fix_diffs_dir,
        "epss": epss,
        "kev": kev,
        "codeql_bin": codeql_bin,
        "db_dir": db_dir,
        "pack_dir": pack_dir,
        "reflection": callsites.reflection_indicators(project_dir),
    }

    findings = [analyse_candidate(cand, project_dir, ctx) for cand in candidates.values()]
    gate = any(verdict.gate_failed(fail_on, f["reachability"], f["verdict"]) for f in findings)
    modes = {f["scope"]["analysis_mode"] for f in findings}
    summary = {
        "project": str(project_dir),
        "dependencies_analysed": len(deps),
        "findings": len(findings),
        "verdicts": {v: sum(1 for f in findings if f["verdict"] == v)
                     for v in sorted({f["verdict"] for f in findings})},
        "analysis_mode": "codeql" if modes == {"codeql"} else "text_scan" if findings else "none",
        "intel": dict(intel.status),
        "fail_on": fail_on,
        "gate_failed": gate,
        "notes": notes,
    }

    report.write_all(output_dir, findings, summary, TOOL_VERSION)
    return summary
