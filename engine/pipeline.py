"""Analysis pipeline.

dependencies → advisories (OSV) → enrichment (EPSS, KEV) → vulnerable symbols
(curated or fix-commit) → call sites and taint (CodeQL, or text fallback) →
preconditions → verdict → reports.
"""

import subprocess
from pathlib import Path

from pathlib import Path

from engine import advisories, callgraph, callsites, codeql, context, exploitability as xp, findings as scanner_findings, ingest, intel as intel_module
from engine import policy, preconditions, report, symbols, verdict, versions

SHIPPED_SCOPE_EXCLUDED = {"test", "dev"}
ECOSYSTEMS_QUERIED = {"Maven", "npm", "PyPI", "Go", "crates.io", "Packagist", "RubyGems", "NuGet"}
NVD_LOOKUP_LIMIT = 25  # NVD allows few unauthenticated requests; a run enriches at most this many CVEs
GHSA_QUERY_LIMIT = 300  # one request per dependency; stops a very large inventory from exhausting the rate limit
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
                # OSV answers the version question for this exact version.
                "version_status": xp.CONFIRMED,
            })

    ghsa_queries = 0
    for dep in deps:
        if ghsa_queries >= GHSA_QUERY_LIMIT:
            break
        if dep["ecosystem"] not in ECOSYSTEMS_QUERIED:
            continue
        ghsa_queries += 1
        for advisory in intel.ghsa_advisories(dep["ecosystem"], dep["name"], dep["version"]) or []:
            ranges = [r for r in advisory["ranges"]
                      if r["package"] == dep["name"]
                      and advisories.GHSA_ECOSYSTEM.get(dep["ecosystem"]) == r["ecosystem"]]
            if not ranges:
                continue
            checks = [advisories.evaluate_range(dep["ecosystem"], dep["version"], r["vulnerable_range"])
                      for r in ranges]
            key = (_cve_or_id(advisory["id"], advisory["cve"]), dep["ecosystem"], dep["name"], dep["version"])
            cand = candidates.setdefault(key, {
                "key": key,
                "cve": advisory["cve"],
                "vuln_id": advisory["id"],
                "aliases": [a for a in (advisory["id"], advisory["cve"]) if a],
                "summary": advisory["summary"],
                "fix_commits": [],
                "dependency": dep,
                "curated": None,
                "sources": ["ghsa"],
                # The provider filtered by this version. A range that disagrees is kept as UNKNOWN and noted.
                "version_status": xp.CONFIRMED if any(c is True for c in checks) else xp.UNKNOWN,
                "conflict": any(c is False for c in checks) and not any(c is True for c in checks),
            })
            cand.setdefault("ghsa", advisory)
            if "ghsa" not in cand["sources"]:
                cand["sources"].append("ghsa")

    for rule in rules:
        for dep in deps:
            if dep["ecosystem"] != rule.get("ecosystem", "Maven") or dep["name"] != rule["library"]:
                continue
            affected = versions.is_affected(dep["ecosystem"], dep["version"],
                                            rule["affected"]["introduced"], rule["affected"]["fixed"])
            key = (rule["cve"], dep["ecosystem"], dep["name"], dep["version"])
            if affected is False:
                if key in candidates:
                    # Another source says this version is affected. The two disagree, so the
                    # version is UNKNOWN, never NOT_AFFECTED.
                    candidates[key]["version_status"] = xp.UNKNOWN
                    candidates[key]["conflict"] = True
                    candidates[key]["conflict_detail"] = "curated range says not affected; another source says affected"
                    continue
                # Outside the curated affected range, and no source says otherwise.
                candidates[key] = {
                    "key": key,
                    "cve": rule["cve"],
                    "vuln_id": rule["cve"],
                    "aliases": [rule["cve"]],
                    "summary": rule.get("summary", ""),
                    "fix_commits": [],
                    "dependency": dep,
                    "curated": rule,
                    "sources": ["curated"],
                    "version_status": xp.NOT_CONFIRMED,
                }
                continue
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
                "version_status": xp.UNKNOWN,
            })
            # affected is None when the ecosystem scheme is unsupported: the version is then UNKNOWN, not unaffected.
            if affected is True:
                cand["version_status"] = xp.CONFIRMED
            cand["curated"] = rule
            cand["sources"].append("curated")

    return candidates


def cand_language(cand: dict) -> str:
    """Curated rules name their language. Symbols derived from fix commits are Java."""
    return cand["curated"].get("language", "java") if cand["curated"] else "java"


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


def derive_stages(*, cand: dict, symbol_names: list[str], mode: str, codeql_requested: bool,
                  hits: list[dict], taint: str, analysis_complete: bool, pre_status: str,
                  mitigated: bool, kev_status: bool | None, config_status: str = "unverified") -> dict[str, str]:
    """Map what the engine observed to one status per stage. See docs/EXPLOITABILITY_MODEL.md."""
    if mode == "codeql":
        reachability = xp.CONFIRMED if hits else (xp.NOT_CONFIRMED if analysis_complete else xp.UNKNOWN)
        data_flow = xp.CONFIRMED if taint == verdict.TAINT_CONFIRMED else xp.NOT_CONFIRMED
    elif codeql_requested:
        # CodeQL was available but did not complete: a failure, not a lexical result.
        reachability = xp.ANALYSIS_FAILED
        data_flow = xp.ANALYSIS_FAILED
    else:
        # Text scan is lexical matching only, so it cannot establish call-graph reachability.
        reachability = xp.UNKNOWN
        data_flow = xp.UNKNOWN

    precondition_map = {"satisfied": xp.CONFIRMED, "not_satisfied": xp.NOT_CONFIRMED, "unverified": xp.UNKNOWN}
    if kev_status is None:
        threat = xp.UNKNOWN
    else:
        threat = xp.CONFIRMED if kev_status else xp.NOT_CONFIRMED

    return {
        "A_presence": xp.CONFIRMED,
        "B_version": cand["version_status"],
        "C_inclusion": xp.UNKNOWN,
        "D_function": xp.CONFIRMED if symbol_names else xp.UNKNOWN,
        "E_function_reachability": reachability,
        "F_entry_point": xp.CONFIRMED if taint == verdict.TAINT_CONFIRMED else xp.UNKNOWN,
        "G_data_flow": data_flow,
        "H_preconditions": precondition_map[pre_status],
        "I_configuration": {"satisfied": xp.CONFIRMED, "not_satisfied": xp.NOT_CONFIRMED}.get(
            config_status, xp.UNKNOWN),
        "J_security_controls": xp.UNKNOWN,
        "K_mitigation": xp.CONFIRMED if mitigated else xp.UNKNOWN,
        "L_threat_intelligence": threat,
    }


def _python_call_paths(hits: list[dict], project_dir: Path, ctx: dict) -> tuple[str, list[dict], dict]:
    """Return (result, paths, graph_summary). result is one of: none_needed, confirmed, not_found, incomplete.

    "not_found" is returned only when the graph is complete and the search finished.
    Otherwise the result is "incomplete": the absence of a path is unknown.
    """
    python_hits = [h for h in hits if str(h.get("file", "")).endswith(".py")]
    if not python_hits:
        return "none_needed", [], {}
    if "python_graph" not in ctx:
        ctx["python_graph"] = callgraph.build(project_dir)
    graph = ctx["python_graph"]
    summary = graph.summary()
    targets = {callgraph.enclosing_function(graph, h["file"], h["line"]) for h in python_hits}
    targets.discard(None)
    if not targets:
        return "incomplete", [], {**summary, "reason": "vulnerable call not inside a graph node"}
    found, search_complete = callgraph.paths_to(graph, targets)
    paths = [{"entry": path[0], "route": graph.nodes[path[0]]["route"], "path": path}
             for path in found]
    if paths:
        return "confirmed", paths, summary
    if not graph.complete or not search_complete:
        return "incomplete", [], summary
    return "not_found", [], summary


def _graph_limitations(call_graph: dict) -> list[str]:
    """A truncated call graph must be visible in the report, not only in evidence.json."""
    if not call_graph or call_graph.get("complete", True):
        return []
    reasons = ", ".join(call_graph.get("incomplete_reasons") or ["unknown"])
    return [f"{report.CALL_GRAPH_INCOMPLETE} ({reasons}); the absence of a call path is unknown"]


def analysis_summary(ctx: dict, findings: list[dict]) -> dict:
    """Completeness of the bounded analysis, for summary.json and SARIF.

    The Python call graph is the only bounded structure. Its limits and counts are reported
    whether or not it was built. "bounded_analysis_complete" is True only when no
    incompleteness was detected. It is not a claim that the analysis is exhaustive.
    """
    graph = ctx.get("python_graph")
    incomplete_findings = [f["id"] for f in findings
                           if any(e.get("type") == "call_paths" and e.get("result") == "incomplete"
                                  for e in f["evidence"])]
    call_graph = None
    if graph is not None:
        call_graph = {**graph.summary(), "built": True}
    reasons = list(graph.incomplete_reasons) if graph is not None else []
    return {
        "python_call_graph": call_graph or {"built": False},
        "limits": {"max_nodes": callgraph.MAX_NODES, "max_edges": callgraph.MAX_EDGES,
                   "max_depth": callgraph.MAX_DEPTH, "max_paths": callgraph.MAX_PATHS,
                   "max_expansions": callgraph.MAX_EXPANSIONS},
        "findings_with_incomplete_call_paths": incomplete_findings,
        "incomplete_reasons": reasons,
        "bounded_analysis_complete": not reasons and not incomplete_findings,
    }


def add_imported_findings(candidates: dict, imported: list[dict], deps: list[dict],
                          rules: list[dict]) -> tuple[dict, int]:
    """Add scanner findings (merged by engine/findings.py) to the candidates.

    An imported finding becomes the same candidate shape as an OSV, GHSA or curated match.
    The scanner's claim that this version is affected is version evidence, and it is recorded
    with the scanner's name. A curated rule that says the version is not affected conflicts
    with the scanner, so the status is UNKNOWN, as it is for the other sources. Findings for an
    unknown ecosystem cannot be analysed and are counted, not guessed at. Returns
    (candidates, skipped_count).
    """
    skipped = 0
    for item in imported:
        if item["ecosystem"] == scanner_findings.UNKNOWN_ECOSYSTEM:
            skipped += 1
            continue
        cve = next((i for i in item["ids"] if scanner_findings.CVE_RE.match(i)), None)
        vuln_id = item["primary_id"]
        dep = next((d for d in deps if scanner_findings._identity(d) == scanner_findings._identity(item)),
                   None)
        if dep is None:
            target = item["sources"][0].get("target") or "scanner-import"
            dep = ingest.make_dependency(item["ecosystem"], item["name"], item["version"], "runtime",
                                         ["scanner-import"], target)
        rule = next((r for r in rules if cve and r["cve"] == cve and r["library"] == dep["name"]
                     and r.get("ecosystem", "Maven") == dep["ecosystem"]), None)
        key = (_cve_or_id(vuln_id, cve), dep["ecosystem"], dep["name"], dep["version"])
        scanners = [s for s in item["sources"]]
        if key in candidates:
            cand = candidates[key]
            cand["aliases"] = list(dict.fromkeys(cand["aliases"] + item["ids"]))
            cand["fix_commits"] = list(dict.fromkeys(cand["fix_commits"] + [
                c for s in scanners for c in s.get("fix_commits", [])]))
            cand["sources"] = cand["sources"] + ["scanner"]
            cand["scanner_sources"] = scanners
            if cand["version_status"] == xp.NOT_CONFIRMED:
                cand["version_status"] = xp.UNKNOWN
                cand["conflict"] = True
                cand["conflict_detail"] = "scanner reports this version affected; curated range says not affected"
            continue
        candidates[key] = {
            "key": key,
            "cve": cve,
            "vuln_id": vuln_id,
            "aliases": item["ids"],
            "summary": item["summary"],
            "fix_commits": [c for s in scanners for c in s.get("fix_commits", [])],
            "dependency": dep,
            "curated": rule,
            "sources": ["scanner"],
            "scanner_sources": scanners,
            # The scanner reported this installed version as affected.
            "version_status": xp.CONFIRMED,
        }
    return candidates, skipped


def analyse_candidate(cand: dict, project_dir: Path, ctx: dict) -> dict:
    dep = cand["dependency"]
    symbol_names, symbol_source = candidate_symbols(cand, ctx["intel"], ctx["fix_diffs_dir"])
    notes: list[str] = []

    hits: list[dict] = []
    taint_flows: list[dict] = []
    mode = "text_scan"
    language = cand_language(cand)
    database = ctx["codeql_dbs"].get(language)
    if ctx["codeql_bin"] and database and symbol_names:
        try:
            for symbol in symbol_names:
                result = codeql.analyse_symbol(ctx["codeql_bin"], database[0], database[1],
                                               symbol, project_dir, language)
                for item in result["call_sites"]:
                    hits.append({**item, "symbol": symbol})
                taint_flows.extend(result["taint_flows"])
            mode = "codeql"
        except (subprocess.CalledProcessError, OSError) as exc:
            notes.append(f"CodeQL failed, text fallback used: {_failure_text(exc)}")
            hits, taint_flows, mode = [], [], "text_scan"

    if mode == "text_scan":
        for symbol in symbol_names:
            hits.extend({**item, "symbol": symbol}
                        for item in callsites.scan_call_sites(project_dir, symbol, language))

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
    call_path_result, call_paths, call_graph = _python_call_paths(hits, project_dir, ctx)
    entry_points = (context.find_entry_points(project_dir) + context.find_python_entry_points(project_dir)
                    + context.find_javascript_entry_points(project_dir)
                    + context.find_go_entry_points(project_dir))
    auth_hints = context.access_control_hints(project_dir)

    nvd = cand.get("nvd")
    config_status, config_details = preconditions.evaluate(
        cand["curated"]["configuration"], project_dir) if cand["curated"] and cand["curated"].get("configuration") \
        else ("unverified", [])
    mitigated = any(c.get("kind") == "mitigated_by" and c.get("result") == "not_satisfied"
                    for c in pre_details)
    kev_status = None
    if ctx["kev"] is not None and cand["cve"]:
        kev_status = cand["cve"] in ctx["kev"]
    stage_values = derive_stages(
        cand=cand, symbol_names=symbol_names, mode=mode, codeql_requested=ctx["codeql_bin"] is not None,
        hits=hits, taint=taint, analysis_complete=analysis_complete, pre_status=pre_status,
        mitigated=mitigated, kev_status=kev_status, config_status=config_status)
    classification, classification_reason = xp.classify(
        stage_values, access_controls_present=bool(auth_hints), exposure=ctx["exposure"])
    final_verdict = xp.legacy_verdict(classification)

    vuln = {
        "scanner_sources": cand.get("scanner_sources", []),
        "id": cand["vuln_id"],
        "cve": cand["cve"],
        "aliases": cand["aliases"],
        "summary": cand["summary"],
        "severity": (cand["curated"] or {}).get("severity") or
                    ((nvd or {}).get("severity") or ((cand.get("ghsa") or {}).get("severity") or "")).upper() or None,
        "cvss": (cand["curated"] or {}).get("cvss") or (nvd or {}).get("cvss_score")
                or (cand.get("ghsa") or {}).get("cvss_score"),
        "cwes": (nvd or {}).get("cwes", []),
        "references": sorted(set((nvd or {}).get("references", []))
                             | set((cand.get("ghsa") or {}).get("references", []))),
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
        {"type": "call_paths", "result": call_path_result, "paths": call_paths, "graph": call_graph,
         "method": "python-ast name resolution (bounded, cycle-free)"},
        {"type": "preconditions", "result": pre_status, "checks": pre_details},
        {"type": "configuration", "result": config_status, "checks": config_details},
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
    limitations += _graph_limitations(call_graph)
    if cand.get("conflict"):
        limitations.append("GHSA reports this version as affected but its range does not match; "
                           "version applicability is treated as UNKNOWN")
    if cand.get("conflict_detail"):
        limitations.append(f"{cand['conflict_detail']}; version applicability is treated as UNKNOWN")

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
        "classification": classification,
        "classification_reason": classification_reason,
        "stages": stage_values,
        "priority": "elevated" if kev_status else "standard",
        "evidence": evidence,
        "scope": {"analysed": [str(project_dir)], "analysis_mode": mode, "limitations": limitations},
    }


def run(project_dir: Path, deps_path: Path | None, rules_dir: Path, output_dir: Path, fail_on: str,
        *, offline: bool = False, cache_dir: Path | None = None, fix_diffs_dir: Path | None = None,
        codeql_path: str | None = None, build_command: str | None = None,
        intel: intel_module.Intel | None = None, policy_path: Path | None = None,
        exposure: str = "unknown", imported_findings: list[dict] | None = None) -> dict:
    notes: list[str] = []
    try:
        resolved = ingest.resolve(project_dir, deps_path)
    except FileNotFoundError:
        # A scanner's own findings name their manifest, so they can be analysed without a resolved file at the root.
        # Without them there is nothing to analyse, so the error stands.
        if not imported_findings:
            raise
        resolved = []
        notes.append("no resolved dependency file at the project root: scanner-reported dependencies only")
    deps = [d for d in resolved if d["scope"] not in SHIPPED_SCOPE_EXCLUDED]
    rules = symbols.load_rules(rules_dir)
    intel = intel or intel_module.Intel(cache_dir=cache_dir, offline=offline)

    candidates = collect_candidates(deps, rules, intel)
    imported_skipped = 0
    if imported_findings:
        candidates, imported_skipped = add_imported_findings(candidates, imported_findings, deps, rules)
    cves = [c["cve"] for c in candidates.values() if c["cve"]]
    epss = intel.epss_scores(cves) if cves else {}
    kev = intel.kev_cves() if cves else None
    for cand in list(candidates.values())[:NVD_LOOKUP_LIMIT]:
        if cand["cve"]:
            cand["nvd"] = intel.nvd_cve(cand["cve"])
    unresolved = sum(1 for d in deps if d["ecosystem"] == "unknown")

    if imported_skipped:
        notes.append(f"{imported_skipped} imported scanner finding(s) skipped: ecosystem not supported for analysis")
    codeql_bin = codeql.find_codeql(codeql_path)
    codeql_dbs: dict[str, tuple[Path, Path]] = {}
    if codeql_bin is None:
        notes.append("CodeQL CLI not found; call sites use the text-scan fallback")
    elif candidates:
        for language in sorted({cand_language(c) for c in candidates.values()}):
            work = output_dir / "codeql-work" / language
            db_dir, pack_dir = work / "db", work / "pack"
            try:
                codeql.build_database(codeql_bin, project_dir, db_dir, language, build_command)
                codeql_dbs[language] = (db_dir, pack_dir)
            except (subprocess.CalledProcessError, OSError) as exc:
                notes.append(f"CodeQL database creation failed for {language}, "
                             f"text-scan fallback used: {_failure_text(exc)}")

    ctx = {
        "intel": intel,
        "exposure": exposure,
        "fix_diffs_dir": fix_diffs_dir,
        "epss": epss,
        "kev": kev,
        "codeql_bin": codeql_bin,
        "codeql_dbs": codeql_dbs,
        "reflection": callsites.reflection_indicators(project_dir),
    }

    findings = [analyse_candidate(cand, project_dir, ctx) for cand in candidates.values()]
    policy_summary = None
    if policy_path is not None:
        # With a policy file, the policy decides the gate. The fail_on value is then ignored.
        policy_summary = policy.evaluate(policy.load_policy(policy_path), findings)
        gate = policy_summary["blocked"]
    else:
        gate = any(verdict.gate_failed(fail_on, f["reachability"], f["verdict"]) for f in findings)
    modes = {f["scope"]["analysis_mode"] for f in findings}
    summary = {
        "project": str(project_dir),
        "dependencies_analysed": len(deps),
        "unresolved_dependencies": unresolved,
        "findings": len(findings),
        "verdicts": {v: sum(1 for f in findings if f["verdict"] == v)
                     for v in sorted({f["verdict"] for f in findings})},
        "analysis_mode": "codeql" if modes == {"codeql"} else "text_scan" if findings else "none",
        "intel": dict(intel.status),
        "intel_health": {source: dict(h) for source, h in intel.health.items()},
        "classifications": {c: sum(1 for f in findings if f["classification"] == c)
                            for c in sorted({f["classification"] for f in findings})},
        "policy": policy_summary,
        "fail_on": fail_on,
        "gate_failed": gate,
        "notes": notes,
        "analysis": analysis_summary(ctx, findings),
    }

    report.write_all(output_dir, findings, summary, TOOL_VERSION)
    return summary
