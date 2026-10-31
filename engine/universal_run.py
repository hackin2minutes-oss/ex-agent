"""Runs the universal path: scanner reports in, assessed findings and reports out.

`python -m engine.universal_run --input A.json --input B.json ...` accepts any number of reports in one run.
Each report is routed to one of two paths:

- A registered universal adapter (Semgrep, Checkov, Zizmor, Gitleaks, Trivy config, Hadolint, Nuclei). The
  adapter's findings go to the engine for their category.
- The SCA path, for Trivy vulnerability, Grype and OSV-Scanner reports. These are merged and run through the
  existing SCA pipeline (engine/pipeline.py) with the scanner findings imported. The pipeline's evidence is
  then projected onto the universal model (engine/sca_universal.py). The SCA pipeline is unchanged.

A report that cannot be read or recognised is skipped with a diagnostic, and the run goes on. The run fails
only if no report can be used. Findings with the same identifier from different reports are merged, and
every reporter is kept in the finding's `sources`.

Adding a scanner means registering an adapter in `build_registry`. Adding a domain means registering an
engine there. Neither changes `run`.
"""

import argparse
import importlib.util
import json
import os
import signal
import sys
from pathlib import Path

from engine import code_scanning, deployment_context, evidence_graph, intel_snapshot, provenance, report_pdf, weakness
from engine import findings as sca_findings
from engine import sarif_dependency
from engine import dependency
from engine import dependency_usage
from engine import pipeline, report, sca_universal, universal, universal_report
from engine import guidance
from engine.application import Application
from engine.checkov_adapter import CheckovAdapter
from engine.cicd import CicdEngine
from engine.container import ContainerEngine
from engine.dast import DastEngine
from engine.gitleaks_adapter import GitleaksAdapter
from engine.hadolint_adapter import HadolintAdapter
from engine.iac import IacEngine
from engine.iast import IastAdapter, IastEngine
from engine.rasp import RaspAdapter, RaspEngine
from engine.nuclei_adapter import NucleiAdapter
from engine.sast import SastEngine
from engine.sarif_adapter import SarifAdapter
from engine.threat_model import ThreatModelAdapter, ThreatModelEngine
from engine.secrets_engine import SecretsEngine
from engine.semgrep_adapter import SemgrepAdapter
from engine.trivy_config_adapter import TrivyConfigAdapter
from engine import updates
from engine.universal import EXPOSURES, ModelError, Registry

REPORT_SUFFIXES = {".sarif", ".json"}
from engine.zizmor_adapter import ZizmorAdapter

TOOL_VERSION = "0.8.0"
# Resource budgets. A report over a budget is skipped with a diagnostic, not read.
MAX_REPORT_BYTES = 50_000_000
MAX_RECORDS = 20_000
DEFAULT_TIMEOUT_SECONDS = 600
EXIT_TIMEOUT = 3
DEFAULT_RULES = Path(__file__).resolve().parent.parent / "rules"
# Verdicts that fail the gate. CONFIRMED_EXPLOITABLE is the default. POTENTIALLY_EXPLOITABLE is
# stricter, for a team that wants a build to stop on any unresolved potential.
GATE_VERDICTS = {
    "confirmed_exploitable": (universal.CONFIRMED_EXPLOITABLE,),
    "potentially_exploitable": (universal.CONFIRMED_EXPLOITABLE, universal.POTENTIALLY_EXPLOITABLE),
}


def build_registry() -> Registry:
    registry = Registry()
    registry.register_adapter(SemgrepAdapter())
    registry.register_adapter(CheckovAdapter())
    registry.register_adapter(ZizmorAdapter())
    registry.register_adapter(GitleaksAdapter())
    registry.register_adapter(TrivyConfigAdapter())
    registry.register_adapter(HadolintAdapter())
    registry.register_adapter(NucleiAdapter())
    registry.register_adapter(SarifAdapter())
    registry.register_adapter(IastAdapter())
    registry.register_adapter(RaspAdapter())
    registry.register_adapter(ThreatModelAdapter())
    registry.register_engine(SastEngine())
    registry.register_engine(IacEngine())
    registry.register_engine(CicdEngine())
    registry.register_engine(SecretsEngine())
    registry.register_engine(ContainerEngine())
    registry.register_engine(DastEngine())
    registry.register_engine(IastEngine())
    registry.register_engine(RaspEngine())
    registry.register_engine(ThreatModelEngine())
    return registry


def _count_verdicts(assessed: list[dict]) -> dict:
    counts = {verdict: 0 for verdict in universal.VERDICTS}
    for finding in assessed:
        counts[finding["assessment"]["verdict"]] += 1
    return counts


def _read(path: Path) -> tuple[str, object]:
    text = path.read_text(encoding="utf-8")
    return text, json.loads(text)


def _image_inventory_finding(item: dict, document: dict, exposure: str) -> dict:
    """A vulnerability in a package installed in a container image. Its verdict is UNKNOWN: the scan shows the
    package is present, not that the application uses the vulnerable part of it."""
    ecosystem = "operating-system package" if item.get("ecosystem") in (None, "unknown") else "installed package"
    package = f"{item.get('name', '')}@{item.get('version', '')}"
    finding = universal.make_finding(
        category="CONTAINER",
        rule_id=item.get("primary_id") or "unknown",
        title=item.get("summary") or item.get("primary_id") or "unknown",
        asset={"type": "container_image", "name": document.get("ArtifactName") or "image"},
        location=None,
        severity_reported=item.get("severity"),
        provenance={"scanner": (item.get("sources") or [{}])[0].get("scanner", "unknown"),
                    "version": None, "format": "scanner-json", "target": package,
                    "reported_by": [src.get("scanner") for src in item.get("sources") or []]},
        original=item,
        ids=list(item.get("ids") or []),
        exposure=exposure,
        identity=(package,),
    )
    # The version dimension is separate from use. A fixed version installed means the component is not affected, so
    # it is NOT_AFFECTED, whatever the application does with it. Anything else stays UNKNOWN.
    status = dependency.version_status(item)
    source = (item.get("sources") or [{}])[0].get("scanner", "scanner")
    if status["status"] == dependency.FIXED_INSTALLED:
        finding["assessment"] = universal.make_assessment(
            universal.NOT_AFFECTED,
            reason=f"{status['reason']}, as the {source} record shows",
            engine="container-image-inventory",
            conditions={"vulnerability_exists": universal.Condition(
                universal.NOT_CONFIRMED, [f"{source} fixed version {status['fixed']}"])},
            evidence=[{"condition": "vulnerability_exists", "kind": "version", "detail": status["reason"],
                       "source": source}],
            confidence="MEDIUM",
            confidence_reason="the fixed version comes from the scanner's record and is not checked against the advisory",
            coverage={"analysed": [f"{package} version against {source}'s fixed version"],
                      "not_analysed": ["application use of the package"]},
            limitations=["the fixed version is taken from the scanner's record, not from the advisory itself"],
            exposure=exposure,
        ).to_dict()
        finding["assessment"]["version_status"] = status["status"]
        finding["assessment"]["dimensions"] = dependency.dimensions(
            presence="image", version=status, usage=None, verdict=universal.NOT_AFFECTED)
        return finding
    finding["assessment"] = universal.make_assessment(
        universal.UNKNOWN,
        reason=f"{ecosystem} {package} is present in the image; whether the application uses the "
               "vulnerable part is not analysed",
        engine="container-image-inventory",
        coverage={"analysed": [f"{package} present in the image"],
                  "not_analysed": ["application use of the package", "runtime exposure of the container"]},
        limitations=["application use of the package is not analysed",
                     "runtime exposure and isolation of the container are not analysed",
                     status["reason"]],
        exposure=exposure,
    ).to_dict()
    finding["assessment"]["version_status"] = status["status"]
    finding["assessment"]["dimensions"] = dependency.dimensions(
        presence="image", version=status, usage=None, verdict=universal.UNKNOWN)
    return finding


def _sca_incomplete(item: dict, exposure: str, reason: str) -> dict:
    """An imported SCA finding whose analysis failed. It is reported, not dropped."""
    package = f"{item.get('name', '')}@{item.get('version', '')}"
    finding = universal.make_finding(
        category="SCA",
        rule_id=item.get("primary_id") or "unknown",
        title=item.get("summary") or item.get("primary_id") or "unknown",
        asset={"type": "dependency", "name": package},
        location=None,
        severity_reported=item.get("severity"),
        provenance={"scanner": (item.get("sources") or [{}])[0].get("scanner", "unknown"),
                    "version": None, "format": "scanner-json", "target": None},
        original=item,
        ids=list(item.get("ids") or []),
        exposure=exposure,
    )
    finding["assessment"] = universal.incomplete_assessment(reason, engine="sca-pipeline").to_dict()
    return finding


def _run_sca(sca_inputs: list[tuple[str, list[dict]]], project_dir: Path, output_dir: Path, *,
             exposure: str, offline: bool, rules_dir: Path, diagnostics: list[str]) -> list[dict]:
    """Run the SCA pipeline over the imported scanner findings and project its evidence."""
    imported = []
    for name, items in sca_inputs:
        imported.extend(items)
    merged = sca_findings.merge_findings(imported)
    sca_dir = output_dir / "sca"
    try:
        summary = pipeline.run(project_dir, None, rules_dir, sca_dir, "confirmed_reachable",
                               offline=offline, exposure=exposure, imported_findings=merged)
        evidence = json.loads((sca_dir / "evidence.json").read_text(encoding="utf-8"))
    except (ModelError, OSError, ValueError, KeyError) as exc:
        reason = f"SCA analysis failed: {type(exc).__name__}: {exc}"[:300]
        diagnostics.append(reason)
        return [_sca_incomplete(item, exposure, reason) for item in merged]
    for note in summary.get("notes") or []:
        diagnostics.append(f"sca: {note}")
    projected = [sca_universal.project_record(record, exposure)
                 for record in evidence.get("findings", [])]
    diagnostics.append(f"sca: {len(merged)} imported scanner finding(s), {len(projected)} assessed")
    return projected


def _sources_of(finding: dict) -> list[dict]:
    """One provenance record per reporter. The SCA projection lists every reporter it merged."""
    provenance = finding["provenance"]
    # Each reporter once. The per-record details of each source stay in the pipeline's evidence.
    reporters = list(dict.fromkeys(provenance.get("reported_by") or []))
    if not reporters:
        return [provenance]
    return [{**provenance, "scanner": name} for name in reporters]


def _merge_duplicates(findings: list[dict]) -> list[dict]:
    """Merge findings that share an identifier. The first is kept, and every reporter is listed in `sources`."""
    merged: dict[str, dict] = {}
    for finding in findings:
        existing = merged.get(finding["id"])
        if existing is None:
            finding["sources"] = _sources_of(finding)
            merged[finding["id"]] = finding
            continue
        for source in _sources_of(finding):
            if source not in existing["sources"]:
                existing["sources"].append(source)
    return list(merged.values())


def load_plugin(path: Path, registry: Registry) -> str:
    """Load a plugin file and let it register its adapters and engines. The core engine is not edited: a plugin file
    defines register(registry) and calls registry.register_adapter / register_engine."""
    if not path.is_file() or path.suffix != ".py":
        raise ModelError(f"plugin must be a .py file: {path}")
    spec = importlib.util.spec_from_file_location(f"sawone_plugin_{path.stem}", path)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # a broken plugin must stop the run, not be skipped
        raise ModelError(f"plugin {path.name} failed to load: {type(exc).__name__}") from exc
    register = getattr(module, "register", None)
    if not callable(register):
        raise ModelError(f"plugin {path.name} defines no register(registry) function")
    register(registry)
    return f"plugin {path.name}: registered"


def run(inputs, project_dir: Path, output_dir: Path, *, exposure: str = "unknown",
        adapter_name: str | None = None, fail_on: str = "confirmed_exploitable",
        registry: Registry | None = None, offline: bool = True,
        rules_dir: Path = DEFAULT_RULES, max_report_bytes: int = MAX_REPORT_BYTES,
        max_records: int = MAX_RECORDS, context_document: dict | None = None,
        intel: intel_snapshot.Snapshot | None = None) -> dict:
    if fail_on not in GATE_VERDICTS:
        raise ModelError(f"unknown gate: {fail_on}")
    if exposure not in EXPOSURES:
        raise ModelError(f"unknown exposure: {exposure}")
    input_paths = [Path(p) for p in ([inputs] if isinstance(inputs, (str, Path)) else inputs)]
    if not input_paths:
        raise ModelError("no scanner report was given")
    registry = registry or build_registry()
    deployment = deployment_context.load(context_document) if context_document is not None else None

    diagnostics: list[str] = []
    findings: list[dict] = []
    sca_inputs: list[tuple[str, list[dict]]] = []
    adapters_used: list[str] = []
    inputs_summary = []
    for path in input_paths:
        try:
            size = path.stat().st_size
        except OSError as exc:
            diagnostics.append(f"skipped {path.name}: not readable ({type(exc).__name__})")
            inputs_summary.append({"input": path.name, "route": "skipped"})
            continue
        if size > max_report_bytes:
            diagnostics.append(f"skipped {path.name}: {size} bytes exceeds the {max_report_bytes}-byte budget")
            inputs_summary.append({"input": path.name, "route": "skipped"})
            continue
        try:
            _, document = _read(path)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            diagnostics.append(f"skipped {path.name}: not readable JSON ({type(exc).__name__})")
            inputs_summary.append({"input": path.name, "route": "skipped"})
            continue
        if isinstance(document, dict) and isinstance(document.get("runs"), list) and not adapter_name:
            # Dependency results in SARIF carry a package and version, not source code. They go to the dependency
            # analysis, not to the source-level SAST engine. The rest of the SARIF goes on to its adapter.
            dependency_records, document = sarif_dependency.split(document)
            if dependency_records:
                image_records = [r for r in dependency_records if r["sources"][0]["scope"] == "image"]
                project_records = [r for r in dependency_records if r["sources"][0]["scope"] != "image"]
                findings.extend(_image_inventory_finding(item, {"ArtifactName": path.name}, exposure)
                                for item in image_records)
                if project_records:
                    sca_inputs.append((path.name, project_records))
                inputs_summary.append({"input": path.name, "route": "sarif-dependency",
                                       "records": len(dependency_records)})
                diagnostics.append(f"sarif-dependency: {len(dependency_records)} dependency result(s), "
                                   f"{len(image_records)} in an image, {len(project_records)} assessed as dependencies")
        if adapter_name:
            adapter = registry.adapter(adapter_name)
        else:
            adapter = registry.detect_adapter(document)
        try:
            if adapter is not None:
                parsed, parse_notes = adapter.parse(document, {"target": path.name})
                if len(parsed) > max_records:
                    raise ModelError(f"{len(parsed)} records exceed the {max_records}-record budget")
                findings.extend(parsed)
                adapters_used.append(adapter.name)
                diagnostics.extend(parse_notes)
                inputs_summary.append({"input": path.name, "route": adapter.name,
                                       "records": len(parsed)})
                continue
            detected = sca_findings.detect(json.dumps(document))
            if detected is not None:
                _, items = detected
                if len(items) > max_records:
                    raise ModelError(f"{len(items)} records exceed the {max_records}-record budget")
                if document.get("ArtifactType") == "container_image":
                    # An image scan lists what is installed in the image. It does not show what the application
                    # uses, so it is not run through the application SCA analysis.
                    image_findings = [_image_inventory_finding(item, document, exposure) for item in items]
                    findings.extend(image_findings)
                    inputs_summary.append({"input": path.name, "route": "container-image",
                                           "records": len(items)})
                    diagnostics.append(f"container-image: {len(items)} installed-package finding(s) "
                                       "recorded as present in the image, not analysed for use by the application")
                    continue
                sca_inputs.append((path.name, items))
                inputs_summary.append({"input": path.name, "route": "sca", "records": len(items)})
                continue
        except ModelError as exc:
            diagnostics.append(f"skipped {path.name}: {exc}")
            inputs_summary.append({"input": path.name, "route": "skipped"})
            continue
        diagnostics.append(f"skipped {path.name}: no registered adapter or SCA format recognises it")
        inputs_summary.append({"input": path.name, "route": "skipped"})

    if not any(item["route"] != "skipped" for item in inputs_summary):
        raise ModelError("no scanner report could be used: " + "; ".join(diagnostics))

    for finding in findings:
        finding["exploitability_context"]["exposure"] = exposure
    if deployment is not None:
        deployment_context.apply_exposure(findings, deployment, project_dir.resolve())
    if sca_inputs:
        sca_results = _run_sca(sca_inputs, project_dir.resolve(), output_dir, exposure=exposure,
                               offline=offline, rules_dir=rules_dir, diagnostics=diagnostics)
        for finding in sca_results:
            # Use of the package is a separate dimension. It is checked in the project's source, and it does not
            # change the verdict the dependency pipeline gave.
            dependency_info = finding["original"].get("dependency") or {}
            usage = dependency_usage.find(project_dir.resolve(), dependency_info.get("ecosystem", ""),
                                          dependency_info.get("name", ""))
            finding["assessment"]["dimensions"] = dependency.dimensions(
                presence="project", version=None, usage=usage, verdict=finding["assessment"]["verdict"])
        findings.extend(sca_results)
        adapters_used.append("sca-pipeline")

    for finding in findings:
        finding["weakness"] = weakness.classify(finding)
    unassessed = [f for f in findings if "assessment" not in f]
    # One shared analysis per run, built only when a finding needs it. Every finding reuses it.
    application = None
    attack_surface = []
    if any(f["category"] == "SAST" for f in unassessed):
        application = Application(project_dir.resolve())
        attack_surface = [{"route": e["route"], "file": e["file"], "line": e["line"]}
                          for e in application.entries()]
    assessed = universal.assess_all(unassessed, registry, {"project_dir": project_dir.resolve(),
                                                           "exposure": exposure,
                                                           "application": application,
                                                           "deployment": deployment})
    assessed = [f for f in findings if "assessment" in f] + assessed
    assessed = [guidance.enrich(f) for f in _merge_duplicates(assessed)]
    if intel is not None:
        assessed = [intel_snapshot.enrich(f, intel) for f in assessed]
    limitations = sorted({item for finding in assessed for item in finding["assessment"]["limitations"]})
    summary = {
        "inputs": inputs_summary,
        "findings": len(assessed),
        "verdicts": _count_verdicts(assessed),
        "categories": sorted({f["category"] for f in assessed}),
        "exposure": exposure,
        "adapters": adapters_used,
        "engines": registry.engines(),
        "diagnostics": diagnostics,
        "limitations": limitations,
    }
    gated = [f["id"] for f in assessed if f["assessment"]["verdict"] in GATE_VERDICTS[fail_on]]
    summary["gate"] = {"fail_on": fail_on, "failed": bool(gated), "failing_findings": gated}
    summary["attack_paths"] = [
        {"finding": f["id"], "rule": f["vulnerability"]["rule_id"], "verdict": f["assessment"]["verdict"],
         "hops": f["assessment"]["attack_path"]}
        for f in assessed if f["assessment"].get("attack_path")]
    if application is not None:
        summary["application"] = application.search_summary()
        summary["attack_surface"] = attack_surface
    graph = evidence_graph.correlate(assessed, deployment or deployment_context.repository_only())
    summary["deployment_context"] = "provided" if deployment is not None else "repository-only"
    summary["evidence_graph"] = {
        "nodes": len(graph.nodes), "edges": len(graph.edges),
        "attack_paths": evidence_graph.attack_paths(graph),
        "not_correlated": list(evidence_graph.NOT_CORRELATED),
    }
    universal_report.write_outputs(output_dir, assessed, summary, TOOL_VERSION, diagnostics)
    (output_dir / "evidence-graph.json").write_text(json.dumps(
        {"nodes": list(graph.nodes.values()), "edges": graph.edges,
         "attack_paths": summary["evidence_graph"]["attack_paths"],
         "not_correlated": summary["evidence_graph"]["not_correlated"]}, indent=2) + "\n", encoding="utf-8")
    report_pdf.build(assessed, summary, TOOL_VERSION, output_dir / "universal-report.pdf")
    return summary


def _load_intel(directory: Path | None, key_path: Path | None):
    """The verified intel snapshot, or None when no directory was given. A snapshot that fails verification is refused
    by the caller, not silently skipped."""
    if directory is None:
        return None
    if key_path is None:
        raise updates.UpdateError("--intel-dir needs --intel-key, the pinned publisher key")
    key = updates.load_publisher_key(key_path)
    return intel_snapshot.load(directory / "installed", directory / "state", key)


def _read_context(path: Path | None) -> dict | None:
    """The context document, or None when no context file was given. An unreadable file is refused by the caller."""
    return json.loads(path.read_text(encoding="utf-8")) if path else None


def _optional_path(value: str) -> Path | None:
    # Action inputs arrive as empty strings when unset; an empty path means "the shipped rules".
    return Path(value) if value else None


def _bool(value: str) -> bool:
    # Action inputs arrive as strings, and a Docker action's arguments are fixed, so the flag is a value.
    if value.lower() in {"true", "1", "yes"}:
        return True
    if value.lower() in {"false", "0", "no", ""}:
        return False
    raise argparse.ArgumentTypeError(f"expected true or false, got {value!r}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="engine.universal_run",
                                     description="Assess scanner reports with the universal engine.")
    parser.add_argument("--input", type=Path, action="append", default=[],
                        help="Scanner report. Repeat for several reports in one run.")
    parser.add_argument("--inputs", default="",
                        help="Comma- or newline-separated list of scanner reports (for the action).")
    parser.add_argument("--max-report-bytes", type=int, default=MAX_REPORT_BYTES)
    parser.add_argument("--max-records", type=int, default=MAX_RECORDS)
    parser.add_argument("--timeout-seconds", type=int, default=DEFAULT_TIMEOUT_SECONDS,
                        help="Wall-clock limit for the whole run; 0 disables it.")
    parser.add_argument("--project-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("universal-report"))
    parser.add_argument("--exposure", choices=EXPOSURES, default="unknown")
    parser.add_argument("--fail-on", choices=sorted(GATE_VERDICTS), default="confirmed_exploitable",
                        help="Verdicts that make the run exit 1")
    parser.add_argument("--adapter", default=None,
                        help="Adapter name, for input that detection cannot tell apart (e.g. empty output)")
    parser.add_argument("--rules-dir", type=_optional_path, default=None,
                        help="Curated SCA rules directory")
    parser.add_argument("--offline", type=_bool, default=False,
                        help="true to skip advisory and intelligence lookups for the SCA path")
    parser.add_argument("--input-dir", type=Path, action="append", default=[],
                        help="Directory of scanner reports (.sarif and .json), searched recursively. Repeatable.")
    parser.add_argument("--plugin", type=Path, action="append", default=[],
                        help="Python file with register(registry) that adds an adapter or engine. Repeatable.")
    parser.add_argument("--allow-dirty", type=_bool, default=False,
                        help="true to analyse a project whose working tree has uncommitted changes")
    parser.add_argument("--allow-commit-mismatch", type=_bool, default=False,
                        help="true to analyse reports generated from a commit other than the project's HEAD")
    parser.add_argument("--intel-dir", type=_optional_path, default=None,
                        help="a directory with installed/ and state/ from the signed-update installer: KEV and EPSS "
                             "signals are added to findings with a CVE")
    parser.add_argument("--intel-key", type=Path, default=None,
                        help="the pinned publisher public key (Ed25519 PEM) that signs the intel snapshot")
    parser.add_argument("--context", type=_optional_path, default=None,
                        help="a sawone-context-1 JSON document: deployment, runtime and exposure evidence")
    parser.add_argument("--code-scanning-repo", default="",
                        help="owner/name whose open Code Scanning alerts are assessed (no scanner runs)")
    parser.add_argument("--code-scanning-ref", default="",
                        help="Git ref of the alerts, e.g. refs/heads/main. Needs --code-scanning-repo.")
    args = parser.parse_args(argv)
    if args.rules_dir is None:
        args.rules_dir = DEFAULT_RULES
    listed = [Path(item.strip()) for item in args.inputs.replace(",", "\n").splitlines() if item.strip()]
    inputs = list(args.input) + listed
    for directory in args.input_dir:
        if not directory.is_dir():
            parser.error(f"--input-dir is not a directory: {directory}")
        found = sorted(p for p in directory.rglob("*")
                       if p.is_file() and p.suffix.lower() in REPORT_SUFFIXES
                       and not any(part.startswith(".") for part in p.relative_to(directory).parts))
        print(f"input directory {directory}: {len(found)} report(s)")
        inputs += found
    if args.code_scanning_repo:
        if not args.code_scanning_ref:
            parser.error("--code-scanning-ref is needed with --code-scanning-repo")
        try:
            alerts = code_scanning.fetch_alerts(args.code_scanning_repo, args.code_scanning_ref,
                                                os.environ.get("GITHUB_TOKEN", ""))
        except ModelError as exc:
            print(f"rejected: {exc}", file=sys.stderr)
            return 2
        inputs += code_scanning.write_alert_reports(alerts, args.output_dir / "code-scanning")
        print(f"code scanning: {len(alerts)} open alert(s) on {args.code_scanning_ref}")
    if not inputs:
        parser.error("give at least one --input, --inputs or --code-scanning-repo")
    try:
        commit_diagnostics, inputs = provenance.check_reports(
            inputs, args.project_dir, allow_mismatch=args.allow_commit_mismatch)
        commit_diagnostics.append(provenance.check_clean(args.project_dir, allow_dirty=args.allow_dirty))
        plugin_registry = build_registry()
        for plugin in args.plugin:
            commit_diagnostics.append(load_plugin(plugin, plugin_registry))
    except ModelError as exc:
        print(f"rejected: {exc}", file=sys.stderr)
        return 2
    for line in commit_diagnostics:
        print(line)

    def on_timeout(signum, frame):
        raise TimeoutError(f"the run exceeded {args.timeout_seconds} seconds")

    if args.timeout_seconds > 0 and hasattr(signal, "SIGALRM"):
        signal.signal(signal.SIGALRM, on_timeout)
        signal.alarm(args.timeout_seconds)
    try:
        intel = _load_intel(args.intel_dir, args.intel_key)
    except (OSError, updates.UpdateError) as exc:
        print(f"rejected: the intel snapshot could not be verified ({exc})", file=sys.stderr)
        return 2
    try:
        context_document = _read_context(args.context)
    except (OSError, ValueError) as exc:
        print(f"rejected: the context file is not readable JSON ({type(exc).__name__})", file=sys.stderr)
        return 2
    try:
        summary = run(inputs, args.project_dir, args.output_dir, exposure=args.exposure,
                      adapter_name=args.adapter, fail_on=args.fail_on, offline=args.offline,
                      rules_dir=args.rules_dir, max_report_bytes=args.max_report_bytes,
                      max_records=args.max_records, registry=plugin_registry,
                      context_document=context_document, intel=intel)
    except ModelError as exc:
        print(f"rejected: {exc}", file=sys.stderr)
        return 2
    except TimeoutError as exc:
        print(f"timed out: {exc}", file=sys.stderr)
        return EXIT_TIMEOUT
    finally:
        if hasattr(signal, "SIGALRM"):
            signal.alarm(0)

    markdown = (args.output_dir / "universal-report.md").read_text(encoding="utf-8")
    report.append_job_summary(markdown)
    print(f"findings: {summary['findings']}  verdicts: {summary['verdicts']}")
    print(f"gate ({args.fail_on}): {'FAILED' if summary['gate']['failed'] else 'passed'}")
    return 1 if summary["gate"]["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
