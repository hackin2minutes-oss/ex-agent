"""Runs the universal path: scanner JSON in, assessed findings and reports out.

Separate from the SCA pipeline (engine/pipeline.py, engine/__main__.py), which is unchanged.
This entry point is `python -m engine.universal_run`. It takes Semgrep JSON today. Adding a
scanner means registering an adapter in `build_registry`, and adding a domain means
registering an engine there. Neither changes `run`.
"""

import argparse
import json
import sys
from pathlib import Path

from engine import report, universal, universal_report
from engine.checkov_adapter import CheckovAdapter
from engine.cicd import CicdEngine
from engine.container import ContainerEngine
from engine.gitleaks_adapter import GitleaksAdapter
from engine.hadolint_adapter import HadolintAdapter
from engine.iac import IacEngine
from engine.sast import SastEngine
from engine.secrets_engine import SecretsEngine
from engine.semgrep_adapter import SemgrepAdapter
from engine.trivy_config_adapter import TrivyConfigAdapter
from engine.universal import EXPOSURES, ModelError, Registry
from engine.zizmor_adapter import ZizmorAdapter

TOOL_VERSION = "0.1.0"
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
    registry.register_engine(SastEngine())
    registry.register_engine(IacEngine())
    registry.register_engine(CicdEngine())
    registry.register_engine(SecretsEngine())
    registry.register_engine(ContainerEngine())
    return registry


def _count_verdicts(assessed: list[dict]) -> dict:
    counts = {verdict: 0 for verdict in universal.VERDICTS}
    for finding in assessed:
        counts[finding["assessment"]["verdict"]] += 1
    return counts


def run(input_path: Path, project_dir: Path, output_dir: Path, *, exposure: str = "unknown",
        adapter_name: str | None = None, fail_on: str = "confirmed_exploitable",
        registry: Registry | None = None) -> dict:
    if fail_on not in GATE_VERDICTS:
        raise ModelError(f"unknown gate: {fail_on}")
    if exposure not in EXPOSURES:
        raise ModelError(f"unknown exposure: {exposure}")
    registry = registry or build_registry()
    try:
        document = json.loads(input_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ModelError(f"input is not readable JSON: {exc}") from exc

    if adapter_name:
        adapter = registry.adapter(adapter_name)
    else:
        adapter = registry.detect_adapter(document)
        if adapter is None:
            raise ModelError("no registered adapter recognises this input; pass --adapter")
    findings, diagnostics = adapter.parse(document, {"target": input_path.name})
    for finding in findings:
        finding["exploitability_context"]["exposure"] = exposure

    assessed = universal.assess_all(findings, registry, {"project_dir": project_dir.resolve(),
                                                         "exposure": exposure})
    limitations = sorted({item for finding in assessed
                          for item in finding["assessment"]["limitations"]})
    summary = {
        "findings": len(assessed),
        "verdicts": _count_verdicts(assessed),
        "categories": sorted({f["category"] for f in assessed}),
        "exposure": exposure,
        "adapters": [adapter.name],
        "engines": registry.engines(),
        "diagnostics": diagnostics,
        "limitations": limitations,
    }
    gated = [f["id"] for f in assessed if f["assessment"]["verdict"] in GATE_VERDICTS[fail_on]]
    summary["gate"] = {"fail_on": fail_on, "failed": bool(gated), "failing_findings": gated}
    universal_report.write_outputs(output_dir, assessed, summary, TOOL_VERSION, diagnostics)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="engine.universal_run",
                                     description="Assess scanner findings with the universal engine.")
    parser.add_argument("--input", type=Path, required=True, help="Scanner JSON output")
    parser.add_argument("--project-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("universal-report"))
    parser.add_argument("--exposure", choices=EXPOSURES, default="unknown")
    parser.add_argument("--fail-on", choices=sorted(GATE_VERDICTS), default="confirmed_exploitable",
                        help="Verdicts that make the run exit 1")
    parser.add_argument("--adapter", default=None,
                        help="Adapter name, for input that detection cannot tell apart (e.g. empty output)")
    args = parser.parse_args(argv)
    try:
        summary = run(args.input, args.project_dir, args.output_dir, exposure=args.exposure,
                      adapter_name=args.adapter, fail_on=args.fail_on)
    except ModelError as exc:
        print(f"rejected: {exc}", file=sys.stderr)
        return 2

    markdown = (args.output_dir / "universal-report.md").read_text(encoding="utf-8")
    report.append_job_summary(markdown)
    print(f"findings: {summary['findings']}  verdicts: {summary['verdicts']}")
    print(f"gate ({args.fail_on}): {'FAILED' if summary['gate']['failed'] else 'passed'}")
    return 1 if summary["gate"]["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
