import argparse
import os
import sys
from pathlib import Path

from engine import findings as scanner_findings, pipeline, report, updates

SHIPPED_RULES = Path(__file__).resolve().parent.parent / "rules"
FAIL_ON_CHOICES = ["confirmed_reachable", "confirmed_exploitable"]
EXPOSURE_CHOICES = ["internet", "internal", "unknown"]


def _optional_path(value: str) -> Path | None:
    # Action inputs arrive as empty strings when unset; an empty path must mean "not given".
    return Path(value) if value else None


def _bool(value: str) -> bool:
    if value.lower() in {"true", "1", "yes"}:
        return True
    if value.lower() in {"false", "0", "no", ""}:
        return False
    raise argparse.ArgumentTypeError(f"expected true or false, got {value!r}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="engine", description="Exploitability analysis")
    parser.add_argument("--project-dir", type=Path, required=True)
    parser.add_argument("--deps", type=_optional_path, default=None,
                        help="Resolved dependency file. Default: first known file in the project.")
    parser.add_argument("--rules-dir", type=_optional_path, default=None,
                        help="Curated rules. Empty or unset: the rules shipped with the engine.")
    parser.add_argument("--output-dir", type=Path, default=Path("exploitability-report"))
    parser.add_argument("--fail-on", choices=FAIL_ON_CHOICES, default="confirmed_reachable")
    parser.add_argument("--exposure", choices=EXPOSURE_CHOICES, default="unknown",
                        help="Declared exposure of the application. confirmed_exploitable needs 'internet'.")
    parser.add_argument("--offline", type=_bool, default=False,
                        help="true to skip all network intelligence lookups")
    parser.add_argument("--cache-dir", type=_optional_path, default=None)
    parser.add_argument("--fix-diffs-dir", type=_optional_path, default=None,
                        help="Directory of <commit-sha>.diff files, used before fetching from GitHub")
    parser.add_argument("--codeql", default=None, help="Path to the CodeQL CLI (default: PATH lookup)")
    parser.add_argument("--build-command", default=None, help="Build command for the CodeQL database")
    parser.add_argument("--policy", type=_optional_path, default=None,
                        help="Policy file (YAML). When given, it decides the gate instead of --fail-on.")
    parser.add_argument("--no-comment", action="store_true", help="Do not post a pull request comment")
    parser.add_argument("--findings", type=_optional_path, default=None,
                        help="Scanner export to analyse: Trivy JSON, Grype JSON or OSV-scanner JSON")
    parser.add_argument("--update-dir", type=_optional_path, default=None,
                        help="Signed update directory to verify and install before analysis")
    parser.add_argument("--update-key", type=_optional_path, default=None,
                        help="Pinned publisher key (Ed25519 PEM). Required with --update-dir.")
    parser.add_argument("--update-target", type=_optional_path,
                        default=Path(".exploitability-cache/updates/current"),
                        help="Where the installed update lives. Its rules/ directory is used for analysis.")
    args = parser.parse_args(argv)
    if args.rules_dir is None:
        args.rules_dir = SHIPPED_RULES

    imported = None
    if args.findings:
        detected = scanner_findings.detect(args.findings.read_text(encoding="utf-8"))
        if detected is None:
            parser.error("--findings: not a supported scanner export (Trivy JSON, Grype JSON, OSV-scanner JSON)")
        imported = scanner_findings.merge_findings(detected[1])
        print(f"imported {len(detected[1])} finding(s) from {detected[0]}, {len(imported)} after merging")

    rules_dir = args.rules_dir
    if args.update_dir is not None:
        if args.update_key is None:
            print("update rejected: --update-dir needs --update-key", file=sys.stderr)
            return 2
        state = args.update_target.parent
        try:
            installed = updates.install(args.update_dir, args.update_target, state,
                                        updates.load_publisher_key(args.update_key))
        except updates.UpdateError as exc:
            print(f"update rejected: {exc}", file=sys.stderr)
            return 2
        print(f"using update {installed['version']}")
        rules_dir = args.update_target / "rules"

    summary = pipeline.run(
        args.project_dir, args.deps, rules_dir, args.output_dir, args.fail_on,
        offline=args.offline, cache_dir=args.cache_dir, fix_diffs_dir=args.fix_diffs_dir,
        codeql_path=args.codeql or None, build_command=args.build_command or None,
        policy_path=args.policy, exposure=args.exposure, imported_findings=imported,
    )

    markdown = (args.output_dir / "report.md").read_text(encoding="utf-8")
    report.append_job_summary(markdown)
    if not args.no_comment and os.environ.get("GITHUB_TOKEN"):
        number = report.pr_number_if_postable()
        if number is not None:
            report.post_pr_comment(markdown, number)

    print(f"findings: {summary['findings']}  verdicts: {summary['verdicts']}")
    print(f"analysis mode: {summary['analysis_mode']}")
    gate_name = "policy" if args.policy else args.fail_on
    print(f"gate ({gate_name}): {'FAILED' if summary['gate_failed'] else 'passed'}")
    return 1 if summary["gate_failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
