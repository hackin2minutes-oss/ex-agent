import argparse
import os
import sys
from pathlib import Path

from engine import pipeline, report

FAIL_ON_CHOICES = ["confirmed_reachable", "confirmed_exploitable"]


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
    parser.add_argument("--rules-dir", type=Path, default=Path("rules"))
    parser.add_argument("--output-dir", type=Path, default=Path("exploitability-report"))
    parser.add_argument("--fail-on", choices=FAIL_ON_CHOICES, default="confirmed_reachable")
    parser.add_argument("--offline", type=_bool, default=False,
                        help="true to skip all network intelligence lookups")
    parser.add_argument("--cache-dir", type=_optional_path, default=None)
    parser.add_argument("--fix-diffs-dir", type=_optional_path, default=None,
                        help="Directory of <commit-sha>.diff files, used before fetching from GitHub")
    parser.add_argument("--codeql", default=None, help="Path to the CodeQL CLI (default: PATH lookup)")
    parser.add_argument("--build-command", default=None, help="Build command for the CodeQL database")
    parser.add_argument("--no-comment", action="store_true", help="Do not post a pull request comment")
    args = parser.parse_args(argv)

    summary = pipeline.run(
        args.project_dir, args.deps, args.rules_dir, args.output_dir, args.fail_on,
        offline=args.offline, cache_dir=args.cache_dir, fix_diffs_dir=args.fix_diffs_dir,
        codeql_path=args.codeql or None, build_command=args.build_command or None,
    )

    markdown = (args.output_dir / "report.md").read_text(encoding="utf-8")
    report.append_job_summary(markdown)
    if not args.no_comment and os.environ.get("GITHUB_TOKEN"):
        number = report.pr_number_if_postable()
        if number is not None:
            report.post_pr_comment(markdown, number)

    print(f"findings: {summary['findings']}  verdicts: {summary['verdicts']}")
    print(f"analysis mode: {summary['analysis_mode']}")
    print(f"gate ({args.fail_on}): {'FAILED' if summary['gate_failed'] else 'passed'}")
    return 1 if summary["gate_failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
