"""Check the shape and content of an exploitability report. CI uses it to verify the action.

Usage: verify_report.py REPORT_DIR --mode {codeql,text_scan} --expect-call-site
"""

import argparse
import json
import sys
from pathlib import Path



def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report_dir", type=Path)
    parser.add_argument("--mode", required=True, choices=["codeql", "text_scan"])
    parser.add_argument("--expect-call-site", action="store_true")
    parser.add_argument("--expect-taint", choices=["confirmed", "not_found", "not_analysed"])
    parser.add_argument("--expect-classification", required=True)
    parser.add_argument("--expect-cve", default=None)
    args = parser.parse_args(argv)

    errors: list[str] = []
    report = args.report_dir

    for name in ["summary.json", "evidence.json", "findings.sarif", "call-graph.json", "report.md"]:
        if not (report / name).is_file():
            errors.append(f"missing {name}")
    if errors:
        for error in errors:
            print(f"::error title=Report verification::{error}")
        return 1

    summary = json.loads((report / "summary.json").read_text())
    findings = json.loads((report / "evidence.json").read_text())["findings"]
    sarif = json.loads((report / "findings.sarif").read_text())

    if summary["analysis_mode"] != args.mode:
        errors.append(f"analysis_mode is {summary['analysis_mode']}, expected {args.mode}")
    if summary["findings"] != 1 or len(findings) != 1:
        errors.append(f"expected 1 finding, got {summary['findings']}")
    if summary["gate_failed"]:
        errors.append("gate failed")

    for finding in findings:
        if finding["classification"] != args.expect_classification:
            errors.append(f"classification is {finding['classification']}, expected {args.expect_classification}")
        if args.expect_cve and finding["vulnerability"]["cve"] != args.expect_cve:
            errors.append(f"finding is {finding['vulnerability']['cve']}, expected {args.expect_cve}")
        call = next(e for e in finding["evidence"] if e["type"] == "call_site")
        if args.expect_call_site and not call["locations"]:
            errors.append("no call site found")
        taint = next(e for e in finding["evidence"] if e["type"] == "taint_path")
        if args.expect_taint and taint["result"] != args.expect_taint:
            errors.append(f"taint_path is {taint['result']}, expected {args.expect_taint}")
        print(f"::notice title=Finding::taint_path={taint['result']} "
              f"reachability={finding['reachability']} verdict={finding['verdict']} "
              f"analysis_mode={summary['analysis_mode']}")

    if sarif.get("version") != "2.1.0":
        errors.append("SARIF version is not 2.1.0")
    if len(sarif["runs"][0]["results"]) != len(findings):
        errors.append("SARIF result count does not match findings")

    for finding in findings:
        for limitation in finding["scope"]["limitations"]:
            if limitation.startswith("CodeQL failed") or "CodeQL" in limitation and "fallback" in limitation:
                print(f"::notice title=Finding engine note::{limitation}")
    for note in summary.get("notes", []):
        print(f"::notice title=Engine note::{note}")
    for source, status in summary.get("intel", {}).items():
        print(f"::notice title=Intel {source}::{status}")
    if errors:
        for error in errors:
            print(f"::error title=Report verification::{error}")
        print("FAILED:\n- " + "\n- ".join(errors))
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
