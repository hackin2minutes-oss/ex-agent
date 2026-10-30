"""Run the evaluation corpus through the universal runner and measure it against ground truth.

Each case directory holds an application (app/), a Semgrep report of it (semgrep.json) and case.json:
    {"description", "exposure", "truth": 1 | 0 | null, "expected_verdict"}
truth 1: the weakness is exploitable in the case. truth 0: it is not. truth null: ground truth is not
decidable from the case (an external caller, or unparseable code), so the case is excluded from precision and recall.

A flagged verdict is CONFIRMED_EXPLOITABLE or POTENTIALLY_EXPLOITABLE. A decided verdict is any verdict other than
UNKNOWN and ANALYSIS_INCOMPLETE. Undecided results are counted separately and are never counted as safe.

Run: python3 tests/eval/evaluate.py [--write]
"""

import argparse
import json
import shutil
import tempfile
import time
from collections import Counter
from pathlib import Path

from engine import universal_run

CORPUS = Path(__file__).resolve().parent / "corpus"
RESULTS = Path(__file__).resolve().parent / "results.json"
FLAGGED = {"CONFIRMED_EXPLOITABLE", "POTENTIALLY_EXPLOITABLE"}
UNDECIDED = {"UNKNOWN", "ANALYSIS_INCOMPLETE"}


def run_case(case_dir: Path, out: Path, report: str = "semgrep.json") -> dict:
    case = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
    started = time.perf_counter()
    summary = universal_run.run([case_dir / report], case_dir, out, exposure=case["exposure"],
                                offline=True)
    elapsed = time.perf_counter() - started
    findings = json.loads((out / "universal-findings.json").read_text(encoding="utf-8"))["findings"]
    verdicts = [f["assessment"]["verdict"] for f in findings]
    return {"case": case_dir.name, "truth": case["truth"], "expected": case["expected_verdict"],
            "verdicts": verdicts, "seconds": round(elapsed, 4), "application": summary.get("application")}


def measure(results: list[dict]) -> dict:
    tp = fp = tn = fn = 0
    undecided_truth1 = undecided_truth0 = 0
    distribution: Counter = Counter()
    coverage_decided = 0
    for result in results:
        if not result["verdicts"]:
            continue
        verdict = result["verdicts"][0]
        distribution[verdict] += 1
        decided = verdict not in UNDECIDED
        coverage_decided += decided
        if result["truth"] is None:
            continue
        flagged = verdict in FLAGGED
        if result["truth"] == 1:
            if flagged:
                tp += 1
            elif decided:
                fn += 1
            else:
                undecided_truth1 += 1
        else:
            if flagged:
                fp += 1
            elif decided:
                tn += 1
            else:
                undecided_truth0 += 1
    scored = tp + fp + tn + fn
    cases = len(results)

    def ratio(a, b):
        return round(a / b, 3) if b else None

    return {
        "cases": cases,
        "scored_cases": scored,
        "true_positive": tp, "false_positive": fp, "true_negative": tn, "false_negative": fn,
        "undecided_exploitable": undecided_truth1, "undecided_not_exploitable": undecided_truth0,
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn + undecided_truth1),
        "recall_decided_only": ratio(tp, tp + fn),
        "false_positive_rate": ratio(fp, fp + tn),
        "false_negative_rate": ratio(fn, tp + fn),
        "verdict_distribution": dict(sorted(distribution.items())),
        "decided_coverage": ratio(coverage_decided, sum(1 for r in results if r["verdicts"])),
        "total_seconds": round(sum(r["seconds"] for r in results), 3),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="write tests/eval/results.json")
    args = parser.parse_args()
    results = []
    scratch = Path(tempfile.mkdtemp())
    try:
        for case_dir in sorted(p for p in CORPUS.iterdir() if p.is_dir()):
            results.append(run_case(case_dir, scratch / case_dir.name))
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    metrics = measure(results)
    # Source independence: the same applications, reported as SARIF instead of Semgrep JSON. The engine must not
    # change its verdicts when only the input format changes.
    sarif_results = []
    scratch = Path(tempfile.mkdtemp())
    try:
        for case_dir in sorted(p for p in CORPUS.iterdir() if p.is_dir() and (p / "semgrep.sarif").exists()):
            sarif_results.append(run_case(case_dir, scratch / case_dir.name, "semgrep.sarif"))
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    by_name = {r["case"]: r for r in results}
    agree = [r["case"] for r in sarif_results if r["verdicts"] == by_name[r["case"]]["verdicts"]]
    metrics["source_agreement"] = {"compared": len(sarif_results), "identical_verdicts": len(agree),
                                   "disagreements": [r["case"] for r in sarif_results if r["case"] not in agree]}
    report = {"metrics": metrics, "cases": results}
    print(json.dumps(metrics, indent=2))
    mismatches = [r for r in results if r["verdicts"] and r["verdicts"][0] != r["expected"]]
    print(f"expected-verdict mismatches: {len(mismatches)}")
    for r in mismatches:
        print(f"  {r['case']}: expected {r['expected']}, got {r['verdicts']}")
    if args.write:
        RESULTS.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
