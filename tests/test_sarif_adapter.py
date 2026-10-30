"""Generic SARIF adapter, and source independence: the same corpus reported as SARIF gets the same verdicts."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from engine import universal_run
from engine.sarif_adapter import SarifAdapter
from engine.universal import ModelError

CORPUS = Path(__file__).resolve().parent / "eval" / "corpus"
CASE = CORPUS / "01_route_request_concat_internet"
SARIF = json.loads((CASE / "semgrep.sarif").read_text(encoding="utf-8"))


def minimal(result_overrides=None, locations=True):
    result = {"ruleId": "r.rule", "message": {"text": "m"}, "level": "warning"}
    if locations:
        result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": "app/views.py"},
                                                     "region": {"startLine": 16, "startColumn": 5,
                                                                "endLine": 16, "endColumn": 23}}}]
    result.update(result_overrides or {})
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Tool", "version": "1"}},
                                          "results": [result]}]}


class SarifAdapterTest(unittest.TestCase):
    def test_detects_sarif_and_not_other_formats(self):
        self.assertTrue(SarifAdapter().detect(SARIF))
        self.assertFalse(SarifAdapter().detect({"results": [], "version": "1", "paths": {}}))

    def test_region_convention_is_one_based_with_exclusive_end_column(self):
        (finding,), _ = SarifAdapter().parse(minimal(), {"target": "t"})
        self.assertEqual(finding["location"]["start_col"], 5)
        self.assertEqual(finding["location"]["end_col"], 23)
        self.assertEqual(finding["provenance"]["scanner"], "Tool")

    def test_result_without_location_is_kept_and_unknown(self):
        document = minimal(locations=False)
        (finding,), diagnostics = SarifAdapter().parse(document, {"target": "t"})
        self.assertIsNone(finding["location"])
        self.assertTrue(any("no source location" in d for d in diagnostics))

    def test_malformed_result_is_refused_not_dropped(self):
        with self.assertRaises(ModelError):
            SarifAdapter().parse(minimal({"ruleId": None}), {"target": "t"})

    def test_original_result_is_kept_verbatim(self):
        (finding,), _ = SarifAdapter().parse(SARIF, {"target": "t"})
        self.assertEqual(finding["original"], SARIF["runs"][0]["results"][0])


class SourceIndependenceTest(unittest.TestCase):
    def test_every_corpus_case_gets_the_same_verdict_from_sarif_as_from_semgrep_json(self):
        scratch = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, scratch, ignore_errors=True)
        for case_dir in sorted(p for p in CORPUS.iterdir() if p.is_dir()):
            if not (case_dir / "semgrep.sarif").exists():
                continue
            with self.subTest(case=case_dir.name):
                out_json = scratch / f"{case_dir.name}-json"
                out_sarif = scratch / f"{case_dir.name}-sarif"
                universal_run.run([case_dir / "semgrep.json"], case_dir, out_json, exposure=json.loads(
                    (case_dir / "case.json").read_text(encoding="utf-8"))["exposure"], offline=True)
                universal_run.run([case_dir / "semgrep.sarif"], case_dir, out_sarif, exposure=json.loads(
                    (case_dir / "case.json").read_text(encoding="utf-8"))["exposure"], offline=True)
                verdicts_json = [f["assessment"]["verdict"] for f in json.loads(
                    (out_json / "universal-findings.json").read_text(encoding="utf-8"))["findings"]]
                verdicts_sarif = [f["assessment"]["verdict"] for f in json.loads(
                    (out_sarif / "universal-findings.json").read_text(encoding="utf-8"))["findings"]]
                self.assertEqual(verdicts_json, verdicts_sarif)


if __name__ == "__main__":
    unittest.main()
