"""Threat-model ingestion: every threat kept, identity preserved, threats treated as design evidence and never as
confirmed vulnerabilities.

The synthetic fixture has the same shape as a SAWONE threat-model report. The real 58-threat MyStore report is not
in this repository, because it describes a private system. Set SAWONE_MYSTORE_THREAT_MODEL to its path to run the
full-report test against it.
"""

import copy
import json
import os
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from engine import universal_run
from engine.threat_model import ThreatModelAdapter, ThreatModelEngine
from engine.universal import ModelError, assess_finding

FIXTURE = Path(__file__).parent / "fixtures" / "threat-model" / "synthetic-threat-model.json"
REAL = os.environ.get("SAWONE_MYSTORE_THREAT_MODEL", "")


def load(path: Path = FIXTURE) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def registry():
    return universal_run.build_registry()


class IngestTest(unittest.TestCase):
    def test_the_adapter_recognises_a_threat_model_report_and_nothing_else(self):
        adapter = ThreatModelAdapter()
        self.assertTrue(adapter.detect(load()))
        self.assertFalse(adapter.detect({"runs": []}))
        self.assertFalse(adapter.detect({"threats": []}))

    def test_every_threat_becomes_one_finding_in_order(self):
        findings, _ = ThreatModelAdapter().parse(load(), {"target": "model.json"})
        self.assertEqual(len(findings), 3)
        self.assertEqual({f["category"] for f in findings}, {"THREAT_MODEL"})
        self.assertEqual([f["vulnerability"]["rule_id"] for f in findings], ["INP05", "AC01", "AC01"])

    def test_two_threats_sharing_a_sid_keep_distinct_identities(self):
        findings, _ = ThreatModelAdapter().parse(load(), {"target": "model.json"})
        self.assertEqual(len({f["id"] for f in findings}), 3)

    def test_the_original_threat_is_kept_verbatim(self):
        document = load()
        findings, _ = ThreatModelAdapter().parse(document, {"target": "model.json"})
        self.assertEqual([f["original"] for f in findings], document["threats"])

    def test_the_fields_the_engine_reads_are_copied_and_the_document_context_is_kept(self):
        findings, _ = ThreatModelAdapter().parse(load(), {"target": "model.json"})
        detail = findings[2]["derived"]["threat_model"]
        self.assertEqual(detail["status"], "in-code")
        self.assertEqual(detail["evidence_total"], 1)
        self.assertEqual(detail["decision"]["state"], "accepted")
        self.assertEqual(findings[0]["derived"]["model"]["dfd"], load()["dfd"])

    def test_a_pytm_severity_label_is_mapped_and_the_reported_label_is_kept(self):
        findings, _ = ThreatModelAdapter().parse(load(), {"target": "model.json"})
        self.assertEqual(findings[0]["severity"]["reported"], "Very High")
        self.assertEqual(findings[0]["severity"]["normalised"], "high")
        self.assertEqual(findings[2]["severity"]["normalised"], "low")

    def test_a_report_whose_declared_total_differs_from_its_threats_is_refused(self):
        document = load()
        document["total"] = 58
        with self.assertRaises(ModelError):
            ThreatModelAdapter().parse(document, {"target": "model.json"})

    def test_a_threat_without_a_sid_or_target_is_refused(self):
        document = load()
        del document["threats"][0]["sid"]
        with self.assertRaises(ModelError):
            ThreatModelAdapter().parse(document, {"target": "model.json"})
        document = load()
        document["threats"][1]["target"] = ""
        with self.assertRaises(ModelError):
            ThreatModelAdapter().parse(document, {"target": "model.json"})

    def test_a_report_with_no_declared_commit_says_so(self):
        findings, diagnostics = ThreatModelAdapter().parse(load(), {"target": "model.json"})
        self.assertIsNone(findings[0]["provenance"]["source_commit"])
        self.assertTrue(any("declares no source commit" in line for line in diagnostics))


class EngineTest(unittest.TestCase):
    def test_no_threat_is_ever_a_confirmed_verdict(self):
        findings, _ = ThreatModelAdapter().parse(load(), {"target": "model.json"})
        for finding in findings:
            finding["exploitability_context"]["exposure"] = "internet"
            assessment = assess_finding(finding, registry(), {"project_dir": Path(".")})
            self.assertEqual(assessment["verdict"], "UNKNOWN")
            self.assertNotIn("CONFIRMED_EXPLOITABLE", assessment["verdict"])

    def test_the_reason_says_the_threat_is_design_evidence(self):
        findings, _ = ThreatModelAdapter().parse(load(), {"target": "model.json"})
        assessment = ThreatModelEngine().assess(findings[0], {})
        self.assertIn("not a confirmed vulnerability", assessment.reason)
        self.assertIn("a threat is not exploitable because it appears in the threat model", assessment.limitations)

    def test_an_in_code_threat_with_evidence_is_still_not_confirmed(self):
        findings, _ = ThreatModelAdapter().parse(load(), {"target": "model.json"})
        assessment = ThreatModelEngine().assess(findings[2], {})
        self.assertEqual(assessment.verdict, "UNKNOWN")
        self.assertIn("1 evidence item(s) recorded", assessment.evidence[0]["detail"])


class RunTest(unittest.TestCase):
    def test_the_synthetic_report_runs_end_to_end_and_every_threat_is_unknown(self):
        project = Path(tempfile.mkdtemp())
        with tempfile.TemporaryDirectory() as out:
            summary = universal_run.run([FIXTURE], project, Path(out))
        self.assertEqual(summary["verdicts"]["UNKNOWN"], 3)
        self.assertEqual(summary["verdicts"]["CONFIRMED_EXPLOITABLE"], 0)
        self.assertIn("THREAT_MODEL", summary["categories"])
        self.assertIn("threat-model", summary["adapters"])


@unittest.skipUnless(REAL and Path(REAL).is_file(),
                     "set SAWONE_MYSTORE_THREAT_MODEL to the 58-threat report to run this")
class FullMyStoreReportTest(unittest.TestCase):
    def test_all_58_threats_are_ingested_and_none_is_confirmed(self):
        document = json.loads(Path(REAL).read_text(encoding="utf-8"))
        findings, diagnostics = ThreatModelAdapter().parse(document, {"target": Path(REAL).name})
        self.assertEqual(len(findings), 58)
        self.assertEqual(len(findings), document["total"])
        by_stride = Counter(f["derived"]["threat_model"]["stride"] for f in findings)
        self.assertEqual(dict(by_stride), document["by_stride"])
        self.assertEqual({f["original"]["sid"] for f in findings}, {t["sid"] for t in document["threats"]})
        for finding in findings:
            self.assertEqual(finding["category"], "THREAT_MODEL")
            self.assertEqual(assess_finding(copy.deepcopy(finding), registry(),
                                            {"project_dir": Path(".")})["verdict"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
