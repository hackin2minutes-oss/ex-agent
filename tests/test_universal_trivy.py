"""Trivy `config` adapter, on real Trivy output for the IaC and Dockerfile fixtures, plus targeted cases.

`tests/fixtures/iac/trivy-config-0.real.json` and `tests/fixtures/container/trivy-config-dockerfile.real.json`
are `trivy config --format json` output from Trivy (built from source, misconfiguration checks bundled)
on copies of the IaC and container fixture projects. Trivy's vulnerability scan needs a database download
that this environment cannot reach, so only configuration output is tested here.
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from engine import universal, universal_run
from engine.checkov_adapter import CheckovAdapter
from engine.semgrep_adapter import SemgrepAdapter
from engine.trivy_config_adapter import TrivyConfigAdapter
from engine.universal import ModelError, POTENTIALLY_EXPLOITABLE, UNKNOWN

FIXTURES = Path(__file__).resolve().parent / "fixtures"
IAC_REAL = FIXTURES / "iac" / "trivy-config-0.real.json"
IAC_PROJECT = FIXTURES / "iac" / "project"
DOCKER_REAL = FIXTURES / "container" / "trivy-config-dockerfile.real.json"
DOCKER_PROJECT = FIXTURES / "container" / "project"


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def assess(document, project_dir, exposure="unknown"):
    registry = universal_run.build_registry()
    findings, _ = TrivyConfigAdapter().parse(document, {"target": "test"})
    for finding in findings:
        finding["exploitability_context"]["exposure"] = exposure
    return universal.assess_all(findings, registry,
                                {"project_dir": Path(project_dir), "exposure": exposure})


def by_rule_and_line(assessed):
    return {(f["vulnerability"]["rule_id"], f["location"] and f["location"]["start_line"]):
            f["assessment"] for f in assessed}


class RealTrivyIacTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.by_key = by_rule_and_line(assess(load(IAC_REAL), IAC_PROJECT))

    def test_all_misconfigurations_are_read_as_iac(self):
        self.assertEqual(len(self.by_key), 14)

    def test_open_ssh_ingress_is_potentially_exploitable(self):
        assessment = self.by_key[("AVD-AWS-0107", 8)]
        self.assertEqual(assessment["verdict"], POTENTIALLY_EXPLOITABLE)
        self.assertIn("0.0.0.0/0", assessment["evidence"][0]["detail"] + assessment["evidence"][1]["detail"])

    def test_public_word_without_ingress_is_unknown(self):
        # "block public ACL" mentions public access, but the block has no ingress rule.
        self.assertEqual(self.by_key[("AVD-AWS-0086", 23)]["verdict"], UNKNOWN)

    def test_no_trivy_result_is_confirmed_or_not_exploitable(self):
        for assessment in self.by_key.values():
            self.assertNotIn(assessment["verdict"], ("CONFIRMED_EXPLOITABLE", "NOT_EXPLOITABLE"))


class RealTrivyDockerfileTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.by_key = by_rule_and_line(assess(load(DOCKER_REAL), DOCKER_PROJECT))

    def test_dockerfile_results_are_container_findings(self):
        findings, _ = TrivyConfigAdapter().parse(load(DOCKER_REAL), {"target": "t"})
        self.assertTrue(all(f["category"] == "CONTAINER" for f in findings))
        self.assertTrue(all(f["asset"]["type"] == "container_image" for f in findings))

    def test_declared_ssh_port_is_potentially_exploitable(self):
        self.assertEqual(self.by_key[("DS004", 7)]["verdict"], POTENTIALLY_EXPLOITABLE)

    def test_result_without_a_line_is_unknown_with_no_location(self):
        assessment = self.by_key[("DS002", None)]
        self.assertEqual(assessment["verdict"], UNKNOWN)
        self.assertIn("no source location", assessment["reason"])


class TrivyEditedCaseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.project = self.tmp / "project"
        shutil.copytree(IAC_PROJECT, self.project)

    def test_changed_security_group_makes_the_result_stale(self):
        main = self.project / "main.tf"
        main.write_text(main.read_text(encoding="utf-8").replace(
            'cidr_blocks = ["0.0.0.0/0"]', 'cidr_blocks = ["10.1.0.0/16"]', 1), encoding="utf-8")
        assessment = by_rule_and_line(assess(load(IAC_REAL), self.project))[("AVD-AWS-0107", 8)]
        self.assertEqual(assessment["verdict"], UNKNOWN)
        self.assertIn("stale", assessment["reason"])

    def test_path_leaving_the_project_is_refused(self):
        document = load(IAC_REAL)
        document["Results"][1]["Target"] = "../outside.tf"
        assessed = by_rule_and_line(assess(document, self.project))
        self.assertEqual(assessed[("AVD-AWS-0107", 8)]["verdict"], UNKNOWN)
        self.assertIn("leaves the project", assessed[("AVD-AWS-0107", 8)]["reason"])


class TrivyAdapterTest(unittest.TestCase):
    def test_vulnerability_records_are_counted_not_read(self):
        document = load(IAC_REAL)
        document["Results"][1]["Vulnerabilities"] = [{"VulnerabilityID": "CVE-2026-0001"}]
        _, diagnostics = TrivyConfigAdapter().parse(document, {"target": "t"})
        self.assertTrue(any("vulnerability record" in d and "not read" in d for d in diagnostics))

    def test_misconfiguration_without_id_is_rejected(self):
        document = load(IAC_REAL)
        del document["Results"][1]["Misconfigurations"][0]["ID"]
        with self.assertRaises(ModelError):
            TrivyConfigAdapter().parse(document, {"target": "t"})

    def test_detection_does_not_claim_other_formats(self):
        self.assertTrue(TrivyConfigAdapter().detect(load(IAC_REAL)))
        self.assertFalse(TrivyConfigAdapter().detect({"SchemaVersion": 2, "Results": [{"Target": "x", "Vulnerabilities": []}]}))
        self.assertFalse(TrivyConfigAdapter().detect(json.loads(
            (FIXTURES / "iac" / "checkov-3.4.0.real.json").read_text(encoding="utf-8"))))
        self.assertFalse(CheckovAdapter().detect(load(IAC_REAL)))
        self.assertFalse(SemgrepAdapter().detect(load(IAC_REAL)))


if __name__ == "__main__":
    unittest.main()
