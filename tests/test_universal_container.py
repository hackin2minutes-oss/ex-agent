"""Container engine (Dockerfile-only) on real Checkov dockerfile output, plus targeted cases.

`tests/fixtures/container/checkov-3.4.0-dockerfile.real.json` is `checkov -d . -o json` output from
Checkov 3.4.0 on `tests/fixtures/container/project`. Those findings are Dockerfile configuration.
They say nothing about image vulnerabilities, which need an image scanner.
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from engine import universal, universal_run
from engine.checkov_adapter import CheckovAdapter
from engine.universal import POTENTIALLY_EXPLOITABLE, UNKNOWN

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "container"
REAL = FIXTURES / "checkov-3.4.0-dockerfile.real.json"
PROJECT = FIXTURES / "project"


def load_real():
    return json.loads(REAL.read_text(encoding="utf-8"))


def assess_document(document, project_dir, exposure="unknown"):
    registry = universal_run.build_registry()
    findings, _ = CheckovAdapter().parse(document, {"target": "test"})
    for finding in findings:
        finding["exploitability_context"]["exposure"] = exposure
    return universal.assess_all(findings, registry,
                                {"project_dir": Path(project_dir), "exposure": exposure})


def by_rule(assessed):
    return {f["vulnerability"]["rule_id"]: f for f in assessed}


class RealDockerfileFixtureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.assessed = by_rule(assess_document(load_real(), PROJECT))

    def test_dockerfile_findings_are_container_category_with_image_asset(self):
        self.assertEqual(len(self.assessed), 3)
        for finding in self.assessed.values():
            self.assertEqual(finding["category"], "CONTAINER")
            self.assertEqual(finding["asset"]["type"], "container_image")

    def test_declared_ssh_port_is_potentially_exploitable(self):
        assessment = self.assessed["CKV_DOCKER_1"]["assessment"]
        self.assertEqual(assessment["verdict"], POTENTIALLY_EXPLOITABLE)
        self.assertIn("EXPOSE", assessment["evidence"][0]["detail"])

    def test_missing_healthcheck_and_user_are_unknown(self):
        for rule in ("CKV_DOCKER_2", "CKV_DOCKER_3"):
            assessment = self.assessed[rule]["assessment"]
            self.assertEqual(assessment["verdict"], UNKNOWN)
            self.assertIn("no image or runtime context", assessment["reason"])

    def test_no_container_result_is_confirmed_even_with_internet_exposure(self):
        for finding in assess_document(load_real(), PROJECT, exposure="internet"):
            self.assertNotEqual(finding["assessment"]["verdict"], "CONFIRMED_EXPLOITABLE")


class DockerfileEdgeCaseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.project = self.tmp / "project"
        shutil.copytree(PROJECT, self.project)

    def test_edited_expose_line_makes_the_scan_stale(self):
        dockerfile = self.project / "Dockerfile"
        dockerfile.write_text(dockerfile.read_text(encoding="utf-8").replace("EXPOSE 22", "EXPOSE 2222"),
                              encoding="utf-8")
        assessment = by_rule(assess_document(load_real(), self.project))["CKV_DOCKER_1"]["assessment"]
        self.assertEqual(assessment["verdict"], UNKNOWN)
        self.assertIn("stale", assessment["reason"])

    def test_path_leaving_the_project_is_refused(self):
        document = load_real()
        document["results"]["failed_checks"][0]["file_path"] = "/../Dockerfile"
        assessment = assess_document(document, self.project)[0]["assessment"]
        self.assertEqual(assessment["verdict"], UNKNOWN)
        self.assertIn("leaves the project", assessment["reason"])


class ContainerEndToEndTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.out = self.tmp / "out"

    def test_run_outputs_and_limitations_name_image_scanning(self):
        summary = universal_run.run(REAL, PROJECT, self.out)
        self.assertEqual(summary["categories"], ["CONTAINER"])
        self.assertEqual(summary["verdicts"]["POTENTIALLY_EXPLOITABLE"], 1)
        markdown = (self.out / "universal-report.md").read_text(encoding="utf-8")
        self.assertIn("image vulnerabilities are not assessed", markdown)
        sarif = json.loads((self.out / "universal.sarif").read_text(encoding="utf-8"))
        levels = {r["ruleId"]: r["level"] for r in sarif["runs"][0]["results"]}
        self.assertEqual(levels, {"CKV_DOCKER_1": "warning", "CKV_DOCKER_2": "note",
                                  "CKV_DOCKER_3": "note"})


if __name__ == "__main__":
    unittest.main()
