"""Dependency findings from SARIF (Trivy, Grype, OSV-Scanner), their version dimension, and their verdicts.

The fixture `tests/fixtures/sarif-dependency/real-messages.sarif` holds result messages copied from real Code Scanning
alerts on a public test repository, with their rule ids and locations. Only the SARIF wrapper is written by hand.

Verdict rules under test: a dependency finding is NOT_AFFECTED only when a fixed version on the installed version's
release line is installed. Nothing here is NOT_EXPLOITABLE, because use of the package is not analysed. Installed
packages that are below their fixed version stay UNKNOWN.
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from engine import dependency, sarif_dependency, universal_run
from engine.universal import NOT_AFFECTED, NOT_EXPLOITABLE, UNKNOWN

FIXTURE = Path(__file__).parent / "fixtures" / "sarif-dependency" / "real-messages.sarif"
PROJECT = Path(__file__).parent / "fixtures" / "python-app"


def _result(message: str, uri: str, rule: str = "CVE-2026-0001") -> dict:
    return {"ruleId": rule, "message": {"text": message},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}]}


def _trivy(name: str, installed: str, fixed: str, uri: str) -> str:
    return (f"Package: {name}\nInstalled Version: {installed}\nVulnerability CVE-2026-0001\nSeverity: HIGH\n"
            f"Fixed Version: {fixed}\nLink: [CVE-2026-0001](https://example.invalid/CVE-2026-0001)")


class ParseTest(unittest.TestCase):
    def test_every_real_message_in_the_fixture_is_read_as_a_dependency(self):
        document = json.loads(FIXTURE.read_text(encoding="utf-8"))
        records, remaining = sarif_dependency.split(document)
        self.assertEqual(len(records), 11)
        self.assertEqual(sum(len(run["results"]) for run in remaining["runs"]), 0)

    def test_trivy_message_gives_package_installed_and_fixed_versions(self):
        result = _result(_trivy("express", "4.18.0", "4.19.2, 5.0.1", "usr/local/lib/node_modules/x/package.json"),
                         "usr/local/lib/node_modules/x/package.json")
        record = sarif_dependency.parse_result(result, "Trivy")
        self.assertEqual((record["name"], record["version"], record["fixed_version"]),
                         ("express", "4.18.0", "4.19.2, 5.0.1"))
        self.assertEqual(record["ecosystem"], "npm")
        self.assertEqual(record["sources"][0]["scope"], "image")

    def test_grype_message_gives_ecosystem_from_its_package_type(self):
        message = ("A high vulnerability in npm package: tar, version 6.2.1 was found in image "
                   "/home/runner/work/app/img.tar at: /usr/local/lib/node_modules/npm/node_modules/tar/package.json")
        record = sarif_dependency.parse_result(_result(message, "usr/local/lib/x/package.json"), "Grype")
        self.assertEqual((record["name"], record["version"], record["ecosystem"]), ("tar", "6.2.1", "npm"))
        self.assertIsNone(record["fixed_version"])
        self.assertEqual(record["sources"][0]["scope"], "image")

    def test_osv_message_in_a_project_manifest_is_project_scope(self):
        message = "Package 'certifi@2026.7.22' is vulnerable to 'PYSEC-2026-4320' (also known as 'GHSA-6q48-6c7w-9gw2')."
        record = sarif_dependency.parse_result(_result(message, "app/requirements.txt", "PYSEC-2026-4320"),
                                               "osv-scanner")
        self.assertEqual((record["name"], record["version"], record["ecosystem"]),
                         ("certifi", "2026.7.22", "PyPI"))
        self.assertEqual(record["sources"][0]["scope"], "project")

    def test_scoped_npm_name_is_kept_whole(self):
        message = "Package '@opentelemetry/instrumentation-pg@0.49.0' is vulnerable to 'CVE-2026-104872'."
        record = sarif_dependency.parse_result(_result(message, "pkg/package-lock.json"), "osv-scanner")
        self.assertEqual(record["name"], "@opentelemetry/instrumentation-pg")

    def test_sbom_source_says_nothing_about_location(self):
        message = "Package 'left-pad@1.0.0' is vulnerable to 'CVE-2026-0002'."
        record = sarif_dependency.parse_result(_result(message, "raw/sbom-source.cdx.json"), "osv-scanner")
        self.assertEqual(record["sources"][0]["scope"], "unspecified")

    def test_terraform_misconfiguration_is_not_a_dependency(self):
        message = ("Artifact: vulnerable_terraform/aws.tf\nType: terraform\nVulnerability AWS-0038\n"
                   "Severity: MEDIUM\nMessage: Control plane logging is not enabled.")
        self.assertIsNone(sarif_dependency.parse_result(_result(message, "vulnerable_terraform/aws.tf"), "Trivy"))

    def test_a_result_from_an_unrelated_tool_is_left_alone(self):
        document = {"runs": [{"tool": {"driver": {"name": "Semgrep OSS"}},
                              "results": [_result("Found 'subprocess' with shell=True", "app.py", "py.shell")]}]}
        records, remaining = sarif_dependency.split(document)
        self.assertEqual(records, [])
        self.assertEqual(len(remaining["runs"][0]["results"]), 1)


class VersionStatusTest(unittest.TestCase):
    def record(self, ecosystem, version, fixed):
        return {"ecosystem": ecosystem, "name": "pkg", "version": version, "fixed_version": fixed}

    def test_fixed_version_installed_on_its_line_is_fixed(self):
        status = dependency.version_status(self.record("npm", "1.9.20", "1.9.16"))
        self.assertEqual(status["status"], dependency.FIXED_INSTALLED)

    def test_installed_below_the_fix_on_its_line_is_below_fixed(self):
        status = dependency.version_status(self.record("npm", "1.9.15", "1.9.16, 2.0.1"))
        self.assertEqual(status["status"], dependency.BELOW_FIXED)
        self.assertIn("introduced", status["reason"])

    def test_a_fix_on_another_minor_line_does_not_cover_the_installed_version(self):
        status = dependency.version_status(self.record("npm", "1.13.2", "1.9.16"))
        self.assertEqual(status["status"], dependency.NO_FIX_FOR_LINE)

    def test_zero_major_versions_use_the_minor_line(self):
        self.assertEqual(dependency.version_status(self.record("npm", "0.7.4", "0.4.9"))["status"],
                         dependency.NO_FIX_FOR_LINE)
        self.assertEqual(dependency.version_status(self.record("npm", "0.4.10", "0.4.9"))["status"],
                         dependency.FIXED_INSTALLED)

    def test_missing_version_is_reported_not_guessed(self):
        self.assertEqual(dependency.version_status(self.record("npm", None, "2.0.0"))["status"],
                         dependency.VERSION_MISSING)

    def test_no_recorded_fix_is_reported(self):
        self.assertEqual(dependency.version_status(self.record("npm", "1.0.0", None))["status"],
                         dependency.NO_FIX_RECORDED)

    def test_unsupported_ecosystem_is_reported(self):
        self.assertEqual(dependency.version_status(self.record("unknown", "3.5.0-r0", "3.5.5-r0"))["status"],
                         dependency.UNSUPPORTED_ECOSYSTEM)

    def test_versions_on_one_line_compare_numerically_not_as_text(self):
        # As text, "2.9.10" sorts before "2.9.9". As versions, it is after.
        status = dependency.version_status(self.record("PyPI", "2.9.10", "2.9.9"))
        self.assertEqual(status["status"], dependency.FIXED_INSTALLED)


class RoutingAndVerdictTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def run_fixture(self, document=None):
        path = self.tmp / "report.sarif"
        path.write_text(json.dumps(document or json.loads(FIXTURE.read_text(encoding="utf-8"))), encoding="utf-8")
        return universal_run.run([path], PROJECT, self.tmp / "out", exposure="internet", offline=True)

    def test_dependency_results_are_not_sent_to_the_source_engine(self):
        summary = self.run_fixture()
        findings = json.loads((self.tmp / "out" / "universal-findings.json").read_text(encoding="utf-8"))["findings"]
        engines = {f["assessment"]["engine"] for f in findings}
        self.assertNotIn("sast-call-site", engines)
        self.assertNotIn("source file", " ".join(f["assessment"]["reason"] for f in findings))
        self.assertGreater(summary["findings"], 0)

    def test_fixed_version_installed_is_not_affected_with_its_source(self):
        document = {"runs": [{"tool": {"driver": {"name": "Trivy"}}, "results": [_result(
            _trivy("express", "4.19.2", "4.19.2", "usr/local/lib/node_modules/x/package.json"),
            "usr/local/lib/node_modules/x/package.json")]}]}
        self.run_fixture(document)
        findings = json.loads((self.tmp / "out" / "universal-findings.json").read_text(encoding="utf-8"))["findings"]
        verdicts = [f["assessment"] for f in findings if f["assessment"]["verdict"] == NOT_AFFECTED]
        self.assertEqual(len(verdicts), 1)
        self.assertEqual(verdicts[0]["version_status"], dependency.FIXED_INSTALLED)
        self.assertIn("Trivy", verdicts[0]["reason"])

    def test_installed_below_the_fix_is_unknown_with_its_reason(self):
        document = {"runs": [{"tool": {"driver": {"name": "Trivy"}}, "results": [_result(
            _trivy("express", "4.19.1", "4.19.2", "usr/local/lib/node_modules/x/package.json"),
            "usr/local/lib/node_modules/x/package.json")]}]}
        self.run_fixture(document)
        findings = json.loads((self.tmp / "out" / "universal-findings.json").read_text(encoding="utf-8"))["findings"]
        assessment = findings[0]["assessment"]
        self.assertEqual(assessment["verdict"], UNKNOWN)
        self.assertEqual(assessment["version_status"], dependency.BELOW_FIXED)

    def test_no_dependency_finding_is_ever_not_exploitable(self):
        self.run_fixture()
        findings = json.loads((self.tmp / "out" / "universal-findings.json").read_text(encoding="utf-8"))["findings"]
        self.assertNotIn(NOT_EXPLOITABLE, {f["assessment"]["verdict"] for f in findings})

    def test_offline_run_with_no_advisory_feed_still_assesses_version_and_location(self):
        summary = self.run_fixture()
        self.assertEqual(summary["findings"], 11)

    def test_project_manifest_without_a_resolved_file_is_analysed_from_the_scanner(self):
        # The fixture project has no resolved dependency file at its root. The scanner names the manifest, so the
        # dependency is analysed from the scanner's record instead of failing.
        document = {"runs": [{"tool": {"driver": {"name": "osv-scanner"}}, "results": [_result(
            "Package 'certifi@2026.7.22' is vulnerable to 'PYSEC-2026-4320'.", "sub/requirements.txt",
            "PYSEC-2026-4320")]}]}
        self.run_fixture(document)
        findings = json.loads((self.tmp / "out" / "universal-findings.json").read_text(encoding="utf-8"))["findings"]
        ours = [f for f in findings if f["vulnerability"]["rule_id"] == "PYSEC-2026-4320"]
        self.assertEqual(len(ours), 1)
        self.assertNotIn("analysis failed", ours[0]["assessment"]["reason"])
        self.assertNotEqual(ours[0]["assessment"]["verdict"], NOT_EXPLOITABLE)


class UsageTest(unittest.TestCase):
    JS = Path(__file__).parent / "fixtures" / "js-analysis-app"

    def test_package_imported_by_python_source_is_imported_with_its_location(self):
        from engine import dependency_usage
        result = dependency_usage.find(PROJECT, "PyPI", "flask")
        self.assertEqual(result["status"], dependency_usage.IMPORTED)
        self.assertEqual(result["locations"], ["app/views.py:2"])

    def test_no_matching_import_is_not_evidence_of_non_use(self):
        # PyYAML is imported as yaml. No import named pyyaml is not proof the package is unused.
        from engine import dependency_usage
        result = dependency_usage.find(PROJECT, "PyPI", "pyyaml")
        self.assertEqual(result["status"], dependency_usage.NOT_FOUND_IN_SOURCE)
        self.assertIn("not evidence", result["reason"])

    def test_npm_require_and_import_are_read_from_the_syntax_tree(self):
        from engine import dependency_usage
        result = dependency_usage.find(self.JS, "npm", "express")
        self.assertEqual(result["status"], dependency_usage.IMPORTED)

    def test_ecosystem_without_import_analysis_is_not_scanned(self):
        from engine import dependency_usage
        self.assertEqual(dependency_usage.find(PROJECT, "Go", "x")["status"], dependency_usage.NOT_SCANNED)

    def test_vulnerable_package_with_unknown_use_stays_out_of_not_exploitable(self):
        document = {"runs": [{"tool": {"driver": {"name": "osv-scanner"}}, "results": [_result(
            "Package 'pyyaml@5.3.1' is vulnerable to 'PYSEC-2021-0001'.", "requirements.txt", "PYSEC-2021-0001")]}]}
        path = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, path, ignore_errors=True)
        (path / "report.sarif").write_text(json.dumps(document), encoding="utf-8")
        universal_run.run([path / "report.sarif"], PROJECT, path / "out", exposure="internet", offline=True)
        findings = json.loads((path / "out" / "universal-findings.json").read_text(encoding="utf-8"))["findings"]
        ours = [f for f in findings if f["vulnerability"]["rule_id"] == "PYSEC-2021-0001"]
        dims = ours[0]["assessment"]["dimensions"]
        self.assertEqual(dims["application_usage"], "NOT_FOUND_IN_SOURCE")
        self.assertEqual(dims["vulnerable_functionality"], "NOT_ESTABLISHED")
        self.assertNotEqual(ours[0]["assessment"]["verdict"], NOT_EXPLOITABLE)


if __name__ == "__main__":
    unittest.main()
