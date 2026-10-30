import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from engine import provenance, universal_run, weakness
from engine.universal import ModelError, Registry

ENGINE = Path(__file__).resolve().parent.parent / "engine"


def sarif_with_tags(tags, message="finding"):
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "scanner", "version": "1"}},
                                          "results": [{"ruleId": "r1", "level": "error",
                                                       "message": {"text": message},
                                                       "locations": [{"physicalLocation": {
                                                           "artifactLocation": {"uri": "a.py"},
                                                           "region": {"startLine": 1}}}],
                                                       "properties": {"tags": tags}}]}]}


class WeaknessTest(unittest.TestCase):
    def test_a_cwe_tag_names_the_weakness_class(self):
        record = {"properties": {"tags": ["security", "external/cwe/cwe-89"]}}
        self.assertEqual(weakness.classify({"original": record}),
                         {"cwe": ["CWE-89"], "classes": ["SQL_INJECTION"], "reason": "from the CWE the source names"})

    def test_a_cwe_written_in_a_message_is_found(self):
        record = {"message": {"text": "Possible CWE-78: OS command injection"}}
        self.assertEqual(weakness.classify({"original": record})["classes"], ["COMMAND_INJECTION"])

    def test_no_cwe_means_no_class_and_says_so(self):
        result = weakness.classify({"original": {"check_id": "rule.without.cwe"}})
        self.assertEqual(result["cwe"], [])
        self.assertEqual(result["classes"], [])
        self.assertIn("names no CWE", result["reason"])

    def test_a_cwe_outside_the_table_is_kept_but_unclassified(self):
        result = weakness.classify({"original": {"text": "CWE-99999"}})
        self.assertEqual(result["cwe"], ["CWE-99999"])
        self.assertEqual(result["classes"], [])
        self.assertIn("not in the weakness table", result["reason"])

    def test_the_class_is_independent_of_the_tool_name(self):
        same_cwe = {"properties": {"tags": ["external/cwe/cwe-89"]}}
        from_one_tool = weakness.classify({"original": dict(same_cwe, tool="semgrep")})
        from_another = weakness.classify({"original": dict(same_cwe, tool="codeql")})
        self.assertEqual(from_one_tool["classes"], from_another["classes"])


class PluginTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def write_plugin(self, name, source):
        path = self.tmp / name
        path.write_text(source, encoding="utf-8")
        return path

    def test_a_plugin_registers_a_new_adapter_without_editing_the_core(self):
        plugin = self.write_plugin("stub_plugin.py", '''
from engine.universal import Adapter, make_finding

class StubAdapter(Adapter):
    name = "stub-plugin"
    formats = ("stub-json",)
    categories = ("SAST",)

    def detect(self, document):
        return isinstance(document, dict) and document.get("format") == "stub"

    def parse(self, document, provenance):
        return [], []

def register(registry):
    registry.register_adapter(StubAdapter())
''')
        registry = universal_run.build_registry()
        message = universal_run.load_plugin(plugin, registry)
        self.assertIn("registered", message)
        self.assertEqual(registry.adapter("stub-plugin").name, "stub-plugin")

    def test_a_plugin_without_register_is_refused(self):
        plugin = self.write_plugin("empty.py", "x = 1\n")
        with self.assertRaisesRegex(ModelError, "no register"):
            universal_run.load_plugin(plugin, Registry())

    def test_a_plugin_that_fails_to_load_stops_the_run(self):
        plugin = self.write_plugin("broken.py", "raise RuntimeError('boom')\n")
        with self.assertRaisesRegex(ModelError, "failed to load"):
            universal_run.load_plugin(plugin, Registry())

    def test_a_plugin_must_be_a_python_file(self):
        plugin = self.write_plugin("plugin.txt", "x = 1\n")
        with self.assertRaisesRegex(ModelError, "must be a .py file"):
            universal_run.load_plugin(plugin, Registry())


class CleanTreeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        git = ["git", "-C", str(self.repo)]
        env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com", "GIT_COMMITTER_NAME": "t",
               "GIT_COMMITTER_EMAIL": "t@example.com", "PATH": "/usr/bin:/bin"}
        subprocess.run(git + ["init", "-q"], check=True, capture_output=True, env=env)
        (self.repo / "app.py").write_text("x = 1\n", encoding="utf-8")
        subprocess.run(git + ["add", "app.py"], check=True, capture_output=True, env=env)
        subprocess.run(git + ["commit", "-q", "-m", "init"], check=True, capture_output=True, env=env)

    def test_a_clean_tree_is_accepted(self):
        self.assertIn("no uncommitted changes", provenance.check_clean(self.repo))

    def test_uncommitted_changes_are_refused(self):
        (self.repo / "app.py").write_text("x = 2\n", encoding="utf-8")
        with self.assertRaisesRegex(ModelError, "uncommitted change"):
            provenance.check_clean(self.repo)

    def test_uncommitted_changes_are_analysed_only_when_allowed(self):
        (self.repo / "app.py").write_text("x = 2\n", encoding="utf-8")
        message = provenance.check_clean(self.repo, allow_dirty=True)
        self.assertIn("allowed", message)

    def test_a_project_that_is_not_a_checkout_is_stated(self):
        plain = self.tmp / "plain"
        plain.mkdir()
        self.assertIn("not a git checkout", provenance.check_clean(plain))


class RunRecordsWeaknessTest(unittest.TestCase):
    def test_every_finding_carries_its_weakness_record(self):
        tmp = Path(tempfile.mkdtemp())
        report = tmp / "r.sarif"
        report.write_text(json.dumps(sarif_with_tags(["external/cwe/cwe-89"])), encoding="utf-8")
        summary = universal_run.run([report], tmp, tmp / "out", offline=True)
        findings = json.loads((tmp / "out" / "universal-findings.json").read_text(encoding="utf-8"))["findings"]
        self.assertEqual(summary["findings"], 1)
        self.assertEqual(findings[0]["weakness"]["classes"], ["SQL_INJECTION"])


class VerdictIsNotScannerOutputTest(unittest.TestCase):
    def test_no_adapter_sets_a_verdict(self):
        pattern = re.compile(r"""["']verdict["']\s*[:=]|\bverdict\s*=""")
        offenders = [p.name for p in ENGINE.glob("*adapter*.py") if pattern.search(p.read_text(encoding="utf-8"))]
        offenders += [p.name for p in ENGINE.glob("*_adapter.py") if pattern.search(p.read_text(encoding="utf-8"))]
        self.assertEqual(sorted(set(offenders)), [])

    def test_sarif_findings_carry_the_scanner_severity_as_reported_only(self):
        from engine.sarif_adapter import SarifAdapter
        findings, _ = SarifAdapter().parse(sarif_with_tags([]), {"target": "t"})
        self.assertNotIn("verdict", findings[0])
        self.assertNotIn("assessment", findings[0])
        self.assertEqual(findings[0]["severity"]["reported"], "error")
