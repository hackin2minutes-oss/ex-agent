"""Source commit provenance: the commit a report was generated from, compared with the commit being analysed.

A clean working tree does not show that the code matches the report. These tests compare commits, not trees."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from engine import provenance
from engine.universal import ModelError

OTHER = "1" * 40


def git_repo(tmp: Path) -> str:
    """A git repository with one commit. Returns the commit it is at."""
    subprocess.run(["git", "init", "-q", str(tmp)], check=True)
    (tmp / "app.py").write_text("print('x')\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(tmp), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"],
                   check=True)
    return subprocess.run(["git", "-C", str(tmp), "rev-parse", "HEAD"], capture_output=True, text=True,
                          check=True).stdout.strip()


def threat_report(tmp: Path, **fields) -> Path:
    path = tmp / "threat-model.json"
    document = {"name": "m", "threats": [], "counts": {}, "by_stride": {}, "total": 0, **fields}
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


class DeclaredCommitTest(unittest.TestCase):
    def test_a_threat_model_declares_its_commit_at_the_top_level_or_under_source(self):
        sha = "a" * 40
        self.assertEqual(provenance.report_commits({"commit": sha}), {sha})
        self.assertEqual(provenance.report_commits({"source_commit": sha}), {sha})
        self.assertEqual(provenance.report_commits({"source": {"commit": sha}}), {sha})

    def test_a_value_that_is_not_a_commit_is_not_a_declaration(self):
        self.assertEqual(provenance.report_commits({"commit": "main"}), set())
        self.assertEqual(provenance.report_commits({"commit": "g" * 40}), set())

    def test_a_sarif_report_still_declares_through_its_runs(self):
        sha = "b" * 40
        document = {"version": "2.1.0", "runs": [{"versionControlProvenance": [{"revisionId": sha}]}]}
        self.assertEqual(provenance.report_commits(document), {sha})


class CheckReportsTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.project = self.tmp / "project"
        self.project.mkdir()
        self.head = git_repo(self.project)

    def tearDown(self):
        self._tmp.cleanup()

    def test_a_report_from_the_project_commit_is_kept_and_says_it_matches(self):
        report = threat_report(self.tmp, commit=self.head)
        diagnostics, kept = provenance.check_reports([report], self.project)
        self.assertEqual(kept, [report])
        self.assertTrue(any("matches the project" in line for line in diagnostics))

    def test_a_report_from_another_commit_is_refused(self):
        report = threat_report(self.tmp, commit=OTHER)
        with self.assertRaises(ModelError) as raised:
            provenance.check_reports([report], self.project)
        self.assertIn("pass --allow-commit-mismatch", str(raised.exception))

    def test_a_mismatch_is_analysed_only_when_explicitly_allowed_and_is_stated(self):
        report = threat_report(self.tmp, commit=OTHER)
        diagnostics, kept = provenance.check_reports([report], self.project, allow_mismatch=True)
        self.assertEqual(kept, [report])
        self.assertTrue(any("mismatch allowed" in line for line in diagnostics))

    def test_a_report_that_declares_no_commit_is_kept_and_marked_unverified(self):
        report = threat_report(self.tmp)
        diagnostics, kept = provenance.check_reports([report], self.project)
        self.assertEqual(kept, [report])
        self.assertTrue(any("declares no commit" in line for line in diagnostics))

    def test_a_project_that_is_not_a_git_checkout_is_stated(self):
        plain = self.tmp / "plain"
        plain.mkdir()
        diagnostics, _ = provenance.check_reports([threat_report(self.tmp, commit=OTHER)], plain,
                                                  allow_mismatch=True)
        self.assertTrue(any("not a git checkout" in line for line in diagnostics))

    def test_a_clean_tree_does_not_prove_the_commit_matches(self):
        report = threat_report(self.tmp, commit=OTHER)
        self.assertEqual(provenance.check_clean(self.project), "clean-tree check: the working tree has no "
                                                              "uncommitted changes")
        with self.assertRaises(ModelError):
            provenance.check_reports([report], self.project)


if __name__ == "__main__":
    unittest.main()
