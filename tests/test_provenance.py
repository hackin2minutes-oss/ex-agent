import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from engine import provenance, universal_run
from engine.universal import ModelError


def git(cwd, *args):
    subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True,
                   env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com",
                        "PATH": "/usr/bin:/bin"})


def make_repo(root: Path) -> str:
    git(root, "init", "-q")
    (root / "app.py").write_text("x = 1\n", encoding="utf-8")
    git(root, "add", "app.py")
    git(root, "commit", "-q", "-m", "init")
    return subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], check=True,
                          capture_output=True, text=True).stdout.strip()


def sarif(revision=None):
    run = {"tool": {"driver": {"name": "semgrep", "version": "1.0"}}, "results": []}
    if revision is not None:
        run["versionControlProvenance"] = [{"repositoryUri": "https://example.com/r", "revisionId": revision}]
    return {"version": "2.1.0", "runs": [run]}


class ReportCommitTest(unittest.TestCase):
    def test_declared_commits_are_read_from_sarif_provenance(self):
        sha = "a" * 40
        self.assertEqual(provenance.report_commits(sarif(sha)), {sha})

    def test_a_report_without_provenance_declares_nothing(self):
        self.assertEqual(provenance.report_commits(sarif()), set())

    def test_a_malformed_revision_is_not_a_commit(self):
        self.assertEqual(provenance.report_commits(sarif("not-a-sha")), set())


class CommitCheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        self.head = make_repo(self.repo)

    def write_report(self, name, document):
        path = self.tmp / name
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_a_report_from_the_project_commit_is_kept(self):
        report = self.write_report("ok.sarif", sarif(self.head))
        diagnostics, kept = provenance.check_reports([report], self.repo)
        self.assertEqual(kept, [report])
        self.assertTrue(any("matches the project" in d for d in diagnostics))

    def test_a_report_from_another_commit_is_refused(self):
        report = self.write_report("old.sarif", sarif("b" * 40))
        with self.assertRaisesRegex(ModelError, "re-scan the project"):
            provenance.check_reports([report], self.repo)

    def test_a_mismatch_is_analysed_only_when_allowed_and_says_so(self):
        report = self.write_report("old.sarif", sarif("b" * 40))
        diagnostics, kept = provenance.check_reports([report], self.repo, allow_mismatch=True)
        self.assertEqual(kept, [report])
        self.assertTrue(any("mismatch allowed" in d for d in diagnostics))

    def test_a_report_without_a_declared_commit_is_kept_and_marked_unverified(self):
        report = self.write_report("plain.json", {"results": []})
        diagnostics, kept = provenance.check_reports([report], self.repo)
        self.assertEqual(kept, [report])
        self.assertTrue(any("not verified" in d for d in diagnostics))

    def test_a_project_that_is_not_a_git_checkout_is_stated(self):
        plain = self.tmp / "plain"
        plain.mkdir()
        report = self.write_report("any.sarif", sarif("c" * 40))
        diagnostics, kept = provenance.check_reports([report], plain)
        self.assertEqual(kept, [report])
        self.assertTrue(any("not a git checkout" in d for d in diagnostics))


class RunnerCommitAndDirectoryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        self.head = make_repo(self.repo)
        self.reports = self.tmp / "reports"
        (self.reports / "nested").mkdir(parents=True)
        (self.reports / ".hidden").mkdir()
        (self.reports / "a.sarif").write_text(json.dumps(sarif(self.head)), encoding="utf-8")
        (self.reports / "nested" / "b.json").write_text(json.dumps({"results": []}), encoding="utf-8")
        (self.reports / ".hidden" / "c.sarif").write_text(json.dumps(sarif(self.head)), encoding="utf-8")
        (self.reports / "notes.txt").write_text("not a report", encoding="utf-8")

    def run_cli(self, *extra):
        out = io.StringIO()
        with redirect_stdout(out):
            code = universal_run.main(["--input-dir", str(self.reports), "--project-dir", str(self.repo),
                                       "--output-dir", str(self.tmp / "out"), "--offline", "true", *extra])
        return code, out.getvalue()

    def test_a_directory_is_searched_recursively_for_reports(self):
        code, output = self.run_cli()
        self.assertIn("2 report(s)", output)  # a.sarif and nested/b.json; .hidden and notes.txt are not read
        self.assertNotIn("c.sarif", output)

    def test_a_directory_that_does_not_exist_is_refused(self):
        with mock.patch("sys.stderr", new=io.StringIO()):
            with self.assertRaises(SystemExit):
                universal_run.main(["--input-dir", str(self.tmp / "missing"), "--project-dir", str(self.repo),
                                    "--output-dir", str(self.tmp / "out")])

    def test_a_mismatched_report_stops_the_run_with_exit_two(self):
        (self.reports / "a.sarif").write_text(json.dumps(sarif("d" * 40)), encoding="utf-8")
        with mock.patch("sys.stderr", new=io.StringIO()) as err:
            code, _ = self.run_cli()
        self.assertEqual(code, 2)
        self.assertIn("re-scan the project", err.getvalue())

    def test_a_mismatch_runs_when_explicitly_allowed(self):
        (self.reports / "a.sarif").write_text(json.dumps(sarif("d" * 40)), encoding="utf-8")
        code, output = self.run_cli("--allow-commit-mismatch", "true")
        self.assertEqual(code, 0)
        self.assertIn("mismatch allowed", output)
