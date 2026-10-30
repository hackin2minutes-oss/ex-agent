"""Runs the PR-comment request against a local server that records what it receives.

This checks the real request the action sends: method, path, bearer token and JSON body.
It does not contact GitHub.
"""

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from engine import report


class _Recorder(BaseHTTPRequestHandler):
    received: list[dict] = []

    def do_POST(self):
        length = int(self.headers["Content-Length"])
        _Recorder.received.append({
            "path": self.path,
            "auth": self.headers.get("Authorization"),
            "accept": self.headers.get("Accept"),
            "body": json.loads(self.rfile.read(length)),
        })
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *args):
        pass


class PrCommentOverHttpTest(unittest.TestCase):
    def setUp(self):
        _Recorder.received = []
        self.server = HTTPServer(("127.0.0.1", 0), _Recorder)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.api = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def event(self, head_repo: str) -> Path:
        path = Path(self.tmp.name) / "event.json"
        path.write_text(json.dumps({"pull_request": {
            "number": 7, "head": {"repo": {"full_name": head_repo}}}}))
        return path

    def env(self, head_repo: str) -> dict:
        return {
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_EVENT_PATH": str(self.event(head_repo)),
            "GITHUB_REPOSITORY": "org/app",
            "GITHUB_TOKEN": "t0k",
            "GITHUB_API_URL": self.api,
        }

    def test_same_repository_pull_request_gets_a_comment(self):
        env = self.env("org/app")
        number = report.pr_number_if_postable(env)
        status = report.post_pr_comment("summary body", number, env=env)

        self.assertEqual(status, 201)
        self.assertEqual(len(_Recorder.received), 1)
        request = _Recorder.received[0]
        self.assertEqual(request["path"], "/repos/org/app/issues/7/comments")
        self.assertEqual(request["auth"], "Bearer t0k")
        self.assertEqual(request["accept"], "application/vnd.github+json")
        self.assertEqual(request["body"], {"body": "summary body"})

    def test_fork_pull_request_gets_no_comment(self):
        env = self.env("someone/fork")
        self.assertIsNone(report.pr_number_if_postable(env))
        self.assertEqual(_Recorder.received, [])


if __name__ == "__main__":
    unittest.main()
