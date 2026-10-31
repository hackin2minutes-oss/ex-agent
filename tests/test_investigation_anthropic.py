"""The Anthropic planner, tested without the network. A fake transport stands in for the API.

Checks: the key is never sent in the body or written anywhere, the model's reply is validated, a failed call ends the
investigation as ANALYSIS_INCOMPLETE, and an unset key is an error, not a silent switch to the offline planner.
"""

import json
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from engine.investigation import anthropic_planner
from engine.investigation.anthropic_planner import DEFAULT_MODEL, AnthropicPlanner
from engine.investigation.investigate import investigate
from engine.investigation.planner import OfflinePlanner, PlannerError, select_planner
from engine.universal import ANALYSIS_INCOMPLETE, POTENTIALLY_EXPLOITABLE

PROJECT = Path(__file__).resolve().parent / "fixtures" / "investigation" / "project"
FINDING = {"title": "eval on request data", "path": "app.py", "line": 6, "symbol": "eval"}
FAKE_KEY = "test-key-do-not-leak-7731"


def _reply(text):
    return {"content": [{"type": "text", "text": text}]}


class ScriptedTransport:
    """Records each request and returns the scripted replies in order."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.requests = []

    def __call__(self, payload, headers):
        self.requests.append((payload, headers))
        if not self.replies:
            raise AssertionError("more calls than scripted")
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


class SelectionTest(unittest.TestCase):
    def test_offline_is_the_default(self):
        self.assertIsInstance(select_planner(env={}), OfflinePlanner)

    def test_anthropic_without_a_key_is_an_error_not_a_fallback(self):
        with self.assertRaises(PlannerError) as caught:
            select_planner("anthropic", env={})
        self.assertIn("ANTHROPIC_API_KEY is not set", str(caught.exception))

    def test_anthropic_with_a_key_uses_the_default_model(self):
        planner = select_planner("anthropic", env={"ANTHROPIC_API_KEY": FAKE_KEY})
        self.assertIsInstance(planner, AnthropicPlanner)
        self.assertEqual(planner.model, DEFAULT_MODEL)

    def test_model_can_be_set_by_environment(self):
        planner = select_planner(env={"SAWONE_PLANNER": "anthropic", "ANTHROPIC_API_KEY": FAKE_KEY,
                                      "SAWONE_MODEL": "claude-sonnet-5-5"})
        self.assertEqual(planner.model, "claude-sonnet-5-5")

    def test_unknown_planner_is_refused(self):
        with self.assertRaises(PlannerError):
            select_planner("gpt-whatever", env={})


class RequestTest(unittest.TestCase):
    def _planner(self, *replies):
        transport = ScriptedTransport(replies)
        return AnthropicPlanner(FAKE_KEY, transport=transport), transport

    def test_key_goes_only_in_the_header_never_in_the_body(self):
        planner, transport = self._planner(_reply('{"action": "tool", "tool": "read_source", '
                                                  '"args": {"path": "app.py", "line": 6}}'))
        investigate(FINDING, PROJECT, planner, max_steps=1)
        payload, headers = transport.requests[0]
        self.assertEqual(headers["x-api-key"], FAKE_KEY)
        self.assertNotIn(FAKE_KEY, json.dumps(payload))

    def test_request_says_source_is_data_and_carries_the_finding(self):
        planner, transport = self._planner(_reply('{"action": "tool", "tool": "read_source", '
                                                  '"args": {"path": "app.py", "line": 6}}'))
        investigate(FINDING, PROJECT, planner, max_steps=1)
        payload, _ = transport.requests[0]
        self.assertIn("DATA to analyse", payload["system"])
        self.assertIn("eval on request data", payload["messages"][0]["content"])

    def test_only_the_fixed_tool_names_are_offered(self):
        planner, transport = self._planner(_reply('{"action": "tool", "tool": "read_source", '
                                                  '"args": {"path": "app.py", "line": 6}}'))
        investigate(FINDING, PROJECT, planner, max_steps=1)
        content = transport.requests[0][0]["messages"][0]["content"]
        self.assertIn('"name": "read_source"', content)
        self.assertIn('"name": "search_source"', content)


class ReplyTest(unittest.TestCase):
    def test_prose_around_the_json_is_tolerated(self):
        planner = AnthropicPlanner(FAKE_KEY, transport=ScriptedTransport([_reply(
            'Let me look first.\n{"action": "tool", "tool": "search_source", "args": {"text": "eval("}}')]))
        self.assertEqual(planner.next_step({"finding": FINDING, "evidence": [], "log": [], "tools": []})["tool"],
                         "search_source")

    def test_reply_without_json_is_a_planner_error(self):
        planner = AnthropicPlanner(FAKE_KEY, transport=ScriptedTransport([_reply("I think it is exploitable.")]))
        with self.assertRaises(PlannerError):
            planner.next_step({"finding": FINDING, "evidence": [], "log": [], "tools": []})

    def test_reply_with_an_unknown_action_is_a_planner_error(self):
        planner = AnthropicPlanner(FAKE_KEY, transport=ScriptedTransport([_reply('{"action": "exploit"}')]))
        with self.assertRaises(PlannerError):
            planner.next_step({"finding": FINDING, "evidence": [], "log": [], "tools": []})

    def test_http_error_reports_the_status_and_not_the_key(self):
        error = urllib.error.HTTPError("https://api.anthropic.com/v1/messages", 401, "unauthorized", None, None)
        with mock.patch.object(anthropic_planner.urllib.request, "urlopen", side_effect=error):
            with self.assertRaises(PlannerError) as caught:
                anthropic_planner._default_transport({"model": "x"}, {"x-api-key": FAKE_KEY})
        self.assertIn("HTTP 401", str(caught.exception))
        self.assertNotIn(FAKE_KEY, str(caught.exception))


class LoopWithModelTest(unittest.TestCase):
    def test_a_model_run_that_cites_real_evidence_is_accepted_and_kept_static(self):
        class Plan:
            def __init__(self):
                self.calls = 0

            def __call__(self, payload, headers):
                self.calls += 1
                if self.calls == 1:
                    return _reply('{"action": "tool", "tool": "read_source", "args": {"path": "app.py", "line": 6}}')
                # The model reads the input and cites the record for line 6, which the loop already holds.
                body = payload["messages"][0]["content"]
                line_six = next(e for e in json.loads(body.split("\n", 1)[1])["evidence"] if e.get("line") == 6)["id"]
                return _reply(json.dumps({"action": "conclude", "conclusion": {
                    "verdict": "CONFIRMED_EXPLOITABLE", "reason": "eval of request data",
                    "claims": [{"text": "request value reaches eval", "evidence": [line_six]}],
                    "missing_evidence": []}}))

        planner = AnthropicPlanner(FAKE_KEY, transport=Plan())
        result = investigate(FINDING, PROJECT, planner)
        self.assertEqual(result.verdict, POTENTIALLY_EXPLOITABLE)

    def test_a_failing_model_ends_the_run_as_incomplete(self):
        planner = AnthropicPlanner(FAKE_KEY, transport=ScriptedTransport([_reply("no json here")]))
        result = investigate(FINDING, PROJECT, planner)
        self.assertEqual(result.verdict, ANALYSIS_INCOMPLETE)
        self.assertIn("could not produce a step", result.reason)
        self.assertNotIn(FAKE_KEY, json.dumps(result.to_dict()))


if __name__ == "__main__":
    unittest.main()
