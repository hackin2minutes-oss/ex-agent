"""The investigation loop: citation checks, the static-confirmation rule, the UNKNOWN gate, and the step budget.

The fixture project is tests/fixtures/investigation/project. Its eval call is on line 6 of app.py.
"""

import unittest
from pathlib import Path

from engine.investigation.citations import check_conclusion, demonstrated_for
from engine.investigation.evidence import EvidenceStore
from engine.investigation.investigate import investigate, unknown_gate
from engine.investigation.planner import OfflinePlanner
from engine.investigation.tools import Toolbox, ToolError
from engine.universal import ANALYSIS_INCOMPLETE, CONFIRMED_EXPLOITABLE, POTENTIALLY_EXPLOITABLE, UNKNOWN

PROJECT = Path(__file__).resolve().parent / "fixtures" / "investigation" / "project"
FINDING = {"title": "eval on request data", "path": "app.py", "line": 6, "symbol": "eval"}


def _conclusion(verdict, evidence_ids, **extra):
    return {"verdict": verdict, "reason": "test", "claims": [{"text": "claim", "evidence": evidence_ids}], **extra}


class ScriptedPlanner:
    """Plays a fixed list of proposals, then repeats the last one."""

    def __init__(self, steps):
        self.steps = list(steps)

    def next_step(self, state):
        return self.steps.pop(0) if len(self.steps) > 1 else self.steps[0]


class CitationTest(unittest.TestCase):
    def setUp(self):
        self.store = EvidenceStore()
        self.toolbox = Toolbox(PROJECT, self.store)

    def test_real_excerpt_at_its_line_is_accepted(self):
        found = self.toolbox.run("read_source", {"path": "app.py", "line": 6})
        eid = next(e.id for e in found if e.line == 6)
        self.assertEqual(check_conclusion(_conclusion(UNKNOWN, [eid]), self.store, PROJECT), [])

    def test_excerpt_that_is_not_in_the_file_is_refused(self):
        evidence = self.store.add(kind="source", tool="model", summary="invented", path="app.py", line=6,
                                  excerpt="    return os.system(expression)")
        problems = check_conclusion(_conclusion(UNKNOWN, [evidence.id]), self.store, PROJECT)
        self.assertTrue(any("excerpt is not the text" in p for p in problems), problems)

    def test_line_that_does_not_exist_is_refused(self):
        evidence = self.store.add(kind="source", tool="model", summary="x", path="app.py", line=999, excerpt="x")
        self.assertTrue(check_conclusion(_conclusion(UNKNOWN, [evidence.id]), self.store, PROJECT))

    def test_path_outside_the_project_is_refused(self):
        evidence = self.store.add(kind="source", tool="model", summary="x", path="../../etc/hosts", line=1,
                                  excerpt="x")
        problems = check_conclusion(_conclusion(UNKNOWN, [evidence.id]), self.store, PROJECT)
        self.assertTrue(any("outside the project" in p for p in problems), problems)

    def test_unknown_evidence_id_is_refused(self):
        problems = check_conclusion(_conclusion(UNKNOWN, ["E99"]), self.store, PROJECT)
        self.assertTrue(any("E99 is not in the evidence store" in p for p in problems))

    def test_claim_without_evidence_is_refused(self):
        problems = check_conclusion({"verdict": UNKNOWN, "claims": [{"text": "bare claim", "evidence": []}]},
                                    self.store, PROJECT)
        self.assertTrue(any("no evidence" in p for p in problems))


class ToolTest(unittest.TestCase):
    def setUp(self):
        self.store = EvidenceStore()
        self.toolbox = Toolbox(PROJECT, self.store)

    def test_read_source_quotes_the_real_line(self):
        found = self.toolbox.run("read_source", {"path": "app.py", "line": 6})
        by_line = {e.line: e.excerpt for e in found}
        self.assertEqual(by_line[6], "    return str(eval(expression))")

    def test_search_source_finds_the_call_with_its_line(self):
        found = self.toolbox.run("search_source", {"text": "eval("})
        self.assertEqual([(e.path, e.line) for e in found], [("app.py", 6)])

    def test_read_source_refuses_paths_outside_the_project(self):
        with self.assertRaises(ToolError):
            self.toolbox.run("read_source", {"path": "../../etc/hosts", "line": 1})

    def test_unknown_tool_and_bad_arguments_are_refused(self):
        with self.assertRaises(ToolError):
            self.toolbox.run("run_exploit", {})
        with self.assertRaises(ToolError):
            self.toolbox.run("read_source", {"path": "app.py", "line": 6, "extra": 1})

    def test_short_search_text_is_refused(self):
        with self.assertRaises(ToolError):
            self.toolbox.run("search_source", {"text": "ev"})


class UnknownGateTest(unittest.TestCase):
    MISSING = [{"what": "a route reaches it", "resolves_with": "call-graph analysis"}]

    def test_unknown_after_one_tool_is_refused(self):
        log = [{"tool": "read_source", "args": {}, "evidence": ["E2"]}]
        problems = unknown_gate({"missing_evidence": self.MISSING}, log)
        self.assertTrue(any("at least 2" in p for p in problems), problems)

    def test_unknown_after_two_different_tools_with_missing_evidence_is_allowed(self):
        log = [{"tool": "read_source", "args": {}, "evidence": ["E2"]},
               {"tool": "search_source", "args": {}, "evidence": ["E9"]}]
        self.assertEqual(unknown_gate({"missing_evidence": self.MISSING}, log), [])

    def test_unknown_without_missing_evidence_is_refused(self):
        log = [{"tool": "read_source", "args": {}, "evidence": ["E2"]},
               {"tool": "search_source", "args": {}, "evidence": ["E9"]}]
        self.assertTrue(unknown_gate({}, log))

    def test_failed_tool_runs_do_not_count(self):
        log = [{"tool": "read_source", "args": {}, "error": "no"}, {"tool": "search_source", "args": {}, "error": "no"}]
        self.assertTrue(unknown_gate({"missing_evidence": self.MISSING}, log))


class LoopTest(unittest.TestCase):
    def test_offline_planner_gathers_checks_and_stops_at_unknown_with_missing_evidence(self):
        result = investigate(FINDING, PROJECT, OfflinePlanner())
        self.assertEqual(result.verdict, UNKNOWN)
        tools_run = [entry["tool"] for entry in result.log if entry.get("evidence")]
        self.assertEqual(sorted(set(tools_run)), ["read_source", "search_source"])
        self.assertTrue(result.missing_evidence)

    def test_a_static_path_is_never_confirmed(self):
        class CiteTheCall:
            """Reads the window, then concludes CONFIRMED citing the record for line 6."""

            def next_step(self, state):
                if not state["log"]:
                    return {"action": "tool", "tool": "read_source", "args": {"path": "app.py", "line": 6}}
                line_six = next(e["id"] for e in state["evidence"] if e.get("line") == 6)
                return {"action": "conclude", "conclusion": _conclusion(CONFIRMED_EXPLOITABLE, [line_six])}

        result = investigate(FINDING, PROJECT, CiteTheCall())
        self.assertEqual(result.verdict, POTENTIALLY_EXPLOITABLE)
        self.assertIn("static evidence alone cannot confirm", result.reason)

    def test_a_conclusion_citing_a_record_that_does_not_exist_is_refused(self):
        planner = ScriptedPlanner([{"action": "conclude", "conclusion": _conclusion(POTENTIALLY_EXPLOITABLE, ["E77"])}])
        result = investigate(FINDING, PROJECT, planner)
        self.assertEqual(result.verdict, ANALYSIS_INCOMPLETE)
        self.assertTrue(any("E77" in p for p in result.problems))

    def test_unknown_too_early_is_refused_and_reported_as_incomplete(self):
        planner = ScriptedPlanner([{"action": "conclude", "conclusion": _conclusion(
            UNKNOWN, ["E1"], missing_evidence=[{"what": "x", "resolves_with": "y"}])}])
        result = investigate(FINDING, PROJECT, planner)
        self.assertEqual(result.verdict, ANALYSIS_INCOMPLETE)
        self.assertIn("UNKNOWN was refused", result.reason)

    def test_step_budget_is_enforced(self):
        planner = ScriptedPlanner([{"action": "tool", "tool": "read_source", "args": {"path": "app.py", "line": 6}}])
        result = investigate(FINDING, PROJECT, planner, max_steps=3)
        self.assertEqual(result.verdict, ANALYSIS_INCOMPLETE)
        self.assertIn("step budget", result.reason)
        self.assertEqual(len(result.log), 3)

    def test_demonstrated_evidence_is_the_only_thing_that_can_confirm(self):
        store = EvidenceStore()
        store.add(kind="dynamic", tool="replay", summary="request returned output", path=None)
        self.assertTrue(demonstrated_for(_conclusion(CONFIRMED_EXPLOITABLE, ["E1"]), store))


if __name__ == "__main__":
    unittest.main()
