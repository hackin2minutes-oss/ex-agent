"""Runtime evidence ingestion: how an observation changes an assessment, and how a whole run uses it."""

import json
import tempfile
import unittest
from pathlib import Path

from engine import deployment_context, universal_run
from engine.languages.csharp import assess_call
from engine.universal import CONFIRMED, NOT_EXPLOITABLE, POTENTIALLY_EXPLOITABLE, UNKNOWN, make_finding
from engine.sast import SastEngine

PROJECT = Path(__file__).parent / "fixtures" / "csharp-app"
FILE = "Controllers/SearchController.cs"
LINES = (PROJECT / FILE).read_text().splitlines()


def line_of(marker: str) -> int:
    return next(i for i, text in enumerate(LINES, 1) if f"// SINK:{marker}" in text)


def finding_at(marker: str, exposure: str = "unknown"):
    number = line_of(marker)
    item = make_finding(category="SAST", rule_id="cs.sink", title="rule",
                        asset={"type": "source_location", "name": FILE},
                        location={"path": FILE, "start_line": number, "end_line": number,
                                  "start_col": None, "end_col": None},
                        severity_reported="error", provenance={"scanner": "test"}, original={})
    item["exploitability_context"]["exposure"] = exposure
    return item


def observation(line: int, outcome: str = "reached", oid: str = "obs-1"):
    return {"id": oid, "file": FILE, "line": line, "outcome": outcome, "source": "tracer"}


def context_with(observations):
    return deployment_context.load({"schema": "sawone-context-1", "runtime_observations": observations})


class ObservationEffectTest(unittest.TestCase):
    def _assess(self, marker: str, observations):
        finding = finding_at(marker)
        deployment = context_with(observations)
        base = SastEngine()._assess_location(finding, {"project_dir": PROJECT})
        return finding, base, deployment_context.apply_runtime(base, finding, {"deployment": deployment})

    def test_a_reached_observation_raises_reachability_and_records_the_observation(self):
        _, base, improved = self._assess("unrouted", [observation(line_of("unrouted"))])
        self.assertEqual(base.conditions["reachable"].status, UNKNOWN)
        self.assertEqual(improved.conditions["reachable"].status, CONFIRMED)
        self.assertEqual(improved.conditions["runtime_observed"].status, CONFIRMED)
        self.assertEqual(improved.conditions["reachable"].evidence, ["obs-1"])

    def test_with_attacker_input_confirmed_an_unknown_verdict_becomes_potentially_exploitable(self):
        marker = "tainted-local"
        _, base, improved = self._assess(marker, [observation(line_of(marker))])
        self.assertEqual(base.verdict, POTENTIALLY_EXPLOITABLE)
        self.assertEqual(improved.verdict, POTENTIALLY_EXPLOITABLE)

    def test_an_observation_at_another_line_changes_nothing(self):
        _, base, improved = self._assess("unrouted", [observation(line_of("unrouted") + 1)])
        self.assertIs(base, improved)

    def test_a_not_reached_observation_changes_nothing(self):
        _, base, improved = self._assess("unrouted", [observation(line_of("unrouted"), outcome="not_reached")])
        self.assertIs(base, improved)

    def test_a_negative_verdict_is_never_changed_by_runtime_evidence(self):
        marker = "constant"
        finding = finding_at(marker)
        base = assess_call(PROJECT.joinpath(FILE).read_bytes(), finding["location"], engine="sast-call-site",
                           exposure="unknown")
        self.assertEqual(base.verdict, NOT_EXPLOITABLE)
        deployment = context_with([observation(line_of(marker))])
        self.assertIs(deployment_context.apply_runtime(base, finding, {"deployment": deployment}), base)

    def test_without_a_deployment_context_the_result_is_unchanged(self):
        finding = finding_at("unrouted")
        base = SastEngine()._assess_location(finding, {"project_dir": PROJECT})
        self.assertIs(deployment_context.apply_runtime(base, finding, {"project_dir": PROJECT}), base)


class RunWithContextTest(unittest.TestCase):
    """A whole run: a SARIF report, the C# project, and a context document with an exposure and an observation."""

    def _run(self, context_document):
        with tempfile.TemporaryDirectory() as tmp:
            sarif = Path(tmp) / "report.sarif"
            sarif.write_text(json.dumps({"version": "2.1.0", "runs": [{
                "tool": {"driver": {"name": "semgrep", "version": "1"}},
                "results": [{"ruleId": "cs.sqli", "level": "error",
                             "message": {"text": "tainted SQL"},
                             "locations": [{"physicalLocation": {"artifactLocation": {"uri": FILE},
                                                                 "region": {"startLine": line_of("tainted-local")}}}]}],
            }]}), encoding="utf-8")
            return universal_run.run([sarif], PROJECT, Path(tmp) / "out", exposure="unknown",
                                     context_document=context_document)

    def test_a_run_without_context_reports_repository_only_evidence(self):
        summary = self._run(None)
        self.assertEqual(summary["deployment_context"], "repository-only")
        self.assertEqual(summary["verdicts"]["POTENTIALLY_EXPLOITABLE"], 1)
        self.assertFalse([p for p in summary["evidence_graph"]["attack_paths"] if p["hops"][-1] == "exposure:public"])

    def test_declared_exposure_and_a_runtime_observation_are_used_by_the_run(self):
        document = {"schema": "sawone-context-1",
                    "endpoints": [{"id": "ep-search", "route": "/search", "exposure": "public",
                                   "handler": {"file": FILE, "symbol": "Search"}}],
                    "runtime_observations": [observation(line_of("tainted-local"))]}
        summary = self._run(document)
        self.assertEqual(summary["deployment_context"], "provided")
        self.assertEqual(summary["exposure"], "unknown", "the run flag is unchanged; the context sets per-finding")
        graph = summary["evidence_graph"]
        self.assertEqual(graph["nodes"] > 0, True)
        public_paths = [p for p in graph["attack_paths"] if p["hops"][-1] == "exposure:public"]
        self.assertEqual(len(public_paths), 1)
        self.assertEqual(public_paths[0]["status"], "path_present")
        self.assertTrue(graph["not_correlated"])

    def test_an_invalid_context_refuses_the_run(self):
        from engine.universal import ModelError
        with self.assertRaises(ModelError):
            self._run({"schema": "sawone-context-1", "endpoints": [{"id": "e", "exposure": "maybe"}]})


if __name__ == "__main__":
    unittest.main()
