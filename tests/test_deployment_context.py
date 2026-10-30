"""Deployment and runtime context: parsing, validation, unknown-by-default, exposure, and the documented example."""

import copy
import re
import unittest
from pathlib import Path

from engine import deployment_context
from engine.universal import ModelError, make_finding

ROOT = Path(__file__).parent.parent
PROJECT = Path(__file__).parent / "fixtures" / "csharp-app"


def doc(**sections):
    return {"schema": "sawone-context-1", **sections}


class ParseTest(unittest.TestCase):
    def test_a_repository_only_context_has_no_records_and_every_field_is_unknown(self):
        ctx = deployment_context.repository_only()
        self.assertEqual(deployment_context.field(None, "exposure"), {"state": "unknown"})
        self.assertEqual(deployment_context.field({"exposure": None}, "exposure"), {"state": "unknown"})
        self.assertEqual(ctx.exposure_for("app/views.py", "search"), "unknown")
        self.assertEqual(ctx.runtime_observations_at("app/views.py", 10), [])

    def test_a_known_field_is_returned_with_its_value(self):
        self.assertEqual(deployment_context.field({"exposure": "public"}, "exposure"),
                         {"state": "known", "value": "public"})

    def test_a_document_without_the_schema_version_is_refused(self):
        with self.assertRaises(ModelError):
            deployment_context.load({"applications": []})
        with self.assertRaises(ModelError):
            deployment_context.load({"schema": "sawone-context-2"})

    def test_an_unknown_top_level_key_is_refused_and_an_extension_key_is_kept(self):
        with self.assertRaises(ModelError):
            deployment_context.load(doc(surprise=[]))
        ctx = deployment_context.load(doc(**{"x-acme-cmdb": {"owner": "store"}}))
        self.assertEqual(ctx.document["x-acme-cmdb"], {"owner": "store"})

    def test_an_exposure_outside_the_allowed_values_is_refused(self):
        with self.assertRaises(ModelError):
            deployment_context.load(doc(endpoints=[{"id": "e", "exposure": "internal"}]))

    def test_an_undeclared_exposure_is_unknown_not_public(self):
        ctx = deployment_context.load(doc(endpoints=[
            {"id": "e", "handler": {"file": "a.cs", "symbol": "Search"}}]))
        self.assertEqual(ctx.exposure_for("a.cs", "Search"), "unknown")

    def test_exposure_levels_map_to_the_engine_levels(self):
        ctx = deployment_context.load(doc(endpoints=[
            {"id": "pub", "exposure": "public", "handler": {"file": "a.cs", "symbol": "Search"}},
            {"id": "priv", "exposure": "private", "handler": {"file": "b.cs", "symbol": "Save"}}]))
        self.assertEqual(ctx.exposure_for("a.cs", "Search"), "internet")
        self.assertEqual(ctx.exposure_for("b.cs", "Save"), "internal")

    def test_a_record_without_an_id_or_a_duplicate_id_is_refused(self):
        with self.assertRaises(ModelError):
            deployment_context.load(doc(workloads=[{"environment": "prod"}]))
        with self.assertRaises(ModelError):
            deployment_context.load(doc(workloads=[{"id": "w"}, {"id": "w"}]))

    def test_a_runtime_observation_needs_a_valid_outcome_and_a_line(self):
        with self.assertRaises(ModelError):
            deployment_context.load(doc(runtime_observations=[{"id": "o", "file": "a.cs", "line": 1,
                                                             "outcome": "maybe"}]))
        with self.assertRaises(ModelError):
            deployment_context.load(doc(runtime_observations=[{"id": "o", "file": "a.cs", "line": 0,
                                                             "outcome": "reached"}]))

    def test_a_protection_event_needs_a_known_action(self):
        with self.assertRaises(ModelError):
            deployment_context.load(doc(runtime_protection_events=[{"id": "p", "file": "a.cs", "line": 1,
                                                                   "action": "ignored"}]))

    def test_a_section_that_is_not_a_list_is_refused(self):
        with self.assertRaises(ModelError):
            deployment_context.load(doc(endpoints={"id": "e"}))


class DocumentedExampleTest(unittest.TestCase):
    def test_the_example_in_the_documentation_loads(self):
        text = (ROOT / "docs" / "CONTEXT_SCHEMA.md").read_text(encoding="utf-8")
        block = re.search(r"```json\n(.*?)\n```", text, re.DOTALL).group(1)
        import json
        ctx = deployment_context.load(json.loads(block))
        self.assertEqual(len(ctx.records["endpoints"]), 1)
        self.assertEqual(len(ctx.records["runtime_observations"]), 1)
        self.assertEqual(ctx.exposure_for("Controllers/SearchController.cs", "Search"), "internet")

    def test_the_schema_file_is_valid_json_with_the_version_constant(self):
        import json
        schema = json.loads((ROOT / "docs" / "schemas" / "sawone-context-1.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(schema["properties"]["schema"]["const"], deployment_context.SCHEMA)
        self.assertEqual(set(deployment_context.SECTIONS) - set(schema["properties"]),
                         set(), "every section the loader accepts is in the schema")


class ExposureTest(unittest.TestCase):
    def _finding(self, line_marker_text: str):
        lines = (PROJECT / "Controllers" / "SearchController.cs").read_text().splitlines()
        number = next(i for i, text in enumerate(lines, 1) if line_marker_text in text)
        return make_finding(category="SAST", rule_id="cs.sink", title="rule",
                            asset={"type": "source_location", "name": "Controllers/SearchController.cs"},
                            location={"path": "Controllers/SearchController.cs", "start_line": number,
                                      "end_line": number, "start_col": None, "end_col": None},
                            severity_reported="error", provenance={"scanner": "test"}, original={})

    def test_a_declared_public_handler_sets_the_finding_exposure(self):
        ctx = deployment_context.load(doc(endpoints=[{"id": "ep", "exposure": "public",
                                                      "handler": {"file": "Controllers/SearchController.cs",
                                                                  "symbol": "Search"}}]))
        finding = self._finding("// SINK:tainted-local")
        deployment_context.apply_exposure([finding], ctx, PROJECT)
        self.assertEqual(finding["exploitability_context"]["exposure"], "internet")

    def test_a_finding_outside_any_declared_handler_keeps_its_exposure(self):
        ctx = deployment_context.load(doc(endpoints=[{"id": "ep", "exposure": "public",
                                                      "handler": {"file": "Controllers/SearchController.cs",
                                                                  "symbol": "Search"}}]))
        finding = self._finding("// SINK:unrouted")
        finding["exploitability_context"]["exposure"] = "unknown"
        deployment_context.apply_exposure([finding], ctx, PROJECT)
        self.assertEqual(finding["exploitability_context"]["exposure"], "unknown")

    def test_the_context_document_is_not_mutated_by_loading(self):
        original = doc(endpoints=[{"id": "ep", "exposure": "private"}])
        before = copy.deepcopy(original)
        deployment_context.load(original)
        self.assertEqual(original, before)


if __name__ == "__main__":
    unittest.main()
