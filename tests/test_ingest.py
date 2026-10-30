import json
import unittest
from pathlib import Path

from engine import ingest

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "app"

GRADLE = """runtimeClasspath - Runtime classpath of compilation
+--- com.example:vulnerable-library:2.4.0
|    \\--- com.example:transitive-helper:1.1.0 -> 1.2.0
\\--- org.springframework:spring-web:6.1.0
     \\--- org.springframework:spring-core:6.1.0 (*)
"""

NPM_LOCK = json.dumps({"packages": {
    "": {"name": "app"},
    "node_modules/left-pad": {"version": "1.3.0"},
    "node_modules/a/node_modules/b": {"version": "2.0.0", "dev": True},
}})


class MavenTreeTest(unittest.TestCase):
    def test_parses_coordinates_scope_and_ancestry(self):
        deps = ingest.parse_maven_tree((FIXTURE / "maven-tree.txt").read_text())
        by_name = {d["name"]: d for d in deps}
        self.assertEqual(by_name["com.example:vulnerable-library"]["version"], "2.4.0")
        self.assertEqual(by_name["com.example:vulnerable-library"]["scope"], "compile")
        self.assertEqual(by_name["com.example:vulnerable-library"]["resolved_via"], ["fixture-app"])
        self.assertEqual(by_name["com.example:transitive-helper"]["resolved_via"],
                         ["fixture-app", "vulnerable-library"])
        self.assertEqual(by_name["org.springframework:spring-core"]["resolved_via"],
                         ["fixture-app", "spring-web"])
        self.assertEqual(len(deps), 4)


class GradleTest(unittest.TestCase):
    def test_parses_levels_and_resolved_versions(self):
        deps = {d["name"]: d for d in ingest.parse_gradle_dependencies(GRADLE)}
        self.assertEqual(deps["com.example:transitive-helper"]["version"], "1.2.0")
        self.assertEqual(deps["com.example:transitive-helper"]["resolved_via"],
                         ["vulnerable-library"])
        self.assertEqual(deps["org.springframework:spring-core"]["resolved_via"], ["spring-web"])
        self.assertEqual(len(deps), 4)


class OtherFormatsTest(unittest.TestCase):
    def test_npm_lock_keeps_dev_scope_for_the_pipeline_to_filter(self):
        deps = {d["name"]: d for d in ingest.parse_npm_lock(NPM_LOCK)}
        self.assertEqual(deps["left-pad"]["scope"], "runtime")
        self.assertEqual(deps["b"]["scope"], "dev")
        self.assertEqual(deps["b"]["ecosystem"], "npm")

    def test_requirements_pins_only(self):
        text = "Django==4.2.1\n# comment\nrequests==2.31.0 ; python_version>'3'\n-r other.txt\n"
        deps = ingest.parse_requirements(text)
        self.assertEqual([(d["name"], d["version"]) for d in deps],
                         [("django", "4.2.1"), ("requests", "2.31.0")])

    def test_resolved_json_round_trip(self):
        text = json.dumps({"manifest": "pom.xml", "dependencies": [
            {"ecosystem": "Maven", "name": "a:b", "version": "1.0", "scope": "runtime"}]})
        dep = ingest.parse_resolved_json(text)[0]
        self.assertEqual(dep["manifest"], "pom.xml")
        self.assertEqual(dep["resolved_via"], [])


class ResolveTest(unittest.TestCase):
    def test_uses_explicit_file(self):
        deps = ingest.resolve(FIXTURE, FIXTURE / "maven-tree.txt")
        self.assertEqual(len(deps), 4)

    def test_missing_input_is_an_actionable_error(self):
        with self.assertRaisesRegex(FileNotFoundError, "--deps"):
            ingest.resolve(Path("/nonexistent-project"), None)


class VersionTest(unittest.TestCase):
    def test_fixed_bound_is_exclusive(self):
        self.assertTrue(ingest.is_affected("2.4.0", "2.0.0", "2.4.1"))
        self.assertFalse(ingest.is_affected("2.4.1", "2.0.0", "2.4.1"))
        self.assertFalse(ingest.is_affected("1.9.9", "2.0.0", "2.4.1"))


if __name__ == "__main__":
    unittest.main()
