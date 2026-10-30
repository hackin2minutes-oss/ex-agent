import tempfile
import unittest
from pathlib import Path

from engine import preconditions, symbols

DIFF = """diff --git a/src/main/java/com/acme/Parser.java b/src/main/java/com/acme/Parser.java
--- a/src/main/java/com/acme/Parser.java
+++ b/src/main/java/com/acme/Parser.java
@@ -10,9 +10,9 @@ public class Parser {
-    public Object parse(String input) {
+    public Object parse(String input, boolean strict) {
-        return parse(input);
+        return parse(input, false);
-    public Parser() {
-    }
+    }
"""


class SymbolsFromDiffTest(unittest.TestCase):
    def test_extracts_removed_method_declarations_only(self):
        self.assertEqual(symbols.symbols_from_diff(DIFF), ["com.acme.Parser.parse"])

    def test_ignores_non_java_files(self):
        diff = "+++ b/README.md\n-    public void parse(String x) {\n"
        self.assertEqual(symbols.symbols_from_diff(diff), [])

    def test_fqcn_from_maven_layout(self):
        self.assertEqual(symbols.fqcn_from_path("src/main/java/com/acme/x/Parser.java"),
                         "com.acme.x.Parser")


class PreconditionsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "Handler.java").write_text("Parser.parse(input);\n")

    def checks(self, regex, kind):
        return [{"id": "c", "kind": kind, "glob": "**/*.java", "regex": regex}]

    def test_no_rule_is_unverified(self):
        self.assertEqual(preconditions.evaluate(None, self.root)[0], "unverified")

    def test_requires_match_is_satisfied(self):
        status, _ = preconditions.evaluate(self.checks(r"Parser\.parse\(", "requires"), self.root)
        self.assertEqual(status, "satisfied")

    def test_requires_without_match_is_unverified_not_refuted(self):
        status, _ = preconditions.evaluate(self.checks(r"NeverThere", "requires"), self.root)
        self.assertEqual(status, "unverified")

    def test_mitigation_present_is_not_satisfied(self):
        status, _ = preconditions.evaluate(self.checks(r"Parser\.parse\(", "mitigated_by"), self.root)
        self.assertEqual(status, "not_satisfied")

    def test_mitigation_absent_stays_unverified(self):
        status, _ = preconditions.evaluate(self.checks(r"NeverThere", "mitigated_by"), self.root)
        self.assertEqual(status, "unverified")

    def test_mixed_checks_are_unverified_unless_all_satisfied(self):
        checks = self.checks(r"Parser\.parse\(", "requires") + self.checks(r"NeverThere", "mitigated_by")
        status, _ = preconditions.evaluate(checks, self.root)
        self.assertEqual(status, "unverified")

    def test_unknown_kind_is_an_error(self):
        with self.assertRaises(ValueError):
            preconditions.evaluate(self.checks("x", "whatever"), self.root)


if __name__ == "__main__":
    unittest.main()
