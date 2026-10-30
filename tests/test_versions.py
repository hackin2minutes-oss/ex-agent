import unittest

from engine import versions


class MavenVersionTest(unittest.TestCase):
    def cmp(self, a, b):
        return versions.compare("Maven", a, b)

    def test_numbers_compare_numerically_not_as_strings(self):
        self.assertEqual(self.cmp("2.10.0", "2.9.0"), 1)

    def test_trailing_zero_is_equivalent(self):
        self.assertEqual(self.cmp("1.0", "1.0.0"), 0)

    def test_qualifiers_sort_below_release(self):
        self.assertEqual(self.cmp("2.4.0-RC1", "2.4.0"), -1)
        self.assertEqual(self.cmp("2.4.0-beta", "2.4.0-alpha"), 1)
        self.assertEqual(self.cmp("2.4.0-rc1", "2.4.0-beta2"), 1)

    def test_release_ga_and_final_are_equal(self):
        self.assertEqual(self.cmp("2.4.0.GA", "2.4.0"), 0)
        self.assertEqual(self.cmp("2.4.0.Final", "2.4.0"), 0)

    def test_number_sorts_above_qualifier(self):
        self.assertEqual(self.cmp("2.4.0.1", "2.4.0-rc1"), 1)

    def test_sp_sorts_above_release(self):
        self.assertEqual(self.cmp("2.4.0-sp1", "2.4.0"), 1)

    def test_snapshot_below_release(self):
        self.assertEqual(self.cmp("2.4.1-SNAPSHOT", "2.4.1"), -1)
        self.assertEqual(self.cmp("2.4.1-SNAPSHOT", "2.4.0"), 1)


class SemverTest(unittest.TestCase):
    def cmp(self, a, b):
        return versions.compare("npm", a, b)

    def test_core_numbers(self):
        self.assertEqual(self.cmp("1.10.0", "1.9.9"), 1)

    def test_prerelease_below_release(self):
        self.assertEqual(self.cmp("1.0.0-rc.1", "1.0.0"), -1)

    def test_prerelease_identifier_precedence(self):
        self.assertEqual(self.cmp("1.0.0-alpha", "1.0.0-alpha.1"), -1)
        self.assertEqual(self.cmp("1.0.0-alpha.2", "1.0.0-alpha.10"), -1)
        self.assertEqual(self.cmp("1.0.0-1", "1.0.0-alpha"), -1)

    def test_build_metadata_is_ignored(self):
        self.assertEqual(self.cmp("1.0.0+build.5", "1.0.0"), 0)

    def test_invalid_version_is_unsupported(self):
        self.assertIsNone(self.cmp("1.0", "1.0.0"))


class PyPiVersionTest(unittest.TestCase):
    def test_release_segments_compare_numerically(self):
        self.assertEqual(versions.compare("PyPI", "5.10", "5.9"), 1)
        self.assertEqual(versions.compare("PyPI", "5.1", "5.1.0"), 0)
        self.assertTrue(versions.is_affected("PyPI", "5.0.0", "0", "5.1"))
        self.assertFalse(versions.is_affected("PyPI", "5.3.1", "0", "5.1"))
        self.assertFalse(versions.is_affected("PyPI", "5.1", "0", "5.1"))

    def test_pre_releases_are_unsupported(self):
        self.assertIsNone(versions.compare("PyPI", "5.1rc1", "5.1"))


class UnsupportedTest(unittest.TestCase):
    def test_other_ecosystems_are_unsupported(self):
        self.assertIsNone(versions.compare("Go", "1.0", "2.0"))
        self.assertIsNone(versions.is_affected("RubyGems", "1.0", "0", "2.0"))


class RangeTest(unittest.TestCase):
    def test_introduced_inclusive_fixed_exclusive(self):
        self.assertTrue(versions.is_affected("Maven", "2.0.0", "2.0.0", "2.4.1"))
        self.assertFalse(versions.is_affected("Maven", "2.4.1", "2.0.0", "2.4.1"))

    def test_release_candidate_before_fix_is_affected(self):
        self.assertTrue(versions.is_affected("Maven", "2.4.1-RC1", "2.0.0", "2.4.1"))

    def test_unsupported_range_returns_none(self):
        self.assertIsNone(versions.is_affected("npm", "1.0", "0.0.0", "2.0.0"))


if __name__ == "__main__":
    unittest.main()
