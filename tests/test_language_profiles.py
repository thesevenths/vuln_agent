"""Tests for language_profiles."""
import unittest

from language_profiles import get_language_profile, get_l2_config_globs, normalize_profile_language


class TestLanguageProfiles(unittest.TestCase):
    def test_c_normalizes_to_cpp(self):
        self.assertEqual(normalize_profile_language("c"), "cpp")

    def test_java_has_build_files(self):
        profile = get_language_profile("java")
        self.assertIn("pom.xml", profile.build_file_names)

    def test_cpp_denies_pom(self):
        profile = get_language_profile("cpp")
        self.assertIn("pom.xml", profile.l2_deny_basenames)

    def test_config_globs_not_empty(self):
        self.assertTrue(len(get_l2_config_globs("python")) >= 2)


if __name__ == "__main__":
    unittest.main()
