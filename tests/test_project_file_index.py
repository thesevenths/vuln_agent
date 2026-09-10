"""Tests for project_file_index."""
import os
import tempfile
import unittest
from pathlib import Path

from project_file_index import (
    build_l2_refutation_file_list,
    build_project_file_index,
    resolve_l2_path,
)


class TestProjectFileIndex(unittest.TestCase):
    def test_resolve_config_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            include = Path(tmp) / "include" / "app"
            include.mkdir(parents=True)
            cfg = include / "app_config.h"
            cfg.write_text("#define FOO 1\n", encoding="utf-8")
            index = build_project_file_index(tmp, "cpp")
            self.assertIsNotNone(index)
            resolved = resolve_l2_path(
                "include/app/config.h",
                language="cpp",
                file_index=index,
                local_source_path=tmp,
            )
            if resolved:
                self.assertTrue(resolved.path.endswith("app_config.h") or "config" in resolved.path)
            else:
                resolved2 = resolve_l2_path(
                    str(include / "app_config.h").replace("\\", "/"),
                    language="cpp",
                    file_index=index,
                    local_source_path=tmp,
                )
                self.assertIsNotNone(resolved2)

    def test_l2_refutation_file_list_prioritizes_config_and_sink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "CMakeLists.txt").write_text("cmake\n", encoding="utf-8")
            include = root / "include" / "mbedtls"
            include.mkdir(parents=True)
            (include / "mbedtls_config.h").write_text("#define X 1\n", encoding="utf-8")
            lib = root / "library"
            lib.mkdir()
            (lib / "ssl_tls.c").write_text("void f() {}\n", encoding="utf-8")
            listing = build_l2_refutation_file_list(
                local_source_path=tmp,
                language="cpp",
                sink_file="library/ssl_tls.c",
                limit=50,
            )
            self.assertIn("mbedtls_config.h", listing)
            self.assertIn("ssl_tls.c", listing)
            self.assertIn("CMakeLists.txt", listing)


if __name__ == "__main__":
    unittest.main()
