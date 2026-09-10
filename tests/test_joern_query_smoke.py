"""
可选 Joern 真机冒烟：对 queries.py 中登记的 DSL 逐条执行，断言无编译/语法错误。

默认跳过（CI 无 Joern 时不应失败）。本地有 WebGoat CPG 时：

    set JOERN_QUERY_SMOKE=1
    set JOERN_URL=http://...
    set JOERN_PROJECT_NAME=...
    python -m unittest discover -s tests -p test_joern_query_smoke.py -v
"""
from __future__ import annotations

import os
import unittest

import queries
from logic_query_validate import is_joern_query_failure


def _joern_smoke_enabled() -> bool:
    return os.environ.get("JOERN_QUERY_SMOKE", "0") == "1"


@unittest.skipUnless(_joern_smoke_enabled(), "set JOERN_QUERY_SMOKE=1 to run live Joern smoke")
class JoernQuerySmokeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from joern_vuln_scanner import JoernVulnScannerHTTP

        cls.scanner = JoernVulnScannerHTTP()
        if not cls.scanner._health_check():
            raise unittest.SkipTest(
                f"Joern 不可达: {cls.scanner.joern_url}（检查 JOERN_URL / 服务是否启动）"
            )
        if not cls.scanner._verify_project_query_ready():
            raise unittest.SkipTest(
                "Joern CPG 未就绪（检查 JOERN_PROJECT_NAME / importCode）"
            )

    def _assert_registry_compiles(self, registry_name: str, query_map: dict) -> None:
        failures: list[tuple[str, str]] = []
        for name, query in sorted(query_map.items()):
            result = self.scanner.run_query((query or "").strip())
            if is_joern_query_failure(result):
                failures.append((f"{registry_name}/{name}", result[:500]))
        self.assertEqual(
            failures,
            [],
            "Joern 查询执行失败:\n"
            + "\n---\n".join(f"{k}:\n{v}" for k, v in failures),
        )

    def test_java_logic_queries_compile_on_live_joern(self):
        self._assert_registry_compiles("java_logic_queries", queries.java_logic_queries)

    @unittest.skipUnless(
        os.environ.get("JOERN_QUERY_SMOKE_TAINT", "0") == "1",
        "set JOERN_QUERY_SMOKE_TAINT=1 to smoke-test taint queries (slower)",
    )
    def test_java_taint_queries_compile_on_live_joern(self):
        self._assert_registry_compiles("java_queries", queries.java_queries)


if __name__ == "__main__":
    unittest.main()

