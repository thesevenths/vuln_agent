"""Tests for planner L2 dedup and ambiguous verdict alignment."""
import unittest
from unittest.mock import MagicMock

from joern_vuln_scanner import JoernVulnScannerHTTP as JoernVulnScanner
from planner import AgentPlannerExecutor


class TestFileEvidenceDedup(unittest.TestCase):
    def test_line_range_covered(self):
        self.assertTrue(AgentPlannerExecutor._line_range_covered(60, 80, [(46, 95)]))
        self.assertFalse(AgentPlannerExecutor._line_range_covered(35, 60, [(46, 95)]))

    def test_find_cached_when_range_already_read(self):
        path = "C:/proj/ssl_test.c"
        path_norm = AgentPlannerExecutor._normalize_evidence_path(path)
        reads = [{"path": path, "lines": "46-95"}]
        contents = [
            {
                "path": path,
                "start_line": 46,
                "end_line": 95,
                "content_preview": "nss_keylog_export",
            }
        ]
        cached = AgentPlannerExecutor(MagicMock())._find_cached_file_evidence(
            path_norm, 60, 80, reads, contents
        )
        self.assertIsNotNone(cached)
        self.assertIn("nss_keylog", cached.get("content_preview", ""))

    def test_get_known_file_total_lines_from_evidence(self):
        executor = AgentPlannerExecutor(MagicMock())
        state = MagicMock()
        state.metadata = {
            "file_evidence_content": [
                {
                    "path": "C:/proj/WebSecurityConfig.java",
                    "start_line": 1,
                    "end_line": 90,
                    "total_lines": 90,
                }
            ]
        }
        path_norm = AgentPlannerExecutor._normalize_evidence_path(
            "C:/proj/WebSecurityConfig.java"
        )
        self.assertEqual(executor._get_known_file_total_lines(state, path_norm), 90)

    def test_file_read_past_eof_result_message(self):
        executor = AgentPlannerExecutor(MagicMock())
        payload = executor._file_read_past_eof_result(
            tool_name="FileTool.read_file",
            file_path="WebSecurityConfig.java",
            resolved_path="C:/proj/WebSecurityConfig.java",
            req_start=91,
            req_end=300,
            total_lines=90,
        )
        self.assertTrue(payload["ok"])
        self.assertIn("共 90 行", payload["result_summary"])
        self.assertTrue(payload["result"].get("skipped_past_eof"))


class TestAmbiguousVerdict(unittest.TestCase):
    def test_clear_yes_not_ambiguous_despite_body_markers(self):
        analysis = (
            "是否真实漏洞：✅ 是\n"
            "L3 待动态验证，证据不足无法完全证实利用链。\n"
        )
        self.assertFalse(JoernVulnScanner._is_ambiguous_verdict(analysis))

    def test_clear_no_not_ambiguous(self):
        analysis = "是否真实漏洞：❌ 否\n反证：likely_false_positive\n"
        self.assertFalse(JoernVulnScanner._is_ambiguous_verdict(analysis))

    def test_partial_still_ambiguous(self):
        analysis = "是否真实漏洞：⚠️ 部分是\n"
        self.assertTrue(JoernVulnScanner._is_ambiguous_verdict(analysis))


if __name__ == "__main__":
    unittest.main()
