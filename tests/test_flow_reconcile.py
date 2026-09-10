"""Tests for ambiguous flow reconciliation and read overlap dedup."""
import unittest

from flow_reconcile import (
    build_bounded_finish_report,
    reconcile_ambiguous_flows,
    update_flow_findings_l2_status,
)
from planner import AgentPlannerExecutor


class TestReadOverlapDedup(unittest.TestCase):
    def test_overlap_coverage_counts_partial_overlap(self):
        self.assertTrue(
            AgentPlannerExecutor._line_range_overlap_coverage(60, 80, [(55, 85)])
        )
        self.assertFalse(
            AgentPlannerExecutor._line_range_overlap_coverage(60, 80, [(10, 20)])
        )

    def test_line_range_covered_uses_overlap(self):
        self.assertTrue(AgentPlannerExecutor._line_range_covered(600, 800, [(550, 850)]))


class TestFlowReconcile(unittest.TestCase):
    def test_l2_read_updates_findings_and_closes_ambiguous(self):
        metadata = {
            "flow_findings_index": [
                {
                    "flow_id": "flow-1",
                    "vuln_type": "buffer_overflow",
                    "refutation_verdict": "likely_false_positive",
                    "l2_status": "absent",
                }
            ],
            "pending_l2_reads": [
                {
                    "flow_id": "flow-1",
                    "path": "include/mbedtls/config.h",
                }
            ],
            "file_evidence_reads": [
                {"path": "E:/proj/include/mbedtls/config.h", "lines": "1-200"},
            ],
            "file_evidence_content": [
                {
                    "path": "E:/proj/include/mbedtls/config.h",
                    "start_line": 1,
                    "end_line": 200,
                    "content_preview": "#define MBEDTLS_SSL_PROTO_TLS1_2",
                }
            ],
        }
        ambiguous = [
            {
                "flow_id": "flow-1",
                "vuln_type": "buffer_overflow",
                "analysis": "是否真实漏洞：⚠️ 部分是\n",
                "meta": {
                    "backtrace": {"stop_reason": "guard_logic_found"},
                    "refutation": {"verdict": "likely_false_positive"},
                },
            }
        ]
        update_flow_findings_l2_status(metadata, local_source_path="E:/proj")
        result = reconcile_ambiguous_flows(
            ambiguous, metadata, local_source_path="E:/proj"
        )
        self.assertEqual(len(result["remaining"]), 0)
        self.assertEqual(result["resolved"][0]["flow_id"], "flow-1")

    def test_l2_present_inconclusive_moves_to_l3(self):
        metadata = {
            "flow_findings_index": [
                {
                    "flow_id": "flow-2",
                    "vuln_type": "xss",
                    "refutation_verdict": "inconclusive",
                    "l2_status": "present",
                }
            ],
            "pending_l2_reads": [
                {"flow_id": "flow-2", "path": "include/config.h"},
            ],
            "file_evidence_reads": [
                {"path": "E:/proj/include/config.h", "lines": "1-50"},
            ],
        }
        ambiguous = [
            {
                "flow_id": "flow-2",
                "vuln_type": "xss",
                "analysis": "是否真实漏洞：⚠️ 部分是\n",
                "meta": {"refutation": {"verdict": "inconclusive"}},
            }
        ]
        result = reconcile_ambiguous_flows(
            ambiguous, metadata, local_source_path="E:/proj"
        )
        self.assertEqual(len(result["remaining"]), 0)
        self.assertEqual(len(result["needs_l3"]), 1)

    def test_bounded_finish_report_mentions_unresolved(self):
        report = build_bounded_finish_report(
            last_report="scan body",
            ambiguous_flows=[{"flow_id": "f1", "vuln_type": "xss", "previous_verdict": "待确认"}],
            source_scan_count=2,
            max_scan=2,
        )
        self.assertIn("未决", report)
        self.assertIn("f1", report)
        self.assertIn("未完全收敛", report)

    def test_bounded_finish_report_skips_double_bounded(self):
        bounded = "# 漏洞审计终态报告\n> 源码扫描次数: 2/2\n"
        report = build_bounded_finish_report(
            last_report=bounded,
            ambiguous_flows=[],
            source_scan_count=2,
            max_scan=2,
            flow_findings_index=[{"refutation_verdict": "confirmed"}],
        )
        self.assertEqual(report.count("源码扫描次数"), 1)
        self.assertIn("已确认", report)

    def test_empty_pending_does_not_close_on_unrelated_reads(self):
        metadata = {
            "flow_findings_index": [
                {
                    "flow_id": "flow-9",
                    "vuln_type": "buffer_overflow",
                    "refutation_verdict": "inconclusive",
                    "l2_status": "absent",
                }
            ],
            "pending_l2_reads": [],
            "file_evidence_reads": [
                {"path": "E:/proj/library/ssl_tls.c", "lines": "1-200"},
            ],
        }
        ambiguous = [
            {
                "flow_id": "flow-9",
                "vuln_type": "buffer_overflow",
                "analysis": "是否真实漏洞：⚠️ 部分是\n",
                "meta": {"refutation": {"verdict": "inconclusive"}},
            }
        ]
        result = reconcile_ambiguous_flows(
            ambiguous, metadata, local_source_path="E:/proj"
        )
        self.assertEqual(len(result["remaining"]), 1)
        self.assertEqual(result["remaining"][0]["flow_id"], "flow-9")


if __name__ == "__main__":
    unittest.main()
