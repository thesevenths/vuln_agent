"""
集成测试：模拟 6/16 审计日志中的 Planner 空转（反复 targeted_scan + 重复 read_file），
验证确定性状态机在有限步数内收口，无需真实 Joern/LLM。
"""
import os
import unittest
from unittest.mock import MagicMock

from audit_log_isolation import isolated_planner_audit_log
from planner import AgentPlannerExecutor
from state import AgentState


class TestPlannerIntegrationSpin(unittest.TestCase):
    def _post_l2_state(self) -> AgentState:
        state = AgentState()
        state.set_project("E:/joern/mbedtls", local_source_path="E:/proj")
        state.language = "c"
        state.ambiguous_flows = [
            {
                "flow_id": "flow-pkcs7",
                "vuln_type": "cpp_buffer_overflow",
                "analysis": "是否真实漏洞：⚠️ 部分是",
            }
        ]
        state.metadata["source_scan_count"] = 1
        state.metadata["pending_l2_reads"] = []
        state.metadata["file_evidence_reads"] = [
            {"path": "E:/proj/library/pkcs7.c", "lines": "564-572"},
        ]
        state.metadata["file_evidence_content"] = [
            {
                "path": "E:/proj/library/pkcs7.c",
                "start_line": 564,
                "end_line": 572,
                "content_preview": "memcpy(buf, src, len);",
            }
        ]
        state.metadata["skill_runtime"] = {
            "expert_cpp_buffer_overflow": {
                "current_node_id": "targeted_scan",
                "history": [{"node_id": "set_context", "ok": True}],
                "done": False,
            }
        }
        return state

    def _bad_llm_plans(self, call_index: dict):
        def complete_json(**kwargs):
            call_index["n"] = call_index.get("n", 0) + 1
            n = call_index["n"]
            if n % 2 == 1:
                return {
                    "done": False,
                    "plan_summary": "stub targeted_scan",
                    "next_action": {
                        "tool_name": "JoernTool.run_targeted_scan",
                        "arguments": {
                            "vuln_types": ["cpp_buffer_overflow"],
                        },
                    },
                    "final_answer": "",
                }
            return {
                "done": False,
                "plan_summary": "stub dup read",
                "next_action": {
                    "tool_name": "FileTool.read_file",
                    "arguments": {
                        "path": "library/pkcs7.c",
                        "start_line": 564,
                        "end_line": 572,
                    },
                },
                "final_answer": "",
            }

        return complete_json

    def test_spin_loop_finishes_within_step_budget(self):
        graph = MagicMock()
        graph.joern.ensure_cpg.return_value = True
        graph.run_source_scan.return_value = {
            "ok": True,
            "flows": {},
            "report": "# scan report\n是否真实漏洞：❌ 否\n",
            "ambiguous_flows": [],
            "flow_findings_index": [],
        }
        graph.joern.run_targeted_source_scan.return_value = {
            "ok": True,
            "flows": {},
            "report": "",
            "ambiguous_flows": [],
        }

        executor = AgentPlannerExecutor(graph=graph, max_steps=25)
        llm = MagicMock()
        llm.complete_json.side_effect = self._bad_llm_plans({})
        executor.llm_client = llm
        executor.file_tool.resolve_allowed_path = MagicMock(
            return_value="E:/proj/library/pkcs7.c"
        )
        executor.file_tool.read_file = MagicMock(
            return_value={
                "ok": True,
                "path": "E:/proj/library/pkcs7.c",
                "start_line": 564,
                "end_line": 572,
                "content": "cached",
            }
        )

        state = self._post_l2_state()
        with isolated_planner_audit_log(extra_env={"PLANNER_MAX_SOURCE_SCAN": "2"}) as audit_path:
            result = executor.run(state, "分析 mbedtls buffer overflow")
            self.assertTrue(os.path.isfile(audit_path), "审计日志应写入 planner_audit_logs_integret_test")
            self.assertTrue(result.get("audit_log_path"), result)
            self.assertEqual(result.get("audit_log_path"), audit_path)
            base, _ = os.path.splitext(audit_path)
            self.assertTrue(os.path.isfile(base + ".html"))
            self.assertTrue(os.path.isfile(base + ".md"))

        self.assertLessEqual(
            len(state.plan_history),
            20,
            f"步数过多，仍可能空转: {len(state.plan_history)}",
        )
        scan_count = int(state.metadata.get("source_scan_count", 0))
        self.assertGreaterEqual(scan_count, 2, "应至少触发第二次增量扫描")
        finish_events = [
            e
            for e in (state.metadata.get("_audit_events") or [])
            if e.get("event_type") == "run_finished"
        ]
        if not finish_events:
            self.assertTrue(
                state.last_planner_answer or state.last_report,
                "应以报告或 final_answer 收口",
            )


if __name__ == "__main__":
    unittest.main()
