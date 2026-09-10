"""Tests for planner stall recovery, incremental scan injection, and skill continuation."""
import unittest
from unittest.mock import MagicMock

from planner import (
    AgentPlannerExecutor,
    PLANNER_BLOCKED_SCAN_FORCE_AFTER,
    PLANNER_DUP_READ_STALL_THRESHOLD,
)


class TestPlannerStallRecovery(unittest.TestCase):
    def _executor(self):
        return AgentPlannerExecutor(graph=MagicMock())

    def _state_with_ambiguous(self, *, scan_count=1, pending=None):
        state = MagicMock()
        state.ambiguous_flows = [{"flow_id": "f-1", "vuln_type": "buffer_overflow"}]
        state.local_source_path = "E:/proj"
        state.metadata = {
            "source_scan_count": scan_count,
            "pending_l2_reads": pending or [],
            "file_evidence_reads": [],
        }
        state.plan_history = []
        return state

    def test_allows_incremental_scan_when_ambiguous_and_l2_done(self):
        executor = self._executor()
        state = self._state_with_ambiguous(scan_count=1)
        blocked = executor._check_planner_action_gate(
            state, "JoernTool.run_source_scan"
        )
        self.assertIsNone(blocked)

    def test_blocks_targeted_scan_suggests_incremental_when_l2_done(self):
        executor = self._executor()
        state = self._state_with_ambiguous(scan_count=1)
        blocked = executor._check_planner_action_gate(
            state,
            "JoernTool.run_targeted_scan",
            action_arguments={"vuln_types": ["cpp_buffer_overflow"]},
        )
        self.assertIsNone(blocked)

    def test_preempt_injects_incremental_scan_after_blocked_targeted(self):
        executor = self._executor()
        state = self._state_with_ambiguous(scan_count=1)
        state.metadata["blocked_scan_attempts"] = PLANNER_BLOCKED_SCAN_FORCE_AFTER
        forced = executor._maybe_preempt_planner_with_forced_action(state)
        self.assertIsNotNone(forced)
        self.assertEqual(
            forced["next_action"]["tool_name"], "JoernTool.run_source_scan"
        )

    def test_duplicate_read_stall_triggers_incremental_scan(self):
        executor = self._executor()
        state = self._state_with_ambiguous(scan_count=1)
        state.metadata["duplicate_read_stalls"] = {
            "e:/proj/library/pkcs7.c:564-572": PLANNER_DUP_READ_STALL_THRESHOLD
        }
        forced = executor._forced_action_on_planner_stall(state)
        self.assertIsNotNone(forced)
        self.assertEqual(
            forced["next_action"]["tool_name"], "JoernTool.run_source_scan"
        )

    def test_duplicate_read_stall_bounded_finish_when_scan_exhausted(self):
        executor = self._executor()
        state = self._state_with_ambiguous(scan_count=2)
        state.metadata["duplicate_read_stalls"] = {
            "e:/proj/library/pkcs7.c:564-572": PLANNER_DUP_READ_STALL_THRESHOLD
        }
        forced = executor._forced_action_on_planner_stall(state)
        self.assertIsNotNone(forced)
        self.assertTrue(forced.get("done"))
        self.assertEqual(forced["next_action"]["tool_name"], "finish")

    def test_skill_hijack_forces_skill_run(self):
        executor = self._executor()
        state = MagicMock()
        state.ambiguous_flows = []
        state.local_source_path = "E:/proj"
        state.metadata = {
            "source_scan_count": 2,
            "pending_l2_reads": [],
            "skill_runtime": {
                "expert_cpp_buffer_overflow": {
                    "current_node_id": "read_sink_code",
                    "history": [{"node_id": "targeted_scan", "ok": False}],
                    "done": False,
                }
            },
        }
        state.plan_history = [
            {
                "step": 5,
                "action": {
                    "tool_name": "FileTool.read_file",
                    "arguments": {"path": "library/pkcs7.c"},
                },
                "observation": {"ok": True, "tool_name": "FileTool.read_file"},
            }
        ]
        self.assertTrue(executor._planner_hijacked_active_skill(state))
        forced = executor._forced_skill_continuation(state)
        self.assertIsNotNone(forced)
        self.assertEqual(forced["next_action"]["tool_name"], "Skill.run")

    def test_skill_hijack_not_during_unread_l2(self):
        executor = self._executor()
        state = MagicMock()
        state.ambiguous_flows = [{"flow_id": "f-1"}]
        state.metadata = {
            "source_scan_count": 1,
            "pending_l2_reads": [{"flow_id": "f-1", "path": "include/config.h"}],
            "file_evidence_reads": [],
            "skill_runtime": {
                "expert_cpp_buffer_overflow": {
                    "current_node_id": "targeted_scan",
                    "history": [{"node_id": "set_context", "ok": True}],
                    "done": False,
                }
            },
        }
        state.plan_history = [
            {
                "action": {"tool_name": "FileTool.read_file"},
                "observation": {"ok": True},
            }
        ]
        executor._is_l2_path_already_read = MagicMock(return_value=False)
        self.assertFalse(executor._planner_hijacked_active_skill(state))

    def test_read_spin_triggers_incremental_scan(self):
        executor = self._executor()
        state = self._state_with_ambiguous(scan_count=1)
        state.plan_history = [
            {"action": {"tool_name": "FileTool.read_file"}, "observation": {"ok": True}},
            {"action": {"tool_name": "FileTool.read_file"}, "observation": {"ok": True}},
            {"action": {"tool_name": "FileTool.read_file"}, "observation": {"ok": True}},
        ]
        self.assertTrue(executor._detect_planner_read_spin(state))
        forced = executor._maybe_preempt_planner_with_forced_action(state)
        self.assertEqual(
            forced["next_action"]["tool_name"], "JoernTool.run_source_scan"
        )


class TestBoundedConfirmedCount(unittest.TestCase):
    def test_no_false_confirmed_from_draft_markdown(self):
        from flow_reconcile import build_bounded_finish_report

        report = build_bounded_finish_report(
            last_report="是否真实漏洞：✅ 是\n系统覆写为 ❌ 否",
            ambiguous_flows=[{"flow_id": "f1", "vuln_type": "xss"}],
            source_scan_count=2,
            max_scan=2,
            flow_findings_index=[
                {"refutation_verdict": "likely_false_positive"},
            ],
        )
        self.assertNotIn("已确认 **1**", report)
        self.assertIn("未完全收敛", report)


if __name__ == "__main__":
    unittest.main()
