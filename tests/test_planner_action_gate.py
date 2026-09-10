"""Tests for planner L2-closure action gates."""
import unittest
from unittest.mock import MagicMock

from planner import AgentPlannerExecutor, PLANNER_SKILL_BLOCKED_WHEN_CLOSURE_TOOLS


class TestPlannerActionGate(unittest.TestCase):
    def _executor(self):
        return AgentPlannerExecutor(graph=MagicMock())

    def test_blocks_run_taint_queries_when_ambiguous(self):
        executor = self._executor()
        state = MagicMock()
        state.ambiguous_flows = [{"flow_id": "f-1"}]
        state.metadata = {"pending_l2_reads": []}
        blocked = executor._check_planner_action_gate(
            state, "JoernTool.run_taint_queries"
        )
        self.assertIsNotNone(blocked)
        self.assertFalse(blocked["ok"])

    def test_allows_file_read_when_ambiguous(self):
        executor = self._executor()
        state = MagicMock()
        state.ambiguous_flows = [{"flow_id": "f-1"}]
        state.metadata = {"pending_l2_reads": []}
        blocked = executor._check_planner_action_gate(state, "FileTool.read_file")
        self.assertIsNone(blocked)

    def test_allows_targeted_scan_when_only_config_pending(self):
        executor = self._executor()
        state = MagicMock()
        state.ambiguous_flows = [{"flow_id": "f-1"}]
        state.metadata = {
            "pending_l2_reads": [
                {
                    "flow_id": "other-flow-1",
                    "path": "include/config.h",
                    "kind": "config",
                    "vuln_type": "cpp_integer_overflow",
                }
            ],
            "file_evidence_reads": [],
        }
        executor._is_l2_path_already_read = MagicMock(return_value=False)
        blocked = executor._check_planner_action_gate(
            state,
            "JoernTool.run_targeted_scan",
            action_arguments={"vuln_types": ["cpp_use_after_free"]},
        )
        self.assertIsNone(blocked)

    def test_blocks_targeted_scan_when_unread_source_l2_same_type(self):
        executor = self._executor()
        state = MagicMock()
        state.ambiguous_flows = []
        state.metadata = {
            "pending_l2_reads": [
                {
                    "flow_id": "cpp_use_after_free-flow-2",
                    "path": "library/ssl_tls.c",
                    "kind": "source",
                    "vuln_type": "cpp_use_after_free",
                }
            ],
            "file_evidence_reads": [],
        }
        executor._is_l2_path_already_read = MagicMock(return_value=False)
        blocked = executor._check_planner_action_gate(
            state,
            "JoernTool.run_targeted_scan",
            action_arguments={"vuln_types": ["cpp_use_after_free", "cpp_double_free"]},
        )
        self.assertIsNotNone(blocked)
        self.assertEqual(blocked["result"].get("reason"), "unread_source_l2_pending")
        self.assertIn("JoernTool.run_targeted_scan", PLANNER_SKILL_BLOCKED_WHEN_CLOSURE_TOOLS)

    def test_allows_targeted_scan_when_ambiguous_and_l2_config_done(self):
        executor = self._executor()
        state = MagicMock()
        state.ambiguous_flows = [{"flow_id": "f-1"}]
        state.metadata = {
            "source_scan_count": 1,
            "pending_l2_reads": [],
            "file_evidence_reads": [],
        }
        blocked = executor._check_planner_action_gate(
            state,
            "JoernTool.run_targeted_scan",
            action_arguments={"vuln_types": ["cpp_buffer_overflow"]},
        )
        self.assertIsNone(blocked)

    def test_blocks_source_scan_when_unread_l2(self):
        executor = self._executor()
        state = MagicMock()
        state.ambiguous_flows = [{"flow_id": "f-1"}]
        state.metadata = {
            "pending_l2_reads": [{"flow_id": "f-1", "path": "include/config.h"}],
            "file_evidence_reads": [],
            "source_scan_count": 0,
        }
        executor._is_l2_path_already_read = MagicMock(return_value=False)
        blocked = executor._check_planner_action_gate(
            state, "JoernTool.run_source_scan"
        )
        self.assertIsNotNone(blocked)
        self.assertEqual(blocked["result"].get("reason"), "unread_l2_pending")


if __name__ == "__main__":
    unittest.main()
