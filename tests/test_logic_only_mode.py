"""Tests for logic-only audit mode detection and planner gates."""
import unittest
from unittest.mock import MagicMock

from logic_scan_settings import detect_logic_only_intent
from planner import AgentPlannerExecutor


class TestLogicOnlyIntent(unittest.TestCase):
    def test_detects_chinese_logic_only(self):
        self.assertTrue(
            detect_logic_only_intent("请对 WebGoat 做逻辑漏洞扫描，鉴权越权 IDOR")
        )

    def test_rejects_when_taint_explicit(self):
        self.assertFalse(
            detect_logic_only_intent("逻辑漏洞和污点扫描都要做")
        )

    def test_rejects_taint_only(self):
        self.assertFalse(detect_logic_only_intent("跑一遍污点扫描找 SQLi"))


class TestLogicOnlyPlannerGate(unittest.TestCase):
    def _executor(self):
        return AgentPlannerExecutor(graph=MagicMock())

    def test_blocks_source_scan_in_logic_only_mode(self):
        executor = self._executor()
        state = MagicMock()
        state.ambiguous_flows = []
        state.metadata = {"audit_mode": "logic_only"}
        blocked = executor._check_planner_action_gate(
            state, "JoernTool.run_source_scan"
        )
        self.assertIsNotNone(blocked)
        self.assertEqual(blocked["result"].get("reason"), "logic_only_mode")

    def test_allows_logic_scan_in_logic_only_mode(self):
        executor = self._executor()
        state = MagicMock()
        state.ambiguous_flows = []
        state.metadata = {"audit_mode": "logic_only"}
        blocked = executor._check_planner_action_gate(
            state, "JoernTool.run_logic_scan"
        )
        self.assertIsNone(blocked)

    def test_blocks_taint_skill_in_logic_only_mode(self):
        executor = self._executor()
        state = MagicMock()
        state.ambiguous_flows = []
        state.metadata = {"audit_mode": "logic_only"}
        blocked = executor._check_planner_action_gate(
            state,
            "Skill.run",
            action_arguments={"skill_id": "source_0day_pipeline"},
        )
        self.assertIsNotNone(blocked)
        self.assertEqual(blocked["result"].get("reason"), "logic_only_mode")


if __name__ == "__main__":
    unittest.main()
