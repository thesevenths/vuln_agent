import unittest
from unittest.mock import MagicMock

from planner import AgentPlannerExecutor
from state import AgentState


class PlannerLogicFinishGateTest(unittest.TestCase):
    def _executor(self) -> AgentPlannerExecutor:
        return AgentPlannerExecutor(graph=MagicMock(), max_steps=5)

    def test_logic_query_failures_block_finish_until_retry(self):
        executor = self._executor()
        state = AgentState(project_path="/app/vuln_app", language="java")
        state.metadata["logic_scan_count"] = 1
        state.metadata["logic_query_failures"] = ["sensitive_operations", "idor_candidates"]

        gate = executor._prepare_finish_gate(state)
        self.assertIn("sensitive_operations", gate["blocker"])

        forced = executor._build_forced_logic_followup_action(state)
        self.assertEqual(
            forced["next_action"]["tool_name"],
            "JoernTool.run_logic_scan",
        )

    def test_after_retry_java_requires_attack_surface(self):
        executor = self._executor()
        state = AgentState(project_path="/app/vuln_app", language="java")
        state.metadata["logic_scan_count"] = 2
        state.metadata["logic_query_failures"] = ["sensitive_operations"]

        blocker = executor._logic_scan_finish_blocker(state)
        self.assertIn("java_attack_surface", blocker)

        forced = executor._build_forced_logic_followup_action(state)
        self.assertEqual(forced["next_action"]["tool_name"], "Skill.run")
        self.assertEqual(
            forced["next_action"]["arguments"]["skill_id"],
            "java_attack_surface",
        )

    def test_no_blocker_when_logic_scan_clean(self):
        executor = self._executor()
        state = AgentState(language="java")
        state.metadata["logic_scan_count"] = 1
        state.metadata["logic_query_failures"] = []

        self.assertIsNone(executor._logic_scan_finish_blocker(state))


if __name__ == "__main__":
    unittest.main()
