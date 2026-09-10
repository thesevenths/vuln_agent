"""Tests for inconclusive flow closure and Skill gate."""
import unittest

from planner import AgentPlannerExecutor
from state import AgentState


class TestInconclusiveClosure(unittest.TestCase):
    def _executor(self):
        return AgentPlannerExecutor(graph=object(), llm_client=object())

    def test_skill_blocked_while_inconclusive_unread_l2(self):
        ex = self._executor()
        state = AgentState()
        state.metadata["flow_findings_index"] = [
            {
                "flow_id": "cpp_buffer_overflow-flow-2",
                "refutation_verdict": "inconclusive",
            }
        ]
        state.metadata["pending_l2_reads"] = [
            {
                "path": "library/pkcs7.c",
                "flow_id": "cpp_buffer_overflow-flow-2",
                "refutation_verdict": "inconclusive",
                "kind": "source",
            }
        ]
        blocked = ex._check_planner_action_gate(state, "Skill.run")
        self.assertIsNotNone(blocked)
        self.assertEqual(
            (blocked.get("result") or {}).get("reason"),
            "inconclusive_closure_pending",
        )

    def test_forced_closure_prefers_expand_before_read(self):
        ex = self._executor()
        state = AgentState()
        state.language = "cpp"
        state.metadata["flow_findings_index"] = [
            {
                "flow_id": "cpp_buffer_overflow-flow-2",
                "refutation_verdict": "inconclusive",
                "vuln_type": "cpp_buffer_overflow",
            }
        ]
        state.metadata["flow_catalog"] = {
            "cpp_buffer_overflow-flow-2": {
                "flow_id": "cpp_buffer_overflow-flow-2",
                "vuln_type": "cpp_buffer_overflow",
                "sink_label": "library/pkcs7.c:570 memcpy",
                "flow_text": "joern flow text",
            }
        }
        state.metadata["pending_l2_reads"] = [
            {
                "path": "library/pkcs7.c",
                "flow_id": "cpp_buffer_overflow-flow-2",
                "refutation_verdict": "inconclusive",
                "kind": "source",
                "start_line": 540,
                "end_line": 600,
            }
        ]
        forced = ex._forced_inconclusive_flow_closure(state)
        self.assertIsNotNone(forced)
        self.assertEqual(
            forced["next_action"]["tool_name"],
            "JoernTool.expand_flow_context",
        )


if __name__ == "__main__":
    unittest.main()
