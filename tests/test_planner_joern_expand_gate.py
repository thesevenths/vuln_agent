"""Tests for Joern expand_flow_context gate before source FileTool reads."""
import os
import unittest
from unittest.mock import MagicMock

from planner import AgentPlannerExecutor, PLANNER_FLOW_EXPAND_MAX_ITERS
from state import AgentState


class TestJoernExpandGate(unittest.TestCase):
    def _make_state(self) -> AgentState:
        state = AgentState()
        state.set_local_source_path("C:/proj")
        state.language = "cpp"
        state.metadata["flow_catalog"] = {
            "flow-1": {
                "flow_id": "flow-1",
                "vuln_type": "cpp_buffer_overflow",
                "sink_label": "memcpy@ssl_msg.c:120",
                "flow_text": "│ memcpy(...)",
            }
        }
        state.metadata["pending_l2_reads"] = [
            {
                "path": "library/ssl_msg.c",
                "flow_id": "flow-1",
                "kind": "source",
                "refutation_verdict": "inconclusive",
                "vuln_type": "cpp_buffer_overflow",
            }
        ]
        return state

    def test_config_read_not_gated(self):
        executor = AgentPlannerExecutor(MagicMock())
        state = self._make_state()
        blocked, reason = executor._source_read_gate_blocked(
            state, path="include/mbedtls/config.h", kind="config"
        )
        self.assertFalse(blocked)
        self.assertEqual(reason, "")

    def test_source_read_blocked_without_expand(self):
        executor = AgentPlannerExecutor(MagicMock())
        state = self._make_state()
        blocked, reason = executor._source_read_gate_blocked(
            state, path="library/ssl_msg.c", kind="source", flow_id="flow-1"
        )
        self.assertTrue(blocked)
        self.assertIn("expand_flow_context", reason)

    def test_source_read_allowed_after_exhausted_expand(self):
        executor = AgentPlannerExecutor(MagicMock())
        state = self._make_state()
        state.metadata["flow_joern_expansion"] = {
            "flow-1": {
                "called": True,
                "exhausted": True,
                "sufficient": False,
                "iterations_used": PLANNER_FLOW_EXPAND_MAX_ITERS,
                "max_iters": PLANNER_FLOW_EXPAND_MAX_ITERS,
            }
        }
        blocked, _ = executor._source_read_gate_blocked(
            state, path="library/ssl_msg.c", kind="source", flow_id="flow-1"
        )
        self.assertFalse(blocked)

    def test_gate_skipped_via_env(self):
        executor = AgentPlannerExecutor(MagicMock())
        state = self._make_state()
        old = os.environ.get("PLANNER_SKIP_JOERN_EXPAND_GATE")
        os.environ["PLANNER_SKIP_JOERN_EXPAND_GATE"] = "1"
        try:
            needs = executor._flow_needs_joern_expand_before_source_read(state, "flow-1")
            self.assertFalse(needs)
        finally:
            if old is None:
                os.environ.pop("PLANNER_SKIP_JOERN_EXPAND_GATE", None)
            else:
                os.environ["PLANNER_SKIP_JOERN_EXPAND_GATE"] = old

    def test_forced_action_prefers_expand(self):
        executor = AgentPlannerExecutor(MagicMock())
        state = self._make_state()
        forced = executor._forced_action_after_finish_block(state)
        self.assertIsNotNone(forced)
        self.assertEqual(
            forced["next_action"]["tool_name"],
            "JoernTool.expand_flow_context",
        )
        self.assertEqual(forced["next_action"]["arguments"]["flow_id"], "flow-1")


if __name__ == "__main__":
    unittest.main()
