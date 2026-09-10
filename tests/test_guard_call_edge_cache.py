"""Tests for guard call-edge cache (caller/callee methodFullName)."""
import unittest
from unittest import mock

from joern_vuln_scanner import JoernVulnScannerHTTP


class TestGuardCallEdgeCache(unittest.TestCase):
    def setUp(self):
        self.scanner = JoernVulnScannerHTTP()

    def test_edge_key_format(self):
        key = JoernVulnScannerHTTP._guard_call_edge_key(
            "buffer_overflow",
            "com.app.Foo.bar:int(int)",
            "com.app.Foo.caller:int()",
        )
        self.assertEqual(
            key,
            "buffer_overflow|com.app.Foo.bar:int(int)|com.app.Foo.caller:int()",
        )

    def test_prune_requires_matching_call_edge_not_just_method_name(self):
        """F→D→A 不应因 C→A 有 guard 而被剪枝（仅方法名重叠时）。"""
        self.scanner._record_guard_call_edge(
            "buffer_overflow",
            "com.app.A:parse(int)",
            "com.app.C:handle()",
        )
        with mock.patch.object(
            self.scanner,
            "_collect_flow_call_edges",
            return_value=[
                {
                    "callee_short": "parse",
                    "callee_full": "com.app.A:parse(int)",
                    "caller_full": "com.app.D:dispatch()",
                    "edge_key": JoernVulnScannerHTTP._guard_call_edge_key(
                        "buffer_overflow",
                        "com.app.A:parse(int)",
                        "com.app.D:dispatch()",
                    ),
                }
            ],
        ):
            result = self.scanner._try_prune_by_guard_cache(
                vuln_type="buffer_overflow",
                flow_id="flow-2",
                sink_label="parse",
                joern_text="dummy",
            )
        self.assertIsNone(result)

    def test_prune_hits_when_same_call_edge(self):
        edge_key = self.scanner._record_guard_call_edge(
            "buffer_overflow",
            "com.app.A:parse(int)",
            "com.app.C:handle()",
        )
        matched_edge = {
            "callee_short": "parse",
            "callee_full": "com.app.A:parse(int)",
            "caller_full": "com.app.C:handle()",
            "edge_key": edge_key,
        }
        with mock.patch.object(
            self.scanner,
            "_collect_flow_call_edges",
            return_value=[matched_edge],
        ):
            result = self.scanner._try_prune_by_guard_cache(
                vuln_type="buffer_overflow",
                flow_id="flow-1",
                sink_label="parse",
                joern_text="dummy",
            )
        self.assertIsNotNone(result)
        self.assertIn("com.app.C:handle()", result)
        self.assertIn("guard_logic_found", result)


if __name__ == "__main__":
    unittest.main()
