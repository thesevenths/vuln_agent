"""Tests for flow_merge keys."""
import unittest

from flow_merge import (
    build_flow_merge_key,
    build_sink_verdict_key,
    extract_symbol_id,
    merge_refutation_verdict,
)


class TestFlowMerge(unittest.TestCase):
    def test_same_function_different_lines_same_merge_key(self):
        sink_a = "programs/ssl/ssl_test.c:72 len += sprintf("
        sink_b = "programs/ssl/ssl_test.c:76 sprintf(nss_keylog_line"
        body = "void nss_keylog_export(void *p) {"
        key_a = build_flow_merge_key("cpp_dangerous_func", sink_a, body)
        key_b = build_flow_merge_key("cpp_dangerous_func", sink_b, body)
        self.assertEqual(key_a, key_b)
        self.assertIn("nss_keylog_export", key_a or "")

    def test_sink_keys_differ_by_line(self):
        sink_a = "lib/a.c:10 foo("
        sink_b = "lib/a.c:20 bar("
        self.assertNotEqual(
            build_sink_verdict_key("x", sink_a),
            build_sink_verdict_key("x", sink_b),
        )

    def test_merge_refutation_conservative(self):
        self.assertEqual(
            merge_refutation_verdict(["likely_false_positive", "confirmed"]),
            "inconclusive",
        )


if __name__ == "__main__":
    unittest.main()
