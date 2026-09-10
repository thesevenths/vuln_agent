"""version_identification 单元测试。"""

import unittest

from version_identification import (
    _apply_tie_break,
    _candidate_fingerprints_differ,
    _top_tier_labels,
    extract_control_flow_fingerprint,
    fingerprint_similarity,
    parse_decompiled_functions,
)


SAMPLE_DECOMPILED = """
/* ---------- Function 1: foo @ 00001000 ---------- */
int foo(int *param_1)
{
  if (param_1[0x30] == 0x16) {
    if (*(byte *)param_1[0x2f] != 0) {
      return 0xffff9400;
    }
  }
  return 0;
}
"""

SOURCE_214_STYLE = """
int foo(void *ssl) {
  if (ssl->out_msgtype == HANDSHAKE && hs_type != HELLO_REQUEST && ssl->handshake == NULL) {
    return ERR;
  }
  return 0;
}
"""

SOURCE_216_STYLE = """
int foo(void *ssl) {
  if (!(ssl->out_msgtype == HANDSHAKE && hs_type == HELLO_REQUEST) && ssl->handshake == NULL) {
    return ERR;
  }
  return 0;
}
"""


class TestControlFlowFingerprint(unittest.TestCase):
    def test_fingerprints_differ_between_214_and_216_style(self):
        bodies = {"2.14": SOURCE_214_STYLE, "2.16": SOURCE_216_STYLE}
        self.assertTrue(_candidate_fingerprints_differ(bodies))

    def test_decompiled_closer_to_214_than_216(self):
        dec = parse_decompiled_functions(SAMPLE_DECOMPILED)["foo"].body
        score_214 = fingerprint_similarity(dec, SOURCE_214_STYLE)
        score_216 = fingerprint_similarity(dec, SOURCE_216_STYLE)
        self.assertGreater(score_214, score_216)

    def test_fingerprint_extracts_if_count(self):
        fp = extract_control_flow_fingerprint(SAMPLE_DECOMPILED)
        self.assertGreaterEqual(fp.if_count, 2)


class TestTopTierAndTieBreak(unittest.TestCase):
    def test_top_tier_excludes_lower_score(self):
        scores = {"2.14.0": 0.1441, "2.14.1": 0.1441, "2.16.0": 0.1423}
        tier = _top_tier_labels(scores)
        self.assertIn("2.14.0", tier)
        self.assertIn("2.14.1", tier)
        self.assertNotIn("2.16.0", tier)

    def test_tie_break_picks_highest_patch_among_214x_only(self):
        import os

        old = os.environ.get("AGENT_VERSION_TIE_BREAK")
        os.environ["AGENT_VERSION_TIE_BREAK"] = "highest_patch"
        try:
            winners, note = _apply_tie_break(["2.14.0", "2.14.1"])
            self.assertEqual(winners, ["2.14.1"])
            self.assertIsNotNone(note)
        finally:
            if old is None:
                os.environ.pop("AGENT_VERSION_TIE_BREAK", None)
            else:
                os.environ["AGENT_VERSION_TIE_BREAK"] = old


if __name__ == "__main__":
    unittest.main()
