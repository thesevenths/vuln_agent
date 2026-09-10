"""Tests for configurable Joern flow quality filter."""
import os
import unittest
from unittest import mock

from joern_vuln_scanner import JoernVulnScannerHTTP

JOERN_PROJECT_SNIPPET = """
val res1935: Option[io.joern.joerncli.console.JoernProject] = Some(
  value = Project(
    projectFile = ProjectFile(inputPath = "/app/vuln_app", name = "VulnerableApp"),
    path = /app/workspace/VulnerableApp,
    cpg = Some(value = Cpg[Graph[126270 nodes]])
  )
)
"""

TAINT_TABLE_SNIPPET = """
┌─────────┬──────────┬────┬──────────┬────────────────────┐
│nodeType │tracked   │line│method    │file                │
│Call    │memcpy    │61  │foo       │ssl_test.c          │
└─────────┴──────────┴────┴──────────┴────────────────────┘
"""


class TestJoernFlowQualityFilter(unittest.TestCase):
    def setUp(self):
        self.scanner = JoernVulnScannerHTTP()

    def _record(self, raw_text: str, sink_label: str = "") -> dict:
        return {
            "flow_id": "cpp_buffer_overflow-flow-1",
            "raw_text": raw_text,
            "sink_label": sink_label or self.scanner._extract_flow_sink_label(raw_text),
        }

    @mock.patch.dict(os.environ, {"JOERN_FLOW_QUALITY_FILTER": "0"}, clear=False)
    def test_filter_off_allows_noise(self):
        reason = self.scanner._flow_quality_skip_reason(self._record(JOERN_PROJECT_SNIPPET))
        self.assertIsNone(reason)

    @mock.patch.dict(
        os.environ,
        {"JOERN_FLOW_QUALITY_FILTER": "1", "JOERN_FLOW_QUALITY_MODE": "standard"},
        clear=False,
    )
    def test_standard_skips_joern_project_only(self):
        reason = self.scanner._flow_quality_skip_reason(self._record(JOERN_PROJECT_SNIPPET))
        self.assertEqual(reason, "joern_project_metadata_only")

    @mock.patch.dict(
        os.environ,
        {"JOERN_FLOW_QUALITY_FILTER": "1", "JOERN_FLOW_QUALITY_MODE": "standard"},
        clear=False,
    )
    def test_standard_allows_taint_table(self):
        record = self._record(TAINT_TABLE_SNIPPET)
        self.assertIsNone(self.scanner._flow_quality_skip_reason(record))

    @mock.patch.dict(
        os.environ,
        {"JOERN_FLOW_QUALITY_FILTER": "1", "JOERN_FLOW_QUALITY_MODE": "standard"},
        clear=False,
    )
    def test_standard_allows_real_sink_label(self):
        record = self._record("short", sink_label="programs/ssl/foo.c:61 memcpy")
        self.assertIsNone(self.scanner._flow_quality_skip_reason(record))

    @mock.patch.dict(
        os.environ,
        {"JOERN_FLOW_QUALITY_FILTER": "1", "JOERN_FLOW_QUALITY_MODE": "strict"},
        clear=False,
    )
    def test_strict_skips_without_table_or_source(self):
        record = self._record("some random text without evidence markers")
        self.assertEqual(
            self.scanner._flow_quality_skip_reason(record),
            "insufficient_flow_evidence",
        )


if __name__ == "__main__":
    unittest.main()
