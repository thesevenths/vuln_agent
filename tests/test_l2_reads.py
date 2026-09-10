"""Tests for L2 read suggestion aggregation."""
import tempfile
import unittest
from pathlib import Path

from l2_reads import (
    aggregate_pending_l2_reads,
    build_pending_l2_entry,
    collect_refutation_l2_read_suggestions,
    enrich_refutation_missing_l2,
    extract_paths_from_refutation_text,
    extract_paths_from_user_request,
    flow_has_new_l2_evidence,
    infer_fallback_l2_reads,
    is_l2_path_applicable,
    resolve_l2_pending_line_range,
    sanitize_joern_project_path,
    sanitize_l2_read_path,
)


class TestL2Reads(unittest.TestCase):
    def test_sanitize_joern_project_path(self):
        self.assertEqual(sanitize_joern_project_path("/app/vuln_app-"), "/app/vuln_app")

    def test_extract_paths_from_user_request(self):
        text = (
            "映射的路径：/app/vuln_app-我本地windows位置："
            "E:\\vuln_agent\\mbedtls-development帮我看看"
        )
        paths = extract_paths_from_user_request(text)
        self.assertEqual(paths["project_path"], "/app/vuln_app")
        self.assertIn("mbedtls-development", paths["local_source_path"] or "")

    def test_cpp_filters_pom(self):
        self.assertFalse(is_l2_path_applicable("pom.xml", "cpp"))
        self.assertTrue(is_l2_path_applicable("include/mbedtls/config.h", "cpp"))

    def test_sanitize_l2_strips_container_prefix(self):
        self.assertEqual(
            sanitize_l2_read_path("/app/vuln_app/include/mbedtls/config.h"),
            "include/mbedtls/config.h",
        )

    def test_aggregate_dedup_and_sort(self):
        raw = [
            {
                "path": "include/mbedtls/config.h",
                "flow_id": "a-flow-1",
                "l2_status": "absent",
                "refutation_verdict": "inconclusive",
            },
            {
                "path": "**/include/mbedtls/config.h",
                "flow_id": "a-flow-2",
                "l2_status": "absent",
                "refutation_verdict": "inconclusive",
            },
            {"path": "pom.xml", "flow_id": "b", "l2_status": "absent"},
        ]
        result = aggregate_pending_l2_reads(raw, language="cpp")
        self.assertEqual(len(result), 1)
        self.assertIn("config.h", result[0]["path"])

    def test_infer_fallback_l2_reads_from_sink_and_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            include = Path(tmp) / "include" / "mbedtls"
            include.mkdir(parents=True)
            (include / "mbedtls_config.h").write_text("#define F\n", encoding="utf-8")
            lib = Path(tmp) / "library"
            lib.mkdir()
            (lib / "pkcs7.c").write_text("void g() {}\n", encoding="utf-8")
            from project_file_index import build_project_file_index

            index = build_project_file_index(tmp, "cpp")
            suggestions = infer_fallback_l2_reads(
                flow_id="f-1",
                vuln_type="cpp_buffer_overflow",
                refutation_result={
                    "evidence_levels": {"L2_static_files": "absent"},
                    "missing_L2_reads": [],
                },
                sink_label="library/pkcs7.c:570 memcpy",
                language="cpp",
                local_source_path=tmp,
                metadata={"project_file_index": index.to_dict() if index else {}},
            )
            joined = " ".join(suggestions)
            self.assertIn("pkcs7.c", joined)
            self.assertIn("mbedtls_config.h", joined)

    def test_collect_l2_reads_when_inconclusive_and_l2_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            lib = Path(tmp) / "library"
            lib.mkdir()
            (lib / "asn1parse.c").write_text("int mbedtls_asn1_get_tag() {}\n", encoding="utf-8")
            (lib / "pkcs7.c").write_text("void f() {}\n", encoding="utf-8")
            from project_file_index import build_project_file_index

            index = build_project_file_index(tmp, "cpp")
            refutation = {
                "verdict": "inconclusive",
                "refutation_summary": "需打开 library/asn1parse.c 中 mbedtls_asn1_get_tag 实现",
                "blocking_factors": ["未读 `library/pkcs7.c` 的 buflen 校验"],
                "residual_risk": "",
                "evidence_levels": {"L2_static_files": "present"},
                "missing_L2_reads": [],
            }
            paths = collect_refutation_l2_read_suggestions(
                flow_id="cpp_buffer_overflow-flow-2",
                vuln_type="cpp_buffer_overflow",
                refutation_result=refutation,
                sink_label="library/pkcs7.c:570 memcpy",
                language="cpp",
                local_source_path=tmp,
                metadata={"project_file_index": index.to_dict() if index else {}},
            )
            joined = " ".join(paths)
            self.assertIn("pkcs7.c", joined)
            self.assertIn("asn1parse.c", joined)

    def test_extract_paths_from_refutation_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            lib = Path(tmp) / "library"
            lib.mkdir()
            (lib / "ssl_msg.c").write_text("x\n", encoding="utf-8")
            from project_file_index import build_project_file_index

            index = build_project_file_index(tmp, "cpp")
            text = "需审查 ssl_msg.c 中 verify_data_len 赋值逻辑"
            paths = extract_paths_from_refutation_text(
                text,
                language="cpp",
                local_source_path=tmp,
                metadata={"project_file_index": index.to_dict() if index else {}},
            )
            self.assertTrue(any("ssl_msg.c" in p for p in paths))

    def test_config_pending_uses_full_file_range_not_sink_line(self):
        entry = build_pending_l2_entry(
            path="CMakeLists.txt",
            flow_id="f-1",
            vuln_type="cpp_buffer_overflow",
            refutation_verdict="inconclusive",
            l2_status="partial",
            sink_line=634,
        )
        self.assertEqual(entry["start_line"], 1)
        self.assertEqual(entry["end_line"], 600)
        self.assertEqual(entry["kind"], "config")

        src = build_pending_l2_entry(
            path="library/pkcs7.c",
            flow_id="f-1",
            vuln_type="cpp_buffer_overflow",
            refutation_verdict="inconclusive",
            l2_status="partial",
            sink_line=570,
        )
        self.assertEqual(src["start_line"], 540)
        self.assertEqual(src["end_line"], 600)

    def test_aggregate_normalizes_config_line_range(self):
        raw = [
            {
                "path": "CMakeLists.txt",
                "flow_id": "f-1",
                "l2_status": "partial",
                "refutation_verdict": "inconclusive",
                "start_line": 634,
                "end_line": 694,
                "kind": "config",
            }
        ]
        result = aggregate_pending_l2_reads(raw, language="cpp")
        self.assertEqual(result[0]["start_line"], 1)
        self.assertEqual(result[0]["end_line"], 600)

    def test_enrich_refutation_missing_l2_from_prose(self):
        with tempfile.TemporaryDirectory() as tmp:
            lib = Path(tmp) / "library"
            lib.mkdir()
            (lib / "asn1parse.c").write_text(
                "int mbedtls_asn1_get_tag() { return 0; }\n", encoding="utf-8"
            )
            from project_file_index import build_project_file_index

            index = build_project_file_index(tmp, "cpp")
            refutation = {
                "verdict": "inconclusive",
                "refutation_summary": "需打开 mbedtls_asn1_get_tag 实现以确认边界检查",
                "blocking_factors": [],
                "residual_risk": "",
                "evidence_levels": {"L2_static_files": "present"},
                "missing_L2_reads": [],
            }
            enrich_refutation_missing_l2(
                refutation,
                flow_id="f-1",
                vuln_type="cpp_buffer_overflow",
                sink_label="library/pkcs7.c:570 memcpy",
                language="cpp",
                local_source_path=tmp,
                metadata={"project_file_index": index.to_dict() if index else {}},
            )
            joined = " ".join(refutation["missing_L2_reads"])
            self.assertIn("asn1parse.c", joined)

    def test_flow_has_new_l2_evidence_by_flow_id(self):
        metadata = {
            "file_evidence_reads": [
                {"path": "library/pkcs7.c", "lines": "540-600", "flow_id": "f-2"}
            ],
            "flow_l2_read_paths": {"f-2": ["library/pkcs7.c"]},
            "pending_l2_reads": [],
            "flow_catalog": {},
        }
        self.assertTrue(flow_has_new_l2_evidence(metadata, "f-2"))
        self.assertFalse(flow_has_new_l2_evidence(metadata, "f-9"))


if __name__ == "__main__":
    unittest.main()
