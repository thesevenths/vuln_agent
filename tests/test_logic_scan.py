import json
import os
import tempfile
import unittest
from unittest import mock
from unittest.mock import MagicMock

from joern_vuln_scanner import JoernVulnScannerHTTP
from logic_scan_settings import LOGIC_LLM_CHECKPOINT_NS, LOGIC_QUERY_CHECKPOINT_NS


class LogicScanHelpersTest(unittest.TestCase):
    def setUp(self):
        self.scanner = JoernVulnScannerHTTP()

    def test_parse_tagged_lines_sets_caller_and_file(self):
        raw = (
            'SENSITIVE_LOG | caller=com.example.Foo.bar:void() | '
            'file=src/Foo.java | arg=password | line=31'
        )
        items = JoernVulnScannerHTTP._parse_tagged_lines(raw, "SENSITIVE_LOG")
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["caller"], "com.example.Foo.bar:void()")
        self.assertEqual(items[0]["file"], "src/Foo.java")
        self.assertEqual(items[0]["line"], 31)

    def test_parse_tagged_lines_legacy_second_field_caller(self):
        raw = "SENSITIVE_LOG | com.example.Legacy.init:void() | arg=secret | line=12"
        items = JoernVulnScannerHTTP._parse_tagged_lines(raw, "SENSITIVE_LOG")
        self.assertEqual(items[0]["caller"], "com.example.Legacy.init:void()")

    def test_dedupe_logic_candidates_same_location(self):
        candidates = [
            {
                "id": 1, "type": "info_leak", "cwe": "CWE-200",
                "caller": "com.example.Foo.<init>:void()",
                "file": "Foo.java", "line": 31, "evidence": "a",
            },
            {
                "id": 3, "type": "info_leak", "cwe": "CWE-200",
                "caller": "com.example.Foo.<init>:void()",
                "file": "Foo.java", "line": 31, "evidence": "b",
            },
        ]
        deduped = JoernVulnScannerHTTP._dedupe_logic_candidates(candidates)
        self.assertEqual(len(deduped), 1)

    def test_prioritize_logic_candidates_prefers_core_logic_types(self):
        candidates = [
            {"id": 1, "type": "info_leak", "cwe": "CWE-200", "file": "a", "line": 1},
            {"id": 2, "type": "missing_auth", "cwe": "CWE-862", "file": "b", "line": 2},
            {"id": 3, "type": "idor_profile", "cwe": "CWE-639", "file": "c", "line": 3},
        ]
        ordered = JoernVulnScannerHTTP._prioritize_logic_candidates(candidates, 2)
        types = [c["type"] for c in ordered]
        self.assertIn("idor_profile", types)
        self.assertIn("missing_auth", types)

    def test_prioritize_logic_candidates_round_robin_across_types(self):
        """大量 sqli_risk（P1）时不应挤掉 idor（P0）配额。"""
        candidates = [
            {"id": i, "type": "sqli_risk", "cwe": "CWE-89", "file": f"s{i}", "line": i}
            for i in range(1, 20)
        ]
        candidates.append(
            {"id": 99, "type": "idor_profile", "cwe": "CWE-639", "file": "j.java", "line": 1},
        )
        ordered = JoernVulnScannerHTTP._prioritize_logic_candidates(candidates, 5)
        types = {c["type"] for c in ordered}
        self.assertIn("idor_profile", types)

    def test_build_logic_scan_report_includes_poc_sections(self):
        findings = [{
            "confirmed": True,
            "candidate_id": "auth_1",
            "candidate_type": "missing_auth",
            "cwe": "CWE-862",
            "summary": "未授权访问",
            "confidence": 0.9,
            "file": "App.java",
            "line": 10,
            "caller": "com.App.list:void()",
            "http_endpoint": "GET /users",
            "code_flow": "GET /users -> list() -> findAll()",
            "exploit_poc": "curl -X GET http://host/users",
            "fix_code": "@PreAuthorize(\"hasRole('ADMIN')\")",
            "remediation": "加注解",
            "root_cause": "无鉴权",
            "evidence_levels": {
                "L1_joern": "present",
                "L2_static_files": "absent",
                "L3_dynamic": "not_verified",
            },
        }]
        report = self.scanner._build_logic_scan_report(
            findings, {"auth_guards": ""},
            funnel_meta={
                "total_extracted": 10,
                "analyzed": 1,
                "max_candidates": 150,
                "type_breakdown_extracted": {"missing_auth": 10},
                "type_breakdown_analyzed": {"missing_auth": 1},
            },
        )
        self.assertIn("漏洞利用（PoC）", report)
        self.assertIn("修复代码", report)
        self.assertIn("代码/调用流", report)
        self.assertIn("候选漏斗", report)
        self.assertIn("curl -X GET", report)

    def test_logic_high_hit_gap_notes(self):
        raw = "\n".join(
            f'JWT_WEAK_SECRET | caller=a.b:c() | file=x{i}.java | line={i}'
            for i in range(5)
        )
        notes = self.scanner._logic_high_hit_gap_notes(
            {"jwt_weakness": raw},
            {"type_breakdown_analyzed": {"missing_auth": 60}},
            set(),
        )
        self.assertTrue(any("jwt_weakness" in n for n in notes))

    def test_extract_logic_candidates_ssrf_and_bizlogic(self):
        query_results = {
            "auth_guards": "",
            "sensitive_operations": "",
            "idor_candidates": "",
            "info_leak_candidates": "",
            "hardcoded_credentials_v2": "",
            "cors_config": "",
            "public_endpoints": "",
            "ssrf_risk": (
                "SSRF_RISK | caller=com.App.fetch:void(java.lang.String) | "
                "file=App.java | line=20"
            ),
            "business_logic_risk": (
                "BIZLOGIC_RISK | caller=com.App.checkout:void() | "
                "file=Order.java | line=55"
            ),
        }
        candidates = self.scanner._extract_logic_candidates(query_results, ["840", "918"])
        types = {c["type"] for c in candidates}
        self.assertIn("ssrf_risk", types)
        self.assertIn("business_logic_risk", types)

    def test_load_cwe_templates_includes_new_logic_cwes(self):
        skills = self.scanner._load_cwe_skill_templates(["367", "840", "918"])
        self.assertIn("367", skills)
        self.assertIn("840", skills)
        self.assertIn("918", skills)
        self.assertIn("differentiation_from_sast", skills["840"])

    def test_load_cwe_templates_merges_logic_common(self):
        skills = self.scanner._load_cwe_skill_templates(["862", "899"])
        self.assertIn("confirmation_criteria", skills["862"])
        self.assertIn("component_scan_handoff", skills["862"])
        self.assertIn("reachable", skills["862"]["confirmation_criteria"])
        self.assertIn("access_control_gap_type", skills["899"]["output_schema"])
        self.assertIn("differentiation_from_related", skills["899"])

    def test_dedupe_logic_findings(self):
        findings = [
            {"confirmed": True, "cwe": "CWE-200", "file": "Foo.java", "line": 31, "caller": "a"},
            {"confirmed": True, "cwe": "CWE-200", "file": "Foo.java", "line": 31, "caller": "a"},
        ]
        self.assertEqual(len(JoernVulnScannerHTTP._dedupe_logic_findings(findings)), 1)

    def test_format_logic_query_coverage_failed(self):
        failed = {"sensitive_operations"}
        text = "-- Error: invalid escape character"
        label = self.scanner._format_logic_query_coverage(
            "sensitive_operations", text, failed_queries=failed,
        )
        self.assertEqual(label, "N/A (查询失败)")

    def test_format_logic_query_coverage_counts_tags_only(self):
        raw = '"SENSITIVE_LOG | caller=a.b:c() | file=x | line=1",\n'
        label = self.scanner._format_logic_query_coverage("info_leak_candidates", raw)
        self.assertEqual(label, "1 条结果")

    def test_build_logic_scan_report_marks_failed_queries(self):
        report = self.scanner._build_logic_scan_report(
            [],
            {
                "auth_guards": 'ANNOTATION_GUARD | com.Foo.bar | PreAuthorize',
                "sensitive_operations": "-- Error: invalid escape",
            },
            query_batch_meta={"failed_transport": ["sensitive_operations"]},
        )
        self.assertIn("sensitive_operations", report)
        self.assertIn("N/A (查询失败)", report)
        self.assertIn("查询告警", report)

    def test_extract_logic_candidates_cross_public_endpoint(self):
        query_results = {
            "auth_guards": "",
            "sensitive_operations": (
                "SENSITIVE_OP | delete | method=m | caller=com.App.deleteUser:void() | "
                "file=App.java | line=10"
            ),
            "idor_candidates": "",
            "info_leak_candidates": "",
            "hardcoded_credentials_v2": "",
            "cors_config": "",
            "public_endpoints": (
                "PUBLIC_ENDPOINT | caller=com.App.deleteUser:void() | file=App.java | line=10"
            ),
        }
        candidates = self.scanner._extract_logic_candidates(query_results, ["862", "306"])
        missing_auth = [c for c in candidates if c["type"] == "missing_auth"]
        self.assertEqual(len(missing_auth), 1)
        self.assertIn("public_endpoint_without_auth", missing_auth[0]["cross_signals"])


    def test_extract_logic_candidates_skips_identity_bound_public_endpoint(self):
        query_results = {
            "auth_guards": (
                "PARAM_IDENTITY_GUARD | com.App.menu:void(java.lang.String) | params=username"
            ),
            "sensitive_operations": "",
            "idor_candidates": "",
            "info_leak_candidates": "",
            "hardcoded_credentials_v2": "",
            "cors_config": "",
            "public_endpoints": (
                "PUBLIC_ENDPOINT | caller=com.App.menu:void(java.lang.String) | "
                "file=App.java | line=10"
            ),
        }
        candidates = self.scanner._extract_logic_candidates(query_results, ["306"])
        pub = [c for c in candidates if c["type"] == "public_endpoint"]
        self.assertEqual(len(pub), 0)

    def test_parse_guarded_methods_includes_param_identity(self):
        raw = "PARAM_IDENTITY_GUARD | com.Foo.bar:void() | params=user"
        guarded = self.scanner._parse_guarded_methods(raw)
        self.assertIn("com.Foo.bar:void()", guarded)


class LogicCheckpointTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.scanner = JoernVulnScannerHTTP(
            project_name="test_proj",
            source_path="/tmp/test_src",
        )
        os.environ["JOERN_CHECKPOINT"] = "1"
        os.environ["JOERN_CHECKPOINT_DIR"] = self.tmp.name
        os.environ.pop("JOERN_CHECKPOINT_RESET", None)

    def tearDown(self):
        os.environ.pop("JOERN_CHECKPOINT", None)
        os.environ.pop("JOERN_CHECKPOINT_DIR", None)

    def test_query_checkpoint_saves_and_resumes_logic_namespace(self):
        self.scanner._save_query_checkpoint(
            LOGIC_QUERY_CHECKPOINT_NS,
            {"auth_guards": "GUARD | foo"},
        )
        loaded = self.scanner._load_query_checkpoint(LOGIC_QUERY_CHECKPOINT_NS)
        self.assertEqual(loaded["auth_guards"], "GUARD | foo")

        with mock.patch.object(self.scanner, "_post_query", return_value="NEW") as post:
            results = self.scanner._run_query_map(
                {"auth_guards": "q1", "public_endpoints": "q2"},
                log_prefix="逻辑漏洞查询",
                checkpoint_namespace=LOGIC_QUERY_CHECKPOINT_NS,
            )
        post.assert_called_once()
        self.assertEqual(results["auth_guards"], "GUARD | foo")
        self.assertEqual(results["public_endpoints"], "NEW")

    def test_should_expand_logic_candidate_includes_idor_and_workflow(self):
        for ctype in ("idor_pathvar", "idor_profile", "idor", "workflow_bypass"):
            self.assertTrue(
                self.scanner._should_expand_logic_candidate({"type": ctype}),
                ctype,
            )
        self.assertFalse(
            self.scanner._should_expand_logic_candidate({"type": "info_leak"}),
        )

    def test_should_expand_logic_candidate_respects_skip_env(self):
        candidate = {"type": "missing_auth"}
        self.assertTrue(self.scanner._should_expand_logic_candidate(candidate))
        old = os.environ.get("LOGIC_SCAN_SKIP_CONTEXT_EXPANSION")
        os.environ["LOGIC_SCAN_SKIP_CONTEXT_EXPANSION"] = "1"
        try:
            self.assertFalse(self.scanner._should_expand_logic_candidate(candidate))
        finally:
            if old is None:
                os.environ.pop("LOGIC_SCAN_SKIP_CONTEXT_EXPANSION", None)
            else:
                os.environ["LOGIC_SCAN_SKIP_CONTEXT_EXPANSION"] = old

    def test_analyze_logic_candidate_runs_context_expansion_for_l2_sensitive(self):
        candidate = {
            "candidate_id": "auth_1",
            "type": "missing_auth",
            "cwe": "CWE-862",
            "caller": "com.example.App.list:void()",
            "file": "App.java",
            "line": 10,
            "evidence": "PUBLIC_ENDPOINT | com.example.App.list",
        }
        self.scanner.ensure_cpg_loaded = MagicMock(return_value=True)
        self.scanner._expand_logic_candidate_context = MagicMock(
            return_value="expanded security chain snippet",
        )
        self.scanner._get_llm = MagicMock()
        self.scanner._get_llm.return_value.complete.return_value = json.dumps({
            "confirmed": False,
            "confidence": 0.4,
            "refutation_verdict": "inconclusive",
            "summary": "need more",
            "exploit_poc": "无",
            "fix_code": "",
            "evidence_levels": {
                "L1_joern": "partial",
                "L2_static_files": "absent",
                "L3_dynamic": "not_verified",
            },
        })
        self.scanner._parse_llm_json = MagicMock(side_effect=lambda x: json.loads(x))
        result = self.scanner._analyze_logic_candidate(
            candidate,
            {"security_filter_chain": "permitAll /register"},
            {},
            gathered_context={
                "method_source": "public void list() {}",
                "caller_chain_source": "",
                "context_block": "",
                "merged_l2": "",
                "skill_fp": "",
            },
        )
        self.scanner._expand_logic_candidate_context.assert_called_once()
        self.assertIn("expansion_context_preview", result or {})

    def test_build_logic_joern_text_for_expansion_includes_method(self):
        text = self.scanner._build_logic_joern_text_for_expansion(
            {"candidate_id": "x1", "cwe": "CWE-862", "type": "missing_auth",
             "file": "A.java", "line": 1},
            caller="com.foo.Bar.baz:void()",
            method_source="void baz() {}",
            caller_chain_source="",
            context_block="",
            evidence="",
        )
        self.assertIn("com.foo.Bar.baz:void()", text)
        self.assertIn("method_source", text)

    def test_logic_llm_checkpoint_uses_per_candidate_input_fingerprint(self):
        query_results = {"auth_guards": "GUARD | com.example.Foo.bar:void() | line=1"}
        candidate = {
            "type": "missing_auth",
            "file": "Foo.java",
            "line": 1,
            "caller": "com.example.Foo.bar:void()",
            "cwe": "CWE-862",
        }
        ctx = {
            "method_source": "public void bar() {}",
            "caller_chain_source": "",
            "merged_l2": "",
            "context_block": "GUARD line",
            "skill_fp": "abc123",
        }
        input_fp = self.scanner._logic_llm_input_fingerprint(ctx)
        ckey = self.scanner._logic_candidate_key(candidate)
        self.scanner._save_logic_llm_checkpoint({
            ckey: {"confirmed": True, "summary": "ok", "input_fingerprint": input_fp},
        })
        loaded = self.scanner._load_logic_llm_checkpoint()
        self.assertIn(ckey, loaded)
        self.assertTrue(
            self.scanner._logic_llm_cache_hit(
                candidate, loaded, input_fp, incremental=False, affected_types=set(),
            )
        )
        self.assertFalse(
            self.scanner._logic_llm_cache_hit(
                candidate, loaded, "different_fingerprint",
                incremental=False, affected_types=set(),
            )
        )

    def test_incremental_retry_reuses_non_affected_without_fingerprint_match(self):
        candidate = {
            "type": "admin_no_auth",
            "file": "Foo.java",
            "line": 1,
            "caller": "com.example.Foo.bar:void()",
            "cwe": "CWE-862",
        }
        ckey = self.scanner._logic_candidate_key(candidate)
        cached = {
            "confirmed": False,
            "refutation_verdict": "rejected",
            "input_fingerprint": "old_fp",
        }
        self.assertTrue(
            self.scanner._logic_llm_cache_hit(
                candidate,
                {ckey: cached},
                "new_fp_after_planner_l2",
                incremental=True,
                affected_types={"cmd_exec_risk"},
            )
        )
        self.assertFalse(
            self.scanner._logic_llm_cache_hit(
                candidate,
                {ckey: cached},
                "new_fp",
                incremental=True,
                affected_types={"admin_no_auth"},
            )
        )

    def test_successful_logic_scan_retains_query_checkpoint(self):
        """成功扫描后不再删除 Joern query 检查点，便于同项目续跑只补新 query。"""
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["JOERN_CHECKPOINT_DIR"] = tmp
            os.environ.pop("JOERN_CHECKPOINT_RESET", None)
            os.environ.pop("JOERN_CPP_CHECKPOINT_RESET", None)
            scanner = JoernVulnScannerHTTP()
            scanner.project_name = "retain_proj"
            scanner.source_path = "/fake/src"
            scanner._save_query_checkpoint(LOGIC_QUERY_CHECKPOINT_NS, {"auth_guards": "ok"})
            path = scanner._checkpoint_file(LOGIC_QUERY_CHECKPOINT_NS)
            self.assertTrue(path.is_file())
            # 模拟旧版成功扫描末尾行为：不应再删除 query 检查点
            # （run_logic_scan 已移除 _remove_checkpoint_file 调用）
            self.assertTrue(path.is_file())

    def test_remove_checkpoint_file(self):
        self.scanner._save_query_checkpoint(LOGIC_QUERY_CHECKPOINT_NS, {"a": "b"})
        path = self.scanner._checkpoint_file(LOGIC_QUERY_CHECKPOINT_NS)
        self.assertTrue(path.is_file())
        self.scanner._remove_checkpoint_file(LOGIC_QUERY_CHECKPOINT_NS)
        self.assertFalse(path.exists())

    def test_taint_namespace_uses_legacy_filename(self):
        path = self.scanner._checkpoint_file("taint")
        self.assertEqual(path.name, "test_proj.json")
        logic_path = self.scanner._checkpoint_file(LOGIC_QUERY_CHECKPOINT_NS)
        self.assertEqual(logic_path.name, f"test_proj_{LOGIC_QUERY_CHECKPOINT_NS}.json")

    def test_companion_findings_dedup_different_cwes(self):
        """相同位置但不同 CWE 的 companion finding 不应被合并。"""
        findings = [
            {"confirmed": True, "cwe": "CWE-862", "file": "Foo.java", "line": 31, "caller": "a"},
            {"confirmed": True, "cwe": "CWE-863", "file": "Foo.java", "line": 31, "caller": "a"},
            {"confirmed": True, "cwe": "CWE-269", "file": "Foo.java", "line": 31, "caller": "a"},
        ]
        deduped = JoernVulnScannerHTTP._dedupe_logic_findings(findings)
        self.assertEqual(len(deduped), 3)

    def test_build_companion_guidance_returns_string(self):
        """_build_companion_guidance 应返回字符串且不报错。"""
        cwe_skills = {
            "863": {
                "reasoning_workflow": ["Step 1: check authz", "Step 2: verify owner"],
                "sanitizers": ["has @PreAuthorize"],
            },
        }
        result = self.scanner._build_companion_guidance(
            "862", cwe_skills, focus_nums={"862", "863"},
        )
        self.assertIsInstance(result, str)
        self.assertIn("CWE-863", result)

    def test_build_companion_guidance_empty_no_companions(self):
        """CWE 无伴随 CWE 时返回空字符串。"""
        result = self.scanner._build_companion_guidance(
            "99999", {}, focus_nums={"99999"},
        )
        self.assertEqual(result, "")


if __name__ == "__main__":
    unittest.main()
