import os
import unittest
from pathlib import Path

import logic_scan_settings as lss
from cwe_query_registry import iter_cwe_skill_template_paths


class LogicScanSettingsTest(unittest.TestCase):
    def test_resolve_max_candidates_floor(self):
        self.assertEqual(lss.resolve_max_candidates(10), lss.MAX_CANDIDATES_FLOOR)
        self.assertEqual(lss.resolve_max_candidates(200), 200)
        self.assertEqual(lss.resolve_max_candidates(None), lss.DEFAULT_MAX_CANDIDATES)

    def test_default_cwe_focus_includes_200_341_22(self):
        focus = set(lss.DEFAULT_CWE_FOCUS)
        self.assertIn("200", focus)
        self.assertIn("341", focus)
        self.assertIn("22", focus)
        self.assertIn("367", focus)
        self.assertIn("840", focus)
        self.assertIn("918", focus)

    def test_resolve_cwe_focus_explicit(self):
        self.assertEqual(lss.resolve_cwe_focus(["CWE-862", "639"]), ["862", "639"])

    def test_env_explicit_below_floor_uses_floor(self):
        self.assertEqual(
            lss.resolve_max_candidates(99),
            lss.MAX_CANDIDATES_FLOOR,
        )

    def test_candidate_catalog_cwes_have_skill_templates(self):
        cwe_dir = Path(__file__).resolve().parent.parent / "skills" / "templates" / "cwe"
        template_stems = {
            p.stem.replace("cwe_", "")
            for p in iter_cwe_skill_template_paths(cwe_dir)
        }
        for name, meta in lss.LOGIC_CANDIDATE_CATALOG.items():
            cwe = meta["cwe"]
            self.assertIn(
                cwe, template_stems,
                f"{name} → CWE-{cwe} 缺少 skills/templates/cwe/cwe_{cwe}.json",
            )

    def test_logic_candidate_cwe_from_catalog(self):
        self.assertEqual(lss.logic_candidate_cwe("idor"), "CWE-639")
        self.assertEqual(lss.logic_candidate_cwe("sqli_risk"), "CWE-89")
        self.assertEqual(lss.logic_candidate_cwe("unknown_type"), "CWE-unknown")

    def test_p0_types_match_catalog_priority(self):
        expected = {
            name for name, meta in lss.LOGIC_CANDIDATE_CATALOG.items()
            if meta["priority"] <= 1
        }
        self.assertEqual(lss.LOGIC_P0_CANDIDATE_TYPES, expected)

    def test_sast_overlap_types_are_p1_tier(self):
        for name in lss.SAST_OVERLAP_CANDIDATE_TYPES:
            self.assertIn(name, lss.LOGIC_CANDIDATE_CATALOG)
            self.assertEqual(
                lss.LOGIC_CANDIDATE_CATALOG[name]["priority"], 2,
                f"{name} 应在 P1（priority=2）",
            )

    def test_query_affected_types_in_catalog(self):
        from joern_vuln_scanner import JoernVulnScannerHTTP
        affected: set = set()
        for types in JoernVulnScannerHTTP._LOGIC_QUERY_AFFECTED_CANDIDATE_TYPES.values():
            affected.update(types)
        missing = affected - set(lss.LOGIC_CANDIDATE_CATALOG.keys())
        self.assertEqual(missing, set(), f"catalog 缺少候选类型: {sorted(missing)}")

    def test_companion_map_bidirectional(self):
        """CWE_COMPANION_MAP 必须对称：若 A 列出 B，则 B 也必须列出 A。"""
        for cwe_a, companions in lss.CWE_COMPANION_MAP.items():
            for cwe_b in companions:
                self.assertIn(
                    cwe_a,
                    lss.CWE_COMPANION_MAP.get(cwe_b, ()),
                    f"CWE-{cwe_a} 列出 CWE-{cwe_b} 为伴随，"
                    f"但 CWE-{cwe_b} 未反向列出 CWE-{cwe_a}",
                )

    def test_get_cwe_companions_returns_tuple(self):
        result = lss.get_cwe_companions("862")
        self.assertIsInstance(result, tuple)
        self.assertIn("863", result)
        # 不存在的 CWE 返回空 tuple
        self.assertEqual(lss.get_cwe_companions("99999"), ())


if __name__ == "__main__":
    unittest.main()
