"""
test_skill_loader.py — YAML skill 加载层单元测试。

覆盖：
1. YAML 加载后 dict 结构与旧 JSON 等价
2. Fallback 到 JSON 正常工作（模拟 YAML 目录不存在）
3. 框架检测返回正确 labels
4. CWE_COMPANION_MAP 从 YAML 生成后与硬编码值一致
5. CWE_PRIMARY_LOGIC_QUERIES 从 YAML 加载
"""

import unittest
from pathlib import Path

import skill_loader


SKILLS_DIR = Path(__file__).resolve().parent.parent / "skills"


class YamlCweSkillLoadTest(unittest.TestCase):
    """测试从新 YAML 目录加载 CWE skill。"""

    def test_yaml_load_returns_dict_for_known_cwes(self):
        """YAML 加载应返回已知 CWE 编号。"""
        skills = skill_loader.load_cwe_skills_yaml(
            SKILLS_DIR, cwe_focus=["862", "840", "89"],
        )
        self.assertIn("862", skills)
        self.assertIn("840", skills)
        self.assertIn("89", skills)

    def test_yaml_load_includes_reasoning_fields(self):
        """YAML 加载应包含 reasoning_workflow 和 sanitizers。"""
        skills = skill_loader.load_cwe_skills_yaml(
            SKILLS_DIR, cwe_focus=["862"],
        )
        skill = skills["862"]
        self.assertIn("reasoning_workflow", skill)
        self.assertIsInstance(skill["reasoning_workflow"], list)
        self.assertIn("sanitizers", skill)

    def test_yaml_load_includes_core_fields_for_logic_cwes(self):
        """P0 逻辑 CWE 应合并 core/ 共享字段。"""
        skills = skill_loader.load_cwe_skills_yaml(
            SKILLS_DIR, cwe_focus=["862"],
        )
        skill = skills["862"]
        self.assertIn("confirmation_criteria", skill)
        self.assertIn("reachable", skill["confirmation_criteria"])
        self.assertIn("verdict_rule", skill)
        self.assertIn("component_scan_handoff", skill)
        self.assertIn("burp_poc_requirements", skill)

    def test_yaml_load_includes_trigger_condition(self):
        """YAML 加载应包含 trigger_condition（来自 patterns.yaml）。"""
        skills = skill_loader.load_cwe_skills_yaml(
            SKILLS_DIR, cwe_focus=["862"],
        )
        skill = skills["862"]
        self.assertIn("trigger_condition", skill)
        tc = skill["trigger_condition"]
        self.assertIn("ast_patterns", tc)
        self.assertIn("semantic_keywords", tc)

    def test_yaml_load_includes_differentiation(self):
        """YAML 加载应保留 differentiation_from_sast/related。"""
        skills = skill_loader.load_cwe_skills_yaml(
            SKILLS_DIR, cwe_focus=["840", "899"],
        )
        self.assertIn("differentiation_from_sast", skills["840"])
        self.assertIn("differentiation_from_related", skills["899"])

    def test_yaml_load_output_schema_merge(self):
        """output_schema 应合并 core 扩展字段。"""
        skills = skill_loader.load_cwe_skills_yaml(
            SKILLS_DIR, cwe_focus=["899"],
        )
        os = skills["899"].get("output_schema", {})
        # 来自 cwe_899/reasoning.yaml
        self.assertIn("access_control_gap_type", os)
        # 来自 core/output_schema.yaml
        self.assertIn("confirmation_checklist", os)

    def test_yaml_load_cwe_focus_filter(self):
        """cwe_focus 应过滤不相关的 CWE。"""
        skills = skill_loader.load_cwe_skills_yaml(
            SKILLS_DIR, cwe_focus=["862"],
        )
        self.assertIn("862", skills)
        self.assertNotIn("840", skills)

    def test_yaml_load_no_focus_loads_all(self):
        """cwe_focus=None 应加载所有 CWE。"""
        skills = skill_loader.load_cwe_skills_yaml(SKILLS_DIR, cwe_focus=None)
        # 至少应有 34 个 CWE（与 registry.yaml cwe_index 一致）
        self.assertGreaterEqual(len(skills), 30)


class FallbackToJsonTest(unittest.TestCase):
    """测试 YAML 不可用时回退到 JSON。"""

    def test_fallback_when_yaml_dir_missing(self):
        """当 authorization/ 目录不存在时应回退 JSON。"""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            fake_dir = Path(td)
            skills = skill_loader.load_cwe_skills(fake_dir, cwe_focus=["862"])
            # 应返回空（因为 JSON 目录也不存在）
            self.assertEqual(skills, {})

    def test_load_cwe_skills_uses_yaml_when_available(self):
        """当 YAML 目录存在时应使用 YAML 路径。"""
        skills = skill_loader.load_cwe_skills(
            SKILLS_DIR, cwe_focus=["862"],
        )
        self.assertIn("862", skills)
        # YAML 路径应包含 core 合并字段
        self.assertIn("confirmation_criteria", skills["862"])


class FrameworkDetectionTest(unittest.TestCase):
    """测试框架信号检测。"""

    def test_detect_language_java(self):
        """检测到 pom.xml 应返回 java。"""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "pom.xml").write_text("<project/>")
            lang = skill_loader.detect_language(Path(td))
            self.assertEqual(lang, "java")

    def test_detect_language_python(self):
        """检测到 requirements.txt 应返回 python。"""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "requirements.txt").write_text("flask==2.0")
            lang = skill_loader.detect_language(Path(td))
            self.assertEqual(lang, "python")

    def test_detect_language_default_cpp(self):
        """无信号文件应默认 cpp。"""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            lang = skill_loader.detect_language(Path(td))
            self.assertEqual(lang, "cpp")


class CompanionMapConsistencyTest(unittest.TestCase):
    """测试 CWE_COMPANION_MAP 从 YAML 加载与硬编码值一致。"""

    def test_yaml_companion_map_matches_fallback(self):
        """从 YAML 加载的 companion map 应与硬编码回退值一致。"""
        from logic_scan_settings import (
            CWE_COMPANION_MAP,
            _CWE_COMPANION_MAP_FALLBACK,
        )
        # YAML 加载成功时应与 fallback 一致（因为 registry.yaml 是从旧数据迁移的）
        for cwe, companions in _CWE_COMPANION_MAP_FALLBACK.items():
            yaml_companions = CWE_COMPANION_MAP.get(cwe, ())
            self.assertEqual(
                set(companions), set(yaml_companions),
                f"CWE-{cwe}: fallback={companions} yaml={yaml_companions}",
            )

    def test_primary_queries_from_yaml_matches_fallback(self):
        """从 YAML 加载的 primary queries 应与硬编码回退值一致。"""
        from cwe_query_registry import (
            CWE_PRIMARY_LOGIC_QUERIES,
            _CWE_PRIMARY_LOGIC_QUERIES_FALLBACK,
        )
        for cwe, queries in _CWE_PRIMARY_LOGIC_QUERIES_FALLBACK.items():
            yaml_queries = CWE_PRIMARY_LOGIC_QUERIES.get(cwe, [])
            self.assertEqual(
                set(queries), set(yaml_queries),
                f"CWE-{cwe}: fallback={queries} yaml={yaml_queries}",
            )


if __name__ == "__main__":
    unittest.main()
