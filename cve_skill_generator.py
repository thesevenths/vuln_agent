"""
`cve_skill_generator.py` 将 CVE 知识库模式转换为可执行的 Skill 模板。

工作流程：
1. 从 `CVEKnowledgeExtractor` 获取 CWE 模式（sink 函数、调用链模式）
2. 基于模式生成增强 Joern 查询（DSL）
3. 生成完整的 Skill JSON 模板（含 DAG 节点 + expert_guidance）
4. 将生成的 Skill 写入 `skills/generated/` 目录

生成的 Skill 与手写专家 Skill 结构一致，但内容来源于 CVE 数据库的实际数据。
"""

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from cve_knowledge_extractor import CWE_TO_JOERN_QUERY_TYPE, CVEKnowledgeExtractor

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class CVESkillGenerator:
    """将 CVE 知识库模式转换为可执行的 Skill 模板。"""

    def __init__(self, extractor: Optional[CVEKnowledgeExtractor] = None, dsn: Optional[str] = None):
        self.extractor = extractor or CVEKnowledgeExtractor(dsn=dsn)
        self.workspace_dir = Path(__file__).resolve().parent
        self.generated_dir = self.workspace_dir / "skills" / "generated"
        self.generated_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Joern 查询生成
    # ------------------------------------------------------------------

    def generate_joern_queries(self, cwe_patterns: Dict[str, Any]) -> Dict[str, str]:
        """
        基于 CVE sink 模式生成增强 Joern 查询。

        Args:
            cwe_patterns: 来自 CVEKnowledgeExtractor 的 CWE 模式字典。

        Returns:
            查询名 → Joern DSL 的映射。
        """
        cwe_id = cwe_patterns.get("cwe_id", "")
        sinks = cwe_patterns.get("common_sinks", [])
        components = cwe_patterns.get("common_components", [])

        queries: Dict[str, str] = {}

        # 基于 sink 函数名生成定向污点查询
        if sinks:
            # 过滤出看起来像函数名的条目（去除过短或含特殊字符的）
            valid_sinks = [s for s in sinks if re.match(r'^[\w]+$', s) and len(s) > 3][:10]
            if valid_sinks:
                sink_pattern = "|".join(valid_sinks)
                # 生成反向污点分析查询
                queries[f"cve_sink_{cwe_id.lower().replace('-', '_')}"] = (
                    f'cpg.call.name("({sink_pattern})").reachableByFlows(cpg.parameter).l'
                )
                # 生成正向 sink 调用点查询
                queries[f"cve_sink_callers_{cwe_id.lower().replace('-', '_')}"] = (
                    f'cpg.method.name("({sink_pattern})").caller.take(10).dumpRaw'
                )

        # 基于组件名生成配置文件搜索提示（不生成 DSL，而是提示 FileTool glob）
        if components:
            queries["_component_hints"] = json.dumps(components[:5])

        return queries

    # ------------------------------------------------------------------
    # Skill 模板生成
    # ------------------------------------------------------------------

    def generate_skill_template(self, cwe_id: str, patterns: Dict[str, Any]) -> Dict[str, Any]:
        """
        生成完整的 Skill JSON 模板。

        Args:
            cwe_id: CWE 编号（如 'CWE-120'）。
            patterns: CWE 模式字典。

        Returns:
            可序列化为 JSON 的 Skill 模板字典。
        """
        cwe_safe = cwe_id.lower().replace("-", "_")
        skill_id = f"cve_generated_{cwe_safe}"
        sinks = patterns.get("common_sinks", [])
        components = patterns.get("common_components", [])
        joern_types = patterns.get("joern_query_types", [])
        cve_count = patterns.get("cve_count", 0)

        # 构建 expert_guidance
        expert_guidance = {
            "analysis_focus": f"基于 CVE 知识库提取的 {cwe_id} 漏洞模式，"
                              f"重点关注高频 sink 函数: {', '.join(sinks[:8]) if sinks else '无已知 sink 数据'}",
            "required_evidence": [
                "sink 函数完整方法体",
                "source → sink 的数据流路径",
                "长度/范围/白名单校验是否存在",
            ],
            "false_positive_patterns": [
                "已有边界检查或长度校验",
                "使用安全 API 替代（如 snprintf 替代 sprintf）",
                "输入已被上层过滤或限制",
            ],
            "refutation_checklist": [
                "检查所有 return 路径是否都释放了资源",
                "检查是否有 lock/mutex 保护",
                "检查配置宏/编译选项是否启用防护",
            ],
            "expert_rules": [
                f"该 CWE 在 CVE 数据库中共有 {cve_count} 个已知案例",
                f"高频受影响组件: {', '.join(components[:5]) if components else '无数据'}",
            ],
        }

        # 构建 DAG 节点
        nodes = [
            {
                "node_id": "set_context",
                "tool_name": "set_context",
                "arguments": {},
                "success_next": "targeted_scan",
                "expert_guidance": {
                    "analysis_focus": f"设置分析上下文，准备 {cwe_id} 漏洞类型的定向扫描",
                },
            },
            {
                "node_id": "targeted_scan",
                "tool_name": "JoernTool.run_targeted_scan",
                "arguments": {
                    "vuln_types": joern_types,
                    "language": "cpp",  # 默认 C/C++，Java CWE 可后续调整
                },
                "success_next": "read_sink_code",
                "failure_next": "report_empty",
                "expert_guidance": {
                    "analysis_focus": f"执行 {cwe_id} 相关的定向污点扫描",
                    "expert_rules": [
                        f"定向扫描类型: {', '.join(joern_types) if joern_types else '无预定义类型'}",
                    ],
                },
            },
            {
                "node_id": "read_sink_code",
                "tool_name": "FileTool.read_file",
                "arguments": {
                    "path": "<from_scan_result>",
                    "start_line": 1,
                    "end_line": 120,
                },
                "success_next": "check_patterns",
                "expert_guidance": expert_guidance,
            },
            {
                "node_id": "check_patterns",
                "tool_name": "FileTool.read_file",
                "arguments": {
                    "path": "<related_header_or_config>",
                    "start_line": 1,
                    "end_line": 80,
                },
                "success_next": "verify",
                "expert_guidance": {
                    "analysis_focus": f"检查 CVE 知识库中提取的 sink 模式是否匹配当前代码",
                    "required_evidence": [
                        f"以下 sink 函数是否在代码中被调用: {', '.join(sinks[:5])}",
                        "调用参数是否来自外部输入",
                    ],
                    "expert_rules": [
                        f"CVE 知识库高频 sink: {', '.join(sinks[:8]) if sinks else '无数据'}",
                    ],
                },
            },
            {
                "node_id": "verify",
                "tool_name": "FileTool.read_file",
                "arguments": {
                    "path": "<caller_or_guard_context>",
                    "start_line": 1,
                    "end_line": 100,
                },
                "success_next": "report",
                "expert_guidance": {
                    "analysis_focus": "反证验证：排除误报，确认漏洞真实存在",
                    "false_positive_patterns": expert_guidance["false_positive_patterns"],
                    "refutation_checklist": expert_guidance["refutation_checklist"],
                },
            },
            {
                "node_id": "report",
                "tool_name": "FileTool.write_report",
                "arguments": {},
                "completion_signal": f"cve_generated_{cwe_safe}_complete",
                "expert_guidance": {
                    "analysis_focus": "生成最终分析报告，包含 CVE 知识库参考",
                },
            },
            {
                "node_id": "report_empty",
                "tool_name": "FileTool.write_report",
                "arguments": {},
                "completion_signal": f"cve_generated_{cwe_safe}_no_findings",
            },
        ]

        # 构建完整 Skill 模板
        template = {
            "skill_id": skill_id,
            "name": f"CVE 知识驱动: {cwe_id}",
            "summary": (
                f"基于 CVE 数据库中 {cve_count} 个 {cwe_id} 案例提取的漏洞模式，"
                f"自动执行定向扫描和模式匹配分析"
            ),
            "trigger_keywords": [cwe_id.lower(), cwe_id],
            "completion_hints": [
                f"完成 {cwe_id} 的 CVE 知识驱动漏洞分析",
                f"参考了 {cve_count} 个已知 CVE 案例的模式",
            ],
            "min_score_to_activate": 0.2,
            "start_node_id": "set_context",
            "nodes": nodes,
            "collab_skill_ids": [],
            "enabled": True,
            "_meta": {
                "source": "cve_knowledge_generator",
                "cwe_id": cwe_id,
                "cve_count": cve_count,
                "generated_sinks": sinks[:10],
                "generated_components": components[:5],
            },
        }

        return template

    def generate_analysis_rules(self, cwe_id: str, patterns: Dict[str, Any]) -> str:
        """
        生成可嵌入 prompts.py 的分析规则文本。

        Args:
            cwe_id: CWE 编号。
            patterns: CWE 模式字典。

        Returns:
            可直接拼入 LLM prompt 的分析规则字符串。
        """
        sinks = patterns.get("common_sinks", [])
        components = patterns.get("common_components", [])
        cve_count = patterns.get("cve_count", 0)

        lines = [
            f"### CVE 知识库参考: {cwe_id}",
            f"- 已知案例数量: {cve_count}",
        ]
        if sinks:
            lines.append(f"- 高频 sink 函数: {', '.join(sinks[:10])}")
        if components:
            lines.append(f"- 高频受影响组件: {', '.join(components[:5])}")
        lines.append(f"- 分析时重点关注上述 sink 函数是否在当前代码中被调用")
        lines.append(f"- 检查调用参数是否来自外部不可信输入")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 持久化
    # ------------------------------------------------------------------

    def persist_generated_skill(self, skill_json: Dict[str, Any]) -> str:
        """
        将生成的 Skill 写入 skills/generated/ 目录。

        Args:
            skill_json: Skill 模板字典。

        Returns:
            生成的文件路径。
        """
        skill_id = skill_json.get("skill_id", "unknown")
        out_path = self.generated_dir / f"{skill_id}.json"
        try:
            out_path.write_text(
                json.dumps(skill_json, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            logger.info("CVE Skill 已生成: %s", out_path)
            return str(out_path)
        except Exception as exc:
            logger.error("写入 CVE Skill 失败: %s", exc)
            return ""

    # ------------------------------------------------------------------
    # 批量生成
    # ------------------------------------------------------------------

    def generate_skills_for_cwes(self, cwe_ids: List[str]) -> List[str]:
        """
        批量为指定 CWE 生成 Skill。

        Args:
            cwe_ids: CWE ID 列表（如 ['CWE-120', 'CWE-416']）。

        Returns:
            生成的文件路径列表。
        """
        generated_paths: List[str] = []
        patterns_list = self.extractor.extract_cwe_patterns()

        # 构建 cwe_id → pattern 映射
        pattern_map: Dict[str, Dict] = {}
        for p in patterns_list:
            pattern_map[p.get("cwe_id", "")] = p

        for cwe_id in cwe_ids:
            cwe_normalized = cwe_id if cwe_id.startswith("CWE-") else f"CWE-{cwe_id}"
            pattern = pattern_map.get(cwe_normalized)
            if not pattern:
                # 单独查询这个 CWE
                single = self.extractor.extract_cwe_patterns(cwe_normalized)
                pattern = single[0] if single else None

            if not pattern:
                logger.warning("CWE %s 未找到模式数据，跳过", cwe_normalized)
                continue

            template = self.generate_skill_template(cwe_normalized, pattern)
            path = self.persist_generated_skill(template)
            if path:
                generated_paths.append(path)

        logger.info("批量生成完成: %d / %d 个 CWE", len(generated_paths), len(cwe_ids))
        return generated_paths

    def generate_all_available_skills(self) -> List[str]:
        """
        为数据库中所有出现过的 CWE 自动生成 Skill。

        Returns:
            生成的文件路径列表。
        """
        all_cwe_ids = self.extractor.get_all_cwe_ids()
        if not all_cwe_ids:
            logger.warning("数据库中未找到任何 CWE ID")
            return []
        logger.info("发现 %d 个 CWE，开始批量生成 Skill", len(all_cwe_ids))
        return self.generate_skills_for_cwes(all_cwe_ids)
