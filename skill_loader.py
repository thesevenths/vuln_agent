"""
skill_loader.py — 统一 CWE skill 模板加载层。

优先从新 YAML 目录结构加载（skills/authorization/、skills/business_logic/、skills/injection/），
失败时回退到旧 JSON 目录（skills/templates/cwe/）。

输出格式完全一致：Dict[cwe_number, template_dict]，
下游消费者（_logic_cwe_skill_fingerprint、_build_companion_guidance、
_analyze_logic_candidate 等）无需任何改动。
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# 尝试导入 yaml；若不可用则只能走 JSON fallback
try:
    import yaml

    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False
    logger.warning("PyYAML 未安装，YAML skill 加载不可用，将回退到 JSON")

# ── 常量 ────────────────────────────────────────────────────────────────────

_CATEGORY_DIRS = ("authorization", "business_logic", "injection")

# _LOGIC_COMMON_CWE_NUMS 与旧代码保持一致（P0 逻辑 CWE 需合并 core 共享字段）
LOGIC_COMMON_CWE_NUMS = frozenset({
    "287", "285", "306", "639", "840", "841", "862", "863", "899",
    "269", "276", "307", "362", "384", "521", "610", "613", "640", "915",
})


# ── 公开入口 ────────────────────────────────────────────────────────────────


def load_cwe_skills(
    skills_dir: Path,
    cwe_focus: Optional[List[str]] = None,
    language: str = "java",
    framework_labels: Optional[List[str]] = None,
) -> Dict[str, Dict[str, Any]]:
    """统一入口：优先 YAML 新目录，失败回退旧 JSON。

    Parameters
    ----------
    skills_dir : Path
        ``agent/skills/`` 目录。
    cwe_focus : list[str] | None
        需要加载的 CWE 编号列表（不含 ``CWE-`` 前缀）。None 表示全部。
    language : str
        项目语言（java / python / ...），用于加载语言特化 patterns。
    framework_labels : list[str] | None
        检测到的框架标签（如 ``["spring_security"]``）。

    Returns
    -------
    Dict[str, Dict[str, Any]]
        ``{cwe_number: template_dict}``，结构与旧 JSON 加载完全一致。
    """
    yaml_available = (
        _HAS_YAML
        and (skills_dir / "authorization").is_dir()
    )
    if yaml_available:
        try:
            return load_cwe_skills_yaml(
                skills_dir, cwe_focus, language, framework_labels or [],
            )
        except Exception as exc:
            logger.warning("YAML skill 加载失败，回退 JSON: %s", exc)

    return load_cwe_skills_json(skills_dir, cwe_focus)


# ── YAML 加载路径 ───────────────────────────────────────────────────────────


def load_cwe_skills_yaml(
    skills_dir: Path,
    cwe_focus: Optional[List[str]] = None,
    language: str = "java",
    framework_labels: Optional[List[str]] = None,
) -> Dict[str, Dict[str, Any]]:
    """从新 YAML 目录加载 CWE skill。"""
    framework_labels = framework_labels or []
    focus_nums = (
        {c.replace("CWE-", "").strip() for c in cwe_focus}
        if cwe_focus
        else None
    )

    # 1) 加载 core/ 共享字段
    core_fields = _load_core_fields(skills_dir / "core")

    # 2) 遍历三个 category 目录
    skills: Dict[str, Dict[str, Any]] = {}
    for cat in _CATEGORY_DIRS:
        cat_dir = skills_dir / cat
        if not cat_dir.is_dir():
            continue
        for cwe_dir in sorted(cat_dir.iterdir()):
            if not cwe_dir.is_dir() or not cwe_dir.name.startswith("cwe_"):
                continue
            skill_yaml = cwe_dir / "skill.yaml"
            if not skill_yaml.is_file():
                continue

            # 解析 skill.yaml 获取 CWE 编号
            meta = _read_yaml(skill_yaml)
            if not meta:
                continue
            cwe_num = _extract_cwe_number(meta.get("source_cwe"))
            if not cwe_num:
                # 从目录名推断：cwe_862 → 862
                stem = cwe_dir.name.replace("cwe_", "")
                cwe_num = stem

            if focus_nums and cwe_num not in focus_nums:
                continue

            # 3) 合并三文件
            template = _merge_cwe_dir(cwe_dir)

            # 4) 合并 core 共享字段（仅对 P0 逻辑 CWE）
            if cwe_num in LOGIC_COMMON_CWE_NUMS:
                template = _merge_core_fields(template, core_fields)

            # 5) 合并语言特化 patterns
            template = _merge_language_patterns(
                skills_dir / "languages", language, framework_labels, template,
            )

            skills[cwe_num] = template

    return skills


def _merge_cwe_dir(cwe_path: Path) -> Dict[str, Any]:
    """合并 skill.yaml + reasoning.yaml + patterns.yaml 为单个 dict。"""
    result: Dict[str, Any] = {}

    # ── skill.yaml → 元数据 ──
    meta = _read_yaml(cwe_path / "skill.yaml") or {}
    result["skill_id"] = meta.get("skill_id", "")
    # source_cwe 统一转为 list
    raw_cwe = meta.get("source_cwe")
    if isinstance(raw_cwe, list):
        result["source_cwe"] = raw_cwe
    elif isinstance(raw_cwe, str):
        result["source_cwe"] = [raw_cwe]
    else:
        result["source_cwe"] = []
    result["priority"] = meta.get("priority", "")
    result["related_cwes"] = meta.get("related_cwes", [])
    result["description"] = meta.get("description", "")

    # ── reasoning.yaml → 分析逻辑 ──
    reasoning = _read_yaml(cwe_path / "reasoning.yaml") or {}
    for key in (
        "reasoning_workflow",
        "knowledge_injection",
        "anti_patterns",
        "output_schema",
        "sanitizers",
        "differentiation_from_sast",
        "differentiation_from_related",
    ):
        if key in reasoning:
            result[key] = reasoning[key]

    # ── patterns.yaml → 检测模式 → 合并进 trigger_condition ──
    patterns = _read_yaml(cwe_path / "patterns.yaml") or {}
    trigger: Dict[str, Any] = {}
    if "ast_patterns" in patterns:
        trigger["ast_patterns"] = patterns["ast_patterns"]
    if "semantic_keywords" in patterns:
        trigger["semantic_keywords"] = patterns["semantic_keywords"]
    if "file_context" in patterns:
        trigger["file_context"] = patterns["file_context"]

    # sensitive_operations + route_patterns → operation_triggers
    op_triggers: Dict[str, Any] = {}
    if "sensitive_operations" in patterns:
        op_triggers["sensitive_operations"] = patterns["sensitive_operations"]
    if "route_patterns" in patterns:
        op_triggers["route_patterns"] = patterns["route_patterns"]
    if op_triggers:
        trigger["operation_triggers"] = op_triggers

    if trigger:
        result["trigger_condition"] = trigger

    # logic_query_keywords_generic → logic_query_keywords.generic
    lqk_generic = patterns.get("logic_query_keywords_generic")
    if lqk_generic:
        result.setdefault("logic_query_keywords", {})["generic"] = lqk_generic

    # sanitizers 在 patterns.yaml 顶层
    if "sanitizers" in patterns:
        result["sanitizers"] = patterns["sanitizers"]

    return result


def _load_core_fields(core_dir: Path) -> Dict[str, Any]:
    """加载 core/ 下的共享字段。"""
    fields: Dict[str, Any] = {}
    if not core_dir.is_dir():
        return fields

    # confirmation_criteria.yaml
    cc = _read_yaml(core_dir / "confirmation_criteria.yaml")
    if cc:
        if "confirmation_criteria" in cc:
            fields["confirmation_criteria"] = cc["confirmation_criteria"]
        if "verdict_rule" in cc:
            fields["verdict_rule"] = cc["verdict_rule"]

    # poc_requirements.yaml
    poc = _read_yaml(core_dir / "poc_requirements.yaml")
    if poc and "burp_poc_requirements" in poc:
        fields["burp_poc_requirements"] = poc["burp_poc_requirements"]

    # component_scan_handoff.yaml
    handoff = _read_yaml(core_dir / "component_scan_handoff.yaml")
    if handoff and "component_scan_handoff" in handoff:
        fields["component_scan_handoff"] = handoff["component_scan_handoff"]

    # output_schema.yaml → output_schema_extensions
    os_yaml = _read_yaml(core_dir / "output_schema.yaml")
    if os_yaml and "output_schema_extensions" in os_yaml:
        fields["output_schema_extensions"] = os_yaml["output_schema_extensions"]

    return fields


def _merge_core_fields(
    template: Dict[str, Any], core_fields: Dict[str, Any],
) -> Dict[str, Any]:
    """将 core 共享字段并入模板（模板自身字段优先，与旧 _merge_cwe_logic_common 一致）。"""
    if not core_fields:
        return template
    merged = dict(template)
    for key in (
        "confirmation_criteria",
        "verdict_rule",
        "burp_poc_requirements",
        "component_scan_handoff",
    ):
        if key in core_fields and key not in merged:
            merged[key] = core_fields[key]
    # output_schema 合并扩展字段
    base_os = dict(core_fields.get("output_schema_extensions") or {})
    tpl_os = dict(merged.get("output_schema") or {})
    if base_os or tpl_os:
        merged["output_schema"] = {**base_os, **tpl_os}
    return merged


def _merge_language_patterns(
    languages_dir: Path,
    language: str,
    framework_labels: List[str],
    template: Dict[str, Any],
) -> Dict[str, Any]:
    """将语言特化模式合并进 CWE 模板。

    主要扩展：
    - ``trigger_condition.route_patterns`` ← languages/{lang}/endpoint_discovery.yaml
    - ``logic_query_keywords.{framework}`` ← languages/{lang}/{framework}.yaml
    """
    lang_dir = languages_dir / language
    if not lang_dir.is_dir():
        return template

    # 1) endpoint_discovery.yaml → 扩展 route_patterns
    ep = _read_yaml(lang_dir / "endpoint_discovery.yaml")
    if ep and "route_patterns" in ep:
        trigger = template.setdefault("trigger_condition", {})
        op_triggers = trigger.setdefault("operation_triggers", {})
        existing_rp = dict(op_triggers.get("route_patterns") or {})
        new_rp = ep["route_patterns"]
        if isinstance(new_rp, dict):
            # 合并：YAML 中的 route_patterns 按语言 key 写入
            for lang_key, patterns in new_rp.items():
                if lang_key not in existing_rp:
                    existing_rp[lang_key] = patterns
            op_triggers["route_patterns"] = existing_rp

    # 2) auth_controls.yaml → 扩展 logic_query_keywords.{language}
    ac = _read_yaml(lang_dir / "auth_controls.yaml")
    if ac:
        lqk = template.setdefault("logic_query_keywords", {})
        lang_key = language  # "java" or "python"
        if lang_key not in lqk:
            lang_kw: Dict[str, Any] = {}
            # 提取 auth annotation patterns 作为关键词
            if "detection_patterns" in ac:
                dp = ac["detection_patterns"]
                for section_key in ("auth_annotations", "security_config", "auth_code_calls"):
                    section = dp.get(section_key, [])
                    if section:
                        lang_kw[section_key] = section
            if lang_kw:
                lqk[lang_key] = lang_kw

    # 3) 框架特化文件 → 扩展 logic_query_keywords.{framework}
    for fw_label in framework_labels:
        fw_file = lang_dir / f"{fw_label}.yaml"
        if not fw_file.is_file():
            continue
        fw_data = _read_yaml(fw_file)
        if not fw_data:
            continue
        lqk = template.setdefault("logic_query_keywords", {})
        if fw_label not in lqk:
            fw_kw: Dict[str, Any] = {}
            # 提取 security_patterns 作为关键词
            sp = fw_data.get("security_patterns") or fw_data.get("detection_patterns") or {}
            if isinstance(sp, dict):
                for k, v in sp.items():
                    if isinstance(v, list):
                        fw_kw[k] = v
            if fw_kw:
                lqk[fw_label] = fw_kw

    return template


# ── JSON 回退路径（旧逻辑） ─────────────────────────────────────────────────


def load_cwe_skills_json(
    skills_dir: Path,
    cwe_focus: Optional[List[str]] = None,
) -> Dict[str, Dict[str, Any]]:
    """旧 JSON 加载路径（回退用）。与旧 ``_load_cwe_skill_templates`` 等价。"""
    from cwe_query_registry import is_cwe_skill_template_file

    skills: Dict[str, Dict[str, Any]] = {}
    cwe_dir = skills_dir / "templates" / "cwe"
    if not cwe_dir.is_dir():
        return skills

    # 加载 cwe_logic_common.json
    logic_common = _load_cwe_logic_common_json(cwe_dir)

    focus_nums = (
        {c.replace("CWE-", "").strip() for c in cwe_focus}
        if cwe_focus
        else None
    )

    for json_file in cwe_dir.glob("cwe_*.json"):
        if not is_cwe_skill_template_file(json_file.name):
            continue
        try:
            template = json.loads(json_file.read_text(encoding="utf-8"))
            source_cwes = template.get("source_cwe", [])
            for cwe_id in source_cwes:
                normalized = cwe_id.replace("CWE-", "").strip()
                if focus_nums and normalized not in focus_nums:
                    continue
                tpl = template
                if normalized in LOGIC_COMMON_CWE_NUMS:
                    tpl = _merge_cwe_logic_common_json(template, logic_common)
                skills[normalized] = tpl
        except Exception as exc:
            logger.debug("加载 CWE skill 失败 (%s): %s", json_file.name, exc)

    return skills


def _load_cwe_logic_common_json(cwe_dir: Path) -> Dict[str, Any]:
    common_path = cwe_dir / "cwe_logic_common.json"
    if not common_path.is_file():
        return {}
    try:
        return json.loads(common_path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.debug("加载 cwe_logic_common 失败: %s", exc)
        return {}


def _merge_cwe_logic_common_json(
    template: Dict[str, Any], common: Dict[str, Any],
) -> Dict[str, Any]:
    """与旧 ``_merge_cwe_logic_common`` 完全一致的浅合并逻辑。"""
    if not common:
        return template
    merged = dict(template)
    for key in (
        "confirmation_criteria",
        "verdict_rule",
        "burp_poc_requirements",
        "component_scan_handoff",
    ):
        if key in common and key not in merged:
            merged[key] = common[key]
    base_os = dict(common.get("output_schema_extensions") or {})
    tpl_os = dict(merged.get("output_schema") or {})
    merged["output_schema"] = {**base_os, **tpl_os}
    return merged


# ── 框架检测 ────────────────────────────────────────────────────────────────


def detect_language(project_root: Path) -> str:
    """根据项目文件检测主要语言。"""
    signals = {
        "java": ["pom.xml", "build.gradle", "build.gradle.kts"],
        "python": ["requirements.txt", "setup.py", "pyproject.toml", "Pipfile"],
        "go": ["go.mod"],
        "rust": ["Cargo.toml"],
        "cpp": ["CMakeLists.txt", "Makefile"],
    }
    for lang, files in signals.items():
        for fname in files:
            if (project_root / fname).is_file():
                return lang
    return "cpp"  # 默认


def detect_frameworks(
    project_root: Path,
    language: str,
    skills_dir: Path,
) -> List[str]:
    """扫描项目文件检测框架信号，返回 framework_labels。

    读取 ``languages/{lang}/_meta.yaml`` 中的 framework_signals，
    然后在项目文件中搜索依赖名匹配。
    """
    meta_path = skills_dir / "languages" / language / "_meta.yaml"
    if not meta_path.is_file():
        return []
    meta = _read_yaml(meta_path)
    if not meta or "framework_signals" not in meta:
        return []

    # 收集项目依赖文本（简化：读取 build 文件内容）
    dep_text = _collect_dependency_text(project_root, language)

    detected: List[str] = []
    for fw_label, fw_meta in meta["framework_signals"].items():
        dep_patterns = fw_meta.get("dependency_patterns", [])
        for pattern in dep_patterns:
            if pattern.lower() in dep_text.lower():
                detected.append(fw_label)
                break

    return detected


def _collect_dependency_text(project_root: Path, language: str) -> str:
    """收集项目依赖文件的文本内容（用于框架信号匹配）。"""
    parts: List[str] = []
    build_files = {
        "java": ["pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle"],
        "python": ["requirements.txt", "setup.py", "pyproject.toml", "Pipfile"],
        "go": ["go.mod"],
        "rust": ["Cargo.toml"],
    }
    for fname in build_files.get(language, []):
        fpath = project_root / fname
        if fpath.is_file():
            try:
                parts.append(fpath.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                pass
    return "\n".join(parts)


# ── 工具函数 ─────────────────────────────────────────────────────────────────


def _read_yaml(path: Path) -> Dict[str, Any]:
    """安全读取 YAML 文件，返回 dict 或空 dict。"""
    if not path.is_file():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception as exc:
        logger.debug("YAML 读取失败 (%s): %s", path, exc)
        return {}


def _extract_cwe_number(source_cwe: Any) -> str:
    """从 source_cwe 字段提取 CWE 编号（去掉 CWE- 前缀）。"""
    if isinstance(source_cwe, list):
        if source_cwe:
            return str(source_cwe[0]).replace("CWE-", "").strip()
        return ""
    if isinstance(source_cwe, str):
        return source_cwe.replace("CWE-", "").strip()
    return ""
