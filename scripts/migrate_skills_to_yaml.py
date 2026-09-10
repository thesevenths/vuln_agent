"""
Skill 目录结构迁移脚本：将 templates/cwe/cwe_XXX.json 拆分为新目录结构。

每个 cwe_XXX.json → {category}/cwe_XXX/{skill.yaml, reasoning.yaml, patterns.yaml}
语言特化部分 → languages/{java,python}/...

运行方式：python scripts/migrate_skills_to_yaml.py
"""

import json
import os
import re
from pathlib import Path

# 尝试导入 yaml，如果没安装则用内置的简易 YAML 输出
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

SKILLS_DIR = Path(__file__).resolve().parent.parent / "skills"
CWE_DIR = SKILLS_DIR / "templates" / "cwe"

# CWE -> category 映射
CWE_CATEGORY = {
    # authorization
    "862": "authorization", "863": "authorization", "287": "authorization",
    "306": "authorization", "352": "authorization", "836": "authorization",
    "285": "authorization", "284": "authorization",
    # business_logic
    "639": "business_logic", "840": "business_logic", "841": "business_logic",
    "915": "business_logic", "362": "business_logic", "367": "business_logic",
    "269": "business_logic", "276": "business_logic", "307": "business_logic",
    "384": "business_logic", "521": "business_logic", "610": "business_logic",
    "613": "business_logic", "640": "business_logic", "899": "business_logic",
    # injection
    "89": "injection", "79": "injection", "78": "injection",
    "611": "injection", "502": "injection", "22": "injection",
    "918": "injection", "200": "injection", "798": "injection",
    "341": "injection", "330": "injection",
}

# 语言特化字段名
LANG_SPECIFIC_ROUTE_PATTERNS = {"java", "python", "go", "javascript", "php", "dotnet", "ruby", "rust"}
LANG_WE_CARE = {"java", "python"}


def yaml_str(val, indent=0):
    """安全地将 Python 值转为 YAML 字符串（不依赖 pyyaml）。"""
    if HAS_YAML:
        return yaml.dump(val, allow_unicode=True, default_flow_style=False, sort_keys=False).rstrip('\n')
    # 简易 YAML 序列化
    return _to_yaml(val, indent_level=indent)


def _to_yaml(val, indent_level=0):
    """简易 YAML 序列化（支持 dict/list/scalar）。"""
    prefix = "  " * indent_level
    if isinstance(val, dict):
        if not val:
            return "{}"
        lines = []
        for k, v in val.items():
            if isinstance(v, (dict, list)) and v:
                lines.append(f"{prefix}{k}:")
                lines.append(_to_yaml(v, indent_level + 1))
            else:
                lines.append(f"{prefix}{k}: {_scalar(v)}")
        return "\n".join(lines)
    elif isinstance(val, list):
        if not val:
            return "[]"
        lines = []
        for item in val:
            if isinstance(item, (dict, list)) and item:
                # 第一个 key 放在 - 后面
                if isinstance(item, dict):
                    first = True
                    for k, v in item.items():
                        if first:
                            lines.append(f"{prefix}- {k}: {_scalar(v) if not isinstance(v, (dict, list)) else ''}")
                            if isinstance(v, (dict, list)) and v:
                                lines.append(_to_yaml(v, indent_level + 2))
                            first = False
                        else:
                            lines.append(f"{prefix}  {k}: {_scalar(v) if not isinstance(v, (dict, list)) else ''}")
                            if isinstance(v, (dict, list)) and v:
                                lines.append(_to_yaml(v, indent_level + 2))
                else:
                    lines.append(f"{prefix}-")
                    lines.append(_to_yaml(item, indent_level + 1))
            else:
                lines.append(f"{prefix}- {_scalar(item)}")
        return "\n".join(lines)
    else:
        return f"{prefix}{_scalar(val)}"


def _scalar(val):
    """序列化标量值。"""
    if val is None:
        return "null"
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, (int, float)):
        return str(val)
    s = str(val)
    # 需要引号的情况：包含特殊字符、是布尔/数字的字符串
    needs_quote = (
        not s or
        s.lower() in ('true', 'false', 'null', 'yes', 'no', 'on', 'off') or
        any(c in s for c in ':#{}[]|>&*!%@`,"\'\\') or
        s.startswith('- ') or s.startswith('? ') or
        re.match(r'^\d+(\.\d+)?$', s)
    )
    if needs_quote:
        # 使用单引号，内部单引号用双单引号转义
        return "'" + s.replace("'", "''") + "'"
    return s


def write_yaml_file(path: Path, content: str):
    """写入 YAML 文件。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content + "\n", encoding="utf-8")
    print(f"  -> {path.relative_to(SKILLS_DIR)}")


def extract_language_patterns(data: dict) -> dict:
    """从 trigger_condition 中提取语言特化的 route_patterns。"""
    lang_patterns = {"java": [], "python": []}
    tc = data.get("trigger_condition", {})
    ot = tc.get("operation_triggers", {})
    rp = ot.get("route_patterns", {})
    for lang in LANG_WE_CARE:
        if lang in rp:
            lang_patterns[lang] = rp[lang]
    return lang_patterns


def extract_lang_query_keywords(data: dict) -> dict:
    """从 logic_query_keywords 中提取语言特化部分。"""
    lqk = data.get("logic_query_keywords", {})
    result = {}
    for lang in LANG_WE_CARE:
        if lang in lqk:
            result[lang] = lqk[lang]
    if "generic" in lqk:
        result["generic"] = lqk["generic"]
    return result


def build_skill_yaml(data: dict, cwe_num: str) -> str:
    """构建 skill.yaml 内容。"""
    lines = [
        f"# CWE-{cwe_num} Skill 元数据",
        f"# 从 templates/cwe/cwe_{cwe_num}.json 迁移",
        "",
        f"skill_id: {data.get('skill_id', f'cwe_{cwe_num}')}",
        f"source_cwe: CWE-{cwe_num}",
        f"priority: {data.get('priority', 'P0')}",
    ]
    # related_cwes
    related = data.get("related_cwes", [])
    if related:
        lines.append("")
        lines.append("related_cwes:")
        if isinstance(related[0], dict):
            for r in related:
                lines.append(f"  - cwe: {r.get('cwe', '')}")
                lines.append(f"    reason: {_scalar(r.get('reason', ''))}")
        else:
            for r in related:
                lines.append(f"  - {r}")
    # description (从 trigger_condition.operation_triggers.description 提取)
    desc = data.get("trigger_condition", {}).get("operation_triggers", {}).get("description", "")
    if desc:
        lines.append("")
        lines.append(f"description: {_scalar(desc)}")
    return "\n".join(lines)


def build_reasoning_yaml(data: dict, cwe_num: str) -> str:
    """构建 reasoning.yaml 内容。"""
    lines = [
        f"# CWE-{cwe_num} 分析推理流程",
        "",
    ]
    # reasoning_workflow
    rw = data.get("reasoning_workflow", [])
    if rw:
        lines.append("reasoning_workflow:")
        for step in rw:
            lines.append(f"  - {_scalar(step)}")
        lines.append("")
    # knowledge_injection
    ki = data.get("knowledge_injection", {})
    if ki:
        lines.append("knowledge_injection:")
        fse = ki.get("few_shot_examples", [])
        if fse:
            lines.append("  few_shot_examples:")
            for ex in fse:
                lines.append(f"    - code_snippet: {_scalar(ex.get('code_snippet', ''))}")
                lines.append(f"      vulnerability_analysis: {_scalar(ex.get('vulnerability_analysis', ''))}")
                fix = ex.get("fix_pattern", "")
                if fix:
                    lines.append(f"      fix_pattern: {_scalar(fix)}")
        mr = ki.get("mitigation_rules", [])
        if mr:
            lines.append("  mitigation_rules:")
            for rule in mr:
                lines.append(f"    - {_scalar(rule)}")
        lines.append("")
    # differentiation_from_sast
    dfs = data.get("differentiation_from_sast", [])
    if dfs:
        lines.append("differentiation_from_sast:")
        for item in dfs:
            lines.append(f"  - {_scalar(item)}")
        lines.append("")
    # anti_patterns
    ap = data.get("anti_patterns", [])
    if ap:
        lines.append("anti_patterns:")
        for item in ap:
            lines.append(f"  - {_scalar(item)}")
        lines.append("")
    # output_schema
    os_ = data.get("output_schema", {})
    if os_:
        lines.append("output_schema:")
        for k, v in os_.items():
            lines.append(f"  {k}: {_scalar(v)}")
    return "\n".join(lines)


def build_patterns_yaml(data: dict, cwe_num: str) -> str:
    """构建 patterns.yaml 内容（不含语言特化部分）。"""
    lines = [
        f"# CWE-{cwe_num} 检测模式",
        "",
    ]
    tc = data.get("trigger_condition", {})
    # ast_patterns
    ap = tc.get("ast_patterns", [])
    if ap:
        lines.append("ast_patterns:")
        for p in ap:
            lines.append(f"  - {_scalar(p)}")
        lines.append("")
    # semantic_keywords
    sk = tc.get("semantic_keywords", [])
    if sk:
        lines.append("semantic_keywords:")
        for kw in sk:
            lines.append(f"  - {_scalar(kw)}")
        lines.append("")
    # file_context
    fc = tc.get("file_context", [])
    if fc:
        lines.append("file_context:")
        for f in fc:
            lines.append(f"  - {_scalar(f)}")
        lines.append("")
    # operation_triggers (不含 route_patterns，那部分移到 languages/)
    ot = tc.get("operation_triggers", {})
    so = ot.get("sensitive_operations", [])
    if so:
        lines.append("sensitive_operations:")
        for op in so:
            lines.append(f"  - {_scalar(op)}")
        lines.append("")
    # logic_query_keywords (不含语言特化部分)
    lqk = data.get("logic_query_keywords", {})
    generic = lqk.get("generic", {})
    if generic:
        lines.append("logic_query_keywords_generic:")
        for k, v in generic.items():
            if isinstance(v, list):
                lines.append(f"  {k}:")
                for item in v:
                    lines.append(f"    - {_scalar(item)}")
            else:
                lines.append(f"  {k}: {_scalar(v)}")
        lines.append("")
    # sanitizers
    san = data.get("sanitizers", [])
    if san:
        lines.append("sanitizers:")
        for s in san:
            lines.append(f"  - {_scalar(s)}")
    return "\n".join(lines)


def build_lang_patterns(cwe_num: str, lang_patterns: dict, lang_query_keywords: dict) -> str:
    """构建语言特化的 patterns 片段（追加到 languages/{lang}/ 下的文件）。"""
    lines = [f"# CWE-{cwe_num} 语言特化检测模式"]
    # route_patterns
    for lang in LANG_WE_CARE:
        rp = lang_patterns.get(lang, [])
        if rp:
            lines.append(f"")
            lines.append(f"# --- {lang} route patterns ---")
            lines.append(f"cwe_{cwe_num}_route_patterns:")
            for p in rp:
                lines.append(f"  - {_scalar(p)}")
    # lang-specific query keywords
    for lang in LANG_WE_CARE:
        lk = lang_query_keywords.get(lang, {})
        if lk:
            lines.append(f"")
            lines.append(f"# --- {lang} query keywords ---")
            lines.append(f"cwe_{cwe_num}_{lang}_keywords:")
            for k, v in lk.items():
                if isinstance(v, list):
                    lines.append(f"  {k}:")
                    for item in v:
                        lines.append(f"    - {_scalar(item)}")
                else:
                    lines.append(f"  {k}: {_scalar(v)}")
    return "\n".join(lines)


def migrate_cwe_file(json_path: Path) -> dict:
    """迁移单个 CWE JSON 文件。返回 {cwe_num, category, target_dir}。"""
    data = json.loads(json_path.read_text(encoding="utf-8"))
    # 提取 CWE 编号
    source_cwe = data.get("source_cwe", [])
    if isinstance(source_cwe, list) and source_cwe:
        cwe_num = str(source_cwe[0]).replace("CWE-", "")
    else:
        # 从文件名提取
        cwe_num = json_path.stem.replace("cwe_", "")
    category = CWE_CATEGORY.get(cwe_num, "business_logic")  # default to business_logic
    target_dir = SKILLS_DIR / category / f"cwe_{cwe_num}"
    # 构建三个文件
    skill_content = build_skill_yaml(data, cwe_num)
    reasoning_content = build_reasoning_yaml(data, cwe_num)
    patterns_content = build_patterns_yaml(data, cwe_num)
    # 写入
    write_yaml_file(target_dir / "skill.yaml", skill_content)
    write_yaml_file(target_dir / "reasoning.yaml", reasoning_content)
    write_yaml_file(target_dir / "patterns.yaml", patterns_content)
    # 提取语言特化部分
    lang_patterns = extract_language_patterns(data)
    lang_query_keywords = extract_lang_query_keywords(data)
    if any(lang_patterns.get(l) for l in LANG_WE_CARE) or any(lang_query_keywords.get(l) for l in LANG_WE_CARE):
        lang_content = build_lang_patterns(cwe_num, lang_patterns, lang_query_keywords)
        # 追加到 languages/{lang}/cwe_patterns.yaml
        for lang in LANG_WE_CARE:
            if lang_patterns.get(lang) or lang_query_keywords.get(lang):
                lang_file = SKILLS_DIR / "languages" / lang / "cwe_patterns.yaml"
                if lang_file.exists():
                    existing = lang_file.read_text(encoding="utf-8")
                    lang_file.write_text(existing.rstrip() + "\n\n" + lang_content + "\n", encoding="utf-8")
                    print(f"  -> languages/{lang}/cwe_patterns.yaml (appended CWE-{cwe_num})")
                else:
                    write_yaml_file(lang_file, f"# 语言特化 CWE 检测模式\n# 由迁移脚本从 templates/cwe/ 提取\n\n{lang_content}")
    return {"cwe_num": cwe_num, "category": category, "target_dir": target_dir}


def main():
    print("=" * 60)
    print("Skill 目录迁移：JSON -> YAML")
    print("=" * 60)
    print(f"源目录: {CWE_DIR}")
    print(f"目标目录: {SKILLS_DIR}")
    print()

    # 跳过非 CWE 文件
    skip_files = {"cwe_logic_common.json", "cwe_high", "note"}
    results = []
    for json_file in sorted(CWE_DIR.glob("cwe_*.json")):
        if json_file.name in skip_files:
            print(f"  SKIP: {json_file.name} (fragment/non-CWE)")
            continue
        print(f"\n迁移: {json_file.name}")
        try:
            result = migrate_cwe_file(json_file)
            results.append(result)
        except Exception as e:
            print(f"  ERROR: {e}")

    print(f"\n{'=' * 60}")
    print(f"迁移完成: {len(results)} 个 CWE 模板")
    print(f"  authorization: {sum(1 for r in results if r['category'] == 'authorization')}")
    print(f"  business_logic: {sum(1 for r in results if r['category'] == 'business_logic')}")
    print(f"  injection: {sum(1 for r in results if r['category'] == 'injection')}")


if __name__ == "__main__":
    main()
