"""
CWE skill 模板 ↔ Joern logic query 覆盖注册表。

run_logic_scan 流水线：
  Joern logic query 枚举候选 → _extract_logic_candidates → LLM + cwe_xxx.json 深度分析

**仅有 cwe_xxx.json 而无 query → Joern 不会产生候选 → 几乎挖不到漏洞**
（除非被其它 query 的交叉分析附带命中，且 CWE 标签可能错误）

本模块供单元测试与文档引用；运行时映射仍以 joern_vuln_scanner._LOGIC_CWE_QUERY_MAP 为准。

以后新增 **带 source_cwe 的** cwe_NNN.json 时，必须同时加 query + 映射 + 注册表 + 测试，否则 CI 会失败。

**例外**：`cwe_logic_common.json` 等为共享片段（无 source_cwe、不产生 Joern 候选），见 `CWE_TEMPLATE_FRAGMENT_FILES`。

v2: 优先从 skills/registry.yaml 的 cwe_index 加载映射；失败则回退本模块硬编码值。
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, Iterable, List, Set

logger = logging.getLogger(__name__)

# 共享片段：匹配 cwe_*.json  glob，但不是独立 CWE skill，不要求 query/映射
CWE_TEMPLATE_FRAGMENT_FILES: Set[str] = {
    "cwe_logic_common.json",
}


def is_cwe_skill_template_file(filename: str) -> bool:
    """True = 参与 CWE 覆盖 CI 的 skill 模板；False = 仅被 merge 的片段。"""
    return filename not in CWE_TEMPLATE_FRAGMENT_FILES


def iter_cwe_skill_template_paths(cwe_dir: Path) -> Iterable[Path]:
    """遍历 skills/templates/cwe 下需登记 query 的模板文件。"""
    for path in sorted(cwe_dir.glob("cwe_*.json")):
        if is_cwe_skill_template_file(path.name):
            yield path

# 每个 skills/templates/cwe/cwe_*.json 的 source_cwe 至少应映射到下列「主查询」之一
# 主查询 = 能直接产出该 CWE 语义候选的 logic query（非仅 auth_guards 等通用支撑查询）
#
# v2: 优先从 registry.yaml 加载；失败则用下方硬编码值。

_REGISTRY_YAML = Path(__file__).resolve().parent / "skills" / "registry.yaml"

# 硬编码回退值（与 registry.yaml cwe_index 保持同步）
_CWE_PRIMARY_LOGIC_QUERIES_FALLBACK: Dict[str, List[str]] = {
    "862": ["sensitive_operations", "admin_ops_no_auth"],
    "306": ["public_endpoints"],
    "639": ["idor_candidates", "idor_path_variable", "idor_profile"],
    "798": ["hardcoded_credentials_v2"],
    "200": ["info_leak_candidates", "info_leak_response", "mass_data_exposure"],
    "284": ["cors_config"],
    "285": ["business_authz_gap"],
    "841": ["workflow_bypass"],
    "287": ["auth_weakness", "jwt_endpoints", "jwt_weakness"],
    "352": ["csrf_gap"],
    "836": ["client_hash_auth"],
    "863": ["incorrect_authz_source"],
    "899": ["sensitive_operations", "incorrect_authz_source", "business_authz_gap"],
    "22": ["file_ops_risk"],
    "330": ["jwt_weakness"],
    "341": ["jwt_weakness", "jwt_endpoints"],
    "89": ["sqli_risk"],
    "79": ["xss_output_risk"],
    "611": ["xxe_risk"],
    "502": ["deserialization_risk"],
    "78": ["cmd_exec_risk"],
    "367": ["toctou_risk"],
    "840": ["business_logic_risk"],
    "918": ["ssrf_risk"],
    # 新增逻辑漏洞 CWE
    "269": ["privilege_escalation", "sensitive_operations"],
    "276": ["incorrect_permissions", "file_ops_risk"],
    "307": ["brute_force_risk", "auth_weakness"],
    "362": ["race_condition_risk", "toctou_risk"],
    "384": ["session_fixation_risk", "auth_weakness"],
    "521": ["weak_password_requirements"],
    "610": ["payment_tampering", "business_logic_risk"],
    "613": ["session_expiration_risk", "jwt_weakness"],
    "640": ["password_recovery_weakness"],
    "915": ["mass_assignment_risk"],
}


def _load_primary_queries_from_yaml() -> Dict[str, List[str]] | None:
    """尝试从 registry.yaml 的 cwe_index 加载主查询映射。"""
    try:
        import yaml
        if not _REGISTRY_YAML.is_file():
            return None
        reg = yaml.safe_load(_REGISTRY_YAML.read_text(encoding="utf-8"))
        if not isinstance(reg, dict) or "cwe_index" not in reg:
            return None
        return {
            str(cwe): list(entry.get("primary_queries", []))
            for cwe, entry in reg["cwe_index"].items()
        }
    except Exception as exc:
        logger.debug("registry.yaml 加载 CWE_PRIMARY_LOGIC_QUERIES 失败: %s", exc)
        return None


CWE_PRIMARY_LOGIC_QUERIES: Dict[str, List[str]] = (
    _load_primary_queries_from_yaml() or _CWE_PRIMARY_LOGIC_QUERIES_FALLBACK
)

# 支撑性查询（交叉分析、L2 上下文）；单独出现不算 CWE 覆盖
LOGIC_SUPPORT_QUERIES: Set[str] = {
    "auth_guards",
    "security_filter_chain",
    "shiro_auth_guards",
    "shiro_security_config",
    "jaxrs_auth_guards",
    "jaxrs_unprotected_resources",
    "public_endpoints",
    "endpoint_enumeration",
    "sensitive_operations",
}


def cwe_numbers_from_template_filename(name: str) -> List[str]:
    """cwe_862.json → ['862']；片段文件返回空列表。"""
    if not is_cwe_skill_template_file(name):
        return []
    stem = name.replace("cwe_", "").replace(".json", "")
    return [stem]


# ── v2: YAML 目录遍历 ─────────────────────────────────────────────────────

_YAML_CATEGORIES = ("authorization", "business_logic", "injection")


def iter_cwe_skill_yaml_dirs(skills_dir: Path) -> Iterable[Path]:
    """遍历新 YAML 目录结构下所有 CWE skill 目录。"""
    for cat in _YAML_CATEGORIES:
        cat_dir = skills_dir / cat
        if not cat_dir.is_dir():
            continue
        for cwe_dir in sorted(cat_dir.iterdir()):
            if cwe_dir.is_dir() and cwe_dir.name.startswith("cwe_"):
                if (cwe_dir / "skill.yaml").is_file():
                    yield cwe_dir


def cwe_number_from_yaml_dir(dir_name: str) -> str:
    """cwe_862 → 862"""
    return dir_name.replace("cwe_", "")


def validate_cwe_primary_queries(
    cwe_map: Dict[str, List[str]],
    available_queries: Set[str],
    *,
    template_cwes: Set[str],
) -> List[str]:
    """返回缺失覆盖的 CWE 说明列表（空 = 全部 OK）。"""
    errors: List[str] = []
    for cwe in sorted(template_cwes):
        primaries = CWE_PRIMARY_LOGIC_QUERIES.get(cwe, [])
        if not primaries:
            errors.append(f"CWE-{cwe}: 未在 CWE_PRIMARY_LOGIC_QUERIES 登记主查询")
            continue
        mapped = set(cwe_map.get(cwe, []))
        if not mapped:
            errors.append(f"CWE-{cwe}: _LOGIC_CWE_QUERY_MAP 无条目")
            continue
        if not mapped.intersection(primaries):
            errors.append(
                f"CWE-{cwe}: 映射 {sorted(mapped)} 未包含主查询 {primaries}"
            )
        for q in primaries:
            if q not in available_queries:
                errors.append(f"CWE-{cwe}: 主查询 '{q}' 不在 java_logic_queries")
    return errors
