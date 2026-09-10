"""
`cve_knowledge_extractor.py` 从 CVE 数据库提取漏洞模式，生成可执行审计知识。

核心思路：
1. 按 CWE 分类聚合 CVE 数据，提取共性模式（高频 sink 函数、调用链模式、补丁模式）
2. 按组件（如 mbedtls、spring、struts）提取漏洞模式
3. 将提取结果交给 `cve_skill_generator.py` 生成可执行 Skill

数据库依赖：PostgreSQL `vuln.*` schema，表包括：
- `vuln.vuln_call_chains`（cve_id, call_stack, entry_point_function_name, component_name）
- `vuln.vuln_chain`（vuln_id, method_owner, method_function, return_type, parameter_types, filepath）
- 以及其他 CVE 元数据表（cve_id, cwe_id, description, patch_url, affected_versions 等）
"""

import json
import logging
import re
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional

from db_connector import PostgresDB

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# CWE ID → 对应 Joern 查询 key 的映射（用于定向扫描）
CWE_TO_JOERN_QUERY_TYPE: Dict[str, List[str]] = {
    "CWE-120": ["cpp_buffer_overflow", "cpp_can_or_buffer_parsing", "embedded_buffer_parsing"],
    "CWE-416": ["cpp_use_after_free"],
    "CWE-415": ["cpp_double_free"],
    "CWE-190": ["cpp_integer_overflow"],
    "CWE-787": ["cpp_array_index_oob", "embedded_ioctl_mmio"],
    "CWE-78": ["cpp_command_injection", "command_injection", "embedded_command_injection"],
    "CWE-22": ["cpp_path_traversal", "path_traversal", "embedded_path_traversal"],
    "CWE-89": ["sql_injection"],
    "CWE-502": ["insecure_deserialization"],
    "CWE-918": ["ssrf"],
    "CWE-611": ["xxe"],
    "CWE-798": ["cpp_hardcoded_secret", "hardcoded_secrets"],
    "CWE-327": ["cpp_weak_crypto", "weak_crypto", "embedded_crypto_misuse"],
    "CWE-362": ["cpp_race_condition", "embedded_race_condition", "cpp_concurrent_uaf_risk"],
    "CWE-476": ["cpp_null_deref"],
    "CWE-131": ["cpp_unsafe_alloc"],
    "CWE-134": ["cpp_format_string", "embedded_format_string"],
    "CWE-457": ["cpp_uninit_read"],
    "CWE-676": ["cpp_dangerous_func"],
}


class CVEKnowledgeExtractor:
    """从 CVE 数据库提取漏洞模式，生成可执行审计知识。"""

    def __init__(self, dsn: Optional[str] = None):
        self.dsn = dsn

    def _connect(self):
        return PostgresDB(dsn=self.dsn)

    # ------------------------------------------------------------------
    # 内部工具方法
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_function_names_from_call_stack(call_stack: Any) -> List[str]:
        """从调用栈（可能是 list/dict/str）中提取函数名列表。"""
        names: List[str] = []
        if isinstance(call_stack, str):
            try:
                call_stack = json.loads(call_stack)
            except json.JSONDecodeError:
                # 尝试从纯文本中提取函数名模式
                found = re.findall(r'[\w:]+(?:\([^)]*\))?', call_stack)
                return [f.strip() for f in found if len(f.strip()) > 3]
        if isinstance(call_stack, list):
            for item in call_stack:
                if isinstance(item, str):
                    names.append(item.strip())
                elif isinstance(item, dict):
                    for key in ("function_name", "method", "callee", "name"):
                        if key in item:
                            names.append(str(item[key]).strip())
        elif isinstance(call_stack, dict):
            for key in ("function_name", "method", "callee", "name"):
                if key in call_stack:
                    names.append(str(call_stack[key]).strip())
        return [n for n in names if n and len(n) > 2]

    @staticmethod
    def _normalize_cwe_id(raw_cwe: Any) -> Optional[str]:
        """标准化 CWE ID（如 '120' → 'CWE-120'，'CWE-120' → 'CWE-120'）。"""
        if not raw_cwe:
            return None
        cwe_str = str(raw_cwe).strip()
        if cwe_str.upper().startswith("CWE-"):
            return cwe_str.upper()
        if cwe_str.isdigit():
            return f"CWE-{cwe_str}"
        # 尝试提取数字部分
        match = re.search(r'(\d+)', cwe_str)
        if match:
            return f"CWE-{match.group(1)}"
        return None

    # ------------------------------------------------------------------
    # 核心提取方法
    # ------------------------------------------------------------------

    def extract_cwe_patterns(self, cwe_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        按 CWE 分类聚合 CVE 数据，提取共性模式。

        Args:
            cwe_id: 可选，指定某个 CWE。若为 None 则提取所有 CWE 的模式。

        Returns:
            每个 CWE 的模式摘要列表，包含：
            - cwe_id
            - cve_count: 该 CWE 下的 CVE 数量
            - common_sinks: 高频 sink 函数名列表
            - common_components: 高频受影响组件
            - call_chain_patterns: 典型调用链模式
        """
        try:
            with self._connect() as db:
                # 尝试查询 CVE 元数据表（适配多种可能的表名）
                cve_rows = self._query_cve_metadata(db, cwe_id)
                if not cve_rows:
                    logger.info("extract_cwe_patterns: 未查询到 CVE 元数据")
                    return []

                # 按 CWE 分组
                cwe_groups: Dict[str, List[Dict]] = defaultdict(list)
                for row in cve_rows:
                    row_cwe = self._normalize_cwe_id(
                        row.get("cwe_id") if isinstance(row, dict) else None
                    )
                    if row_cwe:
                        cwe_groups[row_cwe].append(row)

                results = []
                for group_cwe, cves in cwe_groups.items():
                    pattern = self._build_cwe_pattern(group_cwe, cves, db)
                    if pattern:
                        results.append(pattern)

                return results
        except Exception as exc:
            logger.error("extract_cwe_patterns 失败: %s", exc)
            return []

    def _query_cve_metadata(self, db, cwe_id: Optional[str]) -> List[Dict]:
        """查询 CVE 元数据，适配多种可能的表结构。"""
        # 尝试多种表名（用户说公网爬取的数据都在 DB 中）
        table_candidates = [
            "vuln.cve_info",
            "vuln.cves",
            "vuln.cve_metadata",
            "vuln.vuln_info",
            "vuln.cve_details",
        ]
        for table in table_candidates:
            try:
                if cwe_id:
                    # 支持 CWE-120 和 120 两种格式
                    cwe_clean = cwe_id.replace("CWE-", "").replace("cwe-", "")
                    sql = (
                        f"SELECT * FROM {table} "
                        f"WHERE cwe_id = %s OR cwe_id = %s OR CAST(cwe_id AS TEXT) LIKE %s "
                        f"LIMIT 500"
                    )
                    rows = db.execute_query(sql, (cwe_id, cwe_clean, f"%{cwe_clean}%"))
                else:
                    sql = f"SELECT * FROM {table} LIMIT 2000"
                    rows = db.execute_query(sql)
                if rows:
                    logger.info("CVE 元数据查询成功: %s, 返回 %d 行", table, len(rows))
                    return rows
            except Exception:
                continue
        return []

    def _build_cwe_pattern(self, cwe_id: str, cves: List[Dict], db) -> Optional[Dict[str, Any]]:
        """为单个 CWE 构建模式摘要。"""
        sink_counter: Counter = Counter()
        component_counter: Counter = Counter()
        call_chain_patterns: List[Dict] = []

        # 提取 CVE ID 列表，用于查询调用链
        cve_ids = []
        for cve in cves:
            if isinstance(cve, dict):
                cve_id_val = cve.get("cve_id") or cve.get("cve_number") or cve.get("id")
                if cve_id_val:
                    cve_ids.append(str(cve_id_val))

        # 查询这些 CVE 的调用链和漏洞函数信息
        if cve_ids:
            for target_cve in cve_ids[:20]:  # 限制查询量
                try:
                    # 查调用链
                    chain_sql = (
                        "SELECT call_stack, entry_point_function_name, component_name "
                        "FROM vuln.vuln_call_chains WHERE cve_id = %s"
                    )
                    chains = db.execute_query(chain_sql, (target_cve,))
                    for chain in chains:
                        if isinstance(chain, dict):
                            fn_names = self._extract_function_names_from_call_stack(
                                chain.get("call_stack")
                            )
                            sink_counter.update(fn_names)
                            comp = chain.get("component_name")
                            if comp:
                                component_counter[str(comp)] += 1
                        elif isinstance(chain, (list, tuple)) and len(chain) >= 3:
                            fn_names = self._extract_function_names_from_call_stack(chain[0])
                            sink_counter.update(fn_names)
                            if chain[2]:
                                component_counter[str(chain[2])] += 1

                    # 查漏洞函数
                    vuln_sql = (
                        "SELECT method_function, filepath "
                        "FROM vuln.vuln_chain WHERE vuln_id = %s"
                    )
                    vulns = db.execute_query(vuln_sql, (target_cve,))
                    for vuln in vulns:
                        if isinstance(vuln, dict):
                            fn = vuln.get("method_function")
                            if fn:
                                sink_counter[str(fn)] += 1
                        elif isinstance(vuln, (list, tuple)) and len(vuln) >= 2:
                            if vuln[0]:
                                sink_counter[str(vuln[0])] += 1
                except Exception as exc:
                    logger.warning("查询 CVE %s 的调用链失败: %s", target_cve, exc)
                    continue

        if not sink_counter and not component_counter:
            # 即使没有调用链数据，也返回基本 CWE 信息
            return {
                "cwe_id": cwe_id,
                "cve_count": len(cves),
                "common_sinks": [],
                "common_components": [],
                "call_chain_patterns": [],
                "joern_query_types": CWE_TO_JOERN_QUERY_TYPE.get(cwe_id, []),
            }

        # 取 top 15 的 sink 函数
        top_sinks = [name for name, _ in sink_counter.most_common(15)]
        top_components = [name for name, _ in component_counter.most_common(10)]

        return {
            "cwe_id": cwe_id,
            "cve_count": len(cves),
            "common_sinks": top_sinks,
            "common_components": top_components,
            "call_chain_patterns": call_chain_patterns[:10],
            "joern_query_types": CWE_TO_JOERN_QUERY_TYPE.get(cwe_id, []),
        }

    def extract_component_patterns(self, component: str) -> List[Dict[str, Any]]:
        """
        按组件（如 mbedtls, spring, struts）提取漏洞模式。

        Args:
            component: 组件名称。

        Returns:
            该组件下的漏洞模式列表。
        """
        try:
            with self._connect() as db:
                # 查询该组件的调用链
                sql = (
                    "SELECT DISTINCT cve_id, call_stack, entry_point_function_name "
                    "FROM vuln.vuln_call_chains WHERE component_name ILIKE %s LIMIT 200"
                )
                rows = db.execute_query(sql, (f"%{component}%",))
                if not rows:
                    return []

                sink_counter: Counter = Counter()
                cwe_counter: Counter = Counter()
                cve_ids_seen = set()

                for row in rows:
                    if isinstance(row, dict):
                        cve_id = row.get("cve_id", "")
                        call_stack = row.get("call_stack")
                    else:
                        cve_id = row[0] if len(row) > 0 else ""
                        call_stack = row[1] if len(row) > 1 else None

                    if cve_id:
                        cve_ids_seen.add(str(cve_id))
                    fn_names = self._extract_function_names_from_call_stack(call_stack)
                    sink_counter.update(fn_names)

                return [{
                    "component": component,
                    "cve_count": len(cve_ids_seen),
                    "common_sinks": [n for n, _ in sink_counter.most_common(15)],
                    "cve_ids": list(cve_ids_seen)[:20],
                }]
        except Exception as exc:
            logger.error("extract_component_patterns 失败: %s", exc)
            return []

    def get_sink_patterns_for_cwe(self, cwe_id: str) -> List[str]:
        """
        提取某个 CWE 下最常见的 sink 函数名。

        Args:
            cwe_id: 如 'CWE-120'。

        Returns:
            sink 函数名列表（按频率降序）。
        """
        patterns = self.extract_cwe_patterns(cwe_id)
        for p in patterns:
            if p.get("cwe_id") == cwe_id:
                return p.get("common_sinks", [])
        return []

    def get_call_chain_patterns(self, cwe_id: str) -> List[Dict[str, Any]]:
        """
        提取某个 CWE 的典型 source→sink 调用链模式。

        Args:
            cwe_id: 如 'CWE-89'。

        Returns:
            调用链模式列表。
        """
        patterns = self.extract_cwe_patterns(cwe_id)
        for p in patterns:
            if p.get("cwe_id") == cwe_id:
                return p.get("call_chain_patterns", [])
        return []

    def get_all_cwe_ids(self) -> List[str]:
        """获取数据库中所有出现过的 CWE ID。"""
        try:
            with self._connect() as db:
                rows = self._query_cve_metadata(db, None)
                cwe_ids = set()
                for row in rows:
                    if isinstance(row, dict):
                        cwe = self._normalize_cwe_id(row.get("cwe_id"))
                    else:
                        cwe = None
                    if cwe:
                        cwe_ids.add(cwe)
                return sorted(cwe_ids)
        except Exception as exc:
            logger.error("get_all_cwe_ids 失败: %s", exc)
            return []
