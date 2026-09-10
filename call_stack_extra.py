"""
`call_stack_extra.py` 负责处理“漏洞调用链”和“漏洞函数信息”这两类数据库数据。

这两个函数本身并不做复杂分析，它们的核心职责是：
1. 用固定 SQL 从 PG 中取数
2. 把原始结果转换成更统一、后续更易分析的结构
"""

import json
import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def get_call_chains(db_connector, cve_id: str):
    """
    根据漏洞编号读取调用链。

    Args:
        db_connector: 具备 `execute_query` 方法的数据库连接包装器。
        cve_id: 漏洞编号。

    Returns:
        原始数据库结果列表。每行通常包含：
        - `call_stack`
        - `entry_point_function_name`
        - `component_name`
    """
    query = """
    SELECT call_stack, entry_point_function_name, component_name
    FROM vuln.vuln_call_chains
    WHERE cve_id = %s;
    """
    try:
        # 使用参数化查询，避免把用户输入直接拼进 SQL。
        return db_connector.execute_query(query, (cve_id,))
    except Exception as exc:
        logger.error("查询调用链失败: %s", exc)
        return []


def get_vuln_info(db_connector, cve_id: str):
    """
    根据漏洞编号读取漏洞函数的基础信息。

    Args:
        db_connector: 数据库连接包装器。
        cve_id: 漏洞编号。

    Returns:
        原始结果列表。字段通常包括类名、函数名、返回值、参数列表、文件路径。
    """
    query = """
    SELECT method_owner, method_function, return_type, parameter_types, filepath
    FROM vuln.vuln_chain
    WHERE vuln_id = %s;
    """
    try:
        return db_connector.execute_query(query, (cve_id,))
    except Exception as exc:
        logger.error("查询漏洞基础信息失败: %s", exc)
        return []


def normalize_call_chains(raw_rows: List[Any]) -> List[Dict[str, Any]]:
    """
    把调用链结果标准化成统一字典结构。

    Args:
        raw_rows: 原始数据库结果，可能是 tuple 列表，也可能是 dict 列表。

    Returns:
        统一格式的调用链列表，每个元素都包含组件名、入口函数名和调用栈。
    """
    normalized_rows: List[Dict[str, Any]] = []
    for row in raw_rows or []:
        # 兼容两类返回风格：
        # - `RealDictCursor` 返回字典
        # - 普通 cursor 返回元组
        call_stack = row["call_stack"] if isinstance(row, dict) else row[0]
        entry_point = row["entry_point_function_name"] if isinstance(row, dict) else row[1]
        component_name = row["component_name"] if isinstance(row, dict) else row[2]

        if isinstance(call_stack, str):
            try:
                # 某些驱动会把 JSONB 自动转成字符串，这里补一次反序列化。
                call_stack = json.loads(call_stack)
            except json.JSONDecodeError:
                # 如果字符串不是合法 JSON，至少保留原始内容，避免信息直接丢失。
                call_stack = [{"raw": call_stack}]

        normalized_rows.append(
            {
                "component_name": component_name,
                "entry_point_function_name": entry_point,
                "call_stack": call_stack,
            }
        )
    return normalized_rows


def normalize_vuln_info(raw_rows: List[Any]) -> Dict[str, Any]:
    """
    把漏洞函数信息标准化成单个字典。

    Args:
        raw_rows: 原始数据库结果。

    Returns:
        标准化后的漏洞函数信息；如果没有数据则返回空字典。
    """
    if not raw_rows:
        return {}

    first_row = raw_rows[0]
    if isinstance(first_row, dict):
        return dict(first_row)

    return {
        "method_owner": first_row[0],
        "method_function": first_row[1],
        "return_type": first_row[2],
        "parameter_types": first_row[3],
        "filepath": first_row[4],
    }