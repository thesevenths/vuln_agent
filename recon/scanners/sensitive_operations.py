"""
recon/scanners/sensitive_operations.py — 高价值操作标定

消费适配器返回的敏感操作查询结果，
利用 handler 名称前缀匹配关联 EntryPoint → SensitiveOperation（reachable_from），
输出带可达入口标注的 SensitiveOperation 列表。
"""
from __future__ import annotations

import logging
from typing import Dict, List, Set

from recon.adapters.base import ReconAdapter
from recon.models import EntryPoint, SensitiveOperation

logger = logging.getLogger(__name__)


def scan_sensitive_operations(
    query_results: Dict[str, str],
    adapter: ReconAdapter,
    entries: List[EntryPoint],
) -> List[SensitiveOperation]:
    """
    从 Joern 查询结果中识别敏感操作，并标注其可达入口。

    Args:
        query_results: Joern 批量查询的原始结果。
        adapter: 语言/框架适配器。
        entries: 已发现的 EntryPoint 列表（用于 reachability 关联）。

    Returns:
        SensitiveOperation 列表（含 reachable_from）。
    """
    ops = adapter.parse_sensitive_operations(query_results)
    logger.info("适配器解析敏感操作: %d 个", len(ops))

    if not ops:
        return ops

    # 构建 handler 前缀索引（class_name -> list of entry handlers）
    entry_class_map: Dict[str, List[str]] = {}
    entry_handlers: Set[str] = set()
    for ep in entries:
        entry_handlers.add(ep.handler)
        class_name = ep.handler.rsplit(".", 1)[0] if "." in ep.handler else ep.handler
        entry_class_map.setdefault(class_name, []).append(ep.handler)

    # 构建 callee 反向索引：callee_method -> list of entry handlers
    callee_to_entries: Dict[str, List[str]] = {}
    for ep in entries:
        for callee in (ep.callees or []):
            callee_to_entries.setdefault(callee, []).append(ep.handler)

    # 关联 reachable_from（caller_chain → 字符串匹配 → callee 正向追溯）
    for op in ops:
        reachable = _find_reachable_via_caller_chain(op, entry_handlers, entry_class_map)
        if not reachable:
            reachable = _find_reachable_entries(op, entry_class_map, entry_handlers)
        if not reachable:
            reachable = _find_reachable_via_callees(op, callee_to_entries)
        op.reachable_from = reachable

    # 按类型统计
    type_counts: Dict[str, int] = {}
    risk_counts: Dict[str, int] = {}
    reachable_count = 0
    for op in ops:
        type_counts[op.operation_type] = type_counts.get(op.operation_type, 0) + 1
        risk_counts[op.risk_level] = risk_counts.get(op.risk_level, 0) + 1
        if op.reachable_from:
            reachable_count += 1

    logger.info(
        "敏感操作统计: %d 个可从入口可达, 类型分布=%s, 风险分布=%s",
        reachable_count,
        dict(sorted(type_counts.items())),
        dict(sorted(risk_counts.items())),
    )

    return ops


def _find_reachable_via_caller_chain(
    op: SensitiveOperation,
    entry_handlers: Set[str],
    entry_class_map: Dict[str, List[str]],
) -> List[str]:
    """
    通过 caller_chain（向上 2 层）查找可达的 EntryPoint。

    策略：
    1. 精确匹配：caller_chain 中的方法名 == 某个 EntryPoint handler
    2. 类名前缀匹配：caller 所在类 == 某个 EntryPoint 所在类
    """
    if not op.caller_chain:
        return []

    reachable: List[str] = []

    for caller_name in op.caller_chain:
        # ① 精确匹配
        if caller_name in entry_handlers:
            reachable.append(caller_name)
            continue

        # ② 类名匹配：caller 和 entry 在同一个类中
        caller_class = caller_name.rsplit(".", 1)[0] if "." in caller_name else ""
        if caller_class and caller_class in entry_class_map:
            reachable.extend(entry_class_map[caller_class])
            if len(reachable) >= 5:
                break

    return reachable[:10]


def _find_reachable_entries(
    op: SensitiveOperation,
    entry_class_map: Dict[str, List[str]],
    entry_handlers: Set[str],
) -> List[str]:
    """
    查找可从哪些 EntryPoint 到达此敏感操作。

    策略：
    1. 精确匹配：敏感操作的 handler 本身就是 EntryPoint
    2. 同类匹配：敏感操作所在类有 EntryPoint（Controller → Service 同包）
    3. 名称前缀匹配：handler 前缀与某个 EntryPoint handler 前缀重叠
    """
    reachable: List[str] = []

    # ① 精确匹配
    if op.handler in entry_handlers:
        return [op.handler]

    # ② 同类匹配
    op_class = op.handler.rsplit(".", 1)[0] if "." in op.handler else ""
    if op_class and op_class in entry_class_map:
        reachable.extend(entry_class_map[op_class])

    # ③ Service 层匹配：
    #    op.handler = com.example.service.UserService.updateUser
    #    entry 在 com.example.controller.UserController → 同模块
    if not reachable and op_class:
        # 提取 "service" 之前的包路径
        pkg_parts = op_class.rsplit(".", 1)
        if len(pkg_parts) == 2:
            pkg = pkg_parts[0]  # com.example.service 或 com.example
            # 查找同包或上层包下的 Controller
            for entry_cls, entry_list in entry_class_map.items():
                if entry_cls.startswith(pkg.rsplit(".", 1)[0] if "." in pkg else pkg):
                    reachable.extend(entry_list)
                    if len(reachable) >= 5:
                        break

    return reachable[:10]  # 限制最多 10 个可达入口，避免过长


def _find_reachable_via_callees(
    op: SensitiveOperation,
    callee_to_entries: Dict[str, List[str]],
) -> List[str]:
    """
    通过 entry_points 的 callees（向下 2 层）查找可达的 EntryPoint。

    这是 caller_chain 反向追溯的补充：当敏感操作没有 caller_chain 时，
    通过正向追溯（entry → callees）找到哪些入口能到达该敏感操作。

    策略：
    1. 精确匹配：敏感操作 handler 出现在某 entry 的 callees 中
    2. sink_call 匹配：敏感操作的 sink_call 与 callee 短名匹配
    3. 类名前缀：callee 所在类 == 敏感操作所在类
    """
    reachable: List[str] = []
    seen: Set[str] = set()

    # ① 精确匹配：op.handler 直接出现在 entry.callees 中
    for callee, entry_list in callee_to_entries.items():
        if callee == op.handler:
            for eh in entry_list:
                if eh not in seen:
                    reachable.append(eh)
                    seen.add(eh)

    if reachable:
        return reachable[:10]

    # ② sink_call 短名匹配：op.sink_call == callee 的短名
    sink_name = op.sink_call or op.handler.rsplit(".", 1)[-1] if "." in op.handler else ""
    if sink_name:
        for callee, entry_list in callee_to_entries.items():
            callee_short = callee.rsplit(".", 1)[-1] if "." in callee else callee
            # 取方法名部分（去掉参数签名）
            callee_method = callee_short.split(":")[0] if ":" in callee_short else callee_short
            if callee_method == sink_name:
                for eh in entry_list:
                    if eh not in seen:
                        reachable.append(eh)
                        seen.add(eh)
                if len(reachable) >= 5:
                    break

    if reachable:
        return reachable[:10]

    # ③ 类名前缀匹配：callee 所在类 == op 所在类
    op_class = op.handler.rsplit(".", 1)[0] if "." in op.handler else ""
    if op_class:
        for callee, entry_list in callee_to_entries.items():
            callee_class = callee.rsplit(".", 1)[0] if "." in callee else ""
            if callee_class == op_class:
                for eh in entry_list:
                    if eh not in seen:
                        reachable.append(eh)
                        seen.add(eh)
                if len(reachable) >= 5:
                    break

    return reachable[:10]
