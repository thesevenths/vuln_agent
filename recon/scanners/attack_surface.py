"""
recon/scanners/attack_surface.py — 攻击面地图生成

融合所有 Scanner 结果：
- ProjectInfo（项目结构）
- EntryPoint（入口清单）
- AuthMechanism（鉴权机制）
- SensitiveOperation（敏感操作）
- AuthCoverage（鉴权覆盖状态）

生成：
- AttackPath（entry → intermediate → sink，标注 has_auth / missing_controls）
- AttackSurfaceMap JSON（最终产出）
- coverage_summary（各 CWE 覆盖统计）
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

from recon.models import (
    AttackPath,
    AttackSurfaceMap,
    AuthMechanism,
    CallChainNode,
    EntryPoint,
    ProjectInfo,
    SensitiveOperation,
)
from recon.scanners.auth_mechanisms import AuthCoverage

logger = logging.getLogger(__name__)

# CWE 映射：缺失的安全控制 → CWE 编号
_MISSING_CONTROL_CWE = {
    "no_auth": "CWE-306",          # Missing Authentication
    "no_authz": "CWE-862",         # Missing Authorization
    "no_ownership": "CWE-639",     # Authorization Bypass Through User Control
    "no_csrf": "CWE-352",          # Cross-Site Request Forgery
    "no_input_validation": "CWE-20",  # Improper Input Validation
    "no_rate_limit": "CWE-770",    # Allocation of Resources Without Limits
    "privilege_escalation": "CWE-269",  # Improper Privilege Management
    "race_condition": "CWE-362",   # Concurrent Execution (Race Condition)
}


def build_attack_surface(
    project_info: ProjectInfo,
    entries: List[EntryPoint],
    auth_mechs: List[AuthMechanism],
    sensitive_ops: List[SensitiveOperation],
    auth_coverage: Dict[str, AuthCoverage],
    content_type_entries: Dict[str, List[str]],
) -> AttackSurfaceMap:
    """
    融合所有 Scanner 结果，生成完整攻击面地图。

    Args:
        project_info: 项目结构信息。
        entries: 入口点列表。
        auth_mechs: 鉴权机制列表。
        sensitive_ops: 敏感操作列表。
        auth_coverage: handler -> AuthCoverage 映射。
        content_type_entries: Content-Type -> handler 列表。

    Returns:
        AttackSurfaceMap 实例。
    """
    # ① 生成 AttackPath
    attack_paths = _build_attack_paths(entries, sensitive_ops, auth_coverage)

    # ② 计算 coverage_summary
    coverage_summary = _compute_coverage_summary(
        entries, auth_coverage, sensitive_ops, attack_paths, content_type_entries,
    )

    # ③ 组装 AttackSurfaceMap
    attack_map = AttackSurfaceMap(
        project_info=project_info,
        entry_points=entries,
        auth_mechanisms=auth_mechs,
        sensitive_operations=sensitive_ops,
        attack_paths=attack_paths,
        content_type_entries=content_type_entries,
        coverage_summary=coverage_summary,
        scanned_at=datetime.now(timezone.utc).isoformat(),
    )

    logger.info(attack_map.summary())
    return attack_map


def _build_attack_paths(
    entries: List[EntryPoint],
    sensitive_ops: List[SensitiveOperation],
    auth_coverage: Dict[str, AuthCoverage],
) -> List[AttackPath]:
    """
    构建 entry → sink 的攻击路径。

    对每个有 reachable_from 的敏感操作，为每个可达入口生成一条 AttackPath。
    使用 caller_chain 填充 intermediate 调用链节点。
    """
    paths: List[AttackPath] = []

    # 构建方法名 → (file, line) 的查找表，用于解析 intermediate 节点
    method_info: Dict[str, tuple] = {}
    entry_by_handler: Dict[str, EntryPoint] = {}
    for ep in entries:
        method_info[ep.handler] = (ep.file, ep.line)
        entry_by_handler[ep.handler] = ep
    for op in sensitive_ops:
        if op.handler and op.file:
            method_info[op.handler] = (op.file, op.line)

    for op in sensitive_ops:
        if not op.reachable_from:
            continue

        for entry_handler in op.reachable_from:
            cov = auth_coverage.get(entry_handler)
            has_auth = bool(cov and cov.is_protected)
            auth_mech_list = cov.mechanism_types if cov else []

            # 构建 intermediate 调用链节点
            intermediate_nodes = _build_intermediate_nodes(
                op, entry_handler, method_info, entry_by_handler,
            )

            # 推断缺失的安全控制
            missing = _infer_missing_controls(
                has_auth=has_auth,
                auth_coverage=cov,
                op_type=op.operation_type,
                entry_type=_get_entry_type(entry_handler, entries),
            )

            paths.append(AttackPath(
                entry=entry_handler,
                intermediate=intermediate_nodes,
                sink=op.handler,
                has_auth=has_auth,
                auth_mechanisms=auth_mech_list,
                missing_controls=missing,
            ))

    # 按风险排序：missing_controls 多的优先，无鉴权的优先
    paths.sort(key=lambda p: (-len(p.missing_controls), not p.has_auth, p.entry))

    logger.info("生成攻击路径: %d 条", len(paths))
    return paths


def _build_intermediate_nodes(
    op: SensitiveOperation,
    entry_handler: str,
    method_info: Dict[str, tuple],
    entry_by_handler: Dict[str, EntryPoint],
) -> List[CallChainNode]:
    """
    构建从 entry 到 sink 之间的 intermediate 调用链节点。

    优先级：
    1. 从 sensitive op 的 caller_chain（反向追溯）
    2. 从 entry 的 callees（正向追溯，当 caller_chain 无结果时）

    返回不含 entry 和 sink 本身的中间节点。
    """
    nodes: List[CallChainNode] = []

    # ① 反向追溯：caller_chain
    if op.caller_chain:
        for caller_name in op.caller_chain:
            if caller_name == entry_handler:
                continue
            info = method_info.get(caller_name)
            file_path = info[0] if info else ""
            line_num = info[1] if info else 0
            nodes.append(CallChainNode(
                method=caller_name,
                file=file_path,
                line=line_num,
            ))

    # ② 正向追溯：entry callees（当 caller_chain 无结果时）
    if not nodes:
        ep = entry_by_handler.get(entry_handler)
        if ep and ep.callees:
            sink_short = op.handler.rsplit(".", 1)[-1] if "." in op.handler else op.handler
            sink_method = sink_short.split(":")[0] if ":" in sink_short else sink_short
            for callee in ep.callees:
                # 跳过 entry 和 sink 本身
                if callee == entry_handler or callee == op.handler:
                    continue
                callee_short = callee.rsplit(".", 1)[-1] if "." in callee else callee
                callee_method = callee_short.split(":")[0] if ":" in callee_short else callee_short
                # 跳过 sink 方法（避免重复）
                if callee_method == sink_method:
                    continue
                info = method_info.get(callee)
                file_path = info[0] if info else ""
                line_num = info[1] if info else 0
                nodes.append(CallChainNode(
                    method=callee,
                    file=file_path,
                    line=line_num,
                ))
                if len(nodes) >= 5:  # 限制中间节点数量
                    break

    return nodes


def _infer_missing_controls(
    has_auth: bool,
    auth_coverage: Optional[AuthCoverage],
    op_type: str,
    entry_type: str,
) -> List[str]:
    """根据鉴权状态和操作类型推断缺失的安全控制"""
    missing: List[str] = []

    # CWE-306: 无认证
    if not has_auth:
        missing.append(_MISSING_CONTROL_CWE["no_auth"])

    # CWE-862: 有认证但无授权
    if has_auth and auth_coverage:
        # 检查是否有 authorization 类注解
        has_authz = any(
            a in ("annotation", "aop", "filter")
            for a in auth_coverage.mechanism_types
        )
        has_authz_annotation = any(
            any(kw in ann.lower() for kw in ("authorize", "secured", "roles", "permit", "deny", "hasrole"))
            for ann in auth_coverage.annotations
        )
        if not has_authz_annotation and op_type in ("financial", "auth_change", "cmd_exec"):
            missing.append(_MISSING_CONTROL_CWE["no_authz"])

    # CWE-639: 数据修改类操作缺少 ownership 检查
    if op_type in ("db_write", "financial", "auth_change"):
        missing.append(_MISSING_CONTROL_CWE["no_ownership"])

    # CWE-352: 状态修改操作（POST/PUT/DELETE）缺少 CSRF 保护
    if entry_type == "http" and op_type in ("db_write", "financial", "auth_change", "file_io"):
        missing.append(_MISSING_CONTROL_CWE["no_csrf"])

    # CWE-269: 权限变更操作
    if op_type == "auth_change":
        missing.append(_MISSING_CONTROL_CWE["privilege_escalation"])

    # CWE-362: 资金操作需要防并发
    if op_type == "financial":
        missing.append(_MISSING_CONTROL_CWE["race_condition"])

    return missing


def _get_entry_type(handler: str, entries: List[EntryPoint]) -> str:
    """根据 handler 查找对应的 EntryPoint 类型"""
    for ep in entries:
        if ep.handler == handler:
            return ep.entry_type
    return "http"


def _compute_coverage_summary(
    entries: List[EntryPoint],
    auth_coverage: Dict[str, AuthCoverage],
    sensitive_ops: List[SensitiveOperation],
    attack_paths: List[AttackPath],
    content_type_entries: Dict[str, List[str]],
) -> Dict[str, int]:
    """
    计算各 CWE 的覆盖统计。

    统计维度：
    - 总入口数 / 受保护入口数 / 无鉴权入口数
    - 总敏感操作数 / 可达敏感操作数
    - 总攻击路径数 / 无鉴权路径数
    - 各 CWE 缺失次数
    """
    summary: Dict[str, int] = {}

    # 基础统计
    summary["total_entries"] = len(entries)
    summary["protected_entries"] = sum(1 for c in auth_coverage.values() if c.is_protected)
    summary["unprotected_entries"] = summary["total_entries"] - summary["protected_entries"]

    summary["total_sensitive_ops"] = len(sensitive_ops)
    summary["reachable_sensitive_ops"] = sum(1 for op in sensitive_ops if op.reachable_from)

    summary["total_attack_paths"] = len(attack_paths)
    summary["unauth_attack_paths"] = sum(1 for p in attack_paths if not p.has_auth)

    # CWE 缺失统计
    cwe_counts: Dict[str, int] = {}
    for path in attack_paths:
        for cwe in path.missing_controls:
            cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1

    # 把 CWE 统计加入 summary
    for cwe, count in sorted(cwe_counts.items()):
        summary[f"missing_{cwe}"] = count

    # Content-Type 统计
    for ct, handlers in content_type_entries.items():
        ct_key = ct.replace("/", "_").replace("-", "_")
        summary[f"content_type_{ct_key}"] = len(handlers)

    return summary
