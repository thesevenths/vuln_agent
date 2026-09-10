"""
flow_reconcile.py — Planner 侧模糊 flow 收口与 L2 状态同步

Scanner 在 scan 时写入 ambiguous_flows / flow_findings_index；
Planner 通过 FileTool 读 L2 后，本模块负责：
  1. 按已读文件更新 flow_findings_index 的 l2_status
  2. 将满足条件的模糊 flow 从 ambiguous_flows 移除
  3. 生成「已证实 / 未决」分段的终态报告
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from joern_vuln_scanner import JoernVulnScannerHTTP as JoernVulnScanner
from l2_reads import sanitize_l2_read_path


def _norm_path(path: str) -> str:
    return str(path or "").replace("\\", "/").lower().strip()


def _basename(path: str) -> str:
    return Path(_norm_path(path)).name


def _paths_match(target: str, read_path: str) -> bool:
    """目标 L2 路径与已读路径是否匹配（含 basename 后缀匹配）。"""
    t = _norm_path(target)
    r = _norm_path(read_path)
    if not t or not r:
        return False
    if t == r or r.endswith("/" + t) or t.endswith("/" + r):
        return True
    return _basename(t) == _basename(r) and _basename(t) not in ("", ".", "..")


def _parse_line_range(lines_field: str) -> Optional[Tuple[int, int]]:
    if not lines_field:
        return None
    match = re.match(r"^(\d+)-(\d+)$", str(lines_field).strip())
    if not match:
        return None
    return int(match.group(1)), int(match.group(2))


def _collect_read_ranges_for_path(path_norm: str, reads: List[Dict[str, Any]]) -> List[Tuple[int, int]]:
    ranges: List[Tuple[int, int]] = []
    for entry in reads:
        if _norm_path(entry.get("path", "")) != path_norm and not _paths_match(
            path_norm, entry.get("path", "")
        ):
            continue
        parsed = _parse_line_range(entry.get("lines", ""))
        if parsed:
            ranges.append(parsed)
    return ranges


def _line_range_covered(start: int, end: int, ranges: List[Tuple[int, int]]) -> bool:
    for rs, re_ in ranges:
        if rs <= start and re_ >= end:
            return True
    return False


def is_l2_path_read(
    target_path: str,
    *,
    read_path_keys: Set[str],
    file_evidence_reads: List[Dict[str, Any]],
    local_source_path: Optional[str] = None,
) -> bool:
    """判断某条 L2 建议路径是否已被 FileTool 读过。"""
    normalized = sanitize_l2_read_path(target_path, local_source_path)
    if not normalized:
        return False
    norm = _norm_path(normalized)
    for key in read_path_keys:
        if _paths_match(norm, key):
            return True
    for entry in file_evidence_reads:
        if _paths_match(norm, entry.get("path", "")):
            return True
    return False


def update_flow_findings_l2_status(
    state_metadata: Dict[str, Any],
    *,
    local_source_path: Optional[str] = None,
) -> int:
    """
    根据 file_evidence_reads 更新 flow_findings_index 中各 flow 的 l2_status。

    Returns:
        被更新为 present 的 flow 条数。
    """
    findings = list(state_metadata.get("flow_findings_index") or [])
    pending = list(state_metadata.get("pending_l2_reads") or [])
    reads = list(state_metadata.get("file_evidence_reads") or [])
    read_keys = set()
    for entry in reads:
        path = entry.get("path", "")
        if path:
            read_keys.add(_norm_path(path))
        lines = entry.get("lines")
        if lines:
            read_keys.add(f"{_norm_path(path)}:{lines}")

    updated = 0
    for item in findings:
        flow_id = item.get("flow_id")
        if not flow_id:
            continue
        flow_pending = [p for p in pending if p.get("flow_id") == flow_id]
        if not flow_pending:
            continue
        all_read = all(
            is_l2_path_read(
                p.get("path", ""),
                read_path_keys=read_keys,
                file_evidence_reads=reads,
                local_source_path=local_source_path,
            )
            for p in flow_pending
            if p.get("path")
        )
        if all_read and flow_pending:
            item["l2_status"] = "present"
            updated += 1
        elif any(
            is_l2_path_read(
                p.get("path", ""),
                read_path_keys=read_keys,
                file_evidence_reads=reads,
                local_source_path=local_source_path,
            )
            for p in flow_pending
            if p.get("path")
        ):
            if item.get("l2_status") == "absent":
                item["l2_status"] = "partial"

    state_metadata["flow_findings_index"] = findings
    return updated


def _finding_for_flow(
    flow_id: str, findings: List[Dict[str, Any]]
) -> Optional[Dict[str, Any]]:
    for item in findings:
        if item.get("flow_id") == flow_id:
            return item
    return None


def _flow_l2_satisfied(
    flow_info: Dict[str, Any],
    *,
    pending: List[Dict[str, Any]],
    read_keys: Set[str],
    reads: List[Dict[str, Any]],
    local_source_path: Optional[str],
    finding: Optional[Dict[str, Any]] = None,
) -> bool:
    flow_id = flow_info.get("flow_id", "")
    flow_pending = [p for p in pending if p.get("flow_id") == flow_id]
    if not flow_pending:
        l2_status = str((finding or {}).get("l2_status", "")).lower()
        if l2_status == "present":
            return True
        if l2_status in ("absent", "partial"):
            return False
        return False
    return all(
        is_l2_path_read(
            p.get("path", ""),
            read_path_keys=read_keys,
            file_evidence_reads=reads,
            local_source_path=local_source_path,
        )
        for p in flow_pending
        if p.get("path")
    )


def _should_resolve_ambiguous_flow(
    flow_info: Dict[str, Any],
    finding: Optional[Dict[str, Any]],
    *,
    l2_satisfied: bool,
) -> Optional[str]:
    """
    判断是否可将模糊 flow 收口。

    Returns:
        收口原因；None 表示仍模糊。
    """
    analysis = flow_info.get("analysis", "") or ""
    meta = flow_info.get("meta") or {}
    backtrace = meta.get("backtrace") or {}
    refutation = meta.get("refutation") or {}
    stop_reason = str(backtrace.get("stop_reason", ""))

    structured = JoernVulnScanner._classify_structured_verdict(analysis)
    if structured == "no":
        return "structured_verdict_no"
    if structured == "yes":
        return "structured_verdict_yes"

    ref_verdict = str(
        (finding or {}).get("refutation_verdict")
        or refutation.get("verdict", "")
    ).lower()
    l2_status = str((finding or {}).get("l2_status", "")).lower()

    if ref_verdict == "likely_false_positive" and l2_satisfied:
        return "refutation_false_positive_with_l2"
    if ref_verdict == "likely_false_positive" and stop_reason == "guard_logic_found":
        return "refutation_false_positive_with_guard"
    if stop_reason == "guard_logic_found" and l2_satisfied:
        return "guard_logic_with_l2"
    if l2_status == "present" and ref_verdict == "likely_false_positive":
        return "finding_l2_present_false_positive"
    if l2_satisfied and ref_verdict in ("likely_false_positive", "needs_dynamic_test"):
        if stop_reason in ("guard_logic_found", "source_reached"):
            return f"l2_satisfied_{stop_reason}"
    if l2_satisfied and l2_status == "present" and ref_verdict == "inconclusive":
        return "deferred_to_l3"
    return None


def reconcile_ambiguous_flows(
    ambiguous_flows: List[Dict[str, Any]],
    state_metadata: Dict[str, Any],
    *,
    local_source_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    根据 L2 已读与 flow_findings 更新模糊 flow 列表。

    Returns:
        {
            "remaining": 仍模糊的 flow 列表,
            "resolved": [{flow_id, reason}, ...],
            "l2_updates": update_flow_findings_l2_status 的更新数,
        }
    """
    update_flow_findings_l2_status(
        state_metadata, local_source_path=local_source_path
    )
    findings = list(state_metadata.get("flow_findings_index") or [])
    pending = list(state_metadata.get("pending_l2_reads") or [])
    reads = list(state_metadata.get("file_evidence_reads") or [])
    read_keys: Set[str] = set()
    for entry in reads:
        path = entry.get("path", "")
        if path:
            read_keys.add(_norm_path(path))

    remaining: List[Dict[str, Any]] = []
    resolved: List[Dict[str, str]] = []
    needs_l3: List[Dict[str, Any]] = []

    for flow_info in ambiguous_flows:
        flow_id = flow_info.get("flow_id", "")
        finding = _finding_for_flow(flow_id, findings)
        l2_ok = _flow_l2_satisfied(
            flow_info,
            pending=pending,
            read_keys=read_keys,
            reads=reads,
            local_source_path=local_source_path,
            finding=finding,
        )
        reason = _should_resolve_ambiguous_flow(
            flow_info, finding, l2_satisfied=l2_ok
        )
        if reason:
            resolved.append({"flow_id": flow_id, "reason": reason})
            if reason == "deferred_to_l3":
                needs_l3.append(
                    {
                        "flow_id": flow_id,
                        "vuln_type": flow_info.get("vuln_type"),
                        "note": "L2 已补齐，静态反证仍 inconclusive，转 L3 动态验证",
                    }
                )
        else:
            remaining.append(flow_info)

    return {
        "remaining": remaining,
        "resolved": resolved,
        "needs_l3": needs_l3,
        "l2_updates": len(resolved),
    }


def build_planner_l2_context_bundle(
    state_metadata: Dict[str, Any],
    *,
    flow_id: Optional[str] = None,
    max_chars: int = 12000,
) -> str:
    """将 Planner 已读 L2 内容拼成可注入 Scanner 反证的文本块。"""
    previews = list(state_metadata.get("file_evidence_content") or [])
    pending = list(state_metadata.get("pending_l2_reads") or [])
    if flow_id:
        tagged = [
            p for p in previews if str(p.get("flow_id") or "") == flow_id
        ]
        if tagged:
            previews = tagged
        flow_paths: Set[str] = set()
        for p in pending:
            if p.get("flow_id") == flow_id and p.get("path"):
                flow_paths.add(_norm_path(p.get("path", "")))
        catalog = (state_metadata.get("flow_catalog") or {}).get(flow_id) or {}
        try:
            from flow_merge import parse_sink_location

            sink_file = parse_sink_location(catalog.get("sink_label", "")).get("file", "")
            if sink_file:
                flow_paths.add(_norm_path(sink_file))
        except Exception:
            sink_file = ""
        if flow_paths:
            filtered = [
                p
                for p in previews
                if any(_paths_match(fp, p.get("path", "")) for fp in flow_paths)
            ]
            if filtered:
                previews = filtered
            elif sink_file:
                sink_dir = str(Path(_norm_path(sink_file)).parent).lower()
                if sink_dir and sink_dir != ".":
                    previews = [
                        p
                        for p in previews
                        if sink_dir in _norm_path(p.get("path", ""))
                    ] or previews
    if not previews:
        previews = list(state_metadata.get("file_evidence_content") or [])

    lines = ["### Planner 已读 L2 静态证据（FileTool）\n"]
    total = 0
    for entry in previews[-20:]:
        path = entry.get("path", "?")
        line_range = f"L{entry.get('start_line')}-{entry.get('end_line')}"
        preview = entry.get("content_preview") or ""
        block = f"\n#### `{path}` ({line_range})\n```\n{preview}\n```\n"
        if total + len(block) > max_chars:
            break
        lines.append(block)
        total += len(block)
    return "".join(lines) if len(lines) > 1 else ""


def _count_confirmed_from_findings(findings: List[Dict[str, Any]]) -> int:
    """从结构化 flow_findings 统计 confirmed，避免 Markdown ✅ 误计数。"""
    count = 0
    for item in findings:
        verdict = str(item.get("refutation_verdict", "")).lower()
        if verdict == "confirmed":
            count += 1
    return count


def _report_is_bounded(report_text: str) -> bool:
    text = (report_text or "").strip()
    return text.startswith("# 漏洞审计终态报告")


def build_bounded_finish_report(
    *,
    last_report: str,
    ambiguous_flows: List[Dict[str, Any]],
    source_scan_count: int,
    max_scan: int,
    resolved_notes: Optional[List[Dict[str, str]]] = None,
    needs_l3_flows: Optional[List[Dict[str, Any]]] = None,
    flow_findings_index: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """
    扫描达上限或 finish 被放行时，生成「已证实 / 未决」分段报告，避免与 state 矛盾。
    """
    amb_count = len(ambiguous_flows)
    l3_count = len(needs_l3_flows or [])
    findings = list(flow_findings_index or [])
    confirmed_count = _count_confirmed_from_findings(findings)
    lines = [
        "# 漏洞审计终态报告\n",
        f"> 源码扫描次数: {min(source_scan_count, max_scan)}/{max_scan}\n",
    ]
    if confirmed_count:
        lines.append(f"> 已确认漏洞: **{confirmed_count}** 条（详见下方扫描报告）\n")
    if resolved_notes:
        lines.append(f"> L2 收口: {len(resolved_notes)} 条模糊 flow 已根据静态证据收敛\n")
    if l3_count:
        lines.append(f"> L3 待验证: {l3_count} 条（L2 已补齐，需动态/业务验证）\n")

    if amb_count == 0 and l3_count == 0:
        if confirmed_count:
            lines.append(
                f"\n## 结论\n\n"
                f"已确认 **{confirmed_count}** 条真实漏洞；所有 flow 均已明确终态。\n"
            )
        else:
            lines.append("\n## 结论\n\n所有 flow 均已明确终态（✅ 是 或 ❌ 否）。\n")
        if last_report and not _report_is_bounded(last_report):
            lines.append("\n---\n\n## 扫描详情\n\n")
            lines.append(last_report[:8000])
        return "".join(lines)

    conclusion_parts = []
    if confirmed_count:
        conclusion_parts.append(f"已确认 **{confirmed_count}** 条真实漏洞")
    conclusion_parts.append(
        f"仍有 **{amb_count}** 条 flow **未完全收敛**"
    )
    if l3_count:
        conclusion_parts.append(f"**{l3_count}** 条转 L3 动态验证")
    lines.append(
        f"\n## 结论\n\n"
        + "；".join(conclusion_parts) + "。\n"
        f"\n> ⚠️ 禁止将本报告理解为「零风险」——未决项见下表。\n"
    )
    if l3_count:
        lines.append("\n## L3 待验证 flow\n\n")
        lines.append("| flow_id | vuln_type | 说明 |\n|---|---|---|\n")
        for item in (needs_l3_flows or [])[:30]:
            lines.append(
                f"| `{item.get('flow_id', '?')}` | {item.get('vuln_type', '?')} | "
                f"{item.get('note', 'L3 待验证')[:80]} |\n"
            )
    lines.append("\n## 未决 flow 清单\n\n")
    lines.append("| flow_id | vuln_type | 上次结论 |\n|---|---|---|\n")
    for item in ambiguous_flows[:30]:
        verdict = JoernVulnScanner._extract_verdict_text(item.get("analysis", ""))
        if not verdict:
            verdict = item.get("previous_verdict", "待确认")
        lines.append(
            f"| `{item.get('flow_id', '?')}` | {item.get('vuln_type', '?')} | {verdict[:60]} |\n"
        )

    scan_detail = last_report or ""
    if _report_is_bounded(scan_detail):
        scan_detail = ""
    elif scan_detail.startswith("## 复核结果"):
        scan_detail = scan_detail
    if scan_detail and not _report_is_bounded(scan_detail):
        lines.append("\n---\n\n## 最近扫描摘要\n\n")
        lines.append(scan_detail[:6000])
    return "".join(lines)
