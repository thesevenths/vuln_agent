"""
按 flow_id 合并多轮扫描 Markdown 报告，避免增量/定向扫覆盖首轮结论。
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set

from report_parse import classify_chunks, flow_id_to_vuln_type, split_report_chunks
from report_summary import inject_executive_summary


def _rebuild_type_header(vuln_type: str, flow_ids: List[str], analyzed: int, skipped: int) -> str:
    upper = vuln_type.upper()
    return (
        f"## 漏洞类型: {upper}（共 {len(flow_ids)} 条 flow，"
        f"分析 {analyzed}，跳过 {skipped}）"
    )


def merge_scan_reports(
    existing_report: str,
    new_report: str,
    *,
    flow_findings_index: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """
    将 new_report 中涉及的 flow 块覆盖进 existing_report，其余 flow 保留。
    """
    old_text = (existing_report or "").strip()
    new_text = (new_report or "").strip()
    if not old_text:
        body = new_text
    elif not new_text:
        body = old_text
    else:
        old_preamble, old_chunks = split_report_chunks(old_text)
        new_preamble, new_chunks = split_report_chunks(new_text)

        old_flows, old_type_headers, old_skipped = classify_chunks(old_chunks)
        new_flows, new_type_headers, new_skipped = classify_chunks(new_chunks)

        merged_flows: Dict[str, List[str]] = dict(old_flows)
        for flow_id, chunks in new_flows.items():
            merged_flows[flow_id] = list(chunks)

        all_types: Set[str] = set()
        for flow_id in merged_flows:
            all_types.add(flow_id_to_vuln_type(flow_id).lower())
        all_types.update(old_type_headers.keys())
        all_types.update(new_type_headers.keys())

        preamble = new_preamble if new_preamble else old_preamble
        if old_preamble and new_preamble and old_preamble != new_preamble:
            preamble = new_preamble

        sections: List[str] = [preamble]
        for vuln_type in sorted(all_types):
            flow_ids = sorted(
                fid for fid in merged_flows if flow_id_to_vuln_type(fid).lower() == vuln_type
            )
            if not flow_ids:
                continue
            skipped_chunk = new_skipped.get(vuln_type) or old_skipped.get(vuln_type)
            skipped_count = 0
            if skipped_chunk:
                skipped_count = len(re.findall(r"^-\s*`", skipped_chunk, re.MULTILINE))
            analyzed = max(0, len(flow_ids) - skipped_count)
            sections.append(_rebuild_type_header(vuln_type, flow_ids, analyzed, skipped_count))
            if skipped_chunk:
                sections.append(skipped_chunk)
            for flow_id in flow_ids:
                sections.extend(merged_flows.get(flow_id, []))

        body = "\n---\n".join(sections).strip() + "\n"

    return inject_executive_summary(body, flow_findings_index=flow_findings_index)
