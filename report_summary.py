"""
扫描报告终态摘要：统一口径，避免把 LLM 初稿「✅ 是」误认为实锤漏洞。
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from report_parse import classify_chunks, split_report_chunks


_REFUTATION_RE = re.compile(
    r"refutation_verdict[^`\n]*`([^`]+)`",
    re.IGNORECASE,
)
_L2_RE = re.compile(r"L2 静态补证[^|\n]*\|\s*`([^`]+)`")
_BODY_VERDICT_RE = re.compile(r"是否真实漏洞[：:]\s*([^\n]+)")
_POC_SECTION_RE = re.compile(
    r"漏洞利用[：:]\s*\n", re.IGNORECASE
)


def _normalize_verdict_line(line: str) -> str:
    return (line or "").strip()


def _body_says_yes(text: str) -> bool:
    match = _BODY_VERDICT_RE.search(text or "")
    if not match:
        return bool(re.search(r"是否真实漏洞[：:]\s*[`]*✅\s*是", text or ""))
    line = match.group(1)
    if "❌" in line or "否" in line.split("✅")[0]:
        return False
    return "✅" in line and "是" in line


def _body_says_no(text: str) -> bool:
    match = _BODY_VERDICT_RE.search(text or "")
    if match:
        return "❌" in match.group(1) or "否" in match.group(1)
    return bool(re.search(r"是否真实漏洞[：:]\s*[`]*❌\s*否", text or ""))


def _has_system_override(text: str) -> bool:
    return "系统覆写" in (text or "") or "判定与修复（系统覆写" in (text or "")


def _has_actionable_poc(text: str) -> bool:
    if not text:
        return False
    if re.search(r"漏洞利用[：:]\s*[`]*无[`]*", text):
        return False
    if re.search(r"漏洞利用[：:]\s*无\s*$", text, re.MULTILINE):
        return False
    return bool(_POC_SECTION_RE.search(text)) and len(text) > 200


def _finding_for_flow(
    flow_id: str, findings_index: Optional[List[Dict[str, Any]]]
) -> Optional[Dict[str, Any]]:
    for item in findings_index or []:
        if str(item.get("flow_id")) == flow_id:
            return item
    return None


def terminal_status_for_flow(
    *,
    flow_id: str,
    refutation_verdict: str = "",
    l2_status: str = "",
    analysis_text: str = "",
    structured_text: str = "",
) -> Dict[str, str]:
    """供扫描器写入结构化块时复用的终态分类（与顶部一览表同口径）。"""
    finding = {}
    if refutation_verdict:
        finding["refutation_verdict"] = refutation_verdict
    if l2_status:
        finding["l2_status"] = l2_status
    chunks = [c for c in (structured_text, analysis_text) if c]
    return classify_flow_terminal_status(
        flow_id=flow_id,
        chunks=chunks,
        finding=finding or None,
    )


def classify_flow_terminal_status(
    *,
    flow_id: str,
    chunks: List[str],
    finding: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    """返回终态分类与说明（系统唯一口径）。"""
    combined = "\n".join(chunks)
    refutation = ""
    ref_match = _REFUTATION_RE.search(combined)
    if ref_match:
        refutation = ref_match.group(1).strip().lower()
    if finding and finding.get("refutation_verdict"):
        refutation = str(finding["refutation_verdict"]).lower()

    l2_status = ""
    l2_match = _L2_RE.search(combined)
    if l2_match:
        l2_status = l2_match.group(1).strip().lower()
    if finding and finding.get("l2_status"):
        l2_status = str(finding["l2_status"]).lower()

    draft_yes = _body_says_yes(combined)
    draft_no = _body_says_no(combined)
    overridden = _has_system_override(combined)
    poc_ok = _has_actionable_poc(combined)

    refutation_cn = {
        "confirmed": "反证确认",
        "likely_false_positive": "反证：误报",
        "inconclusive": "反证：证据不足",
        "needs_dynamic_test": "反证：需动态验证",
    }.get(refutation, refutation or "无")

    if refutation == "confirmed" and draft_yes and poc_ok and not overridden:
        return {
            "flow_id": flow_id,
            "terminal": "实锤",
            "exploitable": "是",
            "reproducible": "见 PoC",
            "draft": "✅ 是",
            "refutation": refutation_cn,
            "note": "refutation=confirmed 且具备 PoC",
        }

    if refutation == "likely_false_positive" or (
        draft_no and refutation != "confirmed"
    ):
        note = "反证 LLM 判定为误报/有防御"
        if draft_yes and not overridden:
            note = "正文初稿写「✅ 是」，但反证否决（见结构化判定表）"
        if overridden:
            note = "初稿「✅ 是」已被系统规则覆写为 ❌ 否"
        return {
            "flow_id": flow_id,
            "terminal": "非漏洞",
            "exploitable": "否",
            "reproducible": "否",
            "draft": "✅ 是" if draft_yes else ("❌ 否" if draft_no else "—"),
            "refutation": refutation_cn,
            "note": note,
        }

    if refutation == "needs_dynamic_test":
        return {
            "flow_id": flow_id,
            "terminal": "待动态验证",
            "exploitable": "待定",
            "reproducible": "未测",
            "draft": "✅ 是" if draft_yes else "—",
            "refutation": refutation_cn,
            "note": "L2 已补，需 L3 动态/业务验证",
        }

    if draft_yes or overridden:
        return {
            "flow_id": flow_id,
            "terminal": "未证实",
            "exploitable": "否",
            "reproducible": "未验证",
            "draft": "✅ 是",
            "refutation": refutation_cn,
            "note": (
                "初稿倾向真实漏洞，但反证未 confirmed"
                + (f"；L2={l2_status}" if l2_status else "")
                + "——不算实锤"
            ),
        }

    return {
        "flow_id": flow_id,
        "terminal": "待定",
        "exploitable": "否",
        "reproducible": "未验证",
        "draft": "❌ 否" if draft_no else "—",
        "refutation": refutation_cn,
        "note": "证据不足或待补 L2",
    }


def build_executive_summary(
    report_text: str,
    *,
    flow_findings_index: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """从报告正文 + flow_findings_index 生成顶部终态一览。"""
    _, chunks = split_report_chunks(report_text or "")
    flow_chunks, _, _ = classify_chunks(chunks)
    if not flow_chunks:
        return ""

    rows: List[Dict[str, str]] = []
    for flow_id in sorted(flow_chunks.keys()):
        finding = _finding_for_flow(flow_id, flow_findings_index)
        vuln_type = flow_id.rsplit("-flow-", 1)[0] if "-flow-" in flow_id else "?"
        status = classify_flow_terminal_status(
            flow_id=flow_id,
            chunks=flow_chunks[flow_id],
            finding=finding,
        )
        status["vuln_type"] = vuln_type
        rows.append(status)

    counts: Dict[str, int] = {}
    for row in rows:
        counts[row["terminal"]] = counts.get(row["terminal"], 0) + 1

    confirmed = [r for r in rows if r["terminal"] == "实锤"]
    draft_yes_not_confirmed = [
        r for r in rows if r["draft"] == "✅ 是" and r["terminal"] != "实锤"
    ]

    lines = [
        "## 📋 审计结论一览（终态口径）",
        "",
        "> **请以此表为准。** 正文里单独的「是否真实漏洞：✅ 是」是 LLM 初稿，"
        "须经反证 LLM + 系统规则收敛后，以本表「终态」为准。",
        "> **实锤** = `refutation_verdict=confirmed` 且报告含可执行 PoC；否则不算挖到洞。",
        "",
        "### 数量统计",
        "",
        "| 终态 | 条数 |",
        "|------|------|",
    ]
    for label in ("实锤", "非漏洞", "未证实", "待动态验证", "待定"):
        if counts.get(label):
            lines.append(f"| {label} | {counts[label]} |")
    lines.append(f"| **合计 flow** | **{len(rows)}** |")
    lines.append("")

    lines.append("### 全部 flow 终态")
    lines.append("")
    lines.append(
        "| flow_id | 类型 | 终态 | 反证 | 初稿 | 可利用 | 可复现 | 说明 |"
    )
    lines.append("|---------|------|------|------|------|--------|--------|------|")
    for row in rows:
        lines.append(
            f"| `{row['flow_id']}` | {row.get('vuln_type', '?')} | **{row['terminal']}** | "
            f"{row['refutation']} | {row['draft']} | {row['exploitable']} | "
            f"{row['reproducible']} | {row['note'][:48]} |"
        )
    lines.append("")

    if confirmed:
        lines.append("### ✅ 实锤漏洞")
        lines.append("")
        for row in confirmed:
            lines.append(f"- `{row['flow_id']}`（{row.get('vuln_type')}）")
        lines.append("")
    else:
        lines.append("### ✅ 实锤漏洞")
        lines.append("")
        lines.append("**（无）** 本轮无 `refutation_verdict=confirmed` 且带 PoC 的 flow。")
        lines.append("")

    if draft_yes_not_confirmed:
        lines.append(
            "### ⚠️ 初稿写「✅ 是」但终态非实锤（勿当挖到洞）"
        )
        lines.append("")
        lines.append("| flow_id | 终态 | 反证 | 说明 |")
        lines.append("|---------|------|------|------|")
        for row in draft_yes_not_confirmed:
            lines.append(
                f"| `{row['flow_id']}` | {row['terminal']} | {row['refutation']} | "
                f"{row['note'][:60]} |"
            )
        lines.append("")
        lines.append(
            "> 查看否决依据：在正文中搜索该 flow_id → 看 **「📊 结构化判定」** 表的 "
            "`refutation_verdict`、**反证摘要**、**阻断/支撑因素**；"
            "若存在 **「判定与修复（系统覆写）」** 段落，表示规则层已改为 ❌ 否。"
        )
        lines.append("")

    return "\n".join(lines)


def inject_executive_summary(
    report_text: str,
    *,
    flow_findings_index: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """在报告标题后注入终态一览（已存在则先移除旧块）。"""
    text = (report_text or "").strip()
    if not text:
        return text

    summary = build_executive_summary(text, flow_findings_index=flow_findings_index)
    if not summary:
        return text

    stripped = re.sub(
        r"\n*## 📋 审计结论一览（终态口径）[\s\S]*?(?=\n---\n|\n## 漏洞类型:|\n## 🔎 |\Z)",
        "\n",
        text,
        count=1,
    ).strip()

    preamble, chunks = split_report_chunks(stripped)
    if not preamble:
        return f"{summary}\n\n---\n" + "\n---\n".join(chunks)

    insert_at = preamble.find("\n---\n")
    if insert_at == -1:
        legend_end = preamble.find("\n\n", preamble.find("证据层级说明"))
        if legend_end != -1:
            return (
                preamble[: legend_end + 1]
                + "\n"
                + summary
                + "\n"
                + preamble[legend_end + 1 :]
                + ("\n---\n" + "\n---\n".join(chunks) if chunks else "")
            ).strip() + "\n"
        return f"{preamble}\n\n{summary}\n" + (
            "\n---\n" + "\n---\n".join(chunks) if chunks else ""
        )

    return (
        preamble[:insert_at]
        + "\n\n"
        + summary
        + preamble[insert_at:]
        + ("\n---\n" + "\n---\n".join(chunks) if chunks else "")
    ).strip() + "\n"
