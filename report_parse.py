"""Shared Markdown report chunk parsing for merge/summary."""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

_FLOW_ID_PATTERNS = (
    re.compile(r"##\s*🔎\s*[^\n]+—\s*`([^`]+)`"),
    re.compile(r"##\s*🔎\s*[^\n]+\(([^)]+)\)\s*分析结果"),
    re.compile(r"flow_id\s*\|\s*`([^`]+)`"),
)

_TYPE_HEADER_RE = re.compile(
    r"^##\s*漏洞类型:\s*([A-Z0-9_]+)",
    re.MULTILINE,
)

_SKIPPED_HEADER = "已跳过低质量 flow"


def flow_id_to_vuln_type(flow_id: str) -> str:
    if "-flow-" in flow_id:
        return flow_id.rsplit("-flow-", 1)[0]
    return flow_id


def extract_flow_id(chunk: str) -> Optional[str]:
    for pattern in _FLOW_ID_PATTERNS:
        match = pattern.search(chunk)
        if match:
            return str(match.group(1)).strip()
    return None


def _preamble_and_body_from_first_segment(first: str) -> Tuple[str, List[str]]:
    """首段可能是标题 preamble，也可能是误并入的 flow 块（报告以 --- 开头时）。"""
    segment = (first or "").strip()
    if not segment or segment == "---":
        return "", []
    if segment.startswith("---"):
        segment = segment[3:].lstrip("\n").strip()
        if not segment:
            return "", []
    if _TYPE_HEADER_RE.search(segment) or extract_flow_id(segment):
        return "", [segment]
    parts = re.split(r"(?=\n##\s*🔎)", segment, maxsplit=1)
    if len(parts) == 2:
        preamble, flow_part = parts[0].strip(), parts[1].strip()
        if preamble and flow_part:
            return preamble, [flow_part]
    return segment, []


def split_report_chunks(report_text: str) -> Tuple[str, List[str]]:
    text = (report_text or "").strip()
    if not text:
        return "", []
    parts = re.split(r"\n---\n", text)
    first = parts[0].strip()
    rest = [part.strip() for part in parts[1:] if part.strip()]
    preamble, extra_body = _preamble_and_body_from_first_segment(first)
    return preamble, extra_body + rest


def classify_chunks(chunks: List[str]) -> Tuple[Dict[str, List[str]], Dict[str, str], Dict[str, str]]:
    flow_chunks: Dict[str, List[str]] = {}
    type_headers: Dict[str, str] = {}
    type_skipped: Dict[str, str] = {}
    current_type: Optional[str] = None

    for chunk in chunks:
        header_match = _TYPE_HEADER_RE.search(chunk)
        if header_match:
            current_type = header_match.group(1).lower()
            type_headers[current_type] = chunk
            continue
        if _SKIPPED_HEADER in chunk and current_type:
            type_skipped[current_type] = chunk
            continue
        flow_id = extract_flow_id(chunk)
        if flow_id:
            flow_chunks.setdefault(flow_id, []).append(chunk)
    return flow_chunks, type_headers, type_skipped
