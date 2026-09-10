"""
flow_merge.py — 同文件同符号（函数/方法）级 flow 合并与缓存键。

两层缓存语义：
  - sink_key（原 _flow_verdict_key）：单 sink 行级，用于 guard_edge 剪枝
  - merge_key：同 vuln_type + 文件 + 符号，避免重复 Joern 扩展与 LLM 主分析/反证
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

_C_KEYWORDS = frozenset(
    {
        "if", "for", "while", "return", "sizeof", "static", "const",
        "unsigned", "signed", "void", "int", "char", "len", "memcpy",
        "sprintf", "snprintf", "malloc", "free",
    }
)


def parse_sink_location(sink_label: str) -> Dict[str, str]:
    """从 sink_label 解析 file、line、code 片段。"""
    text = (sink_label or "").strip()
    match = re.match(r"^([^:]+):(\d+)\s*(.*)$", text)
    if not match:
        return {"file": "", "line": "", "code": text[:120]}
    return {
        "file": match.group(1).replace("\\", "/"),
        "line": match.group(2),
        "code": (match.group(3) or "").strip(),
    }


def extract_symbol_id(sink_label: str, flow_text: str = "") -> str:
    """
    提取用于合并的符号 ID（函数/方法名）。
    优先从 flow 文本中的函数定义提取，再回退到 sink 行。
    """
    body = flow_text or ""
    patterns = [
        r"\b(?:static\s+)?(?:inline\s+)?(?:void|int|char|size_t|unsigned|long|short|bool|auto)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*\{",
        r"\b(?:public|private|protected)\s+(?:static\s+)?[\w<>\[\]]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
    ]
    for pattern in patterns:
        match = re.search(pattern, body)
        if match:
            name = match.group(1)
            if name.lower() not in _C_KEYWORDS:
                return name

    loc = parse_sink_location(sink_label)
    code = loc.get("code", "")
    for candidate in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", code):
        if candidate.lower() not in _C_KEYWORDS and not candidate.isupper():
            return candidate

    file_base = loc.get("file", "").rsplit("/", 1)[-1]
    if file_base.endswith((".c", ".cpp", ".cc")):
        return PathStem(file_base)
    return ""


def PathStem(name: str) -> str:
    for ext in (".c", ".cpp", ".cc", ".cxx", ".java", ".py", ".go", ".rs"):
        if name.endswith(ext):
            return name[: -len(ext)]
    return name


def build_sink_verdict_key(vuln_type: str, sink_label: str) -> str:
    loc = parse_sink_location(sink_label)
    if loc.get("file") and loc.get("line"):
        code_word = ""
        code_match = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", loc.get("code", ""))
        if code_match:
            code_word = code_match.group(1)
        return f"{vuln_type}|{loc['file'].lower()}:{loc['line']}|{code_word}"
    return f"{vuln_type}|{(sink_label or '')[:120].strip()}"


def build_flow_merge_key(
    vuln_type: str,
    sink_label: str,
    flow_text: str = "",
) -> Optional[str]:
    loc = parse_sink_location(sink_label)
    if not loc.get("file"):
        return None
    symbol = extract_symbol_id(sink_label, flow_text)
    if not symbol:
        return None
    norm_file = loc["file"].lower()
    return f"{vuln_type}|{norm_file}|{symbol.lower()}"


def merge_refutation_verdict(verdicts: List[str]) -> str:
    """多 sink 合并时取最保守反证结论。"""
    order = {
        "likely_false_positive": 0,
        "inconclusive": 1,
        "needs_dynamic_test": 2,
        "confirmed": 3,
    }
    best = "inconclusive"
    best_rank = -1
    for v in verdicts:
        key = (v or "").lower().strip()
        rank = order.get(key, 1)
        if rank > best_rank:
            best_rank = rank
            best = key
    if "likely_false_positive" in [x.lower() for x in verdicts if x]:
        if any(x.lower() == "confirmed" for x in verdicts if x):
            return "inconclusive"
        return "likely_false_positive"
    return best


def build_merged_flow_header(
    vuln_type: str,
    flow_id: str,
    sink_label: str,
    canonical_flow_id: str,
    extra_sinks: Optional[List[str]] = None,
) -> str:
    lines = [
        f"## 🔎 {vuln_type.upper()} — `{flow_id}`",
        f"> **Sink 线索**: {sink_label or '未知'}",
        f"> **合并分析**: 与 `{canonical_flow_id}` 同文件同符号，复用 Joern/LLM 结论（避免重复查询）。",
    ]
    if extra_sinks:
        for s in extra_sinks[:5]:
            lines.append(f"> - 额外 sink: {s}")
    return "\n".join(lines) + "\n\n"


def should_skip_whole_file_read(
    *,
    kind: str,
    total_lines: Optional[int],
    threshold: int,
) -> bool:
    """源码类 L2 禁止自动扩为整文件。"""
    if kind in ("source", "unknown") and isinstance(total_lines, int):
        return total_lines > threshold
    return False
