"""
l2_reads.py — L2 静态补证路径工具（已接入主流程，非可选脚本）

================================================================================
这个文件干什么？
================================================================================

在 GuardFox-Agent 的三层证据模型里（见 evidence_levels.py）：

    L1 = Joern 污点流 / 硬回溯 / 扩展查询（代码流）
    L2 = FileTool 读到的配置、头文件、构建脚本等（静态补证）
    L3 = 动态/业务验证（默认未做）

Scanner 对每条污点 flow 会跑「反证 LLM」，反证 JSON 里有一项：

    missing_L2_reads: ["include/mbedtls/config.h", "**/ssl_tls.c", ...]

这是 **建议** 路径，不是自动真理——反证模型可能写错路径。
本模块的职责是：把这些原始建议 **清洗、去重、按优先级排序**，
变成 Planner 能执行的 ``pending_l2_reads`` 必读清单。

================================================================================
在项目里谁用？数据怎么流？
================================================================================

    joern_vuln_scanner.py
        每条 flow 反证结束 → _record_flow_scan_artifacts()
            把 missing_L2_reads 追加到 scanner._pending_l2_raw
        run_full_scan / iterative_analyze 结束
            → scan_result["pending_l2_reads_raw"]

    planner.py
        run_source_scan 完成后 → _sync_pending_l2_reads()
            调用 aggregate_pending_l2_reads() 写入 state.metadata["pending_l2_reads"]
        _build_state_snapshot()
            → state_snapshot.pending_l2_reads（最多 12 条，给 Planner prompt）
        _build_planner_json_fallback()
            Planner JSON 解析失败时，优先 glob/read pending_l2_reads 未读项
        run() 开头 → extract_paths_from_user_request() / sanitize_joern_project_path()
            从用户自然语言预填 project_path / local_source_path

    prompts.py
        规则 14/20：Planner 被明确要求 **优先** 执行 pending_l2_reads，再按 vuln_type Playbook

    tests/test_l2_reads.py
        单元测试（路径清洗、C 项目过滤 pom.xml、聚合去重）

================================================================================
「建议清单」做到了什么、没做到什么？
================================================================================

【已做】
  - 从反证 JSON 收集 missing_L2_reads，跨 flow 聚合
  - 去掉 Joern 容器前缀（/app/vuln_app/...）→ 相对 local_source_path 的路径
  - C/C++ 项目过滤 pom.xml 等 Java 专用路径
  - 与 file_evidence_reads 去重，避免 Planner 重复读
  - 按 L2=absent、refutation=inconclusive、具体文件优先 打分排序
  - 注入 Planner state_snapshot + JSON fallback 自动 FileTool

【未做 / 需知局限】
  - 不验证文件在磁盘上是否真实存在（FileTool 读失败再由 observation 反馈）
  - 不保证反证 LLM 给的路径正确——只作「下一步该试什么」的排序列表
  - 读完后由 flow_reconcile.reconcile_ambiguous_flows() 尝试收口 ambiguous_flows
  - 第 2 次 scan 前 Planner 通过 build_planner_l2_context_bundle() 注入 Scanner 反证 prompt

================================================================================
主要导出函数速查
================================================================================

    aggregate_pending_l2_reads   ← 核心：原始列表 → Planner 必读清单
    sanitize_l2_read_path        ← 单条路径规范化
    is_l2_path_applicable        ← 按语言过滤不适用项
    extract_paths_from_user_request  ← 从用户任务文本抽 Joern/本地路径
    sanitize_joern_project_path  ← 修正 /app/vuln_app- 等误解析
    normalize_scan_language      ← c/c++ → cpp，与 queries.py 一致
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

L2_CONFIG_READ_MAX_LINES = int(os.environ.get("L2_CONFIG_READ_MAX_LINES", "600"))

from flow_merge import parse_sink_location
from language_profiles import (
    get_language_profile,
    get_l2_config_globs,
    normalize_profile_language,
)

# 向后兼容：C/C++ 扫描时反证 LLM 常幻觉出的 Java/构建路径
_CPP_L2_DENY = frozenset(
    {"pom.xml", "build.gradle", "application.yml", "application.properties"}
)

# Joern 容器内常见路径前缀；sanitize_l2_read_path 会剥掉以便 FileTool 在 local_source_path 下解析
_JOERN_CONTAINER_PREFIXES = (
    "app/vuln_app/",
    "app/vuln_app-/",
    "app/workspace/VulnerableApp/",
    "mbedtls/",
)


def normalize_scan_language(language: str) -> str:
    """
    统一扫描语言标识，与 queries.get_queries() 行为一致。

    Planner 常写 language=c，底层查询集按 cpp 合并包加载，故 c/c++ 归一为 cpp。
    """
    lang = (language or "cpp").lower().strip()
    if lang in ("c", "c++"):
        return "cpp"
    return lang or "cpp"


def sanitize_joern_project_path(path: str) -> str:
    """
    修正 Joern 工程路径中的常见误解析。

    典型场景：用户写「映射的路径：/app/vuln_app-我本地...」无换行，
    Planner 把尾部 ``-`` 吃进 project_path。set_context / ensure_cpg 前调用。
    """
    text = (path or "").strip().strip('"').strip("'")
    if not text:
        return text
    text = text.rstrip("/\\")
    while text.endswith("-") and len(text) > 1:
        text = text[:-1]
    return text


def extract_paths_from_user_request(text: str) -> Dict[str, Optional[str]]:
    """
    从用户自然语言任务中预提取路径（planner.run 开头 _seed_context_from_user_request 使用）。

    避免 run_started 时 local_source_path 仍是 cwd（如 E:\\model-similarity），
    直到 step 1 set_context 才改正。

    Returns:
        {"project_path": Joern 容器路径或 None,
         "local_source_path": Windows 本地源码根或 None,
         "language": 扫描语言或 None}
    """
    result: Dict[str, Optional[str]] = {
        "project_path": None,
        "local_source_path": None,
        "language": None,
    }
    if not text:
        return result

    joern_patterns = [
        r"映射的路径[：:]\s*(/app/[A-Za-z0-9_./-]+)",
        r"(/app/vuln_app[A-Za-z0-9_./-]*)",
        r"joern[^\\n]{0,40}路径[：:]\s*(/[^\s\"'，。；;\\]+)",
    ]
    for pattern in joern_patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            candidate = sanitize_joern_project_path(match.group(1))
            if candidate.startswith("/app/"):
                result["project_path"] = candidate
                break

    local_patterns = [
        r"本地[^\n]{0,20}位置[：:]\s*([A-Za-z]:\\[^\s\"'，。；;]+)",
        r"([A-Za-z]:\\[^\s\"'，。；;]*mbedtls[^\s\"'，。；;]*)",
        r"([A-Za-z]:\\[^\s\"'，。；;]*vuln_agent[^\s\"'，。；;]*)",
    ]
    for pattern in local_patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            candidate = match.group(1).strip().rstrip("。")
            if os.path.isdir(candidate) or "\\" in candidate:
                result["local_source_path"] = candidate
                break

    lang_match = re.search(
        r"language\s*[=:]\s*([a-zA-Z+#]+)",
        text or "",
        flags=re.IGNORECASE,
    )
    if lang_match:
        result["language"] = normalize_scan_language(lang_match.group(1))

    return result


def _basename_key(path: str) -> str:
    """取路径 basename 小写，用于按文件名过滤（如 pom.xml）。"""
    cleaned = path.strip().lstrip("*").lstrip("/\\")
    return Path(cleaned.replace("\\", "/")).name.lower()


def is_l2_path_applicable(raw_path: str, language: str) -> bool:
    """
    判断反证建议的路径是否适用于当前语言/项目类型。
    """
    if not raw_path or not str(raw_path).strip():
        return False
    profile = get_language_profile(language)
    name = _basename_key(str(raw_path))
    if name in profile.l2_deny_basenames:
        return False
    lang = normalize_profile_language(language)
    if lang == "java" and name.endswith((".c", ".h")) and "native" not in raw_path.lower():
        return False
    return True


def sanitize_l2_read_path(
    raw_path: str,
    local_source_path: Optional[str] = None,
) -> Optional[str]:
    """
    将反证 LLM 的一条 missing_L2_reads 规范为 FileTool 可用的路径。

    处理规则：
      1. 去掉 markdown 反引号、首尾空白
      2. 去掉 glob 前缀 ``**/``（保留路径中间的 * 供 glob_files 使用）
      3. 剥掉 Joern 容器前缀 → 相对 local_source_path 的路径
      4. 若规范化后仍是绝对路径且配置了 local_source_path → 丢弃（避免越权读容器路径）
      5. 过长或 . / .. → 丢弃

    示例：
      "/app/vuln_app/include/mbedtls/config.h" → "include/mbedtls/config.h"
      "**/library/ssl_tls.c" → "library/ssl_tls.c"（is_glob 由 aggregate 判定）

    Args:
        raw_path: 反证 JSON 中的原始字符串
        local_source_path: 本地源码根，用于拒绝无法映射的绝对路径

    Returns:
        规范化路径；无法安全使用时返回 None
    """
    if not raw_path:
        return None
    text = str(raw_path).strip().strip("`").strip()
    text = re.sub(r"^\*+/", "", text)
    text = text.lstrip("/\\")
    lowered = text.replace("\\", "/").lower()
    for prefix in _JOERN_CONTAINER_PREFIXES:
        if lowered.startswith(prefix):
            text = text[len(prefix) :]
            break
    # 处理 Windows / 跨平台绝对路径：若路径位于 local_source_path 之下，
    # 剥掉前缀转为相对路径（兼容 Windows 盘符路径如 E:\... 和 Unix /... ）
    if local_source_path:
        try:
            p = Path(text)
            base = Path(local_source_path)
            if p.is_absolute():
                rel = p.relative_to(base)
                text = str(rel)
        except (ValueError, OSError):
            return None  # 绝对路径不在 local_source_path 下，拒绝
    if local_source_path and text.startswith(("/", "\\")):
        return None
    if not text or text in (".", ".."):
        return None
    if len(text) > 260:
        return None
    return text


def normalize_l2_read_entry(item: Dict[str, Any]) -> Dict[str, Any]:
    """统一 pending_l2_reads 条目结构（兼容旧版纯 path 字符串来源）。"""
    raw_path = item.get("path") or item.get("suggestion") or ""
    entry = {
        "path": str(raw_path).strip(),
        "flow_id": item.get("flow_id"),
        "vuln_type": item.get("vuln_type"),
        "refutation_verdict": item.get("refutation_verdict"),
        "l2_status": item.get("l2_status"),
        "start_line": item.get("start_line"),
        "end_line": item.get("end_line"),
        "symbol": item.get("symbol"),
        "kind": item.get("kind") or "unknown",
        "source": item.get("source") or "refutation",
    }
    return entry


def score_l2_suggestion(entry: Dict[str, Any], *, language: str = "cpp") -> int:
    """
    为一条 L2 建议计算优先级分数（越高越应先读）。
    """
    score = 0
    l2 = str(entry.get("l2_status", "")).lower()
    if l2 == "absent":
        score += 40
    elif l2 == "partial":
        score += 25
    refutation = str(entry.get("refutation_verdict", "")).lower()
    if refutation == "inconclusive":
        score += 30
    elif refutation == "needs_dynamic_test":
        score += 18
    elif refutation == "likely_false_positive":
        score += 5
    path = str(entry.get("path", ""))
    if path and "*" not in path and "?" not in path:
        score += 15
    if entry.get("flow_id"):
        score += 5
    if entry.get("start_line") and entry.get("end_line"):
        score += 12
    kind = str(entry.get("kind", "")).lower()
    if kind in ("config", "header", "build"):
        score += 10
    profile = get_language_profile(language)
    for keyword in profile.config_keywords:
        if keyword in path.lower():
            score += 8
    return score


_REFUTATION_PATH_TOKEN_RE = re.compile(
    r"`([^`]{3,240})`"
    r"|(?:^|[\s（(「「【\[])"
    r"([\w][\w./\\-]*\.(?:c|h|cpp|hpp|cc|hh|java|py|xml|yml|yaml|properties|gradle))"
    r"|(?:^|[\s（(「「【\[])"
    r"(CMakeLists\.txt|Makefile|pom\.xml|build\.gradle)",
    re.IGNORECASE | re.MULTILINE,
)

_SYMBOL_IN_PROSE_RE = re.compile(
    r"(?:函数|方法|实现|宏|macro|function|method)\s*[`'\"]?([a-zA-Z_]\w{3,})"
    r"|`([a-zA-Z_]\w{3,})`\s*\("
    r"|\b([a-zA-Z_]\w{4,})\s*\(",
    re.IGNORECASE,
)

_SNAKE_CASE_IDENT_RE = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]{5,})\b")

_SYMBOL_STOPWORDS = frozenset(
    {
        "return",
        "sizeof",
        "static",
        "const",
        "unsigned",
        "signed",
        "struct",
        "typedef",
        "inline",
        "extern",
        "volatile",
        "register",
        "continue",
        "break",
        "default",
        "switch",
        "while",
        "false",
        "true",
        "null",
        "memory",
        "buffer",
        "length",
        "size_t",
        "int32_t",
        "uint8_t",
    }
)

_CONFIG_PATH_MARKERS = (
    "cmakelists.txt",
    "makefile",
    "pom.xml",
    "build.gradle",
    "meson.build",
    ".cmake",
    ".toml",
    ".yaml",
    ".yml",
    ".properties",
    ".gradle",
)


def _norm_path_key(path: str) -> str:
    return str(path or "").replace("\\", "/").strip().lower().lstrip("./")


def _paths_match(a: str, b: str) -> bool:
    na, nb = _norm_path_key(a), _norm_path_key(b)
    if not na or not nb:
        return False
    if na == nb:
        return True
    if na.endswith("/" + nb) or nb.endswith("/" + na):
        return True
    return Path(na).name == Path(nb).name and Path(na).name != ""


def _is_config_like_path(path: str, kind: Optional[str] = None) -> bool:
    k = str(kind or "").lower()
    if k in ("config", "build", "header", "meta"):
        return True
    lowered = _norm_path_key(path)
    if any(marker in lowered for marker in _CONFIG_PATH_MARKERS):
        return True
    name = Path(lowered).name
    if "config" in name and name.endswith((".h", ".hpp", ".yaml", ".yml", ".json")):
        return True
    return False


def resolve_l2_pending_line_range(
    *,
    kind: str,
    path: str,
    start_line: Optional[int] = None,
    end_line: Optional[int] = None,
) -> Tuple[Optional[int], Optional[int]]:
    """
    为 pending_l2_reads 解析 FileTool 行段。

    构建/配置/头文件类路径不使用 sink 行号（避免 CMakeLists 仅几十行却请求 L634+）。
    源文件保留 sink±30 或调用方传入的范围。
    """
    if _is_config_like_path(path, kind):
        return 1, L2_CONFIG_READ_MAX_LINES
    return start_line, end_line


def sink_line_window(sink_line: Optional[int], *, padding: int = 30) -> Tuple[Optional[int], Optional[int]]:
    if sink_line is None:
        return None, None
    try:
        line = int(sink_line)
    except (TypeError, ValueError):
        return None, None
    return max(1, line - padding), line + padding


def infer_l2_kind(path: str) -> str:
    path_lower = _norm_path_key(path)
    if any(name in path_lower for name in ("cmakelists.txt", "makefile", "pom.xml", "build.gradle")):
        return "config"
    if path_lower.endswith((".h", ".hpp", ".hh")):
        return "header"
    if "config" in path_lower:
        return "config"
    if path_lower.endswith((".c", ".cpp", ".cc", ".java", ".py", ".go", ".rs")):
        return "source"
    return "unknown"


def build_pending_l2_entry(
    *,
    path: str,
    flow_id: str,
    vuln_type: str,
    refutation_verdict: str,
    l2_status: str,
    sink_line: Optional[int] = None,
    symbol: Optional[str] = None,
    kind: Optional[str] = None,
    source: str = "refutation",
) -> Dict[str, Any]:
    """构造单条 pending_l2_raw 条目（Scanner / Planner 共用）。"""
    resolved_kind = kind or infer_l2_kind(path)
    start_line, end_line = sink_line_window(sink_line)
    start_line, end_line = resolve_l2_pending_line_range(
        kind=resolved_kind,
        path=path,
        start_line=start_line,
        end_line=end_line,
    )
    return {
        "path": path,
        "flow_id": flow_id,
        "vuln_type": vuln_type,
        "refutation_verdict": refutation_verdict,
        "l2_status": l2_status,
        "symbol": symbol or None,
        "start_line": start_line,
        "end_line": end_line,
        "kind": resolved_kind,
        "source": source,
    }


def _symbol_to_path_candidates(symbol: str, file_index: Any) -> List[str]:
    """从反证 prose 中的函数/符号名推断可能定义文件（通用 stem 匹配，非项目硬编码）。"""
    if not file_index or not symbol:
        return []
    sym = str(symbol).strip()
    if not sym or sym.startswith(("MBEDTLS_", "CONFIG_", "NULL", "TRUE", "FALSE")):
        return []
    parts = sym.lower().split("_")
    stems: List[str] = []
    if len(parts) >= 2:
        stems.append(parts[1])
        if len(parts) >= 3:
            stems.append("_".join(parts[1:3]))
        stems.append(parts[-1])
    seen: Set[str] = set()
    hits: List[str] = []
    for stem in stems:
        if len(stem) < 3:
            continue
        for pattern in (f"**/*{stem}*.c", f"**/*{stem}*.cpp", f"**/*{stem}*.java"):
            for match in file_index.find_glob(pattern)[:2]:
                key = _norm_path_key(match)
                if key not in seen:
                    seen.add(key)
                    hits.append(match)
    return hits[:4]


def flow_has_new_l2_evidence(
    metadata: Dict[str, Any],
    flow_id: str,
    *,
    baseline_paths: Optional[Set[str]] = None,
) -> bool:
    """
    判断某 flow 在上一轮 inconclusive 反证之后是否新增了 L2 读取。

    用于增量复核时避免 cached_inconclusive 误跳过真实重反证。
    """
    if not flow_id:
        return False
    reads = list(metadata.get("file_evidence_reads") or [])
    if any(str(entry.get("flow_id") or "") == flow_id for entry in reads):
        return True

    tracked = {
        _norm_path_key(p)
        for p in (metadata.get("flow_l2_read_paths") or {}).get(flow_id) or []
    }
    if tracked and (baseline_paths is None or tracked - baseline_paths):
        return True

    read_paths = {_norm_path_key(entry.get("path", "")) for entry in reads if entry.get("path")}
    pending = [
        item
        for item in (metadata.get("pending_l2_reads") or [])
        if str(item.get("flow_id") or "") == flow_id
    ]
    for item in pending:
        p = _norm_path_key(item.get("path", ""))
        if p and any(_paths_match(p, rp) for rp in read_paths):
            if baseline_paths is None or p not in baseline_paths:
                return True

    catalog = (metadata.get("flow_catalog") or {}).get(flow_id) or {}
    try:
        from flow_merge import parse_sink_location

        sink_file = parse_sink_location(catalog.get("sink_label", "")).get("file", "")
    except Exception:
        sink_file = ""
    if sink_file:
        sink_dir = str(Path(_norm_path_key(sink_file)).parent).lower()
        if sink_dir and sink_dir not in (".", ""):
            for rp in read_paths:
                if sink_dir in rp and (baseline_paths is None or rp not in baseline_paths):
                    return True
    return False


def enrich_refutation_missing_l2(
    refutation_result: Dict[str, Any],
    *,
    flow_id: str,
    vuln_type: str,
    sink_label: str,
    language: str,
    local_source_path: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    max_paths: int = 12,
) -> Dict[str, Any]:
    """合并显式 missing_L2_reads 与文本/索引抽取结果，供报告与 pending 队列使用。"""
    merged: List[str] = []
    seen: Set[str] = set()

    def push(raw: str) -> None:
        cleaned = sanitize_l2_read_path(str(raw or ""), local_source_path)
        if not cleaned or not is_l2_path_applicable(cleaned, language):
            return
        key = _norm_path_key(cleaned)
        if key in seen:
            return
        seen.add(key)
        merged.append(cleaned)

    for raw in refutation_result.get("missing_L2_reads") or []:
        push(str(raw))

    for raw in collect_refutation_l2_read_suggestions(
        flow_id=flow_id,
        vuln_type=vuln_type,
        refutation_result=refutation_result,
        sink_label=sink_label,
        language=language,
        local_source_path=local_source_path,
        metadata=metadata,
        max_suggestions=max_paths,
    ):
        push(raw)

    refutation_result["missing_L2_reads"] = merged[:max_paths]
    return refutation_result


def _refutation_text_blob(refutation_result: Dict[str, Any]) -> str:
    parts = [
        str(refutation_result.get("refutation_summary") or ""),
        str(refutation_result.get("residual_risk") or ""),
    ]
    for item in refutation_result.get("blocking_factors") or []:
        parts.append(str(item))
    return "\n".join(parts)


def extract_paths_from_refutation_text(
    text: str,
    *,
    language: str,
    local_source_path: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    max_paths: int = 12,
) -> List[str]:
    """从反证摘要/阻断因素中抽取可解析的源码或配置路径（通用，不写死项目）。"""
    blob = (text or "").strip()
    if not blob:
        return []

    file_index = None
    try:
        from project_file_index import build_project_file_index, index_from_metadata

        file_index = index_from_metadata(metadata or {}) if metadata else None
        if file_index is None and local_source_path:
            file_index = build_project_file_index(local_source_path, language)
    except Exception:
        file_index = None

    suggestions: List[str] = []
    seen: Set[str] = set()

    def push(path: str) -> None:
        raw = str(path or "").strip().strip("`").strip()
        if not raw or not is_l2_path_applicable(raw, language):
            return
        key = raw.replace("\\", "/").lower()
        if key in seen:
            return
        seen.add(key)
        suggestions.append(raw)

    for match in _REFUTATION_PATH_TOKEN_RE.finditer(blob):
        token = next((g for g in match.groups() if g), "")
        if not token:
            continue
        token = token.strip().strip("`")
        if file_index is not None:
            norm = token.replace("\\", "/").lstrip("./")
            if file_index.contains(norm):
                push(norm)
                continue
            for hit in file_index.find_by_basename(Path(norm).name):
                push(hit)
                break
            else:
                for hit in file_index.find_glob(f"**/{Path(norm).name}")[:2]:
                    push(hit)
        else:
            push(token)

    if file_index is not None and len(suggestions) < max_paths:
        for match in _SYMBOL_IN_PROSE_RE.finditer(blob):
            symbol = next((g for g in match.groups() if g), "")
            if not symbol:
                continue
            for hit in _symbol_to_path_candidates(symbol, file_index):
                push(hit)
                if len(suggestions) >= max_paths:
                    break

    if file_index is not None and len(suggestions) < max_paths:
        for match in _SNAKE_CASE_IDENT_RE.finditer(blob):
            symbol = match.group(1)
            if symbol.lower() in _SYMBOL_STOPWORDS:
                continue
            if symbol.isupper() and "_" in symbol:
                continue
            for hit in _symbol_to_path_candidates(symbol, file_index):
                push(hit)
                if len(suggestions) >= max_paths:
                    break

    return suggestions[:max_paths]


def collect_refutation_l2_read_suggestions(
    *,
    flow_id: str,
    vuln_type: str,
    refutation_result: Dict[str, Any],
    sink_label: str,
    language: str,
    local_source_path: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    max_suggestions: int = 8,
) -> List[str]:
    """
    统一收集一条 flow 的 L2 必读路径：显式 missing + 文本抽取 + sink + 索引回退。
    inconclusive / needs_dynamic_test 时即使 L2=present 也会继续补队列。
    """
    evidence = refutation_result.get("evidence_levels") or {}
    l2 = str(evidence.get("L2_static_files", "partial")).lower()
    verdict = str(refutation_result.get("verdict") or "").lower()
    needs_more = verdict in ("inconclusive", "needs_dynamic_test") or l2 in (
        "absent",
        "partial",
    )
    if not needs_more:
        return []

    suggestions: List[str] = []
    seen: Set[str] = set()

    def push(path: str) -> None:
        raw = str(path or "").strip()
        if not raw:
            return
        key = raw.replace("\\", "/").lower()
        if key in seen:
            return
        seen.add(key)
        suggestions.append(raw)

    for raw in refutation_result.get("missing_L2_reads") or []:
        push(str(raw))

    text_blob = _refutation_text_blob(refutation_result)
    for raw in extract_paths_from_refutation_text(
        text_blob,
        language=language,
        local_source_path=local_source_path,
        metadata=metadata,
    ):
        push(raw)

    loc = parse_sink_location(sink_label)
    if loc.get("file"):
        push(str(loc["file"]))

    if len(suggestions) < max_suggestions:
        for raw in infer_fallback_l2_reads(
            flow_id=flow_id,
            vuln_type=vuln_type,
            refutation_result=refutation_result,
            sink_label=sink_label,
            language=language,
            local_source_path=local_source_path,
            metadata=metadata,
            max_suggestions=max(1, max_suggestions - len(suggestions)),
        ):
            push(raw)

    return suggestions[:max_suggestions]


def infer_fallback_l2_reads(
    *,
    flow_id: str,
    vuln_type: str,
    refutation_result: Dict[str, Any],
    sink_label: str,
    language: str,
    local_source_path: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    max_suggestions: int = 6,
) -> List[str]:
    """
    反证 LLM 未写出 missing_L2_reads 时，从索引与 sink 推断必读 L2 路径。

    L2 为 absent/partial，或反证终态为 inconclusive/needs_dynamic_test 时生效。
    """
    evidence = refutation_result.get("evidence_levels") or {}
    l2 = str(evidence.get("L2_static_files", "partial")).lower()
    verdict = str(refutation_result.get("verdict") or "").lower()
    if l2 not in ("absent", "partial") and verdict not in (
        "inconclusive",
        "needs_dynamic_test",
    ):
        return []
    if refutation_result.get("missing_L2_reads") and l2 in ("absent", "partial"):
        return []

    suggestions: List[str] = []
    seen: Set[str] = set()

    def push(path: str) -> None:
        raw = str(path or "").strip()
        if not raw or not is_l2_path_applicable(raw, language):
            return
        key = raw.lower()
        if key in seen:
            return
        seen.add(key)
        suggestions.append(raw)

    loc = parse_sink_location(sink_label)
    if loc.get("file"):
        push(loc["file"])

    file_index = None
    try:
        from project_file_index import build_project_file_index, index_from_metadata

        file_index = index_from_metadata(metadata or {}) if metadata else None
        if file_index is None and local_source_path:
            file_index = build_project_file_index(local_source_path, language)
    except Exception:
        file_index = None

    if file_index is not None:
        profile = get_language_profile(language)
        for basename in ("config.h", "CMakeLists.txt"):
            for match in file_index.find_by_basename(basename):
                push(match)
        for item in file_index.configs[:8]:
            push(item)
        for item in file_index.build_files[:4]:
            push(item)
        for item in file_index.configs[:6]:
            push(item)
        for item in file_index.headers:
            name = Path(item).name.lower()
            if "config" in name or any(kw in item.lower() for kw in profile.config_keywords):
                push(item)
        for pattern in get_l2_config_globs(language):
            if "*" not in pattern and "?" not in pattern:
                if file_index.contains(pattern):
                    push(pattern)
                continue
            for match in file_index.find_glob(pattern)[:2]:
                push(match)

    return suggestions[:max_suggestions]


def aggregate_pending_l2_reads(
    raw_entries: List[Dict[str, Any]],
    *,
    language: str,
    local_source_path: Optional[str] = None,
    already_read_paths: Optional[Set[str]] = None,
    limit: int = 12,
) -> List[Dict[str, Any]]:
    """
    **核心入口**：把 Scanner 收集的原始 L2 建议变成 Planner 的 pending_l2_reads。

    调用方：planner.AgentPlannerExecutor._sync_pending_l2_reads()

    输入 raw_entries 每条通常含（由 joern_vuln_scanner._record_flow_scan_artifacts 写入）：
        path, flow_id, vuln_type, refutation_verdict, l2_status

    输出每条含：
        path          — 规范化后的相对路径或 glob 模式
        flow_id       — 来源 flow（Planner 可写在 plan_summary 里）
        vuln_type
        refutation_verdict, l2_status
        priority_score
        is_glob       — True 时 Planner 应 FileTool.glob_files，否则 read_file

    保证性质：
        - 同 path 去重（跨 flow 多条建议合并为一条）
        - 已在 file_evidence_reads 中的路径跳过
        - 按 priority_score 降序，最多 limit 条（默认 12，snapshot 再截断展示）

    不保证：
        - 路径在磁盘存在（由 FileTool 执行时验证）
        - 读完即收敛漏洞结论（需后续 scan 或人工）
    """
    seen: Set[str] = set()
    already = {p.lower() for p in (already_read_paths or set())}
    bucket: List[Dict[str, Any]] = []

    file_index = None
    try:
        from project_file_index import build_project_file_index, resolve_l2_path

        file_index = build_project_file_index(local_source_path, language)
    except Exception:
        file_index = None

    for item in raw_entries:
        norm_item = normalize_l2_read_entry(item)
        raw_path = norm_item.get("path") or ""
        if not is_l2_path_applicable(str(raw_path), language):
            continue
        resolved_path = raw_path
        resolved_kind = norm_item.get("kind") or "unknown"
        if file_index is not None:
            resolved = resolve_l2_path(
                raw_path,
                language=language,
                file_index=file_index,
                local_source_path=local_source_path,
            )
            if resolved:
                resolved_path = resolved.path
                resolved_kind = resolved.kind
            elif "*" not in raw_path and "?" not in raw_path:
                continue
        else:
            normalized = sanitize_l2_read_path(str(raw_path), local_source_path)
            if not normalized:
                continue
            resolved_path = normalized

        key = resolved_path.lower()
        if key in seen or key in already:
            continue
        seen.add(key)
        entry = {
            "path": resolved_path,
            "flow_id": norm_item.get("flow_id"),
            "vuln_type": norm_item.get("vuln_type"),
            "refutation_verdict": norm_item.get("refutation_verdict"),
            "l2_status": norm_item.get("l2_status"),
            "symbol": norm_item.get("symbol"),
            "kind": resolved_kind,
            "source": norm_item.get("source"),
            "priority_score": score_l2_suggestion(
                {**norm_item, "path": resolved_path, "kind": resolved_kind},
                language=language,
            ),
            "is_glob": "*" in resolved_path or "?" in resolved_path,
        }
        sl, el = resolve_l2_pending_line_range(
            kind=str(resolved_kind),
            path=resolved_path,
            start_line=norm_item.get("start_line"),
            end_line=norm_item.get("end_line"),
        )
        entry["start_line"] = sl
        entry["end_line"] = el
        bucket.append(entry)

    bucket.sort(key=lambda x: (-x["priority_score"], x["path"]))
    return bucket[: max(1, limit)]
