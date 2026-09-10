"""
组件版本识别：将 Ghidra 反编译 C 与多个候选官方源码版本比对，推断最接近的发布版本。

================================================================================
【相似度分析在哪个文件？】
================================================================================
本文件 `version_identification.py` 是**唯一实现**「反编译 C ↔ 官方源码 C」
相似度/指纹比对的模块。入口类 `VersionIdentifier.identify()`。

薄封装：`version_tool.py` 的 `VersionTool.identify_component()` 仅转调本模块，
不包含比对算法。单元测试：`tests/test_version_identification.py`。

================================================================================
【为什么不直接比全文？】
================================================================================
Ghidra 反编译与手写源码在变量名、类型名、格式、注释上差异极大；若用
`difflib.SequenceMatcher` 对整段函数体做文本相似度，各候选版本得分会几乎
相同（历史上曾出现三个版本均为 ~0.02 的情况），无法区分 2.14.x 与 2.16.0。

因此采用「控制流指纹」：只抽取与分支逻辑相关的稳定特征，再与官方源码的
同函数指纹做加权相似度（见 `fingerprint_similarity`）。

================================================================================
【整体流水线】
================================================================================
1. `parse_decompiled_functions` — 按 Ghidra 注释头切分反编译函数
2. `_files_differing_between_roots` — 找出候选版本之间内容不同的 .c 文件
3. `_extract_c_functions_from_file` — 从差异 .c 中解析函数体
4. `_candidate_fingerprints_differ` — 过滤：候选间控制流指纹必须不同
5. `fingerprint_similarity(dec.body, src.body)` — 逐函数、逐候选打分
6. 按 `discrimination_spread` 加权平均 → `aggregate_scores` → 判定 / tie-break

通用策略（不绑定 mbedtls 等特定组件）：
- 仅对「二进制可观察」且「候选间逻辑指纹不同」的函数参与打分
- 补丁级同分（如 2.14.0 vs 2.14.1）可用环境变量 tie-break，与指纹无关
"""

from __future__ import annotations

import difflib
import filecmp
import hashlib
import os
import re
import shutil
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

_DECOMPILED_FUNC_HEADER = re.compile(
    r"/\*\s*-+\s*Function\s+\d+:\s+(\w+)\s+@\s+[0-9a-fA-F]+\s*-+\s*\*/",
    re.MULTILINE,
)
_C_FUNC_DEF = re.compile(
    r"(?:^|\n)([a-zA-Z_][\w\s\*]*?)\b([a-zA-Z_]\w*)\s*\([^;]*?\)\s*\{",
    re.MULTILINE,
)
_VERSION_IN_NAME = re.compile(
    r"(?:^|[^\d])(\d+\.\d+(?:\.\d+)?)(?:[^\d]|$)",
)
_HEX_LITERAL = re.compile(r"0x[0-9a-fA-F]+")
_DECIMAL_LITERAL = re.compile(r"\b\d+\b")
_SOURCE_SUBDIRS = ("library", "src", "lib", "source")
_IF_COND_START = re.compile(r"\bif\s*\(", re.MULTILINE)
_LOGIC_OPS = re.compile(r"==|!=|<=|>=|&&|\|\||!")

# 仅用于「第一名并列」补丁 tie-break（2.14.0 vs 2.14.1），不得把低分版本包进来
_FIRST_PLACE_EPSILON = float(os.environ.get("AGENT_VERSION_FIRST_PLACE_EPSILON", "1e-5"))
_MIN_LOGIC_GAP = float(os.environ.get("AGENT_VERSION_MIN_LOGIC_GAP", "0.06"))
_TIE_BREAK_MODE = os.environ.get("AGENT_VERSION_TIE_BREAK", "highest_patch").strip().lower()


@dataclass(frozen=True)
class ControlFlowFingerprint:
    """
    单函数的控制流/常量「指纹」——反编译与源码各抽一份，再算相似度。

    设计原则：保留版本迭代时容易变的「分支结构」，弱化 Ghidra 命名噪声。

    字段含义：
    - if_shapes: 每个 if 条件归一化后的「形状串」序列（顺序敏感）
    - if_hex_literals: if 条件中出现的十六进制常量集合（如 0x100）
    - return_hex_literals: return 语句中的十六进制常量集合
    - logic_op_signature: 所有 if 条件里逻辑/比较运算符拼接（==, &&, ! 等）
    - if_count: if 个数（大版本重构时分支数可能变化）
    - leading_negations: 以 ! 开头的条件个数（如 2.16 在 ssl 里新增的否定判断）
    """

    if_shapes: Tuple[str, ...]
    if_hex_literals: frozenset
    return_hex_literals: frozenset
    logic_op_signature: str
    if_count: int
    leading_negations: int


@dataclass
class CandidateSource:
    label: str
    path: Path
    version_string: str
    source_root: Path
    version_meta: Dict[str, str] = field(default_factory=dict)
    _temp_dir: Optional[str] = None


@dataclass
class DecompiledFunction:
    name: str
    body: str
    is_plt_stub: bool
    is_observable: bool


@dataclass
class DiscriminatorFunction:
    name: str
    observable: bool
    is_logic_diff: bool
    reason: str
    per_candidate_similarity: Dict[str, float] = field(default_factory=dict)
    discrimination_spread: float = 0.0


def _strip_c_comments(code: str) -> str:
    """去掉块注释与行注释，避免注释里的 if/常量干扰指纹。"""
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)
    code = re.sub(r"//.*?$", "", code, flags=re.MULTILINE)
    return code


def _extract_balanced_parens(text: str, open_index: int) -> str:
    """从 open_index 处的 '(' 开始，匹配括号深度，返回括号内子串（不含外层括号）。"""
    depth = 0
    for index in range(open_index, len(text)):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[open_index + 1 : index]
    return ""


def _extract_if_conditions(body: str) -> List[str]:
    """
    提取函数体内所有 `if (...)` 的原始条件表达式（按源码出现顺序）。

    不处理 switch/for/while：版本差异案例（如 mbedtls ssl）主要集中在 if 链。
    """
    cleaned = _strip_c_comments(body)
    conditions: List[str] = []
    for match in _IF_COND_START.finditer(cleaned):
        cond = _extract_balanced_parens(cleaned, match.end() - 1)
        if cond:
            conditions.append(cond.strip())
    return conditions


def _normalize_condition_shape(condition: str) -> str:
    """
    将条件表达式归一化为「形状」，使反编译变量名与源码变量名可对齐。

    例：`param_1 == 0x100 && ssl->state == 3`
        → `V == H && V -> V == N`（十六进制→H，十进制→N，标识符→V）

    这样 Ghidra 的 param_1 与源码的 ssl 在形状层面等价，只比较逻辑骨架。
    """
    shape = re.sub(r"\s+", " ", condition.strip())
    shape = re.sub(r"\b0x[0-9a-fA-F]+\b", "H", shape)
    shape = re.sub(r"\b\d+\b", "N", shape)
    shape = re.sub(r"\b[a-zA-Z_]\w*\b", "V", shape)
    return shape


def _logic_op_signature(conditions: Sequence[str]) -> str:
    """把所有 if 条件中的 ==、!=、&&、||、! 按出现顺序拼成签名串。"""
    tokens: List[str] = []
    for cond in conditions:
        tokens.extend(_LOGIC_OPS.findall(cond))
    return "|".join(tokens)


def _leading_negation_count(conditions: Sequence[str]) -> int:
    count = 0
    for cond in conditions:
        stripped = cond.lstrip()
        if stripped.startswith("!"):
            count += 1
    return count


def _hex_in_conditions(conditions: Sequence[str]) -> Set[str]:
    result: Set[str] = set()
    for cond in conditions:
        result.update(_HEX_LITERAL.findall(cond))
    return result


def _hex_in_returns(body: str) -> Set[str]:
    cleaned = _strip_c_comments(body)
    literals: Set[str] = set()
    for line in cleaned.splitlines():
        stripped = line.strip()
        if stripped.startswith("return"):
            literals.update(_HEX_LITERAL.findall(stripped))
    return literals


def extract_control_flow_fingerprint(code: str) -> ControlFlowFingerprint:
    """
    从任意 C 函数体（反编译或官方源码）抽取控制流指纹。

    反编译与源码各调用一次，结果送入 `fingerprint_similarity` 比较。
    """
    conditions = _extract_if_conditions(code)
    if_shapes = tuple(_normalize_condition_shape(cond) for cond in conditions)
    return ControlFlowFingerprint(
        if_shapes=if_shapes,
        if_hex_literals=frozenset(_hex_in_conditions(conditions)),
        return_hex_literals=frozenset(_hex_in_returns(code)),
        logic_op_signature=_logic_op_signature(conditions),
        if_count=len(conditions),
        leading_negations=_leading_negation_count(conditions),
    )


def _fingerprint_tuple(fp: ControlFlowFingerprint) -> Tuple[Any, ...]:
    return (
        fp.if_shapes,
        fp.if_hex_literals,
        fp.return_hex_literals,
        fp.logic_op_signature,
        fp.if_count,
        fp.leading_negations,
    )


def _sequence_similarity(left: Sequence[str], right: Sequence[str]) -> float:
    """
    有序序列相似度：对 if_shapes 使用 difflib.SequenceMatcher.ratio()。

    取值 [0,1]：1 表示形状序列完全一致（含顺序），0 表示一方为空另一方非空。
    用于比较「第几个 if 长什么样」，对 2.14 vs 2.16 的 ssl 分支差异敏感。
    """
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    return difflib.SequenceMatcher(None, list(left), list(right)).ratio()


def _jaccard(left: Set[str], right: Set[str]) -> float:
    """
    集合 Jaccard 系数：|A∩B| / |A∪B|。

    用于十六进制常量集合：不关心常量出现在第几个 if，只关心「是否出现同一组魔数」。
    """
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


def fingerprint_similarity(
    decompiled_body: str,
    source_body: str,
) -> float:
    """
    【核心】单函数：反编译体 vs 某一候选版本源码体的相似度，返回 [0, 1]。

    原理：双方先各自 `extract_control_flow_fingerprint`，再对 6 个子特征算
    相似度并加权求和（不是对原始 C 文本做 diff）。

    子特征与默认权重（可通过改代码调整，当前无环境变量）：
    ┌─────────────────────┬────────┬──────────────────────────────────────┐
    │ 子特征              │ 权重   │ 计算方法                             │
    ├─────────────────────┼────────┼──────────────────────────────────────┤
    │ if 条件形状序列     │ 0.40   │ SequenceMatcher(if_shapes)           │
    │ if 内十六进制常量   │ 0.30   │ Jaccard(if_hex_literals)             │
    │ return 十六进制常量 │ 0.10   │ Jaccard(return_hex_literals)         │
    │ 逻辑运算符签名      │ 0.12   │ SequenceMatcher(logic_op_signature)  │
    │ if 个数             │ 0.05   │ 1 - |Δcount|/max(count)              │
    │ 前导 ! 条件个数     │ 0.03   │ 相等 1.0 否则 0.0                    │
    └─────────────────────┴────────┴──────────────────────────────────────┘

    直觉：二进制更接近哪个官方版本，哪个版本的「分支骨架+魔数」与反编译更一致，
    该候选在此函数上得分更高。多函数加权见 `_identify_core`。
    """
    dec_fp = extract_control_flow_fingerprint(decompiled_body)
    src_fp = extract_control_flow_fingerprint(source_body)

    # 分支结构主信号：if 顺序 + 每条条件的归一化形状
    if_shape_sim = _sequence_similarity(dec_fp.if_shapes, src_fp.if_shapes)
    # 条件里的魔数（错误码、掩码等）往往随大版本变化
    if_hex_sim = _jaccard(set(dec_fp.if_hex_literals), set(src_fp.if_hex_literals))
    return_hex_sim = _jaccard(set(dec_fp.return_hex_literals), set(src_fp.return_hex_literals))

    logic_sim = 1.0 if dec_fp.logic_op_signature == src_fp.logic_op_signature else 0.0
    if dec_fp.logic_op_signature and src_fp.logic_op_signature:
        logic_sim = difflib.SequenceMatcher(
            None, dec_fp.logic_op_signature, src_fp.logic_op_signature
        ).ratio()

    if_count_sim = 1.0 - min(1.0, abs(dec_fp.if_count - src_fp.if_count) / max(dec_fp.if_count, src_fp.if_count, 1))
    neg_sim = 1.0 if dec_fp.leading_negations == src_fp.leading_negations else 0.0

    return (
        0.40 * if_shape_sim
        + 0.30 * if_hex_sim
        + 0.10 * return_hex_sim
        + 0.12 * logic_sim
        + 0.05 * if_count_sim
        + 0.03 * neg_sim
    )


def _candidate_fingerprints_differ(bodies: Dict[str, str]) -> bool:
    """
    判断同一函数名在不同候选版本间的指纹是否不全相同。

    若各版本指纹一致（仅注释/格式/非逻辑 diff），则该函数不能用于区分版本，
    不会进入 `logic_observable` 打分列表。
    """
    fingerprints = [_fingerprint_tuple(extract_control_flow_fingerprint(body)) for body in bodies.values()]
    return len(set(fingerprints)) > 1


def _parse_version_tuple(label: str) -> Tuple[int, ...]:
    match = _VERSION_IN_NAME.search(label.replace("_", "."))
    if not match:
        return (0,)
    return tuple(int(part) for part in match.group(1).split("."))


def _normalize_version_label(path: Path) -> str:
    text = path.stem
    for part in reversed(path.parts):
        match = _VERSION_IN_NAME.search(part.replace("_", "."))
        if match:
            return match.group(1)
    match = _VERSION_IN_NAME.search(text.replace("_", "."))
    return match.group(1) if match else text


def _is_plt_stub(body: str) -> bool:
    stripped = body.strip()
    if "halt_baddata" in stripped or "Bad instruction" in stripped:
        return True
    if "PTR_" in stripped and "(*(code *)" in stripped and stripped.count("{") <= 2:
        return True
    return len(stripped) < 120 and "return" in stripped and "param_" not in stripped


def parse_decompiled_functions(content: str) -> Dict[str, DecompiledFunction]:
    """
    解析 Ghidra 导出的 *_decompiled.c。

    按注释头 `/* --- Function N: name @ addr --- */` 切分；过滤 PLT 桩与
    过短不可观察函数。相似度比对时使用 `DecompiledFunction.body`。
    """
    functions: Dict[str, DecompiledFunction] = {}
    headers = list(_DECOMPILED_FUNC_HEADER.finditer(content))
    for index, match in enumerate(headers):
        name = match.group(1)
        start = match.end()
        end = headers[index + 1].start() if index + 1 < len(headers) else len(content)
        body = content[start:end].strip()
        plt = _is_plt_stub(body)
        functions[name] = DecompiledFunction(
            name=name,
            body=body,
            is_plt_stub=plt,
            is_observable=not plt and len(body) > 80,
        )
    return functions


def _find_source_root(extracted: Path) -> Optional[Path]:
    for sub in _SOURCE_SUBDIRS:
        direct = extracted / sub
        if direct.is_dir() and any(direct.glob("*.c")):
            return direct
    for sub in _SOURCE_SUBDIRS:
        for hit in extracted.rglob(sub):
            if hit.is_dir() and any(hit.glob("*.c")):
                return hit
    c_files = list(extracted.rglob("*.c"))
    if c_files:
        return c_files[0].parent
    return None


def _read_version_meta(source_root: Path) -> Dict[str, str]:
    """读取常见 version 头中的版本宏（任意组件，不限于 mbedtls）。"""
    meta: Dict[str, str] = {}
    patterns = (
        r"#define\s+(\w*VERSION_MAJOR\w*)\s+\"?([^\"\n]+)\"?",
        r"#define\s+(\w*VERSION_MINOR\w*)\s+\"?([^\"\n]+)\"?",
        r"#define\s+(\w*VERSION_PATCH\w*)\s+\"?([^\"\n]+)\"?",
        r"#define\s+(\w*VERSION_STRING\w*)\s+\"([^\"\n]+)\"",
    )
    for header in source_root.parent.rglob("version.h"):
        try:
            text = header.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for pattern in patterns:
            for key, value in re.findall(pattern, text):
                meta[key] = value.strip()
        if meta:
            break
    return meta


def _prepare_candidate(raw_path: str, work_dir: Path) -> CandidateSource:
    path = Path(raw_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"候选路径不存在: {raw_path}")

    temp_dir: Optional[str] = None
    extracted = path
    if path.suffix.lower() == ".zip":
        temp_dir = tempfile.mkdtemp(prefix="agent_version_", dir=str(work_dir))
        with zipfile.ZipFile(path, "r") as zf:
            zf.extractall(temp_dir)
        extracted = Path(temp_dir)
        children = [p for p in extracted.iterdir() if p.is_dir()]
        if len(children) == 1:
            extracted = children[0]

    source_root = _find_source_root(extracted)
    if source_root is None:
        raise ValueError(f"无法在候选包中定位源码目录: {raw_path}")

    label = _normalize_version_label(path)
    version_meta = _read_version_meta(source_root)
    version_string = (
        version_meta.get("MBEDTLS_VERSION_STRING")
        or version_meta.get("VERSION_STRING")
        or label
    )

    return CandidateSource(
        label=label,
        path=path,
        version_string=version_string,
        source_root=source_root,
        version_meta=version_meta,
        _temp_dir=temp_dir,
    )


def _list_c_files(root: Path) -> Dict[str, Path]:
    files: Dict[str, Path] = {}
    for fp in root.rglob("*.c"):
        rel = fp.relative_to(root).as_posix()
        files[rel] = fp
    return files


def _files_differing_between_roots(root_a: Path, root_b: Path) -> List[str]:
    files_a = _list_c_files(root_a)
    files_b = _list_c_files(root_b)
    rel_paths = sorted(set(files_a) | set(files_b))
    differing: List[str] = []
    for rel in rel_paths:
        pa, pb = files_a.get(rel), files_b.get(rel)
        if pa is None or pb is None:
            differing.append(rel)
            continue
        if not filecmp.cmp(pa, pb, shallow=False):
            differing.append(rel)
    return differing


def _extract_c_functions_from_file(path: Path) -> Dict[str, str]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return {}
    return _extract_c_functions_from_text(text)


def _extract_c_functions_from_text(text: str) -> Dict[str, str]:
    functions: Dict[str, str] = {}
    for match in _C_FUNC_DEF.finditer(text):
        name = match.group(2)
        if name in ("if", "while", "for", "switch"):
            continue
        start = match.start()
        brace = text.find("{", match.end() - 1)
        if brace < 0:
            continue
        depth = 0
        end = brace
        for index in range(brace, len(text)):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    end = index + 1
                    break
        functions[name] = text[match.start() : end]
    return functions


def _top_tier_labels(aggregate_scores: Dict[str, float]) -> List[str]:
    """
    得分「第一名」的候选标签列表（允许 2.14.0 与 2.14.1 这种真并列）。

    得分明显更低的版本（如 2.16.0=0.1423 vs 2.14.x=0.1441）不得进入此集合。
    """
    if not aggregate_scores:
        return []
    top_score = max(aggregate_scores.values())
    return [
        label
        for label, score in aggregate_scores.items()
        if score >= top_score - _FIRST_PLACE_EPSILON
    ]


def _apply_tie_break(tied_labels: List[str]) -> Tuple[List[str], Optional[str]]:
    """
    仅在「第一名并列」的候选之间做补丁 tie-break（如 2.14.0 vs 2.14.1）。

    调用方必须只传入 _top_tier_labels() 的结果，且 len>1。
    """
    if _TIE_BREAK_MODE in ("", "none") or len(tied_labels) <= 1:
        return tied_labels, None

    if _TIE_BREAK_MODE == "highest_patch":
        winner = max(tied_labels, key=_parse_version_tuple)
        note = (
            f"第一名并列：{', '.join(tied_labels)} 指纹得分相同；"
            f"已按 AGENT_VERSION_TIE_BREAK=highest_patch 选取较高补丁号 {winner}。"
            "该步骤不来自反编译直接证据，仅用于同分补丁选择。"
        )
        return [winner], note

    if _TIE_BREAK_MODE == "lowest_patch":
        winner = min(tied_labels, key=_parse_version_tuple)
        note = (
            f"第一名并列：{', '.join(tied_labels)}；"
            f"已按 lowest_patch 选取 {winner}（非二进制直接证据）。"
        )
        return [winner], note

    return tied_labels, None


class VersionIdentifier:
    def __init__(self, work_dir: Optional[str] = None):
        self.work_dir = Path(work_dir or tempfile.gettempdir()) / "agent_version_id"
        self.work_dir.mkdir(parents=True, exist_ok=True)

    def identify(
        self,
        decompiled_path: str,
        candidate_paths: Sequence[str],
        component_name: Optional[str] = None,
        min_similarity_gap: Optional[float] = None,
    ) -> Dict[str, Any]:
        gap = min_similarity_gap if min_similarity_gap is not None else _MIN_LOGIC_GAP
        decompiled_file = Path(decompiled_path).resolve()
        if not decompiled_file.is_file():
            raise FileNotFoundError(f"反编译文件不存在: {decompiled_path}")

        decompiled_text = decompiled_file.read_text(encoding="utf-8", errors="ignore")
        decompiled_funcs = parse_decompiled_functions(decompiled_text)
        decompiled_names = set(decompiled_funcs)

        candidates: List[CandidateSource] = []
        try:
            for raw in candidate_paths:
                candidates.append(_prepare_candidate(raw, self.work_dir))
        except Exception:
            for cand in candidates:
                self._cleanup_candidate(cand)
            raise

        if len(candidates) < 2:
            for cand in candidates:
                self._cleanup_candidate(cand)
            raise ValueError("至少需要 2 个候选版本路径")

        try:
            return self._identify_core(
                decompiled_file=decompiled_file,
                decompiled_funcs=decompiled_funcs,
                decompiled_names=decompiled_names,
                candidates=candidates,
                component_name=component_name or decompiled_file.stem,
                min_similarity_gap=gap,
            )
        finally:
            for cand in candidates:
                self._cleanup_candidate(cand)

    def _cleanup_candidate(self, cand: CandidateSource) -> None:
        if cand._temp_dir and os.path.isdir(cand._temp_dir):
            shutil.rmtree(cand._temp_dir, ignore_errors=True)

    def _identify_core(
        self,
        *,
        decompiled_file: Path,
        decompiled_funcs: Dict[str, DecompiledFunction],
        decompiled_names: Set[str],
        candidates: List[CandidateSource],
        component_name: str,
        min_similarity_gap: float,
    ) -> Dict[str, Any]:
        # --- 阶段 A：缩小比对范围（仅候选版本之间有 diff 的 .c）---
        differing_files: Set[str] = set()
        for i in range(len(candidates)):
            for j in range(i + 1, len(candidates)):
                differing_files.update(
                    _files_differing_between_roots(
                        candidates[i].source_root,
                        candidates[j].source_root,
                    )
                )

        candidate_func_maps: Dict[str, Dict[str, str]] = {}
        for cand in candidates:
            func_map: Dict[str, str] = {}
            for rel in differing_files:
                fp = cand.source_root / rel
                if fp.is_file():
                    func_map.update(_extract_c_functions_from_file(fp))
            candidate_func_maps[cand.label] = func_map

        all_func_names: Set[str] = set()
        for func_map in candidate_func_maps.values():
            all_func_names.update(func_map)

        discriminators: List[DiscriminatorFunction] = []
        logic_observable: List[DiscriminatorFunction] = []

        # --- 阶段 B：逐函数筛选 + 相似度打分 ---
        for func_name in sorted(all_func_names):
            bodies = {
                label: func_map[func_name]
                for label, func_map in candidate_func_maps.items()
                if func_name in func_map
            }
            if len(bodies) < 2:
                continue
            content_hashes = {
                hashlib.md5(body.encode("utf-8", errors="ignore")).hexdigest()
                for body in bodies.values()
            }
            if len(content_hashes) < 2:
                continue

            is_logic_diff = _candidate_fingerprints_differ(bodies)
            in_decompiled = func_name in decompiled_names
            dec = decompiled_funcs.get(func_name)
            observable = bool(dec and dec.is_observable)

            if in_decompiled and not observable:
                reason = "存在于二进制但仅为 PLT 桩/不可反编译，无法比对控制流"
            elif observable and is_logic_diff:
                reason = "反编译可观察，且候选版本间控制流指纹不同（优先比对）"
            elif observable:
                reason = "反编译可观察，但候选版本间控制流指纹相同（仅文本/非逻辑差异）"
            else:
                reason = "候选版本间有差异但未编入二进制"

            disc = DiscriminatorFunction(
                name=func_name,
                observable=observable,
                is_logic_diff=is_logic_diff,
                reason=reason,
            )

            if observable and dec and is_logic_diff:
                # 对每个候选：反编译函数体 vs 该版本官方同函数源码 → fingerprint_similarity
                for cand in candidates:
                    src_body = candidate_func_maps.get(cand.label, {}).get(func_name, "")
                    if src_body:
                        disc.per_candidate_similarity[cand.label] = fingerprint_similarity(
                            dec.body, src_body
                        )
                    else:
                        disc.per_candidate_similarity[cand.label] = 0.0
                scores = list(disc.per_candidate_similarity.values())
                if scores:
                    disc.discrimination_spread = max(scores) - min(scores)
                logic_observable.append(disc)

            discriminators.append(disc)

        # --- 阶段 C：跨函数加权平均 → 各候选版本综合指纹得分 ---
        # discrimination_spread = 该函数上 max(得分)-min(得分)；spread 越大说明
        # 此函数越能区分版本，权重越高（避免「大家都一样」的函数拉低信号）。
        aggregate_scores: Dict[str, float] = {cand.label: 0.0 for cand in candidates}
        total_weight = 0.0
        for disc in logic_observable:
            spread = disc.discrimination_spread
            weight = 1.0 + min(2.0, spread * 3.0)
            total_weight += weight
            for label, score in disc.per_candidate_similarity.items():
                aggregate_scores[label] += score * weight

        if logic_observable and total_weight > 0:
            for label in aggregate_scores:
                aggregate_scores[label] /= total_weight
        elif not logic_observable:
            for label in aggregate_scores:
                aggregate_scores[label] = 0.0

        # --- 阶段 D：判定（第一梯队 / 排除低分 / 补丁 tie-break）---
        sorted_labels = sorted(aggregate_scores, key=lambda k: aggregate_scores[k], reverse=True)
        top_score = max(aggregate_scores.values()) if aggregate_scores else 0.0
        top_tier = _top_tier_labels(aggregate_scores)
        top_tier_set = set(top_tier)

        excluded: List[Dict[str, str]] = []
        for label in sorted_labels:
            if label in top_tier_set:
                continue
            gap = top_score - aggregate_scores[label]
            excluded.append(
                {
                    "version": label,
                    "reason": (
                        f"控制流指纹综合得分 {aggregate_scores[label]:.4f} 低于第一名档位 "
                        f"{top_score:.4f}（差距 {gap:.4f}）"
                    ),
                }
            )

        # 可选：第一名内若仍有显著差距，再按 MIN_LOGIC_GAP 排除（一般用于多函数加权后）
        if len(top_tier) > 1 and min_similarity_gap > 0:
            tier_sorted = sorted(top_tier, key=lambda k: aggregate_scores[k], reverse=True)
            tier_best = tier_sorted[0]
            tier_best_score = aggregate_scores[tier_best]
            for label in tier_sorted[1:]:
                gap = tier_best_score - aggregate_scores[label]
                if gap >= min_similarity_gap and label in top_tier_set:
                    excluded.append(
                        {
                            "version": label,
                            "reason": (
                                f"虽在第一名档位内，但与 {tier_best} 得分差距 {gap:.3f} "
                                f"≥ 阈值 {min_similarity_gap}"
                            ),
                        }
                    )
                    top_tier_set.discard(label)
            top_tier = [label for label in top_tier if label in top_tier_set]

        tie_break_note: Optional[str] = None
        remaining = list(top_tier)
        if len(remaining) > 1:
            remaining, tie_break_note = _apply_tie_break(remaining)

        indistinguishable: List[List[str]] = []
        if len(remaining) > 1:
            indistinguishable.append(remaining)
        elif not logic_observable:
            indistinguishable.append([cand.label for cand in candidates])

        is_range_conclusion = len(remaining) > 1
        winner_label = remaining[0] if len(remaining) == 1 else None

        if is_range_conclusion:
            conclusion_type = "range"
            conclusion_summary = (
                f"{', '.join(remaining)} 在当前编译配置下不可区分"
            )
        else:
            conclusion_type = "unique"
            conclusion_summary = f"最接近 {winner_label}"
            if tie_break_note:
                conclusion_summary += f"（{tie_break_note}）"

        best_candidates = []
        target_labels = indistinguishable[0] if is_range_conclusion else remaining[:1]
        for cand in candidates:
            if cand.label in target_labels:
                best_candidates.append(
                    {
                        "version": cand.version_string,
                        "label": cand.label,
                        "path": str(cand.path),
                        "source_root": str(cand.source_root),
                        "confidence": round(aggregate_scores.get(cand.label, 0.0), 4),
                        "version_meta": cand.version_meta,
                    }
                )
        best_candidates.sort(key=lambda item: item["confidence"], reverse=True)

        matched_source_path = None
        if winner_label:
            matched_source_path = next(
                (str(c.source_root.parent) for c in candidates if c.label == winner_label),
                None,
            )

        key_discriminators = sorted(
            logic_observable,
            key=lambda item: (-item.discrimination_spread, item.name),
        )

        report_md = self._render_report(
            component_name=component_name,
            decompiled_file=decompiled_file,
            candidates=candidates,
            differing_files=sorted(differing_files),
            discriminators=discriminators,
            key_discriminators=key_discriminators,
            aggregate_scores=aggregate_scores,
            excluded=excluded,
            indistinguishable=indistinguishable,
            decompiled_funcs=decompiled_funcs,
            tie_break_note=tie_break_note,
            winner_label=winner_label,
            scoring_method="control_flow_fingerprint",
        )

        return {
            "ok": True,
            "component_name": component_name,
            "decompiled_path": str(decompiled_file),
            "candidate_count": len(candidates),
            "conclusion_type": conclusion_type,
            "conclusion_summary": conclusion_summary,
            "scoring_method": "control_flow_fingerprint",
            "tie_break_mode": _TIE_BREAK_MODE,
            "tie_break_note": tie_break_note,
            "best_matches": best_candidates,
            "excluded_versions": excluded,
            "indistinguishable_groups": indistinguishable,
            "aggregate_scores": aggregate_scores,
            "observable_logic_diff_count": len(logic_observable),
            "discriminators": [
                {
                    "name": d.name,
                    "observable": d.observable,
                    "is_logic_diff": d.is_logic_diff,
                    "reason": d.reason,
                    "discrimination_spread": round(d.discrimination_spread, 4),
                    "per_candidate_similarity": d.per_candidate_similarity,
                }
                for d in discriminators
            ],
            "key_discriminators": [
                {
                    "name": d.name,
                    "discrimination_spread": round(d.discrimination_spread, 4),
                    "per_candidate_similarity": d.per_candidate_similarity,
                }
                for d in key_discriminators[:15]
            ],
            "matched_source_root": matched_source_path,
            "report_markdown": report_md,
        }

    def _render_report(
        self,
        *,
        component_name: str,
        decompiled_file: Path,
        candidates: List[CandidateSource],
        differing_files: List[str],
        discriminators: List[DiscriminatorFunction],
        key_discriminators: List[DiscriminatorFunction],
        aggregate_scores: Dict[str, float],
        excluded: List[Dict[str, str]],
        indistinguishable: List[List[str]],
        decompiled_funcs: Dict[str, DecompiledFunction],
        tie_break_note: Optional[str],
        winner_label: Optional[str],
        scoring_method: str,
    ) -> str:
        lines = [
            f"# 组件版本识别报告：{component_name}",
            "",
            "## 1. 输入",
            f"- 反编译文件：`{decompiled_file}`",
            f"- 候选版本：{', '.join(c.version_string for c in candidates)}",
            f"- 评分方法：`{scoring_method}`（控制流 if 形状 + 条件常量 + 逻辑运算符骨架）",
            f"- 反编译解析函数数：{len(decompiled_funcs)}（可观察完整实现：{sum(1 for f in decompiled_funcs.values() if f.is_observable)}）",
            "",
            "## 2. 候选版本间差异文件",
        ]
        if differing_files:
            for rel in differing_files[:40]:
                lines.append(f"- `{rel}`")
            if len(differing_files) > 40:
                lines.append(f"- … 另有 {len(differing_files) - 40} 个文件")
        else:
            lines.append("- （无 .c 差异）")

        lines.extend(
            [
                "",
                "## 3. 关键逻辑差异函数（可观察且控制流指纹不同）",
                "| 函数 | 区分度 spread | 各版本指纹得分 |",
                "|------|---------------|----------------|",
            ]
        )
        if key_discriminators:
            for disc in key_discriminators[:20]:
                scores_text = ", ".join(
                    f"{label}={disc.per_candidate_similarity.get(label, 0):.3f}"
                    for label in sorted(disc.per_candidate_similarity)
                )
                lines.append(f"| `{disc.name}` | {disc.discrimination_spread:.3f} | {scores_text} |")
        else:
            lines.append("| （无） | - | 未找到可观察的逻辑差异函数 |")

        lines.extend(
            [
                "",
                "## 4. 其他差异函数（节选）",
                "| 函数 | 可观察 | 逻辑差异 | 说明 |",
                "|------|--------|----------|------|",
            ]
        )
        shown = {d.name for d in key_discriminators}
        extra = [d for d in discriminators if d.name not in shown][:15]
        for disc in extra:
            lines.append(
                f"| `{disc.name}` | {'是' if disc.observable else '否'} | "
                f"{'是' if disc.is_logic_diff else '否'} | {disc.reason} |"
            )
        if len(discriminators) > len(shown) + len(extra):
            lines.append(f"| … | | | 共 {len(discriminators)} 个差异函数 |")

        lines.extend(["", "## 5. 综合指纹得分", "| 候选版本 | 得分 |", "|----------|------|"])
        for label, score in sorted(aggregate_scores.items(), key=lambda x: -x[1]):
            lines.append(f"| {label} | {score:.4f} |")

        lines.extend(["", "## 6. 判定"])
        if winner_label and not (indistinguishable and len(indistinguishable[0]) > 1):
            if tie_break_note:
                lines.append(
                    f"- **唯一结论**：**{winner_label}**（控制流指纹判定为第一梯队；"
                    f"补丁 tie-break 见下）。"
                )
                lines.append(f"- **补丁级说明**：{tie_break_note}")
            else:
                lines.append(
                    f"- **唯一结论**：最接近 **{winner_label}**（控制流指纹 + 排他排除）。"
                )
        elif indistinguishable and len(indistinguishable[0]) > 1:
            lines.append(
                f"- **范围结论**：{', '.join(indistinguishable[0])} 在当前编译配置下不可区分。"
            )
            if tie_break_note:
                lines.append(f"- **补丁级说明**：{tie_break_note}")
            elif not key_discriminators:
                lines.append(
                    "- **原因**：版本间差异未落在可观察函数的 control-flow 指纹 上。"
                )
        else:
            lines.append("- **无法判定**：缺少可观察逻辑差异函数。")

        if excluded:
            lines.extend(["", "### 已排除版本"])
            for item in excluded:
                lines.append(f"- **{item['version']}**：{item['reason']}")

        lines.extend(["", "## 7. 说明"])
        lines.append("- 判定优先使用控制流指纹，而非 Ghidra 反编译文本与源码的全文相似度。")
        lines.append("- SONAME / 文件名版本号为 ABI 号，不能单独当作发布版本。")
        lines.append(
            "- 环境变量：`AGENT_VERSION_TIE_BREAK`（none/highest_patch/lowest_patch），"
            "`AGENT_VERSION_FIRST_PLACE_EPSILON`（第一名档位容差），"
            "`AGENT_VERSION_MIN_LOGIC_GAP`。"
        )
        return "\n".join(lines)
