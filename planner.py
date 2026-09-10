"""
`planner.py` 提供统一的 agent 编排循环。

目标：
1. 让用户以自然语言提出任务，而不是先选择固定模式
2. 让大模型在每一步都执行：思考 -> 计划 -> 行动 -> 复盘 -> 再计划
3. 将现有源码扫描、漏洞可达分析能力统一纳入同一执行框架
"""

import config  # noqa: F401

import json
import logging
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4

import prompts
from audit_renderer import render_audit_reports
from evidence_levels import EVIDENCE_GOALS_ONE_LINER, EVIDENCE_LEVEL_SPECS
from flow_reconcile import (
    build_bounded_finish_report,
    build_planner_l2_context_bundle,
    reconcile_ambiguous_flows,
    update_flow_findings_l2_status,
)
from flow_merge import should_skip_whole_file_read
from l2_reads import (
    aggregate_pending_l2_reads,
    build_pending_l2_entry,
    collect_refutation_l2_read_suggestions,
    extract_paths_from_user_request,
    infer_l2_kind,
    normalize_scan_language,
    resolve_l2_pending_line_range,
    sanitize_joern_project_path,
)
from language_profiles import get_l2_playbook_hint
from logic_scan_settings import (
    DEFAULT_CWE_FOCUS,
    DEFAULT_MAX_CANDIDATES,
    HIGH_HIT_L2_THRESHOLD,
    JAVA_SECURITY_CONFIG_GLOBS,
    LOGIC_ONLY_AUDIT_MODE,
    LOGIC_ONLY_BLOCKED_SKILL_IDS,
    MAX_CANDIDATES_FLOOR,
    TAINT_SCAN_TOOL_NAMES,
    detect_logic_only_intent,
    resolve_cwe_focus,
    resolve_max_candidates,
)
from project_file_index import (
    ProjectFileIndex,
    build_project_file_index,
    index_from_metadata,
    resolve_l2_path,
)
from report_merge import merge_scan_reports
from file_tools import FileTool
from graph import GraphBuilder
from llm_client import LLMClient, get_default_llm_client
from prompt_evolution import PromptEvolutionManager
from java_audit_tool import JavaAuditTool
from skill_engine import SkillEngine
from state import AgentState
from tool_capabilities import TOOL_CAPABILITIES

logger = logging.getLogger(__name__)

FILE_EVIDENCE_PREVIEW_CHARS = int(os.environ.get("PLANNER_FILE_EVIDENCE_PREVIEW_CHARS", "2000"))
FILE_READ_OBSERVATION_PREVIEW_CHARS = int(
    os.environ.get("PLANNER_FILE_READ_OBSERVATION_PREVIEW_CHARS", "4000")
)
FILE_READ_MAX_LINES = int(os.environ.get("PLANNER_FILE_READ_MAX_LINES", "600"))
FILE_READ_OVERLAP_COVERAGE_RATIO = float(
    os.environ.get("PLANNER_FILE_READ_OVERLAP_COVERAGE_RATIO", "0.7")
)
FILE_WHOLE_FILE_LINE_THRESHOLD = int(
    os.environ.get("PLANNER_FILE_WHOLE_FILE_LINE_THRESHOLD", "12000")
)
FILE_SOURCE_WHOLE_FILE_MAX_LINES = int(
    os.environ.get("PLANNER_FILE_SOURCE_WHOLE_FILE_MAX_LINES", "800")
)
PLANNER_FLOW_EXPAND_MAX_ITERS = int(os.environ.get("PLANNER_FLOW_EXPAND_MAX_ITERS", "2"))
PLANNER_SKILL_BLOCKED_WHEN_CLOSURE_TOOLS = frozenset(
    {
        "JoernTool.run_targeted_scan",
        "JoernTool.run_taint_queries",
        "JoernTool.run_source_scan",
        "JoernTool.run_logic_scan",
        "GraphBuilder.run_source_scan",
    }
)
FINISH_BLOCKED_FORCE_ACTION_AFTER = int(
    os.environ.get("PLANNER_FINISH_BLOCKED_FORCE_AFTER", "1")
)
PLANNER_DUP_READ_STALL_THRESHOLD = int(
    os.environ.get("PLANNER_DUP_READ_STALL_THRESHOLD", "2")
)
PLANNER_BLOCKED_SCAN_FORCE_AFTER = int(
    os.environ.get("PLANNER_BLOCKED_SCAN_FORCE_AFTER", "1")
)
PLANNER_FLOW_RE_REFUTE_MAX = int(os.environ.get("PLANNER_FLOW_RE_REFUTE_MAX", "2"))


class AgentPlannerExecutor:
    """
    统一的 planner / executor / replan 编排器。

    该类不直接实现底层扫描逻辑，而是：
    - 根据用户任务生成计划
    - 决定下一步要调用哪个高层工具
    - 执行工具并记录观察结果
    - 把执行结果反馈给模型，继续下一轮规划

    此外还会把每轮规划和执行过程落盘到 JSONL 审计日志，便于回放：
    - planner 生成了什么 plan
    - planner 如何基于上一轮 observation 更新计划（plan_updated）
    - 实际执行了哪个 action
    - action 返回了什么 observation
    - 最终因为什么原因结束
    """

    def __init__(
        self,
        graph: GraphBuilder,
        llm_client: Optional[LLMClient] = None,
        max_steps: int = 120,
        audit_log_path: Optional[str] = None,
    ):
        self.graph = graph
        self.llm_client = llm_client or get_default_llm_client()
        self.file_tool = FileTool()
        self.java_audit_tool = JavaAuditTool()
        self.skill_engine = SkillEngine()
        self.prompt_evolver = PromptEvolutionManager(Path(os.getcwd()))
        self.max_steps = max_steps
        self.audit_log_path = audit_log_path
        # 完整 ProjectFileIndex（相对路径全集），避免 metadata.to_dict() 只保留 ~120 条 sample
        self._live_file_index: Optional[ProjectFileIndex] = None

    @staticmethod
    def _normalize_evidence_path(path: str) -> str:
        try:
            resolved = str(Path(path).resolve(strict=False))
        except (OSError, ValueError):
            resolved = str(path)
        return resolved.lower() if os.name == "nt" else resolved

    def _rebuild_project_file_index(self, state: AgentState) -> None:
        language = normalize_scan_language(state.language or "cpp")
        index = build_project_file_index(state.local_source_path, language)
        if index:
            self._live_file_index = index
            state.metadata["project_file_index"] = index.to_dict()
            state.metadata["available_source_files"] = index.flat_list_for_prompt(100)
            logger.info(
                "project_file_index 已构建: %s 个路径 (truncated=%s, prompt 展示 %s 条)",
                index.total_discovered,
                index.truncated,
                len(state.metadata["available_source_files"]),
            )
        else:
            self._live_file_index = None
            state.metadata.pop("project_file_index", None)
            state.metadata["available_source_files"] = self._list_available_source_files(
                state.local_source_path
            )

    def _ensure_local_source_root(self, state: AgentState, user_request: str) -> None:
        """启动时锁定目标源码根，避免在 Agent 自身 cwd 上列目录/读文件。"""
        seeded = extract_paths_from_user_request(user_request or "")
        if seeded.get("local_source_path"):
            candidate = seeded["local_source_path"]
            if os.path.isdir(candidate):
                state.set_local_source_path(candidate)
        if seeded.get("project_path") and not state.project_path:
            state.set_project(
                sanitize_joern_project_path(seeded["project_path"]),
                local_source_path=state.local_source_path,
            )
        agent_cwd = os.path.normcase(os.getcwd())
        lsp = state.local_source_path or ""
        if lsp and os.path.isdir(lsp):
            if os.path.normcase(lsp) == agent_cwd and seeded.get("local_source_path"):
                fixed = seeded["local_source_path"]
                if fixed and os.path.isdir(fixed) and os.path.normcase(fixed) != agent_cwd:
                    state.set_local_source_path(fixed)
        self._rebuild_project_file_index(state)

    def _get_file_index(self, state: AgentState) -> Optional[ProjectFileIndex]:
        """返回完整索引（相对路径全集）；metadata 里仅为审计摘要。"""
        lsp = (state.local_source_path or "").strip()
        language = normalize_scan_language(state.language or "cpp")
        live = self._live_file_index
        if (
            live is not None
            and live.local_source_path == lsp
            and live.language == language
        ):
            return live
        if lsp and os.path.isdir(lsp):
            rebuilt = build_project_file_index(lsp, language)
            if rebuilt:
                self._live_file_index = rebuilt
                return rebuilt
        return index_from_metadata(state.metadata)

    def _resolve_planner_read_path(
        self, state: AgentState, raw_path: str
    ) -> Optional[Dict[str, Any]]:
        """仅通过 project_file_index 解析；非 glob 路径不得绕过索引直接读盘。"""
        language = normalize_scan_language(state.language or "cpp")
        file_index = self._get_file_index(state)
        if file_index is None:
            return None
        resolved = resolve_l2_path(
            raw_path,
            language=language,
            file_index=file_index,
            local_source_path=state.local_source_path,
        )
        if resolved:
            return {
                "path": resolved.path,
                "kind": resolved.kind,
                "resolved_via": resolved.resolved_via,
            }
        return None

    def _read_file_index_rejected(
        self,
        state: AgentState,
        *,
        raw_path: str,
        tool_name: str = "FileTool.read_file",
    ) -> Dict[str, Any]:
        failures = list(state.metadata.get("file_read_failures") or [])
        if raw_path not in failures:
            failures.append(str(raw_path))
            state.metadata["file_read_failures"] = failures[-50:]
        logger.warning(
            "%s 索引拒绝: %s（不在 project_file_index，请用 available_source_files 或 glob）",
            tool_name,
            raw_path,
        )
        return {
            "ok": False,
            "tool_name": tool_name,
            "result_summary": (
                f"路径未在项目索引中解析: {raw_path}；"
                "请使用 available_source_files 或 glob 确认后再读。"
            ),
            "result": {"path": raw_path, "error": "path_not_in_index"},
        }

    def _l1_covers_read_range(
        self,
        state: AgentState,
        path_norm: str,
        start: int,
        end: int,
    ) -> bool:
        ranges = list(state.metadata.get("l1_covered_ranges") or [])
        for entry in ranges:
            entry_path = self._normalize_evidence_path(entry.get("path", ""))
            if entry_path != path_norm:
                continue
            rs = entry.get("start_line")
            re_ = entry.get("end_line")
            if isinstance(rs, int) and isinstance(re_, int) and rs <= start and re_ >= end:
                return True
        return False
        try:
            resolved = str(Path(path).resolve(strict=False))
        except (OSError, ValueError):
            resolved = str(path)
        return resolved.lower() if os.name == "nt" else resolved

    @staticmethod
    def _parse_evidence_line_range(lines_field: str) -> Optional[tuple]:
        if not lines_field:
            return None
        match = re.match(r"^(\d+)-(\d+)$", str(lines_field).strip())
        if not match:
            return None
        return int(match.group(1)), int(match.group(2))

    @staticmethod
    def _line_range_overlap_coverage(
        start: int, end: int, ranges: List[tuple], min_ratio: float = 0.7
    ) -> bool:
        if end < start:
            return False
        request_len = end - start + 1
        if request_len <= 0:
            return False
        covered = 0
        for range_start, range_end in ranges:
            overlap_start = max(start, range_start)
            overlap_end = min(end, range_end)
            if overlap_start <= overlap_end:
                covered += overlap_end - overlap_start + 1
        return (covered / request_len) >= min_ratio

    @staticmethod
    def _line_range_covered(start: int, end: int, ranges: List[tuple]) -> bool:
        for range_start, range_end in ranges:
            if range_start <= start and range_end >= end:
                return True
        return AgentPlannerExecutor._line_range_overlap_coverage(
            start, end, ranges, min_ratio=FILE_READ_OVERLAP_COVERAGE_RATIO
        )

    def _collect_covered_ranges_for_path(
        self, path_norm: str, reads: List[Dict[str, Any]]
    ) -> List[tuple]:
        covered: List[tuple] = []
        for entry in reads:
            if self._normalize_evidence_path(entry.get("path", "")) != path_norm:
                continue
            parsed = self._parse_evidence_line_range(entry.get("lines", ""))
            if parsed:
                covered.append(parsed)
        return covered

    def _find_cached_file_evidence(
        self,
        path_norm: str,
        start_line: int,
        end_line: int,
        reads: List[Dict[str, Any]],
        contents: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        covered_ranges = self._collect_covered_ranges_for_path(path_norm, reads)
        if not self._line_range_covered(start_line, end_line, covered_ranges):
            return None
        for entry in reversed(contents or []):
            if self._normalize_evidence_path(entry.get("path", "")) != path_norm:
                continue
            entry_start = entry.get("start_line")
            entry_end = entry.get("end_line")
            if (
                isinstance(entry_start, int)
                and isinstance(entry_end, int)
                and entry_start <= start_line
                and entry_end >= end_line
            ):
                return entry
        return {
            "path": path_norm,
            "start_line": start_line,
            "end_line": end_line,
            "content_preview": "(该行段已在 file_evidence_reads 中记录，见 state_snapshot.file_evidence_read_previews)",
            "skipped_duplicate": True,
        }

    def _record_file_evidence_read(
        self,
        state: AgentState,
        read_result: Dict[str, Any],
        *,
        flow_id: Optional[str] = None,
    ) -> None:
        if not read_result.get("ok") or not read_result.get("path"):
            return
        path_norm = self._normalize_evidence_path(str(read_result.get("path", "")))
        if not flow_id:
            flow_id = self._match_pending_l2_flow_for_path(state, path_norm)
        reads = list(state.metadata.get("file_evidence_reads") or [])
        entry = {
            "path": read_result.get("path"),
            "lines": f"{read_result.get('start_line')}-{read_result.get('end_line')}",
        }
        if flow_id:
            entry["flow_id"] = flow_id
        reads.append(entry)
        state.metadata["file_evidence_reads"] = reads[-30:]

        if flow_id and path_norm:
            bucket = dict(state.metadata.get("flow_l2_read_paths") or {})
            paths = list(dict.fromkeys(list(bucket.get(flow_id, [])) + [path_norm]))
            bucket[flow_id] = paths[-20:]
            state.metadata["flow_l2_read_paths"] = bucket

        content = read_result.get("content") or ""
        previews = list(state.metadata.get("file_evidence_content") or [])
        preview_entry = {
            "path": read_result.get("path"),
            "start_line": read_result.get("start_line"),
            "end_line": read_result.get("end_line"),
            "total_lines": read_result.get("total_lines"),
            "content_preview": content[:FILE_EVIDENCE_PREVIEW_CHARS],
        }
        if flow_id:
            preview_entry["flow_id"] = flow_id
        previews.append(preview_entry)
        state.metadata["file_evidence_content"] = previews[-15:]

    @staticmethod
    def _strip_lines_suffix(path_key: str) -> str:
        """去除 _collect_read_path_keys 产出的 ':start-end' 后缀。"""
        idx = path_key.rfind(":")
        if idx > 0 and path_key[idx + 1 :].replace("-", "").isdigit():
            return path_key[:idx]
        return path_key

    def _path_suffix_match(self, target: str, raw_normalized: str) -> bool:
        """精确路径后缀匹配：完全相等 或 任一方以 '/'+另一方 结尾。

        支持 pending_l2_reads（相对路径）与 file_evidence_reads（绝对路径）
        之间的交叉匹配，避免因路径格式不同而误判为"未读"。
        """
        normalized = self._strip_lines_suffix(raw_normalized)
        if target == normalized:
            return True
        if normalized.endswith("/" + target):
            return True
        # 反向匹配：target 是绝对路径、normalized 是相对路径时
        if target.endswith("/" + normalized):
            return True
        return False

    def _is_l2_path_already_read(self, state: AgentState, item: Dict[str, Any]) -> bool:
        target = str(item.get("path") or "").lower().replace("\\", "/")
        if not target:
            return True
        for key in self._collect_read_path_keys(state):
            normalized = str(key).lower().replace("\\", "/")
            if self._path_suffix_match(target, normalized):
                return True
        # 同时检查失败路径列表：已失败的路径不再重试
        for failed_path in list(state.metadata.get("file_read_failures") or []):
            failed_norm = str(failed_path).lower().replace("\\", "/")
            if self._path_suffix_match(target, failed_norm):
                return True
        return False

    def _is_path_already_read_raw(self, state: AgentState, raw_path: str) -> bool:
        """检查原始路径字符串是否已读过（用于 preempt 硬保护）。

        比 _is_l2_path_already_read 更宽松：同时检查 file_evidence_reads
        和 file_read_failures，支持绝对/相对路径交叉匹配。
        """
        target = raw_path.lower().replace("\\", "/")
        # 去除 local_source_path 前缀
        local = str(state.local_source_path or "").replace("\\", "/").rstrip("/")
        if local and target.lower().startswith(local.lower()):
            target = target[len(local):].lstrip("/")
        for key in self._collect_read_path_keys(state):
            normalized = str(key).lower().replace("\\", "/")
            if self._path_suffix_match(target, normalized):
                return True
        for failed_path in list(state.metadata.get("file_read_failures") or []):
            failed_norm = str(failed_path).lower().replace("\\", "/")
            if self._path_suffix_match(target, failed_norm):
                return True
        return False

    def _mark_l2_path_as_read(self, state: AgentState, path: str) -> None:
        """将路径标记为已读（加入失败列表），避免重复尝试。

        自动将绝对路径转为相对路径，确保与 pending_l2_reads 中的
        相对路径格式一致，使 _path_suffix_match 能正确匹配。
        """
        norm = str(path or "").replace("\\", "/").strip()
        # 绝对路径 → 相对路径，与 pending_l2_reads 格式对齐
        local = str(state.local_source_path or "").replace("\\", "/").rstrip("/")
        if local and norm.lower().startswith(local.lower()):
            norm = norm[len(local):].lstrip("/")
        if not norm:
            return
        failures = list(state.metadata.get("file_read_failures") or [])
        if norm not in failures:
            failures.append(norm)
            state.metadata["file_read_failures"] = failures[-50:]

    def _collect_read_path_keys(self, state: AgentState) -> set:
        keys: set = set()
        for entry in list(state.metadata.get("file_evidence_reads") or []):
            path = str(entry.get("path") or "")
            if path:
                keys.add(path.lower())
            lines = entry.get("lines")
            if lines:
                keys.add(f"{path.lower()}:{lines}")
        return keys

    def _sync_pending_l2_reads(self, state: AgentState, scan_result: Dict[str, Any]) -> None:
        raw_entries = scan_result.get("pending_l2_reads_raw") or []
        state.metadata["pending_l2_reads"] = aggregate_pending_l2_reads(
            raw_entries,
            language=state.language,
            local_source_path=state.local_source_path,
            already_read_paths=self._collect_read_path_keys(state),
        )
        self._merge_flow_findings_index(
            state, scan_result.get("flow_findings_index") or []
        )
        self._sync_flow_catalog(state, scan_result)

    def _sync_flow_catalog(self, state: AgentState, scan_result: Dict[str, Any]) -> None:
        catalog = dict(scan_result.get("flow_catalog") or {})
        existing = dict(state.metadata.get("flow_catalog") or {})
        existing.update(catalog)
        for item in scan_result.get("ambiguous_flows") or []:
            flow_id = item.get("flow_id")
            if not flow_id:
                continue
            existing[str(flow_id)] = {
                "vuln_type": item.get("vuln_type"),
                "flow_id": flow_id,
                "sink_label": item.get("sink_label", ""),
                "flow_text": item.get("flow_text", ""),
            }
        state.metadata["flow_catalog"] = existing

    def _lookup_flow_record(self, state: AgentState, flow_id: str) -> Optional[Dict[str, Any]]:
        if not flow_id:
            return None
        catalog = state.metadata.get("flow_catalog") or {}
        if flow_id in catalog:
            return dict(catalog[flow_id])
        for item in state.ambiguous_flows or []:
            if item.get("flow_id") == flow_id:
                return dict(item)
        for item in state.metadata.get("pending_l2_reads") or []:
            if item.get("flow_id") == flow_id:
                return {
                    "flow_id": flow_id,
                    "vuln_type": item.get("vuln_type"),
                    "sink_label": item.get("sink_label", ""),
                    "flow_text": "",
                    "refutation_verdict": item.get("refutation_verdict"),
                    "kind": item.get("kind"),
                }
        for item in state.metadata.get("flow_findings_index") or []:
            if item.get("flow_id") == flow_id:
                return {
                    "flow_id": flow_id,
                    "vuln_type": item.get("vuln_type"),
                    "sink_label": item.get("sink_label", ""),
                    "flow_text": "",
                    "refutation_verdict": item.get("refutation_verdict"),
                }
        return None

    def _build_logic_flow_context(self, state: AgentState, flow_id: str) -> str:
        """从逻辑扫描存储的 finding 中构建 flow_text 上下文。

        逻辑扫描的 finding 已存储了 method_source_preview 和 caller_chain_preview。
        此方法将这些上下文组装成可供 expand_flow_context 使用的格式。

        输出格式参考 Joern taint flow 输出，包含方法全名、文件、行号，
        以便后续的 _extract_code_context 和 follow_up 查询能正确解析。
        """
        # flow_id 格式: logic_xxx_123，提取 candidate_id
        if not flow_id.startswith("logic_"):
            return ""
        candidate_id = flow_id[len("logic_"):]

        # 从 logic_inconclusive_findings 或 logic_findings 中查找
        findings_sources = [
            state.metadata.get("logic_inconclusive_findings") or [],
            state.metadata.get("last_logic_findings") or [],
        ]
        finding = None
        for src in findings_sources:
            for f in src:
                if str(f.get("candidate_id", "")) == candidate_id:
                    finding = f
                    break
            if finding:
                break

        if not finding:
            return ""

        # 组装为类 Joern 输出格式，便于后续解析方法名
        parts = []
        caller = finding.get("caller", "")
        file_info = finding.get("file", "")
        line_info = finding.get("line", 0)
        cwe = finding.get("cwe", "")
        vuln_type = finding.get("candidate_type", "")

        # 模拟 Joern 输出头部，包含关键元信息
        parts.append(f"# Logic Flow: {flow_id}")
        parts.append(f"# CWE: {cwe} | Type: {vuln_type}")
        parts.append(f"# Method: {caller}")
        parts.append(f"# File: {file_info}:{line_info}")
        parts.append("")

        # 源码部分（如果有）
        method_src = finding.get("method_source_preview", "")
        if method_src:
            parts.append(f"--- method_source: {caller} ---")
            parts.append(method_src)
            parts.append(f"--- end_method_source ---")
            parts.append("")

        caller_src = finding.get("caller_chain_preview", "")
        if caller_src:
            parts.append(f"--- caller_chain_source ---")
            parts.append(caller_src)
            parts.append(f"--- end_caller_chain ---")
            parts.append("")

        expansion_src = finding.get("expansion_context_preview", "")
        if expansion_src:
            parts.append("--- expansion_context ---")
            parts.append(expansion_src)
            parts.append("--- end_expansion_context ---")
            parts.append("")

        # 证据信息（如果源码缺失）
        evidence = finding.get("evidence", "")
        if evidence and not method_src:
            parts.append(f"--- evidence ---")
            parts.append(evidence)
            parts.append(f"--- end_evidence ---")

        return "\n".join(parts) if parts else ""

    def _get_logic_flow_method_name(self, state: AgentState, flow_id: str) -> str:
        """从逻辑扫描 finding 中提取方法全名，供 Joern 扩展使用。"""
        if not flow_id.startswith("logic_"):
            return ""
        candidate_id = flow_id[len("logic_"):]

        findings_sources = [
            state.metadata.get("logic_inconclusive_findings") or [],
            state.metadata.get("last_logic_findings") or [],
        ]
        for src in findings_sources:
            for f in src:
                if str(f.get("candidate_id", "")) == candidate_id:
                    return str(f.get("caller", "") or "")
        return ""

    def _infer_read_file_kind(self, state: AgentState, path: str) -> str:
        resolved = self._resolve_planner_read_path(state, path)
        if resolved and resolved.get("kind"):
            return str(resolved["kind"])
        from project_file_index import _guess_kind

        return _guess_kind(path, normalize_scan_language(state.language or "cpp"))

    def _flow_needs_joern_expand_before_source_read(
        self, state: AgentState, flow_id: str
    ) -> bool:
        if os.environ.get("PLANNER_SKIP_JOERN_EXPAND_GATE", "0") == "1":
            return False
        if not flow_id:
            return False
        record = self._lookup_flow_record(state, flow_id) or {}
        refutation = str(record.get("refutation_verdict") or "").lower()
        for item in state.metadata.get("pending_l2_reads") or []:
            if item.get("flow_id") == flow_id:
                refutation = refutation or str(item.get("refutation_verdict") or "").lower()
                if str(item.get("kind") or "").lower() == "source":
                    return refutation in ("", "inconclusive")
        for item in state.metadata.get("flow_findings_index") or []:
            if item.get("flow_id") == flow_id:
                ref = str(item.get("refutation_verdict") or "").lower()
                if ref == "inconclusive":
                    return True
        if refutation == "inconclusive":
            return True
        for item in state.ambiguous_flows or []:
            if item.get("flow_id") == flow_id:
                return True
        return False

    def _joern_expand_allows_source_read(
        self, state: AgentState, flow_id: str
    ) -> tuple:
        if not self._flow_needs_joern_expand_before_source_read(state, flow_id):
            return True, ""
        rec = (state.metadata.get("flow_joern_expansion") or {}).get(flow_id)
        if not rec or not rec.get("called"):
            return (
                False,
                f"flow {flow_id}：L2 仍 inconclusive，须先 JoernTool.expand_flow_context",
            )
        if rec.get("sufficient") or rec.get("exhausted"):
            return True, ""
        return (
            False,
            (
                f"flow {flow_id}：expand_flow_context 未完成 "
                f"({rec.get('iterations_used', 0)}/{rec.get('max_iters', PLANNER_FLOW_EXPAND_MAX_ITERS)})"
            ),
        )

    def _record_flow_joern_expansion(
        self, state: AgentState, flow_id: str, result: Dict[str, Any]
    ) -> None:
        bucket = dict(state.metadata.get("flow_joern_expansion") or {})
        prior = bucket.get(flow_id) or {}
        accumulated = (prior.get("context_preview") or "") + "\n" + (
            result.get("context_preview") or ""
        )
        bucket[flow_id] = {
            "called": True,
            "iterations_used": result.get("iterations_used", 0),
            "max_iters": result.get("max_iters", PLANNER_FLOW_EXPAND_MAX_ITERS),
            "sufficient": bool(result.get("sufficient")),
            "exhausted": bool(result.get("exhausted")),
            "ok": bool(result.get("ok")),
            "context_preview": accumulated.strip()[-4000:],
        }
        state.metadata["flow_joern_expansion"] = bucket
        l1_ranges = result.get("l1_covered_ranges") or []
        if l1_ranges:
            merged = list(state.metadata.get("l1_covered_ranges") or [])
            merged.extend(l1_ranges)
            state.metadata["l1_covered_ranges"] = merged[-200:]

    def _match_pending_l2_flow_for_path(
        self, state: AgentState, path_norm: str
    ) -> Optional[str]:
        basename = Path(path_norm).name.lower()
        for item in state.metadata.get("pending_l2_reads") or []:
            item_path = self._normalize_evidence_path(str(item.get("path", "")))
            if item_path == path_norm and item.get("flow_id"):
                return str(item["flow_id"])
        for item in state.metadata.get("pending_l2_reads") or []:
            item_path = self._normalize_evidence_path(str(item.get("path", "")))
            if (
                Path(item_path).name.lower() == basename
                and basename
                and item.get("flow_id")
            ):
                return str(item["flow_id"])
        return None

    def _source_read_gate_blocked(
        self,
        state: AgentState,
        *,
        path: str,
        flow_id: Optional[str] = None,
        kind: Optional[str] = None,
    ) -> tuple:
        file_kind = kind or self._infer_read_file_kind(state, path)
        if file_kind != "source":
            return False, ""
        fid = flow_id
        if not fid:
            path_norm = self._normalize_evidence_path(path)
            fid = self._match_pending_l2_flow_for_path(state, path_norm)
        if not fid:
            return False, ""
        allowed, reason = self._joern_expand_allows_source_read(state, fid)
        return (not allowed), reason

    def _build_expand_flow_action(
        self, state: AgentState, target: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        flow_id = target.get("flow_id")
        if not flow_id:
            return None
        if str(target.get("kind") or "").lower() != "source":
            return None
        if not self._flow_needs_joern_expand_before_source_read(state, str(flow_id)):
            return None
        allowed, _ = self._joern_expand_allows_source_read(state, str(flow_id))
        if allowed:
            return None
        record = self._lookup_flow_record(state, str(flow_id)) or {}
        vuln_type = (
            target.get("vuln_type")
            or record.get("vuln_type")
            or "unknown"
        )
        arguments: Dict[str, Any] = {
            "flow_id": flow_id,
            "vuln_type": vuln_type,
            "max_extra_iters": PLANNER_FLOW_EXPAND_MAX_ITERS,
        }
        # 逻辑扫描 flow：传递 method_name 供 Joern 扩展使用
        if str(flow_id).startswith("logic_"):
            method_name = self._get_logic_flow_method_name(state, str(flow_id))
            if method_name:
                arguments["method_name"] = method_name
        return {
            "tool_name": "JoernTool.expand_flow_context",
            "arguments": arguments,
        }

    def _merge_flow_findings_index(
        self, state: AgentState, new_findings: List[Dict[str, Any]]
    ) -> None:
        """增量扫描时按 flow_id 合并反证索引，避免覆盖首轮结论。"""
        merged: Dict[str, Dict[str, Any]] = {}
        for item in list(state.metadata.get("flow_findings_index") or []):
            flow_id = item.get("flow_id")
            if flow_id:
                merged[str(flow_id)] = item
        for item in new_findings or []:
            flow_id = item.get("flow_id")
            if flow_id:
                merged[str(flow_id)] = item
        state.metadata["flow_findings_index"] = list(merged.values())[-30:]

    def _count_unread_l2(self, state: AgentState) -> int:
        pending = list(state.metadata.get("pending_l2_reads") or [])
        return sum(1 for item in pending if not self._is_l2_path_already_read(state, item))

    def _pending_item_is_source_l2(self, state: AgentState, item: Dict[str, Any]) -> bool:
        kind = str(item.get("kind") or "").lower()
        if kind in ("config", "build", "header", "glob", "meta"):
            return False
        if kind == "source":
            return True
        path = str(item.get("path") or "")
        if not path:
            return False
        return self._infer_read_file_kind(state, path) == "source"

    def _unread_source_l2_blocking_targeted_scan(
        self,
        state: AgentState,
        vuln_types: Optional[List[str]] = None,
        flow_ids: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """定向扫仅在同 flow 的 source 型 L2 未读时拦截。"""
        vuln_set = {str(v).lower() for v in (vuln_types or []) if v}
        flow_set = {str(f) for f in (flow_ids or []) if f}
        blocking: List[Dict[str, Any]] = []
        for item in list(state.metadata.get("pending_l2_reads") or []):
            if not self._pending_item_is_source_l2(state, item):
                continue
            if self._is_l2_path_already_read(state, item):
                continue
            flow_id = str(item.get("flow_id") or "")
            if not flow_id:
                continue
            vuln_type = str(item.get("vuln_type") or "").lower()
            if not vuln_type and "-flow-" in flow_id:
                vuln_type = flow_id.rsplit("-flow-", 1)[0].lower()
            if flow_set and flow_id not in flow_set:
                continue
            if vuln_set and vuln_type and vuln_type not in vuln_set:
                flow_prefix = (
                    flow_id.rsplit("-flow-", 1)[0].lower() if "-flow-" in flow_id else ""
                )
                if flow_prefix not in vuln_set:
                    continue
            blocking.append(item)
        return blocking

    def _merge_report_into_state(self, state: AgentState, report_text: str) -> str:
        if not (report_text or "").strip():
            return state.last_report or ""
        findings = list(state.metadata.get("flow_findings_index") or [])
        merged = merge_scan_reports(
            state.last_report or "",
            report_text,
            flow_findings_index=findings,
        )
        state.update_report(merged)
        return merged

    def _incremental_scan_available(self, state: AgentState) -> bool:
        scan_count = int(state.metadata.get("source_scan_count", 0))
        max_scan = int(os.environ.get("PLANNER_MAX_SOURCE_SCAN", "2"))
        return (
            bool(state.ambiguous_flows)
            and self._count_unread_l2(state) == 0
            and scan_count < max_scan
        )

    def _inject_logic_scan_cached_findings(
        self, state: AgentState, args: Dict[str, Any],
    ) -> None:
        """注入 cached_findings 到 run_logic_scan 参数，防止重跑时 LLM 缓存失效。

        Planner 多次注入 run_logic_scan 时（finish 被拦、空转熔断等），
        若不传 cached_findings，scanner 会走非增量路径，指纹一旦漂移就
        全部 miss，导致 100+ 次冗余 LLM 调用。
        """
        if "cached_findings" in args:
            return
        cached = state.metadata.get("last_logic_findings")
        if cached:
            args["cached_findings"] = cached
        cached_qr = state.metadata.get("last_logic_query_results")
        if cached_qr and "cached_query_results" not in args:
            args["cached_query_results"] = cached_qr
        # 透传 Recon 侦查结果，避免增量重试时重跑侦查
        cached_recon = state.metadata.get("last_recon_results")
        if cached_recon and "recon_results" not in args:
            args["recon_results"] = cached_recon

    def _build_forced_incremental_scan_action(
        self, state: AgentState, *, reason_prefix: str = ""
    ) -> Dict[str, Any]:
        prefix = f"{reason_prefix}：" if reason_prefix else ""
        if self._is_logic_only_audit(state):
            args = dict(state.metadata.get("last_logic_scan_args") or {})
            args.setdefault("language", state.language or "java")
            if state.project_path:
                args.setdefault("source_root", state.project_path)
            if state.local_source_path:
                args.setdefault("local_source_path", state.local_source_path)
            self._inject_logic_scan_cached_findings(state, args)
            return {
                "done": False,
                "plan_summary": (
                    f"{prefix}logic_only 模式，注入 run_logic_scan 复核（不跑污点扫描）。"
                ),
                "next_action": {
                    "tool_name": "JoernTool.run_logic_scan",
                    "arguments": args,
                },
                "final_answer": "",
            }
        return {
            "done": False,
            "plan_summary": (
                f"{prefix}仍有 {len(state.ambiguous_flows)} 条模糊 flow 且 L2 已读完，"
                "注入增量源码扫描。"
            ),
            "next_action": {
                "tool_name": "JoernTool.run_source_scan",
                "arguments": {},
            },
            "final_answer": "",
        }

    def _build_forced_l2_read_action(
        self, state: AgentState,
    ) -> Optional[Dict[str, Any]]:
        pending = list(state.metadata.get("pending_l2_reads") or [])
        unread = [item for item in pending if not self._is_l2_path_already_read(state, item)]
        if not unread:
            return None

        # 跳过无法经索引解析的路径（LLM 猜错路径、丢掉点号等）
        skipped = 0
        while unread:
            target = unread[0]
            expand_action = self._build_expand_flow_action(state, target)
            if expand_action:
                break
            raw_path = target.get("path")
            if target.get("is_glob"):
                break
            if not raw_path:
                unread.pop(0)
                skipped += 1
                continue
            resolved_meta = self._resolve_planner_read_path(state, str(raw_path))
            if not resolved_meta:
                logger.warning(
                    "pending_l2_reads 索引拒绝: %s (flow=%s)",
                    raw_path,
                    target.get("flow_id"),
                )
                self._mark_l2_path_as_read(state, str(raw_path))
                unread.pop(0)
                skipped += 1
                continue
            rel_path = resolved_meta["path"]
            # 防止 basename fallback 将请求静默重定向到不同子目录的同名文件
            # （如 challenges/WebGoatLabels.properties → authbypass/WebGoatLabels.properties）
            raw_norm = str(raw_path).replace("\\", "/").rstrip("/")
            rel_norm = str(rel_path).replace("\\", "/").rstrip("/")
            raw_base = raw_norm.rsplit("/", 1)[-1].lower()
            rel_base = rel_norm.rsplit("/", 1)[-1].lower()
            if raw_base != rel_base:
                logger.warning(
                    "pending_l2_reads 索引将路径重定向到不同文件: %s → %s (flow=%s)，跳过",
                    raw_path,
                    rel_path,
                    target.get("flow_id"),
                )
                self._mark_l2_path_as_read(state, str(raw_path))
                unread.pop(0)
                skipped += 1
                continue
            # 使用 pathlib 拼接保证 Windows/Linux 均生成正确分隔符的绝对路径
            abs_path = rel_path
            if not os.path.isabs(rel_path) and state.local_source_path:
                abs_path = str(Path(state.local_source_path) / rel_path)
            if not os.path.isfile(abs_path):
                logger.warning(
                    "pending_l2_reads 索引已解析但磁盘不存在: %s -> %s (flow=%s)",
                    raw_path,
                    abs_path,
                    target.get("flow_id"),
                )
                self._mark_l2_path_as_read(state, rel_path)
                unread.pop(0)
                skipped += 1
                continue
            target = dict(target)
            target["path"] = rel_path
            unread[0] = target
            break

        if not unread:
            if skipped:
                logger.info(
                    "pending_l2_reads 中 %s 个路径无法解析或不存在，已全部跳过",
                    skipped,
                )
            return None

        target = unread[0]
        expand_action = self._build_expand_flow_action(state, target)
        if expand_action:
            return {
                "done": False,
                "plan_summary": (
                    f"flow {target.get('flow_id')} 须先 Joern 扩展，"
                    "再允许读取源文件定点行段"
                ),
                "next_action": expand_action,
                "final_answer": "",
            }
        path = target.get("path")
        if path and not os.path.isabs(path) and state.local_source_path:
            path = str(Path(state.local_source_path) / path)
        if target.get("is_glob"):
            return {
                "done": False,
                "plan_summary": (
                    f"优先 glob 未读 L2 `{path}` (flow={target.get('flow_id')})"
                ),
                "next_action": {
                    "tool_name": "FileTool.glob_files",
                    "arguments": {"pattern": path, "limit": 20},
                },
                "final_answer": "",
            }
        # 透传 start_line / end_line，避免 read_file 请求缺失行范围导致
        # 重复读取空转（stall key 因 end_line=None 而不匹配、无法触发熔断）
        read_args: Dict[str, Any] = {"path": path}
        if target.get("start_line"):
            read_args["start_line"] = target["start_line"]
        if target.get("end_line"):
            read_args["end_line"] = target["end_line"]
        return {
            "done": False,
            "plan_summary": (
                f"优先读取未读 L2 `{path}` (flow={target.get('flow_id')})"
            ),
            "next_action": {
                "tool_name": "FileTool.read_file",
                "arguments": read_args,
            },
            "final_answer": "",
        }

    def _flow_refutation_verdict(self, state: AgentState, flow_id: str) -> str:
        for item in state.metadata.get("flow_findings_index") or []:
            if str(item.get("flow_id")) == flow_id:
                return str(item.get("refutation_verdict") or "").lower()
        for item in state.ambiguous_flows or []:
            if str(item.get("flow_id")) == flow_id:
                meta = item.get("meta") or {}
                ref = meta.get("refutation") or {}
                if ref.get("verdict"):
                    return str(ref.get("verdict")).lower()
                return str(item.get("refutation_verdict") or "").lower()
        for item in state.metadata.get("pending_l2_reads") or []:
            if str(item.get("flow_id")) == flow_id:
                return str(item.get("refutation_verdict") or "").lower()
        return ""

    def _inconclusive_flow_ids(self, state: AgentState) -> List[str]:
        ids: List[str] = []
        seen: Set[str] = set()
        # 跳过证据不可达的 flow（所需源码在项目中不存在）
        unreachable = set(
            str(fid) for fid in (state.metadata.get("evidence_unreachable_flow_ids") or [])
        )
        for item in state.metadata.get("flow_findings_index") or []:
            flow_id = str(item.get("flow_id") or "")
            if not flow_id or flow_id in seen or flow_id in unreachable:
                continue
            if str(item.get("refutation_verdict") or "").lower() == "inconclusive":
                seen.add(flow_id)
                ids.append(flow_id)
        for item in state.ambiguous_flows or []:
            flow_id = str(item.get("flow_id") or "")
            if not flow_id or flow_id in seen or flow_id in unreachable:
                continue
            verdict = str(item.get("refutation_verdict") or "").lower()
            if not verdict:
                verdict = self._flow_refutation_verdict(state, flow_id)
            if verdict in ("inconclusive", "needs_dynamic_test"):
                seen.add(flow_id)
                ids.append(flow_id)
        return ids

    def _flow_needs_closure_step(self, state: AgentState, flow_id: str) -> bool:
        if self._flow_re_refute_attempts(state, flow_id) >= PLANNER_FLOW_RE_REFUTE_MAX:
            return False
        verdict = self._flow_refutation_verdict(state, flow_id)
        if verdict not in ("inconclusive", "needs_dynamic_test"):
            return False
        if self._flow_needs_joern_expand_before_source_read(state, flow_id):
            allowed, _ = self._joern_expand_allows_source_read(state, flow_id)
            if not allowed:
                return True
        for item in state.metadata.get("pending_l2_reads") or []:
            if str(item.get("flow_id")) == flow_id and not self._is_l2_path_already_read(
                state, item
            ):
                return True
        expand_rec = (state.metadata.get("flow_joern_expansion") or {}).get(flow_id)
        if expand_rec and expand_rec.get("called"):
            return True
        return False

    def _has_inconclusive_closure_work(self, state: AgentState) -> bool:
        if self._count_unread_l2(state) > 0 and self._inconclusive_flow_ids(state):
            return True
        return any(
            self._flow_needs_closure_step(state, flow_id)
            for flow_id in self._inconclusive_flow_ids(state)
        )

    def _inconclusive_closure_blocks_skill(self, state: AgentState) -> bool:
        return self._has_inconclusive_closure_work(state)

    def _flow_closure_bucket(self, state: AgentState) -> Dict[str, Dict[str, Any]]:
        bucket = dict(state.metadata.get("flow_closure") or {})
        state.metadata["flow_closure"] = bucket
        return bucket

    def _flow_re_refute_attempts(self, state: AgentState, flow_id: str) -> int:
        rec = self._flow_closure_bucket(state).get(flow_id) or {}
        return int(rec.get("re_refute_attempts") or 0)

    def _record_flow_re_refute_attempt(self, state: AgentState, flow_id: str) -> None:
        bucket = self._flow_closure_bucket(state)
        rec = dict(bucket.get(flow_id) or {})
        rec["re_refute_attempts"] = int(rec.get("re_refute_attempts") or 0) + 1
        bucket[flow_id] = rec

    def _append_pending_l2_raw_entries(
        self, state: AgentState, entries: List[Dict[str, Any]]
    ) -> None:
        if not entries:
            return
        raw = list(state.metadata.get("pending_l2_reads_raw") or [])
        raw.extend(entries)
        state.metadata["pending_l2_reads_raw"] = raw
        state.metadata["pending_l2_reads"] = aggregate_pending_l2_reads(
            raw,
            language=state.language,
            local_source_path=state.local_source_path,
            already_read_paths=self._collect_read_path_keys(state),
        )

    def _enqueue_expand_followup_reads(
        self,
        state: AgentState,
        *,
        flow_id: str,
        record: Dict[str, Any],
        expand_result: Dict[str, Any],
    ) -> None:
        verdict = self._flow_refutation_verdict(state, flow_id)
        if verdict not in ("inconclusive", "needs_dynamic_test"):
            return
        vuln_type = record.get("vuln_type") or "unknown"
        sink_label = record.get("sink_label") or ""
        refutation_result = {
            "verdict": verdict or "inconclusive",
            "refutation_summary": "",
            "blocking_factors": [],
            "residual_risk": "",
            "evidence_levels": {"L2_static_files": "partial"},
            "missing_L2_reads": [],
        }
        meta = record.get("meta") or {}
        ref = meta.get("refutation") or {}
        if ref:
            refutation_result["verdict"] = ref.get("verdict") or refutation_result["verdict"]
        paths = collect_refutation_l2_read_suggestions(
            flow_id=flow_id,
            vuln_type=vuln_type,
            refutation_result=refutation_result,
            sink_label=sink_label,
            language=normalize_scan_language(state.language or "cpp"),
            local_source_path=state.local_source_path,
            metadata=state.metadata,
        )
        if not paths:
            return
        loc = {}
        try:
            from flow_merge import parse_sink_location

            loc = parse_sink_location(sink_label)
        except Exception:
            loc = {}
        sink_line = None
        if loc.get("line"):
            try:
                sink_line = int(loc["line"])
            except ValueError:
                sink_line = None
        entries = [
            build_pending_l2_entry(
                path=str(raw),
                flow_id=flow_id,
                vuln_type=vuln_type,
                refutation_verdict=refutation_result.get("verdict"),
                l2_status="partial",
                sink_line=sink_line,
                source="expand_followup",
            )
            for raw in paths
        ]
        self._append_pending_l2_raw_entries(state, entries)

    def _pick_next_closure_flow_id(self, state: AgentState) -> Optional[str]:
        pending_unread: Dict[str, int] = {}
        for item in state.metadata.get("pending_l2_reads") or []:
            flow_id = str(item.get("flow_id") or "")
            if not flow_id or self._is_l2_path_already_read(state, item):
                continue
            pending_unread[flow_id] = pending_unread.get(flow_id, 0) + 1

        def score(flow_id: str) -> tuple:
            needs_expand = 0
            if self._flow_needs_joern_expand_before_source_read(state, flow_id):
                allowed, _ = self._joern_expand_allows_source_read(state, flow_id)
                needs_expand = 0 if allowed else 1
            unread = pending_unread.get(flow_id, 0)
            attempts = self._flow_re_refute_attempts(state, flow_id)
            return (-needs_expand, -unread, attempts, flow_id)

        candidates = self._inconclusive_flow_ids(state)
        if not candidates:
            candidates = list(pending_unread.keys())
        if not candidates:
            return None
        ranked = sorted(candidates, key=score)
        for flow_id in ranked:
            if self._flow_re_refute_attempts(state, flow_id) >= PLANNER_FLOW_RE_REFUTE_MAX:
                continue
            return flow_id
        return ranked[0] if ranked else None

    def _build_flow_l2_read_action(
        self, state: AgentState, flow_id: str
    ) -> Optional[Dict[str, Any]]:
        pending = [
            item
            for item in state.metadata.get("pending_l2_reads") or []
            if str(item.get("flow_id")) == flow_id
            and not self._is_l2_path_already_read(state, item)
        ]
        if not pending:
            return None
        target = pending[0]
        expand_action = self._build_expand_flow_action(state, target)
        if expand_action:
            return {
                "done": False,
                "plan_summary": (
                    f"flow `{flow_id}` 须先 Joern 扩展，再读 L2 `{target.get('path')}`"
                ),
                "next_action": expand_action,
                "final_answer": "",
            }
        path = target.get("path")
        if path and not os.path.isabs(path) and state.local_source_path:
            path = str(Path(state.local_source_path) / path)
        read_args: Dict[str, Any] = {"path": path, "flow_id": flow_id}
        kind = str(target.get("kind") or infer_l2_kind(str(target.get("path") or "")))
        sl, el = resolve_l2_pending_line_range(
            kind=kind,
            path=str(target.get("path") or ""),
            start_line=target.get("start_line"),
            end_line=target.get("end_line"),
        )
        if sl and el:
            read_args["start_line"] = sl
            read_args["end_line"] = el
        return {
            "done": False,
            "plan_summary": f"flow `{flow_id}` 补读 L2 `{target.get('path')}`",
            "next_action": {
                "tool_name": "FileTool.read_file",
                "arguments": read_args,
            },
            "final_answer": "",
        }

    def _build_single_flow_re_refute_action(
        self, state: AgentState, flow_id: str
    ) -> Optional[Dict[str, Any]]:
        record = self._lookup_flow_record(state, flow_id) or {}
        if not record.get("flow_text"):
            for item in state.ambiguous_flows or []:
                if str(item.get("flow_id")) == flow_id:
                    record = dict(item)
                    break
        if not record.get("flow_text"):
            return None
        focus = [
            {
                "vuln_type": record.get("vuln_type"),
                "flow_id": flow_id,
                "sink_label": record.get("sink_label", ""),
                "flow_text": record.get("flow_text", ""),
                "previous_verdict": record.get("previous_verdict", ""),
            }
        ]
        return {
            "done": False,
            "plan_summary": (
                f"flow `{flow_id}` 已完成 expand+L2，注入单 flow 重反证"
                f"（{self._flow_re_refute_attempts(state, flow_id) + 1}/{PLANNER_FLOW_RE_REFUTE_MAX}）"
            ),
            "next_action": {
                "tool_name": "JoernTool.run_source_scan",
                "arguments": {
                    "focus_flows": focus,
                    "re_refute_only": True,
                    "max_iters": state.max_iters,
                },
            },
            "final_answer": "",
        }

    def _forced_inconclusive_flow_closure(
        self, state: AgentState
    ) -> Optional[Dict[str, Any]]:
        if not self._has_inconclusive_closure_work(state):
            return None
        flow_id = self._pick_next_closure_flow_id(state)
        if not flow_id:
            return None

        if self._flow_needs_joern_expand_before_source_read(state, flow_id):
            allowed, _ = self._joern_expand_allows_source_read(state, flow_id)
            if not allowed:
                record = self._lookup_flow_record(state, flow_id) or {"flow_id": flow_id}
                expand_action = self._build_expand_flow_action(state, record) or {
                    "tool_name": "JoernTool.expand_flow_context",
                    "arguments": {
                        "flow_id": flow_id,
                        "vuln_type": record.get("vuln_type") or "unknown",
                        "max_extra_iters": PLANNER_FLOW_EXPAND_MAX_ITERS,
                    },
                }
                return {
                    "done": False,
                    "plan_summary": f"inconclusive 闭环：先扩展 flow `{flow_id}` 的 Joern 上下文",
                    "next_action": expand_action,
                    "final_answer": "",
                }

        read_action = self._build_flow_l2_read_action(state, flow_id)
        if read_action:
            read_action["plan_summary"] = "inconclusive 闭环：" + read_action["plan_summary"]
            return read_action

        if self._flow_re_refute_attempts(state, flow_id) < PLANNER_FLOW_RE_REFUTE_MAX:
            action = self._build_single_flow_re_refute_action(state, flow_id)
            if action:
                action["plan_summary"] = "inconclusive 闭环：" + action["plan_summary"]
                return action
        return None

    def _dup_read_stall_key(self, path: str, start_line: int, end_line: int) -> str:
        return f"{self._normalize_evidence_path(path)}:{start_line}-{end_line}"

    def _record_duplicate_read_stall(
        self, state: AgentState, path: str, start_line: int, end_line: int
    ) -> int:
        key = self._dup_read_stall_key(path, start_line, end_line)
        stalls = dict(state.metadata.get("duplicate_read_stalls") or {})
        stalls[key] = int(stalls.get(key, 0)) + 1
        state.metadata["duplicate_read_stalls"] = stalls
        return stalls[key]

    def _is_duplicate_read_stalled(self, state: AgentState) -> bool:
        stalls = state.metadata.get("duplicate_read_stalls") or {}
        return any(
            int(count) >= PLANNER_DUP_READ_STALL_THRESHOLD for count in stalls.values()
        )

    def _record_blocked_scan_attempt(self, state: AgentState, effective_tool: str) -> None:
        if effective_tool not in (
            "JoernTool.run_targeted_scan",
            "JoernTool.run_source_scan",
            "JoernTool.run_taint_queries",
        ):
            return
        state.metadata["blocked_scan_attempts"] = (
            int(state.metadata.get("blocked_scan_attempts", 0)) + 1
        )

    def _get_active_incomplete_skill_id(self, state: AgentState) -> Optional[str]:
        for skill_id, runtime in (state.metadata.get("skill_runtime") or {}).items():
            if not runtime.get("done"):
                return str(skill_id)
        return None

    def _planner_hijacked_active_skill(self, state: AgentState) -> bool:
        """Skill 已启动但 Planner 抢线；inconclusive 闭环或 L2 必读阶段不抢。"""
        if self._inconclusive_closure_blocks_skill(state):
            return False
        skill_id = self._get_active_incomplete_skill_id(state)
        if not skill_id:
            return False
        if self._count_unread_l2(state) > 0:
            return False
        runtime = self.skill_engine.get_runtime(state, skill_id)
        if len(runtime.get("history") or []) < 1:
            return False
        if not state.plan_history:
            return False
        last_action = state.plan_history[-1].get("action") or {}
        if last_action.get("tool_name") == "Skill.run":
            return False
        if self._incremental_scan_available(state):
            return (
                self._is_duplicate_read_stalled(state)
                or int(state.metadata.get("blocked_scan_attempts", 0))
                >= PLANNER_BLOCKED_SCAN_FORCE_AFTER
            )
        return True

    def _detect_planner_read_spin(self, state: AgentState) -> bool:
        """连续多轮 read_file 且 L2 已读完 → 判定空转。

        不依赖 _incremental_scan_available：空转检测与恢复动作应解耦，
        即使无法增量扫描也应检测空转并强制 finish。
        """
        if self._count_unread_l2(state) > 0:
            return False
        recent = list(state.plan_history)[-3:]
        if len(recent) < 3:
            return False
        return all(
            (item.get("action") or {}).get("tool_name") == "FileTool.read_file"
            for item in recent
        )

    # 通用工具级空转检测：连续 3 次调用相同工具 + 相同参数
    # （覆盖 glob_files / grep_code / 任何非 read_file 工具的循环）
    _ACTION_SPIN_WINDOW = 3

    @staticmethod
    def _action_signature(action: Optional[Dict[str, Any]]) -> Optional[str]:
        """返回动作的工具名+关键参数签名，用于相同性比较。"""
        if not action:
            return None
        tool = action.get("tool_name") or ""
        if not tool:
            return None
        args = action.get("arguments") or {}
        # 仅取字符串/数字参数作为签名（忽略动态字段）
        sig_parts = []
        for k in sorted(args.keys()):
            v = args[k]
            if isinstance(v, (str, int, float, bool)):
                sig_parts.append(f"{k}={v}")
        return f"{tool}|{'|'.join(sig_parts)}"

    def _detect_planner_action_spin(self, state: AgentState) -> bool:
        """连续 N 次相同工具+参数 → 通用空转（不含 read_file，由 _detect_planner_read_spin 处理）。"""
        recent = list(state.plan_history)[-self._ACTION_SPIN_WINDOW:]
        if len(recent) < self._ACTION_SPIN_WINDOW:
            return False
        sigs = [self._action_signature(item.get("action")) for item in recent]
        # 排除 None 签名（空动作）
        if any(s is None for s in sigs):
            return False
        # 全部签名相同
        if len(set(sigs)) != 1:
            return False
        # read_file 循环由 _detect_planner_read_spin 单独处理
        tool_name = (recent[0].get("action") or {}).get("tool_name", "")
        if tool_name == "FileTool.read_file":
            return False
        return True

    def _redirect_blocked_to_incremental_scan(
        self,
        state: AgentState,
        blocked: Dict[str, Any],
        *,
        display_tool_name: str,
        skill_id: Optional[str] = None,
        advance_skill_on_block: bool = False,
        resolved_action: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        reason = (blocked.get("result") or {}).get("reason")
        if reason != "needs_incremental_scan":
            return None
        if not self._incremental_scan_available(state):
            return None
        if self._is_logic_only_audit(state):
            return None
        effective = str(
            (resolved_action or {}).get("tool_name") or display_tool_name
        )
        self._record_blocked_scan_attempt(state, effective)
        runtime_meta = (resolved_action or {}).get("_skill_runtime") or {}
        if advance_skill_on_block and runtime_meta.get("skill_id") and runtime_meta.get("node_id"):
            self.skill_engine.advance_runtime(
                state=state,
                skill_id=runtime_meta["skill_id"],
                node_id=runtime_meta["node_id"],
                action_result={"ok": False, **blocked},
                rewrite_meta=(resolved_action or {}).get("_rewrite_candidate"),
            )
        scan_result = self._execute_action(
            state,
            {"tool_name": "JoernTool.run_source_scan", "arguments": {}},
        )
        scan_result["tool_name"] = display_tool_name
        prefix = (
            f"Skill 节点 {effective} 需增量扫描，已自动执行"
            if skill_id
            else f"{display_tool_name} 被门禁拒绝，已自动改为增量扫描"
        )
        scan_result["result_summary"] = (
            f"{prefix}：{scan_result.get('result_summary', '')}"
        )
        if skill_id:
            scan_result["result"] = {
                "skill_id": skill_id,
                "resolved_action": resolved_action,
                "skill_runtime": state.metadata.get("skill_runtime", {}).get(skill_id),
                "redirected_from_block": True,
                "nested_result": scan_result.get("result", {}),
            }
        return scan_result

    def _forced_skill_continuation(self, state: AgentState) -> Optional[Dict[str, Any]]:
        if self._inconclusive_closure_blocks_skill(state):
            return None
        skill_id = self._get_active_incomplete_skill_id(state)
        if not skill_id:
            return None
        runtime = self.skill_engine.get_runtime(state, skill_id)
        skill = self.skill_engine.skill_defs.get(skill_id)
        if not skill:
            return None
        current_node = runtime.get("current_node_id") or skill.start_node_id
        resolved = self.skill_engine.expand_skill_action(
            {"tool_name": "Skill.run", "arguments": {"skill_id": skill_id}},
            state=state,
        )
        effective = str(resolved.get("tool_name") or "")
        resolved_args = resolved.get("arguments") or {}
        if effective == "JoernTool.run_targeted_scan":
            blocked = self._check_planner_action_gate(
                state, effective, action_arguments=resolved_args
            )
            if blocked:
                if self._incremental_scan_available(state):
                    return self._build_forced_incremental_scan_action(
                        state,
                        reason_prefix=(
                            f"Skill `{skill_id}` 节点 `{current_node}` 需先增量扫描"
                        ),
                    )
                return None
        elif effective in PLANNER_SKILL_BLOCKED_WHEN_CLOSURE_TOOLS:
            if self._incremental_scan_available(state):
                return self._build_forced_incremental_scan_action(
                    state, reason_prefix=f"Skill `{skill_id}` 节点 `{current_node}` 需先增量扫描"
                )
            blocked = self._check_planner_action_gate(
                state,
                effective,
                action_arguments=resolved_args,
            )
            if blocked:
                return None
        return {
            "done": False,
            "plan_summary": (
                f"Skill `{skill_id}` DAG 未完成（节点 `{current_node}`），"
                "禁止 Planner 抢线，强制继续 Skill.run"
            ),
            "next_action": {
                "tool_name": "Skill.run",
                "arguments": {"skill_id": skill_id},
            },
            "final_answer": "",
        }

    def _forced_action_on_planner_stall(self, state: AgentState) -> Optional[Dict[str, Any]]:
        blocked_scans = int(state.metadata.get("blocked_scan_attempts", 0))
        stalled = self._is_duplicate_read_stalled(state)
        if not stalled and blocked_scans < PLANNER_BLOCKED_SCAN_FORCE_AFTER:
            return None

        l2_action = self._build_forced_l2_read_action(state)
        if l2_action:
            l2_action["plan_summary"] = (
                "空转熔断：" + l2_action["plan_summary"]
            )
            return l2_action

        if self._incremental_scan_available(state):
            return self._build_forced_incremental_scan_action(
                state, reason_prefix="空转熔断"
            )

        scan_count = int(state.metadata.get("source_scan_count", 0))
        max_scan = int(os.environ.get("PLANNER_MAX_SOURCE_SCAN", "2"))
        if scan_count >= max_scan:
            return {
                "done": True,
                "plan_summary": (
                    "重复读取/定向扫描被拒且扫描已达上限，结束并生成终态报告。"
                ),
                "next_action": {"tool_name": "finish", "arguments": {}},
                "final_answer": "",
            }
        # 空转熔断触发但无可用强制动作 → 强制 finish
        if stalled:
            return {
                "done": True,
                "plan_summary": "重复读取空转且无可用强制动作，强制结束。",
                "next_action": {"tool_name": "finish", "arguments": {}},
                "final_answer": "",
            }
        return None

    def _needs_l2_closure_work(self, state: AgentState) -> bool:
        if state.ambiguous_flows:
            return True
        if self._count_unread_l2(state) > 0:
            return True
        return bool(self._inconclusive_flow_ids(state))

    def _check_planner_action_gate(
        self,
        state: AgentState,
        effective_tool_name: str,
        action_arguments: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """模糊 flow 或未读 L2 期间，限制会抢步数的扫描类动作。"""
        if not effective_tool_name:
            return None

        logic_only_block = self._check_logic_only_action_gate(
            state, effective_tool_name, action_arguments,
        )
        if logic_only_block:
            return logic_only_block

        unread_l2 = self._count_unread_l2(state)
        has_ambiguous = bool(state.ambiguous_flows)
        has_inconclusive = bool(self._inconclusive_flow_ids(state))
        if not has_ambiguous and unread_l2 == 0 and not has_inconclusive:
            return None

        if effective_tool_name == "Skill.run":
            if self._inconclusive_closure_blocks_skill(state):
                return {
                    "ok": False,
                    "tool_name": effective_tool_name,
                    "result_summary": (
                        "已拒绝 Skill.run：仍有 inconclusive flow 待闭环"
                        "（expand → 读 L2 → 重反证），请先完成主线补证。"
                    ),
                    "result": {"blocked": True, "reason": "inconclusive_closure_pending"},
                }

        if effective_tool_name == "JoernTool.run_taint_queries":
            return {
                "ok": False,
                "tool_name": effective_tool_name,
                "result_summary": (
                    "已拒绝 run_taint_queries：当前有未收敛 flow 或未读 L2。"
                    "请优先 pending_l2_reads、expand_flow_context 或 run_source_scan。"
                ),
                "result": {"blocked": True, "reason": "l2_closure_pending"},
            }

        if effective_tool_name == "JoernTool.run_targeted_scan":
            args = action_arguments or {}
            blocking = self._unread_source_l2_blocking_targeted_scan(
                state,
                list(args.get("vuln_types") or []),
                list(args.get("flow_ids") or []),
            )
            if blocking:
                flow_hint = ", ".join(
                    str(item.get("flow_id") or "?") for item in blocking[:3]
                )
                return {
                    "ok": False,
                    "tool_name": effective_tool_name,
                    "result_summary": (
                        f"已拒绝 {effective_tool_name}：flow {flow_hint} "
                        "仍有未读 source 型 L2，请先精读对应源文件行段。"
                    ),
                    "result": {
                        "blocked": True,
                        "reason": "unread_source_l2_pending",
                        "blocking_flows": [
                            str(item.get("flow_id")) for item in blocking[:10]
                        ],
                    },
                }
            return None

        if effective_tool_name in (
            "JoernTool.run_source_scan",
            "GraphBuilder.run_source_scan",
        ):
            if unread_l2 > 0:
                return {
                    "ok": False,
                    "tool_name": effective_tool_name,
                    "result_summary": (
                        f"已拒绝 {effective_tool_name}：仍有未读 L2，"
                        "请先读完 pending_l2_reads。"
                    ),
                    "result": {"blocked": True, "reason": "unread_l2_pending"},
                }
            if has_ambiguous and self._incremental_scan_available(state):
                return None
            if has_ambiguous:
                return {
                    "ok": False,
                    "tool_name": effective_tool_name,
                    "result_summary": (
                        f"已拒绝 {effective_tool_name}：模糊 flow 仍存在且扫描次数已达上限。"
                    ),
                    "result": {"blocked": True, "reason": "scan_limit_reached"},
                }
            return None

        if effective_tool_name in PLANNER_SKILL_BLOCKED_WHEN_CLOSURE_TOOLS:
            if unread_l2 > 0:
                reason = "unread_l2_pending"
                summary = (
                    f"已拒绝 {effective_tool_name}：仍有未读 L2，"
                    "请先按 pending_l2_reads 补齐。"
                )
            elif has_ambiguous and self._incremental_scan_available(state):
                reason = "needs_incremental_scan"
                summary = (
                    f"已拒绝 {effective_tool_name}：模糊 flow 且 L2 已读完，"
                    "请先执行 JoernTool.run_source_scan 增量扫描。"
                )
            else:
                reason = "l2_closure_pending"
                summary = (
                    f"已拒绝 {effective_tool_name}：请先按 ambiguous_flows / "
                    "pending_l2_reads 补齐 L2，再执行定向或全量扫描。"
                )
            return {
                "ok": False,
                "tool_name": effective_tool_name,
                "result_summary": summary,
                "result": {
                    "blocked": True,
                    "reason": reason,
                    "suggested_tool": (
                        "JoernTool.run_source_scan"
                        if reason == "needs_incremental_scan"
                        else None
                    ),
                },
            }
        return None

    def _ingest_scan_result_into_state(
        self,
        state: AgentState,
        scan_result: Dict[str, Any],
        *,
        merge_ambiguous: bool = True,
    ) -> None:
        flows_payload = scan_result.get("flows", {}) or {}
        state.update_flows(flows_payload)
        state.metadata["joern_hit_vuln_types"] = self._joern_hit_vuln_types_from_flows(
            flows_payload
        )
        report_text = scan_result.get("report", "") or ""
        if report_text:
            self._merge_report_into_state(state, report_text)
        self._sync_pending_l2_reads(state, scan_result)
        findings = scan_result.get("flow_findings_index") or []
        if findings:
            self._merge_flow_findings_index(state, findings)
        # 跟踪证据不可达的 flow（所需源码在项目中不存在）
        unreachable = scan_result.get("evidence_unreachable_flow_ids") or []
        if unreachable:
            existing = set(state.metadata.get("evidence_unreachable_flow_ids") or [])
            existing.update(str(fid) for fid in unreachable)
            state.metadata["evidence_unreachable_flow_ids"] = list(existing)
            logger.info(
                "标记 %d 条 flow 为证据不可达：%s",
                len(unreachable), ", ".join(str(fid) for fid in unreachable[:5]),
            )
        l1_ranges = scan_result.get("l1_covered_ranges") or []
        if l1_ranges:
            merged = list(state.metadata.get("l1_covered_ranges") or [])
            merged.extend(l1_ranges)
            state.metadata["l1_covered_ranges"] = merged[-200:]
        if not merge_ambiguous:
            return
        new_ambiguous = scan_result.get("ambiguous_flows", [])
        if new_ambiguous:
            state.set_ambiguous_flows(new_ambiguous)
            self._reconcile_ambiguous_state(state)
            state.set_previous_scan_conclusions((state.last_report or "")[:2000])
        else:
            state.clear_ambiguous_flows()

    def _prepare_scanner_planner_context(self, state: AgentState) -> str:
        bundle = build_planner_l2_context_bundle(state.metadata)
        self.graph.joern.set_planner_l2_context(bundle)
        self.graph.joern.set_planner_state_metadata(state.metadata)
        return bundle

    def _discover_java_security_config_paths(self, state: AgentState) -> List[str]:
        """在本地源码索引中查找 Security 配置（通用 glob，非项目硬编码）。"""
        file_index = self._get_file_index(state)
        if not file_index:
            return []
        found: List[str] = []
        for pattern in JAVA_SECURITY_CONFIG_GLOBS:
            for path in file_index.find_glob(pattern):
                if path not in found:
                    found.append(path)
                if len(found) >= 6:
                    return found
        return found

    def _ingest_logic_scan_followups(
        self, state: AgentState, scan_result: Dict[str, Any],
    ) -> None:
        """逻辑扫描后：记录 inconclusive、高命中 JWT/硬编码的 L2 补证队列。"""
        findings = list(scan_result.get("logic_findings") or [])
        inconclusive = list(scan_result.get("logic_inconclusive") or [])
        stats = dict(scan_result.get("logic_query_stats") or {})

        state.metadata["logic_inconclusive_findings"] = inconclusive
        state.metadata["logic_query_stats"] = stats

        file_index = self._get_file_index(state)
        language = normalize_scan_language(state.language or "java")
        entries: List[Dict[str, Any]] = []
        for finding in inconclusive:
            flow_id = f"logic_{finding.get('candidate_id', 'unknown')}"
            for raw_path in finding.get("suggested_l2_reads") or []:
                resolved = resolve_l2_path(
                    str(raw_path),
                    language=language,
                    file_index=file_index,
                    local_source_path=state.local_source_path,
                )
                if not resolved:
                    continue
                entries.append(build_pending_l2_entry(
                    path=resolved.path,
                    flow_id=flow_id,
                    vuln_type=str(finding.get("cwe") or "logic"),
                    refutation_verdict="inconclusive",
                    l2_status="absent",
                    source="logic_inconclusive",
                ))

        jwt_hits = max(0, int(stats.get("jwt_weakness") or 0)) + max(
            0, int(stats.get("jwt_endpoints") or 0),
        )
        hard_hits = max(0, int(stats.get("hardcoded_credentials_v2") or 0))
        jwt_confirmed = any(
            f.get("confirmed")
            and str(f.get("candidate_type") or "") in ("jwt_weakness", "jwt_endpoint")
            for f in findings
        )
        hard_confirmed = any(
            f.get("confirmed")
            and str(f.get("candidate_type") or "") == "hardcoded_cred"
            for f in findings
        )
        if (
            (jwt_hits >= HIGH_HIT_L2_THRESHOLD and not jwt_confirmed)
            or (hard_hits >= HIGH_HIT_L2_THRESHOLD and not hard_confirmed)
        ):
            for path in self._discover_java_security_config_paths(state):
                entries.append(build_pending_l2_entry(
                    path=path,
                    flow_id="logic_security_l2_boost",
                    vuln_type="logic_l2",
                    refutation_verdict="inconclusive",
                    l2_status="absent",
                    source="logic_high_hit_l2",
                ))

        if entries:
            self._append_pending_l2_raw_entries(state, entries)

    def _logic_l2_closure_blocker(self, state: AgentState) -> Optional[str]:
        inconclusive = list(state.metadata.get("logic_inconclusive_findings") or [])
        if not inconclusive:
            return None
        unread = self._count_unread_l2(state)
        if unread > 0:
            return (
                f"逻辑漏洞 {len(inconclusive)} 条 inconclusive，"
                f"须先 FileTool 读取 {unread} 个 Security/L2 配置文件"
            )
        if not state.metadata.get("logic_rerun_after_l2"):
            return "逻辑 inconclusive 已补 L2，须重跑 run_logic_scan 复核"
        return None

    def _logic_scan_finish_blocker(self, state: AgentState) -> Optional[str]:
        """逻辑漏洞扫描：核心 Joern 查询失败时不应直接 finish。"""
        if not int(state.metadata.get("logic_scan_count", 0)):
            return None
        failures = list(state.metadata.get("logic_query_failures") or [])
        if not failures:
            return None

        scan_count = int(state.metadata.get("logic_scan_count", 0))
        max_retries = int(os.environ.get("PLANNER_MAX_LOGIC_SCAN_RETRIES", "1"))
        if scan_count <= max_retries:
            return (
                f"逻辑漏洞 Joern 查询失败 ({', '.join(failures)})，"
                "交叉分析不完整，需重试 JoernTool.run_logic_scan"
            )

        if self._is_logic_only_audit(state):
            return None

        language = (state.language or "").lower()
        if language in ("java", "spring", "springboot"):
            if (
                not int(state.metadata.get("java_route_count", 0))
                and not state.metadata.get("logic_attack_surface_attempted")
            ):
                return (
                    "逻辑审计不完整：需叠加 Java 攻击面审计"
                    "（Skill.run java_attack_surface 或 JavaAuditTool.scan_routes）"
                )
            playbooks = state.metadata.get("java_audit_playbooks") or {}
            if (
                "java-auth-audit" not in playbooks
                and not state.metadata.get("logic_playbook_stack_attempted")
            ):
                return "逻辑审计不完整：需加载 java-auth-audit playbook 完成 HTTP 面鉴权审计"
        return None

    def _build_forced_logic_followup_action(self, state: AgentState) -> Optional[Dict[str, Any]]:
        """logic_query_failures 存在时，finish 被拦后的确定性补救动作。"""
        blocker = self._logic_scan_finish_blocker(state)
        if not blocker:
            blocker = self._logic_l2_closure_blocker(state)
        if not blocker:
            return None

        failures = list(state.metadata.get("logic_query_failures") or [])
        scan_count = int(state.metadata.get("logic_scan_count", 0))
        max_retries = int(os.environ.get("PLANNER_MAX_LOGIC_SCAN_RETRIES", "1"))

        if failures and scan_count <= max_retries:
            args = dict(state.metadata.get("last_logic_scan_args") or {})
            args.setdefault("language", state.language or "java")
            prev_max = int(args.get("max_candidates", 0))
            if prev_max < MAX_CANDIDATES_FLOOR:
                args["max_candidates"] = MAX_CANDIDATES_FLOOR
            if state.project_path and "source_root" not in args:
                args["source_root"] = state.project_path
            if state.local_source_path and "local_source_path" not in args:
                args["local_source_path"] = state.local_source_path
            # 增量重试：只重跑失败的查询，合并缓存结果
            cached_qr = state.metadata.get("last_logic_query_results")
            if cached_qr:
                args["incremental_query_names"] = failures
                args["cached_query_results"] = cached_qr
                cached_findings = state.metadata.get("last_logic_findings")
                if cached_findings:
                    args["cached_findings"] = cached_findings
                logger.info(
                    "增量重试: 只重跑 %d 个失败查询 %s（复用 %d 条 LLM 结论）",
                    len(failures),
                    failures,
                    len(cached_findings or []),
                )
            return {
                "done": False,
                "plan_summary": f"finish 被拦：{blocker}",
                "next_action": {
                    "tool_name": "JoernTool.run_logic_scan",
                    "arguments": args,
                },
                "final_answer": "",
            }

        l2_blocker = self._logic_l2_closure_blocker(state)
        if l2_blocker:
            if self._count_unread_l2(state) > 0:
                l2_action = self._build_forced_l2_read_action(state)
                if l2_action:
                    l2_action["plan_summary"] = f"finish 被拦：{l2_blocker}"
                    return l2_action
            if not state.metadata.get("logic_rerun_after_l2"):
                state.metadata["logic_rerun_after_l2"] = True
                args = dict(state.metadata.get("last_logic_scan_args") or {})
                args.setdefault("language", state.language or "java")
                if state.project_path:
                    args.setdefault("source_root", state.project_path)
                if state.local_source_path:
                    args.setdefault("local_source_path", state.local_source_path)
                self._inject_logic_scan_cached_findings(state, args)
                return {
                    "done": False,
                    "plan_summary": f"finish 被拦：{l2_blocker}",
                    "next_action": {
                        "tool_name": "JoernTool.run_logic_scan",
                        "arguments": args,
                    },
                    "final_answer": "",
                }

        language = (state.language or "").lower()
        if language in ("java", "spring", "springboot"):
            if (
                not int(state.metadata.get("java_route_count", 0))
                and not state.metadata.get("logic_attack_surface_attempted")
            ):
                state.metadata["logic_attack_surface_attempted"] = True
                return {
                    "done": False,
                    "plan_summary": f"finish 被拦：{blocker}",
                    "next_action": {
                        "tool_name": "Skill.run",
                        "arguments": {"skill_id": "java_attack_surface"},
                    },
                    "final_answer": "",
                }
            playbooks = state.metadata.get("java_audit_playbooks") or {}
            if (
                "java-auth-audit" not in playbooks
                and not state.metadata.get("logic_playbook_stack_attempted")
            ):
                state.metadata["logic_playbook_stack_attempted"] = True
                return {
                    "done": False,
                    "plan_summary": f"finish 被拦：{blocker}",
                    "next_action": {
                        "tool_name": "JavaAuditTool.load_playbook",
                        "arguments": {"playbook_id": "java-auth-audit"},
                    },
                    "final_answer": "",
                }
        return None

    def _prepare_finish_gate(self, state: AgentState) -> Dict[str, Any]:
        """finish 前统一：收口 ambiguous、检查门禁。"""
        reconcile_result = self._reconcile_ambiguous_state(state)
        allow_unresolved = self._can_finish_with_unresolved(state)
        blocker = self._report_fails_verdict_policy(
            state.last_report or "",
            ambiguous_flows_count=len(state.ambiguous_flows),
            allow_unresolved_finish=allow_unresolved,
        )
        if not blocker:
            blocker = self._logic_scan_finish_blocker(state)
        if not blocker:
            blocker = self._logic_l2_closure_blocker(state)
        return {
            "reconcile": reconcile_result,
            "allow_unresolved": allow_unresolved,
            "blocker": blocker,
        }

    def _finalize_run_answer(
        self,
        state: AgentState,
        planner_result: Dict[str, Any],
        plan_summary: str,
    ) -> str:
        """
        源码扫描任务终态一律走结构化 bounded 报告，禁止 Planner LLM 自由撰写漏洞结论。
        """
        if state.version_identification.get("ok") and state.last_report:
            return state.last_report
        if (
            int(state.metadata.get("source_scan_count", 0)) > 0
            or state.last_flows
            or state.metadata.get("flow_findings_index")
            or state.ambiguous_flows
            or state.metadata.get("needs_l3_flows")
        ):
            return self._build_bounded_final_answer(state)
        return planner_result.get("final_answer") or state.last_report or plan_summary

    def _build_flow_findings_summary(self, state: AgentState) -> str:
        findings = list(state.metadata.get("flow_findings_index") or [])[-12:]
        if not findings:
            return ""
        lines = ["| flow_id | vuln_type | 反证 | L2 | 终态 |", "|---|---|---|---|---|"]
        for item in findings:
            lines.append(
                f"| `{item.get('flow_id', '?')}` | {item.get('vuln_type', '?')} | "
                f"{item.get('refutation_verdict', '?')} | {item.get('l2_status', '?')} | "
                f"{item.get('final_verdict', '?')[:40]} |"
            )
        return "\n".join(lines)

    def _seed_context_from_user_request(self, state: AgentState, user_request: str) -> None:
        seeded = extract_paths_from_user_request(user_request or "")
        if seeded.get("local_source_path") and not state.local_source_path:
            state.set_local_source_path(seeded["local_source_path"])
        if seeded.get("project_path"):
            project_path = sanitize_joern_project_path(seeded["project_path"])
            if not state.project_path:
                state.set_project(
                    project_path,
                    local_source_path=state.local_source_path,
                )
        lowered = (user_request or "").lower()
        if "mbedtls" in lowered:
            state.metadata["project_hint"] = "mbedtls"
        if seeded.get("language"):
            state.language = normalize_scan_language(seeded["language"])
        elif not state.language or state.language == "cpp":
            if any(k in lowered for k in ("mbedtls", "ssl_tls", ".c 源码", "c 源码")):
                state.language = "c"
            elif "java" in lowered and "mbedtls" not in lowered:
                state.language = "java"
        state.language = normalize_scan_language(state.language or "cpp")
        if detect_logic_only_intent(user_request):
            state.metadata["audit_mode"] = LOGIC_ONLY_AUDIT_MODE
            logger.info("用户请求判定为 logic_only 审计模式，将禁止污点扫描类工具")

    def _is_logic_only_audit(self, state: AgentState) -> bool:
        return state.metadata.get("audit_mode") == LOGIC_ONLY_AUDIT_MODE

    def _check_logic_only_action_gate(
        self,
        state: AgentState,
        effective_tool_name: str,
        action_arguments: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """用户明确要求仅逻辑审计时，拒绝污点扫描与会拉起污点的 Skill。"""
        if not self._is_logic_only_audit(state):
            return None
        if effective_tool_name in TAINT_SCAN_TOOL_NAMES:
            return {
                "ok": False,
                "tool_name": effective_tool_name,
                "result_summary": (
                    f"已拒绝 {effective_tool_name}：当前为 logic_only 审计模式，"
                    "请使用 JoernTool.run_logic_scan、FileTool 读 L2 或 finish。"
                ),
                "result": {"blocked": True, "reason": "logic_only_mode"},
            }
        if effective_tool_name == "Skill.run":
            skill_id = str((action_arguments or {}).get("skill_id") or "")
            if skill_id in LOGIC_ONLY_BLOCKED_SKILL_IDS:
                return {
                    "ok": False,
                    "tool_name": effective_tool_name,
                    "result_summary": (
                        f"已拒绝 Skill.run({skill_id})：logic_only 模式不执行污点/全量源码流水线。"
                        "可用 logic_vuln_audit_pipeline 或 run_logic_scan。"
                    ),
                    "result": {
                        "blocked": True,
                        "reason": "logic_only_mode",
                        "skill_id": skill_id,
                    },
                }
        return None

    def _reconcile_ambiguous_state(self, state: AgentState) -> Dict[str, Any]:
        """L2 读完后同步 flow_findings 并尝试收口 ambiguous_flows。"""
        update_flow_findings_l2_status(
            state.metadata, local_source_path=state.local_source_path
        )
        result = reconcile_ambiguous_flows(
            state.ambiguous_flows,
            state.metadata,
            local_source_path=state.local_source_path,
        )
        if result.get("resolved"):
            notes = list(state.metadata.get("ambiguous_resolved_notes") or [])
            notes.extend(result["resolved"])
            state.metadata["ambiguous_resolved_notes"] = notes[-50:]
        state.set_ambiguous_flows(result.get("remaining") or [])
        needs_l3 = list(result.get("needs_l3") or [])
        if needs_l3:
            existing = {
                str(item.get("flow_id")): item
                for item in (state.metadata.get("needs_l3_flows") or [])
                if item.get("flow_id")
            }
            for item in needs_l3:
                flow_id = item.get("flow_id")
                if flow_id:
                    existing[str(flow_id)] = item
            state.metadata["needs_l3_flows"] = list(existing.values())[-30:]
        pending = list(state.metadata.get("pending_l2_reads") or [])
        state.metadata["pending_l2_reads"] = [
            item
            for item in pending
            if not self._is_l2_path_already_read(state, item)
        ]
        return result

    def _can_finish_with_unresolved(self, state: AgentState) -> bool:
        scan_count = int(state.metadata.get("source_scan_count", 0))
        max_scan = int(os.environ.get("PLANNER_MAX_SOURCE_SCAN", "2"))
        pending = list(state.metadata.get("pending_l2_reads") or [])
        unread = [item for item in pending if not self._is_l2_path_already_read(state, item)]
        return scan_count >= max_scan and not unread

    def _forced_action_after_finish_block(self, state: AgentState) -> Optional[Dict[str, Any]]:
        """finish 被拦下后，注入确定性下一步，避免 LLM 空转 done=true。"""
        logic_action = self._build_forced_logic_followup_action(state)
        if logic_action:
            return logic_action
        l2_action = self._build_forced_l2_read_action(state)
        if l2_action:
            l2_action["plan_summary"] = "finish 被拦：" + l2_action["plan_summary"]
            return l2_action
        if self._incremental_scan_available(state):
            return self._build_forced_incremental_scan_action(
                state, reason_prefix="finish 被拦"
            )
        return None

    def _build_bounded_final_answer(self, state: AgentState) -> str:
        max_scan = int(os.environ.get("PLANNER_MAX_SOURCE_SCAN", "2"))
        report = build_bounded_finish_report(
            last_report=state.last_report or "",
            ambiguous_flows=state.ambiguous_flows,
            source_scan_count=int(state.metadata.get("source_scan_count", 0)),
            max_scan=max_scan,
            resolved_notes=list(state.metadata.get("ambiguous_resolved_notes") or []),
            needs_l3_flows=list(state.metadata.get("needs_l3_flows") or []),
            flow_findings_index=list(state.metadata.get("flow_findings_index") or []),
        )
        state.update_report(report)
        return report

    def _get_known_file_total_lines(
        self, state: AgentState, path_norm: str
    ) -> Optional[int]:
        for entry in reversed(list(state.metadata.get("file_evidence_content") or [])):
            if self._normalize_evidence_path(entry.get("path", "")) != path_norm:
                continue
            total = entry.get("total_lines")
            if isinstance(total, int) and total > 0:
                return total
        return None

    def _file_read_past_eof_result(
        self,
        *,
        tool_name: str,
        file_path: str,
        resolved_path: str,
        req_start: int,
        req_end: int,
        total_lines: int,
    ) -> Dict[str, Any]:
        return {
            "ok": True,
            "tool_name": tool_name,
            "result_summary": (
                f"跳过读取 {file_path}：文件共 {total_lines} 行，"
                f"请求 L{req_start}-L{req_end} 已超过末尾（此前已读完全文）"
            ),
            "result": {
                "ok": True,
                "path": resolved_path,
                "start_line": req_start,
                "end_line": total_lines,
                "total_lines": total_lines,
                "content": "",
                "skipped_past_eof": True,
            },
        }

    def _maybe_expand_whole_file_read(
        self,
        state: AgentState,
        path_norm: str,
        req_start: Optional[int],
        req_end: Optional[int],
        total_lines: Optional[int],
    ) -> tuple:
        """同文件多次分段读后，自动扩为整文件读取，减少重叠浪费。"""
        if not isinstance(total_lines, int) or total_lines <= 0:
            return req_start, req_end
        if total_lines > FILE_WHOLE_FILE_LINE_THRESHOLD:
            return req_start, req_end
        reads = list(state.metadata.get("file_evidence_reads") or [])
        same_file_reads = [
            entry
            for entry in reads
            if self._normalize_evidence_path(entry.get("path", "")) == path_norm
        ]
        kind = "source"
        for pending in state.metadata.get("pending_l2_reads") or []:
            if self._normalize_evidence_path(
                str(pending.get("path", ""))
            ) == path_norm and pending.get("kind"):
                kind = str(pending.get("kind"))
                break
        if should_skip_whole_file_read(
            kind=kind,
            total_lines=total_lines,
            threshold=FILE_SOURCE_WHOLE_FILE_MAX_LINES,
        ):
            return req_start, req_end
        if len(same_file_reads) >= 2 and isinstance(req_start, int) and isinstance(req_end, int):
            if req_end - req_start + 1 < total_lines * 0.85:
                return 1, total_lines
        return req_start, req_end

    def _build_planner_json_fallback(self, state: AgentState) -> Dict[str, Any]:
        scan_count = int(state.metadata.get("source_scan_count", 0))
        max_scan = int(os.environ.get("PLANNER_MAX_SOURCE_SCAN", "2"))
        pending = list(state.metadata.get("pending_l2_reads") or [])
        unread = [item for item in pending if not self._is_l2_path_already_read(state, item)]

        if scan_count >= max_scan:
            return {
                "done": True,
                "plan_summary": (
                    f"规划 JSON 解析失败；源码扫描已达上限 {max_scan}，结束任务。"
                    f"剩余模糊 flow: {len(state.ambiguous_flows)}。"
                ),
                "next_action": {"tool_name": "finish", "arguments": {}},
                "final_answer": "",
            }

        if unread:
            target = unread[0]
            expand_action = self._build_expand_flow_action(state, target)
            if expand_action:
                return {
                    "done": False,
                    "plan_summary": (
                        f"规划 JSON 失败：flow {target.get('flow_id')} 须先 Joern 扩展"
                    ),
                    "next_action": expand_action,
                    "final_answer": "",
                }
            path = target.get("path")
            if target.get("is_glob"):
                action = {
                    "tool_name": "FileTool.glob_files",
                    "arguments": {"pattern": path, "limit": 20},
                }
                summary = f"规划 JSON 失败，按反证 L2 必读清单 glob: {path}"
            else:
                action = {
                    "tool_name": "FileTool.read_file",
                    "arguments": {"path": path},
                }
                summary = (
                    f"规划 JSON 失败，按反证 L2 必读清单读取: {path} "
                    f"(flow={target.get('flow_id')})"
                )
            return {
                "done": False,
                "plan_summary": summary,
                "next_action": action,
                "final_answer": "",
            }

        if state.ambiguous_flows and scan_count < max_scan:
            return {
                "done": False,
                "plan_summary": (
                    f"规划 JSON 解析失败；仍有 {len(state.ambiguous_flows)} 条模糊 flow，"
                    "触发增量源码扫描。"
                ),
                "next_action": {
                    "tool_name": "JoernTool.run_source_scan",
                    "arguments": {},
                },
                "final_answer": "",
            }

        return {
            "done": True,
            "plan_summary": "规划 JSON 解析失败；无待办 L2/模糊 flow，结束任务。",
            "next_action": {"tool_name": "finish", "arguments": {}},
            "final_answer": "",
        }

    def _build_file_evidence_read_previews(self, state: AgentState) -> List[Dict[str, Any]]:
        previews: List[Dict[str, Any]] = []
        for entry in list(state.metadata.get("file_evidence_content") or [])[-12:]:
            previews.append(
                {
                    "path": entry.get("path"),
                    "lines": f"{entry.get('start_line')}-{entry.get('end_line')}",
                    "total_lines": entry.get("total_lines"),
                    "preview": entry.get("content_preview", ""),
                }
            )
        return previews

    def _build_observation_preview(self, action_result: Dict[str, Any]) -> str:
        tool_name = action_result.get("tool_name") or ""
        result = action_result.get("result", {}) or {}
        limit = 1500
        if tool_name == "FileTool.read_file":
            limit = FILE_READ_OBSERVATION_PREVIEW_CHARS
            preview_payload = {
                "ok": result.get("ok"),
                "path": result.get("path"),
                "start_line": result.get("start_line"),
                "end_line": result.get("end_line"),
                "total_lines": result.get("total_lines"),
                "skipped_duplicate": result.get("skipped_duplicate"),
                "content": (result.get("content") or "")[:FILE_EVIDENCE_PREVIEW_CHARS],
            }
            return json.dumps(preview_payload, ensure_ascii=False, default=str)[:limit]
        return json.dumps(result, ensure_ascii=False, default=str)[:limit]

    def _resolve_final_answer(
        self,
        state: AgentState,
        planner_result: Dict[str, Any],
        fallback: str,
    ) -> str:
        """
        若已成功执行版本识别，最终回答必须以工具生成的 report_markdown 为准，
        避免 LLM 在 finish 阶段编造「唯一最佳版本」。
        """
        if state.version_identification.get("ok") and state.last_report:
            return state.last_report
        return planner_result.get("final_answer") or state.last_report or fallback

    def _report_fails_verdict_policy(
        self,
        report_text: str,
        *,
        ambiguous_flows_count: int = 0,
        allow_unresolved_finish: bool = False,
    ) -> Optional[str]:
        """
        检查已生成报告是否含禁止的模糊终态或「无 PoC 却声称可利用」。

        Returns:
            违规简述；None 表示可接受 finish。
        """
        if ambiguous_flows_count > 0 and not allow_unresolved_finish:
            return (
                f"仍有 {ambiguous_flows_count} 条 flow 结论未明确"
                "（见 state_snapshot.ambiguous_flows_count），需补证或重扫"
            )
        text = (report_text or "").strip()
        if not text:
            return None
        if re.search(
            r"是否真实漏洞\s*[：:]\s*(⚠️?\s*部分是|待确认)",
            text,
            flags=re.IGNORECASE,
        ):
            return "报告含「部分是/待确认」结构化终态，需补证或重扫"
        if re.search(r"不提供\s*exploit|本报告不提供", text, flags=re.IGNORECASE):
            return "报告拒绝提供 exploit/PoC"
        if re.search(
            r"是否真实漏洞\s*[：:]\s*✅\s*是",
            text,
            flags=re.IGNORECASE,
        ):
            if re.search(
                r"漏洞利用\s*[：:]\s*无",
                text,
                flags=re.IGNORECASE,
            ):
                # 若终态表已收敛（无“未证实”/“待定”/“待动态验证”），才拦截
                # 否则说明系统已判定为“未证实”，不算“判✅是但无利用”
                has_unresolved_terminal = bool(re.search(
                    r"\*\*(未证实|待定|待动态验证)\*\*", text
                ))
                if not has_unresolved_terminal:
                    return "判✅是但漏洞利用为无"
        return None

    def _version_result_summary(self, version_result: Dict[str, Any]) -> str:
        """根据 VersionTool 结构化结果生成简短 observation 摘要。"""
        if version_result.get("conclusion_type") == "unique":
            best = (version_result.get("best_matches") or [{}])[0]
            note = version_result.get("tie_break_note") or version_result.get("conclusion_summary", "")
            return (
                f"版本识别完成，结论=唯一匹配: {best.get('version', '?')} "
                f"(confidence={best.get('confidence', '?')})；{note}"
            )
        groups = version_result.get("indistinguishable_groups") or []
        if groups and len(groups[0]) > 1:
            scores = version_result.get("aggregate_scores") or {}
            score_text = ", ".join(f"{k}={scores.get(k)}" for k in groups[0])
            return (
                f"版本识别完成，结论=不可区分: {', '.join(groups[0])}"
                f"（{score_text or '同分'}）"
            )
        return version_result.get("conclusion_summary", "版本识别完成")

    def _maybe_auto_save_report(self, state: AgentState, report_text: str, subdir: str) -> Optional[str]:
        """扫描/可达分析完成后，可选将 Markdown 报告落盘。"""
        if not report_text or os.environ.get("AGENT_AUTO_SAVE_REPORT", "1") != "1":
            return None
        try:
            save_result = self.file_tool.write_report(report_text, state=state, subdir=subdir)
            saved_path = save_result.get("path")
            if saved_path:
                state.metadata["last_report_path"] = saved_path
            return saved_path
        except Exception as exc:
            logger.warning("自动保存报告失败: %s", exc)
            return None

    def _resolve_audit_log_path(self, state: AgentState) -> str:
        """
        决定当前运行的审计日志文件路径。

        优先级：
        1. `state.audit_log_path`
        2. `self.audit_log_path`
        3. 环境变量 `AGENT_AUDIT_LOG_PATH`
        4. 默认落到当前工作目录下的 `planner_audit_logs/`

        默认文件命名形式：
        - JSONL: `planner_audit_logs/planner_audit_YYYYMMDD_HHMMSS.jsonl`
        - Markdown: 与 JSONL 同名，仅扩展名改为 `.md`
        - HTML: 与 JSONL 同名，仅扩展名改为 `.html`
        """
        configured_path = (
            state.audit_log_path
            or self.audit_log_path
            or os.environ.get("AGENT_AUDIT_LOG_PATH")
        )
        if configured_path:
            return configured_path

        logs_directory = os.path.join(os.getcwd(), "planner_audit_logs")
        timestamp_text = datetime.now().strftime("%Y%m%d_%H%M%S")
        return os.path.join(logs_directory, f"planner_audit_{timestamp_text}.jsonl")

    def _append_audit_event(self, state: AgentState, event: Dict[str, Any]):
        """
        把一条 planner 审计事件追加写入 JSONL 文件。

        Args:
            state: 当前会话状态。
            event: 事件字典，会自动补充 run_id / timestamp。
        """
        audit_log_path = self._resolve_audit_log_path(state)
        state.set_audit_log_path(audit_log_path)

        audit_directory = os.path.dirname(audit_log_path)
        if audit_directory:
            os.makedirs(audit_directory, exist_ok=True)

        event_record = {
            "timestamp": datetime.now().isoformat(),
            "run_id": state.current_plan_run_id,
            **event,
        }
        with open(audit_log_path, "a", encoding="utf-8") as audit_file:
            audit_file.write(json.dumps(event_record, ensure_ascii=False, default=str) + "\n")

    @staticmethod
    def _joern_hit_vuln_types_from_flows(flows: Dict[str, Any]) -> List[str]:
        """从 last_flows 提取有实质内容的 Joern 命中类型名。"""
        if not flows:
            return []
        hit_types: List[str] = []
        for name, text in flows.items():
            if not name:
                continue
            snippet = (text if isinstance(text, str) else str(text or "")).strip()
            if not snippet:
                continue
            lowered = snippet.lower()
            if "no flows" in lowered or "not found" in lowered:
                continue
            if len(snippet) < 20 and "error" in lowered:
                continue
            hit_types.append(str(name))
        return hit_types

    @staticmethod
    def _list_available_source_files(local_source_path: Optional[str], max_files: int = 80) -> List[str]:
        """
        扫描 local_source_path 下的关键源码/配置文件，返回相对路径列表。
        仅返回常见后缀，避免输出过多噪声。
        """
        if not local_source_path or not os.path.isdir(local_source_path):
            return []
        interesting_exts = {
            # C/C++
            ".c", ".h", ".cpp", ".hpp", ".cc", ".hh",
            # Java
            ".java",
            # Python
            ".py", ".pyi",
            # 通用配置
            ".xml", ".yml", ".yaml", ".json",
            ".conf", ".cfg", ".ini", ".gradle", ".properties", ".toml",
        }
        interesting_names = {
            "makefile", "cmakelists.txt", "dockerfile", "pom.xml",
            "build.gradle", "readme.md",
        }
        result: List[str] = []
        base = Path(local_source_path)
        try:
            for root, dirs, files in os.walk(base):
                # 跳过常见无用目录
                dirs[:] = [d for d in dirs if d.lower() not in (
                    ".git", "node_modules", "__pycache__", ".idea", "venv", ".vscode",
                )]
                for fname in files:
                    fpath = Path(root) / fname
                    rel = str(fpath.relative_to(base)).replace("\\", "/")
                    if fname.lower() in interesting_names:
                        result.append(rel)
                    elif fpath.suffix.lower() in interesting_exts:
                        result.append(rel)
                    if len(result) >= max_files:
                        return result
        except OSError:
            pass
        return result

    def _build_state_snapshot(self, state: AgentState) -> Dict[str, Any]:
        """
        构造适合审计和 planner prompt 复用的状态快照。
        """
        joern_hit_vuln_types = self._joern_hit_vuln_types_from_flows(state.last_flows)
        available_files = list(state.metadata.get("available_source_files") or [])
        if not available_files:
            available_files = self._list_available_source_files(state.local_source_path)
        language = normalize_scan_language(state.language or "cpp")
        return {
            "project_path": state.project_path,
            "local_source_path": state.local_source_path,
            "available_source_files": available_files,
            "l2_playbook_hint": get_l2_playbook_hint(language),
            "project_file_index_summary": {
                "truncated": (state.metadata.get("project_file_index") or {}).get(
                    "truncated"
                ),
                "total_discovered": (state.metadata.get("project_file_index") or {}).get(
                    "total_discovered"
                ),
            },
            "project_name": state.project_name,
            "current_cve_id": state.current_cve_id,
            "language": state.language,
            "variant": state.variant,
            "max_iters": state.max_iters,
            "audit_log_path": state.audit_log_path,
            "joern_hit_vuln_types": joern_hit_vuln_types,
            "file_evidence_reads": list(state.metadata.get("file_evidence_reads") or [])[-20:],
            "file_read_failures": list(state.metadata.get("file_read_failures") or [])[-30:],
                        "glob_failures": list(state.metadata.get("glob_failures") or [])[-15:],
            "file_evidence_read_previews": self._build_file_evidence_read_previews(state),
            "pending_l2_reads": list(state.metadata.get("pending_l2_reads") or [])[:12],
            "flow_joern_expansion": {
                k: {
                    "called": v.get("called"),
                    "exhausted": v.get("exhausted"),
                    "sufficient": v.get("sufficient"),
                    "iterations_used": v.get("iterations_used"),
                }
                for k, v in (state.metadata.get("flow_joern_expansion") or {}).items()
            },
            "flow_findings_summary": self._build_flow_findings_summary(state),
            # 三层证据定义见 evidence_levels.py（L1/L2/L3 是证据深度，不是召回率 Recall）
            "evidence_goals": EVIDENCE_GOALS_ONE_LINER,
            "evidence_level_specs": [
                {
                    "id": s["id"],
                    "name": s["name"],
                    "question": s["question"],
                }
                for s in EVIDENCE_LEVEL_SPECS
            ],
            "last_report_preview": (state.last_report or "")[:1000],
            "last_report_flow_table": self._build_flow_findings_summary(state),
            "last_reachability_context_preview": json.dumps(
                state.last_reachability_context,
                ensure_ascii=False,
                default=str,
            )[:1000],
            "version_identification_preview": json.dumps(
                {
                    "best_matches": (state.version_identification or {}).get("best_matches"),
                    "indistinguishable_groups": (state.version_identification or {}).get(
                        "indistinguishable_groups"
                    ),
                },
                ensure_ascii=False,
                default=str,
            )[:800],
            "identified_component_version": state.metadata.get("identified_component_version"),
            "active_skills": state.active_skills[-8:],
            "last_skill_execution": state.metadata.get("last_skill_execution"),
            "skill_runtime": state.metadata.get("skill_runtime", {}),
            "last_skill_rewrite": state.metadata.get("last_skill_rewrite"),
            "java_routes": {
                "route_count": (state.metadata.get("java_routes") or {}).get("route_count"),
                "by_http_method": (state.metadata.get("java_routes") or {}).get("by_http_method"),
            },
            "java_audit_active_playbook": state.metadata.get("java_audit_active_playbook"),
            "java_audit_playbooks_loaded": list((state.metadata.get("java_audit_playbooks") or {}).keys()),
            "java_route_count": state.metadata.get("java_route_count"),
            "logic_scan_count": state.metadata.get("logic_scan_count", 0),
            "logic_query_failures": list(state.metadata.get("logic_query_failures") or []),
            "source_scan_count": state.metadata.get("source_scan_count", 0),
            "ambiguous_flows_count": len(state.ambiguous_flows),
            "ambiguous_resolved_count": len(
                state.metadata.get("ambiguous_resolved_notes") or []
            ),
            "needs_l3_flows_count": len(state.metadata.get("needs_l3_flows") or []),
            "pending_l2_unread_count": self._count_unread_l2(state),
            "finish_blocked_count": int(state.metadata.get("finish_blocked_count", 0)),
        }

    def _extract_cve_id_from_text(self, text: str) -> Optional[str]:
        """
        从自然语言请求中提取 CVE 编号。
        """
        if not text:
            return None
        match = re.search(r"\bCVE-\d{4}-\d{4,7}\b", text, flags=re.IGNORECASE)
        if not match:
            return None
        return match.group(0).upper()

    def _build_replan_reason(
        self,
        previous_history_item: Optional[Dict[str, Any]],
        current_plan_summary: str,
    ) -> Dict[str, Any]:
        """
        根据上一轮 observation 与当前计划摘要，生成结构化 replan 原因。

        Returns:
            统一的原因字典，便于 JSONL、Markdown、HTML 都直接复用。
        """
        if not previous_history_item:
            return {
                "reason_type": "initial_plan",
                "reason_text": "首轮规划，无上一轮 observation。",
                "previous_step": None,
                "previous_tool_name": None,
                "previous_result_summary": None,
                "previous_observation_ok": None,
            }

        previous_observation = previous_history_item.get("observation", {}) or {}
        previous_tool_name = previous_observation.get("tool_name")
        previous_result_summary = previous_observation.get("result_summary")
        previous_observation_ok = previous_observation.get("ok")

        result_preview = str(previous_observation.get("result_preview", "") or "")
        if previous_observation_ok is False:
            reason_type = "previous_action_failed"
        elif previous_observation_ok is True:
            reason_type = "previous_action_succeeded"
        else:
            reason_type = "previous_action_unknown"

        if "No projects loaded" in result_preview:
            reason_type = "joern_project_not_loaded"
        elif "未知工具动作" in (previous_result_summary or ""):
            reason_type = "unsupported_tool_action"
        elif "CPG" in (previous_result_summary or "") and previous_observation_ok is False:
            reason_type = "cpg_not_ready"

        reason_text = (
            f"基于 step {previous_history_item.get('step')} 的 observation 触发重规划："
            f"上一步执行 `{previous_tool_name}`"
        )
        if previous_result_summary:
            reason_text += f"，结果「{previous_result_summary}」"
        reason_text += "。新计划内容见同 step 的 plan_generated 事件。"
        if current_plan_summary and not str(current_plan_summary).startswith("("):
            reason_text += f" 新计划摘要：{current_plan_summary}"

        return {
            "reason_type": reason_type,
            "reason_text": reason_text,
            "previous_step": previous_history_item.get("step"),
            "previous_plan_summary": previous_history_item.get("plan_summary"),
            "previous_tool_name": previous_tool_name,
            "previous_result_summary": previous_result_summary,
            "previous_observation_ok": previous_observation_ok,
        }

    def _resolve_stable_project_name(self, state: AgentState, arguments: Optional[Dict[str, Any]] = None) -> str:
        """
        解析本轮动作应使用的统一 project_name。

        目标：避免 planner 每轮生成不同 project_name，导致 Joern 工程上下文来回切换。
        优先级：
        1. state 里已有值（视为会话内已固定）
        2. 当前动作参数里的 project_name
        3. 环境变量 JOERN_PROJECT_NAME
        4. 默认值 VulnerableApp
        """
        action_arguments = arguments or {}
        return (
            state.project_name
            or action_arguments.get("project_name")
            or os.environ.get("JOERN_PROJECT_NAME")
            or "VulnerableApp"
        )

    def _build_planner_prompt(self, state: AgentState, user_request: str, user_template: str) -> str:
        # `plan_history` 会把“上轮计划 -> 动作 -> 观察”一起喂给模型，
        # 让模型具备最小记忆能力，避免每轮都从零开始猜。
        observation_text = json.dumps(state.plan_history, ensure_ascii=False, indent=2)
        # `state_snapshot` 只放关键字段，避免把大段报告全文塞进 prompt 造成浪费。
        state_snapshot_obj = self._build_state_snapshot(state)
        state_snapshot = json.dumps(state_snapshot_obj, ensure_ascii=False, indent=2)
        java_extra = ""
        if state_snapshot_obj.get("language") == "java" or "java" in (user_request or "").lower():
            java_extra = self.java_audit_tool.render_guidance_block(state_snapshot_obj)
        skill_guidance_block = self.skill_engine.render_skill_guidance(
            user_request=user_request,
            state_snapshot=state_snapshot_obj,
            extra_block=java_extra,
        )

        # --- 专家指导注入：从 active skills 当前节点提取 expert_guidance ---
        expert_guidance_lines = []
        skill_runtime_all = state.metadata.get("skill_runtime") or {}
        for sid, runtime in skill_runtime_all.items():
            if runtime.get("done"):
                continue
            eg = self.skill_engine.get_node_expert_guidance(state, sid)
            if not eg:
                continue
            expert_guidance_lines.append(f"\n### 专家分析方法论（来自技能 {sid}）")
            if eg.get("analysis_focus"):
                expert_guidance_lines.append(f"- **分析重点**：{eg['analysis_focus']}")
            if eg.get("required_evidence"):
                expert_guidance_lines.append(f"- **必须收集证据**：{', '.join(eg['required_evidence'])}")
            if eg.get("false_positive_patterns"):
                expert_guidance_lines.append(f"- **常见误报模式（排除后才可确认）**：{', '.join(eg['false_positive_patterns'])}")
            if eg.get("refutation_checklist"):
                expert_guidance_lines.append(f"- **反证检查清单**：{', '.join(eg['refutation_checklist'])}")
            if eg.get("expert_rules"):
                for rule in eg["expert_rules"]:
                    expert_guidance_lines.append(f"- **专家规则**：{rule}")
        if expert_guidance_lines:
            # 注入已读文件列表，避免 LLM 重复读取
            already_read = self._collect_read_path_keys(state)
            if already_read:
                read_basenames = sorted({
                    str(p).rsplit("/", 1)[-1] if "/" in str(p) else str(p)
                    for p in already_read
                })
                expert_guidance_lines.append(
                    f"- **\u5df2\u8bfb\u6587\u4ef6\uff08\u52ff\u91cd\u590d\u8bfb\u53d6\uff09**\uff1a"
                    f"{', '.join(read_basenames[:15])}"
                )
            skill_guidance_block += "\n" + "\n".join(expert_guidance_lines)

        return user_template.format(
            user_request=user_request,
            state_snapshot=state_snapshot,
            plan_history=observation_text,
            skill_guidance_block=skill_guidance_block,
        )

    def _maybe_preempt_planner_with_forced_action(
        self, state: AgentState
    ) -> Optional[Dict[str, Any]]:
        """跳过 LLM，注入 L2 读取、增量扫描、Skill 续跑或空转熔断。"""
        last_obs: Dict[str, Any] = {}
        if state.plan_history:
            last_obs = state.plan_history[-1].get("observation") or {}

        should_force_finish = (
            int(state.metadata.get("finish_blocked_count", 0)) > 0
            or last_obs.get("tool_name") == "finish_blocked"
        )
        if should_force_finish:
            forced = self._forced_action_after_finish_block(state)
            if forced:
                return forced

        stall_forced = self._forced_action_on_planner_stall(state)
        if stall_forced:
            return stall_forced

        closure_forced = self._forced_inconclusive_flow_closure(state)
        if closure_forced:
            return closure_forced

        if self._detect_planner_read_spin(state):
            if self._incremental_scan_available(state):
                return self._build_forced_incremental_scan_action(
                    state, reason_prefix="连续读文件空转"
                )
            # 无法增量扫描时，空转应直接强制 finish
            return {
                "done": True,
                "plan_summary": "连续读文件空转且无可用强制动作，强制结束。",
                "next_action": {"tool_name": "finish", "arguments": {}},
                "final_answer": "",
            }

        # 通用工具级空转：连续调用相同工具+参数（如 glob_files / grep_code）
        if self._detect_planner_action_spin(state):
            # 优先强制读取剩余 L2 待读项
            l2_action = self._build_forced_l2_read_action(state)
            if l2_action:
                l2_action["plan_summary"] = (
                    "工具空转熔断（重复调用相同工具）：" + l2_action["plan_summary"]
                )
                return l2_action
            if self._incremental_scan_available(state):
                return self._build_forced_incremental_scan_action(
                    state, reason_prefix="工具重复调用空转"
                )
            return {
                "done": True,
                "plan_summary": "工具重复调用空转且无可用强制动作，强制结束。",
                "next_action": {"tool_name": "finish", "arguments": {}},
                "final_answer": "",
            }

        if self._planner_hijacked_active_skill(state):
            skill_forced = self._forced_skill_continuation(state)
            if skill_forced:
                return skill_forced

        blocked_scans = int(state.metadata.get("blocked_scan_attempts", 0))
        if (
            self._incremental_scan_available(state)
            and blocked_scans >= PLANNER_BLOCKED_SCAN_FORCE_AFTER
        ):
            return self._build_forced_incremental_scan_action(
                state, reason_prefix="定向扫描被拒后"
            )

        return None

    def _plan_next_step(self, state: AgentState, user_request: str) -> Dict[str, Any]:
        preempted = self._maybe_preempt_planner_with_forced_action(state)
        if preempted:
            # 硬保护：如果 preempt 注入的 read_file 目标文件已读过，替换为 finish
            # 防止任何代码路径绕过 _is_l2_path_already_read 导致重复读取空转
            next_act = preempted.get("next_action") or {}
            if next_act.get("tool_name") == "FileTool.read_file":
                raw_path = str(next_act.get("arguments", {}).get("path") or "")
                if raw_path and self._is_path_already_read_raw(state, raw_path):
                    logger.warning(
                        "预empt 拦截：注入的 read_file %s 已读过，替换为 finish",
                        raw_path,
                    )
                    return {
                        "done": True,
                        "plan_summary": "预empt 注入的读取目标已读过，强制结束。",
                        "next_action": {"tool_name": "finish", "arguments": {}},
                        "final_answer": "",
                    }
            logger.info(
                "Planner 预empt：注入确定性动作 %s",
                (preempted.get("next_action") or {}).get("tool_name"),
            )
            return preempted

        system_prompt, user_template, variant_id = self.prompt_evolver.resolve_prompt_texts(
            prompts.planner_system_prompt,
            prompts.planner_user_prompt_template,
            run_id=state.current_plan_run_id or "",
        )
        state.metadata["prompt_variant_id"] = variant_id
        planner_prompt = self._build_planner_prompt(state, user_request, user_template=user_template)
        # 这里强制走 `complete_json`，目标是让 planner 输出稳定结构化结果，
        # 便于后续动作执行层做严格分支判断。
        planner_result = self.llm_client.complete_json(
            system_prompt=prompts.inject_tool_capabilities(
                system_prompt,
                TOOL_CAPABILITIES,
            ),
            user_prompt=planner_prompt,
            temperature=0.1,
            max_tokens=int(os.environ.get("PLANNER_MAX_TOKENS", "1800")),
            fallback=self._build_planner_json_fallback(state),
        )
        planner_result.setdefault("done", False)
        planner_result.setdefault("next_action", {"tool_name": "finish", "arguments": {}})
        if not planner_result.get("plan_summary"):
            planner_result["plan_summary"] = "规划结果缺少 plan_summary，使用默认动作。"
        # 把本轮技能匹配结果回写 state，供后续审计和提示词复用。
        state.set_active_skills(
            self.skill_engine.match_skills(
                user_request=user_request,
                state_snapshot=self._build_state_snapshot(state),
            )
        )
        return planner_result

    def _execute_action(self, state: AgentState, action: Dict[str, Any]) -> Dict[str, Any]:
        tool_name = action.get("tool_name", "")
        arguments = action.get("arguments", {}) or {}
        try:
            if tool_name == "Skill.run":
                resolved_action = self.skill_engine.expand_skill_action(action, state=state)
                if not resolved_action:
                    return {
                        "ok": False,
                        "tool_name": tool_name,
                        "result_summary": "Skill.run 解析失败：缺少可执行动作",
                        "result": {"action": action},
                    }
                blocked = self._check_planner_action_gate(
                    state,
                    str(resolved_action.get("tool_name") or ""),
                    action_arguments=resolved_action.get("arguments"),
                )
                if blocked:
                    effective = str(resolved_action.get("tool_name") or "")
                    redirected = self._redirect_blocked_to_incremental_scan(
                        state,
                        blocked,
                        display_tool_name=tool_name,
                        skill_id=(arguments or {}).get("skill_id"),
                        advance_skill_on_block=False,
                        resolved_action=resolved_action,
                    )
                    if redirected:
                        return redirected
                    self._record_blocked_scan_attempt(state, effective)
                    runtime_meta = resolved_action.get("_skill_runtime") or {}
                    skill_id = (arguments or {}).get("skill_id")
                    if runtime_meta.get("skill_id") and runtime_meta.get("node_id"):
                        self.skill_engine.advance_runtime(
                            state=state,
                            skill_id=runtime_meta["skill_id"],
                            node_id=runtime_meta["node_id"],
                            action_result={"ok": False, **blocked},
                            rewrite_meta=resolved_action.get("_rewrite_candidate"),
                        )
                    blocked["tool_name"] = tool_name
                    blocked["result_summary"] = (
                        f"Skill 暂不可用（{resolved_action.get('tool_name')}）："
                        + blocked["result_summary"].replace("已拒绝 ", "", 1)
                    )
                    blocked["result"] = {
                        **(blocked.get("result") or {}),
                        "resolved_tool_name": resolved_action.get("tool_name"),
                        "skill_runtime": (
                            state.metadata.get("skill_runtime", {}).get(skill_id)
                            if skill_id
                            else None
                        ),
                    }
                    return blocked
                skill_id = (arguments or {}).get("skill_id")
                state.metadata["last_skill_execution"] = {
                    "skill_id": skill_id,
                    "requested_action": action,
                    "resolved_action": resolved_action,
                }
                if resolved_action.get("tool_name") == "Skill.parallel":
                    parallel_actions = (resolved_action.get("arguments", {}) or {}).get("actions", []) or []
                    child_results = []
                    child_ok = True
                    for child_action in parallel_actions:
                        child_result = self._execute_action(state, child_action)
                        child_results.append(
                            {
                                "action": child_action,
                                "ok": child_result.get("ok"),
                                "result_summary": child_result.get("result_summary"),
                                "result": child_result.get("result", {}),
                            }
                        )
                        child_ok = child_ok and bool(child_result.get("ok"))
                    nested_result = {
                        "ok": child_ok,
                        "tool_name": "Skill.parallel",
                        "result_summary": f"并行节点执行完成，共 {len(child_results)} 个动作",
                        "result": {"children": child_results},
                    }
                else:
                    nested_result = self._execute_action(state, resolved_action)
                runtime_meta = resolved_action.get("_skill_runtime") or {}
                if runtime_meta.get("skill_id") and runtime_meta.get("node_id"):
                    self.skill_engine.advance_runtime(
                        state=state,
                        skill_id=runtime_meta["skill_id"],
                        node_id=runtime_meta["node_id"],
                        action_result=nested_result,
                        rewrite_meta=resolved_action.get("_rewrite_candidate"),
                    )
                nested_result["tool_name"] = tool_name
                nested_result["result_summary"] = (
                    f"技能 {skill_id or 'unknown'} 已执行，映射动作: "
                    f"{resolved_action.get('tool_name')}"
                )
                nested_result["result"] = {
                    "skill_id": skill_id,
                    "resolved_action": resolved_action,
                    "skill_runtime": state.metadata.get("skill_runtime", {}).get(skill_id) if skill_id else None,
                    "skill_collab_queue": state.metadata.get("skill_collab_queue", []),
                    "nested_result": nested_result.get("result", {}),
                }
                return nested_result

            if tool_name == "set_context":
                # set_context 只更新 state，不触发任何外部工具调用。
                # 这样 planner 可以先补齐参数，再进入真正的扫描/分析动作。
                resolved_project_name = self._resolve_stable_project_name(state, arguments)
                if arguments.get("project_path"):
                    sanitized_path = sanitize_joern_project_path(arguments["project_path"])
                    state.set_project(
                        sanitized_path,
                        project_name=resolved_project_name,
                        local_source_path=arguments.get("local_source_path"),
                    )
                elif arguments.get("local_source_path"):
                    state.set_local_source_path(arguments["local_source_path"])
                if not state.project_name:
                    state.project_name = resolved_project_name
                if arguments.get("cve_id"):
                    state.set_cve_id(arguments["cve_id"])
                if arguments.get("language"):
                    state.set_language(normalize_scan_language(arguments["language"]))
                if arguments.get("variant"):
                    state.set_variant(arguments["variant"])
                if arguments.get("max_iters") is not None:
                    state.set_max_iters(int(arguments["max_iters"]))
                self._rebuild_project_file_index(state)
                return {
                    "ok": True,
                    "tool_name": tool_name,
                    "result_summary": "运行上下文已更新",
                    "result": {
                        "project_path": state.project_path,
                        "local_source_path": state.local_source_path,
                        "project_name": state.project_name,
                        "current_cve_id": state.current_cve_id,
                        "language": state.language,
                        "variant": state.variant,
                        "max_iters": state.max_iters,
                    },
                }

            if tool_name == "JoernTool.ensure_cpg":
                project_path = arguments.get("source_root") or arguments.get("project_path") or state.project_path
                if not project_path:
                    return {
                        "ok": False,
                        "tool_name": tool_name,
                        "result_summary": "缺少源码路径，无法准备 CPG",
                        "result": {},
                    }

                project_name = self._resolve_stable_project_name(state, arguments)
                local_source_path = arguments.get("local_source_path", state.local_source_path)
                # ensure_cpg 之前先把上下文同步到 state，
                # 避免后续 planner 看到的状态与底层 Joern client 绑定的工程不一致。
                state.set_project(
                    project_path,
                    project_name=project_name,
                    local_source_path=local_source_path,
                )
                cpg_ready = self.graph.joern.ensure_cpg(
                    source_root=project_path,
                    project_name=project_name,
                    local_source_path=local_source_path,
                )
                if cpg_ready:
                    # CPG 加载成功后清空之前因 CPG 未就绪而累积的文件读取/glob 失败缓存
                    # （否则之前标记为“失败”的路径会被永久跳过）
                    old_read_failures = len(state.metadata.get("file_read_failures") or [])
                    old_glob_failures = len(state.metadata.get("glob_failures") or [])
                    if old_read_failures > 0 or old_glob_failures > 0:
                        state.metadata["file_read_failures"] = []
                        state.metadata["glob_failures"] = []
                        state.metadata["consecutive_glob_failures"] = 0
                        logger.info(
                            "CPG 就绪后清空失败缓存: %d 条 read 失败, %d 条 glob 失败",
                            old_read_failures, old_glob_failures,
                        )
                return {
                    "ok": cpg_ready,
                    "tool_name": tool_name,
                    "result_summary": "CPG 已就绪" if cpg_ready else "CPG 准备失败",
                    "result": {
                        "project_path": project_path,
                        "project_name": state.project_name,
                        "local_source_path": state.local_source_path,
                        "cpg_ready": cpg_ready,
                    },
                }

            if tool_name == "JoernTool.run_taint_queries":
                blocked = self._check_planner_action_gate(state, tool_name)
                if blocked:
                    return blocked
                project_path = arguments.get("source_root") or arguments.get("project_path") or state.project_path
                if not project_path:
                    return {
                        "ok": False,
                        "tool_name": tool_name,
                        "result_summary": "缺少源码路径，无法执行污点查询",
                        "result": {},
                    }

                project_name = self._resolve_stable_project_name(state, arguments)
                local_source_path = arguments.get("local_source_path", state.local_source_path)
                language = arguments.get("language", state.language)
                variant = arguments.get("variant", state.variant)
                state.set_project(
                    project_path,
                    project_name=project_name,
                    local_source_path=local_source_path,
                )
                cpg_ready = self.graph.joern.ensure_cpg(
                    source_root=project_path,
                    project_name=project_name,
                    local_source_path=local_source_path,
                )
                if not cpg_ready:
                    return {
                        "ok": False,
                        "tool_name": tool_name,
                        "result_summary": "CPG 未就绪，污点查询未执行",
                        "result": {},
                    }

                flows = self.graph.joern.run_taint_queries(
                    language=language,
                    variant=variant,
                )
                state.update_flows(flows)
                state.metadata["joern_hit_vuln_types"] = self._joern_hit_vuln_types_from_flows(
                    flows
                )
                return {
                    "ok": True,
                    "tool_name": tool_name,
                    "result_summary": "已完成污点查询",
                    "result": {"flows": flows},
                }

            if tool_name == "JoernTool.run_targeted_scan":
                blocked = self._check_planner_action_gate(
                    state, tool_name, action_arguments=arguments
                )
                if blocked:
                    redirected = self._redirect_blocked_to_incremental_scan(
                        state, blocked, display_tool_name=tool_name
                    )
                    if redirected:
                        return redirected
                    self._record_blocked_scan_attempt(state, tool_name)
                    return blocked
                project_path = arguments.get("source_root") or arguments.get("project_path") or state.project_path
                if not project_path:
                    return {
                        "ok": False,
                        "tool_name": tool_name,
                        "result_summary": "缺少源码路径，无法执行定向扫描",
                        "result": {},
                    }

                vuln_types = arguments.get("vuln_types") or []
                if not vuln_types:
                    return {
                        "ok": False,
                        "tool_name": tool_name,
                        "result_summary": "缺少 vuln_types 参数，定向扫描需要指定漏洞类型列表",
                        "result": {},
                    }

                project_name = self._resolve_stable_project_name(state, arguments)
                local_source_path = arguments.get("local_source_path", state.local_source_path)
                language = arguments.get("language", state.language)
                state.set_project(
                    project_path,
                    project_name=project_name,
                    local_source_path=local_source_path,
                )
                cpg_ready = self.graph.joern.ensure_cpg(
                    source_root=project_path,
                    project_name=project_name,
                    local_source_path=local_source_path,
                )
                if not cpg_ready:
                    return {
                        "ok": False,
                        "tool_name": tool_name,
                        "result_summary": "CPG 未就绪，定向扫描未执行",
                        "result": {},
                    }

                planner_l2_bundle = self._prepare_scanner_planner_context(state)
                scan_result = self.graph.joern.run_targeted_source_scan(
                    query_types=vuln_types,
                    source_root=project_path,
                    language=language,
                    variant=arguments.get("variant", state.variant),
                    max_iters=int(arguments.get("max_iters", state.max_iters)),
                    project_name=project_name,
                    local_source_path=local_source_path,
                    planner_l2_context=planner_l2_bundle,
                    planner_state_metadata=state.metadata,
                )
                if not scan_result.get("ok"):
                    return {
                        "ok": False,
                        "tool_name": tool_name,
                        "result_summary": "定向源码扫描失败",
                        "result": scan_result,
                    }

                self._ingest_scan_result_into_state(
                    state, scan_result, merge_ambiguous=False
                )
                new_ambiguous = scan_result.get("ambiguous_flows") or []
                if new_ambiguous:
                    existing = {
                        str(item.get("flow_id")): item
                        for item in (state.ambiguous_flows or [])
                        if item.get("flow_id")
                    }
                    for item in new_ambiguous:
                        flow_id = item.get("flow_id")
                        if flow_id:
                            existing[str(flow_id)] = item
                    state.set_ambiguous_flows(list(existing.values()))
                    self._reconcile_ambiguous_state(state)
                self._rebuild_project_file_index(state)
                hit_types = self._joern_hit_vuln_types_from_flows(scan_result.get("flows") or {})
                # targeted_scan 不自动落盘报告，统一在最终扫描/finish 时落盘
                return {
                    "ok": True,
                    "tool_name": tool_name,
                    "result_summary": (
                        f"定向源码扫描完成（含 LLM 分析），查询 {len(vuln_types)} 类，"
                        f"命中 {len(hit_types)} 类（报告延迟至终态保存）"
                    ),
                    "result": scan_result,
                }

            if tool_name == "JoernTool.run_logic_scan":
                project_path = arguments.get("source_root") or arguments.get("project_path") or state.project_path
                if not project_path:
                    return {
                        "ok": False,
                        "tool_name": tool_name,
                        "result_summary": "缺少源码路径，无法执行逻辑漏洞扫描",
                        "result": {},
                    }

                project_name = self._resolve_stable_project_name(state, arguments)
                local_source_path = arguments.get("local_source_path", state.local_source_path)
                language = arguments.get("language", state.language) or "java"
                # 强制使用默认全量 CWE 覆盖，忽略 LLM 手动传入的 cwe_focus
                # LLM 经常传入子集导致查询不全和检查点失效
                cwe_focus = resolve_cwe_focus(None)
                max_candidates = resolve_max_candidates(arguments.get("max_candidates"))

                state.set_project(
                    project_path,
                    project_name=project_name,
                    local_source_path=local_source_path,
                )
                cpg_ready = self.graph.joern.ensure_cpg(
                    source_root=project_path,
                    project_name=project_name,
                    local_source_path=local_source_path,
                )
                if not cpg_ready:
                    return {
                        "ok": False,
                        "tool_name": tool_name,
                        "result_summary": "CPG 未就绪，逻辑漏洞扫描未执行",
                        "result": {},
                    }

                self._prepare_scanner_planner_context(state)
                # 防止 Skill.run 展开的 run_logic_scan 缺少 cached_findings，
                # 导致 LLM 指纹漂移、100+ 次冗余 LLM 调用
                self._inject_logic_scan_cached_findings(state, arguments)

                scan_result = self.graph.run_logic_scan(
                    project_path=project_path,
                    local_source_path=local_source_path,
                    language=language,
                    cwe_focus=cwe_focus,
                    max_candidates=max_candidates,
                    project_name=project_name,
                    incremental_query_names=arguments.get("incremental_query_names"),
                    cached_query_results=arguments.get("cached_query_results"),
                    cached_findings=arguments.get("cached_findings"),
                )

                logic_failures = list(scan_result.get("logic_query_failures") or [])
                state.metadata["logic_scan_count"] = (
                    int(state.metadata.get("logic_scan_count", 0)) + 1
                )
                state.metadata["logic_query_failures"] = logic_failures
                state.metadata["last_logic_scan_args"] = {
                    "source_root": project_path,
                    "local_source_path": local_source_path,
                    "language": language,
                    "cwe_focus": cwe_focus,
                    "max_candidates": max_candidates,
                }
                # 保存查询结果与 LLM 结论缓存，供增量重试时合并
                qr = scan_result.get("logic_query_results")
                if qr:
                    state.metadata["last_logic_query_results"] = qr
                lf = scan_result.get("logic_findings")
                if lf:
                    state.metadata["last_logic_findings"] = lf
                # 保存 Recon 侦查结果，供增量重试时透传
                rr = scan_result.get("recon_results")
                if rr:
                    state.metadata["last_recon_results"] = rr

                ingest_error = None
                try:
                    self._ingest_logic_scan_followups(state, scan_result)
                except Exception as exc:
                    ingest_error = str(exc)
                    logger.warning(
                        "逻辑扫描后处理失败（扫描结果仍有效）: %s", exc, exc_info=True,
                    )

                # logic scan 报告不走 flow-based merge_scan_reports（结构不兼容），
                # 直接用最新报告替换旧报告
                report_text = scan_result.get("report", "") or ""
                if report_text:
                    state.update_report(report_text)
                    old_path = state.metadata.get("last_report_path")
                    if old_path and os.path.isfile(old_path):
                        try:
                            os.remove(old_path)
                        except OSError:
                            pass
                    report_path = self._maybe_auto_save_report(
                        state, report_text, subdir="logic_scan"
                    )
                    if report_path:
                        scan_result["saved_report_path"] = report_path

                # 合并 flow findings
                findings = scan_result.get("flow_findings_index") or []
                if findings:
                    existing = list(state.metadata.get("flow_findings_index") or [])
                    existing.extend(findings)
                    state.metadata["flow_findings_index"] = existing

                confirmed_count = len([
                    f for f in scan_result.get("logic_candidates", [])
                    if any(
                        ff.get("flow_id", "").endswith(f.get("candidate_id", ""))
                        for ff in findings
                    )
                ])

                result_summary = (
                    f"逻辑漏洞扫描完成，分析 {len(scan_result.get('logic_candidates', []))} 个候选，"
                    f"确认 {confirmed_count} 个漏洞"
                )
                if logic_failures:
                    result_summary += f"；查询失败: {', '.join(logic_failures)}"
                if ingest_error:
                    result_summary += f"；后处理告警: {ingest_error[:120]}"

                return {
                    "ok": bool(scan_result.get("ok")),
                    "tool_name": tool_name,
                    "result_summary": result_summary,
                    "result": scan_result,
                }

            if tool_name in ("JoernTool.expand_flow_context", "GraphBuilder.expand_flow_context"):
                flow_id = arguments.get("flow_id")
                if not flow_id:
                    return {
                        "ok": False,
                        "tool_name": tool_name,
                        "result_summary": "缺少 flow_id 参数",
                        "result": {},
                    }
                record = self._lookup_flow_record(state, str(flow_id)) or {}
                vuln_type = arguments.get("vuln_type") or record.get("vuln_type") or "unknown"
                flow_text = arguments.get("flow_text") or record.get("flow_text") or ""
                sink_label = arguments.get("sink_label") or record.get("sink_label") or ""

                # 逻辑扫描 flow 没有传统 flow_text，从存储的 finding 中构建上下文
                if not flow_text and str(flow_id).startswith("logic_"):
                    flow_text = self._build_logic_flow_context(state, str(flow_id))

                if not flow_text:
                    # 无法构建上下文，标记 exhausted 避免死循环
                    self._record_flow_joern_expansion(state, str(flow_id), {
                        "exhausted": True,
                        "sufficient": False,
                        "ok": False,
                        "iterations_used": 0,
                        "max_iters": arguments.get("max_extra_iters", PLANNER_FLOW_EXPAND_MAX_ITERS),
                        "context_preview": "",
                    })
                    return {
                        "ok": False,
                        "tool_name": tool_name,
                        "result_summary": f"flow {flow_id} 无 flow_text 且无法构建上下文（已标记 exhausted）",
                        "result": {"flow_id": flow_id, "error": "missing_flow_text", "exhausted": True},
                    }
                project_path = (
                    arguments.get("source_root")
                    or arguments.get("project_path")
                    or state.project_path
                )
                if not project_path:
                    return {
                        "ok": False,
                        "tool_name": tool_name,
                        "result_summary": "缺少源码路径，无法执行 Joern 扩展",
                        "result": {},
                    }
                prior = (state.metadata.get("flow_joern_expansion") or {}).get(flow_id) or {}
                expand_result = self.graph.expand_flow_context(
                    project_path=project_path,
                    flow_id=str(flow_id),
                    vuln_type=vuln_type,
                    flow_text=flow_text,
                    sink_label=sink_label,
                    language=arguments.get("language", state.language),
                    variant=arguments.get("variant", state.variant),
                    max_extra_iters=arguments.get("max_extra_iters", PLANNER_FLOW_EXPAND_MAX_ITERS),
                    project_name=self._resolve_stable_project_name(state, arguments),
                    local_source_path=arguments.get("local_source_path", state.local_source_path),
                    prior_context=prior.get("context_preview"),
                    method_name=arguments.get("method_name"),
                )
                self._record_flow_joern_expansion(state, str(flow_id), expand_result)
                self._enqueue_expand_followup_reads(
                    state,
                    flow_id=str(flow_id),
                    record=record,
                    expand_result=expand_result,
                )
                summary = expand_result.get("summary") or "Joern flow 扩展完成"
                return {
                    "ok": bool(expand_result.get("ok")),
                    "tool_name": tool_name,
                    "result_summary": summary,
                    "result": expand_result,
                }

            if tool_name in ("JoernTool.run_source_scan", "GraphBuilder.run_source_scan"):
                blocked = self._check_planner_action_gate(state, tool_name)
                if blocked:
                    self._record_blocked_scan_attempt(state, tool_name)
                    return blocked
                # 兼容 source_root 与 project_path 两种参数名，避免 planner 输出差异导致动作失败。
                project_path = arguments.get("source_root") or arguments.get("project_path") or state.project_path
                if not project_path:
                    return {
                        "ok": False,
                        "tool_name": tool_name,
                        "result_summary": "缺少源码路径，无法执行源码扫描",
                        "result": {},
                    }

                re_refute_only = bool(arguments.get("re_refute_only"))
                explicit_focus = arguments.get("focus_flows")

                if re_refute_only and explicit_focus:
                    scan_count = int(state.metadata.get("source_scan_count", 0))
                    focus_flows = explicit_focus
                    review_mode = True
                    previous_conclusions = (
                        arguments.get("previous_conclusions")
                        or state.previous_scan_conclusions
                    )
                    base_iters = int(arguments.get("max_iters", state.max_iters))
                    effective_iters = base_iters
                    for item in focus_flows:
                        flow_id = str(item.get("flow_id") or "")
                        if flow_id:
                            self._record_flow_re_refute_attempt(state, flow_id)
                    logger.info(
                        "单 flow 重反证：%s 条（不计入全量 scan 次数）",
                        len(focus_flows),
                    )
                else:
                    scan_count = state.metadata.get("source_scan_count", 0) + 1
                    state.metadata["source_scan_count"] = scan_count
                    max_scan = int(os.environ.get("PLANNER_MAX_SOURCE_SCAN", "2"))
                    if scan_count > max_scan:
                        logger.warning(
                            "source_scan 已执行 %s 次（上限 %s），强制结束",
                            scan_count, max_scan,
                        )
                        self._reconcile_ambiguous_state(state)
                        final_answer = self._build_bounded_final_answer(state)
                        # scan_limit 强制结束时也确保报告落盘
                        if state.last_report and not state.metadata.get("last_report_path"):
                            self._maybe_auto_save_report(state, state.last_report, subdir="source_scan")
                        state.finish_plan(final_answer)
                        self._append_audit_event(
                            state,
                            {
                                "event_type": "force_finished_scan_limit",
                                "scan_count": scan_count - 1,
                                "limit": max_scan,
                                "ambiguous_flows": len(state.ambiguous_flows),
                            },
                        )
                        return {
                            "ok": True,
                            "tool_name": "finish",
                            "force_finished": True,
                            "result_summary": f"扫描已达上限 {max_scan} 次，强制结束。剩余模糊 flow: {len(state.ambiguous_flows)} 条",
                            "result": {"force_finished": True, "scan_count": scan_count - 1},
                        }

                    base_iters = int(arguments.get("max_iters", state.max_iters))
                    effective_iters = base_iters * scan_count
                    if explicit_focus:
                        focus_flows = explicit_focus
                        review_mode = True
                        previous_conclusions = (
                            arguments.get("previous_conclusions")
                            or state.previous_scan_conclusions
                        )
                    else:
                        focus_flows = (
                            state.ambiguous_flows
                            if scan_count > 1 and state.ambiguous_flows
                            else None
                        )
                        review_mode = scan_count > 1 and bool(focus_flows)
                        previous_conclusions = (
                            state.previous_scan_conclusions if review_mode else None
                        )

                if review_mode and focus_flows:
                    logger.info(
                        "增量复核模式：只重新分析 %s 条 flow",
                        len(focus_flows),
                    )

                planner_l2_bundle = ""
                if focus_flows and len(focus_flows) == 1:
                    planner_l2_bundle = build_planner_l2_context_bundle(
                        state.metadata,
                        flow_id=str(focus_flows[0].get("flow_id") or ""),
                    )
                if not planner_l2_bundle:
                    planner_l2_bundle = build_planner_l2_context_bundle(state.metadata)
                self.graph.joern.set_planner_l2_context(planner_l2_bundle)
                self.graph.joern.set_planner_state_metadata(state.metadata)

                scan_result = self.graph.run_source_scan(
                    project_path=project_path,
                    local_source_path=arguments.get("local_source_path", state.local_source_path),
                    language=arguments.get("language", state.language),
                    variant=arguments.get("variant", state.variant),
                    max_iters=effective_iters,
                    project_name=self._resolve_stable_project_name(state, arguments),
                    focus_flows=focus_flows,
                    review_mode=review_mode,
                    previous_conclusions=previous_conclusions,
                    planner_l2_context=planner_l2_bundle,
                )
                # 扫描动作完成后，统一把结果写回 state，供下一轮 planner 复用。
                flows_payload = scan_result.get("flows", {}) or {}
                state.update_flows(flows_payload)
                state.metadata["joern_hit_vuln_types"] = self._joern_hit_vuln_types_from_flows(
                    flows_payload
                )
                report_text = scan_result.get("report", "") or ""
                merged_report = self._merge_report_into_state(state, report_text)
                self._sync_pending_l2_reads(state, scan_result)
                findings = scan_result.get("flow_findings_index") or []
                if findings:
                    self._merge_flow_findings_index(state, findings)
                # 跟踪证据不可达的 flow
                unreachable_ids = scan_result.get("evidence_unreachable_flow_ids") or []
                if unreachable_ids:
                    existing = set(state.metadata.get("evidence_unreachable_flow_ids") or [])
                    existing.update(str(fid) for fid in unreachable_ids)
                    state.metadata["evidence_unreachable_flow_ids"] = list(existing)
                self._rebuild_project_file_index(state)
                l1_ranges = scan_result.get("l1_covered_ranges") or []
                if l1_ranges:
                    merged = list(state.metadata.get("l1_covered_ranges") or [])
                    merged.extend(l1_ranges)
                    state.metadata["l1_covered_ranges"] = merged[-200:]

                # 保存本次扫描的模糊 flow，供下次增量扫描
                new_ambiguous = scan_result.get("ambiguous_flows", [])
                if new_ambiguous:
                    state.set_ambiguous_flows(new_ambiguous)
                    self._reconcile_ambiguous_state(state)
                    # 保存报告摘要作为下次复核的上下文
                    state.set_previous_scan_conclusions(report_text[:2000])
                    logger.info(
                        "本次扫描有 %s 条模糊 flow，已记录供下次增量复核",
                        len(new_ambiguous),
                    )
                else:
                    # 没有模糊 flow，清空记录
                    state.clear_ambiguous_flows()

                state.metadata["blocked_scan_attempts"] = 0
                # 只有正式扫描才清除空转计数器，re_refute_only 不清除
                if not re_refute_only:
                    state.metadata.pop("duplicate_read_stalls", None)

                # 仅在最终扫描时落盘报告：
                #   - re_refute_only 单 flow 重反证永远不落盘
                #   - 首次扫描始终保存（确保至少有一份基线报告）
                #   - 无模糊 flow 或已达扫描上限时保存
                max_scan = int(os.environ.get("PLANNER_MAX_SOURCE_SCAN", "2"))
                cur_scan = int(state.metadata.get("source_scan_count", 0))
                is_final_scan = (
                    not re_refute_only
                    and (
                        cur_scan <= 1
                        or not new_ambiguous
                        or cur_scan >= max_scan
                    )
                )
                report_path = None
                if is_final_scan:
                    report_path = self._maybe_auto_save_report(state, merged_report, subdir="source_scan")
                    if report_path:
                        scan_result["report_path"] = report_path
                return {
                    "ok": True,
                    "tool_name": tool_name,
                    "result_summary": "已完成源码扫描"
                    + (f"，报告已保存: {report_path}" if report_path else "")
                    + (f"（增量复核 {len(focus_flows)} 条）" if review_mode else "")
                    + ("（单 flow 重反证，报告延迟至终态保存）" if re_refute_only else "")
                    + ("（中间扫描，报告延迟至终态保存）" if (not is_final_scan and not re_refute_only) else ""),
                    "result": scan_result,
                }

            if tool_name == "DBTool.query_cve_by_cwe":
                cwe_id = arguments.get("cwe_id", "")
                if not cwe_id:
                    return {
                        "ok": False,
                        "tool_name": tool_name,
                        "result_summary": "缺少 cwe_id 参数",
                        "result": {},
                    }
                limit = arguments.get("limit", 20)
                cve_list = self.graph.db.query_cve_by_cwe(cwe_id, limit=limit)
                return {
                    "ok": True,
                    "tool_name": tool_name,
                    "result_summary": f"按 {cwe_id} 查询到 {len(cve_list)} 个 CVE",
                    "result": {"cve_list": cve_list, "cwe_id": cwe_id},
                }

            if tool_name == "DBTool.get_cve_patterns":
                component = arguments.get("component")
                cwe_id = arguments.get("cwe_id")
                patterns = self.graph.db.get_cve_patterns(component=component, cwe_id=cwe_id)
                return {
                    "ok": True,
                    "tool_name": tool_name,
                    "result_summary": f"CVE 模式查询完成 (组件={component}, CWE={cwe_id})",
                    "result": {"patterns": patterns},
                }

            if tool_name in ("DBTool.get_reachability_context", "GraphBuilder.run_reachability"):
                # 可达分析优先复用 state 中已有 cve_id，减少重复 set_context。
                cve_id = arguments.get("cve_id") or state.current_cve_id
                if not cve_id:
                    return {
                        "ok": False,
                        "tool_name": tool_name,
                        "result_summary": "缺少 cve_id，无法读取可达分析上下文",
                        "result": {},
                    }

                if tool_name == "DBTool.get_reachability_context":
                    reachability_context = self.graph.db.get_reachability_context(cve_id)
                    # 只取上下文也会写回 state，便于后续模型继续决定是否再跑完整报告。
                    state.update_reachability_context(reachability_context)
                    return {
                        "ok": True,
                        "tool_name": tool_name,
                        "result_summary": "已读取可达分析上下文",
                        "result": {"reachability_context": reachability_context},
                    }

                reachability_result = self.graph.run_reachability(cve_id)
                # 完整可达分析会同时更新结构化上下文与最终报告。
                state.update_reachability_context(reachability_result.get("reachability_context", {}))
                report_text = reachability_result.get("report", "") or ""
                state.update_report(report_text)
                report_path = self._maybe_auto_save_report(state, report_text, subdir="reachability")
                if report_path:
                    reachability_result["report_path"] = report_path
                return {
                    "ok": True,
                    "tool_name": tool_name,
                    "result_summary": "已完成漏洞可达分析"
                    + (f"，报告已保存: {report_path}" if report_path else ""),
                    "result": reachability_result,
                }

            if tool_name in ("VersionTool.identify_component", "GraphBuilder.run_version_identification"):
                decompiled_path = arguments.get("decompiled_path")
                candidate_paths = arguments.get("candidate_paths") or []
                if isinstance(candidate_paths, str):
                    candidate_paths = [p.strip() for p in candidate_paths.split(",") if p.strip()]
                if not decompiled_path:
                    return {
                        "ok": False,
                        "tool_name": tool_name,
                        "result_summary": "缺少 decompiled_path",
                        "result": {},
                    }
                if len(candidate_paths) < 2:
                    return {
                        "ok": False,
                        "tool_name": tool_name,
                        "result_summary": "candidate_paths 至少需要 2 个候选版本",
                        "result": {},
                    }
                version_result = self.graph.run_version_identification(
                    decompiled_path=decompiled_path,
                    candidate_paths=candidate_paths,
                    component_name=arguments.get("component_name"),
                )
                if version_result.get("ok"):
                    state.update_version_identification(version_result)
                    report_text = version_result.get("report_markdown", "") or ""
                    state.update_report(report_text)
                    report_path = self._maybe_auto_save_report(
                        state, report_text, subdir="version_identification"
                    )
                    if report_path:
                        version_result["report_path"] = report_path
                    summary = self._version_result_summary(version_result)
                else:
                    summary = f"版本识别失败: {version_result.get('error', 'unknown')}"
                return {
                    "ok": bool(version_result.get("ok")),
                    "tool_name": tool_name,
                    "result_summary": summary,
                    "result": version_result,
                }

            if tool_name == "FileTool.read_file":
                file_path = arguments.get("path") or arguments.get("file_path")
                if not file_path:
                    return {
                        "ok": False,
                        "tool_name": tool_name,
                        "result_summary": "缺少 path 参数",
                        "result": {},
                    }
                # 方案 2: 检查是否在失败列表中，避免重复尝试
                file_read_failures = list(state.metadata.get("file_read_failures") or [])
                if file_path in file_read_failures:
                    logger.info("FileTool.read_file 跳过已失败路径: %s", file_path)
                    return {
                        "ok": False,
                        "tool_name": tool_name,
                        "result_summary": f"跳过已失败路径: {file_path}（之前已尝试读取但文件不存在）",
                        "result": {"path": file_path, "error": "already_failed"},
                    }
                resolved_meta = self._resolve_planner_read_path(state, str(file_path))
                if resolved_meta:
                    # 当索引通过 basename fallback 解析时，校验父目录结构是否足够相似，
                    # 避免不同子目录的同名文件（如 lessons/challenges/i18n/… 与
                    # lessons/authbypass/i18n/…）互相替代导致读错文件。
                    if resolved_meta.get("resolved_via") == "basename":
                        resolved_path_str = str(resolved_meta["path"]).replace("\\", "/")
                        requested_str = str(file_path).replace("\\", "/")
                        # 计算父目录组件重合度
                        req_parts = [p for p in requested_str.split("/") if p][:-1]
                        res_parts = [p for p in resolved_path_str.split("/") if p][:-1]
                        common = 0
                        for rp, cp in zip(req_parts, res_parts):
                            if rp.lower() == cp.lower():
                                common += 1
                            else:
                                break
                        overlap = common / len(req_parts) if req_parts else 1.0
                        if overlap < 0.6:
                            logger.warning(
                                "FileTool.read_file 索引 basename fallback 重定向到不同目录: %s → %s (overlap=%.0f%%)，拒绝",
                                file_path, resolved_meta["path"], overlap * 100,
                            )
                            resolved_meta = None
                    if resolved_meta:
                        file_path = resolved_meta["path"]
                elif "*" not in str(file_path) and "?" not in str(file_path):
                    return self._read_file_index_rejected(
                        state, raw_path=str(arguments.get("path") or file_path)
                    )
                blocked, gate_reason = self._source_read_gate_blocked(
                    state,
                    path=str(file_path),
                    flow_id=arguments.get("flow_id"),
                    kind=(resolved_meta or {}).get("kind"),
                )
                if blocked:
                    flow_id = arguments.get("flow_id") or self._match_pending_l2_flow_for_path(
                        state, self._normalize_evidence_path(str(file_path))
                    )
                    expand_action = None
                    if flow_id:
                        expand_action = self._build_expand_flow_action(
                            state,
                            {
                                "flow_id": flow_id,
                                "kind": "source",
                                "vuln_type": arguments.get("vuln_type"),
                            },
                        )
                    return {
                        "ok": False,
                        "tool_name": tool_name,
                        "result_summary": gate_reason,
                        "result": {
                            "error": "joern_expand_gate",
                            "flow_id": flow_id,
                            "suggested_action": expand_action,
                        },
                    }
                req_start_raw = arguments.get("start_line")
                req_end_raw = arguments.get("end_line")
                # 提前转换为 int（LLM JSON 可能返回字符串 "1" 而不是整数 1）
                try:
                    req_start = int(req_start_raw) if req_start_raw is not None else None
                except (ValueError, TypeError):
                    req_start = None
                try:
                    req_end = int(req_end_raw) if req_end_raw is not None else None
                except (ValueError, TypeError):
                    req_end = None
                # 自动扩展：LLM 请求的行数远低于上限时，扩展到 FILE_READ_MAX_LINES 以减少空转
                if isinstance(req_start, int) and isinstance(req_end, int):
                    line_count = req_end - req_start + 1
                    if line_count < FILE_READ_MAX_LINES:
                        expanded_end = req_start + FILE_READ_MAX_LINES - 1
                        logger.info(
                            "FileTool.read_file 自动扩展: %s L%s-L%s (%d行) → L%s-L%s (%d行)",
                            file_path, req_start, req_end, line_count,
                            req_start, expanded_end, FILE_READ_MAX_LINES,
                        )
                        req_end = expanded_end
                # 硬限制：单次读取不超过 FILE_READ_MAX_LINES 行，防止 LLM 一次读全文
                was_capped = False
                if isinstance(req_start, int) and isinstance(req_end, int):
                    line_count = req_end - req_start + 1
                    if line_count > FILE_READ_MAX_LINES:
                        capped_end = req_start + FILE_READ_MAX_LINES - 1
                        logger.info(
                            "FileTool.read_file 行数限制: %s L%s-L%s 超出 %s 行限制，截断为 L%s-L%s",
                            file_path, req_start, req_end,
                            FILE_READ_MAX_LINES, req_start, capped_end,
                        )
                        req_end = capped_end
                        was_capped = True
                logger.info(
                    "FileTool.read_file 请求: path=%s L%s-L%s (local_source_path=%s, project_path=%s)",
                    file_path,
                    req_start or "1",
                    req_end or "?",
                    state.local_source_path,
                    state.project_path,
                )
                try:
                    resolved_path = self.file_tool.resolve_allowed_path(file_path, state)
                    path_norm = self._normalize_evidence_path(str(resolved_path))
                except ValueError as exc:
                    logger.warning(
                        "FileTool.read_file 磁盘不存在或未授权: %s (索引已解析 path=%s)",
                        exc,
                        file_path,
                    )
                    # 记录失败路径，避免下次重复尝试
                    failures = list(state.metadata.get("file_read_failures") or [])
                    if file_path not in failures:
                        failures.append(file_path)
                        state.metadata["file_read_failures"] = failures[-50:]  # 最多记 50 条
                    return {
                        "ok": False,
                        "tool_name": tool_name,
                        "result_summary": f"读取失败: {exc}",
                        "result": {"path": file_path, "error": str(exc)},
                    }

                existing_reads = list(state.metadata.get("file_evidence_reads") or [])
                existing_contents = list(state.metadata.get("file_evidence_content") or [])
                if isinstance(req_start, int) and isinstance(req_end, int):
                    if self._l1_covers_read_range(state, path_norm, req_start, req_end):
                        return {
                            "ok": True,
                            "tool_name": tool_name,
                            "result_summary": (
                                f"跳过 L2 读取 {file_path} L{req_start}-L{req_end}"
                                "（Joern L1 硬回溯/扩展已覆盖该行段）"
                            ),
                            "result": {
                                "ok": True,
                                "path": str(resolved_path),
                                "start_line": req_start,
                                "end_line": req_end,
                                "skipped_duplicate": True,
                                "skipped_l1_covered": True,
                            },
                        }
                    cached = self._find_cached_file_evidence(
                        path_norm,
                        req_start,
                        req_end,
                        existing_reads,
                        existing_contents,
                    )
                    if cached:
                        dup_count = self._record_duplicate_read_stall(
                            state, path_norm, req_start, req_end
                        )
                        # 始终将路径标记为已读，防止 _build_forced_l2_read_action
                        # 反复从 pending_l2_reads 取出同一文件（重复读取空转）
                        self._mark_l2_path_as_read(state, path_norm)
                        orig_path = str(arguments.get("path") or "")
                        if orig_path and orig_path != str(cached.get("path") or ""):
                            self._mark_l2_path_as_read(state, orig_path)
                        reconcile_result = self._reconcile_ambiguous_state(state)
                        cached_result = {
                            "ok": True,
                            "path": cached.get("path") or str(resolved_path),
                            "start_line": req_start,
                            "end_line": req_end,
                            "total_lines": cached.get("total_lines")
                            or self._get_known_file_total_lines(state, path_norm),
                            "content": cached.get("content_preview", ""),
                            "skipped_duplicate": True,
                            "from_cache": True,
                            "duplicate_read_count": dup_count,
                        }
                        if reconcile_result.get("resolved"):
                            cached_result["ambiguous_resolved"] = reconcile_result[
                                "resolved"
                            ]
                        summary = (
                            f"跳过重复读取 {cached_result.get('path')} "
                            f"L{req_start}-L{req_end}（已在 file_evidence_reads 中）。"
                            f"请直接使用 state_snapshot.file_evidence_read_previews 中该文件的已有内容继续分析，"
                            f"不要再次请求同一文件。若需其他文件，请 glob/read 其他路径。"
                        )
                        if reconcile_result.get("resolved"):
                            summary += (
                                f"；收口 {len(reconcile_result['resolved'])} 条模糊 flow"
                            )
                        return {
                            "ok": True,
                            "tool_name": tool_name,
                            "result_summary": summary,
                            "result": cached_result,
                        }

                prior_total = None
                for entry in existing_contents:
                    if self._normalize_evidence_path(entry.get("path", "")) == path_norm:
                        prior_total = entry.get("total_lines")
                        break
                if prior_total is None:
                    prior_total = self._get_known_file_total_lines(state, path_norm)
                if (
                    isinstance(prior_total, int)
                    and prior_total > 0
                    and isinstance(req_start, int)
                    and req_start > prior_total
                ):
                    return self._file_read_past_eof_result(
                        tool_name=tool_name,
                        file_path=file_path,
                        resolved_path=str(resolved_path),
                        req_start=req_start,
                        req_end=req_end if isinstance(req_end, int) else prior_total,
                        total_lines=prior_total,
                    )
                expanded_start, expanded_end = self._maybe_expand_whole_file_read(
                    state,
                    path_norm,
                    req_start,
                    req_end,
                    prior_total if isinstance(prior_total, int) else None,
                )
                try:
                    read_result = self.file_tool.read_file(
                        file_path,
                        state=state,
                        start_line=expanded_start,
                        end_line=expanded_end,
                        max_bytes=arguments.get("max_bytes"),
                    )
                except ValueError as exc:
                    logger.warning("FileTool.read_file 失败: %s | 当前 local_source_path=%s", exc, state.local_source_path)
                    return {
                        "ok": False,
                        "tool_name": tool_name,
                        "result_summary": f"读取失败: {exc}",
                        "result": {"path": file_path, "error": str(exc)},
                    }

                if read_result.get("ok") and read_result.get("path"):
                    actual_start = read_result.get("start_line")
                    actual_end = read_result.get("end_line")
                    total_lines = read_result.get("total_lines")
                    if (
                        isinstance(total_lines, int)
                        and total_lines > 0
                        and isinstance(actual_start, int)
                        and actual_start > total_lines
                    ):
                        return self._file_read_past_eof_result(
                            tool_name=tool_name,
                            file_path=file_path,
                            resolved_path=str(read_result.get("path", "")),
                            req_start=actual_start,
                            req_end=req_end if isinstance(req_end, int) else total_lines,
                            total_lines=total_lines,
                        )
                    if isinstance(actual_start, int) and isinstance(actual_end, int):
                        cached_after = self._find_cached_file_evidence(
                            self._normalize_evidence_path(read_result.get("path", "")),
                            actual_start,
                            actual_end,
                            existing_reads,
                            existing_contents,
                        )
                        if cached_after:
                            dup_count = self._record_duplicate_read_stall(
                                state,
                                self._normalize_evidence_path(
                                    str(read_result.get("path", ""))
                                ),
                                actual_start,
                                actual_end,
                            )
                            # 始终将路径标记为已读，防止 _build_forced_l2_read_action
                            # 反复从 pending_l2_reads 取出同一文件（重复读取空转）
                            self._mark_l2_path_as_read(
                                state,
                                self._normalize_evidence_path(
                                    str(read_result.get("path", ""))
                                ),
                            )
                            orig_path = str(arguments.get("path") or "")
                            if orig_path and orig_path != str(read_result.get("path") or ""):
                                self._mark_l2_path_as_read(state, orig_path)
                            return {
                                "ok": True,
                                "tool_name": tool_name,
                                "result_summary": (
                                    f"跳过重复读取 {read_result.get('path')} "
                                    f"L{actual_start}-L{actual_end}（全文/行段已读过）。"
                                    f"请直接使用 state_snapshot.file_evidence_read_previews 中该文件的已有内容继续分析，"
                                    f"不要再次请求同一文件。若需其他文件，请 glob/read 其他路径。"
                                ),
                                "result": {
                                    "ok": True,
                                    "path": read_result.get("path"),
                                    "start_line": actual_start,
                                    "end_line": actual_end,
                                    "content": cached_after.get("content_preview", ""),
                                    "skipped_duplicate": True,
                                    "from_cache": True,
                                    "duplicate_read_count": dup_count,
                                },
                            }
                    self._record_file_evidence_read(
                        state,
                        read_result,
                        flow_id=(
                            arguments.get("flow_id")
                            or self._match_pending_l2_flow_for_path(
                                state,
                                self._normalize_evidence_path(
                                    str(read_result.get("path", ""))
                                ),
                            )
                        ),
                    )
                    # 成功读取后也标记为已读，防止 file_evidence_reads 溢出（30 条上限）
                    # 后 _is_l2_path_already_read 无法找到该文件，导致 preempt 反复注入
                    read_path = str(read_result.get("path") or "")
                    if read_path:
                        self._mark_l2_path_as_read(state, read_path)
                    reconcile_result = self._reconcile_ambiguous_state(state)
                    if reconcile_result.get("resolved"):
                        read_result["ambiguous_resolved"] = reconcile_result["resolved"]
                line_range = (
                    f"L{read_result.get('start_line')}-L{read_result.get('end_line')}"
                    if read_result.get("start_line") and read_result.get("end_line")
                    else ""
                )
                summary = f"已读取 {read_result.get('path')} {line_range}".strip()
                # 若被截断，提示 LLM 后续范围
                if was_capped and isinstance(req_start, int) and isinstance(req_end, int):
                    total = read_result.get("total_lines") or 0
                    next_start = req_end + 1
                    if next_start <= total:
                        summary += (
                            f" ⚠️ 原始请求超出单次行数限制({FILE_READ_MAX_LINES}行)，已截断。"
                            f"如需后续内容，请请求 start_line={next_start}, end_line={min(next_start + FILE_READ_MAX_LINES - 1, total)}"
                            f" (文件共 {total} 行)"
                        )
                    else:
                        summary += f" (已读完全部内容，共 {total} 行)"
                return {
                    "ok": True,
                    "tool_name": tool_name,
                    "result_summary": summary,
                    "result": read_result,
                }

            if tool_name == "FileTool.glob_files":
                pattern = arguments.get("pattern") or "**/pom.xml"
                # 检查 glob 失败缓存，避免重复搜索不存在的文件
                glob_failures = list(state.metadata.get("glob_failures") or [])
                if pattern in glob_failures:
                    # 尝试自动拓宽窄 pattern（如 *Lesson*.java → *.java）
                    _pstr = str(pattern).replace("\\", "/")
                    _last = _pstr.rsplit("/", 1)[-1] if "/" in _pstr else _pstr
                    _is_narrow = (
                        _last not in ("*", "**", "**/*")
                        and "*" in _last
                        and re.match(r"^\*[A-Za-z0-9]", _last)
                    )
                    _broadened = None
                    if _is_narrow:
                        _ext_m = re.search(r"\.\w+$", _last)
                        _ext = _ext_m.group(0) if _ext_m else ""
                        _dir = _pstr.rsplit("/", 1)[0] if "/" in _pstr else ""
                        # 去掉目录尾部多余的 ** 或 */*
                        _dir = _dir.rstrip("/")
                        while _dir.endswith("/**") or _dir.endswith("/*"):
                            _dir = _dir.rsplit("/", 1)[0] if "/" in _dir else ""
                        _broadened = f"{_dir}/**/*{_ext}" if _dir else f"**/*{_ext}"
                    if _broadened and _broadened not in glob_failures:
                        logger.info(
                            "FileTool.glob_files 自动拓宽: %s → %s", pattern, _broadened
                        )
                        glob_result = self.file_tool.glob_files(
                            _broadened,
                            state=state,
                            root=arguments.get("root"),
                            limit=int(arguments.get("limit", 50)),
                        )
                        _bc = glob_result.get("count", 0)
                        if _bc > 0:
                            globs = list(state.metadata.get("file_evidence_globs") or [])
                            globs.append({"pattern": _broadened, "count": _bc, "auto_broadened_from": pattern})
                            state.metadata["file_evidence_globs"] = globs[-20:]
                            state.metadata["consecutive_glob_failures"] = 0
                            glob_failures.append(_broadened)
                            state.metadata["glob_failures"] = glob_failures[-30:]
                            summary = (
                                f"原 pattern `{pattern}` 曾返回 0 结果，"
                                f"自动拓宽为 `{_broadened}` 后匹配 {_bc} 个文件"
                            )
                            return {
                                "ok": True,
                                "tool_name": tool_name,
                                "result_summary": summary,
                                "result": glob_result,
                            }
                        else:
                            glob_failures.append(_broadened)
                            state.metadata["glob_failures"] = glob_failures[-30:]
                    # 无法拓宽或拓宽后仍失败 → 返回带建议的跳过
                    logger.info("FileTool.glob_files 跳过已失败 pattern: %s", pattern)
                    _hint = ""
                    if _broadened:
                        _hint = f"，拓宽为 `{_broadened}` 也返回 0 结果"
                    _suggest = (
                        f"请换用更宽泛的 pattern（如 `**/*.java` 或目录级 `**/*`），"
                        f"或参考 available_source_files 选择已知路径。"
                    )
                    return {
                        "ok": True,
                        "tool_name": tool_name,
                        "result_summary": (
                            f"跳过已失败 glob pattern: {pattern}"
                            f"（之前已搜索但匹配 0 个文件{_hint}）。{_suggest}"
                        ),
                        "result": {"ok": True, "pattern": pattern, "count": 0, "matches": [], "skipped": True},
                    }
                glob_result = self.file_tool.glob_files(
                    pattern,
                    state=state,
                    root=arguments.get("root"),
                    limit=int(arguments.get("limit", 50)),
                )
                if glob_result.get("ok"):
                    count = glob_result.get("count", 0)
                    globs = list(state.metadata.get("file_evidence_globs") or [])
                    globs.append({"pattern": pattern, "count": count})
                    state.metadata["file_evidence_globs"] = globs[-20:]
                    # 记录失败的 glob pattern（0 结果）
                    if count == 0 and pattern not in glob_failures:
                        glob_failures.append(pattern)
                        state.metadata["glob_failures"] = glob_failures[-30:]  # 最多记 30 条
                        # 连续失败计数
                        consec = int(state.metadata.get("consecutive_glob_failures", 0)) + 1
                        state.metadata["consecutive_glob_failures"] = consec
                    elif count > 0:
                        state.metadata["consecutive_glob_failures"] = 0  # 成功则重置
                summary = f"匹配 {glob_result.get('count', 0)} 个文件"
                # 连续 glob 失败时，提示 LLM 停止尝试不存在的文件
                consec = int(state.metadata.get("consecutive_glob_failures", 0))
                if consec >= 3:
                    summary += (
                        f" ⚠️ 已连续 {consec} 次 glob 返回 0 结果。"
                        f"请停止尝试不存在的文件，参考 available_source_files 选择路径，"
                        f"或直接调用 finish 结束分析。"
                    )
                return {
                    "ok": True,
                    "tool_name": tool_name,
                    "result_summary": summary,
                    "result": glob_result,
                }

            if tool_name.startswith("JavaAuditTool."):
                if tool_name == "JavaAuditTool.list_playbooks":
                    result = self.java_audit_tool.list_playbooks()
                    return {
                        "ok": result.get("ok", False),
                        "tool_name": tool_name,
                        "result_summary": result.get("result_summary", ""),
                        "result": result,
                    }
                if tool_name == "JavaAuditTool.load_playbook":
                    playbook_id = arguments.get("playbook_id") or arguments.get("skill_id")
                    if not playbook_id:
                        return {
                            "ok": False,
                            "tool_name": tool_name,
                            "result_summary": "缺少 playbook_id",
                            "result": {},
                        }
                    result = self.java_audit_tool.load_playbook(playbook_id, state)
                    return {
                        "ok": result.get("ok", False),
                        "tool_name": tool_name,
                        "result_summary": result.get("result_summary", ""),
                        "result": result.get("result", {}),
                    }
                if tool_name == "JavaAuditTool.scan_routes":
                    result = self.java_audit_tool.scan_routes(
                        state,
                        project_path=arguments.get("project_path") or arguments.get("source_root"),
                    )
                    if result.get("ok"):
                        route_count = int(result.get("route_count") or 0)
                        if route_count:
                            state.metadata["java_route_count"] = route_count
                    return {
                        "ok": result.get("ok", False),
                        "tool_name": tool_name,
                        "result_summary": result.get("result_summary", ""),
                        "result": result.get("result", {}),
                    }
                return {
                    "ok": False,
                    "tool_name": tool_name,
                    "result_summary": f"未知 JavaAuditTool 动作: {tool_name}",
                    "result": {},
                }

            if tool_name == "FileTool.write_report":
                content = arguments.get("content") or state.last_report
                if not content and arguments.get("filename") == "route_index.md":
                    content = state.metadata.get("java_routes_markdown") or ""
                if not content:
                    return {
                        "ok": False,
                        "tool_name": tool_name,
                        "result_summary": "缺少 content，且 state 中无 last_report",
                        "result": {},
                    }
                write_result = self.file_tool.write_report(
                    content,
                    state=state,
                    filename=arguments.get("filename"),
                    subdir=arguments.get("subdir"),
                )
                return {
                    "ok": True,
                    "tool_name": tool_name,
                    "result_summary": f"报告已写入 {write_result.get('path')}",
                    "result": write_result,
                }

            if tool_name == "finish":
                gate = self._prepare_finish_gate(state)
                report_blocker = gate.get("blocker")
                max_finish_blocks = int(os.environ.get("PLANNER_MAX_FINISH_BLOCKS", "3"))
                prev_block_count = int(state.metadata.get("finish_blocked_count", 0))
                if report_blocker and prev_block_count < max_finish_blocks:
                    block_count = prev_block_count + 1
                    state.metadata["finish_blocked_count"] = block_count
                    return {
                        "ok": False,
                        "tool_name": "finish_blocked",
                        "result_summary": (
                            f"拒绝 finish：{report_blocker}。"
                            f"（第 {block_count}/{max_finish_blocks} 次；系统将注入 L2/增量扫描）"
                        ),
                        "result": {
                            "blocker": report_blocker,
                            "finish_blocked_count": block_count,
                        },
                    }
                if report_blocker and prev_block_count >= max_finish_blocks:
                    logger.info(
                        "finish 拦截已达上限 (%s/%s)，强制放行: %s",
                        prev_block_count, max_finish_blocks, report_blocker,
                    )
                # finish 放行时，确保最终报告落盘
                if state.last_report and not state.metadata.get("last_report_path"):
                    self._maybe_auto_save_report(state, state.last_report, subdir="source_scan")
                return {
                    "ok": True,
                    "tool_name": tool_name,
                    "result_summary": "规划器请求结束流程",
                    "result": {},
                }

            return {
                "ok": False,
                "tool_name": tool_name,
                "result_summary": f"未知工具动作: {tool_name}",
                "result": {},
            }
        except Exception as exc:
            import traceback
            tb = traceback.format_exc()
            logger.error("工具执行异常 [%s]: %s\n%s", tool_name, exc, tb)
            return {
                "ok": False,
                "tool_name": tool_name or "unknown",
                "result_summary": f"工具执行异常: {exc}",
                "result": {
                    "error_type": exc.__class__.__name__,
                    "error_message": str(exc),
                    "traceback": tb,
                    "arguments": arguments,
                },
            }

    def run(self, state: AgentState, user_request: str) -> Dict[str, Any]:
        """
        执行完整 agent 循环，直到模型判断任务完成或达到最大步数。

        Returns:
            一个包含最终回答、计划历史、运行 ID 和审计日志路径的结果字典。
        """
        # 每次 run 都视为一轮全新“规划会话”，先清空上次计划历史。
        state.start_plan(user_request)
        self._seed_context_from_user_request(state, user_request)
        self._ensure_local_source_root(state, user_request)
        # 会话开始时就固定 project_name，避免后续 replan 过程中被模型反复改名。
        if not state.project_name:
            state.project_name = os.environ.get("JOERN_PROJECT_NAME") or "VulnerableApp"
        state.current_plan_run_id = uuid4().hex
        extracted_cve_id = self._extract_cve_id_from_text(user_request)
        if extracted_cve_id and not state.current_cve_id:
            # 自动提取 CVE 只是便捷增强；若用户已手动指定，不覆盖现有值。
            state.set_cve_id(extracted_cve_id)

        self._append_audit_event(
            state,
            {
                "event_type": "run_started",
                "user_request": user_request,
                "state_snapshot": self._build_state_snapshot(state),
            },
        )

        # 把 scanner 内部的 LLM 决策审计事件也接入到 planner 审计日志，
        # 这样 sufficiency_check / expansion_query / hard_backtrace 等内部事件
        # 也会以 "scanner_internal_audit" 类型写入 JSONL，便于事后回放。
        def _scanner_audit_bridge(event_type: str, data: dict):
            self._append_audit_event(state, {
                "event_type": "scanner_internal_audit",
                "scanner_event": event_type,
                "scanner_data": data,
            })

        self.graph.joern.set_audit_callback(_scanner_audit_bridge)

        final_plan_summary = ""
        final_answer = state.last_report or ""

        for step_index in range(1, self.max_steps + 1):
            # 审计事件顺序（每步）：
            #   plan_initialized / plan_updated -> plan_generated -> action_executed
            # 这样 grep plan_updated 即可定位“上一轮 observation 触发的重规划”。
            previous_history_item = state.plan_history[-1] if state.plan_history else None
            if step_index == 1:
                self._append_audit_event(
                    state,
                    {
                        "event_type": "plan_initialized",
                        "step": step_index,
                        "replan_reason": self._build_replan_reason(None, ""),
                    },
                )
            else:
                self._append_audit_event(
                    state,
                    {
                        "event_type": "plan_updated",
                        "step": step_index,
                        "based_on_step": previous_history_item.get("step") if previous_history_item else step_index - 1,
                        "replan_reason": self._build_replan_reason(
                            previous_history_item,
                            "(本轮新计划见紧随其后的 plan_generated)",
                        ),
                    },
                )

            try:
                # Step A: 根据历史 observation 生成“下一步一个动作”。
                planner_result = self._plan_next_step(state, user_request)
            except Exception as exc:
                planner_result = {
                    "done": False,
                    "plan_summary": f"规划阶段异常，回退处理: {exc}",
                    "next_action": {
                        "tool_name": "finish",
                        "arguments": {},
                    },
                    "final_answer": f"规划阶段异常：{exc}",
                }
            final_plan_summary = planner_result.get("plan_summary", "")

            self._append_audit_event(
                state,
                {
                    "event_type": "plan_generated",
                    "step": step_index,
                    "planner_result": planner_result,
                },
            )

            if planner_result.get("done"):
                gate = self._prepare_finish_gate(state)
                report_blocker = gate.get("blocker")
                if report_blocker:
                    block_count = int(state.metadata.get("finish_blocked_count", 0)) + 1
                    state.metadata["finish_blocked_count"] = block_count
                    self._append_audit_event(
                        state,
                        {
                            "event_type": "finish_blocked_verdict_policy",
                            "step": step_index,
                            "blocker": report_blocker,
                            "finish_blocked_count": block_count,
                            "ambiguous_flows_count": len(state.ambiguous_flows),
                        },
                    )
                    forced = self._forced_action_after_finish_block(state)
                    if forced:
                        planner_result = forced
                        final_plan_summary = forced.get("plan_summary", "")
                        self._append_audit_event(
                            state,
                            {
                                "event_type": "finish_blocked_forced_action",
                                "step": step_index,
                                "forced_action": forced.get("next_action"),
                            },
                        )
                    else:
                        final_answer = self._finalize_run_answer(
                            state, planner_result, final_plan_summary
                        )
                        state.finish_plan(final_answer)
                        self._append_audit_event(
                            state,
                            {
                                "event_type": "run_finished",
                                "step": step_index,
                                "finish_reason": "bounded_finish_after_finish_blocked",
                                "final_answer": final_answer,
                                "ambiguous_flows_count": len(state.ambiguous_flows),
                            },
                        )
                        break
                else:
                    final_answer = self._finalize_run_answer(
                        state, planner_result, final_plan_summary
                    )
                    state.finish_plan(final_answer)
                    self._append_audit_event(
                        state,
                        {
                            "event_type": "run_finished",
                            "step": step_index,
                            "finish_reason": "planner_done",
                            "final_answer": final_answer,
                        },
                    )
                    break

            action = planner_result.get("next_action", {}) or {}
            # Step B: 执行动作（扫描、取上下文、更新状态或 finish）。
            action_result = self._execute_action(state, action)
            history_item = {
                "step": step_index,
                "plan_summary": final_plan_summary,
                "action": action,
                "observation": {
                    "ok": action_result.get("ok"),
                    "tool_name": action_result.get("tool_name"),
                    "result_summary": action_result.get("result_summary"),
                    "result_preview": self._build_observation_preview(action_result),
                },
            }
            state.add_plan_history(history_item)
            # Step C: 把本轮“计划+执行+观察”入历史，供下一轮 planner 继续参考。
            self._append_audit_event(
                state,
                {
                    "event_type": "action_executed",
                    "step": step_index,
                    "history_item": history_item,
                    "full_action_result": action_result,
                },
            )

            if action_result.get("force_finished"):
                final_answer = self._finalize_run_answer(
                    state, planner_result, final_plan_summary
                )
                state.finish_plan(final_answer)
                self._append_audit_event(
                    state,
                    {
                        "event_type": "run_finished",
                        "step": step_index,
                        "finish_reason": "force_finished_scan_limit",
                        "final_answer": final_answer,
                    },
                )
                break

            if action_result.get("tool_name") == "finish_blocked":
                continue

            if action.get("tool_name") == "finish" and action_result.get("ok"):
                final_answer = self._finalize_run_answer(
                    state, planner_result, final_plan_summary
                )
                state.finish_plan(final_answer)
                self._append_audit_event(
                    state,
                    {
                        "event_type": "run_finished",
                        "step": step_index,
                        "finish_reason": "finish_action",
                        "final_answer": final_answer,
                    },
                )
                break
        else:
            # for-else 落到这里，表示没有 break（即没 done 也没 finish），触发步数上限退出。
            self._reconcile_ambiguous_state(state)
            final_answer = self._build_bounded_final_answer(state)
            if not state.ambiguous_flows and state.last_report:
                final_answer = state.last_report
            # max_steps_reached 时确保报告落盘
            if state.last_report and not state.metadata.get("last_report_path"):
                self._maybe_auto_save_report(state, state.last_report, subdir="source_scan")
            state.finish_plan(final_answer)
            self._append_audit_event(
                state,
                {
                    "event_type": "run_finished",
                    "step": self.max_steps,
                    "finish_reason": "max_steps_reached",
                    "final_answer": final_answer,
                },
            )

        try:
            audit_report_paths = render_audit_reports(state.audit_log_path) if state.audit_log_path else {}
        except Exception as exc:
            audit_report_paths = {
                "render_error": str(exc),
            }

        run_succeeded = bool(state.last_planner_answer) and "达到最大规划步数" not in (state.last_planner_answer or "")
        prompt_variant_id = str(state.metadata.get("prompt_variant_id") or "base")
        self.prompt_evolver.record_run_outcome(prompt_variant_id, run_succeeded=run_succeeded)
        generated_variant_id = self.prompt_evolver.maybe_generate_candidate(
            user_request=user_request,
            plan_history=state.plan_history,
            run_succeeded=run_succeeded,
        )
        if generated_variant_id:
            state.metadata["last_generated_prompt_variant"] = generated_variant_id
        for skill_item in (state.active_skills or []):
            skill_id = skill_item.get("skill_id")
            if not skill_id:
                continue
            self.skill_engine.record_skill_outcome(skill_id=skill_id, succeeded=run_succeeded)

        return {
            "ok": True,
            "user_request": user_request,
            "plan_run_id": state.current_plan_run_id,
            "audit_log_path": state.audit_log_path,
            "audit_report_paths": audit_report_paths,
            "saved_report_path": state.metadata.get("last_report_path"),
            "plan_history": state.plan_history,
            "final_answer": state.last_planner_answer,
            "last_report": state.last_report,
            "last_flows": state.last_flows,
            "last_reachability_context": state.last_reachability_context,
            "active_skills": state.active_skills,
            "last_skill_execution": state.metadata.get("last_skill_execution"),
            "prompt_variant_id": prompt_variant_id,
            "last_generated_prompt_variant": state.metadata.get("last_generated_prompt_variant"),
        }
