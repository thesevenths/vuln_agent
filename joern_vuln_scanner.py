"""
`joern_vuln_scanner.py` 是当前 Agent 的核心扫描引擎。

它主要负责把一个“源码目录”转成完整的漏洞分析结果。

## 单条污点 flow 的分析流水线（顺序固定）

    queries.py 预置污点查询          ← 全项目批量，找「有没有这类漏洞的 flow」
            ↓
    提取 flow 内代码片段
            ↓
    【硬回溯 hard backtrace】        ← 代码写死的 caller 链查询（见下）
            ↓
    【LLM 上下文扩展】               ← 充分性判断 + follow_up / 模板扩展查询（见下）
            ↓
    主分析 LLM + 反证 LLM

## 硬回溯 vs LLM 自生成 Joern 查询（场景区别）

| 维度 | 硬回溯 | LLM 扩展查询 |
|------|--------|----------------|
| 谁定查询 | Python 固定 DSL（.caller / dumpRaw） | LLM 返回 follow_up_query，或 intent→queries.get_expansion_query 模板 |
| 何时跑 | 每条 flow **只跑一次**，在主分析**之前** | 充分性判断为 false 时，**最多 max_iters 轮** |
| 目标 | 沿**调用链向上**找 caller 体，检测**防御/输入源** | 按**当前缺口**补方法体、变量定义、过滤逻辑等 |
| 停止条件 | hop 上限、见到 guard、见到 source、无 frontier | sufficient=true 或迭代用尽 |
| 典型问题 | 「上游有没有 if/边界检查挡住？」 | 「还缺哪个方法体才能判定？」 |

二者互补：硬回溯先低成本扫调用链；仍不足时再由 LLM 定向补查。
审计日志中通过 `joern_query_executed.query_source` 与 `ANALYSIS_STAGE_NOTES` 区分来源。

因此，这个文件不是单纯的 HTTP client，
而是“Joern 查询 + 上下文提取 + LLM 迭代分析”的总装层。
"""

from typing import Any, Dict, List, Optional  # noqa: F401  # 须在模块级常量之前导入

# ---------------------------------------------------------------------------
# Joern 查询来源说明（写入审计 JSONL/HTML，便于回放时理解「这条 query 为何存在」）
# ---------------------------------------------------------------------------
JOERN_QUERY_SOURCE_CATALOG: Dict[str, Dict[str, str]] = {
    "queries_py_initial": {
        "title": "预置污点查询（queries.py）",
        "usage_scenario": (
            "全项目扫描阶段：对每种漏洞类型执行 queries.py 中写好的 reachableByFlows 等 DSL，"
            "用于发现「是否存在从参数到危险 API 的数据流」。不针对单条 flow 缺口。"
        ),
        "contrasts_with": "非硬回溯（不看 caller 链）；非 LLM 临时编造（DSL 版本可控、可 Benchmark 锁定）。",
    },
    "queries_py_initial_fallback": {
        "title": "预置污点查询·放宽深度 fallback",
        "usage_scenario": "首轮查询结果为空或过短时，去掉 path 深度 filter 再跑同一条 queries.py 查询以提高召回。",
        "contrasts_with": "与 queries_py_initial 同属预置集，仅参数更宽松。",
    },
    "queries_py_reflection": {
        "title": "预置反射站点查询（queries.py）",
        "usage_scenario": "Java 反射保守 pass：枚举 forName/invoke 等站点，不跑完整污点迭代。",
        "contrasts_with": "与主污点 flow 分析分离的独立 pass。",
    },
    "queries_py_cpp_auxiliary": {
        "title": "预置 C++ 间接调用辅助查询",
        "usage_scenario": "可选附录 pass（JOERN_CPP_INDIRECT_AUX=1），补充间接派发面，不改变主污点结论。",
        "contrasts_with": "非硬回溯、非 LLM 扩展。",
    },
    "queries_py_logic": {
        "title": "逻辑漏洞专用查询（queries.py java_logic_queries）",
        "usage_scenario": (
            "逻辑漏洞扫描阶段：枚举端点/鉴权守卫/敏感操作/IDOR候选/信息泄露等，"
            "不依赖 reachableByFlows，而是通过 AST/注解/CFG 查询做交叉分析。"
        ),
        "contrasts_with": "非污点流分析；非硬回溯；服务 CWE-862/306/639/798/200/284 等逻辑漏洞检测。",
    },
    "hard_backtrace_caller_list": {
        "title": "硬回溯·枚举 caller 名称",
        "usage_scenario": (
            "单条 flow 分析早期：从污点所在方法出发，用固定 Joern 查询 .caller.fullName，"
            "确定「谁调用了当前方法」，为下一跳拉方法体做准备。按调用图向上，不按 LLM 意图。"
        ),
        "contrasts_with": (
            "区别于 llm_follow_up_query：不由模型选择查什么；区别于 queries_py_initial："
            "不扫全图污点，只服务当前 flow 的 caller 链。"
        ),
    },
    "hard_backtrace_caller_body": {
        "title": "硬回溯·拉取 caller 方法体",
        "usage_scenario": (
            "硬回溯中对高分 caller 执行 dumpRaw，用于发现防御分支（guard）或输入源线索；"
            "命中 guard 可提前终止回溯（stop_reason=guard_logic_found）。"
        ),
        "contrasts_with": (
            "区别于 llm_template_expansion 的 view_method_body：硬回溯按 BFS 顺序自动选 caller，"
            "扩展阶段才按 LLM 指定的 method_name/变量名定向查。"
        ),
    },
    "llm_follow_up_query": {
        "title": "LLM 自生成 Joern DSL（follow_up_query）",
        "usage_scenario": (
            "上下文充分性判断为 false 且模型在 JSON 中返回 follow_up_query 时："
            "将模型给出的 Joern 语句清洗后原样执行，用于补齐「模型认为缺的那一块」"
            "（如某个嫌疑方法体、特定变量定义）。"
        ),
        "contrasts_with": (
            "区别于硬回溯：不沿固定 caller 链，由模型根据当前 ctx 缺口选题；"
            "区别于 llm_template_expansion：查询文本来自模型而非 get_expansion_query 模板。"
        ),
    },
    "llm_template_expansion": {
        "title": "LLM 意图 + 模板扩展查询",
        "usage_scenario": (
            "充分性为 false 但未提供可执行的 follow_up_query 时：根据 expansion_intent"
            "（trace_upstream / view_method_body / check_sanitization 等）由 queries.get_expansion_query "
            "生成受控 DSL，避免模型随意写坏语法。"
        ),
        "contrasts_with": "区别于 llm_follow_up_query：查询结构固定、意图可审计；区别于硬回溯：按缺口意图查而非固定 caller BFS。",
    },
}

ANALYSIS_STAGE_NOTES: Dict[str, str] = {
    "hard_backtrace": (
        "【阶段·硬回溯】在 LLM 主分析之前执行。用代码固定的 caller 查询向上追 1~N 跳，"
        "优先回答「上游是否已有防御/是否接到输入源」。对应审计 query_source: hard_backtrace_*。"
    ),
    "llm_context_expansion": (
        "【阶段·LLM 扩展】硬回溯之后、主分析之前。每轮先 sufficiency_check，若为 false 再执行 "
        "llm_follow_up_query 或 llm_template_expansion。回答「还缺哪段代码才能判定真伪」。"
    ),
    "queries_py_scan": (
        "【阶段·预置扫描】run_taint_queries 阶段，对全工程跑 queries.py，产出初始 flow 列表。"
    ),
}

import config  # noqa: F401  # 须在模块级 DEFAULT_* 与 import queries 之前加载 .env

import hashlib
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional  # 已在模块顶部导入

import requests

import prompts
import queries
from logic_scan_settings import (
    CWE_COMPANION_MAP,
    DEFAULT_MAX_CANDIDATES,
    LOGIC_CANDIDATE_CATALOG,
    LOGIC_CANDIDATE_PRIORITY,
    LOGIC_CORE_CANDIDATE_TYPES,
    LOGIC_JOERN_CACHE_NS,
    LOGIC_L2_SENSITIVE_TYPES,
    LOGIC_LLM_CHECKPOINT_NS,
    LOGIC_QUERY_CHECKPOINT_NS,
    LOGIC_SCAN_CONTEXT_EXPANSION_TYPES,
    LOGIC_SCAN_EXPANSION_MAX_ITERS,
    SAST_OVERLAP_CANDIDATE_TYPES,
    get_cwe_companions,
    logic_candidate_cwe,
    resolve_cwe_focus,
    resolve_max_candidates,
    TIER1_MAX,
    TIER2_MAX,
)
from logic_verdict_gates import (
    apply_logic_verdict_gates,
    extract_source_literals,
    parse_security_filter_summary,
)
from evidence_levels import EVIDENCE_GOALS_ONE_LINER, REPORT_EVIDENCE_LEVEL_LEGEND
from prompts import LOGIC_VERDICT_AND_POC_POLICY, VERDICT_AND_POC_POLICY
from llm_client import LLMClient, get_default_llm_client
from tool_capabilities import TOOL_CAPABILITIES
from flow_merge import (
    build_flow_merge_key,
    build_merged_flow_header,
    build_sink_verdict_key,
    parse_sink_location,
)
from language_profiles import get_l2_config_globs
from cwe_query_registry import is_cwe_skill_template_file
import skill_loader
from l2_reads import (
    build_pending_l2_entry,
    collect_refutation_l2_read_suggestions,
    enrich_refutation_missing_l2,
    flow_has_new_l2_evidence,
    infer_fallback_l2_reads,
    normalize_scan_language,
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

DEFAULT_JOERN_URL = os.environ.get("JOERN_URL", "http://192.168.50.81:8080")
DEFAULT_PROJECT = os.environ.get("PROJECT_PATH", os.getcwd())
DEFAULT_PROJECT_NAME = os.environ.get("JOERN_PROJECT_NAME", "VulnerableApp")

# 单条 flow 进入 LLM 前的质量过滤（跳过 JoernProject 元数据等噪声）
# JOERN_FLOW_QUALITY_FILTER=0 关闭；=1 启用（默认）
# JOERN_FLOW_QUALITY_MODE: off | lenient | standard（默认）| strict
JOERN_FLOW_QUALITY_FILTER_DEFAULT = "1"
JOERN_FLOW_QUALITY_MODE_DEFAULT = "standard"
JOERN_METADATA_NOISE_MARKERS = (
    "JoernProject",
    "JoernProjectBuilder",
    "console.JoernProject",
)
_SOURCE_FILE_IN_SINK_RE = re.compile(
    r"[^\s:]+\.(?:c|h|cpp|cc|cxx|hpp|java|go|rs):\d+",
    re.IGNORECASE,
)


class JoernVulnScannerHTTP:
    """
    基于 HTTP 接口访问 Joern 的高层扫描器。

    这个类封装了三类能力：
    - **Joern 连接能力**：发查询、导入代码、切换 active project
    - **结果处理能力**：解析 Joern 输出、映射本地源码路径、提取上下文
    - **分析增强能力**：调用 LLM 判断上下文是否足够，并自动补充扩展查询
    """

    def __init__(
        self,
        joern_url: Optional[str] = None,
        project_name: Optional[str] = None,
        source_path: Optional[str] = None,
        local_source_path: Optional[str] = None,
        llm_client: Optional[LLMClient] = None,
        audit_callback=None,
    ):
        """
        初始化扫描器。

        Args:
            joern_url: Joern HTTP 服务地址，例如 `http://192.168.50.81:8080`。
            project_name: Joern workspace 中的项目名；不传则后续自动推导或使用默认值。
            source_path: Joern 服务端可见的源码根目录，用于导入/激活 CPG。
            local_source_path: 当前 agent 本地可读的源码根目录。
                当 Joern 部署在远端容器/服务器，而 agent 运行在本地时，
                需要用它把 Joern 返回的文件路径映射到本地源码镜像。
            llm_client: 可选的大模型客户端。如果不传，会在真正需要分析时懒加载。
            audit_callback: 可选的审计回调函数，签名为 `callback(event_type, data)`。
                用于将 LLM 上下文充分性判断、扩展查询、硬回溯细节等内部决策
                写入 planner 审计日志（JSONL），便于事后回放和排查。
        """
        self.joern_url = joern_url or DEFAULT_JOERN_URL
        self.audit_callback = audit_callback
        self.project_name = (
            project_name
            or os.environ.get("JOERN_PROJECT_NAME")
            or (self._derive_project_name(source_path) if source_path else DEFAULT_PROJECT_NAME)
        )
        self.source_path = source_path or DEFAULT_PROJECT
        self.local_source_path = local_source_path or source_path or DEFAULT_PROJECT
        # Java / C++ 的查询集不同，初始化时先加载默认语言模板。
        self.java_queries = queries.java_queries
        self.java_reflection_queries = queries.java_reflection_queries
        self.cpp_auxiliary_queries = queries.cpp_auxiliary_queries
        self.cpp_variant = os.environ.get("JOERN_CPP_VARIANT", "").lower() or "generic"
        self.cpp_queries = queries.get_queries(language="cpp", variant=self.cpp_variant)
        self.llm = llm_client
        # 这个开关控制：当 LLM 判断当前场景更像 embedded/generic 时，是否自动切换查询集再重跑。
        self.auto_rerun_on_variant_switch = os.environ.get("JOERN_AUTO_RERUN_ON_VARIANT_SWITCH", "0") == "1"
        self._variant_switched_during_run = False
        self._rebind_in_progress = False
        # 熔断器：连续失败计数，超过阈值则暂停发请求并建议重启 Joern
        self._consecutive_joern_failures = 0
        self._joern_circuit_breaker_limit = int(os.environ.get("JOERN_CIRCUIT_BREAKER_LIMIT", "5"))
        self._joern_circuit_open = False  # True 表示熔断器已打开，不再发请求
        self._last_query_batch_meta: Dict[str, Any] = {}
        self._last_checkpoint_resumed: List[str] = []
        self._cpp_checkpoint_resumed: List[str] = []  # 兼容旧字段，同 _last_checkpoint_resumed
        # 硬回溯命中 guard 的调用边缓存 (vuln_type|callee_full|caller_full)
        self._guarded_call_edge_cache: set = set()
        # 逻辑扫描：Joern 源码回查 / caller 链 / 保护矩阵的进程内缓存
        # 同一扫描轮次内，同一方法/类的查询结果不会变，避免重复 HTTP 请求
        self._method_source_cache: Dict[str, str] = {}
        self._caller_chain_source_cache: Dict[str, str] = {}
        self._callee_source_cache: Dict[str, str] = {}
        self._protection_matrix_cache: Dict[str, str] = {}
        self._service_siblings_cache: Dict[str, str] = {}
        self._entity_fields_cache: Dict[str, str] = {}
        self._callee_class_names_cache: Dict[str, List[str]] = {}
        self._joern_method_fullnames_cache: Dict[str, List[str]] = {}
        self._joern_method_callers_cache: Dict[str, List[str]] = {}
        # Flow 级结论缓存（跨运行复用，guard_found 等确定性结论）
        self._flow_verdict_cache: Dict[str, Dict[str, Any]] = {}
        self._flow_merge_verdict_cache: Dict[str, Dict[str, Any]] = {}
        self._flow_merge_session: Dict[str, Dict[str, Any]] = {}
        self._l1_ranges_collected: List[Dict[str, Any]] = []
        # CVE 知识库（懒加载，用于注入漏洞模式参考）
        self._cve_knowledge_base = None
        # Planner FileTool 已读 L2，注入反证/复核 prompt
        self._planner_l2_context: str = ""
        self._planner_state_metadata: Dict[str, Any] = {}
        # Scanner 自行读取的 L2 上下文（当 LLM 说 ✅ 是但缺 L2 时主动补读）
        self._scanner_l2_context: str = ""
        self._scanner_l2_files_read: List[str] = []
        # `local_roots` 用于把 Joern 返回的远端/容器路径映射回本地真实源码位置。
        self.local_roots = self._build_local_roots(self.local_source_path)

    def configure_project(
        self,
        source_path: str,
        project_name: Optional[str] = None,
        local_source_path: Optional[str] = None,
    ):
        """
        切换当前扫描器绑定的目标工程。

        Args:
            source_path: Joern 服务端可见的新源码根目录。
            project_name: 可选的新项目名；不传时自动根据目录名推导。
            local_source_path: 可选的本地源码根目录。
        """
        self.source_path = source_path
        # project_name 的优先级保持稳定：
        # 1. 已有 project_name（保持会话一致性，不被 planner 覆盖）
        # 2. 本次显式传入
        # 3. 再按路径兆底推导
        self.project_name = self.project_name or project_name or self._derive_project_name(source_path)
        if local_source_path is not None:
            self.local_source_path = local_source_path
        elif not self.local_source_path:
            self.local_source_path = source_path
        self.local_roots = self._build_local_roots(self.local_source_path)
        # 每次切换工程后，重置"本轮是否已经切换过查询变体"的标记，
        # 避免旧工程的状态污染新工程。
        self._variant_switched_during_run = False
        # 切换项目时清除可用文件缓存
        self._cached_available_files = None
        # 加载 flow 级结论缓存（跨运行复用）
        self._flow_verdict_cache = self._load_flow_verdict_cache()

    def _list_available_files(self, max_files: int = 60) -> str:
        """
        扫描 local_source_path，返回可用文件列表（相对路径，逗号分隔）。
        用于注入反证 prompt，让 LLM 生成 missing_L2_reads 时参考实际文件。
        """
        if not self.local_source_path or not os.path.isdir(self.local_source_path):
            return ""
        # 覆盖多语言项目的关键文件类型
        exts = {
            # C/C++
            ".c", ".h", ".cpp", ".hpp", ".cc", ".hh",
            # Java
            ".java",
            # Python
            ".py", ".pyi",
            # 通用配置
            ".xml", ".yml", ".yaml", ".json",
            ".conf", ".cfg", ".ini", ".toml", ".properties",
        }
        # 无后缀但关键的构建文件
        names = {"makefile", "cmakelists.txt", "dockerfile", "pom.xml", "build.gradle"}
        skip_dirs = {".git", "node_modules", "__pycache__", ".idea", "venv", ".vscode", "target", "build"}
        result = []
        base = Path(self.local_source_path)
        try:
            for root, dirs, files in os.walk(base):
                dirs[:] = [d for d in dirs if d.lower() not in skip_dirs]
                for fname in files:
                    fpath = Path(root) / fname
                    if fname.lower() in names or fpath.suffix.lower() in exts:
                        rel = str(fpath.relative_to(base)).replace("\\", "/")
                        result.append(rel)
                        if len(result) >= max_files:
                            return ", ".join(result)
        except OSError:
            pass
        return ", ".join(result) if result else ""

    def _get_refutation_available_files(self, sink_label: str = "") -> str:
        """反证 prompt 用 L2 相关文件子集（配置/构建/头文件 + sink 邻域）。"""
        limit = int(os.environ.get("JOERN_REFUTATION_AVAILABLE_FILES_LIMIT", "120"))
        metadata = getattr(self, "_planner_state_metadata", None) or {}
        language = normalize_scan_language(
            metadata.get("language")
            or os.environ.get("JOERN_SCAN_LANGUAGE", "cpp")
        )
        try:
            from project_file_index import build_l2_refutation_file_list
            from flow_merge import parse_sink_location

            sink_file = parse_sink_location(sink_label).get("file", "")
            listing = build_l2_refutation_file_list(
                local_source_path=self.local_source_path,
                language=language,
                sink_file=sink_file,
                metadata=metadata,
                limit=limit,
            )
            if listing:
                return listing
        except Exception as exc:
            logger.warning("构建反证 L2 文件列表失败，回退 walk: %s", exc)
        return self._list_available_files(
            max_files=int(os.environ.get("JOERN_REFUTATION_AVAILABLE_FILES_FALLBACK", "80"))
        )

    def _escape_joern_string_literal(self, value: str) -> str:
        """
        把普通字符串转成可安全嵌入 Joern/Scala 查询的字符串字面量。
        """
        return value.replace("\\", "\\\\").replace('"', '\\"')

    def _get_llm(self) -> LLMClient:
        """
        获取可用的大模型客户端。

        Returns:
            `LLMClient` 实例。
        """
        if self.llm is None:
            self.llm = get_default_llm_client()
        return self.llm

    def _emit_audit(self, event_type: str, data: Optional[Dict[str, Any]] = None):
        """
        向审计回调发送一条结构化事件。

        Args:
            event_type: 事件类型，例如 `sufficiency_check`、`joern_query_executed`。
            data: 事件附带的详细数据字典。
        """
        if self.audit_callback is None:
            return
        try:
            self.audit_callback(event_type, data or {})
        except Exception as exc:
            logger.warning("审计回调执行失败: %s", exc)

    def set_planner_l2_context(self, context: str) -> None:
        """注入 Planner 侧已读 L2 内容，供反证/复核阶段使用。"""
        self._planner_l2_context = (context or "").strip()

    def set_planner_state_metadata(self, metadata: Optional[Dict[str, Any]]) -> None:
        """注入 Planner state.metadata，供增量复核按 flow 选取 L2 片段。"""
        self._planner_state_metadata = dict(metadata or {})

    def _merge_planner_l2_into_context(self, context_text: str) -> str:
        bundle = (self._planner_l2_context or "").strip()
        scanner_l2 = (self._scanner_l2_context or "").strip()
        if not bundle and not scanner_l2:
            return context_text
        combined = "\n\n".join(filter(None, [bundle, scanner_l2]))
        return f"{context_text}\n\n{combined}"[:16000]

    def _try_read_l2_files_for_retry(self, vuln_type: str, flow_id: str) -> bool:
        """
        当 LLM 判 ✅ 是但缺 L2 证据时，主动读取常见配置文件。
        
        Returns:
            是否成功读取了新的 L2 文件。
        """
        if not self.local_source_path or not os.path.isdir(self.local_source_path):
            return False
        
        # 常见配置文件模式（按语言 profile，不绑定具体项目）
        config_patterns = get_l2_config_globs(
            os.environ.get("JOERN_SCAN_LANGUAGE", "cpp")
        )
        
        new_content = []
        files_read_this_time = []
        
        for pattern in config_patterns:
            try:
                import glob
                matches = glob.glob(os.path.join(self.local_source_path, pattern), recursive=True)
                for filepath in matches[:3]:  # 每个模式最多 3 个文件
                    rel_path = os.path.relpath(filepath, self.local_source_path)
                    # 跳过已读文件
                    if rel_path in self._scanner_l2_files_read:
                        continue
                    try:
                        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read(8000)  # 每个文件最多 8000 字符
                        new_content.append(f"### `{rel_path}`\n```\n{content}\n```\n")
                        self._scanner_l2_files_read.append(rel_path)
                        files_read_this_time.append(rel_path)
                    except (IOError, OSError) as e:
                        logger.debug("L2 文件读取失败: %s - %s", filepath, e)
            except Exception as e:
                logger.debug("L2 glob 失败: %s - %s", pattern, e)
        
        if new_content:
            # 追加到 scanner_l2_context
            header = "### Scanner 自动补读 L2 静态证据\n"
            self._scanner_l2_context += "\n" + header + "\n".join(new_content)
            logger.info(
                "L2 补读成功: flow=%s 读取了 %s 个文件: %s",
                flow_id, len(files_read_this_time), ", ".join(files_read_this_time)
            )
            self._emit_audit(
                "l2_auto_read_for_retry",
                {
                    "flow_id": flow_id,
                    "vuln_type": vuln_type,
                    "files_read": files_read_this_time,
                    "stage_note": "LLM 判 ✅ 是但缺 L2 证据，Scanner 主动读取配置文件供重试使用",
                },
            )
            return True
        return False

    @staticmethod
    def _joern_result_ok(result: str, *, min_len: int = 50) -> bool:
        """判断 Joern 返回是否可视为成功（非 HTTP/DSL 硬错误且有一定长度）。"""
        text = (result or "").strip()
        if not text or len(text) < min_len:
            return False
        if JoernVulnScannerHTTP._is_joern_transport_failure(text):
            return False
        return True

    def _emit_joern_query_audit(
        self,
        *,
        query_source: str,
        query_text: str,
        result_text: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        记录单次 Joern 查询的来源与结果摘要，便于区分：
        - queries_py_initial / queries_py_initial_fallback：queries.py 预置污点查询
        - llm_follow_up_query：上下文充分性阶段 LLM 返回的 follow_up_query
        - llm_template_expansion：由 expansion_intent 映射到 queries.get_expansion_query 模板
        - hard_backtrace_caller_list / hard_backtrace_caller_body：硬回溯代码生成查询
        """
        catalog_entry = JOERN_QUERY_SOURCE_CATALOG.get(query_source, {})
        clean_query = self._strip_ansi((query_text or "").strip())
        clean_result = self._strip_ansi((result_text or "").strip())
        query_kind = self._classify_joern_query_kind(clean_query, query_source)
        payload: Dict[str, Any] = {
            "query_source": query_source,
            "query_source_title": catalog_entry.get("title", query_source),
            "usage_scenario": catalog_entry.get("usage_scenario", ""),
            "contrasts_with": catalog_entry.get("contrasts_with", ""),
            "query_kind": query_kind,
            "query_kind_title": self.JOERN_QUERY_KIND_LABELS.get(query_kind, query_kind),
            "query_preview": clean_query[:800],
            "query_length": len(clean_query),
            "ok": self._joern_result_ok(clean_result),
            "result_preview": clean_result[:500],
            "result_length": len(clean_result),
        }
        if extra:
            payload.update(extra)
        self._emit_audit("joern_query_executed", payload)

    def _derive_project_name(self, source_path: Optional[str]) -> str:
        """
        根据源码目录推导一个适合作为 Joern project name 的名字。

        Args:
            source_path: 源码根目录。

        Returns:
            推导出的项目名。如果路径为空，则回退到默认名称。
        """
        if not source_path:
            return "VulnerableApp"
        normalized_path = os.path.normpath(source_path)
        candidate_name = os.path.basename(normalized_path)
        return candidate_name or "VulnerableApp"

    def _build_local_roots(self, source_path: Optional[str]) -> List[str]:
        """
        构建一组用于路径映射的本地根目录候选列表。

        Args:
            source_path: 当前源码根目录。

        Returns:
            一个按优先级排列的目录列表。后续会用这些目录去拼接 Joern 返回的相对路径。
        """
        local_roots: List[str] = []
        if source_path:
            local_roots.append(source_path)
            parent_dir = os.path.dirname(source_path)
            if parent_dir and parent_dir != source_path:
                local_roots.append(parent_dir)
        # 当前工作目录作为最后兜底，适配某些临时执行场景。
        local_roots.append(os.getcwd())
        deduplicated_roots: List[str] = []
        for root in local_roots:
            if root and root not in deduplicated_roots:
                deduplicated_roots.append(root)
        return deduplicated_roots

    def _wrap_query_with_active_project(self, query: str) -> str:
        """
        为需要访问 `cpg` 的查询补上显式的 active project 激活语句。

        Joern HTTP 服务未必会在不同请求之间保留活动工程上下文，
        因此所有项目级查询都应在同一请求里先 `setActiveProject` 再访问 `cpg`。
        """
        if not self.project_name:
            return query
        if "workspace.setActiveProject" in query:
            return query
        escaped_project_name = self._escape_joern_string_literal(self.project_name)
        return f'''
        workspace.setActiveProject("{escaped_project_name}")
        {query.strip()}
        '''

    def _health_check(self) -> bool:
        """
        轻量级健康探测：发 `1+1` 给 Joern。

        注意：Joern 正在执行上一条重查询时可能无法及时响应探测，这不等于服务已死。
        探测失败**不会**单独触发熔断（见 `_post_query`）。
        """
        timeout_sec = int(os.environ.get("JOERN_HEALTH_CHECK_TIMEOUT", "45"))
        try:
            resp = requests.post(
                f"{self.joern_url.rstrip('/')}/query-sync",
                json={"query": "1+1"},
                timeout=timeout_sec,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def reset_circuit_breaker(self) -> None:
        """重置熔断器状态，允许继续发请求。"""
        self._consecutive_joern_failures = 0
        self._joern_circuit_open = False
        logger.info("Joern 熔断器已重置")

    @staticmethod
    def _is_joern_runtime_failure(text: str) -> bool:
        """HTTP 200 但 Joern/JVM 侧 OOM、栈溢出等，应计入熔断而非当作空结果。"""
        if not text:
            return False
        lowered = text.lower()
        markers = (
            "outofmemoryerror",
            "java.lang.outofmemory",
            "gc overhead limit exceeded",
            "stackoverflowerror",
            "connection reset",
            "broken pipe",
            "joern server error",
            "failed to execute query",
            "killed",
        )
        return any(marker in lowered for marker in markers)

    def _checkpoint_enabled(self) -> bool:
        """Joern 查询/逻辑扫描检查点总开关（兼容 JOERN_CPP_CHECKPOINT）。"""
        return os.environ.get(
            "JOERN_CHECKPOINT",
            os.environ.get("JOERN_CPP_CHECKPOINT", "1"),
        ) == "1"

    def _checkpoint_reset_requested(self) -> bool:
        return os.environ.get(
            "JOERN_CHECKPOINT_RESET",
            os.environ.get("JOERN_CPP_CHECKPOINT_RESET", "0"),
        ) == "1"

    def _checkpoint_dir(self) -> Path:
        return Path(
            os.environ.get(
                "JOERN_CHECKPOINT_DIR",
                os.environ.get("JOERN_CPP_CHECKPOINT_DIR", "agent_reports/checkpoints"),
            )
        )

    def _checkpoint_file(self, namespace: str) -> Optional[Path]:
        if not self._checkpoint_enabled():
            return None
        safe = re.sub(r"[^\w\-.]", "_", self.project_name or "default")
        suffix = "" if namespace == "taint" else f"_{namespace}"
        return self._checkpoint_dir() / f"{safe}{suffix}.json"

    def _read_checkpoint_payload(self, namespace: str) -> Optional[Dict[str, Any]]:
        if self._checkpoint_reset_requested():
            logger.info("检查点: RESET=1，跳过加载 namespace=%s", namespace)
            return None
        path = self._checkpoint_file(namespace)
        if not path or not path.is_file():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if payload.get("project_name") != self.project_name:
                logger.info(
                    "检查点: project_name 不匹配 namespace=%s (checkpoint=%r, current=%r)",
                    namespace, payload.get("project_name"), self.project_name,
                )
                return None
            if (payload.get("source_path") or "") != (self.source_path or ""):
                logger.info(
                    "检查点: source_path 不匹配 namespace=%s",
                    namespace,
                )
                return None
            return payload
        except Exception as exc:
            logger.warning("读取检查点失败 namespace=%s: %s", namespace, exc)
            return None

    def _write_checkpoint_payload(self, namespace: str, payload: Dict[str, Any]) -> None:
        path = self._checkpoint_file(namespace)
        if not path:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            body = {
                "project_name": self.project_name,
                "source_path": self.source_path,
                "namespace": namespace,
                "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                **payload,
            }
            path.write_text(
                json.dumps(body, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception as exc:
            logger.warning("写入检查点失败 namespace=%s: %s", namespace, exc)

    def _load_query_checkpoint(self, namespace: str) -> Dict[str, str]:
        payload = self._read_checkpoint_payload(namespace)
        if not payload:
            self._last_checkpoint_resumed = []
            self._cpp_checkpoint_resumed = []
            return {}
        completed = payload.get("completed") or {}
        if not isinstance(completed, dict):
            return {}
        self._last_checkpoint_resumed = list(completed.keys())
        self._cpp_checkpoint_resumed = list(self._last_checkpoint_resumed)
        logger.info(
            "检查点续扫 namespace=%s：跳过已完成 %s 个查询（%s）",
            namespace,
            len(completed),
            self._checkpoint_file(namespace),
        )
        return {k: self._strip_ansi(str(v)) for k, v in completed.items()}

    def _save_query_checkpoint(self, namespace: str, completed: Dict[str, str]) -> None:
        self._write_checkpoint_payload(namespace, {"completed": completed})

    def _cpp_checkpoint_enabled(self) -> bool:
        return self._checkpoint_enabled()

    def _cpp_checkpoint_file(self) -> Optional[Path]:
        return self._checkpoint_file("taint")

    def _load_cpp_checkpoint(self) -> Dict[str, str]:
        return self._load_query_checkpoint("taint")

    def _save_cpp_checkpoint(self, completed: Dict[str, str]) -> None:
        self._save_query_checkpoint("taint", completed)

    def _remove_checkpoint_file(self, namespace: str) -> None:
        path = self._checkpoint_file(namespace)
        if path and path.is_file():
            try:
                path.unlink()
                logger.info("已清除检查点 namespace=%s (%s)", namespace, path)
            except Exception as exc:
                logger.warning("清除检查点失败 namespace=%s: %s", namespace, exc)

    @staticmethod
    def _logic_cwe_skill_fingerprint(
        cwe_skills: Dict[str, Dict[str, Any]], cwe_num: str
    ) -> str:
        """CWE 模板变更时使 LLM 缓存失效。"""
        skill = cwe_skills.get(cwe_num, {})
        if not skill:
            return ""
        keys = (
            "reasoning_workflow",
            "sanitizers",
            "confirmation_criteria",
            "verdict_rule",
            "logic_query_keywords",
            "component_scan_handoff",
            "knowledge_injection",
        )
        blob = {k: skill.get(k) for k in keys if skill.get(k)}
        if not blob:
            return ""
        return hashlib.sha256(
            json.dumps(blob, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()[:16]

    def _build_logic_related_context_block(
        self,
        candidate: Dict[str, Any],
        query_results: Dict[str, str],
    ) -> str:
        cwe_num = str(candidate.get("cwe", "")).replace("CWE-", "").strip()
        caller = str(candidate.get("caller") or "")
        related_types = self._LOGIC_CWE_QUERY_MAP.get(cwe_num, [])
        context_parts: List[str] = []
        for qt in related_types:
            raw = query_results.get(qt, "")
            if raw and len(raw) > 10:
                relevant_lines = [
                    ln for ln in raw.splitlines() if caller and caller in ln
                ]
                if relevant_lines:
                    context_parts.append(
                        f"### {qt} 相关结果\n" + "\n".join(relevant_lines[:10])
                    )
        return "\n\n".join(context_parts)

    def _read_security_config_source(self, query_results: Dict[str, str], max_chars: int = 4000) -> str:
        """Read original SecurityConfig file from disk to get full, accurate configuration.

        Parses file= paths from security_filter_chain query results, resolves against
        local_roots, and reads the original source.  This gives the LLM the complete
        antMatchers/requestMatchers chains that Joern's code.take(200) truncates.
        """
        sec_raw = query_results.get("security_filter_chain", "")
        if not sec_raw or len(sec_raw) < 20:
            return ""
        # Extract file paths from SECURITY_CONFIG lines
        file_paths: List[str] = []
        for line in sec_raw.splitlines():
            m = re.search(r'file=([^\s|]+)', line)
            if m:
                fp = m.group(1).strip().strip('"')
                if fp and fp != "?" and fp not in file_paths:
                    file_paths.append(fp)
        if not file_paths or not self.local_source_path:
            return ""
        # Resolve and read each SecurityConfig file
        parts: List[str] = []
        for fp in file_paths[:3]:  # max 3 files
            for root in self.local_roots:
                resolved = os.path.normpath(os.path.join(root, fp))
                if os.path.exists(resolved):
                    try:
                        with open(resolved, encoding="utf-8", errors="replace") as fh:
                            content = fh.read(max_chars)
                        parts.append(f"[Original SecurityConfig: {fp}]\n{content}")
                    except Exception:
                        pass
                    break
        return "\n\n".join(parts)

    def _build_logic_l2_block(
        self,
        candidate: Dict[str, Any],
        query_results: Dict[str, str],
    ) -> str:
        ctype = str(candidate.get("type") or "")
        sec_raw = query_results.get("security_filter_chain", "")
        shiro_raw = query_results.get("shiro_security_config", "")
        l2_block = ""
        if ctype in LOGIC_L2_SENSITIVE_TYPES or ctype in (
            "jwt_weakness",
            "jwt_endpoint",
            "csrf_gap",
            "shiro_missing_auth",
            "jaxrs_missing_auth",
        ):
            if sec_raw and len(sec_raw) > 20:
                l2_block += f"### security_filter_chain 查询摘要\n{sec_raw[:6000]}\n"
                security_summary = parse_security_filter_summary(sec_raw)
                if security_summary.get("has_global_authenticated"):
                    l2_block += (
                        "- **机读摘要**: 检测到全局 `authenticated()` 配置；"
                        "多数端点需已登录，不能仅因缺少方法级注解判为匿名公开。\n"
                    )
                if security_summary.get("has_permit_all"):
                    l2_block += "- **机读摘要**: 检测到 `permitAll`/匿名白名单路径。\n"
                # ── ③ SecurityConfig 原始文件读取 ──
                sec_original = self._read_security_config_source(query_results)
                if sec_original:
                    l2_block += f"\n### SecurityConfig 原始源码\n{sec_original[:4000]}\n"
            if shiro_raw and len(shiro_raw) > 20 and ctype in (
                "shiro_missing_auth",
                "missing_auth",
            ):
                l2_block += f"### shiro_security_config 查询摘要\n{shiro_raw[:2000]}\n"

        # ── ⑤ 框架安全默认值检测 ──
        fw_defaults_raw = query_results.get("framework_security_defaults", "")
        if fw_defaults_raw and len(fw_defaults_raw) > 10:
            if "NO_CUSTOM_FILTER_CHAIN" in fw_defaults_raw or "ENABLE_SECURITY" in fw_defaults_raw:
                l2_block += (
                    "- **框架默认保护**: 检测到 Spring Security 启用"
                    "（@EnableWebSecurity 或等效配置）；"
                    "Spring Security 默认所有端点需认证，仅 permitAll 显式配置的路径除外。"
                    "若候选方法无 permitAll 覆盖，不应仅因缺少方法级注解判为匿名公开。\n"
                )

        # ── ⑥ Recon 攻击面地图摘要注入 ──
        recon = getattr(self, "_recon_results", None) or {}
        if recon.get("attack_surface_summary"):
            recon_summary = recon["attack_surface_summary"]
            l2_block += "\n### Recon 攻击面摘要\n"
            l2_block += f"- 入口总数: {recon_summary.get('total_entries', 0)}\n"
            l2_block += f"- 受保护入口: {recon_summary.get('protected_entries', 0)}\n"
            l2_block += f"- 无鉴权入口: {recon_summary.get('unprotected_entries', 0)}\n"
            l2_block += f"- 敏感操作总数: {recon_summary.get('total_sensitive_ops', 0)}\n"
            l2_block += f"- 攻击路径: {recon_summary.get('total_attack_paths', 0)}\n"
            l2_block += f"- 无鉴权路径: {recon_summary.get('unauth_attack_paths', 0)}\n"
            # 注入当前候选相关的 CWE 缺失统计
            missing_cwes = {k: v for k, v in recon_summary.items() if k.startswith("missing_CWE-")}
            if missing_cwes:
                l2_block += "- CWE 缺失分布: " + ", ".join(f"{k.replace('missing_', '')}={v}" for k, v in sorted(missing_cwes.items())) + "\n"

        # 注入当前候选的攻击路径信息
        if recon.get("attack_surface"):
            caller = str(candidate.get("caller") or "")
            attack_surface = recon["attack_surface"]
            # 查找当前 candidate handler 对应的攻击路径
            relevant_paths = [
                p for p in (attack_surface.get("attack_paths") or [])
                if caller and (p.get("entry") == caller or p.get("sink") == caller)
            ]
            if relevant_paths:
                l2_block += f"\n### 当前候选攻击路径 ({len(relevant_paths)} 条)\n"
                for rp in relevant_paths[:5]:
                    auth_str = "✅ 有鉴权" if rp.get("has_auth") else "❌ 无鉴权"
                    # 构建调用链显示: entry → intermediate1 → intermediate2 → sink
                    chain_parts = [rp.get('entry', '?')]
                    for node in (rp.get('intermediate') or []):
                        if isinstance(node, dict):
                            m = node.get('method', '')
                            short = m.rsplit('.', 1)[-1] if m else '?'
                            chain_parts.append(short)
                        elif isinstance(node, str):
                            chain_parts.append(node.rsplit('.', 1)[-1] if '.' in node else node)
                    chain_parts.append(rp.get('sink', '?'))
                    chain_str = ' → '.join(chain_parts)
                    l2_block += f"- {chain_str} [{auth_str}] 缺失: {rp.get('missing_controls', [])}\n"

        return l2_block

    def _gather_logic_llm_context(
        self,
        candidate: Dict[str, Any],
        query_results: Dict[str, str],
        cwe_skills: Dict[str, Dict[str, Any]],
    ) -> Dict[str, str]:
        """收集会进入 LLM prompt 的全部材料，供 input_fingerprint 与复用分析。"""
        caller = str(candidate.get("caller") or "")
        cwe_num = str(candidate.get("cwe", "")).replace("CWE-", "").strip()
        method_source = self._fetch_method_source(caller)
        caller_chain_source = self._fetch_caller_chain_source(caller)
        callee_source = self._fetch_callee_source(caller)
        # 横向展开：Service 同级方法 + Entity 字段
        service_siblings = self._fetch_service_sibling_methods(caller)
        entity_fields = self._fetch_entity_fields(candidate)
        context_block = self._build_logic_related_context_block(candidate, query_results)
        l2_block = self._build_logic_l2_block(candidate, query_results)
        merged_l2 = self._merge_planner_l2_into_context(l2_block)
        skill_fp = self._logic_cwe_skill_fingerprint(cwe_skills, cwe_num)
        # Original source (Step 2) — preserves annotations/comments/spatial layout
        original_source = self._read_original_source(candidate)
        # Same-class protection matrix for CRUD inconsistency detection
        protection_matrix = self._fetch_class_protection_matrix(candidate)
        # Recon 攻击面摘要（可选，不影响指纹以保证向后兼容）
        recon = getattr(self, "_recon_results", None) or {}
        attack_surface_summary = str(recon.get("recon_summary") or "")
        return {
            "method_source": method_source,
            "caller_chain_source": caller_chain_source,
            "callee_source": callee_source,
            "merged_l2": merged_l2,
            "context_block": context_block,
            "skill_fp": skill_fp,
            "original_source": original_source,
            "protection_matrix": protection_matrix,
            "service_siblings": service_siblings,
            "entity_fields": entity_fields,
            "attack_surface_summary": attack_surface_summary,
        }

    # Joern REPL 输出归一化：剥离会话计数器 (val res9:, val res1234: 等)
    # 这些计数器每次 Joern 会话递增，导致相同源码产生不同指纹
    _JOERN_RES_COUNTER_RE = re.compile(r'\bval\s+res\d+\b')

    @classmethod
    def _normalize_joern_repl_output(cls, text: str) -> str:
        """将 Joern REPL 的 val resN: 计数器归一化为 val resN:，消除会话间漂移。"""
        if not text:
            return text
        return cls._JOERN_RES_COUNTER_RE.sub('val resN', text)

    @staticmethod
    def _logic_llm_input_fingerprint(ctx: Dict[str, str]) -> str:
        """单候选 LLM 输入指纹：源码回查 + 原始源码 + 保护矩阵 + 相关 query 片段 + L2 + CWE 模板。"""
        parts = [
            ctx.get("method_source") or "",
            ctx.get("caller_chain_source") or "",
            ctx.get("callee_source") or "",
            ctx.get("merged_l2") or "",
            ctx.get("context_block") or "",
            ctx.get("skill_fp") or "",
            ctx.get("original_source") or "",
            ctx.get("protection_matrix") or "",
            ctx.get("service_siblings") or "",
            ctx.get("entity_fields") or "",
        ]
        # 归一化 Joern REPL 计数器，防止 val res9 → val res25 导致指纹漂移
        normalized = [JoernVulnScannerHTTP._normalize_joern_repl_output(p) for p in parts]
        return hashlib.sha256("\n---\n".join(normalized).encode("utf-8")).hexdigest()[:24]

    def _logic_llm_cache_hit(
        self,
        candidate: Dict[str, Any],
        llm_by_key: Dict[str, Dict[str, Any]],
        input_fp: str,
        *,
        incremental: bool,
        affected_types: set,
    ) -> bool:
        ckey = self._logic_candidate_key(candidate)
        cached = llm_by_key.get(ckey) or {}
        if cached.get("skipped_empty"):
            return False
        ctype = str(candidate.get("type") or "")
        if incremental and affected_types and ctype in affected_types:
            return False
        # 增量模式：非受影响类型（或无指定受影响类型时所有类型）直接复用已有结论
        if incremental and ctype not in affected_types:
            return self._logic_llm_has_reusable_conclusion(cached)
        return bool(cached.get("input_fingerprint") == input_fp)

    @staticmethod
    def _logic_llm_has_reusable_conclusion(cached: Dict[str, Any]) -> bool:
        if not cached:
            return False
        if cached.get("skipped_empty"):
            return False
        return bool(
            cached.get("input_fingerprint")
            or cached.get("refutation_verdict")
            or "confirmed" in cached
        )

    def _load_logic_llm_checkpoint(self) -> Dict[str, Dict[str, Any]]:
        payload = self._read_checkpoint_payload(LOGIC_LLM_CHECKPOINT_NS)
        if not payload:
            return {}
        findings = payload.get("findings") or {}
        if not isinstance(findings, dict):
            return {}
        with_fp = sum(1 for v in findings.values() if (v or {}).get("input_fingerprint"))
        logger.info(
            "逻辑 LLM 检查点续扫：%d 条（含 input_fingerprint %d 条，%s）",
            len(findings),
            with_fp,
            self._checkpoint_file(LOGIC_LLM_CHECKPOINT_NS),
        )
        return findings

    def _save_logic_llm_checkpoint(
        self,
        findings_by_key: Dict[str, Dict[str, Any]],
    ) -> None:
        self._write_checkpoint_payload(
            LOGIC_LLM_CHECKPOINT_NS,
            {
                "schema_version": 2,
                "findings": findings_by_key,
            },
        )

    # ────────── Joern 源码回查持久化缓存 ──────────
    # 把 _method_source_cache / _caller_chain_source_cache / _protection_matrix_cache
    # 写入 checkpoints 目录，同项目重跑时避免数千次重复 Joern HTTP 查询。

    def _load_joern_source_cache(self) -> None:
        """加载 Joern 源码回查缓存到内存。"""
        payload = self._read_checkpoint_payload(LOGIC_JOERN_CACHE_NS)
        if not payload:
            return
        cached_ver = int(payload.get("schema_version") or 0)
        if cached_ver < 2:
            logger.warning(
                "Joern 源码缓存 schema_version=%d < 2，丢弃旧缓存（缺少 service_siblings/entity_fields/callee_class_names）",
                cached_ver,
            )
            return
        ms = payload.get("method_source") or {}
        cs = payload.get("caller_chain_source") or {}
        pm = payload.get("protection_matrix") or {}
        ss = payload.get("service_siblings") or {}
        ef = payload.get("entity_fields") or {}
        cc = payload.get("callee_class_names") or {}
        if isinstance(ms, dict):
            self._method_source_cache.update(ms)
        if isinstance(cs, dict):
            self._caller_chain_source_cache.update(cs)
        if isinstance(pm, dict):
            self._protection_matrix_cache.update(pm)
        if isinstance(ss, dict):
            self._service_siblings_cache.update(ss)
        if isinstance(ef, dict):
            self._entity_fields_cache.update(ef)
        if isinstance(cc, dict):
            self._callee_class_names_cache.update(cc)
        total = len(ms) + len(cs) + len(pm) + len(ss) + len(ef) + len(cc)
        if total:
            logger.info(
                "Joern 源码缓存加载: method=%d, caller_chain=%d, matrix=%d, siblings=%d, entity=%d, callee_cls=%d (总计 %d 条，%s)",
                len(ms), len(cs), len(pm), len(ss), len(ef), len(cc), total,
                self._checkpoint_file(LOGIC_JOERN_CACHE_NS),
            )

    def _save_joern_source_cache(self) -> None:
        """把内存中的 Joern 源码回查缓存写入 checkpoints 目录。"""
        ms = self._method_source_cache
        cs = self._caller_chain_source_cache
        pm = self._protection_matrix_cache
        ss = self._service_siblings_cache
        ef = self._entity_fields_cache
        cc = self._callee_class_names_cache
        total = len(ms) + len(cs) + len(pm) + len(ss) + len(ef) + len(cc)
        if not total:
            return
        self._write_checkpoint_payload(
            LOGIC_JOERN_CACHE_NS,
            {
                "schema_version": 2,
                "method_source": ms,
                "caller_chain_source": cs,
                "protection_matrix": pm,
                "service_siblings": ss,
                "entity_fields": ef,
                "callee_class_names": cc,
            },
        )
        logger.info(
            "Joern 源码缓存保存: method=%d, caller_chain=%d, matrix=%d, siblings=%d, entity=%d, callee_cls=%d (总计 %d 条)",
            len(ms), len(cs), len(pm), len(ss), len(ef), len(cc), total,
        )

    def _taint_query_timeout(self, query_name: str) -> int:
        base = int(os.environ.get("JOERN_CPP_TAINT_QUERY_TIMEOUT", "180"))
        heavy = int(os.environ.get("JOERN_CPP_TAINT_QUERY_TIMEOUT_HEAVY", "240"))
        if query_name in queries.CPP_QUERY_HEAVY:
            return heavy
        return base

    # ────────── Flow 级结论缓存（跨运行复用） ──────────
    # 缓存 guard_found 等确定性结论，避免重复硬回溯 + LLM 调用。
    # 缓存 key = "{vuln_type}|{sink_file}:{sink_line}|{method_name}"

    def _flow_verdict_cache_file(self) -> Optional[Path]:
        if not self._checkpoint_enabled():
            return None
        safe = re.sub(r"[^\w\-.]", "_", self.project_name or "default")
        return self._checkpoint_dir() / f"{safe}_flow_verdicts.json"

    def _load_flow_verdict_cache(self) -> Dict[str, Dict[str, Any]]:
        """加载 flow 级结论缓存。返回 {cache_key: verdict_dict}。"""
        path = self._flow_verdict_cache_file()
        if not path or not path.is_file():
            return {}
        if os.environ.get(
            "JOERN_CHECKPOINT_RESET",
            os.environ.get("JOERN_CPP_CHECKPOINT_RESET", "0"),
        ) == "1":
            return {}
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if payload.get("project_name") != self.project_name:
                return {}
            if (payload.get("source_path") or "") != (self.source_path or ""):
                return {}
            verdicts = payload.get("verdicts") or {}
            merge_verdicts = payload.get("merge_verdicts") or {}
            if verdicts:
                logger.info(
                    "Flow 结论缓存加载: %d 条（%s）",
                    len(verdicts), path,
                )
            self._flow_merge_verdict_cache = (
                merge_verdicts if isinstance(merge_verdicts, dict) else {}
            )
            return verdicts if isinstance(verdicts, dict) else {}
        except Exception as exc:
            logger.warning("读取 flow 结论缓存失败: %s", exc)
        return {}

    def _save_flow_verdict_cache(self, verdicts: Dict[str, Dict[str, Any]]) -> None:
        """持久化 flow 级结论缓存（含 sink 级与 merge 级）。"""
        path = self._flow_verdict_cache_file()
        if not path:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(
                    {
                        "project_name": self.project_name,
                        "source_path": self.source_path,
                        "verdicts": verdicts,
                        "merge_verdicts": self._flow_merge_verdict_cache,
                        "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
        except Exception as exc:
            logger.warning("写入 flow 结论缓存失败: %s", exc)

    @staticmethod
    def _flow_verdict_key(vuln_type: str, sink_label: str) -> str:
        """sink 行级缓存键（guard 剪枝等）。"""
        return build_sink_verdict_key(vuln_type, sink_label)

    def _append_l1_coverage(
        self,
        rel_path: str,
        start_line: int,
        end_line: int,
        source: str,
    ) -> None:
        if not rel_path or end_line < start_line:
            return
        entry = {
            "path": rel_path.replace("\\", "/"),
            "start_line": max(1, int(start_line)),
            "end_line": int(end_line),
            "source": source,
        }
        self._l1_ranges_collected.append(entry)

    def _record_sink_l1_window(self, sink_label: str, window: int = 45) -> None:
        loc = parse_sink_location(sink_label)
        if not loc.get("file") or not loc.get("line"):
            return
        try:
            line = int(loc["line"])
        except ValueError:
            return
        self._append_l1_coverage(
            loc["file"],
            max(1, line - window),
            line + window,
            "sink_window",
        )

    def _render_merged_flow_from_cache(
        self,
        *,
        vuln_type: str,
        flow_id: str,
        sink_label: str,
        cached: Dict[str, Any],
    ) -> str:
        canonical_id = cached.get("canonical_flow_id", flow_id)
        header = build_merged_flow_header(
            vuln_type,
            flow_id,
            sink_label,
            canonical_id,
            extra_sinks=cached.get("sink_labels"),
        )
        verdict_block = cached.get("verdict_block", "")
        analysis = cached.get("analysis", "")
        self._current_flow_meta = dict(cached.get("meta") or {})
        self._current_flow_meta["flow_id"] = flow_id
        self._current_flow_meta["merged_from"] = canonical_id
        refutation = (cached.get("meta") or {}).get("refutation") or {}
        self._record_flow_scan_artifacts(
            vuln_type=vuln_type,
            flow_id=flow_id,
            refutation_result={
                "verdict": refutation.get("verdict") or cached.get("refutation_verdict"),
                "evidence_levels": (cached.get("meta") or {}).get("evidence_levels")
                or {
                    "L1_joern": "present",
                    "L2_static_files": "partial",
                    "L3_dynamic": "not_verified",
                },
            },
            final_verdict_line=cached.get("final_verdict_line", "待确认"),
        )
        return f"\n---\n{header}{verdict_block}\n\n{analysis.strip()}\n"

    def _save_flow_merge_cache(
        self,
        *,
        merge_key: str,
        vuln_type: str,
        flow_id: str,
        sink_label: str,
        analysis: str,
        verdict_block: str,
        final_verdict_line: str,
        refutation_result: Dict[str, Any],
    ) -> None:
        sinks = list(
            (self._flow_merge_session.get(merge_key) or {}).get("sink_labels") or []
        )
        if sink_label and sink_label not in sinks:
            sinks.append(sink_label)
        entry = {
            "canonical_flow_id": (
                (self._flow_merge_session.get(merge_key) or {}).get("canonical_flow_id")
                or flow_id
            ),
            "merge_key": merge_key,
            "vuln_type": vuln_type,
            "sink_labels": sinks,
            "analysis": analysis,
            "verdict_block": verdict_block,
            "final_verdict_line": final_verdict_line,
            "refutation_verdict": refutation_result.get("verdict"),
            "meta": dict(getattr(self, "_current_flow_meta", {}) or {}),
        }
        self._flow_merge_session[merge_key] = entry
        self._flow_merge_verdict_cache[merge_key] = entry
        sink_key = self._flow_verdict_key(vuln_type, sink_label)
        self._flow_verdict_cache[sink_key] = {
            "verdict": refutation_result.get("verdict"),
            "analysis": analysis,
            "flow_id": flow_id,
            "merge_key": merge_key,
            "cached_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        self._save_flow_verdict_cache(self._flow_verdict_cache)

    def _taint_query_retries(self) -> int:
        return max(1, int(os.environ.get("JOERN_CPP_TAINT_RETRIES", "1")))

    def _batch_pause_seconds(self) -> float:
        return max(0.0, float(os.environ.get("JOERN_QUERY_BATCH_PAUSE_SEC", "2")))

    def _phase_pause_seconds(self) -> float:
        return max(0.0, float(os.environ.get("JOERN_CPP_PHASE_PAUSE_SEC", "15")))

    def _post_query(
        self,
        query: str,
        timeout: int = 0,
        retries: int = 2,
        ensure_active_project: bool = False,
        skip_rebind: bool = False,
    ) -> str:
        """
        向 Joern 发送同步查询请求。

        Args:
            query: 要执行的 Joern DSL。
            timeout: 单次 HTTP 请求超时时间（秒）。
                     默认 0=从环境变量 JOERN_QUERY_TIMEOUT 读取，回退 90 秒。
            retries: 失败后的最大重试次数。
            ensure_active_project: 是否在同一请求内显式激活当前 project。

        Returns:
            Joern 返回的 `stdout/result` 文本；如果彻底失败则返回错误占位文本。
        """
        if timeout <= 0:
            timeout = int(os.environ.get("JOERN_QUERY_TIMEOUT", "120"))

        # 熔断器打开 → 不再发请求，直接返回失败
        if self._joern_circuit_open:
            logger.error(
                "Joern 熔断器已打开（连续失败 %s 次），跳过查询。请重启 Joern 容器后调用 reset_circuit_breaker()。",
                self._consecutive_joern_failures,
            )
            return "【查询跳过】Joern 熔断器已打开，本请求未发送（请重启 Joern 后重新扫描）"

        # 查询安全守卫：拦截可能导致 Joern 卡死的危险查询
        if self._is_dangerous_joern_query(query):
            return "【查询拦截】该查询可能导致 Joern 超时（全库 reachableByFlows 或无效方法名），已跳过"

        # 软健康探测：仅打日志，不因「忙但未死」而跳过本次重查询
        if (
            self._consecutive_joern_failures > 0
            and os.environ.get("JOERN_HEALTH_PROBE", "1") == "1"
        ):
            if not self._health_check():
                logger.warning(
                    "Joern 健康探测未在时限内响应（可能仍在上一条查询中），"
                    "仍将发送本次查询；仅当本次查询也失败时才累计熔断计数"
                )

        query_to_send = self._wrap_query_with_active_project(query) if ensure_active_project else query
        # 自动补上 semantic CPG import：cpg.method / cpg.call / cpg.metaData 等均为扩展方法
        _SEMCPC_IMPORT = "import io.shiftleft.semanticcpg.language._"
        if "cpg." in query_to_send and _SEMCPC_IMPORT not in query_to_send:
            query_to_send = f"{_SEMCPC_IMPORT}\n{query_to_send}"
        query_url = f"{self.joern_url.rstrip('/')}/query-sync"
        for attempt in range(retries):
            try:
                response = requests.post(query_url, json={"query": query_to_send}, timeout=timeout)
                if response.status_code == 200:
                    payload = response.json()
                    response_text = payload.get("stdout", "") or payload.get("result", "") or str(payload)
                    should_retry_after_rebind = (
                        ensure_active_project
                        and not skip_rebind
                        and attempt == 0
                        and "No projects loaded" in response_text
                        and self.project_name
                        and self.source_path
                        and not self._rebind_in_progress
                    )
                    if should_retry_after_rebind:
                        logger.warning("查询时发现 active project 丢失，尝试重新绑定工程后重试")
                        self._rebind_in_progress = True
                        try:
                            if self.ensure_cpg_loaded():
                                continue
                        finally:
                            self._rebind_in_progress = False
                    if self._is_joern_runtime_failure(response_text):
                        self._consecutive_joern_failures += 1
                        logger.warning(
                            "Joern 运行时错误（连续失败 %s/%s）: %s",
                            self._consecutive_joern_failures,
                            self._joern_circuit_breaker_limit,
                            response_text[:300],
                        )
                        if self._consecutive_joern_failures >= self._joern_circuit_breaker_limit:
                            self._joern_circuit_open = True
                        return (
                            "【查询失败】Joern 运行时错误（可能 OOM/超时），"
                            f"连续失败 {self._consecutive_joern_failures} 次"
                        )
                    # 查询成功 → 重置连续失败计数；去除 Scala REPL ANSI 着色以省 token
                    self._consecutive_joern_failures = 0
                    return self._strip_ansi(response_text)
                logger.warning("Joern HTTP %s: %s", response.status_code, response.text[:400])
            except Exception as exc:
                query_preview = (query or "")[:200].replace("\n", " ")
                logger.warning(
                    "Joern 请求失败（第 %s 次, timeout=%ss）: %s | query预览: %s",
                    attempt + 1, timeout, exc, query_preview,
                )
                self._consecutive_joern_failures += 1
                if self._consecutive_joern_failures >= self._joern_circuit_breaker_limit:
                    self._joern_circuit_open = True
                    logger.error(
                        "Joern 连续失败 %s 次，熔断器已打开。请执行: docker restart joern-server",
                        self._consecutive_joern_failures,
                    )
                    return "【查询失败】Joern 服务疑似卡死，熔断器已打开，请重启容器"
            if attempt < retries - 1:
                time.sleep(2)
        return "【查询失败】无法连接 Joern server"

    def run_query(self, query: str) -> str:
        """
        对外暴露的原始查询接口。

        Args:
            query: 任意可直接执行的 Joern DSL。

        Returns:
            查询结果文本。
        """
        return self._post_query(query, ensure_active_project=True)

    def _verify_project_query_ready(self) -> bool:
        """
        用一个轻量查询验证当前 project 在 HTTP 请求里确实可被 `cpg` 访问。
        注意：此处禁用 rebind，避免 _post_query 内部递归调用 ensure_cpg_loaded 导致
        fallback 到 importCode 的路径被截断。
        """
        # 保存熔断计数：readiness check 超时不应触发熔断
        saved_failures = self._consecutive_joern_failures
        readiness_result = self._post_query(
            "import io.shiftleft.semanticcpg.language._\ncpg.metaData.language.l",
            timeout=180,
            retries=1,
            ensure_active_project=True,
            skip_rebind=True,
        )
        # 恢复熔断计数（readiness check 失败不计入）
        self._consecutive_joern_failures = saved_failures

        # HTTP 超时/连接失败不代表 CPG 不可用——刚 importCpg 后首条查询 Joern 需要预热
        # _post_query 超时返回 "【查询失败】无法连接 Joern server"
        if "查询失败" in readiness_result or "timeout" in readiness_result.lower():
            logger.warning(
                "CPG 就绪校验超时（Joern 可能仍在预热），视为就绪: %s",
                readiness_result[:300],
            )
            return True
        if "No projects loaded" in readiness_result or "Error:" in readiness_result:
            logger.error("CPG 就绪校验失败: %s", readiness_result[:500])
            return False
        return True

    def ensure_cpg_loaded(self) -> bool:
        """
        确保当前项目的 CPG 已经在 Joern 中可用。

        处理逻辑：
        1. 先尝试 `workspace.setActiveProject`
        2. 如果激活成功但校验失败（"No projects loaded"），自动 fallback 到 `importCode`
        3. 导入完成后再次激活并保存

        Returns:
            `True` 表示 CPG 已可查询；`False` 表示激活/导入失败。
        """
        # 内部缓存：如果同一个 project 刚加载成功过，直接复用
        cache_key = (self.project_name, self.source_path)
        if hasattr(self, '_last_cpg_cache_key') and self._last_cpg_cache_key == cache_key:
            if self._verify_project_query_ready():
                return True
            # 缓存失效（可能被其他操作覆盖）
            self._last_cpg_cache_key = None

        logger.info(
            "正在检查/加载 CPG: project=%s remote_source=%s local_source=%s",
            self.project_name,
            self.source_path,
            self.local_source_path,
        )

        escaped_project_name = self._escape_joern_string_literal(self.project_name)
        escaped_source_path = self._escape_joern_string_literal(self.source_path)

        # 先尝试“激活已存在工程”，这是最快路径，不需要重新 import。
        activate_result = self._post_query(f'workspace.setActiveProject("{escaped_project_name}")')

        # 检查激活是否真正成功
        # 成功示例: Some(value = Project(...))
        # 失败示例: None, No projects loaded, Error: ...
        activate_ok = (
            "Some(value = Project" in activate_result
            or ("Project(" in activate_result and "None" not in activate_result)
        )
        activate_failed = (
            "No projects loaded" in activate_result
            or "Error:" in activate_result
            or "= None" in activate_result
        )

        if activate_ok and not activate_failed:
            logger.info("CPG 已存在，直接复用")
            if self._verify_project_query_ready():
                self._last_cpg_cache_key = cache_key
                return True
            # setActiveProject 看起来成功，但 CPG 实际不可查询 → 需要 fallback 到 importCode
            logger.warning(
                "setActiveProject 返回成功但 CPG 校验失败，尝试 importCode 重新导入"
            )
        elif activate_failed:
            logger.info(
                "Joern workspace 无项目（%s），需要 importCode 导入",
                activate_result[:200].replace('\n', ' '),
            )

        if not self.source_path:
            logger.error("未配置源码路径，无法导入 CPG")
            return False

        # 检查 source_path 是否是本地路径（Joern 在 Docker 中无法访问）
        import_source_path = self.source_path
        if self._is_local_only_path(import_source_path):
            logger.warning(
                "source_path 是本地路径（%s），Joern 在 Docker 中可能无法访问。"
                "尝试使用已知的 Docker 映射路径或环境变量 JOERN_DOCKER_SOURCE_PATH。",
                import_source_path,
            )
            docker_path = os.environ.get("JOERN_DOCKER_SOURCE_PATH", "")
            if docker_path:
                import_source_path = docker_path
                logger.info("使用 JOERN_DOCKER_SOURCE_PATH: %s", docker_path)

        escaped_import_path = self._escape_joern_string_literal(import_source_path)

        # ── 分步加载策略（避免 Scala if/else 块在 HTTP API 中解析异常）──
        # 步骤 1: 检查预构建 CPG 文件是否存在
        cpg_bin_path = f"{escaped_import_path}/../cpg.bin"
        check_result = self._post_query(
            f'new java.io.File("{cpg_bin_path}").exists()'
        )
        cpg_bin_exists = "true" in check_result.lower()

        if cpg_bin_exists:
            # 步骤 2a: 加载预构建 CPG（importCpg）
            logger.info("检测到预构建 CPG: %s，使用 importCpg 加载", cpg_bin_path)
            load_result = self._post_query(
                f'importCpg("{cpg_bin_path}")',
                timeout=300,
            )
            logger.info("importCpg 返回: %s", load_result[:500])

            if "Error" in load_result or "error" in load_result:
                logger.warning("importCpg 失败，回退到 importCode")
                load_result = self._post_query(
                    f'importCode("{escaped_import_path}", "{escaped_project_name}")',
                    timeout=300,
                )
                project_to_activate = escaped_project_name
            else:
                # importCpg 成功后，项目名从文件名自动推导（去掉 .bin）
                project_to_activate = "cpg"

            # 激活并保存
            activate_result = self._post_query(
                f'workspace.setActiveProject("{project_to_activate}")'
            )
            self._post_query("save")
            load_result = activate_result + " CPG LOADED SUCCESSFULLY"
        else:
            # 步骤 2b: 从源码导入（Joern 4.x: importCode 返回 Cpg 对象）
            logger.info("未检测到 cpg.bin，使用 importCode 从源码导入")
            load_result = self._post_query(
                f'importCode("{escaped_import_path}", "{escaped_project_name}")',
                timeout=300,
            )
            logger.info("importCode 返回: %s", load_result[:500])
            self._post_query(
                f'workspace.setActiveProject("{escaped_project_name}")'
            )
            self._post_query("save")
            load_result += " CPG LOADED SUCCESSFULLY"

        # 检查是否明确失败
        if "IMPORT_FAILED" in load_result:
            logger.error(
                "CPG 导入失败: importCode 返回 None（路径不存在或无法访问）。"
                "source_path=%s，请确认该路径在 Joern Docker 容器中可访问。",
                import_source_path,
            )
            return False

        if (
            "CPG LOADED" in load_result
            or "Cpg[Graph" in load_result
            or "successfully imported" in load_result.lower()
        ):
            logger.info("CPG 加载/激活成功")
            verified = self._verify_project_query_ready()
            if verified:
                self._last_cpg_cache_key = cache_key
            return verified

        logger.error("CPG 加载失败: %s", load_result[-1000:])
        return False

    @staticmethod
    def _is_local_only_path(path: str) -> bool:
        """
        检测路径是否只在本机可访问（Joern Docker 中不可访问）。
        例如 Windows 驱动器路径 (C:\\, D:\\, E:\\) 或用户目录路径。
        """
        if not path:
            return False
        # Windows 驱动器路径
        if len(path) >= 2 and path[1] == ':' and path[0].isalpha():
            return True
        # 其他本地路径特征（如 /mnt/c/... WSL 路径，或 ~ 开头的用户目录）
        if path.startswith('/mnt/') or path.startswith('~'):
            return True
        return False

    @staticmethod
    def _is_reflection_query_type(query_name: str) -> bool:
        return queries.is_reflection_query_type(query_name)

    @staticmethod
    def _is_joern_transport_failure(text: str) -> bool:
        """HTTP/熔断/健康检查失败占位文本，不可当作污点 flow。"""
        from logic_query_validate import is_joern_query_failure
        return is_joern_query_failure(text)

    @staticmethod
    def _is_joern_real_transport_failure(text: str) -> bool:
        """Checkpoint 保存用的严格判断：只检查是否含真实错误标记，
        空结果（查询无匹配）视为合法结果，允许写入缓存。
        避免空结果被误判为 failure 导致每次重跑都重新查询。"""
        from logic_query_validate import JOERN_QUERY_FAILURE_MARKERS
        if not (text or "").strip():
            return False  # 空结果是合法结果，不是 transport failure
        lower = text.lower()
        return any(marker.lower() in lower for marker in JOERN_QUERY_FAILURE_MARKERS)

    @staticmethod
    def _is_joern_query_execution_failure(text: str) -> bool:
        """Joern 查询执行失败（含语法/编译/invalid escape）。"""
        from logic_query_validate import is_joern_query_failure
        return is_joern_query_failure(text)

    # Joern / Scala REPL 输出中常带 ANSI 转义码（\x1b[33m 等），需在存储/分析前清除
    _ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

    # 明显不是方法名的通用词（Joern 表头 / Scala 关键字 / 解析噪声）
    _INVALID_METHOD_NAMES = frozenset({
        "method", "name", "type", "line", "file", "node", "nodeType",
        "tracked", "call", "identifier", "return", "literal", "parameter",
        "val", "var", "def", "class", "object", "trait", "true", "false",
        "null", "some", "none", "list", "string", "int", "long", "boolean",
        "graph", "cpg", "option", "project", "workspace",
    })

    @classmethod
    def _strip_ansi(cls, text: str) -> str:
        """去除 ANSI 转义码，减少存储体积和 LLM token 消耗。"""
        if not text:
            return text
        return cls._ANSI_RE.sub("", text)

    # Joern DSL 语义分类（审计 query_kind，与 LLM 的 expansion_intent 解耦）
    JOERN_QUERY_KIND_LABELS: Dict[str, str] = {
        "taint_path": "污点路径扫描",
        "trace_caller": "向上追溯 caller",
        "view_body": "查看方法体",
        "trace_forward": "向下追踪（UAF/Double-Free）",
        "other": "其它定点查询",
    }

    @classmethod
    def _classify_joern_query_kind(cls, query_text: str, query_source: str = "") -> str:
        """
        根据 Joern DSL（及 query_source）推断查询语义，写入审计 query_kind。

        与 expansion_intent 独立：后者是 LLM 自述缺口，前者是实际 DSL 在做什么。
        """
        source = (query_source or "").strip()
        if source in ("hard_backtrace_caller_list", "hard_backtrace_caller_body"):
            return "trace_caller"

        normalized = re.sub(r"\s+", " ", (query_text or "").strip().lower())
        if not normalized:
            return "other"

        if "reachablebyflows" in normalized.replace(" ", ""):
            return "taint_path"
        if ".caller" in normalized:
            return "trace_caller"
        if ".body" in normalized or ".dumpraw" in normalized:
            return "view_body"
        return "other"

    @classmethod
    def _is_dangerous_joern_query(cls, query: str) -> bool:
        """
        检测 Joern 查询是否可能导致服务卡死/超时。

        已知危险模式：
        1. reachableByFlows(cpg.parameter) 无任何名称锚定 → 真正的全库污点分析，必超时
           注意：cpg.call.name("strcpy|gets") 或 cpg.method.name("xxx") 都算有锚定
        2. method.name("<短词>") 且词在 INVALID 列表中 → 解析出假方法名
        """
        if not query:
            return False
        q = query.strip()
        # 危险模式 1: 全库 reachableByFlows（无任何名称锚定）
        if "reachableByFlows" in q and "cpg.parameter" in q:
            # 以下都算有效锚定：
            #   cpg.call.name("strcpy|gets")
            #   cpg.call.where(_.name("strcpy|gets"))
            #   cpg.call.where(_.code("..."))
            #   cpg.call.methodFullName("...executeQuery...")
            #   cpg.call.where(_.methodFullName("..."))
            #   cpg.call.where(\n    _.name("..."))  ← 多行格式
            #   cpg.method.name("xxx")
            has_call_anchor = (
                "cpg.call.name(" in q
                or "cpg.call.methodFullName(" in q
                or ".where(_.name(" in q
                or ".where(_.methodFullName(" in q
                or ".where(_.code(" in q
                or re.search(r"\.where\(\s*\n\s*_.name\(", q)  # 多行格式
                or re.search(r"\.where\(\s*\n\s*_.methodFullName\(", q)  # 多行格式
            )
            has_method_anchor = "cpg.method.name(" in q
            if not has_call_anchor and not has_method_anchor:
                logger.warning(
                    "拦截危险查询: reachableByFlows(cpg.parameter) 无方法名/函数名锚定，"
                    "全库污点分析将导致 Joern 超时"
                )
                return True
        # 危险模式 2: 查询了明显无效的方法/函数名（覆盖 cpg.method.name、cpg.call.name、_.name、cpg.method.fullName）
        for pattern in [
            r'cpg\.method\.name\("([^"]+)"\)',
            r'cpg\.method\.fullName\("([^"]+)"\)',
            r'cpg\.call\.name\("([^"]+)"\)',
            r'_\.name\("([^"]+)"\)',
        ]:
            m = re.search(pattern, q)
            if m:
                extracted_name = m.group(1).strip().lower()
                # 单个通用词 → 拦截；含正则/管道符的复合查询（如 "strcpy|gets"）放行
                if "|" not in extracted_name and ".*" not in extracted_name:
                    if extracted_name in cls._INVALID_METHOD_NAMES or len(extracted_name) <= 1:
                        logger.warning(
                            "拦截无效查询: name(\"%s\") 是通用词/表头，不是真实方法名",
                            m.group(1),
                        )
                        return True
        return False

    @staticmethod
    def _has_empty_list_result(text: str) -> bool:
        """
        判断 Joern 查询结果是否为空（Scala REPL 返回 List() / List[String]()）。
        检查文本中最后一个 val 声明是否以空 List 结尾。
        """
        if not text:
            return False
        # 找最后一个 val 行，判断是否 = List() 或 = List[String]()
        lines = text.rsplit("\n", 20)  # 只看末尾
        for line in reversed(lines):
            stripped = line.strip()
            if stripped.startswith("val ") and " = " in stripped:
                return stripped.endswith("List()") or stripped.endswith("= List()")
        # 兜底：整段文本以空 List 结尾
        return text.rstrip().endswith("List()") or " = List()" in text[-200:]

    def _is_valid_flow_text(self, query_name: str, query_result: str) -> bool:
        """判断单次 Joern 查询结果是否值得进入 LLM 分析。"""
        text = (query_result or "").strip()
        if not text or self._is_joern_transport_failure(text) or "invalid escape" in text.lower():
            return False
        # 空 List 结果 → 无论什么查询类型都不进入分析
        if self._has_empty_list_result(text):
            return False
        if self._is_reflection_query_type(query_name):
            return len(text) > 30
        if len(text) <= 100:
            return False
        if self._flow_quality_filter_mode() != "off":
            has_table = self._raw_text_has_taint_table(text)
            has_code = self._raw_text_has_code_evidence(text)
            has_noise = self._raw_text_has_joern_metadata_noise(text)
            if has_noise and not has_table and not has_code:
                return False
        return True

    def _run_query_map(
        self,
        query_map: Dict[str, str],
        *,
        log_prefix: str = "查询",
        query_source: str = "queries_py_initial",
        checkpoint_merge: Optional[Dict[str, str]] = None,
        checkpoint_namespace: Optional[str] = None,
        use_cpp_timeouts: bool = False,
    ) -> Dict[str, str]:
        """
        执行一组 Joern 查询并返回结果映射。

        对应流水线最前面的「预置扫描」阶段（queries.py），与单条 flow 上的
        硬回溯 / LLM 扩展无关。审计中 query_source 见入参，默认 queries_py_initial。
        """
        if self.audit_callback and query_source in JOERN_QUERY_SOURCE_CATALOG:
            self._emit_audit(
                "queries_py_scan_batch_started",
                {
                    "query_source": query_source,
                    "query_count": len(query_map),
                    "stage_note": ANALYSIS_STAGE_NOTES["queries_py_scan"],
                    "usage_scenario": JOERN_QUERY_SOURCE_CATALOG[query_source].get("usage_scenario", ""),
                },
            )
        flow_results: Dict[str, str] = {}
        if checkpoint_namespace and self._checkpoint_enabled():
            flow_results.update(self._load_query_checkpoint(checkpoint_namespace))
        if checkpoint_merge:
            flow_results.update(checkpoint_merge)
        query_items = [
            (name, tpl) for name, tpl in query_map.items() if name not in flow_results
        ]
        batch_meta = {
            "executed_ok": [],
            "failed_transport": [],
            "not_run_circuit_abort": [],
            "circuit_opened_during_batch": False,
            "total_planned": len(query_map),
            "skipped_checkpoint": len(flow_results),
            "resumed_from_checkpoint": list(self._last_checkpoint_resumed),
            "checkpoint_namespace": checkpoint_namespace,
        }
        not_run_placeholder = (
            "【查询未执行·熔断中止】熔断器已打开，本条污点查询未向 Joern 发送；"
            "请重启 Joern 容器后重新跑完整扫描，避免漏扫。"
        )

        for index, (query_name, query_template) in enumerate(query_items):
            if self._joern_circuit_open:
                for remaining_name, _ in query_items[index:]:
                    flow_results[remaining_name] = not_run_placeholder
                    batch_meta["not_run_circuit_abort"].append(remaining_name)
                batch_meta["circuit_opened_during_batch"] = True
                logger.error(
                    "污点查询批次中止：已执行 %s/%s 条，剩余 %s 条未发送（熔断）",
                    index,
                    len(query_items),
                    len(query_items) - index,
                )
                break

            query_to_send = query_template.strip().replace(".path.size", ".elements.size")
            logger.info("执行%s: %s", log_prefix, query_name)
            if os.environ.get("JOERN_LOG_QUERY_DSL", "0") == "1":
                logger.info(
                    "=== Joern Query DSL [%s] ===\n%s\n=== END ===",
                    query_name, query_to_send,
                )
            timeout_sec = self._taint_query_timeout(query_name) if use_cpp_timeouts else 180
            query_result = self._post_query(
                query_to_send,
                timeout=timeout_sec,
                retries=self._taint_query_retries() if use_cpp_timeouts else 2,
                ensure_active_project=True,
            ).strip()
            self._emit_joern_query_audit(
                query_source=query_source,
                query_text=query_to_send,
                result_text=query_result,
                extra={"vuln_type": query_name, "query_name": query_name},
            )
            flow_results[query_name] = query_result
            if self._is_joern_real_transport_failure(query_result):
                batch_meta["failed_transport"].append(query_name)
            else:
                batch_meta["executed_ok"].append(query_name)

            if self._joern_circuit_open:
                for remaining_name, _ in query_items[index + 1 :]:
                    flow_results[remaining_name] = not_run_placeholder
                    batch_meta["not_run_circuit_abort"].append(remaining_name)
                batch_meta["circuit_opened_during_batch"] = True
                logger.error(
                    "污点查询批次中止：第 %s 条后触发熔断，剩余 %s 条未发送",
                    query_name,
                    len(query_items) - index - 1,
                )
                break

            pause_sec = self._batch_pause_seconds()
            if pause_sec > 0 and index < len(query_items) - 1:
                time.sleep(pause_sec)

            if (
                checkpoint_namespace
                and self._checkpoint_enabled()
                and not self._is_joern_real_transport_failure(query_result)
            ):
                self._save_query_checkpoint(checkpoint_namespace, flow_results)

        batch_meta["executed_count"] = len(batch_meta["executed_ok"])
        self._last_query_batch_meta = batch_meta
        if self.audit_callback:
            self._emit_audit("queries_py_scan_batch_finished", batch_meta)
        return flow_results

    def run_java_reflection_queries(self) -> Dict[str, str]:
        """Java 反射保守查询（独立 pass，不改变主污点 query_map）。"""
        return self._run_query_map(
            self.java_reflection_queries,
            log_prefix="反射保守查询",
            query_source="queries_py_reflection",
        )

    def run_cpp_auxiliary_queries(self) -> Dict[str, str]:
        """C/C++ 间接调用辅助查询（可选 pass，默认由环境变量关闭）。"""
        return self._run_query_map(
            self.cpp_auxiliary_queries,
            log_prefix="C++间接辅助查询",
            query_source="queries_py_cpp_auxiliary",
        )

    def run_taint_queries(self, language: str = "java") -> Dict[str, str]:
        """
        执行一组预定义的污点查询。

        Args:
            language: 当前目标语言。决定使用 Java 查询集还是 C/C++ 查询集。

        Returns:
            一个 `漏洞类型 -> Joern 输出文本` 的映射。
        """
        is_cpp = language.lower() in ["c", "cpp", "c++"]
        checkpoint_ns = "taint" if is_cpp else None

        if is_cpp and os.environ.get("JOERN_CPP_SCAN_PHASES", "1") == "1":
            flow_results: Dict[str, str] = {}
            for phase_index, (phase_name, phase_map) in enumerate(queries.get_cpp_scan_phases()):
                if self._joern_circuit_open:
                    logger.error("熔断已开，跳过 C++ 阶段 %s 及后续阶段", phase_name)
                    break
                ordered = queries.order_cpp_query_map(phase_map)
                phase_results = self._run_query_map(
                    ordered,
                    log_prefix=f"污点查询[{phase_name}]",
                    query_source=f"queries_py_{phase_name}",
                    checkpoint_namespace=checkpoint_ns,
                    use_cpp_timeouts=True,
                )
                flow_results.update(phase_results)
                if (
                    phase_index < len(queries.get_cpp_scan_phases()) - 1
                    and not self._joern_circuit_open
                ):
                    pause = self._phase_pause_seconds()
                    if pause > 0:
                        logger.info("C++ 阶段间隔休眠 %.1fs（JOERN_CPP_PHASE_PAUSE_SEC）", pause)
                        time.sleep(pause)
        else:
            query_map = self.cpp_queries if is_cpp else self.java_queries
            if is_cpp:
                query_map = queries.order_cpp_query_map(query_map)
            flow_results = self._run_query_map(
                query_map,
                log_prefix="污点查询",
                query_source="queries_py_initial",
                checkpoint_namespace=checkpoint_ns,
                use_cpp_timeouts=is_cpp,
            )

        enable_fallback = os.environ.get("JOERN_CPP_ENABLE_FALLBACK", "1") == "1"
        query_map = self.cpp_queries if is_cpp else self.java_queries

        for query_name, query_result in flow_results.items():
            is_error = (
                "Error:" in query_result
                or "invalid escape character" in query_result.lower()
                or "invalid escape" in query_result.lower()
            )
            is_empty = (
                query_result.endswith("List()")
                or " = List()" in query_result
                or "List[String] = List()" in query_result
                or "List[Literal] = List()" in query_result
            )
            has_table = "│" in query_result and ("tracked" in query_result.lower() or "nodeType" in query_result.lower())
            has_list_content = "List(" in query_result and not is_empty and len(query_result) > 200

            # 这里不是做“是否真实漏洞”的判定，
            # 只是对查询结果做一次粗分类，帮助日志快速判断命中情况。
            if is_error:
                logger.warning("%s 查询失败: %s", query_name, query_result[:300])
            elif has_table or has_list_content:
                logger.info("%s 找到潜在线索，结果长度=%s", query_name, len(query_result))
            else:
                logger.info("%s 未找到明显有效结果", query_name)

            # 触发 fallback 的条件：
            # - 不是语法错误（错误要优先修 DSL，不盲目重跑）
            # - 没看到有效表格结构
            # - 结果为空或过短（可能是路径深度阈值太小）
            should_fallback = (
                enable_fallback
                and not self._joern_circuit_open
                and not is_error
                and not has_table
                and (is_empty or len(query_result) < 120)
            )
            if should_fallback:
                # 如果当前查询结果过短，说明路径深度限制可能过于保守；
                # 因此去掉深度过滤条件，再重跑一次尝试提高召回率。
                original_query = query_map[query_name].strip().replace(".path.size", ".elements.size")
                fallback_query = re.sub(
                    r"\.filter\([^)]*elements\.size[^)]*\)\s*",
                    "",
                    original_query,
                    flags=re.IGNORECASE,
                ).strip()
                if self._is_joern_transport_failure(query_result):
                    continue
                fallback_timeout = int(os.environ.get("JOERN_CPP_FALLBACK_TIMEOUT", "300"))
                fallback_result = self._post_query(
                    fallback_query,
                    timeout=fallback_timeout,
                    retries=self._taint_query_retries() if is_cpp else 2,
                    ensure_active_project=True,
                ).strip()
                self._emit_joern_query_audit(
                    query_source="queries_py_initial_fallback",
                    query_text=fallback_query,
                    result_text=fallback_result,
                    extra={"vuln_type": query_name, "query_name": query_name},
                )
                fallback_has_table = "│" in fallback_result and (
                    "tracked" in fallback_result.lower() or "nodeType" in fallback_result.lower()
                )
                fallback_has_list_content = "List(" in fallback_result and len(fallback_result) > 200
                if fallback_has_table or fallback_has_list_content or len(fallback_result) > len(query_result):
                    flow_results[query_name] = fallback_result

        return flow_results

    def run_taint_queries_for_types(
        self, query_types: List[str], language: str = "cpp"
    ) -> Dict[str, str]:
        """
        仅执行指定漏洞类型的 Joern 查询（专家 Skill 定向扫描）。

        与 run_taint_queries 的区别：后者跑全量查询集，本方法只跑 query_types
        中列出的查询，减少噪音和耗时。

        Args:
            query_types: 要执行的查询类型列表，如 ['cpp_buffer_overflow', 'cpp_can_or_buffer_parsing']
            language: 目标语言。

        Returns:
            漏洞类型 -> Joern 输出文本的映射（仅含指定类型）。
        """
        is_cpp = language.lower() in ["c", "cpp", "c++"]
        full_query_map = self.cpp_queries if is_cpp else self.java_queries

        # 只保留指定类型的查询
        targeted_map = {}
        for qt in query_types:
            qt_clean = qt.strip()
            if qt_clean in full_query_map:
                targeted_map[qt_clean] = full_query_map[qt_clean]
            else:
                logger.warning("run_taint_queries_for_types: 未知查询类型 '%s'，已跳过", qt_clean)

        if not targeted_map:
            logger.warning("run_taint_queries_for_types: 无有效查询类型，返回空结果")
            return {}

        if is_cpp:
            targeted_map = queries.order_cpp_query_map(targeted_map)

        logger.info(
            "执行定向扫描，查询类型: %s（共 %d 条）",
            list(targeted_map.keys()),
            len(targeted_map),
        )

        flow_results = self._run_query_map(
            targeted_map,
            log_prefix="定向扫描",
            query_source="targeted_scan",
            use_cpp_timeouts=is_cpp,
        )
        return flow_results

    def run_targeted_source_scan(
        self,
        query_types: List[str],
        language: str = "cpp",
        max_iters: int = 3,
    ) -> Dict[str, Any]:
        """
        定向源码扫描：仅跑指定漏洞类型的 Joern 查询 + 完整 LLM 迭代分析/反证。

        供 Skill ``targeted_scan`` 与 ``JoernTool.run_targeted_scan`` 使用；
        语义上等同于「缩小 query 范围的 run_source_scan」，不计入全量扫描批次。
        """
        if not query_types:
            return {
                "ok": False,
                "flows": {},
                "report": "",
                "ambiguous_flows": [],
                "pending_l2_reads_raw": [],
                "flow_findings_index": [],
            }
        if not self.ensure_cpg_loaded():
            return {
                "ok": False,
                "flows": {},
                "report": "",
                "ambiguous_flows": [],
                "pending_l2_reads_raw": [],
                "flow_findings_index": [],
            }

        flows = self.run_taint_queries_for_types(query_types=query_types, language=language)
        report, ambiguous_list = self.iterative_analyze(
            flows,
            language=language,
            max_iters=max_iters,
            return_ambiguous=True,
        )
        artifacts = getattr(self, "_last_scan_artifacts", {}) or {}
        return {
            "ok": True,
            "flows": flows,
            "report": report,
            "ambiguous_flows": ambiguous_list,
            "pending_l2_reads_raw": artifacts.get("pending_l2_reads_raw", []),
            "flow_findings_index": artifacts.get("flow_findings_index", []),
            "l1_covered_ranges": artifacts.get("l1_covered_ranges", []),
            "flow_catalog": artifacts.get("flow_catalog", {}),
            "evidence_unreachable_flow_ids": artifacts.get("evidence_unreachable_flow_ids", []),
        }

    # ------------------------------------------------------------------
    # 逻辑漏洞扫描
    # ------------------------------------------------------------------

    # CWE 编号 → 查询类型 映射（用于交叉引用）
    _LOGIC_CWE_QUERY_MAP = {
        "862": ["auth_guards", "sensitive_operations", "public_endpoints", "shiro_auth_guards", "jaxrs_auth_guards", "jaxrs_unprotected_resources", "shiro_security_config", "class_level_auth", "aop_auth_aspects", "custom_auth_annotations", "framework_security_defaults"],
        "306": ["public_endpoints", "auth_guards", "sensitive_operations", "security_filter_chain", "jaxrs_unprotected_resources", "jaxrs_auth_guards", "shiro_security_config", "class_level_auth", "aop_auth_aspects", "custom_auth_annotations", "framework_security_defaults"],
        "863": ["incorrect_authz_source", "auth_guards", "sensitive_operations", "cors_config", "class_level_auth", "custom_auth_annotations"],
        "639": ["idor_candidates", "idor_path_variable", "idor_profile", "sensitive_operations"],
        "798": ["hardcoded_credentials_v2", "jwt_weakness", "jwt_endpoints"],
        "200": ["info_leak_candidates", "info_leak_response", "mass_data_exposure"],
        "284": ["cors_config", "security_filter_chain", "auth_guards"],
        "285": ["business_authz_gap", "auth_guards", "sensitive_operations", "admin_ops_no_auth"],
        "841": ["workflow_bypass", "sensitive_operations", "auth_guards", "public_endpoints"],
        "287": ["auth_weakness", "auth_guards", "public_endpoints", "security_filter_chain", "jwt_weakness", "jwt_endpoints", "shiro_auth_guards", "jaxrs_auth_guards", "class_level_auth", "custom_auth_annotations"],
        "352": ["sensitive_operations", "cors_config", "public_endpoints", "security_filter_chain", "csrf_gap"],
        "836": ["client_hash_auth", "auth_guards", "public_endpoints"],
        "899": ["auth_guards", "sensitive_operations", "idor_candidates", "admin_ops_no_auth", "incorrect_authz_source", "business_authz_gap"],
        "22": ["file_ops_risk", "idor_path_variable"],
        "341": ["jwt_weakness", "jwt_endpoints"],
        "330": ["jwt_weakness", "jwt_endpoints"],
        "367": ["toctou_risk", "file_ops_risk"],
        "840": ["business_logic_risk", "sensitive_operations", "public_endpoints"],
        "918": ["ssrf_risk", "public_endpoints", "sensitive_operations"],
        "89": ["sqli_risk", "sensitive_operations"],
        "79": ["xss_output_risk", "public_endpoints", "sensitive_operations"],
        "611": ["xxe_risk", "public_endpoints"],
        "502": ["deserialization_risk", "public_endpoints"],
        "78": ["cmd_exec_risk", "file_ops_risk"],
        # 新增逻辑漏洞 CWE
        "269": ["privilege_escalation", "sensitive_operations", "auth_guards", "admin_ops_no_auth"],
        "276": ["incorrect_permissions", "file_ops_risk", "public_endpoints"],
        "307": ["brute_force_risk", "auth_weakness", "public_endpoints", "security_filter_chain"],
        "362": ["race_condition_risk", "toctou_risk", "sensitive_operations"],
        "384": ["session_fixation_risk", "auth_weakness", "public_endpoints", "security_filter_chain"],
        "521": ["weak_password_requirements", "public_endpoints"],
        "610": ["payment_tampering", "business_logic_risk", "sensitive_operations", "public_endpoints"],
        "613": ["session_expiration_risk", "jwt_weakness", "jwt_endpoints", "security_filter_chain"],
        "640": ["password_recovery_weakness", "auth_weakness", "public_endpoints"],
        "915": ["mass_assignment_risk", "sensitive_operations", "public_endpoints"],
    }
    _LOGIC_QUERY_TAGS: Dict[str, tuple] = {
        "auth_guards": ("ANNOTATION_GUARD", "CODE_GUARD", "PARAM_IDENTITY_GUARD", "JAXRS_ANNOTATION_GUARD", "SHIRO_ANNOTATION_GUARD"),
        "sensitive_operations": ("SENSITIVE_OP",),
        "idor_candidates": ("IDOR_CANDIDATE",),
        "idor_path_variable": ("IDOR_PATHVAR", "IDOR_REQPARAM"),
        "idor_profile": ("IDOR_PROFILE",),
        "jwt_endpoints": ("JWT_ENDPOINT",),
        "info_leak_response": ("RESPONSE_LEAK",),
        "csrf_gap": ("CSRF_GAP",),
        "ssrf_risk": ("SSRF_RISK",),
        "business_logic_risk": ("BIZLOGIC_RISK",),
        "workflow_bypass": ("WORKFLOW_BYPASS",),
        "incorrect_authz_source": ("UNTRUSTED_AUTHZ",),
        "client_hash_auth": ("CLIENT_HASH_AUTH",),
        "auth_weakness": ("AUTH_WEAKNESS",),
        "business_authz_gap": ("BIZ_AUTHZ_GAP",),
        "xss_output_risk": ("XSS_OUTPUT_RISK",),
        "toctou_risk": ("TOCTOU_RISK",),
        "admin_ops_no_auth": ("ADMIN_OP_NO_AUTH",),
        "jwt_weakness": ("JWT_WEAK_SECRET", "JWT_NO_VERIFY", "JWT_ALG_CONFUSION"),
        "file_ops_risk": ("FILE_OPS_RISK",),
        "mass_data_exposure": ("MASS_DATA_EXPOSURE",),
        "info_leak_candidates": ("EXCEPTION_LEAK", "SENSITIVE_LOG"),
        "hardcoded_credentials_v2": ("HARDCODED_CRED",),
        "cors_config": ("CORS_CONFIG",),
        "security_filter_chain": ("SECURITY_CONFIG",),
        "shiro_auth_guards": ("SHIRO_ANNOTATION_GUARD", "SHIRO_CODE_GUARD"),
        "shiro_security_config": ("SHIRO_CONFIG",),
        "jaxrs_auth_guards": ("JAXRS_ANNOTATION_GUARD",),
        "jaxrs_unprotected_resources": ("JAXRS_UNPROTECTED",),
        "public_endpoints": ("PUBLIC_ENDPOINT",),
        "endpoint_enumeration": (),
        "sqli_risk": ("SQLI_RISK", "SQLI_NATIVE"),
        "xxe_risk": ("XXE_RISK",),
        "deserialization_risk": ("DESER_RISK",),
        "cmd_exec_risk": ("CMD_EXEC_RISK",),
        # 新增查询标签
        "privilege_escalation": ("PRIV_ESCALATION",),
        "incorrect_permissions": ("PERM_RISK",),
        "brute_force_risk": ("BRUTE_FORCE_RISK",),
        "race_condition_risk": ("RACE_CONDITION",),
        "session_fixation_risk": ("SESSION_FIXATION",),
        "weak_password_requirements": ("WEAK_PASSWORD",),
        "payment_tampering": ("PAYMENT_TAMPER",),
        "session_expiration_risk": ("SESSION_EXPIRATION",),
        "password_recovery_weakness": ("PWD_RECOVERY",),
        "mass_assignment_risk": ("MASS_ASSIGNMENT",),
        # ── 4 个新增鉴权覆盖查询 ──
        "class_level_auth": ("CLASS_AUTH",),
        "aop_auth_aspects": ("AOP_AUTH",),
        "custom_auth_annotations": ("CUSTOM_AUTH_ANNOTATION",),
        "framework_security_defaults": ("ENABLE_SECURITY", "HAS_FILTER_CHAIN", "NO_CUSTOM_FILTER_CHAIN"),
    }
    _LOGIC_CANDIDATE_PRIORITY: Dict[str, int] = LOGIC_CANDIDATE_PRIORITY
    # 增量重试某 Joern query 时，需重新 LLM 分析的候选类型
    _LOGIC_QUERY_AFFECTED_CANDIDATE_TYPES: Dict[str, tuple] = {
        "auth_guards": ("missing_auth", "public_endpoint"),
        "sensitive_operations": ("missing_auth",),
        "public_endpoints": ("missing_auth", "public_endpoint"),
        "admin_ops_no_auth": ("admin_no_auth",),
        "idor_candidates": ("idor",),
        "idor_path_variable": ("idor_pathvar",),
        "idor_profile": ("idor_profile",),
        "jwt_weakness": ("jwt_weakness",),
        "jwt_endpoints": ("jwt_endpoint",),
        "hardcoded_credentials_v2": ("hardcoded_cred",),
        "info_leak_candidates": ("info_leak",),
        "info_leak_response": ("info_leak_response",),
        "csrf_gap": ("csrf_gap",),
        "ssrf_risk": ("ssrf_risk",),
        "business_logic_risk": ("business_logic_risk",),
        "workflow_bypass": ("workflow_bypass",),
        "incorrect_authz_source": ("incorrect_authz",),
        "client_hash_auth": ("client_hash_auth",),
        "auth_weakness": ("auth_weakness",),
        "business_authz_gap": ("business_authz_gap",),
        "toctou_risk": ("toctou_risk",),
        "cors_config": ("cors_misconfig",),
        "mass_data_exposure": ("mass_exposure",),
        "file_ops_risk": ("file_ops",),
        "sqli_risk": ("sqli_risk",),
        "xxe_risk": ("xxe_risk",),
        "deserialization_risk": ("deser_risk",),
        "cmd_exec_risk": ("cmd_exec_risk",),
        "xss_output_risk": ("xss_output_risk",),
        "shiro_auth_guards": ("shiro_missing_auth", "missing_auth"),
        "shiro_security_config": ("shiro_missing_auth", "missing_auth"),
        "jaxrs_auth_guards": ("jaxrs_missing_auth", "missing_auth"),
        "jaxrs_unprotected_resources": ("jaxrs_missing_auth", "public_endpoint"),
        # 新增查询→候选类型映射
        "privilege_escalation": ("privilege_escalation",),
        "incorrect_permissions": ("incorrect_permissions",),
        "brute_force_risk": ("brute_force_risk",),
        "race_condition_risk": ("race_condition_risk",),
        "session_fixation_risk": ("session_fixation_risk",),
        "weak_password_requirements": ("weak_password_requirements",),
        "payment_tampering": ("payment_tampering",),
        "session_expiration_risk": ("session_expiration_risk",),
        "password_recovery_weakness": ("password_recovery_risk",),
        "mass_assignment_risk": ("mass_assignment_risk",),
        "class_level_auth": ("missing_auth", "public_endpoint"),
        "custom_auth_annotations": ("missing_auth", "public_endpoint"),
        "framework_security_defaults": ("missing_auth", "public_endpoint"),
    }

    @staticmethod
    def _logic_candidate_key(candidate: Dict[str, Any]) -> str:
        return "|".join([
            str(candidate.get("type") or ""),
            str(candidate.get("file") or ""),
            str(candidate.get("line") or ""),
            str(candidate.get("caller") or ""),
        ])

    @staticmethod
    def _logic_finding_key(finding: Dict[str, Any]) -> str:
        return "|".join([
            str(finding.get("candidate_type") or finding.get("type") or ""),
            str(finding.get("file") or ""),
            str(finding.get("line") or ""),
            str(finding.get("candidate_id") or ""),
        ])

    def run_recon(
        self,
        *,
        language: str = "java",
        force: bool = False,
    ) -> Dict[str, Any]:
        """
        侦查阶段：生成攻击面地图，作为 logic_scan / taint_scan 的前置 Phase。

        Args:
            language: 目标语言（用于适配器选择）。
            force: 强制重新侦查（忽略缓存）。

        Returns:
            包含 attack_surface 字典的结果，兼容 run_logic_scan 返回结构。
        """
        if not self.ensure_cpg_loaded():
            logger.warning("Recon: CPG 未加载，跳过侦查")
            return {"ok": False, "attack_surface": None}

        from recon import ReconEngine
        engine = ReconEngine(
            scanner=self,
            project_name=self.project_name,
        )
        # 传入本地源文件路径（URL 提取需要读取源文件）
        source_path = self.local_source_path or self.source_path or ""
        attack_map = engine.run(source_path, force=force, language=language)
        # 将 Recon 原始 Joern 查询结果透传，供 logic_scan 复用重叠查询
        raw_results = getattr(engine, "_raw_query_results", None)
        return {
            "ok": True,
            "attack_surface": attack_map.to_dict(),
            "attack_surface_summary": attack_map.coverage_summary,
            "recon_summary": attack_map.summary(),
            "recon_query_results": raw_results,
        }

    def run_logic_scan(
        self,
        *,
        language: str = "java",
        cwe_focus: Optional[List[str]] = None,
        max_candidates: int | None = None,
        incremental_query_names: Optional[List[str]] = None,
        cached_query_results: Optional[Dict[str, str]] = None,
        cached_findings: Optional[List[Dict[str, Any]]] = None,
        recon_results: Optional[Dict[str, Any]] = None,
        recon_query_merge: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        逻辑漏洞扫描：枚举端点/守卫/敏感操作，交叉分析缺失鉴权、IDOR 等逻辑漏洞。

        与 run_source_scan 的区别：不依赖 reachableByFlows 污点流，
        而是通过“枚举 → 交叉 → 候选 → LLM 深度分析”的流水线工作。

        Args:
            language: 目标框架，支持 java/spring/flask/django/express/js 等。
            cwe_focus: 可选的 CWE 编号列表（如 ["862","306"]），缩小扫描范围。
            max_candidates: 最大候选漏洞分析数量，控制 LLM 调用次数。
            incremental_query_names: 增量重试时，只执行这些查询名（而非全量）。
            cached_query_results: 增量重试时，上次扫描的查询结果（合并用）。
            cached_findings: 增量重试时，上次 LLM 分析结果（仅重分析受影响的候选类型）。

        Returns:
            与 run_targeted_source_scan 兼容的结果字典。
        """
        if not self.ensure_cpg_loaded():
            return {
                "ok": False, "flows": {}, "report": "",
                "ambiguous_flows": [], "flow_findings_index": [],
                "logic_candidates": [], "logic_report": "",
                "logic_query_results": {},
            }

        logger.info("开始逻辑漏洞扫描 (language=%s, cwe_focus=%s)", language, cwe_focus)
        cwe_focus = resolve_cwe_focus(cwe_focus)
        max_candidates = resolve_max_candidates(max_candidates)

        # 存储 Recon 结果，供 _build_logic_l2_block / _gather_logic_llm_context 读取
        self._recon_results = recon_results or {}

        # 保存当前框架，供 _analyze_logic_candidate 读取 CWE 模板的 logic_query_keywords
        self._current_logic_framework = language.lower().replace(" ", "").replace("-", "").replace("_", "")

        # 1. 执行枚举查询（按框架选择对应查询集）
        logic_queries = queries.get_logic_queries(framework=language)
        if cwe_focus:
            needed_types: set = set()
            for cwe_id in cwe_focus:
                normalized = cwe_id.replace("CWE-", "").strip()
                for q_type in self._LOGIC_CWE_QUERY_MAP.get(normalized, []):
                    needed_types.add(q_type)
            # endpoint_enumeration 是基础查询，始终保留
            needed_types.add("endpoint_enumeration")
            if needed_types:
                logic_queries = {k: v for k, v in logic_queries.items() if k in needed_types}

        # 增量重试：只执行指定查询
        if incremental_query_names:
            retry_names = set(incremental_query_names)
            logic_queries = {k: v for k, v in logic_queries.items() if k in retry_names}
            logger.info(
                "增量重试: 只执行 %d 个失败查询 %s",
                len(logic_queries), list(logic_queries.keys()),
            )

        # ── 从 recon_results 中提取原始 Joern 查询结果，作为 checkpoint_merge
        #    传给 _run_query_map，跳过重叠的 13 个查询 ──
        if recon_query_merge is None and recon_results and isinstance(recon_results, dict):
            rqr = recon_results.get("recon_query_results")
            if rqr and isinstance(rqr, dict):
                recon_query_merge = rqr
                logger.info("Recon 查询复用: 将 %d 个 Recon 查询结果作为预缓存传给 logic_scan", len(rqr))

        query_results = self._run_query_map(
            logic_queries,
            log_prefix="逻辑漏洞查询",
            query_source="queries_py_logic",
            checkpoint_namespace=LOGIC_QUERY_CHECKPOINT_NS,
            checkpoint_merge=recon_query_merge,
        )
        query_batch_meta = dict(getattr(self, "_last_query_batch_meta", {}) or {})

        # 增量重试：合并上次缓存的查询结果
        if cached_query_results:
            merged = dict(cached_query_results)
            merged.update(query_results)  # 新结果覆盖旧缓存
            query_results = merged
            logger.info("增量合并: 缓存 %d + 新执行 %d = 总计 %d 个查询结果",
                        len(cached_query_results), len(logic_queries), len(query_results))

        # 2. 解析查询结果，提取候选漏洞
        all_candidates = self._extract_logic_candidates(query_results, cwe_focus)
        logic_query_stats = self._compute_logic_query_stats(
            query_results, failed_queries=set(query_batch_meta.get("failed_transport") or []),
        )
        logger.info(
            "逻辑漏洞候选: %d 个（分析上限 %d）",
            len(all_candidates), max_candidates,
        )

        if not all_candidates:
            empty_report = self._build_logic_scan_report(
                [], query_results, query_batch_meta=query_batch_meta,
                funnel_meta={
                    "total_extracted": 0,
                    "max_candidates": max_candidates,
                    "cwe_focus": cwe_focus,
                },
            )
            return {
                "ok": True, "flows": {}, "report": empty_report,
                "ambiguous_flows": [], "flow_findings_index": [],
                "logic_candidates": [], "logic_report": empty_report,
                "logic_findings": [], "logic_inconclusive": [],
                "logic_query_stats": logic_query_stats,
                "logic_query_failures": query_batch_meta.get("failed_transport", []),
                "logic_query_results": query_results,
                "recon_results": getattr(self, "_recon_results", None),
            }

        candidates = self._prioritize_logic_candidates(all_candidates, max_candidates)

        # 3. 加载 CWE skill 模板作为分析指导
        cwe_skills = self._load_cwe_skill_templates(cwe_focus, language=language)

        # 保存当前 focus CWE 编号集合，供 _build_companion_guidance 读取
        self._current_cwe_focus_nums = (
            {c.replace("CWE-", "").strip() for c in cwe_focus}
            if cwe_focus else None
        )

        # 4. LLM 逐候选分析（磁盘检查点：按候选 + input_fingerprint，非全局失效）
        llm_by_key = self._load_logic_llm_checkpoint()

        incremental = bool(incremental_query_names) or bool(cached_findings)
        affected_types: set = set()
        if incremental:
            for qname in incremental_query_names or []:
                affected_types.update(
                    self._LOGIC_QUERY_AFFECTED_CANDIDATE_TYPES.get(qname, ())
                )

        if cached_findings:
            for f in cached_findings:
                ctype = str(f.get("candidate_type") or f.get("type") or "")
                if incremental and affected_types and ctype and ctype in affected_types:
                    continue
                ckey = self._logic_candidate_key({
                    "type": ctype,
                    "file": f.get("file"),
                    "line": f.get("line"),
                    "caller": f.get("caller") or f.get("method") or "",
                })
                llm_by_key.setdefault(ckey, f)
            logger.info(
                "%s合并 %d 条会话缓存结论，受影响类型 %s",
                "增量重试: " if incremental_query_names else "",
                len(cached_findings),
                sorted(affected_types) if affected_types else (
                    "(无指定，全量复用)" if incremental else "(全部)"
                ),
            )

        pending_llm: List[tuple] = []
        cache_hits = 0
        incremental_reuse = 0
        total_candidates = len(candidates)
        # 加载持久化的 Joern 源码回查缓存，避免同项目重跑时重复 HTTP 查询
        self._load_joern_source_cache()
        for i, candidate in enumerate(candidates):
            if (i + 1) % 50 == 0 or i == 0:
                logger.info(
                    "指纹计算进度 %d/%d（缓存命中 %d，Joern 查询缓存: method=%d, caller_chain=%d, matrix=%d, siblings=%d, entity=%d）",
                    i + 1, total_candidates, cache_hits,
                    len(self._method_source_cache),
                    len(self._caller_chain_source_cache),
                    len(self._protection_matrix_cache),
                    len(self._service_siblings_cache),
                    len(self._entity_fields_cache),
                )
            ctx = self._gather_logic_llm_context(candidate, query_results, cwe_skills)
            input_fp = self._logic_llm_input_fingerprint(ctx)
            # 每 10 个候选增量保存 Joern 查询缓存，防止中途崩溃丢失结果
            if (i + 1) % 10 == 0:
                self._save_joern_source_cache()
            ctype = str(candidate.get("type") or "")
            if self._logic_llm_cache_hit(
                candidate,
                llm_by_key,
                input_fp,
                incremental=incremental,
                affected_types=affected_types,
            ):
                cache_hits += 1
                if (
                    incremental
                    and affected_types
                    and ctype not in affected_types
                    and llm_by_key.get(self._logic_candidate_key(candidate), {}).get(
                        "input_fingerprint"
                    ) != input_fp
                ):
                    incremental_reuse += 1
                continue
            pending_llm.append((candidate, ctx, input_fp))

        if cache_hits:
            logger.info(
                "LLM 缓存命中 %d 个候选（增量跳过指纹 %d），待调用 LLM %d 个",
                cache_hits,
                incremental_reuse,
                len(pending_llm),
            )

        # 指纹计算完成，立即保存 Joern 查询缓存（防止后续 LLM 阶段崩溃丢失）
        self._save_joern_source_cache()

        companion_findings_all: List[Dict[str, Any]] = []

        for idx, (candidate, ctx, input_fp) in enumerate(pending_llm):
            logger.info(
                "逻辑漏洞分析 %d/%d: %s",
                idx + 1, len(pending_llm), candidate.get("type", "unknown"),
            )
            finding = self._analyze_logic_candidate(
                candidate, query_results, cwe_skills, gathered_context=ctx,
            )
            ckey = self._logic_candidate_key(candidate)
            if finding:
                finding["input_fingerprint"] = input_fp
                # ── Fan out companion verdicts ──
                companion_verdicts = finding.pop("companion_verdicts", []) or []
                for cv in companion_verdicts:
                    comp_cwe = str(cv.get("cwe", "")).replace("CWE-", "").strip()
                    if not comp_cwe or cv.get("refutation_verdict") == "rejected":
                        continue
                    comp_finding = {
                        "cwe": f"CWE-{comp_cwe}",
                        "candidate_type": f"companion_{comp_cwe}",
                        "candidate_id": f"comp_{comp_cwe}_{candidate.get('id', 0)}",
                        "confirmed": cv.get("confirmed", False),
                        "confidence": cv.get("confidence", 0),
                        "refutation_verdict": cv.get("refutation_verdict", "inconclusive"),
                        "summary": cv.get("summary", ""),
                        "reasoning": cv.get("summary", ""),
                        "exploit_poc": cv.get("exploit_poc", ""),
                        "fix_code": cv.get("fix_code", ""),
                        "remediation": cv.get("remediation", ""),
                        "file": candidate.get("file", ""),
                        "line": candidate.get("line", 0),
                        "caller": candidate.get("caller", ""),
                        "evidence": candidate.get("evidence", ""),
                        "is_companion_finding": True,
                        "input_fingerprint": input_fp,
                    }
                    # confirmed=true requires exploit_poc
                    if comp_finding["confirmed"] and not str(comp_finding.get("exploit_poc") or "").strip():
                        comp_finding["confirmed"] = False
                        comp_finding["refutation_verdict"] = "rejected"
                    companion_findings_all.append(comp_finding)
            llm_by_key[ckey] = finding or {
                "confirmed": False,
                "candidate_type": candidate.get("type"),
                "file": candidate.get("file"),
                "line": candidate.get("line"),
                "input_fingerprint": input_fp,
                "skipped_empty": True,
            }
            self._save_logic_llm_checkpoint(llm_by_key)

        # 持久化 Joern 源码回查缓存，同项目下次扫描直接复用
        self._save_joern_source_cache()

        findings = [
            f for f in (
                llm_by_key.get(self._logic_candidate_key(c)) for c in candidates
            )
            if f and not f.get("skipped_empty")
        ]
        # 合并 companion findings
        findings.extend(companion_findings_all)
        if companion_findings_all:
            logger.info(
                "关联 CWE 分析产出 %d 条额外 finding",
                len(companion_findings_all),
            )

        # 5. 生成报告
        findings = self._dedupe_logic_findings(findings)
        inconclusive = [
            f for f in findings
            if str(f.get("refutation_verdict") or "").lower() == "inconclusive"
        ]
        funnel_meta = {
            "total_extracted": len(all_candidates),
            "analyzed": len(candidates),
            "max_candidates": max_candidates,
            "cwe_focus": cwe_focus,
            "skipped_by_cap": max(0, len(all_candidates) - len(candidates)),
            "type_breakdown_extracted": self._logic_candidate_type_counts(all_candidates),
            "type_breakdown_analyzed": self._logic_candidate_type_counts(candidates),
        }
        report = self._build_logic_scan_report(
            findings, query_results, query_batch_meta=query_batch_meta,
            funnel_meta=funnel_meta,
        )

        # 构造 flow_findings_index
        flow_findings = []
        for f in findings:
            if f.get("confirmed"):
                flow_findings.append({
                    "flow_id": f"logic_{f.get('cwe', 'unknown')}_{f.get('candidate_id', '')}",
                    "vuln_type": f.get("cwe", "logic_vulnerability"),
                    "confidence": f.get("confidence", 0),
                    "verdict": "confirmed",
                    "summary": f.get("summary", ""),
                    "file": f.get("file", ""),
                    "line": f.get("line", 0),
                })

        # logic 检查点（cpg_logic.json / cpg_logic_llm.json）成功扫描后亦保留，同项目重跑仅补新 query 与新候选 LLM。

        return {
            "ok": True,
            "flows": {},
            "report": report,
            "ambiguous_flows": [],
            "flow_findings_index": flow_findings,
            "logic_candidates": candidates,
            "logic_findings": findings,
            "logic_inconclusive": inconclusive,
            "logic_query_stats": logic_query_stats,
            "logic_report": report,
            "logic_query_failures": query_batch_meta.get("failed_transport", []),
            "logic_query_results": query_results,
            "recon_results": getattr(self, "_recon_results", None),
        }

    def _extract_logic_candidates(
        self, query_results: Dict[str, str], cwe_focus: Optional[List[str]]
    ) -> List[Dict[str, Any]]:
        """从查询结果中提取逻辑漏洞候选（交叉分析）。"""
        candidates: List[Dict[str, Any]] = []

        guarded_methods = self._parse_guarded_methods(
            "\n".join(
                [
                    query_results.get("auth_guards", ""),
                    query_results.get("shiro_auth_guards", ""),
                    query_results.get("jaxrs_auth_guards", ""),
                ]
            )
        )

        # ── ② 类级鉴注解：把有 @PreAuthorize 等类级注解的类的所有方法加入 guarded ──
        class_auth_type_names: set = set()
        for line in (query_results.get("class_level_auth") or "").splitlines():
            line = line.strip().strip('",')
            m = re.search(r'CLASS_AUTH\s*\|\s*([^\s|]+)', line)
            if m:
                class_auth_type_names.add(m.group(1).strip())
        if class_auth_type_names:
            # 从 endpoint_enumeration 结果中找到这些类的所有方法
            for line in (query_results.get("endpoint_enumeration") or "").splitlines():
                line = line.strip().strip('",')
                parts = line.split("|")
                if parts:
                    method_full = parts[0].strip()
                    for cls_name in class_auth_type_names:
                        if method_full.startswith(cls_name + "."):
                            guarded_methods.add(method_full)
                            break

        # ── ④ 自定义鉴权注解：把带有 @RequirePerm / @DataScope 等自定义注解的方法加入 guarded ──
        for line in (query_results.get("custom_auth_annotations") or "").splitlines():
            line = line.strip().strip('",')
            m = re.search(r'method=([^\s|]+)', line)
            if m:
                guarded_methods.add(m.group(1).strip())
        shiro_guarded_methods = self._parse_guarded_methods(
            query_results.get("shiro_auth_guards", "")
        )
        shiro_stack_detected = bool(
            self._parse_tagged_lines(
                query_results.get("shiro_security_config", ""), "SHIRO_CONFIG"
            )
            or self._parse_tagged_lines(
                query_results.get("shiro_auth_guards", ""),
                "SHIRO_ANNOTATION_GUARD",
                "SHIRO_CODE_GUARD",
            )
        )
        sensitive_ops = self._parse_tagged_lines(
            query_results.get("sensitive_operations", ""), "SENSITIVE_OP"
        )
        idor_ops = self._parse_tagged_lines(
            query_results.get("idor_candidates", ""), "IDOR_CANDIDATE"
        )
        info_leaks = self._parse_tagged_lines(
            query_results.get("info_leak_candidates", ""),
            "EXCEPTION_LEAK", "SENSITIVE_LOG"
        )
        hardcoded = self._parse_tagged_lines(
            query_results.get("hardcoded_credentials_v2", ""), "HARDCODED_CRED"
        )
        cors_items = self._parse_tagged_lines(
            query_results.get("cors_config", ""), "CORS_CONFIG"
        )
        idor_pathvar_items = self._parse_tagged_lines(
            query_results.get("idor_path_variable", ""),
            "IDOR_PATHVAR", "IDOR_REQPARAM"
        )
        admin_no_auth_items = self._parse_tagged_lines(
            query_results.get("admin_ops_no_auth", ""), "ADMIN_OP_NO_AUTH"
        )
        jwt_items = self._parse_tagged_lines(
            query_results.get("jwt_weakness", ""),
            "JWT_WEAK_SECRET", "JWT_NO_VERIFY", "JWT_ALG_CONFUSION"
        )
        file_ops_items = self._parse_tagged_lines(
            query_results.get("file_ops_risk", ""), "FILE_OPS_RISK"
        )
        mass_exposure_items = self._parse_tagged_lines(
            query_results.get("mass_data_exposure", ""), "MASS_DATA_EXPOSURE"
        )
        public_eps = self._parse_tagged_lines(
            query_results.get("public_endpoints", ""), "PUBLIC_ENDPOINT"
        )
        sqli_items = self._parse_tagged_lines(
            query_results.get("sqli_risk", ""), "SQLI_RISK", "SQLI_NATIVE"
        )
        xxe_items = self._parse_tagged_lines(
            query_results.get("xxe_risk", ""), "XXE_RISK"
        )
        deser_items = self._parse_tagged_lines(
            query_results.get("deserialization_risk", ""), "DESER_RISK"
        )
        cmd_exec_items = self._parse_tagged_lines(
            query_results.get("cmd_exec_risk", ""), "CMD_EXEC_RISK"
        )
        idor_profile_items = self._parse_tagged_lines(
            query_results.get("idor_profile", ""), "IDOR_PROFILE"
        )
        jwt_endpoint_items = self._parse_tagged_lines(
            query_results.get("jwt_endpoints", ""), "JWT_ENDPOINT"
        )
        info_leak_response_items = self._parse_tagged_lines(
            query_results.get("info_leak_response", ""), "RESPONSE_LEAK"
        )
        csrf_gap_items = self._parse_tagged_lines(
            query_results.get("csrf_gap", ""), "CSRF_GAP"
        )
        toctou_items = self._parse_tagged_lines(
            query_results.get("toctou_risk", ""), "TOCTOU_RISK"
        )
        ssrf_items = self._parse_tagged_lines(
            query_results.get("ssrf_risk", ""), "SSRF_RISK"
        )
        bizlogic_items = self._parse_tagged_lines(
            query_results.get("business_logic_risk", ""), "BIZLOGIC_RISK"
        )
        workflow_items = self._parse_tagged_lines(
            query_results.get("workflow_bypass", ""), "WORKFLOW_BYPASS"
        )
        untrusted_authz_items = self._parse_tagged_lines(
            query_results.get("incorrect_authz_source", ""), "UNTRUSTED_AUTHZ"
        )
        client_hash_items = self._parse_tagged_lines(
            query_results.get("client_hash_auth", ""), "CLIENT_HASH_AUTH"
        )
        auth_weak_items = self._parse_tagged_lines(
            query_results.get("auth_weakness", ""), "AUTH_WEAKNESS"
        )
        biz_authz_gap_items = self._parse_tagged_lines(
            query_results.get("business_authz_gap", ""), "BIZ_AUTHZ_GAP"
        )
        xss_output_items = self._parse_tagged_lines(
            query_results.get("xss_output_risk", ""), "XSS_OUTPUT_RISK"
        )
        jaxrs_unprotected_items = self._parse_tagged_lines(
            query_results.get("jaxrs_unprotected_resources", ""), "JAXRS_UNPROTECTED"
        )
        # 新增逻辑漏洞查询结果解析
        priv_escalation_items = self._parse_tagged_lines(
            query_results.get("privilege_escalation", ""), "PRIV_ESCALATION"
        )
        incorrect_perm_items = self._parse_tagged_lines(
            query_results.get("incorrect_permissions", ""), "PERM_RISK"
        )
        brute_force_items = self._parse_tagged_lines(
            query_results.get("brute_force_risk", ""), "BRUTE_FORCE_RISK"
        )
        race_condition_items = self._parse_tagged_lines(
            query_results.get("race_condition_risk", ""), "RACE_CONDITION"
        )
        session_fixation_items = self._parse_tagged_lines(
            query_results.get("session_fixation_risk", ""), "SESSION_FIXATION"
        )
        weak_password_items = self._parse_tagged_lines(
            query_results.get("weak_password_requirements", ""), "WEAK_PASSWORD"
        )
        payment_tamper_items = self._parse_tagged_lines(
            query_results.get("payment_tampering", ""), "PAYMENT_TAMPER"
        )
        session_expiration_items = self._parse_tagged_lines(
            query_results.get("session_expiration_risk", ""), "SESSION_EXPIRATION"
        )
        pwd_recovery_items = self._parse_tagged_lines(
            query_results.get("password_recovery_weakness", ""), "PWD_RECOVERY"
        )
        mass_assignment_items = self._parse_tagged_lines(
            query_results.get("mass_assignment_risk", ""), "MASS_ASSIGNMENT"
        )

        public_method_names = {
            self._logic_candidate_method_key(ep) for ep in public_eps
        }
        public_method_names.discard("")

        cid = 0

        # CWE-862/306: 敏感操作无鉴权守卫（可与公开端点交叉加权）
        for op in sensitive_ops:
            caller = self._logic_candidate_method_key(op)
            if caller and caller not in guarded_methods:
                cid += 1
                cross_signals: List[str] = []
                if caller in public_method_names:
                    cross_signals.append("public_endpoint_without_auth")
                candidate = {
                    "id": cid, "type": "missing_auth", "cwe": logic_candidate_cwe("missing_auth"),
                    "candidate_id": f"auth_{cid}",
                    "caller": caller, "operation": op.get("name", ""),
                    "file": op.get("file", ""), "line": op.get("line", 0),
                    "evidence": op.get("raw_line", ""),
                    "cross_signals": cross_signals,
                }
                self._enrich_logic_candidate_location(candidate)
                candidates.append(candidate)

        if shiro_stack_detected:
            for op in sensitive_ops:
                caller = self._logic_candidate_method_key(op)
                if not caller:
                    continue
                if caller in shiro_guarded_methods or caller in guarded_methods:
                    continue
                cid += 1
                candidate = {
                    "id": cid,
                    "type": "shiro_missing_auth",
                    "cwe": logic_candidate_cwe("shiro_missing_auth"),
                    "candidate_id": f"shiro_{cid}",
                    "caller": caller,
                    "operation": op.get("name", ""),
                    "file": op.get("file", ""),
                    "line": op.get("line", 0),
                    "evidence": op.get("raw_line", ""),
                    "cross_signals": ["shiro_stack_without_method_guard"],
                }
                self._enrich_logic_candidate_location(candidate)
                candidates.append(candidate)

        for item in jaxrs_unprotected_items:
            caller = self._logic_candidate_method_key(item)
            if caller and caller in guarded_methods:
                continue
            cid += 1
            candidate = {
                "id": cid,
                "type": "jaxrs_missing_auth",
                "cwe": logic_candidate_cwe("jaxrs_missing_auth"),
                "candidate_id": f"jaxrs_{cid}",
                "caller": caller or item.get("raw_line", "")[:80],
                "file": item.get("file", ""),
                "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
                "cross_signals": ["jaxrs_path_without_roles_allowed"],
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        # CWE-639: IDOR 候选
        for op in idor_ops:
            cid += 1
            candidate = {
                "id": cid, "type": "idor", "cwe": logic_candidate_cwe("idor"),
                "candidate_id": f"idor_{cid}",
                "caller": self._logic_candidate_method_key(op),
                "operation": op.get("name", ""),
                "file": op.get("file", ""), "line": op.get("line", 0),
                "evidence": op.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        # CWE-200: 信息泄露
        for item in info_leaks:
            cid += 1
            candidate = {
                "id": cid, "type": "info_leak", "cwe": logic_candidate_cwe("info_leak"),
                "candidate_id": f"leak_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        # CWE-798: 硬编码凭证
        for item in hardcoded:
            cid += 1
            literal_val = (item.get("value") or "").strip().strip('"').strip("'")
            candidate = {
                "id": cid, "type": "hardcoded_cred", "cwe": logic_candidate_cwe("hardcoded_cred"),
                "candidate_id": f"cred_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            if literal_val:
                candidate["source_literal"] = literal_val
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        # CWE-284: CORS/访问控制配置缺陷
        for item in cors_items:
            cid += 1
            candidate = {
                "id": cid, "type": "cors_misconfig", "cwe": logic_candidate_cwe("cors_misconfig"),
                "candidate_id": f"cors_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        # CWE-639 深度: IDOR PathVariable/RequestParam 直接作为资源标识符
        for item in idor_pathvar_items:
            cid += 1
            tag = "idor_pathvar"
            candidate = {
                "id": cid, "type": tag, "cwe": logic_candidate_cwe(tag),
                "candidate_id": f"idorpv_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        # CWE-862: 管理级操作无角色校验
        for item in admin_no_auth_items:
            cid += 1
            candidate = {
                "id": cid, "type": "admin_no_auth", "cwe": logic_candidate_cwe("admin_no_auth"),
                "candidate_id": f"admin_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
                "cross_signals": ["admin_op_without_role_check"],
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        # CWE-341/330: JWT 弱点（弱密钥/弱随机/算法混淆）
        for item in jwt_items:
            cid += 1
            candidate = {
                "id": cid, "type": "jwt_weakness", "cwe": logic_candidate_cwe("jwt_weakness"),
                "candidate_id": f"jwt_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        for item in jwt_endpoint_items:
            cid += 1
            candidate = {
                "id": cid, "type": "jwt_endpoint", "cwe": logic_candidate_cwe("jwt_endpoint"),
                "candidate_id": f"jwtep_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        for item in idor_profile_items:
            cid += 1
            candidate = {
                "id": cid, "type": "idor_profile", "cwe": logic_candidate_cwe("idor_profile"),
                "candidate_id": f"idprof_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        for item in info_leak_response_items:
            cid += 1
            candidate = {
                "id": cid, "type": "info_leak_response", "cwe": logic_candidate_cwe("info_leak_response"),
                "candidate_id": f"respleak_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        for item in csrf_gap_items:
            cid += 1
            candidate = {
                "id": cid, "type": "csrf_gap", "cwe": logic_candidate_cwe("csrf_gap"),
                "candidate_id": f"csrf_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        for item in toctou_items:
            cid += 1
            candidate = {
                "id": cid, "type": "toctou_risk", "cwe": logic_candidate_cwe("toctou_risk"),
                "candidate_id": f"toctou_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        for item in ssrf_items:
            cid += 1
            candidate = {
                "id": cid, "type": "ssrf_risk", "cwe": logic_candidate_cwe("ssrf_risk"),
                "candidate_id": f"ssrf_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        for item in bizlogic_items:
            cid += 1
            candidate = {
                "id": cid, "type": "business_logic_risk", "cwe": logic_candidate_cwe("business_logic_risk"),
                "candidate_id": f"bizlogic_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        for item in workflow_items:
            cid += 1
            candidate = {
                "id": cid, "type": "workflow_bypass", "cwe": logic_candidate_cwe("workflow_bypass"),
                "candidate_id": f"workflow_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        for item in untrusted_authz_items:
            cid += 1
            candidate = {
                "id": cid, "type": "incorrect_authz", "cwe": logic_candidate_cwe("incorrect_authz"),
                "candidate_id": f"authzsrc_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        for item in client_hash_items:
            cid += 1
            candidate = {
                "id": cid, "type": "client_hash_auth", "cwe": logic_candidate_cwe("client_hash_auth"),
                "candidate_id": f"clhash_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        for item in auth_weak_items:
            cid += 1
            candidate = {
                "id": cid, "type": "auth_weakness", "cwe": logic_candidate_cwe("auth_weakness"),
                "candidate_id": f"authweak_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        for item in biz_authz_gap_items:
            cid += 1
            candidate = {
                "id": cid, "type": "business_authz_gap", "cwe": logic_candidate_cwe("business_authz_gap"),
                "candidate_id": f"bizauthz_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        for item in xss_output_items:
            cid += 1
            candidate = {
                "id": cid, "type": "xss_output_risk", "cwe": logic_candidate_cwe("xss_output_risk"),
                "candidate_id": f"xss_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        # CWE-22: 文件操作风险（用户可控路径）
        for item in file_ops_items:
            cid += 1
            candidate = {
                "id": cid, "type": "file_ops", "cwe": logic_candidate_cwe("file_ops"),
                "candidate_id": f"fileops_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        # CWE-200: 批量数据暴露（服务端未过滤敏感字段）
        for item in mass_exposure_items:
            cid += 1
            candidate = {
                "id": cid, "type": "mass_exposure", "cwe": logic_candidate_cwe("mass_exposure"),
                "candidate_id": f"massexp_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        # CWE-89: SQL 注入风险（字符串拼接构造 SQL）
        for item in sqli_items:
            cid += 1
            candidate = {
                "id": cid, "type": "sqli_risk", "cwe": logic_candidate_cwe("sqli_risk"),
                "candidate_id": f"sqli_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        # CWE-611: XXE 风险（XML 解析器未禁用外部实体）
        for item in xxe_items:
            cid += 1
            candidate = {
                "id": cid, "type": "xxe_risk", "cwe": logic_candidate_cwe("xxe_risk"),
                "candidate_id": f"xxe_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        # CWE-502: 反序列化风险（不安全反序列化）
        for item in deser_items:
            cid += 1
            candidate = {
                "id": cid, "type": "deser_risk", "cwe": logic_candidate_cwe("deser_risk"),
                "candidate_id": f"deser_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        # CWE-78: 命令注入风险（Runtime.exec/ProcessBuilder）
        for item in cmd_exec_items:
            cid += 1
            candidate = {
                "id": cid, "type": "cmd_exec_risk", "cwe": logic_candidate_cwe("cmd_exec_risk"),
                "candidate_id": f"cmd_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        # CWE-269: 权限提升 / 角色操纵
        for item in priv_escalation_items:
            cid += 1
            candidate = {
                "id": cid, "type": "privilege_escalation", "cwe": logic_candidate_cwe("privilege_escalation"),
                "candidate_id": f"privesc_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        # CWE-276: 不正确的默认权限
        for item in incorrect_perm_items:
            cid += 1
            candidate = {
                "id": cid, "type": "incorrect_permissions", "cwe": logic_candidate_cwe("incorrect_permissions"),
                "candidate_id": f"perm_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        # CWE-307: 认证入口缺少暴力破解防护
        for item in brute_force_items:
            cid += 1
            candidate = {
                "id": cid, "type": "brute_force_risk", "cwe": logic_candidate_cwe("brute_force_risk"),
                "candidate_id": f"brute_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        # CWE-362: 竞态条件 / 不正确的同步
        for item in race_condition_items:
            cid += 1
            candidate = {
                "id": cid, "type": "race_condition_risk", "cwe": logic_candidate_cwe("race_condition_risk"),
                "candidate_id": f"race_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        # CWE-384: 会话固定
        for item in session_fixation_items:
            cid += 1
            candidate = {
                "id": cid, "type": "session_fixation_risk", "cwe": logic_candidate_cwe("session_fixation_risk"),
                "candidate_id": f"sessfix_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        # CWE-521: 弱密码复杂度要求
        for item in weak_password_items:
            cid += 1
            candidate = {
                "id": cid, "type": "weak_password_requirements", "cwe": logic_candidate_cwe("weak_password_requirements"),
                "candidate_id": f"weakpwd_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        # CWE-610: 外部可控引用（支付/订单金额篡改）
        for item in payment_tamper_items:
            cid += 1
            candidate = {
                "id": cid, "type": "payment_tampering", "cwe": logic_candidate_cwe("payment_tampering"),
                "candidate_id": f"paytamper_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        # CWE-613: 不充分的会话过期
        for item in session_expiration_items:
            cid += 1
            candidate = {
                "id": cid, "type": "session_expiration_risk", "cwe": logic_candidate_cwe("session_expiration_risk"),
                "candidate_id": f"sess_exp_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        # CWE-640: 弱密码恢复机制
        for item in pwd_recovery_items:
            cid += 1
            candidate = {
                "id": cid, "type": "password_recovery_risk", "cwe": logic_candidate_cwe("password_recovery_risk"),
                "candidate_id": f"pwdrecov_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        # CWE-915: 批量赋值（Mass Assignment）
        for item in mass_assignment_items:
            cid += 1
            candidate = {
                "id": cid, "type": "mass_assignment_risk", "cwe": logic_candidate_cwe("mass_assignment_risk"),
                "candidate_id": f"massassign_{cid}",
                "caller": self._logic_candidate_method_key(item),
                "file": item.get("file", ""), "line": item.get("line", 0),
                "evidence": item.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        # 公开端点补充（跳过已在 missing_auth 交叉中覆盖的）
        for ep in public_eps:
            caller = self._logic_candidate_method_key(ep)
            if caller and caller in guarded_methods:
                continue
            cid += 1
            candidate = {
                "id": cid, "type": "public_endpoint", "cwe": logic_candidate_cwe("public_endpoint"),
                "candidate_id": f"pub_{cid}",
                "caller": caller or ep.get("raw_line", "")[:80],
                "file": ep.get("file", ""), "line": ep.get("line", 0),
                "evidence": ep.get("raw_line", ""),
            }
            self._enrich_logic_candidate_location(candidate)
            candidates.append(candidate)

        return candidates

    def _parse_guarded_methods(self, raw_text: str) -> set:
        """从 auth_guards 查询结果中提取已保护的方法全名集合。

        支持 Joern REPL 返回的 List/Vector 包装格式。
        """
        guarded: set = set()
        for line in raw_text.splitlines():
            line = line.strip()
            if not line:
                continue
            # 去除 Scala REPL List/Vector 包装元素的前后引号和逗号
            if line.startswith('"'):
                line = line[1:]
            if line.endswith('",'):
                line = line[:-2]
            elif line.endswith('"'):
                line = line[:-1]
            line = line.strip()
            if not line:
                continue
            # 跳过 Scala REPL 的 val 声明行和 List/Vector 包装行
            if line.startswith("val ") or line in ("List(", "Vector(", "Set(", ")"):
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 2:
                tag = parts[0]
                if tag == "ANNOTATION_GUARD":
                    guarded.add(parts[1])
                elif tag == "PARAM_IDENTITY_GUARD":
                    guarded.add(parts[1])
                elif tag in ("SHIRO_ANNOTATION_GUARD", "JAXRS_ANNOTATION_GUARD"):
                    guarded.add(parts[1])
                elif tag == "CODE_GUARD":
                    for part in parts[2:]:
                        if part.startswith("caller="):
                            guarded.add(part[7:])
                elif tag == "SHIRO_CODE_GUARD":
                    for part in parts[1:]:
                        if part.startswith("caller="):
                            guarded.add(part[7:])
        return guarded

    @staticmethod
    def _parse_tagged_lines(raw_text: str, *tags: str) -> List[Dict[str, Any]]:
        """解析带 TAG | key=value 格式标记的查询结果行。

        支持 Joern REPL 返回的 List/Vector 包装格式：
        - 自动去除 `val resN: List[String] = List(...)` 包装
        - 自动去除每行的前导引号 `"` 和尾部的引号+逗号 `",`
        """
        items: List[Dict[str, Any]] = []
        for line in raw_text.splitlines():
            line = line.strip()
            if not line:
                continue
            # 去除 Scala REPL List/Vector 包装元素的前后引号和逗号
            # 例如: `"IDOR_CANDIDATE | ..."`  →  `IDOR_CANDIDATE | ...`
            #        `"IDOR_CANDIDATE | ...",` →  `IDOR_CANDIDATE | ...`
            if line.startswith('"'):
                line = line[1:]
            if line.endswith('",'):
                line = line[:-2]
            elif line.endswith('"'):
                line = line[:-1]
            line = line.strip()
            if not line:
                continue
            # 跳过 Scala REPL 的 val 声明行和 List/Vector 包装行
            if line.startswith("val ") or line in ("List(", "Vector(", "Set(", ")"):
                continue
            parts = [p.strip() for p in line.split("|")]
            if not parts:
                continue
            tag = parts[0].strip()
            if tags and tag not in tags:
                continue
            item: Dict[str, Any] = {"raw_line": line, "tag": tag}
            for part in parts[1:]:
                part = part.strip()
                if "=" in part:
                    key, _, val = part.partition("=")
                    item[key.strip()] = val.strip()
                elif part:
                    item.setdefault("name", part)
            try:
                item["line"] = int(item.get("line", 0))
            except (ValueError, TypeError):
                item["line"] = 0
            if tag == "HARDCODED_CRED" and item.get("method") and not item.get("caller"):
                item["caller"] = item["method"]
            if not item.get("caller"):
                for part in parts[1:]:
                    part = part.strip()
                    if "=" in part:
                        continue
                    if "." in part and not part.startswith("arg"):
                        item["caller"] = part
                        break
            items.append(item)
        return items

    @staticmethod
    def _logic_candidate_method_key(item: Dict[str, Any]) -> str:
        for key in ("caller", "method"):
            value = str(item.get(key) or "").strip()
            if value:
                return value
        return ""

    @staticmethod
    def _enrich_logic_candidate_location(candidate: Dict[str, Any]) -> None:
        evidence = str(candidate.get("evidence") or "")
        if not candidate.get("file"):
            match = re.search(r"(?:^|\|)\s*file=([^|]+)", evidence)
            if match:
                candidate["file"] = match.group(1).strip()
        if not candidate.get("caller"):
            match = re.search(r"(?:^|\|)\s*caller=([^|]+)", evidence)
            if match:
                candidate["caller"] = match.group(1).strip()

    @staticmethod
    def _logic_candidate_dedupe_key(candidate: Dict[str, Any]) -> tuple:
        cwe = str(candidate.get("cwe") or "")
        file_path = str(candidate.get("file") or "").strip()
        line = int(candidate.get("line") or 0)
        caller = str(candidate.get("caller") or candidate.get("method") or "").strip()
        ctype = str(candidate.get("type") or "")
        if file_path or caller:
            return (cwe, file_path, line, caller, ctype)
        return (cwe, line, ctype, str(candidate.get("evidence") or "")[:120])

    @classmethod
    def _dedupe_logic_candidates(cls, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen: set = set()
        deduped: List[Dict[str, Any]] = []
        for candidate in candidates:
            key = cls._logic_candidate_dedupe_key(candidate)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(candidate)
        return deduped

    @classmethod
    def _logic_candidate_sort_key(cls, candidate: Dict[str, Any]) -> tuple:
        ctype = str(candidate.get("type") or "other")
        base = cls._LOGIC_CANDIDATE_PRIORITY.get(ctype, 9)
        if ctype in SAST_OVERLAP_CANDIDATE_TYPES:
            base = max(base, 8)
        if ctype == "missing_auth" and not candidate.get("cross_signals"):
            base = max(base, 2)
        if ctype in LOGIC_CORE_CANDIDATE_TYPES:
            base = min(base, cls._LOGIC_CANDIDATE_PRIORITY.get(ctype, base))
        return (
            base,
            0 if candidate.get("cross_signals") else 1,
            int(candidate.get("id") or 0),
        )

    @classmethod
    def _prioritize_logic_candidates(
        cls, candidates: List[Dict[str, Any]], max_candidates: int,
    ) -> List[Dict[str, Any]]:
        """分层预算：按候选优先级分层控制 LLM 调用数。

        P0（优先级 0-1）：全部分析，不设层上限
        P1（优先级 2）：最多 TIER1_MAX 个
        P2（优先级 3+）：最多 TIER2_MAX 个
        总候选数仍受 max_candidates 全局上限约束。
        """
        deduped = cls._dedupe_logic_candidates(candidates)
        cap = max(0, max_candidates)
        if cap <= 0:
            return []

        # 按优先级分桶
        tier0: Dict[str, List[Dict[str, Any]]] = {}  # priority 0-1
        tier1: Dict[str, List[Dict[str, Any]]] = {}  # priority 2
        tier2: Dict[str, List[Dict[str, Any]]] = {}  # priority 3+
        for candidate in deduped:
            ctype = str(candidate.get("type") or "other")
            pri = cls._LOGIC_CANDIDATE_PRIORITY.get(ctype, 99)
            if pri <= 1:
                bucket = tier0
            elif pri == 2:
                bucket = tier1
            else:
                bucket = tier2
            bucket.setdefault(ctype, []).append(candidate)

        # 各层内部排序
        for bucket in (tier0, tier1, tier2):
            for items in bucket.values():
                items.sort(key=cls._logic_candidate_sort_key)

        def _round_robin_pick(
            buckets: Dict[str, List[Dict[str, Any]]], limit: int,
        ) -> List[Dict[str, Any]]:
            if limit <= 0 or not buckets:
                return []
            type_order = sorted(buckets.keys(), key=lambda t: cls._logic_candidate_sort_key(
                buckets[t][0]
            ))
            indices = {t: 0 for t in type_order}
            picked: List[Dict[str, Any]] = []
            while len(picked) < limit:
                progressed = False
                for ctype in type_order:
                    idx = indices[ctype]
                    if idx < len(buckets[ctype]):
                        picked.append(buckets[ctype][idx])
                        indices[ctype] = idx + 1
                        progressed = True
                        if len(picked) >= limit:
                            break
                if not progressed:
                    break
            return picked

        tier0_n = sum(len(v) for v in tier0.values())

        # P0 层内全量；P1/P2 层内各有上限。合并顺序 P0→P1→P2，全局 cap 截断时 P0 优先占满槽位。
        p0_picked = _round_robin_pick(tier0, tier0_n)
        p1_picked = _round_robin_pick(tier1, TIER1_MAX)
        p2_picked = _round_robin_pick(tier2, TIER2_MAX)

        selected = p0_picked + p1_picked + p2_picked
        logger.info(
            "分层预算: P0=%d(全量) P1=%d(上限%d) P2=%d(上限%d) 合计=%d/%d",
            len(p0_picked), len(p1_picked), TIER1_MAX,
            len(p2_picked), TIER2_MAX, len(selected), cap,
        )
        return selected[:cap]

    @staticmethod
    def _bucket_by_type(
        candidates: List[Dict[str, Any]],
    ) -> Dict[str, List[Dict[str, Any]]]:
        buckets: Dict[str, List[Dict[str, Any]]] = {}
        for candidate in candidates:
            ctype = str(candidate.get("type") or "other")
            buckets.setdefault(ctype, []).append(candidate)
        return buckets

    @staticmethod
    def _logic_candidate_type_counts(
        candidates: List[Dict[str, Any]],
    ) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for candidate in candidates:
            ctype = str(candidate.get("type") or "other")
            counts[ctype] = counts.get(ctype, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))

    def _compute_logic_query_stats(
        self,
        query_results: Dict[str, str],
        *,
        failed_queries: Optional[set] = None,
    ) -> Dict[str, int]:
        stats: Dict[str, int] = {}
        failed = failed_queries or set()
        for qname, raw in query_results.items():
            if qname in failed:
                stats[qname] = -1
                continue
            tags = self._LOGIC_QUERY_TAGS.get(qname)
            if tags:
                stats[qname] = len(self._parse_tagged_lines(raw, *tags))
            else:
                stats[qname] = len([
                    ln for ln in raw.splitlines()
                    if ln.strip() and not ln.strip().startswith("val ")
                ])
        return stats

    @staticmethod
    def _dedupe_logic_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen: set = set()
        deduped: List[Dict[str, Any]] = []
        for finding in findings:
            key = (
                str(finding.get("cwe") or ""),
                str(finding.get("file") or "").strip(),
                int(finding.get("line") or 0),
                str(finding.get("caller") or "").strip(),
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(finding)
        return deduped

    def _format_logic_query_coverage(
        self, query_name: str, result_text: str, *, failed_queries: Optional[set] = None,
    ) -> str:
        if failed_queries and query_name in failed_queries:
            return "N/A (查询失败)"
        if self._is_joern_transport_failure(result_text):
            return "N/A (查询失败)"
        tags = self._LOGIC_QUERY_TAGS.get(query_name)
        if tags:
            count = len(self._parse_tagged_lines(result_text, *tags))
            return f"{count} 条结果"
        nonempty = [
            line for line in result_text.splitlines()
            if line.strip() and not line.strip().startswith("val ")
        ]
        return f"{len(nonempty)} 条结果"

    # 合并 cwe_logic_common.json 的 CWE（逻辑/鉴权类）
    _LOGIC_COMMON_CWE_NUMS = frozenset({
        "287", "285", "306", "639", "840", "841", "862", "863", "899",
        # 新增 P0 逻辑漏洞 CWE
        "269", "276", "307", "362", "384", "521", "610", "613", "640", "915",
    })

    def _load_cwe_logic_common(self, cwe_dir: Path) -> Dict[str, Any]:
        common_path = cwe_dir / "cwe_logic_common.json"
        if not common_path.is_file():
            return {}
        try:
            return json.loads(common_path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.debug("加载 cwe_logic_common 失败: %s", exc)
            return {}

    def _merge_cwe_logic_common(
        self, template: Dict[str, Any], common: Dict[str, Any]
    ) -> Dict[str, Any]:
        """将共享确认标准/组件扫描联动字段并入逻辑 CWE 模板（浅合并，模板字段优先）。"""
        if not common:
            return template
        merged = dict(template)
        for key in (
            "confirmation_criteria",
            "verdict_rule",
            "burp_poc_requirements",
            "component_scan_handoff",
        ):
            if key in common and key not in merged:
                merged[key] = common[key]
        base_os = dict(common.get("output_schema_extensions") or {})
        tpl_os = dict(merged.get("output_schema") or {})
        merged["output_schema"] = {**base_os, **tpl_os}
        return merged

    def _load_cwe_skill_templates(
        self, cwe_focus: Optional[List[str]], *, language: str = "java",
    ) -> Dict[str, Dict[str, Any]]:
        """加载 CWE skill 模板（优先 YAML 新目录，回退旧 JSON）。"""
        skills_dir = Path(__file__).resolve().parent / "skills"
        # 检测框架信号（用于语言特化 patterns 加载）
        framework_labels: List[str] = []
        local_source = getattr(self, "local_source_path", None)
        if local_source:
            try:
                framework_labels = skill_loader.detect_frameworks(
                    Path(local_source), language, skills_dir,
                )
            except Exception:
                pass
        return skill_loader.load_cwe_skills(
            skills_dir, cwe_focus, language, framework_labels,
        )

    def _build_companion_guidance(
        self,
        cwe_num: str,
        cwe_skills: Dict[str, Dict[str, Any]],
        focus_nums: Optional[set] = None,
    ) -> str:
        """构建伴随 CWE 的精简分析指引，注入 LLM prompt 以实现单次多 CWE 检查。

        仅包含伴随 CWE 的核心信息（原则 + 前 3 步推理 + 前 3 个反证），
        总量控制在 1500 字符以内，避免 prompt 过长。
        """
        companions = get_cwe_companions(cwe_num)
        if not companions:
            return ""
        # 过滤：仅保留在 focus 内且有模板的伴随 CWE
        if focus_nums:
            companions = tuple(c for c in companions if c in focus_nums)
        parts: List[str] = []
        total_chars = 0
        max_chars = 1500
        for comp_cwe in companions:
            skill = cwe_skills.get(comp_cwe, {})
            if not skill:
                continue
            # 1 行原则
            principle = ""
            # 从 LOGIC_CANDIDATE_CATALOG 查找 principle
            for _ctype, _meta in LOGIC_CANDIDATE_CATALOG.items():
                if _meta.get("cwe") == comp_cwe:
                    principle = _meta.get("principle", "")
                    break
            if not principle:
                principle = (skill.get("trigger_condition") or {}).get("semantic_keywords", [""])[0] if skill.get("trigger_condition") else ""
            # 前 3 步推理
            workflow = skill.get("reasoning_workflow", [])[:3]
            # 前 3 个反证
            sanitizers = skill.get("sanitizers", [])[:3]
            block_lines = [f"**CWE-{comp_cwe}**: {principle[:80]}"]
            for step in workflow:
                block_lines.append(f"  - {step[:100]}")
            for s in sanitizers:
                block_lines.append(f"  - 反证: {s[:80]}")
            block_text = "\n".join(block_lines)
            if total_chars + len(block_text) > max_chars:
                break
            parts.append(block_text)
            total_chars += len(block_text)
        return "\n\n".join(parts) if parts else ""

    def _fetch_method_source(self, method_full_name: str, max_chars: int = 8000) -> str:
        """通过 Joern 回查方法源码（复用硬回溯的 dumpRaw 模式）。

        与污点扫描硬回溯使用相同的 `.caller.dumpRaw` 机制，
        区别在于：污点扫描沿 flow 路径回溯，逻辑扫描从候选方法回溯。
        """
        if not method_full_name:
            return ""
        if method_full_name in self._method_source_cache:
            return self._method_source_cache[method_full_name]
        import re as _re
        escaped = self._escape_joern_string_literal(_re.escape(method_full_name))
        query = f'''
        cpg.method.fullName("{escaped}")
        .take(1)
        .dumpRaw
        '''
        try:
            result = self._post_query(query, timeout=60, ensure_active_project=True)
            result = result.strip()[:max_chars] if result else ""
        except Exception as exc:
            logger.warning("源码回查失败 [%s]: %s", method_full_name, exc)
            result = ""
        self._method_source_cache[method_full_name] = result
        return result

    def _fetch_caller_chain_source(self, method_full_name: str, max_callers: int = 4, max_chars: int = 8000) -> str:
        """向上回溯 caller 链源码（复用 trace_upstream 的 .caller.dumpRaw 模式）。

        逻辑漏洞的"回溯"方向：从敏感操作向上回溯到 HTTP 端点入口，
        与污点扫描的硬回溯方向一致（sink → source / caller 链）。
        """
        if not method_full_name:
            return ""
        cache_key = f"{method_full_name}|{max_callers}"
        if cache_key in self._caller_chain_source_cache:
            return self._caller_chain_source_cache[cache_key]
        import re as _re
        escaped = self._escape_joern_string_literal(_re.escape(method_full_name))
        query = f'''
        cpg.method.fullName("{escaped}")
        .caller
        .take({max_callers})
        .dumpRaw
        '''
        try:
            result = self._post_query(query, timeout=60, ensure_active_project=True)
            result = result.strip()[:max_chars] if result else ""
        except Exception as exc:
            logger.warning("caller 回溯失败 [%s]: %s", method_full_name, exc)
            result = ""
        self._caller_chain_source_cache[cache_key] = result
        return result

    def _fetch_callee_source(self, method_full_name: str, max_callees: int = 6, max_chars: int = 8000) -> str:
        """向下追溯 callee 源码（从入口方法调用的方法）。

        业务逻辑/权限类漏洞的关键上下文：入口方法调了哪些 Service/Repository 方法，
        这些方法内部有没有权限校验、归属关系检查等。
        同时提取 callee 所在类名缓存，供 _fetch_service_sibling_methods 使用。
        """
        if not method_full_name:
            return ""
        cache_key = f"{method_full_name}|{max_callees}"
        if cache_key in self._callee_source_cache:
            return self._callee_source_cache[cache_key]
        import re as _re
        escaped = self._escape_joern_string_literal(_re.escape(method_full_name))
        query = f'''
        cpg.method.fullNameExact("{method_full_name}")
        .call.take({max_callees}).dumpRaw
        '''
        try:
            result = self._post_query(query, timeout=60, ensure_active_project=True)
            result = result.strip()[:max_chars] if result else ""
        except Exception as exc:
            logger.warning("callee 回溯失败 [%s]: %s", method_full_name, exc)
            result = ""
        self._callee_source_cache[cache_key] = result
        # 同时提取 callee 所在类名（供 service sibling 查询使用）
        if result:
            self._extract_callee_class_names(method_full_name)
        return result

    def _extract_callee_class_names(self, entry_method: str) -> None:
        """轻量查询：提取 entry method 调用的 callee 所在类名，缓存到 _callee_class_names_cache。"""
        import re as _re
        escaped = self._escape_joern_string_literal(_re.escape(entry_method))
        query = f'''
        import io.shiftleft.semanticcpg.language._
        cpg.method.fullNameExact("{escaped}")
        .call
        .map(c => c.methodFullName)
        .dedup
        .filter(fn => !fn.startsWith("<") && fn.contains("."))
        .map(fn => fn.split(":")(0).reverse.dropWhile(_ != '.').drop(1).reverse)
        .dedup
        .take(5)
        .l
        '''
        try:
            result = self._post_query(query, timeout=30, ensure_active_project=True)
            if result and result.strip():
                classes = []
                for ln in result.strip().splitlines():
                    s = ln.strip().strip('",')
                    # 过滤 REPL 噪声：只保留像类名的行（以字母开头，包含 . 但不含 ( = < > :）
                    if not s or not s[0].isalpha():
                        continue
                    if any(c in s for c in ('=', '<', '>', ':', '(', ')', ' ')):
                        continue
                    if '.' not in s:
                        continue
                    classes.append(s)
                if classes:
                    self._callee_class_names_cache[entry_method] = classes
        except Exception:
            pass

    def _fetch_service_sibling_methods(self, caller: str, max_methods: int = 10) -> str:
        """横向展开 [D2]：从 callee 所在的 Service/Repository 类中获取其他方法签名+注解。

        用于状态机对比：如果 OrderService.cancel() 检查了归属但 ship() 没检查，
        这就是状态机不一致性的强信号。
        使用 _callee_class_names_cache 获取 callee 类名（由 _fetch_callee_source 填充）。
        """
        if not caller:
            return ""
        # 从缓存获取 callee 类名（由 _extract_callee_class_names 填充）
        callee_classes = self._callee_class_names_cache.get(caller, [])
        if not callee_classes:
            return ""
        # 合并所有 callee 类的 sibling 结果
        all_formatted: List[str] = []
        for class_key in callee_classes[:3]:  # 最多处理 3 个 callee 类
            if class_key in self._service_siblings_cache:
                cached = self._service_siblings_cache[class_key]
                if cached:
                    all_formatted.append(cached)
                continue
            import re as _re
            escaped_class = self._escape_joern_string_literal(_re.escape(class_key))
            query = f'''
            import io.shiftleft.semanticcpg.language._
            cpg.method.fullName("{escaped_class}.*")
              .filter(m => !m.name.startsWith("<") && !m.name.startsWith("lambda") && !m.name.startsWith("$"))
              .dedup
              .map(m => s"METHOD | name=${{m.name}} | annotations=${{m.annotation.name.l.mkString(",")}} | params=${{m.parameter.name.l.filter(_ != "this").mkString(",")}} | line=${{m.lineNumber.getOrElse(0)}}")
              .take({max_methods})
              .l
            '''
            try:
                result = self._post_query(query, timeout=60, ensure_active_project=True)
                if not result or not result.strip():
                    self._service_siblings_cache[class_key] = ""
                    continue
                lines = [ln.strip().strip('",') for ln in result.strip().splitlines()
                         if ln.strip() and "METHOD |" in ln]
                if not lines:
                    self._service_siblings_cache[class_key] = ""
                    continue
                # 高亮状态变更方法
                state_changing = {"save", "delete", "update", "remove", "create", "cancel",
                                  "refund", "approve", "reject", "activate", "deactivate",
                                  "enable", "disable", "lock", "unlock", "ship", "return",
                                  "transfer", "assign", "revoke", "grant", "reset", "archive"}
                formatted_lines = []
                for ln in lines[:max_methods]:
                    name_match = _re.search(r"name=(\w+)", ln)
                    if name_match and name_match.group(1).lower() in state_changing:
                        formatted_lines.append(f"- \u26a1 {ln}")
                    else:
                        formatted_lines.append(f"- {ln}")
                class_short = class_key.rsplit(".", 1)[-1] if "." in class_key else class_key
                header = f"### Service \u540c\u7ea7\u65b9\u6cd5\u72b6\u6001\u673a\u5bf9\u6bd4\uff08{class_short} \u6240\u6709 public \u65b9\u6cd5\uff09\n"
                header += "\u5173\u6ce8\uff1a\u72b6\u6001\u53d8\u66f4\u65b9\u6cd5\uff08\u26a1\u6807\u8bb0\uff09\u4e4b\u95f4\u662f\u5426\u6709\u4e00\u81f4\u6027\u6821\u9a8c\uff08\u5982\u5f52\u5c5e\u68c0\u67e5\u3001\u72b6\u6001\u524d\u7f6e\u6761\u4ef6\uff09\n\n"
                formatted = header + "\n".join(formatted_lines)
                self._service_siblings_cache[class_key] = formatted
                all_formatted.append(formatted)
            except Exception as exc:
                logger.warning("service sibling query failed [%s]: %s", class_key, exc)
                self._service_siblings_cache[class_key] = ""
        return "\n\n".join(all_formatted) if all_formatted else ""

    def _fetch_entity_fields(self, candidate: Dict[str, Any], max_fields: int = 15) -> str:
        """横向展开 [D3]：提取候选方法参数类型（DTO/Entity）的字段列表。

        用于 Mass Assignment 检测：如果 @RequestBody OrderRequest 包含 price/role/isAdmin
        等敏感字段且未做字段过滤，攻击者可通过构造恶意请求修改受保护属性。
        """
        caller = str(candidate.get("caller") or "").strip()
        if not caller:
            return ""
        # 缓存 key 用方法名（不同方法可能有不同参数类型）
        if caller in self._entity_fields_cache:
            return self._entity_fields_cache[caller]
        import re as _re
        escaped = self._escape_joern_string_literal(_re.escape(caller))
        query = f'''
        import io.shiftleft.semanticcpg.language._
        val _primitives = Set("int", "long", "float", "double", "boolean", "char",
          "byte", "short", "void", "java.lang.String", "java.lang.Integer",
          "java.lang.Long", "java.lang.Boolean", "java.lang.Double",
          "java.lang.Float", "java.lang.Short", "java.lang.Byte",
          "java.math.BigDecimal", "java.math.BigInteger",
          "java.time.LocalDate", "java.time.LocalDateTime",
          "java.time.Instant", "java.util.Date", "java.util.UUID")
        val m = cpg.method.fullNameExact("{escaped}").headOption
        m match {{
          case Some(method) =>
            method.parameter.filter(p => p.name != "this" && !_primitives.contains(p.typeFullName))
              .flatMap {{ p =>
                val rawType = p.typeFullName
                val typeName = if (rawType.contains("<")) rawType.substring(0, rawType.indexOf("<")) else rawType
                val shortName = if (typeName.contains(".")) typeName.substring(typeName.lastIndexOf(".") + 1) else typeName
                val fields = cpg.typeDecl.fullName(".*\\\\." + shortName + "\\\\$?").member
                  .map(f => s"${{f.name}}: ${{f.typeFullName}}")
                  .take({max_fields})
                  .l
                if (fields.nonEmpty) {{
                  List(s"PARAM ${{p.name}} (${{p.typeFullName}}) fields: " + fields.mkString(", "))
                }} else List.empty
              }}
              .l
          case None => List()
        }}
        '''
        try:
            result = self._post_query(query, timeout=60, ensure_active_project=True)
            if not result or not result.strip():
                self._entity_fields_cache[caller] = ""
                return ""
            lines = [ln.strip().strip('",') for ln in result.strip().splitlines()
                     if ln.strip() and "PARAM" in ln]
            if not lines:
                self._entity_fields_cache[caller] = ""
                return ""
            # 高亮可疑字段
            suspicious = {"price", "amount", "cost", "role", "admin", "isadmin",
                          "is_admin", "status", "isapproved", "is_approved",
                          "isactive", "is_active", "balance", "credit",
                          "password", "secret", "token", "type", "level",
                          "permission", "authority", "isdeleted", "is_deleted"}
            formatted_lines = []
            for ln in lines[:5]:
                # 检查是否包含可疑字段名
                has_suspicious = any(s in ln.lower() for s in suspicious)
                prefix = "⚠ " if has_suspicious else "  "
                formatted_lines.append(f"{prefix}{ln}")
            header = "### Entity/DTO 字段提取（Mass Assignment 检测）\n"
            header += "关注：⚠ 标记的字段是否可通过请求体被用户直接修改\n\n"
            formatted = header + "\n".join(formatted_lines)
            self._entity_fields_cache[caller] = formatted
            return formatted
        except Exception as exc:
            logger.warning("entity fields query failed [%s]: %s", caller, exc)
            self._entity_fields_cache[caller] = ""
            return ""

    def _logic_scan_language(self) -> str:
        fw = (getattr(self, "_current_logic_framework", None) or "java").lower()
        if fw in ("spring", "springboot", "springmvc"):
            return "java"
        if fw in ("java", "c", "cpp", "python", "go", "js", "javascript"):
            return "java" if fw == "javascript" else fw
        return "java"

    def _logic_scan_language_ext(self) -> str:
        """Return file extension for the current logic scan language (for markdown code fences)."""
        lang = self._logic_scan_language()
        return {"java": "java", "c": "c", "cpp": "cpp", "python": "python",
                "go": "go", "js": "javascript", "javascript": "javascript",
                "ruby": "ruby", "rust": "rust", "dotnet": "csharp"}.get(lang, "java")

    def _read_original_source(self, candidate: Dict[str, Any], window: int = 60) -> str:
        """Read original source file around the candidate method.

        Preserves comments, annotations, and spatial relationships between
        methods that Joern's AST reconstruction discards.  This is critical
        for control-driven vulnerability detection (missing auth, IDOR,
        privilege escalation) where annotations and adjacent method layout
        are the strongest evidence.

        Args:
            candidate: Logic scan candidate dict with 'file' and 'line' keys.
            window: Number of lines to include before and after the candidate line.

        Returns:
            Original source text with a header, or empty string if file not found.
        """
        file_rel = str(candidate.get("file") or "").strip()
        if not file_rel or not self.local_source_path:
            return ""

        # Resolve relative path against local roots (same mechanism as
        # _extract_code_context for taint scan path resolution)
        resolved = ""
        for root in self.local_roots:
            p = os.path.normpath(os.path.join(root, file_rel))
            if os.path.exists(p):
                resolved = p
                break
        if not resolved:
            return ""

        try:
            with open(resolved, encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except Exception:
            return ""

        line_num = int(candidate.get("line") or 0)
        if line_num > 0:
            start = max(0, line_num - window - 1)
            end = min(len(lines), line_num + window)
            snippet = "".join(lines[start:end])
            header = f"[Original source: {file_rel} lines {start + 1}-{end}]"
        else:
            # No line number available — return first 200 lines as context
            snippet = "".join(lines[:200])
            header = f"[Original source: {file_rel} (first 200 lines)]"

        return f"{header}\n{snippet}"

    def _fetch_class_protection_matrix(self, candidate: Dict[str, Any]) -> str:
        """Query Joern for all methods in the same class, with annotation status.

        Returns a formatted string showing which methods in the same Controller
        class have auth annotations and which don't — the strongest signal for
        detecting CRUD inconsistency (e.g. DELETE without @PreAuthorize while
        GET/POST/PUT have it).

        Args:
            candidate: Logic scan candidate with 'caller' (full method name).

        Returns:
            Formatted protection matrix string, or empty string on failure.
        """
        caller = str(candidate.get("caller") or "").strip()
        if not caller:
            return ""
        # 缓存 key 用类名（caller 去掉最后的方法名），同类方法共享同一矩阵
        class_key = caller.rsplit(".", 1)[0] if "." in caller else caller
        if class_key in self._protection_matrix_cache:
            return self._protection_matrix_cache[class_key]
        import re as _re
        escaped = self._escape_joern_string_literal(_re.escape(caller))
        query = f'''
        import io.shiftleft.semanticcpg.language._
        val target = cpg.method.fullName("{escaped}").headOption
        target match {{
          case Some(m) =>
            m.typeDecl.method
              .map(m => s"METHOD | name=${{m.name}} | annotations=${{m.annotation.name.l.mkString(",")}} | params=${{m.parameter.name.l.mkString(",")}} | line=${{m.lineNumber.getOrElse(0)}}")
              .take(30)
              .l
          case None => List()
        }}
        '''
        try:
            result = self._post_query(query, timeout=60, ensure_active_project=True)
            if not result or not result.strip():
                self._protection_matrix_cache[class_key] = ""
                return ""
            # Parse and format
            lines = [ln.strip() for ln in result.strip().splitlines() if ln.strip()]
            if not lines:
                self._protection_matrix_cache[class_key] = ""
                return ""
            header = "### 同类方法鉴权保护矩阵（同 Controller 所有 public 方法）\n"
            header += "关注：同类 CRUD 操作中是否有个别方法缺少鉴权注解\n\n"
            formatted = header + "\n".join(f"- {ln}" for ln in lines[:30])
            self._protection_matrix_cache[class_key] = formatted
            return formatted
        except Exception as exc:
            logger.warning("class protection matrix query failed [%s]: %s", caller, exc)
            self._protection_matrix_cache[class_key] = ""
            return ""

    @staticmethod
    def _should_expand_logic_candidate(candidate: Dict[str, Any]) -> bool:
        if os.environ.get("LOGIC_SCAN_SKIP_CONTEXT_EXPANSION", "0") == "1":
            return False
        ctype = str(candidate.get("type") or "")
        return ctype in LOGIC_SCAN_CONTEXT_EXPANSION_TYPES

    @staticmethod
    def _build_logic_joern_text_for_expansion(
        candidate: Dict[str, Any],
        *,
        caller: str,
        method_source: str,
        caller_chain_source: str,
        callee_source: str = "",
        context_block: str,
        evidence: str,
    ) -> str:
        parts = [
            f"# Logic candidate: {candidate.get('candidate_id', '')}",
            f"# CWE: {candidate.get('cwe', '')} | Type: {candidate.get('type', '')}",
            f"# Method: {caller}",
            f"# File: {candidate.get('file', '')}:{candidate.get('line', 0)}",
            "",
        ]
        if method_source:
            parts.append(
                f"--- method_source: {caller} ---\n{method_source}\n--- end_method_source ---\n"
            )
        if caller_chain_source:
            parts.append(
                f"--- caller_chain_source ---\n{caller_chain_source}\n"
                f"--- end_caller_chain ---\n"
            )
        if callee_source:
            parts.append(
                f"--- callee_source (downstream calls) ---\n{callee_source}\n"
                f"--- end_callee_source ---\n"
            )
        if context_block:
            parts.append(context_block)
        if evidence and not method_source:
            parts.append(f"--- evidence ---\n{evidence}\n--- end_evidence ---")
        return "\n".join(parts)

    def _expand_logic_candidate_context(
        self,
        candidate: Dict[str, Any],
        *,
        caller: str,
        method_source: str,
        caller_chain_source: str,
        callee_source: str = "",
        context_block: str,
        evidence: str,
        merged_l2: str,
    ) -> str:
        """首轮逻辑 LLM 前：复用 _run_llm_context_expansion_loop 补 Joern 上下文。"""
        if not self._should_expand_logic_candidate(candidate):
            return ""
        if not self.ensure_cpg_loaded():
            return ""

        flow_id = f"logic_{candidate.get('candidate_id', 'unknown')}"
        vuln_type = str(candidate.get("cwe") or candidate.get("type") or "logic")
        joern_text = self._build_logic_joern_text_for_expansion(
            candidate,
            caller=caller,
            method_source=method_source,
            caller_chain_source=caller_chain_source,
            callee_source=callee_source,
            context_block=context_block,
            evidence=evidence,
        )
        if not joern_text.strip() and caller:
            joern_text = (
                f"# Bootstrap for method: {caller}\n"
                f"# flow_id: {flow_id}\n"
                f"# vuln_type: {vuln_type}"
            )

        context_text = self._extract_code_context(joern_text)
        if merged_l2.strip():
            context_text = self._merge_context(context_text, merged_l2[:4000])

        max_iters = max(
            1,
            min(
                int(LOGIC_SCAN_EXPANSION_MAX_ITERS),
                4,
            ),
        )
        self._emit_audit(
            "logic_scan_context_expansion_started",
            {
                "flow_id": flow_id,
                "candidate_type": candidate.get("type"),
                "max_iters": max_iters,
                "prior_context_chars": len(context_text or ""),
            },
        )
        expansion_out = self._run_llm_context_expansion_loop(
            vuln_type=vuln_type,
            flow_id=flow_id,
            joern_text=joern_text,
            context_text=context_text,
            language=self._logic_scan_language(),
            max_iters=max_iters,
            skip_expansion=False,
        )
        expanded = str(expansion_out.get("context_text") or "").strip()
        self._emit_audit(
            "logic_scan_context_expansion_completed",
            {
                "flow_id": flow_id,
                "iterations_used": expansion_out.get("iteration", 0),
                "max_iters": max_iters,
                "sufficient": bool(
                    (expansion_out.get("sufficiency_result") or {}).get("sufficient")
                ),
                "exhausted": bool(expansion_out.get("exhausted")),
                "context_chars": len(expanded),
            },
        )
        return expanded

    def _analyze_logic_candidate(
        self,
        candidate: Dict[str, Any],
        query_results: Dict[str, str],
        cwe_skills: Dict[str, Dict[str, Any]],
        *,
        gathered_context: Optional[Dict[str, str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """用 LLM 分析单个逻辑漏洞候选，注入 CWE reasoning_workflow。

        定位精度提升：在喂给 LLM 之前，通过 Joern 回查候选方法的实际源码
        和 caller 链源码（复用硬回溯的 dumpRaw 机制），使 LLM 能看到真实代码
        而非仅标记文本，精度接近污点扫描。
        """
        cwe_num = candidate.get("cwe", "").replace("CWE-", "").strip()
        skill = cwe_skills.get(cwe_num, {})

        # ── 1. CWE reasoning_workflow 指导 ──
        guidance_parts: List[str] = []
        if skill:
            workflow = skill.get("reasoning_workflow", [])
            if workflow:
                guidance_parts.append("### 分析步骤（必须逐步执行）")
                for step in workflow:
                    guidance_parts.append(f"- {step}")
            examples = (skill.get("knowledge_injection") or {}).get("few_shot_examples", [])
            if examples:
                guidance_parts.append("\n### 参考案例")
                for ex in examples[:2]:
                    guidance_parts.append(f"**代码**: `{ex.get('code_snippet', '')[:120]}`")
                    guidance_parts.append(f"**分析**: {ex.get('vulnerability_analysis', '')[:200]}")
            sanitizers = skill.get("sanitizers", [])
            if sanitizers:
                guidance_parts.append("\n### 反证条件（若满足任一则否决漏洞）")
                for s in sanitizers:
                    guidance_parts.append(f"- {s}")

            criteria = skill.get("confirmation_criteria")
            if criteria:
                guidance_parts.append("\n### 漏洞确认六标准（缺一不得 confirmed）")
                for key, desc in criteria.items():
                    guidance_parts.append(f"- **{key}**: {desc}")
                verdict_rule = skill.get("verdict_rule")
                if verdict_rule:
                    guidance_parts.append(f"\n**判定规则**: {verdict_rule}")

            comp_handoff = skill.get("component_scan_handoff")
            if comp_handoff:
                guidance_parts.append("\n### 组件扫描联动（通用，不写死版本号）")
                if comp_handoff.get("trigger"):
                    guidance_parts.append(f"- **触发**: {comp_handoff['trigger']}")
                for step in comp_handoff.get("workflow", [])[:5]:
                    guidance_parts.append(f"- {step}")

            # ── CWE 模板的 logic_query_keywords（按框架分类的关键词） ──
            # 注入 LLM prompt，帮助模型关注 CWE 特定的敏感操作/鉴权模式
            logic_kw = skill.get("logic_query_keywords", {})
            # 优先用当前框架关键词，回退到 generic
            framework = getattr(self, '_current_logic_framework', 'java')
            kw_section = logic_kw.get(framework) or logic_kw.get("generic") or {}
            if kw_section:
                guidance_parts.append("\n### CWE 重点关注关键词")
                for category, keywords in kw_section.items():
                    if isinstance(keywords, list):
                        guidance_parts.append(f"- **{category}**: {', '.join(keywords[:15])}")

        guidance_block = "\n".join(guidance_parts) if guidance_parts else ""

        # ── 1b. 关联 CWE（Companion）分析指引 ──
        focus_nums = getattr(self, '_current_cwe_focus_nums', None)
        companion_guidance = self._build_companion_guidance(
            cwe_num, cwe_skills, focus_nums=focus_nums,
        )
        companion_cwes = [
            c for c in get_cwe_companions(cwe_num)
            if (not focus_nums or c in focus_nums) and c in cwe_skills
        ]
        self._last_companion_cwes = companion_cwes

        evidence = candidate.get("evidence", "")
        caller = candidate.get("caller", "")

        # ── 2. Joern 源码回查（核心改进） ──
        if gathered_context is not None:
            method_source = gathered_context.get("method_source") or ""
            caller_chain_source = gathered_context.get("caller_chain_source") or ""
            callee_source = gathered_context.get("callee_source") or ""
            context_block = gathered_context.get("context_block") or ""
            merged_l2 = gathered_context.get("merged_l2") or ""
            service_siblings = gathered_context.get("service_siblings") or ""
            entity_fields = gathered_context.get("entity_fields") or ""
        else:
            method_source = self._fetch_method_source(caller)
            caller_chain_source = self._fetch_caller_chain_source(caller)
            callee_source = self._fetch_callee_source(caller)
            service_siblings = self._fetch_service_sibling_methods(caller)
            entity_fields = self._fetch_entity_fields(candidate)
            context_block = self._build_logic_related_context_block(
                candidate, query_results,
            )
            l2_block = self._build_logic_l2_block(candidate, query_results)
            merged_l2 = self._merge_planner_l2_into_context(l2_block)

        sec_raw = query_results.get("security_filter_chain", "")
        security_summary = parse_security_filter_summary(sec_raw)
        ctype = str(candidate.get("type") or "")

        source_literals = extract_source_literals(
            method_source or "",
            str(candidate.get("evidence") or ""),
        )
        explicit_literal = str(candidate.get("source_literal") or "").strip()
        if explicit_literal and explicit_literal not in source_literals:
            source_literals.insert(0, explicit_literal)
        literals_block = ""
        if source_literals:
            literals_block = (
                "### 源码敏感字面量（PoC **必须原样使用**，禁止猜测 password/secret/webgoat 等）\n"
                + "\n".join(f"- `{lit}`" for lit in source_literals[:12])
                + "\n"
            )

        framework_notes = (
            "### 分析注意事项\n"
            "- `@CurrentUser` / `@CurrentUsername` / `@AuthenticationPrincipal` 表示**认证主体已注入**；"
            "对 missing_auth/public_endpoint 类型应判 **❌ 否**，除非证明匿名可访问（须引用 SecurityFilterChain "
            "permitAll 或等效配置）。\n"
            "- 身份注入 **≠** 资源级授权；水平越权用 IDOR/CWE-639 分析，不要重复报 missing_auth。\n"
            "- JWT 类漏洞关注 token **签发/校验/刷新**逻辑，而非 missing_auth 交叉。\n"
            "- 工具类/MD5/内部 helper 若无 HTTP 映射注解，通常不是独立逻辑漏洞入口。\n"
            "- PoC 中密码/密钥/token 必须与上文「源码敏感字面量」一致；"
            "L3 未实测时 `evidence_levels.L3_dynamic` 必须为 `not_verified`。\n"
            "- 若缺少 SecurityConfig/application.yml 且无法否定漏洞，"
            "应设 refutation_verdict=inconclusive 并列出 suggested_l2_reads。\n"
        )

        expansion_block = self._expand_logic_candidate_context(
            candidate,
            caller=caller,
            method_source=method_source,
            caller_chain_source=caller_chain_source,
            callee_source=callee_source,
            context_block=context_block,
            evidence=str(evidence or ""),
            merged_l2=merged_l2,
        )

        # ── 4. 构建 LLM prompt（注入源码） ──
        # 获取可用文件列表，防止 LLM 盲猜路径
        available_files = self._get_refutation_available_files(
            sink_label=str(candidate.get("evidence", ""))
        )
        available_files_note = ""
        if available_files:
            available_files_note = (
                "\n### 可用文件列表（suggested_l2_reads 只能引用此列表中的路径）\n"
                f"{available_files}\n"
                "**禁止编造不存在的路径**；若列表无合适文件，suggested_l2_reads 应为空数组。\n"
            )

        # ── 2b. Original source reading (Step 2 — control-driven evidence) ──
        # Read the original source file to preserve annotations, comments, and
        # spatial relationships between methods that Joern's AST reconstruction
        # discards.  This is the strongest evidence for control-driven vulns.
        # Reuse from gathered_context to avoid duplicate I/O when available.
        if gathered_context is not None:
            original_source = gathered_context.get("original_source") or ""
            protection_matrix = gathered_context.get("protection_matrix") or ""
        else:
            original_source = self._read_original_source(candidate)
            # ── 2c. Same-class method protection matrix ──
            protection_matrix = self._fetch_class_protection_matrix(candidate)

        source_block = ""
        if original_source:
            lang_ext = self._logic_scan_language_ext()
            source_block = (
                f"### 候选方法原始源码（{candidate.get('file', '')}）\n"
                f"```{lang_ext}\n{original_source}\n```\n"
            )
            # Still keep Joern dumpRaw caller chain as supplementary context
            if caller_chain_source:
                source_block += f"\n### 上游 caller 链源码（Joern 重建）\n```{lang_ext}\n{caller_chain_source}\n```\n"
            if callee_source:
                source_block += f"\n### 下游 callee 源码（入口方法调用的 Service/Repository）\n```{lang_ext}\n{callee_source}\n```\n"
        else:
            # Fallback to Joern-reconstructed source when local file not available
            if method_source:
                source_block += f"### 候选方法源码（Joern 重建, {caller}）\n```java\n{method_source}\n```\n"
            if caller_chain_source:
                source_block += f"\n### 上游 caller 链源码\n```java\n{caller_chain_source}\n```\n"
            if callee_source:
                source_block += f"\n### 下游 callee 源码（入口方法调用的 Service/Repository）\n```java\n{callee_source}\n```\n"
            if not source_block:
                # 回退：如果 Joern 回查也失败，至少给标记文本
                source_block = f"### Joern 证据\n`{evidence[:500]}`\n"

        # Append protection matrix as part of source context
        if protection_matrix:
            source_block += f"\n{protection_matrix}\n"
        # Append horizontal expansion context (service siblings + entity fields)
        if service_siblings:
            source_block += f"\n{service_siblings}\n"
        if entity_fields:
            source_block += f"\n{entity_fields}\n"

        source_quality_note = (
            "你将看到候选方法的**原始源码**（保留注解、注释和相邻方法布局）、上游调用链源码"
            + ("、下游 callee 源码" if callee_source else "")
            + ("、Service 同级方法对比" if service_siblings else "")
            + ("、Entity 字段提取" if entity_fields else "")
            + "，请基于代码事实进行分析。\n"
            if original_source
            else "你将看到 Joern 重建的源码（注解可能不完整，注释已丢失）、上游调用链源码"
            + ("、下游 callee 源码" if callee_source else "")
            + ("、Service 同级方法对比" if service_siblings else "")
            + ("、Entity 字段提取" if entity_fields else "")
            + "，请基于代码事实进行分析。\n"
        )
        system_prompt = (
            "你是一个专业的应用安全审计专家，正在分析一个潜在的逻辑漏洞。\n"
            f"{source_quality_note}"
            f"{LOGIC_VERDICT_AND_POC_POLICY}\n"
            "输出 JSON 格式的结果，包含以下字段：\n"
            "{\n"
            '  "confirmed": bool,\n'
            '  "confidence": float(0-1),\n'
            '  "refutation_verdict": "confirmed|rejected|inconclusive",\n'
            '  "summary": string "一句话总结",\n'
            '  "reasoning": string "详细推理过程",\n'
            '  "root_cause": string "根本原因",\n'
            '  "sanitizer_hit": string|null "反证或 null",\n'
            '  "http_endpoint": string "HTTP 方法与路径",\n'
            '  "code_flow": string "端点→handler→敏感操作调用链（纯文本，禁止数组）",\n'
            '  "exploit_poc": string "完整 PoC；否决写 无（纯文本，禁止数组）",\n'
            '  "fix_code": string "可编译修复代码（纯文本，禁止数组）",\n'
            '  "remediation": string "修复说明",\n'
            '  "source_evidence": string "关键证据行",\n'
            '  "evidence_levels": {"L1_joern":"present|partial|absent",'
            '"L2_static_files":"present|partial|absent",'
            '"L3_dynamic":"verified|not_verified|not_applicable"},\n'
            '  "suggested_l2_reads": ["必须来自可用文件列表的真实路径，禁止编造"]\n'
            "}\n"
            "**所有字段值必须是 string 类型（除 confirmed/bool、confidence/float、evidence_levels/object、suggested_l2_reads/array 外），禁止返回数组/列表。**\n"
            "confirmed=true 时 exploit_poc 与 fix_code 不得为空。\n"
            "证据不足且无法反证时：confirmed=false, refutation_verdict=inconclusive。"
        )

        # 追加关联 CWE 指令到 system prompt
        if companion_cwes:
            companion_list_str = ", ".join(f"CWE-{c}" for c in companion_cwes)
            system_prompt += (
                f"\n\n### 关联 CWE 检查\n"
                f"你还需同时检查以下关联 CWE（若代码存在对应漏洞则一并报告）：{companion_list_str}\n"
                f"在 JSON 末尾追加 `companion_verdicts` 数组，每个元素：\n"
                '{{\n'
                '  "cwe": "CWE-xxx",\n'
                '  "confirmed": bool,\n'
                '  "confidence": float(0-1),\n'
                '  "refutation_verdict": "confirmed|rejected|inconclusive",\n'
                '  "summary": "一句话",\n'
                '  "exploit_poc": "完整 PoC 或 无",\n'
                '  "fix_code": "修复代码 或 无"\n'
                '}}\n'
                "若某关联 CWE 无漏洞证据，`refutation_verdict` 设为 `rejected`，`confirmed` 为 false。"
                "若无关联漏洞可返回空数组。"
            )

        user_prompt = (
            f"### 候选漏洞信息\n"
            f"- CWE: {candidate.get('cwe', '')}\n"
            f"- 类型: {candidate.get('type', '')}\n"
            f"- 函数: {caller}\n"
            f"- 文件: {candidate.get('file', '')}\n"
            f"- 行号: {candidate.get('line', 0)}\n\n"
            f"{source_block}\n"
            f"{merged_l2}\n"
            f"{literals_block}\n"
            f"{context_block}\n"
            + (
                f"\n### Joern LLM 扩展上下文（L1 补全）\n{expansion_block[:12000]}\n"
                if expansion_block
                else ""
            )
            + f"\n{framework_notes}\n"
            f"{available_files_note}\n"
            f"{guidance_block}\n"
            + (
                f"\n### 关联 CWE 检查指引\n{companion_guidance}\n"
                if companion_guidance
                else ""
            )
            + f"\n请基于**实际源码**分析此候选是否为真实漏洞，输出 JSON 结果。"
        )

        try:
            llm_client = self._get_llm()
            response = llm_client.complete(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                temperature=0.1,
                max_tokens=3000,
            )
            result = self._parse_llm_json(response)
            if not result:
                return None
            result["cwe"] = candidate.get("cwe", "")
            result["candidate_id"] = candidate.get("candidate_id", "")
            result["candidate_type"] = candidate.get("type", "")
            result["cross_signals"] = list(candidate.get("cross_signals") or [])
            result["file"] = candidate.get("file", "") or result.get("file", "")
            result["line"] = candidate.get("line", 0) or result.get("line", 0)
            result["caller"] = caller or candidate.get("caller", "")
            result["evidence"] = evidence
            if method_source:
                result["method_source_preview"] = method_source[:2000]
            if original_source:
                result["raw_source_preview"] = original_source[:4000]
                result["source_evidence_type"] = "original_file"
            else:
                result["source_evidence_type"] = "joern_reconstructed"
            if caller_chain_source:
                result["caller_chain_preview"] = caller_chain_source[:2000]
            if expansion_block:
                result["expansion_context_preview"] = expansion_block[:2000]

            result = apply_logic_verdict_gates(
                candidate,
                result,
                method_source=method_source or "",
                security_summary=security_summary,
            )

            ev = result.get("evidence_levels") or {}
            l2_status = str(ev.get("L2_static_files") or "absent").lower()
            has_l2 = l2_status in ("present", "partial") or bool(merged_l2.strip())
            verdict = str(result.get("refutation_verdict") or "").lower()
            if result.get("confirmed"):
                if not str(result.get("exploit_poc") or "").strip():
                    result["confirmed"] = False
                    result["refutation_verdict"] = "rejected"
                    result["sanitizer_hit"] = result.get("sanitizer_hit") or "PoC 缺失"
                else:
                    result["refutation_verdict"] = "confirmed"
            elif verdict not in ("inconclusive", "rejected", "confirmed"):
                result["refutation_verdict"] = "rejected"
            if (
                ctype in LOGIC_L2_SENSITIVE_TYPES
                and not has_l2
                and not result.get("confirmed")
                and str(result.get("refutation_verdict")).lower() != "rejected"
            ):
                result["refutation_verdict"] = "inconclusive"
                result["suggested_l2_reads"] = result.get("suggested_l2_reads") or [
                    "*Security*Config*.java",
                    "application.yml",
                    "application.properties",
                ]
            return result
        except Exception as exc:
            logger.warning("LLM 逻辑漏洞分析异常: %s", exc)
            return None

    def _build_logic_scan_report(
        self,
        findings: List[Dict[str, Any]],
        query_results: Dict[str, str],
        *,
        query_batch_meta: Optional[Dict[str, Any]] = None,
        funnel_meta: Optional[Dict[str, Any]] = None,
    ) -> str:
        """构建逻辑漏洞扫描报告（含证据层级、PoC、代码流、修复代码、漏斗统计）。"""
        from datetime import datetime as _dt
        ts = _dt.now().strftime("%Y-%m-%d %H:%M:%S")

        confirmed = [f for f in findings if f.get("confirmed")]
        rejected = [
            f for f in findings
            if not f.get("confirmed")
            and str(f.get("refutation_verdict") or "").lower() != "inconclusive"
        ]
        inconclusive = [
            f for f in findings
            if str(f.get("refutation_verdict") or "").lower() == "inconclusive"
        ]
        failed_queries = set((query_batch_meta or {}).get("failed_transport") or [])
        funnel = funnel_meta or {}

        lines = [
            "# 逻辑漏洞扫描报告",
            f"生成时间: {ts}",
            REPORT_EVIDENCE_LEVEL_LEGEND.strip(),
            "",
            "## 摘要",
            f"- Joern 提取候选总数: {funnel.get('total_extracted', len(findings))}",
            f"- 进入 LLM 分析数: {funnel.get('analyzed', len(findings))} "
            f"(上限 {funnel.get('max_candidates', DEFAULT_MAX_CANDIDATES)})",
            f"- 因上限未分析: {funnel.get('skipped_by_cap', 0)}",
            f"- 确认漏洞: {len(confirmed)}",
            f"- 否决候选: {len(rejected)}",
            f"- 待 L2 补证 (inconclusive): {len(inconclusive)}",
        ]
        if funnel.get("cwe_focus"):
            lines.append(f"- CWE 聚焦: {', '.join(str(c) for c in funnel['cwe_focus'])}")
        lines.append("")

        if funnel.get("type_breakdown_extracted"):
            lines.extend([
                "## 候选漏斗（按类型）",
                f"- 提取后: {self._format_type_breakdown(funnel.get('type_breakdown_extracted'))}",
                f"- 已分析: {self._format_type_breakdown(funnel.get('type_breakdown_analyzed'))}",
                "",
            ])

        skipped = int(funnel.get("skipped_by_cap") or 0)
        if skipped > 0:
            lines.extend([
                "## ⚠️ 漏报风险提示",
                f"- 有 **{skipped}** 个候选因 `max_candidates` 未进入 LLM。",
                f"- 可在 `logic_scan_settings.py` 或 `.env` 的 `LOGIC_SCAN_MAX_CANDIDATES` 调大上限。",
                "",
            ])

        if failed_queries:
            lines.extend([
                "## 查询告警",
                f"- 失败查询: {', '.join(sorted(failed_queries))}",
                "",
            ])

        lines.extend([
            "## 结构化摘要",
            "| finding_id | CWE | 类型 | 判定 | L1 | L2 | L3 | 位置 |",
            "|------------|-----|------|------|----|----|-----|------|",
        ])
        for f in findings:
            ev = f.get("evidence_levels") or {}
            verdict = "✅ 是" if f.get("confirmed") else (
                "⚠️ inconclusive" if str(f.get("refutation_verdict") or "").lower() == "inconclusive"
                else "❌ 否"
            )
            lines.append(
                f"| `{f.get('candidate_id', '')}` | {f.get('cwe', '')} | "
                f"{f.get('candidate_type', '')} | {verdict} | "
                f"{ev.get('L1_joern', '—')} | {ev.get('L2_static_files', '—')} | "
                f"{ev.get('L3_dynamic', '—')} | `{f.get('file', '')}`:{f.get('line', 0)} |"
            )
        lines.append("")

        if confirmed:
            lines.append("## 确认漏洞（PoC / 代码流 / 修复代码）")
            for i, f in enumerate(confirmed, 1):
                lines.extend(self._format_logic_confirmed_finding(i, f))

        if inconclusive:
            lines.append("## 待补证 (inconclusive)")
            for f in inconclusive:
                reads = f.get("suggested_l2_reads") or []
                lines.append(
                    f"- `{f.get('candidate_id', '')}` {f.get('cwe', '')} "
                    f"`{f.get('caller', '')}` — 建议读取: {reads}"
                )
            lines.append("")

        if rejected:
            lines.append("## 否决候选（摘要）")
            for f in rejected:
                lines.append(
                    f"- `{f.get('candidate_id', '')}` {f.get('cwe', '')} "
                    f"`{f.get('caller', '')}` — {f.get('sanitizer_hit') or f.get('summary', '')}"
                )
            lines.append("")

        lines.extend(["## 查询覆盖"])
        for query_name, result_text in query_results.items():
            coverage = self._format_logic_query_coverage(
                query_name, result_text, failed_queries=failed_queries,
            )
            lines.append(f"- {query_name}: {coverage}")

        gap_notes = self._logic_high_hit_gap_notes(query_results, funnel, failed_queries)
        if gap_notes:
            lines.extend(["", "## 覆盖缺口提示", *gap_notes])

        return "\n".join(lines)

    @staticmethod
    def _format_type_breakdown(counts: Optional[Dict[str, int]]) -> str:
        if not counts:
            return "—"
        return ", ".join(f"{k}={v}" for k, v in counts.items())

    def _format_logic_confirmed_finding(
        self, index: int, finding: Dict[str, Any],
    ) -> List[str]:
        ev = finding.get("evidence_levels") or {}
        fid = finding.get("candidate_id") or f"logic-{index}"

        def _to_str(val: Any) -> str:
            """LLM 有时把 code_flow / exploit_poc / fix_code 等字段返回为 list，
            此处统一转成 str，防止 join 时 TypeError。"""
            if val is None:
                return ""
            if isinstance(val, list):
                return "\n".join(str(item) for item in val)
            return str(val)

        return [
            "",
            f"### [{index}] {finding.get('cwe', '')} — `{fid}`",
            f"> {_to_str(finding.get('summary'))}",
            "",
            "#### 证据层级",
            f"| L1 | {ev.get('L1_joern', '—')} | L2 | {ev.get('L2_static_files', '—')} | "
            f"L3 | {ev.get('L3_dynamic', '—')} |",
            "",
            "#### 代码/调用流",
            _to_str(finding.get("code_flow") or finding.get("reasoning")),
            "",
            "#### 漏洞利用（PoC）",
            _to_str(finding.get("exploit_poc")) or "（缺失）",
            "",
            "#### 修复代码",
            "```",
            _to_str(finding.get("fix_code") or finding.get("remediation")),
            "```",
            "",
            f"**说明**: {_to_str(finding.get('remediation'))}",
            "---",
        ]

    def _logic_high_hit_gap_notes(
        self,
        query_results: Dict[str, str],
        funnel: Dict[str, Any],
        failed_queries: set,
    ) -> List[str]:
        notes: List[str] = []
        analyzed_types = set((funnel.get("type_breakdown_analyzed") or {}).keys())
        query_to_type = {
            "jwt_weakness": "jwt_weakness",
            "jwt_endpoints": "jwt_endpoint",
            "hardcoded_credentials_v2": "hardcoded_cred",
            "idor_candidates": "idor",
            "idor_path_variable": "idor_pathvar",
            "idor_profile": "idor_profile",
            "info_leak_candidates": "info_leak",
            "info_leak_response": "info_leak_response",
            "csrf_gap": "csrf_gap",
            "ssrf_risk": "ssrf_risk",
            "business_logic_risk": "business_logic_risk",
            "toctou_risk": "toctou_risk",
            "cors_config": "cors_misconfig",
        }
        for qname, ctype in query_to_type.items():
            if qname in failed_queries:
                continue
            tags = self._LOGIC_QUERY_TAGS.get(qname)
            if not tags:
                continue
            hits = len(self._parse_tagged_lines(query_results.get(qname, ""), *tags))
            if hits >= 3 and ctype not in analyzed_types:
                notes.append(
                    f"- `{qname}` 命中 {hits} 条，但类型 `{ctype}` 未进入 LLM — 提高 max_candidates。"
                )
        return notes

    def _resolve_joern_file_path(self, file_path: str) -> str:
        """
        把 Joern 返回的文件路径映射到本地真实文件路径。

        Args:
            file_path: Joern 输出中的路径，可能是容器路径、工作区路径，也可能已经是本地绝对路径。

        Returns:
            可直接读取的本地路径；如果无法映射则返回空字符串。
        """
        if not file_path:
            return ""

        # 统一改成 "/"，避免 Windows/Linux 路径分隔符差异影响后续前缀判断。
        normalized_file_path = file_path.replace("\\", "/")
        candidate_relative_paths: List[str] = [normalized_file_path.lstrip("/")]

        normalized_remote_source_root = (self.source_path or "").replace("\\", "/").rstrip("/")
        if normalized_remote_source_root and normalized_file_path.startswith(normalized_remote_source_root + "/"):
            candidate_relative_paths.append(
                normalized_file_path[len(normalized_remote_source_root) + 1 :].lstrip("/")
            )

        remote_prefixes = ["/app/vuln_app/", "/workspace/", "/src/"]
        for prefix in remote_prefixes:
            if normalized_file_path.startswith(prefix):
                candidate_relative_paths.append(normalized_file_path.replace(prefix, "", 1).lstrip("/"))

        drive_match = re.match(r"^[A-Za-z]:[/\\].*$", file_path)
        if drive_match and os.path.exists(file_path):
            return file_path

        for relative_path in candidate_relative_paths:
            for local_root in self.local_roots:
                candidate_path = os.path.normpath(os.path.join(local_root, relative_path))
                if os.path.exists(candidate_path):
                    return candidate_path
        return ""

    def _extract_line_window(self, file_lines: List[str], line_number: int, before: int = 20, after: int = 35) -> str:
        """
        提取危险行附近的局部代码窗口。
        """
        current_index = line_number - 1
        start_index = max(0, current_index - before)
        end_index = min(len(file_lines), current_index + after)
        return "".join(file_lines[start_index:end_index]).strip()

    def _extract_guard_context(self, file_lines: List[str], line_number: int, window: int = 30) -> str:
        """
        提取危险行附近可能影响可利用性的防御/分支逻辑。
        """
        interesting_pattern = re.compile(
            r"\b(if|else|switch|case|while|for|return|assert|guard|validate|verify|check|sanitize|normalize|auth|authorize|permission|allow|deny|limit|range|length|size)\b|&&|\|\||<=|>=|==|!=|<|>",
            flags=re.IGNORECASE,
        )
        current_index = line_number - 1
        start_index = max(0, current_index - window)
        end_index = min(len(file_lines), current_index + 6)
        selected_lines: List[str] = []

        for line_index in range(start_index, end_index):
            raw_line = file_lines[line_index].rstrip()
            if not raw_line.strip():
                continue
            if interesting_pattern.search(raw_line):
                selected_lines.append(f"{line_index + 1}: {raw_line}")

        return "\n".join(selected_lines[:18]).strip()

    def _extract_enclosing_method_context(self, file_lines: List[str], line_number: int) -> str:
        """
        用启发式方式提取危险行所在的方法体。

        这里不做完整语法解析，而是尽量稳定地把当前危险点所在方法的主体
        补给 LLM，帮助它检查前置约束、边界检查、白名单和早返回逻辑。
        """
        control_structure_pattern = re.compile(r"^(if|else|for|while|switch|catch|try|do|class|struct|enum)\b")
        current_index = max(0, line_number - 1)
        search_start = max(0, current_index - 120)
        method_open_index: Optional[int] = None
        signature_start_index: Optional[int] = None

        for candidate_index in range(current_index, search_start - 1, -1):
            candidate_line = file_lines[candidate_index].strip()
            if "{" not in candidate_line:
                continue
            if control_structure_pattern.match(candidate_line):
                continue

            signature_window_start = max(search_start, candidate_index - 3)
            signature_window = " ".join(file_lines[signature_window_start : candidate_index + 1])
            if "(" not in signature_window or ")" not in signature_window:
                continue
            if ";" in candidate_line and "{" not in candidate_line.split(";")[-1]:
                continue

            method_open_index = candidate_index
            signature_start_index = candidate_index
            while signature_start_index > search_start:
                previous_line = file_lines[signature_start_index - 1].strip()
                if not previous_line:
                    break
                if previous_line.endswith(";") or previous_line.endswith("}") or control_structure_pattern.match(previous_line):
                    break
                signature_start_index -= 1
            break

        if method_open_index is None or signature_start_index is None:
            return ""

        brace_depth = 0
        seen_open_brace = False
        method_end_index = method_open_index
        for line_index in range(method_open_index, len(file_lines)):
            current_line = file_lines[line_index]
            brace_depth += current_line.count("{")
            if "{" in current_line:
                seen_open_brace = True
            brace_depth -= current_line.count("}")
            if seen_open_brace and brace_depth <= 0 and line_index > method_open_index:
                method_end_index = line_index
                break

        method_body = "".join(file_lines[signature_start_index : method_end_index + 1]).strip()
        if len(method_body) > 6000:
            return method_body[:6000].rstrip() + "\n/* method body truncated */"
        return method_body

    def _extract_code_context(self, text: str) -> str:
        """
        从 Joern 输出中抽取更适合大模型理解的代码上下文。

        Args:
            text: Joern 原始输出，通常是 `.p` 表格或 `.l/List(...)` 文本。

        Returns:
            Markdown 格式的上下文片段文本。
        """
        if not text or len(text) < 80:
            return "*(Joern 输出过短)*"

        snippets: List[str] = []
        seen_locations = set()

        if "│" in text and ("tracked" in text.lower() or "nodeType" in text.lower()):
            lines = text.split("\n")
            current_tracked = ""
            current_file = ""
            current_line = ""
            current_method = ""

            for line in lines:
                # `.p` 表格可能包含分隔线、空白行和多行 tracked 字段，
                # 所以这里按行做容错式累积，而不是假设每一行都结构完整。
                stripped_line = line.strip()
                if not stripped_line:
                    continue

                if "└" in line or "val res" in line or "─" * 10 in line:
                    if current_tracked and current_line:
                        self._add_snippet(snippets, seen_locations, current_file, current_line, current_method, current_tracked)
                    current_tracked = ""
                    current_file = ""
                    current_line = ""
                    current_method = ""
                    continue

                if "│" not in line:
                    continue

                columns = [column.strip() for column in re.split(r"[│|]", line) if column.strip()]
                if len(columns) < 3:
                    continue

                tracked_part = columns[1] if len(columns) > 1 else ""
                line_part = columns[2] if len(columns) > 2 else ""
                method_part = columns[3] if len(columns) > 3 else ""
                file_part = columns[4] if len(columns) > 4 else ""

                if line_part.isdigit() and 1 <= len(line_part) <= 6:
                    current_line = line_part
                if file_part and any(file_part.endswith(extension) for extension in [".c", ".h", ".cpp", ".cc", ".java"]):
                    current_file = file_part
                if method_part and ("(" in method_part or "()" in method_part):
                    current_method = method_part

                if tracked_part and len(tracked_part) > 8:
                    current_tracked = f"{current_tracked} {tracked_part}".strip() if current_tracked else tracked_part

                if any(
                    keyword in tracked_part.lower()
                    for keyword in ["memcpy", "memmove", "strcpy", "malloc", "free", "realloc", "execute", "printf"]
                ):
                    # 如果当前行出现高危函数名，就优先把它当成关键 tracked 节点，
                    # 避免被前后无关文本稀释。
                    current_tracked = tracked_part

            if current_tracked and current_line:
                self._add_snippet(snippets, seen_locations, current_file, current_line, current_method, current_tracked)

        elif "List(" in text or "code=" in text or "CODE:" in text:
            triple_blocks = self._extract_list_triple_quoted_blocks(text)
            if triple_blocks:
                for block in triple_blocks[:5]:
                    method_hint = ""
                    method_match = re.search(r"METHOD_FULL_NAME:\s*([^\s,]+)", block)
                    if method_match:
                        method_hint = method_match.group(1).split(".")[-1]
                    snippets.append(self._format_method_body_snippet(block, method_hint))
            else:
                code_matches = re.findall(
                    r'code\s*=\s*["\']([^"\']{5,2000})["\']',
                    text,
                    re.DOTALL,
                )
                line_matches = re.findall(r"lineNumber\s*=\s*(\d+)", text)
                file_matches = re.findall(
                    r'fileName\s*=\s*["\']?([^"\',\s]+?\.(?:c|h|cpp|java))["\']?',
                    text,
                )
                for index, code in enumerate(code_matches[:12]):
                    line_number = line_matches[index] if index < len(line_matches) else "?"
                    file_path = file_matches[index] if index < len(file_matches) else "unknown.c"
                    cleaned_code = code.replace('\\"', '"').strip()
                    snippets.append(f"```c\n// {file_path}:{line_number}\n{cleaned_code}\n```")

        if snippets:
            return "### 📜 提取到的代码片段\n\n" + "\n\n".join(snippets[:15])

        fallback_chars = int(os.environ.get("JOERN_CONTEXT_FALLBACK_CHARS", "8000"))
        sample = text[:fallback_chars].replace("\n", " ")
        if len(text) > fallback_chars:
            sample += "..."
        return f"*(解析有限)*\n```text\n{sample}\n```"

    def _split_joern_into_flow_chunks(self, text: str, vuln_type: str) -> List[Dict[str, Any]]:
        """
        将单次污点查询的 Joern 输出拆成多条独立 flow（每条单独走回溯 + LLM）。

        优先按 `.p` 表格分隔符（└ / val res）切分；无法切分时退化为单条 flow。
        """
        if not text or len(text.strip()) < 80:
            return []

        max_flows = max(1, int(os.environ.get("JOERN_MAX_FLOWS_PER_QUERY", "5")))
        chunks: List[str] = []

        if "│" in text and ("tracked" in text.lower() or "nodetype" in text.lower()):
            current_lines: List[str] = []
            for line in text.splitlines():
                is_boundary = "└" in line or re.match(r"^\s*val\s+res\d*\s*[:=]", line)
                if is_boundary and current_lines:
                    block = "\n".join(current_lines).strip()
                    if len(block) > 60:
                        chunks.append(block)
                    current_lines = []
                current_lines.append(line)
            tail = "\n".join(current_lines).strip()
            if len(tail) > 60:
                chunks.append(tail)
        else:
            parts = re.split(r"(?m)^\s*val\s+res\d*\s*[:=]", text)
            parts = [part.strip() for part in parts if part and len(part.strip()) > 60]
            if len(parts) > 1:
                chunks = parts
            else:
                chunks = [text.strip()]

        if not chunks:
            chunks = [text.strip()]

        flow_records: List[Dict[str, Any]] = []
        for index, chunk in enumerate(chunks[:max_flows], start=1):
            flow_id = f"{vuln_type}-flow-{index}"
            flow_records.append(
                {
                    "flow_id": flow_id,
                    "raw_text": chunk,
                    "sink_label": self._extract_flow_sink_label(chunk),
                }
            )
        if len(chunks) > max_flows:
            logger.info(
                "污点查询 %s 共 %s 条 flow，仅分析前 %s 条（JOERN_MAX_FLOWS_PER_QUERY）",
                vuln_type,
                len(chunks),
                max_flows,
            )
        return flow_records

    def _extract_flow_sink_label(self, flow_text: str) -> str:
        """从单条 flow 文本提取 sink 展示标签（文件:行 + 关键代码）。"""
        file_path = ""
        line_num = ""
        tracked = ""
        if "│" in flow_text:
            for line in flow_text.splitlines():
                if "│" not in line:
                    continue
                columns = [column.strip() for column in re.split(r"[│|]", line) if column.strip()]
                if len(columns) < 3:
                    continue
                tracked_part = columns[1] if len(columns) > 1 else ""
                line_part = columns[2] if len(columns) > 2 else ""
                file_part = columns[4] if len(columns) > 4 else ""
                if line_part.isdigit():
                    line_num = line_part
                if file_part and any(file_part.endswith(ext) for ext in [".c", ".h", ".cpp", ".cc", ".java"]):
                    file_path = file_part
                if tracked_part and len(tracked_part) > len(tracked):
                    tracked = tracked_part
        if file_path and line_num:
            sink_code = (tracked[:120] + "...") if len(tracked) > 120 else tracked
            return f"{file_path}:{line_num} {sink_code}".strip()
        return (tracked[:160] or flow_text[:160]).replace("\n", " ")

    def _flow_quality_filter_mode(self) -> str:
        """返回 off | lenient | standard | strict。"""
        if os.environ.get("JOERN_FLOW_QUALITY_FILTER", JOERN_FLOW_QUALITY_FILTER_DEFAULT) == "0":
            return "off"
        mode = (
            os.environ.get("JOERN_FLOW_QUALITY_MODE", JOERN_FLOW_QUALITY_MODE_DEFAULT)
            or JOERN_FLOW_QUALITY_MODE_DEFAULT
        ).lower().strip()
        if mode not in ("lenient", "standard", "strict", "off"):
            return JOERN_FLOW_QUALITY_MODE_DEFAULT
        return mode

    @staticmethod
    def _raw_text_has_taint_table(text: str) -> bool:
        if "│" not in text:
            return False
        lowered = text.lower()
        return "tracked" in lowered or "nodetype" in lowered or "method" in lowered

    @staticmethod
    def _raw_text_has_code_evidence(text: str) -> bool:
        if "CODE:" in text or "dumpRaw" in text:
            return True
        return bool(
            re.search(
                r'fileName\s*=\s*["\']?[^"\']+\.(?:c|h|cpp|cc|cxx|hpp|java)',
                text,
                flags=re.IGNORECASE,
            )
        )

    @staticmethod
    def _sink_label_has_real_source(sink_label: str) -> bool:
        if not sink_label:
            return False
        return bool(_SOURCE_FILE_IN_SINK_RE.search(sink_label))

    @staticmethod
    def _raw_text_has_joern_metadata_noise(text: str) -> bool:
        return any(marker in text for marker in JOERN_METADATA_NOISE_MARKERS)

    def _flow_quality_skip_reason(self, flow_record: Dict[str, Any]) -> Optional[str]:
        """
        判断单条 flow 是否应跳过 LLM 分析。

        Returns:
            跳过原因代码；None 表示应进入分析队列。
        """
        mode = self._flow_quality_filter_mode()
        if mode == "off":
            return None

        raw_text = flow_record.get("raw_text") or ""
        sink_label = flow_record.get("sink_label") or ""
        has_table = self._raw_text_has_taint_table(raw_text)
        has_source = self._sink_label_has_real_source(sink_label)
        has_code = self._raw_text_has_code_evidence(raw_text)
        has_noise = self._raw_text_has_joern_metadata_noise(raw_text)

        if mode == "lenient":
            if has_noise and not has_source and not has_table:
                return "joern_project_metadata_only"
            return None

        if mode == "standard":
            if has_noise and not has_source and not has_table:
                return "joern_project_metadata_only"
            if not has_source and not has_table and not has_code:
                return "no_taint_table_or_source"
            return None

        # strict
        if has_source or has_table or has_code:
            return None
        if has_noise:
            return "joern_project_metadata_only"
        return "insufficient_flow_evidence"

    def _partition_flows_by_quality(
        self, flow_chunks: List[Dict[str, Any]], *, vuln_type: str
    ) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """将 flow 列表分为可分析与应跳过两组，并写审计事件。"""
        analyzable: List[Dict[str, Any]] = []
        skipped: List[Dict[str, Any]] = []
        mode = self._flow_quality_filter_mode()
        for flow_record in flow_chunks:
            reason = self._flow_quality_skip_reason(flow_record)
            if reason:
                skipped.append({**flow_record, "skip_reason": reason})
                self._emit_audit(
                    "flow_quality_skipped",
                    {
                        "vuln_type": vuln_type,
                        "flow_id": flow_record.get("flow_id"),
                        "sink_label": flow_record.get("sink_label"),
                        "skip_reason": reason,
                        "filter_mode": mode,
                    },
                )
            else:
                analyzable.append(flow_record)
        return analyzable, skipped

    @staticmethod
    def _format_skipped_flows_report(skipped: List[Dict[str, Any]]) -> str:
        if not skipped:
            return ""
        lines = ["\n### ⏭️ 已跳过低质量 flow（JOERN_FLOW_QUALITY_FILTER）\n"]
        for item in skipped:
            lines.append(
                f"- `{item.get('flow_id')}`: **{item.get('skip_reason')}** "
                f"(sink: `{str(item.get('sink_label', ''))[:120]}`)"
            )
        lines.append("")
        return "\n".join(lines)

    def _extract_method_candidates_from_joern(self, text: str, max_items: int = 16) -> List[str]:
        """
        从 Joern 输出中提取候选方法名，供硬回溯阶段作为起点。
        已过滤表头/通用词等假方法名，避免向 Joern 发送无效查询。
        """
        if not text:
            return []

        candidates: List[str] = []
        seen = set()

        def _is_valid_method_name(name: str) -> bool:
            if not name or len(name) <= 1:
                return False
            if name.lower() in self._INVALID_METHOD_NAMES:
                return False
            # 方法名必须像标识符：字母/下划线开头，包含字母
            if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*", name):
                return False
            return True

        if "│" in text:
            for line in text.splitlines():
                if "│" not in line:
                    continue
                columns = [column.strip() for column in re.split(r"[│|]", line) if column.strip()]
                if len(columns) < 4:
                    continue
                method_name = columns[3]
                if not method_name:
                    continue
                sanitized_name = re.sub(r"\(.*$", "", method_name).strip()
                if (
                    sanitized_name
                    and sanitized_name not in seen
                    and not sanitized_name.startswith("<operator>")
                    and _is_valid_method_name(sanitized_name)
                ):
                    seen.add(sanitized_name)
                    candidates.append(sanitized_name)
                if len(candidates) >= max_items:
                    return candidates

        for matched in re.findall(r"Method:\s*([^\s|`]+)", text):
            sanitized_name = re.sub(r"\(.*$", "", matched).strip()
            if sanitized_name and sanitized_name not in seen and _is_valid_method_name(sanitized_name):
                seen.add(sanitized_name)
                candidates.append(sanitized_name)
            if len(candidates) >= max_items:
                break

        return candidates

    def _parse_joern_list_strings(self, text: str, max_items: int = 20) -> List[str]:
        """
        解析 Joern `List("a", "b")` 风格输出为 Python 列表。
        
        只解析最后一个 `List(...)` 部分，避免误提取 Project 信息中的引号内容
        （如 inputPath="/app/vuln_app", name="VulnerableApp"）。
        """
        if not text:
            return []
        
        # 找到最后一个 List(...) 的内容，避免解析 Project 信息
        # 匹配 List(...) 可能跨行，使用 DOTALL
        list_match = re.search(r'List\s*\(([^)]*)\)\s*$', text, re.DOTALL)
        if not list_match:
            # 兼容 fallback：没有 List(...) 结尾时尝试全文匹配
            list_content = text
        else:
            list_content = list_match.group(1)
        
        # 如果 List() 为空（即 List 后直接 )），直接返回空列表
        if list_match and not list_content.strip():
            return []
        
        items = re.findall(r'"([^"]+)"', list_content)
        if not items:
            items = re.findall(r"'([^']+)'", list_content)
        deduplicated_items: List[str] = []
        seen = set()
        for item in items:
            normalized_item = item.strip()
            if not normalized_item or normalized_item in seen:
                continue
            seen.add(normalized_item)
            deduplicated_items.append(normalized_item)
            if len(deduplicated_items) >= max_items:
                break
        return deduplicated_items

    @staticmethod
    def _guard_call_edge_key(vuln_type: str, callee_full: str, caller_full: str) -> str:
        return f"{vuln_type}|{callee_full.strip()}|{caller_full.strip()}"

    def _record_guard_call_edge(
        self, vuln_type: str, callee_full: str, caller_full: str
    ) -> str:
        """记录已证实含防御逻辑的调用边 (caller → callee)。"""
        key = self._guard_call_edge_key(vuln_type, callee_full, caller_full)
        self._guarded_call_edge_cache.add(key)
        return key

    def _query_method_full_names(
        self, method_name: str, *, max_items: int = 5
    ) -> List[str]:
        cache_key = (method_name or "").strip().lower()
        if not cache_key:
            return []
        if cache_key in self._joern_method_fullnames_cache:
            return self._joern_method_fullnames_cache[cache_key]
        escaped = self._escape_joern_string_literal(method_name)
        query = f'''
        cpg.method.name("{escaped}")
        .fullName
        .dedup
        .take({max_items})
        .l
        '''
        result = self._post_query(query, timeout=120, ensure_active_project=True)
        names = self._parse_joern_list_strings(result, max_items=max_items)
        self._joern_method_fullnames_cache[cache_key] = names
        return names

    def _query_method_caller_full_names(
        self, method_name: str, *, max_items: int = 8
    ) -> List[str]:
        cache_key = (method_name or "").strip().lower()
        if not cache_key:
            return []
        if cache_key in self._joern_method_callers_cache:
            return self._joern_method_callers_cache[cache_key]
        escaped = self._escape_joern_string_literal(method_name)
        query = f'''
        cpg.method.name("{escaped}")
        .caller
        .fullName
        .dedup
        .take({max_items})
        .l
        '''
        result = self._post_query(query, timeout=180, ensure_active_project=True)
        names = self._parse_joern_list_strings(result, max_items=max_items)
        self._joern_method_callers_cache[cache_key] = names
        return names

    def _collect_flow_call_edges(
        self,
        vuln_type: str,
        joern_text: str,
        *,
        sink_label: str = "",
        max_seed_methods: int = 8,
    ) -> List[Dict[str, str]]:
        """
        从 flow 的 Joern 输出提取候选调用边，键为 fullName。

        对 flow 表中出现的每个候选 callee，查询其 caller.fullName，
        得到 (callee_full, caller_full) 边列表，供与 guard 缓存精确比对。
        """
        seed_limit = int(
            os.environ.get(
                "JOERN_GUARD_EDGE_SEED_LIMIT",
                str(max_seed_methods),
            )
        )
        method_names = list(
            self._extract_method_candidates_from_joern(
                joern_text, max_items=min(max_seed_methods, seed_limit)
            )
        )
        sink_short = (sink_label or "").split("(")[0].strip()
        if sink_short and sink_short not in method_names:
            method_names.insert(0, sink_short)

        edges: List[Dict[str, str]] = []
        seen_keys: set = set()
        for method_name in method_names[:max_seed_methods]:
            callee_fulls = self._query_method_full_names(method_name)
            caller_fulls = self._query_method_caller_full_names(method_name)
            if not callee_fulls:
                callee_fulls = [method_name]
            for callee_full in callee_fulls:
                for caller_full in caller_fulls:
                    edge_key = self._guard_call_edge_key(
                        vuln_type, callee_full, caller_full
                    )
                    if edge_key in seen_keys:
                        continue
                    seen_keys.add(edge_key)
                    edges.append(
                        {
                            "callee_short": method_name,
                            "callee_full": callee_full,
                            "caller_full": caller_full,
                            "edge_key": edge_key,
                        }
                    )
        return edges

    def _looks_like_user_input_source(self, method_names: List[str], text_blob: str) -> bool:
        """
        粗略判断当前回溯是否已触达潜在用户输入源附近。
        """
        source_hint_regex = os.environ.get(
            "JOERN_SOURCE_METHOD_HINTS",
            r"(getparameter|getquerystring|getheader|requestbody|readline|scanner\.next|argv|stdin|socket|recv|read|inputstream|http|controller|handler|endpoint|main)",
        )
        source_pattern = re.compile(source_hint_regex, flags=re.IGNORECASE)
        joined_method_text = " ".join(method_names or [])
        return bool(source_pattern.search(joined_method_text) or source_pattern.search(text_blob or ""))

    def _requires_source_for_vuln_type(self, vuln_type: str) -> bool:
        """
        根据漏洞类型判断是否“必须追溯到输入源”。

        默认策略：
        - 注入/反序列化/路径/远程交互类漏洞：强制追输入源
        - 纯内存破坏、竞态、空指针等：可选追输入源（不强制）
        """
        explicit_required = os.environ.get("JOERN_REQUIRE_SOURCE_VULN_TYPES", "")
        explicit_optional = os.environ.get("JOERN_OPTIONAL_SOURCE_VULN_TYPES", "")
        normalized_vuln_type = (vuln_type or "").strip().lower()

        if explicit_required:
            required_set = {item.strip().lower() for item in explicit_required.split(",") if item.strip()}
            if normalized_vuln_type in required_set:
                return True
        if explicit_optional:
            optional_set = {item.strip().lower() for item in explicit_optional.split(",") if item.strip()}
            if normalized_vuln_type in optional_set:
                return False

        required_tokens = (
            "injection",
            "xss",
            "xxe",
            "ssrf",
            "deserialization",
            "path_traversal",
            "command_exec",
            "ldap",
            "sql",
        )
        optional_tokens = (
            "buffer_overflow",
            "use_after_free",
            "null_deref",
            "race",
            "unsafe_alloc",
            "integer_overflow",
            "memory_leak",
            "array_index",
            "concurrent_uaf",
            "double_free",
            "uninit_read",
            "mmio",
        )
        if any(token in normalized_vuln_type for token in required_tokens):
            return True
        if any(token in normalized_vuln_type for token in optional_tokens):
            return False

        # 未识别类型默认不强制，以免误伤内部触发型漏洞分析。
        return False

    # ---- 硬回溯（hard backtrace）：caller 相关性评分与防御逻辑检测 ----
    #
    # 本段代码仅服务于 _run_hard_backtrace，查询语句由 Python 拼接，不经过 LLM。
    # 若需「按缺口定向查某个 method/变量」，在硬回溯结束后的 LLM 扩展阶段处理
    #（见 _analyze_single_taint_flow 中 sufficiency_check + follow_up_query）。

    # 高价值 caller 关键词：出现在方法名中说明该 caller 更可能包含
    # 输入校验、防御分支或外部入口，值得优先取方法体。
    # 覆盖 C/C++ 和 Java Web 场景。
    _HIGH_VALUE_CALLER_HINTS = re.compile(
        r"(?i)(parse|handle|process|dispatch|validate|verify|check|sanitize|filter|"
        r"decode|read|recv|input|init|setup|main|entry|start|begin|prepare|"
        r"authenticate|authorize|permission|guard|protect|wrap|safe|secure|"
        # Java Web 场景：Controller/Service/Filter/Interceptor 等入口层
        r"controller|service|repository|filter|interceptor|middleware|"
        r"handler|endpoint|mapping|invoke|execute|action|listener|servlet)",
    )

    # 防御逻辑关键词：在 caller 方法体中发现这些，说明已经找到了
    # "上游是否做了校验"的证据，继续向上追价值递减。
    # 覆盖范围：
    #   1) if 条件分支：长度/大小/空值/范围/校验/溢出等
    #   2) 数值比较运算符：>=, <=, > MAX 等边界检查
    #   3) 返回值防御：return ERROR/FAIL/NULL/-1/MBEDTLS_ERR_* 等
    #   4) goto 错误处理：goto error/fail/cleanup 等
    #   5) 异常防御：throw Exception/Error
    #   6) 权限/鉴权校验：hasPermission/isAuthorized/isAdmin 等
    #   7) 正则/白名单验证：regex_match/Pattern/isalnum 等
    #   8) 锁/同步机制：mutex_lock/synchronized/Lock 等
    #   9) 断言宏：assert()/ASSERT()/BUG_ON() 等
    #  10) C 错误码模式：errno != 0 / ret < 0 等
    #  11) C++ try-catch 块
    #  12) 空值/空串检查：isEmpty()/isBlank()/strlen()==0 等
    #  13) 指针算术边界检查：if (end - p < n) / CHK_BUF_PTR 等
    #  14) mbedtls 专用校验宏：MBEDTLS_SSL_CHK_BUF_PTR / MBEDTLS_CHK 等
    #  15) if + 逻辑非防御：if (!ptr) / if (!*p) 等
    #  16) 安全函数调用：snprintf/strlcpy/mbedtls_platform_zeroize 等
    #  17) early return 防御：if (x > y) return; / if (...) goto ...
    #  18) 类型安全检查：instanceof / dynamic_cast / static_assert
    #  19) 释放后置空（防 UAF）：free(p); p = NULL
    _GUARD_LOGIC_PATTERN = re.compile(
        r"(?i)("
        # 1) if 条件中的防御关键词
        r"\bif\s*\([^)]*(?:len|size|length|count|null|valid|check|bound|"
        r"range|limit|max|min|overflow|exceed|invalid|error|reject|deny|"
        r"assert|guard|sanitize|filter|escape|encode|normalize|"
        # 12) 空值/空串检查
        r"empty|blank|nil|undefined|zero|is_empty|is_null|is_valid)"
        # 2) 数值比较运算符边界检查
        r"|\bif\s*\([^)]*(?:\s*[><=!]=?\s*[A-Z_0-9]+|sizeof\s*\()"
        # 3) 返回值防御
        r"|return\s+.*(?:ERROR|FAIL|INVALID|NULL|-1|ENOMEM|EINVAL|EACCES|EPERM|EBADF|MBEDTLS_ERR_)"
        # 4) goto 错误处理
        r"|goto\s+(?:error|fail|cleanup|out|exit|err|bail|done|invalid|reject)"
        # 5) 异常防御
        r"|throw\s+.*(?:Exception|Error|IllegalArgument|IllegalState|Security|Permission|Invalid)"
        # 6) 权限/鉴权校验
        r"|(?:has|is|check|require)(?:Permission|Access|Auth|Role|Admin|Privilege|Credential|Token|Session)"
        # 7) 正则/白名单/格式验证
        r"|(?:regex|pattern|regexp|whitelist|allowlist|blacklist|denylist)_?(?:match|compile|check|test|validate)"
        r"|isalnum|isalpha|isdigit|isprint|iscntrl"
        # 8) 锁/同步机制
        r"|mutex_(?:lock|unlock|trylock)|pthread_mutex|synchronized|ReentrantLock|Lock\s*\(|spin_lock|rwlock"
        # 9) 断言宏
        r"|\b(?:assert|ASSERT|BUG_ON|WARN_ON|VERIFY|EXPECT)\s*\("
        # 10) C 错误码模式：errno/ret/retval 比较
        r"|errno\s*[!=]=|ret\s*[<>=!]=\s*-?\d|retval\s*[<>=!]=\s*-?\d|err\s*[<>=!]=\s*-?\d"
        # 11) C++ try-catch
        r"|\btry\s*\{|\bcatch\s*\("
        # 13) 指针算术边界检查（mbedtls/C 高频）
        #     if (end - p < n)  /  if (p + len > end)  /  if (end < p + n)
        r"|\bif\s*\([^)]*(?:end\s*[-+]\s*\w|\w+\s*[-+]\s*\w+\s*[><]=?\s*\w+|"
        r"\w+\s*[><]=?\s*\w+\s*[-+]\s*\w+|"
        r"(?:CHK|chk)_?(?:BUF|buf|PTR|ptr|READ|read))"
        # 14) mbedtls 专用校验宏
        r"|MBEDTLS_(?:SSL_CHK_BUF_READ_PTR|SSL_CHK_BUF_PTR|CHK|ASN1_CHK|CHECK_PARAMS|"
        r"SSL_DEBUG_MSG|PLATFORM_ZEROIZE|SAFE_ADD|SAFE_MUL)"
        # 15) if + 逻辑非防御：if (!ptr) / if (!*p) / if (!buf)
        r"|\bif\s*\(\s*!\s*\*?\w+\s*\)"
        # 16) 安全函数调用（作为防御手段被主动调用）
        r"|\b(?:snprintf|strlcpy|strlcat|strncpy_s|strcpy_s|sprintf_s|fopen_s|"
        r"mbedtls_platform_zeroize|mbedtls_safe_checks|"
        r"memset_s|memcpy_s|memmove_s)\s*\("
        # 17) early return 防御：简单 return 在 if 块中（无错误码但阻断执行流）
        r"|\bif\s*\([^)]*[><=!]=?[^)]*\)\s*(?:return\b|goto\b)"
        # 18) 类型安全检查
        r"|\b(?:instanceof|dynamic_cast|typeid|static_assert)\b"
        # 19) 释放后置空（防 UAF）
        r"|\bfree\s*\([^)]+\)\s*;\s*\w+\s*=\s*(?:NULL|0|nullptr)"
        r")",
    )

    # ---------- LLM 语义防御检测（正则兑底） ----------
    # 正则无法穷举所有防御模式（语义理解、自定义宏、组合逻辑等），
    # 因此当正则未命中时，用 LLM 做一次轻量语义判断作为兑底。
    _GUARD_LLM_SYSTEM_PROMPT = (
        "你是代码安全审计助手。判断给定函数体是否包含防御/校验逻辑。"
        "防御逻辑包括但不限于：参数校验、边界检查、输入清洗、空值检查、"
        "长度限制、类型检查、错误处理返回、权限校验、自定义安全宏等。"
        "只输出合法 JSON，不要输出其他内容。"
    )

    def _llm_check_guard_logic(self, caller_body: str, vuln_type: str) -> bool:
        """
        用 LLM 语义判断 caller 方法体是否包含防御逻辑。

        这是正则 `_GUARD_LOGIC_PATTERN` 的兑底方案：
        正则无法覆盖语义级别的防御意图（如自定义宏、组合逻辑、隐含边界检查等），
        LLM 能理解代码语义从而补上正则的盲区。

        可通过环境变量 `JOERN_LLM_GUARD_CHECK=0` 关闭（仅用正则）。

        Args:
            caller_body: caller 方法的完整源码（dumpRaw）。
            vuln_type: 当前分析的漏洞类型，用于 LLM 上下文。

        Returns:
            True 表示 LLM 判断存在防御逻辑，应提前终止回溯。
        """
        if os.environ.get("JOERN_LLM_GUARD_CHECK", "1") != "1":
            return False
        # 截断避免浪费 token：防御判断只需看前 ~6000 字符
        body_text = caller_body[:6000]
        user_prompt = (
            f"### 漏洞类型\n{vuln_type}\n\n"
            f"### 函数体\n```\n{body_text}\n```\n\n"
            f"请判断该函数体是否包含与上述漏洞类型相关的防御/校验逻辑。\n"
            f"输出 JSON：{{\"has_guard\": true/false, \"reason\": \"一句话理由\"}}"
        )
        try:
            llm_client = self._get_llm()
            response = llm_client.complete(
                system_prompt=self._GUARD_LLM_SYSTEM_PROMPT,
                user_prompt=user_prompt,
                temperature=0.1,
                max_tokens=200,
            )
            result = self._parse_llm_json(response)
            has_guard = bool(result.get("has_guard", False))
            reason = result.get("reason", "")
            if has_guard:
                logger.info("LLM 语义防御检测命中: vuln_type=%s, reason=%s", vuln_type, reason)
            return has_guard
        except Exception as exc:
            logger.warning("LLM 防御检测异常（不影响主流程）: %s", exc)
            return False

    # 按漏洞类型推荐的回溯深度上限：
    # 设计原则：
    #   - 内存安全类（2-3 hop）：通常只需找到边界检查/分配校验层即可
    #   - 注入类（3-4 hop）：必须追到可控输入源，否则无法判断可利用性
    #   - 配置/类型类（2 hop）：问题通常就在使用点附近，不需要深追
    #   - 嵌入式类（2-4 hop）：协议解析类需较深，硬件接口类较浅
    #   - Java Web 类（2-4 hop）：注入类需追到 Controller/Request 入口
    _VULN_TYPE_DEPTH_PROFILE = {
        # ---- C/C++ 内存安全 ----
        "buffer_overflow": {"max_hops": 3, "max_methods": 18},
        "use_after_free": {"max_hops": 3, "max_methods": 18},
        "null_deref": {"max_hops": 2, "max_methods": 12},
        "unsafe_alloc": {"max_hops": 2, "max_methods": 12},
        "integer_overflow": {"max_hops": 3, "max_methods": 18},
        "custom_mem": {"max_hops": 2, "max_methods": 12},
        "double_free": {"max_hops": 2, "max_methods": 12},
        "uninit_read": {"max_hops": 2, "max_methods": 12},
        "dangerous_func": {"max_hops": 2, "max_methods": 10},
        "memory_leak": {"max_hops": 2, "max_methods": 14},
        "array_index_oob": {"max_hops": 3, "max_methods": 18},
        "concurrent_uaf_risk": {"max_hops": 3, "max_methods": 18},
        "can_or_buffer_parsing": {"max_hops": 3, "max_methods": 18},
        # ---- C/C++ 注入类（需追到输入源） ----
        "format_string": {"max_hops": 3, "max_methods": 18},
        "command_injection": {"max_hops": 4, "max_methods": 24},
        "command_exec": {"max_hops": 4, "max_methods": 24},
        "path_traversal": {"max_hops": 4, "max_methods": 24},
        "race_condition": {"max_hops": 3, "max_methods": 18},
        # ---- C/C++ 配置/类型类（问题在使用点附近） ----
        "temp_file": {"max_hops": 2, "max_methods": 12},
        "weak_crypto": {"max_hops": 2, "max_methods": 12},
        "hardcoded_secret": {"max_hops": 2, "max_methods": 10},
        "type_confusion": {"max_hops": 2, "max_methods": 12},
        "signal_handler": {"max_hops": 2, "max_methods": 10},
        # ---- 嵌入式/固件 ----
        "buffer_parsing": {"max_hops": 3, "max_methods": 18},
        "protocol_reassembly": {"max_hops": 4, "max_methods": 24},
        "ioctl_mmio": {"max_hops": 2, "max_methods": 12},
        "firmware_update": {"max_hops": 4, "max_methods": 20},
        "crypto_misuse": {"max_hops": 2, "max_methods": 12},
        "interrupt_shared_state": {"max_hops": 3, "max_methods": 15},
        # ---- Java Web 注入类（需追到 Controller/Request 入口） ----
        "sql_injection": {"max_hops": 4, "max_methods": 24},
        "xss": {"max_hops": 4, "max_methods": 24},
        "ssrf": {"max_hops": 3, "max_methods": 18},
        "ldap_injection": {"max_hops": 3, "max_methods": 18},
        "xxe": {"max_hops": 3, "max_methods": 18},
        "insecure_deserialization": {"max_hops": 4, "max_methods": 24},
        "ssti": {"max_hops": 4, "max_methods": 20},
        "log_injection": {"max_hops": 4, "max_methods": 20},
        "file_upload": {"max_hops": 3, "max_methods": 18},
        # ---- Java Web 配置类（问题在配置点附近） ----
        "open_redirect": {"max_hops": 2, "max_methods": 12},
        "cors_misconfiguration": {"max_hops": 2, "max_methods": 10},
    }

    def _score_caller_relevance(self, caller_name: str, caller_body: str) -> int:
        """
        给一个 caller 打相关性分，决定是否值得取它的完整方法体。

        Returns:
            分数 >= 2: 高优先，取方法体
            分数 1: 中等，仅在还有余量时取
            分数 0: 低价值，跳过
        """
        score = 0
        if self._HIGH_VALUE_CALLER_HINTS.search(caller_name or ""):
            score += 2
        if caller_body and self._GUARD_LOGIC_PATTERN.search(caller_body):
            score += 3
        if caller_body and self._looks_like_user_input_source([caller_name], caller_body):
            score += 4
        # 纯 pass-through wrapper（方法体极短、无分支）价值低
        if caller_body and len(caller_body.strip()) < 80 and "if" not in caller_body.lower():
            score -= 1
        return max(score, 0)

    def _run_hard_backtrace(
        self,
        *,
        vuln_type: str,
        joern_text: str,
        context_text: str,
    ) -> Dict[str, Any]:
        """
        执行「硬回溯」：用**代码写死**的 Joern 查询沿调用链向上追 caller（非 LLM 生成 query）。

        应用场景（何时用硬回溯、不用 LLM 扩展）：
        - 已有单条污点 flow，需要知道**谁调用了 sink 方法**、上游方法体里有没有 **guard/边界检查**。
        - 希望在主分析 LLM 之前，用确定性、可复现的方式先扫 1~N 层 caller（BFS + top-K dumpRaw）。
        - 注入类等类型可配置「必须见到输入源」；硬回溯会尝试用名称/代码启发式识别 source。

        与 LLM 扩展查询的分工：
        - 硬回溯：固定 `.caller` + `dumpRaw`，命中防御可 `guard_logic_found` 提前停。
        - LLM 扩展：仅在硬回溯 + 初始片段仍「不充分」时，按缺口追加**定向**查询（见 _analyze_single_taint_flow 中 while 循环）。

        设计目标：
        - 固定顺序回溯，避免模型每轮先发散
        - 尽量把“上游调用 + 方法体 + 防御分支”补齐后，再让模型判定充分性
        - 设置明确停止条件，防止无限循环和算力浪费

        审计：每条 Joern 查询记为 query_source=hard_backtrace_caller_list / hard_backtrace_caller_body。
        """
        if os.environ.get("JOERN_ENABLE_HARD_BACKTRACE", "1") != "1":
            self._emit_audit(
                "hard_backtrace_started",
                {
                    "vuln_type": vuln_type,
                    "skipped": True,
                    "reason": "JOERN_ENABLE_HARD_BACKTRACE=0",
                },
            )
            return {
                "context_text": context_text,
                "stop_reason": "hard_backtrace_disabled",
                "hops": 0,
                "visited_methods": 0,
            }

        self._emit_audit(
            "hard_backtrace_started",
            {
                "vuln_type": vuln_type,
                "stage_note": ANALYSIS_STAGE_NOTES["hard_backtrace"],
                "mechanism": "code_fixed_caller_chain",
                "not_llm_generated": True,
            },
        )

        # 这组参数共同决定"硬回溯"的成本上限：
        # - hops: 最多向上追几层 caller
        # - branching: 每层最多展开多少方法
        # - caller_limit: 每个方法最多取多少 caller
        # - max_methods: 总共最多访问多少方法
        #
        # 优化策略：按漏洞类型自动调整深度上限。
        # 例如 null_deref 只需 2 hop，不需要追 4 层浪费算力；
        # command_injection 需要追到输入源，允许 4 层。
        vuln_type_key = vuln_type.replace("cpp_", "").replace("embedded_", "")
        depth_profile = self._VULN_TYPE_DEPTH_PROFILE.get(vuln_type_key, {})
        default_hops = depth_profile.get("max_hops", 4)
        default_methods = depth_profile.get("max_methods", 24)
        
        max_hops = max(1, int(os.environ.get("JOERN_HARD_BACKTRACE_MAX_HOPS", str(default_hops))))
        max_hops += max(0, int(os.environ.get("JOERN_HARD_BACKTRACE_HOPS_BONUS", "0")))
        max_expand_per_hop = max(1, int(os.environ.get("JOERN_HARD_BACKTRACE_BRANCHING", "3")))
        max_callers_per_method = max(1, int(os.environ.get("JOERN_HARD_BACKTRACE_CALLER_LIMIT", "6")))
        max_visited_methods = max(1, int(os.environ.get("JOERN_HARD_BACKTRACE_MAX_METHODS", str(default_methods))))
        stagnation_limit = max(1, int(os.environ.get("JOERN_HARD_BACKTRACE_STAGNATION_LIMIT", "2")))
        top_caller_bodies = max(1, int(os.environ.get("JOERN_HARD_BACKTRACE_TOP_CALLER_BODIES", "2")))
        require_source = self._requires_source_for_vuln_type(vuln_type)

        # 从首轮 Joern 输出里提取方法名，作为 BFS 起点集合。
        frontier_methods = self._extract_method_candidates_from_joern(joern_text)
        if not frontier_methods:
            return {
                "context_text": context_text,
                "stop_reason": "no_method_seed",
                "hops": 0,
                "visited_methods": 0,
            }

        # 【UAF/Double-Free 专用】向下追踪：获取包含 free 的完整方法体
        # 对 UAF/Double-Free，关键证据在 free 之后，不是之前。
        # 先获取方法体，让 LLM 能看到 free 后指针是否被置 NULL / 被再次使用。
        is_uaf_or_double_free = any(
            token in vuln_type.lower()
            for token in ("use_after_free", "double_free", "uaf")
        )
        if is_uaf_or_double_free and frontier_methods:
            forward_method = frontier_methods[0]
            try:
                escaped_name = forward_method.replace("\\", "\\\\").replace('"', '\\"')
                forward_query = f'cpg.method.name("{escaped_name}").take(1).dumpRaw'
                forward_result = self._post_query(
                    forward_query,
                    timeout=120,
                    ensure_active_project=True,
                )
                if (
                    forward_result
                    and "Error:" not in forward_result
                    and len(forward_result) > 50
                ):
                    context_text += (
                        f"\n\n### 向下追踪（UAF/Double-Free 专用）\n"
                        f"以下是包含 free 调用的完整方法体，请重点关注 free 后指针是否被置 NULL 或被再次使用/释放：\n"
                        f"```\n{forward_result[:6000]}\n```\n"
                    )
                    self._emit_joern_query_audit(
                        query_source="hard_backtrace_forward",
                        query_text=forward_query,
                        result_text=forward_result,
                        extra={
                            "vuln_type": vuln_type,
                            "stage_note": "UAF/Double-Free 专用：获取 free 后的完整方法体，检查指针是否被置 NULL",
                        },
                    )
            except Exception as e:
                logger.debug("UAF/Double-Free forward trace failed: %s", e)

        visited_methods = set()
        current_context_text = context_text
        consecutive_no_growth = 0
        stop_reason = "max_hops_reached"
        hops_executed = 0
        source_reached_global = False

        for hop_index in range(1, max_hops + 1):
            if not frontier_methods:
                stop_reason = "empty_frontier"
                break
            if len(visited_methods) >= max_visited_methods:
                stop_reason = "visited_limit_reached"
                break

            hops_executed = hop_index
            next_frontier: List[str] = []
            context_grew_this_hop = False
            source_reached_this_hop = False

            for method_name in frontier_methods[:max_expand_per_hop]:
                if not method_name or method_name in visited_methods:
                    continue
                visited_methods.add(method_name)
                escaped_method_name = self._escape_joern_string_literal(method_name)
            
                # 优化：先取 caller 的 fullName（廉价查询），再按相关性打分，
                # 只对高价值 caller 取方法体（昂贵查询）。
                caller_name_query = f'''
                cpg.method.name("{escaped_method_name}")
                .caller
                .fullName
                .dedup
                .take({max_callers_per_method})
                .l
                '''
                caller_name_result = self._post_query(
                    caller_name_query,
                    timeout=180,
                    ensure_active_project=True,
                )
                self._emit_joern_query_audit(
                    query_source="hard_backtrace_caller_list",
                    query_text=caller_name_query,
                    result_text=caller_name_result,
                    extra={
                        "vuln_type": vuln_type,
                        "hop": hop_index,
                        "method_name": method_name,
                    },
                )
                caller_full_names = self._parse_joern_list_strings(
                    caller_name_result, max_items=max_callers_per_method
                )
            
                # 对 caller 名称做初步评分（仅基于名称，不取 body）。
                scored_callers = []
                for caller_full_name in caller_full_names:
                    caller_short_name = re.sub(r"\(.*$", "", caller_full_name).strip()
                    if "." in caller_short_name:
                        caller_short_name = caller_short_name.split(".")[-1]
                    if ":" in caller_short_name:
                        caller_short_name = caller_short_name.split(":")[-1]
                    caller_short_name = caller_short_name or caller_full_name
                    name_score = self._score_caller_relevance(caller_short_name, "")
                    scored_callers.append((caller_full_name, caller_short_name, name_score))
                # 按分数降序，优先处理高分 caller。
                scored_callers.sort(key=lambda item: item[2], reverse=True)
            
                # 只对分数 >= 1 的 caller 取方法体；分数 0 的只保留名称用于下一跳。
                high_value_callers = [
                    (caller_full_name, caller_short_name, score)
                    for caller_full_name, caller_short_name, score in scored_callers
                    if score >= 1
                ]
                callers_for_body = high_value_callers[:top_caller_bodies]
                caller_body_result = ""

                # 仅对 top-K 高分 caller 拉取 dumpRaw，避免无关方法体污染 context。
                if callers_for_body:
                    # 兼容性考虑：不同 Joern 版本对 `.filter(_.name.matches(...))` 语法支持不一致。
                    # 因此这里改为“逐 caller 单独查询方法体”，避免 DSL 兼容性问题。
                    caller_bodies: List[str] = []
                    guarded_edges_this_hop: List[Dict[str, Any]] = []
                    callee_fulls_for_hop = self._query_method_full_names(method_name)
                    for caller_full_name, _, _ in callers_for_body:
                        if not caller_full_name:
                            continue
                        # `cpg.method.fullName(...)` 使用正则，先做 regex-escape，避免把 "." 等字符误当模式。
                        escaped_caller_fullname_regex = self._escape_joern_string_literal(
                            re.escape(caller_full_name)
                        )
                        single_caller_query = f'''
                        cpg.method.fullName("{escaped_caller_fullname_regex}")
                        .take(1)
                        .dumpRaw
                        '''
                        single_body = self._post_query(
                            single_caller_query,
                            timeout=220,
                            ensure_active_project=True,
                        )
                        self._emit_joern_query_audit(
                            query_source="hard_backtrace_caller_body",
                            query_text=single_caller_query,
                            result_text=single_body,
                            extra={
                                "vuln_type": vuln_type,
                                "hop": hop_index,
                                "method_name": method_name,
                                "caller_full_name": caller_full_name,
                            },
                        )
                        if "Error:" not in single_body and len(single_body.strip()) > 40:
                            caller_bodies.append(single_body)
                            regex_hit = bool(
                                self._GUARD_LOGIC_PATTERN.search(single_body)
                            )
                            llm_hit = False
                            if not regex_hit:
                                llm_hit = self._llm_check_guard_logic(
                                    single_body, vuln_type
                                )
                            if regex_hit or llm_hit:
                                guard_source = "regex" if regex_hit else "llm"
                                resolved_callees = callee_fulls_for_hop or [method_name]
                                for callee_full in resolved_callees:
                                    edge_key = self._record_guard_call_edge(
                                        vuln_type, callee_full, caller_full_name
                                    )
                                    guarded_edges_this_hop.append(
                                        {
                                            "callee_short": method_name,
                                            "callee_full": callee_full,
                                            "caller_full": caller_full_name,
                                            "edge_key": edge_key,
                                            "guard_source": guard_source,
                                        }
                                    )
                    caller_body_result = "\n\n".join(caller_bodies).strip()

                    if caller_body_result and "Error:" not in caller_body_result and len(caller_body_result.strip()) > 40:
                        caller_context = self._extract_code_context(caller_body_result)
                        merged_context = self._merge_context(current_context_text, caller_context)
                        if len(merged_context) > len(current_context_text):
                            context_grew_this_hop = True
                            current_context_text = merged_context
                        if guarded_edges_this_hop:
                            has_guard_logic = True
                            guard_source = guarded_edges_this_hop[0].get(
                                "guard_source", "unknown"
                            )
                            logger.info(
                                "硬回溯找到防御逻辑(%s)，提前终止: type=%s hop=%s "
                                "guarded_edges=%s",
                                guard_source,
                                vuln_type,
                                hop_index,
                                guarded_edges_this_hop,
                            )
                            self._emit_audit(
                                "backtrace_guard_found",
                                {
                                    "vuln_type": vuln_type,
                                    "hop": hop_index,
                                    "method": method_name,
                                    "guard_source": guard_source,
                                    "guarded_call_edges": guarded_edges_this_hop,
                                    "stage_note": (
                                        "硬回溯在特定 caller→callee 边上发现防御逻辑，"
                                        "已按 methodFullName 调用边写入剪枝缓存。"
                                    ),
                                    "guard_detection": (
                                        "regex" if guard_source == "regex"
                                        else "llm_semantic" if guard_source == "llm"
                                        else "unknown"
                                    ),
                                },
                            )
                            stop_reason = "guard_logic_found"
                            break
            
                # 全部 caller 名称都进入下一跳 frontier（含低分的），
                # 但低分的只在还有余量时才会被展开。
                for _, caller_short_name, _ in scored_callers:
                    if caller_short_name not in visited_methods and caller_short_name not in next_frontier:
                        next_frontier.append(caller_short_name)
            
                caller_names_for_source_check = [short_name for _, short_name, _ in scored_callers]
                if self._looks_like_user_input_source(
                    caller_names_for_source_check + [method_name],
                    caller_body_result if high_value_callers else "",
                ):
                    source_reached_this_hop = True
            
                if len(visited_methods) >= max_visited_methods:
                    break

            if context_grew_this_hop:
                consecutive_no_growth = 0
            else:
                consecutive_no_growth += 1

            # 如果内层循环因找到防御逻辑而 break，外层也提前终止。
            if stop_reason == "guard_logic_found":
                break

            if source_reached_this_hop:
                source_reached_global = True
                stop_reason = "source_reached"
                break
            if consecutive_no_growth >= stagnation_limit:
                # 连续多跳没有拿到新上下文时提前结束，避免无效查询循环。
                stop_reason = "no_context_growth"
                break

            # 下一跳只保留当前新发现的 caller，按 BFS 方式逐层向上追。
            frontier_methods = next_frontier[:max_visited_methods]

        # 某些漏洞类型（如注入类）强依赖“可控输入”证据；
        # 若未追到 Source，就显式标记该停止原因，提醒后续模型继续补证。
        if require_source and not source_reached_global and stop_reason != "source_reached":
            stop_reason = "source_required_but_not_reached"

        return {
            "context_text": current_context_text,
            "stop_reason": stop_reason,
            "hops": hops_executed,
            "visited_methods": len(visited_methods),
            "require_source": require_source,
            "source_reached": source_reached_global,
        }

    def _add_snippet(
        self,
        snippets: List[str],
        seen_locations: set,
        file_path: str,
        line_num: str,
        method_name: str,
        tracked: str,
    ):
        """
        向上下文列表中追加一个代码片段，并尝试补充本地源码上下文。

        Args:
            snippets: 已收集的片段列表。
            seen_locations: 用于去重的集合，避免同一文件行号重复加入。
            file_path: Joern 返回的文件路径。
            line_num: 关键代码所在行号。
            method_name: 所属方法名。
            tracked: Joern 认为与路径相关的关键代码。
        """
        location_key = f"{file_path or 'unknown'}:{line_num}"
        if location_key in seen_locations or not tracked:
            return
        seen_locations.add(location_key)

        language_name = "java" if file_path and file_path.endswith(".java") else "c"
        snippets.append(
            f"```{language_name}\n// File: {file_path} | Line: {line_num} | Method: {method_name or 'N/A'}\n{tracked}\n```"
        )

        if file_path and line_num.isdigit():
            local_path = self._map_to_local_path(file_path)
            if local_path and os.path.exists(local_path):
                try:
                    with open(local_path, "r", encoding="utf-8", errors="ignore") as source_file:
                        file_lines = source_file.readlines()
                    line_number = int(line_num)
                    local_window = self._extract_line_window(file_lines, line_number)
                    guard_context = self._extract_guard_context(file_lines, line_number)
                    method_context = self._extract_enclosing_method_context(file_lines, line_number)
                    if local_window:
                        snippets.append(
                            f"📍 **本地局部上下文** `{file_path}:{line_num}`:\n```{language_name}\n{local_window}\n```"
                        )
                    if guard_context:
                        snippets.append(
                            f"🛡️ **附近防御/分支线索** `{file_path}:{line_num}`:\n```text\n{guard_context}\n```"
                        )
                    if method_context:
                        snippets.append(
                            f"🧩 **所在方法体** `{file_path}:{line_num}`:\n```{language_name}\n{method_context}\n```"
                        )
                except Exception:
                    pass

    def _parse_llm_json(self, text: str) -> dict:
        """
        尝试把大模型输出解析为 JSON。

        Args:
            text: LLM 返回文本。可能是纯 JSON，也可能被 Markdown 代码块包裹。

        Returns:
            解析后的字典；如果解析失败，则返回一份保守默认值。
        """
        cleaned_text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip(), flags=re.IGNORECASE)
        try:
            return json.loads(cleaned_text)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", cleaned_text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group())
                except json.JSONDecodeError:
                    pass
        return {
            "sufficient": False,
            "confidence": 0.0,
            "missing_context_type": ["sink_full_implementation"],
            "expansion_hints": ["模型输出解析失败，优先查看当前嫌疑方法体和附近防御逻辑"],
            "expansion_intent": "view_method_body",
            "intent_params": {},
        }

    def _context_body_max_chars(self) -> int:
        return max(2000, int(os.environ.get("JOERN_CONTEXT_BODY_MAX_CHARS", "12000")))

    def _extract_list_triple_quoted_blocks(self, text: str) -> List[str]:
        """从 Joern List(\"\"\"...\"\"\") / dumpRaw / body.p 输出中提取 AST 文本块。"""
        blocks: List[str] = []
        seen: set = set()
        for match in re.finditer(r'"""(.*?)"""', text, re.DOTALL):
            content = match.group(1).strip()
            if len(content) < 20:
                continue
            if not any(
                marker in content
                for marker in ("CODE:", "METHOD", "BLOCK", "CALL", "IDENTIFIER", "CONTROL_STRUCTURE")
            ):
                continue
            fingerprint = content[:160]
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            blocks.append(content)
        return blocks

    def _format_method_body_snippet(self, raw_block: str, method_hint: str = "") -> str:
        """将 dumpRaw/body.p 的 AST 块格式化为 LLM 可读的代码片段。"""
        body = raw_block.strip()
        code_match = re.search(r"CODE:\s*\{", body)
        if code_match:
            body = body[code_match.start() :]
        file_match = re.search(r'fileName\s*=\s*["\']?([^"\',\s]+)', body)
        line_match = re.search(r"LINE_NUMBER:\s*(\d+)", body)
        file_path = file_match.group(1) if file_match else "unknown.c"
        line_number = line_match.group(1) if line_match else "?"
        max_chars = self._context_body_max_chars()
        if len(body) > max_chars:
            body = body[:max_chars] + "\n/* ... truncated at JOERN_CONTEXT_BODY_MAX_CHARS ... */"
        header_parts = [f"{file_path}:{line_number}"]
        if method_hint:
            header_parts.append(method_hint)
        header = " // ".join(header_parts)
        return f"```c\n// {header}\n{body}\n```"

    @classmethod
    def _normalize_expansion_query_key(cls, query: str) -> str:
        """归一化扩展查询 DSL，用于本 flow 内去重（body.p 与 dumpRaw 视为等价）。"""
        normalized = re.sub(r"\s+", " ", (query or "").strip().lower())
        normalized = re.sub(r"\.body\.p\b", ".take(3).dumpraw", normalized)
        normalized = re.sub(r"\.body\b(?!\.)", ".take(3).dumpraw", normalized)
        return normalized

    def _get_cve_knowledge_reference(self, vuln_type: str) -> str:
        """
        从 CVE 知识库获取当前漏洞类型的参考信息。

        Args:
            vuln_type: 漏洞类型，如 'cpp_buffer_overflow'。

        Returns:
            可嵌入分析上下文的 CVE 参考文本。若无可参考则返回空字符串。
        """
        # vuln_type → CWE 映射
        vtype_to_cwe = {
            "cpp_buffer_overflow": "CWE-120", "cpp_can_or_buffer_parsing": "CWE-120",
            "embedded_buffer_parsing": "CWE-120",
            "cpp_use_after_free": "CWE-416",
            "cpp_double_free": "CWE-415",
            "cpp_integer_overflow": "CWE-190", "cpp_unsafe_alloc": "CWE-131",
            "cpp_command_injection": "CWE-78", "command_injection": "CWE-78",
            "embedded_command_injection": "CWE-78",
            "cpp_path_traversal": "CWE-22", "path_traversal": "CWE-22",
            "sql_injection": "CWE-89",
            "insecure_deserialization": "CWE-502",
            "ssrf": "CWE-918",
            "xxe": "CWE-611",
            "cpp_hardcoded_secret": "CWE-798", "hardcoded_secrets": "CWE-798",
            "cpp_weak_crypto": "CWE-327", "weak_crypto": "CWE-327",
            "cpp_race_condition": "CWE-362", "embedded_race_condition": "CWE-362",
            "cpp_format_string": "CWE-134",
            "cpp_null_deref": "CWE-476",
            "cpp_dangerous_func": "CWE-676",
        }
        cwe_id = vtype_to_cwe.get(vuln_type, "")
        if not cwe_id:
            return ""

        # 懒加载 CVE 知识库
        if self._cve_knowledge_base is None:
            try:
                from cve_knowledge_base import CVEKnowledgeBase
                self._cve_knowledge_base = CVEKnowledgeBase()
            except Exception as exc:
                logger.debug("CVE 知识库加载失败（非致命）: %s", exc)
                self._cve_knowledge_base = False  # 标记为加载失败，避免重复尝试

        if not self._cve_knowledge_base:
            return ""

        try:
            return self._cve_knowledge_base.get_analysis_context_text(cwe_id)
        except Exception as exc:
            logger.debug("CVE 知识查询失败: %s", exc)
            return ""

    def _merge_context(self, old_ctx: str, new_ctx: str, max_lines: Optional[int] = None) -> str:
        """
        合并两段上下文，并尽可能去重。

        Args:
            old_ctx: 旧上下文。
            new_ctx: 新补充的上下文。
            max_lines: 粗粒度的长度限制，防止上下文无限膨胀。

        Returns:
            合并后的上下文文本。
        """
        if max_lines is None:
            max_lines = int(os.environ.get("JOERN_CONTEXT_MERGE_MAX_LINES", "200"))
        if not new_ctx:
            return old_ctx
        raw_sections = re.split(r"\n\s*\n", old_ctx + "\n\n" + new_ctx)
        seen_sections = set()
        unique_sections: List[str] = []
        for section in raw_sections:
            normalized_section = section.strip()
            if not normalized_section:
                continue
            fingerprint = normalized_section[:120]
            if fingerprint in seen_sections:
                continue
            seen_sections.add(fingerprint)
            unique_sections.append(normalized_section)

        limited_sections = unique_sections[: max_lines // 4]
        return "\n\n".join(limited_sections)

    def _sanitize_follow_up_query(self, query_text: str) -> str:
        """
        清洗大模型生成的 follow-up Joern 查询。

        Args:
            query_text: 模型建议的下一步查询 DSL。

        Returns:
            一个尽量安全、尽量能在 Joern 中执行的查询字符串；
            如果判断风险过高或明显不可修复，则返回空字符串。
        """
        if not query_text or not isinstance(query_text, str):
            return ""

        sanitized_query = query_text.strip()
        sanitized_query = re.sub(r"^```(?:json|scala|text|bash|sh)?\s*|\s*```$", "", sanitized_query, flags=re.IGNORECASE).strip()
        sanitized_query = re.sub(r"(?i)^\s*(query|joern_query)[:：]\s*", "", sanitized_query)
        sanitized_query = re.sub(r"\.l\b", ".p", sanitized_query)
        sanitized_query = sanitized_query.replace(".path.size", ".elements.size")
        sanitized_query = re.sub(r"\.contains\(", ".matches(", sanitized_query)
        sanitized_query = re.sub(r'cpg\.call\(\s*"([^"]+)"\s*\)', r'cpg.call.name("\1")', sanitized_query)
        # C/C++ 方法体：dumpRaw 比 body.p 更易解析且信息更全（含行号/文件名）
        sanitized_query = re.sub(
            r"\.body\.p\b",
            ".take(3).dumpRaw",
            sanitized_query,
            flags=re.IGNORECASE,
        )
        sanitized_query = re.sub(
            r"\.body\b(?!\.)",
            ".take(3).dumpRaw",
            sanitized_query,
            flags=re.IGNORECASE,
        )

        lines = [
            line
            for line in sanitized_query.splitlines()
            if not re.match(r"^\s*#|^\s*//\s*解释|^\s*注释|^\s*说明", line)
        ]
        sanitized_query = "\n".join(lines).strip()
        # 基础结构校验：括号不平衡通常意味着模型输出被截断或混入自然语言。
        if sanitized_query.count("(") != sanitized_query.count(")") or sanitized_query.count("{") != sanitized_query.count("}"):
            return ""
        if len(sanitized_query) > 2000:
            return ""
        # 拦截 LLM 生成的危险查询（全库 reachableByFlows 或无效方法名）
        if self._is_dangerous_joern_query(sanitized_query):
            return ""
        return sanitized_query

    def _determine_variant_from_check(self, check: dict) -> str:
        """
        根据大模型的上下文评估结果，决定是否切换 C/C++ 查询变体。

        Args:
            check: `_check_context_sufficiency` 返回的结构化结果。

        Returns:
            `embedded`、`generic` 或空字符串。
        """
        params = check.get("intent_params") or {}
        scope = (params.get("scope") or "").lower()
        hardware_tags = params.get("hw_tags") or check.get("intent_params", {}).get("hw_tags")

        if scope == "embedded" or (isinstance(hardware_tags, (list, tuple)) and hardware_tags):
            return "embedded"
        if scope == "generic" or os.environ.get("JOERN_FORCE_GENERIC", "0") == "1":
            return "generic"
        env_variant = os.environ.get("JOERN_CPP_VARIANT", "").lower()
        if env_variant in ("embedded", "generic"):
            return env_variant
        return ""

    def _check_context_sufficiency(
        self,
        joern_text: str,
        ctx: str,
        previous_failure: Optional[Dict[str, Any]] = None,
    ) -> dict:
        """
        让大模型评估"当前上下文是否足以判断漏洞真实性"。
    
        Args:
            joern_text: 初始 Joern 输出。
            ctx: 当前已经提取出的代码上下文。
            previous_failure: 可选，上一轮扩展查询的失败记录。
                包含 failed_query / error_message / iteration 字段。
                传入后 LLM 会知道上次尝试了什么、为什么失败，
                从而避免生成相同无效查询。
    
        Returns:
            一个 JSON 字典，里面会说明：
            - 当前上下文是否足够
            - 缺什么信息
            - 建议的扩展意图
            - 可选的 follow-up 查询
        """
        llm_client = self._get_llm()
        # 如果有上一轮失败记录，拼成一段反馈文本追加到用户消息末尾。
        failure_feedback = ""
        if previous_failure:
            failed_q = previous_failure.get("failed_query", "")[:400]
            error_msg = previous_failure.get("error_message", "")[:400]
            fail_iter = previous_failure.get("iteration", "?")
            if previous_failure.get("skipped_duplicate"):
                failure_feedback = (
                    f"\n\n### ⚠️ 上一轮重复查询已跳过（第 {fail_iter} 轮）\n"
                    f"**重复的查询 DSL：**\n```\n{failed_q}\n```\n"
                    f"**系统说明：**\n```\n{error_msg}\n```\n"
                    "请勿再次请求相同方法体/dumpRaw；若上下文已含该方法，请直接判断或改查 caller。"
                )
            else:
                failure_feedback = (
                    f"\n\n### ⚠️ 上一轮扩展查询失败记录（第 {fail_iter} 轮）\n"
                    f"**失败的查询 DSL：**\n```\n{failed_q}\n```\n"
                    f"**Joern 返回的错误：**\n```\n{error_msg}\n```\n"
                    "请在本次生成 follow_up_query 时避开上述错误，尝试使用不同的查询策略。"
                )
        # 主动提取方法名列表提供给 LLM，避免 LLM 从表头“method”胡乱猜测
        available_methods = self._extract_method_candidates_from_joern(joern_text, max_items=50)
        method_list_block = ""
        if available_methods:
            method_list_block = (
                "\n\n### 🔑 可用方法名（从 Joern 路径表格提取，生成查询时请从这里选取）\n"
                + ", ".join(f"`{m}`" for m in available_methods)
            )
        user_message = prompts.context_sufficiency_prompt.format(
            joern_text=joern_text[:10000],
            context_text=ctx[:25000],
        ) + method_list_block + failure_feedback
        response = llm_client.complete(
            system_prompt=prompts.inject_tool_capabilities(
                "你是严谨的代码审计助手。只输出合法JSON。",
                TOOL_CAPABILITIES,
            ),
            user_prompt=user_message,
            temperature=0.1,
            max_tokens=700,
        )
        return self._parse_llm_json(response)

    def _analysis_violates_verdict_policy(self, analysis_text: str, vuln_type: str) -> Optional[str]:
        """
        检查 flow 分析报告是否违反终态二选一 + PoC 必填规则。

        Returns:
            违规原因代码；None 表示通过。
        """
        if self._is_reflection_query_type(vuln_type):
            return None
        text = (analysis_text or "").strip()
        if not text:
            return "empty_analysis"

        if re.search(
            r"是否真实漏洞\s*[：:]\s*(⚠️?\s*部分是|待确认|部分|可能|需人工)",
            text,
            flags=re.IGNORECASE,
        ):
            return "ambiguous_verdict_not_allowed"

        if re.search(r"不提供\s*exploit|本报告不提供", text, flags=re.IGNORECASE):
            return "refused_to_provide_exploit"

        claims_exploitable = bool(
            re.search(
                r"RCE|远程代码执行|远程可利用|double[\s-]?free|二次释放|可被利用",
                text,
                flags=re.IGNORECASE,
            )
        )
        is_confirmed_yes = bool(re.search(r"是否真实漏洞\s*[：:]\s*✅\s*是", text))

        exploit_section = ""
        exploit_match = re.search(
            r"###\s*判定与修复[\s\S]*?漏洞利用\s*[：:]([\s\S]*?)(?=\n-\s*根本原因|\n###|\Z)",
            text,
        )
        if exploit_match:
            exploit_section = exploit_match.group(1).strip()
        elif "漏洞利用" in text:
            exploit_section = text.split("漏洞利用", 1)[-1][:2500].strip()

        exploit_is_empty = (
            not exploit_section
            or re.match(r"^无\s*$", exploit_section)
            or re.match(r"^无[\s\n]", exploit_section)
            or len(exploit_section) < 60
        )

        if is_confirmed_yes and exploit_is_empty:
            return "confirmed_yes_without_poc"

        if claims_exploitable and exploit_is_empty and not re.search(
            r"是否真实漏洞\s*[：:]\s*❌\s*否", text
        ):
            return "claims_exploitability_without_poc"

        if is_confirmed_yes and not re.search(
            r"(触发步骤|步骤\s*1|```|0x[0-9a-fA-F]{8,}|curl\s|mbedtls_|openssl\s|PoC|poc)",
            exploit_section,
            flags=re.IGNORECASE,
        ):
            return "poc_lacks_actionable_steps"

        return None

    def _build_guard_pruned_flow_result(
        self,
        *,
        vuln_type: str,
        flow_id: str,
        sink_label: str,
        matched_edge: Dict[str, str],
    ) -> str:
        callee_full = matched_edge.get("callee_full", "")
        caller_full = matched_edge.get("caller_full", "")
        edge_key = matched_edge.get("edge_key", "")
        logger.info(
            "guard_edge_cache 剪枝: 跳过 flow=%s type=%s edge=%s",
            flow_id,
            vuln_type,
            edge_key,
        )
        self._emit_audit(
            "flow_pruned_guard_cache",
            {
                "vuln_type": vuln_type,
                "flow_id": flow_id,
                "matched_edge": matched_edge,
                "cache_key": edge_key,
                "prune_mode": "call_edge_fullname",
                "stage_note": (
                    "本 flow 的 Joern 调用边 (caller→callee) 与已缓存的 guard 边一致，"
                    "跳过重复 LLM/反证。"
                ),
            },
        )
        refutation_stub = {
            "verdict": "likely_false_positive",
            "confidence_label": "medium",
            "evidence_levels": {
                "L1_joern": "present",
                "L2_static_files": "partial",
                "L3_dynamic": "not_verified",
            },
        }
        analysis = (
            f"是否真实漏洞：❌ 否\n"
            f"剪枝说明：调用边 `{caller_full}` → `{callee_full}` 已在同批次其它 "
            f"flow 硬回溯中命中 `guard_logic_found`，本 flow 不再重复分析。\n"
        )
        self._current_flow_meta = {
            "vuln_type": vuln_type,
            "flow_id": flow_id,
            "sink_label": sink_label,
            "backtrace": {
                "stop_reason": "guard_logic_found_pruned",
                "matched_call_edge": matched_edge,
            },
            "refutation": {
                "verdict": refutation_stub["verdict"],
                "confidence_label": refutation_stub["confidence_label"],
            },
            "analysis": analysis,
        }
        self._record_flow_scan_artifacts(
            vuln_type=vuln_type,
            flow_id=flow_id,
            refutation_result=refutation_stub,
            final_verdict_line="❌ 否",
        )
        flow_header = (
            f"## 🔎 {vuln_type.upper()} — `{flow_id}`\n"
            f"> **Sink 线索**: {sink_label or '未知'}（guard_edge_cache 剪枝）\n\n"
        )
        return f"\n---\n{flow_header}{analysis.strip()}\n"

    def _try_prune_by_guard_cache(
        self,
        *,
        vuln_type: str,
        flow_id: str,
        sink_label: str,
        joern_text: str,
    ) -> Optional[str]:
        """若 flow 的 (caller_full, callee_full) 边已在其它 flow 命中 guard，跳过分析。"""
        if os.environ.get("JOERN_GUARD_FLOW_PRUNE", "1") != "1":
            return None
        if not self._guarded_call_edge_cache:
            return None

        flow_edges = self._collect_flow_call_edges(
            vuln_type, joern_text, sink_label=sink_label
        )
        matched_edge = None
        for edge in flow_edges:
            if edge.get("edge_key") in self._guarded_call_edge_cache:
                matched_edge = edge
                break
        if not matched_edge:
            return None

        return self._build_guard_pruned_flow_result(
            vuln_type=vuln_type,
            flow_id=flow_id,
            sink_label=sink_label,
            matched_edge=matched_edge,
        )

    def _run_flow_analysis_llm(
        self,
        llm_client: LLMClient,
        *,
        vuln_type: str,
        flow_id: str,
        joern_text: str,
        context_text: str,
        language: str,
        extra_instruction: str = "",
    ) -> str:
        """生成单条 flow 的 Markdown 分析报告（含 VERDICT_AND_POC_POLICY）。"""
        context_text = self._merge_planner_l2_into_context(context_text)
        language_hint = "C/C++" if language.lower() in ["c", "cpp", "c++"] else "Java"
        user_prompt = prompts.user_prompt_template.format(
            language_hint=language_hint,
            vtype_upper=f"{vuln_type.upper()} ({flow_id})",
            text=joern_text[:12000],
            ctx=context_text[:12000],
            verdict_and_poc_policy=VERDICT_AND_POC_POLICY,
        )
        if extra_instruction:
            user_prompt = f"{extra_instruction.strip()}\n\n{user_prompt}"
        if self.local_source_path:
            user_prompt += (
                f"\n\n> **本地源码根目录**（报告中文件路径请写相对此目录，"
                f"勿混用 Joern 容器路径）: `{self.local_source_path}`\n"
            )
        max_tokens = int(os.environ.get("JOERN_ANALYSIS_MAX_TOKENS", "4500"))
        return llm_client.complete(
            system_prompt=prompts.inject_tool_capabilities(prompts.system_prompt, TOOL_CAPABILITIES),
            user_prompt=user_prompt,
            temperature=0.0,
            max_tokens=max_tokens,
        )

    def _force_safe_verdict_section(self, violation: str) -> str:
        """LLM 两次仍不合格时，用确定性块覆盖「判定与修复」，避免模糊终态。"""
        return (
            "\n\n### 判定与修复（系统覆写：未通过终态/PoC 校验）\n"
            f"- **是否真实漏洞**：❌ 否\n"
            f"- **漏洞利用**：无\n"
            f"- **根本原因**：自动校验未通过（{violation}）。"
            "报告曾含「部分是/待确认」或判✅是无 PoC/拒绝提供 exploit；"
            "需补 Joern caller 链或 FileTool 配置后再分析。\n"
            "- **修复建议**：补全上游调用链与二次释放证据后重跑；"
            "若证实可利用，须给出可执行 PoC（入口、恶意输入、步骤、预期结果）。\n"
        )

    def _build_insufficient_context_analysis(
        self,
        *,
        vuln_type: str,
        flow_id: str,
        max_iters: int,
        sufficiency_result: Dict[str, Any],
    ) -> str:
        """上下文扩展用尽仍不充分：跳过主分析 LLM，直接给出确定性否结论。"""
        reason = sufficiency_result.get("reason") or sufficiency_result.get("missing_context") or "证据不足"
        return (
            f"## 🔎 {vuln_type.upper()} ({flow_id}) 分析结果\n\n"
            f"### 判定与修复\n"
            f"- **是否真实漏洞**：❌ 否\n"
            f"- **漏洞利用**：无\n"
            f"- **根本原因**：LLM 上下文扩展已用尽（{max_iters} 轮）仍不充分（{reason}），"
            "无法支撑可利用性判定。\n"
            f"- **修复建议**：补读反证块中的 L2 文件（config.h / 相关 .c），或提高 max_iters 后重扫。\n"
        )

    def _build_guard_found_analysis(
        self,
        *,
        vuln_type: str,
        flow_id: str,
        callee: str,
        guard_source: str,
    ) -> str:
        """硬回溯找到防御逻辑时，直接生成确定性分析报告（跳过 LLM 主分析）。"""
        guard_desc = {
            "regex": "正则匹配防御模式",
            "bounds_check": "边界检查",
            "null_check": "空指针检查",
            "sanitization": "输入净化/过滤",
        }.get(guard_source, guard_source)
        return (
            f"## 🔎 {vuln_type.upper()} ({flow_id}) 分析结果\n\n"
            f"### 判定与修复\n"
            f"- **是否真实漏洞**：❌ 否\n"
            f"- **漏洞利用**：无\n"
            f"- **根本原因**：硬回溯在函数 `{callee}` 中发现防御逻辑（{guard_desc}），"
            "污点数据已被检查/过滤，无法到达 sink。\n"
            f"- **修复建议**：无需修复，当前代码已有有效防御。\n"
        )

    def _apply_refutation_to_analysis(
        self,
        analysis_text: str,
        refutation_result: Dict[str, Any],
    ) -> str:
        """用反证结果覆写与主分析矛盾的结构化终态。"""
        verdict = refutation_result.get("verdict", "inconclusive")
        label = str(refutation_result.get("confidence_label", "low")).lower()
        l2 = (refutation_result.get("evidence_levels") or {}).get("L2_static_files", "partial")
        override_reason = None

        if verdict == "likely_false_positive" and label == "low":
            override_reason = "反证：likely_false_positive（低置信）"
        elif verdict == "inconclusive" and l2 in ("absent", "partial"):
            if re.search(r"是否真实漏洞\s*[：:]\s*✅\s*是", analysis_text or ""):
                override_reason = "反证 inconclusive 且 L2 静态证据未补齐"

        if override_reason:
            return self._strip_and_replace_verdict_section(
                analysis_text,
                self._force_safe_verdict_section(override_reason),
            )
        return analysis_text

    def _record_flow_scan_artifacts(
        self,
        *,
        vuln_type: str,
        flow_id: str,
        refutation_result: Dict[str, Any],
        final_verdict_line: str,
    ) -> None:
        """收集 flow 索引与 L2 必读建议，供 Planner 使用。"""
        findings = getattr(self, "_flow_findings_index", None)
        if findings is not None:
            findings.append(
                {
                    "flow_id": flow_id,
                    "vuln_type": vuln_type,
                    "refutation_verdict": refutation_result.get("verdict"),
                    "l2_status": (refutation_result.get("evidence_levels") or {}).get(
                        "L2_static_files"
                    ),
                    "final_verdict": final_verdict_line[:80],
                }
            )
        verdict = str(refutation_result.get("verdict") or "").lower()
        l2 = (refutation_result.get("evidence_levels") or {}).get("L2_static_files", "partial")
        l2_norm = str(l2).lower()
        if verdict not in ("inconclusive", "needs_dynamic_test") and l2_norm not in (
            "absent",
            "partial",
        ):
            return
        pending = getattr(self, "_pending_l2_raw", None)
        if pending is None:
            return
        loc = parse_sink_location(
            (getattr(self, "_current_flow_meta", {}) or {}).get("sink_label", "")
        )
        symbol = ""
        merge_key = build_flow_merge_key(
            vuln_type,
            (getattr(self, "_current_flow_meta", {}) or {}).get("sink_label", ""),
            "",
        )
        if merge_key:
            parts = merge_key.split("|")
            if len(parts) >= 3:
                symbol = parts[2]
        sink_line = None
        if loc.get("line"):
            try:
                sink_line = int(loc["line"])
            except ValueError:
                sink_line = None

        metadata = getattr(self, "_planner_state_metadata", None) or {}
        language = normalize_scan_language(
            metadata.get("language") or os.environ.get("JOERN_SCAN_LANGUAGE", "cpp")
        )
        sink_label = (getattr(self, "_current_flow_meta", {}) or {}).get("sink_label", "")
        missing_paths = collect_refutation_l2_read_suggestions(
            flow_id=flow_id,
            vuln_type=vuln_type,
            refutation_result=refutation_result,
            sink_label=sink_label,
            language=language,
            local_source_path=self.local_source_path,
            metadata=metadata,
        )
        used_fallback = any(
            p not in (refutation_result.get("missing_L2_reads") or []) for p in missing_paths
        )

        for raw in missing_paths:
            pending.append(
                build_pending_l2_entry(
                    path=str(raw),
                    flow_id=flow_id,
                    vuln_type=vuln_type,
                    refutation_verdict=refutation_result.get("verdict"),
                    l2_status=l2,
                    sink_line=sink_line,
                    symbol=symbol or None,
                    source="refutation_gap" if used_fallback else "refutation",
                )
            )

    def _strip_and_replace_verdict_section(self, analysis_text: str, replacement: str) -> str:
        """移除原「判定与修复」并追加系统覆写块。"""
        text = analysis_text or ""
        stripped = re.sub(
            r"###\s*判定与修复[\s\S]*?(?=\n###\s|\Z)",
            "",
            text,
            count=1,
            flags=re.IGNORECASE,
        ).rstrip()
        return f"{stripped}{replacement}"

    def _finalize_flow_analysis(
        self,
        llm_client: LLMClient,
        *,
        vuln_type: str,
        flow_id: str,
        joern_text: str,
        context_text: str,
        language: str,
        preliminary_analysis: str,
    ) -> str:
        """若报告违反终态/PoC 规则则自动重写；仍失败则系统覆写为 ❌ 否。"""
        if os.environ.get("JOERN_ENABLE_VERDICT_RETRY", "1") != "1":
            return preliminary_analysis
        violation = self._analysis_violates_verdict_policy(preliminary_analysis, vuln_type)
        if not violation:
            return preliminary_analysis
        logger.warning(
            "分析报告未通过终态/PoC 校验，触发重写: flow=%s violation=%s",
            flow_id,
            violation,
        )
        self._emit_audit(
            "verdict_policy_retry",
            {
                "flow_id": flow_id,
                "vuln_type": vuln_type,
                "violation": violation,
                "stage_note": (
                    "上一份报告存在「部分是/待确认」或「不提供 exploit」或判✅是无 PoC；"
                    "强制按 VERDICT_AND_POC_POLICY 重写为 ✅是+PoC 或 ❌否。"
                ),
            },
        )
        
        # 【关键修复】重试前主动补读 L2 文件
        l2_hint = ""
        needs_l2 = violation in (
            "confirmed_yes_without_poc",
            "poc_lacks_actionable_steps",
            "claims_exploitability_without_poc",
        )
        if needs_l2:
            l2_read_ok = self._try_read_l2_files_for_retry(vuln_type, flow_id)
            if l2_read_ok:
                l2_hint = "\n\n### 已补充 L2 静态证据（见下方上下文），请结合配置文件内容重新判定。"
        
        retry_instruction = f"""
### 重写指令（上一份不合格，violation={violation}）
你必须重写「判定与修复」：
- 「是否真实漏洞」**只能** `✅ 是` 或 `❌ 否`（禁止部分是/待确认）。
- 若判 `✅ 是`：**必须**在「漏洞利用」给出完整可执行 PoC（入口、恶意输入、步骤、预期结果）。
- 若证据不足以证实可利用：改判 `❌ 否`，利用写「无」，并说明缺什么证据。
- **严禁**「本报告不提供 exploit」。
{l2_hint}
"""
        retried = self._run_flow_analysis_llm(
            llm_client,
            vuln_type=vuln_type,
            flow_id=flow_id,
            joern_text=joern_text,
            context_text=context_text,
            language=language,
            extra_instruction=retry_instruction,
        )
        retry_violation = self._analysis_violates_verdict_policy(retried, vuln_type)
        if not retry_violation:
            return retried
        self._emit_audit(
            "verdict_policy_forced_no",
            {
                "flow_id": flow_id,
                "vuln_type": vuln_type,
                "first_violation": violation,
                "retry_violation": retry_violation,
            },
        )
        return self._strip_and_replace_verdict_section(
            retried,
            self._force_safe_verdict_section(retry_violation or violation),
        )

    def _build_structured_verdict_block(
        self,
        *,
        flow_id: str,
        vuln_type: str,
        hard_backtrace_result: Dict[str, Any],
        refutation_result: Dict[str, Any],
        analysis_text: str = "",
    ) -> str:
        """
        生成报告开头的结构化判定块（对标 Claude Security 的 confidence + stop_reason）。

        其中「证据层级」表来自反证 LLM 的 evidence_levels 字段，含义见 evidence_levels.py：
        - L1_joern：污点流 + 硬回溯 + Joern 扩展（均在分析前写入 context，默认倾向 present）
        - L2_static_files：FileTool/配置类证据；扫描器内通常未自动读取 → 常为 absent/partial
        - L3_dynamic：动态/业务验证；本流水线默认 not_verified
        """
        stop_reason = hard_backtrace_result.get("stop_reason", "unknown")
        refutation_verdict = refutation_result.get("verdict", "inconclusive")
        confidence_label = refutation_result.get("confidence_label", "low")
        confidence_score = refutation_result.get("confidence", 0.0)
        effective_label, effective_score = self._apply_confidence_rules(
            confidence_label=confidence_label,
            confidence_score=confidence_score,
            hard_backtrace_result=hard_backtrace_result,
            refutation_verdict=refutation_verdict,
        )
        blocking = refutation_result.get("blocking_factors") or []
        blocking_lines = "\n".join(f"- {item}" for item in blocking[:8]) if blocking else "- （无）"
        evidence_levels = refutation_result.get("evidence_levels") or {}
        l1 = evidence_levels.get("L1_joern", "present")
        l2 = evidence_levels.get("L2_static_files", "partial")
        l3 = evidence_levels.get("L3_dynamic", "not_verified")
        missing_l2 = refutation_result.get("missing_L2_reads") or []
        missing_l2_lines = (
            "\n".join(f"- {item}" for item in missing_l2[:6]) if missing_l2 else "- （无）"
        )
        try:
            from report_summary import terminal_status_for_flow

            terminal = terminal_status_for_flow(
                flow_id=flow_id,
                refutation_verdict=refutation_verdict,
                l2_status=l2,
                analysis_text=analysis_text,
            )
        except Exception:
            terminal = {
                "terminal": "待定",
                "draft": "—",
                "exploitable": "否",
                "reproducible": "未验证",
                "note": "终态计算失败，请查看 refutation_verdict",
            }
        return (
            f"### 📊 结构化判定 (`{flow_id}`)\n\n"
            f"> **终态口径（系统唯一结论）**：**{terminal['terminal']}** | "
            f"初稿 {terminal['draft']} | 可利用 {terminal['exploitable']} | "
            f"可复现 {terminal['reproducible']} — {terminal['note']}\n\n"
            f"| 字段 | 值 |\n|------|-----|\n"
            f"| flow_id | `{flow_id}` |\n"
            f"| vuln_type | `{vuln_type}` |\n"
            f"| **终态口径** | **{terminal['terminal']}** |\n"
            f"| backtrace_stop_reason | `{stop_reason}` |\n"
            f"| backtrace_hops | `{hard_backtrace_result.get('hops', 0)}` |\n"
            f"| require_source | `{hard_backtrace_result.get('require_source', False)}` |\n"
            f"| source_reached | `{hard_backtrace_result.get('source_reached', False)}` |\n"
            f"| refutation_verdict | `{refutation_verdict}` |\n"
            f"| confidence_label | `{effective_label}` |\n"
            f"| confidence_score | `{effective_score:.2f}` |\n\n"
            f"**证据层级**:\n"
            f"| 层级 | 状态 |\n|------|------|\n"
            f"| L1 代码流（Joern） | `{l1}` |\n"
            f"| L2 静态补证（配置/依赖） | `{l2}` |\n"
            f"| L3 动态/业务 | `{l3}` |\n\n"
            f"**建议补读的 L2 文件**:\n{missing_l2_lines}\n\n"
            f"**反证摘要**: {refutation_result.get('refutation_summary', '待确认')}\n\n"
            f"**阻断/支撑因素**:\n{blocking_lines}\n\n"
            f"**残余风险**: {refutation_result.get('residual_risk', '待确认')}\n"
        )

    def _apply_confidence_rules(
        self,
        *,
        confidence_label: str,
        confidence_score: float,
        hard_backtrace_result: Dict[str, Any],
        refutation_verdict: str,
    ) -> tuple:
        """根据回溯/反证结果对置信度做规则封顶。"""
        label = (confidence_label or "low").lower()
        score = float(confidence_score or 0.0)
        stop_reason = hard_backtrace_result.get("stop_reason", "")
        if hard_backtrace_result.get("require_source") and not hard_backtrace_result.get("source_reached"):
            label = "medium" if label == "high" else label
            score = min(score, 0.65)
        if stop_reason == "source_required_but_not_reached":
            label = "medium" if label == "high" else label
            score = min(score, 0.6)
        if refutation_verdict == "likely_false_positive":
            label = "low"
            score = min(score, 0.35)
        elif refutation_verdict == "needs_dynamic_test":
            label = "medium" if label == "high" else label
            score = min(score, 0.55)
        elif refutation_verdict == "inconclusive":
            score = min(score, 0.5)
        return label, score

    def _run_refutation_check(
        self,
        llm_client: LLMClient,
        *,
        vuln_type: str,
        flow_id: str,
        joern_text: str,
        context_text: str,
        preliminary_analysis: str,
        hard_backtrace_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """第二遍反证 LLM：尝试推翻初步结论，输出结构化 verdict。"""
        if os.environ.get("JOERN_ENABLE_REFUTATION", "1") != "1":
            return {
                "verdict": "inconclusive",
                "confidence": 0.0,
                "confidence_label": "low",
                "refutation_summary": "反证阶段已禁用（JOERN_ENABLE_REFUTATION=0）",
                "blocking_factors": [],
                "residual_risk": "待确认",
                "evidence_levels": {
                    "L1_joern": "present",
                    "L2_static_files": "partial",
                    "L3_dynamic": "not_verified",
                },
                "missing_L2_reads": [],
            }

        merged_context = self._merge_planner_l2_into_context(context_text)
        sink_label = (getattr(self, "_current_flow_meta", {}) or {}).get("sink_label", "")
        available_files = self._get_refutation_available_files(sink_label)
        user_message = prompts.refutation_check_prompt.format(
            vtype_upper=vuln_type.upper(),
            flow_id=flow_id,
            backtrace_stop_reason=hard_backtrace_result.get("stop_reason", "unknown"),
            require_source=hard_backtrace_result.get("require_source", False),
            source_reached=hard_backtrace_result.get("source_reached", False),
            available_files=available_files or "（未提供）",
            joern_text=joern_text[:8000],
            context_text=merged_context[:8000],
            preliminary_analysis=preliminary_analysis[:6000],
        )
        response = llm_client.complete(
            system_prompt=prompts.inject_tool_capabilities(
                "你是独立安全复核员。只输出合法 JSON。",
                TOOL_CAPABILITIES,
            ),
            user_prompt=user_message,
            temperature=0.0,
            max_tokens=600,
        )
        parsed = self._parse_llm_json(response)
        verdict = parsed.get("verdict", "inconclusive")
        if verdict not in (
            "confirmed",
            "likely_false_positive",
            "needs_dynamic_test",
            "inconclusive",
        ):
            verdict = "inconclusive"
        policy_violation = self._analysis_violates_verdict_policy(
            preliminary_analysis, vuln_type
        )
        if policy_violation and verdict == "confirmed":
            verdict = "inconclusive"
            parsed["refutation_summary"] = (
                (parsed.get("refutation_summary") or "")
                + f" [终态/PoC 校验未通过: {policy_violation}]"
            ).strip()
        label = parsed.get("confidence_label", "low")
        if label not in ("high", "medium", "low"):
            label = "low"
        try:
            confidence = float(parsed.get("confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        confidence = max(0.0, min(1.0, confidence))
        evidence_levels = parsed.get("evidence_levels")
        if not isinstance(evidence_levels, dict):
            evidence_levels = {}
        if self._planner_l2_context and evidence_levels.get("L2_static_files") in (
            "absent",
            "partial",
            None,
            "",
        ):
            evidence_levels["L2_static_files"] = "present"
        result = {
            "verdict": verdict,
            "confidence": confidence,
            "confidence_label": label,
            "refutation_summary": parsed.get("refutation_summary", ""),
            "blocking_factors": parsed.get("blocking_factors") or [],
            "residual_risk": parsed.get("residual_risk", ""),
            "evidence_levels": evidence_levels,
            "missing_L2_reads": parsed.get("missing_L2_reads") or [],
        }
        sink_label = (getattr(self, "_current_flow_meta", {}) or {}).get("sink_label", "")
        metadata = getattr(self, "_planner_state_metadata", None) or {}
        language = normalize_scan_language(
            metadata.get("language") or os.environ.get("JOERN_SCAN_LANGUAGE", "cpp")
        )
        enrich_refutation_missing_l2(
            result,
            flow_id=flow_id,
            vuln_type=vuln_type,
            sink_label=sink_label,
            language=language,
            local_source_path=self.local_source_path,
            metadata=metadata,
        )
        return result

    def _run_llm_context_expansion_loop(
        self,
        *,
        vuln_type: str,
        flow_id: str,
        joern_text: str,
        context_text: str,
        language: str,
        max_iters: int,
        skip_expansion: bool = False,
    ) -> Dict[str, Any]:
        """
        LLM 引导的 Joern 上下文扩展循环（与硬回溯互补）。

        供单条 flow 全量分析与 Planner ``expand_flow_context`` 复用。
        """
        previous_query_failure = None
        consecutive_failures = 0
        consecutive_successes = 0
        iteration = 0
        sufficiency_result: Dict[str, Any] = {"sufficient": True}
        executed_expansion_queries: Dict[str, str] = {}
        exhausted = False

        if not skip_expansion:
            self._emit_audit(
                "llm_context_expansion_started",
                {
                    "vuln_type": vuln_type,
                    "flow_id": flow_id,
                    "max_iters": max_iters,
                    "stage_note": ANALYSIS_STAGE_NOTES["llm_context_expansion"],
                    "mechanism": "llm_sufficiency_then_follow_up_or_template",
                },
            )

        while not skip_expansion and iteration < max_iters:
            iteration += 1
            sufficiency_result = self._check_context_sufficiency(
                joern_text, context_text, previous_failure=previous_query_failure,
            )
            follow_up_raw = (sufficiency_result.get("follow_up_query") or "").strip()
            self._emit_audit(
                "sufficiency_check",
                {
                    "vuln_type": vuln_type,
                    "flow_id": flow_id,
                    "iteration": iteration,
                    "sufficient": sufficiency_result.get("sufficient"),
                    "has_follow_up_query": bool(follow_up_raw),
                    "follow_up_query_preview": follow_up_raw[:300] if follow_up_raw else "",
                    "expansion_intent": sufficiency_result.get("expansion_intent"),
                    "expansion_hints": (sufficiency_result.get("expansion_hints") or [])[:5],
                    "stage_note": (
                        "【LLM 扩展阶段·充分性判断】与硬回溯无关：此处决定要不要发「由 LLM 引导」的补充 Joern 查询。"
                    ),
                    "next_query_if_insufficient": (
                        "llm_follow_up_query（模型返回 DSL）"
                        if follow_up_raw
                        else "llm_template_expansion（按 expansion_intent 套模板）"
                    ),
                },
            )
            if sufficiency_result.get("sufficient", True):
                self._emit_audit(
                    "llm_context_expansion_completed",
                    {
                        "vuln_type": vuln_type,
                        "flow_id": flow_id,
                        "reason": "context_sufficient",
                        "iterations_used": iteration,
                    },
                )
                break

            if language.lower() in ["c", "cpp", "c++"]:
                variant_decision = self._determine_variant_from_check(sufficiency_result)
                if variant_decision and variant_decision != self.cpp_variant and not self._variant_switched_during_run:
                    self.cpp_variant = variant_decision
                    self.cpp_queries = queries.get_queries(language="cpp", variant=self.cpp_variant)
                    self._variant_switched_during_run = True

            follow_up_query = follow_up_raw
            query_source = "llm_template_expansion"
            if follow_up_query:
                sanitized_query = self._sanitize_follow_up_query(follow_up_query)
                if sanitized_query:
                    expansion_query = sanitized_query
                    query_source = "llm_follow_up_query"
                else:
                    expansion_query = queries.get_expansion_query(
                        vuln_type,
                        sufficiency_result,
                        current_max_len=int(os.environ.get("JOERN_MAX_PATH_LEN", "10")),
                    )
                    query_source = "llm_template_expansion"
            else:
                expansion_query = queries.get_expansion_query(
                    vuln_type,
                    sufficiency_result,
                    current_max_len=int(os.environ.get("JOERN_MAX_PATH_LEN", "10")),
                )

            expansion_query_key = self._normalize_expansion_query_key(expansion_query)
            skipped_duplicate = expansion_query_key in executed_expansion_queries
            if skipped_duplicate:
                expansion_result = executed_expansion_queries[expansion_query_key]
                self._emit_audit(
                    "expansion_query_skipped_duplicate",
                    {
                        "vuln_type": vuln_type,
                        "flow_id": flow_id,
                        "iteration": iteration,
                        "query_preview": expansion_query.strip()[:300],
                        "query_key": expansion_query_key[:200],
                        "stage_note": (
                            "本 flow 内已成功执行过等价 Joern 查询，跳过重复请求。"
                            "请基于上下文中已有方法体/caller 片段判断，或改用 trace_upstream 等不同 DSL。"
                        ),
                    },
                )
                previous_query_failure = {
                    "failed_query": expansion_query[:500],
                    "error_message": (
                        "【重复查询已跳过】本条 DSL（或与 body.p 等价的 dumpRaw）在本 flow 已成功执行，"
                        "结果应已在「当前代码上下文」中。请勿再次请求相同方法体；"
                        "若仍不充分，请改查 caller（.caller.dumpRaw）或其它方法。"
                    ),
                    "iteration": iteration,
                    "skipped_duplicate": True,
                }
            else:
                expansion_result = self._post_query(
                    expansion_query,
                    timeout=300,
                    ensure_active_project=True,
                )
                expansion_intent = sufficiency_result.get("expansion_intent")
                query_kind = self._classify_joern_query_kind(expansion_query, query_source)
                intent_to_kind = {
                    "trace_upstream": "trace_caller",
                    "view_method_body": "view_body",
                    "find_variable_def": "view_body",
                    "check_sanitization": "view_body",
                    "trace_forward": "view_body",
                }
                expected_kind = intent_to_kind.get(str(expansion_intent or "").strip())
                self._emit_joern_query_audit(
                    query_source=query_source,
                    query_text=expansion_query,
                    result_text=expansion_result,
                    extra={
                        "vuln_type": vuln_type,
                        "flow_id": flow_id,
                        "iteration": iteration,
                        "expansion_intent": expansion_intent,
                        "expansion_intent_matches_query_kind": (
                            query_kind == expected_kind if expected_kind else None
                        ),
                        "used_llm_follow_up": query_source == "llm_follow_up_query",
                    },
                )
                if (
                    "Error:" not in expansion_result
                    and "【查询" not in expansion_result
                    and len(expansion_result) > 50
                ):
                    executed_expansion_queries[expansion_query_key] = expansion_result

            if skipped_duplicate:
                self._emit_audit(
                    "llm_context_expansion_duplicate_exhausted",
                    {
                        "vuln_type": vuln_type,
                        "flow_id": flow_id,
                        "iteration": iteration,
                        "stage_note": (
                            "等价 Joern 扩展查询已执行过，停止继续扩展，"
                            "基于已有上下文进入主分析/反证。"
                        ),
                    },
                )
                sufficiency_result = dict(sufficiency_result)
                sufficiency_result["sufficient"] = True
                break

            if "Error:" not in expansion_result and len(expansion_result) > 50:
                old_len = len(context_text)
                context_text = self._merge_context(
                    context_text, self._extract_code_context(expansion_result),
                )
                previous_query_failure = None
                consecutive_failures = 0
                if len(context_text) - old_len > 100:
                    consecutive_successes += 1
                else:
                    consecutive_successes = 0
                if (
                    consecutive_successes >= 2
                    and sufficiency_result.get("sufficient", True)
                ):
                    break
            else:
                consecutive_failures += 1
                previous_query_failure = {
                    "failed_query": expansion_query[:500],
                    "error_message": (expansion_result or "")[:500],
                    "iteration": iteration,
                }
                if consecutive_failures >= 2:
                    exhausted = True
                    break

        if iteration >= max_iters and not sufficiency_result.get("sufficient", True):
            exhausted = True
            self._emit_audit(
                "llm_context_expansion_completed",
                {
                    "vuln_type": vuln_type,
                    "flow_id": flow_id,
                    "reason": "max_iters_reached_still_insufficient",
                    "iterations_used": iteration,
                },
            )

        return {
            "context_text": context_text,
            "iteration": iteration,
            "sufficiency_result": sufficiency_result,
            "exhausted": exhausted,
            "skip_expansion": skip_expansion,
        }

    def expand_flow_context(
        self,
        *,
        vuln_type: str,
        flow_id: str,
        flow_text: str,
        sink_label: str,
        language: str = "cpp",
        max_extra_iters: Optional[int] = None,
        prior_context: Optional[str] = None,
        method_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Planner 专用：对指定 flow 再跑 1～2 轮 Joern LLM 扩展，不触发主分析/反证 LLM。

        在 L2 仍 inconclusive 时，应先调用本方法；用尽或失败后 Planner 才允许
        FileTool 读取源文件（.c/.java 等）定点行段。

        Args:
            vuln_type: 漏洞类型（如 CWE-639）。
            flow_id: flow 标识符。
            flow_text: Joern 原始输出（污点分析场景），或类 Joern 格式上下文（逻辑扫描场景）。
            sink_label: sink 标签。
            language: 目标语言。
            max_extra_iters: 最大扩展轮数。
            prior_context: 可选的已有上下文（跳过 _extract_code_context）。
            method_name: 可选的方法全名（逻辑扫描场景），用于直接引导 follow_up 查询。
        """
        if not self.ensure_cpg_loaded():
            return {
                "ok": False,
                "flow_id": flow_id,
                "error": "cpg_not_loaded",
                "summary": "CPG 未就绪，无法执行 Joern 扩展",
            }

        max_iters = max_extra_iters
        if max_iters is None:
            max_iters = int(os.environ.get("PLANNER_FLOW_EXPAND_MAX_ITERS", "2"))
        max_iters = max(1, min(int(max_iters), 4))

        joern_text = flow_text or ""

        # 统一处理：如果有 method_name，将其注入为引导信息
        if method_name and not joern_text:
            joern_text = f"# Bootstrap for method: {method_name}\n# flow_id: {flow_id}\n# vuln_type: {vuln_type}"

        context_text = prior_context or self._extract_code_context(joern_text)
        l1_before = len(self._l1_ranges_collected)
        self._record_sink_l1_window(sink_label)

        self._emit_audit(
            "planner_expand_flow_context_started",
            {
                "flow_id": flow_id,
                "vuln_type": vuln_type,
                "max_iters": max_iters,
                "prior_context_chars": len(context_text or ""),
            },
        )

        expansion_out = self._run_llm_context_expansion_loop(
            vuln_type=vuln_type,
            flow_id=flow_id,
            joern_text=joern_text,
            context_text=context_text,
            language=language,
            max_iters=max_iters,
            skip_expansion=False,
        )
        context_text = expansion_out["context_text"]
        iteration = expansion_out["iteration"]
        sufficiency_result = expansion_out["sufficiency_result"]
        sufficient = bool(sufficiency_result.get("sufficient", False))
        exhausted = bool(expansion_out.get("exhausted")) or (
            iteration >= max_iters and not sufficient
        )
        new_l1 = list(self._l1_ranges_collected[l1_before:])

        summary = (
            f"flow {flow_id}: Joern 扩展 {iteration}/{max_iters} 轮；"
            f"{'上下文已充分' if sufficient else '仍不充分'}"
            f"{'，扩展已用尽' if exhausted and not sufficient else ''}"
        )
        self._emit_audit(
            "planner_expand_flow_context_completed",
            {
                "flow_id": flow_id,
                "iterations_used": iteration,
                "max_iters": max_iters,
                "sufficient": sufficient,
                "exhausted": exhausted,
                "new_l1_ranges": len(new_l1),
            },
        )
        return {
            "ok": True,
            "flow_id": flow_id,
            "vuln_type": vuln_type,
            "iterations_used": iteration,
            "max_iters": max_iters,
            "sufficient": sufficient,
            "exhausted": exhausted,
            "context_preview": (context_text or "")[:2500],
            "l1_covered_ranges": new_l1,
            "summary": summary,
        }

    def _analyze_single_taint_flow(
        self,
        llm_client: LLMClient,
        *,
        vuln_type: str,
        flow_id: str,
        flow_text: str,
        sink_label: str,
        language: str,
        max_iters: int,
        review_mode: bool = False,
        previous_conclusions: Optional[str] = None,
        previous_verdict: Optional[str] = None,
    ) -> str:
        """
        对单条污点 flow 执行完整分析。

        流水线（三者不要混为一谈）：
        1. 从 Joern flow 文本提取代码片段（无新 Joern 查询）
        2. **硬回溯**：代码固定 caller 链查询 → 审计 source=hard_backtrace_*
        3. **LLM 上下文扩展**：sufficiency_check → 可能执行 follow_up / 模板查询
           → 审计 source=llm_follow_up_query | llm_template_expansion
        4. 主分析 LLM + 反证 LLM

        Args:
            review_mode: 是否启用复核模式。启用时使用专门的 prompt 告诉 LLM
                         「上次你说这条是模糊的，请给出明确结论」。
            previous_conclusions: 上次扫描的结论摘要。
            previous_verdict: 上次对这条 flow 的结论（如 "⚠️ 部分是"）。
        """
        joern_text = flow_text
        self._record_sink_l1_window(sink_label)

        merge_key = build_flow_merge_key(vuln_type, sink_label, flow_text)
        if merge_key and not review_mode:
            session_hit = self._flow_merge_session.get(merge_key)
            if session_hit:
                self._emit_audit(
                    "flow_merge_session_hit",
                    {
                        "flow_id": flow_id,
                        "merge_key": merge_key,
                        "canonical_flow_id": session_hit.get("canonical_flow_id"),
                    },
                )
                return self._render_merged_flow_from_cache(
                    vuln_type=vuln_type,
                    flow_id=flow_id,
                    sink_label=sink_label,
                    cached=session_hit,
                )
            persist_hit = self._flow_merge_verdict_cache.get(merge_key)
            if persist_hit:
                self._flow_merge_session[merge_key] = persist_hit
                self._emit_audit(
                    "flow_merge_cache_hit",
                    {
                        "flow_id": flow_id,
                        "merge_key": merge_key,
                        "canonical_flow_id": persist_hit.get("canonical_flow_id"),
                    },
                )
                return self._render_merged_flow_from_cache(
                    vuln_type=vuln_type,
                    flow_id=flow_id,
                    sink_label=sink_label,
                    cached=persist_hit,
                )

        # 检查 flow 级结论缓存（跨运行复用）
        verdict_key = self._flow_verdict_key(vuln_type, sink_label)
        cached_verdict = self._flow_verdict_cache.get(verdict_key)
        if cached_verdict and cached_verdict.get("verdict") == "guard_found":
            logger.info(
                "Flow 缓存命中 (guard_found): %s %s",
                flow_id, verdict_key,
            )
            self._emit_audit(
                "flow_verdict_cache_hit",
                {
                    "vuln_type": vuln_type,
                    "flow_id": flow_id,
                    "cache_key": verdict_key,
                    "verdict": "guard_found",
                    "guard_edges": cached_verdict.get("guard_edges", []),
                    "cached_at": cached_verdict.get("cached_at", "unknown"),
                },
            )
            # 重建 guard_edge_cache 供后续 flow 使用
            for edge in cached_verdict.get("guard_edges", []):
                edge_key = edge.get("edge_key")
                if edge_key:
                    self._guarded_call_edge_cache.add(edge_key)
            return cached_verdict.get("analysis", cached_verdict.get("analysis_preview", ""))

        pruned = self._try_prune_by_guard_cache(
            vuln_type=vuln_type,
            flow_id=flow_id,
            sink_label=sink_label,
            joern_text=joern_text,
        )
        if pruned:
            return pruned

        context_text = self._extract_code_context(joern_text)

        # 记录中间过程数据，供复核报告使用
        self._current_flow_meta: Dict[str, Any] = {
            "vuln_type": vuln_type,
            "flow_id": flow_id,
            "sink_label": sink_label,
        }
        self._emit_audit(
            "flow_analysis_started",
            {
                "vuln_type": vuln_type,
                "flow_id": flow_id,
                "sink_label": sink_label,
                "joern_text_length": len(joern_text),
                "pipeline_order": [
                    "extract_context_from_flow",
                    "hard_backtrace (code-fixed Joern)",
                    "llm_context_expansion (optional, max_iters)",
                    "primary_llm_analysis",
                    "refutation_llm",
                ],
                "stage_note": (
                    "初始 flow 来自 queries_py_initial 全项目扫描；"
                    "本条 flow 的补查将区分硬回溯与 LLM 扩展，见 joern_query_executed.query_source。"
                ),
            },
        )

        hard_backtrace_result = self._run_hard_backtrace(
            vuln_type=vuln_type,
            joern_text=joern_text,
            context_text=context_text,
        )
        context_text = hard_backtrace_result.get("context_text", context_text)
        # 记录硬回溯中间数据
        self._current_flow_meta["backtrace"] = {
            "hops": hard_backtrace_result.get("hops", 0),
            "visited_methods": hard_backtrace_result.get("visited_methods", 0),
            "stop_reason": hard_backtrace_result.get("stop_reason", "unknown"),
            "source_reached": hard_backtrace_result.get("source_reached", False),
        }
        if hard_backtrace_result.get("require_source") and not hard_backtrace_result.get("source_reached"):
            context_text = self._merge_context(
                context_text,
                "⚠️ 硬回溯提示：该漏洞类型默认要求追溯到输入源，但当前尚未命中输入源证据。",
            )

        # CVE 知识库参考注入（当前已禁用，DB 就绪后在 _get_cve_knowledge_reference 中启用）
        # cve_reference = self._get_cve_knowledge_reference(vuln_type)
        # if cve_reference:
        #     context_text = self._merge_context(context_text, cve_reference)

        self._emit_audit(
            "hard_backtrace_completed",
            {
                "vuln_type": vuln_type,
                "flow_id": flow_id,
                "stop_reason": hard_backtrace_result.get("stop_reason"),
                "hops": hard_backtrace_result.get("hops", 0),
                "source_reached": hard_backtrace_result.get("source_reached", False),
                "stage_note": ANALYSIS_STAGE_NOTES["hard_backtrace"],
                "next_stage": (
                    "若上下文仍不足，将进入 LLM 扩展阶段（llm_follow_up_query / llm_template_expansion），"
                    "不再使用硬回溯的固定 caller BFS。"
                ),
            },
        )

        skip_expansion = hard_backtrace_result.get("stop_reason") == "guard_logic_found"
        if skip_expansion:
            self._emit_audit(
                "llm_context_expansion_skipped",
                {
                    "vuln_type": vuln_type,
                    "flow_id": flow_id,
                    "reason": "backtrace_guard_found",
                    "stage_note": "硬回溯已找到防御逻辑，跳过 LLM 上下文扩展以节省时间。",
                },
            )
            logger.info(
                "跳过上下文扩展: %s 硬回溯已找到防御逻辑",
                flow_id,
            )

        expansion_out = self._run_llm_context_expansion_loop(
            vuln_type=vuln_type,
            flow_id=flow_id,
            joern_text=joern_text,
            context_text=context_text,
            language=language,
            max_iters=max_iters,
            skip_expansion=skip_expansion,
        )
        context_text = expansion_out["context_text"]
        iteration = expansion_out["iteration"]
        sufficiency_result = expansion_out["sufficiency_result"]

        # 记录上下文扩展中间数据
        self._current_flow_meta["context_expansion"] = {
            "iterations_used": iteration,
            "max_iters": max_iters,
            "context_sufficient": sufficiency_result.get("sufficient", True),
            "context_text_length": len(context_text),
        }

        flow_header = (
            f"## 🔎 {vuln_type.upper()} — `{flow_id}`\n"
            f"> **Sink 线索**: {sink_label or '未知'}\n\n"
        )

        if iteration >= max_iters and not sufficiency_result.get("sufficient", True):
            insufficient_analysis = self._build_insufficient_context_analysis(
                vuln_type=vuln_type,
                flow_id=flow_id,
                max_iters=max_iters,
                sufficiency_result=sufficiency_result,
            )
            self._current_flow_meta["analysis"] = insufficient_analysis
            self._current_flow_meta["context_expansion"]["stopped_reason"] = (
                "max_iters_still_insufficient"
            )
            return f"\n---\n{flow_header}\n{insufficient_analysis.strip()}\n"

        # 复核模式：构造专门的指令告诉 LLM 上次结论模糊，请给出明确判断
        extra_instruction = ""
        if review_mode and previous_verdict:
            extra_instruction = prompts.build_review_instruction(
                vuln_type=vuln_type,
                flow_id=flow_id,
                previous_verdict=previous_verdict,
                previous_conclusions=previous_conclusions,
            )

        # 优化：硬回溯已找到防御逻辑时，跳过主分析+终态确认，只跑反证
        # 硬回溯结论明确（guard_logic_found），无需 LLM 重复判断
        if skip_expansion:
            guarded_edges = hard_backtrace_result.get("guarded_edges") or []
            guard_info = guarded_edges[0] if guarded_edges else {}
            callee = guard_info.get("callee_short", "未知函数")
            preliminary_analysis = self._build_guard_found_analysis(
                vuln_type=vuln_type,
                flow_id=flow_id,
                callee=callee,
                guard_source=guard_info.get("guard_source", "regex"),
            )
            self._emit_audit(
                "analysis_skipped_guard_found",
                {
                    "flow_id": flow_id,
                    "vuln_type": vuln_type,
                    "reason": "hard_backtrace_guard_logic_found",
                    "callee": callee,
                    "stage_note": "硬回溯已找到防御逻辑，跳过主分析+终态确认，只跑反证检查。",
                },
            )
            # 保存 guard_found 结论到 flow 级缓存（跨运行复用）
            verdict_key = self._flow_verdict_key(vuln_type, sink_label)
            self._flow_verdict_cache[verdict_key] = {
                "verdict": "guard_found",
                "guard_edges": guarded_edges,
                "guard_source": guard_info.get("guard_source", "regex"),
                "analysis": preliminary_analysis,
                "flow_id": flow_id,
                "cached_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            }
            self._save_flow_verdict_cache(self._flow_verdict_cache)
        else:
            preliminary_analysis = self._run_flow_analysis_llm(
                llm_client,
                vuln_type=vuln_type,
                flow_id=flow_id,
                joern_text=joern_text,
                context_text=context_text,
                language=language,
                extra_instruction=extra_instruction,
            )
            preliminary_analysis = self._finalize_flow_analysis(
                llm_client,
                vuln_type=vuln_type,
                flow_id=flow_id,
                joern_text=joern_text,
                context_text=context_text,
                language=language,
                preliminary_analysis=preliminary_analysis,
            )
        refutation_result = self._run_refutation_check(
            llm_client,
            vuln_type=vuln_type,
            flow_id=flow_id,
            joern_text=joern_text,
            context_text=context_text,
            preliminary_analysis=preliminary_analysis,
            hard_backtrace_result=hard_backtrace_result,
        )
        preliminary_analysis = self._apply_refutation_to_analysis(
            preliminary_analysis, refutation_result
        )
        self._emit_audit(
            "refutation_completed",
            {
                "flow_id": flow_id,
                "verdict": refutation_result.get("verdict"),
                "confidence_label": refutation_result.get("confidence_label"),
            },
        )
        verdict_block = self._build_structured_verdict_block(
            flow_id=flow_id,
            vuln_type=vuln_type,
            hard_backtrace_result=hard_backtrace_result,
            refutation_result=refutation_result,
            analysis_text=preliminary_analysis,
        )
        final_verdict_line = self._extract_verdict_text(preliminary_analysis)
        self._record_flow_scan_artifacts(
            vuln_type=vuln_type,
            flow_id=flow_id,
            refutation_result=refutation_result,
            final_verdict_line=final_verdict_line,
        )
        # 记录分析结论和反证结果
        self._current_flow_meta["analysis"] = preliminary_analysis.strip()
        self._current_flow_meta["refutation"] = {
            "verdict": refutation_result.get("verdict", ""),
            "confidence_label": refutation_result.get("confidence_label", ""),
        }
        self._current_flow_meta["verdict_block"] = verdict_block
        if merge_key:
            self._save_flow_merge_cache(
                merge_key=merge_key,
                vuln_type=vuln_type,
                flow_id=flow_id,
                sink_label=sink_label,
                analysis=preliminary_analysis.strip(),
                verdict_block=verdict_block,
                final_verdict_line=final_verdict_line,
                refutation_result=refutation_result,
            )
        return f"\n---\n{flow_header}{verdict_block}\n\n{preliminary_analysis.strip()}\n"

    def _analyze_reflection_flow(
        self,
        llm_client: LLMClient,
        vuln_type: str,
        joern_text: str,
        context_text: str,
    ) -> str:
        """对 Java 反射保守查询结果做专用 LLM 分析（不跑污点迭代/硬回溯）。"""
        final_prompt = prompts.reflection_analysis_user_prompt_template.format(
            vtype_upper=vuln_type.upper(),
            text=joern_text[:15000],
            ctx=context_text[:15000],
        )
        return llm_client.complete(
            system_prompt=prompts.inject_tool_capabilities(
                prompts.system_prompt,
                TOOL_CAPABILITIES,
            ),
            user_prompt=final_prompt,
            temperature=0.0,
            max_tokens=2800,
        )

    def _build_cpp_auxiliary_appendix(self, aux_flows: Dict[str, str]) -> str:
        """将 C++ 间接调用辅助查询结果追加到报告末尾（不进入主污点迭代）。"""
        lines = [
            "\n---\n",
            "## 附录：C/C++ 间接调用辅助扫描（可选 pass）\n",
            "> 说明：本节仅列出动态分发/间接敏感 sink 站点，**不**替代主污点查询结论；",
            "> 主流程 `reachableByFlows` 与 hard backtrace 行为未改。启用：`JOERN_CPP_INDIRECT_AUX=1`\n",
        ]
        for query_name, query_result in aux_flows.items():
            preview = (query_result or "").strip()
            if len(preview) > 8000:
                preview = preview[:8000] + "\n...(truncated)"
            lines.append(f"\n### {query_name}\n")
            lines.append(f"```\n{preview}\n```\n")
        return "".join(lines)

    def _format_scan_coverage_section(
        self,
        *,
        valid_flows: Dict[str, str],
        failed_sent: List[str],
        circuit_skipped: List[str],
        not_run_abort: List[str],
        empty_or_short: List[str],
    ) -> str:
        """生成报告中的扫描覆盖说明（区分：已发送失败 / 熔断未发送 / 无命中）。"""
        meta = self._last_query_batch_meta or {}
        if not (
            failed_sent
            or circuit_skipped
            or not_run_abort
            or empty_or_short
            or self._joern_circuit_open
            or meta.get("circuit_opened_during_batch")
        ):
            return ""

        lines = ["### ⚠️ 扫描覆盖说明", ""]
        planned = meta.get("total_planned")
        if planned:
            ok_n = meta.get("executed_count", len(valid_flows))
            skipped_ckpt = meta.get("skipped_checkpoint", 0)
            lines.append(
                f"- **批次进度**: 计划 {planned} 类污点查询，"
                f"有效结果 {ok_n} 类，"
                f"检查点跳过 {skipped_ckpt} 类，"
                f"已向 Joern 发送但失败 {len(failed_sent)} 类，"
                f"熔断后未发送 {len(not_run_abort)} 类"
            )
        resumed = meta.get("resumed_from_checkpoint") or []
        if resumed:
            lines.append(
                f"- **检查点续扫**: 已复用 {len(resumed)} 类历史结果（删除检查点文件或设 JOERN_CPP_CHECKPOINT_RESET=1 可全量重扫）"
            )
        if failed_sent:
            lines.append(
                f"- **已查询但失败（超时/连接/HTTP）**: {', '.join(failed_sent)}"
            )
        if not_run_abort:
            lines.append(
                f"- **熔断中止、未向 Joern 发送**: {', '.join(not_run_abort)}"
            )
        if circuit_skipped:
            lines.append(
                f"- **熔断器已开、请求未发出**: {', '.join(circuit_skipped)}"
            )
        if empty_or_short:
            lines.append(
                f"- **已查询但无有效 flow（空或过短）**: {', '.join(empty_or_short)}"
            )
        if self._joern_circuit_open:
            lines.append(
                "- **熔断器**: 已打开（连续 Joern 请求失败达阈值）。"
                "请 `docker restart` Joern 后**重新跑完整扫描**；"
                "仅 `reset_circuit_breaker()` 不会补跑未发送的查询类型。"
            )
        lines.append("")
        return "\n".join(lines)

    def iterative_analyze(
        self,
        flows: Dict[str, str],
        language: str,
        max_iters: int = 3,
        return_ambiguous: bool = False,
    ) -> Any:
        """
        对初始污点查询结果执行"迭代补上下文 + 最终分析"。
    
        Args:
            flows: 初始污点查询结果。
            language: 目标语言。
            max_iters: 最大补上下文轮数。
            return_ambiguous: 若为 True，返回 (report, ambiguous_list) 元组；
                              若为 False（默认），仅返回 report 字符串。
    
        Returns:
            str 或 (str, list)：报告文本，以及可选的模糊 flow 列表。
        """
        # 先做第一层筛选：明显报错/极短文本的 flow 不进入 LLM 分析，减少噪声与成本。
        failed_sent: List[str] = []
        circuit_skipped: List[str] = []
        not_run_abort: List[str] = []
        empty_or_short: List[str] = []
        valid_flows: Dict[str, str] = {}
        for name, text in flows.items():
            raw = text or ""
            if "【查询未执行·熔断中止】" in raw:
                not_run_abort.append(name)
                continue
            if "【查询跳过】" in raw:
                circuit_skipped.append(name)
                continue
            if self._is_joern_transport_failure(raw):
                failed_sent.append(name)
                continue
            if self._is_valid_flow_text(name, text):
                valid_flows[name] = text
            else:
                empty_or_short.append(name)

        coverage_block = self._format_scan_coverage_section(
            valid_flows=valid_flows,
            failed_sent=failed_sent,
            circuit_skipped=circuit_skipped,
            not_run_abort=not_run_abort,
            empty_or_short=empty_or_short,
        )

        if not valid_flows:
            lines = ["⚠️ Joern 未返回可分析的污点路径（不等于项目无漏洞）。"]
            if coverage_block:
                lines.append(coverage_block)
            report = "\n".join(lines)
            return (report, []) if return_ambiguous else report

        llm_client = self._get_llm()
        full_report = (
            f"# 🔍 Joern + LLM 智能迭代分析报告\n"
            f"> 时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"> 项目: {self.project_name}\n"
            f"{REPORT_EVIDENCE_LEVEL_LEGEND}\n"
        )
        if coverage_block:
            full_report += f"\n{coverage_block}\n"

        # 追踪模糊结论的 flow
        ambiguous_list: List[Dict[str, Any]] = []
        self._pending_l2_raw: List[Dict[str, Any]] = []
        self._flow_findings_index: List[Dict[str, Any]] = []
        self._flow_merge_session = {}
        self._l1_ranges_collected = []
        self._flow_catalog: Dict[str, Dict[str, Any]] = {}
        # 追踪被系统从 ✅ 覆写为 ❌ 的 flow（供下次带 L2 上下文时重新分析）
        self._overridden_yes_flows: List[Dict[str, Any]] = []

        for vuln_type, joern_text in valid_flows.items():
            logger.info("开始迭代分析: %s", vuln_type)
            self._emit_audit(
                "iterative_analysis_started",
                {"vuln_type": vuln_type, "joern_text_length": len(joern_text)},
            )

            if self._is_reflection_query_type(vuln_type):
                logger.info("反射保守分析: %s（跳过污点迭代与 hard backtrace）", vuln_type)
                context_text = self._extract_code_context(joern_text)
                analysis_text = self._analyze_reflection_flow(
                    llm_client,
                    vuln_type,
                    joern_text,
                    context_text,
                )
                full_report += f"\n---\n{analysis_text.strip()}\n"
                continue

            flow_chunks = self._split_joern_into_flow_chunks(joern_text, vuln_type)
            if not flow_chunks:
                flow_chunks = [
                    {
                        "flow_id": f"{vuln_type}-flow-1",
                        "raw_text": joern_text,
                        "sink_label": self._extract_flow_sink_label(joern_text),
                    }
                ]

            analyzable_chunks, skipped_chunks = self._partition_flows_by_quality(
                flow_chunks, vuln_type=vuln_type
            )
            full_report += (
                f"\n---\n## 漏洞类型: {vuln_type.upper()}（共 {len(flow_chunks)} 条 flow，"
                f"分析 {len(analyzable_chunks)}，跳过 {len(skipped_chunks)}）\n"
            )
            full_report += self._format_skipped_flows_report(skipped_chunks)
            for flow_record in analyzable_chunks:
                flow_id = flow_record["flow_id"]
                self._flow_catalog[flow_id] = {
                    "vuln_type": vuln_type,
                    "flow_id": flow_id,
                    "sink_label": flow_record.get("sink_label", ""),
                    "flow_text": flow_record["raw_text"],
                }
                logger.info(
                    "分析单条 flow: %s sink=%s",
                    flow_id,
                    flow_record.get("sink_label", ""),
                )
                analysis_result = self._analyze_single_taint_flow(
                    llm_client,
                    vuln_type=vuln_type,
                    flow_id=flow_id,
                    flow_text=flow_record["raw_text"],
                    sink_label=flow_record.get("sink_label", ""),
                    language=language,
                    max_iters=max_iters,
                )
                full_report += analysis_result

                # 检查是否为模糊结论，如果是则记录以供下次增量扫描
                if self._is_ambiguous_verdict(analysis_result):
                    ambiguous_entry = {
                        "vuln_type": vuln_type,
                        "flow_id": flow_id,
                        "sink_label": flow_record.get("sink_label", ""),
                        "flow_text": flow_record["raw_text"],
                        "previous_verdict": self._extract_verdict_text(analysis_result),
                    }
                    # 合并中间过程数据（硬回溯、上下文扩展、分析结论等）
                    flow_meta = getattr(self, "_current_flow_meta", None)
                    if flow_meta:
                        ambiguous_entry["meta"] = flow_meta
                    ambiguous_list.append(ambiguous_entry)

                self._append_inconclusive_refutation_ambiguous(
                    ambiguous_list,
                    vuln_type=vuln_type,
                    flow_id=flow_id,
                    flow_record=flow_record,
                    analysis_result=analysis_result,
                )

                # 检查是否被系统从 ✅ 覆写为 ❌（需要 L2 证据重新验证）
                if self._was_overridden_yes_to_no(analysis_result):
                    overridden_entry = {
                        "vuln_type": vuln_type,
                        "flow_id": flow_id,
                        "sink_label": flow_record.get("sink_label", ""),
                        "flow_text": flow_record["raw_text"],
                        "previous_verdict": self._extract_verdict_text(analysis_result),
                        "override_reason": "LLM 原始判定为 ✅ 是，但因缺少 L2/PoC 证据被系统覆写为 ❌ 否",
                    }
                    flow_meta = getattr(self, "_current_flow_meta", None)
                    if flow_meta:
                        overridden_entry["meta"] = flow_meta
                    self._overridden_yes_flows.append(overridden_entry)
                    # 也纳入 ambiguous_list，供下次带 L2 上下文重新分析
                    ambiguous_list.append(overridden_entry)

        self._last_scan_artifacts = {
            "pending_l2_reads_raw": list(self._pending_l2_raw),
            "flow_findings_index": list(self._flow_findings_index),
            "l1_covered_ranges": list(self._l1_ranges_collected),
            "flow_catalog": dict(getattr(self, "_flow_catalog", {}) or {}),
            "evidence_unreachable_flow_ids": list(getattr(self, "_evidence_unreachable_flow_ids", [])),
        }
        # 记录被覆写的 flow 数量
        if self._overridden_yes_flows:
            logger.info(
                "检测到 %s 条 flow 被系统从 ✅ 是 覆写为 ❌ 否，已纳入 ambiguous_list 供下次带 L2 重新分析",
                len(self._overridden_yes_flows),
            )
        try:
            from report_summary import inject_executive_summary

            full_report = inject_executive_summary(
                full_report,
                flow_findings_index=list(self._flow_findings_index),
            )
        except Exception as exc:
            logger.warning("注入报告终态一览失败: %s", exc)
        if return_ambiguous:
            return full_report, ambiguous_list
        return full_report

    def run_full_scan(
        self,
        language: str,
        max_iters: int = 3,
        *,
        focus_flows: Optional[List[Dict[str, Any]]] = None,
        review_mode: bool = False,
        previous_conclusions: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        执行完整扫描入口。

        Args:
            language: 当前扫描语言。
            max_iters: LLM 最大补上下文轮数。
            focus_flows: 可选的增量扫描参数。如果提供，只对这些 flow 重新分析，
                         跳过 run_taint_queries 阶段。每个元素包含:
                         {vuln_type, flow_id, sink_label, flow_text, previous_verdict}
            review_mode: 是否启用复核模式。启用时 LLM 分析会使用不同的 prompt，
                         强调「上次结论模糊，请给出明确判断」。
            previous_conclusions: 上次扫描的结论摘要，传给复核 LLM 作为参考。

        Returns:
            统一结果字典，包含：
            - `ok`: 是否成功
            - `flows`: 原始污点查询结果
            - `report`: 最终分析报告
            - `ambiguous_flows`: 本次扫描中结论模糊的 flow 列表（供下次增量扫描）
        """
        if not (focus_flows and review_mode):
            self._guarded_call_edge_cache = set()
            self._joern_method_fullnames_cache = {}
            self._joern_method_callers_cache = {}
            # 重置 Scanner 自行读取的 L2 上下文（每次全量扫描重新读取）
            self._scanner_l2_context = ""
            self._scanner_l2_files_read = []

        if focus_flows and review_mode:
            logger.info("=== 增量复核扫描开始（%s 条模糊 flow）===" , len(focus_flows))
            # 增量模式：跳过 run_taint_queries，只分析指定的模糊 flow
            ambiguous_list = self._analyze_focus_flows(
                focus_flows=focus_flows,
                language=language,
                max_iters=max_iters,
                previous_conclusions=previous_conclusions,
            )
            report = self._build_review_report(ambiguous_list)
            artifacts = getattr(self, "_last_scan_artifacts", {}) or {}
            return {
                "ok": True,
                "flows": {f["flow_id"]: f.get("flow_text", "") for f in focus_flows},
                "report": report,
                "ambiguous_flows": ambiguous_list,
                "pending_l2_reads_raw": artifacts.get("pending_l2_reads_raw", []),
                "flow_findings_index": artifacts.get("flow_findings_index", []),
                "l1_covered_ranges": artifacts.get("l1_covered_ranges", []),
                "flow_catalog": artifacts.get("flow_catalog", {}),
                "evidence_unreachable_flow_ids": artifacts.get("evidence_unreachable_flow_ids", []),
            }

        logger.info("=== 智能迭代扫描开始 ===")
        if not self.ensure_cpg_loaded():
            return {"ok": False, "flows": {}, "report": "", "ambiguous_flows": []}

        flows = self.run_taint_queries(language=language)

        if language.lower() == "java":
            reflection_flows = self.run_java_reflection_queries()
            flows.update(reflection_flows)

        report, ambiguous_list = self.iterative_analyze(
            flows, language=language, max_iters=max_iters,
            return_ambiguous=True,
        )

        if language.lower() in ["c", "cpp", "c++"] and os.environ.get("JOERN_CPP_INDIRECT_AUX", "0") == "1":
            aux_flows = self.run_cpp_auxiliary_queries()
            flows.update(aux_flows)
            report += self._build_cpp_auxiliary_appendix(aux_flows)

        artifacts = getattr(self, "_last_scan_artifacts", {}) or {}
        return {
            "ok": True,
            "flows": flows,
            "report": report,
            "ambiguous_flows": ambiguous_list,
            "pending_l2_reads_raw": artifacts.get("pending_l2_reads_raw", []),
            "flow_findings_index": artifacts.get("flow_findings_index", []),
            "l1_covered_ranges": artifacts.get("l1_covered_ranges", []),
            "flow_catalog": artifacts.get("flow_catalog", {}),
            "evidence_unreachable_flow_ids": artifacts.get("evidence_unreachable_flow_ids", []),
        }

    def _analyze_focus_flows(
        self,
        focus_flows: List[Dict[str, Any]],
        language: str,
        max_iters: int,
        previous_conclusions: Optional[str],
    ) -> List[Dict[str, Any]]:
        """
        增量分析指定的模糊 flow，返回仍有歧义的 flow 列表。
        """
        llm_client = self.llm
        if llm_client is None:
            from llm_client import LLMClient
            llm_client = LLMClient()
            self.llm = llm_client

        results: List[Dict[str, Any]] = []
        new_ambiguous: List[Dict[str, Any]] = []
        self._pending_l2_raw = []
        self._flow_findings_index = []
        self._flow_catalog = {}
        self._evidence_unreachable_flow_ids: List[str] = []

        for flow_info in focus_flows:
            vuln_type = flow_info.get("vuln_type", "unknown")
            flow_id = flow_info.get("flow_id", "")
            flow_text = flow_info.get("flow_text", "")
            sink_label = flow_info.get("sink_label", "")
            previous_verdict = flow_info.get("previous_verdict", "")
            self._flow_catalog[flow_id] = {
                "vuln_type": vuln_type,
                "flow_id": flow_id,
                "sink_label": sink_label,
                "flow_text": flow_text,
            }

            flow_record = {
                "flow_id": flow_id,
                "raw_text": flow_text,
                "sink_label": sink_label,
            }
            skip_reason = self._flow_quality_skip_reason(flow_record)
            if skip_reason:
                logger.info(
                    "增量复核跳过低质量 flow: %s reason=%s", flow_id, skip_reason
                )
                self._emit_audit(
                    "flow_quality_skipped",
                    {
                        "vuln_type": vuln_type,
                        "flow_id": flow_id,
                        "sink_label": sink_label,
                        "skip_reason": skip_reason,
                        "filter_mode": self._flow_quality_filter_mode(),
                        "review_mode": True,
                    },
                )
                continue

            logger.info("增量复核 flow: %s type=%s", flow_id, vuln_type)

            # 检查 verdict 缓存：若已有 inconclusive/needs_dynamic_test 且无新 L2，跳过重复分析
            cached_inconclusive = False
            _cv = {}
            for _ck, _cv in self._flow_verdict_cache.items():
                if str(_cv.get("flow_id")) == flow_id and _cv.get("verdict") in (
                    "inconclusive", "needs_dynamic_test",
                ):
                    cached_inconclusive = True
                    break
            if cached_inconclusive:
                new_l2_for_flow = False
                if self._planner_state_metadata:
                    try:
                        new_l2_for_flow = flow_has_new_l2_evidence(
                            self._planner_state_metadata,
                            flow_id,
                        )
                    except Exception:
                        new_l2_for_flow = False
                if not new_l2_for_flow:
                    logger.info(
                        "增量复核跳过 %s：已有 %s 缓存且无新 L2",
                        flow_id, _cv.get("verdict"),
                    )
                    result_entry = {
                        "vuln_type": vuln_type,
                        "flow_id": flow_id,
                        "sink_label": sink_label,
                        "analysis": _cv.get("analysis", ""),
                        "previous_verdict": previous_verdict,
                        "flow_text": flow_text,
                        "skipped_reason": "cached_inconclusive_no_new_l2",
                    }
                    results.append(result_entry)
                    new_ambiguous.append(result_entry)
                    continue

            if self._planner_state_metadata:
                try:
                    from flow_reconcile import build_planner_l2_context_bundle

                    per_flow_l2 = build_planner_l2_context_bundle(
                        self._planner_state_metadata,
                        flow_id=flow_id,
                    )
                    if per_flow_l2:
                        self.set_planner_l2_context(per_flow_l2)
                except Exception as exc:
                    logger.warning("按 flow 注入 L2 失败 %s: %s", flow_id, exc)

            analysis = self._analyze_single_taint_flow(
                llm_client,
                vuln_type=vuln_type,
                flow_id=flow_id,
                flow_text=flow_text,
                sink_label=sink_label,
                language=language,
                max_iters=max_iters,
                review_mode=True,
                previous_conclusions=previous_conclusions,
                previous_verdict=previous_verdict,
            )

            result_entry = {
                "vuln_type": vuln_type,
                "flow_id": flow_id,
                "sink_label": sink_label,
                "analysis": analysis,
            }
            results.append(result_entry)

            # 检查复核后是否仍然模糊
            if self._is_ambiguous_verdict(analysis):
                result_entry["previous_verdict"] = previous_verdict
                result_entry["flow_text"] = flow_text
                # 合并中间过程数据
                flow_meta = getattr(self, "_current_flow_meta", None)
                if flow_meta:
                    result_entry["meta"] = flow_meta
                new_ambiguous.append(result_entry)

            # 检查是否被系统从 ✅ 覆写为 ❌（需要 L2 证据重新验证）
            if self._was_overridden_yes_to_no(analysis):
                result_entry["previous_verdict"] = previous_verdict
                result_entry["flow_text"] = flow_text
                result_entry["override_reason"] = "LLM 原始判定为 ✅ 是，但因缺少 L2/PoC 证据被系统覆写为 ❌ 否"
                flow_meta = getattr(self, "_current_flow_meta", None)
                if flow_meta:
                    result_entry["meta"] = flow_meta
                # 避免重复添加（如果已经是 ambiguous 则不重复添加）
                if result_entry not in new_ambiguous:
                    new_ambiguous.append(result_entry)

        self._last_scan_artifacts = {
            "pending_l2_reads_raw": list(self._pending_l2_raw),
            "flow_findings_index": list(self._flow_findings_index),
            "l1_covered_ranges": list(self._l1_ranges_collected),
            "flow_catalog": dict(getattr(self, "_flow_catalog", {}) or {}),
            "evidence_unreachable_flow_ids": list(getattr(self, "_evidence_unreachable_flow_ids", [])),
        }
        return new_ambiguous

    def _build_review_report(self, ambiguous_list: List[Dict[str, Any]]) -> str:
        """构建复核报告，包含分析过程详情以便后续审查。"""
        if not ambiguous_list:
            return "## 复核结果\n\n所有模糊 flow 均已明确结论，无剩余歧义。\n"

        lines = [
            f"# 🔍 漏洞扫描复核报告\n",
            f"> 时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n",
            f"> 项目: {self.project_name}\n",
            f"\n---\n",
            f"\n## 概要\n\n仍有 **{len(ambiguous_list)}** 条 flow 结论模糊：\n",
        ]

        # 概要列表
        for item in ambiguous_list:
            current_verdict = self._extract_verdict_text(item.get("analysis", ""))
            display_verdict = current_verdict or item.get("previous_verdict", "未知")
            lines.append(
                f"- **{item.get('vuln_type')}** `{item.get('flow_id')}`: {display_verdict}"
            )

        lines.append("\n---\n\n## 详细过程\n")

        # 逐 flow 详情
        for idx, item in enumerate(ambiguous_list, 1):
            vuln_type = item.get('vuln_type', 'unknown')
            flow_id = item.get('flow_id', '')
            sink_label = item.get('sink_label', '未知')
            meta = item.get('meta', {})
            flow_text = item.get('flow_text', '')
            analysis = item.get('analysis', '') or meta.get('analysis', '')
            verdict = self._extract_verdict_text(analysis) or item.get("previous_verdict", "未知")

            lines.append(f"### {idx}. {vuln_type} — `{flow_id}`\n")

            # 基本信息
            lines.append(f"#### 📌 基本信息\n")
            lines.append(f"- **漏洞类型**: {vuln_type}")
            lines.append(f"- **Flow ID**: `{flow_id}`")
            lines.append(f"- **Sink 函数**: `{sink_label or '未知'}`")
            lines.append(f"- **结论**: {verdict}\n")

            # 硬回溯信息
            backtrace = meta.get('backtrace', {})
            if backtrace:
                lines.append("#### 🔼 硬回溯过程\n")
                lines.append(f"- **回溯层数**: {backtrace.get('hops', 0)}")
                lines.append(f"- **访问方法数**: {backtrace.get('visited_methods', 0)}")
                lines.append(f"- **停止原因**: `{backtrace.get('stop_reason', 'unknown')}`")
                lines.append(f"- **是否追到输入源**: {'✅ 是' if backtrace.get('source_reached') else '❌ 否'}\n")

            # 上下文扩展信息
            expansion = meta.get('context_expansion', {})
            if expansion:
                lines.append("#### 🔄 上下文扩展\n")
                lines.append(f"- **迭代次数**: {expansion.get('iterations_used', 0)} / {expansion.get('max_iters', 0)}")
                lines.append(f"- **上下文是否充足**: {'✅ 是' if expansion.get('context_sufficient') else '❌ 否'}")
                lines.append(f"- **最终上下文长度**: {expansion.get('context_text_length', 0)} 字符\n")

            # 反证结果
            refutation = meta.get('refutation', {})
            if refutation:
                lines.append("#### ⚖️ 反证检查\n")
                lines.append(f"- **结论**: {refutation.get('verdict', '未知')}")
                lines.append(f"- **置信度**: {refutation.get('confidence_label', '未知')}\n")

            # Joern 原始输出 (截断)
            if flow_text:
                lines.append("#### 📊 Joern 原始输出\n")
                lines.append("```scala")
                lines.append(flow_text[:2000] + ("..." if len(flow_text) > 2000 else ""))
                lines.append("```\n")

            # LLM 分析内容
            if analysis:
                lines.append("#### 📝 LLM 分析\n")
                lines.append(analysis[:3000] + ("..." if len(analysis) > 3000 else ""))
                lines.append("")

            lines.append("\n---\n")

        return "\n".join(lines)

    @staticmethod
    def _classify_structured_verdict(analysis: str) -> str:
        """
        从「是否真实漏洞」结构化行提取终态。

        Returns:
            yes | no | partial | unknown
        """
        if not analysis:
            return "unknown"
        match = re.search(r"是否真实漏洞[：:]\s*([^\n]+)", analysis)
        if not match:
            return "unknown"
        text = match.group(1).strip()
        if re.search(r"✅\s*是", text):
            return "yes"
        if re.search(r"❌\s*否", text):
            return "no"
        if re.search(r"⚠️|部分是|待确认", text):
            return "partial"
        return "unknown"

    @staticmethod
    def _was_overridden_yes_to_no(analysis: str) -> bool:
        """检测分析结果是否被系统从 ✅ 是 覆写为 ❌ 否。
        
        判断依据：
        1. 存在「系统覆写」标记
        2. 最终判定为 ❌ 否
        3. 原文中有「✅ 是」的痕迹（被覆写前）
        """
        if not analysis:
            return False
        # 检查是否有系统覆写标记
        if "系统覆写" not in analysis:
            return False
        # 检查最终判定是否为 ❌ 否
        if "❌ 否" not in analysis:
            return False
        # 检查是否有被覆写的痕迹（原始判定为 ✅ 是）
        # 被覆写的报告中会有「判定与修复（系统覆写...」段落
        if "判定与修复（系统覆写" in analysis:
            return True
        return False

    def _append_inconclusive_refutation_ambiguous(
        self,
        ambiguous_list: List[Dict[str, Any]],
        *,
        vuln_type: str,
        flow_id: str,
        flow_record: Dict[str, Any],
        analysis_result: str,
    ) -> None:
        """反证仍为 inconclusive/needs_dynamic_test 时纳入增量复核队列。

        若所需 L2 证据源码在项目中不存在（证据不可达），则跳过加入队列，
        避免无意义的重复扫描。
        """
        flow_meta = getattr(self, "_current_flow_meta", None) or {}
        refutation = flow_meta.get("refutation") or {}
        verdict = str(refutation.get("verdict") or "").lower()
        if verdict not in ("inconclusive", "needs_dynamic_test"):
            return
        if any(str(item.get("flow_id")) == flow_id for item in ambiguous_list):
            return

        # 检查证据可达性：缺失的 L2 文件是否存在于磁盘
        missing_l2 = refutation.get("missing_L2_reads") or []

        # 若 missing_L2_reads 为空但反证摘要提到了源码文件，提取之
        if not missing_l2:
            ref_summary = str(refutation.get("refutation_summary") or "")
            mentioned_files = re.findall(
                r'((?:library|include|src|lib|source)/[\w/.\-]+\.(?:c|h|cpp|hpp|java))',
                ref_summary, re.IGNORECASE,
            )
            if mentioned_files:
                missing_l2 = mentioned_files

        # 若仍无 missing_L2，从反证摘要提取函数名并在项目中搜索定义文件
        if not missing_l2 and self.local_source_path:
            ref_summary = str(refutation.get("refutation_summary") or "")
            blocking = refutation.get("blocking_factors") or []
            all_text = ref_summary + " " + " ".join(str(b) for b in blocking)
            # 提取反证中提到的关键函数名（C 风格标识符，长度 > 4）
            mentioned_funcs = re.findall(r'\b(mbedtls_\w+|\w{6,}_\w+)\b', all_text)
            # 排除已在 sink_label 中出现的函数（已知在当前项目中）
            sink = flow_record.get("sink_label", "")
            mentioned_funcs = [
                f for f in set(mentioned_funcs) if f not in sink and not f.startswith("MBEDTLS_")
            ]
            if mentioned_funcs:
                from pathlib import Path as _Path
                local_root = _Path(self.local_source_path)
                # 搜索这些函数的定义文件
                all_funcs_missing = True
                for func_name in mentioned_funcs[:5]:  # 最多检查 5 个
                    # 在 .c/.cpp 文件中搜索函数定义模式
                    for ext in ("*.c", "*.cpp"):
                        for src_file in local_root.rglob(ext):
                            try:
                                content = src_file.read_text(errors="ignore")
                                if re.search(
                                    rf'(?:^|\n)\w.*\b{re.escape(func_name)}\s*\(',
                                    content,
                                ):
                                    all_funcs_missing = False
                                    break
                            except Exception:
                                pass
                        if not all_funcs_missing:
                            break
                    if not all_funcs_missing:
                        break
                if all_funcs_missing:
                    logger.info(
                        "Flow %s 证据不可达：反证提到的 %d 个函数在项目中无定义，跳过增量复核",
                        flow_id, len(mentioned_funcs),
                    )
                    getattr(self, '_evidence_unreachable_flow_ids', []).append(flow_id)
                    return

        # 检查显式列出的文件是否存在
        if missing_l2 and self.local_source_path:
            from pathlib import Path as _Path
            all_missing = True
            for mpath in missing_l2:
                candidate = _Path(self.local_source_path) / str(mpath)
                if candidate.is_file():
                    all_missing = False
                    break
            if all_missing:
                logger.info(
                    "Flow %s 证据不可达：缺失的 %d 个 L2 文件均不存在，跳过增量复核",
                    flow_id, len(missing_l2),
                )
                getattr(self, '_evidence_unreachable_flow_ids', []).append(flow_id)
                return

        entry = {
            "vuln_type": vuln_type,
            "flow_id": flow_id,
            "sink_label": flow_record.get("sink_label", ""),
            "flow_text": flow_record.get("raw_text", ""),
            "previous_verdict": self._extract_verdict_text(analysis_result),
            "refutation_verdict": verdict,
        }
        if flow_meta:
            entry["meta"] = flow_meta
        ambiguous_list.append(entry)

    @staticmethod
    def _is_ambiguous_verdict(analysis: str) -> bool:
        """判断分析结果是否为模糊结论（与结构化终态对齐）。"""
        if not analysis:
            return False
        structured = JoernVulnScannerHTTP._classify_structured_verdict(analysis)
        if structured in ("yes", "no"):
            return False
        if structured == "partial":
            return True
        ambiguous_markers = [
            "⚠️ 部分是",
            "待确认",
            "证据不足",
            "无法确定",
            "不确定",
            "可能是",
        ]
        return any(marker in analysis for marker in ambiguous_markers)

    @staticmethod
    def _extract_verdict_text(analysis: str) -> str:
        """从分析结果中提取结论摘要（用于记录上次结论）。"""
        if not analysis:
            return ""
        # 尝试提取「是否真实漏洞」行
        match = re.search(r"是否真实漏洞[：:]\s*([^\n]+)", analysis)
        if match:
            return match.group(1).strip()
        # 回退：返回前 200 字符作为摘要
        return analysis[:200].strip()