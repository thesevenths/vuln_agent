"""
`tools.py` 负责把底层能力封装成 Agent 视角下的“工具”。

这里的每个 Tool 都不是给 Joern 或 PostgreSQL 直接调用的原始接口，
而是给上层 `GraphBuilder`、CLI、乃至后续接入真正 Agent 框架时使用的高层能力：

- `JoernTool`：负责源码扫描、CPG 准备、污点查询、完整扫描。
- `DBTool`：负责从 PG 读取漏洞调用链和漏洞函数信息，并整理成可分析的上下文。

之所以要在这一层写清楚注释，是因为上层调度代码通常只会“看到”这些方法名。
如果没有详细 docstring，很难从代码层面快速判断一个 tool 接收什么参数、返回什么结构、
以及适合在什么阶段被调用。
"""

import config  # noqa: F401

import logging
from typing import Any, Dict, List, Optional

from call_stack_extra import get_call_chains, get_vuln_info, normalize_call_chains, normalize_vuln_info
from db_connector import PostgresDB
from joern_vuln_scanner import DEFAULT_JOERN_URL, JoernVulnScannerHTTP
from logic_scan_settings import DEFAULT_MAX_CANDIDATES, resolve_cwe_focus, resolve_max_candidates
import queries
from tool_capabilities import TOOL_CAPABILITIES

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class JoernTool:
    """
    Joern 相关能力的统一封装。

    这个类的职责是把 `JoernVulnScannerHTTP` 提供的细粒度能力，
    封装成更适合 Agent 编排的高层工具方法。

    上层一般不需要关心：
    - CPG 如何切换工程
    - 查询集如何根据语言和 variant 切换
    - 扫描时到底调 `run_taint_queries` 还是 `run_full_scan`

    上层只需要关心“我要扫哪个目录、用什么语言、跑几轮上下文补全”。
    """

    def __init__(self, joern_url: Optional[str] = None, project_name: Optional[str] = None, audit_callback=None):
        """
        初始化 JoernTool。
    
        Args:
            joern_url: Joern HTTP 服务地址。如果不传，则使用默认环境配置。
            project_name: Joern 工作区中的项目名。若不传，后续会从源码路径自动推导。
            audit_callback: 可选的审计回调函数，签名为 `callback(event_type, data)`。
                会透传给底层 `JoernVulnScannerHTTP`，用于记录 LLM 决策等内部事件。
        """
        # JoernTool 本身只做"参数编排"和"能力暴露"，真正执行在 client 内部。
        self.client = JoernVulnScannerHTTP(
            joern_url or DEFAULT_JOERN_URL,
            project_name or None,
            audit_callback=audit_callback,
        )
    
    def set_audit_callback(self, audit_callback):
        """
        动态设置或更新审计回调（供 planner 在运行时注入）。
    
        Args:
            audit_callback: 签名为 `callback(event_type, data)` 的函数。
        """
        self.client.audit_callback = audit_callback

    def set_planner_l2_context(self, context: str) -> None:
        """将 Planner FileTool 已读 L2 注入 Scanner 反证 prompt。"""
        self.client.set_planner_l2_context(context)

    def set_planner_state_metadata(self, metadata: Optional[Dict[str, Any]]) -> None:
        """注入 Planner metadata，供增量复核按 flow 回灌 L2。"""
        self.client.set_planner_state_metadata(metadata)

    def configure_project(
        self,
        source_root: str,
        project_name: Optional[str] = None,
        local_source_path: Optional[str] = None,
    ):
        """
        把当前 Tool 绑定到某个源码工程。

        Args:
            source_root: Joern 服务端可见的源码根目录。
            project_name: 可选的 Joern 项目名；不传时由底层自动生成。
            local_source_path: 可选的本地源码根目录，用于读取补充代码片段。

        Returns:
            无返回值。该方法会原地修改 `self.client` 的项目上下文。
        """
        self.client.configure_project(
            source_root,
            project_name=project_name,
            local_source_path=local_source_path,
        )

    def ensure_cpg(
        self,
        source_root: str,
        project_name: Optional[str] = None,
        local_source_path: Optional[str] = None,
    ) -> bool:
        """
        确保指定工程的 CPG 已经存在且可用。

        Args:
            source_root: Joern 服务端可见的源码目录。
            project_name: 可选的项目名，用于显式指定 Joern workspace 中的名字。
            local_source_path: 可选的本地源码目录。

        Returns:
            `True` 表示 CPG 已可用；`False` 表示导入或激活失败。
        """
        # 先把底层扫描器切换到目标工程，再尝试激活或导入 CPG。
        self.configure_project(
            source_root,
            project_name=project_name,
            local_source_path=local_source_path,
        )
        return self.client.ensure_cpg_loaded()

    def run_taint_queries(self, language: str = "cpp", variant: Optional[str] = None) -> Dict[str, Any]:
        """
        仅执行污点查询，不做 LLM 迭代分析。

        适合场景：
        - 想先快速拿到 Joern 原始结果
        - 想单独调试查询集
        - 想把“查询”和“分析”两个步骤拆开

        Args:
            language: 目标语言。常见值为 `java` / `cpp`。
            variant: C/C++ 查询变体，可选 `generic`、`embedded` 或特定默认变体。

        Returns:
            一个 `dict`，key 是漏洞类型名，value 是 Joern 的原始输出文本。
        """
        if variant:
            # 对 C/C++ 扫描来说，variant 直接影响选用哪一组 Joern DSL 模板。
            self.client.cpp_variant = variant
            self.client.cpp_queries = queries.get_queries(language="cpp", variant=variant)
        # run_taint_queries 只返回“原始流证据”，不生成最终报告。
        return self.client.run_taint_queries(language=language)

    def run_taint_queries_for_types(
        self,
        query_types: List[str],
        language: str = "cpp",
    ) -> Dict[str, str]:
        """
        仅执行指定漏洞类型的 Joern 查询（定向扫描）。

        Args:
            query_types: 漏洞类型列表，如 ['cpp_buffer_overflow', 'cpp_use_after_free']。
            language: 目标语言。

        Returns:
            dict，漏洞类型 → Joern 原始输出。
        """
        return self.client.run_taint_queries_for_types(
            query_types=query_types,
            language=language,
        )

    def run_targeted_source_scan(
        self,
        query_types: List[str],
        *,
        source_root: str,
        language: str = "cpp",
        variant: Optional[str] = None,
        max_iters: int = 3,
        project_name: Optional[str] = None,
        local_source_path: Optional[str] = None,
        planner_l2_context: Optional[str] = None,
        planner_state_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """定向源码扫描：指定漏洞类型 + 完整 LLM 分析/反证（非 raw taint）。"""
        self.configure_project(
            source_root,
            project_name=project_name,
            local_source_path=local_source_path,
        )
        if variant:
            self.client.cpp_variant = variant
            self.client.cpp_queries = queries.get_queries(language="cpp", variant=variant)
        if planner_l2_context:
            self.client.set_planner_l2_context(planner_l2_context)
        if planner_state_metadata is not None:
            self.client.set_planner_state_metadata(planner_state_metadata)
        return self.client.run_targeted_source_scan(
            query_types=query_types,
            language=language,
            max_iters=max_iters,
        )

    def run_source_scan(
        self,
        *,
        source_root: str,
        language: str = "cpp",
        variant: Optional[str] = None,
        max_iters: int = 3,
        project_name: Optional[str] = None,
        local_source_path: Optional[str] = None,
        focus_flows: Optional[List[Dict[str, Any]]] = None,
        review_mode: bool = False,
        previous_conclusions: Optional[str] = None,
        planner_l2_context: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        执行完整源码扫描。

        这个方法会依次完成：
        1. 绑定项目目录
        2. 选择查询 variant
        3. 准备或激活 CPG
        4. 执行污点查询
        5. 调用 LLM 进行上下文补全与最终分析

        Args:
            source_root: Joern 服务端可见的源码根目录。
            language: 目标语言。
            variant: C/C++ 查询变体。
            max_iters: LLM 补上下文的最大轮数。
            project_name: 可选的显式项目名。
            local_source_path: 可选的本地源码根目录。
            focus_flows: 可选的增量扫描参数。如果提供，只对这些 flow 重新分析。
            review_mode: 是否启用复核模式（配合 focus_flows 使用）。
            previous_conclusions: 上次扫描的结论摘要。

        Returns:
            一个结果字典，通常包含 `ok`、`flows`、`report`、`ambiguous_flows` 等字段。
        """
        # 先切项目，再跑完整扫描，确保 CPG 与路径映射都对齐到当前目标工程。
        self.configure_project(
            source_root,
            project_name=project_name,
            local_source_path=local_source_path,
        )
        if variant:
            self.client.cpp_variant = variant
            self.client.cpp_queries = queries.get_queries(language="cpp", variant=variant)
        if planner_l2_context:
            self.client.set_planner_l2_context(planner_l2_context)
        # 这里会触发完整流水线：ensure_cpg -> taint queries -> iterative analyze。
        return self.client.run_full_scan(
            language=language,
            max_iters=max_iters,
            focus_flows=focus_flows,
            review_mode=review_mode,
            previous_conclusions=previous_conclusions,
        )

    def run_recon(
        self,
        *,
        source_root: str,
        language: str = "java",
        force: bool = False,
        project_name: Optional[str] = None,
        local_source_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        侦查阶段：生成攻击面地图，作为 logic_scan / taint_scan 的前置 Phase。

        Args:
            source_root: Joern 服务端可见的源码根目录。
            language: 目标语言（用于适配器选择）。
            force: 强制重新侦查（忽略缓存）。
            project_name: 可选的显式项目名。
            local_source_path: 可选的本地源码根目录。

        Returns:
            包含 attack_surface 字典的结果。
        """
        self.configure_project(
            source_root,
            project_name=project_name,
            local_source_path=local_source_path,
        )
        return self.client.run_recon(language=language, force=force)

    def run_logic_scan(
        self,
        *,
        source_root: str,
        language: str = "java",
        cwe_focus: Optional[List[str]] = None,
        max_candidates: Optional[int] = None,
        project_name: Optional[str] = None,
        local_source_path: Optional[str] = None,
        incremental_query_names: Optional[List[str]] = None,
        cached_query_results: Optional[Dict[str, str]] = None,
        cached_findings: Optional[List[Dict[str, Any]]] = None,
        recon_results: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        逻辑漏洞扫描：枚举端点/守卫/敏感操作，交叉分析缺失鉴权、IDOR 等逻辑漏洞。

        与 run_source_scan 的区别：不依赖 reachableByFlows 污点流，
        而是通过 Joern AST/CFG 查询 + CWE reasoning_workflow 指导的 LLM 分析。

        Args:
            source_root: Joern 服务端可见的源码根目录。
            language: 目标语言（当前仅支持 java）。
            cwe_focus: 可选 CWE 编号列表（如 ["862","306"]），缩小扫描范围。
            max_candidates: 最大候选漏洞分析数量。
            project_name: 可选的显式项目名。
            local_source_path: 可选的本地源码根目录。
            incremental_query_names: 增量重试时，只执行这些查询名。
            cached_query_results: 增量重试时，合并上次 Joern 查询结果。
            cached_findings: 增量重试时，复用上次 LLM 结论（仅重分析失败 query 影响的类型）。
            recon_results: 可选的侦查结果（从 run_recon 产出），注入攻击面信息到 LLM context。

        Returns:
            结果字典，包含 ok、report、flow_findings_index、logic_candidates 等字段。
        """
        self.configure_project(
            source_root,
            project_name=project_name,
            local_source_path=local_source_path,
        )

        # ── 自动前置侦查：如果调用方未传入 recon_results 且非增量重试，
        #    先运行 Recon 生成攻击面地图，再透传给 logic_scan ──
        if recon_results is None and incremental_query_names is None:
            try:
                logger.info("logic_scan 前置侦查: 自动运行 run_recon(language=%s)", language)
                recon_results = self.client.run_recon(language=language)
                if recon_results.get("ok"):
                    logger.info("前置侦查完成: %s", recon_results.get("recon_summary", ""))
                else:
                    logger.warning("前置侦查失败，logic_scan 将在无攻击面信息下运行")
                    recon_results = None
            except Exception as exc:
                logger.warning("前置侦查异常，跳过: %s", exc)
                recon_results = None

        return self.client.run_logic_scan(
            language=language,
            cwe_focus=cwe_focus,
            max_candidates=max_candidates,
            incremental_query_names=incremental_query_names,
            cached_query_results=cached_query_results,
            cached_findings=cached_findings,
            recon_results=recon_results,
        )

    def expand_flow_context(
        self,
        *,
        source_root: str,
        flow_id: str,
        vuln_type: str,
        flow_text: str,
        sink_label: str = "",
        language: str = "cpp",
        variant: Optional[str] = None,
        max_extra_iters: Optional[int] = None,
        project_name: Optional[str] = None,
        local_source_path: Optional[str] = None,
        prior_context: Optional[str] = None,
        method_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        对指定 flow 再跑 1～2 轮 Joern LLM 上下文扩展（Planner 门禁前置步骤）。

        L2 反证仍 inconclusive 且需读源文件定点行段前，必须先调用本方法；
        扩展用尽或失败后才允许 FileTool 读取 .c/.java 等源文件。

        Args:
            source_root: Joern 服务端可见的源码根目录。
            flow_id: flow 标识符。
            vuln_type: 漏洞类型（如 CWE-639）。
            flow_text: Joern 原始输出或类 Joern 格式上下文。
            sink_label: sink 标签。
            language: 目标语言。
            variant: 可选的查询变体。
            max_extra_iters: 最大扩展轮数。
            project_name: 可选的显式项目名。
            local_source_path: 可选的本地源码根目录。
            prior_context: 可选的已有上下文。
            method_name: 可选的方法全名（逻辑扫描场景），用于直接引导 follow_up 查询。
        """
        self.configure_project(
            source_root,
            project_name=project_name,
            local_source_path=local_source_path,
        )
        if variant:
            self.client.cpp_variant = variant
            self.client.cpp_queries = queries.get_queries(language="cpp", variant=variant)
        return self.client.expand_flow_context(
            vuln_type=vuln_type,
            flow_id=flow_id,
            flow_text=flow_text,
            sink_label=sink_label,
            language=language,
            max_extra_iters=max_extra_iters,
            prior_context=prior_context,
            method_name=method_name,
        )


class DBTool:
    """
    PostgreSQL 读取工具。

    该类只负责“读”漏洞相关结构化数据，不负责生成分析结论。
    这样可以把“数据获取”和“数据解释”两个职责拆开：

    - `DBTool`：从库里读取原始事实
    - `chains.py` / `GraphBuilder`：把事实组织成分析报告
    """

    def __init__(self, dsn: Optional[str] = None):
        """
        初始化数据库工具。

        Args:
            dsn: 可选的 PostgreSQL 连接串。若不传，则回退到环境变量配置。
        """
        self.dsn = dsn

    def _connect(self):
        """
        创建一个新的数据库连接包装器。

        Returns:
            `PostgresDB` 实例，供 `with` 语句管理生命周期。
        """
        # 每次调用返回新连接包装器，生命周期由 `with` 自动管理。
        return PostgresDB(dsn=self.dsn)

    def get_call_chains(self, cve_id: str):
        """
        获取某个漏洞的调用链数据。

        Args:
            cve_id: 例如 `CVE-2021-44228`。

        Returns:
            数据库原始查询结果；上层如需稳定结构，应进一步调用 `get_reachability_context`。
        """
        with self._connect() as db:
            return get_call_chains(db, cve_id)

    def get_vuln_info(self, cve_id: str):
        """
        获取某个漏洞函数的基础信息。

        Args:
            cve_id: 漏洞编号。

        Returns:
            原始数据库结果，通常包含方法所属类、函数名、返回值、参数类型、文件路径等。
        """
        with self._connect() as db:
            return get_vuln_info(db, cve_id)

    def get_reachability_context(self, cve_id: str) -> Dict[str, Any]:
        """
        组装漏洞可达分析所需的完整上下文。

        这是 `DBTool` 最重要的方法，因为它不只是“取两张表”，
        还会把两边结果标准化成统一结构，方便后续直接送给 LLM。

        Args:
            cve_id: 漏洞编号。

        Returns:
            一个统一结构的字典，包含：
            - `cve_id`
            - `call_chains`
            - `vuln_info`
        """
        with self._connect() as db:
            raw_call_chains = get_call_chains(db, cve_id)
            raw_vuln_info = get_vuln_info(db, cve_id)

        # 统一结构有两个好处：
        # 1) 上游调用方不用关心 DB cursor 返回 tuple 还是 dict
        # 2) LLM prompt 模板可稳定复用固定字段名
        return {
            "cve_id": cve_id,
            "call_chains": normalize_call_chains(raw_call_chains),
            "vuln_info": normalize_vuln_info(raw_vuln_info),
        }

    def query_cve_by_cwe(self, cwe_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        """
        按 CWE 查询 CVE 列表，返回结构化数据。

        Args:
            cwe_id: CWE 编号，如 'CWE-120' 或 '120'。
            limit: 最大返回数量。

        Returns:
            CVE 信息列表，每项包含 cve_id、描述、函数名等。
        """
        cwe_clean = cwe_id.replace("CWE-", "").replace("cwe-", "").strip()
        results: List[Dict[str, Any]] = []

        # 尝试多种表名（适配不同 DB schema）
        table_candidates = [
            ("vuln.cve_info", "cve_id"),
            ("vuln.cves", "id"),
            ("vuln.cve_metadata", "cve_id"),
            ("vuln.vuln_info", "cve_id"),
        ]

        with self._connect() as db:
            for table, id_col in table_candidates:
                try:
                    sql = (
                        f"SELECT * FROM {table} "
                        f"WHERE cwe_id = %s OR cwe_id = %s OR CAST(cwe_id AS TEXT) LIKE %s "
                        f"ORDER BY {id_col} DESC LIMIT %s"
                    )
                    rows = db.execute_query(sql, (cwe_id, cwe_clean, f"%{cwe_clean}%", limit))
                    if rows:
                        for row in rows:
                            if isinstance(row, dict):
                                results.append(row)
                            else:
                                results.append({"raw": row})
                        logger.info("query_cve_by_cwe: %s 返回 %d 行 (表=%s)", cwe_id, len(results), table)
                        break
                except Exception as exc:
                    logger.debug("query_cve_by_cwe: 表 %s 查询失败: %s", table, exc)
                    continue

        return results

    def get_cve_patterns(self, component: Optional[str] = None, cwe_id: Optional[str] = None) -> Dict[str, Any]:
        """
        获取组件或 CWE 的漏洞模式摘要。

        Args:
            component: 可选组件名（如 'mbedtls'）。
            cwe_id: 可选 CWE 编号（如 'CWE-120'）。

        Returns:
            模式摘要字典，包含 common_sinks、common_components、cve_count 等。
        """
        result: Dict[str, Any] = {
            "component": component,
            "cwe_id": cwe_id,
            "common_sinks": [],
            "common_components": [],
            "cve_count": 0,
        }

        with self._connect() as db:
            # 按组件查询
            if component:
                try:
                    sql = (
                        "SELECT DISTINCT cve_id, call_stack, entry_point_function_name, component_name "
                        "FROM vuln.vuln_call_chains "
                        "WHERE component_name ILIKE %s LIMIT 100"
                    )
                    rows = db.execute_query(sql, (f"%{component}%",))
                    if rows:
                        sink_set = set()
                        comp_set = set()
                        cve_set = set()
                        for row in rows:
                            if isinstance(row, dict):
                                call_stack = row.get("call_stack")
                                comp = row.get("component_name")
                                cve = row.get("cve_id")
                            else:
                                call_stack = row[1] if len(row) > 1 else None
                                comp = row[3] if len(row) > 3 else None
                                cve = row[0] if len(row) > 0 else None
                            if cve:
                                cve_set.add(str(cve))
                            if comp:
                                comp_set.add(str(comp))
                            # 从调用栈提取函数名
                            if isinstance(call_stack, str):
                                import re
                                fns = re.findall(r'[\w]+(?:\([^)]*\))?', call_stack)
                                sink_set.update(f for f in fns if len(f) > 3)

                        result["common_sinks"] = list(sink_set)[:15]
                        result["common_components"] = list(comp_set)[:5]
                        result["cve_count"] = len(cve_set)
                        result["cve_ids"] = list(cve_set)[:20]
                except Exception as exc:
                    logger.warning("get_cve_patterns: 组件查询失败: %s", exc)

            # 按 CWE 查询
            if cwe_id:
                try:
                    cwe_clean = cwe_id.replace("CWE-", "").replace("cwe-", "")
                    sql = (
                        "SELECT DISTINCT call_stack, entry_point_function_name, component_name "
                        "FROM vuln.vuln_call_chains c "
                        "JOIN vuln.cve_info ci ON c.cve_id = ci.cve_id "
                        "WHERE ci.cwe_id = %s OR ci.cwe_id = %s LIMIT 100"
                    )
                    rows = db.execute_query(sql, (cwe_id, cwe_clean))
                    if rows:
                        sink_set = set()
                        for row in rows:
                            if isinstance(row, dict):
                                call_stack = row.get("call_stack")
                            else:
                                call_stack = row[0] if len(row) > 0 else None
                            if isinstance(call_stack, str):
                                import re
                                fns = re.findall(r'[\w]+', call_stack)
                                sink_set.update(f for f in fns if len(f) > 3)
                        if sink_set:
                            result["common_sinks"] = list(sink_set)[:15]
                except Exception as exc:
                    logger.debug("get_cve_patterns: CWE JOIN 查询失败 (可能无 cve_info 表): %s", exc)

        return result

