"""
`graph.py` 负责把底层工具串成一个完整流程。

虽然当前实现没有强依赖外部图框架，
但这个类扮演的角色本质上就是“编排器”：

- 决定先读数据库还是先扫源码
- 决定扫描结果是否还要再做简要 triage
- 决定最终给上层返回什么结构
"""

from typing import Any, Dict, List, Optional

from chains import make_reachability_report, triage_flows
from tools import DBTool, JoernTool
from version_tool import VersionTool


class GraphBuilder:
    """
    轻量流程编排器。

    这个类存在的意义是把“工具调用顺序”固定下来，
    从而避免 CLI 或未来的 Agent 直接拼装底层方法时出现顺序不一致的问题。
    """

    def __init__(self, joern: JoernTool, db: DBTool, version: Optional[VersionTool] = None):
        """
        Args:
            joern: 提供源码扫描能力的工具对象。
            db: 提供 PG 读取能力的工具对象。
            version: 组件版本识别工具；不传则使用默认实例。
        """
        # GraphBuilder 不拥有这些工具的业务逻辑，
        # 它只负责决定“什么时候调用谁、先后顺序是什么”。
        self.joern = joern
        self.db = db
        self.version = version or VersionTool()

    def run_version_identification(
        self,
        *,
        decompiled_path: str,
        candidate_paths: List[str],
        component_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        比对反编译 C 与候选源码版本，返回识别结果。

        典型用法：在 Joern 扫描前确定应导入哪一版官方源码树。
        """
        return self.version.identify_component(
            decompiled_path=decompiled_path,
            candidate_paths=candidate_paths,
            component_name=component_name,
        )

    def run_source_scan(
        self,
        *,
        project_path: str,
        local_source_path: Optional[str] = None,
        language: str = "cpp",
        variant: Optional[str] = None,
        max_iters: int = 3,
        project_name: Optional[str] = None,
        focus_flows: Optional[List[Dict[str, Any]]] = None,
        review_mode: bool = False,
        previous_conclusions: Optional[str] = None,
        planner_l2_context: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        执行"源码扫描"主流程。
    
        Args:
            project_path: Joern 服务端可见的源码根目录。
            local_source_path: 可选的本地源码根目录。
            language: 扫描语言。
            variant: C/C++ 查询变体。
            max_iters: LLM 迭代补上下文的最大轮数。
            project_name: 可选的 Joern 项目名。
            focus_flows: 可选的增量扫描参数（只重新分析这些 flow）。
            review_mode: 是否启用复核模式。
            previous_conclusions: 上次扫描的结论摘要。
    
        Returns:
            包含原始 `flows`、最终 `report`、`ambiguous_flows` 以及附加 `triage` 的结果字典。
        """
        # GraphBuilder 的职责是"固定顺序"，不是"重新实现扫描细节"。
        # 因此这里直接调用 JoernTool 的完整扫描入口。
        scan_result = self.joern.run_source_scan(
            source_root=project_path,
            local_source_path=local_source_path,
            language=language,
            variant=variant,
            max_iters=max_iters,
            project_name=project_name,
            focus_flows=focus_flows,
            review_mode=review_mode,
            previous_conclusions=previous_conclusions,
            planner_l2_context=planner_l2_context,
        )
        # `triage` 不是最终报告，而是快速摘要，便于上层先看大概命中情况。
        # 这样上层 UI/CLI 可以先展示"命中概览"，再决定是否展开完整报告。
        scan_result["triage"] = triage_flows(scan_result.get("flows", {}))
        # 返回值继续沿用 scan_result 原结构，只额外补一个 triage，
        # 这样上层不用维护两套不同的数据格式。
        return scan_result

    def run_logic_scan(
        self,
        *,
        project_path: str,
        local_source_path: Optional[str] = None,
        language: str = "java",
        cwe_focus: Optional[List[str]] = None,
        max_candidates: Optional[int] = None,
        project_name: Optional[str] = None,
        incremental_query_names: Optional[List[str]] = None,
        cached_query_results: Optional[Dict[str, str]] = None,
        cached_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        逻辑漏洞扫描。

        通过 Joern AST 查询枚举端点/鉴权守卫/敏感操作，
        交叉分析缺失鉴权、IDOR、硬编码凭证等逻辑漏洞。

        Args:
            project_path: Joern 服务端可见的源码根目录。
            local_source_path: 可选的本地源码根目录。
            language: 目标语言（当前仅支持 java）。
            cwe_focus: 可选 CWE 编号列表。
            max_candidates: 最大候选漏洞分析数量。
            project_name: 可选的显式项目名。

        Returns:
            结果字典。
        """
        return self.joern.run_logic_scan(
            source_root=project_path,
            language=language,
            cwe_focus=cwe_focus,
            max_candidates=max_candidates,
            project_name=project_name,
            local_source_path=local_source_path,
            incremental_query_names=incremental_query_names,
            cached_query_results=cached_query_results,
            cached_findings=cached_findings,
        )

    def expand_flow_context(
        self,
        *,
        project_path: str,
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
        """Planner 门禁：单 flow Joern 扩展，不触发全量扫描。

        Args:
            method_name: 可选的方法全名（逻辑扫描场景），用于直接引导 follow_up 查询。
        """
        return self.joern.expand_flow_context(
            source_root=project_path,
            flow_id=flow_id,
            vuln_type=vuln_type,
            flow_text=flow_text,
            sink_label=sink_label,
            language=language,
            variant=variant,
            max_extra_iters=max_extra_iters,
            project_name=project_name,
            local_source_path=local_source_path,
            prior_context=prior_context,
            method_name=method_name,
        )

    def run_reachability(self, cve_id: str) -> Dict[str, Any]:
        """
        执行“漏洞可达分析”主流程。

        Args:
            cve_id: 目标漏洞编号。

        Returns:
            包含标准化数据库上下文和最终可达性报告的结果字典。
        """
        # 第一步：从数据库中提取结构化事实（调用链 + 漏洞函数信息）。
        reachability_context = self.db.get_reachability_context(cve_id)
        # 第二步：把这些事实交给 LLM，生成更适合人阅读的可达性说明。
        # 注意这里依赖的是“结构化输入”，不是让模型凭空猜结论。
        reachability_report = make_reachability_report(reachability_context=reachability_context)
        # 这里统一返回 `ok/context/report` 结构，
        # 方便 CLI、planner、REPL 都用同一方式消费结果。
        return {
            "ok": True,
            "cve_id": cve_id,
            "reachability_context": reachability_context,
            "report": reachability_report,
        }