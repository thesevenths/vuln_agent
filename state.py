"""
`state.py` 定义 agent 运行时的共享状态。

这个状态对象的作用是把“当前要分析哪个项目、最近一次跑出了什么结果”
集中存放到一个地方，避免 CLI、REPL、调度层之间互相直接传很多零散参数。
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AgentState:
    """
    保存一次 agent 会话中的关键上下文。

    字段大致可以分成两类：
    - 运行参数：项目路径、语言、variant、最大迭代轮数
    - 最近结果：最近一次 flows、最近报告、最近 reachability 上下文
    """

    # --- 运行参数（planner 和工具执行时会读取） ---
    # 这些字段描述“现在准备分析什么、按什么方式分析”。
    project_path: Optional[str] = None
    local_source_path: Optional[str] = None
    project_name: Optional[str] = None
    language: str = "cpp"
    variant: str = "generic"
    max_iters: int = 3

    # --- 最近一次执行产物（用于连续对话和增量分析） ---
    # 这些字段描述"上一次已经拿到了什么事实/报告"。
    last_flows: Dict[str, Any] = field(default_factory=dict)
    last_report: Optional[str] = None
    last_reachability_context: Dict[str, Any] = field(default_factory=dict)
    
    # --- 模糊结论追踪（用于重扫时的反馈传递和增量分析） ---
    # ambiguous_flows: 上次扫描中结论为"⚠️ 部分是"或"待确认"的 flow 列表
    # 每个元素包含 {vuln_type, flow_id, sink_label, previous_verdict, reason}
    ambiguous_flows: List[Dict[str, Any]] = field(default_factory=list)
    # 上次扫描的简要结论摘要，传给复核 LLM 作为参考
    previous_scan_conclusions: Optional[str] = None

    # --- 组件版本识别（二进制反编译 vs 候选源码） ---
    version_identification: Dict[str, Any] = field(default_factory=dict)

    # --- 当前任务上下文（planner 循环控制） ---
    # 这些字段更多服务于多步 agent run，而不是底层扫描本身。
    current_cve_id: Optional[str] = None
    current_user_request: Optional[str] = None
    plan_history: List[Dict[str, Any]] = field(default_factory=list)
    last_planner_answer: Optional[str] = None
    audit_log_path: Optional[str] = None
    current_plan_run_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    active_skills: List[Dict[str, Any]] = field(default_factory=list)

    def set_project(
        self,
        path: str,
        project_name: Optional[str] = None,
        local_source_path: Optional[str] = None,
    ):
        """
        设置当前目标项目。

        Args:
            path: Joern 服务端可见的项目根目录。
            project_name: 可选的逻辑项目名。
            local_source_path: 可选的本地源码根目录。
                当 Joern 运行在远端容器/服务器，而当前 agent 运行在本地时，
                应通过这个字段告诉 agent 去哪里读取真实源码上下文。
        """
        self.project_path = path
        self.project_name = project_name
        if local_source_path is not None:
            self.local_source_path = local_source_path
        # metadata 用于轻量标记会话行为，不影响核心扫描逻辑。
        self.metadata["project_set"] = True

    def set_local_source_path(self, path: Optional[str]):
        """
        设置当前会话用于补充代码上下文的本地源码根目录。

        Args:
            path: 本地可读源码目录。
        """
        self.local_source_path = path

    def set_language(self, language: str):
        """设置当前扫描语言。"""
        # 语言字段会影响查询集选择，以及最终提示词里使用的语言提示。
        self.language = language

    def set_variant(self, variant: str):
        """设置当前 C/C++ 查询变体。"""
        # variant 主要在 C/C++ 下生效，用于在 generic / embedded / 默认查询间切换。
        self.variant = variant

    def set_max_iters(self, max_iters: int):
        """设置 LLM 补上下文的最大迭代轮数。"""
        # 该值越大，模型越有机会补齐证据，但运行时间和 token 成本也会上升。
        self.max_iters = max_iters

    def update_flows(self, flows: Dict[str, Any]):
        """保存最近一次 Joern/扫描产生的原始 flow 数据。"""
        # 这里保留“原始流”而不是只保留最终结论，方便后续继续追问和复核。
        self.last_flows = flows

    def update_report(self, text: str):
        """保存最近一次生成的分析报告文本。"""
        # last_report 是“最近一次的人类可读结论”，通常给 CLI / planner 直接展示。
        self.last_report = text

    def update_version_identification(self, version_result: Dict[str, Any]):
        """保存最近一次组件版本识别结果（供后续 Joern/SCA 使用）。"""
        self.version_identification = version_result
        if version_result.get("matched_source_root"):
            self.local_source_path = version_result["matched_source_root"]
        best = (version_result.get("best_matches") or [None])[0]
        if isinstance(best, dict) and best.get("source_root"):
            self.metadata["identified_component_version"] = best.get("version")
            self.metadata["identified_source_root"] = best.get("source_root")

    def update_reachability_context(self, reachability_context: Dict[str, Any]):
        """保存最近一次可达分析使用的结构化数据库上下文。"""
        # 与 last_report 不同，这里存的是“结构化事实”，便于后续继续二次分析。
        self.last_reachability_context = reachability_context
        if reachability_context.get("cve_id"):
            # 当上下文里带 cve_id 时，自动同步当前目标，减少重复 set_cve。
            self.current_cve_id = reachability_context["cve_id"]

    def set_cve_id(self, cve_id: Optional[str]):
        """
        设置当前分析目标对应的 CVE 编号。

        Args:
            cve_id: 漏洞编号，例如 `CVE-2021-44228`。
        """
        self.current_cve_id = cve_id

    def start_plan(self, user_request: str):
        """
        开始一次新的规划执行。

        Args:
            user_request: 本轮用户任务原文。
        """
        self.current_user_request = user_request
        # 新一轮 run 开始时清空历史，避免上一次任务的观察污染当前决策。
        self.plan_history = []
        # 清空最终回答，表示本轮还没结束。
        self.last_planner_answer = None
        self.active_skills = []
        self.metadata.pop("last_skill_execution", None)
        self.metadata.pop("skill_runtime", None)
        self.metadata.pop("skill_collab_queue", None)
        self.metadata.pop("last_skill_rewrite", None)
        self.metadata.pop("prompt_variant_id", None)
        self.metadata.pop("last_generated_prompt_variant", None)

    def add_plan_history(self, history_item: Dict[str, Any]):
        """追加一条计划/执行/观察记录。"""
        # 每个 history_item 通常对应一轮：
        # planner 给出计划 -> 执行动作 -> 返回 observation。
        self.plan_history.append(history_item)

    def finish_plan(self, final_answer: str):
        """结束当前规划执行并保存最终回答。"""
        # 保留最终回答，便于 CLI/上层调用在 run() 返回后直接读取。
        self.last_planner_answer = final_answer

    def set_active_skills(self, skills: List[Dict[str, Any]]):
        """
        更新当前 run 的推荐技能列表。

        Args:
            skills: 技能匹配结果（通常由 SkillEngine 生成）。
        """
        self.active_skills = list(skills or [])
        self.metadata["active_skill_ids"] = [item.get("skill_id") for item in self.active_skills if item.get("skill_id")]

    def set_audit_log_path(self, audit_log_path: Optional[str]):
        """
        设置 planner 审计日志落盘路径。

        Args:
            audit_log_path: JSONL 审计文件路径。
        """
        # 审计路径存在 state 中，而不是只存在 planner 中，
        # 是为了让 CLI/REPL/外部调用都能共享同一落盘位置。
        self.audit_log_path = audit_log_path

    def set_ambiguous_flows(self, flows: List[Dict[str, Any]]):
        """
        保存上次扫描中结论模糊的 flow 列表，供下次重扫时增量分析。

        Args:
            flows: 模糊 flow 列表，每个元素包含:
                   - vuln_type: 漏洞类型
                   - flow_id: flow 标识
                   - sink_label: sink 标签
                   - flow_text: 原始 flow 文本
                   - previous_verdict: 上次结论（如 "⚠️ 部分是"）
                   - reason: 模糊原因摘要
        """
        self.ambiguous_flows = list(flows or [])

    def set_previous_scan_conclusions(self, summary: str):
        """
        保存上次扫描的结论摘要，传给复核 LLM。

        Args:
            summary: 上次扫描的结论摘要文本。
        """
        self.previous_scan_conclusions = summary

    def clear_ambiguous_flows(self):
        """清空模糊 flow 追踪（扫描完成且结论明确后调用）。"""
        self.ambiguous_flows = []
        self.previous_scan_conclusions = None