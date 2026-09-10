"""
`main.py` 是当前 `agent` 目录下的命令行入口。

这个文件主要解决两个问题：
1. 把用户输入的命令行参数转换成内部状态对象 `AgentState`
2. 把 REPL 命令映射到真正的扫描/可达分析能力

换句话说，`main.py` 不直接做漏洞分析，
它负责“接参数、调流程、打印结果”。
"""

import config  # noqa: F401  # 必须在其它本地模块之前加载 .env

import argparse
import json
import logging
import os

from graph import GraphBuilder
from joern_vuln_scanner import DEFAULT_JOERN_URL, DEFAULT_PROJECT, DEFAULT_PROJECT_NAME
from planner import AgentPlannerExecutor
from state import AgentState
from tools import DBTool, JoernTool

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def print_result(result: dict):
    """
    统一格式化输出结果对象。

    Args:
        result: 任意可 JSON 序列化的结果字典。

    Returns:
        无返回值。函数会直接把结构化结果打印到终端。
    """
    # 使用 `ensure_ascii=False` 保证中文日志和报告在终端里可读。
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))


def run_agent_task(state: AgentState, planner: AgentPlannerExecutor, user_request: str):
    """
    用统一 agent 编排器执行一个自然语言任务。

    Args:
        state: 当前会话状态。
        planner: planner / executor 编排器。
        user_request: 用户自然语言请求。

    Returns:
        无返回值。会把结果打印到终端。
    """
    # 统一入口：不管是 REPL 命令还是一次性 CLI 模式，最终都走 planner。
    # 这样能保证：
    # 1. 所有模式都共享同一套计划/执行逻辑
    # 2. 都会自动写审计日志
    # 3. 都能复用多步补上下文能力
    result = planner.run(state, user_request)
    if result.get("saved_report_path"):
        print("Vulnerability report saved:", result["saved_report_path"])
    audit_report_paths = result.get("audit_report_paths", {})
    if audit_report_paths:
        # planner 会把 JSONL 审计流额外渲染成 Markdown/HTML，便于人工回放。
        print("Audit reports generated:")
        if audit_report_paths.get("markdown_report_path"):
            print("  Markdown:", audit_report_paths["markdown_report_path"])
        if audit_report_paths.get("html_report_path"):
            print("  HTML:", audit_report_paths["html_report_path"])
    print_result(result)


def run_source_scan(state: AgentState, graph: GraphBuilder):
    """
    基于当前状态执行一次源码漏洞扫描。

    Args:
        state: 当前会话状态，里面保存项目路径、语言、查询变体等运行参数。
        graph: 负责真正调度扫描逻辑的流程对象。

    Returns:
        无返回值。执行结果会写回 `state`，并打印到终端。
    """
    if not state.project_path:
        print("请先设置 project_path")
        return

    # 这里把状态对象中的运行参数原封不动传给图调度层，
    # 保证 CLI / REPL 和后续真正 Agent 编排看到的是同一套行为。
    result = graph.run_source_scan(
        project_path=state.project_path,
        local_source_path=state.local_source_path,
        language=state.language,
        variant=state.variant,
        max_iters=state.max_iters,
        project_name=state.project_name,
    )
    # 扫描结束后把结果回写到 state，后续如果再问“刚才扫到了什么”，
    # planner 或 REPL 就能直接拿到最近结果继续分析。
    state.update_flows(result.get("flows", {}))
    state.update_report(result.get("report", ""))
    print_result(result)


def run_reachability(state: AgentState, graph: GraphBuilder, cve_id: str):
    """
    基于 PG 中已有数据执行漏洞可达分析。

    Args:
        state: 当前会话状态，用于保存本次分析结果。
        graph: 流程调度对象。
        cve_id: 目标漏洞编号。

    Returns:
        无返回值。结果会更新到 `state` 并打印。
    """
    # 可达分析与源码扫描类似：真正的事实提取和报告生成在 graph 内完成，
    # 这里主要负责把结果写回 state，保证会话连续性。
    result = graph.run_reachability(cve_id)
    state.update_reachability_context(result.get("reachability_context", {}))
    state.update_report(result.get("report", ""))
    print_result(result)


def repl(state: AgentState, graph: GraphBuilder, planner: AgentPlannerExecutor):
    """
    启动一个轻量 REPL，方便手动调试 agent。

    Args:
        state: 会话状态对象，所有命令都会读写这个状态。
        graph: 真正负责执行扫描和可达分析的流程对象。

    Returns:
        无返回值。函数会阻塞直到用户退出。
    """
    print(
        "Agent REPL（支持自然语言）. Commands: "
        "set_project <path> | set_project_name <name> | set_language <java|cpp> | "
        "set_variant <generic|embedded|vendor> | set_iters <n> | set_local_source <path> | set_cve <id> | set_audit_log <path> | source_scan | "
        "reachability <cve_id> | version_identify <decompiled.c> <zip1> <zip2> [...] | "
        "prompt_list_variants | prompt_approve <variant_id> | prompt_reject <variant_id> | "
        "ask <natural language task> | show_state | exit\n"
        "也可以直接输入自然语言需求（不用写 ask）。"
    )
    # REPL 主循环是“读一行 -> 解析命令 -> 更新状态或触发任务”。
    while True:
        try:
            raw_command = input(">> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not raw_command:
            continue

        # 这里先做最简单的空格切分；对于路径类参数，
        # 后面会用 `" ".join(parts[1:])` 重新拼回完整字符串。
        parts = raw_command.split()
        command_name = parts[0]

        # 退出类命令直接终止循环。
        if command_name in ("exit", "quit"):
            break
        if command_name == "help":
            print(
                "Commands: set_project <path> | set_project_name <name> | set_language <java|cpp> | "
                "set_variant <generic|embedded|vendor> | set_iters <n> | set_local_source <path> | set_cve <id> | set_audit_log <path> | source_scan | "
                "reachability <cve_id> | version_identify <decompiled.c> <zip1> <zip2> [...] | "
                "prompt_list_variants | prompt_approve <variant_id> | prompt_reject <variant_id> | "
                "ask <natural language task> | show_state | exit"
            )
            continue
        if command_name == "prompt_list_variants":
            result = planner.prompt_evolver.list_variants()
            print_result(result)
            continue
        if command_name == "prompt_approve" and len(parts) > 1:
            result = planner.prompt_evolver.approve_variant(parts[1])
            print_result(result)
            continue
        if command_name == "prompt_reject" and len(parts) > 1:
            result = planner.prompt_evolver.reject_variant(parts[1])
            print_result(result)
            continue
        if command_name == "version_identify" and len(parts) >= 4:
            decompiled_path = parts[1]
            candidate_paths = parts[2:]
            run_agent_task(
                state,
                planner,
                (
                    f"请识别组件版本：反编译文件 `{decompiled_path}`，"
                    f"候选源码 {candidate_paths}。先调用版本识别工具，再给出结论。"
                ),
            )
            continue
        if command_name == "set_project" and len(parts) > 1:
            project_path = " ".join(parts[1:])
            # set_project 只改上下文，不触发扫描。
            state.set_project(project_path, project_name=state.project_name)
            print("Project set to", project_path)
            continue
        if command_name == "set_project_name" and len(parts) > 1:
            project_name = " ".join(parts[1:])
            # 这里只更新 project_name，不改 project_path；
            # 适合“源码目录不变，但想显式指定 Joern workspace 名”的场景。
            state.project_name = project_name
            print("Project name set to", project_name)
            continue
        if command_name == "set_language" and len(parts) > 1:
            state.set_language(parts[1])
            print("Language set to", state.language)
            continue
        if command_name == "set_variant" and len(parts) > 1:
            # variant 主要影响 C/C++ 查询集选择；
            # Java 路径下通常不会用到这个字段。
            state.set_variant(parts[1])
            print("Variant set to", state.variant)
            continue
        if command_name == "set_iters" and len(parts) > 1:
            state.set_max_iters(int(parts[1]))
            print("Max iterations set to", state.max_iters)
            continue
        if command_name == "set_local_source" and len(parts) > 1:
            local_source_path = " ".join(parts[1:])
            state.set_local_source_path(local_source_path)
            print("Local source path set to", state.local_source_path)
            continue
        if command_name == "set_cve" and len(parts) > 1:
            state.set_cve_id(parts[1])
            print("Current CVE set to", state.current_cve_id)
            continue
        if command_name == "set_audit_log" and len(parts) > 1:
            audit_log_path = " ".join(parts[1:])
            # 审计日志路径也存在 state 中，这样 planner 每轮写日志时都能读到。
            state.set_audit_log_path(audit_log_path)
            print("Audit log path set to", audit_log_path)
            continue
        if command_name == "source_scan":
            # source_scan/reachability 在 REPL 里也统一转成自然语言任务，
            # 这样可以复用 planner 的多步规划、审计日志和自动补上下文能力。
            run_agent_task(
                state,
                planner,
                f"请对项目 `{state.project_path}` 执行源码漏洞扫描，并给出最终可执行结论。",
            )
            continue
        if command_name == "reachability" and len(parts) > 1:
            run_agent_task(
                state,
                planner,
                f"请分析漏洞 `{parts[1]}` 在当前项目中的可达性和可利用性，并给出证据链。",
            )
            continue
        if command_name == "show_state":
            # 直接输出 dataclass 的内部字典，便于调试当前上下文是否设置正确。
            print_result(state.__dict__)
            continue
        if command_name == "ask" and len(parts) > 1:
            # ask 是显式自然语言入口；默认分支也支持直接自然语言输入。
            run_agent_task(state, planner, " ".join(parts[1:]))
            continue

        # 默认分支：把整行输入当自然语言任务交给 planner/executor 循环处理。
        run_agent_task(state, planner, raw_command)


def main():
    """
    解析命令行参数并决定当前进程以哪种模式运行。

    支持三种模式：
    - `repl`：交互式调试
    - `source_scan`：一次性执行源码漏洞扫描
    - `reachability`：一次性执行漏洞可达分析
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--joern-url", default=DEFAULT_JOERN_URL)
    parser.add_argument("--project", default=DEFAULT_PROJECT)
    parser.add_argument("--project-name", default=os.environ.get("JOERN_PROJECT_NAME", DEFAULT_PROJECT_NAME))
    parser.add_argument("--language", default=os.environ.get("AGENT_LANGUAGE", "cpp"))
    parser.add_argument("--variant", default=os.environ.get("JOERN_CPP_VARIANT", "generic"))
    parser.add_argument("--max-iters", type=int, default=int(os.environ.get("AGENT_MAX_ITERS", "3")))
    parser.add_argument(
        "--mode",
        choices=["agent", "repl", "source_scan", "reachability", "version_identify"],
        default="repl",
    )
    parser.add_argument(
        "--decompiled-path",
        default=None,
        help="Ghidra 反编译 C 文件路径（version_identify 模式必填）",
    )
    parser.add_argument(
        "--candidate-paths",
        default=None,
        help="候选源码 zip/目录，逗号分隔（version_identify 模式必填，至少 2 个）",
    )
    parser.add_argument("--component-name", default=None, help="可选组件名，用于版本识别报告")
    parser.add_argument("--cve-id", default=None)
    parser.add_argument("--task", default=None)
    parser.add_argument("--audit-log", default=os.environ.get("AGENT_AUDIT_LOG_PATH"))
    parser.add_argument("--local-source-path", default=os.environ.get("AGENT_LOCAL_SOURCE_PATH"))
    parser.add_argument(
        "--max-steps", type=int,
        default=int(os.environ.get("AGENT_MAX_STEPS", "120")),
        help="Planner 最大规划步数（默认 60）",
    )
    parser.add_argument(
        "--generate-cve-skills",
        action="store_true",
        default=False,
        help="从 CVE 数据库提取漏洞模式，自动生成审计 Skill 到 skills/generated/",
    )
    parser.add_argument(
        "--cwe",
        default=None,
        help="配合 --generate-cve-skills 使用，指定 CWE 列表（逗号分隔，如 CWE-120,CWE-416,CWE-78）",
    )
    args = parser.parse_args()

    # 这里先构造出运行时依赖，再把命令行配置灌入 `AgentState`，
    # 这样无论是一次性命令还是 REPL，都共享同一套执行上下文。
    joern_tool = JoernTool(joern_url=args.joern_url, project_name=args.project_name)
    db_tool = DBTool()
    graph = GraphBuilder(joern_tool, db_tool)
    planner = AgentPlannerExecutor(graph, max_steps=args.max_steps)
    state = AgentState(
        project_path=args.project,
        # 若用户没显式传本地源码路径，但 `--project` 本身在本机存在，
        # 就默认把它也当成本地源码目录，方便读取代码上下文。
        local_source_path=args.local_source_path or (args.project if os.path.exists(args.project) else None),
        project_name=args.project_name,
        language=args.language,
        variant=args.variant,
        max_iters=args.max_iters,
        audit_log_path=args.audit_log,
    )
    planner.audit_log_path = args.audit_log

    # CVE Skill 生成模式：从 DB 提取漏洞模式并生成 Skill JSON
    if args.generate_cve_skills:
        from cve_skill_generator import CVESkillGenerator
        generator = CVESkillGenerator()
        if args.cwe:
            cwe_list = [c.strip() for c in args.cwe.split(",") if c.strip()]
            print(f"正在为以下 CWE 生成 Skill: {cwe_list}")
            paths = generator.generate_skills_for_cwes(cwe_list)
        else:
            print("正在为数据库中所有 CWE 自动生成 Skill...")
            paths = generator.generate_all_available_skills()
        print(f"生成完成，共生成 {len(paths)} 个 Skill:")
        for p in paths:
            print(f"  - {p}")
        return

    if args.mode == "source_scan":
        # 一次性源码扫描模式：可直接用 --task 覆盖默认提示词。
        run_agent_task(
            state,
            planner,
            args.task or f"请对项目 `{state.project_path}` 进行源码漏洞扫描，并输出最终分析结论。",
        )
        return
    if args.mode == "version_identify":
        if not args.decompiled_path or not args.candidate_paths:
            raise ValueError("version_identify 模式需要 --decompiled-path 与 --candidate-paths")
        candidates = [p.strip() for p in args.candidate_paths.split(",") if p.strip()]
        run_agent_task(
            state,
            planner,
            args.task
            or (
                f"请对反编译文件 `{args.decompiled_path}` 与候选源码 {candidates} "
                f"执行组件版本识别（component={args.component_name or 'unknown'}），输出最接近版本及依据。"
            ),
        )
        return
    if args.mode == "reachability":
        if not args.cve_id:
            raise ValueError("reachability 模式需要 --cve-id")
        # 一次性可达分析模式：必须有 cve_id，缺失时立即报错阻断。
        run_agent_task(
            state,
            planner,
            args.task or f"请分析漏洞 `{args.cve_id}` 在当前项目中的可达性与可利用性，并输出最终结论。",
        )
        return
    if args.mode == "agent":
        # agent 模式不预设具体任务类型，完全由自然语言 task 决定后续动作。
        run_agent_task(state, planner, args.task or "请根据当前上下文完成用户任务，并给出最终结论。")
        return

    # 默认走 REPL，便于人工迭代调试。
    repl(state, graph, planner)


if __name__ == "__main__":
    main()