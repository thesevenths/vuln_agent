"""
集中维护 agent 可用工具的“机器可读能力说明”。

这个模块的目标是把工具语义从业务代码中解耦出来：
1. 避免 `prompts.py` 和 `tools.py` 相互导入导致循环依赖
2. 让 system prompt 能稳定注入统一工具说明
3. 未来若接 function-calling，也可复用同一份描述
"""

from typing import Any, Dict

from logic_scan_settings import DEFAULT_MAX_CANDIDATES


TOOL_CAPABILITIES: Dict[str, Dict[str, Any]] = {
    "set_context": {
        "purpose": "更新当前分析上下文，例如项目路径、语言、variant、迭代轮数",
        "input": {
            "project_path": "可选的 Joern 服务端源码路径",
            "local_source_path": "可选的本地源码路径，用于读取代码片段",
            "project_name": "可选项目名",
            "cve_id": "可选漏洞编号",
            "language": "java/cpp",
            "variant": "generic/embedded/vendor",
            "max_iters": "最大迭代轮数",
        },
        "output": {"state": "更新后的运行状态快照"},
        "when_to_use": "任务缺少必要上下文时优先调用",
    },
    "JoernTool.ensure_cpg": {
        "purpose": "确保目标源码工程的 CPG 已创建并可查询",
        "input": {
            "source_root": "Joern 服务端源码路径",
            "project_name": "可选项目名",
            "local_source_path": "可选本地源码路径",
        },
        "output": {"ok": "bool，是否成功"},
        "when_to_use": "准备开始任何 Joern 查询前调用",
    },
    "JoernTool.run_taint_queries": {
        "purpose": "只跑污点查询，不做 LLM 迭代",
        "input": {"language": "java/c/cpp", "variant": "generic/embedded/vendor"},
        "output": {"flows": "dict，漏洞类型 -> Joern 原始输出"},
        "when_to_use": "想快速看原始命中结果或调试 DSL",
    },
    "JoernTool.run_source_scan": {
        "purpose": "执行完整源码扫描（含 LLM 迭代分析）",
        "input": {
            "source_root": "Joern 服务端源码路径",
            "local_source_path": "可选本地源码路径",
            "language": "java/c/cpp",
            "variant": "查询变体",
            "max_iters": "最大补上下文轮数",
            "project_name": "可选项目名",
        },
        "output": {"result": "dict，含 ok/flows/report"},
        "when_to_use": "要得到最终可读漏洞报告时",
    },
    "JoernTool.run_targeted_scan": {
        "purpose": "对指定漏洞类型执行定向源码扫描（Joern 查询 + LLM 迭代分析/反证，非 raw taint）",
        "input": {
            "vuln_types": "必填，漏洞类型列表，如 ['cpp_buffer_overflow', 'cpp_use_after_free']",
            "language": "java/c/cpp",
            "variant": "查询变体",
            "source_root": "可选 Joern 服务端源码路径",
            "local_source_path": "可选本地源码路径",
            "max_iters": "LLM 补上下文轮数",
        },
        "output": {
            "flows": "dict，指定类型的 flow 数据",
            "report": "含 LLM 分析的报告",
            "ambiguous_flows": "仍模糊的 flow",
            "pending_l2_reads_raw": "L2 必读建议",
        },
        "when_to_use": "L2 已补齐或 ambiguous 已清空后，专家 Skill 深挖单一漏洞类型",
    },
    "JoernTool.run_logic_scan": {
        "purpose": "逻辑漏洞扫描：枚举端点/鉴权守卫/敏感操作，交叉分析缺失鉴权、IDOR、硬编码凭证等",
        "input": {
            "source_root": "可选 Joern 服务端源码路径",
            "local_source_path": "可选本地源码路径",
            "language": "目标语言，默认 java",
            "cwe_focus": "可选 CWE 编号列表（不传则默认覆盖全部 24 个 CWE 类型，包括 862/306/639/798/89/79 等）",
            "max_candidates": f"最大候选分析数，默认 {DEFAULT_MAX_CANDIDATES}（见 logic_scan_settings / LOGIC_SCAN_MAX_CANDIDATES）",
        },
        "output": {
            "report": "逻辑漏洞分析报告",
            "logic_candidates": "所有候选漏洞列表",
            "flow_findings_index": "确认的漏洞发现",
        },
        "when_to_use": "用户要求逻辑漏洞审计、Web 应用安全审计、授权/鉴权检查时使用。不同于 run_source_scan（污点流），本工具通过端点枚举+交叉分析发现逻辑缺陷",
    },
    "JoernTool.expand_flow_context": {
        "purpose": "对单条 inconclusive flow 再跑 1～2 轮 Joern LLM 上下文扩展（不触发全量扫描/反证）",
        "input": {
            "flow_id": "必填，目标 flow",
            "vuln_type": "漏洞类型（可从 flow_catalog 推断）",
            "max_extra_iters": "扩展轮数，默认 2",
            "source_root": "Joern 服务端源码路径",
            "local_source_path": "可选本地源码路径",
        },
        "output": {
            "ok": "bool",
            "exhausted": "扩展是否已用尽",
            "sufficient": "上下文是否已充分",
            "l1_covered_ranges": "本次扩展新增的 L1 行段",
        },
        "when_to_use": "L2 仍 inconclusive 且需读源文件定点行段前；配置/头文件不受此门禁",
    },
    "GraphBuilder.run_source_scan": {
        "purpose": "统一编排源码扫描并附带 triage 结果",
        "input": {
            "project_path": "Joern 服务端源码路径",
            "local_source_path": "可选本地源码路径",
            "language": "java/c/cpp",
            "variant": "查询变体",
            "max_iters": "最大补上下文轮数",
            "project_name": "可选项目名",
        },
        "output": {"result": "dict，含 ok/flows/triage/report"},
        "when_to_use": "需要编排后的完整扫描结果时",
    },
    "DBTool.get_call_chains": {
        "purpose": "读取指定 CVE 的调用链",
        "input": {"cve_id": "漏洞编号"},
        "output": {"rows": "数据库原始记录"},
        "when_to_use": "只需要调用链原始数据时",
    },
    "DBTool.get_vuln_info": {
        "purpose": "读取指定 CVE 对应漏洞函数基础信息",
        "input": {"cve_id": "漏洞编号"},
        "output": {"rows": "数据库原始记录"},
        "when_to_use": "只需要函数元信息时",
    },
    "DBTool.get_reachability_context": {
        "purpose": "读取并标准化可达性分析上下文",
        "input": {"cve_id": "漏洞编号"},
        "output": {"context": "dict，含 cve_id/call_chains/vuln_info"},
        "when_to_use": "要给 LLM 做可达分析时",
    },
    # TODO: CVE 知识库 DB 就绪后取消注释
    # "DBTool.query_cve_by_cwe": {
    #     "purpose": "按 CWE 分类查询 CVE 列表，返回结构化漏洞数据",
    #     "input": {
    #         "cwe_id": "CWE 编号，如 'CWE-120' 或 '120'",
    #         "limit": "可选，最大返回数量（默认 20）",
    #     },
    #     "output": {"cve_list": "CVE 信息列表", "cwe_id": "查询的 CWE"},
    #     "when_to_use": "需要查询同类漏洞的已知 CVE 案例时，用于模式匹配和参考",
    # },
    # "DBTool.get_cve_patterns": {
    #     "purpose": "获取组件或 CWE 的漏洞模式摘要（高频 sink、组件、CVE 数量）",
    #     "input": {
    #         "component": "可选组件名，如 'mbedtls'、'spring'",
    #         "cwe_id": "可选 CWE 编号，如 'CWE-120'",
    #     },
    #     "output": {"patterns": "dict，含 common_sinks/common_components/cve_count"},
    #     "when_to_use": "想了解某组件或某 CWE 的历史漏洞模式，指导当前分析方向时",
    # },
    "GraphBuilder.run_reachability": {
        "purpose": "执行可达分析完整流程并生成最终报告",
        "input": {"cve_id": "漏洞编号"},
        "output": {"result": "dict，含 reachability_context/report"},
        "when_to_use": "用户明确需要漏洞可达与可利用结论时",
    },
    "FileTool.read_file": {
        "purpose": "读取本机授权目录下的文本文件，用于补齐 L2 静态证据（pom/yml/Security/源码片段），跨 Windows/Linux",
        "input": {
            "path": "文件绝对或相对路径（须在 local_source_path / AGENT_FILE_READ_ROOTS 下）",
            "start_line": "可选，起始行号（从 1 开始）",
            "end_line": "可选，结束行号",
            "max_bytes": "可选，读取字节上限",
        },
        "output": {"content": "带行号文本", "path": "解析后的绝对路径"},
        "when_to_use": "Joern 命中后按 vuln_type 补证清单精读配置或嫌疑源码；SCA/可达分析补依赖版本时",
    },
    "FileTool.glob_files": {
        "purpose": "在授权根目录下按 glob 搜索文件（如 **/pom.xml）",
        "input": {"pattern": "glob 模式", "root": "可选搜索根", "limit": "最大命中数"},
        "output": {"matches": "文件路径列表"},
        "when_to_use": "不知道配置文件确切路径时",
    },
    "VersionTool.identify_component": {
        "purpose": "比对 Ghidra 反编译 C 与多个候选官方源码版本（zip 或目录），推断最接近的组件发布版本",
        "input": {
            "decompiled_path": "必填，*_decompiled.c 或包含该文件的目录",
            "candidate_paths": "必填，至少 2 个候选 zip/源码目录路径的列表",
            "component_name": "可选组件名，如 mbedtls、openssl",
        },
        "output": {
            "best_matches": "最佳匹配列表（含 version、confidence、source_root）",
            "excluded_versions": "被排除的候选及原因",
            "indistinguishable_groups": "不可区分的版本组",
            "report_markdown": "完整 Markdown 分析报告",
            "matched_source_root": "唯一匹配时的源码根目录（可设为 local_source_path）",
        },
        "when_to_use": "用户提供 .so 反编译结果 + 多个候选源码包，需要确认组件版本后再做漏洞/调用链分析时",
    },
    "GraphBuilder.run_version_identification": {
        "purpose": "与 VersionTool.identify_component 相同，经 GraphBuilder 编排并写回 state",
        "input": {
            "decompiled_path": "必填",
            "candidate_paths": "必填列表",
            "component_name": "可选",
        },
        "output": {"result": "版本识别结果字典"},
        "when_to_use": "与 VersionTool.identify_component 相同",
    },
    "FileTool.write_report": {
        "purpose": "将 Markdown 漏洞/可达分析报告写入 agent_reports 目录",
        "input": {
            "content": "报告正文；可省略则使用 state.last_report",
            "filename": "可选文件名",
            "subdir": "可选子目录，如 source_scan / reachability",
        },
        "output": {"path": "写入后的绝对路径"},
        "when_to_use": "需要把最终结论落盘为 .md 文件时",
    },
    "finish": {
        "purpose": "结束当前 agent 循环并输出最终回答",
        "input": {},
        "output": {"final_answer": "最终回答"},
        "when_to_use": "已有证据足够回答用户问题时",
    },
    "JavaAuditTool.scan_routes": {
        "purpose": "静态扫描 Java Web 路由（Spring/JAX-RS 注解），产出攻击面索引",
        "input": {"project_path": "可选，默认 state.local_source_path 或 project_path"},
        "output": {"routes": "路由列表", "java_routes_markdown": "写入 state.metadata"},
        "when_to_use": "Java 代码审计的第一步，梳理 HTTP 入口后再做 Joern/调用链分析",
    },
    "JavaAuditTool.load_playbook": {
        "purpose": "加载 RuoJi6/java-audit-skills 的 SKILL.md 作战手册到上下文",
        "input": {"playbook_id": "如 java-route-mapper、java-sql-audit、java-auth-audit"},
        "output": {"text": "手册正文（可能截断）"},
        "when_to_use": "需要按 java-audit-skills 方法论做路由/鉴权/SQL/XXE 专项审计时",
    },
    "JavaAuditTool.list_playbooks": {
        "purpose": "列出已安装的 java-audit-skills playbook",
        "input": {},
        "output": {"playbooks": "可用手册列表"},
        "when_to_use": "检查 JAVA_AUDIT_SKILLS_PATH 是否配置正确",
    },
    "Skill.run": {
        "purpose": "执行预定义技能，将技能卡映射为下一步具体工具动作",
        "input": {
            "skill_id": "必填，技能标识，如 source_0day_pipeline / reachability_exploitability",
            "skill_ids": "可选，多个技能协同执行队列",
            "tool_name": "可选，指定该技能下要执行的具体工具",
            "tool_arguments": "可选，具体工具参数",
        },
        "output": {
            "resolved_action": "技能解析后的真实工具动作",
            "skill_metadata": "技能摘要、推荐动作、完成提示",
        },
        "when_to_use": "任务符合某个成熟作业流程，希望稳定复用专家步骤时",
    },
}
