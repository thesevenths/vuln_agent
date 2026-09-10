"""
证据层级 L1 / L2 / L3 的统一定义与状态枚举。

注意：这里的 L1/L2/L3 指 **判定一条漏洞结论时所用的证据深度分层**，
不是机器学习里的「召回率 Recall」，也不是 Joern 的 query_source 分类。

设计目的
--------
静态扫描 Agent 很难在一次运行里凑齐「可远程利用」的全部事实。
因此把证据分成三层，报告与反证 JSON 必须标明每一层是 **已掌握 / 部分 / 缺失**
（L3 另用 **已验证 / 待动态验证 / 不适用**），避免只有 Joern flow 就写成 confirmed。

三层划分（记法）
----------------

**L1 — 代码流（Joern / 图分析）**
    回答：从 Source 到 Sink 的 **数据流是否在代码里成立**？

    典型内容：
    - queries.py 预置污点查询产出的 reachableByFlows / 表格
    - 硬回溯拉取的 caller 方法体（dumpRaw）
    - LLM 扩展阶段补充的 Joern 查询结果（follow_up_query / 模板扩展）注入的代码片段
    - 从 Joern 输出解析出的 sink 行、方法签名

    主要来源模块：joern_vuln_scanner（含硬回溯、迭代扩展）
    工具：JoernTool.*；不经过 FileTool 读盘（路径映射除外）

    状态：present | partial | absent
    - present：有清晰 flow 或等价的多段代码链
    - partial：仅有 sink 片段或回溯未完成
    - absent：无有效 Joern 输出

**L2 — 静态补证（配置 / 依赖 / 跨文件源码）**
    回答：**编译期、配置期、依赖版本** 是否阻断或削弱利用？

    典型内容：
    - pom.xml / build.gradle / CMakeLists.txt
    - application*.yml、SecurityConfig、web.xml、Shiro/Spring 安全配置
    - 反序列化白名单、XXE 安全特性、路径 normalize 工具类（需读源码文件）
    - SCA：组件版本是否在 CVE 影响范围（可达性报告）

    主要来源：Planner 的 FileTool.read_file / glob_files；人工提供的配置
    Joern 污点 **不算** L2（算 L1）；读 .c/.java 源码片段算 L2（跨文件实现/配置）

    状态：present | partial | absent
    - absent 时：反证规则要求不得 verdict=confirmed（鉴权/反序列化/路径穿越等）

**L3 — 动态 / 业务（运行态与产品语义）**
    回答：**真实环境** 里能否利用？业务规则是否允许？

    典型内容：
    - 是否需登录、BOLA/越权、网关/WAF、仅内网可达
    - HTTP/DAST 复现、并发竞态、实际生效的配置（非源码能看全的）
    - 产品规则：「已支付订单不可取消」等

    当前 Agent 默认 **不自动执行** L3；报告中应标 not_verified 或 not_applicable
    不得在仅有 L1+L2 时写「已证实远程可利用」

    状态：verified | not_verified | not_applicable

与流水线阶段的对应关系
----------------------

    阶段                          | 主要累积证据层
    ------------------------------|----------------------------------
    run_taint_queries (queries.py) | L1（发现候选 flow）
    硬回溯 hard_backtrace          | L1（caller 体、guard 线索）
    LLM 扩展 Joern 查询            | L1（补方法体/变量/过滤逻辑）
    主分析 LLM 报告                | 叙述 L1，并应填写 L2/L3 表
    Planner FileTool 补证          | L2
    反证 refutation JSON           | 汇总 L1_joern / L2_static_files / L3_dynamic
    （未来 DAST/API 测试）         | L3 → verified

反证 JSON 字段映射
------------------
    evidence_levels.L1_joern        ↔ 上表 L1
    evidence_levels.L2_static_files ↔ 上表 L2
    evidence_levels.L3_dynamic      ↔ 上表 L3
    missing_L2_reads                ↔ 建议 Planner 下一步 FileTool 路径

报告 Markdown 中的「证据层级」表与上述三层一致，见 prompts.user_prompt_template。
"""

from typing import Dict, List, TypedDict


class EvidenceLevelSpec(TypedDict):
    id: str
    name: str
    question: str
    typical_sources: List[str]
    collection_in_code: List[str]
    status_values: List[str]


EVIDENCE_LEVEL_SPECS: List[EvidenceLevelSpec] = [
    {
        "id": "L1",
        "name": "代码流（Joern）",
        "question": "污点/Source→Sink 数据流是否在代码中成立？",
        "typical_sources": [
            "queries.py 预置污点查询",
            "硬回溯 caller 链（dumpRaw）",
            "LLM 扩展 Joern 查询结果",
        ],
        "collection_in_code": [
            "JoernVulnScanner.run_taint_queries",
            "JoernVulnScanner._run_hard_backtrace",
            "JoernVulnScanner._analyze_single_taint_flow 迭代扩展",
        ],
        "status_values": ["present", "partial", "absent"],
    },
    {
        "id": "L2",
        "name": "静态补证（配置/依赖/跨文件）",
        "question": "依赖版本、安全配置、跨文件实现是否阻断利用？",
        "typical_sources": [
            "FileTool.read_file / glob_files",
            "SCA 可达性 DB 上下文",
            "pom/yml/Security 配置与相关源码",
        ],
        "collection_in_code": [
            "planner AgentPlannerExecutor FileTool 动作",
            "prompts.planner_filetool_checklist_by_vuln_type",
        ],
        "status_values": ["present", "partial", "absent"],
    },
    {
        "id": "L3",
        "name": "动态/业务",
        "question": "运行时是否可利用？业务规则是否允许？",
        "typical_sources": [
            "HTTP/API 渗透测试（未默认接入）",
            "人工业务确认",
        ],
        "collection_in_code": [
            "当前仅由 LLM 在报告中标注 not_verified",
            "禁止无 L3 验证时写 confirmed 远程利用",
        ],
        "status_values": ["verified", "not_verified", "not_applicable"],
    },
]

# Planner state_snapshot、简短提示用
EVIDENCE_GOALS_ONE_LINER = (
    "L1=Joern代码流(污点+硬回溯+扩展); "
    "L2=FileTool配置/依赖/跨文件; "
    "L3=动态/业务(默认待验证)"
)

# 写入 Markdown 报告头部的图例（joern_vuln_scanner 全量报告、SCA 报告可复用）
REPORT_EVIDENCE_LEVEL_LEGEND = """
> **证据层级说明**（非「召回率」，而是结论依据的深度）：
> **L1**=Joern 污点流/硬回溯/扩展查询得到的**代码流**证据；
> **L2**=config.h/CMakeLists/pom/yml/Security 等**静态文件**补证（FileTool）；
> **L3**=HTTP/鉴权/业务规则等**运行态**验证（本扫描默认未做则标「待动态验证」）。
"""

# 反证 LLM 输出的 evidence_levels 键说明（写入 refutation prompt 时可引用）
REFUTATION_EVIDENCE_LEVEL_KEYS = {
    "L1_joern": "L1 代码流：Joern flow、回溯与扩展注入的代码上下文",
    "L2_static_files": "L2 静态补证：配置文件、依赖版本、跨文件 Security/工具类",
    "L3_dynamic": "L3 动态/业务：verified=已实测；not_verified=未测；not_applicable=该类不适用动态验证",
}


def format_evidence_levels_for_prompt() -> str:
    """生成可嵌入 system/user prompt 的三层说明（纯文本列表）。"""
    lines = ["### 证据层级 L1/L2/L3（必填，与流水线对应）", ""]
    for spec in EVIDENCE_LEVEL_SPECS:
        lines.append(f"**{spec['id']} {spec['name']}** — {spec['question']}")
        lines.append(f"- 典型来源：{'; '.join(spec['typical_sources'])}")
        lines.append(f"- 代码路径：{'; '.join(spec['collection_in_code'])}")
        lines.append(f"- 状态取值：{', '.join(spec['status_values'])}")
        lines.append("")
    lines.append("反证 JSON 字段：`L1_joern` / `L2_static_files` / `L3_dynamic` 对应上表三层。")
    return "\n".join(lines)
