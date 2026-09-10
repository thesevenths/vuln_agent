"""
`chains.py` 存放偏“分析链路”的纯函数。

这里的函数不负责直接连数据库，也不负责直接调 Joern，
而是负责把已有数据整理成：
- 简单摘要
- 可直接送给 LLM 的 prompt 输入
"""

import config  # noqa: F401

import json
from typing import Any, Dict, Optional

import prompts
from llm_client import LLMClient, get_default_llm_client
from tool_capabilities import TOOL_CAPABILITIES


def triage_flows(flows: Dict[str, Any]) -> str:
    """
    对原始 flow 结果做一个轻量级摘要。

    Args:
        flows: `vuln_type -> Joern 原始输出` 的映射。

    Returns:
        一段人类可读的摘要文本，用于快速判断哪些查询“像是命中了”。
    """
    if not flows:
        return "No flows"

    # 这是“快速分诊”而不是“最终判定”：
    # 目的是先告诉你哪些查询值得优先细看。
    summary_lines = []
    for flow_name, flow_text in flows.items():
        if not isinstance(flow_text, str):
            continue
        # 这里用非常保守的启发式规则判断“像不像有效命中”：
        # 只要文本长度足够且没有明显报错，就先记为 possible evidence。
        is_valid = len(flow_text.strip()) > 100 and "Error:" not in flow_text
        if is_valid:
            summary_lines.append(f"- {flow_name}: possible evidence ({len(flow_text)} chars)")
        else:
            summary_lines.append(f"- {flow_name}: no strong evidence")

    if not summary_lines:
        return "No flows"
    return "\n".join(summary_lines)


def make_reachability_report(
    *,
    reachability_context: Dict[str, Any],
    llm_client: Optional[LLMClient] = None,
) -> str:
    """
    生成漏洞可达分析报告。

    Args:
        reachability_context: 已标准化的漏洞信息和调用链上下文。
        llm_client: 可选的 LLM 客户端；不传则自动初始化默认客户端。

    Returns:
        LLM 输出的 Markdown 报告文本。
    """
    # 支持依赖注入（传入 llm_client）是为了测试和多模型切换更方便。
    effective_llm_client = llm_client or get_default_llm_client()
    # 先把结构化数据序列化成带缩进 JSON，方便模型同时看到字段名和层级结构。
    vuln_info_text = json.dumps(reachability_context.get("vuln_info", {}), ensure_ascii=False, indent=2)
    call_chain_text = json.dumps(reachability_context.get("call_chains", []), ensure_ascii=False, indent=2)
    prompt_text = prompts.reachability_user_prompt_template.format(
        vuln_info=vuln_info_text,
        call_chains=call_chain_text,
    )
    # 可达分析场景强调稳定、证据一致性，temperature 设为 0 减少随机发挥。
    return effective_llm_client.complete(
        system_prompt=prompts.inject_tool_capabilities(
            prompts.reachability_system_prompt,
            TOOL_CAPABILITIES,
        ),
        user_prompt=prompt_text,
        temperature=0.0,
        max_tokens=4500,
    )