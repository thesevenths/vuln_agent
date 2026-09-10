"""
把 planner JSONL 审计日志渲染成更适合人工阅读的 Markdown / HTML 报告。

设计目标：
1. JSONL 保留机器可读、可追加的原始事件流
2. Markdown 便于审计、归档、PR 附件
3. HTML 便于浏览器快速回放和分享
"""

import html
import json
import os
from typing import Any, Dict, List

try:
    from joern_vuln_scanner import ANALYSIS_STAGE_NOTES, JOERN_QUERY_SOURCE_CATALOG
except ImportError:
    JOERN_QUERY_SOURCE_CATALOG = {}
    ANALYSIS_STAGE_NOTES = {}


def load_audit_events(audit_log_path: str) -> List[Dict[str, Any]]:
    """
    读取 JSONL 审计日志中的全部事件。

    Args:
        audit_log_path: JSONL 文件路径。

    Returns:
        事件字典列表。
    """
    audit_events: List[Dict[str, Any]] = []
    if not audit_log_path or not os.path.exists(audit_log_path):
        return audit_events

    with open(audit_log_path, "r", encoding="utf-8") as audit_file:
        for raw_line in audit_file:
            stripped_line = raw_line.strip()
            if not stripped_line:
                continue
            audit_events.append(json.loads(stripped_line))
    return audit_events


def _json_block(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str)


def _lookup_query_source_title(query_source: str) -> str:
    entry = JOERN_QUERY_SOURCE_CATALOG.get(query_source, {})
    return entry.get("title") or query_source


def _build_scanner_event_title(scanner_event: str, scanner_data: Dict[str, Any]) -> str:
    """
    构造 scanner 内部审计事件标题，突出 query_source 等关键字段。
    """
    parts = [f"scanner: {scanner_event}"]
    query_source = scanner_data.get("query_source")
    if query_source:
        title = scanner_data.get("query_source_title") or _lookup_query_source_title(query_source)
        parts.append(f"source={query_source}")
        if title and title != query_source:
            parts.append(title)
    vuln_type = scanner_data.get("vuln_type")
    if vuln_type:
        parts.append(f"vuln={vuln_type}")
    flow_id = scanner_data.get("flow_id")
    if flow_id:
        parts.append(f"flow={flow_id}")
    iteration = scanner_data.get("iteration")
    if iteration:
        parts.append(f"iter={iteration}")
    hop = scanner_data.get("hop")
    if hop is not None:
        parts.append(f"hop={hop}")
    method_name = scanner_data.get("method_name")
    if method_name and scanner_event.startswith("joern_query"):
        parts.append(f"method={method_name}")
    if scanner_event == "joern_query_executed":
        query_kind = scanner_data.get("query_kind")
        if query_kind:
            kind_title = scanner_data.get("query_kind_title") or query_kind
            parts.append(f"kind={query_kind}")
            if kind_title != query_kind:
                parts.append(kind_title)
        expansion_intent = scanner_data.get("expansion_intent")
        if expansion_intent:
            parts.append(f"intent={expansion_intent}")
        intent_match = scanner_data.get("expansion_intent_matches_query_kind")
        if intent_match is False:
            parts.append("intent≠query")
        ok_flag = scanner_data.get("ok")
        if ok_flag is not None:
            parts.append("ok" if ok_flag else "FAIL")
    if scanner_event == "sufficiency_check" and scanner_data.get("has_follow_up_query"):
        parts.append("has_follow_up")
    if scanner_event == "expansion_query_skipped_duplicate":
        parts.append("skipped_duplicate")
    if scanner_event == "flow_quality_skipped":
        skip_reason = scanner_data.get("skip_reason")
        filter_mode = scanner_data.get("filter_mode")
        if skip_reason:
            parts.append(f"reason={skip_reason}")
        if filter_mode:
            parts.append(f"mode={filter_mode}")
    if scanner_event == "flow_pruned_guard_cache":
        edge = scanner_data.get("matched_edge") or {}
        if edge.get("caller_full"):
            parts.append(f"edge={edge.get('caller_full')}→{edge.get('callee_full')}")
        elif scanner_data.get("cache_key"):
            parts.append(f"key={scanner_data.get('cache_key')}")
        parts.append("剪枝=guard_edge")
    if scanner_event in ("hard_backtrace_started", "hard_backtrace_completed"):
        parts.append("阶段=硬回溯")
    if scanner_event in ("llm_context_expansion_started", "llm_context_expansion_completed"):
        parts.append("阶段=LLM扩展")
    return " | ".join(parts)


def _scanner_event_meta_lines(scanner_event: str, scanner_data: Dict[str, Any]) -> List[str]:
    """为 scanner 事件生成 Markdown 元信息行（含场景区说明）。"""
    lines: List[str] = []
    stage_note = scanner_data.get("stage_note")
    if stage_note:
        lines.append(f"- **说明**: {stage_note}")
    usage = scanner_data.get("usage_scenario")
    if usage:
        lines.append(f"- **适用场景**: {usage}")
    contrasts = scanner_data.get("contrasts_with")
    if contrasts:
        lines.append(f"- **与其它查询的区别**: {contrasts}")
    if scanner_data.get("contrasts_with") is None and scanner_data.get("query_source"):
        catalog = JOERN_QUERY_SOURCE_CATALOG.get(scanner_data["query_source"], {})
        if catalog.get("contrasts_with"):
            lines.append(f"- **与其它查询的区别**: {catalog['contrasts_with']}")
        if catalog.get("usage_scenario") and not usage:
            lines.append(f"- **适用场景**: {catalog['usage_scenario']}")
    next_stage = scanner_data.get("next_stage")
    if next_stage:
        lines.append(f"- **下一阶段**: {next_stage}")
    next_query = scanner_data.get("next_query_if_insufficient")
    if next_query:
        lines.append(f"- **若仍不充分将执行**: {next_query}")
    mechanism = scanner_data.get("mechanism")
    if mechanism:
        lines.append(f"- **机制**: `{mechanism}`")
    if scanner_event == "hard_backtrace_started" and not scanner_data.get("skipped"):
        lines.append(
            f"- **阶段总述**: {ANALYSIS_STAGE_NOTES.get('hard_backtrace', '')}"
        )
    if scanner_event == "llm_context_expansion_started":
        lines.append(
            f"- **阶段总述**: {ANALYSIS_STAGE_NOTES.get('llm_context_expansion', '')}"
        )
    if scanner_event == "joern_query_executed":
        query_kind = scanner_data.get("query_kind")
        if query_kind:
            kind_title = scanner_data.get("query_kind_title") or query_kind
            lines.append(f"- **query_kind（DSL 实际语义）**: `{query_kind}` — {kind_title}")
        expansion_intent = scanner_data.get("expansion_intent")
        if expansion_intent:
            lines.append(f"- **expansion_intent（LLM 自述缺口）**: `{expansion_intent}`")
        intent_match = scanner_data.get("expansion_intent_matches_query_kind")
        if intent_match is False:
            lines.append(
                "- **注意**: expansion_intent 与 query_kind 不一致（例如 intent=trace_upstream 但 DSL 为 view_body）"
            )
    return lines


def _build_markdown_report(audit_events: List[Dict[str, Any]]) -> str:
    if not audit_events:
        return "# Planner 审计回放报告\n\n未找到可渲染的审计事件。\n"

    first_event = audit_events[0]
    last_event = audit_events[-1]
    lines = [
        "# Planner 审计回放报告",
        "",
        f"- **run_id**: `{first_event.get('run_id', 'unknown')}`",
        f"- **开始时间**: `{first_event.get('timestamp', 'unknown')}`",
        f"- **结束时间**: `{last_event.get('timestamp', 'unknown')}`",
        f"- **用户请求**: {first_event.get('user_request', 'unknown')}",
        "",
        "## 事件回放",
        "",
        "### 证据层级 L1 / L2 / L3（非召回率 Recall）",
        "",
        "- **L1 代码流**：Joern 污点 + 硬回溯 + 扩展查询 → `queries_py_*` / `hard_backtrace_*` / `llm_*`",
        "- **L2 静态补证**：FileTool 读 pom/yml/Security 等 → planner 的 `file_evidence_reads`",
        "- **L3 动态/业务**：默认未测 → 报告里 `not_verified`；详见 `evidence_levels.py`",
        "",
        "### Scanner：硬回溯 vs LLM 扩展（读日志用）",
        "",
        "- **硬回溯（L1）**：`hard_backtrace_*` + `query_source=hard_backtrace_caller_*`",
        "- **LLM 扩展（L1）**：`llm_context_expansion_*` + `sufficiency_check` + `llm_follow_up_*`",
        "- **预置扫描（L1）**：`queries_py_*`（全项目污点 flow）",
        "- **L2 补证**：planner `FileTool` → `file_evidence_reads`",
        "",
    ]

    for event in audit_events:
        event_type = event.get("event_type", "unknown")
        step_value = event.get("step")
        based_on_step = event.get("based_on_step")
        if event_type == "plan_updated":
            title = f"plan_updated (step {step_value}, 基于 step {based_on_step})"
        elif event_type == "plan_initialized":
            title = f"plan_initialized (step {step_value})"
        elif event_type == "scanner_internal_audit":
            scanner_event = event.get("scanner_event", "unknown")
            scanner_data = event.get("scanner_data", {}) or {}
            title = _build_scanner_event_title(scanner_event, scanner_data)
        else:
            title = event_type
        lines.append(f"### {title}")
        lines.append("")
        lines.append(f"- **timestamp**: `{event.get('timestamp', 'unknown')}`")
        if step_value is not None:
            lines.append(f"- **step**: `{step_value}`")
        if based_on_step is not None:
            lines.append(f"- **based_on_step**: `{based_on_step}`")
        if event.get("finish_reason"):
            lines.append(f"- **finish_reason**: `{event.get('finish_reason')}`")
        replan_reason = event.get("replan_reason") or {}
        if replan_reason:
            lines.append(f"- **reason_type**: `{replan_reason.get('reason_type', 'unknown')}`")
            if replan_reason.get("reason_text"):
                lines.append(f"- **reason_text**: {replan_reason['reason_text']}")
            if replan_reason.get("previous_step") is not None:
                lines.append(f"- **previous_step**: `{replan_reason['previous_step']}`")
            if replan_reason.get("previous_plan_summary"):
                lines.append(f"- **previous_plan_summary**: {replan_reason['previous_plan_summary']}")
            if replan_reason.get("previous_tool_name"):
                lines.append(f"- **previous_tool_name**: `{replan_reason['previous_tool_name']}`")
            if replan_reason.get("previous_result_summary"):
                lines.append(f"- **previous_result_summary**: {replan_reason['previous_result_summary']}")
        if event_type == "scanner_internal_audit":
            scanner_data = event.get("scanner_data", {}) or {}
            lines.extend(_scanner_event_meta_lines(event.get("scanner_event", ""), scanner_data))
        lines.append("")
        lines.append("```json")
        lines.append(_json_block(event))
        lines.append("```")
        lines.append("")

    return "\n".join(lines)


def _build_html_report(audit_events: List[Dict[str, Any]]) -> str:
    if not audit_events:
        return (
            "<html><head><meta charset='utf-8'><title>Planner 审计回放</title></head>"
            "<body><h1>Planner 审计回放报告</h1><p>未找到可渲染的审计事件。</p></body></html>"
        )

    first_event = audit_events[0]
    last_event = audit_events[-1]

    sections: List[str] = []
    for event in audit_events:
        raw_event_type = str(event.get("event_type", "unknown"))
        step_value = event.get("step")
        based_on_step = event.get("based_on_step")
        if raw_event_type == "plan_updated":
            event_title = f"plan_updated (step {step_value}, 基于 step {based_on_step})"
        elif raw_event_type == "plan_initialized":
            event_title = f"plan_initialized (step {step_value})"
        elif raw_event_type == "scanner_internal_audit":
            scanner_event = event.get("scanner_event", "unknown")
            scanner_data = event.get("scanner_data", {}) or {}
            event_title = _build_scanner_event_title(scanner_event, scanner_data)
        else:
            event_title = raw_event_type
        event_type = html.escape(event_title)
        timestamp = html.escape(str(event.get("timestamp", "unknown")))
        finish_reason = event.get("finish_reason")
        replan_reason = event.get("replan_reason") or {}
        pretty_event = html.escape(_json_block(event))

        meta_lines = [f"<li><strong>timestamp</strong>: <code>{timestamp}</code></li>"]
        if step_value is not None:
            meta_lines.append(f"<li><strong>step</strong>: <code>{html.escape(str(step_value))}</code></li>")
        if based_on_step is not None:
            meta_lines.append(
                f"<li><strong>based_on_step</strong>: <code>{html.escape(str(based_on_step))}</code></li>"
            )
        if finish_reason:
            meta_lines.append(
                f"<li><strong>finish_reason</strong>: <code>{html.escape(str(finish_reason))}</code></li>"
            )
        if replan_reason:
            meta_lines.append(
                f"<li><strong>reason_type</strong>: "
                f"<code>{html.escape(str(replan_reason.get('reason_type', 'unknown')))}</code></li>"
            )
            if replan_reason.get("reason_text"):
                meta_lines.append(
                    f"<li><strong>reason_text</strong>: {html.escape(str(replan_reason['reason_text']))}</li>"
                )
            if replan_reason.get("previous_step") is not None:
                meta_lines.append(
                    f"<li><strong>previous_step</strong>: "
                    f"<code>{html.escape(str(replan_reason['previous_step']))}</code></li>"
                )
            if replan_reason.get("previous_plan_summary"):
                meta_lines.append(
                    f"<li><strong>previous_plan_summary</strong>: "
                    f"{html.escape(str(replan_reason['previous_plan_summary']))}</li>"
                )
            if replan_reason.get("previous_tool_name"):
                meta_lines.append(
                    f"<li><strong>previous_tool_name</strong>: "
                    f"<code>{html.escape(str(replan_reason['previous_tool_name']))}</code></li>"
                )
            if replan_reason.get("previous_result_summary"):
                meta_lines.append(
                    f"<li><strong>previous_result_summary</strong>: "
                    f"{html.escape(str(replan_reason['previous_result_summary']))}</li>"
                )
        if raw_event_type == "scanner_internal_audit":
            scanner_data = event.get("scanner_data", {}) or {}
            for meta_line in _scanner_event_meta_lines(event.get("scanner_event", ""), scanner_data):
                label, _, value = meta_line.partition(": ")
                if label.startswith("- **") and "**:" in label:
                    field = label[4 : label.index("**:")]
                    meta_lines.append(
                        f"<li><strong>{html.escape(field)}</strong>: {html.escape(value)}</li>"
                    )

        sections.append(
            "<section class='event'>"
            f"<h2>{event_type}</h2>"
            f"<ul>{''.join(meta_lines)}</ul>"
            f"<pre>{pretty_event}</pre>"
            "</section>"
        )

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <title>Planner 审计回放报告</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      margin: 24px;
      line-height: 1.5;
      color: #1f2328;
      background: #ffffff;
    }}
    h1, h2 {{
      margin-bottom: 12px;
    }}
    .summary {{
      background: #f6f8fa;
      border: 1px solid #d0d7de;
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 24px;
    }}
    .event {{
      border: 1px solid #d0d7de;
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 16px;
    }}
    pre {{
      white-space: pre-wrap;
      word-break: break-word;
      background: #0d1117;
      color: #e6edf3;
      padding: 16px;
      border-radius: 8px;
      overflow: auto;
    }}
    code {{
      background: #f6f8fa;
      padding: 2px 4px;
      border-radius: 4px;
    }}
  </style>
</head>
<body>
  <h1>Planner 审计回放报告</h1>
  <div class="summary">
    <ul>
      <li><strong>run_id</strong>: <code>{html.escape(str(first_event.get("run_id", "unknown")))}</code></li>
      <li><strong>开始时间</strong>: <code>{html.escape(str(first_event.get("timestamp", "unknown")))}</code></li>
      <li><strong>结束时间</strong>: <code>{html.escape(str(last_event.get("timestamp", "unknown")))}</code></li>
      <li><strong>用户请求</strong>: {html.escape(str(first_event.get("user_request", "unknown")))}</li>
    </ul>
    <p><strong>证据层级 L1/L2/L3</strong>（非 ML 召回率）：L1=Joern 代码流；L2=FileTool 配置/依赖；L3=动态/业务（默认待验证）。见 <code>evidence_levels.py</code>。</p>
    <p><strong>Scanner 日志怎么读</strong></p>
    <ul>
      <li><strong>硬回溯（L1）</strong>：<code>hard_backtrace_*</code> + <code>query_source=hard_backtrace_caller_*</code></li>
      <li><strong>LLM 扩展（L1）</strong>：<code>llm_context_expansion_*</code>、<code>sufficiency_check</code> + <code>llm_follow_up_*</code></li>
      <li><strong>预置扫描（L1）</strong>：<code>queries_py_*</code></li>
      <li><strong>L2 补证</strong>：planner <code>FileTool.read_file</code>，看 <code>file_evidence_reads</code></li>
    </ul>
  </div>
  {''.join(sections)}
</body>
</html>
"""


def render_audit_reports(audit_log_path: str) -> Dict[str, str]:
    """
    从 JSONL 审计日志生成 Markdown 和 HTML 报告。

    Args:
        audit_log_path: JSONL 文件路径。

    Returns:
        包含 `markdown_report_path` 和 `html_report_path` 的字典。

        输出路径规则：
        - 输入: `planner_audit_20260528_113000.jsonl`
        - 输出: `planner_audit_20260528_113000.md`
        - 输出: `planner_audit_20260528_113000.html`
    """
    audit_events = load_audit_events(audit_log_path)
    report_base_path, _ = os.path.splitext(audit_log_path)
    markdown_report_path = report_base_path + ".md"
    html_report_path = report_base_path + ".html"

    markdown_report = _build_markdown_report(audit_events)
    html_report = _build_html_report(audit_events)

    with open(markdown_report_path, "w", encoding="utf-8") as markdown_file:
        markdown_file.write(markdown_report)

    with open(html_report_path, "w", encoding="utf-8") as html_file:
        html_file.write(html_report)

    return {
        "markdown_report_path": markdown_report_path,
        "html_report_path": html_report_path,
    }
