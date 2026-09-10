#!/usr/bin/env python3
"""从 docs/客户展示-PPT讲稿.md 结构生成客户展示 PPTX。"""

from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.util import Inches, Pt

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_CN = ROOT / "docs" / "客户展示-智能漏洞挖掘Agent.pptx"
OUTPUT_EN = ROOT / "docs" / "customer-presentation-guardfox-agent.pptx"

# (title, bullets[], speaker_note optional)
SLIDES = [
    (
        "智能漏洞挖掘 Agent",
        [
            "从「告警海洋」到「可行动的真风险」",
            "代码级证据链 + 专家流程 + 可审计 AI",
            "把「可能有问题」变成「值得修的真实问题」",
        ],
        "我们不是再卖一份扫描报告，而是帮您在发版前，用更少误报、更强证据，找到真正该修的安全问题。",
    ),
    (
        "您关心的不是「扫了多少条」，而是「找没找到真的」",
        [
            "误报太多 — 安全疲于「狼来了」，研发不愿配合",
            "漏报更可怕 — 真洞藏在复杂调用链里",
            "结论不可信 — 高危却说不清怎么利用",
            "专家不够用 — 无法每个版本都深度审",
            "难以交代 — 领导、合规追问如何确认",
        ],
        "贵司要的不是又多 500 条告警，而是多找出几条真洞，少浪费几百人天。",
    ),
    (
        "我们帮您做到的三件事",
        [
            "找真的 — 攻击路径线索 + 反证审查压误报",
            "说得清 — 每条结论带证据等级",
            "可追溯 — 全程留痕，方便汇报与审计",
        ],
        "把安全分析从「感觉像漏洞」升级到「有证据链支撑的研判」。",
    ),
    (
        "我们不是再多一种扫描器",
        [
            "传统扫描器 → 模式匹配多，「像漏洞」就多",
            "纯聊天式 AI → 会说，难证明，易「编故事」",
            "纯人工审计 → 准，但慢、贵、难规模化",
            "我们：深度扫描 + 专家方法论 + AI 推理与复核",
        ],
        "不是取代专家，而是把专家最值钱的判断流程，变成可重复运行的系统。",
    ),
    (
        "核心技术：深度图谱 · 反证降噪 · 分级结论",
        [
            "① 代码「地图」级分析（CPG）— 数据从哪进、流到哪些危险操作",
            "② 双引擎：发现 + 反驳 — 宁可多查一步，也不轻易吓您一跳",
            "③ 证据分层：代码层 / 环境层 / 运行层（如实标注）",
        ],
        "对您来说：更真、更稳、更好交代。",
    ),
    (
        "一个中枢，多套专家流程，多种证据来源",
        [
            "您的任务（审项目 / CVE / 版本）",
            "    ↓ 智能编排中枢（分步执行、根据结果调整）",
            "    ↓ 专家技能库（0day · Web · 可达性 · 版本对齐）",
            "    ↓ 深度分析引擎 + 文件与数据库证据",
            "    ↓ 分级报告 + 全程审计记录",
        ],
        "您用自然语言说目标；背后是资深顾问 SOP 在自动跑。",
    ),
    (
        "优点一：找真洞，不是撒告警",
        [
            "跨函数、跨文件的数据流追踪",
            "对每条可疑路径做反向核验（防御、上下文）",
            "区分：高度可疑 / 待补证 / 已证伪",
        ],
        None,
    ),
    (
        "优点二：结论能交代、能复核",
        [
            "标明代码证据、配置依赖、是否需上线验证",
            "确认漏洞时给出可理解的利用逻辑或 PoC 要素",
            "扫描中断会列出「哪些类型还没扫到」",
        ],
        None,
    ),
    (
        "优点三：专家经验产品化",
        [
            "源码挖 0day → 深扫 → 补证 → 报告",
            "Java Web → 梳理入口 → 深扫 → 验证建议",
            "CVE 评估 → 调用链事实 → 可达性分析",
            "二进制场景 → 先对齐版本，再分析",
        ],
        None,
    ),
    (
        "优点四：多源信息一起用",
        [
            "已打通：CPG 深扫、配置精读、CVE 知识库、版本对齐、Java 手册",
            "持续扩展：索引、扫描器接入、动态验证（同一平台编排）",
        ],
        None,
    ),
    (
        "优点五：扫得完、续得上",
        [
            "大规模 C/C++：分批、可续扫",
            "服务异常：自动保护 + 续作指引",
            "全程审计日志，支持复盘",
        ],
        None,
    ),
    (
        "典型场景",
        [
            "C/C++、固件、中间件 — 内存、协议、嵌入式风险",
            "Java / Spring — 入口到危险点 + 配置佐证",
            "CVE / 第三方组件 — 在您产品里是否可达、多危险",
            "二进制交付 — 先对齐源码版本再分析",
        ],
        None,
    ),
    (
        "为什么是我们",
        [
            "看深度：图谱级路径 + AI 复核（非浅规则）",
            "误报：反证 + 证据分级（非告警堆砌）",
            "交付：结构化报告 + 覆盖说明（非聊天摘要）",
        ],
        None,
    ),
    (
        "交付物：能进漏洞管理流程",
        [
            "结构化分析报告（按类型、证据强度）",
            "扫描覆盖说明（查了哪些、哪些未查）",
            "审计轨迹（供内部二次复核）",
            "可选：PoC 要素清单",
        ],
        "不是 AI 聊天记录，是能进流程的工件。",
    ),
    (
        "我们主动说清楚的边界",
        [
            "AI 辅助不替代最终安全责任",
            "部分场景需上线验证 — 报告如实标注",
            "仅对您授权的目标执行分析",
        ],
        "敢写边界的产品，才敢写「真漏洞」三个字。",
    ),
    (
        "不是多找问题，而是找对问题",
        [
            "不是吓您一跳，而是让您敢拍板修",
            "试点：选一个仓库或 CVE 做对比演示",
            "30–60 分钟：从任务到带证据分级的报告",
        ],
        None,
    ),
]

ACCENT = RGBColor(0x1A, 0x56, 0x9B)
TITLE_COLOR = RGBColor(0x1E, 0x29, 0x3B)
BODY_COLOR = RGBColor(0x33, 0x41, 0x55)
NOTE_COLOR = RGBColor(0x64, 0x74, 0x8B)


def _set_title(shape, text: str) -> None:
    tf = shape.text_frame
    tf.clear()
    p = tf.paragraphs[0]
    p.text = text
    p.font.size = Pt(28)
    p.font.bold = True
    p.font.color.rgb = TITLE_COLOR


def _add_bullets(shape, bullets: list[str]) -> None:
    tf = shape.text_frame
    tf.word_wrap = True
    for i, line in enumerate(bullets):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.text = line
        p.level = 0
        p.font.size = Pt(18)
        p.font.color.rgb = BODY_COLOR
        p.space_after = Pt(8)


def _add_notes(slide, note: str) -> None:
    if not note:
        return
    notes = slide.notes_slide
    tf = notes.notes_text_frame
    tf.text = f"演讲者备注：\n{note}"


def build() -> Path:
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    for title, bullets, note in SLIDES:
        slide = prs.slides.add_slide(blank_layout)
        # accent bar
        bar = slide.shapes.add_shape(
            1,  # MSO_SHAPE.RECTANGLE
            Inches(0),
            Inches(0),
            Inches(13.333),
            Inches(0.12),
        )
        bar.fill.solid()
        bar.fill.fore_color.rgb = ACCENT
        bar.line.fill.background()

        title_box = slide.shapes.add_textbox(Inches(0.6), Inches(0.45), Inches(12.1), Inches(1.2))
        _set_title(title_box, title)

        body_box = slide.shapes.add_textbox(Inches(0.6), Inches(1.75), Inches(12.1), Inches(5.2))
        _add_bullets(body_box, bullets)

        footer = slide.shapes.add_textbox(Inches(0.6), Inches(7.0), Inches(12.0), Inches(0.35))
        fp = footer.text_frame.paragraphs[0]
        fp.text = "GuardFox · 智能漏洞挖掘 Agent"
        fp.font.size = Pt(10)
        fp.font.color.rgb = NOTE_COLOR
        fp.alignment = PP_ALIGN.RIGHT

        _add_notes(slide, note or "")

    OUTPUT_CN.parent.mkdir(parents=True, exist_ok=True)
    prs.save(str(OUTPUT_CN))
    prs.save(str(OUTPUT_EN))
    return OUTPUT_CN, OUTPUT_EN


if __name__ == "__main__":
    paths = build()
    for path in paths:
        print(f"Generated: {path}")
