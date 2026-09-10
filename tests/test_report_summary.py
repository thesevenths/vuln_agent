"""Tests for report executive summary."""
import unittest

from report_summary import build_executive_summary, inject_executive_summary


FLOW_INCONCLUSIVE_YES = """---
## 漏洞类型: CPP_BUFFER_OVERFLOW（共 1 条 flow，分析 1，跳过 0）

---
## 🔎 CPP_BUFFER_OVERFLOW — `cpp_buffer_overflow-flow-2`

### 📊 结构化判定 (`cpp_buffer_overflow-flow-2`)
| refutation_verdict | `inconclusive` |
| L2 静态补证（配置/依赖） | `present` |

**反证摘要**: L1 成立但无法确认可利用性

---
## 🔎 CPP_BUFFER_OVERFLOW (cpp_buffer_overflow-flow-2) 分析结果

### 判定与修复
- 是否真实漏洞：✅ 是
- 漏洞利用：Fuzzer 入口 ...
"""

FLOW_FALSE_POS = """---
## 🔎 CPP_USE_AFTER_FREE — `cpp_use_after_free-flow-2`

### 📊 结构化判定
| refutation_verdict | `likely_false_positive` |

**反证摘要**: session==NULL 检查，标准释放序列

---
## 🔎 CPP_USE_AFTER_FREE (cpp_use_after_free-flow-2) 分析结果
- **是否真实漏洞**：❌ 否
"""


class TestReportSummary(unittest.TestCase):
    def test_draft_yes_inconclusive_is_not_confirmed(self):
        summary = build_executive_summary(FLOW_INCONCLUSIVE_YES)
        self.assertIn("未证实", summary)
        self.assertIn("cpp_buffer_overflow-flow-2", summary)
        self.assertIn("初稿写「✅ 是」但终态非实锤", summary)
        self.assertIn("**（无）**", summary)

    def test_likely_false_positive_is_not_vuln(self):
        summary = build_executive_summary(FLOW_FALSE_POS)
        self.assertIn("非漏洞", summary)
        self.assertIn("cpp_use_after_free-flow-2", summary)

    def test_inject_places_summary_near_top(self):
        report = "# 🔍 Joern + LLM 智能迭代分析报告\n> 时间: test\n\n" + FLOW_INCONCLUSIVE_YES
        merged = inject_executive_summary(report)
        self.assertLess(merged.find("审计结论一览"), merged.find("cpp_buffer_overflow-flow-2"))
        self.assertIn("请以此表为准", merged)


if __name__ == "__main__":
    unittest.main()
