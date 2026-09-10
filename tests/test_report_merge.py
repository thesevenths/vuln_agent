"""Tests for scan report merge by flow_id."""
import unittest

from report_merge import merge_scan_reports


OLD_SNIPPET = """# 🔍 Joern + LLM 智能迭代分析报告
> 时间: 2026-06-17 20:32:00
> 项目: VulnerableApp

---
## 漏洞类型: CPP_BUFFER_OVERFLOW（共 1 条 flow，分析 1，跳过 0）

---
## 🔎 CPP_BUFFER_OVERFLOW — `cpp_buffer_overflow-flow-2`
| flow_id | `cpp_buffer_overflow-flow-2` |
| refutation_verdict | `inconclusive` |

---
## 🔎 CPP_BUFFER_OVERFLOW (cpp_buffer_overflow-flow-2) 分析结果
- **是否真实漏洞**：⚠️ 部分是
"""

NEW_SNIPPET = """# 🔍 Joern + LLM 智能迭代分析报告
> 时间: 2026-06-17 20:37:00
> 项目: VulnerableApp

---
## 漏洞类型: CPP_USE_AFTER_FREE（共 1 条 flow，分析 1，跳过 0）

---
## 🔎 CPP_USE_AFTER_FREE — `cpp_use_after_free-flow-2`
| flow_id | `cpp_use_after_free-flow-2` |
| refutation_verdict | `likely_false_positive` |

---
## 🔎 CPP_USE_AFTER_FREE (cpp_use_after_free-flow-2) 分析结果
- **是否真实漏洞**：❌ 否
"""


class TestReportMerge(unittest.TestCase):
    def test_merge_keeps_old_flows_and_adds_new(self):
        merged = merge_scan_reports(OLD_SNIPPET, NEW_SNIPPET)
        self.assertIn("cpp_buffer_overflow-flow-2", merged)
        self.assertIn("cpp_use_after_free-flow-2", merged)
        self.assertIn("CPP_BUFFER_OVERFLOW", merged)
        self.assertIn("CPP_USE_AFTER_FREE", merged)

    def test_new_overwrites_same_flow_id(self):
        updated_old = OLD_SNIPPET.replace(
            "inconclusive", "likely_false_positive"
        ).replace("⚠️ 部分是", "❌ 否")
        newer = OLD_SNIPPET.replace("inconclusive", "confirmed").replace(
            "⚠️ 部分是", "✅ 是"
        )
        merged = merge_scan_reports(updated_old, newer)
        self.assertIn("confirmed", merged)
        self.assertNotIn("likely_false_positive", merged)

    def test_empty_existing_returns_new(self):
        merged = merge_scan_reports("", NEW_SNIPPET)
        self.assertIn("cpp_use_after_free-flow-2", merged)
        self.assertIn("审计结论一览", merged)


if __name__ == "__main__":
    unittest.main()
