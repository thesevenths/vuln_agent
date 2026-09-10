# 组件版本识别（Agent 内置流程说明）

当用户提供：

- `*_decompiled.c`（Ghidra 反编译）
- 多个候选官方源码 `*.zip` 或已解压目录

应使用工具 **`VersionTool.identify_component`**，不要仅凭 SONAME 或文件名猜版本。

## 推荐工作流

1. `VersionTool.identify_component` — 得到 `best_matches` / `excluded_versions` / `report_markdown`
2. 若唯一匹配：`set_context(local_source_path=matched_source_root)`
3. `JoernTool.run_source_scan` — 在确认版本后的源码树上做漏洞挖掘
4. （可选）`GraphBuilder.run_reachability` — 结合 CVE 做可达分析

## CLI 示例

```bash
python main.py --mode version_identify \
  --decompiled-path "C:/path/libfoo_decompiled.c" \
  --candidate-paths "C:/candidates/foo-1.0.0.zip,C:/candidates/foo-1.0.1.zip" \
  --component-name foo
```

## REPL 示例

```
>> version_identify C:/bin/libmbedtls_decompiled.c C:/zips/mbedtls-2.14.0.zip C:/zips/mbedtls-2.14.1.zip C:/zips/mbedtls-2.16.0.zip
```

## 实现位置

- 核心算法：`version_identification.py`（**控制流指纹**，非全文文本相似度）
- 工具封装：`version_tool.py`
- Planner 注册：`tool_capabilities.py` + `planner.py`

## 评分与补丁级 tie-break（通用）

| 环境变量 | 默认 | 含义 |
|----------|------|------|
| `AGENT_VERSION_MIN_LOGIC_GAP` | `0.06` | 候选间综合指纹得分差距低于此值则不排他 |
| `AGENT_VERSION_FIRST_PLACE_EPSILON` | `1e-5` | 与最高分相差不超过此值才算「第一名并列」 |
| `AGENT_VERSION_TIE_BREAK` | `highest_patch` | 仅在第一名并列时取较高补丁号；`none` 则保持「不可区分」 |

**说明**：若 2.14.0 与 2.14.1 在二进制中无可观察逻辑差异（常见于差异仅在 DRBG/RSA 等未编入模块），
工具只能给出「2.14.0 或 2.14.1」；在 `highest_patch` 下会倾向输出 **2.14.1**，并在报告中标注「非二进制直接证据」。
若要严格只信反编译证据，请设 `AGENT_VERSION_TIE_BREAK=none`。
