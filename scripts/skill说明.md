Let我先查看关键的决策代码，确保回答准确。


Now let me also check the CWE skill loading chain and the `_load_cwe_skill_templates` method:


以下是 Agent 执行时的 **Skill 选择流程**，分为两条独立的决策链路：

---

## 链路 A：Planner 层 — Pipeline Skill 选择

这是 Agent 主循环中，根据用户请求**自动选择要执行哪些 Pipeline Skill** 的过程。核心代码在 [SkillEngine.match_skills()](file:///e:/model-similarity/agent/skill_engine.py#L581-L673)。

### 决策步骤

**1. 关键词匹配打分**
```
base_score = 命中关键词数 / 该 skill 总关键词数
```
- 将用户请求文本分词（[[_tokenize()](file:///e:/model-similarity/agent/skill_engine.py#L286-L286)](file:///e:/model-similarity/agent/skill_engine.py#L286-L286)）
- 遍历所有 `SkillDefinition`，检查每个 skill 的 `trigger_keywords` 有多少出现在用户文本中
- 得到 `base_score ∈ [0, 1]`

**2. 状态快照加成**（根据当前 Agent 状态 `state_snapshot` 额外加分）

| 条件 | 加成分配 |
|---|---|
| 有 `project_path` | `source_0day_pipeline` +0.10 |
| 有 `current_cve_id` | `reachability_exploitability` +0.20 |
| 语言=java | `java_attack_surface` / `java_web_audit_pipeline` +0.12 |
| 有 `java_routes.route_count` | `java_web_audit_pipeline` +0.08 |
| 有 `joern_hit_vuln_types` | `poc_generation_validation` +0.15 |
| Joern 命中漏洞类型匹配 | 对应 `expert_*` skill +0.25~0.30 |
| 用户说"二进制直接挖" | `version_identification` × 0.35（压制） |

**3. Benchmark 权重调整**
```
final_score = min(1.0, base_score × benchmark_weight)
```
- [benchmark_weight](file:///e:/model-similarity/agent/skill_engine.py#L289-L298) 基于历史成功率：成功率高的 skill 权重更大（区间 [0.8, 1.2]）
- 历史尝试 < 3 次的 skill 权重固定为 1.0（避免数据不足时偏差）

**4. 激活阈值过滤**
```
if score >= skill.min_score_to_activate (默认 0.25):
    加入匹配列表
```

**5. 排序 → 注入 LLM Prompt**
- 按 `score` 降序排列，取 Top-4 通过 [render_skill_guidance()](file:///e:/model-similarity/agent/skill_engine.py#L675-L705) 注入 Planner 的 system prompt
- Planner（LLM）根据注入的 skill 建议，决定是否调用 `Skill.run`

**6. DAG 执行**（Planner 决定执行后）
- [expand_skill_action()](file:///e:/model-similarity/agent/skill_engine.py#L745-L829) 解析当前 Skill 的 DAG 节点
- 取出当前节点的 `tool_name` + `arguments`，映射为具体 tool action
- 执行完毕后 [advance_runtime()](file:///e:/model-similarity/agent/skill_engine.py#L831-L939) 推进到下一节点：
  - 成功 → `success_next`
  - 失败 → `failure_next`（若无则回退到 `success_next`）
  - `next_node_id = None` → Skill 完成
- 内置**自动重写机制**：低性能节点会触发候选策略替换 → canary 测试 → 达标则正式替换，不达标则回滚

---

## 链路 B：Logic Scan 层 — CWE Skill 加载

这是在 `run_logic_scan` 执行时，为每个逻辑漏洞候选**加载分析知识**的过程。核心代码在 [_load_cwe_skill_templates()](file:///e:/model-similarity/agent/joern_vuln_scanner.py#L3812-L3829) → [skill_loader.load_cwe_skills()](file:///e:/model-similarity/agent/skill_loader.py)。

### 决策步骤

**1. 确定 CWE Focus**
- 显式参数 > `.env` 配置 > 默认全集（`DEFAULT_CWE_FOCUS`）

**2. 语言/框架检测**
- [detect_language()](file:///e:/model-similarity/agent/skill_loader.py)：扫描项目文件后缀判断语言（`pom.xml` → java, `requirements.txt` → python）
- [detect_frameworks()](file:///e:/model-similarity/agent/skill_loader.py)：扫描构建文件匹配 `languages/{lang}/_meta.yaml` 中的 `framework_signals`（如检测到 `spring-boot-starter-security` → `spring_security`）

**3. 4 层 YAML 加载**（优先 YAML，失败回退 JSON）

```
core/           → 共享方法论（confirmation_criteria, verdict_rule, poc_requirements, ...）
authorization/  → CWE 分析逻辑（skill.yaml + reasoning.yaml + patterns.yaml）
business_logic/    同上
injection/         同上
languages/      → 框架特化模式（扩展 trigger_condition + logic_query_keywords）
```

合并规则：
- `skill.yaml` → 基础元数据（`skill_id`, `priority`, `description`）
- `reasoning.yaml` → 分析逻辑（`reasoning_workflow`, `knowledge_injection`, `sanitizers`）
- `patterns.yaml` → 检测模式（`trigger_condition`, `semantic_keywords`）
- `core/` → 合并进 P0 逻辑 CWE（`confirmation_criteria`, `verdict_rule`, `component_scan_handoff`）
- `languages/` → 追加框架特化的 `route_patterns` 和 `logic_query_keywords`

**4. LLM Prompt 注入**（每个候选的 prompt 包含）
- `reasoning_workflow` — 分析步骤指引
- `sanitizers` — 已知安全过滤函数
- `confirmation_criteria` — 确认标准
- `verdict_rule` — 判定规则
- `logic_query_keywords` — Joern 查询关键词
- `companions`（通过 [_build_companion_guidance()](file:///e:/model-similarity/agent/joern_vuln_scanner.py)）— 关联 CWE 的分析结果

**5. LLM 分析 → 输出 finding**

---

## 整体流程图

```
用户请求
  │
  ├─→ SkillEngine.match_skills()
  │     ├─ 关键词匹配 → base_score
  │     ├─ 状态加成（Joern 结果、项目路径、语言…）
  │     ├─ benchmark_weight 调整
  │     ├─ 阈值过滤 + 排序
  │     └─ render_skill_guidance() → 注入 LLM prompt
  │           └─ Planner 决策 → Skill.run → DAG 逐节点执行
  │
  └─→ run_logic_scan（如触发逻辑漏洞扫描）
        ├─ resolve_cwe_focus（确定关注 CWE）
        ├─ detect_frameworks（检测框架）
        ├─ skill_loader.load_cwe_skills（4 层 YAML 加载）
        ├─ 对每个 candidate 构建 LLM prompt
        │     ├─ reasoning_workflow + sanitizers
        │     ├─ confirmation_criteria + verdict_rule
        │     └─ companion guidance
        └─ LLM 分析 → finding
```