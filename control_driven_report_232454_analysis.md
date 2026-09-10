# Control-Driven 最新报告质量分析
**报告**: `control-driven-reports/control_driven_report_with_snippets_20260722_232454.json`
**生成时间**: 2026-07-22T17:30:36Z ｜ **模型**: control_driven_audit (agentic)

## 一、总览数字
| 指标 | 值 |
|---|---|
| 候选总数 (totalCandidates) | 428 |
| 确认 confirmed | 67 |
| 拒绝 rejected | 11 |
| 不确定 inconclusive | 174 |
| 已裁决合计 | 252（其余 ~176 经去重/合并被折叠） |

> `nonConfirmedFindings`(185) = 11 rejected + 174 inconclusive（报告内用 `refutationVerdict` 字段区分：`rejected` / `inconclusive`）。

---

## 二、Q1：已确认的 67 个，准确率有多高？

**分桶看准确率差异很大：**

### ✅ 非认证/CSRF 桶（23 个，准确率约 90%+）
CWE-862 / 863 / 639 / 640 / 840 / 306 —— 基本都是**本地真实缺陷**，准确率高：
- `MissingFunctionAC*` 系列（缺功能级鉴权）、`IDOREditOtherProfile`/`IDORViewOtherProfile`（真 IDOR）、`HijackSession*`、`JWTRefreshEndpoint.*`、`JWTHeaderKIDEndpoint`、`Assignment7/8`、`SqlInjectionLesson5` 等。
- 仅 1–2 个 borderline（如 `Scoreboard.getRankings` conf 0.85）。

### ⚠️ 认证/CSRF 桶（44 个，准确率明显偏低）
CWE-287 / CWE-352 共 44 个，但 **40/44 的证据都引用了同一个全局配置 `WebSecurityConfig`**（NoOpPasswordEncoder 明文密码 / `csrf.disable`）。
其中 **9 个是「纯全局误报」**（证据只有全局配置、该类自身无任何本地认证缺陷，却被判 CWE-352 确认）：

| CWE | 位置 | 证据实质 |
|---|---|---|
| CWE-352 | RegistrationController.registrationOAUTH | 仅 `csrf.disable` |
| CWE-352 | BypassRestrictionsFieldRestrictions.completed | 仅 `csrf.disable` |
| CWE-352 | NetworkLesson.completed | 仅 `csrf.disable` |
| CWE-352 | IDORDiffAttributes.completed | 仅 `csrf.disable` |
| CWE-352 | IDORViewOwnProfileAltUrl.completed | 仅 `csrf.disable` |
| CWE-352 | MissingFunctionACHiddenMenus.completed | 仅 `csrf.disable` |
| CWE-352 | ResetLinkAssignmentForgotPassword.sendPasswordResetLink | 仅 `csrf.disable` |
| CWE-352 | LandingAssignment.click | 仅 `csrf.disable` |
| CWE-352 | DOMCrossSiteScripting.completed | 仅 `csrf.disable` |

其余 35 个虽也引用全局配置，但同时带有**本地真实弱点**（硬编码凭据、弱口令策略、SQLi 认证绕过、弱 JWT 密钥等），属大致可信，但根因/位置仍被全局配置「带偏」。

### 🐞 关键 Bug：上轮 `consolidateGlobalAuth()` 未生效
- 全报告 **`WebSecurityConfig` 作为 finding 出现 0 次**（既无确认、也无归并后的规范项）。
- 原因推断：recon/候选选择**没有把 `WebSecurityConfig` 作为入口候选**（它不是 HTTP 端点/sink），导致 `consolidateGlobalAuth()` 没有可「归并进去」的规范目标，于是业务端点依旧各自确认了全局配置缺陷。
- 结论：**上一轮针对「硬误报 + 全局配置重复」的修复在本轮运行里没有真正收敛**——44 个认证确认里仍有 40 个在引用同一处全局缺陷。

### 准确率估算
- 硬下限：**至少 9 个确定误报**（纯全局 CSRF）。
- 整体：**约 75% 准确率**（~51/67 可行动；非认证桶 ~90%+，认证/CSRF 桶 ~60–70%）。
- 真正的风险不是「漏」，而是**认证/CSRF 桶被同一全局根因严重注水**。

---

## 三、Q2：还有多少漏报？inconclusive 174 是不确定的漏洞吗？为什么这么高？

### inconclusive 是什么？
它是「**无法确认、也无法证伪**」的待人工研判桶（`refutationVerdict="inconclusive"`）。**它不等于「已确认的漏洞」**，而是需要复核的灰色项。

### 为什么高达 174（占已裁决的 69%）？三个叠加原因：
1. **单一全局根因被刷 ~145 次**：174 个里有 **145 个引用 `WebSecurityConfig`**（同一处 `csrf.disable` / 明文密码）。全局缺陷既制造了确认，也制造了大量「不确定」。
2. **Point 4 漏报复核逻辑过宽**：174 个里 **134 个带 exploitPoc、平均 confidence 0.95、llmConfirmed 全为 False**。读 trace 可见模型大多**已论证该处是安全的**（如「`AjaxAuthenticationEntryPoint` 是框架回调，受 `.anyRequest().authenticated()` 保护」、「`MD5.main` 是 CLI 工具非端点」、「`LessonTrackerInterceptor` 是拦截器且全局已认证」）——本应判 `rejected`，但被 Point 4（模型否定 + 有 PoC + conf≥0.8 → 翻成 inconclusive）**错误地留在了不确定桶**。
3. **预算/循环兜底**：部分候选因 agentic 循环耗尽模型调用、未产出 `vulnerability_confirmed`，以 inconclusive 兜底。

### 漏报估算
- **rejected=11 里基本判得对**（CLI 工具、拦截器、框架回调等），但 **`ShopEndpoint.get`(CWE-862) 被拒却明明有「无权限校验直接返回 SUPER_COUPON_CODE」证据**，属潜在漏报（11 个里约 1–2 个）。
- **inconclusive=174 里多数不是真漏洞**（是被 Point 4 过度保护的安全项 / 全局配置重复），但其中**预算耗尽或论证不充分**的子集可能藏有真实漏洞，需人工复核带 PoC 的 134 个。
- **总体漏报规模有限**：上一轮担心的「被判拒的真漏洞」已被 Point 4 兜住（转为 inconclusive 而非丢弃），但代价是**准确率下降 + 不确定桶膨胀**。真正的隐患是：确认列表被全局配置注水，且 `WebSecurityConfig` 本身缺失。

---

## 四、结论与建议
1. **认证/CSRF 桶需真正收敛**：修复 `consolidateGlobalAuth()` —— 当某 CWE-287/352 确认的**唯一证据是全局 `WebSecurityConfig`** 且该类无本地认证信号时，应**抑制该业务端点确认**，改为在 `WebSecurityConfig` 生成**一条规范全局认证缺陷**（当前它 0 条）。这能同时消除 9 个确定误报 + 把 ~185 个「同一根因」收成 1 条。
2. **收窄 Point 4**：仅在「模型明确给出可利用利用链且论证漏洞存在」时翻 inconclusive；若模型论证是**安全**的（即便带了 PoC/高 conf），应判 `rejected`。预计能把 174 里多数安全项正确归为 rejected，大幅压缩不确定桶。
3. **当前可行动清单**：67 个确认里，优先处理 23 个非认证桶（高准）+ 35 个带本地弱点的认证项；9 个纯全局 CSRF 确认建议先剔除/合并。

> 数据口径：基于报告 JSON 程序化统计（confirmed 全量、nonConfirmed 按 `refutationVerdict` 拆分）。漏报为基于 trace 的估算，非 Ground Truth。
