"""
逻辑漏洞扫描（run_logic_scan）统一配置。

只需改一处即可调整全局默认行为：
  1. 本文件中的 DEFAULT_* 常量，或
  2. 项目根目录 `.env` 中的同名环境变量（见下方说明）。

其它模块（joern_vuln_scanner / tools / graph / planner / pipeline skill）
均通过本模块读取配置，禁止再硬编码 max_candidates / 默认 cwe_focus。
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Dict, FrozenSet, List, Tuple, TypedDict

logger = logging.getLogger(__name__)


class LogicCandidateMeta(TypedDict):
    priority: int
    cwe: str
    principle: str
    example_harm: str


# 逻辑候选类型目录：priority / CWE / 原理 / 危害示例（LLM skill 见 skills/templates/cwe/）
LOGIC_CANDIDATE_CATALOG: Dict[str, LogicCandidateMeta] = {
    # ── P0：鉴权 / 越权 / 业务逻辑 ─────────────────────────────────────────
    "admin_no_auth": {
        "priority": 0,
        "cwe": "862",
        "principle": "管理类敏感操作（删用户、授角色、改配置）缺少角色/权限校验。",
        "example_harm": "任意用户 POST /admin/deleteUser?id=1 删除管理员账号。",
    },
    "idor": {
        "priority": 0,
        "cwe": "639",
        "principle": "用外部传入的资源 ID 访问对象，未校验该资源是否属于当前用户。",
        "example_harm": "GET /invoice/1001 改为 /invoice/1002 读取他人发票。",
    },
    "idor_pathvar": {
        "priority": 0,
        "cwe": "639",
        "principle": "@PathVariable / @RequestParam 直接作主键查询，无 owner/tenant 绑定。",
        "example_harm": "GET /users/{userId}/profile 篡改 userId 查看他人资料。",
    },
    "idor_profile": {
        "priority": 0,
        "cwe": "639",
        "principle": "Profile/账户类接口用客户端给的 userId 定位记录，未与 session 身份比对。",
        "example_harm": "POST body {\"userId\":2} 修改他人邮箱或收货地址。",
    },
    "jwt_endpoint": {
        "priority": 0,
        "cwe": "287",
        "principle": "端点依赖 JWT 作身份凭据，但解析/校验链与路由保护配置不一致。",
        "example_harm": "无 Cookie 仅带伪造 JWT 访问 /api/account 获取敏感数据。",
    },
    "csrf_gap": {
        "priority": 0,
        "cwe": "352",
        "principle": "状态变更接口（POST/PUT/DELETE）无 CSRF Token 且 Cookie 会话可被跨站携带。",
        "example_harm": "恶意页面自动提交表单导致受害者转账或改密。",
    },
    "business_logic_risk": {
        "priority": 0,
        "cwe": "840",
        "principle": "服务端信任客户端提交的业务字段（价格、数量、折扣、角色），未独立重算。",
        "example_harm": "下单时传 total=0.01 以一分钱购买高价商品。",
    },
    "workflow_bypass": {
        "priority": 0,
        "cwe": "841",
        "principle": "多步骤流程（注册、审批、支付）可跳过中间状态直接调最终接口。",
        "example_harm": "未付款直接 POST /order/complete 将订单标为已完成。",
    },
    "incorrect_authz": {
        "priority": 0,
        "cwe": "863",
        "principle": "授权决策依赖攻击者可控输入（Header/参数中的 role、userId、isAdmin）。",
        "example_harm": "请求头 X-Role: admin 绕过接口权限检查。",
    },
    "auth_weakness": {
        "priority": 0,
        "cwe": "287",
        "principle": "认证实现存在弱点：可绕过、弱比对、错误的安全上下文使用。",
        "example_harm": "空密码、默认口令或逻辑分支跳过 passwordEncoder 校验。",
    },
    "business_authz_gap": {
        "priority": 0,
        "cwe": "285",
        "principle": "业务层授权缺失：有登录但无「谁能对该业务对象做什么」的规则。",
        "example_harm": "普通员工调用 /hr/salary/export 导出全员薪资。",
    },
    "missing_auth": {
        "priority": 1,
        "cwe": "862",
        "principle": "敏感读写/变更操作前既无方法级守卫，也无全局 Security 链保护。",
        "example_harm": "未登录访问 GET /api/users 列出全部用户。",
    },
    "shiro_missing_auth": {
        "priority": 1,
        "cwe": "862",
        "principle": "Apache Shiro 栈下敏感入口缺少 @RequiresPermissions/@RequiresRoles 或 Subject 校验。",
        "example_harm": "未登录调用 Shiro 保护的 /api/admin 接口执行删用户操作。",
    },
    "jaxrs_missing_auth": {
        "priority": 1,
        "cwe": "862",
        "principle": "JAX-RS 资源有 @Path 但无 @RolesAllowed/@PermitAll/@DenyAll 等声明式鉴权。",
        "example_harm": "GET /api/account 无角色注解，匿名可读他人账户信息。",
    },
    "client_hash_auth": {
        "priority": 1,
        "cwe": "836",
        "principle": "服务端比对客户端预先计算的密码哈希，等价于把密码泄露给传输层。",
        "example_harm": "截获 md5(password) 即可重放登录，无需知道明文。",
    },
    "toctou_risk": {
        "priority": 1,
        "cwe": "367",
        "principle": "先检查权限/路径再使用资源，检查与使用之间存在竞态窗口。",
        "example_harm": "校验文件属主后、打开前被符号链接替换读取 /etc/passwd。",
    },
    # ── P1：SAST 可覆盖 + 配置 / 泄露 / 硬编码 ─────────────────────────────
    "sqli_risk": {
        "priority": 2,
        "cwe": "89",
        "principle": "用户输入拼进 SQL 字符串，未参数化或 ORM 安全绑定。",
        "example_harm": "username=' OR '1'='1 绕过登录或拖库。",
    },
    "xxe_risk": {
        "priority": 2,
        "cwe": "611",
        "principle": "XML 解析器允许外部实体，攻击者注入恶意 DTD/实体。",
        "example_harm": "上传 SVG/XML 读取服务器 file:///etc/passwd。",
    },
    "deser_risk": {
        "priority": 2,
        "cwe": "502",
        "principle": "反序列化不可信数据（ObjectInputStream、JSON 多态等）可触发链式调用。",
        "example_harm": "恶意序列化 payload 在 readObject() 时远程执行命令。",
    },
    "cmd_exec_risk": {
        "priority": 2,
        "cwe": "78",
        "principle": "用户输入进入 Runtime.exec / ProcessBuilder 等命令执行 API。",
        "example_harm": "filename=;rm -rf / 被 shell 解释执行。",
    },
    "xss_output_risk": {
        "priority": 2,
        "cwe": "79",
        "principle": "未编码的用户输入写入 HTML/模板/JavaScript 响应。",
        "example_harm": "评论中 <script> 窃取他人 session Cookie。",
    },
    "ssrf_risk": {
        "priority": 2,
        "cwe": "918",
        "principle": "服务端根据用户提供的 URL 发起 HTTP/连接请求，可打内网。",
        "example_harm": "url=http://169.254.169.254/ 窃取云元数据凭证。",
    },
    "jwt_weakness": {
        "priority": 2,
        "cwe": "341",
        "principle": "JWT 使用硬编码弱密钥、none 算法或关闭签名校验。",
        "example_harm": "用已知 secret 签发 admin JWT 提权访问后台。",
    },
    "cors_misconfig": {
        "priority": 2,
        "cwe": "284",
        "principle": "Access-Control-Allow-Origin 反射任意 Origin 且 Allow-Credentials=true。",
        "example_harm": "恶意站点跨域读取受害者已登录 API 的 JSON 响应。",
    },
    "hardcoded_cred": {
        "priority": 2,
        "cwe": "798",
        "principle": "源码或配置中明文写死 API Key、数据库密码、JWT secret。",
        "example_harm": "反编译 APK/JAR 得到 AWS 密钥接管云资源。",
    },
    "info_leak": {
        "priority": 2,
        "cwe": "200",
        "principle": "异常栈、调试日志、内部路径写入日志或错误页。",
        "example_harm": "500 页面暴露 SQL 语句和表结构辅助进一步攻击。",
    },
    "info_leak_response": {
        "priority": 2,
        "cwe": "200",
        "principle": "API 响应体返回过多字段（密码哈希、token、内部 ID）。",
        "example_harm": "GET /user/1 返回 passwordHash、ssn 等敏感列。",
    },
    "file_ops": {
        "priority": 2,
        "cwe": "22",
        "principle": "文件路径由用户控制，可 ../ 跳出预期目录读写任意文件。",
        "example_harm": "file=../../../etc/passwd 下载系统敏感文件。",
    },
    "mass_exposure": {
        "priority": 2,
        "cwe": "200",
        "principle": "列表/导出接口一次返回大量记录且缺少分页、字段脱敏或权限过滤。",
        "example_harm": "GET /api/users?pageSize=99999 导出全站用户 PII。",
    },
    # ── P0：新增逻辑漏洞 CWE（269/276/307/362/384/521/610/613/640/915） ──────
    "privilege_escalation": {
        "priority": 0,
        "cwe": "269",
        "principle": "角色/权限变更接口接受客户端参数并直接持久化，缺少操作者权限校验或角色值白名单。",
        "example_harm": "普通用户调用 PUT /api/users/1/role?role=ADMIN 将自己提升为管理员。",
    },
    "incorrect_permissions": {
        "priority": 0,
        "cwe": "276",
        "principle": "文件/目录/云存储创建时赋予过于宽松的默认权限（如 chmod 777、S3 public-read）。",
        "example_harm": "配置文件设为 0o777，系统任意用户可读写敏感凭据。",
    },
    "brute_force_risk": {
        "priority": 0,
        "cwe": "307",
        "principle": "认证入口缺少速率限制、账户锁定或验证码等暴力破解防护机制。",
        "example_harm": "登录接口无限次尝试，攻击者通过字典爆破接管账户。",
    },
    "race_condition_risk": {
        "priority": 0,
        "cwe": "362",
        "principle": "资金/库存/积分扣减的 check-then-act 逻辑缺少数据库原子操作或并发锁保护。",
        "example_harm": "并发请求同时读取库存并各自 save()，导致超卖。",
    },
    "session_fixation_risk": {
        "priority": 0,
        "cwe": "384",
        "principle": "登录成功后未重新生成 Session ID，攻击者可预设 Session 并劫持已认证会话。",
        "example_harm": "攻击者将已知 JSESSIONID 发给受害者，受害者登录后攻击者用该 ID 接管账户。",
    },
    "weak_password_requirements": {
        "priority": 0,
        "cwe": "521",
        "principle": "注册/改密接口缺少服务端密码复杂度校验，允许设置弱密码。",
        "example_harm": "用户注册时设置密码为 '123456'，服务端未拦截，增加撞库风险。",
    },
    "payment_tampering": {
        "priority": 0,
        "cwe": "610",
        "principle": "订单金额/价格/折扣等财务参数直接信任客户端传入值，未在服务端重新计算。",
        "example_harm": "抓包将 totalAmount 改为 0.01，以一分钱购买高价商品。",
    },
    "session_expiration_risk": {
        "priority": 0,
        "cwe": "613",
        "principle": "会话/Token 缺少合理的空闲超时或绝对超时，长期有效导致泄露后被持久利用。",
        "example_harm": "JWT 有效期设为 30 天且无撤销机制，Token 泄露后攻击者长期接管账户。",
    },
    "password_recovery_risk": {
        "priority": 0,
        "cwe": "640",
        "principle": "密码恢复机制存在弱 Token、可预测 OTP、安全问题或 IDOR 等缺陷。",
        "example_harm": "重置密码接口信任客户端传入的 userId，攻击者篡改后可重置任意用户密码。",
    },
    "mass_assignment_risk": {
        "priority": 0,
        "cwe": "915",
        "principle": "@ModelAttribute/@RequestBody 直接绑定 Entity 对象，未限制可绑定字段，导致敏感字段被篡改。",
        "example_harm": "POST /profile 传 role=admin，通过自动绑定直接提升权限。",
    },
    # ── P2：低信号枚举 ─────────────────────────────────────────────────────
    "public_endpoint": {
        "priority": 3,
        "cwe": "306",
        "principle": "路由/方法无 @PreAuthorize 等注解，仅表示「可能缺认证」的弱信号。",
        "example_harm": "枚举到 POST /internal/debug 等本应对外关闭的调试入口。",
    },
}

LOGIC_CANDIDATE_PRIORITY: Dict[str, int] = {
    name: meta["priority"] for name, meta in LOGIC_CANDIDATE_CATALOG.items()
}


def logic_candidate_cwe(candidate_type: str) -> str:
    """候选 type → CWE-xxx 标签（单一数据源：LOGIC_CANDIDATE_CATALOG）。"""
    meta = LOGIC_CANDIDATE_CATALOG.get(candidate_type)
    if not meta:
        return "CWE-unknown"
    return f"CWE-{meta['cwe']}"


def logic_candidate_priority(candidate_type: str) -> int:
    """候选 type → 分层 priority（未知类型排最后）。"""
    meta = LOGIC_CANDIDATE_CATALOG.get(candidate_type)
    if not meta:
        return 99
    return int(meta["priority"])


# ── CWE 关联分析（Companion Analysis）─────────────────────────────────────
# 每个 CWE 映射到其强关联的「伴随 CWE」列表（双向 related_cwes 且均在 focus 内）。
# 当 LLM 分析某个候选时，除了检查主 CWE，还会同时检查伴随 CWE，
# 一次 LLM 调用产出多个 finding，避免漏报跨 CWE 的关联漏洞。
#
# v2: 优先从 registry.yaml 的 cwe_index[*].companions 加载；失败则用硬编码值。

_CWE_COMPANION_MAP_FALLBACK: Dict[str, Tuple[str, ...]] = {
    # ── Access Control cluster ──
    "862": ("863", "285", "284", "306"),
    "863": ("862", "285", "284"),
    "285": ("862", "863", "639"),
    "284": ("862", "863"),
    "269": ("915",),
    "915": ("269",),
    "306": ("862", "287", "307"),
    "639": ("285",),
    # ── Authentication cluster ──
    "287": ("384", "613", "640", "306", "307", "798"),
    "384": ("287", "613"),
    "613": ("384", "287"),
    "307": ("287", "521", "306"),
    "521": ("307",),
    "640": ("287",),
    "798": ("287",),
    # ── Concurrency cluster ──
    "362": ("367",),
    "367": ("362",),
}


def _load_companion_map_from_yaml() -> Dict[str, Tuple[str, ...]] | None:
    """尝试从 registry.yaml 的 cwe_index[*].companions 加载伴随 CWE 映射。"""
    try:
        import yaml
        registry_path = Path(__file__).resolve().parent / "skills" / "registry.yaml"
        if not registry_path.is_file():
            return None
        reg = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
        if not isinstance(reg, dict) or "cwe_index" not in reg:
            return None
        result: Dict[str, Tuple[str, ...]] = {}
        for cwe, entry in reg["cwe_index"].items():
            companions = entry.get("companions")
            if companions:
                result[str(cwe)] = tuple(str(c) for c in companions)
        return result if result else None
    except Exception as exc:
        logger.debug("registry.yaml 加载 CWE_COMPANION_MAP 失败: %s", exc)
        return None


CWE_COMPANION_MAP: Dict[str, Tuple[str, ...]] = (
    _load_companion_map_from_yaml() or _CWE_COMPANION_MAP_FALLBACK
)


def get_cwe_companions(cwe_num: str) -> Tuple[str, ...]:
    """返回 CWE 的强关联伴随 CWE 编号列表（不含自身）。"""
    return CWE_COMPANION_MAP.get(cwe_num, ())


def _int_env(name: str, default: int) -> int:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _csv_env(name: str, default: Tuple[str, ...]) -> Tuple[str, ...]:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    parts = [
        p.strip().replace("CWE-", "").replace("cwe-", "")
        for p in raw.split(",")
        if p.strip()
    ]
    return tuple(parts) if parts else default


# ── 候选分析上限（LLM 调用次数）────────────────────────────────────────────
# .env: LOGIC_SCAN_MAX_CANDIDATES=100
DEFAULT_MAX_CANDIDATES: int = _int_env("LOGIC_SCAN_MAX_CANDIDATES", 100)

# Planner 执行 run_logic_scan 时下限（防止 LLM planner 传入过小值）
# .env: LOGIC_SCAN_MAX_CANDIDATES_FLOOR=60
MAX_CANDIDATES_FLOOR: int = _int_env("LOGIC_SCAN_MAX_CANDIDATES_FLOOR", 100)

# ── LLM 分层预算（按候选优先级分层控制 LLM 调用数）───────────────────────
# P0（优先级 0-1）：全部分析，不设层上限
# P1（优先级 2）：最多分析 LOGIC_TIER1_MAX 个
# P2（优先级 3+）：最多分析 LOGIC_TIER2_MAX 个
# .env: LOGIC_TIER1_MAX=30, LOGIC_TIER2_MAX=10
TIER1_MAX: int = _int_env("LOGIC_TIER1_MAX", 30)
TIER2_MAX: int = _int_env("LOGIC_TIER2_MAX", 10)

# jwt/hardcoded 查询命中超过该阈值且无一 confirmed 时，Planner 强制读 Security 配置
# .env: LOGIC_SCAN_HIGH_HIT_THRESHOLD=5
HIGH_HIT_L2_THRESHOLD: int = _int_env("LOGIC_SCAN_HIGH_HIT_THRESHOLD", 5)

# Joern 查询检查点命名空间（与 taint 共用 agent_reports/checkpoints/ 目录）
# 成功扫描后默认保留 {project}_logic.json 与 {project}_logic_llm.json，同项目重跑只补新 query/新候选。
# 清空检查点：JOERN_CHECKPOINT_RESET=1 或 JOERN_CPP_CHECKPOINT_RESET=1
LOGIC_QUERY_CHECKPOINT_NS: str = "logic"
LOGIC_LLM_CHECKPOINT_NS: str = "logic_llm"
# Joern 源码回查缓存（method_source / caller_chain / protection_matrix）
# 同项目重跑时避免重复发起数千次 Joern HTTP 查询
LOGIC_JOERN_CACHE_NS: str = "logic_joern_source"

# ── 默认 CWE 聚焦（None 表示不过滤查询集；Planner/skill 可显式传入）────────
# .env: LOGIC_SCAN_DEFAULT_CWE_FOCUS=862,306,639,798,287,352,200,341,22
DEFAULT_CWE_FOCUS: Tuple[str, ...] = _csv_env(
    "LOGIC_SCAN_DEFAULT_CWE_FOCUS",
    (
        # 逻辑漏洞核心（传统 SAST 难以覆盖）
        "862", "306", "639", "863", "285", "836", "899",
        "841", "287", "284",
        # 认证/凭证
        "798", "341", "330",
        # 信息泄露/配置
        "200", "352",
        # 竞态/业务逻辑/SSRF
        "367", "840", "918",
        # 注入类（SAST 可辅助但逻辑扫描补充攻击面）
        "22", "89", "79", "611", "502", "78",
        # 新增逻辑漏洞 CWE
        "269", "276", "307", "362", "384", "521", "610", "613", "640", "915",
    ),
)

# ── 候选分层预算（见 LOGIC_CANDIDATE_CATALOG / LOGIC_CANDIDATE_PRIORITY）────────
# P0（priority 0-1）：全量 LLM，仅保留传统污点 SAST 难以单独定论的类型
# P1（priority 2）：最多 LOGIC_TIER1_MAX；含 SAST 可覆盖项 + 配置/泄露类
# P2（priority 3+）：最多 LOGIC_TIER2_MAX；低信号枚举类

# P0 核心：由 catalog.priority 推导，禁止手工维护第二份列表
LOGIC_P0_CANDIDATE_TYPES: FrozenSet[str] = frozenset(
    name for name, meta in LOGIC_CANDIDATE_CATALOG.items() if meta["priority"] <= 1
)

# 与传统污点 SAST 高度重叠 — 必须 priority==2（见 test_logic_scan_settings）
SAST_OVERLAP_CANDIDATE_TYPES: FrozenSet[str] = frozenset({
    "sqli_risk",
    "xxe_risk",
    "deser_risk",
    "cmd_exec_risk",
    "xss_output_risk",
    "file_ops",
    "ssrf_risk",
    "jwt_weakness",
})

# 兼容旧名：核心逻辑类型 = P0（配额紧张时 round-robin 仍优先保留）
LOGIC_CORE_CANDIDATE_TYPES: FrozenSet[str] = LOGIC_P0_CANDIDATE_TYPES

# 首轮 run_logic_scan LLM 判定前，先跑 Joern 上下文扩展（与 expand_flow_context 同循环）
# .env: LOGIC_SCAN_EXPANSION_MAX_ITERS=2, LOGIC_SCAN_SKIP_CONTEXT_EXPANSION=1 可关闭
LOGIC_SCAN_EXPANSION_MAX_ITERS: int = _int_env("LOGIC_SCAN_EXPANSION_MAX_ITERS", 2)

# 逻辑分析需 L2 补证（SecurityFilterChain / 配置文件）的候选类型
LOGIC_L2_SENSITIVE_TYPES: FrozenSet[str] = frozenset({
    "jwt_weakness",
    "jwt_endpoint",
    "csrf_gap",
    "ssrf_risk",
    "hardcoded_cred",
    "cors_misconfig",
    "missing_auth",
    "shiro_missing_auth",
    "jaxrs_missing_auth",
    "public_endpoint",
    "admin_no_auth",
    "brute_force_risk",
    "session_fixation_risk",
    "session_expiration_risk",
    "password_recovery_risk",
    "privilege_escalation",
})

# 首轮 LLM 前触发 Joern 扩展的候选类型（L2 敏感 + IDOR/业务流程）
LOGIC_SCAN_CONTEXT_EXPANSION_TYPES: FrozenSet[str] = frozenset(
    set(LOGIC_L2_SENSITIVE_TYPES)
    | {
        "idor",
        "idor_pathvar",
        "idor_profile",
        "workflow_bypass",
        "payment_tampering",
        "mass_assignment_risk",
        "race_condition_risk",
    }
)

# Java/Spring Security 配置文件 glob（Planner 强制补证）
JAVA_SECURITY_CONFIG_GLOBS: Tuple[str, ...] = (
    "**/*Security*Config*.java",
    "**/*WebSecurity*.java",
    "**/shiro.ini",
    "**/application*.yml",
    "**/application*.yaml",
    "**/application*.properties",
    "**/security*.xml",
)


# ── Planner：用户明确要求仅逻辑审计时，禁止污点扫描抢步数 ─────────────────
LOGIC_ONLY_AUDIT_MODE: str = "logic_only"

TAINT_SCAN_TOOL_NAMES: FrozenSet[str] = frozenset({
    "JoernTool.run_source_scan",
    "GraphBuilder.run_source_scan",
    "JoernTool.run_taint_queries",
    "JoernTool.run_targeted_scan",
})

LOGIC_ONLY_BLOCKED_SKILL_IDS: FrozenSet[str] = frozenset({
    "source_0day_pipeline",
    "java_web_audit_pipeline",
    "web_pentest_whitebox_pipeline",
    "binary_0day_direct",
    "cve_pattern_scan",
    "reachability_exploitability",
    "java_attack_surface",
    "poc_generation_validation",
})

_LOGIC_ONLY_SIGNALS: Tuple[str, ...] = (
    "逻辑漏洞",
    "逻辑漏洞扫描",
    "只做逻辑",
    "仅逻辑",
    "只扫逻辑",
    "只要逻辑",
    "不做污点",
    "不要污点",
    "无需污点",
    "不跑污点",
    "鉴权漏洞",
    "越权",
    "idor",
    "bola",
    "业务流程绕过",
    "logic scan",
    "logic vulnerability",
    "logic-only",
    "logic only",
    "run_logic_scan",
    "authorization audit",
    "authentication audit",
)

_TAINT_EXPLICIT_SIGNALS: Tuple[str, ...] = (
    "污点扫描",
    "污点分析",
    "污点漏洞",
    "source scan",
    "run_source_scan",
    "0day",
    "sql注入",
    "sql injection",
    "xss",
    "命令注入",
    "全量源码",
    "源码挖洞",
    "污点流",
)


def detect_logic_only_intent(user_request: str) -> bool:
    """
    从用户 prompt 推断是否「仅逻辑漏洞审计」。

  规则：出现逻辑向关键词且未同时要求污点/0day 全量扫描 → logic_only。
    """
    text = (user_request or "").strip().lower()
    if not text:
        return False
    has_logic = any(sig in text for sig in _LOGIC_ONLY_SIGNALS)
    has_taint = any(sig in text for sig in _TAINT_EXPLICIT_SIGNALS)
    if has_taint:
        return False
    return has_logic


def resolve_max_candidates(explicit: int | None = None) -> int:
    """解析有效 max_candidates（显式参数 → 环境/默认，且不低于 FLOOR）。"""
    base = int(explicit) if explicit is not None else DEFAULT_MAX_CANDIDATES
    return max(base, MAX_CANDIDATES_FLOOR)


def resolve_cwe_focus(explicit: List[str] | None) -> List[str] | None:
    """显式 cwe_focus 优先；未传时使用 DEFAULT_CWE_FOCUS。"""
    if explicit is not None:
        return [
            c.replace("CWE-", "").replace("cwe-", "").strip()
            for c in explicit
            if str(c).strip()
        ] or None
    return list(DEFAULT_CWE_FOCUS)
