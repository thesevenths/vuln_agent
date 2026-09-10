"""
run_logic_scan 通用终态门禁与 PoC 校验（与具体项目无关）。

解决两类系统性问题：
1. 框架身份注入（@CurrentUser 等）被误判为 missing_auth / public_endpoint
2. PoC 使用猜测常量而非源码字面量
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

# Spring / JAX-RS / 常见框架：方法参数级身份绑定
IDENTITY_PARAM_ANNOTATION_RE = re.compile(
    r"@(?:CurrentUser|CurrentUsername|AuthenticationPrincipal|Principal|"
    r"LoggedInUser|ActiveUser|RequestAttribute\s*\(\s*[\"']?(?:user|currentUser|principal))",
    re.IGNORECASE,
)

# 全局需登录配置（Spring Security / 类似 DSL）
GLOBAL_AUTHENTICATED_RE = re.compile(
    r"(?:anyRequest\s*\(\s*\)\s*\.\s*authenticated|"
    r"authorize(?:Http)?Requests\s*\([^)]*\)\s*\.\s*anyRequest\s*\(\s*\)\s*\.\s*authenticated|"
    r"\.authenticated\s*\(\s*\)\s*\)|"
    r"login_required|@login_required|IsAuthenticated)",
    re.IGNORECASE | re.DOTALL,
)

PERMIT_ALL_RE = re.compile(
    r"(?:permitAll|permit_all|anonymous\s*\(\s*\)|AllowAnonymous|@PermitAll|"
    r"requestMatchers\s*\([^)]+\)\s*\.\s*permitAll)",
    re.IGNORECASE,
)

HARDCODED_VALUE_IN_EVIDENCE_RE = re.compile(
    r"value=([^|]+?)(?:\s*\||$)", re.IGNORECASE
)

JAVA_STRING_LITERAL_RE = re.compile(
    r'(?:static\s+final\s+String\s+\w+|String\s+\w+)\s*=\s*"([^"\\]{1,200})"',
    re.IGNORECASE,
)

# PoC 中常见「猜密码」占位，若源码无此字面量则告警
GUESSED_CREDENTIAL_TOKENS = frozenset({
    "password", "secret", "admin", "123456", "webgoat", "changeme", "test",
})

AUTH_SURFACE_TYPES = frozenset({"missing_auth", "public_endpoint"})


def method_has_identity_injection(method_source: str) -> bool:
    if not (method_source or "").strip():
        return False
    return bool(IDENTITY_PARAM_ANNOTATION_RE.search(method_source))


def parse_security_filter_summary(security_raw: str) -> Dict[str, Any]:
    """从 security_filter_chain Joern 查询结果提取可机读摘要。"""
    text = security_raw or ""
    return {
        "has_global_authenticated": bool(GLOBAL_AUTHENTICATED_RE.search(text)),
        "has_permit_all": bool(PERMIT_ALL_RE.search(text)),
        "raw_preview": text[:3000],
    }


def extract_source_literals(method_source: str, evidence: str = "") -> List[str]:
    """从 Joern 证据行与方法源码提取可用于 PoC 的字面量。"""
    literals: List[str] = []
    for m in HARDCODED_VALUE_IN_EVIDENCE_RE.finditer(evidence or ""):
        val = m.group(1).strip().strip('"').strip("'")
        if val and val not in literals:
            literals.append(val)
    for m in JAVA_STRING_LITERAL_RE.finditer(method_source or ""):
        val = m.group(1).strip()
        if len(val) >= 3 and val not in literals:
            literals.append(val)
    return literals


def _poc_credential_values(poc: str) -> List[str]:
    """提取 PoC 中作为凭据使用的值（非 JSON 字段名）。"""
    values: List[str] = []
    for m in re.finditer(
        r'"(?:password|passwd|pwd|secret|token|credential)"\s*:\s*"([^"]+)"',
        poc,
        re.IGNORECASE,
    ):
        values.append(m.group(1))
    for m in re.finditer(
        r"(?:password|passwd|pwd|secret)=([^\s&\"']+)",
        poc,
        re.IGNORECASE,
    ):
        values.append(m.group(1).strip('"').strip("'"))
    return values


def poc_uses_unverified_guesses(
    poc: str, source_literals: List[str], *, candidate_type: str = ""
) -> Tuple[bool, str]:
    """
    检测 PoC 是否使用了源码中不存在的「猜测」凭据。
    返回 (has_issue, reason)。
    """
    if not (poc or "").strip():
        return False, ""
    ctype = (candidate_type or "").lower()
    if ctype not in ("hardcoded_cred", "jwt_weakness", "jwt_endpoint", "auth_weakness", "client_hash_auth"):
        return False, ""

    literal_set_lower = {lit.lower() for lit in source_literals}
    cred_values = _poc_credential_values(poc)
    if not cred_values:
        return False, ""

    for val in cred_values:
        val_lower = val.lower()
        if val_lower in literal_set_lower:
            continue
        if val_lower in GUESSED_CREDENTIAL_TOKENS and source_literals:
            return True, (
                f"PoC 使用猜测凭据值 '{val}'，源码字面量为: "
                + ", ".join(repr(l) for l in source_literals[:5])
            )
        if source_literals and val_lower not in literal_set_lower:
            # 凭据值与源码字面量完全不一致
            if any(len(lit) >= 4 for lit in source_literals):
                return True, (
                    f"PoC 凭据值 '{val}' 与源码字面量不一致: "
                    + ", ".join(repr(l) for l in source_literals[:5])
                )
    return False, ""


def apply_logic_verdict_gates(
    candidate: Dict[str, Any],
    result: Dict[str, Any],
    *,
    method_source: str = "",
    security_summary: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    LLM 分析后的确定性门禁（通用规则，不依赖项目名）。
    可能将 confirmed=true 降为 false / inconclusive。
    """
    out = dict(result)
    ctype = str(candidate.get("type") or out.get("candidate_type") or "")
    sec = security_summary or {}

    if ctype in AUTH_SURFACE_TYPES and method_has_identity_injection(method_source):
        cross = set(candidate.get("cross_signals") or [])
        # 仅有身份注入、无「匿名可访问」交叉信号 → 不是 missing authentication
        if "public_endpoint_without_auth" not in cross and "admin_op_without_role_check" not in cross:
            if out.get("confirmed"):
                out["confirmed"] = False
                out["refutation_verdict"] = "rejected"
                out["sanitizer_hit"] = (
                    "方法参数含框架身份注入注解（如 @CurrentUser/@AuthenticationPrincipal）；"
                    "已绑定认证主体，不构成「缺失认证」(CWE-306/862)。"
                    "若存在越权请改用 IDOR/水平授权 (CWE-639/862) 论证。"
                )
            elif str(out.get("refutation_verdict") or "").lower() not in ("rejected", "inconclusive"):
                out["refutation_verdict"] = "rejected"
                out["sanitizer_hit"] = out.get("sanitizer_hit") or (
                    "框架身份注入参数已 present"
                )

    if ctype == "public_endpoint" and sec.get("has_global_authenticated") and not sec.get("has_permit_all"):
        if out.get("confirmed"):
            out["confirmed"] = False
            out["refutation_verdict"] = "inconclusive"
            out["sanitizer_hit"] = (
                "SecurityFilterChain 显示 anyRequest().authenticated()，"
                "端点需已登录会话；不能仅凭缺少 @PreAuthorize 确认为匿名公开接口。"
            )
            out.setdefault("suggested_l2_reads", [])
            reads = list(out["suggested_l2_reads"])
            for p in ("*Security*Config*.java", "application.yml"):
                if p not in reads:
                    reads.append(p)
            out["suggested_l2_reads"] = reads

    elif ctype == "public_endpoint" and sec.get("has_global_authenticated") and sec.get("has_permit_all"):
        # 有全局 authenticated 也有 permitAll：无 L2 路径匹配时不应 confirmed
        if out.get("confirmed") and not sec.get("raw_preview"):
            out["confirmed"] = False
            out["refutation_verdict"] = "inconclusive"

    # PoC 字面量校验
    evidence = str(candidate.get("evidence") or "")
    literals = extract_source_literals(method_source, evidence)
    poc = str(out.get("exploit_poc") or "")
    bad_poc, poc_reason = poc_uses_unverified_guesses(
        poc, literals, candidate_type=ctype
    )
    if bad_poc and out.get("confirmed"):
        out["confirmed"] = False
        out["refutation_verdict"] = "inconclusive"
        out["poc_validation_error"] = poc_reason
        out["source_literals_for_poc"] = literals
        out.setdefault("suggested_l2_reads", [])
        out["reasoning"] = (
            (out.get("reasoning") or "")
            + f"\n[PoC 校验] {poc_reason}"
        ).strip()

    # hardcoded / jwt：有源码字面量时写入结果供报告引用
    if literals:
        out["source_literals_for_poc"] = literals

    ev = dict(out.get("evidence_levels") or {})
    if ctype in AUTH_SURFACE_TYPES and sec.get("raw_preview"):
        ev["L2_static_files"] = ev.get("L2_static_files") or "partial"
        out["evidence_levels"] = ev

    return out
