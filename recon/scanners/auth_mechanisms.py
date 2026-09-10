"""
recon/scanners/auth_mechanisms.py — 鉴权机制识别

合并 5 种鉴权形式：
1. 方法注解（@PreAuthorize, @Secured, @RolesAllowed）
2. 类级注解（Controller 类上的 @RequestMapping + @PreAuthorize）
3. Filter/Interceptor（SecurityFilterChain, ShiroFilterChain）
4. AOP 切面（@Aspect + @Before）
5. 框架默认保护（@EnableWebSecurity 默认全保护）

对每个 EntryPoint 判定其鉴权覆盖状态。
"""
from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Set

from recon.adapters.base import ReconAdapter
from recon.models import AuthMechanism, EntryPoint

logger = logging.getLogger(__name__)


def scan_auth_mechanisms(
    query_results: Dict[str, str],
    adapter: ReconAdapter,
) -> List[AuthMechanism]:
    """
    从 Joern 查询结果中识别所有鉴权/授权机制。

    Args:
        query_results: Joern 批量查询的原始结果。
        adapter: 语言/框架适配器。

    Returns:
        AuthMechanism 列表。
    """
    mechs = adapter.parse_auth_mechanisms(query_results)
    logger.info("适配器解析鉴权机制: %d 条", len(mechs))

    # 按类型统计
    type_counts: Dict[str, int] = {}
    for m in mechs:
        type_counts[m.mechanism_type] = type_counts.get(m.mechanism_type, 0) + 1
    for t, count in sorted(type_counts.items()):
        logger.info("  鉴权类型 %s: %d", t, count)

    return mechs


def resolve_entry_auth(
    entries: List[EntryPoint],
    mechs: List[AuthMechanism],
) -> Dict[str, AuthCoverage]:
    """
    对每个 EntryPoint 判定其鉴权覆盖状态。

    返回 handler -> AuthCoverage 映射，供 attack_surface scanner 使用。
    """
    # 构建索引
    # ① 方法级精确匹配
    method_auth: Dict[str, List[AuthMechanism]] = {}
    # ② 类级前缀匹配
    class_auth: Dict[str, List[AuthMechanism]] = {}
    # ③ 全局/框架默认（不含具体的 URL 模式规则）
    global_auth: List[AuthMechanism] = []
    # ③-b 具体的 URL 模式规则（按声明顺序，first-match-wins 参与按 URL 匹配）
    url_pattern_rules: List[AuthMechanism] = []
    # ④ permitAll 集合（精确 handler）
    permit_all_targets: Set[str] = set()

    for m in mechs:
        if m.is_permit_all:
            permit_all_targets.add(m.target)
        if m.coverage == "method":
            method_auth.setdefault(m.target, []).append(m)
        elif m.coverage == "class":
            class_auth[m.target] = class_auth.get(m.target, []) + [m]
        elif m.coverage == "url_pattern":
            # 真正的 URL 路径模式（如 "/admin/**"、"**"）参与按 URL 匹配；
            # 非 URL 模式的兜底 filter（target="SecurityFilterChain"）按全局处理
            if m.target and (m.target.startswith("/") or m.target == "**"):
                url_pattern_rules.append(m)
            else:
                global_auth.append(m)
        elif m.coverage == "global":
            global_auth.append(m)

    result: Dict[str, AuthCoverage] = {}
    for ep in entries:
        coverage = _resolve_single(ep, method_auth, class_auth, global_auth, permit_all_targets, url_pattern_rules)
        result[ep.handler] = coverage

    # 统计
    protected = sum(1 for c in result.values() if c.is_protected)
    unprotected = len(result) - protected
    logger.info("鉴权覆盖: %d/%d 入口受保护, %d 无鉴权", protected, len(result), unprotected)
    return result


class AuthCoverage:
    """单个入口的鉴权覆盖状态"""

    def __init__(
        self,
        handler: str,
        is_protected: bool,
        mechanisms: List[AuthMechanism],
        is_permit_all: bool = False,
    ):
        self.handler = handler
        self.is_protected = is_protected
        self.mechanisms = mechanisms
        self.is_permit_all = is_permit_all

    @property
    def mechanism_types(self) -> List[str]:
        return [m.mechanism_type for m in self.mechanisms]

    @property
    def annotations(self) -> List[str]:
        result: List[str] = []
        for m in self.mechanisms:
            result.extend(m.annotations)
        return result

    def summary(self) -> str:
        if self.is_permit_all:
            return "permitAll (explicit)"
        if not self.is_protected:
            return "NO AUTH"
        types = ", ".join(set(self.mechanism_types))
        annots = ", ".join(set(self.annotations)) or "N/A"
        return f"protected ({types}) [{annots}]"


def _ant_match(pattern: str, url: str) -> bool:
    """
    Ant 风格路径匹配（简化版）：
      **  -> 任意层级的任意字符
      *   -> 单段内任意字符（不含 '/'）
    其余字符按字面量匹配。
    """
    if not pattern or not url:
        return False
    if pattern == "**":
        return True
    regex = ""
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            if i + 1 < n and pattern[i + 1] == "*":
                regex += ".*"
                i += 2
                continue
            regex += "[^/]*"
        else:
            regex += re.escape(c)
        i += 1
    return re.match("^" + regex + "$", url) is not None


def _resolve_single(
    ep: EntryPoint,
    method_auth: Dict[str, List[AuthMechanism]],
    class_auth: Dict[str, List[AuthMechanism]],
    global_auth: List[AuthMechanism],
    permit_all_targets: Set[str],
    url_pattern_rules: List[AuthMechanism],
) -> AuthCoverage:
    """解析单个入口的鉴权覆盖"""

    handler = ep.handler
    url = ep.url or ""

    # ① 方法级精确命中
    if handler in method_auth:
        mechs = method_auth[handler]
        is_permit = handler in permit_all_targets
        return AuthCoverage(
            handler=handler,
            is_protected=not is_permit,
            mechanisms=mechs,
            is_permit_all=is_permit,
        )

    # ② 类级前缀命中（handler = com.example.UserController.method -> 匹配 com.example.UserController）
    class_name = handler.rsplit(".", 1)[0] if "." in handler else ""
    if class_name and class_name in class_auth:
        mechs = class_auth[class_name]
        is_permit = handler in permit_all_targets or class_name in permit_all_targets
        return AuthCoverage(
            handler=handler,
            is_protected=not is_permit,
            mechanisms=mechs,
            is_permit_all=is_permit,
        )

    # ③ URL 模式规则匹配（Spring Security first-match-wins）
    #    入口 URL 已由 engine._extract_urls_from_source 回填，可在此按 SecurityConfig 的
    #    逐条 matcher 规则精确判定：permitAll 路径 -> 无鉴权；authenticated/hasRole 等 -> 需认证。
    if url_pattern_rules and url:
        for rule in url_pattern_rules:
            if _ant_match(rule.target, url):
                return AuthCoverage(
                    handler=handler,
                    is_protected=not rule.is_permit_all,
                    mechanisms=[rule],
                    is_permit_all=rule.is_permit_all,
                )

    # ④ 全局保护（框架默认 / 兜底 filter）
    if global_auth:
        has_global = any(
            m.mechanism_type in ("framework_default", "filter")
            and not m.is_permit_all
            for m in global_auth
        )
        is_permit = handler in permit_all_targets
        if has_global and not is_permit:
            return AuthCoverage(
                handler=handler,
                is_protected=True,
                mechanisms=global_auth,
            )

    # ⑤ 无任何保护
    return AuthCoverage(
        handler=handler,
        is_protected=False,
        mechanisms=[],
    )
