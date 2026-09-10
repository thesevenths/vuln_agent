"""
recon/adapters/java_spring.py — Java / Spring Boot 适配器

复用 queries.py 中已有的 java_logic_queries，
新增 Recon 专用查询（WebSocket / MQ / Scheduled / 文件上传等），
并将 Joern 原始输出解析为 recon.models 数据模型。
"""
from __future__ import annotations

import logging
import os
import re
from typing import Dict, List

try:
    import yaml
except ImportError:  # pragma: no cover - 运行时已确认 PyYAML 可用
    yaml = None

from recon.adapters.base import ReconAdapter
from recon.models import (
    AuthMechanism,
    EntryPoint,
    ParamInfo,
    ProjectInfo,
    SensitiveOperation,
)

logger = logging.getLogger(__name__)

# ── 从 queries.py 导入已验证的 java_logic_queries 进行复用 ──────────────────
import queries as _q

_EXISTING = _q.java_logic_queries

# 需要复用的查询名
_REUSE_NAMES = [
    "endpoint_enumeration",
    "auth_guards",
    "class_level_auth",
    "aop_auth_aspects",
    "custom_auth_annotations",
    "framework_security_defaults",
    "security_filter_chain",
    "sensitive_operations",
    "public_endpoints",
    "shiro_auth_guards",
    "shiro_security_config",
    "jaxrs_auth_guards",
    "jaxrs_unprotected_resources",
]

_RECON_QUERY_NAMES = [
    "websocket_endpoints",
    "scheduled_tasks",
    "mq_consumers",
    "file_upload_handlers",
    "deserialization_entries",
    "rpc_endpoints",
    "content_type_consumers",
    "endpoint_parameters",
    "entry_callees",
]

# Spring Security FilterChain 规则解析配置（从 rules/security_controls.yaml 加载）。
# 路径：recon/adapters/java_spring.py -> ../rules/security_controls.yaml
_RULES_YAML = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "rules", "security_controls.yaml",
)

# 配置缺失/解析失败时的内置默认值（与 yaml 中 spring_security_filter_chain 保持一致）
_DEFAULT_FILTER_CHAIN_CFG: Dict[str, object] = {
    "matcher_methods": ["requestMatchers", "antMatchers", "mvcMatchers", "regexMatchers"],
    "any_request_keyword": "anyRequest",
    "permit_rules": ["permitAll", "anonymous"],
    "protected_rules": ["authenticated", "denyAll", "hasRole", "hasAuthority",
                        "hasAnyRole", "hasAnyAuthority"],
}


class JavaSpringAdapter(ReconAdapter):
    """Java / Spring Boot 项目适配器"""

    def __init__(self):
        super().__init__()
        self._filter_chain_cfg = self._load_filter_chain_cfg()

    @staticmethod
    def _load_filter_chain_cfg() -> Dict[str, object]:
        """加载 spring_security_filter_chain 配置段；失败回退内置默认值。"""
        if yaml is None:
            return dict(_DEFAULT_FILTER_CHAIN_CFG)
        try:
            with open(_RULES_YAML, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            cfg = data.get("spring_security_filter_chain") or {}
            merged = dict(_DEFAULT_FILTER_CHAIN_CFG)
            for key in _DEFAULT_FILTER_CHAIN_CFG:
                if cfg.get(key):
                    merged[key] = cfg[key]
            return merged
        except Exception as e:  # 配置缺失/格式错误 -> 不影响主流程
            logger.warning(
                "[java_spring] 加载 spring_security_filter_chain 配置失败，使用内置默认值: %s", e)
            return dict(_DEFAULT_FILTER_CHAIN_CFG)

    # ── 检测 ─────────────────────────────────────────────────────────────────

    def detect(self, source_path: str) -> bool:
        """检查 pom.xml / build.gradle 是否存在"""
        for name in ("pom.xml", "build.gradle", "build.gradle.kts"):
            if os.path.exists(os.path.join(source_path, name)):
                return True
        return False

    @property
    def language(self) -> str:
        return "java"

    @property
    def framework_hint(self) -> str:
        return "spring_boot"

    # ── Joern 查询 ───────────────────────────────────────────────────────────

    def get_joern_queries(self) -> Dict[str, str]:
        """合并复用的现有查询 + Recon 新增查询"""
        result: Dict[str, str] = {}
        for name in _REUSE_NAMES:
            if name in _EXISTING:
                result[name] = _EXISTING[name]
        # Recon 查询从 queries.py 导入
        for name in _RECON_QUERY_NAMES:
            if name in _EXISTING:
                result[name] = _EXISTING[name]
        return result

    # ── 文件扫描模式 ──────────────────────────────────────────────────────────

    def get_file_patterns(self) -> Dict[str, List[str]]:
        return {
            "build_files": ["pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle"],
            "config_files": [
                "application*.yml", "application*.yaml", "application*.properties",
                "bootstrap*.yml", "bootstrap*.yaml",
                "logback*.xml", "log4j2*.xml",
            ],
            "ci_cd_files": [
                "Jenkinsfile", ".github/workflows/*.yml", ".gitlab-ci.yml",
                ".travis.yml", "azure-pipelines.yml",
            ],
            "container_files": [
                "Dockerfile", "docker-compose*.yml",
                "k8s/*.yaml", "k8s/*.yml", "helm/*/values.yaml",
            ],
        }

    # ── 解析入口点 ────────────────────────────────────────────────────────────

    def parse_entry_points(self, query_results: Dict[str, str]) -> List[EntryPoint]:
        entries: List[EntryPoint] = []

        # 构建 handler -> params 映射（从 endpoint_parameters 查询结果）
        handler_params = self._parse_endpoint_parameters(query_results)
        # 构建 handler -> callees 映射（从 entry_callees 查询结果）
        handler_callees = self._parse_entry_callees(query_results)

        # HTTP 端点
        for line in (query_results.get("endpoint_enumeration") or "").splitlines():
            line = line.strip().strip('",')
            if not line or "|" not in line:
                continue
            parts = line.split("|")
            handler = parts[0].strip()
            file_path = ""
            line_num = 0
            annotations: List[str] = []
            for p in parts[1:]:
                p = p.strip()
                if p.startswith("file="):
                    file_path = p[5:].strip().strip('"')
                elif p.startswith("line="):
                    try:
                        line_num = int(p[5:].strip())
                    except ValueError:
                        pass
                elif p.startswith("annotations="):
                    annotations = [a.strip() for a in p[12:].split(",") if a.strip()]
            http_method = self._infer_http_method(annotations)
            # 从 Joern 查询结果中获取参数，如果没有则默认为空（后续由 source 回填）
            params = handler_params.get(handler, [])
            callees = handler_callees.get(handler, [])
            entries.append(EntryPoint(
                url="",
                http_method=http_method,
                handler=handler,
                file=file_path,
                line=line_num,
                entry_type="http",
                annotations=annotations,
                parameters=params,
                callees=callees,
            ))

        # WebSocket
        for line in (query_results.get("websocket_endpoints") or "").splitlines():
            ep = self._parse_tagged_line(line, "WS_ENDPOINT", "websocket")
            if ep:
                entries.append(ep)

        # 定时任务
        for line in (query_results.get("scheduled_tasks") or "").splitlines():
            ep = self._parse_tagged_line(line, "SCHEDULED", "scheduled")
            if ep:
                entries.append(ep)

        # MQ 消费者
        for line in (query_results.get("mq_consumers") or "").splitlines():
            ep = self._parse_tagged_line(line, "MQ_CONSUMER", "mq")
            if ep:
                entries.append(ep)

        # 文件上传
        for line in (query_results.get("file_upload_handlers") or "").splitlines():
            ep = self._parse_tagged_line(line, "FILE_UPLOAD", "file_upload")
            if ep:
                entries.append(ep)

        # 反序列化入口
        for line in (query_results.get("deserialization_entries") or "").splitlines():
            line = line.strip().strip('",')
            m = re.search(r"caller=([^\s|]+)", line)
            sink_m = re.search(r"sink=([^\s|]+)", line)
            file_m = re.search(r"file=([^\s|]+)", line)
            line_m = re.search(r"line=(\d+)", line)
            if m:
                entries.append(EntryPoint(
                    url="",
                    http_method="N/A",
                    handler=m.group(1).strip(),
                    file=file_m.group(1).strip().strip('"') if file_m else "",
                    line=int(line_m.group(1)) if line_m else 0,
                    entry_type="deserialization",
                ))

        # RPC
        for line in (query_results.get("rpc_endpoints") or "").splitlines():
            ep = self._parse_tagged_line(line, "RPC_ENDPOINT", "rpc")
            if ep:
                entries.append(ep)

        return entries

    # ── 解析鉴权机制 ──────────────────────────────────────────────────────────

    def parse_auth_mechanisms(self, query_results: Dict[str, str]) -> List[AuthMechanism]:
        mechs: List[AuthMechanism] = []

        # ① 方法级注解
        for line in (query_results.get("auth_guards") or "").splitlines():
            line = line.strip().strip('",')
            m = re.search(r"(?:ANNOTATION_GUARD|JAXRS_ANNOTATION_GUARD)\s*\|\s*([^\s|]+)", line)
            annot_m = re.search(r"annotations?=(.+?)(?:\s*$|\s*\|)", line)
            if m:
                annots = [a.strip() for a in annot_m.group(1).split(",")] if annot_m else []
                mechs.append(AuthMechanism(
                    mechanism_type="annotation",
                    target=m.group(1).strip(),
                    annotations=annots,
                    coverage="method",
                ))

        # ② 类级注解
        for line in (query_results.get("class_level_auth") or "").splitlines():
            line = line.strip().strip('",')
            m = re.search(r"CLASS_AUTH\s*\|\s*([^\s|]+)", line)
            annot_m = re.search(r"annotations=(.+?)(?:\s*\|)", line)
            if m:
                annots = [a.strip() for a in annot_m.group(1).split(",")] if annot_m else []
                mechs.append(AuthMechanism(
                    mechanism_type="class_level",
                    target=m.group(1).strip(),
                    annotations=annots,
                    coverage="class",
                ))

        # ③ Filter/Interceptor (SecurityConfig)
        sec_raw = query_results.get("security_filter_chain", "")
        if sec_raw and len(sec_raw) > 20:
            file_m = re.search(r"file=([^\s|]+)", sec_raw)
            cfg_file = file_m.group(1).strip().strip('"') if file_m else ""
            rules = self._parse_security_filter_rules(sec_raw, cfg_file)
            if rules:
                mechs.extend(rules)
            else:
                # 兜底：未解析出具体 URL 规则时，保留「存在 SecurityFilterChain」信号
                mechs.append(AuthMechanism(
                    mechanism_type="filter",
                    target="SecurityFilterChain",
                    config_file=cfg_file,
                    coverage="url_pattern",
                    detail=sec_raw[:500],
                ))

        # ④ AOP 切面
        for line in (query_results.get("aop_auth_aspects") or "").splitlines():
            line = line.strip().strip('",')
            m = re.search(r"AOP_AUTH\s*\|\s*([^\s|]+)", line)
            if m:
                mechs.append(AuthMechanism(
                    mechanism_type="aop",
                    target=m.group(1).strip(),
                    coverage="method",
                ))

        # ⑤ 框架默认保护
        fw_raw = query_results.get("framework_security_defaults", "")
        if fw_raw and ("ENABLE_SECURITY" in fw_raw or "NO_CUSTOM_FILTER_CHAIN" in fw_raw):
            mechs.append(AuthMechanism(
                mechanism_type="framework_default",
                target="Spring Security defaults",
                coverage="global",
                detail="All endpoints require authentication unless explicitly permitAll",
            ))

        # 自定义鉴权注解
        for line in (query_results.get("custom_auth_annotations") or "").splitlines():
            line = line.strip().strip('",')
            m = re.search(r"method=([^\s|]+)", line)
            names_m = re.search(r"names=(.+?)(?:\s*\|)", line)
            if m:
                annots = [a.strip() for a in names_m.group(1).split(",")] if names_m else []
                mechs.append(AuthMechanism(
                    mechanism_type="annotation",
                    target=m.group(1).strip(),
                    annotations=annots,
                    coverage="method",
                ))

        return mechs

    def _parse_security_filter_rules(self, sec_raw: str, cfg_file: str) -> List[AuthMechanism]:
        """
        解析 Spring Security 配置（SecurityFilterChain / authorizeHttpRequests /
        authorizeRequests）中的逐条 URL 规则，识别 .permitAll() / .hasRole() /
        .authenticated() / .denyAll() / .anonymous() 等并映射到具体路径。

        旧实现只登记「存在 SecurityFilterChain」且 permitAll 硬编码为 false；
        现逐条解析，使 permitAll 路径能被正确识别为「无需认证」、受保护路径
        被识别为「需认证」，供 resolve_entry_auth 按 URL 模式精确匹配入口。

        查询返回的 sec_raw 含配置方法源码（m.code.take(2000)），可直接正则抽取
        "matcher(...).rule(...)" 链。

        所有 matcher 方法名 / 规则关键字均来自 security_controls.yaml 的
        spring_security_filter_chain 配置段（详见 _load_filter_chain_cfg），
        无需改代码即可扩展。

        Returns:
            每条 (matcher, rule) 对应的 AuthMechanism（coverage=url_pattern）；
            未解析出任何规则时返回空列表（调用方走兜底）。
        """
        cfg = getattr(self, "_filter_chain_cfg", None) or dict(_DEFAULT_FILTER_CHAIN_CFG)
        rules: List[AuthMechanism] = []
        if not sec_raw:
            return rules

        matchers = cfg.get("matcher_methods", _DEFAULT_FILTER_CHAIN_CFG["matcher_methods"])
        any_kw = cfg.get("any_request_keyword", _DEFAULT_FILTER_CHAIN_CFG["any_request_keyword"])
        permit_rules = {r.lower() for r in cfg.get("permit_rules", _DEFAULT_FILTER_CHAIN_CFG["permit_rules"])}
        all_rules = list(permit_rules) + list(
            cfg.get("protected_rules", _DEFAULT_FILTER_CHAIN_CFG["protected_rules"]))
        if not all_rules:
            return rules

        # 从配置动态构建正则（按配置顺序拼接，IGNORECASE 匹配）
        matcher_alt = "|".join(re.escape(m) for m in matchers)
        rule_alt = "|".join(re.escape(r) for r in all_rules)

        # matcher(...) 紧跟 .rule(...) 的配对（URL 串内不含 ')'，可跨行匹配）
        pair_re = re.compile(
            rf"({matcher_alt})\s*\(([^)]*)\)"
            rf"\s*\.\s*"
            rf"({rule_alt})\s*\(([^)]*)\)",
            re.IGNORECASE,
        )
        # anyRequest() 紧跟 .rule(...)
        any_re = re.compile(
            rf"{re.escape(any_kw)}\s*\(\s*\)\s*\."
            rf"({rule_alt})\s*\(([^)]*)\)",
            re.IGNORECASE,
        )

        def _patterns(args: str) -> List[str]:
            out: List[str] = []
            for part in args.split(","):
                part = part.strip()
                qm = re.search(r'"([^"]*)"', part)
                if qm:
                    p = qm.group(1).strip()
                    if p:
                        out.append(p)
                elif re.match(r"^[A-Z_][A-Z0-9_]*$", part):
                    # 常量名（如 HttpMethod.POST 不在内，仅纯常量），原样保留供后续解析
                    out.append(part)
            return out

        def _is_permit(rule: str) -> bool:
            return rule.lower() in permit_rules

        for m in pair_re.finditer(sec_raw):
            matcher, raw_args, rule, _rule_args = m.group(1), m.group(2), m.group(3), m.group(4)
            patterns = _patterns(raw_args) or [matcher]
            for pat in patterns:
                rules.append(AuthMechanism(
                    mechanism_type="filter",
                    target=pat,
                    config_file=cfg_file,
                    coverage="url_pattern",
                    is_permit_all=_is_permit(rule),
                    detail=f"{matcher}({raw_args}) -> {rule}",
                ))

        for m in any_re.finditer(sec_raw):
            rule = m.group(1)
            rules.append(AuthMechanism(
                mechanism_type="filter",
                target="**",
                config_file=cfg_file,
                coverage="url_pattern",
                is_permit_all=_is_permit(rule),
                detail=f"anyRequest() -> {rule}",
            ))

        return rules

    # ── 解析敏感操作 ──────────────────────────────────────────────────────────

    def parse_sensitive_operations(self, query_results: Dict[str, str]) -> List[SensitiveOperation]:
        ops: List[SensitiveOperation] = []

        for line in (query_results.get("sensitive_operations") or "").splitlines():
            line = line.strip().strip('",')
            if not line:
                continue
            # Joern query format:
            # SENSITIVE_OP | ${c.name} | method= | caller= | caller_chain=...;... | file= | line=
            if "SENSITIVE_OP" not in line:
                continue  # skip Joern REPL debug noise
            parts = line.split("|")
            if len(parts) < 2:
                continue
            # parts[0] = "SENSITIVE_OP" (tag), parts[1] = c.name (call name)
            call_name = parts[1].strip()
            method_full_name = ""
            caller_name = ""
            caller_chain_raw = ""
            file_path = ""
            line_num = 0
            for p in parts[2:]:
                p = p.strip()
                if p.startswith("method="):
                    method_full_name = p[7:].strip()
                elif p.startswith("caller_chain="):
                    caller_chain_raw = p[13:].strip()
                elif p.startswith("caller="):
                    caller_name = p[7:].strip()
                elif p.startswith("file="):
                    file_path = p[5:].strip().strip('"')
                elif p.startswith("line="):
                    try:
                        line_num = int(p[5:].strip())
                    except ValueError:
                        pass

            # 解析 caller_chain: "method1;method2" -> ["method1", "method2"]
            caller_chain = [c.strip() for c in caller_chain_raw.split(";") if c.strip()] if caller_chain_raw else []

            # Use call_name as handler; method_full_name for classification
            op_type = self._classify_operation(call_name, method_full_name)
            risk = self._risk_for_type(op_type)
            ops.append(SensitiveOperation(
                operation_type=op_type,
                handler=call_name,
                sink_call=call_name,
                file=file_path,
                line=line_num,
                risk_level=risk,
                caller_chain=caller_chain,
            ))

        return ops

    # ── 丰富项目信息 ──────────────────────────────────────────────────────────

    def enrich_project_info(self, source_path: str, info: ProjectInfo) -> ProjectInfo:
        # 检测 Spring Boot Actuator
        actuator_yml = []
        for root, _dirs, files in os.walk(source_path):
            for f in files:
                if f.startswith("application") and (f.endswith(".yml") or f.endswith(".yaml") or f.endswith(".properties")):
                    actuator_yml.append(os.path.relpath(os.path.join(root, f), source_path))
        if actuator_yml:
            info.config_files.extend(actuator_yml)
        return info

    # ── 解析端点参数（Joern 查询） ────────────────────────────────────────

    @staticmethod
    def _parse_endpoint_parameters(query_results: Dict[str, str]) -> Dict[str, List[ParamInfo]]:
        """
        解析 endpoint_parameters 查询结果，构建 handler -> List[ParamInfo] 映射。

        查询输出格式：
          ENDPOINT_PARAM | method=<fullName> | name=<paramName> | type=<javaType> | annotations=<ann1,ann2>
        """
        handler_params: Dict[str, List[ParamInfo]] = {}
        raw = query_results.get("endpoint_parameters") or ""
        if not raw:
            return handler_params

        for line in raw.splitlines():
            line = line.strip().strip('",')
            if "ENDPOINT_PARAM" not in line:
                continue
            method_m = re.search(r"method=([^\s|]+)", line)
            name_m = re.search(r"name=([^\s|]+)", line)
            type_m = re.search(r"type=([^\s|]+)", line)
            ann_m = re.search(r"annotations=([^\s|]+)", line)
            if not (method_m and name_m):
                continue
            method = method_m.group(1).strip()
            param_name = name_m.group(1).strip()
            java_type = type_m.group(1).strip() if type_m else ""
            ann_raw = ann_m.group(1).strip() if ann_m else "implicit"

            ann_list = [a.strip() for a in ann_raw.split(",") if a.strip()]
            if "implicit" in ann_list:
                param_type = "implicit"
            else:
                param_type = ann_list[0]

            handler_params.setdefault(method, []).append(ParamInfo(
                name=param_name,
                param_type=param_type,
                java_type=java_type,
            ))

        logger.info("Joern 参数提取: %d 个方法有参数信息", len(handler_params))
        return handler_params

    @staticmethod
    def _parse_entry_callees(query_results: Dict[str, str]) -> Dict[str, List[str]]:
        """
        解析 entry_callees 查询结果，构建 handler -> List[callee_fullName] 映射。

        查询输出格式：
          ENTRY_CALLEE | entry=<handler> | callee=<calleeFn> | depth=1 | calleeName=<shortName>
        """
        handler_callees: Dict[str, List[str]] = {}
        raw = query_results.get("entry_callees") or ""
        if not raw:
            return handler_callees

        for line in raw.splitlines():
            line = line.strip().strip('",')
            if "ENTRY_CALLEE" not in line:
                continue
            entry_m = re.search(r"entry=([^\s|]+)", line)
            callee_m = re.search(r"callee=([^\s|]+)", line)
            if not (entry_m and callee_m):
                continue
            entry_handler = entry_m.group(1).strip()
            callee_fn = callee_m.group(1).strip()
            # 过滤掉 <operator> 和 lambda 等无意义 callee
            if callee_fn.startswith("<") or "$" in callee_fn:
                continue
            if callee_fn not in handler_callees.get(entry_handler, []):
                handler_callees.setdefault(entry_handler, []).append(callee_fn)

        logger.info("Joern callee 追溯: %d 个入口有 callee 信息", len(handler_callees))
        return handler_callees

    # ── 内部工具方法 ──────────────────────────────────────────────────────────

    @staticmethod
    def _infer_http_method(annotations: List[str]) -> str:
        mapping = {
            "GetMapping": "GET", "PostMapping": "POST",
            "PutMapping": "PUT", "DeleteMapping": "DELETE",
            "PatchMapping": "PATCH",
        }
        for a in annotations:
            if a in mapping:
                return mapping[a]
        return "ANY"

    @staticmethod
    def _parse_tagged_line(line: str, tag: str, entry_type: str) -> EntryPoint | None:
        line = line.strip().strip('",')
        if tag not in line:
            return None
        handler_m = re.search(rf"{tag}\s*\|\s*([^\s|]+)", line)
        file_m = re.search(r"file=([^\s|]+)", line)
        line_m = re.search(r"line=(\d+)", line)
        annot_m = re.search(r"annotations=(.+?)(?:\s*$|\s*\|)", line)
        if not handler_m:
            return None
        annotations = [a.strip() for a in annot_m.group(1).split(",") if a.strip()] if annot_m else []
        return EntryPoint(
            url="",
            http_method="N/A",
            handler=handler_m.group(1).strip(),
            file=file_m.group(1).strip().strip('"') if file_m else "",
            line=int(line_m.group(1)) if line_m else 0,
            entry_type=entry_type,
            annotations=annotations,
        )

    @staticmethod
    def _classify_operation(handler: str, calls: str) -> str:
        combined = (handler + " " + calls).lower()
        if any(k in combined for k in ("transfer", "withdraw", "deposit", "pay", "refund", "balance")):
            return "financial"
        if any(k in combined for k in ("grantrole", "revokerole", "createuser", "deleteuser", "resetpassword", "assignpermission")):
            return "auth_change"
        if any(k in combined for k in ("runtime.exec", "processbuilder", "exec(", "process")):
            return "cmd_exec"
        if any(k in combined for k in ("resttemplate", "webclient", "feignclient", "httpclient", "sendmail", "sendemail")):
            return "external_call"
        if any(k in combined for k in ("fileinputstream", "fileoutputstream", "files.", "new file")):
            return "file_io"
        return "db_write"

    @staticmethod
    def _risk_for_type(op_type: str) -> str:
        return {
            "financial": "critical",
            "auth_change": "critical",
            "cmd_exec": "critical",
            "external_call": "high",
            "file_io": "high",
            "db_write": "high",
        }.get(op_type, "high")
