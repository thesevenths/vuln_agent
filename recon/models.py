"""
recon/models.py — 侦查模块数据模型

所有数据结构均使用 dataclass，支持 JSON 序列化/反序列化，
便于持久化到 checkpoints 目录和跨扫描复用。
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# 项目结构
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ModuleInfo:
    """子模块信息"""
    name: str                       # "user-service"
    path: str                       # "user-service/"
    build_file: str                 # "user-service/pom.xml"
    source_dirs: List[str] = field(default_factory=list)

@dataclass
class ProjectInfo:
    """项目结构感知结果"""
    language: str                   # "java"
    framework: str                  # "spring_boot" / "django" / "flask"
    build_system: str               # "maven" / "gradle" / "pip" / "poetry"
    modules: List[ModuleInfo] = field(default_factory=list)
    config_files: List[str] = field(default_factory=list)
    ci_cd_files: List[str] = field(default_factory=list)
    container_files: List[str] = field(default_factory=list)
    dependency_count: int = 0
    source_path: str = ""           # 用于缓存校验

# ─────────────────────────────────────────────────────────────────────────────
# 入口点
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ParamInfo:
    """入口参数信息"""
    name: str                       # "id"
    param_type: str                 # "PathVariable" / "RequestParam" / "RequestBody"
    java_type: str = ""             # "Long" / "String"

@dataclass
class EntryPoint:
    """外部暴露入口"""
    url: str                        # "/api/users/{id}" 或 "kafka:topic-name"
    http_method: str                # "GET" / "POST" / "N/A"
    handler: str                    # "com.example.UserController.getUser"
    file: str = ""
    line: int = 0
    entry_type: str = "http"        # http/websocket/mq/scheduled/rpc/file_upload/deserialization
    content_types: List[str] = field(default_factory=list)
    parameters: List[ParamInfo] = field(default_factory=list)
    annotations: List[str] = field(default_factory=list)
    callees: List[str] = field(default_factory=list)  # 向下 2 层被调用方法全名

# ─────────────────────────────────────────────────────────────────────────────
# 鉴权机制
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AuthMechanism:
    """鉴权/授权机制"""
    mechanism_type: str             # annotation / filter / aop / framework_default / class_level
    target: str                     # 方法全限定名 / 类名 / URL 路径
    annotations: List[str] = field(default_factory=list)
    config_file: str = ""
    coverage: str = "method"        # global / class / method / url_pattern
    is_permit_all: bool = False
    detail: str = ""                # 补充说明（如 SecurityConfig 规则摘要）

# ─────────────────────────────────────────────────────────────────────────────
# 调用链节点
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CallChainNode:
    """调用链中的一个节点（方法级）"""
    method: str                     # 方法全限定名 "com.example.UserService.save"
    file: str = ""                  # 源文件相对路径
    line: int = 0                   # 行号

# ─────────────────────────────────────────────────────────────────────────────
# 敏感操作
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SensitiveOperation:
    """高价值敏感操作（Sink 候选）"""
    operation_type: str             # db_write / file_io / cmd_exec / external_call / auth_change / financial
    handler: str                    # 方法全限定名
    sink_call: str                  # "jdbcTemplate.update" / "Runtime.exec"
    file: str = ""
    line: int = 0
    risk_level: str = "high"        # critical / high / medium
    reachable_from: List[str] = field(default_factory=list)
    caller_chain: List[str] = field(default_factory=list)  # 向上 2 层 caller 方法名

# ─────────────────────────────────────────────────────────────────────────────
# 攻击路径
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AttackPath:
    """入口 → 中间处理 → 高价值操作 的攻击路径"""
    entry: str                      # EntryPoint handler
    intermediate: List[CallChainNode] = field(default_factory=list)  # 调用链节点
    sink: str = ""                  # SensitiveOperation handler
    has_auth: bool = False
    auth_mechanisms: List[str] = field(default_factory=list)
    missing_controls: List[str] = field(default_factory=list)   # ["CWE-862", "CWE-639"]

# ─────────────────────────────────────────────────────────────────────────────
# 攻击面地图（最终产出）
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AttackSurfaceMap:
    """
    完整攻击面地图 — 侦查模块的最终产出。

    融合项目结构、入口清单、鉴权机制、敏感操作、攻击路径，
    持久化为 JSON 供 logic_scan / taint_scan / Planner 消费。
    """
    project_info: ProjectInfo = field(default_factory=lambda: ProjectInfo(language="java", framework="", build_system=""))
    entry_points: List[EntryPoint] = field(default_factory=list)
    auth_mechanisms: List[AuthMechanism] = field(default_factory=list)
    sensitive_operations: List[SensitiveOperation] = field(default_factory=list)
    attack_paths: List[AttackPath] = field(default_factory=list)
    content_type_entries: Dict[str, List[str]] = field(default_factory=dict)
    coverage_summary: Dict[str, int] = field(default_factory=dict)
    scanned_at: str = ""

    # ── 序列化 ──────────────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """转为可 JSON 序列化的字典。"""
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent, default=str)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AttackSurfaceMap":
        """从字典反序列化（容忍旧版本缺少的字段）。"""
        def _build(cls_inner, d):
            if not isinstance(d, dict):
                return d
            kwargs = {}
            for f in cls_inner.__dataclass_fields__:
                if f in d:
                    kwargs[f] = d[f]
            return cls_inner(**kwargs)

        pi = _build(ProjectInfo, data.get("project_info") or {})
        eps = []
        for e in (data.get("entry_points") or []):
            ep = _build(EntryPoint, e)
            # 将 parameters 中的 dict 转为 ParamInfo
            if ep.parameters and isinstance(ep.parameters[0], dict):
                ep.parameters = [
                    ParamInfo(**{k: v for k, v in p.items() if k in ParamInfo.__dataclass_fields__})
                    for p in ep.parameters
                ]
            eps.append(ep)
        ams = [_build(AuthMechanism, a) for a in (data.get("auth_mechanisms") or [])]
        sos = [_build(SensitiveOperation, s) for s in (data.get("sensitive_operations") or [])]
        # 反序列化 attack_paths，处理 intermediate 中的 CallChainNode
        raw_aps = data.get("attack_paths") or []
        aps = []
        for ap_data in raw_aps:
            if not isinstance(ap_data, dict):
                continue
            # 将 intermediate 列表转为 CallChainNode（兼容旧格式 str 和新格式 dict）
            raw_intermediate = ap_data.get("intermediate") or []
            nodes = []
            for item in raw_intermediate:
                if isinstance(item, dict):
                    nodes.append(CallChainNode(**{k: item[k] for k in CallChainNode.__dataclass_fields__ if k in item}))
                elif isinstance(item, str):
                    nodes.append(CallChainNode(method=item))
            kwargs = {f: ap_data[f] for f in AttackPath.__dataclass_fields__ if f in ap_data and f != "intermediate"}
            kwargs["intermediate"] = nodes
            aps.append(AttackPath(**kwargs))
        return cls(
            project_info=pi,
            entry_points=eps,
            auth_mechanisms=ams,
            sensitive_operations=sos,
            attack_paths=aps,
            content_type_entries=data.get("content_type_entries") or {},
            coverage_summary=data.get("coverage_summary") or {},
            scanned_at=data.get("scanned_at") or "",
        )

    @classmethod
    def from_json(cls, text: str) -> "AttackSurfaceMap":
        return cls.from_dict(json.loads(text))

    # ── 统计摘要 ─────────────────────────────────────────────────────────────

    def summary(self) -> str:
        """一行摘要，供日志打印。"""
        pi = self.project_info
        return (
            f"Recon: {pi.language}/{pi.framework} | "
            f"入口 {len(self.entry_points)} | "
            f"鉴权 {len(self.auth_mechanisms)} | "
            f"敏感操作 {len(self.sensitive_operations)} | "
            f"攻击路径 {len(self.attack_paths)}"
        )
