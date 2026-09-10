"""
Bridge to RuoJi6/java-audit-skills (external Claude Code playbooks).

This module does NOT run Claude Agent Teams. It loads SKILL.md playbooks so the
local Planner can follow the same audit methodology while using Joern/FileTool.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
import os
import re
import subprocess


# Maps our skill/tool ids to upstream folder names under skills/
PLAYBOOK_ALIASES: Dict[str, str] = {
    "java-route-mapper": "java-route-mapper",
    "java_route_mapper": "java-route-mapper",
    "java-route-tracer": "java-route-tracer",
    "java_route_tracer": "java-route-tracer",
    "java-sql-audit": "java-sql-audit",
    "java_sql_audit": "java-sql-audit",
    "java-auth-audit": "java-auth-audit",
    "java_auth_audit": "java-auth-audit",
    "java-file-upload-audit": "java-file-upload-audit",
    "java-file-read-audit": "java-file-read-audit",
    "java-xxe-audit": "java-xxe-audit",
    "java-vuln-scanner": "java-vuln-scanner",
    "java-audit-pipeline": "java-audit-pipeline",
    "java_audit_pipeline": "java-audit-pipeline",
    "java-log-audit": "java-log-audit",
    "java_log_audit": "java-log-audit",
    "audit-skills": "audit-skills",
}

DEFAULT_PLAYBOOK_IDS: List[str] = [
    "java-route-mapper",
    "java-route-tracer",
    "java-auth-audit",
    "java-vuln-scanner",
    "java-sql-audit",
    "java-xxe-audit",
    "java-file-upload-audit",
    "java-file-read-audit",
    "java-audit-pipeline",
    "audit-skills",
]

# 上游仓库合并为 audit-skills 时，用焦点提示映射旧 playbook_id（通用兼容层）
LEGACY_PLAYBOOK_FOCUS: Dict[str, str] = {
    "java-route-mapper": "梳理路由信息、HTTP 入口、Controller 映射，输出 Markdown 路由报告",
    "java-route-tracer": "追踪单条 HTTP 路由的调用链与参数绑定",
    "java-auth-audit": "梳理鉴权信息：认证机制、权限配置、路由鉴权映射、Filter/Security 链",
    "java-sql-audit": "审计 SQL 注入：用户可控参数到 JDBC/ORM sink 的可达路径",
    "java-xxe-audit": "审计 XXE：XML 解析入口与外部实体配置",
    "java-file-upload-audit": "审计文件上传：扩展名/MIME/路径校验与存储位置",
    "java-file-read-audit": "审计任意文件读取/下载：路径拼接与鉴权",
    "java-vuln-scanner": "组件漏洞扫描与依赖风险（参考 java-vulnerability.yaml）",
    "java-audit-pipeline": "全链路 Java 审计编排：路由→鉴权→污点→报告",
    "java-log-audit": "日志配置审计：敏感字段掩码、日志输出目标与泄露风险",
}


@dataclass(frozen=True)
class PlaybookInfo:
    playbook_id: str
    folder_name: str
    skill_md_path: Path
    description: str


class JavaAuditSkillsBridge:
    """Resolve and load playbooks from a cloned java-audit-skills repository."""

    def __init__(self, root_path: Optional[str] = None):
        self.workspace_dir = Path(__file__).resolve().parent
        default_vendor = self.workspace_dir / "vendor" / "java-audit-skills"
        env_path = (os.environ.get("JAVA_AUDIT_SKILLS_PATH") or "").strip()
        self.root_path = Path(root_path or env_path or default_vendor)
        self.skills_dir = self.root_path / "skills"
        self.max_playbook_chars = int(os.environ.get("JAVA_AUDIT_PLAYBOOK_MAX_CHARS", "12000"))

    def is_available(self) -> bool:
        return self.skills_dir.is_dir()

    def resolve_playbook_folder(self, playbook_id: str) -> Optional[str]:
        normalized = PLAYBOOK_ALIASES.get(playbook_id, playbook_id)
        folder = self.skills_dir / normalized
        if (folder / "SKILL.md").is_file():
            return normalized
        unified = self.skills_dir / "audit-skills"
        if (unified / "SKILL.md").is_file():
            if normalized in LEGACY_PLAYBOOK_FOCUS or normalized == "audit-skills":
                return "audit-skills"
        return None

    def _legacy_playbook_catalog(self) -> List[PlaybookInfo]:
        """当上游仅提供 audit-skills 时，为旧 playbook_id 暴露虚拟目录项。"""
        unified = self.skills_dir / "audit-skills"
        skill_md = unified / "SKILL.md"
        if not skill_md.is_file():
            return []
        meta = self._parse_front_matter(skill_md.read_text(encoding="utf-8", errors="replace"))
        base_desc = str(meta.get("description") or "统一 Java/.NET 审计手册")
        catalog: List[PlaybookInfo] = []
        for legacy_id, focus in LEGACY_PLAYBOOK_FOCUS.items():
            catalog.append(
                PlaybookInfo(
                    playbook_id=legacy_id,
                    folder_name="audit-skills",
                    skill_md_path=skill_md,
                    description=f"{base_desc} | 焦点: {focus}",
                )
            )
        return catalog

    def list_playbooks(self) -> List[PlaybookInfo]:
        if not self.is_available():
            return []
        found: List[PlaybookInfo] = []
        for folder in sorted(self.skills_dir.iterdir()):
            if not folder.is_dir():
                continue
            skill_md = folder / "SKILL.md"
            if not skill_md.is_file():
                continue
            meta = self._parse_front_matter(skill_md.read_text(encoding="utf-8", errors="replace"))
            found.append(
                PlaybookInfo(
                    playbook_id=folder.name,
                    folder_name=folder.name,
                    skill_md_path=skill_md,
                    description=str(meta.get("description") or ""),
                )
            )
        if (self.skills_dir / "audit-skills" / "SKILL.md").is_file():
            legacy = self._legacy_playbook_catalog()
            if legacy:
                existing_ids = {item.playbook_id for item in found}
                for item in legacy:
                    if item.playbook_id not in existing_ids:
                        found.append(item)
        return found

    @staticmethod
    def _parse_front_matter(text: str) -> Dict[str, str]:
        if not text.startswith("---"):
            return {}
        end = text.find("---", 3)
        if end < 0:
            return {}
        block = text[3:end].strip()
        meta: Dict[str, str] = {}
        for line in block.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            meta[key.strip()] = value.strip()
        return meta

    def load_playbook_text(self, playbook_id: str, *, max_chars: Optional[int] = None) -> Dict[str, Any]:
        limit = max_chars if max_chars is not None else self.max_playbook_chars
        requested_id = PLAYBOOK_ALIASES.get(playbook_id, playbook_id)
        folder_name = self.resolve_playbook_folder(playbook_id)
        if not folder_name:
            return {
                "ok": False,
                "playbook_id": playbook_id,
                "error": (
                    f"未找到 playbook '{playbook_id}'。"
                    f"请克隆 https://github.com/RuoJi6/java-audit-skills 到 {self.root_path}"
                ),
                "root_path": str(self.root_path),
            }
        skill_md = self.skills_dir / folder_name / "SKILL.md"
        raw = skill_md.read_text(encoding="utf-8", errors="replace")
        meta = self._parse_front_matter(raw)
        body = raw
        if raw.startswith("---"):
            second = raw.find("---", 3)
            if second >= 0:
                body = raw[second + 3 :].lstrip()
        focus = LEGACY_PLAYBOOK_FOCUS.get(requested_id)
        if focus and folder_name == "audit-skills":
            body = (
                f"## Playbook: {requested_id}\n"
                f"**审计焦点**: {focus}\n\n"
                f"{body}"
            )
        ref_java = self.skills_dir / folder_name / "references" / "java.md"
        if focus and ref_java.is_file() and requested_id in (
            "java-route-mapper", "java-auth-audit", "java-route-tracer",
        ):
            ref_text = ref_java.read_text(encoding="utf-8", errors="replace")
            body += f"\n\n## 参考: references/java.md（节选）\n{ref_text[:4000]}\n"
        truncated = len(body) > limit
        if truncated:
            body = body[:limit] + "\n\n...[playbook truncated]...\n"
        return {
            "ok": True,
            "playbook_id": requested_id,
            "description": meta.get("description", ""),
            "root_path": str(self.root_path),
            "skill_md_path": str(skill_md),
            "truncated": truncated,
            "text": body,
        }

    def render_planner_hint(self, playbook_ids: Optional[List[str]] = None) -> str:
        if not self.is_available():
            return (
                "## java-audit-skills（未安装）\n"
                f"- 期望路径: `{self.root_path}`\n"
                "- 运行 `scripts/sync_java_audit_skills.ps1` 或设置 `JAVA_AUDIT_SKILLS_PATH`\n"
                "- 安装后可用 `JavaAuditTool.load_playbook` 注入 route-mapper / sql-audit 等方法论\n"
            )
        ids = playbook_ids or DEFAULT_PLAYBOOK_IDS[:5]
        lines = ["## java-audit-skills 作战手册（已挂载）"]
        for item in self.list_playbooks():
            if item.playbook_id not in ids and ids != DEFAULT_PLAYBOOK_IDS[:5]:
                continue
            short = (item.description[:120] + "...") if len(item.description) > 120 else item.description
            lines.append(f"- `{item.playbook_id}`: {short or '(无描述)'}")
        lines.append(
            "- 深度步骤: `JavaAuditTool.load_playbook` + `FileTool.read_file`；"
            "污点验证: `JoernTool.run_source_scan`（language=java）"
        )
        return "\n".join(lines)

    @staticmethod
    def check_java_runtime() -> Dict[str, Any]:
        try:
            proc = subprocess.run(
                ["java", "-version"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            combined = (proc.stdout or "") + (proc.stderr or "")
            return {"ok": proc.returncode == 0 or "version" in combined.lower(), "output": combined.strip()}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
