"""
Agent tools wrapping java-audit-skills bridge + route scanner.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from java_audit_bridge import JavaAuditSkillsBridge
from java_route_scanner import format_routes_markdown, scan_java_routes


class JavaAuditTool:
    def __init__(self, bridge: Optional[JavaAuditSkillsBridge] = None):
        self.bridge = bridge or JavaAuditSkillsBridge()

    def list_playbooks(self) -> Dict[str, Any]:
        if not self.bridge.is_available():
            return {
                "ok": False,
                "result_summary": "java-audit-skills 未安装",
                "playbooks": [],
                "root_path": str(self.bridge.root_path),
            }
        playbooks = [
            {
                "playbook_id": p.playbook_id,
                "description": p.description,
                "path": str(p.skill_md_path),
            }
            for p in self.bridge.list_playbooks()
        ]
        return {
            "ok": True,
            "result_summary": f"已发现 {len(playbooks)} 个 playbook",
            "root_path": str(self.bridge.root_path),
            "playbooks": playbooks,
            "java_runtime": self.bridge.check_java_runtime(),
        }

    def load_playbook(self, playbook_id: str, state: Any) -> Dict[str, Any]:
        payload = self.bridge.load_playbook_text(playbook_id)
        if not payload.get("ok"):
            return {
                "ok": False,
                "result_summary": payload.get("error", "load failed"),
                "result": payload,
            }
        store = dict((getattr(state, "metadata", None) or {}).get("java_audit_playbooks") or {})
        store[payload["playbook_id"]] = {
            "description": payload.get("description"),
            "truncated": payload.get("truncated"),
            "text_preview": (payload.get("text") or "")[:2000],
        }
        if hasattr(state, "metadata"):
            state.metadata["java_audit_playbooks"] = store
            state.metadata["java_audit_active_playbook"] = payload["playbook_id"]
        return {
            "ok": True,
            "result_summary": f"已加载 playbook: {payload['playbook_id']}",
            "result": {
                "playbook_id": payload["playbook_id"],
                "description": payload.get("description"),
                "truncated": payload.get("truncated"),
                "text": payload.get("text"),
                "skill_md_path": payload.get("skill_md_path"),
            },
        }

    def scan_routes(self, state: Any, *, project_path: Optional[str] = None) -> Dict[str, Any]:
        # 优先使用本地可访问的路径（project_path 可能是 Docker 内部路径，在 Windows 上不存在）
        candidates = [
            project_path,
            getattr(state, "local_source_path", None),
            getattr(state, "project_path", None),
        ]
        root = None
        for candidate in candidates:
            if candidate and Path(candidate).is_dir():
                root = candidate
                break
        if not root:
            # 最后尝试 local_source_path（即使不在 candidates 里）
            local = getattr(state, "local_source_path", None)
            if local and Path(local).is_dir():
                root = local
        if not root or not Path(root).is_dir():
            return {
                "ok": False,
                "result_summary": "缺少可读的 Java 项目目录（project_path / local_source_path）",
                "result": {},
            }
        scan = scan_java_routes(root)
        if hasattr(state, "metadata"):
            state.metadata["java_routes"] = scan
            state.metadata["java_routes_markdown"] = format_routes_markdown(scan)
        summary = (
            f"静态路由扫描完成: {scan.get('route_count', 0)} 条"
            if scan.get("ok")
            else f"路由扫描失败: {scan.get('error', '')}"
        )
        return {"ok": bool(scan.get("ok")), "result_summary": summary, "result": scan}

    def render_guidance_block(self, state_snapshot: Optional[Dict[str, Any]] = None) -> str:
        base = self.bridge.render_planner_hint()
        snap = state_snapshot or {}
        routes = snap.get("java_routes") or {}
        if routes.get("route_count"):
            base += f"\n- 已缓存路由: {routes.get('route_count')} 条（见 metadata.java_routes）"
        active = snap.get("java_audit_active_playbook")
        if active:
            base += f"\n- 当前激活手册: `{active}`"
        return base
