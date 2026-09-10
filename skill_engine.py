"""
Skill Engine v2: multi-step Skill DAG + benchmark auto-weighting.

v2.1: 优先从 registry.yaml + pipelines/*.yaml 加载；失败回退 registry.json + templates/*.json。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
import json
import logging
import os
import re
import time

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SkillNode:
    """DAG node definition for a skill."""

    node_id: str
    tool_name: str = ""
    arguments: Dict[str, Any] = field(default_factory=dict)
    parallel_actions: List[Dict[str, Any]] = field(default_factory=list)
    success_next: Optional[str] = None
    failure_next: Optional[str] = None
    completion_signal: Optional[str] = None
    expert_guidance: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SkillDefinition:
    """Skill definition with DAG execution graph."""

    skill_id: str
    name: str
    summary: str
    trigger_keywords: List[str] = field(default_factory=list)
    completion_hints: List[str] = field(default_factory=list)
    min_score_to_activate: float = 0.25
    start_node_id: str = ""
    nodes: Dict[str, SkillNode] = field(default_factory=dict)
    collab_skill_ids: List[str] = field(default_factory=list)


class SkillEngine:
    """Planner skill engine with state-machine execution and benchmark weighting."""

    def __init__(self, skill_defs: Optional[Iterable[SkillDefinition]] = None, benchmark_file: Optional[str] = None):
        self.workspace_dir = Path(__file__).resolve().parent
        self.skills_dir = self.workspace_dir / "skills"
        self.templates_dir = self.skills_dir / "templates"
        self.generated_dir = self.skills_dir / "generated"
        self.registry_yaml_path = self.skills_dir / "registry.yaml"
        self.registry_path = self.skills_dir / "registry.json"  # 回退用
        self.auto_rewrite_mode = (os.environ.get("AUTO_REWRITE_MODE", "auto") or "auto").strip().lower()
        self.auto_rewrite_canary_trials = int(os.environ.get("AUTO_REWRITE_CANARY_TRIALS", "5"))
        self.auto_rewrite_canary_pass_rate = float(os.environ.get("AUTO_REWRITE_CANARY_PASS_RATE", "0.55"))
        self.auto_rewrite_monitor_trials = int(os.environ.get("AUTO_REWRITE_MONITOR_TRIALS", "8"))
        self.auto_rewrite_rollback_margin = float(os.environ.get("AUTO_REWRITE_ROLLBACK_MARGIN", "0.08"))
        self.node_whitelist = [x.strip() for x in (os.environ.get("AUTO_REWRITE_NODE_WHITELIST", "") or "").split(",") if x.strip()]
        self.node_blacklist = [x.strip() for x in (os.environ.get("AUTO_REWRITE_NODE_BLACKLIST", "") or "").split(",") if x.strip()]
        self.default_blacklist_prefixes = ["source_0day_pipeline::source_scan", "binary_0day_direct::source_scan"]
        self.generated_dir.mkdir(parents=True, exist_ok=True)
        self.skill_defs: Dict[str, SkillDefinition] = {
            skill.skill_id: skill for skill in (skill_defs or self._default_skill_defs())
        }
        default_benchmark = Path(__file__).resolve().parent / "skill_benchmark.json"
        self.benchmark_file = Path(benchmark_file) if benchmark_file else default_benchmark
        self._benchmark_stats = self._load_benchmark_stats()
        self._replay_rewrites()

    def _empty_benchmark_payload(self) -> Dict[str, Any]:
        return {"skills": {}, "nodes": {}, "rewrites": [], "pending_rewrites": {}, "applied_rewrites": {}}

    def _load_benchmark_stats(self) -> Dict[str, Any]:
        if not self.benchmark_file.exists():
            return self._empty_benchmark_payload()
        try:
            payload = json.loads(self.benchmark_file.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                # 兼容旧版本（直接 skill_id -> stats）
                if "skills" not in payload and "nodes" not in payload:
                    return {"skills": payload, "nodes": {}, "rewrites": []}
                merged = self._empty_benchmark_payload()
                merged.update(payload)
                return merged
        except Exception:
            pass
        return self._empty_benchmark_payload()

    def _persist_benchmark_stats(self) -> None:
        try:
            self.benchmark_file.write_text(
                json.dumps(self._benchmark_stats, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception:
            # benchmark 落盘失败不阻断主流程
            return

    def _apply_node_rewrite(self, skill_id: str, node_id: str, replacement: Dict[str, Any]) -> bool:
        skill = self.skill_defs.get(skill_id)
        if not skill or node_id not in skill.nodes:
            return False
        replacement_node = SkillNode(
            node_id=node_id,
            tool_name=replacement.get("tool_name", ""),
            arguments=replacement.get("arguments", {}) or {},
            parallel_actions=replacement.get("parallel_actions", []) or [],
            success_next=replacement.get("success_next"),
            failure_next=replacement.get("failure_next"),
            completion_signal=replacement.get("completion_signal"),
            expert_guidance=replacement.get("expert_guidance") or {},
        )
        new_nodes = dict(skill.nodes)
        new_nodes[node_id] = replacement_node
        self.skill_defs[skill_id] = SkillDefinition(
            skill_id=skill.skill_id,
            name=skill.name,
            summary=skill.summary,
            trigger_keywords=list(skill.trigger_keywords),
            completion_hints=list(skill.completion_hints),
            min_score_to_activate=skill.min_score_to_activate,
            start_node_id=skill.start_node_id,
            nodes=new_nodes,
            collab_skill_ids=list(skill.collab_skill_ids),
        )
        return True

    def _replay_rewrites(self) -> None:
        rewrites = list(self._benchmark_stats.get("rewrites") or [])
        for event in rewrites:
            replacement = event.get("replacement_node") or {}
            if replacement:
                self._apply_node_rewrite(
                    skill_id=event.get("skill_id", ""),
                    node_id=event.get("node_id", ""),
                    replacement=replacement,
                )

    @staticmethod
    def _template_to_skill_definition(template: Dict[str, Any]) -> SkillDefinition:
        node_map: Dict[str, SkillNode] = {}
        for item in list(template.get("nodes") or []):
            node = SkillNode(
                node_id=str(item.get("node_id")),
                tool_name=str(item.get("tool_name") or ""),
                arguments=dict(item.get("arguments") or {}),
                parallel_actions=list(item.get("parallel_actions") or []),
                success_next=item.get("success_next"),
                failure_next=item.get("failure_next"),
                completion_signal=item.get("completion_signal"),
                expert_guidance=dict(item.get("expert_guidance") or {}),
            )
            node_map[node.node_id] = node
        return SkillDefinition(
            skill_id=str(template.get("skill_id")),
            name=str(template.get("name")),
            summary=str(template.get("summary", "")),
            trigger_keywords=list(template.get("trigger_keywords") or []),
            completion_hints=list(template.get("completion_hints") or []),
            min_score_to_activate=float(template.get("min_score_to_activate", 0.25)),
            start_node_id=str(template.get("start_node_id", "")),
            nodes=node_map,
            collab_skill_ids=list(template.get("collab_skill_ids") or []),
        )

    def _default_skill_defs(self) -> List[SkillDefinition]:
        """
        从 skills/registry.yaml + pipelines/*.yaml 加载技能模板。
        失败时回退到 registry.json + templates/*.json。
        若均失败，则回退最小内置模板，保证可运行。
        """
        # ── 优先 YAML 路径 ──
        if self.registry_yaml_path.exists():
            try:
                return self._load_skill_defs_yaml()
            except Exception as exc:
                logger.warning("registry.yaml 加载失败，回退 JSON: %s", exc)

        # ── JSON 回退路径 ──
        return self._load_skill_defs_json()

    def _load_skill_defs_yaml(self) -> List[SkillDefinition]:
        """从 registry.yaml + pipelines/*.yaml 加载。"""
        import yaml as _yaml
        loaded: List[SkillDefinition] = []
        registry = _yaml.safe_load(self.registry_yaml_path.read_text(encoding="utf-8"))
        if not isinstance(registry, dict):
            raise ValueError("registry.yaml 解析失败")
        for entry in list(registry.get("pipelines") or []):
            if not bool(entry.get("enabled", True)):
                continue
            rel = str(entry.get("file") or "").strip()
            if not rel:
                continue
            pipeline_path = self.skills_dir / rel
            if not pipeline_path.exists():
                logger.debug("Pipeline YAML 不存在: %s", pipeline_path)
                continue
            template_obj = _yaml.safe_load(pipeline_path.read_text(encoding="utf-8"))
            if not isinstance(template_obj, dict):
                continue
            loaded.append(self._template_to_skill_definition(template_obj))

        # 加载自动生成的 CVE 知识 Skills
        for gen_file in sorted(self.generated_dir.glob("*.json")):
            try:
                template_obj = json.loads(gen_file.read_text(encoding="utf-8"))
                if template_obj.get("enabled", True):
                    skill_def = self._template_to_skill_definition(template_obj)
                    if skill_def.skill_id not in {s.skill_id for s in loaded}:
                        loaded.append(skill_def)
            except Exception as gen_exc:
                logger.warning("加载生成的 Skill 失败 (%s): %s", gen_file.name, gen_exc)

        if not loaded:
            loaded = list(self._builtin_minimal_skill_defs())
        return loaded

    def _load_skill_defs_json(self) -> List[SkillDefinition]:
        """从 registry.json + templates/*.json 加载（旧路径回退）。"""
        loaded: List[SkillDefinition] = []
        try:
            registry = json.loads(self.registry_path.read_text(encoding="utf-8"))
            for entry in list(registry.get("templates") or []):
                if not bool(entry.get("enabled", True)):
                    continue
                rel = str(entry.get("file") or "").strip()
                if not rel:
                    continue
                template_path = self.skills_dir / rel
                if not template_path.exists():
                    continue
                template_obj = json.loads(template_path.read_text(encoding="utf-8"))
                loaded.append(self._template_to_skill_definition(template_obj))
        except Exception:
            loaded = []

        # 加载自动生成的 CVE 知识 Skills（来自 skills/generated/ 目录）
        try:
            for gen_file in sorted(self.generated_dir.glob("*.json")):
                try:
                    template_obj = json.loads(gen_file.read_text(encoding="utf-8"))
                    if template_obj.get("enabled", True):
                        skill_def = self._template_to_skill_definition(template_obj)
                        # 避免与 registry 中已有的同名 skill 冲突
                        if skill_def.skill_id not in {s.skill_id for s in loaded}:
                            loaded.append(skill_def)
                except Exception as gen_exc:
                    logger.warning("加载生成的 Skill 失败 (%s): %s", gen_file.name, gen_exc)
        except Exception:
            pass

        if loaded:
            return loaded
        return list(self._builtin_minimal_skill_defs())

    @staticmethod
    def _builtin_minimal_skill_defs() -> List[SkillDefinition]:
        """最小可运行模板（所有加载路径均失败时的最终回退）。"""
        return [
            SkillDefinition(
                skill_id="source_0day_pipeline",
                name="源码0-day挖掘",
                summary="fallback 模板",
                trigger_keywords=["源码", "0day"],
                completion_hints=["fallback 模板，请检查 skills/templates"],
                start_node_id="set_context",
                nodes={
                    "set_context": SkillNode(
                        node_id="set_context",
                        tool_name="set_context",
                        arguments={},
                    )
                },
            )
        ]

    @staticmethod
    def _tokenize(text: str) -> str:
        return re.sub(r"\s+", " ", (text or "").strip().lower())

    def _benchmark_weight(self, skill_id: str) -> float:
        skills_stats = self._benchmark_stats.get("skills", {})
        stats = skills_stats.get(skill_id, {})
        attempts = float(stats.get("attempts", 0.0))
        success = float(stats.get("success", 0.0))
        if attempts < 3:
            return 1.0
        rate = success / max(1.0, attempts)
        # 经验区间压缩到 [0.8, 1.2]，避免权重抖动过大
        return max(0.8, min(1.2, 0.8 + 0.4 * rate))

    def _node_key(self, skill_id: str, node_id: str) -> str:
        return f"{skill_id}::{node_id}"

    @staticmethod
    def _tool_family(tool_name: str) -> str:
        if tool_name.startswith("FileTool."):
            return "file"
        if tool_name.startswith("JoernTool.") or tool_name.startswith("GraphBuilder.run_source_scan"):
            return "scan"
        if tool_name.startswith("DBTool.") or tool_name.startswith("GraphBuilder.run_reachability"):
            return "reachability"
        if tool_name.startswith("VersionTool."):
            return "version"
        if tool_name.startswith("set_context"):
            return "context"
        return "other"

    def _extract_node_features(self, node: SkillNode, node_stats: Dict[str, Any]) -> Dict[str, Any]:
        tool_name = node.tool_name or "Skill.parallel"
        attempts = float(node_stats.get("attempts", 0.0))
        success = float(node_stats.get("success", 0.0))
        success_rate = success / max(1.0, attempts)
        return {
            "tool_name": tool_name,
            "tool_family": self._tool_family(tool_name),
            "is_parallel": bool(node.parallel_actions),
            "attempts": attempts,
            "success_rate": success_rate,
            "has_direct_file_read": tool_name == "FileTool.read_file",
            "has_file_glob": tool_name == "FileTool.glob_files" or bool(node.parallel_actions),
        }

    def _tool_family_success_rate(self, family: str) -> float:
        node_stats_all = self._benchmark_stats.get("nodes", {}) or {}
        attempts = 0.0
        success = 0.0
        for stats in node_stats_all.values():
            tool_name = str(stats.get("last_tool_name", ""))
            if self._tool_family(tool_name) != family:
                continue
            attempts += float(stats.get("attempts", 0.0))
            success += float(stats.get("success", 0.0))
        if attempts <= 0:
            return 0.5
        return success / attempts

    def _strategy_candidates(self, skill_id: str, node_id: str, node: SkillNode) -> List[Dict[str, Any]]:
        # 通用候选策略池，可按节点特征筛选。
        return [
            {
                "strategy_id": "fallback_to_glob",
                "replacement": {
                    "tool_name": "FileTool.glob_files",
                    "arguments": {"pattern": "**/*", "limit": 8},
                    "parallel_actions": [],
                },
                "applies_to": {"families": ["file", "other", "version", "scan"]},
                "base_score": 0.42,
            },
            {
                "strategy_id": "security_focus_glob",
                "replacement": {
                    "tool_name": "FileTool.glob_files",
                    "arguments": {"pattern": "**/*Security*.java", "limit": 12},
                    "parallel_actions": [],
                },
                "applies_to": {"families": ["file", "scan", "other"]},
                "base_score": 0.48,
            },
            {
                "strategy_id": "set_context_recover",
                "replacement": {
                    "tool_name": "set_context",
                    "arguments": {},
                    "parallel_actions": [],
                },
                "applies_to": {"families": ["version", "context", "other", "scan"]},
                "base_score": 0.36,
            },
            {
                "strategy_id": "single_glob_from_parallel",
                "replacement": {
                    "tool_name": "FileTool.glob_files",
                    "arguments": {"pattern": "**/application*.yml", "limit": 20},
                    "parallel_actions": [],
                },
                "applies_to": {"families": ["file", "other"]},
                "base_score": 0.51,
                "require_parallel": True,
            },
            {
                "strategy_id": "minimal_probe",
                "replacement": {
                    "tool_name": "FileTool.glob_files",
                    "arguments": {"pattern": "**/*", "limit": 3},
                    "parallel_actions": [],
                },
                "applies_to": {"families": ["file", "scan", "other", "version"]},
                "base_score": 0.33,
            },
        ]

    def _select_rewrite_strategy(
        self, skill_id: str, node_id: str, node: SkillNode, node_stats: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        features = self._extract_node_features(node=node, node_stats=node_stats)
        family_success = self._tool_family_success_rate(features["tool_family"])
        candidates = self._strategy_candidates(skill_id=skill_id, node_id=node_id, node=node)
        scored: List[Dict[str, Any]] = []
        for candidate in candidates:
            families = list((candidate.get("applies_to") or {}).get("families") or [])
            if families and features["tool_family"] not in families:
                continue
            if candidate.get("require_parallel") and not features["is_parallel"]:
                continue

            # 策略选择器：基于节点特征 + 历史结果打分
            score = float(candidate.get("base_score", 0.0))
            score += max(0.0, 0.5 - features["success_rate"]) * 0.6
            score += max(0.0, 0.5 - family_success) * 0.3
            replacement_tool = str((candidate.get("replacement") or {}).get("tool_name", ""))
            replacement_family = self._tool_family(replacement_tool)
            if replacement_family != features["tool_family"]:
                # 最小改动原则：优先同工具家族替换
                score -= 0.18
                if features["success_rate"] < 0.2:
                    score += 0.08
            if features["has_direct_file_read"] and candidate["strategy_id"] in (
                "fallback_to_glob",
                "security_focus_glob",
            ):
                score += 0.2
            if features["is_parallel"] and candidate["strategy_id"] == "single_glob_from_parallel":
                score += 0.25
            if features["attempts"] > 20 and candidate["strategy_id"] == "minimal_probe":
                score += 0.1

            scored.append(
                {
                    "strategy_id": candidate["strategy_id"],
                    "score": round(score, 4),
                    "replacement": candidate.get("replacement", {}),
                    "features": features,
                    "family_success_rate": round(family_success, 4),
                }
            )
        if not scored:
            return None
        scored.sort(key=lambda item: item["score"], reverse=True)
        return scored[0]

    def _node_allowed_for_rewrite(self, node_key: str) -> bool:
        if any(node_key == item or (item.endswith("*") and node_key.startswith(item[:-1])) for item in self.node_blacklist):
            return False
        if any(node_key.startswith(prefix) for prefix in self.default_blacklist_prefixes):
            return False
        if not self.node_whitelist:
            return True
        return any(node_key == item or (item.endswith("*") and node_key.startswith(item[:-1])) for item in self.node_whitelist)

    def _save_generated_template_draft(self, skill_id: str, event: Dict[str, Any]) -> Optional[str]:
        ts = str(int(time.time()))
        out_path = self.generated_dir / f"{skill_id}_{event.get('node_id','node')}_{ts}.json"
        payload = {
            "draft_type": "rewrite_candidate",
            "skill_id": skill_id,
            "event": event,
            "note": "该草稿由自动改写生成，需人工审核后合并到 skills/templates/",
        }
        try:
            out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            return str(out_path)
        except Exception:
            return None

    def _record_node_outcome(self, skill_id: str, node_id: str, succeeded: bool, node: Optional[SkillNode] = None) -> None:
        node_key = self._node_key(skill_id, node_id)
        node_stats_all = self._benchmark_stats.setdefault("nodes", {})
        stats = dict(node_stats_all.get(node_key) or {})
        stats["attempts"] = float(stats.get("attempts", 0.0)) + 1.0
        if succeeded:
            stats["success"] = float(stats.get("success", 0.0)) + 1.0
        if node is not None:
            stats["last_tool_name"] = node.tool_name or "Skill.parallel"
            if node.parallel_actions:
                stats["last_parallel_count"] = len(node.parallel_actions)
        node_stats_all[node_key] = stats

    def _maybe_rewrite_low_performance_node(self, skill_id: str, node_id: str) -> Optional[Dict[str, Any]]:
        skill = self.skill_defs.get(skill_id)
        if not skill:
            return None
        node = skill.nodes.get(node_id)
        if not node:
            return None
        node_key = self._node_key(skill_id, node_id)
        if not self._node_allowed_for_rewrite(node_key):
            return None
        node_stats = (self._benchmark_stats.get("nodes", {}) or {}).get(node_key, {})
        attempts = float(node_stats.get("attempts", 0.0))
        success = float(node_stats.get("success", 0.0))
        if attempts < 8:
            return None
        success_rate = success / max(1.0, attempts)
        if success_rate >= 0.35:
            return None

        strategy = self._select_rewrite_strategy(
            skill_id=skill_id,
            node_id=node_id,
            node=node,
            node_stats=node_stats,
        )
        if not strategy:
            return None
        replacement = strategy.get("replacement", {}) or {}
        replacement_node = SkillNode(
            node_id=node.node_id,
            tool_name=replacement.get("tool_name", ""),
            arguments=replacement.get("arguments", {}) or {},
            parallel_actions=replacement.get("parallel_actions", []) or [],
            success_next=node.success_next,
            failure_next=node.failure_next,
            completion_signal=node.completion_signal,
            expert_guidance=node.expert_guidance,
        )
        reason = (
            f"节点低表现触发策略选择器，选择策略 {strategy.get('strategy_id')} "
            f"(score={strategy.get('score')})"
        )

        rewrite_event = {
            "skill_id": skill_id,
            "node_id": node_id,
            "attempts": attempts,
            "success_rate": round(success_rate, 3),
            "reason": reason,
            "replacement_tool": replacement_node.tool_name,
            "strategy_id": strategy.get("strategy_id"),
            "strategy_score": strategy.get("score"),
            "selector_features": strategy.get("features", {}),
            "family_success_rate": strategy.get("family_success_rate"),
            "replacement_node": {
                "tool_name": replacement_node.tool_name,
                "arguments": replacement_node.arguments,
                "parallel_actions": replacement_node.parallel_actions,
                "success_next": replacement_node.success_next,
                "failure_next": replacement_node.failure_next,
                "completion_signal": replacement_node.completion_signal,
                "expert_guidance": replacement_node.expert_guidance,
            },
        }
        draft_path = self._save_generated_template_draft(skill_id=skill_id, event=rewrite_event)
        if draft_path:
            rewrite_event["draft_path"] = draft_path

        pending_all = dict(self._benchmark_stats.get("pending_rewrites") or {})
        pending_record = {
            "skill_id": skill_id,
            "node_id": node_id,
            "old_node": {
                "tool_name": node.tool_name,
                "arguments": node.arguments,
                "parallel_actions": node.parallel_actions,
                "success_next": node.success_next,
                "failure_next": node.failure_next,
                "completion_signal": node.completion_signal,
                "expert_guidance": node.expert_guidance,
            },
            "candidate_node": rewrite_event["replacement_node"],
            "baseline_success_rate": round(success_rate, 4),
            "canary_attempts": 0,
            "canary_success": 0,
            "status": "await_review" if self.auto_rewrite_mode == "reviewed" else "canary",
            "created_at": int(time.time()),
            "event": rewrite_event,
        }
        pending_all[node_key] = pending_record
        self._benchmark_stats["pending_rewrites"] = pending_all
        return rewrite_event

    def match_skills(self, user_request: str, state_snapshot: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        text = self._tokenize(user_request)
        state_snapshot = state_snapshot or {}
        matches: List[Dict[str, Any]] = []
        for skill in self.skill_defs.values():
            hit_count = 0
            for keyword in skill.trigger_keywords:
                if keyword.lower() in text:
                    hit_count += 1
            base_score = hit_count / max(1, len(skill.trigger_keywords))
            if skill.skill_id == "poc_generation_validation" and state_snapshot.get("joern_hit_vuln_types"):
                base_score += 0.15
            if skill.skill_id == "source_0day_pipeline" and state_snapshot.get("project_path"):
                base_score += 0.1
            if skill.skill_id == "reachability_exploitability" and state_snapshot.get("current_cve_id"):
                base_score += 0.2
            if skill.skill_id in ("java_attack_surface", "java_web_audit_pipeline") and (
                state_snapshot.get("language") == "java" or "java" in text
            ):
                base_score += 0.12
            if skill.skill_id == "java_web_audit_pipeline" and state_snapshot.get("java_routes", {}).get(
                "route_count"
            ):
                base_score += 0.08
            
            # vuln_type 触发：当 Joern 扫描命中特定漏洞类型时，自动提升对应专家 Skill 的匹配分数
            joern_vuln_types = state_snapshot.get("joern_hit_vuln_types") or []
            if joern_vuln_types and skill.skill_id.startswith("expert_"):
                vuln_type_boost = 0.0
                for vtype in joern_vuln_types:
                    vtype_lower = vtype.lower()
                    if skill.skill_id == "expert_cpp_buffer_overflow" and (
                        "buffer_overflow" in vtype_lower or "cpp_buffer" in vtype_lower
                        or "can_parsing" in vtype_lower or "can_or_buffer" in vtype_lower
                        or "embedded_buffer" in vtype_lower
                    ):
                        vuln_type_boost = max(vuln_type_boost, 0.3)
                    elif skill.skill_id == "expert_cpp_uaf_double_free" and (
                        "use_after_free" in vtype_lower or "double_free" in vtype_lower
                        or "cpp_uaf" in vtype_lower or "cpp_double" in vtype_lower
                        or "cpp_custom_mem" in vtype_lower
                    ):
                        vuln_type_boost = max(vuln_type_boost, 0.3)
                    elif skill.skill_id == "expert_cpp_integer_overflow" and (
                        "integer_overflow" in vtype_lower or "unsafe_alloc" in vtype_lower
                        or "cpp_integer" in vtype_lower
                    ):
                        vuln_type_boost = max(vuln_type_boost, 0.3)
                    elif skill.skill_id == "expert_cpp_memory_leak" and (
                        "memory_leak" in vtype_lower or "cpp_memory" in vtype_lower
                    ):
                        vuln_type_boost = max(vuln_type_boost, 0.3)
                    elif skill.skill_id == "expert_java_sql_injection" and (
                        "sql_injection" in vtype_lower or "sql" in vtype_lower
                    ):
                        vuln_type_boost = max(vuln_type_boost, 0.3)
                    elif skill.skill_id == "expert_java_injection_suite" and (
                        "command_injection" in vtype_lower or "ssrf" in vtype_lower
                        or "path_traversal" in vtype_lower
                    ):
                        vuln_type_boost = max(vuln_type_boost, 0.3)
                    elif skill.skill_id == "expert_java_deserialization" and (
                        "insecure_deserialization" in vtype_lower or "deserialization" in vtype_lower
                    ):
                        vuln_type_boost = max(vuln_type_boost, 0.3)
                    elif skill.skill_id == "expert_java_auth_bypass" and (
                        "auth" in vtype_lower or "privilege" in vtype_lower
                        or "bola" in vtype_lower
                    ):
                        vuln_type_boost = max(vuln_type_boost, 0.25)
                base_score += vuln_type_boost
            
            # 用户明确说"二进制直接挖0day"时，压低版本识别技能
            if skill.skill_id == "version_identification":
                if "二进制" in text and ("直接" in text or "不用" in text or "暂时不用" in text):
                    base_score *= 0.35

            score = min(1.0, base_score * self._benchmark_weight(skill.skill_id))
            if score >= skill.min_score_to_activate:
                first_step = self.skill_defs[skill.skill_id].nodes.get(skill.start_node_id)
                matches.append(
                    {
                        "skill_id": skill.skill_id,
                        "name": skill.name,
                        "score": round(score, 3),
                        "summary": skill.summary,
                        "preferred_actions": [{"tool_name": first_step.tool_name}] if first_step else [],
                        "completion_hints": skill.completion_hints,
                        "benchmark_weight": round(self._benchmark_weight(skill.skill_id), 3),
                    }
                )
        matches.sort(key=lambda item: item.get("score", 0.0), reverse=True)
        return matches

    def render_skill_guidance(
        self,
        user_request: str,
        state_snapshot: Optional[Dict[str, Any]] = None,
        *,
        extra_block: str = "",
    ) -> str:
        matches = self.match_skills(user_request, state_snapshot=state_snapshot)
        if not matches:
            lines = [
                "## Skills建议",
                "- 未匹配到高置信技能；按通用流程规划。",
                "- 如需固定流程，可显式调用 Skill.run。",
            ]
        else:
            lines = ["## Skills建议（优先参考）"]
            for skill in matches[:4]:
                lines.append(
                    f"- {skill['skill_id']}（{skill['name']}，score={skill['score']}，weight={skill['benchmark_weight']}）: {skill['summary']}"
                )
                action_names = [item.get("tool_name", "") for item in skill.get("preferred_actions", [])]
                if action_names:
                    lines.append(f"  起始动作: {', '.join(action_names)}")
            lines.append("- 如要执行技能，请使用动作 `Skill.run`，并传 `skill_id`。")
            lines.append(
                "- Java Web 全链路可: `Skill.run` + `skill_id=java_web_audit_pipeline`（自动串联攻击面→Joern→PoC）。"
            )
        if extra_block:
            lines.append("")
            lines.append(extra_block.strip())
        return "\n".join(lines)

    def _init_runtime(self, state: Any, skill: SkillDefinition) -> Dict[str, Any]:
        runtime_all = dict((state.metadata.get("skill_runtime") or {}))
        runtime = dict(runtime_all.get(skill.skill_id) or {})
        if not runtime:
            runtime = {
                "current_node_id": skill.start_node_id,
                "history": [],
                "done": False,
            }
        runtime_all[skill.skill_id] = runtime
        state.metadata["skill_runtime"] = runtime_all
        return runtime

    def get_runtime(self, state: Any, skill_id: str) -> Dict[str, Any]:
        runtime_all = state.metadata.get("skill_runtime") or {}
        return dict(runtime_all.get(skill_id) or {})

    def get_node_expert_guidance(self, state: Any, skill_id: str) -> Dict[str, Any]:
        """Get expert_guidance for the current active node of a skill."""
        skill = self.skill_defs.get(skill_id)
        if not skill:
            return {}
        runtime = self.get_runtime(state, skill_id)
        node_id = runtime.get("current_node_id") or skill.start_node_id
        node = skill.nodes.get(node_id)
        if not node:
            return {}
        return dict(node.expert_guidance or {})

    def _resolve_skill_id(self, args: Dict[str, Any], state: Any) -> Optional[str]:
        skill_id = args.get("skill_id")
        if skill_id:
            return skill_id
        queue = list(state.metadata.get("skill_collab_queue") or [])
        if queue:
            return queue[0]
        return None

    def expand_skill_action(self, action: Dict[str, Any], state: Any) -> Optional[Dict[str, Any]]:
        if (action or {}).get("tool_name") != "Skill.run":
            return None
        args = (action or {}).get("arguments", {}) or {}
        if args.get("skill_ids"):
            state.metadata["skill_collab_queue"] = list(args.get("skill_ids") or [])
        skill_id = self._resolve_skill_id(args, state)
        if not skill_id:
            return {"tool_name": "set_context", "arguments": {}, "_skill_resolution_error": "缺少 skill_id"}
        skill = self.skill_defs.get(skill_id)
        if not skill:
            return {"tool_name": "set_context", "arguments": {}, "_skill_resolution_error": f"未知 skill_id={skill_id}"}
        if skill.collab_skill_ids and not list(state.metadata.get("skill_collab_queue") or []):
            state.metadata["skill_collab_queue"] = list(skill.collab_skill_ids)
        if skill.collab_skill_ids and not args.get("skill_ids"):
            queue = list(state.metadata.get("skill_collab_queue") or [])
            if queue and queue[0] != skill_id:
                return self.expand_skill_action(
                    {"tool_name": "Skill.run", "arguments": {"skill_id": queue[0]}},
                    state=state,
                )
        requested_tool = args.get("tool_name")
        if requested_tool:
            return {"tool_name": requested_tool, "arguments": args.get("tool_arguments", {}) or {}}

        runtime = self._init_runtime(state, skill)
        if runtime.get("done"):
            queue = list(state.metadata.get("skill_collab_queue") or [])
            if queue and queue[0] == skill_id:
                queue.pop(0)
                state.metadata["skill_collab_queue"] = queue
                if queue:
                    return self.expand_skill_action(
                        {
                            "tool_name": "Skill.run",
                            "arguments": {"skill_id": queue[0]},
                        },
                        state=state,
                    )
            return {"tool_name": "finish", "arguments": {}}
        node_id = runtime.get("current_node_id") or skill.start_node_id
        node = skill.nodes.get(node_id)
        if not node:
            return {"tool_name": "set_context", "arguments": {}, "_skill_resolution_error": f"技能节点不存在: {node_id}"}
        node_key = self._node_key(skill_id, node_id)
        pending_all = self._benchmark_stats.get("pending_rewrites", {}) or {}
        pending = dict(pending_all.get(node_key) or {})
        if pending.get("status") == "canary":
            candidate = dict(pending.get("candidate_node") or {})
            canary_node = SkillNode(
                node_id=node.node_id,
                tool_name=str(candidate.get("tool_name", "")),
                arguments=dict(candidate.get("arguments") or {}),
                parallel_actions=list(candidate.get("parallel_actions") or []),
                success_next=node.success_next,
                failure_next=node.failure_next,
                completion_signal=node.completion_signal,
                expert_guidance=node.expert_guidance,
            )
            if canary_node.parallel_actions:
                return {
                    "tool_name": "Skill.parallel",
                    "arguments": {"actions": canary_node.parallel_actions},
                    "_skill_runtime": {"skill_id": skill_id, "node_id": node.node_id},
                    "_rewrite_candidate": {"node_key": node_key, "mode": "canary"},
                }
            return {
                "tool_name": canary_node.tool_name,
                "arguments": canary_node.arguments,
                "_skill_runtime": {"skill_id": skill_id, "node_id": node.node_id},
                "_rewrite_candidate": {"node_key": node_key, "mode": "canary"},
            }
        if node.parallel_actions:
            return {
                "tool_name": "Skill.parallel",
                "arguments": {"actions": node.parallel_actions},
                "_skill_runtime": {"skill_id": skill_id, "node_id": node.node_id},
                "_expert_guidance": node.expert_guidance,
            }
        return {
            "tool_name": node.tool_name,
            "arguments": node.arguments,
            "_skill_runtime": {"skill_id": skill_id, "node_id": node.node_id},
            "_expert_guidance": node.expert_guidance,
        }

    def advance_runtime(
        self,
        state: Any,
        skill_id: str,
        node_id: str,
        action_result: Dict[str, Any],
        rewrite_meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        skill = self.skill_defs.get(skill_id)
        if not skill:
            return {"ok": False, "error": "unknown_skill"}
        runtime_all = dict((state.metadata.get("skill_runtime") or {}))
        runtime = dict(runtime_all.get(skill_id) or {})
        node = skill.nodes.get(node_id)
        if not node:
            return {"ok": False, "error": "unknown_node"}
        ok = bool(action_result.get("ok"))
        self._record_node_outcome(skill_id=skill_id, node_id=node_id, succeeded=ok, node=node)
        rewrite_event = self._maybe_rewrite_low_performance_node(skill_id=skill_id, node_id=node_id)
        next_node_id = node.success_next if ok else (node.failure_next or node.success_next)
        history = list(runtime.get("history") or [])
        history.append(
            {
                "node_id": node_id,
                "ok": ok,
                "result_summary": action_result.get("result_summary"),
                "rewrite_event": rewrite_event,
            }
        )
        runtime["history"] = history[-20:]
        runtime["current_node_id"] = next_node_id
        runtime["done"] = next_node_id is None
        runtime_all[skill_id] = runtime
        state.metadata["skill_runtime"] = runtime_all

        node_key = self._node_key(skill_id, node_id)
        pending_all = dict(self._benchmark_stats.get("pending_rewrites") or {})
        pending = dict(pending_all.get(node_key) or {})
        if pending and pending.get("status") == "canary" and (rewrite_meta or {}).get("mode") == "canary":
            pending["canary_attempts"] = int(pending.get("canary_attempts", 0)) + 1
            if ok:
                pending["canary_success"] = int(pending.get("canary_success", 0)) + 1
            canary_attempts = int(pending.get("canary_attempts", 0))
            canary_success = int(pending.get("canary_success", 0))
            if canary_attempts >= self.auto_rewrite_canary_trials:
                canary_rate = canary_success / max(1, canary_attempts)
                if canary_rate >= self.auto_rewrite_canary_pass_rate:
                    if self._apply_node_rewrite(skill_id, node_id, pending.get("candidate_node") or {}):
                        applied_all = dict(self._benchmark_stats.get("applied_rewrites") or {})
                        applied_all[node_key] = {
                            "skill_id": skill_id,
                            "node_id": node_id,
                            "old_node": pending.get("old_node", {}),
                            "new_node": pending.get("candidate_node", {}),
                            "baseline_success_rate": float(pending.get("baseline_success_rate", 0.0)),
                            "post_attempts": 0,
                            "post_success": 0,
                            "status": "monitoring",
                            "applied_at": int(time.time()),
                        }
                        self._benchmark_stats["applied_rewrites"] = applied_all
                        rewrites = list(self._benchmark_stats.get("rewrites") or [])
                        event = dict(pending.get("event") or {})
                        event["promotion"] = {"canary_attempts": canary_attempts, "canary_success_rate": round(canary_rate, 4)}
                        rewrites.append(event)
                        self._benchmark_stats["rewrites"] = rewrites[-200:]
                        state.metadata["last_skill_rewrite"] = event
                    pending_all.pop(node_key, None)
                else:
                    pending_all.pop(node_key, None)
            else:
                pending_all[node_key] = pending
            self._benchmark_stats["pending_rewrites"] = pending_all

        applied_all = dict(self._benchmark_stats.get("applied_rewrites") or {})
        applied = dict(applied_all.get(node_key) or {})
        if applied and applied.get("status") == "monitoring":
            applied["post_attempts"] = int(applied.get("post_attempts", 0)) + 1
            if ok:
                applied["post_success"] = int(applied.get("post_success", 0)) + 1
            post_attempts = int(applied.get("post_attempts", 0))
            post_success = int(applied.get("post_success", 0))
            if post_attempts >= self.auto_rewrite_monitor_trials:
                post_rate = post_success / max(1, post_attempts)
                baseline = float(applied.get("baseline_success_rate", 0.0))
                if post_rate < max(0.0, baseline - self.auto_rewrite_rollback_margin):
                    old_node = dict(applied.get("old_node") or {})
                    self._apply_node_rewrite(skill_id, node_id, old_node)
                    rewrites = list(self._benchmark_stats.get("rewrites") or [])
                    rollback_event = {
                        "skill_id": skill_id,
                        "node_id": node_id,
                        "rollback": True,
                        "post_rate": round(post_rate, 4),
                        "baseline": round(baseline, 4),
                        "margin": self.auto_rewrite_rollback_margin,
                    }
                    rewrites.append(rollback_event)
                    self._benchmark_stats["rewrites"] = rewrites[-200:]
                    state.metadata["last_skill_rewrite"] = rollback_event
                applied_all.pop(node_key, None)
            else:
                applied_all[node_key] = applied
            self._benchmark_stats["applied_rewrites"] = applied_all

        if rewrite_event:
            state.metadata["last_skill_rewrite"] = rewrite_event
        self._persist_benchmark_stats()
        return {"ok": True, "runtime": runtime}

    def record_skill_outcome(self, skill_id: str, succeeded: bool) -> None:
        skills_stats = self._benchmark_stats.setdefault("skills", {})
        stats = dict(skills_stats.get(skill_id) or {})
        stats["attempts"] = float(stats.get("attempts", 0.0)) + 1.0
        if succeeded:
            stats["success"] = float(stats.get("success", 0.0)) + 1.0
        skills_stats[skill_id] = stats
        self._persist_benchmark_stats()
