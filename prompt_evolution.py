"""
Prompt evolution manager (v3.2).

能力：
1) 管理 prompts/templates 与 prompts/generated
2) 基于运行失败模式自动生成候选 prompt 片段
3) canary 评估候选，达标发布，不达标淘汰
4) 支持 reviewed 模式（人工审批后再发布）
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import json
import os
import time


@dataclass
class PromptVariant:
    variant_id: str
    status: str  # active | canary | reviewed | archived
    system_patch: str
    user_patch: str
    reason: str


class PromptEvolutionManager:
    def __init__(self, workspace_dir: Path):
        self.workspace_dir = workspace_dir
        self.prompts_dir = workspace_dir / "prompts"
        self.templates_dir = self.prompts_dir / "templates"
        self.generated_dir = self.prompts_dir / "generated"
        self.registry_path = self.prompts_dir / "registry.json"
        self.benchmark_path = workspace_dir / "prompt_benchmark.json"
        self.mode = (os.environ.get("AUTO_PROMPT_MODE", "reviewed") or "reviewed").strip().lower()
        self.canary_trials = int(os.environ.get("AUTO_PROMPT_CANARY_TRIALS", "5"))
        self.canary_pass_rate = float(os.environ.get("AUTO_PROMPT_CANARY_PASS_RATE", "0.6"))
        self.monitor_trials = int(os.environ.get("AUTO_PROMPT_MONITOR_TRIALS", "8"))
        self.rollback_margin = float(os.environ.get("AUTO_PROMPT_ROLLBACK_MARGIN", "0.08"))
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        self.generated_dir.mkdir(parents=True, exist_ok=True)
        self._ensure_files()
        self.registry = self._read_json(self.registry_path, default={"version": 1, "active_variant_id": "base"})
        self.benchmark = self._read_json(
            self.benchmark_path,
            default={
                "variants": {
                    "base": {
                        "status": "active",
                        "attempts": 0,
                        "success": 0
                    }
                },
                "pending": {},
                "active_variant_id": "base",
                "history": []
            },
        )

    def _sync_registry_active_variant(self) -> None:
        self.registry["active_variant_id"] = str(self.benchmark.get("active_variant_id") or "base")
        self._write_json(self.registry_path, self.registry)

    @staticmethod
    def _read_json(path: Path, default: Dict[str, Any]) -> Dict[str, Any]:
        if not path.exists():
            return default
        try:
            obj = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(obj, dict):
                return obj
        except Exception:
            pass
        return default

    def _write_json(self, path: Path, payload: Dict[str, Any]) -> None:
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def _ensure_files(self) -> None:
        base_system = self.templates_dir / "planner_system.base.txt"
        base_user = self.templates_dir / "planner_user.base.txt"
        if not base_system.exists():
            base_system.write_text(
                "BASE_TEMPLATE_PLACEHOLDER: planner system prompt comes from prompts.py and patches are appended.\n",
                encoding="utf-8",
            )
        if not base_user.exists():
            base_user.write_text(
                "BASE_TEMPLATE_PLACEHOLDER: planner user template comes from prompts.py and patches are appended.\n",
                encoding="utf-8",
            )
        if not self.registry_path.exists():
            self._write_json(self.registry_path, {"version": 1, "active_variant_id": "base"})
        if not self.benchmark_path.exists():
            self._write_json(
                self.benchmark_path,
                {
                    "variants": {"base": {"status": "active", "attempts": 0, "success": 0}},
                    "pending": {},
                    "active_variant_id": "base",
                    "history": [],
                },
            )

    def _variant_payload(self, variant_id: str) -> Dict[str, Any]:
        if variant_id == "base":
            return {
                "variant_id": "base",
                "status": "active",
                "system_patch": "",
                "user_patch": "",
                "reason": "base",
            }
        path = self.generated_dir / f"{variant_id}.json"
        if not path.exists():
            return {
                "variant_id": variant_id,
                "status": "archived",
                "system_patch": "",
                "user_patch": "",
                "reason": "missing_file",
            }
        try:
            obj = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(obj, dict):
                return obj
        except Exception:
            pass
        return {
            "variant_id": variant_id,
            "status": "archived",
            "system_patch": "",
            "user_patch": "",
            "reason": "invalid_file",
        }

    def resolve_prompt_texts(
        self,
        base_system_prompt: str,
        base_user_template: str,
        run_id: str,
    ) -> Tuple[str, str, str]:
        active_variant_id = str(self.benchmark.get("active_variant_id") or "base")
        pending = self.benchmark.get("pending", {}) or {}
        # canary 按 run_id 做稳定抽样（约 1/3）
        canary_variant_id = None
        if pending:
            pick = sorted(list(pending.keys()))[0]
            if pick and run_id:
                try:
                    if int(run_id[-2:], 16) % 3 == 0:
                        canary_variant_id = pick
                except Exception:
                    pass

        selected_variant_id = canary_variant_id or active_variant_id
        variant_obj = self._variant_payload(selected_variant_id)
        system_prompt = base_system_prompt + ("\n\n" + variant_obj.get("system_patch", "") if variant_obj.get("system_patch") else "")
        user_template = base_user_template + ("\n\n" + variant_obj.get("user_patch", "") if variant_obj.get("user_patch") else "")
        return system_prompt, user_template, selected_variant_id

    def _extract_failure_signals(self, plan_history: List[Dict[str, Any]]) -> Dict[str, int]:
        signals = {
            "missing_context": 0,
            "finish_blocked": 0,
            "tool_exception": 0,
            "insufficient_l2": 0,
        }
        for item in list(plan_history or []):
            obs = (item.get("observation") or {})
            summary = str(obs.get("result_summary", "") or "")
            preview = str(obs.get("result_preview", "") or "")
            if "缺少源码路径" in summary or "缺少 cve_id" in summary:
                signals["missing_context"] += 1
            if "拒绝 finish" in summary or "finish_blocked" in str(obs.get("tool_name", "")):
                signals["finish_blocked"] += 1
            if "工具执行异常" in summary:
                signals["tool_exception"] += 1
            if "L2" in summary and "缺失" in summary:
                signals["insufficient_l2"] += 1
            if "缺少 path 参数" in summary:
                signals["insufficient_l2"] += 1
            if "工具执行异常" in preview:
                signals["tool_exception"] += 1
        return signals

    def maybe_generate_candidate(self, user_request: str, plan_history: List[Dict[str, Any]], run_succeeded: bool) -> Optional[str]:
        # 仅在失败/质量不佳时生成候选
        if run_succeeded:
            return None
        signals = self._extract_failure_signals(plan_history)
        if max(signals.values()) <= 0:
            return None
        ts = int(time.time())
        variant_id = f"cand_{ts}"
        top_signal = sorted(signals.items(), key=lambda item: item[1], reverse=True)[0][0]
        system_patch_lines = [
            "### Prompt Evolution Patch",
            f"- failure_signal: {top_signal}",
            "- 在规划前先检查上下文是否完整；缺失时优先 set_context。",
            "- finish 前必须确认 L2 补证已尝试，否则继续补证。",
        ]
        user_patch_lines = [
            "### Prompt Evolution Patch",
            "- 若出现工具异常，优先选择更稳妥动作（如 glob 再 read）。",
            "- 若连续两轮结果为空，优先切换到补证或上下文动作。",
        ]
        payload = {
            "variant_id": variant_id,
            "status": "reviewed" if self.mode == "reviewed" else "canary",
            "reason": f"auto-generated from failure signal: {top_signal}",
            "signals": signals,
            "system_patch": "\n".join(system_patch_lines),
            "user_patch": "\n".join(user_patch_lines),
            "created_at": ts,
            "source_user_request": user_request[:300],
        }
        (self.generated_dir / f"{variant_id}.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        if self.mode == "reviewed":
            return variant_id

        pending = dict(self.benchmark.get("pending") or {})
        pending[variant_id] = {
            "attempts": 0,
            "success": 0,
            "status": "canary",
            "candidate_file": str(self.generated_dir / f"{variant_id}.json"),
            "baseline_rate": self._active_success_rate(),
        }
        self.benchmark["pending"] = pending
        self._write_json(self.benchmark_path, self.benchmark)
        return variant_id

    def _active_success_rate(self) -> float:
        active_id = str(self.benchmark.get("active_variant_id") or "base")
        stats = ((self.benchmark.get("variants") or {}).get(active_id) or {})
        attempts = float(stats.get("attempts", 0))
        success = float(stats.get("success", 0))
        if attempts <= 0:
            return 0.5
        return success / attempts

    def record_run_outcome(self, variant_id: str, run_succeeded: bool) -> None:
        variants = dict(self.benchmark.get("variants") or {})
        stats = dict(variants.get(variant_id) or {"status": "active" if variant_id == "base" else "canary", "attempts": 0, "success": 0})
        stats["attempts"] = int(stats.get("attempts", 0)) + 1
        if run_succeeded:
            stats["success"] = int(stats.get("success", 0)) + 1
        variants[variant_id] = stats
        self.benchmark["variants"] = variants

        pending = dict(self.benchmark.get("pending") or {})
        if variant_id in pending:
            p = dict(pending[variant_id] or {})
            p["attempts"] = int(p.get("attempts", 0)) + 1
            if run_succeeded:
                p["success"] = int(p.get("success", 0)) + 1
            attempts = int(p.get("attempts", 0))
            success = int(p.get("success", 0))
            if attempts >= self.canary_trials:
                rate = success / max(1, attempts)
                if rate >= self.canary_pass_rate:
                    self.benchmark["active_variant_id"] = variant_id
                    variants[variant_id]["status"] = "active"
                    p["status"] = "promoted"
                else:
                    variants[variant_id]["status"] = "archived"
                    p["status"] = "rejected"
                pending.pop(variant_id, None)
            else:
                pending[variant_id] = p
        self.benchmark["pending"] = pending
        self.benchmark["history"] = list(self.benchmark.get("history") or [])[-500:] + [
            {"ts": int(time.time()), "variant_id": variant_id, "ok": bool(run_succeeded)}
        ]
        self._write_json(self.benchmark_path, self.benchmark)
        self._sync_registry_active_variant()

    def list_variants(self) -> Dict[str, Any]:
        variants = dict(self.benchmark.get("variants") or {})
        pending = dict(self.benchmark.get("pending") or {})
        rows: List[Dict[str, Any]] = []
        for variant_id, stats in variants.items():
            row = {
                "variant_id": variant_id,
                "status": stats.get("status", "unknown"),
                "attempts": int(stats.get("attempts", 0)),
                "success": int(stats.get("success", 0)),
            }
            if variant_id in pending:
                row["pending"] = dict(pending[variant_id] or {})
            rows.append(row)
        rows.sort(key=lambda item: item["variant_id"])
        return {
            "active_variant_id": str(self.benchmark.get("active_variant_id") or "base"),
            "variants": rows,
            "pending_count": len(pending),
        }

    def approve_variant(self, variant_id: str) -> Dict[str, Any]:
        variant_file = self.generated_dir / f"{variant_id}.json"
        if variant_id != "base" and not variant_file.exists():
            return {"ok": False, "error": f"variant not found: {variant_id}"}

        variants = dict(self.benchmark.get("variants") or {})
        stats = dict(variants.get(variant_id) or {"status": "reviewed", "attempts": 0, "success": 0})
        stats["status"] = "active"
        variants[variant_id] = stats
        self.benchmark["variants"] = variants
        self.benchmark["active_variant_id"] = variant_id

        pending = dict(self.benchmark.get("pending") or {})
        pending.pop(variant_id, None)
        self.benchmark["pending"] = pending

        self._write_json(self.benchmark_path, self.benchmark)
        self._sync_registry_active_variant()
        return {"ok": True, "approved_variant_id": variant_id}

    def reject_variant(self, variant_id: str) -> Dict[str, Any]:
        variants = dict(self.benchmark.get("variants") or {})
        if variant_id not in variants and variant_id != "base":
            variant_file = self.generated_dir / f"{variant_id}.json"
            if not variant_file.exists():
                return {"ok": False, "error": f"variant not found: {variant_id}"}
            variants[variant_id] = {"status": "archived", "attempts": 0, "success": 0}
        stats = dict(variants.get(variant_id) or {})
        stats["status"] = "archived"
        variants[variant_id] = stats
        self.benchmark["variants"] = variants

        pending = dict(self.benchmark.get("pending") or {})
        pending.pop(variant_id, None)
        self.benchmark["pending"] = pending

        active_variant = str(self.benchmark.get("active_variant_id") or "base")
        if active_variant == variant_id:
            self.benchmark["active_variant_id"] = "base"
            base_stats = dict((self.benchmark.get("variants") or {}).get("base") or {"attempts": 0, "success": 0})
            base_stats["status"] = "active"
            self.benchmark["variants"]["base"] = base_stats

        self._write_json(self.benchmark_path, self.benchmark)
        self._sync_registry_active_variant()
        return {"ok": True, "rejected_variant_id": variant_id}
