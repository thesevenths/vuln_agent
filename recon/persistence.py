"""
recon/persistence.py — 侦查结果持久化

将 AttackSurfaceMap 保存为 JSON 到 checkpoints 目录，
支持跨扫描复用（同项目不重跑侦查）。

目录结构：
    agent_reports/checkpoints/{project_name}/recon/
        attack_surface.json      # 完整攻击面地图（唯一必要文件）
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

from recon.models import AttackSurfaceMap

logger = logging.getLogger(__name__)

# 缓存过期时间（秒），默认 7 天
_CACHE_TTL_SECONDS = int(os.environ.get("RECON_CACHE_TTL", "604800"))


class ReconPersistence:
    """侦查结果持久化管理器"""

    def __init__(self, checkpoint_dir: Path, project_name: str):
        """
        Args:
            checkpoint_dir: 检查点根目录（通常是 agent_reports/checkpoints）。
            project_name: 项目名（用于目录隔离）。
        """
        self.base_dir = Path(checkpoint_dir) / project_name / "recon"
        self._attack_surface_file = self.base_dir / "attack_surface.json"

    def save(self, attack_surface: AttackSurfaceMap) -> Path:
        """
        保存攻击面地图到 JSON 文件。

        Args:
            attack_surface: 完整 AttackSurfaceMap 实例。

        Returns:
            保存的文件路径。
        """
        self.base_dir.mkdir(parents=True, exist_ok=True)
        data = attack_surface.to_dict()
        # 写入元数据
        data["_meta"] = {
            "saved_at": time.time(),
            "source_path_hash": _hash_path(attack_surface.project_info.source_path),
        }
        content = json.dumps(data, ensure_ascii=False, indent=2, default=str)
        self._attack_surface_file.write_text(content, encoding="utf-8")
        logger.info("Recon 持久化: 攻击面地图已保存 → %s", self._attack_surface_file)
        return self._attack_surface_file

    def load(self) -> Optional[AttackSurfaceMap]:
        """
        加载已缓存的攻击面地图。

        Returns:
            AttackSurfaceMap 实例，或 None（缓存不存在/已过期/校验失败）。
        """
        if not self._attack_surface_file.exists():
            return None

        try:
            raw = self._attack_surface_file.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Recon 缓存读取失败: %s", exc)
            return None

        # 检查过期
        meta = data.get("_meta") or {}
        saved_at = meta.get("saved_at", 0)
        if _CACHE_TTL_SECONDS > 0 and (time.time() - saved_at) > _CACHE_TTL_SECONDS:
            logger.info("Recon 缓存已过期 (%ds > TTL %ds)", time.time() - saved_at, _CACHE_TTL_SECONDS)
            return None

        # 反序列化
        try:
            result = AttackSurfaceMap.from_dict(data)
            logger.info("Recon 持久化: 从缓存加载攻击面地图 ← %s", self._attack_surface_file)
            return result
        except Exception as exc:
            logger.warning("Recon 缓存反序列化失败: %s", exc)
            return None

    def is_valid(self, source_path: str) -> bool:
        """
        检查缓存是否仍然有效（source_path 匹配 + 未过期）。

        Args:
            source_path: 当前扫描的源码路径。

        Returns:
            True 表示缓存有效且可复用。
        """
        if not self._attack_surface_file.exists():
            return False

        try:
            raw = self._attack_surface_file.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (json.JSONDecodeError, OSError):
            return False

        meta = data.get("_meta") or {}

        # 检查 source_path 一致性
        cached_hash = meta.get("source_path_hash", "")
        if cached_hash and cached_hash != _hash_path(source_path):
            logger.info("Recon 缓存失效: source_path 已变更")
            return False

        # 检查过期
        saved_at = meta.get("saved_at", 0)
        if _CACHE_TTL_SECONDS > 0 and (time.time() - saved_at) > _CACHE_TTL_SECONDS:
            logger.info("Recon 缓存已过期")
            return False

        return True

    def clear(self) -> None:
        """清空所有缓存文件"""
        if self.base_dir.exists():
            import shutil
            shutil.rmtree(self.base_dir, ignore_errors=True)
            logger.info("Recon 缓存已清空: %s", self.base_dir)


def _hash_path(path: str) -> str:
    """对路径字符串取短哈希，用于校验一致性"""
    return hashlib.sha256(path.encode("utf-8")).hexdigest()[:16]
