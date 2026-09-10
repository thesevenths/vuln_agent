"""
`cve_knowledge_base.py` CVE 知识库缓存 + 查询接口。

设计目标：
1. 本地 JSON 缓存，避免每次运行都查 DB
2. 提供简洁的查询 API（按 CWE 查 sink、按组件查版本、获取典型案例）
3. 支持定期从 DB 刷新缓存

数据流：
PostgreSQL → CVEKnowledgeExtractor → 本地 cve_kb_cache.json → CVEKnowledgeBase API
"""

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from cve_knowledge_extractor import CVEKnowledgeExtractor

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# 缓存有效期：24 小时（秒）
DEFAULT_CACHE_TTL = 86400


class CVEKnowledgeBase:
    """CVE 知识库缓存 + 查询接口。"""

    def __init__(
        self,
        cache_file: Optional[str] = None,
        extractor: Optional[CVEKnowledgeExtractor] = None,
        dsn: Optional[str] = None,
        cache_ttl: int = DEFAULT_CACHE_TTL,
    ):
        """
        初始化 CVE 知识库。

        Args:
            cache_file: 本地缓存文件路径。默认为 agent/cve_kb_cache.json。
            extractor: CVEKnowledgeExtractor 实例。若不传则自动创建。
            dsn: 数据库连接串（仅 extractor 未传时使用）。
            cache_ttl: 缓存有效期（秒）。
        """
        self.workspace_dir = Path(__file__).resolve().parent
        self.cache_file = Path(cache_file) if cache_file else self.workspace_dir / "cve_kb_cache.json"
        self.extractor = extractor or CVEKnowledgeExtractor(dsn=dsn)
        self.cache_ttl = cache_ttl
        self._cache: Optional[Dict[str, Any]] = None

    # ------------------------------------------------------------------
    # 缓存管理
    # ------------------------------------------------------------------

    def _load_cache(self) -> Dict[str, Any]:
        """从本地文件加载缓存。"""
        if self._cache is not None:
            return self._cache
        if self.cache_file.exists():
            try:
                data = json.loads(self.cache_file.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    self._cache = data
                    return self._cache
            except Exception as exc:
                logger.warning("缓存文件读取失败，将重新生成: %s", exc)
        self._cache = {"patterns": {}, "components": {}, "updated_at": 0}
        return self._cache

    def _save_cache(self) -> None:
        """将缓存写入本地文件。"""
        try:
            self.cache_file.write_text(
                json.dumps(self._cache or {}, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception as exc:
            logger.warning("缓存文件写入失败: %s", exc)

    def _is_cache_fresh(self) -> bool:
        """检查缓存是否在有效期内。"""
        cache = self._load_cache()
        updated_at = cache.get("updated_at", 0)
        return (time.time() - updated_at) < self.cache_ttl

    def refresh_from_db(self, force: bool = False) -> bool:
        """
        从数据库刷新缓存。

        Args:
            force: 是否强制刷新（忽略 TTL 检查）。

        Returns:
            是否成功刷新。
        """
        if not force and self._is_cache_fresh():
            logger.info("缓存未过期，跳过刷新")
            return True

        try:
            logger.info("正在从数据库刷新 CVE 知识库缓存...")
            # 提取所有 CWE 模式
            all_patterns = self.extractor.extract_cwe_patterns()
            pattern_map: Dict[str, Dict] = {}
            for p in all_patterns:
                cwe_id = p.get("cwe_id", "")
                if cwe_id:
                    pattern_map[cwe_id] = p

            self._cache = {
                "patterns": pattern_map,
                "components": {},
                "updated_at": time.time(),
                "stats": {
                    "cwe_count": len(pattern_map),
                    "total_cves": sum(p.get("cve_count", 0) for p in pattern_map.values()),
                },
            }
            self._save_cache()
            logger.info("CVE 知识库缓存刷新完成: %d 个 CWE", len(pattern_map))
            return True
        except Exception as exc:
            logger.error("CVE 知识库刷新失败: %s", exc)
            return False

    def _ensure_loaded(self) -> Dict[str, Any]:
        """确保缓存已加载（必要时从 DB 刷新）。"""
        cache = self._load_cache()
        if not cache.get("patterns") and not self._is_cache_fresh():
            self.refresh_from_db()
            cache = self._load_cache()
        return cache

    # ------------------------------------------------------------------
    # 查询 API
    # ------------------------------------------------------------------

    def get_cwe_sink_patterns(self, cwe_id: str) -> List[str]:
        """
        获取 CWE 对应的 sink 函数列表。

        Args:
            cwe_id: 如 'CWE-120'。

        Returns:
            sink 函数名列表。
        """
        cache = self._ensure_loaded()
        pattern = cache.get("patterns", {}).get(cwe_id, {})
        return pattern.get("common_sinks", [])

    def get_cwe_pattern(self, cwe_id: str) -> Optional[Dict[str, Any]]:
        """
        获取某个 CWE 的完整模式数据。

        Args:
            cwe_id: 如 'CWE-89'。

        Returns:
            CWE 模式字典，或 None。
        """
        cache = self._ensure_loaded()
        return cache.get("patterns", {}).get(cwe_id)

    def get_cve_examples(self, cwe_id: str, limit: int = 5) -> List[Dict[str, Any]]:
        """
        获取某个 CWE 下的典型 CVE 案例（用于 few-shot 学习）。

        Args:
            cwe_id: CWE 编号。
            limit: 最大返回数量。

        Returns:
            CVE 案例列表。
        """
        cache = self._ensure_loaded()
        pattern = cache.get("patterns", {}).get(cwe_id, {})
        # 当前缓存只存聚合数据；如需详细 CVE 案例，需实时查 DB
        # 这里返回缓存中已有的信息
        cve_count = pattern.get("cve_count", 0)
        return [{
            "cwe_id": cwe_id,
            "total_cves_in_db": cve_count,
            "common_sinks": pattern.get("common_sinks", [])[:limit],
            "common_components": pattern.get("common_components", [])[:limit],
        }]

    def get_affected_versions(self, component: str) -> List[Dict[str, Any]]:
        """
        获取组件受影响版本范围。

        Args:
            component: 组件名称。

        Returns:
            版本信息列表。
        """
        cache = self._ensure_loaded()
        comp_data = cache.get("components", {}).get(component)
        if comp_data:
            return [comp_data]
        # 缓存中未找到，尝试实时查询
        try:
            patterns = self.extractor.extract_component_patterns(component)
            if patterns:
                return patterns
        except Exception as exc:
            logger.warning("查询组件版本失败: %s", exc)
        return []

    def get_joern_query_types_for_cwe(self, cwe_id: str) -> List[str]:
        """
        获取 CWE 对应的 Joern 定向扫描查询类型。

        Args:
            cwe_id: 如 'CWE-120'。

        Returns:
            Joern 查询 key 列表。
        """
        cache = self._ensure_loaded()
        pattern = cache.get("patterns", {}).get(cwe_id, {})
        return pattern.get("joern_query_types", [])

    def get_analysis_context_text(self, cwe_id: str) -> str:
        """
        生成可嵌入 LLM prompt 的 CVE 知识参考文本。

        Args:
            cwe_id: CWE 编号。

        Returns:
            格式化的参考文本。
        """
        pattern = self.get_cwe_pattern(cwe_id)
        if not pattern:
            return ""

        sinks = pattern.get("common_sinks", [])
        components = pattern.get("common_components", [])
        cve_count = pattern.get("cve_count", 0)

        lines = [f"### CVE 知识库参考 ({cwe_id})"]
        lines.append(f"- 已知案例: {cve_count} 个")
        if sinks:
            lines.append(f"- 高频 sink 函数: {', '.join(sinks[:8])}")
        if components:
            lines.append(f"- 高频受影响组件: {', '.join(components[:5])}")
        return "\n".join(lines)

    def get_stats(self) -> Dict[str, Any]:
        """获取知识库统计概览。"""
        cache = self._ensure_loaded()
        return {
            "cwe_count": len(cache.get("patterns", {})),
            "cache_file": str(self.cache_file),
            "cache_fresh": self._is_cache_fresh(),
            "updated_at": cache.get("updated_at", 0),
            "stats": cache.get("stats", {}),
        }
