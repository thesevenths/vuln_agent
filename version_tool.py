"""
VersionTool：供 planner / GraphBuilder 调用的组件版本识别工具封装。

相似度算法不在此文件，见 `version_identification.py`：
- `fingerprint_similarity` — 单函数反编译 vs 源码
- `VersionIdentifier.identify` — 多候选聚合与报告
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from version_identification import VersionIdentifier


class VersionTool:
    """将反编译 C 与候选源码包比对，返回结构化识别结果与 Markdown 报告。"""

    def __init__(self, work_dir: Optional[str] = None):
        self._identifier = VersionIdentifier(work_dir=work_dir)

    def identify_component(
        self,
        decompiled_path: str,
        candidate_paths: Sequence[str],
        component_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        执行版本识别。

        Args:
            decompiled_path: Ghidra 导出的 *_decompiled.c 路径。
            candidate_paths: 候选官方源码 zip 或已解压目录列表（至少 2 个）。
            component_name: 可选组件名，用于报告标题。

        Returns:
            见 `VersionIdentifier.identify` 返回结构。
        """
        paths: List[str] = [str(p) for p in candidate_paths if p]
        if len(paths) < 2:
            return {
                "ok": False,
                "error": "candidate_paths 至少需要 2 个元素",
            }
        try:
            result = self._identifier.identify(
                decompiled_path=decompiled_path,
                candidate_paths=paths,
                component_name=component_name,
            )
            result["ok"] = True
            return result
        except Exception as exc:
            return {
                "ok": False,
                "error": str(exc),
                "error_type": exc.__class__.__name__,
            }
