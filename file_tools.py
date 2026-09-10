"""
跨平台本地文件读写（Windows / Linux）。

供 Agent 读取 pom.xml、application.yml、源码片段等；并将漏洞报告写入 Markdown。
路径解析使用 pathlib，读写统一 UTF-8（可配置）。

证据层级：经 Planner 的 FileTool 读到的内容主要用于补齐 **L2 静态补证**
（配置/依赖/跨文件源码），与 Joern 污点流所属的 **L1** 区分；定义见 evidence_levels.py。
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

PathLike = Union[str, Path]

# 单次读取默认上限（字节），避免把超大文件塞进 LLM
DEFAULT_MAX_READ_BYTES = int(os.environ.get("AGENT_FILE_MAX_READ_BYTES", "262144"))
# 默认报告输出目录（相对当前工作目录）
DEFAULT_REPORT_DIR = os.environ.get("AGENT_REPORT_DIR", "agent_reports")


def _split_root_list(raw: str) -> List[str]:
    if not raw:
        return []
    normalized = raw.replace(";", ",")
    return [item.strip() for item in normalized.split(",") if item.strip()]


def normalize_path(path: PathLike) -> Path:
    """将用户/模型传入路径规范为当前 OS 的 Path（支持 / 与 \\）。"""
    if isinstance(path, Path):
        candidate = path
    else:
        text = str(path).strip().strip('"').strip("'")
        candidate = Path(text)
    try:
        return candidate.expanduser()
    except (TypeError, ValueError):
        return Path(str(path))


class FileTool:
    """
    受根目录约束的本地文件工具。

    仅允许访问「已授权根目录」下的路径，防止任意文件读取。
    """

    def __init__(self, extra_roots: Optional[Sequence[str]] = None):
        self._static_extra_roots = list(extra_roots or [])

    def collect_allowed_roots(self, state: Any = None) -> List[Path]:
        """
        汇总允许读写的根目录（存在且为目录的才保留）。

        优先级：环境变量 AGENT_FILE_READ_ROOTS → state.local_source_path →
        state.project_path（仅当本机存在）→ 当前工作目录 → 构造时 extra_roots。
        """
        root_candidates: List[str] = []
        root_candidates.extend(_split_root_list(os.environ.get("AGENT_FILE_READ_ROOTS", "")))
        root_candidates.extend(self._static_extra_roots)

        if state is not None:
            local_source = getattr(state, "local_source_path", None)
            project_path = getattr(state, "project_path", None)
            if local_source:
                root_candidates.append(local_source)
            if project_path and os.path.isdir(project_path):
                root_candidates.append(project_path)

        root_candidates.append(os.getcwd())

        resolved_roots: List[Path] = []
        seen: set[str] = set()
        for item in root_candidates:
            if not item:
                continue
            try:
                resolved = normalize_path(item).resolve(strict=False)
            except (OSError, ValueError):
                continue
            if not resolved.is_dir():
                continue
            key = str(resolved).lower() if os.name == "nt" else str(resolved)
            if key in seen:
                continue
            seen.add(key)
            resolved_roots.append(resolved)
        return resolved_roots

    def resolve_allowed_path(self, path: PathLike, state: Any = None, *, for_write: bool = False) -> Path:
        """
        解析路径并校验其在授权根目录下。

        Raises:
            ValueError: 路径非法、不存在（写模式可创建父目录）、越权。
        """
        target = normalize_path(path)
        if not target.is_absolute():
            # 优先解析到 local_source_path，否则 fallback 到 cwd
            base_dir = Path.cwd()
            if state and getattr(state, 'local_source_path', None):
                base_dir = Path(state.local_source_path)
            target = (base_dir / target).resolve(strict=False)
        else:
            target = target.resolve(strict=False)

        allowed_roots = self.collect_allowed_roots(state)
        if not allowed_roots:
            raise ValueError("未配置任何可读根目录（请设置 local_source_path 或 AGENT_FILE_READ_ROOTS）")

        if not self._is_under_any_root(target, allowed_roots):
            roots_display = ", ".join(str(root) for root in allowed_roots)
            raise ValueError(
                f"路径越权: {target} 不在授权根目录下。当前允许根: {roots_display}"
            )

        if for_write:
            parent = target.parent
            if not parent.exists():
                parent.mkdir(parents=True, exist_ok=True)
            return target

        if not target.exists():
            raise ValueError(f"文件不存在: {target}")
        if target.is_dir():
            raise ValueError(f"目标是目录而非文件: {target}，请指定具体文件路径")
        return target

    def resolve_allowed_dir(self, path: PathLike, state: Any = None) -> Path:
        """
        解析目录路径并校验其在授权根目录下。

        与 resolve_allowed_path 的区别：
        - 允许目标为目录（用于 glob 搜索等场景）
        """
        target = normalize_path(path)
        if not target.is_absolute():
            target = (Path.cwd() / target).resolve(strict=False)
        else:
            target = target.resolve(strict=False)

        allowed_roots = self.collect_allowed_roots(state)
        if not allowed_roots:
            raise ValueError("未配置任何可读根目录（请设置 local_source_path 或 AGENT_FILE_READ_ROOTS）")

        if not self._is_under_any_root(target, allowed_roots):
            roots_display = ", ".join(str(root) for root in allowed_roots)
            raise ValueError(
                f"路径越权: {target} 不在授权根目录下。当前允许根: {roots_display}"
            )

        if not target.exists():
            raise ValueError(f"目录不存在: {target}")
        if not target.is_dir():
            raise ValueError(f"目标不是目录: {target}")
        return target

    @staticmethod
    def _is_under_any_root(target: Path, roots: Sequence[Path]) -> bool:
        try:
            target_resolved = target.resolve(strict=False)
        except (OSError, ValueError):
            return False

        for root in roots:
            try:
                root_resolved = root.resolve(strict=False)
            except (OSError, ValueError):
                continue
            if os.name == "nt":
                # Windows: 比较 drive + 路径前缀，避免大小写问题
                if (
                    target_resolved.drive.lower() == root_resolved.drive.lower()
                    and str(target_resolved).lower().startswith(str(root_resolved).lower())
                ):
                    return True
            else:
                try:
                    target_resolved.relative_to(root_resolved)
                    return True
                except ValueError:
                    continue
        return False

    def read_file(
        self,
        path: PathLike,
        *,
        state: Any = None,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None,
        max_bytes: Optional[int] = None,
        encoding: str = "utf-8",
    ) -> Dict[str, Any]:
        """
        读取文本文件（支持按行范围）。

        Returns:
            包含绝对路径、行范围、内容、是否截断等字段的字典。
        """
        byte_limit = max_bytes if max_bytes is not None else DEFAULT_MAX_READ_BYTES
        resolved = self.resolve_allowed_path(path, state, for_write=False)

        raw_bytes = resolved.read_bytes()
        truncated_by_bytes = len(raw_bytes) > byte_limit
        if truncated_by_bytes:
            raw_bytes = raw_bytes[:byte_limit]

        text = raw_bytes.decode(encoding, errors="replace")
        lines = text.splitlines()

        start = max(1, int(start_line)) if start_line else 1
        end = int(end_line) if end_line else len(lines)
        if end < start:
            end = start
        sliced = lines[start - 1 : end]

        numbered = "\n".join(f"{start + index:6d}| {line}" for index, line in enumerate(sliced))
        return {
            "ok": True,
            "path": str(resolved),
            "os": os.name,
            "encoding": encoding,
            "total_lines": len(lines),
            "start_line": start,
            "end_line": min(end, len(lines)),
            "truncated_by_bytes": truncated_by_bytes,
            "max_bytes": byte_limit,
            "content": numbered,
        }

    def glob_files(
        self,
        pattern: str,
        *,
        state: Any = None,
        root: Optional[PathLike] = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """在授权根目录下 glob 搜索（如 `**/pom.xml`）。"""
        allowed_roots = self.collect_allowed_roots(state)
        if root is not None:
            # root 允许为目录；若传入文件则以其父目录为搜索起点
            candidate = normalize_path(root)
            if not candidate.is_absolute():
                candidate = (Path.cwd() / candidate).resolve(strict=False)
            else:
                candidate = candidate.resolve(strict=False)
            if candidate.exists() and candidate.is_file():
                candidate = candidate.parent
            search_root = self.resolve_allowed_dir(candidate, state)
            allowed_roots = [search_root]

        # 处理绝对路径 pattern（Python pathlib 不支持 non-relative patterns）
        # 例如: "E:\vuln_agent\WebGoat-2025.3\**\*.java" 或 "/app/vuln_app/**/*.java"
        sanitized_pattern = pattern
        if pattern:
            p = Path(pattern)
            if p.is_absolute():
                # 提取相对 glob 部分（去掉根路径前缀）
                # 例如 "E:\\vuln_agent\\WebGoat-2025.3\\**\\*.java" → "**/*.java"
                # 寻找第一个含通配符的组件之后的部分
                parts = pattern.replace("\\", "/").split("/")
                relative_parts = []
                found_glob = False
                for part in parts:
                    if found_glob or "*" in part or "?" in part or "[" in part:
                        relative_parts.append(part)
                        found_glob = True
                if relative_parts:
                    sanitized_pattern = "/".join(relative_parts)
                # 如果提取失败，回退到 **/* 搜索所有文件
                else:
                    sanitized_pattern = "**/*"

        matches: List[str] = []
        for base in allowed_roots:
            for hit in base.glob(sanitized_pattern):
                if hit.is_file():
                    matches.append(str(hit.resolve(strict=False)))
                if len(matches) >= limit:
                    break
            if len(matches) >= limit:
                break

        return {
            "ok": True,
            "pattern": pattern,
            "count": len(matches),
            "matches": matches[:limit],
        }

    def write_text(
        self,
        path: PathLike,
        content: str,
        *,
        state: Any = None,
        append: bool = False,
        encoding: str = "utf-8",
    ) -> Dict[str, Any]:
        """写入文本文件（须在授权根目录下）。"""
        resolved = self.resolve_allowed_path(path, state, for_write=True)
        mode = "a" if append else "w"
        with open(resolved, mode, encoding=encoding, newline="\n") as handle:
            handle.write(content)
        return {
            "ok": True,
            "path": str(resolved),
            "bytes_written": len(content.encode(encoding)),
            "append": append,
        }

    def write_report(
        self,
        content: str,
        *,
        state: Any = None,
        filename: Optional[str] = None,
        subdir: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        将 Markdown 报告写入默认报告目录。

        目录由 AGENT_REPORT_DIR 控制（默认 `./agent_reports`）。
        """
        report_dir = normalize_path(DEFAULT_REPORT_DIR)
        if not report_dir.is_absolute():
            report_dir = (Path.cwd() / report_dir).resolve(strict=False)
        if subdir:
            report_dir = report_dir / subdir
        report_dir.mkdir(parents=True, exist_ok=True)

        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            cve_part = ""
            if state is not None and getattr(state, "current_cve_id", None):
                cve_part = f"_{state.current_cve_id}"
            filename = f"vuln_report{cve_part}_{timestamp}.md"

        target = report_dir / filename
        return self.write_text(target, content, state=state, append=False)
