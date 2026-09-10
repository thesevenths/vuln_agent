"""
project_file_index.py — 目标源码树的通用文件索引与 L2 路径解析。
"""
from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from language_profiles import LanguageProfile, get_language_profile, normalize_profile_language


@dataclass
class ProjectFileIndex:
    """分层文件索引，供 Planner/反证引用。"""

    local_source_path: str
    language: str
    configs: List[str] = field(default_factory=list)
    headers: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    build_files: List[str] = field(default_factory=list)
    all_paths: Set[str] = field(default_factory=set)
    truncated: bool = False
    total_discovered: int = 0

    def contains(self, rel_path: str) -> bool:
        norm = _norm_rel(rel_path)
        if norm in self.all_paths:
            return True
        base = Path(norm).name.lower()
        return any(Path(p).name.lower() == base for p in self.all_paths)

    def find_by_basename(self, basename: str) -> List[str]:
        target = basename.lower()
        return sorted(p for p in self.all_paths if Path(p).name.lower() == target)

    def find_glob(self, pattern: str) -> List[str]:
        pat = pattern.replace("\\", "/").lower()
        if not any(ch in pat for ch in "*?["):
            return self.find_by_basename(Path(pat).name)
        return sorted(
            p for p in self.all_paths if fnmatch.fnmatch(_norm_rel(p), pat)
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "local_source_path": self.local_source_path,
            "language": self.language,
            "configs": self.configs[:80],
            "headers": self.headers[:80],
            "sources": self.sources[:80],
            "build_files": self.build_files[:40],
            "all_paths_sample": sorted(self.all_paths)[:120],
            "truncated": self.truncated,
            "total_discovered": self.total_discovered,
        }

    def flat_list_for_prompt(self, limit: int = 100) -> List[str]:
        """给 LLM 的可用路径列表：构建/配置优先，再头文件，再源文件。"""
        ordered: List[str] = []
        seen: Set[str] = set()
        for bucket in (self.build_files, self.configs, self.headers, self.sources):
            for item in bucket:
                if item not in seen:
                    seen.add(item)
                    ordered.append(item)
                if len(ordered) >= limit:
                    return ordered
        return ordered


@dataclass
class ResolvedL2Path:
    path: str
    resolved_via: str  # exact | basename | alias | glob
    original: str
    kind: str = "config"  # config | header | source | unknown


def _norm_rel(path: str) -> str:
    s = str(path or "").replace("\\", "/").strip()
    # 只剥离前缀 "./"，不用 lstrip("./") 以免逐字符剥离导致
    # .editorconfig → editorconfig、.github/ → github/ 等问题
    if s.startswith("./"):
        s = s[2:]
    return s


def _classify_path(rel: str, profile: LanguageProfile) -> str:
    name = Path(rel).name.lower()
    suffix = Path(rel).suffix.lower()
    if name in profile.build_file_names:
        return "build"
    if suffix in profile.header_extensions:
        return "header"
    if suffix in profile.source_extensions:
        return "source"
    if "config" in name or name.endswith(".yml") or name.endswith(".properties"):
        return "config"
    if suffix in (".xml", ".json", ".toml", ".ini", ".cfg", ".conf"):
        return "config"
    return "other"


def build_project_file_index(
    local_source_path: Optional[str],
    language: str = "cpp",
    *,
    max_total: int = 4000,
    max_sources: int = 2000,
) -> Optional[ProjectFileIndex]:
    if not local_source_path or not os.path.isdir(local_source_path):
        return None

    profile = get_language_profile(language)
    base = Path(local_source_path)
    skip_dirs = {
        ".git", "node_modules", "__pycache__", ".idea", "venv", ".vscode",
        "target", "build", "dist", ".gradle",
    }
    interesting_suffixes = (
        profile.source_extensions
        | profile.header_extensions
        | {".xml", ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".properties"}
    )

    index = ProjectFileIndex(
        local_source_path=str(base),
        language=normalize_profile_language(language),
    )
    source_count = 0

    try:
        for root, dirs, files in os.walk(base):
            dirs[:] = [d for d in dirs if d.lower() not in skip_dirs]
            for fname in files:
                fpath = Path(root) / fname
                try:
                    rel = _norm_rel(str(fpath.relative_to(base)))
                except ValueError:
                    continue
                index.total_discovered += 1
                if index.total_discovered > max_total:
                    index.truncated = True
                    break
                index.all_paths.add(rel)
                name_lower = fname.lower()
                suffix = fpath.suffix.lower()
                category = _classify_path(rel, profile)
                if name_lower in profile.build_file_names:
                    index.build_files.append(rel)
                elif category == "config":
                    index.configs.append(rel)
                elif category == "header":
                    index.headers.append(rel)
                elif category == "source":
                    if source_count < max_sources:
                        index.sources.append(rel)
                        source_count += 1
                elif suffix in interesting_suffixes or name_lower in profile.build_file_names:
                    index.configs.append(rel)
            if index.truncated:
                break
    except OSError:
        return index

    return index


def _path_component_overlap(requested: str, candidate: str) -> float:
    """计算两条路径的前缀组件重合比例（0.0 ~ 1.0）。

    用于 basename fallback 过滤：同名文件在不同子目录下时
    比例过低说明它们只是碰巧同名，不应互相替代。
    """
    req_parts = [p for p in requested.replace("\\", "/").split("/") if p]
    cand_parts = [p for p in candidate.replace("\\", "/").split("/") if p]
    if not req_parts:
        return 0.0
    common = 0
    for rp, cp in zip(req_parts, cand_parts):
        if rp.lower() == cp.lower():
            common += 1
        else:
            break
    return common / len(req_parts)


def resolve_l2_path(
    raw_path: str,
    *,
    language: str,
    file_index: Optional[ProjectFileIndex],
    local_source_path: Optional[str] = None,
) -> Optional[ResolvedL2Path]:
    """
    将反证/Planner 建议路径解析为索引中真实存在的相对路径。
    """
    from l2_reads import is_l2_path_applicable, sanitize_l2_read_path

    if not is_l2_path_applicable(raw_path, language):
        return None
    normalized = sanitize_l2_read_path(raw_path, local_source_path)
    if not normalized:
        return None
    if "*" in normalized or "?" in normalized:
        if file_index:
            matches = file_index.find_glob(normalized.lower())
            if matches:
                return ResolvedL2Path(
                    path=matches[0],
                    resolved_via="glob",
                    original=raw_path,
                    kind=_guess_kind(matches[0], language),
                )
        return None

    norm = _norm_rel(normalized)
    if file_index:
        if norm in file_index.all_paths:
            return ResolvedL2Path(
                path=norm,
                resolved_via="exact",
                original=raw_path,
                kind=_guess_kind(norm, language),
            )
        basename = Path(norm).name
        matches = file_index.find_by_basename(basename)
        if matches:
            # 仅当路径前缀组件重合度 >= 60% 时才接受 basename fallback，
            # 避免不同子目录下的同名文件（如多个 lesson 目录里的
            # WebGoatLabels.properties）互相替代导致读错文件。
            best_match: Optional[str] = None
            best_overlap = 0.0
            for m in matches:
                overlap = _path_component_overlap(norm, m)
                if overlap > best_overlap:
                    best_overlap = overlap
                    best_match = m
            if best_match and best_overlap >= 0.6:
                return ResolvedL2Path(
                    path=best_match,
                    resolved_via="basename",
                    original=raw_path,
                    kind=_guess_kind(best_match, language),
                )
        profile = get_language_profile(language)
        for pattern in profile.config_globs:
            if not any(ch in pattern for ch in "*?["):
                continue
            glob_matches = file_index.find_glob(pattern.lower())
            if glob_matches and _alias_matches_request(norm, basename, pattern, glob_matches):
                return ResolvedL2Path(
                    path=glob_matches[0],
                    resolved_via="alias",
                    original=raw_path,
                    kind="config",
                )
    return None


def _alias_matches_request(
    norm: str, basename: str, pattern: str, matches: List[str]
) -> bool:
    """config.h 等泛名映射到项目内真实 config 文件。"""
    req = basename.lower()
    if req in ("config.h",) and "config" in pattern.lower():
        return True
    if "config" in norm.lower() and any("config" in m.lower() for m in matches):
        return True
    return False


def _guess_kind(rel_path: str, language: str) -> str:
    profile = get_language_profile(language)
    cat = _classify_path(rel_path, profile)
    if cat in ("build", "config"):
        return "config"
    if cat == "header":
        return "header"
    if cat == "source":
        return "source"
    return "unknown"


def build_l2_refutation_file_list(
    *,
    local_source_path: Optional[str],
    language: str = "cpp",
    sink_file: str = "",
    metadata: Optional[Dict[str, Any]] = None,
    limit: int = 120,
) -> str:
    """
    反证 prompt 用的 L2 相关文件子集（非全量源文件列表）。

    优先级：构建/配置 → 配置类头文件 → 当前 sink 源文件 → sink 同目录邻居。
    """
    profile = get_language_profile(language)
    index = index_from_metadata(metadata or {}) if metadata else None
    if index is None and local_source_path:
        index = build_project_file_index(local_source_path, language)

    ordered: List[str] = []
    seen: Set[str] = set()

    def add(path: str) -> None:
        norm = _norm_rel(path)
        if not norm:
            return
        key = norm.lower()
        if key in seen:
            return
        seen.add(key)
        ordered.append(norm)

    if index:
        for bucket in (index.build_files, index.configs):
            for item in bucket:
                add(item)
                if len(ordered) >= limit:
                    return ", ".join(ordered)
        for item in index.headers:
            name = Path(item).name.lower()
            lowered = item.lower()
            if "config" in name or any(kw in lowered for kw in profile.config_keywords):
                add(item)
                if len(ordered) >= limit:
                    return ", ".join(ordered)

        for basename in ("mbedtls_config.h", "config.h", "CMakeLists.txt", "pom.xml"):
            for match in index.find_by_basename(basename):
                add(match)
                if len(ordered) >= limit:
                    return ", ".join(ordered)

    sink_norm = _norm_rel(sink_file)
    if sink_norm:
        add(sink_norm)
        if index:
            parent = Path(sink_norm).parent.as_posix()
            if parent and parent != ".":
                for rel in sorted(index.all_paths):
                    if rel == sink_norm:
                        continue
                    if rel.startswith(parent + "/") or Path(rel).parent.as_posix() == parent:
                        add(rel)
                        if len(ordered) >= limit:
                            break

    return ", ".join(ordered[:limit])


def index_from_metadata(metadata: Dict[str, Any]) -> Optional[ProjectFileIndex]:
    payload = metadata.get("project_file_index")
    if not isinstance(payload, dict):
        return None
    idx = ProjectFileIndex(
        local_source_path=payload.get("local_source_path", ""),
        language=payload.get("language", "cpp"),
        truncated=bool(payload.get("truncated")),
        total_discovered=int(payload.get("total_discovered") or 0),
    )
    for key in ("configs", "headers", "sources", "build_files"):
        for item in payload.get(key) or []:
            norm = _norm_rel(str(item))
            idx.all_paths.add(norm)
            getattr(idx, key if key != "build_files" else "build_files").append(norm)
    for item in payload.get("all_paths_sample") or []:
        idx.all_paths.add(_norm_rel(str(item)))
    return idx
