"""
recon/scanners/project_structure.py — 项目结构感知

通过文件遍历（不需要 CPG）检测：
- 构建文件（pom.xml, build.gradle, pyproject.toml 等）
- 配置文件（application.yml, settings.py 等）
- CI/CD 配置（Jenkinsfile, .github/workflows 等）
- 容器配置（Dockerfile, docker-compose.yml 等）
- 子模块
"""
from __future__ import annotations

import glob
import logging
import os
from typing import List

from recon.adapters.base import ReconAdapter
from recon.models import ModuleInfo, ProjectInfo

logger = logging.getLogger(__name__)


def scan_project_structure(
    source_path: str,
    adapter: ReconAdapter,
) -> ProjectInfo:
    """
    遍历项目目录，识别构建系统、模块、配置文件。

    Args:
        source_path: 项目源码根目录
        adapter: 语言/框架适配器（提供文件模式）

    Returns:
        ProjectInfo 实例
    """
    patterns = adapter.get_file_patterns()
    info = ProjectInfo(
        language=adapter.language,
        framework=adapter.framework_hint,
        build_system=_detect_build_system(source_path, patterns.get("build_files", [])),
        source_path=source_path,
    )

    # 扫描构建文件 → 子模块
    info.modules = _find_modules(source_path, patterns.get("build_files", []))

    # 扫描配置文件
    info.config_files = _find_files(source_path, patterns.get("config_files", []))

    # CI/CD
    info.ci_cd_files = _find_files(source_path, patterns.get("ci_cd_files", []))

    # 容器配置
    info.container_files = _find_files(source_path, patterns.get("container_files", []))

    # 依赖计数
    info.dependency_count = _count_dependencies(source_path, info.build_system)

    # 适配器特定丰富
    info = adapter.enrich_project_info(source_path, info)

    logger.info(
        "项目结构: %s/%s | 构建=%s | 模块=%d | 配置=%d | CI=%d | 容器=%d",
        info.language, info.framework, info.build_system,
        len(info.modules), len(info.config_files),
        len(info.ci_cd_files), len(info.container_files),
    )
    return info


def _detect_build_system(source_path: str, build_patterns: List[str]) -> str:
    for pat in build_patterns:
        if os.path.exists(os.path.join(source_path, pat)):
            if pat in ("pom.xml",):
                return "maven"
            if pat in ("build.gradle", "build.gradle.kts", "settings.gradle"):
                return "gradle"
            if pat in ("pyproject.toml",):
                return "poetry"
            if pat in ("requirements.txt", "Pipfile"):
                return "pip"
            if pat in ("setup.py", "setup.cfg"):
                return "setuptools"
            if pat in ("go.mod",):
                return "go_modules"
            if pat in ("package.json",):
                return "npm"
    return "unknown"


def _find_modules(source_path: str, build_patterns: List[str]) -> List[ModuleInfo]:
    modules: List[ModuleInfo] = []
    for pat in build_patterns:
        # 递归查找
        for root, _dirs, files in os.walk(source_path):
            for f in files:
                if f == pat or (pat.startswith("*.") and f.endswith(pat[1:])):
                    full = os.path.join(root, f)
                    rel = os.path.relpath(full, source_path)
                    mod_path = os.path.dirname(rel)
                    modules.append(ModuleInfo(
                        name=os.path.basename(mod_path) if mod_path else "root",
                        path=mod_path or ".",
                        build_file=rel,
                    ))
    return modules


def _find_files(source_path: str, patterns: List[str]) -> List[str]:
    found: List[str] = []
    for pat in patterns:
        full_pat = os.path.join(source_path, "**", pat) if "**" not in pat else os.path.join(source_path, pat)
        for match in glob.glob(full_pat, recursive=True):
            rel = os.path.relpath(match, source_path)
            if rel not in found:
                found.append(rel)
    return found


def _count_dependencies(source_path: str, build_system: str) -> int:
    """粗略统计依赖数量"""
    if build_system == "maven":
        pom = os.path.join(source_path, "pom.xml")
        if os.path.exists(pom):
            try:
                content = open(pom, encoding="utf-8", errors="replace").read()
                return content.count("<dependency>")
            except Exception:
                pass
    elif build_system in ("pip", "poetry"):
        req = os.path.join(source_path, "requirements.txt")
        if os.path.exists(req):
            try:
                lines = open(req, encoding="utf-8", errors="replace").readlines()
                return sum(1 for l in lines if l.strip() and not l.startswith("#") and not l.startswith("-"))
            except Exception:
                pass
    return 0
