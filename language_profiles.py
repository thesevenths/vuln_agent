"""
language_profiles.py — 按编程语言/生态的通用配置（不绑定具体项目或厂商）。

用于：L2 路径别名、配置文件 glob、L2 优先级关键词、构建文件识别。
Guard 检测正则仍主要在 joern_vuln_scanner（语言级通用模式，非 SecurityConfig 等框架类名）。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Tuple


@dataclass(frozen=True)
class LanguageProfile:
    """一种扫描语言的静态补证与索引配置。"""

    language: str
    source_extensions: FrozenSet[str]
    header_extensions: FrozenSet[str]
    build_file_names: FrozenSet[str]
    config_globs: Tuple[str, ...]
    config_keywords: Tuple[str, ...]
    l2_deny_basenames: FrozenSet[str]
    # 反证/Planner 提示用的一行说明（非硬编码路径）
    l2_playbook_hint: str


_PROFILES: Dict[str, LanguageProfile] = {
    "cpp": LanguageProfile(
        language="cpp",
        source_extensions=frozenset({".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hh"}),
        header_extensions=frozenset({".h", ".hpp", ".hh"}),
        build_file_names=frozenset(
            {"cmakelists.txt", "makefile", "meson.build", "configure.ac", "configure.in"}
        ),
        config_globs=(
            "**/*config*.h",
            "**/config.h",
            "**/CMakeLists.txt",
            "**/Makefile",
            "**/meson.build",
            "**/*.cmake",
        ),
        config_keywords=(
            "config.h",
            "cmake",
            "makefile",
            "meson",
            "build_info",
            "limits.h",
        ),
        l2_deny_basenames=frozenset(
            {"pom.xml", "build.gradle", "application.yml", "application.properties"}
        ),
        l2_playbook_hint=(
            "C/C++：优先构建脚本（CMakeLists/Makefile/meson）、"
            "*config*.h / build_info.h、与 sink 相关的头文件；"
            "勿读 Java 专用 pom.xml。"
        ),
    ),
    "java": LanguageProfile(
        language="java",
        source_extensions=frozenset({".java", ".kt", ".groovy"}),
        header_extensions=frozenset(),
        build_file_names=frozenset(
            {"pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle"}
        ),
        config_globs=(
            "**/pom.xml",
            "**/build.gradle*",
            "**/application*.yml",
            "**/application*.yaml",
            "**/application*.properties",
            "**/web.xml",
            "**/security*.xml",
        ),
        config_keywords=(
            "pom.xml",
            "build.gradle",
            "application",
            "web.xml",
            "security",
            "spring",
        ),
        l2_deny_basenames=frozenset(),
        l2_playbook_hint=(
            "Java：优先 pom.xml/build.gradle、application*.yml|properties、"
            "web.xml 及安全相关 XML；再读与 sink 相关的 .java。"
        ),
    ),
    "python": LanguageProfile(
        language="python",
        source_extensions=frozenset({".py", ".pyi"}),
        header_extensions=frozenset(),
        build_file_names=frozenset(
            {"pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "pipfile"}
        ),
        config_globs=(
            "**/pyproject.toml",
            "**/setup.py",
            "**/setup.cfg",
            "**/requirements*.txt",
            "**/settings.py",
            "**/.env.example",
        ),
        config_keywords=("pyproject", "requirements", "settings.py", "setup.py", "config"),
        l2_deny_basenames=frozenset(),
        l2_playbook_hint=(
            "Python：优先 pyproject.toml、requirements.txt、settings.py；"
            "再读与 sink 相关的 .py 模块。"
        ),
    ),
    "go": LanguageProfile(
        language="go",
        source_extensions=frozenset({".go"}),
        header_extensions=frozenset(),
        build_file_names=frozenset({"go.mod", "go.sum", "makefile"}),
        config_globs=("**/go.mod", "**/go.sum", "**/Makefile", "**/*_config.go"),
        config_keywords=("go.mod", "config", "Makefile"),
        l2_deny_basenames=frozenset(),
        l2_playbook_hint="Go：优先 go.mod、Makefile 及与 sink 相关的 .go 源文件。",
    ),
    "rust": LanguageProfile(
        language="rust",
        source_extensions=frozenset({".rs"}),
        header_extensions=frozenset(),
        build_file_names=frozenset({"cargo.toml", "makefile"}),
        config_globs=("**/Cargo.toml", "**/Cargo.lock", "**/build.rs"),
        config_keywords=("cargo.toml", "build.rs"),
        l2_deny_basenames=frozenset(),
        l2_playbook_hint="Rust：优先 Cargo.toml、build.rs；再读与 sink 相关的 .rs。",
    ),
}

# 未知语言回退到 cpp 风格（C 系构建/头文件最常见）
_DEFAULT_PROFILE = _PROFILES["cpp"]


def normalize_profile_language(language: str) -> str:
    lang = (language or "cpp").lower().strip()
    if lang in ("c", "c++"):
        return "cpp"
    if lang in _PROFILES:
        return lang
    return "cpp"


def get_language_profile(language: str) -> LanguageProfile:
    return _PROFILES.get(normalize_profile_language(language), _DEFAULT_PROFILE)


def get_l2_config_globs(language: str) -> List[str]:
    return list(get_language_profile(language).config_globs)


def get_l2_playbook_hint(language: str) -> str:
    return get_language_profile(language).l2_playbook_hint
