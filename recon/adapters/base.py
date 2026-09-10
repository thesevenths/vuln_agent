"""
recon/adapters/base.py — 语言/框架适配器抽象基类

每种语言/框架（Java/Spring、Python/Django 等）实现此接口，
为 ReconEngine 提供统一的查询集、文件模式和解析能力。
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, List

from recon.models import (
    AuthMechanism,
    EntryPoint,
    ProjectInfo,
    SensitiveOperation,
)


class ReconAdapter(ABC):
    """语言/框架适配器抽象基类"""

    # ── 检测 ─────────────────────────────────────────────────────────────────

    @abstractmethod
    def detect(self, source_path: str) -> bool:
        """
        检测项目是否匹配此适配器。

        如 Java/Spring 适配器检查 pom.xml / build.gradle 是否存在，
        Python/Django 适配器检查 manage.py / requirements.txt 是否包含 django。
        """

    @property
    @abstractmethod
    def language(self) -> str:
        """适配器语言标识: 'java' / 'python' / 'go' 等"""

    @property
    @abstractmethod
    def framework_hint(self) -> str:
        """框架提示: 'spring_boot' / 'django' / 'flask' 等"""

    # ── Joern CPG 查询 ───────────────────────────────────────────────────────

    @abstractmethod
    def get_joern_queries(self) -> Dict[str, str]:
        """
        返回该语言/框架的完整 Joern 查询集。

        key 为查询名（如 'endpoint_enumeration'），value 为 Scala 查询代码。
        这些查询会一次性批量提交给 Joern 执行。
        """

    # ── 文件扫描模式 ──────────────────────────────────────────────────────────

    @abstractmethod
    def get_file_patterns(self) -> Dict[str, List[str]]:
        """
        返回文件扫描模式（用于 project_structure 等不需要 CPG 的检测）。

        返回格式：
        {
            "build_files": ["pom.xml", "build.gradle"],
            "config_files": ["application*.yml", "application*.properties"],
            "ci_cd_files": ["Jenkinsfile", ".github/workflows/*.yml"],
            "container_files": ["Dockerfile", "docker-compose.yml"],
        }
        """

    # ── 解析 ─────────────────────────────────────────────────────────────────

    @abstractmethod
    def parse_entry_points(self, query_results: Dict[str, str]) -> List[EntryPoint]:
        """
        从 Joern 查询结果解析所有入口点。

        需要处理：HTTP 端点、WebSocket、MQ 消费者、定时任务、
        文件上传、RPC、反序列化入口等。
        """

    @abstractmethod
    def parse_auth_mechanisms(self, query_results: Dict[str, str]) -> List[AuthMechanism]:
        """
        从 Joern 查询结果解析鉴权/授权机制。

        需要覆盖 5 种形式：
        1. 方法注解（@PreAuthorize）
        2. 类级注解
        3. Filter/Interceptor（SecurityConfig）
        4. AOP 切面
        5. 框架默认保护
        """

    @abstractmethod
    def parse_sensitive_operations(self, query_results: Dict[str, str]) -> List[SensitiveOperation]:
        """
        从 Joern 查询结果解析敏感操作（Sink 候选）。

        需要识别：DB 读写、文件 IO、命令执行、外部调用、
        权限变更、资金操作等。
        """

    # ── 可选覆盖 ──────────────────────────────────────────────────────────────

    def enrich_project_info(
        self, source_path: str, info: ProjectInfo
    ) -> ProjectInfo:
        """
        可选：基于文件遍历结果丰富 ProjectInfo。

        默认实现直接返回原 info。适配器可覆盖以添加框架特定检测，
        如识别 Spring Boot Actuator、MyBatis Mapper 等。
        """
        return info
