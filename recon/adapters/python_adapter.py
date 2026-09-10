"""
recon/adapters/python_adapter.py — Python 适配器 (Django / Flask / FastAPI)

检测 Python 项目并生成对应的 Joern 查询集。
当前为初版实现，查询集覆盖核心入口/鉴权/敏感操作，
后续可扩展更多框架（Tornado, aiohttp 等）。
"""
from __future__ import annotations

import logging
import os
import re
from typing import Dict, List

from recon.adapters.base import ReconAdapter
from recon.models import (
    AuthMechanism,
    EntryPoint,
    ProjectInfo,
    SensitiveOperation,
)

logger = logging.getLogger(__name__)


# ── Python Recon 查询 ─────────────────────────────────────────────────────

_PYTHON_QUERIES: Dict[str, str] = {
    # HTTP 路由枚举（Flask / Django / FastAPI）
    "python_route_enumeration": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.annotation.name("(?i)(route|get|post|put|delete|patch|api_view|action)"))
  .map(m => s"PY_ROUTE | ${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)} | annotations=${m.annotation.name.l.mkString(",")}")
  .take(200)
  .l
""",
    # 鉴权装饰器 / 中间件
    "python_auth_decorators": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.annotation.name("(?i)(login_required|permission_required|requires_auth|authenticated|roles_required|roles_accepted|user_passes_test|is_authenticated|requires_scopes)"))
  .map(m => s"PY_AUTH | ${m.fullName} | annotations=${m.annotation.name.l.mkString(",")} | file=${m.file.name.headOption.getOrElse("?")}")
  .take(100)
  .l
""",
    # Django middleware / DRF authentication_classes
    "python_middleware": """
import io.shiftleft.semanticcpg.language._
val middleware = cpg.method
  .where(_.code("(?i).*(MIDDLEWARE|middleware_classes|authentication_classes|permission_classes|DEFAULT_AUTHENTICATION_CLASSES)"))
  .map(m => s"PY_MIDDLEWARE | ${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | code_preview=${m.code.take(400)}")
  .take(30)
  .l
middleware
""",
    # 敏感操作
    "python_sensitive_ops": """
import io.shiftleft.semanticcpg.language._
val byName = cpg.call
  .name("(?i)^(save|delete|update|create|remove|execute|executemany|commit|rollback|merge|add|bulk_create|bulk_update|raw|system|popen|call|run|Popen|check_output|eval|exec|loads?|send_mail|send_mass_mail|upload|download|post|get|send|unlink|rmtree)$")
  .l
val byMethod = cpg.call
  .methodFullName("(?i).*(os\\.|subprocess\\.|pickle\\.|yaml\\.|cursor\\.|session\\.|db\\.|query\\.|filter_by\\.|filter\\.|requests\\.|shutil\\.|commands\\.).*")
  .l
(byName ++ byMethod).distinct
  .whereNot(_.name("(?i)^(toString|hashCode|equals|getClass|notify|wait|print|len|str|int|float|bool|list|dict|set|tuple)$"))
  .map(c => {
    val cc1 = c.method.caller.headOption
    val cc2 = cc1.flatMap(_.caller.headOption)
    val cc = List(cc1, cc2).flatten.map(_.fullName).mkString(";")
    s"SENSITIVE_OP | ${c.name} | method=${c.methodFullName} | caller=${c.method.fullName} | caller_chain=${cc} | file=${c.method.file.name.headOption.getOrElse("?")} | line=${c.lineNumber.getOrElse(0)}"
  })
  .take(150)
  .l
""",
    # 反序列化入口
    "python_deserialization": """
import io.shiftleft.semanticcpg.language._
cpg.call
  .name("(?i)(loads?|Unpickler|fromXML|parse)")
  .where(_.methodFullName("(?i).*(pickle\\.|cPickle\\.|yaml\\.|marshal\\.|shelve\\.|xml\\.|lxml\\.)"))
  .map(c => s"PY_DESER | caller=${c.method.fullName} | sink=${c.methodFullName} | file=${c.file.name.headOption.getOrElse("?")} | line=${c.lineNumber.getOrElse(0)}")
  .take(60)
  .l
""",
}


class PythonAdapter(ReconAdapter):
    """Python 项目适配器（Django / Flask / FastAPI）"""

    def detect(self, source_path: str) -> bool:
        for name in ("requirements.txt", "setup.py", "pyproject.toml", "Pipfile", "manage.py"):
            if os.path.exists(os.path.join(source_path, name)):
                return True
        # 检查 .py 文件是否存在
        for root, _dirs, files in os.walk(source_path):
            if any(f.endswith(".py") for f in files):
                return True
            if root != source_path:
                break
        return False

    @property
    def language(self) -> str:
        return "python"

    @property
    def framework_hint(self) -> str:
        return "python"

    def get_joern_queries(self) -> Dict[str, str]:
        return dict(_PYTHON_QUERIES)

    def get_file_patterns(self) -> Dict[str, List[str]]:
        return {
            "build_files": ["setup.py", "setup.cfg", "pyproject.toml", "Pipfile", "requirements*.txt"],
            "config_files": [
                "settings.py", "*.cfg", "*.ini", "*.toml",
                ".env", ".env.*", "config.py",
            ],
            "ci_cd_files": [
                ".github/workflows/*.yml", ".gitlab-ci.yml",
                "tox.ini", ".travis.yml", "Makefile",
            ],
            "container_files": [
                "Dockerfile", "docker-compose*.yml",
            ],
        }

    def parse_entry_points(self, query_results: Dict[str, str]) -> List[EntryPoint]:
        entries: List[EntryPoint] = []
        for line in (query_results.get("python_route_enumeration") or "").splitlines():
            line = line.strip().strip('",')
            if "PY_ROUTE" not in line:
                continue
            handler_m = re.search(r"PY_ROUTE\s*\|\s*([^\s|]+)", line)
            file_m = re.search(r"file=([^\s|]+)", line)
            line_m = re.search(r"line=(\d+)", line)
            annot_m = re.search(r"annotations=(.+?)(?:\s*$|\s*\|)", line)
            if handler_m:
                annotations = [a.strip() for a in annot_m.group(1).split(",") if a.strip()] if annot_m else []
                entries.append(EntryPoint(
                    url="",
                    http_method="ANY",
                    handler=handler_m.group(1).strip(),
                    file=file_m.group(1).strip().strip('"') if file_m else "",
                    line=int(line_m.group(1)) if line_m else 0,
                    entry_type="http",
                    annotations=annotations,
                ))

        # 反序列化入口
        for line in (query_results.get("python_deserialization") or "").splitlines():
            line = line.strip().strip('",')
            caller_m = re.search(r"caller=([^\s|]+)", line)
            if caller_m:
                entries.append(EntryPoint(
                    url="", http_method="N/A",
                    handler=caller_m.group(1).strip(),
                    entry_type="deserialization",
                ))
        return entries

    def parse_auth_mechanisms(self, query_results: Dict[str, str]) -> List[AuthMechanism]:
        mechs: List[AuthMechanism] = []
        for line in (query_results.get("python_auth_decorators") or "").splitlines():
            line = line.strip().strip('",')
            m = re.search(r"PY_AUTH\s*\|\s*([^\s|]+)", line)
            annot_m = re.search(r"annotations=(.+?)(?:\s*$|\s*\|)", line)
            if m:
                annots = [a.strip() for a in annot_m.group(1).split(",")] if annot_m else []
                mechs.append(AuthMechanism(
                    mechanism_type="annotation",
                    target=m.group(1).strip(),
                    annotations=annots,
                    coverage="method",
                ))

        # Middleware
        mw_raw = query_results.get("python_middleware", "")
        if mw_raw and len(mw_raw) > 20:
            mechs.append(AuthMechanism(
                mechanism_type="filter",
                target="Django MIDDLEWARE / DRF authentication_classes",
                coverage="global",
                detail=mw_raw[:500],
            ))
        return mechs

    def parse_sensitive_operations(self, query_results: Dict[str, str]) -> List[SensitiveOperation]:
        ops: List[SensitiveOperation] = []
        for line in (query_results.get("python_sensitive_ops") or "").splitlines():
            line = line.strip().strip('",')
            if not line:
                continue
            # New format (consistent with Java):
            # SENSITIVE_OP | ${c.name} | method= | caller= | caller_chain=...;... | file= | line=
            if "SENSITIVE_OP" not in line:
                continue  # skip REPL noise
            parts = line.split("|")
            if len(parts) < 2:
                continue
            call_name = parts[1].strip()
            method_full_name = ""
            caller_name = ""
            caller_chain_raw = ""
            file_path = ""
            line_num = 0
            for p in parts[2:]:
                p = p.strip()
                if p.startswith("method="):
                    method_full_name = p[7:].strip()
                elif p.startswith("caller_chain="):
                    caller_chain_raw = p[13:].strip()
                elif p.startswith("caller="):
                    caller_name = p[7:].strip()
                elif p.startswith("file="):
                    file_path = p[5:].strip().strip('"')
                elif p.startswith("line="):
                    try:
                        line_num = int(p[5:].strip())
                    except ValueError:
                        pass
            caller_chain = [c.strip() for c in caller_chain_raw.split(";") if c.strip()] if caller_chain_raw else []
            op_type = self._classify_sink(method_full_name or call_name)
            ops.append(SensitiveOperation(
                operation_type=op_type,
                handler=call_name,
                sink_call=call_name,
                file=file_path,
                line=line_num,
                risk_level="critical" if op_type in ("cmd_exec", "deserialization") else "high",
                caller_chain=caller_chain,
            ))
        return ops

    def enrich_project_info(self, source_path: str, info: ProjectInfo) -> ProjectInfo:
        # 检测 Django 项目
        if os.path.exists(os.path.join(source_path, "manage.py")):
            info.framework = "django"
        # 检测 Flask
        for name in ("app.py", "wsgi.py", "run.py"):
            if os.path.exists(os.path.join(source_path, name)):
                info.framework = info.framework or "flask"
        return info

    @staticmethod
    def _classify_sink(sink: str) -> str:
        s = sink.lower()
        if "exec" in s and "execute" not in s:
            return "cmd_exec"
        if any(k in s for k in ("system", "popen", "call", "run", "subprocess")):
            return "cmd_exec"
        if any(k in s for k in ("pickle", "yaml.load", "marshal", "shelve")):
            return "deserialization"
        if "execute" in s or "cursor" in s:
            return "db_write"
        if any(k in s for k in ("remove", "unlink", "rmtree", "shutil")):
            return "file_io"
        if any(k in s for k in ("requests", "send", "post", "get")):
            return "external_call"
        if "eval" in s:
            return "code_exec"
        return "db_write"
