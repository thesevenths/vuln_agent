"""

Joern DSL 静态校验（Joern 4.x / Scala REPL 兼容）。



不连接 Joern 即可在 CI/单测中捕获常见 DSL 问题：

- Python/Scala 字符串非法转义

- Method 遍历上误用 .filter(_.code(...).l.nonEmpty)（Joern 4.x Type Mismatch）

- 逻辑查询缺少 .l 收尾；污点查询缺少 cpg + .p/.l

"""



from __future__ import annotations



import re

from typing import Dict, List, Tuple



# Joern/Scala 执行失败时常见 stderr 片段（应计入 failed_queries）

JOERN_QUERY_FAILURE_MARKERS: Tuple[str, ...] = (

    "Error:",

    "【查询失败】",

    "【查询跳过】",

    "【查询未执行·熔断中止】",

    "invalid escape character",

    "invalid escape",

    "syntax error",

    "Compilation failed",

    "Parse error",

    "not found: value",

    "repl.MIMEBundle",

    "Type Mismatch Error",

)



# Method 上 .filter(_.code / .filterNot(_.code 在 Joern 4.x 会 Type Mismatch

_METHOD_FILTER_CODE_RE = re.compile(

    r"\.filter(?:Not)?\(_\.code\s*\(",

)





def is_joern_query_failure(text: str) -> bool:

    if not (text or "").strip():

        return True

    lower = text.lower()

    for marker in JOERN_QUERY_FAILURE_MARKERS:

        if marker.lower() in lower:

            return True

    return False





def _scala_regex_escape_issues(name: str, source: str) -> List[str]:

    """Joern/Scala 字符串里单独的 \\( \\) \\. 会编译失败（需 \\\\( 或改写正则）。"""

    issues: List[str] = []

    if re.search(r"(?<!\\)\\[(]", source):

        issues.append(f"{name}: Scala 正则含非法 \\( 转义（应用 \\\\( 或去掉字面括号）")

    if re.search(r"(?<!\\)\\[)]", source):

        issues.append(f"{name}: Scala 正则含非法 \\) 转义")

    for m in re.finditer(r"\\+\\.", source):

        if (len(m.group(0)) - 1) % 2 == 1:

            issues.append(

                f"{name}: Scala 正则含非法 \\. 转义（请改用 [.] 或 Python 源里写成 \\\\\\\\.）"

            )

            break

    return issues





def _method_filter_code_issues(name: str, source: str) -> List[str]:

    if _METHOD_FILTER_CODE_RE.search(source):

        return [

            f"{name}: Method 上禁止 .filter(_.code(...)) / .filterNot(_.code(...))，"

            "请改用 .where(_.code(...)) / .whereNot(_.code(...))",

        ]

    issues: List[str] = []

    if re.search(r"\.where\(_\.parameter\.exists\s*\(", source):

        issues.append(

            f"{name}: Method 上 .where(_.parameter.exists(...)) 在 Joern 4.x 会 Type Mismatch，"

            "请改用 .where(_.parameter.annotation.name(...)) 或 .filter(_.parameter.exists(...))",

        )

    if re.search(r"\.whereNot\(_\.call\.[^)]+\.l\.nonEmpty\)", source):

        issues.append(

            f"{name}: Method 上 .whereNot(_.call.*.l.nonEmpty) 在 Joern 4.x 会 Type Mismatch，"

            "请改用 .filterNot(_.call.*.l.nonEmpty)",

        )

    return issues





def validate_logic_query_source(name: str, source: str) -> List[str]:

    """返回逻辑查询的静态问题列表（空=通过）。"""

    issues: List[str] = []

    body = (source or "").strip()

    if not body:

        issues.append(f"{name}: 空查询")

        return issues

    if "import io.shiftleft.semanticcpg.language._" not in body:

        issues.append(f"{name}: 缺少 semanticcpg import")

    if ".l" not in body:

        issues.append(f"{name}: 未使用 .l 收尾（Joern REPL 需 List 输出）")

    issues.extend(_scala_regex_escape_issues(name, body))

    issues.extend(_method_filter_code_issues(name, body))

    tail = body.rstrip().split("\n")[-1].strip()

    if not (tail.endswith(".l") or tail.endswith(".distinct") or tail == "adminOps"):

        if ".take(" in body and ".l" not in tail:

            issues.append(f"{name}: 最后一行可能未 .l: {tail[:80]}")

    return issues





def validate_taint_query_source(name: str, source: str) -> List[str]:

    """污点流 / 通用 Joern 查询静态检查。"""

    issues: List[str] = []

    body = (source or "").strip()

    if not body:

        issues.append(f"{name}: 空查询")

        return issues

    if "cpg." not in body:

        issues.append(f"{name}: 缺少 cpg. 入口")

    if not (".p" in body or ".l" in body or ".dumpRaw" in body):

        issues.append(f"{name}: 未使用 .p / .l / .dumpRaw 收尾")

    issues.extend(_scala_regex_escape_issues(name, body))

    issues.extend(_method_filter_code_issues(name, body))

    return issues





def validate_all_java_logic_queries(query_map: Dict[str, str]) -> List[str]:

    all_issues: List[str] = []

    for name, src in sorted(query_map.items()):

        all_issues.extend(validate_logic_query_source(name, src))

    return all_issues





def validate_query_registry(

    registry_name: str,

    query_map: Dict[str, str],

    *,

    kind: str = "logic",

) -> List[str]:

    """校验单个 queries.py 注册表。"""

    validate_fn = (

        validate_logic_query_source if kind == "logic" else validate_taint_query_source

    )

    all_issues: List[str] = []

    for name, src in sorted(query_map.items()):

        for issue in validate_fn(name, src):

            all_issues.append(f"{registry_name}/{issue}")

    return all_issues





def validate_all_registered_queries(

    logic_registries: Dict[str, Dict[str, str]],

    taint_registries: Dict[str, Dict[str, str]],

) -> List[str]:

    """校验 queries.py 登记的全部 logic + taint 查询字典。"""

    issues: List[str] = []

    for reg_name, query_map in sorted(logic_registries.items()):

        issues.extend(validate_query_registry(reg_name, query_map, kind="logic"))

    for reg_name, query_map in sorted(taint_registries.items()):

        issues.extend(validate_query_registry(reg_name, query_map, kind="taint"))

    return issues


