"""
recon/engine.py — 核心编排器（ReconEngine）

完整侦查流程：
1. 检查缓存 → 命中且有效则直接返回
2. 项目结构感知（文件遍历）
3. 执行 Joern 查询批次（适配器提供查询集）
4. 解析入口点 / 鉴权机制 / 敏感操作
5. 生成攻击面地图
6. 持久化到 checkpoints
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from recon.adapters.base import ReconAdapter
from recon.adapters.java_spring import JavaSpringAdapter
from recon.adapters.python_adapter import PythonAdapter
from recon.models import AttackSurfaceMap, ParamInfo
from recon.persistence import ReconPersistence
from recon.scanners.attack_surface import build_attack_surface
from recon.scanners.auth_mechanisms import resolve_entry_auth, scan_auth_mechanisms
from recon.scanners.entry_points import build_content_type_map, scan_entry_points
from recon.scanners.project_structure import scan_project_structure
from recon.scanners.sensitive_operations import scan_sensitive_operations

logger = logging.getLogger(__name__)

# 所有已注册的适配器（按优先级排序）
_REGISTERED_ADAPTERS = [
    JavaSpringAdapter(),
    PythonAdapter(),
]


class ReconEngine:
    """
    侦查引擎 — 编排 5 个 Scanner 生成攻击面地图。

    典型使用：
        engine = ReconEngine(scanner, adapter=None)
        attack_map = engine.run(source_path="/data/project")
    """

    def __init__(
        self,
        scanner,
        adapter: Optional[ReconAdapter] = None,
        checkpoint_dir: Optional[str] = None,
        project_name: Optional[str] = None,
    ):
        """
        Args:
            scanner: JoernVulnScannerHTTP 实例（提供 _run_query_map 方法）。
            adapter: 语言/框架适配器。None 则自动检测。
            checkpoint_dir: 检查点根目录，默认 agent_reports/checkpoints。
            project_name: 项目名，默认从 scanner.project_name 获取。
        """
        self.scanner = scanner
        self._adapter = adapter

        # 推导 checkpoint_dir
        if checkpoint_dir:
            self._checkpoint_dir = Path(checkpoint_dir)
        else:
            self._checkpoint_dir = Path("agent_reports") / "checkpoints"

        # 推导 project_name
        self._project_name = project_name or getattr(scanner, "project_name", "unknown")

        # 持久化
        self.persistence = ReconPersistence(self._checkpoint_dir, self._project_name)

    def run(
        self,
        source_path: str,
        force: bool = False,
        language: str = "java",
    ) -> AttackSurfaceMap:
        """
        完整侦查流程。

        Args:
            source_path: 项目源码根目录。
            force: 强制重新侦查（忽略缓存）。
            language: 目标语言提示（用于适配器选择）。

        Returns:
            AttackSurfaceMap 实例。
        """
        logger.info("=" * 60)
        logger.info("Recon 侦查开始: source=%s language=%s force=%s", source_path, language, force)
        logger.info("=" * 60)

        # ① 缓存检查
        if not force and os.environ.get("JOERN_CHECKPOINT_RESET") != "1":
            cached = self._try_load_cache(source_path)
            if cached:
                logger.info("Recon 缓存命中，跳过侦查: %s", cached.summary())
                return cached

        # ② 选择适配器
        adapter = self._adapter or self.select_adapter(source_path, language)
        logger.info("适配器选择: %s/%s", adapter.language, adapter.framework_hint)

        # ③ 项目结构感知（文件遍历，不需要 CPG）
        project_info = scan_project_structure(source_path, adapter)

        # ④ 执行 Joern 查询批次
        query_results = self._execute_joern_queries(adapter)
        # 保存原始查询结果，供 run_recon 返回给 logic_scan 复用
        self._raw_query_results = query_results

        # ⑤ 解析入口点
        entries = scan_entry_points(query_results, adapter)

        # ⑤.5 从源文件注解中提取 URL 路径
        self._extract_urls_from_source(entries, source_path)

        # ⑤.6 从源文件方法签名中提取参数信息（回填 Joern 未捕获的参数）
        self._extract_params_from_source(entries, source_path)

        # ⑥ 解析鉴权机制
        auth_mechs = scan_auth_mechanisms(query_results, adapter)

        # ⑦ 解析敏感操作（关联可达入口）
        sensitive_ops = scan_sensitive_operations(query_results, adapter, entries)

        # ⑧ 鉴权覆盖状态
        auth_coverage = resolve_entry_auth(entries, auth_mechs)

        # ⑨ Content-Type 映射
        content_type_entries = build_content_type_map(query_results, adapter)

        # ⑩ 融合生成攻击面地图
        attack_map = build_attack_surface(
            project_info=project_info,
            entries=entries,
            auth_mechs=auth_mechs,
            sensitive_ops=sensitive_ops,
            auth_coverage=auth_coverage,
            content_type_entries=content_type_entries,
        )

        # ⑪ 持久化
        self.persistence.save(attack_map)

        logger.info("=" * 60)
        logger.info("Recon 侦查完成: %s", attack_map.summary())
        logger.info("=" * 60)

        return attack_map

    def _try_load_cache(self, source_path: str) -> Optional[AttackSurfaceMap]:
        """尝试从缓存加载"""
        if not self.persistence.is_valid(source_path):
            return None
        return self.persistence.load()

    def _execute_joern_queries(self, adapter: ReconAdapter) -> dict:
        """
        通过 scanner._run_query_map 执行适配器提供的全部 Joern 查询。

        Returns:
            query_name -> raw_output 字典。
        """
        queries = adapter.get_joern_queries()
        logger.info("执行 Recon Joern 查询: %d 条", len(queries))

        # 通过 scanner 的 _run_query_map 批量执行
        # 使用专用 checkpoint namespace 支持跨运行缓存
        result = self.scanner._run_query_map(
            queries,
            log_prefix="Recon 查询",
            query_source="recon_adapter",
            checkpoint_namespace="recon_queries",
        )

        # 统计
        ok_count = sum(1 for v in result.values() if v and len(v.strip()) > 5)
        logger.info("Recon 查询完成: %d/%d 有结果", ok_count, len(queries))

        return result

    # ── URL 路径提取 ────────────────────────────────────────────────

    @staticmethod
    def _extract_urls_from_source(
        entries: list,
        source_path: str,
    ) -> None:
        """
        从源文件注解中提取 URL 路径，回填 EntryPoint.url。

        支持以下 Spring MVC 注解模式:
          - 单行: @GetMapping("/api/users")
          - 多行: @RequestMapping(\n    path = "/attack", ...)
          - path/value 属性: @GetMapping(path = "/path")
          - 数组语法: @GetMapping(path = {"/a", "/b"})
          - 常量引用: @GetMapping(path = URL_CONST)
        """
        import os
        import re

        if not source_path or not os.path.isdir(source_path):
            return

        # ---------- 正则 ----------
        # Spring Mapping 注解（含裸 @PostMapping 等无参数形式，用 \b 而非强制 '('）
        # 同时支持 Flask (@app.route) / FastAPI (@app.get / @router.post) 等
        # Python 装饰器式路由（URL 写在装饰器参数里，与 Spring 注解同构）。
        _ANN_RE = re.compile(
            r'@(?:Request|Get|Post|Put|Delete|Patch)Mapping\b'
            r'|@[A-Za-z_][\w]*\.(?:route|get|post|put|delete|patch|head|options)\b'
        )
        # 属性字符串: value = "..." 或 path = "..."
        _ATTR_STR_RE = re.compile(
            r'(?:value|path)\s*=\s*"([^"]+)"'
        )
        # 属性数组: value = {"...", ...} 或 path = {"...", ...}
        _ATTR_ARR_RE = re.compile(
            r'(?:value|path)\s*=\s*\{([^}]+)\}'
        )
        # 位置参数字符串: @GetMapping("/path")  -- 紧跟 '(' 后
        _POS_STR_RE = re.compile(
            r'\(\s*"([^"]+)"'
        )
        # 位置参数数组: @GetMapping({"/a", "/b"})
        _POS_ARR_RE = re.compile(
            r'\(\s*\{([^}]+)\}'
        )
        # 常量引用: value = SOME_CONST 或 path = SOME_CONST
        _CONST_REF_RE = re.compile(
            r'(?:value|path)\s*=\s*([A-Z_][A-Z0-9_]*)'
        )
        # 类级 @RequestMapping（单行，用于前缀）
        _CLASS_MAP_STR_RE = re.compile(
            r'@RequestMapping\s*\(\s*(?:value\s*=\s*|path\s*=\s*)?"([^"]+)"'
        )
        _CLASS_MAP_CONST_RE = re.compile(
            r'@RequestMapping\s*\(\s*(?:value\s*=\s*|path\s*=\s*)?([A-Z_][A-Z0-9_]*)'
        )
        # 文件中 String 常量定义
        _CONST_DEF_RE = re.compile(
            r'(?:static\s+final|final\s+static)\s+String\s+'
            r'([A-Z_][A-Z0-9_]*)\s*=\s*"([^"]+)"'
        )

        # ---------- 文件 / 常量缓存 ----------
        _file_cache: dict = {}
        _const_cache: dict = {}  # (file, const_name) -> value

        def _read_file(fpath: str) -> list:
            if fpath not in _file_cache:
                full = os.path.join(source_path, fpath)
                try:
                    with open(full, "r", encoding="utf-8", errors="replace") as f:
                        _file_cache[fpath] = f.readlines()
                except Exception:
                    _file_cache[fpath] = []
            return _file_cache[fpath]

        def _resolve_const(fpath: str, name: str) -> str:
            key = (fpath, name)
            if key in _const_cache:
                return _const_cache[key]
            val = ""
            for src_line in _read_file(fpath):
                cm = _CONST_DEF_RE.search(src_line)
                if cm and cm.group(1) == name:
                    val = cm.group(2)
                    break
            _const_cache[key] = val
            return val

        def _join_annotation(lines: list, start: int) -> str:
            """从 start 开始拼接多行注解，直到 ')' 闭合。"""
            joined = ""
            depth = 0
            for i in range(start, min(len(lines), start + 6)):
                raw = lines[i]
                joined += " " + raw.strip()
                depth += raw.count("(") - raw.count(")")
                if depth <= 0 and "(" in joined:
                    break
            return joined

        def _first_str_in_braces(text: str) -> str:
            """从 {"/a", "/b"} 中提取第一个字符串。"""
            m = re.search(r'"([^"]+)"', text)
            return m.group(1) if m else ""

        def _extract_url_from_ann(text: str, fpath: str) -> str:
            """
            从注解文本中提取 URL 路径。
            优先级:
              1) path/value 属性的字符串字面量
              2) path/value 属性的常量引用
              3) path/value 属性的数组字面量
              4) 位置参数字符串
              5) 位置参数数组
            """
            # 1) path = "/xxx" 或 value = "/xxx"
            m = _ATTR_STR_RE.search(text)
            if m:
                return m.group(1)
            # 2) path = CONST 或 value = CONST
            m = _CONST_REF_RE.search(text)
            if m:
                val = _resolve_const(fpath, m.group(1))
                if val:
                    return val
            # 3) path = {"/a", "/b"} 或 value = {"/a", "/b"}
            m = _ATTR_ARR_RE.search(text)
            if m:
                val = _first_str_in_braces(m.group(1))
                if val:
                    return val
            # 4) @GetMapping("/path")
            m = _POS_STR_RE.search(text)
            if m:
                return m.group(1)
            # 5) @GetMapping({"/a", "/b"})
            m = _POS_ARR_RE.search(text)
            if m:
                val = _first_str_in_braces(m.group(1))
                if val:
                    return val
            return ""

        # ---------- 主循环 ----------
        filled = 0
        for ep in entries:
            if ep.entry_type != "http" or not ep.file or not ep.line:
                continue
            lines = _read_file(ep.file)
            if not lines:
                continue
            # 行号统一为 0-indexed（ep.line 来自 Joern，为 1-indexed）
            ep_line0 = ep.line - 1

            # ① 查找类级 @RequestMapping 前缀
            class_prefix = ""
            for i, src_line in enumerate(lines):
                if i >= ep_line0:
                    break
                if "@RequestMapping" in src_line:
                    ann = src_line.strip()
                    if "(" in ann and ")" not in ann:
                        ann = _join_annotation(lines, i)
                    sm = _CLASS_MAP_STR_RE.search(ann)
                    if sm:
                        class_prefix = sm.group(1).rstrip("/")
                    else:
                        cm = _CLASS_MAP_CONST_RE.search(ann)
                        if cm:
                            class_prefix = _resolve_const(ep.file, cm.group(1)).rstrip("/")

            # ② 在 entry 行附近查找方法级注解
            #    Joern 有时报告的是 Javadoc @return 行而非注解行，
            #    所以向前 6 行、向后 10 行
            start = max(0, ep_line0 - 6)
            end = min(len(lines), ep_line0 + 10)
            # 锁定「最靠近入口行、优先位于其上方」的那条注解 = 方法自身装饰器；
            # 不再向兄弟方法/类级注解回退。其 URL 拼到类前缀之后；若该注解
            # 本身无 path（如裸 @PostMapping），则仅用类前缀。
            best_dist = None
            best_line = None
            for i in range(start, end):
                src_line = lines[i]
                if not _ANN_RE.search(src_line):
                    continue
                if i <= ep_line0:
                    dist = ep_line0 - i           # 上方：距离越小越近
                else:
                    dist = (i - ep_line0) + 1_000_000  # 下方：加权劣于所有上方
                if best_dist is None or dist < best_dist:
                    best_dist = dist
                    best_line = i
            if best_line is not None:
                ann = lines[best_line].strip()
                if "(" in ann and ")" not in ann:
                    ann = _join_annotation(lines, best_line)
                url_val = _extract_url_from_ann(ann, ep.file)
                if url_val:
                    full_url = (class_prefix + "/" + url_val.lstrip("/")).rstrip("/")
                else:
                    full_url = class_prefix      # 方法注解无 path -> 仅类前缀
                if full_url and not full_url.startswith("/"):
                    full_url = "/" + full_url
                if full_url:
                    ep.url = full_url
                    filled += 1

        logger.info("URL 提取完成: %d/%d 个 HTTP 端点有 URL", filled,
                     sum(1 for e in entries if e.entry_type == "http"))

        # ② Django / DRF 视图 URL 回填（path()/url()/re_path() 注册式路由，
        #    Spring 注解式提取不覆盖 Python）
        filled += ReconEngine._resolve_django_urls(entries, source_path)
        return filled

    @staticmethod
    def _resolve_django_urls(entries: list, source_path: str) -> int:
        """
        为 Django / DRF 视图回填 URL（Spring 注解式提取不覆盖 Python）。

        扫描项目内所有 urls.py / urls_*.py，解析 path() / re_path() / url()
        路由，按 view 引用（如 views.user_list / views.UserView.as_view()）
        映射到 EntryPoint.handler（Joern fullName），回填 ep.url。

        这是 best-effort：URL 为相对 urlconf 的路径（include() 前缀不展开）；
        当多个视图同名时取首个匹配。仅回填尚未有 URL 的 Python 入口。
        """
        import os
        import re

        if not source_path or not os.path.isdir(source_path):
            return 0

        # 收集 urlconf 文件
        url_files: list = []
        for root, _dirs, files in os.walk(source_path):
            for fn in files:
                if fn == "urls.py" or (fn.startswith("urls_") and fn.endswith(".py")):
                    url_files.append(os.path.join(root, fn))
        if not url_files:
            return 0

        # path("...", view) / re_path(...) / url(...)
        _DJANGO_PATH_RE = re.compile(
            r'(?:path|re_path|url)\s*\(\s*'
            r'((?:r|R)?["\'])(.*?)\1'   # 引号 + URL 模式
            r'\s*,\s*'
            r'([^\s,()]+)'               # view 引用
        )

        def _norm_ref(ref: str) -> list:
            # 去掉 .as_view(...) / .as_view({...})，仅保留 view 标识
            ref = re.sub(r'\.as_view\b.*$', '', ref.strip())
            parts = [p for p in ref.split('.') if p]
            keys = []
            if len(parts) >= 2:
                keys.append('.'.join(parts[-2:]))
            if parts:
                keys.append(parts[-1])
            return keys

        # 构建 view 引用 -> [url 模式] 映射
        url_map: dict = {}
        for uf in url_files:
            try:
                with open(uf, "r", encoding="utf-8", errors="replace") as f:
                    text = f.read()
            except Exception:
                continue
            for m in _DJANGO_PATH_RE.finditer(text):
                pattern = m.group(2).strip()
                ref = m.group(3).strip()
                if not pattern or not ref:
                    continue
                # 去掉正则锚点
                pattern = pattern.lstrip('^').rstrip('$')
                if not pattern.startswith('/'):
                    pattern = '/' + pattern
                pattern = pattern.rstrip('/') or '/'
                for key in _norm_ref(ref):
                    url_map.setdefault(key, [])
                    if pattern not in url_map[key]:
                        url_map[key].append(pattern)

        # 回填尚未有 URL 的 Python http 入口
        filled = 0
        for ep in entries:
            if ep.entry_type != "http" or ep.url or not (ep.file and ep.file.endswith(".py")):
                continue
            handler = ep.handler or ""
            handler_parts = [p for p in handler.split('.') if p]
            # 候选键：规范化引用 + 类名（用于 CBV 的 views.UserView.as_view()
            # 与 handler 的 myapp.views.UserView.get 匹配）
            handler_keys = set(_norm_ref(handler))
            if len(handler_parts) >= 2:
                handler_keys.add(handler_parts[-2])
            matched = None
            for key in handler_keys:
                if key in url_map:
                    matched = url_map[key][0]
                    break
            if matched:
                ep.url = matched
                filled += 1

        if filled:
            logger.info("Django/DRF URL 回填: %d 个 Python 端点", filled)
        return filled

    @staticmethod
    def _extract_params_from_source(
        entries: list,
        source_path: str,
    ) -> None:
        """
        从源文件方法签名中提取 @RequestParam/@PathVariable/@RequestBody 参数，
        回填 EntryPoint.parameters（仅填充仍为空的条目）。

        作为 Joern endpoint_parameters 查询的补充回退。
        """
        import os
        import re

        if not source_path or not os.path.isdir(source_path):
            return

        # Spring 参数注解
        _PARAM_ANN_RE = re.compile(
            r'@(RequestParam|PathVariable|RequestBody|ModelAttribute|RequestHeader|CookieValue)'
            r'(?:\s*\(([^)]*)\))?'
        )
        # 方法签名行（简单匹配：修饰符 + 返回类型 + 方法名 + 括号）
        _METHOD_SIG_RE = re.compile(
            r'(?:public|private|protected)\s+\S+.*\s+\w+\s*\('
        )
        # 从注解 value/name 属性提取参数名
        _ANN_NAME_RE = re.compile(r'(?:value|name)\s*=\s*"([^"]+)"')
        # 位置字符串参数: @PathVariable("id") 或 @PathVariable Long id
        _ANN_POS_RE = re.compile(r'\(\s*"([^"]+)"')

        _file_cache: dict = {}

        def _read_file(fpath: str) -> list:
            if fpath not in _file_cache:
                full = os.path.join(source_path, fpath)
                try:
                    with open(full, "r", encoding="utf-8", errors="replace") as f:
                        _file_cache[fpath] = f.readlines()
                except Exception:
                    _file_cache[fpath] = []
            return _file_cache[fpath]

        def _join_method_sig(lines: list, start: int) -> str:
            """从 start 开始拼接方法签名直到 ')' 闭合。"""
            joined = ""
            depth = 0
            started = False
            for i in range(start, min(len(lines), start + 15)):
                raw = lines[i]
                joined += " " + raw.strip()
                if "(" in raw:
                    started = True
                depth += raw.count("(") - raw.count(")")
                if started and depth <= 0:
                    break
            return joined

        def _parse_param_from_annotation(ann_text: str, param_decl: str) -> tuple:
            """
            从单个参数声明中提取 (param_name, param_type, java_type)。
            ann_text: 注解文本如 @RequestParam("q")
            param_decl: 参数声明如 @RequestParam("q") String query
            """
            # 提取注解类型
            ann_m = _PARAM_ANN_RE.search(ann_text)
            if not ann_m:
                return None
            param_type = ann_m.group(1)  # e.g. "RequestParam"

            # 提取参数名：优先从注解属性中取
            param_name = ""
            if ann_m.group(2):
                # 注解属性有值: @RequestParam(value = "q") 或 @RequestParam("q")
                nm = _ANN_NAME_RE.search(ann_m.group(2))
                if nm:
                    param_name = nm.group(1)
                else:
                    pm = _ANN_POS_RE.search(ann_m.group(2))
                    if pm:
                        param_name = pm.group(1)

            # 如果注解中没有名字，从参数声明中取（注解后面的类型 + 变量名）
            if not param_name:
                # 找到注解之后的部分
                after_ann = param_decl[ann_m.end():].strip()
                # 去掉可能的逗号
                after_ann = after_ann.lstrip(',').strip()
                # 匹配: TypeName varName 或 TypeName<Generic> varName
                var_m = re.search(r'[\w<>\[\],\s]+\s+(\w+)\s*[,)]?$', after_ann)
                if var_m:
                    param_name = var_m.group(1)

            # 提取 Java 类型
            java_type = ""
            after_ann = param_decl[ann_m.end():].strip().lstrip(',').strip()
            type_m = re.search(r'([\w<>.\[\]]+)\s+\w+\s*[,)]?$', after_ann)
            if type_m:
                java_type = type_m.group(1)
                # 简化全限定名
                java_type = java_type.split('.')[-1]

            return (param_name or "unknown", param_type, java_type)

        # 需要跳过的 Spring 框架自动注入类型
        _SKIP_TYPES = {
            "HttpServletRequest", "HttpServletResponse", "HttpSession",
            "Model", "ModelMap", "ModelAndView", "RedirectAttributes",
            "BindingResult", "Errors", "Authentication", "Principal",
            "WebGoatUser", "LessonName", "TimeZone",
        }

        # ---------- 主循环 ----------
        filled = 0
        for ep in entries:
            if ep.entry_type != "http" or not ep.file or not ep.line:
                continue
            # 如果 Joern 已经提供了参数，跳过
            if ep.parameters:
                continue

            lines = _read_file(ep.file)
            if not lines:
                continue

            # 在 entry line 附近找到方法签名
            start = max(0, ep.line - 2)
            end = min(len(lines), ep.line + 15)
            method_sig = ""
            for i in range(start, end):
                if _METHOD_SIG_RE.search(lines[i]):
                    method_sig = _join_method_sig(lines, i)
                    break

            if not method_sig:
                continue

            # 提取括号内的参数列表
            paren_m = re.search(r'\(([^)]*)\)', method_sig)
            if not paren_m:
                continue
            params_text = paren_m.group(1).strip()
            if not params_text:
                continue

            # 按逗号分割参数（简单分割，不考虑泛型嵌套逗号）
            # 先做智能分割：遇到 @ 注解时，从 @ 开始到下一个 @ 或结尾是一个参数
            param_decls = []
            current = ""
            for ch in params_text:
                if ch == ',' and current.strip():
                    param_decls.append(current.strip())
                    current = ""
                else:
                    current += ch
            if current.strip():
                param_decls.append(current.strip())

            params = []
            for decl in param_decls:
                decl = decl.strip()
                # 跳过无注解的框架类型
                if not decl.startswith("@"):
                    # 检查是否是框架自动注入类型
                    type_name = decl.split()[-2] if len(decl.split()) >= 2 else ""
                    type_name = type_name.split('.')[-1]
                    if type_name not in _SKIP_TYPES:
                        # 无注解的普通参数，可能是 form 字段
                        parts = decl.rsplit(None, 1)
                        if len(parts) == 2:
                            java_type = parts[0].split('.')[-1]
                            param_name = parts[1].rstrip(')')
                            params.append(ParamInfo(
                                name=param_name,
                                param_type="implicit",
                                java_type=java_type,
                            ))
                    continue

                # 有注解的参数
                result = _parse_param_from_annotation(decl, decl)
                if result:
                    pname, ptype, jtype = result
                    # 跳过框架类型
                    if jtype.split('.')[-1] not in _SKIP_TYPES:
                        params.append(ParamInfo(
                            name=pname,
                            param_type=ptype,
                            java_type=jtype,
                        ))

            if params:
                ep.parameters = params
                filled += 1

        logger.info("源文件参数提取: %d/%d 个 HTTP 端点有参数",
                     filled, sum(1 for e in entries if e.entry_type == "http"))

    @staticmethod
    def select_adapter(source_path: str, language: str = "java") -> ReconAdapter:
        """
        根据项目特征自动选择适配器。

        优先级：
        1. language 参数显式指定
        2. 文件特征自动检测

        Args:
            source_path: 项目源码路径。
            language: 语言提示。

        Returns:
            匹配的 ReconAdapter 实例。
        """
        # 按 language 优先匹配
        lang_lower = language.lower().strip()
        for adapter in _REGISTERED_ADAPTERS:
            if adapter.language == lang_lower:
                if adapter.detect(source_path):
                    logger.info("自动选择适配器: %s/%s (language=%s)", adapter.language, adapter.framework_hint, language)
                    return adapter

        # 按文件特征检测
        for adapter in _REGISTERED_ADAPTERS:
            if adapter.detect(source_path):
                logger.info("自动选择适配器: %s/%s (auto-detect)", adapter.language, adapter.framework_hint)
                return adapter

        # 兜底：返回 Java 适配器
        logger.warning("无匹配适配器，使用默认 Java/Spring 适配器")
        return JavaSpringAdapter()
